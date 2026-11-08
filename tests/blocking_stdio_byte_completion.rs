#![allow(missing_docs)]
#![allow(clippy::pedantic, clippy::nursery)]
//! Public-API regression for the byte-bounded completion of the standard-stream writers.
//!
//! A `BoundedBytes` blocking pool reserves a job's closure storage and declared heap while the job's closure is alive
//! and returns them only after the closure and its allocation have been dropped. The standard-stream writers take
//! their result from inside that closure, so a writer that was woken by the result would run while its own job still
//! held the bytes: its next chunk would find the pool full and be refused as `WouldBlock`. The writers therefore wait
//! for the pool's own report that the job is done, which follows the return of the bytes.
//!
//! This target drives the real `asupersync::io::stderr()` writer through the public API alone, with the library's
//! default features (`Cx::for_testing` is behind `test-internals` and is not used):
//!
//! * a real runtime built from `LegacyProfile` caps: one scheduler worker and one blocking thread, each with a stated
//!   stack, a bounded global queue and a bounded blocking queue, audited against those caps;
//! * that runtime's own blocking pool, read back with `Runtime::blocking_handle`, with its policy set to `BoundedBytes`;
//! * a context from `Runtime::request_cx_with_budget`, which carries that pool, installed with `Cx::set_current`;
//! * a waker that records `charged_bytes()` of that pool at the instant the pool wakes it.
//!
//! The tests then show:
//!
//! * With the blocking thread held by a gate job, the writer's job waits in the queue and the writer is pending when
//!   polled. When the gate opens the pool wakes it, and the bytes the pool still reserves at that instant must be 0.
//! * A write larger than the pool is split into chunks that each fill the pool to the byte, so the next chunk can be
//!   admitted only once the previous job has returned everything; the whole write and a flush must succeed.
//! * A toy job that wakes the same recorder from inside its own closure is seen with bytes still reserved. That is the
//!   shape the writers must not have, and it shows that the `0` above is a measurement and not a blind spot.
//! * A writer that keeps returning `Pending` and keeps waking inside every wait is failed by the one deadline of the
//!   whole `settle` call, with the poll and wake counts, instead of being polled for ever. Tests 1 and 2 are its
//!   permitted positives: the same `settle` returns their results well inside the deadline.
//! * A real job can transfer captured heap through a panic payload. If retiring
//!   that payload fails, its reservation stays charged, an impossible waiter
//!   receives a terminal fault, and a smaller job still runs. This checks
//!   ownership and admission, not peak process memory.
//! * `try_spawn_charged_with` reserves a job's bytes and queue slot before its factory builds the payload: the factory
//!   is not called for a full queue or full bytes (and the same factory is admitted once there is room), the pool
//!   already holds the payload's bytes while the factory copies into them, a factory that panics with the `Vec` it
//!   allocated leaves that `Vec` charged, and the real stderr writer takes its input through it: refused, with
//!   nothing reserved, while the pool has no room, and written when it has. A pool whose original limit cannot hold a
//!   write stays `InvalidInput`; one whose room was pinned is `Other`, with a smaller write still accepted before that.
//!
//! The profile can also state the byte budget itself: `LegacyProfile::with_blocking_live_bytes`. The tests that start
//! from `budgeted_profile` never override the builder; `bounded_runtime` above still does, exactly as before, and is the
//! old-profile case.
//!
//! * The runtime a budgeted profile builds carries exactly the stated `BoundedBytes` policy, `audit` accepts it, and the
//!   real stderr writer and a charged factory use that very pool (admit, copy, write, retire, nothing left reserved).
//! * `audit` refuses a runtime whose pool is count-only or has another budget, naming the budget, and accepts the exact
//!   one; a profile that states no budget builds and audits as it always did, including against a byte-bounded runtime.
//! * On the profile's pool an uncharged submission is `ChargeRequired` and a declared one is admitted; a write that
//!   does not fit beside a holder is `WouldBlock` with nothing reserved for it, and the same write is accepted once the
//!   holder has retired.
//! * With blocking forbidden the budget is accepted and ignored: the pool forbids, the writer is refused as
//!   `Unsupported`, and a profile that allows blocking and states the same budget takes the same write.
//!
//! None of this bounds what a caller holds before the pool admits it, such as the closure owned by a parked
//! `submit_charged` future, or the process heap.
//!
//! The pool stores "done" before it wakes the registered waker, so a poll that no wake preceded could slip into the
//! gap and start the next job before the recorder reads. Every poll after a `Pending` therefore waits for the wake
//! first; the recorder sends its token only after it has read.

use asupersync::error::ErrorKind;
use asupersync::io::{AsyncWrite, stderr};
use asupersync::runtime::legacy_profile::{LegacyCaps, LegacyProfile};
use asupersync::runtime::{
    BlockingAdmissionPolicy, BlockingFactoryError, BlockingPoolHandle, BlockingSpawnErrorKind,
    Runtime,
};
use asupersync::{Budget, Cx};
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

/// The longest any single wait for a wake or a job may take.
const WAIT: Duration = Duration::from_secs(10);

/// The longest a whole `settle` call may take, however often the writer is woken meanwhile. These operations finish
/// in milliseconds; the figure leaves a slow host room and still ends a writer that never completes.
const OPERATION: Duration = Duration::from_secs(30);

/// Stack requested for the scheduler worker and for the blocking thread. The profile's budget is exactly their sum.
const WORKER_STACK: usize = 2 * 1024 * 1024;
const BLOCKING_STACK: usize = 1024 * 1024;

/// The byte limit of the pool in the serialized test. A write job's own storage is a few dozen bytes, so a chunk is
/// the rest of the limit and fills the pool exactly.
const TIGHT: usize = 256;

/// What the serialized test writes: four times what the pool can hold at once.
const SERIAL_LEN: usize = 4 * TIGHT;

const MARKER: &[u8] = b"byte-admission consumer: gated stderr write\n";

/// A runtime built from `LegacyProfile` caps whose blocking pool also bounds live job bytes. The audit fails the test
/// if the runtime does not carry exactly the stated caps.
fn bounded_runtime(max_queued: usize, max_live_bytes: usize) -> Runtime {
    let caps = LegacyCaps {
        worker_threads: 1,
        thread_stack_bytes: WORKER_STACK,
        blocking_max_threads: 1,
        blocking_thread_stack_bytes: BLOCKING_STACK,
        global_queue_limit: 64,
        blocking_max_queued: max_queued,
    };
    let budget = u64::try_from(WORKER_STACK + BLOCKING_STACK).unwrap();
    let profile = LegacyProfile::new(caps, budget);
    let policy = BlockingAdmissionPolicy::BoundedBytes {
        max_queued: NonZeroUsize::new(max_queued).unwrap(),
        max_live_bytes: NonZeroUsize::new(max_live_bytes).unwrap(),
    };
    let runtime = profile
        .builder()
        .expect("the caps are bounded and within budget")
        .blocking_admission_policy(policy)
        .build()
        .expect("a bounded runtime");
    profile
        .audit(&runtime)
        .expect("the runtime carries exactly the stated caps");
    runtime
}

/// The caps `bounded_runtime` states, for a given blocking queue bound: one scheduler worker and one blocking thread,
/// each with a stated stack, a bounded global queue and a bounded blocking queue.
fn profile_caps(max_queued: usize) -> LegacyCaps {
    LegacyCaps {
        worker_threads: 1,
        thread_stack_bytes: WORKER_STACK,
        blocking_max_threads: 1,
        blocking_thread_stack_bytes: BLOCKING_STACK,
        global_queue_limit: 64,
        blocking_max_queued: max_queued,
    }
}

/// The profile for `profile_caps`, whose stack budget is exactly the sum of the two stacks. It states no byte budget.
fn budgetless_profile(max_queued: usize) -> LegacyProfile {
    let budget = u64::try_from(WORKER_STACK + BLOCKING_STACK).unwrap();
    LegacyProfile::new(profile_caps(max_queued), budget)
}

/// The same profile, also stating `max_live_bytes` for the blocking pool. Its own `builder` selects the byte-bounded
/// policy: unlike `bounded_runtime`, nothing overrides it.
fn budgeted_profile(max_queued: usize, max_live_bytes: usize) -> LegacyProfile {
    let max_live_bytes = NonZeroUsize::new(max_live_bytes).unwrap();
    budgetless_profile(max_queued).with_blocking_live_bytes(max_live_bytes)
}

/// The runtime's own blocking pool: the pool that the contexts it issues carry, and so the one the writers use.
fn pool_of(runtime: &Runtime) -> BlockingPoolHandle {
    let pool = runtime
        .blocking_handle()
        .expect("the runtime has a blocking pool");
    assert!(matches!(
        pool.admission_policy(),
        BlockingAdmissionPolicy::BoundedBytes { .. }
    ));
    assert_eq!(pool.charged_bytes(), 0);
    pool
}

/// Woken by the pool, it records the bytes the pool still has reserved at that instant, then tells the test thread.
struct Recorder {
    pool: BlockingPoolHandle,
    wakes: AtomicUsize,
    highest: AtomicUsize,
    woke: Mutex<mpsc::Sender<()>>,
}

impl Wake for Recorder {
    fn wake(self: Arc<Self>) {
        let reserved = self.pool.charged_bytes();
        self.highest.fetch_max(reserved, Ordering::SeqCst);
        self.wakes.fetch_add(1, Ordering::SeqCst);
        let _ = self.woke.lock().unwrap().send(());
    }
}

/// A recording waker, and the channel that tells the test thread it has fired.
struct Wakes {
    recorder: Arc<Recorder>,
    woke: mpsc::Receiver<()>,
}

impl Wakes {
    fn new(pool: &BlockingPoolHandle) -> Self {
        let (sender, woke) = mpsc::channel();
        let recorder = Arc::new(Recorder {
            pool: pool.clone(),
            wakes: AtomicUsize::new(0),
            highest: AtomicUsize::new(0),
            woke: Mutex::new(sender),
        });
        Self { recorder, woke }
    }

    fn waker(&self) -> Waker {
        Waker::from(Arc::clone(&self.recorder))
    }

    fn wait_for_wake(&self) {
        self.woke
            .recv_timeout(WAIT)
            .expect("the pool wakes a pending writer");
    }

    /// What the recorder has seen, for a failure message.
    fn state(&self, polls: usize) -> String {
        let recorder = &self.recorder;
        let wakes = recorder.wakes.load(Ordering::SeqCst);
        let highest = recorder.highest.load(Ordering::SeqCst);
        let reserved = recorder.pool.charged_bytes();
        format!(
            "{polls} polls, {wakes} wakes, {highest} bytes reserved at the highest wake, {reserved} now"
        )
    }

    /// The time left before `deadline`. Fails the test, with the counts, when there is none.
    fn time_left(&self, deadline: Instant, what: &str, polls: usize) -> Duration {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "{what}: not ready in time: {}",
            self.state(polls)
        );
        left
    }

    /// Polls until `poll` is ready. After each `Pending` it waits for the pool to wake the writer.
    ///
    /// The whole call has one absolute deadline, `limit` from its start, checked before and after every poll, and each
    /// wait gets only the time left. A writer that keeps returning `Pending` and keeps waking inside every wait is
    /// therefore failed by the deadline, not polled for ever, and so is one that is never woken.
    fn settle_within<T>(
        &self,
        limit: Duration,
        what: &str,
        mut poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        let deadline = Instant::now() + limit;
        let waker = self.waker();
        let mut cx = Context::from_waker(&waker);
        let mut polls = 0_usize;
        loop {
            self.time_left(deadline, what, polls);
            polls += 1;
            let outcome = poll(&mut cx);
            let left = self.time_left(deadline, what, polls);
            if let Poll::Ready(result) = outcome {
                return result;
            }
            if self.woke.recv_timeout(left).is_err() {
                panic!(
                    "{what}: pending and not woken in time: {}",
                    self.state(polls)
                );
            }
        }
    }

    fn settle<T>(
        &self,
        what: &str,
        poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        self.settle_within(OPERATION, what, poll)
    }
}

#[test]
fn a_stderr_write_completes_only_after_its_job_has_returned_its_bytes() {
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));

    // The pool's only blocking thread is held by a gate job, so the writer's job queues behind it.
    let (open, gate) = mpsc::channel::<()>();
    let (entered, running) = mpsc::channel::<()>();
    let held = pool
        .try_spawn_charged(
            move || {
                let _ = entered.send(());
                let _ = gate.recv_timeout(WAIT);
            },
            0,
        )
        .expect("the pool admits the gate job");
    running.recv_timeout(WAIT).expect("the gate job is running");

    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    // The writer's job is queued in this pool, behind the gate, and declared exactly the payload it copied. That is
    // what shows the writer used the pool that the assertions read.
    assert_eq!(pool.charged_declared_bytes(), MARKER.len());
    assert!(writer.as_mut().poll_flush(&mut cx).is_pending());
    assert_eq!(wakes.recorder.wakes.load(Ordering::SeqCst), 0);

    // Open the gate and wait for the wake before polling again: the write job's wake is the first one.
    open.send(()).unwrap();
    wakes.wait_for_wake();
    let reserved = wakes.recorder.highest.load(Ordering::SeqCst);
    assert_eq!(
        reserved, 0,
        "the writer was woken while its job still held {reserved} bytes"
    );

    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes");
    assert!(held.wait_timeout(WAIT));
    let reserved = wakes.recorder.highest.load(Ordering::SeqCst);
    assert_eq!(reserved, 0, "a wake came while a job held {reserved} bytes");
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
fn a_serialized_multi_chunk_write_and_flush_complete_on_a_pool_that_holds_one_write_job() {
    let runtime = bounded_runtime(4, TIGHT);
    let pool = pool_of(&runtime);
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));

    let wakes = Wakes::new(&pool);
    let mut writer = pin!(stderr());
    let mut data = [b'.'; SERIAL_LEN];
    data[SERIAL_LEN - 1] = b'\n';
    let mut rest: &[u8] = &data;
    let mut chunks = Vec::new();
    wakes
        .settle("the serialized write and flush", |cx| {
            while !rest.is_empty() {
                match writer.as_mut().poll_write(cx, rest) {
                    Poll::Ready(Ok(written)) => {
                        assert_ne!(written, 0, "a non-empty write was accepted as 0 bytes");
                        chunks.push(written);
                        rest = &rest[written..];
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            writer.as_mut().poll_flush(cx)
        })
        .expect("a serialized write and flush complete");

    // Every chunk is smaller than the pool, so there are more than four, and every chunk but the last is the same
    // full size: what fits beside the write job's own storage.
    assert_eq!(chunks.iter().sum::<usize>(), SERIAL_LEN, "{chunks:?}");
    assert!(chunks.len() > SERIAL_LEN / TIGHT, "{chunks:?}");
    let full = chunks[0];
    let (last, others) = chunks.split_last().unwrap();
    assert!(others.iter().all(|chunk| *chunk == full), "{chunks:?}");
    assert!(*last <= full, "{chunks:?}");
    assert_eq!(
        pool.charged_bytes(),
        0,
        "the flush returned with bytes held"
    );
    let reserved = wakes.recorder.highest.load(Ordering::SeqCst);
    assert_eq!(reserved, 0, "a wake came while a job held {reserved} bytes");
}

#[test]
fn the_recorder_sees_a_wake_made_from_inside_the_jobs_own_closure() {
    // The shape the writers must not have: the wake comes from the job's closure, which the pool has not yet dropped,
    // so the job's bytes are still reserved.
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let early = pool
        .try_spawn_charged(move || waker.wake(), 0)
        .expect("the pool admits the job");
    wakes.wait_for_wake();
    assert!(early.wait_timeout(WAIT));
    let reserved = wakes.recorder.highest.load(Ordering::SeqCst);
    assert!(
        reserved > 0,
        "the recorder missed a wake made inside the job"
    );
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
#[should_panic(expected = "a writer that keeps waking: not ready in time")]
fn settle_gives_up_on_a_writer_that_keeps_returning_pending_and_keeps_waking() {
    // Every poll wakes at once, so no single wait ever times out: only the deadline of the whole call can end this.
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    let wakes = Wakes::new(&pool);
    let limit = Duration::from_millis(50);
    let _ = wakes.settle_within(limit, "a writer that keeps waking", |cx| {
        std::thread::sleep(Duration::from_millis(1));
        cx.waker().wake_by_ref();
        Poll::<io::Result<()>>::Pending
    });
}

#[test]
fn settle_refuses_a_ready_result_that_arrives_after_its_deadline() {
    // A Ready result must not bypass the post-poll deadline check. This bounds the
    // verdict after a poll returns; it cannot preempt a poll that never returns.
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    let wakes = Wakes::new(&pool);
    let calls = AtomicUsize::new(0);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wakes.settle_within(Duration::from_millis(100), "a late ready writer", |_cx| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Poll::Ready(Ok(()))
        })
    }));
    // A timeout before entering the poll must not masquerade as a successful
    // detector of the missing post-Ready deadline check.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the late poll was not exercised"
    );
    let payload = outcome.expect_err("a late Ready result bypassed the deadline");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("the deadline has a textual diagnostic");
    assert!(
        message.contains("a late ready writer: not ready in time"),
        "{message}"
    );
}

struct RetainedHeap {
    bytes: Vec<u8>,
    drops: Arc<AtomicUsize>,
}

impl Drop for RetainedHeap {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct TransferOnDrop(Option<RetainedHeap>);

impl Drop for TransferOnDrop {
    fn drop(&mut self) {
        if let Some(owned) = self.0.take() {
            // The secondary payload owns the original Vec; it is not a new
            // allocation made to evade the original declared-heap charge.
            std::panic::resume_unwind(Box::new(owned));
        }
    }
}

#[test]
fn transferred_panic_heap_stays_charged_wakes_an_impossible_waiter_and_allows_smaller_work() {
    const LIMIT: usize = 2048;
    const PAYLOAD: usize = 1024;
    let runtime = bounded_runtime(4, LIMIT);
    let pool = pool_of(&runtime);
    let drops = Arc::new(AtomicUsize::new(0));
    let owned = RetainedHeap {
        bytes: vec![0; PAYLOAD],
        drops: Arc::clone(&drops),
    };
    let (open, gate) = mpsc::channel::<()>();
    let (entered, running) = mpsc::channel::<()>();
    let job = pool
        .try_spawn_charged(
            move || {
                entered.send(()).unwrap();
                gate.recv_timeout(WAIT).unwrap();
                assert_eq!(owned.bytes.len(), PAYLOAD);
                std::panic::resume_unwind(Box::new(TransferOnDrop(Some(owned))));
            },
            PAYLOAD,
        )
        .expect("the original captured heap fits");
    running.recv_timeout(WAIT).unwrap();
    let original_charge = pool.charged_bytes();
    assert!((PAYLOAD..LIMIT).contains(&original_charge));

    // This zero-sized closure requests the entire original budget: it fits an
    // empty pool but cannot ever fit after the captured heap is quarantined.
    let mut waiting = pin!(pool.submit_charged(|| {}, LIMIT));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut context = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut context).is_pending());
    open.send(()).unwrap();
    wakes.wait_for_wake();
    match waiting.as_mut().poll(&mut context) {
        Poll::Ready(Err(refused)) => {
            assert_eq!(
                refused.kind(),
                BlockingSpawnErrorKind::ByteBudgetQuarantined
            );
        }
        Poll::Ready(Ok(_)) => panic!("an impossible request was admitted"),
        Poll::Pending => panic!("an impossible request was left waiting after quarantine"),
    }
    assert!(job.wait_timeout(WAIT));
    assert_eq!(pool.quarantined_bytes(), original_charge);
    assert_eq!(pool.charged_bytes(), original_charge);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "the secondary still owns the heap"
    );

    // The fault consumes capacity without disabling useful work that still fits.
    let ran = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&ran);
    let smaller = pool
        .try_spawn_charged(move || observed.store(1, Ordering::SeqCst), 0)
        .expect("a smaller job fits beside the quarantine");
    assert!(smaller.wait_timeout(WAIT));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(pool.charged_bytes(), original_charge);
}

/// A job type for factories that only ever panic: a boxed job has the same size wherever it comes from.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Holds the pool's only blocking thread until the returned sender is used.
fn hold_blocking_thread(
    pool: &BlockingPoolHandle,
    declared: usize,
) -> (asupersync::runtime::BlockingTaskHandle, mpsc::Sender<()>) {
    let (open, gate) = mpsc::channel::<()>();
    let (entered, running) = mpsc::channel::<()>();
    let held = pool
        .try_spawn_charged(
            move || {
                let _ = entered.send(());
                let _ = gate.recv_timeout(WAIT);
            },
            declared,
        )
        .expect("the pool admits the gate job");
    running.recv_timeout(WAIT).expect("the gate job is running");
    (held, open)
}

#[test]
fn a_factory_is_refused_unrun_for_a_full_queue_or_full_bytes_and_runs_once_when_there_is_room() {
    // One queue slot and 1_000 bytes.
    let runtime = bounded_runtime(1, 1000);
    let pool = pool_of(&runtime);
    let made = Arc::new(AtomicUsize::new(0));
    let ran = Arc::new(AtomicUsize::new(0));
    let factory = {
        let made = Arc::clone(&made);
        let ran = Arc::clone(&ran);
        move || {
            made.fetch_add(1, Ordering::SeqCst);
            move || {
                ran.fetch_add(1, Ordering::SeqCst);
            }
        }
    };

    // The queue is full: the only blocking thread is held and the one queue slot is taken.
    let (held, open) = hold_blocking_thread(&pool, 0);
    let queued = pool
        .try_spawn_charged(|| {}, 0)
        .expect("the one queue slot is free");
    let factory = match pool.try_spawn_charged_with(100, factory) {
        Err(BlockingFactoryError::Refused(refused)) => {
            assert_eq!(refused.kind(), BlockingSpawnErrorKind::Saturated);
            refused.into_inner()
        }
        other => panic!("expected a refusal before the factory ran, got {other:?}"),
    };
    assert_eq!(
        made.load(Ordering::SeqCst),
        0,
        "built a payload for a full queue"
    );
    open.send(()).unwrap();
    assert!(held.wait_timeout(WAIT) && queued.wait_timeout(WAIT));

    // The bytes are full: 950 declared bytes (and the gate job's own storage) leave no room for 100 more.
    let (held, open) = hold_blocking_thread(&pool, 950);
    let factory = match pool.try_spawn_charged_with(100, factory) {
        Err(BlockingFactoryError::Refused(refused)) => {
            assert_eq!(refused.kind(), BlockingSpawnErrorKind::ByteBudgetSaturated);
            refused.into_inner()
        }
        other => panic!("expected a refusal before the factory ran, got {other:?}"),
    };
    assert_eq!(
        made.load(Ordering::SeqCst),
        0,
        "built a payload for a full pool"
    );
    open.send(()).unwrap();
    assert!(held.wait_timeout(WAIT));

    // The permitted counterpart: with room, the very factory that came back is admitted, built once, and run.
    let job = pool
        .try_spawn_charged_with(100, factory)
        .expect("room for the same factory");
    assert!(job.wait_timeout(WAIT));
    assert_eq!(made.load(Ordering::SeqCst), 1);
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
fn the_pool_holds_the_payloads_bytes_before_the_factory_copies_into_them() {
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    // The caller's bounded input. The factory borrows it, which a `'static` closure could not.
    let source = vec![9_u8; 300];
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    let storage = Arc::new(AtomicUsize::new(0));
    let copied = Arc::new(AtomicUsize::new(0));
    let (seen_in, storage_in, copied_in, probe) = (
        Arc::clone(&seen),
        Arc::clone(&storage),
        Arc::clone(&copied),
        pool.clone(),
    );
    let task = pool
        .try_spawn_charged_with(source.len(), || {
            // Nothing has been copied yet; the reservation already exists.
            seen_in.store(probe.charged_bytes(), Ordering::SeqCst);
            let copy = source.clone();
            let job = move || copied_in.store(copy.len(), Ordering::SeqCst);
            storage_in.store(std::mem::size_of_val(&job), Ordering::SeqCst);
            job
        })
        .expect("the pool admits the factory");
    assert!(task.wait_timeout(WAIT));
    assert_eq!(
        seen.load(Ordering::SeqCst),
        source.len() + storage.load(Ordering::SeqCst)
    );
    assert_eq!(copied.load(Ordering::SeqCst), source.len());
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
fn a_factory_that_panics_with_its_vec_stays_charged_and_a_smaller_factory_still_runs() {
    const LIMIT: usize = 2048;
    const PAYLOAD: usize = 1024;
    let runtime = bounded_runtime(4, LIMIT);
    let pool = pool_of(&runtime);
    let drops = Arc::new(AtomicUsize::new(0));

    // A factory on another thread holds its reservation while a waiter that needs the whole pool parks behind it.
    let (open, gate) = mpsc::channel::<()>();
    let (entered, running) = mpsc::channel::<()>();
    let builder_pool = pool.clone();
    let builder_drops = Arc::clone(&drops);
    let builder = std::thread::spawn(move || {
        let outcome = builder_pool.try_spawn_charged_with(PAYLOAD, move || -> Job {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
            // The payload is allocated only now, inside the reservation, and then unwinds with the SAME Vec.
            let owned = RetainedHeap {
                bytes: vec![0; PAYLOAD],
                drops: builder_drops,
            };
            std::panic::resume_unwind(Box::new(TransferOnDrop(Some(owned))));
        });
        match outcome {
            Err(BlockingFactoryError::FactoryPanicked { quarantined }) => Some(quarantined),
            _ => None,
        }
    });
    running.recv_timeout(WAIT).unwrap();
    let original_charge = pool.charged_bytes();
    assert_eq!(original_charge, PAYLOAD + std::mem::size_of::<Job>());

    let mut waiting = pin!(pool.submit_charged(|| {}, LIMIT));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut context = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut context).is_pending());
    open.send(()).unwrap();
    wakes.wait_for_wake();
    assert_eq!(
        builder.join().unwrap(),
        Some(true),
        "the factory reported its panic and that the pool pinned its reservation"
    );
    match waiting.as_mut().poll(&mut context) {
        Poll::Ready(Err(refused)) => {
            assert_eq!(
                refused.kind(),
                BlockingSpawnErrorKind::ByteBudgetQuarantined
            );
        }
        Poll::Ready(Ok(_)) => panic!("an impossible request was admitted"),
        Poll::Pending => panic!("an impossible request was left waiting after quarantine"),
    }
    assert_eq!(pool.quarantined_bytes(), original_charge);
    assert_eq!(pool.charged_bytes(), original_charge);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "the secondary payload still owns the Vec"
    );

    // The fault consumes capacity without disabling work that still fits, through the same factory path.
    let ran = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&ran);
    let smaller = pool
        .try_spawn_charged_with(0, move || move || observed.store(1, Ordering::SeqCst))
        .expect("a smaller factory fits beside the quarantine");
    assert!(smaller.wait_timeout(WAIT));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(pool.charged_bytes(), original_charge);
}

#[test]
fn a_stderr_write_is_refused_while_the_queue_is_full_and_written_when_there_is_room() {
    // One queue slot, plenty of bytes.
    let runtime = bounded_runtime(1, 4096);
    let pool = pool_of(&runtime);
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());

    // The queue is full: the blocking thread is held and the one slot is taken. The write is refused, and the pool has
    // no declared payload byte from it was admitted. The inline copy counter separately checks that no copy ran.
    let (held, open) = hold_blocking_thread(&pool, 0);
    let queued = pool
        .try_spawn_charged(|| {}, 0)
        .expect("the one queue slot is free");
    let refused = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(&refused, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock),
        "{refused:?}"
    );
    assert_eq!(pool.charged_declared_bytes(), 0);
    open.send(()).unwrap();
    assert!(held.wait_timeout(WAIT) && queued.wait_timeout(WAIT));

    // The permitted counterpart, on the same pool: with the slot free, the same write is accepted in full and its job
    // waits behind a held thread having declared exactly the bytes it copied. Then it runs and the flush completes.
    let (held, open) = hold_blocking_thread(&pool, 0);
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    assert_eq!(pool.charged_declared_bytes(), MARKER.len());
    open.send(()).unwrap();
    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes");
    assert!(held.wait_timeout(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
}

/// Pins about `bytes` of `pool` for good, the way a factory that panics with the `Vec` it allocated does. Returns the
/// number of bytes the pool now reports pinned beyond what it did before.
fn pin_bytes(pool: &BlockingPoolHandle, bytes: usize) -> usize {
    let before = pool.quarantined_bytes();
    let drops = Arc::new(AtomicUsize::new(0));
    let outcome = pool.try_spawn_charged_with(bytes, move || -> Job {
        let owned = RetainedHeap {
            bytes: Vec::new(),
            drops,
        };
        std::panic::resume_unwind(Box::new(TransferOnDrop(Some(owned))));
    });
    assert!(
        matches!(
            outcome,
            Err(BlockingFactoryError::FactoryPanicked { quarantined: true })
        ),
        "{outcome:?}"
    );
    let pinned = pool.quarantined_bytes() - before;
    assert_eq!(pinned, bytes + std::mem::size_of::<Job>());
    pinned
}

#[test]
fn a_stderr_write_tells_a_pool_too_small_for_any_write_from_one_whose_room_was_pinned() {
    // Too small: the limit itself cannot hold a write job plus one byte, however empty the pool is.
    {
        let runtime = bounded_runtime(2, 16);
        let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
        let pool = pool_of(&runtime);
        let wakes = Wakes::new(&pool);
        let waker = wakes.waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = pin!(stderr());
        let outcome = writer.as_mut().poll_write(&mut cx, MARKER);
        let kind = match &outcome {
            Poll::Ready(Err(error)) => Some(error.kind()),
            _ => None,
        };
        assert_eq!(kind, Some(io::ErrorKind::InvalidInput), "{outcome:?}");
        assert_eq!(pool.charged_bytes(), 0);
    }

    // Pinned: the original limit holds a write, and a fault later takes the room.
    let runtime = bounded_runtime(2, 4096);
    let pool = pool_of(&runtime);
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());

    // Most of the pool is pinned, but a smaller write still runs, in full, through the same pool.
    let first = pin_bytes(&pool, 3000);
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes beside the pin");
    assert_eq!(pool.charged_bytes(), first);

    // Pin all but 8 bytes: no write job (or flush job) fits any more. That is a fault of the pool, not an invalid
    // request: `Other`, with the reason, and never `Ok(0)` or `WouldBlock`.
    let second = 4096 - first - 8;
    let _ = pin_bytes(&pool, second - std::mem::size_of::<Job>());
    let outcome = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(
            &outcome,
            Poll::Ready(Err(error))
                if error.kind() == io::ErrorKind::Other && error.to_string().contains("pinned")
        ),
        "{outcome:?}"
    );
    let flush = writer.as_mut().poll_flush(&mut cx);
    assert!(
        matches!(&flush, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Other),
        "{flush:?}"
    );
}

/// The limit of the pools in the tests that start from a budgeted profile. A write job's own storage is a few dozen
/// bytes and `MARKER` is 44, so one write fits and a pool nearly full of a holder's bytes does not take it.
const PROFILED: usize = 1000;

#[test]
fn a_profile_that_states_a_byte_budget_builds_the_pool_the_writer_uses_and_the_audit_pins_it() {
    let profile = budgeted_profile(2, 4096);
    assert_eq!(profile.blocking_live_bytes(), NonZeroUsize::new(4096));
    let runtime = profile
        .build()
        .expect("the profile builds a runtime that carries exactly what it states");
    let pool = pool_of(&runtime);
    assert_eq!(
        pool.admission_policy(),
        BlockingAdmissionPolicy::BoundedBytes {
            max_queued: NonZeroUsize::new(2).unwrap(),
            max_live_bytes: NonZeroUsize::new(4096).unwrap(),
        }
    );
    profile
        .audit(&runtime)
        .expect("the runtime the profile built is the one it states");

    // Admit, copy and retire on that pool: it already holds the declared bytes while the factory copies into them, and
    // every byte is back once the job is done.
    let source = vec![3_u8; 200];
    let reserved_in_factory = Arc::new(AtomicUsize::new(usize::MAX));
    let copied = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (seen, sink, probe) = (
        Arc::clone(&reserved_in_factory),
        Arc::clone(&copied),
        pool.clone(),
    );
    let job = pool
        .try_spawn_charged_with(source.len(), || {
            seen.store(probe.charged_bytes(), Ordering::SeqCst);
            let copy = source.clone();
            move || *sink.lock().unwrap() = copy
        })
        .expect("the pool the profile built admits a charged factory");
    assert!(job.wait_timeout(WAIT));
    assert!(reserved_in_factory.load(Ordering::SeqCst) >= source.len());
    assert_eq!(*copied.lock().unwrap(), source);
    assert_eq!(pool.charged_bytes(), 0);

    // Write: the real stderr writer, through the context the same runtime issues, uses that very pool. Its job waits
    // behind a held thread, so the pool shows exactly the bytes the write declared.
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());
    let (held, open) = hold_blocking_thread(&pool, 0);
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    assert_eq!(pool.charged_declared_bytes(), MARKER.len());
    open.send(()).unwrap();
    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes");
    assert!(held.wait_timeout(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
fn a_profile_audit_refuses_a_missing_or_different_budget_and_leaves_budgetless_profiles_alone() {
    let stated = budgeted_profile(4, 2048);
    let exact = stated
        .build()
        .expect("the profile builds a runtime that carries exactly what it states");
    stated.audit(&exact).expect("the exact runtime is accepted");

    // Missing: the same caps without a budget build a count-only pool, which shows the very same queue bound.
    let budgetless = budgetless_profile(4);
    assert_eq!(budgetless.blocking_live_bytes(), None);
    let count_only = budgetless
        .build()
        .expect("a profile without a budget builds");
    assert_eq!(
        policy_of(&count_only),
        BlockingAdmissionPolicy::Bounded {
            max_queued: NonZeroUsize::new(4).unwrap(),
        },
        "a profile that states no budget still builds the count-only pool"
    );
    let error = stated
        .audit(&count_only)
        .expect_err("a count-only pool is not the stated byte-bounded one");
    assert_eq!(error.kind(), ErrorKind::ConfigError);
    let message = error.message().unwrap();
    assert!(message.contains("live-byte budget of 2048"), "{message}");

    // Different: a byte-bounded pool with another budget is refused too, and the message names both.
    let other = budgeted_profile(4, 4096)
        .build()
        .expect("another budget builds");
    let error = stated
        .audit(&other)
        .expect_err("another budget is not the stated one");
    assert_eq!(error.kind(), ErrorKind::ConfigError);
    let message = error.message().unwrap();
    assert!(
        message.contains("2048") && message.contains("4096"),
        "{message}"
    );

    // Old profiles: one that states no budget accepts the runtimes it always accepted, byte-bounded or not, including
    // the one `bounded_runtime` makes by overriding the builder.
    budgetless
        .audit(&count_only)
        .expect("a budgetless profile accepts its own runtime");
    budgetless
        .audit(&exact)
        .expect("a budgetless profile does not constrain the byte policy");
    budgetless
        .audit(&bounded_runtime(4, 2048))
        .expect("the builder-override runtime is still accepted");
    // The plant it is paired with: caps that do differ are refused whatever the budget.
    let wider = LegacyProfile::new(profile_caps(5), budgetless.stack_budget_bytes());
    assert!(wider.audit(&count_only).is_err());
}

/// The admission policy of a runtime's blocking pool.
fn policy_of(runtime: &Runtime) -> BlockingAdmissionPolicy {
    runtime
        .blocking_handle()
        .expect("the runtime has a blocking pool")
        .admission_policy()
}

#[test]
fn a_profile_pool_refuses_uncharged_work_and_a_write_that_does_not_fit_then_takes_it_later() {
    let runtime = budgeted_profile(4, PROFILED)
        .build()
        .expect("the profile builds a runtime that carries exactly what it states");
    let pool = pool_of(&runtime);
    let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
    let wakes = Wakes::new(&pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());

    // A byte-bounded pool refuses every uncharged submission, by name, and runs nothing of it ...
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ran);
    let refused = pool.try_spawn(move || {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(BlockingSpawnErrorKind::ChargeRequired)
    );
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(pool.charged_bytes(), 0);
    // ... and a declared charge, even of 0 bytes, is admitted and runs once.
    let counted = Arc::clone(&ran);
    let declared = pool
        .try_spawn_charged(
            move || {
                counted.fetch_add(1, Ordering::SeqCst);
            },
            0,
        )
        .expect("a declared charge is admitted");
    assert!(declared.wait_timeout(WAIT));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(pool.charged_bytes(), 0);

    // The room is measured, not assumed: what the pool charges for the gate job when it declares nothing is the gate
    // job's own storage. A holder then takes all but 8 bytes of the budget.
    let (held, open) = hold_blocking_thread(&pool, 0);
    let gate_storage = pool.charged_bytes();
    open.send(()).unwrap();
    assert!(held.wait_timeout(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
    assert!(gate_storage + 8 < PROFILED, "{gate_storage}");
    let (held, open) = hold_blocking_thread(&pool, PROFILED - 8 - gate_storage);
    assert_eq!(pool.charged_bytes(), PROFILED - 8);

    // Bytes, not the queue, are what is full: the queue has room, and 9 bytes do not fit in 8.
    let probe = pool.try_spawn_charged(|| {}, 9);
    assert_eq!(
        probe.err().map(|error| error.kind()),
        Some(BlockingSpawnErrorKind::ByteBudgetSaturated)
    );
    let refused = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(&refused, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock),
        "{refused:?}"
    );
    assert_eq!(
        pool.charged_bytes(),
        PROFILED - 8,
        "the refused write reserved nothing"
    );

    // The permitted counterpart, on the same pool and the same writer: once the holder has retired, the same write is
    // accepted in full and the flush completes with nothing left reserved.
    open.send(()).unwrap();
    assert!(held.wait_timeout(WAIT));
    assert_eq!(pool.charged_bytes(), 0);
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes");
    assert_eq!(pool.charged_bytes(), 0);
}

#[test]
fn a_profile_that_forbids_blocking_ignores_a_byte_budget_and_its_pool_refuses_the_writer() {
    let caps = LegacyCaps {
        blocking_max_threads: 0,
        blocking_max_queued: 0,
        blocking_thread_stack_bytes: 0,
        ..profile_caps(2)
    };
    let plain = LegacyProfile::new(caps, u64::try_from(WORKER_STACK).unwrap());
    let stated = plain.with_blocking_live_bytes(NonZeroUsize::new(4096).unwrap());
    let runtime = stated
        .build()
        .expect("a budget is accepted and ignored when blocking is forbidden");
    let pool = runtime
        .blocking_handle()
        .expect("a forbidding pool, not an absent one");
    assert_eq!(pool.admission_policy(), BlockingAdmissionPolicy::Forbidden);
    assert_eq!(
        policy_of(&plain.build().unwrap()),
        BlockingAdmissionPolicy::Forbidden,
        "the same pool as the profile without a budget"
    );
    stated
        .audit(&runtime)
        .expect("a forbidding pool meets a forbidding profile");

    // The real writer on that pool is refused by name, and nothing is reserved or run.
    {
        let _ambient = Cx::set_current(Some(runtime.request_cx_with_budget(Budget::INFINITE)));
        let wakes = Wakes::new(&pool);
        let waker = wakes.waker();
        let mut cx = Context::from_waker(&waker);
        let mut writer = pin!(stderr());
        let refused = writer.as_mut().poll_write(&mut cx, MARKER);
        assert!(
            matches!(&refused, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Unsupported),
            "{refused:?}"
        );
        assert_eq!(pool.charged_bytes(), 0);
    }

    // Paired refusal: a byte-bounded pool of a profile that allows blocking does not meet a profile that forbids it.
    let allowing_profile = budgeted_profile(2, 4096);
    let allowing = allowing_profile
        .build()
        .expect("the allowing profile builds");
    let error = stated
        .audit(&allowing)
        .expect_err("a pool that admits work does not meet a profile that forbids it");
    assert_eq!(error.kind(), ErrorKind::ConfigError);
    assert!(
        error.message().unwrap().contains("absent or admits work"),
        "{:?}",
        error.message()
    );

    // The permitted counterpart: that profile, stating the same budget, takes the same write.
    let allowing_pool = pool_of(&allowing);
    let _ambient = Cx::set_current(Some(allowing.request_cx_with_budget(Budget::INFINITE)));
    let wakes = Wakes::new(&allowing_pool);
    let waker = wakes.waker();
    let mut cx = Context::from_waker(&waker);
    let mut writer = pin!(stderr());
    let accepted = writer.as_mut().poll_write(&mut cx, MARKER);
    assert!(
        matches!(accepted, Poll::Ready(Ok(written)) if written == MARKER.len()),
        "{accepted:?}"
    );
    wakes
        .settle("the flush", |cx| writer.as_mut().poll_flush(cx))
        .expect("the flush completes");
    assert_eq!(allowing_pool.charged_bytes(), 0);
}
