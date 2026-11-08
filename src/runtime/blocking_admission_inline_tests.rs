#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::runtime::blocking_pool::{BlockingPoolOptions, BlockingQueuePolicy};
use crate::runtime::config::BlockingPoolAffinityProfile;
use crate::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
use std::sync::atomic::AtomicUsize;
use std::sync::{Barrier, Weak, mpsc};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);

fn policy(capacity: usize) -> BlockingAdmissionPolicy {
    BlockingAdmissionPolicy::Bounded {
        max_queued: NonZeroUsize::new(capacity).unwrap(),
    }
}

fn pool(capacity: usize) -> BlockingPool {
    BlockingPool::with_config_and_policies(
        1,
        1,
        BlockingPoolOptions {
            thread_name_prefix: "bounded-admission".to_owned(),
            ..Default::default()
        },
        BlockingQueuePolicy::Fifo,
        policy(capacity),
    )
}

fn hold_worker(pool: &BlockingPoolHandle) -> (BlockingTaskHandle, mpsc::Sender<()>) {
    let (entered, entry) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let task = pool
        .try_spawn(move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        })
        .unwrap();
    entry.recv_timeout(WAIT).unwrap();
    (task, release)
}

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .expect("bounded blocking admission scenario must terminate");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

struct CaptureProbe {
    pool: BlockingPoolHandle,
    drops: Arc<AtomicUsize>,
}

impl Drop for CaptureProbe {
    fn drop(&mut self) {
        // Actual reentry would deadlock if destruction held either mutex.
        let _ = self.pool.try_spawn(|| {});
        let _waiter_count = self.pool.inner.admission.waiters.lock().len();
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct WakeProbe {
    pool: Weak<BlockingPoolInner>,
    signal: mpsc::Sender<()>,
}

impl std::task::Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        if let Some(pool) = self.pool.upgrade() {
            // Real lock acquisition tolerates other threads holding them and
            // detects same-thread wake-under-lock by the outer test timeout.
            drop(pool.mutex.lock());
            drop(pool.admission.waiters.lock());
        }
        self.signal.send(()).unwrap();
    }
}

fn wake_probe(pool: &BlockingPool) -> (Waker, mpsc::Receiver<()>) {
    let (signal, receive) = mpsc::channel();
    let waker = Waker::from(Arc::new(WakeProbe {
        pool: Arc::downgrade(&pool.inner),
        signal,
    }));
    (waker, receive)
}

#[test]
fn refusal_recovers_work_and_running_jobs_do_not_consume_queue_capacity() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        assert_eq!(pool.pending_count(), 1);
        assert_eq!(pool.busy_threads(), 1);

        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let capture = CaptureProbe {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
        };
        let called = Arc::clone(&calls);
        let rejected = pool
            .try_spawn(move || {
                called.fetch_add(1, Ordering::SeqCst);
                drop(capture);
            })
            .unwrap_err();
        assert_eq!(rejected.kind(), BlockingSpawnErrorKind::Saturated);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert_eq!(pool.pending_count(), 1);

        let old_api_called = Arc::clone(&calls);
        let refused = pool.spawn(move || {
            old_api_called.fetch_add(100, Ordering::SeqCst);
        });
        assert!(refused.is_cancelled());
        assert!(refused.is_done());
        assert_eq!(pool.pending_count(), 1);

        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        let retried = pool.try_spawn(rejected.into_inner()).unwrap();
        assert!(retried.wait_timeout(WAIT));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(
            pool.try_spawn(|| {}).unwrap_err().kind(),
            BlockingSpawnErrorKind::Shutdown
        );
    });
}

#[test]
fn waiting_submission_parks_and_resumes_after_dequeue() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let called = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&called);
        let mut submission = pool.submit(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let (waker, wake) = wake_probe(&pool);
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        assert!(matches!(wake.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(called.load(Ordering::SeqCst), 0);

        release.send(()).unwrap();
        wake.recv_timeout(WAIT).unwrap();
        let accepted = futures_lite::future::block_on(submission).unwrap();
        assert!(accepted.wait_timeout(WAIT));
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn dropping_a_waiting_submission_removes_registration_and_retires_work_outside_locks() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = CaptureProbe {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
        };
        let mut submission = pool.submit(move || drop(capture));
        let mut context = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        drop(submission);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(pool.pending_count(), 1);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn shutdown_wakes_waiting_submission_and_returns_its_uninvoked_work() {
    bounded(|| {
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let mut submission = pool.submit(move || {
            called.fetch_add(1, Ordering::SeqCst);
        });
        let (waker, wake) = wake_probe(&pool);
        assert!(
            Pin::new(&mut submission)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        pool.shutdown();
        wake.recv_timeout(WAIT).unwrap();
        let refused = futures_lite::future::block_on(submission).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::Shutdown);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        refused.into_inner()();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn concurrent_cohort_submissions_share_one_hard_queue_bound() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions {
                affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 1,
                    spill_check_interval: 1,
                },
                cohort_count: Some(2),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            policy(3),
        );
        let (running, release) = hold_worker(&pool.handle());
        let start = Arc::new(Barrier::new(9));
        let results = std::thread::scope(|scope| {
            let submitters: Vec<_> = (0..8)
                .map(|index| {
                    let handle = pool.handle();
                    let start = Arc::clone(&start);
                    scope.spawn(move || {
                        start.wait();
                        handle
                            .try_spawn_on_cohort_with_priority(index % 2, || {}, 128)
                            .map_err(|error| error.kind())
                    })
                })
                .collect();
            start.wait();
            submitters
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(BlockingSpawnErrorKind::Saturated)))
                .count(),
            5
        );
        assert_eq!(pool.pending_count(), 3);
        let metrics = pool.affinity_metrics();
        assert_eq!(
            metrics.global_pending_count + metrics.cohort_pending_counts.iter().sum::<usize>(),
            3
        );
        release.send(()).unwrap();
        for task in results.into_iter().filter_map(Result::ok) {
            assert!(task.wait_timeout(WAIT));
        }
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn bounded_cohort_queue_keeps_priority_selection() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions {
                affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 4,
                    spill_check_interval: 8,
                },
                cohort_count: Some(1),
                ..Default::default()
            },
            BlockingQueuePolicy::Priority {
                max_priority_streak: NonZeroUsize::new(4).unwrap(),
            },
            policy(2),
        );
        let (running, release) = hold_worker(&pool.handle());
        let (order, received) = mpsc::channel();
        let low_sender = order.clone();
        let low = pool
            .try_spawn_on_cohort_with_priority(0, move || low_sender.send(1).unwrap(), 1)
            .unwrap();
        let high = pool
            .try_spawn_on_cohort_with_priority(0, move || order.send(200).unwrap(), 200)
            .unwrap();
        assert_eq!(
            pool.try_spawn(|| {}).unwrap_err().kind(),
            BlockingSpawnErrorKind::Saturated
        );
        release.send(()).unwrap();
        assert_eq!(received.recv_timeout(WAIT).unwrap(), 200);
        assert_eq!(received.recv_timeout(WAIT).unwrap(), 1);
        assert!(low.wait_timeout(WAIT));
        assert!(high.wait_timeout(WAIT));
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn ordinary_async_blocking_waits_for_capacity_without_inline_or_fallback_execution() {
    bounded(|| {
        struct PinnedCapture {
            _pin: std::marker::PhantomPinned,
        }
        let pool = pool(1);
        let (running, release) = hold_worker(&pool.handle());
        let queued = pool.try_spawn(|| {}).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let pinned = PinnedCapture {
            _pin: std::marker::PhantomPinned,
        };
        let mut operation = Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
            pool.handle(),
            move || {
                let _pinned = std::hint::black_box(pinned);
                called.fetch_add(1, Ordering::SeqCst);
                std::thread::current().name().unwrap().to_owned()
            },
        ));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        release.send(()).unwrap();
        let thread_name = futures_lite::future::block_on(operation);
        assert!(
            thread_name.starts_with("bounded-admission-blocking-"),
            "{thread_name}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn drained_cancellation_retains_waiting_captures_until_a_blocking_worker_retires_them() {
    bounded(|| {
        for workers in [1, 2] {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::new().worker_threads(workers)
            };
            let runtime = builder
                .enable_platform_reactor(false)
                .blocking_threads(1, 1)
                .blocking_admission_policy(policy(1))
                .build()
                .unwrap();
            let pool = runtime.blocking_handle().unwrap();
            assert_eq!(pool.admission_policy(), policy(1));
            let (running, release_pool) = hold_worker(&pool);
            let queued = pool.try_spawn(|| {}).unwrap();
            let (dropping, drop_entered) = mpsc::channel();
            let (release_drop, drop_gate) = mpsc::channel();
            let drops = Arc::new(AtomicUsize::new(0));
            struct BlockingCapture {
                dropping: mpsc::Sender<String>,
                gate: mpsc::Receiver<()>,
                drops: Arc<AtomicUsize>,
            }
            impl Drop for BlockingCapture {
                fn drop(&mut self) {
                    self.dropping
                        .send(std::thread::current().name().unwrap().to_owned())
                        .unwrap();
                    self.gate.recv_timeout(WAIT).unwrap();
                    self.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
            let capture = BlockingCapture {
                dropping,
                gate: drop_gate,
                drops: Arc::clone(&drops),
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let called = Arc::clone(&calls);
            let mut task = runtime
                .spawn_blocking_drained(move |_| {
                    called.fetch_add(1, Ordering::SeqCst);
                    drop(capture);
                    42_u8
                })
                .unwrap();
            runtime.block_on(async {
                let deadline = Instant::now() + WAIT;
                while pool.inner.admission.waiters.lock().is_empty() {
                    assert!(
                        Instant::now() < deadline,
                        "drained work must reach pending admission"
                    );
                    crate::runtime::yield_now::yield_now().await;
                }
            });
            task.abort_with_reason(crate::types::CancelReason::user(
                "cancel while awaiting pool capacity",
            ));
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(report.live_tasks > 0);
            assert!(!task.is_finished());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert!(matches!(
                drop_entered.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));

            release_pool.send(()).unwrap();
            // Releasing capacity only wakes the admission future. Keep driving
            // a current-thread runtime until that future publishes the cancelled
            // envelope and its capture destructor actually starts.
            let deadline = Instant::now() + WAIT;
            let drop_thread = loop {
                match drop_entered.try_recv() {
                    Ok(thread) => break thread,
                    Err(mpsc::TryRecvError::Empty) => {
                        assert!(Instant::now() < deadline, "capture retirement must start");
                        let report = runtime.shutdown_drained(Duration::from_millis(1));
                        assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("capture retirement sender disappeared");
                    }
                }
            };
            assert!(drop_thread.contains("-blocking-"), "{drop_thread}");
            assert_eq!(pool.busy_threads(), 1);
            let report = runtime.shutdown_drained(Duration::from_millis(20));
            assert_eq!(report.outcome, RootDrainOutcome::TimedOut, "{report:?}");
            assert!(
                !task.is_finished(),
                "drain must wait for capture destruction"
            );
            release_drop.send(()).unwrap();
            let report = runtime.shutdown_drained(WAIT);
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert!(matches!(
                futures_lite::future::block_on(task.join()),
                Err(JoinError::Cancelled(_))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(running.wait_timeout(WAIT));
            assert!(queued.wait_timeout(WAIT));
        }
    });
}

fn forbidden_pool() -> BlockingPool {
    BlockingPool::with_config_and_policies(
        0,
        1,
        BlockingPoolOptions {
            thread_name_prefix: "forbidden-admission".to_owned(),
            ..Default::default()
        },
        BlockingQueuePolicy::Fifo,
        BlockingAdmissionPolicy::Forbidden,
    )
}

// `use<>`: the job owns a clone of the `Arc` and borrows nothing from the argument. Edition 2024 would otherwise
// capture the argument's lifetime in the return type, and a factory closure could not return `count_job(&ran)`.
fn count_job(ran: &Arc<AtomicUsize>) -> impl FnOnce() + Send + 'static + use<> {
    let ran = Arc::clone(ran);
    move || {
        ran.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_forbidden_pool_refuses_every_entry_point_unrun_and_starts_no_thread() {
    bounded(|| {
        let pool = forbidden_pool();
        let handle = pool.handle();
        assert_eq!(
            handle.admission_policy(),
            BlockingAdmissionPolicy::Forbidden
        );
        assert!(handle.forbids_blocking());
        let ran = Arc::new(AtomicUsize::new(0));

        let refused = pool.try_spawn(count_job(&ran)).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::Forbidden);
        let refused = handle.try_spawn(count_job(&ran)).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::Forbidden);
        // The plain spawn path completes a cancelled handle and queues nothing.
        let spawned = pool.spawn(count_job(&ran));
        assert!(spawned.is_cancelled());
        assert!(spawned.is_done());
        // A waiting submission resolves at once: waiting cannot help, so it never parks.
        let submitted = futures_lite::future::block_on(pool.submit(count_job(&ran)));
        assert_eq!(
            submitted.unwrap_err().kind(),
            BlockingSpawnErrorKind::Forbidden
        );

        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.active_threads(), 0);
        assert_eq!(pool.busy_threads(), 0);
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        // A closed forbidden pool still says Forbidden: it must not hand work back as a shutdown, which the
        // async entry points would run inline.
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(
            pool.try_spawn(count_job(&ran)).unwrap_err().kind(),
            BlockingSpawnErrorKind::Forbidden
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        // Remove the plant: the same options with an unbounded policy run the job on a pool thread.
        let open = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "open-admission".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            BlockingAdmissionPolicy::Unbounded,
        );
        assert!(!open.handle().forbids_blocking());
        let task = open.try_spawn(count_job(&ran)).unwrap();
        assert!(task.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(open.shutdown_and_wait(WAIT));
    });
}

#[test]
fn only_the_forbidden_policy_is_forbidden() {
    let unbounded = BlockingAdmissionPolicy::default();
    assert_eq!(unbounded, BlockingAdmissionPolicy::Unbounded);
    assert_ne!(unbounded, BlockingAdmissionPolicy::Forbidden);
    assert_ne!(policy(1), BlockingAdmissionPolicy::Forbidden);
    assert!(BlockingSpawnErrorKind::Forbidden.is_final());
    assert!(BlockingSpawnErrorKind::Shutdown.is_final());
    assert!(!BlockingSpawnErrorKind::Saturated.is_final());
    let bounded_pool = pool(1);
    let handle = bounded_pool.handle();
    assert_ne!(
        handle.admission_policy(),
        BlockingAdmissionPolicy::Forbidden
    );
    assert!(!handle.forbids_blocking());
    assert!(bounded_pool.shutdown_and_wait(WAIT));
}

// ---------------------------------------------------------------------------------------------------- captured bytes

fn bytes_policy(max_queued: usize, max_live_bytes: usize) -> BlockingAdmissionPolicy {
    BlockingAdmissionPolicy::BoundedBytes {
        max_queued: NonZeroUsize::new(max_queued).unwrap(),
        max_live_bytes: NonZeroUsize::new(max_live_bytes).unwrap(),
    }
}

fn byte_pool(max_queued: usize, max_live_bytes: usize) -> BlockingPool {
    BlockingPool::with_config_and_policies(
        1,
        1,
        BlockingPoolOptions {
            thread_name_prefix: "byte-admission".to_owned(),
            ..Default::default()
        },
        BlockingQueuePolicy::Fifo,
        bytes_policy(max_queued, max_live_bytes),
    )
}

/// What the pool measures for a closure of this type: its size rounded up to its alignment. The tests compute it
/// independently of the pool, from the value they are about to submit.
fn storage_of<F>(_job: &F) -> usize {
    std::alloc::Layout::new::<F>().pad_to_align().size()
}

/// Occupies the only worker with a job that declares `declared` heap bytes and waits for the returned sender.
/// Also returns the storage the pool measures for that job's closure.
fn hold_charged_worker(
    pool: &BlockingPoolHandle,
    declared: usize,
) -> (BlockingTaskHandle, mpsc::Sender<()>, usize) {
    let (entered, entry) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let job = move || {
        entered.send(()).unwrap();
        gate.recv_timeout(WAIT).unwrap();
    };
    let storage = storage_of(&job);
    let task = pool.try_spawn_charged(job, declared).unwrap();
    entry.recv_timeout(WAIT).unwrap();
    (task, release, storage)
}

/// A closure that captures `PAYLOAD` bytes inline, by value, and owns no heap behind a pointer.
const PAYLOAD: usize = 32 * 1024;

fn large_inline_job(ran: &Arc<AtomicUsize>) -> impl FnOnce() + Send + 'static {
    let payload = [7_u8; PAYLOAD];
    let ran = Arc::clone(ran);
    move || {
        ran.fetch_add(usize::from(payload[1]), Ordering::SeqCst);
    }
}

/// Records, when it is dropped, how many bytes the pool still had charged: a charge must outlive its captures.
struct ChargeObserver {
    pool: BlockingPoolHandle,
    seen_in_drop: Arc<AtomicUsize>,
}

impl Drop for ChargeObserver {
    fn drop(&mut self) {
        self.seen_in_drop
            .store(self.pool.charged_bytes(), Ordering::SeqCst);
    }
}

#[test]
fn the_byte_refusals_say_whether_waiting_can_help() {
    assert!(BlockingSpawnErrorKind::ChargeRequired.is_final());
    assert!(BlockingSpawnErrorKind::ChargeTooLarge.is_final());
    assert!(BlockingSpawnErrorKind::ByteBudgetQuarantined.is_final());
    assert!(!BlockingSpawnErrorKind::ByteBudgetSaturated.is_final());
    assert_ne!(bytes_policy(1, 1), policy(1));
    assert_ne!(bytes_policy(1, 1), BlockingAdmissionPolicy::Forbidden);
    assert_ne!(bytes_policy(2, 1), bytes_policy(2, 3));
}

#[test]
fn a_byte_pool_admits_small_jobs_keeps_the_two_components_apart_and_returns_both_after_release() {
    bounded(|| {
        let pool = byte_pool(8, 10_000);
        assert_eq!(pool.charged_bytes(), 0);
        let (running, release, held_storage) = hold_charged_worker(&pool.handle(), 400);
        // A running job keeps its bytes until its closure is gone; it is not a queued job. The pool measured the
        // closure itself and trusted the 400 declared: the two are never mixed.
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.charged_declared_bytes(), 400);
        assert_eq!(pool.charged_storage_bytes(), held_storage);
        assert_eq!(pool.charged_bytes(), 400 + held_storage);
        // A closure with no captures has no storage: only its declared heap is charged.
        let queued = pool.try_spawn_charged(|| {}, 500).unwrap();
        assert_eq!(pool.charged_declared_bytes(), 900);
        assert_eq!(pool.charged_storage_bytes(), held_storage);

        // 9_500 declared fits an empty pool but not beside the live jobs: refused, and the closure comes back unrun.
        let ran = Arc::new(AtomicUsize::new(0));
        let refused = pool.try_spawn_charged(count_job(&ran), 9_500).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::ByteBudgetSaturated);
        let recovered = refused.into_inner();
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(
            pool.charged_declared_bytes(),
            900,
            "a refusal reserves nothing"
        );
        assert_eq!(pool.charged_storage_bytes(), held_storage);

        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        // The permitted counterpart: the same closure is admitted once the bytes are free.
        let readmitted = pool.try_spawn_charged(recovered, 9_500).unwrap();
        assert!(readmitted.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_large_inline_capture_with_zero_declared_heap_cannot_enter_a_small_pool() {
    bounded(|| {
        let pool = byte_pool(4, 64);
        let ran = Arc::new(AtomicUsize::new(0));
        let job = large_inline_job(&ran);
        assert!(
            storage_of(&job) >= PAYLOAD,
            "the array is captured by value, inline"
        );

        // Declared heap is 0, so a pool that counted only the declaration would admit it. The pool measures the
        // closure it would box and queue, so it does not.
        let refused = pool.try_spawn_charged(job, 0).unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::ChargeTooLarge);
        drop(refused);
        let mut submission = pool.submit_charged(large_inline_job(&ran), 0);
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(&mut submission).poll(&mut context) {
            Poll::Ready(Err(error)) => {
                assert_eq!(error.kind(), BlockingSpawnErrorKind::ChargeTooLarge);
            }
            _ => panic!("a closure that can never fit must be refused at once, not parked"),
        }
        drop(submission);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        // The permitted counterparts on the same 64-byte pool: a closure with no captures and a small one.
        let empty = pool.try_spawn_charged(|| {}, 0).unwrap();
        assert!(empty.wait_timeout(WAIT));
        let small = pool.try_spawn_charged(count_job(&ran), 0).unwrap();
        assert!(small.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn the_pool_charges_an_inline_capture_the_submitter_never_declared() {
    bounded(|| {
        let pool = byte_pool(4, 1 << 20);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let payload = [1_u8; PAYLOAD];
        let job = move || {
            let _inline = &payload;
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        };
        let storage = storage_of(&job);
        assert!(storage >= PAYLOAD);
        let task = pool.try_spawn_charged(job, 0).unwrap();
        entry.recv_timeout(WAIT).unwrap();
        // Nothing was declared, yet the live job is charged what it occupies.
        assert_eq!(pool.charged_declared_bytes(), 0);
        assert_eq!(pool.charged_storage_bytes(), storage);
        assert_eq!(pool.charged_bytes(), storage);
        release.send(()).unwrap();
        assert!(task.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn an_impossible_total_is_refused_for_good_and_exactly_the_limit_is_admitted() {
    bounded(|| {
        let pool = byte_pool(4, 1_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let storage = storage_of(&count_job(&ran));
        assert!(storage > 0 && storage < 1_000);

        // One declared byte too many for the whole limit, counting the measured storage.
        let refused = pool
            .try_spawn_charged(count_job(&ran), 1_000 - storage + 1)
            .unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::ChargeTooLarge);
        drop(refused);
        // A declaration that overflows the sum is a charge that can never fit, not a wrapped small one.
        let refused = pool
            .try_spawn_charged(count_job(&ran), usize::MAX)
            .unwrap_err();
        assert_eq!(refused.kind(), BlockingSpawnErrorKind::ChargeTooLarge);
        drop(refused);

        // The asynchronous entry point does not park on a charge that can never fit.
        let mut submission = pool.submit_charged(count_job(&ran), usize::MAX - 1);
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(&mut submission).poll(&mut context) {
            Poll::Ready(Err(error)) => {
                assert_eq!(error.kind(), BlockingSpawnErrorKind::ChargeTooLarge);
            }
            _ => panic!("an impossible charge must be refused at once"),
        }
        drop(submission);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        // The permitted counterpart: exactly the whole limit is admitted.
        let exact = pool
            .try_spawn_charged(count_job(&ran), 1_000 - storage)
            .unwrap();
        assert!(exact.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_byte_pool_refuses_every_uncharged_entry_point_unrun_and_never_inline() {
    bounded(|| {
        let pool = byte_pool(4, 10_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let kinds = [
            pool.try_spawn(count_job(&ran)).unwrap_err().kind(),
            pool.handle()
                .try_spawn_with_priority(count_job(&ran), 7)
                .unwrap_err()
                .kind(),
            pool.try_spawn_on_cohort_with_priority(0, count_job(&ran), 7)
                .unwrap_err()
                .kind(),
        ];
        assert_eq!(kinds, [BlockingSpawnErrorKind::ChargeRequired; 3]);

        // `submit` is refused at once and does not park.
        let mut submission = pool.submit(count_job(&ran));
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(&mut submission).poll(&mut context) {
            Poll::Ready(Err(error)) => {
                assert_eq!(error.kind(), BlockingSpawnErrorKind::ChargeRequired);
            }
            _ => panic!("an uncharged submission must be refused at once"),
        }
        drop(submission);

        // The infallible `spawn` hands back a completed, cancelled handle and drops the closure unrun.
        let spawned = pool.spawn(count_job(&ran));
        assert!(spawned.is_cancelled());
        assert!(spawned.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.inner.admission.waiters.lock().is_empty());

        // After shutdown a missing charge is still a missing charge and not `Shutdown`, which would hand the closure
        // back to entry points that run a handed-back closure inline; a stated charge reports the shutdown.
        pool.shutdown();
        assert_eq!(
            pool.try_spawn(count_job(&ran)).unwrap_err().kind(),
            BlockingSpawnErrorKind::ChargeRequired
        );
        assert_eq!(
            pool.try_spawn_charged(count_job(&ran), 1)
                .unwrap_err()
                .kind(),
            BlockingSpawnErrorKind::Shutdown
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn the_value_returning_compatibility_sink_refuses_on_a_byte_pool_and_never_runs_inline() {
    bounded(|| {
        let pool = byte_pool(4, 10_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&ran);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures_lite::future::block_on(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
                pool.handle(),
                move || {
                    called.fetch_add(1, Ordering::SeqCst);
                    7_u32
                },
            ))
        }));
        let payload = outcome.expect_err("a byte pool refuses an operation that declares no heap");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("bounds live job bytes"), "{message}");
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_reservation_outlives_the_closure_and_cancelling_the_handle_releases_nothing() {
    bounded(|| {
        let pool = byte_pool(4, 1_000);
        let (running, release, held_storage) = hold_charged_worker(&pool.handle(), 10);
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = ChargeObserver {
            pool: pool.handle(),
            seen_in_drop: Arc::clone(&seen),
        };
        let ran = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&ran);
        let job = move || {
            let _held = &observer;
            called.fetch_add(1, Ordering::SeqCst);
        };
        let queued_storage = storage_of(&job);
        let queued = pool.try_spawn_charged(job, 60).unwrap();
        let live = 10 + held_storage + 60 + queued_storage;
        assert_eq!(pool.charged_bytes(), live);

        queued.cancel();
        assert!(queued.is_cancelled());
        // Cancelling closes the claim gate but the closure is still alive in the queue: nothing is released, and the
        // bytes still count against the limit.
        assert_eq!(pool.charged_bytes(), live);
        assert_eq!(seen.load(Ordering::SeqCst), usize::MAX);
        let blocked = pool.try_spawn_charged(|| {}, 900).unwrap_err();
        assert_eq!(blocked.kind(), BlockingSpawnErrorKind::ByteBudgetSaturated);

        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        // The worker skipped the cancelled job and dropped its closure. This job's own bytes were still reserved at
        // that moment (the running job's had been returned first): the reservation goes back after the closure.
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(seen.load(Ordering::SeqCst), 60 + queued_storage);
        assert_eq!(pool.charged_bytes(), 0);
        // The permitted counterpart: the freed bytes are admissible again.
        let again = pool.try_spawn_charged(|| {}, 900).unwrap();
        assert!(again.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_panicking_charged_job_releases_its_reservation_and_the_pool_keeps_admitting() {
    bounded(|| {
        let pool = byte_pool(4, 1_000);
        let panicking = pool
            .try_spawn_charged(|| panic!("charged job panics on purpose"), 900)
            .unwrap();
        assert!(panicking.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        // Admissible only if the panicking job's 900 went back.
        let ran = Arc::new(AtomicUsize::new(0));
        let next = pool.try_spawn_charged(count_job(&ran), 900).unwrap();
        assert!(next.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_waiting_charged_submission_reserves_nothing_and_is_admitted_when_the_closure_is_gone() {
    bounded(|| {
        let pool = byte_pool(4, 1_000);
        let (running, release, held_storage) = hold_charged_worker(&pool.handle(), 900);
        let held = 900 + held_storage;
        let ran = Arc::new(AtomicUsize::new(0));
        let mut submission = pool.submit_charged(count_job(&ran), 300);
        let (waker, wake) = wake_probe(&pool);
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        assert_eq!(pool.charged_bytes(), held, "waiting reserves nothing");
        assert!(matches!(wake.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        // The running job's closure is gone: its reservation is returned and the waiter is woken.
        release.send(()).unwrap();
        wake.recv_timeout(WAIT).unwrap();
        let accepted = futures_lite::future::block_on(submission).unwrap();
        assert!(accepted.wait_timeout(WAIT));
        assert!(running.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn dropping_a_waiting_charged_submission_reserves_and_releases_nothing() {
    bounded(|| {
        let pool = byte_pool(4, 1_000);
        let (running, release, held_storage) = hold_charged_worker(&pool.handle(), 900);
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = CaptureProbe {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
        };
        let mut submission = pool.submit_charged(move || drop(capture), 300);
        let mut context = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut submission).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        drop(submission);
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            pool.charged_bytes(),
            900 + held_storage,
            "only the running job's bytes remain"
        );
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn the_byte_policy_keeps_the_job_count_bound_and_other_policies_ignore_a_declared_charge() {
    bounded(|| {
        let metered = byte_pool(1, 100_000);
        let (running, release, held_storage) = hold_charged_worker(&metered.handle(), 1);
        let queued = metered.try_spawn_charged(|| {}, 1).unwrap();
        // Plenty of byte room, but the one queue slot is taken.
        assert_eq!(
            metered.try_spawn_charged(|| {}, 1).unwrap_err().kind(),
            BlockingSpawnErrorKind::Saturated
        );
        assert_eq!(metered.charged_bytes(), 2 + held_storage);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert_eq!(metered.charged_bytes(), 0);
        assert!(metered.shutdown_and_wait(WAIT));

        // A count-bounded pool and an unbounded pool take a declared charge as a plain submission and track nothing.
        let ran = Arc::new(AtomicUsize::new(0));
        let counted = pool(2);
        let task = counted.try_spawn_charged(count_job(&ran), 12_345).unwrap();
        assert!(task.wait_timeout(WAIT));
        assert_eq!(counted.charged_bytes(), 0);
        assert!(counted.shutdown_and_wait(WAIT));
        let open = BlockingPool::new(1, 1);
        assert_eq!(open.admission_policy(), BlockingAdmissionPolicy::Unbounded);
        let task = open.try_spawn_charged(count_job(&ran), usize::MAX).unwrap();
        assert!(task.wait_timeout(WAIT));
        assert_eq!(open.charged_bytes(), 0);
        assert_eq!(ran.load(Ordering::SeqCst), 2);
        assert!(open.shutdown_and_wait(WAIT));
    });
}

#[test]
fn concurrent_charged_submitters_never_exceed_the_limit_and_every_admitted_job_runs_and_releases() {
    bounded(|| {
        // Each job declares 1_000 bytes and its closure adds a few dozen of measured storage, so at most three or
        // four jobs are live at once under this limit.
        const LIMIT: usize = 4_096;
        const CHARGE: usize = 1_000;
        const SUBMITTERS: usize = 6;
        const JOBS_EACH: usize = 40;
        let pool = BlockingPool::with_config_and_policies(
            2,
            2,
            BlockingPoolOptions {
                thread_name_prefix: "byte-concurrent".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(64, LIMIT),
        );
        let highest = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..SUBMITTERS {
                let handle = pool.handle();
                let highest = Arc::clone(&highest);
                let ran = Arc::clone(&ran);
                scope.spawn(move || {
                    for _ in 0..JOBS_EACH {
                        let observer = handle.clone();
                        let highest = Arc::clone(&highest);
                        let ran = Arc::clone(&ran);
                        let admitted = futures_lite::future::block_on(handle.submit_charged(
                            move || {
                                highest.fetch_max(observer.charged_bytes(), Ordering::SeqCst);
                                ran.fetch_add(1, Ordering::SeqCst);
                            },
                            CHARGE,
                        ))
                        .unwrap();
                        drop(admitted);
                    }
                });
            }
        });
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), SUBMITTERS * JOBS_EACH);
        let highest = highest.load(Ordering::SeqCst);
        assert!(highest >= CHARGE, "some job observed its own charge");
        assert!(
            highest <= LIMIT,
            "no observation exceeded the limit: {highest}"
        );
        assert_eq!(pool.charged_bytes(), 0);
    });
}

#[test]
fn a_stranded_queue_returns_each_reservation_only_after_its_closure_is_dropped() {
    bounded(|| {
        // No minimum thread, and no spawn permitted below, so admitted jobs stay queued as when every worker spawn failed.
        let pool = BlockingPool::with_config_and_policies(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "byte-stranded".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(4, 10_000),
        );
        pool.inner.live_max_threads.store(0, Ordering::Release);
        let ran = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let first_job = count_job(&ran);
        let first_storage = storage_of(&first_job);
        let first = pool.try_spawn_charged(first_job, 30).unwrap();
        let observer = ChargeObserver {
            pool: pool.handle(),
            seen_in_drop: Arc::clone(&seen),
        };
        let second_job = move || {
            let _held = &observer;
        };
        let second_storage = storage_of(&second_job);
        let second = pool.try_spawn_charged(second_job, 50).unwrap();
        let live = 30 + first_storage + 50 + second_storage;
        assert_eq!(pool.charged_bytes(), live);
        assert_eq!(pool.pending_count(), 2);

        // The last worker claim fails to start: every queue is detached from the pool.
        pool.inner.active_threads.store(1, Ordering::Release);
        let stranded = {
            let _guard = pool.inner.mutex.lock();
            super::super::rollback_failed_worker_spawn_locked(&pool.inner)
                .expect("a failed final worker claim must detach the pending tasks")
        };
        // Detached is not dropped: the closures are alive, so their bytes are still reserved.
        assert_eq!(pool.pending_count(), 0);
        assert_eq!(pool.charged_bytes(), live);
        assert_eq!(seen.load(Ordering::SeqCst), usize::MAX);

        stranded.cancel();
        assert_eq!(pool.charged_bytes(), 0);
        assert!(first.is_cancelled() && second.is_cancelled());
        assert!(first.wait_timeout(WAIT) && second.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        // Whichever job was dropped first, the observed job's own bytes were still reserved when its captures dropped.
        assert!(seen.load(Ordering::SeqCst) >= 50 + second_storage);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

/// Woken when a task is reported done. It first takes every lock a pool or a waiter could be holding while it wakes
/// (a wake under one of them deadlocks this thread, and the scenario's timeout fails the test), then records what the
/// pool still had charged and what the job's captures saw when they dropped.
struct DoneProbe {
    pool: BlockingPoolHandle,
    completion: Arc<super::super::BlockingTaskCompletion>,
    seen: Arc<AtomicUsize>,
    charged_at_wake: AtomicUsize,
    seen_at_wake: AtomicUsize,
    signal: mpsc::Sender<()>,
}

impl std::task::Wake for DoneProbe {
    fn wake(self: Arc<Self>) {
        drop(self.pool.inner.mutex.lock());
        drop(self.pool.inner.admission.waiters.lock());
        drop(self.completion.mutex.lock());
        self.charged_at_wake
            .store(self.pool.charged_bytes(), Ordering::SeqCst);
        self.seen_at_wake
            .store(self.seen.load(Ordering::SeqCst), Ordering::SeqCst);
        self.signal.send(()).unwrap();
    }
}

fn done_probe(
    pool: &BlockingPoolHandle,
    task: &BlockingTaskHandle,
    seen: &Arc<AtomicUsize>,
) -> (Arc<DoneProbe>, Waker, mpsc::Receiver<()>) {
    let (signal, receive) = mpsc::channel();
    let probe = Arc::new(DoneProbe {
        pool: pool.clone(),
        completion: Arc::clone(&task.completion),
        seen: Arc::clone(seen),
        charged_at_wake: AtomicUsize::new(usize::MAX),
        seen_at_wake: AtomicUsize::new(usize::MAX),
        signal,
    });
    let waker = Waker::from(Arc::clone(&probe));
    (probe, waker, receive)
}

#[test]
fn a_task_is_reported_done_only_after_its_closure_is_dropped_and_its_bytes_are_back() {
    bounded(|| {
        let pool = byte_pool(4, 10_000);
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = ChargeObserver {
            pool: pool.handle(),
            seen_in_drop: Arc::clone(&seen),
        };
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let job = move || {
            let _held = &observer;
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        };
        let storage = storage_of(&job);
        let task = pool.try_spawn_charged(job, 40).unwrap();
        entry.recv_timeout(WAIT).unwrap();
        let (probe, waker, woken) = done_probe(&pool.handle(), &task, &seen);

        // Running is not done: the registration waits, and nothing has been woken or returned.
        assert!(task.poll_done(&Context::from_waker(&waker)).is_pending());
        assert_eq!(pool.charged_bytes(), 40 + storage);
        assert!(woken.try_recv().is_err());

        release.send(()).unwrap();
        woken
            .recv_timeout(WAIT)
            .expect("a task that finishes wakes its registered waiter");
        // The waiter was woken after the closure's captures were dropped (while the task's own bytes were still
        // reserved) and after those bytes were returned.
        assert_eq!(probe.seen_at_wake.load(Ordering::SeqCst), 40 + storage);
        assert_eq!(probe.charged_at_wake.load(Ordering::SeqCst), 0);
        assert!(task.poll_done(&Context::from_waker(&waker)).is_ready());
        assert!(task.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_stranded_task_is_reported_done_only_after_its_closure_is_dropped_and_its_bytes_are_back() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "byte-stranded-done".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(4, 10_000),
        );
        pool.inner.live_max_threads.store(0, Ordering::Release);
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = ChargeObserver {
            pool: pool.handle(),
            seen_in_drop: Arc::clone(&seen),
        };
        let job = move || {
            let _held = &observer;
        };
        let storage = storage_of(&job);
        let task = pool.try_spawn_charged(job, 50).unwrap();
        let (probe, waker, woken) = done_probe(&pool.handle(), &task, &seen);
        assert!(task.poll_done(&Context::from_waker(&waker)).is_pending());

        pool.inner.active_threads.store(1, Ordering::Release);
        let stranded = {
            let _guard = pool.inner.mutex.lock();
            super::super::rollback_failed_worker_spawn_locked(&pool.inner)
                .expect("a failed final worker claim must detach the pending task")
        };
        // Detached is neither dropped nor done.
        assert_eq!(pool.charged_bytes(), 50 + storage);
        assert!(woken.try_recv().is_err());

        stranded.cancel();
        woken
            .recv_timeout(WAIT)
            .expect("a stranded task wakes its registered waiter");
        assert_eq!(probe.seen_at_wake.load(Ordering::SeqCst), 50 + storage);
        assert_eq!(probe.charged_at_wake.load(Ordering::SeqCst), 0);
        assert!(task.is_cancelled());
        assert!(task.poll_done(&Context::from_waker(&waker)).is_ready());
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

/// Takes the task's completion lock when it is woken and when it is dropped: either one under that lock deadlocks the
/// thread, and the scenario's timeout fails the test.
struct LockProbe {
    completion: Arc<super::super::BlockingTaskCompletion>,
    wakes: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl std::task::Wake for LockProbe {
    fn wake(self: Arc<Self>) {
        drop(self.completion.mutex.lock());
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for LockProbe {
    fn drop(&mut self) {
        drop(self.completion.mutex.lock());
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_registered_waker_is_replaced_cleared_and_woken_outside_the_completion_lock() {
    bounded(|| {
        let pool = byte_pool(4, 10_000);
        let (task, release, _storage) = hold_charged_worker(&pool.handle(), 0);
        let wakes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        // Registers a fresh waker and lets go of the caller's reference: the completion holds the only one.
        let register = || {
            let waker = Waker::from(Arc::new(LockProbe {
                completion: Arc::clone(&task.completion),
                wakes: Arc::clone(&wakes),
                drops: Arc::clone(&drops),
            }));
            assert!(task.poll_done(&Context::from_waker(&waker)).is_pending());
        };

        register();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // A second registration replaces the first, whose last reference is dropped after the lock is released.
        register();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        // Clearing drops the registered waker the same way, and wakes nothing.
        task.clear_done_waiter();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(wakes.load(Ordering::SeqCst), 0);

        register();
        release.send(()).unwrap();
        assert!(task.wait_timeout(WAIT));
        // Shutdown joins the worker, so its wake has returned by now.
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    });
}

/// A panic payload whose destruction is ordinary: it counts itself and records how many bytes the pool still had
/// charged at that instant.
struct OrdinaryPayload {
    pool: BlockingPoolHandle,
    drops: Arc<AtomicUsize>,
    charged_at_drop: Arc<AtomicUsize>,
}

impl Drop for OrdinaryPayload {
    fn drop(&mut self) {
        self.charged_at_drop
            .store(self.pool.charged_bytes(), Ordering::SeqCst);
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

/// A panic payload whose destructor panics with another instance of itself. Dropping the caught `Err` as an ordinary
/// local unwinds the caller, and disposing of the secondary payload would panic again, so each is counted when its
/// destructor starts: one count means the secondary payload was never disposed of.
struct PathologicalPayload {
    drops: Arc<AtomicUsize>,
}

impl Drop for PathologicalPayload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        std::panic::resume_unwind(Box::new(PathologicalPayload {
            drops: Arc::clone(&self.drops),
        }));
    }
}

/// A job capture whose destructor unwinds with `payload`. Only ever dropped outside an unwind here: a second panic
/// during cleanup would abort the test process.
struct PanickingCapture<P: Send + 'static> {
    payload: Option<P>,
}

impl<P: Send + 'static> Drop for PanickingCapture<P> {
    fn drop(&mut self) {
        if let Some(payload) = self.payload.take() {
            std::panic::resume_unwind(Box::new(payload));
        }
    }
}

/// A waker whose `wake` unwinds with `payload`.
struct WakePanics<P: Send + 'static>(parking_lot::Mutex<Option<P>>);

impl<P: Send + 'static> std::task::Wake for WakePanics<P> {
    fn wake(self: Arc<Self>) {
        let payload = self.0.lock().take();
        if let Some(payload) = payload {
            std::panic::resume_unwind(Box::new(payload));
        }
    }
}

/// A one-thread byte pool whose worker exits are counted: a worker that died of a job's panic shows up as a stop, and
/// as a later job running on another thread.
fn watched_pool() -> (BlockingPool, Arc<AtomicUsize>) {
    let stops = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&stops);
    let pool = BlockingPool::with_config_and_policies(
        1,
        1,
        BlockingPoolOptions {
            thread_name_prefix: "byte-payload".to_owned(),
            on_thread_stop: Some(Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            })),
            ..Default::default()
        },
        BlockingQueuePolicy::Fifo,
        bytes_policy(8, 10_000),
    );
    (pool, stops)
}

/// A job that records the thread it runs on.
fn record_thread(
    ids: &Arc<parking_lot::Mutex<Vec<std::thread::ThreadId>>>,
) -> impl FnOnce() + Send + 'static {
    let ids = Arc::clone(ids);
    move || {
        ids.lock().push(std::thread::current().id());
    }
}

#[test]
fn a_worker_frees_an_ordinary_panic_payload_and_survives_one_whose_destructor_panics() {
    bounded(|| {
        let (pool, stops) = watched_pool();
        let ids = Arc::new(parking_lot::Mutex::new(Vec::new()));

        // An ordinary payload is freed exactly once, while its job's bytes are still reserved, and before the job is
        // reported done.
        let drops = Arc::new(AtomicUsize::new(0));
        let charged_at_drop = Arc::new(AtomicUsize::new(usize::MAX));
        let payload = OrdinaryPayload {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
            charged_at_drop: Arc::clone(&charged_at_drop),
        };
        let record = record_thread(&ids);
        let panicking = move || {
            record();
            std::panic::resume_unwind(Box::new(payload));
        };
        let storage = storage_of(&panicking);
        let ordinary = pool.try_spawn_charged(panicking, 70).unwrap();
        assert!(ordinary.wait_timeout(WAIT));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(charged_at_drop.load(Ordering::SeqCst), 70 + storage);
        // Nothing was left behind: the reservation came back and nothing is pinned.
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);

        // A payload whose destructor panics is contained: the worker lives and the job behind it runs on it, and the
        // job's reservation stays pinned because the secondary payload may own anything the job captured.
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = PathologicalPayload {
            drops: Arc::clone(&drops),
        };
        let record = record_thread(&ids);
        let panicking = move || {
            record();
            std::panic::resume_unwind(Box::new(payload));
        };
        let pinned = storage_of(&panicking);
        let pathological = pool.try_spawn_charged(panicking, 0).unwrap();
        let sibling = pool.try_spawn_charged(record_thread(&ids), 0).unwrap();
        assert!(pathological.wait_timeout(WAIT) && sibling.wait_timeout(WAIT));
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "destroyed once; its secondary payload is never disposed of"
        );
        let seen = ids.lock().to_vec();
        assert_eq!(seen.len(), 3);
        assert!(
            seen.iter().all(|id| *id == seen[0]),
            "every job ran on the one worker: {seen:?}"
        );
        assert_eq!(stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_skipped_tasks_capture_panic_is_freed_or_contained_and_the_worker_goes_on() {
    bounded(|| {
        let (pool, stops) = watched_pool();
        let (holder, release, _) = hold_charged_worker(&pool.handle(), 0);

        // The pathological payload is first in line, so the ordinary one is behind it: a worker that unwound on the
        // first would never reach the second.
        let pathological_drops = Arc::new(AtomicUsize::new(0));
        let capture = PanickingCapture {
            payload: Some(PathologicalPayload {
                drops: Arc::clone(&pathological_drops),
            }),
        };
        let pathological_job = move || {
            let _held = &capture;
        };
        let pinned = 20 + storage_of(&pathological_job);
        let pathological = pool.try_spawn_charged(pathological_job, 20).unwrap();

        let ordinary_drops = Arc::new(AtomicUsize::new(0));
        let charged_at_drop = Arc::new(AtomicUsize::new(usize::MAX));
        let capture = PanickingCapture {
            payload: Some(OrdinaryPayload {
                pool: pool.handle(),
                drops: Arc::clone(&ordinary_drops),
                charged_at_drop: Arc::clone(&charged_at_drop),
            }),
        };
        let ordinary_job = move || {
            let _held = &capture;
        };
        let ordinary_storage = storage_of(&ordinary_job);
        let ordinary = pool.try_spawn_charged(ordinary_job, 10).unwrap();

        let ran = Arc::new(AtomicUsize::new(0));
        let sibling_job = count_job(&ran);
        let sibling_storage = storage_of(&sibling_job);
        let sibling = pool.try_spawn_charged(sibling_job, 0).unwrap();

        pathological.cancel();
        ordinary.cancel();
        release.send(()).unwrap();
        assert!(holder.wait_timeout(WAIT));
        assert!(pathological.wait_timeout(WAIT) && ordinary.wait_timeout(WAIT));
        assert!(sibling.wait_timeout(WAIT));

        assert_eq!(pathological_drops.load(Ordering::SeqCst), 1);
        assert_eq!(ordinary_drops.load(Ordering::SeqCst), 1);
        // The ordinary payload was freed while its own task's bytes (and the queued sibling's) were still reserved,
        // beside the reservation the pathological victim ahead of it pinned.
        assert_eq!(
            charged_at_drop.load(Ordering::SeqCst),
            pinned + 10 + ordinary_storage + sibling_storage
        );
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_stranded_drain_reports_both_tasks_when_the_first_capture_panics_with_a_pathological_payload() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "byte-stranded-payload".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(4, 10_000),
        );
        pool.inner.live_max_threads.store(0, Ordering::Release);
        let drops = Arc::new(AtomicUsize::new(0));
        let capture = PanickingCapture {
            payload: Some(PathologicalPayload {
                drops: Arc::clone(&drops),
            }),
        };
        let first_job = move || {
            let _held = &capture;
        };
        let first_storage = storage_of(&first_job);
        let first = pool.try_spawn_charged(first_job, 30).unwrap();
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let observer = ChargeObserver {
            pool: pool.handle(),
            seen_in_drop: Arc::clone(&seen),
        };
        let second_job = move || {
            let _held = &observer;
        };
        let second_storage = storage_of(&second_job);
        let second = pool.try_spawn_charged(second_job, 50).unwrap();
        assert_eq!(
            pool.charged_bytes(),
            30 + first_storage + 50 + second_storage
        );

        pool.inner.active_threads.store(1, Ordering::Release);
        let stranded = {
            let _guard = pool.inner.mutex.lock();
            super::super::rollback_failed_worker_spawn_locked(&pool.inner)
                .expect("a failed final worker claim must detach the pending tasks")
        };
        let drained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stranded.cancel()));
        if let Err(payload) = drained {
            // Its destructor would panic again; the failure message is the point.
            std::mem::forget(payload);
            panic!("the stranded drain unwound out of cancel()");
        }
        assert!(first.wait_timeout(WAIT) && second.wait_timeout(WAIT));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        // The first task's reservation is pinned. The second task's captures were dropped while its own bytes were
        // still reserved beside it, and then they went back.
        let pinned = 30 + first_storage;
        assert_eq!(seen.load(Ordering::SeqCst), pinned + 50 + second_storage);
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), pinned);
    });
}

/// Finishes a held task whose registered waker unwinds with `payload`, and returns once a job queued behind it has run
/// on the same worker.
fn finish_a_task_whose_waker_panics<P: Send + 'static>(pool: &BlockingPool, payload: P) {
    let (task, release, _) = hold_charged_worker(&pool.handle(), 0);
    let waker = Waker::from(Arc::new(WakePanics(parking_lot::Mutex::new(Some(payload)))));
    assert!(task.poll_done(&Context::from_waker(&waker)).is_pending());
    // The completion holds the only reference.
    drop(waker);
    let ran = Arc::new(AtomicUsize::new(0));
    let sibling = pool.try_spawn_charged(count_job(&ran), 0).unwrap();
    release.send(()).unwrap();
    assert!(task.wait_timeout(WAIT) && sibling.wait_timeout(WAIT));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

#[test]
fn a_waker_that_panics_has_its_payload_freed_or_contained_and_the_worker_goes_on() {
    bounded(|| {
        let (pool, stops) = watched_pool();

        let drops = Arc::new(AtomicUsize::new(0));
        let payload = OrdinaryPayload {
            pool: pool.handle(),
            drops: Arc::clone(&drops),
            charged_at_drop: Arc::new(AtomicUsize::new(usize::MAX)),
        };
        finish_a_task_whose_waker_panics(&pool, payload);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "an ordinary payload is freed"
        );

        let drops = Arc::new(AtomicUsize::new(0));
        let payload = PathologicalPayload {
            drops: Arc::clone(&drops),
        };
        finish_a_task_whose_waker_panics(&pool, payload);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        assert_eq!(stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

/// Stands for what a job owns: counts its release. `T` is the real thing (a `Vec`, an inline array).
struct Tracked<T> {
    _data: T,
    frees: Arc<AtomicUsize>,
}

impl<T> Drop for Tracked<T> {
    fn drop(&mut self) {
        self.frees.fetch_add(1, Ordering::SeqCst);
    }
}

fn tracked<T>(data: T, frees: &Arc<AtomicUsize>) -> Tracked<T> {
    Tracked {
        _data: data,
        frees: Arc::clone(frees),
    }
}

/// A panic payload that owns `held` and, when destroyed, hands it to a new payload instead of freeing it. Its
/// destructor panics, so the pool cannot dispose of what it passes on.
struct Relay<T: Send + 'static> {
    held: Option<Tracked<T>>,
}

impl<T: Send + 'static> Drop for Relay<T> {
    fn drop(&mut self) {
        if let Some(held) = self.held.take() {
            std::panic::resume_unwind(Box::new(Carried { _held: held }));
        }
    }
}

/// The secondary payload: ordinary, and now the owner.
struct Carried<T> {
    _held: Tracked<T>,
}

/// An ordinary panic payload that owns `held`.
struct Owner<T> {
    _held: Tracked<T>,
}

/// What `relay_run` leaves behind.
struct Relayed {
    pool: BlockingPool,
    stops: Arc<AtomicUsize>,
    frees: Arc<AtomicUsize>,
    /// The closure storage the pool measured for the job.
    storage: usize,
}

/// Runs a job that owns `data` (declared as `declared` heap bytes) and unwinds with a [`Relay`] payload that owns it,
/// then a sibling behind it, on a watched one-worker pool.
fn relay_run<T: Send + 'static>(data: T, declared: usize) -> Relayed {
    let (pool, stops) = watched_pool();
    let frees = Arc::new(AtomicUsize::new(0));
    let held = tracked(data, &frees);
    let job = move || {
        std::panic::resume_unwind(Box::new(Relay { held: Some(held) }));
    };
    let storage = storage_of(&job);
    let task = pool.try_spawn_charged(job, declared).unwrap();
    let sibling = pool.try_spawn_charged(|| {}, 0).unwrap();
    assert!(task.wait_timeout(WAIT) && sibling.wait_timeout(WAIT));
    Relayed {
        pool,
        stops,
        frees,
        storage,
    }
}

/// The invariant the byte limit rests on: what a job owned is either freed or still reserved. The pool may not return a
/// reservation and also keep (or forget) what it covered.
fn owned_is_freed_or_reserved(relayed: &Relayed, reserved: usize) {
    let freed = relayed.frees.load(Ordering::SeqCst);
    let charged = relayed.pool.charged_bytes();
    assert!(
        freed == 1 || charged >= reserved,
        "owned state alive (freed {freed} times) with only {charged} of {reserved} bytes reserved"
    );
}

fn refusal_kind(pool: &BlockingPool, declared: usize) -> BlockingSpawnErrorKind {
    pool.try_spawn_charged(|| {}, declared).unwrap_err().kind()
}

#[test]
fn a_run_payload_that_moves_a_vec_on_leaves_it_freed_or_pinned() {
    bounded(|| {
        let relayed = relay_run(vec![7_u8; 4_096], 4_096);
        let pinned = 4_096 + relayed.storage;
        owned_is_freed_or_reserved(&relayed, pinned);
        // The Vec went into a forgotten payload, so the whole reservation stays: counted, and reported as pinned.
        assert_eq!(relayed.frees.load(Ordering::SeqCst), 0);
        assert_eq!(relayed.pool.charged_bytes(), pinned);
        assert_eq!(relayed.pool.quarantined_bytes(), pinned);
        assert_eq!(relayed.stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert!(relayed.pool.shutdown_and_wait(WAIT));
        assert_eq!(relayed.pool.charged_bytes(), pinned);
    });
}

#[test]
fn a_run_payload_that_moves_inline_storage_on_leaves_it_freed_or_pinned() {
    bounded(|| {
        let relayed = relay_run([7_u8; 2_048], 0);
        assert!(relayed.storage >= 2_048, "the array is inline storage");
        owned_is_freed_or_reserved(&relayed, relayed.storage);
        assert_eq!(relayed.frees.load(Ordering::SeqCst), 0);
        assert_eq!(relayed.pool.charged_bytes(), relayed.storage);
        assert_eq!(relayed.pool.quarantined_bytes(), relayed.storage);
        assert_eq!(relayed.stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert!(relayed.pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_stranded_payload_that_moves_a_vec_on_leaves_it_freed_or_pinned() {
    bounded(|| {
        let pool = BlockingPool::with_config_and_policies(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "byte-stranded-relay".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(4, 10_000),
        );
        pool.inner.live_max_threads.store(0, Ordering::Release);
        let frees = Arc::new(AtomicUsize::new(0));
        let capture = PanickingCapture {
            payload: Some(Relay {
                held: Some(tracked(vec![7_u8; 4_096], &frees)),
            }),
        };
        let job = move || {
            let _held = &capture;
        };
        let pinned = 4_096 + storage_of(&job);
        let task = pool.try_spawn_charged(job, 4_096).unwrap();

        pool.inner.active_threads.store(1, Ordering::Release);
        let stranded = {
            let _guard = pool.inner.mutex.lock();
            super::super::rollback_failed_worker_spawn_locked(&pool.inner)
                .expect("a failed final worker claim must detach the pending task")
        };
        let drained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stranded.cancel()));
        if let Err(payload) = drained {
            std::mem::forget(payload);
            panic!("the stranded drain unwound out of cancel()");
        }
        assert!(task.wait_timeout(WAIT));
        assert_eq!(frees.load(Ordering::SeqCst), 0);
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        // The drain is over and the pool closes with the pin still in place.
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), pinned);
    });
}

#[test]
fn a_skipped_payload_that_moves_a_vec_on_leaves_it_freed_or_pinned() {
    bounded(|| {
        let (pool, stops) = watched_pool();
        let (holder, release, _) = hold_charged_worker(&pool.handle(), 0);
        let frees = Arc::new(AtomicUsize::new(0));
        let capture = PanickingCapture {
            payload: Some(Relay {
                held: Some(tracked(vec![7_u8; 4_096], &frees)),
            }),
        };
        let job = move || {
            let _held = &capture;
        };
        let pinned = 4_096 + storage_of(&job);
        let victim = pool.try_spawn_charged(job, 4_096).unwrap();
        let sibling = pool.try_spawn_charged(|| {}, 0).unwrap();
        victim.cancel();
        release.send(()).unwrap();
        assert!(holder.wait_timeout(WAIT));
        assert!(victim.wait_timeout(WAIT) && sibling.wait_timeout(WAIT));
        assert_eq!(frees.load(Ordering::SeqCst), 0);
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert_eq!(stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn an_ordinary_payload_that_owns_a_vec_frees_it_and_the_reservation_returns() {
    // The control: nothing is pinned or leaked for a payload that is destroyed normally.
    bounded(|| {
        let (pool, stops) = watched_pool();
        let frees = Arc::new(AtomicUsize::new(0));
        let held = tracked(vec![7_u8; 4_096], &frees);
        let job = move || {
            std::panic::resume_unwind(Box::new(Owner { _held: held }));
        };
        let task = pool.try_spawn_charged(job, 4_096).unwrap();
        let sibling = pool.try_spawn_charged(|| {}, 0).unwrap();
        assert!(task.wait_timeout(WAIT) && sibling.wait_timeout(WAIT));
        assert_eq!(frees.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);
        assert_eq!(stops.load(Ordering::SeqCst), 0, "no worker exited");
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_pin_refuses_what_can_never_fit_again_and_still_admits_what_does() {
    bounded(|| {
        let relayed = relay_run(vec![7_u8; 4_096], 4_096);
        let pool = &relayed.pool;
        let pinned = 4_096 + relayed.storage;
        let room = 10_000 - pinned;

        // Bigger than the whole limit: `ChargeTooLarge` keeps its meaning. Fits an empty pool but not what is left
        // of it: refused for good, with its own reason.
        assert_eq!(
            refusal_kind(pool, 10_001),
            BlockingSpawnErrorKind::ChargeTooLarge
        );
        assert_eq!(
            refusal_kind(pool, room + 1),
            BlockingSpawnErrorKind::ByteBudgetQuarantined
        );

        // Backpressure stays transient: a job that fits what is left, but not beside a running one, is told to wait.
        let (holder, release, _) = hold_charged_worker(&pool.handle(), 100);
        let wanted = room - 50;
        assert_eq!(
            refusal_kind(pool, wanted),
            BlockingSpawnErrorKind::ByteBudgetSaturated
        );
        release.send(()).unwrap();
        assert!(holder.wait_timeout(WAIT));
        // It fits once the running job is gone, and exactly what is left fits too.
        assert!(
            pool.try_spawn_charged(|| {}, wanted)
                .unwrap()
                .wait_timeout(WAIT)
        );
        assert!(
            pool.try_spawn_charged(|| {}, room)
                .unwrap()
                .wait_timeout(WAIT)
        );
        assert_eq!(pool.charged_bytes(), pinned);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn pinning_wakes_a_parked_submitter_and_it_resolves_with_the_terminal_reason() {
    bounded(|| {
        let (pool, _stops) = watched_pool();
        let frees = Arc::new(AtomicUsize::new(0));
        let held = tracked(vec![7_u8; 4_096], &frees);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let faulty = move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
            std::panic::resume_unwind(Box::new(Relay { held: Some(held) }));
        };
        let pinned = 4_096 + storage_of(&faulty);
        let task = pool.try_spawn_charged(faulty, 4_096).unwrap();
        entry.recv_timeout(WAIT).unwrap();

        // 9_900 fits an empty pool but not beside the running job: it parks, as for any saturation.
        let mut waiting = pool.submit_charged(|| {}, 9_900);
        let (waker, woken) = wake_probe(&pool);
        let mut context = Context::from_waker(&waker);
        assert!(Pin::new(&mut waiting).poll(&mut context).is_pending());
        assert_eq!(pool.inner.admission.waiters.lock().len(), 1);
        assert!(matches!(woken.try_recv(), Err(mpsc::TryRecvError::Empty)));

        // The job then pins its reservation: 9_900 can no longer fit, ever.
        release.send(()).unwrap();
        woken
            .recv_timeout(WAIT)
            .expect("pinning wakes the parked submitter");
        assert_eq!(pool.quarantined_bytes(), pinned);
        match Pin::new(&mut waiting).poll(&mut context) {
            Poll::Ready(Err(refused)) => {
                assert_eq!(
                    refused.kind(),
                    BlockingSpawnErrorKind::ByteBudgetQuarantined
                );
                refused.into_inner()();
            }
            other => {
                panic!("the parked submitter must resolve with the terminal refusal: {other:?}")
            }
        }
        assert!(pool.inner.admission.waiters.lock().is_empty());
        assert!(task.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_pool_with_pinned_bytes_shuts_down_and_still_says_why_a_job_cannot_fit() {
    bounded(|| {
        let relayed = relay_run(vec![7_u8; 4_096], 4_096);
        let pool = &relayed.pool;
        let pinned = 4_096 + relayed.storage;
        let room = 10_000 - pinned;
        assert!(pool.shutdown_and_wait(WAIT));
        // The pin outlives the drain and the workers.
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        // Reasons stay apart after shutdown: a job that can never fit says so (it is not handed back as a shutdown
        // for an entry point to run inline), and a job that would have fit says shutdown.
        assert_eq!(
            refusal_kind(pool, room + 1),
            BlockingSpawnErrorKind::ByteBudgetQuarantined
        );
        assert_eq!(
            refusal_kind(pool, 10_001),
            BlockingSpawnErrorKind::ChargeTooLarge
        );
        assert_eq!(refusal_kind(pool, 1), BlockingSpawnErrorKind::Shutdown);
    });
}

// ---------------------------------------------------------------------------------------------------------------
// `try_spawn_charged_with`: the pool reserves, then the factory builds the payload, then the job is queued.
// ---------------------------------------------------------------------------------------------------------------

/// The job type of factories that only ever panic: a boxed job is the same size wherever it comes from.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Counts its own drop: stands for a capture whose destruction must be seen.
struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A job that counts its runs and, when it is destroyed (run or not), its drop.
///
/// `use<>`: the job owns clones of both `Arc`s and borrows nothing from the arguments. Edition 2024 would otherwise
/// capture the arguments' lifetimes in the return type, and a factory closure could not return `counted_job(&ran, ..)`.
fn counted_job(
    ran: &Arc<AtomicUsize>,
    drops: &Arc<AtomicUsize>,
) -> impl FnOnce() + Send + 'static + use<> {
    let ran = Arc::clone(ran);
    let guard = DropCount(Arc::clone(drops));
    move || {
        let _held = &guard;
        ran.fetch_add(1, Ordering::SeqCst);
    }
}

/// The refusal a factory submission made before it ran, and the factory it hands back unrun.
fn refused_unrun<M>(
    result: Result<BlockingTaskHandle, BlockingFactoryError<M>>,
) -> (BlockingSpawnErrorKind, M) {
    match result {
        Err(BlockingFactoryError::Refused(refused)) => (refused.kind(), refused.into_inner()),
        Err(other) => panic!("expected a refusal before the factory ran, got {other:?}"),
        Ok(_) => panic!("expected a refusal, but the job was admitted"),
    }
}

fn reserved_slots(pool: &BlockingPool) -> usize {
    pool.inner.admission.reserved_slots.load(Ordering::SeqCst)
}

#[test]
fn a_factory_is_not_called_for_a_full_queue_or_full_bytes_and_is_admitted_once_there_is_room() {
    bounded(|| {
        // One queue slot and 1_000 bytes.
        let pool = byte_pool(1, 1_000);
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

        // The queue is full: the worker is busy and the one queue slot is taken.
        let (running, release, _) = hold_charged_worker(&pool.handle(), 0);
        let queued = pool.try_spawn_charged(|| {}, 0).unwrap();
        let (kind, factory) = refused_unrun(pool.try_spawn_charged_with(100, factory));
        assert_eq!(kind, BlockingSpawnErrorKind::Saturated);
        assert_eq!(
            made.load(Ordering::SeqCst),
            0,
            "built a payload for a full queue"
        );
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT) && queued.wait_timeout(WAIT));

        // The bytes are full: 950 live bytes leave no room for 100 more.
        let (running, release, held) = hold_charged_worker(&pool.handle(), 950);
        assert!(950 + held + 100 > 1_000);
        let (kind, factory) = refused_unrun(pool.try_spawn_charged_with(100, factory));
        assert_eq!(kind, BlockingSpawnErrorKind::ByteBudgetSaturated);
        assert_eq!(
            made.load(Ordering::SeqCst),
            0,
            "built a payload for a full pool"
        );
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));

        // The permitted counterpart: with room, the very factory that came back is admitted, built once, and run.
        let job = pool
            .try_spawn_charged_with(100, factory)
            .expect("room for the same factory");
        assert!(job.wait_timeout(WAIT));
        assert_eq!(made.load(Ordering::SeqCst), 1);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn the_bytes_and_the_slot_are_already_held_while_the_factory_builds_the_payload() {
    bounded(|| {
        let pool = byte_pool(2, 10_000);
        let handle = pool.handle();
        let inner = Arc::clone(&pool.inner);
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let slots = Arc::new(AtomicUsize::new(usize::MAX));
        let storage = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(AtomicUsize::new(0));
        let (seen_in, slots_in, storage_in) =
            (Arc::clone(&seen), Arc::clone(&slots), Arc::clone(&storage));
        let ran_in = Arc::clone(&ran);
        let task = pool
            .try_spawn_charged_with(500, move || {
                seen_in.store(handle.charged_bytes(), Ordering::SeqCst);
                slots_in.store(
                    inner.admission.reserved_slots.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                );
                let job = move || {
                    ran_in.fetch_add(1, Ordering::SeqCst);
                };
                storage_in.store(storage_of(&job), Ordering::SeqCst);
                job
            })
            .unwrap();
        assert!(task.wait_timeout(WAIT));
        // Reserved BEFORE the payload existed: the declared heap plus the closure storage, and one queue slot.
        assert_eq!(
            seen.load(Ordering::SeqCst),
            500 + storage.load(Ordering::SeqCst)
        );
        assert_eq!(slots.load(Ordering::SeqCst), 1);
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        // The slot became the queued job and the job's bytes came back after it ran.
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn the_queue_slot_is_reserved_before_the_payload_and_a_rolled_back_build_returns_it() {
    bounded(|| {
        // Room for exactly one queued job.
        let pool = byte_pool(1, 10_000);
        let probe = pool.handle();
        let (running, release, _) = hold_charged_worker(&probe, 0);

        // While the factory runs nothing is queued, yet the one slot is taken: a submission made from inside it (the
        // pool is not locked, so reentry is safe) is refused as saturated.
        let verdict = Arc::new(AtomicUsize::new(0));
        let verdict_in = Arc::clone(&verdict);
        let queued = pool
            .try_spawn_charged_with(0, move || {
                let kind = probe.try_spawn_charged(|| {}, 0).unwrap_err().kind();
                verdict_in.store(
                    usize::from(kind == BlockingSpawnErrorKind::Saturated),
                    Ordering::SeqCst,
                );
                || {}
            })
            .unwrap();
        assert_eq!(
            verdict.load(Ordering::SeqCst),
            1,
            "the slot was not reserved yet"
        );
        assert_eq!(pool.pending_count(), 1);
        // Now the job really is queued, and the next build is refused before its factory runs.
        let (kind, _) = refused_unrun(pool.try_spawn_charged_with(0, || || {}));
        assert_eq!(kind, BlockingSpawnErrorKind::Saturated);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT) && queued.wait_timeout(WAIT));

        // A build that panics leaves nothing behind: no bytes, no slot, and nothing pinned.
        let outcome = pool.try_spawn_charged_with(64, || -> Job { panic!("boom") });
        match outcome {
            Err(BlockingFactoryError::FactoryPanicked { quarantined }) => {
                assert!(!quarantined);
            }
            other => panic!("expected the factory's panic, got {other:?}"),
        }
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
        // The returned slot and bytes are reused at once.
        let again = pool.try_spawn_charged_with(64, || || {}).unwrap();
        assert!(again.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

/// A panic payload that owns the `Vec` a factory had just allocated, and records what the pool still had reserved at
/// the instant the payload was destroyed.
struct VecPayload {
    _held: Tracked<Vec<u8>>,
    pool: BlockingPoolHandle,
    charged_at_drop: Arc<AtomicUsize>,
}

impl Drop for VecPayload {
    fn drop(&mut self) {
        self.charged_at_drop
            .store(self.pool.charged_bytes(), Ordering::SeqCst);
    }
}

#[test]
fn a_factory_that_panics_with_the_vec_it_allocated_has_it_destroyed_before_the_credit_returns() {
    bounded(|| {
        let pool = byte_pool(2, 10_000);
        let frees = Arc::new(AtomicUsize::new(0));
        let charged_at_drop = Arc::new(AtomicUsize::new(usize::MAX));
        let payload_pool = pool.handle();
        let (frees_in, charged_in) = (Arc::clone(&frees), Arc::clone(&charged_at_drop));
        let outcome = pool.try_spawn_charged_with(600, move || -> Job {
            let held = tracked(vec![7_u8; 600], &frees_in);
            std::panic::resume_unwind(Box::new(VecPayload {
                _held: held,
                pool: payload_pool,
                charged_at_drop: charged_in,
            }));
        });
        match outcome {
            Err(BlockingFactoryError::FactoryPanicked { quarantined }) => {
                assert!(!quarantined, "an ordinary payload is destroyed, not pinned");
            }
            other => panic!("expected the factory's panic, got {other:?}"),
        }
        // The Vec was destroyed, and while its whole reservation (the declared heap and the storage of the job type
        // it was reserved for) was still held: only then did the credit go back.
        assert_eq!(frees.load(Ordering::SeqCst), 1);
        assert_eq!(
            charged_at_drop.load(Ordering::SeqCst),
            600 + std::mem::size_of::<Job>()
        );
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);

        // The permitted counterpart: the same pool then builds, queues and runs a normal job of the same size.
        let ran = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let job = pool
            .try_spawn_charged_with(600, {
                let (ran, drops) = (Arc::clone(&ran), Arc::clone(&drops));
                move || counted_job(&ran, &drops)
            })
            .unwrap();
        assert!(job.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_factory_that_hands_its_vec_to_a_secondary_payload_pins_the_reservation_and_frees_its_slot() {
    bounded(|| {
        let pool = byte_pool(2, 10_000);
        let frees = Arc::new(AtomicUsize::new(0));
        let held = tracked(vec![7_u8; 600], &frees);
        let outcome = pool.try_spawn_charged_with(600, move || -> Job {
            std::panic::resume_unwind(Box::new(Relay { held: Some(held) }));
        });
        assert!(matches!(
            outcome,
            Err(BlockingFactoryError::FactoryPanicked { quarantined: true })
        ));
        // The Vec sits in a secondary payload the pool will not dispose of: its reservation is pinned, the slot is not.
        let pinned = 600 + std::mem::size_of::<Job>();
        assert_eq!(frees.load(Ordering::SeqCst), 0);
        assert_eq!(pool.charged_bytes(), pinned);
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert_eq!(reserved_slots(&pool), 0);

        // The permitted counterparts: smaller work still builds and runs beside the pin, and a request that no longer
        // fits is refused for good, before its factory runs.
        let ran = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let smaller = pool
            .try_spawn_charged_with(0, {
                let (ran, drops) = (Arc::clone(&ran), Arc::clone(&drops));
                move || counted_job(&ran, &drops)
            })
            .unwrap();
        assert!(smaller.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        let (kind, _) = refused_unrun(pool.try_spawn_charged_with(10_000 - pinned + 1, || || {}));
        assert_eq!(kind, BlockingSpawnErrorKind::ByteBudgetQuarantined);
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.charged_bytes(), pinned);
    });
}

/// A build on another thread holds the pool's one queue slot while a 9_500-byte submission parks behind it. The build
/// then panics, with an ordinary payload or with one that hands its `Vec` on. Returns the pool and how the parked
/// submission ended: admitted and run, or refused with a kind.
fn submit_parked_behind_a_failing_build(
    pathological: bool,
) -> (BlockingPool, Result<(), BlockingSpawnErrorKind>) {
    let pool = byte_pool(1, 10_000);
    let (running, release, _) = hold_charged_worker(&pool.handle(), 0);
    let (entered, entry) = mpsc::channel();
    let (go, gate) = mpsc::channel::<()>();
    let handle = pool.handle();
    let builder = std::thread::spawn(move || {
        let frees = Arc::new(AtomicUsize::new(0));
        let held = tracked(vec![7_u8; 600], &frees);
        let outcome = handle.try_spawn_charged_with(600, move || -> Job {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
            if pathological {
                std::panic::resume_unwind(Box::new(Relay { held: Some(held) }));
            }
            std::panic::resume_unwind(Box::new(Owner { _held: held }));
        });
        match outcome {
            Err(BlockingFactoryError::FactoryPanicked { quarantined }) => Some(quarantined),
            _ => None,
        }
    });
    entry.recv_timeout(WAIT).unwrap();

    // The build holds the one slot, so this submission parks even though nothing is queued.
    let mut waiting = pool.submit_charged(|| {}, 9_500);
    let (waker, woke) = wake_probe(&pool);
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut waiting).poll(&mut context).is_pending());
    go.send(()).unwrap();
    woke.recv_timeout(WAIT)
        .expect("the build's failure wakes the parked submitter");
    assert_eq!(
        builder.join().unwrap(),
        Some(pathological),
        "the build reported its panic, and whether its reservation was pinned"
    );
    let outcome = match Pin::new(&mut waiting).poll(&mut context) {
        Poll::Ready(Ok(task)) => {
            release.send(()).unwrap();
            assert!(task.wait_timeout(WAIT));
            Ok(())
        }
        Poll::Ready(Err(refused)) => {
            let _ = release.send(());
            Err(refused.kind())
        }
        Poll::Pending => panic!("the parked submitter was left waiting"),
    };
    assert!(running.wait_timeout(WAIT));
    (pool, outcome)
}

#[test]
fn a_parked_submitter_is_woken_by_a_failed_build_and_admitted_when_nothing_was_pinned() {
    bounded(|| {
        let (pool, outcome) = submit_parked_behind_a_failing_build(false);
        assert_eq!(
            outcome,
            Ok(()),
            "the ordinary payload was destroyed and everything returned"
        );
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_parked_submitter_is_woken_by_a_pinning_build_and_resolves_with_the_terminal_reason() {
    bounded(|| {
        let (pool, outcome) = submit_parked_behind_a_failing_build(true);
        assert_eq!(outcome, Err(BlockingSpawnErrorKind::ByteBudgetQuarantined));
        let pinned = 600 + std::mem::size_of::<Job>();
        assert_eq!(pool.quarantined_bytes(), pinned);
        assert_eq!(reserved_slots(&pool), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn a_pool_that_closes_while_the_payload_is_built_destroys_it_and_orphans_no_slot() {
    bounded(|| {
        // The permitted counterpart: the same factory shape on an open pool builds, queues and runs its job.
        let open = byte_pool(2, 1_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let job = open
            .try_spawn_charged_with(100, || counted_job(&ran, &drops))
            .unwrap();
        assert!(job.wait_timeout(WAIT));
        assert_eq!(
            (ran.load(Ordering::SeqCst), drops.load(Ordering::SeqCst)),
            (1, 1)
        );
        assert!(open.shutdown_and_wait(WAIT));

        // The pool closes after the reservation and before the enqueue (the factory itself closes it).
        let closing = byte_pool(2, 1_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let outcome = closing.try_spawn_charged_with(100, || {
            closing.shutdown();
            counted_job(&ran, &drops)
        });
        assert!(matches!(
            outcome,
            Err(BlockingFactoryError::Shutdown { quarantined: false })
        ));
        // The built job never ran, was destroyed by the pool, and everything it held came back.
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(closing.charged_bytes(), 0);
        assert_eq!(reserved_slots(&closing), 0);
        assert!(closing.shutdown_and_wait(WAIT));

        // A capture of the built job whose destructor panics pathologically while the pool is closing is contained:
        // the reservation is pinned (the capture may have moved anything on), and the slot is still released.
        let faulty = byte_pool(2, 1_000);
        let capture_drops = Arc::new(AtomicUsize::new(0));
        let capture = PanickingCapture {
            payload: Some(PathologicalPayload {
                drops: Arc::clone(&capture_drops),
            }),
        };
        let outcome = faulty.try_spawn_charged_with(100, || {
            faulty.shutdown();
            move || {
                let _held = &capture;
            }
        });
        assert!(matches!(
            outcome,
            Err(BlockingFactoryError::Shutdown { quarantined: true })
        ));
        let pinned = 100 + std::mem::size_of::<PanickingCapture<PathologicalPayload>>();
        assert_eq!(capture_drops.load(Ordering::SeqCst), 1);
        assert_eq!(faulty.charged_bytes(), pinned);
        assert_eq!(faulty.quarantined_bytes(), pinned);
        assert_eq!(reserved_slots(&faulty), 0);
        assert!(faulty.shutdown_and_wait(WAIT));
    });
}

#[test]
fn one_jobs_capacity_is_reused_by_every_factory_admission_in_turn_on_a_lazily_staffed_pool() {
    bounded(|| {
        // The limit holds exactly one job: 100 declared bytes plus the closure's own storage. The pool starts with no
        // worker, so each admitted job is run by a worker spawned after its enqueue.
        let ran = Arc::new(AtomicUsize::new(0));
        let storage = storage_of(&count_job(&ran));
        let pool = BlockingPool::with_config_and_policies(
            0,
            1,
            BlockingPoolOptions {
                thread_name_prefix: "byte-lazy".to_owned(),
                ..Default::default()
            },
            BlockingQueuePolicy::Fifo,
            bytes_policy(2, 100 + storage),
        );
        let handle = pool.handle();
        let nested = Arc::new(AtomicUsize::new(0));
        for round in 1..=5_usize {
            let (ran_in, nested_in, probe) =
                (Arc::clone(&ran), Arc::clone(&nested), handle.clone());
            let task = pool
                .try_spawn_charged_with(100, move || {
                    // Inside the factory the pool is exactly full: one more byte is refused, not queued.
                    let kind = probe.try_spawn_charged(|| {}, 1).unwrap_err().kind();
                    if kind == BlockingSpawnErrorKind::ByteBudgetSaturated {
                        nested_in.fetch_add(1, Ordering::SeqCst);
                    }
                    count_job(&ran_in)
                })
                .unwrap_or_else(|error| panic!("round {round}: {error:?}"));
            assert!(task.wait_timeout(WAIT), "round {round}");
        }
        assert_eq!(ran.load(Ordering::SeqCst), 5);
        assert_eq!(nested.load(Ordering::SeqCst), 5);
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
        assert!(pool.shutdown_and_wait(WAIT));
    });
}

#[test]
fn other_policies_keep_their_slot_bound_ignore_the_declaration_and_a_forbidden_pool_never_builds() {
    bounded(|| {
        let made = Arc::new(AtomicUsize::new(0));
        let ran = Arc::new(AtomicUsize::new(0));

        // Count-bounded: the declaration is ignored, and the reserved slot still counts against the bound.
        let counted = pool(1);
        let (running, release) = hold_worker(&counted.handle());
        let queued = counted
            .try_spawn_charged_with(usize::MAX, || count_job(&ran))
            .unwrap();
        let made_in = Arc::clone(&made);
        let (kind, _) = refused_unrun(counted.try_spawn_charged_with(0, move || {
            made_in.fetch_add(1, Ordering::SeqCst);
            || {}
        }));
        assert_eq!(kind, BlockingSpawnErrorKind::Saturated);
        assert_eq!(made.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT) && queued.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        let again = counted
            .try_spawn_charged_with(0, || count_job(&ran))
            .unwrap();
        assert!(again.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 2);
        assert_eq!(reserved_slots(&counted), 0);
        assert!(counted.shutdown_and_wait(WAIT));

        // Unbounded: always admitted.
        let open = BlockingPool::new(1, 1);
        let job = open.try_spawn_charged_with(7, || count_job(&ran)).unwrap();
        assert!(job.wait_timeout(WAIT));
        assert_eq!(ran.load(Ordering::SeqCst), 3);
        assert!(open.shutdown_and_wait(WAIT));

        // Forbidden: refused for good before the factory runs, and nothing runs inline.
        let forbidden = forbidden_pool();
        let made_in = Arc::clone(&made);
        let (kind, _) = refused_unrun(forbidden.try_spawn_charged_with(0, move || {
            made_in.fetch_add(1, Ordering::SeqCst);
            || {}
        }));
        assert_eq!(kind, BlockingSpawnErrorKind::Forbidden);
        assert_eq!(made.load(Ordering::SeqCst), 0);
        assert_eq!(forbidden.active_threads(), 0);
        assert!(forbidden.shutdown_and_wait(WAIT));
    });
}

#[test]
fn shutdown_does_not_wait_for_a_factory_in_flight_and_its_late_job_is_destroyed_unrun() {
    bounded(|| {
        let pool = byte_pool(2, 1_000);
        let ran = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));

        // The permitted counterpart: before the pool closes, a factory builds, queues and runs its job.
        let early = pool
            .try_spawn_charged_with(100, || counted_job(&ran, &drops))
            .unwrap();
        assert!(early.wait_timeout(WAIT));
        assert_eq!(
            (ran.load(Ordering::SeqCst), drops.load(Ordering::SeqCst)),
            (1, 1)
        );

        // A second factory, on another thread, is held open mid-build.
        let handle = pool.handle();
        let late_ran = Arc::new(AtomicUsize::new(0));
        let late_drops = Arc::new(AtomicUsize::new(0));
        let (entered, entry) = mpsc::channel();
        let (go, gate) = mpsc::channel::<()>();
        let (ran_in, drops_in) = (Arc::clone(&late_ran), Arc::clone(&late_drops));
        let builder = std::thread::spawn(move || {
            let outcome = handle.try_spawn_charged_with(100, move || {
                entered.send(()).unwrap();
                gate.recv_timeout(WAIT).unwrap();
                counted_job(&ran_in, &drops_in)
            });
            match outcome {
                Err(BlockingFactoryError::Shutdown { quarantined }) => Some(quarantined),
                _ => None,
            }
        });
        entry.recv_timeout(WAIT).unwrap();
        assert_eq!(reserved_slots(&pool), 1);
        assert!(pool.charged_bytes() >= 100);

        // The pool closes and its workers finish while that caller is still inside `make`: shutdown waits for queued
        // and running jobs, not for producers. The caller keeps its reservation and its slot until `make` returns.
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(pool.active_threads(), 0);
        assert_eq!(reserved_slots(&pool), 1);
        assert!(pool.charged_bytes() >= 100);
        // Once closed, no new submission is admitted, however much room it asks for.
        assert_eq!(refusal_kind(&pool, 1), BlockingSpawnErrorKind::Shutdown);
        assert_eq!(late_ran.load(Ordering::SeqCst), 0);

        // The factory returns: it finds the pool closed, destroys the job it built unrun, and returns everything.
        go.send(()).unwrap();
        assert_eq!(builder.join().unwrap(), Some(false));
        assert_eq!(late_ran.load(Ordering::SeqCst), 0);
        assert_eq!(late_drops.load(Ordering::SeqCst), 1);
        assert_eq!(pool.charged_bytes(), 0);
        assert_eq!(pool.quarantined_bytes(), 0);
        assert_eq!(reserved_slots(&pool), 0);
    });
}

#[test]
fn a_factory_error_reports_fixed_text_for_any_factory_type_and_never_the_payloads() {
    bounded(|| {
        let pool = byte_pool(2, 1_000);
        // A payload of 4 KiB of text: nothing of it may come back in the error.
        let huge = "x".repeat(4 * 1024);
        let error = pool
            .try_spawn_charged_with(8, move || -> Job { panic!("{huge}") })
            .expect_err("the factory panicked");
        let shown = format!("{error} / {error:?}");
        assert!(shown.len() < 512, "{} bytes of diagnostic", shown.len());
        assert!(!shown.contains("xxxx"), "the payload's text came back");
        assert!(matches!(
            error,
            BlockingFactoryError::FactoryPanicked { quarantined: false }
        ));

        // Debug and Display need nothing of the factory type: a refusal reports through a closure that is not Debug.
        let held = hold_charged_worker(&pool.handle(), 0);
        let queued = pool.try_spawn_charged(|| {}, 0).unwrap();
        let another = pool.try_spawn_charged(|| {}, 0).unwrap();
        let refused = pool
            .try_spawn_charged_with(0, || || {})
            .expect_err("the queue is full");
        let shown = format!("{refused} / {refused:?}");
        assert!(shown.len() < 512, "{shown}");
        held.1.send(()).unwrap();
        assert!(
            held.0.wait_timeout(WAIT) && queued.wait_timeout(WAIT) && another.wait_timeout(WAIT)
        );
        assert!(pool.shutdown_and_wait(WAIT));
    });
}
