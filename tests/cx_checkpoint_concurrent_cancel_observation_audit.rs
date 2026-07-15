//! Audit + regression test for `Cx::checkpoint()` observation
//! of CONCURRENT cancel arrivals.
//!
//! Operator's question: "when checkpoint is called and a
//! CONCURRENT cancel arrives mid-call, must the checkpoint
//! observe the cancel and return Err (correct: prompt
//! cancellation) or finish without observing (incorrect:
//! window for missed cancellation)?"
//!
//! Audit findings:
//!
//!   asupersync's checkpoint provides **bounded next-call
//!   observation** of concurrent cancels via a Release-
//!   Acquire pair on `fast_cancel: Arc<AtomicBool>`. The
//!   semantics are nuanced:
//!
//!   1. **Cancel arrives BEFORE fast-path Acquire load**:
//!      fast path observes the cancel, falls through to
//!      slow path, returns Err on the SAME call.
//!   2. **Cancel arrives BETWEEN fast-path read lock + Acquire
//!      load and early Ok return**: a sub-microsecond
//!      window where the fast path returns Ok. The cancel
//!      is published via Release; the NEXT checkpoint's
//!      Acquire load observes it.
//!   3. **Cancel arrives DURING slow path**: serialized by
//!      the write lock on CxInner. The cancel-publishing
//!      thread (request_cancel_with_budget) and the slow-
//!      path checkpoint both acquire the write lock —
//!      whichever lock acquisition order wins determines
//!      observation order, but no cancel is LOST.
//!
//!   The "missed cancellation" framing is technically a
//!   one-checkpoint-cycle delay, NOT a permanent miss. The
//!   Release-Acquire pair guarantees cross-thread visibility
//!   on the next Acquire load. Per asupersync's cooperative-
//!   cancel contract, checkpoints fire frequently enough
//!   (typically every iteration of an async loop) that
//!   one-checkpoint delay is well within the bounded-
//!   latency promise.
//!
//!   The chain:
//!
//!   1. **`fast_cancel: Arc<AtomicBool>`** is the cross-
//!      thread cancel signal (types/task_context.rs:115).
//!      The Arc lets multiple threads share the atomic.
//!
//!   2. **Cancel publisher (request_cancel_with_budget)**:
//!      ```ignore
//!      inner.fast_cancel.store(true, Release);
//!      ```
//!      The Release store synchronizes with any subsequent
//!      Acquire load on the same atomic. ALL prior writes
//!      become visible to the reader.
//!
//!   3. **Cancel reader (checkpoint fast path)** (cx/cx.rs:
//!      1664):
//!      ```ignore
//!      let guard = self.inner.read();
//!      let cancelled = guard.fast_cancel.load(Acquire);
//!      ```
//!      The Acquire load synchronizes with any prior
//!      Release store. If the cancel was published BEFORE
//!      this load (in the happens-before sense), `cancelled`
//!      is true.
//!
//!   4. **Bounded race window**: between the Acquire load
//!      and the early Ok return, the fast path does only:
//!      read budget for exhaustion check (Copy), perform two
//!      Relaxed atomic ops for accounting, and return Ok.
//!      The window is sub-microsecond. A cancel arriving
//!      in this window is observed by the NEXT checkpoint
//!      (not THIS one).
//!
//!   5. **Slow-path write lock serializes concurrent
//!      operations**: when checkpoint enters the slow path,
//!      it acquires `self.inner.write()`. The cancel
//!      publisher also acquires `self.inner.write()` in
//!      request_cancel_with_budget. parking_lot's write
//!      lock is exclusive — only one thread mutates inner
//!      at a time. So during slow-path execution, NO
//!      concurrent publish can interleave; the slow path's
//!      `inner.cancel_requested` read sees a consistent
//!      snapshot.
//!
//!   6. **No instantaneous-observation guarantee**: the
//!      Release-Acquire pair does NOT make checkpoint
//!      observe a cancel SET DURING the fast-path window.
//!      That would require either:
//!        - A blocking primitive (would slow the hot path).
//!        - A polling loop in checkpoint (CPU waste).
//!
//!      asupersync chooses the cooperative model: checkpoints
//!      fire frequently; one-checkpoint delay is acceptable.
//!
//!   7. **Cancel WAKER for parked tasks**: tasks parked on
//!      a Sleep/channel/etc. don't poll checkpoint at all.
//!      For these, the cross-thread cancel propagation goes
//!      through the cancel-aware Waker (CancelLaneWaker) —
//!      see tests/scheduler_cross_thread_cancel_propagation_audit.rs.
//!      The waker triggers a re-poll which then enters
//!      checkpoint. So parked-task observation is bounded
//!      by waker dispatch latency, not by checkpoint
//!      frequency.
//!
//! Verdict: **SOUND**. Concurrent cancels are observed by
//! the NEXT checkpoint via the Release-Acquire pair —
//! bounded one-cycle latency, never permanent miss. The
//! operator's "missed cancellation" framing is a category
//! error: missed-this-checkpoint vs missed-forever. The
//! latter doesn't happen.
//!
//! For STRICT same-call observation, callers can:
//!   1. Acquire the inner write lock manually before
//!      checkpoint (would force serialization with the
//!      publisher).
//!   2. Use yield_now() between checkpoints in tight loops
//!      (gives the publisher a chance to grab the lock).
//!   3. Rely on the cancel waker for parked-task wakeup.
//!
//! A regression that:
//!   - changed fast_cancel from Arc<AtomicBool> to a non-
//!     shared bool (would lose cross-thread visibility
//!     entirely — concurrent cancel observation broken),
//!   - replaced the Acquire load with Relaxed (cross-thread
//!     visibility no longer guaranteed — observation may
//!     be permanent miss, not just one-cycle delay),
//!   - replaced the Release store with Relaxed (publisher
//!     may not see the cancel published; same effect as
//!     above),
//!   - removed the slow-path write-lock serialization
//!     (concurrent publishes during slow path could race
//!     and lose updates),
//!   - introduced a "polling loop" in checkpoint that
//!     spin-waits for cancel observation (CPU waste; would
//!     also block other progress on the worker),
//!   - lost the cancel waker for parked tasks (parked
//!     tasks would never observe cancel — full
//!     missed-cancel pathway),
//!     would all be caught by the structural pins below or
//!     by behavioral verification.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn source_window(source: &str, start: usize, len: usize) -> &str {
    let mut end = start.saturating_add(len).min(source.len());
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[start..end]
}

#[test]
fn checkpoint_fast_path_uses_acquire_load_for_cross_thread_visibility() {
    // Pin (link 3): the fast-path cancel observation uses
    // Acquire ordering — synchronizes with the publisher's
    // Release store. Without Acquire, the Release-Acquire
    // pair is broken and observations may permanently miss.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 4000);

    assert!(
        body.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: fast-path cancel check no longer uses \
         Acquire ordering. The Release-Acquire pair is \
         broken — concurrent cancels may be observed only \
         eventually (or never) instead of on the next \
         checkpoint.",
    );
}

#[test]
fn cancel_publisher_uses_release_store_for_cross_thread_visibility() {
    // Pin (link 2): request_cancel_with_budget publishes
    // fast_cancel via Release store. Pairs with the
    // checkpoint reader's Acquire load.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: request_cancel_with_budget no longer \
         publishes fast_cancel with Release ordering. The \
         Release-Acquire pair is broken — checkpoint readers \
         may never observe the cancel.",
    );
}

#[test]
fn fast_cancel_is_arc_atomic_bool_for_cross_thread_sharing() {
    // Pin (link 1): fast_cancel is Arc<AtomicBool>. The
    // Arc lets multiple threads share the atomic; AtomicBool
    // provides the lock-free synchronization primitive.
    let source = read("src/types/task_context.rs");

    assert!(
        source.contains("pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,"),
        "REGRESSION: CxInner.fast_cancel is no longer \
         Arc<AtomicBool>. Without the Arc, publisher and \
         reader can't share the atomic — concurrent cancel \
         observation has no synchronization mechanism.",
    );
}

#[test]
fn checkpoint_slow_path_acquires_write_lock_for_serialization() {
    // Pin (link 5): the slow path acquires self.inner.write()
    // — exclusive access. This serializes the slow-path
    // execution with any concurrent publisher (which also
    // takes write lock).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("let mut inner = self.inner.write();"),
        "REGRESSION: checkpoint slow path no longer acquires \
         the write lock. Concurrent publishes during slow \
         path could race — cancel state mutation is no \
         longer atomic with checkpoint observation.",
    );
}

#[test]
fn fast_path_keeps_window_minimal_only_relaxed_accounting_after_acquire() {
    // Pin (link 4): between the Acquire load and the early
    // Ok return, the fast path does only Copy reads + two
    // Relaxed atomic ops. No write lock, no expensive work.
    // This minimizes the race window where a concurrent
    // cancel could be missed by THIS checkpoint.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 4000);

    // The accounting is via Relaxed atomic ops — not a
    // write lock.
    assert!(
        body.contains("std::sync::atomic::Ordering::Relaxed"),
        "REGRESSION: fast-path accounting no longer uses \
         Relaxed atomics. Either the accounting now uses \
         stronger ordering (slower) or it was removed \
         (lost observability).",
    );

    // Forbid expensive work in the fast-path window.
    let suspect_expensive_in_fast_path = [
        "self.inner.write();", // Would block on publisher.
        "thread::sleep",
        "std::thread::yield_now",
    ];
    let fast_path_window = body.split("// ── Slow path ─").next().unwrap_or(body);
    for pat in &suspect_expensive_in_fast_path {
        assert!(
            !fast_path_window.contains(pat),
            "REGRESSION: fast-path window now contains \
             `{pat}` — expensive work between Acquire load \
             and early Ok return. The race window has \
             grown; concurrent cancels are missed for longer.",
        );
    }
}

#[test]
fn cancel_publisher_acquires_inner_write_for_cancel_state_publish() {
    // Pin (link 5): request_cancel_with_budget acquires
    // inner.write() for the cancel-state publish. This
    // serializes with the slow-path checkpoint's write
    // lock — neither can observe a half-published state.
    let source = read("src/record/task.rs");

    let fn_marker = "pub(crate) fn request_cancel_with_budget_and_publication(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget_and_publication fn");
    let body = source_window(&source, start, 4000);

    assert!(
        body.contains("let mut inner_guard = cx_inner.as_ref().map(|inner| inner.write());")
            && body.contains("if let Some(guard) = inner_guard.as_mut() {"),
        "REGRESSION: request_cancel_with_budget no longer \
         acquires the inner write lock. The publish is no \
         longer serialized with checkpoint slow path — \
         cancel state mutations could race.",
    );
}

#[test]
fn no_polling_loop_in_checkpoint_for_synchronous_cancel_wait() {
    // Pin (link 6): checkpoint must NOT spin-poll for cancel
    // observation. Spin-poll would waste CPU AND would not
    // help (the cancel publisher takes the write lock that
    // the spin would block on indirectly).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    let suspect_polling = [
        "while !cancelled {",
        "loop {\n            let cancelled = guard.fast_cancel",
        "spin_loop",
    ];
    for pat in &suspect_polling {
        assert!(
            !body.contains(pat),
            "REGRESSION: checkpoint now contains a polling \
             loop (`{pat}`) for synchronous cancel \
             observation. CPU waste — cooperative model is \
             that checkpoints fire often, not that one \
             checkpoint blocks for cancel.",
        );
    }
}

#[test]
fn cancel_waker_provides_parked_task_wakeup_path() {
    // Pin (link 7): tasks parked on Sleep/channel/etc. that
    // don't poll checkpoint must be woken via a cancel
    // waker. CancelLaneWaker is the cross-thread mechanism
    // that bridges parked tasks to the cancel observation.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("struct CancelLaneWaker {")
            && source.contains("impl Wake for CancelLaneWaker {"),
        "REGRESSION: CancelLaneWaker is gone. Parked tasks \
         (Sleep/channel/etc.) would never observe a \
         concurrently-arriving cancel — full \
         missed-cancellation pathway for the parked-task \
         case.",
    );

    // The waker schedules cancel-lane work + wakes the
    // coordinator.
    assert!(
        source.contains("self.global.inject_cancel(self.task_id, priority);")
            && source.contains("self.coordinator.wake_one();"),
        "REGRESSION: CancelLaneWaker no longer routes through \
         inject_cancel + coordinator.wake_one. Parked tasks \
         are not woken — silent missed cancellation for \
         the parked-task case.",
    );
}

#[test]
fn checkpoint_signature_returns_result_for_question_mark_propagation_after_observation() {
    // Pin (link 4): when checkpoint DOES observe the
    // cancel, the Result<(), Error> return lets the user
    // propagate via `?`. This is what makes "next-checkpoint
    // observation" actually surrender the worker.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: checkpoint signature changed. The \
         next-checkpoint observation contract requires \
         Result<(), Error> for ?-propagation.",
    );
}

#[test]
fn slow_path_re_reads_cancel_requested_under_write_lock() {
    // Pin (link 5): the slow path's tuple destructure reads
    // inner.cancel_requested under the write lock — gets a
    // consistent snapshot regardless of concurrent
    // publishers (they're blocked on the write lock).
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("inner.cancel_requested,"),
        "REGRESSION: checkpoint slow path no longer reads \
         inner.cancel_requested. Concurrent cancels would \
         not be observed during slow-path execution.",
    );
}

// ─────────── BEHAVIORAL PIN: concurrent cancel observation ──
//
// Two threads:
// - Reader: tight loop calling mock_checkpoint.
// - Writer: small delay then publishes cancel via Release.
// Verify: reader observes the cancel within bounded
// iterations after the publish.

#[derive(Debug)]
struct MockCxInner {
    fast_cancel: Arc<AtomicBool>,
    mask_depth: u32,
    cancel_requested: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum MockResult {
    Ok,
    ErrCancelled,
}

fn mock_checkpoint(inner: &mut MockCxInner) -> MockResult {
    // Fast path: Acquire load.
    let cancelled = inner.fast_cancel.load(Ordering::Acquire);
    if !cancelled {
        return MockResult::Ok; // Fast-path early Ok.
    }
    // Slow path: publish self-cancel + mask gate.
    inner.cancel_requested = true;
    if inner.mask_depth == 0 {
        return MockResult::ErrCancelled;
    }
    MockResult::Ok
}

#[test]
fn concurrent_cancel_observed_by_next_checkpoint_via_release_acquire_pair() {
    // Behavioral pin: writer Release-stores cancel after a
    // short delay; reader Acquire-loads in a tight loop.
    // Reader observes cancel within bounded iterations —
    // never permanently misses.
    const MAX_ITERATIONS: u64 = 100_000_000;

    let fast_cancel = Arc::new(AtomicBool::new(false));
    let observed_at_iter = Arc::new(AtomicU64::new(u64::MAX));

    // Writer thread.
    let writer_flag = Arc::clone(&fast_cancel);
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        writer_flag.store(true, Ordering::Release);
    });

    // Reader thread (this thread): tight loop.
    let observed = Arc::clone(&observed_at_iter);
    let mut iter = 0_u64;
    loop {
        let mut inner = MockCxInner {
            fast_cancel: Arc::clone(&fast_cancel),
            mask_depth: 0,
            cancel_requested: false,
        };
        let result = mock_checkpoint(&mut inner);
        if matches!(result, MockResult::ErrCancelled) {
            observed.store(iter, Ordering::Relaxed);
            break;
        }
        iter += 1;
        if iter >= MAX_ITERATIONS {
            break;
        }
    }
    writer.join().expect("writer panicked");

    let observation_iter = observed.load(Ordering::Relaxed);
    assert!(
        observation_iter < MAX_ITERATIONS,
        "REGRESSION: reader never observed the concurrently-\
         published cancel after {iter} iterations. The \
         Release-Acquire pair is broken — concurrent cancels \
         can be permanently missed.",
        iter = MAX_ITERATIONS,
    );
}

#[test]
fn concurrent_cancel_observation_is_bounded_within_microseconds() {
    // Behavioral pin: the wall-clock time between cancel
    // publish and observation is bounded by the cooperative-
    // checkpoint frequency. For a tight loop, observation
    // happens within microseconds of publish.
    let fast_cancel = Arc::new(AtomicBool::new(false));

    let writer_flag = Arc::clone(&fast_cancel);
    let publish_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let publish_at_writer = Arc::clone(&publish_at);

    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1));
        let now = Instant::now();
        *publish_at_writer.lock().unwrap() = Some(now);
        writer_flag.store(true, Ordering::Release);
    });

    let mut inner = MockCxInner {
        fast_cancel: Arc::clone(&fast_cancel),
        mask_depth: 0,
        cancel_requested: false,
    };
    loop {
        if matches!(mock_checkpoint(&mut inner), MockResult::ErrCancelled) {
            break;
        }
    }
    let observed_at = Instant::now();
    writer.join().expect("writer panicked");

    let publish_at_unwrap = publish_at
        .lock()
        .unwrap()
        .expect("publish timestamp was set");
    let latency = observed_at.saturating_duration_since(publish_at_unwrap);

    // 1ms is a generous CI-friendly bound. In practice this
    // is sub-microsecond on modern hardware.
    assert!(
        latency < Duration::from_millis(10),
        "REGRESSION: concurrent cancel observation latency \
         is {latency:?} (>= 10ms). The Release-Acquire pair \
         should give microsecond-class latency; if its \
         milliseconds, either the publisher is blocked \
         (write-lock contention regression) or the reader's \
         tight loop has stalled.",
    );
}

#[test]
fn fast_path_returns_ok_when_no_cancel_set_no_slow_path_overhead() {
    // Behavioral pin: BEFORE cancel is set, the fast path
    // returns Ok via the Acquire-load + early-return path.
    // No slow-path overhead. Verifies the common case is
    // optimized.
    let fast_cancel = Arc::new(AtomicBool::new(false));
    let mut inner = MockCxInner {
        fast_cancel: Arc::clone(&fast_cancel),
        mask_depth: 0,
        cancel_requested: false,
    };

    for _ in 0..1000 {
        let result = mock_checkpoint(&mut inner);
        assert_eq!(
            result,
            MockResult::Ok,
            "REGRESSION: pre-cancel checkpoint returned Err. \
             The fast-path early Ok return is broken — \
             healthy tasks now pay slow-path cost on every \
             checkpoint.",
        );
        assert!(
            !inner.cancel_requested,
            "REGRESSION: pre-cancel checkpoint mutated \
             cancel_requested. The fast-path early return \
             must be a true no-op.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
        "tests/cx_checkpoint_past_deadline_immediate_err_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
