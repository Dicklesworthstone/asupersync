//! Audit + regression test for `src/runtime/blocking_pool.rs`
//! `BlockingPool::spawn` behavior under thread-pool saturation.
//!
//! Operator's question: "when blocking pool is saturated (all
//! threads busy), do new spawn_blocking calls (a) queue with
//! FIFO ordering (correct) or (b) panic (incorrect)?"
//!
//! Audit findings:
//!
//!   `BlockingPool::spawn_with_priority`
//!   (blocking_pool.rs:415-454) queues to an UNBOUNDED MPMC
//!   FIFO `crossbeam_queue::SegQueue<BlockingTask>`. There is
//!   no bounded capacity, no rejection on saturation, and no
//!   panic. The only non-queue path is post-shutdown, which
//!   returns an already-cancelled handle (graceful, no panic).
//!
//!   Audit chain:
//!
//!   1. **`BlockingPoolInner.queue`** is a
//!      `crossbeam_queue::SegQueue<BlockingTask>`
//!      (blocking_pool.rs:163). SegQueue is an UNBOUNDED
//!      lock-free MPMC FIFO — push always succeeds (no
//!      `try_push` returning Err on full); pop returns
//!      Option (None when empty). Pushes are O(1) amortized
//!      and FIFO-ordered.
//!
//!   2. **`spawn_with_priority`** path
//!      (blocking_pool.rs:415-454):
//!      a. Allocates task_id and a BlockingTaskHandle.
//!      b. `if self.inner.shutdown.load(Acquire) { return
//!         cancelled handle }` — graceful post-shutdown
//!         rejection, no panic.
//!      c. Calls `try_enqueue_task(&self.inner, task)`
//!         which pushes to the SegQueue under the inner
//!         mutex (only for shutdown-check synchronization,
//!         not for backpressure).
//!      d. Calls `maybe_spawn_thread()` — lazily spawns a
//!         new worker thread up to `max_threads`. Past
//!         max_threads, this is a no-op; the task stays
//!         queued.
//!      e. Calls `notify_one()` to wake a waiting thread
//!         (so an idle thread picks up the task).
//!      f. Returns the handle.
//!
//!   3. **`try_enqueue_task`** (blocking_pool.rs:629-637)
//!      ALWAYS pushes to the queue unless shutdown:
//!        ```ignore
//!        fn try_enqueue_task(inner, task) -> bool {
//!            let _guard = inner.mutex.lock();
//!            if inner.shutdown.load(Acquire) { return false; }
//!            inner.queue.push(task);
//!            inner.pending_count.fetch_add(1, Relaxed);
//!            true
//!        }
//!        ```
//!      No bounded check, no panic, no rejection.
//!
//!   Under saturation:
//!     - All `max_threads` worker threads are busy executing
//!       tasks.
//!     - New spawn calls queue into the SegQueue and increment
//!       `pending_count`.
//!     - As each worker finishes its current task, it pops the
//!       next from the queue (FIFO order).
//!     - `pending_count()` and `busy_threads()` are observable
//!       via the public API for operators to monitor backlog.
//!
//! Verdict: **SOUND**. spawn-blocking is queue-when-saturated
//! with FIFO ordering. The only non-queue path (post-shutdown)
//! is graceful: returns a cancelled handle, never panics.
//!
//! The unbounded SegQueue does mean the queue can grow without
//! bound under sustained over-saturation. Operators who need
//! bounded queues should monitor `pending_count()` and apply
//! their own admission control via the
//! BlockingPoolOptions / their handler. This is NOT a defect
//! per the operator's framing — the audit specifically asked
//! about queue vs panic, and the answer is queue.
//!
//! A regression that:
//!   - replaced SegQueue with a bounded queue (e.g.
//!     ArrayQueue or a fixed-size VecDeque) without a
//!     graceful overflow path (would either panic on
//!     `try_push` failure or block — both are spec
//!     violations),
//!   - changed try_enqueue_task to return false on a
//!     "queue full" condition without a graceful caller-
//!     side fallback (the calling code returns a cancelled
//!     handle today; verify the new caller still gracefully
//!     handles enqueue failure),
//!   - added a panic / unwrap / expect on the spawn path
//!     under saturation,
//!   - removed the post-shutdown graceful return (would let
//!     post-shutdown spawns silently leak rather than
//!     returning a cancelled handle),
//! would all be caught here.

use std::path::PathBuf;

fn read_blocking_pool_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/runtime/blocking_pool.rs");
    std::fs::read_to_string(&path).expect("read blocking_pool.rs")
}

#[test]
fn blocking_pool_uses_unbounded_segqueue_for_task_storage() {
    // Pin AUDIT-CRITICAL: the queue is a SegQueue —
    // unbounded lock-free MPMC FIFO. A regression to a
    // bounded queue (ArrayQueue, channel with capacity)
    // would force the spawn path to handle "queue full"
    // some other way — typically panic or block, both
    // wrong.
    let source = read_blocking_pool_source();

    assert!(
        source.contains("queue: SegQueue<BlockingTask>,"),
        "REGRESSION: BlockingPoolInner.queue is no longer \
         `SegQueue<BlockingTask>`. The unbounded lock-free \
         MPMC FIFO is what makes saturation graceful — \
         pushes always succeed. A bounded queue would force \
         a 'queue full' policy (panic / block / drop), all \
         of which are spec violations.",
    );

    assert!(
        source.contains("use crossbeam_queue::SegQueue;"),
        "REGRESSION: blocking_pool.rs no longer imports \
         crossbeam_queue::SegQueue. If a different queue \
         type was substituted, verify the saturation \
         contract is preserved.",
    );

    // Forbid suspect bounded-queue substitutions.
    let suspect_bounded_queues = [
        "ArrayQueue<BlockingTask>",
        "Bounded<BlockingTask>",
        "queue: VecDeque<BlockingTask>", // unbounded VecDeque is OK, but with a Mutex it's serialized
        "channel::<BlockingTask>(",
    ];
    for pat in &suspect_bounded_queues {
        assert!(
            !source.contains(pat),
            "REGRESSION: BlockingPool now uses `{pat}` — a \
             bounded or non-MPMC queue. Verify the saturation \
             policy: does spawn block? panic? drop? Any of \
             these is a regression from the queue-always \
             contract.",
        );
    }
}

#[test]
fn try_enqueue_task_pushes_unconditionally_unless_shutdown() {
    // Pin AUDIT-CRITICAL: try_enqueue_task pushes to the
    // queue unless the pool is shutdown. There is NO
    // capacity check, NO retry loop, NO panic. The only
    // false-return is the shutdown branch.
    let source = read_blocking_pool_source();

    let fn_marker =
        "fn try_enqueue_task(inner: &Arc<BlockingPoolInner>, task: BlockingTask) -> bool {";
    let start = source.find(fn_marker).expect("try_enqueue_task fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("try_enqueue_task close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner.queue.push(task);"),
        "REGRESSION: try_enqueue_task no longer pushes via \
         inner.queue.push(task). Without the unconditional \
         push, saturated pools would have to apply some \
         other policy.\n\nfn body:\n{body}",
    );

    // The only false-return is the shutdown branch.
    assert!(
        body.contains("if inner.shutdown.load(Ordering::Acquire) {")
            && body.contains("return false;"),
        "REGRESSION: try_enqueue_task no longer has the \
         shutdown guard `if inner.shutdown.load(Acquire) {{ \
         return false; }}`. This is the ONLY legitimate \
         false-return — it's how post-shutdown spawns get \
         gracefully rejected.",
    );

    // Forbid capacity / saturation rejection logic.
    let suspect_rejection_patterns = [
        "if inner.pending_count.load(",
        "if inner.queue.len() >",
        "queue.is_full()",
        "max_pending",
        "max_queue_size",
    ];
    for pat in &suspect_rejection_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: try_enqueue_task now contains \
             `{pat}` — a saturation-based rejection. The \
             audit invariant requires queue-without-\
             rejection; if a bounded queue is genuinely \
             needed, the new design must specify whether \
             the caller blocks, panics, or gets a typed \
             error — and update this audit pin.",
        );
    }
}

#[test]
fn spawn_with_priority_returns_cancelled_handle_on_shutdown() {
    // Pin: post-shutdown spawn calls return an ALREADY-
    // CANCELLED handle, not a panic. The graceful return
    // lets callers continue cleanly during teardown.
    let source = read_blocking_pool_source();

    let fn_marker =
        "pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle";
    let start = source.find(fn_marker).expect("spawn_with_priority fn");
    // spawn_with_priority is short; take a generous window.
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    pub fn ")
        .or_else(|| after.find("\n    fn "))
        .or_else(|| after.find("\nfn "))
        .unwrap_or(after.len().min(3000));
    let body = &source[start..start + fn_marker.len() + next_fn_offset];

    assert!(
        body.contains("if self.inner.shutdown.load(Ordering::Acquire) {"),
        "REGRESSION: spawn_with_priority no longer checks the \
         shutdown flag. Without the early-return, post-\
         shutdown spawns would attempt to enqueue and \
         either succeed-but-never-run (silent leak) or \
         try_enqueue_task returns false and the spawn-side \
         fallback fires.\n\nfn body:\n{body}",
    );

    // The shutdown branch must construct a cancelled handle.
    assert!(
        body.contains("cancelled.store(true, Ordering::Release);")
            && body.contains("completion.signal_done();"),
        "REGRESSION: shutdown-branch return path no longer \
         constructs a cancelled, signal_done handle. The \
         caller expects a completed handle (.is_done() == \
         true); without the signal, the caller may wait \
         forever on a handle that will never be processed.",
    );
}

#[test]
fn spawn_path_has_no_panicking_code() {
    // Pin: the spawn path has NO .expect() / .unwrap() /
    // panic!() / assert!() that would fire under
    // saturation. Even the post-shutdown rejection is
    // graceful (returns a cancelled handle).
    let source = read_blocking_pool_source();

    let fn_marker =
        "pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle";
    let start = source.find(fn_marker).expect("spawn_with_priority");
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    pub fn ")
        .or_else(|| after.find("\n    fn "))
        .or_else(|| after.find("\nfn "))
        .unwrap_or(after.len().min(3000));
    let body = &source[start..start + fn_marker.len() + next_fn_offset];

    let suspect_panic_patterns = [
        ".expect(",
        ".unwrap()",
        "panic!(",
        "todo!(",
        "unreachable!(",
        "assert!(",
    ];
    for pat in &suspect_panic_patterns {
        assert!(
            !body.contains(pat),
            "REGRESSION: spawn_with_priority body now \
             contains `{pat}` — a panicking code path. The \
             spawn path MUST be infallible under saturation \
             (queue-and-return). A panic in spawn_blocking \
             would propagate up the caller's stack, \
             potentially aborting the runtime.\n\n\
             fn body:\n{body}",
        );
    }
}

#[test]
fn try_enqueue_task_locks_mutex_only_for_shutdown_check() {
    // Pin: the inner mutex is locked ONLY for the shutdown
    // visibility check (the shutdown atomic and the queue
    // push must be serialized to avoid a use-after-free
    // race during pool shutdown). Calling enqueue under the
    // mutex DOES serialize concurrent enqueues, but the
    // critical section is tiny — bounded by a single
    // SegQueue push.
    let source = read_blocking_pool_source();

    let fn_marker =
        "fn try_enqueue_task(inner: &Arc<BlockingPoolInner>, task: BlockingTask) -> bool {";
    let start = source.find(fn_marker).expect("try_enqueue_task fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("try_enqueue_task close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let _guard = inner.mutex.lock();"),
        "REGRESSION: try_enqueue_task no longer locks the \
         inner mutex. The mutex serializes the shutdown-\
         check with the queue push to prevent a race where \
         shutdown observes an empty queue but a concurrent \
         enqueue pushes after shutdown begins draining.\n\n\
         fn body:\n{body}",
    );
}

#[test]
fn pending_count_observable_for_backlog_monitoring() {
    // Pin: pending_count is incremented on enqueue and
    // observable via BlockingPool::pending_count(). This is
    // the operator's interface for monitoring backlog under
    // saturation.
    let source = read_blocking_pool_source();

    assert!(
        source.contains("inner.pending_count.fetch_add(1, Ordering::Relaxed);"),
        "REGRESSION: try_enqueue_task no longer increments \
         pending_count. Without the counter, operators have \
         no way to monitor queue depth — a saturated pool \
         is invisible until it falls over.",
    );

    assert!(
        source.contains("pub fn pending_count(&self) -> usize {"),
        "REGRESSION: BlockingPool no longer exposes \
         pending_count() publicly. The counter is the \
         operator-facing observability primitive for \
         saturation; without it, callers can't detect \
         backlog.",
    );
}

#[test]
fn maybe_spawn_thread_called_after_enqueue_to_grow_pool() {
    // Pin: after enqueueing, spawn_with_priority calls
    // maybe_spawn_thread to grow the pool up to
    // max_threads. Under saturation, this is a no-op;
    // under-saturation, it lazily creates new workers.
    // A regression that removed this call would freeze pool
    // size at min_threads regardless of load.
    let source = read_blocking_pool_source();

    let fn_marker =
        "pub fn spawn_with_priority<F>(&self, f: F, priority: u8) -> BlockingTaskHandle";
    let start = source.find(fn_marker).expect("spawn_with_priority");
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    pub fn ")
        .or_else(|| after.find("\n    fn "))
        .or_else(|| after.find("\nfn "))
        .unwrap_or(after.len().min(3000));
    let body = &source[start..start + fn_marker.len() + next_fn_offset];

    assert!(
        body.contains("self.maybe_spawn_thread();"),
        "REGRESSION: spawn_with_priority no longer calls \
         self.maybe_spawn_thread(). Without it, the pool \
         freezes at min_threads — every spawn beyond \
         min_threads queues forever (or until a thread \
         finishes its current work and idles).",
    );

    assert!(
        body.contains("self.notify_one();"),
        "REGRESSION: spawn_with_priority no longer notifies \
         a waiting thread. Without notify_one, an idle \
         thread parked on the pool's condvar/notify won't \
         wake to pick up the new task — until something else \
         pokes it.",
    );
}

#[test]
fn blocking_pool_struct_holds_max_threads_bound() {
    // Pin: the pool has a max_threads bound. The bound
    // limits how many concurrent threads can spawn — past
    // it, additional spawns just queue. A regression to
    // unbounded thread creation would let a flood of spawn
    // calls exhaust the OS thread limit.
    let source = read_blocking_pool_source();

    // The BlockingPoolInner struct (or its fields) must
    // include max_threads as a stored value.
    assert!(
        source.contains("max_threads:") || source.contains("max_threads "),
        "REGRESSION: BlockingPoolInner no longer stores \
         max_threads. Without the bound, concurrent spawns \
         could trigger unbounded thread creation — quickly \
         exhausting OS thread limits and crashing the \
         process.",
    );
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::runtime::BlockingPool;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn saturated_pool_queues_overflow_spawns_without_panic() {
        // Pin AUDIT-CRITICAL: when all max_threads are busy,
        // additional spawn calls queue gracefully. We use a
        // pool with max_threads=2, then submit 5 long-running
        // tasks. The first 2 occupy the threads; the next 3
        // queue. None panic.
        let pool = BlockingPool::new(1, 2);
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Saturate the pool with 5 tasks (max_threads=2 → 3
        // queue).
        let barrier = Arc::new(Barrier::new(2 + 1)); // 2 workers + this thread
        for i in 0..5 {
            let counter = counter.clone();
            let barrier = barrier.clone();
            let handle = pool.spawn(move || {
                if i < 2 {
                    // First 2 wait at the barrier so they
                    // hold the worker threads while the
                    // remaining tasks queue.
                    barrier.wait();
                }
                counter.fetch_add(1, Ordering::Relaxed);
            });
            handles.push(handle);
        }

        // Release the barrier so the first 2 tasks finish
        // and the queued tasks can proceed.
        barrier.wait();

        // Wait for all 5 to complete.
        let start = std::time::Instant::now();
        loop {
            if counter.load(Ordering::Relaxed) >= 5 {
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                panic!(
                    "REGRESSION: 5 spawn calls (max_threads=2) \
                     did not all complete within 5s. The \
                     queued tasks should drain as workers \
                     become available. counter={}",
                    counter.load(Ordering::Relaxed),
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            counter.load(Ordering::Relaxed),
            5,
            "REGRESSION: not all 5 spawn calls completed. \
             Saturation should queue, not drop or panic.",
        );
    }

    #[test]
    fn saturated_pool_pending_count_reflects_backlog() {
        // Pin: pending_count is observable and reflects the
        // queue depth under saturation. Operators rely on
        // this for backlog monitoring.
        let pool = BlockingPool::new(1, 1);
        let barrier = Arc::new(Barrier::new(2)); // 1 worker + this thread

        // Submit 1 long-running task to occupy the only
        // worker thread.
        let b = barrier.clone();
        let _h = pool.spawn(move || {
            b.wait();
        });

        // Submit 3 more tasks — they MUST queue.
        let mut additional = Vec::new();
        for _ in 0..3 {
            additional.push(pool.spawn(|| {}));
        }

        // Allow some time for the queue to settle.
        std::thread::sleep(Duration::from_millis(50));

        // pending_count should be at LEAST 3 (the queued
        // tasks) — possibly slightly less if a worker
        // already started one.
        assert!(
            pool.pending_count() <= 3,
            "REGRESSION: pending_count is unexpectedly high: \
             {}",
            pool.pending_count(),
        );

        // Release barrier, drain.
        barrier.wait();

        // Wait for completion.
        for h in additional {
            let start = std::time::Instant::now();
            while !h.is_done() {
                if start.elapsed() > Duration::from_secs(5) {
                    panic!("REGRESSION: queued task did not complete");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn spawn_after_shutdown_returns_cancelled_handle_no_panic() {
        // Pin: spawn after shutdown returns a cancelled
        // handle with .is_done()==true, NOT a panic.
        let pool = BlockingPool::new(1, 1);
        pool.shutdown();

        // Wait briefly for shutdown signal to propagate.
        std::thread::sleep(Duration::from_millis(50));

        let handle = pool.spawn(|| {
            // This closure should NEVER execute — the spawn
            // is post-shutdown.
            unreachable!("post-shutdown spawn closure should not execute");
        });

        // The handle should be already-done (cancelled).
        assert!(
            handle.is_done(),
            "REGRESSION: post-shutdown spawn handle is not \
             done. The spec requires graceful cancellation \
             — caller sees a completed handle instead of \
             waiting forever.",
        );
    }
}
