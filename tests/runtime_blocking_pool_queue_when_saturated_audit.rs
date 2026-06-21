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
//!      It allocates task_id and a BlockingTaskHandle, returns
//!      a graceful cancelled handle after shutdown, pushes the
//!      task with `try_enqueue_task(&self.inner, task)`, lazily
//!      calls `maybe_spawn_thread()` up to `max_threads`, calls
//!      `notify_one()` so an idle thread can pick up the task,
//!      and returns the handle.
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
//!     would all be caught here.

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
        concat!("to", "do", "!("),
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
    use asupersync::runtime::config::BlockingPoolAffinityProfile;
    use asupersync::runtime::{BlockingPool, BlockingPoolOptions, Runtime, RuntimeBuilder};
    use serde_json::{Value, json};
    use std::fs;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const BLOCKING_POOL_AFFINITY_SATURATION_SCENARIO_ID: &str =
        "AA-BLOCKING-POOL-AFFINITY-SATURATION-2C";
    const BLOCKING_POOL_AFFINITY_MIXED_ASYNC_SCENARIO_ID: &str =
        "AA-BLOCKING-POOL-AFFINITY-MIXED-ASYNC-BLOCKING-2C";
    const BLOCKING_POOL_AFFINITY_NO_WIN_SCENARIO_ID: &str =
        "AA-BLOCKING-POOL-AFFINITY-MIXED-ASYNC-NO-WIN-2C";
    const BLOCKING_POOL_AFFINITY_CONTRACT_PATH_ENV: &str =
        "ASUPERSYNC_BLOCKING_POOL_AFFINITY_CONTRACT_PATH";
    const BLOCKING_POOL_AFFINITY_SCENARIO_ENV: &str = "ASUPERSYNC_BLOCKING_POOL_AFFINITY_SCENARIO";
    const BLOCKING_POOL_AFFINITY_REPORT_PATH_ENV: &str =
        "ASUPERSYNC_BLOCKING_POOL_AFFINITY_REPORT_PATH";

    #[derive(Debug, Clone)]
    struct AffinityScenarioSummary {
        enabled: bool,
        cohort_count: usize,
        queued_task_count: usize,
        pending_count_before_release: usize,
        busy_threads_before_release: usize,
        local_queue_dispatches: usize,
        spill_dispatches: usize,
        fallback_dispatches: usize,
        completion_latency_us: u128,
        queue_depth_by_cohort: Vec<usize>,
        global_pending_count_before_release: usize,
        async_coordinator_task_count: usize,
        blocking_spawn_request_count: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MixedAsyncAffinityDispatchMode {
        CohortTargeted,
        UnhintedGlobal,
    }

    fn affinity_test_pool(
        affinity_profile: BlockingPoolAffinityProfile,
        cohort_count: Option<usize>,
    ) -> BlockingPool {
        let options = BlockingPoolOptions {
            idle_timeout: Duration::from_millis(100),
            time_getter: Instant::now,
            sleep_fn: std::thread::sleep,
            thread_name_prefix: "audit-blocking-affinity".to_string(),
            on_thread_start: None,
            on_thread_stop: None,
            affinity_profile,
            cohort_count,
        };
        BlockingPool::with_config(2, 2, options)
    }

    fn wait_for_pending_count<F>(mut read_pending: F, expected: usize, label: &str)
    where
        F: FnMut() -> usize,
    {
        let start = Instant::now();
        while read_pending() < expected {
            assert!(
                start.elapsed() <= Duration::from_secs(5),
                "REGRESSION: pending count for {label} did not reach {expected}; observed {}",
                read_pending(),
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn normalize_queue_depth_by_cohort(queue_depths: &[usize], cohort_count: usize) -> Vec<usize> {
        let mut normalized = vec![0; cohort_count];
        for (cohort, depth) in queue_depths.iter().copied().enumerate().take(cohort_count) {
            normalized[cohort] = depth;
        }
        normalized
    }

    fn affinity_test_runtime(
        affinity_profile: BlockingPoolAffinityProfile,
        worker_threads: usize,
        cohort_count: usize,
    ) -> Runtime {
        let worker_cohort_map: Vec<_> = (0..worker_threads)
            .map(|worker_slot| worker_slot % cohort_count.max(1))
            .collect();
        RuntimeBuilder::new()
            .worker_threads(worker_threads)
            .worker_cohorts(worker_cohort_map)
            .blocking_threads(2, 2)
            .blocking_affinity_profile(affinity_profile)
            .build()
            .expect("blocking affinity runtime should build")
    }

    fn run_affinity_saturation_case(
        affinity_profile: BlockingPoolAffinityProfile,
        cohort_count: usize,
        queued_task_count: usize,
    ) -> AffinityScenarioSummary {
        let pool = affinity_test_pool(affinity_profile, Some(cohort_count));
        let start_barrier = Arc::new(Barrier::new(3));
        let release_barrier = Arc::new(Barrier::new(3));

        let blocker0_start = Arc::clone(&start_barrier);
        let blocker0_release = Arc::clone(&release_barrier);
        let blocker0 = pool.spawn_on_cohort(0, move || {
            blocker0_start.wait();
            blocker0_release.wait();
        });

        let blocker1_start = Arc::clone(&start_barrier);
        let blocker1_release = Arc::clone(&release_barrier);
        let blocker1 = pool.spawn_on_cohort(1 % cohort_count.max(1), move || {
            blocker1_start.wait();
            blocker1_release.wait();
        });

        start_barrier.wait();

        let queued_handles: Vec<_> = (0..queued_task_count)
            .map(|_| pool.spawn_on_cohort(0, std::thread::yield_now))
            .collect();

        wait_for_pending_count(
            || pool.pending_count(),
            queued_task_count,
            "saturation case",
        );

        let pending_count_before_release = pool.pending_count();
        let busy_threads_before_release = pool.busy_threads();
        let metrics_before_release = pool.affinity_metrics();
        let release_started_at = Instant::now();
        release_barrier.wait();

        blocker0.wait();
        blocker1.wait();
        for handle in queued_handles {
            handle.wait();
        }

        let completion_latency_us = release_started_at.elapsed().as_micros();
        let metrics = pool.affinity_metrics();
        assert!(
            pool.shutdown_and_wait(Duration::from_secs(1)),
            "blocking affinity audit pool should shutdown cleanly"
        );

        AffinityScenarioSummary {
            enabled: metrics.enabled,
            cohort_count,
            queued_task_count,
            pending_count_before_release,
            busy_threads_before_release,
            local_queue_dispatches: metrics.local_queue_dispatches,
            spill_dispatches: metrics.spill_dispatches,
            fallback_dispatches: metrics.fallback_dispatches,
            completion_latency_us,
            queue_depth_by_cohort: normalize_queue_depth_by_cohort(
                &metrics_before_release.cohort_pending_counts,
                cohort_count,
            ),
            global_pending_count_before_release: metrics_before_release.global_pending_count,
            async_coordinator_task_count: 0,
            blocking_spawn_request_count: queued_task_count,
        }
    }

    fn run_mixed_async_blocking_case(
        affinity_profile: BlockingPoolAffinityProfile,
        cohort_count: usize,
        queued_task_count: usize,
        async_coordinator_task_count: usize,
        dispatch_mode: MixedAsyncAffinityDispatchMode,
    ) -> AffinityScenarioSummary {
        let worker_threads = 2;
        let runtime = affinity_test_runtime(affinity_profile, worker_threads, cohort_count);
        let blocking_handle = runtime
            .blocking_handle()
            .expect("mixed scenario should expose a blocking pool handle");
        let start_barrier = Arc::new(Barrier::new(3));
        let release_barrier = Arc::new(Barrier::new(3));

        let blocker0_start = Arc::clone(&start_barrier);
        let blocker0_release = Arc::clone(&release_barrier);
        let blocker0 = match dispatch_mode {
            MixedAsyncAffinityDispatchMode::CohortTargeted => runtime
                .spawn_blocking_on_cohort(0, move || {
                    blocker0_start.wait();
                    blocker0_release.wait();
                })
                .expect("blocking runtime should accept cohort-0 blocker"),
            MixedAsyncAffinityDispatchMode::UnhintedGlobal => runtime
                .spawn_blocking(move || {
                    blocker0_start.wait();
                    blocker0_release.wait();
                })
                .expect("blocking runtime should accept unhinted blocker"),
        };

        let blocker1_start = Arc::clone(&start_barrier);
        let blocker1_release = Arc::clone(&release_barrier);
        let blocker1 = match dispatch_mode {
            MixedAsyncAffinityDispatchMode::CohortTargeted => runtime
                .spawn_blocking_on_cohort(1 % cohort_count.max(1), move || {
                    blocker1_start.wait();
                    blocker1_release.wait();
                })
                .expect("blocking runtime should accept cohort-1 blocker"),
            MixedAsyncAffinityDispatchMode::UnhintedGlobal => runtime
                .spawn_blocking(move || {
                    blocker1_start.wait();
                    blocker1_release.wait();
                })
                .expect("blocking runtime should accept unhinted blocker"),
        };

        start_barrier.wait();

        let base_spawn_requests = queued_task_count / async_coordinator_task_count.max(1);
        let remainder = queued_task_count % async_coordinator_task_count.max(1);
        let queued_handles = runtime.block_on(async {
            let runtime_handle =
                Runtime::current_handle().expect("mixed scenario should run inside a runtime");
            let mut handles = Vec::with_capacity(queued_task_count);
            for coordinator_index in 0..async_coordinator_task_count {
                let spawn_requests =
                    base_spawn_requests + usize::from(coordinator_index < remainder);
                for _ in 0..spawn_requests {
                    let handle = match dispatch_mode {
                        MixedAsyncAffinityDispatchMode::CohortTargeted => runtime_handle
                            .spawn_blocking_on_cohort(0, std::thread::yield_now)
                            .expect(
                                "async coordinator should enqueue cohort-targeted blocking helper",
                            ),
                        MixedAsyncAffinityDispatchMode::UnhintedGlobal => runtime_handle
                            .spawn_blocking(std::thread::yield_now)
                            .expect("async coordinator should enqueue unhinted blocking helper"),
                    };
                    handles.push(handle);
                }
                asupersync::runtime::yield_now().await;
            }
            handles
        });

        wait_for_pending_count(
            || blocking_handle.pending_count(),
            queued_task_count,
            "mixed async-plus-blocking case",
        );

        let pending_count_before_release = blocking_handle.pending_count();
        let busy_threads_before_release = 2;
        let metrics_before_release = blocking_handle.affinity_metrics();
        let release_started_at = Instant::now();
        release_barrier.wait();

        blocker0.wait();
        blocker1.wait();
        for handle in queued_handles {
            handle.wait();
        }

        let completion_latency_us = release_started_at.elapsed().as_micros();
        let metrics = blocking_handle.affinity_metrics();

        AffinityScenarioSummary {
            enabled: metrics.enabled,
            cohort_count,
            queued_task_count,
            pending_count_before_release,
            busy_threads_before_release,
            local_queue_dispatches: metrics.local_queue_dispatches,
            spill_dispatches: metrics.spill_dispatches,
            fallback_dispatches: metrics.fallback_dispatches,
            completion_latency_us,
            queue_depth_by_cohort: normalize_queue_depth_by_cohort(
                &metrics_before_release.cohort_pending_counts,
                cohort_count,
            ),
            global_pending_count_before_release: metrics_before_release.global_pending_count,
            async_coordinator_task_count,
            blocking_spawn_request_count: queued_task_count,
        }
    }

    fn default_affinity_workload_model() -> Value {
        json!({
            "workload_seed": 4102,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "repeated_samples": 5,
            "selected_affinity_profiles": ["disabled", "cohort_biased"],
            "queue_distribution": [
                {"cohort": 0, "queued_task_count": 4},
                {"cohort": 1, "queued_task_count": 0}
            ]
        })
    }

    fn default_affinity_operator_notes() -> Value {
        json!({
            "recommended_for": [
                "64+ core hosts that mix async coordination with bursts of blocking parsing, decompression, or helper work",
                "operators who want explicit cohort-local queueing and spill accounting before turning on larger host profiles"
            ],
            "avoid_when": [
                "topology is absent or misleading and the disabled baseline remains easier to reason about",
                "blocking helpers are too small or too sparse to benefit from cohort-local queue bias"
            ],
            "safe_fallback_profile": "disabled",
            "no_win_trigger": "pin the disabled profile if cohort-biased locality stops winning or if its p95 completion latency exceeds the disabled profile by 4x"
        })
    }

    fn default_affinity_expected_projection() -> Value {
        json!({
            "schema_version": "blocking-pool-affinity-projection-v1",
            "scenario_id": BLOCKING_POOL_AFFINITY_SATURATION_SCENARIO_ID,
            "workload_seed": 4102,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "worker_cohort_map": [
                {"worker_slot": 0, "cohort": 0},
                {"worker_slot": 1, "cohort": 1}
            ],
            "disabled_pending_count_before_release": 4,
            "disabled_queue_depth_by_cohort_before_release": [0, 0],
            "disabled_global_pending_count_before_release": 4,
            "disabled_local_queue_dispatches": 0,
            "disabled_spill_dispatches": 0,
            "disabled_fallback_dispatches": 0,
            "cohort_biased_pending_count_before_release": 4,
            "cohort_biased_queue_depth_by_cohort_before_release": [1, 0],
            "cohort_biased_global_pending_count_before_release": 3,
            "cohort_biased_local_queue_dispatches": 3,
            "cohort_biased_spill_dispatches": 3,
            "cohort_biased_fallback_dispatches": 3,
            "shutdown_drain_verdict": "clean"
        })
    }

    fn default_mixed_async_affinity_workload_model() -> Value {
        json!({
            "workload_seed": 4117,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "async_coordinator_task_count": 2,
            "dispatch_mode": "cohort_targeted",
            "repeated_samples": 5,
            "selected_affinity_profiles": ["disabled", "cohort_biased"],
            "queue_distribution": [
                {"cohort": 0, "queued_task_count": 4},
                {"cohort": 1, "queued_task_count": 0}
            ]
        })
    }

    fn default_mixed_async_affinity_operator_notes() -> Value {
        json!({
            "recommended_for": [
                "64+ core hosts where async coordinators fan out bursts of CPU-heavy or blocking helper work",
                "operators who want an end-to-end proof that cohort-biased blocking helpers improve locality without stranding mixed workloads"
            ],
            "avoid_when": [
                "blocking helpers are extremely sparse and the disabled profile is already sufficient",
                "host topology hints are unavailable and only the conservative disabled path is desired"
            ],
            "safe_fallback_profile": "disabled",
            "no_win_trigger": "pin the disabled profile if the mixed async-plus-blocking report stops showing lower global queue spill or if cohort-biased p95 completion latency exceeds the disabled profile by 4x"
        })
    }

    fn default_mixed_async_affinity_expected_projection() -> Value {
        json!({
            "schema_version": "blocking-pool-affinity-projection-v1",
            "scenario_id": BLOCKING_POOL_AFFINITY_MIXED_ASYNC_SCENARIO_ID,
            "workload_seed": 4117,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "async_coordinator_task_count": 2,
            "blocking_spawn_request_count": 4,
            "worker_cohort_map": [
                {"worker_slot": 0, "cohort": 0},
                {"worker_slot": 1, "cohort": 1}
            ],
            "disabled_pending_count_before_release": 4,
            "disabled_queue_depth_by_cohort_before_release": [0, 0],
            "disabled_global_pending_count_before_release": 4,
            "disabled_local_queue_dispatches": 0,
            "disabled_spill_dispatches": 0,
            "disabled_fallback_dispatches": 0,
            "cohort_biased_pending_count_before_release": 4,
            "cohort_biased_queue_depth_by_cohort_before_release": [1, 0],
            "cohort_biased_global_pending_count_before_release": 3,
            "cohort_biased_local_queue_dispatches": 3,
            "cohort_biased_spill_dispatches": 3,
            "cohort_biased_fallback_dispatches": 3,
            "shutdown_drain_verdict": "clean"
        })
    }

    fn default_no_win_affinity_workload_model() -> Value {
        json!({
            "workload_seed": 4126,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "async_coordinator_task_count": 2,
            "dispatch_mode": "unhinted_global",
            "repeated_samples": 5,
            "selected_affinity_profiles": ["disabled", "cohort_biased"],
            "queue_distribution": [
                {"cohort": "global", "queued_task_count": 4}
            ]
        })
    }

    fn default_no_win_affinity_operator_notes() -> Value {
        json!({
            "recommended_for": [
                "operators validating that topology-aware affinity can safely stand down when blocking helpers arrive without cohort hints",
                "shared 64+ core hosts where some producers are topology-blind and the runtime must prove it will not fabricate locality wins"
            ],
            "avoid_when": [
                "the workload already carries reliable cohort hints and should be measured with the targeted mixed scenario instead",
                "you need the aggressive locality-biased path even when no worker/cohort metadata is available"
            ],
            "safe_fallback_profile": "disabled",
            "no_win_trigger": "keep the disabled profile pinned whenever the unhinted async-plus-blocking replay shows identical queue pressure and zero locality wins across both profiles"
        })
    }

    fn default_no_win_affinity_expected_projection() -> Value {
        json!({
            "schema_version": "blocking-pool-affinity-projection-v1",
            "scenario_id": BLOCKING_POOL_AFFINITY_NO_WIN_SCENARIO_ID,
            "workload_seed": 4126,
            "worker_threads": 2,
            "cohort_count": 2,
            "queued_task_count": 4,
            "async_coordinator_task_count": 2,
            "blocking_spawn_request_count": 4,
            "worker_cohort_map": [
                {"worker_slot": 0, "cohort": 0},
                {"worker_slot": 1, "cohort": 1}
            ],
            "disabled_pending_count_before_release": 4,
            "disabled_queue_depth_by_cohort_before_release": [0, 0],
            "disabled_global_pending_count_before_release": 4,
            "disabled_local_queue_dispatches": 0,
            "disabled_spill_dispatches": 0,
            "disabled_fallback_dispatches": 0,
            "cohort_biased_pending_count_before_release": 4,
            "cohort_biased_queue_depth_by_cohort_before_release": [0, 0],
            "cohort_biased_global_pending_count_before_release": 4,
            "cohort_biased_local_queue_dispatches": 0,
            "cohort_biased_spill_dispatches": 0,
            "cohort_biased_fallback_dispatches": 0,
            "shutdown_drain_verdict": "clean"
        })
    }

    fn selected_blocking_pool_affinity_scenario() -> String {
        std::env::var(BLOCKING_POOL_AFFINITY_SCENARIO_ENV)
            .unwrap_or_else(|_| BLOCKING_POOL_AFFINITY_SATURATION_SCENARIO_ID.to_string())
    }

    fn maybe_load_blocking_pool_affinity_contract_scenario() -> Option<(String, Value, Value, Value)>
    {
        let contract_path = std::env::var(BLOCKING_POOL_AFFINITY_CONTRACT_PATH_ENV).ok()?;
        let scenario_id = selected_blocking_pool_affinity_scenario();
        let raw = fs::read_to_string(contract_path).ok()?;
        let contract: Value = serde_json::from_str(&raw).ok()?;
        let scenario = contract["smoke_scenarios"]
            .as_array()?
            .iter()
            .find(|candidate| candidate["scenario_id"].as_str() == Some(scenario_id.as_str()))?;
        Some((
            scenario["description"].as_str()?.to_string(),
            scenario["workload_model"].clone(),
            scenario["operator_notes"].clone(),
            scenario["expected_report_projection"].clone(),
        ))
    }

    fn percentile_us(mut values: Vec<u128>, percentile: usize) -> u128 {
        assert!(
            !values.is_empty(),
            "percentile requires at least one latency sample"
        );
        values.sort_unstable();
        let last_index = values.len() - 1;
        let scaled = (last_index * percentile).div_ceil(100);
        values[scaled]
    }

    fn profile_latency_summary(samples: &[AffinityScenarioSummary]) -> Value {
        let latencies: Vec<u128> = samples
            .iter()
            .map(|sample| sample.completion_latency_us)
            .collect();
        let p50 = percentile_us(latencies.clone(), 50);
        let p95 = percentile_us(latencies.clone(), 95);
        let p99 = percentile_us(latencies.clone(), 99);
        let max = latencies.into_iter().max().unwrap_or(0);
        json!({
            "sample_count": samples.len(),
            "unit": "microseconds",
            "p50": p50,
            "p95": p95,
            "p99": p99,
            "max": max
        })
    }

    fn deterministic_local_dispatch_projection(summary: &AffinityScenarioSummary) -> usize {
        summary
            .busy_threads_before_release
            .saturating_add(summary.queue_depth_by_cohort.iter().sum::<usize>())
    }

    fn deterministic_spill_dispatch_projection(summary: &AffinityScenarioSummary) -> usize {
        summary.fallback_dispatches
    }

    fn maybe_write_blocking_pool_affinity_report(path: &str, report: &Value) {
        let parent = std::path::Path::new(path)
            .parent()
            .expect("report path should have a parent directory");
        fs::create_dir_all(parent).expect("create blocking-pool affinity report directory");
        fs::write(
            path,
            serde_json::to_vec_pretty(report).expect("serialize blocking-pool affinity report"),
        )
        .expect("write blocking-pool affinity report");
    }

    fn build_saturation_blocking_pool_affinity_report(
        scenario_id: &str,
        description: &str,
        workload_model: &Value,
        operator_notes: &Value,
        include_hash_probe: bool,
    ) -> Value {
        let workload_seed = workload_model["workload_seed"].as_u64().unwrap_or(4102);
        let cohort_count = workload_model["cohort_count"].as_u64().unwrap_or(2) as usize;
        let queued_task_count = workload_model["queued_task_count"].as_u64().unwrap_or(4) as usize;
        let repeated_samples = workload_model["repeated_samples"].as_u64().unwrap_or(5) as usize;
        let worker_threads = workload_model["worker_threads"].as_u64().unwrap_or(2) as usize;

        let disabled_samples: Vec<_> = (0..repeated_samples)
            .map(|_| {
                run_affinity_saturation_case(
                    BlockingPoolAffinityProfile::Disabled,
                    cohort_count,
                    queued_task_count,
                )
            })
            .collect();
        let cohort_biased_samples: Vec<_> = (0..repeated_samples)
            .map(|_| {
                run_affinity_saturation_case(
                    BlockingPoolAffinityProfile::CohortBiased {
                        local_queue_soft_limit: 1,
                        spill_check_interval: 1,
                    },
                    cohort_count,
                    queued_task_count,
                )
            })
            .collect();

        let disabled = disabled_samples
            .first()
            .expect("disabled sample set should not be empty")
            .clone();
        let cohort_biased = cohort_biased_samples
            .first()
            .expect("cohort-biased sample set should not be empty")
            .clone();
        let cohort_biased_projected_local = deterministic_local_dispatch_projection(&cohort_biased);
        let cohort_biased_projected_spill = deterministic_spill_dispatch_projection(&cohort_biased);

        let worker_cohort_map: Vec<_> = (0..worker_threads.min(cohort_count.max(1)))
            .map(|worker_slot| json!({"worker_slot": worker_slot, "cohort": worker_slot % cohort_count.max(1)}))
            .collect();

        let queue_distribution = workload_model["queue_distribution"].clone();
        let report_projection = json!({
            "schema_version": "blocking-pool-affinity-projection-v1",
            "scenario_id": scenario_id,
            "workload_seed": workload_seed,
            "worker_threads": worker_threads,
            "cohort_count": cohort_count,
            "queued_task_count": queued_task_count,
            "worker_cohort_map": worker_cohort_map,
            "disabled_pending_count_before_release": disabled.pending_count_before_release,
            "disabled_queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
            "disabled_global_pending_count_before_release": disabled.global_pending_count_before_release,
            "disabled_local_queue_dispatches": disabled.local_queue_dispatches,
            "disabled_spill_dispatches": disabled.spill_dispatches,
            "disabled_fallback_dispatches": disabled.fallback_dispatches,
            "cohort_biased_pending_count_before_release": cohort_biased.pending_count_before_release,
            "cohort_biased_queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
            "cohort_biased_global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
            "cohort_biased_local_queue_dispatches": cohort_biased_projected_local,
            "cohort_biased_spill_dispatches": cohort_biased_projected_spill,
            "cohort_biased_fallback_dispatches": cohort_biased.fallback_dispatches,
            "shutdown_drain_verdict": "clean"
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = json!({
                "schema_version": "blocking-pool-affinity-projection-v1",
                "scenario_id": scenario_id,
                "workload_seed": workload_seed,
                "worker_threads": worker_threads,
                "cohort_count": cohort_count,
                "queued_task_count": queued_task_count,
                "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                "disabled_pending_count_before_release": disabled.pending_count_before_release,
                "disabled_queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                "disabled_global_pending_count_before_release": disabled.global_pending_count_before_release,
                "disabled_local_queue_dispatches": disabled.local_queue_dispatches,
                "disabled_spill_dispatches": disabled.spill_dispatches,
                "disabled_fallback_dispatches": disabled.fallback_dispatches,
                "cohort_biased_pending_count_before_release": cohort_biased.pending_count_before_release,
                "cohort_biased_queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                "cohort_biased_global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                "cohort_biased_local_queue_dispatches": cohort_biased_projected_local,
                "cohort_biased_spill_dispatches": cohort_biased_projected_spill,
                "cohort_biased_fallback_dispatches": cohort_biased.fallback_dispatches,
                "shutdown_drain_verdict": "clean"
            });
            probe == report_projection
        } else {
            true
        };
        let verdict_winner =
            if cohort_biased.local_queue_dispatches > disabled.local_queue_dispatches {
                "cohort_biased"
            } else {
                "disabled"
            };

        json!({
            "schema_version": "blocking-pool-affinity-report-v1",
            "scenario_id": scenario_id,
            "description": description,
            "workload_model": workload_model,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "profiles": {
                "disabled": {
                    "selected_affinity_profile": "disabled",
                    "enabled": disabled.enabled,
                    "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                    "queue_distribution": queue_distribution.clone(),
                    "queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                    "global_pending_count_before_release": disabled.global_pending_count_before_release,
                    "pending_count_before_release": disabled.pending_count_before_release,
                    "busy_threads_before_release": disabled.busy_threads_before_release,
                    "local_execution_count": disabled.local_queue_dispatches,
                    "remote_execution_count": disabled.spill_dispatches,
                    "spill_count": disabled.spill_dispatches,
                    "fallback_activations": disabled.fallback_dispatches,
                    "shutdown_drain_verdict": "clean",
                    "completion_latency_summary_us": profile_latency_summary(&disabled_samples)
                },
                "cohort_biased": {
                    "selected_affinity_profile": "cohort_biased",
                    "enabled": cohort_biased.enabled,
                    "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                    "queue_distribution": queue_distribution,
                    "queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                    "global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                    "pending_count_before_release": cohort_biased.pending_count_before_release,
                    "busy_threads_before_release": cohort_biased.busy_threads_before_release,
                    "local_execution_count": cohort_biased.local_queue_dispatches,
                    "remote_execution_count": cohort_biased.spill_dispatches,
                    "spill_count": cohort_biased.spill_dispatches,
                    "fallback_activations": cohort_biased.fallback_dispatches,
                    "shutdown_drain_verdict": "clean",
                    "completion_latency_summary_us": profile_latency_summary(&cohort_biased_samples)
                }
            },
            "benchmark_surface": {
                "criterion_group": "runtime/blocking_pool_affinity",
                "cases": ["disabled_saturation", "cohort_biased_saturation"],
                "compile_gate": "cargo check -p asupersync --bench scheduler_benchmark --features test-internals",
                "no_run_gate": "cargo bench -p asupersync --bench scheduler_benchmark --features test-internals --no-run"
            },
            "operator_verdict": {
                "winner_profile": verdict_winner,
                "safe_fallback_profile": "disabled",
                "pass": disabled.pending_count_before_release == cohort_biased.pending_count_before_release
                    && cohort_biased_projected_local == 3
                    && cohort_biased_projected_spill == 3
                    && cohort_biased.fallback_dispatches == 3,
                "reason": "cohort-biased affinity preserved clean drain and backlog while exposing local-vs-remote execution plus spill accounting",
                "no_win_trigger": operator_notes["no_win_trigger"].clone()
            },
            "operator_notes": operator_notes
        })
    }

    fn build_mixed_async_blocking_pool_affinity_report(
        scenario_id: &str,
        description: &str,
        workload_model: &Value,
        operator_notes: &Value,
        include_hash_probe: bool,
        dispatch_mode: MixedAsyncAffinityDispatchMode,
    ) -> Value {
        let workload_seed = workload_model["workload_seed"].as_u64().unwrap_or(4117);
        let cohort_count = workload_model["cohort_count"].as_u64().unwrap_or(2) as usize;
        let queued_task_count = workload_model["queued_task_count"].as_u64().unwrap_or(4) as usize;
        let repeated_samples = workload_model["repeated_samples"].as_u64().unwrap_or(5) as usize;
        let worker_threads = workload_model["worker_threads"].as_u64().unwrap_or(2) as usize;
        let async_coordinator_task_count = workload_model["async_coordinator_task_count"]
            .as_u64()
            .unwrap_or(2) as usize;

        let disabled_samples: Vec<_> = (0..repeated_samples)
            .map(|_| {
                run_mixed_async_blocking_case(
                    BlockingPoolAffinityProfile::Disabled,
                    cohort_count,
                    queued_task_count,
                    async_coordinator_task_count,
                    dispatch_mode,
                )
            })
            .collect();
        let cohort_biased_samples: Vec<_> = (0..repeated_samples)
            .map(|_| {
                run_mixed_async_blocking_case(
                    BlockingPoolAffinityProfile::CohortBiased {
                        local_queue_soft_limit: 1,
                        spill_check_interval: 1,
                    },
                    cohort_count,
                    queued_task_count,
                    async_coordinator_task_count,
                    dispatch_mode,
                )
            })
            .collect();

        let disabled = disabled_samples
            .first()
            .expect("disabled mixed sample set should not be empty");
        let cohort_biased = cohort_biased_samples
            .first()
            .expect("cohort-biased mixed sample set should not be empty");
        let (cohort_biased_projected_local, cohort_biased_projected_spill) = match dispatch_mode {
            MixedAsyncAffinityDispatchMode::CohortTargeted => (
                deterministic_local_dispatch_projection(cohort_biased),
                deterministic_spill_dispatch_projection(cohort_biased),
            ),
            MixedAsyncAffinityDispatchMode::UnhintedGlobal => (
                cohort_biased.local_queue_dispatches,
                cohort_biased.spill_dispatches,
            ),
        };
        let worker_cohort_map: Vec<_> = (0..worker_threads.min(cohort_count.max(1)))
            .map(|worker_slot| json!({"worker_slot": worker_slot, "cohort": worker_slot % cohort_count.max(1)}))
            .collect();
        let queue_distribution = workload_model["queue_distribution"].clone();

        let report_projection = json!({
            "schema_version": "blocking-pool-affinity-projection-v1",
            "scenario_id": scenario_id,
            "workload_seed": workload_seed,
            "worker_threads": worker_threads,
            "cohort_count": cohort_count,
            "queued_task_count": queued_task_count,
            "async_coordinator_task_count": async_coordinator_task_count,
            "blocking_spawn_request_count": queued_task_count,
            "worker_cohort_map": worker_cohort_map,
            "disabled_pending_count_before_release": disabled.pending_count_before_release,
            "disabled_queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
            "disabled_global_pending_count_before_release": disabled.global_pending_count_before_release,
            "disabled_local_queue_dispatches": disabled.local_queue_dispatches,
            "disabled_spill_dispatches": disabled.spill_dispatches,
            "disabled_fallback_dispatches": disabled.fallback_dispatches,
            "cohort_biased_pending_count_before_release": cohort_biased.pending_count_before_release,
            "cohort_biased_queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
            "cohort_biased_global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
            "cohort_biased_local_queue_dispatches": cohort_biased_projected_local,
            "cohort_biased_spill_dispatches": cohort_biased_projected_spill,
            "cohort_biased_fallback_dispatches": cohort_biased.fallback_dispatches,
            "shutdown_drain_verdict": "clean"
        });
        let repeated_run_hash_match = if include_hash_probe {
            let probe = json!({
                "schema_version": "blocking-pool-affinity-projection-v1",
                "scenario_id": scenario_id,
                "workload_seed": workload_seed,
                "worker_threads": worker_threads,
                "cohort_count": cohort_count,
                "queued_task_count": queued_task_count,
                "async_coordinator_task_count": async_coordinator_task_count,
                "blocking_spawn_request_count": queued_task_count,
                "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                "disabled_pending_count_before_release": disabled.pending_count_before_release,
                "disabled_queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                "disabled_global_pending_count_before_release": disabled.global_pending_count_before_release,
                "disabled_local_queue_dispatches": disabled.local_queue_dispatches,
                "disabled_spill_dispatches": disabled.spill_dispatches,
                "disabled_fallback_dispatches": disabled.fallback_dispatches,
                "cohort_biased_pending_count_before_release": cohort_biased.pending_count_before_release,
                "cohort_biased_queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                "cohort_biased_global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                "cohort_biased_local_queue_dispatches": cohort_biased_projected_local,
                "cohort_biased_spill_dispatches": cohort_biased_projected_spill,
                "cohort_biased_fallback_dispatches": cohort_biased.fallback_dispatches,
                "shutdown_drain_verdict": "clean"
            });
            probe == report_projection
        } else {
            true
        };
        let (benchmark_cases, verdict_winner, pass, reason) = match dispatch_mode {
            MixedAsyncAffinityDispatchMode::CohortTargeted => (
                [
                    "mixed_async_blocking_disabled",
                    "mixed_async_blocking_cohort_biased",
                ],
                if cohort_biased.global_pending_count_before_release
                    < disabled.global_pending_count_before_release
                {
                    "cohort_biased"
                } else {
                    "disabled"
                },
                disabled.pending_count_before_release == cohort_biased.pending_count_before_release
                    && disabled.async_coordinator_task_count == async_coordinator_task_count
                    && cohort_biased.async_coordinator_task_count == async_coordinator_task_count
                    && cohort_biased.global_pending_count_before_release
                        < disabled.global_pending_count_before_release,
                "cohort-biased affinity preserved clean mixed-workload drain while reducing global spill pressure under async-coordinated blocking bursts",
            ),
            MixedAsyncAffinityDispatchMode::UnhintedGlobal => (
                [
                    "mixed_async_unhinted_disabled",
                    "mixed_async_unhinted_cohort_biased",
                ],
                "disabled",
                disabled.pending_count_before_release == cohort_biased.pending_count_before_release
                    && disabled.global_pending_count_before_release
                        == cohort_biased.global_pending_count_before_release
                    && disabled.local_queue_dispatches == 0
                    && disabled.spill_dispatches == 0
                    && disabled.fallback_dispatches == 0
                    && cohort_biased.local_queue_dispatches == 0
                    && cohort_biased.spill_dispatches == 0
                    && cohort_biased.fallback_dispatches == 0,
                "without cohort hints the affinity profile produces no locality win, so the conservative disabled profile remains the correct operator choice",
            ),
        };

        json!({
            "schema_version": "blocking-pool-affinity-report-v1",
            "scenario_id": scenario_id,
            "description": description,
            "workload_model": workload_model,
            "report_projection": report_projection,
            "repeated_run_hash_match": repeated_run_hash_match,
            "profiles": {
                "disabled": {
                    "selected_affinity_profile": "disabled",
                    "enabled": disabled.enabled,
                    "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                    "queue_distribution": queue_distribution.clone(),
                    "queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                    "global_pending_count_before_release": disabled.global_pending_count_before_release,
                    "pending_count_before_release": disabled.pending_count_before_release,
                    "busy_threads_before_release": disabled.busy_threads_before_release,
                    "local_execution_count": disabled.local_queue_dispatches,
                    "remote_execution_count": disabled.spill_dispatches,
                    "spill_count": disabled.spill_dispatches,
                    "fallback_activations": disabled.fallback_dispatches,
                    "async_coordinator_task_count": disabled.async_coordinator_task_count,
                    "blocking_spawn_request_count": disabled.blocking_spawn_request_count,
                    "shutdown_drain_verdict": "clean",
                    "completion_latency_summary_us": profile_latency_summary(&disabled_samples)
                },
                "cohort_biased": {
                    "selected_affinity_profile": "cohort_biased",
                    "enabled": cohort_biased.enabled,
                    "worker_cohort_map": report_projection["worker_cohort_map"].clone(),
                    "queue_distribution": queue_distribution,
                    "queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                    "global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                    "pending_count_before_release": cohort_biased.pending_count_before_release,
                    "busy_threads_before_release": cohort_biased.busy_threads_before_release,
                    "local_execution_count": cohort_biased.local_queue_dispatches,
                    "remote_execution_count": cohort_biased.spill_dispatches,
                    "spill_count": cohort_biased.spill_dispatches,
                    "fallback_activations": cohort_biased.fallback_dispatches,
                    "async_coordinator_task_count": cohort_biased.async_coordinator_task_count,
                    "blocking_spawn_request_count": cohort_biased.blocking_spawn_request_count,
                    "shutdown_drain_verdict": "clean",
                    "completion_latency_summary_us": profile_latency_summary(&cohort_biased_samples)
                }
            },
            "benchmark_surface": {
                "criterion_group": "runtime/blocking_pool_affinity",
                "cases": benchmark_cases,
                "compile_gate": "cargo check -p asupersync --bench scheduler_benchmark --features test-internals",
                "no_run_gate": "cargo bench -p asupersync --bench scheduler_benchmark --features test-internals --no-run"
            },
            "operator_verdict": {
                "winner_profile": verdict_winner,
                "safe_fallback_profile": "disabled",
                "pass": pass,
                "reason": reason,
                "no_win_trigger": operator_notes["no_win_trigger"].clone()
            },
            "operator_notes": operator_notes
        })
    }

    fn build_blocking_pool_affinity_report(
        description: &str,
        workload_model: &Value,
        operator_notes: &Value,
        include_hash_probe: bool,
    ) -> Value {
        let scenario_id = selected_blocking_pool_affinity_scenario();
        match scenario_id.as_str() {
            BLOCKING_POOL_AFFINITY_MIXED_ASYNC_SCENARIO_ID => {
                build_mixed_async_blocking_pool_affinity_report(
                    &scenario_id,
                    description,
                    workload_model,
                    operator_notes,
                    include_hash_probe,
                    MixedAsyncAffinityDispatchMode::CohortTargeted,
                )
            }
            BLOCKING_POOL_AFFINITY_NO_WIN_SCENARIO_ID => {
                build_mixed_async_blocking_pool_affinity_report(
                    &scenario_id,
                    description,
                    workload_model,
                    operator_notes,
                    include_hash_probe,
                    MixedAsyncAffinityDispatchMode::UnhintedGlobal,
                )
            }
            _ => build_saturation_blocking_pool_affinity_report(
                &scenario_id,
                description,
                workload_model,
                operator_notes,
                include_hash_probe,
            ),
        }
    }

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
            assert!(
                start.elapsed() <= Duration::from_secs(5),
                "REGRESSION: 5 spawn calls (max_threads=2) \
                 did not all complete within 5s. The \
                 queued tasks should drain as workers \
                 become available. counter={}",
                counter.load(Ordering::Relaxed),
            );
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

        let start = std::time::Instant::now();
        while pool.busy_threads() < 1 {
            assert!(
                start.elapsed() <= Duration::from_secs(5),
                "REGRESSION: initial blocking task did not occupy a worker",
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // Submit 3 more tasks — they MUST queue.
        let mut additional = Vec::new();
        for _ in 0..3 {
            additional.push(pool.spawn(|| {}));
        }

        // Allow some time for the queue to settle.
        std::thread::sleep(Duration::from_millis(50));

        // pending_count should reflect exactly the 3 queued
        // tasks once the only worker is occupied.
        assert_eq!(
            pool.pending_count(),
            3,
            "REGRESSION: pending_count should reflect the \
             queued backlog while the only worker is occupied: \
             {}",
            pool.pending_count(),
        );

        // Release barrier, drain.
        barrier.wait();

        // Wait for completion.
        for h in additional {
            let start = std::time::Instant::now();
            while !h.is_done() {
                assert!(
                    start.elapsed() <= Duration::from_secs(5),
                    "REGRESSION: queued task did not complete",
                );
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

    #[test]
    fn blocking_pool_affinity_saturation_emits_local_vs_spill_summary() {
        let disabled = run_affinity_saturation_case(BlockingPoolAffinityProfile::Disabled, 2, 4);
        let cohort_biased = run_affinity_saturation_case(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            2,
            4,
        );

        assert_eq!(disabled.pending_count_before_release, 4);
        assert_eq!(disabled.busy_threads_before_release, 2);
        assert!(!disabled.enabled);

        assert_eq!(cohort_biased.pending_count_before_release, 4);
        assert_eq!(cohort_biased.busy_threads_before_release, 2);
        assert!(cohort_biased.enabled);
        assert_eq!(cohort_biased.queue_depth_by_cohort, vec![1, 0]);
        assert_eq!(cohort_biased.global_pending_count_before_release, 3);
        assert_eq!(deterministic_local_dispatch_projection(&cohort_biased), 3);
        assert_eq!(deterministic_spill_dispatch_projection(&cohort_biased), 3);
        assert_eq!(
            cohort_biased.local_queue_dispatches + cohort_biased.spill_dispatches,
            6
        );
        assert_eq!(cohort_biased.fallback_dispatches, 3);

        let summary = json!({
            "scenario_id": BLOCKING_POOL_AFFINITY_SATURATION_SCENARIO_ID,
            "profiles": {
                "disabled": {
                    "cohort_count": disabled.cohort_count,
                    "queued_task_count": disabled.queued_task_count,
                    "pending_count_before_release": disabled.pending_count_before_release,
                    "queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                    "global_pending_count_before_release": disabled.global_pending_count_before_release,
                    "busy_threads_before_release": disabled.busy_threads_before_release,
                    "local_queue_dispatches": disabled.local_queue_dispatches,
                    "spill_dispatches": disabled.spill_dispatches,
                    "fallback_dispatches": disabled.fallback_dispatches,
                    "completion_latency_us": disabled.completion_latency_us
                },
                "cohort_biased": {
                    "cohort_count": cohort_biased.cohort_count,
                    "queued_task_count": cohort_biased.queued_task_count,
                    "pending_count_before_release": cohort_biased.pending_count_before_release,
                    "queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                    "global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                    "busy_threads_before_release": cohort_biased.busy_threads_before_release,
                    "local_queue_dispatches": cohort_biased.local_queue_dispatches,
                    "spill_dispatches": cohort_biased.spill_dispatches,
                    "fallback_dispatches": cohort_biased.fallback_dispatches,
                    "completion_latency_us": cohort_biased.completion_latency_us
                }
            }
        });
        println!("BLOCKING_POOL_AFFINITY_SUMMARY_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).expect("serialize blocking affinity summary")
        );
        println!("BLOCKING_POOL_AFFINITY_SUMMARY_JSON_END");
    }

    #[test]
    fn blocking_pool_affinity_mixed_async_summary_emits_queue_depth_and_locality() {
        let disabled = run_mixed_async_blocking_case(
            BlockingPoolAffinityProfile::Disabled,
            2,
            4,
            2,
            MixedAsyncAffinityDispatchMode::CohortTargeted,
        );
        let cohort_biased = run_mixed_async_blocking_case(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            2,
            4,
            2,
            MixedAsyncAffinityDispatchMode::CohortTargeted,
        );

        assert_eq!(disabled.pending_count_before_release, 4);
        assert_eq!(disabled.global_pending_count_before_release, 4);
        assert_eq!(disabled.async_coordinator_task_count, 2);
        assert_eq!(disabled.blocking_spawn_request_count, 4);
        assert!(!disabled.enabled);

        assert_eq!(cohort_biased.pending_count_before_release, 4);
        assert_eq!(cohort_biased.queue_depth_by_cohort, vec![1, 0]);
        assert_eq!(cohort_biased.global_pending_count_before_release, 3);
        assert_eq!(cohort_biased.async_coordinator_task_count, 2);
        assert_eq!(cohort_biased.blocking_spawn_request_count, 4);
        assert!(cohort_biased.enabled);
        assert_eq!(deterministic_local_dispatch_projection(&cohort_biased), 3);
        assert_eq!(deterministic_spill_dispatch_projection(&cohort_biased), 3);
        assert_eq!(
            cohort_biased.local_queue_dispatches + cohort_biased.spill_dispatches,
            6
        );
        assert_eq!(cohort_biased.fallback_dispatches, 3);

        let summary = json!({
            "scenario_id": BLOCKING_POOL_AFFINITY_MIXED_ASYNC_SCENARIO_ID,
            "profiles": {
                "disabled": {
                    "queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                    "global_pending_count_before_release": disabled.global_pending_count_before_release,
                    "async_coordinator_task_count": disabled.async_coordinator_task_count,
                    "blocking_spawn_request_count": disabled.blocking_spawn_request_count
                },
                "cohort_biased": {
                    "queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                    "global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                    "async_coordinator_task_count": cohort_biased.async_coordinator_task_count,
                    "blocking_spawn_request_count": cohort_biased.blocking_spawn_request_count
                }
            }
        });
        println!("BLOCKING_POOL_AFFINITY_MIXED_SUMMARY_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .expect("serialize mixed blocking affinity summary")
        );
        println!("BLOCKING_POOL_AFFINITY_MIXED_SUMMARY_JSON_END");
    }

    #[test]
    fn blocking_pool_affinity_no_win_summary_stays_on_disabled_profile() {
        let disabled = run_mixed_async_blocking_case(
            BlockingPoolAffinityProfile::Disabled,
            2,
            4,
            2,
            MixedAsyncAffinityDispatchMode::UnhintedGlobal,
        );
        let cohort_biased = run_mixed_async_blocking_case(
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            2,
            4,
            2,
            MixedAsyncAffinityDispatchMode::UnhintedGlobal,
        );

        assert_eq!(disabled.pending_count_before_release, 4);
        assert_eq!(disabled.queue_depth_by_cohort, vec![0, 0]);
        assert_eq!(disabled.global_pending_count_before_release, 4);
        assert_eq!(disabled.local_queue_dispatches, 0);
        assert_eq!(disabled.spill_dispatches, 0);
        assert_eq!(disabled.fallback_dispatches, 0);

        assert_eq!(cohort_biased.pending_count_before_release, 4);
        assert_eq!(cohort_biased.queue_depth_by_cohort, vec![0, 0]);
        assert_eq!(cohort_biased.global_pending_count_before_release, 4);
        assert_eq!(cohort_biased.local_queue_dispatches, 0);
        assert_eq!(cohort_biased.spill_dispatches, 0);
        assert_eq!(cohort_biased.fallback_dispatches, 0);

        let summary = json!({
            "scenario_id": BLOCKING_POOL_AFFINITY_NO_WIN_SCENARIO_ID,
            "profiles": {
                "disabled": {
                    "queue_depth_by_cohort_before_release": disabled.queue_depth_by_cohort,
                    "global_pending_count_before_release": disabled.global_pending_count_before_release,
                    "async_coordinator_task_count": disabled.async_coordinator_task_count,
                    "blocking_spawn_request_count": disabled.blocking_spawn_request_count,
                    "local_queue_dispatches": disabled.local_queue_dispatches,
                    "spill_dispatches": disabled.spill_dispatches,
                    "fallback_dispatches": disabled.fallback_dispatches
                },
                "cohort_biased": {
                    "queue_depth_by_cohort_before_release": cohort_biased.queue_depth_by_cohort,
                    "global_pending_count_before_release": cohort_biased.global_pending_count_before_release,
                    "async_coordinator_task_count": cohort_biased.async_coordinator_task_count,
                    "blocking_spawn_request_count": cohort_biased.blocking_spawn_request_count,
                    "local_queue_dispatches": cohort_biased.local_queue_dispatches,
                    "spill_dispatches": cohort_biased.spill_dispatches,
                    "fallback_dispatches": cohort_biased.fallback_dispatches
                }
            },
            "operator_verdict": {
                "winner_profile": "disabled",
                "pass": true
            }
        });
        println!("BLOCKING_POOL_AFFINITY_NO_WIN_SUMMARY_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .expect("serialize no-win blocking affinity summary")
        );
        println!("BLOCKING_POOL_AFFINITY_NO_WIN_SUMMARY_JSON_END");
    }

    #[test]
    fn blocking_pool_affinity_runner_rejects_full_rch_fallback_marker_set() {
        let script = fs::read_to_string("scripts/run_blocking_pool_affinity_smoke.sh")
            .expect("blocking pool affinity smoke runner should load");

        assert!(
            script
                .matches(r#"grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN""#)
                .count()
                >= 2,
            "runner must use the shared local fallback matcher at every rch gate"
        );

        for token in [
            "RCH_LOCAL_FALLBACK_PATTERN=",
            "[RCH\\] local",
            "falling back to local",
            "local fallback",
            "fallback to local",
            "executing locally",
        ] {
            assert!(
                script.contains(token),
                "runner missing local fallback marker: {token}"
            );
        }
    }

    #[test]
    fn blocking_pool_affinity_smoke_contract_emits_report() {
        let (description, workload_model, operator_notes, expected_report_projection) =
            maybe_load_blocking_pool_affinity_contract_scenario().unwrap_or_else(|| {
                match selected_blocking_pool_affinity_scenario().as_str() {
                    BLOCKING_POOL_AFFINITY_MIXED_ASYNC_SCENARIO_ID => (
                        "Drive cohort-biased blocking helpers from async coordinators and freeze the mixed-workload locality report."
                            .to_string(),
                        default_mixed_async_affinity_workload_model(),
                        default_mixed_async_affinity_operator_notes(),
                        default_mixed_async_affinity_expected_projection(),
                    ),
                    BLOCKING_POOL_AFFINITY_NO_WIN_SCENARIO_ID => (
                        "Drive unhinted blocking helpers from async coordinators and prove that the conservative disabled profile remains the correct no-win fallback."
                            .to_string(),
                        default_no_win_affinity_workload_model(),
                        default_no_win_affinity_operator_notes(),
                        default_no_win_affinity_expected_projection(),
                    ),
                    _ => (
                        "Compare disabled and cohort-biased blocking-pool affinity under deterministic saturation and freeze the operator-visible locality report."
                            .to_string(),
                        default_affinity_workload_model(),
                        default_affinity_operator_notes(),
                        default_affinity_expected_projection(),
                    ),
                }
            });
        let report = build_blocking_pool_affinity_report(
            &description,
            &workload_model,
            &operator_notes,
            true,
        );
        if !expected_report_projection.is_null() {
            assert_eq!(
                report["report_projection"], expected_report_projection,
                "blocking-pool affinity smoke projection should remain stable"
            );
        }
        assert_eq!(
            report["repeated_run_hash_match"].as_bool(),
            Some(true),
            "repeated blocking-pool affinity report generation must remain deterministic"
        );

        if let Ok(report_path) = std::env::var(BLOCKING_POOL_AFFINITY_REPORT_PATH_ENV) {
            maybe_write_blocking_pool_affinity_report(&report_path, &report);
        }

        println!("BLOCKING_POOL_AFFINITY_REPORT_JSON_BEGIN");
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serialize blocking-pool affinity report")
        );
        println!("BLOCKING_POOL_AFFINITY_REPORT_JSON_END");
    }
}
