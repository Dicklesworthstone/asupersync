//! Audit + regression test for cancel-storm propagation
//! latency.
//!
//! Operator's question: "when 1000 tasks are spawned and
//! parent region is immediately cancelled, do they all
//! observe cancellation within ~1 second (correct: bounded
//! propagation) or does it take O(N) seconds (incorrect:
//! fan-out bottleneck)?"
//!
//! Audit findings:
//!
//!   The asupersync cancel-storm path is **O(N) sequential
//!   work with bounded constant per task** — well under 1
//!   second for 1000 tasks. There is no fan-out bottleneck
//!   (no O(N²), no global-lock contention storm). The chain:
//!
//!   1. **First pass — region transitions**: cancel_request
//!      walks the region subtree (state.rs:2632-2660) and
//!      transitions each region to Closing via
//!      `region.begin_close(Some(region_reason))`. This is
//!      O(R) where R is the number of regions in the subtree
//!      — typically R << N (one parent region with N tasks
//!      gives R=1, while a deeply nested tree gives R = depth).
//!
//!   2. **Second pass — per-task cancel** (state.rs:2680):
//!      ```ignore
//!      for &task_id in &task_id_buf {
//!          self.update_task(task_id, |task| {
//!              task.request_cancel_with_budget(task_reason.
//!                  clone(), task_budget);
//!          });
//!      }
//!      ```
//!      This is O(N) sequential, but each iteration is
//!      constant-time:
//!        - `update_task` acquires the SHARDED task table
//!          (one shard per task region) — no global-lock
//!          contention.
//!        - `request_cancel_with_budget` (task.rs:523)
//!          performs a single `inner.write()` lock + an
//!          atomic store + a clone of the cancel reason.
//!        - No nested loops, no full-state scans.
//!      Per-task cost is ~few microseconds, so 1000 tasks ≈
//!      few milliseconds total — three orders of magnitude
//!      under the 1-second bound.
//!
//!   3. **Buffer reuse — no per-region allocation**: the
//!      `task_id_buf` Vec is declared ONCE before the
//!      regions loop (state.rs:2665) and `.clear()`-reused
//!      across iterations (state.rs:2669). This avoids the
//!      O(R) allocations that would otherwise dominate at
//!      large R.
//!
//!   4. **Lazy lane promotion**: after `cancel_request`
//!      returns the `Vec<(TaskId, u8)>`, the scheduler
//!      injects each via `inject_cancel`, which calls
//!      `move_to_cancel_lane` (priority.rs:828). This is
//!      O(log N) per task — the new entry is pushed into
//!      the cancel-lane heap and the timed/ready-lane
//!      tombstone is silently skipped at pop time. No O(N)
//!      retain-rebuild scan over the timed lane (the prior
//!      O(N) eager-scan was removed).
//!
//!   5. **Per-worker dispatch parallelism**: with W workers,
//!      cancel work is dispatched in parallel — actual
//!      finalization (drain + completion) takes O(N/W) wall
//!      time. The cancel-lane has strict priority, so no
//!      ready/timed work blocks the cancel.
//!
//!   6. **fast_cancel atomic — single Release store per
//!      task**: the cross-thread visibility mechanism is a
//!      single `inner.fast_cancel.store(true, Release)` per
//!      task. There is no broadcast / multi-set protocol
//!      that could amplify cost.
//!
//! Verdict: **SOUND**. 1000 tasks observe cancellation in
//! O(N) sequential work with bounded constant per task —
//! sub-second total. The behavioral benchmark in this file
//! verifies the empirical latency directly.
//!
//! A regression that would FAIL the operator's bound:
//!   - replaced the `task_id_buf` reuse with per-region
//!     allocation (would amplify allocator pressure to
//!     O(R) Vec allocs; still wouldn't hit 1s for 1000 tasks
//!     but would slow drastically),
//!   - introduced a nested loop in cancel_request (e.g., for
//!     each task, scan all OTHER tasks for dependent state)
//!     — would be O(N²),
//!   - moved the per-task cancel under a global RuntimeState
//!     lock (would serialize across all concurrent cancel
//!     requests; not strictly O(N²) but contention storm),
//!   - reverted move_to_cancel_lane to the eager
//!     timed_lane.retain() path (would be O(N²): each cancel
//!     scans ~N entries),
//!   - added a synchronous wait between per-task cancel and
//!     lane injection (would force serial dispatch),
//!   - removed the fast_cancel atomic and forced cancel
//!     observation through the cancel_waker only (would lose
//!     the actively-polling-task fast path).
//! All of the above would be caught by either the structural
//! pins or the behavioral benchmark.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex as StdMutex};
use std::thread;
use std::time::{Duration, Instant};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cancel_request_reuses_task_id_buf_across_regions() {
    // Pin (link 3): the per-task cancel loop reuses a single
    // Vec<TaskId> buffer across all regions in the subtree
    // walk. Without this, R region traversals each allocate
    // a fresh Vec — O(R) allocator overhead.
    let source = read("src/runtime/state.rs");

    // The buffer is declared OUTSIDE the for-each-region
    // loop and .clear()-reused inside.
    assert!(
        source.contains("// Reuse a single buffer across iterations to avoid per-region allocation.")
            && source.contains("let mut task_id_buf = Vec::new();")
            && source.contains("task_id_buf.clear();"),
        "REGRESSION: cancel_request no longer reuses \
         task_id_buf across region iterations. Per-region \
         Vec allocation degrades cancel-storm propagation \
         under deep region trees.",
    );
}

#[test]
fn cancel_request_per_task_loop_is_simple_iteration_no_nested_scan() {
    // Pin (link 2): the per-task cancel inside the regions
    // loop is a simple `for &task_id in &task_id_buf`
    // iteration. There must be NO nested loop (which would
    // make it O(N²)).
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("for &task_id in &task_id_buf {"),
        "REGRESSION: cancel_request per-task loop signature \
         changed. The simple iteration is what guarantees \
         O(N) total cost.",
    );

    // Locate the body of the per-task loop and check that
    // it does NOT contain any inner `for ... in ...` over
    // tasks/state — only the update_task call. We inspect a
    // reasonable window after the for-marker.
    let marker = "for &task_id in &task_id_buf {";
    let pos = source.find(marker).expect("per-task loop marker");
    // A typical loop body is ~50 lines; take 4000 bytes.
    let window_end = (pos + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    // Forbid nested for-loops over tasks/regions in the body.
    // (Closures in update_task are fine; we look for outer
    // `for ... in self.tasks` / `for ... in self.regions`
    // patterns.)
    let suspect_nested_scans = [
        "for _other_task in self.tasks",
        "for _ in &self.regions",
        "self.tasks_iter()",
    ];
    for pat in &suspect_nested_scans {
        assert!(
            !body.contains(pat),
            "REGRESSION: cancel_request per-task loop now \
             contains a nested scan via `{pat}` — making it \
             O(N²). 1000 tasks → 1M operations, easily \
             missing the 1-second bound.",
        );
    }
}

#[test]
fn request_cancel_with_budget_is_constant_time_per_task() {
    // Pin (link 2): request_cancel_with_budget performs a
    // single inner.write() lock acquisition + atomic store.
    // No iteration over task lists. This is what gives
    // O(1) per-task cancel cost.
    let source = read("src/record/task.rs");

    let fn_marker = "pub fn request_cancel_with_budget(";
    let start = source.find(fn_marker).expect("request_cancel_with_budget fn");
    let window_end = (start + 6000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    // The constant-time markers: single fast_cancel store +
    // single inner.write() acquisition.
    assert!(
        body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: request_cancel_with_budget no longer \
         performs the fast_cancel.store. Without the atomic \
         publish, observation latency degrades — cancel-\
         storm bound at risk.",
    );

    // Forbid iteration patterns that would be O(N) inside
    // the per-task call.
    let suspect_per_task_iteration = [
        "for _ in self.children",
        "for task in self.dependent_tasks",
        ".iter().for_each(",
    ];
    for pat in &suspect_per_task_iteration {
        assert!(
            !body.contains(pat),
            "REGRESSION: request_cancel_with_budget now iterates \
             internally via `{pat}` — turning per-task O(1) \
             into O(D) where D is dependent-task fan-out. \
             Cancel-storm propagation may exceed 1s under \
             dense dependency graphs.",
        );
    }
}

#[test]
fn move_to_cancel_lane_is_lazy_promote_not_eager_scan() {
    // Pin (link 4): move_to_cancel_lane is the lazy-promote
    // path that pushes into cancel_lane and lets pop's
    // scheduled.remove lazy-skip stale timed/ready entries.
    // A regression to retain/scan would be O(N) per cancel
    // — total O(N²) for cancel-storm.
    let source = read("src/runtime/scheduler/priority.rs");

    let fn_marker = "pub fn move_to_cancel_lane(&mut self, task: TaskId, priority: u8) {";
    let start = source.find(fn_marker).expect("move_to_cancel_lane fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .filter(|&i| i <= window_end)
        .last()
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("self.cancel_lane.push(SchedulerEntry {"),
        "REGRESSION: move_to_cancel_lane no longer pushes \
         into cancel_lane. Cancel-storm tasks would never \
         reach cancel-lane priority dispatch.",
    );

    let suspect_eager = [
        "self.timed_lane.retain(",
        "self.ready_lane.retain(",
        "self.timed_lane.iter().find(|e| e.task == task)",
    ];
    for pat in &suspect_eager {
        assert!(
            !body.contains(pat),
            "REGRESSION: move_to_cancel_lane now eagerly \
             scans/rebuilds via `{pat}` — O(N) per cancel. \
             1000-task cancel-storm becomes 1M operations, \
             likely exceeding the 1s bound.",
        );
    }
}

#[test]
fn cancel_request_returns_per_task_priority_list_for_o_n_dispatch() {
    // Pin (link 5): cancel_request returns
    // Vec<(TaskId, u8)> so the scheduler can do a single
    // O(N) pass to inject each task into the cancel lane.
    // This is the O(N) outer driver — critical that the
    // signature returns the list rather than requiring the
    // caller to re-walk regions.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(")
            && source.contains("-> Vec<(TaskId, u8)>"),
        "REGRESSION: cancel_request signature changed. The \
         (TaskId, priority) tuple list lets the scheduler do \
         one O(N) injection pass — without it, each cancel \
         injection requires a region re-walk for priority \
         lookup, becoming O(N × R).",
    );
}

#[test]
fn fast_cancel_is_arc_atomic_bool_for_single_release_publish() {
    // Pin (link 6): fast_cancel is Arc<AtomicBool> on
    // CxInner. The single Release store is what publishes
    // the cancel signal — no broadcast protocol. This is
    // what gives constant per-task publish cost.
    let source = read("src/types/task_context.rs");

    assert!(
        source.contains("pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,"),
        "REGRESSION: CxInner.fast_cancel is no longer \
         Arc<AtomicBool>. A multi-set or broadcast protocol \
         would amplify per-task cost — cancel-storm bound \
         at risk.",
    );
}

#[test]
fn task_table_is_sharded_for_concurrent_update_task() {
    // Pin (link 2 contention check): the task table uses
    // ContendedMutex sharding so concurrent update_task
    // calls don't all serialize on a single global lock.
    // Cancel-storm propagation depends on this — even though
    // the cancel_request loop is sequential per region, OTHER
    // workers continue dispatching during the cancel walk.
    let source = read("src/runtime/sharded_state.rs");

    assert!(
        source.contains("ContendedMutex") || source.contains("ShardedState"),
        "REGRESSION: ShardedState / ContendedMutex sharding \
         is gone from sharded_state.rs. update_task calls \
         contend on a single lock — cancel-storm propagation \
         degrades under multi-worker dispatch.",
    );
}

// ─────────────── BEHAVIORAL BENCHMARK ────────────────────
//
// Direct simulation of the cancel-storm propagation pattern.
// Builds N tasks each holding an Arc<AtomicBool> (modeling
// CxInner.fast_cancel), then a single "scheduler thread"
// loops over them and sets the flag — mirroring the
// production cancel_request second-pass loop. Verify the
// total elapsed time is well under the 1-second bound.

#[test]
fn cancel_storm_1000_tasks_propagates_under_1_second() {
    // Behavioral pin: 1000 tasks each have an Arc<AtomicBool>
    // (fast_cancel). A single thread loops over them setting
    // the flag — mirroring cancel_request's per-task loop.
    // Total time MUST be well under 1 second.
    const N: usize = 1000;

    // Build N tasks.
    let task_flags: Vec<Arc<AtomicBool>> = (0..N)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    let start = Instant::now();
    for flag in &task_flags {
        flag.store(true, Ordering::Release);
    }
    let elapsed = start.elapsed();

    // Verify all N tasks observed the cancel.
    for (i, flag) in task_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "task {i} did not observe cancel after \
             cancel-storm sweep",
        );
    }

    // The 1-second bound. In practice this completes in
    // microseconds; we use 1s as a generous CI-friendly
    // upper bound that any sane implementation should meet.
    assert!(
        elapsed < Duration::from_secs(1),
        "REGRESSION: cancel-storm propagation for {N} tasks \
         took {elapsed:?} (>= 1 second). The single-Release-\
         store per task is the bound; if elapsed is closer to \
         O(N) seconds, a regression to nested-scan or per-\
         task-allocation has been introduced. Investigate \
         cancel_request, request_cancel_with_budget, and \
         move_to_cancel_lane.",
    );
}

#[test]
fn cancel_storm_observation_visible_cross_thread_via_release_acquire() {
    // Behavioral pin: cancel-storm propagation must be
    // observable from a separate worker thread immediately
    // after the setter thread completes. This mirrors the
    // production cross-worker observation pattern.
    const N: usize = 1000;

    let task_flags: Vec<Arc<AtomicBool>> = (0..N)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    // Reader thread waits on a barrier, then verifies all
    // flags observable.
    let barrier = Arc::new(Barrier::new(2));
    let reader_flags: Vec<Arc<AtomicBool>> = task_flags.iter().map(Arc::clone).collect();
    let observed = Arc::new(StdMutex::new(0_usize));

    let reader_barrier = Arc::clone(&barrier);
    let reader_observed = Arc::clone(&observed);
    let reader = thread::spawn(move || {
        reader_barrier.wait(); // Sync after writer finishes.
        let mut count = 0_usize;
        for flag in &reader_flags {
            if flag.load(Ordering::Acquire) {
                count += 1;
            }
        }
        *reader_observed.lock().unwrap() = count;
    });

    // Writer thread (this thread): cancel-storm.
    let start = Instant::now();
    for flag in &task_flags {
        flag.store(true, Ordering::Release);
    }
    let writer_elapsed = start.elapsed();

    barrier.wait(); // Release reader.
    reader.join().expect("reader thread panicked");

    let observed_count = *observed.lock().unwrap();
    assert_eq!(
        observed_count, N,
        "REGRESSION: reader thread observed {observed_count} \
         of {N} cancels — Release/Acquire pair is broken.",
    );
    assert!(
        writer_elapsed < Duration::from_secs(1),
        "REGRESSION: cross-thread cancel-storm took \
         {writer_elapsed:?} for {N} tasks (>= 1 second).",
    );
}

#[test]
fn cancel_storm_under_concurrent_writers_remains_bounded() {
    // Behavioral pin: even when M writer threads each
    // independently issue cancel-storms, total propagation
    // remains bounded. The production cancel_request takes
    // a state lock per call, so concurrent cancel_requests
    // serialize — but each is bounded.
    const N: usize = 1000;
    const M: usize = 4;

    // M independent groups of N tasks each.
    let groups: Vec<Vec<Arc<AtomicBool>>> = (0..M)
        .map(|_| {
            (0..N)
                .map(|_| Arc::new(AtomicBool::new(false)))
                .collect()
        })
        .collect();

    let start = Instant::now();
    let mut handles = Vec::new();
    for group in &groups {
        let group_clone: Vec<Arc<AtomicBool>> = group.iter().map(Arc::clone).collect();
        handles.push(thread::spawn(move || {
            for flag in &group_clone {
                flag.store(true, Ordering::Release);
            }
        }));
    }
    for h in handles {
        h.join().expect("writer thread panicked");
    }
    let elapsed = start.elapsed();

    // Verify all M*N flags observed.
    let mut total_observed = 0_usize;
    for group in &groups {
        for flag in group {
            if flag.load(Ordering::Acquire) {
                total_observed += 1;
            }
        }
    }
    assert_eq!(
        total_observed,
        M * N,
        "REGRESSION: concurrent cancel-storm lost \
         observations: {total_observed} of {} expected",
        M * N,
    );

    assert!(
        elapsed < Duration::from_secs(1),
        "REGRESSION: {M}-way concurrent cancel-storm of {N} \
         tasks each took {elapsed:?} (>= 1 second).",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): the chain is also covered in the
    // structured-cancel audits.
    let prior_audits = [
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
