//! Structural audit for cancel-storm propagation.
//!
//! This file pins several useful implementation properties: region task-ID
//! buffers are reused, the outer fanout loop does not rescan the global task or
//! region tables per child, lane promotion does not retain-scan the ready or
//! timed heap, and cancellation effects cross a post-lock publication boundary.
//!
//! It deliberately makes no wall-clock latency or constant-time claim. A task
//! may own an unbounded number `W` of cancel-Waker registrations, and snapshot
//! deduplication currently performs a linear `will_wake` search per target, so
//! one task's snapshot can be O(W^2). Reason cloning, validator work, locks,
//! effect merging, scheduler publication, and later lifecycle processing also
//! sit outside the atomic microfixtures below. Those fixtures prove only
//! Release/Acquire visibility for the isolated fast-cancel flags; they are not
//! production cancellation benchmarks.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex as StdMutex};
use std::thread;

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
        source
            .contains("// Reuse a single buffer across iterations to avoid per-region allocation.")
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
    // Pin the outer traversal shape only. Work performed by
    // each TaskRecord, including Waker deduplication, is not
    // constant and is deliberately outside this assertion.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("for &task_id in &task_id_buf {"),
        "REGRESSION: cancel_request per-task loop signature \
         changed; inspect whether the replacement rescans the \
         global task or region tables per child.",
    );

    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);"),
        "REGRESSION: the outer task loop no longer performs callback-free \
         cancellation mutation and aggregates opaque observers/Wakers. Dispatch under \
         task/state locks can serialize or reenter a cancel storm.",
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
        .rfind(|&i| i <= window_end)
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
             contains a global nested scan via `{pat}`; inspect \
             the resulting fanout cost.",
        );
    }
}

#[test]
fn request_cancel_with_budget_avoids_global_task_or_region_scans() {
    // Pin the fast flag publication and absence of known
    // global-table scans. This is not an O(1) claim:
    // cancel_waker_snapshot deduplicates W registrations with
    // a linear search per target and may cost O(W^2).
    let source = read("src/record/task.rs");

    let fn_marker = "pub(crate) fn request_cancel_with_budget_and_publication(";
    let start = source
        .find(fn_marker)
        .expect("request_cancel_with_budget_and_publication fn");
    let end = source[start..]
        .find("\n    pub(crate) fn publish_delegated_cancel_lane<T>(")
        .expect("request_cancel_with_budget_and_publication end marker");
    let body = &source[start..start + end];

    assert!(
        body.contains(".store(true, std::sync::atomic::Ordering::Release);")
            && body.contains("guard.cancel_waker_snapshot()"),
        "REGRESSION: request_cancel_with_budget no longer \
         exposes the fast-cancel Release store and explicit \
         Waker snapshot surface audited here.",
    );

    // Forbid known global/dependency-table scans inside the
    // per-task call. This list does not constrain per-task
    // Waker registrations or prove a latency bound.
    let suspect_per_task_iteration = [
        "for _ in self.children",
        "for task in self.dependent_tasks",
        ".iter().for_each(",
    ];
    for pat in &suspect_per_task_iteration {
        assert!(
            !body.contains(pat),
            "REGRESSION: request_cancel_with_budget now iterates \
             a global/dependency surface via `{pat}`; inspect \
             the resulting fanout cost.",
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
        .rfind(|&i| i <= window_end)
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
             This restores a task-count-dependent nested cost.",
        );
    }
}

#[test]
fn cancel_request_returns_effects_for_single_post_lock_routing_pass() {
    // Pin (link 5): cancel_request returns the task list
    // paired with Waker effects so the scheduler can do a single
    // post-lock publication pass, then dispatch callbacks.
    // This does not bound Waker snapshot/dispatch work.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(")
            && source.contains("-> CancellationEffects<Vec<(TaskId, u8)>>")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request signature changed. The \
         effects-wrapped (TaskId, priority) list lets the scheduler do \
         one post-lock injection pass — without it, each cancel \
         injection requires a region re-walk for priority \
         lookup, becoming O(N × R).",
    );
}

#[test]
fn fast_cancel_is_arc_atomic_bool_for_single_release_publish() {
    // Pin (link 6): fast_cancel is Arc<AtomicBool> on CxInner.
    // The flag itself has a single Release publication; this
    // says nothing about the rest of per-task cancellation.
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

#[test]
fn sharded_handle_cancel_proves_retirement_before_runtime_state_lock() {
    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let start = scheduler
        .find("fn drain_handle_cancel_requests(&self)")
        .expect("handle-cancel consumer");
    let end = scheduler[start..]
        .find("\n    /// Publishes cancellation routes")
        .expect("handle-cancel consumer end");
    let body = &scheduler[start..start + end];
    let retirement_proof = body
        .find("let task_still_live =")
        .expect("external shard retirement proof");
    let runtime_state_lock = body
        .find("let state = self")
        .expect("runtime-state validator lock");

    assert!(
        retirement_proof < runtime_state_lock,
        "REGRESSION: the external-shard handle-cancel consumer reacquires the task table while \
         holding RuntimeState, restoring the opposing nested lock order"
    );
    assert!(
        body.contains(".external_handle_cancel_request_violation(")
            && body.contains("diagnostic.push_cancel_protocol_violation(")
            && body.contains("immediate_wakes.push(diagnostic)"),
        "REGRESSION: external-shard handle cancellation no longer returns a closed validator \
         diagnostic for dispatch after runtime-state and task-table locks are released"
    );

    let state = read("src/runtime/state.rs");
    let start = state
        .find("pub(crate) fn external_handle_cancel_request_violation(")
        .expect("external handle-cancel validator");
    let end = state[start..]
        .find("\n    fn validate_and_retire_external_task_protocol(")
        .expect("external handle-cancel validator end");
    let body = &state[start..start + end];
    assert!(
        body.contains(") -> Option<String>") && !body.contains("log_cancel_protocol_violation("),
        "REGRESSION: the external handle-cancel validator invokes a tracing subscriber while \
         RuntimeState is locked instead of returning closed diagnostic data"
    );
}

// ─────────────── ATOMIC VISIBILITY MICROFIXTURES ──────────
//
// These isolate only the fast_cancel Release/Acquire flags.
// They do not execute RuntimeState, TaskRecord, Waker
// snapshotting, validator, scheduler, or lifecycle code and
// therefore are not production performance measurements.

#[test]
fn atomic_visibility_microfixture_sets_all_1000_flags() {
    const N: usize = 1000;

    // Build N tasks.
    let task_flags: Vec<Arc<AtomicBool>> =
        (0..N).map(|_| Arc::new(AtomicBool::new(false))).collect();

    for flag in &task_flags {
        flag.store(true, Ordering::Release);
    }

    // Verify all N tasks observed the cancel.
    for (i, flag) in task_flags.iter().enumerate() {
        assert!(
            flag.load(Ordering::Acquire),
            "task {i} did not observe cancel after \
             cancel-storm sweep",
        );
    }
}

#[test]
fn cancel_storm_observation_visible_cross_thread_via_release_acquire() {
    // Behavioral pin: cancel-storm propagation must be
    // observable from a separate worker thread immediately
    // after the setter thread completes. This mirrors the
    // production cross-worker observation pattern.
    const N: usize = 1000;

    let task_flags: Vec<Arc<AtomicBool>> =
        (0..N).map(|_| Arc::new(AtomicBool::new(false))).collect();

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

    // Writer thread (this thread): isolated flag publication.
    for flag in &task_flags {
        flag.store(true, Ordering::Release);
    }

    barrier.wait(); // Release reader.
    reader.join().expect("reader thread panicked");

    let observed_count = *observed.lock().unwrap();
    assert_eq!(
        observed_count, N,
        "REGRESSION: reader thread observed {observed_count} \
         of {N} cancels — Release/Acquire pair is broken.",
    );
}

#[test]
fn concurrent_atomic_writers_preserve_all_visibility() {
    // This checks independent flag visibility only. It does
    // not model concurrent RuntimeState cancellation or its
    // locking/publication costs.
    const N: usize = 1000;
    const M: usize = 4;

    // M independent groups of N tasks each.
    let groups: Vec<Vec<Arc<AtomicBool>>> = (0..M)
        .map(|_| (0..N).map(|_| Arc::new(AtomicBool::new(false))).collect())
        .collect();

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
