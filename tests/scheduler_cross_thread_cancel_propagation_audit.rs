//! Audit + regression test for cross-thread cancellation
//! propagation in the three-lane scheduler.
//!
//! Operator's question: "when a task is on worker-A and parent
//! region (on worker-B) is cancelled, does the cancellation
//! reach worker-A's task within bounded time (< 1 quantum)?"
//!
//! Audit findings:
//!
//!   The asupersync cross-worker cancel chain is **bounded by
//!   one checkpoint observation OR one dispatch loop iteration
//!   on worker-A**, regardless of where the cancel originates.
//!   Both bounds are well under "one quantum":
//!
//!   1. **Shared state via Arc<AtomicBool>**: each task's
//!      `CxInner.fast_cancel` is `Arc<AtomicBool>` shared
//!      between every thread that holds the CxInner. When
//!      worker-B's call to `region.close()` invokes
//!      `state.cancel_request → task.request_cancel_with_budget`
//!      (state.rs:2682, task.rs:523), the
//!      `fast_cancel.store(true, Release)` is immediately
//!      published.
//!
//!   2. **Acquire-Release pair guarantees visibility on next
//!      load**: worker-A's `cx.checkpoint()` reads
//!      `guard.fast_cancel.load(Acquire)` (cx/cx.rs). The
//!      Release-Acquire pair guarantees that any subsequent
//!      checkpoint observes the cancel — not "eventually" but
//!      "next checkpoint". For an actively-polling task on
//!      worker-A, that's at most one cooperative-yield window.
//!
//!   3. **Wake mechanism for parked tasks**: if worker-A's
//!      task is currently PARKED (e.g., sleeping on Sleep,
//!      awaiting on a channel), the cancel propagation also
//!      triggers a wake. This wake path is:
//!      a. `state.cancel_request` returns `Vec<(TaskId, u8)>`
//!      — tasks needing cancel-lane promotion.
//!      b. The caller invokes `scheduler.inject_cancel(task,
//!      priority)` per task (three_lane.rs:1474).
//!      c. For !Send local tasks, inject_cancel routes to the
//!      pinned worker via `local.lock().move_to_cancel_lane`
//!      and calls `parker.unpark()` on that worker
//!      (three_lane.rs:1493-1499). Bounded wake to the
//!      specific worker, no broadcast.
//!      d. For global tasks, inject_cancel calls
//!      `global.inject_cancel(task, priority)` and
//!      `coordinator.wake_one()` (three_lane.rs:1527-1528).
//!      wake_one picks an idle parker via round-robin
//!      atomic fetch_add and unparks it.
//!
//!   4. **CancelLaneWaker**: tasks that registered a cancel
//!      waker via Cx::cancel_waker() get woken via
//!      `CancelLaneWaker::schedule` (three_lane.rs:5157),
//!      which:
//!      a. Reads cx_inner.cancel_requested + priority.
//!      b. If !cancel_requested, returns (spurious-wake guard).
//!      c. Calls `wake_state.notify()` for dedup.
//!      d. Calls `global.inject_cancel + coordinator.wake_one`
//!      — same path as inject_cancel.
//!      This is the cross-thread mechanism that wakes a parked
//!      task without requiring polling on worker-A.
//!
//!   5. **Strict cancel-lane priority**: once injected, the
//!      cancel-lane work is dispatched FIRST in the worker's
//!      next loop iteration (three_lane.rs:3411 — Phase 1 for
//!      Default suggestion: `pop_cancel` before timed/ready).
//!      The `cancel_streak` fairness limit allows occasional
//!      timed/ready interleaving but enforces "if cancel work
//!      pending, dispatch within at most cancel_streak_limit
//!      iterations" — typically 32.
//!
//!   6. **WorkerCoordinator.wake_one is round-robin**: the
//!      `next_wake.fetch_add(1, Relaxed)` cursor distributes
//!      wakes across parkers. A pathological case where
//!      worker-A is repeatedly skipped is bounded by the
//!      io_driver.wake() side-effect (which all parked workers
//!      observe).
//!
//! Verdict: **SOUND**. Cross-thread cancel propagation reaches
//! worker-A's task within:
//!   - One checkpoint call (Acquire load observes the Release
//!     store) for actively-polling tasks.
//!   - One coordinator.wake_one() + one dispatch loop iteration
//!     for parked tasks.
//!   - One parker.unpark() + one dispatch loop iteration for
//!     pinned local tasks (no coordinator round-robin).
//!
//! All three bounds are sub-quantum.
//!
//! A regression that:
//!   - changed `fast_cancel` from `Arc<AtomicBool>` to a
//!     non-shared field (would require an explicit per-thread
//!     poll for visibility — unbounded latency),
//!   - dropped the `coordinator.wake_one()` call after
//!     inject_cancel (a parked worker would never wake until
//!     its next park-timeout),
//!   - dropped the `parker.unpark()` call after
//!     move_to_cancel_lane for local tasks (pinned-worker case
//!     becomes silently stuck),
//!   - changed the Release/Acquire ordering pair to Relaxed
//!     (cross-thread visibility no longer guaranteed),
//!   - removed the cancel-lane priority from the dispatch
//!     loop (would push cancel behind timed/ready and break
//!     bounded-latency guarantee),
//!   - changed CancelLaneWaker.schedule to no-op when
//!     cancel_requested is false but ALSO no-op when
//!     cancel_requested is true (would silently drop the
//!     cross-thread wake),
//!
//! would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_inner_fast_cancel_field_is_arc_atomic_bool_for_cross_thread_sharing() {
    // Pin (link 1): fast_cancel is Arc<AtomicBool>, shared
    // between worker-B (writer via request_cancel_with_budget)
    // and worker-A (reader via cx.checkpoint). The Arc is the
    // sharing mechanism; AtomicBool is the synchronization
    // primitive. The CxInner struct lives in
    // src/types/task_context.rs (re-exported via cx).
    let source = read("src/types/task_context.rs");

    let suspect_non_shared = [
        "pub fast_cancel: bool,",
        "pub fast_cancel: AtomicBool,",
        "pub fast_cancel: std::sync::atomic::AtomicBool,",
        "pub fast_cancel: Cell<bool>,",
    ];
    for pat in &suspect_non_shared {
        assert!(
            !source.contains(pat),
            "REGRESSION: CxInner.fast_cancel is no longer \
             Arc<AtomicBool> (now `{pat}`). Without Arc \
             sharing, cross-thread cancel propagation requires \
             a per-thread poll — unbounded latency. Restore \
             the Arc<AtomicBool> shared-state pattern.",
        );
    }

    // Must contain the Arc<AtomicBool> form (the actual
    // declaration uses fully-qualified std paths).
    assert!(
        source.contains("pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,"),
        "REGRESSION: CxInner.fast_cancel is no longer declared \
         as `pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>`. \
         Cross-thread propagation requires shared-state \
         synchronization via Arc<AtomicBool>.",
    );
}

#[test]
fn request_cancel_with_budget_publishes_fast_cancel_with_release() {
    // Pin (link 1): the writer side of the Release-Acquire
    // pair lives in task.rs request_cancel_with_budget. A
    // regression to Relaxed would break cross-thread
    // visibility — the worker-A reader could load stale
    // values indefinitely.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(
            "fast_cancel\n                .store(true, std::sync::atomic::Ordering::Release);"
        ) || source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: task.rs request_cancel_with_budget no \
         longer publishes fast_cancel with Release ordering. \
         Without it, a task on worker-A may never observe a \
         cancel set by worker-B.",
    );

    // Forbid Relaxed publication.
    let suspect_relaxed = [
        "fast_cancel.store(true, std::sync::atomic::Ordering::Relaxed)",
        "fast_cancel.store(true, Ordering::Relaxed)",
    ];
    for pat in &suspect_relaxed {
        assert!(
            !source.contains(pat),
            "REGRESSION: task.rs publishes fast_cancel with \
             Relaxed ordering (`{pat}`). Cross-thread \
             visibility is not guaranteed under Relaxed — use \
             Release.",
        );
    }
}

#[test]
fn cx_checkpoint_observes_fast_cancel_with_acquire_load() {
    // Pin (link 2): the reader side of the Release-Acquire
    // pair lives in cx.checkpoint. A regression to Relaxed
    // would let a task on worker-A miss a cancel set by
    // worker-B.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: cx.checkpoint() no longer reads fast_cancel \
         with Acquire ordering. Without it, the Release-Acquire \
         pair is broken — cross-thread cancel propagation has \
         unbounded latency.",
    );
}

#[test]
fn inject_cancel_unparks_pinned_local_worker() {
    // Pin (link 3): inject_cancel for !Send local tasks calls
    // parker.unpark() on the pinned worker so that worker can
    // dispatch the cancel-lane entry from its parked state.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn inject_cancel(&self, task: TaskId, priority: u8) {";
    let start = source.find(fn_marker).expect("inject_cancel fn");
    // Take a generous window for the inject_cancel body.
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .rfind(|&(i, _)| i <= window_end)
        .map_or(window_end, |(i, _)| i);
    let body = &source[start..safe_end];

    assert!(
        body.contains("parker.unpark();"),
        "REGRESSION: inject_cancel for local pinned tasks no \
         longer calls parker.unpark(). A parked pinned worker \
         would never wake to dispatch the cancel — \
         cross-thread cancel propagation silently stuck.\n\n\
         body:\n{body}",
    );
}

#[test]
fn inject_cancel_wakes_coordinator_for_global_tasks() {
    // Pin (link 3): inject_cancel for global tasks calls
    // global.inject_cancel + self.wake_one. wake_one delegates
    // to coordinator.wake_one() (three_lane.rs:1787) which
    // unparks one worker via round-robin.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn inject_cancel(&self, task: TaskId, priority: u8) {";
    let start = source.find(fn_marker).expect("inject_cancel fn");
    let after = &source[start..];
    // Find global injection inside the body.
    assert!(
        after.contains("self.global.inject_cancel(task, priority);"),
        "REGRESSION: inject_cancel no longer routes global \
         tasks through global.inject_cancel. Worker-A would \
         never see the cancel-lane entry.",
    );
    assert!(
        after.contains("self.wake_one();"),
        "REGRESSION: inject_cancel no longer calls wake_one() \
         after global injection. A parked worker would never \
         wake to dispatch the cancel — propagation silently \
         stuck.",
    );
}

#[test]
fn cancel_lane_waker_schedule_calls_inject_cancel_and_wake_one() {
    // Pin (link 4): CancelLaneWaker.schedule (the cross-
    // thread waker used for parked tasks) calls
    // global.inject_cancel + coordinator.wake_one to ensure a
    // worker dispatches the cancel within bounded time.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "impl CancelLaneWaker {";
    let start = source.find(fn_marker).expect("CancelLaneWaker impl");
    let next_impl = source[start + fn_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + fn_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("self.global.inject_cancel(self.task_id, priority);"),
        "REGRESSION: CancelLaneWaker.schedule no longer routes \
         through global.inject_cancel. A parked task waiting \
         on its cancel waker would never re-enter the dispatch \
         loop on the cancel lane.",
    );

    assert!(
        body.contains("self.coordinator.wake_one();"),
        "REGRESSION: CancelLaneWaker.schedule no longer wakes \
         the coordinator. The cross-thread cancel signal is \
         injected but no parked worker is unparked to dispatch \
         it — silently stuck propagation.",
    );
}

#[test]
fn cancel_lane_waker_guards_against_spurious_wakes() {
    // Pin (link 4 audit): CancelLaneWaker.schedule reads
    // cancel_requested under the cx_inner read lock and
    // returns early if false. Without this guard, a spurious
    // waker wake (from the executor's wake-after-poll dance)
    // would falsely promote the task to the cancel lane.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "impl CancelLaneWaker {";
    let start = source.find(fn_marker).expect("CancelLaneWaker impl");
    let next_impl = source[start + fn_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + fn_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("if !cancel_requested {") && body.contains("return;"),
        "REGRESSION: CancelLaneWaker.schedule no longer \
         short-circuits when cancel_requested is false. A \
         spurious wake would promote a non-cancelled task to \
         the cancel lane — wasting cancel-priority resources \
         and breaking strict-priority semantics.",
    );
}

#[test]
fn worker_coordinator_wake_one_unparks_via_round_robin_cursor() {
    // Pin (link 6): WorkerCoordinator.wake_one uses a
    // round-robin cursor (next_wake.fetch_add) to distribute
    // wakes across parkers. Without round-robin, the same
    // worker would be repeatedly woken — a pathological case
    // where worker-A is never selected.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub(crate) fn wake_one(&self) {";
    let start = source.find(fn_marker).expect("wake_one fn");
    let body_end = source[start..].find("\n    }\n").expect("wake_one close");
    let body = &source[start..start + body_end];

    assert!(
        (body.contains("self.next_wake.fetch_add(1, Ordering::Relaxed)")
            || body.contains("self.next_wake.fetch_add(1, Ordering::AcqRel)"))
            && body.contains("self.parkers[slot].unpark();"),
        "REGRESSION: WorkerCoordinator.wake_one no longer uses \
         round-robin via next_wake.fetch_add. Cross-thread \
         cancel propagation depends on round-robin so worker-A \
         is eventually selected — without it, a single worker \
         can monopolize wakes.",
    );
}

#[test]
fn cancel_lane_dispatched_first_in_default_suggestion() {
    // Pin (link 5): the dispatch loop pops cancel-lane work
    // before timed/ready in the Default (non-MeetDeadlines)
    // suggestion path. Without this priority, cross-thread
    // cancel reaches the queue but waits behind timed/ready —
    // breaking the bounded-latency guarantee.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // Phase 1 default branch: cancel before timed.
    assert!(
        source.contains("// Default / drain: cancel > timed.")
            && source.contains("if let Some(pt) = self.global.pop_cancel() {"),
        "REGRESSION: dispatch loop no longer prioritizes \
         cancel over timed in the default suggestion path. \
         Cross-thread cancel propagation reaches the queue but \
         is starved by timed/ready work.",
    );
}

#[test]
fn three_lane_local_waker_routes_cancelled_local_task_to_cancel_lane() {
    // Pin (link 3-prime): ThreeLaneLocalWaker.schedule reads
    // fast_cancel with Acquire and, if cancelling, promotes
    // the local task to the cancel lane via
    // move_to_cancel_lane + parker.unpark. This is what
    // unifies the wake-from-park path with the cross-thread
    // cancel: a local task that was sleeping on a channel/
    // sleep gets re-routed to cancel lane on wake instead of
    // ready lane.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "impl ThreeLaneLocalWaker {";
    let start = source.find(fn_marker).expect("ThreeLaneLocalWaker impl");
    let next_impl = source[start + fn_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + fn_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("self.fast_cancel.load(Ordering::Acquire)"),
        "REGRESSION: ThreeLaneLocalWaker.schedule no longer \
         reads fast_cancel with Acquire. A local task being \
         woken (e.g. from Sleep) would not re-route to the \
         cancel lane on a concurrently-arrived cancel — \
         breaking propagation for parked local tasks.",
    );

    assert!(
        (body.contains("move_local_ready_task_to_cancel_lane(")
            || body.contains("local.move_to_cancel_lane(self.task_id, priority);"))
            && body.contains("self.parker.unpark();"),
        "REGRESSION: ThreeLaneLocalWaker.schedule no longer \
         promotes cancelled local tasks to the cancel lane + \
         unparks the worker. A locally-pinned task waking up \
         under cancel would land on the ready lane instead of \
         cancel lane — wrong-priority dispatch.",
    );
}

#[test]
fn cancel_request_returns_per_task_priorities_for_lane_routing() {
    // Pin (link 3-prime): cancel_request returns
    // Vec<(TaskId, u8)> so the scheduler can call inject_cancel
    // for each entry. Without this, the per-task lane routing
    // chain breaks at the boundary between state and scheduler.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(") && source.contains("-> Vec<(TaskId, u8)>"),
        "REGRESSION: cancel_request signature changed. The \
         scheduler depends on the (TaskId, priority) tuple list \
         to drive per-task inject_cancel — without this list, \
         lane routing for cross-thread cancel is dropped.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): related cross-thread / cancel chain
    // audits.
    let prior_audits = [
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/scheduler_cooperative_budget_yield_audit.rs",
        "tests/scheduler_region_drop_propagates_cancel_to_timed_lane_audit.rs",
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing. \
             This audit relies on the chain audits for deeper \
             coverage; if they're gone, restore them or update \
             this audit to include the deeper checks.",
        );
    }
}
