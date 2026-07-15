//! Audit + regression test for cross-thread cancellation
//! propagation in the three-lane scheduler.
//!
//! Operator's question: "when a task is on worker-A and parent
//! region (on worker-B) is cancelled, what ordering and wakeup
//! guarantees carry the cancellation across workers?"
//!
//! Audit findings:
//!
//!   The asupersync cross-worker cancel chain has two explicit
//!   visibility paths: the next cooperative checkpoint observes
//!   the shared atomic flag, while parked work receives a concrete
//!   Parker permit and cancel-lane publication. These are protocol
//!   ordering guarantees, not wall-clock or sub-quantum latency
//!   claims; checkpoint cadence, worker fairness, OS scheduling,
//!   and structural route validity still bound elapsed time.
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
//!      Release-Acquire pair guarantees that the next subsequent
//!      checkpoint load observes the published cancel. It does
//!      not guarantee when user code reaches that checkpoint.
//!
//!   3. **Wake mechanism for parked tasks**: if worker-A's
//!      task is currently PARKED (e.g., sleeping on Sleep,
//!      awaiting on a channel), the cancel propagation also
//!      triggers a wake. This wake path is:
//!      a. `state.cancel_request` returns
//!      `CancellationEffects<Vec<(TaskId, u8)>>` — a
//!      callback-free routing list paired with opaque Wakers.
//!      b. `defer_cancel_dispatch` stores the batch, publishes its
//!      ready flag, then uses the scheduler's concrete
//!      `WorkerCoordinator` to leave a Parker permit. It does not
//!      call an arbitrary notifier or reactor under RuntimeState.
//!      c. The scheduler takes queued effects under its state
//!      guard, releases that guard, publishes every task ID to
//!      the cancel lane, then panic-isolating dispatches all
//!      Wakers. No reentrant auxiliary cancellation-Waker or
//!      deferred cancellation-observer callback sees the task
//!      cancellation before runnable work exists.
//!      d. For !Send local tasks, inject_cancel routes to the
//!      pinned worker via `local.lock().move_to_cancel_lane`
//!      and calls `parker.unpark()` on that worker
//!      (three_lane.rs:1493-1499). Targeted wake to the
//!      specific worker, no broadcast.
//!      e. For global tasks, inject_cancel calls
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
//!      — same path as inject_cancel. This is the cross-thread
//!      mechanism that wakes a parked task without waiting for
//!      another user-level poll to create runnable work.
//!
//!   5. **Strict cancel-lane priority**: once injected, the
//!      cancel-lane work is dispatched FIRST in the worker's
//!      next eligible loop selection (three_lane.rs:3411 — Phase 1 for
//!      Default suggestion: `pop_cancel` before timed/ready).
//!      The `cancel_streak` fairness limit allows occasional
//!      timed/ready interleaving but enforces "if cancel work
//!      pending, dispatch within at most cancel_streak_limit
//!      eligible selections" — typically 32. This is not a
//!      wall-clock bound.
//!
//!   6. **WorkerCoordinator.wake_one is round-robin**: the
//!      `next_wake.fetch_add(1, Relaxed)` cursor distributes
//!      wakes across parkers. This distributes progress permits;
//!      it does not promise that a particular worker runs within
//!      a fixed elapsed-time window.
//!
//! Verdict: **SOUND FOR ORDERING AND WAKEUP**. The next
//! checkpoint observes the Release store, and deferred/parked
//! cancellation publishes a Parker permit plus cancel-lane work.
//! This audit makes no p50/p99, wall-clock, one-iteration, or
//! sub-quantum claim, and it does not cover permanently invalid
//! local-owner routes.
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
//!     loop (would push cancel behind timed/ready and weaken
//!     cancel-lane selection priority),
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
fn pending_checkpoint_ack_republishes_cancel_lane_before_wakers() {
    // A task may acknowledge cancellation inside the poll that returns
    // Pending before the queued handle command reaches a worker. That receipt
    // must itself make the cancel lane visible before auxiliary Wakers run;
    // otherwise a reentrant Waker can observe a parked, unpublished task.
    let task = read("src/record/task.rs");
    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let start = scheduler
        .find("Ok(Poll::Pending) => {")
        .expect("three-lane Pending branch");
    let end = scheduler[start..]
        .find("\n            Err(payload) => {")
        .expect("three-lane Pending branch end");
    let body = &scheduler[start..start + end];

    let receipt = body
        .find("let (cancel_ack, mut cancel_wakes) = cancel_effects.into_parts();")
        .expect("checkpoint receipt split");
    let local_publication = body
        .find("move_local_ready_task_to_cancel_lane(")
        .expect("local cancel publication");
    let global_publication = body
        .find("self.global.inject_cancel(task_id, cancel_priority);")
        .expect("global cancel publication");
    let dispatch = body
        .find("cancel_wakes.dispatch();")
        .expect("post-publication Waker dispatch");

    assert!(
        task.contains("Callers that observe a receipt after `Poll::Pending` must publish a")
            && body.contains("if wake_state.finish_poll() || cancel_ack.is_some()")
            && receipt < local_publication
            && receipt < global_publication
            && local_publication < dispatch
            && global_publication < dispatch,
        "REGRESSION: a same-poll checkpoint acknowledgement no longer republishes the task on \
         its cancel lane before auxiliary Wakers run. A checkpoint-first handle race can strand \
         a Pending task or expose cancellation callbacks before runnable visibility.",
    );
}

#[test]
fn deferred_cancel_enqueue_publishes_queue_flag_then_parker_permit() {
    // RegionRunner::Drop and other outer-lock owners cannot publish the
    // scheduler routes themselves. Pin the owner handoff order: queue the
    // opaque batch, publish the Release flag, then leave a concrete Parker
    // permit. The notifier must be the coordinator's Parker-only path so an
    // arbitrary reactor callback cannot run beneath RuntimeState.
    let state = read("src/runtime/state.rs");
    let marker = "pub(crate) fn defer_cancel_dispatch(";
    let start = state.find(marker).expect("deferred cancel enqueue");
    let end = state[start..]
        .find("\n    /// Installs the concrete parked-worker notifier")
        .expect("deferred cancel enqueue end");
    let body = &state[start..start + end];

    let enqueue = body
        .find("self.pending_cancel_dispatches.push(effects);")
        .expect("queue publication");
    let ready = body
        .find(".store(true, Ordering::Release);")
        .expect("ready-flag publication");
    let permit = body
        .find("coordinator.wake_one_parker();")
        .expect("Parker permit publication");
    assert!(
        enqueue < ready && ready < permit && body.contains(".and_then(std::sync::Weak::upgrade)"),
        "REGRESSION: deferred cancellation no longer queues its opaque batch, publishes the \
         Release-ready flag, and then leaves a concrete Parker permit in that order.",
    );

    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let wake_marker = "pub(crate) fn wake_one_parker(&self) {";
    let wake_start = scheduler
        .find(wake_marker)
        .expect("Parker-only coordinator wake");
    let wake_end = scheduler[wake_start..]
        .find("\n    }\n")
        .expect("Parker-only coordinator wake end");
    let wake_body = &scheduler[wake_start..wake_start + wake_end];
    assert!(
        wake_body.contains("self.parkers[slot].unpark();") && !wake_body.contains("io.wake()"),
        "REGRESSION: deferred cancellation's outer-lock notifier is no longer Parker-only; \
         reactor callbacks must remain outside RuntimeState.",
    );

    let coordinator = scheduler
        .find("let coordinator = Arc::new(WorkerCoordinator::new(")
        .expect("coordinator construction");
    let install = scheduler[coordinator..]
        .find("state.set_pending_cancel_dispatch_coordinator(&coordinator);")
        .map(|offset| coordinator + offset)
        .expect("deferred notifier installation");
    let ready_handle = scheduler[coordinator..]
        .find("state.pending_cancel_dispatch_ready_handle()")
        .map(|offset| coordinator + offset)
        .expect("deferred ready handle");
    assert!(
        install < ready_handle,
        "REGRESSION: ThreeLaneScheduler no longer installs the concrete deferred-cancel \
         coordinator before exposing the ready-flag handle.",
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
    // global.inject_cancel + coordinator.wake_one to publish
    // runnable work and leave a progress permit.
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
    // cancel reaches the queue but loses its documented lane
    // selection priority behind timed/ready.
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
fn cancel_request_effects_publish_all_tasks_before_waker_dispatch() {
    // Pin (link 3-prime): cancel_request couples per-task
    // priorities to opaque Wakers. The scheduler takes effects
    // while holding state, releases that guard, publishes all
    // routing entries, and dispatches Wakers only afterward. A structurally
    // invalid route suppresses that batch fail-closed; this contract does not
    // claim retry, eventual recovery, or a quiescence proof for invalid input.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("pub fn cancel_request(")
            && source.contains("-> CancellationEffects<Vec<(TaskId, u8)>>")
            && source.contains("CancellationEffects::new(tasks_to_cancel, wakes)"),
        "REGRESSION: cancel_request signature changed. The \
         scheduler no longer receives the (TaskId, priority) \
         tuple list coupled to deferred Wakers; cross-thread \
         post-lock publication cannot be enforced.",
    );

    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let start = scheduler
        .find("fn drain_deferred_cancel_dispatches(&self) {")
        .expect("deferred cancel drain");
    let body = &scheduler[start..(start + 1800).min(scheduler.len())];
    let take = body
        .find("state.take_deferred_cancel_dispatches()")
        .expect("take cancellation batches");
    let release = take
        + body[take..]
            .find("\n        };")
            .expect("release RuntimeState guard");
    let publish = body
        .find("self.publish_deferred_cancel_task(task_id, priority)")
        .expect("publish cancellation task");
    let collect_wakes = body
        .find("wakes.push((batch_published, batch_wakes));")
        .expect("collect publication-gated Wakers");
    let dispatch = body
        .find("batch_wakes.dispatch();")
        .expect("dispatch Wakers");
    assert!(
        body.contains("let batches = {")
            && take < publish
            && take < release
            && release < publish
            && publish < collect_wakes
            && collect_wakes < dispatch
            && body.contains("if batch_published {")
            && body.contains("batch_wakes.suppress();")
            && body.matches(".dispatch();").count() == 1,
        "REGRESSION: scheduler no longer releases RuntimeState, publishes \
         every cancel-lane task, and only then dispatches Wakers. A \
         reentrant cross-thread Waker can observe unpublishable work.",
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
