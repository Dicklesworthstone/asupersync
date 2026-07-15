//! Audit + regression test for panic-in-task isolation in
//! the three-lane scheduler.
//!
//! Operator's question: "when a task panics in deadline-monotone
//! lane, does (a) the panic bubble to ParentRegion which
//! catches it (correct: structured), (b) propagate to entire
//! runtime (incorrect: takes down everything), or (c) silently
//! swallow (worst)?"
//!
//! Audit findings:
//!
//!   The asupersync panic-in-task path is **(a) bubble to
//!   parent region as Outcome::Panicked**. The chain is:
//!
//!   1. **catch_unwind boundary at worker.execute()**: the
//!      worker polls the future inside
//!      `std::panic::catch_unwind(std::panic::AssertUnwindSafe
//!      (|| stored.poll(&mut cx)))` (three_lane.rs:4732). This
//!      is the structural panic boundary — every poll is
//!      contained. No matter which lane the task came from
//!      (cancel / timed / ready), the panic is caught at the
//!      same location.
//!
//!   2. **AssertUnwindSafe wraps the closure**: futures are
//!      not `UnwindSafe` by default (the default trait
//!      implementation is opt-in to avoid silent corruption
//!      under panic). asupersync uses `AssertUnwindSafe` to
//!      explicitly assert that the runtime maintains its own
//!      invariants under unwind — every state mutation goes
//!      through the lock-protected RuntimeState methods, not
//!      through interior-mutable fields that could be left
//!      partially-updated.
//!
//!   3. **Panic payload converted to Outcome::Panicked**: in
//!      the Err arm of the catch_unwind match (three_lane.rs:
//!      4920-4958), the worker:
//!      a. Captures the panic payload via
//!      `crate::cx::scope::payload_to_string(&payload)`
//!      (handles `&'static str` and `String` downcasts).
//!      b. Wraps in `crate::types::outcome::PanicPayload::
//!      new(msg)`.
//!      c. Calls `record.complete(Outcome::Panicked(...))` so
//!      the task transitions to a terminal Panicked state.
//!      d. Sets `credit_adaptive_epoch = false` so the
//!      adaptive cancel-streak policy doesn't learn from
//!      panic-induced potential drops.
//!
//!   4. **Waiters woken so parent observes the panic**: the
//!      worker splits `state.task_completed(task_id).into_parts()` to gather
//!      waiters plus an owned completion observer, then calls
//!      `wake_dependents_locked(&state, waiters)`
//!      to schedule them. The parent region's `JoinHandle`
//!      `await` consumes the Panicked outcome via the standard
//!      completion handshake — no special-case unwind path.
//!
//!   5. **Worker thread continues**: the catch_unwind Err arm
//!      does NOT call `panic::resume_unwind`,
//!      `std::process::abort`, or anything that would propagate
//!      the panic to the worker thread. The worker loop returns
//!      to the dispatch phase and picks up the next task. A
//!      panic in one task takes down only that task.
//!
//!   6. **TaskExecutionGuard safety-net**: an additional Drop
//!      guard (three_lane.rs:4485) fires when
//!      `std::thread::panicking()` returns true at drop. This
//!      is the secondary defense against panics that somehow
//!      escape catch_unwind (e.g., a panic in the
//!      catch_unwind machinery itself, or a double-panic from
//!      a destructor running during the catch_unwind dance).
//!      It marks the task as Panicked and wakes dependents
//!      under poison-tolerant lock acquisition.
//!
//!   7. **Factory-panic path uses resume_unwind**: the
//!      scope-construction path (cx/scope.rs:938) DOES call
//!      `std::panic::resume_unwind(payload)` — but ONLY when
//!      the future-factory closure (the `f` in
//!      `scope.spawn(f)`) panicked BEFORE returning a future.
//!      In that case there is no task to mark as Panicked and
//!      no JoinHandle to deliver the outcome through, so
//!      resuming the unwind is the only way the parent sees
//!      the failure. This is a different failure mode than a
//!      panic during normal task polling — it's a region-
//!      construction panic, not a task-execution panic, and
//!      it's still bounded by the parent region's own
//!      catch_unwind/CatchUnwind future.
//!
//! Verdict: **SOUND**. Answer (a) — panic in a task bubbles
//! to the parent region as `Outcome::Panicked`. The runtime
//! is NOT taken down (worker continues, no resume_unwind in
//! the task-execute path) and the panic is NOT silently
//! swallowed (parent observes via JoinHandle outcome).
//!
//! The lane the task came from (cancel / timed / ready) is
//! irrelevant: the catch_unwind boundary is in the SHARED
//! execute() entry point that all three lanes funnel through.
//!
//! A regression that:
//!   - removed the catch_unwind around the poll (panics would
//!     unwind through the worker thread → kill the worker →
//!     potentially kill the runtime),
//!   - changed AssertUnwindSafe to a real UnwindSafe bound
//!     (would refuse to compile most futures and force users
//!     to wrap them — workable but a major API change),
//!   - dropped the `record.complete(Outcome::Panicked(...))`
//!     call in the Err arm (task would never transition to
//!     terminal — region would never reach quiescence),
//!   - dropped the `wake_dependents_locked` call after panic
//!     (parent JoinHandle would never observe the Panicked
//!     outcome — silent swallow → matches the operator's
//!     "worst" answer (c)),
//!   - added `panic::resume_unwind(payload)` in the Err arm
//!     (the panic would propagate up the worker thread —
//!     matches the "takes down everything" answer (b)),
//!   - removed the TaskExecutionGuard Drop impl (escapes
//!     from catch_unwind would leave the task in non-terminal
//!     state and orphan its waiters),
//!   - removed `credit_adaptive_epoch = false` on panic (the
//!     adaptive policy would receive a fabricated good-reward
//!     signal from the abrupt potential drop, biasing toward
//!     longer cancel streaks for the wrong reason),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn panic_err_arm(source: &str) -> &str {
    let start = source.find("Err(payload) => {").expect("Err arm marker");
    let tail = &source[start..];
    let end_marker = "\n            }\n        }\n        drop(guard);";
    let end = tail.find(end_marker).expect("Err arm semantic boundary") + end_marker.len();
    &tail[..end]
}

#[test]
fn worker_execute_wraps_poll_in_catch_unwind_with_assert_unwind_safe() {
    // Pin (link 1+2): the catch_unwind + AssertUnwindSafe pair
    // is the structural panic boundary. Without it, panics
    // would unwind through the worker thread.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {"),
        "REGRESSION: worker execute() no longer wraps the \
         poll in catch_unwind(AssertUnwindSafe(...)). A panic \
         in any task would unwind through the worker thread \
         — taking down the worker, and potentially the entire \
         runtime if the worker is the last live thread. This \
         matches the operator's 'incorrect: takes down \
         everything' answer (b).",
    );

    // Forbid plain catch_unwind without AssertUnwindSafe —
    // most futures aren't UnwindSafe, so this would fail to
    // compile or silently move panic-unsafety into user code.
    let suspect_no_assert = [
        "std::panic::catch_unwind(|| {",
        "panic::catch_unwind(|| stored.poll",
    ];
    for pat in &suspect_no_assert {
        assert!(
            !source.contains(pat),
            "REGRESSION: worker execute() now uses \
             catch_unwind without AssertUnwindSafe (`{pat}`). \
             Most futures don't implement UnwindSafe — this \
             would either fail to compile or push the \
             unwind-safety burden to user code.",
        );
    }
}

#[test]
fn catch_unwind_err_arm_marks_task_outcome_panicked() {
    // Pin (link 3): the Err arm of the catch_unwind match
    // marks the task as Outcome::Panicked. Without this, the
    // task would never reach a terminal state — the region
    // would never quiesce.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("let panic_outcome = crate::types::Outcome::Panicked(panic_payload);")
            && source.contains("record.complete(panic_outcome);"),
        "REGRESSION: panic-in-task Err arm no longer marks \
         the task as Outcome::Panicked. The task stays in \
         non-terminal state — region.quiesce() loops forever \
         waiting for it. Parent JoinHandle never resolves.",
    );
}

#[test]
fn catch_unwind_err_arm_uses_payload_to_string_for_message_extraction() {
    // Pin (link 3): the panic payload is downcast via
    // payload_to_string (handles &'static str and String).
    // Without it, the panic message would be lost — the
    // parent JoinHandle observes Panicked but cannot show
    // WHAT panicked.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("let panic_message = crate::cx::scope::payload_to_string(&payload);"),
        "REGRESSION: panic-in-task Err arm no longer extracts \
         the panic message via payload_to_string. The Panicked \
         outcome carries an empty/default payload — observers \
         lose the reason for the panic.",
    );
}

#[test]
fn catch_unwind_err_arm_wakes_dependents_so_parent_observes_panic() {
    // Pin (link 4): after marking Panicked, the worker calls
    // wake_dependents_locked to schedule the parent's
    // JoinHandle awaiter. Without this, the parent never
    // wakes — silent-swallow regression matching operator
    // answer (c) "worst".
    let source = read("src/runtime/scheduler/three_lane.rs");

    // The Err arm contains the wake_dependents call.
    let body = panic_err_arm(&source);

    assert!(
        body.contains("self.wake_dependents_locked(&state, waiters);"),
        "REGRESSION: panic-in-task Err arm no longer wakes \
         dependents. The parent's JoinHandle awaiter never \
         re-enters the dispatch loop — silent swallow of the \
         panic. Matches operator answer (c) 'worst'.",
    );

    // The waiters set is gathered via task_completed.
    assert!(
        body.contains("let (waiters, completion_observer)")
            && body.contains("state.task_completed(task_id).into_parts();"),
        "REGRESSION: panic-in-task Err arm no longer gathers \
         waiters and the owned completion observer via task_completed. The wake_dependents call \
         has nothing to wake — equivalent silent-swallow.",
    );
}

#[test]
fn catch_unwind_err_arm_does_not_resume_unwind_or_abort() {
    // Pin (link 5): the Err arm must NOT call resume_unwind
    // or abort. Either would propagate the panic to the
    // worker thread — taking down the worker and matching
    // operator answer (b) 'takes down everything'.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let body = panic_err_arm(&source);

    let suspect_propagation = [
        "std::panic::resume_unwind(payload)",
        "std::panic::resume_unwind(",
        "std::process::abort()",
        "std::process::abort(",
        "process::exit",
    ];
    for pat in &suspect_propagation {
        assert!(
            !body.contains(pat),
            "REGRESSION: panic-in-task Err arm now calls \
             `{pat}` — propagating the panic to the worker \
             thread. This kills the worker and potentially \
             the entire runtime — matches operator answer (b) \
             'takes down everything'. The panic must be \
             contained at the task boundary.",
        );
    }
}

#[test]
fn catch_unwind_err_arm_disables_adaptive_epoch_credit_on_panic() {
    // Pin (link 3): credit_adaptive_epoch is set to false
    // on panic so the cancel-streak adaptive policy doesn't
    // mistake the abrupt potential drop for a "good" reward.
    // This is a subtle correctness pin — without it, the
    // policy biases toward wider cancel streaks for the
    // wrong reason.
    let source = read("src/runtime/scheduler/three_lane.rs");

    let err_marker = "Err(payload) => {";
    let pos = source.find(err_marker).expect("Err arm marker");
    let window_end = (pos + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    assert!(
        body.contains("credit_adaptive_epoch = false;"),
        "REGRESSION: panic-in-task Err arm no longer sets \
         credit_adaptive_epoch = false. The adaptive policy \
         observes a fabricated 'good' reward from the abrupt \
         potential drop — biasing toward wider cancel streaks. \
         Subtle correctness regression for adaptive learning.",
    );
}

#[test]
fn task_execution_guard_fires_on_panic_unwind_as_safety_net() {
    // Pin (link 6): TaskExecutionGuard's Drop fires when
    // std::thread::panicking() — the safety net for any
    // panic that somehow escapes catch_unwind (e.g.,
    // double-panic from a destructor). Without it, an
    // escaping panic leaves the task in non-terminal state
    // and orphans its waiters.
    let source = read("src/runtime/scheduler/three_lane.rs");

    assert!(
        source.contains("struct TaskExecutionGuard<'a> {")
            && source.contains("if !self.completed && std::thread::panicking() {"),
        "REGRESSION: TaskExecutionGuard safety net is gone. \
         A panic that escapes catch_unwind (e.g., from a \
         destructor running during unwind) would leave the \
         task in non-terminal state — orphaning its waiters \
         and stranding the region in non-quiescent state.",
    );

    // The guard must still mark the task as Panicked under
    // the safety-net path.
    assert!(
        source.contains("record.complete(crate::types::Outcome::Panicked("),
        "REGRESSION: TaskExecutionGuard safety-net no longer \
         marks the task as Outcome::Panicked. Even if the \
         guard fires, the task wouldn't transition to a \
         terminal state.",
    );
}

#[test]
fn task_execution_guard_uses_poison_tolerant_lock_during_unwind() {
    // Pin (link 6): the safety-net guard accepts a poisoned
    // RuntimeState lock via PoisonError::into_inner. A panic
    // earlier in the chain may have poisoned the lock; if
    // the guard refused to recover, the runtime would lose
    // its ability to process any subsequent tasks.
    let source = read("src/runtime/scheduler/three_lane.rs");

    // The TaskExecutionGuard Drop impl must use into_inner
    // for poison-tolerant lock recovery.
    let guard_marker = "impl Drop for TaskExecutionGuard<'_> {";
    let start = source.find(guard_marker).expect("TaskExecutionGuard Drop");
    let next_impl = source[start + guard_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + guard_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains(".unwrap_or_else(std::sync::PoisonError::into_inner)"),
        "REGRESSION: TaskExecutionGuard Drop no longer uses \
         poison-tolerant lock recovery. A poisoned RuntimeState \
         lock would propagate the unwind further — eventually \
         taking down the worker thread.",
    );
}

#[test]
fn factory_panic_path_resumes_unwind_only_after_region_cleanup() {
    // Pin (link 7): the factory-construction panic path in
    // cx/scope.rs (the `f` closure that BUILDS the future)
    // is the ONLY legitimate resume_unwind in the panic
    // chain. It runs AFTER cancel_request mutation/capture,
    // region.begin_close + advance_region_state cleanup, and
    // explicit suppression of captured cancellation observers/Wakers, so the
    // parent's region tree isn't left in a broken state. This does not claim
    // unrelated close/finalizer callbacks are absent. Verify the cleanup
    // happens before resume_unwind.
    let source = read("src/cx/scope.rs");

    let resume_idx = source
        .find("std::panic::resume_unwind(payload);")
        .expect("factory-panic resume_unwind");

    // Look at the ~3000 bytes BEFORE resume_unwind for the
    // cleanup sequence (~60 lines back covers the full
    // pre-resume cleanup chain at scope.rs:905-938).
    let cleanup_start = resume_idx.saturating_sub(3000);
    let safe_start = source
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= cleanup_start)
        .unwrap_or(cleanup_start);
    let preamble = &source[safe_start..resume_idx];

    assert!(
        preamble
            .contains("let cancel_effects = state.cancel_request(child_region, &reason, None);")
            && preamble.contains("let (_, cancel_wakes) = cancel_effects.into_parts();")
            && preamble.contains("cancel_wakes.suppress();"),
        "REGRESSION: factory-panic path no longer cancels the \
         child region and explicitly suppresses its callback \
         effects before resume_unwind. The region's tasks \
         are orphaned and the parent's region tree is left in \
         non-quiescent state during the unwind.",
    );

    assert!(
        preamble.contains("region.begin_close(None);"),
        "REGRESSION: factory-panic path no longer transitions \
         the child region to Closing before resume_unwind. \
         The region remains Open during unwind — invariant \
         violation.",
    );

    assert!(
        preamble.contains("state.advance_region_state(child_region);"),
        "REGRESSION: factory-panic path no longer drives \
         region state advancement before resume_unwind. The \
         region's lifecycle is stranded mid-transition.",
    );
}

#[test]
fn panic_isolation_module_isolates_task_panics_by_default() {
    // Pin (configuration audit): the PanicIsolationConfig
    // default has isolate_task_panics = true. A regression
    // that defaulted to false would let panics escape the
    // catch_unwind boundary if isolation were checked
    // before catch_unwind.
    let source = read("src/runtime/panic_isolation.rs");

    assert!(
        source.contains("isolate_task_panics: true,"),
        "REGRESSION: PanicIsolationConfig default no longer \
         isolates task panics. Even if catch_unwind is in \
         place, configuration-gated isolation would leave \
         panics propagating through if the gate is closed.",
    );

    assert!(
        source.contains("isolate_finalizer_panics: true,"),
        "REGRESSION: PanicIsolationConfig default no longer \
         isolates finalizer panics. Region-cleanup panics \
         would propagate — taking down the cleanup path \
         and stranding the region.",
    );
}

#[test]
fn panic_payload_carries_message_through_outcome_panicked() {
    // Pin (audit): PanicPayload::new(msg) is what carries the
    // panic message into the Panicked outcome. Without this
    // field, the panic message would be lost — observers see
    // only "Panicked" with no context.
    let source = read("src/types/outcome.rs");

    assert!(
        source.contains("pub fn new(") && source.contains("PanicPayload"),
        "REGRESSION: PanicPayload::new constructor is gone. \
         The panic message can't be threaded into the Panicked \
         outcome — observers lose the panic reason.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    // Pin (documentary): related audits.
    let prior_audits = [
        "tests/runtime_region_close_timed_lane_task_cancellation_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
        "tests/scheduler_three_lane_edf_vs_fifo_deadline_pressure_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
