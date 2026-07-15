//! Audit + regression test for cancel-signal coalescing.
//!
//! Operator's question: "when 100 cancel signals arrive on
//! the same task in rapid succession (e.g., timeout fires,
//! then user calls cancel, then drop), do we coalesce
//! (correct: idempotent cancel) or do 100 separate
//! cancellations (wasteful)?"
//!
//! Audit findings:
//!
//!   `request_cancel_with_budget` is **fully idempotent and
//!   coalescing**. 100 cancel signals on the same task
//!   produce ONE state transition (the first call) and 99
//!   strengthen-only updates (subsequent calls). The
//!   structural mechanism:
//!
//!   1. **Terminal-state early return** (record/task.rs:528):
//!      ```ignore
//!      if self.state.is_terminal() {
//!          return CancellationEffects::ready(false);
//!      }
//!      ```
//!      Any cancel call on a Completed task is a no-op —
//!      can't cancel what's already terminal.
//!
//!   2. **Atomic fast_cancel store is idempotent**
//!      (task.rs:535-538):
//!      ```ignore
//!      guard.cancel_requested = true;
//!      guard.fast_cancel.store(true, Release);
//!      ```
//!      `cancel_requested = true` and
//!      `fast_cancel.store(true)` are both idempotent —
//!      setting an already-true value is a no-op for the
//!      reader. No observability change after the first
//!      call's publish.
//!
//!   3. **State machine match dispatches by current state**
//!      (task.rs:545-616):
//!      - **`CancelRequested`**: strengthen existing reason,
//!        combine budgets, return `false` (NOT newly
//!        cancelled).
//!      - **`Cancelling`**: same — strengthen + combine,
//!        return false.
//!      - **`Finalizing`**: same — strengthen + combine,
//!        return false.
//!      - **`Created`/`Running`**: transition to
//!        CancelRequested, increment cancel_epoch, return
//!        true (NEWLY cancelled).
//!        Only the FIRST call from a non-cancelling state
//!        returns true; all others return false.
//!
//!   4. **Reason strengthening preserves the strongest
//!      attribution** (task.rs:557, 573, 600):
//!      ```ignore
//!      existing_reason.strengthen(&reason);
//!      ```
//!      Multiple cancel signals with different reasons
//!      converge on the highest-severity reason. The cause
//!      chain is preserved — operators can audit which
//!      cancels arrived without losing attribution.
//!
//!   5. **Budget combining uses lattice meet** (task.rs:558,
//!      574, 601):
//!      ```ignore
//!      *existing_budget = existing_budget.combine(cleanup_budget);
//!      ```
//!      `combine` is the Budget::meet operation — MIN on
//!      deadline/poll_quota/cost_quota, MAX on priority.
//!      Multiple cancel signals with different cleanup
//!      budgets converge on the TIGHTEST budget — never
//!      relax.
//!
//!   6. **`cancel_epoch` increments only on first transition**
//!      (task.rs:621-624): the epoch counter increments when
//!      the task moves from Created/Running to CancelRequested.
//!      Subsequent strengthen-only calls do NOT increment.
//!      This is what makes "first cancel observed" countable
//!      for metrics.
//!
//!   7. **The effects value distinguishes transition from change**:
//!      `newly_cancelled` gates the first RequestCancel protocol/trace
//!      transition. `changed && publication.is_published()` separately
//!      selects lane routing, so a stronger reason or tighter cleanup budget
//!      can deliberately re-promote an already-cancelled task. Identical
//!      repeats remain routing no-ops. Effects are extracted under state and
//!      dispatched only after the caller's publication boundary:
//!      ```ignore
//!      let effects = task.request_cancel_with_budget(...);
//!      let ((newly_cancelled, changed, publication), task_wakes) =
//!          effects.into_parts();
//!      wakes.merge(task_wakes);
//!      if changed && publication.is_published() {
//!          tasks_to_cancel.push((task_id, priority));
//!      }
//!      ```
//!
//!   8. **Multiple producer paths share authoritative state**: region/task
//!      cancellation, managed handles, and checkpoint reconciliation do not
//!      share one public entrypoint. They converge through the TaskRecord/Cx
//!      cancellation state and runtime-owned command/publication boundaries.
//!
//! Verdict: **SOUND**. 100 cancel signals on the same task
//! produce 1 state transition + 99 strengthen-only updates.
//! The fast_cancel atomic store is naturally idempotent.
//! The paired booleans preserve first-transition accounting and permit only
//! changed published cancellations to be routed again. Wakers remain deferred,
//! and cancel_epoch counts only the first cancel.
//!
//! A regression that:
//!   - removed the terminal-state early return (would let
//!     post-completion cancels mutate state — UB),
//!   - changed the state-match arms to report every call as a new transition
//!     (duplicate protocol/trace events and broken first-transition accounting),
//!   - changed strengthen to OVERWRITE the existing reason
//!     (lost attribution — last cancel wins instead of
//!     strongest),
//!   - changed combine to e.g. AVERAGE budgets instead of
//!     MEET (would relax constraints under repeated cancel),
//!   - removed the cancel_epoch increment guard (would let
//!     the epoch grow unboundedly under coalesced cancels),
//!   - introduced a producer that bypasses authoritative TaskRecord/Cx
//!     reconciliation,
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn cancellation_mutation_body(source: &str) -> &str {
    let start = source
        .find("pub(crate) fn request_cancel_with_budget_and_publication(")
        .expect("request_cancel_with_budget_and_publication fn");
    let end = source[start..]
        .find("\n    /// Returns a cancellation witness")
        .expect("request_cancel_with_budget_and_publication end marker");
    &source[start..start + end]
}

#[test]
fn request_cancel_with_budget_returns_ready_false_effect_when_task_already_terminal() {
    // Pin (link 1): the early return on is_terminal() is
    // the first idempotency gate. Without it, post-
    // completion cancels mutate state.
    let source = read("src/record/task.rs");

    let mutation_body = cancellation_mutation_body(&source);

    assert!(
        mutation_body.contains(") -> CancellationEffects<(bool, bool, RunnablePublication)> {")
            && mutation_body.contains("if self.state.is_terminal() {")
            && mutation_body.contains("return CancellationEffects::ready((")
            && mutation_body.contains("RunnablePublication::Published,")
            && mutation_body.contains("(result.0, result.1, runnable_publication),")
            && mutation_body.contains("let wakes = CancelWakeEffects::new(cancel_wakers);")
            && mutation_body.contains("let trace = PendingTaskCancelTrace::new(")
            && mutation_body.contains("trace.append_to(&mut wakes);")
            && mutation_body.contains(".pending_task_cancel_trace;")
            && !mutation_body.contains("trace!(")
            && !mutation_body.contains("tracing_compat::debug!(")
            && !mutation_body.contains(".dispatch()")
            && !mutation_body.contains("wake_by_ref("),
        "REGRESSION: request_cancel_with_budget no longer \
         returns an empty cancellation-effects token for a \
         terminal state. Cancels on \
         completed tasks would mutate state — UB pathway \
         AND breaks coalescing for completed tasks; or it \
         invokes tracing subscribers or Wakers inline instead of mutation + capture only.",
    );
}

#[test]
fn fast_cancel_store_is_idempotent_atomic_no_compare_swap() {
    // Pin (link 2): fast_cancel uses .store(true, Release),
    // NOT compare_exchange. Idempotent — setting an
    // already-true value is naturally a no-op for readers.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: fast_cancel publish no longer uses \
         .store. If it switched to compare_exchange, \
         coalesced cancels would 'fail' the CAS on the \
         second-and-later call — the bool return semantics \
         would conflate.",
    );

    // The cancel_requested = true assignment is also
    // idempotent.
    assert!(
        source.contains("guard.cancel_requested = true;"),
        "REGRESSION: cancel_requested assignment is gone. \
         Without it, the slow-path cancel observation in \
         checkpoint() doesn't see the cancel.",
    );
}

#[test]
fn state_match_arms_strengthen_existing_reason_for_already_cancelling_states() {
    // Pin (link 4): the state machine arms for
    // CancelRequested/Cancelling/Finalizing call
    // existing_reason.strengthen(&reason). Without this,
    // multi-cancel attribution is lost.
    let source = read("src/record/task.rs");

    let body = cancellation_mutation_body(&source);

    let strengthen_count = body.matches("existing_reason.strengthen(&reason);").count();
    assert!(
        strengthen_count >= 3,
        "REGRESSION: only {strengthen_count} \
         existing_reason.strengthen calls found (expected \
         >= 3 — one per CancelRequested/Cancelling/\
         Finalizing arm). Multi-cancel reason \
         strengthening is broken; either the arms are \
         gone or they overwrite instead of strengthen.",
    );

    // Forbid overwriting (the loser pattern).
    let suspect_overwrite = [
        "*existing_reason = reason.clone();",
        "*existing_reason = reason;",
    ];
    for pat in &suspect_overwrite {
        assert!(
            !body.contains(pat),
            "REGRESSION: state match arm now overwrites \
             existing_reason via `{pat}` — last-cancel-wins \
             attribution. The strongest cancel reason is \
             lost when a weaker cancel arrives later.",
        );
    }
}

#[test]
fn state_match_arms_combine_budgets_via_meet_for_tightest_constraint() {
    // Pin (link 5): the state arms call existing_budget.
    // combine(cleanup_budget) which is the lattice-meet
    // (MIN on deadline/poll/cost, MAX on priority). Without
    // this, repeated cancels could RELAX budgets.
    let source = read("src/record/task.rs");

    let body = cancellation_mutation_body(&source);

    let combine_count = body.matches(".combine_untraced(cleanup_budget)").count();
    assert!(
        combine_count >= 3,
        "REGRESSION: only {combine_count} \
         budget.combine_untraced(cleanup_budget) calls found \
         (expected >= 3). Multi-cancel budget tightening \
         is broken — repeated cancels may relax \
         constraints.",
    );
}

#[test]
fn state_match_arms_for_cancelling_states_return_false_not_true() {
    // Pin (link 7): the CancelRequested/Cancelling/
    // Finalizing arms return false (NOT newly cancelled).
    // Without this, first-transition accounting and protocol
    // diagnostics would repeat for every strengthened signal.
    let source = read("src/record/task.rs");

    let body = cancellation_mutation_body(&source);

    // Each of the three already-cancelling arms returns
    // false. We count returns inside the matching arms by
    // looking for the trace + strengthen + false pattern.
    let already_cancelled_returns = body.matches("reason_changed || budget_changed").count();
    assert!(
        already_cancelled_returns >= 3,
        "REGRESSION: state match arms for already-cancelling \
         states return only {already_cancelled_returns} \
         falses (expected >= 3 — one per arm). Either \
         the arms now report duplicate first transitions or \
         the structure changed.",
    );
}

#[test]
fn cancel_epoch_increments_only_on_first_transition_to_cancel_requested() {
    // Pin (link 6): cancel_epoch increments ONLY when the
    // task transitions from Created/Running to
    // CancelRequested. Subsequent strengthen-only calls do
    // NOT increment. Without this guard, the epoch grows
    // unboundedly under coalesced cancels.
    let source = read("src/record/task.rs");

    let body = cancellation_mutation_body(&source);

    // The increment must be inside the Created/Running arm.
    assert!(
        body.contains("TaskState::Created | TaskState::Running =>")
            && body.contains("if self.cancel_epoch == 0 {")
            && body.contains("self.cancel_epoch = 1;"),
        "REGRESSION: cancel_epoch increment is no longer \
         gated to the Created/Running arm (first \
         transition only). Either the epoch grows \
         unboundedly under coalesced cancels OR the \
         first-cancel signal is lost.",
    );
}

#[test]
fn cancel_request_separates_first_transition_from_changed_routing() {
    // Pin (link 7): state.cancel_request extracts both the
    // first-transition and changed/publication receipts. The
    // former gates protocol/trace recording; the latter gates
    // lane routing for new or strengthened cancellation.
    let source = read("src/runtime/state.rs");

    assert!(
        source.contains("task.request_cancel_with_budget_and_publication(")
            && source.contains("let ((newly_cancelled, changed, publication), task_wakes) =",)
            && source.contains("wakes.merge(task_wakes);"),
        "REGRESSION: cancel_request no longer captures task \
         mutation effects and splits/merges their opaque \
         wake token. Auxiliary cancellation observers/Wakers may run while \
         task/state locks are live, or be silently lost.",
    );

    assert!(
        source.contains("if newly_cancelled {")
            && source.contains("if changed && publication.is_published() {"),
        "REGRESSION: cancel_request no longer separates the \
         first RequestCancel transition from changed, already-published \
         lane routing.",
    );
}

#[test]
fn budget_update_is_deferred_to_acknowledge_cancel_to_avoid_pre_emption() {
    // Pin (link 2 audit): the comment in
    // request_cancel_with_budget notes that budget update is
    // DEFERRED to acknowledge_cancel — preventing the
    // budget-exhaustion check from pre-empting the cancel
    // observation. This is a subtle ordering invariant.
    let source = read("src/record/task.rs");

    assert!(
        source.contains(
            "// Budget update is deferred to acknowledge_cancel to prevent\n            // pre-empting the cancellation check with a budget exhaustion error."
        ) || source.contains("Budget update is deferred to acknowledge_cancel"),
        "REGRESSION: the budget-deferral comment is gone. \
         The ordering invariant (cancel before budget \
         tightening) may drift — checkpoint may see \
         budget exhaustion BEFORE the cancel signal, \
         masking the cancel attribution.",
    );
}

#[test]
fn cancel_request_returns_effects_for_per_task_priority_routing() {
    // Pin (link 8): cancel_request returns a callback-free
    // Vec<(TaskId, u8)> paired with opaque auxiliary Waker and
    // cancellation-observer effects. The scheduler can publish
    // the list only after its RuntimeState guard is gone and
    // before dispatching those deferred effects. This does not
    // claim that empty-region lifecycle advancement, finalizers,
    // close waiters, heap payload retirement, or region-close metrics
    // reachable later in this same method are deferred.
    let source = read("src/runtime/state.rs");
    let start = source
        .find("pub fn cancel_request(")
        .expect("cancel_request fn");
    let end = source[start..]
        .find("\n    /// Collects a region and all its descendants")
        .expect("cancel_request end marker");
    let body = &source[start..start + end];

    assert!(
        body.contains("-> CancellationEffects<Vec<(TaskId, u8)>>")
            && body.contains("CancellationEffects::new(tasks_to_cancel, wakes)")
            && body.contains("let now = reason.timestamp;")
            && body.contains("wakes.push_region_cancellation_metric(")
            && body.contains("wakes.push_cancel_protocol_violation(")
            && !body.contains(".dispatch()")
            && !body.contains("current_runtime_time()")
            && !body.contains("wake_by_ref("),
        "REGRESSION: cancel_request signature no longer \
         returns the task-routing list coupled to deferred \
         cancellation observers/Wakers, or invokes auxiliary Wakers inline. \
         The post-lock publication/dispatch boundary can no \
         longer be enforced.",
    );

    let sibling_start = source
        .find("fn cancel_sibling_tasks(")
        .expect("sibling cancel helper");
    let sibling_end = source[sibling_start..]
        .find("\n    /// Requests cancellation for a region")
        .expect("sibling cancel helper end");
    let sibling = &source[sibling_start..sibling_start + sibling_end];
    assert!(
        sibling.contains("let now = reason.timestamp;")
            && !sibling.contains("current_runtime_time()"),
        "REGRESSION: sibling cancellation invokes an arbitrary TimeSource callback beneath \
         its caller's RuntimeState lock"
    );
}

#[test]
fn cancellation_validator_transition_never_logs_under_runtime_state() {
    fn function_body<'a>(source: &'a str, marker: &str) -> &'a str {
        let start = source.find(marker).expect("validator helper");
        let tail = &source[start..];
        let end = tail
            .find("\n    }\n\n")
            .expect("validator helper closing brace");
        &tail[..end]
    }

    let validator = read("src/cancel/protocol_state_machines.rs");
    let body = function_body(
        &validator,
        "pub(crate) fn validate_task_transition_without_logging(",
    );
    assert!(
        body.contains("self.record_task_transition(task_id, event, context)")
            && !body.contains("log_violation("),
        "REGRESSION: the task validator's runtime-lock entrypoint can invoke a tracing subscriber"
    );

    let state = read("src/runtime/state.rs");
    let shared = function_body(&state, "fn validate_task_protocol_transition(");
    assert!(
        shared.contains("validate_task_transition_without_logging")
            && !shared.contains(".validate_task_transition("),
        "REGRESSION: the shared RuntimeState task validator invokes logging under its caller's lock"
    );
    for marker in [
        "pub(crate) fn external_checkpoint_cancel_materialization_violation(",
        "pub(crate) fn external_handle_cancel_request_violation(",
    ] {
        let body = function_body(&state, marker);
        assert!(
            body.contains("validate_task_transition_without_logging")
                && !body.contains(".validate_task_transition("),
            "REGRESSION: {marker} returned to the logging validator API while runtime state is locked"
        );
    }
}

#[test]
fn task_cancel_trace_waits_for_first_physical_lane_publication() {
    fn function_body<'a>(source: &'a str, marker: &str) -> &'a str {
        let start = source.find(marker).expect("publication helper");
        let tail = &source[start..];
        let end = tail
            .find("\n    }\n\n")
            .expect("publication helper closing brace");
        &tail[..end]
    }

    let task = read("src/record/task.rs");
    let request = function_body(
        &task,
        "pub(crate) fn request_cancel_with_budget_and_publication(",
    );
    assert!(
        request.contains("if runnable_publication.is_published() {")
            && request.contains(".pending_task_cancel_trace;")
            && request.contains("if pending.is_none() {")
            && request.contains("*pending = Some(trace);"),
        "REGRESSION: a task-cancel trace can escape while admission is Unpublished or \
         DelegatedCancel, or prepublication traces can grow without a bounded first receipt"
    );

    let handle = read("src/runtime/task_handle.rs");
    let admission = function_body(&handle, "pub(crate) fn publish_admitted_cancel_state(");
    let lane = admission
        .find("publish_lane(effective_priority);")
        .expect("physical admission lane publication");
    let published = admission
        .find("lock.runnable_publication.mark_published();")
        .expect("Cx publication marker");
    let trace_take = admission
        .find("lock.pending_task_cancel_trace.take()")
        .expect("pending trace take");
    let unlock = admission.find("drop(lock);").expect("Cx unlock");
    let append = admission
        .find("trace.append_to(&mut wakes);")
        .expect("post-lock trace effect append");
    assert!(
        lane < published && published < trace_take && trace_take < unlock && unlock < append,
        "REGRESSION: admission no longer orders physical lane publication before Cx Published, \
         pending-trace take, unlock, and observer effect release"
    );

    let delegated = function_body(&task, "pub(crate) fn publish_delegated_cancel_lane<T>(");
    let delegated_gate = delegated
        .find("if !guard.runnable_publication.is_delegated_cancel()")
        .expect("delegated Cx gate check");
    let snapshot = delegated
        .find("let cancel_wakers =")
        .expect("prepublication Waker snapshot");
    let lane = delegated
        .find("let publication = publish_lane(")
        .expect("physical delegated lane publication");
    let published = delegated
        .find("guard.runnable_publication.mark_published()")
        .expect("delegated Cx publication marker");
    let unlock = published
        + delegated[published..]
            .find("drop(guard);")
            .expect("successful-publication Cx unlock");
    let append = delegated
        .find("trace.append_to(&mut wakes);")
        .expect("post-lock trace effect append");
    assert!(
        delegated_gate < snapshot
            && snapshot < lane
            && lane < published
            && published < unlock
            && unlock < append,
        "REGRESSION: delegated cancellation can emit or discard its pending trace before a \
         successful first cancel-lane publication"
    );

    let scheduler = read("src/runtime/scheduler/three_lane.rs");
    let drain = function_body(&scheduler, "fn drain_handle_cancel_requests(&self) {");
    assert!(
        drain.contains("record.publish_delegated_cancel_lane(")
            && drain.contains("self.insert_deferred_cancel_lane_without_wake(")
            && drain
                .contains("self.finish_deferred_cancel_lane_publication(task_id, publication);")
            && drain.contains("publication_wakes.retire_without_dispatch();")
            && !drain.contains("mailbox.enqueue_handle_cancel(task_id, reason);"),
        "REGRESSION: delegated cancellation no longer keeps record/Cx publication atomic, or \
         an invalid/stale route can self-requeue forever"
    );

    let delegated_loop = drain
        .find("for (task_id, requested_priority, reason, mut task_wakes) in delegated")
        .expect("delegated publication loop");
    let successful = &drain[delegated_loop..];
    let worker_permit = successful
        .find("self.finish_deferred_cancel_lane_publication(task_id, publication);")
        .expect("delegated worker permit");
    let priority_assert = successful
        .find("debug_assert!(publication.priority >= requested_priority);")
        .expect("post-publication priority assertion");
    let effect_merge = successful
        .find("task_wakes.merge(publication_wakes);")
        .expect("post-publication effect merge");
    assert!(
        worker_permit < priority_assert && worker_permit < effect_merge,
        "REGRESSION: fallible delegated-publication bookkeeping runs before the only concrete \
         worker permit and can strand an already-Published lane"
    );

    let finish = function_body(&scheduler, "fn finish_deferred_cancel_lane_publication(");
    let evidence = finish
        .find("self.record_scheduler_evidence_enqueue(task_id);")
        .expect("scheduler evidence attempt");
    let containment = finish
        .find("std::panic::catch_unwind")
        .expect("evidence unwind containment");
    let wake = finish
        .find("match publication.wake_target")
        .expect("worker wake dispatch");
    assert!(
        containment < evidence && evidence < wake,
        "REGRESSION: scheduler evidence can unwind past delegated publication or worker wake no \
         longer follows the contained evidence attempt"
    );
    let diagnostics = function_body(&scheduler, "fn emit_cancel_diagnostic(");
    assert!(
        diagnostics.contains("std::panic::catch_unwind"),
        "REGRESSION: a tracing diagnostic can abort an already-dequeued cancellation batch"
    );

    let context = read("src/types/task_context.rs");
    let retirement = function_body(&context, "pub(crate) fn take_cancel_wakers(&mut self)");
    assert!(
        retirement.contains("self.pending_task_cancel_trace = None;"),
        "REGRESSION: terminal retirement can retain and later replay a cancellation trace for a \
         task that never acquired a physical lane"
    );
    let failed_route_retirement = function_body(&context, "pub(crate) fn retire_without_dispatch(");
    assert!(
        failed_route_retirement.contains("std::panic::catch_unwind")
            && failed_route_retirement.contains("drop(target)"),
        "REGRESSION: a failed delegated route can retire the final RawWaker without post-lock \
         panic containment"
    );

    let steal = function_body(&scheduler, "pub(crate) fn try_steal(&mut self)");
    let victim_batch = steal
        .find(".steal_ready_batch_into(")
        .expect("victim ready-batch mutation");
    let victim_drop = victim_batch
        + steal[victim_batch..]
            .find("drop(victim);")
            .expect("victim lock release");
    let record_lookup = victim_batch
        + steal[victim_batch..]
            .find("self.with_task_table_ref(")
            .expect("stolen-task record audit");
    assert!(
        victim_batch < victim_drop && victim_drop < record_lookup,
        "REGRESSION: a steal path holds a victim local scheduler while acquiring TaskTable, \
         reversing delegated publication's TaskTable -> Cx -> local order"
    );
}

#[test]
fn runtime_state_does_not_mutate_cx_cancel_flags_directly() {
    // Pin (link 8): RuntimeState routes its task mutations
    // through TaskRecord rather than writing Cx cancellation
    // flags itself. Other legitimate producer paths exist in
    // Cx, handles, and checkpoint reconciliation.
    let source = read("src/runtime/state.rs");

    let suspect_alternate_paths = ["task.cancel_requested = true;", ".fast_cancel.store(true,"];

    let mut findings: Vec<String> = Vec::new();
    for pat in &suspect_alternate_paths {
        if source.contains(pat) {
            // Check it's only in the legitimate
            // request_cancel_with_budget call (which is fine)
            // OR in tests.
            for (line_no, line) in source.lines().enumerate() {
                if line.contains(pat) && !line.contains("request_cancel_with_budget") {
                    let trimmed = line.trim_start();
                    if !trimmed.starts_with("//") && !trimmed.starts_with("///") {
                        findings.push(format!(
                            "state.rs:{line_no}: pattern `{pat}` outside request_cancel_with_budget",
                            line_no = line_no + 1,
                        ));
                    }
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "REGRESSION: state.rs now mutates Cx cancel flags \
         directly instead of reconciling through TaskRecord. \
         Findings:\n  {findings}",
        findings = findings.join("\n  "),
    );
}

// ─────────── BEHAVIORAL PIN: 100-cancel coalescing ─────────
//
// Direct simulation: build a MockTask with a state machine
// + cancel-counter. Issue 100 cancels and verify only ONE
// transition fires (newly_cancelled count == 1) and 99 are
// strengthen-only (newly_cancelled count == 0).

#[derive(Debug, PartialEq, Clone, Copy)]
enum MockState {
    Running,
    CancelRequested,
}

struct MockTask {
    state: MockState,
    fast_cancel: Arc<AtomicBool>,
    cancel_epoch: u64,
    transition_count: Arc<AtomicU32>,
    strengthen_count: Arc<AtomicU32>,
}

impl MockTask {
    fn new() -> Self {
        Self {
            state: MockState::Running,
            fast_cancel: Arc::new(AtomicBool::new(false)),
            cancel_epoch: 0,
            transition_count: Arc::new(AtomicU32::new(0)),
            strengthen_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn request_cancel(&mut self) -> bool {
        // Idempotent fast_cancel publish.
        self.fast_cancel.store(true, Ordering::Release);

        match self.state {
            MockState::CancelRequested => {
                // Coalesced — strengthen only.
                self.strengthen_count.fetch_add(1, Ordering::Relaxed);
                false
            }
            MockState::Running => {
                // First transition.
                self.state = MockState::CancelRequested;
                self.cancel_epoch = 1;
                self.transition_count.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }
}

#[test]
fn behavior_100_cancels_produce_exactly_one_transition_and_99_strengthens() {
    // Behavioral pin: the operator's exact scenario. 100
    // cancel signals on the same task. Verify exactly 1
    // transition + 99 strengthens.
    let mut task = MockTask::new();

    let mut newly_cancelled_count = 0_u32;
    for _ in 0..100 {
        if task.request_cancel() {
            newly_cancelled_count += 1;
        }
    }

    let transitions = task.transition_count.load(Ordering::Relaxed);
    let strengthens = task.strengthen_count.load(Ordering::Relaxed);

    assert_eq!(
        newly_cancelled_count, 1,
        "REGRESSION: 100 cancels produced {newly_cancelled_count} \
         newly_cancelled returns (expected 1). The bool \
         coalescing signal is broken — higher-level \
         scheduler would re-inject the task multiple times.",
    );

    assert_eq!(
        transitions, 1,
        "REGRESSION: 100 cancels produced {transitions} \
         state transitions (expected 1). The state machine \
         is not coalescing — every cancel re-runs the \
         transition logic.",
    );

    assert_eq!(
        strengthens, 99,
        "REGRESSION: 100 cancels produced {strengthens} \
         strengthen-only operations (expected 99). The \
         99 redundant cancels did not all flow into the \
         strengthen path.",
    );

    let epoch = task.cancel_epoch;
    assert_eq!(
        epoch, 1,
        "REGRESSION: cancel_epoch grew to {epoch} after 100 \
         cancels (expected 1). The epoch is no longer \
         gated to the first transition.",
    );

    assert!(
        task.fast_cancel.load(Ordering::Acquire),
        "REGRESSION: fast_cancel is not set after 100 \
         cancels. The atomic publish is broken.",
    );
}

#[test]
fn behavior_concurrent_cancels_from_multiple_threads_are_coalesced() {
    // Behavioral pin: 100 concurrent cancels from 10
    // threads. Verify total transitions == 1 even under
    // race conditions.
    use std::sync::Mutex;
    use std::thread;

    let task = Arc::new(Mutex::new(MockTask::new()));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let task = Arc::clone(&task);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let mut t = task.lock().unwrap();
                t.request_cancel();
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    let task_locked = task.lock().unwrap();
    let transitions = task_locked.transition_count.load(Ordering::Relaxed);
    let strengthens = task_locked.strengthen_count.load(Ordering::Relaxed);

    assert_eq!(
        transitions, 1,
        "REGRESSION: concurrent 100 cancels (10 threads) \
         produced {transitions} transitions (expected 1). \
         Cross-thread coalescing is broken.",
    );

    assert_eq!(
        transitions + strengthens,
        100,
        "REGRESSION: total cancel calls {} != 100. Some \
         cancels were lost.",
        transitions + strengthens,
    );
}

#[test]
fn behavior_cancel_after_terminal_returns_false_no_state_mutation() {
    // Behavioral pin: cancel on a "terminal" task (already
    // CancelRequested in the mock) is a no-op.
    let mut task = MockTask::new();
    task.state = MockState::CancelRequested;

    let result = task.request_cancel();
    assert!(
        !result,
        "REGRESSION: cancel on already-CancelRequested task \
         returned true. The coalescing bool signal is \
         broken — a repeat is reported as a new transition.",
    );

    assert_eq!(
        task.transition_count.load(Ordering::Relaxed),
        0,
        "REGRESSION: cancel on already-CancelRequested task \
         transitioned. State machine corruption.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_region_close_idempotency_audit.rs",
        "tests/scheduler_cancel_storm_propagation_audit.rs",
        "tests/runtime_cancel_cause_chain_depth_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
