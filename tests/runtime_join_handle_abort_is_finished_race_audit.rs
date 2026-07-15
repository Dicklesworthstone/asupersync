//! Audit + regression test for `TaskHandle::abort` /
//! `TaskHandle::is_finished` race semantics.
//!
//! Operator's question: "when abort() is called and
//! immediately is_finished() is checked, what's the
//! expected return? Per asupersync spec, is_finished
//! returns true once cancellation has been observed by
//! the task (could be later)."
//!
//! Audit findings:
//!
//!   `TaskHandle::abort()` is a CANCEL REQUEST, not an
//:   instantaneous task-termination. Right after abort(),
//!   the task hasn't yet observed the cancel via its next
//!   checkpoint, so `is_finished()` returns **false**.
//!   Eventually (after the task's next checkpoint observes
//!   the published fast_cancel, propagates Err, and the
//!   wrapping future sends `Outcome::Cancelled` through
//!   the result channel), `is_finished()` flips to **true**.
//!
//!   This matches the operator's spec: "is_finished returns
//!   true once cancellation has been observed by the task
//!   (could be later)."
//!
//!   The chain:
//!
//!   1. **`abort()` publishes cancel signal**
//!      (runtime/task_handle.rs:213-240):
//!      ```ignore
//!      pub fn abort(&self) {
//!          self.abort_with_reason(CancelReason::user("abort"));
//!      }
//!      pub fn abort_with_reason(&self, reason: CancelReason) {
//!          apply_or_defer_cancel_reason(/* ... */, &reason);
//!      }
//!      ```
//!      `apply_or_defer_cancel_reason` sets cancel_requested +
//!      fast_cancel + cancel_reason, releases caller-side
//!      locks, and enqueues a callback-free runtime command.
//!      The runtime reconciles the TaskRecord (or accepts the
//!      task's checkpoint-first materialization), publishes the
//!      cancel lane, and only then dispatches panic-isolated
//!      Waker effects. Its next poll observes cancellation via
//!      checkpoint.
//!
//!   2. **`is_finished()` returns based on result-channel
//!      state** (runtime/task_handle.rs:108-110):
//!      ```ignore
//!      pub fn is_finished(&self) -> bool {
//!          self.terminal_consumed
//!              || self.receiver.is_ready()
//!              || self.receiver.is_closed()
//!      }
//!      ```
//!      Three conditions, ANY of which signals
//!      task-finished:
//!      a. `terminal_consumed` — the handle already took
//!      the result via join().await.
//!      b. `receiver.is_ready()` — the wrapping future
//!      sent the outcome through the channel; the result is
//!      sitting there waiting.
//!      c. `receiver.is_closed()` — the sender has been
//!      dropped (the task's wrapping future completed and
//!      the result_tx went out of scope).
//!
//!   3. **Right after abort()**: terminal_consumed = false
//!      (nothing has consumed yet), receiver.is_ready() =
//!      false (the wrapping future hasn't sent yet), and
//!      receiver.is_closed() = false (the sender is still
//!      alive). So is_finished() returns **false**.
//!
//!   4. **Eventually** (after the task's next checkpoint
//!      observes the cancel and the wrapping fn sends its
//!      terminal result through result_tx): receiver.is_ready()
//!      becomes true, and
//!      is_finished() returns **true**. The "could be
//!      later" clause is bounded by the task's next
//!      checkpoint frequency.
//!      The payload is path-dependent: scope-managed futures may
//!      preserve a returned payload even though TaskRecord/region
//!      completion is authoritatively cancelled.
//!
//!   5. **For PARKED tasks** (sleeping on Sleep / channel
//!      / etc.), runtime-owned post-publication effects
//!      dispatch propagates the cancel via the cancel Waker (per
//!      tests/scheduler_cross_thread_cancel_propagation_audit.rs).
//!      The task wakes, polls, observes cancel via
//!      checkpoint, and eventually sends through result_tx.
//!      is_finished() flips after one waker-dispatch cycle.
//!
//! Verdict: **SOUND**. is_finished() returns false right
//! after abort() — the task hasn't yet observed the cancel.
//! Eventually flips to true after the task's wrapping
//! future sends the cancel outcome. The "could be later"
//! is bounded by the task's next checkpoint frequency.
//!
//! No bead filed. The async semantics is documented and
//! the structural mechanism (cancel publish vs result-
//! channel state) is two-stage by design.
//!
//! Note on alternative semantics: a "synchronous abort"
//! that flipped is_finished() immediately would require
//! either (a) blocking abort() until the task quiesces
//! (would block the calling thread arbitrarily — bad), or
//! (b) lying — claim is_finished even though the task is
//! still running (would let users access state thats not
//! actually settled). asupersync chooses the honest
//! "cancel-request semantics".
//!
//! A regression that:
//!   - changed abort() to BLOCK until the task quiesces
//!     (would deadlock if abort is called from inside the
//!     same runtime — async-cancel hazard),
//!   - changed is_finished() to return true immediately
//!     after abort() regardless of result-channel state
//!     (would lie to users — they'd try to take a result
//!     thats not yet sent),
//!   - removed the receiver.is_ready() check from
//!     is_finished (would never see the result-arrived
//!     state — perpetual false),
//!   - removed the receiver.is_closed() check (would miss
//!     the sender-dropped case — perpetual false even after
//!     task completion),
//!   - removed the runtime gateway, cancel-lane publication,
//!     or post-publication Waker dispatch (parked tasks never
//!     observe cancel — is_finished stuck false forever),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn task_handle_abort_publishes_cancel_state_does_not_block() {
    // Pin (link 1): abort() is non-blocking — sets the
    // cancel state and wakes the waker. Does NOT wait for
    // the task to quiesce.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort(&self) {";
    let start = source.find(fn_marker).expect("abort fn");
    let body_end = source[start..].find("\n    }\n").expect("abort close");
    let body = &source[start..start + body_end];

    // The body is a one-liner that delegates to
    // abort_with_reason. No blocking await/poll/wait.
    assert!(
        body.contains("self.abort_with_reason(CancelReason::user(\"abort\"));"),
        "REGRESSION: abort() body changed. If it now blocks \
         (e.g., awaits the task to quiesce), the API \
         becomes deadlock-prone — abort from the same \
         runtime would self-block.",
    );

    // Forbid synchronous-block patterns.
    let suspect_blocking = ["loop {", "while !is_finished", "block_on"];
    for pat in &suspect_blocking {
        assert!(
            !body.contains(pat),
            "REGRESSION: abort() now contains blocking \
             pattern (`{pat}`). The cancel-request \
             semantics is broken — the API is no longer \
             non-blocking.",
        );
    }
}

#[test]
fn task_handle_abort_with_reason_publishes_via_release_store() {
    // Pin (link 1): abort_with_reason publishes
    // cancel_requested + fast_cancel.store(Release). The
    // Release store is what makes the cancel signal
    // visible to the task's next Acquire load.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.contains("let mut cached = requested.write();")
            && source.contains(".filter(|task| task.is_published())")
            && source.contains("strengthen_cancel_reason_locked(&mut lock, &strongest_requested);")
            && source.contains("lock.cancel_requested = true;")
            && source.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: abort_with_reason no longer publishes \
         through the admission gate and cancel_requested + \
         fast_cancel.store(Release). \
         The task can't observe the abort — is_finished \
         stuck false forever.",
    );
}

#[test]
fn task_handle_abort_defers_wakers_until_runtime_cancel_lane_publication() {
    // Pin (link 5): abort itself runs no Waker. It releases the
    // caller-side locks and enqueues plain data; the scheduler
    // performs the TaskRecord transition, publishes the cancel
    // lane, and only then dispatches panic-isolated Wakers.
    let source = read("src/runtime/task_handle.rs");
    let mailbox = read("src/runtime/spawn_mailbox.rs");
    let state = read("src/runtime/state.rs");
    let scheduler = read("src/runtime/scheduler/three_lane.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];
    let gate_start = source
        .find("fn apply_or_defer_cancel_reason(")
        .expect("admission-aware abort helper");
    let gate_end = source[gate_start..]
        .find("\n}\n")
        .expect("admission-aware abort helper close");
    let gate_body = &source[gate_start..gate_start + gate_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.matches("apply_or_defer_cancel_reason(").count() >= 3
            && gate_body.contains("let mut cached = requested.write();")
            && gate_body.contains(".filter(|task| task.is_published())")
            && !gate_body.contains(".dispatch()")
            && !gate_body.contains("cancel_waker_snapshot")
            && gate_body.contains("drop(cached);")
            && gate_body.contains("changed || lock.runnable_publication.is_delegated_cancel()")
            && gate_body.contains("gateway.enqueue_handle_cancel(task_id, effective_reason)")
            && mailbox.contains("pub(crate) fn enqueue_handle_cancel(")
            && state.contains("pub(crate) fn cancel_task_for_handle(")
            && state.contains("record.request_cancel_for_handle(reason)")
            && scheduler.contains("record.publish_delegated_cancel_lane(")
            && scheduler.contains("publication_wakes.retire_without_dispatch();")
            && !scheduler.contains("mailbox.enqueue_handle_cancel(task_id, reason);")
            && scheduler.contains("for wakes in wakes_to_dispatch")
            && scheduler.contains("wakes.dispatch();"),
        "REGRESSION: abort_with_reason no longer crosses the callback-free \
         runtime boundary before TaskRecord transition, cancel-lane \
         publication, and Waker dispatch. Parked tasks may miss abort or \
         reentrant Waker code may run in the caller's lock stack.",
    );
}

#[test]
fn is_finished_checks_terminal_consumed_or_receiver_ready_or_closed() {
    // Pin (link 2): is_finished checks three conditions
    // — terminal_consumed, receiver.is_ready(),
    // receiver.is_closed(). All three are needed.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn is_finished(&self) -> bool {";
    let start = source.find(fn_marker).expect("is_finished fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("is_finished close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains(
            "self.terminal_consumed || self.receiver.is_ready() || self.receiver.is_closed()"
        ),
        "REGRESSION: is_finished body changed. Either it \
         now over-reports finished (e.g., returns true on \
         abort regardless of result channel — lies to \
         users) or under-reports (missing one of the three \
         conditions — perpetual false in some legitimate \
         finish state).",
    );
}

#[test]
fn is_finished_documentation_explains_three_termination_conditions() {
    // Pin (link 2 documentation): the docstring explains
    // why is_finished checks all three conditions. Without
    // this docstring, future readers may simplify the
    // logic and break the contract.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("the result value is ready, or")
            && source.contains("the join channel is already closed"),
        "REGRESSION: is_finished docstring no longer \
         explains the three termination conditions. \
         Future-proofing against simplification regressions \
         is broken.",
    );
}

#[test]
fn is_finished_terminal_consumed_field_set_by_join_future_drop() {
    // Pin (link 2 terminal_consumed): the
    // terminal_consumed field is set when JoinFuture
    // takes the result. Without this signal, is_finished
    // can't detect the take.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("terminal_consumed: bool,"),
        "REGRESSION: TaskHandle.terminal_consumed field is \
         gone. The handle cant remember that a result was \
         already taken — could double-take or skip the \
         finished signal.",
    );

    assert!(
        source.contains("terminal_state: &'a mut bool,"),
        "REGRESSION: JoinFuture.terminal_state borrow is \
         gone. The handles terminal_consumed cant be \
         set when the await completes.",
    );
}

#[test]
fn task_handle_abort_does_not_consume_terminal_directly() {
    // Pin (anti-conflation): abort() does NOT set
    // terminal_consumed. The cancel publish is separate
    // from the result-take. is_finished() should NOT
    // return true after abort() on its own.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    assert!(
        !body.contains("self.terminal_consumed = true;"),
        "REGRESSION: abort_with_reason now sets \
         terminal_consumed = true. is_finished() would \
         return true immediately after abort — LYING to \
         users about result availability.",
    );

    // Forbid receiver-state mutation from abort.
    let suspect_receiver_mutation = [
        "self.receiver.close();",
        "self.receiver.take();",
        "self.receiver.disconnect();",
    ];
    for pat in &suspect_receiver_mutation {
        assert!(
            !body.contains(pat),
            "REGRESSION: abort_with_reason now mutates the \
             receiver state (`{pat}`). is_finished would \
             return true immediately — same lying-to-user \
             failure.",
        );
    }
}

#[test]
fn join_future_completes_via_receiver_recv_uninterruptible_after_abort() {
    // Pin (link 4 propagation): JoinFuture awaits via
    // receiver.recv_uninterruptible. After abort, the task
    // observes cancel via checkpoint and the wrapping fn
    // sends its path-specific terminal result. JoinFuture
    // resolves independently of whether that payload is a
    // cancellation error or a scope-preserved return value.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn join<'a>(&'a mut self, _cx: &'a Cx) -> JoinFuture<'a, T> {";
    let start = source.find(fn_marker).expect("TaskHandle::join fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("TaskHandle::join close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner: receiver.recv_uninterruptible(),"),
        "REGRESSION: TaskHandle::join no longer uses \
         receiver.recv_uninterruptible. The await would \
         either be interruptible (cancel-on-await-drop \
         lost) or never resolve (broken).",
    );
}

#[test]
fn fast_cancel_is_arc_atomic_bool_for_cross_thread_propagation() {
    // Pin (link 1 cross-thread): fast_cancel is
    // Arc<AtomicBool>. Without the Arc, abort from one
    // thread + checkpoint on another wouldn't share the
    // atomic — is_finished stuck false even after
    // checkpoint observation.
    let source = read("src/types/task_context.rs");

    assert!(
        source.contains("pub fast_cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,"),
        "REGRESSION: CxInner.fast_cancel is no longer \
         Arc<AtomicBool>. abort+checkpoint cross-thread \
         pair is broken.",
    );
}

#[test]
fn abort_publishes_cancel_reason_for_attribution_in_outcome() {
    // Pin (link 1 attribution): abort sets cancel_reason
    // via strengthen-or-set. The authoritative TaskRecord
    // and region completion surface this attribution even
    // when a scope-specific join payload is preserved.
    let source = read("src/runtime/task_handle.rs");

    let fn_marker = "pub fn abort_with_reason(&self, reason: CancelReason) {";
    let start = source.find(fn_marker).expect("abort_with_reason fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("abort_with_reason close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("apply_or_defer_cancel_reason(")
            && !body.contains(".dispatch()")
            && source.contains("if let Some(existing) = cached.as_mut() {")
            && source.contains("if let Some(existing) = &mut lock.cancel_reason {")
            && source.contains("existing.strengthen(reason)")
            && source.contains("lock.cancel_reason = Some(reason.clone());"),
        "REGRESSION: abort_with_reason no longer manages \
         cancel_reason via strengthen-or-set. Attribution \
         is lost — Outcome::Cancelled would carry no reason.",
    );
}

#[test]
fn task_handle_uses_weak_handle_to_avoid_keeping_inner_alive() {
    // Pin (audit hygiene): TaskHandle.inner is Weak — the
    // handle doesnt keep the task's CxInner alive. Without
    // Weak, the task lives until ALL handles drop —
    // unbounded lifetime.
    let source = read("src/runtime/task_handle.rs");

    let struct_marker = "pub struct TaskHandle<T> {";
    let start = source.find(struct_marker).expect("TaskHandle struct");
    let body_end = source[start..].find("\n}\n").expect("TaskHandle close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner: Weak<RwLock<CxInner>>,"),
        "REGRESSION: TaskHandle.inner is no longer Weak. \
         Either Arc (semantic leak) or raw pointer (UB).",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_join_handle_drop_lifecycle_audit.rs",
        "tests/runtime_abort_vs_cancel_semantics_audit.rs",
        "tests/scheduler_cross_thread_cancel_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
