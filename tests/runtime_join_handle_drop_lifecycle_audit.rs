//! Audit + regression test for `TaskHandle` and `JoinFuture`
//! drop lifecycle.
//!
//! Operator's question: "when a JoinHandle is dropped
//! without await, does the spawned task get aborted
//! (abort_on_drop semantics, like tokio) or detached
//! (continue running, asupersync default)? Per asupersync
//! structured concurrency, region-bound tasks should abort
//! on region drop."
//!
//! Audit findings:
//!
//!   asupersync has **three distinct drop scopes** with
//!   **three different behaviors** — each appropriate for
//!   its layer:
//!
//!   1. **`TaskHandle` drop alone — DETACHED** (task continues
//!      running). TaskHandle has NO Drop impl. Dropping the
//!      handle without joining lets the spawned task keep
//!      running until completion. This matches asupersyncs
//!      documented "spawn-then-detach" pattern for fire-
//:      and-forget tasks.
//!
//!   2. **`JoinFuture` drop mid-await — ABORTS** (cancel-safe).
//!      JoinFuture (the future returned by
//!      `handle.join(cx)`) DOES have Drop that aborts the
//!      task. This makes `handle.join(cx).await` cancel-
//!      safe — if the await is interrupted (e.g., by a
//!      timeout or race), the spawned task is aborted.
//:      Documented in TaskHandle::join's docstring:
//:      "If this method is cancelled (the returned future
//!      is dropped), the task is automatically aborted."
//!
//!   3. **`Scope::region` future drop — CANCELS ALL CHILDREN**
//!      (structured concurrency). RegionRunner::Drop calls
//!      `state.cancel_request(child_region, ...)`, queues the
//!      returned auxiliary cancellation observer/Waker effects,
//!      and later scheduler dispatch runs only after RuntimeState
//!      is released.
//!      This propagates cancel to all tasks in the region.
//!      This statement does not cover close waiters, finalizers,
//!      region metrics, tracing, or destructors reached by the
//!      subsequent state-advance call.
//!      Operators "region-bound tasks should abort on
//!      region drop" maps onto this path.
//!
//!   The chain:
//!
//!   1. **TaskHandle struct has no Drop impl** (runtime/
//!      task_handle.rs:62-71): four fields (task_id,
//!      receiver, inner, terminal_consumed). No Drop fires
//!      when TaskHandle is dropped. Detached.
//!
//!   2. **JoinFuture::Drop aborts unless defused** (task_handle.rs:
//!      337-353):
//!      ```ignore
//!      impl<T> Drop for JoinFuture<'_, T> {
//!          fn drop(&mut self) {
//!              if !*self.terminal_state && !self.drop_abort_defused {
//!                  if self.inner.receiver_finished() {
//!                      return;
//!                  }
//!                  if let Some(reason) = self.drop_reason.take() {
//!                      self.abort_with_reason(reason);
//!                  } else {
//!                      self.abort_with_reason(CancelReason::user("abort"));
//!                  }
//!              }
//!          }
//!      }
//!      ```
//!      Three guards cover the already-resolved await path,
//!      the internal-combinator defuse path (race, etc.), and
//!      the receiver-finished path where the result already
//!      landed in the channel and should not receive a spurious
//!      cancel reason.
//!
//!   3. **RegionRunner::Drop cancels region** (cx/scope.rs:
//!      181-192):
//!      ```ignore
//!      impl<Fut> Drop for RegionRunner<'_, Fut> {
//!          fn drop(&mut self) {
//!              if let Some(state) = self.state.take() {
//!                  let reason = CancelReason::fail_fast()
//!                      .with_region(self.child_region);
//!                  let effects = state.cancel_request(self.child_region, &reason, None);
//!                  state.defer_cancel_dispatch(effects);
//!                  if let Some(region) = state.region(self.child_region) {
//!                      region.begin_close(None);
//!                  }
//!                  state.advance_region_state(self.child_region);
//!              }
//!          }
//!      }
//!      ```
//!      Region drop cascades cancel via cancel_request,
//!      which fans out to all tasks in the region (per
//:      tests/scheduler_cancel_storm_propagation_audit.rs).
//!      Each tasks fast_cancel.store(true, Release) gets
//!      published; tasks abort on next checkpoint.
//!
//!   Why TaskHandle is detached and JoinFuture is
//!   abort_on_drop:
//!     - TaskHandle drop = "I dont care about the result"
//:       (could be a long-running background task; the user
//!       doesnt want to forcibly cancel it just because
//!       theyre done holding the handle).
//!     - JoinFuture drop = "I was actively waiting for the
//:       result, then stopped" (race / timeout / parent
//!       cancel — the user clearly wants the task to stop).
//!
//!   The two semantics are intentionally DIFFERENT.
//!
//! Verdict: **SOUND**. asupersync has three drop scopes
//! with three contracts:
//!   - TaskHandle drop = detach.
//!   - JoinFuture drop = abort (cancel-safe).
//!   - Region drop = cancel all children (structured
//!     concurrency).
//!
//! Per the operator's "region-bound tasks should abort on
//! region drop" requirement, the RegionRunner path
//! delivers this — verified by structural pin + the prior
//: scheduler_cancel_storm_propagation_audit.rs.
//!
//! No bead filed. The tri-level drop semantics is
//! intentional and well-documented (each Drop has a
//! docstring or behavioral test).
//!
//! A regression that:
//!   - added a Drop impl to TaskHandle that aborts the
//:     task (would conflate handle-drop with active-cancel
//!     — fire-and-forget tasks would be cancelled when the
//!     parent stops holding the handle),
//!   - removed JoinFuture::Drop (would lose cancel-safety
//:     — race/timeout would orphan the task),
//!   - changed JoinFuture::Drop to NOT check terminal_state
//!     (would stamp a spurious cancel on completed tasks
//!     — wrong attribution in the cancel cause chain),
//!   - removed RegionRunner::Drop (would let the region
//!     leak when its future is dropped before await
//!     completes — orphan tasks under panic-above-region),
//!   - changed receiver_finished guard so JoinFuture::Drop
//!     ALWAYS aborts even when the result already arrived
//!     (would silently overwrite a successful result with
//!     a cancel attribution),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn task_handle_has_no_drop_impl_detached_semantics() {
    // Pin (link 1): TaskHandle has no `impl Drop for
    // TaskHandle`. Dropping the handle without joining is
    // a no-op — the task continues running.
    let source = read("src/runtime/task_handle.rs");

    let suspect_drop_impls = [
        "impl<T> Drop for TaskHandle<T> {",
        "impl Drop for TaskHandle {",
    ];
    for pat in &suspect_drop_impls {
        assert!(
            !source.contains(pat),
            "REGRESSION: TaskHandle now has a Drop impl \
             (`{pat}`). The detached-on-drop semantic is \
             broken — fire-and-forget tasks would be \
             cancelled when the parent drops the handle.",
        );
    }

    // Confirm TaskHandle is just a struct definition with
    // no Drop.
    assert!(
        source.contains("pub struct TaskHandle<T> {"),
        "REGRESSION: TaskHandle struct is gone. The handle-\
         to-spawned-task API is broken.",
    );
}

#[test]
fn join_future_has_drop_impl_that_aborts_unless_defused() {
    // Pin (link 2): JoinFuture has Drop that aborts the
    // task. Three guards ensure the abort fires only when
    // appropriate.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("impl<T> Drop for JoinFuture<'_, T> {"),
        "REGRESSION: JoinFuture::Drop impl is gone. \
         handle.join(cx).await is no longer cancel-safe — \
         dropping the await orphans the task.",
    );
}

#[test]
fn join_future_drop_checks_terminal_state_before_aborting() {
    // Pin (link 2 guard a): JoinFuture::Drop checks
    // *self.terminal_state. If the await already resolved,
    // dont stamp a spurious cancel reason.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let start = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("JoinFuture Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if !*self.terminal_state"),
        "REGRESSION: JoinFuture::Drop no longer checks \
         terminal_state. Already-resolved awaits would \
         stamp a spurious cancel reason — wrong \
         attribution.",
    );
}

#[test]
fn join_future_drop_checks_drop_abort_defused_for_internal_combinators() {
    // Pin (link 2 guard b): JoinFuture::Drop checks
    // drop_abort_defused. Internal combinators (race,
    // first_ok) defuse to take ownership of the result.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let start = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("JoinFuture Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("&& !self.drop_abort_defused"),
        "REGRESSION: JoinFuture::Drop no longer checks \
         drop_abort_defused. Internal combinators that \
         take ownership of the result would still trigger \
         abort on drop — double-cancel hazard.",
    );

    // The defuse_drop_abort method must exist for combinators
    // to use.
    assert!(
        source.contains("pub(crate) fn defuse_drop_abort(&mut self) {"),
        "REGRESSION: defuse_drop_abort method is gone. \
         Internal combinators cant disable the abort-on-\
         drop semantic — combinator integration broken.",
    );
}

#[test]
fn join_future_drop_checks_receiver_finished_before_stamping_abort() {
    // Pin (link 2 guard c): JoinFuture::Drop checks
    // self.inner.receiver_finished(). If the result
    // already landed, return without stamping.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let start = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("JoinFuture Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if self.inner.receiver_finished() {") && body.contains("return;"),
        "REGRESSION: JoinFuture::Drop no longer checks \
         receiver_finished. A late-drop after the result \
         landed would silently overwrite the success \
         outcome with a cancel attribution.",
    );
}

#[test]
fn join_future_drop_uses_drop_reason_when_available_else_user_abort() {
    // Pin (link 2 reason): the Drop fires
    // abort_with_reason — using drop_reason if set, else
    // CancelReason::user("abort"). The default attribution
    // is User-kind for documented JoinFuture-drop case.
    let source = read("src/runtime/task_handle.rs");

    let impl_marker = "impl<T> Drop for JoinFuture<'_, T> {";
    let start = source.find(impl_marker).expect("JoinFuture Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("JoinFuture Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if let Some(reason) = self.drop_reason.take() {")
            && body.contains("self.abort_with_reason(reason);")
            && body.contains("self.abort_with_reason(CancelReason::user(\"abort\"));"),
        "REGRESSION: JoinFuture::Drop reason-selection \
         logic changed. Either drop_reason is no longer \
         used (combinators lose the ability to specify a \
         custom reason) or the User-default fallback is \
         gone (abort attribution conflates).",
    );
}

#[test]
fn region_runner_drop_cancels_child_region_for_structured_concurrency() {
    // Pin (link 3): RegionRunner::Drop is the structural
    // mechanism for "region-bound tasks abort on region
    // drop". Without this, parent-panic-above-region
    // leaks the region.
    let source = read("src/cx/scope.rs");

    let impl_marker = "impl<Fut> Drop for RegionRunner<'_, Fut> {";
    let start = source.find(impl_marker).expect("RegionRunner Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("RegionRunner Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("CancelReason::fail_fast().with_region(self.child_region);")
            && body
                .contains("let effects = state.cancel_request(self.child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref("),
        "REGRESSION: RegionRunner::Drop no longer cancels \
         the child region through deferred post-lock effects. Region-drop-cancels-children \
         semantic is broken — orphan tasks under panic-\
         above-region.",
    );

    assert!(
        body.contains("region.begin_close(None);"),
        "REGRESSION: RegionRunner::Drop no longer transitions \
         the region to Closing. Region stays Open under \
         pre-completion drop.",
    );

    assert!(
        body.contains("state.advance_region_state(self.child_region);"),
        "REGRESSION: RegionRunner::Drop no longer drives \
         region state advancement. Quiescence stuck mid-\
         transition.",
    );
}

#[test]
fn task_handle_join_documents_cancel_safety_via_drop() {
    // Pin (link 2 documentation): TaskHandle::join's
    // docstring must document the abort-on-JoinFuture-drop
    // semantic. Without this, users dont know the
    // contract.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("# Cancel Safety")
            && source.contains("If this method is cancelled (the returned future")
            && source.contains("the task")
            && source.contains("is automatically aborted"),
        "REGRESSION: TaskHandle::join docstring no longer \
         documents the cancel-safety / abort-on-drop \
         contract. Users may assume different semantics — \
         either expecting detach (would surface a leaked \
         task) or always-abort (would not match the JoinFuture \
         scope).",
    );
}

#[test]
fn task_handle_is_finished_predicate_for_drop_safety_check() {
    // Pin (audit hygiene): is_finished() lets users check
    // if the task already terminated before deciding
    // whether to drop or join. Without this predicate,
    // users cant tell if dropping the handle is safe.
    let source = read("src/runtime/task_handle.rs");

    assert!(
        source.contains("pub fn is_finished(&self) -> bool {"),
        "REGRESSION: TaskHandle::is_finished is gone. Users \
         lose the predicate that distinguishes 'task \
         finished, safe to drop' from 'task running, drop \
         would detach'.",
    );

    assert!(
        source.contains(
            "self.terminal_consumed || self.receiver.is_ready() || self.receiver.is_closed()"
        ),
        "REGRESSION: is_finished body changed. The three \
         conditions (terminal_consumed, receiver ready, \
         receiver closed) collectively detect any \
         termination state.",
    );
}

#[test]
fn task_handle_struct_holds_weak_inner_to_avoid_keeping_task_alive() {
    // Pin (link 1 lifetime): TaskHandle holds Weak<RwLock<
    // CxInner>>, NOT a strong Arc. Without Weak, the
    // handle would keep the task's CxInner alive past task
    // completion — leaks.
    let source = read("src/runtime/task_handle.rs");

    let struct_marker = "pub struct TaskHandle<T> {";
    let start = source.find(struct_marker).expect("TaskHandle struct");
    let body_end = source[start..].find("\n}\n").expect("TaskHandle close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("inner: Weak<RwLock<CxInner>>,"),
        "REGRESSION: TaskHandle.inner is no longer Weak. \
         Either it became Arc (would keep CxInner alive \
         past task drop — semantic leak) or a raw pointer \
         (UB).",
    );
}

#[test]
fn join_future_struct_has_terminal_state_drop_abort_defused_drop_reason_fields() {
    // Pin (link 2 struct): JoinFuture has the three Drop-
    // guard fields: terminal_state, drop_abort_defused,
    // drop_reason. All three are required for the
    // documented Drop semantics.
    let source = read("src/runtime/task_handle.rs");

    let struct_marker = "pub struct JoinFuture<'a, T> {";
    let start = source.find(struct_marker).expect("JoinFuture struct");
    let body_end = source[start..].find("\n}\n").expect("JoinFuture close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("terminal_state: &'a mut bool,"),
        "REGRESSION: JoinFuture.terminal_state is gone. \
         Drop cant detect already-resolved awaits.",
    );

    assert!(
        body.contains("drop_abort_defused: bool,"),
        "REGRESSION: JoinFuture.drop_abort_defused is gone. \
         Combinators cant defuse abort.",
    );

    assert!(
        body.contains("drop_reason: Option<CancelReason>,"),
        "REGRESSION: JoinFuture.drop_reason is gone. \
         Custom drop reasons cant be specified.",
    );
}

#[test]
fn task_handle_does_not_have_abort_on_drop_method_named_force_abort_or_similar() {
    // Pin (anti-conflation): TaskHandle must NOT have a
    // method that implies hard-kill on drop. The detach-
    // on-drop semantic is intentional.
    let source = read("src/runtime/task_handle.rs");

    let suspect_methods = [
        "pub fn force_abort_on_drop(",
        "pub fn detach(",
        "pub fn detach_silently(",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: TaskHandle now has `{pat}` — \
             implying explicit detach is needed. The \
             detach-on-drop is the DEFAULT; explicit detach \
             methods conflict with the documented \
             semantic.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_abort_vs_cancel_semantics_audit.rs",
        "tests/cx_scope_panic_propagation_audit.rs",
        "tests/scheduler_cancel_storm_propagation_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
