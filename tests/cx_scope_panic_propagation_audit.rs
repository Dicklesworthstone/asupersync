//! Audit + regression test for `Scope::region()` panic
//! propagation: when the future passed to scope panics
//! during poll, the panic must propagate to the parent as
//! a structured `Outcome::Panicked` (NOT swallowed).
//!
//! Operator's question: "when the future passed to
//! Cx::scope(...) panics, does the scope correctly
//! propagate the panic to the parent (correct: panic
//! transparency) or swallow it (incorrect: hidden errors)?"
//!
//! Audit findings:
//!
//!   When the future inside a `Scope::region()` panics
//!   during poll, the panic is **structurally propagated**
//!   to the parent as `Outcome::Panicked(PanicPayload)`.
//!   It is NOT swallowed AND it does NOT escape as a
//!   thread-level unwind that would crash the worker. The
//!   chain:
//!
//!   1. **`CatchUnwind` future wraps the inner fut**
//!      (cx/scope.rs:130-150):
//!      ```ignore
//!      pub(crate) struct CatchUnwind<F> {
//!          #[pin] pub(crate) inner: F,
//!      }
//!      impl<F: Future> Future for CatchUnwind<F> {
//!          type Output = std::thread::Result<F::Output>;
//!          fn poll(self, cx) -> Poll<Self::Output> {
//!              let result = catch_unwind(AssertUnwindSafe(|| {
//!                  this.inner.as_mut().poll(cx)
//!              }));
//!              match result {
//!                  Ok(Poll::Pending) => Poll::Pending,
//!                  Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
//!                  Err(payload) => Poll::Ready(Err(payload)),
//!              }
//!          }
//!      }
//!      ```
//!      Panics during inner.poll are caught and converted
//!      to `Poll::Ready(Err(payload))` — same poll
//!      iteration, no scheduler yield, no worker crash.
//!
//!   2. **`RegionRunner` carries the result + state to the
//!      caller** (cx/scope.rs:160-179): RegionRunner.poll
//!      delegates to fut.poll (the CatchUnwind), packs the
//!      `std::thread::Result<F::Output>` + `&mut
//!      RuntimeState` into Poll::Ready((res, state)).
//!
//!   3. **`region_with_budget` converts to `Outcome::Panicked`**
//!      (cx/scope.rs:951-957):
//!      ```ignore
//!      let (result, state) = runner.await;
//!      let outcome = match result {
//!          Ok(outcome) => outcome,
//!          Err(payload) => {
//!              let msg = payload_to_string(&payload);
//!              Outcome::Panicked(PanicPayload::new(msg))
//!          }
//!      };
//!      ```
//!      The thread::Result Err is downcast to a String
//!      message via payload_to_string and wrapped in
//!      PanicPayload. The panic is now a STRUCTURED
//!      Outcome::Panicked variant.
//!
//!   4. **Region cleanup fires for Panicked outcome**
//!      (cx/scope.rs:971-977):
//!      ```ignore
//!      Outcome::Err(_) | Outcome::Panicked(_) => {
//!          let reason = CancelReason::fail_fast().with_region(...);
//!          let effects = state.cancel_request(child_region, &reason, None);
//!          state.defer_cancel_dispatch(effects);
//!          if let Some(region) = state.region(child_region) {
//!              region.begin_close(None);
//!          }
//!      }
//!      ```
//!      The panicked region's children are cancelled with
//!      CancelKind::FailFast. Sibling tasks dont leak.
//!
//!   5. **`Outcome::Panicked` is returned to the parent**
//!      (cx/scope.rs:987): `Ok(outcome)` — the structured
//!      panic outcome is the function's return. The parent
//!      can match on it:
//!      ```ignore
//!      match scope.region(state, cx, policy, f).await? {
//!          Outcome::Ok(v) => ...,
//!          Outcome::Err(e) => ...,
//!          Outcome::Cancelled(reason) => ...,
//!          Outcome::Panicked(payload) => {
//!              eprintln!("child panicked: {payload}");
//:              ...
//!          }
//!      }
//!      ```
//!      Panic transparency without thread-unwind.
//!
//!   6. **`RegionRunner::Drop` cancels region on
//:      panic-unwind** (cx/scope.rs:181-192): if the
//!      RegionRunner future is dropped before await
//!      completes (e.g., from a panic above region), Drop
//!      cancels the child region — no orphan tasks.
//!
//!   7. **Factory-panic path uses resume_unwind** (cx/scope.rs:
//!      938): when the FACTORY closure (the `f` that
//!      builds the future) itself panics — distinct from
//:      the inner future panicking — the path cancels the
//!      child region first, then explicitly suppresses the
//!      captured Wakers because unwind offers no safe
//!      post-lock dispatch boundary, and resume_unwinds the
//!      payload to the caller. This is the ONLY legitimate
//!      thread-unwind path; it fires when there's no
//!      future to mark Panicked.
//!
//! Verdict: **SOUND**. Panic transparency is preserved as
//! Outcome::Panicked — parent observes the panic via the
//: structured outcome variant. The thread-level unwind is
//! caught at the CatchUnwind boundary; the worker continues.
//! Region cleanup fires (FailFast cancel + begin_close)
//! for sibling-task safety. NOT swallowed: the parent's
//! match on the Result/Outcome surfaces the panic message.
//!
//! No bead filed. Panic propagation is structurally enforced
//! via Outcome::Panicked.
//!
//! A regression that:
//!   - removed the CatchUnwind wrapper (panics escape the
//!     await chain, crash the worker thread),
//!   - changed the Err arm of the result match to silently
//!     return Outcome::Ok or drop the panic info (the
//!     operators 'swallow' failure mode becomes true),
//!   - changed Outcome::Panicked to Outcome::Cancelled
//!     in the conversion (would conflate panic with
//!     normal cancellation — supervisors/audit lose
//!     panic-vs-cancel distinction),
//!   - removed the FailFast cleanup for the Panicked
//!     branch (sibling tasks orphaned — region leak under
//!     panic),
//!   - changed payload_to_string to return a constant
//!     message (panic-cause attribution lost),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn child_admission_body(source: &str) -> &str {
    let fn_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let start = source
        .find(fn_marker)
        .expect("region_with_child_admission fn");
    let body_end = source[start..]
        .find("\n    // =========================================================================")
        .map_or(source.len(), |offset| start + offset);
    &source[start..body_end]
}

#[test]
fn catch_unwind_future_wraps_inner_with_pin_project() {
    // Pin (link 1): CatchUnwind is the structural panic
    // boundary inside scopes. The pin_project lets
    // CatchUnwind project to the inner future safely.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub(crate) struct CatchUnwind<F> {")
            && source.contains("#[pin]\n    pub(crate) inner: F,"),
        "REGRESSION: CatchUnwind struct or its pin-project \
         is gone. Without it, scope panics escape the await \
         chain and crash the worker thread.",
    );
}

#[test]
fn catch_unwind_poll_uses_assert_unwind_safe_for_future_compatibility() {
    // Pin (link 1): CatchUnwind::poll uses
    // catch_unwind(AssertUnwindSafe(...)) — futures arent
    // UnwindSafe by default, so AssertUnwindSafe is required.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {"),
        "REGRESSION: CatchUnwind no longer uses \
         catch_unwind(AssertUnwindSafe(...)) for the inner \
         poll. Panics during poll either escape (crash \
         worker) or fail to compile (futures not UnwindSafe).",
    );
}

#[test]
fn catch_unwind_poll_converts_panic_to_poll_ready_err() {
    // Pin (link 1): the Err arm of the catch_unwind match
    // returns Poll::Ready(Err(payload)) — the panic is
    // converted to a structured Result on the SAME poll.
    let source = read("src/cx/scope.rs");

    let fn_marker = "impl<F: Future> Future for CatchUnwind<F> {";
    let start = source.find(fn_marker).expect("CatchUnwind impl");
    let next_impl = source[start + fn_marker.len()..]
        .find("\nimpl ")
        .map_or(source.len(), |o| start + fn_marker.len() + o);
    let body = &source[start..next_impl];

    assert!(
        body.contains("Err(payload) => Poll::Ready(Err(payload)),"),
        "REGRESSION: CatchUnwind no longer converts caught \
         panic to Poll::Ready(Err). The panic may be \
         silently swallowed (operators failure mode) or \
         re-thrown (worker crash).",
    );

    // Output must be std::thread::Result<F::Output>.
    assert!(
        body.contains("type Output = std::thread::Result<F::Output>;"),
        "REGRESSION: CatchUnwind Output type changed. The \
         std::thread::Result wrapper is what carries the \
         panic payload to the caller.",
    );
}

#[test]
fn region_with_budget_converts_thread_result_err_to_outcome_panicked() {
    // Pin (link 3): region_with_budget destructures the
    // RegionRunner result and converts Err(payload) to
    // Outcome::Panicked(PanicPayload::new(msg)). This is
    // the structural transparency point.
    let source = read("src/cx/scope.rs");
    let body = child_admission_body(&source);

    assert!(
        body.contains("Err(payload) => {")
            && body.contains("let msg = payload_to_string(&payload);")
            && body.contains("Outcome::Panicked(PanicPayload::new(msg))"),
        "REGRESSION: region_with_budget no longer converts \
         the thread::Result Err to Outcome::Panicked. \
         Either the panic is swallowed (operators failure \
         mode), conflated with another outcome, or causes \
         a runtime crash on the convert path.",
    );
}

#[test]
fn region_with_budget_does_not_convert_panicked_to_cancelled() {
    // Pin (link 3 anti-conflation): the Err arm must NOT
    // map to Outcome::Cancelled — that would conflate panic
    // with normal cancel and lose supervisor-relevant
    // attribution.
    let source = read("src/cx/scope.rs");
    let body = child_admission_body(&source);

    // Search for the panic-to-Cancelled anti-pattern.
    let suspect_conflation = [
        "Err(payload) => Outcome::Cancelled",
        "Err(_payload) => Outcome::Cancelled",
        "Err(_) => Outcome::Cancelled",
    ];
    for pat in &suspect_conflation {
        assert!(
            !body.contains(pat),
            "REGRESSION: region_with_budget Err arm now \
             conflates panic with Cancelled (`{pat}`). \
             Supervisors lose the panic-vs-cancel \
             distinction; audit logs misattribute crashes.",
        );
    }
}

#[test]
fn region_with_budget_panicked_outcome_triggers_fail_fast_cleanup() {
    // Pin (link 4): when outcome is Panicked, the cleanup
    // path cancels the child region with FailFast. Without
    // this, sibling tasks orphan — region leak.
    let source = read("src/cx/scope.rs");
    let body = child_admission_body(&source);

    assert!(
        body.contains("Outcome::Err(_) | Outcome::Panicked(_) => {")
            && body.contains("let reason = CancelReason::fail_fast().with_region(child_region);")
            && body.contains("let effects = state.cancel_request(child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref("),
        "REGRESSION: Panicked outcome no longer triggers \
         FailFast region cleanup through deferred post-lock \
         effects. Sibling tasks orphan — \
         region leak. The structured panic propagation \
         is broken (cleanup gap).",
    );

    // begin_close fires too.
    assert!(
        body.contains("region.begin_close(None);"),
        "REGRESSION: Panicked branch no longer calls \
         begin_close. Region stays Open — close-quiescence \
         violated.",
    );
}

#[test]
fn region_with_budget_returns_outcome_to_parent_for_match_observability() {
    // Pin (link 5): the function returns Result<Outcome<T,
    // P2::Error>, RegionCreateError> so the parent can
    // match on the Outcome::Panicked variant. Without this
    // return type, the parent loses panic observability.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region_with_budget<P2, F, Fut, T, Caps>(")
            && source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: region_with_budget signature changed. \
         Without Result<Outcome<...>, ...>, the parent \
         cant observe the four Outcome variants — panic \
         transparency lost.",
    );
}

#[test]
fn payload_to_string_extracts_str_or_string_payload_for_panic_message() {
    // Pin (link 3 supporting): payload_to_string downcasts
    // the panic payload to &str or String. Without this,
    // the Panicked outcome carries an empty/default message
    // — debugging panic causes is degraded.
    let source = read("src/cx/scope.rs");

    let fn_marker =
        "pub(crate) fn payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {";
    let start = source.find(fn_marker).expect("payload_to_string fn");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("payload_to_string close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains(".downcast_ref::<&str>()") && body.contains(".downcast_ref::<String>()"),
        "REGRESSION: payload_to_string no longer downcasts \
         to &str + String. Panic messages from these \
         common payload types are lost — operators see \
         only 'unknown panic' for every crash.",
    );

    assert!(
        body.contains("\"unknown panic\".to_string()"),
        "REGRESSION: payload_to_string fallback message is \
         gone. Non-string payloads (rare) would produce an \
         empty String — observers cant tell panicked from \
         normal completion via the message alone.",
    );
}

#[test]
fn region_runner_drop_cancels_child_region_on_pre_completion_drop() {
    // Pin (link 6): if the RegionRunner future is dropped
    // before await completes (e.g., a panic at a level
    // ABOVE region runs the destructor), Drop cancels the
    // child region. Without this, dropping the region
    // future leaks the region.
    let source = read("src/cx/scope.rs");

    let impl_marker = "impl<Fut> Drop for RegionRunner<'_, Fut> {";
    let start = source.find(impl_marker).expect("RegionRunner Drop impl");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("RegionRunner Drop close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("let effects = state.cancel_request(self.child_region, &reason, None);")
            && body.contains("state.defer_cancel_dispatch(effects);")
            && !body.contains(".dispatch()")
            && !body.contains("wake_by_ref(")
            && body.contains("region.begin_close(None);")
            && body.contains("state.advance_region_state(self.child_region);"),
        "REGRESSION: RegionRunner::drop no longer cleans up \
         the child region on pre-completion drop. Dropping \
         the region future before await completes leaks \
         the region — orphan tasks under panic-above-region.",
    );
}

#[test]
fn factory_panic_path_uses_resume_unwind_only_after_region_cleanup() {
    // Pin (link 7): the factory-panic path is a SEPARATE
    // case from inner-future-panic. When the factory `f`
    // itself panics (before returning a future), the path
    // cancels the child region and then resume_unwinds.
    // This is the ONLY legitimate thread-unwind from the
    // scope path.
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("std::panic::resume_unwind(payload);"),
        "REGRESSION: factory-panic path no longer \
         resume_unwinds. Either the factory panic is \
         silently swallowed (NO outcome to deliver) OR \
         escapes uncleanly.",
    );

    // The resume_unwind must come AFTER cancellation mutation/capture,
    // begin_close, and advance_region_state, and after the captured
    // cancellation observers/Wakers are explicitly suppressed. This pin does
    // not claim that unrelated finalizer/close callbacks inside state advance
    // are callback-free.
    let resume_idx = source
        .find("std::panic::resume_unwind(payload);")
        .expect("resume_unwind call");
    let cleanup_window_start = resume_idx.saturating_sub(3000);
    let safe_start = source
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= cleanup_window_start)
        .unwrap_or(cleanup_window_start);
    let preamble = &source[safe_start..resume_idx];

    assert!(
        preamble
            .contains("let cancel_effects = state.cancel_request(child_region, &reason, None);")
            && preamble.contains("region.begin_close(None);")
            && preamble.contains("state.advance_region_state(child_region);")
            && preamble.contains("let (_, cancel_wakes) = cancel_effects.into_parts();")
            && preamble.contains("cancel_wakes.suppress();"),
        "REGRESSION: factory-panic resume_unwind fires \
         before region cancellation cleanup and explicit suppression of the \
         captured cancellation effects. Region stays in non-\
         quiescent state during unwind — invariant \
         violation.",
    );
}

#[test]
fn region_with_budget_does_not_silently_swallow_panic_outcome() {
    // Pin (link 5 anti-swallow): the function must NOT have
    // a path that converts Outcome::Panicked to
    // Outcome::Ok or discards it. Either pattern is the
    // operators "swallow" failure mode.
    let source = read("src/cx/scope.rs");
    let body = child_admission_body(&source);

    let suspect_swallow = [
        "Outcome::Panicked(_) => Outcome::Ok",
        "Outcome::Panicked(_) => return Ok(Outcome::Ok",
        "_ => Outcome::Ok",
    ];
    for pat in &suspect_swallow {
        assert!(
            !body.contains(pat),
            "REGRESSION: region_with_budget silently \
             swallows Panicked via `{pat}`. The operators \
             'hidden errors' failure mode becomes true.",
        );
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/scheduler_panic_in_task_isolation_audit.rs",
        "tests/scheduler_worker_resilience_panic_during_poll_audit.rs",
        "tests/cx_panic_during_poll_cancel_correctness_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
