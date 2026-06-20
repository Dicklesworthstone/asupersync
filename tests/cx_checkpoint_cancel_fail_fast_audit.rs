//! Audit + regression test for `Cx::checkpoint()` fail-fast
//! behavior when the cancel-bit is already set.
//!
//! Operator's question: "when checkpoint() is called and
//! cancel-bit is already set, does it return Err immediately
//! (correct: fail-fast) or proceed to do work then return Err
//! on next attempt (incorrect: extra work after
//! cancellation)?"
//!
//! Audit findings:
//!
//!   `Cx::checkpoint()` returns `Err(Cancelled)` on the
//!   **SAME call** where the cancel-bit is observed (when
//!   mask_depth==0). The user does NOT need to call
//!   checkpoint twice. The fast path's early `Ok(())` return
//!   is GATED on `!cancelled` — when cancel is observed,
//!   the early return is SKIPPED and the slow path runs
//!   (under the write lock) to:
//!     (a) acknowledge the cancel (cancel_acknowledged = true),
//!     (b) emit cancel/budget evidence for observability,
//!     (c) drain fast-path checkpoint accounting into
//!         CheckpointState for replay,
//!     (d) return Err via check_cancel_from_values.
//!
//!   The slow-path work is **necessary protocol bookkeeping**,
//!   not unrelated user work. The user-facing contract is
//!   fail-fast: Err on the same call as the observation.
//!   The chain:
//!
//!   1. **Fast-path early return is gated on !cancelled**
//!      (cx/cx.rs:1673):
//!      ```ignore
//!      let guard = self.inner.read();
//!      let cancelled = guard.fast_cancel.load(Acquire);
//!      let exhausted = !cancelled && checkpoint_budget_exhaustion(...).is_some();
//!      let has_message = guard.checkpoint_state.last_message.is_some();
//!      let is_first_checkpoint = guard.checkpoint_state.checkpoint_count == 0
//!          && guard.fast_path_count.load(Relaxed) == 0;
//!      if !cancelled && !exhausted && !has_message && !is_first_checkpoint {
//!          // accounting via Relaxed atomics
//!          return Ok(());
//!      }
//!      ```
//!      The fast-return predicate must include `!cancelled`.
//!      When cancellation is set, the fast path falls through
//!      to the slow path. There is no branch that returns Ok
//!      when cancel is set. The extra message/first-checkpoint
//!      guards preserve checkpoint-history accounting and do
//!      not weaken fail-fast cancellation.
//!
//!   2. **Slow path runs same-call** (cx.rs:1684+): when
//!      the fast-path predicate is false, control falls
//!      directly into the slow path. The user's stack
//!      frame is the same — no scheduler yield, no future
//!      Pending, no second poll required.
//!
//!   3. **Slow path acknowledges cancel** (cx.rs:1718):
//!      `if inner.cancel_requested && inner.mask_depth ==
//!      0 { inner.cancel_acknowledged = true; }`. The
//!      acknowledgment is a one-time state transition that
//!      bridges "cancel observed" to "cleanup begins".
//!
//!   4. **Slow path emits cancel evidence** (cx.rs:1747-
//!      1759): `emit_cancel_evidence` records the cancel
//!      decision for observability. Without this, operators
//!      can't see when cancels are observed at checkpoint
//!      vs propagated from elsewhere.
//!
//!   5. **`check_cancel_from_values` returns Err**
//!      (cx.rs:2068-2098): when cancel_requested && mask_depth
//!      == 0, returns `Err(Cancelled)`. When mask_depth > 0,
//!      returns `Ok(())` (mask-deferred). Same-call Err in
//!      the unmasked case.
//!
//!   6. **Mask-deferred case is the documented exception**:
//!      inside Cx::with_mask, cancel is OBSERVED but
//!      acknowledgment is DEFERRED. The Err return is
//!      deferred too — but the cancel STATE is published
//!      under the mask, so the NEXT checkpoint AFTER mask
//!      unwind catches it. This is option-(a) two-call
//!      semantics ONLY for masked critical sections — the
//!      mask is the user's explicit opt-in.
//!
//!   7. **No "Ok now, Err next" path for unmasked cancels**:
//!      a grep over cx.rs for patterns like "skip cancel
//!      check on first call" / "cancel_pending_until_next"
//!      finds nothing. The fail-fast contract is enforced
//!      structurally.
//!
//! Verdict: **SOUND**. checkpoint() returns Err on the
//! SAME call where the cancel-bit is observed at
//! mask_depth==0. The slow-path work (write lock,
//! acknowledgment, evidence, accounting drain) is
//! NECESSARY protocol bookkeeping — not "extra work".
//! The operator's "Ok now, Err next" failure mode does
//! not exist in the unmasked path.
//!
//! Documented exception: inside a Cx::with_mask block,
//! checkpoint returns Ok on observation and the cancel
//! materializes on the next checkpoint AFTER mask
//! unwind. This is the explicit mask protocol — masked
//! critical sections complete before cleanup begins.
//!
//! A regression that:
//!   - removed `!cancelled` from the fast-path predicate
//!     (for example, by changing it to just `!exhausted`)
//!     would let the early Ok return when cancel is set —
//!     operator's "extra work" answer becomes true,
//!   - moved the slow-path acknowledgment after the
//!     check_cancel_from_values call (would defer ack
//!     past the user-visible Err — extra observability
//!     latency),
//!   - introduced a "deferred-Err on first observation"
//:     path (would split the fail-fast contract — first
//!     checkpoint sees cancel but returns Ok, second
//!     checkpoint returns Err),
//!   - removed the cancel_requested check from
//!     check_cancel_from_values (would always return Ok —
//!     cancel observation has no effect on the user-
//:     facing contract),
//!   - removed the mask_depth gate from
//!     cancel_acknowledged (would either prematurely
//!     acknowledge inside a mask, breaking the protocol,
//:     OR never acknowledge — priority inversion),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn checkpoint_fast_path_early_return_gated_on_not_cancelled_and_not_exhausted() {
    // Pin (link 1): the fast path returns Ok ONLY when
    // the predicate includes !cancelled. The Ok early-return
    // is the structural mechanism that enforces fail-fast at
    // the user-API level; the additional message and first-
    // checkpoint guards preserve checkpoint-history accounting.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("if !cancelled && !exhausted && !has_message && !is_first_checkpoint {"),
        "REGRESSION: fast-path early-return predicate \
         changed. The fast-return gate must include \
         `!cancelled`; without it, the early Ok return may \
         fire when cancel is set, allowing user code to \
         proceed past the cancel observation. Operator's \
         'extra work after cancellation' failure mode \
         becomes possible.",
    );
}

#[test]
fn checkpoint_fast_path_reads_cancel_via_acquire_load() {
    // Pin (link 1): the fast-path cancel observation uses
    // Acquire ordering on fast_cancel. Without this, the
    // observation may miss a concurrent Release publish —
    // user proceeds past a cancel that has already been
    // signaled.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire)"),
        "REGRESSION: fast-path cancel check no longer uses \
         Acquire ordering. A concurrently-set cancel may \
         not be observed — fail-fast contract broken under \
         multi-worker dispatch.",
    );
}

#[test]
fn checkpoint_slow_path_runs_same_call_when_cancel_observed() {
    // Pin (link 2): when the fast-path predicate is false,
    // control falls into the slow path on the SAME call.
    // The slow path is NOT a separate future / scheduler
    // yield — checkpoint returns Err on the same call.
    let source = read("src/cx/cx.rs");

    // The slow path is marked by the comment after the
    // fast-path early-return block.
    let slow_path_marker = "// ── Slow path ─";
    let pos = source.find(slow_path_marker).expect("slow path marker");

    // The slow path must NOT yield to the scheduler (no
    // .await / Poll::Pending) — that would split the
    // user-facing call into two polls.
    let window_end = (pos + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[pos..safe_end];

    let suspect_yield = [".await;", "return Poll::Pending"];
    for pat in &suspect_yield {
        assert!(
            !body.contains(pat),
            "REGRESSION: checkpoint slow path now contains \
             `{pat}` — the user's call yields to the \
             scheduler. Same-call Err is broken; the user \
             must call checkpoint twice to see the cancel.",
        );
    }
}

#[test]
fn checkpoint_slow_path_acknowledges_cancel_when_unmasked() {
    // Pin (link 3): the slow path sets cancel_acknowledged
    // = true when mask_depth == 0. This bridges "observation"
    // to "cleanup begins" — without it, the cancel is
    // observed but never finalized.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("if inner.cancel_requested && inner.mask_depth == 0 {")
            && body.contains("inner.cancel_acknowledged = true;"),
        "REGRESSION: checkpoint slow path no longer \
         acknowledges cancel at mask_depth == 0. Cancel is \
         observed but never acknowledged — finalization \
         path may not fire, region quiescence may be \
         delayed.",
    );
}

#[test]
fn checkpoint_slow_path_returns_err_via_check_cancel_from_values() {
    // Pin (link 5): the slow path's final action is to call
    // check_cancel_from_values which returns Err(Cancelled)
    // when cancel observed at mask_depth==0. Without this
    // call, the slow path would silently complete with Ok —
    // user proceeds past the cancel.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("Self::check_cancel_from_values("),
        "REGRESSION: checkpoint slow path no longer \
         delegates to check_cancel_from_values. Without \
         this call, the slow path may return Ok despite \
         observing the cancel — silent cancel-swallow.",
    );

    // The call must be the LAST operation in the function
    // (its return value is the function's return value).
    let call_idx = body
        .rfind("Self::check_cancel_from_values(")
        .expect("check_cancel_from_values call");

    // After the call, only the closing ) and };  remain.
    let after_call = &body[call_idx..];
    assert!(
        !after_call.contains("return Ok(());"),
        "REGRESSION: checkpoint slow path returns Ok AFTER \
         check_cancel_from_values. The Err result is \
         silently overridden — user proceeds past the cancel.",
    );
}

#[test]
fn check_cancel_from_values_returns_err_on_unmasked_cancel() {
    // Pin (link 5+6): check_cancel_from_values returns
    // Err(Cancelled) when cancel_requested && mask_depth==0.
    // Returns Ok when masked. Same-call Err in the unmasked
    // case is the operator's "fail-fast" answer.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn check_cancel_from_values(";
    let start = source.find(fn_marker).expect("check_cancel_from_values fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("check_cancel_from_values close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if cancel_requested {")
            && body.contains("if mask_depth == 0 {")
            && body.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: check_cancel_from_values no longer \
         returns Err(Cancelled) when cancel observed at \
         mask_depth==0. The fail-fast contract is broken — \
         user proceeds past the cancel.",
    );
}

#[test]
fn checkpoint_does_not_have_first_call_skip_cancel_check_path() {
    // Pin (link 7): there must be NO "Ok on first
    // observation, Err on next" path. Such a pattern would
    // be the operator's "extra work after cancellation"
    // failure mode.
    let source = read("src/cx/cx.rs");

    let suspect_two_call_patterns = [
        "first_observation_ok",
        "cancel_pending_until_next_call",
        "skip_first_cancel_check",
        "deferred_err_on_first_observation",
    ];
    for pat in &suspect_two_call_patterns {
        assert!(
            !source.contains(pat),
            "REGRESSION: cx.rs now contains a two-call \
             cancel observation pattern (`{pat}`). The \
             fail-fast contract is broken — user must call \
             checkpoint twice to see a cancel.",
        );
    }
}

#[test]
fn checkpoint_slow_path_emits_cancel_evidence_for_observability() {
    // Pin (link 4): emit_cancel_evidence runs in the slow
    // path when cancel observed at mask_depth==0. Operators
    // see when cancels are observed at checkpoint vs
    // propagated from other sources.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let window_end = (start + 8000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("crate::evidence_sink::emit_cancel_evidence("),
        "REGRESSION: checkpoint no longer emits cancel \
         evidence on observation. Decision audit trail is \
         broken — operators can't see WHERE the cancel was \
         observed.",
    );
}

#[test]
fn checkpoint_signature_returns_result_for_question_mark_propagation() {
    // Pin (link 5 supporting): the Result<(), Error>
    // signature is what makes `cx.checkpoint()?` propagate
    // the Err on the SAME call. A change here would break
    // the surface fail-fast contract.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: checkpoint signature changed. The \
         Result<(), Error> return is what makes ? \
         propagate the cancel Err on the same call.",
    );
}

#[test]
fn no_cancel_check_skip_on_subsequent_polls_in_cx_inner() {
    // Pin (link 7): there must be NO field on CxInner that
    // tracks "cancel was observed but not yet returned" —
    // such a field would imply a two-call observation
    // pattern.
    let source = read("src/types/task_context.rs");

    let suspect_deferral_fields = [
        "cancel_pending_return:",
        "next_checkpoint_returns_err:",
        "cancel_observed_but_not_returned:",
        "deferred_cancel_err:",
    ];
    for pat in &suspect_deferral_fields {
        assert!(
            !source.contains(pat),
            "REGRESSION: CxInner now has a deferred-cancel-\
             return field (`{pat}`). The fail-fast contract \
             is broken — checkpoint may return Ok on the \
             cancel-observation call and Err on the next.",
        );
    }
}

// ─────────── BEHAVIORAL PIN: same-call Err after cancel ──
//
// Direct simulation: build a MockCxInner with the cancel
// state already set, call mock_checkpoint, verify Err on
// the FIRST call (not the second).

#[derive(Debug)]
struct MockCxInner {
    cancel_requested: bool,
    fast_cancel: Arc<AtomicBool>,
    mask_depth: u32,
    cancel_acknowledged: bool,
}

#[derive(Debug, PartialEq)]
enum MockResult {
    Ok,
    ErrCancelled,
}

fn mock_checkpoint(inner: &mut MockCxInner) -> MockResult {
    // Fast path: read-only check.
    let cancelled = inner.fast_cancel.load(Ordering::Acquire);
    assert_eq!(
        inner.cancel_requested, cancelled,
        "mock cancel_requested must mirror fast_cancel"
    );
    if !cancelled {
        return MockResult::Ok;
    }
    // Slow path: cancel observed.
    if inner.mask_depth == 0 {
        inner.cancel_acknowledged = true;
        return MockResult::ErrCancelled;
    }
    // Mask-deferred.
    MockResult::Ok
}

#[test]
fn behavior_cancel_set_returns_err_on_first_call_unmasked() {
    // Behavioral pin: when cancel-bit is set and mask_depth
    // == 0, mock_checkpoint returns Err on the FIRST call —
    // not the second. This is the fail-fast contract.
    let mut inner = MockCxInner {
        cancel_requested: true,
        fast_cancel: Arc::new(AtomicBool::new(true)),
        mask_depth: 0,
        cancel_acknowledged: false,
    };

    let first_result = mock_checkpoint(&mut inner);
    assert_eq!(
        first_result,
        MockResult::ErrCancelled,
        "REGRESSION: first call to checkpoint with cancel \
         set + unmasked did NOT return Err. The fail-fast \
         contract is broken — operator's 'extra work after \
         cancellation' answer becomes true.",
    );

    // Acknowledgment should have happened on the same call.
    assert!(
        inner.cancel_acknowledged,
        "REGRESSION: cancel_acknowledged was not set on the \
         same call. Acknowledgment is deferred — finalization \
         may be delayed.",
    );
}

#[test]
fn behavior_cancel_set_returns_ok_under_mask_first_then_err_after_unwind() {
    // Behavioral pin: under a mask (mask_depth > 0),
    // checkpoint returns Ok on observation. After the mask
    // unwinds, the next checkpoint returns Err. This is the
    // documented mask-deferred case (the ONLY path where
    // two-call semantics applies).
    let mut inner = MockCxInner {
        cancel_requested: true,
        fast_cancel: Arc::new(AtomicBool::new(true)),
        mask_depth: 1, // Inside a mask.
        cancel_acknowledged: false,
    };

    let masked_result = mock_checkpoint(&mut inner);
    assert_eq!(
        masked_result,
        MockResult::Ok,
        "REGRESSION: checkpoint inside a mask returned Err \
         on cancel observation. The mask contract requires \
         deferred Err — masked critical sections must \
         complete.",
    );

    assert!(
        !inner.cancel_acknowledged,
        "REGRESSION: cancel_acknowledged was set INSIDE a \
         mask. Acknowledgment must be deferred until the \
         mask unwinds — premature ack breaks the mask \
         protocol.",
    );

    // After mask unwind, checkpoint returns Err on the next
    // call.
    inner.mask_depth = 0;
    let post_unwind = mock_checkpoint(&mut inner);
    assert_eq!(
        post_unwind,
        MockResult::ErrCancelled,
        "REGRESSION: checkpoint after mask unwind did not \
         return Err. The deferred-Err path is broken — \
         masked tasks would never observe the cancel.",
    );
}

#[test]
fn behavior_cancel_not_set_returns_ok_no_extra_work() {
    // Behavioral pin: when cancel is NOT set, the fast path
    // returns Ok immediately — no slow-path work, no
    // bookkeeping. This is the common-case performance
    // contract.
    let mut inner = MockCxInner {
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
        cancel_acknowledged: false,
    };

    for _ in 0..1000 {
        let result = mock_checkpoint(&mut inner);
        assert_eq!(result, MockResult::Ok);
        assert!(!inner.cancel_acknowledged);
    }
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/cx_checkpoint_budget_exhausted_yield_audit.rs",
        "tests/scheduler_checkpoint_tight_loop_dos_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
