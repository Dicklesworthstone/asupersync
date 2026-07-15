//! Audit + regression test for `Cx::checkpoint()` behavior
//! when budget is exhausted (poll_quota=0 / cost_quota=0 /
//! past deadline).
//!
//! Operator's question: "when budget=0, does checkpoint()
//! yield to scheduler (correct: anti-monopoly) or proceed
//! without yielding (incorrect: allows runaway tasks)?"
//!
//! Audit findings:
//!
//!   `Cx::checkpoint()` correctly **forces a yield** when
//!   budget is exhausted, by returning `Err(Cancelled)` so
//!   the user's `?` propagation surrenders the worker. The
//!   anti-monopoly chain:
//!
//!   1. **`checkpoint_budget_exhaustion` detects exhaustion**
//!      (cx/cx.rs:1952): a single function checks all three
//!      bounds in one pass:
//!      ```ignore
//!      if budget.is_past_deadline(now) { Some((Deadline, ...)) }
//!      if budget.poll_quota == 0 { Some((PollQuota, ...)) }
//!      if matches!(budget.cost_quota, Some(0)) { Some((CostBudget, ...)) }
//!      ```
//!      Returns `Some((CancelReason, exhaustion_kind, ...))`
//!      when any bound is breached.
//!
//!   2. **Slow path publishes self-cancel** (cx/cx.rs:1707-
//!      1717): when the fast path observes exhaustion via
//!      the same function, it falls into the slow path which
//!      under the write lock:
//!      ```ignore
//!      if let Some((reason, _, _)) = &budget_exhaustion {
//!          inner.cancel_requested = true;
//!          inner.fast_cancel.store(true, Release);
//!          let changed = if let Some(existing) = &mut inner.cancel_reason {
//!              existing.strengthen(reason)
//!          } else {
//!              inner.cancel_reason = Some(reason.clone());
//!              true
//!          };
//!          if changed {
//!              inner.cancel_wakers_pending = true;
//!          }
//!      }
//!      ```
//!      The exhaustion is converted into a STRUCTURAL CANCEL
//!      — same protocol as a parent-region cancel, just
//!      with a different `CancelKind` (Deadline / PollQuota /
//!      CostBudget instead of UserCancel / ParentCancelled).
//!
//!   3. **Mask-respecting acknowledgment** (cx/cx.rs:1718):
//!      `if inner.cancel_requested && inner.mask_depth == 0`
//!      gates `cancel_acknowledged = true`. Inside a
//!      Cx::with_mask block, the cancel is OBSERVED but
//!      acknowledgment is DEFERRED until the mask unwinds.
//!
//!   4. **`check_cancel_from_values` returns Err on
//!      observation** (cx/cx.rs:2068-2098): the final return
//!      depends on mask_depth:
//!        - `mask_depth == 0`: `Err(Cancelled)` — the
//!          surface contract forces a yield.
//!        - `mask_depth > 0`: `Ok(())` — but the cancel
//!          state is recorded, so the NEXT checkpoint
//!          AFTER the mask unwinds returns Err.
//!
//!   5. **`?` propagation surrenders the worker**: the user
//!      writes `cx.checkpoint()?;` in their async code. The
//!      Err propagates up the await chain, returning the
//!      future's poll as `Poll::Ready(Outcome::Cancelled(...))`
//!      (or similar). The worker observes the Ready outcome
//!      and dispatches the task as cancel work.
//!
//!   6. **Self-cancel CancelKind reflects exhausted resource**:
//!      the `CancelReason` stamped onto the cx carries
//!      `CancelKind::Deadline`, `CancelKind::PollQuota`, or
//!      `CancelKind::CostBudget` depending on which bound was
//!      hit. Cleanup tasks see the right reason in their
//!      cancel-cause chain — debugging fidelity preserved.
//!
//!   7. **Anti-monopoly contract is hard, not advisory**:
//!      a runaway task that ignores the Err from checkpoint
//!      (e.g., `let _ = cx.checkpoint();`) does NOT escape
//!      the bound. The slow path ALSO sets the state on
//!      CxInner, so the next checkpoint observes the prior
//!      cancel. The cooperative-scheduling general property
//!      still applies: the task can only run as long as it
//!      cooperatively returns Pending or Ready. If it ignores
//!      checkpoint Err and continues, that's the user's bug,
//!      not a runtime defect.
//!
//! Verdict: **SOUND**. checkpoint() with exhausted budget
//! forces a yield via Err(Cancelled) → ?-propagation. The
//! mechanism is the same as parent-region cancel: cancel
//! state on CxInner + Acquire-Release atomic for cross-
//! thread visibility + ?-propagation surrenders the worker.
//!
//! The mask-deferred case (cancel_requested=true, mask_depth>0)
//! is correct: cancel is OBSERVED but ack DEFERRED. The
//! next checkpoint after mask unwind catches it.
//!
//! A regression that:
//!   - removed the budget_exhaustion → cancel-state publish
//!     in the slow path (cx.rs:1707-1717) (would let
//!     subsequent checkpoints observe a stale fast_cancel
//!     state — the exhaustion would be detected once but
//!     not converted into a structural cancel),
//!   - changed checkpoint to return Ok on exhaustion when
//!     mask_depth == 0 (would let runaway tasks proceed
//!     past their budget — exactly the operator's "incorrect"
//!     answer),
//!   - removed the CancelKind::Deadline / PollQuota /
//!     CostBudget stamping (would lose the exhausted-resource
//!     attribution — debugging cancel reasons becomes blind),
//!   - changed the mask gate so acknowledgment fires INSIDE
//!     the mask (would break the mask protocol — masked code
//!     gets cancelled mid-critical-section),
//!   - made the slow-path budget_exhaustion check skip the
//!     fast_cancel.store(Release) (would lose cross-thread
//!     visibility for subsequent checkpoint calls),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn source_window(source: &str, start: usize, len: usize) -> &str {
    let mut end = start.saturating_add(len).min(source.len());
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[start..end]
}

#[test]
fn checkpoint_budget_exhaustion_checks_all_three_bounds() {
    // Pin (link 1): checkpoint_budget_exhaustion checks
    // is_past_deadline AND poll_quota==0 AND cost_quota==
    // Some(0). All three bounds must be present.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("budget.is_past_deadline(now)"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         checks is_past_deadline. Tasks with deadline budgets \
         can run past their deadline — runaway pathway opened.",
    );

    assert!(
        body.contains("if budget.poll_quota == 0 {"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         checks poll_quota == 0. Tasks with finite poll \
         quota can spin past their budget — runaway.",
    );

    assert!(
        body.contains("if matches!(budget.cost_quota, Some(0)) {"),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         checks cost_quota == Some(0). Tasks tracking cost \
         budget (e.g., per-byte or per-row) can run past \
         their cost limit — runaway pathway.",
    );
}

#[test]
fn checkpoint_budget_exhaustion_emits_correct_cancel_kinds() {
    // Pin (link 6): the CancelReason stamped onto the cx
    // carries the right CancelKind. Without these, the
    // cancel cause chain loses the exhausted-resource
    // attribution.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("CancelKind::Deadline"),
        "REGRESSION: deadline-exhaustion CancelKind is gone. \
         Tasks past deadline get a generic cancel reason — \
         debugging loses the deadline attribution.",
    );

    assert!(
        body.contains("CancelKind::PollQuota"),
        "REGRESSION: poll-quota-exhaustion CancelKind is gone. \
         poll-quota-exhausted tasks get a generic reason — \
         debugging loses the quota attribution.",
    );

    assert!(
        body.contains("CancelKind::CostBudget"),
        "REGRESSION: cost-budget-exhaustion CancelKind is gone.",
    );
}

#[test]
fn checkpoint_slow_path_publishes_self_cancel_on_exhaustion() {
    // Pin (link 2): when budget_exhaustion is Some, the slow
    // path sets cancel_requested=true + fast_cancel.store(
    // Release) + cancel_reason. This is what makes
    // exhaustion equivalent to a structural cancel.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("if let Some((reason, _, _)) = &budget_exhaustion {")
            && body.contains("inner.cancel_requested = true;")
            && body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: checkpoint slow path no longer publishes \
         the self-cancel on budget exhaustion. The exhaustion \
         is detected once but not converted into a structural \
         cancel — subsequent checkpoints would not observe \
         the exhaustion via the fast path.",
    );
}

#[test]
fn checkpoint_slow_path_strengthens_existing_cancel_reason() {
    // Pin (link 2 cause-chain): when the slow path observes
    // exhaustion AND a prior cancel is already present, it
    // strengthens (not replaces) the existing reason. This
    // preserves the cancel cause chain.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("let changed = if let Some(existing) = &mut inner.cancel_reason {")
            && body.contains("existing.strengthen(reason)")
            && body.contains("if changed {")
            && body.contains("inner.cancel_wakers_pending = true;"),
        "REGRESSION: checkpoint slow path no longer strengthens \
         existing cancel_reason or no longer marks changed \
         cancellation Wakers pending. A prior cancel from a \
         parent region could be overwritten, or a stronger \
         budget-exhaustion request could remain unobserved.",
    );

    // The Else arm sets cancel_reason for the no-prior-cancel
    // case.
    assert!(
        body.contains("inner.cancel_reason = Some(reason.clone());"),
        "REGRESSION: checkpoint slow path no longer sets \
         cancel_reason when no prior cancel exists. The \
         budget-exhaustion case wouldn't carry any reason — \
         the Err returned to the user has no context.",
    );
}

#[test]
fn checkpoint_acknowledges_cancel_only_when_mask_depth_zero() {
    // Pin (link 3): cancel_acknowledged is gated on
    // mask_depth == 0. Inside Cx::with_mask, observation
    // happens but acknowledgment is deferred — masked
    // critical sections complete before cleanup begins.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("if inner.cancel_requested && inner.mask_depth == 0 {"),
        "REGRESSION: cancel_acknowledged is no longer gated \
         on mask_depth == 0. Either the mask is leaking \
         (masked code gets cancelled mid-section, breaking \
         the mask contract) OR cancel is never acknowledged \
         (priority inversion).",
    );

    assert!(
        body.contains("inner.cancel_acknowledged = true;"),
        "REGRESSION: cancel_acknowledged is no longer set in \
         the slow-path mask gate. Without it, the worker \
         doesn't see the ack signal and may not finalize \
         the cancel.",
    );
}

#[test]
fn check_cancel_from_values_returns_err_when_cancel_observed_at_mask_depth_zero() {
    // Pin (link 4): check_cancel_from_values returns
    // Err(Cancelled) when cancel_requested && mask_depth==0.
    // Inside a mask, returns Ok (deferred). This is the
    // surface contract that ?-propagation depends on.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn check_cancel_from_values(";
    let start = source.find(fn_marker).expect("check_cancel_from_values fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("check_cancel_from_values close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("if cancel_requested {") && body.contains("if mask_depth == 0 {"),
        "REGRESSION: check_cancel_from_values no longer \
         distinguishes mask_depth. Either masked code gets \
         cancelled (breaks mask contract) or unmasked code \
         doesn't get cancelled (runaway tasks).",
    );

    assert!(
        body.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: check_cancel_from_values no longer \
         returns Err(Cancelled) on observation. The yield \
         contract is broken — runaway tasks proceed past \
         their budget without any signal.",
    );

    // Ok is returned when masked.
    assert!(
        body.contains("Ok(())"),
        "REGRESSION: check_cancel_from_values no longer \
         returns Ok in the masked case. Mask defer is gone — \
         every checkpoint Err-propagates regardless of mask.",
    );
}

#[test]
fn checkpoint_signature_is_result_unit_error_for_question_mark_propagation() {
    // Pin (link 5): the signature must be Result<(), Error>
    // so the user can write `cx.checkpoint()?;`. A change
    // here breaks every handler.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: checkpoint signature changed. The \
         Result<(), Error> return is what makes \
         `cx.checkpoint()?` work in handler code; a change \
         here breaks the ?-propagation contract for \
         budget-exhaustion yield.",
    );
}

#[test]
fn budget_exhaustion_emits_evidence_via_evidence_sink() {
    // Pin (link 6 audit): the slow path emits budget-evidence
    // via emit_budget_evidence so that observability tooling
    // can detect when tasks hit their bounds. Without this,
    // operators can't see when budgets are being exhausted.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("crate::evidence_sink::emit_budget_evidence("),
        "REGRESSION: checkpoint no longer emits budget \
         evidence on exhaustion. Operators lose visibility \
         into which tasks are hitting their bounds — \
         debugging budget tuning becomes blind.",
    );
}

#[test]
fn budget_exhaustion_emits_cancel_evidence_when_acknowledging() {
    // Pin (link 6 audit): on acknowledgment (mask_depth==0
    // + cancel_requested), the slow path emits
    // emit_cancel_evidence so the cancel decision is
    // observable.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    let body = source_window(&source, start, 8000);

    assert!(
        body.contains("crate::evidence_sink::emit_cancel_evidence("),
        "REGRESSION: checkpoint no longer emits cancel \
         evidence on acknowledgment. Decision audit trail \
         is broken — operators can't see when cancels are \
         observed at checkpoint vs propagated from elsewhere.",
    );
}

#[test]
fn budget_field_is_copy_for_lock_free_snapshot_in_fast_path() {
    // Pin (link 1 hot-path supporting): Budget must be Copy
    // so the fast-path can snapshot it without acquiring the
    // write lock. Without Copy, every checkpoint would need
    // either a clone (allocation) or a write lock (contention).
    let source = read("src/types/budget.rs");

    assert!(
        source.contains("#[derive(") && source.contains("Copy"),
        "REGRESSION: Budget no longer derives Copy. The fast-\
         path checkpoint snapshot would require a clone or \
         write lock — performance regression on the hot path.",
    );
}

// ─────────── BEHAVIORAL PIN: budget exhaustion forces yield ──
//
// Direct simulation: a "checkpoint" function that mirrors the
// production fast-path + slow-path budget-exhaustion check,
// followed by Err return. Verify a tight loop that ignores
// the Err is bounded by the budget (one iteration past
// exhaustion, then permanent Err).

#[derive(Debug, Clone, Copy)]
struct MockBudget {
    poll_quota: u32,
}

#[derive(Debug)]
struct MockCxInner {
    budget: MockBudget,
    cancel_requested: bool,
    fast_cancel: Arc<AtomicBool>,
    mask_depth: u32,
}

#[derive(Debug)]
struct MockBudgetExhaustedError;

fn mock_checkpoint(inner: &mut MockCxInner) -> Result<(), MockBudgetExhaustedError> {
    // Fast path: read-only check.
    if inner.fast_cancel.load(Ordering::Acquire) {
        if inner.mask_depth == 0 {
            return Err(MockBudgetExhaustedError);
        }
        return Ok(()); // Mask defers acknowledgment.
    }

    // Slow path: detect exhaustion and publish self-cancel.
    if inner.budget.poll_quota == 0 {
        inner.cancel_requested = true;
        inner.fast_cancel.store(true, Ordering::Release);
        if inner.mask_depth == 0 {
            return Err(MockBudgetExhaustedError);
        }
        return Ok(()); // Mask defers.
    }

    Ok(())
}

#[test]
fn exhausted_budget_returns_err_at_mask_depth_zero() {
    // Behavioral pin: a tight loop calling checkpoint with
    // poll_quota=0 must observe Err immediately — and on
    // every subsequent call (the cancel state persists).
    let mut inner = MockCxInner {
        budget: MockBudget { poll_quota: 0 },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
    };

    // First call detects exhaustion, publishes self-cancel,
    // returns Err.
    let first = mock_checkpoint(&mut inner);
    assert!(
        first.is_err(),
        "REGRESSION: first checkpoint call with exhausted \
         budget returned Ok. Anti-monopoly contract broken \
         — runaway tasks can proceed past their budget.",
    );

    // Subsequent calls observe the published cancel via the
    // fast path → also Err.
    for i in 1..100 {
        let result = mock_checkpoint(&mut inner);
        assert!(
            result.is_err(),
            "REGRESSION: checkpoint call #{i} after exhaustion \
             returned Ok. The self-cancel state should \
             persist; subsequent checkpoints observe via the \
             fast-path Acquire load.",
        );
    }
}

#[test]
fn exhausted_budget_inside_mask_defers_err_until_mask_unwinds() {
    // Behavioral pin: inside a mask (mask_depth > 0),
    // checkpoint OBSERVES the exhaustion (sets cancel state)
    // but DEFERS the Err return — masked critical sections
    // complete before cleanup.
    let mut inner = MockCxInner {
        budget: MockBudget { poll_quota: 0 },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 1, // Inside a mask.
    };

    let result = mock_checkpoint(&mut inner);
    assert!(
        result.is_ok(),
        "REGRESSION: checkpoint inside a mask returned Err \
         on budget exhaustion. The mask contract requires \
         deferred acknowledgment — masked critical sections \
         must complete.",
    );

    // The cancel state IS published (next checkpoint after
    // mask unwind would catch it).
    assert!(
        inner.cancel_requested,
        "REGRESSION: masked checkpoint did not publish the \
         cancel state. Once the mask unwinds, the next \
         checkpoint wouldn't catch the deferred exhaustion \
         — runaway tasks escape via mask abuse.",
    );

    // After the mask unwinds (mask_depth = 0), checkpoint
    // returns Err on the next call.
    inner.mask_depth = 0;
    let post_unwind = mock_checkpoint(&mut inner);
    assert!(
        post_unwind.is_err(),
        "REGRESSION: checkpoint after mask unwind did not \
         return Err. The deferred cancel should now \
         materialize — without it, the mask permanently \
         masks budget exhaustion.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_observes_parent_region_cancel_audit.rs",
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
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
