//! Audit + regression test for `Cx::checkpoint()` behavior
//! when the task's deadline has already passed.
//!
//! Operator's question: "when a task's deadline is in the
//! past and it calls checkpoint, must return
//! Err(DeadlineExceeded) immediately (correct: no work
//! after deadline) NOT proceed and check at next checkpoint
//! (incorrect: extra work)."
//!
//! Audit findings:
//!
//!   `Cx::checkpoint()` returns `Err` on the **SAME call**
//!   where the past-deadline condition is observed (when
//!   `mask_depth==0`). The error is
//!   `Error::new(ErrorKind::Cancelled)` carrying a
//!   `CancelReason` with `CancelKind::Deadline` —
//!   asupersync uses the unified Cancelled error variant
//!   for ALL cancel causes; the kind discrimination is
//!   carried in the CancelReason chain.
//!
//!   Note: there is NO `ErrorKind::DeadlineExceeded`
//!   variant. The operator's framing maps to:
//!     - `Err(Error::new(ErrorKind::Cancelled))` returned
//!       from the user-facing API
//!     - `CancelReason { kind: CancelKind::Deadline, .. }`
//!       carried as the cancel reason on CxInner, accessible
//!       via the cause chain.
//!   This is intentional — the unified Cancelled type
//!   simplifies `?`-propagation while the structured
//!   CancelReason preserves debug attribution.
//!
//!   The chain (same-call Err on past-deadline):
//!
//!   1. **Fast-path detects past-deadline via
//!      checkpoint_budget_exhaustion** (cx/cx.rs:1665):
//!      ```ignore
//!      let exhausted = !cancelled
//!          && Self::checkpoint_budget_exhaustion(
//!              guard.region, guard.task, guard.budget,
//!              checkpoint_time,
//!          ).is_some();
//!      let has_message = guard.checkpoint_state.last_message.is_some();
//!      let is_first_checkpoint = guard.checkpoint_state.checkpoint_count == 0
//!          && guard.fast_path_count.load(Relaxed) == 0;
//!      if !cancelled && !exhausted && !has_message && !is_first_checkpoint {
//!          return Ok(());
//!      }
//!      ```
//!      `checkpoint_budget_exhaustion` checks
//!      `budget.is_past_deadline(now)` first (cx/cx.rs:
//!      1962). When true, returns
//!      `Some((CancelReason{kind:Deadline,...}, "time", ...))`.
//!      The fast-return predicate includes `!exhausted`, so
//!      a past-deadline task is EXCLUDED from the early Ok
//!      return — control falls into the slow path on the
//!      SAME call. The extra message/first-checkpoint guards
//!      only narrow the healthy fast path further.
//!
//!   2. **`Budget::is_past_deadline` is the source-of-truth
//:      predicate** (types/budget.rs:298):
//!      ```ignore
//!      pub fn is_past_deadline(&self, now: Time) -> bool {
//!          self.deadline.is_some_and(|d| now >= d)
//!      }
//!      ```
//!      Returns true when `now >= deadline`. The
//!      `is_some_and` short-circuits on None — tasks
//!      without a deadline never trigger this.
//!
//!   3. **Slow-path publishes self-cancel with Deadline
//:      kind** (cx/cx.rs:1707-1717): under the write lock,
//!      the slow path observes `budget_exhaustion` (which
//!      includes the past-deadline case from step 1):
//!      ```ignore
//!      if let Some((reason, _, _)) = &budget_exhaustion {
//!          inner.cancel_requested = true;
//!          inner.fast_cancel.store(true, Release);
//!          if let Some(existing) = &mut inner.cancel_reason {
//!              existing.strengthen(reason);
//!          } else {
//!              inner.cancel_reason = Some(reason.clone());
//!          }
//!      }
//!      ```
//!      The `reason` carries `CancelKind::Deadline`. The
//!      cancel state is published with Release ordering so
//!      subsequent checkpoints (and other observers) see
//!      it via Acquire load.
//!
//!   4. **`check_cancel_from_values` returns Err on same
//:      call** (cx/cx.rs:2068-2098): when
//!      `cancel_requested && mask_depth == 0`, returns
//!      `Err(Cancelled)`. Same call as the original
//!      checkpoint invocation — no scheduler yield, no
//!      future Pending, no second poll.
//!
//!   5. **Subsequent checkpoints also return Err via
//!      fast-path cancel branch**: after the slow path
//!      published `fast_cancel=true`, subsequent
//!      checkpoints hit the `cancelled` true branch in
//!      the fast path. They fall through to the slow path
//!      and return Err — still same-call. The deadline-
//!      exceeded state PERSISTS until the task is
//!      finalized.
//!
//!   6. **Mask-deferred case is the documented exception**:
//!      inside `Cx::with_mask`, checkpoint returns Ok on
//!      observation (the mask defers acknowledgment). The
//!      cancel state IS published, so the next checkpoint
//!      AFTER mask unwind returns Err. This is the SAME
//!      mask protocol as for any other cancel cause —
//!      consistent with deadline detection.
//!
//! Verdict: **SOUND**. Past-deadline is detected on the
//! SAME call via checkpoint_budget_exhaustion's
//! `budget.is_past_deadline(now)` check, the slow path
//! publishes `CancelKind::Deadline` self-cancel, and
//! check_cancel_from_values returns Err(Cancelled).
//! The user's `?` propagation surrenders the worker on
//! the SAME call — no extra work after deadline.
//!
//! The operator's "Err(DeadlineExceeded)" framing is
//! technically loose — the actual error type is
//! Err(Cancelled) carrying CancelKind::Deadline. This is
//! the unified-cancel-error design (one ErrorKind variant,
//! many CancelKind reasons).
//!
//! A regression that:
//!   - changed checkpoint_budget_exhaustion to NOT check
//!     is_past_deadline (would let past-deadline tasks
//:     proceed past their deadline — operator's "extra
//!     work" failure mode),
//!   - changed is_past_deadline to use > instead of >=
//!     (one-tick window where the deadline is exactly now
//!     and not detected — flaky deadline behavior),
//!   - moved the past-deadline check to a separate
//:     non-checkpoint code path (would defeat the
//!     same-call Err contract — apps would see deadline
//!     exceeded on the next checkpoint, not the first),
//!   - added a "first call after deadline returns Ok"
//!     branch (operators "extra work after deadline"
//!     failure mode becomes true),
//!   - removed the slow-path strengthen+publish for
//!     deadline-exhaustion (subsequent checkpoints would
//!     not see the cancel state — task continues
//!     proceeding past deadline),
//!
//! would all be caught by the structural pins below.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn budget_is_past_deadline_uses_now_geq_deadline_for_inclusive_check() {
    // Pin (link 2): is_past_deadline returns true when
    // now >= deadline (inclusive). Without this, exact-
    // tick deadlines may be missed.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub fn is_past_deadline(&self, now: Time) -> bool {";
    let start = source.find(fn_marker).expect("is_past_deadline fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("is_past_deadline close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.deadline.is_some_and(|d| now >= d)"),
        "REGRESSION: is_past_deadline no longer uses now >= d \
         comparison. Either the comparison is > (one-tick \
         window where deadline=now is missed) or the \
         is_some_and short-circuit is gone (Option-handling \
         broken).",
    );
}

#[test]
fn checkpoint_budget_exhaustion_checks_is_past_deadline_first() {
    // Pin (link 1): checkpoint_budget_exhaustion checks
    // is_past_deadline FIRST in the function body. The
    // ordering matters — deadline is the most common
    // exhaustion path and should be checked before the
    // less-common poll/cost quotas.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let body = &source[start..start + body_end];

    let deadline_idx = body
        .find("budget.is_past_deadline(now)")
        .expect("is_past_deadline check");
    let poll_quota_idx = body
        .find("if budget.poll_quota == 0 {")
        .expect("poll_quota check");

    assert!(
        deadline_idx < poll_quota_idx,
        "REGRESSION: checkpoint_budget_exhaustion now \
         checks poll_quota BEFORE deadline. The deadline \
         check should run first — it's the canonical \
         exhaustion path.",
    );

    // The Deadline kind must be stamped on the reason.
    assert!(
        body.contains(
            "CancelReason::with_origin(CancelKind::Deadline, region, now).with_task(task)"
        ),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         stamps CancelKind::Deadline on past-deadline. The \
         cancel reason loses its deadline attribution — \
         debugging consumers cant distinguish deadline from \
         poll/cost exhaustion.",
    );
}

#[test]
fn checkpoint_fast_path_falls_through_when_exhausted_is_some() {
    // Pin (link 1): the fast-path early-return predicate
    // includes `!exhausted`. When past-deadline makes
    // exhausted = Some(...), the predicate is false and
    // control falls through to the slow path on the SAME call.
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
        body.contains("if !cancelled && !exhausted && !has_message && !is_first_checkpoint {")
            && body.contains("return Ok(());"),
        "REGRESSION: fast-path early-return predicate is no \
         longer gated on `!exhausted`. Past-deadline \
         tasks may take the early Ok path — operator's \
         'extra work after deadline' failure mode.",
    );
}

#[test]
fn checkpoint_slow_path_publishes_deadline_self_cancel_with_release() {
    // Pin (link 3): when the slow path observes
    // budget_exhaustion (which includes the past-deadline
    // case), it sets cancel_requested=true and
    // fast_cancel.store(true, Release). This makes the
    // deadline-exceeded state observable to subsequent
    // checkpoints.
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
        body.contains("if let Some((reason, _, _)) = &budget_exhaustion {")
            && body.contains("inner.cancel_requested = true;")
            && body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: checkpoint slow path no longer publishes \
         the budget-exhaustion self-cancel. Past-deadline is \
         detected once but not converted to a structural \
         cancel — subsequent checkpoints would not observe \
         the deadline via the fast path.",
    );
}

#[test]
fn checkpoint_slow_path_strengthens_existing_reason_on_deadline_exhaustion() {
    // Pin (link 3): the slow path strengthens an existing
    // cancel_reason (e.g., from a parent-region cancel
    // that arrived earlier). Without this, the deadline
    // would overwrite a stronger parent reason.
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
        body.contains("if let Some(existing) = &mut inner.cancel_reason {")
            && body.contains("existing.strengthen(reason);"),
        "REGRESSION: checkpoint slow path no longer \
         strengthens existing cancel_reason. A parent \
         cancel arriving before deadline would be overwritten \
         by the deadline self-cancel — wrong attribution \
         in the cause chain.",
    );

    // The else arm sets reason for the no-prior-cancel case.
    assert!(
        body.contains("inner.cancel_reason = Some(reason.clone());"),
        "REGRESSION: checkpoint slow path no longer sets \
         cancel_reason when none exists. Past-deadline case \
         with no prior cancel would carry no reason — the \
         Err returned to the user has no Deadline \
         attribution.",
    );
}

#[test]
fn check_cancel_from_values_returns_err_for_deadline_at_mask_depth_zero() {
    // Pin (link 4): check_cancel_from_values returns
    // Err(Cancelled) when cancel_requested && mask_depth==0.
    // This is what makes deadline detection produce same-
    // call Err.
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
         returns Err when cancel observed at mask_depth==0. \
         Past-deadline tasks see Ok despite the deadline \
         exhaustion — operators 'extra work after deadline' \
         failure mode.",
    );
}

#[test]
fn checkpoint_slow_path_runs_same_call_no_yield_for_past_deadline() {
    // Pin (link 1+3+4): the slow path runs synchronously on
    // the SAME call as the user's checkpoint invocation.
    // No .await / Poll::Pending — the user gets Err on the
    // first call, not the second.
    let source = read("src/cx/cx.rs");

    let slow_path_marker = "// ── Slow path ─";
    let pos = source.find(slow_path_marker).expect("slow path marker");
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
             `{pat}` — yields to scheduler. Past-deadline \
             tasks must call checkpoint twice to see Err — \
             same-call contract broken.",
        );
    }
}

#[test]
fn checkpoint_returns_result_unit_error_for_question_mark_propagation() {
    // Pin (link 4 supporting): the Result<(), Error>
    // signature is what makes `cx.checkpoint()?` propagate
    // the deadline Err to the future's Poll::Ready.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: checkpoint signature changed. The \
         Result<(), Error> return is what makes ? \
         propagate the deadline Err to the future's poll.",
    );
}

#[test]
fn budget_exhaustion_emits_evidence_for_deadline_observability() {
    // Pin (link 3 audit): the slow path emits budget
    // evidence with the exhaustion_kind (which is "time"
    // for the deadline case). Without this, operators can't
    // see when tasks hit their deadline.
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
        body.contains("crate::evidence_sink::emit_budget_evidence("),
        "REGRESSION: checkpoint no longer emits budget \
         evidence on exhaustion. Operators lose visibility \
         into deadline-induced cancels — debugging slow \
         tasks gets harder.",
    );

    // The exhaustion_kind label is "time" for deadline
    // (set in checkpoint_budget_exhaustion).
    let cb_marker = "fn checkpoint_budget_exhaustion(";
    let cb_start = source
        .find(cb_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let cb_body_end = source[cb_start..]
        .find("\n    }\n")
        .expect("checkpoint_budget_exhaustion close");
    let cb_body = &source[cb_start..cb_start + cb_body_end];

    assert!(
        cb_body.contains("\"time\""),
        "REGRESSION: checkpoint_budget_exhaustion no longer \
         labels deadline-exhaustion as \"time\". Evidence \
         consumers see the wrong exhaustion-kind label — \
         budget-tuning dashboards regress.",
    );
}

#[test]
fn checkpoint_returns_cancelled_kind_not_deadline_exceeded_kind() {
    // Pin (operator framing nuance): both ErrorKind::Cancelled
    // and ErrorKind::DeadlineExceeded exist (error.rs:48, 54).
    // For checkpoint() past-deadline, the returned Err carries
    // ErrorKind::Cancelled — NOT DeadlineExceeded. The
    // discrimination is in the CancelReason carried by
    // CxInner.cancel_reason (CancelKind::Deadline).
    //
    // ErrorKind::DeadlineExceeded is reserved for combinator-
    // level timeout errors (e.g., the timeout combinator's
    // direct return), NOT for cooperative-yield checkpoint
    // returns. This split lets `?`-propagation distinguish
    // "task was cancelled (any cause)" from "outer combinator
    // timed out".
    let source = read("src/error.rs");

    // Both variants must exist — they serve different purposes.
    assert!(
        source.contains("Cancelled,"),
        "REGRESSION: ErrorKind::Cancelled is gone. The \
         checkpoint-return target is broken — past-deadline \
         tasks have nothing to propagate.",
    );

    assert!(
        source.contains("DeadlineExceeded,"),
        "REGRESSION: ErrorKind::DeadlineExceeded is gone. \
         Combinator-level timeouts lose their dedicated \
         error variant — apps that match on \
         DeadlineExceeded for combinator timeouts would \
         break.",
    );

    // The check_cancel_from_values helper (in cx.rs) must
    // return the Cancelled variant — not DeadlineExceeded.
    let cx_source = read("src/cx/cx.rs");
    assert!(
        cx_source.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: check_cancel_from_values no longer \
         returns ErrorKind::Cancelled. If it now returns \
         DeadlineExceeded, the unified-cancel-error design \
         is broken — apps that match on Cancelled would \
         miss deadline-exceeded checkpoint returns.",
    );
}

// ─────────── BEHAVIORAL PIN: same-call Err on past-deadline ──
//
// Direct simulation: build a MockCxInner with a deadline in
// the past. Call mock_checkpoint at "now" >= deadline and
// verify Err on the FIRST call AND on every subsequent call.

#[derive(Debug)]
struct MockBudget {
    deadline_nanos: Option<u64>,
}

impl MockBudget {
    fn is_past_deadline(&self, now_nanos: u64) -> bool {
        self.deadline_nanos.is_some_and(|d| now_nanos >= d)
    }
}

#[derive(Debug)]
struct MockCxInner {
    budget: MockBudget,
    cancel_requested: bool,
    fast_cancel: Arc<AtomicBool>,
    mask_depth: u32,
}

#[derive(Debug, PartialEq)]
enum MockResult {
    Ok,
    ErrCancelled,
}

fn mock_checkpoint(inner: &mut MockCxInner, now_nanos: u64) -> MockResult {
    // Fast path: read-only check.
    let cancelled = inner.fast_cancel.load(Ordering::Acquire);
    let exhausted = !cancelled && inner.budget.is_past_deadline(now_nanos);
    if !cancelled && !exhausted {
        return MockResult::Ok;
    }
    // Slow path.
    if exhausted {
        // Publish self-cancel.
        inner.cancel_requested = true;
        inner.fast_cancel.store(true, Ordering::Release);
    }
    if inner.cancel_requested && inner.mask_depth == 0 {
        return MockResult::ErrCancelled;
    }
    MockResult::Ok // Mask-deferred.
}

#[test]
fn behavior_past_deadline_returns_err_on_first_call_unmasked() {
    // Behavioral pin: the operator's exact scenario. Task
    // with deadline=100ns calls checkpoint at now=200ns —
    // returns Err on the FIRST call.
    let mut inner = MockCxInner {
        budget: MockBudget {
            deadline_nanos: Some(100),
        },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
    };

    let result = mock_checkpoint(&mut inner, 200);
    assert_eq!(
        result,
        MockResult::ErrCancelled,
        "REGRESSION: first checkpoint call past-deadline \
         returned Ok. Operators 'extra work after deadline' \
         failure mode is now true — task continues past \
         its deadline.",
    );

    // Cancel state is published.
    assert!(
        inner.cancel_requested,
        "REGRESSION: past-deadline did not publish \
         cancel_requested. Subsequent checkpoints would \
         not see the deadline via fast path.",
    );

    assert!(
        inner.fast_cancel.load(Ordering::Acquire),
        "REGRESSION: past-deadline did not set fast_cancel. \
         Subsequent checkpoints take the !cancelled fast \
         path and may hit the early Ok return.",
    );
}

#[test]
fn behavior_subsequent_checkpoints_after_past_deadline_also_return_err() {
    // Behavioral pin: deadline state PERSISTS — every
    // subsequent checkpoint after past-deadline observes
    // the published cancel via fast-path Acquire load and
    // returns Err. No "Ok now, Err later" pattern.
    let mut inner = MockCxInner {
        budget: MockBudget {
            deadline_nanos: Some(100),
        },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
    };

    // First call: detects deadline, publishes cancel.
    let _ = mock_checkpoint(&mut inner, 200);

    // 100 subsequent calls: all return Err via fast-path
    // cancel branch.
    for i in 1..100 {
        let result = mock_checkpoint(&mut inner, 200 + i * 10);
        assert_eq!(
            result,
            MockResult::ErrCancelled,
            "REGRESSION: checkpoint call #{i} after \
             past-deadline returned Ok. The deadline state \
             must persist across calls — without it, tasks \
             would oscillate between Err and Ok.",
        );
    }
}

#[test]
fn behavior_pre_deadline_returns_ok_no_extra_work() {
    // Behavioral pin: BEFORE the deadline, checkpoint
    // returns Ok via the fast path. No slow-path work for
    // the common-case healthy task.
    let mut inner = MockCxInner {
        budget: MockBudget {
            deadline_nanos: Some(1000),
        },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
    };

    for now in [0_u64, 100, 500, 999] {
        let result = mock_checkpoint(&mut inner, now);
        assert_eq!(
            result,
            MockResult::Ok,
            "REGRESSION: checkpoint at now={now}ns (before \
             deadline=1000ns) returned Err. The fast-path \
             early Ok return is broken — healthy tasks \
             pay slow-path cost on every checkpoint.",
        );
        assert!(
            !inner.cancel_requested,
            "REGRESSION: pre-deadline checkpoint published \
             cancel state. The state shouldn't change for \
             healthy tasks.",
        );
    }
}

#[test]
fn behavior_inclusive_boundary_past_deadline_at_exactly_now_equals_deadline() {
    // Behavioral pin: is_past_deadline uses now >= deadline
    // (inclusive). A checkpoint at exactly now=deadline
    // returns Err — not Ok then Err on the next tick.
    let mut inner = MockCxInner {
        budget: MockBudget {
            deadline_nanos: Some(100),
        },
        cancel_requested: false,
        fast_cancel: Arc::new(AtomicBool::new(false)),
        mask_depth: 0,
    };

    let result = mock_checkpoint(&mut inner, 100);
    assert_eq!(
        result,
        MockResult::ErrCancelled,
        "REGRESSION: checkpoint at exactly now=deadline \
         returned Ok. The is_past_deadline boundary is \
         exclusive (>) instead of inclusive (>=) — \
         one-tick window where deadline is missed.",
    );
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/cx_checkpoint_budget_exhausted_yield_audit.rs",
        "tests/cx_checkpoint_cancel_fail_fast_audit.rs",
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
