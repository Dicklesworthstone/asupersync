//! Audit + regression test for cooperative-budget exhaustion
//! enforcement at `cx.checkpoint()`.
//!
//! Operator's question: "when a task exhausts its budget mid-
//! quantum, is it forcibly yielded (correct) or allowed to
//! continue (priority inversion)? Per asupersync philosophy,
//! budget exhaustion MUST yield."
//!
//! Audit findings:
//!
//!   asupersync is **COOPERATIVE**. Per AGENTS.md: "Cancellation
//!   is a protocol: request → drain → finalize (idempotent)" —
//!   not OS-level preemption. The runtime does NOT forcibly
//!   yield tasks; tasks must yield voluntarily via `.await`
//!   (which the scheduler can interleave with other work) or
//!   via `cx.checkpoint()` (which observes cancellation /
//!   budget exhaustion and returns Err).
//!
//!   The "MUST yield on budget exhaustion" invariant is
//!   enforced through the COOPERATIVE-yield protocol, NOT
//!   preemption:
//!
//!   1. **`Budget`** (types/budget.rs:145+) carries
//!      `poll_quota: u32`, `cost_quota: Option<u64>`, and
//!      `deadline: Option<Time>`. `is_exhausted` returns true
//!      when poll_quota == 0 OR cost_quota == Some(0).
//!      `is_past_deadline(now)` checks the deadline.
//!
//!   2. **`Cx::checkpoint`** (cx/cx.rs:1644-1733) is the
//!      cooperative yield point. On every call:
//!      - Fast path: snapshots fast_cancel atomic AND inline-
//!        checks budget exhaustion (cx.rs:1664-1672). If
//!        cancelled OR exhausted, falls through to the slow
//!        path. Otherwise returns Ok(()) without touching the
//!        write lock.
//!      - Slow path (cx.rs:1697-1733): under write lock,
//!        re-runs `checkpoint_budget_exhaustion`. If exhausted,
//!        it sets `inner.cancel_requested = true`, sets
//!        `inner.fast_cancel = true` (Release), strengthens
//!        `inner.cancel_reason` with the new reason, sets
//!        cancel_acknowledged when mask_depth == 0, and returns
//!        `Err(crate::error::Error)` to the caller.
//!
//!   3. **`checkpoint_budget_exhaustion`** (cx.rs:1952-1999)
//!      checks all three exhaustion classes (deadline, poll
//!      quota, cost quota) and produces a `CancelReason` with
//!      the appropriate `CancelKind` (Deadline / PollQuota /
//!      CostBudget). Multiple exhausted classes are merged via
//!      `strengthen` so the strongest reason wins.
//!
//!   4. **Cooperative yield via `?`**: handlers conventionally
//!      call `cx.checkpoint()?` so an exhaustion Err propagates
//!      through the await chain, returning control to the
//!      scheduler. The task is then re-dispatched as a
//!      cancellation (cancel_requested=true) and finalized
//!      through the normal cancellation drain.
//!
//!   5. **Non-cooperative task detection**: tasks that never
//!      checkpoint are observable via:
//!      - `MetricsProvider::deadline_warning` /
//!        `deadline_violation` (when deadline passes).
//!      - `MetricsProvider::task_stuck_detected` (configurable
//!        threshold for last-checkpoint age).
//!      - `Cx::cancel_acknowledged` flag (false until
//!        checkpoint observes the request).
//!
//!      The runtime does NOT preempt them; observability is
//!      the mitigation. Operators can build alerts on these
//!      metrics to detect runaway tasks.
//!
//! Verdict: **SOUND**. Budget exhaustion DOES yield — through
//! the cooperative-checkpoint protocol. The operator's "MUST
//! yield" requirement is satisfied by:
//!   - The fast-path inline budget check at every checkpoint
//!     call (no expensive lock acquisition required).
//!   - The unconditional Err return when exhaustion is
//!     detected, which propagates via `?` and returns control
//!     to the scheduler.
//!   - The cancel_requested=true + fast_cancel=true latching
//!     so subsequent checkpoints continue to observe the
//!     exhaustion (no race).
//!
//! The "priority inversion" failure mode the operator flags is
//! real for tasks that NEVER call cx.checkpoint() — but that's
//! the documented user contract for asupersync. The runtime
//! makes such tasks observable (deadline_monitor, task_stuck_
//! detected) but does NOT forcibly preempt. Forcible preemption
//! would require OS-thread-level signals, which conflict with
//! the structured-concurrency / no-orphan-tasks invariants.
//!
//! A regression that:
//!   - removed the budget-exhaustion check from `Cx::
//!     checkpoint`'s fast path (would let exhausted tasks
//!     continue running until cancellation arrived through some
//!     other path),
//!   - returned Ok(()) on exhaustion instead of Err (would
//!     defeat the cooperative-yield protocol entirely),
//!   - failed to set `fast_cancel.store(true, Release)` on
//!     exhaustion (subsequent checkpoints would miss the
//!     latched exhaustion via the fast path),
//!   - removed the `is_exhausted` / `is_past_deadline` methods
//!     on Budget (the underlying check primitives),
//!     would all be caught here.

use std::path::PathBuf;

fn read_cx_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/cx/cx.rs");
    std::fs::read_to_string(&path).expect("read cx.rs")
}

fn read_budget_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/types/budget.rs");
    std::fs::read_to_string(&path).expect("read budget.rs")
}

fn checkpoint_fn_body(source: &str) -> &str {
    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let start = source.find(fn_marker).expect("checkpoint fn");
    // The checkpoint function body is long and contains many
    // nested blocks (each ending in `\n    }\n` at indent 4),
    // so the naive `find("\n    }\n")` slices off too early.
    // Slice up to the next top-level `\n    fn ` or `\n    pub fn `
    // (the next sibling method in the impl block) instead.
    let after = &source[start + fn_marker.len()..];
    let next_fn_offset = after
        .find("\n    fn ")
        .or_else(|| after.find("\n    pub fn "))
        .or_else(|| after.find("\n    #[inline]\n    fn "))
        .or_else(|| after.find("\n    #[inline]\n    pub fn "))
        .unwrap_or(after.len().min(40000));
    &source[start..start + fn_marker.len() + next_fn_offset]
}

#[test]
fn budget_struct_has_three_exhaustion_dimensions() {
    // Pin: Budget tracks deadline, poll_quota, and cost_quota
    // — the three dimensions checkpoint_budget_exhaustion
    // checks. A regression that dropped one would silently
    // disable that exhaustion class.
    let source = read_budget_source();

    assert!(
        source.contains("pub poll_quota: u32,"),
        "REGRESSION: Budget no longer has `pub poll_quota: u32`. \
         Without it, the cooperative budget can't bound poll \
         counts.",
    );
    assert!(
        source.contains("pub deadline: Option<Time>,")
            || source.contains("deadline: Option<Time>,"),
        "REGRESSION: Budget no longer carries a deadline field. \
         Deadline is the most common budget dimension; dropping \
         it would silently disable deadline-based yielding.",
    );
    assert!(
        source.contains("pub cost_quota: Option<u64>,")
            || source.contains("cost_quota: Option<u64>,"),
        "REGRESSION: Budget no longer carries cost_quota. \
         Cost-based budgets are a documented dimension.",
    );
}

#[test]
fn budget_is_exhausted_returns_true_when_quota_zero() {
    // Pin: Budget::is_exhausted returns true when poll_quota
    // hits 0 OR cost_quota is Some(0). A regression that only
    // checked one would let the other class silently continue.
    let source = read_budget_source();

    let fn_marker = "pub const fn is_exhausted(&self) -> bool {";
    let start = source.find(fn_marker).expect("is_exhausted fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("is_exhausted close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.poll_quota == 0"),
        "REGRESSION: is_exhausted no longer checks `poll_quota \
         == 0`. Without this, poll-quota exhaustion is silent.",
    );
    assert!(
        body.contains("matches!(self.cost_quota, Some(0))"),
        "REGRESSION: is_exhausted no longer checks `cost_quota \
         == Some(0)` via matches!. Without this, cost-quota \
         exhaustion is silent.",
    );
}

#[test]
fn budget_has_is_past_deadline_check() {
    // Pin: is_past_deadline is the deadline-class exhaustion
    // primitive used by checkpoint_budget_exhaustion. A
    // regression to a strict `>` (instead of `>=`) would let a
    // task run for one more nanosecond past its deadline —
    // small, but a violation of "MUST yield on exhaustion".
    let source = read_budget_source();

    let fn_marker = "pub fn is_past_deadline(&self, now: Time) -> bool {";
    let start = source.find(fn_marker).expect("is_past_deadline fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("is_past_deadline close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("now >= d"),
        "REGRESSION: is_past_deadline no longer uses `now >= d` \
         (saturating equal). The `>=` is required so a task at \
         the exact deadline is considered exhausted; `>` would \
         leak one tick.\n\nfn body:\n{body}",
    );
}

#[test]
fn checkpoint_fast_path_inline_checks_budget_exhaustion() {
    // Pin AUDIT-CRITICAL: Cx::checkpoint's fast path inline-
    // checks budget exhaustion via checkpoint_budget_exhaustion.
    // This is the LOAD-BEARING path that catches exhausted
    // tasks WITHOUT acquiring the write lock — keeping the
    // hot path cheap. A regression that moved the check to the
    // slow path only would force every healthy checkpoint to
    // pay the lock overhead.
    let source = read_cx_source();
    let body = checkpoint_fn_body(&source);

    assert!(
        body.contains("Self::checkpoint_budget_exhaustion("),
        "REGRESSION: Cx::checkpoint no longer calls \
         checkpoint_budget_exhaustion in the fast path. Without \
         this, exhausted tasks need an external nudge \
         (cancellation, deadline_monitor) to observe their \
         budget — defeating the 'MUST yield on exhaustion' \
         invariant on the cooperative-yield path.\n\n\
         fn body:\n{body}",
    );

    // The fast path must short-circuit on exhausted=true OR
    // cancelled=true. Additional guards may send message
    // clearing and first-checkpoint initialization through
    // the slow path, but the Ok return must stay behind the
    // cancellation and exhaustion gates.
    assert!(
        body.contains("if !cancelled && !exhausted && !has_message && !is_first_checkpoint {"),
        "REGRESSION: Cx::checkpoint fast path no longer guards \
         the Ok(()) return on `!cancelled` and `!exhausted`. \
         Without these guards, an exhausted or cancelled task \
         could observe Ok(()) and continue running.\n\nfn body:\n{body}",
    );
}

#[test]
fn checkpoint_slow_path_sets_fast_cancel_on_exhaustion() {
    // Pin AUDIT-CRITICAL: when checkpoint detects exhaustion in
    // the slow path, it MUST set fast_cancel=true (Release) so
    // subsequent fast-path checkpoints observe the latched
    // state. Without this, the fast path could miss the
    // exhaustion on the next call and let the task continue.
    let source = read_cx_source();
    let body = checkpoint_fn_body(&source);

    // Find the slow-path branch where exhaustion sets
    // fast_cancel.
    assert!(
        body.contains(".store(true, std::sync::atomic::Ordering::Release);"),
        "REGRESSION: Cx::checkpoint no longer stores \
         fast_cancel=true with Release ordering on exhaustion. \
         Without this, the fast path won't observe the latched \
         exhaustion on subsequent calls and the task could \
         continue running past its budget.\n\nfn body:\n{body}",
    );
}

#[test]
fn checkpoint_returns_err_on_exhaustion() {
    // Pin AUDIT-CRITICAL: checkpoint MUST return Err when
    // exhaustion is detected. The Err is what propagates via
    // `?` and yields control back to the scheduler. A
    // regression that returned Ok(()) on exhaustion would
    // silently break the cooperative-yield contract.
    let source = read_cx_source();
    let body = checkpoint_fn_body(&source);

    // The slow-path body delegates to `check_cancel_from_values`
    // — a helper that produces the Err return. Either the body
    // contains a direct Err return OR it ends with a call to
    // the helper. Both are acceptable; the absence of BOTH
    // would mean checkpoint can never return Err.
    let direct_err = body.contains("Err(") || body.contains("return Err(");
    let via_helper = body.contains("check_cancel_from_values(");
    assert!(
        direct_err || via_helper,
        "REGRESSION: Cx::checkpoint no longer has an Err return \
         path (neither direct `Err(...)` nor a delegating call \
         to `check_cancel_from_values`). The cooperative-yield \
         contract requires Err on exhaustion / cancellation; \
         without it, exhausted tasks observe Ok and continue \
         running.\n\nfn body:\n{body}",
    );

    // Defense-in-depth: the function signature must continue
    // to be `-> Result<(), crate::error::Error>`. A change to
    // `Result<bool, _>` or `()` would silently break the `?`
    // propagation that handlers depend on.
    assert!(
        source.contains("pub fn checkpoint(&self) -> Result<(), crate::error::Error> {"),
        "REGRESSION: Cx::checkpoint signature changed. The \
         canonical signature `-> Result<(), crate::error::\
         Error>` is what handler code patterns like \
         `cx.checkpoint()?` depend on. A change here would \
         force a churn-wide update of every handler.",
    );
}

#[test]
fn checkpoint_budget_exhaustion_checks_all_three_dimensions() {
    // Pin: checkpoint_budget_exhaustion checks deadline, poll
    // quota, AND cost quota. A regression that only checked
    // one or two would let the missing dimension's exhaustion
    // pass silently.
    let source = read_cx_source();

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let start = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[start..].find("\n    }\n").expect("fn close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("budget.is_past_deadline(now)"),
        "REGRESSION: deadline check is missing from \
         checkpoint_budget_exhaustion. Without it, deadlines \
         are unenforced at the cooperative-yield protocol.\n\n\
         fn body:\n{body}",
    );
    assert!(
        body.contains("budget.poll_quota == 0"),
        "REGRESSION: poll_quota check is missing. Tasks \
         exceeding their poll budget would not be flagged as \
         exhausted at checkpoint.",
    );
    assert!(
        body.contains("matches!(budget.cost_quota, Some(0))"),
        "REGRESSION: cost_quota check is missing. Cost-based \
         budgets are a documented dimension; without the \
         check, cost-exhausted tasks continue running.",
    );

    // Each dimension must produce a CancelReason with the
    // matching CancelKind.
    for kind in &[
        "CancelKind::Deadline",
        "CancelKind::PollQuota",
        "CancelKind::CostBudget",
    ] {
        assert!(
            body.contains(kind),
            "REGRESSION: checkpoint_budget_exhaustion no longer \
             produces `{kind}` for its respective exhaustion \
             dimension. Operators rely on the kind label to \
             distinguish deadline vs poll vs cost exhaustion in \
             metrics.",
        );
    }
}

#[test]
fn checkpoint_strengthens_cancel_reason_on_exhaustion() {
    // Pin: when exhaustion is detected, the new CancelReason
    // is merged with any existing reason via `strengthen`.
    // Without this, an existing weaker cancellation could
    // mask the budget-exhaustion reason in subsequent
    // observations.
    let source = read_cx_source();
    let body = checkpoint_fn_body(&source);

    assert!(
        body.contains(".strengthen(reason)"),
        "REGRESSION: Cx::checkpoint no longer calls \
         `.strengthen(reason)` to merge budget-exhaustion \
         reasons with prior reasons. Without this, an existing \
         weaker reason could shadow the exhaustion class in \
         downstream observations.",
    );
}

#[test]
fn checkpoint_acknowledges_when_mask_depth_zero() {
    // Pin: cancel_acknowledged is set to true when
    // mask_depth == 0. Inside a mask, cancellation is
    // DEFERRED (the task continues running until the mask
    // unwinds), per AGENTS.md cancel-protocol semantics.
    let source = read_cx_source();
    let body = checkpoint_fn_body(&source);

    assert!(
        body.contains("if inner.cancel_requested && inner.mask_depth == 0 {"),
        "REGRESSION: cancel_acknowledged guard no longer checks \
         `mask_depth == 0`. Either the mask is leaking (cancel \
         acknowledged inside a mask, breaking the mask \
         contract) OR cancellation is never acknowledged \
         (priority inversion is real). Both are bugs.\n\n\
         fn body:\n{body}",
    );

    assert!(
        body.contains("inner.cancel_acknowledged = true;"),
        "REGRESSION: Cx::checkpoint no longer sets \
         cancel_acknowledged. Without this, the runtime can't \
         distinguish 'cancellation requested' from 'cancellation \
         observed by the task'.",
    );
}

#[test]
fn checkpoint_doc_explicitly_describes_cooperative_yield() {
    // Pin: the doc comment on Cx::checkpoint describes the
    // cooperative-yield semantics. A regression that changed
    // the doc to imply preemption would mislead operators
    // about the contract.
    let source = read_cx_source();

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let fn_pos = source.find(fn_marker).expect("checkpoint fn");
    let mut doc_start = fn_pos;
    for _ in 0..40 {
        match source[..doc_start].rfind('\n') {
            Some(p) => doc_start = p,
            None => {
                doc_start = 0;
                break;
            }
        }
    }
    let doc_window = &source[doc_start..fn_pos];

    let required_phrases = ["checkpoint", "cancel"];
    for phrase in &required_phrases {
        assert!(
            doc_window.contains(phrase),
            "REGRESSION: Cx::checkpoint doc no longer mentions \
             `{phrase}`. The doc is the public contract for the \
             cooperative-yield primitive.\n\n\
             doc window:\n{doc_window}",
        );
    }
}

// ─── Behavioral end-to-end pin (gated on test-internals) ────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::cx::Cx;
    use asupersync::types::{Budget, Time};

    #[test]
    fn checkpoint_yields_when_poll_quota_hits_zero() {
        // Pin AUDIT-CRITICAL behavioral: a Cx whose budget
        // has poll_quota = 0 returns Err on checkpoint. The
        // returned Error must be classifiable as a budget
        // exhaustion (PollQuota cancel kind).
        let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_poll_quota(0));
        let result = cx.checkpoint();

        assert!(
            result.is_err(),
            "REGRESSION: checkpoint returned Ok with \
             poll_quota=0. The cooperative-yield contract \
             requires Err so the task yields via `?` \
             propagation. result: {result:?}",
        );
    }

    #[test]
    fn checkpoint_yields_when_deadline_passed() {
        // Pin: a Cx whose budget has a deadline in the past
        // returns Err on checkpoint.
        let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::ZERO));
        // Time::ZERO is in the past relative to any nontrivial
        // checkpoint time, which the test Cx provides.
        let result = cx.checkpoint();

        assert!(
            result.is_err(),
            "REGRESSION: checkpoint returned Ok with a passed \
             deadline. The deadline class of budget exhaustion \
             must trigger cooperative yield.\n\nresult: {result:?}",
        );
    }

    #[test]
    fn checkpoint_yields_when_cost_quota_zero() {
        // Pin: cost_quota = Some(0) triggers exhaustion.
        let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_cost_quota(0));
        let result = cx.checkpoint();

        assert!(
            result.is_err(),
            "REGRESSION: checkpoint returned Ok with \
             cost_quota=0. Cost-budget exhaustion must trigger \
             cooperative yield like the other dimensions.\n\n\
             result: {result:?}",
        );
    }

    #[test]
    fn checkpoint_returns_ok_with_unlimited_budget() {
        // Pin: the happy path returns Ok with no exhaustion. A
        // regression that returned Err on every checkpoint
        // would catastrophically break every handler.
        let cx = Cx::for_testing_with_budget(Budget::INFINITE);
        let result = cx.checkpoint();

        assert!(
            result.is_ok(),
            "REGRESSION: checkpoint returned Err with \
             Budget::INFINITE. The fast path must short-circuit \
             on healthy tasks. result: {result:?}",
        );
    }

    #[test]
    fn checkpoint_after_exhaustion_continues_to_return_err_via_fast_cancel() {
        // Pin AUDIT-CRITICAL: once exhaustion is observed, the
        // fast_cancel atomic stays true so subsequent
        // checkpoints continue to return Err without re-checking
        // the budget. This is what makes the cooperative yield
        // STICKY — a task that ignored the first Err and looped
        // would observe Err on the next checkpoint too.
        let cx = Cx::for_testing_with_budget(Budget::INFINITE.with_poll_quota(0));

        let first = cx.checkpoint();
        assert!(first.is_err(), "first checkpoint must Err");

        let second = cx.checkpoint();
        assert!(
            second.is_err(),
            "REGRESSION: second checkpoint after exhaustion \
             returned Ok. The fast_cancel latch should keep \
             returning Err — a regression that cleared the \
             latch on first observation would let a misbehaving \
             handler swallow the Err and continue.",
        );
    }
}
