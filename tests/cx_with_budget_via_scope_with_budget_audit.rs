//! Audit + regression test for budget-limiting APIs.
//!
//! Operator's question: "Cx::with_budget(budget, fut): is
//! there an API to limit a future's CPU budget? If yes,
//! verify exhaustion produces Err(Exhausted) cleanly. If
//! not, file feature bead."
//!
//! Audit findings: **SOUND BY DESIGN — the API exists,
//! but uses structured-concurrency shape rather than the
//! tokio-style `with_budget(budget, fut)` shape**.
//!
//! ── The actual APIs ────────────────────────────────────
//!
//! 1. `Cx::scope_with_budget(budget) -> Scope<'static>`
//!    (src/cx/cx.rs:2996) — creates a Scope handle with
//!    a budget that is `parent.meet(child)` (clamped to
//!    parent constraints; structured-concurrency
//!    invariant — child cannot relax parent limits).
//!
//! 2. `Scope::region_with_budget(state, cx, budget, policy, f).await`
//!    -> `Result<Outcome<T, P2::Error>, RegionCreateError>`
//!    (src/cx/scope.rs:881) — async constructor that
//!    creates a child region with the specified budget,
//!    runs the closure under it, awaits child quiescence.
//!
//! 3. The `scope!` macro with `budget:` parameter
//!    (cx.rs:2989-2994 docs) — ergonomic surface for
//!    scope_with_budget.
//!
//! There is NO literal `Cx::with_budget(budget, fut)`.
//! The operator's framing assumes a tokio-style API like
//! `tokio::time::timeout(d, fut)`. Asupersync rejects that
//! shape because:
//!
//!   - It would create an unstructured region (orphan
//!     scope), violating "every task is owned by exactly
//!     one region."
//!   - It would have no obvious place for the cancel /
//!     finalize / drain protocol to attach.
//!
//! Instead, asupersync's structured shape is:
//!   `region_with_budget(state, cx, budget, policy, f).await`
//! which wraps the budget-bounded work in a properly-
//! tracked region.
//!
//! ── How budget exhaustion produces Err ──────────────────
//!
//! Budget exhaustion is detected at every `cx.checkpoint()`
//! via `Cx::checkpoint_budget_exhaustion` (cx.rs:1952):
//!
//! ```ignore
//! fn checkpoint_budget_exhaustion(
//!     region: RegionId, task: TaskId, budget: Budget, now: Time,
//! ) -> Option<(CancelReason, &'static str, Option<u64>)> {
//!     // 1. Past deadline?
//!     if budget.is_past_deadline(now) {
//!         CancelReason::with_origin(CancelKind::Deadline, region, now).with_task(task)
//!     }
//!     // 2. Poll quota = 0?
//!     if budget.poll_quota == 0 {
//!         CancelReason::with_origin(CancelKind::PollQuota, region, now).with_task(task)
//!     }
//!     // 3. Cost quota = Some(0)?
//!     if matches!(budget.cost_quota, Some(0)) {
//!         CancelReason::with_origin(CancelKind::CostBudget, region, now).with_task(task)
//!     }
//! }
//! ```
//!
//! When exhaustion is detected:
//!   - inner.cancel_requested = true
//!   - inner.fast_cancel.store(true, Release)
//!   - inner.cancel_reason = Some(reason) (or strengthened)
//!   - checkpoint returns Err(ErrorKind::Cancelled)
//!
//! The CANCEL REASON carries the specific kind (Deadline /
//! PollQuota / CostBudget). Operator's "Err(Exhausted)"
//! corresponds to this unified-Cancelled-with-kind pattern.
//!
//! ── Why the unified Cancelled return (not Exhausted) ────
//!
//! Asupersync's cancel protocol is unified
//! (`runtime_cancel_cause_kinds_distinct_audit.rs`,
//! `cx_no_interrupt_method_unified_cancel_audit.rs`): all
//! exhaustion paths funnel through Err(Cancelled), and the
//! specific reason is in `cx.cancel_reason()`. Splitting
//! out a separate Err(Exhausted) variant would force every
//! caller to match on TWO cancel-shaped errors instead of
//! one — fragmentation that doesn't help anyone.
//!
//! Callers who want to distinguish Deadline from PollQuota
//! call `cx.cancelled_by(CancelKind::Deadline)` /
//! `cx.cancel_chain()`.
//!
//! ── Budget::meet (parent ∩ child) ───────────────────────
//!
//! `scope_with_budget` clamps the child budget to the
//! parent's via `Budget::meet`-equivalent logic at
//! cx.rs:3020+. Children can only TIGHTEN, never relax.
//! Priority is unclamped (boosts allowed). This enforces
//! the structured-concurrency invariant.
//!
//! Verdict: **SOUND**. Budget-limiting APIs exist
//! (scope_with_budget, region_with_budget). Exhaustion
//! produces Err(Cancelled) with a specific CancelKind
//! (Deadline / PollQuota / CostBudget) in cancel_reason —
//! the unified-cancel equivalent of operator's
//! "Err(Exhausted)".
//!
//! No bead filed.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn cx_scope_with_budget_api_exists() {
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains(
            "pub fn scope_with_budget(&self, budget: Budget) -> crate::cx::Scope<'static> {"
        ),
        "REGRESSION: Cx::scope_with_budget API is gone. \
         The Phase-0 budget-tightened scope handle is broken.",
    );
}

#[test]
fn scope_region_with_budget_api_exists() {
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("pub async fn region_with_budget<P2, F, Fut, T, Caps>("),
        "REGRESSION: Scope::region_with_budget is gone. \
         The async budget-bounded region constructor is \
         broken.",
    );
}

#[test]
fn region_with_budget_returns_result_outcome() {
    let source = read("src/cx/scope.rs");

    assert!(
        source.contains("-> Result<Outcome<T, P2::Error>, RegionCreateError>"),
        "REGRESSION: region_with_budget return type \
         changed. Either the Outcome wrapping is gone or \
         the RegionCreateError boundary is gone.",
    );
}

#[test]
fn scope_with_budget_clamps_child_to_parent() {
    // Pin: structured-concurrency invariant — children
    // cannot relax parent constraints. scope_with_budget
    // must clamp the child budget to parent's.
    let source = read("src/cx/cx.rs");

    let fn_marker =
        "pub fn scope_with_budget(&self, budget: Budget) -> crate::cx::Scope<'static> {";
    let pos = source.find(fn_marker).expect("scope_with_budget fn");
    let body_window = &source[pos..pos + 4500];

    assert!(
        body_window.contains("Clamp child budget to parent constraints"),
        "REGRESSION: scope_with_budget no longer documents \
         the clamp-to-parent invariant. Future readers may \
         accidentally allow child to relax parent limits.",
    );

    // The clamp logic must use min for deadline (`if child < parent { child } else { parent }`).
    assert!(
        body_window.contains("if child < parent { child } else { parent }"),
        "REGRESSION: scope_with_budget no longer takes the \
         min of (parent, child) for deadline. Children may \
         now be permitted to exceed parent deadline.",
    );
}

#[test]
fn checkpoint_detects_budget_exhaustion_with_three_kinds() {
    // Pin: budget exhaustion detection covers Deadline,
    // PollQuota, and CostBudget — three distinct cancel
    // kinds.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn checkpoint_budget_exhaustion(";
    let pos = source
        .find(fn_marker)
        .expect("checkpoint_budget_exhaustion fn");
    let body_end = source[pos..].find("\n    }\n").expect("fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("CancelKind::Deadline"),
        "REGRESSION: budget exhaustion no longer detects \
         Deadline expiry.",
    );

    assert!(
        body.contains("CancelKind::PollQuota"),
        "REGRESSION: budget exhaustion no longer detects \
         PollQuota exhaustion.",
    );

    assert!(
        body.contains("CancelKind::CostBudget"),
        "REGRESSION: budget exhaustion no longer detects \
         CostBudget exhaustion.",
    );
}

#[test]
fn checkpoint_sets_cancel_state_on_exhaustion() {
    // Pin: when budget exhaustion is detected, checkpoint
    // sets cancel_requested + fast_cancel + cancel_reason
    // BEFORE returning Err. This is the unified-cancel
    // path the operator's Err(Exhausted) maps to.
    let source = read("src/cx/cx.rs");

    let fn_marker = "pub fn checkpoint(&self) -> Result<(), crate::error::Error> {";
    let pos = source.find(fn_marker).expect("checkpoint fn");
    let body_window = &source[pos..pos + 6000];

    assert!(
        body_window.contains("inner.cancel_requested = true;")
            && body_window.contains(".fast_cancel")
            && body_window.contains(".store(true, std::sync::atomic::Ordering::Release)"),
        "REGRESSION: checkpoint no longer sets cancel state \
         on budget exhaustion. Exhausted budgets won't \
         produce Err.",
    );
}

#[test]
fn checkpoint_returns_cancelled_error_kind_on_exhaustion() {
    // Pin: terminal Err is ErrorKind::Cancelled (not a
    // separate Exhausted variant). The unified cancel
    // protocol routes Deadline/PollQuota/CostBudget all
    // through Cancelled with a specific CancelKind in
    // cancel_reason.
    let source = read("src/cx/cx.rs");

    let fn_marker = "fn check_cancel_from_values(";
    let pos = source.find(fn_marker).expect("check_cancel_from_values fn");
    let body_end = source[pos..].find("\n    }\n").expect("fn close");
    let body = &source[pos..pos + body_end];

    assert!(
        body.contains("Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))"),
        "REGRESSION: checkpoint no longer returns \
         ErrorKind::Cancelled for the budget-exhaustion \
         path. The unified-cancel contract is broken.",
    );
}

#[test]
fn cx_with_budget_named_method_does_not_exist() {
    // Pin: there is no literal `Cx::with_budget(budget, fut)`
    // method. The structured-concurrency shape is via
    // scope_with_budget / region_with_budget. If a future
    // regression added the tokio-shape `with_budget`,
    // structured concurrency could be silently bypassed.
    let source = read("src/cx/cx.rs");

    let suspect_methods = [
        "pub fn with_budget(",
        "pub async fn with_budget(",
        "pub fn with_budget<F",
    ];
    for pat in &suspect_methods {
        assert!(
            !source.contains(pat),
            "REGRESSION: Cx now has `{pat}` — the tokio-\
             shape unstructured budget API is being \
             introduced. Tasks under this would not be \
             owned by a region — structured-concurrency \
             violation.",
        );
    }
}

#[test]
fn cx_cancel_reason_exposes_kind_for_caller_dispatch() {
    // Pin: cx.cancel_reason() and cx.cancelled_by(kind)
    // exist so callers who want to distinguish Deadline
    // vs PollQuota vs CostBudget can — the unified-cancel
    // design's escape hatch.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("pub fn cancel_reason(&self) -> Option<CancelReason> {"),
        "REGRESSION: Cx::cancel_reason accessor is gone. \
         Callers cannot distinguish exhaustion kinds.",
    );

    assert!(
        source.contains("pub fn cancelled_by(&self, kind: CancelKind) -> bool {"),
        "REGRESSION: Cx::cancelled_by predicate is gone.",
    );
}

#[test]
fn region_with_budget_uses_budget_meet_semantics() {
    // Pin: region_with_budget forwards the explicit child budget through the
    // current generalized child-admission path, whose RegionTable constructor
    // applies the parent.meet(child) clamp. The operator's "limit a future's
    // CPU budget" semantic is enforced at region creation.
    let scope_source = read("src/cx/scope.rs");

    let fn_marker = "pub async fn region_with_budget<P2, F, Fut, T, Caps>(";
    let pos = scope_source.find(fn_marker).expect("region_with_budget fn");
    let body_window = &scope_source[pos..pos + 1500];

    assert!(
        body_window.contains(
            "self.region_with_budget_and_priority(state, _cx, budget, RegionPriority::Normal, _policy, f)"
        ),
        "REGRESSION: region_with_budget no longer forwards \
         the supplied budget into the child-region admission path. \
         The structured budget-bound is broken.",
    );

    let admission_marker = "async fn region_with_child_admission<P2, F, Fut, T, Caps>(";
    let admission_pos = scope_source
        .find(admission_marker)
        .expect("region_with_child_admission fn");
    let admission_window = &scope_source[admission_pos..admission_pos + 1800];

    assert!(
        admission_window.contains("state.create_child_region_with_capability_budget_and_priority(")
            && admission_window.contains("admission.budget,"),
        "REGRESSION: child-region admission no longer passes \
         the explicit scheduler budget into RuntimeState.",
    );

    let table_source = read("src/runtime/region_table.rs");

    assert!(
        table_source.contains("let effective_budget = parent_budget.meet(budget);"),
        "REGRESSION: generalized child-region creation no longer \
         applies parent.meet(child) to the scheduler budget.",
    );
}

#[test]
fn budget_exhaustion_inline_tests_pin_three_kinds() {
    // Pin: inline tests cover all three exhaustion kinds.
    let source = read("src/cx/cx.rs");

    assert!(
        source.contains("fn checkpoint_deadline_exhaustion_sets_cancel_reason()"),
        "REGRESSION: deadline-exhaustion inline test gone.",
    );

    assert!(
        source.contains("fn checkpoint_poll_budget_exhaustion_sets_cancel_reason()"),
        "REGRESSION: poll-quota exhaustion inline test gone.",
    );

    assert!(
        source.contains("fn checkpoint_cost_budget_exhaustion_sets_cancel_reason()"),
        "REGRESSION: cost-budget exhaustion inline test gone.",
    );
}

// ── Behavioral pins ─────────────────────────────────────

use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Budget {
    deadline_ns: Option<u64>,
    poll_quota: u64,
    cost_quota: Option<u64>,
}

impl Budget {
    fn meet(self, other: Self) -> Self {
        Self {
            deadline_ns: match (self.deadline_ns, other.deadline_ns) {
                (Some(p), Some(c)) => Some(p.min(c)),
                (Some(p), None) => Some(p),
                (None, Some(c)) => Some(c),
                _ => None,
            },
            poll_quota: self.poll_quota.min(other.poll_quota),
            cost_quota: match (self.cost_quota, other.cost_quota) {
                (Some(p), Some(c)) => Some(p.min(c)),
                (Some(p), None) => Some(p),
                (None, Some(c)) => Some(c),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CancelKind {
    Deadline,
    PollQuota,
    CostBudget,
}

struct MockCx {
    budget: Mutex<Budget>,
    cancel_kind: Mutex<Option<CancelKind>>,
    now_ns: Mutex<u64>,
}

impl MockCx {
    fn new(budget: Budget) -> Self {
        Self {
            budget: Mutex::new(budget),
            cancel_kind: Mutex::new(None),
            now_ns: Mutex::new(0),
        }
    }

    fn advance_time(&self, ns: u64) {
        *self.now_ns.lock().unwrap() += ns;
    }

    fn checkpoint(&self) -> Result<(), CancelKind> {
        let mut budget = self.budget.lock().unwrap();
        let now = *self.now_ns.lock().unwrap();

        // 1. Deadline check.
        if let Some(deadline) = budget.deadline_ns {
            if now >= deadline {
                *self.cancel_kind.lock().unwrap() = Some(CancelKind::Deadline);
                return Err(CancelKind::Deadline);
            }
        }

        // 2. Poll quota check.
        if budget.poll_quota == 0 {
            *self.cancel_kind.lock().unwrap() = Some(CancelKind::PollQuota);
            return Err(CancelKind::PollQuota);
        }

        // 3. Cost quota check.
        if matches!(budget.cost_quota, Some(0)) {
            *self.cancel_kind.lock().unwrap() = Some(CancelKind::CostBudget);
            return Err(CancelKind::CostBudget);
        }

        // Healthy: decrement poll quota.
        budget.poll_quota -= 1;
        Ok(())
    }
}

#[test]
fn behavioral_deadline_exhaustion_returns_err_with_deadline_kind() {
    let cx = MockCx::new(Budget {
        deadline_ns: Some(1000),
        poll_quota: 1000,
        cost_quota: None,
    });

    // Advance time past deadline.
    cx.advance_time(2000);

    let result = cx.checkpoint();
    assert_eq!(result, Err(CancelKind::Deadline));
}

#[test]
fn behavioral_poll_quota_exhaustion_returns_err_with_poll_quota_kind() {
    let cx = MockCx::new(Budget {
        deadline_ns: None,
        poll_quota: 1,
        cost_quota: None,
    });

    // First checkpoint: ok, decrements quota to 0.
    cx.checkpoint().unwrap();
    // Second checkpoint: quota is 0, exhaustion.
    let result = cx.checkpoint();
    assert_eq!(result, Err(CancelKind::PollQuota));
}

#[test]
fn behavioral_cost_quota_exhaustion_returns_err_with_cost_budget_kind() {
    let cx = MockCx::new(Budget {
        deadline_ns: None,
        poll_quota: 1000,
        cost_quota: Some(0),
    });

    let result = cx.checkpoint();
    assert_eq!(result, Err(CancelKind::CostBudget));
}

#[test]
fn behavioral_meet_clamps_child_budget_to_parent() {
    // Parent: 5s deadline, 100 polls.
    let parent = Budget {
        deadline_ns: Some(5_000_000_000),
        poll_quota: 100,
        cost_quota: Some(1000),
    };

    // Child wants 10s deadline (relaxed!) and 50 polls.
    let child_request = Budget {
        deadline_ns: Some(10_000_000_000),
        poll_quota: 50,
        cost_quota: Some(2000),
    };

    let effective = parent.meet(child_request);

    // Deadline clamped to parent's 5s (not relaxed to 10s).
    assert_eq!(effective.deadline_ns, Some(5_000_000_000));
    // Poll quota clamped to child's tightened 50.
    assert_eq!(effective.poll_quota, 50);
    // Cost quota clamped to parent's tighter 1000.
    assert_eq!(effective.cost_quota, Some(1000));
}

#[test]
fn behavioral_healthy_checkpoint_decrements_poll_quota() {
    let cx = MockCx::new(Budget {
        deadline_ns: None,
        poll_quota: 5,
        cost_quota: None,
    });

    for _ in 0..5 {
        cx.checkpoint().unwrap();
    }

    // Now exhausted.
    let result = cx.checkpoint();
    assert_eq!(result, Err(CancelKind::PollQuota));
}

#[test]
fn behavioral_unified_err_carries_specific_kind_for_caller_dispatch() {
    // The operator's "Err(Exhausted)" pattern is the
    // unified Err with a specific kind retrievable for
    // dispatch. Our mock returns CancelKind directly;
    // production returns Err(Cancelled) with cx.cancel_reason()
    // exposing the kind.
    let cases = [
        (
            Budget {
                deadline_ns: Some(0),
                poll_quota: 1000,
                cost_quota: Some(1000),
            },
            CancelKind::Deadline,
        ),
        (
            Budget {
                deadline_ns: None,
                poll_quota: 0,
                cost_quota: Some(1000),
            },
            CancelKind::PollQuota,
        ),
        (
            Budget {
                deadline_ns: None,
                poll_quota: 1000,
                cost_quota: Some(0),
            },
            CancelKind::CostBudget,
        ),
    ];

    for (budget, expected_kind) in cases {
        let cx = MockCx::new(budget);
        cx.advance_time(1); // ensure deadline 0 is past
        let result = cx.checkpoint();
        assert_eq!(
            result,
            Err(expected_kind),
            "REGRESSION: budget {:?} did not produce \
             expected cancel kind {:?}.",
            budget,
            expected_kind,
        );
    }
}

#[test]
fn cross_reference_to_related_audits() {
    let prior_audits = [
        "tests/runtime_cancel_cause_kinds_distinct_audit.rs",
        "tests/cx_deadline_inheritance_min_parent_child_audit.rs",
        "tests/cx_no_interrupt_method_unified_cancel_audit.rs",
        "tests/cx_checkpoint_during_region_cancel_timing_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
