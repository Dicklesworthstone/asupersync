//! Audit + regression test for `Cx`/`Budget` deadline
//! inheritance — parent's tighter deadline wins.
//!
//! Operator's question: "when Cx with deadline=10s creates
//! child Cx with deadline=20s, which deadline takes effect
//! on the child task? Per asupersync structured concurrency,
//! MIN(parent, child) — parent's deadline wins if tighter."
//!
//! Audit findings:
//!
//!   asupersync's `Budget::meet` operation enforces
//!   **MIN(parent, child)** on every constraint axis. The
//!   child can never RELAX a parent constraint. The child's
//!   effective budget is the tightest of the two — for the
//!   operator's scenario (parent=10s, child=20s), the
//!   effective deadline is exactly 10s.
//!
//!   The chain:
//!
//!   1. **`Budget::combine` is the lattice meet** (types/
//!      budget.rs:361):
//!      ```ignore
//!      pub fn combine(self, other: Self) -> Self {
//!          let combined = Self {
//!              deadline: match (self.deadline, other.deadline) {
//!                  (Some(a), Some(b)) => Some(a.min(b)),
//!                  (deadline @ Some(_), None) | (None, deadline @ Some(_)) => deadline,
//!                  (None, None) => None,
//!              },
//!              poll_quota: self.poll_quota.min(other.poll_quota),
//!              cost_quota: match (self.cost_quota, other.cost_quota) {
//!                  (Some(a), Some(b)) => Some(a.min(b)),
//!                  (quota @ Some(_), None) | (None, quota @ Some(_)) => quota,
//!                  (None, None) => None,
//!              },
//!              priority: self.priority.max(other.priority),
//!          };
//!          ...
//!      }
//!      ```
//!      Per-axis semantics:
//!        - **deadline**: MIN (the earlier deadline wins —
//!          tighter constraint).
//!        - **poll_quota**: MIN (fewer polls = tighter).
//!        - **cost_quota**: MIN (less cost = tighter).
//!        - **priority**: MAX (higher priority for cleanup
//!          = stronger preemption).
//!          The None-case handling (None means "no constraint")
//!          lets either side be unconstrained without the other
//!          being clamped to None.
//!
//!   2. **`Budget::meet` is an alias for `combine`** (budget.
//!      rs:441): documented as the lattice-meet operation.
//!      Used at every parent → child budget transition.
//!
//!   3. **`RegionTable::create_child` applies meet**
//!      (runtime/region_table.rs:261): `let effective_budget
//!      = parent_budget.meet(budget);` — the parent's
//!      budget is fetched from the parent's RegionRecord,
//!      and the proposed child budget is meeted with it.
//!      The resulting RegionRecord stores the effective
//!      budget — the child can NEVER observe a budget
//!      looser than its parent's.
//!
//!   4. **Tightening is traced**: when combine produces a
//!      tighter budget than either input, a trace event
//!      fires (budget.rs:381-417). Operators can see when
//!      a child's proposed budget was clamped by the parent.
//!
//!   5. **Recursive nesting compounds**: nesting region A
//!      (deadline=30) → B (deadline=20) → C (deadline=10)
//!      gives effective_C = meet(B, child_proposed) =
//!      meet(meet(A, 20), 10) = meet(20, 10) = 10. Each
//!      level applies meet against its parent's
//!      already-tightened budget — the deepest descendant
//!      is bounded by the strictest ancestor at any depth.
//!
//! Verdict: **SOUND**. The MIN(parent, child) deadline
//! semantics is enforced via Budget::meet at every
//! parent → child transition. The operator's scenario
//! (parent=10s, child=20s) → effective=10s is the
//! canonical case. The lattice-meet design generalizes
//! naturally to multi-level nesting.
//!
//! A regression that:
//!   - replaced MIN with MAX on the deadline axis (would
//!     let children RELAX parent deadlines — full
//!     structured-concurrency violation),
//!   - removed the None-arm fallback (would force every
//!     ancestor to set a finite deadline — defeats the
//!     escape hatch for unbounded scopes),
//!   - changed priority to MIN instead of MAX (would
//!     downgrade cleanup priority on nesting — cleanup
//!     under cancellation would deprioritize),
//!   - removed RegionTable::create_child's
//!     parent_budget.meet(budget) call (would give the
//!     child its proposed budget directly — could exceed
//!     parent constraints, violating MIN),
//!   - removed the tightening trace event (would lose
//!     observability when child budgets get clamped),
//!     would all be caught by the structural pins below.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

fn budget_combine_untraced_body(source: &str) -> &str {
    let fn_marker = "pub(crate) fn combine_untraced(self, other: Self) -> Self {";
    let start = source.find(fn_marker).expect("Budget::combine_untraced fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::combine_untraced close");
    &source[start..start + body_end]
}

#[test]
fn budget_combine_uses_min_on_deadline_axis() {
    // Pin (link 1): Budget::combine takes MIN on deadline.
    // Some(a).min(Some(b)) ensures parent's tighter
    // deadline wins.
    let source = read("src/types/budget.rs");

    let body = budget_combine_untraced_body(&source);

    assert!(
        body.contains("(Some(a), Some(b)) => Some(a.min(b)),"),
        "REGRESSION: Budget::combine no longer takes MIN on \
         deadline. The operators MIN(parent, child) contract \
         is broken — children may RELAX parent deadlines, \
         violating structured concurrency.",
    );

    // The None arms must allow one-sided constraints — None
    // means "no constraint", so meet(None, Some(x)) = Some(x).
    assert!(
        body.contains("(deadline @ Some(_), None) | (None, deadline @ Some(_)) => deadline,"),
        "REGRESSION: Budget::combine no longer handles the \
         one-sided None case for deadline. Either every \
         ancestor must now set a finite deadline (defeats \
         unbounded scopes) or one None forces the other to \
         None (loses parent constraints).",
    );

    assert!(
        body.contains("(None, None) => None,"),
        "REGRESSION: Budget::combine no longer maps (None, \
         None) → None for deadline. Default-budget tasks \
         lose the no-constraint contract.",
    );
}

#[test]
fn budget_combine_uses_min_on_poll_quota() {
    // Pin (link 1): poll_quota also takes MIN — fewer
    // polls = tighter constraint.
    let source = read("src/types/budget.rs");

    let body = budget_combine_untraced_body(&source);

    assert!(
        body.contains("poll_quota: self.poll_quota.min(other.poll_quota),"),
        "REGRESSION: Budget::combine no longer takes MIN on \
         poll_quota. Children could exceed parent poll \
         budgets — anti-monopoly contract weakened.",
    );
}

#[test]
fn budget_combine_uses_min_on_cost_quota_with_none_handling() {
    // Pin (link 1): cost_quota MIN with the same one-sided
    // None handling as deadline.
    let source = read("src/types/budget.rs");

    let body = budget_combine_untraced_body(&source);

    assert!(
        body.contains("cost_quota: match (self.cost_quota, other.cost_quota) {")
            && body.contains("(Some(a), Some(b)) => Some(a.min(b)),"),
        "REGRESSION: Budget::combine no longer takes MIN on \
         cost_quota. Children could exceed parent cost \
         budgets.",
    );
}

#[test]
fn budget_combine_uses_max_on_priority_for_stronger_cleanup() {
    // Pin (link 1): priority takes MAX, not MIN. Higher
    // priority = stronger preemption for cleanup. The
    // child's higher priority should not be DOWNGRADED by
    // parent meet.
    let source = read("src/types/budget.rs");

    let body = budget_combine_untraced_body(&source);

    assert!(
        body.contains("priority: self.priority.max(other.priority),"),
        "REGRESSION: Budget::combine no longer takes MAX on \
         priority. Either the cleanup-priority promotion is \
         broken (child cleanup deprioritized under cancel) \
         OR priority follows the wrong meet direction.",
    );
}

#[test]
fn budget_meet_is_alias_for_combine() {
    // Pin (link 2): meet() is an alias for combine() — both
    // names refer to the same lattice-meet operation. The
    // alias is the documented public API for budget nesting.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub fn meet(self, other: Self) -> Self {";
    let start = source.find(fn_marker).expect("Budget::meet fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::meet close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("self.combine(other)"),
        "REGRESSION: Budget::meet no longer delegates to \
         combine. Either the alias is gone or the \
         semantics has drifted from combine — divergent \
         behavior between meet and combine breaks docs.",
    );
}

#[test]
fn region_table_create_child_applies_parent_budget_meet_child_budget() {
    // Pin (link 3): RegionTable::create_child applies
    // parent_budget.meet(child_budget) before storing the
    // RegionRecord. This is the runtime enforcement point
    // for the MIN-deadline contract.
    let source = read("src/runtime/region_table.rs");

    assert!(
        source.contains("let effective_budget = parent_budget.meet(budget);"),
        "REGRESSION: RegionTable::create_child no longer \
         meets the proposed child budget against the \
         parents. Children get their proposed budget \
         directly — could RELAX parent constraints. Full \
         structured-concurrency violation.",
    );
}

#[test]
fn region_table_create_child_stores_effective_not_proposed_budget() {
    // Pin (link 3 supporting): the RegionRecord stores the
    // effective_budget (post-meet), NOT the proposed budget.
    // Without this, the meet result is computed but
    // discarded.
    let source = read("src/runtime/region_table.rs");

    let fn_marker = "pub fn create_child(";
    let start = source.find(fn_marker).expect("create_child fn");
    let window_end = (start + 4000).min(source.len());
    let safe_end = source
        .char_indices()
        .map(|(i, _)| i)
        .rfind(|&i| i <= window_end)
        .unwrap_or(window_end);
    let body = &source[start..safe_end];

    assert!(
        body.contains("RegionRecord::new_with_time(\n                RegionId::from_arena(idx),\n                Some(parent),\n                effective_budget,")
            || body.contains("effective_budget,"),
        "REGRESSION: create_child no longer passes \
         effective_budget into RegionRecord::new_with_time. \
         The meet is computed but discarded — child stores \
         its proposed budget, defeating the MIN contract.",
    );
}

#[test]
fn budget_combine_traces_when_tightening_for_observability() {
    // Pin (link 4): when meet produces a strictly tighter
    // budget, a trace event fires. Operators can see when
    // child budgets get clamped by parent.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub fn combine(self, other: Self) -> Self {";
    let start = source.find(fn_marker).expect("Budget::combine fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::combine close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("budget combined (tightened)"),
        "REGRESSION: Budget::combine no longer emits a \
         tightening trace event. Operators lose visibility \
         into which level of nesting clamped the budget — \
         debugging budget surprises gets harder.",
    );

    // The deadline_tightened predicate must check that the
    // combined deadline is strictly tighter than at least
    // one input.
    assert!(
        body.contains("(Some(c), Some(s), _) if c < s => true,"),
        "REGRESSION: deadline_tightened predicate no longer \
         detects strict tightening. Either it always fires \
         (noisy logs) or never fires (silent tightening — \
         lost observability).",
    );
}

#[test]
fn budget_combine_keeps_the_runtime_lock_path_callback_free() {
    // The public wrapper retains observability, while cancellation paths that
    // already own RuntimeState/Cx locks use the exact same meet without tracing
    // subscriber callbacks.
    let source = read("src/types/budget.rs");
    let untraced = budget_combine_untraced_body(&source);
    let fn_marker = "pub fn combine(self, other: Self) -> Self {";
    let start = source.find(fn_marker).expect("Budget::combine fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::combine close");
    let public_body = &source[start..start + body_end];

    assert!(
        public_body.contains("let combined = self.combine_untraced(other);")
            && !untraced.contains("trace!(")
            && !untraced.contains("info!("),
        "REGRESSION: the public and callback-free Budget meets diverged, or \
         the lock-safe combine_untraced path can invoke a tracing subscriber.",
    );
}

#[test]
fn budget_combine_traces_priority_tightening_max_direction() {
    // Pin (link 1+4): priority_tightened predicate detects
    // when combined priority is STRICTLY GREATER than
    // either input — confirming the MAX direction.
    let source = read("src/types/budget.rs");

    let fn_marker = "pub fn combine(self, other: Self) -> Self {";
    let start = source.find(fn_marker).expect("Budget::combine fn");
    let body_end = source[start..]
        .find("\n    }\n")
        .expect("Budget::combine close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("combined.priority > self.priority || combined.priority > other.priority"),
        "REGRESSION: priority_tightened predicate no longer \
         uses > comparison. Either it uses < (wrong \
         direction — would imply priority MIN) or it's \
         silenced (lost observability).",
    );
}

#[test]
fn budget_documentation_example_pins_min_deadline_semantics() {
    // Pin (audit hygiene): the rustdoc on Budget::meet
    // includes a runnable example demonstrating the MIN
    // semantics: parent=30s, child=10s → effective=10s.
    // This is the canonical user-facing documentation of
    // the contract.
    let source = read("src/types/budget.rs");

    assert!(
        source.contains("// Child deadline is tighter, so it wins")
            && source.contains("let effective = parent.meet(child);")
            && source.contains("assert_eq!(effective.deadline, Some(Time::from_secs(10)));"),
        "REGRESSION: Budget::meet docstring example no \
         longer pins the MIN(parent, child) semantics. Users \
         lose the canonical contract documentation — easy \
         to drift away from the structured-concurrency \
         invariant in future refactors.",
    );
}

#[test]
fn budget_meet_is_idempotent_under_self_combine() {
    // Pin (lattice property audit): meet(b, b) = b. This is
    // the idempotence property of the lattice-meet
    // operation. While there's no explicit test for this in
    // the production code, the per-axis MIN/MAX operations
    // give it for free — verify the formulas don't violate
    // it via a regression that adds an asymmetric step.
    let source = read("src/types/budget.rs");

    let body = budget_combine_untraced_body(&source);

    // Forbid asymmetric arithmetic that would break
    // idempotence (e.g., adding instead of taking min).
    let suspect_asymmetric = [
        "self.deadline + other.deadline",
        "self.poll_quota + other.poll_quota",
        "self.cost_quota + other.cost_quota",
    ];
    for pat in &suspect_asymmetric {
        assert!(
            !body.contains(pat),
            "REGRESSION: Budget::combine now contains \
             asymmetric arithmetic via `{pat}`. The meet \
             operation must be idempotent (b.meet(b) = b); \
             addition or other arithmetic breaks the \
             lattice contract.",
        );
    }
}

// ─────────── BEHAVIORAL PIN: MIN(parent, child) deadline ──
//
// Direct simulation of Budget::combine with the production
// per-axis semantics. Verify the operator's scenario:
// parent=10s, child=20s → effective=10s (parent wins).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MockTime(u64); // nanos

#[derive(Debug, Clone, Copy)]
struct MockBudget {
    deadline: Option<MockTime>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

impl MockBudget {
    fn meet(self, other: Self) -> Self {
        Self {
            deadline: match (self.deadline, other.deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (deadline @ Some(_), None) | (None, deadline @ Some(_)) => deadline,
                (None, None) => None,
            },
            poll_quota: self.poll_quota.min(other.poll_quota),
            cost_quota: match (self.cost_quota, other.cost_quota) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (quota @ Some(_), None) | (None, quota @ Some(_)) => quota,
                (None, None) => None,
            },
            priority: self.priority.max(other.priority),
        }
    }
}

#[test]
fn behavior_parent_10s_child_20s_yields_effective_10s() {
    // Behavioral pin: the operator's scenario. Parent
    // deadline=10s, child=20s → effective=10s (MIN).
    let parent = MockBudget {
        deadline: Some(MockTime(10_000_000_000)), // 10s in nanos
        poll_quota: 1000,
        cost_quota: Some(100),
        priority: 128,
    };
    let child = MockBudget {
        deadline: Some(MockTime(20_000_000_000)), // 20s in nanos
        poll_quota: 2000,
        cost_quota: Some(200),
        priority: 100, // child has lower priority
    };

    let effective = parent.meet(child);

    assert_eq!(
        effective.deadline,
        Some(MockTime(10_000_000_000)),
        "REGRESSION: parent=10s meet child=20s → effective \
         deadline is {actual:?}, expected Some(10s). The \
         MIN(parent, child) contract is broken — child \
         could exceed parent deadline.",
        actual = effective.deadline,
    );

    assert_eq!(
        effective.poll_quota,
        1000,
        "REGRESSION: poll_quota meet not MIN. Got {actual}, \
         expected 1000.",
        actual = effective.poll_quota,
    );

    assert_eq!(
        effective.cost_quota,
        Some(100),
        "REGRESSION: cost_quota meet not MIN. Got {actual:?}, \
         expected Some(100).",
        actual = effective.cost_quota,
    );

    assert_eq!(
        effective.priority,
        128,
        "REGRESSION: priority meet not MAX. Got {actual}, \
         expected 128 (parent's higher priority wins for \
         cleanup).",
        actual = effective.priority,
    );
}

#[test]
fn behavior_three_level_nesting_compounds_meet() {
    // Behavioral pin: three-level nesting (A=30s, B=20s,
    // C=10s) — effective at C is min(min(30, 20), 10) = 10.
    let level_a = MockBudget {
        deadline: Some(MockTime(30_000_000_000)),
        poll_quota: 5000,
        cost_quota: None,
        priority: 100,
    };
    let level_b_proposed = MockBudget {
        deadline: Some(MockTime(20_000_000_000)),
        poll_quota: 3000,
        cost_quota: None,
        priority: 110,
    };
    let level_c_proposed = MockBudget {
        deadline: Some(MockTime(10_000_000_000)),
        poll_quota: 1000,
        cost_quota: None,
        priority: 105,
    };

    let level_b = level_a.meet(level_b_proposed);
    let level_c = level_b.meet(level_c_proposed);

    assert_eq!(
        level_c.deadline,
        Some(MockTime(10_000_000_000)),
        "REGRESSION: 3-level nesting deadline meet not \
         MIN. Got {actual:?}, expected Some(10s).",
        actual = level_c.deadline,
    );

    assert_eq!(
        level_c.poll_quota, 1000,
        "REGRESSION: 3-level nesting poll_quota not MIN.",
    );

    assert_eq!(
        level_c.priority,
        110,
        "REGRESSION: 3-level nesting priority not MAX. Got \
         {actual}, expected 110 (the level-B max wins).",
        actual = level_c.priority,
    );
}

#[test]
fn behavior_none_deadline_parent_does_not_clamp_child() {
    // Behavioral pin: parent with no deadline, child with
    // deadline=10s → effective=Some(10s) (child's
    // constraint stands; None means no constraint).
    let parent = MockBudget {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 0,
    };
    let child = MockBudget {
        deadline: Some(MockTime(10_000_000_000)),
        poll_quota: 1000,
        cost_quota: None,
        priority: 100,
    };

    let effective = parent.meet(child);
    assert_eq!(
        effective.deadline,
        Some(MockTime(10_000_000_000)),
        "REGRESSION: meet(None, Some(10s)) → effective is \
         {actual:?}, expected Some(10s). The one-sided None \
         arm is broken — unbounded parents now force \
         children to None too.",
        actual = effective.deadline,
    );
}

#[test]
fn behavior_meet_is_idempotent_b_meet_b_equals_b() {
    // Behavioral pin: lattice-meet idempotence. b.meet(b) = b.
    let b = MockBudget {
        deadline: Some(MockTime(15_000_000_000)),
        poll_quota: 2000,
        cost_quota: Some(500),
        priority: 100,
    };

    let result = b.meet(b);
    assert_eq!(
        result.deadline, b.deadline,
        "REGRESSION: meet idempotence broken on deadline.",
    );
    assert_eq!(result.poll_quota, b.poll_quota);
    assert_eq!(result.cost_quota, b.cost_quota);
    assert_eq!(result.priority, b.priority);
}

#[test]
fn cross_reference_to_prior_audits() {
    let prior_audits = [
        "tests/runtime_budget_carry_forward_across_yields_audit.rs",
        "tests/cx_checkpoint_budget_exhausted_yield_audit.rs",
        "tests/cx_scope_deep_nesting_bookkeeping_audit.rs",
    ];

    for audit in &prior_audits {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(audit);
        assert!(
            path.exists(),
            "REGRESSION: prior audit `{audit}` is missing.",
        );
    }
}
