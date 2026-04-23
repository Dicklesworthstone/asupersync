//! Golden snapshots for `src/plan/analysis.rs` Display impls and summary output.
//!
//! Run as an integration test (separate compile unit) so these goldens stay
//! generable even when unrelated unit-test modules break `cargo test --lib`.
//! The lib-crate duplicates in `src/plan/analysis.rs` (`golden_display_*`) are
//! dormant mirrors that can be accepted via `cargo insta accept` once the lib
//! test target compiles again.

use asupersync::plan::{
    BudgetEffect, CancelSafety, DeadlineMicros, IndependenceResult, ObligationFlow,
    ObligationSafety, PlanAnalyzer, PlanDag, TraceEquivalenceHint,
};

#[test]
fn golden_display_obligation_safety_all_variants() {
    let rendered = [
        ObligationSafety::Clean,
        ObligationSafety::MayLeak,
        ObligationSafety::Leaked,
        ObligationSafety::Unknown,
    ]
    .map(|v| format!("{v:?} -> {v}"))
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_cancel_safety_all_variants() {
    let rendered = [
        CancelSafety::Safe,
        CancelSafety::MayOrphan,
        CancelSafety::Orphan,
        CancelSafety::Unknown,
    ]
    .map(|v| format!("{v:?} -> {v}"))
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_budget_effect_shapes() {
    let leaf = BudgetEffect::LEAF;
    let unknown = BudgetEffect::UNKNOWN;
    let with_deadline = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(2_500));
    let parallel = leaf.parallel(leaf);
    let sequential_with_deadline = leaf
        .with_deadline(DeadlineMicros::from_micros(500))
        .sequential(leaf.with_deadline(DeadlineMicros::from_micros(750)));
    let rendered = [
        ("leaf", leaf),
        ("unknown", unknown),
        ("with_deadline(2500µs)", with_deadline),
        ("parallel(leaf, leaf)", parallel),
        ("sequential(500µs, 750µs)", sequential_with_deadline),
    ]
    .map(|(tag, b)| format!("{tag}: {b}"))
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_obligation_flow_shapes() {
    let empty = ObligationFlow::empty();
    let leaf = ObligationFlow::leaf_with_obligation("obl:permit".to_string());
    let joined = ObligationFlow::leaf_with_obligation("obl:a".to_string())
        .join(ObligationFlow::leaf_with_obligation("obl:b".to_string()));
    let raced = ObligationFlow::leaf_with_obligation("obl:winner".to_string())
        .race(ObligationFlow::leaf_with_obligation("obl:loser".to_string()));
    let rendered = [
        ("empty", empty),
        ("leaf_with_obligation", leaf),
        ("join(a,b)", joined),
        ("race(winner,loser)", raced),
    ]
    .iter()
    .map(|(tag, f)| format!("{tag}: {f}"))
    .collect::<Vec<_>>()
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_independence_result_all_variants() {
    let rendered = [
        IndependenceResult::Independent,
        IndependenceResult::Dependent,
        IndependenceResult::Uncertain,
    ]
    .map(|v| format!("{v:?} -> {v}"))
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_trace_equivalence_hint_all_variants() {
    let partial_two_groups = TraceEquivalenceHint::PartiallyCommutative {
        groups: vec![vec![0, 1], vec![2]],
    };
    let partial_three_groups = TraceEquivalenceHint::PartiallyCommutative {
        groups: vec![vec![0], vec![1], vec![2, 3]],
    };
    let rendered = [
        ("Atomic", TraceEquivalenceHint::Atomic),
        ("FullyCommutative", TraceEquivalenceHint::FullyCommutative),
        ("PartiallyCommutative(2)", partial_two_groups),
        ("PartiallyCommutative(3)", partial_three_groups),
        ("Sequential", TraceEquivalenceHint::Sequential),
        ("Unknown", TraceEquivalenceHint::Unknown),
    ]
    .iter()
    .map(|(tag, v)| format!("{tag}: {v}"))
    .collect::<Vec<_>>()
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_display_deadline_micros_orders_of_magnitude() {
    let rendered = [
        DeadlineMicros::UNBOUNDED,
        DeadlineMicros::ZERO,
        DeadlineMicros::from_micros(42),
        DeadlineMicros::from_micros(1_500),
        DeadlineMicros::from_micros(2_500_000),
    ]
    .map(|d| format!("{d:?} -> {d}"))
    .join("\n");
    insta::assert_snapshot!(rendered);
}

#[test]
fn golden_analysis_summary_race_of_leaves() {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let race = dag.race(vec![a, b]);
    dag.set_root(race);

    let analysis = PlanAnalyzer::analyze(&dag);
    insta::assert_snapshot!(analysis.summary());
}

#[test]
fn golden_analysis_summary_nested_join_in_race() {
    let mut dag = PlanDag::new();
    let a = dag.leaf("a");
    let b = dag.leaf("b");
    let c = dag.leaf("c");
    let join = dag.join(vec![a, b]);
    let race = dag.race(vec![join, c]);
    dag.set_root(race);

    let analysis = PlanAnalyzer::analyze(&dag);
    insta::assert_snapshot!(analysis.summary());
}
