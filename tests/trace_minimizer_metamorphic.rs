//! Metamorphic harness for `asupersync::trace::minimizer`.
//!
//! `TraceMinimizer::minimize` is a hierarchical delta-debugging engine: given
//! a scenario (a list of `ScenarioElement`s) and a `checker` predicate that
//! says whether a subset still reproduces a failure, it returns a minimal
//! failing subset. The checker is supplied by the caller, which makes this an
//! unusually clean target — we can construct oracles whose minimal failing
//! set is *known in advance* and assert the minimizer recovers it exactly.
//!
//! Properties pinned here:
//!
//! - **Failure preservation**: the minimized subset always still satisfies
//!   the checker (for every checker, not just the crafted ones).
//! - **Valid subset**: `minimized_indices` are in range, strictly ascending,
//!   and `minimized_elements()` reads back the indexed originals.
//! - **Known-minimum recovery** (the core metamorphic relations):
//!   - a monotone "contains element X" checker minimizes to exactly `{X}`;
//!   - a conjunctive "contains all of {a,b,c}" checker minimizes to exactly
//!     that set;
//!   - a cardinality "size ≥ k" checker minimizes to exactly `k` elements;
//!   - an always-true checker minimizes to the empty set.
//! - **1-minimality**: whenever the report claims `is_minimal`, removing any
//!   single element of the result genuinely breaks the checker.
//! - **Idempotence**: re-minimizing an already-minimal result is a no-op.
//! - **Determinism**: with a `LogicalMinimizerClock`, identical inputs yield
//!   byte-identical reports.
//! - **Bookkeeping**: counts, reduction ratio, and replay tally stay
//!   mutually consistent.
//!
//! No `proptest` dependency; scenarios and oracles are constructed directly.

#![allow(clippy::needless_range_loop)]

use asupersync::trace::minimizer::LogicalMinimizerClock;
use asupersync::trace::{MinimizationReport, ScenarioElement, StepKind, TraceMinimizer};

// ---------------------------------------------------------------------------
// Scenario-element helpers
// ---------------------------------------------------------------------------

/// An `AdvanceTime` element — the simplest `ScenarioElement` (no region), and
/// every distinct `nanos` value yields a distinct, comparable element.
fn adv(nanos: u64) -> ScenarioElement {
    ScenarioElement::AdvanceTime { nanos }
}

/// A scenario of `n` distinct `AdvanceTime` elements: `[adv(1), …, adv(n)]`.
fn adv_scenario(n: u64) -> Vec<ScenarioElement> {
    (1..=n).map(adv).collect()
}

// ---------------------------------------------------------------------------
// Oracle constructors — each returns a fresh closure so it can be used twice.
// ---------------------------------------------------------------------------

/// Monotone oracle: a subset "fails" iff it contains `target`.
fn contains_oracle(target: ScenarioElement) -> impl Fn(&[ScenarioElement]) -> bool {
    move |s: &[ScenarioElement]| s.contains(&target)
}

/// Monotone conjunctive oracle: fails iff the subset contains every element
/// of `targets`.
fn conjunction_oracle(targets: Vec<ScenarioElement>) -> impl Fn(&[ScenarioElement]) -> bool {
    move |s: &[ScenarioElement]| targets.iter().all(|t| s.contains(t))
}

/// Monotone cardinality oracle: fails iff the subset has at least `k` elements.
fn cardinality_oracle(k: usize) -> impl Fn(&[ScenarioElement]) -> bool {
    move |s: &[ScenarioElement]| s.len() >= k
}

// ---------------------------------------------------------------------------
// Universal invariants — hold for any oracle the full set satisfies.
// ---------------------------------------------------------------------------

/// Assert the report-level invariants that must hold for *any* minimization.
fn assert_report_well_formed(report: &MinimizationReport, original_len: usize) {
    assert_eq!(report.original_count, original_len, "original_count wrong");
    assert_eq!(
        report.minimized_count,
        report.minimized_indices.len(),
        "minimized_count != minimized_indices.len()"
    );
    assert!(
        report.minimized_count <= report.original_count,
        "minimized set larger than original"
    );
    assert!(
        report.replay_attempts >= 1,
        "must replay at least the full set"
    );

    // Indices are in range and strictly ascending.
    let mut prev: Option<usize> = None;
    for &idx in &report.minimized_indices {
        assert!(idx < original_len, "index {idx} out of range");
        if let Some(p) = prev {
            assert!(p < idx, "minimized_indices not strictly ascending");
        }
        prev = Some(idx);
    }

    // minimized_elements() reads back exactly the indexed originals.
    let elems = report.minimized_elements();
    assert_eq!(elems.len(), report.minimized_count);
    for (slot, &idx) in report.minimized_indices.iter().enumerate() {
        assert_eq!(
            elems[slot], report.original_elements[idx],
            "minimized_elements()[{slot}] != original_elements[{idx}]"
        );
    }

    // reduction_ratio = 1 - minimized/original.
    let expected_ratio = if original_len == 0 {
        0.0
    } else {
        1.0 - (report.minimized_count as f64 / original_len as f64)
    };
    assert!(
        (report.reduction_ratio - expected_ratio).abs() < 1e-12,
        "reduction_ratio {} != expected {expected_ratio}",
        report.reduction_ratio
    );
}

#[test]
fn minimized_subset_always_reproduces_the_failure() {
    // For every oracle, the minimized subset must still satisfy the checker.
    for n in [1u64, 2, 4, 8, 12] {
        let scenario = adv_scenario(n);
        let oracles: Vec<Box<dyn Fn(&[ScenarioElement]) -> bool>> = vec![
            Box::new(contains_oracle(adv(n))),
            Box::new(contains_oracle(adv(1))),
            Box::new(cardinality_oracle((n as usize).min(3))),
            Box::new(|_: &[ScenarioElement]| true),
        ];
        for oracle in oracles {
            let report = TraceMinimizer::minimize(&scenario, &oracle);
            assert_report_well_formed(&report, scenario.len());
            assert!(
                oracle(&report.minimized_elements()),
                "minimized subset no longer reproduces the failure (n={n})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Known-minimum recovery — the core metamorphic relations.
// ---------------------------------------------------------------------------

#[test]
fn monotone_singleton_oracle_recovers_the_unique_culprit() {
    // The minimal failing set of "contains adv(target)" is exactly {adv(target)}.
    for n in [1u64, 3, 7, 16] {
        let scenario = adv_scenario(n);
        for target in [1u64, n / 2 + 1, n] {
            let oracle = contains_oracle(adv(target));
            let report = TraceMinimizer::minimize(&scenario, &oracle);
            assert_report_well_formed(&report, scenario.len());
            assert_eq!(
                report.minimized_elements(),
                vec![adv(target)],
                "singleton oracle did not isolate adv({target}) in a scenario of {n}"
            );
            assert!(report.is_minimal, "singleton result must be 1-minimal");
        }
    }
}

#[test]
fn conjunctive_oracle_recovers_exactly_the_conjunction() {
    let scenario = adv_scenario(16);
    let targets = vec![adv(3), adv(8), adv(14)];
    let oracle = conjunction_oracle(targets.clone());
    let report = TraceMinimizer::minimize(&scenario, &oracle);
    assert_report_well_formed(&report, scenario.len());

    let mut got = report.minimized_elements();
    got.sort_by_key(|e| match e {
        ScenarioElement::AdvanceTime { nanos } => *nanos,
        _ => u64::MAX,
    });
    let mut want = targets;
    want.sort_by_key(|e| match e {
        ScenarioElement::AdvanceTime { nanos } => *nanos,
        _ => u64::MAX,
    });
    assert_eq!(got, want, "conjunctive oracle did not recover {{3,8,14}}");
    assert!(report.is_minimal, "conjunction result must be 1-minimal");
}

#[test]
fn cardinality_oracle_reduces_to_exactly_the_threshold() {
    for &(n, k) in &[(8u64, 1usize), (8, 3), (12, 5), (16, 16), (10, 9)] {
        let scenario = adv_scenario(n);
        let oracle = cardinality_oracle(k);
        let report = TraceMinimizer::minimize(&scenario, &oracle);
        assert_report_well_formed(&report, scenario.len());
        assert_eq!(
            report.minimized_count, k,
            "size>={k} oracle should minimize a scenario of {n} to exactly {k}"
        );
        assert!(report.is_minimal, "a tight cardinality result is 1-minimal");
    }
}

#[test]
fn always_true_oracle_reduces_to_the_ddmin_floor() {
    // `ddmin` never reduces below a single element (the `indices.len() <= 1`
    // early return). An always-true oracle therefore minimizes a non-empty
    // all-`AdvanceTime` scenario down to exactly one element — and the report
    // is honest about that not being a true minimum: removing the survivor
    // still satisfies the oracle, so `is_minimal` is false.
    for n in [1u64, 4, 10] {
        let scenario = adv_scenario(n);
        let report = TraceMinimizer::minimize(&scenario, |_: &[ScenarioElement]| true);
        assert_report_well_formed(&report, scenario.len());
        assert_eq!(
            report.minimized_count, 1,
            "ddmin floors at one element for a non-empty scenario"
        );
        assert!(
            !report.is_minimal,
            "the lone survivor is itself removable, so is_minimal must be false"
        );
    }
}

// ---------------------------------------------------------------------------
// 1-minimality: the report's `is_minimal` flag must be honest.
// ---------------------------------------------------------------------------

#[test]
fn is_minimal_flag_implies_genuine_one_minimality() {
    // When the report claims 1-minimality, dropping any single element of the
    // result must break the oracle.
    let scenario = adv_scenario(14);
    let oracles: Vec<Box<dyn Fn(&[ScenarioElement]) -> bool>> = vec![
        Box::new(contains_oracle(adv(9))),
        Box::new(conjunction_oracle(vec![adv(2), adv(11)])),
        Box::new(cardinality_oracle(4)),
    ];
    for oracle in &oracles {
        let report = TraceMinimizer::minimize(&scenario, oracle);
        if !report.is_minimal {
            continue;
        }
        let minimal = report.minimized_elements();
        for drop in 0..minimal.len() {
            let reduced: Vec<ScenarioElement> = minimal
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != drop)
                .map(|(_, e)| e.clone())
                .collect();
            assert!(
                !oracle(&reduced),
                "is_minimal claimed, but dropping element {drop} keeps the oracle satisfied"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Idempotence — re-minimizing a minimal result changes nothing.
// ---------------------------------------------------------------------------

#[test]
fn minimization_is_idempotent() {
    let scenario = adv_scenario(16);
    let specs: Vec<Box<dyn Fn(&[ScenarioElement]) -> bool>> = vec![
        Box::new(contains_oracle(adv(6))),
        Box::new(conjunction_oracle(vec![adv(1), adv(9), adv(15)])),
        Box::new(cardinality_oracle(5)),
    ];
    for oracle in &specs {
        let first = TraceMinimizer::minimize(&scenario, oracle);
        let second = TraceMinimizer::minimize(&first.minimized_elements(), oracle);
        assert_eq!(
            second.minimized_elements(),
            first.minimized_elements(),
            "re-minimizing an already-minimal scenario changed the result"
        );
    }
}

// ---------------------------------------------------------------------------
// Determinism — LogicalMinimizerClock makes the report byte-stable.
// ---------------------------------------------------------------------------

#[test]
fn minimize_with_logical_clock_is_deterministic() {
    let scenario = adv_scenario(15);
    for run_spec in 0..3 {
        let oracle = match run_spec {
            0 => Box::new(contains_oracle(adv(7))) as Box<dyn Fn(&[ScenarioElement]) -> bool>,
            1 => Box::new(conjunction_oracle(vec![adv(4), adv(13)])),
            _ => Box::new(cardinality_oracle(6)),
        };
        let a =
            TraceMinimizer::minimize_with_clock(&scenario, &oracle, &LogicalMinimizerClock::new());
        let b =
            TraceMinimizer::minimize_with_clock(&scenario, &oracle, &LogicalMinimizerClock::new());
        assert_eq!(a.minimized_indices, b.minimized_indices, "indices differ");
        assert_eq!(a.replay_attempts, b.replay_attempts, "replay tally differs");
        assert_eq!(a.is_minimal, b.is_minimal, "is_minimal differs");
        assert_eq!(a.minimized_count, b.minimized_count);
        assert_eq!(
            a.wall_time_ms, b.wall_time_ms,
            "logical-clock time not stable"
        );
        assert_eq!(a.steps.len(), b.steps.len(), "step count differs");
    }
}

// ---------------------------------------------------------------------------
// Region-structured scenarios — exercises the ConcurrencyTree / top-down phase.
// ---------------------------------------------------------------------------

#[test]
fn region_structured_scenario_isolates_a_targeted_element() {
    // A scenario with regions, a spawned task, and time advances. The oracle
    // targets the spawn; the minimizer must keep at least that element and
    // the result must still satisfy the oracle.
    let spawn = ScenarioElement::SpawnTask {
        task_idx: 0,
        region_idx: 1,
        lane: 0,
    };
    let scenario = vec![
        ScenarioElement::CreateRegion {
            region_idx: 1,
            parent_idx: 0,
        },
        spawn.clone(),
        adv(100),
        ScenarioElement::CreateRegion {
            region_idx: 2,
            parent_idx: 0,
        },
        adv(200),
        ScenarioElement::CancelRegion { region_idx: 2 },
    ];
    let oracle = contains_oracle(spawn.clone());
    let report = TraceMinimizer::minimize(&scenario, &oracle);
    assert_report_well_formed(&report, scenario.len());
    assert!(
        oracle(&report.minimized_elements()),
        "region-structured minimization dropped the targeted element"
    );
    assert!(
        report.minimized_elements().contains(&spawn),
        "the spawn must survive minimization"
    );
    // "contains spawn" is monotone with a unique culprit → exactly {spawn}.
    assert_eq!(report.minimized_elements(), vec![spawn]);
}

// ---------------------------------------------------------------------------
// Degenerate input + report value-type sanity.
// ---------------------------------------------------------------------------

#[test]
fn empty_scenario_minimizes_to_an_empty_report() {
    let report = TraceMinimizer::minimize(&[], |_: &[ScenarioElement]| true);
    assert_eq!(report.original_count, 0);
    assert_eq!(report.minimized_count, 0);
    assert!(report.minimized_indices.is_empty());
    assert!(report.minimized_elements().is_empty());
    assert!(report.replay_attempts >= 1);
}

#[test]
fn step_kind_has_value_semantics() {
    let a = StepKind::TopDownPrune;
    let copied = a;
    assert_eq!(a, copied);
    assert!(!format!("{a:?}").is_empty());
}
