//! Runnable proof for lineage-driven fault injection (bead
//! `asupersync-adaptive-control-plane-yj2nxx.4`, AC1/AC2 — hypothesis layer).
//!
//! Proves the LDFI minimal-hitting-set generator (`src/lab/ldfi.rs`) on a seeded
//! fixture with a KNOWN single-fault vulnerability and frames the AC1 count
//! comparison: blind chaos would try every single-event fault (|universe|
//! experiments); LDFI proposes only the minimal fault set(s) that could remove
//! the outcome's support — here, exactly one — orders of magnitude fewer. Also
//! proves the AC2 coverage certificate on a fault-tolerant fixture.
//!
//! Run with: `cargo test --test ldfi_fault_hypothesis_proof --features test-internals`.

use asupersync::lab::ldfi::{
    FaultEventId, HittingSetBudget, LdfiExperimentBudget, LdfiExperimentObservation,
    LdfiExperimentStatus, SupportGraph,
};

fn ev(i: u64) -> FaultEventId {
    FaultEventId::new(i)
}

#[test]
fn finds_known_single_fault_with_far_fewer_experiments_than_blind_chaos() {
    // Event e1 supports EVERY derivation of the outcome (it appears in all of
    // them); every other event supports only one. Dropping e1 alone breaks the
    // outcome. The "universe" is 20 distinct fault-able events.
    let universe: u64 = 20;
    let mut graph = SupportGraph::new();
    for other in 2..=universe {
        graph.add_derivation([ev(1), ev(other)]);
    }

    let result = graph.minimal_hitting_sets(HittingSetBudget::default());

    // LDFI finds the single-fault hypothesis {e1} at depth 1.
    let single_faults: Vec<_> = result.hypotheses.iter().filter(|h| h.len() == 1).collect();
    assert!(
        single_faults.iter().any(|h| h.contains(&ev(1))),
        "LDFI did not surface the known single-fault {{e1}}"
    );

    // AC1 count comparison: blind chaos's single-fault sweep = |universe|
    // experiments; LDFI proposes far fewer hypotheses. With one shared support
    // event, LDFI converges on a single depth-1 hypothesis.
    let blind_chaos_single_fault_experiments = usize::try_from(universe).unwrap();
    assert!(
        result.hypotheses.len() < blind_chaos_single_fault_experiments,
        "LDFI proposed {} hypotheses; blind chaos would run {}",
        result.hypotheses.len(),
        blind_chaos_single_fault_experiments
    );
    assert_eq!(
        result.hypotheses.len(),
        1,
        "expected exactly one minimal hitting set"
    );
    // Note: `exhausted` may be false here — with 19 derivations the bounded
    // search hits its raw-transversal cap before the minimal filter collapses
    // everything to {e1}. That does not affect correctness of the result.
}

#[test]
fn disjoint_support_requires_a_multi_fault_hitting_set() {
    // Two independent derivations sharing no events: no single fault breaks the
    // outcome; the minimal hypothesis has size 2.
    let mut graph = SupportGraph::new();
    graph.add_derivation([ev(1), ev(2)]);
    graph.add_derivation([ev(3), ev(4)]);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(!result.hypotheses.is_empty());
    assert!(result.hypotheses.iter().all(|h| h.len() == 2));
}

#[test]
fn fault_tolerant_fixture_yields_coverage_certificate() {
    // AC2: an outcome with a support derivation that has no fault-able events is
    // unbreakable; LDFI emits a (per-corpus) coverage certificate.
    let mut graph = SupportGraph::new();
    graph.add_derivation([ev(1)]);
    graph.add_derivation(std::iter::empty());
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(result.is_empty());
    assert!(result.unbreakable);
    assert_eq!(result.coverage_certificate(), Some(3));
}

#[test]
fn experiment_loop_stops_on_first_observed_violation() {
    let mut graph = SupportGraph::new();
    graph.add_derivation([ev(1), ev(2)]);
    graph.add_derivation([ev(1), ev(3)]);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());

    let report = result.run_experiments(LdfiExperimentBudget::default(), |hypothesis| {
        if hypothesis.contains(&ev(1)) {
            LdfiExperimentObservation::InvariantViolated
        } else {
            LdfiExperimentObservation::InvariantHeld
        }
    });

    assert_eq!(report.experiments_run, 1);
    assert!(report.refuted.is_empty());
    assert_eq!(
        report.status,
        LdfiExperimentStatus::FoundViolation {
            hypothesis: std::iter::once(ev(1)).collect()
        }
    );
    assert_eq!(report.coverage_certificate(), None);
}

#[test]
fn experiment_loop_refutes_exhausted_hypotheses_into_coverage() {
    let mut graph = SupportGraph::new();
    graph.add_derivation([ev(1)]);
    graph.add_derivation([ev(2)]);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(result.exhausted, "fixture must fully enumerate hypotheses");

    let report = result.run_experiments(LdfiExperimentBudget::default(), |_| {
        LdfiExperimentObservation::InvariantHeld
    });

    assert_eq!(
        report.status,
        LdfiExperimentStatus::RefutedUpToDepth { max_depth: 3 }
    );
    assert_eq!(report.experiments_run, result.len());
    assert_eq!(report.refuted, result.hypotheses);
    assert_eq!(report.coverage_certificate(), Some(3));
}

#[test]
fn experiment_loop_budget_exhaustion_does_not_claim_coverage() {
    let mut graph = SupportGraph::new();
    graph.add_derivation([ev(1), ev(2)]);
    graph.add_derivation([ev(3), ev(4)]);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(
        result.len() > 1,
        "fixture needs multiple generated hypotheses"
    );

    let report = result.run_experiments(LdfiExperimentBudget { max_experiments: 1 }, |_| {
        LdfiExperimentObservation::InvariantHeld
    });

    assert_eq!(report.experiments_run, 1);
    assert_eq!(
        report.status,
        LdfiExperimentStatus::ExperimentBudgetExhausted {
            remaining_hypotheses: result.len() - 1
        }
    );
    assert_eq!(report.coverage_certificate(), None);
}
