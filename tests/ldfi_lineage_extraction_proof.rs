//! Runnable proof for the LDFI lineage-extraction layer (bead
//! `asupersync-adaptive-control-plane-yj2nxx.4`, WHAT step 1 / AC1).
//!
//! The minimal-hitting-set core (`SupportGraph` + `minimal_hitting_sets`) is
//! already proven by `tests/ldfi_fault_hypothesis_proof.rs`. This crate proves
//! the layer that feeds it: [`CausalLineage`] turns a happens-before relation
//! into a [`SupportGraph`] by taking the fault-able causal cone of each outcome
//! production, and composing the two yields the lineage→hypothesis pipeline that
//! AC1 calls for. Coverage proves the soundness contract from the module docs
//! (over-approximate, never under-approximate) rather than re-deriving the
//! hitting-set algebra.
//!
//! Run with: `cargo test --test ldfi_lineage_extraction_proof --features test-internals`.

use asupersync::lab::ldfi::{CausalLineage, FaultEventId, HittingSetBudget, SupportGraph};

fn ev(id: u64) -> FaultEventId {
    FaultEventId::new(id)
}

fn ids(set: &std::collections::BTreeSet<FaultEventId>) -> Vec<u64> {
    set.iter().map(|e| e.get()).collect()
}

/// AC1 — a realistic delivery lineage with a single point of failure.
///
/// One `send` fans out to three redundant relays, each of which acks; the
/// "delivered" outcome can be produced via any relay. Blind chaos would try a
/// fault on each of the ~10 fault-able events. LDFI, fed the lineage, proposes
/// exactly the one hypothesis worth testing — drop the shared `send` — because
/// it is the only event in every derivation.
#[test]
fn single_point_of_failure_found_via_lineage_with_one_hypothesis() {
    let send = ev(1);
    let relays = [ev(2), ev(3), ev(4)];
    let acks = [ev(5), ev(6), ev(7)];
    let deliveries = [ev(20), ev(21), ev(22)]; // non-fault-able outcome nodes

    let mut lineage = CausalLineage::new();
    lineage.mark_faultable(send);
    for &e in relays.iter().chain(acks.iter()) {
        lineage.mark_faultable(e);
    }
    // send -> relay_i -> ack_i -> delivery_i for each path.
    for ((&relay, &ack), &delivery) in relays.iter().zip(acks.iter()).zip(deliveries.iter()) {
        lineage.add_happens_before(send, relay);
        lineage.add_happens_before(relay, ack);
        lineage.add_happens_before(ack, delivery);
    }

    let graph = SupportGraph::from_causal_cones(&lineage, deliveries);
    assert_eq!(
        graph.derivations().len(),
        3,
        "one derivation per delivery path"
    );
    // Each derivation is the fault-able cone of its delivery: {send, relay_i, ack_i}.
    assert_eq!(ids(&graph.derivations()[0]), vec![1, 2, 5]);

    // AC1: LDFI finds the single point of failure within depth-1 experiments.
    let result = graph.minimal_hitting_sets(HittingSetBudget {
        max_depth: 1,
        max_hypotheses: 64,
    });
    let blind_chaos_experiments = 1 + relays.len() + acks.len(); // every fault-able event
    assert_eq!(result.len(), 1, "exactly one depth-1 hypothesis");
    assert_eq!(
        ids(&result.hypotheses[0]),
        vec![1],
        "the one hypothesis worth testing is dropping the shared send"
    );
    assert!(
        result.len() < blind_chaos_experiments,
        "LDFI proposed {} depth-1 hypothesis vs {} blind-chaos single-fault experiments",
        result.len(),
        blind_chaos_experiments
    );
}

/// Soundness — over-approximation is safe. Padding a cone with extra fault-able
/// ancestry (e.g. a setup lease the outcome transitively depends on) only ever
/// *adds* hypotheses; it can never drop the true single point of failure. This
/// is the module's documented contract: include-when-in-doubt.
#[test]
fn over_approximated_cone_preserves_the_true_hypothesis() {
    // Minimal lineage: shared send 1 under two paths.
    let mut tight = CausalLineage::new();
    for id in [1, 2, 3] {
        tight.mark_faultable(ev(id));
    }
    tight.add_happens_before(ev(1), ev(2));
    tight.add_happens_before(ev(1), ev(3));
    tight.add_happens_before(ev(2), ev(20));
    tight.add_happens_before(ev(3), ev(21));

    // Over-approximated lineage: same, plus an upstream lease 9 that everything
    // transitively depends on (so it joins every cone).
    let mut padded = tight.clone();
    padded.mark_faultable(ev(9));
    padded.add_happens_before(ev(9), ev(1));

    let tight_hs = SupportGraph::from_causal_cones(&tight, [ev(20), ev(21)])
        .minimal_hitting_sets(HittingSetBudget::default());
    let padded_hs = SupportGraph::from_causal_cones(&padded, [ev(20), ev(21)])
        .minimal_hitting_sets(HittingSetBudget::default());

    // The true {1} hypothesis survives the over-approximation...
    assert!(tight_hs.hypotheses.iter().any(|h| ids(h) == vec![1]));
    assert!(padded_hs.hypotheses.iter().any(|h| ids(h) == vec![1]));
    // ...and the padded version additionally surfaces {9} (the shared lease),
    // i.e. it is a superset of proposals, never a subset that lost the truth.
    assert!(padded_hs.hypotheses.iter().any(|h| ids(h) == vec![9]));
    assert!(padded_hs.len() >= tight_hs.len());
}

/// Two outcome productions with *disjoint* fault-able support require a size-2
/// hypothesis — there is no single fault that breaks both paths.
#[test]
fn disjoint_cones_require_depth_two_hypothesis() {
    let mut lineage = CausalLineage::new();
    for id in [1, 2, 3, 4] {
        lineage.mark_faultable(ev(id));
    }
    // Path A: 1 -> 2 -> outcome 20.  Path B: 3 -> 4 -> outcome 21. No shared root.
    lineage.add_happens_before(ev(1), ev(2));
    lineage.add_happens_before(ev(2), ev(20));
    lineage.add_happens_before(ev(3), ev(4));
    lineage.add_happens_before(ev(4), ev(21));

    let graph = SupportGraph::from_causal_cones(&lineage, [ev(20), ev(21)]);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(!result.is_empty());
    assert!(
        result.hypotheses.iter().all(|h| h.len() == 2),
        "no single fault breaks two disjoint cones"
    );
    for h in &result.hypotheses {
        assert!(!h.is_disjoint(&graph.derivations()[0]));
        assert!(!h.is_disjoint(&graph.derivations()[1]));
    }
}

/// AC2 — an outcome produced with no fault-able causal support is unbreakable by
/// event faults, and the pipeline emits a per-corpus coverage certificate.
#[test]
fn unbreakable_outcome_emits_coverage_certificate() {
    let mut lineage = CausalLineage::new();
    // A pure local computation outcome: registered, but not fault-able, and with
    // no fault-able ancestry.
    lineage.add_event(ev(42), false);
    lineage.add_event(ev(43), false);
    lineage.add_happens_before(ev(43), ev(42));

    let graph = SupportGraph::from_causal_cone(&lineage, ev(42));
    assert_eq!(graph.derivations().len(), 1);
    assert!(graph.derivations()[0].is_empty(), "no fault-able support");

    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(result.unbreakable);
    assert!(result.is_empty());
    assert_eq!(result.coverage_certificate(), Some(3));
}

/// Determinism end-to-end (AC3): the same lineage yields a byte-identical
/// support graph and hitting-set result across independent extractions.
#[test]
fn lineage_extraction_is_deterministic() {
    let build = || {
        let mut lineage = CausalLineage::new();
        for id in [1, 2, 3, 4, 5] {
            lineage.mark_faultable(ev(id));
        }
        lineage.add_happens_before(ev(1), ev(3));
        lineage.add_happens_before(ev(2), ev(3));
        lineage.add_happens_before(ev(3), ev(5));
        lineage.add_happens_before(ev(4), ev(5));
        lineage.add_happens_before(ev(5), ev(50));
        SupportGraph::from_causal_cone(&lineage, ev(50))
    };

    let a = build();
    let b = build();
    assert_eq!(a, b, "extraction must be reproducible");
    assert_eq!(
        a.minimal_hitting_sets(HittingSetBudget::default()),
        b.minimal_hitting_sets(HittingSetBudget::default()),
    );
}

/// Defensive — a malformed *cyclic* happens-before relation (which a correct
/// trace never produces, since happens-before is a partial order) must still
/// terminate and yield the reachable cone rather than hang.
#[test]
fn cyclic_lineage_terminates_and_yields_the_reachable_cone() {
    let mut lineage = CausalLineage::new();
    for id in [1, 2, 3] {
        lineage.mark_faultable(ev(id));
    }
    lineage.add_happens_before(ev(1), ev(2));
    lineage.add_happens_before(ev(2), ev(3));
    lineage.add_happens_before(ev(3), ev(1)); // cycle back

    let cone = lineage.causal_cone(ev(3));
    assert_eq!(ids(&cone), vec![1, 2, 3], "cycle collapses to its members");
    let support = lineage.support_of(ev(3));
    assert_eq!(ids(&support), vec![1, 2, 3]);
}

/// Non-fault-able intermediate events propagate causality but are never part of
/// a derivation, so they never become fault hypotheses.
#[test]
fn non_faultable_intermediates_propagate_but_never_appear_in_support() {
    let mut lineage = CausalLineage::new();
    lineage.mark_faultable(ev(1)); // a fault-able send
    lineage.add_event(ev(2), false); // a non-fault-able local decode step
    lineage.mark_faultable(ev(3)); // a fault-able downstream ack
    lineage.add_happens_before(ev(1), ev(2));
    lineage.add_happens_before(ev(2), ev(3));

    // Cone of the ack reaches back through the non-fault-able decode to the send.
    assert_eq!(ids(&lineage.causal_cone(ev(3))), vec![1, 2, 3]);
    // But the support excludes the non-fault-able 2.
    assert_eq!(ids(&lineage.support_of(ev(3))), vec![1, 3]);

    let graph = SupportGraph::from_causal_cone(&lineage, ev(3));
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    for h in &result.hypotheses {
        assert!(
            !h.contains(&ev(2)),
            "non-fault-able event must never be a hypothesis"
        );
    }
}
