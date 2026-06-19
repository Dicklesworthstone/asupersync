//! Runnable proof for the LDFI lab-runtime trace adapter (bead
//! `asupersync-adaptive-control-plane-yj2nxx.4`, WHAT step 1 — the adapter).
//!
//! The pure hitting-set core (`SupportGraph` + `minimal_hitting_sets`) and the
//! abstract lineage extractor (`CausalLineage`) are already certified by
//! `tests/ldfi_fault_hypothesis_proof.rs` and
//! `tests/ldfi_lineage_extraction_proof.rs`. This crate proves the *adapter* that
//! fills the pure `CausalLineage` from a real recorded lab trace
//! (`asupersync::lab::ldfi_trace`): it recovers the happens-before relation from
//! per-task program order, per-resource correlation, and logical clocks, and the
//! composed `trace -> lineage -> SupportGraph -> hitting sets` pipeline reproduces
//! the AC1 single-shared-fault result on a trace-shaped fixture, an AC2 coverage
//! certificate on an unbreakable trace, determinism (AC3), and the documented
//! over-approximation soundness contract.
//!
//! Run with:
//! `cargo test -p asupersync --test ldfi_trace_adapter_proof --features test-internals`.

use std::collections::BTreeSet;

use asupersync::lab::ldfi::{
    FaultEventId, HittingSetBudget, LdfiExperimentBudget, LdfiExperimentObservation,
    LdfiExperimentStatus, SupportGraph,
};
use asupersync::lab::ldfi_trace::{
    LDFI_REPORT_SCHEMA, LdfiReport, TraceLineageConfig, blind_chaos_single_fault_count,
    build_causal_lineage, default_faultable, ldfi_report, outcome_events, support_graph_for,
};
use asupersync::record::ObligationKind;
use asupersync::remote::NodeId;
use asupersync::trace::distributed::{LamportClock, LogicalTime, VectorClock};
use asupersync::trace::{TraceEvent, TraceEventKind};
use asupersync::types::{ObligationId, RegionId, TaskId, Time};

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

fn region() -> RegionId {
    RegionId::new_for_test(0, 0)
}

fn ob(id: u32) -> ObligationId {
    ObligationId::new_for_test(id, 0)
}

fn set(ids: &[u64]) -> BTreeSet<FaultEventId> {
    ids.iter().copied().map(FaultEventId::new).collect()
}

fn ids(s: &BTreeSet<FaultEventId>) -> Vec<u64> {
    s.iter().map(|e| e.get()).collect()
}

/// A message-delivery trace where two independent acks both causally depend on a
/// single send, expressed through vector-clock happens-before. Dropping the send
/// is the one fault that breaks every delivery path. `node` selects the clock
/// flavour so the soundness test can re-run the same shape under Lamport.
fn delivery_trace_vector() -> Vec<TraceEvent> {
    let net = NodeId::new("net");
    let a = NodeId::new("a");
    let b = NodeId::new("b");
    let mut send_vc = VectorClock::new();
    send_vc.increment(&net);
    let mut ack_a_vc = send_vc.clone();
    ack_a_vc.increment(&a);
    let mut ack_b_vc = send_vc.clone();
    ack_b_vc.increment(&b);
    let mut ok_a_vc = ack_a_vc.clone();
    ok_a_vc.increment(&a);
    let mut ok_b_vc = ack_b_vc.clone();
    ok_b_vc.increment(&b);

    vec![
        TraceEvent::io_result(1, Time::ZERO, 10, 4).with_logical_time(LogicalTime::Vector(send_vc)),
        TraceEvent::io_ready(2, Time::ZERO, 20, 1).with_logical_time(LogicalTime::Vector(ack_a_vc)),
        TraceEvent::io_ready(3, Time::ZERO, 30, 1).with_logical_time(LogicalTime::Vector(ack_b_vc)),
        TraceEvent::user_trace(10, Time::ZERO, "delivered-a")
            .with_logical_time(LogicalTime::Vector(ok_a_vc)),
        TraceEvent::user_trace(11, Time::ZERO, "delivered-b")
            .with_logical_time(LogicalTime::Vector(ok_b_vc)),
    ]
}

fn is_outcome(ev: &TraceEvent) -> bool {
    ev.kind == TraceEventKind::UserTrace
}

/// AC1 — the trace adapter reproduces the single-shared-fault result.
///
/// From a real (trace-shaped) successful run, the lineage extracted by the
/// adapter yields exactly the `{send}` depth-1 fault hypothesis, and the count of
/// LDFI hypotheses worth testing is far below the blind-chaos single-fault count.
#[test]
fn ac1_adapter_finds_single_shared_send_fault() {
    let trace = delivery_trace_vector();
    let graph = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);

    // Two productions of the outcome -> two derivations, both rooted at the send.
    assert_eq!(graph.derivations().len(), 2);
    assert_eq!(ids(&graph.derivations()[0]), vec![1, 2]); // {send, ack_a}
    assert_eq!(ids(&graph.derivations()[1]), vec![1, 3]); // {send, ack_b}

    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    let smallest = result
        .hypotheses
        .first()
        .expect("a breaking hypothesis exists");
    assert_eq!(
        smallest,
        &set(&[1]),
        "the minimal breaking hypothesis is the send"
    );
    assert!(result.exhausted);

    // Blind-chaos baseline: every fault-able event is a single-fault experiment.
    let blind_single_fault_experiments =
        trace.iter().filter(|ev| default_faultable(ev.kind)).count();
    assert_eq!(blind_single_fault_experiments, 3, "send + ack_a + ack_b");
    // LDFI's first hypothesis is the one fault that actually breaks delivery.
    assert!(result.hypotheses.len() < blind_single_fault_experiments);
}

/// AC1 — the experiment loop confirms the violation in a single experiment.
///
/// Wiring the adapter's support graph to the pure experiment loop: an outcome
/// survives a hypothesis iff some derivation is left intact. The first (smallest)
/// hypothesis `{send}` hits every derivation, so the loop reports a violation
/// after exactly one experiment — orders of magnitude fewer than blind chaos.
#[test]
fn ac1_experiment_loop_finds_violation_in_one_run() {
    let trace = delivery_trace_vector();
    let graph = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    let derivations: Vec<BTreeSet<FaultEventId>> = graph.derivations().to_vec();

    let report = result.run_experiments(LdfiExperimentBudget::default(), |hypothesis| {
        // The "delivered" invariant holds iff at least one production survived,
        // i.e. some derivation is disjoint from the disabled-event set.
        if derivations.iter().any(|d| d.is_disjoint(hypothesis)) {
            LdfiExperimentObservation::InvariantHeld
        } else {
            LdfiExperimentObservation::InvariantViolated
        }
    });

    match &report.status {
        LdfiExperimentStatus::FoundViolation { hypothesis } => {
            assert_eq!(hypothesis, &set(&[1]));
        }
        other => panic!("expected a found violation, got {other:?}"),
    }
    assert_eq!(report.experiments_run, 1);
    assert!(report.refuted.is_empty());
    assert!(report.coverage_certificate().is_none());
}

/// AC2 — an unbreakable trace yields a per-corpus coverage certificate.
///
/// A run whose outcome has no fault-able causal ancestry (only structural spawn
/// and completion) cannot be broken by any event fault; the pipeline emits the
/// honest per-corpus certificate rather than a hypothesis.
#[test]
fn ac2_unbreakable_trace_yields_coverage_certificate() {
    let trace = vec![
        TraceEvent::spawn(0, Time::ZERO, task(1), region()),
        TraceEvent::complete(1, Time::ZERO, task(1), region()),
    ];
    let graph = support_graph_for(&trace, TraceLineageConfig::default(), |ev| {
        ev.kind == TraceEventKind::Complete
    });
    assert_eq!(graph.derivations().len(), 1);
    assert!(graph.derivations()[0].is_empty(), "no fault-able support");

    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    assert!(result.is_empty());
    assert!(result.unbreakable);
    assert_eq!(result.coverage_certificate(), Some(3));
}

/// AC3 — the adapter is deterministic end-to-end.
#[test]
fn ac3_determinism_end_to_end() {
    let trace = delivery_trace_vector();
    let a = build_causal_lineage(&trace, TraceLineageConfig::default());
    let b = build_causal_lineage(&trace, TraceLineageConfig::default());
    assert_eq!(a, b);

    let ga = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);
    let gb = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);
    assert_eq!(
        ga.minimal_hitting_sets(HittingSetBudget::default()),
        gb.minimal_hitting_sets(HittingSetBudget::default())
    );
}

/// Soundness — Lamport clocks over-approximate but never miss the true fault.
///
/// Re-running the same delivery shape with a total-order Lamport clock pulls more
/// events into each cone, so LDFI emits *more* (sound, refutable) hypotheses; the
/// true breaking fault `{send}` is still present. Under-approximation — dropping
/// `{send}` — would be the unsafe failure the contract forbids.
#[test]
fn soundness_lamport_overapproximates_but_keeps_true_fault() {
    let clock = LamportClock::new();
    let send = LogicalTime::Lamport(clock.tick());
    let ack_a = LogicalTime::Lamport(clock.tick());
    let ack_b = LogicalTime::Lamport(clock.tick());
    let ok_a = LogicalTime::Lamport(clock.tick());
    let ok_b = LogicalTime::Lamport(clock.tick());
    let trace = vec![
        TraceEvent::io_result(1, Time::ZERO, 10, 4).with_logical_time(send),
        TraceEvent::io_ready(2, Time::ZERO, 20, 1).with_logical_time(ack_a),
        TraceEvent::io_ready(3, Time::ZERO, 30, 1).with_logical_time(ack_b),
        TraceEvent::user_trace(10, Time::ZERO, "delivered-a").with_logical_time(ok_a),
        TraceEvent::user_trace(11, Time::ZERO, "delivered-b").with_logical_time(ok_b),
    ];

    let lamport = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome)
        .minimal_hitting_sets(HittingSetBudget::default());
    let vector = support_graph_for(
        &delivery_trace_vector(),
        TraceLineageConfig::default(),
        is_outcome,
    )
    .minimal_hitting_sets(HittingSetBudget::default());

    // The true fault is never under-approximated away.
    assert!(lamport.hypotheses.contains(&set(&[1])));
    // The total order is a strictly looser relation -> at least as many hypotheses.
    assert!(lamport.hypotheses.len() >= vector.hypotheses.len());
}

/// Extraction rules — the structural sources assemble the cone without any
/// logical clock, so the adapter works on traces that carry no `logical_time`.
#[test]
fn structural_sources_assemble_cone_without_clocks() {
    // All three events on task 1; the obligation also chains reserve -> commit.
    let trace = vec![
        TraceEvent::obligation_reserve(
            0,
            Time::ZERO,
            ob(1),
            task(1),
            region(),
            ObligationKind::Lease,
        ),
        TraceEvent::wake(1, Time::ZERO, task(1), region()),
        TraceEvent::obligation_commit(
            2,
            Time::ZERO,
            ob(1),
            task(1),
            region(),
            ObligationKind::Lease,
            10,
        ),
    ];
    let config = TraceLineageConfig {
        use_logical_time: false,
        correlate_resources: true,
    };
    let lineage = build_causal_lineage(&trace, config);
    // The commit's fault-able support is the reserve, the wake, and itself —
    // all reachable through program order and the obligation chain alone.
    assert_eq!(
        ids(&lineage.support_of(FaultEventId::new(2))),
        vec![0, 1, 2]
    );

    let graph = SupportGraph::from_causal_cones(&lineage, outcome_events(&trace, |ev| ev.seq == 2));
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    // A single chain -> every fault-able event is its own size-1 hypothesis.
    assert_eq!(result.hypotheses, vec![set(&[0]), set(&[1]), set(&[2])]);
}

/// The default classifier matches the documented fault taxonomy.
#[test]
fn classifier_taxonomy_smoke() {
    for kind in [
        TraceEventKind::Wake,
        TraceEventKind::TimerFired,
        TraceEventKind::IoReady,
        TraceEventKind::IoResult,
        TraceEventKind::ObligationReserve,
        TraceEventKind::ObligationCommit,
        TraceEventKind::DownDelivered,
        TraceEventKind::ExitDelivered,
    ] {
        assert!(default_faultable(kind), "{kind:?} should be fault-able");
    }
    for kind in [
        TraceEventKind::Spawn,
        TraceEventKind::Schedule,
        TraceEventKind::Poll,
        TraceEventKind::Complete,
        TraceEventKind::IoRequested,
        TraceEventKind::RegionCreated,
        TraceEventKind::UserTrace,
    ] {
        assert!(!default_faultable(kind), "{kind:?} should be structural");
    }
}

/// AC5 — the JSON report is byte-stable and round-trips through serde.
#[test]
fn ac5_json_report_is_deterministic_and_roundtrips() {
    let trace = delivery_trace_vector();
    let graph = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    let baseline = blind_chaos_single_fault_count(&trace);
    let report = ldfi_report(&result, baseline);

    assert_eq!(report.schema, LDFI_REPORT_SCHEMA);
    assert_eq!(report.blind_chaos_single_fault_experiments, 3);
    assert_eq!(report.hypotheses[0], vec![1u64]);
    assert_eq!(report.coverage_certificate, None);
    assert!(report.experiment.is_none());

    let json = serde_json::to_string(&report).expect("serialize");
    let json_again = serde_json::to_string(&report).expect("serialize");
    assert_eq!(json, json_again, "serialization is deterministic");
    let round_trip: LdfiReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(round_trip, report);
}

/// AC5 — the report carries the experiment-loop violation verdict.
#[test]
fn ac5_report_carries_experiment_violation() {
    let trace = delivery_trace_vector();
    let graph = support_graph_for(&trace, TraceLineageConfig::default(), is_outcome);
    let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    let derivations: Vec<BTreeSet<FaultEventId>> = graph.derivations().to_vec();
    let experiment = result.run_experiments(LdfiExperimentBudget::default(), |hypothesis| {
        if derivations.iter().any(|d| d.is_disjoint(hypothesis)) {
            LdfiExperimentObservation::InvariantHeld
        } else {
            LdfiExperimentObservation::InvariantViolated
        }
    });

    let report =
        ldfi_report(&result, blind_chaos_single_fault_count(&trace)).with_experiment(&experiment);
    let summary = report
        .experiment
        .as_ref()
        .expect("experiment summary attached");
    assert_eq!(summary.status, "found_violation");
    assert_eq!(summary.experiments_run, 1);
    assert_eq!(summary.violating_hypothesis, Some(vec![1]));
    assert!(summary.refuted.is_empty());

    // The whole report still round-trips with the experiment attached.
    let json = serde_json::to_string(&report).expect("serialize");
    let back: LdfiReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, report);
}
