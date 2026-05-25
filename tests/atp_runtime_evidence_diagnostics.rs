#![allow(missing_docs)]

use asupersync::atp::diagnostics::{
    ATP_NETWORK_TRUTH_PRESSURE_SCHEMA, AtpNetworkPressureLevel, AtpNetworkTruthMetric,
    AtpNetworkTruthPressureModel, AtpNetworkTruthSignal, AtpNetworkTruthSignalKind,
};
use asupersync::atp::{
    ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA,
    AtpCancellationDrainEvidence, AtpFinalizerEvidence, AtpObligationEvidenceCounts,
    AtpReplayEvidencePointer, AtpRuntimeEvidenceBridge, AtpRuntimeEvidenceEnvelope,
    AtpRuntimeEvidenceSignal, AtpRuntimeSignalClass, AtpRuntimeSignalSource,
};

fn runtime_evidence_envelope() -> AtpRuntimeEvidenceEnvelope {
    let mut envelope = AtpRuntimeEvidenceEnvelope::new("transfer-public-correlation-123456");
    envelope.cx_region_id = Some("cx-region-runtime-root-abcdef".to_string());
    envelope.transfer_actor_id = Some("transfer-actor-send-654321".to_string());
    envelope.obligation_counts = AtpObligationEvidenceCounts {
        created: 4,
        committed: 3,
        aborted: 1,
        outstanding: 0,
        futurelock_waiters: 0,
    };
    envelope.cancellation = Some(AtpCancellationDrainEvidence {
        requested: true,
        drained: true,
        losers_drained: 2,
        drain_certificate_id: Some("drain-cert-001".to_string()),
        reason: "path_race_cancelled_loser".to_string(),
    });
    envelope.finalizer = Some(AtpFinalizerEvidence {
        ran: true,
        completed: true,
        outcome: "region_finalizers_joined".to_string(),
    });
    envelope.replay = Some(AtpReplayEvidencePointer {
        trace_id: Some("trace-public-correlation-abcdef".to_string()),
        crashpack_id: Some("crashpack-public-correlation-654321".to_string()),
        replay_command: "asupersync lab replay trace-public-correlation-abcdef".to_string(),
        redaction_policy: "atp-runtime-evidence-default".to_string(),
    });
    envelope.signals.push(AtpRuntimeEvidenceSignal::proof(
        "ledger-row",
        AtpRuntimeSignalSource::EvidenceLedger,
        "decision ledger row binds runtime trace to transfer proof",
        "ledger-row-public-correlation",
    ));
    envelope.signals.push(AtpRuntimeEvidenceSignal::advisory(
        "spectral-health",
        AtpRuntimeSignalSource::SpectralWaitGraph,
        "spectral wait graph indicates elevated contention",
        "spectral-public-correlation",
    ));
    envelope.signals.push(AtpRuntimeEvidenceSignal::unavailable(
        "conformal-alert",
        AtpRuntimeSignalSource::ConformalAlert,
        "calibration window unavailable",
    ));
    envelope
}

fn network_truth_pressure_model() -> AtpNetworkTruthPressureModel {
    let mut model = AtpNetworkTruthPressureModel::new(1_234_567);
    model.path_id = Some("path-public-correlation-abcdef".to_string());
    assert!(model.add_signal(AtpNetworkTruthSignal::measured(
        AtpNetworkTruthMetric::Rtt,
        28_000,
        "micros",
        120_000,
        "pathlog-rtt-public-correlation",
    )));
    assert!(model.add_signal(AtpNetworkTruthSignal::measured(
        AtpNetworkTruthMetric::Pto,
        0,
        "count",
        0,
        "pathlog-pto-public-correlation",
    )));
    assert!(model.add_signal(AtpNetworkTruthSignal::inferred(
        AtpNetworkTruthMetric::Loss,
        18,
        "permille",
        700_000,
        "pathlog-loss-public-correlation",
        "loss inferred from ACK gaps and resend pressure",
    )));
    assert!(model.add_signal(AtpNetworkTruthSignal::advisory(
        AtpNetworkTruthMetric::RelayDirectDelta,
        140_000,
        "ppm",
        520_000,
        "relay-delta-public-correlation",
        "relay delta is derived from current profile rather than a direct OS signal",
    )));
    assert!(model.add_signal(AtpNetworkTruthSignal::unsupported(
        AtpNetworkTruthMetric::CongestionWindow,
        "cwnd unavailable on this platform",
    )));
    model
}

#[test]
fn runtime_evidence_bridge_labels_proofs_advisory_and_unavailable_signals() {
    let doc = AtpRuntimeEvidenceBridge::explain(runtime_evidence_envelope());

    assert_eq!(doc.schema_version, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA);
    assert_eq!(
        doc.evidence.schema_version,
        ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA
    );
    assert!(
        doc.proof_claims
            .iter()
            .any(|claim| claim.contains("obligation accounting closed cleanly")),
        "obligation counts should become a proof claim: {:#?}",
        doc.proof_claims
    );
    assert!(
        doc.proof_claims
            .iter()
            .any(|claim| claim.contains("deterministic replay pointer is present")),
        "replay pointer should be surfaced as proof-backed runtime evidence"
    );
    assert!(
        doc.advisory_risks
            .iter()
            .any(|risk| risk.contains("spectral_wait_graph [advisory_risk]")),
        "spectral signals must stay advisory: {:#?}",
        doc.advisory_risks
    );
    assert!(
        doc.unavailable_signals
            .iter()
            .any(|signal| signal == "calibration window unavailable"),
        "unavailable conformal evidence must be an explicit downgrade"
    );

    let spectral_signal = doc
        .evidence
        .signals
        .iter()
        .find(|signal| signal.signal_id == "spectral-health")
        .expect("spectral signal is retained");
    assert_eq!(spectral_signal.class, AtpRuntimeSignalClass::AdvisoryRisk);
    assert!(!spectral_signal.class.is_proof());
}

#[test]
fn user_explanation_is_backed_by_structured_trace_but_redacts_correlation_ids() {
    let envelope = runtime_evidence_envelope();
    let doc = AtpRuntimeEvidenceBridge::explain_for_user(&envelope);

    assert_eq!(doc.schema_version, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA);
    assert!(
        doc.human_summary
            .contains("ATP runtime evidence includes advisory or unavailable signals")
    );
    assert!(!doc.transfer_id.contains("public-correlation"));
    assert_eq!(
        doc.evidence.replay.as_ref().unwrap().replay_command,
        "<redacted>"
    );
    assert!(
        doc.evidence
            .signals
            .iter()
            .all(|signal| signal.evidence_ref.as_deref() != Some("ledger-row-public-correlation"))
    );
}

#[test]
fn runtime_evidence_envelope_round_trips_as_contract_json() {
    let envelope = runtime_evidence_envelope();
    let json = serde_json::to_string(&envelope).expect("runtime evidence envelope serializes");
    let roundtrip: AtpRuntimeEvidenceEnvelope =
        serde_json::from_str(&json).expect("runtime evidence envelope deserializes");

    assert_eq!(roundtrip, envelope);
}

#[test]
fn network_truth_pressure_model_distinguishes_facts_estimates_and_unsupported() {
    let mut envelope = runtime_evidence_envelope();
    envelope.network_truth = Some(network_truth_pressure_model());

    let doc = AtpRuntimeEvidenceBridge::explain(envelope);
    let network_truth = doc
        .evidence
        .network_truth
        .as_ref()
        .expect("network truth model is carried in diagnostic evidence");

    assert_eq!(
        network_truth.schema_version,
        ATP_NETWORK_TRUTH_PRESSURE_SCHEMA
    );
    assert_eq!(
        network_truth.pressure_level(),
        AtpNetworkPressureLevel::Degraded
    );
    assert!(
        network_truth.signals.iter().any(|signal| signal.kind
            == AtpNetworkTruthSignalKind::MeasuredFact
            && signal.metric == AtpNetworkTruthMetric::Rtt),
        "RTT must be represented as a measured fact"
    );
    assert!(
        network_truth.signals.iter().any(|signal| signal.kind
            == AtpNetworkTruthSignalKind::AdvisoryEstimate
            && signal.metric == AtpNetworkTruthMetric::RelayDirectDelta),
        "relay/direct delta must stay an advisory estimate"
    );
    assert!(
        doc.unavailable_signals
            .iter()
            .any(|signal| signal == "network truth congestion_window unsupported"),
        "unsupported platform truth must be explicit"
    );
    assert!(
        doc.network_truth_explanations
            .iter()
            .any(|line| line.contains("network truth pressure degraded"))
    );
    assert!(
        doc.proof_claims
            .iter()
            .all(|claim| !claim.contains("network truth")),
        "network truth facts and estimates must not be upgraded to proof claims"
    );
}

#[test]
fn user_network_truth_explanation_redacts_path_and_source_correlation() {
    let mut envelope = runtime_evidence_envelope();
    envelope.network_truth = Some(network_truth_pressure_model());

    let doc = AtpRuntimeEvidenceBridge::explain_for_user(&envelope);
    let network_truth = doc
        .evidence
        .network_truth
        .as_ref()
        .expect("network truth model is retained");

    assert!(
        network_truth
            .path_id
            .as_deref()
            .unwrap_or_default()
            .starts_with("<redacted>")
    );
    assert!(network_truth.signals.iter().all(|signal| {
        signal
            .source_ref
            .as_deref()
            .is_none_or(|source_ref| source_ref.starts_with("<redacted>"))
    }));
    assert!(
        network_truth
            .signals
            .iter()
            .filter_map(|signal| signal.detail.as_deref())
            .all(|detail| detail == "<redacted>")
    );
}
