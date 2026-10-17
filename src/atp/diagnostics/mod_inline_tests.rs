    use super::*;

    fn sample_envelope() -> AtpRuntimeEvidenceEnvelope {
        let mut envelope = AtpRuntimeEvidenceEnvelope::new("transfer-abcdef123456");
        envelope.cx_region_id = Some("region-root-42".to_string());
        envelope.transfer_actor_id = Some("actor-send-7".to_string());
        envelope.obligation_counts = AtpObligationEvidenceCounts {
            created: 3,
            committed: 2,
            aborted: 1,
            outstanding: 0,
            futurelock_waiters: 0,
        };
        envelope.cancellation = Some(AtpCancellationDrainEvidence {
            requested: true,
            drained: true,
            losers_drained: 2,
            drain_certificate_id: Some("drain-cert-1".to_string()),
            reason: "operator_cancel".to_string(),
        });
        envelope.finalizer = Some(AtpFinalizerEvidence {
            ran: true,
            completed: true,
            outcome: "all_finalizers_joined".to_string(),
        });
        envelope.replay = Some(AtpReplayEvidencePointer {
            trace_id: Some("trace-123456789".to_string()),
            crashpack_id: Some("crashpack-abcdef".to_string()),
            replay_command: "asupersync lab replay trace-123456789 --redacted".to_string(),
            redaction_policy: "atp-runtime-evidence-default".to_string(),
        });
        envelope.signals.push(AtpRuntimeEvidenceSignal::proof(
            "decision-ledger",
            AtpRuntimeSignalSource::EvidenceLedger,
            "decision ledger row binds path choice to transfer evidence",
            "evidence-ledger-row-1",
        ));
        envelope.signals.push(AtpRuntimeEvidenceSignal::advisory(
            "spectral-risk",
            AtpRuntimeSignalSource::SpectralWaitGraph,
            "spectral wait graph is degraded but not a correctness proof",
            "spectral-report-1",
        ));
        envelope.signals.push(AtpRuntimeEvidenceSignal::unavailable(
            "conformal-risk",
            AtpRuntimeSignalSource::ConformalAlert,
            "insufficient calibration window",
        ));
        envelope
    }

    #[test]
    fn bridge_keeps_proof_claims_separate_from_advisory_risk() {
        let doc = AtpRuntimeEvidenceBridge::explain(sample_envelope());
        assert_eq!(doc.schema_version, ATP_RUNTIME_EVIDENCE_EXPLANATION_SCHEMA);
        assert!(
            doc.proof_claims
                .iter()
                .any(|claim| claim.contains("obligation accounting closed cleanly"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .any(|claim| claim.contains("cancellation drain completed"))
        );
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("spectral_wait_graph [advisory_risk]"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("advisory_risk")),
            "advisory signals must not be upgraded to proof claims"
        );
        assert_eq!(
            doc.unavailable_signals,
            vec!["insufficient calibration window".to_string()]
        );
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let envelope = sample_envelope();
        let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
        let decoded: AtpRuntimeEvidenceEnvelope =
            serde_json::from_str(&encoded).expect("deserialize envelope");
        assert_eq!(decoded, envelope);
        assert_eq!(
            decoded.schema_version,
            ATP_RUNTIME_EVIDENCE_DIAGNOSTIC_SCHEMA
        );
    }

    #[test]
    fn user_explanation_redacts_correlation_ids_and_replay_command() {
        let envelope = sample_envelope();
        let doc = AtpRuntimeEvidenceBridge::explain_for_user(&envelope);
        assert!(doc.transfer_id.starts_with(REDACTED));
        assert_eq!(
            doc.evidence
                .replay
                .as_ref()
                .expect("replay pointer")
                .replay_command,
            REDACTED
        );
        assert!(
            doc.human_summary.len() < 400,
            "human explanation must stay concise"
        );
    }

    #[test]
    fn incomplete_obligations_downgrade_to_advisory_risk() {
        let mut envelope = sample_envelope();
        envelope.obligation_counts.outstanding = 1;
        let doc = AtpRuntimeEvidenceBridge::explain(envelope);
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("obligation accounting is incomplete"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("obligation accounting closed cleanly"))
        );
    }

    #[test]
    fn network_truth_pressure_keeps_measurements_out_of_proof_claims() {
        let mut envelope = sample_envelope();
        let mut network_truth = AtpNetworkTruthPressureModel::new(42_000);
        network_truth.path_id = Some("path-local-correlation-123456".to_string());
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::measured(
            AtpNetworkTruthMetric::Rtt,
            25_000,
            "micros",
            120_000,
            "pathlog-rtt-123456",
        )));
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::inferred(
            AtpNetworkTruthMetric::Loss,
            22,
            "permille",
            720_000,
            "pathlog-loss-123456",
            "loss inferred from ACK gap and retransmit evidence",
        )));
        assert!(network_truth.add_signal(AtpNetworkTruthSignal::unsupported(
            AtpNetworkTruthMetric::CongestionWindow,
            "platform did not expose cwnd",
        )));
        envelope.network_truth = Some(network_truth);

        let doc = AtpRuntimeEvidenceBridge::explain(envelope);
        assert!(
            doc.network_truth_explanations
                .iter()
                .any(|line| line.contains("network truth pressure degraded"))
        );
        assert!(
            doc.advisory_risks
                .iter()
                .any(|risk| risk.contains("network truth pressure is degraded"))
        );
        assert!(
            doc.proof_claims
                .iter()
                .all(|claim| !claim.contains("network truth")),
            "measured network facts must not become proof claims"
        );
        assert!(
            doc.unavailable_signals
                .iter()
                .any(|signal| signal == "network truth congestion_window unsupported")
        );
    }

    #[test]
    fn network_truth_model_bounds_cardinality_and_redacts_user_view() {
        let mut model = AtpNetworkTruthPressureModel::new(7);
        model.path_id = Some("path-sensitive-abcdef".to_string());
        for idx in 0..ATP_NETWORK_TRUTH_MAX_SIGNALS {
            assert!(model.add_signal(AtpNetworkTruthSignal::advisory(
                AtpNetworkTruthMetric::RelayDirectDelta,
                i64::try_from(idx).expect("idx fits"),
                "ppm",
                250_000,
                format!("relay-delta-sensitive-{idx}"),
                "relay path id contained a local endpoint",
            )));
        }
        assert!(!model.add_signal(AtpNetworkTruthSignal::measured(
            AtpNetworkTruthMetric::Rtt,
            1,
            "micros",
            1,
            "overflow",
        )));

        let redacted = model.redacted_for_user();
        assert_eq!(redacted.signals.len(), ATP_NETWORK_TRUTH_MAX_SIGNALS);
        assert!(
            redacted
                .path_id
                .as_deref()
                .unwrap_or_default()
                .starts_with(REDACTED)
        );
        assert!(
            redacted
                .signals
                .iter()
                .all(|signal| signal.detail.as_deref() == Some(REDACTED))
        );
    }

    #[test]
    fn network_truth_pressure_hysteresis_prevents_noisy_downshift() {
        let mut model = AtpNetworkTruthPressureModel::new(99);
        assert!(model.add_signal(AtpNetworkTruthSignal::inferred(
            AtpNetworkTruthMetric::DiskLag,
            510_000,
            "ppm",
            510_000,
            "disk-lag-row",
            "disk write lag remained near degraded threshold",
        )));
        assert_eq!(model.pressure_level(), AtpNetworkPressureLevel::Watch);
        assert_eq!(
            model.pressure_level_with_hysteresis(Some(AtpNetworkPressureLevel::Degraded)),
            AtpNetworkPressureLevel::Degraded
        );
    }
