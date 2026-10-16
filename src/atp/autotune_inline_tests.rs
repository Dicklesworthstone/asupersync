    use super::*;

    fn healthy_telemetry() -> AtpAutotuneTelemetry {
        AtpAutotuneTelemetry::new("trace-a", "workload-a").with_sample_count(16)
    }

    fn repair_inputs() -> AtpRepairRoiInputs {
        AtpRepairRoiInputs {
            trace_id: String::from("trace-repair"),
            workload_id: String::from("workload-repair"),
            expected_time_saved_micros: 400_000,
            encode_cpu_micros: 10_000,
            decode_cpu_micros: 10_000,
            bandwidth_overhead_bytes: 64 * 1_024,
            memory_pressure_permille: 50,
            stream_contention_permille: 25,
            relay_cost_micros_per_mib: 100_000,
            path_stability_permille: 950,
            resume_value_permille: 0,
            loss_permille: 1,
            available_peer_count: 1,
            path_mode: AtpRepairPathMode::Direct,
            requested_mode: None,
            missing_tail_chunks: 0,
            rtt_micros: 50_000,
            path_migration_events: 0,
            broadcast_peer_count: 0,
        }
    }

    #[test]
    fn metric_names_are_stable_and_namespaced() {
        let names: Vec<_> = ATP_AUTOTUNE_METRIC_NAMES
            .iter()
            .map(|metric| metric.as_str())
            .collect();

        assert_eq!(names.len(), 14);
        assert!(names.iter().all(|name| name.starts_with("atp.autotune.")));
        assert_eq!(names[0], "atp.autotune.rtt_micros");
        assert_eq!(names[13], "atp.autotune.migration_events");
    }

    #[test]
    fn metric_json_uses_stable_names() -> serde_json::Result<()> {
        let encoded = serde_json::to_string(&AtpAutotuneMetric::LossPermille)?;
        assert_eq!(encoded, r#""atp.autotune.loss_permille""#);

        let decoded: AtpAutotuneMetric = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, AtpAutotuneMetric::LossPermille);
        Ok(())
    }

    #[test]
    fn telemetry_report_collects_stable_metric_samples() -> Result<(), Box<dyn std::error::Error>> {
        let report = AtpAutotuneTelemetryReport::new("trace-report", "workload-report")
            .with_sample_count(16)
            .with_sample(AtpAutotuneMetric::RttMicros, 42_000)
            .with_sample(AtpAutotuneMetric::LossPermille, 7)
            .with_sample(AtpAutotuneMetric::EncodeBacklogSymbols, 128)
            .with_sample(AtpAutotuneMetric::RelayCostMicrosPerMiB, 250_000);

        let encoded = serde_json::to_string(&report)?;
        assert!(encoded.contains("atp.autotune.rtt_micros"));

        let decoded: AtpAutotuneTelemetryReport = serde_json::from_str(&encoded)?;
        let telemetry = decoded.into_telemetry()?;

        assert_eq!(telemetry.trace_id, "trace-report");
        assert_eq!(telemetry.workload_id, "workload-report");
        assert_eq!(telemetry.sample_count, 16);
        assert_eq!(telemetry.rtt_micros, Some(42_000));
        assert_eq!(telemetry.loss_permille, Some(7));
        assert_eq!(telemetry.encode_backlog_symbols, Some(128));
        assert_eq!(telemetry.relay_cost_micros_per_mib, Some(250_000));
        Ok(())
    }

    #[test]
    fn telemetry_report_rejects_out_of_range_metric_samples() {
        let report = AtpAutotuneTelemetryReport::new("trace-report", "workload-report")
            .with_sample(AtpAutotuneMetric::LossPermille, u64::from(u16::MAX) + 1);

        let error = report.into_telemetry();

        assert_eq!(
            error,
            Err(AtpAutotuneTelemetryError::MetricValueOutOfRange {
                metric: AtpAutotuneMetric::LossPermille,
                value: u64::from(u16::MAX) + 1,
                max: u64::from(u16::MAX),
            })
        );
    }

    #[test]
    fn telemetry_window_exports_stable_sample_report_order() {
        let mut telemetry =
            AtpAutotuneTelemetry::new("trace-window", "workload-window").with_sample_count(32);
        telemetry.loss_permille = Some(5);
        telemetry.rtt_micros = Some(40_000);
        telemetry.congestion_window_bytes = Some(64 * 1_048_576);
        telemetry.migration_events = Some(2);

        let report = telemetry.to_report();

        assert_eq!(report.trace_id, "trace-window");
        assert_eq!(report.workload_id, "workload-window");
        assert_eq!(report.sample_count, 32);
        assert_eq!(
            report.samples,
            vec![
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 40_000),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::LossPermille, 5),
                AtpAutotuneMetricSample::new(
                    AtpAutotuneMetric::CongestionWindowBytes,
                    64 * 1_048_576,
                ),
                AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 2),
            ]
        );
    }

    #[test]
    fn telemetry_window_roundtrips_through_sample_report() -> Result<(), Box<dyn std::error::Error>>
    {
        let telemetry = AtpAutotuneTelemetry {
            trace_id: String::from("trace-roundtrip"),
            workload_id: String::from("workload-roundtrip"),
            sample_count: 16,
            rtt_micros: Some(41_000),
            loss_permille: Some(3),
            pto_micros: Some(125_000),
            congestion_window_bytes: Some(96 * 1_048_576),
            in_flight_bytes: Some(32 * 1_048_576),
            send_buffer_queued_bytes: Some(2 * 1_048_576),
            receive_buffer_queued_bytes: Some(1_048_576),
            disk_read_lag_micros: Some(10_000),
            disk_write_lag_micros: Some(12_000),
            encode_backlog_symbols: Some(128),
            decode_backlog_symbols: Some(64),
            repair_roi_permille: Some(800),
            relay_cost_micros_per_mib: Some(250_000),
            migration_events: Some(1),
        };

        let report = AtpAutotuneTelemetryReport::from_telemetry(&telemetry);

        assert_eq!(report.samples.len(), ATP_AUTOTUNE_METRIC_NAMES.len());
        assert_eq!(
            report.samples[0],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RttMicros, 41_000)
        );
        assert_eq!(
            report.samples[13],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::MigrationEvents, 1)
        );
        assert_eq!(report.into_telemetry()?, telemetry);
        Ok(())
    }

    #[test]
    fn telemetry_window_zero_sample_count_roundtrip_uses_exported_sample_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut telemetry = AtpAutotuneTelemetry::new("trace-inferred", "workload-inferred");
        telemetry.rtt_micros = Some(25_000);
        telemetry.loss_permille = Some(1);

        let roundtrip = telemetry.to_report().into_telemetry()?;

        assert_eq!(roundtrip.trace_id, telemetry.trace_id);
        assert_eq!(roundtrip.workload_id, telemetry.workload_id);
        assert_eq!(roundtrip.sample_count, 2);
        assert_eq!(roundtrip.rtt_micros, Some(25_000));
        assert_eq!(roundtrip.loss_permille, Some(1));
        Ok(())
    }

    #[test]
    fn transfer_pressure_snapshot_exports_runtime_metrics_and_derived_costs()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot =
            AtpTransferPressureSnapshot::new("trace-transfer", "transfer-42").with_sample_count(12);
        snapshot.rtt_micros = Some(44_000);
        snapshot.loss_permille = Some(9);
        snapshot.pto_micros = Some(120_000);
        snapshot.congestion_window_bytes = Some(96 * 1_048_576);
        snapshot.in_flight_bytes = Some(32 * 1_048_576);
        snapshot.send_buffer_queued_bytes = Some(512 * 1_024);
        snapshot.receive_buffer_queued_bytes = Some(256 * 1_024);
        snapshot.disk_read_lag_micros = Some(8_000);
        snapshot.disk_write_lag_micros = Some(9_000);
        snapshot.encode_backlog_symbols = Some(64);
        snapshot.decode_backlog_symbols = Some(32);
        snapshot.repair_symbols_sent = Some(400);
        snapshot.useful_repair_symbols = Some(250);
        snapshot.relay_cost_micros = Some(300_000);
        snapshot.relay_bytes = Some(2 * 1_048_576);
        snapshot.migration_events = Some(1);

        assert_eq!(snapshot.repair_roi_permille(), Some(625));
        assert_eq!(snapshot.relay_cost_micros_per_mib(), Some(150_000));

        let report = snapshot.to_report();
        assert_eq!(report.trace_id, "trace-transfer");
        assert_eq!(report.workload_id, "transfer-42");
        assert_eq!(report.sample_count, 12);
        assert_eq!(report.samples.len(), ATP_AUTOTUNE_METRIC_NAMES.len());
        assert_eq!(
            report.samples[11],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RepairRoiPermille, 625)
        );
        assert_eq!(
            report.samples[12],
            AtpAutotuneMetricSample::new(AtpAutotuneMetric::RelayCostMicrosPerMiB, 150_000)
        );

        let telemetry = report.into_telemetry()?;
        assert_eq!(telemetry.trace_id, "trace-transfer");
        assert_eq!(telemetry.workload_id, "transfer-42");
        assert_eq!(telemetry.sample_count, 12);
        assert_eq!(telemetry.loss_permille, Some(9));
        assert_eq!(telemetry.repair_roi_permille, Some(625));
        assert_eq!(telemetry.relay_cost_micros_per_mib, Some(150_000));
        assert_eq!(telemetry.migration_events, Some(1));
        Ok(())
    }

    #[test]
    fn transfer_pressure_snapshot_omits_denominator_based_metrics_when_empty()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut snapshot = AtpTransferPressureSnapshot::new("trace-empty", "transfer-empty");
        snapshot.repair_symbols_sent = Some(0);
        snapshot.useful_repair_symbols = Some(10);
        snapshot.relay_cost_micros = Some(1_000);
        snapshot.relay_bytes = Some(0);
        snapshot.migration_events = Some(2);

        assert_eq!(snapshot.repair_roi_permille(), None);
        assert_eq!(snapshot.relay_cost_micros_per_mib(), None);

        let report = snapshot.to_report();
        assert_eq!(
            report.samples,
            vec![AtpAutotuneMetricSample::new(
                AtpAutotuneMetric::MigrationEvents,
                2,
            )]
        );

        let telemetry = report.into_telemetry()?;
        assert_eq!(telemetry.sample_count, 1);
        assert_eq!(telemetry.repair_roi_permille, None);
        assert_eq!(telemetry.relay_cost_micros_per_mib, None);
        assert_eq!(telemetry.migration_events, Some(2));
        Ok(())
    }

    #[test]
    fn healthy_window_grows_conservatively() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let decision = policy.decide(current, &healthy_telemetry());

        assert!(!decision.fail_closed);
        assert_eq!(decision.reason_code, "conservative_growth");
        assert_eq!(
            decision.settings.in_flight_bytes,
            current.in_flight_bytes + current.in_flight_bytes / 8
        );
        assert_eq!(decision.settings.stream_count, current.stream_count + 1);
        assert_eq!(
            decision.settings.chunk_size_bytes,
            current.chunk_size_bytes + current.chunk_size_bytes / 8
        );
        assert_eq!(
            decision.settings.repair_symbols_per_second,
            current.repair_symbols_per_second
        );
    }

    #[test]
    fn insufficient_samples_hold_existing_settings() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let telemetry = AtpAutotuneTelemetry::new("trace-a", "workload-a").with_sample_count(2);
        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert_eq!(decision.settings, current);
        assert_eq!(
            decision.bottlenecks[0].kind,
            AtpBottleneckKind::InsufficientTelemetry
        );
    }

    #[test]
    fn loss_backs_off_transport_and_raises_repair_rate() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::NetworkLoss)
        );
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count - 1);
        assert!(decision.settings.repair_symbols_per_second > current.repair_symbols_per_second);
    }

    #[test]
    fn low_repair_roi_reduces_repair_rate_without_transport_backoff() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.repair_roi_permille = Some(100);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert_eq!(decision.settings.in_flight_bytes, current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count);
        assert!(decision.settings.repair_symbols_per_second < current.repair_symbols_per_second);
    }

    #[test]
    fn relay_cost_backs_off_transport_without_repair_backoff() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.relay_cost_micros_per_mib = Some(policy.relay_cost_micros_per_mib + 1);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::RelayCost)
        );
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert_eq!(decision.settings.stream_count, current.stream_count - 1);
        assert_eq!(
            decision.settings.repair_symbols_per_second,
            current.repair_symbols_per_second
        );
    }

    #[test]
    fn repair_coordinator_clean_path_defaults_to_no_repair() {
        let coordinator = AtpRepairCoordinator::default();
        let mut inputs = repair_inputs();
        inputs.expected_time_saved_micros = 20_000;
        inputs.bandwidth_overhead_bytes = 0;

        let decision = coordinator.decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::NoRepair);
        assert_eq!(decision.mode, AtpRepairMode::Off);
        assert!(decision.fail_closed);
        assert_eq!(decision.reason_code, "repair_roi_not_positive");
        assert!(
            decision
                .factors
                .iter()
                .any(|factor| factor.kind == AtpRepairDecisionFactorKind::NetRoi)
        );
    }

    #[test]
    fn repair_coordinator_selects_exact_retransmit_for_low_loss_positive_roi() {
        let decision = AtpRepairCoordinator::default().decide(&repair_inputs());

        assert_eq!(decision.action, AtpRepairAction::ExactRetransmit);
        assert_eq!(decision.mode, AtpRepairMode::Tail);
        assert!(!decision.fail_closed);
        assert_eq!(decision.reason_code, "exact_retransmit_roi_positive");
        assert!(decision.net_roi_micros > 0);
    }

    #[test]
    fn repair_coordinator_selects_parity_trickle_for_moderate_loss() {
        let mut inputs = repair_inputs();
        inputs.loss_permille = 25;
        inputs.expected_time_saved_micros = 700_000;
        inputs.resume_value_permille = 200;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::ParityTrickle);
        assert_eq!(decision.mode, AtpRepairMode::Lossy);
        assert_eq!(decision.reason_code, "parity_trickle_roi_positive");
    }

    #[test]
    fn repair_coordinator_selects_burst_and_multi_peer_for_high_loss() {
        let coordinator = AtpRepairCoordinator::default();
        let mut burst = repair_inputs();
        burst.loss_permille = 120;
        burst.expected_time_saved_micros = 2_000_000;
        burst.resume_value_permille = 500;

        let burst_decision = coordinator.decide(&burst);
        assert_eq!(burst_decision.action, AtpRepairAction::BurstRepair);
        assert_eq!(burst_decision.mode, AtpRepairMode::Lossy);

        let mut multi_peer = burst;
        multi_peer.available_peer_count = 4;
        let multi_peer_decision = coordinator.decide(&multi_peer);
        assert_eq!(multi_peer_decision.action, AtpRepairAction::MultiPeerRepair);
        assert_eq!(multi_peer_decision.mode, AtpRepairMode::Swarm);
        assert_eq!(
            multi_peer_decision.reason_code,
            "multi_peer_repair_roi_positive"
        );
    }

    #[test]
    fn repair_coordinator_selects_relay_only_when_direct_path_is_unstable() {
        let mut inputs = repair_inputs();
        inputs.path_mode = AtpRepairPathMode::DirectAndRelay;
        inputs.path_stability_permille = 200;
        inputs.loss_permille = 40;
        inputs.expected_time_saved_micros = 1_000_000;
        inputs.relay_cost_micros_per_mib = 100_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::RelayOnlyRepair);
        assert_eq!(decision.mode, AtpRepairMode::MobileUnstable);
        assert_eq!(decision.reason_code, "relay_only_repair_roi_positive");
        assert!(
            decision
                .human_summary_lines()
                .join("\n")
                .contains("Repair mode: mobile_unstable")
        );
    }

    #[test]
    fn repair_coordinator_blocks_repair_under_high_memory_pressure() {
        let mut inputs = repair_inputs();
        inputs.expected_time_saved_micros = 2_000_000;
        inputs.memory_pressure_permille = 950;
        inputs.resume_value_permille = 100;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.action, AtpRepairAction::NoRepair);
        assert_eq!(decision.mode, AtpRepairMode::Off);
        assert_eq!(decision.reason_code, "blocked_by_memory_pressure");
        assert!(decision.fail_closed);
    }

    #[test]
    fn repair_coordinator_honors_manual_resume_mode_after_budget_gates() {
        let mut inputs = repair_inputs();
        inputs.requested_mode = Some(AtpRepairMode::ResumeRepair);
        inputs.resume_value_permille = 700;
        inputs.expected_time_saved_micros = 900_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.mode, AtpRepairMode::ResumeRepair);
        assert_eq!(decision.action, AtpRepairAction::ParityTrickle);
        assert_eq!(decision.mode_reason_code, "manual_repair_mode_requested");
        assert_eq!(
            decision.mode_cooldown_micros,
            AtpRepairCoordinatorPolicy::default().resume_cooldown_micros
        );
    }

    #[test]
    fn repair_coordinator_auto_selects_relay_expensive_mode() {
        let mut inputs = repair_inputs();
        inputs.path_mode = AtpRepairPathMode::DirectAndRelay;
        inputs.relay_cost_micros_per_mib =
            AtpRepairCoordinatorPolicy::default().max_relay_cost_micros_per_mib + 1;
        inputs.expected_time_saved_micros = 800_000;

        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(decision.mode, AtpRepairMode::RelayExpensive);
        assert_eq!(decision.action, AtpRepairAction::ExactRetransmit);
        assert_eq!(decision.mode_reason_code, "auto_relay_expensive_cost_gate");
    }

    #[test]
    fn repair_coordinator_auto_selects_satellite_broadcast_and_tail_modes() {
        let coordinator = AtpRepairCoordinator::default();
        let mut satellite = repair_inputs();
        satellite.rtt_micros =
            AtpRepairCoordinatorPolicy::default().satellite_high_bdp_min_rtt_micros;
        satellite.expected_time_saved_micros = 900_000;
        satellite.loss_permille = 20;
        assert_eq!(
            coordinator.decide(&satellite).mode,
            AtpRepairMode::SatelliteHighBdp
        );

        let mut broadcast = repair_inputs();
        broadcast.broadcast_peer_count = AtpRepairCoordinatorPolicy::default().broadcast_min_peers;
        broadcast.expected_time_saved_micros = 2_000_000;
        assert_eq!(
            coordinator.decide(&broadcast).mode,
            AtpRepairMode::Broadcast
        );

        let mut tail = repair_inputs();
        tail.missing_tail_chunks = AtpRepairCoordinatorPolicy::default().tail_min_missing_chunks;
        tail.expected_time_saved_micros = 300_000;
        assert_eq!(coordinator.decide(&tail).mode, AtpRepairMode::Tail);
    }

    #[test]
    fn repair_roi_inputs_derive_traceable_status_values_from_autotune() {
        let mut telemetry = healthy_telemetry();
        telemetry.rtt_micros = Some(50_000);
        telemetry.pto_micros = Some(300_000);
        telemetry.loss_permille = Some(100);
        telemetry.decode_backlog_symbols = Some(32);
        telemetry.repair_roi_permille = Some(700);
        telemetry.migration_events = Some(1);
        telemetry.relay_cost_micros_per_mib = Some(100_000);

        let inputs = AtpRepairRoiInputs::from_autotune_telemetry(&telemetry);
        let decision = AtpRepairCoordinator::default().decide(&inputs);

        assert_eq!(inputs.trace_id, "trace-a");
        assert_eq!(inputs.workload_id, "workload-a");
        assert_eq!(inputs.path_mode, AtpRepairPathMode::DirectAndRelay);
        assert_eq!(inputs.missing_tail_chunks, 32);
        assert_eq!(inputs.path_migration_events, 1);
        assert_eq!(inputs.rtt_micros, 50_000);
        assert!(inputs.expected_time_saved_micros > 0);
        assert_ne!(decision.action, AtpRepairAction::NoRepair);
    }

    #[test]
    fn buffer_and_disk_pressure_reduce_different_knobs() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.send_buffer_queued_bytes = Some(policy.buffer_pressure_bytes + 1);
        telemetry.disk_write_lag_micros = Some(policy.disk_lag_micros + 1);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(decision.settings.in_flight_bytes < current.in_flight_bytes);
        assert!(decision.settings.chunk_size_bytes < current.chunk_size_bytes);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::SendBufferPressure)
        );
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::DiskWriteLag)
        );
    }

    #[test]
    fn empty_ids_fail_closed() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let telemetry = AtpAutotuneTelemetry::new("", " ").with_sample_count(16);

        let decision = policy.decide(current, &telemetry);

        assert!(decision.fail_closed);
        assert!(
            decision
                .bottlenecks
                .iter()
                .any(|signal| signal.kind == AtpBottleneckKind::ContradictoryTelemetry)
        );
    }

    #[test]
    fn limits_are_enforced_on_growth_and_backoff() {
        let policy = AtpAutotunePolicy {
            limits: AtpAutotuneLimits {
                min_in_flight_bytes: 4,
                max_in_flight_bytes: 10,
                min_stream_count: 2,
                max_stream_count: 3,
                min_chunk_size_bytes: 8,
                max_chunk_size_bytes: 12,
                min_repair_symbols_per_second: 2,
                max_repair_symbols_per_second: 4,
            },
            ..AtpAutotunePolicy::default()
        };
        let current = AtpAutotuneSettings::new(100, 99, 100, 99);
        let decision = policy.decide(current, &healthy_telemetry());

        assert_eq!(decision.settings.in_flight_bytes, 10);
        assert_eq!(decision.settings.stream_count, 3);
        assert_eq!(decision.settings.chunk_size_bytes, 12);
        assert_eq!(decision.settings.repair_symbols_per_second, 4);
    }

    #[test]
    fn decision_receipt_records_stable_knob_changes_and_outcome() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = policy.decide_with_receipt(current, &telemetry);

        assert_eq!(
            receipt.schema_version,
            ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION
        );
        assert_eq!(receipt.trace_id, "trace-a");
        assert_eq!(receipt.workload_id, "workload-a");
        assert_eq!(receipt.sample_count, 16);
        assert_eq!(receipt.current_settings, current);
        assert_eq!(receipt.outcome, AtpAutotuneDecisionOutcome::PressureBackoff);
        assert_eq!(receipt.consumer_status, AtpAutotuneReceiptStatus::Degraded);
        assert_eq!(receipt.confidence, AtpAutotuneReceiptConfidence::FailClosed);
        assert_eq!(receipt.caveats, vec![String::from("network_loss")]);
        assert!(receipt.stale_sources.is_empty());
        assert_eq!(
            receipt.proof_pointer,
            AtpAutotuneReceiptProofPointer {
                receipt_schema_version: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
                trace_id: String::from("trace-a"),
                workload_id: String::from("workload-a"),
                sample_count: 16,
            }
        );
        assert!(receipt.validate_for_consumers().is_ok());
        assert!(
            receipt
                .omitted_sources
                .contains(&AtpAutotuneMetric::RttMicros)
        );
        assert!(
            !receipt
                .omitted_sources
                .contains(&AtpAutotuneMetric::LossPermille)
        );
        assert_eq!(receipt.changes.len(), 4);
        assert_eq!(receipt.changes[0].knob, AtpAutotuneKnob::InFlightBytes);
        assert_eq!(
            receipt.changes[0].direction,
            AtpAutotuneKnobDirection::Decrease
        );
        assert_eq!(receipt.changes[1].knob.as_str(), "stream_count");
        assert_eq!(
            receipt.changes[3].direction,
            AtpAutotuneKnobDirection::Increase
        );
        assert_eq!(
            receipt.selected_knobs(),
            vec![
                AtpAutotuneKnob::InFlightBytes,
                AtpAutotuneKnob::StreamCount,
                AtpAutotuneKnob::RepairSymbolsPerSecond,
            ]
        );

        let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
        assert!(encoded.contains(r#""consumer_status":"degraded""#));
        assert!(encoded.contains(r#""confidence":"fail_closed""#));
        let decoded: AtpAutotuneDecisionReceipt =
            serde_json::from_str(&encoded).expect("roundtrip receipt JSON");
        assert_eq!(decoded, receipt);

        let human = receipt.render_human_summary(true);
        assert!(human.contains("Status: degraded"));
        assert!(human.contains("Confidence: fail_closed"));
        assert!(human.contains("- network_loss: metric=atp.autotune.loss_permille"));
    }

    #[test]
    fn decision_receipt_classifies_malformed_and_no_win_outcomes() {
        let policy = AtpAutotunePolicy {
            limits: AtpAutotuneLimits {
                min_in_flight_bytes: 8 * 1_048_576,
                max_in_flight_bytes: 8 * 1_048_576,
                min_stream_count: 4,
                max_stream_count: 4,
                min_chunk_size_bytes: 256 * 1_024,
                max_chunk_size_bytes: 256 * 1_024,
                min_repair_symbols_per_second: 256,
                max_repair_symbols_per_second: 256,
            },
            ..AtpAutotunePolicy::default()
        };

        let malformed = policy.decide_with_receipt(
            AtpAutotuneSettings::default(),
            &AtpAutotuneTelemetry::new("", "workload-a").with_sample_count(16),
        );
        assert_eq!(
            malformed.outcome,
            AtpAutotuneDecisionOutcome::MalformedTelemetry
        );
        assert_eq!(
            malformed.consumer_status,
            AtpAutotuneReceiptStatus::Malformed
        );
        assert_eq!(
            malformed.validate_for_consumers(),
            Err(AtpAutotuneReceiptValidationError::MissingTraceId)
        );

        let bounded =
            policy.decide_with_receipt(AtpAutotuneSettings::default(), &healthy_telemetry());
        assert_eq!(bounded.outcome, AtpAutotuneDecisionOutcome::HoldNoWin);
        assert_eq!(bounded.consumer_status, AtpAutotuneReceiptStatus::NoWin);
        assert_eq!(
            bounded.confidence,
            AtpAutotuneReceiptConfidence::Conservative
        );
        assert_eq!(bounded.caveats, vec![String::from("bounded_no_win")]);
        assert!(
            bounded
                .changes
                .iter()
                .all(|change| change.direction == AtpAutotuneKnobDirection::Hold)
        );
    }

    #[test]
    fn decision_receipt_status_distinguishes_blocked_and_malformed_consumers() {
        let policy = AtpAutotunePolicy::default();
        let current = AtpAutotuneSettings::default();
        let blocked = policy.decide_with_receipt(
            current,
            &AtpAutotuneTelemetry::new("trace-blocked", "workload-blocked").with_sample_count(2),
        );

        assert_eq!(blocked.outcome, AtpAutotuneDecisionOutcome::HoldNoWin);
        assert_eq!(blocked.consumer_status, AtpAutotuneReceiptStatus::Blocked);
        assert_eq!(
            blocked.confidence,
            AtpAutotuneReceiptConfidence::InsufficientEvidence
        );
        assert_eq!(blocked.caveats, vec![String::from("insufficient_evidence")]);
        assert!(blocked.validate_for_consumers().is_ok());

        let mut unsupported = blocked.clone();
        unsupported.schema_version = String::from("atp-autotune-decision-receipt-v0");
        assert_eq!(
            unsupported.validate_for_consumers(),
            Err(
                AtpAutotuneReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_DECISION_RECEIPT_SCHEMA_VERSION),
                    actual: String::from("atp-autotune-decision-receipt-v0"),
                },
            )
        );

        let mut bad_pointer = blocked;
        bad_pointer.proof_pointer.trace_id = String::from("other-trace");
        assert_eq!(
            bad_pointer.validate_for_consumers(),
            Err(AtpAutotuneReceiptValidationError::ProofPointerMismatch {
                field: String::from("trace_id"),
            })
        );
    }

    #[test]
    fn application_state_defers_growth_until_hysteresis_is_satisfied() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let initial = state.settings;

        let first = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(first.consumer_status, AtpAutotuneReceiptStatus::Blocked);
        assert!(!first.applied);
        assert_eq!(state.settings, initial);
        assert_eq!(state.consecutive_growth_windows, 1);

        let second = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            second.outcome,
            AtpAutotuneApplicationOutcome::AppliedConfirmedGrowth
        );
        assert_eq!(second.consumer_status, AtpAutotuneReceiptStatus::Pass);
        assert!(second.applied);
        assert!(state.settings.in_flight_bytes > initial.in_flight_bytes);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_state_applies_pressure_backoff_immediately() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let initial = state.settings;
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = state.apply_policy_window(policy, &telemetry);

        assert_eq!(
            receipt.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(receipt.consumer_status, AtpAutotuneReceiptStatus::Degraded);
        assert!(receipt.applied);
        assert!(state.settings.in_flight_bytes < initial.in_flight_bytes);
        assert!(state.settings.repair_symbols_per_second > initial.repair_symbols_per_second);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_receipt_validates_consumer_identity_and_applied_flag() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let mut telemetry = healthy_telemetry();
        telemetry.loss_permille = Some(100);

        let receipt = state.apply_policy_window(policy, &telemetry);

        assert!(receipt.validate_for_consumers().is_ok());

        let mut unsupported_schema = receipt.clone();
        unsupported_schema.schema_version = String::from("atp-autotune-application-receipt-v0");
        assert_eq!(
            unsupported_schema.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::UnsupportedSchemaVersion {
                    expected: String::from(ATP_AUTOTUNE_APPLICATION_RECEIPT_SCHEMA_VERSION),
                    actual: String::from("atp-autotune-application-receipt-v0"),
                },
            )
        );

        let mut mismatched_trace = receipt.clone();
        mismatched_trace.trace_id = String::from("other-trace");
        assert_eq!(
            mismatched_trace.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptMismatch {
                    field: String::from("trace_id"),
                },
            )
        );

        let mut mismatched_applied = receipt;
        mismatched_applied.applied = false;
        assert_eq!(
            mismatched_applied.validate_for_consumers(),
            Err(AtpAutotuneApplicationReceiptValidationError::AppliedFlagMismatch)
        );
    }

    #[test]
    fn application_state_resets_pending_growth_after_noisy_pressure() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let first = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            first.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(state.consecutive_growth_windows, 1);

        let mut telemetry = healthy_telemetry();
        telemetry.send_buffer_queued_bytes = Some(policy.buffer_pressure_bytes + 1);
        let noisy = state.apply_policy_window(policy, &telemetry);

        assert_eq!(
            noisy.outcome,
            AtpAutotuneApplicationOutcome::AppliedPressureBackoff
        );
        assert_eq!(state.consecutive_growth_windows, 0);

        let next_clean = state.apply_policy_window(policy, &healthy_telemetry());
        assert_eq!(
            next_clean.outcome,
            AtpAutotuneApplicationOutcome::DeferredGrowthHysteresis
        );
        assert_eq!(state.consecutive_growth_windows, 1);
    }

    #[test]
    fn application_state_rejects_stale_receipts_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let stale_current = AtpAutotuneSettings::new(1, 1, 64 * 1_024, 0);
        let stale_receipt = policy.decide_with_receipt(stale_current, &healthy_telemetry());
        let before = state.settings;

        let applied = state.apply_decision_receipt(stale_receipt);

        assert_eq!(
            applied.outcome,
            AtpAutotuneApplicationOutcome::RejectedStaleReceipt
        );
        assert_eq!(
            applied.consumer_status,
            AtpAutotuneReceiptStatus::StaleEvidence
        );
        assert!(!applied.applied);
        assert_eq!(state.settings, before);
        assert_eq!(state.consecutive_growth_windows, 0);
    }

    #[test]
    fn application_state_rejects_malformed_receipts_without_mutation() {
        let policy = AtpAutotunePolicy::default();
        let mut state = AtpAutotuneApplicationState::default();
        let malformed = policy.decide_with_receipt(
            state.settings,
            &AtpAutotuneTelemetry::new("", "workload-a").with_sample_count(16),
        );
        let before = state.settings;

        let applied = state.apply_decision_receipt(malformed);

        assert_eq!(
            applied.outcome,
            AtpAutotuneApplicationOutcome::RejectedMalformedTelemetry
        );
        assert_eq!(applied.consumer_status, AtpAutotuneReceiptStatus::Malformed);
        assert!(!applied.applied);
        assert_eq!(state.settings, before);
        assert_eq!(state.consecutive_growth_windows, 0);
        assert!(matches!(
            applied.validate_for_consumers(),
            Err(
                AtpAutotuneApplicationReceiptValidationError::DecisionReceiptInvalid {
                    reason: AtpAutotuneReceiptValidationError::MissingTraceId,
                },
            )
        ));
    }
