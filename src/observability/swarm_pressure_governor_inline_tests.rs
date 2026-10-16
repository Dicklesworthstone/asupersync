    use super::*;
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::runtime::resource_monitor::ResourceType;
    use crate::types::Budget;

    fn create_test_swarm_governor() -> SwarmPressureGovernor {
        create_test_swarm_governor_with_config(SwarmPressureGovernorConfig::default())
    }

    fn create_test_swarm_governor_with_config(
        config: SwarmPressureGovernorConfig,
    ) -> SwarmPressureGovernor {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let resource_monitor = runtime.resource_monitor();
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        SwarmPressureGovernor::new(config, resource_monitor, pressure_governor)
    }

    fn admission_rank(decision: AdmissionDecision) -> u8 {
        match decision {
            AdmissionDecision::Admit => 0,
            AdmissionDecision::AdmitWithBackpressure => 1,
            AdmissionDecision::Reject => 2,
        }
    }

    fn fourth_wave_sample_evidence_rows() -> Vec<FourthWaveEvidenceRow> {
        vec![
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::BeadMailContext,
                "mail-ready-clean",
                FourthWaveEvidenceClaimStatus::CoordinationEvidence,
                8_400,
            )
            .with_age_seconds(120),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::CapacitySnapshot,
                "large-host-64c-256g",
                FourthWaveEvidenceClaimStatus::SchemaContract,
                8_400,
            )
            .with_age_seconds(150),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::LabReplay,
                "large-host-low-pressure-replay",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_600,
            )
            .with_age_seconds(200),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::ObligationPressure,
                "obligation-drain-low",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_400,
            )
            .with_age_seconds(170),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::RchProofLane,
                "remote-required-admit",
                FourthWaveEvidenceClaimStatus::RemoteProof,
                8_400,
            )
            .with_age_seconds(180),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::RegionPressure,
                "regions-low",
                FourthWaveEvidenceClaimStatus::ReplayBacked,
                8_400,
            )
            .with_age_seconds(185),
            FourthWaveEvidenceRow::new(
                FourthWaveEvidenceClass::WorkerEnvelope,
                "worker-envelope-low",
                FourthWaveEvidenceClaimStatus::SchemaContract,
                8_400,
            )
            .with_age_seconds(160),
        ]
    }

    fn fourth_wave_sample_input(scenario_id: &str) -> FourthWaveGovernorInput {
        FourthWaveGovernorInput {
            bead_id: "asupersync-86fe9v.2".to_string(),
            scenario_id: scenario_id.to_string(),
            objective: FourthWaveGovernorObjective::required("release-proof-safety", 8_000),
            pressure_snapshot: FourthWavePressureSnapshot {
                schema_version: FOURTH_WAVE_PRESSURE_SNAPSHOT_SCHEMA_VERSION.to_string(),
                snapshot_id: format!("fw-snapshot-{}", fourth_wave_scenario_slug(scenario_id)),
                input_status: FourthWaveInputStatus::Complete,
                policy_version: FOURTH_WAVE_GOVERNOR_POLICY_VERSION.to_string(),
                input_artifact_hashes: vec![
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ],
                normalized_host_capacity: FourthWaveHostCapacity {
                    host_profile_id: "large-host-64c-256g".to_string(),
                    physical_core_count: 64,
                    available_parallelism: 64,
                    numa_node_count: 2,
                    memory_total_mib: 262_144,
                    cgroup_cpu_quota_millis: 64_000,
                },
                worker_envelope: FourthWaveWorkerEnvelope {
                    local_agent_slots: 24,
                    max_agent_count: 48,
                    active_agent_count: 16,
                    remote_worker_slots: 6,
                    cache_warm_remote_workers: 3,
                },
                core_envelope: FourthWaveCoreEnvelope {
                    local_core_pressure_bps: 3_200,
                    remote_core_pressure_bps: 2_800,
                    reserved_critical_cores: 8,
                    admit_core_budget_bps: 7_600,
                },
                memory_envelope: FourthWaveMemoryEnvelope {
                    total_mib: 262_144,
                    available_mib: 180_224,
                    reserved_validation_mib: 32_768,
                    artifact_cache_mib: 8_192,
                    memory_pressure_bps: 3_100,
                },
                active_region_pressure: FourthWaveActiveRegionPressure {
                    active_region_count: 28,
                    region_limit: 128,
                    queue_depth: 18,
                    region_pressure_bps: 2_600,
                },
                obligation_pressure: FourthWaveObligationPressure {
                    live_obligation_count: 96,
                    drain_backlog: 4,
                    leak_suspect_count: 0,
                    obligation_pressure_bps: 1_800,
                },
                rch_admission_state: FourthWaveRchAdmissionState {
                    remote_required: true,
                    workers_admissible: true,
                    selected_worker: Some("rch-worker://redacted/cache-warm-01".to_string()),
                    local_fallback_marker_detected: false,
                    first_blocker: None,
                },
                bead_mail_workload_context: FourthWaveBeadMailWorkloadContext {
                    ready_beads: 2,
                    in_progress_beads: 1,
                    reserved_path_count: 4,
                    ack_required_backlog: 0,
                    tracker_writable: true,
                },
                lab_replay_metadata: FourthWaveLabReplayMetadata {
                    scenario_family: "large_host_low_pressure".to_string(),
                    seed: 860_001,
                    replay_artifact: Some(
                        "artifacts/large_host_topology_corpus_v1.json".to_string(),
                    ),
                    replay_backed: true,
                },
                evidence_rows: fourth_wave_sample_evidence_rows(),
            },
        }
    }

    #[test]
    fn fourth_wave_governor_admits_required_work_with_stable_receipt() {
        let input = fourth_wave_sample_input("FW-GOVERNOR-ADMIT-REQUIRED-WORK");

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::AdmitRequiredWork
        );
        assert_eq!(receipt.rule_id, "admit-required-work");
        assert!(!receipt.fail_closed);
        assert_eq!(
            receipt.decision_id,
            "fw-governor-decision/admit-required-work/policy-v1"
        );
        assert_eq!(receipt.confidence_bps, 8_400);
        assert_eq!(receipt.evidence_rows.len(), 7);
        assert!(receipt.rejected_rows.is_empty());
        assert_eq!(receipt.log_fields.selected_action, "admit_required_work");
        assert_eq!(receipt.log_fields.rejected_row_count, 0);
        assert_eq!(
            receipt.objective_row.objective_id,
            input.objective.objective_id
        );
        assert_eq!(receipt.evidence_quality.required_input_classes_present, 7);
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "brownout-optional-work")
        );
    }

    #[test]
    fn fourth_wave_governor_zero_evidence_fails_missing_required_evidence() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-MISSING-REQUIRED-EVIDENCE");
        input.pressure_snapshot.evidence_rows.clear();

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedMissingEvidence
        );
        assert_eq!(receipt.rule_id, "missing-required-evidence");
        assert!(receipt.fail_closed);
        assert_eq!(receipt.confidence_bps, 0);
        assert_eq!(
            receipt.rejected_rows,
            vec![
                "bead_mail_context",
                "capacity_snapshot",
                "lab_replay",
                "obligation_pressure",
                "rch_proof_lane",
                "region_pressure",
                "worker_envelope"
            ]
        );
        assert_eq!(receipt.evidence_quality.row_count, 0);
        assert_eq!(receipt.log_fields.rejected_row_count, 7);
    }

    #[test]
    fn fourth_wave_governor_stale_evidence_fails_closed() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-STALE-EVIDENCE");
        input.pressure_snapshot.evidence_rows[2].evidence_age_seconds =
            FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS + 1;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedStaleEvidence
        );
        assert_eq!(receipt.rule_id, "stale-evidence");
        assert_eq!(
            receipt.rejected_rows,
            vec!["large-host-low-pressure-replay"]
        );
        assert!(
            receipt
                .non_action_reason
                .contains("evidence older than 900 seconds")
        );
        assert!(receipt.fail_closed);
    }

    #[test]
    fn fourth_wave_governor_local_fallback_marker_preempts_stale_and_pressure() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-LOCAL-RCH-FALLBACK");
        input.pressure_snapshot.memory_envelope.memory_pressure_bps = 9_300;
        input.pressure_snapshot.evidence_rows[0].evidence_age_seconds =
            FOURTH_WAVE_MAX_EVIDENCE_AGE_SECONDS + 1;
        input
            .pressure_snapshot
            .rch_admission_state
            .local_fallback_marker_detected = true;
        let local_fallback_row = input.pressure_snapshot.evidence_rows[4]
            .clone()
            .with_local_fallback_marker("local_fallback_detected");
        input.pressure_snapshot.evidence_rows[4] = local_fallback_row;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedLocalRchFallback
        );
        assert_eq!(receipt.rule_id, "local-rch-fallback");
        assert_eq!(receipt.rejected_rows, vec!["remote-required-admit"]);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "local_fallback_detected"
        );
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "stale-evidence"
                    && alternative.reason.contains("skipped"))
        );
    }

    #[test]
    fn fourth_wave_governor_advisory_only_without_replay_fails_closed() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-ADVISORY-ONLY");
        input.pressure_snapshot.lab_replay_metadata.replay_backed = false;
        input.pressure_snapshot.lab_replay_metadata.replay_artifact = None;
        for row in &mut input.pressure_snapshot.evidence_rows {
            row.claim_status = FourthWaveEvidenceClaimStatus::AdvisoryOnly;
            row.confidence_bps = 4_200;
            row.rejected_reason = "advisory_without_replay".to_string();
        }

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedAdvisoryOnly
        );
        assert_eq!(receipt.rule_id, "advisory-only-evidence");
        assert_eq!(receipt.rejected_rows.len(), 7);
        assert_eq!(receipt.confidence_bps, 0);
        assert_eq!(receipt.evidence_quality.advisory_only_row_count, 7);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "advisory_without_replay"
        );
    }

    #[test]
    fn fourth_wave_governor_defer_no_remote_worker_no_win_refuses_local_fallback() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-DEFER-NO-REMOTE-WORKER");
        input
            .pressure_snapshot
            .rch_admission_state
            .workers_admissible = false;
        input.pressure_snapshot.rch_admission_state.selected_worker = None;
        input.pressure_snapshot.rch_admission_state.first_blocker =
            Some("active_project_exclusion".to_string());
        input.pressure_snapshot.evidence_rows[4].claim_status =
            FourthWaveEvidenceClaimStatus::RemoteRefusal;
        input.pressure_snapshot.evidence_rows[4].rejected_reason =
            "active_project_exclusion".to_string();
        input.pressure_snapshot.evidence_rows[4].confidence_bps = 7_800;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::DeferNoRemoteWorker
        );
        assert_eq!(receipt.rule_id, "remote-required-no-worker");
        assert!(!receipt.fail_closed);
        assert_eq!(receipt.rejected_rows, vec!["remote-required-admit"]);
        assert_eq!(
            receipt.log_fields.first_rejected_row_reason,
            "active_project_exclusion"
        );
        assert!(receipt.non_action_reason.contains("local fallback refused"));
        assert_eq!(receipt.confidence_bps, 7_800);
    }

    #[test]
    fn fourth_wave_governor_pressure_boundaries_brownout_optional_work() {
        let mut exact_memory = fourth_wave_sample_input("FW-GOVERNOR-BROWNOUT-OPTIONAL-WORK");
        exact_memory
            .pressure_snapshot
            .memory_envelope
            .memory_pressure_bps = FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS;
        let receipt = evaluate_fourth_wave_governor(&exact_memory);
        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::BrownoutOptionalWork
        );
        assert_eq!(
            receipt.non_action_reason,
            "optional work exceeds memory pressure budget"
        );
        assert!(!receipt.fail_closed);

        let mut exact_core_budget = fourth_wave_sample_input("FW-GOVERNOR-ADMIT-EXACT-CORE");
        exact_core_budget
            .pressure_snapshot
            .core_envelope
            .local_core_pressure_bps = 7_600;
        assert_eq!(
            evaluate_fourth_wave_governor(&exact_core_budget).selected_action,
            FourthWaveGovernorAction::AdmitRequiredWork
        );

        let mut cpu_heavy = fourth_wave_sample_input("FW-GOVERNOR-CPU-BROWNOUT");
        cpu_heavy
            .pressure_snapshot
            .core_envelope
            .local_core_pressure_bps = 7_601;
        assert_eq!(
            evaluate_fourth_wave_governor(&cpu_heavy).non_action_reason,
            "optional work exceeds core pressure budget"
        );

        let mut region_heavy = fourth_wave_sample_input("FW-GOVERNOR-REGION-BROWNOUT");
        region_heavy
            .pressure_snapshot
            .active_region_pressure
            .region_pressure_bps = FOURTH_WAVE_BROWNOUT_PRESSURE_THRESHOLD_BPS;
        assert_eq!(
            evaluate_fourth_wave_governor(&region_heavy).non_action_reason,
            "optional work exceeds region pressure budget"
        );

        let mut obligation_heavy = fourth_wave_sample_input("FW-GOVERNOR-OBLIGATION-BROWNOUT");
        obligation_heavy
            .pressure_snapshot
            .obligation_pressure
            .leak_suspect_count = 1;
        assert_eq!(
            evaluate_fourth_wave_governor(&obligation_heavy).non_action_reason,
            "optional work exceeds obligation pressure budget"
        );
    }

    #[test]
    fn fourth_wave_governor_malformed_input_preempts_evidence_rules() {
        let mut input = fourth_wave_sample_input("FW-GOVERNOR-FAIL-MALFORMED-INPUT");
        input.pressure_snapshot.input_status = FourthWaveInputStatus::Malformed;
        input.pressure_snapshot.evidence_rows.clear();
        input
            .pressure_snapshot
            .rch_admission_state
            .local_fallback_marker_detected = true;

        let receipt = evaluate_fourth_wave_governor(&input);

        assert_eq!(
            receipt.selected_action,
            FourthWaveGovernorAction::FailClosedMalformedInput
        );
        assert_eq!(receipt.rule_id, "malformed-input");
        assert_eq!(
            receipt.non_action_reason,
            "snapshot input_status is malformed"
        );
        assert_eq!(
            receipt.rejected_rows,
            vec!["fw-snapshot-fail-malformed-input"]
        );
        assert!(
            receipt
                .rejected_alternatives
                .iter()
                .any(|alternative| alternative.rule_id == "local-rch-fallback"
                    && alternative.reason.contains("skipped"))
        );
    }

    #[test]
    fn test_resource_envelope_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 1), 1000, 1000000, 100);

        // Should allow allocation within budget
        assert!(envelope.reserve_memory(500).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.5);

        // Should reject allocation exceeding budget
        assert!(envelope.reserve_memory(600).is_err());

        // Should allow allocation after release
        envelope.release_memory(200);
        assert!(envelope.reserve_memory(400).is_ok());
        assert_eq!(envelope.memory_utilization(), 0.7);
    }

    #[test]
    fn test_resource_envelope_cpu_and_io_budget_enforcement() {
        let envelope = ResourceEnvelope::new(RegionId::new_for_test(1, 2), 1000, 100, 10);

        assert!(envelope.reserve_cpu(60).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.6);
        assert!(matches!(
            envelope.reserve_cpu(50),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "cpu"
        ));
        envelope.release_cpu(25);
        assert!(envelope.reserve_cpu(40).is_ok());
        assert_eq!(envelope.cpu_utilization(), 0.75);

        assert!(envelope.reserve_io(7).is_ok());
        assert_eq!(envelope.io_utilization(), 0.7);
        assert!(matches!(
            envelope.reserve_io(4),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "io"
        ));
        envelope.release_io(3);
        assert!(envelope.reserve_io(2).is_ok());
        assert_eq!(envelope.io_utilization(), 0.6);
    }

    #[test]
    fn test_resource_envelope_concurrent_reservations_do_not_overshoot_budget() {
        let envelope = std::sync::Arc::new(ResourceEnvelope::new(
            RegionId::new_for_test(1, 3),
            64,
            100,
            100,
        ));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let envelope = std::sync::Arc::clone(&envelope);
            handles.push(std::thread::spawn(move || {
                let mut successful_reservations = 0_u64;
                for _ in 0..32 {
                    if envelope.reserve_memory(1).is_ok() {
                        successful_reservations += 1;
                    }
                }
                successful_reservations
            }));
        }

        let successful_reservations: u64 = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation thread should finish"))
            .sum();

        assert_eq!(successful_reservations, 64);
        assert_eq!(envelope.memory_used.load(Ordering::Relaxed), 64);
        assert!(matches!(
            envelope.reserve_memory(1),
            Err(SwarmPressureError::EnvelopeBudgetExceeded { resource, .. }) if resource == "memory"
        ));
    }

    #[test]
    fn test_register_region_envelope_binds_envelope_to_region_key() {
        let governor = create_test_swarm_governor();
        let actual_region_id = RegionId::new_for_test(9, 1);
        let stale_admission_region_id = RegionId::new_for_test(1, 99);
        let envelope = ResourceEnvelope::new(stale_admission_region_id, 2048, 100, 10);

        governor.register_region_envelope(actual_region_id, envelope);

        let registered = governor
            .get_region_envelope(actual_region_id)
            .expect("registered region envelope should be retrievable by actual region id");
        assert_eq!(registered.region_id, actual_region_id);
        assert!(
            governor
                .get_region_envelope(stale_admission_region_id)
                .is_none(),
            "stale admission id must not become a separately registered region"
        );
    }

    #[test]
    fn test_unregister_region_envelope_updates_active_region_metrics() {
        let governor = create_test_swarm_governor();
        let region_id = RegionId::new_for_test(10, 1);
        let envelope = ResourceEnvelope::new(region_id, 4096, 100, 10);
        envelope
            .reserve_memory(512)
            .expect("test reservation should fit inside the envelope budget");

        governor.register_region_envelope(region_id, envelope);
        assert_eq!(governor.metrics().active_region_count, 1);

        let removed = governor
            .unregister_region_envelope(region_id)
            .expect("registered envelope should be returned exactly once");
        assert_eq!(removed.region_id, region_id);
        assert_eq!(removed.memory_used.load(Ordering::Relaxed), 512);
        assert!(governor.get_region_envelope(region_id).is_none());
        assert_eq!(governor.metrics().active_region_count, 0);
        assert!(governor.unregister_region_envelope(region_id).is_none());
    }

    #[test]
    fn test_metrics_report_active_envelope_utilization() {
        let governor = create_test_swarm_governor();
        let low_region_id = RegionId::new_for_test(11, 1);
        let high_region_id = RegionId::new_for_test(12, 1);
        let low_envelope = ResourceEnvelope::new(low_region_id, 1024, 100, 10);
        low_envelope
            .reserve_memory(512)
            .expect("memory reservation should fit");
        low_envelope
            .reserve_cpu(25)
            .expect("cpu reservation should fit");
        low_envelope
            .reserve_io(3)
            .expect("io reservation should fit");

        let high_envelope = ResourceEnvelope::new(high_region_id, 1000, 100, 20);
        high_envelope
            .reserve_memory(900)
            .expect("memory reservation should fit");
        high_envelope
            .reserve_cpu(80)
            .expect("cpu reservation should fit");
        high_envelope
            .reserve_io(4)
            .expect("io reservation should fit");

        governor.register_region_envelope(low_region_id, low_envelope);
        governor.register_region_envelope(high_region_id, high_envelope);

        let metrics = governor.metrics();
        assert_eq!(metrics.active_region_count, 2);
        assert_eq!(metrics.max_memory_utilization_scaled, 9000);
        assert_eq!(metrics.max_cpu_utilization_scaled, 8000);
        assert_eq!(metrics.max_io_utilization_scaled, 3000);
    }

    #[test]
    fn test_swarm_governor_region_limits() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_regions_per_instance = 2;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );

        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");

        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);

        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        // First two admissions should succeed
        let decision1 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("First admission should succeed");
        assert!(matches!(decision1.decision, AdmissionDecision::Admit));

        let decision2 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Second admission should succeed");
        assert!(matches!(decision2.decision, AdmissionDecision::Admit));

        // Add envelopes to simulate active regions
        governor
            .register_region_envelope(RegionId::new_for_test(1, 1), decision1.envelope.unwrap());
        governor
            .register_region_envelope(RegionId::new_for_test(2, 1), decision2.envelope.unwrap());

        // Third admission should be rejected
        let decision3 = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Third admission check should succeed");
        assert!(matches!(decision3.decision, AdmissionDecision::Reject));
        assert!(decision3.reason.contains("Region limit exceeded"));
    }

    #[test]
    fn test_disabled_governance_admissions_update_metrics() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.enabled = false;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let requested_memory = governor.config.default_memory_budget_bytes + 4096;

        let decision = governor
            .check_region_admission(&cx, RegionPriority::BestEffort, Some(requested_memory))
            .expect("disabled governance should always produce an admission decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        let envelope = decision
            .envelope
            .expect("disabled governance should still return an envelope");
        assert_eq!(envelope.memory_budget, requested_memory);
        assert_eq!(
            envelope.memory_used.load(Ordering::Relaxed),
            requested_memory
        );
        assert_eq!(decision.reason, "Swarm governance disabled");

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 1);
        assert_eq!(metrics.regions_admitted, 1);
        assert_eq!(metrics.regions_rejected, 0);
    }

    #[test]
    fn test_no_pressure_governor_default_snapshot_reports_no_win_fallback() {
        let config = SwarmPressureGovernorConfig::default();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let governor = SwarmPressureGovernor::new_without_pressure_governor(
            config,
            runtime.resource_monitor(),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("no-pressure-governor admission should still produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert_eq!(
            decision.pressure_snapshot.signal_availability,
            crate::observability::pressure_governor::PressureSignalAvailability::NONE
        );
        assert_eq!(
            decision.pressure_snapshot.fallback_verdict,
            crate::observability::pressure_governor::PressureFallbackVerdict::NoWinNoLiveSignals,
            "a snapshot with no live runtime-local signals must not claim complete pressure evidence"
        );
    }

    #[test]
    fn test_metrics_report_max_decision_latency() {
        let governor = create_test_swarm_governor();
        assert_eq!(governor.metrics().max_decision_latency_ns, 0);

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("admission should produce a latency-bearing decision");

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 1);
        assert_eq!(
            metrics.max_decision_latency_ns, decision.decision_latency_ns,
            "single admission should publish its latency as the max latency metric"
        );
    }

    #[test]
    fn test_backpressure_admission_still_gets_resource_envelope() {
        let governor = create_test_swarm_governor();
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1024))
            .expect("Backpressure admission should produce a decision");

        assert!(matches!(
            decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        let envelope = decision
            .envelope
            .expect("backpressure admission still admits work and must return an envelope");
        assert_eq!(
            envelope.memory_budget,
            governor.config.default_memory_budget_bytes
        );
        assert_eq!(
            envelope.memory_used.load(Ordering::Relaxed),
            1024,
            "admitted requested memory must be charged to the returned envelope"
        );

        governor.register_region_envelope(envelope.region_id, envelope);
        assert_eq!(governor.metrics().active_region_count, 1);
    }

    #[test]
    fn test_requested_memory_over_envelope_budget_rejects_admission() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, Some(1025))
            .expect("Oversized request should be represented as an admission rejection");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("exceeds region envelope budget"));
        let metrics = governor.metrics();
        assert_eq!(metrics.regions_rejected, 1);
        assert_eq!(metrics.envelope_budget_violations, 1);
    }

    #[test]
    fn test_workload_admission_request_charges_declared_resources_and_owner_metadata() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "asw2-proof-lane",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        )
        .with_priority(RegionPriority::High)
        .with_declared_resources(Some(4096), Some(25_000), Some(7))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(Instant::now() + Duration::from_secs(60))
        .with_cancellation_budget(Duration::from_millis(250));

        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        let envelope = decision
            .envelope
            .expect("admitted workload must receive a resource envelope");
        assert_eq!(envelope.memory_used.load(Ordering::Relaxed), 4096);
        assert_eq!(envelope.cpu_used_ns.load(Ordering::Relaxed), 25_000);
        assert_eq!(envelope.io_ops_used.load(Ordering::Relaxed), 7);
        for expected in [
            "workload_id=asw2-proof-lane",
            "owner_agent=DustyGorge",
            "bead_id=asupersync-oxqrae.2",
            "reservation_scope=src/observability/swarm_pressure_governor.rs",
            "priority=High",
            "proof_lane=cargo_check_lib",
            "requested_memory_bytes=4096",
            "requested_cpu_ns_per_sec=25000",
            "requested_io_ops_per_sec=7",
            "deadline_set=true",
            "cancellation_budget_ms=250",
            "Admission approved",
        ] {
            assert!(
                decision.reason.contains(expected),
                "decision reason missing {expected}: {}",
                decision.reason
            );
        }
    }

    #[test]
    fn test_workload_admission_rejects_declared_memory_cpu_and_io_over_envelope_budget() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;
        config.default_cpu_budget_ns_per_sec = 100;
        config.default_io_budget_ops_per_sec = 10;

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let memory_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-memory",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(Some(1025), Some(10), Some(1))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let memory_decision = governor
            .check_workload_admission(&cx, &memory_request)
            .expect("oversized memory request should classify");
        assert!(matches!(
            memory_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(memory_decision.envelope.is_none());
        assert!(
            memory_decision
                .reason
                .contains("Requested memory 1025 exceeds")
        );
        assert!(
            memory_decision
                .reason
                .contains("workload_id=oversized-memory")
        );
        assert!(
            memory_decision
                .reason
                .contains("proof_lane=cargo_check_lib")
        );

        let cpu_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-cpu",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(None, Some(101), Some(1))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckAllTargets);
        let cpu_decision = governor
            .check_workload_admission(&cx, &cpu_request)
            .expect("oversized cpu request should classify");
        assert!(matches!(cpu_decision.decision, AdmissionDecision::Reject));
        assert!(cpu_decision.envelope.is_none());
        assert!(cpu_decision.reason.contains("Requested cpu 101 exceeds"));
        assert!(cpu_decision.reason.contains("workload_id=oversized-cpu"));
        assert!(
            cpu_decision
                .reason
                .contains("proof_lane=cargo_check_all_targets")
        );

        let io_request = SwarmWorkloadAdmissionRequest::new(
            "oversized-io",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_declared_resources(None, Some(10), Some(11))
        .with_proof_lane(SwarmProofLaneKind::Test);
        let io_decision = governor
            .check_workload_admission(&cx, &io_request)
            .expect("oversized io request should classify");
        assert!(matches!(io_decision.decision, AdmissionDecision::Reject));
        assert!(io_decision.envelope.is_none());
        assert!(io_decision.reason.contains("Requested io 11 exceeds"));
        assert!(io_decision.reason.contains("workload_id=oversized-io"));
        assert!(io_decision.reason.contains("proof_lane=test"));

        let metrics = governor.metrics();
        assert_eq!(metrics.regions_rejected, 3);
        assert_eq!(metrics.envelope_budget_violations, 3);
    }

    #[test]
    fn test_workload_admission_rejects_invalid_owner_deadline_and_cancel_budget() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let missing_owner =
            SwarmWorkloadAdmissionRequest::new("missing-owner", SwarmAdmissionOwner::new(" "));
        let missing_owner_decision = governor
            .check_workload_admission(&cx, &missing_owner)
            .expect("missing owner should classify as a rejection");
        assert!(matches!(
            missing_owner_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(missing_owner_decision.envelope.is_none());
        assert!(
            missing_owner_decision
                .reason
                .contains("owner agent_name must be non-empty")
        );

        let expired_deadline = SwarmWorkloadAdmissionRequest::new(
            "expired-deadline",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_deadline(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction"),
        );
        let expired_deadline_decision = governor
            .check_workload_admission(&cx, &expired_deadline)
            .expect("expired deadline should classify as a rejection");
        assert!(matches!(
            expired_deadline_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(
            expired_deadline_decision
                .reason
                .contains("deadline has already expired")
        );

        let zero_cancel_budget = SwarmWorkloadAdmissionRequest::new(
            "zero-cancel-budget",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_cancellation_budget(Duration::ZERO);
        let zero_cancel_budget_decision = governor
            .check_workload_admission(&cx, &zero_cancel_budget)
            .expect("zero cancel budget should classify as a rejection");
        assert!(matches!(
            zero_cancel_budget_decision.decision,
            AdmissionDecision::Reject
        ));
        assert!(
            zero_cancel_budget_decision
                .reason
                .contains("cancellation_budget must be non-zero")
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.total_admission_checks, 3);
        assert_eq!(metrics.regions_rejected, 3);
        assert_eq!(metrics.regions_admitted, 0);
    }

    #[test]
    fn test_workload_lease_commit_renew_release_lifecycle() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let cancellation_budget = Duration::from_millis(750);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-lifecycle",
            SwarmAdmissionOwner::new("DustyGorge").with_bead_id("asupersync-oxqrae.2"),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_deadline(Instant::now() + Duration::from_secs(60))
        .with_cancellation_budget(cancellation_budget);
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let region_id = RegionId::new_for_test(50, 1);

        let acquired = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");
        assert_eq!(acquired.lease_id.as_u64(), 1);
        assert_eq!(acquired.state, SwarmWorkloadLeaseState::Active);
        assert_eq!(acquired.transition, SwarmWorkloadLeaseTransition::Acquired);
        assert_eq!(acquired.transition_reason, "workload lease acquired");
        assert_eq!(
            acquired.replay_pointer,
            "swarm-workload-lease://lease/1/transition/acquired"
        );
        assert_eq!(acquired.cancellation_budget, Some(cancellation_budget));
        assert!(acquired.reason.contains("workload lease acquired"));
        assert!(acquired.reason.contains("cancellation_budget_ms=750"));

        let committed = governor
            .commit_workload_lease(acquired.lease_id)
            .expect("live lease should commit");
        assert_eq!(committed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(
            committed.transition,
            SwarmWorkloadLeaseTransition::Committed
        );
        assert_eq!(committed.transition_reason, "workload lease committed");
        assert_eq!(
            committed.replay_pointer,
            "swarm-workload-lease://lease/1/transition/committed"
        );
        assert_eq!(committed.cancellation_budget, Some(cancellation_budget));
        assert!(committed.reason.contains("cancellation_budget_ms=750"));
        let old_expiry = committed.expires_at;

        let renewed = governor
            .renew_workload_lease(acquired.lease_id, Duration::from_secs(30))
            .expect("committed lease should renew");
        assert_eq!(renewed.state, SwarmWorkloadLeaseState::Committed);
        assert_eq!(renewed.transition, SwarmWorkloadLeaseTransition::Renewed);
        assert_eq!(renewed.transition_reason, "workload lease renewed");
        assert_eq!(
            renewed.replay_pointer,
            "swarm-workload-lease://lease/1/transition/renewed"
        );
        assert_eq!(renewed.cancellation_budget, Some(cancellation_budget));
        assert!(renewed.expires_at > old_expiry);
        assert!(renewed.reason.contains("renewals=1"));
        assert!(renewed.reason.contains("cancellation_budget_ms=750"));

        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-lifecycle",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.40, 0.50),
            )
            .expect("live workload pressure feedback should record");
        assert_eq!(governor.metrics().live_workload_feedback_reports, 1);
        let schedule = governor.workload_lease_schedule();
        assert_eq!(schedule.len(), 1);
        assert_eq!(schedule[0].cancellation_budget_ms, Some(750));
        assert!(
            schedule[0].reason.contains("cancellation_budget_ms=750"),
            "schedule rows should expose the lease cancellation budget"
        );

        let released = governor
            .release_workload_lease(acquired.lease_id)
            .expect("renewed lease should release");
        assert_eq!(released.state, SwarmWorkloadLeaseState::Released);
        assert_eq!(released.transition, SwarmWorkloadLeaseTransition::Released);
        assert_eq!(released.transition_reason, "workload lease released");
        assert_eq!(
            released.replay_pointer,
            "swarm-workload-lease://lease/1/transition/released"
        );
        assert_eq!(released.cancellation_budget, Some(cancellation_budget));
        assert!(released.reason.contains("cancellation_budget_ms=750"));
        assert!(released.terminal_at.is_some());
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal release should clear matching workload pressure feedback"
        );
        assert!(
            governor
                .clear_workload_pressure_feedback("lease-lifecycle")
                .is_none(),
            "release should remove the feedback row rather than leaving it for TTL pruning"
        );
        assert!(
            governor
                .renew_workload_lease(acquired.lease_id, Duration::from_secs(1))
                .is_err(),
            "terminal leases must not renew"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_acquired, 1);
        assert_eq!(metrics.workload_leases_committed, 1);
        assert_eq!(metrics.workload_leases_renewed, 1);
        assert_eq!(metrics.workload_leases_released, 1);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
    }

    #[test]
    fn test_workload_admission_receipt_binds_lease_to_exact_request() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline = Instant::now() + Duration::from_secs(60);
        let request = SwarmWorkloadAdmissionRequest::new(
            " receipt-owner-a ",
            SwarmAdmissionOwner::new(" DustyGorge ")
                .with_bead_id(" asupersync-oxqrae.2 ")
                .with_reservation_scope(" ./src//observability/swarm_pressure_governor.rs "),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline)
        .with_cancellation_budget(Duration::from_secs(5));

        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let receipt = decision
            .workload_receipt
            .as_ref()
            .expect("workload admission should bind a typed workload receipt");
        assert_eq!(receipt.workload_id, "receipt-owner-a");
        assert_eq!(receipt.owner.agent_name, "DustyGorge");
        assert_eq!(
            receipt.owner.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            receipt.owner.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert!(receipt.matches_request(&request));
        assert_eq!(decision.decision_receipt.decision, AdmissionDecision::Admit);
        assert!(decision.decision_receipt.decision_id > 0);
        assert!(
            decision
                .decision_receipt
                .replay_pointer
                .starts_with("swarm-admission://decision/")
        );
        assert_eq!(decision.decision_receipt.reason, decision.reason);
        assert_eq!(
            decision.decision_receipt.workload_id.as_deref(),
            Some("receipt-owner-a")
        );
        assert_eq!(
            decision.decision_receipt.owner_agent.as_deref(),
            Some("DustyGorge")
        );
        assert_eq!(
            decision.decision_receipt.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            decision.decision_receipt.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert_eq!(
            decision.decision_receipt.proof_lane,
            Some(SwarmProofLaneKind::CargoCheckLib)
        );
        assert_eq!(decision.decision_receipt.requested_memory_bytes, Some(1024));
        assert_eq!(decision.decision_receipt.requested_cpu_ns_per_sec, Some(50));
        assert_eq!(decision.decision_receipt.requested_io_ops_per_sec, Some(5));
        assert!(decision.decision_receipt.deadline_set);
        assert_eq!(decision.decision_receipt.cancellation_budget_ms, Some(5000));
        assert_eq!(decision.decision_receipt.overall_pressure_scaled, 0);
        assert_eq!(decision.decision_receipt.workload_feedback_report_count, 0);
        assert_eq!(
            decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            0
        );
        assert_eq!(decision.decision_receipt.workload_queue_pressure_scaled, 0);
        assert_eq!(
            decision.decision_receipt.workload_disk_io_pressure_scaled,
            0
        );
        assert_eq!(
            decision.decision_receipt.workload_rch_queue_pressure_scaled,
            0
        );
        assert_eq!(
            decision
                .decision_receipt
                .workload_validation_frontier_pressure_scaled,
            0
        );
        assert_eq!(
            decision
                .decision_receipt
                .workload_cancellation_tail_pressure_scaled,
            0
        );

        let mismatched_request = SwarmWorkloadAdmissionRequest::new(
            "receipt-owner-b",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        )
        .with_declared_resources(Some(1024), Some(50), Some(5))
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline)
        .with_cancellation_budget(Duration::from_secs(5));
        let mismatch = governor
            .acquire_workload_lease(
                RegionId::new_for_test(50, 2),
                &mismatched_request,
                &decision,
            )
            .expect_err("lease acquisition must reject a mismatched admission receipt");
        assert!(matches!(
            mismatch,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("admission workload receipt does not match request")
                    && reason.contains("decision_workload_id=receipt-owner-a")
                    && reason.contains("request_workload_id=receipt-owner-b")
        ));
        assert_eq!(governor.metrics().workload_leases_acquired, 0);

        let acquired = governor
            .acquire_workload_lease(RegionId::new_for_test(50, 1), &request, &decision)
            .expect("matching workload receipt should acquire");
        assert_eq!(acquired.workload_id, "receipt-owner-a");
        assert_eq!(acquired.transition, SwarmWorkloadLeaseTransition::Acquired);
        assert_eq!(acquired.transition_reason, "workload lease acquired");
        assert_eq!(acquired.owner.agent_name, "DustyGorge");
        assert_eq!(
            acquired.owner.bead_id.as_deref(),
            Some("asupersync-oxqrae.2")
        );
        assert_eq!(
            acquired.owner.reservation_scope.as_deref(),
            Some("src/observability/swarm_pressure_governor.rs")
        );
        assert_eq!(acquired.proof_lane, SwarmProofLaneKind::CargoCheckLib);
        assert_eq!(acquired.reserved_memory_bytes, Some(1024));
        assert_eq!(acquired.reserved_cpu_ns_per_sec, Some(50));
        assert_eq!(acquired.reserved_io_ops_per_sec, Some(5));
        assert!(acquired.issued_at <= acquired.expires_at);
        assert_eq!(governor.metrics().workload_leases_acquired, 1);
    }

    #[test]
    fn test_workload_lease_conflicts_abort_and_expiry_are_terminal() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-conflict",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");

        let first = governor
            .acquire_workload_lease(RegionId::new_for_test(51, 1), &request, &decision)
            .expect("first workload lease should acquire");
        assert!(
            governor
                .acquire_workload_lease(RegionId::new_for_test(52, 1), &request, &decision)
                .is_err(),
            "same workload id must not hold two live leases"
        );
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-conflict",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.25, 0.0, 0.0, 0.0, 0.0),
            )
            .expect("abort feedback should record before terminal transition");

        let aborted = governor
            .abort_workload_lease(first.lease_id, "cancelled before proof lane started")
            .expect("live lease should abort");
        assert_eq!(aborted.state, SwarmWorkloadLeaseState::Aborted);
        assert_eq!(aborted.transition, SwarmWorkloadLeaseTransition::Aborted);
        assert_eq!(
            aborted.transition_reason,
            "cancelled before proof lane started"
        );
        assert_eq!(
            aborted.replay_pointer,
            "swarm-workload-lease://lease/1/transition/aborted"
        );
        assert!(
            aborted
                .reason
                .contains("cancelled before proof lane started")
        );
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal abort should clear matching workload pressure feedback"
        );

        let second_request = SwarmWorkloadAdmissionRequest::new(
            "lease-expiry",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second workload admission should classify");
        let expiring = governor
            .acquire_workload_lease(
                RegionId::new_for_test(53, 1),
                &second_request,
                &second_decision,
            )
            .expect("second workload lease should acquire");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "lease-expiry",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.0, 0.0, 0.90, 0.0, 0.0),
            )
            .expect("expiry feedback should record before terminal transition");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&expiring.lease_id)
                .expect("lease should exist for forced expiry")
                .expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction");
        }

        let expired = governor.expire_stale_workload_leases();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lease_id, expiring.lease_id);
        assert_eq!(expired[0].state, SwarmWorkloadLeaseState::Expired);
        assert_eq!(expired[0].transition, SwarmWorkloadLeaseTransition::Expired);
        assert_eq!(expired[0].transition_reason, "workload lease expired");
        assert_eq!(
            expired[0].replay_pointer,
            "swarm-workload-lease://lease/2/transition/expired"
        );
        assert_eq!(
            governor.metrics().live_workload_feedback_reports,
            0,
            "terminal expiry should clear matching workload pressure feedback"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_lease_conflicts, 1);
        assert_eq!(metrics.workload_leases_aborted, 1);
        assert_eq!(metrics.workload_leases_expired, 1);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 2);
    }

    #[test]
    fn test_workload_lease_conflicts_on_live_reservation_scope() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let reservation_scope = "src/observability/swarm_pressure_governor.rs";
        let first_request = SwarmWorkloadAdmissionRequest::new(
            "scope-owner-a",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_reservation_scope(format!(" ./{reservation_scope} ")),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first workload admission should classify");
        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(55, 1),
                &first_request,
                &first_decision,
            )
            .expect("first scoped workload lease should acquire");

        let second_request = SwarmWorkloadAdmissionRequest::new(
            "scope-owner-b",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_reservation_scope("src/observability//swarm_pressure_governor.rs"),
        )
        .with_proof_lane(SwarmProofLaneKind::ClippyAllTargets);
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second workload admission should classify before lease conflict check");

        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 1),
                &second_request,
                &second_decision,
            )
            .expect_err("live reservation scope must reject a second workload lease");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("reservation_scope src/observability/swarm_pressure_governor.rs")
                    && reason.contains("live proof_lane=cargo_check_lib")
                    && reason.contains("requested proof_lane=clippy_all_targets")
        ));
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .abort_workload_lease(first.lease_id, "scope owner cancelled")
            .expect("terminal first lease should release reservation-scope conflict");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 1),
                &second_request,
                &second_decision,
            )
            .expect("terminal prior lease must not block the same reservation scope forever");
        assert_eq!(second.workload_id, "scope-owner-b");
    }

    #[test]
    fn test_workload_lease_proof_lane_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_proof_lane = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-a",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-b",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let source_request = SwarmWorkloadAdmissionRequest::new(
            "proof-lane-source",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("proof/source"),
        )
        .with_proof_lane(SwarmProofLaneKind::SourceOnly);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first proof-lane workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second proof-lane workload admission should classify");
        let source_decision = governor
            .check_workload_admission(&cx, &source_request)
            .expect("different proof-lane workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 10),
                &first_request,
                &first_decision,
            )
            .expect("first workload in capped proof lane should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 11),
                &second_request,
                &second_decision,
            )
            .expect_err("same proof lane should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("proof_lane cargo_check_lib already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_proof_lane=1")
        ));

        let source = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 12),
                &source_request,
                &source_decision,
            )
            .expect("different proof lane should not consume cargo_check_lib capacity");
        assert_eq!(source.workload_id, "proof-lane-source");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first lease should free proof-lane capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(56, 13),
                &second_request,
                &second_decision,
            )
            .expect("released proof-lane capacity should allow the next lease");
        assert_eq!(second.workload_id, "proof-lane-b");
    }

    #[test]
    fn test_workload_lease_owner_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_owner = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-a",
            SwarmAdmissionOwner::new(" DustyGorge ").with_reservation_scope("owner/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-b",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("owner/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);
        let other_owner_request = SwarmWorkloadAdmissionRequest::new(
            "owner-cap-other",
            SwarmAdmissionOwner::new("TealBass").with_reservation_scope("owner/other"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first owner workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second owner workload admission should classify");
        let other_owner_decision = governor
            .check_workload_admission(&cx, &other_owner_request)
            .expect("different owner workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 1),
                &first_request,
                &first_decision,
            )
            .expect("first workload for capped owner should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 2),
                &second_request,
                &second_decision,
            )
            .expect_err("same owner should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("owner_agent DustyGorge already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_owner=1")
        ));

        let other_owner = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 3),
                &other_owner_request,
                &other_owner_decision,
            )
            .expect("different owner should not consume DustyGorge capacity");
        assert_eq!(other_owner.workload_id, "owner-cap-other");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first owner lease should free owner capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(60, 4),
                &second_request,
                &second_decision,
            )
            .expect("released owner capacity should allow the next lease");
        assert_eq!(second.workload_id, "owner-cap-b");
    }

    #[test]
    fn test_workload_lease_bead_capacity_rejects_over_cap_and_releases() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.max_live_workload_leases_per_bead = 1;
        let governor = create_test_swarm_governor_with_config(config);
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let first_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-a",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id(" asupersync-oxqrae.2 ")
                .with_reservation_scope("bead/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-b",
            SwarmAdmissionOwner::new("TanAspen")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("bead/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);
        let other_bead_request = SwarmWorkloadAdmissionRequest::new(
            "bead-cap-other",
            SwarmAdmissionOwner::new("TanAspen")
                .with_bead_id("asupersync-oxqrae.3")
                .with_reservation_scope("bead/other"),
        )
        .with_proof_lane(SwarmProofLaneKind::RustfmtCheck);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first bead workload admission should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second bead workload admission should classify");
        let other_bead_decision = governor
            .check_workload_admission(&cx, &other_bead_request)
            .expect("different bead workload admission should classify");

        let first = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 1),
                &first_request,
                &first_decision,
            )
            .expect("first workload for capped bead should acquire");
        let conflict = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 2),
                &second_request,
                &second_decision,
            )
            .expect_err("same bead should reject over the live lease cap");
        assert!(matches!(
            conflict,
            SwarmPressureError::WorkloadLease { ref reason }
                if reason.contains("bead_id asupersync-oxqrae.2 already has 1 live workload leases")
                    && reason.contains("max_live_workload_leases_per_bead=1")
        ));

        let other_bead = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 3),
                &other_bead_request,
                &other_bead_decision,
            )
            .expect("different bead should not consume asupersync-oxqrae.2 capacity");
        assert_eq!(other_bead.workload_id, "bead-cap-other");
        assert_eq!(governor.metrics().workload_lease_conflicts, 1);

        governor
            .release_workload_lease(first.lease_id)
            .expect("releasing first bead lease should free bead capacity");
        let second = governor
            .acquire_workload_lease(
                RegionId::new_for_test(61, 4),
                &second_request,
                &second_decision,
            )
            .expect("released bead capacity should allow the next lease");
        assert_eq!(second.workload_id, "bead-cap-b");
    }

    #[test]
    fn test_unregister_region_envelope_releases_bound_workload_lease() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "region-close-release",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let region_id = RegionId::new_for_test(54, 1);
        governor.register_region_envelope(
            region_id,
            decision
                .envelope
                .clone()
                .expect("admitted workload should include an envelope"),
        );
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");
        governor
            .commit_workload_lease(lease.lease_id)
            .expect("lease should commit before region close");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "region-close-release",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::SourceOnly,
                )
                .with_pressures(0.0, 0.70, 0.0, 0.0, 0.0),
            )
            .expect("region-close feedback should record before terminal transition");

        let removed = governor.unregister_region_envelope(region_id);
        assert!(removed.is_some());
        let stored = governor
            .get_workload_lease(lease.lease_id)
            .expect("released lease should remain available for audit");
        assert_eq!(stored.state, SwarmWorkloadLeaseState::Released);
        assert!(stored.terminal_at.is_some());

        let metrics = governor.metrics();
        assert_eq!(metrics.active_region_count, 0);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
        assert_eq!(metrics.workload_leases_released, 1);
        assert_eq!(
            metrics.live_workload_feedback_reports, 0,
            "region close release should clear matching workload pressure feedback"
        );
    }

    #[test]
    fn test_release_region_workload_leases_marks_region_close_transition() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 2);
        let request = SwarmWorkloadAdmissionRequest::new(
            "region-close-transition",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire a lease");

        let receipts = governor.release_region_workload_leases(region_id);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].lease_id, lease.lease_id);
        assert_eq!(receipts[0].state, SwarmWorkloadLeaseState::Released);
        assert_eq!(
            receipts[0].transition,
            SwarmWorkloadLeaseTransition::ReleasedByRegionClose
        );
        assert_eq!(
            receipts[0].transition_reason,
            "workload lease released by region close"
        );
        assert_eq!(
            receipts[0].replay_pointer,
            "swarm-workload-lease://lease/1/transition/released_by_region_close"
        );
        assert!(
            receipts[0]
                .reason
                .contains("workload lease released by region close")
        );
    }

    #[test]
    fn test_abort_region_workload_leases_clears_cancelled_admission_obligations() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 5);
        let first_request = SwarmWorkloadAdmissionRequest::new(
            "cancelled-admission-a",
            SwarmAdmissionOwner::new("OrangeElm").with_reservation_scope("asw/cancel/a"),
        )
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib);
        let second_request = SwarmWorkloadAdmissionRequest::new(
            "cancelled-admission-b",
            SwarmAdmissionOwner::new("OrangeElm").with_reservation_scope("asw/cancel/b"),
        )
        .with_proof_lane(SwarmProofLaneKind::Test);

        let first_decision = governor
            .check_workload_admission(&cx, &first_request)
            .expect("first cancelled admission workload should classify");
        let second_decision = governor
            .check_workload_admission(&cx, &second_request)
            .expect("second cancelled admission workload should classify");
        let first = governor
            .acquire_workload_lease(region_id, &first_request, &first_decision)
            .expect("first cancelled admission lease should acquire");
        let second = governor
            .acquire_workload_lease(region_id, &second_request, &second_decision)
            .expect("second cancelled admission lease should acquire");
        governor
            .commit_workload_lease(first.lease_id)
            .expect("committed lease should still abort on region cancellation");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cancelled-admission-a",
                    SwarmAdmissionOwner::new("OrangeElm"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.40, 0.50),
            )
            .expect("first feedback should record before cancellation");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cancelled-admission-b",
                    SwarmAdmissionOwner::new("OrangeElm"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(0.50, 0.40, 0.30, 0.20, 0.10),
            )
            .expect("second feedback should record before cancellation");
        assert_eq!(governor.metrics().live_workload_feedback_reports, 2);

        let receipts =
            governor.abort_region_workload_leases(region_id, "admission cancelled by operator");
        let aborted_ids: Vec<_> = receipts.iter().map(|receipt| receipt.lease_id).collect();
        assert_eq!(receipts.len(), 2);
        assert!(aborted_ids.contains(&first.lease_id));
        assert!(aborted_ids.contains(&second.lease_id));
        for receipt in &receipts {
            assert_eq!(receipt.state, SwarmWorkloadLeaseState::Aborted);
            assert_eq!(receipt.transition, SwarmWorkloadLeaseTransition::Aborted);
            assert_eq!(receipt.transition_reason, "admission cancelled by operator");
            assert!(
                receipt
                    .replay_pointer
                    .starts_with("swarm-workload-lease://lease/")
            );
            assert!(receipt.replay_pointer.ends_with("/transition/aborted"));
            assert!(receipt.reason.contains("admission cancelled by operator"));
        }
        assert!(
            governor
                .abort_region_workload_leases(region_id, "")
                .is_empty(),
            "terminal cancelled leases must not emit duplicate abort receipts"
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_aborted, 2);
        assert_eq!(metrics.active_workload_lease_count, 0);
        assert_eq!(metrics.terminal_workload_lease_count, 2);
        assert_eq!(
            metrics.live_workload_feedback_reports, 0,
            "region cancellation should clear cancelled workload feedback"
        );
        let audit = governor.workload_lease_audit_snapshot();
        assert_eq!(audit.live_lease_count, 0);
        assert_eq!(audit.aborted_lease_count, 2);
        assert!(!audit.leak_detected, "{}", audit.reason);
    }

    #[test]
    fn test_workload_lease_audit_snapshot_reports_linear_obligation_invariants() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let region_id = RegionId::new_for_test(54, 3);
        let duplicate_region_id = RegionId::new_for_test(54, 4);
        let request = SwarmWorkloadAdmissionRequest::new(
            "lease-audit",
            SwarmAdmissionOwner::new("DustyGorge")
                .with_bead_id("asupersync-oxqrae.2")
                .with_reservation_scope("src/observability/swarm_pressure_governor.rs"),
        );
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("workload admission should classify");
        let envelope = decision
            .envelope
            .clone()
            .expect("admitted workload should include an envelope");
        let lease = governor
            .acquire_workload_lease(region_id, &request, &decision)
            .expect("admitted workload should acquire");

        let unbound_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(unbound_audit.live_lease_count, 1);
        assert_eq!(unbound_audit.active_lease_count, 1);
        assert_eq!(unbound_audit.live_unregistered_region_count, 1);
        assert!(unbound_audit.leak_detected, "{}", unbound_audit.reason);
        assert!(
            unbound_audit
                .reason
                .contains("live_unregistered_region_count=1")
        );

        governor.register_region_envelope(region_id, envelope.clone());
        let bound_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(bound_audit.live_unregistered_region_count, 0);
        assert!(!bound_audit.leak_detected, "{}", bound_audit.reason);

        governor
            .commit_workload_lease(lease.lease_id)
            .expect("bound lease should commit");
        governor.register_region_envelope(duplicate_region_id, envelope);
        let duplicate_id = SwarmWorkloadLeaseId::new_for_test(99_001);
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            let mut duplicate = leases
                .get(&lease.lease_id)
                .expect("original lease should exist")
                .clone();
            duplicate.lease_id = duplicate_id;
            duplicate.region_id = duplicate_region_id;
            duplicate.state = SwarmWorkloadLeaseState::Active;
            duplicate.terminal_at = None;
            leases.insert(duplicate_id, duplicate);
        }

        let duplicate_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(duplicate_audit.live_lease_count, 2);
        assert_eq!(duplicate_audit.duplicate_live_workload_id_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_owner_agent_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_bead_id_count, 1);
        assert_eq!(duplicate_audit.duplicate_live_reservation_scope_count, 1);
        assert!(
            duplicate_audit
                .reason
                .contains("duplicate_live_owner_agent_count=1")
        );
        assert!(
            duplicate_audit
                .reason
                .contains("duplicate_live_bead_id_count=1")
        );
        assert!(duplicate_audit.leak_detected, "{}", duplicate_audit.reason);

        {
            let mut leases = governor.workload_leases.lock().unwrap();
            let duplicate = leases
                .get_mut(&duplicate_id)
                .expect("duplicate lease should exist");
            duplicate.state = SwarmWorkloadLeaseState::Aborted;
            duplicate.terminal_at = Some(Instant::now());
        }
        governor
            .release_workload_lease(lease.lease_id)
            .expect("original lease should release");
        let terminal_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(terminal_audit.live_lease_count, 0);
        assert_eq!(terminal_audit.terminal_lease_count, 2);
        assert!(!terminal_audit.leak_detected, "{}", terminal_audit.reason);

        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&lease.lease_id)
                .expect("released lease should exist")
                .terminal_at = None;
        }
        let missing_terminal_audit = governor.workload_lease_audit_snapshot();
        assert_eq!(missing_terminal_audit.terminal_missing_terminal_at_count, 1);
        assert!(
            missing_terminal_audit.leak_detected,
            "{}",
            missing_terminal_audit.reason
        );
    }

    #[test]
    fn test_workload_lease_schedule_orders_live_leases_deterministically_and_expires_stale() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline_base = Instant::now() + Duration::from_secs(60);
        let shared_high_deadline = deadline_base + Duration::from_secs(90);

        let critical_request = SwarmWorkloadAdmissionRequest::new(
            "critical-source",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::Critical)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline_base + Duration::from_secs(300));
        let high_release_request = SwarmWorkloadAdmissionRequest::new(
            "high-release",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::High)
        .with_proof_lane(SwarmProofLaneKind::ReleaseProof)
        .with_deadline(shared_high_deadline);
        let high_source_request = SwarmWorkloadAdmissionRequest::new(
            "high-source",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::High)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(shared_high_deadline);
        let normal_request = SwarmWorkloadAdmissionRequest::new(
            "normal-check",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::Normal)
        .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
        .with_deadline(deadline_base + Duration::from_secs(10));
        let stale_request = SwarmWorkloadAdmissionRequest::new(
            "stale-best-effort",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::BestEffort)
        .with_proof_lane(SwarmProofLaneKind::Test)
        .with_deadline(deadline_base + Duration::from_secs(5));

        let critical_decision = governor
            .check_workload_admission(&cx, &critical_request)
            .expect("critical workload admission should classify");
        let high_release_decision = governor
            .check_workload_admission(&cx, &high_release_request)
            .expect("release proof workload admission should classify");
        let high_source_decision = governor
            .check_workload_admission(&cx, &high_source_request)
            .expect("source workload admission should classify");
        let normal_decision = governor
            .check_workload_admission(&cx, &normal_request)
            .expect("normal workload admission should classify");
        let stale_decision = governor
            .check_workload_admission(&cx, &stale_request)
            .expect("stale workload admission should classify");

        let critical = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 1),
                &critical_request,
                &critical_decision,
            )
            .expect("critical workload should acquire a lease");
        let high_release = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 2),
                &high_release_request,
                &high_release_decision,
            )
            .expect("high release workload should acquire a lease");
        let high_source = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 3),
                &high_source_request,
                &high_source_decision,
            )
            .expect("high source workload should acquire a lease");
        let normal = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 4),
                &normal_request,
                &normal_decision,
            )
            .expect("normal workload should acquire a lease");
        let stale = governor
            .acquire_workload_lease(
                RegionId::new_for_test(57, 5),
                &stale_request,
                &stale_decision,
            )
            .expect("stale workload should initially acquire a lease");

        governor
            .commit_workload_lease(high_release.lease_id)
            .expect("committed lease should remain scheduleable");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&high_release.lease_id)
                .expect("release lease should exist")
                .expires_at = shared_high_deadline;
            leases
                .get_mut(&high_source.lease_id)
                .expect("source lease should exist")
                .expires_at = shared_high_deadline;
            leases
                .get_mut(&stale.lease_id)
                .expect("stale lease should exist")
                .expires_at = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test instant should support one-second subtraction");
        }

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![
                critical.lease_id,
                high_release.lease_id,
                high_source.lease_id,
                normal.lease_id
            ]
        );
        assert_eq!(schedule[0].scheduling_rank, 0);
        assert_eq!(schedule[0].priority, RegionPriority::Critical);
        assert!(!schedule[0].pressure_feedback_present);
        assert_eq!(schedule[0].max_pressure_scaled, 0);
        assert!(
            schedule[0].time_to_expiry_ms > 0,
            "live schedule rows should expose structured time-to-expiry"
        );
        assert_eq!(schedule[1].proof_lane, SwarmProofLaneKind::ReleaseProof);
        assert_eq!(schedule[2].proof_lane, SwarmProofLaneKind::SourceOnly);
        assert!(
            schedule[1]
                .replay_pointer
                .starts_with("swarm-workload-lease://lease/")
        );
        assert!(
            schedule[1]
                .reason
                .contains("live workload lease scheduled without pressure feedback")
        );
        assert!(schedule[1].reason.contains("time_to_expiry_ms="));

        let expired = governor
            .get_workload_lease(stale.lease_id)
            .expect("expired lease should remain available for audit");
        assert_eq!(expired.state, SwarmWorkloadLeaseState::Expired);
        let metrics = governor.metrics();
        assert_eq!(metrics.workload_leases_expired, 1);
        assert_eq!(metrics.active_workload_lease_count, 4);
        assert_eq!(metrics.terminal_workload_lease_count, 1);
    }

    #[test]
    fn test_workload_lease_schedule_applies_starvation_aging_without_overtaking_critical() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let mut config = SwarmPressureGovernorConfig::default();
        config.workload_lease_starvation_aging_step = Duration::from_secs(10);
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let deadline = Instant::now() + Duration::from_secs(300);

        let critical_request = SwarmWorkloadAdmissionRequest::new(
            "critical-admission",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("critical-lane"),
        )
        .with_priority(RegionPriority::Critical)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);
        let fresh_normal_request = SwarmWorkloadAdmissionRequest::new(
            "fresh-normal",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("normal-lane"),
        )
        .with_priority(RegionPriority::Normal)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);
        let aged_low_request = SwarmWorkloadAdmissionRequest::new(
            "aged-low",
            SwarmAdmissionOwner::new("DustyGorge").with_reservation_scope("low-lane"),
        )
        .with_priority(RegionPriority::Low)
        .with_proof_lane(SwarmProofLaneKind::SourceOnly)
        .with_deadline(deadline);

        let critical_decision = governor
            .check_workload_admission(&cx, &critical_request)
            .expect("critical workload admission should classify");
        let fresh_normal_decision = governor
            .check_workload_admission(&cx, &fresh_normal_request)
            .expect("fresh normal workload admission should classify");
        let aged_low_decision = governor
            .check_workload_admission(&cx, &aged_low_request)
            .expect("aged low workload admission should classify");

        let critical = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 1),
                &critical_request,
                &critical_decision,
            )
            .expect("critical workload should acquire lease");
        let fresh_normal = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 2),
                &fresh_normal_request,
                &fresh_normal_decision,
            )
            .expect("fresh normal workload should acquire lease");
        let aged_low = governor
            .acquire_workload_lease(
                RegionId::new_for_test(59, 3),
                &aged_low_request,
                &aged_low_decision,
            )
            .expect("aged low workload should acquire lease");

        let now = Instant::now();
        let old_issued_at = now
            .checked_sub(Duration::from_secs(25))
            .expect("test time should support subtracting wait age");
        {
            let mut leases = governor.workload_leases.lock().unwrap();
            leases
                .get_mut(&critical.lease_id)
                .expect("critical lease should exist")
                .expires_at = deadline;
            leases
                .get_mut(&fresh_normal.lease_id)
                .expect("fresh normal lease should exist")
                .expires_at = deadline;
            let aged = leases
                .get_mut(&aged_low.lease_id)
                .expect("aged low lease should exist");
            aged.issued_at = old_issued_at;
            aged.expires_at = deadline;
        }

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![critical.lease_id, aged_low.lease_id, fresh_normal.lease_id],
            "aged low-priority work should catch up to fresh normal work but not critical work"
        );
        assert_eq!(schedule[0].effective_priority_rank, 0);
        assert_eq!(schedule[0].starvation_aging_discount, 0);
        assert_eq!(schedule[1].workload_id, "aged-low");
        assert_eq!(schedule[1].effective_priority_rank, 1);
        assert_eq!(schedule[1].starvation_aging_discount, 2);
        assert!(
            schedule[1].wait_age_ms >= 20_000,
            "aged low-priority lease should expose structured wait age"
        );
        assert!(
            schedule[1].time_to_expiry_ms > 0,
            "aged low-priority lease should expose structured time-to-expiry"
        );
        assert!(schedule[1].reason.contains("wait_age_ms="));
        assert!(schedule[1].reason.contains("time_to_expiry_ms="));
        assert!(
            schedule[1].reason.contains("starvation_aging_discount=2"),
            "{}",
            schedule[1].reason
        );
        assert!(
            schedule[1].reason.contains("effective_priority_rank=1"),
            "{}",
            schedule[1].reason
        );
        assert_eq!(schedule[2].workload_id, "fresh-normal");
        assert_eq!(schedule[2].effective_priority_rank, 2);
        assert_eq!(schedule[2].starvation_aging_discount, 0);

        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(ResourceType::Memory, DegradationLevel::Heavy);

        let pressure_schedule = governor.workload_lease_schedule();
        let pressure_ordered_ids: Vec<_> = pressure_schedule
            .iter()
            .map(|entry| entry.lease_id)
            .collect();
        assert_eq!(
            pressure_ordered_ids,
            vec![critical.lease_id, fresh_normal.lease_id, aged_low.lease_id],
            "host resource pressure should defer aged background work behind fresh foreground work"
        );
        let normal_row = pressure_schedule
            .iter()
            .find(|entry| entry.workload_id == "fresh-normal")
            .expect("fresh normal row should be scheduled");
        assert_eq!(
            normal_row.resource_degradation_level,
            DegradationLevel::Heavy
        );
        assert_eq!(normal_row.resource_pressure_scaled, 7500);
        assert!(!normal_row.resource_pressure_deferral);
        let aged_row = pressure_schedule
            .iter()
            .find(|entry| entry.workload_id == "aged-low")
            .expect("aged low row should be scheduled");
        assert_eq!(aged_row.resource_degradation_level, DegradationLevel::Heavy);
        assert_eq!(aged_row.resource_pressure_scaled, 7500);
        assert!(aged_row.resource_pressure_deferral, "{}", aged_row.reason);
        assert!(
            aged_row.reason.contains("resource_degradation_level=heavy"),
            "{}",
            aged_row.reason
        );
        assert!(
            aged_row.reason.contains("resource_pressure_deferral=true"),
            "{}",
            aged_row.reason
        );
    }

    #[test]
    fn test_workload_lease_schedule_uses_live_pressure_feedback() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let shared_deadline = Instant::now() + Duration::from_secs(120);
        let hot_owner = SwarmAdmissionOwner::new("DustyGorge")
            .with_bead_id("asupersync-oxqrae.2")
            .with_reservation_scope("asw-hot-rch-lane");
        let cool_owner = SwarmAdmissionOwner::new("DustyGorge")
            .with_bead_id("asupersync-oxqrae.2")
            .with_reservation_scope("asw-cool-rch-lane");
        let hot_request = SwarmWorkloadAdmissionRequest::new("hot-rch-lane", hot_owner)
            .with_priority(RegionPriority::Normal)
            .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
            .with_deadline(shared_deadline);
        let cool_request = SwarmWorkloadAdmissionRequest::new("cool-rch-lane", cool_owner)
            .with_priority(RegionPriority::Normal)
            .with_proof_lane(SwarmProofLaneKind::CargoCheckLib)
            .with_deadline(shared_deadline);

        let hot_decision = governor
            .check_workload_admission(&cx, &hot_request)
            .expect("hot workload admission should classify");
        let cool_decision = governor
            .check_workload_admission(&cx, &cool_request)
            .expect("cool workload admission should classify");
        let hot = governor
            .acquire_workload_lease(RegionId::new_for_test(58, 1), &hot_request, &hot_decision)
            .expect("hot workload should acquire first lease");
        let cool = governor
            .acquire_workload_lease(RegionId::new_for_test(58, 2), &cool_request, &cool_decision)
            .expect("cool workload should acquire second lease");

        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "hot-rch-lane",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.20, 0.40, 0.95, 0.90, 0.30),
            )
            .expect("hot pressure feedback should be accepted");
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "cool-rch-lane",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.05, 0.10, 0.20, 0.15, 0.05),
            )
            .expect("cool pressure feedback should be accepted");

        let schedule = governor.workload_lease_schedule();
        let ordered_ids: Vec<_> = schedule.iter().map(|entry| entry.lease_id).collect();
        assert_eq!(
            ordered_ids,
            vec![cool.lease_id, hot.lease_id],
            "lower-pressure workload should schedule before an otherwise identical hot lane"
        );
        assert_eq!(schedule[0].workload_id, "cool-rch-lane");
        assert!(schedule[0].pressure_feedback_present);
        assert!(
            !schedule[0].workload_pressure_deferral,
            "{}",
            schedule[0].reason
        );
        assert_eq!(
            schedule[0].dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(schedule[0].max_pressure_scaled, 2000);
        assert_eq!(schedule[0].rch_queue_pressure_scaled, 2000);
        assert_eq!(schedule[1].workload_id, "hot-rch-lane");
        assert!(schedule[1].pressure_feedback_present);
        assert!(
            schedule[1].workload_pressure_deferral,
            "{}",
            schedule[1].reason
        );
        assert_eq!(
            schedule[1].dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(schedule[1].queue_pressure_scaled, 2000);
        assert_eq!(schedule[1].disk_io_pressure_scaled, 4000);
        assert_eq!(schedule[1].rch_queue_pressure_scaled, 9500);
        assert_eq!(schedule[1].validation_frontier_pressure_scaled, 9000);
        assert_eq!(schedule[1].cancellation_tail_pressure_scaled, 3000);
        assert_eq!(schedule[1].max_pressure_scaled, 9500);
        assert!(
            schedule[1]
                .reason
                .contains("scheduled with pressure feedback")
        );
        assert!(
            schedule[1]
                .reason
                .contains("dominant_pressure_source=rch_queue")
        );
        assert!(
            schedule[1]
                .reason
                .contains("workload_pressure_deferral=true")
        );
    }

    #[test]
    fn test_peer_pressure_backpressures_normal_admission() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("peer-a", 0.85, DegradationLevel::Moderate)
            .expect("peer pressure report should be accepted");

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Peer pressure admission should produce a decision");

        assert!(matches!(
            decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(decision.envelope.is_some());
        assert!(decision.reason.contains("live peer pressure reports"));
        assert_eq!(decision.decision_receipt.peer_pressure_report_count, 1);
        assert!(
            (decision.decision_receipt.peer_pressure_max_pressure_scaled - 8500).abs() <= 1,
            "receipt peer pressure should round near 8500, got {}",
            decision.decision_receipt.peer_pressure_max_pressure_scaled
        );
        assert_eq!(
            decision
                .decision_receipt
                .peer_pressure_backpressure_threshold_scaled,
            8000
        );
        assert!(
            decision
                .decision_receipt
                .peer_pressure_backpressure_triggered
        );
        assert_eq!(
            decision
                .decision_receipt
                .peer_pressure_max_degradation_level,
            DegradationLevel::Moderate as u8
        );
        assert!(decision.reason.contains("peer pressure threshold 0.800"));
        assert!(
            decision
                .reason
                .contains("peer pressure backpressure triggered true")
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.live_peer_pressure_reports, 1);
        assert!(
            (metrics.max_peer_pressure_scaled - 8500).abs() <= 1,
            "scaled peer pressure should round near 8500, got {}",
            metrics.max_peer_pressure_scaled
        );
        assert_eq!(
            metrics.max_peer_degradation_level,
            DegradationLevel::Moderate as u8
        );
    }

    #[test]
    fn test_configurable_peer_pressure_threshold_controls_backpressure() {
        let mut tuned_config = SwarmPressureGovernorConfig::default();
        tuned_config.peer_pressure_backpressure_threshold = 0.70;
        let tuned_runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let tuned_pressure_governor = PressureGovernor::new(
            tuned_config.pressure_config.clone(),
            std::sync::Arc::clone(&tuned_runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let tuned_governor = SwarmPressureGovernor::new(
            tuned_config,
            tuned_runtime.resource_monitor(),
            tuned_pressure_governor,
        );
        tuned_governor
            .record_peer_pressure("peer-tuned", 0.75, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        let tuned_cx = tuned_runtime.request_cx_with_budget(Budget::INFINITE);

        let tuned_decision = tuned_governor
            .check_region_admission(&tuned_cx, RegionPriority::Normal, None)
            .expect("tuned peer pressure admission should produce a decision");

        assert!(matches!(
            tuned_decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(tuned_decision.reason.contains("max peer pressure 0.750"));

        let default_governor = create_test_swarm_governor();
        default_governor
            .record_peer_pressure("peer-default", 0.75, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        let default_runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let default_cx = default_runtime.request_cx_with_budget(Budget::INFINITE);

        let default_decision = default_governor
            .check_region_admission(&default_cx, RegionPriority::Normal, None)
            .expect("default peer pressure admission should produce a decision");

        assert!(matches!(
            default_decision.decision,
            AdmissionDecision::Admit
        ));
    }

    #[test]
    fn test_invalid_peer_pressure_threshold_falls_back_to_default() {
        for invalid_threshold in [f64::NAN, -0.01] {
            let mut config = SwarmPressureGovernorConfig::default();
            config.peer_pressure_backpressure_threshold = invalid_threshold;
            let runtime = std::sync::Arc::new(
                RuntimeBuilder::new()
                    .worker_threads(1)
                    .build()
                    .expect("Failed to create test runtime"),
            );
            let pressure_governor = PressureGovernor::new(
                config.pressure_config.clone(),
                std::sync::Arc::clone(&runtime),
                Metrics::new(),
            )
            .expect("Failed to create pressure governor");
            let governor =
                SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);

            governor
                .record_peer_pressure("peer-below-default", 0.75, DegradationLevel::Light)
                .expect("peer pressure report should be accepted");
            let below_default = governor
                .check_region_admission(&cx, RegionPriority::Normal, None)
                .expect("admission should use fallback peer threshold");
            assert!(matches!(below_default.decision, AdmissionDecision::Admit));

            assert!(governor.clear_peer_pressure("peer-below-default").is_some());
            governor
                .record_peer_pressure("peer-above-default", 0.85, DegradationLevel::Light)
                .expect("peer pressure report should be accepted");
            let above_default = governor
                .check_region_admission(&cx, RegionPriority::Normal, None)
                .expect("admission should use fallback peer threshold");
            assert!(matches!(
                above_default.decision,
                AdmissionDecision::AdmitWithBackpressure
            ));
        }
    }

    #[test]
    fn test_peer_pressure_rejects_low_priority_admission() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("peer-b", 0.81, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Low, None)
            .expect("Peer pressure admission should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("peer pressure"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn test_workload_pressure_feedback_backpressures_matching_workload_only() {
        let governor = create_test_swarm_governor();
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "hot-proof",
                    SwarmAdmissionOwner::new(" DustyGorge ")
                        .with_bead_id(" asupersync-oxqrae.2 ")
                        .with_reservation_scope(" src/observability/swarm_pressure_governor.rs "),
                    SwarmProofLaneKind::CargoCheckLib,
                )
                .with_pressures(0.20, 0.30, 0.85, 0.40, 0.10),
            )
            .expect("workload feedback should be accepted");
        {
            let reports = governor.workload_pressure_feedback.lock().unwrap();
            let feedback = reports
                .get("hot-proof")
                .expect("feedback should be stored by normalized workload id");
            assert_eq!(feedback.owner.agent_name, "DustyGorge");
            assert_eq!(
                feedback.owner.bead_id.as_deref(),
                Some("asupersync-oxqrae.2")
            );
            assert_eq!(
                feedback.owner.reservation_scope.as_deref(),
                Some("src/observability/swarm_pressure_governor.rs")
            );
        }

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let hot_request =
            SwarmWorkloadAdmissionRequest::new("hot-proof", SwarmAdmissionOwner::new("DustyGorge"));
        let hot_decision = governor
            .check_workload_admission(&cx, &hot_request)
            .expect("hot workload admission should classify");
        assert!(matches!(
            hot_decision.decision,
            AdmissionDecision::AdmitWithBackpressure
        ));
        assert!(
            hot_decision
                .reason
                .contains("live workload feedback reports")
        );
        assert!(hot_decision.reason.contains("max workload pressure 0.850"));
        assert!(
            hot_decision
                .reason
                .contains("dominant workload pressure source rch_queue")
        );
        assert_eq!(
            hot_decision.decision_receipt.workload_feedback_report_count,
            1
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            8500
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_backpressure_threshold_scaled,
            8000
        );
        assert!(
            hot_decision
                .decision_receipt
                .workload_feedback_backpressure_triggered
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert!(
            hot_decision
                .reason
                .contains("workload feedback threshold 0.800")
        );
        assert!(
            hot_decision
                .reason
                .contains("workload feedback backpressure triggered true")
        );
        assert_eq!(
            hot_decision.decision_receipt.workload_queue_pressure_scaled,
            2000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_disk_io_pressure_scaled,
            3000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_rch_queue_pressure_scaled,
            8500
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_validation_frontier_pressure_scaled,
            4000
        );
        assert_eq!(
            hot_decision
                .decision_receipt
                .workload_cancellation_tail_pressure_scaled,
            1000
        );

        let cold_request = SwarmWorkloadAdmissionRequest::new(
            "cold-proof",
            SwarmAdmissionOwner::new("DustyGorge"),
        );
        let cold_decision = governor
            .check_workload_admission(&cx, &cold_request)
            .expect("cold workload admission should classify");
        assert!(matches!(cold_decision.decision, AdmissionDecision::Admit));
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_report_count,
            0
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_max_pressure_scaled,
            0
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_backpressure_threshold_scaled,
            8000
        );
        assert!(
            !cold_decision
                .decision_receipt
                .workload_feedback_backpressure_triggered
        );
        assert_eq!(
            cold_decision
                .decision_receipt
                .workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::None
        );

        let metrics = governor.metrics();
        assert_eq!(metrics.workload_feedback_reports_recorded, 1);
        assert_eq!(metrics.live_workload_feedback_reports, 1);
        assert!(
            (metrics.max_workload_feedback_pressure_scaled - 8500).abs() <= 1,
            "scaled workload feedback should round near 8500, got {}",
            metrics.max_workload_feedback_pressure_scaled
        );
        assert_eq!(
            metrics.workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::RchQueue
        );
        assert_eq!(metrics.max_workload_feedback_queue_pressure_scaled, 2000);
        assert_eq!(metrics.max_workload_feedback_disk_io_pressure_scaled, 3000);
        assert_eq!(
            metrics.max_workload_feedback_rch_queue_pressure_scaled,
            8500
        );
        assert_eq!(
            metrics.max_workload_feedback_validation_frontier_pressure_scaled,
            4000
        );
        assert_eq!(
            metrics.max_workload_feedback_cancellation_tail_pressure_scaled,
            1000
        );
    }

    #[test]
    fn test_workload_pressure_feedback_rejects_background_and_prunes_stale_reports() {
        let governor = create_test_swarm_governor();
        governor
            .record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "background-proof",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(0.10, 0.20, 0.30, 0.90, 0.40),
            )
            .expect("workload feedback should be accepted");
        assert!(matches!(
            governor.record_workload_pressure_feedback(
                SwarmWorkloadPressureFeedback::new(
                    "bad-feedback",
                    SwarmAdmissionOwner::new("DustyGorge"),
                    SwarmProofLaneKind::Test,
                )
                .with_pressures(f64::NAN, 0.0, 0.0, 0.0, 0.0),
            ),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let request = SwarmWorkloadAdmissionRequest::new(
            "background-proof",
            SwarmAdmissionOwner::new("DustyGorge"),
        )
        .with_priority(RegionPriority::BestEffort);
        let decision = governor
            .check_workload_admission(&cx, &request)
            .expect("background workload admission should classify");
        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("live workload feedback reports"));

        {
            let mut reports = governor.workload_pressure_feedback.lock().unwrap();
            reports
                .get_mut("background-proof")
                .expect("feedback should exist before forced stale pruning")
                .reported_at = Instant::now()
                .checked_sub(
                    governor
                        .config
                        .workload_feedback_max_age
                        .checked_mul(2)
                        .expect("test feedback max age should double"),
                )
                .expect("test instant should support feedback-age subtraction");
        }
        assert_eq!(governor.prune_stale_workload_pressure_feedback(), 1);
        let metrics = governor.metrics();
        assert_eq!(metrics.live_workload_feedback_reports, 0);
        assert_eq!(
            metrics.workload_feedback_dominant_pressure_source,
            SwarmWorkloadPressureSource::None
        );
        assert_eq!(metrics.max_workload_feedback_pressure_scaled, 0);
        assert_eq!(
            metrics.max_workload_feedback_validation_frontier_pressure_scaled,
            0
        );
    }

    #[test]
    fn test_hard_pressure_reject_is_not_downgraded_by_moderate_degradation() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let mut config = SwarmPressureGovernorConfig::default();
        config.pressure_config.enabled = true;
        config.pressure_config.admission_control = true;
        config.pressure_config.sample_interval = Duration::ZERO;

        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        pressure_governor.record_channel_backlog_sample(5, 4);

        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Moderate,
            );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("hard pressure rejection should produce a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("Rejected due to pressure"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn test_emergency_system_degradation_rejects_normal_admission() {
        let governor = create_test_swarm_governor();
        governor
            .resource_monitor
            .pressure()
            .update_degradation_level(
                crate::runtime::resource_monitor::ResourceType::Memory,
                DegradationLevel::Emergency,
            );
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Normal, None)
            .expect("Emergency degradation should still return a decision");

        assert!(matches!(decision.decision, AdmissionDecision::Reject));
        assert!(decision.envelope.is_none());
        assert!(decision.reason.contains("Emergency"));
        assert_eq!(governor.metrics().regions_rejected, 1);
    }

    #[test]
    fn metamorphic_degradation_never_makes_noncritical_admission_safer() {
        let governor = create_test_swarm_governor();
        let levels = [
            DegradationLevel::None,
            DegradationLevel::Light,
            DegradationLevel::Moderate,
            DegradationLevel::Heavy,
            DegradationLevel::Emergency,
        ];

        for priority in [
            RegionPriority::Normal,
            RegionPriority::Low,
            RegionPriority::BestEffort,
        ] {
            let mut previous_rank = 0;
            for level in levels {
                let decision = governor
                    .evaluate_swarm_admission(
                        priority,
                        &AdmissionDecision::Admit,
                        level,
                        None,
                        SwarmPeerPressureSummary::EMPTY,
                        SwarmWorkloadPressureSummary::EMPTY,
                    )
                    .expect("metamorphic degradation admission should classify");
                let rank = admission_rank(decision.decision);
                assert!(
                    rank >= previous_rank,
                    "worse degradation made {priority:?} admission safer: {level:?} -> {:?}",
                    decision.decision
                );
                previous_rank = rank;
            }
        }

        let critical = governor
            .evaluate_swarm_admission(
                RegionPriority::Critical,
                &AdmissionDecision::Admit,
                DegradationLevel::Emergency,
                None,
                SwarmPeerPressureSummary::EMPTY,
                SwarmWorkloadPressureSummary::EMPTY,
            )
            .expect("critical admission should classify");
        assert!(matches!(critical.decision, AdmissionDecision::Admit));
    }

    #[test]
    fn metamorphic_requested_memory_never_makes_normal_admission_safer() {
        let mut config = SwarmPressureGovernorConfig::default();
        config.default_memory_budget_bytes = 1024;
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let pressure_governor = PressureGovernor::new(
            config.pressure_config.clone(),
            std::sync::Arc::clone(&runtime),
            Metrics::new(),
        )
        .expect("Failed to create pressure governor");
        let governor =
            SwarmPressureGovernor::new(config, runtime.resource_monitor(), pressure_governor);
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let requests = [0, 512, 1024, 1025, 2048, u64::MAX];

        let mut previous_rank = 0;
        for requested_memory in requests {
            let decision = governor
                .check_region_admission(&cx, RegionPriority::Normal, Some(requested_memory))
                .expect("memory-pressure admission should classify");
            let rank = admission_rank(decision.decision);
            assert!(
                rank >= previous_rank,
                "larger requested memory made normal admission safer: {requested_memory} -> {:?}",
                decision.decision
            );
            if requested_memory <= 1024 {
                assert!(
                    decision.envelope.is_some(),
                    "in-budget request should preserve admitted envelope"
                );
            } else {
                assert!(
                    decision.envelope.is_none(),
                    "over-budget request must not allocate an envelope"
                );
            }
            previous_rank = rank;
        }
    }

    #[test]
    fn metamorphic_peer_pressure_transition_storm_never_improves_background_admission() {
        let governor = create_test_swarm_governor();
        let peer_pressures = [0.0, 0.20, 0.79, 0.80, 0.95, 1.25];

        for priority in [
            RegionPriority::Normal,
            RegionPriority::Low,
            RegionPriority::BestEffort,
        ] {
            let mut previous_rank = 0;
            for peer_pressure in peer_pressures {
                governor
                    .record_peer_pressure("peer-storm", peer_pressure, DegradationLevel::Light)
                    .expect("peer pressure report should be accepted");
                let decision = governor
                    .evaluate_swarm_admission(
                        priority,
                        &AdmissionDecision::Admit,
                        DegradationLevel::None,
                        None,
                        governor.peer_pressure_summary(Instant::now()),
                        SwarmWorkloadPressureSummary::EMPTY,
                    )
                    .expect("peer-pressure admission should classify");
                let rank = admission_rank(decision.decision);
                assert!(
                    rank >= previous_rank,
                    "higher peer pressure made {priority:?} admission safer: {peer_pressure} -> {:?}",
                    decision.decision
                );
                previous_rank = rank;
            }
            assert!(governor.clear_peer_pressure("peer-storm").is_some());
        }
    }

    #[test]
    fn test_peer_pressure_rejects_invalid_reports() {
        let governor = create_test_swarm_governor();

        assert!(matches!(
            governor.record_peer_pressure("", 0.5, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert!(matches!(
            governor.record_peer_pressure("peer-a", f64::NAN, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert!(matches!(
            governor.record_peer_pressure("peer-a", -0.01, DegradationLevel::Light),
            Err(SwarmPressureError::SwarmCoordinationFailed { .. })
        ));
        assert_eq!(governor.metrics().live_peer_pressure_reports, 0);
    }

    #[test]
    fn test_peer_pressure_normalizes_instance_ids() {
        let governor = create_test_swarm_governor();

        governor
            .record_peer_pressure(" peer-a ", 0.40, DegradationLevel::Light)
            .expect("peer pressure report should be accepted");
        governor
            .record_peer_pressure("peer-a", 0.85, DegradationLevel::Moderate)
            .expect("same peer report should update by normalized id");

        let metrics = governor.metrics();
        assert_eq!(
            metrics.live_peer_pressure_reports, 1,
            "whitespace variants must not inflate live peer counts"
        );
        assert!(
            (metrics.max_peer_pressure_scaled - 8500).abs() <= 1,
            "normalized update should replace the old peer pressure, got {}",
            metrics.max_peer_pressure_scaled
        );

        let cleared = governor
            .clear_peer_pressure(" peer-a ")
            .expect("normalized peer report should be clearable by whitespace variant");
        assert_eq!(cleared.instance_id, "peer-a");
        assert_eq!(governor.metrics().live_peer_pressure_reports, 0);
    }

    #[test]
    fn test_prune_stale_peer_pressure_reports_removes_dead_peer_state() {
        let governor = create_test_swarm_governor();
        governor
            .record_peer_pressure("stale-peer", 0.91, DegradationLevel::Heavy)
            .expect("stale peer report should be accepted");
        governor
            .record_peer_pressure("fresh-peer", 0.40, DegradationLevel::Light)
            .expect("fresh peer report should be accepted");
        let stale_reported_at = Instant::now()
            .checked_sub(
                governor
                    .config
                    .peer_pressure_max_age
                    .checked_mul(2)
                    .expect("test peer pressure max age should double without overflow"),
            )
            .expect("test stale timestamp should be representable");

        {
            let mut reports = governor.peer_pressure_reports.lock().unwrap();
            reports
                .get_mut("stale-peer")
                .expect("stale peer report should exist before pruning")
                .reported_at = stale_reported_at;
        }

        assert_eq!(governor.prune_stale_peer_pressure_reports(), 1);
        assert!(governor.clear_peer_pressure("stale-peer").is_none());

        let metrics = governor.metrics();
        assert_eq!(metrics.live_peer_pressure_reports, 1);
        assert_eq!(
            metrics.max_peer_degradation_level,
            DegradationLevel::Light as u8
        );
        assert!(governor.clear_peer_pressure("fresh-peer").is_some());
    }

    #[test]
    fn test_critical_priority_always_admitted() {
        let governor = create_test_swarm_governor();
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor
            .check_region_admission(&cx, RegionPriority::Critical, None)
            .expect("Critical admission should succeed");

        assert!(matches!(decision.decision, AdmissionDecision::Admit));
        assert_eq!(decision.reason, "Admission approved");
    }
