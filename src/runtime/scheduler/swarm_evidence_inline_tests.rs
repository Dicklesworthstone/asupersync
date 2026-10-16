    use super::*;

    fn baseline_artifact() -> SchedulerEvidenceArtifact {
        SchedulerEvidenceArtifact {
            schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            run_label: "unit-baseline-64c".to_string(),
            workload_class: SchedulerWorkloadClass::InteractiveSwarm,
            topology: SchedulerTopologyDescriptor {
                worker_threads: 64,
                cohort_count: 2,
                memory_budget_gib: 256,
            },
            current_knobs: SchedulerKnobProfile {
                worker_threads: 64,
                steal_batch_size: 8,
                cancel_streak_limit: 16,
                global_queue_limit: 0,
                parking_enabled: true,
            },
            metrics: SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 5_000,
                wake_to_run_p95_ns: 20_000,
                wake_to_run_p99_ns: 60_000,
                queue_residency_p50_ns: 8_000,
                queue_residency_p95_ns: 30_000,
                queue_residency_p99_ns: 90_000,
                ready_backlog_p95: 32,
                ready_backlog_p99: 96,
                cancel_debt_p95: 4,
                cancel_debt_p99: 8,
                remote_steal_ratio_pct: Some(12),
                cross_cohort_wake_p99_ns: Some(70_000),
            },
            notes: vec!["unit".to_string()],
        }
    }

    fn coordination_input(
        family: CoordinationPressureFamily,
        workload_id: &str,
    ) -> SchedulerCoordinationEvidenceInput {
        SchedulerCoordinationEvidenceInput {
            evidence_input_id: format!("coordination-evidence-{workload_id}"),
            workload_id: workload_id.to_string(),
            workload_class: SchedulerWorkloadClass::InteractiveSwarm,
            scenario_family: family,
            semantic_pressure: vec![
                "ready-backlog".to_string(),
                "queue-residency-tail".to_string(),
            ],
            provenance_only_context: vec![
                "pseudonymized-agent".to_string(),
                "hashed-path".to_string(),
            ],
            source_event_count: 2,
            source_hashes: vec!["sha256:event-a".to_string(), "sha256:event-b".to_string()],
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
        }
    }

    #[test]
    fn validate_rejects_schema_and_required_zero_fields() {
        let mut artifact = baseline_artifact();
        artifact.schema_version = "asupersync.scheduler-evidence.v0".to_string();
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
                expected: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
                found: "asupersync.scheduler-evidence.v0".to_string(),
            })
        );

        let mut artifact = baseline_artifact();
        artifact.run_label = "   ".to_string();
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::EmptyRunLabel)
        );

        let mut artifact = baseline_artifact();
        artifact.topology.worker_threads = 0;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::ZeroWorkerThreads)
        );

        let mut artifact = baseline_artifact();
        artifact.current_knobs.steal_batch_size = 0;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::ZeroStealBatchSize)
        );
    }

    #[test]
    fn validate_rejects_metric_boundary_violations() {
        let mut artifact = baseline_artifact();
        artifact.metrics.wake_to_run_p95_ns = artifact.metrics.wake_to_run_p50_ns - 1;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::NonMonotonicPercentiles {
                field: "wake_to_run",
            })
        );

        let mut artifact = baseline_artifact();
        artifact.metrics.remote_steal_ratio_pct = Some(101);
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::RemoteStealRatioOutOfRange(101))
        );
    }

    #[test]
    fn tune_report_keeps_conservative_fallback_for_balanced_baseline() {
        let artifact = baseline_artifact();
        let report = artifact
            .tune_report()
            .expect("balanced artifact should tune");

        assert_eq!(report.profile_name, "conservative_baseline");
        assert_eq!(report.recommended_knobs, artifact.current_knobs);
        assert_eq!(report.fallback_profile, artifact.current_knobs);
        assert_eq!(report.global_queue_limit_hint, None);
        assert_eq!(
            report.reason_codes,
            vec![SchedulerRecommendationReason::BalancedBaseline]
        );
        assert_eq!(report.confidence_percent, 65);
        assert!(
            report
                .explanation
                .iter()
                .any(|line| line.contains("conservative baseline envelope"))
        );
    }

    #[test]
    fn coordination_evidence_inputs_validate_all_pressure_families() {
        let evidence = SchedulerCoordinationEvidenceInputs {
            schema_version: SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION.to_string(),
            source_pack_id: "agent-swarm-coordination-pressure".to_string(),
            source_bundle_hash: "sha256:coordination-runtime-fixture".to_string(),
            source_run_id: "coordination-runtime-fixture-accepted-all-families".to_string(),
            evidence_inputs: vec![
                coordination_input(
                    CoordinationPressureFamily::TrackerLockContention,
                    "ASWARM-WL-LOCK-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ConcurrentRchProofs,
                    "ASWARM-WL-RCH-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::FailClosedDirtyFrontier,
                    "ASWARM-WL-DIRTY-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ArtifactRetrievalTail,
                    "ASWARM-WL-ARTIFACT-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ProofRunnerFanout,
                    "ASWARM-WL-FANOUT-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::StaleInProgressReclaim,
                    "ASWARM-WL-STALE-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::CoordinationLatencyBurst,
                    "ASWARM-WL-LATENCY-001",
                ),
            ],
        };

        evidence
            .validate()
            .expect("coordination evidence validates");
    }

    #[test]
    fn coordination_evidence_rejects_missing_semantics_and_unstable_hashes() {
        let mut evidence = SchedulerCoordinationEvidenceInputs {
            schema_version: SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION.to_string(),
            source_pack_id: "agent-swarm-coordination-pressure".to_string(),
            source_bundle_hash: "sha256:coordination-runtime-fixture".to_string(),
            source_run_id: "coordination-runtime-fixture-accepted-all-families".to_string(),
            evidence_inputs: vec![coordination_input(
                CoordinationPressureFamily::TrackerLockContention,
                "ASWARM-WL-LOCK-001",
            )],
        };

        evidence.evidence_inputs[0].semantic_pressure.clear();
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::EmptySemanticPressure)
        );

        evidence.evidence_inputs[0].semantic_pressure = vec!["ready-backlog".to_string()];
        evidence.evidence_inputs[0].source_hashes = vec!["not-a-sha".to_string()];
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::InvalidSourceHash {
                found: "not-a-sha".to_string(),
            })
        );

        evidence.evidence_inputs.clear();
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::EmptyEvidenceInputSet)
        );
    }
