    use super::*;
    use crate::runtime::config::{
        ArenaLocalityAccessModel, ArenaLocalityPolicy, RuntimeConfig, WorkerCohortMapping,
    };
    use crate::runtime::resource_monitor::{
        DegradationLevel, ResourceProbeOperatorVerdict, ResourceType,
        RuntimePressureEarlyWarningSeverity, RuntimePressureResourceSnapshot,
        RuntimePressureSignalSnapshot, RuntimePressureSignalStatus, RuntimePressureSpectralClass,
        RuntimePressureSpectralSnapshot,
    };

    fn large_host_config(policy: ArenaTemperaturePolicy) -> RuntimeConfig {
        let mut config = RuntimeConfig::default();
        config.worker_threads = 64;
        config.capacity_hints = Some(RuntimeCapacityHints::new(4_096, 1_024, 2_048));
        config.trace_storage_profile = TraceStorageProfile::LargeMemory256G;
        config.arena_temperature_policy = policy;
        let mut worker_to_cohort = Vec::with_capacity(64);
        for cohort in 0..8 {
            for _ in 0..8 {
                worker_to_cohort.push(cohort);
            }
        }
        config.worker_cohort_map = Some(WorkerCohortMapping::new(worker_to_cohort));
        config
    }

    fn access_model_with_win() -> ArenaLocalityAccessModel {
        ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![900, 10, 10, 10, 10, 10, 10, 10],
            region_arena_touches_by_cohort: vec![800, 20, 20, 20, 20, 20, 20, 20],
            obligation_arena_touches_by_cohort: vec![700, 30, 30, 30, 30, 30, 30, 30],
            task_record_pool_touches_by_cohort: vec![600, 40, 40, 40, 40, 40, 40, 40],
        }
    }

    fn access_model_no_win() -> ArenaLocalityAccessModel {
        ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![100; 8],
            region_arena_touches_by_cohort: vec![100; 8],
            obligation_arena_touches_by_cohort: vec![100; 8],
            task_record_pool_touches_by_cohort: vec![100; 8],
        }
    }

    fn locality_report(
        config: &RuntimeConfig,
        access_model: &ArenaLocalityAccessModel,
    ) -> ArenaLocalityReport {
        config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6_000,
                accounting_epoch: 1,
            },
            Some(95),
            access_model,
        )
    }

    fn warm_proof() -> ProofPackWarmthTelemetry {
        ProofPackWarmthTelemetry::new(true, true, 30, 300)
    }

    fn hot_artifact_snapshot() -> ArtifactMemoryPressureSnapshot {
        ArtifactMemoryPressureSnapshot {
            resident_bytes: 900,
            max_resident_bytes: 1_000,
            hot_resident_bytes: 300,
            cold_resident_bytes: 600,
            spill_eligible_bytes: 512,
            remote_numa_bytes: 0,
            pressure_bps: 8_700,
            high_pressure: true,
            duplicate_bytes_avoided: 0,
            artifact_count: 3,
        }
    }

    fn pressure_snapshot(verdict: RuntimePressureVerdict) -> RuntimePressureSnapshot {
        RuntimePressureSnapshot {
            schema_version: "test-runtime-pressure-v1".to_string(),
            overall_verdict: verdict,
            missing_signal_count: 0,
            degraded_signal_count: u64::from(verdict == RuntimePressureVerdict::Degraded),
            critical_signal_count: u64::from(verdict == RuntimePressureVerdict::Critical),
            resource_composite_degradation: if verdict == RuntimePressureVerdict::Critical {
                DegradationLevel::Emergency
            } else {
                DegradationLevel::None
            },
            platform_probe_operator_verdict: ResourceProbeOperatorVerdict::Complete,
            signal_statuses: vec![RuntimePressureSignalSnapshot {
                signal: crate::runtime::resource_monitor::RuntimePressureSignal::Resources,
                status: if verdict == RuntimePressureVerdict::Critical {
                    RuntimePressureSignalStatus::Critical
                } else {
                    RuntimePressureSignalStatus::Present
                },
                reason: "test".to_string(),
            }],
            resources: vec![RuntimePressureResourceSnapshot {
                resource_type: ResourceType::Memory,
                resource_label: "memory".to_string(),
                current: 98,
                soft_limit: 70,
                hard_limit: 85,
                max_limit: 100,
                usage_bps: 9_800,
                soft_limit_exceeded: true,
                hard_limit_exceeded: true,
                critical_limit_exceeded: verdict == RuntimePressureVerdict::Critical,
                degradation_level: DegradationLevel::Emergency,
            }],
            scheduler: None,
            spectral: RuntimePressureSpectralSnapshot {
                class: RuntimePressureSpectralClass::Healthy,
                fiedler_micro_units: None,
                spectral_gap_bps: None,
                spectral_radius_micro_units: None,
                bottleneck_count: 0,
                components: None,
                approaching_disconnect: false,
                trapped_wait_cycle: false,
                early_warning_severity: RuntimePressureEarlyWarningSeverity::None,
            },
            spectral_recommendations: Vec::new(),
            region_memory_budgets: Vec::new(),
            rch_proof_lanes: Vec::new(),
        }
    }

    fn base_input<'a>(
        config: &'a RuntimeConfig,
        locality: Option<&'a ArenaLocalityReport>,
    ) -> MemoryResidencyPolicyInput<'a> {
        let mut input = MemoryResidencyPolicyInput::new(
            config.resolved_capacity_hints(),
            config.trace_storage_profile,
            config.arena_temperature_policy,
        )
        .with_large_page_cold_slabs_supported(true)
        .with_proof_pack_warmth(warm_proof());
        if let Some(locality) = locality {
            input = input.with_locality_report(locality, 30);
        }
        input
    }

    #[test]
    fn default_policy_is_disabled_and_falls_back() {
        let config = RuntimeConfig::default();
        let input = MemoryResidencyPolicyInput::new(
            config.resolved_capacity_hints(),
            config.trace_storage_profile,
            config.arena_temperature_policy,
        );
        let decision = MemoryResidencyPolicy::default().decide(&input);

        assert!(!decision.policy_enabled);
        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::PolicyDisabled)
        );
        assert!(
            decision
                .no_claim_boundaries
                .contains(&MemoryResidencyNoClaimBoundary::DefaultRuntimeBehaviorUnchanged)
        );
        assert!(
            decision
                .no_claim_boundaries
                .contains(&MemoryResidencyNoClaimBoundary::NoLiveTaskMutation)
        );
    }

    #[test]
    fn fresh_topology_selects_warm_recommendation() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Warm);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::FreshTopology)
        );
        assert!(decision.recommended_warm_evidence_bytes > 0);
        assert_eq!(
            decision.live_task_action,
            MemoryResidencyLiveTaskAction::RecommendOnly
        );
    }

    #[test]
    fn stale_topology_fails_closed_to_fallback() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality)).with_locality_report(&locality, 901);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::StaleTopology)
        );
    }

    #[test]
    fn no_win_locality_refuses_the_policy() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_no_win());
        let input = base_input(&config, Some(&locality));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::NoWinLocality)
        );
    }

    #[test]
    fn cold_evidence_budget_exhaustion_falls_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: 1,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ColdEvidenceBudgetExhausted)
        );
    }

    #[test]
    fn proof_pack_warmth_mismatch_falls_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let input = base_input(&config, Some(&locality))
            .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(false, false, 1_000, 300));
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ProofPackWarmthMismatch)
        );
    }

    #[test]
    fn critical_runtime_pressure_snapshot_refuses_the_policy() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let pressure = pressure_snapshot(RuntimePressureVerdict::Critical);
        let input = base_input(&config, Some(&locality)).with_runtime_pressure(&pressure);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::NoWin);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::CriticalMemoryPressure)
        );
    }

    #[test]
    fn unsupported_large_pages_fall_back() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidenceLargePages);
        let locality = locality_report(&config, &access_model_with_win());
        let input =
            base_input(&config, Some(&locality)).with_large_page_cold_slabs_supported(false);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Fallback);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::UnsupportedLargePages)
        );
    }

    #[test]
    fn artifact_cache_pressure_selects_cold_when_spill_is_available() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: u64::MAX,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let decision = MemoryResidencyPolicy::experimental_opt_in().decide(&input);

        assert_eq!(decision.selected_tier, MemoryResidencyTier::Cold);
        assert!(
            decision
                .reason_codes
                .contains(&MemoryResidencyReasonCode::ArtifactCachePressure)
        );
        assert!(decision.recommended_cold_evidence_bytes > 0);
    }

    #[test]
    fn stable_report_lines_are_byte_stable() {
        let config = large_host_config(ArenaTemperaturePolicy::TieredColdEvidence);
        let locality = locality_report(&config, &access_model_with_win());
        let cache = ArtifactMemoryPressureSnapshot {
            spill_eligible_bytes: u64::MAX,
            ..hot_artifact_snapshot()
        };
        let input = base_input(&config, Some(&locality)).with_artifact_cache_pressure(&cache);
        let policy = MemoryResidencyPolicy::experimental_opt_in();

        let first = policy.decide(&input).stable_report_lines();
        let second = policy.decide(&input).stable_report_lines();

        assert_eq!(first, second);
        assert!(first.iter().any(|line| line == "selected_tier=cold"));
        assert!(
            first
                .iter()
                .any(|line| line == "no_claim=no_performance_claim")
        );
    }
