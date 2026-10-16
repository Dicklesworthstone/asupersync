    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn derived_policy_defaults_preserve_existing_variants() {
        init_test("derived_policy_defaults_preserve_existing_variants");
        crate::assert_with_log!(
            BlockingPoolAffinityProfile::default() == BlockingPoolAffinityProfile::Disabled,
            "blocking affinity default",
            BlockingPoolAffinityProfile::Disabled,
            BlockingPoolAffinityProfile::default()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::default() == ArenaTemperaturePolicy::Unified,
            "arena temperature default",
            ArenaTemperaturePolicy::Unified,
            ArenaTemperaturePolicy::default()
        );
        crate::assert_with_log!(
            ArenaLocalityPolicy::default() == ArenaLocalityPolicy::Disabled,
            "arena locality default",
            ArenaLocalityPolicy::Disabled,
            ArenaLocalityPolicy::default()
        );
        crate::test_complete!("derived_policy_defaults_preserve_existing_variants");
    }

    #[test]
    fn artifact_json_path_validation_accepts_case_insensitive_json_paths() {
        init_test("artifact_json_path_validation_accepts_case_insensitive_json_paths");
        for value in [
            "evidence/controller.json",
            "evidence/controller.JSON",
            "evidence/controller.JsOn",
        ] {
            let result = validate_artifact_json_path(value, "artifact_id");
            crate::assert_with_log!(
                result.is_ok(),
                "case-insensitive json artifact path",
                "Ok",
                format!("{value}: {result:?}")
            );
        }
        crate::test_complete!("artifact_json_path_validation_accepts_case_insensitive_json_paths");
    }

    #[test]
    fn artifact_json_path_validation_rejects_unsafe_or_non_json_paths() {
        init_test("artifact_json_path_validation_rejects_unsafe_or_non_json_paths");
        for value in [
            "",
            "evidence/controller.txt",
            "../evidence/controller.json",
            "evidence/controller space.json",
        ] {
            let result = validate_artifact_json_path(value, "artifact_id");
            crate::assert_with_log!(
                result.is_err(),
                "unsafe or non-json artifact path rejected",
                "Err",
                format!("{value}: {result:?}")
            );
        }
        crate::test_complete!("artifact_json_path_validation_rejects_unsafe_or_non_json_paths");
    }

    #[test]
    fn shadow_run_regret_margin_saturates_without_wrapping() {
        init_test("shadow_run_regret_margin_saturates_without_wrapping");
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(150, 100) == 50,
            "positive regret margin",
            50,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(150, 100)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 150) == -50,
            "negative regret margin",
            -50,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 150)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 100) == 0,
            "zero regret margin",
            0,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(100, 100)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(u64::MAX, 0) == i64::MAX,
            "positive regret margin saturates",
            i64::MAX,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(u64::MAX, 0)
        );
        crate::assert_with_log!(
            signed_profile_bundle_shadow_run_regret_margin_basis_points(0, u64::MAX) == -i64::MAX,
            "negative regret margin saturates",
            -i64::MAX,
            signed_profile_bundle_shadow_run_regret_margin_basis_points(0, u64::MAX)
        );
        crate::test_complete!("shadow_run_regret_margin_saturates_without_wrapping");
    }

    #[test]
    fn test_default_config_sane() {
        init_test("test_default_config_sane");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            config.worker_threads >= 1,
            "worker_threads",
            true,
            config.worker_threads >= 1
        );
        crate::assert_with_log!(
            config.worker_cohort_map.is_none(),
            "worker_cohort_map",
            "None",
            format!("{:?}", config.worker_cohort_map)
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            !config.thread_name_prefix.is_empty(),
            "thread_name_prefix",
            true,
            !config.thread_name_prefix.is_empty()
        );
        crate::assert_with_log!(
            config.poll_budget == 128,
            "poll_budget",
            128,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.trace_storage_profile == TraceStorageProfile::Default,
            "trace_storage_profile",
            TraceStorageProfile::Default,
            config.trace_storage_profile
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 0,
            "browser_ready_handoff_limit",
            0,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            !config.browser_worker_offload.enabled,
            "browser_worker_offload.enabled",
            false,
            config.browser_worker_offload.enabled
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 1024,
            "browser_worker_offload.min_task_cost",
            1024,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 16,
            "browser_worker_offload.max_in_flight",
            16,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            !config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            false,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 128,
            "adaptive_cancel_streak_epoch_steps",
            128,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            !config.enable_read_biased_region_snapshot,
            "enable_read_biased_region_snapshot",
            false,
            config.enable_read_biased_region_snapshot
        );
        crate::assert_with_log!(
            config.logical_clock_mode.is_none(),
            "logical_clock_mode",
            "None",
            format!("{:?}", config.logical_clock_mode)
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Panic,
            "obligation_leak_response",
            ObligationLeakResponse::Panic,
            config.obligation_leak_response
        );
        crate::assert_with_log!(
            config.cancel_attribution == CancelAttributionConfig::default(),
            "cancel_attribution default",
            CancelAttributionConfig::default(),
            config.cancel_attribution
        );
        crate::assert_with_log!(
            config.arena_temperature_policy == ArenaTemperaturePolicy::Unified,
            "arena_temperature_policy",
            ArenaTemperaturePolicy::Unified,
            config.arena_temperature_policy
        );
        crate::test_complete!("test_default_config_sane");
    }

    #[test]
    fn arena_temperature_policy_text_roundtrip_is_stable() {
        init_test("arena_temperature_policy_text_roundtrip_is_stable");
        crate::assert_with_log!(
            ArenaTemperaturePolicy::Unified.as_str() == "unified",
            "unified as_str",
            "unified",
            ArenaTemperaturePolicy::Unified.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::TieredColdEvidence.as_str() == "tiered-cold-evidence",
            "tiered-cold-evidence as_str",
            "tiered-cold-evidence",
            ArenaTemperaturePolicy::TieredColdEvidence.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages.as_str()
                == "tiered-cold-evidence-large-pages",
            "tiered-cold-evidence-large-pages as_str",
            "tiered-cold-evidence-large-pages",
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages.as_str()
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("unified").expect("parse unified")
                == ArenaTemperaturePolicy::Unified,
            "parse unified",
            ArenaTemperaturePolicy::Unified,
            ArenaTemperaturePolicy::from_str("unified").expect("parse unified")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("tiered-cold-evidence")
                .expect("parse tiered-cold-evidence")
                == ArenaTemperaturePolicy::TieredColdEvidence,
            "parse tiered-cold-evidence",
            ArenaTemperaturePolicy::TieredColdEvidence,
            ArenaTemperaturePolicy::from_str("tiered-cold-evidence")
                .expect("parse tiered-cold-evidence")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("tiered_cold_evidence_large_pages")
                .expect("parse tiered_cold_evidence_large_pages")
                == ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            "parse tiered_cold_evidence_large_pages",
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            ArenaTemperaturePolicy::from_str("tiered_cold_evidence_large_pages")
                .expect("parse tiered_cold_evidence_large_pages")
        );
        crate::assert_with_log!(
            ArenaTemperaturePolicy::from_str("nope").is_err(),
            "invalid parse rejected",
            true,
            ArenaTemperaturePolicy::from_str("nope").is_err()
        );
        crate::test_complete!("arena_temperature_policy_text_roundtrip_is_stable");
    }

    #[test]
    fn trace_storage_profile_text_roundtrip_is_stable() {
        init_test("trace_storage_profile_text_roundtrip_is_stable");
        crate::assert_with_log!(
            TraceStorageProfile::Default.as_str() == "default",
            "default as_str",
            "default",
            TraceStorageProfile::Default.as_str()
        );
        crate::assert_with_log!(
            TraceStorageProfile::LargeMemory256G.as_str() == "large-memory-256g",
            "large-memory as_str",
            "large-memory-256g",
            TraceStorageProfile::LargeMemory256G.as_str()
        );
        crate::assert_with_log!(
            TraceStorageProfile::Default.to_string() == "default",
            "default display",
            "default",
            TraceStorageProfile::Default.to_string()
        );
        crate::assert_with_log!(
            TraceStorageProfile::LargeMemory256G.to_string() == "large-memory-256g",
            "large-memory display",
            "large-memory-256g",
            TraceStorageProfile::LargeMemory256G.to_string()
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("default").expect("parse default")
                == TraceStorageProfile::Default,
            "default parse",
            TraceStorageProfile::Default,
            TraceStorageProfile::from_str("default").expect("parse default")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("large-memory-256g").expect("parse large-memory kebab")
                == TraceStorageProfile::LargeMemory256G,
            "large-memory kebab parse",
            TraceStorageProfile::LargeMemory256G,
            TraceStorageProfile::from_str("large-memory-256g").expect("parse large-memory kebab")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("large_memory_256g").expect("parse large-memory alias")
                == TraceStorageProfile::LargeMemory256G,
            "large-memory underscore parse",
            TraceStorageProfile::LargeMemory256G,
            TraceStorageProfile::from_str("large_memory_256g").expect("parse large-memory alias")
        );
        crate::assert_with_log!(
            TraceStorageProfile::from_str("invalid-profile").is_err(),
            "invalid parse rejected",
            true,
            TraceStorageProfile::from_str("invalid-profile").is_err()
        );
        crate::test_complete!("trace_storage_profile_text_roundtrip_is_stable");
    }

    fn zero_minimums_config() -> RuntimeConfig {
        RuntimeConfig {
            worker_threads: 0,
            spawn_admission: SpawnAdmissionMode::default(),
            worker_cohort_map: None,
            scheduler_placement_mode: SchedulerPlacementMode::default(),
            thread_stack_size: 0,
            thread_name_prefix: String::new(),
            global_queue_limit: 0,
            steal_batch_size: 0,
            adaptive_ready_batch: AdaptiveReadyBatchConfig {
                enabled: true,
                min_batch_size: 0,
                max_batch_size: 0,
                scale_up_ready_depth: 0,
                scale_up_in_flight: 0,
                scale_up_claim_failures: 0,
                cancel_debt_floor: 0,
                cooldown_steps: 0,
            },
            blocking: BlockingPoolConfig {
                min_threads: 4,
                max_threads: 1,
                affinity_profile: BlockingPoolAffinityProfile::Disabled,
            },
            enable_parking: true,
            poll_budget: 0,
            capacity_hints: Some(RuntimeCapacityHints::new(0, 0, 0)),
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
            trace_storage_profile: TraceStorageProfile::Default,
            browser_ready_handoff_limit: 0,
            browser_worker_offload: BrowserWorkerOffloadConfig {
                enabled: true,
                min_task_cost: 0,
                max_in_flight: 0,
                transfer_mode: WorkerTransferMode::CloneStructured,
                cancellation_mode: WorkerCancellationMode::BestEffortAbort,
                require_owned_payloads: false,
            },
            cancel_lane_max_streak: 0,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(1, 256),
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 0,
            enable_read_biased_region_snapshot: false,
            enable_adaptive_cancel_streak: false,
            adaptive_cancel_streak_epoch_steps: 0,
            runtime_state_shape: RuntimeStateShape::Unified,
            security: SecurityConfig::default(),
        }
    }

    fn assert_normalized_minimums(config: &RuntimeConfig) {
        crate::assert_with_log!(
            config.worker_threads == 1,
            "worker_threads",
            1,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 2 * 1024 * 1024,
            "thread_stack_size",
            2 * 1024 * 1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.steal_batch_size == 1,
            "steal_batch_size",
            1,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 1,
            "poll_budget",
            1,
            config.poll_budget
        );
        let capacity_hints = config
            .capacity_hints
            .expect("explicit capacity hints should remain configured");
        crate::assert_with_log!(
            capacity_hints.task_capacity == RuntimeCapacityHints::DEFAULT_TASK_CAPACITY,
            "capacity_hints.task_capacity",
            RuntimeCapacityHints::DEFAULT_TASK_CAPACITY,
            capacity_hints.task_capacity
        );
        crate::assert_with_log!(
            capacity_hints.region_capacity == RuntimeCapacityHints::DEFAULT_REGION_CAPACITY,
            "capacity_hints.region_capacity",
            RuntimeCapacityHints::DEFAULT_REGION_CAPACITY,
            capacity_hints.region_capacity
        );
        crate::assert_with_log!(
            capacity_hints.obligation_capacity == RuntimeCapacityHints::DEFAULT_OBLIGATION_CAPACITY,
            "capacity_hints.obligation_capacity",
            RuntimeCapacityHints::DEFAULT_OBLIGATION_CAPACITY,
            capacity_hints.obligation_capacity
        );
        crate::assert_with_log!(
            config.arena_temperature_policy == ArenaTemperaturePolicy::Unified,
            "arena_temperature_policy",
            ArenaTemperaturePolicy::Unified,
            config.arena_temperature_policy
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 0,
            "browser_ready_handoff_limit",
            0,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 1,
            "browser_worker_offload.min_task_cost",
            1,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 1,
            "browser_worker_offload.max_in_flight",
            1,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 1,
            "cancel_lane_max_streak",
            1,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 1,
            "governor_interval",
            1,
            config.governor_interval
        );
        crate::assert_with_log!(
            !config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            false,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 1,
            "adaptive_cancel_streak_epoch_steps",
            1,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "asupersync-worker",
            "thread_name_prefix",
            "asupersync-worker",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.blocking.max_threads == config.blocking.min_threads,
            "blocking normalize",
            config.blocking.min_threads,
            config.blocking.max_threads
        );
    }

    #[test]
    fn test_normalize_enforces_minimums() {
        init_test("test_normalize_enforces_minimums");
        let mut config = zero_minimums_config();

        config.normalize();
        assert_normalized_minimums(&config);
        crate::test_complete!("test_normalize_enforces_minimums");
    }

    #[test]
    fn test_blocking_pool_normalize() {
        init_test("test_blocking_pool_normalize");
        let mut blocking = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 1,
            affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 0,
                spill_check_interval: 0,
            },
        };
        blocking.normalize();
        crate::assert_with_log!(
            blocking.max_threads == blocking.min_threads,
            "blocking max>=min",
            blocking.min_threads,
            blocking.max_threads
        );
        crate::assert_with_log!(
            blocking.affinity_profile
                == BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 1,
                    spill_check_interval: 1,
                },
            "blocking affinity profile normalized",
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 1,
                spill_check_interval: 1,
            },
            blocking.affinity_profile
        );
        crate::test_complete!("test_blocking_pool_normalize");
    }

    #[test]
    fn worker_cohort_mapping_derives_cohort_count_from_labels() {
        init_test("worker_cohort_mapping_derives_cohort_count_from_labels");
        let mapping = WorkerCohortMapping::new(vec![0, 0, 2, 2]);
        crate::assert_with_log!(
            mapping.cohort_count() == 3,
            "cohort_count",
            3,
            mapping.cohort_count()
        );
        crate::test_complete!("worker_cohort_mapping_derives_cohort_count_from_labels");
    }

    #[test]
    fn worker_cohort_mapping_validation_checks_worker_count() {
        init_test("worker_cohort_mapping_validation_checks_worker_count");
        let mapping = WorkerCohortMapping::new(vec![0, 1, 1]);
        let err = mapping
            .validate_for_workers(4)
            .expect_err("length mismatch should be rejected");
        crate::assert_with_log!(
            err == "worker cohort map length must match worker_threads",
            "worker cohort map length mismatch",
            "worker cohort map length must match worker_threads",
            err
        );
        crate::test_complete!("worker_cohort_mapping_validation_checks_worker_count");
    }

    #[test]
    fn test_leak_escalation_new_clamps_zero_threshold() {
        init_test("test_leak_escalation_new_clamps_zero_threshold");
        let escalation = LeakEscalation::new(0, ObligationLeakResponse::Panic);
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Panic,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Panic,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_new_clamps_zero_threshold");
    }

    #[test]
    fn test_normalize_clamps_zero_leak_escalation_threshold() {
        init_test("test_normalize_clamps_zero_leak_escalation_threshold");
        let mut config = RuntimeConfig {
            leak_escalation: Some(LeakEscalation {
                threshold: 0,
                escalate_to: ObligationLeakResponse::Recover,
            }),
            ..RuntimeConfig::default()
        };

        config.normalize();

        let escalation = config
            .leak_escalation
            .expect("leak escalation should remain configured");
        crate::assert_with_log!(
            escalation.threshold == 1,
            "leak_escalation.threshold",
            1,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "leak_escalation.escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_normalize_clamps_zero_leak_escalation_threshold");
    }

    #[test]
    fn test_default_worker_threads_nonzero() {
        init_test("test_default_worker_threads_nonzero");
        let threads = RuntimeConfig::default_worker_threads();
        crate::assert_with_log!(threads >= 1, "default_worker_threads", true, threads >= 1);
        crate::test_complete!("test_default_worker_threads_nonzero");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_normalize_preserves_custom_values() {
        init_test("test_normalize_preserves_custom_values");
        let mut config = RuntimeConfig {
            worker_threads: 4,
            spawn_admission: SpawnAdmissionMode::default(),
            worker_cohort_map: None,
            scheduler_placement_mode: SchedulerPlacementMode::LatencyFirst,
            thread_stack_size: 1024,
            thread_name_prefix: "custom".to_string(),
            global_queue_limit: 64,
            steal_batch_size: 8,
            adaptive_ready_batch: AdaptiveReadyBatchConfig {
                enabled: true,
                min_batch_size: 2,
                max_batch_size: 32,
                scale_up_ready_depth: 128,
                scale_up_in_flight: 4,
                scale_up_claim_failures: 3,
                cancel_debt_floor: 6,
                cooldown_steps: 2,
            },
            blocking: BlockingPoolConfig {
                min_threads: 2,
                max_threads: 4,
                affinity_profile: BlockingPoolAffinityProfile::Disabled,
            },
            enable_parking: false,
            poll_budget: 32,
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            browser_ready_handoff_limit: 64,
            browser_worker_offload: BrowserWorkerOffloadConfig {
                enabled: true,
                min_task_cost: 4096,
                max_in_flight: 8,
                transfer_mode: WorkerTransferMode::TransferableOnly,
                cancellation_mode: WorkerCancellationMode::RequireAck,
                require_owned_payloads: true,
            },
            cancel_lane_max_streak: 16,
            root_region_limits: None,
            on_thread_start: None,
            on_thread_stop: None,
            deadline_monitor: None,
            deadline_warning_handler: None,
            metrics_provider: Arc::new(NoOpMetrics),
            observability: None,
            cancel_attribution: CancelAttributionConfig::new(8, 1024),
            obligation_leak_response: ObligationLeakResponse::Silent,
            leak_escalation: None,
            logical_clock_mode: None,
            enable_governor: false,
            governor_interval: 7,
            enable_read_biased_region_snapshot: true,
            enable_adaptive_cancel_streak: true,
            adaptive_cancel_streak_epoch_steps: 64,
            runtime_state_shape: RuntimeStateShape::Unified,
            security: SecurityConfig::default(),
        };

        config.normalize();
        crate::assert_with_log!(
            config.worker_threads == 4,
            "worker_threads",
            4,
            config.worker_threads
        );
        crate::assert_with_log!(
            config.thread_stack_size == 1024,
            "thread_stack_size",
            1024,
            config.thread_stack_size
        );
        crate::assert_with_log!(
            config.thread_name_prefix == "custom",
            "thread_name_prefix",
            "custom",
            config.thread_name_prefix
        );
        crate::assert_with_log!(
            config.steal_batch_size == 8,
            "steal_batch_size",
            8,
            config.steal_batch_size
        );
        crate::assert_with_log!(
            config.poll_budget == 32,
            "poll_budget",
            32,
            config.poll_budget
        );
        crate::assert_with_log!(
            config.trace_storage_profile == TraceStorageProfile::LargeMemory256G,
            "trace_storage_profile",
            TraceStorageProfile::LargeMemory256G,
            config.trace_storage_profile
        );
        crate::assert_with_log!(
            config.scheduler_placement_mode == SchedulerPlacementMode::LatencyFirst,
            "scheduler_placement_mode",
            SchedulerPlacementMode::LatencyFirst,
            config.scheduler_placement_mode
        );
        let capacity_hints = config
            .capacity_hints
            .expect("custom capacity hints should remain configured");
        crate::assert_with_log!(
            capacity_hints == RuntimeCapacityHints::new(4096, 1024, 2048),
            "capacity_hints",
            RuntimeCapacityHints::new(4096, 1024, 2048),
            capacity_hints
        );
        crate::assert_with_log!(
            config.browser_ready_handoff_limit == 64,
            "browser_ready_handoff_limit",
            64,
            config.browser_ready_handoff_limit
        );
        crate::assert_with_log!(
            config.browser_worker_offload.enabled,
            "browser_worker_offload.enabled",
            true,
            config.browser_worker_offload.enabled
        );
        crate::assert_with_log!(
            config.browser_worker_offload.min_task_cost == 4096,
            "browser_worker_offload.min_task_cost",
            4096,
            config.browser_worker_offload.min_task_cost
        );
        crate::assert_with_log!(
            config.browser_worker_offload.max_in_flight == 8,
            "browser_worker_offload.max_in_flight",
            8,
            config.browser_worker_offload.max_in_flight
        );
        crate::assert_with_log!(
            config.cancel_lane_max_streak == 16,
            "cancel_lane_max_streak",
            16,
            config.cancel_lane_max_streak
        );
        crate::assert_with_log!(
            config.governor_interval == 7,
            "governor_interval",
            7,
            config.governor_interval
        );
        crate::assert_with_log!(
            config.enable_adaptive_cancel_streak,
            "enable_adaptive_cancel_streak",
            true,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 64,
            "adaptive_cancel_streak_epoch_steps",
            64,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::assert_with_log!(
            config.blocking.max_threads == 4,
            "blocking max",
            4,
            config.blocking.max_threads
        );
        crate::assert_with_log!(
            config.obligation_leak_response == ObligationLeakResponse::Silent,
            "obligation_leak_response",
            ObligationLeakResponse::Silent,
            config.obligation_leak_response
        );
        crate::test_complete!("test_normalize_preserves_custom_values");
    }

    #[test]
    fn test_browser_worker_offload_defaults() {
        init_test("test_browser_worker_offload_defaults");
        let cfg = BrowserWorkerOffloadConfig::default();
        crate::assert_with_log!(
            !cfg.enabled,
            "offload disabled by default",
            false,
            cfg.enabled
        );
        crate::assert_with_log!(
            cfg.min_task_cost == 1024,
            "default min task cost",
            1024,
            cfg.min_task_cost
        );
        crate::assert_with_log!(
            cfg.max_in_flight == 16,
            "default max in flight",
            16,
            cfg.max_in_flight
        );
        crate::assert_with_log!(
            cfg.transfer_mode == WorkerTransferMode::TransferableOnly,
            "default transfer mode",
            WorkerTransferMode::TransferableOnly,
            cfg.transfer_mode
        );
        crate::assert_with_log!(
            cfg.cancellation_mode == WorkerCancellationMode::RequireAck,
            "default cancellation mode",
            WorkerCancellationMode::RequireAck,
            cfg.cancellation_mode
        );
        crate::assert_with_log!(
            cfg.require_owned_payloads,
            "default require_owned_payloads",
            true,
            cfg.require_owned_payloads
        );
        crate::test_complete!("test_browser_worker_offload_defaults");
    }

    #[test]
    fn test_browser_worker_offload_normalize_clamps_zero_values() {
        init_test("test_browser_worker_offload_normalize_clamps_zero_values");
        let mut cfg = BrowserWorkerOffloadConfig {
            enabled: true,
            min_task_cost: 0,
            max_in_flight: 0,
            transfer_mode: WorkerTransferMode::CloneStructured,
            cancellation_mode: WorkerCancellationMode::BestEffortAbort,
            require_owned_payloads: false,
        };
        cfg.normalize();
        crate::assert_with_log!(
            cfg.min_task_cost == 1,
            "min_task_cost",
            1,
            cfg.min_task_cost
        );
        crate::assert_with_log!(
            cfg.max_in_flight == 1,
            "max_in_flight",
            1,
            cfg.max_in_flight
        );
        crate::test_complete!("test_browser_worker_offload_normalize_clamps_zero_values");
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn obligation_leak_response_clone_copy() {
        let a = ObligationLeakResponse::Recover;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn leak_escalation_debug_eq() {
        let a = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        let b = LeakEscalation::new(5, ObligationLeakResponse::Panic);
        assert_eq!(a, b);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("LeakEscalation"), "{dbg}");
    }

    #[test]
    fn leak_escalation_clone_copy() {
        let a = LeakEscalation::new(10, ObligationLeakResponse::Log);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn blocking_pool_config_default() {
        let bp = BlockingPoolConfig::default();
        assert_eq!(bp.min_threads, 0);
        assert_eq!(bp.max_threads, 0);
        assert_eq!(bp.affinity_profile, BlockingPoolAffinityProfile::Disabled);
    }

    #[test]
    fn blocking_pool_config_clone() {
        let bp = BlockingPoolConfig {
            min_threads: 2,
            max_threads: 8,
            affinity_profile: BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 16,
                spill_check_interval: 4,
            },
        };
        let cloned = bp.clone();
        assert_eq!(cloned.min_threads, 2);
        assert_eq!(cloned.max_threads, 8);
        assert_eq!(cloned.affinity_profile, bp.affinity_profile);
    }

    #[test]
    fn runtime_config_clone() {
        let config = RuntimeConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.worker_threads, config.worker_threads);
        assert_eq!(cloned.poll_budget, config.poll_budget);
        assert_eq!(
            cloned.obligation_leak_response,
            config.obligation_leak_response
        );
    }

    /// Invariant: ObligationLeakResponse variants are distinct and Debug-printable.
    #[test]
    fn test_obligation_leak_response_variants() {
        init_test("test_obligation_leak_response_variants");
        let variants = [
            ObligationLeakResponse::Panic,
            ObligationLeakResponse::Log,
            ObligationLeakResponse::Silent,
            ObligationLeakResponse::Recover,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    crate::assert_with_log!(*a == *b, "same variant eq", true, *a == *b);
                } else {
                    crate::assert_with_log!(*a != *b, "diff variant ne", true, *a != *b);
                }
            }
            let dbg = format!("{a:?}");
            crate::assert_with_log!(!dbg.is_empty(), "Debug non-empty", true, !dbg.is_empty());
        }
        crate::test_complete!("test_obligation_leak_response_variants");
    }

    /// Invariant: LeakEscalation preserves non-zero threshold.
    #[test]
    fn test_leak_escalation_preserves_nonzero() {
        init_test("test_leak_escalation_preserves_nonzero");
        let escalation = LeakEscalation::new(10, ObligationLeakResponse::Recover);
        crate::assert_with_log!(
            escalation.threshold == 10,
            "threshold preserved",
            10,
            escalation.threshold
        );
        crate::assert_with_log!(
            escalation.escalate_to == ObligationLeakResponse::Recover,
            "escalate_to",
            ObligationLeakResponse::Recover,
            escalation.escalate_to
        );
        crate::test_complete!("test_leak_escalation_preserves_nonzero");
    }

    /// Invariant: RuntimeConfig default governor settings are off with interval 32.
    #[test]
    fn test_default_governor_settings() {
        init_test("test_default_governor_settings");
        let config = RuntimeConfig::default();
        crate::assert_with_log!(
            !config.enable_governor,
            "governor disabled by default",
            false,
            config.enable_governor
        );
        crate::assert_with_log!(
            config.governor_interval == 32,
            "default governor interval",
            32,
            config.governor_interval
        );
        crate::assert_with_log!(
            !config.enable_read_biased_region_snapshot,
            "read-biased region snapshot disabled by default",
            false,
            config.enable_read_biased_region_snapshot
        );
        crate::assert_with_log!(
            !config.enable_adaptive_cancel_streak,
            "adaptive cancel streak disabled by default",
            false,
            config.enable_adaptive_cancel_streak
        );
        crate::assert_with_log!(
            config.adaptive_cancel_streak_epoch_steps == 128,
            "adaptive cancel streak default epoch",
            128,
            config.adaptive_cancel_streak_epoch_steps
        );
        crate::test_complete!("test_default_governor_settings");
    }

    /// br-asupersync-ry2trw: `RuntimeConfig::default()` must produce a
    /// host-independent worker_threads value. Two defaults built on
    /// the same host must agree (sanity), and the value must equal
    /// `DEFAULT_WORKER_THREADS` (the deterministic constant) — NOT
    /// the host's `available_parallelism()`.
    #[test]
    fn ry2trw_default_worker_threads_is_host_independent_constant() {
        let a = RuntimeConfig::default();
        let b = RuntimeConfig::default();
        assert_eq!(a.worker_threads, b.worker_threads);
        assert_eq!(a.worker_threads, RuntimeConfig::DEFAULT_WORKER_THREADS);
    }

    /// br-asupersync-ry2trw: the explicit opt-in for host-scaled
    /// parallelism must remain available for production callers that
    /// genuinely want it. Asserts the function returns at least 1
    /// (clamp invariant).
    #[test]
    fn ry2trw_ambient_default_worker_threads_returns_positive() {
        let n = ambient_default_worker_threads();
        assert!(n >= 1, "ambient_default_worker_threads must clamp to >= 1");
    }

    #[test]
    fn runtime_capacity_hints_from_expected_tasks_adds_headroom() {
        init_test("runtime_capacity_hints_from_expected_tasks_adds_headroom");

        let small = RuntimeCapacityHints::from_expected_concurrent_tasks(64);
        assert_eq!(
            small,
            RuntimeCapacityHints::default(),
            "small explicit hints should clamp to the historical minimums"
        );

        let large = RuntimeCapacityHints::from_expected_concurrent_tasks(4096);
        assert_eq!(
            large,
            RuntimeCapacityHints::new(6144, 1024, 2048),
            "explicit task hints should add task headroom and proportionally scale sibling tables"
        );
    }

    #[test]
    fn runtime_capacity_hints_auto_scale_from_worker_threads() {
        init_test("runtime_capacity_hints_auto_scale_from_worker_threads");

        assert_eq!(
            RuntimeCapacityHints::for_worker_threads(RuntimeConfig::DEFAULT_WORKER_THREADS),
            RuntimeCapacityHints::default(),
            "4-worker baseline should preserve the historical default capacities"
        );
        assert_eq!(
            RuntimeCapacityHints::for_worker_threads(64),
            RuntimeCapacityHints::new(8192, 2048, 4096),
            "high-core runtimes should scale their initial table capacities linearly"
        );
    }

    #[test]
    fn runtime_capacity_hints_huge_expected_tasks_saturate_without_wrapping() {
        init_test("runtime_capacity_hints_huge_expected_tasks_saturate_without_wrapping");

        let huge = RuntimeCapacityHints::from_expected_concurrent_tasks(usize::MAX);

        assert_eq!(
            huge,
            RuntimeCapacityHints::new(usize::MAX / 2, usize::MAX / 4, usize::MAX / 2),
            "saturating arithmetic should preserve a conservative monotonic envelope for huge task hints"
        );
        assert!(
            huge.task_capacity >= huge.obligation_capacity
                && huge.obligation_capacity >= huge.region_capacity,
            "huge hints should keep sibling table sizing monotonic after saturation"
        );
    }

    #[test]
    fn resolved_capacity_hints_without_explicit_override_preserve_baseline_defaults() {
        init_test("resolved_capacity_hints_without_explicit_override_preserve_baseline_defaults");

        let mut config = RuntimeConfig {
            worker_threads: RuntimeConfig::DEFAULT_WORKER_THREADS,
            capacity_hints: None,
            ..RuntimeConfig::default()
        };
        config.normalize();

        assert_eq!(
            config.resolved_capacity_hints(),
            RuntimeCapacityHints::default(),
            "missing explicit capacity hints should stay equivalent to the historical default baseline"
        );
    }

    #[test]
    fn arena_temperature_report_keeps_hot_metadata_out_of_cold_tier() {
        init_test("arena_temperature_report_keeps_hot_metadata_out_of_cold_tier");

        let capacity_hints = RuntimeCapacityHints::new(4096, 1024, 2048);
        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(capacity_hints),
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report_with_locality(false, Some(&locality), false);

        assert_eq!(
            report.requested_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(
            report.effective_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(report.fallback_reason, None);
        assert_eq!(
            report.cold_allocation_source,
            ArenaColdAllocationSource::ColdTier
        );
        assert!(!report.large_page_cold_slabs_active);
        assert!(report.locality_profile_present);
        assert!(!report.locality_profile_stale);
        assert!(!report.locality_safe_fallback);
        assert!(!report.locality_no_win_trigger);
        assert_eq!(
            report.locality_selected_remote_touch_ratio_bps,
            locality.selected.remote_touch_ratio_bps()
        );
        assert!(report.hot_task_table_bytes > 0);
        assert!(report.hot_region_table_bytes > 0);
        assert!(report.hot_obligation_table_bytes > 0);
        assert_eq!(
            report.retained_evidence_bytes,
            config.trace_storage_budget().estimated_cold_bytes()
        );
        assert_eq!(report.cold_evidence_bytes, report.retained_evidence_bytes);
        assert_eq!(
            report.estimated_total_bytes(),
            report
                .estimated_hot_bytes()
                .saturating_add(report.retained_evidence_bytes)
        );
    }

    #[test]
    fn arena_temperature_report_falls_back_when_large_pages_are_unavailable() {
        init_test("arena_temperature_report_falls_back_when_large_pages_are_unavailable");

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let config = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        };
        let report = config.arena_temperature_report_with_locality(false, Some(&locality), false);

        assert_eq!(
            report.requested_policy,
            ArenaTemperaturePolicy::TieredColdEvidenceLargePages
        );
        assert_eq!(
            report.effective_policy,
            ArenaTemperaturePolicy::TieredColdEvidence
        );
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LargePagesUnsupported)
        );
        assert_eq!(
            report.cold_allocation_source,
            ArenaColdAllocationSource::ColdTier
        );
        assert!(!report.large_page_cold_slabs_active);

        let rendered = report.render_report_fields();
        assert!(
            rendered.iter().any(|(key, value)| *key == "fallback_reason"
                && value == ArenaTemperatureFallbackReason::LargePagesUnsupported.as_str()),
            "rendered report should expose the conservative fallback reason"
        );
    }

    #[test]
    fn arena_temperature_report_restores_unified_mode_when_disabled_again() {
        init_test("arena_temperature_report_restores_unified_mode_when_disabled_again");

        let capacity_hints = RuntimeCapacityHints::new(4096, 1024, 2048);
        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let tiered = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);
        let unified = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            capacity_hints: Some(capacity_hints),
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);

        assert_eq!(unified.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(unified.cold_evidence_bytes, 0);
        assert_eq!(
            unified.retained_evidence_bytes,
            tiered.retained_evidence_bytes
        );
        assert_eq!(unified.hot_task_table_bytes, tiered.hot_task_table_bytes);
        assert_eq!(
            unified.hot_region_table_bytes,
            tiered.hot_region_table_bytes
        );
        assert_eq!(
            unified.hot_obligation_table_bytes,
            tiered.hot_obligation_table_bytes
        );
    }

    #[test]
    fn arena_temperature_report_requires_ready_locality_profile() {
        init_test("arena_temperature_report_requires_ready_locality_profile");

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, None, false);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LocalityProfileMissing)
        );
        assert_eq!(report.cold_evidence_bytes, 0);
        assert!(!report.locality_profile_present);
    }

    #[test]
    fn arena_temperature_report_rejects_stale_locality_profile() {
        init_test("arena_temperature_report_rejects_stale_locality_profile");

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
                region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
                obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
                task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            },
        );

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), true);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::StaleLocalityProfile)
        );
        assert!(report.locality_profile_stale);
    }

    #[test]
    fn arena_temperature_report_falls_back_when_locality_no_win_triggers() {
        init_test("arena_temperature_report_falls_back_when_locality_no_win_triggers");

        let locality = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(WorkerCohortMapping::new(vec![
                0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3,
                3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6,
                7, 7, 7, 7, 7, 7, 7, 7,
            ])),
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        }
        .arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 9000,
                accounting_epoch: 13,
            },
            Some(95),
            &ArenaLocalityAccessModel {
                task_arena_touches_by_cohort: vec![1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
                region_arena_touches_by_cohort: vec![256, 256, 256, 256, 256, 256, 256, 256],
                obligation_arena_touches_by_cohort: vec![512, 512, 512, 512, 512, 512, 512, 512],
                task_record_pool_touches_by_cohort: vec![
                    1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
                ],
            },
        );

        let report = RuntimeConfig {
            arena_temperature_policy: ArenaTemperaturePolicy::TieredColdEvidence,
            trace_storage_profile: TraceStorageProfile::LargeMemory256G,
            ..RuntimeConfig::default()
        }
        .arena_temperature_report_with_locality(false, Some(&locality), false);

        assert_eq!(report.effective_policy, ArenaTemperaturePolicy::Unified);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaTemperatureFallbackReason::LocalityProfileFallback)
        );
        assert!(report.locality_safe_fallback);
        assert!(report.locality_no_win_trigger);
    }

    #[test]
    fn arena_locality_policy_normalize_clamps_bounds() {
        init_test("arena_locality_policy_normalize_clamps_bounds");

        let mut policy = ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 0,
            remote_touch_budget_bps: 20_000,
            accounting_epoch: 0,
        };
        policy.normalize();

        assert_eq!(
            policy,
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 1,
                remote_touch_budget_bps: 10_000,
                accounting_epoch: 1,
            }
        );
    }

    #[test]
    fn arena_remote_touch_counters_reset_and_saturate() {
        init_test("arena_remote_touch_counters_reset_and_saturate");

        let mut counters = ArenaRemoteTouchCounters::new(7);
        counters.record_sample(u64::MAX, 5);
        counters.record_sample(3, u64::MAX);

        let saturated = counters.snapshot();
        assert_eq!(saturated.accounting_epoch, 7);
        assert_eq!(saturated.reset_count, 0);
        assert_eq!(saturated.local_touch_count, u64::MAX);
        assert_eq!(saturated.remote_touch_count, u64::MAX);

        counters.reset_for_next_epoch(8);
        let reset = counters.snapshot();
        assert_eq!(reset.accounting_epoch, 8);
        assert_eq!(reset.reset_count, 1);
        assert_eq!(reset.local_touch_count, 0);
        assert_eq!(reset.remote_touch_count, 0);
    }

    #[test]
    fn arena_locality_report_prefers_skewed_cohorts_and_tracks_pool_budget() {
        init_test("arena_locality_report_prefers_skewed_cohorts_and_tracks_pool_budget");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            },
            Some(91),
            &access_model,
        );

        assert_eq!(
            report.effective_policy,
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 11,
            }
        );
        assert_eq!(report.fallback_reason, None);
        assert_eq!(report.cohort_count, 8);
        assert_eq!(
            report.task_record_pool_capacity,
            TaskTable::recommended_pool_limit_for_capacity(report.task_capacity)
        );
        assert_eq!(report.placements.len(), 4);
        assert_eq!(
            report.placements[0].preferred_cohort, 0,
            "task arena should pin to the busiest cohort"
        );
        assert!(
            report.candidate.remote_touch_count < report.baseline.remote_touch_count,
            "skewed locality evidence should beat the conservative baseline"
        );
        assert!(
            report.selected.remote_touch_ratio_bps() <= 6500,
            "selected placement must respect the remote-touch budget"
        );
        assert!(report.ownership_preserved);
    }

    #[test]
    fn arena_locality_report_falls_back_when_confidence_is_too_low() {
        init_test("arena_locality_report_falls_back_when_confidence_is_too_low");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 90,
                remote_touch_budget_bps: 6500,
                accounting_epoch: 12,
            },
            Some(40),
            &access_model,
        );

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaLocalityFallbackReason::TopologyConfidenceBelowThreshold)
        );
        assert_eq!(
            report.selected.remote_touch_count,
            report.baseline.remote_touch_count
        );
        assert!(report.used_safe_fallback());
    }

    #[test]
    fn arena_locality_report_no_win_trigger_keeps_baseline() {
        init_test("arena_locality_report_no_win_trigger_keeps_baseline");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![1024; 8],
            region_arena_touches_by_cohort: vec![256; 8],
            obligation_arena_touches_by_cohort: vec![512; 8],
            task_record_pool_touches_by_cohort: vec![1024; 8],
        };

        let report = config.arena_locality_report(
            ArenaLocalityPolicy::CohortPinned {
                min_topology_confidence_percent: 80,
                remote_touch_budget_bps: 9000,
                accounting_epoch: 13,
            },
            Some(95),
            &access_model,
        );

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(
            report.fallback_reason,
            Some(ArenaLocalityFallbackReason::NoRemoteTouchWin)
        );
        assert!(report.no_win_trigger);
        assert_eq!(report.selected, report.baseline);
    }

    #[test]
    fn arena_locality_report_disabled_mode_preserves_baseline_projection() {
        init_test("arena_locality_report_disabled_mode_preserves_baseline_projection");

        let config = RuntimeConfig {
            worker_threads: 64,
            worker_cohort_map: Some(large_host_worker_cohort_map()),
            capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
            ..RuntimeConfig::default()
        };
        let access_model = ArenaLocalityAccessModel {
            task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
            region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
            obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
            task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        };

        let report =
            config.arena_locality_report(ArenaLocalityPolicy::Disabled, Some(99), &access_model);

        assert_eq!(report.effective_policy, ArenaLocalityPolicy::Disabled);
        assert_eq!(report.fallback_reason, None);
        assert_eq!(report.selected, report.baseline);
        assert!(!report.no_win_trigger);
    }

    #[test]
    fn resolved_capacity_hints_prefers_explicit_values_over_worker_scaling() {
        init_test("resolved_capacity_hints_prefers_explicit_values_over_worker_scaling");

        let mut config = RuntimeConfig {
            worker_threads: 64,
            capacity_hints: Some(RuntimeCapacityHints::new(900, 200, 600)),
            arena_temperature_policy: ArenaTemperaturePolicy::Unified,
            ..RuntimeConfig::default()
        };
        config.normalize();

        assert_eq!(
            config.resolved_capacity_hints(),
            RuntimeCapacityHints::new(900, 200, 600),
            "explicit capacity hints should win after normalization"
        );
    }
