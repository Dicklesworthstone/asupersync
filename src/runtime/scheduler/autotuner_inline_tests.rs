    use super::*;

    #[test]
    fn autotuner_reduces_batch_size_for_high_latency() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // 5ms - much higher than 1ms target
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() < 16);
        assert!(recommendation.reasoning.contains("latency"));
    }

    #[test]
    fn autotuner_reduces_batch_size_for_high_cancel_load() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            cancel_dispatch_ratio_bps: 4000, // 40% cancel work
            current_steal_batch_size: 12,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() < 12);
        assert!(recommendation.reasoning.contains("cancel responsiveness"));
    }

    #[test]
    fn autotuner_increases_batch_size_for_low_utilization() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            ready_dispatch_ratio_bps: 2000, // 20% ready work - low utilization
            estimated_p95_latency_us: 200,  // Good latency
            current_steal_batch_size: 4,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() > 4);
        assert!(recommendation.reasoning.contains("throughput"));
    }

    #[test]
    fn autotuner_respects_observation_window() {
        let config = AutotunerConfig {
            observation_window_ms: 5000, // 5 second window
            ..Default::default()
        };
        let mut autotuner = SchedulerAutotuner::new(config);

        autotuner.last_adjustment_time = Some(Instant::now());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // Should trigger recommendation
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);

        // Should not recommend due to recent adjustment
        assert!(autotuner.recommend().is_none());
    }

    #[test]
    fn extract_observation_from_metrics() {
        let mut metrics = PreemptionMetrics::default();
        metrics.cancel_dispatches = 20;
        metrics.ready_dispatches = 80;
        metrics.global_ready_batch_drains = 10;
        metrics.global_ready_batch_tasks = 50;

        let obs = extract_observation(&metrics);

        assert_eq!(obs.cancel_dispatch_ratio_bps, 2000); // 20%
        assert_eq!(obs.ready_dispatch_ratio_bps, 8000); // 80%
        assert_eq!(obs.mean_ready_batch_size, 5.0); // 50/10
    }

    fn stable_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.30),
            ready_queue_pressure: Some(0.35),
            blocking_pool_pressure: Some(0.20),
            channel_backlog_pressure: Some(0.25),
            cancellation_pressure: Some(0.10),
            cleanup_debt_pressure: Some(0.10),
            memory_budget_pressure: Some(0.40),
            p95_dispatch_latency_us: Some(500),
            p99_dispatch_latency_us: Some(900),
        }
    }

    fn burst_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.91),
            ready_queue_pressure: Some(0.88),
            blocking_pool_pressure: Some(0.62),
            channel_backlog_pressure: Some(0.86),
            cancellation_pressure: Some(0.18),
            cleanup_debt_pressure: Some(0.15),
            memory_budget_pressure: Some(0.52),
            p95_dispatch_latency_us: Some(1_800),
            p99_dispatch_latency_us: Some(2_700),
        }
    }

    fn cancellation_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.70),
            ready_queue_pressure: Some(0.66),
            blocking_pool_pressure: Some(0.55),
            channel_backlog_pressure: Some(0.42),
            cancellation_pressure: Some(0.76),
            cleanup_debt_pressure: Some(0.72),
            memory_budget_pressure: Some(0.48),
            p95_dispatch_latency_us: Some(1_400),
            p99_dispatch_latency_us: Some(3_000),
        }
    }

    fn memory_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.68),
            ready_queue_pressure: Some(0.64),
            blocking_pool_pressure: Some(0.50),
            channel_backlog_pressure: Some(0.57),
            cancellation_pressure: Some(0.12),
            cleanup_debt_pressure: Some(0.14),
            memory_budget_pressure: Some(0.91),
            p95_dispatch_latency_us: Some(1_100),
            p99_dispatch_latency_us: Some(1_900),
        }
    }

    fn feedback_current_knobs() -> SchedulerFeedbackCurrentKnobs {
        SchedulerFeedbackCurrentKnobs {
            worker_threads: 8,
            cohort_count: 2,
            steal_batch_size: 16,
            global_queue_limit: 8_192,
            placement_mode: SchedulerPlacementMode::LocalityFirst,
            ..SchedulerFeedbackCurrentKnobs::default()
        }
    }

    fn assert_invariants_preserved(recommendation: &SchedulerFeedbackRecommendation) {
        assert!(recommendation.dry_run);
        assert!(recommendation.protected_invariants.cancellation_drain);
        assert!(recommendation.protected_invariants.loser_drain);
        assert!(recommendation.protected_invariants.obligation_cleanup);
        assert!(recommendation.protected_invariants.region_quiescence);
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::ProtectedInvariantsPinned)
        );
    }

    #[test]
    fn scheduler_feedback_stable_workload_observe_only() {
        let recommendation = recommend_scheduler_feedback(
            stable_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::Stable
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::StableNoChange)
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_burst_workload_recommends_throughput_knobs() {
        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::Burst
        );
        assert_eq!(recommendation.steal_batch_size, Some(32));
        assert_eq!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::ThroughputFirst)
        );
        assert!(recommendation.global_queue_limit.unwrap_or(0) > 8_192);
        assert!(recommendation.ready_batch_profile.unwrap().enabled);
        assert!(matches!(
            recommendation.blocking_pool_affinity,
            Some(BlockingPoolAffinityProfile::CohortBiased { .. })
        ));
        assert!(recommendation.admission_thresholds.is_some());
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_cancellation_heavy_workload_prioritizes_responsiveness() {
        let recommendation = recommend_scheduler_feedback(
            cancellation_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::CancellationHeavy
        );
        assert_eq!(recommendation.steal_batch_size, Some(8));
        assert_eq!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::LatencyFirst)
        );
        let profile = recommendation.ready_batch_profile.unwrap();
        assert_eq!(profile.cancel_debt_floor, 1);
        assert!(profile.scale_up_ready_depth > feedback_current_knobs().worker_threads);
        let thresholds = recommendation.admission_thresholds.unwrap();
        assert!(
            thresholds.cleanup_debt < feedback_current_knobs().admission_thresholds.cleanup_debt
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_memory_pressure_conserves_queue_growth() {
        let recommendation = recommend_scheduler_feedback(
            memory_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::MemoryPressure
        );
        assert_eq!(recommendation.steal_batch_size, Some(8));
        assert!(recommendation.global_queue_limit.unwrap_or(usize::MAX) < 8_192);
        let thresholds = recommendation.admission_thresholds.unwrap();
        assert!(
            thresholds.memory_budget < feedback_current_knobs().admission_thresholds.memory_budget
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_invalid_metrics_stay_observe_only_with_evidence() {
        let mut metrics = stable_feedback_metrics();
        metrics.runnable_queue_pressure = Some(f64::NAN);
        metrics.memory_budget_pressure = Some(-0.1);

        let recommendation = SchedulerAutotuner::recommend_feedback(
            metrics,
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::InvalidMetrics
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .invalid_signals
                .contains(&SchedulerFeedbackSignal::RunnableQueue)
        );
        assert!(
            recommendation
                .evidence
                .invalid_signals
                .contains(&SchedulerFeedbackSignal::MemoryBudget)
        );
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::PressureMetric
                && clamp.reason == SchedulerFeedbackClampReason::InvalidMetric
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_missing_metrics_stay_observe_only() {
        let recommendation = recommend_scheduler_feedback(
            SchedulerFeedbackMetrics {
                runnable_queue_pressure: Some(0.90),
                ..SchedulerFeedbackMetrics::default()
            },
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::InsufficientMetrics
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::MissingMetricsObserveOnly)
        );
        assert!(recommendation.evidence.missing_signals.len() >= 4);
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_clamps_unsafe_recommendations() {
        let policy = SchedulerFeedbackPolicy {
            max_steal_batch_size: 24,
            max_ready_batch_size: 24,
            max_global_queue_limit: 1_024,
            max_admission_threshold: 0.82,
            ..SchedulerFeedbackPolicy::default()
        };

        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            policy,
        );

        assert_eq!(recommendation.steal_batch_size, Some(24));
        assert_eq!(recommendation.global_queue_limit, Some(1_024));
        assert!(
            recommendation
                .ready_batch_profile
                .is_some_and(|profile| profile.max_batch_size == 24)
        );
        assert!(
            recommendation
                .admission_thresholds
                .is_some_and(|thresholds| thresholds.runnable_queue <= 0.82)
        );
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::StealBatchSize
                && clamp.reason == SchedulerFeedbackClampReason::AboveMaximum
        }));
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::GlobalQueueLimit
                && clamp.reason == SchedulerFeedbackClampReason::AboveMaximum
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_records_inverted_admission_threshold_policy() {
        let policy = SchedulerFeedbackPolicy {
            min_admission_threshold: 0.90,
            max_admission_threshold: 0.20,
            ..SchedulerFeedbackPolicy::default()
        };

        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            policy,
        );

        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::AdmissionControlThresholds
                && clamp.reason == SchedulerFeedbackClampReason::BelowMinimum
                && clamp.requested == "0.200"
                && clamp.clamped == "0.900"
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_contradictory_pressure_suppresses_throughput_profile() {
        let mut metrics = burst_feedback_metrics();
        metrics.cancellation_pressure = Some(0.82);
        metrics.cleanup_debt_pressure = Some(0.78);

        let recommendation = recommend_scheduler_feedback(
            metrics,
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::CancellationHeavy
        );
        assert_ne!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::ThroughputFirst)
        );
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::ContradictoryThroughputSuppressed)
        );
        assert!(
            recommendation.evidence.clamps.iter().any(|clamp| {
                clamp.reason == SchedulerFeedbackClampReason::ContradictoryPressure
            })
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_preserves_protected_invariants_across_scenarios() {
        let scenarios = [
            stable_feedback_metrics(),
            burst_feedback_metrics(),
            cancellation_feedback_metrics(),
            memory_feedback_metrics(),
            SchedulerFeedbackMetrics::default(),
        ];

        for metrics in scenarios {
            let recommendation = recommend_scheduler_feedback(
                metrics,
                feedback_current_knobs(),
                SchedulerFeedbackPolicy::default(),
            );
            assert_invariants_preserved(&recommendation);
        }
    }
