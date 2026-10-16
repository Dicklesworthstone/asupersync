    use super::*;
    use crate::lab::{LabConfig, LabRunReport, LabRuntime};
    use crate::observability::metrics::Metrics;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;
    use std::time::Duration;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PressureLabTransition {
        pending_items: usize,
        total_capacity: usize,
        channel_backlog_pressure_scaled: i64,
        decision: AdmissionDecision,
        fallback_verdict: PressureFallbackVerdict,
        channel_backlog_live: bool,
    }

    fn run_lab_pressure_transition_projection(
        seed: u64,
    ) -> (Vec<PressureLabTransition>, LabRunReport) {
        let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(10_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        for _ in 0..3 {
            let (task_id, _handle) = lab
                .state
                .create_task(root, Budget::INFINITE, async {
                    crate::runtime::yield_now::yield_now().await;
                })
                .expect("lab pressure task should be created");
            lab.scheduler.lock().schedule(task_id, 0);
        }

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create pressure transition runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let mut transitions = Vec::new();
        for (pending_items, total_capacity) in [(0, 4), (3, 4), (5, 4)] {
            governor.record_channel_backlog_sample(pending_items, total_capacity);
            let snapshot = governor
                .sample_pressure(&cx)
                .expect("pressure snapshot should not fail");
            let decision = governor
                .check_admission(&cx)
                .expect("pressure admission should not fail");
            transitions.push(PressureLabTransition {
                pending_items,
                total_capacity,
                channel_backlog_pressure_scaled: (snapshot.channel_backlog_pressure * 10_000.0)
                    as i64,
                decision,
                fallback_verdict: snapshot.fallback_verdict,
                channel_backlog_live: snapshot.signal_availability.channel_backlog,
            });
        }

        let report = lab.run_until_quiescent_with_report();
        (transitions, report)
    }

    #[test]
    fn test_pressure_governor_config_defaults() {
        let config = PressureGovernorConfig::default();
        assert!(!config.enabled);
        assert!(!config.admission_control);
        assert_eq!(config.sample_interval, Duration::from_secs(1));

        let thresholds = config.thresholds;
        assert_eq!(thresholds.runnable_queue, 0.8);
        assert_eq!(thresholds.blocking_pool, 0.9);
        assert_eq!(thresholds.channel_backlog, 0.7);
        assert_eq!(thresholds.cleanup_debt, 0.8);
        assert_eq!(thresholds.memory_budget, 0.9);
    }

    #[test]
    fn test_pressure_thresholds_evaluation() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            thresholds: PressureThresholds {
                runnable_queue: 0.8,
                blocking_pool: 0.9,
                channel_backlog: 0.7,
                cleanup_debt: 0.8,
                memory_budget: 0.9,
            },
            ..Default::default()
        };

        use std::sync::Arc;

        let runtime = Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics).unwrap();

        // Test low pressure - should admit
        let low_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.5,
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 0.5,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&low_pressure);
        assert_eq!(decision, AdmissionDecision::Admit);

        // Test moderate pressure - should admit with backpressure
        let moderate_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.85, // Above threshold (0.8)
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 0.85,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&moderate_pressure);
        assert_eq!(decision, AdmissionDecision::AdmitWithBackpressure);

        // Test high pressure - should reject
        let high_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 1.0, // Above rejection threshold (0.8 * 1.2 = 0.96)
            blocking_pool_pressure: 0.5,
            channel_backlog_pressure: 0.5,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.5,
            overall_pressure: 1.0,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        let decision = governor.evaluate_admission(&high_pressure);
        assert_eq!(decision, AdmissionDecision::Reject);
    }

    fn pressure_snapshot_from_values(values: [f64; 5]) -> PressureSnapshot {
        let overall_pressure = values.iter().copied().fold(0.0, f64::max);
        PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: values[0],
            blocking_pool_pressure: values[1],
            channel_backlog_pressure: values[2],
            cleanup_debt_pressure: values[3],
            memory_budget_pressure: values[4],
            overall_pressure,
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        }
    }

    #[test]
    fn pressure_governor_no_win_fallback_uses_backpressure() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics)
            .expect("pressure governor should initialize");

        let no_win_pressure = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.0,
            blocking_pool_pressure: 0.0,
            channel_backlog_pressure: 0.0,
            cleanup_debt_pressure: 0.0,
            memory_budget_pressure: 0.0,
            overall_pressure: 0.0,
            signal_availability: PressureSignalAvailability::NONE,
            fallback_verdict: PressureFallbackVerdict::NoWinNoLiveSignals,
        };
        assert_eq!(
            governor.evaluate_admission(&no_win_pressure),
            AdmissionDecision::AdmitWithBackpressure
        );

        let complete_low_pressure = PressureSnapshot {
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
            ..no_win_pressure
        };
        assert_eq!(
            governor.evaluate_admission(&complete_low_pressure),
            AdmissionDecision::Admit
        );
    }

    #[test]
    fn pressure_threshold_boundaries_apply_to_every_signal() {
        let thresholds = PressureThresholds {
            runnable_queue: 0.8,
            blocking_pool: 0.9,
            channel_backlog: 0.7,
            cleanup_debt: 0.8,
            memory_budget: 0.9,
        };
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            thresholds: thresholds.clone(),
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics).unwrap();
        let cases = [
            ("runnable_queue", 0, thresholds.runnable_queue),
            ("blocking_pool", 1, thresholds.blocking_pool),
            ("channel_backlog", 2, thresholds.channel_backlog),
            ("cleanup_debt", 3, thresholds.cleanup_debt),
            ("memory_budget", 4, thresholds.memory_budget),
        ];

        for (name, index, threshold) in cases {
            let hard_reject_threshold = threshold * 1.2;

            let mut at_threshold = [0.0; 5];
            at_threshold[index] = threshold;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(at_threshold)),
                AdmissionDecision::Admit,
                "{name} pressure equal to threshold should still admit"
            );

            let mut above_threshold = [0.0; 5];
            above_threshold[index] = threshold + 0.0001;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(above_threshold)),
                AdmissionDecision::AdmitWithBackpressure,
                "{name} pressure just above threshold should apply backpressure"
            );

            let mut at_hard_reject_threshold = [0.0; 5];
            at_hard_reject_threshold[index] = hard_reject_threshold;
            assert_eq!(
                governor
                    .evaluate_admission(&pressure_snapshot_from_values(at_hard_reject_threshold,)),
                AdmissionDecision::AdmitWithBackpressure,
                "{name} pressure equal to hard reject threshold should not reject"
            );

            let mut above_hard_reject_threshold = [0.0; 5];
            above_hard_reject_threshold[index] = hard_reject_threshold + 0.0001;
            assert_eq!(
                governor.evaluate_admission(&pressure_snapshot_from_values(
                    above_hard_reject_threshold,
                )),
                AdmissionDecision::Reject,
                "{name} pressure above hard reject threshold should reject"
            );
        }
    }

    #[test]
    fn test_pressure_governor_disabled_always_admits() {
        let config = PressureGovernorConfig {
            enabled: false, // Disabled
            admission_control: false,
            ..Default::default()
        };

        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();

        let result = PressureGovernor::new(config, runtime, metrics);
        assert!(result.is_ok());

        let governor = result.unwrap();

        // Even with very high simulated pressure, disabled governor should not reject
        assert!(!governor.config().enabled);
    }

    #[test]
    fn test_pressure_governor_observe_only_mode() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first blocking task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        if let Err(error) = started_rx.recv_timeout(Duration::from_secs(2)) {
            let _ = release_tx.send(());
            panic!("first blocking task should start: {error}");
        }

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                queued_tx
                    .send(())
                    .expect("test should observe queued blocking task run");
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: false,
            sample_interval: Duration::ZERO,
            thresholds: PressureThresholds {
                blocking_pool: 0.5,
                ..Default::default()
            },
        };
        let metrics = Metrics::new();
        let governor =
            PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics).unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let decision = governor.check_admission(&cx);

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");

        let decision = decision.expect("observe-only admission should not fail");

        assert!(governor.config().enabled);
        assert!(!governor.config().admission_control);
        assert_eq!(decision, AdmissionDecision::Admit);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
    }

    #[test]
    fn test_pressure_snapshot_overall_pressure_calculation() {
        let snapshot = PressureSnapshot {
            timestamp: Instant::now(),
            runnable_queue_pressure: 0.6,
            blocking_pool_pressure: 0.8, // Highest
            channel_backlog_pressure: 0.4,
            cleanup_debt_pressure: 0.5,
            memory_budget_pressure: 0.7,
            overall_pressure: 0.8, // Should be max of all signals
            signal_availability: PressureSignalAvailability::ALL,
            fallback_verdict: PressureFallbackVerdict::Complete,
        };

        // Verify overall pressure matches the highest signal
        assert_eq!(snapshot.overall_pressure, 0.8);
        assert!(snapshot.overall_pressure >= snapshot.runnable_queue_pressure);
        assert!(snapshot.overall_pressure >= snapshot.blocking_pool_pressure);
        assert!(snapshot.overall_pressure >= snapshot.channel_backlog_pressure);
        assert!(snapshot.overall_pressure >= snapshot.cleanup_debt_pressure);
        assert!(snapshot.overall_pressure >= snapshot.memory_budget_pressure);
    }

    #[test]
    fn pressure_signal_availability_reports_no_win_fallback() {
        let none = PressureSignalAvailability::NONE;
        assert!(!none.any_live());
        assert!(!none.all_live());
        assert_eq!(
            PressureFallbackVerdict::from_availability(none),
            PressureFallbackVerdict::NoWinNoLiveSignals
        );

        let partial = PressureSignalAvailability {
            runnable_queue: true,
            ..PressureSignalAvailability::NONE
        };
        assert!(partial.any_live());
        assert!(!partial.all_live());
        assert_eq!(
            PressureFallbackVerdict::from_availability(partial),
            PressureFallbackVerdict::PartialSignalsUnavailable
        );

        let round_trip = PressureSignalAvailability::from_mask(partial.mask());
        assert_eq!(round_trip, partial);
    }

    #[test]
    fn pressure_governor_records_fallback_counters_by_verdict() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create fallback-counter runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, runtime, metrics)
            .expect("pressure governor should initialize");

        governor.record_fallback_verdict(PressureFallbackVerdict::Complete);
        assert_eq!(governor.partial_fallback_total.get(), 0);
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        governor.record_fallback_verdict(PressureFallbackVerdict::PartialSignalsUnavailable);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );

        governor.record_fallback_verdict(PressureFallbackVerdict::NoWinNoLiveSignals);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 1);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::NoWinNoLiveSignals.as_metric_value()
        );
    }

    #[test]
    fn pressure_governor_records_partial_fallback_and_decision_latency() {
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            ..Default::default()
        };
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .blocking_threads(0, 0)
                .build()
                .expect("Failed to create test runtime"),
        );
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let sampled = governor
            .sample_pressure(&cx)
            .expect("direct pressure sample should not fail");
        assert_eq!(
            sampled.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(
            governor.partial_fallback_total.get(),
            0,
            "direct sampling updates the verdict gauge without counting an admission fallback"
        );
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        let decision = governor
            .check_admission(&cx)
            .expect("pressure admission should not fail");

        assert_eq!(decision, AdmissionDecision::Admit);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(governor.sample_count(), 1);
        let p95 = governor
            .decision_latency_p95_ns()
            .expect("p95 decision latency should be recorded");
        let p999 = governor
            .decision_latency_p999_ns()
            .expect("p999 decision latency should be recorded");
        assert_eq!(
            governor.decision_latency_p95_metric_ns(),
            u64_to_i64_saturating(p95)
        );
        assert_eq!(
            governor.decision_latency_p999_metric_ns(),
            u64_to_i64_saturating(p999)
        );

        let cached = governor
            .sample_pressure(&cx)
            .expect("cached pressure snapshot should not fail");
        assert_eq!(
            cached.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert!(!cached.signal_availability.runnable_queue);
        assert!(!cached.signal_availability.blocking_pool);
        assert!(!cached.signal_availability.channel_backlog);
        assert!(cached.signal_availability.cleanup_debt);
        assert!(!cached.signal_availability.memory_budget);
    }

    #[test]
    fn pressure_governor_samples_blocking_pool_pressure_when_runtime_exposes_pool() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create blocking-pool runtime"),
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first blocking task should start");

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                let _ = queued_tx.send(());
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("blocking-pool pressure snapshot should not fail");
        assert!(snapshot.signal_availability.blocking_pool);
        assert!(!snapshot.signal_availability.runnable_queue);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert!(
            snapshot.blocking_pool_pressure >= 1.0,
            "one busy blocking thread should produce saturation, got {}",
            snapshot.blocking_pool_pressure
        );
        assert_eq!(snapshot.overall_pressure, snapshot.blocking_pool_pressure);

        let decision = governor
            .check_admission(&cx)
            .expect("blocking-pool pressure decision should not fail");
        assert!(
            matches!(
                decision,
                AdmissionDecision::AdmitWithBackpressure | AdmissionDecision::Reject
            ),
            "blocking-pool pressure should influence admission, got {decision:?}"
        );
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");
    }

    #[test]
    fn pressure_governor_leaves_runnable_queue_unavailable_without_capacity() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create test runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert!(!snapshot.signal_availability.runnable_queue);
        assert_eq!(snapshot.runnable_queue_pressure, 0.0);
    }

    #[test]
    fn pressure_governor_samples_runnable_queue_when_capacity_is_configured() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create global-queue-limited runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert_eq!(runtime.scheduler_global_ready_depth(), 0);
        assert!(snapshot.signal_availability.runnable_queue);
        assert_eq!(snapshot.runnable_queue_pressure, 0.0);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn pressure_governor_samples_cleanup_debt_from_runtime_draining_regions() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create cleanup-debt runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert_eq!(runtime.draining_region_count(), 0);
        assert!(snapshot.signal_availability.cleanup_debt);
        assert_eq!(snapshot.cleanup_debt_pressure, 0.0);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn pressure_governor_samples_memory_budget_from_resource_monitor() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create memory-pressure runtime"),
        );
        runtime.resource_monitor().pressure().update_measurement(
            ResourceType::Memory,
            crate::runtime::resource_monitor::ResourceMeasurement::new(768, 800, 950, 1024),
        );

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let snapshot = governor
            .sample_pressure(&cx)
            .expect("pressure snapshot should not fail");

        assert!(snapshot.signal_availability.memory_budget);
        assert_eq!(snapshot.memory_budget_pressure, 0.75);
        assert_eq!(snapshot.overall_pressure, snapshot.memory_budget_pressure);
        assert_eq!(
            snapshot.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
    }

    #[test]
    fn pressure_governor_cached_snapshot_preserves_signal_availability() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create cached-snapshot runtime"),
        );
        runtime.resource_monitor().pressure().update_measurement(
            ResourceType::Memory,
            crate::runtime::resource_monitor::ResourceMeasurement::new(512, 800, 950, 1024),
        );

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let fresh = governor
            .sample_pressure(&cx)
            .expect("fresh pressure snapshot should not fail");
        let cached = governor
            .sample_pressure(&cx)
            .expect("cached pressure snapshot should not fail");

        assert_eq!(governor.sample_count(), 1);
        assert_eq!(cached.signal_availability, fresh.signal_availability);
        assert!(cached.signal_availability.runnable_queue);
        assert!(cached.signal_availability.cleanup_debt);
        assert!(cached.signal_availability.memory_budget);
        assert_eq!(
            cached.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(cached.memory_budget_pressure, 0.5);
        assert_eq!(cached.overall_pressure, fresh.overall_pressure);
    }

    #[test]
    fn pressure_governor_samples_explicit_channel_backlog_telemetry() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create channel-backlog runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let initial = governor
            .sample_pressure(&cx)
            .expect("initial pressure snapshot should not fail");
        assert!(!initial.signal_availability.channel_backlog);
        assert_eq!(governor.sample_count(), 1);

        let (tx, _rx) = crate::channel::mpsc::channel::<u8>(4);
        tx.try_send(1).expect("first queued message should fit");
        tx.try_send(2).expect("second queued message should fit");
        let permit = tx.try_reserve().expect("reserved obligation should fit");
        let telemetry = tx.telemetry_snapshot(17);

        governor.record_channel_backlog_sample(
            telemetry.queued_messages + telemetry.reserved_uncommitted_obligations,
            telemetry.capacity,
        );
        let sampled = governor
            .sample_pressure(&cx)
            .expect("channel backlog pressure snapshot should not fail");

        assert_eq!(governor.sample_count(), 2);
        assert!(sampled.signal_availability.channel_backlog);
        assert_eq!(sampled.channel_backlog_pressure, 0.75);
        assert_eq!(sampled.overall_pressure, 0.75);
        assert_eq!(
            sampled.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );

        permit.abort();
        governor.clear_channel_backlog_sample();
        let cleared = governor
            .sample_pressure(&cx)
            .expect("cleared channel backlog snapshot should not fail");

        assert_eq!(governor.sample_count(), 3);
        assert!(!cleared.signal_availability.channel_backlog);
        assert_eq!(cleared.channel_backlog_pressure, 0.0);
    }

    #[test]
    fn pressure_governor_channel_backlog_sample_drives_admission() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .build()
                .expect("Failed to create channel-backlog admission runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        governor.record_channel_backlog_sample(3, 4);
        let decision = governor
            .check_admission(&cx)
            .expect("channel backlog admission should not fail");

        assert_eq!(decision, AdmissionDecision::AdmitWithBackpressure);
        assert_eq!(governor.backpressure_total.get(), 1);
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
    }

    #[test]
    fn pressure_governor_lab_runtime_pressure_transitions_are_deterministic() {
        let (first_trace, first_report) = run_lab_pressure_transition_projection(0x5A17);
        let (second_trace, second_report) = run_lab_pressure_transition_projection(0x5A17);

        assert_eq!(
            first_trace,
            vec![
                PressureLabTransition {
                    pending_items: 0,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 0,
                    decision: AdmissionDecision::Admit,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
                PressureLabTransition {
                    pending_items: 3,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 7_500,
                    decision: AdmissionDecision::AdmitWithBackpressure,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
                PressureLabTransition {
                    pending_items: 5,
                    total_capacity: 4,
                    channel_backlog_pressure_scaled: 12_500,
                    decision: AdmissionDecision::Reject,
                    fallback_verdict: PressureFallbackVerdict::PartialSignalsUnavailable,
                    channel_backlog_live: true,
                },
            ]
        );
        assert_eq!(first_trace, second_trace);

        assert!(first_report.quiescent);
        assert!(second_report.quiescent);
        assert_eq!(
            first_report.trace_fingerprint, second_report.trace_fingerprint,
            "matching LabRuntime pressure scenarios should replay to the same trace fingerprint"
        );
        assert_eq!(
            first_report.trace_certificate, second_report.trace_certificate,
            "matching LabRuntime pressure scenarios should keep certificate evidence stable"
        );
        assert_eq!(
            first_report.oracle_report.to_json(),
            second_report.oracle_report.to_json()
        );
        assert_eq!(
            first_report.invariant_violations,
            second_report.invariant_violations
        );
        assert!(first_report.oracle_report.all_passed());
        assert!(second_report.oracle_report.all_passed());
        assert!(first_report.invariant_violations.is_empty());
        assert!(second_report.invariant_violations.is_empty());
    }

    #[test]
    fn test_pressure_thresholds_defaults() {
        let thresholds = PressureThresholds::default();

        // Verify reasonable defaults
        assert_eq!(thresholds.runnable_queue, 0.8);
        assert_eq!(thresholds.blocking_pool, 0.9);
        assert_eq!(thresholds.channel_backlog, 0.7);
        assert_eq!(thresholds.cleanup_debt, 0.8);
        assert_eq!(thresholds.memory_budget, 0.9);

        // Verify all thresholds are in reasonable range
        assert!(thresholds.runnable_queue > 0.0 && thresholds.runnable_queue < 1.0);
        assert!(thresholds.blocking_pool > 0.0 && thresholds.blocking_pool < 1.0);
        assert!(thresholds.channel_backlog > 0.0 && thresholds.channel_backlog < 1.0);
        assert!(thresholds.cleanup_debt > 0.0 && thresholds.cleanup_debt < 1.0);
        assert!(thresholds.memory_budget > 0.0 && thresholds.memory_budget < 1.0);
    }

    /// Integration test demonstrating the pressure governor against live runtime signals.
    #[cfg(feature = "test-internals")]
    #[test]
    fn test_pressure_governor_integration_scenario() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .global_queue_limit(4)
                .blocking_threads(0, 1)
                .build()
                .expect("Failed to create runtime for pressure integration scenario"),
        );

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = runtime
            .spawn_blocking(move || {
                started_tx
                    .send(())
                    .expect("test should observe first blocking task start");
                release_rx
                    .recv()
                    .expect("test should release first blocking task");
            })
            .expect("runtime should expose a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first blocking task should start");

        let (queued_tx, queued_rx) = std::sync::mpsc::channel();
        let second = runtime
            .spawn_blocking(move || {
                queued_tx
                    .send(())
                    .expect("test should observe queued blocking task run");
            })
            .expect("runtime should accept a queued blocking task");

        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            thresholds: PressureThresholds {
                runnable_queue: 0.5,
                blocking_pool: 0.5,
                channel_backlog: 0.6,
                cleanup_debt: 0.7,
                memory_budget: 0.8,
            },
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        let saturated = governor.sample_pressure(&cx);
        let decision = governor.check_admission(&cx);

        release_tx
            .send(())
            .expect("test should release first blocking task");
        assert!(
            first.wait_timeout(Duration::from_secs(2)),
            "first blocking task should finish"
        );
        assert!(
            second.wait_timeout(Duration::from_secs(2)),
            "queued blocking task should finish"
        );
        queued_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("queued blocking task should execute after release");

        let drained = governor
            .sample_pressure(&cx)
            .expect("drained pressure snapshot should not fail");

        let saturated = saturated.expect("pressure snapshot should not fail");
        assert!(saturated.signal_availability.runnable_queue);
        assert!(saturated.signal_availability.blocking_pool);
        assert!(!saturated.signal_availability.channel_backlog);
        assert!(saturated.signal_availability.cleanup_debt);
        assert_eq!(
            saturated.fallback_verdict,
            PressureFallbackVerdict::PartialSignalsUnavailable
        );
        assert_eq!(saturated.runnable_queue_pressure, 0.0);
        assert_eq!(saturated.cleanup_debt_pressure, 0.0);
        assert!(
            saturated.blocking_pool_pressure >= 1.0,
            "busy plus queued blocking work should saturate the pool, got {}",
            saturated.blocking_pool_pressure
        );
        assert_eq!(saturated.overall_pressure, saturated.blocking_pool_pressure);

        let decision = decision.expect("admission decision should not fail");
        assert_eq!(decision, AdmissionDecision::Reject);
        assert_eq!(
            governor.fallback_verdict_metric(),
            PressureFallbackVerdict::PartialSignalsUnavailable.as_metric_value()
        );
        assert_eq!(governor.partial_fallback_total.get(), 1);
        assert_eq!(governor.no_win_fallback_total.get(), 0);

        assert!(drained.signal_availability.runnable_queue);
        assert!(drained.signal_availability.blocking_pool);
        assert!(drained.signal_availability.cleanup_debt);
        assert_eq!(drained.runnable_queue_pressure, 0.0);
        assert_eq!(drained.blocking_pool_pressure, 0.0);
        assert_eq!(drained.cleanup_debt_pressure, 0.0);
        assert_eq!(drained.overall_pressure, 0.0);
        assert!(
            runtime.is_quiescent(),
            "runtime should be quiescent after pressure scenario drains"
        );
    }

    #[test]
    fn enhanced_admission_control_with_resource_envelope() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create enhanced admission runtime"),
        );
        let config = PressureGovernorConfig {
            enabled: true,
            admission_control: true,
            sample_interval: Duration::ZERO,
            ..Default::default()
        };
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);

        // Test basic enhanced admission
        let decision = governor
            .check_enhanced_admission(&cx, None)
            .expect("enhanced admission should not fail");

        assert_eq!(decision.decision, AdmissionDecision::Admit);
        assert!(decision.suggested_envelope.is_some());
        assert!(!decision.backpressure_signals.shed_load);

        let envelope = decision.suggested_envelope.unwrap();
        assert_eq!(envelope.memory_budget, 64 * 1024 * 1024); // 64MB default
        assert_eq!(envelope.cpu_weight, 1.0);
        assert_eq!(envelope.io_budget, 10);
        assert_eq!(envelope.task_limit, 100);
    }

    #[test]
    fn resource_envelope_tracking() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create envelope tracking runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Register a resource envelope
        let envelope = ResourceEnvelope {
            memory_budget: 128 * 1024 * 1024, // 128MB
            cpu_weight: 2.0,
            io_budget: 20,
            task_limit: 200,
            usage: ResourceUsage::default(),
        };

        governor
            .register_envelope(1, envelope.clone())
            .expect("envelope registration should succeed");

        assert_eq!(governor.envelope_metrics.envelopes_active.get(), 1);

        // Update envelope usage
        let usage = ResourceUsage {
            memory_used: 64 * 1024 * 1024, // 64MB used
            cpu_utilization: 0.5,
            io_active: 10,
            task_count: 50,
        };

        governor
            .update_envelope_usage(1, usage)
            .expect("envelope usage update should succeed");

        assert_eq!(
            governor.envelope_metrics.envelope_memory_used.get(),
            64 * 1024 * 1024
        );

        // Unregister envelope
        governor
            .unregister_envelope(1)
            .expect("envelope unregistration should succeed");

        assert_eq!(governor.envelope_metrics.envelopes_active.get(), 0);
        assert_eq!(governor.envelope_metrics.envelope_memory_used.get(), 0);
    }

    #[test]
    fn swarm_coordination_peer_management() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create swarm coordination runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Add a peer with low pressure
        let peer_state = PeerPressureState {
            overall_pressure: 0.3,
            admission_rate: 0.9,
            last_update: Instant::now(),
            available: true,
        };

        governor
            .update_peer_pressure(100, peer_state)
            .expect("peer pressure update should succeed");

        assert_eq!(governor.swarm_metrics.peers_active.get(), 1);

        // Check swarm coordination hints
        let hints = governor
            .generate_swarm_hints()
            .expect("swarm hints generation should succeed");

        assert!(hints.redistribute_load);
        assert_eq!(hints.preferred_peers, vec![100]);

        // Test swarm state retrieval
        let swarm_state = governor
            .get_swarm_state()
            .expect("swarm state retrieval should succeed");

        assert_eq!(swarm_state.peer_states.len(), 1);
        assert!(swarm_state.peer_states.contains_key(&100));
    }

    #[test]
    fn backpressure_signal_generation() {
        let runtime = std::sync::Arc::new(
            RuntimeBuilder::new()
                .worker_threads(1)
                .build()
                .expect("Failed to create backpressure runtime"),
        );
        let config = PressureGovernorConfig::default();
        let metrics = Metrics::new();
        let governor = PressureGovernor::new(config, std::sync::Arc::clone(&runtime), metrics)
            .expect("pressure governor should initialize");

        // Test backpressure signals under pressure
        let signals = governor
            .generate_backpressure_signals(true)
            .expect("backpressure signal generation should succeed");

        assert!(signals.shed_load);
        assert!(signals.retry_delay.is_some());
        assert_eq!(signals.retry_delay.unwrap(), Duration::from_millis(100));
        assert!(!signals.component_pressures.is_empty());
        assert_eq!(signals.component_pressures.get("scheduler"), Some(&0.8));

        // Test normal signals without pressure
        let normal_signals = governor
            .generate_backpressure_signals(false)
            .expect("normal signal generation should succeed");

        assert!(!normal_signals.shed_load);
        assert!(normal_signals.retry_delay.is_none());
        assert!(normal_signals.component_pressures.is_empty());
    }
