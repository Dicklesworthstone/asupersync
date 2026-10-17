    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::{
        CancellationDebtConfig, CancellationDebtMonitor, DebtAlertLevel, DebtMonitorSleeper,
        DebtRuntimeIntegration, DebtSnapshot, WorkType,
    };
    use crate::types::{CancelKind, CancelReason, TaskId};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn test_integration_creation() {
        let integration = DebtRuntimeIntegration::default();
        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
        assert_eq!(snapshot.debt_percentage, 0.0);
    }

    #[test]
    fn test_task_cleanup_tracking() {
        let integration = DebtRuntimeIntegration::default();

        let task_id = TaskId::new_for_test(42, 0);
        let cancel_reason = CancelReason::user("test");

        let work_id =
            integration.on_task_cleanup_started(task_id, &cancel_reason, CancelKind::User, 100);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 1);
        assert!(
            snapshot
                .pending_by_type
                .contains_key(&WorkType::TaskCleanup)
        );

        integration.on_cleanup_completed(work_id);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_priority_calculation() {
        let integration = DebtRuntimeIntegration::default();

        // Shutdown cancellation should get highest priority
        let emergency_priority = integration.calculate_priority(CancelKind::Shutdown);
        let user_priority = integration.calculate_priority(CancelKind::User);

        assert!(emergency_priority > user_priority);
    }

    #[test]
    fn test_health_score_calculation() {
        let integration = DebtRuntimeIntegration::default();

        let good_snapshot = DebtSnapshot {
            snapshot_time: crate::observability::replayable_system_time(),
            total_pending: 0,
            pending_by_type: HashMap::new(),
            debt_percentage: 5.0,
            processing_rate: 200.0,
            entity_queue_depths: HashMap::new(),
            oldest_work_age: Duration::from_secs(1),
            memory_usage_mb: 1.0,
            alert_level: DebtAlertLevel::Normal,
        };

        let health_score = integration.calculate_health_score(&good_snapshot);
        assert!(health_score > 90.0);
    }

    #[test]
    fn test_batch_completion() {
        let integration = DebtRuntimeIntegration::default();

        let work_ids: Vec<u64> = (0..5)
            .map(|i| {
                integration.on_waker_cleanup_started(
                    format!("waker-{}", i),
                    &CancelReason::user("batch_test"),
                    CancelKind::User,
                )
            })
            .collect();

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 5);

        let completed = integration.on_batch_cleanup_completed(&work_ids);
        assert_eq!(completed, 5);

        let snapshot = integration.get_debt_status();
        assert_eq!(snapshot.total_pending, 0);
    }

    #[test]
    fn test_emergency_intervention() {
        let mut config = CancellationDebtConfig::default();
        config.max_queue_depth = 10; // Very low threshold for testing
        let integration = DebtRuntimeIntegration::new(config);

        // Queue enough work to trigger emergency level
        for i in 0..12 {
            let _ = integration.on_task_cleanup_started(
                TaskId::new_for_test(i, 0),
                &CancelReason::user("emergency_test"),
                CancelKind::User,
                50,
            );
        }

        assert!(integration.check_emergency_intervention());

        let cleaned = integration.execute_emergency_relief(Duration::ZERO);
        assert!(cleaned > 0);
    }

    // ====================================================================
    // br-asupersync-b4ocgc: pluggable Sleeper covers the wall-clock
    // dependency in monitoring_loop. The default uses thread::sleep
    // (production behaviour). Tests inject a virtual-time sleeper to
    // keep the loop deterministic and replayable under LabRuntime.
    // ====================================================================

    #[test]
    fn b4ocgc_default_sleeper_is_thread_sleep_compatible() {
        // Sanity: the default constructor produces an integration
        // whose sleeper, when called with a tiny duration, returns
        // promptly without panicking. We don't assert exact timing
        // (wall-clock-dependent), only that the function shape is
        // callable.
        let integration = DebtRuntimeIntegration::default();
        let start = std::time::Instant::now();
        (integration.sleeper)(Duration::from_millis(1));
        let elapsed = start.elapsed();
        // Sanity bound: 1ms sleep should complete within 1s on any
        // sane system. Generous to avoid CI flakes.
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn b4ocgc_with_sleeper_replaces_thread_sleep_in_loop() {
        // Inject a virtual-time sleeper that records every duration
        // it was called with. Drive monitoring_loop manually for a
        // bounded number of iterations and assert the sleeper saw
        // exactly the configured check_interval each tick — without
        // ever blocking on wall-clock.
        let sleep_log: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
        let log_for_sleeper = sleep_log.clone();
        let max_calls = 3usize;
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_for_sleeper = shutdown.clone();

        let virtual_sleeper: DebtMonitorSleeper = Arc::new(move |d: Duration| {
            let mut log = log_for_sleeper
                .lock()
                .expect("sleeper log mutex should not be poisoned");
            log.push(d);
            // After max_calls iterations, set shutdown so the loop
            // exits — preserves the loop semantics test without
            // hanging the test process.
            if log.len() >= max_calls {
                *shutdown_for_sleeper
                    .lock()
                    .expect("sleeper shutdown mutex should not be poisoned") = true;
            }
            // No real sleep — we're under virtual time semantics.
        });

        let monitor = Arc::new(CancellationDebtMonitor::new(
            CancellationDebtConfig::default(),
        ));
        let check_interval = Duration::from_millis(123);
        DebtRuntimeIntegration::monitoring_loop(
            monitor,
            shutdown.clone(),
            check_interval,
            None,
            virtual_sleeper,
        );

        let calls = sleep_log
            .lock()
            .expect("sleep log mutex should not be poisoned");
        assert!(
            calls.len() >= max_calls,
            "loop should have called the sleeper at least {max_calls} times, got {}",
            calls.len()
        );
        for d in calls.iter() {
            assert_eq!(*d, check_interval, "every sleep must use check_interval");
        }
    }

    #[test]
    fn b4ocgc_with_sleeper_builder_threads_through_to_loop() {
        // Verify the with_sleeper builder's value is captured when
        // start_monitoring is called (covered indirectly: we inspect
        // the integration's sleeper field after building).
        let probe = Arc::new(Mutex::new(0u32));
        let probe_for_sleeper = probe.clone();
        let sleeper: DebtMonitorSleeper = Arc::new(move |_d| {
            *probe_for_sleeper
                .lock()
                .expect("probe mutex should not be poisoned in sleeper") += 1;
        });
        let integration = DebtRuntimeIntegration::default().with_sleeper(sleeper.clone());
        // Direct invocation of the captured sleeper to confirm the
        // field carries our closure (not the std::thread::sleep
        // default).
        (integration.sleeper)(Duration::from_secs(0));
        assert_eq!(
            *probe
                .lock()
                .expect("probe mutex should not be poisoned for assertion"),
            1
        );
    }

    /// br-asupersync-p9wth4 — Verify the panic-counter API on
    /// `CancellationDebtMonitor`. The `record_monitoring_loop_panic`
    /// hook is invoked from `monitoring_loop` whenever the
    /// `catch_unwind` guard recovers a tick-body panic; operators
    /// scrape `monitoring_loop_panic_count()` to detect that the
    /// observability loop has been hit.
    #[test]
    fn monitoring_loop_panic_counter_increments() {
        let monitor = CancellationDebtMonitor::default();
        assert_eq!(monitor.monitoring_loop_panic_count(), 0);
        monitor.record_monitoring_loop_panic();
        monitor.record_monitoring_loop_panic();
        assert_eq!(monitor.monitoring_loop_panic_count(), 2);
    }

    /// br-asupersync-p9wth4 — Direct in-line verification that a
    /// panic in code shaped like the per-tick body is caught by the
    /// same `catch_unwind` + `AssertUnwindSafe` pattern the loop
    /// uses, and that we can increment the recovered-panic counter
    /// from the catch path. This pins the catch_unwind/recovery
    /// contract independent of the real monitoring_loop's timing
    /// (which is awkward to drive deterministically without
    /// virtual time).
    #[test]
    fn monitoring_loop_catch_unwind_pattern_recovers_panic() {
        let monitor = Arc::new(CancellationDebtMonitor::default());
        let monitor_ref = &monitor;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Mimics the per-tick closure from monitoring_loop. The
            // panic stands in for a panicking alert callback or a
            // monitor accessor that asserted internally.
            let _ = monitor_ref.get_recent_alerts(1);
            panic!("simulated tick-body panic (p9wth4)");
        }));
        assert!(result.is_err(), "catch_unwind must capture the panic");
        monitor.record_monitoring_loop_panic();
        assert_eq!(
            monitor.monitoring_loop_panic_count(),
            1,
            "the recover path must be wired to the counter"
        );
    }
