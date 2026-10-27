    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::metrics::NoOpMetrics;
    use crate::types::{RegionId, TaskId};
    use crate::util::ArenaIndex;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct CapturingMetrics {
        on_panic: Option<Box<dyn Fn(&'static str) + Send + Sync>>,
        panics: StdMutex<Vec<&'static str>>,
        tasks_spawned: StdMutex<Vec<(RegionId, TaskId)>>,
        tasks_completed: StdMutex<
            Vec<(
                TaskId,
                crate::observability::metrics::OutcomeKind,
                std::time::Duration,
            )>,
        >,
        regions_created: StdMutex<Vec<(RegionId, Option<RegionId>)>>,
        regions_closed: StdMutex<Vec<(RegionId, std::time::Duration)>>,
        cancellation_requests: StdMutex<Vec<(RegionId, crate::types::CancelKind)>>,
        drain_completions: StdMutex<Vec<(RegionId, std::time::Duration)>>,
        obligations_created: StdMutex<Vec<RegionId>>,
        obligations_discharged: StdMutex<Vec<RegionId>>,
        obligations_leaked: StdMutex<Vec<RegionId>>,
    }

    impl CapturingMetrics {
        fn tasks_spawned(&self) -> Vec<(RegionId, TaskId)> {
            self.tasks_spawned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn regions_created(&self) -> Vec<(RegionId, Option<RegionId>)> {
            self.regions_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn regions_closed(&self) -> Vec<(RegionId, std::time::Duration)> {
            self.regions_closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn obligations_created(&self) -> Vec<RegionId> {
            self.obligations_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn cancellation_requests(&self) -> Vec<(RegionId, crate::types::CancelKind)> {
            self.cancellation_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        #[allow(dead_code)]
        fn panics_captured(&self) -> Vec<&'static str> {
            self.panics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl crate::observability::metrics::MetricsProvider for CapturingMetrics {
        fn task_spawned(&self, region_id: RegionId, task_id: TaskId) {
            self.tasks_spawned
                .lock()
                .unwrap()
                .push((region_id, task_id));
        }

        fn task_completed(
            &self,
            task_id: TaskId,
            outcome: crate::observability::metrics::OutcomeKind,
            duration: std::time::Duration,
        ) {
            self.tasks_completed
                .lock()
                .unwrap()
                .push((task_id, outcome, duration));
        }

        fn region_created(&self, region_id: RegionId, parent_id: Option<RegionId>) {
            self.regions_created
                .lock()
                .unwrap()
                .push((region_id, parent_id));
        }

        fn region_closed(&self, region_id: RegionId, duration: std::time::Duration) {
            self.regions_closed
                .lock()
                .unwrap()
                .push((region_id, duration));
        }

        fn cancellation_requested(
            &self,
            region_id: RegionId,
            cancel_kind: crate::types::CancelKind,
        ) {
            self.cancellation_requests
                .lock()
                .unwrap()
                .push((region_id, cancel_kind));
        }

        fn drain_completed(&self, region_id: RegionId, duration: std::time::Duration) {
            self.drain_completions
                .lock()
                .unwrap()
                .push((region_id, duration));
        }

        fn deadline_set(&self, __region_id: RegionId, __duration: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_exceeded(&self, __region_id: RegionId) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_warning(
            &self,
            _context: &str,
            _location: &'static str,
            _remaining: std::time::Duration,
        ) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_violation(&self, _context: &str, _elapsed: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_remaining(&self, _context: &str, _remaining: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn checkpoint_interval(&self, _context: &str, _interval: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn task_stuck_detected(&self, _task_context: &str) {
            // Simple implementation - could extend if needed for testing
        }

        fn obligation_created(&self, region_id: RegionId) {
            self.obligations_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn obligation_discharged(&self, region_id: RegionId) {
            self.obligations_discharged
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn obligation_leaked(&self, region_id: RegionId) {
            self.obligations_leaked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn scheduler_tick(&self, _ready_count: usize, _tick_duration: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn record_panic(&self, location: &'static str) {
            self.panics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(location);
            if let Some(observer) = &self.on_panic {
                observer(location);
            }
        }
    }

    #[test]
    fn test_panic_isolation_success() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || 42,
        );

        assert!(result.is_success());
        assert_eq!(result.into_success(), Some(42));
    }

    #[test]
    fn test_panic_isolation_catches_panic() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || panic!("test panic"),
        );

        assert!(result.is_panicked());
        if let PanicIsolationResult::Panicked(context) = result {
            assert_eq!(context.panic_message, Some("test panic".to_string()));
            assert!(matches!(
                context.location,
                PanicLocation::TaskExecution { .. }
            ));
        }
    }

    #[test]
    fn test_panic_context_creation() {
        let config = PanicIsolationConfig {
            capture_backtraces: true,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_finalizer_execution(
            RegionId::from_arena(ArenaIndex::new(2, 0)),
            FinalizerType::Sync,
            || panic!("finalizer panic"),
        );

        if let PanicIsolationResult::Panicked(context) = result {
            assert!(context.backtrace.is_some());
            assert_eq!(
                context.region_id,
                Some(RegionId::from_arena(ArenaIndex::new(2, 0)))
            );
            assert!(matches!(
                context.location,
                PanicLocation::FinalizerExecution { .. }
            ));
        } else {
            panic!("Expected panicked result");
        }
    }

    #[test]
    fn test_panic_to_outcome_conversion() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let context = PanicContext {
            panic_id: 1,
            location: PanicLocation::TaskExecution {
                task_id: TaskId::from_arena(ArenaIndex::new(1, 0)),
                region_id: RegionId::from_arena(ArenaIndex::new(1, 0)),
                poll_attempt: 1,
            },
            timestamp: Instant::now(),
            panic_message: Some("test panic".to_string()),
            backtrace: None,
            region_id: Some(RegionId::from_arena(ArenaIndex::new(1, 0))),
            task_id: Some(TaskId::from_arena(ArenaIndex::new(1, 0))),
            obligation_id: None,
        };

        let outcome = isolator.panic_to_outcome(&context);
        assert!(matches!(outcome, Outcome::Panicked(_)));
    }

    #[test]
    fn test_disabled_isolation() {
        let config = PanicIsolationConfig {
            isolate_task_panics: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        // This should not panic because isolation is disabled,
        // but we can't easily test this without actually panicking
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || 42,
        );

        assert!(result.is_success());
        assert_eq!(result.into_success(), Some(42));
    }

    #[test]
    fn test_region_panic_threshold_skips_followup_operations() {
        let config = PanicIsolationConfig {
            panic_threshold_per_region: Some(1),
            capture_backtraces: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(7, 0));

        let first = isolator.isolate_task_execution(task_id, region_id, 1, || panic!("boom"));
        assert!(matches!(first, PanicIsolationResult::Panicked(_)));

        let second = isolator.isolate_task_execution(task_id, region_id, 2, || 99);
        match second {
            PanicIsolationResult::Skipped { reason, context } => {
                assert!(reason.contains("exceeded panic threshold 1"));
                assert_eq!(context.region_id, Some(region_id));
                assert_eq!(context.task_id, Some(task_id));
                assert_eq!(context.panic_message.as_deref(), Some(reason.as_str()));
            }
            other => panic!("expected skipped result, got {:?}", other),
        }
    }

    #[test]
    fn test_panic_threshold_isolated_per_region() {
        let config = PanicIsolationConfig {
            panic_threshold_per_region: Some(1),
            capture_backtraces: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_a = RegionId::from_arena(ArenaIndex::new(8, 0));
        let region_b = RegionId::from_arena(ArenaIndex::new(9, 0));

        let first = isolator.isolate_task_execution(task_id, region_a, 1, || panic!("boom"));
        assert!(matches!(first, PanicIsolationResult::Panicked(_)));

        let other_region = isolator.isolate_task_execution(task_id, region_b, 1, || 7);
        assert!(matches!(other_region, PanicIsolationResult::Success(7)));
    }

    #[test]
    fn exhausted_panic_threshold_still_runs_cleanup_and_resolves_obligations() {
        use crate::obligation::ledger::ObligationLedger;
        use crate::record::{ObligationAbortReason, ObligationKind};
        use crate::types::Time;

        for threshold in [0, 1, 3] {
            let metrics = Arc::new(CapturingMetrics::default());
            let isolator = PanicIsolator::new(
                PanicIsolationConfig {
                    capture_backtraces: false,
                    enable_panic_logging: false,
                    panic_threshold_per_region: Some(threshold),
                    ..Default::default()
                },
                metrics.clone(),
            );
            let task = TaskId::from_arena(ArenaIndex::new(28, 0));
            let region = RegionId::from_arena(ArenaIndex::new(29, 0));
            for poll in 0..threshold {
                assert!(
                    isolator
                        .isolate_task_execution(task, region, poll, || panic!("task failure"))
                        .is_panicked()
                );
            }
            let task_invoked = std::cell::Cell::new(false);
            assert!(matches!(
                isolator.isolate_task_execution(task, region, threshold, || {
                    task_invoked.set(true);
                }),
                PanicIsolationResult::Skipped { .. }
            ));
            assert!(!task_invoked.get(), "threshold still fences ordinary work");

            let cleanup_count = std::cell::Cell::new(0);
            for finalizer_type in [
                FinalizerType::Sync,
                FinalizerType::Async,
                FinalizerType::Custom("release resource".into()),
            ] {
                let failed = isolator.isolate_finalizer_execution(
                    region,
                    finalizer_type.clone(),
                    || panic!("finalizer failure"),
                );
                assert!(failed.is_panicked(), "finalizer must be attempted");
                assert_eq!(
                    failed.panic_context().unwrap().panic_message.as_deref(),
                    Some("finalizer failure")
                );
                let completed = isolator.isolate_finalizer_execution(region, finalizer_type, || {
                    cleanup_count.set(cleanup_count.get() + 1);
                });
                assert!(completed.is_success(), "later finalizer must still run");
            }
            for phase in [
                CleanupPhase::Finalizers,
                CleanupPhase::ObligationResolution,
                CleanupPhase::ResourceCleanup,
                CleanupPhase::StateTransition,
            ] {
                assert!(
                    isolator
                        .isolate_region_cleanup(region, phase, || {
                            cleanup_count.set(cleanup_count.get() + 1);
                        })
                        .is_success()
                );
            }
            assert_eq!(cleanup_count.get(), 7);

            let mut ledger = ObligationLedger::new();
            let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
            let obligation = token.id();
            assert_eq!(ledger.pending_count(), 1, "fixture owns a real obligation");
            assert!(
                isolator
                    .isolate_obligation_handling(obligation, region, || {
                        ledger.abort(token, Time::ZERO, ObligationAbortReason::Cancel);
                    })
                    .is_success()
            );
            assert_eq!(ledger.pending_count(), 0, "cleanup discharges the obligation");
            assert_eq!(ledger.stats().total_aborted, 1);
            assert_eq!(
                isolator.region_panic_counts.lock().get(&region),
                Some(&(threshold + 3)),
                "cleanup still records every original panic"
            );
            assert_eq!(metrics.panics_captured().len(), threshold as usize + 3);
        }
    }

    /// br-asupersync-zcu3c4 — verifies that the previously inert
    /// `MetricsProviderPanicExt::record_panic` now actually delegates to
    /// `MetricsProvider::record_panic`, with the canonical location tag.
    /// The old code path computed `_location_tag` and discarded it; production
    /// dashboards never observed any panic-rate signal.
    #[test]
    fn record_panic_routes_to_metrics_provider() {
        use std::sync::Mutex as StdMutex;

        #[derive(Default)]
        struct CapturingMetrics {
            panics: StdMutex<Vec<&'static str>>,
            tasks_spawned: StdMutex<Vec<(RegionId, TaskId)>>,
            tasks_completed: StdMutex<
                Vec<(
                    TaskId,
                    crate::observability::metrics::OutcomeKind,
                    std::time::Duration,
                )>,
            >,
            regions_created: StdMutex<Vec<(RegionId, Option<RegionId>)>>,
            regions_closed: StdMutex<Vec<(RegionId, std::time::Duration)>>,
            cancellation_requests: StdMutex<Vec<(RegionId, crate::types::CancelKind)>>,
            drain_completions: StdMutex<Vec<(RegionId, std::time::Duration)>>,
            obligations_created: StdMutex<Vec<RegionId>>,
            obligations_discharged: StdMutex<Vec<RegionId>>,
            obligations_leaked: StdMutex<Vec<RegionId>>,
        }

        #[allow(dead_code)]
        impl CapturingMetrics {
            fn tasks_spawned(&self) -> Vec<(RegionId, TaskId)> {
                self.tasks_spawned
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn regions_created(&self) -> Vec<(RegionId, Option<RegionId>)> {
                self.regions_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn regions_closed(&self) -> Vec<(RegionId, std::time::Duration)> {
                self.regions_closed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn obligations_created(&self) -> Vec<RegionId> {
                self.obligations_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn obligations_leaked(&self) -> Vec<RegionId> {
                self.obligations_leaked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn cancellation_requests(&self) -> Vec<(RegionId, crate::types::CancelKind)> {
                self.cancellation_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }
        }

        impl crate::observability::metrics::MetricsProvider for CapturingMetrics {
            fn task_spawned(&self, region_id: RegionId, task_id: TaskId) {
                self.tasks_spawned
                    .lock()
                    .unwrap()
                    .push((region_id, task_id));
            }

            fn task_completed(
                &self,
                task_id: TaskId,
                outcome_kind: crate::observability::metrics::OutcomeKind,
                duration: std::time::Duration,
            ) {
                self.tasks_completed
                    .lock()
                    .unwrap()
                    .push((task_id, outcome_kind, duration));
            }

            fn region_created(&self, region_id: RegionId, parent_id: Option<RegionId>) {
                self.regions_created
                    .lock()
                    .unwrap()
                    .push((region_id, parent_id));
            }

            fn region_closed(&self, region_id: RegionId, duration: std::time::Duration) {
                self.regions_closed
                    .lock()
                    .unwrap()
                    .push((region_id, duration));
            }

            fn cancellation_requested(
                &self,
                region_id: RegionId,
                cancel_kind: crate::types::CancelKind,
            ) {
                self.cancellation_requests
                    .lock()
                    .unwrap()
                    .push((region_id, cancel_kind));
            }

            fn drain_completed(&self, region_id: RegionId, duration: std::time::Duration) {
                self.drain_completions
                    .lock()
                    .unwrap()
                    .push((region_id, duration));
            }

            fn deadline_set(&self, _region_id: RegionId, _duration: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_exceeded(&self, _region_id: RegionId) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_warning(
                &self,
                _context: &str,
                _location: &'static str,
                _remaining: std::time::Duration,
            ) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_violation(&self, _context: &str, _elapsed: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_remaining(&self, _context: &str, _remaining: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn checkpoint_interval(&self, _context: &str, _interval: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn task_stuck_detected(&self, _task_context: &str) {
                // Simple implementation - could extend if needed for testing
            }

            fn obligation_created(&self, region_id: RegionId) {
                self.obligations_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn obligation_discharged(&self, region_id: RegionId) {
                self.obligations_discharged
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn obligation_leaked(&self, region_id: RegionId) {
                self.obligations_leaked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn scheduler_tick(&self, _ready_count: usize, _tick_duration: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn record_panic(&self, location: &'static str) {
                self.panics
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(location);
            }
        }

        let metrics = CapturingMetrics::default();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(2, 0));

        // Build a panic context for each of the 5 PanicLocation variants and
        // route through the extension trait. Each must produce exactly one
        // record_panic call with the matching canonical tag.
        let cases: Vec<(PanicLocation, &'static str)> = vec![
            (
                PanicLocation::TaskExecution {
                    task_id,
                    region_id,
                    poll_attempt: 1,
                },
                "task_execution",
            ),
            (
                PanicLocation::FinalizerExecution {
                    region_id,
                    finalizer_type: FinalizerType::Sync,
                },
                "finalizer_execution",
            ),
            (
                PanicLocation::RegionCleanup {
                    region_id,
                    cleanup_phase: CleanupPhase::Finalizers,
                },
                "region_cleanup",
            ),
            (
                PanicLocation::ObligationHandling {
                    obligation_id: ObligationId::from_arena(ArenaIndex::new(3, 0)),
                    region_id,
                },
                "obligation_handling",
            ),
            (
                PanicLocation::SchedulerInternal {
                    worker_id: Some(0),
                    operation: "test".to_string(),
                },
                "scheduler_internal",
            ),
        ];

        for (location, _expected) in &cases {
            let ctx = PanicContext {
                panic_id: 0,
                location: location.clone(),
                timestamp: Instant::now(),
                panic_message: Some("test".to_string()),
                backtrace: None,
                region_id: Some(region_id),
                task_id: Some(task_id),
                obligation_id: None,
            };
            <CapturingMetrics as MetricsProviderPanicExt>::record_panic(&metrics, &ctx);
        }

        let observed: Vec<&'static str> = metrics
            .panics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let expected: Vec<&'static str> = cases.iter().map(|(_, t)| *t).collect();
        assert_eq!(
            observed, expected,
            "every PanicLocation must route to a record_panic call with the canonical tag"
        );
    }

    /// Test that instrumentation callbacks properly capture runtime lifecycle events
    /// during panic isolation scenarios. This verifies that the previously inert
    /// MetricsProvider implementation now collects observability data for monitoring
    /// region creation, task spawning, obligation tracking, and cancellation events.
    #[test]
    fn instrumentation_callbacks_capture_runtime_lifecycle_events() {
        // Create CapturingMetrics directly so we can access the captured data
        let metrics = Arc::new(CapturingMetrics::default());

        let task_id = TaskId::from_arena(ArenaIndex::new(42, 1));
        let region_id = RegionId::from_arena(ArenaIndex::new(100, 2));
        let parent_region_id = RegionId::from_arena(ArenaIndex::new(99, 1));

        // Simulate runtime events by directly calling the metrics provider
        let metrics_ref = &*metrics;

        // Simulate region lifecycle
        metrics_ref.region_created(region_id, Some(parent_region_id));
        metrics_ref.task_spawned(region_id, task_id);

        // Simulate obligation tracking
        metrics_ref.obligation_created(region_id);

        // Simulate task completion
        metrics_ref.task_completed(
            task_id,
            crate::observability::metrics::OutcomeKind::Ok,
            std::time::Duration::from_millis(100),
        );

        // Simulate cancellation
        metrics_ref.cancellation_requested(region_id, crate::types::CancelKind::User);

        // Simulate obligation lifecycle
        metrics_ref.obligation_discharged(region_id);

        // Simulate region closure
        metrics_ref.region_closed(region_id, std::time::Duration::from_millis(500));

        // Verify all events were captured
        // Check that region creation was captured
        let regions_created = metrics.regions_created();
        assert_eq!(regions_created.len(), 1);
        assert_eq!(regions_created[0], (region_id, Some(parent_region_id)));

        // Check that task spawning was captured
        let tasks_spawned = metrics.tasks_spawned();
        assert_eq!(tasks_spawned.len(), 1);
        assert_eq!(tasks_spawned[0], (region_id, task_id));

        // Check that region closure was captured
        let regions_closed = metrics.regions_closed();
        assert_eq!(regions_closed.len(), 1);
        assert_eq!(regions_closed[0].0, region_id);
        assert_eq!(regions_closed[0].1, std::time::Duration::from_millis(500));

        // Check that obligations were tracked
        let obligations_created = metrics.obligations_created();
        assert_eq!(obligations_created.len(), 1);
        assert_eq!(obligations_created[0], region_id);

        // Check that cancellation was captured
        let cancellation_requests = metrics.cancellation_requests();
        assert_eq!(cancellation_requests.len(), 1);
        assert_eq!(
            cancellation_requests[0],
            (region_id, crate::types::CancelKind::User)
        );
    }

    fn quiet_isolator(metrics: Arc<dyn MetricsProvider>) -> PanicIsolator {
        PanicIsolator::new(
            PanicIsolationConfig {
                capture_backtraces: false,
                enable_panic_logging: false,
                panic_threshold_per_region: Some(2),
                ..Default::default()
            },
            metrics,
        )
    }

    struct PanickingPayload(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for PanickingPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("payload destructor panic");
        }
    }

    #[test]
    fn panicking_metrics_preserve_primary_context_and_region_accounting() {
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(|_| panic!("metrics observer panic"))),
            ..Default::default()
        });
        let isolator = quiet_isolator(metrics.clone());
        let task = TaskId::from_arena(ArenaIndex::new(11, 0));
        let region = RegionId::from_arena(ArenaIndex::new(12, 0));

        let result = isolator.isolate_task_execution(task, region, 1, || {
            panic!("original task panic");
        });
        let context = result.panic_context().expect("original panic is retained");
        assert_eq!(context.panic_message.as_deref(), Some("original task panic"));
        assert_eq!(context.task_id, Some(task));
        assert_eq!(context.region_id, Some(region));
        assert_eq!(metrics.panics_captured(), vec!["task_execution"]);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
        // A secondary metrics panic must not exhaust the two-panic threshold.
        assert_eq!(
            isolator
                .isolate_task_execution(task, region, 2, || 7)
                .into_success(),
            Some(7)
        );
    }

    #[test]
    fn payload_destructor_panic_does_not_escape_or_suppress_metrics() {
        let metrics = Arc::new(CapturingMetrics::default());
        let isolator = quiet_isolator(metrics.clone());
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payload = PanickingPayload(drops.clone());
        let region = RegionId::from_arena(ArenaIndex::new(13, 0));
        let result = isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || {
            std::panic::panic_any(payload);
        });

        assert!(result.is_panicked());
        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("Non-string panic payload")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.panics_captured(), vec!["finalizer_execution"]);
        assert_eq!(isolator.suppressed_observer_panics(), 0);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
    }

    #[test]
    fn observer_payload_destructor_panic_is_also_contained() {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observer_drops = drops.clone();
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(move |_| {
                std::panic::panic_any(PanickingPayload(observer_drops.clone()));
            })),
            ..Default::default()
        });
        let isolator = quiet_isolator(metrics);
        let result = isolator.isolate_scheduler_operation(None, "poll".into(), || {
            panic!("primary scheduler panic");
        });

        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("primary scheduler panic")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
    }

    #[test]
    fn recursively_panicking_payload_gets_only_one_destructor_attempt() {
        struct RecursivePayload(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for RecursivePayload {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(Self(self.0.clone()));
            }
        }

        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let isolator = quiet_isolator(Arc::new(NoOpMetrics));
        let payload = RecursivePayload(drops.clone());
        let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
            isolator.isolate_scheduler_operation(None, "poll".into(), || {
                std::panic::panic_any(payload);
            })
        }));
        let result = match caught {
            Ok(result) => result,
            Err(escaped) => {
                // Keep the negative control from aborting the test process by
                // dropping this intentionally self-reproducing panic payload.
                std::mem::forget(escaped);
                panic!("payload destructor escaped panic isolation");
            }
        };
        assert!(result.is_panicked());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
    }

    #[test]
    fn failed_observer_does_not_prevent_independent_observer_dispatch() {
        let isolator = quiet_isolator(Arc::new(NoOpMetrics));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        isolator.run_observer(|| panic!("first observer"));
        isolator.run_observer(|| {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn metrics_observer_can_reenter_after_primary_accounting_is_published() {
        let slot = Arc::new(StdMutex::new(std::sync::Weak::<PanicIsolator>::new()));
        let observer_slot = slot.clone();
        let region = RegionId::from_arena(ArenaIndex::new(14, 0));
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(move |_| {
                let isolator = observer_slot.lock().unwrap().upgrade().unwrap();
                {
                    let counts = isolator
                        .region_panic_counts
                        .try_lock()
                        .expect("observer must not run under the counter lock");
                    assert_eq!(counts.get(&region), Some(&1));
                }
                assert_eq!(
                    isolator
                        .isolate_region_cleanup(region, CleanupPhase::ResourceCleanup, || 9)
                        .into_success(),
                    Some(9)
                );
            })),
            ..Default::default()
        });
        let isolator = Arc::new(quiet_isolator(metrics.clone()));
        *slot.lock().unwrap() = Arc::downgrade(&isolator);
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(15, 0)),
            region,
            1,
            || panic!("primary"),
        );
        assert!(result.is_panicked());
        assert_eq!(metrics.panics_captured(), vec!["task_execution"]);
        // Assertions inside observers must not be silently swallowed by the
        // boundary being tested.
        assert_eq!(isolator.suppressed_observer_panics(), 0);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
    }

    #[test]
    fn threshold_skip_releases_captures_without_running_operation() {
        struct Capture(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Capture {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let metrics = Arc::new(CapturingMetrics::default());
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(0);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture(drops.clone());
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(16, 0)),
            RegionId::from_arena(ArenaIndex::new(17, 0)),
            1,
            || {
                invoked.store(true, Ordering::SeqCst);
                drop(capture);
                42
            },
        );
        assert!(matches!(result, PanicIsolationResult::Skipped { .. }));
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(metrics.panics_captured().is_empty());
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn threshold_contains_capture_drop_panics_at_each_region_entrypoint() {
        let task_id = TaskId::from_arena(ArenaIndex::new(18, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(19, 0));
        let obligation_id = ObligationId::from_arena(ArenaIndex::new(20, 0));
        let cases = [
            (
                PanicLocation::TaskExecution {
                    task_id,
                    region_id,
                    poll_attempt: 3,
                },
                "task_execution",
            ),
            (
                PanicLocation::FinalizerExecution {
                    region_id,
                    finalizer_type: FinalizerType::Sync,
                },
                "finalizer_execution",
            ),
            (
                PanicLocation::RegionCleanup {
                    region_id,
                    cleanup_phase: CleanupPhase::ResourceCleanup,
                },
                "region_cleanup",
            ),
            (
                PanicLocation::ObligationHandling {
                    obligation_id,
                    region_id,
                },
                "obligation_handling",
            ),
        ];
        for (location, tag) in cases {
            let metrics = Arc::new(CapturingMetrics::default());
            let mut isolator = quiet_isolator(metrics.clone());
            isolator.config.panic_threshold_per_region = Some(0);
            let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let capture = PanickingPayload(drops.clone());
            let invoked = std::sync::atomic::AtomicBool::new(false);
            let operation = || {
                invoked.store(true, Ordering::SeqCst);
                drop(capture);
                42
            };
            let result = match &location {
                PanicLocation::TaskExecution { poll_attempt, .. } => {
                    isolator.isolate_task_execution(task_id, region_id, *poll_attempt, operation)
                }
                PanicLocation::FinalizerExecution { finalizer_type, .. } => {
                    isolator.isolate_finalizer_execution(region_id, finalizer_type.clone(), operation)
                }
                PanicLocation::RegionCleanup { cleanup_phase, .. } => {
                    isolator.isolate_region_cleanup(region_id, cleanup_phase.clone(), operation)
                }
                PanicLocation::ObligationHandling { .. } => {
                    isolator.isolate_obligation_handling(obligation_id, region_id, operation)
                }
                PanicLocation::SchedulerInternal { .. } => unreachable!(),
            };
            assert!(
                result.is_panicked(),
                "capture cleanup must not escape or be hidden as skipped"
            );
            let context = result.panic_context().unwrap();
            assert_eq!(context.location, location);
            assert_eq!(context.region_id, Some(region_id));
            assert_eq!(
                context.panic_message.as_deref(),
                Some("payload destructor panic")
            );
            assert_eq!(
                invoked.load(Ordering::SeqCst),
                !matches!(location, PanicLocation::TaskExecution { .. }),
                "only task polling may be skipped; cleanup must be attempted"
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(metrics.panics_captured(), vec![tag]);
            assert_eq!(isolator.region_panic_counts.lock().get(&region_id), Some(&1));
            assert_eq!(isolator.suppressed_observer_panics(), 0);
            // The capture panicked; its resulting string payload did not.
            assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
        }
    }

    #[test]
    fn reached_threshold_counts_cleanup_failure_without_affecting_other_regions() {
        let metrics = Arc::new(CapturingMetrics::default());
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(1);
        let task = TaskId::from_arena(ArenaIndex::new(21, 0));
        let region = RegionId::from_arena(ArenaIndex::new(22, 0));
        assert!(
            isolator
                .isolate_task_execution(task, region, 1, || panic!("first"))
                .is_panicked()
        );

        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = PanickingPayload(drops.clone());
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_region_cleanup(region, CleanupPhase::ResourceCleanup, || {
            invoked.store(true, Ordering::SeqCst);
            drop(capture);
        });
        assert!(result.is_panicked());
        assert!(invoked.load(Ordering::SeqCst));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&2));
        assert_eq!(
            metrics.panics_captured(),
            vec!["task_execution", "region_cleanup"]
        );
        let healthy_region = RegionId::from_arena(ArenaIndex::new(23, 0));
        assert_eq!(
            isolator
                .isolate_task_execution(task, healthy_region, 1, || 7)
                .into_success(),
            Some(7)
        );
    }

    #[test]
    fn threshold_cleanup_contains_compound_payload_and_observer_failures() {
        struct Capture {
            drops: Arc<std::sync::atomic::AtomicUsize>,
            payload_drops: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload(self.payload_drops.clone()));
            }
        }

        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(|_| panic!("observer failed too"))),
            ..Default::default()
        });
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(0);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payload_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture {
            drops: drops.clone(),
            payload_drops: payload_drops.clone(),
        };
        let region = RegionId::from_arena(ArenaIndex::new(24, 0));
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || {
            invoked.store(true, Ordering::SeqCst);
            drop(capture);
        });
        assert!(result.is_panicked());
        assert!(invoked.load(Ordering::SeqCst));
        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("Non-string panic payload")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.panics_captured(), vec!["finalizer_execution"]);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
    }

    #[test]
    fn threshold_cleanup_can_reenter_without_region_counter_lock() {
        struct Capture {
            isolator: Arc<PanicIsolator>,
            drops: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                {
                    let counts = self
                        .isolator
                        .region_panic_counts
                        .try_lock()
                        .expect("capture retirement must be outside the region counter lock");
                    assert!(counts.is_empty());
                }
                assert_eq!(
                    self.isolator
                        .isolate_scheduler_operation(None, "capture cleanup".into(), || 9)
                        .into_success(),
                    Some(9)
                );
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let mut isolator = quiet_isolator(Arc::new(NoOpMetrics));
        isolator.config.panic_threshold_per_region = Some(0);
        let isolator = Arc::new(isolator);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture {
            isolator: isolator.clone(),
            drops: drops.clone(),
        };
        let result = isolator.isolate_region_cleanup(
            RegionId::from_arena(ArenaIndex::new(25, 0)),
            CleanupPhase::ResourceCleanup,
            || drop(capture),
        );
        // A swallowed assertion in the capture destructor must fail this test.
        assert!(matches!(result, PanicIsolationResult::Success(())));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn disabled_isolation_still_bypasses_zero_threshold() {
        let mut isolator = quiet_isolator(Arc::new(NoOpMetrics));
        isolator.config.panic_threshold_per_region = Some(0);
        isolator.config.isolate_task_panics = false;
        isolator.config.isolate_finalizer_panics = false;
        let task = TaskId::from_arena(ArenaIndex::new(26, 0));
        let region = RegionId::from_arena(ArenaIndex::new(27, 0));
        assert_eq!(
            isolator.isolate_task_execution(task, region, 1, || 5).into_success(),
            Some(5)
        );
        assert_eq!(
            isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || 6).into_success(),
            Some(6)
        );
        let propagated = std::panic::catch_unwind(AssertUnwindSafe(|| {
            isolator.isolate_task_execution(task, region, 2, || panic!("not isolated"))
        }));
        assert!(propagated.is_err());
        assert!(isolator.region_panic_counts.lock().is_empty());
    }
