    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_oracle_creation() {
        let oracle = RegionLeakOracle::with_defaults();
        assert_eq!(oracle.violations().len(), 0);
    }

    #[test]
    fn test_region_lifecycle_tracking() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();
        let region_id = RegionId::new_for_test(1, 0);

        // Create a region
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);

        // Activate and close it properly
        oracle.on_region_activated(region_id);
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());
    }

    #[test]
    fn test_stuck_region_detection() {
        let mut oracle = RegionLeakOracle::with_strict_timeouts();
        let region_id = RegionId::new_for_test(1, 0);

        // Create a region but never activate it
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);

        // Wait longer than timeout would allow
        std::thread::sleep(Duration::from_millis(50));

        // `with_strict_timeouts` enables `fail_fast_mode`, which causes
        // `check_for_violations` to return `Err` as soon as any violation is
        // recorded. Drain the recorded violation list directly instead of
        // unwrapping the result, which would panic in fail-fast mode.
        let _ = oracle.check_for_violations();
        let recorded: Vec<_> = oracle.violations().iter().cloned().collect();
        assert!(!recorded.is_empty());
        assert!(matches!(
            recorded[0].violation_type,
            ViolationType::StuckCreation
        ));
    }

    #[test]
    fn test_task_tracking() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        // Create region and spawn task
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        // Complete task
        oracle.on_task_completed(task_id, Outcome::Ok(()));

        // Close region
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_tasks_spawned, 1);
        assert_eq!(stats.total_tasks_completed, 1);
    }

    #[test]
    fn statistics_report_current_active_entities() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        let active_stats = oracle.statistics();
        assert_eq!(active_stats.active_regions, 1);
        assert_eq!(active_stats.active_tasks, 1);

        oracle.on_task_completed(task_id, Outcome::Ok(()));
        oracle.on_task_completed(task_id, Outcome::Err("duplicate completion".to_string()));
        oracle.on_task_completed(TaskId::new_for_test(999, 0), Outcome::Ok(()));
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);
        oracle.on_region_closed(region_id);
        oracle.on_region_closed(RegionId::new_for_test(999, 0));

        let closed_stats = oracle.statistics();
        assert_eq!(closed_stats.active_regions, 0);
        assert_eq!(closed_stats.active_tasks, 0);
        assert_eq!(closed_stats.total_regions_created, 1);
        assert_eq!(closed_stats.total_regions_closed, 1);
        assert_eq!(closed_stats.total_tasks_spawned, 1);
        assert_eq!(closed_stats.total_tasks_completed, 1);
    }

    #[test]
    fn violation_context_ids_are_deterministically_ordered() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let parent = RegionId::new_for_test(10, 0);
        let child_a = RegionId::new_for_test(30, 0);
        let child_b = RegionId::new_for_test(20, 0);
        let task_a = TaskId::new_for_test(300, 0);
        let task_b = TaskId::new_for_test(100, 0);
        let task_c = TaskId::new_for_test(200, 0);

        oracle.on_region_created(parent, None, None, Budget::INFINITE);
        oracle.on_region_created(child_a, Some(parent), None, Budget::INFINITE);
        oracle.on_region_created(child_b, Some(parent), None, Budget::INFINITE);
        oracle.on_task_spawned(task_a, parent, None);
        oracle.on_task_spawned(task_b, parent, None);
        oracle.on_task_spawned(task_c, parent, None);

        let parent_region = oracle.regions.get(&parent).unwrap();
        let context = oracle.build_violation_context(parent_region);
        assert_eq!(context.active_tasks, vec![task_b, task_c, task_a]);
        assert_eq!(context.child_regions, vec![child_b, child_a]);
    }

    #[test]
    fn extra_finalizer_events_do_not_underflow_context() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);

        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_region_closing(region_id, 1);
        oracle.on_finalizer_completed(region_id);
        oracle.on_finalizer_completed(region_id);

        let region = oracle.regions.get(&region_id).unwrap();
        let context = oracle.build_violation_context(region);
        assert_eq!(context.outstanding_finalizers, 0);
    }

    #[test]
    fn test_orphaned_task_detection() {
        let mut oracle = RegionLeakOracle::with_defaults();
        let region_id = RegionId::new_for_test(1, 0);
        let task_id = TaskId::new_for_test(100, 0);

        // Create region and spawn task
        oracle.on_region_created(region_id, None, None, Budget::INFINITE);
        oracle.on_task_spawned(task_id, region_id, None);

        // Close region without completing task (violation!)
        oracle.on_region_closing(region_id, 0);
        oracle.on_region_closed(region_id);

        // Should detect orphaned tasks
        let violations = oracle.check_for_violations().unwrap();
        assert!(!violations.is_empty());
        assert!(matches!(
            violations[0].violation_type,
            ViolationType::OrphanedTasks
        ));
    }

    /// br-asupersync-rw5m1a: `RegionViolation` must implement
    /// `std::error::Error` so it composes with the `?` operator and
    /// other `dyn Error`-keyed plumbing.
    #[test]
    fn region_violation_implements_std_error() {
        // Compile-time bound: a function that requires `dyn Error +
        // Send + Sync + 'static` accepts our type. If `RegionViolation`
        // does not impl `Error`, this fails to compile.
        fn assert_impls_error<E: std::error::Error + Send + Sync + 'static>(_: &E) {}

        let violation = RegionViolation {
            violation_type: ViolationType::IdleRegion,
            region_id: RegionId::new_for_test(1, 0),
            detected_at: SystemTime::now(),
            duration: Duration::from_secs(0),
            description: "test".to_string(),
            context: ViolationContext::empty(),
            suggested_fix: String::new(),
        };
        assert_impls_error(&violation);

        // The default `source()` returns None for our aggregate type.
        let as_error: &dyn std::error::Error = &violation;
        assert!(as_error.source().is_none());
    }

    /// br-asupersync-rw5m1a: `?` operator works on a function that
    /// returns `Result<_, RegionViolation>` and converts via
    /// `Box<dyn Error>`. This locks in the practical use-case the
    /// Error impl exists to enable.
    #[test]
    fn region_violation_works_with_question_mark_operator() {
        fn make_failing() -> Result<(), RegionViolation> {
            Err(RegionViolation {
                violation_type: ViolationType::ResourceLeak,
                region_id: RegionId::new_for_test(2, 0),
                detected_at: SystemTime::now(),
                duration: Duration::from_secs(0),
                description: "synthetic".to_string(),
                context: ViolationContext::empty(),
                suggested_fix: String::new(),
            })
        }

        // The body uses `?` to convert RegionViolation into
        // `Box<dyn Error>` via the `From<E: Error> for Box<dyn Error>`
        // blanket impl. If `RegionViolation` did not impl `Error`,
        // this function would fail to compile.
        fn boxed_error_caller() -> Result<(), Box<dyn std::error::Error>> {
            make_failing()?;
            Ok(())
        }

        let result = boxed_error_caller();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The Display impl renders "<violation_type>: <description>".
        let rendered = format!("{err}");
        assert!(rendered.contains("Resource Leak"));
        assert!(rendered.contains("synthetic"));
    }
