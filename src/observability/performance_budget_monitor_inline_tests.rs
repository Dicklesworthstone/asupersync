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
    fn upper_bound_budget_transitions_from_healthy_to_critical() {
        let pressure = Arc::new(SystemPressure::new());
        let mut monitor = PerformanceBudgetMonitor::new().with_pressure(pressure.clone());
        monitor.register_budget(
            PerformanceBudget::new(
                "sched.p99_latency_ms",
                "scheduler",
                "p99_latency_ms",
                BudgetDirection::UpperBound,
                10.0,
            )
            .with_warning_margin(0.20)
            .with_recommendation("inspect queue contention"),
        );

        let healthy = monitor.evaluate(1, &[BudgetSample::new("sched.p99_latency_ms", 7.0)]);
        assert_eq!(healthy.worst_severity, BudgetSeverity::Healthy);
        assert!(healthy.alerts.is_empty());
        assert!((pressure.headroom() - 1.0).abs() < f32::EPSILON);

        let warning = monitor.evaluate(2, &[BudgetSample::new("sched.p99_latency_ms", 8.5)]);
        assert_eq!(warning.worst_severity, BudgetSeverity::Warning);
        assert_eq!(warning.alerts.len(), 1);
        assert_eq!(warning.alerts[0].severity, BudgetSeverity::Warning);
        assert!(pressure.headroom() < 1.0);
        assert!(pressure.headroom() > 0.0);

        let critical = monitor.evaluate(3, &[BudgetSample::new("sched.p99_latency_ms", 12.0)]);
        assert_eq!(critical.worst_severity, BudgetSeverity::Critical);
        assert_eq!(critical.alerts.len(), 1);
        assert_eq!(critical.alerts[0].severity, BudgetSeverity::Critical);
        assert!(pressure.headroom().abs() < f32::EPSILON);
    }

    #[test]
    fn lower_bound_budget_warns_before_falling_below_threshold() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(
            PerformanceBudget::new(
                "codec.throughput_ops_per_sec",
                "codec",
                "throughput_ops_per_sec",
                BudgetDirection::LowerBound,
                1_000.0,
            )
            .with_warning_margin(0.10),
        );

        let warning = monitor.evaluate(
            7,
            &[BudgetSample::new("codec.throughput_ops_per_sec", 1_050.0)],
        );
        assert_eq!(warning.worst_severity, BudgetSeverity::Warning);
        assert_eq!(warning.alerts.len(), 1);
        assert_eq!(warning.alerts[0].severity, BudgetSeverity::Warning);

        let critical = monitor.evaluate(
            8,
            &[BudgetSample::new("codec.throughput_ops_per_sec", 980.0)],
        );
        assert_eq!(critical.worst_severity, BudgetSeverity::Critical);
        assert_eq!(critical.alerts.len(), 1);
        assert_eq!(critical.alerts[0].severity, BudgetSeverity::Critical);
        assert!(critical.worst_headroom.abs() < f32::EPSILON);
    }

    #[test]
    fn alerts_are_sorted_by_severity_then_budget_id() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(PerformanceBudget::new(
            "b.latency",
            "network",
            "latency_ms",
            BudgetDirection::UpperBound,
            5.0,
        ));
        monitor.register_budget(
            PerformanceBudget::new(
                "a.throughput",
                "network",
                "throughput_ops_per_sec",
                BudgetDirection::LowerBound,
                100.0,
            )
            .with_warning_margin(0.25),
        );

        let snapshot = monitor.evaluate(
            11,
            &[
                BudgetSample::new("b.latency", 7.0),
                BudgetSample::new("a.throughput", 110.0),
            ],
        );

        assert_eq!(snapshot.alerts.len(), 2);
        assert_eq!(snapshot.alerts[0].budget_id, "b.latency");
        assert_eq!(snapshot.alerts[0].severity, BudgetSeverity::Critical);
        assert_eq!(snapshot.alerts[1].budget_id, "a.throughput");
        assert_eq!(snapshot.alerts[1].severity, BudgetSeverity::Warning);
    }

    #[test]
    fn unknown_budget_samples_are_ignored() {
        let mut monitor = PerformanceBudgetMonitor::new();
        monitor.register_budget(PerformanceBudget::new(
            "runtime.queue_depth",
            "runtime",
            "queue_depth",
            BudgetDirection::UpperBound,
            1_000.0,
        ));

        let snapshot = monitor.evaluate(13, &[BudgetSample::new("other.metric", 123.0)]);
        assert!(snapshot.evaluations.is_empty());
        assert!(snapshot.alerts.is_empty());
        assert_eq!(snapshot.worst_severity, BudgetSeverity::Healthy);
        assert!((snapshot.worst_headroom - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn unknown_budget_samples_do_not_clear_shared_pressure() {
        let pressure = Arc::new(SystemPressure::with_headroom(0.25));
        let mut monitor = PerformanceBudgetMonitor::new().with_pressure(Arc::clone(&pressure));
        monitor.register_budget(PerformanceBudget::new(
            "runtime.queue_depth",
            "runtime",
            "queue_depth",
            BudgetDirection::UpperBound,
            1_000.0,
        ));

        let snapshot = monitor.evaluate(21, &[BudgetSample::new("other.metric", 123.0)]);
        assert!(snapshot.evaluations.is_empty());
        assert!(snapshot.alerts.is_empty());
        assert!(
            (pressure.headroom() - 0.25).abs() < f32::EPSILON,
            "a pass with no matching samples must preserve the previously published pressure"
        );
    }

    #[test]
    fn empty_pass_does_not_clear_shared_pressure() {
        let pressure = Arc::new(SystemPressure::with_headroom(0.5));
        let mut monitor = PerformanceBudgetMonitor::new().with_pressure(Arc::clone(&pressure));
        monitor.register_budget(PerformanceBudget::new(
            "scheduler.p99_latency_ms",
            "scheduler",
            "p99_latency_ms",
            BudgetDirection::UpperBound,
            10.0,
        ));

        let snapshot = monitor.evaluate(22, &[]);
        assert!(snapshot.evaluations.is_empty());
        assert!(snapshot.alerts.is_empty());
        assert!(
            (pressure.headroom() - 0.5).abs() < f32::EPSILON,
            "an empty evaluation pass must not publish synthetic full headroom"
        );
    }
