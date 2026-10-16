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
    fn conformance_runner_executes_all_harnesses() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        // Should have results for all three components
        assert_eq!(runner.overall_results.len(), 3);

        let component_names: Vec<_> = runner.overall_results.iter().map(|r| r.component).collect();

        assert!(component_names.contains(&"E-Process Martingales"));
        assert!(component_names.contains(&"Static Leak Checker"));
        assert!(component_names.contains(&"Graded Types"));
    }

    #[test]
    fn compliance_report_generation() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        let report = runner.generate_compliance_report();

        // Should contain key sections
        assert!(report.contains("Obligation System Conformance Report"));
        assert!(report.contains("Executive Summary"));
        assert!(report.contains("Component Details"));
        assert!(report.contains("E-Process Martingale Analysis"));
        assert!(report.contains("Static Leak Checker Analysis"));
        assert!(report.contains("Graded Types Analysis"));
    }

    #[test]
    fn component_result_access() {
        let mut runner = ObligationConformanceRunner::new();
        runner.run_all_conformance_tests();

        let eprocess_result = runner.component_result("E-Process Martingales");
        assert!(eprocess_result.is_some());

        let nonexistent = runner.component_result("Nonexistent Component");
        assert!(nonexistent.is_none());
    }
