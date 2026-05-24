//! Integration test for runtime+scheduler conformance test harnesses.
//!
//! This test verifies that our newly created conformance test harnesses for the
//! runtime+scheduler domain are properly integrated and working correctly.

#[path = "conformance/mod.rs"]
mod conformance;

use conformance::{
    KernelConformanceHarness, ReactorConformanceHarness, RemoteConformanceHarness,
    RuntimeRequirementLevel, RuntimeTestCategory, RuntimeTestVerdict, SchedulerConformanceHarness,
    harness::run_full_runtime_conformance_suite,
};

#[test]
fn test_remote_conformance_harness() {
    let mut harness = RemoteConformanceHarness::new();
    let results = harness.run_full_suite();

    assert!(
        !results.is_empty(),
        "Remote conformance should produce test results"
    );

    // Check that we have tests covering all major remote execution aspects
    let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category).collect();

    assert!(categories.contains(&RuntimeTestCategory::DistributedStructuredConcurrency));
    assert!(categories.contains(&RuntimeTestCategory::NamedComputationContract));
    assert!(categories.contains(&RuntimeTestCategory::RemoteCapabilityModel));

    // Verify we have MUST-level requirements
    let must_tests = results
        .iter()
        .filter(|r| r.requirement_level == RuntimeRequirementLevel::Must)
        .count();
    assert!(
        must_tests > 0,
        "Should have MUST-level requirements for remote execution"
    );

    // Check for any hard failures (not expected failures)
    let failures: Vec<_> = results.iter().filter(|r| r.is_hard_failure()).collect();
    if !failures.is_empty() {
        panic!("Remote conformance tests failed: {:#?}", failures);
    }
}

#[test]
fn test_kernel_conformance_harness() {
    let mut harness = KernelConformanceHarness::new();
    let results = harness.run_full_suite();

    assert!(
        !results.is_empty(),
        "Kernel conformance should produce test results"
    );

    // Check that we have tests covering kernel contracts
    let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category).collect();

    assert!(categories.contains(&RuntimeTestCategory::SnapshotContract));
    assert!(categories.contains(&RuntimeTestCategory::ControllerRegistration));
    assert!(categories.contains(&RuntimeTestCategory::VersionCompatibility));

    // Check for any hard failures
    let failures: Vec<_> = results.iter().filter(|r| r.is_hard_failure()).collect();
    if !failures.is_empty() {
        panic!("Kernel conformance tests failed: {:#?}", failures);
    }
}

#[test]
fn test_reactor_conformance_harness() {
    let mut harness = ReactorConformanceHarness::new();
    let results = harness.run_full_suite();

    assert!(
        !results.is_empty(),
        "Reactor conformance should produce test results"
    );

    // Check that we have tests covering reactor contracts
    let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category).collect();

    assert!(categories.contains(&RuntimeTestCategory::IoEventNotification));
    assert!(categories.contains(&RuntimeTestCategory::RegistrationLifecycle));
    assert!(categories.contains(&RuntimeTestCategory::ThreadSafety));

    // Check for any hard failures
    let failures: Vec<_> = results.iter().filter(|r| r.is_hard_failure()).collect();
    if !failures.is_empty() {
        panic!("Reactor conformance tests failed: {:#?}", failures);
    }
}

#[test]
fn test_scheduler_conformance_harness() {
    let mut harness = SchedulerConformanceHarness::new();
    let results = harness.run_full_suite();

    assert!(
        !results.is_empty(),
        "Scheduler conformance should produce test results"
    );

    // Check that we have tests covering scheduler contracts
    let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category).collect();

    assert!(categories.contains(&RuntimeTestCategory::TaskExecution));
    assert!(categories.contains(&RuntimeTestCategory::WorkStealing));
    assert!(categories.contains(&RuntimeTestCategory::PriorityScheduling));

    // Check for any hard failures
    let failures: Vec<_> = results.iter().filter(|r| r.is_hard_failure()).collect();
    if !failures.is_empty() {
        panic!("Scheduler conformance tests failed: {:#?}", failures);
    }
}

#[test]
fn test_full_runtime_conformance_suite() {
    let results = run_full_runtime_conformance_suite();

    assert!(
        !results.is_empty(),
        "Full runtime conformance suite should produce results"
    );

    // Verify we have comprehensive coverage
    assert!(
        results.len() >= 100,
        "Should have comprehensive test coverage, got {}",
        results.len()
    );

    // Check requirement level distribution
    let must_tests = results
        .iter()
        .filter(|r| r.requirement_level == RuntimeRequirementLevel::Must)
        .count();
    let should_tests = results
        .iter()
        .filter(|r| r.requirement_level == RuntimeRequirementLevel::Should)
        .count();
    let may_tests = results
        .iter()
        .filter(|r| r.requirement_level == RuntimeRequirementLevel::May)
        .count();

    assert!(must_tests > 0, "Should have MUST-level requirements");
    assert!(should_tests > 0, "Should have SHOULD-level requirements");
    assert!(
        must_tests >= should_tests,
        "MUST requirements should be most common"
    );

    // Check category coverage
    let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category).collect();

    // Remote categories
    assert!(categories.contains(&RuntimeTestCategory::DistributedStructuredConcurrency));
    assert!(categories.contains(&RuntimeTestCategory::NamedComputationContract));
    assert!(categories.contains(&RuntimeTestCategory::RemoteCapabilityModel));

    // Kernel categories
    assert!(categories.contains(&RuntimeTestCategory::SnapshotContract));
    assert!(categories.contains(&RuntimeTestCategory::ControllerRegistration));

    // Reactor categories
    assert!(categories.contains(&RuntimeTestCategory::IoEventNotification));
    assert!(categories.contains(&RuntimeTestCategory::ThreadSafety));

    // Scheduler categories
    assert!(categories.contains(&RuntimeTestCategory::TaskExecution));
    assert!(categories.contains(&RuntimeTestCategory::WorkStealing));
    assert!(categories.contains(&RuntimeTestCategory::PriorityScheduling));

    println!("Runtime+Scheduler Conformance Suite Summary:");
    println!("  Total tests: {}", results.len());
    println!("  MUST tests: {}", must_tests);
    println!("  SHOULD tests: {}", should_tests);
    println!("  MAY tests: {}", may_tests);
    println!("  Categories: {}", categories.len());

    // Report any hard failures
    let failures: Vec<_> = results.iter().filter(|r| r.is_hard_failure()).collect();

    if !failures.is_empty() {
        println!("\nFailed tests:");
        for failure in &failures {
            println!("  - {}: {:?}", failure.test_name, failure.verdict);
        }
        panic!("{} runtime conformance tests failed", failures.len());
    } else {
        println!("✅ All runtime+scheduler conformance tests passed!");
    }
}

#[test]
fn test_coverage_statistics() {
    use crate::conformance::harness::CoverageStats;

    let results = run_full_runtime_conformance_suite();
    let stats = CoverageStats::from_results(&results);

    println!("\nCoverage Statistics:");
    println!("  Total tests: {}", stats.total_tests);
    println!("  Passing: {}", stats.passing);
    println!("  Failing: {}", stats.failing);
    println!("  Expected failures: {}", stats.expected_failures);
    println!("  MUST coverage: {:.1}%", stats.must_score * 100.0);
    println!("  SHOULD coverage: {:.1}%", stats.should_score * 100.0);
    println!("  MAY coverage: {:.1}%", stats.may_score * 100.0);

    // Verify reasonable coverage thresholds
    assert!(
        stats.must_score >= 0.95,
        "MUST coverage should be ≥95%, got {:.1}%",
        stats.must_score * 100.0
    );
    assert!(
        stats.should_score >= 0.80,
        "SHOULD coverage should be ≥80%, got {:.1}%",
        stats.should_score * 100.0
    );

    // Check overall conformance
    if stats.is_conformant() {
        println!("✅ Runtime+Scheduler implementation is CONFORMANT");
    } else {
        println!("❌ Runtime+Scheduler implementation is NON-CONFORMANT");
        assert!(
            stats.is_conformant(),
            "Runtime+Scheduler should be conformant"
        );
    }
}

#[test]
fn test_conformance_report_generation() {
    use crate::conformance::harness::generate_conformance_report;

    let report = generate_conformance_report();
    println!("\n{}", report);

    // Verify report structure
    assert!(!report.is_empty(), "Conformance report should not be empty");
    assert!(
        report.contains("Runtime+Scheduler Conformance Report"),
        "Should contain report title"
    );
    assert!(report.contains("Summary"), "Should contain summary section");
    assert!(
        report.contains("Compliance Scores"),
        "Should contain compliance scores"
    );
    assert!(
        report.contains("Detailed Test Results"),
        "Should contain detailed results"
    );
}
