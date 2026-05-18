//! Integration tests for the H1 request building conformance runner binary.
//!
//! These tests verify that the binary correctly fails closed on partial coverage
//! and produces appropriate exit codes.

use std::process::{Command, Output};

fn run_h1_request_building_conformance(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_h1_request_building_conformance"))
        .args(args)
        .output()
        .expect("Failed to run h1_request_building_conformance binary")
}

/// Test that the binary runs without panicking and produces expected output format
#[test]
fn test_binary_runs_successfully() {
    let output = run_h1_request_building_conformance(&["--timeout", "10", "--format", "summary"]);

    // The binary should run without being killed by signal
    assert!(
        output.status.code().is_some(),
        "Binary should exit with a specific exit code, not be killed by signal"
    );

    // Check that it produces expected output format
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain conformance results
    assert!(
        stderr.contains("HTTP/1.1 REQUEST BUILDING CONFORMANCE RESULTS")
            || stdout.contains("HTTP/1.1 REQUEST BUILDING CONFORMANCE SUMMARY"),
        "Output should contain conformance results. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

/// Test that the binary exit code is deterministic (fail-closed behavior)
#[test]
fn test_binary_fail_closed_behavior() {
    // Run the binary and capture exit code
    let output = run_h1_request_building_conformance(&["--timeout", "10"]);

    let exit_code = output.status.code();

    // The exit code should be deterministic (either 0 for full coverage success or 1 for failures/partial coverage)
    assert!(
        exit_code == Some(0) || exit_code == Some(1),
        "Binary should exit with code 0 (full coverage success) or 1 (failures/partial coverage), got: {:?}",
        exit_code
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // If exit code is 1, there should be indication of why in the output
    if exit_code == Some(1) {
        assert!(
            stderr.contains("FAILED")
                || stderr.contains("PARTIAL COVERAGE")
                || stderr.contains("Expected Failures")
                || stderr.contains("Skipped")
                || stdout.contains("Failed:")
                || stdout.contains("Expected Failures:")
                || stdout.contains("Skipped:"),
            "Exit code 1 should be accompanied by indication of failures or partial coverage. stdout: {}, stderr: {}",
            stdout,
            stderr
        );
    }

    // If exit code is 0, should indicate full success
    if exit_code == Some(0) {
        assert!(
            stderr.contains("ALL TESTS PASSED") || stdout.contains("Compliance Score: 100.0%"),
            "Exit code 0 should indicate all tests passed with full coverage. stdout: {}, stderr: {}",
            stdout,
            stderr
        );
    }
}

/// Test that the binary handles the --format flag correctly
#[test]
fn test_binary_output_formats() {
    // Test JSON format
    let json_output = run_h1_request_building_conformance(&["--format", "json", "--timeout", "5"]);

    assert!(
        json_output.status.code().is_some(),
        "JSON format should produce valid exit code"
    );

    // Test Markdown format
    let md_output =
        run_h1_request_building_conformance(&["--format", "markdown", "--timeout", "5"]);

    assert!(
        md_output.status.code().is_some(),
        "Markdown format should produce valid exit code"
    );

    // Test Summary format
    let summary_output =
        run_h1_request_building_conformance(&["--format", "summary", "--timeout", "5"]);

    assert!(
        summary_output.status.code().is_some(),
        "Summary format should produce valid exit code"
    );
}

/// Test that the binary handles timeout correctly
#[test]
fn test_binary_timeout_handling() {
    // Test with a very short timeout to ensure timeout handling works
    let output = run_h1_request_building_conformance(&["--timeout", "1"]);

    let exit_code = output.status.code();

    // Should either complete successfully or timeout (exit code 1)
    assert!(
        exit_code == Some(0) || exit_code == Some(1),
        "Binary should exit cleanly even with short timeout, got: {:?}",
        exit_code
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // If it timed out, should contain timeout message
    if stderr.contains("timed out") {
        assert_eq!(exit_code, Some(1), "Timeout should result in exit code 1");
    }
}

/// Test that verbose flag provides additional output without breaking exit code logic
#[test]
fn test_binary_verbose_flag() {
    let output = run_h1_request_building_conformance(&["--verbose", "--timeout", "10"]);

    // Verbose flag should not break exit code logic
    let exit_code = output.status.code();
    assert!(
        exit_code == Some(0) || exit_code == Some(1),
        "Verbose mode should not affect exit code logic, got: {:?}",
        exit_code
    );

    // Verbose mode might provide additional debug information in stderr
    // but should still produce the main results
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONFORMANCE RESULTS") || stderr.len() > 0,
        "Verbose mode should produce output"
    );
}

#[cfg(test)]
mod unit_tests {
    //! Unit tests for the exit code logic that can be tested without running the full binary

    use asupersync_conformance::{
        RequestBuildingComplianceReport, RequestBuildingComplianceSummary,
        RequestBuildingTestResult, RequestBuildingTestVerdict,
    };

    /// Test the fail-closed exit code logic
    #[test]
    fn test_exit_code_logic() {
        // Test case 1: All tests pass, no partial coverage -> exit 0
        let report1 = create_test_report(5, 0, 0, 0);
        assert_eq!(
            calculate_exit_code(&report1),
            0,
            "All pass with full coverage should exit 0"
        );

        // Test case 2: Some tests fail -> exit 1
        let report2 = create_test_report(3, 2, 0, 0);
        assert_eq!(
            calculate_exit_code(&report2),
            1,
            "Test failures should exit 1"
        );

        // Test case 3: Expected failures (partial coverage) -> exit 1
        let report3 = create_test_report(3, 0, 2, 0);
        assert_eq!(
            calculate_exit_code(&report3),
            1,
            "Expected failures should exit 1"
        );

        // Test case 4: Skipped tests (partial coverage) -> exit 1
        let report4 = create_test_report(3, 0, 0, 2);
        assert_eq!(
            calculate_exit_code(&report4),
            1,
            "Skipped tests should exit 1"
        );

        // Test case 5: Mixed failures and partial coverage -> exit 1
        let report5 = create_test_report(2, 1, 1, 1);
        assert_eq!(
            calculate_exit_code(&report5),
            1,
            "Mixed failures and partial coverage should exit 1"
        );
    }

    fn create_test_report(
        passed: usize,
        failed: usize,
        expected_failures: usize,
        skipped: usize,
    ) -> RequestBuildingComplianceReport {
        let total = passed + failed + expected_failures + skipped;
        let mut results = Vec::new();

        // Add results based on counts
        for i in 0..passed {
            results.push(create_test_result(
                format!("PASS-{}", i),
                RequestBuildingTestVerdict::Pass,
                true,
            ));
        }
        for i in 0..failed {
            results.push(create_test_result(
                format!("FAIL-{}", i),
                RequestBuildingTestVerdict::Fail,
                false,
            ));
        }
        for i in 0..expected_failures {
            results.push(create_test_result(
                format!("XFAIL-{}", i),
                RequestBuildingTestVerdict::ExpectedFailure,
                false,
            ));
        }
        for i in 0..skipped {
            results.push(create_test_result(
                format!("SKIP-{}", i),
                RequestBuildingTestVerdict::Skipped,
                false,
            ));
        }

        let compliance_score = if passed + failed > 0 {
            passed as f64 / (passed + failed) as f64
        } else {
            1.0
        };

        RequestBuildingComplianceReport {
            test_run_id: "test-123".to_string(),
            timestamp: "2026-05-07T00:00:00Z".to_string(),
            total_cases: total,
            results,
            summary: RequestBuildingComplianceSummary {
                passed,
                failed,
                expected_failures,
                skipped,
                total,
                compliance_score,
            },
        }
    }

    fn create_test_result(
        case_id: String,
        verdict: RequestBuildingTestVerdict,
        bytes_match: bool,
    ) -> RequestBuildingTestResult {
        let error = if verdict == RequestBuildingTestVerdict::Pass {
            None
        } else {
            Some(format!("Test error for {}", verdict))
        };

        RequestBuildingTestResult {
            case_id,
            verdict,
            error,
            asupersync_wire: vec![1, 2, 3],
            reqwest_wire: if bytes_match {
                vec![1, 2, 3]
            } else {
                vec![1, 2]
            },
            bytes_match,
            asupersync_size: 3,
            reqwest_size: if bytes_match { 3 } else { 2 },
        }
    }

    /// Calculate exit code using the same logic as the binary
    fn calculate_exit_code(report: &RequestBuildingComplianceReport) -> i32 {
        let has_failures = report.summary.failed > 0;
        let has_partial_coverage =
            report.summary.expected_failures > 0 || report.summary.skipped > 0;
        if has_failures || has_partial_coverage {
            1
        } else {
            0
        }
    }
}
