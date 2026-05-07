//! RFC 9000 Section 9 QUIC connection migration conformance binary.
//!
//! The executable delegates to the production-backed conformance harness used by
//! `tests/conformance/quic_connection_migration_rfc9000.rs`. That harness drives
//! `NativeQuicConnection` where the native QUIC seam exists, and reports explicit
//! unsupported-boundary evidence where RFC 9000 behavior is not exposed yet.

#[path = "../../../tests/conformance/quic_connection_migration_rfc9000.rs"]
mod quic_connection_migration_rfc9000;

use quic_connection_migration_rfc9000::{QuicConnectionMigrationConformanceHarness, TestVerdict};

fn main() {
    println!("QUIC Connection Migration Conformance Tests (RFC 9000 Section 9)");
    println!("=================================================================");
    println!();

    let harness = QuicConnectionMigrationConformanceHarness::new();
    let results = harness.run_all_tests();

    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    let mut skipped_count = 0usize;
    let mut expected_failure_count = 0usize;

    for result in &results {
        match result.verdict {
            TestVerdict::Pass => {
                pass_count += 1;
                println!(
                    "PASS {} [{} / {}]",
                    result.test_id,
                    result.support_class(),
                    result.evidence_quality()
                );
            }
            TestVerdict::Fail => {
                fail_count += 1;
                println!(
                    "FAIL {}: {}",
                    result.test_id,
                    result
                        .error_message
                        .as_deref()
                        .unwrap_or("no failure detail")
                );
            }
            TestVerdict::Skipped => {
                skipped_count += 1;
                println!(
                    "SKIP {}: {}",
                    result.test_id,
                    result.error_message.as_deref().unwrap_or("no skip detail")
                );
            }
            TestVerdict::ExpectedFailure => {
                expected_failure_count += 1;
                println!(
                    "EXPECTED_FAILURE {} [{} / {}]: {}",
                    result.test_id,
                    result.support_class(),
                    result.evidence_quality(),
                    result
                        .error_message
                        .as_deref()
                        .unwrap_or("unsupported boundary recorded")
                );
            }
        }
    }

    println!();
    println!("Summary:");
    println!("--------");
    println!("Tests run: {}", results.len());
    println!("Passed: {pass_count}");
    println!("Failed: {fail_count}");
    println!("Skipped: {skipped_count}");
    println!("Expected failures: {expected_failure_count}");

    println!(
        "{}",
        final_status_line(skipped_count, expected_failure_count)
    );

    std::process::exit(exit_code(
        results.len(),
        fail_count,
        skipped_count,
        expected_failure_count,
    ));
}

fn final_status_line(skipped_count: usize, expected_failure_count: usize) -> String {
    if skipped_count == 0 && expected_failure_count == 0 {
        "ALL TESTS PASSED".to_string()
    } else {
        format!(
            "NO FAILURES; PARTIAL COVERAGE ({skipped_count} skipped, {expected_failure_count} expected failures)"
        )
    }
}

fn exit_code(
    total_count: usize,
    fail_count: usize,
    skipped_count: usize,
    expected_failure_count: usize,
) -> i32 {
    if fail_count > 0 || total_count == 0 || skipped_count > 0 || expected_failure_count > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_runner_reports_no_failed_results() {
        let harness = QuicConnectionMigrationConformanceHarness::new();
        let results = harness.run_all_tests();

        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|result| result.verdict != TestVerdict::Fail),
            "{results:#?}"
        );
    }

    #[test]
    fn binary_runner_preserves_live_and_unsupported_evidence_classes() {
        let harness = QuicConnectionMigrationConformanceHarness::new();
        let results = harness.run_all_tests();

        assert!(
            results
                .iter()
                .any(|result| result.support_class() == "production_live")
        );
        assert!(
            results
                .iter()
                .any(|result| result.evidence_quality() == "unsupported_boundary")
        );
    }

    #[test]
    fn final_status_does_not_claim_all_passed_for_partial_coverage() {
        let harness = QuicConnectionMigrationConformanceHarness::new();
        let results = harness.run_all_tests();
        let skipped_count = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Skipped)
            .count();
        let expected_failure_count = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::ExpectedFailure)
            .count();

        assert!(
            skipped_count + expected_failure_count > 0,
            "fixture must keep at least one unsupported-boundary result"
        );

        let status = final_status_line(skipped_count, expected_failure_count);

        assert!(status.starts_with("NO FAILURES; PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }

    #[test]
    fn final_status_claims_all_passed_only_for_full_green_results() {
        assert_eq!(final_status_line(0, 0), "ALL TESTS PASSED");
    }

    #[test]
    fn exit_code_is_nonzero_for_partial_coverage() {
        let harness = QuicConnectionMigrationConformanceHarness::new();
        let results = harness.run_all_tests();
        let fail_count = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Fail)
            .count();
        let skipped_count = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Skipped)
            .count();
        let expected_failure_count = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::ExpectedFailure)
            .count();

        assert_eq!(
            exit_code(
                results.len(),
                fail_count,
                skipped_count,
                expected_failure_count,
            ),
            1
        );
    }

    #[test]
    fn exit_code_is_zero_only_for_full_pass_coverage() {
        assert_eq!(exit_code(1, 0, 0, 0), 0);
        assert_eq!(exit_code(0, 0, 0, 0), 1);
    }

    #[test]
    fn binary_source_has_no_legacy_local_model_names() {
        let source = include_str!("quic_migration_rfc9000.rs");
        for (left, right) in [
            ("Mock", "PathValidator"),
            ("MockConnection", "IdManager"),
            ("simulate_source", "_address_change"),
            ("simulate_concurrent", "_migration"),
        ] {
            let forbidden = format!("{left}{right}");
            assert!(!source.contains(&forbidden), "found {forbidden}");
        }
    }
}
