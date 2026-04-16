//! Conformance testing module for asupersync.
//!
//! This module contains conformance test suites that validate our implementations
//! against formal specifications (RFCs) and reference implementations.

pub mod hpack_rfc7541;
pub mod hpack_metamorphic;

// Re-export main conformance test functionality
pub use hpack_rfc7541::{
    HpackConformanceHarness,
    ConformanceTestResult,
    RequirementLevel,
    TestCategory,
    TestVerdict,
};

/// Run all available conformance test suites.
pub fn run_all_conformance_tests() -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // HPACK RFC 7541 conformance
    let hpack_harness = HpackConformanceHarness::new();
    results.extend(hpack_harness.run_all_tests());

    // Additional conformance suites will be added here:
    // - HTTP/2 RFC 7540 conformance
    // - WebSocket RFC 6455 conformance
    // - gRPC conformance
    // - Codec framing conformance

    results
}

/// Generate conformance compliance report in JSON format.
pub fn generate_compliance_report() -> serde_json::Value {
    let results = run_all_conformance_tests();

    let total = results.len();
    let passed = results.iter().filter(|r| r.verdict == TestVerdict::Pass).count();
    let failed = results.iter().filter(|r| r.verdict == TestVerdict::Fail).count();
    let skipped = results.iter().filter(|r| r.verdict == TestVerdict::Skipped).count();
    let expected_failures = results.iter().filter(|r| r.verdict == TestVerdict::ExpectedFailure).count();

    // MUST clause coverage calculation
    let must_tests: Vec<_> = results.iter()
        .filter(|r| r.requirement_level == RequirementLevel::Must)
        .collect();
    let must_passed = must_tests.iter()
        .filter(|r| r.verdict == TestVerdict::Pass)
        .count();
    let must_total = must_tests.len();
    let must_coverage = if must_total > 0 {
        (must_passed as f64 / must_total as f64) * 100.0
    } else {
        0.0
    };

    // Group results by category
    let mut by_category = std::collections::HashMap::new();
    for result in &results {
        let category_name = format!("{:?}", result.category);
        let category_stats = by_category.entry(category_name).or_insert_with(|| {
            serde_json::json!({
                "total": 0,
                "passed": 0,
                "failed": 0,
                "expected_failures": 0
            })
        });

        category_stats["total"] = category_stats["total"].as_u64().unwrap() + 1;
        match result.verdict {
            TestVerdict::Pass => {
                category_stats["passed"] = category_stats["passed"].as_u64().unwrap() + 1;
            }
            TestVerdict::Fail => {
                category_stats["failed"] = category_stats["failed"].as_u64().unwrap() + 1;
            }
            TestVerdict::ExpectedFailure => {
                category_stats["expected_failures"] = category_stats["expected_failures"].as_u64().unwrap() + 1;
            }
            _ => {}
        }
    }

    serde_json::json!({
        "conformance_report": {
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "asupersync_version": env!("CARGO_PKG_VERSION"),
            "summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "expected_failures": expected_failures,
                "success_rate": if total > 0 { (passed as f64 / total as f64) * 100.0 } else { 0.0 }
            },
            "must_clause_coverage": {
                "passed": must_passed,
                "total": must_total,
                "coverage_percent": must_coverage,
                "meets_target": must_coverage >= 95.0
            },
            "categories": by_category,
            "test_suites": {
                "hpack_rfc7541": {
                    "status": "implemented",
                    "coverage": "systematic",
                    "reference": "RFC 7541 Appendix C test vectors"
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conformance_suite_integration() {
        let results = run_all_conformance_tests();
        assert!(!results.is_empty(), "Should have conformance test results");

        // Verify all tests have required fields
        for result in &results {
            assert!(!result.test_id.is_empty(), "Test ID must not be empty");
            assert!(!result.description.is_empty(), "Description must not be empty");
        }

        // Generate and validate report structure
        let report = generate_compliance_report();
        assert!(report["conformance_report"].is_object(), "Report should have conformance_report section");
        assert!(report["conformance_report"]["summary"].is_object(), "Report should have summary");
        assert!(report["conformance_report"]["must_clause_coverage"].is_object(), "Report should have MUST coverage");
    }

    #[test]
    fn test_hpack_conformance_integration() {
        let hpack_harness = HpackConformanceHarness::new();
        let results = hpack_harness.run_all_tests();

        assert!(!results.is_empty(), "HPACK conformance should have tests");

        // Check for expected test categories
        let categories: std::collections::HashSet<_> = results
            .iter()
            .map(|r| &r.category)
            .collect();

        assert!(categories.contains(&TestCategory::StaticTable), "Should test static table");
        assert!(categories.contains(&TestCategory::RoundTrip), "Should test round-trip");
    }

    #[test]
    fn test_compliance_report_generation() {
        let report = generate_compliance_report();
        let summary = &report["conformance_report"]["summary"];

        assert!(summary["total_tests"].as_u64().unwrap() > 0, "Should have tests");
        assert!(summary["success_rate"].as_f64().is_some(), "Should calculate success rate");

        let must_coverage = &report["conformance_report"]["must_clause_coverage"];
        assert!(must_coverage["coverage_percent"].as_f64().is_some(), "Should calculate MUST coverage");
    }
}