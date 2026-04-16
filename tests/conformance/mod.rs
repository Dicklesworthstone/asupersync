//! Conformance testing module for asupersync.
//!
//! This module contains conformance test suites that validate our implementations
//! against formal specifications (RFCs) and reference implementations.

pub mod hpack_rfc7541;
pub mod hpack_metamorphic;
pub mod codec_framing;
pub mod h2_rfc7540;

// Re-export main conformance test functionality
pub use hpack_rfc7541::{
    HpackConformanceHarness,
    RequirementLevel,
    TestVerdict,
};
pub use h2_rfc7540::{H2ConformanceHarness, H2ConformanceResult};

// Unified test categories for all conformance suites
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCategory {
    // HPACK categories
    StaticTable,
    DynamicTable,
    Huffman,
    Indexing,
    Context,
    ErrorHandling,
    RoundTrip,
    // HTTP/2 categories
    FrameFormat,
    StreamStates,
    Connection,
    Settings,
    FlowControl,
    Priority,
    Security,
    // Codec categories
    Framing,
    ResourceLimits,
    EdgeCases,
    Performance,
}

// Unified conformance test result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConformanceTestResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Run all available conformance test suites.
pub fn run_all_conformance_tests() -> Vec<ConformanceTestResult> {
    let mut results = Vec::new();

    // HPACK RFC 7541 conformance
    let hpack_harness = HpackConformanceHarness::new();
    let hpack_results: Vec<ConformanceTestResult> = hpack_harness.run_all_tests()
        .into_iter()
        .map(|r| ConformanceTestResult {
            test_id: r.test_id,
            description: r.description,
            category: match r.category {
                hpack_rfc7541::TestCategory::StaticTable => TestCategory::StaticTable,
                hpack_rfc7541::TestCategory::DynamicTable => TestCategory::DynamicTable,
                hpack_rfc7541::TestCategory::Huffman => TestCategory::Huffman,
                hpack_rfc7541::TestCategory::Indexing => TestCategory::Indexing,
                hpack_rfc7541::TestCategory::Context => TestCategory::Context,
                hpack_rfc7541::TestCategory::ErrorHandling => TestCategory::ErrorHandling,
                hpack_rfc7541::TestCategory::RoundTrip => TestCategory::RoundTrip,
            },
            requirement_level: r.requirement_level,
            verdict: r.verdict,
            error_message: r.error_message,
            execution_time_ms: r.execution_time_ms,
        })
        .collect();
    results.extend(hpack_results);

    // HTTP/2 RFC 7540 conformance
    let h2_harness = H2ConformanceHarness::new();
    let h2_results: Vec<ConformanceTestResult> = h2_harness.run_all_tests()
        .into_iter()
        .map(|r| ConformanceTestResult {
            test_id: r.test_id,
            description: r.description,
            category: match r.category {
                h2_rfc7540::TestCategory::FrameFormat => TestCategory::FrameFormat,
                h2_rfc7540::TestCategory::StreamStates => TestCategory::StreamStates,
                h2_rfc7540::TestCategory::Connection => TestCategory::Connection,
                h2_rfc7540::TestCategory::Settings => TestCategory::Settings,
                h2_rfc7540::TestCategory::ErrorHandling => TestCategory::ErrorHandling,
                h2_rfc7540::TestCategory::FlowControl => TestCategory::FlowControl,
                h2_rfc7540::TestCategory::Priority => TestCategory::Priority,
                h2_rfc7540::TestCategory::Security => TestCategory::Security,
            },
            requirement_level: match r.requirement_level {
                h2_rfc7540::RequirementLevel::Must => RequirementLevel::Must,
                h2_rfc7540::RequirementLevel::Should => RequirementLevel::Should,
                h2_rfc7540::RequirementLevel::May => RequirementLevel::May,
            },
            verdict: match r.verdict {
                h2_rfc7540::TestVerdict::Pass => TestVerdict::Pass,
                h2_rfc7540::TestVerdict::Fail => TestVerdict::Fail,
                h2_rfc7540::TestVerdict::Skipped => TestVerdict::Skipped,
                h2_rfc7540::TestVerdict::ExpectedFailure => TestVerdict::ExpectedFailure,
            },
            error_message: r.notes,
            execution_time_ms: r.elapsed_ms,
        })
        .collect();
    results.extend(h2_results);

    // Codec framing conformance
    let codec_harness = codec_framing::CodecConformanceHarness::new();
    let codec_results: Vec<ConformanceTestResult> = codec_harness.run_all_tests()
        .into_iter()
        .map(|r| ConformanceTestResult {
            test_id: r.test_id,
            description: r.description,
            category: match r.category {
                codec_framing::TestCategory::Framing => TestCategory::Framing,
                codec_framing::TestCategory::RoundTrip => TestCategory::RoundTrip,
                codec_framing::TestCategory::ErrorHandling => TestCategory::ErrorHandling,
                codec_framing::TestCategory::ResourceLimits => TestCategory::ResourceLimits,
                codec_framing::TestCategory::EdgeCases => TestCategory::EdgeCases,
                codec_framing::TestCategory::Performance => TestCategory::Performance,
            },
            requirement_level: r.requirement_level,
            verdict: r.verdict,
            error_message: r.error_message,
            execution_time_ms: r.execution_time_ms,
        })
        .collect();
    results.extend(codec_results);

    // Additional conformance suites will be added here:
    // - WebSocket RFC 6455 conformance
    // - gRPC conformance

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
                },
                "h2_rfc7540": {
                    "status": "implemented",
                    "coverage": "systematic",
                    "reference": "RFC 7540 HTTP/2 specification requirements"
                },
                "codec_framing": {
                    "status": "implemented",
                    "coverage": "systematic",
                    "reference": "Length-delimited, line-delimited, and byte-stream codecs"
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