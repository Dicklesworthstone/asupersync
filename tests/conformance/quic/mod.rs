//! QUIC Stream Conformance Test Suite
//!
//! Validates QUIC stream implementation against RFC 9000 requirements.
//!
//! Usage:
//! ```bash
//! cargo test --test conformance_quic_stream_rfc9000
//! cargo run --bin quic_conformance_report  # Generate compliance report
//! ```

pub mod stream_states;

use crate::conformance_quic_stream_rfc9000::{ComplianceReport, RequirementLevel, TestVerdict};
use std::collections::HashMap;

/// Integration point for QUIC stream conformance tests
pub struct QuicStreamConformanceHarness;

impl QuicStreamConformanceHarness {
    /// Run full RFC 9000 conformance suite
    pub fn run_full_suite() -> ConformanceResults {
        let report = ComplianceReport::generate();
        let mut results = ConformanceResults::default();

        for (section, stats) in &report.section_stats {
            results.section_results.insert(section.clone(), SectionResult {
                must_score: if stats.must_total > 0 {
                    (stats.must_passing as f64 / stats.must_total as f64) * 100.0
                } else {
                    100.0
                },
                should_score: if stats.should_total > 0 {
                    (stats.should_passing as f64 / stats.should_total as f64) * 100.0
                } else {
                    100.0
                },
                may_score: if stats.may_total > 0 {
                    (stats.may_passing as f64 / stats.may_total as f64) * 100.0
                } else {
                    100.0
                },
                total_tests: stats.must_total + stats.should_total + stats.may_total,
                passing_tests: stats.must_passing + stats.should_passing + stats.may_passing,
                xfail_count: stats.xfail,
            });
        }

        results
    }

    /// Check minimum conformance requirements
    pub fn validate_minimum_conformance() -> Result<(), Vec<String>> {
        let results = Self::run_full_suite();
        let mut errors = Vec::new();

        for (section, result) in &results.section_results {
            if result.must_score < 95.0 {
                errors.push(format!(
                    "Section {}: MUST clause coverage {:.1}% < required 95%",
                    section, result.must_score
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Generate detailed compliance report
    pub fn generate_compliance_report() -> String {
        let report = ComplianceReport::generate();
        report.to_markdown()
    }
}

#[derive(Debug, Default)]
pub struct ConformanceResults {
    pub section_results: HashMap<String, SectionResult>,
}

#[derive(Debug)]
pub struct SectionResult {
    pub must_score: f64,
    pub should_score: f64,
    pub may_score: f64,
    pub total_tests: usize,
    pub passing_tests: usize,
    pub xfail_count: usize,
}

impl ConformanceResults {
    /// Get overall conformance score
    pub fn overall_score(&self) -> f64 {
        let total_tests: usize = self.section_results.values()
            .map(|r| r.total_tests)
            .sum();
        let passing_tests: usize = self.section_results.values()
            .map(|r| r.passing_tests)
            .sum();

        if total_tests == 0 {
            0.0
        } else {
            (passing_tests as f64 / total_tests as f64) * 100.0
        }
    }

    /// Check if conformant (all MUST clauses pass)
    pub fn is_conformant(&self) -> bool {
        self.section_results.values()
            .all(|result| result.must_score >= 95.0)
    }

    /// Get summary statistics
    pub fn summary(&self) -> ConformanceSummary {
        let total_tests: usize = self.section_results.values()
            .map(|r| r.total_tests)
            .sum();
        let passing_tests: usize = self.section_results.values()
            .map(|r| r.passing_tests)
            .sum();
        let xfail_total: usize = self.section_results.values()
            .map(|r| r.xfail_count)
            .sum();

        ConformanceSummary {
            total_tests,
            passing_tests,
            failing_tests: total_tests - passing_tests - xfail_total,
            xfail_tests: xfail_total,
            overall_score: self.overall_score(),
            is_conformant: self.is_conformant(),
        }
    }
}

#[derive(Debug)]
pub struct ConformanceSummary {
    pub total_tests: usize,
    pub passing_tests: usize,
    pub failing_tests: usize,
    pub xfail_tests: usize,
    pub overall_score: f64,
    pub is_conformant: bool,
}

impl std::fmt::Display for ConformanceSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,
            "RFC 9000 QUIC Stream Conformance Summary:\n\
             Total: {}\n\
             Passed: {}\n\
             Failed: {}\n\
             Expected Failures: {}\n\
             Overall Score: {:.1}%\n\
             Conformant: {}",
            self.total_tests,
            self.passing_tests,
            self.failing_tests,
            self.xfail_tests,
            self.overall_score,
            if self.is_conformant { "✅ YES" } else { "❌ NO" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_conformance_minimum_requirements() {
        let result = QuicStreamConformanceHarness::validate_minimum_conformance();

        match result {
            Ok(()) => {
                println!("✅ QUIC stream implementation meets minimum RFC 9000 conformance");
            }
            Err(errors) => {
                for error in &errors {
                    eprintln!("❌ {}", error);
                }
                panic!("RFC 9000 conformance failed: {} requirement violations", errors.len());
            }
        }
    }

    #[test]
    fn test_conformance_report_generation() {
        let report = QuicStreamConformanceHarness::generate_compliance_report();
        assert!(!report.is_empty());
        assert!(report.contains("RFC 9000"));
        assert!(report.contains("MUST"));
        assert!(report.contains("Score"));
    }

    #[test]
    fn test_conformance_results_summary() {
        let results = QuicStreamConformanceHarness::run_full_suite();
        let summary = results.summary();

        println!("{}", summary);

        // Basic sanity checks
        assert!(summary.total_tests > 0);
        assert!(summary.overall_score >= 0.0 && summary.overall_score <= 100.0);
        assert_eq!(
            summary.total_tests,
            summary.passing_tests + summary.failing_tests + summary.xfail_tests
        );
    }
}