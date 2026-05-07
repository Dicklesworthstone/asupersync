//! HTTP/1.1 Request Building Conformance Test Runner
//!
//! Runs differential conformance testing for HTTP/1.1 request building,
//! comparing asupersync RequestBuilder against reqwest reference implementation
//! to ensure byte-identical wire output.
//!
//! Usage:
//!   cargo run --bin h1_request_building_conformance
//!   cargo run --bin h1_request_building_conformance -- --format json
//!   cargo run --bin h1_request_building_conformance -- --output report.md

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "h1_request_building_conformance")]
#[command(about = "HTTP/1.1 request building conformance tester")]
struct Args {
    /// Output format for results
    #[arg(long, default_value = "markdown")]
    format: OutputFormat,

    /// Output file path (defaults to stdout)
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Run specific test case by ID
    #[arg(long)]
    test_case: Option<String>,

    /// Verbose logging
    #[arg(long, short)]
    verbose: bool,

    /// Timeout in seconds for test execution
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Markdown,
    Summary,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    }

    println!("🔧 HTTP/1.1 Request Building Conformance Tester");
    println!("   Testing asupersync against hyper-util reference");
    println!("   Focus: Byte-identical wire format for same RequestBuilder operations");
    println!();

    // Create and configure the tester
    let mut tester = asupersync_conformance::RequestBuildingConformanceTester::new();

    // Filter to specific test case if requested
    if let Some(test_id) = &args.test_case {
        tester.test_cases.retain(|case| case.id == *test_id);
        if tester.test_cases.is_empty() {
            eprintln!("❌ Test case '{}' not found", test_id);
            std::process::exit(1);
        }
        println!("🔍 Running single test case: {}", test_id);
    } else {
        println!(
            "📋 Running {} conformance test cases",
            tester.test_cases.len()
        );
    }

    // Set up timeout
    let timeout_duration = std::time::Duration::from_secs(args.timeout);

    // Run the conformance tests with timeout
    let report = match tokio::time::timeout(timeout_duration, tester.run_all_tests()).await {
        Ok(report) => report,
        Err(_) => {
            eprintln!("❌ Tests timed out after {} seconds", args.timeout);
            std::process::exit(1);
        }
    };

    // Generate output based on format
    let output = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
        OutputFormat::Markdown => tester.generate_markdown_report(&report),
        OutputFormat::Summary => generate_summary_output(&report),
    };

    // Write output
    match args.output {
        Some(path) => {
            std::fs::write(&path, &output)?;
            println!("📝 Report written to: {}", path.display());
        }
        None => {
            println!("{}", output);
        }
    }

    // Print final status
    println!();
    print_test_summary(&report);

    // Exit with appropriate code (fail closed on partial coverage)
    // Exit non-zero if there are failures, expected failures, or skipped tests (indicating incomplete coverage)
    let has_failures = report.summary.failed > 0;
    let has_partial_coverage = has_incomplete_coverage(&report);
    let exit_code = exit_code(&report);

    if args.verbose && exit_code != 0 {
        eprintln!("🚨 Exiting with code {} due to:", exit_code);
        if has_failures {
            eprintln!("   - {} test failures", report.summary.failed);
        }
        if has_partial_coverage {
            eprintln!(
                "   - Partial coverage: {} expected failures, {} skipped",
                report.summary.expected_failures, report.summary.skipped
            );
        }
    }

    std::process::exit(exit_code);
}

/// Generate a concise summary output
fn generate_summary_output(
    report: &asupersync_conformance::RequestBuildingComplianceReport,
) -> String {
    let mut output = String::new();

    output.push_str("HTTP/1.1 REQUEST BUILDING CONFORMANCE SUMMARY\n");
    output.push_str("=========================================\n\n");

    output.push_str(&format!("Test Run: {}\n", report.test_run_id));
    output.push_str(&format!("Timestamp: {}\n", report.timestamp));
    output.push_str(&format!("Total Cases: {}\n\n", report.total_cases));

    output.push_str("RESULTS:\n");
    output.push_str(&format!("  ✅ Passed: {}\n", report.summary.passed));
    output.push_str(&format!("  ❌ Failed: {}\n", report.summary.failed));
    output.push_str(&format!(
        "  ⚠️  Expected Failures: {}\n",
        report.summary.expected_failures
    ));
    output.push_str(&format!("  ⏭️  Skipped: {}\n\n", report.summary.skipped));

    output.push_str(&format!(
        "Compliance Score: {:.1}%\n",
        report.summary.compliance_score * 100.0
    ));

    if report.summary.failed > 0 {
        output.push_str("\nFAILURES:\n");
        for result in &report.results {
            if result.verdict == asupersync_conformance::RequestBuildingTestVerdict::Fail {
                output.push_str(&format!(
                    "  ❌ {}: {}\n",
                    result.case_id,
                    result.error.as_deref().unwrap_or("Unknown error")
                ));
                output.push_str(&format!(
                    "     Bytes match: {}, Asupersync: {} bytes, Hyper-util: {} bytes\n",
                    result.bytes_match, result.asupersync_size, result.reqwest_size
                ));
            }
        }
    }

    // Wire format analysis
    output.push_str("\nWIRE FORMAT ANALYSIS:\n");
    for result in &report.results {
        output.push_str(&format!(
            "  📊 {}: match={}, asupersync={} bytes, hyper-util={} bytes\n",
            result.case_id, result.bytes_match, result.asupersync_size, result.reqwest_size
        ));
    }

    output
}

/// Print colorized test summary to stderr
fn print_test_summary(report: &asupersync_conformance::RequestBuildingComplianceReport) {
    eprintln!("╭─ HTTP/1.1 REQUEST BUILDING CONFORMANCE RESULTS ─╮");
    eprintln!("│                                                  │");

    let has_failures = report.summary.failed > 0;
    let has_partial_coverage = has_incomplete_coverage(report);
    let status_line = final_status_line(
        report.summary.failed,
        report.summary.skipped,
        report.summary.expected_failures,
    );

    eprintln!("│  {:<46}│", status_line);

    if !has_failures && !has_partial_coverage {
        eprintln!(
            "│  🎯 Compliance: {:.1}%                            │",
            report.summary.compliance_score * 100.0
        );
    } else if has_failures && has_partial_coverage {
        eprintln!(
            "│  📊 Compliance: {:.1}%                           │",
            report.summary.compliance_score * 100.0
        );
    } else if has_failures {
        eprintln!(
            "│  📊 Compliance: {:.1}%                           │",
            report.summary.compliance_score * 100.0
        );
    } else {
        eprintln!(
            "│  📊 Coverage: {} expected failures, {} skipped    │",
            report.summary.expected_failures, report.summary.skipped
        );
    }

    eprintln!("│                                                  │");
    eprintln!(
        "│  📋 Total: {}                                    │",
        report.total_cases
    );
    eprintln!(
        "│  ✅ Passed: {}                                  │",
        report.summary.passed
    );
    eprintln!(
        "│  ❌ Failed: {}                                  │",
        report.summary.failed
    );
    eprintln!(
        "│  ⚠️  Expected: {}                                │",
        report.summary.expected_failures
    );
    eprintln!(
        "│  ⏭️  Skipped: {}                                 │",
        report.summary.skipped
    );
    eprintln!("│                                                  │");
    eprintln!("╰──────────────────────────────────────────────────╯");
}

fn has_incomplete_coverage(
    report: &asupersync_conformance::RequestBuildingComplianceReport,
) -> bool {
    report.total_cases == 0 || report.summary.expected_failures > 0 || report.summary.skipped > 0
}

fn exit_code(report: &asupersync_conformance::RequestBuildingComplianceReport) -> i32 {
    if report.summary.failed > 0 || has_incomplete_coverage(report) {
        1
    } else {
        0
    }
}

fn final_status_line(failed: usize, skipped: usize, expected_failures: usize) -> String {
    let has_partial_coverage = skipped > 0 || expected_failures > 0;

    if failed == 0 && !has_partial_coverage {
        "✅ ALL TESTS PASSED - FULL COVERAGE".to_string()
    } else if failed > 0 && has_partial_coverage {
        format!("❌ {failed} TESTS FAILED + PARTIAL COVERAGE")
    } else if failed > 0 {
        format!("❌ {failed} TESTS FAILED")
    } else {
        "⚠️  PARTIAL COVERAGE - NOT ALL TESTS RUN".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync_conformance::RequestBuildingComplianceSummary;

    fn synthetic_report(
        total_cases: usize,
        failed: usize,
        expected_failures: usize,
        skipped: usize,
    ) -> asupersync_conformance::RequestBuildingComplianceReport {
        asupersync_conformance::RequestBuildingComplianceReport {
            test_run_id: "synthetic".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            total_cases,
            results: Vec::new(),
            summary: RequestBuildingComplianceSummary {
                passed: total_cases
                    .saturating_sub(failed)
                    .saturating_sub(expected_failures)
                    .saturating_sub(skipped),
                failed,
                expected_failures,
                skipped,
                total: total_cases,
                compliance_score: 0.0,
            },
        }
    }

    #[test]
    fn exit_code_is_nonzero_for_expected_failures() {
        let report = synthetic_report(8, 0, 1, 0);

        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn exit_code_is_nonzero_for_skipped_coverage() {
        let report = synthetic_report(8, 0, 0, 1);

        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn exit_code_is_nonzero_for_zero_case_reports() {
        let report = synthetic_report(0, 0, 0, 0);

        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn exit_code_is_nonzero_for_failures() {
        let report = synthetic_report(8, 1, 0, 0);

        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn exit_code_is_zero_for_full_pass_coverage() {
        let report = synthetic_report(8, 0, 0, 0);

        assert_eq!(exit_code(&report), 0);
    }

    #[test]
    fn incomplete_coverage_is_true_for_zero_case_reports() {
        let report = synthetic_report(0, 0, 0, 0);

        assert!(has_incomplete_coverage(&report));
    }

    #[test]
    fn final_status_line_does_not_claim_full_coverage_for_partial_results() {
        let status = final_status_line(0, 1, 0);

        assert!(status.contains("PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }

    #[test]
    fn final_status_line_claims_full_coverage_only_for_full_green_results() {
        assert_eq!(
            final_status_line(0, 0, 0),
            "✅ ALL TESTS PASSED - FULL COVERAGE"
        );
    }
}
