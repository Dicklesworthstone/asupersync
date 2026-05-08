//! HTTP/2 PING Frame Conformance Test Runner
//!
//! Runs HTTP/2 PING frame checks against RFC expected states while the h2
//! reference path remains an explicit XFAIL.
//!
//! Usage:
//!   rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_conformance_bin_docs cargo run --bin h2_ping_conformance
//!   rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_conformance_bin_docs cargo run --bin h2_ping_conformance -- --format json
//!   rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_conformance_bin_docs cargo run --bin h2_ping_conformance -- --output report.md

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[cfg(test)]
use asupersync_conformance::PingComplianceSummary;
use asupersync_conformance::{PingComplianceReport, PingTestVerdict};

#[derive(Parser)]
#[command(name = "h2_ping_conformance")]
#[command(about = "HTTP/2 PING frame conformance tester")]
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

fn reference_scope_line() -> &'static str {
    "Testing asupersync against RFC expected states; h2 reference is XFAIL"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    }

    println!("🔧 HTTP/2 PING Frame Conformance Tester");
    println!("   {}", reference_scope_line());
    println!("   Focus: RTT computation accuracy, connection stability");
    println!();

    // Create and configure the tester
    let mut tester = asupersync_conformance::PingConformanceTester::new();

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

    // Exit with appropriate code
    std::process::exit(exit_code(&report));
}

/// Generate a concise summary output
fn generate_summary_output(report: &PingComplianceReport) -> String {
    let mut output = String::new();

    output.push_str("HTTP/2 PING FRAME CONFORMANCE SUMMARY\n");
    output.push_str("====================================\n\n");

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
            if result.verdict == PingTestVerdict::Fail {
                output.push_str(&format!(
                    "  ❌ {}: {}\n",
                    result.case_id,
                    result.error.as_deref().unwrap_or("Unknown error")
                ));
                if !result.differences.is_empty() {
                    output.push_str("     Differences:\n");
                    for diff in &result.differences {
                        output.push_str(&format!("     - {}\n", diff));
                    }
                }
            }
        }
    }

    // Summary of RTT behavior
    output.push_str("\nRTT BEHAVIOR:\n");
    for result in &report.results {
        if let Some(state) = &result.asupersync_state {
            if !state.ping_timings.is_empty() {
                output.push_str(&format!(
                    "  📊 {}: {} RTT measurements\n",
                    result.case_id,
                    state.ping_timings.len()
                ));
                for (i, timing) in state.ping_timings.iter().enumerate() {
                    if let Some(rtt) = timing.rtt_ms {
                        output.push_str(&format!("      RTT[{}]: {}ms\n", i, rtt));
                    } else {
                        output.push_str(&format!("      RTT[{}]: pending\n", i));
                    }
                }
            }
        }
    }

    output
}

/// Print colorized test summary to stderr
fn print_test_summary(report: &PingComplianceReport) {
    eprintln!("╭─ HTTP/2 PING CONFORMANCE RESULTS ─╮");
    eprintln!("│                                    │");

    if report.summary.failed == 0 {
        eprintln!(
            "│  {}  │",
            final_status_line(report.summary.skipped, report.summary.expected_failures)
        );
        eprintln!(
            "│  🎯 Compliance: {:.1}%              │",
            report.summary.compliance_score * 100.0
        );
    } else {
        eprintln!(
            "│  ❌ {} TESTS FAILED                │",
            report.summary.failed
        );
        eprintln!(
            "│  📊 Compliance: {:.1}%              │",
            report.summary.compliance_score * 100.0
        );
    }

    eprintln!("│                                    │");
    eprintln!("│  📋 Total: {}                     │", report.total_cases);
    eprintln!(
        "│  ✅ Passed: {}                    │",
        report.summary.passed
    );
    eprintln!(
        "│  ❌ Failed: {}                    │",
        report.summary.failed
    );
    eprintln!(
        "│  ⚠️  Expected: {}                  │",
        report.summary.expected_failures
    );
    eprintln!(
        "│  ⏭️  Skipped: {}                   │",
        report.summary.skipped
    );
    eprintln!("│                                    │");
    eprintln!("╰────────────────────────────────────╯");
}

fn final_status_line(skipped_count: usize, expected_failure_count: usize) -> String {
    if skipped_count == 0 && expected_failure_count == 0 {
        "✅ ALL TESTS PASSED".to_string()
    } else {
        format!(
            "⚠️  NO FAILURES; PARTIAL COVERAGE ({skipped_count} skipped, {expected_failure_count} expected failures)"
        )
    }
}

fn has_incomplete_coverage(report: &PingComplianceReport) -> bool {
    report.total_cases == 0 || report.summary.skipped > 0 || report.summary.expected_failures > 0
}

fn exit_code(report: &PingComplianceReport) -> i32 {
    if report.summary.failed > 0 || has_incomplete_coverage(report) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_report(
        total_cases: usize,
        failed: usize,
        expected_failures: usize,
        skipped: usize,
    ) -> PingComplianceReport {
        PingComplianceReport {
            test_run_id: "synthetic".to_string(),
            timestamp: chrono::Utc::now(),
            total_cases,
            results: Vec::new(),
            summary: PingComplianceSummary {
                total_cases,
                passed: total_cases
                    .saturating_sub(failed)
                    .saturating_sub(expected_failures)
                    .saturating_sub(skipped),
                failed,
                expected_failures,
                skipped,
                compliance_score: 0.0,
            },
        }
    }

    #[test]
    fn final_status_does_not_claim_all_passed_for_partial_coverage() {
        let status = final_status_line(1, 0);

        assert!(status.contains("NO FAILURES; PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }

    #[test]
    fn final_status_claims_all_passed_only_for_full_green_results() {
        assert_eq!(final_status_line(0, 0), "✅ ALL TESTS PASSED");
    }

    #[test]
    fn reference_scope_line_does_not_claim_live_h2_parity() {
        let line = reference_scope_line();

        assert!(line.contains("RFC expected states"));
        assert!(line.contains("XFAIL"));
        assert!(!line.contains("h2 reference implementation"));
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
    fn exit_code_is_zero_for_full_pass_coverage() {
        let report = synthetic_report(8, 0, 0, 0);

        assert_eq!(exit_code(&report), 0);
    }
}
