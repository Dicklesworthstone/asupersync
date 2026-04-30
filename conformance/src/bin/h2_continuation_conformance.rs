//! HTTP/2 CONTINUATION Frame Conformance Test Runner
//!
//! Runs conformance testing for HTTP/2 CONTINUATION frame handling, specifically
//! testing that CONTINUATION frames must immediately follow HEADERS/PUSH_PROMISE
//! frames without any intervening frames.
//!
//! Usage:
//!   cargo run --bin h2_continuation_conformance
//!   cargo run --bin h2_continuation_conformance -- --format json
//!   cargo run --bin h2_continuation_conformance -- --output report.md

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "h2_continuation_conformance")]
#[command(about = "HTTP/2 CONTINUATION frame conformance tester")]
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

    println!("🔧 HTTP/2 CONTINUATION Frame Conformance Tester");
    println!("   Testing frame ordering requirements per RFC 9113");
    println!("   Focus: CONTINUATION frames must follow HEADERS without intervening frames");
    println!();

    // Create and configure the tester
    let mut tester = asupersync_conformance::ContinuationConformanceTester::new();

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
    let exit_code = if report.summary.failed > 0 { 1 } else { 0 };
    std::process::exit(exit_code);
}

/// Generate a concise summary output
fn generate_summary_output(
    report: &asupersync_conformance::ContinuationComplianceReport,
) -> String {
    let mut output = String::new();

    output.push_str("HTTP/2 CONTINUATION FRAME CONFORMANCE SUMMARY\n");
    output.push_str("==========================================\n\n");

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
            if result.verdict == asupersync_conformance::ContinuationTestVerdict::Fail {
                output.push_str(&format!(
                    "  ❌ {}: {}\n",
                    result.case_id,
                    result.error.as_deref().unwrap_or("Unknown error")
                ));
                output.push_str(&format!(
                    "     Error codes match: {}\n",
                    result.error_codes_match
                ));
            }
        }
    }

    // Frame sequence analysis
    output.push_str("\nFRAME SEQUENCE ANALYSIS:\n");
    for result in &report.results {
        output.push_str(&format!(
            "  📊 {}: {} frames processed, accepted={}\n",
            result.case_id,
            result.asupersync_result.frames_processed,
            result.asupersync_result.accepted
        ));
        if let Some(error_code) = &result.asupersync_result.error_code {
            output.push_str(&format!("      Error: {}\n", error_code));
        }
    }

    output
}

/// Print colorized test summary to stderr
fn print_test_summary(report: &asupersync_conformance::ContinuationComplianceReport) {
    eprintln!("╭─ HTTP/2 CONTINUATION CONFORMANCE RESULTS ─╮");
    eprintln!("│                                            │");

    if report.summary.failed == 0 {
        eprintln!("│  ✅ ALL TESTS PASSED                       │");
        eprintln!(
            "│  🎯 Compliance: {:.1}%                       │",
            report.summary.compliance_score * 100.0
        );
    } else {
        eprintln!(
            "│  ❌ {} TESTS FAILED                        │",
            report.summary.failed
        );
        eprintln!(
            "│  📊 Compliance: {:.1}%                      │",
            report.summary.compliance_score * 100.0
        );
    }

    eprintln!("│                                            │");
    eprintln!(
        "│  📋 Total: {}                              │",
        report.total_cases
    );
    eprintln!(
        "│  ✅ Passed: {}                            │",
        report.summary.passed
    );
    eprintln!(
        "│  ❌ Failed: {}                            │",
        report.summary.failed
    );
    eprintln!(
        "│  ⚠️  Expected: {}                          │",
        report.summary.expected_failures
    );
    eprintln!(
        "│  ⏭️  Skipped: {}                           │",
        report.summary.skipped
    );
    eprintln!("│                                            │");
    eprintln!("╰────────────────────────────────────────────╯");
}
