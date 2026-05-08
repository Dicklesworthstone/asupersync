//! CLI runner for H2 RST_STREAM error code propagation conformance testing
//!
//! This binary runs the RST_STREAM conformance harness. Until the h2 crate
//! reference adapter is wired, it exits non-zero instead of reporting mocked
//! differential success.

use std::env;
use std::process;

use asupersync_conformance::h2_rst_stream_error_propagation_conformance::{
    ConformanceReport, ConformanceStatus, RstStreamConformanceTester,
};

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Json,
    Markdown,
    Summary,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut output_format = OutputFormat::Summary;
    let mut verbose = false;

    // Parse command line arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => output_format = OutputFormat::Json,
            "--markdown" => output_format = OutputFormat::Markdown,
            "--summary" => output_format = OutputFormat::Summary,
            "--all" => {}
            "--verbose" | "-v" => verbose = true,
            "--help" | "-h" => {
                print_help();
                return;
            }
            arg if arg.starts_with("--") => {
                eprintln!("Unknown option: {}", arg);
                process::exit(1);
            }
            _ => {
                eprintln!("Unexpected argument: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    // Run the conformance tests
    let mut tester = RstStreamConformanceTester::new();
    if verbose {
        tester = tester.with_verbose();
    }
    let report = tester.run_all_tests();

    // Output results
    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Markdown => {
            println!("{}", format_report_as_markdown(&report));
        }
        OutputFormat::Summary => {
            println!("{}", report);
        }
    }

    // Exit with appropriate code
    let exit_code = if report.failed == 0 && report.skipped == 0 {
        0
    } else {
        1
    };
    process::exit(exit_code);
}

fn format_report_as_markdown(report: &ConformanceReport) -> String {
    let mut output = String::new();
    output.push_str("# HTTP/2 RST_STREAM Fail-Closed Report\n\n");
    output.push_str("## Summary\n\n");
    output.push_str(&format!("- **Total tests:** {}\n", report.total_tests));
    output.push_str(&format!("- **Passed:** {}\n", report.passed));
    output.push_str(&format!("- **Failed:** {}\n", report.failed));
    output.push_str(&format!("- **Skipped:** {}\n\n", report.skipped));

    if report.failed == 0 && report.skipped == 0 {
        output.push_str("## Live H2 Reference Passed\n\n");
        output.push_str(
            "RST_STREAM behavior matched observed h2 output for every checked scenario.\n",
        );
    } else {
        output.push_str("## Fail-Closed Results\n\n");
        for result in &report.results {
            if result.conformance_status == ConformanceStatus::Fail {
                output.push_str(&format!("### {}\n\n", result.test_name));
                if let Some(details) = &result.error_details {
                    output.push_str(&format!("**Error:** {}\n\n", details));
                }
                output.push_str(&format!(
                    "**asupersync result:** {:?}\n\n",
                    result.asupersync_result
                ));
                output.push_str(&format!("**h2 result:** {:?}\n\n", result.h2_result));
            }
        }
    }

    output
}

fn print_help() {
    println!("H2 RST_STREAM Error Code Propagation Conformance Test");
    println!();
    println!("USAGE:");
    println!("    h2_rst_stream_error_propagation_conformance [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --json       Output results in JSON format");
    println!("    --markdown   Output results in Markdown format");
    println!("    --summary    Output results in summary format (default)");
    println!("    --all        Accepted for compatibility; runs the generated suite");
    println!("    --verbose    Include per-case progress");
    println!("    --help, -h   Print this help message");
    println!();
    println!("DESCRIPTION:");
    println!("    This tool tests HTTP/2 RST_STREAM error code propagation compliance.");
    println!("    The h2 crate reference adapter is currently fail-closed until a live");
    println!("    h2 seam is wired; the harness must not report mocked differential");
    println!("    success as conformance evidence.");
    println!();
    println!("EXIT CODES:");
    println!("    0    Live h2 reference comparison passed");
    println!("    1    Fail-closed, unsupported reference, or behavior divergence detected");
}
