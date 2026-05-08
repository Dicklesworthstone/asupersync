//! CLI runner for H2 RST_STREAM error code propagation conformance testing
//!
//! This binary runs the RST_STREAM conformance harness. Until the h2 crate
//! reference adapter is wired, it exits non-zero instead of reporting mocked
//! differential success.

use std::env;
use std::process;

use conformance::h2_rst_stream_error_propagation_conformance::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut output_format = OutputFormat::Summary;
    let mut run_all = false;

    // Parse command line arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => output_format = OutputFormat::Json,
            "--markdown" => output_format = OutputFormat::Markdown,
            "--summary" => output_format = OutputFormat::Summary,
            "--all" => run_all = true,
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
    let results = if run_all {
        run_all_conformance_tests()
    } else {
        run_basic_conformance_tests()
    };

    // Output results
    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
        }
        OutputFormat::Markdown => {
            println!("{}", format_results_as_markdown(&results));
        }
        OutputFormat::Summary => {
            println!("{}", format_results_as_summary(&results));
        }
    }

    // Exit with appropriate code
    let exit_code = if results.overall_pass { 0 } else { 1 };
    process::exit(exit_code);
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
    println!("    --all        Run comprehensive test suite (default: basic tests)");
    println!("    --help, -h   Print this help message");
    println!();
    println!("DESCRIPTION:");
    println!("    This tool tests HTTP/2 RST_STREAM error code propagation compliance.");
    println!("    The h2 crate reference adapter is currently fail-closed until a live");
    println!("    h2 seam is wired; the harness must not report mocked differential");
    println!("    success as conformance evidence.");
    println!();
    println!("EXIT CODES:");
    println!("    0    All tests passed - implementations are conformant");
    println!("    1    One or more tests failed - behavior divergence detected");
}
