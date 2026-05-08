//! CLI runner for H2 PING RTT measurement conformance testing
//!
//! This binary runs the PING timing harness in fail-closed mode until a live
//! h2 crate PING frame observation seam is wired.

use std::env;
use std::process;

use asupersync_conformance::h2_ping_rtt_measurement_conformance::*;

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
    let exit_code = if results.conformant_implementations {
        0
    } else {
        1
    };
    process::exit(exit_code);
}

fn print_help() {
    println!("H2 PING RTT Measurement Conformance Test");
    println!();
    println!("USAGE:");
    println!("    h2_ping_rtt_measurement_conformance [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --json       Output results in JSON format");
    println!("    --markdown   Output results in Markdown format");
    println!("    --summary    Output results in summary format (default)");
    println!("    --all        Run comprehensive test suite (default: basic tests)");
    println!("    --help, -h   Print this help message");
    println!();
    println!("DESCRIPTION:");
    println!("    This tool exercises the asupersync HTTP/2 PING RTT model.");
    println!("    The h2 crate reference side is currently unsupported and");
    println!("    fails closed instead of treating model-only timing as");
    println!("    conformance evidence. A zero exit code is only valid after");
    println!("    a real h2 PING frame observation seam is wired.");
    println!();
    println!("EXIT CODES:");
    println!("    0    Live h2 PING reference comparison passed");
    println!("    1    Fail-closed, unsupported reference, or behavior divergence detected");
}
