//! CLI runner for H2 SETTINGS_INITIAL_WINDOW_SIZE conformance testing
//!
//! This binary runs a fail-closed check until the harness drives both
//! asupersync H2 and a live h2 crate endpoint.

use std::env;
use std::process;

use asupersync_conformance::h2_initial_window_size_conformance::*;

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
            println!("{}", format_results_as_json(&results));
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
    println!("H2 SETTINGS_INITIAL_WINDOW_SIZE Fail-Closed Check");
    println!();
    println!("USAGE:");
    println!("    h2_initial_window_size_conformance [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --json       Output results in JSON format");
    println!("    --markdown   Output results in Markdown format");
    println!("    --summary    Output results in summary format (default)");
    println!("    --all        Run comprehensive test suite (default: basic tests)");
    println!("    --help, -h   Print this help message");
    println!();
    println!("DESCRIPTION:");
    println!("    This tool refuses to claim HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE");
    println!("    differential conformance until the harness drives a live h2 crate");
    println!("    endpoint and the asupersync H2 implementation for the same RFC");
    println!("    9113 §6.5.2 scenarios.");
    println!();
    println!("    Tests cover window size increases, decreases, mixed stream states,");
    println!("    boundary conditions, and data transfer scenarios to ensure");
    println!("    modeled flow-control behavior only; they are not a conformance pass.");
    println!();
    println!("EXIT CODES:");
    println!("    0    Live reference comparison passed");
    println!("    1    Fail-closed or behavior divergence detected");
}
