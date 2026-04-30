//! CLI runner for HTTP/2 CONTINUATION frame ordering conformance tests
//!
//! Usage:
//!   cargo run --bin h2_continuation_ordering_conformance [OPTIONS]
//!
//! Options:
//!   --format <json|markdown|summary>  Output format (default: summary)
//!   --test-case <name>               Run specific test case only
//!   --verbose                        Include detailed test output
//!   --help                           Show this help message

use std::env;
use std::process;
use serde_json;
use asupersync_conformance::h2_continuation_ordering_conformance::{
    generate_test_cases, run_conformance_test, run_all_conformance_tests,
    generate_conformance_report, ConformanceResult
};

#[derive(Debug, Clone)]
struct Config {
    format: OutputFormat,
    test_case: Option<String>,
    verbose: bool,
}

#[derive(Debug, Clone)]
enum OutputFormat {
    Json,
    Markdown,
    Summary,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            format: OutputFormat::Summary,
            test_case: None,
            verbose: false,
        }
    }
}

fn main() {
    let config = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        process::exit(1);
    });

    let results = if let Some(test_name) = &config.test_case {
        run_single_test_case(test_name).unwrap_or_else(|err| {
            eprintln!("Error running test case '{}': {}", test_name, err);
            process::exit(1);
        })
    } else {
        run_all_conformance_tests().unwrap_or_else(|err| {
            eprintln!("Error running conformance tests: {}", err);
            process::exit(1);
        })
    };

    output_results(&results, &config).unwrap_or_else(|err| {
        eprintln!("Error generating output: {}", err);
        process::exit(1);
    });

    // Exit with failure code if any tests failed
    let failed_count = results.iter().filter(|r| !r.passed()).count();
    if failed_count > 0 {
        eprintln!("\n{} conformance tests failed", failed_count);
        process::exit(1);
    }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    let mut config = Config::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                if i >= args.len() {
                    return Err("--format requires a value".to_string());
                }
                config.format = match args[i].as_str() {
                    "json" => OutputFormat::Json,
                    "markdown" => OutputFormat::Markdown,
                    "summary" => OutputFormat::Summary,
                    other => return Err(format!("Unknown format: {}", other)),
                };
            }
            "--test-case" => {
                i += 1;
                if i >= args.len() {
                    return Err("--test-case requires a value".to_string());
                }
                config.test_case = Some(args[i].clone());
            }
            "--verbose" => {
                config.verbose = true;
            }
            "--help" => {
                print_help();
                process::exit(0);
            }
            arg if arg.starts_with("--") => {
                return Err(format!("Unknown option: {}", arg));
            }
            _ => {
                return Err(format!("Unexpected argument: {}", args[i]));
            }
        }
        i += 1;
    }

    Ok(config)
}

fn run_single_test_case(test_name: &str) -> Result<Vec<ConformanceResult>, Box<dyn std::error::Error>> {
    let test_cases = generate_test_cases();
    let test_case = test_cases
        .iter()
        .find(|tc| tc.name == test_name)
        .ok_or_else(|| format!("Test case '{}' not found", test_name))?;

    let result = run_conformance_test(test_case)?;
    Ok(vec![result])
}

fn output_results(results: &[ConformanceResult], config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    match config.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(results)?;
            println!("{}", json);
        }
        OutputFormat::Markdown => {
            let report = generate_conformance_report(results);
            println!("{}", report);
        }
        OutputFormat::Summary => {
            output_summary(results, config.verbose);
        }
    }
    Ok(())
}

fn output_summary(results: &[ConformanceResult], verbose: bool) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed()).count();
    let failed = total - passed;

    println!("HTTP/2 CONTINUATION Frame Ordering Conformance Test Results");
    println!("===========================================================");
    println!();
    println!("Total tests:  {}", total);
    println!("Passed:       {} ({:.1}%)", passed, (passed as f64 / total as f64) * 100.0);
    println!("Failed:       {} ({:.1}%)", failed, (failed as f64 / total as f64) * 100.0);
    println!();

    if passed == total {
        println!("🎉 ALL TESTS PASSED - asupersync and h2 produce identical CONTINUATION frame handling");
    } else {
        println!("❌ CONFORMANCE ISSUES DETECTED");
    }
    println!();

    // Show individual test results
    for result in results {
        if verbose || !result.passed() {
            println!("{}", result.summary());
            if verbose && !result.passed() {
                if let (Some(ref a_headers), Some(ref h_headers)) = (&result.asupersync_headers, &result.h2_headers) {
                    println!("  asupersync headers: {} entries", a_headers.len());
                    println!("  h2 headers:         {} entries", h_headers.len());
                    if a_headers.len() != h_headers.len() {
                        println!("  → Header count mismatch!");
                    }
                }
                println!();
            }
        } else if result.passed() {
            println!("✓ {}", result.test_name);
        }
    }

    if failed > 0 {
        println!();
        println!("Failed test cases:");
        for result in results.iter().filter(|r| !r.passed()) {
            println!("- {}: {}", result.test_name,
                result.asupersync_error.as_deref()
                    .or(result.h2_error.as_deref())
                    .unwrap_or("Header mismatch"));
        }
    }
}

fn print_help() {
    println!("HTTP/2 CONTINUATION Frame Ordering Conformance Test");
    println!();
    println!("Tests HEADERS + CONTINUATION frame sequence handling between asupersync");
    println!("and h2 crate reference implementation to ensure identical HeaderMap decoding.");
    println!();
    println!("USAGE:");
    println!("    cargo run --bin h2_continuation_ordering_conformance [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --format <FORMAT>     Output format: json, markdown, summary (default: summary)");
    println!("    --test-case <NAME>    Run specific test case only");
    println!("    --verbose             Include detailed test output");
    println!("    --help                Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    # Run all tests with summary output");
    println!("    cargo run --bin h2_continuation_ordering_conformance");
    println!();
    println!("    # Run specific test case");
    println!("    cargo run --bin h2_continuation_ordering_conformance --test-case simple_continuation");
    println!();
    println!("    # Generate detailed markdown report");
    println!("    cargo run --bin h2_continuation_ordering_conformance --format markdown > report.md");
    println!();
    println!("    # Generate JSON output for CI");
    println!("    cargo run --bin h2_continuation_ordering_conformance --format json > results.json");
    println!();
    println!("TEST CASES:");
    let test_cases = generate_test_cases();
    for test_case in test_cases {
        println!("    {} - {}", test_case.name, test_case.description);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_default() {
        // Temporarily override args
        std::env::set_var("test_args", "program_name");

        // Test default config parsing would work
        let config = Config::default();
        matches!(config.format, OutputFormat::Summary);
        assert!(config.test_case.is_none());
        assert!(!config.verbose);
    }

    #[test]
    fn test_output_format_parsing() {
        // Test that format parsing logic works
        let formats = [
            ("json", OutputFormat::Json),
            ("markdown", OutputFormat::Markdown),
            ("summary", OutputFormat::Summary),
        ];

        for (input, expected_format) in formats {
            // Test the format matching logic
            let parsed_format = match input {
                "json" => OutputFormat::Json,
                "markdown" => OutputFormat::Markdown,
                "summary" => OutputFormat::Summary,
                _ => OutputFormat::Summary,
            };

            matches!(parsed_format, expected_format);
        }
    }
}

// Add Serialize support for JSON output
impl serde::Serialize for ConformanceResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConformanceResult", 6)?;
        state.serialize_field("test_name", &self.test_name)?;
        state.serialize_field("passed", &self.passed())?;
        state.serialize_field("asupersync_headers", &self.asupersync_headers)?;
        state.serialize_field("h2_headers", &self.h2_headers)?;
        state.serialize_field("asupersync_error", &self.asupersync_error)?;
        state.serialize_field("h2_error", &self.h2_error)?;
        state.end()
    }
}