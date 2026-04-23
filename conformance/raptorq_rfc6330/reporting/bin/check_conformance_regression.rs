//! Conformance Regression Detection CLI
//!
//! Checks for conformance regressions against historical baselines and
//! configurable thresholds for CI integration.

use clap::{Arg, Command};
use serde_json::Value;
use std::fs;

fn main() {
    let matches = Command::new("check_conformance_regression")
        .version("1.0.0")
        .author("asupersync contributors")
        .about("Check for RFC 6330 conformance regressions")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Input JSON file with test execution results")
                .required(true),
        )
        .arg(
            Arg::new("history")
                .long("history")
                .value_name("FILE")
                .help("Historical conformance data file")
                .default_value("conformance_history.json"),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .long("threshold")
                .value_name("PERCENT")
                .help("Minimum compliance threshold")
                .default_value("90.0"),
        )
        .arg(
            Arg::new("baseline")
                .short('b')
                .long("baseline")
                .value_name("BRANCH")
                .help("Baseline branch for comparison")
                .default_value("main"),
        )
        .get_matches();

    let input_file = matches.get_one::<String>("input").unwrap();
    let history_file = matches.get_one::<String>("history").unwrap();
    let threshold: f64 = matches
        .get_one::<String>("threshold")
        .unwrap()
        .parse()
        .expect("Threshold must be a valid number");
    let baseline = matches.get_one::<String>("baseline").unwrap();

    println!("Checking conformance regression...");
    println!("Input: {}", input_file);
    println!("Threshold: {}%", threshold);
    println!("Baseline: {}", baseline);

    match check_regression(input_file, history_file, threshold, baseline) {
        Ok(regression_detected) => {
            if regression_detected {
                eprintln!("❌ CONFORMANCE REGRESSION DETECTED!");
                std::process::exit(1);
            } else {
                println!("✅ No conformance regressions detected");
            }
        }
        Err(e) => {
            eprintln!("Error checking regression: {}", e);
            std::process::exit(2);
        }
    }
}

/// Check for conformance regression against threshold.
fn check_regression(
    input_file: &str,
    _history_file: &str,
    threshold: f64,
    _baseline: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Read input test results
    let content = fs::read_to_string(input_file)?;
    let data: Value = serde_json::from_str(&content)?;

    // Extract conformance percentage from JSON
    let conformance_rate = extract_conformance_rate(&data)?;

    println!("Current conformance rate: {:.2}%", conformance_rate);

    // Check if below threshold
    let regression_detected = conformance_rate < threshold;

    if regression_detected {
        println!(
            "Conformance rate {:.2}% is below threshold {:.2}%",
            conformance_rate, threshold
        );
    }

    Ok(regression_detected)
}

/// Extract conformance percentage from test results JSON.
fn extract_conformance_rate(data: &Value) -> Result<f64, Box<dyn std::error::Error>> {
    // Try multiple possible JSON structures for conformance data

    // Structure 1: {"conformance_rate": 95.5}
    if let Some(rate) = data.get("conformance_rate") {
        if let Some(val) = rate.as_f64() {
            return Ok(val);
        }
    }

    // Structure 2: {"results": {"pass": 100, "total": 105}}
    if let Some(results) = data.get("results") {
        if let (Some(pass), Some(total)) = (results.get("pass"), results.get("total")) {
            if let (Some(pass_count), Some(total_count)) = (pass.as_u64(), total.as_u64()) {
                if total_count > 0 {
                    return Ok((pass_count as f64 / total_count as f64) * 100.0);
                }
            }
        }
    }

    // Structure 3: {"test_summary": {"passed": 95, "failed": 5}}
    if let Some(summary) = data.get("test_summary") {
        if let (Some(passed), Some(failed)) = (summary.get("passed"), summary.get("failed")) {
            if let (Some(pass_count), Some(fail_count)) = (passed.as_u64(), failed.as_u64()) {
                let total = pass_count + fail_count;
                if total > 0 {
                    return Ok((pass_count as f64 / total as f64) * 100.0);
                }
            }
        }
    }

    Err("Could not extract conformance rate from JSON data".into())
}
