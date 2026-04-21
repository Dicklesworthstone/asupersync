#![allow(clippy::all)]
//! Check Conformance Regression Binary
//!
//! CLI tool for detecting regressions in RaptorQ RFC 6330 conformance tests
//! by comparing current results against historical baselines.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use raptorq_conformance_reporting::{
    coverage_matrix::CoverageMatrixCalculator,
    regression_detection::{RegressionConfig, RegressionDetector, RegressionSeverity},
};
use std::path::PathBuf;

#[allow(dead_code)]

fn main() -> Result<()> {
    let app = Command::new("check_conformance_regression")
        .about("Check for RaptorQ RFC 6330 conformance regressions")
        .version("1.0.0")
        .arg(
            Arg::new("golden-dir")
                .short('g')
                .long("golden-dir")
                .value_name("DIR")
                .help("Path to golden files directory")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("baseline-dir")
                .short('b')
                .long("baseline-dir")
                .value_name("DIR")
                .help("Directory containing baseline snapshots")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for regression report (JSON format)")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("max-score-drop")
                .long("max-score-drop")
                .value_name("THRESHOLD")
                .help("Maximum allowed conformance score drop (0.0-1.0)")
                .default_value("0.05")
                .value_parser(clap::value_parser!(f64)),
        )
        .arg(
            Arg::new("min-score")
                .long("min-score")
                .value_name("THRESHOLD")
                .help("Minimum required conformance score (0.0-1.0)")
                .default_value("0.95")
                .value_parser(clap::value_parser!(f64)),
        )
        .arg(
            Arg::new("baseline-window")
                .long("baseline-window")
                .value_name("COUNT")
                .help("Number of historical snapshots to use for baseline")
                .default_value("10")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("Strict mode: fail on any test failures")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("commit-hash")
                .long("commit-hash")
                .value_name("HASH")
                .help("Git commit hash for this check"),
        )
        .arg(
            Arg::new("save-snapshot")
                .long("save-snapshot")
                .value_name("FILE")
                .help("Save current state as a baseline snapshot")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["json", "text", "summary"])
                .default_value("text"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        );

    let matches = app.get_matches();

    let golden_dir = matches.get_one::<PathBuf>("golden-dir").unwrap();
    let baseline_dir = matches.get_one::<PathBuf>("baseline-dir").unwrap();
    let output_file = matches.get_one::<PathBuf>("output");
    let max_score_drop = *matches.get_one::<f64>("max-score-drop").unwrap();
    let min_score = *matches.get_one::<f64>("min-score").unwrap();
    let baseline_window = *matches.get_one::<usize>("baseline-window").unwrap();
    let strict_mode = matches.get_flag("strict");
    let commit_hash = matches.get_one::<String>("commit-hash");
    let save_snapshot = matches.get_one::<PathBuf>("save-snapshot");
    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");

    // Validate thresholds
    if max_score_drop < 0.0 || max_score_drop > 1.0 {
        anyhow::bail!(
            "max-score-drop must be between 0.0 and 1.0, got {}",
            max_score_drop
        );
    }
    if min_score < 0.0 || min_score > 1.0 {
        anyhow::bail!("min-score must be between 0.0 and 1.0, got {}", min_score);
    }

    if verbose {
        println!("🔍 Checking for conformance regressions...");
        println!("  Golden directory: {}", golden_dir.display());
        println!("  Baseline directory: {}", baseline_dir.display());
        println!("  Max score drop: {:.1}%", max_score_drop * 100.0);
        println!("  Min score required: {:.1}%", min_score * 100.0);
        println!("  Baseline window: {} snapshots", baseline_window);
        println!("  Strict mode: {}", strict_mode);
    }

    // Calculate current coverage matrix
    if verbose {
        println!("📊 Calculating current conformance coverage...");
    }

    let calculator = CoverageMatrixCalculator::new();
    let coverage_matrix = calculator
        .calculate_coverage(golden_dir)
        .context("Failed to calculate coverage matrix")?;

    if verbose {
        println!("  Total tests: {}", coverage_matrix.total_tests);
        println!("  Passed tests: {}", coverage_matrix.passed_tests);
        println!("  Failed tests: {}", coverage_matrix.failed_tests);
        println!(
            "  Current score: {:.1}%",
            coverage_matrix.overall_conformance_score * 100.0
        );
    }

    // Configure regression detection
    let mut regression_config = RegressionConfig {
        min_conformance_score: min_score,
        max_score_drop,
        baseline_window,
        strict_mode,
        historical_data_paths: vec![],
    };

    // Find historical snapshots in the baseline directory
    if baseline_dir.exists() {
        let entries = std::fs::read_dir(baseline_dir).with_context(|| {
            format!(
                "Failed to read baseline directory: {}",
                baseline_dir.display()
            )
        })?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                regression_config.historical_data_paths.push(path);
            }
        }

        if verbose {
            println!(
                "📁 Found {} baseline snapshot(s)",
                regression_config.historical_data_paths.len()
            );
        }
    } else {
        if verbose {
            println!(
                "⚠️  Baseline directory does not exist: {}",
                baseline_dir.display()
            );
        }
    }

    // Perform regression detection
    if verbose {
        println!("🔍 Performing regression analysis...");
    }

    let detector = RegressionDetector::new(regression_config);
    let regression_analysis = detector
        .detect_regressions(&coverage_matrix, golden_dir)
        .context("Failed to perform regression analysis")?;

    // Save current snapshot if requested
    if let Some(snapshot_path) = save_snapshot {
        if verbose {
            println!("💾 Saving current snapshot: {}", snapshot_path.display());
        }

        // Ensure the parent directory exists
        if let Some(parent) = snapshot_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        detector
            .store_snapshot(&coverage_matrix, commit_hash.cloned(), snapshot_path)
            .context("Failed to save snapshot")?;

        if verbose {
            println!("✅ Snapshot saved");
        }
    }

    // Generate output based on format
    match format.as_str() {
        "json" => print_json_output(&regression_analysis, output_file, verbose)?,
        "text" => print_text_output(&regression_analysis, output_file, verbose)?,
        "summary" => print_summary_output(&regression_analysis, verbose)?,
        _ => anyhow::bail!(
            "Invalid format: {}. Valid options: json, text, summary",
            format
        ),
    }

    // Determine exit code based on results
    let exit_code = calculate_exit_code(
        &regression_analysis,
        &coverage_matrix,
        min_score,
        strict_mode,
    );

    if verbose && exit_code != 0 {
        println!(
            "\n🚨 Exiting with code {} due to conformance issues",
            exit_code
        );
    }

    std::process::exit(exit_code);
}

#[allow(dead_code)]

fn print_json_output(
    analysis: &raptorq_conformance_reporting::regression_detection::RegressionAnalysis,
    output_file: Option<&PathBuf>,
    verbose: bool,
) -> Result<()> {
    let json_output = serde_json::to_string_pretty(analysis)
        .context("Failed to serialize regression analysis")?;

    if let Some(file_path) = output_file {
        std::fs::write(file_path, &json_output)
            .with_context(|| format!("Failed to write output to {}", file_path.display()))?;

        if verbose {
            println!("📄 JSON report written to: {}", file_path.display());
        }
    } else {
        println!("{}", json_output);
    }

    Ok(())
}

#[allow(dead_code)]

fn print_text_output(
    analysis: &raptorq_conformance_reporting::regression_detection::RegressionAnalysis,
    output_file: Option<&PathBuf>,
    verbose: bool,
) -> Result<()> {
    let mut output = String::new();

    output.push_str("# RaptorQ Conformance Regression Analysis\n\n");

    // Overall status
    let status_emoji = if analysis.has_regressions {
        "❌"
    } else {
        "✅"
    };
    output.push_str(&format!(
        "{} **Overall Status:** {}\n\n",
        status_emoji,
        if analysis.has_regressions {
            "REGRESSIONS DETECTED"
        } else {
            "NO REGRESSIONS"
        }
    ));

    // Scores
    output.push_str("## Conformance Scores\n\n");
    output.push_str(&format!(
        "- **Current Score:** {:.1}%\n",
        analysis.current_score * 100.0
    ));
    output.push_str(&format!(
        "- **Baseline Score:** {:.1}%\n",
        analysis.baseline_score * 100.0
    ));

    let change_emoji = if analysis.score_change >= 0.0 {
        "📈"
    } else {
        "📉"
    };
    output.push_str(&format!(
        "- **Score Change:** {} {:.1}%\n\n",
        change_emoji,
        analysis.score_change * 100.0
    ));

    // Summary
    if analysis.summary.total_regressions > 0 {
        output.push_str("## Regression Summary\n\n");
        output.push_str(&format!(
            "- **Total Regressions:** {}\n",
            analysis.summary.total_regressions
        ));

        // By severity
        if !analysis.summary.by_severity.is_empty() {
            output.push_str("- **By Severity:**\n");
            let severities = [
                RegressionSeverity::Critical,
                RegressionSeverity::High,
                RegressionSeverity::Medium,
                RegressionSeverity::Low,
            ];

            for severity in &severities {
                if let Some(&count) = analysis.summary.by_severity.get(severity) {
                    if count > 0 {
                        let emoji = match severity {
                            RegressionSeverity::Critical => "🚨",
                            RegressionSeverity::High => "⚠️",
                            RegressionSeverity::Medium => "⚡",
                            RegressionSeverity::Low => "ℹ️",
                        };
                        output.push_str(&format!("  - {} {:?}: {}\n", emoji, severity, count));
                    }
                }
            }
        }

        output.push_str(&format!("- **Trend:** {:?}\n\n", analysis.summary.trend));

        // Detailed findings
        output.push_str("## Detailed Findings\n\n");
        for (i, regression) in analysis.regressions.iter().enumerate() {
            let severity_emoji = match regression.severity {
                RegressionSeverity::Critical => "🚨",
                RegressionSeverity::High => "⚠️",
                RegressionSeverity::Medium => "⚡",
                RegressionSeverity::Low => "ℹ️",
            };

            output.push_str(&format!(
                "### {} Finding #{} - {:?} {:?}\n\n",
                severity_emoji,
                i + 1,
                regression.severity,
                regression.regression_type
            ));
            output.push_str(&format!("**Description:** {}\n\n", regression.description));
            output.push_str(&format!(
                "**Affected Section:** {}\n\n",
                regression.affected_section
            ));
            output.push_str(&format!(
                "**Previous Value:** {}\n\n",
                regression.previous_value
            ));
            output.push_str(&format!(
                "**Current Value:** {}\n\n",
                regression.current_value
            ));

            if !regression.remediation_suggestions.is_empty() {
                output.push_str("**Remediation Suggestions:**\n\n");
                for suggestion in &regression.remediation_suggestions {
                    output.push_str(&format!("- {}\n", suggestion));
                }
                output.push_str("\n");
            }
        }
    } else {
        output.push_str("## ✅ No Regressions Detected\n\n");
        output.push_str("All conformance tests are performing at or above baseline levels.\n\n");
    }

    if let Some(file_path) = output_file {
        std::fs::write(file_path, &output)
            .with_context(|| format!("Failed to write output to {}", file_path.display()))?;

        if verbose {
            println!("📄 Text report written to: {}", file_path.display());
        }
    } else {
        print!("{}", output);
    }

    Ok(())
}

#[allow(dead_code)]

fn print_summary_output(
    analysis: &raptorq_conformance_reporting::regression_detection::RegressionAnalysis,
    _verbose: bool,
) -> Result<()> {
    // Compact summary for CI/automated use
    let status = if analysis.has_regressions {
        "FAIL"
    } else {
        "PASS"
    };
    let emoji = if analysis.has_regressions {
        "❌"
    } else {
        "✅"
    };

    println!("{} STATUS: {}", emoji, status);
    println!(
        "SCORE: {:.1}% (change: {:+.1}%)",
        analysis.current_score * 100.0,
        analysis.score_change * 100.0
    );

    if analysis.has_regressions {
        println!("REGRESSIONS: {}", analysis.summary.total_regressions);

        // Show critical and high severity counts
        let critical = analysis
            .summary
            .by_severity
            .get(&RegressionSeverity::Critical)
            .unwrap_or(&0);
        let high = analysis
            .summary
            .by_severity
            .get(&RegressionSeverity::High)
            .unwrap_or(&0);

        if *critical > 0 {
            println!("CRITICAL: {}", critical);
        }
        if *high > 0 {
            println!("HIGH: {}", high);
        }
    }

    Ok(())
}

#[allow(dead_code)]

fn calculate_exit_code(
    analysis: &raptorq_conformance_reporting::regression_detection::RegressionAnalysis,
    coverage_matrix: &raptorq_conformance_reporting::coverage_matrix::CoverageMatrix,
    min_score: f64,
    strict_mode: bool,
) -> i32 {
    // Exit code priority:
    // 3: Critical regressions
    // 2: High severity regressions or below minimum score
    // 1: Any regressions (in strict mode) or medium/low regressions
    // 0: No issues

    if analysis.has_regressions {
        let critical_count = analysis
            .summary
            .by_severity
            .get(&RegressionSeverity::Critical)
            .unwrap_or(&0);
        let high_count = analysis
            .summary
            .by_severity
            .get(&RegressionSeverity::High)
            .unwrap_or(&0);

        if *critical_count > 0 {
            return 3;
        }

        if *high_count > 0 || coverage_matrix.overall_conformance_score < min_score {
            return 2;
        }

        if strict_mode || analysis.summary.total_regressions > 0 {
            return 1;
        }
    }

    // Check minimum score even without regressions
    if coverage_matrix.overall_conformance_score < min_score {
        return 2;
    }

    // Check for any test failures in strict mode
    if strict_mode && coverage_matrix.failed_tests > 0 {
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use raptorq_conformance_reporting::coverage_matrix::CoverageMatrix;
    use raptorq_conformance_reporting::regression_detection::{
        RegressionAnalysis, RegressionSummary,
    };
    use std::collections::HashMap;

    #[test]
    #[allow(dead_code)]
    fn test_exit_code_calculation() {
        let mut coverage_matrix = CoverageMatrix::default();
        coverage_matrix.overall_conformance_score = 0.98;
        coverage_matrix.failed_tests = 0;

        // No regressions, good score
        let analysis = RegressionAnalysis {
            has_regressions: false,
            current_score: 0.98,
            baseline_score: 0.97,
            score_change: 0.01,
            regressions: vec![],
            summary: RegressionSummary {
                total_regressions: 0,
                by_severity: HashMap::new(),
                by_type: HashMap::new(),
                trend:
                    raptorq_conformance_reporting::regression_detection::ConformanceTrend::Stable,
            },
        };

        let exit_code = calculate_exit_code(&analysis, &coverage_matrix, 0.95, false);
        assert_eq!(exit_code, 0);

        // Low score, no regressions
        coverage_matrix.overall_conformance_score = 0.90;
        let exit_code = calculate_exit_code(&analysis, &coverage_matrix, 0.95, false);
        assert_eq!(exit_code, 2);

        // Test failures in strict mode
        coverage_matrix.overall_conformance_score = 0.98;
        coverage_matrix.failed_tests = 1;
        let exit_code = calculate_exit_code(&analysis, &coverage_matrix, 0.95, true);
        assert_eq!(exit_code, 1);
    }

    #[test]
    #[allow(dead_code)]
    fn test_cli_parsing() {
        let app = Command::new("check_conformance_regression")
            .arg(
                Arg::new("golden-dir")
                    .short('g')
                    .long("golden-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("baseline-dir")
                    .short('b')
                    .long("baseline-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            );

        let args = vec![
            "check_conformance_regression",
            "--golden-dir",
            "/tmp/golden",
            "--baseline-dir",
            "/tmp/baseline",
        ];

        let matches = app.try_get_matches_from(args);
        assert!(matches.is_ok());
    }
}
