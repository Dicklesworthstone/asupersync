//! Generate Compliance Report Binary
//!
//! CLI tool for generating comprehensive RaptorQ RFC 6330 conformance reports
//! in multiple formats (Markdown, HTML, JSON, SVG badges).

use anyhow::{Context, Result};
use clap::{Arg, Command};
use raptorq_conformance_reporting::{
    compliance_report::{ComplianceReportGenerator, ReportFormat, ReportConfig},
    coverage_matrix::CoverageMatrixCalculator,
    regression_detection::{RegressionDetector, RegressionConfig},
};
use std::path::PathBuf;

fn main() -> Result<()> {
    let app = Command::new("generate_compliance_report")
        .about("Generate RaptorQ RFC 6330 conformance compliance reports")
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
            Arg::new("output-dir")
                .short('o')
                .long("output-dir")
                .value_name("DIR")
                .help("Output directory for reports")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["markdown", "html", "json", "svg", "all"])
                .default_value("all"),
        )
        .arg(
            Arg::new("template-dir")
                .short('t')
                .long("template-dir")
                .value_name("DIR")
                .help("Custom template directory")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("title")
                .long("title")
                .value_name("TITLE")
                .help("Custom report title")
                .default_value("RaptorQ RFC 6330 Conformance Report"),
        )
        .arg(
            Arg::new("project-name")
                .long("project-name")
                .value_name("NAME")
                .help("Project name for the report")
                .default_value("asupersync"),
        )
        .arg(
            Arg::new("project-url")
                .long("project-url")
                .value_name("URL")
                .help("Project URL for the report")
                .default_value("https://github.com/your-org/asupersync"),
        )
        .arg(
            Arg::new("include-regression")
                .long("include-regression")
                .help("Include regression analysis in the report")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("regression-baseline")
                .long("regression-baseline")
                .value_name("PATH")
                .help("Path to regression baseline data")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("commit-hash")
                .long("commit-hash")
                .value_name("HASH")
                .help("Git commit hash for the report"),
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
    let output_dir = matches.get_one::<PathBuf>("output-dir").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let template_dir = matches.get_one::<PathBuf>("template-dir");
    let title = matches.get_one::<String>("title").unwrap();
    let project_name = matches.get_one::<String>("project-name").unwrap();
    let project_url = matches.get_one::<String>("project-url").unwrap();
    let include_regression = matches.get_flag("include-regression");
    let regression_baseline = matches.get_one::<PathBuf>("regression-baseline");
    let commit_hash = matches.get_one::<String>("commit-hash");
    let verbose = matches.get_flag("verbose");

    if verbose {
        println!("Generating compliance report...");
        println!("  Golden directory: {}", golden_dir.display());
        println!("  Output directory: {}", output_dir.display());
        println!("  Format: {}", format);
    }

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    // Create coverage matrix calculator and generate matrix
    let calculator = CoverageMatrixCalculator::new();
    let coverage_matrix = calculator
        .calculate_coverage(golden_dir)
        .context("Failed to calculate coverage matrix")?;

    if verbose {
        println!("Coverage analysis complete:");
        println!("  Total tests: {}", coverage_matrix.total_tests);
        println!("  Passed tests: {}", coverage_matrix.passed_tests);
        println!("  Failed tests: {}", coverage_matrix.failed_tests);
        println!("  Overall conformance score: {:.1}%",
                 coverage_matrix.overall_conformance_score * 100.0);
    }

    // Handle regression analysis if requested
    let regression_analysis = if include_regression {
        if verbose {
            println!("Performing regression analysis...");
        }

        let mut regression_config = RegressionConfig::default();
        if let Some(baseline_path) = regression_baseline {
            regression_config.historical_data_paths = vec![baseline_path.clone()];
        }

        let detector = RegressionDetector::new(regression_config);
        match detector.detect_regressions(&coverage_matrix, golden_dir) {
            Ok(analysis) => {
                if verbose {
                    println!("  Regressions detected: {}", analysis.has_regressions);
                    println!("  Score change: {:.3}", analysis.score_change);
                    println!("  Number of findings: {}", analysis.regressions.len());
                }
                Some(analysis)
            }
            Err(e) => {
                eprintln!("Warning: Regression analysis failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Configure report generation
    let mut report_config = ReportConfig::default();
    report_config.title = title.clone();
    report_config.project_name = project_name.clone();
    report_config.project_url = project_url.clone();
    if let Some(hash) = commit_hash {
        report_config.commit_hash = Some(hash.clone());
    }
    if let Some(template_path) = template_dir {
        report_config.template_dir = Some(template_path.clone());
    }

    let generator = ComplianceReportGenerator::with_config(report_config);

    // Generate reports based on requested format
    let formats_to_generate = match format.as_str() {
        "all" => vec![
            ReportFormat::Markdown,
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::SvgBadge
        ],
        "markdown" => vec![ReportFormat::Markdown],
        "html" => vec![ReportFormat::Html],
        "json" => vec![ReportFormat::Json],
        "svg" => vec![ReportFormat::SvgBadge],
        _ => {
            anyhow::bail!("Invalid format: {}. Valid options: markdown, html, json, svg, all", format);
        }
    };

    for report_format in formats_to_generate {
        let output_file = output_dir.join(match report_format {
            ReportFormat::Markdown => "compliance_report.md",
            ReportFormat::Html => "compliance_report.html",
            ReportFormat::Json => "compliance_report.json",
            ReportFormat::SvgBadge => "compliance_badge.svg",
        });

        if verbose {
            println!("Generating {:?} report: {}", report_format, output_file.display());
        }

        match generator.generate_report(&coverage_matrix, regression_analysis.as_ref(), report_format) {
            Ok(content) => {
                std::fs::write(&output_file, content)
                    .with_context(|| format!("Failed to write report to {}", output_file.display()))?;

                println!("✅ Generated {} report: {}",
                         format!("{:?}", report_format).to_lowercase(),
                         output_file.display());
            }
            Err(e) => {
                eprintln!("❌ Failed to generate {:?} report: {}", report_format, e);
            }
        }
    }

    // Generate summary JSON for programmatic consumption
    let summary_file = output_dir.join("summary.json");
    let summary = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "golden_directory": golden_dir,
        "total_tests": coverage_matrix.total_tests,
        "passed_tests": coverage_matrix.passed_tests,
        "failed_tests": coverage_matrix.failed_tests,
        "overall_score": coverage_matrix.overall_conformance_score,
        "has_regressions": regression_analysis.as_ref().map(|r| r.has_regressions).unwrap_or(false),
        "regression_count": regression_analysis.as_ref().map(|r| r.regressions.len()).unwrap_or(0),
        "commit_hash": commit_hash,
        "project_name": project_name,
    });

    std::fs::write(&summary_file, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("Failed to write summary to {}", summary_file.display()))?;

    if verbose {
        println!("📊 Generated summary: {}", summary_file.display());
    }

    // Final status summary
    let status_emoji = if coverage_matrix.overall_conformance_score >= 0.95 {
        if regression_analysis.as_ref().map(|r| r.has_regressions).unwrap_or(false) {
            "⚠️"
        } else {
            "✅"
        }
    } else {
        "❌"
    };

    println!("\n{} Compliance Report Generation Complete", status_emoji);
    println!("📈 Overall conformance: {:.1}%", coverage_matrix.overall_conformance_score * 100.0);

    if let Some(ref analysis) = regression_analysis {
        if analysis.has_regressions {
            println!("⚠️  {} regression(s) detected", analysis.regressions.len());
        } else {
            println!("✅ No regressions detected");
        }
    }

    println!("📁 Reports saved to: {}", output_dir.display());

    // Return appropriate exit code
    let exit_code = if coverage_matrix.overall_conformance_score < 0.95 {
        2 // Poor conformance
    } else if regression_analysis.as_ref().map(|r| r.has_regressions).unwrap_or(false) {
        1 // Regressions detected
    } else {
        0 // Success
    };

    if exit_code != 0 && verbose {
        println!("\nExiting with code {} due to conformance issues.", exit_code);
    }

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cli_parsing() {
        // Test that the CLI parsing works without actually running the main function
        let app = Command::new("generate_compliance_report")
            .arg(
                Arg::new("golden-dir")
                    .short('g')
                    .long("golden-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("output-dir")
                    .short('o')
                    .long("output-dir")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf)),
            );

        let temp_dir = TempDir::new().unwrap();
        let args = vec![
            "generate_compliance_report",
            "--golden-dir", temp_dir.path().to_str().unwrap(),
            "--output-dir", temp_dir.path().to_str().unwrap(),
        ];

        let matches = app.try_get_matches_from(args);
        assert!(matches.is_ok());
    }
}