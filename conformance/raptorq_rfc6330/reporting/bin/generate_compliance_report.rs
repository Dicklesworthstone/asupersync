//! Compliance Report Generation CLI
//!
//! Generates detailed RFC 6330 conformance reports from test execution results
//! in multiple formats (Markdown, JSON, HTML, badges) for documentation and CI.
//!
//! # Usage
//!
//! ```bash
//! # Generate Markdown report from conformance test results
//! cargo run --bin generate_compliance_report -- --input results.json --output report.md
//!
//! # Generate all formats
//! cargo run --bin generate_compliance_report -- --input results.json --format all
//!
//! # Generate badge URL only
//! cargo run --bin generate_compliance_report -- --input results.json --format badge
//!
//! # Generate with CI-friendly output
//! cargo run --bin generate_compliance_report -- --input results.json --format json --ci-mode
//! ```

use std::fs;
use std::path::PathBuf;
use clap::{Arg, ArgAction, Command};
use serde_json;

// Import from parent crate
use asupersync_conformance::raptorq_rfc6330::TestExecution;

// Import from reporting module
mod reporting {
    pub use super::super::src::*;
}

use reporting::{
    CoverageMatrix, ComplianceReportGenerator, ReportConfig, OutputFormat,
    generate_ci_summary
};

fn main() {
    let matches = Command::new("generate_compliance_report")
        .version("1.0.0")
        .author("asupersync contributors")
        .about("Generate RFC 6330 conformance compliance reports")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Input JSON file with test execution results")
                .required(true)
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file path (default: stdout)")
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format: markdown, json, html, badge, all")
                .default_value("markdown")
        )
        .arg(
            Arg::new("implementation-version")
                .long("implementation-version")
                .value_name("VERSION")
                .help("Implementation version string (default: detect from git)")
        )
        .arg(
            Arg::new("ci-mode")
                .long("ci-mode")
                .action(ArgAction::SetTrue)
                .help("Generate CI-friendly output with exit codes")
        )
        .arg(
            Arg::new("include-failures")
                .long("include-failures")
                .action(ArgAction::SetTrue)
                .help("Include detailed failure analysis in report")
        )
        .arg(
            Arg::new("badge-style")
                .long("badge-style")
                .value_name("STYLE")
                .help("Badge style: flat, flat-square, plastic, for-the-badge")
                .default_value("flat")
        )
        .get_matches();

    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output");
    let format = matches.get_one::<String>("format").unwrap();
    let implementation_version = matches.get_one::<String>("implementation-version")
        .map(|s| s.clone())
        .unwrap_or_else(|| detect_implementation_version());
    let ci_mode = matches.get_flag("ci-mode");
    let include_failures = matches.get_flag("include-failures");
    let badge_style = matches.get_one::<String>("badge-style").unwrap();

    // Load test execution results
    let executions = match load_test_executions(input_path) {
        Ok(executions) => executions,
        Err(e) => {
            eprintln!("Error loading test results: {}", e);
            std::process::exit(1);
        }
    };

    // Generate coverage matrix
    let matrix = CoverageMatrix::from_test_results(&executions, implementation_version);

    // Configure report generation
    let report_config = ReportConfig {
        include_failing_tests: include_failures,
        include_timing_data: false,
        include_historical_data: false,
        badge_style: parse_badge_style(badge_style),
        output_format: parse_output_format(format),
    };

    let generator = ComplianceReportGenerator::new(report_config);

    // Generate reports based on format
    match format.as_str() {
        "all" => {
            generate_all_formats(&generator, &matrix, output_path);
        }
        "badge" => {
            let badge_url = generator.generate_report(&matrix);
            if let Some(output) = output_path {
                if let Err(e) = fs::write(output, &badge_url) {
                    eprintln!("Error writing badge URL: {}", e);
                    std::process::exit(1);
                }
            } else {
                println!("{}", badge_url);
            }
        }
        _ => {
            let report = generator.generate_report(&matrix);
            if let Some(output) = output_path {
                if let Err(e) = fs::write(output, &report) {
                    eprintln!("Error writing report: {}", e);
                    std::process::exit(1);
                }
            } else {
                println!("{}", report);
            }
        }
    }

    // Generate CI summary if requested
    if ci_mode {
        let ci_summary = generate_ci_summary(&matrix);
        let ci_json = serde_json::to_string_pretty(&ci_summary)
            .unwrap_or_else(|_| "{}".to_string());

        eprintln!("=== CI SUMMARY ===");
        eprintln!("{}", ci_json);

        // Exit with appropriate code based on conformance level
        match matrix.conformance_level {
            reporting::ConformanceLevel::FullyConformant => {
                eprintln!("✅ Conformance check PASSED");
                std::process::exit(0);
            }
            reporting::ConformanceLevel::PartiallyConformant => {
                eprintln!("⚠️ Conformance check WARNING - partial conformance only");
                std::process::exit(1);
            }
            reporting::ConformanceLevel::NonConformant => {
                eprintln!("❌ Conformance check FAILED - non-conformant");
                std::process::exit(2);
            }
        }
    }
}

/// Load test execution results from JSON file
fn load_test_executions(path: &str) -> Result<Vec<TestExecution>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;

    // For now, use a simplified JSON structure since TestExecution contains trait objects
    // In a real implementation, this would need proper serialization support
    let _json_data: serde_json::Value = serde_json::from_str(&content)?;

    // TODO: Implement proper deserialization of TestExecution from JSON
    // For now, return empty vector as placeholder
    eprintln!("Warning: Test execution loading not yet fully implemented");
    Ok(vec![])
}

/// Detect implementation version from git
fn detect_implementation_version() -> String {
    use std::process::Command;

    // Try to get git describe output
    if let Ok(output) = Command::new("git")
        .args(&["describe", "--tags", "--always", "--dirty"])
        .output()
    {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    // Fallback to commit hash
    if let Ok(output) = Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            return String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
    }

    // Final fallback
    "unknown-version".to_string()
}

/// Parse badge style from string
fn parse_badge_style(style: &str) -> reporting::compliance_report::BadgeStyle {
    match style.to_lowercase().as_str() {
        "flat" => reporting::compliance_report::BadgeStyle::Flat,
        "flat-square" => reporting::compliance_report::BadgeStyle::FlatSquare,
        "plastic" => reporting::compliance_report::BadgeStyle::Plastic,
        "for-the-badge" => reporting::compliance_report::BadgeStyle::ForTheBadge,
        _ => {
            eprintln!("Warning: Unknown badge style '{}', using 'flat'", style);
            reporting::compliance_report::BadgeStyle::Flat
        }
    }
}

/// Parse output format from string
fn parse_output_format(format: &str) -> OutputFormat {
    match format.to_lowercase().as_str() {
        "markdown" | "md" => OutputFormat::Markdown,
        "json" => OutputFormat::Json,
        "html" => OutputFormat::Html,
        "badge" => OutputFormat::Badge,
        _ => {
            eprintln!("Warning: Unknown format '{}', using 'markdown'", format);
            OutputFormat::Markdown
        }
    }
}

/// Generate all report formats
fn generate_all_formats(generator: &ComplianceReportGenerator, matrix: &CoverageMatrix, base_path: Option<&String>) {
    let base = base_path.map(|p| PathBuf::from(p))
        .unwrap_or_else(|| PathBuf::from("conformance_report"));

    // Generate each format
    let formats = [
        (OutputFormat::Markdown, "md", "Markdown"),
        (OutputFormat::Json, "json", "JSON"),
        (OutputFormat::Html, "html", "HTML"),
        (OutputFormat::Badge, "txt", "Badge URL"),
    ];

    for (format, ext, name) in formats {
        let mut config = generator.config.clone();
        config.output_format = format;
        let format_generator = ComplianceReportGenerator::new(config);

        let report = format_generator.generate_report(matrix);
        let output_path = base.with_extension(ext);

        match fs::write(&output_path, &report) {
            Ok(()) => {
                println!("Generated {} report: {}", name, output_path.display());
            }
            Err(e) => {
                eprintln!("Error writing {} report to {}: {}", name, output_path.display(), e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_detection() {
        let version = detect_implementation_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_badge_style_parsing() {
        assert!(matches!(
            parse_badge_style("flat"),
            reporting::compliance_report::BadgeStyle::Flat
        ));
        assert!(matches!(
            parse_badge_style("flat-square"),
            reporting::compliance_report::BadgeStyle::FlatSquare
        ));
    }

    #[test]
    fn test_output_format_parsing() {
        assert!(matches!(parse_output_format("markdown"), OutputFormat::Markdown));
        assert!(matches!(parse_output_format("json"), OutputFormat::Json));
        assert!(matches!(parse_output_format("html"), OutputFormat::Html));
        assert!(matches!(parse_output_format("badge"), OutputFormat::Badge));
    }
}