//! Compliance Report Generation CLI
//!
//! Generates detailed RFC 6330 conformance reports from test execution results
//! in multiple formats (Markdown, JSON, HTML, badges) for documentation and CI.

use std::fs;
use std::path::PathBuf;
use clap::{Arg, ArgAction, Command};
use serde_json;

// Import from conformance crate
use asupersync_conformance::raptorq_rfc6330::TestExecution;

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Markdown,
    Json,
    Html,
    Badge,
}

#[derive(Debug, Clone)]
pub enum ConformanceLevel {
    FullyConformant,
    PartiallyConformant,
    NonConformant,
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub include_failing_tests: bool,
    pub include_timing_data: bool,
    pub include_historical_data: bool,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct ComplianceMatrix {
    pub executions: Vec<TestExecution>,
    pub conformance_level: ConformanceLevel,
    pub pass_count: usize,
    pub total_count: usize,
}

impl ComplianceMatrix {
    pub fn from_test_results(executions: Vec<TestExecution>, _implementation_version: String) -> Self {
        let total_count = executions.len();
        let pass_count = executions.iter()
            .filter(|e| matches!(e.result, asupersync_conformance::raptorq_rfc6330::ConformanceResult::Pass))
            .count();

        let conformance_level = if total_count == 0 {
            ConformanceLevel::NonConformant
        } else {
            let pass_rate = (pass_count as f64) / (total_count as f64);
            if pass_rate >= 1.0 {
                ConformanceLevel::FullyConformant
            } else if pass_rate >= 0.8 {
                ConformanceLevel::PartiallyConformant
            } else {
                ConformanceLevel::NonConformant
            }
        };

        Self {
            executions,
            conformance_level,
            pass_count,
            total_count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComplianceReportGenerator {
    pub config: ReportConfig,
}

impl ComplianceReportGenerator {
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    pub fn generate_report(&self, matrix: &ComplianceMatrix) -> String {
        match self.config.output_format {
            OutputFormat::Markdown => self.generate_markdown_report(matrix),
            OutputFormat::Json => self.generate_json_report(matrix),
            OutputFormat::Html => self.generate_html_report(matrix),
            OutputFormat::Badge => self.generate_badge_url(matrix),
        }
    }

    fn generate_markdown_report(&self, matrix: &ComplianceMatrix) -> String {
        format!(
            "# RFC 6330 Conformance Report\n\n\
            ## Summary\n\n\
            - Total tests: {}\n\
            - Passed: {}\n\
            - Failed: {}\n\
            - Pass rate: {:.1}%\n\
            - Conformance level: {:?}\n\n\
            ## Test Results\n\n{}",
            matrix.total_count,
            matrix.pass_count,
            matrix.total_count - matrix.pass_count,
            (matrix.pass_count as f64 / matrix.total_count as f64 * 100.0),
            matrix.conformance_level,
            if self.config.include_failing_tests {
                self.format_test_details(&matrix.executions)
            } else {
                "Details omitted (use --include-failures for full report)".to_string()
            }
        )
    }

    fn generate_json_report(&self, matrix: &ComplianceMatrix) -> String {
        let summary = serde_json::json!({
            "total_tests": matrix.total_count,
            "passed": matrix.pass_count,
            "failed": matrix.total_count - matrix.pass_count,
            "pass_rate": (matrix.pass_count as f64) / (matrix.total_count as f64) * 100.0,
            "conformance_level": format!("{:?}", matrix.conformance_level),
            "executions": if self.config.include_failing_tests {
                serde_json::to_value(&matrix.executions).unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        });
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
    }

    fn generate_html_report(&self, matrix: &ComplianceMatrix) -> String {
        format!(
            "<html><head><title>RFC 6330 Conformance Report</title></head>\
            <body><h1>RFC 6330 Conformance Report</h1>\
            <h2>Summary</h2>\
            <ul>\
            <li>Total tests: {}</li>\
            <li>Passed: {}</li>\
            <li>Failed: {}</li>\
            <li>Pass rate: {:.1}%</li>\
            <li>Conformance level: {:?}</li>\
            </ul></body></html>",
            matrix.total_count,
            matrix.pass_count,
            matrix.total_count - matrix.pass_count,
            (matrix.pass_count as f64 / matrix.total_count as f64 * 100.0),
            matrix.conformance_level
        )
    }

    fn generate_badge_url(&self, matrix: &ComplianceMatrix) -> String {
        let pass_rate = (matrix.pass_count as f64) / (matrix.total_count as f64) * 100.0;
        let color = if pass_rate >= 100.0 { "green" } else if pass_rate >= 80.0 { "yellow" } else { "red" };
        format!(
            "https://img.shields.io/badge/RFC%206330%20Conformance-{:.1}%25-{}",
            pass_rate, color
        )
    }

    fn format_test_details(&self, executions: &[TestExecution]) -> String {
        executions.iter()
            .map(|e| format!("- {}: {:?}", e.test_name, e.result))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

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
        .get_matches();

    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output");
    let format = matches.get_one::<String>("format").unwrap();
    let implementation_version = matches.get_one::<String>("implementation-version")
        .map(|s| s.clone())
        .unwrap_or_else(|| detect_implementation_version());
    let ci_mode = matches.get_flag("ci-mode");
    let include_failures = matches.get_flag("include-failures");

    // Load test execution results
    let executions = match load_test_executions(input_path) {
        Ok(executions) => executions,
        Err(e) => {
            eprintln!("Error loading test results: {}", e);
            std::process::exit(1);
        }
    };

    // Generate compliance matrix
    let matrix = ComplianceMatrix::from_test_results(executions, implementation_version);

    // Configure report generation
    let report_config = ReportConfig {
        include_failing_tests: include_failures,
        include_timing_data: false,
        include_historical_data: false,
        output_format: parse_output_format(format),
    };

    let generator = ComplianceReportGenerator::new(report_config);

    // Generate reports based on format
    match format.as_str() {
        "all" => {
            generate_all_formats(&generator, &matrix, output_path);
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
        let ci_summary = serde_json::json!({
            "total": matrix.total_count,
            "passed": matrix.pass_count,
            "failed": matrix.total_count - matrix.pass_count,
            "pass_rate": (matrix.pass_count as f64) / (matrix.total_count as f64) * 100.0,
            "conformance_level": format!("{:?}", matrix.conformance_level)
        });

        eprintln!("=== CI SUMMARY ===");
        eprintln!("{}", serde_json::to_string_pretty(&ci_summary).unwrap_or_else(|_| "{}".to_string()));

        // Exit with appropriate code based on conformance level
        match matrix.conformance_level {
            ConformanceLevel::FullyConformant => {
                eprintln!("✅ Conformance check PASSED");
                std::process::exit(0);
            }
            ConformanceLevel::PartiallyConformant => {
                eprintln!("⚠️ Conformance check WARNING - partial conformance only");
                std::process::exit(1);
            }
            ConformanceLevel::NonConformant => {
                eprintln!("❌ Conformance check FAILED - non-conformant");
                std::process::exit(2);
            }
        }
    }
}

/// Load test execution results from JSON file
fn load_test_executions(path: &str) -> Result<Vec<TestExecution>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;

    // TestExecution implements Serialize/Deserialize, so we can deserialize directly
    let executions: Vec<TestExecution> = serde_json::from_str(&content)?;

    println!("Loaded {} test execution records", executions.len());
    Ok(executions)
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
fn generate_all_formats(generator: &ComplianceReportGenerator, matrix: &ComplianceMatrix, base_path: Option<&String>) {
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
    fn test_output_format_parsing() {
        assert!(matches!(parse_output_format("markdown"), OutputFormat::Markdown));
        assert!(matches!(parse_output_format("json"), OutputFormat::Json));
        assert!(matches!(parse_output_format("html"), OutputFormat::Html));
        assert!(matches!(parse_output_format("badge"), OutputFormat::Badge));
    }
}