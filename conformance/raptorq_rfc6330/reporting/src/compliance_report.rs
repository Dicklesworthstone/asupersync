//! Compliance Report Generation for RFC 6330 Conformance
//!
//! Generates detailed conformance reports in multiple formats:
//! - Markdown tables with coverage breakdown
//! - JSON data for CI integration
//! - HTML reports with interactive features
//! - SVG badges for README display

use std::collections::BTreeMap;
use serde_json;

use crate::coverage_matrix::{CoverageMatrix, SectionCoverage, ConformanceLevel};

/// Report generation configuration
#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub include_failing_tests: bool,
    pub include_timing_data: bool,
    pub include_historical_data: bool,
    pub badge_style: BadgeStyle,
    pub output_format: OutputFormat,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            include_failing_tests: true,
            include_timing_data: false,
            include_historical_data: false,
            badge_style: BadgeStyle::Flat,
            output_format: OutputFormat::Markdown,
        }
    }
}

/// Badge style options for conformance badges
#[derive(Debug, Clone, Copy)]
pub enum BadgeStyle {
    Flat,
    FlatSquare,
    Plastic,
    ForTheBadge,
}

impl BadgeStyle {
    fn as_str(self) -> &'static str {
        match self {
            BadgeStyle::Flat => "flat",
            BadgeStyle::FlatSquare => "flat-square",
            BadgeStyle::Plastic => "plastic",
            BadgeStyle::ForTheBadge => "for-the-badge",
        }
    }
}

/// Output format options
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Markdown,
    Json,
    Html,
    Badge,
}

/// Compliance report generator
pub struct ComplianceReportGenerator {
    config: ReportConfig,
}

impl ComplianceReportGenerator {
    pub fn new(config: ReportConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(ReportConfig::default())
    }

    /// Generate complete compliance report
    pub fn generate_report(&self, matrix: &CoverageMatrix) -> String {
        match self.config.output_format {
            OutputFormat::Markdown => self.generate_markdown_report(matrix),
            OutputFormat::Json => self.generate_json_report(matrix),
            OutputFormat::Html => self.generate_html_report(matrix),
            OutputFormat::Badge => self.generate_badge_url(matrix),
        }
    }

    /// Generate markdown compliance report
    fn generate_markdown_report(&self, matrix: &CoverageMatrix) -> String {
        let mut report = String::new();

        // Header
        report.push_str(&format!("# RFC 6330 RaptorQ Conformance Report\n\n"));
        report.push_str(&format!("**Generated:** {}\n", matrix.generated_at));
        report.push_str(&format!("**Implementation Version:** {}\n", matrix.implementation_version));
        report.push_str(&format!("**RFC Version:** {}\n\n", matrix.rfc_version));

        // Overall status
        report.push_str("## Overall Conformance Status\n\n");
        report.push_str(&format!("**Status:** {}\n", matrix.conformance_level));
        report.push_str(&format!("**Compliance Score:** {:.1}%\n\n", matrix.compliance_score));

        // Conformance badge
        report.push_str("### Conformance Badge\n\n");
        report.push_str(&format!("```markdown\n"));
        report.push_str(&format!("![RFC 6330 Conformance]({})\n", self.generate_badge_url(matrix)));
        report.push_str(&format!("```\n\n"));

        // Coverage summary
        report.push_str("## Coverage Summary\n\n");
        report.push_str("| Requirement Level | Total | Passing | Coverage |\n");
        report.push_str("|-------------------|-------|---------|----------|\n");
        report.push_str(&format!("| **MUST**          | {}    | {}      | {:.1}%   |\n",
            matrix.overall.must_total,
            matrix.overall.must_passing,
            matrix.overall.must_coverage_percent()));
        report.push_str(&format!("| **SHOULD**        | {}    | {}      | {:.1}%   |\n",
            matrix.overall.should_total,
            matrix.overall.should_passing,
            matrix.overall.should_coverage_percent()));
        report.push_str(&format!("| **MAY**           | {}    | {}      | {:.1}%   |\n\n",
            matrix.overall.may_total,
            matrix.overall.may_passing,
            matrix.overall.may_coverage_percent()));

        // Test execution summary
        report.push_str("### Test Execution Summary\n\n");
        report.push_str("| Status | Count | Percentage |\n");
        report.push_str("|--------|-------|------------|\n");
        report.push_str(&format!("| Passing | {} | {:.1}% |\n",
            matrix.overall.passing_tests,
            (matrix.overall.passing_tests as f64 / matrix.overall.total_tests as f64) * 100.0));
        report.push_str(&format!("| Failing | {} | {:.1}% |\n",
            matrix.overall.failing_tests,
            (matrix.overall.failing_tests as f64 / matrix.overall.total_tests as f64) * 100.0));
        report.push_str(&format!("| Skipped | {} | {:.1}% |\n",
            matrix.overall.skipped_tests,
            (matrix.overall.skipped_tests as f64 / matrix.overall.total_tests as f64) * 100.0));
        report.push_str(&format!("| **Total** | **{}** | **100.0%** |\n\n", matrix.overall.total_tests));

        // Section-by-section breakdown
        report.push_str("## Section-by-Section Coverage\n\n");
        report.push_str("| Section | MUST (pass/total) | SHOULD (pass/total) | MAY (pass/total) | Score | Status |\n");
        report.push_str("|---------|-------------------|---------------------|------------------|-------|--------|\n");

        for section in matrix.sections.values() {
            report.push_str(&format!(
                "| §{}    | {}/{}             | {}/{}                | {}/{}             | {:.1}% | {} |\n",
                section.section,
                section.must_passing, section.must_total,
                section.should_passing, section.should_total,
                section.may_passing, section.may_total,
                section.score,
                section.conformance_status
            ));
        }
        report.push_str("\n");

        // Overall row
        report.push_str(&format!(
            "| **Overall** | **{}/{}**        | **{}/{}**           | **{}/{}**         | **{:.1}%** | **{}** |\n\n",
            matrix.overall.must_passing, matrix.overall.must_total,
            matrix.overall.should_passing, matrix.overall.should_total,
            matrix.overall.may_passing, matrix.overall.may_total,
            matrix.compliance_score,
            matrix.conformance_level
        ));

        // Failing sections details
        if self.config.include_failing_tests {
            let failing = matrix.failing_sections();
            let warning = matrix.warning_sections();

            if !failing.is_empty() || !warning.is_empty() {
                report.push_str("## Detailed Analysis\n\n");

                if !failing.is_empty() {
                    report.push_str("### Failing Sections\n\n");
                    for section in failing {
                        self.add_section_details(&mut report, section, "❌");
                    }
                }

                if !warning.is_empty() {
                    report.push_str("### Warning Sections\n\n");
                    for section in warning {
                        self.add_section_details(&mut report, section, "⚠️");
                    }
                }
            }
        }

        // Conformance interpretation
        report.push_str("## Conformance Interpretation\n\n");
        match matrix.conformance_level {
            ConformanceLevel::FullyConformant => {
                report.push_str("✅ **Fully Conformant**: This implementation meets the high standards for RFC 6330 conformance with ≥95% MUST clause coverage and ≥90% SHOULD clause coverage.\n\n");
            }
            ConformanceLevel::PartiallyConformant => {
                report.push_str("⚠️ **Partially Conformant**: This implementation has good RFC 6330 conformance but falls below full conformance thresholds. Focus on improving MUST clause coverage to ≥95% and SHOULD clause coverage to ≥90%.\n\n");
            }
            ConformanceLevel::NonConformant => {
                report.push_str("❌ **Non-Conformant**: This implementation does not meet minimum RFC 6330 conformance standards. MUST clause coverage should be ≥85% and SHOULD clause coverage should be ≥70% for partial conformance.\n\n");
            }
        }

        report.push_str("### Conformance Thresholds\n\n");
        report.push_str("- **Fully Conformant**: ≥95% MUST coverage + ≥90% SHOULD coverage\n");
        report.push_str("- **Partially Conformant**: ≥85% MUST coverage + ≥70% SHOULD coverage\n");
        report.push_str("- **Non-Conformant**: Below partial conformance thresholds\n\n");

        report.push_str("---\n");
        report.push_str(&format!("*Generated by asupersync RFC 6330 conformance pipeline at {}*\n", matrix.generated_at));

        report
    }

    /// Add detailed section analysis to report
    fn add_section_details(&self, report: &mut String, section: &SectionCoverage, icon: &str) {
        report.push_str(&format!("#### {} Section {} - {}\n\n", icon, section.section, section.title));
        report.push_str(&format!("- **MUST Coverage**: {:.1}% ({}/{})\n",
            section.must_coverage_percent(), section.must_passing, section.must_total));
        report.push_str(&format!("- **SHOULD Coverage**: {:.1}% ({}/{})\n",
            section.should_coverage_percent(), section.should_passing, section.should_total));
        report.push_str(&format!("- **Overall Score**: {:.1}%\n", section.score));

        if !section.failing_tests.is_empty() {
            report.push_str(&format!("- **Failing Tests**: {}\n", section.failing_tests.join(", ")));
        }
        report.push_str("\n");
    }

    /// Generate JSON report for CI integration
    fn generate_json_report(&self, matrix: &CoverageMatrix) -> String {
        serde_json::to_string_pretty(matrix)
            .unwrap_or_else(|_| "{}".to_string())
    }

    /// Generate HTML report with interactive features
    fn generate_html_report(&self, matrix: &CoverageMatrix) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("  <title>RFC 6330 Conformance Report</title>\n");
        html.push_str("  <meta charset=\"utf-8\">\n");
        html.push_str("  <style>\n");
        html.push_str(include_str!("../templates/report.css"));
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");

        // Header
        html.push_str("  <div class=\"container\">\n");
        html.push_str("    <header>\n");
        html.push_str("      <h1>RFC 6330 RaptorQ Conformance Report</h1>\n");
        html.push_str(&format!("      <p><strong>Generated:</strong> {}</p>\n", matrix.generated_at));
        html.push_str(&format!("      <p><strong>Implementation:</strong> {}</p>\n", matrix.implementation_version));
        html.push_str("    </header>\n\n");

        // Overall status
        html.push_str("    <section class=\"status\">\n");
        html.push_str("      <h2>Overall Conformance</h2>\n");
        html.push_str(&format!("      <div class=\"status-badge {}\">{}</div>\n",
            matrix.badge_color(), matrix.conformance_level));
        html.push_str(&format!("      <p><strong>Compliance Score:</strong> {:.1}%</p>\n", matrix.compliance_score));
        html.push_str("    </section>\n\n");

        // Coverage table
        html.push_str("    <section class=\"coverage\">\n");
        html.push_str("      <h2>Coverage Matrix</h2>\n");
        html.push_str("      <table>\n");
        html.push_str("        <thead>\n");
        html.push_str("          <tr><th>Section</th><th>MUST</th><th>SHOULD</th><th>MAY</th><th>Score</th><th>Status</th></tr>\n");
        html.push_str("        </thead>\n");
        html.push_str("        <tbody>\n");

        for section in matrix.sections.values() {
            html.push_str("          <tr>\n");
            html.push_str(&format!("            <td>§{}</td>\n", section.section));
            html.push_str(&format!("            <td>{}/{} ({:.1}%)</td>\n",
                section.must_passing, section.must_total, section.must_coverage_percent()));
            html.push_str(&format!("            <td>{}/{} ({:.1}%)</td>\n",
                section.should_passing, section.should_total, section.should_coverage_percent()));
            html.push_str(&format!("            <td>{}/{} ({:.1}%)</td>\n",
                section.may_passing, section.may_total, section.may_coverage_percent()));
            html.push_str(&format!("            <td>{:.1}%</td>\n", section.score));
            html.push_str(&format!("            <td>{}</td>\n", section.conformance_status));
            html.push_str("          </tr>\n");
        }

        html.push_str("        </tbody>\n");
        html.push_str("      </table>\n");
        html.push_str("    </section>\n\n");

        html.push_str("  </div>\n");
        html.push_str("</body>\n</html>\n");

        html
    }

    /// Generate conformance badge URL
    fn generate_badge_url(&self, matrix: &CoverageMatrix) -> String {
        let text = matrix.badge_text();
        let color = matrix.badge_color();
        let style = self.config.badge_style.as_str();

        format!(
            "https://img.shields.io/badge/RFC%206330-{}-{}?style={}",
            text.replace(" ", "%20").replace("%", "%25"),
            color,
            style
        )
    }
}

/// Generate quick compliance summary for CI output
pub fn generate_ci_summary(matrix: &CoverageMatrix) -> BTreeMap<String, serde_json::Value> {
    let mut summary = BTreeMap::new();

    summary.insert("conformance_level".to_string(),
        serde_json::Value::String(format!("{:?}", matrix.conformance_level)));
    summary.insert("compliance_score".to_string(),
        serde_json::Value::Number(serde_json::Number::from_f64(matrix.compliance_score).unwrap()));
    summary.insert("must_coverage".to_string(),
        serde_json::Value::Number(serde_json::Number::from_f64(matrix.overall.must_coverage_percent()).unwrap()));
    summary.insert("should_coverage".to_string(),
        serde_json::Value::Number(serde_json::Number::from_f64(matrix.overall.should_coverage_percent()).unwrap()));
    summary.insert("total_tests".to_string(),
        serde_json::Value::Number(matrix.overall.total_tests.into()));
    summary.insert("passing_tests".to_string(),
        serde_json::Value::Number(matrix.overall.passing_tests.into()));
    summary.insert("failing_tests".to_string(),
        serde_json::Value::Number(matrix.overall.failing_tests.into()));

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_matrix::{CoverageMatrix, SectionCoverage, OverallCoverage};

    fn create_test_matrix() -> CoverageMatrix {
        let mut matrix = CoverageMatrix::new("test-v1.0.0".to_string());

        let mut section = SectionCoverage::new("4.1".to_string(), "Parameter Derivation".to_string());
        section.must_total = 10;
        section.must_passing = 9;
        section.should_total = 5;
        section.should_passing = 4;
        section.calculate_score();
        matrix.sections.insert("4.1".to_string(), section);

        matrix.overall.must_total = 10;
        matrix.overall.must_passing = 9;
        matrix.overall.should_total = 5;
        matrix.overall.should_passing = 4;
        matrix.overall.total_tests = 15;
        matrix.overall.passing_tests = 13;
        matrix.overall.failing_tests = 2;

        matrix
    }

    #[test]
    fn test_markdown_report_generation() {
        let matrix = create_test_matrix();
        let generator = ComplianceReportGenerator::with_default_config();
        let report = generator.generate_markdown_report(&matrix);

        assert!(report.contains("# RFC 6330 RaptorQ Conformance Report"));
        assert!(report.contains("## Overall Conformance Status"));
        assert!(report.contains("| Section | MUST (pass/total)"));
        assert!(report.contains("| §4.1"));
        assert!(report.contains("9/10"));
        assert!(report.contains("4/5"));
    }

    #[test]
    fn test_json_report_generation() {
        let matrix = create_test_matrix();
        let generator = ComplianceReportGenerator::with_default_config();
        let json = generator.generate_json_report(&matrix);

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["sections"].is_object());
        assert!(parsed["overall"].is_object());
        assert!(parsed["compliance_score"].is_number());
    }

    #[test]
    fn test_badge_url_generation() {
        let matrix = create_test_matrix();
        let mut config = ReportConfig::default();
        config.badge_style = BadgeStyle::Flat;
        let generator = ComplianceReportGenerator::new(config);
        let url = generator.generate_badge_url(&matrix);

        assert!(url.starts_with("https://img.shields.io/badge/RFC%206330-"));
        assert!(url.contains("style=flat"));
    }

    #[test]
    fn test_ci_summary_generation() {
        let matrix = create_test_matrix();
        let summary = generate_ci_summary(&matrix);

        assert!(summary.contains_key("conformance_level"));
        assert!(summary.contains_key("compliance_score"));
        assert!(summary.contains_key("must_coverage"));
        assert!(summary.contains_key("total_tests"));
    }
}