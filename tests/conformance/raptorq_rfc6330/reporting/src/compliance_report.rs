//! Compliance report generation for RaptorQ RFC 6330 conformance.
//!
//! This module generates multi-format conformance reports including Markdown,
//! JSON, HTML, and SVG badges from coverage matrix data.

use crate::coverage_matrix::{CoverageMatrix, ConformanceLevel, SectionConformanceStatus};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Report generation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Output directory for generated reports
    pub output_dir: String,
    /// Whether to generate Markdown report
    pub generate_markdown: bool,
    /// Whether to generate JSON report
    pub generate_json: bool,
    /// Whether to generate HTML report
    pub generate_html: bool,
    /// Whether to generate SVG badges
    pub generate_badges: bool,
    /// Custom report title
    pub report_title: String,
    /// Include historical trend data
    pub include_trends: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            output_dir: "reports".to_string(),
            generate_markdown: true,
            generate_json: true,
            generate_html: true,
            generate_badges: true,
            report_title: "RaptorQ RFC 6330 Conformance Report".to_string(),
            include_trends: false,
        }
    }
}

/// Generated report artifacts
#[derive(Debug, Clone)]
pub struct GeneratedReports {
    pub markdown_path: Option<String>,
    pub json_path: Option<String>,
    pub html_path: Option<String>,
    pub badge_path: Option<String>,
    pub summary: ReportSummary,
}

/// High-level report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_sections: usize,
    pub passing_sections: usize,
    pub failing_sections: usize,
    pub overall_score: f64,
    pub conformance_level: ConformanceLevel,
    pub critical_failures: usize,
    pub recommendations: Vec<String>,
}

/// Report generator
pub struct ComplianceReportGenerator {
    handlebars: Handlebars<'static>,
    config: ReportConfig,
}

impl ComplianceReportGenerator {
    /// Create a new report generator
    pub fn new(config: ReportConfig) -> Result<Self, ReportError> {
        let mut handlebars = Handlebars::new();

        // Register templates
        handlebars.register_template_string("markdown", MARKDOWN_TEMPLATE)?;
        handlebars.register_template_string("html", HTML_TEMPLATE)?;
        handlebars.register_template_string("badge", BADGE_TEMPLATE)?;
        handlebars.register_template_string("ci_summary", CI_SUMMARY_TEMPLATE)?;

        // Register helper functions
        handlebars.register_helper("percentage", Box::new(percentage_helper));
        handlebars.register_helper("status_icon", Box::new(status_icon_helper));
        handlebars.register_helper("badge_color", Box::new(badge_color_helper));

        Ok(Self { handlebars, config })
    }

    /// Generate all configured report formats
    pub fn generate_reports(
        &self,
        matrix: &CoverageMatrix,
    ) -> Result<GeneratedReports, ReportError> {
        // Ensure output directory exists
        fs::create_dir_all(&self.config.output_dir)?;

        let context = self.create_template_context(matrix);
        let mut reports = GeneratedReports {
            markdown_path: None,
            json_path: None,
            html_path: None,
            badge_path: None,
            summary: self.create_report_summary(matrix),
        };

        // Generate Markdown report
        if self.config.generate_markdown {
            let path = self.generate_markdown_report(&context)?;
            reports.markdown_path = Some(path);
        }

        // Generate JSON report
        if self.config.generate_json {
            let path = self.generate_json_report(matrix)?;
            reports.json_path = Some(path);
        }

        // Generate HTML report
        if self.config.generate_html {
            let path = self.generate_html_report(&context)?;
            reports.html_path = Some(path);
        }

        // Generate SVG badges
        if self.config.generate_badges {
            let path = self.generate_badges(&context)?;
            reports.badge_path = Some(path);
        }

        Ok(reports)
    }

    /// Create template context data
    fn create_template_context(&self, matrix: &CoverageMatrix) -> TemplateContext {
        let sections: Vec<SectionData> = matrix
            .sections
            .values()
            .map(|section| SectionData {
                section: section.section.clone(),
                must_passing: section.must_passing,
                must_total: section.must_total,
                should_passing: section.should_passing,
                should_total: section.should_total,
                may_passing: section.may_passing,
                may_total: section.may_total,
                score: section.score,
                status: section.conformance_status,
                failures: section
                    .failures
                    .iter()
                    .map(|f| FailureData {
                        test_name: f.test_name.clone(),
                        error_message: f.error_message.clone(),
                        requirement_level: format!("{:?}", f.requirement_level),
                        failure_type: format!("{:?}", f.failure_type),
                    })
                    .collect(),
            })
            .collect();

        TemplateContext {
            title: self.config.report_title.clone(),
            generated_at: matrix.generated_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            git_commit: matrix.git_commit.clone().unwrap_or_default(),
            sections,
            overall: OverallData {
                must_passing: matrix.overall.must_passing,
                must_total: matrix.overall.must_total,
                should_passing: matrix.overall.should_passing,
                should_total: matrix.overall.should_total,
                may_passing: matrix.overall.may_passing,
                may_total: matrix.overall.may_total,
                total_tests: matrix.overall.total_tests,
                passing_tests: matrix.overall.passing_tests,
                compliance_score: matrix.compliance_score,
                conformance_level: matrix.conformance_level,
            },
        }
    }

    /// Generate Markdown report
    fn generate_markdown_report(&self, context: &TemplateContext) -> Result<String, ReportError> {
        let content = self.handlebars.render("markdown", context)?;
        let path = format!("{}/CONFORMANCE_REPORT.md", self.config.output_dir);
        fs::write(&path, content)?;
        Ok(path)
    }

    /// Generate JSON report
    fn generate_json_report(&self, matrix: &CoverageMatrix) -> Result<String, ReportError> {
        let json = serde_json::to_string_pretty(matrix)?;
        let path = format!("{}/conformance_matrix.json", self.config.output_dir);
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Generate HTML report
    fn generate_html_report(&self, context: &TemplateContext) -> Result<String, ReportError> {
        let content = self.handlebars.render("html", context)?;
        let path = format!("{}/conformance_report.html", self.config.output_dir);
        fs::write(&path, content)?;
        Ok(path)
    }

    /// Generate SVG badges
    fn generate_badges(&self, context: &TemplateContext) -> Result<String, ReportError> {
        let badge_data = BadgeData {
            score: context.overall.compliance_score,
            level: context.overall.conformance_level,
        };

        let content = self.handlebars.render("badge", &badge_data)?;
        let path = format!("{}/conformance_badge.svg", self.config.output_dir);
        fs::write(&path, content)?;

        // Also generate CI summary for automated processing
        let ci_content = self.handlebars.render("ci_summary", context)?;
        let ci_path = format!("{}/ci_summary.json", self.config.output_dir);
        fs::write(&ci_path, ci_content)?;

        Ok(path)
    }

    /// Create high-level report summary
    fn create_report_summary(&self, matrix: &CoverageMatrix) -> ReportSummary {
        let total_sections = matrix.sections.len();
        let passing_sections = matrix
            .sections
            .values()
            .filter(|s| s.conformance_status == SectionConformanceStatus::Pass)
            .count();
        let failing_sections = total_sections - passing_sections;

        let critical_failures = matrix
            .sections
            .values()
            .map(|s| s.failures.len())
            .sum();

        let recommendations = self.generate_recommendations(matrix);

        ReportSummary {
            total_sections,
            passing_sections,
            failing_sections,
            overall_score: matrix.compliance_score,
            conformance_level: matrix.conformance_level,
            critical_failures,
            recommendations,
        }
    }

    /// Generate actionable recommendations based on failures
    fn generate_recommendations(&self, matrix: &CoverageMatrix) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Check for critical MUST requirement failures
        let must_failures: usize = matrix
            .sections
            .values()
            .map(|s| s.must_total - s.must_passing)
            .sum();

        if must_failures > 0 {
            recommendations.push(format!(
                "Address {} failing MUST requirements immediately - these are critical for conformance",
                must_failures
            ));
        }

        // Check sections with low scores
        let low_scoring_sections: Vec<&str> = matrix
            .sections
            .values()
            .filter(|s| s.score < 0.9)
            .map(|s| s.section.as_str())
            .collect();

        if !low_scoring_sections.is_empty() {
            recommendations.push(format!(
                "Focus on improving sections: {} (scores below 90%)",
                low_scoring_sections.join(", ")
            ));
        }

        // Check overall conformance level
        match matrix.conformance_level {
            ConformanceLevel::NonConformant => {
                recommendations.push(
                    "Overall conformance is below acceptable threshold - significant work required".to_string()
                );
            }
            ConformanceLevel::PartiallyConformant => {
                recommendations.push(
                    "Improve conformance score to achieve full RFC 6330 compliance".to_string()
                );
            }
            ConformanceLevel::MostlyConformant => {
                recommendations.push(
                    "Close remaining gaps to achieve full conformance status".to_string()
                );
            }
            ConformanceLevel::FullyConformant => {
                recommendations.push("Maintain excellent conformance through regression testing".to_string());
            }
        }

        if recommendations.is_empty() {
            recommendations.push("Continue maintaining high conformance standards".to_string());
        }

        recommendations
    }
}

// Template context structures
#[derive(Serialize)]
struct TemplateContext {
    title: String,
    generated_at: String,
    git_commit: String,
    sections: Vec<SectionData>,
    overall: OverallData,
}

#[derive(Serialize)]
struct SectionData {
    section: String,
    must_passing: usize,
    must_total: usize,
    should_passing: usize,
    should_total: usize,
    may_passing: usize,
    may_total: usize,
    score: f64,
    status: SectionConformanceStatus,
    failures: Vec<FailureData>,
}

#[derive(Serialize)]
struct FailureData {
    test_name: String,
    error_message: String,
    requirement_level: String,
    failure_type: String,
}

#[derive(Serialize)]
struct OverallData {
    must_passing: usize,
    must_total: usize,
    should_passing: usize,
    should_total: usize,
    may_passing: usize,
    may_total: usize,
    total_tests: usize,
    passing_tests: usize,
    compliance_score: f64,
    conformance_level: ConformanceLevel,
}

#[derive(Serialize)]
struct BadgeData {
    score: f64,
    level: ConformanceLevel,
}

// Handlebars helper functions
fn percentage_helper(
    h: &handlebars::Helper,
    _: &Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let (Some(numerator), Some(denominator)) = (h.param(0), h.param(1)) {
        if let (Some(num), Some(denom)) = (
            numerator.value().as_f64(),
            denominator.value().as_f64(),
        ) {
            if denom > 0.0 {
                let percentage = (num / denom * 100.0).round();
                out.write(&format!("{:.0}%", percentage))?;
            } else {
                out.write("N/A")?;
            }
        }
    }
    Ok(())
}

fn status_icon_helper(
    h: &handlebars::Helper,
    _: &Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(status) = h.param(0) {
        let icon = match status.value().as_str() {
            Some("Pass") => "✅",
            Some("Fail") => "❌",
            _ => "❓",
        };
        out.write(icon)?;
    }
    Ok(())
}

fn badge_color_helper(
    h: &handlebars::Helper,
    _: &Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(level) = h.param(0) {
        let color = match level.value().as_str() {
            Some("FullyConformant") => "brightgreen",
            Some("MostlyConformant") => "green",
            Some("PartiallyConformant") => "yellow",
            Some("NonConformant") => "red",
            _ => "lightgrey",
        };
        out.write(color)?;
    }
    Ok(())
}

/// Errors that can occur during report generation
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Template error: {0}")]
    TemplateError(#[from] handlebars::TemplateError),

    #[error("Render error: {0}")]
    RenderError(#[from] handlebars::RenderError),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Report generation failed: {0}")]
    GenerationError(String),
}

// Template definitions
const MARKDOWN_TEMPLATE: &str = r#"# {{title}}

**Generated:** {{generated_at}}
**Git Commit:** `{{git_commit}}`
**Overall Score:** {{percentage overall.compliance_score 1}}
**Conformance Level:** {{overall.conformance_level.description}}

## Summary

| Metric | MUST | SHOULD | MAY | Total |
|--------|------|--------|-----|-------|
| **Requirements** | {{overall.must_total}} | {{overall.should_total}} | {{overall.may_total}} | {{overall.total_tests}} |
| **Passing** | {{overall.must_passing}} | {{overall.should_passing}} | {{overall.may_passing}} | {{overall.passing_tests}} |
| **Pass Rate** | {{percentage overall.must_passing overall.must_total}} | {{percentage overall.should_passing overall.should_total}} | {{percentage overall.may_passing overall.may_total}} | {{percentage overall.passing_tests overall.total_tests}} |

## Section Breakdown

| Section | MUST | SHOULD | MAY | Score | Status |
|---------|------|--------|-----|-------|--------|
{{#each sections}}
| {{section}} | {{must_passing}}/{{must_total}} | {{should_passing}}/{{should_total}} | {{may_passing}}/{{may_total}} | {{percentage score 1}} | {{status_icon status}} |
{{/each}}

{{#if (gt overall.critical_failures 0)}}
## Critical Failures

{{#each sections}}
{{#if failures}}
### Section {{section}}

{{#each failures}}
- **{{test_name}}** ({{requirement_level}}): {{error_message}}
{{/each}}

{{/if}}
{{/each}}
{{/if}}

---

*This report was automatically generated by the RaptorQ RFC 6330 conformance system.*
"#;

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .score-{{overall.conformance_level}} {
            background: {{#if (eq overall.conformance_level "FullyConformant")}}#d4edda{{else}}{{#if (eq overall.conformance_level "MostlyConformant")}}#d1ecf1{{else}}{{#if (eq overall.conformance_level "PartiallyConformant")}}#fff3cd{{else}}#f8d7da{{/if}}{{/if}}{{/if}};
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid {{#if (eq overall.conformance_level "FullyConformant")}}#28a745{{else}}{{#if (eq overall.conformance_level "MostlyConformant")}}#17a2b8{{else}}{{#if (eq overall.conformance_level "PartiallyConformant")}}#ffc107{{else}}#dc3545{{/if}}{{/if}}{{/if}};
        }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .failures { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p><strong>Generated:</strong> {{generated_at}}</p>
        <p><strong>Git Commit:</strong> <code>{{git_commit}}</code></p>
        <div class="score-{{overall.conformance_level}}">
            <strong>Overall Score:</strong> {{percentage overall.compliance_score 1}}
            ({{overall.conformance_level.description}})
        </div>
    </div>

    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>MUST</th><th>SHOULD</th><th>MAY</th><th>Total</th></tr>
        <tr>
            <td><strong>Requirements</strong></td>
            <td>{{overall.must_total}}</td>
            <td>{{overall.should_total}}</td>
            <td>{{overall.may_total}}</td>
            <td>{{overall.total_tests}}</td>
        </tr>
        <tr>
            <td><strong>Passing</strong></td>
            <td>{{overall.must_passing}}</td>
            <td>{{overall.should_passing}}</td>
            <td>{{overall.may_passing}}</td>
            <td>{{overall.passing_tests}}</td>
        </tr>
        <tr>
            <td><strong>Pass Rate</strong></td>
            <td>{{percentage overall.must_passing overall.must_total}}</td>
            <td>{{percentage overall.should_passing overall.should_total}}</td>
            <td>{{percentage overall.may_passing overall.may_total}}</td>
            <td>{{percentage overall.passing_tests overall.total_tests}}</td>
        </tr>
    </table>

    <h2>Section Breakdown</h2>
    <table>
        <tr><th>Section</th><th>MUST</th><th>SHOULD</th><th>MAY</th><th>Score</th><th>Status</th></tr>
        {{#each sections}}
        <tr>
            <td>{{section}}</td>
            <td>{{must_passing}}/{{must_total}}</td>
            <td>{{should_passing}}/{{should_total}}</td>
            <td>{{may_passing}}/{{may_total}}</td>
            <td>{{percentage score 1}}</td>
            <td class="{{#if (eq status "Pass")}}pass{{else}}fail{{/if}}">{{status_icon status}}</td>
        </tr>
        {{/each}}
    </table>

    {{#if overall.critical_failures}}
    <h2>Critical Failures</h2>
    {{#each sections}}
    {{#if failures}}
    <h3>Section {{section}}</h3>
    <div class="failures">
        {{#each failures}}
        <p><strong>{{test_name}}</strong> ({{requirement_level}}): {{error_message}}</p>
        {{/each}}
    </div>
    {{/if}}
    {{/each}}
    {{/if}}

    <hr>
    <p><em>This report was automatically generated by the RaptorQ RFC 6330 conformance system.</em></p>
</body>
</html>
"#;

const BADGE_TEMPLATE: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="180" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="180" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h90v20H0z"/>
    <path fill="{{badge_color level}}" d="M90 0h90v20H90z"/>
    <path fill="url(#b)" d="M0 0h180v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="45" y="15" fill="#010101" fill-opacity=".3">RFC 6330</text>
    <text x="45" y="14">RFC 6330</text>
    <text x="135" y="15" fill="#010101" fill-opacity=".3">{{percentage score 1}} Conformant</text>
    <text x="135" y="14">{{percentage score 1}} Conformant</text>
  </g>
</svg>"#;

const CI_SUMMARY_TEMPLATE: &str = r#"{
  "conformance": {
    "score": {{overall.compliance_score}},
    "level": "{{overall.conformance_level}}",
    "must_passing": {{overall.must_passing}},
    "must_total": {{overall.must_total}},
    "should_passing": {{overall.should_passing}},
    "should_total": {{overall.should_total}},
    "critical_failures": {{overall.critical_failures}},
    "generated_at": "{{generated_at}}",
    "git_commit": "{{git_commit}}"
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage_matrix::*;

    fn create_test_matrix() -> CoverageMatrix {
        let mut sections = BTreeMap::new();
        sections.insert(
            "4.1".to_string(),
            SectionCoverage {
                section: "4.1".to_string(),
                must_total: 2,
                must_passing: 2,
                should_total: 1,
                should_passing: 1,
                may_total: 1,
                may_passing: 0,
                score: 0.95,
                conformance_status: SectionConformanceStatus::Pass,
                failures: Vec::new(),
            },
        );

        CoverageMatrix {
            sections,
            overall: OverallCoverage {
                must_total: 2,
                must_passing: 2,
                should_total: 1,
                should_passing: 1,
                may_total: 1,
                may_passing: 0,
                total_tests: 4,
                passing_tests: 3,
            },
            compliance_score: 0.95,
            conformance_level: ConformanceLevel::MostlyConformant,
            generated_at: chrono::Utc::now(),
            git_commit: Some("abc123".to_string()),
        }
    }

    #[test]
    fn test_report_generator_creation() {
        let config = ReportConfig::default();
        let generator = ComplianceReportGenerator::new(config);
        assert!(generator.is_ok());
    }

    #[test]
    fn test_template_context_creation() {
        let config = ReportConfig::default();
        let generator = ComplianceReportGenerator::new(config).unwrap();
        let matrix = create_test_matrix();

        let context = generator.create_template_context(&matrix);
        assert_eq!(context.sections.len(), 1);
        assert_eq!(context.overall.compliance_score, 0.95);
    }

    #[test]
    fn test_report_summary_creation() {
        let config = ReportConfig::default();
        let generator = ComplianceReportGenerator::new(config).unwrap();
        let matrix = create_test_matrix();

        let summary = generator.create_report_summary(&matrix);
        assert_eq!(summary.total_sections, 1);
        assert_eq!(summary.passing_sections, 1);
        assert_eq!(summary.failing_sections, 0);
        assert!(!summary.recommendations.is_empty());
    }
}