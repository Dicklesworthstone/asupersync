//! Spec-to-test traceability matrix generation.
//!
//! This module provides tools for tracking which specification requirements
//! are covered by which tests, generating coverage reports, and identifying
//! gaps in test coverage.
//!
//! # Example
//!
//! ```ignore
//! use conformance::traceability::{TraceabilityMatrix, TraceabilityEntry, SpecRequirement};
//!
//! // Define specification requirements
//! let requirements = vec![
//!     SpecRequirement::new("3.2.1", "Region close waits for all children"),
//!     SpecRequirement::new("3.2.2", "Orphan tasks are prevented"),
//! ];
//!
//! // Create matrix with test mappings
//! let mut matrix = TraceabilityMatrix::new(requirements);
//! matrix.add_test_mapping("3.2.1", "test_region_close_waits", "tests/region.rs", 42);
//!
//! // Generate reports
//! println!("Coverage: {:.1}%", matrix.coverage_percentage());
//! println!("{}", matrix.to_markdown());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A specification requirement that should be covered by tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecRequirement {
    /// Section identifier (e.g., "3.2.1").
    pub section: String,
    /// Human-readable requirement description.
    pub description: String,
    /// Optional category for grouping.
    pub category: Option<String>,
    /// Priority level (higher = more important).
    pub priority: u8,
}

impl SpecRequirement {
    /// Create a new specification requirement.
    pub fn new(section: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            section: section.into(),
            description: description.into(),
            category: None,
            priority: 1,
        }
    }

    /// Set the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
}

/// An entry linking a test to a specification requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceabilityEntry {
    /// The specification section this test covers.
    pub spec_section: String,
    /// The requirement description.
    pub requirement: String,
    /// Name of the test function.
    pub test_name: String,
    /// Path to the test file.
    pub test_file: PathBuf,
    /// Line number in the test file.
    pub test_line: u32,
    /// Optional tags for filtering.
    pub tags: Vec<String>,
}

impl TraceabilityEntry {
    /// Create a new traceability entry.
    pub fn new(
        spec_section: impl Into<String>,
        requirement: impl Into<String>,
        test_name: impl Into<String>,
        test_file: impl Into<PathBuf>,
        test_line: u32,
    ) -> Self {
        Self {
            spec_section: spec_section.into(),
            requirement: requirement.into(),
            test_name: test_name.into(),
            test_file: test_file.into(),
            test_line,
            tags: Vec::new(),
        }
    }

    /// Add tags to this entry.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Warning emitted while scanning for traceability metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanWarning {
    /// File that triggered the warning.
    pub file: PathBuf,
    /// Line number in the file (1-based).
    pub line: u32,
    /// Warning message.
    pub message: String,
}

impl ScanWarning {
    fn new(file: PathBuf, line: u32, message: impl Into<String>) -> Self {
        Self {
            file,
            line,
            message: message.into(),
        }
    }
}

/// Result of scanning source files for `#[conformance]` attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceabilityScan {
    /// Discovered traceability entries.
    pub entries: Vec<TraceabilityEntry>,
    /// Non-fatal warnings encountered during scanning.
    pub warnings: Vec<ScanWarning>,
}

/// Errors that prevent traceability scanning from completing.
#[derive(Debug)]
pub struct TraceabilityScanError {
    /// Path that triggered the error.
    pub path: PathBuf,
    /// Underlying I/O error.
    pub source: io::Error,
}

impl fmt::Display for TraceabilityScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "traceability scan failed for {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for TraceabilityScanError {}

/// Scan a list of paths for `#[conformance]` attributes.
///
/// Directories are walked recursively and `.rs` files are scanned.
pub fn scan_conformance_attributes(
    paths: &[PathBuf],
) -> Result<TraceabilityScan, TraceabilityScanError> {
    let mut files = Vec::new();
    for path in paths {
        collect_rs_files(path, &mut files)?;
    }

    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for file in files {
        let scan = scan_file_for_conformance(&file)?;
        entries.extend(scan.entries);
        warnings.extend(scan.warnings);
    }

    Ok(TraceabilityScan { entries, warnings })
}

/// Derive requirements from traceability entries.
pub fn requirements_from_entries(entries: &[TraceabilityEntry]) -> Vec<SpecRequirement> {
    let mut by_section: BTreeMap<String, String> = BTreeMap::new();
    for entry in entries {
        by_section
            .entry(entry.spec_section.clone())
            .or_insert_with(|| entry.requirement.clone());
    }
    by_section
        .into_iter()
        .map(|(section, description)| SpecRequirement::new(section, description))
        .collect()
}

/// A matrix tracking specification requirements and their test coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceabilityMatrix {
    /// All specification requirements.
    pub requirements: Vec<SpecRequirement>,
    /// Entries mapping tests to requirements.
    pub entries: Vec<TraceabilityEntry>,
    /// Cached coverage data (section -> test names).
    #[serde(skip)]
    coverage_cache: HashMap<String, Vec<String>>,
}

impl TraceabilityMatrix {
    /// Create a new traceability matrix with the given requirements.
    pub fn new(requirements: Vec<SpecRequirement>) -> Self {
        Self {
            requirements,
            entries: Vec::new(),
            coverage_cache: HashMap::new(),
        }
    }

    /// Create a traceability matrix from requirements and entries.
    pub fn from_entries(
        requirements: Vec<SpecRequirement>,
        entries: Vec<TraceabilityEntry>,
    ) -> Self {
        let mut matrix = TraceabilityMatrix::new(requirements);
        for entry in entries {
            matrix.add_entry(entry);
        }
        matrix
    }

    /// Create an empty matrix.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Add a specification requirement.
    pub fn add_requirement(&mut self, requirement: SpecRequirement) {
        self.requirements.push(requirement);
        self.invalidate_cache();
    }

    /// Add a test mapping.
    pub fn add_test_mapping(
        &mut self,
        spec_section: impl Into<String>,
        test_name: impl Into<String>,
        test_file: impl Into<PathBuf>,
        test_line: u32,
    ) {
        let section = spec_section.into();
        let requirement = self
            .requirements
            .iter()
            .find(|r| r.section == section)
            .map(|r| r.description.clone())
            .unwrap_or_default();

        self.entries.push(TraceabilityEntry::new(
            section,
            requirement,
            test_name,
            test_file,
            test_line,
        ));
        self.invalidate_cache();
    }

    /// Add a complete traceability entry.
    pub fn add_entry(&mut self, entry: TraceabilityEntry) {
        self.entries.push(entry);
        self.invalidate_cache();
    }

    /// Build the coverage cache.
    fn build_cache(&mut self) {
        self.coverage_cache.clear();
        for entry in &self.entries {
            self.coverage_cache
                .entry(entry.spec_section.clone())
                .or_default()
                .push(entry.test_name.clone());
        }
    }

    /// Invalidate the coverage cache.
    fn invalidate_cache(&mut self) {
        self.coverage_cache.clear();
    }

    /// Ensure the cache is populated.
    fn ensure_cache(&mut self) {
        if self.coverage_cache.is_empty() && !self.entries.is_empty() {
            self.build_cache();
        }
    }

    /// Get the sections that are covered by at least one test.
    pub fn covered_sections(&mut self) -> HashSet<String> {
        self.ensure_cache();
        self.coverage_cache.keys().cloned().collect()
    }

    /// Get the sections that have no test coverage.
    pub fn missing_sections(&mut self) -> Vec<String> {
        self.ensure_cache();
        self.requirements
            .iter()
            .filter(|r| !self.coverage_cache.contains_key(&r.section))
            .map(|r| r.section.clone())
            .collect()
    }

    /// Get tests covering a specific section.
    pub fn tests_for_section(&mut self, section: &str) -> Vec<&TraceabilityEntry> {
        self.entries
            .iter()
            .filter(|e| e.spec_section == section)
            .collect()
    }

    /// Calculate coverage percentage.
    pub fn coverage_percentage(&mut self) -> f64 {
        if self.requirements.is_empty() {
            return 100.0;
        }
        let covered = self.covered_sections();
        (covered.len() as f64 / self.requirements.len() as f64) * 100.0
    }

    /// Get coverage statistics.
    pub fn coverage_stats(&mut self) -> CoverageStats {
        self.ensure_cache();
        let covered = self.covered_sections();
        CoverageStats {
            total_requirements: self.requirements.len(),
            covered_requirements: covered.len(),
            missing_requirements: self.requirements.len() - covered.len(),
            total_tests: self.entries.len(),
            coverage_percentage: self.coverage_percentage(),
        }
    }

    /// Generate a markdown report.
    pub fn to_markdown(&mut self) -> String {
        self.ensure_cache();
        let mut output = String::new();

        // Header
        output.push_str("# Specification Traceability Matrix\n\n");

        // Summary
        let stats = self.coverage_stats();
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- **Total Requirements:** {}\n",
            stats.total_requirements
        ));
        output.push_str(&format!(
            "- **Covered Requirements:** {}\n",
            stats.covered_requirements
        ));
        output.push_str(&format!(
            "- **Missing Requirements:** {}\n",
            stats.missing_requirements
        ));
        output.push_str(&format!("- **Total Tests:** {}\n", stats.total_tests));
        output.push_str(&format!(
            "- **Coverage:** {:.1}%\n\n",
            stats.coverage_percentage
        ));

        // Coverage Matrix
        output.push_str("## Coverage Matrix\n\n");
        output.push_str("| Section | Requirement | Tests | Status |\n");
        output.push_str("|---------|-------------|-------|--------|\n");

        for req in &self.requirements {
            let tests = self
                .coverage_cache
                .get(&req.section)
                .map(|t| t.join(", "))
                .unwrap_or_else(|| "-".to_string());
            let status = if self.coverage_cache.contains_key(&req.section) {
                "Covered"
            } else {
                "**MISSING**"
            };
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                req.section, req.description, tests, status
            ));
        }

        // Missing sections
        let missing = self.missing_sections();
        if !missing.is_empty() {
            output.push_str("\n## Missing Coverage\n\n");
            output.push_str("The following specification sections have no test coverage:\n\n");
            for section in &missing {
                if let Some(req) = self.requirements.iter().find(|r| r.section == *section) {
                    output.push_str(&format!("- **{}**: {}\n", section, req.description));
                } else {
                    output.push_str(&format!("- **{}**\n", section));
                }
            }
        }

        // Test Details
        output.push_str("\n## Test Details\n\n");
        output.push_str("| Test | File | Line | Covers |\n");
        output.push_str("|------|------|------|--------|\n");

        for entry in &self.entries {
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                entry.test_name,
                entry.test_file.display(),
                entry.test_line,
                entry.spec_section
            ));
        }

        output
    }

    /// Generate a JSON report.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Check if coverage meets a threshold.
    pub fn meets_threshold(&mut self, threshold_percent: f64) -> bool {
        self.coverage_percentage() >= threshold_percent
    }

    /// Get a coverage report suitable for CI.
    pub fn ci_report(&mut self) -> CiReport {
        let stats = self.coverage_stats();
        let missing = self.missing_sections();
        CiReport {
            passed: missing.is_empty(),
            coverage_percentage: stats.coverage_percentage,
            total_requirements: stats.total_requirements,
            covered_requirements: stats.covered_requirements,
            missing_sections: missing,
        }
    }
}

impl Default for TraceabilityMatrix {
    fn default() -> Self {
        Self::empty()
    }
}

/// Coverage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Total number of requirements.
    pub total_requirements: usize,
    /// Number of requirements with at least one test.
    pub covered_requirements: usize,
    /// Number of requirements without any test.
    pub missing_requirements: usize,
    /// Total number of test entries.
    pub total_tests: usize,
    /// Coverage percentage (0-100).
    pub coverage_percentage: f64,
}

/// CI-friendly report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiReport {
    /// Whether all requirements are covered.
    pub passed: bool,
    /// Coverage percentage.
    pub coverage_percentage: f64,
    /// Total requirements.
    pub total_requirements: usize,
    /// Covered requirements.
    pub covered_requirements: usize,
    /// List of missing sections.
    pub missing_sections: Vec<String>,
}

impl fmt::Display for CiReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Coverage: {:.1}% ({}/{} requirements)",
            self.coverage_percentage, self.covered_requirements, self.total_requirements
        )?;
        if !self.missing_sections.is_empty() {
            writeln!(f, "Missing: {}", self.missing_sections.join(", "))?;
        }
        if self.passed {
            writeln!(f, "Status: PASSED")
        } else {
            writeln!(f, "Status: FAILED")
        }
    }
}

/// Builder for creating a TraceabilityMatrix from test metadata.
#[derive(Debug, Default)]
pub struct TraceabilityMatrixBuilder {
    requirements: Vec<SpecRequirement>,
    entries: Vec<TraceabilityEntry>,
}

impl TraceabilityMatrixBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a requirement.
    pub fn requirement(mut self, section: &str, description: &str) -> Self {
        self.requirements
            .push(SpecRequirement::new(section, description));
        self
    }

    /// Add a requirement with category.
    pub fn requirement_with_category(
        mut self,
        section: &str,
        description: &str,
        category: &str,
    ) -> Self {
        self.requirements
            .push(SpecRequirement::new(section, description).with_category(category));
        self
    }

    /// Add a test mapping.
    pub fn test(
        mut self,
        spec_section: &str,
        test_name: &str,
        test_file: &str,
        test_line: u32,
    ) -> Self {
        let requirement = self
            .requirements
            .iter()
            .find(|r| r.section == spec_section)
            .map(|r| r.description.clone())
            .unwrap_or_default();

        self.entries.push(TraceabilityEntry::new(
            spec_section,
            requirement,
            test_name,
            test_file,
            test_line,
        ));
        self
    }

    /// Build the matrix.
    pub fn build(self) -> TraceabilityMatrix {
        let mut matrix = TraceabilityMatrix::new(self.requirements);
        matrix.entries = self.entries;
        matrix
    }
}

/// Macro for defining traceability entries inline.
///
/// # Example
///
/// ```ignore
/// let entries = trace_entries![
///     ("3.2.1", "test_region_close", "tests/region.rs", 42),
///     ("3.2.2", "test_no_orphans", "tests/region.rs", 100),
/// ];
/// ```
#[macro_export]
macro_rules! trace_entries {
    ($(($section:expr, $test:expr, $file:expr, $line:expr)),* $(,)?) => {
        vec![
            $(
                $crate::traceability::TraceabilityEntry::new(
                    $section,
                    "", // Requirement filled in by matrix
                    $test,
                    $file,
                    $line,
                ),
            )*
        ]
    };
}

fn collect_rs_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), TraceabilityScanError> {
    if path.is_dir() {
        let entries = fs::read_dir(path).map_err(|err| TraceabilityScanError {
            path: path.to_path_buf(),
            source: err,
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| TraceabilityScanError {
                path: path.to_path_buf(),
                source: err,
            })?;
            let entry_path = entry.path();
            collect_rs_files(&entry_path, out)?;
        }
        return Ok(());
    }

    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext == "rs")
        .unwrap_or(false)
    {
        out.push(path.to_path_buf());
    }

    Ok(())
}

fn scan_file_for_conformance(path: &Path) -> Result<TraceabilityScan, TraceabilityScanError> {
    let content = fs::read_to_string(path).map_err(|err| TraceabilityScanError {
        path: path.to_path_buf(),
        source: err,
    })?;

    let lines: Vec<&str> = content.lines().collect();
    let mut pending = Vec::new();
    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim_start();

        if trimmed.starts_with("#[conformance") {
            let mut attr = trimmed.to_string();
            let start_line = index + 1;
            while !attr.contains(']') && index + 1 < lines.len() {
                index += 1;
                attr.push('\n');
                attr.push_str(lines[index]);
            }
            match parse_conformance_attribute(&attr) {
                Ok(args) => pending.push(args),
                Err(message) => warnings.push(ScanWarning::new(
                    path.to_path_buf(),
                    start_line as u32,
                    message,
                )),
            }
            index += 1;
            continue;
        }

        if let Some(name) = parse_fn_name(trimmed)
            && !pending.is_empty()
        {
            let line_number = (index + 1) as u32;
            for args in pending.drain(..) {
                entries.push(TraceabilityEntry::new(
                    args.spec,
                    args.requirement,
                    name.clone(),
                    path.to_path_buf(),
                    line_number,
                ));
            }
        }

        index += 1;
    }

    if !pending.is_empty() {
        for args in pending {
            warnings.push(ScanWarning::new(
                path.to_path_buf(),
                0,
                format!(
                    "conformance attribute for spec '{}' was not followed by a test function",
                    args.spec
                ),
            ));
        }
    }

    Ok(TraceabilityScan { entries, warnings })
}

#[derive(Debug, Clone)]
struct ConformanceArgs {
    spec: String,
    requirement: String,
}

fn parse_conformance_attribute(input: &str) -> Result<ConformanceArgs, String> {
    let start = input
        .find("conformance")
        .ok_or_else(|| "missing conformance attribute".to_string())?;
    let after = &input[start..];
    let open = after
        .find('(')
        .ok_or_else(|| "conformance attribute missing '('".to_string())?;
    let close = after
        .rfind(')')
        .ok_or_else(|| "conformance attribute missing ')'".to_string())?;
    if close <= open {
        return Err("conformance attribute has malformed arguments".to_string());
    }
    let args = &after[open + 1..close];
    parse_conformance_args(args)
}

fn parse_conformance_args(input: &str) -> Result<ConformanceArgs, String> {
    let mut spec = None;
    let mut requirement = None;

    for part in split_args(input) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = split_key_value(part)?;
        let value = parse_string_literal(value)?;
        match key {
            "spec" => spec = Some(value),
            "requirement" => requirement = Some(value),
            other => {
                return Err(format!(
                    "conformance attribute has unknown key '{other}', expected 'spec' or 'requirement'"
                ));
            }
        }
    }

    let spec = spec.ok_or_else(|| "conformance attribute missing 'spec'".to_string())?;
    let requirement =
        requirement.ok_or_else(|| "conformance attribute missing 'requirement'".to_string())?;

    Ok(ConformanceArgs { spec, requirement })
}

fn split_args(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;

    for ch in input.chars() {
        if in_string {
            current.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            ',' => {
                parts.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        parts.push(current);
    }

    parts
}

fn split_key_value(input: &str) -> Result<(&str, &str), String> {
    let mut iter = input.splitn(2, '=');
    let key = iter
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "conformance attribute expects key = \"value\" pairs".to_string())?;
    let value = iter
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("conformance attribute missing value for '{key}'"))?;
    Ok((key, value))
}

fn parse_string_literal(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('"') || !trimmed.ends_with('"') {
        return Err(format!(
            "conformance attribute values must be string literals, got: {trimmed}"
        ));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let next = chars.next().ok_or_else(|| {
                "conformance attribute contains dangling escape sequence".to_string()
            })?;
            match next {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => {
                    return Err(format!(
                        "conformance attribute contains unsupported escape: \\{other}"
                    ));
                }
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn parse_fn_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
    {
        return None;
    }

    let mut saw_fn = false;
    for token in trimmed.split_whitespace() {
        if saw_fn {
            let name = token
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
                .collect::<String>();
            if name.is_empty() {
                return None;
            }
            return Some(name);
        }
        if token == "fn" {
            saw_fn = true;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_requirement_new() {
        let req = SpecRequirement::new("3.2.1", "Region close waits for children");
        assert_eq!(req.section, "3.2.1");
        assert_eq!(req.description, "Region close waits for children");
        assert!(req.category.is_none());
        assert_eq!(req.priority, 1);
    }

    #[test]
    fn test_spec_requirement_with_category() {
        let req = SpecRequirement::new("3.2.1", "Test")
            .with_category("regions")
            .with_priority(5);
        assert_eq!(req.category, Some("regions".to_string()));
        assert_eq!(req.priority, 5);
    }

    #[test]
    fn test_traceability_entry_new() {
        let entry = TraceabilityEntry::new("3.2.1", "Requirement", "test_foo", "tests/foo.rs", 42);
        assert_eq!(entry.spec_section, "3.2.1");
        assert_eq!(entry.test_name, "test_foo");
        assert_eq!(entry.test_file, PathBuf::from("tests/foo.rs"));
        assert_eq!(entry.test_line, 42);
    }

    #[test]
    fn test_empty_matrix_coverage() {
        let mut matrix = TraceabilityMatrix::empty();
        assert_eq!(matrix.coverage_percentage(), 100.0);
    }

    #[test]
    fn test_matrix_with_requirements_no_tests() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        assert_eq!(matrix.coverage_percentage(), 0.0);
        assert_eq!(matrix.missing_sections().len(), 2);
    }

    #[test]
    fn test_matrix_partial_coverage() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);

        assert_eq!(matrix.coverage_percentage(), 50.0);
        assert_eq!(matrix.missing_sections(), vec!["3.2.2".to_string()]);
    }

    #[test]
    fn test_matrix_full_coverage() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);
        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);

        assert_eq!(matrix.coverage_percentage(), 100.0);
        assert!(matrix.missing_sections().is_empty());
    }

    #[test]
    fn test_coverage_stats() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
            SpecRequirement::new("3.2.3", "Req 3"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);
        matrix.add_test_mapping("3.2.1", "test_req1_extra", "tests/test.rs", 15);
        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);

        let stats = matrix.coverage_stats();
        assert_eq!(stats.total_requirements, 3);
        assert_eq!(stats.covered_requirements, 2);
        assert_eq!(stats.missing_requirements, 1);
        assert_eq!(stats.total_tests, 3);
        assert!((stats.coverage_percentage - 66.666).abs() < 0.1);
    }

    #[test]
    fn test_meets_threshold() {
        let mut matrix = TraceabilityMatrix::new(vec![
            SpecRequirement::new("3.2.1", "Req 1"),
            SpecRequirement::new("3.2.2", "Req 2"),
        ]);
        matrix.add_test_mapping("3.2.1", "test_req1", "tests/test.rs", 10);

        assert!(matrix.meets_threshold(50.0));
        assert!(!matrix.meets_threshold(51.0));
    }

    #[test]
    fn test_builder() {
        let matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .requirement("3.2.2", "Req 2")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        assert_eq!(matrix.requirements.len(), 2);
        assert_eq!(matrix.entries.len(), 1);
    }

    #[test]
    fn test_markdown_output() {
        let mut matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Region close waits")
            .requirement("3.2.2", "No orphan tasks")
            .test("3.2.1", "test_region_close", "tests/region.rs", 42)
            .build();

        let md = matrix.to_markdown();
        assert!(md.contains("# Specification Traceability Matrix"));
        assert!(md.contains("3.2.1"));
        assert!(md.contains("Region close waits"));
        assert!(md.contains("test_region_close"));
        assert!(md.contains("MISSING"));
    }

    #[test]
    fn test_json_roundtrip() {
        let matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        let json = matrix.to_json().unwrap();
        let loaded = TraceabilityMatrix::from_json(&json).unwrap();

        assert_eq!(matrix.requirements.len(), loaded.requirements.len());
        assert_eq!(matrix.entries.len(), loaded.entries.len());
    }

    #[test]
    fn test_ci_report() {
        let mut matrix = TraceabilityMatrixBuilder::new()
            .requirement("3.2.1", "Req 1")
            .requirement("3.2.2", "Req 2")
            .test("3.2.1", "test_req1", "tests/test.rs", 10)
            .build();

        let report = matrix.ci_report();
        assert!(!report.passed);
        assert_eq!(report.missing_sections, vec!["3.2.2".to_string()]);

        matrix.add_test_mapping("3.2.2", "test_req2", "tests/test.rs", 20);
        let report = matrix.ci_report();
        assert!(report.passed);
        assert!(report.missing_sections.is_empty());
    }

    #[test]
    fn test_scan_conformance_attributes_basic() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("example.rs");
        let contents = concat!(
            "#[conformance(spec = \"3.2.1\", requirement = \"Region close waits\")]\n",
            "#[test]\n",
            "fn test_region_close() {}\n"
        );
        std::fs::write(&file, contents).unwrap();

        let scan = scan_conformance_attributes(std::slice::from_ref(&file)).unwrap();
        assert!(scan.warnings.is_empty());
        assert_eq!(scan.entries.len(), 1);
        let entry = &scan.entries[0];
        assert_eq!(entry.spec_section, "3.2.1");
        assert_eq!(entry.requirement, "Region close waits");
        assert_eq!(entry.test_name, "test_region_close");
        assert_eq!(entry.test_line, 3);
    }

    #[test]
    fn test_scan_multiple_conformance_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("example.rs");
        let contents = concat!(
            "#[conformance(spec = \"3.2.1\", requirement = \"Region close waits\")]\n",
            "#[conformance(spec = \"3.2.2\", requirement = \"No orphan tasks\")]\n",
            "#[test]\n",
            "fn test_region_close() {}\n"
        );
        std::fs::write(&file, contents).unwrap();

        let scan = scan_conformance_attributes(std::slice::from_ref(&file)).unwrap();
        assert!(scan.warnings.is_empty());
        assert_eq!(scan.entries.len(), 2);
        assert!(
            scan.entries
                .iter()
                .any(|entry| entry.spec_section == "3.2.1")
        );
        assert!(
            scan.entries
                .iter()
                .any(|entry| entry.spec_section == "3.2.2")
        );
    }
}
