//! Structured error messages for CLI tools.
//!
//! Follows RFC 9457 (Problem Details) style for machine-readable errors
//! with human-friendly formatting.

use super::exit::ExitCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structured error following RFC 9457 (Problem Details) style.
///
/// Provides machine-readable error information with human-friendly presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliError {
    /// Error type identifier (machine-readable).
    #[serde(rename = "type")]
    pub error_type: String,

    /// Short human-readable title.
    pub title: String,

    /// Detailed explanation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,

    /// Suggested action for recovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,

    /// Related documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,

    /// Additional context (varies by error type).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, serde_json::Value>,

    /// Exit code for this error.
    pub exit_code: i32,
}

impl CliError {
    /// Create a new CLI error.
    #[must_use]
    pub fn new(error_type: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            title: title.into(),
            detail: String::new(),
            suggestion: None,
            docs_url: None,
            context: HashMap::new(),
            exit_code: ExitCode::RUNTIME_ERROR,
        }
    }

    /// Add detailed explanation.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Add a suggested recovery action.
    #[must_use]
    pub fn suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }

    /// Add documentation URL.
    #[must_use]
    pub fn docs(mut self, url: impl Into<String>) -> Self {
        self.docs_url = Some(url.into());
        self
    }

    /// Add context field.
    #[must_use]
    pub fn context(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.context.insert(key.into(), v);
        }
        self
    }

    /// Set exit code.
    #[must_use]
    pub const fn exit_code(mut self, code: i32) -> Self {
        self.exit_code = code;
        self
    }

    /// Format for human output.
    ///
    /// When `color` is true, includes ANSI escape codes for terminal coloring.
    #[must_use]
    pub fn human_format(&self, color: bool) -> String {
        let mut out = String::new();

        // Error title in red
        if color {
            out.push_str("\x1b[1;31m"); // Bold red
        }
        out.push_str("Error: ");
        out.push_str(&self.title);
        if color {
            out.push_str("\x1b[0m"); // Reset
        }
        out.push('\n');

        // Detail in normal text
        if !self.detail.is_empty() {
            out.push_str(&self.detail);
            out.push('\n');
        }

        // Suggestion in yellow
        if let Some(ref suggestion) = self.suggestion {
            out.push('\n');
            if color {
                out.push_str("\x1b[33m"); // Yellow
            }
            out.push_str("Suggestion: ");
            out.push_str(suggestion);
            if color {
                out.push_str("\x1b[0m");
            }
            out.push('\n');
        }

        // Docs link in blue/underline
        if let Some(ref docs) = self.docs_url {
            if color {
                out.push_str("\x1b[4;34m"); // Underline blue
            }
            out.push_str("See: ");
            out.push_str(docs);
            if color {
                out.push_str("\x1b[0m");
            }
            out.push('\n');
        }

        // Context in dim
        if !self.context.is_empty() {
            out.push('\n');
            if color {
                out.push_str("\x1b[2m"); // Dim
            }
            out.push_str("Context:\n");
            for (k, v) in &self.context {
                use std::fmt::Write;
                let _ = writeln!(out, "  {k}: {v}");
            }
            if color {
                out.push_str("\x1b[0m");
            }
        }

        out
    }

    /// Format as JSON.
    #[must_use]
    pub fn json_format(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.title.clone())
    }

    /// Format as pretty JSON.
    #[must_use]
    pub fn json_pretty_format(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.title.clone())
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_type, self.title)
    }
}

impl std::error::Error for CliError {}

/// Standard error constructors.
pub mod errors {
    use super::{CliError, ExitCode};

    /// Invalid argument error.
    #[must_use]
    pub fn invalid_argument(arg: &str, reason: &str) -> CliError {
        CliError::new("invalid_argument", format!("Invalid argument: {arg}"))
            .detail(reason)
            .exit_code(ExitCode::USER_ERROR)
    }

    /// File not found error.
    #[must_use]
    pub fn file_not_found(path: &str) -> CliError {
        CliError::new("file_not_found", "File not found")
            .detail(format!("The file '{path}' does not exist"))
            .suggestion("Check the path and try again")
            .context("path", path)
            .exit_code(ExitCode::USER_ERROR)
    }

    /// Permission denied error.
    #[must_use]
    pub fn permission_denied(path: &str) -> CliError {
        CliError::new("permission_denied", "Permission denied")
            .detail(format!("Cannot access '{path}'"))
            .suggestion("Check file permissions or run with appropriate privileges")
            .context("path", path)
            .exit_code(ExitCode::USER_ERROR)
    }

    /// Invariant violation error.
    #[must_use]
    pub fn invariant_violation(invariant: &str, details: &str) -> CliError {
        CliError::new(
            "invariant_violation",
            format!("Invariant violated: {invariant}"),
        )
        .detail(details)
        .docs("https://docs.asupersync.dev/invariants")
        .exit_code(ExitCode::RUNTIME_ERROR)
    }

    /// Parse error.
    #[must_use]
    pub fn parse_error(what: &str, details: &str) -> CliError {
        CliError::new("parse_error", format!("Failed to parse {what}"))
            .detail(details)
            .exit_code(ExitCode::USER_ERROR)
    }

    /// Operation cancelled error.
    #[must_use]
    pub fn cancelled() -> CliError {
        CliError::new("cancelled", "Operation cancelled")
            .detail("The operation was cancelled by user or signal")
            .exit_code(ExitCode::CANCELLED)
    }

    /// Timeout error.
    #[must_use]
    pub fn timeout(operation: &str, duration_ms: u64) -> CliError {
        CliError::new("timeout", format!("Operation timed out: {operation}"))
            .detail(format!("Exceeded timeout after {duration_ms}ms"))
            .context("duration_ms", duration_ms)
            .exit_code(ExitCode::RUNTIME_ERROR)
    }

    /// Internal error (bug).
    #[must_use]
    pub fn internal(details: &str) -> CliError {
        CliError::new("internal_error", "Internal error")
            .detail(details)
            .suggestion("Please report this bug at https://github.com/Dicklesworthstone/asupersync/issues")
            .exit_code(ExitCode::INTERNAL_ERROR)
    }

    /// Test failure error.
    #[must_use]
    pub fn test_failure(test_name: &str, reason: &str) -> CliError {
        CliError::new("test_failure", format!("Test failed: {test_name}"))
            .detail(reason)
            .context("test_name", test_name)
            .exit_code(ExitCode::TEST_FAILURE)
    }

    /// Oracle violation error.
    #[must_use]
    pub fn oracle_violation(oracle: &str, details: &str) -> CliError {
        CliError::new("oracle_violation", format!("Oracle violation: {oracle}"))
            .detail(details)
            .context("oracle", oracle)
            .exit_code(ExitCode::ORACLE_VIOLATION)
    }
}

#[cfg(test)]
mod tests {
    use super::{errors, CliError, ExitCode};

    #[test]
    fn error_serializes_to_json() {
        let error = CliError::new("test_error", "Test Error")
            .detail("Something went wrong")
            .suggestion("Try again")
            .context("file", "test.rs")
            .exit_code(1);

        let json = serde_json::to_string(&error).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "test_error");
        assert_eq!(parsed["title"], "Test Error");
        assert_eq!(parsed["detail"], "Something went wrong");
        assert_eq!(parsed["suggestion"], "Try again");
        assert_eq!(parsed["context"]["file"], "test.rs");
        assert_eq!(parsed["exit_code"], 1);
    }

    #[test]
    fn error_human_format_includes_all_parts() {
        let error = CliError::new("test_error", "Test Error")
            .detail("Details here")
            .suggestion("Try this");

        let human = error.human_format(false);

        assert!(human.contains("Error: Test Error"));
        assert!(human.contains("Details here"));
        assert!(human.contains("Suggestion: Try this"));
    }

    #[test]
    fn error_human_format_no_ansi_when_disabled() {
        let error = CliError::new("test", "Test");
        let human = error.human_format(false);

        assert!(!human.contains("\x1b["));
    }

    #[test]
    fn error_human_format_has_ansi_when_enabled() {
        let error = CliError::new("test", "Test");
        let human = error.human_format(true);

        assert!(human.contains("\x1b["));
    }

    #[test]
    fn error_implements_display() {
        let error = CliError::new("test_type", "Test Title");
        let display = format!("{error}");

        assert!(display.contains("test_type"));
        assert!(display.contains("Test Title"));
    }

    #[test]
    fn standard_errors_have_correct_exit_codes() {
        assert_eq!(
            errors::invalid_argument("foo", "bad").exit_code,
            ExitCode::USER_ERROR
        );
        assert_eq!(
            errors::file_not_found("/path").exit_code,
            ExitCode::USER_ERROR
        );
        assert_eq!(
            errors::permission_denied("/path").exit_code,
            ExitCode::USER_ERROR
        );
        assert_eq!(errors::cancelled().exit_code, ExitCode::CANCELLED);
        assert_eq!(
            errors::internal("bug").exit_code,
            ExitCode::INTERNAL_ERROR
        );
        assert_eq!(
            errors::test_failure("test", "reason").exit_code,
            ExitCode::TEST_FAILURE
        );
        assert_eq!(
            errors::oracle_violation("oracle", "details").exit_code,
            ExitCode::ORACLE_VIOLATION
        );
    }

    #[test]
    fn error_context_accepts_various_types() {
        let error = CliError::new("test", "Test")
            .context("string", "value")
            .context("number", 42)
            .context("bool", true)
            .context("array", vec![1, 2, 3]);

        assert_eq!(error.context.len(), 4);
        assert_eq!(error.context["string"], "value");
        assert_eq!(error.context["number"], 42);
        assert_eq!(error.context["bool"], true);
    }

    #[test]
    fn error_deserializes_from_json() {
        let json = r#"{"type":"test","title":"Test","exit_code":1}"#;
        let error: CliError = serde_json::from_str(json).unwrap();

        assert_eq!(error.error_type, "test");
        assert_eq!(error.title, "Test");
        assert_eq!(error.exit_code, 1);
    }
}
