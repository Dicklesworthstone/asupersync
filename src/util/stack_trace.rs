//! Stack trace capture utilities for debugging oracle violations.
//!
//! This module provides cross-platform stack trace capture functionality
//! for lab oracle modules. Stack trace capture can be enabled/disabled
//! via the `lab-stack-traces` feature flag to control overhead in production.

use std::fmt;

/// Captures a stack trace at the current location.
///
/// When the `lab-stack-traces` feature is enabled, this will capture a real
/// stack trace using the backtrace crate. When disabled, returns a
/// disabled-feature diagnostic string to avoid overhead.
///
/// The captured stack trace includes file names and line numbers when
/// debug information is available.
#[cfg(feature = "lab-stack-traces")]
pub fn capture_stack_trace() -> String {
    use std::fmt::Write;

    let bt = backtrace::Backtrace::new();
    let mut output = String::new();

    let _ = writeln!(&mut output, "Stack trace:");

    for (i, frame) in bt.frames().iter().enumerate() {
        for symbol in frame.symbols() {
            if let Some(name) = symbol.name() {
                let _ = write!(&mut output, "  {}: ", i);

                // Try to demangle the symbol name
                if let Ok(demangled) = rustc_demangle::try_demangle(&name.to_string()) {
                    let _ = write!(&mut output, "{}", demangled);
                } else {
                    let _ = write!(&mut output, "{}", name);
                }

                // Add file and line info if available
                if let (Some(filename), Some(lineno)) = (symbol.filename(), symbol.lineno()) {
                    let _ = write!(&mut output, " at {}:{}", filename.display(), lineno);
                }

                let _ = writeln!(&mut output);
            }
        }
    }

    output
}

/// Returns the disabled-feature diagnostic when stack traces are disabled.
#[cfg(not(feature = "lab-stack-traces"))]
pub fn capture_stack_trace() -> String {
    "Stack trace capture disabled (enable 'lab-stack-traces' feature)".to_string()
}

/// A captured stack trace with formatting options.
#[derive(Debug, Clone)]
pub struct StackTrace {
    trace: String,
}

impl StackTrace {
    /// Captures a new stack trace.
    pub fn capture() -> Self {
        Self {
            trace: capture_stack_trace(),
        }
    }

    /// Returns the raw stack trace string.
    pub fn as_str(&self) -> &str {
        &self.trace
    }

    /// Returns a compact representation of the stack trace (first few frames).
    pub fn compact(&self) -> String {
        let lines: Vec<&str> = self.trace.lines().collect();
        if lines.len() <= 5 {
            return self.trace.clone();
        }

        let mut result = String::new();
        for line in lines.iter().take(5) {
            result.push_str(line);
            result.push('\n');
        }
        result.push_str(&format!("... ({} more frames)\n", lines.len() - 5));
        result
    }

    /// Returns the number of frames in the stack trace.
    pub fn frame_count(&self) -> usize {
        self.trace.lines().count()
    }

    /// Filters the stack trace to only include frames containing the given pattern.
    pub fn filter_frames(&self, pattern: &str) -> Self {
        let filtered_lines: Vec<&str> = self
            .trace
            .lines()
            .filter(|line| line.contains(pattern))
            .collect();

        Self {
            trace: filtered_lines.join("\n"),
        }
    }
}

impl fmt::Display for StackTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.trace)
    }
}

impl From<StackTrace> for String {
    fn from(trace: StackTrace) -> String {
        trace.trace
    }
}

#[cfg(test)]
#[path = "stack_trace_inline_tests.rs"]
mod tests;
