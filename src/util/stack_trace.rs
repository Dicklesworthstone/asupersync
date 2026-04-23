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
/// placeholder message to avoid overhead.
///
/// The captured stack trace includes file names and line numbers when
/// debug information is available.
#[cfg(feature = "lab-stack-traces")]
pub fn capture_stack_trace() -> String {
    use std::fmt::Write;

    let bt = backtrace::Backtrace::new();
    let mut output = String::new();

    writeln!(&mut output, "Stack trace:").unwrap();

    for (i, frame) in bt.frames().iter().enumerate() {
        for symbol in frame.symbols() {
            if let Some(name) = symbol.name() {
                write!(&mut output, "  {}: ", i).unwrap();

                // Try to demangle the symbol name
                if let Ok(demangled) = rustc_demangle::try_demangle(&name.to_string()) {
                    write!(&mut output, "{}", demangled).unwrap();
                } else {
                    write!(&mut output, "{}", name).unwrap();
                }

                // Add file and line info if available
                if let (Some(filename), Some(lineno)) = (symbol.filename(), symbol.lineno()) {
                    write!(&mut output, " at {}:{}", filename.display(), lineno).unwrap();
                }

                writeln!(&mut output).unwrap();
            }
        }
    }

    output
}

/// Returns a placeholder message when stack traces are disabled.
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
mod tests {
    use super::*;

    #[test]
    fn test_capture_stack_trace() {
        let trace = capture_stack_trace();

        // Should not be empty
        assert!(!trace.is_empty());

        // When stack traces are enabled, should contain "Stack trace:"
        // When disabled, should contain "disabled"
        assert!(trace.contains("Stack trace:") || trace.contains("disabled"));
    }

    #[test]
    fn test_stack_trace_wrapper() {
        let trace = StackTrace::capture();

        // Should not be empty
        assert!(!trace.as_str().is_empty());

        // Display trait should work
        let displayed = format!("{}", trace);
        assert_eq!(displayed, trace.as_str());

        // Compact should work
        let compact = trace.compact();
        assert!(!compact.is_empty());
    }
}