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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_capture_stack_trace() {
        let trace = capture_stack_trace();

        // Should not be empty
        assert!(!trace.is_empty());

        // When stack traces are enabled, should contain "Stack trace:"
        // When disabled, should contain "disabled"
        #[cfg(feature = "lab-stack-traces")]
        assert!(trace.contains("Stack trace:"));

        #[cfg(not(feature = "lab-stack-traces"))]
        assert!(trace.contains("disabled"));
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

        // Frame count should be reasonable
        let frame_count = trace.frame_count();
        assert!(frame_count > 0);
    }

    #[test]
    fn test_stack_trace_from_deep_call() {
        fn level_1() -> StackTrace {
            level_2()
        }

        fn level_2() -> StackTrace {
            level_3()
        }

        fn level_3() -> StackTrace {
            StackTrace::capture()
        }

        let trace = level_1();

        // Should contain function names (when feature enabled)
        #[cfg(feature = "lab-stack-traces")]
        {
            let trace_str = trace.as_str();
            assert!(
                trace_str.contains("level_1")
                    || trace_str.contains("level_2")
                    || trace_str.contains("level_3")
            );
        }

        // Should have multiple frames
        assert!(trace.frame_count() > 1);
    }

    #[test]
    fn test_compact_formatting() {
        // Create a trace with many lines to test compacting
        let long_trace = StackTrace {
            trace: (0..10)
                .map(|i| format!("  {}: function_{}", i, i))
                .collect::<Vec<_>>()
                .join("\n"),
        };

        let compact = long_trace.compact();

        // Should contain ellipsis for truncated traces
        if long_trace.frame_count() > 5 {
            assert!(compact.contains("... ("));
            assert!(compact.contains("more frames)"));
        }
    }

    #[test]
    fn test_filter_frames() {
        let trace = StackTrace {
            trace: "Stack trace:\n  0: my_function\n  1: std::panic\n  2: other_function\n  3: std::thread".to_string(),
        };

        let filtered = trace.filter_frames("std::");
        assert!(filtered.as_str().contains("std::panic"));
        assert!(filtered.as_str().contains("std::thread"));
        assert!(!filtered.as_str().contains("my_function"));
        assert!(!filtered.as_str().contains("other_function"));
    }

    #[test]
    fn test_feature_flag_behavior() {
        let trace = capture_stack_trace();

        #[cfg(feature = "lab-stack-traces")]
        {
            // With feature enabled, should get real stack trace
            assert!(trace.starts_with("Stack trace:"));
            assert!(trace.lines().count() > 1);
        }

        #[cfg(not(feature = "lab-stack-traces"))]
        {
            // With feature disabled, should get placeholder message
            assert_eq!(
                trace,
                "Stack trace capture disabled (enable 'lab-stack-traces' feature)"
            );
        }
    }

    #[test]
    fn test_performance_characteristics() {
        use std::time::Instant;

        let start = Instant::now();

        // Capture multiple stack traces to measure performance
        for _ in 0..10 {
            let _ = capture_stack_trace();
        }

        let duration = start.elapsed();

        // Performance check - should complete in reasonable time
        // This is a rough check - actual performance depends on feature flag
        #[cfg(feature = "lab-stack-traces")]
        {
            // Real stack traces are slower but should still be under 1 second for 10 captures
            assert!(duration.as_secs() < 1);
        }

        #[cfg(not(feature = "lab-stack-traces"))]
        {
            // Disabled stack traces should be very fast (microseconds)
            assert!(duration.as_millis() < 100);
        }
    }

    #[test]
    fn test_string_conversion() {
        let trace = StackTrace::capture();
        let as_string: String = trace.clone().into();
        assert_eq!(as_string, trace.as_str());
    }

    #[test]
    fn test_debug_formatting() {
        let trace = StackTrace::capture();
        let debug_str = format!("{:?}", trace);
        assert!(debug_str.contains("StackTrace"));
        assert!(debug_str.contains("trace:"));
    }
}
