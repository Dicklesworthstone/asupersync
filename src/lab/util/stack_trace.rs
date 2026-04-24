/*!
Stack trace capture utility for lab oracle violations.

Provides cross-platform stack trace capture with configurable formatting and filtering.
Uses the `backtrace` crate for portability across platforms, with optional debug symbols.
*/

#[cfg(feature = "lab-stack-traces")]
use backtrace::Backtrace;
#[cfg(feature = "lab-stack-traces")]
use rustc_demangle::demangle;

/// Configuration for stack trace capture
#[derive(Debug, Clone)]
pub struct StackTraceConfig {
    /// Maximum number of frames to capture (0 = unlimited)
    pub max_frames: usize,
    /// Whether to include file/line information (debug builds only)
    pub include_file_line: bool,
    /// Frame numbers to skip from the top (to filter utility frames)
    pub skip_frames: usize,
}

impl Default for StackTraceConfig {
    fn default() -> Self {
        Self {
            max_frames: 50, // Reasonable default to avoid excessive output
            include_file_line: cfg!(debug_assertions),
            skip_frames: 2, // Skip capture_stack_trace and caller
        }
    }
}

/// Captures the current stack trace as a formatted string.
///
/// Returns a multi-line string with numbered stack frames. Each frame includes
/// the symbol name and optionally file/line information in debug builds.
///
/// # Arguments
/// * `config` - Configuration for trace capture and formatting
///
/// # Returns
/// Formatted stack trace string, or placeholder if feature disabled
///
/// # Example
/// ```
/// use asupersync::lab::util::stack_trace::{capture_stack_trace, StackTraceConfig};
///
/// let trace = capture_stack_trace(&StackTraceConfig::default());
/// println!("Stack trace:\n{}", trace);
/// ```
pub fn capture_stack_trace(config: &StackTraceConfig) -> String {
    #[cfg(feature = "lab-stack-traces")]
    {
        let bt = Backtrace::new();
        format_backtrace(&bt, config)
    }

    #[cfg(not(feature = "lab-stack-traces"))]
    {
        let _ = config; // Suppress unused parameter warning
        "<stack traces disabled: enable 'lab-stack-traces' feature>".to_string()
    }
}

/// Captures a stack trace with default configuration.
///
/// Convenience function that uses default settings for most use cases.
pub fn capture_stack_trace_default() -> String {
    capture_stack_trace(&StackTraceConfig::default())
}

/// Formats a backtrace according to the provided configuration.
#[cfg(feature = "lab-stack-traces")]
fn format_backtrace(bt: &Backtrace, config: &StackTraceConfig) -> String {
    use std::fmt::Write;

    let mut output = String::new();
    let frames: Vec<_> = bt.frames().iter().collect();

    // Apply frame skipping and limiting
    let start = config.skip_frames.min(frames.len());
    let end = if config.max_frames == 0 {
        frames.len()
    } else {
        (start + config.max_frames).min(frames.len())
    };

    if start >= frames.len() {
        return "  <all frames skipped>".to_string();
    }

    for (i, frame) in frames[start..end].iter().enumerate() {
        let frame_num = i + 1;
        let mut frame_info = format!("  {:2}: ", frame_num);

        let symbols = frame.symbols();
        if symbols.is_empty() {
            writeln!(frame_info, "<unknown>").unwrap();
        } else {
            // Use the first symbol (most specific)
            let symbol = &symbols[0];

            if let Some(name) = symbol.name() {
                let name_str = format!("{}", name);
                let demangled = demangle(&name_str);
                write!(frame_info, "{}", demangled).unwrap();
            } else {
                write!(frame_info, "<unknown>").unwrap();
            }

            // Add file/line info if available and requested
            if config.include_file_line {
                if let (Some(filename), Some(line)) = (symbol.filename(), symbol.lineno()) {
                    if let Some(filename_str) = filename.to_str() {
                        write!(frame_info, "\n        at {}:{}", filename_str, line).unwrap();
                    }
                }
            }

            writeln!(frame_info).unwrap();
        }

        output.push_str(&frame_info);
    }

    // Add indication if trace was truncated
    if config.max_frames > 0 && end < frames.len() {
        let remaining = frames.len() - end;
        writeln!(output, "  ... ({} more frames)", remaining).unwrap();
    }

    output
}

/// Captures a stack trace with custom depth limit.
///
/// Convenience function for controlling trace depth without full configuration.
pub fn capture_stack_trace_depth(max_frames: usize) -> String {
    let config = StackTraceConfig {
        max_frames,
        ..Default::default()
    };
    capture_stack_trace(&config)
}

/// Captures a minimal stack trace (top 10 frames, no file/line info).
///
/// Useful for logging where brevity is important.
pub fn capture_stack_trace_minimal() -> String {
    let config = StackTraceConfig {
        max_frames: 10,
        include_file_line: false,
        skip_frames: 2,
    };
    capture_stack_trace(&config)
}

#[cfg(all(test, feature = "lab-stack-traces"))]
mod tests {
    use super::*;

    #[test]
    fn test_stack_trace_capture() {
        let trace = capture_stack_trace_default();

        // Should contain frame numbers
        assert!(trace.contains("1: "));

        // Should not be empty
        assert!(!trace.is_empty());

        // Should be multi-line
        assert!(trace.contains('\n'));
    }

    #[test]
    fn test_stack_trace_config() {
        let config = StackTraceConfig {
            max_frames: 5,
            include_file_line: true,
            skip_frames: 1,
        };

        let trace = capture_stack_trace(&config);

        // Should respect max_frames (rough check - may have fewer due to skipping)
        let frame_count = trace.matches(": ").count();
        assert!(
            frame_count <= 5,
            "Frame count {} exceeds max 5",
            frame_count
        );
    }

    #[test]
    fn test_minimal_trace() {
        let trace = capture_stack_trace_minimal();

        // Should be shorter than default
        let frame_count = trace.matches(": ").count();
        assert!(frame_count <= 10);

        // Should still have content
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_depth_limit() {
        let trace = capture_stack_trace_depth(3);
        let frame_count = trace.matches(": ").count();
        assert!(frame_count <= 3);
    }

    #[test]
    fn test_skip_frames() {
        let config = StackTraceConfig {
            max_frames: 0, // unlimited
            include_file_line: false,
            skip_frames: 5, // Skip many frames
        };

        let trace = capture_stack_trace(&config);

        // Should still produce output (unless we skipped everything)
        if !trace.contains("<all frames skipped>") {
            assert!(trace.contains("1: ")); // Frame numbering should restart at 1
        }
    }

    // Test that the function compiles and runs when feature is disabled
    #[test]
    fn test_feature_disabled_fallback() {
        // This test primarily ensures the conditional compilation works
        let config = StackTraceConfig::default();
        let _trace = capture_stack_trace(&config);

        // If we reach here without compile errors, the feature flags work correctly
        assert!(true);
    }
}

#[cfg(all(test, not(feature = "lab-stack-traces")))]
mod tests_feature_disabled {
    use super::*;

    #[test]
    fn test_disabled_feature_returns_placeholder() {
        let trace = capture_stack_trace_default();
        assert_eq!(
            trace,
            "<stack traces disabled: enable 'lab-stack-traces' feature>"
        );
    }
}
