//! CLI utilities for Asupersync tools.
//!
//! This module provides a comprehensive framework for building CLI tools that are
//! both human-friendly and machine-readable. Key features:
//!
//! - **Dual-mode output**: Automatic JSON/human output based on environment
//! - **Structured errors**: RFC 9457-style errors with context and suggestions
//! - **Semantic exit codes**: Machine-parseable exit codes for automation
//! - **Progress reporting**: Streaming progress with cancellation support
//! - **Signal handling**: Graceful shutdown with cancellation tokens
//! - **Shell completions**: Generation for bash, zsh, fish, PowerShell, elvish
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use asupersync::cli::{Output, OutputFormat, CliError, ExitCode};
//!
//! // Auto-detect output format (JSON in CI/pipes, human in terminal)
//! let format = OutputFormat::auto_detect();
//! let mut output = Output::new(format);
//!
//! // Write structured output
//! output.write(&my_data)?;
//!
//! // Handle errors with context
//! let error = CliError::new("config_error", "Invalid configuration")
//!     .detail("The 'timeout' field must be a positive integer")
//!     .suggestion("Set timeout to a value like 30 or 60")
//!     .context("field", "timeout")
//!     .exit_code(ExitCode::USER_ERROR);
//! ```
//!
//! # Output Format Detection
//!
//! The output format is automatically detected based on:
//! 1. `ASUPERSYNC_OUTPUT_FORMAT` environment variable
//! 2. `CI` environment variable (forces JSON)
//! 3. TTY detection (JSON for pipes, human for terminals)
//!
//! # Color Support
//!
//! Colors are automatically enabled for terminals and respect:
//! - `NO_COLOR` environment variable (disables colors)
//! - `CLICOLOR_FORCE` environment variable (forces colors)
//!
//! # Exit Codes
//!
//! Standard exit codes for automation:
//! - 0: Success
//! - 1: User error (bad input)
//! - 2: Runtime error
//! - 3: Internal error (bug)
//! - 4: Cancelled
//! - 5: Partial success
//! - 10-13: Application-specific (test failure, oracle violation, etc.)

pub mod args;
pub mod completion;
pub mod error;
pub mod exit;
pub mod output;
pub mod progress;
pub mod signal;

// Re-export commonly used types
pub use args::{parse_color_choice, parse_output_format, CommonArgs, COMMON_ARGS_HELP};
pub use completion::{generate_completions, Completable, CompletionItem, Shell};
pub use error::{errors, CliError};
pub use exit::ExitCode;
pub use output::{ColorChoice, Output, OutputFormat, Outputtable};
pub use progress::{ProgressEvent, ProgressKind, ProgressReporter};
pub use signal::{CancellationToken, Signal, SignalHandler};

/// Prelude for convenient imports.
///
/// ```rust,ignore
/// use asupersync::cli::prelude::*;
/// ```
pub mod prelude {
    pub use super::args::{CommonArgs, COMMON_ARGS_HELP};
    pub use super::error::{errors, CliError};
    pub use super::exit::ExitCode;
    pub use super::output::{ColorChoice, Output, OutputFormat, Outputtable};
    pub use super::progress::{ProgressEvent, ProgressReporter};
    pub use super::signal::{CancellationToken, SignalHandler};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelude_exports_work() {
        // Verify prelude exports compile
        let _ = ExitCode::SUCCESS;
        let _ = OutputFormat::Human;
        let _ = ColorChoice::Auto;
    }

    #[test]
    fn error_integration() {
        // Test that error module integrates with exit codes
        let error = errors::invalid_argument("test", "invalid");
        assert_eq!(error.exit_code, ExitCode::USER_ERROR);
    }

    #[test]
    fn output_integration() {
        use serde::Serialize;
        use std::io::Cursor;

        #[derive(Serialize)]
        struct TestData {
            value: i32,
        }

        impl Outputtable for TestData {
            fn human_format(&self) -> String {
                format!("Value: {}", self.value)
            }
        }

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);
        let data = TestData { value: 42 };
        output.write(&data).unwrap();
    }

    #[test]
    fn signal_integration() {
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        assert!(!token.is_cancelled());
        handler.record_signal();
        assert!(token.is_cancelled());
    }

    #[test]
    fn completion_integration() {
        struct TestCmd;

        impl Completable for TestCmd {
            fn command_name(&self) -> &str {
                "test"
            }

            fn subcommands(&self) -> Vec<CompletionItem> {
                vec![CompletionItem::new("run")]
            }

            fn global_options(&self) -> Vec<CompletionItem> {
                vec![CompletionItem::new("--help")]
            }

            fn subcommand_options(&self, _: &str) -> Vec<CompletionItem> {
                vec![]
            }
        }

        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &TestCmd, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("test"));
    }
}
