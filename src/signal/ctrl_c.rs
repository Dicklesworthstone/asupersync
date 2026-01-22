//! Cross-platform Ctrl+C handling.
//!
//! Provides a simple async function to wait for Ctrl+C (SIGINT on Unix,
//! console Ctrl+C event on Windows).
//!
//! # Phase 0 Implementation
//!
//! In Phase 0, Ctrl+C handling requires external signal infrastructure
//! that is not yet available. This module provides the API surface for
//! forward compatibility.

use std::io;

/// Error returned when Ctrl+C handling is not available.
#[derive(Debug, Clone)]
pub struct CtrlCError {
    message: &'static str,
}

impl CtrlCError {
    const fn not_implemented() -> Self {
        Self {
            message: "Ctrl+C handling not implemented in Phase 0",
        }
    }
}

impl std::fmt::Display for CtrlCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CtrlCError {}

impl From<CtrlCError> for io::Error {
    fn from(e: CtrlCError) -> Self {
        Self::new(io::ErrorKind::Unsupported, e)
    }
}

/// Waits for Ctrl+C (SIGINT on Unix, Ctrl+C event on Windows).
///
/// This is the cross-platform way to handle graceful shutdown triggered
/// by the user pressing Ctrl+C in the terminal.
///
/// # Errors
///
/// Returns an error if Ctrl+C handling is not available on this platform
/// or if the handler could not be registered.
///
/// # Cancel Safety
///
/// This function is cancel-safe. If cancelled, no Ctrl+C event is lost.
///
/// # Example
///
/// ```ignore
/// use asupersync::signal::ctrl_c;
///
/// async fn run_server() -> std::io::Result<()> {
///     println!("Server starting. Press Ctrl+C to stop.");
///
///     // Set up the Ctrl+C handler
///     let ctrl_c_fut = ctrl_c();
///
///     // Run until Ctrl+C
///     ctrl_c_fut.await?;
///
///     println!("Shutting down...");
///     Ok(())
/// }
/// ```
pub async fn ctrl_c() -> io::Result<()> {
    // Phase 0: Ctrl+C handling not yet implemented.
    //
    // A proper implementation requires one of:
    // 1. Platform-specific signal handling (sigaction on Unix, SetConsoleCtrlHandler on Windows)
    // 2. The `ctrlc` crate or similar
    // 3. The `signal-hook` crate with async integration
    //
    // Since we want to minimize dependencies and forbid unsafe code,
    // this is deferred to Phase 1 where we'll add proper signal integration.
    //
    // For now, return an error indicating the feature is not available.
    Err(CtrlCError::not_implemented().into())
}

/// Checks if Ctrl+C handling is available on this platform.
///
/// Returns `true` if `ctrl_c()` can successfully register a handler.
#[must_use]
pub fn is_available() -> bool {
    // Phase 0: Not available without signal infrastructure
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn ctrl_c_not_available() {
        init_test("ctrl_c_not_available");
        let available = is_available();
        crate::assert_with_log!(!available, "not available", false, available);
        crate::test_complete!("ctrl_c_not_available");
    }

    #[test]
    fn ctrl_c_error_display() {
        init_test("ctrl_c_error_display");
        let err = CtrlCError::not_implemented();
        let msg = format!("{err}");
        let contains = msg.contains("Phase 0");
        crate::assert_with_log!(contains, "contains Phase 0", true, contains);
        crate::test_complete!("ctrl_c_error_display");
    }
}
