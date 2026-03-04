//! Cross-platform Ctrl+C handling.
//!
//! Provides a simple async function to wait for Ctrl+C.
//! On platforms without signal support in this build, returns an unsupported error.

use std::io;

use super::{SignalKind, signal};

/// Error returned when Ctrl+C handling is not available.
#[derive(Debug, Clone)]
pub struct CtrlCError {
    message: &'static str,
}

impl CtrlCError {
    const fn unavailable() -> Self {
        Self {
            message: "Ctrl+C handling is unavailable on this platform/build",
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
    let mut stream = signal(SignalKind::interrupt())
        .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, CtrlCError::unavailable()))?;
    match stream.recv().await {
        Some(()) => Ok(()),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "ctrl_c signal stream closed unexpectedly",
        )),
    }
}

/// Checks if Ctrl+C handling is available on this platform.
///
/// Returns `true` if `ctrl_c()` can successfully register a handler.
#[must_use]
pub fn is_available() -> bool {
    #[cfg(any(unix, windows))]
    {
        signal(SignalKind::interrupt()).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
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
        #[cfg(any(unix, windows))]
        crate::assert_with_log!(available, "available", true, available);
        #[cfg(not(any(unix, windows)))]
        crate::assert_with_log!(!available, "not available", false, available);
        crate::test_complete!("ctrl_c_not_available");
    }

    #[test]
    fn ctrl_c_error_display() {
        init_test("ctrl_c_error_display");
        let err = CtrlCError::unavailable();
        let msg = format!("{err}");
        let contains = msg.contains("unavailable");
        crate::assert_with_log!(contains, "contains unavailable", true, contains);
        crate::test_complete!("ctrl_c_error_display");
    }
}
