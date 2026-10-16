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
/// or if the handler could not be registered. Refuses with
/// [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied), as
/// [`signal`](super::signal()) does, when the calling task's `Cx` lacks the
/// IO capability.
///
/// # Cancel Safety
///
/// Dropping the future is safe, but each call starts a fresh stream at the
/// current delivery count. A Ctrl+C that arrives while no `ctrl_c()` future
/// is being polled, or that completes a future which is then dropped, is not
/// seen by a later call. A loop that must not miss one keeps a single
/// `signal(SignalKind::interrupt())` stream and awaits its `recv`.
///
/// # Example
///
/// ```
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
    let mut stream = signal(SignalKind::interrupt()).map_err(|err| {
        // A refused IO capability [ASUP-E009] is not a platform limit.
        if err
            .get_ref()
            .is_some_and(|inner| inner.is::<crate::cx::IoCapabilityDenied>())
        {
            err
        } else {
            io::Error::new(io::ErrorKind::Unsupported, CtrlCError::unavailable())
        }
    })?;
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
/// Returns `true` if `ctrl_c()` can successfully register a handler. On
/// Unix the check registers nothing, so Ctrl+C keeps its default action
/// (terminating the process) until `ctrl_c()` or `signal()` is called. On
/// Windows, starting the signal dispatcher installs its console handler.
#[must_use]
pub fn is_available() -> bool {
    #[cfg(any(unix, windows))]
    {
        super::signal::dispatcher_has_slot(SignalKind::interrupt())
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
#[path = "ctrl_c_inline_tests.rs"]
mod tests;
