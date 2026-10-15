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

    /// is_available() used to register a SIGINT handler that is never
    /// removed, so a program that only probed availability could no longer
    /// be stopped with Ctrl+C. Checked in a fresh child test process (other
    /// tests here register SIGINT for real) through the kernel's own record
    /// of caught signals, which does not depend on how the test runner's
    /// SIGINT disposition was inherited.
    #[cfg(target_os = "linux")]
    #[test]
    fn is_available_does_not_install_a_sigint_handler() {
        const CHILD_ENV: &str = "ASUPERSYNC_CTRL_C_PROBE_CHILD";
        const TEST_NAME: &str =
            "signal::ctrl_c::tests::is_available_does_not_install_a_sigint_handler";
        fn sigint_caught() -> bool {
            let status = std::fs::read_to_string("/proc/self/status").expect("read status");
            let mask = status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
                .expect("SigCgt line");
            // SIGINT is signal 2, bit 1 of the mask.
            mask & (1 << 1) != 0
        }

        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(!sigint_caught(), "a fresh process starts without one");
            assert!(is_available());
            assert!(
                !sigint_caught(),
                "is_available() must not install a SIGINT handler"
            );
            return;
        }
        init_test("is_available_does_not_install_a_sigint_handler");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("spawn child test binary");
        assert!(
            output.status.success(),
            "child probe failed: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        // The child must actually have run the test, not filtered it out.
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("1 passed"),
            "child did not run the probe: {stdout}"
        );
        crate::test_complete!("is_available_does_not_install_a_sigint_handler");
    }
}
