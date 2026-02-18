//! Signal handling for CLI tools.
//!
//! Provides structured signal handling with proper cleanup semantics.
//! Integrates with cancellation tokens for graceful shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Global signal state for tracking received signals.
static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);
static SIGNAL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Signal types that can be handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Interrupt signal (Ctrl+C, SIGINT).
    Interrupt,

    /// Termination signal (SIGTERM).
    Terminate,

    /// Hangup signal (SIGHUP).
    Hangup,
}

impl Signal {
    /// Get the signal name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
            Self::Hangup => "SIGHUP",
        }
    }

    /// Get the signal number (Unix).
    #[must_use]
    pub const fn number(&self) -> i32 {
        match self {
            Self::Interrupt => 2,
            Self::Terminate => 15,
            Self::Hangup => 1,
        }
    }
}

/// Signal handler callback type.
pub type SignalCallback = Box<dyn Fn(Signal) + Send + Sync>;

/// Signal handler that tracks cancellation state.
///
/// Provides a clean interface for handling signals in CLI applications.
pub struct SignalHandler {
    /// Whether a signal has been received.
    cancelled: Arc<AtomicBool>,

    /// Number of signals received (for force-quit on repeated signals).
    signal_count: Arc<AtomicU32>,

    /// Threshold for force quit (e.g., 3 Ctrl+C = force quit).
    force_quit_threshold: u32,
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalHandler {
    /// Create a new signal handler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            signal_count: Arc::new(AtomicU32::new(0)),
            force_quit_threshold: 3,
        }
    }

    /// Set the threshold for force quit.
    ///
    /// After this many signals, the process should exit immediately.
    #[must_use]
    pub const fn with_force_quit_threshold(mut self, threshold: u32) -> Self {
        self.force_quit_threshold = threshold;
        self
    }

    /// Check if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Get the number of signals received.
    #[must_use]
    pub fn signal_count(&self) -> u32 {
        self.signal_count.load(Ordering::Relaxed)
    }

    /// Check if force quit threshold has been reached.
    #[must_use]
    pub fn should_force_quit(&self) -> bool {
        self.signal_count() >= self.force_quit_threshold
    }

    /// Record a signal reception.
    ///
    /// Returns true if this is a force-quit situation.
    #[must_use]
    pub fn record_signal(&self) -> bool {
        self.cancelled.store(true, Ordering::Relaxed);
        let count = self.signal_count.fetch_add(1, Ordering::Relaxed) + 1;
        count >= self.force_quit_threshold
    }

    /// Get a cancellation token that can be shared across threads.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        CancellationToken {
            cancelled: Arc::clone(&self.cancelled),
        }
    }

    /// Reset the signal state.
    ///
    /// Useful for testing or when reusing a handler.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
        self.signal_count.store(0, Ordering::Relaxed);
    }
}

/// A token that can be used to check for cancellation.
///
/// Clone-able and thread-safe for sharing across async tasks.
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Check if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Check if any signal has been received globally.
///
/// This uses the global signal state, which is useful for simple CLI tools.
#[must_use]
pub fn signal_received() -> bool {
    SIGNAL_RECEIVED.load(Ordering::Relaxed)
}

/// Get the global signal count.
#[must_use]
pub fn global_signal_count() -> u32 {
    SIGNAL_COUNT.load(Ordering::Relaxed)
}

/// Record a signal reception in global state.
///
/// Returns the new signal count.
pub fn record_global_signal() -> u32 {
    SIGNAL_RECEIVED.store(true, Ordering::Relaxed);
    SIGNAL_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}

/// Reset global signal state.
///
/// Primarily useful for testing.
pub fn reset_global_signal_state() {
    SIGNAL_RECEIVED.store(false, Ordering::Relaxed);
    SIGNAL_COUNT.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn signal_names() {
        init_test("signal_names");
        let interrupt = Signal::Interrupt.name();
        crate::assert_with_log!(interrupt == "SIGINT", "SIGINT", "SIGINT", interrupt);
        let terminate = Signal::Terminate.name();
        crate::assert_with_log!(terminate == "SIGTERM", "SIGTERM", "SIGTERM", terminate);
        let hangup = Signal::Hangup.name();
        crate::assert_with_log!(hangup == "SIGHUP", "SIGHUP", "SIGHUP", hangup);
        crate::test_complete!("signal_names");
    }

    #[test]
    fn signal_numbers() {
        init_test("signal_numbers");
        let interrupt = Signal::Interrupt.number();
        crate::assert_with_log!(interrupt == 2, "SIGINT number", 2, interrupt);
        let terminate = Signal::Terminate.number();
        crate::assert_with_log!(terminate == 15, "SIGTERM number", 15, terminate);
        let hangup = Signal::Hangup.number();
        crate::assert_with_log!(hangup == 1, "SIGHUP number", 1, hangup);
        crate::test_complete!("signal_numbers");
    }

    #[test]
    fn signal_handler_initial_state() {
        init_test("signal_handler_initial_state");
        let handler = SignalHandler::new();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(!cancelled, "not cancelled", false, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 0, "signal_count", 0, count);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(!force_quit, "no force quit", false, force_quit);
        crate::test_complete!("signal_handler_initial_state");
    }

    #[test]
    fn signal_handler_records_signals() {
        init_test("signal_handler_records_signals");
        let handler = SignalHandler::new();

        let first = handler.record_signal();
        crate::assert_with_log!(!first, "first record", false, first);
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 1, "signal_count", 1, count);

        let second = handler.record_signal();
        crate::assert_with_log!(!second, "second record", false, second);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 2, "signal_count", 2, count);

        // Third signal triggers force quit (default threshold is 3)
        let third = handler.record_signal();
        crate::assert_with_log!(third, "third triggers force quit", true, third);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(force_quit, "force quit", true, force_quit);
        crate::test_complete!("signal_handler_records_signals");
    }

    #[test]
    fn signal_handler_custom_threshold() {
        init_test("signal_handler_custom_threshold");
        let handler = SignalHandler::new().with_force_quit_threshold(2);

        let first = handler.record_signal();
        crate::assert_with_log!(!first, "first record", false, first);
        let second = handler.record_signal(); // Second signal triggers force quit
        crate::assert_with_log!(second, "second triggers force quit", true, second);
        let force_quit = handler.should_force_quit();
        crate::assert_with_log!(force_quit, "force quit", true, force_quit);
        crate::test_complete!("signal_handler_custom_threshold");
    }

    #[test]
    fn signal_handler_reset() {
        init_test("signal_handler_reset");
        let handler = SignalHandler::new();

        let _ = handler.record_signal();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "cancelled", true, cancelled);

        handler.reset();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(!cancelled, "not cancelled", false, cancelled);
        let count = handler.signal_count();
        crate::assert_with_log!(count == 0, "signal_count", 0, count);
        crate::test_complete!("signal_handler_reset");
    }

    #[test]
    fn cancellation_token_shares_state() {
        init_test("cancellation_token_shares_state");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        let cancelled = token.is_cancelled();
        crate::assert_with_log!(!cancelled, "token not cancelled", false, cancelled);

        let _ = handler.record_signal();
        let cancelled = token.is_cancelled();
        crate::assert_with_log!(cancelled, "token cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_shares_state");
    }

    #[test]
    fn cancellation_token_can_cancel() {
        init_test("cancellation_token_can_cancel");
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        token.cancel();
        let cancelled = handler.is_cancelled();
        crate::assert_with_log!(cancelled, "handler cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_can_cancel");
    }

    #[test]
    fn cancellation_token_cloneable() {
        init_test("cancellation_token_cloneable");
        let handler = SignalHandler::new();
        let token1 = handler.cancellation_token();
        let token2 = token1.clone();

        token1.cancel();
        let cancelled = token2.is_cancelled();
        crate::assert_with_log!(cancelled, "token2 cancelled", true, cancelled);
        crate::test_complete!("cancellation_token_cloneable");
    }

    #[test]
    fn global_signal_state() {
        init_test("global_signal_state");
        reset_global_signal_state();

        let received = signal_received();
        crate::assert_with_log!(!received, "no signal", false, received);
        let count = global_signal_count();
        crate::assert_with_log!(count == 0, "count 0", 0, count);

        let count = record_global_signal();
        crate::assert_with_log!(count == 1, "record count", 1, count);
        let received = signal_received();
        crate::assert_with_log!(received, "signal received", true, received);
        let count = global_signal_count();
        crate::assert_with_log!(count == 1, "count 1", 1, count);

        reset_global_signal_state();
        let received = signal_received();
        crate::assert_with_log!(!received, "reset cleared", false, received);
        crate::test_complete!("global_signal_state");
    }
}
