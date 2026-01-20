//! Signal handling for CLI tools.
//!
//! Provides structured signal handling with proper cleanup semantics.
//! Integrates with cancellation tokens for graceful shutdown.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

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
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the number of signals received.
    #[must_use]
    pub fn signal_count(&self) -> u32 {
        self.signal_count.load(Ordering::SeqCst)
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
        self.cancelled.store(true, Ordering::SeqCst);
        let count = self.signal_count.fetch_add(1, Ordering::SeqCst) + 1;
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
        self.cancelled.store(false, Ordering::SeqCst);
        self.signal_count.store(0, Ordering::SeqCst);
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
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

/// Check if any signal has been received globally.
///
/// This uses the global signal state, which is useful for simple CLI tools.
#[must_use]
pub fn signal_received() -> bool {
    SIGNAL_RECEIVED.load(Ordering::SeqCst)
}

/// Get the global signal count.
#[must_use]
pub fn global_signal_count() -> u32 {
    SIGNAL_COUNT.load(Ordering::SeqCst)
}

/// Record a signal reception in global state.
///
/// Returns the new signal count.
pub fn record_global_signal() -> u32 {
    SIGNAL_RECEIVED.store(true, Ordering::SeqCst);
    SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst) + 1
}

/// Reset global signal state.
///
/// Primarily useful for testing.
pub fn reset_global_signal_state() {
    SIGNAL_RECEIVED.store(false, Ordering::SeqCst);
    SIGNAL_COUNT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names() {
        assert_eq!(Signal::Interrupt.name(), "SIGINT");
        assert_eq!(Signal::Terminate.name(), "SIGTERM");
        assert_eq!(Signal::Hangup.name(), "SIGHUP");
    }

    #[test]
    fn signal_numbers() {
        assert_eq!(Signal::Interrupt.number(), 2);
        assert_eq!(Signal::Terminate.number(), 15);
        assert_eq!(Signal::Hangup.number(), 1);
    }

    #[test]
    fn signal_handler_initial_state() {
        let handler = SignalHandler::new();
        assert!(!handler.is_cancelled());
        assert_eq!(handler.signal_count(), 0);
        assert!(!handler.should_force_quit());
    }

    #[test]
    fn signal_handler_records_signals() {
        let handler = SignalHandler::new();

        assert!(!handler.record_signal());
        assert!(handler.is_cancelled());
        assert_eq!(handler.signal_count(), 1);

        assert!(!handler.record_signal());
        assert_eq!(handler.signal_count(), 2);

        // Third signal triggers force quit (default threshold is 3)
        assert!(handler.record_signal());
        assert!(handler.should_force_quit());
    }

    #[test]
    fn signal_handler_custom_threshold() {
        let handler = SignalHandler::new().with_force_quit_threshold(2);

        assert!(!handler.record_signal());
        assert!(handler.record_signal()); // Second signal triggers force quit
        assert!(handler.should_force_quit());
    }

    #[test]
    fn signal_handler_reset() {
        let handler = SignalHandler::new();

        handler.record_signal();
        assert!(handler.is_cancelled());

        handler.reset();
        assert!(!handler.is_cancelled());
        assert_eq!(handler.signal_count(), 0);
    }

    #[test]
    fn cancellation_token_shares_state() {
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        assert!(!token.is_cancelled());

        handler.record_signal();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_token_can_cancel() {
        let handler = SignalHandler::new();
        let token = handler.cancellation_token();

        token.cancel();
        assert!(handler.is_cancelled());
    }

    #[test]
    fn cancellation_token_cloneable() {
        let handler = SignalHandler::new();
        let token1 = handler.cancellation_token();
        let token2 = token1.clone();

        token1.cancel();
        assert!(token2.is_cancelled());
    }

    #[test]
    fn global_signal_state() {
        reset_global_signal_state();

        assert!(!signal_received());
        assert_eq!(global_signal_count(), 0);

        let count = record_global_signal();
        assert_eq!(count, 1);
        assert!(signal_received());
        assert_eq!(global_signal_count(), 1);

        reset_global_signal_state();
        assert!(!signal_received());
    }
}
