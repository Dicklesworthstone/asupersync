//! Signal kind enumeration for Unix signals.
//!
//! Provides a cross-platform representation of Unix signals.

/// Unix signal kinds.
///
/// This enum represents the various Unix signals that can be handled
/// asynchronously. On Windows, only a subset of signals are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignalKind {
    /// SIGINT - Interrupt from keyboard (Ctrl+C).
    Interrupt,
    /// SIGTERM - Termination signal.
    Terminate,
    /// SIGHUP - Hangup detected on controlling terminal.
    Hangup,
    /// SIGQUIT - Quit from keyboard.
    Quit,
    /// SIGUSR1 - User-defined signal 1.
    User1,
    /// SIGUSR2 - User-defined signal 2.
    User2,
    /// SIGCHLD - Child stopped or terminated.
    Child,
    /// SIGWINCH - Window resize signal.
    WindowChange,
    /// SIGPIPE - Broken pipe.
    Pipe,
    /// SIGALRM - Timer signal.
    Alarm,
}

impl SignalKind {
    /// Creates a `SignalKind` for SIGINT (Ctrl+C).
    #[must_use]
    pub const fn interrupt() -> Self {
        Self::Interrupt
    }

    /// Creates a `SignalKind` for SIGTERM.
    #[must_use]
    pub const fn terminate() -> Self {
        Self::Terminate
    }

    /// Creates a `SignalKind` for SIGHUP.
    #[must_use]
    pub const fn hangup() -> Self {
        Self::Hangup
    }

    /// Creates a `SignalKind` for SIGQUIT.
    #[must_use]
    pub const fn quit() -> Self {
        Self::Quit
    }

    /// Creates a `SignalKind` for SIGUSR1.
    #[must_use]
    pub const fn user_defined1() -> Self {
        Self::User1
    }

    /// Creates a `SignalKind` for SIGUSR2.
    #[must_use]
    pub const fn user_defined2() -> Self {
        Self::User2
    }

    /// Creates a `SignalKind` for SIGCHLD.
    #[must_use]
    pub const fn child() -> Self {
        Self::Child
    }

    /// Creates a `SignalKind` for SIGWINCH.
    #[must_use]
    pub const fn window_change() -> Self {
        Self::WindowChange
    }

    /// Creates a `SignalKind` for SIGPIPE.
    #[must_use]
    pub const fn pipe() -> Self {
        Self::Pipe
    }

    /// Creates a `SignalKind` for SIGALRM.
    #[must_use]
    pub const fn alarm() -> Self {
        Self::Alarm
    }

    /// Returns the signal number on Unix platforms.
    ///
    /// Returns `None` on non-Unix platforms.
    #[cfg(unix)]
    #[must_use]
    pub const fn as_raw_value(&self) -> i32 {
        match self {
            Self::Interrupt => 2,     // SIGINT
            Self::Terminate => 15,    // SIGTERM
            Self::Hangup => 1,        // SIGHUP
            Self::Quit => 3,          // SIGQUIT
            Self::User1 => 10,        // SIGUSR1
            Self::User2 => 12,        // SIGUSR2
            Self::Child => 17,        // SIGCHLD
            Self::WindowChange => 28, // SIGWINCH
            Self::Pipe => 13,         // SIGPIPE
            Self::Alarm => 14,        // SIGALRM
        }
    }

    /// Returns the signal number on Unix platforms.
    ///
    /// Returns `None` on non-Unix platforms.
    #[cfg(not(unix))]
    #[must_use]
    pub const fn as_raw_value(&self) -> Option<i32> {
        None
    }

    /// Returns the name of the signal.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
            Self::Hangup => "SIGHUP",
            Self::Quit => "SIGQUIT",
            Self::User1 => "SIGUSR1",
            Self::User2 => "SIGUSR2",
            Self::Child => "SIGCHLD",
            Self::WindowChange => "SIGWINCH",
            Self::Pipe => "SIGPIPE",
            Self::Alarm => "SIGALRM",
        }
    }
}

impl std::fmt::Display for SignalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
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
    fn signal_kind_constructors() {
        init_test("signal_kind_constructors");
        crate::assert_with_log!(
            SignalKind::interrupt() == SignalKind::Interrupt,
            "interrupt",
            SignalKind::Interrupt,
            SignalKind::interrupt()
        );
        crate::assert_with_log!(
            SignalKind::terminate() == SignalKind::Terminate,
            "terminate",
            SignalKind::Terminate,
            SignalKind::terminate()
        );
        crate::assert_with_log!(
            SignalKind::hangup() == SignalKind::Hangup,
            "hangup",
            SignalKind::Hangup,
            SignalKind::hangup()
        );
        crate::assert_with_log!(
            SignalKind::quit() == SignalKind::Quit,
            "quit",
            SignalKind::Quit,
            SignalKind::quit()
        );
        crate::assert_with_log!(
            SignalKind::user_defined1() == SignalKind::User1,
            "user1",
            SignalKind::User1,
            SignalKind::user_defined1()
        );
        crate::assert_with_log!(
            SignalKind::user_defined2() == SignalKind::User2,
            "user2",
            SignalKind::User2,
            SignalKind::user_defined2()
        );
        crate::assert_with_log!(
            SignalKind::child() == SignalKind::Child,
            "child",
            SignalKind::Child,
            SignalKind::child()
        );
        crate::assert_with_log!(
            SignalKind::window_change() == SignalKind::WindowChange,
            "window_change",
            SignalKind::WindowChange,
            SignalKind::window_change()
        );
        crate::test_complete!("signal_kind_constructors");
    }

    #[test]
    fn signal_kind_names() {
        init_test("signal_kind_names");
        let interrupt = SignalKind::Interrupt.name();
        crate::assert_with_log!(interrupt == "SIGINT", "interrupt", "SIGINT", interrupt);
        let terminate = SignalKind::Terminate.name();
        crate::assert_with_log!(terminate == "SIGTERM", "terminate", "SIGTERM", terminate);
        let hangup = SignalKind::Hangup.name();
        crate::assert_with_log!(hangup == "SIGHUP", "hangup", "SIGHUP", hangup);
        crate::test_complete!("signal_kind_names");
    }

    #[test]
    fn signal_kind_display() {
        init_test("signal_kind_display");
        let interrupt = format!("{}", SignalKind::Interrupt);
        crate::assert_with_log!(interrupt == "SIGINT", "interrupt", "SIGINT", interrupt);
        let terminate = format!("{}", SignalKind::Terminate);
        crate::assert_with_log!(terminate == "SIGTERM", "terminate", "SIGTERM", terminate);
        crate::test_complete!("signal_kind_display");
    }

    #[cfg(unix)]
    #[test]
    fn signal_kind_raw_values() {
        init_test("signal_kind_raw_values");
        let interrupt = SignalKind::Interrupt.as_raw_value();
        crate::assert_with_log!(interrupt == 2, "interrupt", 2, interrupt);
        let terminate = SignalKind::Terminate.as_raw_value();
        crate::assert_with_log!(terminate == 15, "terminate", 15, terminate);
        let hangup = SignalKind::Hangup.as_raw_value();
        crate::assert_with_log!(hangup == 1, "hangup", 1, hangup);
        crate::test_complete!("signal_kind_raw_values");
    }
}
