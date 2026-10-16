//! Signal kind enumeration for supported process signals.
//!
//! Provides a cross-platform representation of signal intents. Unix targets
//! map every variant to the matching POSIX signal number. Windows targets map
//! the supported subset (`SIGINT`, `SIGTERM`, and `SIGBREAK` via
//! [`SignalKind::quit`]) and report the remaining POSIX-only variants as
//! unsupported.

/// Supported process signal kinds.
///
/// This enum represents signal intents that can be handled asynchronously on
/// Unix. On Windows, only the Ctrl-C/Ctrl-Break-compatible subset is
/// supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignalKind {
    /// SIGINT - Interrupt from keyboard (Ctrl+C).
    Interrupt,
    /// SIGTERM - Termination signal.
    Terminate,
    /// SIGHUP - Hangup detected on controlling terminal.
    Hangup,
    /// SIGQUIT on Unix; SIGBREAK / Ctrl+Break on Windows.
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
    #[inline]
    pub const fn interrupt() -> Self {
        Self::Interrupt
    }

    /// Creates a `SignalKind` for SIGTERM.
    #[must_use]
    #[inline]
    pub const fn terminate() -> Self {
        Self::Terminate
    }

    /// Creates a `SignalKind` for SIGHUP.
    #[must_use]
    #[inline]
    pub const fn hangup() -> Self {
        Self::Hangup
    }

    /// Creates a `SignalKind` for SIGQUIT.
    #[must_use]
    #[inline]
    pub const fn quit() -> Self {
        Self::Quit
    }

    /// Creates a `SignalKind` for SIGUSR1.
    #[must_use]
    #[inline]
    pub const fn user_defined1() -> Self {
        Self::User1
    }

    /// Creates a `SignalKind` for SIGUSR2.
    #[must_use]
    #[inline]
    pub const fn user_defined2() -> Self {
        Self::User2
    }

    /// Creates a `SignalKind` for SIGCHLD.
    #[must_use]
    #[inline]
    pub const fn child() -> Self {
        Self::Child
    }

    /// Creates a `SignalKind` for SIGWINCH.
    #[must_use]
    #[inline]
    pub const fn window_change() -> Self {
        Self::WindowChange
    }

    /// Creates a `SignalKind` for SIGPIPE.
    #[must_use]
    #[inline]
    pub const fn pipe() -> Self {
        Self::Pipe
    }

    /// Creates a `SignalKind` for SIGALRM.
    #[must_use]
    #[inline]
    pub const fn alarm() -> Self {
        Self::Alarm
    }

    /// Returns the platform signal number on Unix.
    #[cfg(unix)]
    #[must_use]
    #[inline]
    pub const fn as_raw_value(&self) -> i32 {
        match self {
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
            Self::Hangup => libc::SIGHUP,
            Self::Quit => libc::SIGQUIT,
            Self::User1 => libc::SIGUSR1,
            Self::User2 => libc::SIGUSR2,
            Self::Child => libc::SIGCHLD,
            Self::WindowChange => libc::SIGWINCH,
            Self::Pipe => libc::SIGPIPE,
            Self::Alarm => libc::SIGALRM,
        }
    }

    /// Returns the signal number on Windows platforms.
    ///
    /// Supported mappings:
    /// - `Interrupt` -> `SIGINT`
    /// - `Terminate` -> `SIGTERM`
    /// - `Quit` -> `SIGBREAK`
    ///
    /// Other signal kinds are unsupported and return `None`.
    #[cfg(windows)]
    #[must_use]
    #[inline]
    pub const fn as_raw_value(&self) -> Option<i32> {
        // signal_hook::consts::SIGBREAK is 21 on Windows (Ctrl+Break).
        // We use the literal here because `const fn` cannot call non-const
        // items from external crates.
        const SIGBREAK: i32 = 21;
        match self {
            Self::Interrupt => Some(libc::SIGINT),
            Self::Terminate => Some(libc::SIGTERM),
            Self::Quit => Some(SIGBREAK),
            _ => None,
        }
    }

    /// Returns the signal number on other non-Unix platforms.
    ///
    /// Returns `None` when no mapping exists.
    #[cfg(not(any(unix, windows)))]
    #[must_use]
    #[inline]
    pub const fn as_raw_value(&self) -> Option<i32> {
        None
    }

    /// Returns the name of the signal.
    #[must_use]
    #[inline]
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
#[path = "kind_inline_tests.rs"]
mod tests;
