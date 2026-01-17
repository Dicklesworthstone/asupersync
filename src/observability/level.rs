//! Log severity levels.
//!
//! Defines the standard severity levels for structured logging.

use core::fmt;

/// Severity level for log entries.
///
/// Levels are ordered from least to most severe. Filtering can be done
/// by comparing levels: `entry.level() >= LogLevel::Warn`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Fine-grained debugging information (very verbose).
    Trace = 0,
    /// Debugging information for development.
    Debug = 1,
    /// General informational messages.
    #[default]
    Info = 2,
    /// Potentially problematic situations.
    Warn = 3,
    /// Error conditions that don't halt execution.
    Error = 4,
}

impl LogLevel {
    /// Returns the level name as a static string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// Returns the level name in lowercase.
    #[must_use]
    pub const fn as_str_lower(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// Returns a single-character representation.
    #[must_use]
    pub const fn as_char(self) -> char {
        match self {
            Self::Trace => 'T',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warn => 'W',
            Self::Error => 'E',
        }
    }

    /// Returns true if this level is at least as severe as the given level.
    #[must_use]
    pub const fn is_at_least(self, other: Self) -> bool {
        self as u8 >= other as u8
    }

    /// Returns true if this is a Trace level.
    #[must_use]
    pub const fn is_trace(self) -> bool {
        matches!(self, Self::Trace)
    }

    /// Returns true if this is a Debug level.
    #[must_use]
    pub const fn is_debug(self) -> bool {
        matches!(self, Self::Debug)
    }

    /// Returns true if this is an Info level.
    #[must_use]
    pub const fn is_info(self) -> bool {
        matches!(self, Self::Info)
    }

    /// Returns true if this is a Warn level.
    #[must_use]
    pub const fn is_warn(self) -> bool {
        matches!(self, Self::Warn)
    }

    /// Returns true if this is an Error level.
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn level_is_at_least() {
        assert!(LogLevel::Error.is_at_least(LogLevel::Trace));
        assert!(LogLevel::Warn.is_at_least(LogLevel::Warn));
        assert!(!LogLevel::Debug.is_at_least(LogLevel::Info));
    }

    #[test]
    fn level_strings() {
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Info.as_str_lower(), "info");
        assert_eq!(LogLevel::Info.as_char(), 'I');
    }

    #[test]
    fn level_predicates() {
        assert!(LogLevel::Trace.is_trace());
        assert!(LogLevel::Debug.is_debug());
        assert!(LogLevel::Info.is_info());
        assert!(LogLevel::Warn.is_warn());
        assert!(LogLevel::Error.is_error());
    }
}
