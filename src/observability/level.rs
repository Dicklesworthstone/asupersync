//! Logging severity levels.

use core::fmt;
use std::str::FromStr;

/// Severity level for log entries.
///
/// Levels are ordered: Trace < Debug < Info < Warn < Error.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Detailed tracing information (lowest priority).
    Trace,
    /// Debugging information.
    Debug,
    /// General informational messages (default).
    #[default]
    Info,
    /// Warning conditions that are not errors.
    Warn,
    /// Error conditions (highest priority).
    Error,
}

impl LogLevel {
    /// Returns true if this level is enabled given the threshold.
    ///
    /// # Example
    /// ```
    /// use asupersync::observability::LogLevel;
    ///
    /// assert!(LogLevel::Error.is_enabled_at(LogLevel::Info));
    /// assert!(!LogLevel::Debug.is_enabled_at(LogLevel::Info));
    /// ```
    #[must_use]
    pub const fn is_enabled_at(&self, threshold: Self) -> bool {
        // Since we derive Ord, comparison works as expected:
        // Trace (0) < Debug (1) < Info (2) < Warn (3) < Error (4)
        // If self (the event level) >= threshold (the config), it is enabled.
        // Wait, enum variants are ordered by definition order.
        // So Trace < Debug < Info.
        // If threshold is Info (2), then:
        // Error (4) >= Info (2) -> True
        // Info (2) >= Info (2) -> True
        // Debug (1) >= Info (2) -> False
        // Correct. But `PartialOrd` implementation needs to be verified.
        // Derived Ord uses discriminant order.
        // Trace=0, Debug=1, Info=2, Warn=3, Error=4.
        (*self as u8) >= (threshold as u8)
    }

    /// Returns a single-character representation (T, D, I, W, E).
    #[must_use]
    pub const fn as_char(&self) -> char {
        match self {
            Self::Trace => 'T',
            Self::Debug => 'D',
            Self::Info => 'I',
            Self::Warn => 'W',
            Self::Error => 'E',
        }
    }

    /// Returns the string representation in lowercase.
    #[must_use]
    pub const fn as_str_lower(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "TRACE" => Ok(Self::Trace),
            "DEBUG" => Ok(Self::Debug),
            "INFO" => Ok(Self::Info),
            "WARN" => Ok(Self::Warn),
            "ERROR" => Ok(Self::Error),
            _ => Err(format!("Invalid log level: {s}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_level_enabled_at_threshold() {
        let threshold = LogLevel::Info;
        assert!(LogLevel::Error.is_enabled_at(threshold));
        assert!(LogLevel::Warn.is_enabled_at(threshold));
        assert!(LogLevel::Info.is_enabled_at(threshold));
        assert!(!LogLevel::Debug.is_enabled_at(threshold));
        assert!(!LogLevel::Trace.is_enabled_at(threshold));
    }

    #[test]
    fn test_level_from_str() {
        assert_eq!(LogLevel::from_str("info"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("INFO"), Ok(LogLevel::Info));
        assert_eq!(LogLevel::from_str("Warn"), Ok(LogLevel::Warn));
        assert!(LogLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_level_display() {
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
    }

    #[test]
    fn test_as_char() {
        assert_eq!(LogLevel::Trace.as_char(), 'T');
        assert_eq!(LogLevel::Error.as_char(), 'E');
    }

    // =========================================================================
    // Wave 52 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn log_level_debug_clone_copy_hash_default() {
        use std::collections::HashSet;
        let l = LogLevel::Warn;
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Warn"), "{dbg}");
        let copied = l;
        let cloned = l.clone();
        assert_eq!(copied, cloned);
        let def = LogLevel::default();
        assert_eq!(def, LogLevel::Info);
        let mut set = HashSet::new();
        set.insert(l);
        assert!(set.contains(&LogLevel::Warn));
    }
}
