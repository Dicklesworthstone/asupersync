//! Tracing compatibility layer for structured logging and spans.
//!
//! This module provides a unified interface for tracing that works whether or not
//! the `tracing-integration` feature is enabled:
//!
//! - **With feature enabled**: Re-exports from the `tracing` crate for full functionality.
//! - **Without feature**: No-op macros that compile to nothing for zero runtime overhead.
//!
//! # Usage
//!
//! ```rust,ignore
//! use asupersync::tracing_compat::{info, debug, trace, span, Level};
//!
//! // These compile to no-ops when tracing-integration is disabled
//! info!("Starting operation");
//! debug!(task_id = ?id, "Task spawned");
//!
//! let _span = span!(Level::INFO, "my_operation");
//! ```
//!
//! # Feature Flag
//!
//! Enable tracing by adding the feature to your `Cargo.toml`:
//!
//! ```toml
//! asupersync = { version = "0.1", features = ["tracing-integration"] }
//! ```

#[cfg(feature = "tracing-integration")]
pub use tracing::{
    Instrument, Level, Span, debug, debug_span, error, error_span, event, info, info_span,
    instrument, span, trace, trace_span, warn, warn_span,
};

// When tracing is disabled, provide no-op macros
#[cfg(not(feature = "tracing-integration"))]
mod noop {
    //! No-op implementations when tracing is disabled.
    //!
    //! These macros expand to nothing, ensuring zero compile-time and runtime cost.

    /// No-op trace-level logging macro.
    #[macro_export]
    macro_rules! trace {
        ($($arg:tt)*) => {};
    }

    /// No-op debug-level logging macro.
    #[macro_export]
    macro_rules! debug {
        ($($arg:tt)*) => {};
    }

    /// No-op info-level logging macro.
    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => {};
    }

    /// No-op warn-level logging macro.
    #[macro_export]
    macro_rules! warn {
        ($($arg:tt)*) => {};
    }

    /// No-op error-level logging macro.
    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => {};
    }

    /// No-op event macro.
    #[macro_export]
    macro_rules! event {
        ($($arg:tt)*) => {};
    }

    /// No-op span macro that returns a `NoopSpan`.
    #[macro_export]
    macro_rules! span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op trace_span macro.
    #[macro_export]
    macro_rules! trace_span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op debug_span macro.
    #[macro_export]
    macro_rules! debug_span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op info_span macro.
    #[macro_export]
    macro_rules! info_span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op warn_span macro.
    #[macro_export]
    macro_rules! warn_span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op error_span macro.
    #[macro_export]
    macro_rules! error_span {
        ($($arg:tt)*) => {
            $crate::tracing_compat::NoopSpan
        };
    }

    /// No-op instrument attribute (does nothing).
    /// This is a placeholder - the actual `#[instrument]` attribute requires proc-macro.
    #[macro_export]
    macro_rules! instrument {
        ($($arg:tt)*) => {};
    }

    // Re-export the macros at module level
    pub use crate::{
        debug, debug_span, error, error_span, event, info, info_span, instrument, span, trace,
        trace_span, warn, warn_span,
    };
}

#[cfg(not(feature = "tracing-integration"))]
pub use noop::*;

/// A no-op span that does nothing.
///
/// When tracing is disabled, span macros return this type. It implements
/// the necessary methods to allow code like `span.enter()` to compile
/// without the tracing feature.
#[cfg(not(feature = "tracing-integration"))]
#[derive(Debug, Clone, Copy)]
pub struct NoopSpan;

#[cfg(not(feature = "tracing-integration"))]
impl NoopSpan {
    /// Returns a no-op guard that does nothing on drop.
    #[inline]
    #[must_use]
    pub fn enter(&self) -> NoopGuard {
        NoopGuard
    }

    /// Returns self (no-op).
    #[inline]
    #[must_use]
    pub fn entered(self) -> Self {
        self
    }

    /// Returns self (no-op).
    #[inline]
    #[must_use]
    pub fn or_current(self) -> Self {
        self
    }

    /// Returns self (no-op).
    #[inline]
    pub fn follows_from(&self, _span: &Self) {}

    /// Returns true (always "enabled" to avoid branch differences).
    #[inline]
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        true
    }

    /// Records a value (no-op).
    #[inline]
    pub fn record<V>(&self, _field: &str, _value: V) {}

    /// Returns a no-op span (current span is always a no-op when disabled).
    #[inline]
    #[must_use]
    pub fn current() -> Self {
        Self
    }

    /// Returns a no-op span (none is always a no-op when disabled).
    #[inline]
    #[must_use]
    pub fn none() -> Self {
        Self
    }
}

/// A no-op span guard that does nothing on drop.
#[cfg(not(feature = "tracing-integration"))]
#[derive(Debug)]
pub struct NoopGuard;

/// No-op level type for when tracing is disabled.
#[cfg(not(feature = "tracing-integration"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level;

#[cfg(not(feature = "tracing-integration"))]
impl Level {
    /// Trace level (most verbose).
    pub const TRACE: Self = Self;
    /// Debug level.
    pub const DEBUG: Self = Self;
    /// Info level.
    pub const INFO: Self = Self;
    /// Warn level.
    pub const WARN: Self = Self;
    /// Error level (least verbose).
    pub const ERROR: Self = Self;
}

/// Alias for `NoopSpan` when tracing is disabled.
#[cfg(not(feature = "tracing-integration"))]
pub type Span = NoopSpan;

/// No-op `Instrument` trait when tracing is disabled.
///
/// This trait is implemented for all `Future` types and does nothing,
/// allowing code using `.instrument(span)` to compile without the feature.
#[cfg(not(feature = "tracing-integration"))]
pub trait Instrument: Sized {
    /// Instruments this future with a span (no-op when disabled).
    #[must_use]
    fn instrument(self, _span: NoopSpan) -> Self {
        self
    }

    /// Instruments this future with the current span (no-op when disabled).
    #[must_use]
    fn in_current_span(self) -> Self {
        self
    }
}

#[cfg(not(feature = "tracing-integration"))]
impl<T> Instrument for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    #[test]
    fn test_noop_macros_compile() {
        init_test("test_noop_macros_compile");
        // These should all compile and do nothing
        trace!("trace message");
        debug!("debug message");
        info!("info message");
        warn!("warn message");
        error!("error message");

        trace!(field = "value", "trace with field");
        debug!(count = 42, "debug with field");
        info!(name = "test", "info with field");
        crate::test_complete!("test_noop_macros_compile");
    }

    #[test]
    fn test_noop_span_compile() {
        init_test("test_noop_span_compile");
        let span = span!(Level::INFO, "test_span");
        let _guard = span.enter();

        let span2 = info_span!("info_span");
        let _entered = span2.entered();

        let span3 = debug_span!("debug_span", task_id = 42);
        span3.record("field", "value");
        crate::test_complete!("test_noop_span_compile");
    }

    #[test]
    fn test_noop_level_constants() {
        init_test("test_noop_level_constants");
        // Verify that Level constants are accessible — tested further in
        // `level_equality_and_ordering`.
        crate::test_complete!("test_noop_level_constants");
    }

    #[test]
    fn test_noop_span_methods() {
        init_test("test_noop_span_methods");
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span = NoopSpan;
            let disabled = span.is_disabled();
            crate::assert_with_log!(disabled, "noop span should be disabled", true, disabled);

            let current = NoopSpan::current();
            let none = NoopSpan::none();
            let _ = current.or_current();
            none.follows_from(&span);
        }
        crate::test_complete!("test_noop_span_methods");
    }

    #[test]
    fn noop_guard_debug() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let guard = NoopGuard;
            let dbg = format!("{guard:?}");
            assert!(dbg.contains("NoopGuard"), "{dbg}");
        }
    }

    #[test]
    fn noop_span_debug_clone_copy() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span = NoopSpan;
            let dbg = format!("{span:?}");
            assert!(dbg.contains("NoopSpan"), "{dbg}");

            let copied = span;
            let cloned = span;
            assert!(copied.is_disabled());
            assert!(cloned.is_disabled());
        }
    }

    #[test]
    fn level_equality_and_ordering() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            // All noop levels are the same unit struct
            assert_eq!(Level::TRACE, Level::DEBUG);
            assert_eq!(Level::INFO, Level::WARN);
            assert_eq!(Level::WARN, Level::ERROR);

            // Ordering is consistent
            assert!(Level::TRACE <= Level::ERROR);

            // Debug
            let dbg = format!("{:?}", Level::INFO);
            assert!(dbg.contains("Level"), "{dbg}");

            // Clone/Copy
            let l = Level::INFO;
            let copied = l;
            let cloned = l;
            assert_eq!(copied, cloned);
        }
    }

    #[test]
    fn span_type_alias_works() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let span: Span = NoopSpan::current();
            let _guard = span.enter();
        }
    }

    #[test]
    fn all_span_macros_compile() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let _ = trace_span!("t");
            let _ = debug_span!("d");
            let _ = info_span!("i");
            let _ = warn_span!("w");
            let _ = error_span!("e");
        }
    }

    #[test]
    fn instrument_trait_noop() {
        #[cfg(not(feature = "tracing-integration"))]
        {
            let fut = async { 42 };
            let instrumented = fut.instrument(NoopSpan);
            // Can also use in_current_span
            drop(async { 1 }.in_current_span());
            drop(instrumented);
        }
    }
}
