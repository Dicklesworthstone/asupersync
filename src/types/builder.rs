//! Builder API types and validation for Asupersync.
//!
//! This module defines the common types used by builders throughout Asupersync,
//! including error types, validation utilities, and the builder trait.
//!
//! # Design Philosophy
//!
//! ## Builder Ownership Model
//!
//! Asupersync uses **move-based builders** where each method takes `self` by value
//! and returns `Self`. This provides:
//!
//! - Clear ownership semantics with no borrowing issues
//! - Natural method chaining: `Builder::new().option1(x).option2(y).build()`
//! - Prevents partial configuration state from escaping
//!
//! ```ignore
//! // Preferred pattern
//! let runtime = RuntimeBuilder::new()
//!     .worker_threads(4)
//!     .poll_budget(128)
//!     .build()?;
//! ```
//!
//! ## Sub-Builder Pattern
//!
//! For complex nested configuration, use closures that receive sub-builders:
//!
//! ```ignore
//! let runtime = RuntimeBuilder::new()
//!     .scheduler(|s| s
//!         .steal_batch_size(16)
//!         .parking_enabled(true))
//!     .deadline_monitoring(|m| m
//!         .check_interval(Duration::from_secs(1))
//!         .enabled(true))
//!     .build()?;
//! ```
//!
//! This keeps the main builder API clean while allowing deep customization.
//!
//! ## Validation Strategy
//!
//! Validation follows a two-phase approach:
//!
//! 1. **Immediate validation** in setters for obviously invalid values:
//!    - Probabilities outside [0.0, 1.0]
//!    - Negative values where only positive makes sense
//!    - Empty strings where non-empty is required
//!
//! 2. **Deferred validation** at `build()` for cross-field constraints:
//!    - `min_threads <= max_threads`
//!    - Required fields are set
//!    - Conflicting options
//!
//! ## Error Philosophy
//!
//! All `build()` methods return `Result<T, BuildError>` for recoverable failures.
//! Only clearly programmer errors (like probabilities > 1.0) panic immediately.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::types::builder::{BuildError, BuildResult};
//!
//! struct MyBuilder {
//!     name: Option<String>,
//!     threads: usize,
//! }
//!
//! impl MyBuilder {
//!     fn name(mut self, name: impl Into<String>) -> Self {
//!         self.name = Some(name.into());
//!         self
//!     }
//!
//!     fn threads(mut self, n: usize) -> Self {
//!         self.threads = n;
//!         self
//!     }
//!
//!     fn build(self) -> BuildResult<MyConfig> {
//!         let name = self.name.ok_or_else(||
//!             BuildError::missing_required("name")
//!         )?;
//!
//!         if self.threads == 0 {
//!             return Err(BuildError::invalid_value("threads", "must be >= 1"));
//!         }
//!
//!         Ok(MyConfig { name, threads: self.threads })
//!     }
//! }
//! ```

use core::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// BuildError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur when building a configuration.
///
/// `BuildError` captures validation failures, constraint violations, and
/// configuration errors that can occur during the `build()` call.
///
/// # Error Categories
///
/// | Category | Description | Example |
/// |----------|-------------|---------|
/// | `MissingRequired` | Required field not set | `name` field is None |
/// | `InvalidValue` | Value fails validation | `threads = 0` |
/// | `InvalidRange` | Range constraints violated | `min > max` |
/// | `ConflictingOptions` | Mutually exclusive options | `sync` and `async` both set |
/// | `InvalidProbability` | Probability not in [0.0, 1.0] | `0.5..=1.5` |
/// | `InvalidDuration` | Duration constraint violated | `timeout = 0` |
/// | `DependencyMissing` | Required dependency not configured | `tls` without certificates |
/// | `Custom` | Domain-specific validation errors | Application-specific rules |
///
/// # Usage
///
/// ```ignore
/// fn build(self) -> BuildResult<Config> {
///     // Check required fields
///     let name = self.name.ok_or_else(||
///         BuildError::missing_required("name")
///     )?;
///
///     // Validate values
///     if self.threads == 0 {
///         return Err(BuildError::invalid_value("threads", "must be >= 1"));
///     }
///
///     // Check ranges
///     if self.min_connections > self.max_connections {
///         return Err(BuildError::invalid_range(
///             "connections",
///             self.min_connections,
///             self.max_connections,
///         ));
///     }
///
///     Ok(Config { name, threads: self.threads, ... })
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum BuildError {
    /// A required field was not set.
    ///
    /// # Example
    /// ```ignore
    /// BuildError::MissingRequired { field: "name" }
    /// ```
    MissingRequired {
        /// The name of the missing field.
        field: &'static str,
    },

    /// A field value failed validation.
    ///
    /// # Example
    /// ```ignore
    /// BuildError::InvalidValue {
    ///     field: "worker_threads",
    ///     reason: "must be >= 1".to_string(),
    /// }
    /// ```
    InvalidValue {
        /// The field that failed validation.
        field: &'static str,
        /// Why the value is invalid.
        reason: String,
    },

    /// A range constraint was violated (min > max).
    ///
    /// # Example
    /// ```ignore
    /// BuildError::InvalidRange {
    ///     field: "connections",
    ///     min: 100,
    ///     max: 10,
    /// }
    /// ```
    InvalidRange {
        /// The field or field pair with the range issue.
        field: &'static str,
        /// The minimum value provided.
        min: u64,
        /// The maximum value provided.
        max: u64,
    },

    /// Two options that cannot both be enabled were set.
    ///
    /// # Example
    /// ```ignore
    /// BuildError::ConflictingOptions {
    ///     option_a: "single_threaded",
    ///     option_b: "work_stealing",
    /// }
    /// ```
    ConflictingOptions {
        /// The first conflicting option.
        option_a: &'static str,
        /// The second conflicting option.
        option_b: &'static str,
    },

    /// A probability value was not in [0.0, 1.0].
    ///
    /// # Example
    /// ```ignore
    /// BuildError::InvalidProbability {
    ///     field: "cancel_probability",
    ///     value: 1.5,
    /// }
    /// ```
    InvalidProbability {
        /// The field with the invalid probability.
        field: &'static str,
        /// The invalid probability value.
        value: f64,
    },

    /// A duration value violated constraints.
    ///
    /// # Example
    /// ```ignore
    /// BuildError::InvalidDuration {
    ///     field: "timeout",
    ///     reason: "must be non-zero".to_string(),
    /// }
    /// ```
    InvalidDuration {
        /// The field with the invalid duration.
        field: &'static str,
        /// Why the duration is invalid.
        reason: String,
    },

    /// A dependency required by the configuration is missing.
    ///
    /// # Example
    /// ```ignore
    /// BuildError::DependencyMissing {
    ///     feature: "tls",
    ///     dependency: "certificate",
    /// }
    /// ```
    DependencyMissing {
        /// The feature that has the missing dependency.
        feature: &'static str,
        /// The name of the missing dependency.
        dependency: &'static str,
    },

    /// A custom validation error with arbitrary message.
    ///
    /// Use this for domain-specific validation that doesn't fit other variants.
    Custom {
        /// The error message.
        message: String,
    },
}

impl BuildError {
    // ─────────────────────────────────────────────────────────────────────────
    // Constructors
    // ─────────────────────────────────────────────────────────────────────────

    /// Creates a `MissingRequired` error.
    #[must_use]
    pub const fn missing_required(field: &'static str) -> Self {
        Self::MissingRequired { field }
    }

    /// Creates an `InvalidValue` error.
    #[must_use]
    pub fn invalid_value(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidValue {
            field,
            reason: reason.into(),
        }
    }

    /// Creates an `InvalidRange` error.
    #[must_use]
    pub const fn invalid_range(field: &'static str, min: u64, max: u64) -> Self {
        Self::InvalidRange { field, min, max }
    }

    /// Creates a `ConflictingOptions` error.
    #[must_use]
    pub const fn conflicting_options(option_a: &'static str, option_b: &'static str) -> Self {
        Self::ConflictingOptions { option_a, option_b }
    }

    /// Creates an `InvalidProbability` error.
    #[must_use]
    pub const fn invalid_probability(field: &'static str, value: f64) -> Self {
        Self::InvalidProbability { field, value }
    }

    /// Creates an `InvalidDuration` error.
    #[must_use]
    pub fn invalid_duration(field: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidDuration {
            field,
            reason: reason.into(),
        }
    }

    /// Creates a `DependencyMissing` error.
    #[must_use]
    pub const fn dependency_missing(feature: &'static str, dependency: &'static str) -> Self {
        Self::DependencyMissing {
            feature,
            dependency,
        }
    }

    /// Creates a `Custom` error.
    #[must_use]
    pub fn custom(message: impl Into<String>) -> Self {
        Self::Custom {
            message: message.into(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Introspection
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns the field name associated with this error, if any.
    #[must_use]
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::MissingRequired { field }
            | Self::InvalidValue { field, .. }
            | Self::InvalidRange { field, .. }
            | Self::InvalidProbability { field, .. }
            | Self::InvalidDuration { field, .. } => Some(field),
            Self::ConflictingOptions { .. }
            | Self::DependencyMissing { .. }
            | Self::Custom { .. } => None,
        }
    }

    /// Returns true if this is a missing required field error.
    #[must_use]
    pub const fn is_missing_required(&self) -> bool {
        matches!(self, Self::MissingRequired { .. })
    }

    /// Returns true if this is an invalid value error.
    #[must_use]
    pub const fn is_invalid_value(&self) -> bool {
        matches!(self, Self::InvalidValue { .. })
    }

    /// Returns true if this is a conflicting options error.
    #[must_use]
    pub const fn is_conflicting_options(&self) -> bool {
        matches!(self, Self::ConflictingOptions { .. })
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequired { field } => {
                write!(f, "missing required configuration: {field}")
            }
            Self::InvalidValue { field, reason } => {
                write!(f, "invalid {field}: {reason}")
            }
            Self::InvalidRange { field, min, max } => {
                write!(
                    f,
                    "invalid {field} range: min ({min}) must be <= max ({max})"
                )
            }
            Self::ConflictingOptions { option_a, option_b } => {
                write!(
                    f,
                    "conflicting options: {option_a} and {option_b} cannot both be enabled"
                )
            }
            Self::InvalidProbability { field, value } => {
                write!(
                    f,
                    "invalid {field}: probability {value} must be in [0.0, 1.0]"
                )
            }
            Self::InvalidDuration { field, reason } => {
                write!(f, "invalid {field} duration: {reason}")
            }
            Self::DependencyMissing {
                feature,
                dependency,
            } => {
                write!(
                    f,
                    "{feature} requires {dependency} to be configured but it is missing"
                )
            }
            Self::Custom { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for BuildError {}

// ─────────────────────────────────────────────────────────────────────────────
// BuildResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result type for builder operations.
pub type BuildResult<T> = Result<T, BuildError>;

// ─────────────────────────────────────────────────────────────────────────────
// Validation Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Validation helper functions for common constraints.
///
/// These functions return `BuildResult<()>` for use with `?` in `build()` methods.
pub mod validate {
    use super::{BuildError, BuildResult};
    use std::time::Duration;

    /// Validates that a probability is in [0.0, 1.0].
    ///
    /// # Example
    /// ```ignore
    /// validate::probability("cancel_rate", self.cancel_rate)?;
    /// ```
    pub fn probability(field: &'static str, value: f64) -> BuildResult<()> {
        if (0.0..=1.0).contains(&value) {
            Ok(())
        } else {
            Err(BuildError::invalid_probability(field, value))
        }
    }

    /// Validates that a value is > 0.
    ///
    /// # Example
    /// ```ignore
    /// validate::positive("worker_threads", self.threads)?;
    /// ```
    pub fn positive(field: &'static str, value: usize) -> BuildResult<()> {
        if value > 0 {
            Ok(())
        } else {
            Err(BuildError::invalid_value(field, "must be > 0"))
        }
    }

    /// Validates that a value is >= 1.
    ///
    /// # Example
    /// ```ignore
    /// validate::at_least_one("replicas", self.replicas)?;
    /// ```
    pub fn at_least_one(field: &'static str, value: usize) -> BuildResult<()> {
        if value >= 1 {
            Ok(())
        } else {
            Err(BuildError::invalid_value(field, "must be >= 1"))
        }
    }

    /// Validates that min <= max.
    ///
    /// # Example
    /// ```ignore
    /// validate::range("connections", self.min_conn, self.max_conn)?;
    /// ```
    pub fn range(field: &'static str, min: u64, max: u64) -> BuildResult<()> {
        if min <= max {
            Ok(())
        } else {
            Err(BuildError::invalid_range(field, min, max))
        }
    }

    /// Validates that a duration is non-zero.
    ///
    /// # Example
    /// ```ignore
    /// validate::nonzero_duration("timeout", self.timeout)?;
    /// ```
    pub fn nonzero_duration(field: &'static str, duration: Duration) -> BuildResult<()> {
        if duration.is_zero() {
            Err(BuildError::invalid_duration(field, "must be non-zero"))
        } else {
            Ok(())
        }
    }

    /// Validates that a string is not empty.
    ///
    /// # Example
    /// ```ignore
    /// validate::non_empty_string("name", &self.name)?;
    /// ```
    pub fn non_empty_string(field: &'static str, value: &str) -> BuildResult<()> {
        if value.is_empty() {
            Err(BuildError::invalid_value(field, "must not be empty"))
        } else {
            Ok(())
        }
    }

    /// Validates that an option is Some, returning the inner value.
    ///
    /// # Example
    /// ```ignore
    /// let name = validate::required("name", self.name)?;
    /// ```
    pub fn required<T>(field: &'static str, value: Option<T>) -> BuildResult<T> {
        value.ok_or_else(|| BuildError::missing_required(field))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder Type Signatures
// ─────────────────────────────────────────────────────────────────────────────
//
// The following sections document the type signatures for builders in Asupersync.
// Implementations are in their respective modules; this serves as a design reference.

// ───────────────────────────────────────────────────────────────────────────
// RuntimeBuilder (src/runtime/builder.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct RuntimeBuilder {
//     config: RuntimeConfig,
// }
//
// impl RuntimeBuilder {
//     pub fn new() -> Self;
//     pub fn current_thread() -> Self;
//     pub fn multi_thread() -> Self;
//
//     // Worker configuration
//     pub fn worker_threads(self, n: usize) -> Self;
//     pub fn thread_stack_size(self, size: usize) -> Self;
//     pub fn thread_name_prefix(self, prefix: impl Into<String>) -> Self;
//
//     // Scheduling
//     pub fn global_queue_limit(self, limit: usize) -> Self;
//     pub fn steal_batch_size(self, size: usize) -> Self;
//     pub fn poll_budget(self, budget: u32) -> Self;
//     pub fn enable_parking(self, enable: bool) -> Self;
//
//     // Blocking pool
//     pub fn blocking_threads(self, min: usize, max: usize) -> Self;
//
//     // Callbacks
//     pub fn on_thread_start<F>(self, f: F) -> Self
//         where F: Fn() + Send + Sync + 'static;
//     pub fn on_thread_stop<F>(self, f: F) -> Self
//         where F: Fn() + Send + Sync + 'static;
//
//     // Sub-builders
//     pub fn deadline_monitoring<F>(self, f: F) -> Self
//         where F: FnOnce(DeadlineMonitoringBuilder) -> DeadlineMonitoringBuilder;
//
//     // Build
//     pub fn build(self) -> BuildResult<Runtime>;
// }
// ```
//
// **Validation at build()**:
// - `worker_threads >= 1`
// - `poll_budget >= 1`
// - `blocking.min_threads <= blocking.max_threads`

// ───────────────────────────────────────────────────────────────────────────
// LabRuntimeBuilder (src/lab/mod.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct LabRuntimeBuilder {
//     config: LabConfig,
// }
//
// impl LabRuntimeBuilder {
//     pub fn new(seed: u64) -> Self;
//     pub fn from_time() -> Self;
//
//     // Core settings
//     pub fn seed(self, seed: u64) -> Self;
//     pub fn panic_on_leak(self, enable: bool) -> Self;
//     pub fn trace_capacity(self, capacity: usize) -> Self;
//     pub fn max_steps(self, steps: u64) -> Self;
//     pub fn no_step_limit(self) -> Self;
//
//     // Futurelock detection
//     pub fn futurelock_max_idle_steps(self, steps: u64) -> Self;
//     pub fn panic_on_futurelock(self, enable: bool) -> Self;
//
//     // Chaos injection (sub-builder)
//     pub fn chaos<F>(self, f: F) -> Self
//         where F: FnOnce(ChaosConfigBuilder) -> ChaosConfigBuilder;
//     pub fn with_light_chaos(self) -> Self;
//     pub fn with_heavy_chaos(self) -> Self;
//
//     // Replay recording
//     pub fn with_replay_recording<F>(self, f: F) -> Self
//         where F: FnOnce(RecorderConfigBuilder) -> RecorderConfigBuilder;
//
//     // Build
//     pub fn build(self) -> BuildResult<LabRuntime>;
// }
// ```
//
// **Validation at build()**:
// - None required (all fields have sensible defaults)

// ───────────────────────────────────────────────────────────────────────────
// ChaosConfigBuilder (src/lab/chaos.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct ChaosConfigBuilder {
//     config: ChaosConfig,
// }
//
// impl ChaosConfigBuilder {
//     pub fn new(seed: u64) -> Self;
//     pub fn off() -> Self;
//     pub fn light() -> Self;
//     pub fn heavy() -> Self;
//
//     pub fn seed(self, seed: u64) -> Self;
//     pub fn cancel_probability(self, p: f64) -> Self;
//     pub fn delay_probability(self, p: f64) -> Self;
//     pub fn delay_range(self, range: Range<Duration>) -> Self;
//     pub fn io_error_probability(self, p: f64) -> Self;
//     pub fn io_error_kinds(self, kinds: Vec<io::ErrorKind>) -> Self;
//     pub fn wakeup_storm_probability(self, p: f64) -> Self;
//     pub fn wakeup_storm_count(self, range: Range<usize>) -> Self;
//     pub fn budget_exhaust_probability(self, p: f64) -> Self;
//
//     pub fn build(self) -> BuildResult<ChaosConfig>;
// }
// ```
//
// **Validation (immediate in setters)**:
// - All probabilities must be in [0.0, 1.0]
//
// **Validation at build()**:
// - If `io_error_probability > 0.0`, `io_error_kinds` must not be empty

// ───────────────────────────────────────────────────────────────────────────
// PoolConfigBuilder (src/sync/pool.rs, src/http/pool.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct PoolConfigBuilder {
//     min_size: usize,
//     max_size: usize,
//     acquire_timeout: Duration,
//     idle_timeout: Option<Duration>,
//     max_lifetime: Option<Duration>,
// }
//
// impl PoolConfigBuilder {
//     pub fn new() -> Self;
//
//     pub fn min_size(self, n: usize) -> Self;
//     pub fn max_size(self, n: usize) -> Self;
//     pub fn acquire_timeout(self, timeout: Duration) -> Self;
//     pub fn idle_timeout(self, timeout: Duration) -> Self;
//     pub fn max_lifetime(self, lifetime: Duration) -> Self;
//
//     pub fn build(self) -> BuildResult<PoolConfig>;
// }
// ```
//
// **Validation at build()**:
// - `min_size <= max_size`
// - `max_size >= 1`
// - `acquire_timeout > 0`

// ───────────────────────────────────────────────────────────────────────────
// TransportConfigBuilder (src/config.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct TransportConfigBuilder {
//     max_symbol_size: usize,
//     max_concurrent_streams: usize,
//     stream_timeout: Duration,
//     congestion_control: CongestionControlStrategy,
// }
//
// impl TransportConfigBuilder {
//     pub fn new() -> Self;
//
//     pub fn max_symbol_size(self, size: usize) -> Self;
//     pub fn max_concurrent_streams(self, n: usize) -> Self;
//     pub fn stream_timeout(self, timeout: Duration) -> Self;
//     pub fn congestion_control(self, strategy: CongestionControlStrategy) -> Self;
//
//     pub fn build(self) -> BuildResult<TransportConfig>;
// }
// ```
//
// **Validation at build()**:
// - `max_symbol_size > 0`
// - `max_concurrent_streams >= 1`
// - `stream_timeout > 0`

// ───────────────────────────────────────────────────────────────────────────
// CircuitBreakerBuilder (src/combinator/circuit_breaker.rs)
// ───────────────────────────────────────────────────────────────────────────
//
// ```rust
// pub struct CircuitBreakerBuilder {
//     failure_threshold: u32,
//     success_threshold: u32,
//     half_open_max_calls: u32,
//     timeout: Duration,
// }
//
// impl CircuitBreakerBuilder {
//     pub fn new() -> Self;
//
//     pub fn failure_threshold(self, n: u32) -> Self;
//     pub fn success_threshold(self, n: u32) -> Self;
//     pub fn half_open_max_calls(self, n: u32) -> Self;
//     pub fn timeout(self, timeout: Duration) -> Self;
//
//     pub fn build(self) -> BuildResult<CircuitBreaker>;
// }
// ```
//
// **Validation at build()**:
// - `failure_threshold >= 1`
// - `success_threshold >= 1`
// - `timeout > 0`

// ─────────────────────────────────────────────────────────────────────────────
// Ergonomics Guidelines
// ─────────────────────────────────────────────────────────────────────────────
//
// 1. **Always use `#[must_use]` on builder methods**
//    This prevents accidental dropped configurations:
//    ```rust
//    #[must_use]
//    pub fn threads(mut self, n: usize) -> Self { ... }
//    ```
//
// 2. **Accept `impl Into<T>` for string-like arguments**
//    ```rust
//    pub fn name(mut self, name: impl Into<String>) -> Self { ... }
//    ```
//
// 3. **Provide presets for common configurations**
//    ```rust
//    pub fn high_throughput() -> Self { ... }
//    pub fn low_latency() -> Self { ... }
//    ```
//
// 4. **Document validation requirements in doc comments**
//    ```rust
//    /// Sets the worker thread count.
//    ///
//    /// # Validation
//    /// Must be >= 1. Validated at `build()` time.
//    pub fn worker_threads(mut self, n: usize) -> Self { ... }
//    ```
//
// 5. **Return `BuildResult<T>` from `build()`, never panic**
//    ```rust
//    pub fn build(self) -> BuildResult<Runtime> { ... }
//    ```
//
// 6. **Implement `Default` for builders with sensible defaults**
//    ```rust
//    impl Default for RuntimeBuilder {
//        fn default() -> Self { Self::new() }
//    }
//    ```
//
// 7. **Use sub-builder closures for deeply nested config**
//    ```rust
//    pub fn scheduler<F>(self, f: F) -> Self
//        where F: FnOnce(SchedulerBuilder) -> SchedulerBuilder
//    { ... }
//    ```

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn build_error_missing_required() {
        let err = BuildError::missing_required("name");
        assert_eq!(err.field(), Some("name"));
        assert!(err.is_missing_required());
        assert!(err.to_string().contains("missing required"));
        assert!(err.to_string().contains("name"));
    }

    #[test]
    fn build_error_invalid_value() {
        let err = BuildError::invalid_value("threads", "must be >= 1");
        assert_eq!(err.field(), Some("threads"));
        assert!(err.is_invalid_value());
        assert!(err.to_string().contains("invalid threads"));
    }

    #[test]
    fn build_error_invalid_range() {
        let err = BuildError::invalid_range("connections", 100, 10);
        assert_eq!(err.field(), Some("connections"));
        assert!(err.to_string().contains("min (100)"));
        assert!(err.to_string().contains("max (10)"));
    }

    #[test]
    fn build_error_conflicting_options() {
        let err = BuildError::conflicting_options("sync", "async");
        assert!(err.is_conflicting_options());
        assert!(err.to_string().contains("sync"));
        assert!(err.to_string().contains("async"));
        assert!(err.to_string().contains("cannot both be enabled"));
    }

    #[test]
    fn build_error_invalid_probability() {
        let err = BuildError::invalid_probability("cancel_rate", 1.5);
        assert_eq!(err.field(), Some("cancel_rate"));
        assert!(err.to_string().contains("1.5"));
        assert!(err.to_string().contains("[0.0, 1.0]"));
    }

    #[test]
    fn build_error_invalid_duration() {
        let err = BuildError::invalid_duration("timeout", "must be non-zero");
        assert_eq!(err.field(), Some("timeout"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn build_error_dependency_missing() {
        let err = BuildError::dependency_missing("tls", "certificate");
        assert!(err.to_string().contains("tls"));
        assert!(err.to_string().contains("certificate"));
    }

    #[test]
    fn build_error_custom() {
        let err = BuildError::custom("something went wrong");
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn validate_probability_valid() {
        assert!(validate::probability("p", 0.0).is_ok());
        assert!(validate::probability("p", 0.5).is_ok());
        assert!(validate::probability("p", 1.0).is_ok());
    }

    #[test]
    fn validate_probability_invalid() {
        assert!(validate::probability("p", -0.1).is_err());
        assert!(validate::probability("p", 1.1).is_err());
    }

    #[test]
    fn validate_positive() {
        assert!(validate::positive("n", 1).is_ok());
        assert!(validate::positive("n", 0).is_err());
    }

    #[test]
    fn validate_range_valid() {
        assert!(validate::range("r", 0, 100).is_ok());
        assert!(validate::range("r", 50, 50).is_ok());
    }

    #[test]
    fn validate_range_invalid() {
        assert!(validate::range("r", 100, 50).is_err());
    }

    #[test]
    fn validate_nonzero_duration() {
        assert!(validate::nonzero_duration("t", Duration::from_secs(1)).is_ok());
        assert!(validate::nonzero_duration("t", Duration::ZERO).is_err());
    }

    #[test]
    fn validate_non_empty_string() {
        assert!(validate::non_empty_string("s", "hello").is_ok());
        assert!(validate::non_empty_string("s", "").is_err());
    }

    #[test]
    fn validate_required() {
        assert!(validate::required("x", Some(42)).is_ok());
        assert!(validate::required::<i32>("x", None).is_err());
    }
}
