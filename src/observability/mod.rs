//! Comprehensive observability and logging infrastructure.
//!
//! This module provides structured observability primitives for the Asupersync
//! runtime and RaptorQ distributed layer. Unlike the low-level `trace` module
//! (which is optimized for deterministic replay), this module provides:
//!
//! - **Structured logging** with severity levels and rich context
//! - **Metrics** for runtime statistics (counters, gauges, histograms)
//! - **Diagnostic context** for hierarchical operation tracking
//! - **Event batching** for efficient reporting
//! - **Configuration** for runtime observability settings
//!
//! # Design Principles
//!
//! 1. **No stdout/stderr in core**: All output goes through structured types
//! 2. **Determinism-compatible**: Metrics use explicit time, not wall clock
//! 3. **Zero-allocation hot path**: Critical paths avoid heap allocation
//! 4. **Composable**: Works with both lab runtime and production
//!
//! # Example
//!
//! ```ignore
//! use asupersync::observability::{LogEntry, LogLevel, Metrics, ObservabilityConfig};
//!
//! let config = ObservabilityConfig::default()
//!     .with_log_level(LogLevel::Info)
//!     .with_sample_rate(0.1);
//!
//! let mut metrics = Metrics::new();
//! metrics.counter("symbols_encoded").increment(1);
//! metrics.gauge("pending_symbols").set(42);
//!
//! let entry = LogEntry::info("Symbol encoded successfully")
//!     .with_field("object_id", "Obj-12345678")
//!     .with_field("symbol_count", "10");
//! ```

pub mod collector;
pub mod context;
pub mod diagnostics;
pub mod entry;
pub mod level;
pub mod metrics;
pub mod obligation_tracker;
#[cfg(feature = "metrics")]
pub mod otel;
pub mod task_inspector;

pub use collector::LogCollector;
pub use context::{DiagnosticContext, Span, SpanId};
pub use diagnostics::{
    BlockReason, CancelReasonInfo, CancellationExplanation, CancellationStep, Diagnostics,
    ObligationLeak, Reason, RegionOpenExplanation, TaskBlockedExplanation,
};
pub use entry::LogEntry;
pub use level::LogLevel;
pub use metrics::{
    Counter, Gauge, Histogram, MetricValue, Metrics, MetricsProvider, NoOpMetrics, OutcomeKind,
};
pub use obligation_tracker::{
    ObligationInfo, ObligationStateInfo, ObligationSummary, ObligationTracker,
    ObligationTrackerConfig, TypeSummary,
};
#[cfg(feature = "metrics")]
pub use otel::{
    CardinalityOverflow, ExportError, InMemoryExporter, MetricsConfig, MetricsExporter,
    MetricsSnapshot, MultiExporter, NullExporter, OtelMetrics, SamplingConfig, StdoutExporter,
};
pub use task_inspector::{
    TaskDetails, TaskInspector, TaskInspectorConfig, TaskStateInfo, TaskSummary,
};

/// Configuration for observability and logging.
///
/// This struct controls logging levels, tracing behavior, and sampling rates
/// for the runtime. It integrates with both the high-level observability
/// infrastructure and the low-level trace module.
///
/// # Example
///
/// ```
/// use asupersync::observability::{LogLevel, ObservabilityConfig};
///
/// // Development config: verbose logging
/// let dev_config = ObservabilityConfig::default()
///     .with_log_level(LogLevel::Debug)
///     .with_trace_all_symbols(true);
///
/// // Production config: minimal overhead
/// let prod_config = ObservabilityConfig::default()
///     .with_log_level(LogLevel::Warn)
///     .with_sample_rate(0.01)
///     .with_trace_all_symbols(false);
/// ```
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Minimum log level to record.
    log_level: LogLevel,
    /// Whether to trace all symbols (expensive, useful for debugging).
    trace_all_symbols: bool,
    /// Sampling rate for traces (0.0 = none, 1.0 = all).
    sample_rate: f64,
    /// Maximum number of spans to retain in the diagnostic context.
    max_spans: usize,
    /// Maximum number of log entries to retain in the collector.
    max_log_entries: usize,
    /// Whether to include timestamps in log entries.
    include_timestamps: bool,
    /// Whether to enable metrics collection.
    metrics_enabled: bool,
}

impl ObservabilityConfig {
    /// Creates a new observability configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            log_level: LogLevel::Info,
            trace_all_symbols: false,
            sample_rate: 1.0,
            max_spans: 1000,
            max_log_entries: 10000,
            include_timestamps: true,
            metrics_enabled: true,
        }
    }

    /// Sets the minimum log level.
    #[must_use]
    pub fn with_log_level(mut self, level: LogLevel) -> Self {
        self.log_level = level;
        self
    }

    /// Sets whether to trace all symbols.
    #[must_use]
    pub fn with_trace_all_symbols(mut self, trace: bool) -> Self {
        self.trace_all_symbols = trace;
        self
    }

    /// Sets the sampling rate for traces.
    ///
    /// # Panics
    ///
    /// Panics if the rate is not in the range [0.0, 1.0].
    #[must_use]
    pub fn with_sample_rate(mut self, rate: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&rate),
            "sample_rate must be between 0.0 and 1.0"
        );
        self.sample_rate = rate;
        self
    }

    /// Sets the maximum number of spans to retain.
    #[must_use]
    pub fn with_max_spans(mut self, max: usize) -> Self {
        self.max_spans = max;
        self
    }

    /// Sets the maximum number of log entries to retain.
    #[must_use]
    pub fn with_max_log_entries(mut self, max: usize) -> Self {
        self.max_log_entries = max;
        self
    }

    /// Sets whether to include timestamps in log entries.
    #[must_use]
    pub fn with_include_timestamps(mut self, include: bool) -> Self {
        self.include_timestamps = include;
        self
    }

    /// Sets whether to enable metrics collection.
    #[must_use]
    pub fn with_metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Returns the minimum log level.
    #[must_use]
    pub const fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Returns whether to trace all symbols.
    #[must_use]
    pub const fn trace_all_symbols(&self) -> bool {
        self.trace_all_symbols
    }

    /// Returns the sampling rate for traces.
    #[must_use]
    pub const fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Returns the maximum number of spans to retain.
    #[must_use]
    pub const fn max_spans(&self) -> usize {
        self.max_spans
    }

    /// Returns the maximum number of log entries to retain.
    #[must_use]
    pub const fn max_log_entries(&self) -> usize {
        self.max_log_entries
    }

    /// Returns whether timestamps are included in log entries.
    #[must_use]
    pub const fn include_timestamps(&self) -> bool {
        self.include_timestamps
    }

    /// Returns whether metrics collection is enabled.
    #[must_use]
    pub const fn metrics_enabled(&self) -> bool {
        self.metrics_enabled
    }

    /// Creates a log collector configured according to this config.
    #[must_use]
    pub fn create_collector(&self) -> LogCollector {
        LogCollector::new(self.max_log_entries).with_min_level(self.log_level)
    }

    /// Creates a diagnostic context configured according to this config.
    #[must_use]
    pub fn create_diagnostic_context(&self) -> DiagnosticContext {
        DiagnosticContext::new().with_max_completed(self.max_spans)
    }

    /// Creates a metrics registry if metrics are enabled.
    #[must_use]
    pub fn create_metrics(&self) -> Option<Metrics> {
        if self.metrics_enabled {
            Some(Metrics::new())
        } else {
            None
        }
    }

    /// Checks if a trace should be sampled based on the sample rate.
    ///
    /// Uses deterministic sampling based on a hash of the provided key.
    #[must_use]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)] // sample_rate is validated to be 0.0..=1.0
    pub fn should_sample(&self, key: u64) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        // Simple deterministic sampling based on key hash
        let threshold = (self.sample_rate * f64::from(u32::MAX)) as u32;
        (key as u32) < threshold
    }

    /// Returns a development-oriented configuration.
    ///
    /// Verbose logging, full tracing, all metrics enabled.
    #[must_use]
    pub fn development() -> Self {
        Self::new()
            .with_log_level(LogLevel::Debug)
            .with_trace_all_symbols(true)
            .with_sample_rate(1.0)
    }

    /// Returns a production-oriented configuration.
    ///
    /// Minimal logging, sampled tracing, metrics enabled.
    #[must_use]
    pub fn production() -> Self {
        Self::new()
            .with_log_level(LogLevel::Warn)
            .with_trace_all_symbols(false)
            .with_sample_rate(0.01)
    }

    /// Returns a testing-oriented configuration.
    ///
    /// Full logging and tracing for deterministic replay.
    #[must_use]
    pub fn testing() -> Self {
        Self::new()
            .with_log_level(LogLevel::Trace)
            .with_trace_all_symbols(true)
            .with_sample_rate(1.0)
            .with_max_spans(10_000)
            .with_max_log_entries(100_000)
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.log_level(), LogLevel::Info);
        assert!(!config.trace_all_symbols());
        assert!((config.sample_rate() - 1.0).abs() < f64::EPSILON);
        assert!(config.metrics_enabled());
    }

    #[test]
    fn config_builder() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Debug)
            .with_trace_all_symbols(true)
            .with_sample_rate(0.5)
            .with_max_spans(500)
            .with_max_log_entries(5000)
            .with_include_timestamps(false)
            .with_metrics_enabled(false);

        assert_eq!(config.log_level(), LogLevel::Debug);
        assert!(config.trace_all_symbols());
        assert!((config.sample_rate() - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.max_spans(), 500);
        assert_eq!(config.max_log_entries(), 5000);
        assert!(!config.include_timestamps());
        assert!(!config.metrics_enabled());
    }

    #[test]
    fn config_presets() {
        let dev = ObservabilityConfig::development();
        assert_eq!(dev.log_level(), LogLevel::Debug);
        assert!(dev.trace_all_symbols());

        let prod = ObservabilityConfig::production();
        assert_eq!(prod.log_level(), LogLevel::Warn);
        assert!(!prod.trace_all_symbols());
        assert!(prod.sample_rate() < 0.1);

        let test = ObservabilityConfig::testing();
        assert_eq!(test.log_level(), LogLevel::Trace);
        assert!(test.trace_all_symbols());
    }

    #[test]
    fn config_create_collector() {
        let config = ObservabilityConfig::new()
            .with_log_level(LogLevel::Warn)
            .with_max_log_entries(100);

        let collector = config.create_collector();
        assert_eq!(collector.min_level(), LogLevel::Warn);
        assert_eq!(collector.capacity(), 100);
    }

    #[test]
    fn config_create_metrics() {
        let enabled = ObservabilityConfig::new().with_metrics_enabled(true);
        assert!(enabled.create_metrics().is_some());

        let disabled = ObservabilityConfig::new().with_metrics_enabled(false);
        assert!(disabled.create_metrics().is_none());
    }

    #[test]
    fn config_sampling() {
        let full = ObservabilityConfig::new().with_sample_rate(1.0);
        assert!(full.should_sample(0));
        assert!(full.should_sample(u64::MAX));

        let none = ObservabilityConfig::new().with_sample_rate(0.0);
        assert!(!none.should_sample(0));
        assert!(!none.should_sample(u64::MAX));

        let half = ObservabilityConfig::new().with_sample_rate(0.5);
        // Deterministic: same key always gives same result
        let result1 = half.should_sample(12345);
        let result2 = half.should_sample(12345);
        assert_eq!(result1, result2);
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_high() {
        let _ = ObservabilityConfig::new().with_sample_rate(1.5);
    }

    #[test]
    #[should_panic(expected = "sample_rate must be between 0.0 and 1.0")]
    fn config_invalid_sample_rate_negative() {
        let _ = ObservabilityConfig::new().with_sample_rate(-0.1);
    }
}
