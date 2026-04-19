//! OpenTelemetry metrics provider.
//!
//! This module provides [`OtelMetrics`], an implementation of [`MetricsProvider`]
//! that exports Asupersync runtime metrics via OpenTelemetry.
//!
//! # Feature
//!
//! Enable the `metrics` feature to compile this module.
//!
//! # Cardinality Limits
//!
//! High-cardinality labels can cause metric explosion. Use [`MetricsConfig`]
//! to set cardinality limits:
//!
//! ```ignore
//! let config = MetricsConfig {
//!     max_cardinality: 500,
//!     overflow_strategy: CardinalityOverflow::Aggregate,
//!     ..Default::default()
//! };
//! let metrics = OtelMetrics::new_with_config(global::meter("asupersync"), config);
//! ```
//!
//! # Custom Exporters
//!
//! Use [`MetricsExporter`] trait for custom export backends:
//!
//! ```ignore
//! let stdout = StdoutExporter::new();
//! let multi = MultiExporter::new(vec![Box::new(stdout)]);
//! ```
//!
//! # Example
//!
//! ```ignore
//! use opentelemetry::global;
//! use opentelemetry_prometheus::exporter;
//! use prometheus::Registry;
//! use asupersync::observability::OtelMetrics;
//!
//! let registry = Registry::new();
//! let exporter = exporter().with_registry(registry.clone()).build().unwrap();
//! let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
//!     .with_reader(opentelemetry_sdk::metrics::PeriodicReader::builder(exporter).build())
//!     .build();
//! opentelemetry::global::set_meter_provider(provider);
//!
//! let metrics = OtelMetrics::new(global::meter("asupersync"));
//! // RuntimeBuilder::new().metrics(metrics).build();
//! ```

use crate::observability::metrics::{MetricsProvider, OutcomeKind};
use crate::types::{CancelKind, RegionId, TaskId};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// =============================================================================
// Cardinality Management
// =============================================================================

/// Strategy when cardinality limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardinalityOverflow {
    /// Stop recording new label combinations (drop silently).
    #[default]
    Drop,
    /// Aggregate into 'other' bucket.
    Aggregate,
    /// Log warning and continue recording (may cause OOM).
    Warn,
}

/// Configuration for metrics collection.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Maximum unique label combinations per metric.
    pub max_cardinality: usize,
    /// Strategy when cardinality limit is reached.
    pub overflow_strategy: CardinalityOverflow,
    /// Labels to always drop (e.g., request_id, trace_id).
    pub drop_labels: Vec<String>,
    /// Sampling configuration for high-frequency metrics.
    pub sampling: Option<SamplingConfig>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            max_cardinality: 1000,
            overflow_strategy: CardinalityOverflow::Drop,
            drop_labels: Vec::new(),
            sampling: None,
        }
    }
}

impl MetricsConfig {
    /// Create a new metrics configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum cardinality per metric.
    #[must_use]
    pub fn with_max_cardinality(mut self, max: usize) -> Self {
        self.max_cardinality = max;
        self
    }

    /// Set overflow strategy.
    #[must_use]
    pub fn with_overflow_strategy(mut self, strategy: CardinalityOverflow) -> Self {
        self.overflow_strategy = strategy;
        self
    }

    /// Add a label to always drop.
    #[must_use]
    pub fn with_drop_label(mut self, label: impl Into<String>) -> Self {
        self.drop_labels.push(label.into());
        self
    }

    /// Set sampling configuration.
    #[must_use]
    pub fn with_sampling(mut self, sampling: SamplingConfig) -> Self {
        self.sampling = Some(sampling);
        self
    }
}

/// Sampling configuration for high-frequency metrics.
#[derive(Debug, Clone)]
pub struct SamplingConfig {
    /// Sample rate (0.0-1.0). 1.0 = record all.
    pub sample_rate: f64,
    /// Metrics to sample (others recorded fully).
    pub sampled_metrics: Vec<String>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            sample_rate: 1.0,
            sampled_metrics: Vec::new(),
        }
    }
}

impl SamplingConfig {
    /// Create new sampling config with given rate.
    #[must_use]
    pub fn new(sample_rate: f64) -> Self {
        Self {
            sample_rate: sample_rate.clamp(0.0, 1.0),
            sampled_metrics: Vec::new(),
        }
    }

    /// Add a metric to the sampled set.
    #[must_use]
    pub fn with_sampled_metric(mut self, metric: impl Into<String>) -> Self {
        self.sampled_metrics.push(metric.into());
        self
    }
}

/// Tracks cardinality per metric to prevent explosion.
#[derive(Debug, Default)]
struct CardinalityTracker {
    /// Map of metric name -> set of label combination hashes.
    seen: RwLock<HashMap<String, HashSet<u64>>>,
    /// Number of times cardinality limit was hit.
    overflow_count: AtomicU64,
}

impl CardinalityTracker {
    fn new() -> Self {
        Self::default()
    }

    /// Check if recording this label combination would exceed the limit.
    fn would_exceed(&self, metric: &str, labels: &[KeyValue], max_cardinality: usize) -> bool {
        let hash = Self::hash_labels(labels);
        let seen = self.seen.read();

        if max_cardinality == 0 {
            return seen.get(metric).is_none_or(|set| !set.contains(&hash));
        }

        if let Some(set) = seen.get(metric) {
            if set.contains(&hash) {
                return false; // Already seen
            }
            set.len() >= max_cardinality
        } else {
            false // First entry for this metric
        }
    }

    /// Record a label combination.
    fn record(&self, metric: &str, labels: &[KeyValue]) {
        let hash = Self::hash_labels(labels);
        let mut seen = self.seen.write();
        seen.entry(metric.to_string()).or_default().insert(hash);
    }

    /// Atomically check whether a new label set would exceed cardinality and
    /// record it if allowed.
    ///
    /// Returns `true` when the limit would be exceeded and the label set was
    /// not recorded.
    fn check_and_record(&self, metric: &str, labels: &[KeyValue], max_cardinality: usize) -> bool {
        let hash = Self::hash_labels(labels);
        let mut seen = self.seen.write();
        let set = seen.entry(metric.to_string()).or_default();

        if set.contains(&hash) {
            return false;
        }
        if set.len() >= max_cardinality {
            return true;
        }

        set.insert(hash);
        false
    }

    /// Increment overflow counter.
    fn record_overflow(&self) {
        self.overflow_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get overflow count.
    fn overflow_count(&self) -> u64 {
        self.overflow_count.load(Ordering::Relaxed)
    }

    /// Hash labels for tracking.
    fn hash_labels(labels: &[KeyValue]) -> u64 {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        // Treat label sets as order-insensitive. Different construction order of
        // equivalent labels should map to the same cardinality bucket.
        let mut normalized: Vec<(&str, String)> = labels
            .iter()
            .map(|kv| (kv.key.as_str(), format!("{:?}", kv.value)))
            .collect();
        normalized.sort_unstable_by(|(a_key, a_val), (b_key, b_val)| {
            a_key.cmp(b_key).then_with(|| a_val.cmp(b_val))
        });

        let mut hasher = DetHasher::default();
        for (key, value) in normalized {
            key.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get current cardinality for a metric.
    #[cfg(test)]
    fn cardinality(&self, metric: &str) -> usize {
        self.seen
            .read()
            .get(metric)
            .map_or(0, std::collections::HashSet::len)
    }
}

// =============================================================================
// Custom Exporters
// =============================================================================

/// Labels for a metric data point.
pub type MetricLabels = Vec<(String, String)>;

/// A counter data point: (name, labels, value).
pub type CounterDataPoint = (String, MetricLabels, u64);

/// A gauge data point: (name, labels, value).
pub type GaugeDataPoint = (String, MetricLabels, i64);

/// A histogram data point: (name, labels, count, sum).
pub type HistogramDataPoint = (String, MetricLabels, u64, f64);

/// Snapshot of metrics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Counter values: (name, labels, value).
    pub counters: Vec<CounterDataPoint>,
    /// Gauge values: (name, labels, value).
    pub gauges: Vec<GaugeDataPoint>,
    /// Histogram values: (name, labels, count, sum).
    pub histograms: Vec<HistogramDataPoint>,
}

impl MetricsSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a counter value.
    pub fn add_counter(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        value: u64,
    ) {
        self.counters.push((name.into(), labels, value));
    }

    /// Add a gauge value.
    pub fn add_gauge(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        value: i64,
    ) {
        self.gauges.push((name.into(), labels, value));
    }

    /// Add a histogram value.
    pub fn add_histogram(
        &mut self,
        name: impl Into<String>,
        labels: Vec<(String, String)>,
        count: u64,
        sum: f64,
    ) {
        self.histograms.push((name.into(), labels, count, sum));
    }
}

/// Error type for export operations.
#[derive(Debug, Clone)]
pub struct ExportError {
    message: String,
}

impl ExportError {
    /// Create a new export error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "export error: {}", self.message)
    }
}

impl std::error::Error for ExportError {}

/// Trait for custom metrics exporters.
pub trait MetricsExporter: Send + Sync {
    /// Export a snapshot of metrics.
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError>;

    /// Flush any buffered data.
    fn flush(&self) -> Result<(), ExportError>;
}

/// Exporter that writes to stdout (for debugging).
#[derive(Debug)]
pub struct StdoutExporter {
    prefix: String,
}

impl Default for StdoutExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutExporter {
    /// Create a new stdout exporter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    /// Create with a prefix for each line.
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    fn format_labels(labels: &[(String, String)]) -> String {
        if labels.is_empty() {
            String::new()
        } else {
            let parts: Vec<_> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

impl MetricsExporter for StdoutExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let mut stdout = std::io::stdout().lock();

        for (name, labels, value) in &metrics.counters {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}COUNTER {}{} {}",
                self.prefix, name, label_str, value
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        for (name, labels, value) in &metrics.gauges {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}GAUGE {}{} {}",
                self.prefix, name, label_str, value
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        for (name, labels, count, sum) in &metrics.histograms {
            let label_str = Self::format_labels(labels);
            writeln!(
                stdout,
                "{}HISTOGRAM {}{} count={} sum={}",
                self.prefix, name, label_str, count, sum
            )
            .map_err(|e| ExportError::new(e.to_string()))?;
        }

        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        std::io::stdout()
            .flush()
            .map_err(|e| ExportError::new(e.to_string()))
    }
}

/// Exporter that does nothing (for testing).
#[derive(Debug, Default)]
pub struct NullExporter;

impl NullExporter {
    /// Create a new null exporter.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl MetricsExporter for NullExporter {
    fn export(&self, _metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

/// Exporter that fans out to multiple exporters.
#[derive(Default)]
pub struct MultiExporter {
    exporters: Vec<Box<dyn MetricsExporter>>,
}

impl MultiExporter {
    /// Create a new multi-exporter.
    #[must_use]
    pub fn new(exporters: Vec<Box<dyn MetricsExporter>>) -> Self {
        Self { exporters }
    }

    /// Add an exporter.
    pub fn add(&mut self, exporter: Box<dyn MetricsExporter>) {
        self.exporters.push(exporter);
    }

    /// Number of exporters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exporters.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exporters.is_empty()
    }
}

impl std::fmt::Debug for MultiExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiExporter")
            .field("exporters_count", &self.exporters.len())
            .finish()
    }
}

impl MetricsExporter for MultiExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(e) = exporter.export(metrics) {
                errors.push(e.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }

    fn flush(&self) -> Result<(), ExportError> {
        let mut errors = Vec::new();
        for exporter in &self.exporters {
            if let Err(e) = exporter.flush() {
                errors.push(e.message);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ExportError::new(errors.join("; ")))
        }
    }
}

/// Exporter that collects metrics in memory for testing.
#[derive(Debug, Default)]
pub struct InMemoryExporter {
    snapshots: Mutex<Vec<MetricsSnapshot>>,
}

impl InMemoryExporter {
    /// Create a new in-memory exporter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all collected snapshots.
    #[must_use]
    pub fn snapshots(&self) -> Vec<MetricsSnapshot> {
        self.snapshots.lock().clone()
    }

    /// Clear collected snapshots.
    pub fn clear(&self) {
        self.snapshots.lock().clear();
    }

    /// Get total number of metrics recorded.
    #[must_use]
    pub fn total_metrics(&self) -> usize {
        let snapshots = self.snapshots.lock();
        snapshots
            .iter()
            .map(|s| s.counters.len() + s.gauges.len() + s.histograms.len())
            .sum()
    }
}

impl MetricsExporter for InMemoryExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        self.snapshots.lock().push(metrics.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), ExportError> {
        Ok(())
    }
}

// =============================================================================
// OtelMetrics
// =============================================================================

/// OpenTelemetry metrics provider for Asupersync.
///
/// This provider supports:
/// - Cardinality limits to prevent metric explosion
/// - Configurable overflow strategies
/// - Sampling for high-frequency metrics
#[derive(Clone)]
pub struct OtelMetrics {
    // Task metrics
    #[allow(dead_code)]
    tasks_active: ObservableGauge<u64>,
    tasks_spawned: Counter<u64>,
    tasks_completed: Counter<u64>,
    task_duration: Histogram<f64>,
    // Region metrics
    #[allow(dead_code)]
    regions_active: ObservableGauge<u64>,
    regions_created: Counter<u64>,
    regions_closed: Counter<u64>,
    region_lifetime: Histogram<f64>,
    // Cancellation metrics
    cancellations: Counter<u64>,
    drain_duration: Histogram<f64>,
    // Budget metrics
    deadlines_set: Counter<u64>,
    deadlines_exceeded: Counter<u64>,
    // Deadline monitoring metrics
    deadline_warnings: Counter<u64>,
    deadline_violations: Counter<u64>,
    deadline_remaining: Histogram<f64>,
    checkpoint_interval: Histogram<f64>,
    task_stuck_detected: Counter<u64>,
    // Obligation metrics
    #[allow(dead_code)]
    obligations_active: ObservableGauge<u64>,
    obligations_created: Counter<u64>,
    obligations_discharged: Counter<u64>,
    obligations_leaked: Counter<u64>,
    // Scheduler metrics
    scheduler_poll_time: Histogram<f64>,
    scheduler_tasks_polled: Histogram<f64>,
    // Shared gauge state
    state: Arc<MetricsState>,
    // Cardinality tracking
    config: MetricsConfig,
    cardinality_tracker: Arc<CardinalityTracker>,
    // Sampling state
    sample_counter: Arc<AtomicU64>,
}

impl std::fmt::Debug for OtelMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelMetrics")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
struct MetricsState {
    active_tasks: AtomicU64,
    active_regions: AtomicU64,
    active_obligations: AtomicU64,
}

impl MetricsState {
    fn inc_tasks(&self) {
        self.active_tasks.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_tasks(&self) {
        let _ = self
            .active_tasks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    fn inc_regions(&self) {
        self.active_regions.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_regions(&self) {
        let _ = self
            .active_regions
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    fn inc_obligations(&self) {
        self.active_obligations.fetch_add(1, Ordering::Relaxed);
    }

    fn dec_obligations(&self) {
        let _ = self
            .active_obligations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }
}

impl OtelMetrics {
    /// Constructs a new OpenTelemetry metrics provider from a [`Meter`].
    #[must_use]
    pub fn new(meter: Meter) -> Self {
        Self::new_with_config(meter, MetricsConfig::default())
    }

    /// Constructs a new OpenTelemetry metrics provider with configuration.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::needless_pass_by_value)] // Meter is consumed by builder pattern
    pub fn new_with_config(meter: Meter, config: MetricsConfig) -> Self {
        let state = Arc::new(MetricsState::default());

        let tasks_active = meter
            .u64_observable_gauge("asupersync.tasks.active")
            .with_description("Currently running tasks")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_tasks.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        let regions_active = meter
            .u64_observable_gauge("asupersync.regions.active")
            .with_description("Currently active regions")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_regions.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        let obligations_active = meter
            .u64_observable_gauge("asupersync.obligations.active")
            .with_description("Currently active obligations")
            .with_callback({
                let state = Arc::clone(&state);
                move |observer| {
                    observer.observe(state.active_obligations.load(Ordering::Relaxed), &[]);
                }
            })
            .build();

        Self {
            tasks_active,
            tasks_spawned: meter
                .u64_counter("asupersync.tasks.spawned")
                .with_description("Total tasks spawned")
                .build(),
            tasks_completed: meter
                .u64_counter("asupersync.tasks.completed")
                .with_description("Total tasks completed")
                .build(),
            task_duration: meter
                .f64_histogram("asupersync.tasks.duration")
                .with_description("Task execution duration in seconds")
                .build(),
            regions_active,
            regions_created: meter
                .u64_counter("asupersync.regions.created")
                .with_description("Total regions created")
                .build(),
            regions_closed: meter
                .u64_counter("asupersync.regions.closed")
                .with_description("Total regions closed")
                .build(),
            region_lifetime: meter
                .f64_histogram("asupersync.regions.lifetime")
                .with_description("Region lifetime in seconds")
                .build(),
            cancellations: meter
                .u64_counter("asupersync.cancellations")
                .with_description("Cancellation requests")
                .build(),
            drain_duration: meter
                .f64_histogram("asupersync.cancellation.drain_duration")
                .with_description("Cancellation drain duration in seconds")
                .build(),
            deadlines_set: meter
                .u64_counter("asupersync.deadlines.set")
                .with_description("Deadlines configured")
                .build(),
            deadlines_exceeded: meter
                .u64_counter("asupersync.deadlines.exceeded")
                .with_description("Deadline exceeded events")
                .build(),
            deadline_warnings: meter
                .u64_counter("asupersync.deadline.warnings_total")
                .with_description("Deadline warning events")
                .build(),
            deadline_violations: meter
                .u64_counter("asupersync.deadline.violations_total")
                .with_description("Deadline violation events")
                .build(),
            deadline_remaining: meter
                .f64_histogram("asupersync.deadline.remaining_seconds")
                .with_description("Time remaining at completion in seconds")
                .build(),
            checkpoint_interval: meter
                .f64_histogram("asupersync.checkpoint.interval_seconds")
                .with_description("Time between checkpoints in seconds")
                .build(),
            task_stuck_detected: meter
                .u64_counter("asupersync.task.stuck_detected_total")
                .with_description("Tasks detected as stuck (no progress)")
                .build(),
            obligations_active,
            obligations_created: meter
                .u64_counter("asupersync.obligations.created")
                .with_description("Obligations created")
                .build(),
            obligations_discharged: meter
                .u64_counter("asupersync.obligations.discharged")
                .with_description("Obligations discharged")
                .build(),
            obligations_leaked: meter
                .u64_counter("asupersync.obligations.leaked")
                .with_description("Obligations leaked")
                .build(),
            scheduler_poll_time: meter
                .f64_histogram("asupersync.scheduler.poll_time")
                .with_description("Scheduler poll duration in seconds")
                .build(),
            scheduler_tasks_polled: meter
                .f64_histogram("asupersync.scheduler.tasks_polled")
                .with_description("Tasks polled per scheduler tick")
                .build(),
            state,
            config,
            cardinality_tracker: Arc::new(CardinalityTracker::new()),
            sample_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the current configuration.
    #[must_use]
    pub fn config(&self) -> &MetricsConfig {
        &self.config
    }

    /// Get the number of cardinality overflows that have occurred.
    #[must_use]
    pub fn cardinality_overflow_count(&self) -> u64 {
        self.cardinality_tracker.overflow_count()
    }

    /// Check if recording a metric should proceed, handling cardinality limits.
    ///
    /// Returns `Some(labels)` with potentially modified labels if recording should proceed,
    /// or `None` if the metric should be dropped.
    fn check_cardinality(&self, metric: &str, labels: &[KeyValue]) -> Option<Vec<KeyValue>> {
        // Filter out dropped labels
        let filtered: Vec<KeyValue> = labels
            .iter()
            .filter(|kv| !self.config.drop_labels.contains(&kv.key.to_string()))
            .cloned()
            .collect();

        if self
            .cardinality_tracker
            .check_and_record(metric, &filtered, self.config.max_cardinality)
        {
            self.cardinality_tracker.record_overflow();

            match self.config.overflow_strategy {
                CardinalityOverflow::Drop => return None,
                CardinalityOverflow::Aggregate => {
                    // Replace high-cardinality labels with "other"
                    let aggregated: Vec<KeyValue> = filtered
                        .into_iter()
                        .map(|kv| KeyValue::new(kv.key, "other"))
                        .collect();
                    if self.cardinality_tracker.check_and_record(
                        metric,
                        &aggregated,
                        self.config.max_cardinality,
                    ) {
                        return None;
                    }
                    return Some(aggregated);
                }
                CardinalityOverflow::Warn => {
                    crate::tracing_compat::warn!(
                        metric = metric,
                        "cardinality limit reached for metric"
                    );
                    self.cardinality_tracker.record(metric, &filtered);
                }
            }
        }
        Some(filtered)
    }

    /// Check if a metric should be sampled.
    fn should_sample(&self, metric: &str) -> bool {
        let Some(ref sampling) = self.config.sampling else {
            return true; // No sampling configured
        };

        // Check if this metric is in the sampled set
        if !sampling.sampled_metrics.is_empty()
            && !sampling.sampled_metrics.iter().any(|m| metric.contains(m))
        {
            return true; // Not a sampled metric
        }

        if sampling.sample_rate >= 1.0 {
            return true;
        }
        if sampling.sample_rate <= 0.0 {
            return false;
        }

        // Use counter-based sampling for determinism
        let count = self.sample_counter.fetch_add(1, Ordering::Relaxed);
        // sample_rate is always 0.0..=1.0, so the cast is safe
        #[allow(clippy::cast_sign_loss)]
        let threshold = (sampling.sample_rate * 100.0) as u64;
        (count % 100) < threshold
    }
}

impl MetricsProvider for OtelMetrics {
    fn task_spawned(&self, _region_id: RegionId, _task_id: TaskId) {
        self.state.inc_tasks();
        self.tasks_spawned.add(1, &[]);
    }

    fn task_completed(&self, _task_id: TaskId, outcome: OutcomeKind, duration: Duration) {
        self.state.dec_tasks();

        let labels = [KeyValue::new("outcome", outcome_label(outcome))];
        if let Some(filtered) = self.check_cardinality("asupersync.tasks.completed", &labels) {
            self.tasks_completed.add(1, &filtered);
        }

        if self.should_sample("asupersync.tasks.duration") {
            if let Some(filtered) = self.check_cardinality("asupersync.tasks.duration", &labels) {
                self.task_duration.record(duration.as_secs_f64(), &filtered);
            }
        }
    }

    fn region_created(&self, _region_id: RegionId, _parent: Option<RegionId>) {
        self.state.inc_regions();
        self.regions_created.add(1, &[]);
    }

    fn region_closed(&self, _region_id: RegionId, lifetime: Duration) {
        self.state.dec_regions();
        self.regions_closed.add(1, &[]);

        if self.should_sample("asupersync.regions.lifetime") {
            self.region_lifetime.record(lifetime.as_secs_f64(), &[]);
        }
    }

    fn cancellation_requested(&self, _region_id: RegionId, kind: CancelKind) {
        let labels = [KeyValue::new("kind", cancel_kind_label(kind))];
        if let Some(filtered) = self.check_cardinality("asupersync.cancellations", &labels) {
            self.cancellations.add(1, &filtered);
        }
    }

    fn drain_completed(&self, _region_id: RegionId, duration: Duration) {
        if self.should_sample("asupersync.cancellation.drain_duration") {
            self.drain_duration.record(duration.as_secs_f64(), &[]);
        }
    }

    fn deadline_set(&self, _region_id: RegionId, _deadline: Duration) {
        self.deadlines_set.add(1, &[]);
    }

    fn deadline_exceeded(&self, _region_id: RegionId) {
        self.deadlines_exceeded.add(1, &[]);
    }

    fn deadline_warning(&self, task_type: &str, reason: &'static str, remaining: Duration) {
        let task_type = task_type.to_string();
        let labels = [
            KeyValue::new("task_type", task_type),
            KeyValue::new("reason", reason),
        ];
        if let Some(filtered) =
            self.check_cardinality("asupersync.deadline.warnings_total", &labels)
        {
            self.deadline_warnings.add(1, &filtered);
        }
        let _ = remaining;
    }

    fn deadline_violation(&self, task_type: &str, _over_by: Duration) {
        let task_type = task_type.to_string();
        let labels = [KeyValue::new("task_type", task_type)];
        if let Some(filtered) =
            self.check_cardinality("asupersync.deadline.violations_total", &labels)
        {
            self.deadline_violations.add(1, &filtered);
        }
    }

    fn deadline_remaining(&self, task_type: &str, remaining: Duration) {
        if self.should_sample("asupersync.deadline.remaining_seconds") {
            let task_type = task_type.to_string();
            let labels = [KeyValue::new("task_type", task_type)];
            if let Some(filtered) =
                self.check_cardinality("asupersync.deadline.remaining_seconds", &labels)
            {
                self.deadline_remaining
                    .record(remaining.as_secs_f64(), &filtered);
            }
        }
    }

    fn checkpoint_interval(&self, task_type: &str, interval: Duration) {
        if self.should_sample("asupersync.checkpoint.interval_seconds") {
            let task_type = task_type.to_string();
            let labels = [KeyValue::new("task_type", task_type)];
            if let Some(filtered) =
                self.check_cardinality("asupersync.checkpoint.interval_seconds", &labels)
            {
                self.checkpoint_interval
                    .record(interval.as_secs_f64(), &filtered);
            }
        }
    }

    fn task_stuck_detected(&self, task_type: &str) {
        let task_type = task_type.to_string();
        let labels = [KeyValue::new("task_type", task_type)];
        if let Some(filtered) =
            self.check_cardinality("asupersync.task.stuck_detected_total", &labels)
        {
            self.task_stuck_detected.add(1, &filtered);
        }
    }

    fn obligation_created(&self, _region_id: RegionId) {
        self.state.inc_obligations();
        self.obligations_created.add(1, &[]);
    }

    fn obligation_discharged(&self, _region_id: RegionId) {
        self.state.dec_obligations();
        self.obligations_discharged.add(1, &[]);
    }

    fn obligation_leaked(&self, _region_id: RegionId) {
        self.state.dec_obligations();
        self.obligations_leaked.add(1, &[]);
    }

    fn scheduler_tick(&self, tasks_polled: usize, duration: Duration) {
        if self.should_sample("asupersync.scheduler") {
            self.scheduler_poll_time.record(duration.as_secs_f64(), &[]);
            // Precision loss is acceptable for metrics (only affects counts > 2^52)
            #[allow(clippy::cast_precision_loss)]
            self.scheduler_tasks_polled.record(tasks_polled as f64, &[]);
        }
    }
}

const fn outcome_label(outcome: OutcomeKind) -> &'static str {
    match outcome {
        OutcomeKind::Ok => "ok",
        OutcomeKind::Err => "err",
        OutcomeKind::Cancelled => "cancelled",
        OutcomeKind::Panicked => "panicked",
    }
}

const fn cancel_kind_label(kind: CancelKind) -> &'static str {
    match kind {
        CancelKind::User => "user",
        CancelKind::Timeout => "timeout",
        CancelKind::Deadline => "deadline",
        CancelKind::PollQuota => "poll_quota",
        CancelKind::CostBudget => "cost_budget",
        CancelKind::FailFast => "fail_fast",
        CancelKind::RaceLost => "race_lost",
        CancelKind::ParentCancelled => "parent_cancelled",
        CancelKind::ResourceUnavailable => "resource_unavailable",
        CancelKind::Shutdown => "shutdown",
        CancelKind::LinkedExit => "linked_exit",
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use crate::test_utils::init_test_logging;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter as OtelInMemoryExporter, PeriodicReader, SdkMeterProvider,
        data::ResourceMetrics,
    };
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::{Arc, Barrier};

    const EXPECTED_METRICS: &[&str] = &[
        "asupersync.tasks.spawned",
        "asupersync.tasks.completed",
        "asupersync.tasks.duration",
        "asupersync.regions.created",
        "asupersync.regions.closed",
        "asupersync.regions.lifetime",
        "asupersync.cancellations",
        "asupersync.cancellation.drain_duration",
        "asupersync.deadlines.set",
        "asupersync.deadlines.exceeded",
        "asupersync.deadline.warnings_total",
        "asupersync.deadline.violations_total",
        "asupersync.deadline.remaining_seconds",
        "asupersync.checkpoint.interval_seconds",
        "asupersync.task.stuck_detected_total",
        "asupersync.obligations.created",
        "asupersync.obligations.discharged",
        "asupersync.obligations.leaked",
        "asupersync.scheduler.poll_time",
        "asupersync.scheduler.tasks_polled",
    ];

    fn metric_names(finished: &[ResourceMetrics]) -> HashSet<String> {
        let mut names = HashSet::new();
        for resource_metrics in finished {
            for scope_metrics in resource_metrics.scope_metrics() {
                for metric in scope_metrics.metrics() {
                    names.insert(metric.name().to_string());
                }
            }
        }
        names
    }

    fn assert_expected_metrics_present(names: &HashSet<String>, expected: &[&str]) {
        for name in expected {
            assert!(names.contains(*name), "missing metric: {name}");
        }
    }

    fn collect_grafana_queries(value: &serde_json::Value, output: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    if key == "expr" || key == "query" {
                        if let serde_json::Value::String(text) = val {
                            output.push(text.clone());
                        }
                    } else {
                        collect_grafana_queries(val, output);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_grafana_queries(item, output);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn otel_metrics_exports_in_memory() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let metrics = OtelMetrics::new(meter);

        metrics.task_spawned(RegionId::testing_default(), TaskId::testing_default());
        metrics.task_completed(
            TaskId::testing_default(),
            OutcomeKind::Ok,
            Duration::from_millis(10),
        );
        metrics.region_created(RegionId::testing_default(), None);
        metrics.region_closed(RegionId::testing_default(), Duration::from_secs(1));
        metrics.cancellation_requested(RegionId::testing_default(), CancelKind::User);
        metrics.drain_completed(RegionId::testing_default(), Duration::from_millis(5));
        metrics.deadline_set(RegionId::testing_default(), Duration::from_secs(2));
        metrics.deadline_exceeded(RegionId::testing_default());
        metrics.deadline_warning("test", "no_progress", Duration::from_secs(1));
        metrics.deadline_violation("test", Duration::from_secs(1));
        metrics.deadline_remaining("test", Duration::from_secs(5));
        metrics.checkpoint_interval("test", Duration::from_millis(200));
        metrics.task_stuck_detected("test");
        metrics.obligation_created(RegionId::testing_default());
        metrics.obligation_discharged(RegionId::testing_default());
        metrics.obligation_leaked(RegionId::testing_default());
        metrics.scheduler_tick(3, Duration::from_millis(1));

        provider.force_flush().expect("force_flush");
        let finished = exporter.get_finished_metrics().expect("finished metrics");
        assert!(!finished.is_empty());
        let names = metric_names(&finished);
        assert_expected_metrics_present(&names, EXPECTED_METRICS);

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn otel_metrics_runtime_integration_emits_task_metrics() {
        init_test_logging();
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let metrics = OtelMetrics::new(meter);
        let runtime = RuntimeBuilder::new()
            .metrics(metrics)
            .build()
            .expect("runtime build");

        let handle = runtime.handle().spawn(async { 7u8 });
        let result = runtime.block_on(handle);
        assert_eq!(result, 7);

        for _ in 0..1024 {
            if runtime.is_quiescent() {
                break;
            }
            std::thread::yield_now();
        }
        assert!(runtime.is_quiescent(), "runtime did not reach quiescence");

        provider.force_flush().expect("force_flush");
        let finished = exporter.get_finished_metrics().expect("finished metrics");
        assert!(!finished.is_empty());
        let names = metric_names(&finished);
        assert_expected_metrics_present(
            &names,
            &[
                "asupersync.tasks.spawned",
                "asupersync.tasks.completed",
                "asupersync.tasks.duration",
            ],
        );

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn grafana_dashboard_references_expected_metrics() {
        init_test_logging();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/grafana_dashboard.json");
        let contents = std::fs::read_to_string(path).expect("read grafana dashboard");
        let json: serde_json::Value =
            serde_json::from_str(&contents).expect("parse grafana dashboard");

        let mut queries = Vec::new();
        collect_grafana_queries(&json, &mut queries);
        assert!(!queries.is_empty(), "expected grafana queries to exist");

        let joined = queries.join("\n");
        let expected = [
            "asupersync_tasks_spawned_total",
            "asupersync_tasks_completed_total",
            "asupersync_tasks_duration_bucket",
            "asupersync_regions_active",
            "asupersync_cancellations_total",
            "asupersync_deadline_warnings_total",
            "asupersync_deadline_violations_total",
            "asupersync_deadline_remaining_seconds_bucket",
            "asupersync_checkpoint_interval_seconds_bucket",
            "asupersync_task_stuck_detected_total",
        ];
        for metric in expected {
            assert!(
                joined.contains(metric),
                "missing grafana query metric: {metric}"
            );
        }
    }

    #[test]
    fn otel_metrics_with_config() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new()
            .with_max_cardinality(500)
            .with_overflow_strategy(CardinalityOverflow::Aggregate);

        let metrics = OtelMetrics::new_with_config(meter, config);
        assert_eq!(metrics.config().max_cardinality, 500);
        assert_eq!(
            metrics.config().overflow_strategy,
            CardinalityOverflow::Aggregate
        );

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn cardinality_tracker_basic() {
        let tracker = CardinalityTracker::new();

        let labels = [KeyValue::new("outcome", "ok")];
        assert!(!tracker.would_exceed("test", &labels, 10));

        tracker.record("test", &labels);
        assert_eq!(tracker.cardinality("test"), 1);

        // Same labels should not increase cardinality
        tracker.record("test", &labels);
        assert_eq!(tracker.cardinality("test"), 1);

        // Different labels should increase
        let labels2 = [KeyValue::new("outcome", "err")];
        tracker.record("test", &labels2);
        assert_eq!(tracker.cardinality("test"), 2);
    }

    #[test]
    fn cardinality_limit_enforced() {
        let tracker = CardinalityTracker::new();

        // Fill up to max
        for i in 0..5 {
            let labels = [KeyValue::new("id", i.to_string())];
            tracker.record("test", &labels);
        }
        assert_eq!(tracker.cardinality("test"), 5);

        // Next should exceed
        let labels = [KeyValue::new("id", "new")];
        assert!(tracker.would_exceed("test", &labels, 5));
    }

    #[test]
    fn cardinality_limit_zero_rejects_new_series() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("id", "first")];
        assert!(
            tracker.would_exceed("test", &labels, 0),
            "zero-cardinality budget must reject unseen label sets"
        );
        assert!(tracker.check_and_record("test", &labels, 0));
        assert_eq!(tracker.cardinality("test"), 0);
    }

    #[test]
    fn cardinality_enforcement_is_atomic_under_concurrency() {
        let tracker = Arc::new(CardinalityTracker::new());
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let tracker = Arc::clone(&tracker);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let labels = [KeyValue::new("id", i.to_string())];
                    barrier.wait();
                    !tracker.check_and_record("test", &labels, 1)
                })
            })
            .collect();

        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread join"))
            .filter(|accepted| *accepted)
            .count();

        assert_eq!(accepted, 1, "exactly one series should fit under max=1");
        assert_eq!(tracker.cardinality("test"), 1);
    }

    #[test]
    fn cardinality_label_order_is_ignored() {
        let tracker = CardinalityTracker::new();

        let labels_a = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("region", "root"),
        ];
        let labels_b = [
            KeyValue::new("region", "root"),
            KeyValue::new("outcome", "ok"),
        ];

        tracker.record("test", &labels_a);
        assert!(
            !tracker.would_exceed("test", &labels_b, 1),
            "label order should not increase cardinality"
        );
        tracker.record("test", &labels_b);
        assert_eq!(tracker.cardinality("test"), 1);
    }

    #[test]
    fn drop_labels_filtered() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new().with_drop_label("request_id");
        let metrics = OtelMetrics::new_with_config(meter, config);

        // Labels with request_id should have it filtered
        let labels = [
            KeyValue::new("outcome", "ok"),
            KeyValue::new("request_id", "12345"),
        ];

        let filtered = metrics.check_cardinality("test", &labels);
        assert!(filtered.is_some());
        let filtered = filtered.unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].key.as_str(), "outcome");

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn aggregate_overflow_does_not_exceed_configured_budget() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("asupersync");

        let config = MetricsConfig::new()
            .with_max_cardinality(1)
            .with_overflow_strategy(CardinalityOverflow::Aggregate);
        let metrics = OtelMetrics::new_with_config(meter, config);

        let first = [KeyValue::new("task_type", "fast")];
        let second = [KeyValue::new("task_type", "slow")];

        let first_labels = metrics
            .check_cardinality("test.metric", &first)
            .expect("first label set should fit");
        assert_eq!(first_labels, first);
        assert_eq!(metrics.cardinality_tracker.cardinality("test.metric"), 1);

        assert!(
            metrics.check_cardinality("test.metric", &second).is_none(),
            "aggregate overflow must not create a second series beyond the configured cap"
        );
        assert_eq!(metrics.cardinality_tracker.cardinality("test.metric"), 1);

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn sampling_config() {
        let sampling = SamplingConfig::new(0.5).with_sampled_metric("duration");
        assert!((sampling.sample_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(sampling.sampled_metrics.len(), 1);
    }

    #[test]
    fn sampling_rate_clamped() {
        let sampling = SamplingConfig::new(1.5);
        assert!((sampling.sample_rate - 1.0).abs() < f64::EPSILON);

        let sampling = SamplingConfig::new(-0.5);
        assert!(sampling.sample_rate.abs() < f64::EPSILON);
    }
}

#[cfg(test)]
mod exporter_tests {
    use super::*;

    #[test]
    fn null_exporter_works() {
        let exporter = NullExporter::new();
        let snapshot = MetricsSnapshot::new();
        assert!(exporter.export(&snapshot).is_ok());
        assert!(exporter.flush().is_ok());
    }

    #[test]
    fn in_memory_exporter_collects() {
        let exporter = InMemoryExporter::new();

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test.counter", vec![], 42);
        snapshot.add_gauge(
            "test.gauge",
            vec![("label".to_string(), "value".to_string())],
            100,
        );
        snapshot.add_histogram("test.histogram", vec![], 10, 5.5);

        assert!(exporter.export(&snapshot).is_ok());
        assert_eq!(exporter.total_metrics(), 3);

        let snapshots = exporter.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].counters.len(), 1);
        assert_eq!(snapshots[0].gauges.len(), 1);
        assert_eq!(snapshots[0].histograms.len(), 1);

        exporter.clear();
        assert_eq!(exporter.total_metrics(), 0);
    }

    #[test]
    fn multi_exporter_fans_out() {
        // Create a wrapper to use with MultiExporter
        struct ArcExporter(Arc<InMemoryExporter>);
        impl MetricsExporter for ArcExporter {
            fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
                self.0.export(metrics)
            }
            fn flush(&self) -> Result<(), ExportError> {
                self.0.flush()
            }
        }

        let exp1 = InMemoryExporter::new();
        let exp2 = InMemoryExporter::new();

        // Need to use Arc to share between multi-exporter and tests
        let exp1_arc = Arc::new(exp1);
        let exp2_arc = Arc::new(exp2);

        let mut multi = MultiExporter::new(vec![]);
        multi.add(Box::new(ArcExporter(Arc::clone(&exp1_arc))));
        multi.add(Box::new(ArcExporter(Arc::clone(&exp2_arc))));
        assert_eq!(multi.len(), 2);

        let mut snapshot = MetricsSnapshot::new();
        snapshot.add_counter("test", vec![], 1);

        assert!(multi.export(&snapshot).is_ok());
        assert!(multi.flush().is_ok());

        // Both exporters should have received the snapshot
        assert_eq!(exp1_arc.total_metrics(), 1);
        assert_eq!(exp2_arc.total_metrics(), 1);
    }

    #[test]
    fn metrics_snapshot_building() {
        let mut snapshot = MetricsSnapshot::new();

        snapshot.add_counter(
            "requests",
            vec![("method".to_string(), "GET".to_string())],
            100,
        );
        snapshot.add_gauge("connections", vec![], 42);
        snapshot.add_histogram("latency", vec![], 1000, 125.5);

        assert_eq!(snapshot.counters.len(), 1);
        assert_eq!(snapshot.gauges.len(), 1);
        assert_eq!(snapshot.histograms.len(), 1);

        let (name, labels, value) = &snapshot.counters[0];
        assert_eq!(name, "requests");
        assert_eq!(labels.len(), 1);
        assert_eq!(*value, 100);
    }

    #[test]
    fn export_error_display() {
        let err = ExportError::new("test error");
        assert!(err.to_string().contains("test error"));
    }

    // Pure data-type tests (wave 38 – CyanBarn)

    #[test]
    fn cardinality_overflow_debug_clone_copy_eq_default() {
        let overflow = CardinalityOverflow::default();
        assert_eq!(overflow, CardinalityOverflow::Drop);
        let dbg = format!("{overflow:?}");
        assert!(dbg.contains("Drop"));

        let aggregate = CardinalityOverflow::Aggregate;
        let cloned = aggregate;
        assert_eq!(cloned, CardinalityOverflow::Aggregate);
        assert_ne!(aggregate, CardinalityOverflow::Warn);

        let warn = CardinalityOverflow::Warn;
        let copied = warn;
        assert_eq!(copied, warn);
    }

    #[test]
    fn metrics_config_debug_clone_default() {
        let config = MetricsConfig::default();
        assert_eq!(config.max_cardinality, 1000);
        assert_eq!(config.overflow_strategy, CardinalityOverflow::Drop);
        assert!(config.drop_labels.is_empty());
        assert!(config.sampling.is_none());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("MetricsConfig"));

        let cloned = config;
        assert_eq!(cloned.max_cardinality, 1000);
    }

    #[test]
    fn sampling_config_debug_clone_default() {
        let config = SamplingConfig::default();
        assert!((config.sample_rate - 1.0).abs() < f64::EPSILON);
        assert!(config.sampled_metrics.is_empty());

        let dbg = format!("{config:?}");
        assert!(dbg.contains("SamplingConfig"));

        let cloned = config;
        assert!((cloned.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn metrics_snapshot_debug_clone_default() {
        let snapshot = MetricsSnapshot::default();
        assert!(snapshot.counters.is_empty());
        assert!(snapshot.gauges.is_empty());
        assert!(snapshot.histograms.is_empty());

        let dbg = format!("{snapshot:?}");
        assert!(dbg.contains("MetricsSnapshot"));

        let mut s = MetricsSnapshot::new();
        s.add_counter("c", vec![], 1);
        let cloned = s.clone();
        assert_eq!(cloned.counters.len(), 1);
    }

    #[test]
    fn export_error_debug_clone() {
        let err = ExportError::new("something failed");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ExportError"));

        let cloned = err.clone();
        assert_eq!(cloned.to_string(), err.to_string());
    }

    #[test]
    fn stdout_exporter_debug_default() {
        let exporter = StdoutExporter::default();
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("StdoutExporter"));

        let with_prefix = StdoutExporter::with_prefix("[test] ");
        let dbg2 = format!("{with_prefix:?}");
        assert!(dbg2.contains("StdoutExporter"));
    }

    #[test]
    fn null_exporter_debug_default() {
        let exporter = NullExporter;
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("NullExporter"));
    }

    #[test]
    fn multi_exporter_debug_default() {
        let exporter = MultiExporter::default();
        assert!(exporter.is_empty());
        assert_eq!(exporter.len(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("MultiExporter"));
    }

    #[test]
    fn in_memory_exporter_debug_default() {
        let exporter = InMemoryExporter::default();
        assert_eq!(exporter.total_metrics(), 0);
        let dbg = format!("{exporter:?}");
        assert!(dbg.contains("InMemoryExporter"));
    }
}

// =============================================================================
// OpenTelemetry Span Semantics Conformance
// =============================================================================

#[cfg(feature = "tracing-integration")]
pub mod span_semantics {
    //! OpenTelemetry span semantics conformance tests.
    //!
    //! This module provides comprehensive conformance testing for OpenTelemetry
    //! span semantics according to the OpenTelemetry specification. It verifies
    //! span lifecycle, hierarchy, attributes, events, status, and context propagation.
    //!
    //! # Conformance Areas
    //!
    //! 1. **Span Lifecycle**: Start, end, finish, duration calculation
    //! 2. **Span Hierarchy**: Parent-child relationships, context propagation
    //! 3. **Span Attributes**: Setting, updating, limits, validation
    //! 4. **Span Events**: Recording events with timestamps and attributes
    //! 5. **Span Status**: Status codes, descriptions, error indication
    //! 6. **Span Sampling**: Sampled vs non-sampled behavior
    //! 7. **Span Context**: TraceID, SpanID, trace flags, state propagation
    //! 8. **Resource Association**: Service resource attachment
    //!
    //! # Example
    //!
    //! ```ignore
    //! use asupersync::observability::otel::span_semantics::run_span_conformance_tests;
    //!
    //! // Run all span semantic conformance tests
    //! run_span_conformance_tests().expect("All span semantic tests should pass");
    //! ```

    use opentelemetry::trace::{
        SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_TEST_SPAN_SEED: AtomicU64 = AtomicU64::new(1);
    static NEXT_TEST_TIME_TICK: AtomicU64 = AtomicU64::new(1);

    fn next_test_trace_id() -> TraceId {
        let seed = NEXT_TEST_SPAN_SEED.fetch_add(1, Ordering::Relaxed);
        let hi = splitmix64(seed);
        let lo = splitmix64(seed ^ 0x9e37_79b9_7f4a_7c15);
        let trace_id = TraceId::from_bytes([
            (hi >> 56) as u8,
            (hi >> 48) as u8,
            (hi >> 40) as u8,
            (hi >> 32) as u8,
            (hi >> 24) as u8,
            (hi >> 16) as u8,
            (hi >> 8) as u8,
            hi as u8,
            (lo >> 56) as u8,
            (lo >> 48) as u8,
            (lo >> 40) as u8,
            (lo >> 32) as u8,
            (lo >> 24) as u8,
            (lo >> 16) as u8,
            (lo >> 8) as u8,
            lo as u8,
        ]);
        if trace_id == TraceId::INVALID {
            TraceId::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            trace_id
        }
    }

    fn next_test_span_id() -> SpanId {
        let seed = NEXT_TEST_SPAN_SEED.fetch_add(1, Ordering::Relaxed);
        let raw = splitmix64(seed ^ 0xa5a5_a5a5_a5a5_a5a5);
        let span_id = SpanId::from_bytes([
            (raw >> 56) as u8,
            (raw >> 48) as u8,
            (raw >> 40) as u8,
            (raw >> 32) as u8,
            (raw >> 24) as u8,
            (raw >> 16) as u8,
            (raw >> 8) as u8,
            raw as u8,
        ]);
        if span_id == SpanId::INVALID {
            SpanId::from_bytes([0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            span_id
        }
    }

    fn splitmix64(mut state: u64) -> u64 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_test_time() -> SystemTime {
        let tick = NEXT_TEST_TIME_TICK.fetch_add(1, Ordering::Relaxed);
        UNIX_EPOCH + Duration::from_nanos(tick)
    }

    fn truncate_value(value: &str, max_len: Option<usize>) -> String {
        match max_len {
            Some(limit) => value.chars().take(limit).collect(),
            None => value.to_string(),
        }
    }

    /// Configuration for span semantics conformance testing.
    #[derive(Debug, Clone)]
    pub struct SpanConformanceConfig {
        /// Maximum number of attributes per span (default: 128 per OTel spec).
        pub max_attributes: usize,
        /// Maximum number of events per span (default: 128 per OTel spec).
        pub max_events: usize,
        /// Maximum attribute value length (default: none per OTel spec).
        pub max_attribute_length: Option<usize>,
        /// Whether to test sampling behavior.
        pub test_sampling: bool,
        /// Whether to test context propagation.
        pub test_context_propagation: bool,
    }

    impl Default for SpanConformanceConfig {
        fn default() -> Self {
            Self {
                max_attributes: 128,
                max_events: 128,
                max_attribute_length: None,
                test_sampling: true,
                test_context_propagation: true,
            }
        }
    }

    /// Result of span semantic conformance testing.
    #[derive(Debug)]
    pub struct SpanConformanceResult {
        /// Total number of tests run.
        pub tests_run: usize,
        /// Number of tests passed.
        pub tests_passed: usize,
        /// Number of tests failed.
        pub tests_failed: usize,
        /// Detailed failure messages.
        pub failures: Vec<String>,
    }

    impl SpanConformanceResult {
        /// Create new empty result.
        pub fn new() -> Self {
            Self {
                tests_run: 0,
                tests_passed: 0,
                tests_failed: 0,
                failures: Vec::new(),
            }
        }

        /// Record a test pass.
        pub fn record_pass(&mut self, _test_name: &str) {
            self.tests_run += 1;
            self.tests_passed += 1;
        }

        /// Record a test failure.
        pub fn record_failure(&mut self, test_name: &str, reason: &str) {
            self.tests_run += 1;
            self.tests_failed += 1;
            self.failures.push(format!("{}: {}", test_name, reason));
        }

        /// Check if all tests passed.
        pub fn is_success(&self) -> bool {
            self.tests_failed == 0
        }

        /// Get success rate as percentage.
        pub fn success_rate(&self) -> f64 {
            if self.tests_run == 0 {
                0.0
            } else {
                (self.tests_passed as f64 / self.tests_run as f64) * 100.0
            }
        }
    }

    /// Test span for conformance verification.
    #[derive(Debug)]
    pub struct TestSpan {
        /// Span context (trace ID, span ID, flags).
        pub context: SpanContext,
        /// Span name.
        pub name: String,
        /// Span kind.
        pub kind: SpanKind,
        /// Start time.
        pub start_time: SystemTime,
        /// End time (if ended).
        pub end_time: Option<SystemTime>,
        /// Span attributes.
        pub attributes: HashMap<String, String>,
        /// Span events.
        pub events: Vec<SpanEvent>,
        /// Span status.
        pub status: Status,
        /// Parent span context.
        pub parent_context: Option<SpanContext>,
        /// Propagated baggage entries.
        pub baggage: HashMap<String, String>,
        max_attributes: usize,
        max_events: usize,
        max_attribute_length: Option<usize>,
    }

    /// Span event for conformance testing.
    #[derive(Debug, Clone)]
    pub struct SpanEvent {
        /// Event name.
        pub name: String,
        /// Event timestamp.
        pub timestamp: SystemTime,
        /// Event attributes.
        pub attributes: HashMap<String, String>,
    }

    impl TestSpan {
        /// Create a new test span.
        pub fn new(name: &str, kind: SpanKind) -> Self {
            Self::new_with_config(name, kind, &SpanConformanceConfig::default())
        }

        /// Create a new root test span with explicit limits.
        pub fn new_with_config(name: &str, kind: SpanKind, config: &SpanConformanceConfig) -> Self {
            let context = SpanContext::new(
                next_test_trace_id(),
                next_test_span_id(),
                TraceFlags::SAMPLED,
                false,
                TraceState::default(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                None,
                HashMap::new(),
                config.max_attributes,
                config.max_events,
                config.max_attribute_length,
            )
        }

        /// Create a child span.
        pub fn new_child(&self, name: &str, kind: SpanKind) -> Self {
            let parent_context = self.context.clone();
            let context = SpanContext::new(
                parent_context.trace_id(),
                next_test_span_id(),
                parent_context.trace_flags(),
                false,
                parent_context.trace_state().clone(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                Some(parent_context),
                self.baggage.clone(),
                self.max_attributes,
                self.max_events,
                self.max_attribute_length,
            )
        }

        /// Create a child span from an extracted remote parent.
        pub fn child_from_remote_parent(
            parent_context: SpanContext,
            baggage: HashMap<String, String>,
            name: &str,
            kind: SpanKind,
            config: &SpanConformanceConfig,
        ) -> Self {
            let context = SpanContext::new(
                parent_context.trace_id(),
                next_test_span_id(),
                parent_context.trace_flags(),
                false,
                parent_context.trace_state().clone(),
            );
            Self::from_parts(
                name,
                kind,
                context,
                Some(parent_context),
                baggage,
                config.max_attributes,
                config.max_events,
                config.max_attribute_length,
            )
        }

        fn from_parts(
            name: &str,
            kind: SpanKind,
            context: SpanContext,
            parent_context: Option<SpanContext>,
            baggage: HashMap<String, String>,
            max_attributes: usize,
            max_events: usize,
            max_attribute_length: Option<usize>,
        ) -> Self {
            Self {
                context,
                name: name.to_string(),
                kind,
                start_time: next_test_time(),
                end_time: None,
                attributes: HashMap::new(),
                events: Vec::new(),
                status: Status::Unset,
                parent_context,
                baggage,
                max_attributes,
                max_events,
                max_attribute_length,
            }
        }

        /// Set span attribute.
        pub fn set_attribute(&mut self, key: &str, value: &str) {
            let value = truncate_value(value, self.max_attribute_length);
            if self.attributes.contains_key(key) || self.attributes.len() < self.max_attributes {
                self.attributes.insert(key.to_string(), value);
            }
        }

        /// Set a propagated baggage entry.
        pub fn set_baggage_item(&mut self, key: &str, value: &str) {
            self.baggage.insert(key.to_string(), value.to_string());
        }

        /// Add span event.
        pub fn add_event(&mut self, name: &str, mut attributes: HashMap<String, String>) {
            if self.events.len() >= self.max_events {
                return;
            }
            for value in attributes.values_mut() {
                *value = truncate_value(value, self.max_attribute_length);
            }
            let event = SpanEvent {
                name: name.to_string(),
                timestamp: next_test_time(),
                attributes,
            };
            self.events.push(event);
        }

        /// Set span status.
        pub fn set_status(&mut self, status: Status) {
            match status {
                Status::Error { .. } => self.status = status,
                Status::Ok => {
                    if !matches!(self.status, Status::Error { .. }) {
                        self.status = Status::Ok;
                    }
                }
                Status::Unset => {
                    if matches!(self.status, Status::Unset) {
                        self.status = Status::Unset;
                    }
                }
            }
        }

        /// End the span.
        pub fn end(&mut self) {
            if self.end_time.is_none() {
                self.end_time = Some(next_test_time());
            }
        }

        /// Get span duration.
        pub fn duration(&self) -> Option<Duration> {
            if let Some(end_time) = self.end_time {
                end_time.duration_since(self.start_time).ok()
            } else {
                None
            }
        }

        /// Check if span is ended.
        pub fn is_ended(&self) -> bool {
            self.end_time.is_some()
        }
    }

    /// Run comprehensive span semantics conformance tests.
    pub fn run_span_conformance_tests() -> Result<SpanConformanceResult, Box<dyn std::error::Error>>
    {
        let config = SpanConformanceConfig::default();
        run_span_conformance_tests_with_config(&config)
    }

    /// Run span semantics conformance tests with custom configuration.
    pub fn run_span_conformance_tests_with_config(
        config: &SpanConformanceConfig,
    ) -> Result<SpanConformanceResult, Box<dyn std::error::Error>> {
        let mut result = SpanConformanceResult::new();

        // Test 1: Span Lifecycle Semantics
        test_span_lifecycle(&mut result, config);

        // Test 2: Span Hierarchy and Context Propagation
        test_span_hierarchy(&mut result, config);

        // Test 3: Span Attributes
        test_span_attributes(&mut result, config);

        // Test 4: Span Events
        test_span_events(&mut result, config);

        // Test 5: Span Status
        test_span_status(&mut result, config);

        // Test 6: Span Context and IDs
        test_span_context(&mut result, config);

        // Test 7: Span Sampling (if enabled)
        if config.test_sampling {
            test_span_sampling(&mut result, config);
        }

        // Test 8: Context Propagation (if enabled)
        if config.test_context_propagation {
            test_context_propagation(&mut result, config);
        }

        Ok(result)
    }

    /// Test span lifecycle semantics.
    fn test_span_lifecycle(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 1.1: Basic span start/end
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            let start_time = span.start_time;

            // Span should not be ended initially
            if span.is_ended() {
                result.record_failure("span_lifecycle_start", "New span should not be ended");
                return;
            }

            span.end();

            // Span should be ended after calling end()
            if !span.is_ended() {
                result.record_failure(
                    "span_lifecycle_end",
                    "Span should be ended after end() call",
                );
                return;
            }

            // End time should be after start time
            if let Some(duration) = span.duration() {
                if duration.is_zero() && span.end_time.unwrap() < start_time {
                    result.record_failure(
                        "span_lifecycle_duration",
                        "End time should be >= start time",
                    );
                    return;
                }
            } else {
                result.record_failure(
                    "span_lifecycle_duration",
                    "Ended span should have calculable duration",
                );
                return;
            }

            result.record_pass("span_lifecycle_basic");
        }

        // Test 1.2: Multiple end() calls should be idempotent
        {
            let mut span = TestSpan::new("test_span_double_end", SpanKind::Internal);
            span.end();
            let first_end_time = span.end_time;

            // Second end() call should not change end time
            std::thread::sleep(Duration::from_millis(1));
            span.end();

            if span.end_time != first_end_time {
                result.record_failure(
                    "span_lifecycle_idempotent",
                    "Multiple end() calls should be idempotent",
                );
                return;
            }

            result.record_pass("span_lifecycle_idempotent");
        }
    }

    /// Test span hierarchy and parent-child relationships.
    fn test_span_hierarchy(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 2.1: Parent-child relationship
        {
            let parent = TestSpan::new("parent_span", SpanKind::Internal);
            let child = parent.new_child("child_span", SpanKind::Internal);

            // Child should have same trace ID as parent
            if child.context.trace_id() != parent.context.trace_id() {
                result.record_failure(
                    "span_hierarchy_trace_id",
                    "Child span should have same trace ID as parent",
                );
                return;
            }

            // Child should have different span ID from parent
            if child.context.span_id() == parent.context.span_id() {
                result.record_failure(
                    "span_hierarchy_span_id",
                    "Child span should have different span ID from parent",
                );
                return;
            }

            // Child should reference parent context
            if child.parent_context.is_none() {
                result.record_failure(
                    "span_hierarchy_parent_context",
                    "Child span should have parent context",
                );
                return;
            }

            if child.parent_context.unwrap() != parent.context {
                result.record_failure(
                    "span_hierarchy_parent_reference",
                    "Child span should reference correct parent context",
                );
                return;
            }

            result.record_pass("span_hierarchy_basic");
        }

        // Test 2.2: Multi-level hierarchy
        {
            let grandparent = TestSpan::new("grandparent", SpanKind::Internal);
            let parent = grandparent.new_child("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            // All spans should share same trace ID
            if child.context.trace_id() != grandparent.context.trace_id()
                || parent.context.trace_id() != grandparent.context.trace_id()
            {
                result.record_failure(
                    "span_hierarchy_multi_level",
                    "All spans in hierarchy should share trace ID",
                );
                return;
            }

            result.record_pass("span_hierarchy_multi_level");
        }
    }

    /// Test span attributes.
    fn test_span_attributes(result: &mut SpanConformanceResult, config: &SpanConformanceConfig) {
        // Test 3.1: Basic attribute setting
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            span.set_attribute("service.name", "test-service");
            span.set_attribute("http.method", "GET");

            if span.attributes.len() != 2 {
                result.record_failure("span_attributes_basic", "Span should have 2 attributes");
                return;
            }

            if span.attributes.get("service.name") != Some(&"test-service".to_string()) {
                result.record_failure("span_attributes_basic", "Attribute value should match");
                return;
            }

            result.record_pass("span_attributes_basic");
        }

        // Test 3.2: Attribute overwrite
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            span.set_attribute("test.key", "original_value");
            span.set_attribute("test.key", "new_value");

            if span.attributes.get("test.key") != Some(&"new_value".to_string()) {
                result.record_failure(
                    "span_attributes_overwrite",
                    "Attribute should be overwritten",
                );
                return;
            }

            result.record_pass("span_attributes_overwrite");
        }

        // Test 3.3: Attribute limits (if configured)
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            // Add more than max_attributes to test limit
            for i in 0..config.max_attributes + 10 {
                span.set_attribute(&format!("attr_{}", i), "value");
            }

            if span.attributes.len() != config.max_attributes {
                result.record_failure(
                    "span_attributes_limits",
                    "Attribute count should respect max_attributes",
                );
                return;
            }

            result.record_pass("span_attributes_limits");
        }

        if let Some(limit) = config.max_attribute_length {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            let oversized = "x".repeat(limit + 5);
            span.set_attribute("oversized", &oversized);

            if span.attributes.get("oversized").map(String::len) != Some(limit) {
                result.record_failure(
                    "span_attributes_value_length",
                    "Attribute values should respect max_attribute_length",
                );
                return;
            }

            result.record_pass("span_attributes_value_length");
        }
    }

    /// Test span events.
    fn test_span_events(result: &mut SpanConformanceResult, config: &SpanConformanceConfig) {
        // Test 4.1: Basic event recording
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);
            let mut event_attrs = HashMap::new();
            event_attrs.insert("event.severity".to_string(), "info".to_string());

            span.add_event("test_event", event_attrs);

            if span.events.len() != 1 {
                result.record_failure("span_events_basic", "Span should have 1 event");
                return;
            }

            let event = &span.events[0];
            if event.name != "test_event" {
                result.record_failure("span_events_basic", "Event name should match");
                return;
            }

            result.record_pass("span_events_basic");
        }

        // Test 4.2: Multiple events with ordering
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            span.add_event("first_event", HashMap::new());
            std::thread::sleep(Duration::from_millis(1));
            span.add_event("second_event", HashMap::new());

            if span.events.len() != 2 {
                result.record_failure("span_events_multiple", "Span should have 2 events");
                return;
            }

            // Events should be in chronological order
            if span.events[0].timestamp > span.events[1].timestamp {
                result.record_failure(
                    "span_events_ordering",
                    "Events should be in chronological order",
                );
                return;
            }

            result.record_pass("span_events_multiple");
        }

        // Test 4.3: Event limits (if configured)
        {
            let mut span = TestSpan::new_with_config("test_span", SpanKind::Internal, config);

            // Add more than max_events to test limit
            for i in 0..config.max_events + 10 {
                span.add_event(&format!("event_{}", i), HashMap::new());
            }

            if span.events.len() != config.max_events {
                result.record_failure(
                    "span_events_limits",
                    "Event count should respect max_events",
                );
                return;
            }

            result.record_pass("span_events_limits");
        }
    }

    /// Test span status semantics.
    fn test_span_status(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 5.1: Default status
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);

            if !matches!(span.status, Status::Unset) {
                result.record_failure("span_status_default", "Default span status should be Unset");
                return;
            }

            result.record_pass("span_status_default");
        }

        // Test 5.2: Setting status
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            span.set_status(Status::Error {
                description: "Something went wrong".into(),
            });

            if let Status::Error { description } = &span.status {
                if description != "Something went wrong" {
                    result.record_failure("span_status_set", "Status description should match");
                    return;
                }
            } else {
                result.record_failure("span_status_set", "Status should be Error");
                return;
            }

            result.record_pass("span_status_set");
        }

        // Test 5.3: Status precedence (Error takes precedence over Ok)
        {
            let mut span = TestSpan::new("test_span", SpanKind::Internal);
            span.set_status(Status::Ok);
            span.set_status(Status::Error {
                description: "Error occurred".into(),
            });

            if !matches!(span.status, Status::Error { .. }) {
                result.record_failure(
                    "span_status_precedence",
                    "Error status should take precedence",
                );
                return;
            }

            result.record_pass("span_status_precedence");
        }
    }

    /// Test span context and ID semantics.
    fn test_span_context(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 6.1: Unique span IDs
        {
            let span1 = TestSpan::new("span1", SpanKind::Internal);
            let span2 = TestSpan::new("span2", SpanKind::Internal);

            if span1.context.span_id() == span2.context.span_id() {
                result.record_failure(
                    "span_context_unique_ids",
                    "Different spans should have different span IDs",
                );
                return;
            }

            result.record_pass("span_context_unique_ids");
        }

        // Test 6.2: Trace ID format
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);
            let trace_id = span.context.trace_id();

            // Trace ID should not be zero (invalid)
            if trace_id == TraceId::INVALID {
                result.record_failure(
                    "span_context_trace_id",
                    "Trace ID should not be invalid/zero",
                );
                return;
            }

            result.record_pass("span_context_trace_id");
        }

        // Test 6.3: Span ID format
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);
            let span_id = span.context.span_id();

            // Span ID should not be zero (invalid)
            if span_id == SpanId::INVALID {
                result.record_failure("span_context_span_id", "Span ID should not be invalid/zero");
                return;
            }

            result.record_pass("span_context_span_id");
        }
    }

    /// Test span sampling behavior.
    fn test_span_sampling(result: &mut SpanConformanceResult, _config: &SpanConformanceConfig) {
        // Test 7.1: Sampled flag consistency
        {
            let span = TestSpan::new("test_span", SpanKind::Internal);

            // In our test implementation, spans are always sampled
            if !span.context.trace_flags().is_sampled() {
                result.record_failure("span_sampling_flag", "Test spans should be sampled");
                return;
            }

            result.record_pass("span_sampling_basic");
        }

        // Test 7.2: Sampling inheritance
        {
            let parent = TestSpan::new("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            // Child should inherit sampling decision from parent
            if parent.context.trace_flags().is_sampled() != child.context.trace_flags().is_sampled()
            {
                result.record_failure(
                    "span_sampling_inheritance",
                    "Child should inherit parent sampling decision",
                );
                return;
            }

            result.record_pass("span_sampling_inheritance");
        }
    }

    /// Test context propagation semantics.
    fn test_context_propagation(
        result: &mut SpanConformanceResult,
        config: &SpanConformanceConfig,
    ) {
        // Test 8.1: Context propagation across service boundaries
        {
            // Simulate extracting context from incoming request
            let trace_id = TraceId::from_bytes([
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                0xcd, 0xef,
            ]);
            let span_id = SpanId::from_bytes([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
            let trace_state =
                TraceState::from_key_value([("vendor", "upstream")]).expect("valid trace state");
            let incoming_context = SpanContext::new(
                trace_id,
                span_id,
                TraceFlags::SAMPLED,
                true,
                trace_state.clone(),
            );

            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());
            let child = TestSpan::child_from_remote_parent(
                incoming_context.clone(),
                baggage,
                "remote_child",
                SpanKind::Server,
                config,
            );

            if child.context.trace_id() != incoming_context.trace_id() {
                result.record_failure(
                    "context_propagation_trace_id",
                    "Trace ID should be preserved across boundaries",
                );
                return;
            }

            if child.context.trace_flags() != incoming_context.trace_flags() {
                result.record_failure(
                    "context_propagation_flags",
                    "Trace flags should be preserved",
                );
                return;
            }

            if !incoming_context.is_remote() || child.context.is_remote() {
                result.record_failure(
                    "context_propagation_remote_flag",
                    "Incoming context should stay remote while child becomes local",
                );
                return;
            }

            result.record_pass("context_propagation_basic");
        }

        // Test 8.2: TraceState propagation
        {
            let trace_state =
                TraceState::from_key_value([("vendor", "upstream")]).expect("valid trace state");
            let incoming_context = SpanContext::new(
                TraceId::from_bytes([
                    0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd,
                    0xdd, 0xdd, 0xdd,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                trace_state,
            );
            let child = TestSpan::child_from_remote_parent(
                incoming_context,
                HashMap::new(),
                "remote_child",
                SpanKind::Consumer,
                config,
            );

            if child.context.trace_state().get("vendor") != Some("upstream") {
                result.record_failure(
                    "context_propagation_state",
                    "TraceState should propagate to child spans",
                );
                return;
            }

            result.record_pass("context_propagation_state");
        }

        // Test 8.3: Baggage propagation
        {
            let incoming_context = SpanContext::new(
                TraceId::from_bytes([
                    0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0x11, 0x11, 0x11, 0x11, 0x22,
                    0x22, 0x22, 0x22,
                ]),
                SpanId::from_bytes([0x22; 8]),
                TraceFlags::SAMPLED,
                true,
                TraceState::default(),
            );
            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());
            baggage.insert("request.class".to_string(), "gold".to_string());
            let child = TestSpan::child_from_remote_parent(
                incoming_context,
                baggage,
                "remote_child",
                SpanKind::Server,
                config,
            );

            if child.baggage.get("tenant").map(String::as_str) != Some("alpha")
                || child.baggage.get("request.class").map(String::as_str) != Some("gold")
            {
                result.record_failure(
                    "context_propagation_baggage",
                    "Baggage should propagate across service boundaries",
                );
                return;
            }

            result.record_pass("context_propagation_baggage");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_span_conformance_config_default() {
            let config = SpanConformanceConfig::default();
            assert_eq!(config.max_attributes, 128);
            assert_eq!(config.max_events, 128);
            assert!(config.test_sampling);
            assert!(config.test_context_propagation);
        }

        #[test]
        fn test_span_conformance_result() {
            let mut result = SpanConformanceResult::new();
            assert_eq!(result.tests_run, 0);
            assert!(result.is_success()); // No tests run is considered success

            result.record_pass("test1");
            assert_eq!(result.tests_run, 1);
            assert_eq!(result.tests_passed, 1);
            assert!(result.is_success());

            result.record_failure("test2", "failed");
            assert_eq!(result.tests_run, 2);
            assert_eq!(result.tests_failed, 1);
            assert!(!result.is_success());
            assert_eq!(result.success_rate(), 50.0);
        }

        #[test]
        fn test_span_basic_operations() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            assert!(!span.is_ended());
            assert!(span.duration().is_none());

            span.set_attribute("key", "value");
            assert_eq!(span.attributes.get("key"), Some(&"value".to_string()));

            span.add_event("event", HashMap::new());
            assert_eq!(span.events.len(), 1);

            span.end();
            assert!(span.is_ended());
            assert!(span.duration().is_some());
        }

        #[test]
        fn test_span_end_is_idempotent() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            span.end();
            let first_end_time = span.end_time;
            span.end();
            assert_eq!(span.end_time, first_end_time);
        }

        #[test]
        fn test_span_hierarchy() {
            let parent = TestSpan::new("parent", SpanKind::Internal);
            let child = parent.new_child("child", SpanKind::Internal);

            assert_eq!(child.context.trace_id(), parent.context.trace_id());
            assert_ne!(child.context.span_id(), parent.context.span_id());
            assert!(child.parent_context.is_some());
            assert_eq!(child.parent_context.unwrap(), parent.context);
        }

        #[test]
        fn test_span_remote_parent_propagates_trace_state_and_baggage() {
            let config = SpanConformanceConfig {
                max_attributes: 8,
                max_events: 8,
                max_attribute_length: Some(8),
                test_sampling: true,
                test_context_propagation: true,
            };
            let trace_state =
                TraceState::from_key_value([("vendor", "edge")]).expect("valid trace state");
            let remote_parent = SpanContext::new(
                TraceId::from_bytes([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
                    0x16, 0x17, 0x18,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                trace_state,
            );
            let mut baggage = HashMap::new();
            baggage.insert("tenant".to_string(), "alpha".to_string());

            let child = TestSpan::child_from_remote_parent(
                remote_parent,
                baggage,
                "child",
                SpanKind::Server,
                &config,
            );

            assert_eq!(child.context.trace_state().get("vendor"), Some("edge"));
            assert_eq!(
                child.baggage.get("tenant").map(String::as_str),
                Some("alpha")
            );
            assert!(!child.context.is_remote());
            assert!(child.parent_context.expect("parent").is_remote());
        }

        #[test]
        fn test_span_attribute_and_event_limits_are_enforced() {
            let config = SpanConformanceConfig {
                max_attributes: 2,
                max_events: 1,
                max_attribute_length: Some(4),
                test_sampling: true,
                test_context_propagation: true,
            };
            let mut span = TestSpan::new_with_config("test", SpanKind::Internal, &config);

            span.set_attribute("k1", "value");
            span.set_attribute("k2", "value");
            span.set_attribute("k3", "value");
            assert_eq!(span.attributes.len(), 2);
            assert_eq!(span.attributes.get("k1").map(String::as_str), Some("valu"));

            span.add_event("one", HashMap::new());
            span.add_event("two", HashMap::new());
            assert_eq!(span.events.len(), 1);
        }

        #[test]
        fn test_span_timestamps_are_monotonic() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let start_time = span.start_time;

            span.add_event("first", HashMap::new());
            span.add_event("second", HashMap::new());
            span.end();

            let first_event = &span.events[0];
            let second_event = &span.events[1];
            let end_time = span.end_time.expect("span end time");

            assert!(first_event.timestamp >= start_time);
            assert!(second_event.timestamp >= first_event.timestamp);
            assert!(end_time >= second_event.timestamp);
            assert!(span.duration().is_some());
        }

        #[test]
        fn run_basic_conformance_tests() {
            // Test the actual conformance runner
            let config = SpanConformanceConfig::default();
            let result = run_span_conformance_tests_with_config(&config)
                .expect("Conformance tests should run");

            assert!(result.tests_run > 0);
            assert!(
                result.is_success(),
                "span conformance failures: {:?}",
                result.failures
            );
        }
    }
}

#[cfg(not(feature = "tracing-integration"))]
pub mod span_semantics {
    //! Span semantics module (disabled when tracing-integration feature is not enabled).
    //!
    //! Enable the `tracing-integration` feature to access OpenTelemetry span semantics
    //! conformance testing functionality.

    /// Placeholder result when tracing is disabled.
    #[derive(Debug)]
    pub struct SpanConformanceResult {
        /// Total number of tests executed.
        pub tests_run: usize,
        /// Number of tests that passed.
        pub tests_passed: usize,
        /// Number of tests that failed.
        pub tests_failed: usize,
        /// Failure descriptions captured during the run.
        pub failures: Vec<String>,
    }

    impl SpanConformanceResult {
        /// Returns `true` when no failures were recorded.
        pub fn is_success(&self) -> bool {
            self.tests_failed == 0
        }

        /// Returns a placeholder success rate for the disabled implementation.
        pub fn success_rate(&self) -> f64 {
            0.0
        }
    }

    /// Placeholder function when tracing is disabled.
    pub fn run_span_conformance_tests() -> Result<SpanConformanceResult, Box<dyn std::error::Error>>
    {
        Err("OpenTelemetry span semantics testing requires 'tracing-integration' feature".into())
    }
}
