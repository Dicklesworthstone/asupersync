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
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge};
use opentelemetry::KeyValue;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
        let seen = self.seen.read().unwrap();

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
        let mut seen = self.seen.write().unwrap();
        seen.entry(metric.to_string())
            .or_default()
            .insert(hash);
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
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        for kv in labels {
            kv.key.as_str().hash(&mut hasher);
            format!("{:?}", kv.value).hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get current cardinality for a metric.
    #[cfg(test)]
    fn cardinality(&self, metric: &str) -> usize {
        self.seen
            .read()
            .unwrap()
            .get(metric)
            .map_or(0, |s| s.len())
    }
}

// =============================================================================
// Custom Exporters
// =============================================================================

/// Snapshot of metrics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    /// Counter values: (name, labels, value).
    pub counters: Vec<(String, Vec<(String, String)>, u64)>,
    /// Gauge values: (name, labels, value).
    pub gauges: Vec<(String, Vec<(String, String)>, i64)>,
    /// Histogram values: (name, labels, count, sum).
    pub histograms: Vec<(String, Vec<(String, String)>, u64, f64)>,
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
            let parts: Vec<_> = labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

impl MetricsExporter for StdoutExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        let mut stdout = std::io::stdout().lock();

        for (name, labels, value) in &metrics.counters {
            let label_str = Self::format_labels(labels);
            writeln!(stdout, "{}COUNTER {}{} {}", self.prefix, name, label_str, value)
                .map_err(|e| ExportError::new(e.to_string()))?;
        }

        for (name, labels, value) in &metrics.gauges {
            let label_str = Self::format_labels(labels);
            writeln!(stdout, "{}GAUGE {}{} {}", self.prefix, name, label_str, value)
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
        self.snapshots.lock().unwrap().clone()
    }

    /// Clear collected snapshots.
    pub fn clear(&self) {
        self.snapshots.lock().unwrap().clear();
    }

    /// Get total number of metrics recorded.
    #[must_use]
    pub fn total_metrics(&self) -> usize {
        let snapshots = self.snapshots.lock().unwrap();
        snapshots
            .iter()
            .map(|s| s.counters.len() + s.gauges.len() + s.histograms.len())
            .sum()
    }
}

impl MetricsExporter for InMemoryExporter {
    fn export(&self, metrics: &MetricsSnapshot) -> Result<(), ExportError> {
        self.snapshots.lock().unwrap().push(metrics.clone());
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
    tasks_active: ObservableGauge<u64>,
    tasks_spawned: Counter<u64>,
    tasks_completed: Counter<u64>,
    task_duration: Histogram<f64>,
    // Region metrics
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
    // Obligation metrics
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

        // Check cardinality
        if self
            .cardinality_tracker
            .would_exceed(metric, &filtered, self.config.max_cardinality)
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
                    self.cardinality_tracker.record(metric, &aggregated);
                    return Some(aggregated);
                }
                CardinalityOverflow::Warn => {
                    tracing::warn!(
                        metric = %metric,
                        "Cardinality limit reached for metric"
                    );
                }
            }
        }

        // Record this label combination
        self.cardinality_tracker.record(metric, &filtered);
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
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter as OtelInMemoryExporter, PeriodicReader, SdkMeterProvider,
    };

    #[test]
    fn otel_metrics_exports_in_memory() {
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
        metrics.obligation_created(RegionId::testing_default());
        metrics.obligation_discharged(RegionId::testing_default());
        metrics.obligation_leaked(RegionId::testing_default());
        metrics.scheduler_tick(3, Duration::from_millis(1));

        provider.force_flush().expect("force_flush");
        let finished = exporter.get_finished_metrics().expect("finished metrics");
        assert!(!finished.is_empty());

        provider.shutdown().expect("shutdown");
    }

    #[test]
    fn otel_metrics_with_config() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
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
    fn drop_labels_filtered() {
        let exporter = OtelInMemoryExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
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
        snapshot.add_gauge("test.gauge", vec![("label".to_string(), "value".to_string())], 100);
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
        let exp1 = InMemoryExporter::new();
        let exp2 = InMemoryExporter::new();

        // Need to use Arc to share between multi-exporter and tests
        let exp1_arc = Arc::new(exp1);
        let exp2_arc = Arc::new(exp2);

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

        snapshot.add_counter("requests", vec![("method".to_string(), "GET".to_string())], 100);
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
}
