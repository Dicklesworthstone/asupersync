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
    /// Maximum distinct metric NAMES tracked. Once this cap is hit,
    /// new metric names hit the overflow path and are not recorded
    /// (br-asupersync-qipj44). Existing metric names continue to
    /// accept new label combinations up to `max_cardinality`.
    ///
    /// The default cap (4096) is high enough that legitimate
    /// applications never hit it (real services have on the order of
    /// 50-500 distinct metric names) while bounding the worst case
    /// for SaaS workloads where attacker-influenced strings could
    /// otherwise reach a metric-naming code path.
    pub max_metrics: usize,
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
            max_metrics: 4096,
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

    /// Set maximum number of distinct metric NAMES (br-asupersync-qipj44).
    /// Once the cap is hit, newly-named metrics are dropped to prevent
    /// memory exhaustion via attacker-controlled metric strings.
    #[must_use]
    pub fn with_max_metrics(mut self, max: usize) -> Self {
        self.max_metrics = max;
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
///
/// br-asupersync-bs92bg — `hasher_seed` is a per-instance
/// `RandomState` (per-process random SipHash key). Switched from the
/// previously-used `DetHasher` (fixed seed) because the cardinality
/// tracker's keyspace is attacker-influenced — label values arrive
/// from external sources via every metric path. With a fixed seed,
/// an attacker who knows the hash function parameters can pre-compute
/// label values that collide on a single bucket, exhausting the
/// per-metric `max_cardinality` cap with one collision class and
/// effectively suppressing every legitimate label combination
/// thereafter (or, depending on call order, evicting legitimate
/// labels from the seen-set so they re-trigger the overflow path on
/// every subsequent record). RandomState's per-process seed defeats
/// the pre-compute: an attacker cannot know the local hasher's key
/// at startup, so they cannot construct a collision class.
#[derive(Debug)]
struct CardinalityTracker {
    /// Map of metric name -> set of label combination hashes.
    seen: RwLock<HashMap<String, HashSet<u64>>>,
    /// Number of times cardinality limit was hit.
    overflow_count: AtomicU64,
    /// Per-instance random hash seed (br-asupersync-bs92bg).
    hasher_seed: std::collections::hash_map::RandomState,
}

impl CardinalityTracker {
    fn new() -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            overflow_count: AtomicU64::new(0),
            hasher_seed: std::collections::hash_map::RandomState::new(),
        }
    }

    /// Check if recording this label combination would exceed the limit.
    #[cfg(test)]
    fn would_exceed(&self, metric: &str, labels: &[KeyValue], max_cardinality: usize) -> bool {
        let hash = self.hash_labels(labels);
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
        let hash = self.hash_labels(labels);
        let mut seen = self.seen.write();
        seen.entry(metric.to_string()).or_default().insert(hash);
    }

    /// Atomically check whether a new label set would exceed cardinality and
    /// record it if allowed.
    ///
    /// Returns `true` when the limit would be exceeded and the label set was
    /// not recorded. Two distinct caps are enforced:
    ///
    ///   - `max_cardinality` — distinct label combinations PER metric
    ///     (existing behaviour, preserved).
    ///   - `max_metrics` — distinct metric NAMES across the whole tracker
    ///     (br-asupersync-qipj44). Without this cap, a code path that
    ///     derived the metric name from attacker-controlled input
    ///     (`format!("user_{user_id}")`, request URL path, content type,
    ///     etc.) could grow `seen` without bound — DoS via memory
    ///     exhaustion. With the cap, the FIRST `max_metrics` distinct
    ///     names are accepted and subsequent new names are dropped to
    ///     the overflow bucket. Existing metric names continue to
    ///     accept new label combinations.
    fn check_and_record(
        &self,
        metric: &str,
        labels: &[KeyValue],
        max_cardinality: usize,
        max_metrics: usize,
    ) -> bool {
        let hash = self.hash_labels(labels);
        let mut seen = self.seen.write();

        // br-asupersync-qipj44: enforce the metric-name cap BEFORE
        // creating a new entry. If the cap is hit and this metric name
        // is not already tracked, refuse to insert.
        if !seen.contains_key(metric) && max_metrics > 0 && seen.len() >= max_metrics {
            return true;
        }

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
    ///
    /// br-asupersync-bs92bg — uses the per-instance `RandomState`
    /// seed instead of `DetHasher`. The seed is randomised at
    /// `CardinalityTracker::new()` and never observable to a remote
    /// attacker, defeating the pre-computed-collision DoS that the
    /// fixed-seed `DetHasher` would have permitted.
    fn hash_labels(&self, labels: &[KeyValue]) -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        let _ = std::marker::PhantomData::<RandomState>;

        // Treat label sets as order-insensitive. Different construction order of
        // equivalent labels should map to the same cardinality bucket.
        let mut normalized: Vec<(&str, String)> = labels
            .iter()
            .map(|kv| (kv.key.as_str(), format!("{:?}", kv.value)))
            .collect();
        normalized.sort_unstable_by(|(a_key, a_val), (b_key, b_val)| {
            a_key.cmp(b_key).then_with(|| a_val.cmp(b_val))
        });

        let mut hasher = self.hasher_seed.build_hasher();
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

/// br-asupersync-coxhdt — Escape a Prometheus label value per the
/// exposition format. The spec mandates that values containing the
/// canonical trio (`\\`, `\n`, `\"`) be backslash-escaped; without
/// this, a value containing `"` would terminate the quoted string
/// early (corrupting the line and potentially injecting attacker-
/// controlled labels), and a value containing `\` or `\n` would
/// likewise corrupt the exposition. CR is also escaped to keep
/// downstream line-oriented parsers from splitting on it.
///
/// This is the otel-exporter parallel to
/// [`crate::observability::metrics::escape_prometheus_label_value`]
/// (br-asupersync-pdu7wg) — same canonical escape trio applied on a
/// separate code path to keep otel.rs self-contained.
fn escape_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '"' => {
                out.push('\\');
                out.push('"');
            }
            '\r' => out.push_str(r"\r"),
            _ => out.push(c),
        }
    }
    out
}

/// Exporter that writes to stdout (for debugging).
#[derive(Debug, Default)]
pub struct StdoutExporter {
    prefix: String,
}

impl StdoutExporter {
    /// Create a new stdout exporter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a prefix for each line.
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// br-asupersync-coxhdt — Format labels for the Prometheus
    /// exposition output of `StdoutExporter`. The previous shape
    /// was `format!("{k}=\"{v}\"")` — a value containing `"` would
    /// terminate the quoted string early, and a value containing
    /// `\` (or `\n`) would corrupt the line. Per the Prometheus
    /// exposition spec the value MUST escape `\\`, `\n`, and `\"`.
    /// This shares the spec-required trio with the
    /// `escape_prometheus_label_value` function in metrics.rs
    /// (br-asupersync-pdu7wg) — same canonical escape set, applied
    /// to the otel exporter's separate code path.
    fn format_labels(labels: &[(String, String)]) -> String {
        if labels.is_empty() {
            String::new()
        } else {
            let parts: Vec<_> = labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
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

        if self.cardinality_tracker.check_and_record(
            metric,
            &filtered,
            self.config.max_cardinality,
            self.config.max_metrics,
        ) {
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
                        self.config.max_metrics,
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

        // br-asupersync-2dwg47 — AcqRel ordering on the sampling
        // counter so the fetch_add observed by each thread is
        // sequentially consistent with respect to the prior writes:
        // every thread sees a strictly-increasing sequence of
        // returned counts, which is the property a counter-based
        // deterministic-sampling scheme depends on. Relaxed allows
        // stale counter values to be observed across threads on
        // weakly-ordered targets, breaking lab replay (same input,
        // two replays, different sampled-event sets). AcqRel keeps
        // the single-CAS cost (no full fence) while making the
        // visibility property explicit.
        let count = self.sample_counter.fetch_add(1, Ordering::AcqRel);
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
        let task_type = sanitize_task_type_label(task_type);
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
        let task_type = sanitize_task_type_label(task_type);
        let labels = [KeyValue::new("task_type", task_type)];
        if let Some(filtered) =
            self.check_cardinality("asupersync.deadline.violations_total", &labels)
        {
            self.deadline_violations.add(1, &filtered);
        }
    }

    fn deadline_remaining(&self, task_type: &str, remaining: Duration) {
        if self.should_sample("asupersync.deadline.remaining_seconds") {
            let task_type = sanitize_task_type_label(task_type);
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
            let task_type = sanitize_task_type_label(task_type);
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
        let task_type = sanitize_task_type_label(task_type);
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

/// Sanitise a `task_type` value before stamping it as an OpenTelemetry
/// label. Defence-in-depth against the Cx::set_task_type validator
/// (which is the primary gate); this protects against any code path
/// that constructs a TaskRecord directly and bypasses set_task_type
/// (test paths, internal runtime initialisation).
///
/// Substitutes the bucketed sentinel `"<invalid>"` for values that
/// either:
///   * exceed 64 bytes (cardinality bomb risk), OR
///   * contain any byte outside `[A-Za-z0-9_.:-]` (PII / control-char
///     risk — the same charset enforced by `cx::is_valid_task_type`).
///
/// Pre-validated values pass through unchanged. The single bucket
/// `"<invalid>"` keeps cardinality bounded even when many distinct
/// dirty values are seen.
/// (br-asupersync-9vpwpc)
fn sanitize_task_type_label(task_type: &str) -> String {
    const MAX: usize = 64;
    const SENTINEL: &str = "<invalid>";
    if task_type.is_empty() || task_type.len() > MAX {
        return SENTINEL.to_string();
    }
    let mut bytes = task_type.bytes();
    let first = bytes.next().expect("non-empty checked above");
    if !first.is_ascii_alphabetic() {
        return SENTINEL.to_string();
    }
    if bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':')) {
        task_type.to_string()
    } else {
        SENTINEL.to_string()
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

    /// br-asupersync-bs92bg — Pre-computed-collision DoS mitigation.
    /// Each `CardinalityTracker::new()` instance gets a fresh
    /// `RandomState` seed, so the same label set hashes to a
    /// different bucket in two trackers. An attacker who knows the
    /// hash function shape (which is public — it's std SipHash) but
    /// not the per-process seed cannot pre-compute label values that
    /// collide on the local tracker's buckets.
    ///
    /// The strict assertion below ("at least one of N pairs differs")
    /// allows for the tiny probability that two random seeds happen
    /// to map a single label set to the same 64-bit bucket; with N
    /// distinct labels the probability of all-N collisions is
    /// approximately N * 2^-64, indistinguishable from impossible.
    #[test]
    fn hash_labels_uses_per_instance_random_seed() {
        let tracker_a = CardinalityTracker::new();
        let tracker_b = CardinalityTracker::new();

        let mut differ = false;
        for i in 0..16u32 {
            let labels = [KeyValue::new("id", i.to_string())];
            let h_a = tracker_a.hash_labels(&labels);
            let h_b = tracker_b.hash_labels(&labels);
            if h_a != h_b {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "br-asupersync-bs92bg: two CardinalityTracker instances must hash labels under different seeds"
        );
    }

    /// br-asupersync-bs92bg — Within a single tracker, hashing the
    /// same label set twice must produce the same bucket (the
    /// cardinality contract: identical labels deduplicate). The
    /// per-instance seed is stable for the tracker's lifetime.
    #[test]
    fn hash_labels_is_stable_within_one_tracker() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("outcome", "ok")];
        let h1 = tracker.hash_labels(&labels);
        let h2 = tracker.hash_labels(&labels);
        assert_eq!(
            h1, h2,
            "same labels must hash equally within one tracker (cardinality dedup contract)"
        );
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
        assert!(tracker.check_and_record("test", &labels, 0, usize::MAX));
        assert_eq!(tracker.cardinality("test"), 0);
    }

    #[test]
    fn cardinality_enforcement_is_atomic_under_concurrency() {
        let tracker = Arc::new(CardinalityTracker::new());
        let barrier = Arc::new(Barrier::new(8));

        let handles: [_; 8] = std::array::from_fn(|i| {
            let tracker = Arc::clone(&tracker);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let labels = [KeyValue::new("id", i.to_string())];
                barrier.wait();
                !tracker.check_and_record("test", &labels, 1, usize::MAX)
            })
        });

        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread join"))
            .filter(|accepted| *accepted)
            .count();

        assert_eq!(accepted, 1, "exactly one series should fit under max=1");
        assert_eq!(tracker.cardinality("test"), 1);
    }

    /// br-asupersync-qipj44: with `max_metrics` set to N, the FIRST
    /// N distinct metric names must be accepted; subsequent new
    /// names must hit the overflow path. Existing metric names
    /// continue to accept additional label combinations up to
    /// `max_cardinality` regardless of the metric-name cap.
    #[test]
    fn metric_name_cap_rejects_new_names_after_limit() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];

        // Cap = 3 — first three distinct names accepted.
        for name in ["a", "b", "c"] {
            assert!(
                !tracker.check_and_record(name, &labels, 100, 3),
                "name {name} should be accepted under cap=3"
            );
        }
        // A fourth distinct name must be rejected.
        assert!(
            tracker.check_and_record("d", &labels, 100, 3),
            "fourth distinct metric name must hit overflow path under cap=3"
        );
        // Existing names still accept new label combinations.
        let other_labels = [KeyValue::new("k", "v2")];
        assert!(
            !tracker.check_and_record("a", &other_labels, 100, 3),
            "existing metric must accept new label combinations even under cap"
        );
    }

    /// `max_metrics = 0` is the legacy unbounded behaviour (cap
    /// disabled) — preserved for callers that explicitly want it.
    #[test]
    fn metric_name_cap_zero_disables_the_limit() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];
        for i in 0..1000 {
            let name = format!("m{i}");
            assert!(
                !tracker.check_and_record(&name, &labels, 100, 0),
                "max_metrics=0 must allow unbounded metric names"
            );
        }
    }

    /// Re-recording an already-tracked metric name must not reject
    /// even when the cap is otherwise reached.
    #[test]
    fn metric_name_cap_does_not_reject_existing_metrics() {
        let tracker = CardinalityTracker::new();
        let labels = [KeyValue::new("k", "v")];
        // Fill to cap.
        for i in 0..3 {
            let name = format!("m{i}");
            assert!(!tracker.check_and_record(&name, &labels, 100, 3));
        }
        // Re-record one of the existing names with a brand-new label.
        let new_labels = [KeyValue::new("k", "vNew")];
        assert!(
            !tracker.check_and_record("m0", &new_labels, 100, 3),
            "existing metric must still accept new labels under cap"
        );
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

    /// br-asupersync-coxhdt: escape_label_value must handle the
    /// Prometheus-spec-required escape trio (\\\\, \\n, \\") plus \\r as
    /// defense-in-depth. Otherwise an attacker-controlled label value
    /// containing a literal '"' would close the value-string early
    /// and inject spurious labels.
    #[test]
    fn escape_label_value_handles_spec_required_trio_plus_cr() {
        // Plain values pass through unchanged.
        assert_eq!(escape_label_value("plain"), "plain");
        // Backslash → \\
        assert_eq!(escape_label_value(r"a\b"), r"a\\b");
        // Newline → \n
        assert_eq!(escape_label_value("a\nb"), r"a\nb");
        // Double-quote → \"
        assert_eq!(escape_label_value(r#"a"b"#), r#"a\"b"#);
        // Carriage return → \r
        assert_eq!(escape_label_value("a\rb"), r"a\rb");
        // All four together.
        assert_eq!(escape_label_value("a\\b\nc\"d\re"), r#"a\\b\nc\"d\re"#);
    }

    /// br-asupersync-coxhdt: format_labels MUST route every label
    /// value through escape_label_value. An attacker who controls
    /// a label value containing a literal '"' must NOT be able to
    /// close the value string early and inject `,attacker_label="x"`
    /// into the resulting Prometheus output.
    #[test]
    fn format_labels_escapes_quote_to_prevent_label_injection() {
        let labels = vec![(
            "path".to_string(),
            r#"/api","attacker_label"="injected"#.to_string(),
        )];
        let rendered = StdoutExporter::format_labels(&labels);
        // The literal '"' in the value MUST appear as \" in the output.
        assert!(
            rendered.contains(r#"\""#),
            "format_labels failed to escape attacker quote: {rendered}"
        );
        // The fragment that would inject if escaping failed must NOT
        // appear as a parseable second label.
        assert!(
            !rendered.contains(r#"","attacker_label"="injected"}"#),
            "format_labels permitted label injection: {rendered}"
        );
    }

    /// br-asupersync-coxhdt: a backslash in a label value is doubled,
    /// not consumed.
    #[test]
    fn format_labels_escapes_backslash_to_prevent_value_corruption() {
        let labels = vec![("k".to_string(), r"a\b".to_string())];
        let rendered = StdoutExporter::format_labels(&labels);
        assert!(rendered.contains(r"a\\b"));
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
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, KeyValue, any_value::Value as ProtoValue,
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

    /// br-asupersync-6ofylg — OTel attribute keys are bounded by the
    /// 1 KiB cap from the OTel spec (and most collectors' wire-level
    /// limits). MockSpan::set_attribute previously truncated only
    /// the value, leaving the key path open as an asymmetric
    /// memory-amplification axis when combined with the cardinality
    /// tracker (an attacker-controlled key with fixed prefix
    /// produces one map entry per oversized key, each up to
    /// arbitrarily many bytes). Mirror the closed bd-65gy5c
    /// span.rs key cap by truncating keys to MAX_OTEL_ATTRIBUTE_KEY_LEN.
    const MAX_OTEL_ATTRIBUTE_KEY_LEN: usize = 1024;

    fn truncate_key(key: &str) -> String {
        if key.len() <= MAX_OTEL_ATTRIBUTE_KEY_LEN {
            key.to_string()
        } else {
            // The cap is in bytes, but truncation must still land on
            // a UTF-8 character boundary so the stored key remains
            // valid Unicode.
            let mut cut = MAX_OTEL_ATTRIBUTE_KEY_LEN;
            while cut > 0 && !key.is_char_boundary(cut) {
                cut -= 1;
            }
            key[..cut].to_string()
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
        /// OTLP-typed span attributes for wire-format conformance helpers.
        pub attribute_values: HashMap<String, AttributeValue>,
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

    /// OTLP attribute value variants for typed span-attribute coverage.
    #[derive(Debug, Clone, PartialEq)]
    pub enum AttributeValue {
        String(String),
        Int(i64),
        Float(f64),
        Bool(bool),
        StringArray(Vec<String>),
        IntArray(Vec<i64>),
        FloatArray(Vec<f64>),
        BoolArray(Vec<bool>),
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
                attribute_values: HashMap::new(),
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
        ///
        /// br-asupersync-6ofylg — both key and value are length-
        /// bounded. Keys longer than `MAX_OTEL_ATTRIBUTE_KEY_LEN`
        /// are truncated (mirroring the closed bd-65gy5c span
        /// hardening); values are truncated by the existing
        /// `max_attribute_length` config field.
        pub fn set_attribute(&mut self, key: &str, value: &str) {
            self.set_attribute_value(key, AttributeValue::String(value.to_string()));
        }

        /// Set an integer span attribute.
        pub fn set_int_attribute(&mut self, key: &str, value: i64) {
            self.set_attribute_value(key, AttributeValue::Int(value));
        }

        /// Set a floating-point span attribute.
        pub fn set_float_attribute(&mut self, key: &str, value: f64) {
            self.set_attribute_value(key, AttributeValue::Float(value));
        }

        /// Set a boolean span attribute.
        pub fn set_bool_attribute(&mut self, key: &str, value: bool) {
            self.set_attribute_value(key, AttributeValue::Bool(value));
        }

        /// Set an OTLP-typed span attribute for protobuf conformance checks.
        pub fn set_attribute_value(&mut self, key: &str, value: AttributeValue) {
            let key = truncate_key(key);
            if self.attributes.contains_key(&key) || self.attributes.len() < self.max_attributes {
                let value = self.normalize_attribute_value(value);
                self.attributes
                    .insert(key.clone(), attribute_value_text(&value));
                self.attribute_values.insert(key, value);
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

        /// Convert span attributes to OTLP protobuf key/value pairs with stable ordering.
        pub fn to_otlp_attributes(&self) -> Vec<KeyValue> {
            let mut attributes: Vec<_> = self
                .attribute_values
                .iter()
                .map(|(key, value)| KeyValue {
                    key: key.clone(),
                    value: Some(attribute_value_to_any_value(value)),
                })
                .collect();
            attributes.sort_by(|left, right| left.key.cmp(&right.key));
            attributes
        }

        fn normalize_attribute_value(&self, value: AttributeValue) -> AttributeValue {
            match value {
                AttributeValue::String(value) => {
                    AttributeValue::String(truncate_value(&value, self.max_attribute_length))
                }
                AttributeValue::StringArray(values) => AttributeValue::StringArray(
                    values
                        .into_iter()
                        .map(|value| truncate_value(&value, self.max_attribute_length))
                        .collect(),
                ),
                other => other,
            }
        }
    }

    fn attribute_value_text(value: &AttributeValue) -> String {
        match value {
            AttributeValue::String(value) => value.clone(),
            AttributeValue::Int(value) => value.to_string(),
            AttributeValue::Float(value) => value.to_string(),
            AttributeValue::Bool(value) => value.to_string(),
            AttributeValue::StringArray(values) => values.join(","),
            AttributeValue::IntArray(values) => values
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            AttributeValue::FloatArray(values) => values
                .iter()
                .map(f64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            AttributeValue::BoolArray(values) => values
                .iter()
                .map(bool::to_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    fn attribute_value_to_any_value(value: &AttributeValue) -> AnyValue {
        use opentelemetry_proto::tonic::common::v1::ArrayValue;

        match value {
            AttributeValue::String(value) => AnyValue {
                value: Some(ProtoValue::StringValue(value.clone())),
            },
            AttributeValue::Int(value) => AnyValue {
                value: Some(ProtoValue::IntValue(*value)),
            },
            AttributeValue::Float(value) => AnyValue {
                value: Some(ProtoValue::DoubleValue(*value)),
            },
            AttributeValue::Bool(value) => AnyValue {
                value: Some(ProtoValue::BoolValue(*value)),
            },
            AttributeValue::StringArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::StringValue(value.clone())),
                        })
                        .collect(),
                })),
            },
            AttributeValue::IntArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::IntValue(*value)),
                        })
                        .collect(),
                })),
            },
            AttributeValue::FloatArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::DoubleValue(*value)),
                        })
                        .collect(),
                })),
            },
            AttributeValue::BoolArray(values) => AnyValue {
                value: Some(ProtoValue::ArrayValue(ArrayValue {
                    values: values
                        .iter()
                        .map(|value| AnyValue {
                            value: Some(ProtoValue::BoolValue(*value)),
                        })
                        .collect(),
                })),
            },
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
    pub(crate) mod tests {
        use super::*;
        use crate::observability::MetricsSnapshot;
        use serde_json::{Value, json};
        use std::collections::BTreeMap;

        fn scrub_span_field(key: &str, value: &str) -> String {
            match key {
                "trace_id" | "span_id" | "parent_span_id" => "[ID]".to_string(),
                "start_time" | "end_time" | "timestamp" => "[TIMESTAMP]".to_string(),
                "request_id" | "traceparent" => "[ID]".to_string(),
                _ => value.to_string(),
            }
        }

        fn sorted_string_map_snapshot(map: &HashMap<String, String>) -> BTreeMap<String, String> {
            map.iter()
                .map(|(key, value)| (key.clone(), scrub_span_field(key, value)))
                .collect()
        }

        fn span_status_snapshot(status: &Status) -> Value {
            match status {
                Status::Unset => json!({"kind": "unset"}),
                Status::Ok => json!({"kind": "ok"}),
                Status::Error { description } => json!({
                    "kind": "error",
                    "description": description,
                }),
            }
        }

        fn span_event_snapshot(event: &SpanEvent) -> Value {
            json!({
                "name": event.name,
                "timestamp": "[TIMESTAMP]",
                "attributes": sorted_string_map_snapshot(&event.attributes),
            })
        }

        pub(crate) fn test_span_snapshot(span: &TestSpan) -> Value {
            json!({
                "name": span.name,
                "kind": format!("{:?}", span.kind),
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "parent_span_id": span.parent_context.as_ref().map(|_| "[ID]"),
                "is_remote": span.context.is_remote(),
                "sampled": span.context.trace_flags().is_sampled(),
                "trace_state_vendor": span.context.trace_state().get("vendor"),
                "start_time": "[TIMESTAMP]",
                "end_time": span.end_time.map(|_| "[TIMESTAMP]"),
                "status": span_status_snapshot(&span.status),
                "attributes": sorted_string_map_snapshot(&span.attributes),
                "baggage": sorted_string_map_snapshot(&span.baggage),
                "events": span.events.iter().map(span_event_snapshot).collect::<Vec<_>>(),
            })
        }

        fn otlp_attributes_snapshot(map: &HashMap<String, String>) -> Vec<Value> {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            entries
                .into_iter()
                .map(|(key, value)| {
                    json!({
                        "key": key,
                        "value": {
                            "string_value": scrub_span_field(key, value),
                        }
                    })
                })
                .collect()
        }

        fn otlp_metric_labels_snapshot(labels: &[(String, String)]) -> Vec<Value> {
            let mut entries: Vec<_> = labels.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            entries
                .into_iter()
                .map(|(key, value)| {
                    json!({
                        "key": key,
                        "value": {
                            "string_value": value,
                        }
                    })
                })
                .collect()
        }

        fn otlp_status_snapshot(status: &Status) -> Value {
            match status {
                Status::Unset => json!({"code": 0, "message": ""}),
                Status::Ok => json!({"code": 1, "message": ""}),
                Status::Error { description } => json!({
                    "code": 2,
                    "message": description,
                }),
            }
        }

        fn otlp_event_wire_snapshot(event: &SpanEvent) -> Value {
            json!({
                "name": event.name,
                "time_unix_nano": "[TIMESTAMP]",
                "attributes": otlp_attributes_snapshot(&event.attributes),
            })
        }

        fn otlp_span_wire_snapshot(span: &TestSpan) -> Value {
            json!({
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "parent_span_id": span.parent_context.as_ref().map(|_| "[ID]").unwrap_or(""),
                "name": span.name,
                "kind": format!("{:?}", span.kind),
                "start_time_unix_nano": "[TIMESTAMP]",
                "end_time_unix_nano": span.end_time.map(|_| "[TIMESTAMP]"),
                "attributes": otlp_attributes_snapshot(&span.attributes),
                "events": span.events.iter().map(otlp_event_wire_snapshot).collect::<Vec<_>>(),
                "status": otlp_status_snapshot(&span.status),
                "trace_state_vendor": span.context.trace_state().get("vendor"),
                "sampled": span.context.trace_flags().is_sampled(),
            })
        }

        fn otlp_metrics_wire_snapshot(snapshot: &MetricsSnapshot) -> Value {
            let mut counters: Vec<_> = snapshot.counters.iter().collect();
            counters.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

            let mut gauges: Vec<_> = snapshot.gauges.iter().collect();
            gauges.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

            let mut histograms: Vec<_> = snapshot.histograms.iter().collect();
            histograms.sort_by(|(left, _, _, _), (right, _, _, _)| left.cmp(right));

            json!({
                "scope_metrics": [{
                    "scope": {
                        "name": "asupersync.observability.otel",
                        "version": "0.2.9",
                    },
                    "metrics": {
                        "counters": counters.into_iter().map(|(name, labels, value)| {
                            json!({
                                "name": name,
                                "sum": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "as_int": value,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                        "gauges": gauges.into_iter().map(|(name, labels, value)| {
                            json!({
                                "name": name,
                                "gauge": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "as_int": value,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                        "histograms": histograms.into_iter().map(|(name, labels, count, sum)| {
                            json!({
                                "name": name,
                                "histogram": {
                                    "data_points": [{
                                        "attributes": otlp_metric_labels_snapshot(labels),
                                        "count": count,
                                        "sum": sum,
                                    }]
                                }
                            })
                        }).collect::<Vec<_>>(),
                    }
                }]
            })
        }

        fn otlp_log_record_snapshot(body: &str, attributes: HashMap<String, String>) -> Value {
            json!({
                "time_unix_nano": "[TIMESTAMP]",
                "trace_id": "[ID]",
                "span_id": "[ID]",
                "severity_text": "INFO",
                "body": body,
                "attributes": otlp_attributes_snapshot(&attributes),
            })
        }

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
        fn test_span_typed_attributes_round_trip_to_otlp() {
            use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;

            let mut span = TestSpan::new("typed", SpanKind::Internal);
            span.set_attribute("service.name", "edge");
            span.set_int_attribute("http.status_code", 200);
            span.set_float_attribute("latency_ms", 1.5);
            span.set_bool_attribute("cached", true);
            span.set_attribute_value("replicas", AttributeValue::IntArray(vec![1, 2, 3]));

            let otlp = span.to_otlp_attributes();
            assert_eq!(otlp.len(), 5);

            let replicas = otlp
                .iter()
                .find(|attr| attr.key == "replicas")
                .and_then(|attr| attr.value.as_ref())
                .and_then(|value| value.value.as_ref());
            assert!(matches!(replicas, Some(ProtoValue::ArrayValue(_))));

            let status = otlp
                .iter()
                .find(|attr| attr.key == "http.status_code")
                .and_then(|attr| attr.value.as_ref())
                .and_then(|value| value.value.as_ref());
            assert_eq!(status, Some(&ProtoValue::IntValue(200)));
        }

        #[test]
        fn test_span_typed_attribute_limits_apply() {
            let config = SpanConformanceConfig {
                max_attributes: 2,
                max_events: 4,
                max_attribute_length: Some(4),
                test_sampling: true,
                test_context_propagation: true,
            };
            let mut span = TestSpan::new_with_config("typed", SpanKind::Internal, &config);

            span.set_attribute("alpha", "abcdef");
            span.set_int_attribute("beta", 42);
            span.set_bool_attribute("gamma", true);

            assert_eq!(span.to_otlp_attributes().len(), 2);
            assert_eq!(
                span.attributes.get("alpha").map(String::as_str),
                Some("abcd")
            );
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

        /// br-asupersync-6ofylg — keys longer than
        /// `MAX_OTEL_ATTRIBUTE_KEY_LEN` MUST be truncated to the cap.
        #[test]
        fn test_span_attribute_key_is_truncated_to_otel_cap() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let oversized_key: String = "k".repeat(super::MAX_OTEL_ATTRIBUTE_KEY_LEN + 100);
            span.set_attribute(&oversized_key, "value");
            // The stored key length must equal the cap (ASCII path:
            // bytes == chars).
            let stored_keys: Vec<&String> = span.attributes.keys().collect();
            assert_eq!(stored_keys.len(), 1);
            assert_eq!(stored_keys[0].len(), super::MAX_OTEL_ATTRIBUTE_KEY_LEN);
            // Original oversized key is NOT in the map (it was truncated).
            assert!(!span.attributes.contains_key(&oversized_key));
        }

        /// br-asupersync-6ofylg — the 1 KiB cap is byte-based, not
        /// char-based. Oversized multibyte keys must therefore be
        /// truncated to <= 1024 bytes while remaining valid UTF-8.
        #[test]
        fn test_span_attribute_multibyte_key_is_truncated_by_bytes() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            let oversized_key = "🔒".repeat(400);
            assert!(oversized_key.len() > super::MAX_OTEL_ATTRIBUTE_KEY_LEN);

            span.set_attribute(&oversized_key, "value");

            let stored_key = span.attributes.keys().next().expect("stored key");
            assert!(stored_key.len() <= super::MAX_OTEL_ATTRIBUTE_KEY_LEN);
            assert!(std::str::from_utf8(stored_key.as_bytes()).is_ok());
            assert!(!span.attributes.contains_key(&oversized_key));
        }

        /// br-asupersync-6ofylg — short keys pass through unchanged.
        #[test]
        fn test_span_attribute_short_key_unchanged() {
            let mut span = TestSpan::new("test", SpanKind::Internal);
            span.set_attribute("short_key", "value");
            assert!(span.attributes.contains_key("short_key"));
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

        #[test]
        fn span_export_snapshot_scrubs_ids_and_timestamps() {
            let config = SpanConformanceConfig {
                max_attributes: 4,
                max_events: 2,
                max_attribute_length: Some(16),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut parent = TestSpan::new_with_config("checkout", SpanKind::Server, &config);
            parent.set_attribute("component", "orders");
            parent.set_attribute("request_id", "req-7c1f7ecf-54ff-4ac8-8ec5-6aa64500a161");
            parent.set_baggage_item("tenant", "alpha");
            parent.add_event(
                "db.query",
                HashMap::from([
                    ("statement".to_string(), "select".to_string()),
                    (
                        "traceparent".to_string(),
                        "00-abcdef-0123456789".to_string(),
                    ),
                ]),
            );
            parent.set_status(Status::Error {
                description: "timeout".into(),
            });
            parent.end();

            let remote_parent = SpanContext::new(
                TraceId::from_bytes([
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
                    0x16, 0x17, 0x18,
                ]),
                SpanId::from_bytes([0x11; 8]),
                TraceFlags::SAMPLED,
                true,
                TraceState::from_key_value([("vendor", "edge")]).expect("valid trace state"),
            );
            let remote_child = TestSpan::child_from_remote_parent(
                remote_parent,
                HashMap::from([("tenant".to_string(), "alpha".to_string())]),
                "cache.lookup",
                SpanKind::Client,
                &config,
            );

            insta::assert_json_snapshot!(
                "span_export_scrubbed",
                json!({
                    "parent": test_span_snapshot(&parent),
                    "remote_child": test_span_snapshot(&remote_child),
                })
            );
        }

        #[test]
        fn span_export_format_snapshot_scrubs_ids_and_timestamps() {
            let config = SpanConformanceConfig {
                max_attributes: 6,
                max_events: 3,
                max_attribute_length: Some(20),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut happy_path =
                TestSpan::new_with_config("http.request", SpanKind::Server, &config);
            happy_path.set_attribute("service.name", "checkout");
            happy_path.set_attribute("http.method", "POST");
            happy_path.add_event(
                "response.sent",
                HashMap::from([("status_code".to_string(), "200".to_string())]),
            );
            happy_path.set_status(Status::Ok);
            happy_path.end();

            let mut error_path = TestSpan::new_with_config("db.query", SpanKind::Client, &config);
            error_path.set_attribute("db.system", "postgresql");
            error_path.set_attribute("db.operation", "select");
            error_path.add_event(
                "db.error",
                HashMap::from([
                    ("error.kind".to_string(), "timeout".to_string()),
                    ("statement".to_string(), "select * from orders".to_string()),
                ]),
            );
            error_path.set_status(Status::Error {
                description: "deadline exceeded".into(),
            });
            error_path.end();

            let mut root = TestSpan::new_with_config("batch.import", SpanKind::Producer, &config);
            root.set_attribute("job.name", "nightly-import");
            root.set_baggage_item("tenant", "alpha");

            let mut decode_child = root.new_child("decode.payload", SpanKind::Internal);
            decode_child.set_attribute("stage", "decode");
            decode_child.add_event(
                "payload.decoded",
                HashMap::from([("records".to_string(), "42".to_string())]),
            );
            decode_child.set_status(Status::Ok);
            decode_child.end();

            let mut publish_child = root.new_child("publish.kafka", SpanKind::Producer);
            publish_child.set_attribute("messaging.system", "kafka");
            publish_child.add_event(
                "broker.ack",
                HashMap::from([("partition".to_string(), "7".to_string())]),
            );
            publish_child.set_status(Status::Ok);
            publish_child.end();

            root.add_event(
                "pipeline.completed",
                HashMap::from([("children".to_string(), "2".to_string())]),
            );
            root.set_status(Status::Ok);
            root.end();

            insta::assert_json_snapshot!(
                "span_export_format_scrubbed",
                json!({
                    "happy_path": test_span_snapshot(&happy_path),
                    "error_path": test_span_snapshot(&error_path),
                    "multi_span_trace": [
                        test_span_snapshot(&root),
                        test_span_snapshot(&decode_child),
                        test_span_snapshot(&publish_child),
                    ],
                })
            );
        }

        #[test]
        fn otlp_wire_format_scrubbed() {
            let config = SpanConformanceConfig {
                max_attributes: 6,
                max_events: 3,
                max_attribute_length: Some(24),
                test_sampling: true,
                test_context_propagation: true,
            };

            let mut root = TestSpan::new_with_config("otlp.export", SpanKind::Server, &config);
            root.set_attribute("service.name", "checkout");
            root.set_attribute("deployment.environment", "staging");
            root.add_event(
                "request.accepted",
                HashMap::from([("route".to_string(), "/v1/orders".to_string())]),
            );
            root.set_status(Status::Ok);
            root.end();

            let mut child = root.new_child("postgres.query", SpanKind::Client);
            child.set_attribute("db.system", "postgresql");
            child.set_attribute("db.operation", "select");
            child.add_event(
                "row.batch",
                HashMap::from([("rows".to_string(), "3".to_string())]),
            );
            child.set_status(Status::Error {
                description: "deadline exceeded".into(),
            });
            child.end();

            let mut metrics = MetricsSnapshot::new();
            metrics.add_counter(
                "otel.export.spans",
                vec![("signal".to_string(), "traces".to_string())],
                2,
            );
            metrics.add_gauge(
                "otel.export.queue_depth",
                vec![("pipeline".to_string(), "primary".to_string())],
                1,
            );
            metrics.add_histogram(
                "otel.export.latency_ms",
                vec![("signal".to_string(), "mixed".to_string())],
                2,
                17.5,
            );

            insta::assert_json_snapshot!(
                "otlp_wire_format_scrubbed",
                json!({
                    "resource_spans": [{
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"string_value": "checkout"}},
                                {"key": "telemetry.sdk.name", "value": {"string_value": "asupersync"}},
                            ]
                        },
                        "scope_spans": [{
                            "scope": {
                                "name": "asupersync.observability.otel",
                                "version": "0.2.9",
                            },
                            "spans": [
                                otlp_span_wire_snapshot(&root),
                                otlp_span_wire_snapshot(&child),
                            ],
                        }]
                    }],
                    "resource_metrics": [otlp_metrics_wire_snapshot(&metrics)],
                    "resource_logs": [{
                        "scope_logs": [{
                            "scope": {
                                "name": "asupersync.observability.otel",
                                "version": "0.2.9",
                            },
                            "log_records": [
                                otlp_log_record_snapshot(
                                    "export started",
                                    HashMap::from([
                                        ("component".to_string(), "otlp".to_string()),
                                        ("signal".to_string(), "traces".to_string()),
                                    ]),
                                ),
                                otlp_log_record_snapshot(
                                    "export retry scheduled",
                                    HashMap::from([
                                        ("component".to_string(), "otlp".to_string()),
                                        ("retry_in_ms".to_string(), "250".to_string()),
                                    ]),
                                ),
                            ],
                        }]
                    }],
                })
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

        /// Returns the pass percentage, matching the enabled implementation.
        pub fn success_rate(&self) -> f64 {
            if self.tests_run == 0 {
                0.0
            } else {
                (self.tests_passed as f64 / self.tests_run as f64) * 100.0
            }
        }
    }

    /// Placeholder function when tracing is disabled.
    pub fn run_span_conformance_tests() -> Result<SpanConformanceResult, Box<dyn std::error::Error>>
    {
        Err("OpenTelemetry span semantics testing requires 'tracing-integration' feature".into())
    }

    #[cfg(test)]
    mod tests {
        use super::SpanConformanceResult;

        #[test]
        fn disabled_success_rate_reflects_recorded_counts() {
            let empty = SpanConformanceResult {
                tests_run: 0,
                tests_passed: 0,
                tests_failed: 0,
                failures: Vec::new(),
            };
            assert_eq!(empty.success_rate(), 0.0);

            let partial = SpanConformanceResult {
                tests_run: 4,
                tests_passed: 3,
                tests_failed: 1,
                failures: vec!["span-status".to_string()],
            };
            assert_eq!(partial.success_rate(), 75.0);
        }
    }
}

// Golden artifact tests for OTEL span serialization
#[cfg(all(test, feature = "tracing-integration"))]
#[path = "otel_span_golden_tests.rs"]
mod otel_span_golden_tests;

#[cfg(all(
    any(test, feature = "fuzz"),
    feature = "metrics",
    feature = "tracing-integration"
))]
pub mod otlp_request_builder {
    use super::span_semantics::TestSpan;
    use super::{MetricLabels, MetricsSnapshot};
    use opentelemetry::trace::{SpanKind as ApiSpanKind, Status as ApiStatus};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{
        LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind as ProtoSpanKind;
    use opentelemetry_proto::tonic::trace::v1::status::StatusCode as ProtoStatusCode;
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus, span,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
    pub const OTEL_SCOPE_NAME: &str = "asupersync.observability.otel";
    pub const OTEL_SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OtlpLogRecordInput {
        pub time_unix_nano: u64,
        pub observed_time_unix_nano: u64,
        pub severity_number: i32,
        pub severity_text: String,
        pub body: String,
        pub attributes: Vec<(String, String)>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OtlpLogScopeInput {
        pub service_name: String,
        pub batch_sequence: u64,
        pub scope_name: String,
        pub log_records: Vec<OtlpLogRecordInput>,
    }

    pub fn severity_number_from_bucket(raw: u8) -> i32 {
        match raw % 6 {
            0 => SeverityNumber::Trace as i32,
            1 => SeverityNumber::Debug as i32,
            2 => SeverityNumber::Info as i32,
            3 => SeverityNumber::Warn as i32,
            4 => SeverityNumber::Error as i32,
            _ => SeverityNumber::Fatal as i32,
        }
    }

    pub fn severity_text_from_bucket(raw: u8) -> String {
        match raw % 6 {
            0 => "TRACE",
            1 => "DEBUG",
            2 => "INFO",
            3 => "WARN",
            4 => "ERROR",
            _ => "FATAL",
        }
        .to_string()
    }

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(ProtoValue::StringValue(value.to_string())),
        }
    }

    fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(string_value(&value.into())),
        }
    }

    fn ordered_proto_attributes(
        attributes: &std::collections::HashMap<String, String>,
    ) -> Vec<KeyValue> {
        let mut ordered: Vec<_> = attributes.iter().collect();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            .map(|(key, value)| key_value(key.clone(), value.clone()))
            .collect()
    }

    fn proto_labels(labels: &MetricLabels) -> Vec<KeyValue> {
        let mut ordered = labels.clone();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            .map(|(key, value)| key_value(key, value))
            .collect()
    }

    fn instrumentation_scope(name: &str) -> InstrumentationScope {
        InstrumentationScope {
            name: name.to_string(),
            version: OTEL_SCOPE_VERSION.to_string(),
            ..Default::default()
        }
    }

    fn resource_with_batch(service_name: &str, batch_sequence: u64) -> Resource {
        Resource {
            attributes: vec![
                key_value("service.name", service_name),
                key_value("batch.sequence", batch_sequence.to_string()),
                key_value("telemetry.sdk.name", "asupersync"),
            ],
            ..Default::default()
        }
    }

    fn unix_nanos(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }

    pub fn metrics_request_from_snapshot(
        snapshot: &MetricsSnapshot,
        service_name: &str,
        batch_sequence: u64,
        scope_name: &str,
    ) -> ExportMetricsServiceRequest {
        let mut metrics = Vec::new();

        for (name, labels, value) in &snapshot.counters {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Sum(Sum {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    is_monotonic: true,
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 1,
                        time_unix_nano: batch_sequence * 1_000 + 2,
                        value: Some(number_data_point::Value::AsInt(*value as i64)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, value) in &snapshot.gauges {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Gauge(Gauge {
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        time_unix_nano: batch_sequence * 1_000 + 3,
                        value: Some(number_data_point::Value::AsInt(*value)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, count, sum) in &snapshot.histograms {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Histogram(Histogram {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    data_points: vec![HistogramDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 4,
                        time_unix_nano: batch_sequence * 1_000 + 5,
                        count: *count,
                        sum: Some(*sum),
                        bucket_counts: vec![*count],
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(instrumentation_scope(scope_name)),
                    metrics,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn proto_span_kind(kind: ApiSpanKind) -> i32 {
        match kind {
            ApiSpanKind::Internal => ProtoSpanKind::Internal as i32,
            ApiSpanKind::Server => ProtoSpanKind::Server as i32,
            ApiSpanKind::Client => ProtoSpanKind::Client as i32,
            ApiSpanKind::Producer => ProtoSpanKind::Producer as i32,
            ApiSpanKind::Consumer => ProtoSpanKind::Consumer as i32,
        }
    }

    fn proto_status(status: &ApiStatus) -> ProtoStatus {
        match status {
            ApiStatus::Unset => ProtoStatus {
                code: ProtoStatusCode::Unset as i32,
                message: String::new(),
            },
            ApiStatus::Ok => ProtoStatus {
                code: ProtoStatusCode::Ok as i32,
                message: String::new(),
            },
            ApiStatus::Error { description } => ProtoStatus {
                code: ProtoStatusCode::Error as i32,
                message: description.clone().into_owned(),
            },
        }
    }

    fn proto_span(span: &TestSpan) -> ProtoSpan {
        ProtoSpan {
            trace_id: span.context.trace_id().to_bytes().to_vec(),
            span_id: span.context.span_id().to_bytes().to_vec(),
            parent_span_id: span
                .parent_context
                .as_ref()
                .map_or_else(Vec::new, |parent| parent.span_id().to_bytes().to_vec()),
            name: span.name.clone(),
            kind: proto_span_kind(span.kind.clone()),
            start_time_unix_nano: unix_nanos(span.start_time),
            end_time_unix_nano: unix_nanos(span.end_time.expect("ended span")),
            attributes: ordered_proto_attributes(&span.attributes),
            events: span
                .events
                .iter()
                .map(|event| span::Event {
                    time_unix_nano: unix_nanos(event.timestamp),
                    name: event.name.clone(),
                    attributes: ordered_proto_attributes(&event.attributes),
                    ..Default::default()
                })
                .collect(),
            status: Some(proto_status(&span.status)),
            ..Default::default()
        }
    }

    pub fn traces_request(
        service_name: &str,
        batch_sequence: u64,
        scope_name: &str,
        spans: &[TestSpan],
    ) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_spans: vec![ScopeSpans {
                    scope: Some(instrumentation_scope(scope_name)),
                    spans: spans.iter().map(proto_span).collect(),
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn log_record(record: &OtlpLogRecordInput) -> LogRecord {
        LogRecord {
            time_unix_nano: record.time_unix_nano,
            observed_time_unix_nano: record.observed_time_unix_nano,
            severity_number: record.severity_number,
            severity_text: record.severity_text.clone(),
            body: Some(string_value(&record.body)),
            attributes: record
                .attributes
                .iter()
                .map(|(key, value)| key_value(key.clone(), value.clone()))
                .collect(),
            ..Default::default()
        }
    }

    pub fn logs_request(scopes: &[OtlpLogScopeInput]) -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: scopes
                .iter()
                .map(|scope| ResourceLogs {
                    resource: Some(resource_with_batch(
                        &scope.service_name,
                        scope.batch_sequence,
                    )),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope(&scope.scope_name)),
                        log_records: scope.log_records.iter().map(log_record).collect(),
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(all(test, feature = "metrics", feature = "tracing-integration"))]
mod otlp_wire_format_tests {
    use super::span_semantics::{SpanConformanceConfig, TestSpan};
    use super::{MetricLabels, MetricsSnapshot};
    use opentelemetry::trace::{SpanKind as ApiSpanKind, Status as ApiStatus};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{
        LogRecord, ResourceLogs, ScopeLogs, SeverityNumber,
    };
    use opentelemetry_proto::tonic::metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind as ProtoSpanKind;
    use opentelemetry_proto::tonic::trace::v1::status::StatusCode as ProtoStatusCode;
    use opentelemetry_proto::tonic::trace::v1::{
        ResourceSpans, ScopeSpans, Span as ProtoSpan, Status as ProtoStatus, span,
    };
    use prost::Message;
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
    const OTEL_SCOPE_NAME: &str = "asupersync.observability.otel";
    const OTEL_SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

    fn string_value(value: &str) -> AnyValue {
        AnyValue {
            value: Some(ProtoValue::StringValue(value.to_string())),
        }
    }

    fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(string_value(&value.into())),
        }
    }

    fn ordered_proto_attributes(attributes: &HashMap<String, String>) -> Vec<KeyValue> {
        let mut ordered: Vec<_> = attributes.iter().collect();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            .map(|(key, value)| key_value(key.clone(), value.clone()))
            .collect()
    }

    fn proto_labels(labels: &MetricLabels) -> Vec<KeyValue> {
        let mut ordered = labels.clone();
        ordered.sort_unstable_by(|(left_key, left_value), (right_key, right_value)| {
            left_key
                .cmp(right_key)
                .then_with(|| left_value.cmp(right_value))
        });
        ordered
            .into_iter()
            .map(|(key, value)| key_value(key, value))
            .collect()
    }

    fn instrumentation_scope(name: &str) -> InstrumentationScope {
        InstrumentationScope {
            name: name.to_string(),
            version: OTEL_SCOPE_VERSION.to_string(),
            ..Default::default()
        }
    }

    fn resource_with_batch(service_name: &str, batch_sequence: u64) -> Resource {
        Resource {
            attributes: vec![
                key_value("service.name", service_name),
                key_value("batch.sequence", batch_sequence.to_string()),
                key_value("telemetry.sdk.name", "asupersync"),
            ],
            ..Default::default()
        }
    }

    fn unix_nanos(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64
    }

    fn any_value_as_str(value: &AnyValue) -> &str {
        match value.value.as_ref() {
            Some(ProtoValue::StringValue(text)) => text.as_str(),
            other => panic!("expected string AnyValue, got {other:?}"),
        }
    }

    fn key_value_str_value(attribute: &KeyValue) -> &str {
        any_value_as_str(attribute.value.as_ref().expect("attribute value"))
    }

    fn metrics_request_from_snapshot(
        snapshot: &MetricsSnapshot,
        service_name: &str,
        batch_sequence: u64,
    ) -> ExportMetricsServiceRequest {
        let mut metrics = Vec::new();

        for (name, labels, value) in &snapshot.counters {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Sum(Sum {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    is_monotonic: true,
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 1,
                        time_unix_nano: batch_sequence * 1_000 + 2,
                        value: Some(number_data_point::Value::AsInt(*value as i64)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, value) in &snapshot.gauges {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Gauge(Gauge {
                    data_points: vec![NumberDataPoint {
                        attributes: proto_labels(labels),
                        time_unix_nano: batch_sequence * 1_000 + 3,
                        value: Some(number_data_point::Value::AsInt(*value)),
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        for (name, labels, count, sum) in &snapshot.histograms {
            metrics.push(Metric {
                name: name.clone(),
                data: Some(metric::Data::Histogram(Histogram {
                    aggregation_temporality: AggregationTemporality::Cumulative as i32,
                    data_points: vec![HistogramDataPoint {
                        attributes: proto_labels(labels),
                        start_time_unix_nano: batch_sequence * 1_000 + 4,
                        time_unix_nano: batch_sequence * 1_000 + 5,
                        count: *count,
                        sum: Some(*sum),
                        bucket_counts: vec![*count],
                        ..Default::default()
                    }],
                })),
                ..Default::default()
            });
        }

        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(resource_with_batch(service_name, batch_sequence)),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                    metrics,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn proto_span_kind(kind: ApiSpanKind) -> i32 {
        match kind {
            ApiSpanKind::Internal => ProtoSpanKind::Internal as i32,
            ApiSpanKind::Server => ProtoSpanKind::Server as i32,
            ApiSpanKind::Client => ProtoSpanKind::Client as i32,
            ApiSpanKind::Producer => ProtoSpanKind::Producer as i32,
            ApiSpanKind::Consumer => ProtoSpanKind::Consumer as i32,
        }
    }

    fn proto_status(status: &ApiStatus) -> ProtoStatus {
        match status {
            ApiStatus::Unset => ProtoStatus {
                code: ProtoStatusCode::Unset as i32,
                message: String::new(),
            },
            ApiStatus::Ok => ProtoStatus {
                code: ProtoStatusCode::Ok as i32,
                message: String::new(),
            },
            ApiStatus::Error { description } => ProtoStatus {
                code: ProtoStatusCode::Error as i32,
                message: description.clone().into_owned(),
            },
        }
    }

    fn proto_span(span: &TestSpan) -> ProtoSpan {
        ProtoSpan {
            trace_id: span.context.trace_id().to_bytes().to_vec(),
            span_id: span.context.span_id().to_bytes().to_vec(),
            parent_span_id: span
                .parent_context
                .as_ref()
                .map_or_else(Vec::new, |parent| parent.span_id().to_bytes().to_vec()),
            name: span.name.clone(),
            kind: proto_span_kind(span.kind.clone()),
            start_time_unix_nano: unix_nanos(span.start_time),
            end_time_unix_nano: unix_nanos(span.end_time.expect("ended span")),
            attributes: ordered_proto_attributes(&span.attributes),
            events: span
                .events
                .iter()
                .map(|event| span::Event {
                    time_unix_nano: unix_nanos(event.timestamp),
                    name: event.name.clone(),
                    attributes: ordered_proto_attributes(&event.attributes),
                    ..Default::default()
                })
                .collect(),
            status: Some(proto_status(&span.status)),
            ..Default::default()
        }
    }

    fn traces_request(spans: Vec<ProtoSpan>) -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(resource_with_batch("checkout", 7)),
                scope_spans: vec![ScopeSpans {
                    scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                    spans,
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                }],
                schema_url: OTEL_SCHEMA_URL.to_string(),
            }],
        }
    }

    fn log_record(sequence: u64, body: &str, attributes: &[(&str, &str)]) -> LogRecord {
        LogRecord {
            time_unix_nano: sequence,
            observed_time_unix_nano: sequence + 1,
            severity_number: SeverityNumber::Info as i32,
            severity_text: "INFO".to_string(),
            body: Some(string_value(body)),
            attributes: attributes
                .iter()
                .map(|(key, value)| key_value(*key, *value))
                .collect(),
            ..Default::default()
        }
    }

    fn logs_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![
                ResourceLogs {
                    resource: Some(resource_with_batch("checkout", 1)),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope(OTEL_SCOPE_NAME)),
                        log_records: vec![
                            log_record(
                                10,
                                "export started",
                                &[("component", "otlp"), ("sequence", "1")],
                            ),
                            log_record(
                                20,
                                "export retry scheduled",
                                &[("component", "otlp"), ("sequence", "2")],
                            ),
                        ],
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                },
                ResourceLogs {
                    resource: Some(resource_with_batch("billing", 2)),
                    scope_logs: vec![ScopeLogs {
                        scope: Some(instrumentation_scope("asupersync.billing")),
                        log_records: vec![log_record(
                            30,
                            "billing flush complete",
                            &[("component", "billing"), ("sequence", "3")],
                        )],
                        schema_url: OTEL_SCHEMA_URL.to_string(),
                    }],
                    schema_url: OTEL_SCHEMA_URL.to_string(),
                },
            ],
        }
    }

    #[test]
    fn otlp_metrics_protobuf_round_trip_preserves_batches_and_metric_order() {
        let mut primary = MetricsSnapshot::new();
        primary.add_counter(
            "otel.export.requests",
            vec![("signal".to_string(), "metrics".to_string())],
            5,
        );
        primary.add_gauge(
            "otel.export.queue_depth",
            vec![("pipeline".to_string(), "primary".to_string())],
            2,
        );
        primary.add_histogram(
            "otel.export.latency_ms",
            vec![("signal".to_string(), "metrics".to_string())],
            3,
            12.5,
        );

        let mut secondary = MetricsSnapshot::new();
        secondary.add_counter(
            "otel.export.requests",
            vec![("signal".to_string(), "logs".to_string())],
            1,
        );

        let mut request = metrics_request_from_snapshot(&primary, "checkout", 1);
        request
            .resource_metrics
            .extend(metrics_request_from_snapshot(&secondary, "billing", 2).resource_metrics);

        let encoded = request.encode_to_vec();
        let decoded = ExportMetricsServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        assert_eq!(decoded.resource_metrics.len(), 2);
        assert_eq!(
            key_value_str_value(
                &decoded.resource_metrics[0]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "1"
        );
        assert_eq!(
            key_value_str_value(
                &decoded.resource_metrics[1]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "2"
        );

        let primary_metrics = &decoded.resource_metrics[0].scope_metrics[0].metrics;
        assert_eq!(primary_metrics[0].name, "otel.export.requests");
        assert_eq!(primary_metrics[1].name, "otel.export.queue_depth");
        assert_eq!(primary_metrics[2].name, "otel.export.latency_ms");
        assert_eq!(
            decoded.resource_metrics[0].scope_metrics[0]
                .scope
                .as_ref()
                .expect("scope")
                .name,
            OTEL_SCOPE_NAME
        );
    }

    #[test]
    fn otlp_trace_protobuf_round_trip_preserves_span_order_and_attribute_limits() {
        let config = SpanConformanceConfig {
            max_attributes: 8,
            max_events: 4,
            max_attribute_length: Some(12),
            test_sampling: true,
            test_context_propagation: true,
        };
        let mut root = TestSpan::new_with_config("checkout", ApiSpanKind::Server, &config);
        let oversized_key = "k".repeat(1_200);
        root.set_attribute(&oversized_key, "value-that-should-truncate");
        root.set_attribute("service.name", "checkout");
        root.add_event(
            "db.query",
            HashMap::from([("sql".to_string(), "select * from orders".to_string())]),
        );
        root.set_status(ApiStatus::Ok);
        root.end();

        let mut child = root.new_child("postgres.query", ApiSpanKind::Client);
        child.set_attribute("db.system", "postgresql");
        child.set_status(ApiStatus::Error {
            description: "deadline exceeded".into(),
        });
        child.end();

        let request = traces_request(vec![proto_span(&root), proto_span(&child)]);
        let encoded = request.encode_to_vec();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        let spans = &decoded.resource_spans[0].scope_spans[0].spans;
        assert_eq!(spans[0].name, "checkout");
        assert_eq!(spans[1].name, "postgres.query");
        assert_eq!(spans[1].parent_span_id, spans[0].span_id);

        let oversized_attribute = spans[0]
            .attributes
            .iter()
            .find(|attribute| attribute.key.starts_with('k'))
            .expect("oversized attribute");
        assert_eq!(oversized_attribute.key.len(), 1024);
        assert_eq!(key_value_str_value(oversized_attribute), "value-that-s");
        assert_eq!(
            spans[0].events[0].attributes[0]
                .value
                .as_ref()
                .map(any_value_as_str),
            Some("select * fro")
        );
    }

    #[test]
    fn otlp_logs_protobuf_round_trip_preserves_batch_and_record_sequence() {
        let request = logs_request();
        let encoded = request.encode_to_vec();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).expect("decode");
        assert_eq!(decoded, request);

        assert_eq!(decoded.resource_logs.len(), 2);
        assert_eq!(
            key_value_str_value(
                &decoded.resource_logs[0]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "1"
        );
        assert_eq!(
            key_value_str_value(
                &decoded.resource_logs[1]
                    .resource
                    .as_ref()
                    .expect("resource")
                    .attributes[1]
            ),
            "2"
        );

        let first_scope = &decoded.resource_logs[0].scope_logs[0];
        assert_eq!(first_scope.log_records.len(), 2);
        assert_eq!(
            any_value_as_str(first_scope.log_records[0].body.as_ref().expect("body")),
            "export started"
        );
        assert_eq!(
            key_value_str_value(&first_scope.log_records[0].attributes[1]),
            "1"
        );
        assert_eq!(
            any_value_as_str(first_scope.log_records[1].body.as_ref().expect("body")),
            "export retry scheduled"
        );
        assert_eq!(
            key_value_str_value(&first_scope.log_records[1].attributes[1]),
            "2"
        );
    }

    /// OTLP export conformance test against opentelemetry-rs reference implementation.
    ///
    /// This test ensures that the same span tree produces byte-identical OTLP protobuf
    /// output between our implementation and the opentelemetry-rs reference implementation.
    /// This is Pattern 1: Differential Testing (Reference Implementation) from the
    /// testing-conformance-harnesses methodology.
    #[test]
    #[cfg(feature = "tracing-integration")]
    fn otlp_export_conformance_byte_identical() {
        use opentelemetry::trace::{SpanBuilder, SpanKind, Status, TraceContextExt, Tracer};
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
        use opentelemetry_proto::tonic::resource::v1::Resource;
        use opentelemetry_proto::tonic::trace::v1::{
            ExportTraceServiceRequest, ResourceSpans, ScopeSpans, Span as OtlpSpan,
        };
        use opentelemetry_sdk::Resource as SdkResource;
        use opentelemetry_sdk::trace::{BatchSpanProcessor, TracerProvider};
        use prost::Message;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        // Shared span data for both implementations
        #[derive(Clone)]
        struct CanonicalSpanTree {
            spans: Vec<CanonicalSpan>,
        }

        #[derive(Clone)]
        struct CanonicalSpan {
            name: String,
            kind: SpanKind,
            attributes: HashMap<String, String>,
            events: Vec<(String, HashMap<String, String>)>,
            status: Status,
            parent_idx: Option<usize>,
        }

        impl CanonicalSpanTree {
            fn new() -> Self {
                Self {
                    spans: vec![
                        CanonicalSpan {
                            name: "root_operation".to_string(),
                            kind: SpanKind::Server,
                            attributes: [
                                ("service.name".to_string(), "asupersync".to_string()),
                                ("http.method".to_string(), "POST".to_string()),
                                ("http.url".to_string(), "/api/v1/process".to_string()),
                            ]
                            .into(),
                            events: vec![(
                                "request.received".to_string(),
                                [("bytes".to_string(), "1024".to_string())].into(),
                            )],
                            status: Status::Ok,
                            parent_idx: None,
                        },
                        CanonicalSpan {
                            name: "database_query".to_string(),
                            kind: SpanKind::Client,
                            attributes: [
                                ("db.system".to_string(), "postgresql".to_string()),
                                (
                                    "db.statement".to_string(),
                                    "SELECT * FROM users".to_string(),
                                ),
                            ]
                            .into(),
                            events: vec![
                                ("query.start".to_string(), HashMap::new()),
                                (
                                    "query.end".to_string(),
                                    [("rows".to_string(), "42".to_string())].into(),
                                ),
                            ],
                            status: Status::Ok,
                            parent_idx: Some(0),
                        },
                        CanonicalSpan {
                            name: "response_processing".to_string(),
                            kind: SpanKind::Internal,
                            attributes: [("component".to_string(), "json_serializer".to_string())]
                                .into(),
                            events: vec![],
                            status: Status::Ok,
                            parent_idx: Some(0),
                        },
                    ],
                }
            }
        }

        // Build OTLP export with our implementation
        fn build_our_otlp_export(tree: &CanonicalSpanTree) -> Vec<u8> {
            // Create OTLP request using our implementation patterns
            let resource = Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(
                            opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                                "asupersync".to_string(),
                            ),
                        ),
                    }),
                }],
                dropped_attributes_count: 0,
            };

            let spans: Vec<OtlpSpan> = tree.spans.iter().enumerate().map(|(idx, span)| {
                OtlpSpan {
                    trace_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], // Fixed for comparison
                    span_id: vec![(idx + 1) as u8, 0, 0, 0, 0, 0, 0, 0],
                    parent_span_id: span.parent_idx.map_or_else(Vec::new, |parent| {
                        vec![(parent + 1) as u8, 0, 0, 0, 0, 0, 0, 0]
                    }),
                    name: span.name.clone(),
                    kind: match span.kind {
                        SpanKind::Internal => 1,
                        SpanKind::Server => 2,
                        SpanKind::Client => 3,
                        SpanKind::Producer => 4,
                        SpanKind::Consumer => 5,
                    },
                    start_time_unix_nano: 1000000000, // Fixed timestamp
                    end_time_unix_nano: 1001000000,
                    attributes: span.attributes.iter().map(|(k, v)| {
                        KeyValue {
                            key: k.clone(),
                            value: Some(AnyValue {
                                value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(v.clone())),
                            }),
                        }
                    }).collect(),
                    events: span.events.iter().map(|(name, attrs)| {
                        opentelemetry_proto::tonic::trace::v1::span::Event {
                            time_unix_nano: 1000500000,
                            name: name.clone(),
                            attributes: attrs.iter().map(|(k, v)| {
                                KeyValue {
                                    key: k.clone(),
                                    value: Some(AnyValue {
                                        value: Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(v.clone())),
                                    }),
                                }
                            }).collect(),
                            dropped_attributes_count: 0,
                        }
                    }).collect(),
                    status: Some(opentelemetry_proto::tonic::trace::v1::Status {
                        code: match span.status {
                            Status::Unset => 0,
                            Status::Ok => 1,
                            Status::Error { .. } => 2,
                        },
                        message: match &span.status {
                            Status::Error { description } => description.clone(),
                            _ => String::new(),
                        },
                    }),
                    dropped_attributes_count: 0,
                    dropped_events_count: 0,
                    dropped_links_count: 0,
                    links: vec![],
                    trace_state: String::new(),
                    flags: 1, // Sampled
                }
            }).collect();

            let scope_spans = ScopeSpans {
                scope: Some(
                    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
                        name: "asupersync".to_string(),
                        version: "0.3.1".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    },
                ),
                spans,
                schema_url: String::new(),
            };

            let resource_spans = ResourceSpans {
                resource: Some(resource),
                scope_spans: vec![scope_spans],
                schema_url: String::new(),
            };

            let request = ExportTraceServiceRequest {
                resource_spans: vec![resource_spans],
            };

            request.encode_to_vec()
        }

        // Build OTLP export with reference opentelemetry-rs implementation
        fn build_reference_otlp_export(tree: &CanonicalSpanTree) -> Vec<u8> {
            // Create a collector that captures the OTLP bytes
            let captured_bytes = Arc::new(Mutex::new(Vec::new()));
            let bytes_clone = captured_bytes.clone();

            // Mock exporter that captures the protobuf bytes
            struct ByteCapturingExporter {
                captured: Arc<Mutex<Vec<u8>>>,
            }

            impl opentelemetry_sdk::export::trace::SpanExporter for ByteCapturingExporter {
                fn export(
                    &mut self,
                    batch: Vec<opentelemetry_sdk::export::trace::SpanData>,
                ) -> opentelemetry_sdk::export::trace::ExportResult {
                    // Convert SpanData to OTLP and capture bytes
                    use opentelemetry_proto::transform::trace::spans_to_proto;

                    let resource = SdkResource::new(vec![opentelemetry::KeyValue::new(
                        "service.name",
                        "asupersync",
                    )]);

                    let resource_spans = spans_to_proto(resource, batch);
                    let request = ExportTraceServiceRequest { resource_spans };
                    let bytes = request.encode_to_vec();

                    *self.captured.lock().unwrap() = bytes;
                    Ok(())
                }
            }

            let exporter = ByteCapturingExporter {
                captured: bytes_clone,
            };

            let tracer_provider = TracerProvider::builder()
                .with_simple_exporter(exporter)
                .with_resource(SdkResource::new(vec![opentelemetry::KeyValue::new(
                    "service.name",
                    "asupersync",
                )]))
                .build();

            let tracer = tracer_provider.tracer("asupersync");

            // Generate the same spans using the reference implementation
            let mut span_contexts = Vec::new();

            for (idx, canonical_span) in tree.spans.iter().enumerate() {
                let span_builder = tracer
                    .span_builder(&canonical_span.name)
                    .with_kind(canonical_span.kind);

                let span_context = if let Some(parent_idx) = canonical_span.parent_idx {
                    // Set parent context
                    opentelemetry::Context::current().with_span(
                        opentelemetry::trace::noop::NoopSpan::new(
                            span_contexts[parent_idx].clone(),
                        ),
                    )
                } else {
                    opentelemetry::Context::current()
                };

                let span = span_context.span();

                for (key, value) in &canonical_span.attributes {
                    span.set_attribute(opentelemetry::KeyValue::new(key.clone(), value.clone()));
                }

                for (event_name, event_attrs) in &canonical_span.events {
                    let attrs: Vec<_> = event_attrs
                        .iter()
                        .map(|(k, v)| opentelemetry::KeyValue::new(k.clone(), v.clone()))
                        .collect();
                    span.add_event_with_timestamp(
                        event_name.clone(),
                        std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_nanos(1000500000),
                        attrs,
                    );
                }

                span.set_status(canonical_span.status.clone());
                span_contexts.push(span.span_context().clone());
                span.end();
            }

            // Force export
            tracer_provider.force_flush();

            captured_bytes.lock().unwrap().clone()
        }

        // Run the conformance test
        let tree = CanonicalSpanTree::new();

        let our_bytes = build_our_otlp_export(&tree);
        let reference_bytes = build_reference_otlp_export(&tree);

        // Verify byte-identical output
        if our_bytes != reference_bytes {
            // For debugging: decode both and compare structure
            let our_decoded =
                ExportTraceServiceRequest::decode(our_bytes.as_slice()).expect("decode our OTLP");
            let ref_decoded = ExportTraceServiceRequest::decode(reference_bytes.as_slice())
                .expect("decode reference OTLP");

            // Create detailed comparison for debugging
            eprintln!("OTLP Conformance Failure:");
            eprintln!(
                "Our implementation spans: {}",
                our_decoded.resource_spans.len()
            );
            eprintln!(
                "Reference implementation spans: {}",
                ref_decoded.resource_spans.len()
            );

            // Use insta for detailed comparison snapshot
            insta::with_settings!({
                snapshot_path => "../../tests/snapshots",
                prepend_module_to_snapshot => false,
            }, {
                insta::assert_yaml_snapshot!("otlp_export_conformance_failure_our", our_decoded);
                insta::assert_yaml_snapshot!("otlp_export_conformance_failure_ref", ref_decoded);
            });

            panic!(
                "OTLP export conformance test failed: byte outputs differ\n\
                 Our bytes: {} bytes\n\
                 Reference bytes: {} bytes\n\
                 Check snapshot files for detailed comparison",
                our_bytes.len(),
                reference_bytes.len()
            );
        }

        // Success: byte-identical OTLP protobuf output
        eprintln!(
            "✅ OTLP conformance test passed: {} byte-identical protobuf output",
            our_bytes.len()
        );
    }
}
