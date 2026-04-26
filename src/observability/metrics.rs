//! Runtime metrics.
//!
//! Provides counters, gauges, and histograms for runtime statistics.

use crate::types::{CancelKind, Outcome, RegionId, TaskId};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

/// A monotonically increasing counter.
#[derive(Debug)]
pub struct Counter {
    name: String,
    value: AtomicU64,
}

impl Counter {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: AtomicU64::new(0),
        }
    }

    /// Increments the counter by 1.
    pub fn increment(&self) {
        self.add(1);
    }

    /// Adds a value to the counter.
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    /// Returns the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Returns the counter name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A gauge that can go up and down.
#[derive(Debug)]
pub struct Gauge {
    name: String,
    value: AtomicI64,
}

impl Gauge {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: AtomicI64::new(0),
        }
    }

    /// Sets the gauge value.
    pub fn set(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Increments the gauge by 1.
    pub fn increment(&self) {
        self.add(1);
    }

    /// Decrements the gauge by 1.
    pub fn decrement(&self) {
        self.sub(1);
    }

    /// Adds a value to the gauge.
    pub fn add(&self, value: i64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    /// Subtracts a value from the gauge.
    pub fn sub(&self, value: i64) {
        self.value.fetch_sub(value, Ordering::Relaxed);
    }

    /// Returns the current value.
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Returns the gauge name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A histogram for distribution tracking.
#[derive(Debug)]
pub struct Histogram {
    name: String,
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64, // Stored as bits of f64
    count: AtomicU64,
}

impl Histogram {
    pub(crate) fn new(name: impl Into<String>, buckets: Vec<f64>) -> Self {
        let mut buckets = buckets;
        buckets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let len = buckets.len();
        let mut counts = Vec::with_capacity(len + 1);
        for _ in 0..=len {
            counts.push(AtomicU64::new(0));
        }

        Self {
            name: name.into(),
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Observes a value.
    pub fn observe(&self, value: f64) {
        // Find bucket index
        let idx = self
            .buckets
            .iter()
            .position(|&b| value <= b)
            .unwrap_or(self.buckets.len());

        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update sum (spin loop for atomic float update)
        let mut current = self.sum.load(Ordering::Relaxed);
        loop {
            let current_f64 = f64::from_bits(current);
            let new_f64 = current_f64 + value;
            let new_bits = new_f64.to_bits();
            match self.sum.compare_exchange_weak(
                current,
                new_bits,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current = v,
            }
        }
    }

    /// Returns the total count of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns the sum of observations.
    pub fn sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }

    /// Returns the histogram name.
    pub fn name(&self) -> &str {
        &self.name
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn bucket_counts(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|atomic| atomic.load(Ordering::Relaxed))
            .collect()
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn reset(&self) {
        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
        self.count.store(0, Ordering::Relaxed);
        self.sum.store(0.0f64.to_bits(), Ordering::Relaxed);
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn mean(&self) -> f64 {
        let total_count = self.count();
        if total_count == 0 {
            0.0
        } else {
            self.sum() / (total_count as f64)
        }
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn bucket_boundaries(&self) -> &[f64] {
        &self.buckets
    }

    #[cfg(test)]
    pub(crate) fn percentile(&self, p: f64) -> Option<f64> {
        if !(0.0..=1.0).contains(&p) || self.count() == 0 {
            return None;
        }

        let total = self.count();
        let target_rank = if p == 0.0 {
            1
        } else {
            ((total as f64) * p).ceil() as u64
        };
        let mut cumulative = 0_u64;

        for (i, count) in self
            .counts
            .iter()
            .enumerate()
            .map(|(i, count)| (i, count.load(Ordering::Relaxed)))
        {
            cumulative += count;
            if cumulative >= target_rank {
                if i == self.buckets.len() {
                    return None;
                }
                return Some(self.buckets[i]);
            }
        }
        None
    }
}

/// A summary for quantile-oriented distribution tracking.
#[derive(Debug)]
pub struct Summary {
    name: String,
    values: Mutex<Vec<f64>>,
    sum: AtomicU64, // Stored as bits of f64
    count: AtomicU64,
}

impl Summary {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            values: Mutex::new(Vec::new()),
            sum: AtomicU64::new(0.0f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }

    /// Observes a value.
    pub fn observe(&self, value: f64) {
        self.values
            .lock()
            .expect("summary values mutex poisoned")
            .push(value);
        self.count.fetch_add(1, Ordering::Relaxed);

        let mut current = self.sum.load(Ordering::Relaxed);
        loop {
            let current_f64 = f64::from_bits(current);
            let new_f64 = current_f64 + value;
            let new_bits = new_f64.to_bits();
            match self.sum.compare_exchange_weak(
                current,
                new_bits,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => current = v,
            }
        }
    }

    /// Returns the total count of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns the sum of observations.
    pub fn sum(&self) -> f64 {
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }

    /// Returns the summary name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns an exact quantile from the observed values.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if !(0.0..=1.0).contains(&q) {
            return None;
        }

        let mut values = self
            .values
            .lock()
            .expect("summary values mutex poisoned")
            .clone();
        if values.is_empty() {
            return None;
        }

        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let last_index = values.len() - 1;
        let rank = ((last_index as f64) * q).round() as usize;
        values.get(rank).copied()
    }
}

/// Default per-kind cardinality cap for [`Metrics`] (br-asupersync-eq197n).
///
/// Each metric kind (counters, gauges, histograms, summaries) is capped
/// independently at this value to bound the in-process registry size and
/// the downstream Prometheus scrape size. Override via
/// [`Metrics::with_cardinality_cap`].
pub const DEFAULT_METRIC_CARDINALITY_CAP: usize = 10_000;

/// Sentinel name used by the overflow bucket when the per-kind cap is hit.
///
/// Callers requesting a fresh metric beyond the cap receive the shared
/// overflow bucket for that kind so observations are NOT silently
/// dropped — they are just aggregated into a single named entry the
/// operator can spot in the Prometheus output.
const OVERFLOW_METRIC_NAME: &str = "asupersync_metric_cardinality_overflow";

/// A collection of metrics.
#[derive(Debug)]
pub struct Metrics {
    counters: BTreeMap<String, Arc<Counter>>,
    gauges: BTreeMap<String, Arc<Gauge>>,
    histograms: BTreeMap<String, Arc<Histogram>>,
    summaries: BTreeMap<String, Arc<Summary>>,
    /// Per-kind cap on distinct metric names. Default
    /// [`DEFAULT_METRIC_CARDINALITY_CAP`]. (br-asupersync-eq197n)
    cardinality_cap: usize,
    /// Per-kind overflow-warning latch (counters, gauges, histograms,
    /// summaries). The warn line fires at most once per kind per
    /// `Metrics` instance to avoid log-flooding under sustained
    /// overflow pressure.
    overflow_warned_counter: AtomicBool,
    overflow_warned_gauge: AtomicBool,
    overflow_warned_histogram: AtomicBool,
    overflow_warned_summary: AtomicBool,
    /// Per-kind cumulative count of times the cap rejected a fresh
    /// name and routed to the overflow bucket. Useful for SREs auditing
    /// cardinality pressure without parsing logs.
    overflow_rejections_counter: AtomicU64,
    overflow_rejections_gauge: AtomicU64,
    overflow_rejections_histogram: AtomicU64,
    overflow_rejections_summary: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::with_cardinality_cap(DEFAULT_METRIC_CARDINALITY_CAP)
    }
}

impl Metrics {
    /// Creates a new metrics registry with the default cardinality cap
    /// ([`DEFAULT_METRIC_CARDINALITY_CAP`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new metrics registry with a custom per-kind cardinality cap
    /// (br-asupersync-eq197n).
    ///
    /// A cap of `0` disables the limit (legacy unbounded behaviour). Any
    /// other value caps each metric kind independently — once the
    /// counters map reaches `cap` distinct names, a request for a new
    /// counter name returns the shared overflow bucket
    /// (`asupersync_metric_cardinality_overflow`) and the rejection is
    /// recorded in [`Self::overflow_rejections_counter`].
    #[must_use]
    pub fn with_cardinality_cap(cap: usize) -> Self {
        Self {
            counters: BTreeMap::new(),
            gauges: BTreeMap::new(),
            histograms: BTreeMap::new(),
            summaries: BTreeMap::new(),
            cardinality_cap: cap,
            overflow_warned_counter: AtomicBool::new(false),
            overflow_warned_gauge: AtomicBool::new(false),
            overflow_warned_histogram: AtomicBool::new(false),
            overflow_warned_summary: AtomicBool::new(false),
            overflow_rejections_counter: AtomicU64::new(0),
            overflow_rejections_gauge: AtomicU64::new(0),
            overflow_rejections_histogram: AtomicU64::new(0),
            overflow_rejections_summary: AtomicU64::new(0),
        }
    }

    /// Returns the configured per-kind cardinality cap. `0` means
    /// unlimited (legacy behaviour).
    #[must_use]
    pub fn cardinality_cap(&self) -> usize {
        self.cardinality_cap
    }

    /// Returns the cumulative overflow-rejection count per kind in the
    /// order `(counters, gauges, histograms, summaries)`. SREs can poll
    /// this to detect cardinality pressure without parsing logs.
    #[must_use]
    pub fn overflow_rejections(&self) -> (u64, u64, u64, u64) {
        (
            self.overflow_rejections_counter.load(Ordering::Relaxed),
            self.overflow_rejections_gauge.load(Ordering::Relaxed),
            self.overflow_rejections_histogram.load(Ordering::Relaxed),
            self.overflow_rejections_summary.load(Ordering::Relaxed),
        )
    }

    /// Internal helper: returns true if `name` would be a fresh entry
    /// AND the kind's map is already at the cap. The caller routes to
    /// the overflow bucket in that case.
    #[inline]
    fn cap_would_reject(
        cardinality_cap: usize,
        map_len: usize,
        name: &str,
        contains: bool,
    ) -> bool {
        if cardinality_cap == 0 {
            return false; // Unlimited.
        }
        if contains {
            return false; // Existing name — no growth.
        }
        if name == OVERFLOW_METRIC_NAME {
            // The overflow bucket itself must always be insertable so
            // we can record rejections. Don't recurse.
            return false;
        }
        map_len >= cardinality_cap
    }

    /// Gets or creates a counter. (br-asupersync-eq197n: capped at
    /// [`Self::cardinality_cap`] distinct names; over-cap requests
    /// return the shared overflow bucket.)
    pub fn counter(&mut self, name: &str) -> Arc<Counter> {
        let contains = self.counters.contains_key(name);
        if Self::cap_would_reject(self.cardinality_cap, self.counters.len(), name, contains) {
            self.overflow_rejections_counter
                .fetch_add(1, Ordering::Relaxed);
            if !self.overflow_warned_counter.swap(true, Ordering::Relaxed) {
                crate::tracing_compat::warn!(
                    "metrics: counter cardinality cap ({}) reached; \
                     subsequent fresh names route to '{}' bucket. \
                     Inspect Metrics::overflow_rejections() to monitor pressure.",
                    self.cardinality_cap,
                    OVERFLOW_METRIC_NAME
                );
            }
            return self
                .counters
                .entry(OVERFLOW_METRIC_NAME.to_string())
                .or_insert_with(|| Arc::new(Counter::new(OVERFLOW_METRIC_NAME)))
                .clone();
        }
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new(name)))
            .clone()
    }

    /// Gets or creates a gauge. (br-asupersync-eq197n: capped.)
    pub fn gauge(&mut self, name: &str) -> Arc<Gauge> {
        let contains = self.gauges.contains_key(name);
        if Self::cap_would_reject(self.cardinality_cap, self.gauges.len(), name, contains) {
            self.overflow_rejections_gauge
                .fetch_add(1, Ordering::Relaxed);
            if !self.overflow_warned_gauge.swap(true, Ordering::Relaxed) {
                crate::tracing_compat::warn!(
                    "metrics: gauge cardinality cap ({}) reached; \
                     subsequent fresh names route to '{}' bucket.",
                    self.cardinality_cap,
                    OVERFLOW_METRIC_NAME
                );
            }
            return self
                .gauges
                .entry(OVERFLOW_METRIC_NAME.to_string())
                .or_insert_with(|| Arc::new(Gauge::new(OVERFLOW_METRIC_NAME)))
                .clone();
        }
        self.gauges
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Gauge::new(name)))
            .clone()
    }

    /// Gets or creates a histogram with default buckets.
    /// (br-asupersync-eq197n: capped. Note: re-creating histogram with
    /// different buckets is not supported for same name.)
    pub fn histogram(&mut self, name: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        let contains = self.histograms.contains_key(name);
        if Self::cap_would_reject(self.cardinality_cap, self.histograms.len(), name, contains) {
            self.overflow_rejections_histogram
                .fetch_add(1, Ordering::Relaxed);
            if !self.overflow_warned_histogram.swap(true, Ordering::Relaxed) {
                crate::tracing_compat::warn!(
                    "metrics: histogram cardinality cap ({}) reached; \
                     subsequent fresh names route to '{}' bucket. \
                     Overflow histogram uses the FIRST seen bucket layout.",
                    self.cardinality_cap,
                    OVERFLOW_METRIC_NAME
                );
            }
            return self
                .histograms
                .entry(OVERFLOW_METRIC_NAME.to_string())
                .or_insert_with(|| Arc::new(Histogram::new(OVERFLOW_METRIC_NAME, buckets)))
                .clone();
        }
        self.histograms
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Histogram::new(name, buckets)))
            .clone()
    }

    /// Gets or creates a summary. (br-asupersync-eq197n: capped.)
    pub fn summary(&mut self, name: &str) -> Arc<Summary> {
        let contains = self.summaries.contains_key(name);
        if Self::cap_would_reject(self.cardinality_cap, self.summaries.len(), name, contains) {
            self.overflow_rejections_summary
                .fetch_add(1, Ordering::Relaxed);
            if !self.overflow_warned_summary.swap(true, Ordering::Relaxed) {
                crate::tracing_compat::warn!(
                    "metrics: summary cardinality cap ({}) reached; \
                     subsequent fresh names route to '{}' bucket.",
                    self.cardinality_cap,
                    OVERFLOW_METRIC_NAME
                );
            }
            return self
                .summaries
                .entry(OVERFLOW_METRIC_NAME.to_string())
                .or_insert_with(|| Arc::new(Summary::new(OVERFLOW_METRIC_NAME)))
                .clone();
        }
        self.summaries
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Summary::new(name)))
            .clone()
    }

    /// Exports metrics in a simple text format (Prometheus-like).
    ///
    /// br-asupersync-aog3fz: every metric name is sanitized through
    /// [`sanitize_prometheus_metric_name`] and every label value through
    /// [`escape_prometheus_label_value`] before being written to the
    /// exposition output. A name that does not match the
    /// `[a-zA-Z_:][a-zA-Z0-9_:]*` Prometheus regex would otherwise let
    /// any caller of `Metrics::counter("foo\nbad_metric{job=\"x\"} 999")`
    /// inject arbitrary forged samples into the scrape output by smuggling
    /// `\n` / `{` / `"` through the format string.
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();

        for (name, counter) in &self.counters {
            let Some(name) = sanitize_prometheus_metric_name(name) else {
                continue;
            };
            let _ = writeln!(output, "# TYPE {name} counter");
            let _ = writeln!(output, "{name} {}", counter.get());
        }

        for (name, gauge) in &self.gauges {
            let Some(name) = sanitize_prometheus_metric_name(name) else {
                continue;
            };
            let _ = writeln!(output, "# TYPE {name} gauge");
            let _ = writeln!(output, "{name} {}", gauge.get());
        }

        for (name, hist) in &self.histograms {
            let Some(name) = sanitize_prometheus_metric_name(name) else {
                continue;
            };
            let _ = writeln!(output, "# TYPE {name} histogram");
            let mut cumulative = 0;
            for (i, count) in hist.counts.iter().enumerate() {
                let val = count.load(Ordering::Relaxed);
                cumulative += val;
                let le = if i < hist.buckets.len() {
                    hist.buckets[i].to_string()
                } else {
                    "+Inf".to_string()
                };
                // f64::to_string and the literal "+Inf" cannot contain
                // backslash / newline / double-quote, so the escape is
                // an inexpensive no-op for the values currently emitted.
                // Calling it anyway keeps the contract robust if future
                // code paths route user-supplied label values here.
                let le = escape_prometheus_label_value(&le);
                let _ = writeln!(output, "{name}_bucket{{le=\"{le}\"}} {cumulative}");
            }
            let _ = writeln!(output, "{name}_sum {}", hist.sum());
            let _ = writeln!(output, "{name}_count {}", hist.count());
        }

        for (name, summary) in &self.summaries {
            let Some(name) = sanitize_prometheus_metric_name(name) else {
                continue;
            };
            let _ = writeln!(output, "# TYPE {name} summary");
            for quantile in [0.5, 0.9, 0.99] {
                if let Some(value) = summary.quantile(quantile) {
                    let q = escape_prometheus_label_value(&quantile.to_string());
                    let _ = writeln!(output, "{name}{{quantile=\"{q}\"}} {value}");
                }
            }
            let _ = writeln!(output, "{name}_sum {}", summary.sum());
            let _ = writeln!(output, "{name}_count {}", summary.count());
        }

        output
    }
}

/// Sanitize a Prometheus metric name to match `[a-zA-Z_:][a-zA-Z0-9_:]*`.
///
/// br-asupersync-aog3fz: the Prometheus exposition format treats `\n`,
/// `{`, `}`, and `"` as structural delimiters. A metric name that
/// contains any of those characters can be used to forge additional
/// samples in the scrape output (the classic exposition-format injection
/// — analogous to log injection or HTTP header injection). The fix is
/// to validate against the spec regex before writing the name to the
/// output. We *sanitize* (replace each disallowed byte with `_`) rather
/// than reject, so a caller that names a metric with a `.` or `-`
/// (common in legacy code) still produces a usable scrape; only the
/// empty-string corner case is rejected (returns `None`) since there is
/// no meaningful sanitization for it.
///
/// Returns `None` only for the empty input. Any non-empty input is
/// rewritten to a name that matches `[a-zA-Z_:][a-zA-Z0-9_:]*` — the
/// first character is guaranteed to be a letter, `_`, or `:` (any
/// other leading byte is replaced with `_`).
fn sanitize_prometheus_metric_name(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(name.len());
    for (i, b) in name.bytes().enumerate() {
        let allowed = if i == 0 {
            b.is_ascii_alphabetic() || b == b'_' || b == b':'
        } else {
            b.is_ascii_alphanumeric() || b == b'_' || b == b':'
        };
        out.push(if allowed { b as char } else { '_' });
    }
    Some(out)
}

/// Sanitize a Prometheus label name to match `[a-zA-Z_][a-zA-Z0-9_]*`.
///
/// Mirrors [`sanitize_prometheus_metric_name`] but excludes `:` from
/// the allowed set (label names reserve `:` for metric names per the
/// exposition format). Returns `None` only for the empty input.
#[allow(dead_code)] // exposed for future label-bearing exporters
fn sanitize_prometheus_label_name(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(name.len());
    for (i, b) in name.bytes().enumerate() {
        let allowed = if i == 0 {
            b.is_ascii_alphabetic() || b == b'_'
        } else {
            b.is_ascii_alphanumeric() || b == b'_'
        };
        out.push(if allowed { b as char } else { '_' });
    }
    Some(out)
}

/// Escape a Prometheus label value per the exposition format spec:
/// `\` → `\\`, `\n` → `\n`, `"` → `\"`. All other bytes pass through
/// unchanged (the format permits any UTF-8).
fn escape_prometheus_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '"' => {
                out.push('\\');
                out.push('"');
            }
            _ => out.push(c),
        }
    }
    out
}

/// A wrapper enum for metric values.
#[derive(Debug, Clone, Copy)]
pub enum MetricValue {
    /// Counter value.
    Counter(u64),
    /// Gauge value.
    Gauge(i64),
    /// Histogram summary (count, sum).
    Histogram(u64, f64),
}

/// Simplified outcome kind for metrics labeling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    /// Successful completion.
    Ok,
    /// Application-level error.
    Err,
    /// Cancelled before completion.
    Cancelled,
    /// Task panicked.
    Panicked,
}

impl<T, E> From<&Outcome<T, E>> for OutcomeKind {
    fn from(outcome: &Outcome<T, E>) -> Self {
        match outcome {
            Outcome::Ok(_) => Self::Ok,
            Outcome::Err(_) => Self::Err,
            Outcome::Cancelled(_) => Self::Cancelled,
            Outcome::Panicked(_) => Self::Panicked,
        }
    }
}

/// Trait for runtime metrics collection.
///
/// Implementations can export metrics to various backends (OpenTelemetry,
/// Prometheus, custom sinks) or be no-op for zero overhead.
///
/// # Thread Safety
///
/// Implementations must be safe to call from any thread. Prefer atomics or
/// lock-free aggregation on hot paths.
pub trait MetricsProvider: Send + Sync + 'static {
    // === Task Metrics ===

    /// Called when a task is spawned.
    fn task_spawned(&self, region_id: RegionId, task_id: TaskId);

    /// Called when a task completes.
    fn task_completed(&self, task_id: TaskId, outcome: OutcomeKind, duration: Duration);

    // === Region Metrics ===

    /// Called when a region is created.
    fn region_created(&self, region_id: RegionId, parent: Option<RegionId>);

    /// Called when a region is closed.
    fn region_closed(&self, region_id: RegionId, lifetime: Duration);

    // === Cancellation Metrics ===

    /// Called when a cancellation is requested.
    fn cancellation_requested(&self, region_id: RegionId, kind: CancelKind);

    /// Called when drain phase completes.
    fn drain_completed(&self, region_id: RegionId, duration: Duration);

    // === Budget Metrics ===

    /// Called when a deadline is set.
    fn deadline_set(&self, region_id: RegionId, deadline: Duration);

    /// Called when a deadline is exceeded.
    fn deadline_exceeded(&self, region_id: RegionId);

    // === Deadline Monitoring Metrics ===

    /// Called when a deadline warning is emitted.
    fn deadline_warning(&self, task_type: &str, reason: &'static str, remaining: Duration);

    /// Called when a deadline violation is observed.
    fn deadline_violation(&self, task_type: &str, over_by: Duration);

    /// Called to record remaining time at task completion.
    fn deadline_remaining(&self, task_type: &str, remaining: Duration);

    /// Called to record time between progress checkpoints.
    fn checkpoint_interval(&self, task_type: &str, interval: Duration);

    /// Called when a task is detected as stuck (no progress).
    fn task_stuck_detected(&self, task_type: &str);

    // === Obligation Metrics ===

    /// Called when an obligation is created.
    fn obligation_created(&self, region_id: RegionId);

    /// Called when an obligation is discharged.
    fn obligation_discharged(&self, region_id: RegionId);

    /// Called when an obligation is dropped without discharge.
    fn obligation_leaked(&self, region_id: RegionId);

    // === Scheduler Metrics ===

    /// Called after each scheduler tick.
    fn scheduler_tick(&self, tasks_polled: usize, duration: Duration);
}

/// Metrics provider that does nothing.
///
/// Used when metrics are disabled; the compiler should optimize calls away.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpMetrics;

impl MetricsProvider for NoOpMetrics {
    fn task_spawned(&self, _: RegionId, _: TaskId) {}

    fn task_completed(&self, _: TaskId, _: OutcomeKind, _: Duration) {}

    fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

    fn region_closed(&self, _: RegionId, _: Duration) {}

    fn cancellation_requested(&self, _: RegionId, _: CancelKind) {}

    fn drain_completed(&self, _: RegionId, _: Duration) {}

    fn deadline_set(&self, _: RegionId, _: Duration) {}

    fn deadline_exceeded(&self, _: RegionId) {}

    fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}

    fn deadline_violation(&self, _: &str, _: Duration) {}

    fn deadline_remaining(&self, _: &str, _: Duration) {}

    fn checkpoint_interval(&self, _: &str, _: Duration) {}

    fn task_stuck_detected(&self, _: &str) {}

    fn obligation_created(&self, _: RegionId) {}

    fn obligation_discharged(&self, _: RegionId) {}

    fn obligation_leaked(&self, _: RegionId) {}

    fn scheduler_tick(&self, _: usize, _: Duration) {}
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let counter = Counter::new("test");
        counter.increment();
        assert_eq!(counter.get(), 1);
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge_set() {
        let gauge = Gauge::new("test");
        gauge.set(42);
        assert_eq!(gauge.get(), 42);
        gauge.increment();
        assert_eq!(gauge.get(), 43);
        gauge.decrement();
        assert_eq!(gauge.get(), 42);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_histogram_observe() {
        let hist = Histogram::new("test", vec![1.0, 2.0, 5.0]);
        hist.observe(0.5); // bucket 0
        hist.observe(1.5); // bucket 1
        hist.observe(10.0); // bucket 3 (+Inf)

        assert_eq!(hist.count(), 3);
        assert_eq!(hist.sum(), 12.0);
    }

    #[test]
    fn test_registry_register() {
        let mut metrics = Metrics::new();
        let c1 = metrics.counter("c1");
        c1.increment();

        let c2 = metrics.counter("c1"); // Same counter
        assert_eq!(c2.get(), 1);
    }

    #[test]
    fn test_registry_export() {
        let mut metrics = Metrics::new();
        metrics.counter("requests").add(10);
        metrics.gauge("memory").set(1024);

        let output = metrics.export_prometheus();
        assert!(output.contains("requests 10"));
        assert!(output.contains("memory 1024"));
    }

    /// br-asupersync-eq197n: cardinality cap rejects fresh names beyond
    /// the limit and routes them to the shared overflow bucket while
    /// preserving access to existing-name lookups.
    #[test]
    fn cardinality_cap_routes_fresh_names_to_overflow_bucket() {
        let mut metrics = Metrics::with_cardinality_cap(3);
        // Fill cap exactly.
        metrics.counter("a").increment();
        metrics.counter("b").increment();
        metrics.counter("c").increment();
        assert_eq!(metrics.counters.len(), 3);
        assert_eq!(metrics.overflow_rejections().0, 0);

        // Existing names still resolve — no growth, no rejection.
        let a_again = metrics.counter("a");
        a_again.add(5);
        assert_eq!(metrics.counters.len(), 3);
        assert_eq!(metrics.overflow_rejections().0, 0);

        // Fresh name beyond cap routes to overflow bucket. The map
        // grows by ONE (the overflow entry itself, created lazily).
        let overflow = metrics.counter("d");
        overflow.add(7);
        assert_eq!(
            metrics.overflow_rejections().0,
            1,
            "first over-cap name should bump rejection counter"
        );
        // Subsequent fresh names DON'T grow the map further — they all
        // funnel into the SAME overflow bucket.
        metrics.counter("e").add(3);
        metrics.counter("f").add(11);
        assert_eq!(
            metrics.overflow_rejections().0,
            3,
            "every fresh-name-over-cap should bump rejection counter"
        );
        // Map size: 3 originals + 1 overflow bucket = 4. Stable.
        assert_eq!(metrics.counters.len(), 4);

        // The overflow bucket aggregates all over-cap observations
        // (7 + 3 + 11 = 21).
        assert_eq!(overflow.get(), 21);
    }

    /// br-asupersync-eq197n: per-kind caps are independent — counter
    /// overflow does NOT affect gauge / histogram / summary growth.
    #[test]
    fn cardinality_cap_is_per_kind_not_shared() {
        let mut metrics = Metrics::with_cardinality_cap(1);
        metrics.counter("c1");
        metrics.counter("c2"); // overflow on counters
        assert_eq!(metrics.overflow_rejections().0, 1);

        // Gauges have their own cap budget, untouched.
        metrics.gauge("g1");
        assert_eq!(metrics.overflow_rejections().1, 0);
        metrics.gauge("g2"); // overflow on gauges only
        assert_eq!(metrics.overflow_rejections().1, 1);

        // Histograms still untouched.
        metrics.histogram("h1", vec![1.0, 2.0]);
        assert_eq!(metrics.overflow_rejections().2, 0);

        // Summaries still untouched.
        metrics.summary("s1");
        assert_eq!(metrics.overflow_rejections().3, 0);
    }

    /// br-asupersync-eq197n: cap of 0 disables the limit (legacy
    /// unbounded behaviour) — non-breaking escape hatch for callers
    /// that explicitly opt out.
    #[test]
    fn cardinality_cap_zero_disables_limit() {
        let mut metrics = Metrics::with_cardinality_cap(0);
        for i in 0..50 {
            metrics.counter(&format!("c{i}"));
        }
        assert_eq!(metrics.counters.len(), 50);
        assert_eq!(metrics.overflow_rejections().0, 0);
    }

    /// br-asupersync-eq197n: warn-once latches per kind so sustained
    /// overflow pressure doesn't flood the log.
    #[test]
    fn cardinality_cap_warn_latches_per_kind() {
        let mut metrics = Metrics::with_cardinality_cap(1);
        metrics.counter("c1");
        // Trigger the warn-once latch by a single overflow.
        metrics.counter("c2");
        assert!(metrics.overflow_warned_counter.load(Ordering::Relaxed));
        // Many subsequent overflows must NOT re-flip the latch.
        for i in 0..100 {
            metrics.counter(&format!("c_extra_{i}"));
        }
        assert!(metrics.overflow_warned_counter.load(Ordering::Relaxed));
        // Gauge latch must still be unset (per-kind isolation).
        assert!(!metrics.overflow_warned_gauge.load(Ordering::Relaxed));
    }

    #[test]
    fn test_metrics_provider_object_safe() {
        fn assert_object_safe(_: &dyn MetricsProvider) {}

        let provider = NoOpMetrics;
        assert_object_safe(&provider);

        let boxed: Box<dyn MetricsProvider> = Box::new(NoOpMetrics);
        boxed.task_spawned(RegionId::testing_default(), TaskId::testing_default());
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn counter_name() {
        let c = Counter::new("requests_total");
        assert_eq!(c.name(), "requests_total");
        assert_eq!(c.get(), 0);
    }

    #[test]
    fn counter_debug() {
        let c = Counter::new("ctr");
        c.add(42);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ctr"));
    }

    #[test]
    fn gauge_sub() {
        let g = Gauge::new("g");
        g.set(10);
        g.sub(3);
        assert_eq!(g.get(), 7);
    }

    #[test]
    fn gauge_name_debug() {
        let g = Gauge::new("active_conns");
        assert_eq!(g.name(), "active_conns");
        let dbg = format!("{g:?}");
        assert!(dbg.contains("active_conns"));
    }

    #[test]
    fn gauge_negative_values() {
        let g = Gauge::new("g");
        g.set(-5);
        assert_eq!(g.get(), -5);
        g.increment();
        assert_eq!(g.get(), -4);
    }

    #[test]
    fn histogram_name_debug() {
        let h = Histogram::new("latency", vec![0.1, 0.5, 1.0]);
        assert_eq!(h.name(), "latency");
        let dbg = format!("{h:?}");
        assert!(dbg.contains("latency"));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn summary_observe_and_quantiles() {
        let summary = Summary::new("request_size_bytes");
        summary.observe(10.0);
        summary.observe(20.0);
        summary.observe(40.0);
        summary.observe(80.0);
        summary.observe(160.0);

        assert_eq!(summary.name(), "request_size_bytes");
        assert_eq!(summary.count(), 5);
        assert_eq!(summary.sum(), 310.0);
        assert_eq!(summary.quantile(0.5), Some(40.0));
        assert_eq!(summary.quantile(0.9), Some(160.0));
        assert_eq!(summary.quantile(0.99), Some(160.0));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn histogram_empty() {
        let h = Histogram::new("h", vec![1.0, 5.0]);
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum(), 0.0);
    }

    #[test]
    fn histogram_bucket_sorting() {
        // Buckets given out of order should still work correctly
        let h = Histogram::new("h", vec![5.0, 1.0, 10.0]);
        h.observe(0.5); // should go in the <=1.0 bucket
        h.observe(3.0); // should go in the <=5.0 bucket
        h.observe(100.0); // should go in the +Inf bucket
        assert_eq!(h.count(), 3);
    }

    #[test]
    fn histogram_percentile_skips_empty_leading_buckets() {
        let h = Histogram::new("h", vec![1.0, 5.0, 10.0]);
        h.observe(6.0);

        assert_eq!(h.percentile(0.0), Some(10.0));
        assert_eq!(h.percentile(0.5), Some(10.0));
    }

    #[cfg(feature = "metrics")]
    #[test]
    #[allow(clippy::float_cmp)]
    fn histogram_metrics_feature_test_helpers_round_trip() {
        let h = Histogram::new("h", vec![5.0, 1.0, 10.0]);
        assert_eq!(h.bucket_boundaries(), &[1.0, 5.0, 10.0]);
        assert_eq!(h.bucket_counts(), vec![0, 0, 0, 0]);
        assert_eq!(h.mean(), 0.0);

        h.observe(0.5);
        h.observe(4.5);
        h.observe(20.0);
        assert_eq!(h.bucket_counts(), vec![1, 1, 0, 1]);
        assert_eq!(h.mean(), 25.0 / 3.0);

        h.reset();
        assert_eq!(h.count(), 0);
        assert_eq!(h.sum(), 0.0);
        assert_eq!(h.bucket_counts(), vec![0, 0, 0, 0]);
        assert_eq!(h.mean(), 0.0);
    }

    #[test]
    fn metric_value_debug_copy() {
        let c = MetricValue::Counter(42);
        let g = MetricValue::Gauge(-7);
        let h = MetricValue::Histogram(10, 2.75);

        let dbg_c = format!("{c:?}");
        assert!(dbg_c.contains("Counter"));
        assert!(dbg_c.contains("42"));

        let dbg_g = format!("{g:?}");
        assert!(dbg_g.contains("Gauge"));

        let dbg_h = format!("{h:?}");
        assert!(dbg_h.contains("Histogram"));

        // Copy
        let c2 = c;
        let _ = c; // original still usable
        let _ = c2;
    }

    #[test]
    fn metric_value_clone() {
        let v = MetricValue::Counter(99);
        let v2 = v;
        let _ = v; // Copy
        let _ = v2;
    }

    #[test]
    fn outcome_kind_debug_copy_eq_hash() {
        use std::collections::HashSet;

        let ok = OutcomeKind::Ok;
        let err = OutcomeKind::Err;
        let canc = OutcomeKind::Cancelled;
        let pan = OutcomeKind::Panicked;

        assert_ne!(ok, err);
        assert_ne!(canc, pan);
        assert_eq!(ok, OutcomeKind::Ok);

        let dbg = format!("{ok:?}");
        assert!(dbg.contains("Ok"));

        // Copy
        let ok2 = ok;
        assert_eq!(ok, ok2);

        // Hash
        let mut set = HashSet::new();
        set.insert(ok);
        set.insert(err);
        set.insert(canc);
        set.insert(pan);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn noop_metrics_debug_default_copy() {
        let m = NoOpMetrics;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("NoOpMetrics"));

        let m2 = NoOpMetrics;
        let _ = m2;

        // Copy
        let m3 = m;
        let _ = m;
        let _ = m3;

        // Clone
        let m4 = m;
        let _ = m4;
    }

    #[test]
    fn metrics_default_empty() {
        let m = Metrics::default();
        let export = m.export_prometheus();
        assert!(export.is_empty());
    }

    #[test]
    fn metrics_same_name_returns_same_counter() {
        let mut m = Metrics::new();
        let c1 = m.counter("x");
        c1.add(5);
        let c2 = m.counter("x");
        assert_eq!(c2.get(), 5); // same underlying counter
    }

    #[test]
    fn metrics_same_name_returns_same_gauge() {
        let mut m = Metrics::new();
        let g1 = m.gauge("y");
        g1.set(42);
        let g2 = m.gauge("y");
        assert_eq!(g2.get(), 42);
    }

    #[test]
    fn metrics_export_histogram() {
        let mut m = Metrics::new();
        let h = m.histogram("latency", vec![1.0, 5.0]);
        h.observe(0.5);
        h.observe(3.0);

        let output = m.export_prometheus();
        assert!(output.contains("latency_bucket"));
        assert!(output.contains("latency_sum"));
        assert!(output.contains("latency_count 2"));
    }

    #[test]
    fn metrics_export_prometheus_snapshot() {
        let mut metrics = Metrics::new();
        metrics.counter("requests_total").add(7);
        metrics.gauge("active_connections").set(3);
        let histogram = metrics.histogram("latency_seconds", vec![0.5, 1.0, 5.0]);
        histogram.observe(0.25);
        histogram.observe(0.75);
        histogram.observe(3.5);

        insta::assert_snapshot!(
            "metrics_export_prometheus_mixed_registry",
            metrics.export_prometheus()
        );
    }

    #[test]
    fn metrics_export_prometheus_full_registry_snapshot() {
        let mut metrics = Metrics::new();
        metrics.counter("requests_total").add(11);
        metrics.gauge("memory_usage_bytes").set(4096);

        let histogram = metrics.histogram("latency_seconds", vec![0.5, 1.0, 5.0]);
        histogram.observe(0.25);
        histogram.observe(0.75);
        histogram.observe(3.5);

        let summary = metrics.summary("request_size_bytes");
        for value in [128.0, 256.0, 512.0, 1024.0, 2048.0] {
            summary.observe(value);
        }

        insta::assert_snapshot!(
            "metrics_export_prometheus_full_registry",
            metrics.export_prometheus()
        );
    }

    fn sorted_metric_blocks_snapshot(rendered: &str) -> String {
        let mut blocks = Vec::new();
        let mut current = Vec::new();

        for line in rendered.lines() {
            if line.starts_with("# TYPE ") && !current.is_empty() {
                blocks.push(current.join("\n"));
                current.clear();
            }
            current.push(line);
        }

        if !current.is_empty() {
            blocks.push(current.join("\n"));
        }

        blocks.sort_unstable();
        let mut snapshot = blocks.join("\n");
        if !snapshot.is_empty() {
            snapshot.push('\n');
        }
        snapshot
    }

    #[test]
    fn metrics_export_prometheus_runtime_scheduler_region_snapshot() {
        let mut metrics = Metrics::new();

        metrics
            .counter("runtime_regions_total{state=\"open\"}")
            .add(3);
        metrics
            .counter("runtime_regions_total{state=\"closed\"}")
            .add(1);
        metrics
            .counter("scheduler_dispatch_total{lane=\"ready\",worker=\"primary\"}")
            .add(11);
        metrics
            .counter("scheduler_dispatch_total{lane=\"cancel\",worker=\"primary\"}")
            .add(2);

        metrics
            .gauge("scheduler_queue_depth{lane=\"ready\"}")
            .set(4);
        metrics
            .gauge("scheduler_queue_depth{lane=\"timed\"}")
            .set(1);
        metrics
            .gauge("region_live_tasks{region=\"root\",phase=\"draining\"}")
            .set(2);
        metrics
            .gauge("region_live_tasks{region=\"worker\",phase=\"steady\"}")
            .set(5);

        let histogram = metrics.histogram("runtime_poll_latency_seconds", vec![0.001, 0.01, 0.1]);
        for value in [0.0005, 0.004, 0.08] {
            histogram.observe(value);
        }

        insta::assert_snapshot!(
            "metrics_export_prometheus_runtime_scheduler_region",
            sorted_metric_blocks_snapshot(&metrics.export_prometheus())
        );
    }

    #[test]
    fn counter_metamorphic_fixed_schedule_never_decreases() {
        let counter = Counter::new("metamorphic_counter");
        let mut rng = crate::util::DetRng::new(0xC0FF_EE11);
        let mut expected_total = 0_u64;
        let mut previous = counter.get();

        for _ in 0..64 {
            let delta = (rng.next_u64() % 7) + 1;
            counter.add(delta);
            expected_total += delta;

            let current = counter.get();
            assert!(
                current >= previous,
                "counter must remain monotonic: previous={previous}, current={current}"
            );
            assert_eq!(
                current, expected_total,
                "counter should equal the cumulative sum of applied increments"
            );
            previous = current;
        }
    }

    #[test]
    fn counter_metamorphic_label_sum_matches_total() {
        let mut metrics = Metrics::new();
        let total = metrics.counter("requests_total");
        let ok = metrics.counter("requests_total{outcome=\"ok\"}");
        let err = metrics.counter("requests_total{outcome=\"err\"}");
        let cancelled = metrics.counter("requests_total{outcome=\"cancelled\"}");
        let mut rng = crate::util::DetRng::new(0x51A8_EE01);

        for _ in 0..48 {
            let delta = (rng.next_u64() % 5) + 1;
            match rng.next_u64() % 3 {
                0 => ok.add(delta),
                1 => err.add(delta),
                _ => cancelled.add(delta),
            }
            total.add(delta);

            let labeled_sum = ok.get() + err.get() + cancelled.get();
            assert_eq!(
                total.get(),
                labeled_sum,
                "sum across labeled counters should match the total counter"
            );
        }
    }

    #[test]
    fn counter_metamorphic_concurrent_schedule_matches_sequential() {
        let mut rng = crate::util::DetRng::new(0xF17E_D5E5);
        let mut workloads = Vec::new();
        let mut expected_total = 0_u64;

        for _ in 0..4 {
            let mut shard = Vec::new();
            for _ in 0..16 {
                let delta = (rng.next_u64() % 11) + 1;
                expected_total += delta;
                shard.push(delta);
            }
            workloads.push(shard);
        }

        let sequential = Counter::new("sequential_counter");
        for shard in &workloads {
            for &delta in shard {
                sequential.add(delta);
            }
        }

        let concurrent = std::sync::Arc::new(Counter::new("concurrent_counter"));
        let mut handles = Vec::new();
        for shard in workloads.clone() {
            let counter = std::sync::Arc::clone(&concurrent);
            handles.push(std::thread::spawn(move || {
                for delta in shard {
                    counter.add(delta);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("counter worker should not panic");
        }

        assert_eq!(
            sequential.get(),
            expected_total,
            "sequential replay should match the fixed workload sum"
        );
        assert_eq!(
            concurrent.get(),
            expected_total,
            "concurrent replay should preserve the same cumulative count semantics"
        );
        assert_eq!(
            concurrent.get(),
            sequential.get(),
            "concurrent and sequential application of the same schedule should agree"
        );
    }

    // =========================================================================
    // OpenTelemetry Exporter Implementation
    // =========================================================================

    /// OpenTelemetry metric descriptor.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct OtelMetricDescriptor {
        pub name: String,
        pub description: String,
        pub unit: String,
    }

    /// OpenTelemetry data point.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct OtelDataPoint {
        pub timestamp_nanos: u64,
        pub value: OtelValue,
        pub attributes: BTreeMap<String, String>,
    }

    /// OpenTelemetry metric value types.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum OtelValue {
        Counter(u64),
        Gauge(f64),
        Histogram {
            count: u64,
            sum: f64,
            buckets: Vec<(f64, u64)>, // (upper_bound, count)
        },
    }

    /// OpenTelemetry resource attributes.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct OtelResource {
        pub attributes: BTreeMap<String, String>,
    }

    /// OpenTelemetry metric export request.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct OtelMetricsRequest {
        pub resource: OtelResource,
        pub metrics: Vec<OtelMetric>,
    }

    /// OpenTelemetry metric.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct OtelMetric {
        pub descriptor: OtelMetricDescriptor,
        pub data_points: Vec<OtelDataPoint>,
    }

    /// Deterministic transport behavior for the test-only OTEL exporter harness.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub enum OtelTransportMode {
        /// Simulate successful collector delivery while recording the dispatch.
        #[default]
        CaptureSuccess,
        /// Simulate a network-level transport failure.
        FailNetwork(String),
        /// Simulate collector authentication failure.
        FailAuth,
        /// Simulate collector rate limiting.
        FailRateLimit,
    }

    /// OpenTelemetry exporter configuration.
    #[derive(Debug, Clone)]
    pub struct OtelExporterConfig {
        pub endpoint: String,
        pub api_key: Option<String>,
        pub timeout_secs: u64,
        pub compression: bool,
        pub batch_size: usize,
        pub transport_mode: OtelTransportMode,
    }

    impl Default for OtelExporterConfig {
        fn default() -> Self {
            Self {
                endpoint: "http://localhost:4317/v1/metrics".to_string(),
                api_key: None,
                timeout_secs: 10,
                compression: true,
                batch_size: 100,
                transport_mode: OtelTransportMode::CaptureSuccess,
            }
        }
    }

    /// Recorded request dispatch emitted by the OTEL exporter test harness.
    #[derive(Debug, Clone)]
    pub struct OtelDispatchRecord {
        pub endpoint: String,
        pub timeout_secs: u64,
        pub headers: BTreeMap<String, String>,
        pub body: Vec<u8>,
        pub serialized_json: String,
    }

    /// OpenTelemetry metrics exporter.
    #[derive(Debug)]
    pub struct OtelMetricsExporter {
        config: OtelExporterConfig,
        resource: OtelResource,
        dispatches: Mutex<Vec<OtelDispatchRecord>>,
    }

    impl OtelMetricsExporter {
        /// Creates a new OpenTelemetry exporter.
        pub fn new(config: OtelExporterConfig) -> Self {
            let mut resource_attrs = BTreeMap::new();
            resource_attrs.insert("service.name".to_string(), "asupersync".to_string());
            resource_attrs.insert(
                "service.version".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            );

            Self {
                config,
                resource: OtelResource {
                    attributes: resource_attrs,
                },
                dispatches: Mutex::new(Vec::new()),
            }
        }

        /// Exports metrics to OpenTelemetry collector.
        pub async fn export(&self, metrics: &Metrics) -> Result<(), OtelExportError> {
            let request = self.build_request(metrics)?;
            self.send_request(&request).await
        }

        fn serialize_request(request: &OtelMetricsRequest) -> Result<String, OtelExportError> {
            serde_json::to_string(request)
                .map_err(|err| OtelExportError::InvalidData(err.to_string()))
        }

        /// Builds OTLP request from metrics registry.
        fn build_request(&self, metrics: &Metrics) -> Result<OtelMetricsRequest, OtelExportError> {
            let mut otel_metrics = Vec::new();
            let timestamp = crate::observability::replayable_system_time()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| OtelExportError::TimestampError)?
                .as_nanos() as u64;

            // Export counters
            for (name, counter) in &metrics.counters {
                let metric = OtelMetric {
                    descriptor: OtelMetricDescriptor {
                        name: name.clone(),
                        description: format!("Counter: {name}"),
                        unit: "1".to_string(),
                    },
                    data_points: vec![OtelDataPoint {
                        timestamp_nanos: timestamp,
                        value: OtelValue::Counter(counter.get()),
                        attributes: BTreeMap::new(),
                    }],
                };
                otel_metrics.push(metric);
            }

            // Export gauges
            for (name, gauge) in &metrics.gauges {
                let metric = OtelMetric {
                    descriptor: OtelMetricDescriptor {
                        name: name.clone(),
                        description: format!("Gauge: {name}"),
                        unit: "1".to_string(),
                    },
                    data_points: vec![OtelDataPoint {
                        timestamp_nanos: timestamp,
                        value: OtelValue::Gauge(gauge.get() as f64),
                        attributes: BTreeMap::new(),
                    }],
                };
                otel_metrics.push(metric);
            }

            // Export histograms
            for (name, histogram) in &metrics.histograms {
                let mut buckets = Vec::new();
                let mut cumulative = 0;

                for (i, count_atomic) in histogram.counts.iter().enumerate() {
                    let count = count_atomic.load(Ordering::Relaxed);
                    cumulative += count;
                    let upper_bound = if i < histogram.buckets.len() {
                        histogram.buckets[i]
                    } else {
                        f64::INFINITY
                    };
                    buckets.push((upper_bound, cumulative));
                }

                let metric = OtelMetric {
                    descriptor: OtelMetricDescriptor {
                        name: name.clone(),
                        description: format!("Histogram: {name}"),
                        unit: "s".to_string(),
                    },
                    data_points: vec![OtelDataPoint {
                        timestamp_nanos: timestamp,
                        value: OtelValue::Histogram {
                            count: histogram.count(),
                            sum: histogram.sum(),
                            buckets,
                        },
                        attributes: BTreeMap::new(),
                    }],
                };
                otel_metrics.push(metric);
            }

            Ok(OtelMetricsRequest {
                resource: self.resource.clone(),
                metrics: otel_metrics,
            })
        }

        /// Returns the recorded dispatches performed by this test harness.
        fn dispatches(&self) -> Vec<OtelDispatchRecord> {
            self.dispatches
                .lock()
                .expect("dispatches mutex poisoned")
                .clone()
        }

        /// Sends request to the deterministic OTEL collector test harness.
        async fn send_request(&self, request: &OtelMetricsRequest) -> Result<(), OtelExportError> {
            use std::io::Write;

            let serialized_json = Self::serialize_request(request)?;
            let mut headers = BTreeMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            if let Some(api_key) = &self.config.api_key {
                headers.insert("authorization".to_string(), format!("Bearer {api_key}"));
            }

            let body = if self.config.compression {
                use flate2::Compression;
                use flate2::write::GzEncoder;

                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder
                    .write_all(serialized_json.as_bytes())
                    .map_err(|err| OtelExportError::NetworkError(err.to_string()))?;
                headers.insert("content-encoding".to_string(), "gzip".to_string());
                encoder
                    .finish()
                    .map_err(|err| OtelExportError::NetworkError(err.to_string()))?
            } else {
                serialized_json.as_bytes().to_vec()
            };

            self.dispatches
                .lock()
                .expect("dispatches mutex poisoned")
                .push(OtelDispatchRecord {
                    endpoint: self.config.endpoint.clone(),
                    timeout_secs: self.config.timeout_secs,
                    headers,
                    body,
                    serialized_json,
                });

            match &self.config.transport_mode {
                OtelTransportMode::CaptureSuccess => Ok(()),
                OtelTransportMode::FailNetwork(message) => {
                    Err(OtelExportError::NetworkError(message.clone()))
                }
                OtelTransportMode::FailAuth => Err(OtelExportError::AuthError),
                OtelTransportMode::FailRateLimit => Err(OtelExportError::RateLimited),
            }
        }
    }

    /// Errors that can occur during OpenTelemetry export.
    #[derive(Debug, Clone)]
    pub enum OtelExportError {
        /// Failed to get system timestamp.
        TimestampError,
        /// Network or HTTP error.
        NetworkError(String),
        /// Authentication error.
        AuthError,
        /// Rate limited by collector.
        RateLimited,
        /// Invalid metric data.
        InvalidData(String),
    }

    impl std::fmt::Display for OtelExportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::TimestampError => write!(f, "Failed to get system timestamp"),
                Self::NetworkError(msg) => write!(f, "Network error: {msg}"),
                Self::AuthError => write!(f, "Authentication failed"),
                Self::RateLimited => write!(f, "Rate limited"),
                Self::InvalidData(msg) => write!(f, "Invalid metric data: {msg}"),
            }
        }
    }

    impl std::error::Error for OtelExportError {}

    // =========================================================================
    // OpenTelemetry Conformance Tests (CONF-OTEL)
    // =========================================================================

    /// CONF-OTEL-001: Resource Attribution Conformance
    /// Metrics must include proper resource attributes according to OTLP spec
    #[test]
    fn conf_otel_resource_attribution() {
        let config = OtelExporterConfig::default();
        let exporter = OtelMetricsExporter::new(config);

        // Verify required resource attributes are present
        assert!(exporter.resource.attributes.contains_key("service.name"));
        assert!(exporter.resource.attributes.contains_key("service.version"));

        let service_name = exporter.resource.attributes.get("service.name").unwrap();
        assert_eq!(service_name, "asupersync");

        let version = exporter.resource.attributes.get("service.version").unwrap();
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    /// CONF-OTEL-002: Metric Descriptor Conformance
    /// Metric descriptors must follow OpenTelemetry naming and structure conventions
    #[test]
    fn conf_otel_metric_descriptor_conformance() {
        let config = OtelExporterConfig::default();
        let exporter = OtelMetricsExporter::new(config);

        let mut metrics = Metrics::new();
        metrics.counter("http_requests_total").add(100);
        metrics.gauge("memory_usage_bytes").set(1024);
        metrics
            .histogram("request_duration_seconds", vec![0.1, 0.5, 1.0])
            .observe(0.25);

        let request = exporter
            .build_request(&metrics)
            .expect("build_request failed");

        // Verify metric descriptor structure
        assert_eq!(request.metrics.len(), 3);

        // Check counter descriptor
        let counter_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "http_requests_total")
            .expect("counter metric not found");
        assert!(!counter_metric.descriptor.name.is_empty());
        assert!(!counter_metric.descriptor.description.is_empty());
        assert_eq!(counter_metric.descriptor.unit, "1");

        // Check gauge descriptor
        let gauge_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "memory_usage_bytes")
            .expect("gauge metric not found");
        assert!(gauge_metric.descriptor.description.contains("Gauge"));

        // Check histogram descriptor
        let hist_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "request_duration_seconds")
            .expect("histogram metric not found");
        assert_eq!(hist_metric.descriptor.unit, "s");
    }

    /// CONF-OTEL-003: Data Point Structure Conformance
    /// Data points must have proper timestamp, value, and attributes structure
    #[test]
    fn conf_otel_data_point_structure() {
        let config = OtelExporterConfig::default();
        let exporter = OtelMetricsExporter::new(config);

        let mut metrics = Metrics::new();
        metrics.counter("test_counter").add(42);

        let request = exporter
            .build_request(&metrics)
            .expect("build_request failed");
        let metric = &request.metrics[0];
        let data_point = &metric.data_points[0];

        // Verify timestamp is present and reasonable
        assert!(data_point.timestamp_nanos > 0);
        assert!(data_point.timestamp_nanos < u64::MAX);

        // Verify value structure
        match &data_point.value {
            OtelValue::Counter(value) => assert_eq!(*value, 42),
            _ => panic!("Expected Counter value"),
        }

        // Verify attributes structure exists (even if empty)
        assert!(data_point.attributes.is_empty()); // No custom attributes set
    }

    /// CONF-OTEL-004: Aggregation Temporality Conformance
    /// Different metric types must have correct aggregation semantics
    #[test]
    fn conf_otel_aggregation_temporality() {
        let config = OtelExporterConfig::default();
        let exporter = OtelMetricsExporter::new(config);

        let mut metrics = Metrics::new();

        // Counters are cumulative (monotonic)
        let counter = metrics.counter("requests");
        counter.add(10);
        counter.add(5); // Should be cumulative: 15

        // Gauges are instantaneous
        let gauge = metrics.gauge("cpu_usage");
        gauge.set(50);
        gauge.set(75); // Should overwrite: 75

        // Histograms are cumulative distributions
        let hist = metrics.histogram("latencies", vec![0.1, 1.0]);
        hist.observe(0.05);
        hist.observe(0.5);
        hist.observe(2.0);

        let request = exporter
            .build_request(&metrics)
            .expect("build_request failed");

        // Verify counter semantics
        let counter_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "requests")
            .expect("counter not found");
        if let OtelValue::Counter(value) = counter_metric.data_points[0].value {
            assert_eq!(value, 15); // Cumulative
        }

        // Verify gauge semantics
        let gauge_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "cpu_usage")
            .expect("gauge not found");
        if let OtelValue::Gauge(value) = gauge_metric.data_points[0].value {
            assert_eq!(value, 75.0); // Latest value
        }

        // Verify histogram semantics
        let hist_metric = request
            .metrics
            .iter()
            .find(|m| m.descriptor.name == "latencies")
            .expect("histogram not found");
        if let OtelValue::Histogram {
            count,
            sum,
            buckets,
        } = &hist_metric.data_points[0].value
        {
            assert_eq!(*count, 3); // Total observations
            assert!(*sum > 2.5); // Sum of all values
            assert!(!buckets.is_empty()); // Bucket distribution
        }
    }

    /// CONF-OTEL-005: Batch Export Conformance
    /// Multiple metrics must be exportable in a single request
    #[test]
    fn conf_otel_batch_export_conformance() {
        let config = OtelExporterConfig {
            batch_size: 100,
            ..Default::default()
        };
        let exporter = OtelMetricsExporter::new(config);

        let mut metrics = Metrics::new();

        // Create multiple metrics of different types
        for i in 0..5 {
            metrics.counter(&format!("counter_{i}")).add(i as u64 * 10);
            metrics.gauge(&format!("gauge_{i}")).set(i as i64);
            metrics
                .histogram(&format!("hist_{i}"), vec![1.0, 10.0])
                .observe(i as f64);
        }

        let request = exporter
            .build_request(&metrics)
            .expect("build_request failed");

        // Verify all metrics are in single request
        assert_eq!(request.metrics.len(), 15); // 5 * 3 types

        // Verify request has single resource attribution
        assert!(!request.resource.attributes.is_empty());

        // Verify batch contains metrics of different types
        let counter_count = request
            .metrics
            .iter()
            .filter(|m| m.descriptor.name.starts_with("counter_"))
            .count();
        let gauge_count = request
            .metrics
            .iter()
            .filter(|m| m.descriptor.name.starts_with("gauge_"))
            .count();
        let hist_count = request
            .metrics
            .iter()
            .filter(|m| m.descriptor.name.starts_with("hist_"))
            .count();

        assert_eq!(counter_count, 5);
        assert_eq!(gauge_count, 5);
        assert_eq!(hist_count, 5);
    }

    /// CONF-OTEL-006: Configuration Validation Conformance
    /// Exporter configuration must validate required fields and defaults
    #[test]
    fn conf_otel_configuration_validation() {
        // Test default configuration
        let default_config = OtelExporterConfig::default();
        assert!(!default_config.endpoint.is_empty());
        assert!(default_config.endpoint.contains("http"));
        assert!(default_config.endpoint.contains("4317")); // OTLP standard port
        assert!(default_config.endpoint.contains("/v1/metrics")); // Standard path
        assert!(default_config.timeout_secs > 0);
        assert!(default_config.batch_size > 0);

        // Test custom configuration
        let custom_config = OtelExporterConfig {
            endpoint: "https://otel-collector.example.com/v1/metrics".to_string(),
            api_key: Some("secret_key_123".to_string()),
            timeout_secs: 30,
            compression: false,
            batch_size: 50,
            transport_mode: OtelTransportMode::CaptureSuccess,
        };

        let exporter = OtelMetricsExporter::new(custom_config.clone());
        assert_eq!(exporter.config.endpoint, custom_config.endpoint);
        assert_eq!(exporter.config.api_key, custom_config.api_key);
        assert_eq!(exporter.config.timeout_secs, 30);
        assert!(!exporter.config.compression);
        assert_eq!(exporter.config.batch_size, 50);
        assert_eq!(exporter.config.transport_mode, custom_config.transport_mode);
    }

    /// CONF-OTEL-007: Error Handling Conformance
    /// Exporter must handle various error conditions properly
    #[test]
    fn conf_otel_error_handling_conformance() {
        // Test error types are properly categorized
        let errors = vec![
            OtelExportError::TimestampError,
            OtelExportError::NetworkError("connection timeout".to_string()),
            OtelExportError::AuthError,
            OtelExportError::RateLimited,
            OtelExportError::InvalidData("malformed metric name".to_string()),
        ];

        for error in errors {
            // All errors must implement Display and Error traits
            let display_str = format!("{error}");
            assert!(!display_str.is_empty());

            // Error must be Debug-able for logging
            let debug_str = format!("{error:?}");
            assert!(!debug_str.is_empty());
        }

        // Test specific error messages
        let net_err = OtelExportError::NetworkError("timeout".to_string());
        assert!(format!("{net_err}").contains("Network error"));
        assert!(format!("{net_err}").contains("timeout"));

        let data_err = OtelExportError::InvalidData("bad name".to_string());
        assert!(format!("{data_err}").contains("Invalid metric data"));
        assert!(format!("{data_err}").contains("bad name"));
    }

    /// CONF-OTEL-008: Histogram Bucket Conformance
    /// Histogram buckets must follow OpenTelemetry cumulative distribution requirements
    #[test]
    fn conf_otel_histogram_bucket_conformance() {
        let config = OtelExporterConfig::default();
        let exporter = OtelMetricsExporter::new(config);

        let mut metrics = Metrics::new();
        let hist = metrics.histogram("response_times", vec![0.1, 0.5, 1.0, 5.0]);

        // Observe values across different buckets
        hist.observe(0.05); // bucket 0 (<=0.1)
        hist.observe(0.3); // bucket 1 (<=0.5)
        hist.observe(0.8); // bucket 2 (<=1.0)
        hist.observe(2.0); // bucket 3 (<=5.0)
        hist.observe(10.0); // bucket 4 (+Inf)

        let request = exporter
            .build_request(&metrics)
            .expect("build_request failed");
        let hist_metric = &request.metrics[0];

        if let OtelValue::Histogram {
            count,
            sum,
            buckets,
        } = &hist_metric.data_points[0].value
        {
            assert_eq!(*count, 5);
            assert!((*sum - 13.15).abs() < 0.01); // 0.05+0.3+0.8+2.0+10.0

            // Verify buckets are cumulative and properly bounded
            assert_eq!(buckets.len(), 5); // 4 explicit buckets + +Inf

            // Verify cumulative property: each bucket >= previous
            for i in 1..buckets.len() {
                assert!(
                    buckets[i].1 >= buckets[i - 1].1,
                    "Bucket {i} count {} should be >= previous bucket count {}",
                    buckets[i].1,
                    buckets[i - 1].1
                );
            }

            // Verify final bucket has all observations
            assert_eq!(buckets.last().unwrap().1, 5);

            // Verify +Inf bucket
            assert_eq!(buckets.last().unwrap().0, f64::INFINITY);
        } else {
            panic!("Expected Histogram value");
        }
    }

    #[test]
    fn conf_otel_serialized_request_structure_is_deterministic() {
        let request = OtelMetricsRequest {
            resource: OtelResource {
                attributes: BTreeMap::from([
                    ("service.name".to_string(), "asupersync".to_string()),
                    ("service.version".to_string(), "0.3.1-test".to_string()),
                ]),
            },
            metrics: vec![OtelMetric {
                descriptor: OtelMetricDescriptor {
                    name: "requests_total".to_string(),
                    description: "Counter: requests_total".to_string(),
                    unit: "1".to_string(),
                },
                data_points: vec![OtelDataPoint {
                    timestamp_nanos: 123,
                    value: OtelValue::Counter(7),
                    attributes: BTreeMap::new(),
                }],
            }],
        };

        let serialized =
            OtelMetricsExporter::serialize_request(&request).expect("serialize_request failed");
        assert_eq!(
            serialized,
            "{\"resource\":{\"attributes\":{\"service.name\":\"asupersync\",\"service.version\":\"0.3.1-test\"}},\"metrics\":[{\"descriptor\":{\"name\":\"requests_total\",\"description\":\"Counter: requests_total\",\"unit\":\"1\"},\"data_points\":[{\"timestamp_nanos\":123,\"value\":{\"Counter\":7},\"attributes\":{}}]}]}"
        );
    }

    #[test]
    fn conf_otel_export_dispatch_records_headers_and_body() {
        use flate2::read::GzDecoder;
        use futures_lite::future::block_on;
        use std::io::Read;

        let config = OtelExporterConfig {
            endpoint: "http://collector.test/v1/metrics".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_secs: 3,
            compression: true,
            batch_size: 16,
            transport_mode: OtelTransportMode::CaptureSuccess,
        };
        let exporter = OtelMetricsExporter::new(config);
        let mut metrics = Metrics::new();
        metrics.counter("requests_total").add(7);

        block_on(exporter.export(&metrics)).expect("export should succeed");

        let dispatches = exporter.dispatches();
        assert_eq!(dispatches.len(), 1);
        let dispatch = &dispatches[0];
        assert_eq!(dispatch.endpoint, "http://collector.test/v1/metrics");
        assert_eq!(dispatch.timeout_secs, 3);
        assert_eq!(
            dispatch.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            dispatch.headers.get("authorization").map(String::as_str),
            Some("Bearer test-key")
        );
        assert_eq!(
            dispatch.headers.get("content-encoding").map(String::as_str),
            Some("gzip")
        );

        let mut decoder = GzDecoder::new(dispatch.body.as_slice());
        let mut decompressed = String::new();
        decoder
            .read_to_string(&mut decompressed)
            .expect("gzip body should decode");
        assert_eq!(decompressed, dispatch.serialized_json);
        assert!(dispatch.serialized_json.contains("\"requests_total\""));
    }

    #[test]
    fn conf_otel_export_transport_errors_are_not_silent() {
        use futures_lite::future::block_on;

        let cases = [
            (
                OtelTransportMode::FailNetwork("socket closed".to_string()),
                OtelExportError::NetworkError("socket closed".to_string()),
            ),
            (OtelTransportMode::FailAuth, OtelExportError::AuthError),
            (
                OtelTransportMode::FailRateLimit,
                OtelExportError::RateLimited,
            ),
        ];

        for (transport_mode, expected) in cases {
            let config = OtelExporterConfig {
                transport_mode,
                compression: false,
                ..Default::default()
            };
            let exporter = OtelMetricsExporter::new(config);
            let mut metrics = Metrics::new();
            metrics.counter("requests_total").increment();

            let err = block_on(exporter.export(&metrics)).expect_err("export should fail");
            match (err, expected) {
                (
                    OtelExportError::NetworkError(actual),
                    OtelExportError::NetworkError(expected),
                ) => {
                    assert_eq!(actual, expected);
                }
                (OtelExportError::AuthError, OtelExportError::AuthError)
                | (OtelExportError::RateLimited, OtelExportError::RateLimited) => {}
                (actual, expected) => {
                    panic!("unexpected transport error: got {actual:?}, expected {expected:?}")
                }
            }

            assert_eq!(
                exporter.dispatches().len(),
                1,
                "failed dispatches should still be recorded for deterministic verification"
            );
        }
    }

    #[test]
    fn metrics_export_prometheus_exposition_format_compliance_snapshot() {
        let mut metrics = Metrics::new();

        // Test comprehensive Prometheus exposition format compliance
        // including edge cases, special values, and format requirements

        // Counters with various values
        metrics.counter("http_requests_total").add(0); // Zero value
        metrics.counter("bytes_processed_total").add(u64::MAX); // Max value
        metrics.counter("errors_total{status=\"404\"}").add(42); // With labels
        metrics
            .counter("requests_with_underscore_name_total")
            .add(123); // Underscore in name

        // Gauges with various values including negatives
        metrics.gauge("temperature_celsius").set(-273); // Negative value
        metrics.gauge("memory_usage_bytes").set(0); // Zero gauge
        metrics.gauge("cpu_usage_percent{cpu=\"0\"}").set(99); // With labels
        metrics.gauge("queue_depth").set(i64::MAX); // Max positive value
        metrics.gauge("offset_microseconds").set(i64::MIN); // Min negative value

        // Histograms with comprehensive bucket testing
        let response_time_hist = metrics.histogram(
            "http_request_duration_seconds",
            vec![0.001, 0.01, 0.1, 1.0, 10.0],
        );
        response_time_hist.observe(0.0005); // Below first bucket
        response_time_hist.observe(0.005); // Between buckets
        response_time_hist.observe(0.05); // Between buckets
        response_time_hist.observe(0.5); // Between buckets
        response_time_hist.observe(5.0); // Between buckets
        response_time_hist.observe(50.0); // Above all buckets (+Inf)

        let size_hist = metrics.histogram(
            "request_size_bytes{endpoint=\"/api/v1/data\"}",
            vec![100.0, 1000.0, 10000.0],
        );
        size_hist.observe(0.0); // Zero value
        size_hist.observe(50.0); // First bucket
        size_hist.observe(500.0); // Middle bucket
        size_hist.observe(5000.0); // Third bucket
        size_hist.observe(100000.0); // +Inf bucket

        // Summaries with comprehensive quantile testing
        let latency_summary = metrics.summary("response_latency_summary");
        for &value in &[1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0] {
            latency_summary.observe(value);
        }

        let throughput_summary = metrics.summary("throughput_ops_per_second{worker=\"primary\"}");
        // Edge case: single observation
        throughput_summary.observe(1000.0);

        let _empty_summary = metrics.summary("empty_metric_summary");
        // Edge case: no observations (should still export with 0 values)

        // Special metric names testing edge cases
        metrics.counter("metric_with_1234_numbers").add(1);
        metrics.gauge("CamelCaseMetric").set(42); // Non-standard but valid
        metrics.counter("metric.with.dots").add(7); // Dots in name

        insta::assert_snapshot!(
            "metrics_export_prometheus_exposition_format_compliance",
            metrics.export_prometheus()
        );
    }

    // ===================================================================
    // br-asupersync-aog3fz: exposition-format injection tests for the
    // metric-name / label-name / label-value sanitizers introduced to
    // close the Prometheus exposition-format injection vector.
    // ===================================================================

    #[test]
    fn aog3fz_metric_name_injection_via_newlines_sanitized() {
        // A caller (or untrusted upstream that names metrics from user
        // input) attempts to forge an extra metric line by smuggling
        // \n + a complete fake exposition record into the metric name.
        let mut metrics = Metrics::new();
        let crafted = "real_metric\n# TYPE forged_metric counter\nforged_metric 999";
        metrics.counter(crafted).add(1);
        let exported = metrics.export_prometheus();
        // The sanitized output must NOT contain the forged line — every
        // newline-and-control-character in the crafted name was replaced
        // with `_`, so the only `\n` chars left are the legitimate
        // line-terminators that writeln! emits between the # TYPE and
        // value lines for a single metric.
        assert!(
            !exported.contains("forged_metric 999"),
            "injection bypassed sanitization: {exported}"
        );
        assert!(
            !exported.contains("# TYPE forged_metric counter"),
            "injection bypassed sanitization: {exported}"
        );
        // The legitimate metric is still emitted with a sanitized name
        // — every `\n`, `#`, ` `, `\t` is replaced with `_`.
        assert!(
            exported.contains("real_metric_"),
            "expected sanitized real_metric_ prefix in: {exported}"
        );
    }

    #[test]
    fn aog3fz_metric_name_with_curly_brace_injection_sanitized() {
        // Smuggle fake labels by closing the metric name with `{` and
        // injecting a label clause before the value.
        let mut metrics = Metrics::new();
        metrics.counter("evil{job=\"hacker\"}").add(1);
        let exported = metrics.export_prometheus();
        assert!(
            !exported.contains("evil{job=\"hacker\"}"),
            "raw injected name leaked: {exported}"
        );
        // Sanitized form: { = " and } all become _.
        assert!(
            exported.contains("evil_job__hacker__"),
            "expected sanitized form in: {exported}"
        );
    }

    #[test]
    fn aog3fz_sanitize_metric_name_first_char_constraints() {
        // First char must be in `[a-zA-Z_:]`. Digits and other punctuation
        // get rewritten to `_`.
        assert_eq!(
            sanitize_prometheus_metric_name("0bad").as_deref(),
            Some("_bad")
        );
        assert_eq!(
            sanitize_prometheus_metric_name("-bad").as_deref(),
            Some("_bad")
        );
        assert_eq!(
            sanitize_prometheus_metric_name(":valid").as_deref(),
            Some(":valid")
        );
        assert_eq!(
            sanitize_prometheus_metric_name("_valid").as_deref(),
            Some("_valid")
        );
        assert_eq!(
            sanitize_prometheus_metric_name("Valid").as_deref(),
            Some("Valid")
        );
    }

    #[test]
    fn aog3fz_sanitize_metric_name_continuation_constraints() {
        assert_eq!(
            sanitize_prometheus_metric_name("a:b_c").as_deref(),
            Some("a:b_c")
        );
        assert_eq!(
            sanitize_prometheus_metric_name("a-b.c d").as_deref(),
            Some("a_b_c_d")
        );
        assert_eq!(
            sanitize_prometheus_metric_name("a\nb").as_deref(),
            Some("a_b")
        );
        // Tabs, CR, NUL, all sanitized.
        assert_eq!(
            sanitize_prometheus_metric_name("a\tb\rc\0d").as_deref(),
            Some("a_b_c_d")
        );
    }

    #[test]
    fn aog3fz_sanitize_metric_name_empty_returns_none() {
        assert_eq!(sanitize_prometheus_metric_name(""), None);
    }

    #[test]
    fn aog3fz_sanitize_label_name_excludes_colon() {
        // Label names per spec are `[a-zA-Z_][a-zA-Z0-9_]*` — `:` is
        // reserved for metric names and must NOT be allowed in labels.
        assert_eq!(
            sanitize_prometheus_label_name("a:b").as_deref(),
            Some("a_b")
        );
        assert_eq!(
            sanitize_prometheus_label_name(":start").as_deref(),
            Some("_start")
        );
        assert_eq!(
            sanitize_prometheus_label_name("0digit").as_deref(),
            Some("_digit")
        );
        assert_eq!(
            sanitize_prometheus_label_name("valid_name").as_deref(),
            Some("valid_name")
        );
        assert_eq!(sanitize_prometheus_label_name(""), None);
    }

    #[test]
    fn aog3fz_escape_label_value_handles_all_three_specials() {
        // Per spec: \ → \\, \n → \n, " → \".
        assert_eq!(escape_prometheus_label_value("plain"), "plain");
        assert_eq!(escape_prometheus_label_value(r"a\b"), r"a\\b");
        assert_eq!(escape_prometheus_label_value("a\nb"), r"a\nb");
        assert_eq!(escape_prometheus_label_value(r#"a"b"#), r#"a\"b"#);
        // All three combined plus passthrough of other UTF-8.
        assert_eq!(
            escape_prometheus_label_value("a\\b\nc\"d e"),
            r#"a\\b\nc\"d e"#
        );
        // Carriage return, tab, NUL pass through (spec only requires
        // escaping the three above; other control bytes are a Prometheus
        // text-format peculiarity but do not break the parser).
        assert_eq!(escape_prometheus_label_value("a\tb"), "a\tb");
    }

    #[test]
    fn aog3fz_export_prometheus_output_has_no_control_characters() {
        // Strong invariant: after sanitization, every byte of the
        // output is either ASCII-printable, a single `\n` line break,
        // or a space. This is the security property that defeats
        // injection: the output is structurally constrained regardless
        // of input.
        let mut metrics = Metrics::new();
        metrics.counter("evil\n{}\"\\\r\t\0").add(1);
        metrics.gauge("\x07ring\x08").set(1);
        metrics
            .histogram("\x1b[31mansi\x1b[0m", vec![1.0])
            .observe(0.5);
        let exported = metrics.export_prometheus();
        for b in exported.bytes() {
            assert!(
                b == b'\n' || (b'\x20'..=b'\x7e').contains(&b),
                "control byte {b:#04x} in exported output: {exported:?}"
            );
        }
    }
}
