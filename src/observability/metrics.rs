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
    state_lock: Mutex<()>,
}

/// Point-in-time view of a [`Histogram`].
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramSnapshot {
    /// Histogram metric name.
    pub name: String,
    /// Sorted explicit bucket upper bounds. The implicit final bucket is `+Inf`.
    pub bucket_boundaries: Vec<f64>,
    /// Per-bucket observation counts, including the final `+Inf` bucket.
    pub bucket_counts: Vec<u64>,
    /// Total number of observations.
    pub count: u64,
    /// Sum of all observed values.
    pub sum: f64,
}

impl Histogram {
    pub(crate) fn new(name: impl Into<String>, buckets: Vec<f64>) -> Self {
        let mut buckets = buckets;
        buckets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        // Deduplicate boundaries: after sorting, equal boundaries are adjacent.
        // A duplicate boundary would emit two `_bucket{le="x"}` series with the
        // same `le`, which Prometheus rejects (duplicate series), poisoning the
        // whole scrape. (NaN boundaries are caller error and left as-is.)
        buckets.dedup();
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
            state_lock: Mutex::new(()),
        }
    }

    /// Observes a value.
    pub fn observe(&self, value: f64) {
        // Reject non-finite observations up front. Counting a NaN/Inf while the
        // sum-update below freezes the sum (its old `is_finite` guard) would
        // permanently desync `sum` from `count` and corrupt the derived mean.
        if !value.is_finite() {
            return;
        }
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
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
            // `value` is finite (guarded at fn entry), so `new_f64` is finite
            // or a saturated ±inf on overflow — never NaN. Record it rather
            // than freezing the sum, which would break the sum<->count
            // invariant (count already incremented above).
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
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        self.count.load(Ordering::Relaxed)
    }

    /// Returns the sum of observations.
    pub fn sum(&self) -> f64 {
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        f64::from_bits(self.sum.load(Ordering::Relaxed))
    }

    /// Returns the histogram name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a point-in-time snapshot for conformance and export checks.
    #[must_use]
    pub fn snapshot(&self) -> HistogramSnapshot {
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        HistogramSnapshot {
            name: self.name.clone(),
            bucket_boundaries: self.buckets.clone(),
            bucket_counts: self
                .counts
                .iter()
                .map(|atomic| atomic.load(Ordering::Relaxed))
                .collect(),
            count: self.count.load(Ordering::Relaxed),
            sum: f64::from_bits(self.sum.load(Ordering::Relaxed)),
        }
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn bucket_counts(&self) -> Vec<u64> {
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        self.counts
            .iter()
            .map(|atomic| atomic.load(Ordering::Relaxed))
            .collect()
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn reset(&self) {
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
        self.count.store(0, Ordering::Relaxed);
        self.sum.store(0.0f64.to_bits(), Ordering::Relaxed);
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn mean(&self) -> f64 {
        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        let total_count = self.count.load(Ordering::Relaxed);
        if total_count == 0 {
            0.0
        } else {
            f64::from_bits(self.sum.load(Ordering::Relaxed)) / (total_count as f64)
        }
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn bucket_boundaries(&self) -> &[f64] {
        &self.buckets
    }

    #[cfg(test)]
    pub(crate) fn percentile(&self, p: f64) -> Option<f64> {
        if !(0.0..=1.0).contains(&p) {
            return None;
        }

        let _guard = self
            .state_lock
            .lock()
            .expect("histogram state mutex poisoned");
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }

        let target_rank = if p == 0.0 {
            1
        } else {
            let rank_f64 = (total as f64) * p;
            // Safely handle potential overflow in f64->u64 conversion
            if rank_f64.is_finite() && rank_f64 <= (u64::MAX as f64) {
                rank_f64.ceil() as u64
            } else {
                total // Fallback to total count if calculation overflows
            }
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
    samples: Mutex<SummarySamples>,
    sum: AtomicU64, // Stored as bits of f64
    count: AtomicU64,
}

/// Maximum retained observations per summary for quantile estimation.
///
/// `count` and `sum` remain exact for all observations; only the quantile
/// sample is bounded so a hot summary cannot grow memory or scrape work
/// without limit.
const SUMMARY_SAMPLE_CAP: usize = 4096;

#[derive(Debug)]
struct SummarySamples {
    values: Vec<f64>,
    next: usize,
}

impl SummarySamples {
    fn new() -> Self {
        Self {
            values: Vec::with_capacity(SUMMARY_SAMPLE_CAP),
            next: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        if self.values.len() < SUMMARY_SAMPLE_CAP {
            self.values.push(value);
            return;
        }

        self.values[self.next] = value;
        self.next = (self.next + 1) % SUMMARY_SAMPLE_CAP;
    }

    fn snapshot(&self) -> Vec<f64> {
        self.values.clone()
    }

    fn len(&self) -> usize {
        self.values.len()
    }
}

impl Summary {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            samples: Mutex::new(SummarySamples::new()),
            sum: AtomicU64::new(0.0f64.to_bits()),
            count: AtomicU64::new(0),
        }
    }

    /// Observes a value.
    pub fn observe(&self, value: f64) {
        // Reject non-finite observations (see `Histogram::observe`): counting
        // them while the sum freezes would desync `sum` from `count`.
        if !value.is_finite() {
            return;
        }
        self.samples
            .lock()
            .expect("summary samples mutex poisoned")
            .observe(value);
        self.count.fetch_add(1, Ordering::Relaxed);

        let mut current = self.sum.load(Ordering::Relaxed);
        loop {
            let current_f64 = f64::from_bits(current);
            let new_f64 = current_f64 + value;
            // `value` is finite (guarded at fn entry), so `new_f64` is finite
            // or a saturated ±inf on overflow — never NaN. Record it rather
            // than freezing the sum, which would break the sum<->count
            // invariant (count already incremented above).
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

    /// Returns the number of observations retained for quantile estimation.
    #[must_use]
    pub fn retained_sample_count(&self) -> usize {
        self.samples
            .lock()
            .expect("summary samples mutex poisoned")
            .len()
    }

    /// Returns the maximum number of retained quantile observations.
    #[must_use]
    pub const fn retained_sample_capacity() -> usize {
        SUMMARY_SAMPLE_CAP
    }

    /// Returns an exact quantile from the observed values.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if !(0.0..=1.0).contains(&q) {
            return None;
        }

        let mut values = self
            .samples
            .lock()
            .expect("summary samples mutex poisoned")
            .snapshot();
        if values.is_empty() {
            return None;
        }

        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let last_index = values.len() - 1;
        let rank_f64 = (last_index as f64) * q;
        // Safely handle potential overflow in f64->usize conversion
        let rank = if rank_f64.is_finite() && rank_f64 <= (usize::MAX as f64) {
            rank_f64.round() as usize
        } else {
            last_index // Fallback to last index if calculation overflows
        };
        values.get(rank).copied()
    }

    #[cfg(test)]
    fn sample_len(&self) -> usize {
        self.retained_sample_count()
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
    /// recorded in the counters returned by [`Self::overflow_rejections`].
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

    /// Collect counters, gauges, and histogram totals for a custom exporter.
    ///
    /// Call this from the application's collection task, then pass the same
    /// snapshot to `MultiExporter`. Collection allocates; updates through an
    /// already acquired counter or gauge handle remain atomic operations.
    /// Each histogram is read coherently, but different instruments are not
    /// captured in one atomic transaction. Summaries and histogram buckets
    /// are outside the legacy `MetricsSnapshot` representation.
    #[cfg(feature = "metrics")]
    #[must_use]
    pub fn export_snapshot(&self) -> crate::observability::otel::MetricsSnapshot {
        let mut snapshot = crate::observability::otel::MetricsSnapshot::new();
        for (name, counter) in &self.counters {
            snapshot.add_counter(name, Vec::new(), counter.get());
        }
        for (name, gauge) in &self.gauges {
            snapshot.add_gauge(name, Vec::new(), gauge.get());
        }
        for (name, histogram) in &self.histograms {
            let value = histogram.snapshot();
            snapshot.add_histogram(name, Vec::new(), value.count, value.sum);
        }
        snapshot
    }

    /// Exports metrics in a simple text format (Prometheus-like).
    ///
    /// br-asupersync-aog3fz: every metric name is sanitized through
    /// `sanitize_prometheus_metric_name` and every label value through
    /// `escape_prometheus_label_value` before being written to the
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
            // Read bucket counts, sum, and count from ONE coherent snapshot
            // under the histogram's state lock. Reading `hist.counts` unlocked
            // and then calling `sum()`/`count()` as separate lock acquisitions
            // let a concurrent `observe()` land between them, producing a scrape
            // where `+Inf` bucket != `_count` (or `_sum` includes an extra
            // sample) — a Prometheus invariant violation that corrupts
            // `histogram_quantile()`.
            let snap = hist.snapshot();
            let _ = writeln!(output, "# TYPE {name} histogram");
            let mut cumulative = 0;
            for (i, count) in snap.bucket_counts.iter().enumerate() {
                cumulative += *count;
                let le = if i < snap.bucket_boundaries.len() {
                    snap.bucket_boundaries[i].to_string()
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
            let _ = writeln!(output, "{name}_sum {}", snap.sum);
            let _ = writeln!(output, "{name}_count {}", snap.count);
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

/// Escape a Prometheus label value per the exposition format spec.
///
/// br-asupersync-pdu7wg — Extended escape set. The Prometheus
/// exposition format strictly requires only `\` → `\\`, `\n` → `\n`,
/// and `"` → `\"`, but a label value flowing into a structured log,
/// a downstream log forwarder, a JSON envelope, or a terminal can
/// inject lines / control sequences if it carries any of:
///
///   * `\r` (CR) — splits a log line in any reader that treats CRLF
///     as a record separator (most do).
///   * `\t` (HTAB) — survives most log paths but breaks
///     space-delimited Prometheus exposition rendering.
///   * NUL (`\x00`) — terminates strings in C-extracted parsers
///     (e.g. systemd-journald, syslog ABI).
///   * U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR — recognised
///     as line terminators by the EcmaScript JSON parser and many
///     downstream log viewers; Unicode-aware injection vector
///     specifically targeted by the asupersync-pdu7wg bead.
///   * Other C0 (0x01..=0x1F except already-handled \n/\r/\t) and DEL
///     (0x7F) — terminals interpret as escape / cursor sequences;
///     C1 controls (0x80..=0x9F) flow through some legacy log paths
///     as additional terminator-equivalents.
///
/// Each control byte is escaped to its `\xHH` form (using lowercase
/// hex for stability across snapshots). Multi-byte Unicode separators
/// are emitted as `\u{...}` so the output remains a valid UTF-8
/// string while losing its line-terminator semantics in every
/// downstream parser.
fn escape_prometheus_label_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            // Spec-required escapes (must produce backslash-escaped
            // sequences, not \xHH, so the Prometheus client itself
            // unescapes them correctly).
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '"' => {
                out.push('\\');
                out.push('"');
            }
            // br-asupersync-pdu7wg — CR + Unicode line separators +
            // NUL + remaining C0/C1 controls.
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\u{0000}' => out.push_str(r"\x00"),
            '\u{2028}' => out.push_str(r"\u{2028}"),
            '\u{2029}' => out.push_str(r"\u{2029}"),
            // C0 controls (excluding already-handled \t \n \r) and DEL.
            c if (c as u32) < 0x20 || c == '\u{007F}' => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\x{:02x}", c as u32);
            }
            // C1 controls (0x80..=0x9F) — also unsafe in legacy log
            // paths.
            c if (0x80..=0x9F).contains(&(c as u32)) => {
                use std::fmt::Write;
                let _ = write!(&mut out, "\\x{:02x}", c as u32);
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
    ///
    /// The runtime calls this once for each admitted task whose budget has a
    /// deadline, with the task's region and the time left at admission.
    fn deadline_set(&self, region_id: RegionId, deadline: Duration);

    /// Called when a deadline is exceeded.
    ///
    /// The runtime calls this once for each task that ends cancelled by its
    /// deadline ([`CancelKind::Deadline`]), with the task's region.
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
    ///
    /// The three-lane runtime calls it once per task poll, with `tasks_polled`
    /// 1 and that poll's duration, so a poll-time histogram holds one sample
    /// per poll. Each call runs on the polling worker, after the poll.
    fn scheduler_tick(&self, tasks_polled: usize, duration: Duration);

    /// Whether the runtime should time polls for [`Self::scheduler_tick`].
    ///
    /// Defaults to `true`. [`NoOpMetrics`] returns `false`, so a runtime
    /// without a metrics provider reads no clock for it (br-asupersync-x9mmxl).
    fn wants_scheduler_ticks(&self) -> bool {
        true
    }

    // === Panic Metrics ===

    /// br-asupersync-zcu3c4 — Called when an isolated panic is recorded by
    /// `runtime::panic_isolation::PanicIsolator`. `location` is one of the
    /// stable string tags `task_execution`, `finalizer_execution`,
    /// `region_cleanup`, `obligation_handling`, `scheduler_internal` (see
    /// `PanicLocation`). Default is a no-op so existing providers continue
    /// to compile and silently ignore panic events; production providers
    /// should override to count panics by location.
    fn record_panic(&self, _location: &'static str) {}
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

    fn wants_scheduler_ticks(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "metrics_inline_tests.rs"]
mod tests;
