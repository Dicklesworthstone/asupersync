//! Runtime metrics for observability.
//!
//! Provides counters, gauges, and histograms for tracking runtime statistics.
//! All metrics are designed to work with virtual time for determinism.

use crate::types::Time;
use core::fmt;
use std::collections::HashMap;

/// A monotonically increasing counter.
///
/// Counters track cumulative values that only increase (e.g., total requests,
/// bytes sent, errors encountered).
#[derive(Debug, Clone)]
pub struct Counter {
    name: String,
    value: u64,
    labels: HashMap<String, String>,
}

impl Counter {
    /// Creates a new counter with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: 0,
            labels: HashMap::new(),
        }
    }

    /// Adds a label to the counter.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Returns the counter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Increments the counter by the given amount.
    pub fn increment(&mut self, amount: u64) {
        self.value = self.value.saturating_add(amount);
    }

    /// Increments the counter by 1.
    pub fn inc(&mut self) {
        self.increment(1);
    }

    /// Resets the counter to zero.
    pub fn reset(&mut self) {
        self.value = 0;
    }

    /// Returns the labels.
    #[must_use]
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// A gauge that can increase or decrease.
///
/// Gauges track instantaneous values (e.g., current queue depth, active
/// connections, memory usage).
#[derive(Debug, Clone)]
pub struct Gauge {
    name: String,
    value: i64,
    labels: HashMap<String, String>,
}

impl Gauge {
    /// Creates a new gauge with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: 0,
            labels: HashMap::new(),
        }
    }

    /// Adds a label to the gauge.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Returns the gauge name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current value.
    #[must_use]
    pub const fn value(&self) -> i64 {
        self.value
    }

    /// Sets the gauge to the given value.
    pub fn set(&mut self, value: i64) {
        self.value = value;
    }

    /// Increments the gauge by the given amount.
    pub fn increment(&mut self, amount: i64) {
        self.value = self.value.saturating_add(amount);
    }

    /// Decrements the gauge by the given amount.
    pub fn decrement(&mut self, amount: i64) {
        self.value = self.value.saturating_sub(amount);
    }

    /// Increments the gauge by 1.
    pub fn inc(&mut self) {
        self.increment(1);
    }

    /// Decrements the gauge by 1.
    pub fn dec(&mut self) {
        self.decrement(1);
    }

    /// Returns the labels.
    #[must_use]
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }
}

impl fmt::Display for Gauge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// A histogram for tracking value distributions.
///
/// Histograms track the distribution of values across configurable buckets.
/// Useful for latency measurements, size distributions, etc.
#[derive(Debug, Clone)]
pub struct Histogram {
    name: String,
    /// Bucket upper bounds.
    buckets: Vec<f64>,
    /// Counts per bucket (includes +Inf bucket at end).
    counts: Vec<u64>,
    /// Sum of all observed values.
    sum: f64,
    /// Total count of observations.
    count: u64,
    labels: HashMap<String, String>,
}

impl Histogram {
    /// Creates a new histogram with the given bucket boundaries.
    ///
    /// Buckets should be sorted in ascending order. An implicit +Inf bucket
    /// is added automatically.
    #[must_use]
    pub fn new(name: impl Into<String>, buckets: Vec<f64>) -> Self {
        let count_len = buckets.len() + 1; // +1 for +Inf
        Self {
            name: name.into(),
            buckets,
            counts: vec![0; count_len],
            sum: 0.0,
            count: 0,
            labels: HashMap::new(),
        }
    }

    /// Creates a histogram with default latency buckets (in milliseconds).
    #[must_use]
    pub fn with_latency_buckets(name: impl Into<String>) -> Self {
        Self::new(
            name,
            vec![
                1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
            ],
        )
    }

    /// Creates a histogram with exponential buckets.
    #[must_use]
    pub fn with_exponential_buckets(
        name: impl Into<String>,
        start: f64,
        factor: f64,
        count: usize,
    ) -> Self {
        let mut buckets = Vec::with_capacity(count);
        let mut bound = start;
        for _ in 0..count {
            buckets.push(bound);
            bound *= factor;
        }
        Self::new(name, buckets)
    }

    /// Adds a label to the histogram.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Returns the histogram name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Records a value in the histogram.
    pub fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;

        // Find the appropriate bucket
        for (i, &bound) in self.buckets.iter().enumerate() {
            if value <= bound {
                self.counts[i] += 1;
                return;
            }
        }
        // Value exceeds all buckets, goes in +Inf
        if let Some(last) = self.counts.last_mut() {
            *last += 1;
        }
    }

    /// Returns the sum of all observed values.
    #[must_use]
    pub fn sum(&self) -> f64 {
        self.sum
    }

    /// Returns the total count of observations.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the mean of observed values.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    /// Returns the bucket boundaries.
    #[must_use]
    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    /// Returns the counts per bucket.
    #[must_use]
    pub fn bucket_counts(&self) -> &[u64] {
        &self.counts
    }

    /// Returns the labels.
    #[must_use]
    pub fn labels(&self) -> &HashMap<String, String> {
        &self.labels
    }

    /// Resets the histogram.
    pub fn reset(&mut self) {
        self.counts.fill(0);
        self.sum = 0.0;
        self.count = 0;
    }
}

impl fmt::Display for Histogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} count={} sum={:.2}", self.name, self.count, self.sum)
    }
}

/// A value that can be stored in the metrics registry.
#[derive(Debug, Clone)]
pub enum MetricValue {
    /// A counter metric.
    Counter(Counter),
    /// A gauge metric.
    Gauge(Gauge),
    /// A histogram metric.
    Histogram(Histogram),
}

/// A registry for collecting and organizing metrics.
///
/// The `Metrics` struct provides a central place to register and access
/// all metrics in the runtime.
#[derive(Debug, Clone)]
pub struct Metrics {
    /// Counters by name.
    counters: HashMap<String, Counter>,
    /// Gauges by name.
    gauges: HashMap<String, Gauge>,
    /// Histograms by name.
    histograms: HashMap<String, Histogram>,
    /// Timestamp of last snapshot.
    last_snapshot: Time,
}

impl Metrics {
    /// Creates a new empty metrics registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            histograms: HashMap::new(),
            last_snapshot: Time::ZERO,
        }
    }

    /// Returns a mutable reference to a counter, creating it if needed.
    pub fn counter(&mut self, name: &str) -> &mut Counter {
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| Counter::new(name))
    }

    /// Returns a mutable reference to a gauge, creating it if needed.
    pub fn gauge(&mut self, name: &str) -> &mut Gauge {
        self.gauges
            .entry(name.to_string())
            .or_insert_with(|| Gauge::new(name))
    }

    /// Returns a mutable reference to a histogram, creating it if needed.
    ///
    /// Uses default latency buckets if the histogram doesn't exist.
    pub fn histogram(&mut self, name: &str) -> &mut Histogram {
        self.histograms
            .entry(name.to_string())
            .or_insert_with(|| Histogram::with_latency_buckets(name))
    }

    /// Registers a histogram with custom buckets.
    pub fn register_histogram(&mut self, histogram: Histogram) {
        self.histograms
            .insert(histogram.name().to_string(), histogram);
    }

    /// Returns an iterator over all counters.
    pub fn counters(&self) -> impl Iterator<Item = &Counter> {
        self.counters.values()
    }

    /// Returns an iterator over all gauges.
    pub fn gauges(&self) -> impl Iterator<Item = &Gauge> {
        self.gauges.values()
    }

    /// Returns an iterator over all histograms.
    pub fn histograms(&self) -> impl Iterator<Item = &Histogram> {
        self.histograms.values()
    }

    /// Takes a snapshot and records the time.
    pub fn snapshot(&mut self, now: Time) {
        self.last_snapshot = now;
    }

    /// Returns the time of the last snapshot.
    #[must_use]
    pub const fn last_snapshot(&self) -> Time {
        self.last_snapshot
    }

    /// Resets all metrics to their initial values.
    pub fn reset(&mut self) {
        for counter in self.counters.values_mut() {
            counter.reset();
        }
        for gauge in self.gauges.values_mut() {
            gauge.set(0);
        }
        for histogram in self.histograms.values_mut() {
            histogram.reset();
        }
    }

    /// Formats all metrics as a human-readable string.
    #[must_use]
    pub fn format_text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();

        s.push_str("# Counters\n");
        for counter in self.counters.values() {
            let _ = writeln!(s, "{counter}");
        }

        s.push_str("\n# Gauges\n");
        for gauge in self.gauges.values() {
            let _ = writeln!(s, "{gauge}");
        }

        s.push_str("\n# Histograms\n");
        for histogram in self.histograms.values() {
            let _ = writeln!(s, "{histogram}");
        }

        s
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_operations() {
        let mut counter = Counter::new("requests_total");
        assert_eq!(counter.value(), 0);

        counter.inc();
        assert_eq!(counter.value(), 1);

        counter.increment(5);
        assert_eq!(counter.value(), 6);

        counter.reset();
        assert_eq!(counter.value(), 0);
    }

    #[test]
    fn counter_with_labels() {
        let counter = Counter::new("requests")
            .with_label("method", "GET")
            .with_label("path", "/api");

        assert_eq!(counter.labels().get("method"), Some(&"GET".to_string()));
        assert_eq!(counter.labels().get("path"), Some(&"/api".to_string()));
    }

    #[test]
    fn gauge_operations() {
        let mut gauge = Gauge::new("queue_depth");
        assert_eq!(gauge.value(), 0);

        gauge.set(10);
        assert_eq!(gauge.value(), 10);

        gauge.inc();
        assert_eq!(gauge.value(), 11);

        gauge.dec();
        assert_eq!(gauge.value(), 10);

        gauge.decrement(5);
        assert_eq!(gauge.value(), 5);
    }

    #[test]
    fn histogram_operations() {
        let mut hist = Histogram::new("latency", vec![10.0, 50.0, 100.0]);

        hist.observe(5.0);
        hist.observe(25.0);
        hist.observe(75.0);
        hist.observe(200.0);

        assert_eq!(hist.count(), 4);
        assert!((hist.sum() - 305.0).abs() < 0.001);
        assert!((hist.mean() - 76.25).abs() < 0.001);

        let counts = hist.bucket_counts();
        assert_eq!(counts[0], 1); // <= 10
        assert_eq!(counts[1], 1); // <= 50
        assert_eq!(counts[2], 1); // <= 100
        assert_eq!(counts[3], 1); // +Inf
    }

    #[test]
    fn histogram_latency_buckets() {
        let hist = Histogram::with_latency_buckets("request_duration");
        assert_eq!(hist.buckets().len(), 10);
        assert!((hist.buckets()[0] - 1.0).abs() < 0.001);
    }

    #[test]
    fn histogram_exponential_buckets() {
        let hist = Histogram::with_exponential_buckets("sizes", 1.0, 2.0, 5);
        assert_eq!(hist.buckets(), &[1.0, 2.0, 4.0, 8.0, 16.0]);
    }

    #[test]
    fn metrics_registry() {
        let mut metrics = Metrics::new();

        metrics.counter("requests").inc();
        metrics.counter("requests").inc();
        metrics.gauge("connections").set(5);
        metrics.histogram("latency").observe(10.0);

        assert_eq!(metrics.counter("requests").value(), 2);
        assert_eq!(metrics.gauge("connections").value(), 5);
        assert_eq!(metrics.histogram("latency").count(), 1);
    }

    #[test]
    fn metrics_format_text() {
        let mut metrics = Metrics::new();
        metrics.counter("test_counter").increment(42);
        metrics.gauge("test_gauge").set(100);

        let text = metrics.format_text();
        assert!(text.contains("test_counter=42"));
        assert!(text.contains("test_gauge=100"));
    }

    #[test]
    fn metrics_reset() {
        let mut metrics = Metrics::new();
        metrics.counter("c").increment(10);
        metrics.gauge("g").set(20);

        metrics.reset();

        assert_eq!(metrics.counter("c").value(), 0);
        assert_eq!(metrics.gauge("g").value(), 0);
    }
}
