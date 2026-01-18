//! Runtime metrics.
//!
//! Provides counters, gauges, and histograms for runtime statistics.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

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
}

/// A collection of metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    counters: HashMap<String, Arc<Counter>>,
    gauges: HashMap<String, Arc<Gauge>>,
    histograms: HashMap<String, Arc<Histogram>>,
}

impl Metrics {
    /// Creates a new metrics registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets or creates a counter.
    pub fn counter(&mut self, name: &str) -> Arc<Counter> {
        self.counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new(name)))
            .clone()
    }

    /// Gets or creates a gauge.
    pub fn gauge(&mut self, name: &str) -> Arc<Gauge> {
        self.gauges
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Gauge::new(name)))
            .clone()
    }

    /// Gets or creates a histogram with default buckets.
    pub fn histogram(&mut self, name: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        // Note: Re-creating histogram with different buckets is not supported for same name
        self.histograms
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Histogram::new(name, buckets)))
            .clone()
    }

    /// Exports metrics in a simple text format (Prometheus-like).
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut output = String::new();

        for (name, counter) in &self.counters {
            let _ = writeln!(output, "# TYPE {name} counter");
            let _ = writeln!(output, "{name} {}", counter.get());
        }

        for (name, gauge) in &self.gauges {
            let _ = writeln!(output, "# TYPE {name} gauge");
            let _ = writeln!(output, "{name} {}", gauge.get());
        }

        for (name, hist) in &self.histograms {
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
                let _ = writeln!(output, "{name}_bucket{{le=\"{le}\"}} {cumulative}");
            }
            let _ = writeln!(output, "{name}_sum {}", hist.sum());
            let _ = writeln!(output, "{name}_count {}", hist.count());
        }

        output
    }
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

#[cfg(test)]
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
}
