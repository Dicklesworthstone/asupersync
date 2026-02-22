//! Runtime metrics.
//!
//! Provides counters, gauges, and histograms for runtime statistics.

use crate::types::{CancelKind, Outcome, RegionId, TaskId};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
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
}

/// A collection of metrics.
#[derive(Debug, Default)]
pub struct Metrics {
    counters: BTreeMap<String, Arc<Counter>>,
    gauges: BTreeMap<String, Arc<Gauge>>,
    histograms: BTreeMap<String, Arc<Histogram>>,
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
}
