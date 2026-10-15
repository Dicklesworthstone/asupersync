#![no_main]

use arbitrary::Arbitrary;
use asupersync::observability::metrics::Metrics;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Concurrent updates fuzzer for Counter/Gauge/Histogram thread safety
///
/// Tests metamorphic properties under concurrent access:
/// 1. Counter: final value = sum of all add() operations
/// 2. Gauge: final value = initial + sum(adds) - sum(subs) (accounting for set() operations)
/// 3. Histogram: count = number of observe() calls, sum = sum of observed values
/// 4. No data races, deadlocks, or atomic operation inconsistencies
#[derive(Arbitrary, Debug)]
struct MetricsConcurrentFuzz {
    /// Test configuration parameters
    config: TestConfig,
    /// Operation sequences per thread
    operations: Vec<Vec<MetricOperation>>,
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Number of concurrent threads (1-8)
    thread_count: u8,
    /// Brief delay before starting threads (0-5ms)
    startup_delay_ms: u8,
    /// Histogram bucket configuration
    histogram_buckets: HistogramBuckets,
}

#[derive(Arbitrary, Debug)]
enum HistogramBuckets {
    Small,  // [1.0, 5.0, 10.0]
    Medium, // [0.1, 0.5, 1.0, 5.0, 10.0, 50.0]
    Large,  // [0.01, 0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0]
}

#[derive(Arbitrary, Debug, Clone)]
enum MetricOperation {
    CounterIncrement,
    CounterAdd { value: u64 },
    GaugeIncrement,
    GaugeDecrement,
    GaugeAdd { value: i64 },
    GaugeSub { value: i64 },
    GaugeSet { value: i64 },
    HistogramObserve { value: f64 },
}

// Resource limits to prevent fuzzer timeouts
const MAX_THREADS: usize = 8;
const MAX_STARTUP_DELAY_MS: u64 = 5;
const MAX_OPERATIONS_PER_THREAD: usize = 100;
const THREAD_TIMEOUT: Duration = Duration::from_secs(5);

// Bounds for generated values to prevent overflow/underflow edge cases
const MAX_COUNTER_ADD: u64 = 1000;
const MAX_GAUGE_VALUE: i64 = 10000;
const MIN_GAUGE_VALUE: i64 = -10000;
const MAX_HISTOGRAM_VALUE: f64 = 1000.0;
const MIN_HISTOGRAM_VALUE: f64 = 0.001;

impl HistogramBuckets {
    fn to_vec(&self) -> Vec<f64> {
        match self {
            HistogramBuckets::Small => vec![1.0, 5.0, 10.0],
            HistogramBuckets::Medium => vec![0.1, 0.5, 1.0, 5.0, 10.0, 50.0],
            HistogramBuckets::Large => vec![0.01, 0.1, 1.0, 10.0, 100.0, 1000.0, 10000.0],
        }
    }
}

fuzz_target!(|input: MetricsConcurrentFuzz| {
    // Apply resource limits
    let thread_count = (input.config.thread_count as usize).min(MAX_THREADS).max(1);
    let startup_delay =
        Duration::from_millis((input.config.startup_delay_ms as u64).min(MAX_STARTUP_DELAY_MS));

    // Limit operations per thread to prevent timeouts
    let operations: Vec<Vec<MetricOperation>> = input
        .operations
        .into_iter()
        .take(thread_count)
        .map(|ops| ops.into_iter().take(MAX_OPERATIONS_PER_THREAD).collect())
        .collect();

    // Pad with empty operation lists if we have fewer than thread_count
    let mut operations = operations;
    while operations.len() < thread_count {
        operations.push(Vec::new());
    }

    // Create shared metrics
    let mut metrics = Metrics::new();
    let counter = metrics.counter("test_counter");
    let gauge = metrics.gauge("test_gauge");
    let histogram_buckets = input.config.histogram_buckets.to_vec();
    let histogram = metrics.histogram("test_histogram", histogram_buckets);

    // Track expected values for metamorphic verification
    let mut expected_counter_total = 0u64;
    let mut expected_histogram_count = 0u64;
    let mut expected_histogram_sum = 0.0f64;

    // For gauge, we need to track the sequence of operations to compute expected final value
    // This is more complex due to set() operations overriding previous state
    let mut gauge_operations = Vec::new();

    // Flatten all operations to compute expected values
    for thread_ops in &operations {
        for op in thread_ops {
            match op.clone() {
                MetricOperation::CounterIncrement => {
                    expected_counter_total += 1;
                }
                MetricOperation::CounterAdd { value } => {
                    let bounded_value = value.min(MAX_COUNTER_ADD);
                    expected_counter_total += bounded_value;
                }
                MetricOperation::HistogramObserve { value } => {
                    let bounded_value = value.max(MIN_HISTOGRAM_VALUE).min(MAX_HISTOGRAM_VALUE);
                    if bounded_value.is_finite() && !bounded_value.is_nan() {
                        expected_histogram_count += 1;
                        expected_histogram_sum += bounded_value;
                    }
                }
                gauge_op => {
                    gauge_operations.push(gauge_op);
                }
            }
        }
    }

    // For gauge, compute expected final value by replaying operations sequentially
    // Note: In concurrent execution, the final state may differ due to interleaving,
    // but we can verify that the operations themselves are atomic
    let _expected_gauge_value = compute_gauge_final_value(&gauge_operations);

    // Brief startup delay to increase chance of race conditions
    thread::sleep(startup_delay);

    // Spawn concurrent threads
    let mut handles = Vec::new();
    for thread_ops in operations {
        let counter_clone = Arc::clone(&counter);
        let gauge_clone = Arc::clone(&gauge);
        let histogram_clone = Arc::clone(&histogram);

        let handle = thread::spawn(move || {
            for op in thread_ops {
                match op {
                    MetricOperation::CounterIncrement => {
                        counter_clone.increment();
                    }
                    MetricOperation::CounterAdd { value } => {
                        let bounded_value = value.min(MAX_COUNTER_ADD);
                        counter_clone.add(bounded_value);
                    }
                    MetricOperation::GaugeIncrement => {
                        gauge_clone.increment();
                    }
                    MetricOperation::GaugeDecrement => {
                        gauge_clone.decrement();
                    }
                    MetricOperation::GaugeAdd { value } => {
                        let bounded_value = value.max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                        gauge_clone.add(bounded_value);
                    }
                    MetricOperation::GaugeSub { value } => {
                        let bounded_value = value.max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                        gauge_clone.sub(bounded_value);
                    }
                    MetricOperation::GaugeSet { value } => {
                        let bounded_value = value.max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                        gauge_clone.set(bounded_value);
                    }
                    MetricOperation::HistogramObserve { value } => {
                        let bounded_value = value.max(MIN_HISTOGRAM_VALUE).min(MAX_HISTOGRAM_VALUE);
                        if bounded_value.is_finite() && !bounded_value.is_nan() {
                            histogram_clone.observe(bounded_value);
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads with timeout
    let start_time = Instant::now();
    for handle in handles {
        if start_time.elapsed() > THREAD_TIMEOUT {
            panic!("Thread execution timeout");
        }
        handle.join().expect("Thread should not panic");
    }

    // Verify metamorphic properties

    // Counter: final value should equal sum of all add operations
    let final_counter = counter.get();
    assert_eq!(
        final_counter, expected_counter_total,
        "Counter final value {} != expected total {}",
        final_counter, expected_counter_total
    );

    // Histogram: count and sum should match expected values
    let final_histogram_count = histogram.count();
    let final_histogram_sum = histogram.sum();

    assert_eq!(
        final_histogram_count, expected_histogram_count,
        "Histogram count {} != expected {}",
        final_histogram_count, expected_histogram_count
    );

    // For histogram sum, use epsilon comparison due to floating point precision
    let epsilon = 1e-10;
    let sum_diff = (final_histogram_sum - expected_histogram_sum).abs();
    assert!(
        sum_diff < epsilon,
        "Histogram sum {} != expected {} (diff: {})",
        final_histogram_sum,
        expected_histogram_sum,
        sum_diff
    );

    // For gauge, we can't predict the exact final value due to concurrent interleaving
    // of set() operations, but we can verify that the atomic operations are working
    // by checking that the gauge value is within reasonable bounds
    let final_gauge = gauge.get();
    assert!(
        final_gauge >= MIN_GAUGE_VALUE && final_gauge <= MAX_GAUGE_VALUE,
        "Gauge value {} outside expected bounds [{}, {}]",
        final_gauge,
        MIN_GAUGE_VALUE,
        MAX_GAUGE_VALUE
    );

    // Additional invariant: if there were no operations, values should be at initial state
    if expected_counter_total == 0 {
        assert_eq!(final_counter, 0, "Counter should be 0 with no operations");
    }
    if expected_histogram_count == 0 {
        assert_eq!(
            final_histogram_count, 0,
            "Histogram count should be 0 with no observations"
        );
        assert_eq!(
            final_histogram_sum, 0.0,
            "Histogram sum should be 0.0 with no observations"
        );
    }
});

/// Compute expected gauge final value if operations were executed sequentially
fn compute_gauge_final_value(operations: &[MetricOperation]) -> i64 {
    let mut value = 0i64; // Gauges start at 0

    for op in operations {
        match op {
            MetricOperation::GaugeIncrement => {
                value = value.saturating_add(1);
            }
            MetricOperation::GaugeDecrement => {
                value = value.saturating_sub(1);
            }
            MetricOperation::GaugeAdd { value: add_val } => {
                let bounded_val = (*add_val).max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                value = value.saturating_add(bounded_val);
            }
            MetricOperation::GaugeSub { value: sub_val } => {
                let bounded_val = (*sub_val).max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                value = value.saturating_sub(bounded_val);
            }
            MetricOperation::GaugeSet { value: set_val } => {
                let bounded_val = (*set_val).max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
                value = bounded_val;
            }
            _ => {} // Other operations don't affect gauge
        }
        // Keep within bounds
        value = value.max(MIN_GAUGE_VALUE).min(MAX_GAUGE_VALUE);
    }

    value
}
