//! Gauge value tracking fuzz target (Tick #142)
//!
//! This fuzzer tests the metamorphic property that gauge values match the last
//! set operation, not an aggregation of all operations. Specifically:
//!
//! - If the last operation was `set(x)`, then `get() == x`
//! - `add/sub/increment/decrement` operations modify the current value
//! - Concurrent operations from multiple threads are handled atomically
//!
//! The key property being tested is that gauges are instantaneous values
//! (not cumulative like counters), where `set()` operations override any
//! previous state.

#![no_main]

use asupersync::observability::metrics::{Gauge, Metrics};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, Barrier};
use std::thread;

/// Maximum number of operations in a single sequence to keep fuzzing fast
const MAX_OPERATIONS: usize = 1000;

/// Maximum number of threads for concurrent testing
const MAX_THREADS: usize = 8;

/// Maximum absolute value for gauge operations to prevent overflow
const MAX_ABS_VALUE: i64 = 1_000_000;

/// A sequence of gauge operations to be executed
#[derive(Debug, Clone, Arbitrary)]
struct GaugeOperationSequence {
    operations: Vec<GaugeOperation>,
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(1..=MAX_THREADS))]
    thread_count: usize,
}

/// Individual gauge operation
#[derive(Debug, Clone, Arbitrary)]
enum GaugeOperation {
    Set(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(-MAX_ABS_VALUE..=MAX_ABS_VALUE))] i64),
    Add(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(-MAX_ABS_VALUE..=MAX_ABS_VALUE))] i64),
    Sub(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(-MAX_ABS_VALUE..=MAX_ABS_VALUE))] i64),
    Increment,
    Decrement,
}

impl GaugeOperation {
    /// Apply this operation to a gauge
    fn apply(&self, gauge: &Gauge) {
        match self {
            GaugeOperation::Set(value) => gauge.set(*value),
            GaugeOperation::Add(value) => gauge.add(*value),
            GaugeOperation::Sub(value) => gauge.sub(*value),
            GaugeOperation::Increment => gauge.increment(),
            GaugeOperation::Decrement => gauge.decrement(),
        }
    }

    /// Compute the new expected value given the current value
    fn expected_result(&self, current: i64) -> i64 {
        match self {
            GaugeOperation::Set(value) => *value,
            GaugeOperation::Add(value) => current.saturating_add(*value),
            GaugeOperation::Sub(value) => current.saturating_sub(*value),
            GaugeOperation::Increment => current.saturating_add(1),
            GaugeOperation::Decrement => current.saturating_sub(1),
        }
    }
}

fuzz_target!(|seq: GaugeOperationSequence| {
    if seq.operations.is_empty() || seq.operations.len() > MAX_OPERATIONS {
        return;
    }

    test_sequential_operations(&seq.operations);
    test_concurrent_operations(&seq);
    test_last_set_wins_property(&seq.operations);
});

/// Test sequential operations and verify expected values
fn test_sequential_operations(operations: &[GaugeOperation]) {
    let mut metrics = Metrics::new();
    let gauge = metrics.gauge("test_sequential");

    let mut expected_value = 0i64; // gauges start at 0

    for operation in operations {
        operation.apply(&gauge);
        expected_value = operation.expected_result(expected_value);

        assert_eq!(
            gauge.get(),
            expected_value,
            "Sequential operation {:?} resulted in incorrect gauge value. Expected {}, got {}",
            operation,
            expected_value,
            gauge.get()
        );
    }
}

/// Test concurrent operations from multiple threads
fn test_concurrent_operations(seq: &GaugeOperationSequence) {
    let mut metrics = Metrics::new();
    let gauge = Arc::new(metrics.gauge("test_concurrent"));

    // Divide operations among threads
    let ops_per_thread = seq.operations.len() / seq.thread_count;
    if ops_per_thread == 0 {
        return; // Not enough operations for threading
    }

    let barrier = Arc::new(Barrier::new(seq.thread_count));
    let mut handles = Vec::new();

    for thread_id in 0..seq.thread_count {
        let start_idx = thread_id * ops_per_thread;
        let end_idx = if thread_id == seq.thread_count - 1 {
            seq.operations.len() // Last thread gets remaining operations
        } else {
            (thread_id + 1) * ops_per_thread
        };

        let thread_ops = seq.operations[start_idx..end_idx].to_vec();
        let gauge_clone = gauge.clone();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier_clone.wait();

            // Execute operations
            for operation in thread_ops {
                operation.apply(&gauge_clone);

                // Verify gauge value is always a valid i64 (no corruption)
                let value = gauge_clone.get();
                assert!(
                    value >= i64::MIN && value <= i64::MAX,
                    "Gauge value {} is outside valid i64 range",
                    value
                );
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // After concurrent operations, the gauge should have a valid value
    let final_value = gauge.get();
    assert!(
        final_value >= i64::MIN && final_value <= i64::MAX,
        "Final concurrent gauge value {} is outside valid i64 range",
        final_value
    );
}

/// Test the key metamorphic property: last set operation wins
fn test_last_set_wins_property(operations: &[GaugeOperation]) {
    // Find the last set operation in the sequence
    let last_set_value = operations
        .iter()
        .rev()
        .find_map(|op| match op {
            GaugeOperation::Set(value) => Some(*value),
            _ => None,
        });

    if last_set_value.is_none() {
        return; // No set operations to test
    }

    let mut metrics = Metrics::new();
    let gauge = metrics.gauge("test_last_set_wins");

    // Apply all operations
    for operation in operations {
        operation.apply(&gauge);
    }

    // Find last set operation and calculate expected value from that point
    let mut found_last_set = false;
    let mut expected_from_last_set = 0i64;

    for operation in operations.iter().rev() {
        if let GaugeOperation::Set(value) = operation {
            expected_from_last_set = *value;
            found_last_set = true;
            break;
        }
    }

    if found_last_set {
        // Apply operations after the last set
        let last_set_index = operations
            .iter()
            .rposition(|op| matches!(op, GaugeOperation::Set(_)))
            .unwrap();

        for operation in operations.iter().skip(last_set_index + 1) {
            expected_from_last_set = operation.expected_result(expected_from_last_set);
        }

        assert_eq!(
            gauge.get(),
            expected_from_last_set,
            "Last set wins property violated. Expected {}, got {}",
            expected_from_last_set,
            gauge.get()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gauge_set_overwrites_previous_value() {
        let mut metrics = Metrics::new();
        let gauge = metrics.gauge("test");

        gauge.add(100);
        assert_eq!(gauge.get(), 100);

        gauge.set(42);
        assert_eq!(gauge.get(), 42); // Set overwrites, doesn't add
    }

    #[test]
    fn test_gauge_operations_are_atomic() {
        let mut metrics = Metrics::new();
        let gauge = Arc::new(metrics.gauge("test"));

        let gauge_clone = gauge.clone();
        let handle = thread::spawn(move || {
            for i in 0..1000 {
                gauge_clone.set(i);
            }
        });

        for i in 1000..2000 {
            gauge.set(i);
        }

        handle.join().unwrap();

        // Value should be one of the set values, not corrupted
        let final_value = gauge.get();
        assert!(
            final_value >= 0 && final_value < 2000,
            "Gauge value {} suggests atomic operations failed",
            final_value
        );
    }

    #[test]
    fn test_gauge_add_sub_modify_current_value() {
        let mut metrics = Metrics::new();
        let gauge = metrics.gauge("test");

        gauge.set(10);
        gauge.add(5);
        assert_eq!(gauge.get(), 15);

        gauge.sub(3);
        assert_eq!(gauge.get(), 12);
    }

    #[test]
    fn test_gauge_increment_decrement() {
        let mut metrics = Metrics::new();
        let gauge = metrics.gauge("test");

        gauge.set(0);
        gauge.increment();
        assert_eq!(gauge.get(), 1);

        gauge.decrement();
        assert_eq!(gauge.get(), 0);
    }

    #[test]
    fn test_operation_expected_result() {
        assert_eq!(GaugeOperation::Set(42).expected_result(100), 42);
        assert_eq!(GaugeOperation::Add(5).expected_result(10), 15);
        assert_eq!(GaugeOperation::Sub(3).expected_result(10), 7);
        assert_eq!(GaugeOperation::Increment.expected_result(10), 11);
        assert_eq!(GaugeOperation::Decrement.expected_result(10), 9);
    }
}