//! Counter monotonic compliance fuzz target (Tick #143)
//!
//! This fuzzer tests OTLP monotonic counter specification compliance by verifying:
//!
//! 1. Counters never decrease in value (monotonicity)
//! 2. Large values don't cause overflow/wrapping that breaks monotonicity
//! 3. Concurrent operations maintain atomicity and monotonicity
//! 4. Edge cases around u64::MAX are handled correctly
//!
//! The OTLP specification requires monotonic counters to only increase, never decrease.
//! Since Counter.add() takes u64, negative deltas are prevented at the type level,
//! but we test edge cases that could still break monotonicity.

#![no_main]

use asupersync::observability::metrics::{Counter, Metrics};
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, Barrier};
use std::thread;

/// Maximum number of operations in a single sequence
const MAX_OPERATIONS: usize = 1000;

/// Maximum number of threads for concurrent testing
const MAX_THREADS: usize = 8;

/// Maximum delta value to prevent immediate overflow in most cases
const MAX_DELTA: u64 = u64::MAX / 1000;

/// A sequence of counter operations to test monotonicity
#[derive(Debug, Clone, Arbitrary)]
struct CounterOperationSequence {
    operations: Vec<CounterOperation>,
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(1..=MAX_THREADS))]
    thread_count: usize,
    #[arbitrary(with = |u: &mut Unstructured| u.int_in_range(0..=u64::MAX / 2))]
    initial_value: u64,
}

/// Counter operation types that could affect monotonicity
#[derive(Debug, Clone, Arbitrary)]
enum CounterOperation {
    /// Add a small value (normal operation)
    Add(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(1..=1000))] u64),
    /// Add a large value (testing overflow scenarios)
    AddLarge(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(MAX_DELTA..=u64::MAX))] u64),
    /// Add the maximum possible value
    AddMax,
    /// Increment by 1 (most common operation)
    Increment,
    /// Rapid increment sequence (stress test)
    RapidIncrement(#[arbitrary(with = |u: &mut Unstructured| u.int_in_range(1..=100))] u8),
}

impl CounterOperation {
    /// Apply this operation to a counter
    fn apply(&self, counter: &Counter) {
        match self {
            CounterOperation::Add(value) => counter.add(*value),
            CounterOperation::AddLarge(value) => counter.add(*value),
            CounterOperation::AddMax => counter.add(u64::MAX),
            CounterOperation::Increment => counter.increment(),
            CounterOperation::RapidIncrement(count) => {
                for _ in 0..*count {
                    counter.increment();
                }
            }
        }
    }

    /// Expected minimum increase (for overflow detection)
    fn expected_minimum_increase(&self, current: u64) -> Option<u64> {
        match self {
            CounterOperation::Add(value) => current.checked_add(*value),
            CounterOperation::AddLarge(value) => current.checked_add(*value),
            CounterOperation::AddMax => current.checked_add(u64::MAX),
            CounterOperation::Increment => current.checked_add(1),
            CounterOperation::RapidIncrement(count) => current.checked_add(*count as u64),
        }
    }
}

fuzz_target!(|seq: CounterOperationSequence| {
    if seq.operations.is_empty() || seq.operations.len() > MAX_OPERATIONS {
        return;
    }

    test_monotonic_property(&seq.operations, seq.initial_value);
    test_concurrent_monotonicity(&seq);
    test_overflow_handling(&seq.operations);
    test_otlp_compliance_properties(&seq.operations);
});

/// Test the core monotonic property: counters never decrease
fn test_monotonic_property(operations: &[CounterOperation], initial_value: u64) {
    let mut metrics = Metrics::new();
    let counter = metrics.counter("test_monotonic");

    // Set initial value by adding it
    if initial_value > 0 {
        counter.add(initial_value);
    }

    let mut previous_value = counter.get();

    for (i, operation) in operations.iter().enumerate() {
        operation.apply(&counter);
        let current_value = counter.get();

        // Core OTLP requirement: monotonic counters never decrease
        assert!(
            current_value >= previous_value,
            "MONOTONICITY VIOLATION at operation {i}: Counter decreased from {previous_value} to {current_value}. Operation: {operation:?}"
        );

        // Additional check: if we can compute expected value, verify reasonable increase
        if let Some(expected_min) = operation.expected_minimum_increase(previous_value) {
            assert!(
                current_value >= expected_min || current_value == previous_value,
                "Counter increase is less than expected at operation {i}. Previous: {previous_value}, Current: {current_value}, Expected min: {expected_min}"
            );
        }

        previous_value = current_value;
    }
}

/// Test concurrent operations maintain monotonicity
fn test_concurrent_monotonicity(seq: &CounterOperationSequence) {
    let mut metrics = Metrics::new();
    let counter = Arc::new(metrics.counter("test_concurrent_monotonic"));

    // Set initial value
    if seq.initial_value > 0 {
        counter.add(seq.initial_value);
    }

    let initial_snapshot = counter.get();

    // Divide operations among threads
    let ops_per_thread = seq.operations.len() / seq.thread_count;
    if ops_per_thread == 0 {
        return;
    }

    let barrier = Arc::new(Barrier::new(seq.thread_count));
    let mut handles = Vec::new();

    for thread_id in 0..seq.thread_count {
        let start_idx = thread_id * ops_per_thread;
        let end_idx = if thread_id == seq.thread_count - 1 {
            seq.operations.len()
        } else {
            (thread_id + 1) * ops_per_thread
        };

        let thread_ops = seq.operations[start_idx..end_idx].to_vec();
        let counter_clone = counter.clone();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            let mut last_observed = counter_clone.get();
            for operation in thread_ops {
                operation.apply(&counter_clone);
                let new_value = counter_clone.get();

                // In concurrent settings, we can only assert non-strict monotonicity
                // (value can stay same due to other threads, but never decrease from our view)
                assert!(
                    new_value >= last_observed,
                    "Concurrent monotonicity violation: saw value decrease from {last_observed} to {new_value}"
                );

                last_observed = new_value;
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let final_value = counter.get();

    // Final value must be at least the initial value (global monotonicity)
    assert!(
        final_value >= initial_snapshot,
        "Global monotonicity violation: final value {final_value} less than initial {initial_snapshot}"
    );
}

/// Test overflow handling doesn't break monotonicity
fn test_overflow_handling(operations: &[CounterOperation]) {
    let mut metrics = Metrics::new();
    let counter = metrics.counter("test_overflow");

    // Start near u64::MAX to test overflow scenarios
    let near_max = u64::MAX - 1000;
    counter.add(near_max);

    let mut previous = counter.get();

    for operation in operations {
        operation.apply(&counter);
        let current = counter.get();

        // Even during overflow, monotonicity must be preserved
        // (saturating at u64::MAX is acceptable per OTLP spec)
        assert!(
            current >= previous,
            "Overflow broke monotonicity: {previous} -> {current} during {operation:?}"
        );

        previous = current;
    }
}

/// Test OTLP specification compliance properties
fn test_otlp_compliance_properties(operations: &[CounterOperation]) {
    let mut metrics = Metrics::new();
    let counter = metrics.counter("test_otlp_compliance");

    // OTLP Property 1: Counter starts at 0 (or explicitly initialized value)
    assert_eq!(counter.get(), 0, "Counter must start at 0");

    // OTLP Property 2: Only positive deltas are allowed (enforced by u64 type)
    // This is verified by the type system - no test needed

    // OTLP Property 3: Value is cumulative and monotonic
    let mut cumulative_sum = 0u64;
    let mut previous = 0u64;

    for operation in operations {
        let before = counter.get();
        operation.apply(&counter);
        let after = counter.get();

        // Calculate expected cumulative sum (handling overflow)
        match operation {
            CounterOperation::Add(value) => {
                cumulative_sum = cumulative_sum.saturating_add(*value);
            }
            CounterOperation::AddLarge(value) => {
                cumulative_sum = cumulative_sum.saturating_add(*value);
            }
            CounterOperation::AddMax => {
                cumulative_sum = u64::MAX; // Saturate
            }
            CounterOperation::Increment => {
                cumulative_sum = cumulative_sum.saturating_add(1);
            }
            CounterOperation::RapidIncrement(count) => {
                cumulative_sum = cumulative_sum.saturating_add(*count as u64);
            }
        }

        // Monotonicity check
        assert!(
            after >= before,
            "OTLP monotonicity violation: {before} -> {after}"
        );

        // Value should be at least the cumulative sum (might saturate at u64::MAX)
        assert!(
            after >= previous && (after == cumulative_sum || after == u64::MAX),
            "OTLP cumulative property violation: after={after}, cumulative_sum={cumulative_sum}, previous={previous}"
        );

        previous = after;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_starts_at_zero() {
        let mut metrics = Metrics::new();
        let counter = metrics.counter("test");
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_counter_add_maintains_monotonicity() {
        let mut metrics = Metrics::new();
        let counter = metrics.counter("test");

        let values = [1, 100, 5, u64::MAX / 2];
        let mut expected = 0;

        for &value in &values {
            counter.add(value);
            expected = expected.saturating_add(value);
            assert_eq!(counter.get(), expected);
        }
    }

    #[test]
    fn test_counter_increment_monotonicity() {
        let mut metrics = Metrics::new();
        let counter = metrics.counter("test");

        for i in 1..=100 {
            counter.increment();
            assert_eq!(counter.get(), i);
        }
    }

    #[test]
    fn test_counter_overflow_saturates() {
        let mut metrics = Metrics::new();
        let counter = metrics.counter("test");

        counter.add(u64::MAX);
        assert_eq!(counter.get(), u64::MAX);

        // Adding more should saturate, not wrap
        let before = counter.get();
        counter.add(1);
        let after = counter.get();

        assert!(after >= before, "Counter wrapped on overflow");
    }

    #[test]
    fn test_counter_concurrent_monotonicity() {
        let mut metrics = Metrics::new();
        let counter = Arc::new(metrics.counter("test"));

        let counter1 = counter.clone();
        let handle1 = thread::spawn(move || {
            for _ in 0..1000 {
                counter1.increment();
            }
        });

        let counter2 = counter.clone();
        let handle2 = thread::spawn(move || {
            for _ in 0..1000 {
                counter2.add(1);
            }
        });

        handle1.join().unwrap();
        handle2.join().unwrap();

        // Should have exactly 2000 after both threads complete
        assert_eq!(counter.get(), 2000);
    }

    #[test]
    fn test_operation_types() {
        let add_op = CounterOperation::Add(42);
        let increment_op = CounterOperation::Increment;
        let large_op = CounterOperation::AddLarge(u64::MAX / 2);

        assert_eq!(add_op.expected_minimum_increase(0), Some(42));
        assert_eq!(increment_op.expected_minimum_increase(10), Some(11));
        assert!(large_op.expected_minimum_increase(u64::MAX / 2 + 1).is_none()); // Overflow
    }
}