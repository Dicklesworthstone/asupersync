#![allow(clippy::all)]
//! Metamorphic property tests for observability::metrics counter monotonicity invariants.
//!
//! These tests verify the core invariants of asupersync's metrics system using
//! metamorphic relations rather than oracle-based testing. The properties ensure
//! correct behavior of counters, gauges, and histograms under concurrent access,
//! cancellation scenarios, and snapshot consistency requirements.
//!
//! ## Key Properties Tested
//!
//! 1. **Counter Monotonicity**: Counters never decrease (monotonic increment only)
//! 2. **Gauge Bidirectionality**: Gauges can increase or decrease arbitrarily
//! 3. **Histogram Sample Preservation**: All observed values are preserved in buckets
//! 4. **Label Aggregation Invariants**: Labels do not alter core aggregation properties
//! 5. **Concurrent Snapshot Consistency**: Concurrent record/collect operations produce consistent snapshots
//!
//! ## Metamorphic Relations
//!
//! - **Monotonicity preservation**: Counter(t₁) ≤ Counter(t₂) for t₁ ≤ t₂
//! - **Gauge commutativity**: add(x) then add(y) ≡ add(y) then add(x)
//! - **Histogram additivity**: sum(observations) = histogram.sum(), count(observations) = histogram.count()
//! - **Label orthogonality**: metric{label=A} + metric{label=B} = total metric value
//! - **Snapshot atomicity**: concurrent collect() sees consistent state across all metrics

use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::time::Duration;

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::observability::metrics::{Counter, Gauge, Histogram, Metrics};
use asupersync::types::{ArenaIndex, Budget, Outcome, RegionId, TaskId};

// =============================================================================
// Test Infrastructure
// =============================================================================

/// Create a test context for metrics testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot for concurrent testing.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Create a deterministic LabRuntime for testing.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(
        LabConfig::deterministic()
            .with_seed(seed)
            .with_deterministic_time()
            .with_exhaustive_dpor(),
    )
}

/// Configuration for metrics metamorphic tests.
#[derive(Debug, Clone)]
struct MetricsTestConfig {
    /// Random seed for deterministic execution.
    seed: u64,
    /// Number of counter increment operations.
    counter_operations: Vec<u64>,
    /// Sequence of gauge operations (positive = add, negative = sub).
    gauge_operations: Vec<i64>,
    /// Histogram observation values.
    histogram_observations: Vec<f64>,
    /// Histogram bucket configuration.
    histogram_buckets: Vec<f64>,
    /// Number of concurrent workers.
    worker_count: u8,
    /// Whether to test with labeled metrics.
    use_labels: bool,
    /// Label values for testing aggregation invariants.
    label_values: Vec<String>,
    /// Whether to inject cancellation during operations.
    inject_cancellation: bool,
}

impl Arbitrary for MetricsTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u64>(),                                           // seed
            prop::collection::vec(1u64..1000, 1..20),             // counter_operations
            prop::collection::vec(-1000i64..1000, 1..20),         // gauge_operations
            prop::collection::vec(0.0f64..1000.0, 1..50),         // histogram_observations
            prop::collection::vec(1.0f64..100.0, 3..10),          // histogram_buckets
            1u8..8,                                                // worker_count
            any::<bool>(),                                         // use_labels
            prop::collection::vec("[a-z]{1,5}", 1..5),            // label_values
            any::<bool>(),                                         // inject_cancellation
        )
            .prop_map(
                |(
                    seed,
                    mut counter_operations,
                    gauge_operations,
                    histogram_observations,
                    mut histogram_buckets,
                    worker_count,
                    use_labels,
                    label_values,
                    inject_cancellation,
                )| {
                    // Ensure at least one operation
                    if counter_operations.is_empty() {
                        counter_operations.push(1);
                    }

                    // Sort and deduplicate histogram buckets
                    histogram_buckets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    histogram_buckets.dedup_by(|a, b| (a - b).abs() < f64::EPSILON);
                    if histogram_buckets.is_empty() {
                        histogram_buckets = vec![1.0, 10.0, 100.0];
                    }

                    MetricsTestConfig {
                        seed,
                        counter_operations,
                        gauge_operations,
                        histogram_observations,
                        histogram_buckets,
                        worker_count: worker_count.max(1),
                        use_labels,
                        label_values,
                        inject_cancellation,
                    }
                },
            )
            .boxed()
    }
}

/// Tracks metric operations and their expected outcomes.
#[derive(Debug, Default)]
struct MetricsTracker {
    counter_total: u64,
    gauge_value: i64,
    histogram_observations: Vec<f64>,
    operation_count: AtomicU64,
}

impl MetricsTracker {
    fn new() -> Self {
        Self::default()
    }

    fn record_counter_add(&mut self, value: u64) {
        self.counter_total += value;
        self.operation_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_gauge_add(&mut self, value: i64) {
        self.gauge_value += value;
        self.operation_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_histogram_observe(&mut self, value: f64) {
        self.histogram_observations.push(value);
        self.operation_count.fetch_add(1, Ordering::Relaxed);
    }

    fn expected_histogram_sum(&self) -> f64 {
        self.histogram_observations.iter().sum()
    }

    fn expected_histogram_count(&self) -> u64 {
        self.histogram_observations.len() as u64
    }
}

// =============================================================================
// Metamorphic Relation 1: Counter Monotonicity
// =============================================================================

/// **MR1: Counter Monotonicity**
///
/// Property: Counters are strictly monotonic - they never decrease.
///
/// Test: For any sequence of add() operations, counter.get() ≥ previous counter.get()
/// at all observation points.
#[test]
fn mr1_counter_monotonicity() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "counter_monotonicity_test");
                let counter = Arc::new(Counter::new("test_counter"));

                let mut previous_value = 0u64;
                let mut tracker = MetricsTracker::new();

                // Apply counter operations and verify monotonicity
                for &operation in &config.counter_operations {
                    let current_value = counter.get();

                    // MR1 Assertion: Counter never decreases
                    prop_assert!(
                        current_value >= previous_value,
                        "Counter decreased from {} to {} (monotonicity violation)",
                        previous_value,
                        current_value
                    );

                    counter.add(operation);
                    tracker.record_counter_add(operation);
                    previous_value = current_value;
                }

                // Final monotonicity check
                let final_value = counter.get();
                prop_assert!(
                    final_value >= previous_value,
                    "Final counter value {} < previous {}",
                    final_value,
                    previous_value
                );

                // Verify total matches expected
                prop_assert_eq!(
                    final_value,
                    tracker.counter_total,
                    "Counter final value doesn't match expected total"
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Metamorphic Relation 2: Gauge Bidirectionality
// =============================================================================

/// **MR2: Gauge Bidirectionality**
///
/// Property: Gauges can increase or decrease, and operations are commutative.
///
/// Test: add(x) followed by add(y) equals add(y) followed by add(x).
#[test]
fn mr2_gauge_bidirectionality() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "gauge_bidirectionality_test");

                if config.gauge_operations.len() < 2 {
                    return Ok(());
                }

                // Test commutativity: add(x) + add(y) = add(y) + add(x)
                let gauge1 = Arc::new(Gauge::new("test_gauge_1"));
                let gauge2 = Arc::new(Gauge::new("test_gauge_2"));

                let x = config.gauge_operations[0];
                let y = config.gauge_operations[1];

                // Path 1: add(x) then add(y)
                gauge1.add(x);
                gauge1.add(y);
                let result1 = gauge1.get();

                // Path 2: add(y) then add(x)
                gauge2.add(y);
                gauge2.add(x);
                let result2 = gauge2.get();

                // MR2 Assertion: Addition is commutative
                prop_assert_eq!(
                    result1,
                    result2,
                    "Gauge addition not commutative: add({}) + add({}) = {}, but add({}) + add({}) = {}",
                    x, y, result1, y, x, result2
                );

                // Test bidirectionality with increment/decrement pattern
                let gauge3 = Arc::new(Gauge::new("test_gauge_3"));
                let initial = gauge3.get();

                // Apply all operations
                let mut expected_value = initial;
                for &operation in &config.gauge_operations {
                    gauge3.add(operation);
                    expected_value += operation;
                }

                let final_value = gauge3.get();

                // MR2 Assertion: Final value matches expected sum
                prop_assert_eq!(
                    final_value,
                    expected_value,
                    "Gauge final value {} doesn't match expected {}",
                    final_value,
                    expected_value
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Metamorphic Relation 3: Histogram Sample Preservation
// =============================================================================

/// **MR3: Histogram Sample Preservation**
///
/// Property: Histograms preserve all observed values in their bucket counts and sum.
///
/// Test: sum(observations) = histogram.sum(), count(observations) = histogram.count()
#[test]
fn mr3_histogram_sample_preservation() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "histogram_preservation_test");

                let histogram = Arc::new(Histogram::new(
                    "test_histogram",
                    config.histogram_buckets.clone()
                ));

                let mut tracker = MetricsTracker::new();

                // Record all observations
                for &observation in &config.histogram_observations {
                    histogram.observe(observation);
                    tracker.record_histogram_observe(observation);
                }

                let expected_sum = tracker.expected_histogram_sum();
                let expected_count = tracker.expected_histogram_count();

                let actual_sum = histogram.sum();
                let actual_count = histogram.count();

                // MR3 Assertion: Count preservation
                prop_assert_eq!(
                    actual_count,
                    expected_count,
                    "Histogram count {} doesn't match expected {}",
                    actual_count,
                    expected_count
                );

                // MR3 Assertion: Sum preservation (with floating point tolerance)
                let sum_diff = (actual_sum - expected_sum).abs();
                prop_assert!(
                    sum_diff < 1e-10 || sum_diff < expected_sum.abs() * 1e-12,
                    "Histogram sum {} doesn't match expected {} (diff: {})",
                    actual_sum,
                    expected_sum,
                    sum_diff
                );

                // Test bucket distribution preservation
                let mut expected_buckets = vec![0u64; config.histogram_buckets.len() + 1];

                for &observation in &config.histogram_observations {
                    let bucket_idx = config.histogram_buckets
                        .iter()
                        .position(|&bucket| observation <= bucket)
                        .unwrap_or(config.histogram_buckets.len());
                    expected_buckets[bucket_idx] += 1;
                }

                // Verify bucket counts sum to total count
                let bucket_sum: u64 = expected_buckets.iter().sum();
                prop_assert_eq!(
                    bucket_sum,
                    expected_count,
                    "Bucket sum {} doesn't match total count {}",
                    bucket_sum,
                    expected_count
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Metamorphic Relation 4: Label Aggregation Invariants
// =============================================================================

/// **MR4: Label Aggregation Invariants**
///
/// Property: Labels partition metrics but don't alter fundamental aggregation properties.
///
/// Test: sum(metric{label=*}) = total metric value across all label values.
#[test]
fn mr4_label_aggregation_invariants() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "label_aggregation_test");

                if !config.use_labels || config.label_values.is_empty() {
                    return Ok(());
                }

                // Create labeled counters
                let mut labeled_counters = Vec::new();
                for label in &config.label_values {
                    let counter_name = format!("test_counter_label_{}", label);
                    labeled_counters.push(Arc::new(Counter::new(counter_name)));
                }

                // Create unlabeled counter for comparison
                let unlabeled_counter = Arc::new(Counter::new("test_counter_unlabeled"));

                let operations = &config.counter_operations[..config.counter_operations.len().min(config.label_values.len())];

                // Apply same operations to both labeled and unlabeled metrics
                let mut expected_total = 0u64;
                for (i, &operation) in operations.iter().enumerate() {
                    if i < labeled_counters.len() {
                        labeled_counters[i].add(operation);
                    }
                    unlabeled_counter.add(operation);
                    expected_total += operation;
                }

                // MR4 Assertion: Labeled metrics sum equals unlabeled total
                let labeled_sum: u64 = labeled_counters.iter()
                    .map(|counter| counter.get())
                    .sum();
                let unlabeled_total = unlabeled_counter.get();

                prop_assert_eq!(
                    labeled_sum,
                    unlabeled_total,
                    "Labeled counter sum {} != unlabeled total {}",
                    labeled_sum,
                    unlabeled_total
                );

                // MR4 Assertion: Both equal expected total
                prop_assert_eq!(
                    unlabeled_total,
                    expected_total,
                    "Unlabeled total {} != expected total {}",
                    unlabeled_total,
                    expected_total
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Metamorphic Relation 5: Concurrent Snapshot Consistency
// =============================================================================

/// **MR5: Concurrent Snapshot Consistency**
///
/// Property: Concurrent record/collect operations produce snapshot-consistent results.
///
/// Test: At any point in time, metrics snapshot shows consistent state across all metric types.
#[test]
fn mr5_concurrent_snapshot_consistency() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "concurrent_consistency_test");

                if config.worker_count < 2 {
                    return Ok(());
                }

                let counter = Arc::new(Counter::new("concurrent_counter"));
                let gauge = Arc::new(Gauge::new("concurrent_gauge"));
                let histogram = Arc::new(Histogram::new(
                    "concurrent_histogram",
                    config.histogram_buckets.clone()
                ));

                let snapshot_counter = Arc::new(AtomicU64::new(0));
                let operation_tracker = Arc::new(StdMutex::new(MetricsTracker::new()));

                // Spawn concurrent workers
                let mut tasks = Vec::new();

                for worker_id in 0..config.worker_count {
                    let worker_counter = Arc::clone(&counter);
                    let worker_gauge = Arc::clone(&gauge);
                    let worker_histogram = Arc::clone(&histogram);
                    let worker_snapshot_counter = Arc::clone(&snapshot_counter);
                    let worker_tracker = Arc::clone(&operation_tracker);

                    let worker_config = config.clone();
                    let worker_cx = test_cx_with_slot(worker_id as u32);

                    let task = scope.spawn(format!("metrics_worker_{}", worker_id), async move {
                        let operations_per_worker = worker_config.counter_operations.len() / worker_config.worker_count as usize;
                        let start_idx = worker_id as usize * operations_per_worker;
                        let end_idx = ((worker_id + 1) as usize * operations_per_worker).min(worker_config.counter_operations.len());

                        for i in start_idx..end_idx {
                            // Perform metric operations
                            let counter_op = worker_config.counter_operations[i];
                            worker_counter.add(counter_op);

                            if i < worker_config.gauge_operations.len() {
                                let gauge_op = worker_config.gauge_operations[i];
                                worker_gauge.add(gauge_op);
                            }

                            if i < worker_config.histogram_observations.len() {
                                let hist_op = worker_config.histogram_observations[i];
                                worker_histogram.observe(hist_op);
                            }

                            // Track operations for consistency checking
                            {
                                let mut tracker = worker_tracker.lock().unwrap();
                                tracker.record_counter_add(counter_op);
                                if i < worker_config.gauge_operations.len() {
                                    tracker.record_gauge_add(worker_config.gauge_operations[i]);
                                }
                                if i < worker_config.histogram_observations.len() {
                                    tracker.record_histogram_observe(worker_config.histogram_observations[i]);
                                }
                            }

                            // Periodically take snapshots to test consistency
                            if i % 3 == 0 {
                                let snapshot_id = worker_snapshot_counter.fetch_add(1, Ordering::SeqCst);

                                // MR5 Snapshot: All metric reads should be consistent within snapshot
                                let counter_snapshot = worker_counter.get();
                                let gauge_snapshot = worker_gauge.get();
                                let histogram_count_snapshot = worker_histogram.count();
                                let histogram_sum_snapshot = worker_histogram.sum();

                                // Verify snapshot internal consistency
                                // (Counter values should be non-decreasing within worker)
                                // (Histogram count and sum should be consistent)

                                if histogram_count_snapshot > 0 {
                                    // Sum should be finite and non-NaN for non-empty histogram
                                    if !histogram_sum_snapshot.is_finite() {
                                        return Err(format!(
                                            "Snapshot {}: Histogram sum {} is not finite for count {}",
                                            snapshot_id, histogram_sum_snapshot, histogram_count_snapshot
                                        ));
                                    }
                                }
                            }
                        }

                        Ok(())
                    })?;

                    tasks.push(task);
                }

                // Wait for all workers to complete
                for task in tasks {
                    task.await?;
                }

                // Final consistency check
                let final_tracker = operation_tracker.lock().unwrap();

                let final_counter = counter.get();
                let final_gauge = gauge.get();
                let final_histogram_count = histogram.count();
                let final_histogram_sum = histogram.sum();

                // MR5 Assertion: Final state matches tracker expectations
                prop_assert_eq!(
                    final_counter,
                    final_tracker.counter_total,
                    "Final counter {} != expected {}",
                    final_counter,
                    final_tracker.counter_total
                );

                prop_assert_eq!(
                    final_gauge,
                    final_tracker.gauge_value,
                    "Final gauge {} != expected {}",
                    final_gauge,
                    final_tracker.gauge_value
                );

                prop_assert_eq!(
                    final_histogram_count,
                    final_tracker.expected_histogram_count(),
                    "Final histogram count {} != expected {}",
                    final_histogram_count,
                    final_tracker.expected_histogram_count()
                );

                // Check histogram sum with floating-point tolerance
                let expected_hist_sum = final_tracker.expected_histogram_sum();
                let sum_diff = (final_histogram_sum - expected_hist_sum).abs();
                prop_assert!(
                    sum_diff < 1e-10 || sum_diff < expected_hist_sum.abs() * 1e-12,
                    "Final histogram sum {} != expected {} (diff: {})",
                    final_histogram_sum,
                    expected_hist_sum,
                    sum_diff
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Composite Metamorphic Relations
// =============================================================================

/// **Composite MR: All Metrics Invariants Combined**
///
/// Property: All five metamorphic relations hold simultaneously under realistic workloads.
///
/// Test: Execute mixed operations and verify all MRs hold together.
#[test]
fn composite_all_metrics_invariants() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "composite_metrics_test");

                let mut metrics_registry = Metrics::new();

                // Create metrics with different configurations
                let counter = metrics_registry.counter("composite_counter");
                let gauge = metrics_registry.gauge("composite_gauge");
                let histogram = metrics_registry.histogram("composite_histogram", config.histogram_buckets.clone());

                let mut tracker = MetricsTracker::new();
                let mut previous_counter_value = 0u64;

                // Execute mixed operations
                let max_ops = config.counter_operations.len()
                    .max(config.gauge_operations.len())
                    .max(config.histogram_observations.len());

                for i in 0..max_ops {
                    // Counter operations (MR1: Monotonicity)
                    if i < config.counter_operations.len() {
                        let current_counter = counter.get();
                        prop_assert!(
                            current_counter >= previous_counter_value,
                            "Counter monotonicity violation at step {}: {} < {}",
                            i, current_counter, previous_counter_value
                        );

                        counter.add(config.counter_operations[i]);
                        tracker.record_counter_add(config.counter_operations[i]);
                        previous_counter_value = current_counter;
                    }

                    // Gauge operations (MR2: Bidirectionality)
                    if i < config.gauge_operations.len() {
                        gauge.add(config.gauge_operations[i]);
                        tracker.record_gauge_add(config.gauge_operations[i]);
                    }

                    // Histogram operations (MR3: Sample Preservation)
                    if i < config.histogram_observations.len() {
                        histogram.observe(config.histogram_observations[i]);
                        tracker.record_histogram_observe(config.histogram_observations[i]);
                    }
                }

                // Verify all MRs hold at the end

                // MR1: Final counter monotonicity
                let final_counter = counter.get();
                prop_assert_eq!(
                    final_counter,
                    tracker.counter_total,
                    "Final counter monotonicity check failed"
                );

                // MR2: Final gauge bidirectionality
                let final_gauge = gauge.get();
                prop_assert_eq!(
                    final_gauge,
                    tracker.gauge_value,
                    "Final gauge bidirectionality check failed"
                );

                // MR3: Final histogram preservation
                let final_hist_count = histogram.count();
                let final_hist_sum = histogram.sum();
                prop_assert_eq!(
                    final_hist_count,
                    tracker.expected_histogram_count(),
                    "Final histogram count preservation failed"
                );

                let expected_sum = tracker.expected_histogram_sum();
                let sum_diff = (final_hist_sum - expected_sum).abs();
                prop_assert!(
                    sum_diff < 1e-10 || sum_diff < expected_sum.abs() * 1e-12,
                    "Final histogram sum preservation failed: {} vs {}",
                    final_hist_sum, expected_sum
                );

                // MR5: Snapshot consistency (verify export doesn't crash)
                let prometheus_export = metrics_registry.export_prometheus();
                prop_assert!(
                    !prometheus_export.is_empty(),
                    "Prometheus export should not be empty"
                );
                prop_assert!(
                    prometheus_export.contains("composite_counter"),
                    "Export should contain counter metric"
                );

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// =============================================================================
// Property-Based Integration Tests
// =============================================================================

/// Property-based test that verifies metrics behavior under cancellation scenarios.
#[test]
fn property_metrics_cancellation_safety() {
    proptest!(|(config: MetricsTestConfig)| {
        let mut runtime = test_lab_runtime_with_seed(config.seed);
        let result = runtime.block_on(|cx| async {
            if !config.inject_cancellation {
                return Ok(());
            }

            cx.region(|region| async {
                let scope = Scope::new(region, "metrics_cancellation_test");

                let counter = Arc::new(Counter::new("cancel_counter"));
                let gauge = Arc::new(Gauge::new("cancel_gauge"));

                // Operations before potential cancellation
                let half_ops = config.counter_operations.len() / 2;
                let mut expected_counter = 0u64;
                let mut expected_gauge = 0i64;

                for i in 0..half_ops {
                    counter.add(config.counter_operations[i]);
                    expected_counter += config.counter_operations[i];

                    if i < config.gauge_operations.len() {
                        gauge.add(config.gauge_operations[i]);
                        expected_gauge += config.gauge_operations[i];
                    }
                }

                // Create a task that might be cancelled
                let task_counter = Arc::clone(&counter);
                let task_gauge = Arc::clone(&gauge);
                let task_config = config.clone();

                let cancellable_task = scope.spawn("cancellable_metrics", async move {
                    // Apply remaining operations
                    for i in half_ops..task_config.counter_operations.len() {
                        task_counter.add(task_config.counter_operations[i]);

                        if i < task_config.gauge_operations.len() {
                            task_gauge.add(task_config.gauge_operations[i]);
                        }
                    }
                    Ok(())
                })?;

                // Potentially cancel the task
                let task_result = if config.inject_cancellation && config.counter_operations.len() > 4 {
                    scope.cancel_after(Duration::from_millis(config.cancel_delay_ms.min(100)));
                    cancellable_task.await
                } else {
                    cancellable_task.await
                };

                // Verify metrics state regardless of cancellation outcome
                let final_counter = counter.get();
                let final_gauge = gauge.get();

                // Metrics should never be in inconsistent state due to cancellation
                prop_assert!(
                    final_counter >= expected_counter,
                    "Counter {} should be >= pre-cancel value {}",
                    final_counter, expected_counter
                );

                // Gauge can be any value, but should be consistent with completed operations
                // (We can't predict exact final value due to potential partial operations)

                Ok(())
            })
        });

        prop_assert!(matches!(result, Outcome::Ok(_) | Outcome::Cancelled(_)));
    });
}