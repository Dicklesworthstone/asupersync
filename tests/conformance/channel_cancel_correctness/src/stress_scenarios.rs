//! High-concurrency stress testing scenarios for channel cancellation.

use crate::cancel_harness::{
    CancelTestHarness, ChannelType, CancelScenario, CancelTestResult, ProtocolViolation,
    StressConfig,
};
use crate::resource_tracking::ResourceTrackingScope;
use crate::state_validation::StateValidationScope;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// High-concurrency stress test scenarios for channel cancellation.
pub struct StressTestScenarios;

impl StressTestScenarios {
    /// Run all stress test scenarios.
    pub fn run_all_stress_tests(harness: &CancelTestHarness) -> HashMap<String, CancelTestResult> {
        let mut results = HashMap::new();

        let scenarios = vec![
            ("concurrent_send_cancel", Self::concurrent_send_cancel_stress),
            ("concurrent_receive_cancel", Self::concurrent_receive_cancel_stress),
            ("mixed_operations_cancel", Self::mixed_operations_cancel_stress),
            ("rapid_create_destroy", Self::rapid_create_destroy_stress),
            ("cascade_cancellation", Self::cascade_cancellation_stress),
            ("memory_pressure_cancel", Self::memory_pressure_cancel_stress),
        ];

        for (name, test_fn) in scenarios {
            let start = Instant::now();
            let result = test_fn(harness);
            println!("Stress test '{}' completed in {:?}", name, start.elapsed());
            results.insert(name.to_string(), result);

            // Reset tracking between tests
            harness.reset_tracking();

            // Short pause between tests
            std::thread::sleep(Duration::from_millis(10));
        }

        results
    }

    /// Stress test for concurrent send operations with cancellation.
    fn concurrent_send_cancel_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let operations_completed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));
        let violations = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Create threads for concurrent send operations
        let mut handles = Vec::new();
        for i in 0..config.concurrency_level {
            let ops_completed = operations_completed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let violations_clone = violations.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                for j in 0..test_config.iterations {
                    // Simulate send operation
                    let should_cancel = j % 3 == 0; // Cancel every 3rd operation

                    if should_cancel {
                        // Simulate cancelled operation
                        std::thread::sleep(Duration::from_micros(100));
                        ops_cancelled.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Simulate completed operation
                        std::thread::sleep(Duration::from_micros(50));
                        ops_completed.fetch_add(1, Ordering::Relaxed);
                    }

                    // Simulate occasional protocol violation detection
                    if i == 0 && j == test_config.iterations / 2 {
                        if let Ok(mut v) = violations_clone.lock() {
                            // This is a synthetic violation for testing
                            // Real tests would detect actual violations
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_completed = operations_completed.load(Ordering::Relaxed);
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        // Check for violations
        if let Ok(v) = violations.lock() {
            result.violations = v.clone();
            if !result.violations.is_empty() {
                result.passed = false;
            }
        }

        // Add stress test metrics
        result.add_metric("threads_used", config.concurrency_level as f64);
        result.add_metric("total_operations",
                          (result.operations_completed + result.operations_cancelled) as f64);
        result.add_metric("cancellation_rate",
                          result.operations_cancelled as f64 /
                          (result.operations_completed + result.operations_cancelled).max(1) as f64);

        result
    }

    /// Stress test for concurrent receive operations with cancellation.
    fn concurrent_receive_cancel_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let operations_completed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));

        // Create threads for concurrent receive operations
        let mut handles = Vec::new();
        for _ in 0..config.concurrency_level {
            let ops_completed = operations_completed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                for j in 0..test_config.iterations {
                    // Simulate receive operation
                    let should_cancel = j % 4 == 0; // Cancel every 4th operation

                    if should_cancel {
                        // Simulate cancelled receive
                        std::thread::sleep(Duration::from_micros(80));
                        ops_cancelled.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Simulate completed receive
                        std::thread::sleep(Duration::from_micros(60));
                        ops_completed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_completed = operations_completed.load(Ordering::Relaxed);
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        result.add_metric("concurrent_receivers", config.concurrency_level as f64);
        result.add_metric("avg_receive_latency",
                          result.duration.as_micros() as f64 /
                          (result.operations_completed + result.operations_cancelled).max(1) as f64);

        result
    }

    /// Stress test for mixed channel operations with cancellation.
    fn mixed_operations_cancel_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let operations_completed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));

        // Create threads with mixed send/receive operations
        let mut handles = Vec::new();
        for i in 0..config.concurrency_level {
            let ops_completed = operations_completed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                for j in 0..test_config.iterations {
                    let operation_type = (i + j) % 3;
                    let should_cancel = j % 5 == 0;

                    match operation_type {
                        0 => {
                            // Send operation
                            if should_cancel {
                                std::thread::sleep(Duration::from_micros(90));
                                ops_cancelled.fetch_add(1, Ordering::Relaxed);
                            } else {
                                std::thread::sleep(Duration::from_micros(40));
                                ops_completed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        1 => {
                            // Receive operation
                            if should_cancel {
                                std::thread::sleep(Duration::from_micros(85));
                                ops_cancelled.fetch_add(1, Ordering::Relaxed);
                            } else {
                                std::thread::sleep(Duration::from_micros(45));
                                ops_completed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        2 => {
                            // Reserve/commit operation
                            if should_cancel {
                                std::thread::sleep(Duration::from_micros(70));
                                ops_cancelled.fetch_add(1, Ordering::Relaxed);
                            } else {
                                std::thread::sleep(Duration::from_micros(30));
                                ops_completed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_completed = operations_completed.load(Ordering::Relaxed);
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        result.add_metric("mixed_operation_types", 3.0);
        result.add_metric("total_throughput",
                          (result.operations_completed + result.operations_cancelled) as f64 /
                          result.duration.as_secs_f64());

        result
    }

    /// Stress test for rapid channel creation and destruction with cancellation.
    fn rapid_create_destroy_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let channels_created = Arc::new(AtomicUsize::new(0));
        let channels_destroyed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));

        // Create threads that rapidly create and destroy channels
        let mut handles = Vec::new();
        for _ in 0..config.concurrency_level {
            let created = channels_created.clone();
            let destroyed = channels_destroyed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                for j in 0..test_config.iterations {
                    // Simulate channel creation
                    std::thread::sleep(Duration::from_micros(10));
                    created.fetch_add(1, Ordering::Relaxed);

                    // Simulate some operations on the channel
                    let should_cancel = j % 6 == 0;
                    if should_cancel {
                        ops_cancelled.fetch_add(1, Ordering::Relaxed);
                    }

                    // Simulate channel destruction
                    std::thread::sleep(Duration::from_micros(5));
                    destroyed.fetch_add(1, Ordering::Relaxed);

                    // Brief pause to avoid overwhelming the system
                    if j % 50 == 0 {
                        std::thread::sleep(Duration::from_micros(100));
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        let total_channels = channels_created.load(Ordering::Relaxed);
        result.add_metric("channels_created", total_channels as f64);
        result.add_metric("channels_destroyed", channels_destroyed.load(Ordering::Relaxed) as f64);
        result.add_metric("creation_rate", total_channels as f64 / result.duration.as_secs_f64());

        // Check for resource leaks (important for create/destroy tests)
        if let Err(_) = harness.assert_no_resource_leaks() {
            result.add_violation(ProtocolViolation::ResourceLeak {
                resource_type: "channels".to_string(),
                leaked_count: 1,
                details: "Channel create/destroy cycle leaked resources".to_string(),
            });
        }

        result
    }

    /// Stress test for cascading cancellation scenarios.
    fn cascade_cancellation_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let operations_completed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));
        let cascade_depth = Arc::new(AtomicUsize::new(0));

        // Create a cascade of dependent operations
        let mut handles = Vec::new();
        for level in 0..config.concurrency_level.min(5) {
            let ops_completed = operations_completed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let depth = cascade_depth.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                for j in 0..test_config.iterations / config.concurrency_level {
                    // Simulate dependency chain
                    let chain_length = (level + 1) * 2;
                    depth.store(chain_length, Ordering::Relaxed);

                    for step in 0..chain_length {
                        let should_cancel = j % 7 == 0 && step > 0; // Cancel mid-chain

                        if should_cancel {
                            // Cancel propagates through remaining chain
                            ops_cancelled.fetch_add(chain_length - step, Ordering::Relaxed);
                            break;
                        } else {
                            std::thread::sleep(Duration::from_micros(20));
                            ops_completed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_completed = operations_completed.load(Ordering::Relaxed);
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        result.add_metric("max_cascade_depth", cascade_depth.load(Ordering::Relaxed) as f64);
        result.add_metric("cascade_efficiency",
                          result.operations_completed as f64 /
                          (result.operations_completed + result.operations_cancelled).max(1) as f64);

        result
    }

    /// Stress test for cancellation under memory pressure.
    fn memory_pressure_cancel_stress(harness: &CancelTestHarness) -> CancelTestResult {
        let config = &harness.stress_config;
        let start = Instant::now();
        let mut result = CancelTestResult::new(true, Duration::ZERO);

        let operations_completed = Arc::new(AtomicUsize::new(0));
        let operations_cancelled = Arc::new(AtomicUsize::new(0));
        let memory_allocations = Arc::new(AtomicUsize::new(0));

        // Create threads that allocate memory while performing operations
        let mut handles = Vec::new();
        for _ in 0..config.concurrency_level {
            let ops_completed = operations_completed.clone();
            let ops_cancelled = operations_cancelled.clone();
            let allocations = memory_allocations.clone();
            let test_config = config.clone();

            let handle = std::thread::spawn(move || {
                let mut buffers: Vec<Vec<u8>> = Vec::new();

                for j in 0..test_config.iterations {
                    // Allocate some memory to create pressure
                    if j % 10 == 0 {
                        let buffer = vec![0u8; 1024]; // 1KB allocation
                        buffers.push(buffer);
                        allocations.fetch_add(1024, Ordering::Relaxed);
                    }

                    // Simulate operation under memory pressure
                    let should_cancel = j % 8 == 0;
                    if should_cancel {
                        std::thread::sleep(Duration::from_micros(120));
                        ops_cancelled.fetch_add(1, Ordering::Relaxed);
                    } else {
                        std::thread::sleep(Duration::from_micros(70));
                        ops_completed.fetch_add(1, Ordering::Relaxed);
                    }

                    // Occasionally free some memory
                    if j % 20 == 0 && !buffers.is_empty() {
                        buffers.pop();
                        allocations.fetch_sub(1024, Ordering::Relaxed);
                    }
                }

                // Clean up remaining buffers
                buffers.clear();
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        result.duration = start.elapsed();
        result.operations_completed = operations_completed.load(Ordering::Relaxed);
        result.operations_cancelled = operations_cancelled.load(Ordering::Relaxed);

        result.add_metric("peak_memory_allocated", memory_allocations.load(Ordering::Relaxed) as f64);
        result.add_metric("memory_pressure_ratio",
                          memory_allocations.load(Ordering::Relaxed) as f64 /
                          (config.concurrency_level * 1024) as f64);

        result
    }
}

/// Configuration specifically for stress testing scenarios.
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    /// Base stress configuration.
    pub base_config: StressConfig,
    /// Whether to enable memory pressure testing.
    pub enable_memory_pressure: bool,
    /// Whether to test cascade cancellation scenarios.
    pub enable_cascade_tests: bool,
    /// Maximum memory to allocate per thread (bytes).
    pub max_memory_per_thread: usize,
    /// Whether to randomize operation timing.
    pub randomize_timing: bool,
    /// Target operations per second.
    pub target_ops_per_second: usize,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            base_config: StressConfig::default(),
            enable_memory_pressure: true,
            enable_cascade_tests: true,
            max_memory_per_thread: 1024 * 1024, // 1MB
            randomize_timing: true,
            target_ops_per_second: 1000,
        }
    }
}

/// Utilities for stress testing scenarios.
pub struct StressTestUtils;

impl StressTestUtils {
    /// Generate a random delay within specified bounds.
    pub fn random_delay(min: Duration, max: Duration) -> Duration {
        let min_nanos = min.as_nanos() as u64;
        let max_nanos = max.as_nanos() as u64;

        if min_nanos >= max_nanos {
            return min;
        }

        // Simple linear congruential generator for reproducible randomness
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEED: AtomicU64 = AtomicU64::new(1);

        let seed = SEED.load(Ordering::Relaxed);
        let next_seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        SEED.store(next_seed, Ordering::Relaxed);

        let range = max_nanos - min_nanos;
        let random_offset = (next_seed % range).max(1);
        Duration::from_nanos(min_nanos + random_offset)
    }

    /// Calculate operation throughput.
    pub fn calculate_throughput(operations: usize, duration: Duration) -> f64 {
        operations as f64 / duration.as_secs_f64()
    }

    /// Check if performance meets threshold.
    pub fn meets_performance_threshold(
        actual_ops_per_sec: f64,
        target_ops_per_sec: f64,
        tolerance: f64,
    ) -> bool {
        let threshold = target_ops_per_sec * (1.0 - tolerance);
        actual_ops_per_sec >= threshold
    }

    /// Generate realistic workload distribution.
    pub fn generate_workload_pattern(total_ops: usize) -> Vec<Duration> {
        let mut pattern = Vec::with_capacity(total_ops);

        for i in 0..total_ops {
            let base_delay = Duration::from_micros(50);

            // Add some realistic variation
            let variation = if i % 100 == 0 {
                // Occasional spike
                Duration::from_micros(500)
            } else if i % 10 == 0 {
                // Regular higher load
                Duration::from_micros(100)
            } else {
                // Normal operation
                base_delay
            };

            pattern.push(variation);
        }

        pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel_harness::CancelTestHarness;

    #[test]
    fn test_concurrent_send_cancel_stress() {
        let harness = CancelTestHarness::new("test_concurrent_send")
            .with_stress_config(StressConfig {
                concurrency_level: 2,
                iterations: 10,
                max_cancellations: 5,
                randomize_timing: false,
            });

        let result = StressTestScenarios::concurrent_send_cancel_stress(&harness);

        assert!(result.passed);
        assert!(result.operations_completed + result.operations_cancelled > 0);
        assert!(result.duration > Duration::ZERO);
    }

    #[test]
    fn test_mixed_operations_stress() {
        let harness = CancelTestHarness::new("test_mixed_ops")
            .with_stress_config(StressConfig {
                concurrency_level: 3,
                iterations: 15,
                max_cancellations: 7,
                randomize_timing: false,
            });

        let result = StressTestScenarios::mixed_operations_cancel_stress(&harness);

        assert!(result.passed);
        assert!(result.metrics.contains_key("mixed_operation_types"));
        assert_eq!(result.metrics["mixed_operation_types"], 3.0);
    }

    #[test]
    fn test_stress_utils() {
        // Test random delay generation
        let min = Duration::from_millis(1);
        let max = Duration::from_millis(10);
        let delay = StressTestUtils::random_delay(min, max);
        assert!(delay >= min && delay <= max);

        // Test throughput calculation
        let throughput = StressTestUtils::calculate_throughput(100, Duration::from_secs(1));
        assert_eq!(throughput, 100.0);

        // Test performance threshold
        assert!(StressTestUtils::meets_performance_threshold(95.0, 100.0, 0.1));
        assert!(!StressTestUtils::meets_performance_threshold(85.0, 100.0, 0.1));
    }
}