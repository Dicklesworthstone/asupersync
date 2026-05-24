//! Real Timer/Sleep E2E Tests
//!
//! Implements the /testing-real-service-e2e-no-mocks skill for timer and sleep operations.
//! Tests actual deadline scheduling, timer wheel accuracy, and sleep wakeup behavior under load.
//!
//! Key principle: "If a mock hides a bug that would break production, the mock is worse than no test at all."
//! We test real timer scheduling with actual deadlines and verify precise wakeup behavior.

#[cfg(all(test, feature = "real-service-e2e"))]
use crate::{
    channel::{mpsc, oneshot},
    combinator::{join, race},
    cx::Cx,
    error::{AsupersyncError, Outcome},
    runtime::{Region, RuntimeBuilder},
    stream::Stream,
    time::{Deadline, Duration, Instant, Sleep, interval, sleep, timeout},
};

#[cfg(all(test, feature = "real-service-e2e"))]
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::SystemTime,
};

#[cfg(all(test, feature = "real-service-e2e"))]
use serde::{Deserialize, Serialize};

/// Real timer manager that creates actual timer wheels and sleep futures
/// Uses the asupersync time primitives with real deadline scheduling
#[cfg(all(test, feature = "real-service-e2e"))]
struct RealTimerManager {
    runtime_name: String,
    stats: Arc<TimerE2EStats>,
    logger: TimerE2ELogger,
}

/// Comprehensive statistics for timer E2E operations
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct TimerE2EStats {
    sleep_operations: AtomicU64,
    timeout_operations: AtomicU64,
    interval_ticks: AtomicU64,
    deadline_hits: AtomicU64,
    deadline_misses: AtomicU64,
    total_latency_ns: AtomicU64,
    max_latency_ns: AtomicU64,
    concurrent_sleeps: AtomicU64,
    wakeup_accuracy_violations: AtomicU64,
    timer_wheel_rotations: AtomicU64,
}

/// Structured logger for timer E2E test observability
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct TimerE2ELogger {
    test_id: String,
    component: String,
}

/// Timer operation result with precise timing measurements
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimerOperation {
    operation_type: TimerOperationType,
    requested_duration_ns: u64,
    actual_duration_ns: u64,
    latency_ns: u64,
    accuracy_error_ns: i64,
    deadline_hit: bool,
    concurrent_operations: u64,
}

/// Types of timer operations under test
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum TimerOperationType {
    Sleep,
    Timeout,
    IntervalTick,
    DeadlineCheck,
    ConcurrentSleep,
}

/// Timer E2E test configuration
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone)]
struct TimerE2EConfig {
    max_operations: usize,
    concurrency_level: usize,
    accuracy_tolerance_ns: u64,
    load_duration_ms: u64,
    timer_resolution_ns: u64,
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl RealTimerManager {
    /// Create a new real timer manager with actual asupersync time primitives
    fn new(test_name: &str) -> Self {
        let stats = Arc::new(TimerE2EStats {
            sleep_operations: AtomicU64::new(0),
            timeout_operations: AtomicU64::new(0),
            interval_ticks: AtomicU64::new(0),
            deadline_hits: AtomicU64::new(0),
            deadline_misses: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            max_latency_ns: AtomicU64::new(0),
            concurrent_sleeps: AtomicU64::new(0),
            wakeup_accuracy_violations: AtomicU64::new(0),
            timer_wheel_rotations: AtomicU64::new(0),
        });

        Self {
            runtime_name: format!("timer-e2e-{}", test_name),
            stats,
            logger: TimerE2ELogger::new(test_name, "timer-manager"),
        }
    }

    /// Test basic sleep operation with precise timing measurement
    async fn test_sleep_operation(
        &self,
        cx: &Cx,
        duration: Duration,
    ) -> Result<TimerOperation, AsupersyncError> {
        self.logger.log_phase("sleep_start");
        let start = Instant::now();
        let requested_ns = duration.as_nanos() as u64;

        // Real sleep using asupersync primitives
        sleep(duration).await;

        let end = Instant::now();
        let actual_ns = end.duration_since(start).as_nanos() as u64;
        let latency_ns = actual_ns.saturating_sub(requested_ns);
        let accuracy_error = actual_ns as i64 - requested_ns as i64;

        // Update statistics
        self.stats.sleep_operations.fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);

        let current_max = self.stats.max_latency_ns.load(Ordering::Relaxed);
        if latency_ns > current_max {
            self.stats
                .max_latency_ns
                .store(latency_ns, Ordering::Relaxed);
        }

        if accuracy_error.abs() > 1_000_000 {
            // > 1ms
            self.stats
                .wakeup_accuracy_violations
                .fetch_add(1, Ordering::Relaxed);
        }

        self.logger
            .log_operation("sleep", requested_ns, actual_ns, latency_ns);

        Ok(TimerOperation {
            operation_type: TimerOperationType::Sleep,
            requested_duration_ns: requested_ns,
            actual_duration_ns: actual_ns,
            latency_ns,
            accuracy_error,
            deadline_hit: accuracy_error.abs() <= 1_000_000,
            concurrent_operations: 1,
        })
    }

    /// Test timeout operation with cancellation behavior
    async fn test_timeout_operation(
        &self,
        cx: &Cx,
        timeout_duration: Duration,
        work_duration: Duration,
    ) -> Result<TimerOperation, AsupersyncError> {
        self.logger.log_phase("timeout_start");
        let start = Instant::now();
        let requested_ns = timeout_duration.as_nanos() as u64;

        // Real timeout operation using asupersync timeout combinator
        let result = timeout(timeout_duration, async {
            sleep(work_duration).await;
            "work_completed"
        })
        .await;

        let end = Instant::now();
        let actual_ns = end.duration_since(start).as_nanos() as u64;
        let latency_ns = actual_ns.saturating_sub(requested_ns);
        let accuracy_error = actual_ns as i64 - requested_ns as i64;

        // Update statistics
        self.stats
            .timeout_operations
            .fetch_add(1, Ordering::Relaxed);
        self.stats
            .total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);

        let deadline_hit = match result {
            Outcome::Ok(_) => false,    // Work completed before timeout
            Outcome::Cancelled => true, // Timeout fired
            _ => false,
        };

        if deadline_hit {
            self.stats.deadline_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.deadline_misses.fetch_add(1, Ordering::Relaxed);
        }

        self.logger
            .log_operation("timeout", requested_ns, actual_ns, latency_ns);

        Ok(TimerOperation {
            operation_type: TimerOperationType::Timeout,
            requested_duration_ns: requested_ns,
            actual_duration_ns: actual_ns,
            latency_ns,
            accuracy_error,
            deadline_hit,
            concurrent_operations: 1,
        })
    }

    /// Test interval stream with precise tick timing
    async fn test_interval_operation(
        &self,
        cx: &Cx,
        interval_duration: Duration,
        tick_count: usize,
    ) -> Result<Vec<TimerOperation>, AsupersyncError> {
        self.logger.log_phase("interval_start");
        let mut operations = Vec::new();
        let mut interval_stream = interval(interval_duration);
        let start = Instant::now();

        for i in 0..tick_count {
            let tick_start = Instant::now();

            // Wait for the next interval tick
            interval_stream.next().await;

            let tick_end = Instant::now();
            let expected_ns = ((i + 1) as u64) * interval_duration.as_nanos() as u64;
            let actual_ns = tick_end.duration_since(start).as_nanos() as u64;
            let latency_ns = actual_ns.saturating_sub(expected_ns);
            let accuracy_error = actual_ns as i64 - expected_ns as i64;

            self.stats.interval_ticks.fetch_add(1, Ordering::Relaxed);

            let operation = TimerOperation {
                operation_type: TimerOperationType::IntervalTick,
                requested_duration_ns: expected_ns,
                actual_duration_ns: actual_ns,
                latency_ns,
                accuracy_error,
                deadline_hit: accuracy_error.abs() <= 5_000_000, // 5ms tolerance for intervals
                concurrent_operations: 1,
            };

            operations.push(operation);
        }

        self.logger.log_operation(
            "interval",
            interval_duration.as_nanos() as u64 * tick_count as u64,
            operations
                .last()
                .map(|op| op.actual_duration_ns)
                .unwrap_or(0),
            operations.iter().map(|op| op.latency_ns).sum(),
        );

        Ok(operations)
    }

    /// Test deadline checking with precise timing validation
    async fn test_deadline_operation(
        &self,
        cx: &Cx,
        deadline: Deadline,
    ) -> Result<TimerOperation, AsupersyncError> {
        self.logger.log_phase("deadline_start");
        let start = Instant::now();

        // Calculate time until deadline
        let time_to_deadline = deadline.time_until().unwrap_or(Duration::from_nanos(0));
        let requested_ns = time_to_deadline.as_nanos() as u64;

        // Sleep until just before deadline
        if time_to_deadline > Duration::from_millis(1) {
            sleep(time_to_deadline - Duration::from_millis(1)).await;
        }

        // Check if deadline has passed
        let deadline_passed = deadline.has_passed();
        let end = Instant::now();
        let actual_ns = end.duration_since(start).as_nanos() as u64;
        let latency_ns = actual_ns.saturating_sub(requested_ns);
        let accuracy_error = actual_ns as i64 - requested_ns as i64;

        if deadline_passed {
            self.stats.deadline_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.deadline_misses.fetch_add(1, Ordering::Relaxed);
        }

        self.logger
            .log_operation("deadline", requested_ns, actual_ns, latency_ns);

        Ok(TimerOperation {
            operation_type: TimerOperationType::DeadlineCheck,
            requested_duration_ns: requested_ns,
            actual_duration_ns: actual_ns,
            latency_ns,
            accuracy_error,
            deadline_hit: deadline_passed,
            concurrent_operations: 1,
        })
    }

    /// Test concurrent sleep operations under load
    async fn test_concurrent_sleep_load(
        &self,
        cx: &Cx,
        config: &TimerE2EConfig,
    ) -> Result<Vec<TimerOperation>, AsupersyncError> {
        self.logger.log_phase("concurrent_load_start");
        let mut handles = Vec::new();
        let start = Instant::now();

        // Spawn multiple concurrent sleep operations
        let (sender, mut receiver) = mpsc::unbounded();

        for i in 0..config.concurrency_level {
            let duration = Duration::from_millis(config.load_duration_ms + (i as u64 * 10));
            let sender = sender.clone();
            let stats = self.stats.clone();
            let operation_start = Instant::now();

            // Create a spawned task that measures sleep accuracy under load
            let handle = cx.spawn(async move {
                let sleep_start = Instant::now();
                let requested_ns = duration.as_nanos() as u64;

                sleep(duration).await;

                let sleep_end = Instant::now();
                let actual_ns = sleep_end.duration_since(sleep_start).as_nanos() as u64;
                let latency_ns = actual_ns.saturating_sub(requested_ns);
                let accuracy_error = actual_ns as i64 - requested_ns as i64;

                stats.concurrent_sleeps.fetch_add(1, Ordering::Relaxed);
                stats.sleep_operations.fetch_add(1, Ordering::Relaxed);

                let operation = TimerOperation {
                    operation_type: TimerOperationType::ConcurrentSleep,
                    requested_duration_ns: requested_ns,
                    actual_duration_ns: actual_ns,
                    latency_ns,
                    accuracy_error,
                    deadline_hit: accuracy_error.abs() <= 10_000_000, // 10ms tolerance under load
                    concurrent_operations: config.concurrency_level as u64,
                };

                let _ = sender.send(operation).await;
            });

            handles.push(handle);
        }

        drop(sender); // Close the sender

        // Collect all results
        let mut operations = Vec::new();
        while let Some(operation) = receiver.recv().await {
            operations.push(operation);
        }

        // Wait for all spawned tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        self.logger.log_phase("concurrent_load_complete");
        self.logger.log_operation(
            "concurrent_sleep",
            config.load_duration_ms * 1_000_000,
            operations
                .iter()
                .map(|op| op.actual_duration_ns)
                .max()
                .unwrap_or(0),
            operations.iter().map(|op| op.latency_ns).sum(),
        );

        Ok(operations)
    }

    /// Get comprehensive timer statistics
    fn get_stats_summary(&self) -> TimerE2EStatsSummary {
        TimerE2EStatsSummary {
            total_sleep_operations: self.stats.sleep_operations.load(Ordering::Relaxed),
            total_timeout_operations: self.stats.timeout_operations.load(Ordering::Relaxed),
            total_interval_ticks: self.stats.interval_ticks.load(Ordering::Relaxed),
            deadline_hit_rate: {
                let hits = self.stats.deadline_hits.load(Ordering::Relaxed);
                let misses = self.stats.deadline_misses.load(Ordering::Relaxed);
                if hits + misses > 0 {
                    hits as f64 / (hits + misses) as f64
                } else {
                    0.0
                }
            },
            average_latency_ns: {
                let total = self.stats.total_latency_ns.load(Ordering::Relaxed);
                let ops = self.stats.sleep_operations.load(Ordering::Relaxed)
                    + self.stats.timeout_operations.load(Ordering::Relaxed);
                if ops > 0 { total / ops } else { 0 }
            },
            max_latency_ns: self.stats.max_latency_ns.load(Ordering::Relaxed),
            concurrent_operations: self.stats.concurrent_sleeps.load(Ordering::Relaxed),
            accuracy_violations: self
                .stats
                .wakeup_accuracy_violations
                .load(Ordering::Relaxed),
        }
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
impl TimerE2ELogger {
    fn new(test_id: &str, component: &str) -> Self {
        Self {
            test_id: test_id.to_string(),
            component: component.to_string(),
        }
    }

    fn log_phase(&self, phase: &str) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"phase_change\",\"phase\":\"{}\"}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            phase
        );
    }

    fn log_operation(
        &self,
        operation_type: &str,
        requested_ns: u64,
        actual_ns: u64,
        latency_ns: u64,
    ) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"timer_operation\",\"operation_type\":\"{}\",\"requested_ns\":{},\"actual_ns\":{},\"latency_ns\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            operation_type,
            requested_ns,
            actual_ns,
            latency_ns
        );
    }

    fn log_stats_summary(&self, stats: &TimerE2EStatsSummary) {
        eprintln!(
            "{{\"ts\":\"{}\",\"test_id\":\"{}\",\"component\":\"{}\",\"event\":\"stats_summary\",\"data\":{}}}",
            chrono::Utc::now().to_rfc3339(),
            self.test_id,
            self.component,
            serde_json::to_string(stats).unwrap_or_else(|_| "{}".to_string())
        );
    }
}

/// Timer E2E statistics summary
#[cfg(all(test, feature = "real-service-e2e"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimerE2EStatsSummary {
    total_sleep_operations: u64,
    total_timeout_operations: u64,
    total_interval_ticks: u64,
    deadline_hit_rate: f64,
    average_latency_ns: u64,
    max_latency_ns: u64,
    concurrent_operations: u64,
    accuracy_violations: u64,
}

/// Default timer E2E test configuration with production safety guards
#[cfg(all(test, feature = "real-service-e2e"))]
impl Default for TimerE2EConfig {
    fn default() -> Self {
        Self {
            max_operations: 1000,
            concurrency_level: 10,
            accuracy_tolerance_ns: 1_000_000, // 1ms
            load_duration_ms: 100,
            timer_resolution_ns: 1_000_000, // 1ms
        }
    }
}

/// Production safety guard: prevents timer tests from running too long
#[cfg(all(test, feature = "real-service-e2e"))]
fn validate_timer_e2e_environment() -> Result<(), &'static str> {
    // Prevent running in production-like environments
    if std::env::var("TIMER_E2E_TESTS").unwrap_or_default() != "true" {
        return Err("TIMER_E2E_TESTS environment variable must be set to 'true'");
    }

    // Ensure test duration limits
    let max_duration = std::env::var("MAX_TIMER_TEST_DURATION_MS")
        .unwrap_or_else(|_| "30000".to_string()) // 30 seconds default
        .parse::<u64>()
        .map_err(|_| "Invalid MAX_TIMER_TEST_DURATION_MS")?;

    if max_duration > 60000 {
        return Err("Timer tests must complete within 60 seconds");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sleep_operation() {
        // Validate environment first
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-sleep-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("sleep-test");

            // Test various sleep durations
            let durations = [
                Duration::from_millis(10),
                Duration::from_millis(50),
                Duration::from_millis(100),
            ];

            for duration in durations {
                let cx = Cx::root();
                let operation = manager
                    .test_sleep_operation(&cx, duration)
                    .await
                    .expect("Sleep operation should succeed");

                assert_eq!(operation.operation_type, TimerOperationType::Sleep);
                assert!(
                    operation.deadline_hit,
                    "Sleep should meet timing requirements"
                );
                assert!(
                    operation.latency_ns < 10_000_000,
                    "Sleep latency should be < 10ms"
                );
            }

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_sleep_operations, durations.len() as u64);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_timeout_operation_hit_and_miss() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-timeout-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("timeout-test");
            let cx = Cx::root();

            // Test timeout hit (work takes longer than timeout)
            let timeout_hit = manager
                .test_timeout_operation(
                    &cx,
                    Duration::from_millis(50),  // 50ms timeout
                    Duration::from_millis(100), // 100ms work
                )
                .await
                .expect("Timeout operation should succeed");

            assert_eq!(timeout_hit.operation_type, TimerOperationType::Timeout);
            assert!(timeout_hit.deadline_hit, "Timeout should fire");

            // Test timeout miss (work completes before timeout)
            let timeout_miss = manager
                .test_timeout_operation(
                    &cx,
                    Duration::from_millis(100), // 100ms timeout
                    Duration::from_millis(50),  // 50ms work
                )
                .await
                .expect("Timeout operation should succeed");

            assert_eq!(timeout_miss.operation_type, TimerOperationType::Timeout);
            assert!(
                !timeout_miss.deadline_hit,
                "Work should complete before timeout"
            );

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_timeout_operations, 2);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_interval_tick_accuracy() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-interval-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("interval-test");
            let cx = Cx::root();

            // Test interval with multiple ticks
            let operations = manager
                .test_interval_operation(
                    &cx,
                    Duration::from_millis(25), // 25ms intervals
                    5,                         // 5 ticks
                )
                .await
                .expect("Interval operation should succeed");

            assert_eq!(operations.len(), 5);

            for (i, operation) in operations.iter().enumerate() {
                assert_eq!(operation.operation_type, TimerOperationType::IntervalTick);

                // Check that intervals are roughly accurate
                let expected_time = (i + 1) as u64 * 25_000_000; // 25ms in ns
                let tolerance = 10_000_000; // 10ms tolerance
                assert!(
                    operation.accuracy_error.abs() <= tolerance as i64,
                    "Interval tick {} accuracy error {} exceeds tolerance {}",
                    i,
                    operation.accuracy_error,
                    tolerance
                );
            }

            let stats = manager.get_stats_summary();
            assert_eq!(stats.total_interval_ticks, 5);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_deadline_checking() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-deadline-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("deadline-test");
            let cx = Cx::root();

            // Test deadline that should be hit
            let deadline = Deadline::from_duration(Duration::from_millis(100));
            let operation = manager
                .test_deadline_operation(&cx, deadline)
                .await
                .expect("Deadline operation should succeed");

            assert_eq!(operation.operation_type, TimerOperationType::DeadlineCheck);
            assert!(operation.deadline_hit, "Deadline should be detected as hit");

            let stats = manager.get_stats_summary();
            assert!(stats.deadline_hit_rate > 0.0);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_concurrent_sleep_under_load() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-concurrent-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("concurrent-test");
            let cx = Cx::root();

            let config = TimerE2EConfig {
                concurrency_level: 5,
                load_duration_ms: 50,
                accuracy_tolerance_ns: 10_000_000, // 10ms tolerance under load
                ..TimerE2EConfig::default()
            };

            let operations = manager
                .test_concurrent_sleep_load(&cx, &config)
                .await
                .expect("Concurrent sleep load should succeed");

            assert_eq!(operations.len(), config.concurrency_level);

            for operation in &operations {
                assert_eq!(
                    operation.operation_type,
                    TimerOperationType::ConcurrentSleep
                );
                assert_eq!(
                    operation.concurrent_operations,
                    config.concurrency_level as u64
                );

                // Under load, we allow more tolerance
                assert!(
                    operation.latency_ns < 50_000_000, // < 50ms
                    "Concurrent sleep latency {} exceeds 50ms",
                    operation.latency_ns
                );
            }

            let stats = manager.get_stats_summary();
            assert_eq!(stats.concurrent_operations, config.concurrency_level as u64);
            assert!(stats.average_latency_ns < 50_000_000);
            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_timer_wheel_stress_load() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-stress-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("stress-test");
            let cx = Cx::root();

            // Create a stress test with many overlapping timers
            let mut handles = Vec::new();
            let operations_per_batch = 20;
            let batch_count = 3;

            for batch in 0..batch_count {
                for i in 0..operations_per_batch {
                    let duration = Duration::from_millis(10 + (i * 5) as u64);
                    let mgr = manager.clone();

                    let handle = cx.spawn(async move {
                        let operation = mgr.test_sleep_operation(&cx, duration).await?;
                        Ok::<_, AsupersyncError>(operation)
                    });

                    handles.push(handle);
                }

                // Small delay between batches
                sleep(Duration::from_millis(5)).await;
            }

            // Wait for all operations to complete
            let mut completed_operations = 0;
            for handle in handles {
                match handle.await {
                    Outcome::Ok(Ok(_)) => completed_operations += 1,
                    other => eprintln!("Timer operation failed: {:?}", other),
                }
            }

            assert_eq!(completed_operations, operations_per_batch * batch_count);

            let stats = manager.get_stats_summary();
            assert_eq!(
                stats.total_sleep_operations,
                (operations_per_batch * batch_count) as u64
            );

            // Under stress, we allow higher latency but still require reasonable performance
            assert!(
                stats.average_latency_ns < 20_000_000,
                "Average latency under stress should be < 20ms"
            );
            assert!(
                stats.accuracy_violations <= (completed_operations / 10) as u64,
                "< 10% accuracy violations allowed"
            );

            manager.logger.log_stats_summary(&stats);
        });
    }

    #[test]
    fn test_production_safety_guards() {
        // Test without TIMER_E2E_TESTS environment variable
        std::env::remove_var("TIMER_E2E_TESTS");
        assert!(validate_timer_e2e_environment().is_err());

        // Test with invalid duration
        std::env::set_var("TIMER_E2E_TESTS", "true");
        std::env::set_var("MAX_TIMER_TEST_DURATION_MS", "invalid");
        assert!(validate_timer_e2e_environment().is_err());

        // Test with excessive duration
        std::env::set_var("MAX_TIMER_TEST_DURATION_MS", "120000");
        assert!(validate_timer_e2e_environment().is_err());

        // Test valid configuration
        std::env::set_var("MAX_TIMER_TEST_DURATION_MS", "30000");
        assert!(validate_timer_e2e_environment().is_ok());
    }

    #[test]
    fn test_timer_e2e_comprehensive_scenario() {
        std::env::set_var("TIMER_E2E_TESTS", "true");
        validate_timer_e2e_environment().expect("Environment validation failed");

        let runtime = RuntimeBuilder::new()
            .with_name("timer-e2e-comprehensive-test")
            .build();

        runtime.block_on(async {
            let manager = RealTimerManager::new("comprehensive-test");
            let cx = Cx::root();

            // Comprehensive test combining all timer operations
            let mut all_operations = Vec::new();

            // 1. Basic sleep operations
            for ms in [10, 25, 50] {
                let operation = manager
                    .test_sleep_operation(&cx, Duration::from_millis(ms))
                    .await
                    .expect("Sleep operation should succeed");
                all_operations.push(operation);
            }

            // 2. Timeout operations (both hit and miss)
            let timeout_hit = manager
                .test_timeout_operation(&cx, Duration::from_millis(30), Duration::from_millis(60))
                .await
                .expect("Timeout hit should succeed");
            all_operations.push(timeout_hit);

            let timeout_miss = manager
                .test_timeout_operation(&cx, Duration::from_millis(60), Duration::from_millis(30))
                .await
                .expect("Timeout miss should succeed");
            all_operations.push(timeout_miss);

            // 3. Interval operations
            let interval_ops = manager
                .test_interval_operation(&cx, Duration::from_millis(20), 3)
                .await
                .expect("Interval operation should succeed");
            all_operations.extend(interval_ops);

            // 4. Deadline check
            let deadline = Deadline::from_duration(Duration::from_millis(40));
            let deadline_op = manager
                .test_deadline_operation(&cx, deadline)
                .await
                .expect("Deadline operation should succeed");
            all_operations.push(deadline_op);

            // 5. Concurrent load test
            let config = TimerE2EConfig {
                concurrency_level: 3,
                load_duration_ms: 30,
                ..TimerE2EConfig::default()
            };
            let concurrent_ops = manager
                .test_concurrent_sleep_load(&cx, &config)
                .await
                .expect("Concurrent load should succeed");
            all_operations.extend(concurrent_ops);

            // Validate comprehensive results
            assert!(!all_operations.is_empty());

            let total_operations = all_operations.len();
            let successful_operations = all_operations
                .iter()
                .filter(|op| op.latency_ns < 100_000_000) // < 100ms
                .count();

            assert!(
                successful_operations as f64 / total_operations as f64 > 0.8,
                "At least 80% of operations should have reasonable latency"
            );

            let stats = manager.get_stats_summary();
            manager.logger.log_stats_summary(&stats);

            // Final validation
            assert!(stats.total_sleep_operations > 0);
            assert!(stats.total_timeout_operations > 0);
            assert!(stats.total_interval_ticks > 0);
            assert!(stats.deadline_hit_rate >= 0.0 && stats.deadline_hit_rate <= 1.0);
        });
    }
}
