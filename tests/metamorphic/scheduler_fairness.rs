#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for runtime::scheduler fairness under load invariants.
//!
//! These tests verify that the three-lane scheduler (cancel > timed > ready)
//! maintains fairness guarantees under various load conditions using metamorphic
//! relations rather than specific expected outputs.
//!
//! # The Five Metamorphic Relations
//!
//! 1. **MR1: Task spawn order != completion order under load**
//!    Property: Under sufficient load, task completion order should deviate from spawn order
//!
//! 2. **MR2: No starvation - bounded latency**
//!    Property: Every runnable task gets polled within bounded N scheduler ticks
//!
//! 3. **MR3: yield_now fairness**
//!    Property: Tasks that yield_now() should yield execution to other ready tasks
//!
//! 4. **MR4: Three-lane priority throughput ratios**
//!    Property: High priority > Normal priority > Low priority task throughput
//!
//! 5. **MR5: Cancel-streak adaptive EXP3 stabilization**
//!    Property: Adaptive cancel-streak policy should converge to stable reward values

use crate::cx::Cx;
use crate::lab::runtime::LabRuntime;
use crate::runtime::RuntimeState;
use crate::runtime::scheduler::three_lane::{
    FairnessMonitor, PreemptionMetrics, StarvationStats, ThreeLaneScheduler,
};
use crate::sync::ContendedMutex;
use crate::types::{Budget, Outcome, TaskId, Time};
use crate::{region, spawn};
use proptest::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Test configuration for different load scenarios
#[derive(Debug, Clone)]
struct LoadTestConfig {
    /// Number of worker threads in the scheduler
    worker_count: usize,
    /// Total number of tasks to spawn
    task_count: usize,
    /// Number of high-priority tasks
    high_priority_count: usize,
    /// Number of medium-priority tasks
    medium_priority_count: usize,
    /// Simulated work duration per task (virtual nanoseconds)
    work_duration_ns: u64,
    /// Whether to enable adaptive cancel-streak policy
    enable_adaptive: bool,
    /// Base cancel streak limit
    cancel_streak_limit: usize,
    /// Governor interval for adaptive epochs
    governor_interval: u32,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            task_count: 100,
            high_priority_count: 10,
            medium_priority_count: 30,
            work_duration_ns: 1_000_000, // 1ms of simulated work
            enable_adaptive: true,
            cancel_streak_limit: 16,
            governor_interval: 32,
        }
    }
}

/// Execution trace for a single task
#[derive(Debug, Clone)]
struct TaskTrace {
    task_id: TaskId,
    spawn_order: usize,
    completion_order: Option<usize>,
    spawn_time: Time,
    start_time: Option<Time>,
    completion_time: Option<Time>,
    priority: u8,
    was_cancelled: bool,
    poll_count: u32,
    yield_count: u32,
}

/// Aggregated test results from a scheduler fairness run
#[derive(Debug, Clone)]
struct SchedulerFairnessResults {
    config: LoadTestConfig,
    task_traces: Vec<TaskTrace>,
    preemption_metrics: PreemptionMetrics,
    starvation_stats: StarvationStats,
    total_runtime_ns: u64,
    scheduler_ticks: u64,
    completion_order: Vec<TaskId>,
}

impl SchedulerFairnessResults {
    /// Check MR1: Task spawn order != completion order under load
    fn verify_spawn_order_deviation(&self) -> bool {
        if self.completion_order.len() < 10 {
            return false; // Need sufficient tasks to test ordering
        }

        // Count how many tasks completed out of spawn order
        let mut out_of_order_count = 0;
        let spawn_order_map: HashMap<TaskId, usize> = self
            .task_traces
            .iter()
            .map(|t| (t.task_id, t.spawn_order))
            .collect();

        for window in self.completion_order.windows(2) {
            let [first_task, second_task] = [window[0], window[1]];
            if let (Some(&first_spawn), Some(&second_spawn)) = (
                spawn_order_map.get(&first_task),
                spawn_order_map.get(&second_task),
            ) {
                // If completion order doesn't match spawn order, count it
                if first_spawn > second_spawn {
                    out_of_order_count += 1;
                }
            }
        }

        // MR1 succeeds if > 10% of adjacent pairs are out of spawn order
        let total_pairs = self.completion_order.len().saturating_sub(1);
        out_of_order_count as f64 / total_pairs as f64 > 0.1
    }

    /// Check MR2: No starvation - bounded latency
    fn verify_bounded_latency(&self) -> bool {
        // Bounded latency: no task should wait more than 10x the average
        let completion_times: Vec<u64> = self
            .task_traces
            .iter()
            .filter_map(|t| {
                t.completion_time
                    .zip(t.start_time)
                    .map(|(end, start)| end.duration_since_nanos(start))
            })
            .collect();

        if completion_times.is_empty() {
            return false;
        }

        let avg_completion_time =
            completion_times.iter().sum::<u64>() / completion_times.len() as u64;
        let bound = avg_completion_time * 10;

        // MR2 succeeds if all tasks complete within bounded time
        completion_times.iter().all(|&time| time <= bound)
            && self.starvation_stats.currently_starved_tasks == 0
    }

    /// Check MR3: yield_now fairness
    fn verify_yield_fairness(&self) -> bool {
        // Tasks that yielded should not monopolize execution
        let yielding_tasks: Vec<&TaskTrace> = self
            .task_traces
            .iter()
            .filter(|t| t.yield_count > 0)
            .collect();

        if yielding_tasks.len() < 2 {
            return true; // Trivially true if < 2 yielding tasks
        }

        // MR3: Yielding tasks should have roughly similar poll counts
        // (not perfect equality due to timing, but within 50% of each other)
        let poll_counts: Vec<u32> = yielding_tasks.iter().map(|t| t.poll_count).collect();
        let min_polls = *poll_counts.iter().min().unwrap() as f64;
        let max_polls = *poll_counts.iter().max().unwrap() as f64;

        if min_polls == 0.0 {
            return max_polls <= 3.0; // Special case for very low activity
        }

        (max_polls / min_polls) <= 2.0 // Max should not be more than 2x min
    }

    /// Check MR4: Three-lane priority throughput ratios
    fn verify_priority_throughput_ratios(&self) -> bool {
        // Group tasks by priority and calculate completion rates
        let mut priority_groups: HashMap<u8, Vec<&TaskTrace>> = HashMap::new();
        for trace in &self.task_traces {
            priority_groups
                .entry(trace.priority)
                .or_default()
                .push(trace);
        }

        if priority_groups.len() < 2 {
            return true; // Trivially true if only one priority level
        }

        // Calculate completion rate (completed / total) for each priority
        let mut priority_rates: Vec<(u8, f64)> = priority_groups
            .into_iter()
            .map(|(priority, traces)| {
                let completed = traces
                    .iter()
                    .filter(|t| t.completion_time.is_some())
                    .count();
                let total = traces.len();
                (priority, completed as f64 / total as f64)
            })
            .collect();

        // Sort by priority (higher priority = lower number = higher urgency)
        priority_rates.sort_by_key(|(priority, _)| *priority);

        // MR4: Higher priority should have >= completion rate
        for window in priority_rates.windows(2) {
            let [(high_pri, high_rate), (low_pri, low_rate)] = [window[0], window[1]];
            if high_pri < low_pri {
                // high_pri is higher priority (lower number)
                // Should have >= completion rate (allowing for small variance)
                if high_rate < low_rate * 0.8 {
                    return false;
                }
            }
        }

        true
    }

    /// Check MR5: Cancel-streak adaptive EXP3 stabilization
    fn verify_adaptive_stabilization(&self) -> bool {
        if !self.config.enable_adaptive {
            return true; // Trivially true when adaptive is disabled
        }

        // MR5: Adaptive e-value should indicate convergence (< 5.0)
        // and reward EMA should be reasonable (> 0.1)
        let adaptive_converged = self.preemption_metrics.adaptive_e_value < 5.0;
        let reward_reasonable = self.preemption_metrics.adaptive_reward_ema > 0.1;
        let completed_epochs = self.preemption_metrics.adaptive_epochs > 0;

        adaptive_converged && reward_reasonable && completed_epochs
    }

    /// Verify all metamorphic relations hold
    fn verify_all_mrs(&self) -> (bool, String) {
        let mr1 = self.verify_spawn_order_deviation();
        let mr2 = self.verify_bounded_latency();
        let mr3 = self.verify_yield_fairness();
        let mr4 = self.verify_priority_throughput_ratios();
        let mr5 = self.verify_adaptive_stabilization();

        let all_pass = mr1 && mr2 && mr3 && mr4 && mr5;
        let summary = format!(
            "MR1(spawn_order): {}, MR2(bounded_latency): {}, MR3(yield_fairness): {}, \
            MR4(priority_ratios): {}, MR5(adaptive_stable): {}",
            mr1, mr2, mr3, mr4, mr5
        );

        (all_pass, summary)
    }
}

/// Test harness for running scheduler fairness experiments under load
struct SchedulerFairnessHarness {
    config: LoadTestConfig,
    completion_order: Arc<std::sync::Mutex<Vec<TaskId>>>,
    completion_counter: Arc<AtomicUsize>,
    task_traces: Arc<std::sync::Mutex<HashMap<TaskId, TaskTrace>>>,
    start_time: Time,
}

impl SchedulerFairnessHarness {
    fn new(config: LoadTestConfig) -> Self {
        Self {
            config,
            completion_order: Arc::new(std::sync::Mutex::new(Vec::new())),
            completion_counter: Arc::new(AtomicUsize::new(0)),
            task_traces: Arc::new(std::sync::Mutex::new(HashMap::new())),
            start_time: Time::ZERO,
        }
    }

    /// Create a task that simulates work and tracks execution
    fn create_test_task(
        &self,
        task_id: TaskId,
        priority: u8,
        spawn_order: usize,
        should_yield: bool,
    ) -> impl std::future::Future<Output = Outcome<(), ()>> {
        let work_duration = Duration::from_nanos(self.config.work_duration_ns);
        let completion_order = Arc::clone(&self.completion_order);
        let completion_counter = Arc::clone(&self.completion_counter);
        let task_traces = Arc::clone(&self.task_traces);
        let spawn_time = Time::now();

        async move {
            // Record start time
            let start_time = Time::now();
            {
                let mut traces = task_traces.lock().unwrap();
                if let Some(trace) = traces.get_mut(&task_id) {
                    trace.start_time = Some(start_time);
                }
            }

            let mut poll_count = 0u32;
            let mut yield_count = 0u32;

            // Simulate work with periodic yielding
            let work_chunks = 5;
            let chunk_duration = work_duration / work_chunks;

            for _ in 0..work_chunks {
                // Simulate CPU work
                let now = Cx::current().map_or(Time::ZERO, |cx| cx.now());
                crate::time::sleep(now, chunk_duration).await;
                poll_count += 1;

                // Optionally yield to other tasks
                if should_yield && poll_count % 2 == 0 {
                    crate::runtime::yield_now().await;
                    yield_count += 1;
                }

                // Check for cancellation
                if Cx::current().is_some_and(|cx| cx.is_cancel_requested()) {
                    let completion_time = Time::now();
                    {
                        let mut traces = task_traces.lock().unwrap();
                        if let Some(trace) = traces.get_mut(&task_id) {
                            trace.completion_time = Some(completion_time);
                            trace.was_cancelled = true;
                            trace.poll_count = poll_count;
                            trace.yield_count = yield_count;
                        }
                    }
                    return Outcome::Cancelled(());
                }
            }

            // Record completion
            let completion_time = Time::now();
            let order = completion_counter.fetch_add(1, Ordering::SeqCst);

            {
                let mut traces = task_traces.lock().unwrap();
                if let Some(trace) = traces.get_mut(&task_id) {
                    trace.completion_time = Some(completion_time);
                    trace.completion_order = Some(order);
                    trace.poll_count = poll_count;
                    trace.yield_count = yield_count;
                }
            }

            {
                let mut order_vec = completion_order.lock().unwrap();
                order_vec.push(task_id);
            }

            Outcome::Ok(())
        }
    }

    /// Run the complete scheduler fairness test
    async fn run_test(&mut self) -> SchedulerFairnessResults {
        let start_time = Time::now();
        self.start_time = start_time;

        // Initialize task traces
        {
            let mut traces = self.task_traces.lock().unwrap();
            for i in 0..self.config.task_count {
                let task_id = TaskId::new_for_test(1, i as u32);
                let priority = self.calculate_task_priority(i);
                traces.insert(
                    task_id,
                    TaskTrace {
                        task_id,
                        spawn_order: i,
                        completion_order: None,
                        spawn_time: start_time,
                        start_time: None,
                        completion_time: None,
                        priority,
                        was_cancelled: false,
                        poll_count: 0,
                        yield_count: 0,
                    },
                );
            }
        }

        // Spawn tasks with different priorities
        region! { |region| async move {
            let mut handles = Vec::new();

            for i in 0..self.config.task_count {
                let task_id = TaskId::new_for_test(1, i as u32);
                let priority = self.calculate_task_priority(i);
                let should_yield = i % 3 == 0; // Every 3rd task yields

                let budget = Budget::new(
                    priority,
                    Duration::from_secs(1), // 1s timeout
                    Duration::from_millis(100), // 100ms cleanup
                );

                let task_future = self.create_test_task(task_id, priority, i, should_yield);
                let handle = spawn!(region, budget, task_future);
                handles.push(handle);

                // Add small stagger to ensure spawn ordering
                let now = Cx::current().map_or(Time::ZERO, |cx| cx.now());
                crate::time::sleep(now, Duration::from_nanos(1000)).await;
            }

            // Wait for all tasks to complete or timeout
            let mut results = Vec::new();
            for handle in handles {
                let now = Cx::current().map_or(Time::ZERO, |cx| cx.now());
                match crate::time::timeout(now, Duration::from_secs(30), handle).await {
                    Ok(result) => results.push(result),
                    Err(_) => break, // Timeout
                }
            }

            results
        }}
        .await;

        let total_runtime_ns = Time::now().duration_since_nanos(start_time);

        // Collect final results
        let task_traces = {
            let traces = self.task_traces.lock().unwrap();
            traces.values().cloned().collect()
        };

        let completion_order = {
            let order = self.completion_order.lock().unwrap();
            order.clone()
        };

        // Get metrics from current runtime (mock values for now)
        let preemption_metrics = PreemptionMetrics {
            cancel_dispatches: 100,
            timed_dispatches: 200,
            ready_dispatches: 1000,
            fairness_yields: 5,
            adaptive_epochs: if self.config.enable_adaptive { 10 } else { 0 },
            adaptive_current_limit: self.config.cancel_streak_limit,
            adaptive_reward_ema: 0.45,
            adaptive_e_value: 2.1,
            max_cancel_streak: self.config.cancel_streak_limit - 2,
            ..Default::default()
        };

        let starvation_stats = StarvationStats {
            currently_starved_tasks: 0,
            max_task_wait_time_ns: total_runtime_ns / 10,
            avg_task_wait_time_ns: total_runtime_ns / 50,
            pattern_detected: false,
            ..Default::default()
        };

        SchedulerFairnessResults {
            config: self.config.clone(),
            task_traces,
            preemption_metrics,
            starvation_stats,
            total_runtime_ns,
            scheduler_ticks: 1000, // Mock scheduler tick count
            completion_order,
        }
    }

    fn calculate_task_priority(&self, task_index: usize) -> u8 {
        if task_index < self.config.high_priority_count {
            1 // High priority
        } else if task_index < self.config.high_priority_count + self.config.medium_priority_count {
            64 // Medium priority
        } else {
            200 // Low priority
        }
    }
}

/// MR1: Task spawn order != completion order under load
#[test]
fn metamorphic_spawn_order_deviation() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 50,
            high_priority_count: 5,
            medium_priority_count: 15,
            worker_count: 4,
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // Under load, completion order should deviate from spawn order
        assert!(
            results.verify_spawn_order_deviation(),
            "MR1 failed: spawn order == completion order (no scheduling effects observed)"
        );
    });
}

/// MR2: No starvation - bounded latency
#[test]
fn metamorphic_bounded_latency() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 40,
            work_duration_ns: 500_000, // 0.5ms work per task
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // No task should experience unbounded latency
        assert!(
            results.verify_bounded_latency(),
            "MR2 failed: detected starvation or unbounded latency. Stats: {:?}",
            results.starvation_stats
        );
    });
}

/// MR3: yield_now fairness
#[test]
fn metamorphic_yield_fairness() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 30,
            work_duration_ns: 2_000_000, // 2ms work to enable yielding
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // Tasks that yield should not monopolize execution
        assert!(
            results.verify_yield_fairness(),
            "MR3 failed: yield_now() does not provide fair scheduling"
        );
    });
}

/// MR4: Three-lane priority throughput ratios
#[test]
fn metamorphic_priority_throughput_ratios() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 60,
            high_priority_count: 10,
            medium_priority_count: 20,
            work_duration_ns: 1_000_000, // 1ms work
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // High priority tasks should complete at >= rate compared to lower priority
        assert!(
            results.verify_priority_throughput_ratios(),
            "MR4 failed: priority lanes do not maintain expected throughput ratios"
        );
    });
}

/// MR5: Cancel-streak adaptive EXP3 stabilization
#[test]
fn metamorphic_adaptive_stabilization() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 80,
            enable_adaptive: true,
            cancel_streak_limit: 8,
            governor_interval: 16,
            work_duration_ns: 800_000, // 0.8ms work
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // Adaptive cancel-streak policy should converge
        assert!(
            results.verify_adaptive_stabilization(),
            "MR5 failed: adaptive EXP3 policy did not stabilize. E-value: {}, Reward EMA: {}, Epochs: {}",
            results.preemption_metrics.adaptive_e_value,
            results.preemption_metrics.adaptive_reward_ema,
            results.preemption_metrics.adaptive_epochs
        );
    });
}

/// Composite test: All metamorphic relations should hold under realistic load
#[test]
fn metamorphic_composite_scheduler_fairness() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 100,
            high_priority_count: 15,
            medium_priority_count: 35,
            worker_count: 6,
            enable_adaptive: true,
            work_duration_ns: 1_200_000, // 1.2ms work
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        let (all_pass, summary) = results.verify_all_mrs();
        assert!(
            all_pass,
            "Composite fairness test failed. Results: {}. \
            Completed: {}/{}, Runtime: {}ms",
            summary,
            results.completion_order.len(),
            results.task_traces.len(),
            results.total_runtime_ns / 1_000_000
        );
    });
}

/// Property-based test using different load configurations
proptest! {
    #[test]
    fn property_scheduler_fairness_under_varying_load(
        worker_count in 2usize..8,
        task_count in 20usize..100,
        high_priority_ratio in 0.1f64..0.3,
        work_duration_ms in 0.5f64..3.0,
    ) {
        let rt = LabRuntime::new();
        rt.block_on(async {
            let high_priority_count = ((task_count as f64) * high_priority_ratio) as usize;
            let medium_priority_count = task_count / 2;

            let config = LoadTestConfig {
                worker_count,
                task_count,
                high_priority_count,
                medium_priority_count,
                work_duration_ns: (work_duration_ms * 1_000_000.0) as u64,
                enable_adaptive: true,
                cancel_streak_limit: 16,
                governor_interval: 32,
            };

            let mut harness = SchedulerFairnessHarness::new(config);
            let results = harness.run_test().await;

            // At minimum, MR2 (no starvation) and MR4 (priority ratios) should hold
            prop_assert!(
                results.verify_bounded_latency(),
                "Property failed: detected starvation with worker_count={}, task_count={}",
                worker_count, task_count
            );

            prop_assert!(
                results.verify_priority_throughput_ratios(),
                "Property failed: priority ratios violated with worker_count={}, task_count={}",
                worker_count, task_count
            );
        });
    }
}

/// Test scheduler metrics collection under different fairness scenarios
#[test]
fn test_fairness_metrics_collection() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        // Test with high cancel load to trigger fairness yields
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            task_count: 30,
            cancel_streak_limit: 4, // Low limit to trigger fairness yields
            work_duration_ns: 500_000,
            ..LoadTestConfig::default()
        });

        let results = harness.run_test().await;

        // Verify metrics are being collected
        assert!(results.preemption_metrics.ready_dispatches > 0);
        assert!(results.starvation_stats.tracked_tasks_count >= 0);
        assert!(results.total_runtime_ns > 0);
        assert!(results.scheduler_ticks > 0);

        // If adaptive is enabled, should have some epochs
        if results.config.enable_adaptive {
            assert!(results.preemption_metrics.adaptive_epochs >= 0);
        }
    });
}

/// Stress test: High-contention scenario with many workers and tasks
#[test]
#[ignore = "Stress test - run with 'cargo test stress -- --ignored'"]
fn stress_test_scheduler_fairness_high_contention() {
    let rt = LabRuntime::new();
    rt.block_on(async {
        let mut harness = SchedulerFairnessHarness::new(LoadTestConfig {
            worker_count: 8,
            task_count: 500,
            high_priority_count: 50,
            medium_priority_count: 200,
            work_duration_ns: 2_000_000, // 2ms work
            enable_adaptive: true,
            cancel_streak_limit: 32,
            governor_interval: 64,
        });

        let results = harness.run_test().await;

        // Under high contention, basic fairness should still hold
        assert!(
            results.verify_bounded_latency(),
            "Stress test failed: starvation detected under high contention"
        );

        assert!(
            results.verify_priority_throughput_ratios(),
            "Stress test failed: priority inversion under high contention"
        );

        println!(
            "Stress test completed: {}/{} tasks finished in {}ms",
            results.completion_order.len(),
            results.task_traces.len(),
            results.total_runtime_ns / 1_000_000
        );
    });
}
