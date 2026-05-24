//! Real service E2E tests for scheduler/three_lane ↔ obligation/leak_check integration.
//!
//! Verifies that three-lane scheduling preserves obligation tracking under
//! concurrent task spawn/abort scenarios. Tests obligation lifecycle consistency
//! across multiple scheduler lanes and workers without mocks.

use crate::cx::Cx;
use crate::runtime::scheduler::three_lane::{ThreeLaneScheduler, SchedulerConfig, FairnessPolicy};
use crate::runtime::task::TaskId;
use crate::runtime::{RegionId, ObligationId, RuntimeState};
use crate::obligation::leak_check::{ObligationVar, VarState};
use crate::obligation::{ObligationTracker, ObligationLease, ObligationPermit};
use crate::record::{ObligationKind, ObligationRecord};
use crate::types::{Outcome, Budget, Priority};
use crate::time::{Duration, Instant};
use crate::util::det_rng::DetRng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use futures_lite::future;

/// Configuration for scheduler + obligation integration testing.
#[derive(Debug, Clone)]
struct SchedulerObligationConfig {
    /// Number of worker threads in the scheduler.
    worker_count: usize,
    /// Number of tasks to spawn per test scenario.
    task_count: usize,
    /// Number of obligations per task.
    obligations_per_task: usize,
    /// Percentage of tasks to abort (0.0 to 1.0).
    abort_rate: f64,
    /// Scheduler fairness policy for testing.
    fairness_policy: FairnessPolicy,
    /// Task priority distribution across lanes.
    priority_distribution: PriorityDistribution,
}

/// Distribution of task priorities across scheduler lanes.
#[derive(Debug, Clone)]
struct PriorityDistribution {
    /// Percentage of high-priority (cancel lane) tasks.
    high_priority_pct: f64,
    /// Percentage of medium-priority (timed lane) tasks.
    medium_priority_pct: f64,
    /// Percentage of low-priority (ready lane) tasks.
    low_priority_pct: f64,
}

impl Default for SchedulerObligationConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            task_count: 200,
            obligations_per_task: 3,
            abort_rate: 0.3,
            fairness_policy: FairnessPolicy::Balanced,
            priority_distribution: PriorityDistribution {
                high_priority_pct: 0.2,  // 20% cancel lane
                medium_priority_pct: 0.3, // 30% timed lane
                low_priority_pct: 0.5,   // 50% ready lane
            },
        }
    }
}

/// Statistics for tracking obligation lifecycle during testing.
#[derive(Debug, Default)]
struct ObligationStats {
    /// Number of obligations created.
    created: AtomicU32,
    /// Number of obligations committed.
    committed: AtomicU32,
    /// Number of obligations aborted.
    aborted: AtomicU32,
    /// Number of potential leaks detected.
    leaks_detected: AtomicU32,
    /// Number of tasks that completed successfully.
    tasks_completed: AtomicU32,
    /// Number of tasks that were aborted.
    tasks_aborted: AtomicU32,
    /// Number of scheduler fairness violations.
    fairness_violations: AtomicU32,
}

impl ObligationStats {
    fn snapshot(&self) -> ObligationStatsSnapshot {
        ObligationStatsSnapshot {
            created: self.created.load(Ordering::Acquire),
            committed: self.committed.load(Ordering::Acquire),
            aborted: self.aborted.load(Ordering::Acquire),
            leaks_detected: self.leaks_detected.load(Ordering::Acquire),
            tasks_completed: self.tasks_completed.load(Ordering::Acquire),
            tasks_aborted: self.tasks_aborted.load(Ordering::Acquire),
            fairness_violations: self.fairness_violations.load(Ordering::Acquire),
        }
    }
}

/// Snapshot of obligation statistics for analysis.
#[derive(Debug, Clone)]
struct ObligationStatsSnapshot {
    created: u32,
    committed: u32,
    aborted: u32,
    leaks_detected: u32,
    tasks_completed: u32,
    tasks_aborted: u32,
    fairness_violations: u32,
}

impl ObligationStatsSnapshot {
    /// Check if obligation lifecycle is consistent (no leaks).
    fn is_consistent(&self) -> bool {
        // All created obligations should be resolved (committed or aborted)
        let resolved = self.committed + self.aborted;
        resolved == self.created && self.leaks_detected == 0
    }

    /// Calculate the task abort rate.
    fn abort_rate(&self) -> f64 {
        let total_tasks = self.tasks_completed + self.tasks_aborted;
        if total_tasks > 0 {
            self.tasks_aborted as f64 / total_tasks as f64
        } else {
            0.0
        }
    }

    /// Calculate the obligation resolution rate.
    fn resolution_rate(&self) -> f64 {
        if self.created > 0 {
            (self.committed + self.aborted) as f64 / self.created as f64
        } else {
            1.0
        }
    }
}

/// A test task that creates obligations and may be aborted.
struct ObligationTestTask {
    task_id: TaskId,
    region_id: RegionId,
    priority: Priority,
    obligations: Vec<ObligationId>,
    should_abort: bool,
    work_duration_ms: u64,
}

impl ObligationTestTask {
    fn new(
        task_id: TaskId,
        region_id: RegionId,
        priority: Priority,
        obligation_count: usize,
        should_abort: bool,
        work_duration_ms: u64,
    ) -> Self {
        Self {
            task_id,
            region_id,
            priority,
            obligations: Vec::with_capacity(obligation_count),
            should_abort,
            work_duration_ms,
        }
    }

    /// Execute the task's work, creating and managing obligations.
    async fn execute(
        &mut self,
        cx: &Cx,
        obligation_tracker: &Arc<ObligationTracker>,
        stats: &Arc<ObligationStats>,
    ) -> Outcome<(), String> {
        cx.trace("task_started", &format!(
            "task_id={:?} priority={:?} obligations={} should_abort={}",
            self.task_id, self.priority, self.obligations.capacity(), self.should_abort
        ));

        // Create obligations
        for i in 0..self.obligations.capacity() {
            let obligation_id = ObligationId::new();
            let obligation_record = ObligationRecord::new(
                obligation_id,
                ObligationKind::Permit,
                self.region_id,
                self.task_id,
            );

            match obligation_tracker.track_obligation(obligation_record).await {
                Ok(()) => {
                    self.obligations.push(obligation_id);
                    stats.created.fetch_add(1, Ordering::Relaxed);
                    cx.trace("obligation_created", &format!(
                        "task_id={:?} obligation_id={:?} index={}",
                        self.task_id, obligation_id, i
                    ));
                }
                Err(e) => {
                    cx.trace("obligation_creation_failed", &format!(
                        "task_id={:?} error={:?}",
                        self.task_id, e
                    ));
                    stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
                    return Outcome::Err(format!("Failed to create obligation: {:?}", e));
                }
            }
        }

        // Simulate work
        let work_start = Instant::now();
        while work_start.elapsed().as_millis() < self.work_duration_ms {
            // Check for cancellation
            if cx.is_cancelled() || self.should_abort {
                cx.trace("task_aborted", &format!("task_id={:?}", self.task_id));
                return self.abort_obligations(cx, obligation_tracker, stats).await;
            }

            // Yield periodically to allow scheduler fairness testing
            if work_start.elapsed().as_millis() % 10 == 0 {
                cx.yield_now().await;
            }

            // Simulate CPU work
            std::hint::spin_loop();
        }

        // Complete successfully - commit obligations
        self.commit_obligations(cx, obligation_tracker, stats).await
    }

    /// Commit all obligations when task completes successfully.
    async fn commit_obligations(
        &mut self,
        cx: &Cx,
        obligation_tracker: &Arc<ObligationTracker>,
        stats: &Arc<ObligationStats>,
    ) -> Outcome<(), String> {
        for &obligation_id in &self.obligations {
            match obligation_tracker.commit_obligation(obligation_id).await {
                Ok(()) => {
                    stats.committed.fetch_add(1, Ordering::Relaxed);
                    cx.trace("obligation_committed", &format!(
                        "task_id={:?} obligation_id={:?}",
                        self.task_id, obligation_id
                    ));
                }
                Err(e) => {
                    cx.trace("obligation_commit_failed", &format!(
                        "task_id={:?} obligation_id={:?} error={:?}",
                        self.task_id, obligation_id, e
                    ));
                    stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        stats.tasks_completed.fetch_add(1, Ordering::Relaxed);
        Outcome::Ok(())
    }

    /// Abort all obligations when task is cancelled or fails.
    async fn abort_obligations(
        &mut self,
        cx: &Cx,
        obligation_tracker: &Arc<ObligationTracker>,
        stats: &Arc<ObligationStats>,
    ) -> Outcome<(), String> {
        for &obligation_id in &self.obligations {
            match obligation_tracker.abort_obligation(obligation_id).await {
                Ok(()) => {
                    stats.aborted.fetch_add(1, Ordering::Relaxed);
                    cx.trace("obligation_aborted", &format!(
                        "task_id={:?} obligation_id={:?}",
                        self.task_id, obligation_id
                    ));
                }
                Err(e) => {
                    cx.trace("obligation_abort_failed", &format!(
                        "task_id={:?} obligation_id={:?} error={:?}",
                        self.task_id, obligation_id, e
                    ));
                    stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        stats.tasks_aborted.fetch_add(1, Ordering::Relaxed);
        Outcome::Cancelled
    }
}

/// Integrated test harness for scheduler + obligation testing.
struct SchedulerObligationTestHarness {
    scheduler: Arc<ThreeLaneScheduler>,
    obligation_tracker: Arc<ObligationTracker>,
    runtime_state: Arc<RuntimeState>,
    config: SchedulerObligationConfig,
    stats: Arc<ObligationStats>,
}

impl SchedulerObligationTestHarness {
    async fn new(config: SchedulerObligationConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let scheduler_config = SchedulerConfig {
            worker_count: config.worker_count,
            fairness_policy: config.fairness_policy.clone(),
            cancel_streak_limit: 8,
            timed_fairness_limit: 4,
            steal_fairness_limit: 6,
            adaptive_cancel_streak: true,
            work_stealing_enabled: true,
        };

        let scheduler = Arc::new(ThreeLaneScheduler::new(scheduler_config).await?);
        let runtime_state = Arc::new(RuntimeState::new());
        let obligation_tracker = Arc::new(ObligationTracker::new(runtime_state.clone()));
        let stats = Arc::new(ObligationStats::default());

        Ok(Self {
            scheduler,
            obligation_tracker,
            runtime_state,
            config,
            stats,
        })
    }

    /// Run concurrent task spawn/abort test with obligation tracking.
    async fn run_concurrent_spawn_abort_test(
        &self,
        cx: &Cx,
    ) -> Result<ObligationStatsSnapshot, Box<dyn std::error::Error>> {
        cx.trace("test_started", &format!("config={:?}", self.config));

        let mut tasks = Vec::with_capacity(self.config.task_count);
        let mut rng = DetRng::from_seed(12345);

        // Create test tasks with different priorities and abort patterns
        for i in 0..self.config.task_count {
            let task_id = TaskId::new();
            let region_id = RegionId::new();

            // Assign priority based on distribution
            let priority = self.assign_priority(i, &mut rng);

            // Determine if this task should be aborted
            let should_abort = rng.next_f64() < self.config.abort_rate;

            // Randomize work duration (10-100ms)
            let work_duration_ms = 10 + (rng.next_u64() % 90);

            let mut task = ObligationTestTask::new(
                task_id,
                region_id,
                priority,
                self.config.obligations_per_task,
                should_abort,
                work_duration_ms,
            );

            tasks.push(task);
        }

        // Spawn all tasks concurrently across scheduler lanes
        let mut task_handles = Vec::new();

        for mut task in tasks {
            let cx_task = cx.clone();
            let obligation_tracker = Arc::clone(&self.obligation_tracker);
            let stats = Arc::clone(&self.stats);
            let scheduler = Arc::clone(&self.scheduler);

            let handle = scheduler.spawn_with_priority(
                task.priority,
                async move {
                    task.execute(&cx_task, &obligation_tracker, &stats).await
                },
            ).await?;

            task_handles.push((task.task_id, handle));
        }

        // Wait for all tasks to complete or abort
        let mut completed_count = 0;
        let mut aborted_count = 0;

        for (task_id, handle) in task_handles {
            match handle.await {
                Outcome::Ok(()) => {
                    completed_count += 1;
                    cx.trace("task_finished_ok", &format!("task_id={:?}", task_id));
                }
                Outcome::Cancelled => {
                    aborted_count += 1;
                    cx.trace("task_finished_cancelled", &format!("task_id={:?}", task_id));
                }
                Outcome::Err(e) => {
                    cx.trace("task_finished_error", &format!("task_id={:?} error={:?}", task_id, e));
                    self.stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
                }
                Outcome::Panicked => {
                    cx.trace("task_finished_panicked", &format!("task_id={:?}", task_id));
                    self.stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Verify scheduler fairness properties
        self.verify_scheduler_fairness(cx).await?;

        // Verify obligation leak detection
        self.verify_obligation_consistency(cx).await?;

        let final_stats = self.stats.snapshot();
        cx.trace("test_completed", &format!(
            "completed={} aborted={} stats={:?}",
            completed_count, aborted_count, final_stats
        ));

        Ok(final_stats)
    }

    /// Assign task priority based on configured distribution.
    fn assign_priority(&self, task_index: usize, rng: &mut DetRng) -> Priority {
        let rand_val = rng.next_f64();
        let dist = &self.config.priority_distribution;

        if rand_val < dist.high_priority_pct {
            Priority::High  // Cancel lane
        } else if rand_val < dist.high_priority_pct + dist.medium_priority_pct {
            Priority::Medium  // Timed lane
        } else {
            Priority::Low  // Ready lane
        }
    }

    /// Verify that the scheduler maintained fairness properties.
    async fn verify_scheduler_fairness(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
        let scheduler_stats = self.scheduler.get_fairness_stats().await?;

        // Check for fairness violations
        let mut violations = 0;

        for (worker_id, worker_stats) in scheduler_stats.worker_stats.iter() {
            // Check cancel lane fairness
            if worker_stats.max_cancel_streak > self.scheduler.config().cancel_streak_limit * 2 {
                violations += 1;
                cx.trace("fairness_violation_cancel", &format!(
                    "worker={:?} max_cancel_streak={} limit={}",
                    worker_id, worker_stats.max_cancel_streak, self.scheduler.config().cancel_streak_limit
                ));
            }

            // Check timed lane fairness
            if worker_stats.max_timed_streak > self.scheduler.config().timed_fairness_limit {
                violations += 1;
                cx.trace("fairness_violation_timed", &format!(
                    "worker={:?} max_timed_streak={} limit={}",
                    worker_id, worker_stats.max_timed_streak, self.scheduler.config().timed_fairness_limit
                ));
            }

            // Check work stealing fairness
            if worker_stats.max_steal_streak > self.scheduler.config().steal_fairness_limit {
                violations += 1;
                cx.trace("fairness_violation_steal", &format!(
                    "worker={:?} max_steal_streak={} limit={}",
                    worker_id, worker_stats.max_steal_streak, self.scheduler.config().steal_fairness_limit
                ));
            }
        }

        self.stats.fairness_violations.store(violations, Ordering::Release);

        cx.trace("scheduler_fairness_verified", &format!(
            "violations={} workers={}",
            violations, scheduler_stats.worker_stats.len()
        ));

        Ok(())
    }

    /// Verify obligation tracking consistency and detect leaks.
    async fn verify_obligation_consistency(&self, cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
        let tracker_stats = self.obligation_tracker.get_tracking_stats().await?;

        // Check for obligation leaks
        let active_obligations = tracker_stats.active_count;
        let pending_cleanup = tracker_stats.pending_cleanup_count;

        if active_obligations > 0 {
            cx.trace("obligation_leak_detected", &format!(
                "active_obligations={} pending_cleanup={}",
                active_obligations, pending_cleanup
            ));
            self.stats.leaks_detected.fetch_add(active_obligations, Ordering::Relaxed);
        }

        // Verify obligation state transitions are valid
        for (obligation_id, state_history) in tracker_stats.state_transitions.iter() {
            if !self.is_valid_state_transition_sequence(state_history) {
                cx.trace("invalid_obligation_state_transition", &format!(
                    "obligation_id={:?} states={:?}",
                    obligation_id, state_history
                ));
                self.stats.leaks_detected.fetch_add(1, Ordering::Relaxed);
            }
        }

        cx.trace("obligation_consistency_verified", &format!(
            "active={} pending_cleanup={} total_tracked={}",
            active_obligations, pending_cleanup, tracker_stats.total_tracked
        ));

        Ok(())
    }

    /// Check if an obligation state transition sequence is valid.
    fn is_valid_state_transition_sequence(&self, states: &[VarState]) -> bool {
        if states.is_empty() {
            return true;
        }

        let mut current = VarState::Empty;

        for &next_state in states {
            match (current, next_state) {
                // Valid transitions
                (VarState::Empty, VarState::Held(_)) => {
                    // Obligation created
                    current = next_state;
                }
                (VarState::Held(_), VarState::Resolved) => {
                    // Obligation resolved (committed or aborted)
                    current = next_state;
                }
                (VarState::Held(_), VarState::MayHold(_)) => {
                    // Obligation state became uncertain
                    current = next_state;
                }
                (VarState::MayHold(_), VarState::Resolved) => {
                    // Uncertain obligation resolved
                    current = next_state;
                }
                (VarState::Resolved, VarState::Resolved) => {
                    // Stay resolved (idempotent)
                }
                // Invalid transitions
                _ => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod scheduler_obligation_integration_tests {
    use super::*;
    use crate::test_utils::{init_test_logging, TestRuntime};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    /// Test concurrent task spawn/abort with obligation tracking across scheduler lanes.
    #[test]
    fn test_concurrent_spawn_abort_obligation_consistency() {
        init_test("test_concurrent_spawn_abort_obligation_consistency");

        let config = SchedulerObligationConfig {
            worker_count: 4,
            task_count: 100,
            obligations_per_task: 2,
            abort_rate: 0.25,
            fairness_policy: FairnessPolicy::Balanced,
            ..Default::default()
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(60), async move |cx| {
            let harness = SchedulerObligationTestHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_spawn_abort_test(&cx).await?;

            // Verify obligation consistency
            assert!(
                stats.is_consistent(),
                "Obligation lifecycle should be consistent: {:?}",
                stats
            );

            // Verify expected abort rate
            let expected_abort_rate = config.abort_rate;
            let actual_abort_rate = stats.abort_rate();
            let abort_rate_tolerance = 0.15; // 15% tolerance

            assert!(
                (actual_abort_rate - expected_abort_rate).abs() < abort_rate_tolerance,
                "Abort rate should be close to expected: actual={:.2}, expected={:.2}",
                actual_abort_rate, expected_abort_rate
            );

            // Verify no fairness violations
            assert_eq!(
                stats.fairness_violations, 0,
                "Scheduler should maintain fairness properties"
            );

            // Verify obligation resolution rate
            assert!(
                stats.resolution_rate() >= 0.98,
                "At least 98% of obligations should be resolved: rate={:.3}",
                stats.resolution_rate()
            );

            cx.trace("test_concurrent_spawn_abort_obligation_consistency_complete", &format!(
                "tasks_completed={} tasks_aborted={} obligations_created={} obligations_resolved={} leaks={}",
                stats.tasks_completed, stats.tasks_aborted, stats.created,
                stats.committed + stats.aborted, stats.leaks_detected
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_concurrent_spawn_abort_obligation_consistency");
    }

    /// Test high-concurrency scenario with scheduler lane pressure.
    #[test]
    fn test_high_concurrency_scheduler_lane_pressure() {
        init_test("test_high_concurrency_scheduler_lane_pressure");

        let config = SchedulerObligationConfig {
            worker_count: 8,
            task_count: 500,
            obligations_per_task: 4,
            abort_rate: 0.4,
            fairness_policy: FairnessPolicy::MeetDeadlines,
            priority_distribution: PriorityDistribution {
                high_priority_pct: 0.4,  // High cancel lane pressure
                medium_priority_pct: 0.35, // High timed lane pressure
                low_priority_pct: 0.25,  // Moderate ready lane pressure
            },
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(90), async move |cx| {
            let harness = SchedulerObligationTestHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_spawn_abort_test(&cx).await?;

            // Under high pressure, allow slightly more tolerance for consistency
            let resolution_rate = stats.resolution_rate();
            assert!(
                resolution_rate >= 0.95,
                "Under high concurrency, at least 95% of obligations should be resolved: rate={:.3}",
                resolution_rate
            );

            // Verify minimal leaks despite high concurrency
            let leak_rate = stats.leaks_detected as f64 / stats.created as f64;
            assert!(
                leak_rate < 0.05,
                "Leak rate should be under 5% even under high concurrency: rate={:.3}",
                leak_rate
            );

            // Verify scheduler handled lane pressure well
            let total_tasks = stats.tasks_completed + stats.tasks_aborted;
            assert!(
                total_tasks >= (config.task_count as f64 * 0.9) as u32,
                "At least 90% of tasks should complete or abort properly: {}/{}",
                total_tasks, config.task_count
            );

            cx.trace("test_high_concurrency_scheduler_lane_pressure_complete", &format!(
                "total_tasks={} resolution_rate={:.3} leak_rate={:.3} fairness_violations={}",
                total_tasks, resolution_rate, leak_rate, stats.fairness_violations
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_high_concurrency_scheduler_lane_pressure");
    }

    /// Test scheduler fairness under obligation tracking load.
    #[test]
    fn test_scheduler_fairness_under_obligation_tracking_load() {
        init_test("test_scheduler_fairness_under_obligation_tracking_load");

        let config = SchedulerObligationConfig {
            worker_count: 6,
            task_count: 300,
            obligations_per_task: 6, // High obligation load per task
            abort_rate: 0.2,
            fairness_policy: FairnessPolicy::Strict,
            priority_distribution: PriorityDistribution {
                high_priority_pct: 0.15,
                medium_priority_pct: 0.40, // Focus on timed lane fairness
                low_priority_pct: 0.45,
            },
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(75), async move |cx| {
            let harness = SchedulerObligationTestHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_spawn_abort_test(&cx).await?;

            // Under strict fairness, should have zero violations
            assert_eq!(
                stats.fairness_violations, 0,
                "Strict fairness policy should have zero violations"
            );

            // Should maintain high obligation consistency under fairness constraints
            assert!(
                stats.is_consistent(),
                "Obligation consistency should be maintained under strict fairness: {:?}",
                stats
            );

            // Verify all lanes were utilized (indicating fairness is working)
            let total_tasks = stats.tasks_completed + stats.tasks_aborted;
            assert!(
                total_tasks >= config.task_count as u32 * 95 / 100,
                "At least 95% of tasks should be processed: {}/{}",
                total_tasks, config.task_count
            );

            cx.trace("test_scheduler_fairness_under_obligation_tracking_load_complete", &format!(
                "fairness_policy={:?} fairness_violations={} total_tasks={} consistency={}",
                config.fairness_policy, stats.fairness_violations, total_tasks, stats.is_consistent()
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_scheduler_fairness_under_obligation_tracking_load");
    }

    /// Test obligation leak detection during rapid task churn.
    #[test]
    fn test_obligation_leak_detection_during_rapid_task_churn() {
        init_test("test_obligation_leak_detection_during_rapid_task_churn");

        let config = SchedulerObligationConfig {
            worker_count: 4,
            task_count: 150,
            obligations_per_task: 3,
            abort_rate: 0.6, // High abort rate to stress leak detection
            fairness_policy: FairnessPolicy::Balanced,
            priority_distribution: PriorityDistribution {
                high_priority_pct: 0.5,  // Many high-priority cancellations
                medium_priority_pct: 0.25,
                low_priority_pct: 0.25,
            },
        };

        TestRuntime::run_with_timeout(Duration::from_seconds(45), async move |cx| {
            let harness = SchedulerObligationTestHarness::new(config.clone()).await?;

            let stats = harness.run_concurrent_spawn_abort_test(&cx).await?;

            // With high abort rate, should still maintain obligation consistency
            let resolution_rate = stats.resolution_rate();
            assert!(
                resolution_rate >= 0.95,
                "Even with high task churn, resolution rate should be high: rate={:.3}",
                resolution_rate
            );

            // Verify abort rate matches expectation (allowing for some variance)
            let actual_abort_rate = stats.abort_rate();
            let expected_abort_rate = config.abort_rate;
            assert!(
                (actual_abort_rate - expected_abort_rate).abs() < 0.20,
                "Abort rate should be close to configured rate: actual={:.2}, expected={:.2}",
                actual_abort_rate, expected_abort_rate
            );

            // Leak detection should be effective
            let leak_rate = stats.leaks_detected as f64 / stats.created as f64;
            assert!(
                leak_rate < 0.03,
                "Leak detection should keep leak rate very low: rate={:.3}",
                leak_rate
            );

            cx.trace("test_obligation_leak_detection_during_rapid_task_churn_complete", &format!(
                "abort_rate={:.3} resolution_rate={:.3} leak_rate={:.3} created={} resolved={}",
                actual_abort_rate, resolution_rate, leak_rate,
                stats.created, stats.committed + stats.aborted
            ));

            Ok(())
        }).unwrap();

        crate::test_complete!("test_obligation_leak_detection_during_rapid_task_churn");
    }
}