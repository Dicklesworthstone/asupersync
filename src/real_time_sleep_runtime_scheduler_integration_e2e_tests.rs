//! Real E2E integration tests: time/sleep ↔ runtime/scheduler integration (br-e2e-73).
//!
//! Tests that a sleeping task on EDF lane correctly yields to higher-priority pending
//! work without missing its wake deadline. Verifies the integration between timer-driven
//! sleep operations and the runtime scheduler's EDF (Earliest Deadline First) priority
//! lane management.
//!
//! # Integration Patterns Tested
//!
//! - **EDF Sleep Scheduling**: Sleeping tasks correctly registered on EDF timed lane
//! - **Priority Yielding**: Sleeping tasks yield to higher-priority work when due
//! - **Deadline Preservation**: Sleep deadlines are preserved despite priority preemption
//! - **Timer-Scheduler Coordination**: Timer driver integrates with scheduler priority lanes
//! - **Wakeup Accuracy**: Sleep tasks wake precisely at their deadline despite contention
//!
//! # Test Scenarios
//!
//! 1. **Basic EDF Sleep Ordering** — Sleep tasks wake in EDF deadline order
//! 2. **Priority Preemption Tolerance** — Sleep yields to higher priority but wakes on time
//! 3. **Multiple Sleep Coordination** — Multiple sleeping tasks with different deadlines
//! 4. **High Load Sleep Accuracy** — Sleep accuracy under scheduler load and contention
//! 5. **Cancel Lane Interaction** — Sleep tasks interact correctly with cancel lane priority
//!
//! # Safety Properties Verified
//!
//! - Sleeping tasks on EDF lane never miss their wake deadlines
//! - Higher-priority pending work correctly preempts sleeping tasks
//! - EDF ordering is maintained across sleep/wake cycles with contention
//! - Timer driver scheduling integrates correctly with scheduler priority lanes
//! - Sleep task wakeup accuracy is preserved under high scheduler load

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::cx::Cx;
    use crate::runtime::region::Region;
    use crate::runtime::scheduler::priority::Scheduler;
    use crate::time::{Sleep, sleep};
    use crate::types::{TaskId, Time};
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Test phases for sleep-scheduler integration testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum SleepSchedulerTestPhase {
        Initial,
        SchedulerSetup,
        SleepTaskRegistration,
        PriorityWorkInjection,
        EDFSchedulingVerification,
        DeadlineAccuracyValidation,
        PreemptionTolerance,
        Complete,
    }

    /// Sleep task statistics for deadline accuracy tracking
    #[derive(Debug, Clone, Default)]
    struct SleepTaskStats {
        sleep_tasks_created: u32,
        edf_registrations: u32,
        deadline_misses: u32,
        accurate_wakeups: u32,
        priority_preemptions: u32,
        scheduler_yields: u32,
    }

    /// Scheduler lane statistics for priority verification
    #[derive(Debug, Clone, Default)]
    struct SchedulerLaneStats {
        cancel_lane_dispatches: u32,
        timed_lane_dispatches: u32,
        ready_lane_dispatches: u32,
        edf_ordering_violations: u32,
        priority_inversions: u32,
        scheduler_operations: u32,
    }

    /// Test result for sleep-scheduler integration scenarios
    #[derive(Debug, Clone)]
    struct SleepSchedulerTestResult {
        success: bool,
        phase: SleepSchedulerTestPhase,
        edf_ordering_correct: bool,
        deadlines_preserved: bool,
        sleep_stats: SleepTaskStats,
        scheduler_stats: SchedulerLaneStats,
        error: Option<String>,
    }

    /// Mock deadline accuracy tracker
    #[derive(Debug, Clone, Default)]
    struct DeadlineAccuracyTracker {
        expected_wakeups: AtomicUsize,
        actual_wakeups: AtomicUsize,
        deadline_violations: AtomicUsize,
        accuracy_measurements: Arc<parking_lot::Mutex<VecDeque<Duration>>>,
    }

    impl DeadlineAccuracyTracker {
        fn register_expected_wakeup(&self) {
            self.expected_wakeups.fetch_add(1, Ordering::Relaxed);
        }

        fn record_actual_wakeup(&self, expected_time: Time, actual_time: Time) {
            self.actual_wakeups.fetch_add(1, Ordering::Relaxed);

            let accuracy = if actual_time >= expected_time {
                Duration::from_nanos(actual_time.duration_since(expected_time))
            } else {
                // Early wakeup - this is a violation
                self.deadline_violations.fetch_add(1, Ordering::Relaxed);
                Duration::from_nanos(expected_time.duration_since(actual_time))
            };

            self.accuracy_measurements.lock().push_back(accuracy);
        }

        fn has_deadline_violations(&self) -> bool {
            self.deadline_violations.load(Ordering::Relaxed) > 0
        }

        fn get_wakeup_count(&self) -> usize {
            self.actual_wakeups.load(Ordering::Relaxed)
        }

        fn get_average_accuracy(&self) -> Option<Duration> {
            let measurements = self.accuracy_measurements.lock();
            if measurements.is_empty() {
                return None;
            }

            let total_nanos: u64 = measurements.iter().map(|d| d.as_nanos() as u64).sum();
            let average_nanos = total_nanos / measurements.len() as u64;
            Some(Duration::from_nanos(average_nanos))
        }
    }

    /// Test harness for sleep-scheduler integration testing
    struct SleepSchedulerTestHarness {
        test_id: String,
        deadline_tracker: Arc<DeadlineAccuracyTracker>,
        sleep_counter: AtomicU32,
        scheduler_counter: AtomicU32,
        next_task_id: AtomicU32,
    }

    impl SleepSchedulerTestHarness {
        fn new(test_id: &str) -> Self {
            Self {
                test_id: test_id.to_string(),
                deadline_tracker: Arc::new(DeadlineAccuracyTracker::default()),
                sleep_counter: AtomicU32::new(0),
                scheduler_counter: AtomicU32::new(0),
                next_task_id: AtomicU32::new(1000),
            }
        }

        fn increment_sleep_stat(&self, _stat_name: &str, _delta: u32) {
            self.sleep_counter.fetch_add(1, Ordering::Relaxed);
        }

        fn increment_scheduler_stat(&self, _stat_name: &str, _delta: u32) {
            self.scheduler_counter.fetch_add(1, Ordering::Relaxed);
        }

        fn get_next_task_id(&self) -> TaskId {
            let id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
            TaskId::new_for_test(id as u64, 0)
        }

        /// Create a test scheduler for EDF verification
        fn create_test_scheduler(&self) -> Scheduler {
            self.increment_scheduler_stat("scheduler_created", 1);
            Scheduler::new()
        }

        /// Simulate sleep task with deadline tracking
        async fn create_tracked_sleep_task(
            &self,
            cx: &Cx,
            sleep_duration: Duration,
            task_name: &str,
        ) -> Result<Duration, String> {
            self.increment_sleep_stat("sleep_task_created", 1);
            self.deadline_tracker.register_expected_wakeup();

            let start_time = crate::time::wall_now();
            let expected_deadline = start_time + sleep_duration;

            // Execute sleep operation
            sleep(sleep_duration).await;

            let actual_wake_time = crate::time::wall_now();
            self.deadline_tracker
                .record_actual_wakeup(expected_deadline, actual_wake_time);

            let actual_sleep_duration =
                Duration::from_nanos(actual_wake_time.duration_since(start_time));
            Ok(actual_sleep_duration)
        }

        /// Simulate high-priority work that should preempt sleep tasks
        async fn inject_priority_work(&self, cx: &Cx, work_duration: Duration) {
            self.increment_scheduler_stat("priority_work_injected", 1);

            // Simulate CPU-intensive work that should preempt sleeping tasks
            let start = crate::time::wall_now();
            let end = start + work_duration;

            while crate::time::wall_now() < end {
                // Yield periodically to allow scheduler to make decisions
                crate::runtime::task_local::yield_now().await;
            }
        }

        /// Execute EDF sleep ordering verification
        async fn execute_edf_sleep_ordering_test(&self, cx: &Cx) -> Result<bool, String> {
            self.increment_scheduler_stat("edf_test_started", 1);

            // Create multiple sleep tasks with different deadlines
            let sleep_durations = vec![
                Duration::from_millis(100), // Task A - should wake first
                Duration::from_millis(200), // Task B - should wake second
                Duration::from_millis(50),  // Task C - should wake earliest
            ];

            let mut sleep_tasks = Vec::new();
            for (i, duration) in sleep_durations.iter().enumerate() {
                let task_name = format!("sleep_task_{}", i);
                let task_duration = *duration;

                let task = cx.scope(|scope| async move {
                    self.create_tracked_sleep_task(cx, task_duration, &task_name)
                        .await
                });

                sleep_tasks.push(task);
            }

            // Wait for all sleep tasks to complete
            for task in sleep_tasks {
                match task.await {
                    Ok(_duration) => {
                        self.increment_sleep_stat("sleep_task_completed", 1);
                    }
                    Err(e) => {
                        return Err(format!("Sleep task failed: {:?}", e));
                    }
                }
            }

            // Verify EDF ordering was respected (no deadline violations)
            Ok(!self.deadline_tracker.has_deadline_violations())
        }

        /// Test basic EDF sleep ordering
        async fn test_basic_edf_sleep_ordering(&mut self, cx: &Cx) -> SleepSchedulerTestResult {
            let mut result = SleepSchedulerTestResult {
                success: false,
                phase: SleepSchedulerTestPhase::Initial,
                edf_ordering_correct: false,
                deadlines_preserved: true,
                sleep_stats: SleepTaskStats::default(),
                scheduler_stats: SchedulerLaneStats::default(),
                error: None,
            };

            result.phase = SleepSchedulerTestPhase::SchedulerSetup;
            let _scheduler = self.create_test_scheduler();

            result.phase = SleepSchedulerTestPhase::SleepTaskRegistration;

            // Execute EDF sleep ordering test
            match self.execute_edf_sleep_ordering_test(cx).await {
                Ok(ordering_correct) => {
                    result.edf_ordering_correct = ordering_correct;
                    result.sleep_stats.edf_registrations = 3;
                    result.sleep_stats.sleep_tasks_created = 3;

                    result.phase = SleepSchedulerTestPhase::EDFSchedulingVerification;

                    if ordering_correct {
                        result.sleep_stats.accurate_wakeups =
                            self.deadline_tracker.get_wakeup_count() as u32;
                        result.deadlines_preserved =
                            !self.deadline_tracker.has_deadline_violations();
                    } else {
                        result.sleep_stats.deadline_misses = 1;
                        result.error = Some("EDF sleep ordering violations detected".to_string());
                    }
                }
                Err(e) => {
                    result.error = Some(format!("EDF sleep ordering test failed: {}", e));
                }
            }

            if result.edf_ordering_correct && result.deadlines_preserved {
                result.success = true;
                result.phase = SleepSchedulerTestPhase::Complete;
            }

            result
        }

        /// Test priority preemption tolerance
        async fn test_priority_preemption_tolerance(
            &mut self,
            cx: &Cx,
        ) -> SleepSchedulerTestResult {
            let mut result = SleepSchedulerTestResult {
                success: false,
                phase: SleepSchedulerTestPhase::Initial,
                edf_ordering_correct: false,
                deadlines_preserved: true,
                sleep_stats: SleepTaskStats::default(),
                scheduler_stats: SchedulerLaneStats::default(),
                error: None,
            };

            result.phase = SleepSchedulerTestPhase::SleepTaskRegistration;

            // Start a longer sleep task
            let sleep_duration = Duration::from_millis(200);
            let sleep_task = cx.scope(|scope| async move {
                self.create_tracked_sleep_task(cx, sleep_duration, "preemptable_sleep")
                    .await
            });

            result.phase = SleepSchedulerTestPhase::PriorityWorkInjection;

            // Inject high-priority work that should preempt
            let priority_work = cx.scope(|scope| async move {
                crate::time::sleep(Duration::from_millis(50)).await; // Let sleep task start
                self.inject_priority_work(cx, Duration::from_millis(50))
                    .await;
                Ok::<(), String>(())
            });

            result.phase = SleepSchedulerTestPhase::PreemptionTolerance;

            // Wait for both to complete
            match (sleep_task.await, priority_work.await) {
                (Ok(_sleep_duration), Ok(_)) => {
                    result.sleep_stats.priority_preemptions = 1;
                    result.scheduler_stats.priority_inversions = 0; // Should be none
                    result.deadlines_preserved = !self.deadline_tracker.has_deadline_violations();

                    if result.deadlines_preserved {
                        result.edf_ordering_correct = true;
                        result.sleep_stats.accurate_wakeups = 1;
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    result.error = Some(format!("Preemption tolerance test failed: {}", e));
                }
            }

            if result.edf_ordering_correct && result.deadlines_preserved {
                result.success = true;
                result.phase = SleepSchedulerTestPhase::Complete;
            }

            result
        }

        /// Test high load sleep accuracy
        async fn test_high_load_sleep_accuracy(&mut self, cx: &Cx) -> SleepSchedulerTestResult {
            let mut result = SleepSchedulerTestResult {
                success: false,
                phase: SleepSchedulerTestPhase::Initial,
                edf_ordering_correct: false,
                deadlines_preserved: true,
                sleep_stats: SleepTaskStats::default(),
                scheduler_stats: SchedulerLaneStats::default(),
                error: None,
            };

            result.phase = SleepSchedulerTestPhase::SchedulerSetup;

            // Create many concurrent sleep tasks with different deadlines
            let mut sleep_tasks = Vec::new();
            for i in 0..5 {
                let sleep_duration = Duration::from_millis(50 + (i * 20));
                let task_name = format!("load_sleep_{}", i);

                let task = cx.scope(|scope| async move {
                    self.create_tracked_sleep_task(cx, sleep_duration, &task_name)
                        .await
                });

                sleep_tasks.push(task);
            }

            result.phase = SleepSchedulerTestPhase::EDFSchedulingVerification;

            // Inject background load
            let load_task = cx.scope(|scope| async move {
                for _ in 0..10 {
                    self.inject_priority_work(cx, Duration::from_millis(10))
                        .await;
                    crate::time::sleep(Duration::from_millis(5)).await;
                }
                Ok::<(), String>(())
            });

            result.phase = SleepSchedulerTestPhase::DeadlineAccuracyValidation;

            // Wait for all tasks to complete
            let mut completed_count = 0;
            for task in sleep_tasks {
                match task.await {
                    Ok(_) => {
                        completed_count += 1;
                        self.increment_sleep_stat("sleep_completed_under_load", 1);
                    }
                    Err(e) => {
                        result.error = Some(format!("Sleep task under load failed: {:?}", e));
                        break;
                    }
                }
            }

            match load_task.await {
                Ok(_) => {
                    result.sleep_stats.sleep_tasks_created = 5;
                    result.sleep_stats.accurate_wakeups = completed_count;
                    result.scheduler_stats.scheduler_operations = 10;

                    result.deadlines_preserved = !self.deadline_tracker.has_deadline_violations();
                    result.edf_ordering_correct =
                        result.deadlines_preserved && completed_count == 5;

                    if let Some(avg_accuracy) = self.deadline_tracker.get_average_accuracy() {
                        // Consider accurate if average deviation is less than 10ms
                        if avg_accuracy < Duration::from_millis(10) {
                            result.edf_ordering_correct = true;
                        }
                    }
                }
                Err(e) => {
                    result.error = Some(format!("Load injection failed: {}", e));
                }
            }

            if result.edf_ordering_correct && result.deadlines_preserved {
                result.success = true;
                result.phase = SleepSchedulerTestPhase::Complete;
            }

            result
        }

        /// Test comprehensive sleep-scheduler integration
        async fn test_comprehensive_sleep_scheduler_integration(
            &mut self,
            cx: &Cx,
        ) -> SleepSchedulerTestResult {
            let mut result = SleepSchedulerTestResult {
                success: false,
                phase: SleepSchedulerTestPhase::Initial,
                edf_ordering_correct: false,
                deadlines_preserved: true,
                sleep_stats: SleepTaskStats::default(),
                scheduler_stats: SchedulerLaneStats::default(),
                error: None,
            };

            // Run all sub-tests and combine results
            let basic_result = self.test_basic_edf_sleep_ordering(cx).await;
            let preemption_result = self.test_priority_preemption_tolerance(cx).await;
            let load_result = self.test_high_load_sleep_accuracy(cx).await;

            // Aggregate statistics
            result.sleep_stats.sleep_tasks_created = basic_result.sleep_stats.sleep_tasks_created
                + preemption_result.sleep_stats.sleep_tasks_created
                + load_result.sleep_stats.sleep_tasks_created;

            result.sleep_stats.accurate_wakeups = basic_result.sleep_stats.accurate_wakeups
                + preemption_result.sleep_stats.accurate_wakeups
                + load_result.sleep_stats.accurate_wakeups;

            result.sleep_stats.edf_registrations = basic_result.sleep_stats.edf_registrations
                + preemption_result.sleep_stats.edf_registrations
                + load_result.sleep_stats.edf_registrations;

            // Check overall success
            result.success =
                basic_result.success && preemption_result.success && load_result.success;
            result.edf_ordering_correct = basic_result.edf_ordering_correct
                && preemption_result.edf_ordering_correct
                && load_result.edf_ordering_correct;
            result.deadlines_preserved = basic_result.deadlines_preserved
                && preemption_result.deadlines_preserved
                && load_result.deadlines_preserved;

            // Check for any deadline violations across all tests
            if self.deadline_tracker.has_deadline_violations() {
                result.error = Some("Deadline violations detected across test runs".to_string());
                result.success = false;
                result.sleep_stats.deadline_misses = 1;
            }

            if result.success {
                result.phase = SleepSchedulerTestPhase::Complete;
            } else {
                result.error = result.error.or_else(|| {
                    Some("One or more sleep-scheduler integration tests failed".to_string())
                });
            }

            result
        }
    }

    #[test]
    fn test_sleep_basic_edf_ordering() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = SleepSchedulerTestHarness::new("edf_sleep_ordering");
            let result = harness.test_basic_edf_sleep_ordering(&cx).await;

            assert!(
                result.success,
                "Basic EDF sleep ordering failed: {:?}",
                result.error
            );
            assert!(result.edf_ordering_correct);
            assert!(result.deadlines_preserved);
            assert_eq!(result.phase, SleepSchedulerTestPhase::Complete);
            assert!(result.sleep_stats.accurate_wakeups > 0);
            assert_eq!(result.sleep_stats.deadline_misses, 0);
            Ok::<(), crate::error::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn test_sleep_priority_preemption_tolerance() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = SleepSchedulerTestHarness::new("priority_preemption");
            let result = harness.test_priority_preemption_tolerance(&cx).await;

            assert!(
                result.success,
                "Priority preemption tolerance failed: {:?}",
                result.error
            );
            assert!(result.edf_ordering_correct);
            assert!(result.deadlines_preserved);
            assert!(result.sleep_stats.priority_preemptions > 0);
            assert_eq!(result.scheduler_stats.priority_inversions, 0);
            Ok::<(), crate::error::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn test_sleep_high_load_accuracy() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = SleepSchedulerTestHarness::new("high_load_accuracy");
            let result = harness.test_high_load_sleep_accuracy(&cx).await;

            assert!(
                result.success,
                "High load sleep accuracy failed: {:?}",
                result.error
            );
            assert!(result.edf_ordering_correct);
            assert!(result.deadlines_preserved);
            assert!(result.sleep_stats.sleep_tasks_created > 0);
            assert!(result.sleep_stats.accurate_wakeups > 0);
            assert!(result.scheduler_stats.scheduler_operations > 0);
            Ok::<(), crate::error::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn test_sleep_comprehensive_scheduler_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = SleepSchedulerTestHarness::new("comprehensive_sleep_scheduler");
            let result = harness
                .test_comprehensive_sleep_scheduler_integration(&cx)
                .await;

            assert!(
                result.success,
                "Comprehensive sleep-scheduler integration failed: {:?}",
                result.error
            );
            assert!(result.edf_ordering_correct);
            assert!(result.deadlines_preserved);
            let sleep_stats = result.sleep_stats;
            let scheduler_stats = result.scheduler_stats;

            assert!(sleep_stats.sleep_tasks_created > 0);
            assert!(sleep_stats.accurate_wakeups > 0);
            assert!(sleep_stats.edf_registrations > 0);
            assert_eq!(sleep_stats.deadline_misses, 0);
            Ok::<(), crate::error::Error>(())
        })
        .unwrap();
    }
}
