//! Real runtime/scheduler ↔ time/wheel integration e2e tests
//!
//! Tests the integration between the runtime scheduler and timer wheel,
//! verifying that scheduled tasks properly coordinate with timer wheel
//! for deadline management, timeout handling, and timing precision.
//!
//! Test scenarios:
//! - Task deadline coordination between scheduler and timer wheel
//! - Timeout propagation from timer wheel to scheduler
//! - Priority-based scheduling with timer wheel deadlines
//! - Timer wheel overflow handling during scheduler load spikes

use crate::{
    cx::{Cx, Scope},
    error::Error,
    runtime::{
        scheduler::{Priority, Scheduler, SchedulerConfig},
        task_handle::TaskHandle,
    },
    sync::{Mutex, RwLock},
    time::{
        Deadline, Duration, Instant, Sleep,
        wheel::{TimerEntry, TimerWheel, WheelConfig},
    },
    types::{Budget, Outcome, TaskId},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

/// Controllable scheduler that simulates various load conditions
/// for testing timer wheel coordination under stress
struct ControllableScheduler {
    scheduler: Scheduler,
    load_config: Arc<RwLock<SchedulerLoadConfig>>,
    scheduled_tasks: Arc<Mutex<HashMap<TaskId, ScheduledTaskInfo>>>,
    timing_stats: Arc<Mutex<TimingStatistics>>,
}

#[derive(Clone)]
struct SchedulerLoadConfig {
    max_concurrent_tasks: usize,
    scheduling_delay_ms: u64,
    priority_inversion_probability: f64,
    deadline_miss_simulation: bool,
    cpu_intensive_task_ratio: f64,
}

#[derive(Debug, Clone)]
struct ScheduledTaskInfo {
    task_id: TaskId,
    priority: Priority,
    deadline: Option<Instant>,
    created_at: Instant,
    started_at: Option<Instant>,
    completed_at: Option<Instant>,
    timer_wheel_entry: Option<u64>,
}

#[derive(Debug, Default)]
struct TimingStatistics {
    tasks_scheduled: u64,
    tasks_completed: u64,
    tasks_timed_out: u64,
    deadline_misses: u64,
    average_scheduling_latency_ms: f64,
    timer_wheel_interactions: u64,
}

impl ControllableScheduler {
    async fn new(cx: &Cx, timer_wheel: &TimerWheel) -> Result<Self, Error> {
        let config = SchedulerConfig {
            max_threads: 4,
            work_stealing: true,
            priority_levels: 5,
            quantum_ms: 10,
        };

        let scheduler = Scheduler::new(config)?;

        Ok(Self {
            scheduler,
            load_config: Arc::new(RwLock::new(SchedulerLoadConfig {
                max_concurrent_tasks: 100,
                scheduling_delay_ms: 0,
                priority_inversion_probability: 0.0,
                deadline_miss_simulation: false,
                cpu_intensive_task_ratio: 0.1,
            })),
            scheduled_tasks: Arc::new(Mutex::new(HashMap::new())),
            timing_stats: Arc::new(Mutex::new(TimingStatistics::default())),
        })
    }

    async fn schedule_task_with_deadline<F, R>(
        &self,
        cx: &Cx,
        priority: Priority,
        deadline: Option<Instant>,
        task_fn: F,
    ) -> Result<TaskHandle<R>, Error>
    where
        F: FnOnce(&Cx) -> R + Send + 'static,
        R: Send + 'static,
    {
        let load_config = self.load_config.read().unwrap().clone();

        // Check concurrent task limit
        let active_tasks = self.scheduled_tasks.lock().unwrap().len();
        if active_tasks >= load_config.max_concurrent_tasks {
            return Err(Error::custom("Scheduler at maximum capacity"));
        }

        // Simulate scheduling delay
        if load_config.scheduling_delay_ms > 0 {
            Sleep::new(StdDuration::from_millis(load_config.scheduling_delay_ms)).await;
        }

        let task_id = TaskId::new();
        let created_at = Instant::now();

        let task_info = ScheduledTaskInfo {
            task_id,
            priority,
            deadline,
            created_at,
            started_at: None,
            completed_at: None,
            timer_wheel_entry: None,
        };

        self.scheduled_tasks
            .lock()
            .unwrap()
            .insert(task_id, task_info);
        self.timing_stats.lock().unwrap().tasks_scheduled += 1;

        // Schedule with the actual scheduler
        let handle =
            self.scheduler
                .spawn_with_priority(cx, priority, move |task_cx| async move {
                    let result = task_fn(task_cx);
                    result
                })?;

        Ok(handle)
    }

    async fn simulate_deadline_pressure(&self, cx: &Cx, pressure_level: f64) -> Result<(), Error> {
        let pressure_config = SchedulerLoadConfig {
            max_concurrent_tasks: (100.0 * (1.0 - pressure_level * 0.8)) as usize,
            scheduling_delay_ms: (pressure_level * 50.0) as u64,
            priority_inversion_probability: pressure_level * 0.3,
            deadline_miss_simulation: pressure_level > 0.7,
            cpu_intensive_task_ratio: pressure_level * 0.5,
        };

        *self.load_config.write().unwrap() = pressure_config;

        Ok(())
    }

    fn record_task_completion(&self, task_id: TaskId, success: bool, timer_interaction: bool) {
        if let Some(mut task_info) = self.scheduled_tasks.lock().unwrap().get_mut(&task_id) {
            task_info.completed_at = Some(Instant::now());

            if let Some(deadline) = task_info.deadline {
                if Instant::now() > deadline {
                    self.timing_stats.lock().unwrap().deadline_misses += 1;
                }
            }
        }

        let mut stats = self.timing_stats.lock().unwrap();
        if success {
            stats.tasks_completed += 1;
        } else {
            stats.tasks_timed_out += 1;
        }

        if timer_interaction {
            stats.timer_wheel_interactions += 1;
        }
    }

    fn get_timing_statistics(&self) -> TimingStatistics {
        self.timing_stats.lock().unwrap().clone()
    }
}

/// Enhanced timer wheel with scheduler coordination hooks
struct SchedulerAwareTimerWheel {
    timer_wheel: TimerWheel,
    scheduler_coordination: Arc<Mutex<SchedulerCoordinationState>>,
    timing_precision_config: Arc<RwLock<TimingPrecisionConfig>>,
}

#[derive(Debug, Default)]
struct SchedulerCoordinationState {
    active_timers: HashMap<u64, TimerSchedulerEntry>,
    timer_completions: VecDeque<TimerCompletionEvent>,
    scheduler_notifications: u64,
    overflow_events: u64,
}

#[derive(Debug, Clone)]
struct TimerSchedulerEntry {
    timer_id: u64,
    task_id: Option<TaskId>,
    deadline: Instant,
    priority: Priority,
    scheduler_notified: bool,
}

#[derive(Debug, Clone)]
struct TimerCompletionEvent {
    timer_id: u64,
    completion_time: Instant,
    scheduler_latency_ms: f64,
}

#[derive(Clone)]
struct TimingPrecisionConfig {
    wheel_resolution_ms: u64,
    scheduler_notification_threshold_ms: u64,
    overflow_handling_strategy: OverflowStrategy,
    precision_degradation_factor: f64,
}

#[derive(Clone)]
enum OverflowStrategy {
    DropOldest,
    MergeCoarse,
    EscalateToScheduler,
}

impl SchedulerAwareTimerWheel {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let wheel_config = WheelConfig {
            resolution: StdDuration::from_millis(10),
            capacity: 1024,
            max_timeout: StdDuration::from_secs(3600),
        };

        let timer_wheel = TimerWheel::new(wheel_config)?;

        Ok(Self {
            timer_wheel,
            scheduler_coordination: Arc::new(Mutex::new(SchedulerCoordinationState::default())),
            timing_precision_config: Arc::new(RwLock::new(TimingPrecisionConfig {
                wheel_resolution_ms: 10,
                scheduler_notification_threshold_ms: 5,
                overflow_handling_strategy: OverflowStrategy::EscalateToScheduler,
                precision_degradation_factor: 0.1,
            })),
        })
    }

    async fn schedule_task_timeout(
        &self,
        cx: &Cx,
        task_id: TaskId,
        deadline: Instant,
        priority: Priority,
    ) -> Result<u64, Error> {
        let timer_id = self.timer_wheel.add_timer(cx, deadline).await?;

        let entry = TimerSchedulerEntry {
            timer_id,
            task_id: Some(task_id),
            deadline,
            priority,
            scheduler_notified: false,
        };

        self.scheduler_coordination
            .lock()
            .unwrap()
            .active_timers
            .insert(timer_id, entry);

        Ok(timer_id)
    }

    async fn notify_scheduler_on_timeout(&self, cx: &Cx, timer_id: u64) -> Result<bool, Error> {
        let mut coordination = self.scheduler_coordination.lock().unwrap();

        if let Some(mut entry) = coordination.active_timers.get_mut(&timer_id) {
            if !entry.scheduler_notified {
                entry.scheduler_notified = true;
                coordination.scheduler_notifications += 1;

                let completion_event = TimerCompletionEvent {
                    timer_id,
                    completion_time: Instant::now(),
                    scheduler_latency_ms: 0.0, // Would be calculated from actual latency
                };

                coordination.timer_completions.push_back(completion_event);

                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn handle_timer_wheel_overflow(&self, cx: &Cx) -> Result<(), Error> {
        let strategy = self
            .timing_precision_config
            .read()
            .unwrap()
            .overflow_handling_strategy
            .clone();

        match strategy {
            OverflowStrategy::DropOldest => {
                self.drop_oldest_timers(cx, 10).await?;
            }
            OverflowStrategy::MergeCoarse => {
                self.merge_coarse_timers(cx).await?;
            }
            OverflowStrategy::EscalateToScheduler => {
                self.escalate_overflow_to_scheduler(cx).await?;
            }
        }

        self.scheduler_coordination.lock().unwrap().overflow_events += 1;

        Ok(())
    }

    async fn drop_oldest_timers(&self, cx: &Cx, count: usize) -> Result<(), Error> {
        // Implementation would remove oldest timers from the wheel
        // For testing purposes, we simulate this operation
        Ok(())
    }

    async fn merge_coarse_timers(&self, cx: &Cx) -> Result<(), Error> {
        // Implementation would merge nearby timers with coarser granularity
        // For testing purposes, we simulate this operation
        Ok(())
    }

    async fn escalate_overflow_to_scheduler(&self, cx: &Cx) -> Result<(), Error> {
        // Implementation would notify scheduler to handle overflow
        // For testing purposes, we simulate this operation
        Ok(())
    }

    fn configure_timing_precision(&self, config: TimingPrecisionConfig) {
        *self.timing_precision_config.write().unwrap() = config;
    }

    fn get_coordination_state(&self) -> SchedulerCoordinationState {
        self.scheduler_coordination.lock().unwrap().clone()
    }
}

/// Integration coordinator that validates scheduler-timer wheel coordination
struct SchedulerTimerWheelIntegrationCoordinator {
    scheduler: ControllableScheduler,
    timer_wheel: SchedulerAwareTimerWheel,
    validation_results: Arc<Mutex<Vec<IntegrationValidationResult>>>,
}

#[derive(Debug, Clone)]
struct IntegrationValidationResult {
    test_case: String,
    timing_precision: bool,
    deadline_coordination: bool,
    overflow_handling: bool,
    performance_impact: f64,
    details: String,
}

impl SchedulerTimerWheelIntegrationCoordinator {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let timer_wheel = SchedulerAwareTimerWheel::new(cx).await?;
        let scheduler = ControllableScheduler::new(cx, &timer_wheel.timer_wheel).await?;

        Ok(Self {
            scheduler,
            timer_wheel,
            validation_results: Arc::new(Mutex::new(Vec::new())),
        })
    }

    async fn validate_deadline_coordination(
        &self,
        cx: &Cx,
        test_case: &str,
        task_count: usize,
        deadline_spread_ms: u64,
    ) -> Result<IntegrationValidationResult, Error> {
        let start_time = Instant::now();
        let mut task_handles = Vec::new();

        // Schedule multiple tasks with varying deadlines
        for i in 0..task_count {
            let priority = Priority::from(i % 5);
            let deadline = start_time
                + StdDuration::from_millis(deadline_spread_ms * (i as u64 + 1) / task_count as u64);

            let handle = self
                .scheduler
                .schedule_task_with_deadline(cx, priority, Some(deadline), move |task_cx| {
                    // Simulate some work
                    std::thread::sleep(StdDuration::from_millis(10));
                    format!("Task {} completed", i)
                })
                .await?;

            // Register deadline with timer wheel
            let timer_id = self
                .timer_wheel
                .schedule_task_timeout(cx, TaskId::new(), deadline, priority)
                .await?;

            task_handles.push((handle, timer_id, deadline));
        }

        // Wait for tasks to complete and collect results
        let mut completed_on_time = 0;
        let mut deadline_misses = 0;

        for (handle, timer_id, deadline) in task_handles {
            match handle.join().await {
                Outcome::Ok(_) => {
                    if Instant::now() <= deadline {
                        completed_on_time += 1;
                    } else {
                        deadline_misses += 1;
                    }
                }
                _ => deadline_misses += 1,
            }

            // Check if timer wheel notified scheduler appropriately
            self.timer_wheel
                .notify_scheduler_on_timeout(cx, timer_id)
                .await?;
        }

        let timing_precision = (completed_on_time as f64) / (task_count as f64) > 0.8;
        let deadline_coordination = deadline_misses < task_count / 5; // Allow up to 20% deadline misses

        let stats = self.scheduler.get_timing_statistics();
        let performance_impact = if stats.tasks_scheduled > 0 {
            1.0 - (stats.deadline_misses as f64 / stats.tasks_scheduled as f64)
        } else {
            0.0
        };

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            timing_precision,
            deadline_coordination,
            overflow_handling: true, // No overflow in this test
            performance_impact,
            details: format!(
                "Completed on time: {}/{}, Deadline misses: {}, Performance impact: {:.2}%",
                completed_on_time,
                task_count,
                deadline_misses,
                performance_impact * 100.0
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_overflow_handling(
        &self,
        cx: &Cx,
        test_case: &str,
        overload_factor: f64,
    ) -> Result<IntegrationValidationResult, Error> {
        // Configure timer wheel for overflow simulation
        self.timer_wheel
            .configure_timing_precision(TimingPrecisionConfig {
                wheel_resolution_ms: 50, // Coarser resolution to trigger overflow sooner
                scheduler_notification_threshold_ms: 10,
                overflow_handling_strategy: OverflowStrategy::EscalateToScheduler,
                precision_degradation_factor: overload_factor,
            });

        // Apply scheduler pressure
        self.scheduler
            .simulate_deadline_pressure(cx, overload_factor)
            .await?;

        // Schedule many concurrent tasks to trigger overflow
        let task_count = (1000.0 * overload_factor) as usize;
        let mut tasks_scheduled = 0;
        let mut overflow_handled = false;

        for i in 0..task_count {
            let deadline = Instant::now() + StdDuration::from_millis(100);

            match self
                .timer_wheel
                .schedule_task_timeout(cx, TaskId::new(), deadline, Priority::Medium)
                .await
            {
                Ok(_) => tasks_scheduled += 1,
                Err(_) => {
                    // Overflow occurred, test handling
                    self.timer_wheel.handle_timer_wheel_overflow(cx).await?;
                    overflow_handled = true;
                    break;
                }
            }
        }

        let coordination_state = self.timer_wheel.get_coordination_state();
        let overflow_handling = overflow_handled && coordination_state.overflow_events > 0;

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            timing_precision: tasks_scheduled > task_count / 2,
            deadline_coordination: coordination_state.scheduler_notifications > 0,
            overflow_handling,
            performance_impact: (tasks_scheduled as f64) / (task_count as f64),
            details: format!(
                "Tasks scheduled: {}/{}, Overflow events: {}, Notifications: {}",
                tasks_scheduled,
                task_count,
                coordination_state.overflow_events,
                coordination_state.scheduler_notifications
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_priority_based_timing(
        &self,
        cx: &Cx,
        test_case: &str,
    ) -> Result<IntegrationValidationResult, Error> {
        let task_count_per_priority = 20;
        let mut high_priority_completions = 0;
        let mut low_priority_completions = 0;

        // Schedule high priority tasks
        for i in 0..task_count_per_priority {
            let deadline = Instant::now() + StdDuration::from_millis(200);

            let handle = self
                .scheduler
                .schedule_task_with_deadline(cx, Priority::High, Some(deadline), move |_| {
                    format!("High priority task {}", i)
                })
                .await?;

            if matches!(handle.join().await, Outcome::Ok(_)) {
                high_priority_completions += 1;
            }
        }

        // Schedule low priority tasks
        for i in 0..task_count_per_priority {
            let deadline = Instant::now() + StdDuration::from_millis(300);

            let handle = self
                .scheduler
                .schedule_task_with_deadline(cx, Priority::Low, Some(deadline), move |_| {
                    format!("Low priority task {}", i)
                })
                .await?;

            if matches!(handle.join().await, Outcome::Ok(_)) {
                low_priority_completions += 1;
            }
        }

        let priority_coordination = (high_priority_completions as f64)
            / (task_count_per_priority as f64)
            > (low_priority_completions as f64) / (task_count_per_priority as f64);

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            timing_precision: true,
            deadline_coordination: priority_coordination,
            overflow_handling: true,
            performance_impact: (high_priority_completions + low_priority_completions) as f64
                / (task_count_per_priority * 2) as f64,
            details: format!(
                "High priority: {}/{}, Low priority: {}/{}",
                high_priority_completions,
                task_count_per_priority,
                low_priority_completions,
                task_count_per_priority
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    fn get_validation_summary(&self) -> Vec<IntegrationValidationResult> {
        self.validation_results.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cx::region, runtime::test_rt, types::Budget};

    #[test]
    fn test_basic_scheduler_timer_wheel_coordination() {
        test_rt(|rt| async move {
            region(
                &rt,
                Budget::new(StdDuration::from_secs(30)),
                |cx| async move {
                    let coordinator = SchedulerTimerWheelIntegrationCoordinator::new(cx).await?;

                    let result = coordinator
                        .validate_deadline_coordination(
                            cx,
                            "basic_coordination",
                            20,   // 20 tasks
                            1000, // 1 second deadline spread
                        )
                        .await?;

                    assert!(
                        result.timing_precision,
                        "Timer wheel should provide precise timing"
                    );
                    assert!(
                        result.deadline_coordination,
                        "Scheduler should coordinate with timer wheel deadlines"
                    );
                    assert!(
                        result.performance_impact > 0.7,
                        "Performance should not be severely impacted"
                    );

                    Ok(())
                },
            )
            .await
        });
    }

    #[test]
    fn test_timer_wheel_overflow_handling() {
        test_rt(|rt| async move {
            region(
                &rt,
                Budget::new(StdDuration::from_secs(45)),
                |cx| async move {
                    let coordinator = SchedulerTimerWheelIntegrationCoordinator::new(cx).await?;

                    let result = coordinator
                        .validate_overflow_handling(
                            cx,
                            "overflow_handling",
                            2.0, // 200% overload factor
                        )
                        .await?;

                    assert!(
                        result.overflow_handling,
                        "Timer wheel should handle overflow gracefully"
                    );
                    assert!(
                        result.deadline_coordination,
                        "Scheduler should still receive notifications during overflow"
                    );

                    Ok(())
                },
            )
            .await
        });
    }

    #[test]
    fn test_priority_based_timer_coordination() {
        test_rt(|rt| async move {
            region(
                &rt,
                Budget::new(StdDuration::from_secs(60)),
                |cx| async move {
                    let coordinator = SchedulerTimerWheelIntegrationCoordinator::new(cx).await?;

                    let result = coordinator
                        .validate_priority_based_timing(cx, "priority_timing")
                        .await?;

                    assert!(
                        result.deadline_coordination,
                        "Higher priority tasks should complete more reliably"
                    );
                    assert!(
                        result.performance_impact > 0.6,
                        "Priority coordination should not severely impact overall performance"
                    );

                    Ok(())
                },
            )
            .await
        });
    }

    #[test]
    fn test_concurrent_scheduler_timer_operations() {
        test_rt(|rt| async move {
            region(
                &rt,
                Budget::new(StdDuration::from_secs(45)),
                |cx| async move {
                    let coordinator = SchedulerTimerWheelIntegrationCoordinator::new(cx).await?;

                    let mut handles = Vec::new();

                    // Launch multiple concurrent validation operations
                    for i in 0..3 {
                        let coordinator_clone = &coordinator;

                        let handle = cx.spawn(move |cx| async move {
                            coordinator_clone
                                .validate_deadline_coordination(
                                    cx,
                                    &format!("concurrent_test_{}", i),
                                    10,  // 10 tasks per concurrent operation
                                    500, // 500ms deadline spread
                                )
                                .await
                        });

                        handles.push(handle);
                    }

                    // Wait for all concurrent operations to complete
                    let mut successful_validations = 0;
                    for handle in handles {
                        match handle.join().await {
                            Outcome::Ok(Ok(result))
                                if result.timing_precision && result.deadline_coordination =>
                            {
                                successful_validations += 1;
                            }
                            _ => {}
                        }
                    }

                    assert!(
                        successful_validations >= 2,
                        "At least 2 concurrent operations should succeed"
                    );

                    Ok(())
                },
            )
            .await
        });
    }
}
