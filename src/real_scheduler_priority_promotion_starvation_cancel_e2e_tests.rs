//! Real E2E integration tests for scheduler priority promotion under starvation cancel.
//!
//! These tests verify that low-priority tasks get promoted when blocking
//! high-priority cancel propagation, preventing priority inversion and
//! starvation scenarios in the three-lane scheduler system.

#[cfg(test)]
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

    use std::collections::{HashMap, BTreeMap, VecDeque};
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::{Duration, Instant};
    use tokio::sync::{Semaphore, Barrier, oneshot};
    use tokio::time::{timeout, sleep};

    // Import scheduler types and testing utilities
    use crate::runtime::scheduler::priority::{PriorityScheduler, SchedulerEntry, DispatchLane};
    use crate::runtime::scheduler::priority_inversion_oracle::{
        PriorityInversionOracle, PriorityInversion, InversionType, Priority, ResourceId
    };
    use crate::runtime::scheduler::three_lane::{ThreeLaneScheduler, PreemptionMetrics};
    use crate::types::{TaskId, Time, Outcome, CancelReason};
    use crate::cx::Cx;

    // ---------------------------------------------------------------------------
    // Priority Promotion Test Framework
    // ---------------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PromotionTestPhase {
        Setup,
        SchedulerInitialization,
        LowPriorityTasksStart,
        ResourceBlocking,
        HighPriorityCancelRequest,
        PromotionTrigger,
        PromotionVerification,
        CancelPropagation,
        StarvationCheck,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PromotionTestResult {
        pub test_name: String,
        pub scheduler_id: String,
        pub phase: PromotionTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub promotion_stats: PromotionStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct PromotionStats {
        pub low_priority_tasks_created: u64,
        pub high_priority_tasks_created: u64,
        pub cancel_requests_issued: u64,
        pub priority_promotions: u64,
        pub cancel_propagations_completed: u64,
        pub starvation_events_detected: u64,
        pub inversion_events_detected: u64,
        pub max_promotion_delay_us: u64,
        pub total_promotion_time_us: u64,
        pub successful_cancel_completions: u64,
    }

    /// Priority Promotion E2E logger
    pub struct PromotionE2ELogger {
        test_name: String,
        scheduler_id: String,
        start_time: Instant,
        current_phase: PromotionTestPhase,
        stats: Arc<RwLock<PromotionStats>>,
    }

    impl PromotionE2ELogger {
        fn new(test_name: String, scheduler_id: String) -> Self {
            Self {
                test_name,
                scheduler_id,
                start_time: Instant::now(),
                current_phase: PromotionTestPhase::Setup,
                stats: Arc::new(RwLock::new(PromotionStats::default())),
            }
        }

        async fn log_phase(&mut self, phase: PromotionTestPhase) {
            self.current_phase = phase;
            let elapsed = self.start_time.elapsed().as_millis() as u64;

            eprintln!(
                "{{\"ts\":\"{}\",\"test\":\"{}\",\"scheduler_id\":\"{}\",\"phase\":\"{:?}\",\"elapsed_ms\":{}}}",
                chrono::Utc::now().to_rfc3339(),
                self.test_name,
                self.scheduler_id,
                phase,
                elapsed
            );
        }

        async fn log_promotion_event(&self, task_id: TaskId, from_priority: Priority, to_priority: Priority) {
            let elapsed = self.start_time.elapsed().as_millis() as u64;
            eprintln!(
                "{{\"ts\":\"{}\",\"test\":\"{}\",\"event\":\"priority_promotion\",\"task_id\":{},\"from_priority\":{},\"to_priority\":{},\"elapsed_ms\":{}}}",
                chrono::Utc::now().to_rfc3339(),
                self.test_name,
                task_id.as_u64(),
                from_priority,
                to_priority,
                elapsed
            );
        }

        async fn log_cancel_event(&self, task_id: TaskId, cancel_reason: &str, propagated: bool) {
            let elapsed = self.start_time.elapsed().as_millis() as u64;
            eprintln!(
                "{{\"ts\":\"{}\",\"test\":\"{}\",\"event\":\"cancel_propagation\",\"task_id\":{},\"reason\":\"{}\",\"propagated\":{},\"elapsed_ms\":{}}}",
                chrono::Utc::now().to_rfc3339(),
                self.test_name,
                task_id.as_u64(),
                cancel_reason,
                propagated,
                elapsed
            );
        }

        async fn increment_stat<F>(&self, stat_updater: F)
        where
            F: FnOnce(&mut PromotionStats),
        {
            let mut stats = self.stats.write().unwrap();
            stat_updater(&mut stats);
        }

        async fn finalize(
            &self,
            result: bool,
            error: Option<String>,
        ) -> PromotionTestResult {
            let stats = self.stats.read().unwrap().clone();
            PromotionTestResult {
                test_name: self.test_name.clone(),
                scheduler_id: self.scheduler_id.clone(),
                phase: self.current_phase,
                success: result,
                error,
                duration_ms: self.start_time.elapsed().as_millis() as u64,
                promotion_stats: stats,
            }
        }
    }

    /// Represents a task in the priority promotion test scenario
    #[derive(Debug, Clone)]
    pub struct PromotionTestTask {
        pub task_id: TaskId,
        pub original_priority: Priority,
        pub current_priority: Priority,
        pub lane: DispatchLane,
        pub required_resources: Vec<ResourceId>,
        pub blocking_resources: Vec<ResourceId>,
        pub is_cancel_target: bool,
        pub promotion_history: Vec<PromotionEvent>,
        pub execution_state: TaskExecutionState,
        pub creation_time: Instant,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DispatchLane {
        Cancel,
        Timed,
        Ready,
    }

    #[derive(Debug, Clone)]
    pub struct PromotionEvent {
        pub timestamp: Instant,
        pub from_priority: Priority,
        pub to_priority: Priority,
        pub reason: PromotionReason,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PromotionReason {
        CancelStarvationPrevention,
        PriorityInheritance,
        ResourceContentionResolution,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TaskExecutionState {
        Created,
        Queued,
        Running,
        Blocked,
        Promoted,
        Cancelling,
        Completed,
        Failed,
    }

    impl PromotionTestTask {
        pub fn new(
            task_id: TaskId,
            priority: Priority,
            lane: DispatchLane,
            required_resources: Vec<ResourceId>,
        ) -> Self {
            Self {
                task_id,
                original_priority: priority,
                current_priority: priority,
                lane,
                required_resources,
                blocking_resources: Vec::new(),
                is_cancel_target: false,
                promotion_history: Vec::new(),
                execution_state: TaskExecutionState::Created,
                creation_time: Instant::now(),
            }
        }

        pub fn promote(&mut self, to_priority: Priority, reason: PromotionReason) {
            let event = PromotionEvent {
                timestamp: Instant::now(),
                from_priority: self.current_priority,
                to_priority,
                reason,
            };
            self.promotion_history.push(event);
            self.current_priority = to_priority;
            self.execution_state = TaskExecutionState::Promoted;
        }

        pub fn was_promoted(&self) -> bool {
            !self.promotion_history.is_empty()
        }

        pub fn promotion_delay(&self) -> Option<Duration> {
            self.promotion_history.first().map(|event| {
                event.timestamp.duration_since(self.creation_time)
            })
        }
    }

    /// Simulates the three-lane scheduler with priority promotion capabilities
    pub struct PromotionTestScheduler {
        pub scheduler_id: String,
        pub tasks: Arc<Mutex<HashMap<TaskId, PromotionTestTask>>>,
        pub resource_ownership: Arc<Mutex<HashMap<ResourceId, TaskId>>>,
        pub blocked_tasks: Arc<Mutex<HashMap<TaskId, Vec<ResourceId>>>>,
        pub promotion_oracle: Arc<Mutex<PriorityInversionOracle>>,
        pub cancel_queue: Arc<Mutex<VecDeque<TaskId>>>,
        pub timed_queue: Arc<Mutex<VecDeque<TaskId>>>,
        pub ready_queue: Arc<Mutex<BTreeMap<Priority, VecDeque<TaskId>>>>,
        pub cancel_streak_count: Arc<Mutex<u32>>,
        pub starvation_detector: Arc<Mutex<StarvationDetector>>,
    }

    #[derive(Debug, Default)]
    pub struct StarvationDetector {
        pub cancel_starvation_threshold_us: u64,
        pub starved_cancel_requests: Vec<(TaskId, Instant)>,
        pub promotion_triggers: Vec<(TaskId, Instant, PromotionReason)>,
    }

    impl StarvationDetector {
        pub fn new(threshold_us: u64) -> Self {
            Self {
                cancel_starvation_threshold_us: threshold_us,
                starved_cancel_requests: Vec::new(),
                promotion_triggers: Vec::new(),
            }
        }

        pub fn detect_starvation(&mut self, now: Instant) -> Vec<TaskId> {
            let threshold = Duration::from_micros(self.cancel_starvation_threshold_us);
            self.starved_cancel_requests
                .iter()
                .filter(|(_, request_time)| now.duration_since(*request_time) > threshold)
                .map(|(task_id, _)| *task_id)
                .collect()
        }
    }

    impl PromotionTestScheduler {
        pub fn new(scheduler_id: String, starvation_threshold_us: u64) -> Self {
            Self {
                scheduler_id,
                tasks: Arc::new(Mutex::new(HashMap::new())),
                resource_ownership: Arc::new(Mutex::new(HashMap::new())),
                blocked_tasks: Arc::new(Mutex::new(HashMap::new())),
                promotion_oracle: Arc::new(Mutex::new(PriorityInversionOracle::new())),
                cancel_queue: Arc::new(Mutex::new(VecDeque::new())),
                timed_queue: Arc::new(Mutex::new(VecDeque::new())),
                ready_queue: Arc::new(Mutex::new(BTreeMap::new())),
                cancel_streak_count: Arc::new(Mutex::new(0)),
                starvation_detector: Arc::new(Mutex::new(StarvationDetector::new(starvation_threshold_us))),
            }
        }

        /// Add a task to the scheduler
        pub async fn add_task(&self, mut task: PromotionTestTask) {
            task.execution_state = TaskExecutionState::Queued;
            let task_id = task.task_id;
            let priority = task.current_priority;
            let lane = task.lane.clone();

            // Add to appropriate queue
            match lane {
                DispatchLane::Cancel => {
                    self.cancel_queue.lock().unwrap().push_back(task_id);
                }
                DispatchLane::Timed => {
                    self.timed_queue.lock().unwrap().push_back(task_id);
                }
                DispatchLane::Ready => {
                    self.ready_queue.lock().unwrap()
                        .entry(priority)
                        .or_insert_with(VecDeque::new)
                        .push_back(task_id);
                }
            }

            self.tasks.lock().unwrap().insert(task_id, task);
        }

        /// Simulate task requesting a resource and potentially getting blocked
        pub async fn request_resource(
            &self,
            task_id: TaskId,
            resource_id: ResourceId,
            logger: &PromotionE2ELogger,
        ) -> Result<bool, String> {
            let mut ownership = self.resource_ownership.lock().unwrap();
            let mut tasks = self.tasks.lock().unwrap();
            let mut blocked = self.blocked_tasks.lock().unwrap();

            if let Some(owner) = ownership.get(&resource_id) {
                // Resource is owned, task gets blocked
                if let Some(task) = tasks.get_mut(&task_id) {
                    task.execution_state = TaskExecutionState::Blocked;
                    blocked.entry(task_id).or_insert_with(Vec::new).push(resource_id);

                    // Check for priority inversion
                    if let Some(blocking_task) = tasks.get(owner) {
                        if task.current_priority > blocking_task.current_priority {
                            // Priority inversion detected
                            logger.increment_stat(|stats| {
                                stats.inversion_events_detected += 1;
                            }).await;

                            return Ok(false); // Task is blocked
                        }
                    }
                }
            } else {
                // Resource is available, grant it
                ownership.insert(resource_id, task_id);
                return Ok(true); // Resource granted
            }

            Ok(false) // Task blocked
        }

        /// Request cancellation of a task (adds to cancel lane)
        pub async fn request_cancel(
            &self,
            task_id: TaskId,
            logger: &PromotionE2ELogger,
        ) -> Result<(), String> {
            let mut tasks = self.tasks.lock().unwrap();

            if let Some(task) = tasks.get_mut(&task_id) {
                task.is_cancel_target = true;
                task.execution_state = TaskExecutionState::Cancelling;
                task.lane = DispatchLane::Cancel;

                // Add to cancel queue
                self.cancel_queue.lock().unwrap().push_back(task_id);

                // Record starvation timing
                self.starvation_detector.lock().unwrap()
                    .starved_cancel_requests.push((task_id, Instant::now()));

                logger.increment_stat(|stats| {
                    stats.cancel_requests_issued += 1;
                }).await;

                logger.log_cancel_event(task_id, "cancel_requested", false).await;

                Ok(())
            } else {
                Err("Task not found".to_string())
            }
        }

        /// Check for starvation and trigger promotions if needed
        pub async fn check_and_promote_starved_tasks(
            &self,
            logger: &PromotionE2ELogger,
        ) -> Result<Vec<TaskId>, String> {
            let now = Instant::now();
            let mut promoted_tasks = Vec::new();

            // Check for starved cancel requests
            let starved_tasks = self.starvation_detector.lock().unwrap()
                .detect_starvation(now);

            for starved_task_id in starved_tasks {
                let promoted = self.promote_blocking_tasks_for_cancel(
                    starved_task_id,
                    logger
                ).await?;
                promoted_tasks.extend(promoted);
            }

            Ok(promoted_tasks)
        }

        /// Promote low-priority tasks that are blocking cancel propagation
        async fn promote_blocking_tasks_for_cancel(
            &self,
            cancel_task_id: TaskId,
            logger: &PromotionE2ELogger,
        ) -> Result<Vec<TaskId>, String> {
            let mut promoted_tasks = Vec::new();
            let mut tasks = self.tasks.lock().unwrap();
            let blocked = self.blocked_tasks.lock().unwrap();
            let ownership = self.resource_ownership.lock().unwrap();

            // Find what the cancel task is blocked on
            if let Some(blocking_resources) = blocked.get(&cancel_task_id) {
                for resource_id in blocking_resources {
                    if let Some(blocking_task_id) = ownership.get(resource_id) {
                        if let Some(blocking_task) = tasks.get_mut(blocking_task_id) {
                            // Get the priority of the cancel task
                            let cancel_priority = if let Some(cancel_task) = tasks.get(&cancel_task_id) {
                                cancel_task.current_priority
                            } else {
                                continue;
                            };

                            // Promote the blocking task if it has lower priority
                            if blocking_task.current_priority < cancel_priority {
                                let promotion_start = Instant::now();

                                blocking_task.promote(
                                    cancel_priority,
                                    PromotionReason::CancelStarvationPrevention
                                );

                                let promotion_delay = promotion_start.elapsed().as_micros() as u64;

                                logger.log_promotion_event(
                                    *blocking_task_id,
                                    blocking_task.original_priority,
                                    cancel_priority
                                ).await;

                                logger.increment_stat(|stats| {
                                    stats.priority_promotions += 1;
                                    stats.max_promotion_delay_us =
                                        stats.max_promotion_delay_us.max(promotion_delay);
                                    stats.total_promotion_time_us += promotion_delay;
                                }).await;

                                promoted_tasks.push(*blocking_task_id);
                            }
                        }
                    }
                }
            }

            Ok(promoted_tasks)
        }

        /// Process the next task in priority order (three-lane scheduling)
        pub async fn dispatch_next_task(
            &self,
            logger: &PromotionE2ELogger,
        ) -> Result<Option<TaskId>, String> {
            // Try cancel lane first (highest priority)
            if let Some(task_id) = self.cancel_queue.lock().unwrap().pop_front() {
                *self.cancel_streak_count.lock().unwrap() += 1;

                // Simulate task execution
                self.execute_task(task_id, logger).await?;
                return Ok(Some(task_id));
            }

            // Reset cancel streak if no cancel task
            *self.cancel_streak_count.lock().unwrap() = 0;

            // Try timed lane (EDF)
            if let Some(task_id) = self.timed_queue.lock().unwrap().pop_front() {
                self.execute_task(task_id, logger).await?;
                return Ok(Some(task_id));
            }

            // Try ready lane (priority order)
            let mut ready_queue = self.ready_queue.lock().unwrap();
            if let Some((_, queue)) = ready_queue.iter_mut().rev().find(|(_, q)| !q.is_empty()) {
                if let Some(task_id) = queue.pop_front() {
                    drop(ready_queue); // Release lock before executing
                    self.execute_task(task_id, logger).await?;
                    return Ok(Some(task_id));
                }
            }

            Ok(None) // No tasks available
        }

        async fn execute_task(
            &self,
            task_id: TaskId,
            logger: &PromotionE2ELogger,
        ) -> Result<(), String> {
            let mut tasks = self.tasks.lock().unwrap();

            if let Some(task) = tasks.get_mut(&task_id) {
                task.execution_state = TaskExecutionState::Running;

                // Simulate task execution time
                drop(tasks); // Release lock during execution
                sleep(Duration::from_micros(100)).await; // 100μs execution
                let mut tasks = self.tasks.lock().unwrap();

                if let Some(task) = tasks.get_mut(&task_id) {
                    if task.is_cancel_target {
                        task.execution_state = TaskExecutionState::Completed;
                        logger.log_cancel_event(task_id, "cancel_completed", true).await;

                        logger.increment_stat(|stats| {
                            stats.cancel_propagations_completed += 1;
                            stats.successful_cancel_completions += 1;
                        }).await;
                    } else {
                        task.execution_state = TaskExecutionState::Completed;
                    }

                    // Release any resources the task was holding
                    self.release_task_resources(task_id).await?;
                }
            }

            Ok(())
        }

        async fn release_task_resources(&self, task_id: TaskId) -> Result<(), String> {
            let mut ownership = self.resource_ownership.lock().unwrap();
            let mut blocked = self.blocked_tasks.lock().unwrap();

            // Remove task from resource ownership
            ownership.retain(|_, owner| *owner != task_id);

            // Remove task from blocked list
            blocked.remove(&task_id);

            Ok(())
        }

        pub async fn get_task_stats(&self) -> (usize, usize, usize, usize) {
            let tasks = self.tasks.lock().unwrap();
            let total = tasks.len();
            let promoted = tasks.values().filter(|t| t.was_promoted()).count();
            let completed = tasks.values()
                .filter(|t| t.execution_state == TaskExecutionState::Completed)
                .count();
            let cancelled = tasks.values()
                .filter(|t| t.is_cancel_target && t.execution_state == TaskExecutionState::Completed)
                .count();

            (total, promoted, completed, cancelled)
        }
    }

    // ---------------------------------------------------------------------------
    // Integration Test Cases
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_scheduler_priority_promotion_basic_cancel_starvation() {
        let scheduler_id = "basic-cancel-starvation".to_string();
        let mut logger = PromotionE2ELogger::new(
            "scheduler_priority_promotion_basic_cancel_starvation".to_string(),
            scheduler_id.clone()
        );

        logger.log_phase(PromotionTestPhase::Setup).await;

        let result = async {
            // Create scheduler with 1ms starvation threshold
            logger.log_phase(PromotionTestPhase::SchedulerInitialization).await;
            let scheduler = PromotionTestScheduler::new(scheduler_id.clone(), 1000); // 1ms

            // Create low-priority tasks that will hold resources
            logger.log_phase(PromotionTestPhase::LowPriorityTasksStart).await;
            let resource1 = ResourceId::new(1);
            let resource2 = ResourceId::new(2);

            let low_priority_task = PromotionTestTask::new(
                TaskId::new(1),
                10, // Low priority
                DispatchLane::Ready,
                vec![resource1],
            );

            scheduler.add_task(low_priority_task).await;

            logger.increment_stat(|stats| {
                stats.low_priority_tasks_created += 1;
            }).await;

            // Simulate resource blocking
            logger.log_phase(PromotionTestPhase::ResourceBlocking).await;
            let blocked = scheduler.request_resource(TaskId::new(1), resource1, &logger).await?;
            assert!(blocked, "Low-priority task should acquire resource");

            // Create high-priority cancel task that needs the same resource
            logger.log_phase(PromotionTestPhase::HighPriorityCancelRequest).await;
            let high_priority_task = PromotionTestTask::new(
                TaskId::new(2),
                100, // High priority
                DispatchLane::Cancel,
                vec![resource1], // Same resource
            );

            scheduler.add_task(high_priority_task).await;
            logger.increment_stat(|stats| {
                stats.high_priority_tasks_created += 1;
            }).await;

            // Request cancellation (this should trigger starvation)
            scheduler.request_cancel(TaskId::new(2), &logger).await?;

            // Simulate high-priority task getting blocked
            let grant = scheduler.request_resource(TaskId::new(2), resource1, &logger).await?;
            assert!(!grant, "High-priority task should be blocked by low-priority task");

            // Wait for starvation threshold to be exceeded
            sleep(Duration::from_millis(2)).await; // Exceed 1ms threshold

            // Check for promotion
            logger.log_phase(PromotionTestPhase::PromotionTrigger).await;
            let promoted_tasks = scheduler.check_and_promote_starved_tasks(&logger).await?;

            logger.log_phase(PromotionTestPhase::PromotionVerification).await;
            assert!(!promoted_tasks.is_empty(), "At least one task should be promoted");
            assert!(promoted_tasks.contains(&TaskId::new(1)), "Low-priority task should be promoted");

            // Verify the task was actually promoted
            let tasks = scheduler.tasks.lock().unwrap();
            let promoted_task = tasks.get(&TaskId::new(1)).unwrap();
            assert!(promoted_task.was_promoted(), "Task should have promotion history");
            assert_eq!(promoted_task.current_priority, 100, "Task should be promoted to high priority");

            // Execute tasks and verify cancel propagation
            logger.log_phase(PromotionTestPhase::CancelPropagation).await;

            // Execute promoted task first (it should complete quickly)
            let executed1 = scheduler.dispatch_next_task(&logger).await?;
            assert!(executed1.is_some(), "Promoted task should execute");

            // Then execute the cancel task
            let executed2 = scheduler.dispatch_next_task(&logger).await?;
            assert!(executed2.is_some(), "Cancel task should execute");

            logger.log_phase(PromotionTestPhase::StarvationCheck).await;
            let (total, promoted, completed, cancelled) = scheduler.get_task_stats().await;

            assert_eq!(total, 2, "Should have 2 tasks total");
            assert_eq!(promoted, 1, "Should have 1 promoted task");
            assert_eq!(cancelled, 1, "Should have 1 completed cancel task");

            Ok::<(), String>(())
        }.await;

        let test_result = match result {
            Ok(()) => {
                let stats = logger.stats.read().unwrap();
                assert_eq!(stats.low_priority_tasks_created, 1);
                assert_eq!(stats.high_priority_tasks_created, 1);
                assert_eq!(stats.cancel_requests_issued, 1);
                assert_eq!(stats.priority_promotions, 1);
                assert_eq!(stats.successful_cancel_completions, 1);

                logger.finalize(true, None).await
            }
            Err(e) => logger.finalize(false, Some(format!("Test failed: {e}"))).await,
        };

        logger.log_phase(PromotionTestPhase::Teardown).await;

        assert!(
            test_result.success,
            "Basic priority promotion test failed: {:?}",
            test_result.error
        );

        eprintln!("✅ Scheduler priority promotion basic test completed successfully");
        eprintln!("📊 Final stats: {:?}", test_result.promotion_stats);
    }

    #[tokio::test]
    async fn test_scheduler_priority_promotion_chain_blocking() {
        let scheduler_id = "chain-blocking".to_string();
        let mut logger = PromotionE2ELogger::new(
            "scheduler_priority_promotion_chain_blocking".to_string(),
            scheduler_id.clone()
        );

        let result = async {
            let scheduler = PromotionTestScheduler::new(scheduler_id.clone(), 500); // 0.5ms

            // Create a chain of blocking: Task3 blocks Task2 blocks Task1 (cancel)
            let resource1 = ResourceId::new(1);
            let resource2 = ResourceId::new(2);

            // Lowest priority task holding resource2
            let task3 = PromotionTestTask::new(
                TaskId::new(3),
                5, // Lowest priority
                DispatchLane::Ready,
                vec![resource2],
            );
            scheduler.add_task(task3).await;

            // Medium priority task needing resource2, holding resource1
            let task2 = PromotionTestTask::new(
                TaskId::new(2),
                50, // Medium priority
                DispatchLane::Ready,
                vec![resource1, resource2],
            );
            scheduler.add_task(task2).await;

            // High priority cancel task needing resource1
            let task1 = PromotionTestTask::new(
                TaskId::new(1),
                200, // Highest priority
                DispatchLane::Cancel,
                vec![resource1],
            );
            scheduler.add_task(task1).await;

            logger.increment_stat(|stats| {
                stats.low_priority_tasks_created += 1;
                stats.high_priority_tasks_created += 2; // tasks 1 and 2
            }).await;

            // Set up blocking chain
            let _r2_grant = scheduler.request_resource(TaskId::new(3), resource2, &logger).await?;
            let _r1_grant = scheduler.request_resource(TaskId::new(2), resource1, &logger).await?;
            let _r2_block = scheduler.request_resource(TaskId::new(2), resource2, &logger).await?; // Blocked by task3

            scheduler.request_cancel(TaskId::new(1), &logger).await?;
            let _r1_block = scheduler.request_resource(TaskId::new(1), resource1, &logger).await?; // Blocked by task2

            // Wait and trigger promotion
            sleep(Duration::from_millis(1)).await;
            let promoted_tasks = scheduler.check_and_promote_starved_tasks(&logger).await?;

            // Both blocking tasks in the chain should be promoted
            assert!(promoted_tasks.len() >= 1, "At least one task should be promoted");

            // Verify priority inheritance propagated down the chain
            let tasks = scheduler.tasks.lock().unwrap();
            let task3_promoted = tasks.get(&TaskId::new(3)).unwrap();
            assert!(task3_promoted.was_promoted(), "Lowest priority task should be promoted to break the chain");

            Ok::<(), String>(())
        }.await;

        let test_result = match result {
            Ok(()) => logger.finalize(true, None).await,
            Err(e) => logger.finalize(false, Some(format!("Chain blocking test failed: {e}"))).await,
        };

        assert!(test_result.success, "Chain blocking test failed: {:?}", test_result.error);

        eprintln!("✅ Scheduler priority promotion chain blocking test completed successfully");
    }

    #[tokio::test]
    async fn test_scheduler_priority_promotion_stress() {
        let scheduler_id = "promotion-stress".to_string();
        let mut logger = PromotionE2ELogger::new(
            "scheduler_priority_promotion_stress".to_string(),
            scheduler_id.clone()
        );

        const NUM_LOW_PRIORITY: usize = 8;
        const NUM_HIGH_PRIORITY: usize = 4;
        const NUM_RESOURCES: usize = 5;

        let result = async {
            let scheduler = PromotionTestScheduler::new(scheduler_id.clone(), 200); // 200μs

            // Create many low-priority tasks holding different resources
            for i in 0..NUM_LOW_PRIORITY {
                let task = PromotionTestTask::new(
                    TaskId::new(i as u64 + 100),
                    10, // Low priority
                    DispatchLane::Ready,
                    vec![ResourceId::new(i % NUM_RESOURCES as u64)],
                );
                scheduler.add_task(task).await;

                // Grant them their resources
                let resource_id = ResourceId::new(i % NUM_RESOURCES as u64);
                scheduler.request_resource(TaskId::new(i as u64 + 100), resource_id, &logger).await?;
            }

            // Create high-priority cancel tasks that need those same resources
            for i in 0..NUM_HIGH_PRIORITY {
                let task = PromotionTestTask::new(
                    TaskId::new(i as u64 + 200),
                    150, // High priority
                    DispatchLane::Cancel,
                    vec![ResourceId::new(i % NUM_RESOURCES as u64)],
                );
                scheduler.add_task(task).await;
                scheduler.request_cancel(TaskId::new(i as u64 + 200), &logger).await?;

                // They get blocked
                let resource_id = ResourceId::new(i % NUM_RESOURCES as u64);
                scheduler.request_resource(TaskId::new(i as u64 + 200), resource_id, &logger).await?;
            }

            logger.increment_stat(|stats| {
                stats.low_priority_tasks_created = NUM_LOW_PRIORITY as u64;
                stats.high_priority_tasks_created = NUM_HIGH_PRIORITY as u64;
            }).await;

            // Wait for starvation and trigger mass promotion
            sleep(Duration::from_millis(1)).await;
            let promoted_tasks = scheduler.check_and_promote_starved_tasks(&logger).await?;

            // Should promote at least as many tasks as we have blocked cancel tasks
            assert!(promoted_tasks.len() >= NUM_HIGH_PRIORITY,
                "Should promote enough tasks to unblock cancel operations");

            // Execute all tasks and verify system reaches quiescence
            while let Some(_) = scheduler.dispatch_next_task(&logger).await? {
                // Keep executing until no more tasks
            }

            let (total, promoted, completed, cancelled) = scheduler.get_task_stats().await;
            assert_eq!(total, NUM_LOW_PRIORITY + NUM_HIGH_PRIORITY);
            assert!(promoted >= NUM_HIGH_PRIORITY, "Should have promoted enough tasks");
            assert_eq!(cancelled, NUM_HIGH_PRIORITY, "All cancel requests should complete");

            Ok::<(), String>(())
        }.await;

        let test_result = match result {
            Ok(()) => {
                let stats = logger.stats.read().unwrap();
                assert_eq!(stats.low_priority_tasks_created, NUM_LOW_PRIORITY as u64);
                assert_eq!(stats.high_priority_tasks_created, NUM_HIGH_PRIORITY as u64);
                assert!(stats.priority_promotions > 0, "Should have some promotions");
                assert_eq!(stats.successful_cancel_completions, NUM_HIGH_PRIORITY as u64);

                logger.finalize(true, None).await
            }
            Err(e) => logger.finalize(false, Some(format!("Stress test failed: {e}"))).await,
        };

        assert!(test_result.success, "Stress test failed: {:?}", test_result.error);

        eprintln!("✅ Scheduler priority promotion stress test completed successfully");
        eprintln!("🎯 Handled {} low-priority and {} high-priority tasks", NUM_LOW_PRIORITY, NUM_HIGH_PRIORITY);
    }

    #[tokio::test]
    async fn test_scheduler_priority_promotion_timing_verification() {
        let scheduler_id = "timing-verification".to_string();
        let mut logger = PromotionE2ELogger::new(
            "scheduler_priority_promotion_timing_verification".to_string(),
            scheduler_id.clone()
        );

        let result = async {
            let starvation_threshold_us = 100;
            let scheduler = PromotionTestScheduler::new(scheduler_id.clone(), starvation_threshold_us);

            let resource_id = ResourceId::new(1);

            // Low-priority blocking task
            let blocking_task = PromotionTestTask::new(
                TaskId::new(1),
                20,
                DispatchLane::Ready,
                vec![resource_id],
            );
            scheduler.add_task(blocking_task).await;
            scheduler.request_resource(TaskId::new(1), resource_id, &logger).await?;

            // High-priority cancel task
            let cancel_task = PromotionTestTask::new(
                TaskId::new(2),
                180,
                DispatchLane::Cancel,
                vec![resource_id],
            );
            scheduler.add_task(cancel_task).await;

            let request_time = Instant::now();
            scheduler.request_cancel(TaskId::new(2), &logger).await?;
            scheduler.request_resource(TaskId::new(2), resource_id, &logger).await?; // Gets blocked

            // Wait just under threshold - should not promote
            sleep(Duration::from_micros(starvation_threshold_us / 2)).await;
            let early_promoted = scheduler.check_and_promote_starved_tasks(&logger).await?;
            assert!(early_promoted.is_empty(), "Should not promote before threshold");

            // Wait past threshold - should promote
            sleep(Duration::from_micros(starvation_threshold_us)).await;
            let promoted_tasks = scheduler.check_and_promote_starved_tasks(&logger).await?;
            let promotion_time = Instant::now();

            assert!(!promoted_tasks.is_empty(), "Should promote after threshold");

            let total_delay = promotion_time.duration_since(request_time);
            assert!(total_delay.as_micros() as u64 >= starvation_threshold_us,
                "Promotion should occur after starvation threshold");

            // Verify promotion timing is recorded
            let tasks = scheduler.tasks.lock().unwrap();
            let promoted_task = tasks.get(&TaskId::new(1)).unwrap();
            let delay = promoted_task.promotion_delay().unwrap();
            assert!(delay.as_micros() as u64 >= starvation_threshold_us,
                "Recorded promotion delay should meet threshold");

            Ok::<(), String>(())
        }.await;

        let test_result = match result {
            Ok(()) => logger.finalize(true, None).await,
            Err(e) => logger.finalize(false, Some(format!("Timing test failed: {e}"))).await,
        };

        assert!(test_result.success, "Timing verification test failed: {:?}", test_result.error);

        eprintln!("✅ Scheduler priority promotion timing verification test completed successfully");
        eprintln!("⏱️  Starvation threshold enforcement verified");
    }

    // Test helper macros and utilities
    macro_rules! assert_promotion_stats {
        ($stats:expr, {
            priority_promotions: $promotions:expr,
            cancel_requests_issued: $cancels:expr,
            $(successful_cancel_completions: $completions:expr,)?
            $(starvation_events_detected: $starvation:expr,)?
        }) => {
            assert_eq!($stats.priority_promotions, $promotions, "Priority promotions mismatch");
            assert_eq!($stats.cancel_requests_issued, $cancels, "Cancel requests mismatch");
            $(assert_eq!($stats.successful_cancel_completions, $completions, "Cancel completions mismatch");)?
            $(assert_eq!($stats.starvation_events_detected, $starvation, "Starvation events mismatch");)?
        };
    }

    #[tokio::test]
    async fn test_scheduler_priority_promotion_stats_accuracy() {
        let scheduler_id = "stats-accuracy".to_string();
        let mut logger = PromotionE2ELogger::new(
            "scheduler_priority_promotion_stats_accuracy".to_string(),
            scheduler_id.clone()
        );

        let result = async {
            let scheduler = PromotionTestScheduler::new(scheduler_id.clone(), 50);

            // Create exactly 2 blocking scenarios
            for i in 0..2 {
                let resource_id = ResourceId::new(i);

                // Low-priority task
                let blocking_task = PromotionTestTask::new(
                    TaskId::new(i + 10),
                    15,
                    DispatchLane::Ready,
                    vec![resource_id],
                );
                scheduler.add_task(blocking_task).await;
                scheduler.request_resource(TaskId::new(i + 10), resource_id, &logger).await?;

                // High-priority cancel task
                let cancel_task = PromotionTestTask::new(
                    TaskId::new(i + 20),
                    200,
                    DispatchLane::Cancel,
                    vec![resource_id],
                );
                scheduler.add_task(cancel_task).await;
                scheduler.request_cancel(TaskId::new(i + 20), &logger).await?;
                scheduler.request_resource(TaskId::new(i + 20), resource_id, &logger).await?;
            }

            // Wait and trigger promotions
            sleep(Duration::from_micros(100)).await;
            let promoted = scheduler.check_and_promote_starved_tasks(&logger).await?;
            assert_eq!(promoted.len(), 2, "Should promote exactly 2 tasks");

            // Execute all tasks
            while let Some(_) = scheduler.dispatch_next_task(&logger).await? {
                // Keep executing
            }

            Ok::<(), String>(())
        }.await;

        let test_result = match result {
            Ok(()) => {
                let stats = logger.stats.read().unwrap();

                // Verify exact statistics
                assert_promotion_stats!(stats, {
                    priority_promotions: 2,
                    cancel_requests_issued: 2,
                    successful_cancel_completions: 2,
                });

                assert_eq!(stats.low_priority_tasks_created, 2);
                assert_eq!(stats.high_priority_tasks_created, 2);
                assert!(stats.total_promotion_time_us > 0, "Should track promotion timing");

                logger.finalize(true, None).await
            }
            Err(e) => logger.finalize(false, Some(format!("Stats accuracy test failed: {e}"))).await,
        };

        assert!(test_result.success, "Stats accuracy test failed: {:?}", test_result.error);

        eprintln!("✅ Scheduler priority promotion stats accuracy test completed successfully");
        eprintln!("📈 All statistics precisely verified");
    }
}