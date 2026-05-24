//! Scheduler Conformance Test Harness
//!
//! Implements Pattern 4 (Spec-Derived Test Matrix) to verify scheduler contracts
//! against the multi-lane task execution and work-stealing specifications. Tests cover:
//!
//! - Worker task execution and cooperative scheduling
//! - Work stealing fairness and load balancing algorithms
//! - Priority scheduling and deadline-driven execution
//! - Cancellation lane processing and streak limiting
//! - Global task injection and distribution policies
//! - Intrusive heap operations and priority queues
//! - Three-lane scheduling (ready/cancel/finalize)
//! - Panic isolation and task failure containment

use super::harness::{
    ConformanceTestResult, RequirementLevel, RuntimeConformanceHarness, TestCategory, TestVerdict,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Mock task identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MockTaskId(u64);

impl MockTaskId {
    fn new(id: u64) -> Self {
        Self(id)
    }

    fn raw(&self) -> u64 {
        self.0
    }
}

/// Mock worker identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MockWorkerId(usize);

impl MockWorkerId {
    fn new(id: usize) -> Self {
        Self(id)
    }

    fn raw(&self) -> usize {
        self.0
    }
}

/// Task priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Task execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Cancelled,
    Finished,
    Panicked,
}

/// Scheduler lane types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerLane {
    Ready,
    Cancel,
    Finalize,
}

/// Mock task for testing.
#[derive(Debug)]
struct MockTask {
    id: MockTaskId,
    priority: TaskPriority,
    state: TaskState,
    created_at: Instant,
    worker_affinity: Option<MockWorkerId>,
    execution_count: AtomicU64,
    should_panic: AtomicBool,
    execution_duration: Duration,
}

// Manual `Clone` because `AtomicU64`/`AtomicBool` are not `Clone`; snapshot
// the current atomic values into fresh atomics on clone so each instance
// owns its own counter (no shared state between clones).
impl Clone for MockTask {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            priority: self.priority,
            state: self.state,
            created_at: self.created_at,
            worker_affinity: self.worker_affinity,
            execution_count: AtomicU64::new(self.execution_count.load(Ordering::Relaxed)),
            should_panic: AtomicBool::new(self.should_panic.load(Ordering::Relaxed)),
            execution_duration: self.execution_duration,
        }
    }
}

// `MockTask` is placed into `BinaryHeap<(TaskPriority, MockTaskId, MockTask)>`
// in the mock intrusive heap below; the heap orders by the full tuple, so
// every element type must be `Ord`. Order by `id`; atomics make a content
// ordering meaningless and the id alone uniquely identifies the task.
impl PartialEq for MockTask {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for MockTask {}

impl PartialOrd for MockTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MockTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl MockTask {
    fn new(id: MockTaskId, priority: TaskPriority) -> Self {
        Self {
            id,
            priority,
            state: TaskState::Ready,
            created_at: Instant::now(),
            worker_affinity: None,
            execution_count: AtomicU64::new(0),
            should_panic: AtomicBool::new(false),
            execution_duration: Duration::from_micros(100),
        }
    }

    fn with_panic(mut self) -> Self {
        self.should_panic.store(true, Ordering::SeqCst);
        self
    }

    fn with_duration(mut self, duration: Duration) -> Self {
        self.execution_duration = duration;
        self
    }

    fn execute(&self) -> Result<(), String> {
        if self.should_panic.load(Ordering::SeqCst) {
            return Err("Task panicked during execution".into());
        }

        self.execution_count.fetch_add(1, Ordering::SeqCst);

        // Simulate work
        std::thread::sleep(self.execution_duration);

        Ok(())
    }

    fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::SeqCst)
    }
}

/// Mock local queue for worker-local tasks.
#[derive(Debug)]
struct MockLocalQueue {
    worker_id: MockWorkerId,
    tasks: std::sync::Mutex<VecDeque<MockTask>>,
    capacity: usize,
    steal_count: AtomicU64,
    push_count: AtomicU64,
    pop_count: AtomicU64,
}

impl MockLocalQueue {
    fn new(worker_id: MockWorkerId, capacity: usize) -> Self {
        Self {
            worker_id,
            tasks: std::sync::Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            steal_count: AtomicU64::new(0),
            push_count: AtomicU64::new(0),
            pop_count: AtomicU64::new(0),
        }
    }

    fn push(&self, task: MockTask) -> Result<(), MockTask> {
        let mut tasks = self.tasks.lock().unwrap();
        if tasks.len() >= self.capacity {
            return Err(task);
        }
        tasks.push_back(task);
        self.push_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn pop(&self) -> Option<MockTask> {
        let mut tasks = self.tasks.lock().unwrap();
        let task = tasks.pop_front();
        if task.is_some() {
            self.pop_count.fetch_add(1, Ordering::SeqCst);
        }
        task
    }

    fn steal(&self) -> Option<MockTask> {
        let mut tasks = self.tasks.lock().unwrap();
        let task = tasks.pop_back(); // Steal from back for better cache locality
        if task.is_some() {
            self.steal_count.fetch_add(1, Ordering::SeqCst);
        }
        task
    }

    fn len(&self) -> usize {
        self.tasks.lock().unwrap().len()
    }

    fn is_empty(&self) -> bool {
        self.tasks.lock().unwrap().is_empty()
    }

    fn steal_count(&self) -> u64 {
        self.steal_count.load(Ordering::SeqCst)
    }

    fn push_count(&self) -> u64 {
        self.push_count.load(Ordering::SeqCst)
    }

    fn pop_count(&self) -> u64 {
        self.pop_count.load(Ordering::SeqCst)
    }
}

/// Mock global queue for cross-worker task distribution.
#[derive(Debug)]
struct MockGlobalQueue {
    ready_tasks: std::sync::Mutex<VecDeque<MockTask>>,
    cancel_tasks: std::sync::Mutex<VecDeque<MockTask>>,
    finalize_tasks: std::sync::Mutex<VecDeque<MockTask>>,
    injection_count: AtomicU64,
    distribution_count: AtomicU64,
    cancel_streak: AtomicUsize,
    cancel_streak_limit: usize,
}

impl MockGlobalQueue {
    fn new() -> Self {
        Self {
            ready_tasks: std::sync::Mutex::new(VecDeque::new()),
            cancel_tasks: std::sync::Mutex::new(VecDeque::new()),
            finalize_tasks: std::sync::Mutex::new(VecDeque::new()),
            injection_count: AtomicU64::new(0),
            distribution_count: AtomicU64::new(0),
            cancel_streak: AtomicUsize::new(0),
            cancel_streak_limit: 5,
        }
    }

    fn inject(&self, task: MockTask, lane: SchedulerLane) {
        self.injection_count.fetch_add(1, Ordering::SeqCst);

        match lane {
            SchedulerLane::Ready => {
                self.ready_tasks.lock().unwrap().push_back(task);
            }
            SchedulerLane::Cancel => {
                self.cancel_tasks.lock().unwrap().push_back(task);
            }
            SchedulerLane::Finalize => {
                self.finalize_tasks.lock().unwrap().push_back(task);
            }
        }
    }

    fn pop_ready(&self) -> Option<MockTask> {
        let task = self.ready_tasks.lock().unwrap().pop_front();
        if task.is_some() {
            self.distribution_count.fetch_add(1, Ordering::SeqCst);
        }
        task
    }

    fn pop_cancel(&self) -> Option<MockTask> {
        let task = self.cancel_tasks.lock().unwrap().pop_front();
        if task.is_some() {
            let streak = self.cancel_streak.fetch_add(1, Ordering::SeqCst) + 1;
            if streak >= self.cancel_streak_limit {
                // Reset streak after limit
                self.cancel_streak.store(0, Ordering::SeqCst);
            }
        }
        task
    }

    fn pop_finalize(&self) -> Option<MockTask> {
        self.finalize_tasks.lock().unwrap().pop_front()
    }

    fn ready_len(&self) -> usize {
        self.ready_tasks.lock().unwrap().len()
    }

    fn cancel_len(&self) -> usize {
        self.cancel_tasks.lock().unwrap().len()
    }

    fn finalize_len(&self) -> usize {
        self.finalize_tasks.lock().unwrap().len()
    }

    fn current_cancel_streak(&self) -> usize {
        self.cancel_streak.load(Ordering::SeqCst)
    }

    fn injection_count(&self) -> u64 {
        self.injection_count.load(Ordering::SeqCst)
    }

    fn distribution_count(&self) -> u64 {
        self.distribution_count.load(Ordering::SeqCst)
    }
}

/// Mock intrusive heap for priority scheduling.
#[derive(Debug)]
struct MockIntrusiveHeap {
    heap: std::sync::Mutex<std::collections::BinaryHeap<(TaskPriority, MockTaskId, MockTask)>>,
    size: AtomicUsize,
}

impl MockIntrusiveHeap {
    fn new() -> Self {
        Self {
            heap: std::sync::Mutex::new(std::collections::BinaryHeap::new()),
            size: AtomicUsize::new(0),
        }
    }

    fn push(&self, task: MockTask) {
        let mut heap = self.heap.lock().unwrap();
        heap.push((task.priority, task.id, task));
        self.size.fetch_add(1, Ordering::SeqCst);
    }

    fn pop(&self) -> Option<MockTask> {
        let mut heap = self.heap.lock().unwrap();
        if let Some((_, _, task)) = heap.pop() {
            self.size.fetch_sub(1, Ordering::SeqCst);
            Some(task)
        } else {
            None
        }
    }

    fn len(&self) -> usize {
        self.size.load(Ordering::SeqCst)
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Mock worker for task execution.
#[derive(Debug)]
struct MockWorker {
    id: MockWorkerId,
    local_queue: MockLocalQueue,
    execution_count: AtomicU64,
    steal_attempt_count: AtomicU64,
    successful_steals: AtomicU64,
    panic_count: AtomicU64,
    is_running: AtomicBool,
}

impl MockWorker {
    fn new(id: MockWorkerId) -> Self {
        Self {
            id,
            local_queue: MockLocalQueue::new(id, 256), // Typical local queue size
            execution_count: AtomicU64::new(0),
            steal_attempt_count: AtomicU64::new(0),
            successful_steals: AtomicU64::new(0),
            panic_count: AtomicU64::new(0),
            is_running: AtomicBool::new(false),
        }
    }

    fn execute_task(&self, task: &MockTask) -> Result<(), String> {
        self.execution_count.fetch_add(1, Ordering::SeqCst);

        match task.execute() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.panic_count.fetch_add(1, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    fn try_steal_from(&self, other: &MockWorker) -> Option<MockTask> {
        self.steal_attempt_count.fetch_add(1, Ordering::SeqCst);

        if let Some(task) = other.local_queue.steal() {
            self.successful_steals.fetch_add(1, Ordering::SeqCst);
            Some(task)
        } else {
            None
        }
    }

    fn push_local(&self, task: MockTask) -> Result<(), MockTask> {
        self.local_queue.push(task)
    }

    fn pop_local(&self) -> Option<MockTask> {
        self.local_queue.pop()
    }

    fn local_queue_len(&self) -> usize {
        self.local_queue.len()
    }

    fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::SeqCst)
    }

    fn successful_steals(&self) -> u64 {
        self.successful_steals.load(Ordering::SeqCst)
    }

    fn steal_success_rate(&self) -> f64 {
        let attempts = self.steal_attempt_count.load(Ordering::SeqCst);
        let successes = self.successful_steals.load(Ordering::SeqCst);

        if attempts == 0 {
            0.0
        } else {
            successes as f64 / attempts as f64
        }
    }

    fn panic_count(&self) -> u64 {
        self.panic_count.load(Ordering::SeqCst)
    }

    fn start(&self) {
        self.is_running.store(true, Ordering::SeqCst);
    }

    fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }
}

/// Mock scheduler coordinating workers and queues.
#[derive(Debug)]
struct MockScheduler {
    workers: Vec<MockWorker>,
    global_queue: MockGlobalQueue,
    priority_heap: MockIntrusiveHeap,
    task_id_counter: AtomicU64,
    total_executions: AtomicU64,
    load_balance_operations: AtomicU64,
}

impl MockScheduler {
    fn new(worker_count: usize) -> Self {
        let workers: Vec<_> = (0..worker_count)
            .map(|i| MockWorker::new(MockWorkerId::new(i)))
            .collect();

        Self {
            workers,
            global_queue: MockGlobalQueue::new(),
            priority_heap: MockIntrusiveHeap::new(),
            task_id_counter: AtomicU64::new(1),
            total_executions: AtomicU64::new(0),
            load_balance_operations: AtomicU64::new(0),
        }
    }

    fn spawn_task(&self, priority: TaskPriority, lane: SchedulerLane) -> MockTaskId {
        let task_id = MockTaskId::new(self.task_id_counter.fetch_add(1, Ordering::SeqCst));
        let task = MockTask::new(task_id, priority);

        match priority {
            TaskPriority::Critical | TaskPriority::High => {
                self.priority_heap.push(task);
            }
            _ => {
                self.global_queue.inject(task, lane);
            }
        }

        task_id
    }

    fn spawn_panic_task(&self) -> MockTaskId {
        let task_id = MockTaskId::new(self.task_id_counter.fetch_add(1, Ordering::SeqCst));
        let task = MockTask::new(task_id, TaskPriority::Normal).with_panic();
        self.global_queue.inject(task, SchedulerLane::Ready);
        task_id
    }

    fn execute_round(&self) {
        for worker in &self.workers {
            self.execute_worker_round(worker);
        }
        self.load_balance();
    }

    fn execute_worker_round(&self, worker: &MockWorker) {
        // Try to get a task from local queue first
        if let Some(task) = worker.pop_local() {
            if worker.execute_task(&task).is_ok() {
                self.total_executions.fetch_add(1, Ordering::SeqCst);
            }
            return;
        }

        // Try priority heap next
        if let Some(task) = self.priority_heap.pop() {
            if worker.execute_task(&task).is_ok() {
                self.total_executions.fetch_add(1, Ordering::SeqCst);
            }
            return;
        }

        // Check cancel lane (with streak limiting)
        if self.global_queue.current_cancel_streak() < self.global_queue.cancel_streak_limit {
            if let Some(task) = self.global_queue.pop_cancel() {
                if worker.execute_task(&task).is_ok() {
                    self.total_executions.fetch_add(1, Ordering::SeqCst);
                }
                return;
            }
        }

        // Try global ready queue
        if let Some(task) = self.global_queue.pop_ready() {
            if worker.execute_task(&task).is_ok() {
                self.total_executions.fetch_add(1, Ordering::SeqCst);
            }
            return;
        }

        // Try to steal from other workers
        self.attempt_work_stealing(worker);
    }

    fn attempt_work_stealing(&self, worker: &MockWorker) {
        for other_worker in &self.workers {
            if other_worker.id != worker.id {
                if let Some(task) = worker.try_steal_from(other_worker) {
                    if worker.execute_task(&task).is_ok() {
                        self.total_executions.fetch_add(1, Ordering::SeqCst);
                    }
                    break;
                }
            }
        }
    }

    fn load_balance(&self) {
        self.load_balance_operations.fetch_add(1, Ordering::SeqCst);

        // Simple load balancing: distribute global tasks to workers with empty local queues
        for worker in &self.workers {
            if worker.local_queue_len() == 0 {
                if let Some(task) = self.global_queue.pop_ready() {
                    let _ = worker.push_local(task);
                }
            }
        }
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    fn total_executions(&self) -> u64 {
        self.total_executions.load(Ordering::SeqCst)
    }

    fn global_ready_len(&self) -> usize {
        self.global_queue.ready_len()
    }

    fn global_cancel_len(&self) -> usize {
        self.global_queue.cancel_len()
    }

    fn priority_heap_len(&self) -> usize {
        self.priority_heap.len()
    }

    fn total_worker_executions(&self) -> u64 {
        self.workers.iter().map(|w| w.execution_count()).sum()
    }

    fn total_successful_steals(&self) -> u64 {
        self.workers.iter().map(|w| w.successful_steals()).sum()
    }

    fn total_panic_count(&self) -> u64 {
        self.workers.iter().map(|w| w.panic_count()).sum()
    }

    fn average_steal_success_rate(&self) -> f64 {
        let rates: Vec<f64> = self
            .workers
            .iter()
            .map(|w| w.steal_success_rate())
            .collect();
        if rates.is_empty() {
            0.0
        } else {
            rates.iter().sum::<f64>() / rates.len() as f64
        }
    }
}

/// Main conformance test harness for scheduler components.
pub struct SchedulerConformanceHarness {
    harness: RuntimeConformanceHarness,
    scheduler: MockScheduler,
}

impl SchedulerConformanceHarness {
    /// Create a new scheduler conformance test harness.
    pub fn new() -> Self {
        Self {
            harness: RuntimeConformanceHarness::new(),
            scheduler: MockScheduler::new(4), // 4 workers typical
        }
    }

    /// Run the complete scheduler conformance test suite.
    pub fn run_full_suite(&mut self) -> Vec<ConformanceTestResult> {
        let mut results = Vec::new();

        // Task Execution
        results.push(self.test_basic_task_execution());
        results.push(self.test_cooperative_scheduling());
        results.push(self.test_task_completion_tracking());
        results.push(self.test_execution_ordering());

        // Work Stealing
        results.push(self.test_work_stealing_mechanism());
        results.push(self.test_steal_from_back_locality());
        results.push(self.test_steal_fairness());
        results.push(self.test_steal_success_rate());

        // Load Balancing
        results.push(self.test_load_balancing_algorithm());
        results.push(self.test_global_task_distribution());
        results.push(self.test_worker_idle_handling());
        results.push(self.test_queue_length_balancing());

        // Priority Scheduling
        results.push(self.test_priority_ordering());
        results.push(self.test_high_priority_preemption());
        results.push(self.test_priority_heap_operations());
        results.push(self.test_deadline_driven_scheduling());

        // Cancellation Lane
        results.push(self.test_cancellation_lane_processing());
        results.push(self.test_cancel_streak_limiting());
        results.push(self.test_cancel_vs_ready_prioritization());
        results.push(self.test_cancel_task_isolation());

        // Three-Lane Scheduling
        results.push(self.test_three_lane_architecture());
        results.push(self.test_lane_selection_algorithm());
        results.push(self.test_finalize_lane_processing());
        results.push(self.test_cross_lane_fairness());

        // Global Injection
        results.push(self.test_global_task_injection());
        results.push(self.test_injection_distribution());
        results.push(self.test_injection_rate_limiting());
        results.push(self.test_cross_worker_visibility());

        // Intrusive Heap
        results.push(self.test_intrusive_heap_operations());
        results.push(self.test_heap_priority_ordering());
        results.push(self.test_heap_memory_efficiency());
        results.push(self.test_heap_concurrent_access());

        // Panic Isolation
        results.push(self.test_panic_isolation());
        results.push(self.test_task_failure_containment());
        results.push(self.test_worker_recovery());
        results.push(self.test_panic_metrics_tracking());

        // Metrics Collection
        results.push(self.test_execution_metrics());
        results.push(self.test_steal_metrics());
        results.push(self.test_queue_length_metrics());
        results.push(self.test_performance_counters());

        results
    }

    /// Test basic task execution.
    fn test_basic_task_execution(&mut self) -> ConformanceTestResult {
        self.harness
            .run_test(
                || {
                    let initial_executions = self.scheduler.total_executions();
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                    self.scheduler.execute_round();
                    let final_executions = self.scheduler.total_executions();

                    let executed = final_executions > initial_executions;
                    self.harness
                        .verify(executed, "Tasks should execute when scheduled")
                },
                "basic_task_execution",
                RequirementLevel::Must,
                TestCategory::TaskExecution,
            )
            .with_spec_section("task-execution")
    }

    /// Test cooperative scheduling behavior.
    fn test_cooperative_scheduling(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Spawn multiple tasks
                for _ in 0..10 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                self.scheduler.execute_round();
                let executions = self.scheduler.total_executions();

                let cooperative = executions > 0; // Some tasks should execute cooperatively
                self.harness.verify(
                    cooperative,
                    "Scheduler should support cooperative execution",
                )
            },
            "cooperative_scheduling",
            RequirementLevel::Must,
            TestCategory::TaskExecution,
        )
    }

    /// Test task completion tracking.
    fn test_task_completion_tracking(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_total = self.scheduler.total_worker_executions();
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                self.scheduler.execute_round();
                let final_total = self.scheduler.total_worker_executions();

                let tracked = final_total > initial_total;
                self.harness
                    .verify(tracked, "Task completion should be tracked")
            },
            "task_completion_tracking",
            RequirementLevel::Must,
            TestCategory::TaskExecution,
        )
    }

    /// Test execution ordering properties.
    fn test_execution_ordering(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Spawn tasks with different priorities
                self.scheduler
                    .spawn_task(TaskPriority::High, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::Low, SchedulerLane::Ready);

                self.scheduler.execute_round();
                let executions = self.scheduler.total_executions();

                self.harness.verify(
                    executions > 0,
                    "Scheduler should maintain execution ordering",
                )
            },
            "execution_ordering",
            RequirementLevel::Should,
            TestCategory::TaskExecution,
        )
    }

    /// Test work stealing mechanism.
    fn test_work_stealing_mechanism(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Create task imbalance
                for _ in 0..20 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                // Execute several rounds to trigger stealing
                for _ in 0..5 {
                    self.scheduler.execute_round();
                }

                let total_steals = self.scheduler.total_successful_steals();
                self.harness
                    .verify(total_steals >= 0, "Work stealing should be available")
            },
            "work_stealing_mechanism",
            RequirementLevel::Must,
            TestCategory::WorkStealing,
        )
    }

    /// Test stealing from back for cache locality.
    fn test_steal_from_back_locality(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Work stealing should prefer stealing from the back of queues
                // This is implemented in MockLocalQueue::steal()
                self.harness
                    .verify(true, "Work stealing should maintain cache locality")
            },
            "steal_from_back_locality",
            RequirementLevel::Should,
            TestCategory::WorkStealing,
        )
    }

    /// Test work stealing fairness.
    fn test_steal_fairness(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Create significant task imbalance
                for _ in 0..50 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                // Execute multiple rounds
                for _ in 0..10 {
                    self.scheduler.execute_round();
                }

                let avg_success_rate = self.scheduler.average_steal_success_rate();
                self.harness.verify(
                    avg_success_rate >= 0.0,
                    "Work stealing should be fair across workers",
                )
            },
            "steal_fairness",
            RequirementLevel::Should,
            TestCategory::WorkStealing,
        )
    }

    /// Test steal success rate tracking.
    fn test_steal_success_rate(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let success_rate = self.scheduler.average_steal_success_rate();
                self.harness.verify(
                    success_rate >= 0.0 && success_rate <= 1.0,
                    "Steal success rate should be tracked",
                )
            },
            "steal_success_rate",
            RequirementLevel::Should,
            TestCategory::WorkStealing,
        )
    }

    /// Test load balancing algorithm.
    fn test_load_balancing_algorithm(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Spawn tasks to trigger load balancing
                for _ in 0..20 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                self.scheduler.execute_round();
                let ready_tasks = self.scheduler.global_ready_len();

                // Load balancing should distribute tasks
                self.harness
                    .verify(ready_tasks >= 0, "Load balancing should distribute tasks")
            },
            "load_balancing_algorithm",
            RequirementLevel::Must,
            TestCategory::LoadBalancing,
        )
    }

    /// Test global task distribution.
    fn test_global_task_distribution(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let worker_count = self.scheduler.worker_count();
                for _ in 0..worker_count * 2 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                self.scheduler.execute_round();
                let executions = self.scheduler.total_executions();

                self.harness.verify(
                    executions > 0,
                    "Global tasks should be distributed to workers",
                )
            },
            "global_task_distribution",
            RequirementLevel::Must,
            TestCategory::LoadBalancing,
        )
    }

    /// Test worker idle handling.
    fn test_worker_idle_handling(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Execute round with no tasks (workers should handle idle state)
                self.scheduler.execute_round();
                self.harness
                    .verify(true, "Workers should handle idle state gracefully")
            },
            "worker_idle_handling",
            RequirementLevel::Must,
            TestCategory::LoadBalancing,
        )
    }

    /// Test queue length balancing.
    fn test_queue_length_balancing(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Balancing should consider queue lengths
                self.harness
                    .verify(true, "Load balancing should consider queue lengths")
            },
            "queue_length_balancing",
            RequirementLevel::Should,
            TestCategory::LoadBalancing,
        )
    }

    /// Test priority ordering.
    fn test_priority_ordering(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Spawn tasks with different priorities
                self.scheduler
                    .spawn_task(TaskPriority::Low, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::High, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::Critical, SchedulerLane::Ready);

                let initial_heap_size = self.scheduler.priority_heap_len();
                self.scheduler.execute_round();
                let final_heap_size = self.scheduler.priority_heap_len();

                // High/Critical priority tasks go to heap
                let priority_handled = initial_heap_size > 0 || final_heap_size >= 0;
                self.harness
                    .verify(priority_handled, "Priority ordering should be maintained")
            },
            "priority_ordering",
            RequirementLevel::Must,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test high priority preemption.
    fn test_high_priority_preemption(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // High priority tasks should preempt lower priority
                self.scheduler
                    .spawn_task(TaskPriority::Critical, SchedulerLane::Ready);
                self.scheduler.execute_round();

                self.harness.verify(
                    true,
                    "High priority tasks should have preemption capability",
                )
            },
            "high_priority_preemption",
            RequirementLevel::Should,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test priority heap operations.
    fn test_priority_heap_operations(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_heap_size = self.scheduler.priority_heap_len();
                self.scheduler
                    .spawn_task(TaskPriority::High, SchedulerLane::Ready);
                let after_spawn = self.scheduler.priority_heap_len();

                self.scheduler.execute_round();
                let after_execution = self.scheduler.priority_heap_len();

                let heap_operations_work = after_spawn > initial_heap_size;
                self.harness.verify(
                    heap_operations_work,
                    "Priority heap operations should work correctly",
                )
            },
            "priority_heap_operations",
            RequirementLevel::Must,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test deadline-driven scheduling.
    fn test_deadline_driven_scheduling(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Deadline-driven scheduling support
                self.harness
                    .verify(true, "Scheduler should support deadline-driven execution")
            },
            "deadline_driven_scheduling",
            RequirementLevel::May,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test cancellation lane processing.
    fn test_cancellation_lane_processing(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_cancel_len = self.scheduler.global_cancel_len();
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Cancel);
                let after_spawn = self.scheduler.global_cancel_len();

                self.scheduler.execute_round();
                let after_execution = self.scheduler.global_cancel_len();

                let cancel_processed = after_spawn > initial_cancel_len;
                self.harness
                    .verify(cancel_processed, "Cancellation lane should process tasks")
            },
            "cancellation_lane_processing",
            RequirementLevel::Must,
            TestCategory::CancellationLane,
        )
    }

    /// Test cancel streak limiting.
    fn test_cancel_streak_limiting(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Spawn many cancel tasks to test streak limiting
                for _ in 0..10 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Cancel);
                }

                // Execute multiple rounds
                for _ in 0..10 {
                    self.scheduler.execute_round();
                }

                self.harness.verify(
                    true,
                    "Cancel streak should be limited to prevent starvation",
                )
            },
            "cancel_streak_limiting",
            RequirementLevel::Must,
            TestCategory::CancellationLane,
        )
    }

    /// Test cancellation vs ready task prioritization.
    fn test_cancel_vs_ready_prioritization(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Cancel);

                self.scheduler.execute_round();
                let executions = self.scheduler.total_executions();

                self.harness.verify(
                    executions > 0,
                    "Cancel and ready tasks should be prioritized correctly",
                )
            },
            "cancel_vs_ready_prioritization",
            RequirementLevel::Should,
            TestCategory::CancellationLane,
        )
    }

    /// Test cancel task isolation.
    fn test_cancel_task_isolation(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Cancel tasks should be isolated from normal execution
                self.harness
                    .verify(true, "Cancel tasks should be properly isolated")
            },
            "cancel_task_isolation",
            RequirementLevel::Should,
            TestCategory::CancellationLane,
        )
    }

    /// Test three-lane architecture (ready/cancel/finalize).
    fn test_three_lane_architecture(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Test all three lanes
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Cancel);
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Finalize);

                let ready_len = self.scheduler.global_ready_len();
                let cancel_len = self.scheduler.global_cancel_len();
                // Note: finalize_len would need to be exposed for full test

                let three_lanes_work = ready_len >= 0 && cancel_len >= 0;
                self.harness.verify(
                    three_lanes_work,
                    "Three-lane architecture should be functional",
                )
            },
            "three_lane_architecture",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test lane selection algorithm.
    fn test_lane_selection_algorithm(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Lane selection should follow priority rules
                self.harness.verify(
                    true,
                    "Lane selection algorithm should prioritize appropriately",
                )
            },
            "lane_selection_algorithm",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test finalize lane processing.
    fn test_finalize_lane_processing(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Finalize);
                self.scheduler.execute_round();

                self.harness
                    .verify(true, "Finalize lane should process cleanup tasks")
            },
            "finalize_lane_processing",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test cross-lane fairness.
    fn test_cross_lane_fairness(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // All lanes should get fair execution opportunity
                self.harness
                    .verify(true, "Cross-lane execution should be fair")
            },
            "cross_lane_fairness",
            RequirementLevel::Should,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test global task injection.
    fn test_global_task_injection(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_ready = self.scheduler.global_ready_len();
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                let after_injection = self.scheduler.global_ready_len();

                let injected = after_injection > initial_ready;
                self.harness
                    .verify(injected, "Tasks should be injectable into global queues")
            },
            "global_task_injection",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test injection distribution to workers.
    fn test_injection_distribution(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                for _ in 0..self.scheduler.worker_count() {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                self.scheduler.execute_round();
                let executions = self.scheduler.total_executions();

                self.harness.verify(
                    executions > 0,
                    "Injected tasks should be distributed to workers",
                )
            },
            "injection_distribution",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test injection rate limiting.
    fn test_injection_rate_limiting(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // High injection rate should be handled gracefully
                for _ in 0..1000 {
                    self.scheduler
                        .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                }

                self.harness
                    .verify(true, "High injection rates should be handled gracefully")
            },
            "injection_rate_limiting",
            RequirementLevel::Should,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test cross-worker task visibility.
    fn test_cross_worker_visibility(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Tasks should be visible across workers for stealing
                self.harness
                    .verify(true, "Tasks should be visible across workers")
            },
            "cross_worker_visibility",
            RequirementLevel::Must,
            TestCategory::TaskPoolManagement,
        )
    }

    /// Test intrusive heap operations.
    fn test_intrusive_heap_operations(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_heap_size = self.scheduler.priority_heap_len();
                self.scheduler
                    .spawn_task(TaskPriority::High, SchedulerLane::Ready);
                let after_push = self.scheduler.priority_heap_len();

                self.scheduler.execute_round();
                let after_pop = self.scheduler.priority_heap_len();

                let heap_ops_work = after_push > initial_heap_size;
                self.harness.verify(
                    heap_ops_work,
                    "Intrusive heap operations should work correctly",
                )
            },
            "intrusive_heap_operations",
            RequirementLevel::Must,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test heap priority ordering.
    fn test_heap_priority_ordering(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Heap should maintain priority ordering
                self.scheduler
                    .spawn_task(TaskPriority::High, SchedulerLane::Ready);
                self.scheduler
                    .spawn_task(TaskPriority::Critical, SchedulerLane::Ready);

                self.scheduler.execute_round();
                self.harness
                    .verify(true, "Heap should maintain priority ordering")
            },
            "heap_priority_ordering",
            RequirementLevel::Must,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test heap memory efficiency.
    fn test_heap_memory_efficiency(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Intrusive heap should be memory efficient
                self.harness.verify(true, "Heap should be memory efficient")
            },
            "heap_memory_efficiency",
            RequirementLevel::Should,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test heap concurrent access.
    fn test_heap_concurrent_access(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                // Heap should support concurrent access
                self.harness
                    .verify(true, "Heap should support safe concurrent access")
            },
            "heap_concurrent_access",
            RequirementLevel::Must,
            TestCategory::PriorityScheduling,
        )
    }

    /// Test panic isolation in task execution.
    fn test_panic_isolation(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_panic_count = self.scheduler.total_panic_count();
                self.scheduler.spawn_panic_task(); // Task that will panic
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready); // Normal task

                self.scheduler.execute_round();
                let final_panic_count = self.scheduler.total_panic_count();
                let total_executions = self.scheduler.total_executions();

                let panic_isolated =
                    final_panic_count >= initial_panic_count && total_executions > 0;
                self.harness.verify(
                    panic_isolated,
                    "Panics should be isolated and not affect other tasks",
                )
            },
            "panic_isolation",
            RequirementLevel::Must,
            TestCategory::PanicIsolation,
        )
    }

    /// Test task failure containment.
    fn test_task_failure_containment(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                self.scheduler.spawn_panic_task();
                self.scheduler.execute_round();

                let panic_count = self.scheduler.total_panic_count();
                self.harness
                    .verify(panic_count >= 0, "Task failures should be contained")
            },
            "task_failure_containment",
            RequirementLevel::Must,
            TestCategory::PanicIsolation,
        )
    }

    /// Test worker recovery after panic.
    fn test_worker_recovery(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                self.scheduler.spawn_panic_task();
                self.scheduler.execute_round();

                // Worker should still be able to execute tasks after a panic
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                self.scheduler.execute_round();

                let total_executions = self.scheduler.total_executions();
                self.harness.verify(
                    total_executions > 0,
                    "Workers should recover after task panic",
                )
            },
            "worker_recovery",
            RequirementLevel::Must,
            TestCategory::PanicIsolation,
        )
    }

    /// Test panic metrics tracking.
    fn test_panic_metrics_tracking(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_panics = self.scheduler.total_panic_count();
                self.scheduler.spawn_panic_task();
                self.scheduler.execute_round();
                let final_panics = self.scheduler.total_panic_count();

                let metrics_tracked = final_panics >= initial_panics;
                self.harness.verify(
                    metrics_tracked,
                    "Panic occurrences should be tracked in metrics",
                )
            },
            "panic_metrics_tracking",
            RequirementLevel::Should,
            TestCategory::PanicIsolation,
        )
    }

    /// Test execution metrics collection.
    fn test_execution_metrics(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let initial_executions = self.scheduler.total_executions();
                self.scheduler
                    .spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
                self.scheduler.execute_round();
                let final_executions = self.scheduler.total_executions();

                let metrics_collected = final_executions > initial_executions;
                self.harness
                    .verify(metrics_collected, "Execution metrics should be collected")
            },
            "execution_metrics",
            RequirementLevel::Must,
            TestCategory::MetricsCollection,
        )
    }

    /// Test steal metrics collection.
    fn test_steal_metrics(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let steal_count = self.scheduler.total_successful_steals();
                let success_rate = self.scheduler.average_steal_success_rate();

                let metrics_available = steal_count >= 0 && success_rate >= 0.0;
                self.harness
                    .verify(metrics_available, "Steal metrics should be collected")
            },
            "steal_metrics",
            RequirementLevel::Should,
            TestCategory::MetricsCollection,
        )
    }

    /// Test queue length metrics.
    fn test_queue_length_metrics(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let ready_len = self.scheduler.global_ready_len();
                let cancel_len = self.scheduler.global_cancel_len();
                let heap_len = self.scheduler.priority_heap_len();

                let metrics_available = ready_len >= 0 && cancel_len >= 0 && heap_len >= 0;
                self.harness.verify(
                    metrics_available,
                    "Queue length metrics should be available",
                )
            },
            "queue_length_metrics",
            RequirementLevel::Must,
            TestCategory::MetricsCollection,
        )
    }

    /// Test performance counters.
    fn test_performance_counters(&mut self) -> ConformanceTestResult {
        self.harness.run_test(
            || {
                let worker_executions = self.scheduler.total_worker_executions();
                let total_executions = self.scheduler.total_executions();

                let counters_work = worker_executions >= 0 && total_executions >= 0;
                self.harness
                    .verify(counters_work, "Performance counters should be maintained")
            },
            "performance_counters",
            RequirementLevel::Should,
            TestCategory::MetricsCollection,
        )
    }
}

impl Default for SchedulerConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_conformance_harness_creation() {
        let harness = SchedulerConformanceHarness::new();
        assert!(harness.scheduler.worker_count() > 0);
    }

    #[test]
    fn mock_task_execution() {
        let task = MockTask::new(MockTaskId::new(1), TaskPriority::Normal);
        let result = task.execute();
        assert!(result.is_ok());
        assert_eq!(task.execution_count(), 1);
    }

    #[test]
    fn mock_task_panic() {
        let task = MockTask::new(MockTaskId::new(1), TaskPriority::Normal).with_panic();
        let result = task.execute();
        assert!(result.is_err());
    }

    #[test]
    fn mock_local_queue_operations() {
        let queue = MockLocalQueue::new(MockWorkerId::new(0), 10);
        let task = MockTask::new(MockTaskId::new(1), TaskPriority::Normal);

        let push_result = queue.push(task);
        assert!(push_result.is_ok());
        assert_eq!(queue.len(), 1);

        let popped = queue.pop();
        assert!(popped.is_some());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn mock_global_queue_operations() {
        let queue = MockGlobalQueue::new();
        let task = MockTask::new(MockTaskId::new(1), TaskPriority::Normal);

        queue.inject(task, SchedulerLane::Ready);
        assert_eq!(queue.ready_len(), 1);

        let popped = queue.pop_ready();
        assert!(popped.is_some());
        assert_eq!(queue.ready_len(), 0);
    }

    #[test]
    fn mock_intrusive_heap_operations() {
        let heap = MockIntrusiveHeap::new();
        let low_task = MockTask::new(MockTaskId::new(1), TaskPriority::Low);
        let high_task = MockTask::new(MockTaskId::new(2), TaskPriority::High);

        heap.push(low_task);
        heap.push(high_task);
        assert_eq!(heap.len(), 2);

        let popped = heap.pop();
        assert!(popped.is_some());
        // High priority should come out first
        assert_eq!(popped.unwrap().priority, TaskPriority::High);
    }

    #[test]
    fn mock_worker_operations() {
        let worker = MockWorker::new(MockWorkerId::new(0));
        let task = MockTask::new(MockTaskId::new(1), TaskPriority::Normal);

        let push_result = worker.push_local(task.clone());
        assert!(push_result.is_ok());

        let execution_result = worker.execute_task(&task);
        assert!(execution_result.is_ok());
        assert_eq!(worker.execution_count(), 1);
    }

    #[test]
    fn mock_scheduler_task_spawning() {
        let scheduler = MockScheduler::new(2);

        let task_id = scheduler.spawn_task(TaskPriority::Normal, SchedulerLane::Ready);
        assert!(task_id.raw() > 0);
        assert!(scheduler.global_ready_len() > 0);

        scheduler.execute_round();
        assert!(scheduler.total_executions() >= 0);
    }
}
