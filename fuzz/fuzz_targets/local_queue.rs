#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use asupersync::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use asupersync::runtime::RuntimeState;
use asupersync::sync::ContendedMutex;
use asupersync::types::TaskId;

/// Structure-aware fuzz input for LocalQueue operations
#[derive(Arbitrary, Debug)]
struct LocalQueueFuzz {
    /// Sequential operations to execute
    operations: Vec<QueueOperation>,
    /// Maximum task ID for the test
    max_task_id: u16,
    /// Whether to enable concurrent operations
    enable_concurrency: bool,
}

/// Queue operations to fuzz
#[derive(Arbitrary, Debug)]
enum QueueOperation {
    /// Push a task to the queue
    Push { task_id: u16 },
    /// Push multiple tasks in batch
    PushMany { task_ids: Vec<u16> },
    /// Pop from owner (LIFO)
    Pop,
    /// Steal from thief (FIFO)
    Steal,
    /// Steal batch from one queue to another
    StealBatch,
    /// Mark a task as local (pinned)
    MarkLocal { task_id: u16 },
    /// Check queue length
    CheckLength,
    /// Check if queue is empty
    CheckEmpty,
    /// Create a new stealer
    CreateStealer,
    /// Concurrent operation sequence
    ConcurrentOps {
        owner_ops: Vec<SingleQueueOp>,
        stealer_ops: Vec<SingleQueueOp>,
    },
}

/// Single operation for concurrent testing
#[derive(Arbitrary, Debug, Clone)]
enum SingleQueueOp {
    Push { task_id: u16 },
    Pop,
    Steal,
    CheckLength,
}

/// Shadow model to track queue state and verify invariants
#[derive(Debug)]
struct ShadowModel {
    /// Tasks that should be in the queue (mapping task_id -> count)
    expected_tasks: HashMap<u16, usize>,
    /// Tasks that are marked as local/pinned
    local_tasks: HashSet<u16>,
    /// Total operations performed
    total_operations: AtomicUsize,
    /// Whether any invariant violations were detected
    violation_detected: AtomicBool,
}

impl ShadowModel {
    fn new() -> Self {
        Self {
            expected_tasks: HashMap::new(),
            local_tasks: HashSet::new(),
            total_operations: AtomicUsize::new(0),
            violation_detected: AtomicBool::new(false),
        }
    }

    fn push_task(&mut self, task_id: u16) {
        *self.expected_tasks.entry(task_id).or_insert(0) += 1;
    }

    fn pop_task(&mut self, task_id: u16) -> bool {
        if let Some(count) = self.expected_tasks.get_mut(&task_id) {
            if *count > 0 {
                *count -= 1;
                if *count == 0 {
                    self.expected_tasks.remove(&task_id);
                }
                return true;
            }
        }
        false
    }

    fn mark_local(&mut self, task_id: u16) {
        self.local_tasks.insert(task_id);
    }

    fn is_local(&self, task_id: u16) -> bool {
        self.local_tasks.contains(&task_id)
    }

    fn total_tasks(&self) -> usize {
        self.expected_tasks.values().sum()
    }

    fn verify_no_duplicates(&self, actual_tasks: &[u16]) -> Result<(), String> {
        let mut seen = HashSet::new();
        for &task_id in actual_tasks {
            if !seen.insert(task_id) {
                return Err(format!("Duplicate task found: {}", task_id));
            }
        }
        Ok(())
    }

    fn verify_no_local_theft(&self, stolen_task: u16) -> Result<(), String> {
        if self.is_local(stolen_task) {
            return Err(format!("Local task {} was stolen", stolen_task));
        }
        Ok(())
    }
}

/// Test environment with queues and shadow state
struct TestEnvironment {
    queue_a: LocalQueue,
    queue_b: LocalQueue,
    stealer_a: Stealer,
    shadow: Arc<std::sync::Mutex<ShadowModel>>,
    state: Arc<ContendedMutex<RuntimeState>>,
}

impl TestEnvironment {
    fn new(max_task_id: u16) -> Self {
        let state = LocalQueue::test_state(max_task_id as u32);
        let queue_a = LocalQueue::new(Arc::clone(&state));
        let queue_b = LocalQueue::new(Arc::clone(&state));
        let stealer_a = queue_a.stealer();
        let shadow = Arc::new(std::sync::Mutex::new(ShadowModel::new()));

        Self {
            queue_a,
            queue_b,
            stealer_a,
            shadow,
            state,
        }
    }

    fn push(&self, task_id: u16) {
        let task = TaskId::new_for_test(task_id as u32, 0);
        self.queue_a.push(task);
        self.shadow.lock().unwrap().push_task(task_id);
    }

    fn push_many(&self, task_ids: &[u16]) {
        let tasks: Vec<_> = task_ids
            .iter()
            .map(|&id| TaskId::new_for_test(id as u32, 0))
            .collect();
        self.queue_a.push_many(&tasks);
        let mut shadow = self.shadow.lock().unwrap();
        for &task_id in task_ids {
            shadow.push_task(task_id);
        }
    }

    fn pop(&self) -> Option<u16> {
        if let Some(task) = self.queue_a.pop() {
            let task_id = task.arena_index().index() as u16;
            let mut shadow = self.shadow.lock().unwrap();
            if !shadow.pop_task(task_id) {
                shadow.violation_detected.store(true, Ordering::SeqCst);
                panic!("Popped task {} not in shadow model", task_id);
            }
            Some(task_id)
        } else {
            None
        }
    }

    fn steal(&self) -> Option<u16> {
        if let Some(task) = self.stealer_a.steal() {
            let task_id = task.arena_index().index() as u16;
            let mut shadow = self.shadow.lock().unwrap();
            // Verify this wasn't a local task
            if let Err(e) = shadow.verify_no_local_theft(task_id) {
                shadow.violation_detected.store(true, Ordering::SeqCst);
                panic!("{}", e);
            }
            if !shadow.pop_task(task_id) {
                shadow.violation_detected.store(true, Ordering::SeqCst);
                panic!("Stolen task {} not in shadow model", task_id);
            }
            Some(task_id)
        } else {
            None
        }
    }

    fn steal_batch(&self) -> bool {
        let result = self.stealer_a.steal_batch(&self.queue_b);
        // Note: Batch stealing is complex to model precisely due to local task filtering
        // We'll verify invariants at the end instead of tracking precisely here
        result
    }

    fn mark_local(&self, task_id: u16) {
        let task = TaskId::new_for_test(task_id as u32, 0);
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = guard.task_mut(task) {
            record.mark_local();
            self.shadow.lock().unwrap().mark_local(task_id);
        }
    }

    fn verify_queue_invariants(&self) -> Result<(), String> {
        // Check that queue lengths are reasonable
        let len_a = self.queue_a.len();
        let len_b = self.queue_b.len();

        if len_a > 10000 || len_b > 10000 {
            return Err(format!(
                "Queue lengths too large: queue_a={}, queue_b={}",
                len_a, len_b
            ));
        }

        // Verify no invariant violations were detected
        if self
            .shadow
            .lock()
            .unwrap()
            .violation_detected
            .load(Ordering::SeqCst)
        {
            return Err("Invariant violation detected during operations".to_string());
        }

        Ok(())
    }

    fn verify_final_state(&self) -> Result<(), String> {
        // Collect all remaining tasks
        let mut all_tasks = Vec::new();

        // Drain queue_a
        while let Some(task) = self.queue_a.pop() {
            all_tasks.push(task.arena_index().index() as u16);
        }

        // Drain queue_b
        while let Some(task) = self.queue_b.pop() {
            all_tasks.push(task.arena_index().index() as u16);
        }

        // Verify no duplicates
        let shadow = self.shadow.lock().unwrap();
        shadow.verify_no_duplicates(&all_tasks)?;

        // Verify total task count matches expectation
        let expected_total = shadow.total_tasks();
        let actual_total = all_tasks.len();

        if expected_total != actual_total {
            return Err(format!(
                "Task count mismatch: expected {}, found {}",
                expected_total, actual_total
            ));
        }

        Ok(())
    }
}

/// Constants for operation limits
const MAX_OPERATIONS: usize = 200;
const MAX_TASK_ID: u16 = 1000;
const MAX_CONCURRENT_OPS: usize = 50;

fuzz_target!(|input: LocalQueueFuzz| {
    // Limit the scope to prevent timeouts
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let max_task_id = input.max_task_id.min(MAX_TASK_ID);
    if max_task_id == 0 {
        return;
    }

    let mut env = TestEnvironment::new(max_task_id);

    // Execute the operation sequence
    for (i, operation) in input.operations.into_iter().enumerate() {
        env.shadow
            .lock()
            .unwrap()
            .total_operations
            .store(i, Ordering::SeqCst);

        match operation {
            QueueOperation::Push { task_id } => {
                let bounded_id = task_id % max_task_id;
                env.push(bounded_id);
            }

            QueueOperation::PushMany { task_ids } => {
                let bounded_ids: Vec<_> = task_ids
                    .into_iter()
                    .take(20) // Limit batch size
                    .map(|id| id % max_task_id)
                    .collect();
                if !bounded_ids.is_empty() {
                    env.push_many(&bounded_ids);
                }
            }

            QueueOperation::Pop => {
                env.pop();
            }

            QueueOperation::Steal => {
                env.steal();
            }

            QueueOperation::StealBatch => {
                env.steal_batch();
            }

            QueueOperation::MarkLocal { task_id } => {
                let bounded_id = task_id % max_task_id;
                env.mark_local(bounded_id);
            }

            QueueOperation::CheckLength => {
                let _len = env.queue_a.len();
                // Just exercise the length check
            }

            QueueOperation::CheckEmpty => {
                let _empty = env.queue_a.is_empty();
                // Just exercise the empty check
            }

            QueueOperation::CreateStealer => {
                let _new_stealer = env.queue_a.stealer();
                // Just exercise stealer creation
            }

            QueueOperation::ConcurrentOps {
                owner_ops,
                stealer_ops,
            } => {
                if !input.enable_concurrency {
                    continue;
                }

                let limited_owner_ops: Vec<_> =
                    owner_ops.into_iter().take(MAX_CONCURRENT_OPS).collect();
                let limited_stealer_ops: Vec<_> =
                    stealer_ops.into_iter().take(MAX_CONCURRENT_OPS).collect();

                run_concurrent_test(
                    &mut env,
                    limited_owner_ops,
                    limited_stealer_ops,
                    max_task_id,
                );
            }
        }

        // Verify invariants after each major operation
        if i % 10 == 0 {
            env.verify_queue_invariants().unwrap_or_else(|e| {
                panic!("Queue invariant violation at operation {}: {}", i, e);
            });
        }
    }

    // Final verification
    env.verify_queue_invariants().unwrap_or_else(|e| {
        panic!("Final queue invariant violation: {}", e);
    });

    env.verify_final_state().unwrap_or_else(|e| {
        panic!("Final state verification failed: {}", e);
    });
});

/// Run concurrent owner/stealer operations to test race conditions
fn run_concurrent_test(
    env: &mut TestEnvironment,
    owner_ops: Vec<SingleQueueOp>,
    stealer_ops: Vec<SingleQueueOp>,
    max_task_id: u16,
) {
    if owner_ops.is_empty() && stealer_ops.is_empty() {
        return;
    }

    let barrier = Arc::new(Barrier::new(2));
    let queue_for_owner = env.queue_a.clone();
    let stealer_for_thief = env.stealer_a.clone();

    let barrier_owner = Arc::clone(&barrier);
    let owner_handle = thread::spawn(move || {
        barrier_owner.wait();
        for op in owner_ops {
            match op {
                SingleQueueOp::Push { task_id } => {
                    let bounded_id = task_id % max_task_id;
                    let task = TaskId::new_for_test(bounded_id as u32, 0);
                    queue_for_owner.push(task);
                }
                SingleQueueOp::Pop => {
                    let _ = queue_for_owner.pop();
                }
                SingleQueueOp::Steal => {
                    // Owner doing steal on its own queue (should be rare but test it)
                    let _ = stealer_for_thief.steal();
                }
                SingleQueueOp::CheckLength => {
                    let _ = queue_for_owner.len();
                }
            }
            thread::yield_now();
        }
    });

    let barrier_stealer = Arc::clone(&barrier);
    let stealer_for_stealer = env.stealer_a.clone();
    let stealer_handle = thread::spawn(move || {
        barrier_stealer.wait();
        for op in stealer_ops {
            match op {
                SingleQueueOp::Push { task_id: _ } => {
                    // Stealers don't push, skip
                }
                SingleQueueOp::Pop => {
                    // Stealers don't pop, they steal
                    let _ = stealer_for_stealer.steal();
                }
                SingleQueueOp::Steal => {
                    let _ = stealer_for_stealer.steal();
                }
                SingleQueueOp::CheckLength => {
                    let _ = stealer_for_stealer.len();
                }
            }
            thread::yield_now();
        }
    });

    // Wait for both threads to complete
    owner_handle.join().expect("Owner thread panicked");
    stealer_handle.join().expect("Stealer thread panicked");
}
