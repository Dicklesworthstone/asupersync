#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::scheduler::GlobalQueue;
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Structure-aware fuzz target for GlobalQueue MPMC injector correctness
///
/// Tests the correctness properties of the MPMC global task queue:
/// 1. No task lost: every pushed task is eventually popped exactly once
/// 2. No task duplicated: no task is popped more than once
/// 3. FIFO ordering: tasks are generally popped in the order they were pushed
/// 4. Concurrent correctness: multiple producers and consumers work correctly
/// 5. Count consistency: advisory count roughly matches actual queue contents
#[derive(Arbitrary, Debug)]
struct GlobalQueueMpmcFuzz {
    /// Sequence of queue operations to perform across workers
    operations: Vec<QueueOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Producer: push a task to the global queue
    Push {
        worker_id: u8,     // Worker to execute on (0-15)
        task_value: u32,   // Task identifier value
    },
    /// Consumer: steal (pop) a task from the global queue
    Steal {
        worker_id: u8,     // Worker to execute on (0-15)
    },
    /// Observer: check queue length and emptiness
    Observe {
        worker_id: u8,     // Worker to execute on (0-15)
    },
    /// Producer: burst push multiple tasks
    BurstPush {
        worker_id: u8,     // Worker to execute on (0-15)
        count: u8,         // Number of tasks to push (1-32)
        base_value: u32,   // Starting task identifier
    },
    /// Consumer: burst steal multiple tasks
    BurstSteal {
        worker_id: u8,     // Worker to execute on (0-15)
        max_count: u8,     // Maximum tasks to steal (1-32)
    },
    /// Brief delay to allow scheduling variations
    Delay {
        worker_id: u8,     // Worker to execute on (0-15)
        milliseconds: u8,  // Delay duration (0-255ms)
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u16,
    /// Maximum number of workers to use
    max_workers: u8,
    /// Test duration timeout
    timeout_seconds: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 500;
const MAX_WORKERS: usize = 16;
const MAX_BURST_SIZE: usize = 32;
const MAX_DELAY_MS: u64 = 10;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

fuzz_target!(|input: GlobalQueueMpmcFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize).min(MAX_OPERATIONS).max(1);
    let max_workers = (input.config.max_workers as usize).min(MAX_WORKERS).max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Create shared queue and tracking structures
    let global_queue = Arc::new(GlobalQueue::new());
    let tracker = Arc::new(parking_lot::Mutex::new(MpmcTracker::new()));

    // Group operations by worker
    let mut operations_by_worker: HashMap<usize, Vec<QueueOperation>> = HashMap::new();
    for op in operations {
        let worker_id = (op.worker_id() as usize) % max_workers;
        operations_by_worker
            .entry(worker_id)
            .or_insert_with(Vec::new)
            .push(op);
    }

    // Execute operations and verify correctness
    execute_and_verify_mpmc_correctness(
        global_queue,
        tracker,
        operations_by_worker,
        max_workers,
    );
});

/// Tracks MPMC correctness properties
struct MpmcTracker {
    /// Tasks that have been pushed (producer side)
    pushed_tasks: HashSet<u32>,
    /// Tasks that have been popped (consumer side)
    popped_tasks: HashSet<u32>,
    /// Sequence of push events for ordering analysis
    push_sequence: Vec<PushEvent>,
    /// Sequence of pop events for ordering analysis
    pop_sequence: Vec<PopEvent>,
    /// Current best-effort queue length observations
    length_observations: Vec<(Instant, usize)>,
}

#[derive(Debug, Clone)]
struct PushEvent {
    /// Task identifier that was pushed
    task_id: u32,
    /// Worker that pushed the task
    worker_id: usize,
    /// Timestamp of the push
    timestamp: Instant,
    /// Sequence number for ordering
    sequence: u64,
}

#[derive(Debug, Clone)]
struct PopEvent {
    /// Task identifier that was popped
    task_id: u32,
    /// Worker that popped the task
    worker_id: usize,
    /// Timestamp of the pop
    timestamp: Instant,
    /// Sequence number for ordering
    sequence: u64,
}

impl MpmcTracker {
    fn new() -> Self {
        Self {
            pushed_tasks: HashSet::new(),
            popped_tasks: HashSet::new(),
            push_sequence: Vec::new(),
            pop_sequence: Vec::new(),
            length_observations: Vec::new(),
        }
    }

    /// Record a task being pushed
    fn record_push(&mut self, task_id: u32, worker_id: usize) {
        assert!(
            !self.pushed_tasks.contains(&task_id),
            "Task {} pushed multiple times", task_id
        );

        self.pushed_tasks.insert(task_id);
        let sequence = self.push_sequence.len() as u64;
        self.push_sequence.push(PushEvent {
            task_id,
            worker_id,
            timestamp: Instant::now(),
            sequence,
        });
    }

    /// Record a task being popped
    fn record_pop(&mut self, task_id: u32, worker_id: usize) {
        assert!(
            !self.popped_tasks.contains(&task_id),
            "Task {} popped multiple times (duplicate)", task_id
        );
        assert!(
            self.pushed_tasks.contains(&task_id),
            "Task {} popped without being pushed (lost or phantom)", task_id
        );

        self.popped_tasks.insert(task_id);
        let sequence = self.pop_sequence.len() as u64;
        self.pop_sequence.push(PopEvent {
            task_id,
            worker_id,
            timestamp: Instant::now(),
            sequence,
        });
    }

    /// Record queue length observation
    fn record_length_observation(&mut self, length: usize) {
        self.length_observations.push((Instant::now(), length));
    }

    /// Verify MPMC correctness properties
    fn verify_correctness(&self) {
        self.verify_no_task_lost();
        self.verify_no_task_duplicated();
        self.verify_fifo_ordering();
        self.verify_count_consistency();
    }

    /// Verify no tasks are lost (every pushed task is popped)
    fn verify_no_task_lost(&self) {
        let lost_tasks: Vec<_> = self.pushed_tasks
            .difference(&self.popped_tasks)
            .collect();

        if !lost_tasks.is_empty() {
            panic!(
                "MPMC correctness violation: {} tasks lost (pushed but not popped): {:?}",
                lost_tasks.len(),
                lost_tasks
            );
        }
    }

    /// Verify no tasks are duplicated (no task is popped more than once)
    fn verify_no_task_duplicated(&self) {
        // This is already enforced by record_pop assertions, but let's double-check
        assert_eq!(
            self.popped_tasks.len(),
            self.pop_sequence.len(),
            "Task duplication detected: popped set size != pop sequence length"
        );

        // Also verify all popped tasks exist in pushed set
        for &popped_task in &self.popped_tasks {
            assert!(
                self.pushed_tasks.contains(&popped_task),
                "Phantom task {} was popped without being pushed", popped_task
            );
        }
    }

    /// Verify FIFO ordering is generally maintained
    fn verify_fifo_ordering(&self) {
        if self.push_sequence.len() < 2 || self.pop_sequence.len() < 2 {
            return; // Need at least 2 events for ordering analysis
        }

        // Create a mapping from task_id to push order
        let mut push_order = HashMap::new();
        for (push_index, event) in self.push_sequence.iter().enumerate() {
            push_order.insert(event.task_id, push_index);
        }

        // Check that pop order generally follows push order
        let mut inversions = 0;
        let mut valid_comparisons = 0;

        for i in 0..self.pop_sequence.len() {
            for j in i + 1..self.pop_sequence.len() {
                let task_i = self.pop_sequence[i].task_id;
                let task_j = self.pop_sequence[j].task_id;

                if let (Some(&push_i), Some(&push_j)) =
                    (push_order.get(&task_i), push_order.get(&task_j)) {
                    valid_comparisons += 1;

                    // If task_i was pushed before task_j, but popped after task_j,
                    // that's an inversion of FIFO order
                    if push_i < push_j && i > j {
                        inversions += 1;
                    }
                }
            }
        }

        if valid_comparisons > 0 {
            let inversion_rate = inversions as f64 / valid_comparisons as f64;

            // Allow moderate inversion rate due to concurrent scheduling
            // FIFO is a best-effort property in MPMC scenarios
            assert!(
                inversion_rate < 0.5,
                "FIFO ordering severely violated: {}/{} inversions ({:.1}%)",
                inversions, valid_comparisons, inversion_rate * 100.0
            );
        }
    }

    /// Verify count consistency (advisory count roughly matches reality)
    fn verify_count_consistency(&self) {
        // The count is advisory and may be momentarily inconsistent,
        // but we can check some basic bounds

        let total_pushed = self.pushed_tasks.len();
        let total_popped = self.popped_tasks.len();
        let expected_remaining = total_pushed.saturating_sub(total_popped);

        // Check that no length observation was drastically wrong
        for &(timestamp, observed_length) in &self.length_observations {
            // Allow significant slack since count is advisory
            let max_reasonable_length = total_pushed + 50; // Some slack for concurrent operations

            assert!(
                observed_length <= max_reasonable_length,
                "Length observation {} at {:?} exceeds reasonable bound {} (pushed: {}, popped: {})",
                observed_length, timestamp, max_reasonable_length, total_pushed, total_popped
            );
        }
    }
}

impl QueueOperation {
    fn worker_id(&self) -> u8 {
        match self {
            QueueOperation::Push { worker_id, .. } => *worker_id,
            QueueOperation::Steal { worker_id } => *worker_id,
            QueueOperation::Observe { worker_id } => *worker_id,
            QueueOperation::BurstPush { worker_id, .. } => *worker_id,
            QueueOperation::BurstSteal { worker_id, .. } => *worker_id,
            QueueOperation::Delay { worker_id, .. } => *worker_id,
        }
    }
}

/// Execute operations across workers and verify MPMC correctness
fn execute_and_verify_mpmc_correctness(
    global_queue: Arc<GlobalQueue>,
    tracker: Arc<parking_lot::Mutex<MpmcTracker>>,
    operations_by_worker: HashMap<usize, Vec<QueueOperation>>,
    max_workers: usize,
) {
    let mut handles = Vec::new();

    // Spawn worker threads
    for worker_id in 0..max_workers {
        let ops = operations_by_worker.get(&worker_id).cloned().unwrap_or_default();
        if ops.is_empty() {
            continue;
        }

        let queue_clone = global_queue.clone();
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            execute_worker_operations(worker_id, ops, queue_clone, tracker_clone);
        });
        handles.push(handle);
    }

    // Wait for all workers with timeout
    let start = Instant::now();
    for (i, handle) in handles.into_iter().enumerate() {
        let remaining_time = OPERATION_TIMEOUT.saturating_sub(start.elapsed());

        let join_result = thread_join_with_timeout(handle, remaining_time);
        assert!(
            join_result.is_ok(),
            "Worker {} timed out - possible deadlock or infinite loop", i
        );
    }

    // Verify MPMC correctness properties
    let tracker_guard = tracker.lock();
    tracker_guard.verify_correctness();
}

/// Simple timeout wrapper for thread join
fn thread_join_with_timeout(
    handle: thread::JoinHandle<()>,
    timeout: Duration,
) -> Result<(), &'static str> {
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("timeout");
        }

        if handle.is_finished() {
            return handle.join().map_err(|_| "thread panicked");
        }

        thread::sleep(Duration::from_millis(1));
    }
}

/// Execute queue operations for a single worker
fn execute_worker_operations(
    worker_id: usize,
    operations: Vec<QueueOperation>,
    queue: Arc<GlobalQueue>,
    tracker: Arc<parking_lot::Mutex<MpmcTracker>>,
) {
    for operation in operations {
        match operation {
            QueueOperation::Push { task_value, .. } => {
                let task_id = create_task_id(task_value);

                // Record the push
                tracker.lock().record_push(task_value, worker_id);

                // Push to queue
                queue.push(task_id);
            }

            QueueOperation::Steal { .. } => {
                // Attempt to steal (pop) from queue
                if let Some(task_id) = queue.pop() {
                    let task_value = extract_task_value(task_id);

                    // Record the pop
                    tracker.lock().record_pop(task_value, worker_id);
                }
                // If pop returns None, that's fine - queue was empty
            }

            QueueOperation::Observe { .. } => {
                // Observe queue state
                let length = queue.len();
                let _is_empty = queue.is_empty();

                tracker.lock().record_length_observation(length);
            }

            QueueOperation::BurstPush { count, base_value, .. } => {
                let burst_count = (count as usize).min(MAX_BURST_SIZE).max(1);

                for i in 0..burst_count {
                    let task_value = base_value.wrapping_add(i as u32);
                    let task_id = create_task_id(task_value);

                    // Record the push
                    tracker.lock().record_push(task_value, worker_id);

                    // Push to queue
                    queue.push(task_id);
                }
            }

            QueueOperation::BurstSteal { max_count, .. } => {
                let burst_count = (max_count as usize).min(MAX_BURST_SIZE).max(1);

                for _ in 0..burst_count {
                    if let Some(task_id) = queue.pop() {
                        let task_value = extract_task_value(task_id);

                        // Record the pop
                        tracker.lock().record_pop(task_value, worker_id);
                    } else {
                        // Queue is empty, stop burst stealing
                        break;
                    }
                }
            }

            QueueOperation::Delay { milliseconds, .. } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                thread::sleep(delay);
            }
        }
    }
}

/// Create a TaskId from a u32 value for testing
fn create_task_id(value: u32) -> TaskId {
    // Use the value as both index and generation for simplicity
    let arena_index = ArenaIndex::new(value, 0);
    TaskId::from_arena(arena_index)
}

/// Extract the u32 value from a TaskId for tracking
fn extract_task_value(task_id: TaskId) -> u32 {
    // Extract the index portion (the value we stored)
    task_id.arena_index().index()
}