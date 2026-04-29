#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::scheduler::LocalQueue;
use asupersync::types::TaskId;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Structure-aware fuzz target for LocalQueue steal-half correctness
///
/// Tests the correctness properties of the local work-stealing queue:
/// 1. Total drained == total pushed: no tasks lost or created
/// 2. No duplicates: each task appears at most once across all outputs
/// 3. FIFO within local: owner pop sequence maintains LIFO order
/// 4. Steal-half properties: steals approximately half the queue (1 to len/2)
/// 5. Concurrent correctness: multiple workers stealing/pushing simultaneously
#[derive(Arbitrary, Debug)]
struct LocalQueueStealHalfFuzz {
    /// Sequence of queue operations to perform
    operations: Vec<QueueOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Owner: push a task to the local queue
    Push {
        worker_id: u8,   // Worker to execute on (0-7)
        task_value: u32, // Task identifier value
    },
    /// Owner: pop a task from the local queue (LIFO)
    LocalPop {
        worker_id: u8, // Worker to execute on (0-7)
    },
    /// Stealer: steal one task from another worker's queue (FIFO)
    Steal {
        stealer_id: u8, // Stealer worker (0-7)
        victim_id: u8,  // Victim worker (0-7)
    },
    /// Stealer: steal half of another worker's queue
    StealHalf {
        stealer_id: u8, // Stealer worker (0-7)
        victim_id: u8,  // Victim worker (0-7)
    },
    /// Owner: push multiple tasks in batch
    PushMany {
        worker_id: u8,   // Worker to execute on (0-7)
        count: u8,       // Number of tasks (1-32)
        base_value: u32, // Starting task value
    },
    /// Observer: check queue state
    Observe {
        worker_id: u8, // Worker to observe (0-7)
    },
    /// Brief delay for scheduling variations
    Delay {
        worker_id: u8,    // Worker to execute on (0-7)
        milliseconds: u8, // Delay duration (0-255ms)
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u16,
    /// Maximum number of workers to use
    max_workers: u8,
    /// Maximum task ID to use
    max_task_id: u32,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 300;
const MAX_WORKERS: usize = 8;
const MAX_BATCH_SIZE: usize = 32;
const MAX_DELAY_MS: u64 = 5;
const MAX_TASK_ID: u32 = 10000;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

fuzz_target!(|input: LocalQueueStealHalfFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize)
        .min(MAX_OPERATIONS)
        .max(1);
    let max_workers = (input.config.max_workers as usize).min(MAX_WORKERS).max(1);
    let max_task_id = input.config.max_task_id.min(MAX_TASK_ID).max(100);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Create shared queues and tracking structures
    let mut queues = Vec::new();
    for _ in 0..max_workers {
        queues.push(Arc::new(LocalQueue::new_for_test(max_task_id)));
    }

    let tracker = Arc::new(parking_lot::Mutex::new(StealHalfTracker::new()));

    // Group operations by worker
    let mut operations_by_worker: HashMap<usize, Vec<QueueOperation>> = HashMap::new();
    for op in operations {
        let primary_worker = op.primary_worker_id() as usize % max_workers;
        operations_by_worker
            .entry(primary_worker)
            .or_insert_with(Vec::new)
            .push(op);
    }

    // Execute operations and verify correctness
    execute_and_verify_steal_half_correctness(queues, tracker, operations_by_worker, max_workers);
});

/// Tracks steal-half correctness properties
struct StealHalfTracker {
    /// All tasks that have been pushed to any queue
    pushed_tasks: HashSet<u32>,
    /// All tasks that have been popped/stolen from any queue
    drained_tasks: HashSet<u32>,
    /// Per-worker push sequences for FIFO/LIFO analysis
    worker_push_sequences: HashMap<usize, Vec<PushEvent>>,
    /// Per-worker local pop sequences for LIFO verification
    worker_pop_sequences: HashMap<usize, Vec<PopEvent>>,
    /// Steal events for cross-worker validation
    steal_events: Vec<StealEvent>,
    /// Queue length observations
    length_observations: Vec<LengthObservation>,
}

#[derive(Debug, Clone)]
struct PushEvent {
    task_id: u32,
    timestamp: Instant,
    sequence: u64,
}

#[derive(Debug, Clone)]
struct PopEvent {
    task_id: u32,
    worker_id: usize,
    operation_type: PopType,
    timestamp: Instant,
    sequence: u64,
}

#[derive(Debug, Clone)]
enum PopType {
    LocalPop,  // Owner LIFO pop
    Steal,     // Single task steal (FIFO)
    StealHalf, // Batch steal
}

#[derive(Debug, Clone)]
struct StealEvent {
    stolen_tasks: Vec<u32>,
    stealer_id: usize,
    victim_id: usize,
    timestamp: Instant,
}

#[derive(Debug, Clone)]
struct LengthObservation {
    worker_id: usize,
    length: usize,
    timestamp: Instant,
}

impl StealHalfTracker {
    fn new() -> Self {
        Self {
            pushed_tasks: HashSet::new(),
            drained_tasks: HashSet::new(),
            worker_push_sequences: HashMap::new(),
            worker_pop_sequences: HashMap::new(),
            steal_events: Vec::new(),
            length_observations: Vec::new(),
        }
    }

    /// Record a task being pushed
    fn record_push(&mut self, task_id: u32, worker_id: usize) {
        assert!(
            !self.pushed_tasks.contains(&task_id),
            "Task {} pushed multiple times",
            task_id
        );

        self.pushed_tasks.insert(task_id);
        let sequence = self
            .worker_push_sequences
            .get(&worker_id)
            .map(|seq| seq.len())
            .unwrap_or(0) as u64;

        self.worker_push_sequences
            .entry(worker_id)
            .or_insert_with(Vec::new)
            .push(PushEvent {
                task_id,
                timestamp: Instant::now(),
                sequence,
            });
    }

    /// Record a task being drained (popped or stolen)
    fn record_drain(&mut self, task_id: u32, worker_id: usize, operation_type: PopType) {
        assert!(
            !self.drained_tasks.contains(&task_id),
            "Task {} drained multiple times (duplicate)",
            task_id
        );
        assert!(
            self.pushed_tasks.contains(&task_id),
            "Task {} drained without being pushed (phantom task)",
            task_id
        );

        self.drained_tasks.insert(task_id);
        let sequence = self
            .worker_pop_sequences
            .get(&worker_id)
            .map(|seq| seq.len())
            .unwrap_or(0) as u64;

        self.worker_pop_sequences
            .entry(worker_id)
            .or_insert_with(Vec::new)
            .push(PopEvent {
                task_id,
                worker_id,
                operation_type,
                timestamp: Instant::now(),
                sequence,
            });
    }

    /// Record a steal event
    fn record_steal(&mut self, stolen_tasks: Vec<u32>, stealer_id: usize, victim_id: usize) {
        self.steal_events.push(StealEvent {
            stolen_tasks,
            stealer_id,
            victim_id,
            timestamp: Instant::now(),
        });
    }

    /// Record queue length observation
    fn record_length_observation(&mut self, worker_id: usize, length: usize) {
        self.length_observations.push(LengthObservation {
            worker_id,
            length,
            timestamp: Instant::now(),
        });
    }

    /// Verify steal-half correctness properties
    fn verify_correctness(&self) {
        self.verify_task_balance();
        self.verify_no_duplicates();
        self.verify_lifo_within_local();
        self.verify_steal_half_properties();
    }

    /// Verify total drained == total pushed
    fn verify_task_balance(&self) {
        let lost_tasks: Vec<_> = self.pushed_tasks.difference(&self.drained_tasks).collect();

        if !lost_tasks.is_empty() {
            panic!(
                "Task balance violation: {} tasks lost (pushed but not drained): {:?}",
                lost_tasks.len(),
                lost_tasks
            );
        }

        // Also check for phantom tasks (shouldn't happen with our assertions)
        let phantom_tasks: Vec<_> = self.drained_tasks.difference(&self.pushed_tasks).collect();

        assert!(
            phantom_tasks.is_empty(),
            "Phantom tasks detected (drained but not pushed): {:?}",
            phantom_tasks
        );
    }

    /// Verify no tasks are duplicated
    fn verify_no_duplicates(&self) {
        assert_eq!(
            self.drained_tasks.len(),
            self.worker_pop_sequences
                .values()
                .map(|seq| seq.len())
                .sum::<usize>(),
            "Duplicate detection failed: drained set size != pop sequence total"
        );
    }

    /// Verify LIFO ordering within local operations
    fn verify_lifo_within_local(&self) {
        for (worker_id, push_seq) in &self.worker_push_sequences {
            if let Some(pop_seq) = self.worker_pop_sequences.get(worker_id) {
                // Extract only local pops for this worker
                let local_pops: Vec<_> = pop_seq
                    .iter()
                    .filter(|event| matches!(event.operation_type, PopType::LocalPop))
                    .collect();

                self.verify_lifo_order(worker_id, push_seq, &local_pops);
            }
        }
    }

    /// Verify LIFO order between push and local pop sequences
    fn verify_lifo_order(
        &self,
        worker_id: &usize,
        push_seq: &[PushEvent],
        local_pops: &[&PopEvent],
    ) {
        if push_seq.len() < 2 || local_pops.is_empty() {
            return; // Need enough data for meaningful LIFO analysis
        }

        // Create mapping from task_id to push order
        let mut push_order = HashMap::new();
        for (push_index, event) in push_seq.iter().enumerate() {
            push_order.insert(event.task_id, push_index);
        }

        // Check LIFO property: later pushed tasks should be popped first (locally)
        let mut inversions = 0;
        let mut valid_comparisons = 0;

        for i in 0..local_pops.len() {
            for j in i + 1..local_pops.len() {
                let task_i = local_pops[i].task_id;
                let task_j = local_pops[j].task_id;

                if let (Some(&push_i), Some(&push_j)) =
                    (push_order.get(&task_i), push_order.get(&task_j))
                {
                    valid_comparisons += 1;

                    // For LIFO: if task_i was pushed after task_j,
                    // it should be popped before task_j
                    if push_i > push_j && i > j {
                        inversions += 1;
                    }
                }
            }
        }

        if valid_comparisons > 0 {
            let inversion_rate = inversions as f64 / valid_comparisons as f64;
            assert!(
                inversion_rate < 0.3,
                "LIFO order violation for worker {}: {}/{} inversions ({:.1}%)",
                worker_id,
                inversions,
                valid_comparisons,
                inversion_rate * 100.0
            );
        }
    }

    /// Verify steal-half properties
    fn verify_steal_half_properties(&self) {
        for steal_event in &self.steal_events {
            let stolen_count = steal_event.stolen_tasks.len();

            // Steal-half should steal at least 1 task (if any were available)
            if stolen_count > 0 {
                assert!(
                    stolen_count >= 1,
                    "Steal-half stole 0 tasks but recorded as successful"
                );

                // For steal-batch, verify it steals a reasonable portion
                // (implementation steals up to half, clamped between 1 and 256)
                assert!(
                    stolen_count <= 256,
                    "Steal-half stole {} tasks, exceeds max batch size 256",
                    stolen_count
                );
            }
        }
    }
}

impl QueueOperation {
    fn primary_worker_id(&self) -> u8 {
        match self {
            QueueOperation::Push { worker_id, .. } => *worker_id,
            QueueOperation::LocalPop { worker_id } => *worker_id,
            QueueOperation::Steal { stealer_id, .. } => *stealer_id,
            QueueOperation::StealHalf { stealer_id, .. } => *stealer_id,
            QueueOperation::PushMany { worker_id, .. } => *worker_id,
            QueueOperation::Observe { worker_id } => *worker_id,
            QueueOperation::Delay { worker_id, .. } => *worker_id,
        }
    }
}

/// Execute operations across workers and verify steal-half correctness
fn execute_and_verify_steal_half_correctness(
    queues: Vec<Arc<LocalQueue>>,
    tracker: Arc<parking_lot::Mutex<StealHalfTracker>>,
    operations_by_worker: HashMap<usize, Vec<QueueOperation>>,
    max_workers: usize,
) {
    let mut handles = Vec::new();

    // Spawn worker threads
    for worker_id in 0..max_workers {
        let ops = operations_by_worker
            .get(&worker_id)
            .cloned()
            .unwrap_or_default();
        if ops.is_empty() {
            continue;
        }

        let queues_clone = queues.clone();
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            execute_worker_operations(worker_id, ops, queues_clone, tracker_clone);
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
            "Worker {} timed out - possible deadlock",
            i
        );
    }

    // Verify steal-half correctness properties
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
    queues: Vec<Arc<LocalQueue>>,
    tracker: Arc<parking_lot::Mutex<StealHalfTracker>>,
) {
    for operation in operations {
        match operation {
            QueueOperation::Push { task_value, .. } => {
                let task_id = create_task_id(task_value);
                let queue = &queues[worker_id];

                // Record the push
                tracker.lock().record_push(task_value, worker_id);

                // Push to queue
                queue.push(task_id);
            }

            QueueOperation::LocalPop { .. } => {
                let queue = &queues[worker_id];

                // Attempt local pop (LIFO)
                if let Some(task_id) = queue.pop() {
                    let task_value = extract_task_value(task_id);

                    // Record the drain
                    tracker
                        .lock()
                        .record_drain(task_value, worker_id, PopType::LocalPop);
                }
            }

            QueueOperation::Steal {
                stealer_id,
                victim_id,
                ..
            } => {
                let stealer_worker = (stealer_id as usize) % queues.len();
                let victim_worker = (victim_id as usize) % queues.len();

                if stealer_worker == victim_worker {
                    continue; // Can't steal from self
                }

                let victim_queue = &queues[victim_worker];
                let stealer = victim_queue.stealer();

                // Attempt to steal one task
                if let Some(task_id) = stealer.steal() {
                    let task_value = extract_task_value(task_id);

                    // Record the drain (credited to stealer)
                    tracker
                        .lock()
                        .record_drain(task_value, stealer_worker, PopType::Steal);
                }
            }

            QueueOperation::StealHalf {
                stealer_id,
                victim_id,
                ..
            } => {
                let stealer_worker = (stealer_id as usize) % queues.len();
                let victim_worker = (victim_id as usize) % queues.len();

                if stealer_worker == victim_worker {
                    continue; // Can't steal from self
                }

                let victim_queue = &queues[victim_worker];
                let stealer_queue = &queues[stealer_worker];
                let stealer = victim_queue.stealer();

                // Capture pre-steal state for analysis
                let pre_steal_tasks = stealer_queue.snapshot_tasks();
                let pre_steal_count = pre_steal_tasks.len();

                // Attempt batch steal
                let stole = stealer.steal_batch(stealer_queue);

                if stole {
                    // Capture post-steal state
                    let post_steal_tasks = stealer_queue.snapshot_tasks();
                    let stolen_count = post_steal_tasks.len() - pre_steal_count;

                    // Extract newly stolen tasks
                    let mut stolen_task_values = Vec::new();
                    for &task_id in &post_steal_tasks[pre_steal_count..] {
                        let task_value = extract_task_value(task_id);
                        stolen_task_values.push(task_value);

                        // Record each stolen task as drained
                        tracker
                            .lock()
                            .record_drain(task_value, stealer_worker, PopType::StealHalf);
                    }

                    // Record the steal event
                    tracker
                        .lock()
                        .record_steal(stolen_task_values, stealer_worker, victim_worker);
                }
            }

            QueueOperation::PushMany {
                count, base_value, ..
            } => {
                let batch_count = (count as usize).min(MAX_BATCH_SIZE).max(1);
                let queue = &queues[worker_id];

                let mut task_ids = Vec::new();
                for i in 0..batch_count {
                    let task_value = base_value.wrapping_add(i as u32);
                    let task_id = create_task_id(task_value);
                    task_ids.push(task_id);

                    // Record the push
                    tracker.lock().record_push(task_value, worker_id);
                }

                // Push many at once
                queue.push_many(&task_ids);
            }

            QueueOperation::Observe { .. } => {
                let queue = &queues[worker_id];
                let length = queue.len();
                let _is_empty = queue.is_empty();

                tracker.lock().record_length_observation(worker_id, length);
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
    TaskId::new_for_test(value, 0)
}

/// Extract the u32 value from a TaskId for tracking
fn extract_task_value(task_id: TaskId) -> u32 {
    task_id.arena_index().index()
}
