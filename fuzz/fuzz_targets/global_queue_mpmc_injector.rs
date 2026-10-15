#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::scheduler::GlobalQueue;
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, VecDeque};
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
    /// Adaptive batch reservation / drain epochs over the real pre-accounted
    /// global queue publish path.
    adaptive_batching: AdaptiveBatchingScenario,
}

#[derive(Arbitrary, Debug, Clone)]
enum QueueOperation {
    /// Producer: push a task to the global queue
    Push {
        worker_id: u8,   // Worker to execute on (0-15)
        task_value: u32, // Task identifier value
    },
    /// Consumer: steal (pop) a task from the global queue
    Steal {
        worker_id: u8, // Worker to execute on (0-15)
    },
    /// Observer: check queue length and emptiness
    Observe {
        worker_id: u8, // Worker to execute on (0-15)
    },
    /// Producer: burst push multiple tasks
    BurstPush {
        worker_id: u8,   // Worker to execute on (0-15)
        count: u8,       // Number of tasks to push (1-32)
        base_value: u32, // Starting task identifier
    },
    /// Consumer: burst steal multiple tasks
    BurstSteal {
        worker_id: u8, // Worker to execute on (0-15)
        max_count: u8, // Maximum tasks to steal (1-32)
    },
    /// Brief delay to allow scheduling variations
    Delay {
        worker_id: u8,    // Worker to execute on (0-15)
        milliseconds: u8, // Delay duration (0-255ms)
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

#[derive(Arbitrary, Debug)]
struct AdaptiveBatchingScenario {
    /// Adaptive publish/drain epochs.
    epochs: Vec<AdaptiveBatchEpoch>,
    /// Initial controller batch size.
    initial_batch: u8,
    /// Maximum batch size the controller may reserve.
    max_batch: u8,
}

#[derive(Arbitrary, Debug, Clone)]
struct AdaptiveBatchEpoch {
    /// New producer arrivals made available this epoch.
    push_rate: u8,
    /// Maximum consumer drain budget this epoch.
    drain_rate: u8,
    /// Unpublished suffix to leave behind so the reservation rollback path
    /// gets exercised.
    publish_slack: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 500;
const MAX_WORKERS: usize = 16;
const MAX_BURST_SIZE: usize = 32;
const MAX_ADAPTIVE_EPOCHS: usize = 64;
const MAX_ADAPTIVE_RATE: usize = 32;
const MAX_ADAPTIVE_BATCH: usize = 32;
const MAX_DELAY_MS: u64 = 10;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

fuzz_target!(|input: GlobalQueueMpmcFuzz| {
    assert_adaptive_batching_bounds(&input.adaptive_batching);

    // Apply resource limits
    let max_ops = (input.config.max_operations as usize)
        .min(MAX_OPERATIONS)
        .max(1);
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
    execute_and_verify_mpmc_correctness(global_queue, tracker, operations_by_worker, max_workers);
});

/// Tracks MPMC correctness properties
struct MpmcTracker {
    /// Tasks that have been pushed (producer side), keyed by logical task value.
    pushed_tasks: HashMap<u32, usize>,
    /// Tasks that have been popped (consumer side), keyed by logical task value.
    popped_tasks: HashMap<u32, usize>,
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
            pushed_tasks: HashMap::new(),
            popped_tasks: HashMap::new(),
            push_sequence: Vec::new(),
            pop_sequence: Vec::new(),
            length_observations: Vec::new(),
        }
    }

    /// Record a task being pushed
    fn record_push(&mut self, task_id: u32, worker_id: usize) {
        *self.pushed_tasks.entry(task_id).or_insert(0) += 1;
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
        let pushed_count = self.pushed_tasks.get(&task_id).copied().unwrap_or(0);
        let popped_count = self.popped_tasks.entry(task_id).or_insert(0);
        assert!(
            *popped_count < pushed_count,
            "Task {} popped without a matching push credit (pushed: {}, popped so far: {})",
            task_id,
            pushed_count,
            popped_count
        );
        *popped_count += 1;
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
    fn verify_correctness(&self, remaining_tasks: &[u32], final_advisory_len: usize) {
        self.verify_total_preserved(remaining_tasks);
        self.verify_no_task_duplicated();
        self.verify_fifo_ordering();
        self.verify_count_consistency(remaining_tasks.len(), final_advisory_len);
    }

    /// Verify every push is accounted for as either a consumed item or post-race residue.
    fn verify_total_preserved(&self, remaining_tasks: &[u32]) {
        let mut remaining_counts = HashMap::new();
        for &task_id in remaining_tasks {
            *remaining_counts.entry(task_id).or_insert(0usize) += 1;
        }

        for (&task_id, &pushed_count) in &self.pushed_tasks {
            let popped_count = self.popped_tasks.get(&task_id).copied().unwrap_or(0);
            let remaining_count = remaining_counts.get(&task_id).copied().unwrap_or(0);
            assert_eq!(
                popped_count + remaining_count,
                pushed_count,
                "Task {} accounting drifted across inject/drain race (pushed: {}, popped: {}, remaining: {})",
                task_id,
                pushed_count,
                popped_count,
                remaining_count
            );
        }

        for (&task_id, &popped_count) in &self.popped_tasks {
            let pushed_count = self.pushed_tasks.get(&task_id).copied().unwrap_or(0);
            assert!(
                popped_count <= pushed_count,
                "Task {} was popped too many times (pushed: {}, popped: {})",
                task_id,
                pushed_count,
                popped_count
            );
        }

        for (&task_id, &remaining_count) in &remaining_counts {
            let pushed_count = self.pushed_tasks.get(&task_id).copied().unwrap_or(0);
            assert!(
                remaining_count <= pushed_count,
                "Task {} remained in queue without enough push credit (pushed: {}, remaining: {})",
                task_id,
                pushed_count,
                remaining_count
            );
        }
    }

    /// Verify no tasks are duplicated (no task is popped more than once)
    fn verify_no_task_duplicated(&self) {
        for (&popped_task, &popped_count) in &self.popped_tasks {
            let pushed_count = self.pushed_tasks.get(&popped_task).copied().unwrap_or(0);
            assert!(
                popped_count <= pushed_count,
                "Phantom or duplicated task {} was popped too many times (pushed: {}, popped: {})",
                popped_task,
                pushed_count,
                popped_count
            );
        }
    }

    /// Verify FIFO ordering is generally maintained
    fn verify_fifo_ordering(&self) {
        if self.pushed_tasks.values().any(|&count| count > 1) {
            return;
        }

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
                    (push_order.get(&task_i), push_order.get(&task_j))
                {
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
                inversions,
                valid_comparisons,
                inversion_rate * 100.0
            );
        }
    }

    /// Verify count consistency (advisory count roughly matches reality)
    fn verify_count_consistency(&self, remaining_count: usize, final_advisory_len: usize) {
        let total_pushed: usize = self.pushed_tasks.values().sum();
        let total_popped: usize = self.popped_tasks.values().sum();
        let expected_remaining = total_pushed.saturating_sub(total_popped);

        assert_eq!(
            expected_remaining, remaining_count,
            "Final residue count drifted after the inject/drain race (pushed: {}, popped: {}, remaining: {})",
            total_pushed, total_popped, remaining_count
        );
        assert_eq!(
            final_advisory_len, remaining_count,
            "Advisory queue count drifted after all producers and consumers quiesced"
        );

        // Even though the count is advisory under concurrency, it must never wrap
        // or exceed the total amount of work ever injected into the queue.
        for &(timestamp, observed_length) in &self.length_observations {
            assert!(
                observed_length <= total_pushed,
                "Length observation {} at {:?} exceeds total injected work {}",
                observed_length,
                timestamp,
                total_pushed
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
        let ops = operations_by_worker
            .get(&worker_id)
            .cloned()
            .unwrap_or_default();
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
            "Worker {} timed out - possible deadlock or infinite loop",
            i
        );
    }

    let final_advisory_len = global_queue.len();
    let remaining_tasks = drain_remaining_tasks(&global_queue);

    // Verify MPMC correctness properties
    let tracker_guard = tracker.lock();
    tracker_guard.verify_correctness(&remaining_tasks, final_advisory_len);
}

fn assert_adaptive_batching_bounds(scenario: &AdaptiveBatchingScenario) {
    let queue = GlobalQueue::new();
    let max_batch = usize::from(scenario.max_batch).clamp(1, MAX_ADAPTIVE_BATCH);
    let mut current_batch = usize::from(scenario.initial_batch).clamp(1, max_batch);
    let mut pending = VecDeque::new();
    let mut visible = VecDeque::new();
    let mut next_task_value = 1_000_000u32;

    for epoch in scenario.epochs.iter().take(MAX_ADAPTIVE_EPOCHS) {
        let push_rate = usize::from(epoch.push_rate).min(MAX_ADAPTIVE_RATE);
        let drain_rate = usize::from(epoch.drain_rate).min(MAX_ADAPTIVE_RATE);

        for _ in 0..push_rate {
            pending.push_back(create_task_id(next_task_value));
            next_task_value = next_task_value.wrapping_add(1);
        }

        let pending_before = pending.len();
        let visible_before = visible.len();
        let previous_batch = current_batch;
        let reserved_batch = next_adaptive_batch_size(
            previous_batch,
            pending_before,
            visible_before,
            drain_rate,
            max_batch,
        );

        if pending_before == 0 {
            assert_eq!(
                reserved_batch, 0,
                "adaptive batcher must idle when no producer backlog exists"
            );
        } else {
            assert!(
                reserved_batch >= 1 && reserved_batch <= max_batch,
                "adaptive batch size must stay within configured bounds"
            );
            assert!(
                reserved_batch <= pending_before,
                "adaptive batch size must never reserve more tasks than are pending"
            );
            if pending_before + visible_before > drain_rate
                && previous_batch < max_batch
                && previous_batch < pending_before
            {
                assert!(
                    reserved_batch >= previous_batch,
                    "producer pressure should not shrink the reserved batch"
                );
            }
            if drain_rate > pending_before + visible_before && previous_batch > 1 {
                assert!(
                    reserved_batch <= previous_batch,
                    "drain pressure should not grow the reserved batch"
                );
            }
        }

        current_batch = reserved_batch.max(1);

        if reserved_batch > 0 {
            let publish_slack = usize::from(epoch.publish_slack).min(reserved_batch);
            let publish_count = reserved_batch
                .saturating_sub(publish_slack)
                .min(pending_before);
            let mut reservation = queue.reserve_batch_for_test(reserved_batch);

            for _ in 0..publish_count {
                let task = pending
                    .pop_front()
                    .expect("publish count must not exceed pending backlog");
                reservation.publish_one(task);
                visible.push_back(task);
            }
            drop(reservation);

            assert_eq!(
                queue.len(),
                visible.len(),
                "dropping an adaptive reservation must roll back any unpublished count credit"
            );
        } else {
            assert_eq!(queue.len(), visible.len());
        }

        let drain_count = drain_rate.min(visible.len());
        for _ in 0..drain_count {
            let expected = visible
                .pop_front()
                .expect("drain count must not exceed visible queue contents");
            assert_eq!(
                queue.pop(),
                Some(expected),
                "adaptive batch publication must preserve FIFO order under drain pressure"
            );
        }

        assert_eq!(
            queue.len(),
            visible.len(),
            "advisory count must match the visible queue depth after each adaptive epoch"
        );
    }

    while let Some(expected) = visible.pop_front() {
        assert_eq!(
            queue.pop(),
            Some(expected),
            "post-epoch residue drain must preserve FIFO order"
        );
    }

    assert_eq!(
        queue.len(),
        0,
        "adaptive batch accounting must converge to zero after the final drain"
    );
    assert!(
        queue.is_empty(),
        "global queue should report empty after adaptive batch residue drain"
    );
}

fn next_adaptive_batch_size(
    previous_batch: usize,
    pending_backlog: usize,
    visible_backlog: usize,
    drain_rate: usize,
    max_batch: usize,
) -> usize {
    if pending_backlog == 0 {
        return 0;
    }

    let producer_pressure = pending_backlog.saturating_add(visible_backlog);
    let next = if producer_pressure > drain_rate {
        previous_batch.saturating_add((producer_pressure - drain_rate).min(2))
    } else if drain_rate > producer_pressure {
        previous_batch.saturating_sub((drain_rate - producer_pressure).min(2))
    } else {
        previous_batch
    };

    next.clamp(1, max_batch).min(pending_backlog)
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
                tracker.lock().record_length_observation(queue.len());
            }

            QueueOperation::Steal { .. } => {
                // Attempt to steal (pop) from queue
                if let Some(task_id) = queue.pop() {
                    let task_value = extract_task_value(task_id);

                    // Record the pop
                    tracker.lock().record_pop(task_value, worker_id);
                }
                // If pop returns None, that's fine - queue was empty
                tracker.lock().record_length_observation(queue.len());
            }

            QueueOperation::Observe { .. } => {
                // Observe queue state
                let length = queue.len();
                let _is_empty = queue.is_empty();

                tracker.lock().record_length_observation(length);
            }

            QueueOperation::BurstPush {
                count, base_value, ..
            } => {
                let burst_count = (count as usize).min(MAX_BURST_SIZE).max(1);

                for i in 0..burst_count {
                    let task_value = base_value.wrapping_add(i as u32);
                    let task_id = create_task_id(task_value);

                    // Record the push
                    tracker.lock().record_push(task_value, worker_id);

                    // Push to queue
                    queue.push(task_id);
                    tracker.lock().record_length_observation(queue.len());
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
                    tracker.lock().record_length_observation(queue.len());
                }
                tracker.lock().record_length_observation(queue.len());
            }

            QueueOperation::Delay { milliseconds, .. } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                thread::sleep(delay);
            }
        }
    }
}

fn drain_remaining_tasks(queue: &GlobalQueue) -> Vec<u32> {
    let mut remaining = Vec::new();
    while let Some(task_id) = queue.pop() {
        remaining.push(extract_task_value(task_id));
    }
    assert!(
        queue.is_empty(),
        "queue should be empty after residue drain"
    );
    remaining
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
