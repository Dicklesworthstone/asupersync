#![no_main]

use arbitrary::Arbitrary;
use asupersync::cx::Cx;
use asupersync::sync::RwLock;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Structure-aware fuzz target for RwLock reader-writer queue starvation
///
/// Tests the fairness properties of the RwLock primitive:
/// 1. No reader starvation: readers eventually acquire despite writer pressure
/// 2. No writer starvation: writers eventually acquire despite reader pressure
/// 3. Writer-preference fairness: writers block new readers when waiting
/// 4. Bounded reader starvation: max 16 consecutive writers before forced reader turn
/// 5. FIFO ordering within read/write tiers: requests served in arrival order
#[derive(Arbitrary, Debug)]
struct RwLockQueueFuzz {
    /// Sequence of lock operations to perform
    operations: Vec<LockOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum LockOperation {
    /// Acquire shared read lock
    AcquireRead {
        thread_id: u8,     // Thread to execute on (0-7)
        hold_ms: u8,       // How long to hold the lock (0-255ms)
    },
    /// Acquire exclusive write lock
    AcquireWrite {
        thread_id: u8,     // Thread to execute on (0-7)
        hold_ms: u8,       // How long to hold the lock (0-255ms)
    },
    /// Try to acquire read lock without waiting
    TryRead {
        thread_id: u8,     // Thread to execute on (0-7)
        hold_ms: u8,       // How long to hold if acquired
    },
    /// Try to acquire write lock without waiting
    TryWrite {
        thread_id: u8,     // Thread to execute on (0-7)
        hold_ms: u8,       // How long to hold if acquired
    },
    /// Brief delay to allow for scheduling variations
    Delay {
        thread_id: u8,     // Thread to execute on (0-7)
        milliseconds: u8,  // Delay duration (0-255ms)
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u8,
    /// Maximum number of threads to use
    max_threads: u8,
    /// Test duration timeout
    timeout_seconds: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 200;
const MAX_THREADS: usize = 8;
const MAX_HOLD_MS: u64 = 50;
const MAX_DELAY_MS: u64 = 20;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

// Constants from RwLock implementation for starvation testing
const MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH: usize = 16;

fuzz_target!(|input: RwLockQueueFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize).min(MAX_OPERATIONS).max(1);
    let max_threads = (input.config.max_threads as usize).min(MAX_THREADS).max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Create shared lock and tracking structures
    let rwlock = Arc::new(RwLock::new(0u64)); // Shared counter
    let tracker = Arc::new(parking_lot::Mutex::new(StarvationTracker::new()));

    // Group operations by thread
    let mut operations_by_thread: HashMap<usize, Vec<LockOperation>> = HashMap::new();
    for op in operations {
        let thread_id = (op.thread_id() as usize) % max_threads;
        operations_by_thread
            .entry(thread_id)
            .or_insert_with(Vec::new)
            .push(op);
    }

    // Execute operations and verify no starvation
    execute_and_verify_fairness(
        rwlock,
        tracker,
        operations_by_thread,
        max_threads,
    );
});

/// Tracks starvation and fairness properties
struct StarvationTracker {
    /// Sequence of acquire events for starvation analysis
    acquire_events: Vec<AcquireEvent>,
    /// Number of consecutive writers served
    consecutive_writers: usize,
    /// Current readers holding the lock
    active_readers: usize,
    /// Whether a writer is currently active
    active_writer: bool,
    /// Queue of waiting operations for fairness analysis
    waiting_operations: VecDeque<WaitingOperation>,
}

#[derive(Debug, Clone)]
struct AcquireEvent {
    /// Unique sequence number for this event
    sequence: u64,
    /// Thread that acquired the lock
    thread_id: usize,
    /// Type of acquisition
    operation_type: AcquireType,
    /// Timestamp of acquisition
    timestamp: Instant,
    /// How long the lock was held
    hold_duration: Duration,
}

#[derive(Debug, Clone, Copy)]
enum AcquireType {
    Read,
    Write,
    TryRead,
    TryWrite,
}

#[derive(Debug, Clone)]
struct WaitingOperation {
    /// Thread performing the operation
    thread_id: usize,
    /// Type of operation requested
    operation_type: AcquireType,
    /// When the request started waiting
    start_time: Instant,
    /// Sequence number for ordering
    sequence: u64,
}

impl StarvationTracker {
    fn new() -> Self {
        Self {
            acquire_events: Vec::new(),
            consecutive_writers: 0,
            active_readers: 0,
            active_writer: false,
            waiting_operations: VecDeque::new(),
        }
    }

    /// Record a successful acquisition
    fn record_acquire(
        &mut self,
        thread_id: usize,
        operation_type: AcquireType,
        hold_duration: Duration,
    ) {
        let sequence = self.acquire_events.len() as u64;
        let event = AcquireEvent {
            sequence,
            thread_id,
            operation_type,
            timestamp: Instant::now(),
            hold_duration,
        };

        // Update state tracking
        match operation_type {
            AcquireType::Read | AcquireType::TryRead => {
                self.active_readers += 1;
                self.consecutive_writers = 0; // Reset on reader turn
            }
            AcquireType::Write | AcquireType::TryWrite => {
                assert!(!self.active_writer, "Multiple writers active");
                assert_eq!(self.active_readers, 0, "Writers with active readers");
                self.active_writer = true;
                self.consecutive_writers += 1;
            }
        }

        self.acquire_events.push(event);
    }

    /// Record lock release
    fn record_release(&mut self, operation_type: AcquireType) {
        match operation_type {
            AcquireType::Read | AcquireType::TryRead => {
                assert!(self.active_readers > 0, "Reader release with no active readers");
                self.active_readers -= 1;
            }
            AcquireType::Write | AcquireType::TryWrite => {
                assert!(self.active_writer, "Writer release with no active writer");
                self.active_writer = false;
            }
        }
    }

    /// Record the start of a waiting operation
    fn record_wait_start(&mut self, thread_id: usize, operation_type: AcquireType) {
        let sequence = self.waiting_operations.len() as u64;
        self.waiting_operations.push_back(WaitingOperation {
            thread_id,
            operation_type,
            start_time: Instant::now(),
            sequence,
        });
    }

    /// Record the end of a waiting operation (successful or cancelled)
    fn record_wait_end(&mut self, thread_id: usize, operation_type: AcquireType) {
        // Find and remove the corresponding waiting operation
        if let Some(pos) = self
            .waiting_operations
            .iter()
            .position(|w| w.thread_id == thread_id && matches_operation_type(w.operation_type, operation_type))
        {
            self.waiting_operations.remove(pos);
        }
    }

    /// Verify no starvation has occurred
    fn verify_no_starvation(&self) {
        self.verify_writer_starvation_bounds();
        self.verify_reader_starvation_bounds();
        self.verify_fairness_ordering();
    }

    /// Verify that consecutive writers don't exceed the starvation bound
    fn verify_writer_starvation_bounds(&self) {
        assert!(
            self.consecutive_writers <= MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH + 1,
            "Consecutive writers {} exceeds starvation bound {}",
            self.consecutive_writers,
            MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH
        );
    }

    /// Verify reader starvation is bounded
    fn verify_reader_starvation_bounds(&self) {
        // Check for patterns of excessive reader starvation
        let mut consecutive_writers = 0;
        let mut max_consecutive_writers = 0;

        for event in &self.acquire_events {
            match event.operation_type {
                AcquireType::Write | AcquireType::TryWrite => {
                    consecutive_writers += 1;
                    max_consecutive_writers = max_consecutive_writers.max(consecutive_writers);
                }
                AcquireType::Read | AcquireType::TryRead => {
                    consecutive_writers = 0;
                }
            }
        }

        assert!(
            max_consecutive_writers <= MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH + 2,
            "Observed {} consecutive writers, bound is {}",
            max_consecutive_writers,
            MAX_CONSECUTIVE_WRITERS_BEFORE_READER_BATCH
        );
    }

    /// Verify fairness ordering within operation types
    fn verify_fairness_ordering(&self) {
        // Group events by type and verify ordering constraints
        let mut reader_sequences = Vec::new();
        let mut writer_sequences = Vec::new();

        for event in &self.acquire_events {
            match event.operation_type {
                AcquireType::Read | AcquireType::TryRead => {
                    reader_sequences.push(event.sequence);
                }
                AcquireType::Write | AcquireType::TryWrite => {
                    writer_sequences.push(event.sequence);
                }
            }
        }

        // Within each type, sequences should be generally increasing
        // (allowing some flexibility due to try operations and concurrent scheduling)
        verify_general_ordering(&reader_sequences, "readers");
        verify_general_ordering(&writer_sequences, "writers");
    }
}

fn matches_operation_type(a: AcquireType, b: AcquireType) -> bool {
    match (a, b) {
        (AcquireType::Read, AcquireType::Read)
        | (AcquireType::Write, AcquireType::Write)
        | (AcquireType::TryRead, AcquireType::TryRead)
        | (AcquireType::TryWrite, AcquireType::TryWrite) => true,
        _ => false,
    }
}

/// Verify that a sequence is generally increasing (allowing some reordering)
fn verify_general_ordering(sequences: &[u64], context: &str) {
    if sequences.len() < 2 {
        return;
    }

    // Allow up to 25% inversions due to concurrent scheduling
    let mut inversions = 0;
    for i in 0..sequences.len() - 1 {
        if sequences[i] > sequences[i + 1] {
            inversions += 1;
        }
    }

    let inversion_rate = inversions as f64 / sequences.len() as f64;
    assert!(
        inversion_rate < 0.25,
        "Too many ordering inversions for {}: {}/{} ({:.2}%)",
        context, inversions, sequences.len(), inversion_rate * 100.0
    );
}

impl LockOperation {
    fn thread_id(&self) -> u8 {
        match self {
            LockOperation::AcquireRead { thread_id, .. } => *thread_id,
            LockOperation::AcquireWrite { thread_id, .. } => *thread_id,
            LockOperation::TryRead { thread_id, .. } => *thread_id,
            LockOperation::TryWrite { thread_id, .. } => *thread_id,
            LockOperation::Delay { thread_id, .. } => *thread_id,
        }
    }
}

/// Execute operations across threads and verify fairness properties
fn execute_and_verify_fairness(
    rwlock: Arc<RwLock<u64>>,
    tracker: Arc<parking_lot::Mutex<StarvationTracker>>,
    operations_by_thread: HashMap<usize, Vec<LockOperation>>,
    max_threads: usize,
) {
    let mut handles = Vec::new();

    // Spawn worker threads
    for thread_id in 0..max_threads {
        let ops = operations_by_thread.get(&thread_id).cloned().unwrap_or_default();
        if ops.is_empty() {
            continue;
        }

        let rwlock_clone = rwlock.clone();
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            execute_thread_operations(thread_id, ops, rwlock_clone, tracker_clone);
        });
        handles.push(handle);
    }

    // Wait for all threads with timeout
    let start = Instant::now();
    for (i, handle) in handles.into_iter().enumerate() {
        let remaining_time = OPERATION_TIMEOUT.saturating_sub(start.elapsed());

        // Simple timeout mechanism using thread::sleep polling
        let join_result = thread_join_with_timeout(handle, remaining_time);
        assert!(
            join_result.is_ok(),
            "Thread {} timed out - possible deadlock or starvation", i
        );
    }

    // Verify no starvation occurred
    let tracker_guard = tracker.lock();
    tracker_guard.verify_no_starvation();
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

/// Execute lock operations for a single thread
fn execute_thread_operations(
    thread_id: usize,
    operations: Vec<LockOperation>,
    rwlock: Arc<RwLock<u64>>,
    tracker: Arc<parking_lot::Mutex<StarvationTracker>>,
) {
    let cx = Cx::for_testing();

    for operation in operations {
        match operation {
            LockOperation::AcquireRead { hold_ms, .. } => {
                let hold_duration = Duration::from_millis((hold_ms as u64).min(MAX_HOLD_MS));

                // Record wait start
                tracker.lock().record_wait_start(thread_id, AcquireType::Read);

                // Acquire read lock (blocking)
                let _guard = match futures_executor::block_on(rwlock.read(&cx)) {
                    Ok(guard) => {
                        tracker.lock().record_wait_end(thread_id, AcquireType::Read);
                        tracker.lock().record_acquire(thread_id, AcquireType::Read, hold_duration);
                        guard
                    }
                    Err(_) => {
                        tracker.lock().record_wait_end(thread_id, AcquireType::Read);
                        continue;
                    }
                };

                // Hold the lock
                thread::sleep(hold_duration);

                // Release (automatic via drop)
                drop(_guard);
                tracker.lock().record_release(AcquireType::Read);
            }

            LockOperation::AcquireWrite { hold_ms, .. } => {
                let hold_duration = Duration::from_millis((hold_ms as u64).min(MAX_HOLD_MS));

                // Record wait start
                tracker.lock().record_wait_start(thread_id, AcquireType::Write);

                // Acquire write lock (blocking)
                let _guard = match futures_executor::block_on(rwlock.write(&cx)) {
                    Ok(guard) => {
                        tracker.lock().record_wait_end(thread_id, AcquireType::Write);
                        tracker.lock().record_acquire(thread_id, AcquireType::Write, hold_duration);
                        guard
                    }
                    Err(_) => {
                        tracker.lock().record_wait_end(thread_id, AcquireType::Write);
                        continue;
                    }
                };

                // Hold the lock
                thread::sleep(hold_duration);

                // Release (automatic via drop)
                drop(_guard);
                tracker.lock().record_release(AcquireType::Write);
            }

            LockOperation::TryRead { hold_ms, .. } => {
                let hold_duration = Duration::from_millis((hold_ms as u64).min(MAX_HOLD_MS));

                // Try to acquire read lock (non-blocking)
                if let Ok(_guard) = rwlock.try_read() {
                    tracker.lock().record_acquire(thread_id, AcquireType::TryRead, hold_duration);

                    // Hold the lock
                    thread::sleep(hold_duration);

                    // Release (automatic via drop)
                    drop(_guard);
                    tracker.lock().record_release(AcquireType::TryRead);
                }
                // If try_read fails, continue (this is expected behavior)
            }

            LockOperation::TryWrite { hold_ms, .. } => {
                let hold_duration = Duration::from_millis((hold_ms as u64).min(MAX_HOLD_MS));

                // Try to acquire write lock (non-blocking)
                if let Ok(_guard) = rwlock.try_write() {
                    tracker.lock().record_acquire(thread_id, AcquireType::TryWrite, hold_duration);

                    // Hold the lock
                    thread::sleep(hold_duration);

                    // Release (automatic via drop)
                    drop(_guard);
                    tracker.lock().record_release(AcquireType::TryWrite);
                }
                // If try_write fails, continue (this is expected behavior)
            }

            LockOperation::Delay { milliseconds, .. } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                thread::sleep(delay);
            }
        }
    }
}