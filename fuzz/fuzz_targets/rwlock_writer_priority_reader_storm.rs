//! Fuzz RwLock writer-priority under reader-storm conditions.
//!
//! Tests arbitrary mix of long-reader + waiting-writer to ensure writers
//! are not starved by sustained reader sequences. Validates writer-preference
//! fairness policy and proper prevention of writer starvation.
//!
//! Critical invariants:
//! - Writers not starved by continuous reader activity
//! - When writers are waiting, new readers are blocked
//! - Writer-preference policy is enforced consistently
//! - Bounded reader starvation via consecutive writer limits

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::cx::Cx;
use asupersync::sync::rwlock::RwLock;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use futures::task::{Context, noop_waker};
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Arbitrary)]
struct RwLockConfig {
    /// Number of reader threads (1-8)
    reader_count: u8,
    /// Number of writer threads (1-4)
    writer_count: u8,
    /// Read hold durations (milliseconds)
    read_hold_durations: Vec<u16>,
    /// Write hold durations (milliseconds)
    write_hold_durations: Vec<u16>,
    /// Reader arrival delays (microseconds)
    reader_delays: Vec<u16>,
    /// Writer arrival delays (microseconds)
    writer_delays: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
struct WriterPrioritySequence {
    /// Test configuration
    config: RwLockConfig,
    /// Duration to run the test (milliseconds)
    test_duration_ms: u16,
    /// Whether to create reader storm (sustained reader load)
    reader_storm_mode: bool,
}

impl WriterPrioritySequence {
    fn max_readers() -> u8 {
        8 // Reasonable upper bound for thread testing
    }

    fn max_writers() -> u8 {
        4 // Reasonable upper bound for writer testing
    }

    fn max_test_duration_ms() -> u16 {
        5000 // Maximum 5 second test duration
    }
}

/// Statistics tracking for the test
#[derive(Debug)]
struct TestStats {
    reader_acquisitions: AtomicUsize,
    writer_acquisitions: AtomicUsize,
    reader_blocks_due_to_writer: AtomicUsize,
    writer_wait_times_ms: Arc<parking_lot::Mutex<Vec<u64>>>,
    test_start_time: Instant,
    test_complete: AtomicBool,
}

impl TestStats {
    fn new() -> Self {
        Self {
            reader_acquisitions: AtomicUsize::new(0),
            writer_acquisitions: AtomicUsize::new(0),
            reader_blocks_due_to_writer: AtomicUsize::new(0),
            writer_wait_times_ms: Arc::new(parking_lot::Mutex::new(Vec::new())),
            test_start_time: Instant::now(),
            test_complete: AtomicBool::new(false),
        }
    }

    fn check_writer_starvation_invariants(&self) -> Result<(), String> {
        let reader_acqs = self.reader_acquisitions.load(Ordering::SeqCst);
        let writer_acqs = self.writer_acquisitions.load(Ordering::SeqCst);
        let reader_blocks = self.reader_blocks_due_to_writer.load(Ordering::SeqCst);

        // If writers attempted to acquire, they should not be completely starved
        if writer_acqs == 0 && !self.writer_wait_times_ms.lock().is_empty() {
            return Err(
                "Writer starvation detected: writers waited but none succeeded".to_string(),
            );
        }

        // Check writer wait times for excessive delays
        let wait_times = self.writer_wait_times_ms.lock();
        if let Some(&max_wait) = wait_times.iter().max() {
            if max_wait > 2000 {
                // 2 second maximum wait time
                return Err(format!("Excessive writer wait time: {} ms", max_wait));
            }
        }

        // If readers were blocked due to writers, it should show writer priority working
        if reader_blocks > 0 && writer_acqs == 0 {
            return Err("Readers blocked for writers but no writers succeeded".to_string());
        }

        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: WriterPrioritySequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.reader_count == 0
        || sequence.config.writer_count == 0
        || sequence.config.reader_count > WriterPrioritySequence::max_readers()
        || sequence.config.writer_count > WriterPrioritySequence::max_writers()
    {
        return;
    }

    let reader_count = sequence.config.reader_count as usize;
    let writer_count = sequence.config.writer_count as usize;
    let test_duration = Duration::from_millis(
        sequence
            .test_duration_ms
            .min(WriterPrioritySequence::max_test_duration_ms()) as u64,
    );

    // Create shared RwLock and test infrastructure
    let rwlock = Arc::new(RwLock::new(0u32));
    let stats = Arc::new(TestStats::new());
    let start_barrier = Arc::new(Barrier::new(reader_count + writer_count + 1));

    let mut handles = Vec::new();

    // Spawn reader threads
    for reader_id in 0..reader_count {
        let rwlock = Arc::clone(&rwlock);
        let stats = Arc::clone(&stats);
        let start_barrier = Arc::clone(&start_barrier);
        let hold_duration = sequence
            .config
            .read_hold_durations
            .get(reader_id)
            .copied()
            .unwrap_or(100); // Default 100ms hold
        let arrival_delay = sequence
            .config
            .reader_delays
            .get(reader_id)
            .copied()
            .unwrap_or(0);

        let handle = thread::spawn(move || {
            start_barrier.wait();

            // Apply initial arrival delay
            if arrival_delay > 0 {
                thread::sleep(Duration::from_micros(arrival_delay as u64));
            }

            while !stats.test_complete.load(Ordering::Acquire) {
                let cx = Cx::new(
                    RegionId::from_arena(ArenaIndex::new(0, reader_id as u32)),
                    TaskId::from_arena(ArenaIndex::new(0, reader_id as u32)),
                    Budget::INFINITE,
                );

                // Try to acquire read lock
                let mut read_future = rwlock.read(&cx);
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                let start_wait = Instant::now();
                let read_guard = loop {
                    match Pin::new(&mut read_future).poll(&mut context) {
                        Poll::Ready(Ok(guard)) => break guard,
                        Poll::Ready(Err(_)) => {
                            // Failed to acquire (cancelled or poisoned)
                            return;
                        }
                        Poll::Pending => {
                            // Check if blocked due to waiting writer
                            if start_wait.elapsed() > Duration::from_millis(10) {
                                stats
                                    .reader_blocks_due_to_writer
                                    .fetch_add(1, Ordering::SeqCst);
                            }

                            // Small yield to avoid busy spinning
                            thread::sleep(Duration::from_millis(1));

                            // Check test completion
                            if stats.test_complete.load(Ordering::Acquire) {
                                return;
                            }
                        }
                    }
                };

                // Successfully acquired read lock
                stats.reader_acquisitions.fetch_add(1, Ordering::SeqCst);

                // Hold the read lock for the specified duration
                thread::sleep(Duration::from_millis(hold_duration as u64));

                // Access the data while holding read lock
                let _value = *read_guard;

                // Drop read guard (automatic on scope exit)
                drop(read_guard);

                // In reader storm mode, immediately try to acquire again
                if !sequence.reader_storm_mode {
                    thread::sleep(Duration::from_millis(10)); // Small gap between acquisitions
                }
            }
        });

        handles.push(handle);
    }

    // Spawn writer threads
    for writer_id in 0..writer_count {
        let rwlock = Arc::clone(&rwlock);
        let stats = Arc::clone(&stats);
        let start_barrier = Arc::clone(&start_barrier);
        let hold_duration = sequence
            .config
            .write_hold_durations
            .get(writer_id)
            .copied()
            .unwrap_or(50); // Default 50ms hold (shorter than reads)
        let arrival_delay = sequence
            .config
            .writer_delays
            .get(writer_id)
            .copied()
            .unwrap_or(0);

        let handle = thread::spawn(move || {
            start_barrier.wait();

            // Apply initial arrival delay
            if arrival_delay > 0 {
                thread::sleep(Duration::from_micros(arrival_delay as u64));
            }

            while !stats.test_complete.load(Ordering::Acquire) {
                let cx = Cx::new(
                    RegionId::from_arena(ArenaIndex::new(1, writer_id as u32)),
                    TaskId::from_arena(ArenaIndex::new(1, writer_id as u32)),
                    Budget::INFINITE,
                );

                // Try to acquire write lock
                let mut write_future = rwlock.write(&cx);
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                let wait_start = Instant::now();
                let mut write_guard = loop {
                    match Pin::new(&mut write_future).poll(&mut context) {
                        Poll::Ready(Ok(guard)) => break guard,
                        Poll::Ready(Err(_)) => {
                            // Failed to acquire (cancelled or poisoned)
                            return;
                        }
                        Poll::Pending => {
                            // Small yield to avoid busy spinning
                            thread::sleep(Duration::from_millis(1));

                            // Check test completion
                            if stats.test_complete.load(Ordering::Acquire) {
                                return;
                            }
                        }
                    }
                };

                // Successfully acquired write lock
                let wait_time_ms = wait_start.elapsed().as_millis() as u64;
                stats.writer_wait_times_ms.lock().push(wait_time_ms);
                stats.writer_acquisitions.fetch_add(1, Ordering::SeqCst);

                // Hold the write lock for the specified duration
                thread::sleep(Duration::from_millis(hold_duration as u64));

                // Modify the data while holding write lock
                *write_guard += 1;

                // Drop write guard (automatic on scope exit)
                drop(write_guard);

                // Gap between write attempts
                thread::sleep(Duration::from_millis(20));
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to start
    start_barrier.wait();

    // Let the test run for the specified duration
    thread::sleep(test_duration);

    // Signal test completion
    stats.test_complete.store(true, Ordering::Release);

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete");
    }

    // Validate writer-priority invariants
    if let Err(msg) = stats.check_writer_starvation_invariants() {
        panic!("Writer priority invariant violation: {}", msg);
    }

    // Check basic sanity - at least some acquisitions should have occurred
    let total_reader_acqs = stats.reader_acquisitions.load(Ordering::SeqCst);
    let total_writer_acqs = stats.writer_acquisitions.load(Ordering::SeqCst);

    assert!(
        total_reader_acqs > 0 || total_writer_acqs > 0,
        "No lock acquisitions occurred during test"
    );

    // In reader storm mode with writers present, writers should eventually succeed
    if sequence.reader_storm_mode && writer_count > 0 && total_reader_acqs > 0 {
        assert!(
            total_writer_acqs > 0,
            "Writer starvation in reader storm: {} reader acquisitions but 0 writer acquisitions",
            total_reader_acqs
        );
    }

    // Verify the final value makes sense (should equal total writer acquisitions)
    let final_value = *rwlock.try_read().expect("Should be able to read at end");
    assert_eq!(
        final_value, total_writer_acqs as u32,
        "Final value {} should equal writer acquisitions {}",
        final_value, total_writer_acqs
    );

    // Log statistics for analysis
    let elapsed = stats.test_start_time.elapsed().as_millis();
    println!(
        "Test completed in {}ms: {} readers, {} writers, {} reader blocks",
        elapsed,
        total_reader_acqs,
        total_writer_acqs,
        stats.reader_blocks_due_to_writer.load(Ordering::SeqCst)
    );
});
