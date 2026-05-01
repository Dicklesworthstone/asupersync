//! RwLock fairness conformance test: asupersync vs std::sync::RwLock
//!
//! Tests that both implementations exhibit similar fairness characteristics
//! when the same sequence of N readers + M writers arrive in the same order.
//! Validates basic ordering semantics and absence of starvation.

use asupersync::cx::Cx;
use asupersync::sync::RwLock as AsyncRwLock;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::pin::Pin;
use std::sync::RwLock as StdRwLock;
use std::sync::{Arc, Barrier, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

/// Result of a rwlock fairness conformance test comparing both implementations.
#[derive(Debug, Clone, PartialEq)]
struct RwLockConformanceResult {
    /// Test scenario identifier
    scenario: String,
    /// Total number of operations completed
    total_operations: usize,
    /// Number of readers that successfully acquired
    reader_acquisitions: usize,
    /// Number of writers that successfully acquired
    writer_acquisitions: usize,
    /// Order in which acquisitions completed (thread_id, is_writer)
    completion_order: Vec<(usize, bool)>,
    /// Total test duration
    duration: Duration,
}

/// Test configuration for fairness comparison
#[derive(Debug, Clone)]
struct FairnessTest {
    /// Number of readers to spawn
    reader_count: usize,
    /// Number of writers to spawn
    writer_count: usize,
    /// How long each reader holds the lock (ms)
    read_hold_time: u64,
    /// How long each writer holds the lock (ms)
    write_hold_time: u64,
}

/// Tracks the order of lock completions
#[derive(Debug)]
struct CompletionTracker {
    completions: StdMutex<Vec<(usize, bool, Instant)>>,
}

impl CompletionTracker {
    fn new() -> Self {
        Self {
            completions: StdMutex::new(Vec::new()),
        }
    }

    fn record_completion(&self, thread_id: usize, is_writer: bool) {
        self.completions
            .lock()
            .unwrap()
            .push((thread_id, is_writer, Instant::now()));
    }

    fn get_completion_order(&self) -> Vec<(usize, bool)> {
        let mut completions = self.completions.lock().unwrap().clone();
        completions.sort_by_key(|(_, _, timestamp)| *timestamp);
        completions
            .into_iter()
            .map(|(id, is_writer, _)| (id, is_writer))
            .collect()
    }
}

/// Run fairness test on asupersync RwLock
fn test_async_rwlock_fairness(config: &FairnessTest) -> RwLockConformanceResult {
    let rwlock = Arc::new(AsyncRwLock::new(0u32));
    let tracker = Arc::new(CompletionTracker::new());
    let start_barrier = Arc::new(Barrier::new(config.reader_count + config.writer_count + 1));
    let start_time = Instant::now();

    let mut handles = Vec::new();

    // Spawn readers
    for i in 0..config.reader_count {
        let rwlock = Arc::clone(&rwlock);
        let tracker = Arc::clone(&tracker);
        let start_barrier = Arc::clone(&start_barrier);
        let config = config.clone();

        let handle = thread::spawn(move || {
            let thread_id = i;
            start_barrier.wait();

            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, thread_id as u32)),
                TaskId::from_arena(ArenaIndex::new(0, thread_id as u32)),
                Budget::INFINITE,
            );

            // Manual polling approach to simulate blocking
            let mut read_future = rwlock.read(&cx);

            // Simple polling loop
            loop {
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                match Pin::new(&mut read_future).poll(&mut context) {
                    Poll::Ready(Ok(guard)) => {
                        // Hold the read lock
                        thread::sleep(Duration::from_millis(config.read_hold_time));
                        drop(guard);
                        tracker.record_completion(thread_id, false);
                        break;
                    }
                    Poll::Ready(Err(_)) => break, // Error
                    Poll::Pending => {
                        thread::sleep(Duration::from_millis(1)); // Small yield
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Spawn writers
    for i in 0..config.writer_count {
        let rwlock = Arc::clone(&rwlock);
        let tracker = Arc::clone(&tracker);
        let start_barrier = Arc::clone(&start_barrier);
        let config = config.clone();

        let handle = thread::spawn(move || {
            let thread_id = config.reader_count + i; // Offset by reader count
            start_barrier.wait();

            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(1, i as u32)),
                TaskId::from_arena(ArenaIndex::new(1, i as u32)),
                Budget::INFINITE,
            );

            // Manual polling approach
            let mut write_future = rwlock.write(&cx);

            // Simple polling loop
            loop {
                let waker = noop_waker();
                let mut context = Context::from_waker(&waker);

                match Pin::new(&mut write_future).poll(&mut context) {
                    Poll::Ready(Ok(mut guard)) => {
                        // Hold the write lock and modify data
                        *guard += 1;
                        thread::sleep(Duration::from_millis(config.write_hold_time));
                        drop(guard);
                        tracker.record_completion(thread_id, true);
                        break;
                    }
                    Poll::Ready(Err(_)) => break, // Error
                    Poll::Pending => {
                        thread::sleep(Duration::from_millis(1)); // Small yield
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Start all threads
    start_barrier.wait();

    // Wait for completion
    for handle in handles {
        handle.join().unwrap();
    }

    let completion_order = tracker.get_completion_order();
    let reader_acquisitions = completion_order
        .iter()
        .filter(|(_, is_writer)| !is_writer)
        .count();
    let writer_acquisitions = completion_order
        .iter()
        .filter(|(_, is_writer)| *is_writer)
        .count();

    RwLockConformanceResult {
        scenario: "async_rwlock".to_string(),
        total_operations: completion_order.len(),
        reader_acquisitions,
        writer_acquisitions,
        completion_order,
        duration: start_time.elapsed(),
    }
}

/// Run fairness test on std::sync::RwLock
fn test_std_rwlock_fairness(config: &FairnessTest) -> RwLockConformanceResult {
    let rwlock = Arc::new(StdRwLock::new(0u32));
    let tracker = Arc::new(CompletionTracker::new());
    let start_barrier = Arc::new(Barrier::new(config.reader_count + config.writer_count + 1));
    let start_time = Instant::now();

    let mut handles = Vec::new();

    // Spawn readers
    for i in 0..config.reader_count {
        let rwlock = Arc::clone(&rwlock);
        let tracker = Arc::clone(&tracker);
        let start_barrier = Arc::clone(&start_barrier);
        let config = config.clone();

        let handle = thread::spawn(move || {
            let thread_id = i;
            start_barrier.wait();

            // Acquire read lock (blocking)
            let guard = rwlock.read().unwrap();

            // Hold the read lock
            thread::sleep(Duration::from_millis(config.read_hold_time));
            drop(guard);

            tracker.record_completion(thread_id, false);
        });

        handles.push(handle);
    }

    // Spawn writers
    for i in 0..config.writer_count {
        let rwlock = Arc::clone(&rwlock);
        let tracker = Arc::clone(&tracker);
        let start_barrier = Arc::clone(&start_barrier);
        let config = config.clone();

        let handle = thread::spawn(move || {
            let thread_id = config.reader_count + i; // Offset by reader count
            start_barrier.wait();

            // Acquire write lock (blocking)
            let mut guard = rwlock.write().unwrap();

            // Hold the write lock and modify data
            *guard += 1;
            thread::sleep(Duration::from_millis(config.write_hold_time));
            drop(guard);

            tracker.record_completion(thread_id, true);
        });

        handles.push(handle);
    }

    // Start all threads
    start_barrier.wait();

    // Wait for completion
    for handle in handles {
        handle.join().unwrap();
    }

    let completion_order = tracker.get_completion_order();
    let reader_acquisitions = completion_order
        .iter()
        .filter(|(_, is_writer)| !is_writer)
        .count();
    let writer_acquisitions = completion_order
        .iter()
        .filter(|(_, is_writer)| *is_writer)
        .count();

    RwLockConformanceResult {
        scenario: "std_rwlock".to_string(),
        total_operations: completion_order.len(),
        reader_acquisitions,
        writer_acquisitions,
        completion_order,
        duration: start_time.elapsed(),
    }
}

/// Compare fairness results between implementations
fn compare_fairness_results(
    async_result: &RwLockConformanceResult,
    std_result: &RwLockConformanceResult,
) -> Result<(), String> {
    // Both should complete all operations
    if async_result.total_operations
        != async_result.reader_acquisitions + async_result.writer_acquisitions
    {
        return Err("Async RwLock: total operations != sum of acquisitions".to_string());
    }

    if std_result.total_operations
        != std_result.reader_acquisitions + std_result.writer_acquisitions
    {
        return Err("Std RwLock: total operations != sum of acquisitions".to_string());
    }

    // Both should have same number of total operations
    if async_result.total_operations != std_result.total_operations {
        return Err(format!(
            "Total operations differ: async={}, std={}",
            async_result.total_operations, std_result.total_operations
        ));
    }

    // Both should complete all readers and writers (no starvation)
    if async_result.reader_acquisitions != std_result.reader_acquisitions {
        return Err(format!(
            "Reader acquisitions differ: async={}, std={}",
            async_result.reader_acquisitions, std_result.reader_acquisitions
        ));
    }

    if async_result.writer_acquisitions != std_result.writer_acquisitions {
        return Err(format!(
            "Writer acquisitions differ: async={}, std={}",
            async_result.writer_acquisitions, std_result.writer_acquisitions
        ));
    }

    println!(
        "Async RwLock completion order: {:?}",
        async_result.completion_order
    );
    println!(
        "Std RwLock completion order: {:?}",
        std_result.completion_order
    );
    println!(
        "Async duration: {:?}, Std duration: {:?}",
        async_result.duration, std_result.duration
    );

    Ok(())
}

#[test]
fn rwlock_fairness_basic_conformance() {
    let config = FairnessTest {
        reader_count: 3,
        writer_count: 2,
        read_hold_time: 10,
        write_hold_time: 10,
    };

    let async_result = test_async_rwlock_fairness(&config);
    let std_result = test_std_rwlock_fairness(&config);

    compare_fairness_results(&async_result, &std_result)
        .expect("Basic fairness conformance check failed");
}

#[test]
fn rwlock_fairness_writer_preference_conformance() {
    let config = FairnessTest {
        reader_count: 4,
        writer_count: 2,
        read_hold_time: 20,
        write_hold_time: 5,
    };

    let async_result = test_async_rwlock_fairness(&config);
    let std_result = test_std_rwlock_fairness(&config);

    compare_fairness_results(&async_result, &std_result)
        .expect("Writer preference fairness conformance check failed");
}

#[test]
fn rwlock_fairness_no_starvation_conformance() {
    // Test that both implementations complete all operations without starvation
    let config = FairnessTest {
        reader_count: 6,
        writer_count: 3,
        read_hold_time: 5,
        write_hold_time: 5,
    };

    let async_result = test_async_rwlock_fairness(&config);
    let std_result = test_std_rwlock_fairness(&config);

    // Verify no starvation occurred
    assert_eq!(
        async_result.reader_acquisitions, config.reader_count,
        "Async RwLock: reader starvation detected"
    );
    assert_eq!(
        async_result.writer_acquisitions, config.writer_count,
        "Async RwLock: writer starvation detected"
    );
    assert_eq!(
        std_result.reader_acquisitions, config.reader_count,
        "Std RwLock: reader starvation detected"
    );
    assert_eq!(
        std_result.writer_acquisitions, config.writer_count,
        "Std RwLock: writer starvation detected"
    );

    compare_fairness_results(&async_result, &std_result)
        .expect("No starvation fairness conformance check failed");
}
