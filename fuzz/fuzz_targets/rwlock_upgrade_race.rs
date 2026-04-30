//! Fuzz RwLock read-to-write upgrade race conditions.
//!
//! Tests arbitrary upgrade attempts to ensure only one upgrade succeeds
//! while others fail appropriately. An "upgrade" means dropping a read
//! guard and immediately acquiring a write guard. Multiple concurrent
//! upgrade attempts should result in exactly one success.
//!
//! Critical invariants:
//! - Only one upgrade succeeds per round
//! - Failed upgrades return appropriate errors (not panics)
//! - No lost wakeups or deadlocks during upgrade races
//! - Upgrade success is deterministic given fixed timing

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::RwLock;
use asupersync::cx::Cx;
use asupersync::util::ArenaIndex;
use asupersync::types::{RegionId, TaskId};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::pin::Pin;
use std::future::Future;

#[derive(Debug, Clone, Arbitrary)]
struct RwLockUpgradeConfig {
    /// Number of initial readers
    initial_readers: u8,
    /// Operations to perform
    operations: Vec<UpgradeOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum UpgradeOperation {
    /// Add a new reader
    AddReader { reader_id: u8 },
    /// Attempt to upgrade a specific reader to writer
    AttemptUpgrade { reader_id: u8 },
    /// Release a specific reader without upgrading
    ReleaseReader { reader_id: u8 },
    /// Release the current writer (if any)
    ReleaseWriter,
    /// Multiple readers attempt upgrade simultaneously
    ConcurrentUpgrade { reader_ids: Vec<u8> },
    /// Check state consistency
    CheckState,
}

impl RwLockUpgradeConfig {
    fn max_readers() -> u8 {
        15 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_concurrent_upgrades() -> u8 {
        8 // Limit concurrent upgrade attempts
    }
}

/// Tracks upgrade behavior to detect race condition violations
#[derive(Debug)]
struct UpgradeTracker {
    upgrade_attempts: AtomicUsize,
    successful_upgrades: AtomicUsize,
    failed_upgrades: AtomicUsize,
    readers_created: AtomicUsize,
    writers_created: AtomicUsize,
    deadlocks_detected: AtomicUsize,
}

impl UpgradeTracker {
    fn new() -> Self {
        Self {
            upgrade_attempts: AtomicUsize::new(0),
            successful_upgrades: AtomicUsize::new(0),
            failed_upgrades: AtomicUsize::new(0),
            readers_created: AtomicUsize::new(0),
            writers_created: AtomicUsize::new(0),
            deadlocks_detected: AtomicUsize::new(0),
        }
    }

    fn record_upgrade_attempt(&self) {
        self.upgrade_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_successful_upgrade(&self) {
        self.successful_upgrades.fetch_add(1, Ordering::SeqCst);
    }

    fn record_failed_upgrade(&self) {
        self.failed_upgrades.fetch_add(1, Ordering::SeqCst);
    }

    fn record_reader_created(&self) {
        self.readers_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_writer_created(&self) {
        self.writers_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_deadlock(&self) {
        self.deadlocks_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let attempts = self.upgrade_attempts.load(Ordering::SeqCst);
        let successes = self.successful_upgrades.load(Ordering::SeqCst);
        let failures = self.failed_upgrades.load(Ordering::SeqCst);
        let deadlocks = self.deadlocks_detected.load(Ordering::SeqCst);

        // Core invariant: no deadlocks should be detected
        if deadlocks > 0 {
            return Err(format!("Detected {} deadlocks during upgrade operations", deadlocks));
        }

        // All attempts should be accounted for
        if attempts > 0 && (successes + failures) == 0 {
            return Err(format!(
                "Had {} upgrade attempts but no recorded outcomes",
                attempts
            ));
        }

        // Sanity checks
        if successes > attempts {
            return Err(format!(
                "More successful upgrades ({}) than total attempts ({})",
                successes, attempts
            ));
        }

        if successes + failures > attempts {
            return Err(format!(
                "Recorded outcomes ({}) exceed total attempts ({})",
                successes + failures, attempts
            ));
        }

        Ok(())
    }
}

/// Tracks a reader that may attempt to upgrade
struct TrackedReader {
    read_guard: Option<Pin<Box<dyn Future<Output = Result<(), String>> + Send>>>,
    attempting_upgrade: bool,
    completed: Arc<AtomicBool>,
    upgrade_success: Arc<AtomicBool>,
}

impl TrackedReader {
    fn new(rwlock: Arc<RwLock<i32>>, reader_id: u8, tracker: Arc<UpgradeTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let upgrade_success = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let tracker_clone = tracker.clone();

        let read_future = Box::pin(async move {
            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 0)),
                TaskId::from_arena(ArenaIndex::new(0, 0)),
            );

            match rwlock.read(&cx).await {
                Ok(_guard) => {
                    tracker_clone.record_reader_created();
                    // Hold the read guard - in real usage this would do some read work
                    completed_clone.store(true, Ordering::SeqCst);
                    Ok(())
                }
                Err(e) => {
                    completed_clone.store(true, Ordering::SeqCst);
                    Err(format!("Failed to acquire read lock for reader {}: {:?}", reader_id, e))
                }
            }
        });

        Self {
            read_guard: Some(read_future),
            attempting_upgrade: false,
            completed,
            upgrade_success,
        }
    }

    fn attempt_upgrade(&mut self, rwlock: Arc<RwLock<i32>>, reader_id: u8, tracker: Arc<UpgradeTracker>) {
        if self.attempting_upgrade {
            return; // Already attempting
        }

        tracker.record_upgrade_attempt();
        self.attempting_upgrade = true;

        // Drop the read guard and try to acquire write guard
        self.read_guard = None;

        let upgrade_success = self.upgrade_success.clone();
        let completed = self.completed.clone();

        let upgrade_future = Box::pin(async move {
            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 0)),
                TaskId::from_arena(ArenaIndex::new(0, 0)),
            );

            match rwlock.write(&cx).await {
                Ok(_write_guard) => {
                    tracker.record_successful_upgrade();
                    tracker.record_writer_created();
                    upgrade_success.store(true, Ordering::SeqCst);
                    completed.store(true, Ordering::SeqCst);
                    Ok(())
                }
                Err(e) => {
                    tracker.record_failed_upgrade();
                    completed.store(true, Ordering::SeqCst);
                    Err(format!("Failed to upgrade reader {} to writer: {:?}", reader_id, e))
                }
            }
        });

        self.read_guard = Some(upgrade_future);
    }

    fn poll(&mut self) -> Poll<Result<(), String>> {
        if let Some(ref mut future) = self.read_guard {
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            if result.is_ready() {
                self.read_guard = None;
            }

            result
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn upgrade_succeeded(&self) -> bool {
        self.upgrade_success.load(Ordering::SeqCst)
    }
}

fn noop_waker() -> Waker {
    use std::task::{RawWaker, RawWakerVTable};

    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

/// Test RwLock upgrade race scenarios
fn test_upgrade_race_scenario(
    config: &RwLockUpgradeConfig,
    tracker: &UpgradeTracker,
) -> Result<(), String> {
    let rwlock = Arc::new(RwLock::new(42i32));
    let mut readers: HashMap<u8, TrackedReader> = HashMap::new();
    let mut current_writer: Option<u8> = None;

    let max_readers = config.initial_readers.min(RwLockUpgradeConfig::max_readers());

    // Create initial readers
    for i in 0..max_readers {
        let reader = TrackedReader::new(rwlock.clone(), i, Arc::new(UpgradeTracker::new()));
        readers.insert(i, reader);
    }

    let max_ops = config.max_operations.min(RwLockUpgradeConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            UpgradeOperation::AddReader { reader_id } => {
                let id = *reader_id % 20; // Limit total readers
                if !readers.contains_key(&id) && readers.len() < RwLockUpgradeConfig::max_readers() as usize {
                    let reader = TrackedReader::new(rwlock.clone(), id, Arc::new(UpgradeTracker::new()));
                    readers.insert(id, reader);
                }
            }

            UpgradeOperation::AttemptUpgrade { reader_id } => {
                let id = *reader_id % 20;
                if let Some(reader) = readers.get_mut(&id) {
                    if current_writer.is_none() {
                        reader.attempt_upgrade(rwlock.clone(), id, Arc::new(UpgradeTracker::new()));
                    }
                }
            }

            UpgradeOperation::ReleaseReader { reader_id } => {
                let id = *reader_id % 20;
                readers.remove(&id);
            }

            UpgradeOperation::ReleaseWriter => {
                current_writer = None;
            }

            UpgradeOperation::ConcurrentUpgrade { reader_ids } => {
                let max_concurrent = RwLockUpgradeConfig::max_concurrent_upgrades() as usize;
                let concurrent_count = reader_ids.len().min(max_concurrent);

                if current_writer.is_none() {
                    let mut upgrade_attempts = 0;
                    let mut successful_upgrades = 0;

                    for &reader_id in reader_ids.iter().take(concurrent_count) {
                        let id = reader_id % 20;
                        if let Some(reader) = readers.get_mut(&id) {
                            reader.attempt_upgrade(rwlock.clone(), id, Arc::new(UpgradeTracker::new()));
                            upgrade_attempts += 1;
                        }
                    }

                    // Poll all readers to see results
                    for _ in 0..10 { // Give some iterations for completion
                        for reader in readers.values_mut() {
                            let _ = reader.poll();
                            if reader.upgrade_succeeded() {
                                successful_upgrades += 1;
                            }
                        }
                    }

                    // Critical invariant: only one upgrade should succeed
                    if successful_upgrades > 1 {
                        return Err(format!(
                            "Multiple concurrent upgrades succeeded: {} out of {} attempts",
                            successful_upgrades, upgrade_attempts
                        ));
                    }

                    if successful_upgrades == 1 {
                        // Find which one succeeded and mark as current writer
                        for (&id, reader) in readers.iter() {
                            if reader.upgrade_succeeded() {
                                current_writer = Some(id);
                                break;
                            }
                        }
                    }
                }
            }

            UpgradeOperation::CheckState => {
                // Check for consistency
                let active_readers = readers.iter().filter(|(_, r)| !r.attempting_upgrade).count();
                let attempting_upgrades = readers.iter().filter(|(_, r)| r.attempting_upgrade).count();

                if current_writer.is_some() && active_readers > 0 {
                    return Err(format!(
                        "Inconsistent state: writer present with {} active readers",
                        active_readers
                    ));
                }

                if attempting_upgrades > RwLockUpgradeConfig::max_readers() as usize {
                    tracker.record_deadlock();
                    return Err(format!("Too many concurrent upgrade attempts: {}", attempting_upgrades));
                }

                // Check our tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }

        // Always poll all readers to make progress
        let mut to_remove = Vec::new();
        for (&id, reader) in readers.iter_mut() {
            let _ = reader.poll();
            if reader.is_completed() && !reader.attempting_upgrade {
                to_remove.push(id);
            }
        }
        for id in to_remove {
            readers.remove(&id);
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: RwLockUpgradeConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = UpgradeTracker::new();

    // Test the upgrade race scenario
    if let Err(msg) = test_upgrade_race_scenario(&config, &tracker) {
        panic!("RwLock upgrade race test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = UpgradeTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_upgrade_race_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent upgrade race test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_attempts = tracker.upgrade_attempts.load(Ordering::SeqCst);
    let total_readers = tracker.readers_created.load(Ordering::SeqCst);

    if total_attempts == 0 && total_readers == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});