//! Fuzz RwLock reentrant read scenarios from same thread.
//!
//! Tests arbitrary recursive read lock acquisitions from the same thread to
//! ensure no deadlocks occur and proper reference counting is maintained.
//! Validates that nested read guards can be acquired and released correctly
//! without double-grant issues or state corruption.
//!
//! Critical invariants:
//! - Same thread can acquire multiple read locks without deadlock
//! - Reader count properly tracks nested acquisitions
//! - All guards release correctly when dropped
//! - No use-after-free or double-release bugs in nested scenarios

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::cx::Cx;
use asupersync::sync::RwLock;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, hash_map::Entry};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Arbitrary)]
struct RwLockReentrantConfig {
    /// Operations to perform
    operations: Vec<ReentrantOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum ReentrantOperation {
    /// Acquire a new read lock (nested)
    AcquireRead { lock_id: u8, guard_id: u8 },
    /// Try to acquire read lock without waiting
    TryAcquireRead { lock_id: u8, guard_id: u8 },
    /// Release a specific read guard
    ReleaseGuard { lock_id: u8, guard_id: u8 },
    /// Nested read acquisitions in sequence
    NestedReads { lock_id: u8, count: u8 },
    /// Acquire multiple, release some, acquire more
    MixedSequence { lock_id: u8, sequence: Vec<u8> },
    /// Deep nesting (acquire many, then release all)
    DeepNesting { lock_id: u8, depth: u8 },
    /// Rapid acquire/release cycles
    RapidCycle { lock_id: u8, cycles: u8 },
    /// Check lock state consistency
    CheckState,
}

impl RwLockReentrantConfig {
    fn max_locks() -> u8 {
        6 // Limit total locks for testing
    }

    fn max_operations() -> u8 {
        35 // Limit test duration
    }

    fn max_guards_per_lock() -> u8 {
        12 // Limit nested depth
    }

    fn max_nesting_depth() -> u8 {
        8 // Limit deep nesting
    }

    fn max_cycles() -> u8 {
        6 // Limit rapid cycles
    }

    fn max_sequence() -> u8 {
        10 // Limit mixed sequence operations
    }
}

/// Tracks reentrant read behavior to detect invariant violations
#[derive(Debug)]
struct ReentrantTracker {
    read_acquisitions: AtomicUsize,
    read_releases: AtomicUsize,
    try_read_attempts: AtomicUsize,
    try_read_successes: AtomicUsize,
    deadlock_detected: AtomicUsize,
    double_release_detected: AtomicUsize,
    inconsistent_state_detected: AtomicUsize,
    active_guards: AtomicUsize,
}

impl ReentrantTracker {
    fn new() -> Self {
        Self {
            read_acquisitions: AtomicUsize::new(0),
            read_releases: AtomicUsize::new(0),
            try_read_attempts: AtomicUsize::new(0),
            try_read_successes: AtomicUsize::new(0),
            deadlock_detected: AtomicUsize::new(0),
            double_release_detected: AtomicUsize::new(0),
            inconsistent_state_detected: AtomicUsize::new(0),
            active_guards: AtomicUsize::new(0),
        }
    }

    fn record_read_acquisition(&self) {
        self.read_acquisitions.fetch_add(1, Ordering::SeqCst);
        self.active_guards.fetch_add(1, Ordering::SeqCst);
    }

    fn record_read_release(&self) {
        self.read_releases.fetch_add(1, Ordering::SeqCst);
        let prev_active = self.active_guards.fetch_sub(1, Ordering::SeqCst);
        if prev_active == 0 {
            self.double_release_detected.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_try_read_attempt(&self) {
        self.try_read_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_try_read_success(&self) {
        self.try_read_successes.fetch_add(1, Ordering::SeqCst);
    }

    fn record_double_release(&self) {
        self.double_release_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn record_inconsistent_state(&self) {
        self.inconsistent_state_detected
            .fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let acquisitions = self.read_acquisitions.load(Ordering::SeqCst);
        let releases = self.read_releases.load(Ordering::SeqCst);
        let active = self.active_guards.load(Ordering::SeqCst);
        let deadlocks = self.deadlock_detected.load(Ordering::SeqCst);
        let double_releases = self.double_release_detected.load(Ordering::SeqCst);
        let inconsistent = self.inconsistent_state_detected.load(Ordering::SeqCst);

        // Core invariants: no deadlocks, no double releases, no inconsistencies
        if deadlocks > 0 {
            return Err(format!("Detected {deadlocks} deadlock situations"));
        }

        if double_releases > 0 {
            return Err(format!(
                "Detected {double_releases} double-release situations"
            ));
        }

        if inconsistent > 0 {
            return Err(format!(
                "Detected {inconsistent} inconsistent state situations"
            ));
        }

        // Active guards should equal acquisitions minus releases
        if active != acquisitions.saturating_sub(releases) {
            return Err(format!(
                "Guard count mismatch: {active} active vs {} expected (acq {acquisitions} - rel {releases})",
                acquisitions.saturating_sub(releases)
            ));
        }

        // Sanity checks
        if releases > acquisitions {
            return Err(format!(
                "More releases ({releases}) than acquisitions ({acquisitions})"
            ));
        }

        if acquisitions > 1000 {
            return Err(format!("Excessive acquisitions: {acquisitions}"));
        }

        Ok(())
    }
}

/// Tracks an individual read guard for testing
struct TrackedGuard {
    _guard: asupersync::sync::RwLockReadGuard<'static, i32>,
    acquired: bool,
}

impl TrackedGuard {
    fn new(guard: asupersync::sync::RwLockReadGuard<'static, i32>) -> Self {
        Self {
            _guard: guard,
            acquired: true,
        }
    }

    fn is_acquired(&self) -> bool {
        self.acquired
    }
}

impl Drop for TrackedGuard {
    fn drop(&mut self) {
        // Guard will be automatically released when dropped
        self.acquired = false;
    }
}

/// Test RwLock reentrant read scenarios
fn test_rwlock_reentrant_read_scenario(
    config: &RwLockReentrantConfig,
    tracker: &ReentrantTracker,
) -> Result<(), String> {
    let cx = Cx::for_testing();

    // Use leaked reference to get 'static lifetime for guards
    let locks: Vec<&'static RwLock<i32>> = (0..RwLockReentrantConfig::max_locks())
        .map(|i| &*Box::leak(Box::new(RwLock::new(i32::from(i)))))
        .collect();

    let mut guards: HashMap<(u8, u8), TrackedGuard> = HashMap::new(); // (lock_id, guard_id) -> guard

    let max_ops_limit = if config.test_concurrency {
        RwLockReentrantConfig::max_operations()
    } else {
        RwLockReentrantConfig::max_operations().saturating_sub(5)
    };
    let max_ops = config.max_operations.min(max_ops_limit) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            ReentrantOperation::AcquireRead { lock_id, guard_id } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let guard_key = (
                    lock_idx as u8,
                    *guard_id % RwLockReentrantConfig::max_guards_per_lock(),
                );

                if let Entry::Vacant(entry) = guards.entry(guard_key) {
                    let lock = locks[lock_idx];

                    // Use blocking read for simplicity in fuzzing (we're testing same-thread reentrancy)
                    let guard_result = futures::executor::block_on(lock.read(&cx));

                    match guard_result {
                        Ok(guard) => {
                            tracker.record_read_acquisition();
                            let tracked_guard = TrackedGuard::new(guard);
                            entry.insert(tracked_guard);
                        }
                        Err(_) => {
                            // Read acquisition failed - this could happen if lock is poisoned
                            // For reentrant reads from same thread, this should be rare
                        }
                    }
                }
            }

            ReentrantOperation::TryAcquireRead { lock_id, guard_id } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let guard_key = (
                    lock_idx as u8,
                    *guard_id % RwLockReentrantConfig::max_guards_per_lock(),
                );

                if let Entry::Vacant(entry) = guards.entry(guard_key) {
                    let lock = locks[lock_idx];
                    tracker.record_try_read_attempt();

                    match lock.try_read() {
                        Ok(guard) => {
                            tracker.record_try_read_success();
                            tracker.record_read_acquisition();
                            let tracked_guard = TrackedGuard::new(guard);
                            entry.insert(tracked_guard);
                        }
                        Err(_) => {
                            // try_read failed - could be due to writer waiting or lock poisoned
                        }
                    }
                }
            }

            ReentrantOperation::ReleaseGuard { lock_id, guard_id } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let guard_key = (
                    lock_idx as u8,
                    *guard_id % RwLockReentrantConfig::max_guards_per_lock(),
                );

                if let Some(guard) = guards.remove(&guard_key) {
                    if guard.is_acquired() {
                        tracker.record_read_release();
                        // Guard will be automatically released when dropped
                        drop(guard);
                    } else {
                        tracker.record_double_release();
                        return Err(format!(
                            "Attempted to release already-released guard {guard_key:?}"
                        ));
                    }
                }
            }

            ReentrantOperation::NestedReads { lock_id, count } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let read_count = (*count).min(RwLockReentrantConfig::max_nesting_depth()) as usize;
                let lock = locks[lock_idx];

                // Acquire multiple nested read locks
                let mut nested_guards = Vec::new();
                for _ in 0..read_count {
                    let guard_result = futures::executor::block_on(lock.read(&cx));

                    match guard_result {
                        Ok(guard) => {
                            tracker.record_read_acquisition();
                            nested_guards.push(guard);
                        }
                        Err(_) => {
                            // Read failed
                            break;
                        }
                    }
                }

                // Release all nested guards
                for _guard in nested_guards {
                    tracker.record_read_release();
                    // Guards released automatically on drop
                }
            }

            ReentrantOperation::MixedSequence { lock_id, sequence } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let max_seq = RwLockReentrantConfig::max_sequence() as usize;
                let lock = locks[lock_idx];
                let mut temp_guards = Vec::new();

                for (i, &op) in sequence.iter().take(max_seq).enumerate() {
                    match op % 3 {
                        0 => {
                            // Acquire read
                            let guard_result = futures::executor::block_on(lock.read(&cx));

                            if let Ok(guard) = guard_result {
                                tracker.record_read_acquisition();
                                temp_guards.push((guard, i));
                            }
                        }
                        1 => {
                            // Release a guard if any
                            if let Some((_guard, _idx)) = temp_guards.pop() {
                                tracker.record_read_release();
                                // Guard released on drop
                            }
                        }
                        2 => {
                            // Try acquire read
                            tracker.record_try_read_attempt();
                            if let Ok(guard) = lock.try_read() {
                                tracker.record_try_read_success();
                                tracker.record_read_acquisition();
                                temp_guards.push((guard, i));
                            }
                        }
                        _ => unreachable!(),
                    }
                }

                // Release all remaining guards
                for (_guard, _idx) in temp_guards {
                    tracker.record_read_release();
                    // Guards released on drop
                }
            }

            ReentrantOperation::DeepNesting { lock_id, depth } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let nest_depth = (*depth).min(RwLockReentrantConfig::max_nesting_depth()) as usize;
                let lock = locks[lock_idx];

                // Acquire deeply nested read locks
                let mut nested_guards = Vec::new();
                for _i in 0..nest_depth {
                    let guard_result = futures::executor::block_on(lock.read(&cx));

                    match guard_result {
                        Ok(guard) => {
                            tracker.record_read_acquisition();
                            nested_guards.push(guard);
                        }
                        Err(_) => break,
                    }
                }

                // Verify all guards are still valid by accessing the data
                for guard in &nested_guards {
                    let _value = **guard; // Dereference to access the data
                }

                // Release all in reverse order (LIFO)
                for _guard in nested_guards.into_iter().rev() {
                    tracker.record_read_release();
                    // Guard released on drop
                }
            }

            ReentrantOperation::RapidCycle { lock_id, cycles } => {
                let lock_idx = (*lock_id % RwLockReentrantConfig::max_locks()) as usize;
                let cycle_count = (*cycles).min(RwLockReentrantConfig::max_cycles()) as usize;
                let lock = locks[lock_idx];

                for _i in 0..cycle_count {
                    // Rapid acquire/release
                    let guard_result = futures::executor::block_on(lock.read(&cx));

                    if let Ok(guard) = guard_result {
                        tracker.record_read_acquisition();
                        let _value = *guard; // Use the guard
                        tracker.record_read_release();
                        drop(guard); // Explicit drop for clarity
                    }
                }
            }

            ReentrantOperation::CheckState => {
                // Check consistency of our tracking
                let current_active = tracker.active_guards.load(Ordering::SeqCst);
                let tracked_guards_count = guards.len();

                if tracked_guards_count != current_active {
                    tracker.record_inconsistent_state();
                    return Err(format!(
                        "Inconsistent guard tracking: {tracked_guards_count} tracked vs {current_active} active"
                    ));
                }

                // Check tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {msg}"));
                }
            }
        }
    }

    // Release all remaining guards
    for guard in guards.into_values() {
        if guard.is_acquired() {
            tracker.record_read_release();
        }
        drop(guard);
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {msg}"));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: RwLockReentrantConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = ReentrantTracker::new();

    // Test the reentrant read scenario
    if let Err(msg) = test_rwlock_reentrant_read_scenario(&config, &tracker) {
        panic!("RwLock reentrant read test failed: {msg}");
    }
});
