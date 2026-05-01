//! Fuzz target: Mutex pulled from Arc clone race
//!
//! Tests race conditions between Arc<Mutex<T>> cloning operations and concurrent
//! mutex access from existing Arc clones. Focuses on reference counting races,
//! concurrent access patterns, and Arc lifecycle vs mutex state consistency.
//!
//! # Race Conditions Tested
//! 1. Arc::clone during active mutex lock operations
//! 2. Multiple Arc clones accessing mutex simultaneously
//! 3. Arc reference counting vs mutex poisoning interactions
//! 4. Arc clone vs Arc drop timing during mutex access
//! 5. Weak reference upgrade races during mutex operations
//! 6. Arc clone burst vs lock contention scenarios

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::sync::Mutex;
use std::sync::{Arc, Weak, Barrier, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Configuration for Arc<Mutex> clone race test
#[derive(Debug, Arbitrary)]
struct MutexArcCloneConfig {
    /// Number of threads that will clone Arc (1-8)
    cloner_thread_count: u8,
    /// Number of threads that will access mutex (1-12)
    accessor_thread_count: u8,
    /// Number of threads that will drop Arc clones (1-6)
    dropper_thread_count: u8,
    /// Clone patterns for each cloner thread
    clone_patterns: Vec<ClonePattern>,
    /// Access patterns for accessor threads
    access_patterns: Vec<AccessPattern>,
    /// Drop patterns for dropper threads
    drop_patterns: Vec<DropPattern>,
    /// Whether to use barrier synchronization for tight races
    use_barrier_sync: bool,
    /// Whether to test with weak references
    use_weak_refs: bool,
    /// Initial mutex value
    initial_value: u32,
}

#[derive(Debug, Arbitrary, Clone)]
enum ClonePattern {
    /// Single Arc clone
    SingleClone,
    /// Multiple rapid clones
    RapidClone { count: u8 },
    /// Clone with delay between each
    DelayedClone { clones: u8, delay_micros: u16 },
    /// Clone while holding lock
    CloneWhileLocked { work_duration: u16 },
    /// Clone burst at specific timing
    BurstClone { burst_size: u8, timing_delay: u16 },
    /// Create weak reference and upgrade
    WeakUpgrade { attempts: u8 },
}

#[derive(Debug, Arbitrary, Clone)]
enum AccessPattern {
    /// Single lock attempt
    SingleLock,
    /// Try lock without blocking
    TryLock,
    /// Lock with work inside critical section
    LockWithWork { work_items: u8, work_delay: u16 },
    /// Rapid lock/unlock cycles
    RapidLockUnlock { cycles: u8 },
    /// Lock and panic (to test poisoning)
    LockAndPanic { should_panic: bool },
    /// Long-held lock
    LongHeldLock { hold_duration: u16 },
    /// Lock with nested Arc clone inside
    LockThenClone { clone_count: u8 },
}

#[derive(Debug, Arbitrary, Clone)]
enum DropPattern {
    /// Drop Arc immediately
    DropImmediate,
    /// Drop after delay
    DropDelayed { delay_micros: u16 },
    /// Drop while holding lock
    DropWhileLocked,
    /// Drop all clones simultaneously
    DropAll,
    /// Selective drop pattern
    DropSelective { keep_ratio: u8 },
}

impl MutexArcCloneConfig {
    fn normalize(&mut self) {
        // Limit thread counts
        self.cloner_thread_count = (self.cloner_thread_count % 8).max(1);
        self.accessor_thread_count = (self.accessor_thread_count % 12).max(1);
        self.dropper_thread_count = (self.dropper_thread_count % 6).max(1);

        // Ensure we have enough patterns
        self.clone_patterns.resize(self.cloner_thread_count as usize, ClonePattern::SingleClone);
        self.access_patterns.resize(self.accessor_thread_count as usize, AccessPattern::SingleLock);
        self.drop_patterns.resize(self.dropper_thread_count as usize, DropPattern::DropImmediate);

        // Normalize pattern parameters
        for pattern in &mut self.clone_patterns {
            match pattern {
                ClonePattern::RapidClone { count } => {
                    *count = (*count % 10).max(1);
                },
                ClonePattern::DelayedClone { clones, delay_micros } => {
                    *clones = (*clones % 8).max(1);
                    *delay_micros = *delay_micros % 200; // Max 0.2ms
                },
                ClonePattern::CloneWhileLocked { work_duration } => {
                    *work_duration = *work_duration % 100; // Max 0.1ms
                },
                ClonePattern::BurstClone { burst_size, timing_delay } => {
                    *burst_size = (*burst_size % 5).max(1);
                    *timing_delay = *timing_delay % 300;
                },
                ClonePattern::WeakUpgrade { attempts } => {
                    *attempts = (*attempts % 15).max(1);
                },
                _ => {},
            }
        }

        for pattern in &mut self.access_patterns {
            match pattern {
                AccessPattern::LockWithWork { work_items, work_delay } => {
                    *work_items = (*work_items % 20).max(1);
                    *work_delay = *work_delay % 50; // Max 0.05ms per work item
                },
                AccessPattern::RapidLockUnlock { cycles } => {
                    *cycles = (*cycles % 25).max(1);
                },
                AccessPattern::LongHeldLock { hold_duration } => {
                    *hold_duration = *hold_duration % 500; // Max 0.5ms
                },
                AccessPattern::LockThenClone { clone_count } => {
                    *clone_count = (*clone_count % 5).max(1);
                },
                _ => {},
            }
        }

        for pattern in &mut self.drop_patterns {
            match pattern {
                DropPattern::DropDelayed { delay_micros } => {
                    *delay_micros = *delay_micros % 400; // Max 0.4ms
                },
                DropPattern::DropSelective { keep_ratio } => {
                    *keep_ratio = (*keep_ratio % 80).max(10); // Keep 10-80%
                },
                _ => {},
            }
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    cloner_threads_started: AtomicUsize,
    accessor_threads_started: AtomicUsize,
    dropper_threads_started: AtomicUsize,
    arc_clones_created: AtomicUsize,
    weak_refs_created: AtomicUsize,
    weak_upgrades_attempted: AtomicUsize,
    weak_upgrades_succeeded: AtomicUsize,
    lock_attempts: AtomicUsize,
    lock_successes: AtomicUsize,
    try_lock_attempts: AtomicUsize,
    try_lock_successes: AtomicUsize,
    panics_occurred: AtomicUsize,
    poison_detected: AtomicUsize,
    arc_drops_completed: AtomicUsize,
    concurrent_clones_peak: AtomicUsize,
    nested_operations: AtomicUsize,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config = match MutexArcCloneConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };
    config.normalize();

    let mutex: Arc<Mutex<u32>> = Arc::new(Mutex::new(config.initial_value));
    let results = Arc::new(TestResults::default());

    // Shared storage for Arc clones and weak references
    let arc_clones: Arc<parking_lot::Mutex<Vec<Arc<Mutex<u32>>>>> =
        Arc::new(parking_lot::Mutex::new(vec![mutex.clone()]));
    let weak_refs: Arc<parking_lot::Mutex<Vec<Weak<Mutex<u32>>>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));

    let total_threads = config.cloner_thread_count + config.accessor_thread_count + config.dropper_thread_count;
    let barrier = if config.use_barrier_sync {
        Some(Arc::new(Barrier::new(total_threads as usize)))
    } else {
        None
    };

    let mut handles = Vec::new();

    // Spawn cloner threads - these create new Arc clones
    for i in 0..config.cloner_thread_count {
        let arc_clones = Arc::clone(&arc_clones);
        let weak_refs = Arc::clone(&weak_refs);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.clone_patterns[i as usize].clone();
        let use_weak_refs = config.use_weak_refs;

        let handle = thread::spawn(move || {
            results.cloner_threads_started.fetch_add(1, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            match pattern {
                ClonePattern::SingleClone => {
                    let source_arc = {
                        let clones = arc_clones.lock();
                        if let Some(arc) = clones.first() {
                            Some(arc.clone())
                        } else {
                            None
                        }
                    };

                    if let Some(arc) = source_arc {
                        let new_clone = arc.clone();
                        arc_clones.lock().push(new_clone);
                        results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                    }
                },

                ClonePattern::RapidClone { count } => {
                    for _ in 0..count {
                        let source_arc = {
                            let clones = arc_clones.lock();
                            if let Some(arc) = clones.first() {
                                Some(arc.clone())
                            } else {
                                None
                            }
                        };

                        if let Some(arc) = source_arc {
                            let new_clone = arc.clone();
                            arc_clones.lock().push(new_clone);
                            results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                },

                ClonePattern::DelayedClone { clones, delay_micros } => {
                    for _ in 0..clones {
                        let source_arc = {
                            let clones = arc_clones.lock();
                            if let Some(arc) = clones.first() {
                                Some(arc.clone())
                            } else {
                                None
                            }
                        };

                        if let Some(arc) = source_arc {
                            let new_clone = arc.clone();
                            arc_clones.lock().push(new_clone);
                            results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                        }

                        if delay_micros > 0 {
                            thread::sleep(Duration::from_micros(delay_micros as u64));
                        }
                    }
                },

                ClonePattern::CloneWhileLocked { work_duration } => {
                    let source_arc = {
                        let clones = arc_clones.lock();
                        if let Some(arc) = clones.first() {
                            Some(arc.clone())
                        } else {
                            None
                        }
                    };

                    if let Some(arc) = source_arc {
                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                // Clone while holding lock
                                let new_clone = arc.clone();
                                arc_clones.lock().push(new_clone);
                                results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                                results.nested_operations.fetch_add(1, Ordering::SeqCst);

                                // Do some work while holding lock
                                if work_duration > 0 {
                                    thread::sleep(Duration::from_micros(work_duration as u64));
                                }
                                *guard += 1;
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                ClonePattern::BurstClone { burst_size, timing_delay } => {
                    if timing_delay > 0 {
                        thread::sleep(Duration::from_micros(timing_delay as u64));
                    }

                    // Create burst of clones rapidly
                    for _ in 0..burst_size {
                        let source_arc = {
                            let clones = arc_clones.lock();
                            if let Some(arc) = clones.first() {
                                Some(arc.clone())
                            } else {
                                None
                            }
                        };

                        if let Some(arc) = source_arc {
                            let new_clone = arc.clone();

                            // Update peak concurrent clones
                            let current_count = arc_clones.lock().len();
                            results.concurrent_clones_peak.fetch_max(current_count, Ordering::SeqCst);

                            arc_clones.lock().push(new_clone);
                            results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                },

                ClonePattern::WeakUpgrade { attempts } => {
                    if !use_weak_refs {
                        return; // Skip if weak refs disabled
                    }

                    // Create weak reference first
                    let weak = {
                        let clones = arc_clones.lock();
                        if let Some(arc) = clones.first() {
                            Some(Arc::downgrade(arc))
                        } else {
                            None
                        }
                    };

                    if let Some(weak_ref) = weak {
                        weak_refs.lock().push(weak_ref.clone());
                        results.weak_refs_created.fetch_add(1, Ordering::SeqCst);

                        // Attempt upgrades
                        for _ in 0..attempts {
                            results.weak_upgrades_attempted.fetch_add(1, Ordering::SeqCst);

                            if let Some(upgraded) = weak_ref.upgrade() {
                                results.weak_upgrades_succeeded.fetch_add(1, Ordering::SeqCst);
                                arc_clones.lock().push(upgraded);
                                results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                            }

                            thread::sleep(Duration::from_micros(10)); // Brief delay between upgrade attempts
                        }
                    }
                },
            }
        });

        handles.push(handle);
    }

    // Spawn accessor threads - these access the mutex through various Arc clones
    for i in 0..config.accessor_thread_count {
        let arc_clones = Arc::clone(&arc_clones);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.access_patterns[i as usize].clone();

        let handle = thread::spawn(move || {
            results.accessor_threads_started.fetch_add(1, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            match pattern {
                AccessPattern::SingleLock => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);
                                *guard += 1;
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                AccessPattern::TryLock => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.try_lock_attempts.fetch_add(1, Ordering::SeqCst);

                        match arc.try_lock() {
                            Ok(mut guard) => {
                                results.try_lock_successes.fetch_add(1, Ordering::SeqCst);
                                *guard += 1;
                            },
                            Err(asupersync::sync::TryLockError::Locked) => {
                                // Mutex is locked by another thread
                            },
                            Err(asupersync::sync::TryLockError::Poisoned) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                AccessPattern::LockWithWork { work_items, work_delay } => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);

                                // Do work while holding lock
                                for _ in 0..work_items {
                                    *guard = guard.wrapping_add(1);
                                    if work_delay > 0 {
                                        thread::sleep(Duration::from_micros(work_delay as u64));
                                    }
                                }
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                AccessPattern::RapidLockUnlock { cycles } => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        for _ in 0..cycles {
                            results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                            let cx = asupersync::Cx::for_testing();
                            match futures::executor::block_on(arc.lock(&cx)) {
                                Ok(mut guard) => {
                                    results.lock_successes.fetch_add(1, Ordering::SeqCst);
                                    *guard = guard.wrapping_add(1);
                                    // Lock is dropped automatically
                                },
                                Err(_) => {
                                    results.poison_detected.fetch_add(1, Ordering::SeqCst);
                                    break; // Stop on poison
                                },
                            }
                        }
                    }
                },

                AccessPattern::LockAndPanic { should_panic } => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        let panic_result = catch_unwind(AssertUnwindSafe(|| {
                            let cx = asupersync::Cx::for_testing();
                            let mut guard = futures::executor::block_on(arc.lock(&cx)).expect("Lock should succeed");
                            *guard += 1;

                            if should_panic {
                                panic!("Intentional panic while holding mutex lock");
                            }
                        }));

                        match panic_result {
                            Ok(()) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);
                            },
                            Err(_) => {
                                results.panics_occurred.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                AccessPattern::LongHeldLock { hold_duration } => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);

                                if hold_duration > 0 {
                                    thread::sleep(Duration::from_micros(hold_duration as u64));
                                }

                                *guard += 1;
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                AccessPattern::LockThenClone { clone_count } => {
                    let arc_opt = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_opt {
                        results.lock_attempts.fetch_add(1, Ordering::SeqCst);

                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                results.lock_successes.fetch_add(1, Ordering::SeqCst);

                                // Clone Arc while holding lock
                                for _ in 0..clone_count {
                                    let new_clone = arc.clone();
                                    arc_clones.lock().push(new_clone);
                                    results.arc_clones_created.fetch_add(1, Ordering::SeqCst);
                                    results.nested_operations.fetch_add(1, Ordering::SeqCst);
                                }

                                *guard += 1;
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },
            }
        });

        handles.push(handle);
    }

    // Spawn dropper threads - these drop Arc clones
    for i in 0..config.dropper_thread_count {
        let arc_clones = Arc::clone(&arc_clones);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.drop_patterns[i as usize].clone();

        let handle = thread::spawn(move || {
            results.dropper_threads_started.fetch_add(1, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Give other threads time to create Arc clones
            thread::sleep(Duration::from_micros(100));

            match pattern {
                DropPattern::DropImmediate => {
                    let to_drop = {
                        let mut clones = arc_clones.lock();
                        if clones.len() > 1 {
                            clones.pop()
                        } else {
                            None
                        }
                    };

                    if to_drop.is_some() {
                        results.arc_drops_completed.fetch_add(1, Ordering::SeqCst);
                    }
                },

                DropPattern::DropDelayed { delay_micros } => {
                    if delay_micros > 0 {
                        thread::sleep(Duration::from_micros(delay_micros as u64));
                    }

                    let to_drop = {
                        let mut clones = arc_clones.lock();
                        if clones.len() > 1 {
                            clones.pop()
                        } else {
                            None
                        }
                    };

                    if to_drop.is_some() {
                        results.arc_drops_completed.fetch_add(1, Ordering::SeqCst);
                    }
                },

                DropPattern::DropWhileLocked => {
                    let arc_to_use = {
                        let clones = arc_clones.lock();
                        clones.get(i as usize % clones.len().max(1)).cloned()
                    };

                    if let Some(arc) = arc_to_use {
                        let cx = asupersync::Cx::for_testing();
                        match futures::executor::block_on(arc.lock(&cx)) {
                            Ok(mut guard) => {
                                // Drop another Arc while holding lock on this one
                                let to_drop = {
                                    let mut clones = arc_clones.lock();
                                    if clones.len() > 1 {
                                        clones.pop()
                                    } else {
                                        None
                                    }
                                };

                                if to_drop.is_some() {
                                    results.arc_drops_completed.fetch_add(1, Ordering::SeqCst);
                                    results.nested_operations.fetch_add(1, Ordering::SeqCst);
                                }

                                *guard += 1;
                            },
                            Err(_) => {
                                results.poison_detected.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                DropPattern::DropAll => {
                    let mut dropped_count = 0;
                    let to_drop = {
                        let mut clones = arc_clones.lock();
                        let to_drop = clones.split_off(1); // Keep at least one
                        dropped_count = to_drop.len();
                        to_drop
                    };

                    drop(to_drop);
                    results.arc_drops_completed.fetch_add(dropped_count, Ordering::SeqCst);
                },

                DropPattern::DropSelective { keep_ratio } => {
                    let mut dropped_count = 0;
                    {
                        let mut clones = arc_clones.lock();
                        let target_keep = (clones.len() * keep_ratio as usize / 100).max(1);

                        while clones.len() > target_keep {
                            clones.pop();
                            dropped_count += 1;
                        }
                    }

                    results.arc_drops_completed.fetch_add(dropped_count, Ordering::SeqCst);
                },
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join(); // Ignore panics - they're expected in some patterns
    }

    // Verify results and race condition consistency
    let cloner_threads_started = results.cloner_threads_started.load(Ordering::SeqCst);
    let accessor_threads_started = results.accessor_threads_started.load(Ordering::SeqCst);
    let dropper_threads_started = results.dropper_threads_started.load(Ordering::SeqCst);
    let arc_clones_created = results.arc_clones_created.load(Ordering::SeqCst);
    let weak_refs_created = results.weak_refs_created.load(Ordering::SeqCst);
    let weak_upgrades_attempted = results.weak_upgrades_attempted.load(Ordering::SeqCst);
    let weak_upgrades_succeeded = results.weak_upgrades_succeeded.load(Ordering::SeqCst);
    let lock_attempts = results.lock_attempts.load(Ordering::SeqCst);
    let lock_successes = results.lock_successes.load(Ordering::SeqCst);
    let try_lock_attempts = results.try_lock_attempts.load(Ordering::SeqCst);
    let try_lock_successes = results.try_lock_successes.load(Ordering::SeqCst);
    let panics_occurred = results.panics_occurred.load(Ordering::SeqCst);
    let poison_detected = results.poison_detected.load(Ordering::SeqCst);
    let arc_drops_completed = results.arc_drops_completed.load(Ordering::SeqCst);
    let concurrent_clones_peak = results.concurrent_clones_peak.load(Ordering::SeqCst);
    let nested_operations = results.nested_operations.load(Ordering::SeqCst);

    // Basic accounting checks
    assert_eq!(cloner_threads_started, config.cloner_thread_count as usize,
        "All cloner threads should start");
    assert_eq!(accessor_threads_started, config.accessor_thread_count as usize,
        "All accessor threads should start");
    assert_eq!(dropper_threads_started, config.dropper_thread_count as usize,
        "All dropper threads should start");

    // Lock attempt accounting
    assert!(lock_successes <= lock_attempts,
        "Lock successes should not exceed attempts");
    assert!(try_lock_successes <= try_lock_attempts,
        "Try-lock successes should not exceed attempts");

    // Weak reference consistency
    if config.use_weak_refs {
        assert!(weak_upgrades_succeeded <= weak_upgrades_attempted,
            "Weak upgrades succeeded should not exceed attempts");
    } else {
        assert_eq!(weak_refs_created, 0,
            "No weak references should be created when disabled");
    }

    // Poison detection consistency
    if panics_occurred > 0 {
        // If panics occurred, some poison detection is expected (but not guaranteed due to timing)
    }

    // Arc clone consistency
    assert!(arc_clones_created >= cloner_threads_started,
        "Should have at least as many clones as cloner threads (each does minimum 1)");

    // Nested operations tracking
    if nested_operations > 0 {
        // Nested operations occurred - this is fine and expected in some patterns
    }

    // Peak concurrent clones should be reasonable
    assert!(concurrent_clones_peak <= arc_clones_created + 1, // +1 for initial Arc
        "Peak concurrent clones should not exceed total created + initial");

    // Race condition verification: The key property is that Arc clone/drop operations
    // should not interfere with mutex semantics, regardless of timing

    // Verify final state: at least one Arc should remain
    let final_arc_count = {
        arc_clones.lock().len()
    };
    assert!(final_arc_count >= 1,
        "At least one Arc should remain after all operations");

    // The fact that we reached this point without deadlocks, data races, or memory
    // safety violations indicates the Arc<Mutex> clone race behavior is working correctly
});