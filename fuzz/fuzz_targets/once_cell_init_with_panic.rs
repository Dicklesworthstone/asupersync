//! Fuzz OnceCell init-with-panic scenarios.
//!
//! Tests arbitrary panic-during-init patterns to ensure panic recovery behavior
//! is correct. Validates that after a panic during initialization, the cell
//! stays uninitialized and subsequent retry attempts can succeed.
//!
//! Critical invariants:
//! - Panic during init leaves cell uninitialized (not stuck in INITIALIZING)
//! - Cell can be successfully initialized after panic recovery
//! - Multiple panic/retry cycles work correctly
//! - Concurrent panic recovery doesn't cause deadlocks or state corruption

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::OnceCell;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Arbitrary)]
struct OnceCellPanicConfig {
    /// Operations to perform
    operations: Vec<PanicOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum PanicOperation {
    /// Initialize with a function that panics at specific step
    InitWithPanic { cell_id: u8, panic_at_step: u8 },
    /// Initialize with successful function
    InitSuccessfully { cell_id: u8, value: i32 },
    /// Check if cell is initialized
    CheckInitialized { cell_id: u8 },
    /// Try multiple panic attempts then succeed
    PanicRetrySequence { cell_id: u8, panic_count: u8, final_value: i32 },
    /// Concurrent panic initialization attempts
    ConcurrentPanicInit { cell_id: u8, thread_count: u8 },
    /// Mixed panic/success sequence
    MixedSequence { cell_id: u8, sequence: Vec<u8> },
    /// Check state consistency
    CheckState,
}

impl OnceCellPanicConfig {
    fn max_cells() -> u8 {
        8 // Limit total cells for testing
    }

    fn max_operations() -> u8 {
        30 // Limit test duration
    }

    fn max_panic_retries() -> u8 {
        5 // Limit retry attempts
    }

    fn max_concurrent_threads() -> u8 {
        6 // Limit concurrent operations
    }

    fn max_sequence() -> u8 {
        8 // Limit sequence operations
    }
}

/// Tracks panic behavior to detect invariant violations
#[derive(Debug)]
struct PanicTracker {
    init_attempts: AtomicUsize,
    panic_count: AtomicUsize,
    successful_inits: AtomicUsize,
    panic_recovery_count: AtomicUsize,
    state_corruption_detected: AtomicUsize,
    stuck_in_initializing: AtomicUsize,
    deadlock_detected: AtomicUsize,
}

impl PanicTracker {
    fn new() -> Self {
        Self {
            init_attempts: AtomicUsize::new(0),
            panic_count: AtomicUsize::new(0),
            successful_inits: AtomicUsize::new(0),
            panic_recovery_count: AtomicUsize::new(0),
            state_corruption_detected: AtomicUsize::new(0),
            stuck_in_initializing: AtomicUsize::new(0),
            deadlock_detected: AtomicUsize::new(0),
        }
    }

    fn record_init_attempt(&self) {
        self.init_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_panic(&self) {
        self.panic_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_successful_init(&self) {
        self.successful_inits.fetch_add(1, Ordering::SeqCst);
    }

    fn record_panic_recovery(&self) {
        self.panic_recovery_count.fetch_add(1, Ordering::SeqCst);
    }

    fn record_state_corruption(&self) {
        self.state_corruption_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn record_stuck_in_initializing(&self) {
        self.stuck_in_initializing.fetch_add(1, Ordering::SeqCst);
    }

    fn record_deadlock(&self) {
        self.deadlock_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let attempts = self.init_attempts.load(Ordering::SeqCst);
        let panics = self.panic_count.load(Ordering::SeqCst);
        let successes = self.successful_inits.load(Ordering::SeqCst);
        let recoveries = self.panic_recovery_count.load(Ordering::SeqCst);
        let corruptions = self.state_corruption_detected.load(Ordering::SeqCst);
        let stuck = self.stuck_in_initializing.load(Ordering::SeqCst);
        let deadlocks = self.deadlock_detected.load(Ordering::SeqCst);

        // Core invariants: no corruptions, no stuck states, no deadlocks
        if corruptions > 0 {
            return Err(format!("Detected {} state corruptions", corruptions));
        }

        if stuck > 0 {
            return Err(format!("Detected {} cells stuck in INITIALIZING state", stuck));
        }

        if deadlocks > 0 {
            return Err(format!("Detected {} deadlock situations", deadlocks));
        }

        // Panic recovery should work
        if panics > 0 && recoveries == 0 {
            return Err(format!("Had {} panics but no recovery detected", panics));
        }

        // Sanity checks
        if attempts < panics + successes {
            return Err(format!(
                "More outcomes ({} panics + {} successes) than attempts ({})",
                panics, successes, attempts
            ));
        }

        if attempts > 1000 {
            return Err(format!("Excessive init attempts: {}", attempts));
        }

        Ok(())
    }
}

/// A function that panics at a specific step
struct PanicAt {
    panic_step: u8,
    current_step: AtomicUsize,
}

impl PanicAt {
    fn new(panic_step: u8) -> Self {
        Self {
            panic_step,
            current_step: AtomicUsize::new(0),
        }
    }

    fn step(&self) -> i32 {
        let step = self.current_step.fetch_add(1, Ordering::SeqCst);
        if step >= self.panic_step as usize {
            panic!("Intentional panic at step {}", step);
        }
        42 // Return a value if we don't panic
    }
}

/// Test OnceCell panic recovery scenarios
fn test_once_cell_panic_scenario(
    config: &OnceCellPanicConfig,
    tracker: &PanicTracker,
) -> Result<(), String> {
    let mut cells: HashMap<u8, Arc<OnceCell<i32>>> = HashMap::new();

    let max_ops = config.max_operations.min(OnceCellPanicConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            PanicOperation::InitWithPanic { cell_id, panic_at_step } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();

                let cell = cells.entry(id)
                    .or_insert_with(|| Arc::new(OnceCell::new()));

                if !cell.is_initialized() {
                    tracker.record_init_attempt();
                    let panic_at = PanicAt::new(*panic_at_step % 10);

                    let panic_result = catch_unwind(AssertUnwindSafe(|| {
                        cell.get_or_init_blocking(|| panic_at.step())
                    }));

                    match panic_result {
                        Ok(_) => {
                            // Initialization succeeded (panic_step was too high)
                            tracker.record_successful_init();
                        }
                        Err(_) => {
                            // Panic occurred as expected
                            tracker.record_panic();

                            // Critical invariant: cell should be uninitialized after panic
                            if cell.is_initialized() {
                                tracker.record_state_corruption();
                                return Err(format!(
                                    "Cell {} is initialized after panic - state corruption",
                                    id
                                ));
                            }

                            tracker.record_panic_recovery();
                        }
                    }
                } else {
                    // Cell already initialized - this is ok, no-op
                }
            }

            PanicOperation::InitSuccessfully { cell_id, value } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();

                let cell = cells.entry(id)
                    .or_insert_with(|| Arc::new(OnceCell::new()));

                if !cell.is_initialized() {
                    tracker.record_init_attempt();
                    let result = cell.get_or_init_blocking(|| *value);

                    if *result == *value {
                        tracker.record_successful_init();
                    } else {
                        tracker.record_state_corruption();
                        return Err(format!(
                            "Cell {} initialized with wrong value: expected {}, got {}",
                            id, value, result
                        ));
                    }
                }
            }

            PanicOperation::CheckInitialized { cell_id } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();

                if let Some(cell) = cells.get(&id) {
                    let initialized = cell.is_initialized();
                    if let Some(value) = cell.get() {
                        // If get() returns Some, is_initialized() must be true
                        if !initialized {
                            tracker.record_state_corruption();
                            return Err(format!(
                                "Cell {} get() returns value but is_initialized() is false",
                                id
                            ));
                        }
                    }
                }
            }

            PanicOperation::PanicRetrySequence { cell_id, panic_count, final_value } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();
                let retry_count = (*panic_count).min(OnceCellPanicConfig::max_panic_retries()) as usize;

                let cell = cells.entry(id)
                    .or_insert_with(|| Arc::new(OnceCell::new()));

                if cell.is_initialized() {
                    continue; // Already initialized, skip
                }

                // First, try several times with panics
                for i in 0..retry_count {
                    if cell.is_initialized() {
                        break;
                    }

                    tracker.record_init_attempt();
                    let panic_at = PanicAt::new(1); // Always panic quickly

                    let panic_result = catch_unwind(AssertUnwindSafe(|| {
                        cell.get_or_init_blocking(|| panic_at.step())
                    }));

                    match panic_result {
                        Ok(_) => {
                            // Unexpected success
                            tracker.record_successful_init();
                            break;
                        }
                        Err(_) => {
                            tracker.record_panic();

                            // Verify cell is still uninitialized
                            if cell.is_initialized() {
                                tracker.record_state_corruption();
                                return Err(format!(
                                    "Cell {} corrupted after panic retry {}: still initialized",
                                    id, i
                                ));
                            }

                            tracker.record_panic_recovery();
                        }
                    }
                }

                // Finally, succeed with the real value
                if !cell.is_initialized() {
                    tracker.record_init_attempt();
                    let result = cell.get_or_init_blocking(|| *final_value);

                    if *result == *final_value {
                        tracker.record_successful_init();
                    } else {
                        tracker.record_state_corruption();
                        return Err(format!(
                            "Cell {} final init failed: expected {}, got {}",
                            id, final_value, result
                        ));
                    }
                }
            }

            PanicOperation::ConcurrentPanicInit { cell_id, thread_count } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();
                let num_threads = (*thread_count).min(OnceCellPanicConfig::max_concurrent_threads()).max(1) as usize;

                let cell = cells.entry(id)
                    .or_insert_with(|| Arc::new(OnceCell::new()));

                if cell.is_initialized() {
                    continue; // Already initialized, skip
                }

                // Launch concurrent threads that may panic
                let mut handles = Vec::new();
                let tracker_arc = Arc::new(PanicTracker::new());

                for thread_idx in 0..num_threads {
                    let cell_clone = cell.clone();
                    let tracker_clone = tracker_arc.clone();
                    let panic_step = (thread_idx % 3) as u8; // Vary panic timing

                    let handle = std::thread::spawn(move || {
                        tracker_clone.record_init_attempt();
                        let panic_at = PanicAt::new(panic_step);

                        let result = catch_unwind(AssertUnwindSafe(|| {
                            cell_clone.get_or_init_blocking(|| panic_at.step())
                        }));

                        match result {
                            Ok(_) => {
                                tracker_clone.record_successful_init();
                                true // Success
                            }
                            Err(_) => {
                                tracker_clone.record_panic();
                                tracker_clone.record_panic_recovery();
                                false // Panic
                            }
                        }
                    });

                    handles.push(handle);
                }

                // Wait for all threads and check results
                let mut any_succeeded = false;
                for handle in handles {
                    match handle.join() {
                        Ok(success) => {
                            if success {
                                any_succeeded = true;
                            }
                        }
                        Err(_) => {
                            tracker.record_deadlock();
                            return Err(format!("Thread panicked in concurrent test for cell {}", id));
                        }
                    }
                }

                // Verify final state
                let is_init = cell.is_initialized();
                if any_succeeded && !is_init {
                    tracker.record_state_corruption();
                    return Err(format!(
                        "Cell {} should be initialized after concurrent success",
                        id
                    ));
                }

                // Aggregate concurrent tracker stats
                let concurrent_attempts = tracker_arc.init_attempts.load(Ordering::SeqCst);
                let concurrent_panics = tracker_arc.panic_count.load(Ordering::SeqCst);
                let concurrent_successes = tracker_arc.successful_inits.load(Ordering::SeqCst);
                let concurrent_recoveries = tracker_arc.panic_recovery_count.load(Ordering::SeqCst);

                tracker.init_attempts.fetch_add(concurrent_attempts, Ordering::SeqCst);
                tracker.panic_count.fetch_add(concurrent_panics, Ordering::SeqCst);
                tracker.successful_inits.fetch_add(concurrent_successes, Ordering::SeqCst);
                tracker.panic_recovery_count.fetch_add(concurrent_recoveries, Ordering::SeqCst);
            }

            PanicOperation::MixedSequence { cell_id, sequence } => {
                let id = *cell_id % OnceCellPanicConfig::max_cells();
                let max_seq = OnceCellPanicConfig::max_sequence() as usize;

                let cell = cells.entry(id)
                    .or_insert_with(|| Arc::new(OnceCell::new()));

                for (i, &op) in sequence.iter().take(max_seq).enumerate() {
                    if cell.is_initialized() {
                        break; // Already initialized, remaining ops are no-ops
                    }

                    match op % 3 {
                        0 => {
                            // Panic attempt
                            tracker.record_init_attempt();
                            let panic_at = PanicAt::new(1);

                            let result = catch_unwind(AssertUnwindSafe(|| {
                                cell.get_or_init_blocking(|| panic_at.step())
                            }));

                            match result {
                                Ok(_) => {
                                    tracker.record_successful_init();
                                }
                                Err(_) => {
                                    tracker.record_panic();
                                    if cell.is_initialized() {
                                        tracker.record_state_corruption();
                                        return Err(format!(
                                            "Cell {} corrupted in mixed sequence step {}",
                                            id, i
                                        ));
                                    }
                                    tracker.record_panic_recovery();
                                }
                            }
                        }
                        1 => {
                            // Success attempt
                            tracker.record_init_attempt();
                            let value = (i as i32) + 100;
                            let result = cell.get_or_init_blocking(|| value);

                            if *result == value {
                                tracker.record_successful_init();
                            }
                        }
                        2 => {
                            // Check state
                            if cell.get().is_some() != cell.is_initialized() {
                                tracker.record_state_corruption();
                                return Err(format!(
                                    "Cell {} state inconsistency in mixed sequence step {}",
                                    id, i
                                ));
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }

            PanicOperation::CheckState => {
                // Verify consistency across all cells
                for (&id, cell) in cells.iter() {
                    let is_init = cell.is_initialized();
                    let has_value = cell.get().is_some();

                    if is_init != has_value {
                        tracker.record_state_corruption();
                        return Err(format!(
                            "Cell {} inconsistent: is_initialized={} but get().is_some()={}",
                            id, is_init, has_value
                        ));
                    }
                }

                // Check tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
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
    let config: OnceCellPanicConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = PanicTracker::new();

    // Test the panic recovery scenario
    if let Err(msg) = test_once_cell_panic_scenario(&config, &tracker) {
        panic!("OnceCell panic recovery test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        let tracker2 = PanicTracker::new();
        let config2 = config.clone();

        let handle = std::thread::spawn(move || {
            test_once_cell_panic_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent OnceCell panic test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we performed meaningful operations
    let total_attempts = tracker.init_attempts.load(Ordering::SeqCst);
    let total_panics = tracker.panic_count.load(Ordering::SeqCst);

    if total_attempts == 0 && !config.operations.is_empty() {
        panic!("No meaningful initialization operations were performed during the test");
    }
});