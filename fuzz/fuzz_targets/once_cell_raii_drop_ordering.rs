//! Fuzz OnceCell RAII drop ordering semantics.
//!
//! Tests arbitrary set+drop+set sequences to ensure drop runs before re-set
//! and validates no double-free or use-after-drop issues. Tests that contained
//! values are properly destructed when OnceCell is dropped.
//!
//! Critical invariants:
//! - Drop runs before re-initialization
//! - No double-free of contained values
//! - No use-after-drop of contained values
//! - Proper RAII semantics for complex drop sequences

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::once_cell::OnceCell;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

/// Test value that tracks its lifecycle for RAII validation
#[derive(Debug, Clone)]
struct TrackedValue {
    id: usize,
    counter: Arc<AtomicUsize>,
    drop_counter: Arc<AtomicUsize>,
}

impl TrackedValue {
    fn new(id: usize, counter: Arc<AtomicUsize>, drop_counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            counter,
            drop_counter,
        }
    }
}

impl Drop for TrackedValue {
    fn drop(&mut self) {
        self.drop_counter.fetch_add(1, Ordering::SeqCst);
        // Don't decrement creation counter - it tracks total created, not current active
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct RaiiConfig {
    /// Sequences of operations to perform
    operations: Vec<RaiiOperation>,
    /// Values to use for initialization
    init_values: Vec<u32>,
    /// Delay patterns between operations (microseconds)
    operation_delays: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
enum RaiiOperation {
    /// Create new OnceCell and set value
    CreateAndSet { value_index: u8 },
    /// Try to set value in existing cell
    TrySet { value_index: u8 },
    /// Drop the current OnceCell
    Drop,
    /// Read value from OnceCell if it exists
    Get,
    /// Check if OnceCell is initialized
    CheckInitialized,
    /// Small delay
    Delay { micros: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
struct RaiiSequence {
    /// Test configuration
    config: RaiiConfig,
    /// Maximum operations to perform
    max_operations: u8,
    /// Whether to test concurrent access
    test_concurrency: bool,
}

impl RaiiSequence {
    fn max_operations() -> u8 {
        30 // Keep test duration reasonable
    }

    fn max_init_values() -> usize {
        20 // Reasonable number of different values
    }
}

/// Test execution context
#[derive(Debug)]
struct RaiiTracker {
    creation_counter: Arc<AtomicUsize>,
    drop_counter: Arc<AtomicUsize>,
    active_cells: Vec<Option<OnceCell<TrackedValue>>>,
    current_cell_index: usize,
}

impl RaiiTracker {
    fn new() -> Self {
        Self {
            creation_counter: Arc::new(AtomicUsize::new(0)),
            drop_counter: Arc::new(AtomicUsize::new(0)),
            active_cells: vec![None; 5], // Pool of cells for testing
            current_cell_index: 0,
        }
    }

    fn create_tracked_value(&self, id: usize) -> TrackedValue {
        TrackedValue::new(
            id,
            Arc::clone(&self.creation_counter),
            Arc::clone(&self.drop_counter),
        )
    }

    fn check_invariants(&self) -> Result<(), String> {
        let created = self.creation_counter.load(Ordering::SeqCst);
        let dropped = self.drop_counter.load(Ordering::SeqCst);

        // Basic invariant: dropped count should never exceed created count
        if dropped > created {
            return Err(format!(
                "Drop count {} exceeds creation count {} - possible double-free",
                dropped, created
            ));
        }

        // Check that active values count matches expected
        let expected_active = created - dropped;
        let mut actual_active = 0;

        for cell_opt in &self.active_cells {
            if let Some(cell) = cell_opt {
                if cell.is_initialized() {
                    if let Some(_value) = cell.get() {
                        actual_active += 1;
                    }
                }
            }
        }

        if actual_active != expected_active {
            return Err(format!(
                "Active value count mismatch: expected {} but found {} active values",
                expected_active, actual_active
            ));
        }

        Ok(())
    }

    fn get_current_cell_mut(&mut self) -> &mut Option<OnceCell<TrackedValue>> {
        &mut self.active_cells[self.current_cell_index]
    }

    fn advance_cell_index(&mut self) {
        self.current_cell_index = (self.current_cell_index + 1) % self.active_cells.len();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: RaiiSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.operations.is_empty()
        || sequence.config.init_values.is_empty()
        || sequence.config.init_values.len() > RaiiSequence::max_init_values()
    {
        return;
    }

    let max_ops = sequence.max_operations.min(RaiiSequence::max_operations()) as usize;

    // Create tracker for RAII validation
    let mut tracker = RaiiTracker::new();

    // Execute operation sequence
    for (i, op) in sequence.config.operations.iter().take(max_ops).enumerate() {
        // Check invariants before each operation
        if let Err(msg) = tracker.check_invariants() {
            panic!("RAII invariant violation at operation {}: {}", i, msg);
        }

        // Apply delay if specified
        if let Some(&delay) = sequence.config.operation_delays.get(i) {
            if delay > 0 {
                thread::sleep(Duration::from_micros(delay as u64));
            }
        }

        match op {
            RaiiOperation::CreateAndSet { value_index } => {
                let value_id = sequence
                    .config
                    .init_values
                    .get(*value_index as usize % sequence.config.init_values.len())
                    .copied()
                    .unwrap_or(42) as usize;

                // Create new OnceCell and tracked value
                let new_cell = OnceCell::new();
                let tracked_value = tracker.create_tracked_value(value_id);

                // Set the value
                match new_cell.set(tracked_value) {
                    Ok(()) => {
                        // Replace current cell (dropping old one if exists)
                        let old_cell =
                            std::mem::replace(tracker.get_current_cell_mut(), Some(new_cell));
                        drop(old_cell); // Explicit drop to ensure RAII ordering

                        tracker.advance_cell_index();
                    }
                    Err(_tracked_value) => {
                        // Value was returned, so creation and drop should cancel out
                        // The tracked value will be dropped here automatically
                    }
                }
            }

            RaiiOperation::TrySet { value_index } => {
                if let Some(ref cell) = tracker.active_cells[tracker.current_cell_index] {
                    let value_id = sequence
                        .config
                        .init_values
                        .get(*value_index as usize % sequence.config.init_values.len())
                        .copied()
                        .unwrap_or(99) as usize;

                    let tracked_value = tracker.create_tracked_value(value_id);

                    match cell.set(tracked_value) {
                        Ok(()) => {
                            // Successfully set (cell was uninitialized)
                        }
                        Err(_tracked_value) => {
                            // Cell was already initialized, tracked_value will be dropped
                        }
                    }
                }
            }

            RaiiOperation::Drop => {
                // Drop current cell explicitly
                let old_cell = std::mem::replace(tracker.get_current_cell_mut(), None);
                drop(old_cell); // Explicit drop

                tracker.advance_cell_index();
            }

            RaiiOperation::Get => {
                if let Some(ref cell) = tracker.active_cells[tracker.current_cell_index] {
                    let _value = cell.get(); // Just access, don't store reference
                }
            }

            RaiiOperation::CheckInitialized => {
                if let Some(ref cell) = tracker.active_cells[tracker.current_cell_index] {
                    let _is_init = cell.is_initialized();
                }
            }

            RaiiOperation::Delay { micros } => {
                thread::sleep(Duration::from_micros(*micros as u64));
            }
        }

        // Check invariants after each operation
        if let Err(msg) = tracker.check_invariants() {
            panic!("RAII invariant violation after operation {}: {}", i, msg);
        }
    }

    // Test concurrent drop behavior if requested
    if sequence.test_concurrency && tracker.active_cells.iter().any(|cell| cell.is_some()) {
        let barrier = Arc::new(Barrier::new(3));
        let creation_counter = Arc::clone(&tracker.creation_counter);
        let drop_counter = Arc::clone(&tracker.drop_counter);

        // Spawn threads that create and drop OnceCell concurrently
        let handles: Vec<_> = (0..2)
            .map(|thread_id| {
                let barrier = Arc::clone(&barrier);
                let creation_counter = Arc::clone(&creation_counter);
                let drop_counter = Arc::clone(&drop_counter);

                thread::spawn(move || {
                    barrier.wait();

                    for i in 0..5 {
                        let cell = OnceCell::new();
                        let value = TrackedValue::new(
                            thread_id * 1000 + i,
                            Arc::clone(&creation_counter),
                            Arc::clone(&drop_counter),
                        );

                        let _ = cell.set(value);
                        thread::sleep(Duration::from_micros(100));
                        drop(cell); // Explicit drop
                    }
                })
            })
            .collect();

        // Wait for concurrent threads
        barrier.wait();

        // Join all threads
        for handle in handles {
            handle.join().expect("Concurrent thread should complete");
        }
    }

    // Final cleanup and validation
    for cell_slot in &mut tracker.active_cells {
        let _old_cell = std::mem::replace(cell_slot, None);
        // old_cell drops here
    }

    // Small delay to ensure all destructors complete
    thread::sleep(Duration::from_millis(10));

    // Final invariant check
    if let Err(msg) = tracker.check_invariants() {
        panic!("Final RAII invariant violation: {}", msg);
    }

    // Verify that all created values were eventually dropped
    let final_created = tracker.creation_counter.load(Ordering::SeqCst);
    let final_dropped = tracker.drop_counter.load(Ordering::SeqCst);

    assert_eq!(
        final_created, final_dropped,
        "Memory leak detected: created {} values but only dropped {}",
        final_created, final_dropped
    );

    // Additional safety check: no active references should remain
    for cell_opt in &tracker.active_cells {
        if let Some(cell) = cell_opt {
            if cell.is_initialized() {
                panic!("Cell should have been dropped but is still initialized");
            }
        }
    }
});
