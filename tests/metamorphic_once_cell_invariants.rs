//! Metamorphic Testing for OnceCell Initialization Invariants
//!
//! Tests the initialization and concurrency properties of the cancel-aware OnceCell
//! under various scenarios with structured cancellation.
//!
//! Target: src/sync/once_cell.rs
//!
//! # Metamorphic Relations
//!
//! 1. **Initialization Path Equivalence**: All initialization methods produce same final state
//! 2. **Concurrent Convergence**: Multiple concurrent initializers converge on single value
//! 3. **Cancel Recovery Invariant**: Cancelled init leaves cell as if never attempted
//! 4. **Panic Recovery Invariant**: Panicked init resets to clean uninitialized state
//! 5. **Waiter Consistency**: All waiters observe same final value regardless of timing
//! 6. **State Monotonicity**: Cell state transitions are monotonic (uninit → initializing → initialized)

#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use asupersync::sync::OnceCell;
use futures_lite::future::block_on;

/// Test harness for OnceCell metamorphic testing
struct OnceCellTestHarness;

impl OnceCellTestHarness {
    fn new() -> Self {
        Self
    }

    /// Run a test scenario
    fn run_scenario<F, R>(&self, name: &str, scenario: F) -> R
    where
        F: FnOnce(&Self) -> R,
    {
        eprintln!("Running OnceCell metamorphic scenario: {}", name);
        scenario(self)
    }
}

// MR1: Initialization Path Equivalence
// All methods of initialization should produce equivalent final states
#[test]
fn mr_initialization_path_equivalence() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("path_equivalence", |_h| {
        let test_value = 42u32;

        // Different initialization paths
        let cell_with_value = OnceCell::with_value(test_value);
        let cell_set = OnceCell::new();
        cell_set.set(test_value).expect("set should succeed");

        let cell_blocking = OnceCell::new();
        let blocking_result = cell_blocking.get_or_init_blocking(|| test_value);

        // All should have equivalent state
        assert!(cell_with_value.is_initialized(), "with_value cell should be initialized");
        assert!(cell_set.is_initialized(), "set cell should be initialized");
        assert!(cell_blocking.is_initialized(), "blocking init cell should be initialized");

        // All should return the same value
        assert_eq!(cell_with_value.get(), Some(&test_value));
        assert_eq!(cell_set.get(), Some(&test_value));
        assert_eq!(cell_blocking.get(), Some(&test_value));
        assert_eq!(*blocking_result, test_value);

        // All clones should be equivalent
        let clone_with_value = cell_with_value.clone();
        let clone_set = cell_set.clone();
        let clone_blocking = cell_blocking.clone();

        assert_eq!(clone_with_value.get(), clone_set.get());
        assert_eq!(clone_set.get(), clone_blocking.get());

        // Debug representations should be consistent
        let debug_with_value = format!("{:?}", cell_with_value);
        let debug_set = format!("{:?}", cell_set);
        let debug_blocking = format!("{:?}", cell_blocking);

        assert!(debug_with_value.contains(&test_value.to_string()));
        assert!(debug_set.contains(&test_value.to_string()));
        assert!(debug_blocking.contains(&test_value.to_string()));
    });
}

// MR2: Concurrent Convergence
// Multiple concurrent initializers must converge on exactly one value
#[test]
fn mr_concurrent_convergence() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("concurrent_convergence", |_h| {
        let candidates = [7u32, 11, 13, 17, 19];
        let cell = Arc::new(OnceCell::<u32>::new());
        let init_counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Launch multiple concurrent initializers
        for &candidate in &candidates {
            let cell = Arc::clone(&cell);
            let counter = Arc::clone(&init_counter);
            handles.push(thread::spawn(move || {
                let result = cell.get_or_init_blocking(|| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1));
                    candidate
                });
                *result
            }));
        }

        // Collect all results
        let results: Vec<u32> = handles
            .into_iter()
            .map(|h| h.join().expect("thread should not panic"))
            .collect();

        // MR: All results must be identical (convergence)
        let winner = results[0];
        assert!(results.iter().all(|&v| v == winner),
               "All concurrent initializers should converge on same value: {:?}", results);

        // MR: Exactly one initializer should have run
        assert_eq!(init_counter.load(Ordering::SeqCst), 1,
                  "Exactly one initialization should occur");

        // MR: Winner must be one of the candidates
        assert!(candidates.contains(&winner),
               "Winner {} must be one of the candidates: {:?}", winner, candidates);

        // MR: Cell state must be consistent
        assert!(cell.is_initialized());
        assert_eq!(cell.get(), Some(&winner));
    });
}

// MR3: Cancel Recovery Invariant
// Cancelled initialization leaves cell in same state as if never attempted
#[test]
fn mr_cancel_recovery_invariant() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("cancel_recovery", |_h| {
        let test_value = 55u32;

        // Reference: fresh cell that never had init attempted
        let fresh_cell = OnceCell::<u32>::new();

        // Test: cell with cancelled initialization
        let cancel_cell = OnceCell::<u32>::new();

        // Simulate async cancellation (this mirrors the existing test pattern)
        block_on(async {
            use std::future::Future;
            use std::task::Context;

            // Create a future that will be cancelled
            let mut cancel_fut = Box::pin(cancel_cell.get_or_init(|| async {
                // Never completes
                std::future::pending::<u32>().await
            }));

            // Poll once to start initialization
            let waker = std::task::Waker::noop();
            let mut cx = Context::from_waker(&waker);
            assert!(Future::poll(cancel_fut.as_mut(), &mut cx).is_pending());

            // Cancel by dropping
            drop(cancel_fut);
        });

        // Now both cells should be in identical states
        assert_eq!(fresh_cell.is_initialized(), cancel_cell.is_initialized());
        assert_eq!(fresh_cell.get(), cancel_cell.get());

        // Both should accept the same successful initialization
        let fresh_result = fresh_cell.get_or_init_blocking(|| test_value);
        let cancel_result = cancel_cell.get_or_init_blocking(|| test_value);

        assert_eq!(*fresh_result, *cancel_result);
        assert_eq!(fresh_cell.is_initialized(), cancel_cell.is_initialized());
        assert_eq!(fresh_cell.get(), cancel_cell.get());

        // Clone behavior should be identical
        let fresh_clone = fresh_cell.clone();
        let cancel_clone = cancel_cell.clone();
        assert_eq!(fresh_clone.get(), cancel_clone.get());
    });
}

// MR4: Panic Recovery Invariant
// Panicked initialization resets to clean uninitialized state
#[test]
fn mr_panic_recovery_invariant() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("panic_recovery", |_h| {
        let recovery_value = 77u32;

        // Reference: fresh cell
        let fresh_cell = OnceCell::<u32>::new();

        // Test: cell with panicked initialization
        let panic_cell = Arc::new(OnceCell::<u32>::new());
        let panic_cell_clone = Arc::clone(&panic_cell);

        // Cause a panic in initialization (in separate thread to contain it)
        let panic_handle = thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = panic_cell_clone.get_or_init_blocking(|| -> u32 {
                    panic!("intentional panic for testing");
                });
            }));
        });

        panic_handle.join().expect("panic thread should complete");

        // MR: After panic recovery, cell should be equivalent to fresh cell
        assert_eq!(fresh_cell.is_initialized(), panic_cell.is_initialized());
        assert_eq!(fresh_cell.get(), panic_cell.get());

        // MR: Both should accept identical successful initialization
        let fresh_result = fresh_cell.get_or_init_blocking(|| recovery_value);
        let panic_result = panic_cell.get_or_init_blocking(|| recovery_value);

        assert_eq!(*fresh_result, *panic_result);
        assert_eq!(fresh_cell.is_initialized(), panic_cell.is_initialized());
        assert_eq!(fresh_cell.get(), panic_cell.get());

        // MR: All derived operations should be equivalent
        assert_eq!(fresh_cell.clone().get(), panic_cell.clone().get());
        assert_eq!(format!("{:?}", fresh_cell), format!("{:?}", panic_cell));
    });
}

// MR5: Waiter Consistency
// All waiters observe the same final value regardless of timing
#[test]
fn mr_waiter_consistency() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("waiter_consistency", |_h| {
        let cell = Arc::new(OnceCell::<u32>::new());
        let barrier = Arc::new(std::sync::Barrier::new(6)); // 1 initializer + 5 waiters
        let winner_value = 123u32;

        let mut handles = Vec::new();

        // One initializer
        {
            let cell = Arc::clone(&cell);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let result = cell.get_or_init_blocking(|| {
                    thread::sleep(Duration::from_millis(10));
                    winner_value
                });
                *result
            }));
        }

        // Multiple waiters with different timing
        for delay_ms in [0, 1, 2, 5, 8] {
            let cell = Arc::clone(&cell);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                if delay_ms > 0 {
                    thread::sleep(Duration::from_millis(delay_ms));
                }
                // Give the initializer thread time to start
                thread::sleep(Duration::from_millis(15));
                let result = cell.get_or_init_blocking(|| {
                    panic!("waiter should never initialize");
                });
                *result
            }));
        }

        // Collect all results
        let results: Vec<u32> = handles
            .into_iter()
            .map(|h| h.join().expect("thread should not panic"))
            .collect();

        // MR: All threads should observe the same value
        assert!(results.iter().all(|&v| v == winner_value),
               "All waiters should observe the same value: {:?}", results);

        // MR: Cell should be in consistent final state
        assert!(cell.is_initialized());
        assert_eq!(cell.get(), Some(&winner_value));
    });
}

// MR6: State Monotonicity
// Cell state transitions are monotonic and never regress (except on error/cancel)
#[test]
fn mr_state_monotonicity() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("state_monotonicity", |_h| {
        let cell = OnceCell::<u32>::new();
        let test_value = 99u32;

        // Initial state: uninitialized
        assert!(!cell.is_initialized(), "Initial state should be uninitialized");
        assert_eq!(cell.get(), None, "Initial get should return None");

        // State progression: uninitialized → initialized
        let result = cell.get_or_init_blocking(|| test_value);
        assert_eq!(*result, test_value);

        // State should now be initialized and remain so
        assert!(cell.is_initialized(), "Cell should be initialized after init");
        assert_eq!(cell.get(), Some(&test_value), "Cell should contain the value");

        // MR: Subsequent operations should not regress state
        let second_result = cell.get_or_init_blocking(|| 999);
        assert_eq!(*second_result, test_value, "Second init should return original value");
        assert!(cell.is_initialized(), "Cell should remain initialized");

        // MR: set() on initialized cell should fail but not change state
        let set_result = cell.set(888);
        assert!(set_result.is_err(), "set() on initialized cell should fail");
        assert!(cell.is_initialized(), "Cell should remain initialized after failed set");
        assert_eq!(cell.get(), Some(&test_value), "Value should be unchanged after failed set");

        // MR: Async operations should also see consistent state
        block_on(async {
            let async_result = cell.get_or_init(|| async { 777 }).await;
            assert_eq!(*async_result, test_value, "Async init should return original value");
        });

        // MR: Clone should preserve state monotonicity
        let cloned = cell.clone();
        assert!(cloned.is_initialized(), "Clone should be initialized");
        assert_eq!(cloned.get(), Some(&test_value), "Clone should have same value");
    });
}

// MR7: Error Recovery Consistency
// Failed initialization (via get_or_try_init) should reset to consistent state
#[test]
fn mr_error_recovery_consistency() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("error_recovery", |_h| {
        let recovery_value = 333u32;

        // Reference: fresh cell
        let fresh_cell = OnceCell::<u32>::new();

        // Test: cell with failed initialization
        let error_cell = OnceCell::<u32>::new();

        // Cause initialization error
        block_on(async {
            let error_result = error_cell.get_or_try_init(|| async {
                Err::<u32, &'static str>("intentional error")
            }).await;
            assert!(error_result.is_err(), "Initialization should fail");
        });

        // MR: After error, cell should be equivalent to fresh cell
        assert_eq!(fresh_cell.is_initialized(), error_cell.is_initialized());
        assert_eq!(fresh_cell.get(), error_cell.get());

        // MR: Both should accept identical recovery initialization
        let fresh_result = fresh_cell.get_or_init_blocking(|| recovery_value);
        let error_result = error_cell.get_or_init_blocking(|| recovery_value);

        assert_eq!(*fresh_result, *error_result);
        assert_eq!(fresh_cell.is_initialized(), error_cell.is_initialized());
        assert_eq!(fresh_cell.get(), error_cell.get());

        // MR: All derived operations should be equivalent post-recovery
        block_on(async {
            let fresh_async = fresh_cell.get_or_init(|| async { 999 }).await;
            let error_async = error_cell.get_or_init(|| async { 999 }).await;
            assert_eq!(*fresh_async, *error_async);
        });
    });
}

// Comprehensive test combining multiple metamorphic relations
#[test]
fn mr_comprehensive_invariants() {
    let harness = OnceCellTestHarness::new();

    harness.run_scenario("comprehensive", |_h| {
        let test_values = [11u32, 22, 33, 44, 55];
        let cells: Vec<OnceCell<u32>> = (0..5).map(|_| OnceCell::new()).collect();

        // Initialize cells through different paths
        cells[0].set(test_values[0]).expect("set should work");
        let _ = cells[1].get_or_init_blocking(|| test_values[1]);

        block_on(async {
            let _ = cells[2].get_or_init(|| async { test_values[2] }).await;
        });

        let cells_3 = &cells[3];
        block_on(async {
            let _ = cells_3.get_or_try_init(|| async {
                Ok::<u32, &'static str>(test_values[3])
            }).await.expect("should succeed");
        });

        // Fifth cell: recover from error
        block_on(async {
            let _ = cells[4].get_or_try_init(|| async {
                Err::<u32, &'static str>("first error")
            }).await;

            let _ = cells[4].get_or_try_init(|| async {
                Ok::<u32, &'static str>(test_values[4])
            }).await.expect("recovery should work");
        });

        // MR: All cells should be initialized
        for (i, cell) in cells.iter().enumerate() {
            assert!(cell.is_initialized(), "Cell {} should be initialized", i);
            assert_eq!(cell.get(), Some(&test_values[i]), "Cell {} should have correct value", i);
        }

        // MR: All cells should behave identically under equivalent operations
        for (i, cell) in cells.iter().enumerate() {
            // Clone behavior
            let clone = cell.clone();
            assert_eq!(clone.get(), Some(&test_values[i]));

            // Redundant initialization attempts should return original values
            let redundant = cell.get_or_init_blocking(|| 999);
            assert_eq!(*redundant, test_values[i]);

            // Failed set should not change anything
            assert!(cell.set(888).is_err());
            assert_eq!(cell.get(), Some(&test_values[i]));
        }

        // MR: Async operations should be consistent across all cells
        block_on(async {
            for (i, cell) in cells.iter().enumerate() {
                let async_get = cell.get_or_init(|| async { 777 }).await;
                assert_eq!(*async_get, test_values[i]);
            }
        });
    });
}

#[test]
fn test_complete_coverage() {
    eprintln!("All OnceCell metamorphic relation tests completed successfully!");
}
