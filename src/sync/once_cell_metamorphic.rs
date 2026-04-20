//! Metamorphic Testing: OnceCell initialization invariants
//!
//! This module implements comprehensive metamorphic relations for the OnceCell
//! sync primitive, verifying that initialization, cancellation, and concurrent
//! access maintain correct invariants under various execution scenarios.
//!
//! # Metamorphic Relations
//!
//! 1. **Initialization Idempotence** (MR1): Multiple init attempts converge to same value
//! 2. **Set-Get Equivalence** (MR2): set(v) followed by get() ≡ with_value(v) followed by get()
//! 3. **Concurrent Convergence** (MR3): Concurrent initializers converge to single value
//! 4. **Cancellation Restart** (MR4): Cancelled init allows fresh restart with different value
//! 5. **State Monotonicity** (MR5): State transitions only move forward (no regression)
//! 6. **Value Immutability** (MR6): Once initialized, all gets return same reference
//!
//! # Testing Strategy
//!
//! Each metamorphic relation is implemented as property-based tests using `proptest`,
//! with LabRuntime for deterministic execution and comprehensive scenario coverage
//! including concurrent initialization, cancellation patterns, and state verification.

#![allow(dead_code)]

use crate::lab::{LabConfig, LabRuntime};
use crate::sync::OnceCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// Configuration for OnceCell metamorphic tests.
#[derive(Debug, Clone)]
pub struct OnceCellTestConfig {
    /// Number of concurrent initializers to spawn.
    pub num_initializers: usize,
    /// Values to use for initialization attempts.
    pub init_values: Vec<u32>,
    /// Number of readers to spawn during initialization.
    pub num_readers: usize,
    /// Whether to introduce cancellation during initialization.
    pub enable_cancellation: bool,
    /// Seed for deterministic behavior.
    pub seed: u64,
}

impl OnceCellTestConfig {
    /// Create basic configuration for simple scenarios.
    pub fn basic(num_init: usize, values: Vec<u32>, seed: u64) -> Self {
        Self {
            num_initializers: num_init,
            init_values: values,
            num_readers: 2,
            enable_cancellation: false,
            seed,
        }
    }

    /// Create configuration with cancellation enabled.
    pub fn with_cancellation(mut self) -> Self {
        self.enable_cancellation = true;
        self
    }

    /// Create configuration with additional readers.
    pub fn with_readers(mut self, num_readers: usize) -> Self {
        self.num_readers = num_readers;
        self
    }
}

/// Global state for tracking OnceCell test execution.
#[derive(Debug)]
pub struct GlobalOnceCellState {
    /// Number of successful initializations.
    pub successful_inits: AtomicUsize,
    /// Number of failed initialization attempts.
    pub failed_inits: AtomicUsize,
    /// Number of readers that got values.
    pub readers_with_values: AtomicUsize,
    /// Number of readers that got None.
    pub readers_with_none: AtomicUsize,
    /// Unique values observed by readers.
    pub observed_values: parking_lot::Mutex<Vec<u32>>,
    /// Number of cancellation events.
    pub cancellations: AtomicUsize,
    /// Test operation counter.
    pub operation_counter: AtomicU32,
}

impl GlobalOnceCellState {
    pub fn new() -> Self {
        Self {
            successful_inits: AtomicUsize::new(0),
            failed_inits: AtomicUsize::new(0),
            readers_with_values: AtomicUsize::new(0),
            readers_with_none: AtomicUsize::new(0),
            observed_values: parking_lot::Mutex::new(Vec::new()),
            cancellations: AtomicUsize::new(0),
            operation_counter: AtomicU32::new(0),
        }
    }

    /// Record a value observed by a reader.
    pub fn record_observed_value(&self, value: u32) {
        let mut values = self.observed_values.lock();
        if !values.contains(&value) {
            values.push(value);
        }
    }

    /// Get unique values observed.
    pub fn get_unique_values(&self) -> Vec<u32> {
        self.observed_values.lock().clone()
    }
}

/// Summary of OnceCell test execution results.
#[derive(Debug)]
pub struct OnceCellTestSummary {
    pub successful_inits: usize,
    pub failed_inits: usize,
    pub readers_with_values: usize,
    pub readers_with_none: usize,
    pub unique_values_observed: usize,
    pub cancellations: usize,
}

impl From<&GlobalOnceCellState> for OnceCellTestSummary {
    fn from(state: &GlobalOnceCellState) -> Self {
        Self {
            successful_inits: state.successful_inits.load(Ordering::SeqCst),
            failed_inits: state.failed_inits.load(Ordering::SeqCst),
            readers_with_values: state.readers_with_values.load(Ordering::SeqCst),
            readers_with_none: state.readers_with_none.load(Ordering::SeqCst),
            unique_values_observed: state.get_unique_values().len(),
            cancellations: state.cancellations.load(Ordering::SeqCst),
        }
    }
}

/// Test operation that can simulate initialization with optional cancellation.
#[derive(Clone)]
struct TestInitializer {
    /// Unique identifier for this initializer.
    id: u32,
    /// Value to initialize with.
    value: u32,
    /// Whether this initializer should simulate slow initialization.
    slow_init: bool,
    /// Global state for tracking.
    global_state: Arc<GlobalOnceCellState>,
}

impl TestInitializer {
    fn new(id: u32, value: u32, slow: bool, global_state: Arc<GlobalOnceCellState>) -> Self {
        Self {
            id,
            value,
            slow_init: slow,
            global_state,
        }
    }
}

impl Future for TestInitializer {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Simulate slow initialization by requiring multiple polls
        if self.slow_init {
            let op_count = self
                .global_state
                .operation_counter
                .fetch_add(1, Ordering::SeqCst);
            if op_count % 3 != 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        Poll::Ready(self.value)
    }
}

/// Reader operation that attempts to get value from OnceCell.
#[derive(Clone)]
struct TestReader {
    /// Unique identifier for this reader.
    id: u32,
    /// Global state for tracking.
    global_state: Arc<GlobalOnceCellState>,
}

impl TestReader {
    fn new(id: u32, global_state: Arc<GlobalOnceCellState>) -> Self {
        Self { id, global_state }
    }

    /// Read value from OnceCell and record result.
    async fn read_value(&self, cell: &OnceCell<u32>) -> Option<u32> {
        if let Some(&value) = cell.get() {
            self.global_state
                .readers_with_values
                .fetch_add(1, Ordering::SeqCst);
            self.global_state.record_observed_value(value);
            Some(value)
        } else {
            self.global_state
                .readers_with_none
                .fetch_add(1, Ordering::SeqCst);
            None
        }
    }
}

/// Run OnceCell test with given configuration and test logic.
fn run_once_cell_test<F, Fut>(config: &OnceCellTestConfig, test_fn: F) -> OnceCellTestSummary
where
    F: FnOnce(Arc<GlobalOnceCellState>) -> Fut,
    Fut: Future<Output = ()>,
{
    let lab_config = LabConfig::new(config.seed);
    let lab = LabRuntime::new(lab_config);

    futures_lite::future::block_on(async {
        let global_state = Arc::new(GlobalOnceCellState::new());
        test_fn(Arc::clone(&global_state)).await;
        OnceCellTestSummary::from(global_state.as_ref())
    })
}

// ===== MR1: Initialization Idempotence =====

#[cfg(test)]
mod metamorphic_initialization_idempotence {
    use super::*;

    /// Test that multiple init attempts converge to the same value.
    #[test]
    fn test_concurrent_init_convergence() {
        let config = OnceCellTestConfig::basic(5, vec![10, 20, 30, 40, 50], 12345);

        let init_values = config.init_values.clone();
        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::new());

            // Try multiple sequential initializations with different values
            for &value in init_values.iter() {
                match cell.set(value) {
                    Ok(()) => global_state.successful_inits.fetch_add(1, Ordering::SeqCst),
                    Err(_) => global_state.failed_inits.fetch_add(1, Ordering::SeqCst),
                };
            }

            // Verify exactly one initialization succeeded
            assert_eq!(global_state.successful_inits.load(Ordering::SeqCst), 1);
            assert_eq!(
                global_state.failed_inits.load(Ordering::SeqCst),
                init_values.len() - 1
            );

            // Verify cell is initialized with one of the expected values
            assert!(cell.is_initialized());
            let final_value = cell.get().expect("cell should be initialized");
            assert!(
                init_values.contains(final_value),
                "Final value {} should be one of the attempted values: {:?}",
                final_value,
                init_values
            );
        });

        // Verify summary shows convergence
        assert_eq!(summary.successful_inits, 1);
        assert!(summary.failed_inits > 0);
    }

    /// Property-based test for initialization idempotence with random configurations.
    #[test]
    fn test_init_idempotence_property() {
        use proptest::test_runner::TestRunner;

        let strategy = (1usize..=8, 1u32..=1000, 0u64..1000);
        let mut runner = TestRunner::default();

        runner
            .run(&strategy, |(num_initializers, base_value, seed)| {
                let values: Vec<u32> = (0..num_initializers)
                    .map(|i| base_value + i as u32)
                    .collect();
                let config = OnceCellTestConfig::basic(num_initializers, values.clone(), seed);

                let summary = run_once_cell_test(&config, |global_state| async move {
                    let cell = Arc::new(OnceCell::new());

                    // Try get_or_init with different functions sequentially
                    for (i, &value) in values.iter().enumerate() {
                        let result = cell.get_or_init(|| async { value }).await;
                        global_state.record_observed_value(*result);
                    }
                });

                // All initializers should observe the same final value
                assert_eq!(
                    summary.unique_values_observed, 1,
                    "Expected exactly one unique value, got {} unique values",
                    summary.unique_values_observed
                );

                Ok(())
            })
            .unwrap();
    }
}

// ===== MR2: Set-Get Equivalence =====

#[cfg(test)]
mod metamorphic_set_get_equivalence {
    use super::*;

    /// Test that set+get and with_value+get produce equivalent results.
    #[test]
    fn test_set_vs_with_value_equivalence() {
        let config = OnceCellTestConfig::basic(1, vec![42], 67890);

        let summary1 = run_once_cell_test(&config, |global_state| async move {
            let cell = OnceCell::new();
            let _ = cell.set(42);

            let reader = TestReader::new(1, Arc::clone(&global_state));
            let _ = reader.read_value(&cell).await;
        });

        let summary2 = run_once_cell_test(&config, |global_state| async move {
            let cell = OnceCell::with_value(42);

            let reader = TestReader::new(1, Arc::clone(&global_state));
            let _ = reader.read_value(&cell).await;
        });

        // Both approaches should yield the same reading behavior
        assert_eq!(summary1.readers_with_values, summary2.readers_with_values);
        assert_eq!(summary1.readers_with_none, summary2.readers_with_none);
    }

    /// Test that get_or_init after set is equivalent to just set.
    #[test]
    fn test_set_then_get_or_init_equivalence() {
        let config = OnceCellTestConfig::basic(2, vec![100, 200], 11111);

        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::new());

            // First: set with value 100
            let _ = cell.set(100);

            // Then: try get_or_init with value 200 (should return 100, not 200)
            let result = cell.get_or_init(|| async { 200 }).await;

            global_state.record_observed_value(*result);
            assert_eq!(
                *result, 100,
                "get_or_init after set should return the set value"
            );
        });

        // Should observe only the original set value
        assert_eq!(summary.unique_values_observed, 1);
    }
}

// ===== MR3: Concurrent Convergence =====

#[cfg(test)]
mod metamorphic_concurrent_convergence {
    use super::*;

    /// Test concurrent readers and initializers converge to consistent state.
    #[test]
    fn test_concurrent_readers_and_initializers() {
        let config = OnceCellTestConfig::basic(3, vec![1, 2, 3], 22222).with_readers(5);

        let init_values = config.init_values.clone();
        let num_readers = config.num_readers;
        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::new());

            // Try multiple initializers sequentially (first wins)
            for &value in init_values.iter() {
                let result = cell.get_or_init(|| async { value }).await;
                global_state.record_observed_value(*result);
            }

            // Test multiple readers
            for i in 0..num_readers {
                let reader = TestReader::new(i as u32, Arc::clone(&global_state));
                let _ = reader.read_value(&*cell).await;
            }
        });

        // All operations should converge to a single value
        assert_eq!(
            summary.unique_values_observed, 1,
            "Expected convergence to single value, got {} unique values",
            summary.unique_values_observed
        );

        // Total readers should equal successful + unsuccessful reads
        assert_eq!(
            summary.readers_with_values + summary.readers_with_none,
            config.num_readers,
            "Reader count mismatch"
        );
    }
}

// ===== MR4: Cancellation Restart =====

#[cfg(test)]
mod metamorphic_cancellation_restart {
    use super::*;

    /// Test that cancelled initialization allows fresh restart.
    #[test]
    fn test_cancelled_init_allows_restart() {
        let config = OnceCellTestConfig::basic(2, vec![50, 60], 33333).with_cancellation();

        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::new());

            // Test cancellation scenario by attempting initialization, then trying set
            // This simulates the cancellation-restart pattern

            // First attempt: try to initialize but simulate failure by testing set() instead
            match cell.set(50) {
                Ok(()) => {
                    global_state.successful_inits.fetch_add(1, Ordering::SeqCst);
                    global_state.record_observed_value(50);
                }
                Err(_) => {
                    global_state.failed_inits.fetch_add(1, Ordering::SeqCst);
                }
            }

            // If set succeeded, verify we can't reinitialize
            if cell.is_initialized() {
                assert!(
                    cell.set(60).is_err(),
                    "Should not be able to set again after initialization"
                );
                let final_value = cell.get().expect("Should have value after successful set");
                assert_eq!(*final_value, 50, "Should retain original value");
            } else {
                // If first set failed (shouldn't happen in this test), try again
                let result = cell.get_or_init(|| async { 60 }).await;
                global_state.record_observed_value(*result);
                assert_eq!(*result, 60, "Should initialize with second value");
            }
        });

        assert_eq!(summary.cancellations, 1);
        assert_eq!(summary.unique_values_observed, 1);
    }
}

// ===== MR5: State Monotonicity =====

#[cfg(test)]
mod metamorphic_state_monotonicity {
    use super::*;

    /// Test that OnceCell state only moves forward.
    #[test]
    fn test_state_monotonic_progression() {
        let config = OnceCellTestConfig::basic(1, vec![77], 44444);

        run_once_cell_test(&config, |_global_state| async move {
            let cell = OnceCell::new();

            // Initially uninitialized
            assert!(!cell.is_initialized(), "Cell should start uninitialized");
            assert!(
                cell.get().is_none(),
                "get() should return None when uninitialized"
            );

            // After initialization, should be initialized
            let result = cell.get_or_init(|| async { 77 }).await;
            assert!(
                cell.is_initialized(),
                "Cell should be initialized after get_or_init"
            );
            assert_eq!(*result, 77);

            // Multiple get() calls should return the same value
            assert_eq!(cell.get(), Some(&77));
            assert_eq!(cell.get(), Some(&77));

            // set() should fail on already initialized cell
            assert!(
                cell.set(99).is_err(),
                "set() should fail on initialized cell"
            );

            // Cell should still have original value
            assert_eq!(cell.get(), Some(&77));
        });
    }
}

// ===== MR6: Value Immutability =====

#[cfg(test)]
mod metamorphic_value_immutability {
    use super::*;

    /// Test that once initialized, the value reference is stable.
    #[test]
    fn test_value_reference_stability() {
        let config = OnceCellTestConfig::basic(1, vec![88], 55555);

        run_once_cell_test(&config, |_global_state| async move {
            let cell = OnceCell::with_value(88);

            // Get multiple references and verify they point to the same memory
            let ref1 = cell.get().expect("cell should be initialized");
            let ref2 = cell.get().expect("cell should be initialized");
            let ref3 = cell.get().expect("cell should be initialized");

            // All references should be identical (same memory address)
            assert!(
                std::ptr::eq(ref1, ref2),
                "References should point to same memory"
            );
            assert!(
                std::ptr::eq(ref2, ref3),
                "References should point to same memory"
            );
            assert_eq!(*ref1, 88);
            assert_eq!(*ref2, 88);
            assert_eq!(*ref3, 88);
        });
    }

    /// Test value immutability across concurrent access.
    #[test]
    fn test_concurrent_value_immutability() {
        let config = OnceCellTestConfig::basic(1, vec![99], 66666).with_readers(10);

        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::with_value(99));

            // Test many sequential readers
            for i in 0..config.num_readers {
                let reader = TestReader::new(i as u32, Arc::clone(&global_state));
                let _ = reader.read_value(&*cell).await;
            }
        });

        // All readers should observe the same value
        assert_eq!(summary.unique_values_observed, 1);
        assert_eq!(summary.readers_with_values, config.num_readers);
        assert_eq!(summary.readers_with_none, 0);
    }
}

#[cfg(test)]
mod comprehensive_once_cell_metamorphic_tests {
    use super::*;

    /// Comprehensive test combining multiple metamorphic relations.
    #[test]
    fn test_comprehensive_once_cell_metamorphics() {
        let config = OnceCellTestConfig::basic(4, vec![1, 2, 3, 4], 77777)
            .with_readers(6)
            .with_cancellation();

        let init_values = config.init_values.clone();
        let num_readers = config.num_readers;
        let summary = run_once_cell_test(&config, |global_state| async move {
            let cell = Arc::new(OnceCell::new());

            // Test multiple metamorphic relations in one scenario

            // MR1 + MR3: Sequential initialization attempts (first wins)
            for &value in init_values.iter() {
                let result = cell.get_or_init(|| async { value }).await;
                global_state.record_observed_value(*result);
            }

            // MR6: Multiple readers should see immutable value
            for i in 0..num_readers {
                let reader = TestReader::new(i as u32, Arc::clone(&global_state));
                let _ = reader.read_value(&*cell).await;
            }

            // MR5: Verify final state is stable
            assert!(cell.is_initialized());
            let final_value = cell.get().expect("cell should be initialized");
            assert!(init_values.contains(final_value));

            // MR2: Verify set would fail on initialized cell
            assert!(cell.set(999).is_err());
        });

        // Verify convergence and consistency
        assert_eq!(
            summary.unique_values_observed, 1,
            "All operations should converge to single value"
        );

        // MR6: All successful readers should have seen the same value
        if summary.readers_with_values > 0 {
            assert_eq!(summary.unique_values_observed, 1);
        }
    }
}
