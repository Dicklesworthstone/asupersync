//! Conformance test for asupersync::sync::Mutex vs std::sync::Mutex poison semantics.
//!
//! Tests that both Mutex implementations exhibit identical poison behavior for:
//! - Same panic-during-lock scenario producing identical poisoned state
//! - Identical poisoned-state behavior on next acquire attempts
//! - Consistent poison detection and error handling
//! - Proper panic propagation and poison state persistence

use asupersync::cx::Cx;
use asupersync::sync::{
    LockError, Mutex as AsupersyncMutex, TryLockError as AsupersyncTryLockError,
};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, PoisonError, TryLockError as StdTryLockError};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

/// Result of a mutex poison conformance test comparing both implementations.
#[derive(Debug, Clone, PartialEq)]
struct PoisonConformanceResult {
    /// Test scenario identifier
    scenario: String,
    /// Whether this scenario intentionally panicked while holding the mutex
    should_panic: bool,
    /// Whether asupersync mutex became poisoned
    asupersync_poisoned: bool,
    /// Whether std mutex became poisoned
    std_poisoned: bool,
    /// Error on next lock attempt for asupersync
    asupersync_next_lock_error: bool,
    /// Error on next lock attempt for std
    std_next_lock_error: bool,
    /// Error on try_lock attempt for asupersync
    asupersync_try_lock_error: bool,
    /// Error on try_lock attempt for std
    std_try_lock_error: bool,
}

/// Test configuration for poison conformance.
#[derive(Debug, Clone)]
struct PoisonTestConfig {
    /// Test scenario name
    scenario: String,
    /// Whether to panic during lock hold
    should_panic: bool,
    /// Value to store in mutex
    initial_value: u32,
    /// Panic message for identification
    panic_message: String,
}

/// Test context for running poison conformance tests.
struct PoisonConformanceContext {
    config: PoisonTestConfig,
}

impl PoisonConformanceContext {
    fn new(config: PoisonTestConfig) -> Self {
        Self { config }
    }

    /// Run the same poison scenario on both implementations and compare results.
    fn run_differential_test(&self) -> PoisonConformanceResult {
        let asupersync_result = self.test_asupersync_poison();
        let std_result = self.test_std_poison();

        PoisonConformanceResult {
            scenario: self.config.scenario.clone(),
            should_panic: self.config.should_panic,
            asupersync_poisoned: asupersync_result.0,
            std_poisoned: std_result.0,
            asupersync_next_lock_error: asupersync_result.1,
            std_next_lock_error: std_result.1,
            asupersync_try_lock_error: asupersync_result.2,
            std_try_lock_error: std_result.2,
        }
    }

    /// Test asupersync mutex poison behavior.
    /// Returns (is_poisoned, next_lock_fails, try_lock_fails)
    fn test_asupersync_poison(&self) -> (bool, bool, bool) {
        let mutex = Arc::new(AsupersyncMutex::new(self.config.initial_value));

        // Spawn thread that acquires lock and potentially panics
        let mutex_clone = Arc::clone(&mutex);
        let should_panic = self.config.should_panic;
        let panic_message = self.config.panic_message.clone();

        let handle = thread::spawn(move || {
            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 0)),
                TaskId::from_arena(ArenaIndex::new(0, 0)),
                Budget::INFINITE,
            );

            // Block on async lock using simple polling
            let mut lock_future = mutex_clone.lock(&cx);
            let mut context = Context::from_waker(std::task::Waker::noop());

            let _guard = loop {
                match Pin::new(&mut lock_future).poll(&mut context) {
                    Poll::Ready(Ok(guard)) => break guard,
                    Poll::Ready(Err(e)) => panic!("Lock failed: {:?}", e),
                    Poll::Pending => {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            };

            // Modify value to prove we held the lock
            // guard content modification would happen through deref_mut in real use

            assert!(!should_panic, "{}", panic_message);
        });

        if should_panic {
            assert!(handle.join().is_err(), "Thread should have panicked");
        } else {
            handle.join().expect("Thread should not have panicked");
        }

        // Small delay to ensure poison state propagates
        thread::sleep(Duration::from_millis(10));

        // Check if mutex is now poisoned
        let is_poisoned = mutex.is_poisoned();

        // Test next lock attempt
        let next_lock_fails = {
            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 1)),
                TaskId::from_arena(ArenaIndex::new(0, 1)),
                Budget::INFINITE,
            );

            let mut lock_future = mutex.lock(&cx);
            let mut context = Context::from_waker(std::task::Waker::noop());

            match Pin::new(&mut lock_future).poll(&mut context) {
                Poll::Ready(Err(LockError::Poisoned)) => true,
                Poll::Ready(Ok(_)) => false,
                Poll::Ready(Err(_)) => false, // Other error types
                Poll::Pending => false,       // Would eventually succeed or fail
            }
        };

        // Test try_lock
        let try_lock_fails = match AsupersyncMutex::try_lock(&mutex) {
            Err(AsupersyncTryLockError::Poisoned) => true,
            Ok(_) => false,
            Err(AsupersyncTryLockError::Locked) => false, // Different error
        };

        (is_poisoned, next_lock_fails, try_lock_fails)
    }

    /// Test std::sync::Mutex poison behavior.
    /// Returns (is_poisoned, next_lock_fails, try_lock_fails)
    fn test_std_poison(&self) -> (bool, bool, bool) {
        let mutex = Arc::new(StdMutex::new(self.config.initial_value));

        // Spawn thread that acquires lock and potentially panics
        let mutex_clone = Arc::clone(&mutex);
        let should_panic = self.config.should_panic;
        let panic_message = self.config.panic_message.clone();

        let handle = thread::spawn(move || {
            let mut guard = mutex_clone.lock().unwrap();

            // Modify value to prove we held the lock
            *guard += 1;

            assert!(!should_panic, "{}", panic_message);
        });

        if should_panic {
            assert!(handle.join().is_err(), "Thread should have panicked");
        } else {
            handle.join().expect("Thread should not have panicked");
        }

        // Small delay to ensure poison state propagates
        thread::sleep(Duration::from_millis(10));

        // Check if mutex is now poisoned
        let is_poisoned = mutex.is_poisoned();

        // Test next lock attempt
        let next_lock_fails = match mutex.lock() {
            Err(PoisonError { .. }) => true,
            Ok(_) => false,
        };

        // Test try_lock
        let try_lock_fails = match mutex.try_lock() {
            Err(StdTryLockError::Poisoned(_)) => true,
            Ok(_) => false,
            Err(StdTryLockError::WouldBlock) => false, // Different error
        };

        (is_poisoned, next_lock_fails, try_lock_fails)
    }
}

/// Verify that both mutex implementations have conformant poison behavior.
fn assert_poison_conformance(result: &PoisonConformanceResult, test_name: &str) {
    // Both should have identical poison state
    assert_eq!(
        result.asupersync_poisoned, result.std_poisoned,
        "{}: Poison state differs: asupersync={}, std={}",
        test_name, result.asupersync_poisoned, result.std_poisoned
    );

    // Both should have identical next lock behavior
    assert_eq!(
        result.asupersync_next_lock_error, result.std_next_lock_error,
        "{}: Next lock error behavior differs: asupersync={}, std={}",
        test_name, result.asupersync_next_lock_error, result.std_next_lock_error
    );

    // Both should have identical try_lock behavior
    assert_eq!(
        result.asupersync_try_lock_error, result.std_try_lock_error,
        "{}: Try lock error behavior differs: asupersync={}, std={}",
        test_name, result.asupersync_try_lock_error, result.std_try_lock_error
    );

    // If poison should have occurred, verify it did
    if result.should_panic {
        assert!(
            result.asupersync_poisoned,
            "{}: asupersync should be poisoned after panic",
            test_name
        );
        assert!(
            result.std_poisoned,
            "{}: std should be poisoned after panic",
            test_name
        );
        assert!(
            result.asupersync_next_lock_error,
            "{}: asupersync next lock should fail when poisoned",
            test_name
        );
        assert!(
            result.std_next_lock_error,
            "{}: std next lock should fail when poisoned",
            test_name
        );
    } else {
        // No panic scenario - should not be poisoned
        assert!(
            !result.asupersync_poisoned,
            "{}: asupersync should not be poisoned without panic",
            test_name
        );
        assert!(
            !result.std_poisoned,
            "{}: std should not be poisoned without panic",
            test_name
        );
    }
}

/// Test basic mutex usage without panic (no poison).
#[test]
fn conformance_no_panic_no_poison() {
    let config = PoisonTestConfig {
        scenario: "no_panic".to_string(),
        should_panic: false,
        initial_value: 42,
        panic_message: String::new(),
    };

    let ctx = PoisonConformanceContext::new(config);
    let result = ctx.run_differential_test();

    assert_poison_conformance(&result, "no_panic_no_poison");
}

/// Test panic during lock hold causes poison.
#[test]
fn conformance_panic_during_lock() {
    let config = PoisonTestConfig {
        scenario: "panic_during_lock".to_string(),
        should_panic: true,
        initial_value: 100,
        panic_message: "Test panic for poison".to_string(),
    };

    let ctx = PoisonConformanceContext::new(config);
    let result = ctx.run_differential_test();

    assert_poison_conformance(&result, "panic_during_lock");
}

/// Test poison state persistence across multiple lock attempts.
#[test]
fn conformance_poison_persistence() {
    let config = PoisonTestConfig {
        scenario: "poison_persistence".to_string(),
        should_panic: true,
        initial_value: 200,
        panic_message: "Persistent poison test".to_string(),
    };

    let ctx = PoisonConformanceContext::new(config);
    let result = ctx.run_differential_test();

    assert_poison_conformance(&result, "poison_persistence");

    // Additional test: poison should persist for future attempts
    // Both mutexes should remain poisoned
    assert!(result.asupersync_poisoned);
    assert!(result.std_poisoned);
    assert!(result.asupersync_next_lock_error);
    assert!(result.std_next_lock_error);
    assert!(result.asupersync_try_lock_error);
    assert!(result.std_try_lock_error);
}

/// Comprehensive poison conformance test matrix.
#[test]
fn conformance_comprehensive_poison_matrix() {
    let test_cases = vec![
        // (scenario_name, should_panic, initial_value, panic_msg)
        ("normal_operation", false, 1, ""),
        ("panic_early", true, 2, "Early panic"),
        ("panic_late", true, 3, "Late panic"),
        ("panic_with_modification", true, 4, "Panic after modify"),
    ];

    for (name, should_panic, initial, msg) in test_cases {
        let config = PoisonTestConfig {
            scenario: name.to_string(),
            should_panic,
            initial_value: initial,
            panic_message: msg.to_string(),
        };

        let ctx = PoisonConformanceContext::new(config);
        let result = ctx.run_differential_test();

        assert_poison_conformance(&result, name);
    }
}

/// Verify the documented poison coverage matrix instead of printing a report
/// that can pass without exercising any implementation behavior.
#[test]
fn poison_coverage_matrix_exercises_all_scenarios() {
    let test_cases = vec![
        PoisonTestConfig {
            scenario: "no_panic".to_string(),
            should_panic: false,
            initial_value: 42,
            panic_message: String::new(),
        },
        PoisonTestConfig {
            scenario: "panic_during_lock".to_string(),
            should_panic: true,
            initial_value: 100,
            panic_message: "Test panic for poison".to_string(),
        },
        PoisonTestConfig {
            scenario: "poison_persistence".to_string(),
            should_panic: true,
            initial_value: 200,
            panic_message: "Persistent poison test".to_string(),
        },
        PoisonTestConfig {
            scenario: "normal_operation".to_string(),
            should_panic: false,
            initial_value: 1,
            panic_message: String::new(),
        },
    ];

    assert_eq!(test_cases.len(), 4, "coverage matrix should stay explicit");

    for config in test_cases {
        let scenario = config.scenario.clone();
        let ctx = PoisonConformanceContext::new(config);
        let result = ctx.run_differential_test();

        assert_poison_conformance(&result, &scenario);
    }
}
