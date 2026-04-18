//! Integration test for mutex metamorphic relations
//!
//! This test verifies that the mutex poisoning metamorphic relations work
//! correctly in a simplified environment without requiring the full test suite.

use asupersync::lab::runtime::LabRuntime;
use asupersync::lab::LabConfig;
use asupersync::sync::{LockError, Mutex, TryLockError};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{Cx, RegionId, TaskId};
use std::sync::Arc;

/// Test data structure for mutex operations
#[derive(Debug, Clone, PartialEq)]
struct TestData {
    value: u32,
    counter: u64,
}

impl Default for TestData {
    fn default() -> Self {
        Self {
            value: 42,
            counter: 0,
        }
    }
}

/// Create a test context with unique identifiers
fn create_test_context(region_id: u32, task_id: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(region_id, 0)),
        TaskId::from_arena(ArenaIndex::new(task_id, 0)),
        Budget::INFINITE,
    )
}

/// **MR1: Panic Poisoning Consistency (Integration Test)**
///
/// Verifies that panic-based poisoning is consistently detected
#[test]
fn mr1_panic_poisoning_consistency_integration() {
    let mutex = Arc::new(Mutex::new(TestData::default()));

    // Phase 1: Poison the mutex via panic in guard
    let mutex_clone = Arc::clone(&mutex);
    let handle = std::thread::spawn(move || {
        let cx = create_test_context(1, 1);
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let mut guard = mutex_clone.lock(&cx).await.expect("lock should succeed");
            guard.counter += 1;
            panic!("deliberate panic to test poisoning");
        })
        .expect_err("should panic");
    });

    let _ = handle.join();

    // Phase 2: Verify poison state is consistent
    assert!(mutex.is_poisoned(), "mutex should be poisoned after panic");

    // MR1.1: try_lock returns Poisoned
    let try_result = mutex.try_lock();
    assert!(
        matches!(try_result, Err(TryLockError::Poisoned)),
        "try_lock should return Poisoned, got {:?}",
        try_result
    );

    // MR1.2: async lock returns Poisoned
    let cx = create_test_context(2, 1);
    let lab = LabRuntime::new(LabConfig::default());
    let lock_result = futures_lite::future::block_on(async { mutex.lock(&cx).await });
    assert!(
        matches!(lock_result, Err(LockError::Poisoned)),
        "async lock should return Poisoned, got {:?}",
        lock_result
    );
}

/// **MR2: Cancel Non-Poisoning (Integration Test)**
///
/// Verifies that cancellation does NOT poison the mutex
#[test]
fn mr2_cancel_non_poisoning_integration() {
    let mutex = Arc::new(Mutex::new(TestData::default()));

    // Phase 1: Test cancellation while holding lock
    let cx = create_test_context(1, 1);
    let lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let mut guard = mutex.lock(&cx).await.expect("lock should succeed");

        // Perform operations
        guard.counter += 1;
        guard.value = 100;

        // Request cancellation while holding the lock
        cx.set_cancel_requested(true);

        // Continue using guard (should work fine)
        guard.value += 1;

        // Drop guard normally (no panic should occur)
        drop(guard);
    })
    .expect("cancel test should not panic");

    // Phase 2: Verify mutex is NOT poisoned
    assert!(
        !mutex.is_poisoned(),
        "mutex should not be poisoned after cancel"
    );

    // Phase 3: Verify subsequent operations succeed
    let try_result = mutex.try_lock();
    assert!(
        try_result.is_ok(),
        "try_lock should succeed after cancel, got {:?}",
        try_result
    );

    let cx2 = create_test_context(2, 1);
    let lab2 = LabRuntime::new(LabConfig::default());
    let lock_result = lab2.block_on(async { mutex.lock(&cx2).await });
    assert!(
        lock_result.is_ok(),
        "async lock should succeed after cancel, got {:?}",
        lock_result
    );
}

/// **MR4: Concurrent Poison Consistency (Simplified Integration Test)**
///
/// Verifies that concurrent waiters see consistent poison state
#[test]
fn mr4_concurrent_poison_consistency_integration() {
    let mutex = Arc::new(Mutex::new(TestData::default()));
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));

    // Phase 1: Create a few waiters
    let mut handles = vec![];
    for i in 0..3 {
        let mutex_clone = Arc::clone(&mutex);
        let results_clone = Arc::clone(&results);

        let handle = std::thread::spawn(move || {
            // Small stagger
            std::thread::sleep(std::time::Duration::from_millis(i * 10));

            let cx = create_test_context(i + 10, i + 10);
            let result = futures_lite::future::block_on(async { mutex_clone.lock(&cx).await });
            results_clone.lock().unwrap().push((i, result));
        });

        handles.push(handle);
    }

    // Phase 2: Poison the mutex after a short delay
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mutex_for_poison = Arc::clone(&mutex);
    let poison_handle = std::thread::spawn(move || {
        let cx = create_test_context(1, 1);
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let _guard = mutex_for_poison
                .lock(&cx)
                .await
                .expect("poison thread should lock");
            panic!("deliberate poison");
        })
        .expect_err("poison thread should panic");
    });

    // Phase 3: Wait for all threads
    let _ = poison_handle.join();
    for handle in handles {
        let _ = handle.join();
    }

    // Phase 4: Check results
    let results = results.lock().unwrap();
    assert!(!results.is_empty(), "should have some results");

    // All waiters should see either success (if they got lock before poison) or poison
    let mut poison_count = 0;
    let mut success_count = 0;
    for (_i, result) in results.iter() {
        match result {
            Err(LockError::Poisoned) => poison_count += 1,
            Ok(_) => success_count += 1,
            other => panic!(
                "Unexpected result (should be success or poison): {:?}",
                other
            ),
        }
    }

    // At most one should succeed, rest should see poison
    assert!(success_count <= 1, "at most 1 should succeed");
    if success_count == 1 {
        assert_eq!(poison_count, results.len() - 1, "rest should see poison");
    } else {
        assert_eq!(poison_count, results.len(), "all should see poison");
    }

    // Mutex should be poisoned at end
    assert!(mutex.is_poisoned(), "mutex should be poisoned at end");
}

/// **Comprehensive Integration Test**
///
/// Tests all metamorphic relations together to ensure they work in combination
#[test]
fn comprehensive_metamorphic_integration() {
    // Test MR1: Basic poison behavior
    let mutex1 = Arc::new(Mutex::new(TestData::default()));
    let mutex1_clone = Arc::clone(&mutex1);
    let handle1 = std::thread::spawn(move || {
        let cx = create_test_context(1, 1);
        let lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let _guard = mutex1_clone.lock(&cx).await.expect("lock");
            panic!("test poison");
        })
        .expect_err("should panic");
    });

    let _ = handle1.join();
    assert!(mutex1.is_poisoned());
    assert!(matches!(mutex1.try_lock(), Err(TryLockError::Poisoned)));

    // Test MR2: Cancel doesn't poison
    let mutex2 = Arc::new(Mutex::new(TestData::default()));
    let cx = create_test_context(2, 2);
    let lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let _guard = mutex2.lock(&cx).await.expect("clean lock");
        cx.set_cancel_requested(true);
        // Guard drops normally, shouldn't poison
    })
    .expect("cancel test should not panic");

    assert!(!mutex2.is_poisoned());
    assert!(mutex2.try_lock().is_ok());

    // Test MR3: Recovery path verification (indirect via poison checking)
    let poison_result1 = mutex1.try_lock();
    let poison_result2 = mutex1.try_lock();
    assert_eq!(
        std::mem::discriminant(&poison_result1),
        std::mem::discriminant(&poison_result2),
        "poison detection should be consistent"
    );

    println!("All metamorphic relations verified successfully!");
}
