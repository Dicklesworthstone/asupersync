//! Metamorphic tests for semaphore acquire-then-release reversibility.
//!
//! Tests the invariant that acquire(N) followed by release(N) under no
//! concurrent waiters is observationally a no-op for both borrowed and
//! owned permits.

use asupersync::lab::LabRuntime;
use asupersync::sync::Semaphore;
use asupersync::types::Budget;
use proptest::prelude::*;
use std::sync::Arc;

/// Test that single acquire-release cycle is reversible (borrowed permits).
#[test]
fn borrowed_single_acquire_release_reversibility() {
    proptest!(|(
        initial_permits in 1..100usize,
        acquire_count in 1..50usize
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            // Only test acquire counts that can be satisfied
            let acquire_count = acquire_count.min(initial_permits);

            let sem = Semaphore::new(initial_permits);
            let initial_available = sem.available_permits();

            // Acquire permits
            let permit = sem.try_acquire(acquire_count)
                .expect("should acquire permits when no waiters");

            // Verify permits were decremented
            assert_eq!(sem.available_permits(), initial_permits - acquire_count);

            // Release permits (via drop)
            drop(permit);

            // Verify no-op: semaphore state should be identical to initial
            assert_eq!(sem.available_permits(), initial_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());

            // Verify we can still acquire max permits
            let full_acquire = sem.try_acquire(initial_permits);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits after release");
        });
    });
}

/// Test that single acquire-release cycle is reversible (owned permits).
#[test]
fn owned_single_acquire_release_reversibility() {
    proptest!(|(
        initial_permits in 1..100usize,
        acquire_count in 1..50usize
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let acquire_count = acquire_count.min(initial_permits);
            let sem = Arc::new(Semaphore::new(initial_permits));
            let initial_available = sem.available_permits();

            // Acquire owned permits
            let owned_permit = asupersync::sync::OwnedSemaphorePermit::try_acquire(
                Arc::clone(&sem),
                acquire_count
            ).expect("should acquire permits when no waiters");

            // Verify permits were decremented
            assert_eq!(sem.available_permits(), initial_permits - acquire_count);
            assert_eq!(owned_permit.count(), acquire_count);

            // Release permits (via drop)
            drop(owned_permit);

            // Verify no-op: semaphore state should be identical to initial
            assert_eq!(sem.available_permits(), initial_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());

            // Verify we can still acquire max permits
            let full_acquire = sem.try_acquire(initial_permits);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits after release");
        });
    });
}

/// Test reversibility with permit chunking and release order independence.
#[test]
fn chunked_acquire_release_reversibility() {
    proptest!(|(
        initial_permits in 10..100usize,
        chunks in prop::collection::vec(1..10usize, 1..8)
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let total_acquire: usize = chunks.iter().sum();
            // Only test when total can be satisfied
            if total_acquire > initial_permits {
                return Ok(());
            }

            let sem = Semaphore::new(initial_permits);
            let initial_available = sem.available_permits();

            // Acquire permits in chunks
            let mut permits = Vec::new();
            for &chunk_size in &chunks {
                let permit = sem.try_acquire(chunk_size)
                    .expect("should acquire chunk when no waiters");
                permits.push(permit);
            }

            // Verify total permits were decremented
            assert_eq!(sem.available_permits(), initial_permits - total_acquire);

            // Release permits in reverse order (test order independence)
            for permit in permits.into_iter().rev() {
                drop(permit);
            }

            // Verify no-op: semaphore state should be identical to initial
            assert_eq!(sem.available_permits(), initial_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());

            // Verify we can still acquire max permits
            let full_acquire = sem.try_acquire(initial_permits);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits after release");
        });
    });
}

/// Test mixed borrowed and owned permit reversibility.
#[test]
fn mixed_permit_types_reversibility() {
    proptest!(|(
        initial_permits in 10..100usize,
        borrowed_count in 1..20usize,
        owned_count in 1..20usize
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let total_acquire = borrowed_count + owned_count;
            if total_acquire > initial_permits {
                return Ok(());
            }

            let sem = Arc::new(Semaphore::new(initial_permits));
            let initial_available = sem.available_permits();

            // Acquire borrowed permit
            let borrowed_permit = sem.try_acquire(borrowed_count)
                .expect("should acquire borrowed permits");

            // Acquire owned permit
            let owned_permit = asupersync::sync::OwnedSemaphorePermit::try_acquire(
                Arc::clone(&sem),
                owned_count
            ).expect("should acquire owned permits");

            // Verify total permits were decremented
            assert_eq!(sem.available_permits(), initial_permits - total_acquire);
            assert_eq!(borrowed_permit.count(), borrowed_count);
            assert_eq!(owned_permit.count(), owned_count);

            // Release in mixed order
            drop(owned_permit);  // Release owned first
            drop(borrowed_permit); // Then borrowed

            // Verify no-op: semaphore state should be identical to initial
            assert_eq!(sem.available_permits(), initial_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());

            // Verify we can still acquire max permits
            let full_acquire = sem.try_acquire(initial_permits);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits after release");
        });
    });
}

/// Test explicit commit vs drop reversibility equivalence.
#[test]
fn explicit_commit_vs_drop_equivalence() {
    proptest!(|(
        initial_permits in 10..100usize,
        acquire_count in 1..20usize,
        use_explicit_commit: bool
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let acquire_count = acquire_count.min(initial_permits);
            let sem = Semaphore::new(initial_permits);
            let initial_available = sem.available_permits();

            // Acquire permit
            let permit = sem.try_acquire(acquire_count)
                .expect("should acquire permits");

            // Verify permits were decremented
            assert_eq!(sem.available_permits(), initial_permits - acquire_count);

            // Release via explicit commit or drop
            if use_explicit_commit {
                permit.commit(); // Explicit commit
            } else {
                drop(permit); // Implicit via drop
            }

            // Both paths should yield identical results
            assert_eq!(sem.available_permits(), initial_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());

            // Verify we can still acquire max permits
            let full_acquire = sem.try_acquire(initial_permits);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits after release");
        });
    });
}

/// Test add_permits followed by acquire reversibility.
#[test]
fn add_then_acquire_reversibility() {
    proptest!(|(
        initial_permits in 1..50usize,
        add_count in 1..30usize,
        acquire_count in 1..30usize
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let sem = Semaphore::new(initial_permits);
            let initial_available = sem.available_permits();

            // Add permits
            sem.add_permits(add_count);
            let after_add = sem.available_permits();
            assert_eq!(after_add, initial_permits + add_count);

            // Acquire some permits (up to what's available)
            let acquire_count = acquire_count.min(after_add);
            let permit = sem.try_acquire(acquire_count)
                .expect("should acquire permits after add");

            assert_eq!(sem.available_permits(), after_add - acquire_count);

            // Release permits
            drop(permit);

            // Should be back to post-add state
            assert_eq!(sem.available_permits(), after_add);
            assert_eq!(sem.max_permits(), initial_permits); // max_permits doesn't change

            // Verify we can acquire all available permits
            let full_acquire = sem.try_acquire(after_add);
            assert!(full_acquire.is_ok(), "should be able to acquire all permits");
        });
    });
}

/// Test that operations preserve semaphore invariants under virtual time.
#[test]
fn virtual_time_invariant_preservation() {
    proptest!(|(
        initial_permits in 1..50usize,
        operations in prop::collection::vec(
            prop_oneof![
                (1..20usize).prop_map(|n| SemOp::Acquire(n)),
                (1..20usize).prop_map(|n| SemOp::Add(n)),
            ],
            1..10
        )
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let sem = Semaphore::new(initial_permits);
            let mut permits_held = Vec::new();
            let mut expected_available = initial_permits;

            // Execute operations
            for op in operations {
                match op {
                    SemOp::Acquire(count) => {
                        if count <= sem.available_permits() {
                            let permit = sem.try_acquire(count).unwrap();
                            expected_available -= count;
                            permits_held.push(permit);
                        }
                    }
                    SemOp::Add(count) => {
                        sem.add_permits(count);
                        expected_available += count;
                    }
                }

                // Invariant: available permits should match expected
                assert_eq!(sem.available_permits(), expected_available);
                assert!(!sem.is_closed());
                assert_eq!(sem.max_permits(), initial_permits);
            }

            // Release all held permits
            let total_held: usize = permits_held.iter().map(|p| p.count()).sum();
            drop(permits_held);
            expected_available += total_held;

            // Final invariant checks
            assert_eq!(sem.available_permits(), expected_available);
            assert_eq!(sem.max_permits(), initial_permits);
            assert!(!sem.is_closed());
        });
    });
}

#[derive(Debug, Clone)]
enum SemOp {
    Acquire(usize),
    Add(usize),
}

/// Test boundary conditions for reversibility.
#[test]
fn boundary_condition_reversibility() {
    let lab = LabRuntime::new();
    lab.block_on(async {
        let cx = lab.cx();

        // Test with 1 permit
        let sem1 = Semaphore::new(1);
        let permit1 = sem1.try_acquire(1).unwrap();
        assert_eq!(sem1.available_permits(), 0);
        drop(permit1);
        assert_eq!(sem1.available_permits(), 1);

        // Test with maximum reasonable permits
        let max_permits = 1000;
        let sem_max = Semaphore::new(max_permits);
        let permit_max = sem_max.try_acquire(max_permits).unwrap();
        assert_eq!(sem_max.available_permits(), 0);
        drop(permit_max);
        assert_eq!(sem_max.available_permits(), max_permits);

        // Test acquire-all-release-all cycle
        let sem_all = Semaphore::new(50);
        let permit_all = sem_all.try_acquire(50).unwrap();
        assert_eq!(sem_all.available_permits(), 0);

        // Should not be able to acquire more when at zero
        assert!(sem_all.try_acquire(1).is_err());

        drop(permit_all);
        assert_eq!(sem_all.available_permits(), 50);

        // Should be able to acquire again after release
        let permit_again = sem_all.try_acquire(1).unwrap();
        assert!(permit_again.count() == 1);
    });
}

/// Test that shadow counter stays consistent with actual permits.
#[test]
fn shadow_counter_consistency() {
    proptest!(|(
        initial_permits in 1..100usize,
        acquire_releases in prop::collection::vec(1..20usize, 1..10)
    )| {
        let lab = LabRuntime::new();
        lab.block_on(async {
            let cx = lab.cx();

            let sem = Semaphore::new(initial_permits);

            for &count in &acquire_releases {
                let count = count.min(sem.available_permits());
                if count == 0 { continue; }

                let before_available = sem.available_permits();
                let permit = sem.try_acquire(count).unwrap();

                // Shadow counter should immediately reflect the change
                assert_eq!(sem.available_permits(), before_available - count);

                drop(permit);

                // Shadow counter should immediately reflect the release
                assert_eq!(sem.available_permits(), before_available);
            }

            // Final state should be consistent
            assert_eq!(sem.available_permits(), initial_permits);
        });
    });
}