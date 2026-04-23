//! Metamorphic tests for semaphore acquire/release pairing under cancellation.
//!
//! These tests verify invariant relationships that must hold regardless of
//! exact timing or cancellation patterns.

#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::sync::Semaphore;
use crate::cx::Cx;
use crate::runtime::yield_now;
use proptest::prelude::*;

/// MR1: Total Conservation - Permits are conserved across all operations
/// The total number of permits in the system (held + available) equals initial count
/// regardless of cancellation patterns.
#[derive(Debug)]
struct PermitConservation {
    initial_permits: usize,
    semaphore: Arc<Semaphore>,
    live_permits: AtomicUsize,
}

impl PermitConservation {
    fn new(initial_permits: usize) -> Self {
        Self {
            initial_permits,
            semaphore: Arc::new(Semaphore::new(initial_permits)),
            live_permits: AtomicUsize::new(0),
        }
    }

    fn verify_conservation(&self) {
        let available = self.semaphore.available_permits();
        let held = self.live_permits.load(Ordering::Acquire);
        let total = available + held;
        assert_eq!(total, self.initial_permits,
            "Permit conservation violated: initial={}, available={}, held={}, total={}",
            self.initial_permits, available, held, total);
    }
}

/// MR2: Idempotent Close - Closing multiple times has same effect as closing once
#[tokio::test]
async fn mr_idempotent_close() {
    let cx = Cx::new();
    let sem = Arc::new(Semaphore::new(5));

    // Baseline: close once
    let sem1 = sem.clone();
    sem1.close();
    let closed_once = sem1.is_closed();
    let permits_once = sem1.available_permits();

    // Transform: close multiple times
    let sem2 = Arc::new(Semaphore::new(5));
    sem2.close();
    sem2.close();
    sem2.close();
    let closed_multiple = sem2.is_closed();
    let permits_multiple = sem2.available_permits();

    // MR: f(close(x)) = f(close(close(close(x))))
    assert_eq!(closed_once, closed_multiple, "Multiple closes should be idempotent");
    assert_eq!(permits_once, permits_multiple, "Permit count after close should be idempotent");
}

/// MR3: Cancellation Equivalence - Different cancellation patterns with same
/// total acquired permits should leave semaphore in equivalent states
#[tokio::test]
async fn mr_cancellation_equivalence() {
    let initial_permits = 10;

    // Pattern A: acquire some, cancel others immediately
    let sem_a = Arc::new(Semaphore::new(initial_permits));
    let permit_count_a = Arc::new(AtomicUsize::new(0));

    let cx_a = Cx::new();
    let _permit_a1 = sem_a.acquire(&cx_a, 3).await.unwrap();
    permit_count_a.fetch_add(3, Ordering::Relaxed);

    // Try to acquire 5, but cancel the context immediately
    let cx_cancel = Cx::new();
    cx_cancel.cancel();
    let result_a = sem_a.acquire(&cx_cancel, 5).await;
    assert!(result_a.is_err()); // Should be cancelled

    let available_a = sem_a.available_permits();

    // Pattern B: acquire same total successfully
    let sem_b = Arc::new(Semaphore::new(initial_permits));
    let cx_b = Cx::new();
    let _permit_b1 = sem_b.acquire(&cx_b, 3).await.unwrap();
    let available_b = sem_b.available_permits();

    // MR: Different cancellation patterns with same net effect should yield same available permits
    assert_eq!(available_a, available_b,
        "Equivalent permit usage should yield same available count regardless of cancellation pattern");
}

/// MR4: Scaling Linearity - If all operations scale by factor k, results scale proportionally
#[tokio::test]
async fn mr_scaling_linearity() {
    let base_permits = 6;
    let scale_factor = 3;

    // Base scenario
    let sem_base = Arc::new(Semaphore::new(base_permits));
    let cx = Cx::new();
    let _permit1 = sem_base.acquire(&cx, 2).await.unwrap();
    let available_base = sem_base.available_permits();

    // Scaled scenario
    let sem_scaled = Arc::new(Semaphore::new(base_permits * scale_factor));
    let _permit2 = sem_scaled.acquire(&cx, 2 * scale_factor).await.unwrap();
    let available_scaled = sem_scaled.available_permits();

    // MR: f(k*x) should scale proportionally
    assert_eq!(available_scaled, available_base * scale_factor,
        "Scaling all permits by factor {} should scale results proportionally", scale_factor);
}

/// MR5: Acquire-Release Roundtrip - Acquiring then releasing should restore original state
#[tokio::test]
async fn mr_acquire_release_roundtrip() {
    let sem = Arc::new(Semaphore::new(10));
    let cx = Cx::new();

    let original_permits = sem.available_permits();

    // Acquire permits
    let permit = sem.acquire(&cx, 4).await.unwrap();
    let after_acquire = sem.available_permits();
    assert_eq!(after_acquire, original_permits - 4);

    // Release via drop
    drop(permit);

    let after_release = sem.available_permits();

    // MR: acquire(n) then release should restore original count
    assert_eq!(after_release, original_permits,
        "Acquire-release roundtrip should restore original permit count");
}

/// MR6: Commutativity under non-overlapping regions - Two independent acquire/release
/// sequences should be commutative if they don't overlap in time
#[tokio::test]
async fn mr_non_overlapping_commutativity() {
    let sem = Arc::new(Semaphore::new(10));
    let cx = Cx::new();

    // Sequence A then B
    let sem_ab = sem.clone();
    let permit_a1 = sem_ab.acquire(&cx, 3).await.unwrap();
    drop(permit_a1);
    let permit_b1 = sem_ab.acquire(&cx, 2).await.unwrap();
    drop(permit_b1);
    let final_ab = sem_ab.available_permits();

    // Reset semaphore for sequence B then A
    let sem_ba = Arc::new(Semaphore::new(10));
    let permit_b2 = sem_ba.acquire(&cx, 2).await.unwrap();
    drop(permit_b2);
    let permit_a2 = sem_ba.acquire(&cx, 3).await.unwrap();
    drop(permit_a2);
    let final_ba = sem_ba.available_permits();

    // MR: Non-overlapping sequences should be commutative
    assert_eq!(final_ab, final_ba,
        "Non-overlapping acquire/release sequences should be commutative");
}

/// MR7: Cancel Monotonicity - Adding cancellation should never increase available permits
#[tokio::test]
async fn mr_cancel_monotonicity() {
    let sem = Arc::new(Semaphore::new(8));

    // Scenario without cancellation
    let cx_no_cancel = Cx::new();
    let _permit1 = sem.acquire(&cx_no_cancel, 3).await.unwrap();
    let available_no_cancel = sem.available_permits();

    // Reset and try with cancellation
    let sem_with_cancel = Arc::new(Semaphore::new(8));
    let cx_with_cancel = Cx::new();
    let _permit2 = sem_with_cancel.acquire(&cx_with_cancel, 3).await.unwrap();

    // Try to acquire more but cancel it
    let cx_cancel = Cx::new();
    cx_cancel.cancel();
    let _ = sem_with_cancel.acquire(&cx_cancel, 2).await; // Should fail

    let available_with_cancel = sem_with_cancel.available_permits();

    // MR: Adding cancellation should not increase available permits
    assert!(available_with_cancel <= available_no_cancel + 2,
        "Cancellation should not increase available permits beyond what would be released");
}

/// MR8: Batch vs Sequential Equivalence - Acquiring N permits at once vs N permits
/// one-by-one should have equivalent end state (when all succeed)
#[tokio::test]
async fn mr_batch_vs_sequential_equivalence() {
    let cx = Cx::new();

    // Batch acquire
    let sem_batch = Arc::new(Semaphore::new(10));
    let _batch_permit = sem_batch.acquire(&cx, 4).await.unwrap();
    let available_batch = sem_batch.available_permits();

    // Sequential acquire
    let sem_sequential = Arc::new(Semaphore::new(10));
    let _permit1 = sem_sequential.acquire(&cx, 1).await.unwrap();
    let _permit2 = sem_sequential.acquire(&cx, 1).await.unwrap();
    let _permit3 = sem_sequential.acquire(&cx, 1).await.unwrap();
    let _permit4 = sem_sequential.acquire(&cx, 1).await.unwrap();
    let available_sequential = sem_sequential.available_permits();

    // MR: Batch and sequential should yield same available count
    assert_eq!(available_batch, available_sequential,
        "Batch vs sequential acquire should yield equivalent end state");
}

/// Property-based test for permit conservation under random operations
proptest! {
    #[test]
    fn prop_permit_conservation(
        initial_permits in 1usize..20,
        operations in prop::collection::vec(
            (1usize..5, prop::bool::ANY), // (count, should_cancel)
            0..10
        )
    ) {
        tokio_test::block_on(async {
            let conservation = PermitConservation::new(initial_permits);
            conservation.verify_conservation();

            let mut permits_held = Vec::new();

            for (count, should_cancel) in operations {
                if count > initial_permits { continue; } // Skip impossible requests

                let cx = Cx::new();
                if should_cancel {
                    cx.cancel();
                }

                match conservation.semaphore.acquire(&cx, count).await {
                    Ok(permit) => {
                        conservation.live_permits.fetch_add(count, Ordering::Release);
                        permits_held.push((permit, count));
                    },
                    Err(_) => {
                        // Cancellation or semaphore closed - expected
                    }
                }

                conservation.verify_conservation();

                // Randomly release some permits
                if !permits_held.is_empty() && rand::random::<bool>() {
                    if let Some((permit, count)) = permits_held.pop() {
                        conservation.live_permits.fetch_sub(count, Ordering::Release);
                        drop(permit);
                        conservation.verify_conservation();
                    }
                }
            }

            // Clean up remaining permits
            for (permit, count) in permits_held {
                conservation.live_permits.fetch_sub(count, Ordering::Release);
                drop(permit);
                conservation.verify_conservation();
            }
        });
    }
}

/// Composite MR: Conservation + Cancellation + Scaling
#[tokio::test]
async fn mr_composite_properties() {
    let base_permits = 6;
    let scale = 2;

    // Create scaled semaphore
    let sem = Arc::new(Semaphore::new(base_permits * scale));
    let cx = Cx::new();

    // Acquire scaled amounts
    let permit1 = sem.acquire(&cx, 2 * scale).await.unwrap();
    let after_acquire = sem.available_permits();

    // Cancel an operation (should not affect state)
    let cx_cancel = Cx::new();
    cx_cancel.cancel();
    let _ = sem.acquire(&cx_cancel, 1 * scale).await; // Should fail

    let after_cancel = sem.available_permits();
    assert_eq!(after_acquire, after_cancel, "Cancelled operation should not change state");

    // Release and verify conservation
    drop(permit1);
    let final_permits = sem.available_permits();
    assert_eq!(final_permits, base_permits * scale, "Final state should conserve all permits");
}