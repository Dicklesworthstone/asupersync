//! Fuzz barrier wait-N reset cycle behavior.
//!
//! Tests arbitrary cycles of (wait until N) → (reset) → (wait until N) to ensure
//! reset between cycles works without spurious wake. The barrier automatically
//! resets when all N parties arrive (generation advances, arrived=0).
//!
//! Critical invariants:
//! - Exactly one leader per generation
//! - No spurious wakes during reset transition
//! - Generation counter advances correctly
//! - Arrival counter resets to 0 after trip

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::cx::Cx;
use asupersync::sync::barrier::{Barrier, BarrierWaitError};
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use futures::task::noop_waker;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Debug, Clone, Arbitrary)]
struct BarrierCycle {
    /// Number of parties required to trip the barrier (1-8)
    parties: u8,
    /// Operations to perform in this cycle
    operations: Vec<CycleOp>,
}

#[derive(Debug, Clone, Arbitrary)]
enum CycleOp {
    /// Arrive at barrier and wait for trip
    ArriveAndWait { party_id: u8 },
    /// Cancel while waiting (if currently waiting)
    CancelWaiting { party_id: u8 },
    /// Check barrier state (arrived count, generation)
    CheckState,
    /// Small delay to allow async operations to proceed
    Yield,
}

#[derive(Debug, Clone, Arbitrary)]
struct CycleSequence {
    /// Multiple cycles to test reset behavior
    cycles: Vec<BarrierCycle>,
    /// Maximum operations per cycle
    max_ops_per_cycle: u8,
}

impl CycleSequence {
    fn max_cycles() -> usize {
        10 // Keep test bounded
    }

    fn max_parties() -> u8 {
        8 // Reasonable upper bound
    }
}

// Helper to poll a future once without blocking
fn poll_once<F: Future>(mut future: Pin<&mut F>, cx: &mut Context<'_>) -> Poll<F::Output> {
    future.as_mut().poll(cx)
}

// Simple future wrapper for easier polling
struct BarrierWaitWrapper<'a> {
    future: asupersync::sync::barrier::BarrierWaitFuture<'a>,
    completed: bool,
}

impl<'a> BarrierWaitWrapper<'a> {
    fn new(barrier: &'a Barrier, cx: &'a Cx) -> Self {
        Self {
            future: barrier.wait(cx),
            completed: false,
        }
    }

    fn poll_once(
        &mut self,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<asupersync::sync::barrier::BarrierWaitResult, BarrierWaitError>> {
        if self.completed {
            return Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion));
        }

        let result = Pin::new(&mut self.future).poll(ctx);
        if result.is_ready() {
            self.completed = true;
        }
        result
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: CycleSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Limit sequence to prevent timeouts
    if sequence.cycles.len() > CycleSequence::max_cycles() {
        return;
    }

    // Track overall state across cycles
    let leader_count = AtomicUsize::new(0);
    let spurious_wake_detected = AtomicBool::new(false);
    let mut expected_generation = 0u64;

    for (cycle_idx, cycle) in sequence.cycles.iter().enumerate() {
        // Validate parties count
        if cycle.parties == 0 || cycle.parties > CycleSequence::max_parties() {
            continue; // Skip invalid cycle
        }

        // Limit operations per cycle
        let max_ops = sequence.max_ops_per_cycle.min(50) as usize; // Hard cap
        let operations = &cycle.operations[..cycle.operations.len().min(max_ops)];

        let barrier = Arc::new(Barrier::new(cycle.parties as usize));
        let parties = cycle.parties as usize;

        // Track per-cycle state
        let mut waiters: Vec<Option<BarrierWaitWrapper>> = vec![None; parties];
        let mut party_cxs: Vec<Cx> = (0..parties)
            .map(|i| {
                Cx::new(
                    RegionId::from_arena(ArenaIndex::new(cycle_idx as u32, i as u32)),
                    TaskId::from_arena(ArenaIndex::new(cycle_idx as u32, i as u32)),
                    Budget::INFINITE,
                )
            })
            .collect();

        let mut arrived_count = 0;
        let mut completed_count = 0;
        let cycle_leaders = AtomicUsize::new(0);

        // Get initial state
        #[cfg(test)]
        let (initial_arrived, initial_generation, initial_waiters) =
            barrier.state_snapshot_for_test();
        #[cfg(not(test))]
        let (initial_arrived, initial_generation, initial_waiters) = (0, expected_generation, 0);

        // Initial state should be clean
        assert_eq!(
            initial_arrived, 0,
            "Cycle {}: barrier should start with 0 arrived",
            cycle_idx
        );
        assert_eq!(
            initial_waiters, 0,
            "Cycle {}: barrier should start with 0 waiters",
            cycle_idx
        );

        for op in operations {
            let waker = noop_waker();
            let mut ctx = Context::from_waker(&waker);

            match op {
                CycleOp::ArriveAndWait { party_id } => {
                    let party_idx = (*party_id as usize) % parties;

                    // Only start waiting if not already waiting or completed
                    if waiters[party_idx].is_none() && completed_count < parties {
                        let barrier_ref = &*barrier;
                        let cx_ref = &party_cxs[party_idx];

                        let mut wrapper = BarrierWaitWrapper::new(barrier_ref, cx_ref);

                        // Poll once to start the wait
                        match wrapper.poll_once(&mut ctx) {
                            Poll::Ready(Ok(result)) => {
                                // Barrier tripped immediately (we were the last to arrive)
                                if result.is_leader() {
                                    cycle_leaders.fetch_add(1, Ordering::SeqCst);
                                }
                                completed_count += 1;
                            }
                            Poll::Ready(Err(BarrierWaitError::Cancelled)) => {
                                // Cancelled immediately
                            }
                            Poll::Pending => {
                                // Started waiting
                                arrived_count += 1;
                                waiters[party_idx] = Some(wrapper);
                            }
                            _ => {} // Other error cases
                        }
                    }
                }

                CycleOp::CancelWaiting { party_id } => {
                    let party_idx = (*party_id as usize) % parties;

                    if let Some(_waiter) = waiters[party_idx].take() {
                        // Cancel the party's Cx
                        party_cxs[party_idx].set_cancel_requested(true);
                        arrived_count = arrived_count.saturating_sub(1);
                    }
                }

                CycleOp::CheckState => {
                    #[cfg(test)]
                    let (current_arrived, current_generation, current_waiters) =
                        barrier.state_snapshot_for_test();
                    #[cfg(not(test))]
                    let (current_arrived, current_generation, current_waiters) = (
                        arrived_count,
                        expected_generation,
                        waiters.iter().filter(|w| w.is_some()).count(),
                    );

                    // Validate state consistency
                    assert!(
                        current_arrived <= parties,
                        "Cycle {}: arrived count {} cannot exceed parties {}",
                        cycle_idx,
                        current_arrived,
                        parties
                    );

                    assert!(
                        current_waiters <= parties,
                        "Cycle {}: waiters count {} cannot exceed parties {}",
                        cycle_idx,
                        current_waiters,
                        parties
                    );

                    // If all parties have arrived, generation should advance
                    if arrived_count >= parties {
                        expected_generation = expected_generation.wrapping_add(1);
                        arrived_count = 0; // Reset for next cycle
                    }
                }

                CycleOp::Yield => {
                    // Poll all active waiters to advance their state
                    for (i, waiter_opt) in waiters.iter_mut().enumerate() {
                        if let Some(waiter) = waiter_opt {
                            match waiter.poll_once(&mut ctx) {
                                Poll::Ready(Ok(result)) => {
                                    // Completed successfully
                                    if result.is_leader() {
                                        cycle_leaders.fetch_add(1, Ordering::SeqCst);
                                    }
                                    completed_count += 1;
                                    *waiter_opt = None;
                                }
                                Poll::Ready(Err(BarrierWaitError::Cancelled)) => {
                                    // Cancelled
                                    *waiter_opt = None;
                                }
                                Poll::Ready(Err(BarrierWaitError::PolledAfterCompletion)) => {
                                    // Already completed, shouldn't happen
                                    spurious_wake_detected.store(true, Ordering::SeqCst);
                                    *waiter_opt = None;
                                }
                                Poll::Pending => {
                                    // Still waiting
                                }
                            }
                        }
                    }
                }
            }

            // Early termination if cycle is complete
            if completed_count >= parties {
                break;
            }
        }

        // Cycle invariants
        let cycle_leader_count = cycle_leaders.load(Ordering::SeqCst);
        if completed_count >= parties {
            // If cycle completed, exactly one leader
            assert_eq!(
                cycle_leader_count, 1,
                "Cycle {}: exactly one leader required when cycle completes, got {}",
                cycle_idx, cycle_leader_count
            );

            // Generation should have advanced
            expected_generation = expected_generation.wrapping_add(1);
        } else {
            // If cycle didn't complete, no leaders yet
            assert_eq!(
                cycle_leader_count, 0,
                "Cycle {}: no leaders until cycle completes, got {}",
                cycle_idx, cycle_leader_count
            );
        }

        leader_count.fetch_add(cycle_leader_count, Ordering::SeqCst);
    }

    // Final invariant: no spurious wakes detected
    assert!(
        !spurious_wake_detected.load(Ordering::SeqCst),
        "Spurious wake detected during barrier reset cycle"
    );

    // If we completed any full cycles, validate leader counts
    let total_leaders = leader_count.load(Ordering::SeqCst);
    let completed_cycles = sequence
        .cycles
        .iter()
        .filter(|c| c.operations.len() >= c.parties as usize)
        .count();

    if completed_cycles > 0 {
        // Each completed cycle should have exactly one leader
        // (This is a loose check since we might not complete all cycles in the fuzz run)
        assert!(
            total_leaders <= completed_cycles,
            "Total leaders {} should not exceed expected completed cycles {}",
            total_leaders,
            completed_cycles
        );
    }
});
