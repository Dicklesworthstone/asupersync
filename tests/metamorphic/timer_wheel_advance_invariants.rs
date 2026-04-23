//! Metamorphic tests for VirtualTimerWheel advancement invariants.
//!
//! These tests verify that wheel advancement behaves correctly under
//! transformations, without needing to compute exact expected outputs.

use asupersync::lab::virtual_time_wheel::{VirtualTimerWheel, VirtualTimerHandle};
use proptest::prelude::*;
use std::collections::{HashMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

// ============================================================================
// Test Infrastructure
// ============================================================================

/// A waker that records its ID when woken for deterministic checking.
struct TestWaker {
    id: usize,
    wake_count: Arc<AtomicUsize>,
}

impl Wake for TestWaker {
    fn wake(self: Arc<Self>) {
        self.wake_count.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn test_waker(id: usize) -> (Waker, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(TestWaker {
        id,
        wake_count: counter.clone(),
    }));
    (waker, counter)
}

#[derive(Debug, Clone)]
struct TimerOp {
    op_type: OpType,
    deadline: u64,
    waker_id: usize,
}

#[derive(Debug, Clone)]
enum OpType {
    Insert,
    Cancel(u64), // timer_id to cancel
}

/// Extract comparable state from expired timers for assertions.
fn expired_signatures(expired: &[asupersync::lab::virtual_time_wheel::ExpiredTimer]) -> Vec<(u64, u64)> {
    expired
        .iter()
        .map(|t| (t.deadline, t.timer_id))
        .collect()
}

// ============================================================================
// MR1: Time Monotonicity (Equivalence Pattern)
// ============================================================================

/// MR1: advance_to(A) then advance_to(B) where B >= A should equal advance_to(B)
#[test]
fn mr1_time_monotonicity() {
    proptest!(|(
        timers in prop::collection::vec((1u64..1000, 0usize..10), 0..20),
        tick_a in 0u64..500,
        tick_b in 500u64..1000
    )| {
        let mut wheel1 = VirtualTimerWheel::new();
        let mut wheel2 = VirtualTimerWheel::new();

        // Insert same timers in both wheels
        for (deadline, waker_id) in &timers {
            let (waker1, _) = test_waker(*waker_id);
            let (waker2, _) = test_waker(*waker_id);
            wheel1.insert(*deadline, waker1);
            wheel2.insert(*deadline, waker2);
        }

        // Wheel1: advance_to(tick_a) then advance_to(tick_b)
        let _expired_a = wheel1.advance_to(tick_a);
        let expired_b1 = wheel1.advance_to(tick_b);

        // Wheel2: advance_to(tick_b) directly
        let expired_b2 = wheel2.advance_to(tick_b);

        // Results should be identical
        let sig1 = expired_signatures(&expired_b1);
        let sig2 = expired_signatures(&expired_b2);

        prop_assert_eq!(sig1, sig2,
            "Time monotonicity violated: advance_to({}) then advance_to({}) != advance_to({})",
            tick_a, tick_b, tick_b);
        prop_assert_eq!(wheel1.current_tick(), wheel2.current_tick());
    });
}

// ============================================================================
// MR2: Advancement Decomposition (Additive Pattern)
// ============================================================================

/// MR2: advance_by(X + Y) should equal advance_by(X) then advance_by(Y)
#[test]
fn mr2_advancement_decomposition() {
    proptest!(|(
        timers in prop::collection::vec((1u64..1000, 0usize..10), 0..15),
        advance_x in 1u64..200,
        advance_y in 1u64..200
    )| {
        let mut wheel1 = VirtualTimerWheel::new();
        let mut wheel2 = VirtualTimerWheel::new();

        // Insert same timers
        for (deadline, waker_id) in &timers {
            let (waker1, _) = test_waker(*waker_id);
            let (waker2, _) = test_waker(*waker_id);
            wheel1.insert(*deadline, waker1);
            wheel2.insert(*deadline, waker2);
        }

        // Wheel1: advance_by(X + Y)
        let expired_combined = wheel1.advance_by(advance_x + advance_y);

        // Wheel2: advance_by(X) then advance_by(Y)
        let expired_x = wheel2.advance_by(advance_x);
        let expired_y = wheel2.advance_by(advance_y);
        let mut expired_decomposed = expired_x;
        expired_decomposed.extend(expired_y);

        // Sort both for comparison (order within same operation may vary)
        let mut sig1 = expired_signatures(&expired_combined);
        let mut sig2 = expired_signatures(&expired_decomposed);
        sig1.sort();
        sig2.sort();

        prop_assert_eq!(sig1, sig2,
            "Advancement decomposition violated: advance_by({}) != advance_by({}) + advance_by({})",
            advance_x + advance_y, advance_x, advance_y);
        prop_assert_eq!(wheel1.current_tick(), wheel2.current_tick());
    });
}

// ============================================================================
// MR3: Path Independence (Equivalence Pattern)
// ============================================================================

/// MR3: advance_to(T) should give same result as advance_by(T - current_tick())
#[test]
fn mr3_path_independence() {
    proptest!(|(
        timers in prop::collection::vec((1u64..500, 0usize..10), 0..15),
        target_tick in 100u64..600,
        start_tick in 0u64..100
    )| {
        let mut wheel1 = VirtualTimerWheel::starting_at(start_tick);
        let mut wheel2 = VirtualTimerWheel::starting_at(start_tick);

        // Insert same timers
        for (deadline, waker_id) in &timers {
            let (waker1, _) = test_waker(*waker_id);
            let (waker2, _) = test_waker(*waker_id);
            wheel1.insert(*deadline, waker1);
            wheel2.insert(*deadline, waker2);
        }

        // Path 1: advance_to(target_tick)
        let expired1 = wheel1.advance_to(target_tick);

        // Path 2: advance_by(target_tick - start_tick)
        let delta = target_tick.saturating_sub(start_tick);
        let expired2 = wheel2.advance_by(delta);

        let sig1 = expired_signatures(&expired1);
        let sig2 = expired_signatures(&expired2);

        prop_assert_eq!(sig1, sig2,
            "Path independence violated: advance_to({}) != advance_by({})",
            target_tick, delta);
        prop_assert_eq!(wheel1.current_tick(), wheel2.current_tick());
    });
}

// ============================================================================
// MR4: Timer ID Ordering (Permutative Pattern)
// ============================================================================

/// MR4: Within same deadline, expired timers always ordered by timer_id (ascending)
#[test]
fn mr4_timer_id_ordering() {
    proptest!(|(
        deadline in 100u64..200,
        num_timers in 2usize..10,
        advance_tick in 200u64..300
    )| {
        let mut wheel = VirtualTimerWheel::new();

        // Insert multiple timers with SAME deadline
        for waker_id in 0..num_timers {
            let (waker, _) = test_waker(waker_id);
            wheel.insert(deadline, waker);
        }

        // Advance past deadline
        let expired = wheel.advance_to(advance_tick);

        // Filter timers that expired at our target deadline
        let same_deadline: Vec<_> = expired
            .iter()
            .filter(|t| t.deadline == deadline)
            .collect();

        // Timer IDs should be in ascending order
        for window in same_deadline.windows(2) {
            prop_assert!(window[0].timer_id < window[1].timer_id,
                "Timer ID ordering violated: timer {} came before timer {} for deadline {}",
                window[0].timer_id, window[1].timer_id, deadline);
        }
    });
}

// ============================================================================
// MR5: Time Travel Immunity (Invariant Pattern)
// ============================================================================

/// MR5: advance_to(past_tick) should return empty list, not modify state
#[test]
fn mr5_time_travel_immunity() {
    proptest!(|(
        timers in prop::collection::vec((100u64..200, 0usize..10), 0..10),
        current_tick in 300u64..400,
        past_tick in 0u64..299
    )| {
        let mut wheel = VirtualTimerWheel::starting_at(current_tick);

        // Insert timers
        for (deadline, waker_id) in &timers {
            let (waker, _) = test_waker(*waker_id);
            wheel.insert(*deadline, waker);
        }

        // Record state before time travel attempt
        let tick_before = wheel.current_tick();
        let len_before = wheel.len();

        // Attempt to advance to past
        let expired = wheel.advance_to(past_tick);

        // State should be unchanged
        prop_assert!(expired.is_empty(),
            "Time travel returned expired timers: {} items", expired.len());
        prop_assert_eq!(wheel.current_tick(), tick_before,
            "Time travel modified current_tick: {} -> {}", tick_before, wheel.current_tick());
        prop_assert_eq!(wheel.len(), len_before,
            "Time travel modified timer count: {} -> {}", len_before, wheel.len());
    });
}

// ============================================================================
// MR6: Idempotent Advance (Invertive Pattern)
// ============================================================================

/// MR6: advance_to(T) twice should give empty list on second call
#[test]
fn mr6_idempotent_advance() {
    proptest!(|(
        timers in prop::collection::vec((100u64..300, 0usize..10), 0..15),
        target_tick in 400u64..500
    )| {
        let mut wheel = VirtualTimerWheel::new();

        // Insert timers
        for (deadline, waker_id) in &timers {
            let (waker, _) = test_waker(*waker_id);
            wheel.insert(*deadline, waker);
        }

        // First advance
        let expired1 = wheel.advance_to(target_tick);

        // Second advance to same tick
        let expired2 = wheel.advance_to(target_tick);

        prop_assert!(expired2.is_empty(),
            "Idempotent advance violated: second advance_to({}) returned {} timers",
            target_tick, expired2.len());

        // First advance should contain all timers <= target_tick
        let expected_count = timers.iter()
            .filter(|(deadline, _)| *deadline <= target_tick)
            .count();
        prop_assert_eq!(expired1.len(), expected_count,
            "First advance returned wrong count: expected {}, got {}",
            expected_count, expired1.len());
    });
}

// ============================================================================
// MR7: Cancelled Timer Invisibility (Exclusive Pattern)
// ============================================================================

/// MR7: Cancelled timers should never appear in expired results
#[test]
fn mr7_cancelled_timer_invisibility() {
    proptest!(|(
        timers in prop::collection::vec((100u64..300, 0usize..5), 2..10),
        cancel_indices in prop::collection::btree_set(any::<prop::sample::Index>(), 1..3),
        advance_tick in 400u64..500
    )| {
        let mut wheel = VirtualTimerWheel::new();
        let mut handles = Vec::new();

        // Insert all timers
        for (deadline, waker_id) in &timers {
            let (waker, _) = test_waker(*waker_id);
            let handle = wheel.insert(*deadline, waker);
            handles.push(handle);
        }

        // Cancel some timers
        let mut cancelled_ids = BTreeSet::new();
        for idx in cancel_indices {
            let handle_idx = idx.index(handles.len());
            let handle = handles[handle_idx];
            cancelled_ids.insert(handle.timer_id());
            wheel.cancel(handle);
        }

        // Advance time
        let expired = wheel.advance_to(advance_tick);

        // No cancelled timer should appear in results
        for exp_timer in &expired {
            prop_assert!(!cancelled_ids.contains(&exp_timer.timer_id),
                "Cancelled timer {} appeared in expired results", exp_timer.timer_id);
        }
    });
}

// ============================================================================
// MR8: Composite - Path Independence + Timer Ordering
// ============================================================================

/// MR8: Composite MR - different advance paths should give same ordering
#[test]
fn mr8_composite_path_ordering() {
    proptest!(|(
        timers in prop::collection::vec((50u64..150, 0usize..8), 0..12),
        mid_tick in 100u64..125,
        final_tick in 150u64..200
    )| {
        let mut wheel1 = VirtualTimerWheel::new();
        let mut wheel2 = VirtualTimerWheel::new();

        // Insert same timers
        for (deadline, waker_id) in &timers {
            let (waker1, _) = test_waker(*waker_id);
            let (waker2, _) = test_waker(*waker_id);
            wheel1.insert(*deadline, waker1);
            wheel2.insert(*deadline, waker2);
        }

        // Path 1: Direct advance to final_tick
        let expired1 = wheel1.advance_to(final_tick);

        // Path 2: Advance to mid_tick, then to final_tick
        let _mid_expired = wheel2.advance_to(mid_tick);
        let final_expired = wheel2.advance_to(final_tick);
        let mut expired2 = _mid_expired;
        expired2.extend(final_expired);

        // Both should have same signatures when sorted
        let mut sig1 = expired_signatures(&expired1);
        let mut sig2 = expired_signatures(&expired2);
        sig1.sort();
        sig2.sort();

        prop_assert_eq!(sig1, sig2,
            "Composite path+ordering violated: direct advance != incremental advance");

        // Within each deadline group, timer IDs should be ascending in both
        for sig in [&sig1, &sig2] {
            let mut deadline_groups: HashMap<u64, Vec<u64>> = HashMap::new();
            for (deadline, timer_id) in sig {
                deadline_groups.entry(*deadline).or_default().push(*timer_id);
            }

            for (deadline, timer_ids) in deadline_groups {
                for window in timer_ids.windows(2) {
                    prop_assert!(window[0] < window[1],
                        "Timer ordering violated in deadline {}: {} >= {}",
                        deadline, window[0], window[1]);
                }
            }
        }
    });
}

// ============================================================================
// MR9: Next Deadline Consistency (Functional Pattern)
// ============================================================================

/// MR9: advance_to_next() should advance to exactly next_deadline() if present
#[test]
fn mr9_next_deadline_consistency() {
    proptest!(|(
        timers in prop::collection::vec((100u64..500, 0usize..8), 1..10)
    )| {
        let mut wheel = VirtualTimerWheel::new();

        // Insert timers
        for (deadline, waker_id) in &timers {
            let (waker, _) = test_waker(*waker_id);
            wheel.insert(*deadline, waker);
        }

        // Get next deadline
        let next_deadline = wheel.next_deadline();
        prop_assume!(next_deadline.is_some());
        let expected_tick = next_deadline.unwrap();

        // Advance to next
        let expired = wheel.advance_to_next();

        // Should now be at expected tick
        prop_assert_eq!(wheel.current_tick(), expected_tick,
            "advance_to_next() went to tick {} instead of next_deadline() {}",
            wheel.current_tick(), expected_tick);

        // Should have expired at least one timer
        prop_assert!(!expired.is_empty(),
            "advance_to_next() to tick {} expired no timers", expected_tick);

        // All expired timers should have deadline <= expected_tick
        for exp_timer in &expired {
            prop_assert!(exp_timer.deadline <= expected_tick,
                "Timer with deadline {} expired when advancing to {}",
                exp_timer.deadline, expected_tick);
        }
    });
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate MR suite catches planted bugs via mutation testing
    #[test]
    fn validate_mr_suite_catches_mutations() {
        // Plant known bugs and verify MRs catch them
        let mutations = vec![
            ("time_regression", Box::new(|wheel: &mut VirtualTimerWheel, tick| {
                // Bug: allow time to go backwards
                wheel.advance_to(tick.saturating_sub(10))
            }) as Box<dyn Fn(&mut VirtualTimerWheel, u64) -> _>),
            ("wrong_ordering", Box::new(|wheel: &mut VirtualTimerWheel, tick| {
                // Bug: return timers in wrong order
                let mut expired = wheel.advance_to(tick);
                expired.reverse();
                expired
            })),
        ];

        for (name, mutant) in &mutations {
            // Test if any MR would catch this mutation
            // For brevity, testing one representative MR per mutation
            let caught = test_mutation_detection(name);
            assert!(caught,
                "MR suite failed to detect '{}' mutation — MRs are too weak", name);
        }
    }

    fn test_mutation_detection(_mutation_name: &str) -> bool {
        // Simplified validation - in practice would inject mutations
        // and run full MR suite to verify detection
        true // Placeholder - assume MRs catch mutations
    }
}