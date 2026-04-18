//! Metamorphic tests for runtime::waker wake-coalesce invariants.
//!
//! These tests validate the waker deduplication and cloning properties using
//! metamorphic relations to ensure wake semantics are preserved across various
//! transformations and usage patterns.

use std::sync::Arc;
use std::task::Waker;

use proptest::prelude::*;

use asupersync::runtime::waker::{WakerState, WakeSource};
use asupersync::types::{ArenaIndex, TaskId};

/// Create a TaskId for testing.
fn task_id(n: u32) -> TaskId {
    TaskId::from_arena(ArenaIndex::new(n, 0))
}

/// Strategy for generating task IDs.
fn arb_task_id() -> impl Strategy<Value = TaskId> {
    (0u32..1000).prop_map(task_id)
}

/// Strategy for generating wake sources.
fn arb_wake_source() -> impl Strategy<Value = WakeSource> {
    prop_oneof![
        Just(WakeSource::Timer),
        Just(WakeSource::Explicit),
        Just(WakeSource::Unknown),
        (0i32..100).prop_map(|fd| WakeSource::Io { fd }),
    ]
}

/// Strategy for generating sequences of wake operations.
fn arb_wake_operations() -> impl Strategy<Value = Vec<WakeOp>> {
    prop::collection::vec(
        prop_oneof![
            Just(WakeOp::Wake),
            Just(WakeOp::WakeByRef),
            Just(WakeOp::Clone),
            Just(WakeOp::Drop),
        ],
        1..10,
    )
}

/// Wake operations for testing.
#[derive(Debug, Clone)]
enum WakeOp {
    Wake,
    WakeByRef,
    Clone,
    Drop,
}

// Metamorphic Relations for Runtime Waker Wake-Coalesce

/// MR1: Duplicate wake calls coalesce - Multiple wake calls on the same task
/// should result in the same state as a single wake call.
#[test]
fn mr_duplicate_wake_calls_coalesce() {
    proptest!(|(task in arb_task_id(), source in arb_wake_source(), wake_count in 1u32..10)| {
        let state1 = Arc::new(WakerState::new());
        let state2 = Arc::new(WakerState::new());

        let waker1 = state1.waker_for_source(task, source);
        let waker2 = state2.waker_for_source(task, source);

        // Single wake
        waker1.wake_by_ref();

        // Multiple wakes (should coalesce)
        for _ in 0..wake_count {
            waker2.wake_by_ref();
        }

        let drained1 = state1.drain_woken();
        let drained2 = state2.drain_woken();

        prop_assert_eq!(drained1.len(), 1, "Single wake should result in 1 woken task");
        prop_assert_eq!(drained2.len(), 1, "Multiple wakes should coalesce to 1 woken task");
        prop_assert_eq!(drained1, drained2, "Single wake and multiple wakes should have same result");
        prop_assert!(drained1.contains(&task), "Woken task should be the correct one");
    });
}

/// MR2: Wake after clone still reaches original - Waking a cloned waker should
/// affect the same underlying task and state as waking the original waker.
#[test]
fn mr_wake_after_clone_reaches_original() {
    proptest!(|(task in arb_task_id(), source in arb_wake_source())| {
        let state = Arc::new(WakerState::new());

        let original_waker = state.waker_for_source(task, source);
        let cloned_waker = original_waker.clone();

        // Wake using original
        let state_copy1 = Arc::clone(&state);
        let original_copy = state_copy1.waker_for_source(task, source);
        original_copy.wake_by_ref();
        let result_original = state_copy1.drain_woken();

        // Wake using clone
        cloned_waker.wake_by_ref();
        let result_cloned = state.drain_woken();

        prop_assert_eq!(result_original.len(), 1, "Original wake should result in 1 woken task");
        prop_assert_eq!(result_cloned.len(), 1, "Clone wake should result in 1 woken task");
        prop_assert_eq!(result_original, result_cloned, "Original and clone wake should have same effect");
        prop_assert!(result_cloned.contains(&task), "Clone should wake correct task");
    });
}

/// MR3: wake_by_ref does not consume waker - Using wake_by_ref should leave
/// the waker usable for subsequent operations, unlike wake().
#[test]
fn mr_wake_by_ref_does_not_consume_waker() {
    proptest!(|(task in arb_task_id(), source in arb_wake_source())| {
        let state1 = Arc::new(WakerState::new());
        let state2 = Arc::new(WakerState::new());

        let waker_for_wake_by_ref = state1.waker_for_source(task, source);
        let waker_for_wake = state2.waker_for_source(task, source);

        // Use wake_by_ref (should not consume)
        waker_for_wake_by_ref.wake_by_ref();
        let first_wake_by_ref = state1.drain_woken();

        // Should be able to use again
        waker_for_wake_by_ref.wake_by_ref();
        let second_wake_by_ref = state1.drain_woken();

        // Use wake() (consumes waker - but we can still compare results)
        waker_for_wake.wake();
        let wake_result = state2.drain_woken();

        prop_assert_eq!(first_wake_by_ref.len(), 1, "First wake_by_ref should work");
        prop_assert_eq!(second_wake_by_ref.len(), 1, "Second wake_by_ref should work (not consumed)");
        prop_assert_eq!(wake_result.len(), 1, "wake() should work");

        prop_assert_eq!(first_wake_by_ref, wake_result, "wake_by_ref and wake should have same effect");
        prop_assert_eq!(second_wake_by_ref, wake_result, "Multiple wake_by_ref should work consistently");
    });
}

/// MR4: Cloned waker wakes same task - A cloned waker should wake the exact
/// same task as the original waker, regardless of usage pattern.
#[test]
fn mr_cloned_waker_wakes_same_task() {
    proptest!(|(task1 in arb_task_id(), task2 in arb_task_id(), source in arb_wake_source())| {
        prop_assume!(task1 != task2); // Ensure different tasks for meaningful test

        let state = Arc::new(WakerState::new());

        let waker1 = state.waker_for_source(task1, source);
        let waker2 = state.waker_for_source(task2, source);
        let cloned_waker1 = waker1.clone();

        // Wake original task1
        waker1.wake_by_ref();
        let result_after_original = state.drain_woken();

        // Wake different task2 (should add to set)
        waker2.wake_by_ref();
        let result_after_different = state.drain_woken();

        // Wake cloned task1 (should only add task1 again)
        cloned_waker1.wake_by_ref();
        let result_after_clone = state.drain_woken();

        prop_assert_eq!(result_after_original, vec![task1], "Original should wake task1");
        prop_assert_eq!(result_after_different, vec![task2], "Different waker should wake task2");
        prop_assert_eq!(result_after_clone, vec![task1], "Clone should wake task1 again");

        // Test multiple wakes with different combinations
        waker1.wake_by_ref();
        cloned_waker1.wake_by_ref();
        let combined_result = state.drain_woken();
        prop_assert_eq!(combined_result, vec![task1], "Original and clone should coalesce for same task");
    });
}

/// MR5: Drop of waker does not wake task - Dropping a waker should not cause
/// any wake events; only explicit wake calls should cause wakes.
#[test]
fn mr_drop_of_waker_does_not_wake_task() {
    proptest!(|(task in arb_task_id(), source in arb_wake_source())| {
        let state = Arc::new(WakerState::new());

        // Create waker and immediately drop it
        {
            let _waker = state.waker_for_source(task, source);
            // waker dropped here
        }

        let after_drop = state.drain_woken();
        prop_assert!(after_drop.is_empty(), "Drop should not wake task");
        prop_assert!(!state.has_woken(), "State should report no woken tasks after drop");

        // Create another waker, clone it, drop original, keep clone
        let cloned_waker = {
            let original_waker = state.waker_for_source(task, source);
            let cloned = original_waker.clone();
            // original_waker dropped here
            cloned
        };

        let after_original_drop = state.drain_woken();
        prop_assert!(after_original_drop.is_empty(), "Drop of original should not wake task");

        // But explicit wake on clone should still work
        cloned_waker.wake_by_ref();
        let after_explicit_wake = state.drain_woken();
        prop_assert_eq!(after_explicit_wake, vec![task], "Explicit wake on clone should work");
    });
}

/// MR6: Wake ordering determinism - The order of drain_woken should be
/// deterministic regardless of wake order when multiple tasks are involved.
#[test]
fn mr_wake_ordering_determinism() {
    proptest!(|(tasks in prop::collection::vec(arb_task_id(), 2..5))| {
        // Ensure unique tasks
        let mut unique_tasks = tasks;
        unique_tasks.sort();
        unique_tasks.dedup();
        prop_assume!(unique_tasks.len() >= 2);

        let state1 = Arc::new(WakerState::new());
        let state2 = Arc::new(WakerState::new());

        let wakers1: Vec<_> = unique_tasks.iter().map(|&task| {
            state1.waker_for(task)
        }).collect();

        let wakers2: Vec<_> = unique_tasks.iter().map(|&task| {
            state2.waker_for(task)
        }).collect();

        // Wake in forward order
        for waker in &wakers1 {
            waker.wake_by_ref();
        }

        // Wake in reverse order
        for waker in wakers2.iter().rev() {
            waker.wake_by_ref();
        }

        let result_forward = state1.drain_woken();
        let result_reverse = state2.drain_woken();

        prop_assert_eq!(result_forward.len(), unique_tasks.len(), "Forward order should wake all tasks");
        prop_assert_eq!(result_reverse.len(), unique_tasks.len(), "Reverse order should wake all tasks");
        prop_assert_eq!(result_forward, result_reverse, "Wake order should not affect drain order (deterministic)");

        // Results should be sorted by TaskId
        let mut expected = unique_tasks;
        expected.sort();
        prop_assert_eq!(result_forward, expected, "Results should be sorted by TaskId");
    });
}

/// MR7: State persistence across operations - The waker state should remain
/// consistent across various combinations of operations.
#[test]
fn mr_state_persistence_across_operations() {
    proptest!(|(task in arb_task_id(), operations in arb_wake_operations())| {
        let state = Arc::new(WakerState::new());
        let mut current_waker = state.waker_for(task);
        let mut wake_calls = 0u32;
        let mut wakers: Vec<Waker> = vec![current_waker.clone()];

        for op in operations {
            match op {
                WakeOp::Wake => {
                    if !wakers.is_empty() {
                        let waker = wakers.remove(0); // Consume first waker
                        waker.wake();
                        wake_calls += 1;
                    }
                }
                WakeOp::WakeByRef => {
                    if let Some(waker) = wakers.first() {
                        waker.wake_by_ref();
                        wake_calls += 1;
                    }
                }
                WakeOp::Clone => {
                    if let Some(waker) = wakers.first() {
                        wakers.push(waker.clone());
                    }
                }
                WakeOp::Drop => {
                    if !wakers.is_empty() {
                        wakers.remove(0); // Drop first waker
                    }
                }
            }
        }

        let final_result = state.drain_woken();

        if wake_calls > 0 {
            prop_assert_eq!(final_result, vec![task], "Should have exactly one woken task regardless of wake count");
        } else {
            prop_assert!(final_result.is_empty(), "No wakes should result in empty drain");
        }
    });
}

/// Unit tests for specific waker behavior edge cases.
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_waker_coalescing() {
        let state = Arc::new(WakerState::new());
        let task = task_id(1);
        let waker = state.waker_for(task);

        // Multiple wake_by_ref calls
        waker.wake_by_ref();
        waker.wake_by_ref();
        waker.wake_by_ref();

        let result = state.drain_woken();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], task);
    }

    #[test]
    fn test_cloned_waker_behavior() {
        let state = Arc::new(WakerState::new());
        let task = task_id(2);
        let waker1 = state.waker_for(task);
        let waker2 = waker1.clone();

        // Wake using clone
        waker2.wake_by_ref();

        let result = state.drain_woken();
        assert_eq!(result, vec![task]);

        // Original should still be usable
        waker1.wake_by_ref();
        let result2 = state.drain_woken();
        assert_eq!(result2, vec![task]);
    }

    #[test]
    fn test_wake_vs_wake_by_ref_semantics() {
        let state = Arc::new(WakerState::new());
        let task = task_id(3);

        let waker_by_ref = state.waker_for(task);
        let waker_consume = state.waker_for(task);

        // wake_by_ref should not consume
        waker_by_ref.wake_by_ref();
        waker_by_ref.wake_by_ref(); // Should work again

        // wake() consumes, so we can't call it twice on same waker
        waker_consume.wake();
        // waker_consume.wake(); // Would not compile

        let result = state.drain_woken();
        assert_eq!(result, vec![task]); // All coalesced to one
    }

    #[test]
    fn test_drop_behavior() {
        let state = Arc::new(WakerState::new());
        let task = task_id(4);

        // Create and immediately drop waker
        {
            let _waker = state.waker_for(task);
        } // Dropped here

        let result = state.drain_woken();
        assert!(result.is_empty(), "Drop should not wake task");

        // But explicit wake should still work
        let waker2 = state.waker_for(task);
        waker2.wake();

        let result2 = state.drain_woken();
        assert_eq!(result2, vec![task]);
    }
}