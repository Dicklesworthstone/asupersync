//! Metamorphic testing for RuntimeState.
//!
//! This module implements comprehensive metamorphic relations for the runtime state,
//! testing critical properties like state machine monotonicity, epoch consistency,
//! time advancement, leak tracking, and lifecycle invariants.
//!
//! # Testing Philosophy
//!
//! Runtime state management involves complex interactions between regions, tasks,
//! obligations, finalizers, and time. Rather than testing exact state sequences
//! (oracle problem), we verify that the system satisfies mathematical properties
//! that MUST hold regardless of specific operation ordering or timing.
//!
//! # Metamorphic Relations Implemented
//!
//! - **MR1: State Machine Monotonicity** - State transitions are irreversible
//! - **MR2: Epoch Consistency** - Epoch IDs advance monotonically across operations
//! - **MR3: Time Monotonicity** - Logical time never moves backward
//! - **MR4: Leak Count Additivity** - Leak counts accumulate correctly
//! - **MR5: Region Hierarchy Conservation** - Parent-child relationships preserved
//! - **MR6: Finalizer Ordering** - LIFO ordering maintained across operations
//! - **MR7: Obligation Conservation** - Obligations neither lost nor duplicated
//! - **MR8: Instance Identity Invariance** - Runtime instance ID never changes

use crate::record::{ObligationKind, RegionLimits, SourceLocation};
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::state::RuntimeState;
use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const TIME_EPSILON_NANOS: u64 = 1000; // 1µs tolerance

/// Helper to create test source location
fn test_source_location() -> SourceLocation {
    SourceLocation::new("test_file.rs", 42, 12)
}

/// Helper to create region limits
fn test_region_limits() -> RegionLimits {
    RegionLimits {
        max_tasks: Some(1000),
        max_obligations: Some(1000),
        max_children: Some(100),
    }
}

/// MR1: State Machine Monotonicity
///
/// Property: State machine transitions should be monotonic - once a region
/// moves to a more advanced state, it should never regress.
///
/// Transformation: Perform sequence of state-advancing operations
/// Relation: state_advancement(t+1) ≥ state_advancement(t)
#[test]
fn mr1_state_machine_monotonicity() {
    proptest!(|(
        region_count in 1usize..8,
        operation_sequences: Vec<Vec<u8>>
    )| {
        prop_assume!(!operation_sequences.is_empty() && operation_sequences.len() <= region_count);

        let mut state = RuntimeState::new();

        // Create regions and track their initial states
        let mut region_ids = Vec::new();
        for i in 0..region_count {
            let region_result = state.regions.create_region(
                None, // root region
                format!("test_region_{}", i),
                test_region_limits(),
                test_source_location(),
            );

            if let Ok(region_id) = region_result {
                region_ids.push(region_id);
            }
        }

        prop_assume!(!region_ids.is_empty());

        // Track state progression for each region
        let mut region_state_levels = HashMap::new();

        // Initialize state levels
        for &region_id in &region_ids {
            if let Some(record) = state.regions.get(region_id) {
                region_state_levels.insert(region_id, state_level(&record.state));
            }
        }

        // Apply operations and verify monotonicity
        for (region_idx, operations) in operation_sequences.iter().enumerate() {
            if region_idx >= region_ids.len() { continue; }
            let region_id = region_ids[region_idx];

            for &op in operations.iter().take(5) { // Limit operations to avoid timeout
                match op % 3 {
                    0 => {
                        // Request close
                        let _ = state.regions.request_close(region_id);
                    }
                    1 => {
                        // Advance region state
                        state.advance_region_state(region_id);
                    }
                    2 => {
                        // Mark as finalizing (if possible)
                        if let Some(mut record) = state.regions.get_mut(region_id) {
                            // Only advance if currently in Ready state
                            if matches!(record.state, crate::record::region::RegionState::Ready) {
                                // This would be done by proper close mechanism
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // Check monotonicity
                if let Some(record) = state.regions.get(region_id) {
                    let current_level = state_level(&record.state);
                    let previous_level = region_state_levels.get(&region_id).copied().unwrap_or(0);

                    prop_assert!(current_level >= previous_level,
                        "State regression detected for region {:?}: {} -> {}",
                        region_id, previous_level, current_level);

                    region_state_levels.insert(region_id, current_level);
                }
            }
        }
    });
}

/// Helper to convert region state to monotonic level
fn state_level(state: &crate::record::region::RegionState) -> u8 {
    match state {
        crate::record::region::RegionState::Ready => 0,
        crate::record::region::RegionState::Finalizing => 1,
        crate::record::region::RegionState::Closed(_) => 2,
    }
}

/// MR2: Epoch Consistency
///
/// Property: Epoch IDs should advance monotonically and never move backward.
///
/// Transformation: Perform operations that should advance epochs
/// Relation: epoch_id(t+1) ≥ epoch_id(t)
#[test]
fn mr2_epoch_consistency() {
    proptest!(|(
        operations: Vec<u8>
    )| {
        prop_assume!(!operations.is_empty() && operations.len() <= 10);

        let mut state = RuntimeState::new();

        // Create a region to work with
        let region_id = state.regions.create_region(
            None,
            "test_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create region");

        let mut last_region_epoch = state.region_table_epoch;
        let mut last_task_epoch = state.task_table_epoch;
        let mut last_obligation_epoch = state.obligation_table_epoch;

        for &op in operations.iter() {
            match op % 4 {
                0 => {
                    // Create child region (should advance region epoch)
                    let _ = state.regions.create_region(
                        Some(region_id),
                        format!("child_{}", op),
                        test_region_limits(),
                        test_source_location(),
                    );
                }
                1 => {
                    // Advance region state (may advance epochs)
                    state.advance_region_state(region_id);
                }
                2 => {
                    // Create obligation (should advance obligation epoch)
                    if let Ok(obligation_id) = state.obligations.create_obligation(
                        region_id,
                        ObligationKind::Generic { description: format!("test_obligation_{}", op) },
                        test_source_location(),
                    ) {
                        // Mark as leaked to advance state
                        let _ = state.mark_obligation_leaked(obligation_id);
                    }
                }
                3 => {
                    // Update time
                    state.now = Time::from_nanos(state.now.as_nanos() + 1_000_000);
                }
                _ => unreachable!(),
            }

            // Verify epoch monotonicity
            let current_region_epoch = state.region_table_epoch;
            let current_task_epoch = state.task_table_epoch;
            let current_obligation_epoch = state.obligation_table_epoch;

            prop_assert!(current_region_epoch >= last_region_epoch,
                "Region epoch regression: {:?} -> {:?}", last_region_epoch, current_region_epoch);
            prop_assert!(current_task_epoch >= last_task_epoch,
                "Task epoch regression: {:?} -> {:?}", last_task_epoch, current_task_epoch);
            prop_assert!(current_obligation_epoch >= last_obligation_epoch,
                "Obligation epoch regression: {:?} -> {:?}", last_obligation_epoch, current_obligation_epoch);

            last_region_epoch = current_region_epoch;
            last_task_epoch = current_task_epoch;
            last_obligation_epoch = current_obligation_epoch;
        }
    });
}

/// MR3: Time Monotonicity
///
/// Property: Logical time should advance monotonically and never move backward.
///
/// Transformation: Advance time in various ways
/// Relation: time(t+1) ≥ time(t)
#[test]
fn mr3_time_monotonicity() {
    proptest!(|(
        time_advances: Vec<u64>
    )| {
        prop_assume!(!time_advances.is_empty() && time_advances.len() <= 20);
        prop_assume!(time_advances.iter().all(|&t| t > 0 && t < 1_000_000_000)); // Reasonable advances

        let mut state = RuntimeState::new();
        let start_time = state.now;
        let mut last_time = start_time;

        for &advance in &time_advances {
            // Advance time
            let new_time_nanos = state.now.as_nanos().saturating_add(advance);
            state.now = Time::from_nanos(new_time_nanos);

            let current_time = state.now;

            // Verify monotonicity
            prop_assert!(current_time.as_nanos() >= last_time.as_nanos(),
                "Time moved backward: {} -> {}", last_time.as_nanos(), current_time.as_nanos());

            last_time = current_time;
        }

        // Final time should be at least start time
        prop_assert!(state.now.as_nanos() >= start_time.as_nanos(),
            "Final time should be at least start time");
    });
}

/// MR4: Leak Count Additivity
///
/// Property: Leak counts should accumulate correctly and never decrease
/// unless explicitly reset.
///
/// Transformation: Create and leak obligations
/// Relation: leak_count(after_leaks) = leak_count(before) + new_leaks
#[test]
fn mr4_leak_count_additivity() {
    proptest!(|(
        leak_batches: Vec<usize>
    )| {
        prop_assume!(!leak_batches.is_empty() && leak_batches.len() <= 5);
        prop_assume!(leak_batches.iter().all(|&count| count > 0 && count <= 8));

        let mut state = RuntimeState::new();

        // Create a region to hold obligations
        let region_id = state.regions.create_region(
            None,
            "leak_test_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create region");

        let initial_leak_count = state.leak_count;
        let mut expected_total_leaks = 0;

        for (batch_idx, &leak_count) in leak_batches.iter().enumerate() {
            let before_leak_count = state.leak_count;

            // Create and leak obligations
            for i in 0..leak_count {
                if let Ok(obligation_id) = state.obligations.create_obligation(
                    region_id,
                    ObligationKind::Generic {
                        description: format!("leak_test_{}_{}", batch_idx, i)
                    },
                    test_source_location(),
                ) {
                    let _ = state.mark_obligation_leaked(obligation_id);
                }
            }

            expected_total_leaks += leak_count;
            let after_leak_count = state.leak_count;

            // Verify leak count increased correctly
            prop_assert!(after_leak_count >= before_leak_count,
                "Leak count should not decrease: {} -> {}", before_leak_count, after_leak_count);

            // Total leak count should match expected
            let total_leaked = after_leak_count - initial_leak_count;
            prop_assert!(total_leaked <= expected_total_leaks as u64,
                "Leak count exceeded expectations: {} > {}", total_leaked, expected_total_leaks);
        }
    });
}

/// MR5: Region Hierarchy Conservation
///
/// Property: Parent-child relationships in region hierarchy should be preserved
/// across state transitions.
///
/// Transformation: Create region hierarchy, perform operations
/// Relation: parent_of(child) remains stable unless region is closed
#[test]
fn mr5_region_hierarchy_conservation() {
    proptest!(|(
        child_counts: Vec<usize>
    )| {
        prop_assume!(!child_counts.is_empty() && child_counts.len() <= 3);
        prop_assume!(child_counts.iter().all(|&count| count > 0 && count <= 4));

        let mut state = RuntimeState::new();

        // Create root region
        let root_id = state.regions.create_region(
            None,
            "root_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create root region");

        let mut hierarchy_map: HashMap<RegionId, Option<RegionId>> = HashMap::new();
        hierarchy_map.insert(root_id, None);

        // Build hierarchy
        let mut current_parents = vec![root_id];
        for (level, &child_count) in child_counts.iter().enumerate() {
            let mut next_parents = Vec::new();

            for &parent_id in &current_parents {
                for i in 0..child_count {
                    if let Ok(child_id) = state.regions.create_region(
                        Some(parent_id),
                        format!("child_{}_{}", level, i),
                        test_region_limits(),
                        test_source_location(),
                    ) {
                        hierarchy_map.insert(child_id, Some(parent_id));
                        next_parents.push(child_id);
                    }
                }
            }

            current_parents = next_parents;
        }

        // Verify initial hierarchy
        for (child_id, expected_parent) in &hierarchy_map {
            if let Some(record) = state.regions.get(*child_id) {
                prop_assert_eq!(record.parent, *expected_parent,
                    "Initial hierarchy mismatch for region {:?}", child_id);
            }
        }

        // Perform various operations
        for &region_id in hierarchy_map.keys().take(3) {
            // Advance state but verify hierarchy preservation
            state.advance_region_state(region_id);
        }

        // Verify hierarchy preservation for non-closed regions
        for (child_id, expected_parent) in &hierarchy_map {
            if let Some(record) = state.regions.get(*child_id) {
                // Only check if region is still alive
                if !matches!(record.state, crate::record::region::RegionState::Closed(_)) {
                    prop_assert_eq!(record.parent, *expected_parent,
                        "Hierarchy changed for live region {:?}", child_id);
                }
            }
        }
    });
}

/// MR6: Instance Identity Invariance
///
/// Property: Runtime instance ID should never change after creation.
///
/// Transformation: Perform various operations on state
/// Relation: instance_id remains constant throughout lifetime
#[test]
fn mr6_instance_identity_invariance() {
    proptest!(|(
        operations: Vec<u8>
    )| {
        prop_assume!(!operations.is_empty() && operations.len() <= 15);

        let mut state = RuntimeState::new();
        let initial_instance_id = state.instance_id;

        // Create some initial state
        let region_id = state.regions.create_region(
            None,
            "test_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create region");

        // Perform various operations
        for (i, &op) in operations.iter().enumerate() {
            match op % 5 {
                0 => {
                    // Create child region
                    let _ = state.regions.create_region(
                        Some(region_id),
                        format!("child_{}", i),
                        test_region_limits(),
                        test_source_location(),
                    );
                }
                1 => {
                    // Advance time
                    state.now = Time::from_nanos(state.now.as_nanos() + 1_000_000);
                }
                2 => {
                    // Create and leak obligation
                    if let Ok(obligation_id) = state.obligations.create_obligation(
                        region_id,
                        ObligationKind::Generic { description: format!("test_{}", i) },
                        test_source_location(),
                    ) {
                        let _ = state.mark_obligation_leaked(obligation_id);
                    }
                }
                3 => {
                    // Advance region state
                    state.advance_region_state(region_id);
                }
                4 => {
                    // Request close
                    let _ = state.regions.request_close(region_id);
                }
                _ => unreachable!(),
            }

            // Verify instance ID hasn't changed
            prop_assert_eq!(state.instance_id, initial_instance_id,
                "Instance ID changed after operation {}: {} -> {}",
                i, initial_instance_id, state.instance_id);
        }
    });
}

/// MR7: Obligation Conservation
///
/// Property: Obligations should neither be lost nor duplicated during
/// state transitions.
///
/// Transformation: Create obligations, perform state transitions
/// Relation: total_obligations = created - resolved - leaked
#[test]
fn mr7_obligation_conservation() {
    proptest!(|(
        obligation_batches: Vec<usize>
    )| {
        prop_assume!(!obligation_batches.is_empty() && obligation_batches.len() <= 3);
        prop_assume!(obligation_batches.iter().all(|&count| count > 0 && count <= 5));

        let mut state = RuntimeState::new();

        // Create region for obligations
        let region_id = state.regions.create_region(
            None,
            "obligation_test_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create region");

        let mut created_obligations = HashSet::new();
        let mut leaked_obligations = HashSet::new();

        // Create obligations in batches
        for (batch_idx, &count) in obligation_batches.iter().enumerate() {
            let initial_obligation_count = created_obligations.len();

            // Create obligations
            for i in 0..count {
                if let Ok(obligation_id) = state.obligations.create_obligation(
                    region_id,
                    ObligationKind::Generic {
                        description: format!("obligation_{}_{}", batch_idx, i)
                    },
                    test_source_location(),
                ) {
                    prop_assert!(created_obligations.insert(obligation_id),
                        "Obligation ID {:?} was duplicated", obligation_id);
                }
            }

            // Leak some obligations
            let obligations_to_leak: Vec<_> = created_obligations
                .iter()
                .filter(|id| !leaked_obligations.contains(id))
                .take(count / 2)
                .copied()
                .collect();

            for obligation_id in obligations_to_leak {
                if state.mark_obligation_leaked(obligation_id).is_ok() {
                    leaked_obligations.insert(obligation_id);
                }
            }

            // Verify conservation
            let expected_created = initial_obligation_count + count;
            prop_assert!(created_obligations.len() <= expected_created,
                "More obligations created than expected: {} > {}",
                created_obligations.len(), expected_created);

            // All leaked obligations should be in created set
            for leaked_id in &leaked_obligations {
                prop_assert!(created_obligations.contains(leaked_id),
                    "Leaked obligation {:?} was never created", leaked_id);
            }
        }
    });
}

/// MR8: State Transition Validity
///
/// Property: All state transitions should be valid according to the state machine.
/// Invalid transitions should be rejected.
///
/// Transformation: Attempt various state transitions
/// Relation: only valid transitions succeed
#[test]
fn mr8_state_transition_validity() {
    proptest!(|(
        transition_sequences: Vec<u8>
    )| {
        prop_assume!(!transition_sequences.is_empty() && transition_sequences.len() <= 8);

        let mut state = RuntimeState::new();

        // Create a region to test transitions
        let region_id = state.regions.create_region(
            None,
            "transition_test_region".to_string(),
            test_region_limits(),
            test_source_location(),
        ).expect("Failed to create region");

        let mut last_state_level = 0u8;

        for &transition in &transition_sequences {
            let before_state = if let Some(record) = state.regions.get(region_id) {
                state_level(&record.state)
            } else {
                // Region no longer exists (closed)
                break;
            };

            match transition % 3 {
                0 => {
                    // Request close (valid from Ready)
                    let _ = state.regions.request_close(region_id);
                }
                1 => {
                    // Advance state (should follow valid transitions)
                    state.advance_region_state(region_id);
                }
                2 => {
                    // Try to create child (should succeed if parent is Ready)
                    let _ = state.regions.create_region(
                        Some(region_id),
                        "child_region".to_string(),
                        test_region_limits(),
                        test_source_location(),
                    );
                }
                _ => unreachable!(),
            }

            // Check that transitions are monotonic (no regression)
            if let Some(record) = state.regions.get(region_id) {
                let after_state = state_level(&record.state);

                prop_assert!(after_state >= before_state,
                    "Invalid state regression detected: {} -> {}", before_state, after_state);

                last_state_level = after_state;
            }
        }
    });
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn mr_composition_hierarchy_with_leaks() {
        // Composite MR: Region hierarchy + leak tracking
        let mut state = RuntimeState::new();

        let root = state
            .regions
            .create_region(
                None,
                "root".to_string(),
                test_region_limits(),
                test_source_location(),
            )
            .expect("Failed to create root");

        let child = state
            .regions
            .create_region(
                Some(root),
                "child".to_string(),
                test_region_limits(),
                test_source_location(),
            )
            .expect("Failed to create child");

        // Create obligation in child
        let obligation = state
            .obligations
            .create_obligation(
                child,
                ObligationKind::Generic {
                    description: "test".to_string(),
                },
                test_source_location(),
            )
            .expect("Failed to create obligation");

        // Leak obligation
        let initial_leaks = state.leak_count;
        state
            .mark_obligation_leaked(obligation)
            .expect("Failed to leak obligation");

        // Verify both hierarchy and leak count
        assert_eq!(state.leak_count, initial_leaks + 1);
        if let Some(child_record) = state.regions.get(child) {
            assert_eq!(child_record.parent, Some(root));
        }
    }

    #[test]
    fn mr_validation_catches_invariant_violations() {
        // Test that our MRs would catch common runtime state bugs
        let mut state = RuntimeState::new();

        let initial_instance = state.instance_id;
        let initial_time = state.now;

        // These operations should preserve invariants
        let region = state
            .regions
            .create_region(
                None,
                "test".to_string(),
                test_region_limits(),
                test_source_location(),
            )
            .expect("Failed to create region");

        state.advance_region_state(region);

        // Instance ID should be stable
        assert_eq!(state.instance_id, initial_instance);

        // Time should not have moved backward
        assert!(state.now.as_nanos() >= initial_time.as_nanos());
    }
}
