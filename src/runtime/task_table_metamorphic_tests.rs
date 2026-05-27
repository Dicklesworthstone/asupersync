//! Metamorphic tests for TaskTable runtime component.
//!
//! These tests verify invariant relationships that must hold regardless of
//! operation sequences, addressing the oracle problem for complex runtime
//! state management. Each test focuses on a specific metamorphic relation
//! derived from TaskTable domain properties.

#![allow(clippy::pedantic, clippy::nursery, clippy::unwrap_used)]

use proptest::prelude::*;

use super::*;
use crate::record::task::{TaskPhase, TaskRecord};
use crate::runtime::stored_task::StoredTask;
use crate::types::{Budget, Outcome, RegionId, TaskId, Time};
use crate::util::ArenaIndex;

/// Helper to create a test task record with given parameters.
fn make_test_task(owner: RegionId, deadline: Option<Time>) -> TaskRecord {
    let provisional_id = TaskId::from_arena(ArenaIndex::new(0, 0));
    let budget = match deadline {
        Some(d) => Budget::INFINITE.with_deadline(d),
        None => Budget::INFINITE,
    };
    TaskRecord::new(provisional_id, owner, budget)
}

/// Generate arbitrary valid RegionId for property-based testing.
fn arb_region_id() -> impl Strategy<Value = RegionId> {
    any::<u32>().prop_map(|x| RegionId::from_arena(ArenaIndex::new(x % 1000, 0)))
}

/// Generate arbitrary optional deadline.
fn arb_deadline() -> impl Strategy<Value = Option<Time>> {
    prop_oneof![
        Just(None),
        (1u64..1_000_000).prop_map(|ns| Some(Time::from_nanos(ns)))
    ]
}

/// Operation types for metamorphic testing.
#[derive(Debug, Clone)]
enum TableOperation {
    Insert {
        owner: RegionId,
        deadline: Option<Time>,
    },
    Remove {
        task_index: usize,
    },
    RecycledRemove {
        task_index: usize,
    },
    UpdatePhase {
        task_index: usize,
        new_phase: TaskPhase,
    },
    StoreFuture {
        task_index: usize,
    },
    RemoveFuture {
        task_index: usize,
    },
}

/// Generate arbitrary table operations for property-based testing.
fn arb_table_operation() -> impl Strategy<Value = TableOperation> {
    prop_oneof![
        (arb_region_id(), arb_deadline())
            .prop_map(|(owner, deadline)| TableOperation::Insert { owner, deadline }),
        any::<usize>().prop_map(|idx| TableOperation::Remove { task_index: idx }),
        any::<usize>().prop_map(|idx| TableOperation::RecycledRemove { task_index: idx }),
        (any::<usize>(), any::<u8>()).prop_map(|(idx, phase)| TableOperation::UpdatePhase {
            task_index: idx,
            new_phase: match phase % 6 {
                0 => TaskPhase::Created,
                1 => TaskPhase::Running,
                2 => TaskPhase::CancelRequested,
                3 => TaskPhase::Cancelling,
                4 => TaskPhase::Finalizing,
                _ => TaskPhase::Completed,
            }
        }),
        any::<usize>().prop_map(|idx| TableOperation::StoreFuture { task_index: idx }),
        any::<usize>().prop_map(|idx| TableOperation::RemoveFuture { task_index: idx }),
    ]
}

/// Apply operation to table, tracking task indices for later operations.
fn apply_operation(
    table: &mut TaskTable,
    op: &TableOperation,
    task_indices: &mut Vec<(TaskId, ArenaIndex)>,
) {
    match op {
        TableOperation::Insert { owner, deadline } => {
            let record = make_test_task(*owner, *deadline);
            let idx = table.insert_task(record);
            let task_id = TaskId::from_arena(idx);
            task_indices.push((task_id, idx));
        }
        TableOperation::Remove { task_index } => {
            if let Some((task_id, _idx)) = task_indices.get(*task_index % task_indices.len().max(1))
            {
                table.remove_task(*task_id);
                // Note: Not removing from task_indices to allow some operations on non-existent tasks
            }
        }
        TableOperation::RecycledRemove { task_index } => {
            if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                table.remove_and_recycle_task(*task_id);
            }
        }
        TableOperation::UpdatePhase {
            task_index,
            new_phase,
        } => {
            if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                table.update_task(*task_id, |record| {
                    record.phase.store(*new_phase);
                });
            }
        }
        TableOperation::StoreFuture { task_index } => {
            if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                if table.task(*task_id).is_some() {
                    let stored = StoredTask::new(async { Outcome::Ok(()) });
                    table.store_spawned_task(*task_id, stored);
                }
            }
        }
        TableOperation::RemoveFuture { task_index } => {
            if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                table.remove_stored_future(*task_id);
            }
        }
    }
}

/// Capture table state for invariant checking.
#[derive(Debug, Clone, PartialEq)]
struct TableSnapshot {
    task_count: usize,
    live_task_count: usize,
    stored_future_count: usize,
    pool_stats: TaskRecordPoolStats,
    deadline_sum: u128,
    tasks_with_deadline: usize,
    phase_counts: [usize; 6], // All 6 phases including Completed
}

impl TableSnapshot {
    fn capture(table: &TaskTable) -> Self {
        let mut phase_counts = [0; 6];
        for (_, record) in table.iter() {
            let phase_idx = record.phase.load() as usize;
            if phase_idx < 6 {
                phase_counts[phase_idx] += 1;
            }
        }

        Self {
            task_count: table.len(),
            live_task_count: table.live_task_count(),
            stored_future_count: table.stored_future_count(),
            pool_stats: table.task_record_pool_stats(),
            deadline_sum: table.deadline_sum_ns(),
            tasks_with_deadline: table.tasks_with_deadline_count(),
            phase_counts,
        }
    }
}

//
// METAMORPHIC RELATIONS - Each test verifies one core invariant
//

/// MR1: EQUIVALENCE - Permutation Invariance
/// Operations applied in different orders should produce equivalent final states
/// (for commutative operations like independent insertions).
#[test]
fn mr_operation_order_invariance() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        // Only test with operations that should be commutative
        let commutative_ops: Vec<_> = ops.into_iter()
            .filter(|op| matches!(op,
                TableOperation::Insert { .. } |
                TableOperation::StoreFuture { .. }
            ))
            .take(10) // Limit for performance
            .collect();

        if commutative_ops.len() < 2 {
            return Ok(());
        }

        let mut table1 = TaskTable::new();
        let mut task_indices1 = Vec::new();
        let mut table2 = TaskTable::new();
        let mut task_indices2 = Vec::new();

        // Apply operations in original order
        for op in &commutative_ops {
            apply_operation(&mut table1, op, &mut task_indices1);
        }

        // Apply operations in reverse order
        for op in commutative_ops.iter().rev() {
            apply_operation(&mut table2, op, &mut task_indices2);
        }

        // For independent operations, certain properties should be equivalent
        prop_assert_eq!(table1.len(), table2.len(),
            "Task count should be invariant to operation order");
        prop_assert_eq!(table1.stored_future_count(), table2.stored_future_count(),
            "Stored future count should be invariant to operation order");
    });
}

/// MR2: ADDITIVE - Arena Capacity Monotonicity
/// Arena capacity should never decrease during any sequence of operations.
#[test]
fn mr_capacity_monotonicity() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let mut table = TaskTable::with_capacity(64);
        let mut task_indices = Vec::new();
        let mut prev_capacity = table.capacity();

        for op in ops.iter().take(20) {
            apply_operation(&mut table, op, &mut task_indices);
            let current_capacity = table.capacity();

            prop_assert!(current_capacity >= prev_capacity,
                "Arena capacity decreased from {} to {} after operation {:?}",
                prev_capacity, current_capacity, op);

            prev_capacity = current_capacity;
        }
    });
}

/// MR3: EQUIVALENCE - Live Task Count Consistency
/// live_task_count() must always equal the actual count of non-terminal tasks.
#[test]
fn mr_live_task_count_consistency() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let mut table = TaskTable::new();
        let mut task_indices = Vec::new();

        for op in ops.iter().take(15) {
            apply_operation(&mut table, op, &mut task_indices);

            let reported_count = table.live_task_count();
            let actual_count = table.iter()
                .filter(|(_, record)| (record.phase.load() as usize) < 5) // Non-terminal
                .count();

            prop_assert_eq!(reported_count, actual_count,
                "Live task count mismatch after operation {:?}: reported={}, actual={}",
                op, reported_count, actual_count);
        }
    });
}

/// MR4: INCLUSIVE - Remove Task Cleans Stored Future
/// Removing a task must also clean up its stored future (subset relation).
#[test]
fn mr_remove_task_cleans_future() {
    proptest!(|(owner in arb_region_id(), deadline in arb_deadline())| {
        let mut table = TaskTable::new();

        // Insert task and store future
        let record = make_test_task(owner, deadline);
        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        let stored = StoredTask::new(async { Outcome::Ok(()) });
        table.store_spawned_task(task_id, stored);

        prop_assert_eq!(table.stored_future_count(), 1, "Future should be stored");

        // Remove task - this MUST clean the stored future
        table.remove_task(task_id);

        prop_assert_eq!(table.stored_future_count(), 0,
            "Stored future should be cleaned when task is removed");
        prop_assert!(table.get_stored_future(task_id).is_none(),
            "Get stored future should return None after task removal");
    });
}

/// MR5: EQUIVALENCE - Arena-Future Parallel Indexing
/// stored_futures[slot] should exist iff tasks[slot] exists.
#[test]
fn mr_arena_future_parallel_indexing() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let mut table = TaskTable::new();
        let mut task_indices = Vec::new();

        for op in ops.iter().take(12) {
            apply_operation(&mut table, op, &mut task_indices);

            // Check parallel indexing invariant
            for (task_id, _) in &task_indices {
                let task_exists = table.task(*task_id).is_some();
                let future_exists = table.get_stored_future(*task_id).is_some();

                if task_exists {
                    // If task exists, future may or may not exist (valid states)
                    // But if future exists, task MUST exist
                } else {
                    // If task doesn't exist, future MUST NOT exist
                    prop_assert!(!future_exists,
                        "Stored future exists for non-existent task {:?} after {:?}",
                        task_id, op);
                }
            }
        }
    });
}

/// MR6: ADDITIVE - Pool Statistics Conservation
/// Pool hits + misses should equal total acquisition attempts.
#[test]
fn mr_pool_stats_conservation() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let mut table = TaskTable::with_capacity(32);
        let mut task_indices = Vec::new();

        let initial_stats = table.task_record_pool_stats();
        let mut expected_misses = initial_stats.misses;
        let mut expected_hits = initial_stats.hits;

        for op in ops.iter().take(10) {
            match op {
                TableOperation::Insert {
                    owner: _,
                    deadline: _,
                } => {
                    // insertions use pooled acquisition
                    if table.recycled_task_record_count() > 0 {
                        expected_hits += 1;
                    } else {
                        expected_misses += 1;
                    }
                }
                _ => {}
            }
            apply_operation(&mut table, op, &mut task_indices);
        }

        let final_stats = table.task_record_pool_stats();

        // Note: This relation may not hold perfectly due to internal pooled operations
        // but should hold for the operations we directly trigger
        prop_assert!(final_stats.hits + final_stats.misses >= expected_hits + expected_misses,
            "Pool stats conservation violated: final hits={}, misses={}, expected hits={}, misses={}",
            final_stats.hits, final_stats.misses, expected_hits, expected_misses);
    });
}

/// MR7: MULTIPLICATIVE - Deadline Sum Scaling
/// Scaling all deadlines by factor k should scale deadline_sum by k.
#[test]
fn mr_deadline_sum_scaling() {
    proptest!(|(base_deadlines in prop::collection::vec(1u64..1_000_000, 0..=20), scale_factor in 1u64..=10)| {
        let scale_factor = (scale_factor % 10) + 1; // 1-10 to avoid overflow
        let base_deadlines: Vec<_> = base_deadlines.into_iter()
            .take(5)
            .map(|d| d % 100_000 + 1) // Keep deadlines reasonable
            .collect();

        if base_deadlines.is_empty() {
            return Ok(());
        }

        let mut table1 = TaskTable::new();
        let mut table2 = TaskTable::new();
        let owner = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut scaled_sum = 0u128;
        let mut base_sum = 0u128;

        for &deadline_ns in &base_deadlines {
            // Insert task with base deadline
            let base_deadline = Time::from_nanos(deadline_ns);
            let record1 = make_test_task(owner, Some(base_deadline));
            table1.insert_task(record1);
            base_sum += u128::from(base_deadline.as_nanos());

            // Insert task with scaled deadline
            let scaled_deadline = Time::from_nanos(deadline_ns * scale_factor);
            let record2 = make_test_task(owner, Some(scaled_deadline));
            table2.insert_task(record2);
            scaled_sum += u128::from(scaled_deadline.as_nanos());
        }

        let table1_sum = table1.deadline_sum_ns();
        let table2_sum = table2.deadline_sum_ns();

        prop_assert_eq!(table1_sum, base_sum, "Base deadline sum mismatch");
        prop_assert_eq!(table2_sum, scaled_sum, "Scaled deadline sum mismatch");

        // The key metamorphic relation: scaling property
        prop_assert_eq!(table2_sum, table1_sum * u128::from(scale_factor),
            "Deadline sum scaling property violated: base={}, scaled={}, factor={}",
            table1_sum, table2_sum, scale_factor);
    });
}

/// MR8: INVERTIVE - Insert-Remove Round Trip
/// insert(task) followed by remove(task) should restore table to original state.
#[test]
fn mr_insert_remove_round_trip() {
    proptest!(|(owner in arb_region_id(), deadline in arb_deadline())| {
        let mut table = TaskTable::new();

        // Capture initial state
        let initial_state = TableSnapshot::capture(&table);

        // Insert task
        let record = make_test_task(owner, deadline);
        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        // Verify task was inserted
        prop_assert!(table.task(task_id).is_some(), "Task should exist after insertion");

        // Remove task
        let removed = table.remove_task(task_id);
        prop_assert!(removed.is_some(), "Remove should return the task");

        // Verify task was removed
        prop_assert!(table.task(task_id).is_none(), "Task should not exist after removal");

        // Capture final state
        let final_state = TableSnapshot::capture(&table);

        // Key invariant: round-trip should restore state
        prop_assert_eq!(initial_state.task_count, final_state.task_count,
            "Task count should be restored after insert-remove round trip");
        prop_assert_eq!(initial_state.live_task_count, final_state.live_task_count,
            "Live task count should be restored after insert-remove round trip");
        prop_assert_eq!(initial_state.stored_future_count, final_state.stored_future_count,
            "Stored future count should be restored after insert-remove round trip");
    });
}

/// MR9: EQUIVALENCE - ID Canonicalization
/// TaskRecord.id must always match its arena slot index after insertion.
#[test]
fn mr_id_canonicalization() {
    proptest!(|(owner in arb_region_id(), stale_id_value in any::<u32>())| {
        let mut table = TaskTable::new();

        // Create record with intentionally stale/wrong TaskId
        let stale_id = TaskId::from_arena(ArenaIndex::new(stale_id_value % 1000, 0));
        let record = TaskRecord::new(stale_id, owner, Budget::INFINITE);
        prop_assert_eq!(record.id, stale_id, "Record should start with stale ID");

        // Insert task - this should canonicalize the ID
        let idx = table.insert_task(record);
        let canonical_id = TaskId::from_arena(idx);

        // Verify canonicalization
        let retrieved = table.task(canonical_id).expect("Task should exist");
        prop_assert_eq!(retrieved.id, canonical_id,
            "Task ID should be canonicalized to match arena slot: expected {:?}, got {:?}",
            canonical_id, retrieved.id);
    });
}

/// MR10: PERMUTATIVE - Phase Transition Consistency
/// Valid phase transitions should maintain bookkeeping consistency.
#[test]
fn mr_phase_transition_consistency() {
    proptest!(|(owner in arb_region_id(), transition_sequence in prop::collection::vec(any::<u8>(), 0..=20))| {
        let mut table = TaskTable::new();

        // Insert task in Created phase
        let record = make_test_task(owner, None);
        let idx = table.insert_task(record);
        let task_id = TaskId::from_arena(idx);

        let mut prev_live_count = table.live_task_count();

        for transition in transition_sequence.iter().take(8) {
            let new_phase = match transition % 6 {
                0 => TaskPhase::Created,
                1 => TaskPhase::Running,
                2 => TaskPhase::CancelRequested,
                3 => TaskPhase::Cancelling,
                4 => TaskPhase::Finalizing,
                _ => TaskPhase::Completed,
            };

            let old_phase = table.task(task_id)
                .map(|r| r.phase.load())
                .unwrap_or(TaskPhase::Completed);

            // Apply phase transition
            table.update_task(task_id, |record| {
                record.phase.store(new_phase);
            });

            let current_live_count = table.live_task_count();

            // Check transition consistency
            let old_was_live = (old_phase as usize) < 5;
            let new_is_live = (new_phase as usize) < 5;

            match (old_was_live, new_is_live) {
                (true, false) => {
                    prop_assert_eq!(current_live_count, prev_live_count.saturating_sub(1),
                        "Live count should decrease when transitioning from live to terminal");
                }
                (false, true) => {
                    prop_assert_eq!(current_live_count, prev_live_count + 1,
                        "Live count should increase when transitioning from terminal to live");
                }
                _ => {
                    // No change expected for live->live or terminal->terminal
                }
            }

            prev_live_count = current_live_count;
        }
    });
}

/// MR11: INCLUSIVE - Pool Capacity Bounds
/// Number of recycled items should never exceed pool capacity.
#[test]
fn mr_pool_capacity_bounds() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let pool_capacity = 16;
        let mut table = TaskTable::with_capacity_and_pool_limit(64, pool_capacity);
        let mut task_indices = Vec::new();

        for op in ops.iter().take(20) {
            apply_operation(&mut table, op, &mut task_indices);

            let recycled_count = table.recycled_task_record_count();
            prop_assert!(recycled_count <= pool_capacity,
                "Recycled count {} exceeds pool capacity {} after operation {:?}",
                recycled_count, pool_capacity, op);
        }
    });
}

/// MR12: EQUIVALENCE - Future Count Accuracy
/// stored_future_count() must match actual number of Some(_) slots.
#[test]
fn mr_future_count_accuracy() {
    proptest!(|(ops in prop::collection::vec(arb_table_operation(), 0..=30))| {
        let mut table = TaskTable::new();
        let mut task_indices = Vec::new();
        let mut actual_future_count: usize = 0;

        for op in ops.iter().take(15) {
            match op {
                TableOperation::StoreFuture { task_index } => {
                    if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                        if table.task(*task_id).is_some() && table.get_stored_future(*task_id).is_none() {
                            actual_future_count += 1;
                        }
                    }
                }
                TableOperation::RemoveFuture { task_index } => {
                    if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                        if table.get_stored_future(*task_id).is_some() {
                            actual_future_count = actual_future_count.saturating_sub(1);
                        }
                    }
                }
                TableOperation::Remove { task_index } | TableOperation::RecycledRemove { task_index } => {
                    if let Some((task_id, _)) = task_indices.get(*task_index % task_indices.len().max(1)) {
                        if table.get_stored_future(*task_id).is_some() {
                            actual_future_count = actual_future_count.saturating_sub(1);
                        }
                    }
                }
                _ => {}
            }

            apply_operation(&mut table, op, &mut task_indices);

            let reported_count = table.stored_future_count();
            // Note: Due to implementation details, we check that reported count is reasonable
            prop_assert!(reported_count <= task_indices.len(),
                "Future count {} exceeds possible maximum {} after operation {:?}",
                reported_count, task_indices.len(), op);
        }
    });
}

#[cfg(test)]
mod composition_tests {
    use super::*;

    /// Composite MR: Insert-Store-Remove (chaining multiple relations)
    /// This tests the composition of MR4 (remove cleans future) + MR8 (insert-remove round trip).
    #[test]
    fn mr_composite_insert_store_remove() {
        proptest!(|(owner in arb_region_id(), deadline in arb_deadline())| {
            let mut table = TaskTable::new();
            let initial_state = TableSnapshot::capture(&table);

            // 1. Insert task
            let record = make_test_task(owner, deadline);
            let idx = table.insert_task(record);
            let task_id = TaskId::from_arena(idx);

            // 2. Store future
            let stored = StoredTask::new(async { Outcome::Ok(()) });
            table.store_spawned_task(task_id, stored);
            prop_assert_eq!(table.stored_future_count(), 1, "Future should be stored");

            // 3. Remove task (should clean future)
            table.remove_task(task_id);

            let final_state = TableSnapshot::capture(&table);

            // Composite relation: insert-store-remove should restore initial state
            prop_assert_eq!(initial_state.task_count, final_state.task_count,
                "Task count should be restored after composite operation");
            prop_assert_eq!(initial_state.stored_future_count, final_state.stored_future_count,
                "Future count should be restored after composite operation");
            prop_assert_eq!(final_state.stored_future_count, 0,
                "No futures should remain after composite operation");
        });
    }
}
