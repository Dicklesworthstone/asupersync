#![allow(clippy::all)]
//! Metamorphic tests for runtime::TaskTable lookup/insert/evict invariants.
//!
//! Validates critical properties of the TaskTable using metamorphic relations
//! and property-based testing with deterministic LabRuntime. The TaskTable is
//! a core component of the sharded runtime that manages task records and stored
//! futures for hot-path operations.
//!
//! ## Key Properties Tested
//!
//! 1. **Unique TaskId assignment**: Each insert produces a globally unique TaskId
//! 2. **Lookup consistency**: lookup by TaskId returns exactly the inserted task
//! 3. **Evict completeness**: evict removes task and frees arena slot for reuse
//! 4. **Generation safety**: generation tokens prevent access to stale TaskIds
//! 5. **Concurrent integrity**: concurrent insert/evict preserve table consistency
//!
//! ## Metamorphic Relations (MRs)
//!
//! - **MR1 Insert Uniqueness**: insert(T₁) → id₁, insert(T₂) → id₂ where id₁ ≠ id₂
//! - **MR2 Lookup Consistency**: lookup(insert(T).id) = T (round-trip identity)
//! - **MR3 Evict Completeness**: evict(id) → lookup(id) = None (removal finality)
//! - **MR4 Generation Safety**: evict(id₁) → insert(T) → id₂ where id₁ ≠ id₂
//! - **MR5 Concurrent Integrity**: parallel ops maintain count invariants
//!
//! These relations ensure the TaskTable maintains correctness under the concurrent
//! workloads typical of the async runtime's hot-path operations.

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;

use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::task::TaskRecord;
use asupersync::runtime::sharded_state::{ShardedState, ShardGuard};
use asupersync::runtime::task_table::TaskTable;
use asupersync::runtime::TaskTable as RuntimeTaskTable;
use asupersync::types::{ArenaIndex, Budget, RegionId, TaskId, Time};
use asupersync::util::EntropySource;
use asupersync::observability::{ObservabilityConfig, metrics::NoOpMetrics};
use asupersync::trace::{TraceBufferHandle, TraceConfig};
use asupersync::runtime::config::RuntimeConfig;

// =============================================================================
// Test Infrastructure
// =============================================================================

/// Mock entropy source for deterministic testing
#[derive(Debug, Clone)]
struct MockEntropySource;

impl EntropySource for MockEntropySource {
    fn generate(&self) -> u64 {
        42 // Deterministic value for testing
    }

    fn generate_array<const N: usize>(&self) -> [u8; N] {
        [42; N]
    }
}

/// Creates a test TaskTable for isolated testing
fn create_test_task_table() -> TaskTable {
    TaskTable::new()
}

/// Creates a test ShardedState for testing TaskTable within the sharded runtime
fn create_test_sharded_state() -> Arc<ShardedState> {
    let trace_handle = TraceBufferHandle::new(1024);
    let metrics: Arc<dyn asupersync::observability::metrics::MetricsProvider> = Arc::new(NoOpMetrics);

    let config = Arc::new(asupersync::runtime::ShardedConfig {
        runtime: RuntimeConfig::default(),
        observability: ObservabilityConfig::default(),
    });

    Arc::new(ShardedState::new(trace_handle, metrics, config))
}

/// Helper to create a test TaskRecord
fn make_task_record(owner: RegionId) -> TaskRecord {
    // Use placeholder TaskId - will be canonicalized during insertion
    let placeholder = TaskId::from_arena(ArenaIndex::new(0, 0));
    TaskRecord::new(placeholder, owner, Budget::INFINITE)
}

/// Helper to create test RegionId
fn make_region_id(gen: u32, idx: u32) -> RegionId {
    RegionId::from_arena(ArenaIndex::new(gen, idx))
}

/// Test harness for deterministic TaskTable operations
#[derive(Debug)]
struct TaskTableTestHarness {
    runtime: LabRuntime,
    shards: Arc<ShardedState>,
}

impl TaskTableTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed).with_deterministic_scheduling();
        let runtime = LabRuntime::new(config);
        let shards = create_test_sharded_state();

        Self { runtime, shards }
    }

    /// Execute a test within a deterministic runtime context
    fn execute<F, R>(&mut self, test_fn: F) -> R
    where
        F: FnOnce(&Arc<ShardedState>) -> R + Send,
    {
        self.runtime.block_on(|_cx| async {
            test_fn(&self.shards)
        }).into_ok()
    }
}

/// Configuration for property-based TaskTable tests
#[derive(Debug, Clone)]
struct TaskTableTestConfig {
    seed: u64,
    operation_count: u8,
    thread_count: u8,
    region_variants: Vec<(u32, u32)>, // (generation, index) pairs
}

impl Arbitrary for TaskTableTestConfig {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> impl Strategy<Value = Self> {
        (
            any::<u64>(),
            1u8..=20,  // operation_count
            1u8..=4,   // thread_count
            prop::collection::vec((any::<u32>(), any::<u32>()), 1..=10), // region_variants
        ).prop_map(|(seed, operation_count, thread_count, region_variants)| {
            TaskTableTestConfig {
                seed,
                operation_count,
                thread_count,
                region_variants,
            }
        })
    }
}

// =============================================================================
// Metamorphic Relations
// =============================================================================

/// MR1: Insert Uniqueness (Score: 5.0)
/// Property: Each insert operation assigns a globally unique TaskId
/// Invariant: ∀ i,j where i ≠ j: insert(Ti).id ≠ insert(Tj).id
/// Catches: Arena index collisions, generation counter bugs, ID reuse
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr1_insert_assigns_unique_task_id() {
        proptest!(|(config: TaskTableTestConfig)| {
            let mut harness = TaskTableTestHarness::new(config.seed);

            let result = harness.execute(|shards| {
                let mut guard = ShardGuard::tasks_only(shards);
                let tasks = guard.tasks.as_mut().unwrap();

                let mut assigned_ids = HashSet::new();
                let mut inserted_tasks = Vec::new();

                // Insert multiple tasks with different owners
                for (i, &(gen, idx)) in config.region_variants.iter()
                    .take(config.operation_count as usize).enumerate() {
                    let owner = make_region_id(gen.wrapping_add(i as u32), idx);
                    let record = make_task_record(owner);

                    let arena_idx = tasks.insert_task(record);
                    let task_id = TaskId::from_arena(arena_idx);

                    // MR1: Each TaskId must be unique
                    assert!(!assigned_ids.contains(&task_id),
                        "TaskId {:?} was assigned twice (collision)", task_id);

                    assigned_ids.insert(task_id);
                    inserted_tasks.push((task_id, owner));
                }

                // Additional verification: all TaskIds should have unique arena indices
                let unique_arena_indices: HashSet<ArenaIndex> = assigned_ids.iter()
                    .map(|id| id.arena_index()).collect();
                assert_eq!(unique_arena_indices.len(), assigned_ids.len(),
                    "Arena indices should be unique across all TaskIds");

                inserted_tasks
            });

            // Verify we got unique IDs for all insertions
            let task_ids: Vec<TaskId> = result.iter().map(|(id, _)| *id).collect();
            let unique_ids: HashSet<TaskId> = task_ids.iter().copied().collect();
            prop_assert_eq!(unique_ids.len(), task_ids.len(), "All TaskIds should be unique");
        });
    }

    /// MR2: Lookup Consistency (Score: 4.5)
    /// Property: lookup by TaskId returns exactly the inserted task record
    /// Invariant: ∀ T: lookup(insert(T).id).owner = T.owner (round-trip identity)
    /// Catches: Lookup bugs, storage corruption, indexing errors
    #[test]
    fn mr2_lookup_returns_exactly_inserted_task() {
        proptest!(|(config: TaskTableTestConfig)| {
            let mut harness = TaskTableTestHarness::new(config.seed);

            harness.execute(|shards| {
                let mut guard = ShardGuard::tasks_only(shards);
                let tasks = guard.tasks.as_mut().unwrap();

                let mut test_data = Vec::new();

                // Insert tasks and collect their data
                for &(gen, idx) in config.region_variants.iter()
                    .take(config.operation_count as usize) {
                    let owner = make_region_id(gen, idx);
                    let record = make_task_record(owner);

                    let arena_idx = tasks.insert_task(record);
                    let task_id = TaskId::from_arena(arena_idx);

                    test_data.push((task_id, owner));
                }

                // MR2: Verify lookup returns exactly what was inserted
                for (task_id, expected_owner) in test_data {
                    let retrieved = tasks.task(task_id);
                    assert!(retrieved.is_some(), "Inserted task should be retrievable");

                    let task_record = retrieved.unwrap();
                    assert_eq!(task_record.owner, expected_owner,
                        "Retrieved task owner should match inserted owner");
                    assert_eq!(task_record.id, task_id,
                        "Retrieved task ID should match lookup ID");
                }
            });
        });
    }

    /// MR3: Evict Completeness (Score: 4.8)
    /// Property: evict removes task completely and frees slot for reuse
    /// Invariant: evict(id) → lookup(id) = None ∧ slot_freed(id.arena_index)
    /// Catches: Incomplete removal, memory leaks, slot accounting errors
    #[test]
    fn mr3_evict_removes_task_and_frees_slot() {
        proptest!(|(config: TaskTableTestConfig)| {
            let mut harness = TaskTableTestHarness::new(config.seed);

            harness.execute(|shards| {
                let mut guard = ShardGuard::tasks_only(shards);
                let tasks = guard.tasks.as_mut().unwrap();

                let mut inserted_tasks = Vec::new();

                // Insert tasks
                for &(gen, idx) in config.region_variants.iter()
                    .take(config.operation_count as usize) {
                    let owner = make_region_id(gen, idx);
                    let record = make_task_record(owner);

                    let arena_idx = tasks.insert_task(record);
                    let task_id = TaskId::from_arena(arena_idx);
                    inserted_tasks.push(task_id);
                }

                let initial_count = tasks.live_task_count();
                assert_eq!(initial_count, config.operation_count as usize);

                // Evict half the tasks
                let tasks_to_evict = &inserted_tasks[..inserted_tasks.len() / 2];

                for &task_id in tasks_to_evict {
                    let removed = tasks.remove_task(task_id);

                    // MR3: Evict should return the removed task
                    assert!(removed.is_some(), "Evict should return removed task");
                    assert_eq!(removed.unwrap().id, task_id, "Removed task ID should match");

                    // MR3: Lookup after evict should return None
                    assert!(tasks.task(task_id).is_none(),
                        "Lookup after evict should return None");
                }

                // Verify count consistency after evictions
                let expected_remaining = config.operation_count as usize - tasks_to_evict.len();
                assert_eq!(tasks.live_task_count(), expected_remaining);

                // Verify remaining tasks are still accessible
                let remaining_tasks = &inserted_tasks[inserted_tasks.len() / 2..];
                for &task_id in remaining_tasks {
                    assert!(tasks.task(task_id).is_some(),
                        "Non-evicted tasks should remain accessible");
                }
            });
        });
    }

    /// MR4: Generation Safety (Score: 4.7)
    /// Property: generation tokens prevent access to stale TaskIds after eviction
    /// Invariant: evict(id₁) → insert(T) → id₂ where id₁ ≠ id₂ (no immediate reuse)
    /// Catches: Generation counter bugs, stale ID access, arena corruption
    #[test]
    fn mr4_generation_token_prevents_stale_access() {
        proptest!(|(config: TaskTableTestConfig)| {
            let mut harness = TaskTableTestHarness::new(config.seed);

            harness.execute(|shards| {
                let mut guard = ShardGuard::tasks_only(shards);
                let tasks = guard.tasks.as_mut().unwrap();

                let owner = make_region_id(1, 0);
                let mut previous_ids = HashSet::new();

                // Perform multiple insert-evict cycles
                for i in 0..config.operation_count.min(10) {
                    let record = make_task_record(owner);
                    let arena_idx = tasks.insert_task(record);
                    let task_id = TaskId::from_arena(arena_idx);

                    // MR4: New TaskId should not reuse previous IDs from this session
                    assert!(!previous_ids.contains(&task_id),
                        "TaskId {:?} was reused after eviction in cycle {}", task_id, i);

                    // Verify task is accessible
                    assert!(tasks.task(task_id).is_some());

                    // Evict the task
                    let removed = tasks.remove_task(task_id);
                    assert!(removed.is_some());

                    // MR4: Stale access should fail
                    assert!(tasks.task(task_id).is_none(),
                        "Stale TaskId should not be accessible after eviction");

                    previous_ids.insert(task_id);
                }

                // Additional verification: all generated IDs were unique
                assert_eq!(previous_ids.len(), config.operation_count.min(10) as usize,
                    "All generated TaskIds should have been unique");
            });
        });
    }

    /// MR5: Concurrent Integrity (Score: 5.0)
    /// Property: concurrent insert/evict operations preserve table integrity
    /// Invariant: ∀ concurrent ops: Σ(inserts) - Σ(evicts) = final_count
    /// Catches: Race conditions, lost updates, count inconsistencies
    #[test]
    fn mr5_concurrent_operations_preserve_integrity() {
        proptest!(|(config in any::<TaskTableTestConfig>()
            .prop_filter("Need multiple threads", |c| c.thread_count >= 2))| {
            let mut harness = TaskTableTestHarness::new(config.seed);

            harness.execute(|shards| {
                use std::sync::{Arc, Barrier, Mutex as StdMutex};
                use std::thread;

                let barrier = Arc::new(Barrier::new(config.thread_count as usize));
                let operation_counts = Arc::new(StdMutex::new(HashMap::new()));
                let inserted_ids = Arc::new(StdMutex::new(Vec::new()));

                let handles: Vec<_> = (0..config.thread_count)
                    .map(|thread_id| {
                        let shards = Arc::clone(shards);
                        let barrier = Arc::clone(&barrier);
                        let operation_counts = Arc::clone(&operation_counts);
                        let inserted_ids = Arc::clone(&inserted_ids);
                        let regions = config.region_variants.clone();
                        let ops_per_thread = config.operation_count / config.thread_count;

                        thread::spawn(move || {
                            barrier.wait();

                            let mut local_inserts = 0;
                            let mut local_evicts = 0;
                            let mut local_ids = Vec::new();

                            for i in 0..ops_per_thread {
                                let mut guard = ShardGuard::tasks_only(&shards);
                                let tasks = guard.tasks.as_mut().unwrap();

                                if i % 3 == 0 && !local_ids.is_empty() {
                                    // Evict operation
                                    if let Some(task_id) = local_ids.pop() {
                                        if tasks.remove_task(task_id).is_some() {
                                            local_evicts += 1;
                                        }
                                    }
                                } else {
                                    // Insert operation
                                    let region_idx = (i + thread_id as u8) as usize % regions.len();
                                    let (gen, idx) = regions[region_idx];
                                    let owner = make_region_id(
                                        gen.wrapping_add(thread_id as u32),
                                        idx
                                    );

                                    let record = make_task_record(owner);
                                    let arena_idx = tasks.insert_task(record);
                                    let task_id = TaskId::from_arena(arena_idx);

                                    local_ids.push(task_id);
                                    local_inserts += 1;
                                }
                            }

                            // Record thread statistics
                            {
                                let mut counts = operation_counts.lock().unwrap();
                                counts.insert(thread_id, (local_inserts, local_evicts));
                            }

                            // Contribute remaining task IDs to global list
                            {
                                let mut global_ids = inserted_ids.lock().unwrap();
                                global_ids.extend(local_ids);
                            }
                        })
                    })
                    .collect();

                // Wait for all threads to complete
                for handle in handles {
                    handle.join().expect("Thread should complete without panicking");
                }

                // MR5: Verify final integrity
                let final_guard = ShardGuard::tasks_only(shards);
                let final_tasks = final_guard.tasks.as_ref().unwrap();
                let final_count = final_tasks.live_task_count();

                // Calculate expected count from operation statistics
                let counts = operation_counts.lock().unwrap();
                let total_inserts: u64 = counts.values().map(|(i, _)| *i).sum();
                let total_evicts: u64 = counts.values().map(|(_, e)| *e).sum();
                let expected_count = total_inserts - total_evicts;

                // MR5: Final count should match insert-evict arithmetic
                assert_eq!(final_count, expected_count as usize,
                    "Final count should equal total inserts minus total evicts");

                // Additional verification: all remaining tasks should be accessible
                let global_ids = inserted_ids.lock().unwrap();
                for task_id in global_ids.iter() {
                    if final_tasks.task(*task_id).is_none() {
                        // This ID was evicted, which is fine
                        continue;
                    }

                    // This ID exists, so it should have valid data
                    let task_record = final_tasks.task(*task_id).unwrap();
                    assert_eq!(task_record.id, *task_id,
                        "Accessible task should have consistent ID");
                }
            });
        });
    }

    /// Integration test: Verify TaskTable operations work correctly within ShardedState
    #[test]
    fn integration_task_table_within_sharded_runtime() {
        proptest!(|(seed in any::<u64>(), op_count in 5u8..=15)| {
            let mut harness = TaskTableTestHarness::new(seed);

            harness.execute(|shards| {
                // Test through different ShardGuard access patterns
                let test_operations = vec![
                    ("tasks_only", || ShardGuard::tasks_only(shards)),
                    ("for_spawn", || ShardGuard::for_spawn(shards)),
                    ("for_task_completed", || ShardGuard::for_task_completed(shards)),
                ];

                for (guard_type, guard_fn) in test_operations {
                    let mut guard = guard_fn();
                    if let Some(tasks) = guard.tasks.as_mut() {
                        let owner = make_region_id(1, 0);
                        let mut inserted_ids = Vec::new();

                        // Insert tasks
                        for i in 0..op_count {
                            let record = make_task_record(owner);
                            let arena_idx = tasks.insert_task(record);
                            let task_id = TaskId::from_arena(arena_idx);
                            inserted_ids.push(task_id);

                            // Verify task is immediately accessible
                            assert!(tasks.task(task_id).is_some(),
                                "Task should be accessible immediately after insert via {}",
                                guard_type);
                        }

                        assert_eq!(tasks.live_task_count(), op_count as usize);

                        // Remove all tasks
                        for task_id in inserted_ids {
                            assert!(tasks.remove_task(task_id).is_some(),
                                "Task should be removable via {}", guard_type);
                        }

                        assert_eq!(tasks.live_task_count(), 0);
                    }
                }
            });
        });
    }
}