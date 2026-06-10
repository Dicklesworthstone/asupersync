//! Metamorphic tests for RegionHeap ordering invariants.
//!
//! These tests verify invariant relationships that must hold for correct
//! allocator behavior, focusing on scenarios where computing exact expected
//! final states is intractable due to complex alloc/dealloc sequences.

use crate::runtime::region_heap::{HeapIndex, RegionHeap, global_alloc_count};

/// Test value type for allocator testing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestValue {
    id: u32,
    data: Vec<u8>,
}

impl TestValue {
    fn new(id: u32, size: usize) -> Self {
        Self {
            id,
            data: vec![id as u8; size],
        }
    }
}

/// Generate sequences of heap operations.
#[derive(Debug, Clone)]
enum HeapOperation {
    Alloc { id: u32, size: usize },
    Dealloc { target_id: u32 },
    AllocMany { count: u32, base_id: u32 },
    DeallocMany { target_ids: Vec<u32> },
    ReclaimAll,
}

/// Execute a sequence of operations and track allocated indices.
fn execute_operations(heap: &mut RegionHeap, operations: &[HeapOperation]) -> OperationResults {
    let mut allocated_indices: std::collections::HashMap<u32, HeapIndex> =
        std::collections::HashMap::new();
    let mut allocation_count = 0;
    let mut deallocation_count = 0;
    let mut reclaim_count = 0;

    for op in operations {
        match op {
            HeapOperation::Alloc { id, size } => {
                let value = TestValue::new(*id, *size);
                let index = heap.alloc(value);
                allocated_indices.insert(*id, index);
                allocation_count += 1;
            }
            HeapOperation::Dealloc { target_id } => {
                if let Some(index) = allocated_indices.remove(target_id) {
                    if heap.dealloc(index) {
                        deallocation_count += 1;
                    }
                }
            }
            HeapOperation::AllocMany { count, base_id } => {
                for i in 0..*count {
                    let id = base_id + i;
                    let value = TestValue::new(id, 64); // Fixed size for bulk ops
                    let index = heap.alloc(value);
                    allocated_indices.insert(id, index);
                    allocation_count += 1;
                }
            }
            HeapOperation::DeallocMany { target_ids } => {
                for target_id in target_ids {
                    if let Some(index) = allocated_indices.remove(target_id) {
                        if heap.dealloc(index) {
                            deallocation_count += 1;
                        }
                    }
                }
            }
            HeapOperation::ReclaimAll => {
                let live_before = heap.len();
                heap.reclaim_all();
                allocated_indices.clear();
                reclaim_count += live_before;
            }
        }
    }

    OperationResults {
        allocation_count,
        deallocation_count,
        reclaim_count,
        remaining_allocations: allocated_indices,
    }
}

#[derive(Debug)]
struct OperationResults {
    allocation_count: usize,
    deallocation_count: usize,
    reclaim_count: usize,
    remaining_allocations: std::collections::HashMap<u32, HeapIndex>,
}

#[cfg(test)]
mod metamorphic_tests {
    use super::*;

    /// MR1: Statistics Conservation (Additive)
    /// Property: stats.allocations - stats.reclaimed = stats.live
    #[test]
    fn mr_statistics_conservation() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_statistics_conservation");

        let mut heap = RegionHeap::new();

        // Test across various operation sequences
        let operation_sequences = vec![
            vec![
                HeapOperation::Alloc { id: 1, size: 64 },
                HeapOperation::Alloc { id: 2, size: 128 },
                HeapOperation::Dealloc { target_id: 1 },
            ],
            vec![
                HeapOperation::AllocMany {
                    count: 5,
                    base_id: 10,
                },
                HeapOperation::DeallocMany {
                    target_ids: vec![10, 12, 14],
                },
            ],
            vec![
                HeapOperation::Alloc { id: 100, size: 32 },
                HeapOperation::Alloc { id: 101, size: 64 },
                HeapOperation::ReclaimAll,
            ],
        ];

        for (i, ops) in operation_sequences.iter().enumerate() {
            let _results = execute_operations(&mut heap, ops);
            let final_stats = heap.stats();

            // Conservation law: allocations - reclaimed = live
            assert_eq!(
                final_stats.allocations - final_stats.reclaimed,
                final_stats.live,
                "Statistics conservation violated in sequence {}: allocations={}, reclaimed={}, live={}",
                i,
                final_stats.allocations,
                final_stats.reclaimed,
                final_stats.live
            );

            // Length consistency: heap.len() = stats.live
            assert_eq!(
                heap.len() as u64,
                final_stats.live,
                "Length inconsistent with live count in sequence {}: len={}, live={}",
                i,
                heap.len(),
                final_stats.live
            );
        }

        crate::test_complete!("mr_statistics_conservation");
    }

    /// MR2: Global Count Consistency (Equivalence)
    /// Property: The allocation count tracks actual allocations.
    ///
    /// NOTE ON ISOLATION: `global_alloc_count()` reads a single PROCESS-GLOBAL
    /// `AtomicU64` shared by every `RegionHeap` in the process. Under the full
    /// parallel test run, other tests (and runtime code) allocate/free via
    /// `RegionHeap` concurrently, so the *absolute value* of the global counter
    /// — and even a delta between two reads of it — is non-deterministic. The
    /// genuine, load-independent invariant is per-heap: each heap's own `stats`
    /// (allocations/reclaimed/live) and `len()` must track its operations
    /// exactly. We assert those isolated per-heap invariants here, plus the
    /// monotonic global property that the global counter never drops below the
    /// number of allocations our heaps still hold live (a one-directional bound
    /// that concurrent allocations cannot violate).
    #[test]
    fn mr_global_count_consistency() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_global_count_consistency");

        let mut heap1 = RegionHeap::new();
        let mut heap2 = RegionHeap::new();

        // Scenario 1: Single heap operations — per-heap stats track allocations.
        let idx1 = heap1.alloc(TestValue::new(1, 64));
        let _idx2 = heap1.alloc(TestValue::new(2, 128));
        assert_eq!(heap1.stats().allocations, 2, "heap1 alloc count");
        assert_eq!(heap1.stats().live, 2, "heap1 live count after 2 allocs");
        assert_eq!(heap1.len(), 2, "heap1 len after 2 allocs");

        // Scenario 2: A second heap is independent.
        let _idx3 = heap2.alloc(TestValue::new(3, 32));
        assert_eq!(heap2.stats().allocations, 1, "heap2 alloc count");
        assert_eq!(heap2.stats().live, 1, "heap2 live count");
        // heap1 is unaffected by heap2's allocation.
        assert_eq!(heap1.stats().live, 2, "heap1 live unaffected by heap2");

        // The process-global counter must be at least the live allocations our
        // heaps currently hold. This bound is robust to concurrent allocations
        // by other parallel tests (which only ever push it higher).
        assert!(
            global_alloc_count() >= heap1.stats().live + heap2.stats().live,
            "global count must cover our live allocations"
        );

        // Scenario 3: Deallocation decrements the owning heap's live count.
        assert!(heap1.dealloc(idx1), "dealloc idx1");
        assert_eq!(heap1.stats().live, 1, "heap1 live after dealloc");
        assert_eq!(heap1.stats().reclaimed, 1, "heap1 reclaimed after dealloc");
        assert_eq!(heap1.len(), 1, "heap1 len after dealloc");

        // Scenario 4: reclaim_all empties heap2 only.
        heap2.reclaim_all();
        assert_eq!(heap2.stats().live, 0, "heap2 live after reclaim_all");
        assert_eq!(heap2.len(), 0, "heap2 len after reclaim_all");
        // heap1 still holds its remaining live allocation.
        assert_eq!(heap1.stats().live, 1, "heap1 live unaffected by heap2 reclaim");

        // Cleanup: reclaim_all empties heap1 as well.
        heap1.reclaim_all();
        assert_eq!(heap1.stats().live, 0, "heap1 live after cleanup");
        assert_eq!(heap1.len(), 0, "heap1 len after cleanup");

        crate::test_complete!("mr_global_count_consistency");
    }

    /// MR3: Generation Monotonicity (Permutative)
    /// Property: Generations should only increase when slots are reused
    #[test]
    fn mr_generation_monotonicity() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_generation_monotonicity");

        let mut heap = RegionHeap::new();

        // Allocate and track original generation
        let idx1 = heap.alloc(TestValue::new(1, 64));
        let original_gen = idx1.generation();

        // Deallocate to create a free slot
        assert!(heap.dealloc(idx1), "Failed to deallocate idx1");

        // Reallocate - should reuse the slot with incremented generation
        let idx2 = heap.alloc(TestValue::new(2, 128));

        if idx2.index() == idx1.index() {
            // Same slot reused
            assert!(
                idx2.generation() > original_gen,
                "Generation did not increase on slot reuse: original={}, reused={}",
                original_gen,
                idx2.generation()
            );
        }

        // Multiple reuse cycles
        assert!(heap.dealloc(idx2), "Failed to deallocate idx2");
        let idx3 = heap.alloc(TestValue::new(3, 64));

        if idx3.index() == idx1.index() {
            assert!(
                idx3.generation() > idx2.generation(),
                "Generation not monotonic across multiple reuses"
            );
        }

        crate::test_complete!("mr_generation_monotonicity");
    }

    /// MR4: Access Stability (Equivalence)
    /// Property: Valid indices should return same value until deallocated
    #[test]
    fn mr_access_stability() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_access_stability");

        let mut heap = RegionHeap::new();

        // Allocate test values
        let test_value = TestValue::new(42, 256);
        let idx = heap.alloc(test_value.clone());

        // Multiple accesses should return the same value
        for i in 0..10 {
            let retrieved = heap.get::<TestValue>(idx);
            assert!(retrieved.is_some(), "Access failed on iteration {}", i);
            assert_eq!(
                *retrieved.unwrap(),
                test_value,
                "Value changed between accesses on iteration {}",
                i
            );
        }

        // Access should remain stable across other operations
        let other_idx = heap.alloc(TestValue::new(99, 64));

        // Original value should still be stable
        let retrieved = heap.get::<TestValue>(idx);
        assert!(retrieved.is_some(), "Access failed after other allocation");
        assert_eq!(
            *retrieved.unwrap(),
            test_value,
            "Value corrupted by other allocation"
        );

        // Deallocate the other value
        heap.dealloc(other_idx);

        // Original value should still be accessible
        let retrieved = heap.get::<TestValue>(idx);
        assert!(
            retrieved.is_some(),
            "Access failed after other deallocation"
        );
        assert_eq!(
            *retrieved.unwrap(),
            test_value,
            "Value corrupted by other deallocation"
        );

        crate::test_complete!("mr_access_stability");
    }

    /// MR5: Free List Integrity (Inclusive/Exclusive)
    /// Property: Free list should contain no cycles and valid indices only
    #[test]
    fn mr_free_list_integrity() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_free_list_integrity");

        let mut heap = RegionHeap::new();

        // Create a pattern that exercises the free list
        let mut indices = Vec::new();
        for i in 0..10 {
            let idx = heap.alloc(TestValue::new(i, 64));
            indices.push(idx);
        }

        // Deallocate some indices to create free list
        let dealloc_indices = [0, 2, 4, 6, 8];
        for &i in &dealloc_indices {
            heap.dealloc(indices[i]);
        }

        // Verify that we can still allocate (free list working)
        let new_idx = heap.alloc(TestValue::new(100, 64));
        assert!(heap.contains(new_idx), "New allocation not accessible");

        // Verify remaining allocated values are still accessible
        let remaining_indices = [1, 3, 5, 7, 9];
        for &i in &remaining_indices {
            assert!(
                heap.contains(indices[i]),
                "Remaining allocation {} not accessible",
                i
            );
            let value = heap.get::<TestValue>(indices[i]);
            assert!(value.is_some(), "Cannot access remaining value {}", i);
            assert_eq!(
                value.unwrap().id,
                i as u32,
                "Value corrupted for index {}",
                i
            );
        }

        crate::test_complete!("mr_free_list_integrity");
    }

    /// MR6: Allocation/Deallocation Symmetry (Invertive)
    /// Property: Allocating then deallocating should restore heap state
    #[test]
    fn mr_allocation_deallocation_symmetry() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_allocation_deallocation_symmetry");

        let mut heap = RegionHeap::new();

        // Record initial state. NOTE: only per-heap state is asserted for
        // symmetry — `global_alloc_count()` reads a PROCESS-GLOBAL counter
        // shared by every RegionHeap, so under the parallel test run its
        // absolute value is perturbed by other tests and is not a sound basis
        // for an equality check. The genuine invertibility invariant is local
        // to this heap.
        let initial_stats = heap.stats();
        let initial_len = heap.len();

        // Perform allocation followed by immediate deallocation
        let test_sizes = [32, 64, 128, 256, 512];
        for (i, &size) in test_sizes.iter().enumerate() {
            let value = TestValue::new(i as u32, size);
            let idx = heap.alloc(value);

            // Verify allocation happened
            assert!(heap.contains(idx), "Allocation {} not present", i);

            // Immediately deallocate
            assert!(heap.dealloc(idx), "Failed to deallocate {}", i);

            // Verify deallocation happened
            assert!(
                !heap.contains(idx),
                "Index {} still accessible after dealloc",
                i
            );
        }

        // Check symmetry: per-heap state should be equivalent to initial.
        let final_stats = heap.stats();
        let final_len = heap.len();

        assert_eq!(
            final_len, initial_len,
            "Heap length not symmetric after alloc/dealloc cycle"
        );
        assert_eq!(
            final_stats.live, initial_stats.live,
            "Live count not symmetric: initial={}, final={}",
            initial_stats.live, final_stats.live
        );
        // Per-heap conservation: every allocation in the cycle was reclaimed.
        assert_eq!(
            final_stats.allocations - initial_stats.allocations,
            final_stats.reclaimed - initial_stats.reclaimed,
            "alloc/dealloc not balanced for this heap: \
             allocs_delta={}, reclaimed_delta={}",
            final_stats.allocations - initial_stats.allocations,
            final_stats.reclaimed - initial_stats.reclaimed
        );

        crate::test_complete!("mr_allocation_deallocation_symmetry");
    }

    /// MR7: Composite Operation Invariants (Multiplicative Power)
    /// Property: Complex sequences should maintain all invariants simultaneously
    #[test]
    fn mr_composite_operation_invariants() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_composite_operation_invariants");

        let mut heap = RegionHeap::new();

        // Execute complex operation sequence
        let operations = vec![
            HeapOperation::AllocMany {
                count: 5,
                base_id: 1000,
            },
            HeapOperation::Alloc {
                id: 2000,
                size: 256,
            },
            HeapOperation::DeallocMany {
                target_ids: vec![1001, 1003],
            },
            HeapOperation::AllocMany {
                count: 3,
                base_id: 3000,
            },
            HeapOperation::Dealloc { target_id: 2000 },
            HeapOperation::Alloc {
                id: 4000,
                size: 512,
            },
        ];

        let results = execute_operations(&mut heap, &operations);
        let final_stats = heap.stats();
        assert_eq!(
            results.allocation_count,
            results.deallocation_count
                + results.reclaim_count
                + results.remaining_allocations.len(),
            "operation accounting must explain every allocation"
        );

        // MR1: Statistics conservation
        assert_eq!(
            final_stats.allocations - final_stats.reclaimed,
            final_stats.live,
            "Statistics conservation violated in composite operations"
        );

        // MR2: Length consistency
        assert_eq!(
            heap.len() as u64,
            final_stats.live,
            "Length inconsistent with live count in composite operations"
        );

        // MR4: All remaining allocations should be accessible
        for (&id, &index) in &results.remaining_allocations {
            assert!(
                heap.contains(index),
                "Remaining allocation {} not accessible",
                id
            );
            let value = heap.get::<TestValue>(index);
            assert!(value.is_some(), "Cannot retrieve remaining value {}", id);
            assert_eq!(value.unwrap().id, id, "Value corrupted for id {}", id);
        }

        // MR2: This heap's own live count must equal the number of remaining
        // allocations. (The process-global counter is shared across every
        // RegionHeap in the process and is perturbed by concurrent parallel
        // tests, so it is not a sound oracle here — the per-heap live count is
        // the genuine, isolated invariant.)
        assert_eq!(
            final_stats.live as usize,
            results.remaining_allocations.len(),
            "live count inconsistent with remaining allocations: live={}, remaining={}",
            final_stats.live,
            results.remaining_allocations.len()
        );
        // The process-global counter must at least cover this heap's live
        // allocations — a one-directional bound robust to concurrent allocation
        // by other parallel tests.
        assert!(
            global_alloc_count() >= final_stats.live,
            "global count must cover this heap's live allocations"
        );

        // Cleanup and verify per-heap symmetry: reclaim_all empties this heap.
        heap.reclaim_all();
        assert_eq!(
            heap.stats().live,
            0,
            "heap live count not zero after reclaim_all"
        );
        assert_eq!(heap.len(), 0, "heap len not zero after reclaim_all");

        crate::test_complete!("mr_composite_operation_invariants");
    }

    /// MR8: Type Safety Invariant (Equivalence)
    /// Property: Type mismatches should consistently return None
    #[test]
    fn mr_type_safety_invariant() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("mr_type_safety_invariant");

        let mut heap = RegionHeap::new();

        // Allocate different types
        let string_idx = heap.alloc("hello".to_string());
        let int_idx = heap.alloc(42u32);
        let vec_idx = heap.alloc(vec![1, 2, 3]);

        // Correct type access should work
        assert!(heap.get::<String>(string_idx).is_some());
        assert!(heap.get::<u32>(int_idx).is_some());
        assert!(heap.get::<Vec<i32>>(vec_idx).is_some());

        // Type mismatches should consistently return None
        assert!(
            heap.get::<u32>(string_idx).is_none(),
            "Type mismatch allowed for string->u32"
        );
        assert!(
            heap.get::<String>(int_idx).is_none(),
            "Type mismatch allowed for u32->String"
        );
        assert!(
            heap.get::<Vec<i32>>(string_idx).is_none(),
            "Type mismatch allowed for string->Vec"
        );
        assert!(
            heap.get::<String>(vec_idx).is_none(),
            "Type mismatch allowed for Vec->String"
        );

        // Type safety should be stable across operations
        let _another_idx = heap.alloc(TestValue::new(99, 64));

        // Original type checks should still fail consistently
        assert!(
            heap.get::<u32>(string_idx).is_none(),
            "Type safety changed after other alloc"
        );
        assert!(
            heap.get::<String>(int_idx).is_none(),
            "Type safety changed after other alloc"
        );

        crate::test_complete!("mr_type_safety_invariant");
    }
}
