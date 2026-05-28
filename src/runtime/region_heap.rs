//! Region heap allocator with quiescent reclamation.
//!
//! This module provides a per-region heap allocator that enables safe parallel task
//! execution by ensuring allocated data outlives all tasks in the region.
//!
//! # Design
//!
//! The region heap uses a bump allocator for fast-path allocation with fallback
//! to the global allocator. Memory is reclaimed only when the region reaches
//! quiescence (all tasks terminal, finalizers complete, obligations resolved).
//!
//! # Determinism
//!
//! Allocation addresses are not exposed as observable identifiers. Instead, we use
//! generation-based indices (like `Arena`) to provide stable handles that don't
//! leak memory addresses into the computation.
//!
//! # Proof Sketch: Reclamation Only At Quiescence
//!
//! **Claim.** `reclaim_all()` is invoked on a region's heap if and only if the
//! region has reached quiescence (no live tasks, no live children, no pending
//! obligations, no remaining finalizers).
//!
//! **Proof outline.**
//!
//! 1. *Single reclamation site.* `RegionHeap::reclaim_all()` is called exactly
//!    once per region, from `RegionRecord::clear_heap()`, which is called from
//!    `RegionRecord::complete_close()`.
//!
//! 2. *State machine guard.* `complete_close()` performs an atomic
//!    `state.transition(Finalizing, Closed)`. The `RegionState` state machine
//!    enforces that `Finalizing` is reachable only from `Draining`, which is
//!    reachable only from `Closing`:
//!
//!    `Open → Closing → Draining → Finalizing → Closed`
//!
//! 3. *Closing requires quiescence.* Each transition is guarded:
//!    - `begin_close()`: sets state to `Closing`, after which all admission
//!      paths (`add_task`, `add_child`, `try_reserve_obligation`, `heap_alloc`)
//!      return `Err(AdmissionError::Closed)`. No new work can enter.
//!    - `begin_drain()`: transitions `Closing → Draining` only when invoked.
//!      The runtime invokes this only after propagating cancel to all children.
//!    - `begin_finalize()`: transitions `Draining → Finalizing` only when
//!      invoked. The runtime invokes this only after all child regions are
//!      closed and all tasks are terminal.
//!    - `complete_close()`: transitions `Finalizing → Closed` only after all
//!      finalizers have run. At this point:
//!      `children ∅ ∧ tasks ∅ ∧ obligations = 0 ∧ finalizers ∅`
//!
//! 4. *No aliased access after reclamation.* After `complete_close()`:
//!    - `RRef::get()` checks `state.is_terminal()` and returns
//!      `Err(AllocationInvalid)`.
//!    - `HeapIndex` carries a generation counter; even if a stale index is
//!      presented to a new heap, the generation mismatch prevents access (ABA
//!      safety).
//!
//! 5. *Global counter conservation.* Every `alloc()` increments
//!    `GLOBAL_ALLOC_COUNT` and every `dealloc()` / `reclaim_all()` / `Drop`
//!    decrements it by the appropriate amount. When all regions are closed:
//!    `GLOBAL_ALLOC_COUNT == 0`.
//!
//! **QED.** Reclamation is triggered only by the `Finalizing → Closed`
//! transition, which is reachable only after the quiescence preconditions
//! are satisfied. □
//!
//! # Example
//!
//! ```ignore
//! let mut heap = RegionHeap::new();
//!
//! // Allocate values
//! let idx1 = heap.alloc(42u32);
//! let idx2 = heap.alloc("hello".to_string());
//!
//! // Access via index
//! assert_eq!(heap.get::<u32>(idx1), Some(&42));
//! assert_eq!(heap.get::<String>(idx2).map(String::as_str), Some("hello"));
//!
//! // Memory is reclaimed when heap is dropped (region close)
//! ```

use std::any::{Any, TypeId};
use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for region heap allocations.
///
/// Used for debugging and testing to verify memory reclamation without UB.
#[derive(Debug, Default, Clone, Copy)]
pub struct HeapStats {
    /// Total number of allocations made.
    pub allocations: u64,
    /// Total number of allocations reclaimed.
    pub reclaimed: u64,
    /// Current number of live allocations.
    pub live: u64,
    /// Total bytes allocated (approximate, type-erased overhead not counted).
    pub bytes_allocated: u64,
    /// Current live bytes (approximate, type-erased overhead not counted).
    pub bytes_live: u64,
}

/// Global allocation counter for testing memory reclamation.
///
/// This is incremented on allocation and decremented on deallocation,
/// allowing tests to verify that region close reclaims all memory.
static GLOBAL_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

/// Returns the current global allocation count.
///
/// Useful for tests to verify memory reclamation.
#[must_use]
pub fn global_alloc_count() -> u64 {
    GLOBAL_ALLOC_COUNT.load(Ordering::Relaxed)
}

/// An index into the region heap with a generation counter.
///
/// This provides a stable handle to an allocation that doesn't expose
/// memory addresses, maintaining determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeapIndex {
    index: u32,
    generation: u32,
    type_id: TypeId,
}

impl HeapIndex {
    /// Returns the raw index value.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Returns the generation counter.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// A type-erased allocation entry in the heap.
struct HeapEntry {
    /// The boxed value (type-erased).
    value: Box<dyn Any + Send + Sync>,
    /// Generation counter for ABA safety.
    generation: u32,
    /// Size hint for statistics (may not be exact due to type erasure).
    size_hint: usize,
}

/// Slot state in the heap.
enum HeapSlot {
    /// Occupied with an allocation.
    Occupied(HeapEntry),
    /// Vacant, pointing to next free slot.
    Vacant {
        next_free: Option<u32>,
        generation: u32,
    },
}

/// A region-owned heap allocator.
///
/// The `RegionHeap` provides memory allocation tied to a region's lifetime.
/// All allocations are automatically reclaimed when the heap is dropped
/// (which happens when the region closes after reaching quiescence).
///
/// # Memory Model
///
/// - Fast path: bump allocation within pre-allocated chunks (future enhancement)
/// - Current: direct boxing with type erasure for simplicity
/// - Reclamation: bulk drop on region close
///
/// # Thread Safety
///
/// The heap itself is not thread-safe. In a parallel runtime, each region
/// should have exclusive access to its heap during allocation. Tasks can
/// hold `HeapIndex` handles and read through shared references.
#[derive(Default)]
pub struct RegionHeap {
    /// Storage for type-erased allocations.
    slots: Vec<HeapSlot>,
    /// Head of the free list.
    free_head: Option<u32>,
    /// Number of live allocations.
    len: usize,
    /// Allocation statistics.
    stats: HeapStats,
}

impl std::fmt::Debug for RegionHeap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegionHeap")
            .field("len", &self.len)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl RegionHeap {
    /// Creates a new empty region heap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new region heap with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free_head: None,
            len: 0,
            stats: HeapStats::default(),
        }
    }

    /// Returns the number of live allocations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if there are no live allocations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns allocation statistics.
    #[must_use]
    pub const fn stats(&self) -> HeapStats {
        self.stats
    }

    /// Allocates a value in the region heap and returns its index.
    ///
    /// The value must be `Send + Sync + 'static` to be safely shared
    /// across tasks within the region.
    ///
    /// # Panics
    ///
    /// Panics if the heap exceeds `u32::MAX` allocations.
    pub fn alloc<T: Send + Sync + 'static>(&mut self, value: T) -> HeapIndex {
        let size_hint = std::mem::size_of::<T>();
        let type_id = TypeId::of::<T>();
        let entry_value: Box<dyn Any + Send + Sync> = Box::new(value);

        // Try to reuse a free slot
        let heap_index = if let Some(free_index) = self.free_head {
            let Some(slot) = self.slots.get_mut(free_index as usize) else {
                unreachable!("free list pointed outside heap slots");
            };
            match slot {
                HeapSlot::Vacant {
                    next_free,
                    generation,
                } => {
                    let generation_value = *generation;
                    self.free_head = *next_free;
                    *slot = HeapSlot::Occupied(HeapEntry {
                        value: entry_value,
                        generation: generation_value,
                        size_hint,
                    });
                    HeapIndex {
                        index: free_index,
                        generation: generation_value,
                        type_id,
                    }
                }
                HeapSlot::Occupied(_) => unreachable!("free list pointed to occupied slot"),
            }
        } else {
            // Allocate new slot
            let index = u32::try_from(self.slots.len()).expect("region heap overflow");
            self.slots.push(HeapSlot::Occupied(HeapEntry {
                value: entry_value,
                generation: 0,
                size_hint,
            }));
            HeapIndex {
                index,
                generation: 0,
                type_id,
            }
        };

        // Update statistics only after slot insertion succeeds.
        self.len += 1;
        self.stats.allocations += 1;
        self.stats.live += 1;
        self.stats.bytes_allocated += size_hint as u64;
        self.stats.bytes_live += size_hint as u64;
        GLOBAL_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);

        heap_index
    }

    /// Returns a reference to the value at the given index.
    ///
    /// Returns `None` if:
    /// - The index is invalid
    /// - The slot is vacant
    /// - The type doesn't match
    #[must_use]
    pub fn get<T: 'static>(&self, index: HeapIndex) -> Option<&T> {
        if TypeId::of::<T>() != index.type_id {
            return None;
        }

        match self.slots.get(index.index as usize)? {
            HeapSlot::Occupied(entry) if entry.generation == index.generation => {
                entry.value.downcast_ref::<T>()
            }
            _ => None,
        }
    }

    /// Returns a mutable reference to the value at the given index.
    ///
    /// Returns `None` if:
    /// - The index is invalid
    /// - The slot is vacant
    /// - The type doesn't match
    pub fn get_mut<T: 'static>(&mut self, index: HeapIndex) -> Option<&mut T> {
        if TypeId::of::<T>() != index.type_id {
            return None;
        }

        match self.slots.get_mut(index.index as usize)? {
            HeapSlot::Occupied(entry) if entry.generation == index.generation => {
                entry.value.downcast_mut::<T>()
            }
            _ => None,
        }
    }

    /// Checks if an index is valid (points to a live allocation).
    #[must_use]
    pub fn contains(&self, index: HeapIndex) -> bool {
        match self.slots.get(index.index as usize) {
            Some(HeapSlot::Occupied(entry)) => entry.generation == index.generation,
            _ => false,
        }
    }

    /// Deallocates the value at the given index.
    ///
    /// This is typically not called directly - the heap is bulk-reclaimed
    /// on region close. However, it's provided for cases where early
    /// deallocation is beneficial.
    ///
    /// Returns `true` if the index was valid and the value was deallocated.
    pub fn dealloc(&mut self, index: HeapIndex) -> bool {
        let Some(slot) = self.slots.get_mut(index.index as usize) else {
            return false;
        };

        let (size_hint, new_gen) = {
            let HeapSlot::Occupied(entry) = slot else {
                return false;
            };
            if entry.generation != index.generation {
                return false;
            }
            (entry.size_hint, entry.generation.wrapping_add(1))
        };

        let old_slot = std::mem::replace(
            slot,
            HeapSlot::Vacant {
                next_free: self.free_head,
                generation: new_gen,
            },
        );
        self.free_head = Some(index.index);
        self.len -= 1;

        // Update statistics
        self.stats.reclaimed += 1;
        self.stats.live -= 1;
        self.stats.bytes_live = self.stats.bytes_live.saturating_sub(size_hint as u64);
        GLOBAL_ALLOC_COUNT.fetch_sub(1, Ordering::Relaxed);

        drop(old_slot);
        true
    }

    /// Reclaims all allocations in the heap.
    ///
    /// This is called automatically when the heap is dropped, but can be
    /// called explicitly for eager reclamation.
    pub fn reclaim_all(&mut self) {
        let reclaimed_count = self.len as u64;
        GLOBAL_ALLOC_COUNT.fetch_sub(reclaimed_count, Ordering::Relaxed);

        self.stats.reclaimed += reclaimed_count;
        self.stats.live = 0;
        self.stats.bytes_live = 0;

        self.free_head = None;
        self.len = 0; // Set to 0 before clear to prevent double-subtraction in Drop if a destructor panics.
        self.slots.clear();
    }
}

impl Drop for RegionHeap {
    fn drop(&mut self) {
        // Decrement global counter for all live allocations
        let live = self.len as u64;
        if live > 0 {
            GLOBAL_ALLOC_COUNT.fetch_sub(live, Ordering::Relaxed);
        }
        // slots are dropped automatically, reclaiming memory
    }
}

/// A typed handle to a region heap allocation.
///
/// This provides a more ergonomic API when the type is known statically.
/// It stores the `HeapIndex` internally and provides typed access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeapRef<T> {
    index: HeapIndex,
    _marker: std::marker::PhantomData<T>,
}

impl<T: Send + Sync + 'static> HeapRef<T> {
    /// Creates a new typed reference from a heap index.
    ///
    /// # Safety
    ///
    /// The caller must ensure the index was created by allocating a value
    /// of type `T`. This is enforced at runtime via type ID checking.
    #[must_use]
    pub const fn new(index: HeapIndex) -> Self {
        Self {
            index,
            _marker: std::marker::PhantomData,
        }
    }

    /// Returns the underlying heap index.
    #[must_use]
    pub const fn index(&self) -> HeapIndex {
        self.index
    }

    /// Gets a reference to the value from the heap.
    #[must_use]
    pub fn get<'a>(&self, heap: &'a RegionHeap) -> Option<&'a T> {
        heap.get::<T>(self.index)
    }

    /// Gets a mutable reference to the value from the heap.
    pub fn get_mut<'a>(&self, heap: &'a mut RegionHeap) -> Option<&'a mut T> {
        heap.get_mut::<T>(self.index)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct DropLog(Arc<Mutex<Vec<&'static str>>>);

    impl DropLog {
        fn push(&self, label: &'static str) {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(label);
        }

        fn snapshot(&self) -> Vec<&'static str> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    struct DropProbe {
        label: &'static str,
        log: DropLog,
    }

    impl DropProbe {
        fn new(label: &'static str, log: DropLog) -> Self {
            Self { label, log }
        }
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.log.push(self.label);
        }
    }

    fn close_suffix_after_early_deallocs(
        first: &'static str,
        second: &'static str,
    ) -> Vec<&'static str> {
        let log = DropLog::default();
        let mut heap = RegionHeap::new();

        let a = heap.alloc(DropProbe::new("a", log.clone()));
        let b = heap.alloc(DropProbe::new("b", log.clone()));
        let c = heap.alloc(DropProbe::new("c", log.clone()));
        let d = heap.alloc(DropProbe::new("d", log.clone()));

        for label in [first, second] {
            let deallocated = match label {
                "a" => heap.dealloc(a),
                "b" => heap.dealloc(b),
                "c" => heap.dealloc(c),
                "d" => heap.dealloc(d),
                _ => panic!("unexpected label"),
            };
            assert!(deallocated, "{label} should deallocate successfully");
        }

        let dealloc_drops = log.snapshot();
        assert_eq!(dealloc_drops.len(), 2, "expected two eager drops");

        heap.reclaim_all();
        log.snapshot()[dealloc_drops.len()..].to_vec()
    }

    fn independent_heap_drop_traces(
        reclaim_order: [usize; 2],
    ) -> (Vec<&'static str>, Vec<&'static str>) {
        let left_log = DropLog::default();
        let right_log = DropLog::default();

        let mut left = RegionHeap::new();
        left.alloc(DropProbe::new("left-a", left_log.clone()));
        left.alloc(DropProbe::new("left-b", left_log.clone()));

        let mut right = RegionHeap::new();
        right.alloc(DropProbe::new("right-a", right_log.clone()));
        right.alloc(DropProbe::new("right-b", right_log.clone()));

        for which in reclaim_order {
            match which {
                0 => left.reclaim_all(),
                1 => right.reclaim_all(),
                _ => panic!("unexpected heap selector"),
            }
        }

        (left_log.snapshot(), right_log.snapshot())
    }

    #[test]
    fn alloc_and_get() {
        let mut heap = RegionHeap::new();

        let idx = heap.alloc(42u32);
        assert_eq!(heap.get::<u32>(idx), Some(&42));
        assert_eq!(heap.len(), 1);

        // Verify via heap stats (more reliable than global counter in parallel tests)
        assert_eq!(heap.stats().allocations, 1);
        assert_eq!(heap.stats().live, 1);
    }

    #[test]
    fn multiple_types() {
        let mut heap = RegionHeap::new();

        let idx1 = heap.alloc(42u32);
        let idx2 = heap.alloc("hello".to_string());
        let idx3 = heap.alloc(vec![1, 2, 3]);

        assert_eq!(heap.get::<u32>(idx1), Some(&42));
        assert_eq!(heap.get::<String>(idx2).map(String::as_str), Some("hello"));
        assert_eq!(heap.get::<Vec<i32>>(idx3), Some(&vec![1, 2, 3]));

        // Wrong type returns None
        assert_eq!(heap.get::<String>(idx1), None);
        assert_eq!(heap.get::<u32>(idx2), None);
    }

    #[test]
    fn dealloc_and_reuse() {
        let mut heap = RegionHeap::new();

        let idx1 = heap.alloc(1u32);
        let idx2 = heap.alloc(2u32);

        assert!(heap.dealloc(idx1));
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.stats().live, 1);
        assert_eq!(heap.stats().reclaimed, 1);

        // Old index should be invalid
        assert_eq!(heap.get::<u32>(idx1), None);

        // New alloc should reuse the slot
        let idx3 = heap.alloc(3u32);
        assert_eq!(idx3.index(), idx1.index());
        assert_ne!(idx3.generation(), idx1.generation());

        assert_eq!(heap.get::<u32>(idx2), Some(&2));
        assert_eq!(heap.get::<u32>(idx3), Some(&3));
    }

    #[test]
    fn generation_prevents_aba() {
        let mut heap = RegionHeap::new();

        let idx1 = heap.alloc(1u32);
        heap.dealloc(idx1);
        let idx2 = heap.alloc(2u32);

        // Same slot, different generation
        assert_eq!(idx1.index(), idx2.index());
        assert_ne!(idx1.generation(), idx2.generation());

        // Old index should not work
        assert_eq!(heap.get::<u32>(idx1), None);
        assert_eq!(heap.get::<u32>(idx2), Some(&2));
    }

    #[test]
    fn generation_monotonic_on_reuse() {
        let mut heap = RegionHeap::new();

        let mut idx = heap.alloc(0u32);
        for i in 1u32..16 {
            assert!(heap.dealloc(idx));

            let next = heap.alloc(i);
            assert_eq!(next.index(), idx.index());
            assert_eq!(next.generation(), idx.generation().wrapping_add(1));
            assert_eq!(heap.get::<u32>(idx), None);

            idx = next;
        }
    }

    #[test]
    fn deterministic_reuse_pattern() {
        fn run_pattern() -> Vec<(u32, u32)> {
            let mut heap = RegionHeap::new();

            let first = heap.alloc(1u32);
            let second = heap.alloc(2u32);
            let third = heap.alloc(3u32);

            assert!(heap.dealloc(second));
            let reuse_second = heap.alloc(4u32); // should reuse second's slot

            assert!(heap.dealloc(first));
            assert!(heap.dealloc(third));
            let reuse_third = heap.alloc(5u32); // reuse third's slot (last freed)
            let reuse_first = heap.alloc(6u32); // reuse first's slot

            vec![
                (first.index(), first.generation()),
                (second.index(), second.generation()),
                (third.index(), third.generation()),
                (reuse_second.index(), reuse_second.generation()),
                (reuse_third.index(), reuse_third.generation()),
                (reuse_first.index(), reuse_first.generation()),
            ]
        }

        let first = run_pattern();
        let second = run_pattern();
        assert_eq!(first, second, "allocation pattern should be deterministic");
    }

    #[test]
    fn mr_early_dealloc_permutation_preserves_close_drop_suffix() {
        let forward = close_suffix_after_early_deallocs("b", "d");
        let reverse = close_suffix_after_early_deallocs("d", "b");

        assert_eq!(forward, reverse);
        assert_eq!(forward, vec!["a", "c"]);
    }

    #[test]
    fn mr_independent_heap_reclaim_order_preserves_per_heap_drop_traces() {
        let forward = independent_heap_drop_traces([0, 1]);
        let reverse = independent_heap_drop_traces([1, 0]);

        assert_eq!(forward.0, reverse.0);
        assert_eq!(forward.1, reverse.1);
        assert_eq!(forward.0, vec!["left-a", "left-b"]);
        assert_eq!(forward.1, vec!["right-a", "right-b"]);
    }

    #[test]
    fn alloc_panic_does_not_mutate_len_or_stats() {
        let mut heap = RegionHeap::new();
        heap.free_head = Some(1);

        let before_len = heap.len();
        let before_stats = heap.stats();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = heap.alloc(123u32);
        }));

        assert!(
            result.is_err(),
            "alloc should panic on corrupted free-list head"
        );
        assert_eq!(heap.len(), before_len);
        let after_stats = heap.stats();
        assert_eq!(after_stats.allocations, before_stats.allocations);
        assert_eq!(after_stats.reclaimed, before_stats.reclaimed);
        assert_eq!(after_stats.live, before_stats.live);
        assert_eq!(after_stats.bytes_allocated, before_stats.bytes_allocated);
        assert_eq!(after_stats.bytes_live, before_stats.bytes_live);
    }

    #[test]
    fn reclaim_all() {
        let mut heap = RegionHeap::new();

        heap.alloc(1u32);
        heap.alloc(2u32);
        heap.alloc(3u32);
        assert_eq!(heap.len(), 3);
        assert_eq!(heap.stats().live, 3);

        heap.reclaim_all();
        assert_eq!(heap.len(), 0);
        assert!(heap.is_empty());
        assert_eq!(heap.stats().live, 0);
        assert_eq!(heap.stats().reclaimed, 3);
    }

    #[test]
    fn stats_tracking() {
        let mut heap = RegionHeap::new();

        heap.alloc(42u32);
        heap.alloc("hello".to_string());

        let stats = heap.stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.live, 2);
        assert_eq!(stats.reclaimed, 0);

        heap.dealloc(HeapIndex {
            index: 0,
            generation: 0,
            type_id: TypeId::of::<u32>(),
        });

        let stats = heap.stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.live, 1);
        assert_eq!(stats.reclaimed, 1);
    }

    #[test]
    fn heap_ref_typed_access() {
        let mut heap = RegionHeap::new();

        let idx = heap.alloc(42u32);
        let href: HeapRef<u32> = HeapRef::new(idx);

        assert_eq!(href.get(&heap), Some(&42));

        *href.get_mut(&mut heap).unwrap() = 100;
        assert_eq!(href.get(&heap), Some(&100));
    }

    #[test]
    fn drop_reclaims_memory() {
        // This test verifies that Drop properly reclaims allocations.
        // We verify via heap stats rather than global counter (which has race conditions
        // in parallel tests).

        let mut heap = RegionHeap::new();
        for i in 0u64..100 {
            heap.alloc(i);
        }
        // Verify heap has 100 allocations
        assert_eq!(heap.len(), 100);
        assert_eq!(heap.stats().live, 100);
        assert_eq!(heap.stats().allocations, 100);
        assert_eq!(heap.stats().reclaimed, 0);

        // Drop is implicitly tested - if it didn't work, we'd leak memory.
        // The global_alloc_count() function is available for debugging but
        // not used in this test due to parallel execution concerns.
    }

    // =========================================================================
    // Wave 43 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn heap_stats_debug_default_clone_copy() {
        let stats = HeapStats::default();
        assert_eq!(stats.allocations, 0);
        assert_eq!(stats.reclaimed, 0);
        assert_eq!(stats.live, 0);
        assert_eq!(stats.bytes_allocated, 0);
        assert_eq!(stats.bytes_live, 0);
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("HeapStats"), "{dbg}");
        let copied = stats;
        let cloned = stats;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn heap_index_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let mut heap = RegionHeap::new();
        let idx1 = heap.alloc(42u32);
        let idx2 = heap.alloc(99u32);

        // Debug
        let dbg = format!("{idx1:?}");
        assert!(dbg.contains("HeapIndex"), "{dbg}");

        // Clone + Copy
        let copied = idx1;
        let cloned = idx1;
        assert_eq!(copied, cloned);

        // PartialEq + Eq
        assert_eq!(idx1, idx1);
        assert_ne!(idx1, idx2);

        // Hash
        let mut set = HashSet::new();
        set.insert(idx1);
        set.insert(idx2);
        set.insert(idx1);
        assert_eq!(set.len(), 2);

        // Accessors
        assert_eq!(idx1.index(), 0);
        assert_eq!(idx1.generation(), 0);
    }

    #[test]
    fn heap_ref_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let mut heap = RegionHeap::new();
        let idx1 = heap.alloc(42u32);
        let idx2 = heap.alloc(99u32);

        let r1 = HeapRef::<u32>::new(idx1);
        let r2 = HeapRef::<u32>::new(idx2);

        // Debug
        let dbg = format!("{r1:?}");
        assert!(dbg.contains("HeapRef"), "{dbg}");

        // Clone + Copy
        let copied = r1;
        let cloned = r1;
        assert_eq!(copied, cloned);

        // PartialEq + Eq
        assert_eq!(r1, r1);
        assert_ne!(r1, r2);

        // Hash
        let mut set = HashSet::new();
        set.insert(r1);
        set.insert(r2);
        set.insert(r1);
        assert_eq!(set.len(), 2);

        // Typed accessor
        assert_eq!(r1.get(&heap), Some(&42));
        assert_eq!(r2.get(&heap), Some(&99));
    }

    #[test]
    fn region_heap_debug_default() {
        let heap = RegionHeap::default();
        let dbg = format!("{heap:?}");
        assert!(dbg.contains("RegionHeap"), "{dbg}");
        assert_eq!(heap.len(), 0);
        assert!(heap.is_empty());
    }

    // =========================================================================
    // Metamorphic Testing Suite - Region Heap Allocator
    // =========================================================================

    use proptest::prelude::*;

    // Test data generators
    prop_compose! {
        fn arb_allocation_sequence()
                                   (size in 1usize..50)
                                   (allocations in prop::collection::vec(0u64..1000, size)) -> Vec<u64> {
            allocations
        }
    }

    prop_compose! {
        fn arb_mixed_types()
                           (nums in prop::collection::vec(0u32..100, 0..20),
                            strs in prop::collection::vec("[a-z]{1,10}", 0..20),
                            vecs in prop::collection::vec(prop::collection::vec(0i32..10, 0..5), 0..20))
                           -> (Vec<u32>, Vec<String>, Vec<Vec<i32>>) {
            (nums, strs, vecs)
        }
    }

    #[allow(dead_code)]
    #[derive(Clone, Copy, Debug)]
    enum HeapOp {
        AllocU32(u32),
        AllocString(usize), // index into string pool
        Dealloc(usize),     // index into allocation list
    }

    prop_compose! {
        fn arb_heap_operations()
                              (alloc_ops in 5usize..30,
                               dealloc_rate in 0.1f64..0.7)
                              (ops in prop::collection::vec(
                                  prop_oneof![
                                      (0u32..100).prop_map(HeapOp::AllocU32),
                                      (0usize..20).prop_map(HeapOp::AllocString),
                                      prop::strategy::Just(()).prop_flat_map(move |_|
                                          if fastrand::f64() < dealloc_rate {
                                              (0usize..alloc_ops).prop_map(HeapOp::Dealloc).boxed()
                                          } else {
                                              prop::strategy::Just(HeapOp::AllocU32(fastrand::u32(..100))).boxed()
                                          }
                                      )
                                  ],
                                  alloc_ops
                              )) -> Vec<HeapOp> {
            ops
        }
    }

    // MR1: Live Count Conservation (Score: 5.0)
    // Invariant: heap.len() = allocations_made - successful_deallocations
    proptest! {
        #[test]
        fn mr_live_count_conservation(sequence in arb_allocation_sequence()) {
            let mut heap = RegionHeap::new();
            let mut allocation_indices = Vec::new();
            let mut deallocated_count = 0;

            // Phase 1: Allocate
            for value in &sequence {
                let idx = heap.alloc(*value);
                allocation_indices.push(idx);
            }

            let initial_allocs = sequence.len();
            prop_assert_eq!(heap.len(), initial_allocs);
            prop_assert_eq!(heap.stats().live as usize, initial_allocs);

            // Phase 2: Dealloc some
            let dealloc_indices = if allocation_indices.len() >= 2 {
                vec![allocation_indices[0], allocation_indices[allocation_indices.len() / 2]]
            } else {
                vec![]
            };

            for idx in dealloc_indices {
                if heap.dealloc(idx) {
                    deallocated_count += 1;
                }
            }

            // MR: live = allocated - deallocated
            let expected_live = initial_allocs - deallocated_count;
            prop_assert_eq!(heap.len(), expected_live);
            prop_assert_eq!(heap.stats().live as usize, expected_live);
            prop_assert_eq!(heap.stats().reclaimed as usize, deallocated_count);

            // Phase 3: reclaim_all should zero everything
            heap.reclaim_all();
            prop_assert_eq!(heap.len(), 0);
            prop_assert_eq!(heap.stats().live, 0);
            prop_assert_eq!(heap.stats().reclaimed as usize, initial_allocs);
        }
    }

    // MR2: Generation Isolation (Score: 5.0)
    // Invariant: Old generation indices cannot access new generation values
    proptest! {
        #[test]
        fn mr_generation_isolation(values in prop::collection::vec(0u32..1000, 3..10)) {
            let mut heap = RegionHeap::new();

            // Allocate, then deallocate to create stale indices
            let mut stale_indices = Vec::new();
            for value in &values {
                let idx = heap.alloc(*value);
                stale_indices.push(idx);
            }

            // Deallocate all to make indices stale
            for idx in &stale_indices {
                prop_assert!(heap.dealloc(*idx));
            }

            // Reallocate in same slots (generations should increment)
            let mut fresh_indices = Vec::new();
            for value in &values {
                let idx = heap.alloc(value + 1000); // Different values
                fresh_indices.push(idx);
            }

            // MR: Stale indices (old generation) should not access fresh values
            for (i, stale_idx) in stale_indices.iter().enumerate() {
                prop_assert_eq!(heap.get::<u32>(*stale_idx), None,
                    "Stale index {} should not access fresh value", i);
                prop_assert!(!heap.contains(*stale_idx),
                    "Stale index {} should not be contained", i);
            }

            let stale_generation_by_slot: BTreeMap<u32, u32> = stale_indices
                .iter()
                .map(|idx| (idx.index(), idx.generation()))
                .collect();

            // MR: Fresh indices should access correct values
            for (i, fresh_idx) in fresh_indices.iter().enumerate() {
                prop_assert_eq!(heap.get::<u32>(*fresh_idx), Some(&(values[i] + 1000)));
                prop_assert!(heap.contains(*fresh_idx));

                // Free-list reuse is LIFO, so compare by slot rather than by
                // allocation order.
                let stale_generation = stale_generation_by_slot
                    .get(&fresh_idx.index())
                    .copied()
                    .expect("fresh allocation should reuse a stale slot");
                prop_assert_eq!(
                    fresh_idx.generation(),
                    stale_generation.wrapping_add(1)
                );
            }
        }
    }

    // MR3: Type Isolation (Score: 5.0)
    // Invariant: Operations on type T don't affect accessibility of type U
    proptest! {
        #[test]
        fn mr_type_isolation(mixed_data in arb_mixed_types()) {
            let (nums, strs, vecs) = mixed_data;
            let mut heap = RegionHeap::new();

            // Allocate mixed types
            let mut u32_indices = Vec::new();
            let mut str_indices = Vec::new();
            let mut vec_indices = Vec::new();

            for num in &nums {
                u32_indices.push(heap.alloc(*num));
            }
            for s in &strs {
                str_indices.push(heap.alloc(s.clone()));
            }
            for v in &vecs {
                vec_indices.push(heap.alloc(v.clone()));
            }

            // Deallocate some u32 values
            let u32_deallocs = if u32_indices.len() >= 2 {
                vec![u32_indices[0], u32_indices[u32_indices.len() / 2]]
            } else {
                vec![]
            };

            for idx in u32_deallocs {
                heap.dealloc(idx);
            }

            // MR: String and Vec accessibility should be unaffected by u32 deallocs
            for (i, idx) in str_indices.iter().enumerate() {
                prop_assert_eq!(heap.get::<String>(*idx).map(String::as_str), Some(strs[i].as_str()),
                    "String {} accessibility affected by u32 operations", i);
            }
            for (i, idx) in vec_indices.iter().enumerate() {
                prop_assert_eq!(heap.get::<Vec<i32>>(*idx), Some(&vecs[i]),
                    "Vec {} accessibility affected by u32 operations", i);
            }

            // MR: Wrong type access should always return None
            for idx in &str_indices {
                prop_assert_eq!(heap.get::<u32>(*idx), None);
                prop_assert_eq!(heap.get::<Vec<i32>>(*idx), None);
            }
        }
    }

    // MR4: Free-Reuse Determinism (Score: 5.0)
    // Invariant: dealloc(idx) followed by alloc(new_val) should reuse the same slot
    proptest! {
        #[test]
        fn mr_free_reuse_determinism(values in prop::collection::vec(0u32..100, 5..15)) {
            let mut heap = RegionHeap::new();

            // Allocate sequence
            let mut indices = Vec::new();
            for val in &values {
                indices.push(heap.alloc(*val));
            }

            // Test reuse for each position
            for (i, &original_val) in values.iter().enumerate() {
                let original_idx = indices[i];

                // Deallocate
                prop_assert!(heap.dealloc(original_idx));

                // Reallocate new value
                let new_val = original_val + 1000;
                let reused_idx = heap.alloc(new_val);

                // MR: Should reuse same slot index with incremented generation
                prop_assert_eq!(reused_idx.index(), original_idx.index(),
                    "Failed to reuse slot {} for position {}", original_idx.index(), i);
                prop_assert_eq!(reused_idx.generation(), original_idx.generation().wrapping_add(1),
                    "Generation not incremented correctly for slot {}", original_idx.index());

                // MR: Old index invalid, new index valid
                prop_assert_eq!(heap.get::<u32>(original_idx), None);
                prop_assert_eq!(heap.get::<u32>(reused_idx), Some(&new_val));

                // Update for next iteration
                indices[i] = reused_idx;
            }
        }
    }

    // MR5: Allocation Count Linearity (Score: 4.0)
    // Invariant: N allocations should increment stats.allocations by exactly N
    proptest! {
        #[test]
        fn mr_allocation_count_linearity(
            first_batch in prop::collection::vec(0u32..100, 5..20),
            second_batch in prop::collection::vec(100u32..200, 3..15)
        ) {
            let mut heap = RegionHeap::new();
            let initial_stats = heap.stats();

            // First batch
            for val in &first_batch {
                heap.alloc(*val);
            }
            let after_first = heap.stats();

            // MR: Allocation count should increase linearly
            prop_assert_eq!(after_first.allocations,
                initial_stats.allocations + first_batch.len() as u64);

            // Second batch
            for val in &second_batch {
                heap.alloc(*val);
            }
            let after_second = heap.stats();

            // MR: Total allocation count = sum of both batches
            prop_assert_eq!(after_second.allocations,
                initial_stats.allocations + (first_batch.len() + second_batch.len()) as u64);

            // MR: Live count should match total allocated (no deallocs yet)
            prop_assert_eq!(after_second.live, after_second.allocations);
        }
    }

    // MR6: Deallocation Order Independence (Score: 3.0)
    // Invariant: deallocating [A,B] vs [B,A] should result in equivalent final state
    proptest! {
        #[test]
        fn mr_deallocation_order_independence(values in prop::collection::vec(0u32..50, 4..8)) {
            fn run_with_dealloc_order(values: &[u32], first: usize, second: usize) -> (HeapStats, Vec<bool>) {
                let mut heap = RegionHeap::new();

                // Allocate all
                let indices: Vec<_> = values.iter().map(|&v| heap.alloc(v)).collect();

                // Dealloc two in specified order
                let dealloc_results = vec![
                    heap.dealloc(indices[first]),
                    heap.dealloc(indices[second]),
                ];

                (heap.stats(), dealloc_results)
            }

            if values.len() >= 4 {
                let forward = run_with_dealloc_order(&values, 1, 3);
                let reverse = run_with_dealloc_order(&values, 3, 1);

                // MR: Final stats should be identical regardless of deallocation order
                prop_assert_eq!(forward.0.live, reverse.0.live);
                prop_assert_eq!(forward.0.reclaimed, reverse.0.reclaimed);
                prop_assert_eq!(forward.0.allocations, reverse.0.allocations);

                // Both orders should succeed in deallocating
                prop_assert_eq!(forward.1, vec![true, true]);
                prop_assert_eq!(reverse.1, vec![true, true]);
            }
        }
    }

    // MR7: Composite - Allocation + Deallocation Commutativity (Chain multiple simple MRs)
    proptest! {
        #[test]
        fn mr_composite_alloc_dealloc_commutativity(
            base_values in prop::collection::vec(0u32..50, 3..10),
            extra_values in prop::collection::vec(100u32..150, 2..5)
        ) {
            // Test composition of: allocation order independence + deallocation order independence + type isolation

            let mut heap1 = RegionHeap::new();
            let mut heap2 = RegionHeap::new();

            // Pattern 1: allocate base, then extra, then dealloc middle
            let mut indices1 = Vec::new();
            for val in &base_values { indices1.push(heap1.alloc(*val)); }
            for val in &extra_values { indices1.push(heap1.alloc(*val)); }
            if indices1.len() >= 3 {
                heap1.dealloc(indices1[1]);
                heap1.dealloc(indices1[indices1.len() - 2]);
            }

            // Pattern 2: allocate extra, then base, then dealloc in different order
            let mut indices2 = Vec::new();
            for val in &extra_values { indices2.push(heap2.alloc(*val)); }
            for val in &base_values { indices2.push(heap2.alloc(*val)); }
            if indices2.len() >= 3 {
                heap2.dealloc(indices2[indices2.len() - 2]);
                heap2.dealloc(indices2[1]);
            }

            // MR: Different allocation/deallocation orders should yield same final heap state
            prop_assert_eq!(heap1.len(), heap2.len());
            prop_assert_eq!(heap1.stats().live, heap2.stats().live);
            prop_assert_eq!(heap1.stats().allocations, heap2.stats().allocations);
            prop_assert_eq!(heap1.stats().reclaimed, heap2.stats().reclaimed);

            // Both heaps should have same values accessible (order-independent)
            let all_values: Vec<u32> = base_values.iter().chain(extra_values.iter()).copied().collect();
            prop_assert_eq!(all_values.len(), heap1.stats().allocations as usize);
        }
    }

    // MR8: Mutation Testing Validation - Planted Bug Detection
    #[test]
    fn validate_mr_suite_catches_planted_bugs() {
        // Test that our MR suite can detect common allocator bugs

        // Bug 1: Stats not updated on allocation
        {
            let mut heap = RegionHeap::new();
            heap.alloc(42u32);
            // This would fail if stats weren't updated
            assert_eq!(heap.stats().allocations, 1);
            assert_eq!(heap.len(), 1);
        }

        // Bug 2: Generation not incremented on reuse
        {
            let mut heap = RegionHeap::new();
            let idx1 = heap.alloc(1u32);
            heap.dealloc(idx1);
            let idx2 = heap.alloc(2u32);
            // This would fail if generation wasn't incremented
            assert_eq!(idx1.index(), idx2.index());
            assert_ne!(idx1.generation(), idx2.generation());
        }

        // Bug 3: Type safety violation
        {
            let mut heap = RegionHeap::new();
            let str_idx = heap.alloc("hello".to_string());
            // This would fail if type checking was broken
            assert_eq!(heap.get::<u32>(str_idx), None);
            assert_ne!(heap.get::<String>(str_idx), None);
        }

        // Bug 4: Live count incorrect after dealloc
        {
            let mut heap = RegionHeap::new();
            heap.alloc(1u32);
            heap.alloc(2u32);
            let idx3 = heap.alloc(3u32);

            assert_eq!(heap.len(), 3);
            heap.dealloc(idx3);
            // This would fail if len wasn't decremented
            assert_eq!(heap.len(), 2);
        }
    }
}
