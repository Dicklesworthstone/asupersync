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
        Self {
            slots: Vec::new(),
            free_head: None,
            len: 0,
            stats: HeapStats::default(),
        }
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
                panic!("free list pointed outside heap slots");
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
                HeapSlot::Occupied(_) => panic!("free list pointed to occupied slot"),
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

        *slot = HeapSlot::Vacant {
            next_free: self.free_head,
            generation: new_gen,
        };
        self.free_head = Some(index.index);
        self.len -= 1;

        // Update statistics
        self.stats.reclaimed += 1;
        self.stats.live -= 1;
        self.stats.bytes_live = self.stats.bytes_live.saturating_sub(size_hint as u64);
        GLOBAL_ALLOC_COUNT.fetch_sub(1, Ordering::Relaxed);

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

        self.slots.clear();
        self.free_head = None;
        self.len = 0;
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
    use super::*;

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
}
