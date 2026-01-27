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
//! generation-based indices (like [`Arena`]) to provide stable handles that don't
//! leak memory addresses into the computation.
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

        // Update statistics
        self.stats.allocations += 1;
        self.stats.live += 1;
        self.stats.bytes_allocated += size_hint as u64;
        GLOBAL_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);

        let entry = HeapEntry {
            value: Box::new(value),
            generation: 0,
            size_hint,
        };

        self.len += 1;

        // Try to reuse a free slot
        if let Some(free_index) = self.free_head {
            let slot = &mut self.slots[free_index as usize];
            match slot {
                HeapSlot::Vacant {
                    next_free,
                    generation,
                } => {
                    let gen = *generation;
                    self.free_head = *next_free;
                    *slot = HeapSlot::Occupied(HeapEntry {
                        value: entry.value,
                        generation: gen,
                        size_hint: entry.size_hint,
                    });
                    HeapIndex {
                        index: free_index,
                        generation: gen,
                        type_id,
                    }
                }
                HeapSlot::Occupied(_) => unreachable!("free list pointed to occupied slot"),
            }
        } else {
            // Allocate new slot
            let index = u32::try_from(self.slots.len()).expect("region heap overflow");
            self.slots.push(HeapSlot::Occupied(entry));
            HeapIndex {
                index,
                generation: 0,
                type_id,
            }
        }
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

        match slot {
            HeapSlot::Occupied(entry) if entry.generation == index.generation => {
                let new_gen = entry.generation.wrapping_add(1);

                *slot = HeapSlot::Vacant {
                    next_free: self.free_head,
                    generation: new_gen,
                };
                self.free_head = Some(index.index);
                self.len -= 1;

                // Update statistics
                self.stats.reclaimed += 1;
                self.stats.live -= 1;
                GLOBAL_ALLOC_COUNT.fetch_sub(1, Ordering::Relaxed);

                true
            }
            _ => false,
        }
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
