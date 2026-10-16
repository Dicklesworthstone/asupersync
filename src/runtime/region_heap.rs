//! Region heap allocator with quiescent reclamation.
//!
//! This module provides a per-region heap allocator that enables safe parallel task
//! execution by ensuring allocated data outlives all tasks in the region.
//!
//! # Design
//!
//! The region heap currently allocates via direct type-erased boxing on the
//! global allocator; a bump-allocation fast path within pre-allocated chunks
//! is a planned enhancement (see `RegionHeap`'s Memory Model notes). Memory is
//! reclaimed only when the region reaches quiescence (all tasks terminal,
//! finalizers complete, obligations resolved).
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
//! 1. *Single reclamation site.* A region empties its heap with `take_all()`
//!    (which `reclaim_all()` wraps) once, from `RegionRecord::complete_close()`
//!    or, for a snapshot restored as closed, `RegionRecord::clear_heap()`.
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
//!    - Within the same heap, `HeapIndex` carries a generation counter so
//!      that slot reuse by a later allocation prevents access (intra-heap ABA
//!      safety). Across different heaps or regions, `RRef` checks the region ID
//!      to prevent cross-region access.
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

/// Next generation for a freed slot, or `None` when the slot must be retired.
///
/// `HeapIndex.generation` is a `u32`. Recycling a slot at the maximum generation
/// with `wrapping_add(1)` would wrap to 0 and, after a full `u32` of
/// alloc/dealloc cycles on the same slot, re-issue a generation that a stale
/// `HeapIndex` still holds — `get`/`get_mut`/`contains` would then accept the
/// stale handle (ABA, returning the wrong allocation). Returning `None` at
/// `u32::MAX` lets `dealloc` permanently retire the slot instead of wrapping,
/// mirroring the `reactor/token.rs` retirement (br-asupersync-rtiu1s).
const fn next_slot_generation(current: u32) -> Option<u32> {
    current.checked_add(1)
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

        let (size_hint, next_gen) = {
            let HeapSlot::Occupied(entry) = slot else {
                return false;
            };
            if entry.generation != index.generation {
                return false;
            }
            (entry.size_hint, next_slot_generation(entry.generation))
        };

        match next_gen {
            Some(new_gen) => {
                // Normal recycle: bump the generation and link the slot back
                // onto the free list for reuse.
                let old_slot = std::mem::replace(
                    slot,
                    HeapSlot::Vacant {
                        next_free: self.free_head,
                        generation: new_gen,
                    },
                );
                self.free_head = Some(index.index);
                drop(old_slot);
            }
            None => {
                // Generation is at u32::MAX: permanently retire the slot rather
                // than wrapping (ABA guard, mirrors reactor/token.rs). The slot
                // is left Vacant at the max generation but is NOT linked into
                // the free list, so `alloc` never reuses it; stale handles to it
                // fail closed because it is no longer `Occupied`.
                let old_slot = std::mem::replace(
                    slot,
                    HeapSlot::Vacant {
                        next_free: None,
                        generation: u32::MAX,
                    },
                );
                drop(old_slot);
            }
        }
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
        drop(self.take_all());
    }

    /// Reclaims all allocations like [`Self::reclaim_all`], but returns their
    /// payloads, in ascending index order, instead of dropping them. A region
    /// drops them after it has released its own lock and before it publishes
    /// its close, so a destructor that panics cannot leave it half closed and
    /// one that touches the region does not deadlock on that lock. The
    /// runtime's own locks may still be held (br-asupersync-fu6cr0 M2).
    pub(crate) fn take_all(&mut self) -> Vec<Box<dyn Any + Send + Sync>> {
        let mut payloads = Vec::with_capacity(self.len);
        let reclaimed_count = self.len as u64;
        GLOBAL_ALLOC_COUNT.fetch_sub(reclaimed_count, Ordering::Relaxed);

        self.stats.reclaimed += reclaimed_count;
        self.stats.live = 0;
        self.stats.bytes_live = 0;

        // Set the live count to 0 before touching slots so a panicking element
        // destructor cannot double-subtract in Drop.
        self.len = 0;

        // Fold every slot's generation forward rather than `slots.clear()`. A
        // bare clear discards all per-slot generations, so the next `alloc`
        // re-issues index 0 / generation 0 and a stale pre-reclaim `HeapIndex`
        // of the same type would validate against the new allocation — an ABA
        // reuse the generation counter exists to prevent, and which the module
        // proof (item 4, "generation mismatch prevents access") explicitly
        // relies on surviving reclamation. `clear()` retains the Vec capacity
        // anyway, so preserving the slots as recycled Vacant entries costs no
        // extra memory. Iterate FORWARD so each Occupied slot's payload is
        // dropped in ascending index order — matching `slots.clear()`'s
        // front-to-back drop, which the region-close drop-trace metamorphic
        // tests pin.
        self.free_head = None;
        for i in 0..self.slots.len() {
            // Occupied slots fold forward (matching `dealloc`); already-Vacant
            // slots keep their generation. A slot at u32::MAX is permanently
            // retired and stays off the free list.
            let (generation, retired) = match &self.slots[i] {
                HeapSlot::Occupied(entry) => match next_slot_generation(entry.generation) {
                    Some(next) => (next, false),
                    None => (u32::MAX, true),
                },
                HeapSlot::Vacant { generation, .. } => (*generation, *generation == u32::MAX),
            };
            let next_free = if retired { None } else { self.free_head };
            let previous = std::mem::replace(
                &mut self.slots[i],
                HeapSlot::Vacant {
                    next_free,
                    generation,
                },
            );
            if let HeapSlot::Occupied(entry) = previous {
                payloads.push(entry.value);
            }
            if !retired {
                self.free_head = Some(i as u32);
            }
        }
        payloads
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
#[path = "region_heap_inline_tests.rs"]
mod tests;
