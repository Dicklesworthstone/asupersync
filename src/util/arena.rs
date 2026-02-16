//! Arena allocator for runtime records.
//!
//! This module provides a simple arena allocator for managing runtime records
//! (tasks, regions, obligations). The arena provides stable indices that can
//! be used as identifiers.
//!
//! # Design
//!
//! - Elements are stored in a Vec with generation counters for ABA safety
//! - Removed elements are tracked in a free list for reuse
//! - No unsafe code; relies on bounds checking and generation validation

use core::fmt;
use core::hash::{Hash, Hasher};

/// An index into an arena with a generation counter for ABA safety.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArenaIndex {
    index: u32,
    generation: u32,
}

impl ArenaIndex {
    /// Creates a new arena index (primarily for testing).
    #[inline]
    #[must_use]
    pub const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    /// Returns the raw index value.
    #[inline]
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Returns the generation counter.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

impl fmt::Debug for ArenaIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArenaIndex({}:{})", self.index, self.generation)
    }
}

impl Hash for ArenaIndex {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        let packed = (u64::from(self.index) << 32) | u64::from(self.generation);
        state.write_u64(packed);
    }
}

/// A slot in the arena that can be occupied or vacant.
#[derive(Debug)]
enum Slot<T> {
    Occupied {
        value: T,
        generation: u32,
    },
    Vacant {
        next_free: Option<u32>,
        generation: u32,
    },
}

/// A simple arena allocator with generation-based indices.
///
/// This arena provides stable indices for inserted elements, with generation
/// counters to detect use-after-free errors (ABA problem).
#[derive(Debug)]
pub struct Arena<T> {
    slots: Vec<Slot<T>>,
    free_head: Option<u32>,
    len: usize,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arena<T> {
    /// Creates a new empty arena.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            len: 0,
        }
    }

    /// Creates a new arena with the specified capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free_head: None,
            len: 0,
        }
    }

    /// Returns the number of occupied slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the arena has no occupied slots.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts a value into the arena and returns its index.
    #[inline]
    pub fn insert(&mut self, value: T) -> ArenaIndex {
        if let Some(free_index) = self.free_head {
            let slot = &mut self.slots[free_index as usize];
            let idx = match slot {
                Slot::Vacant {
                    next_free,
                    generation,
                } => {
                    let gen = *generation;
                    self.free_head = *next_free;
                    *slot = Slot::Occupied {
                        value,
                        generation: gen,
                    };
                    ArenaIndex {
                        index: free_index,
                        generation: gen,
                    }
                }
                Slot::Occupied { .. } => unreachable!("free list pointed to occupied slot"),
            };
            self.len += 1;
            idx
        } else {
            let index = u32::try_from(self.slots.len()).expect("arena overflow");
            self.slots.push(Slot::Occupied {
                value,
                generation: 0,
            });
            self.len += 1;
            ArenaIndex {
                index,
                generation: 0,
            }
        }
    }

    /// Inserts a value produced by `f` into the arena and returns its index.
    ///
    /// The closure receives the assigned `ArenaIndex`, allowing callers to
    /// construct records that embed their final ID without placeholder updates.
    pub fn insert_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> T,
    {
        if let Some(free_index) = self.free_head {
            let (next_free, generation) = match self.slots[free_index as usize] {
                Slot::Vacant {
                    next_free,
                    generation,
                } => (next_free, generation),
                Slot::Occupied { .. } => unreachable!("free list pointed to occupied slot"),
            };

            let idx = ArenaIndex {
                index: free_index,
                generation,
            };
            let value = f(idx);

            self.free_head = next_free;
            self.slots[free_index as usize] = Slot::Occupied { value, generation };
            self.len += 1;
            idx
        } else {
            let index = u32::try_from(self.slots.len()).expect("arena overflow");
            let idx = ArenaIndex {
                index,
                generation: 0,
            };
            let value = f(idx);
            self.slots.push(Slot::Occupied {
                value,
                generation: 0,
            });
            self.len += 1;
            idx
        }
    }

    /// Removes the value at the given index and returns it.
    ///
    /// Returns `None` if the index is invalid or the slot is vacant.
    pub fn remove(&mut self, index: ArenaIndex) -> Option<T> {
        let slot = self.slots.get_mut(index.index as usize)?;

        match slot {
            Slot::Occupied { generation, .. } if *generation == index.generation => {
                let new_gen = generation.wrapping_add(1);
                let old_slot = core::mem::replace(
                    slot,
                    Slot::Vacant {
                        next_free: self.free_head,
                        generation: new_gen,
                    },
                );
                self.free_head = Some(index.index);
                self.len -= 1;

                match old_slot {
                    Slot::Occupied { value, .. } => Some(value),
                    Slot::Vacant { .. } => unreachable!(),
                }
            }
            _ => None,
        }
    }

    /// Returns a reference to the value at the given index.
    ///
    /// Returns `None` if the index is invalid or the slot is vacant.
    #[inline]
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&T> {
        match self.slots.get(index.index as usize)? {
            Slot::Occupied { value, generation } if *generation == index.generation => Some(value),
            _ => None,
        }
    }

    /// Returns a mutable reference to the value at the given index.
    ///
    /// Returns `None` if the index is invalid or the slot is vacant.
    #[inline]
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut T> {
        match self.slots.get_mut(index.index as usize)? {
            Slot::Occupied { value, generation } if *generation == index.generation => Some(value),
            _ => None,
        }
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all elements `e` such that `f(&e)` returns `false`.
    /// This method operates in place and preserves the generation counters of removed elements.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut T) -> bool,
    {
        // Pass 1: Apply predicate and mark slots as Vacant if needed.
        let mut new_len = 0;
        for slot in &mut self.slots {
            let is_occupied = matches!(*slot, Slot::Occupied { .. });
            if is_occupied {
                // Check if we should remove (and run side effects)
                // We use a separate match to avoid holding the borrow of `slot` while calling `f`
                let remove = match slot {
                    Slot::Occupied { value, .. } => !f(value),
                    Slot::Vacant { .. } => unreachable!(),
                };

                if remove {
                    // Perform removal
                    // Re-match to get generation (safe because previous borrow ended)
                    let gen = if let Slot::Occupied { generation, .. } = slot {
                        *generation
                    } else {
                        unreachable!()
                    };

                    *slot = Slot::Vacant {
                        next_free: None,
                        generation: gen.wrapping_add(1),
                    };
                } else {
                    new_len += 1;
                }
            }
        }
        self.len = new_len;

        // Pass 2: Rebuild free list in-place.
        let mut first_free = None;
        let mut last_free: Option<usize> = None;

        for i in 0..self.slots.len() {
            // Check if vacant (read-only borrow)
            let is_vacant = matches!(self.slots[i], Slot::Vacant { .. });

            if is_vacant {
                if let Some(prev) = last_free {
                    // Link previous to current (mutable borrow of distinct element)
                    if let Slot::Vacant { next_free, .. } = &mut self.slots[prev] {
                        *next_free = Some(i as u32);
                    }
                } else {
                    first_free = Some(i as u32);
                }
                last_free = Some(i);
            }
        }

        // Terminate the last one
        if let Some(last) = last_free {
            if let Slot::Vacant { next_free, .. } = &mut self.slots[last] {
                *next_free = None;
            }
        }

        self.free_head = first_free;
    }

    /// Returns true if the index is valid and points to an occupied slot.
    #[must_use]
    pub fn contains(&self, index: ArenaIndex) -> bool {
        self.get(index).is_some()
    }

    /// Iterates over all occupied slots.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| match slot {
                Slot::Occupied { value, generation } => Some((
                    ArenaIndex {
                        index: i as u32,
                        generation: *generation,
                    },
                    value,
                )),
                Slot::Vacant { .. } => None,
            })
    }

    /// Iterates mutably over all occupied slots.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (ArenaIndex, &mut T)> {
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(i, slot)| match slot {
                Slot::Occupied { value, generation } => Some((
                    ArenaIndex {
                        index: i as u32,
                        generation: *generation,
                    },
                    value,
                )),
                Slot::Vacant { .. } => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn insert_and_get() {
        let mut arena = Arena::new();
        let idx = arena.insert(42);
        assert_eq!(arena.get(idx), Some(&42));
        assert_eq!(arena.len(), 1);
    }

    #[test]
    fn remove_and_reuse() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(1);
        let idx2 = arena.insert(2);

        assert_eq!(arena.remove(idx1), Some(1));
        assert_eq!(arena.len(), 1);

        // Old index should be invalid
        assert_eq!(arena.get(idx1), None);

        // New insert should reuse the slot
        let idx3 = arena.insert(3);
        assert_eq!(idx3.index(), idx1.index());
        assert_ne!(idx3.generation(), idx1.generation());

        // Both remaining indices should work
        assert_eq!(arena.get(idx2), Some(&2));
        assert_eq!(arena.get(idx3), Some(&3));
    }

    #[test]
    fn generation_prevents_aba() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(1);
        arena.remove(idx1);
        let idx2 = arena.insert(2);

        // Same slot, different generation
        assert_eq!(idx1.index(), idx2.index());
        assert_ne!(idx1.generation(), idx2.generation());

        // Old index should not work
        assert_eq!(arena.get(idx1), None);
        assert_eq!(arena.get(idx2), Some(&2));
    }

    #[test]
    fn insert_with_passes_assigned_index() {
        let mut arena = Arena::new();
        let idx = arena.insert_with(super::ArenaIndex::index);
        assert_eq!(arena.get(idx), Some(&idx.index()));
    }

    #[test]
    fn insert_with_panic_keeps_arena_empty_when_no_free_slots() {
        let mut arena = Arena::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = arena.insert_with(|_| -> u32 { panic!("boom") });
        }));
        assert!(result.is_err());
        assert!(arena.is_empty());
        assert_eq!(arena.len(), 0);

        let idx = arena.insert(7);
        assert_eq!(idx.index(), 0);
        assert_eq!(arena.get(idx), Some(&7));
    }

    #[test]
    fn insert_with_panic_preserves_free_list_when_reusing_slot() {
        let mut arena = Arena::new();
        let idx1 = arena.insert(10);
        let idx2 = arena.insert(20);
        assert_eq!(arena.remove(idx1), Some(10));
        assert_eq!(arena.len(), 1);

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = arena.insert_with(|_| -> u32 { panic!("boom") });
        }));
        assert!(result.is_err());
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.get(idx2), Some(&20));

        // The next insert should still reuse the previously freed slot.
        let reused = arena.insert(30);
        assert_eq!(reused.index(), idx1.index());
        assert_ne!(reused.generation(), idx1.generation());
        assert_eq!(arena.get(reused), Some(&30));
    }

    #[test]
    fn test_retain() {
        let mut arena = Arena::new();
        let idx0 = arena.insert(0);
        let idx1 = arena.insert(1);
        let idx2 = arena.insert(2);
        let idx3 = arena.insert(3);

        assert_eq!(arena.len(), 4);

        // Remove odd numbers
        arena.retain(|&mut val| val % 2 == 0);

        assert_eq!(arena.len(), 2);
        assert_eq!(arena.get(idx0), Some(&0));
        assert_eq!(arena.get(idx1), None);
        assert_eq!(arena.get(idx2), Some(&2));
        assert_eq!(arena.get(idx3), None);

        // Insert new items - should reuse slots of 1 and 3 (indices 1 and 3)
        // Free list order is linear (0..N) after retain rebuilds it.
        // So first free should be 1, then 3.

        let idx_new_a = arena.insert(10);
        let idx_new_b = arena.insert(30);

        assert_eq!(idx_new_a.index(), 1);
        assert_eq!(idx_new_b.index(), 3);
        assert_eq!(arena.len(), 4);

        // Generations should be bumped
        assert_ne!(idx_new_a.generation(), idx1.generation());
        assert_ne!(idx_new_b.generation(), idx3.generation());
    }
}
