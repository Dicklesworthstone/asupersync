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

/// An index into an arena with a generation counter for ABA safety.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArenaIndex {
    index: u32,
    generation: u32,
}

impl ArenaIndex {
    /// Creates a new arena index (primarily for testing).
    #[must_use]
    pub const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

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

impl fmt::Debug for ArenaIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArenaIndex({}:{})", self.index, self.generation)
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
    pub fn insert(&mut self, value: T) -> ArenaIndex {
        self.len += 1;

        if let Some(free_index) = self.free_head {
            let slot = &mut self.slots[free_index as usize];
            match slot {
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
            }
        } else {
            let index = u32::try_from(self.slots.len()).expect("arena overflow");
            self.slots.push(Slot::Occupied {
                value,
                generation: 0,
            });
            ArenaIndex {
                index,
                generation: 0,
            }
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
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut T> {
        match self.slots.get_mut(index.index as usize)? {
            Slot::Occupied { value, generation } if *generation == index.generation => Some(value),
            _ => None,
        }
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
}
