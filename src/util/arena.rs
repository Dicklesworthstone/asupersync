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

/// Maximum generation allowed before an arena slot is retired permanently.
///
/// Retiring slots at `ARENA_MAX_GENERATION` (2^31 - 1) serves two critical
/// purposes:
/// 1. Prevents generation wrapping back to 0 (the ABA hazard addressed in
///    `br-asupersync-rvz1tq`).
/// 2. Ensures that canonical arena indices never have their MSB (bit 31) set,
///    preventing collisions with provisional ID namespaces that reserve bit 31
///    (e.g., `SPAWN_ID_GENERATION_TAG = 0x8000_0000` in `spawn_mailbox.rs`;
///    `br-asupersync-01oghn` L2).
pub const ARENA_MAX_GENERATION: u32 = 0x7fff_ffff;

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
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arena<T> {
    /// Creates a new empty arena.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            len: 0,
        }
    }

    /// Creates a new arena with the specified capacity.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free_head: None,
            len: 0,
        }
    }

    /// Returns the number of occupied slots.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns the reserved slot capacity of the arena backing storage.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    /// Returns the estimated bytes reserved by the arena backing slots.
    #[inline]
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        Self::estimated_bytes_for_capacity(self.capacity())
    }

    /// Returns the estimated bytes required to reserve `capacity` arena slots.
    #[inline]
    #[must_use]
    pub fn estimated_bytes_for_capacity(capacity: usize) -> usize {
        capacity.saturating_mul(core::mem::size_of::<Slot<T>>())
    }

    /// Returns true if the arena has no occupied slots.
    #[inline]
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
                    let generation_value = *generation;
                    self.free_head = *next_free;
                    *slot = Slot::Occupied {
                        value,
                        generation: generation_value,
                    };
                    ArenaIndex {
                        index: free_index,
                        generation: generation_value,
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
    /// construct records that embed their final ID without later backpatching.
    #[inline]
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
    ///
    /// br-asupersync-rvz1tq / br-asupersync-01oghn (L2) — generation-overflow safety:
    /// if the slot has already cycled through `ARENA_MAX_GENERATION` reuses (2^31 - 1),
    /// the next generation would set bit 31 (colliding with provisional IDs such as
    /// `SPAWN_ID_GENERATION_TAG`) and eventually roll back to 0 (ABA bypass).
    /// This branch panics in debug to catch the bug fast, and in release retires
    /// the slot permanently — it is removed from the free list so it is never
    /// reused, capping the leak at one slot per 2^31 reuses (per slot).
    #[inline]
    pub fn remove(&mut self, index: ArenaIndex) -> Option<T> {
        let slot = self.slots.get_mut(index.index as usize)?;

        match slot {
            Slot::Occupied { generation, .. } if *generation == index.generation => {
                let cur_gen = *generation;
                let retire_slot = if cur_gen >= ARENA_MAX_GENERATION {
                    debug_assert!(
                        false,
                        "ArenaIndex generation wrap detected at slot {} \
                         (br-asupersync-rvz1tq / br-asupersync-01oghn L2)",
                        index.index
                    );
                    true
                } else {
                    false
                };
                let new_gen = cur_gen.wrapping_add(1);
                let old_slot = core::mem::replace(
                    slot,
                    Slot::Vacant {
                        // Retired slot: detached from the free list so it
                        // will never be re-allocated.
                        next_free: if retire_slot { None } else { self.free_head },
                        generation: new_gen,
                    },
                );
                if !retire_slot {
                    self.free_head = Some(index.index);
                }
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
    ///
    /// Uses a single pass over `self.slots` that applies the predicate and
    /// rebuilds the free list simultaneously, instead of the two-pass approach.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut T) -> bool,
    {
        struct Guard<'a, T> {
            arena: &'a mut Arena<T>,
            current_index: usize,
            new_len: usize,
            first_free: Option<u32>,
            prev_free: Option<usize>,
            panicked: bool,
        }

        impl<T> Drop for Guard<'_, T> {
            fn drop(&mut self) {
                // If we dropped early (panic), the current element i was Occupied
                // and f() panicked, so it remains Occupied. We must count it.
                if self.panicked && self.current_index < self.arena.slots.len() {
                    self.new_len += 1;
                    self.current_index += 1;
                }

                // Process the remaining slots to link any existing Vacant slots
                // into our newly rebuilt free list.
                for i in self.current_index..self.arena.slots.len() {
                    if matches!(&self.arena.slots[i], Slot::Occupied { .. }) {
                        self.new_len += 1;
                        continue;
                    }

                    if let Slot::Vacant {
                        next_free,
                        generation,
                    } = &mut self.arena.slots[i]
                    {
                        if *generation == 0 {
                            continue;
                        }
                        *next_free = None;
                    }

                    if let Some(prev) = self.prev_free {
                        if let Slot::Vacant { next_free, .. } = &mut self.arena.slots[prev] {
                            *next_free = Some(i as u32);
                        }
                    } else {
                        self.first_free = Some(i as u32);
                    }
                    self.prev_free = Some(i);
                }

                self.arena.len = self.new_len;
                self.arena.free_head = self.first_free;
            }
        }

        let mut guard = Guard {
            arena: self,
            current_index: 0,
            new_len: 0,
            first_free: None,
            prev_free: None,
            panicked: true,
        };

        while guard.current_index < guard.arena.slots.len() {
            let i = guard.current_index;

            let kept = match &mut guard.arena.slots[i] {
                Slot::Occupied { value, .. } => f(value),
                Slot::Vacant { .. } => false,
            };

            if kept {
                guard.new_len += 1;
                guard.current_index += 1;
                continue;
            }

            let mut skip_link = false;
            if let Slot::Occupied { generation, .. } = &guard.arena.slots[i] {
                let cur_gen = *generation;
                let retire_slot = cur_gen >= ARENA_MAX_GENERATION;
                if retire_slot {
                    debug_assert!(
                        false,
                        "ArenaIndex generation wrap detected at slot {} \
                         (br-asupersync-rvz1tq / br-asupersync-01oghn L2)",
                        i
                    );
                }
                guard.arena.slots[i] = Slot::Vacant {
                    next_free: None,
                    generation: cur_gen.wrapping_add(1),
                };
                if retire_slot {
                    skip_link = true;
                }
            } else if let Slot::Vacant {
                next_free,
                generation,
            } = &mut guard.arena.slots[i]
            {
                if *generation == 0 {
                    skip_link = true;
                } else {
                    *next_free = None;
                }
            }

            if skip_link {
                guard.current_index += 1;
                continue;
            }

            if let Some(prev) = guard.prev_free {
                if let Slot::Vacant { next_free, .. } = &mut guard.arena.slots[prev] {
                    *next_free = Some(i as u32);
                }
            } else {
                guard.first_free = Some(i as u32);
            }
            guard.prev_free = Some(i);

            guard.current_index += 1;
        }

        guard.panicked = false;
    }

    /// Drains all occupied values, leaving the arena empty.
    ///
    /// Yields ownership of each value without cloning, in index order. All
    /// slots become vacant and are linked into the free list ahead of the
    /// slots already free, lowest index first, so the next inserts reuse the
    /// lowest indices. The scan stops at the last occupied slot.
    pub fn drain_values(&mut self) -> DrainValues<'_, T> {
        DrainValues {
            arena: self,
            pos: 0,
            last_drained: None,
        }
    }

    /// Returns true if the index is valid and points to an occupied slot.
    #[inline]
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
                        // br-asupersync-njd135 — explicit bounds check on
                        // the usize→u32 cast. The arena enforces
                        // slots.len() <= u32::MAX at insert (line 154 uses
                        // try_from + expect); if that invariant is ever
                        // violated, fail loud here rather than silently
                        // truncate the index and produce a bogus
                        // ArenaIndex that aliases an unrelated slot.
                        index: u32::try_from(i).expect("arena slot index overflows u32"),
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
                        // br-asupersync-njd135 — explicit bounds check on
                        // the usize→u32 cast. The arena enforces
                        // slots.len() <= u32::MAX at insert (line 154 uses
                        // try_from + expect); if that invariant is ever
                        // violated, fail loud here rather than silently
                        // truncate the index and produce a bogus
                        // ArenaIndex that aliases an unrelated slot.
                        index: u32::try_from(i).expect("arena slot index overflows u32"),
                        generation: *generation,
                    },
                    value,
                )),
                Slot::Vacant { .. } => None,
            })
    }
}

/// Iterator that drains all occupied values from an [`Arena`].
///
/// Produced by [`Arena::drain_values`]. On each call to `next`, the next
/// occupied slot is converted to vacant and its value yielded by ownership.
/// When the iterator is dropped (whether exhausted or not), any remaining
/// occupied slots are also drained.
pub struct DrainValues<'a, T> {
    arena: &'a mut Arena<T>,
    pos: usize,
    /// The last slot this drain linked into the free list; the next drained
    /// slot is linked right after it.
    last_drained: Option<u32>,
}

impl<T> Iterator for DrainValues<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        // br-asupersync-lh4z78 L3: an arena that once held many entries is
        // not rescanned past its last occupied slot. Broadcast drains its
        // waker arena on every send, so the scan used to cost the arena's
        // historical peak even with one waiter or none.
        while self.arena.len > 0 && self.pos < self.arena.slots.len() {
            let i = self.pos;
            self.pos += 1;

            if let Slot::Occupied { generation, .. } = &self.arena.slots[i] {
                let cur_gen = *generation;
                let retire_slot = cur_gen >= ARENA_MAX_GENERATION;
                if retire_slot {
                    debug_assert!(
                        false,
                        "ArenaIndex generation wrap detected at slot {} \
                         (br-asupersync-rvz1tq / br-asupersync-01oghn L2)",
                        i
                    );
                }
                let new_gen = cur_gen.wrapping_add(1);
                let index = u32::try_from(i).expect("arena slot index overflows u32");
                // Drained slots join the free list in ascending order ahead
                // of the slots already free, so inserts after the drain take
                // the lowest indices and the next drain stops early. Each
                // step leaves the list consistent.
                let next_free = if retire_slot {
                    None
                } else if let Some(previous) = self.last_drained {
                    match &mut self.arena.slots[previous as usize] {
                        Slot::Vacant { next_free, .. } => next_free.replace(index),
                        Slot::Occupied { .. } => {
                            unreachable!(
                                "a drained slot stays vacant while the drain holds the arena"
                            )
                        }
                    }
                } else {
                    self.arena.free_head.replace(index)
                };
                let old = core::mem::replace(
                    &mut self.arena.slots[i],
                    Slot::Vacant {
                        next_free,
                        generation: new_gen,
                    },
                );
                if !retire_slot {
                    self.last_drained = Some(index);
                }
                self.arena.len -= 1;
                if let Slot::Occupied { value, .. } = old {
                    return Some(value);
                }
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.arena.len))
    }
}

impl<T> Drop for DrainValues<'_, T> {
    fn drop(&mut self) {
        // Exhaust the iterator to ensure all values are dropped and
        // the arena is left in a consistent state.
        for _ in self {}
    }
}

#[cfg(test)]
#[path = "arena_inline_tests.rs"]
mod tests;

