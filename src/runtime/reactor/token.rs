//! Token slab allocator for waker mapping.
//!
//! This module provides efficient management of I/O source registrations,
//! mapping compact integer tokens to task wakers. When the reactor reports
//! events, the token is used to find and wake the correct task.
//!
//! # Design
//!
//! The slab allocator uses a free list for O(1) allocation and deallocation.
//! Each token includes a generation counter to prevent ABA problems where
//! a freed slot is reallocated and a stale token references the wrong waker.
//!
//! # Example
//!
//! ```ignore
//! use std::task::Waker;
//!
//! let mut slab = TokenSlab::new();
//! let token = slab.insert(waker);
//!
//! // Later, when event arrives:
//! if let Some(waker) = slab.get(token) {
//!     waker.wake_by_ref();
//! }
//!
//! // When deregistering:
//! slab.remove(token);
//! ```

use std::task::Waker;

// SlabToken encodes two u32 fields (index + generation) into usize.
// On 64-bit targets, this is completely lossless (32 bits each).
//
// br-asupersync-rtiu1s — On 32-bit targets, the previous packing was
// 24 bits index + 8 bits generation. The 8-bit generation field
// wrapped after only 256 reuse cycles per slot — well within the
// lifetime of a long-running 32-bit reactor — and a stale token from
// generation N could match a slot reissued at generation N (mod 256),
// defeating the ABA guard the generation counter is supposed to
// provide. The new 32-bit packing splits the available 32 bits as
// 16 bits index + 16 bits generation, raising the wrap point to
// 65,536 cycles per slot. Slab capacity on 32-bit drops from
// 2^24 ≈ 16M to 2^16 = 65,536 slots, which is comfortably above the
// typical I/O reactor working set.

/// Compact identifier for registered I/O sources.
///
/// Tokens are indexes into a slab allocator. They encode:
/// - Index: which slot in the slab
/// - Generation: catches use-after-free (ABA prevention)
///
/// The generation counter ensures that if a token is freed and the slot
/// is reused, any stale tokens referencing the old allocation will fail
/// to match.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SlabToken {
    index: u32,
    generation: u32,
}

impl SlabToken {
    /// Creates a new token with the given index and generation.
    const fn new(index: u32, generation: u32) -> Self {
        Self { index, generation }
    }

    /// Returns the index portion of the token.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the generation portion of the token.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Packs the token into a single usize for reactor APIs (mio compatibility).
    ///
    /// On 64-bit platforms: generation is in upper 32 bits, index in lower 32 bits.
    /// On 32-bit platforms (br-asupersync-rtiu1s): generation is in upper 16
    /// bits, index in lower 16 bits — widened from the previous 8-bit
    /// generation that wrapped after only 256 cycles.
    #[must_use]
    pub const fn to_usize(self) -> usize {
        #[cfg(target_pointer_width = "64")]
        {
            ((self.generation as usize) << 32) | (self.index as usize)
        }
        #[cfg(target_pointer_width = "32")]
        {
            ((self.generation as usize & 0xFFFF) << 16) | (self.index as usize & 0xFFFF)
        }
        #[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
        {
            0 // Fallback for unsupported platforms
        }
    }

    /// Unpacks a usize into a token.
    #[must_use]
    pub const fn from_usize(val: usize) -> Self {
        #[cfg(target_pointer_width = "64")]
        {
            Self {
                index: val as u32,
                generation: (val >> 32) as u32,
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            let index = (val & 0xFFFF) as u32;
            let generation = ((val >> 16) & 0xFFFF) as u32;
            // Index `0xFFFF` is reserved (live indices are `<= MAX_INDEX ==
            // 0xFFFE`): it is the packed form of `invalid()`, so map it back to
            // the canonical invalid token rather than a spurious live token
            // (aasraf). This makes `from_usize(invalid().to_usize())` round-trip
            // to `invalid()` on 32-bit.
            if index == 0xFFFF {
                Self::invalid()
            } else {
                Self { index, generation }
            }
        }
        #[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
        {
            Self {
                index: 0,
                generation: 0,
            }
        }
    }

    /// The maximum generation value supported on this platform.
    #[cfg(target_pointer_width = "64")]
    pub const MAX_GENERATION: u32 = u32::MAX;

    /// br-asupersync-rtiu1s — Maximum generation value on 32-bit
    /// platforms. Previously `0xFF` (256 cycles, ABA-vulnerable);
    /// widened to `0xFFFF` (65,536 cycles) by reallocating 8 bits
    /// from the index field.
    #[cfg(target_pointer_width = "32")]
    pub const MAX_GENERATION: u32 = 0xFFFF;

    /// br-asupersync-rtiu1s — Maximum index value on 32-bit
    /// platforms. Reduced from 0xFF_FFFF (16M slots) to 0xFFFE
    /// (64K slots) to make room for the widened generation field.
    /// 64K is comfortably above the typical I/O reactor working set
    /// on a 32-bit host. The top index value `0xFFFF` is reserved as
    /// the packed [`invalid`](Self::invalid) sentinel (aasraf) so a
    /// live max-slot token can never alias it after a `usize`
    /// round-trip; a live index is therefore `<= 0xFFFE`.
    #[cfg(target_pointer_width = "32")]
    pub const MAX_INDEX: u32 = 0xFFFE;

    /// Maximum index value on 64-bit platforms (lossless).
    #[cfg(target_pointer_width = "64")]
    pub const MAX_INDEX: u32 = u32::MAX;

    /// Returns an invalid token that will never match any slab entry.
    ///
    /// On 32-bit platforms the packed form (`to_usize`) folds to index bits
    /// `0xFFFF`, which is reserved above [`MAX_INDEX`](Self::MAX_INDEX) so no
    /// live token can produce it; [`from_usize`](Self::from_usize) maps it back
    /// here, so the sentinel survives a `usize` round-trip without aliasing a
    /// live max-slot token (aasraf).
    #[must_use]
    pub const fn invalid() -> Self {
        Self {
            index: u32::MAX,
            generation: u32::MAX,
        }
    }
}

impl Default for SlabToken {
    fn default() -> Self {
        Self::invalid()
    }
}

/// Entry in the token slab.
#[derive(Debug)]
enum Entry<T> {
    /// Occupied slot with a value.
    Occupied { value: T, generation: u32 },
    /// Vacant slot pointing to the next free slot.
    Vacant { next_free: u32, generation: u32 },
}

impl<T> Entry<T> {
    /// Returns the generation of this entry.
    fn generation(&self) -> u32 {
        match self {
            Self::Occupied { generation, .. } | Self::Vacant { generation, .. } => *generation,
        }
    }
}

/// Sentinel value indicating end of free list.
const FREE_LIST_END: u32 = u32::MAX;

/// Slab allocator for generational tokens.
///
/// The default payload is a [`Waker`], preserving the reactor-oriented API,
/// while callers that need callback-free ownership snapshots can select a
/// different payload type. The slab provides O(1) insert, get, and remove
/// operations. It maintains a free list of available slots and tracks
/// generation counters to prevent ABA problems.
///
/// # Thread Safety
///
/// `TokenSlab` is not thread-safe. For concurrent access, wrap it in a
/// synchronization primitive like `Mutex` or use per-thread slabs.
#[derive(Debug)]
pub struct TokenSlab<T = Waker> {
    /// Storage for entries.
    entries: Vec<Entry<T>>,
    /// Head of the free list (index of first free slot).
    free_head: u32,
    /// Number of occupied entries.
    len: usize,
}

impl<T> TokenSlab<T> {
    /// Creates a new empty token slab.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            free_head: FREE_LIST_END,
            len: 0,
        }
    }

    /// Creates a new token slab with the specified initial capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            free_head: FREE_LIST_END,
            len: 0,
        }
    }

    /// Inserts a value into the slab and returns its token.
    ///
    /// If there's a free slot, it will be reused. Otherwise, a new slot
    /// is allocated at the end.
    pub fn insert(&mut self, value: T) -> SlabToken {
        if self.free_head == FREE_LIST_END {
            // Allocate a new slot.
            #[cfg(target_pointer_width = "32")]
            assert!(
                self.entries.len() <= SlabToken::MAX_INDEX as usize,
                "TokenSlab capacity exceeded 32-bit packed token index capacity"
            );
            #[cfg(target_pointer_width = "64")]
            assert!(
                self.entries.len() < u32::MAX as usize,
                "TokenSlab capacity exceeded u32::MAX - 1 (conflicts with FREE_LIST_END)"
            );
            let index = self.entries.len() as u32;
            let generation = 0;

            self.entries.push(Entry::Occupied { value, generation });
            self.len += 1;

            SlabToken::new(index, generation)
        } else {
            // Reuse a free slot.
            let index = self.free_head;
            let entry = &mut self.entries[index as usize];

            // Get generation and next free from the vacant entry.
            let (generation, next_free) = match entry {
                Entry::Vacant {
                    next_free,
                    generation,
                } => (*generation, *next_free),
                Entry::Occupied { .. } => {
                    // This should never happen if our invariants are maintained.
                    unreachable!("free list pointed to occupied entry");
                }
            };

            // Convert to occupied entry (generation incremented on removal).
            *entry = Entry::Occupied { value, generation };
            self.free_head = next_free;
            self.len += 1;

            SlabToken::new(index, generation)
        }
    }

    /// Returns a reference to the value associated with the token.
    ///
    /// Returns `None` if the token is invalid, has been removed, or
    /// the generation doesn't match (stale token).
    #[must_use]
    pub fn get(&self, token: SlabToken) -> Option<&T> {
        let index = token.index as usize;
        if index >= self.entries.len() {
            return None;
        }

        match &self.entries[index] {
            Entry::Occupied { value, generation } if *generation == token.generation => Some(value),
            _ => None,
        }
    }

    /// Returns a mutable reference to the value associated with the token.
    ///
    /// Returns `None` if the token is invalid, has been removed, or
    /// the generation doesn't match (stale token).
    #[must_use]
    pub fn get_mut(&mut self, token: SlabToken) -> Option<&mut T> {
        let index = token.index as usize;
        if index >= self.entries.len() {
            return None;
        }

        match &mut self.entries[index] {
            Entry::Occupied { value, generation } if *generation == token.generation => Some(value),
            _ => None,
        }
    }

    /// Removes the value associated with the token and returns it.
    ///
    /// Returns `None` if the token is invalid, has been removed, or
    /// the generation doesn't match (stale token).
    ///
    /// The slot is added to the free list for reuse. The generation counter
    /// is incremented to invalidate any remaining references to this slot.
    pub fn remove(&mut self, token: SlabToken) -> Option<T> {
        let index = token.index as usize;
        let entry = self.entries.get_mut(index)?;

        let current_generation = match entry {
            Entry::Occupied { generation, .. } if *generation == token.generation => *generation,
            _ => return None,
        };

        // Increment generation to invalidate stale tokens.
        let new_generation = current_generation.wrapping_add(1) & SlabToken::MAX_GENERATION;
        let recycle_slot = current_generation != SlabToken::MAX_GENERATION;
        let next_free = if recycle_slot {
            self.free_head
        } else {
            FREE_LIST_END
        };
        let old_entry = std::mem::replace(
            entry,
            Entry::Vacant {
                next_free,
                generation: new_generation,
            },
        );

        if recycle_slot {
            self.free_head = index as u32;
        }
        self.len -= 1;

        match old_entry {
            Entry::Occupied { value, .. } => Some(value),
            Entry::Vacant { .. } => unreachable!(),
        }
    }

    /// Returns `true` if the token is valid (points to an occupied entry).
    #[must_use]
    pub fn contains(&self, token: SlabToken) -> bool {
        self.get(token).is_some()
    }

    /// Returns the number of values in the slab.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the slab contains no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the total capacity (including free slots).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Clears all entries from the slab.
    pub fn clear(&mut self) {
        if self.len == 0 {
            return;
        }

        self.free_head = FREE_LIST_END;
        for index in (0..self.entries.len()).rev() {
            let current_generation = self.entries[index].generation();
            let generation = current_generation.wrapping_add(1) & SlabToken::MAX_GENERATION;
            if current_generation == SlabToken::MAX_GENERATION {
                self.entries[index] = Entry::Vacant {
                    next_free: FREE_LIST_END,
                    generation,
                };
            } else {
                self.entries[index] = Entry::Vacant {
                    next_free: self.free_head,
                    generation,
                };
                self.free_head = index as u32;
            }
        }
        self.len = 0;
    }

    /// Retains only the values that satisfy the predicate.
    ///
    /// Values for which the predicate returns `false` are removed.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(SlabToken, &T) -> bool,
    {
        if self.len == 0 {
            return;
        }

        for index in 0..self.entries.len() {
            let mut remove = false;
            let current_generation = self.entries[index].generation();

            if let Entry::Occupied { value, generation } = &self.entries[index] {
                let token = SlabToken::new(index as u32, *generation);
                if !f(token, value) {
                    remove = true;
                }
            }

            if remove {
                let new_generation = current_generation.wrapping_add(1) & SlabToken::MAX_GENERATION;
                if current_generation == SlabToken::MAX_GENERATION {
                    self.entries[index] = Entry::Vacant {
                        next_free: FREE_LIST_END,
                        generation: new_generation,
                    };
                } else {
                    self.entries[index] = Entry::Vacant {
                        next_free: self.free_head,
                        generation: new_generation,
                    };
                    self.free_head = index as u32;
                }
                self.len -= 1;
            }
        }
    }

    /// Iterates over all occupied entries.
    pub fn iter(&self) -> impl Iterator<Item = (SlabToken, &T)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                if let Entry::Occupied { value, generation } = entry {
                    Some((SlabToken::new(index as u32, *generation), value))
                } else {
                    None
                }
            })
    }
}

impl<T> Default for TokenSlab<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "token_inline_tests.rs"]
mod tests;
