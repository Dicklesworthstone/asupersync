//! Region table for structured-concurrency ownership data.
//!
//! Encapsulates the region arena to enable finer-grained locking and clearer
//! ownership boundaries in RuntimeState.

use crate::record::RegionRecord;
use crate::util::{Arena, ArenaIndex};

/// Encapsulates the region arena for ownership tree operations.
#[derive(Debug, Default)]
pub struct RegionTable {
    regions: Arena<RegionRecord>,
}

impl RegionTable {
    /// Creates an empty region table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Arena::new(),
        }
    }

    /// Returns a shared reference to a region record by arena index.
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&RegionRecord> {
        self.regions.get(index)
    }

    /// Returns a mutable reference to a region record by arena index.
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut RegionRecord> {
        self.regions.get_mut(index)
    }

    /// Inserts a new region record into the arena.
    pub fn insert(&mut self, record: RegionRecord) -> ArenaIndex {
        self.regions.insert(record)
    }

    /// Removes a region record from the arena.
    pub fn remove(&mut self, index: ArenaIndex) -> Option<RegionRecord> {
        self.regions.remove(index)
    }

    /// Returns an iterator over all region records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &RegionRecord)> {
        self.regions.iter()
    }

    /// Returns the number of region records in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` if the region table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}
