//! Obligation table for tracked resource obligations.
//!
//! Encapsulates the obligation arena to enable finer-grained locking and
//! clearer ownership boundaries in RuntimeState.

use crate::record::ObligationRecord;
use crate::util::{Arena, ArenaIndex};

/// Encapsulates the obligation arena for resource tracking operations.
#[derive(Debug, Default)]
pub struct ObligationTable {
    obligations: Arena<ObligationRecord>,
}

impl ObligationTable {
    /// Creates an empty obligation table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: Arena::new(),
        }
    }

    /// Returns a shared reference to an obligation record by arena index.
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&ObligationRecord> {
        self.obligations.get(index)
    }

    /// Returns a mutable reference to an obligation record by arena index.
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut ObligationRecord> {
        self.obligations.get_mut(index)
    }

    /// Inserts a new obligation record into the arena.
    pub fn insert(&mut self, record: ObligationRecord) -> ArenaIndex {
        self.obligations.insert(record)
    }

    /// Removes an obligation record from the arena.
    pub fn remove(&mut self, index: ArenaIndex) -> Option<ObligationRecord> {
        self.obligations.remove(index)
    }

    /// Returns an iterator over all obligation records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations.iter()
    }

    /// Returns the number of obligation records in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns `true` if the obligation table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obligations.is_empty()
    }
}
