//! Region table for structured-concurrency ownership data.
//!
//! Encapsulates the region arena to enable finer-grained locking and clearer
//! ownership boundaries in RuntimeState. Provides both low-level arena access
//! and domain-level methods for region lifecycle management.
//! Cross-cutting concerns (tracing, metrics) remain in RuntimeState.

use crate::record::region::AdmissionError;
use crate::record::{RegionLimits, RegionRecord};
use crate::types::{Budget, RegionId, Time};
use crate::util::{Arena, ArenaIndex};

/// Errors that can occur when creating a child region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionCreateError {
    /// The parent region does not exist.
    ParentNotFound(RegionId),
    /// The parent region is closed or draining and cannot accept new children.
    ParentClosed(RegionId),
    /// The parent region has reached its admission limit for children.
    ParentAtCapacity {
        /// The parent region that rejected the child.
        region: RegionId,
        /// The configured admission limit.
        limit: usize,
        /// The number of live children at the time of rejection.
        live: usize,
    },
}

impl std::fmt::Display for RegionCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentNotFound(id) => write!(f, "parent region not found: {id:?}"),
            Self::ParentClosed(id) => write!(f, "parent region closed: {id:?}"),
            Self::ParentAtCapacity {
                region,
                limit,
                live,
            } => write!(
                f,
                "parent region admission limit reached: region={region:?} limit={limit} live={live}"
            ),
        }
    }
}

impl std::error::Error for RegionCreateError {}

/// Encapsulates the region arena for ownership tree operations.
///
/// Provides both low-level arena access and domain-level methods for
/// region lifecycle management (create root/child, admission control).
/// Cross-cutting concerns (tracing, metrics) remain in RuntimeState.
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

    // =========================================================================
    // Low-level arena access
    // =========================================================================

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

    /// Inserts a new region record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    pub fn insert_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> RegionRecord,
    {
        self.regions.insert_with(f)
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

    // =========================================================================
    // Domain-level region operations
    // =========================================================================

    /// Creates a root region record and returns its ID.
    ///
    /// Callers are responsible for emitting trace events and setting
    /// `root_region` on RuntimeState.
    pub fn create_root(&mut self, budget: Budget, now: Time) -> RegionId {
        let idx = self.regions.insert_with(|idx| {
            RegionRecord::new_with_time(RegionId::from_arena(idx), None, budget, now)
        });
        RegionId::from_arena(idx)
    }

    /// Creates a child region under the given parent and returns its ID.
    ///
    /// The child's effective budget is the meet (tightest constraints) of the
    /// parent budget and the provided budget. On failure, the child record is
    /// rolled back (removed from the arena).
    ///
    /// Callers are responsible for emitting trace events.
    pub fn create_child(
        &mut self,
        parent: RegionId,
        budget: Budget,
        now: Time,
    ) -> Result<RegionId, RegionCreateError> {
        let parent_budget = self
            .regions
            .get(parent.arena_index())
            .map(RegionRecord::budget)
            .ok_or(RegionCreateError::ParentNotFound(parent))?;

        let effective_budget = parent_budget.meet(budget);

        let idx = self.regions.insert_with(|idx| {
            RegionRecord::new_with_time(
                RegionId::from_arena(idx),
                Some(parent),
                effective_budget,
                now,
            )
        });
        let id = RegionId::from_arena(idx);

        let add_result = self
            .regions
            .get(parent.arena_index())
            .ok_or(RegionCreateError::ParentNotFound(parent))
            .and_then(|record| {
                record.add_child(id).map_err(|err| match err {
                    AdmissionError::Closed => RegionCreateError::ParentClosed(parent),
                    AdmissionError::LimitReached { limit, live, .. } => {
                        RegionCreateError::ParentAtCapacity {
                            region: parent,
                            limit,
                            live,
                        }
                    }
                })
            });

        if let Err(err) = add_result {
            self.regions.remove(idx);
            return Err(err);
        }

        Ok(id)
    }

    /// Updates admission limits for a region.
    ///
    /// Returns `false` if the region does not exist.
    #[must_use]
    pub fn set_limits(&self, region: RegionId, limits: RegionLimits) -> bool {
        let Some(record) = self.regions.get(region.arena_index()) else {
            return false;
        };
        record.set_limits(limits);
        true
    }

    /// Returns the current admission limits for a region.
    #[must_use]
    pub fn limits(&self, region: RegionId) -> Option<RegionLimits> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::limits)
    }

    /// Returns the current state of a region.
    #[must_use]
    pub fn state(&self, region: RegionId) -> Option<crate::record::region::RegionState> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::state)
    }

    /// Returns the parent of a region.
    #[must_use]
    pub fn parent(&self, region: RegionId) -> Option<Option<RegionId>> {
        self.regions.get(region.arena_index()).map(|r| r.parent)
    }

    /// Returns the budget of a region.
    #[must_use]
    pub fn budget(&self, region: RegionId) -> Option<Budget> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::budget)
    }

    /// Returns child IDs of a region.
    #[must_use]
    pub fn child_ids(&self, region: RegionId) -> Option<Vec<RegionId>> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::child_ids)
    }

    /// Returns task IDs of a region.
    #[must_use]
    pub fn task_ids(&self, region: RegionId) -> Option<Vec<crate::types::TaskId>> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::task_ids)
    }

    /// Returns the number of pending obligations for a region.
    #[must_use]
    pub fn pending_obligations(&self, region: RegionId) -> Option<usize> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::pending_obligations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::region::RegionState;

    #[test]
    fn create_root_region() {
        let mut table = RegionTable::new();
        let id = table.create_root(Budget::default(), Time::ZERO);
        assert_eq!(table.len(), 1);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.id, id);
        assert!(record.parent.is_none());
        assert_eq!(record.state(), RegionState::Open);
    }

    #[test]
    fn create_child_region() {
        let mut table = RegionTable::new();
        let parent = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(parent, Budget::default(), Time::ZERO)
            .unwrap();

        assert_eq!(table.len(), 2);
        let child_rec = table.get(child.arena_index()).unwrap();
        assert_eq!(child_rec.parent, Some(parent));

        let parent_children = table.child_ids(parent).unwrap();
        assert!(parent_children.contains(&child));
    }

    #[test]
    fn create_child_nonexistent_parent_fails() {
        let mut table = RegionTable::new();
        let fake_parent = RegionId::from_arena(ArenaIndex::new(99, 0));
        let result = table.create_child(fake_parent, Budget::default(), Time::ZERO);
        assert!(matches!(result, Err(RegionCreateError::ParentNotFound(_))));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn create_child_rolls_back_on_admission_failure() {
        let mut table = RegionTable::new();
        let parent = table.create_root(Budget::default(), Time::ZERO);

        // Set limit to 1 child
        assert!(table.set_limits(
            parent,
            RegionLimits {
                max_children: Some(1),
                ..RegionLimits::UNLIMITED
            },
        ));

        // First child should succeed
        let _child1 = table
            .create_child(parent, Budget::default(), Time::ZERO)
            .unwrap();
        assert_eq!(table.len(), 2);

        // Second child should fail and roll back
        let result = table.create_child(parent, Budget::default(), Time::ZERO);
        assert!(matches!(
            result,
            Err(RegionCreateError::ParentAtCapacity { .. })
        ));
        assert_eq!(table.len(), 2); // No leaked record
    }

    #[test]
    fn create_child_rolls_back_when_parent_is_closed() {
        let mut table = RegionTable::new();
        let parent = table.create_root(Budget::default(), Time::ZERO);

        let parent_record = table.get(parent.arena_index()).unwrap();
        assert!(parent_record.begin_close(None));

        let result = table.create_child(parent, Budget::default(), Time::ZERO);
        assert!(matches!(result, Err(RegionCreateError::ParentClosed(_))));
        assert_eq!(table.len(), 1); // Child insert must be rolled back
        assert!(table.child_ids(parent).unwrap().is_empty());
    }

    #[test]
    fn create_child_uses_meet_for_effective_budget() {
        let mut table = RegionTable::new();
        let parent_budget = Budget::new()
            .with_deadline(Time::from_secs(50))
            .with_poll_quota(1_000)
            .with_cost_quota(100)
            .with_priority(80);
        let child_budget = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(2_000)
            .with_cost_quota(50)
            .with_priority(200);
        let expected = parent_budget.meet(child_budget);

        let parent = table.create_root(parent_budget, Time::ZERO);
        let child = table.create_child(parent, child_budget, Time::ZERO).unwrap();

        let actual = table.budget(child).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn set_and_get_limits() {
        let mut table = RegionTable::new();
        let id = table.create_root(Budget::default(), Time::ZERO);

        let limits = RegionLimits {
            max_tasks: Some(10),
            max_children: Some(5),
            ..RegionLimits::UNLIMITED
        };
        assert!(table.set_limits(id, limits.clone()));
        assert_eq!(table.limits(id).unwrap(), limits);
    }

    #[test]
    fn set_limits_nonexistent_returns_false() {
        let table = RegionTable::new();
        let fake = RegionId::from_arena(ArenaIndex::new(99, 0));
        assert!(!table.set_limits(fake, RegionLimits::UNLIMITED));
    }

    #[test]
    fn state_and_parent_accessors() {
        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(root, Budget::default(), Time::ZERO)
            .unwrap();

        assert_eq!(table.state(root), Some(RegionState::Open));
        assert_eq!(table.parent(root), Some(None));
        assert_eq!(table.parent(child), Some(Some(root)));
    }

    #[test]
    fn pending_obligations_initial_zero() {
        let mut table = RegionTable::new();
        let id = table.create_root(Budget::default(), Time::ZERO);
        assert_eq!(table.pending_obligations(id), Some(0));
    }
}
