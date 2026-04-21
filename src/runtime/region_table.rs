//! Region table for structured-concurrency ownership data.
//!
//! Encapsulates the region arena to enable finer-grained locking and clearer
//! ownership boundaries in RuntimeState. Provides both low-level arena access
//! and domain-level methods for region lifecycle management.
//! Cross-cutting concerns (tracing, metrics) remain in RuntimeState.

use crate::record::region::AdmissionError;
use crate::record::{RegionLimits, RegionRecord};
use crate::runtime::resource_monitor::RegionPriority;
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
    /// Resource pressure prevents creating new regions.
    ResourcePressure {
        /// The priority requested for the new region.
        requested_priority: RegionPriority,
        /// The reason for rejection due to resource pressure.
        reason: String,
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
            Self::ResourcePressure {
                requested_priority,
                reason,
            } => write!(
                f,
                "resource pressure prevents region creation: priority={:?} reason={}",
                requested_priority, reason
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
    #[inline]
    pub fn new() -> Self {
        Self {
            regions: Arena::new(),
        }
    }

    // =========================================================================
    // Low-level arena access
    // =========================================================================

    /// Returns a shared reference to a region record by arena index.
    #[inline]
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&RegionRecord> {
        self.regions.get(index)
    }

    /// Returns a mutable reference to a region record by arena index.
    #[inline]
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut RegionRecord> {
        self.regions.get_mut(index)
    }

    /// Inserts a new region record into the arena.
    #[inline]
    pub fn insert(&mut self, mut record: RegionRecord) -> ArenaIndex {
        self.regions.insert_with(|idx| {
            record.id = RegionId::from_arena(idx);
            record
        })
    }

    /// Inserts a new region record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    #[inline]
    pub fn insert_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> RegionRecord,
    {
        self.regions.insert_with(|idx| {
            let mut record = f(idx);
            record.id = RegionId::from_arena(idx);
            record
        })
    }

    /// Removes a region record from the arena.
    #[inline]
    pub fn remove(&mut self, index: ArenaIndex) -> Option<RegionRecord> {
        self.regions.remove(index)
    }

    /// Returns an iterator over all region records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &RegionRecord)> {
        self.regions.iter()
    }

    /// Returns the number of region records in the table.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` if the region table is empty.
    #[inline]
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
    #[inline]
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
    #[inline]
    pub fn set_limits(&self, region: RegionId, limits: RegionLimits) -> bool {
        let Some(record) = self.regions.get(region.arena_index()) else {
            return false;
        };
        record.set_limits(limits);
        true
    }

    /// Returns the current admission limits for a region.
    #[inline]
    #[must_use]
    pub fn limits(&self, region: RegionId) -> Option<RegionLimits> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::limits)
    }

    /// Returns the current state of a region.
    #[inline]
    #[must_use]
    pub fn state(&self, region: RegionId) -> Option<crate::record::region::RegionState> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::state)
    }

    /// Returns the parent of a region.
    #[inline]
    #[must_use]
    pub fn parent(&self, region: RegionId) -> Option<Option<RegionId>> {
        self.regions.get(region.arena_index()).map(|r| r.parent)
    }

    /// Returns the budget of a region.
    #[inline]
    #[must_use]
    pub fn budget(&self, region: RegionId) -> Option<Budget> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::budget)
    }

    /// Returns child IDs of a region.
    #[inline]
    #[must_use]
    pub fn child_ids(&self, region: RegionId) -> Option<Vec<RegionId>> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::child_ids)
    }

    /// Returns task IDs of a region.
    #[inline]
    #[must_use]
    pub fn task_ids(&self, region: RegionId) -> Option<Vec<crate::types::TaskId>> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::task_ids)
    }

    /// Returns the number of pending obligations for a region.
    #[inline]
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
    use crate::types::{CancelReason, TaskId};

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
        let child = table
            .create_child(parent, child_budget, Time::ZERO)
            .unwrap();

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
    fn close_requires_quiescence_for_all_live_work() {
        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(root, Budget::default(), Time::ZERO)
            .unwrap();
        let root_record = table.get(root.arena_index()).unwrap();
        let task = TaskId::from_arena(ArenaIndex::new(7, 0));

        assert!(root_record.add_task(task).is_ok());
        assert!(root_record.begin_close(None));
        assert!(root_record.begin_finalize());
        assert_eq!(table.state(root), Some(RegionState::Finalizing));
        assert!(!root_record.complete_close());

        root_record.remove_task(task);
        assert!(!root_record.complete_close());

        root_record.remove_child(child);
        assert!(root_record.complete_close());
        assert_eq!(table.state(root), Some(RegionState::Closed));
    }

    #[test]
    fn close_outcome_is_invariant_to_live_work_removal_order() {
        let mut remove_task_then_child = RegionTable::new();
        let root_a = remove_task_then_child.create_root(Budget::default(), Time::ZERO);
        let child_a = remove_task_then_child
            .create_child(root_a, Budget::default(), Time::ZERO)
            .unwrap();
        let root_a_record = remove_task_then_child.get(root_a.arena_index()).unwrap();
        let task_a = TaskId::from_arena(ArenaIndex::new(11, 0));
        assert!(root_a_record.add_task(task_a).is_ok());
        assert!(root_a_record.begin_close(None));
        assert!(root_a_record.begin_finalize());
        root_a_record.remove_task(task_a);
        assert!(!root_a_record.complete_close());
        root_a_record.remove_child(child_a);
        assert!(root_a_record.complete_close());

        let mut remove_child_then_task = RegionTable::new();
        let root_b = remove_child_then_task.create_root(Budget::default(), Time::ZERO);
        let child_b = remove_child_then_task
            .create_child(root_b, Budget::default(), Time::ZERO)
            .unwrap();
        let root_b_record = remove_child_then_task.get(root_b.arena_index()).unwrap();
        let task_b = TaskId::from_arena(ArenaIndex::new(12, 0));
        assert!(root_b_record.add_task(task_b).is_ok());
        assert!(root_b_record.begin_close(None));
        assert!(root_b_record.begin_finalize());
        root_b_record.remove_child(child_b);
        assert!(!root_b_record.complete_close());
        root_b_record.remove_task(task_b);
        assert!(root_b_record.complete_close());

        assert_eq!(
            remove_task_then_child.state(root_a),
            Some(RegionState::Closed)
        );
        assert_eq!(
            remove_child_then_task.state(root_b),
            Some(RegionState::Closed)
        );
    }

    #[test]
    fn repeated_child_creation_attempts_after_close_stay_rejected() {
        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let root_record = table.get(root.arena_index()).unwrap();

        assert!(root_record.begin_close(None));
        assert!(root_record.begin_finalize());
        assert!(root_record.complete_close());
        assert_eq!(table.state(root), Some(RegionState::Closed));

        for attempt in 0..3 {
            let result = table.create_child(
                root,
                Budget::default(),
                Time::from_nanos((attempt + 1) as u64),
            );
            assert!(matches!(result, Err(RegionCreateError::ParentClosed(id)) if id == root));
            assert_eq!(table.len(), 1);
            assert!(table.child_ids(root).unwrap().is_empty());
        }
    }

    #[test]
    fn close_completion_tracks_zero_live_work_across_child_task_obligation_combinations() {
        for mask in 0_u8..8 {
            let has_child = mask & 0b001 != 0;
            let has_task = mask & 0b010 != 0;
            let has_obligation = mask & 0b100 != 0;

            let mut table = RegionTable::new();
            let root = table.create_root(Budget::default(), Time::ZERO);
            let child = if has_child {
                Some(
                    table
                        .create_child(root, Budget::default(), Time::ZERO)
                        .unwrap(),
                )
            } else {
                None
            };
            let root_record = table.get(root.arena_index()).unwrap();
            let task = if has_task {
                Some(TaskId::from_arena(ArenaIndex::new(
                    100 + u32::from(mask),
                    0,
                )))
            } else {
                None
            };

            if let Some(task) = task {
                assert!(root_record.add_task(task).is_ok());
            }
            if has_obligation {
                assert!(root_record.try_reserve_obligation().is_ok());
                assert_eq!(table.pending_obligations(root), Some(1));
            }

            assert!(root_record.begin_close(None));
            assert!(root_record.begin_finalize());

            let should_close_immediately = !(has_child || has_task || has_obligation);
            assert_eq!(
                root_record.complete_close(),
                should_close_immediately,
                "close outcome should depend only on whether live work remains: mask={mask:03b}",
            );

            if let Some(task) = task {
                root_record.remove_task(task);
            }
            if let Some(child) = child {
                root_record.remove_child(child);
            }
            if has_obligation {
                root_record.resolve_obligation();
            }

            if !should_close_immediately {
                assert!(root_record.complete_close());
            }

            assert_eq!(table.state(root), Some(RegionState::Closed));
            assert!(!root_record.has_live_work());
            assert_eq!(table.pending_obligations(root), Some(0));
        }
    }

    #[test]
    fn cancel_during_close_preserves_budget_and_completes_after_drain() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(64)
            .with_cost_quota(512)
            .with_priority(77);
        let mut table = RegionTable::new();
        let root = table.create_root(budget, Time::ZERO);
        let root_record = table.get(root.arena_index()).unwrap();
        let task = TaskId::from_arena(ArenaIndex::new(200, 0));
        let reason = CancelReason::timeout().with_message("close budget preserved");

        assert!(root_record.add_task(task).is_ok());
        assert!(root_record.try_reserve_obligation().is_ok());
        assert!(root_record.begin_close(Some(reason.clone())));
        assert_eq!(root_record.cancel_reason(), Some(reason));
        assert_eq!(root_record.budget(), budget);
        assert_eq!(table.budget(root), Some(budget));

        assert!(root_record.begin_finalize());
        assert!(!root_record.complete_close());

        root_record.remove_task(task);
        assert!(!root_record.complete_close());

        root_record.resolve_obligation();
        assert!(root_record.complete_close());
        assert_eq!(table.state(root), Some(RegionState::Closed));
        assert_eq!(root_record.budget(), budget);
        assert_eq!(table.budget(root), Some(budget));
        assert_eq!(table.pending_obligations(root), Some(0));
    }

    #[test]
    fn repeated_complete_close_after_closed_stays_idempotent() {
        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let root_record = table.get(root.arena_index()).unwrap();

        assert!(root_record.begin_close(None));
        assert!(root_record.begin_finalize());
        assert!(root_record.complete_close());
        assert_eq!(table.state(root), Some(RegionState::Closed));

        for _ in 0..3 {
            assert!(!root_record.complete_close());
            assert_eq!(table.state(root), Some(RegionState::Closed));
            assert_eq!(table.len(), 1);
            assert!(table.child_ids(root).unwrap().is_empty());
            assert!(table.task_ids(root).unwrap().is_empty());
            assert_eq!(table.pending_obligations(root), Some(0));
        }
    }

    // =========================================================================
    // Wave 43 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn region_create_error_debug_clone_eq_display() {
        let id = {
            let mut table = RegionTable::new();
            table.create_root(Budget::default(), Time::ZERO)
        };

        let e1 = RegionCreateError::ParentNotFound(id);
        let e2 = RegionCreateError::ParentClosed(id);
        let e3 = RegionCreateError::ParentAtCapacity {
            region: id,
            limit: 10,
            live: 10,
        };

        // Debug
        let d1 = format!("{e1:?}");
        assert!(d1.contains("ParentNotFound"), "{d1}");
        let d2 = format!("{e2:?}");
        assert!(d2.contains("ParentClosed"), "{d2}");
        let d3 = format!("{e3:?}");
        assert!(d3.contains("ParentAtCapacity"), "{d3}");

        // Display
        let s1 = format!("{e1}");
        assert!(s1.contains("parent region not found"), "{s1}");
        let s2 = format!("{e2}");
        assert!(s2.contains("parent region closed"), "{s2}");
        let s3 = format!("{e3}");
        assert!(s3.contains("admission limit reached"), "{s3}");

        // Clone + PartialEq + Eq
        assert_eq!(e1.clone(), e1);
        assert_eq!(e2.clone(), e2);
        assert_eq!(e3.clone(), e3);
        assert_ne!(e1, e2);

        // std::error::Error
        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn pending_obligations_initial_zero() {
        let mut table = RegionTable::new();
        let id = table.create_root(Budget::default(), Time::ZERO);
        assert_eq!(table.pending_obligations(id), Some(0));
    }
}
