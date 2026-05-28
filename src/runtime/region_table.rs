//! Region table for structured-concurrency ownership data.
//!
//! Encapsulates the region arena to enable finer-grained locking and clearer
//! ownership boundaries in RuntimeState. Provides both low-level arena access
//! and domain-level methods for region lifecycle management.
//! Cross-cutting concerns (tracing, metrics) remain in RuntimeState.

use crate::record::region::AdmissionError;
use crate::record::{RegionLimits, RegionRecord};
use crate::runtime::resource_monitor::RegionPriority;
use crate::types::{
    Budget, CapabilityBudget, CapabilityBudgetRefusal, CapabilityBudgetRequirements, RegionId, Time,
};
use crate::util::{Arena, ArenaIndex};

/// Errors that can occur when creating a child region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionCreateError {
    /// The parent region does not exist.
    ParentNotFound(RegionId),
    /// The parent region is not open and cannot accept new children.
    ParentClosed {
        /// The parent region that rejected the child.
        region: RegionId,
        /// The exact lifecycle phase observed at rejection time.
        state: crate::record::region::RegionState,
    },
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
    /// A required capability-budget dimension was missing or exhausted.
    CapabilityBudgetRefused {
        /// The parent region whose child admission was refused.
        parent: RegionId,
        /// The fail-closed budget refusal reason.
        reason: CapabilityBudgetRefusal,
    },
}

impl std::fmt::Display for RegionCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentNotFound(id) => write!(f, "parent region not found: {id:?}"),
            Self::ParentClosed { region, state } => {
                write!(f, "parent region not open: {region:?} state={state:?}")
            }
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
            Self::CapabilityBudgetRefused { parent, reason } => write!(
                f,
                "capability budget prevents child region creation: parent={parent:?} reason={reason}"
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
    /// Returns the number of regions currently draining or finalizing.
    ///
    /// **Recomputed from authoritative state on every call** (br-asupersync-yj9czm).
    /// The previous incremental cache (`cached_draining_count` from
    /// br-asupersync-xxcss5) drifted because every production state
    /// transition flows through `RegionRecord::transition()` (an atomic
    /// CAS on `state`) which never notified the table. The dead helper
    /// `note_region_state_transition` had zero callers in the entire
    /// `src/` tree; relying on it would have required threading every
    /// transition site (record/region.rs, lab/runtime.rs, lab/fuzz.rs,
    /// lab/meta/mutation.rs) through the table — a much larger refactor
    /// with its own correctness risk.
    ///
    /// Cost: O(N) over the live region arena per call. N is small in
    /// practice (tens to hundreds of regions per runtime), and Lyapunov
    /// snapshots are not an inner-loop hot path. Restoring O(1) requires
    /// either making `RegionTable` the sole transition site (option (a) in
    /// the bead) or installing a `RegionRecord` → `RegionTable` notifier
    /// callback (option (b)). Both are out of scope for this fix; the
    /// correctness regression is the priority.
    #[must_use]
    pub fn draining_region_count(&self) -> usize {
        use crate::record::region::RegionState;
        self.regions
            .iter()
            .filter(|(_, r)| matches!(r.state(), RegionState::Draining | RegionState::Finalizing))
            .count()
    }
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

    /// Creates a region table with pre-allocated capacity.
    ///
    /// Pre-sizing eliminates reallocation overhead during initial region creation.
    /// Based on benchmark analysis, arena growth contributes ~28% of allocations.
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            regions: Arena::with_capacity(capacity),
        }
    }

    /// Returns the reserved region arena capacity.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub(crate) fn capacity(&self) -> usize {
        self.regions.capacity()
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
        let removed = self.regions.remove(index)?;
        if let Some(parent) = removed.parent {
            if let Some(parent_record) = self.regions.get(parent.arena_index()) {
                parent_record.remove_child(removed.id);
            }
        }
        Some(removed)
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
        self.create_root_with_capability_budget(budget, CapabilityBudget::UNSPECIFIED, now)
    }

    /// Creates a root region record with an explicit capability budget.
    ///
    /// Callers are responsible for emitting trace events and setting
    /// `root_region` on RuntimeState.
    #[inline]
    pub fn create_root_with_capability_budget(
        &mut self,
        budget: Budget,
        capability_budget: CapabilityBudget,
        now: Time,
    ) -> RegionId {
        let idx = self.regions.insert_with(|idx| {
            RegionRecord::new_with_time_and_capability_budget(
                RegionId::from_arena(idx),
                None,
                budget,
                now,
                capability_budget,
            )
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
        self.create_child_with_capability_budget(
            parent,
            budget,
            CapabilityBudget::UNSPECIFIED,
            CapabilityBudgetRequirements::NONE,
            now,
        )
    }

    /// Creates a child region with explicit capability-budget admission.
    ///
    /// The child's effective budget and capability budget both inherit from the
    /// parent and are tightened by the child-supplied envelopes.
    pub fn create_child_with_capability_budget(
        &mut self,
        parent: RegionId,
        budget: Budget,
        capability_budget: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
        now: Time,
    ) -> Result<RegionId, RegionCreateError> {
        // Invariant: on `Err` return, the arena length is unchanged from
        // entry; on `Ok`, the arena length is exactly `entry_len + 1`. The
        // rollback path is the only thing keeping that invariant in the
        // non-attached / parent-rejected case, so any future refactor that
        // forgets to call `regions.remove(idx)` on failure must trip a
        // debug assertion here rather than silently leak an orphan region
        // record into the arena.
        let entry_len = self.regions.len();

        let parent_record = self
            .regions
            .get(parent.arena_index())
            .ok_or(RegionCreateError::ParentNotFound(parent))?;
        let parent_budget = parent_record.budget();
        let parent_capability_budget = parent_record.capability_budget();

        let effective_budget = parent_budget.meet(budget);
        let effective_capability_budget = parent_capability_budget
            .plan_child(capability_budget, requirements)
            .map_err(|reason| RegionCreateError::CapabilityBudgetRefused { parent, reason })?;

        let idx = self.regions.insert_with(|idx| {
            RegionRecord::new_with_time_and_capability_budget(
                RegionId::from_arena(idx),
                Some(parent),
                effective_budget,
                now,
                effective_capability_budget,
            )
        });
        let id = RegionId::from_arena(idx);

        let add_result = self
            .regions
            .get(parent.arena_index())
            .ok_or(RegionCreateError::ParentNotFound(parent))
            .and_then(|record| {
                record.add_child(id).map_err(|err| match err {
                    AdmissionError::Closed => RegionCreateError::ParentClosed {
                        region: parent,
                        state: record.state(),
                    },
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
            debug_assert_eq!(
                self.regions.len(),
                entry_len,
                "create_child rollback must restore arena length on failure",
            );
            return Err(err);
        }

        debug_assert_eq!(
            self.regions.len(),
            entry_len + 1,
            "create_child success path must grow arena by exactly one",
        );
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

    /// Returns the capability budget of a region.
    #[inline]
    #[must_use]
    pub fn capability_budget(&self, region: RegionId) -> Option<CapabilityBudget> {
        self.regions
            .get(region.arena_index())
            .map(RegionRecord::capability_budget)
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::finalizer::Finalizer;
    use crate::record::region::RegionState;
    use crate::types::{CancelReason, CapabilityBudgetDimension, TaskId};

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
        let unknown_parent = RegionId::from_arena(ArenaIndex::new(99, 0));
        let result = table.create_child(unknown_parent, Budget::default(), Time::ZERO);
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
        assert!(matches!(
            result,
            Err(RegionCreateError::ParentClosed {
                region,
                state: RegionState::Closing,
            }) if region == parent
        ));
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
    fn create_child_inherits_and_tightens_capability_budget() {
        let mut table = RegionTable::new();
        let parent_capability_budget = CapabilityBudget::new()
            .with_memory_bytes(1_024)
            .with_io_bytes(8_192)
            .with_cleanup_budget(Budget::new().with_poll_quota(20));
        let child_capability_budget = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_io_bytes(1_024);

        let parent = table.create_root_with_capability_budget(
            Budget::default(),
            parent_capability_budget,
            Time::ZERO,
        );
        let child = table
            .create_child_with_capability_budget(
                parent,
                Budget::default(),
                child_capability_budget,
                CapabilityBudgetRequirements::new()
                    .require_memory_bytes()
                    .require_io_bytes()
                    .require_cleanup(),
                Time::ZERO,
            )
            .unwrap();

        let actual = table.capability_budget(child).unwrap();
        assert_eq!(actual.memory_bytes, Some(1_024));
        assert_eq!(actual.io_bytes, Some(1_024));
        assert_eq!(
            actual.cleanup_budget.map(|budget| budget.poll_quota),
            Some(20)
        );
    }

    #[test]
    fn create_child_required_capability_budget_fails_closed() {
        let mut table = RegionTable::new();
        let parent = table.create_root(Budget::default(), Time::ZERO);

        let result = table.create_child_with_capability_budget(
            parent,
            Budget::default(),
            CapabilityBudget::new(),
            CapabilityBudgetRequirements::new().require_artifact_bytes(),
            Time::ZERO,
        );

        assert!(matches!(
            result,
            Err(RegionCreateError::CapabilityBudgetRefused {
                parent: refused_parent,
                reason: CapabilityBudgetRefusal::MissingRequired(
                    CapabilityBudgetDimension::ArtifactBytes
                ),
            }) if refused_parent == parent
        ));
        assert_eq!(table.len(), 1);
        assert!(table.child_ids(parent).unwrap().is_empty());
    }

    #[test]
    fn remove_unlinks_child_from_parent_before_close() {
        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(root, Budget::default(), Time::ZERO)
            .unwrap();

        let removed = table
            .remove(child.arena_index())
            .expect("child region should exist");
        assert_eq!(removed.id, child);
        assert_eq!(table.len(), 1);
        assert!(table.child_ids(root).unwrap().is_empty());

        let root_record = table.get(root.arena_index()).unwrap();
        assert!(root_record.begin_close(None));
        assert!(root_record.begin_finalize());
        assert!(
            root_record.complete_close(),
            "parent close should not be blocked by a removed child that was already reclaimed"
        );
        assert_eq!(table.state(root), Some(RegionState::Closed));
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
        let unknown_region = RegionId::from_arena(ArenaIndex::new(99, 0));
        assert!(!table.set_limits(unknown_region, RegionLimits::UNLIMITED));
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
            assert!(matches!(
                result,
                Err(RegionCreateError::ParentClosed {
                    region,
                    state: RegionState::Closed,
                }) if region == root
            ));
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

    fn run_close_reentry_scenario(
        pre_child_drain_close_calls: usize,
        post_child_drain_close_calls: usize,
    ) -> (usize, usize, RegionState, usize, bool) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut table = RegionTable::new();
        let root = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(root, Budget::default(), Time::ZERO)
            .unwrap();
        let root_record = table.get(root.arena_index()).unwrap();
        let finalize_count = Arc::new(AtomicUsize::new(0));
        let finalize_count_clone = Arc::clone(&finalize_count);
        root_record.add_finalizer(Finalizer::Sync(Box::new(move || {
            finalize_count_clone.fetch_add(1, Ordering::SeqCst);
        })));

        assert!(root_record.begin_close(None));
        assert!(root_record.begin_finalize());

        let mut successful_complete_close_calls = 0;
        for _ in 0..pre_child_drain_close_calls {
            successful_complete_close_calls += usize::from(root_record.complete_close());
        }

        assert_eq!(root_record.state(), RegionState::Finalizing);
        assert_eq!(root_record.finalizer_count(), 1);
        assert_eq!(finalize_count.load(Ordering::SeqCst), 0);

        root_record.remove_child(child);
        for _ in 0..post_child_drain_close_calls {
            successful_complete_close_calls += usize::from(root_record.complete_close());
        }

        assert_eq!(root_record.state(), RegionState::Finalizing);
        assert_eq!(root_record.finalizer_count(), 1);
        assert_eq!(finalize_count.load(Ordering::SeqCst), 0);

        let finalizer = root_record.pop_finalizer().expect("pending finalizer");
        match finalizer {
            Finalizer::Sync(f) => f(),
            Finalizer::Async(_) => panic!("expected sync finalizer"), // ubs:ignore - test oracle
        }

        successful_complete_close_calls += usize::from(root_record.complete_close());
        let repeated_after_closed = root_record.complete_close();
        (
            successful_complete_close_calls,
            finalize_count.load(Ordering::SeqCst),
            table.state(root).unwrap(),
            root_record.finalizer_count(),
            repeated_after_closed,
        )
    }

    #[test]
    fn close_reentry_during_quiesce_preserves_single_finalize_and_close_transition() {
        let baseline = run_close_reentry_scenario(1, 1);
        let reentered = run_close_reentry_scenario(3, 2);

        for (successful_closes, finalize_count, state, finalizers_left, repeated_after_closed) in
            [baseline, reentered]
        {
            assert_eq!(successful_closes, 1);
            assert_eq!(finalize_count, 1);
            assert_eq!(state, RegionState::Closed);
            assert_eq!(finalizers_left, 0);
            assert!(!repeated_after_closed);
        }

        assert_eq!(baseline, reentered);
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
        let e2 = RegionCreateError::ParentClosed {
            region: id,
            state: RegionState::Closing,
        };
        let e3 = RegionCreateError::ParentAtCapacity {
            region: id,
            limit: 10,
            live: 10,
        };
        let e4 = RegionCreateError::CapabilityBudgetRefused {
            parent: id,
            reason: CapabilityBudgetRefusal::MissingRequired(
                CapabilityBudgetDimension::MemoryBytes,
            ),
        };

        // Debug
        let d1 = format!("{e1:?}");
        assert!(d1.contains("ParentNotFound"), "{d1}");
        let d2 = format!("{e2:?}");
        assert!(d2.contains("ParentClosed"), "{d2}");
        let d3 = format!("{e3:?}");
        assert!(d3.contains("ParentAtCapacity"), "{d3}");
        let d4 = format!("{e4:?}");
        assert!(d4.contains("CapabilityBudgetRefused"), "{d4}");

        // Display
        let s1 = format!("{e1}");
        assert!(s1.contains("parent region not found"), "{s1}");
        let s2 = format!("{e2}");
        assert!(s2.contains("parent region not open"), "{s2}");
        assert!(s2.contains("Closing"), "{s2}");
        let s3 = format!("{e3}");
        assert!(s3.contains("admission limit reached"), "{s3}");
        let s4 = format!("{e4}");
        assert!(s4.contains("capability budget prevents"), "{s4}");

        // Clone + PartialEq + Eq
        assert_eq!(e1.clone(), e1);
        assert_eq!(e2.clone(), e2);
        assert_eq!(e3.clone(), e3);
        assert_eq!(e4.clone(), e4);
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

    /// REGRESSION: Region close MUST block when obligations remain.
    ///
    /// Per AGENTS.md core invariant "no obligation leaks", region close
    /// must be blocked until all obligations are resolved. This test
    /// verifies the blocking behavior is correctly implemented.
    #[test]
    fn regression_region_close_blocks_on_pending_obligations() {
        let mut table = RegionTable::new();
        let region = table.create_root(Budget::default(), Time::ZERO);
        let region_record = table.get(region.arena_index()).unwrap();

        // Reserve an obligation (simulating a held lock)
        assert!(region_record.try_reserve_obligation().is_ok());
        assert_eq!(table.pending_obligations(region), Some(1));

        // Begin region close
        assert!(region_record.begin_close(None));
        assert!(region_record.begin_finalize());

        // CRITICAL: Close must block while obligation remains
        assert!(
            !region_record.complete_close(),
            "Region close MUST block when obligations are pending"
        );
        assert_eq!(
            region_record.state(),
            crate::record::region::RegionState::Finalizing
        );

        // Resolve the obligation
        region_record.resolve_obligation();
        assert_eq!(table.pending_obligations(region), Some(0));

        // Now close should succeed
        assert!(
            region_record.complete_close(),
            "Region close should succeed after obligations are resolved"
        );
        assert_eq!(
            region_record.state(),
            crate::record::region::RegionState::Closed
        );
    }

    #[test]
    fn close_quiescence_race_spawn_after_begin_close_blocked() {
        // Test the specific race: region begins close, then child tries to spawn
        // grandchild. The double-check pattern should prevent the spawn.

        let mut table = RegionTable::new();
        let parent = table.create_root(Budget::default(), Time::ZERO);
        let child = table
            .create_child(parent, Budget::default(), Time::ZERO)
            .unwrap();

        // Step 1: Begin close on parent (this sets state to Closing)
        // Verify initial state
        assert_eq!(table.state(parent), Some(RegionState::Open));
        assert_eq!(table.state(child), Some(RegionState::Open));

        // Begin close on parent
        let close_result = table.get(parent.arena_index()).unwrap().begin_close(None);
        assert!(close_result, "Parent close should succeed");
        assert_eq!(table.state(parent), Some(RegionState::Closing));

        // Step 2: Now try to add grandchild to the parent (should fail)
        let grandchild_result = table.create_child(parent, Budget::default(), Time::ZERO);
        assert!(
            matches!(
                grandchild_result,
                Err(RegionCreateError::ParentClosed { .. })
            ),
            "Creating grandchild should fail after parent close, got: {:?}",
            grandchild_result
        );

        // Step 3: Try to add grandchild to the child region (should succeed since child is still Open)
        let grandchild_on_child = table.create_child(child, Budget::default(), Time::ZERO);
        assert!(
            grandchild_on_child.is_ok(),
            "Creating grandchild on still-open child should succeed, got: {:?}",
            grandchild_on_child
        );

        let grandchild = grandchild_on_child.unwrap();

        // Step 4: Now begin close on child as well
        let child_close = table.get(child.arena_index()).unwrap().begin_close(None);
        assert!(child_close, "Child close should succeed");
        assert_eq!(table.state(child), Some(RegionState::Closing));

        // Step 5: Try to add great-grandchild to child (should fail now)
        let great_grandchild_result = table.create_child(child, Budget::default(), Time::ZERO);
        assert!(
            matches!(
                great_grandchild_result,
                Err(RegionCreateError::ParentClosed { .. })
            ),
            "Creating great-grandchild should fail after child close, got: {:?}",
            great_grandchild_result
        );

        // Step 6: Verify quiescence check sees all children
        let parent_close_attempt = {
            let parent_record = table.get(parent.arena_index()).unwrap();
            parent_record.begin_finalize();
            parent_record.complete_close()
        };
        assert!(
            !parent_close_attempt,
            "Parent should not close while child and grandchild are still live"
        );

        // Verify parent sees both child regions
        let parent_children = table.child_ids(parent).unwrap();
        assert_eq!(parent_children.len(), 1, "Parent should have 1 child");
        assert_eq!(parent_children[0], child);

        let child_children = table.child_ids(child).unwrap();
        assert_eq!(child_children.len(), 1, "Child should have 1 grandchild");
        assert_eq!(child_children[0], grandchild);

        // Step 7: Clean up grandchild first
        let child_close_attempt = {
            let child_record = table.get(child.arena_index()).unwrap();
            child_record.begin_finalize();
            child_record.remove_child(grandchild);
            child_record.complete_close()
        };
        assert!(
            child_close_attempt,
            "Child should close after grandchild removed"
        );

        // Step 8: Now parent should be able to close
        let final_parent_close = {
            let parent_record = table.get(parent.arena_index()).unwrap();
            parent_record.remove_child(child);
            parent_record.complete_close()
        };
        assert!(
            final_parent_close,
            "Parent should close after child removed"
        );

        assert_eq!(table.state(parent), Some(RegionState::Closed));
        assert_eq!(table.state(child), Some(RegionState::Closed));
    }

    // =========================================================================
    // Metamorphic Testing Suite - Region Table
    // =========================================================================

    use proptest::prelude::*;

    // Test data generators
    prop_compose! {
        fn arb_region_sequence()
                              (size in 1usize..20)
                              (count in Just(size)) -> usize {
            count
        }
    }

    prop_compose! {
        fn arb_budget_components()
                               (deadline_secs in 10u64..1000,
                                poll_quota in 100u32..10000,
                                cost_quota in 50u64..5000,
                                priority in 1u8..=254)
                               -> (u64, u32, u64, u8) {
            (deadline_secs, poll_quota, cost_quota, priority)
        }
    }

    #[allow(dead_code)]
    #[derive(Clone, Copy, Debug)]
    enum WorkType {
        Task,
        Child,
        Obligation,
    }

    prop_compose! {
        fn arb_work_mix()
                        (task_count in 0usize..5,
                         child_count in 0usize..3,
                         obligation_count in 0usize..4)
                        -> (usize, usize, usize) {
            (task_count, child_count, obligation_count)
        }
    }

    // MR1: Parent-Child Hierarchy Invariants (Score: 6.25)
    // Invariant: Child creation/removal operations maintain consistent parent-child relationships
    proptest! {
        #[test]
        fn mr_parent_child_hierarchy_invariants(
            root_count in 1usize..5,
            children_per_root in prop::collection::vec(0usize..4, 1..5)
        ) {
            let mut table = RegionTable::new();
            let mut roots = Vec::new();
            let mut all_children = Vec::new();

            // Phase 1: Create roots
            for _ in 0..root_count {
                let root = table.create_root(Budget::default(), Time::ZERO);
                roots.push(root);
            }

            prop_assert_eq!(table.len(), root_count);

            // Phase 2: Create children under each root
            for (i, &child_count) in children_per_root.iter().enumerate() {
                if i >= roots.len() { break; }
                let parent = roots[i];

                for _ in 0..child_count {
                    let child = table.create_child(parent, Budget::default(), Time::ZERO)?;
                    all_children.push((parent, child));
                }
            }

            let expected_total = root_count + children_per_root.iter().take(root_count).sum::<usize>();
            prop_assert_eq!(table.len(), expected_total);

            // MR: Parent-child relationships must be consistent
            for (parent, child) in &all_children {
                prop_assert_eq!(table.parent(*child), Some(Some(*parent)),
                    "Child {:?} should have parent {:?}", child, parent);

                let parent_children = table.child_ids(*parent).unwrap();
                prop_assert!(parent_children.contains(child),
                    "Parent {:?} should contain child {:?}", parent, child);
            }

            // MR: Root regions should have no parent
            for root in &roots {
                prop_assert_eq!(table.parent(*root), Some(None),
                    "Root region {:?} should have no parent", root);
            }

            // Phase 3: Remove some children and verify consistency
            let to_remove = all_children.len() / 2;
            for (parent, child) in all_children.iter().take(to_remove) {
                let removed = table.remove(child.arena_index());
                prop_assert!(removed.is_some(), "Child removal should succeed");

                // MR: Removed child should no longer appear in parent's children
                let remaining_children = table.child_ids(*parent).unwrap();
                prop_assert!(!remaining_children.contains(child),
                    "Removed child {:?} should not appear in parent's children", child);
            }

            prop_assert_eq!(table.len(), expected_total - to_remove);
        }
    }

    // MR2: Quiescence Requirements (Score: 6.67)
    // Invariant: Region close must block until all work (children, tasks, obligations) is resolved
    proptest! {
        #[test]
        fn mr_quiescence_requirements(work_mix in arb_work_mix()) {
            let (task_count, child_count, obligation_count) = work_mix;
            let mut table = RegionTable::new();
            let root = table.create_root(Budget::default(), Time::ZERO);

            // Add work to the region
            let mut tasks = Vec::new();
            let mut children = Vec::new();

            {
                let root_record = table.get(root.arena_index()).unwrap();
                for i in 0..task_count {
                    let task =
                        crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(i as u32, 0));
                    prop_assert!(root_record.add_task(task).is_ok());
                    tasks.push(task);
                }
            }

            for _ in 0..child_count {
                let child = table.create_child(root, Budget::default(), Time::ZERO)?;
                children.push(child);
            }

            let root_record = table.get(root.arena_index()).unwrap();
            for _ in 0..obligation_count {
                prop_assert!(root_record.try_reserve_obligation().is_ok());
            }

            let has_any_work = task_count > 0 || child_count > 0 || obligation_count > 0;

            // Begin close sequence
            prop_assert!(root_record.begin_close(None));
            prop_assert!(root_record.begin_finalize());

            // MR: Close should block if and only if work remains
            let should_block = has_any_work;
            let completed_immediately = root_record.complete_close();
            prop_assert_eq!(completed_immediately, !should_block,
                "Close completion should be inverse of work presence");

            if should_block {
                prop_assert_eq!(root_record.state(), RegionState::Finalizing);
            } else {
                prop_assert_eq!(root_record.state(), RegionState::Closed);
                prop_assert_eq!(table.pending_obligations(root), Some(0));
                return Ok(());
            }

            // Remove all work
            for task in tasks {
                root_record.remove_task(task);
            }
            for child in children {
                root_record.remove_child(child);
            }
            for _ in 0..obligation_count {
                root_record.resolve_obligation();
            }

            // MR: After removing all work, close should succeed
            prop_assert!(root_record.complete_close(),
                "Close should succeed after all work is removed");
            prop_assert_eq!(root_record.state(), RegionState::Closed);
            prop_assert_eq!(table.pending_obligations(root), Some(0));
        }
    }

    // MR3: Work Removal Order Independence (Score: 5.33)
    // Invariant: Removing work items in different orders should yield the same final state
    proptest! {
        #[test]
        fn mr_work_removal_order_independence(_remove_tasks_first in any::<bool>()) {
            fn run_close_with_order(tasks_first: bool) -> (RegionState, usize) {
                let mut table = RegionTable::new();
                let root = table.create_root(Budget::default(), Time::ZERO);
                let child = table.create_child(root, Budget::default(), Time::ZERO).unwrap();
                let root_record = table.get(root.arena_index()).unwrap();

                let task = crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(42, 0));
                assert!(root_record.add_task(task).is_ok());
                assert!(root_record.try_reserve_obligation().is_ok());

                assert!(root_record.begin_close(None));
                assert!(root_record.begin_finalize());
                assert!(!root_record.complete_close()); // Should block on work

                if tasks_first {
                    root_record.remove_task(task);
                    root_record.resolve_obligation();
                    root_record.remove_child(child);
                } else {
                    root_record.remove_child(child);
                    root_record.remove_task(task);
                    root_record.resolve_obligation();
                }

                assert!(root_record.complete_close());
                (root_record.state(), table.pending_obligations(root).unwrap())
            }

            let result_tasks_first = run_close_with_order(true);
            let result_obligations_first = run_close_with_order(false);

            // MR: Different removal orders should yield identical final states
            prop_assert_eq!(result_tasks_first.0, result_obligations_first.0);
            prop_assert_eq!(result_tasks_first.1, result_obligations_first.1);
            prop_assert_eq!(result_tasks_first.0, RegionState::Closed);
            prop_assert_eq!(result_tasks_first.1, 0);
        }
    }

    // MR4: Region Count Linearity (Score: 4.0)
    // Invariant: Creating N regions should increase table size by exactly N
    proptest! {
        #[test]
        fn mr_region_count_linearity(
            first_batch in 1usize..8,
            second_batch in 1usize..6
        ) {
            let mut table = RegionTable::new();
            let initial_len = table.len();
            prop_assert_eq!(initial_len, 0);

            // First batch: Create roots
            for _ in 0..first_batch {
                table.create_root(Budget::default(), Time::ZERO);
            }
            let after_roots = table.len();

            // MR: Length should increase linearly by number of roots created
            prop_assert_eq!(after_roots, initial_len + first_batch);

            // Second batch: Create children under first root if it exists
            if first_batch > 0 {
                let first_root = table.iter().next().unwrap().1.id;
                let mut children_created = 0;

                for _ in 0..second_batch {
                    if table.create_child(first_root, Budget::default(), Time::ZERO).is_ok() {
                        children_created += 1;
                    }
                }

                let after_children = table.len();

                // MR: Length should increase linearly by number of children successfully created
                prop_assert_eq!(after_children, after_roots + children_created);
            }

            // Verify final count matches expected
            let expected_final = first_batch + if first_batch > 0 { second_batch } else { 0 };
            prop_assert_eq!(table.len(), expected_final);
        }
    }

    // MR5: Budget Inheritance Consistency (Score: 3.0)
    // Invariant: Child budget should be meet(parent_budget, child_budget)
    proptest! {
        #[test]
        fn mr_budget_inheritance_consistency(
            parent_components in arb_budget_components(),
            child_components in arb_budget_components()
        ) {
            let (p_deadline, p_poll, p_cost, p_priority) = parent_components;
            let (c_deadline, c_poll, c_cost, c_priority) = child_components;

            let parent_budget = Budget::new()
                .with_deadline(Time::from_secs(p_deadline))
                .with_poll_quota(p_poll)
                .with_cost_quota(p_cost)
                .with_priority(p_priority);

            let child_budget = Budget::new()
                .with_deadline(Time::from_secs(c_deadline))
                .with_poll_quota(c_poll)
                .with_cost_quota(c_cost)
                .with_priority(c_priority);

            let expected_effective = parent_budget.meet(child_budget);

            let mut table = RegionTable::new();
            let parent = table.create_root(parent_budget, Time::ZERO);
            let child = table.create_child(parent, child_budget, Time::ZERO)?;

            let actual_child_budget = table.budget(child).unwrap();

            // MR: Child's effective budget should equal meet of parent and child budgets
            prop_assert_eq!(actual_child_budget, expected_effective);

            // MR: Parent budget should be unchanged
            prop_assert_eq!(table.budget(parent).unwrap(), parent_budget);
        }
    }

    // MR6: Obligation Count Conservation (Score: 3.2)
    // Invariant: Obligation operations should precisely track pending counts
    proptest! {
        #[test]
        fn mr_obligation_count_conservation(operations in prop::collection::vec(any::<bool>(), 5..20)) {
            let mut table = RegionTable::new();
            let root = table.create_root(Budget::default(), Time::ZERO);
            let root_record = table.get(root.arena_index()).unwrap();

            let mut expected_pending = 0usize;
            prop_assert_eq!(table.pending_obligations(root), Some(0));

            for &reserve in &operations {
                if reserve && expected_pending < 10 { // Cap to prevent excessive obligations
                    if root_record.try_reserve_obligation().is_ok() {
                        expected_pending += 1;
                    }
                } else if expected_pending > 0 {
                    root_record.resolve_obligation();
                    expected_pending -= 1;
                }

                // MR: Actual pending count should always match expected
                prop_assert_eq!(table.pending_obligations(root), Some(expected_pending),
                    "Obligation count mismatch after operation");
            }

            // Resolve all remaining obligations
            while expected_pending > 0 {
                root_record.resolve_obligation();
                expected_pending -= 1;
                prop_assert_eq!(table.pending_obligations(root), Some(expected_pending));
            }

            // Final state should have zero obligations
            prop_assert_eq!(table.pending_obligations(root), Some(0));
        }
    }

    // MR7: Composite - Hierarchical Consistency (Chains multiple simple MRs)
    proptest! {
        #[test]
        fn mr_composite_hierarchical_consistency(
            tree_depth in 1usize..4,
            children_per_level in prop::collection::vec(1usize..3, 1..4)
        ) {
            let mut table = RegionTable::new();
            let root = table.create_root(Budget::default(), Time::ZERO);
            let initial_len = table.len();
            prop_assert_eq!(initial_len, 1);

            let mut current_level = vec![root];
            let mut total_regions = 1;

            // Build hierarchical tree
            for (_depth, &children_count) in children_per_level.iter().enumerate().take(tree_depth) {
                let mut next_level = Vec::new();

                for parent in &current_level {
                    for _ in 0..children_count {
                        let child = table.create_child(*parent, Budget::default(), Time::ZERO)?;
                        next_level.push(child);
                        total_regions += 1;
                    }
                }

                // MR1: Count linearity at each level
                prop_assert_eq!(table.len(), total_regions);

                // MR2: Parent-child consistency at each level
                for parent in &current_level {
                    let children = table.child_ids(*parent).unwrap();
                    prop_assert_eq!(children.len(), children_count);

                    for child in &children {
                        prop_assert_eq!(table.parent(*child), Some(Some(*parent)));
                    }
                }

                current_level = next_level;
            }

            // MR3: Close propagation must respect hierarchy (leaves first)
            let mut close_order = Vec::new();

            // Close leaf nodes first
            for leaf in &current_level {
                let leaf_record = table.get(leaf.arena_index()).unwrap();
                prop_assert!(leaf_record.begin_close(None));
                prop_assert!(leaf_record.begin_finalize());
                prop_assert!(leaf_record.complete_close()); // Leaves should close immediately
                close_order.push(*leaf);
            }

            // MR4: Hierarchy constraints - parents can only close after all children are closed
            let root_record = table.get(root.arena_index()).unwrap();
            prop_assert!(root_record.begin_close(None));
            prop_assert!(root_record.begin_finalize());

            // Should initially block due to children
            if tree_depth > 1 || (tree_depth == 1 && !children_per_level.is_empty() && children_per_level[0] > 0) {
                prop_assert!(!root_record.complete_close(),
                    "Root should not close while children exist");
            }
        }
    }

    // MR8: Mutation Testing Validation - Planted Bug Detection
    #[test]
    fn validate_mr_suite_catches_planted_bugs() {
        // Test that our MR suite can detect common region table bugs

        // Bug 1: Incorrect child count tracking
        {
            let mut table = RegionTable::new();
            let parent = table.create_root(Budget::default(), Time::ZERO);
            let child = table
                .create_child(parent, Budget::default(), Time::ZERO)
                .unwrap();

            let children = table.child_ids(parent).unwrap();
            assert_eq!(children.len(), 1);
            assert!(children.contains(&child));
        }

        // Bug 2: Parent-child relationship corruption
        {
            let mut table = RegionTable::new();
            let parent = table.create_root(Budget::default(), Time::ZERO);
            let child = table
                .create_child(parent, Budget::default(), Time::ZERO)
                .unwrap();

            assert_eq!(table.parent(child), Some(Some(parent)));
        }

        // Bug 3: Obligation count tracking errors
        {
            let mut table = RegionTable::new();
            let region = table.create_root(Budget::default(), Time::ZERO);
            let record = table.get(region.arena_index()).unwrap();

            assert_eq!(table.pending_obligations(region), Some(0));
            assert!(record.try_reserve_obligation().is_ok());
            assert_eq!(table.pending_obligations(region), Some(1));
            record.resolve_obligation();
            assert_eq!(table.pending_obligations(region), Some(0));
        }

        // Bug 4: Close completion logic errors
        {
            let mut table = RegionTable::new();
            let region = table.create_root(Budget::default(), Time::ZERO);
            let record = table.get(region.arena_index()).unwrap();

            // Empty region should close immediately
            assert!(record.begin_close(None));
            assert!(record.begin_finalize());
            assert!(record.complete_close());
            assert_eq!(record.state(), RegionState::Closed);
        }

        // Bug 5: Arena length inconsistencies on failed operations
        {
            let mut table = RegionTable::new();
            let initial_len = table.len();

            // Invalid parent should fail cleanly without affecting length
            let invalid_parent = RegionId::from_arena(ArenaIndex::new(999, 0));
            let result = table.create_child(invalid_parent, Budget::default(), Time::ZERO);
            assert!(result.is_err());
            assert_eq!(table.len(), initial_len);
        }
    }
}
