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
        removed.revoke_obligation_handles();
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
#[path = "region_table_inline_tests.rs"]
mod tests;
