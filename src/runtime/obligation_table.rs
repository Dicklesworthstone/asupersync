//! Obligation table for tracked resource obligations.
//!
//! Encapsulates the obligation arena and provides domain-level operations for
//! obligation lifecycle management. This separation enables finer-grained locking
//! in the sharded runtime state (each table behind its own lock).

use crate::error::{Error, ErrorKind};
use crate::record::{ObligationAbortReason, ObligationKind, ObligationRecord, SourceLocation};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::{Arena, ArenaIndex};
use smallvec::SmallVec;
use std::backtrace::Backtrace;
use std::sync::Arc;

type HolderIds = SmallVec<[ObligationId; 4]>;
type HolderBucket = SmallVec<[(TaskId, HolderIds); 1]>;

/// Information returned when an obligation is committed.
#[derive(Debug, Clone)]
pub struct ObligationCommitInfo {
    /// The obligation ID.
    pub id: ObligationId,
    /// The task that held the obligation.
    pub holder: TaskId,
    /// The region the obligation belongs to.
    pub region: RegionId,
    /// The kind of obligation.
    pub kind: ObligationKind,
    /// Duration the obligation was held (nanoseconds).
    pub duration: u64,
}

/// Information returned when an obligation is aborted.
#[derive(Debug, Clone)]
pub struct ObligationAbortInfo {
    /// The obligation ID.
    pub id: ObligationId,
    /// The task that held the obligation.
    pub holder: TaskId,
    /// The region the obligation belongs to.
    pub region: RegionId,
    /// The kind of obligation.
    pub kind: ObligationKind,
    /// Duration the obligation was held (nanoseconds).
    pub duration: u64,
    /// The reason for the abort.
    pub reason: ObligationAbortReason,
}

/// Information returned when an obligation is marked as leaked.
#[derive(Debug, Clone)]
pub struct ObligationLeakInfo {
    /// The obligation ID.
    pub id: ObligationId,
    /// The task that held the obligation.
    pub holder: TaskId,
    /// The region the obligation belongs to.
    pub region: RegionId,
    /// The kind of obligation.
    pub kind: ObligationKind,
    /// Duration the obligation was held (nanoseconds).
    pub duration: u64,
    /// Source location where the obligation was acquired.
    pub acquired_at: SourceLocation,
    /// Optional backtrace from when the obligation was acquired.
    pub acquire_backtrace: Option<Arc<Backtrace>>,
    /// Optional description.
    pub description: Option<String>,
}

/// Arguments for creating an obligation record.
///
/// Kept as a struct (instead of many positional parameters) to make callsites
/// explicit and to keep clippy pedantic clean under `-D warnings`.
#[derive(Debug, Clone)]
pub struct ObligationCreateArgs {
    /// Obligation kind.
    pub kind: ObligationKind,
    /// Task that holds the obligation.
    pub holder: TaskId,
    /// Region that owns the obligation.
    pub region: RegionId,
    /// Current time at reservation.
    pub now: Time,
    /// Optional description for diagnostics.
    pub description: Option<String>,
    /// Source location where the obligation was acquired.
    pub acquired_at: SourceLocation,
    /// Optional backtrace captured at acquisition time.
    pub acquire_backtrace: Option<Arc<Backtrace>>,
}

/// Number of variants in [`ObligationKind`] — sized at compile time so we can
/// stash per-kind counters in a fixed array without boxing.
const OBLIGATION_KIND_COUNT: usize = 5;

/// Encapsulates the obligation arena for resource tracking operations.
///
/// Provides both low-level arena access and domain-level methods for
/// obligation lifecycle management (create, commit, abort, leak).
/// Cross-cutting concerns (tracing, metrics) remain in RuntimeState.
///
/// Maintains a secondary index (`by_holder`) mapping each `TaskId` to its
/// obligation IDs. This turns holder-based lookups (leak detection, orphan
/// abort) from O(arena_capacity) scans to O(obligations_per_task).
#[derive(Debug, Default)]
pub struct ObligationTable {
    obligations: Arena<ObligationRecord>,
    /// Secondary index: arena slot → per-generation task → obligation IDs.
    ///
    /// Task arena slots are generation-counted and can be reused. Keep each
    /// generation distinct so task-specific lookups remain correct across reuse.
    by_holder: Vec<HolderBucket>,
    /// Cached count of pending (Reserved) obligations.
    ///
    /// Maintained incrementally: +1 on create, -1 on commit/abort/leak.
    /// This turns `pending_count()` from an O(arena_capacity) scan to O(1).
    cached_pending: usize,
    /// Per-kind pending counts, indexed by [`kind_index`]. Supports O(1)
    /// Lyapunov snapshots (br-asupersync-xxcss5): the governor's per-kind
    /// obligation breakdown no longer iterates the arena each snapshot.
    pending_by_kind: [usize; OBLIGATION_KIND_COUNT],
    /// Running sum of `reserved_at.as_nanos()` over currently pending
    /// obligations. Combined with the virtual-time `now` at snapshot time,
    /// `obligation_age_sum_ns = now.as_nanos().saturating_mul(pending) -
    /// pending_reserved_at_sum_ns` yields the total age in nanoseconds without
    /// scanning the arena. `u128` is wide enough that a billion-obligation,
    /// century-long runtime still fits.
    pending_reserved_at_sum_ns: u128,
}

/// Stable index for `ObligationKind` in the per-kind counter array.
///
/// `SemaphorePermit` is bucketed with `Lease` in the governor snapshot to
/// match the existing `StateSnapshot::from_runtime_state` aggregation, so we
/// still give it a distinct counter slot here to keep the running sum
/// book-keeping simple.
#[inline]
#[must_use]
const fn kind_index(kind: ObligationKind) -> usize {
    match kind {
        ObligationKind::SendPermit => 0,
        ObligationKind::Ack => 1,
        ObligationKind::Lease => 2,
        ObligationKind::IoOp => 3,
        ObligationKind::SemaphorePermit => 4,
    }
}

impl ObligationTable {
    /// Creates an empty obligation table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: Arena::new(),
            by_holder: Vec::with_capacity(32),
            cached_pending: 0,
            pending_by_kind: [0; OBLIGATION_KIND_COUNT],
            pending_reserved_at_sum_ns: 0,
        }
    }

    /// Creates an obligation table with pre-allocated capacity.
    ///
    /// Pre-sizing eliminates reallocation overhead during initial obligation creation.
    /// Based on benchmark analysis, arena growth contributes ~28% of allocations.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            obligations: Arena::with_capacity(capacity),
            by_holder: Vec::with_capacity(capacity.max(32)),
            cached_pending: 0,
            pending_by_kind: [0; OBLIGATION_KIND_COUNT],
            pending_reserved_at_sum_ns: 0,
        }
    }

    /// Atomically bump the pending counters for a newly-created obligation.
    #[inline]
    fn note_pending_added(&mut self, kind: ObligationKind, reserved_at: Time) {
        self.cached_pending += 1;
        self.pending_by_kind[kind_index(kind)] += 1;
        self.pending_reserved_at_sum_ns = self
            .pending_reserved_at_sum_ns
            .saturating_add(u128::from(reserved_at.as_nanos()));
    }

    /// Atomically decrement the pending counters when an obligation leaves the
    /// `Reserved` state (commit / abort / leak / removal-while-pending).
    #[inline]
    fn note_pending_removed(&mut self, kind: ObligationKind, reserved_at: Time) {
        debug_assert!(
            self.cached_pending > 0,
            "pending counter underflow removing {kind:?} obligation reserved at {reserved_at:?}"
        );
        let kind_slot = kind_index(kind);
        debug_assert!(
            self.pending_by_kind[kind_slot] > 0,
            "per-kind pending counter underflow removing {kind:?} obligation reserved at {reserved_at:?}"
        );
        debug_assert!(
            self.pending_reserved_at_sum_ns >= u128::from(reserved_at.as_nanos()),
            "pending reserved-at sum underflow removing {kind:?} obligation reserved at {reserved_at:?}"
        );

        self.cached_pending = self.cached_pending.saturating_sub(1);
        let slot = &mut self.pending_by_kind[kind_slot];
        *slot = slot.saturating_sub(1);
        self.pending_reserved_at_sum_ns = self
            .pending_reserved_at_sum_ns
            .saturating_sub(u128::from(reserved_at.as_nanos()));
    }

    #[cfg(debug_assertions)]
    fn debug_assert_pending_counters_match(&self) {
        let mut pending = 0usize;
        let mut by_kind = [0usize; OBLIGATION_KIND_COUNT];
        let mut reserved_at_sum = 0u128;

        for (_, record) in self.obligations.iter() {
            if record.is_pending() {
                pending += 1;
                by_kind[kind_index(record.kind)] += 1;
                reserved_at_sum =
                    reserved_at_sum.saturating_add(u128::from(record.reserved_at.as_nanos()));
            }
        }

        debug_assert_eq!(
            self.cached_pending, pending,
            "pending counter drift: cached count no longer matches arena scan"
        );
        debug_assert_eq!(
            self.pending_by_kind, by_kind,
            "pending counter drift: per-kind cached counts no longer match arena scan"
        );
        debug_assert_eq!(
            self.pending_reserved_at_sum_ns, reserved_at_sum,
            "pending counter drift: cached reserved-at sum no longer matches arena scan"
        );
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    fn debug_assert_pending_counters_match(&self) {}

    // =========================================================================
    // Low-level arena access
    // =========================================================================

    /// Returns a shared reference to an obligation record by arena index.
    #[inline]
    #[must_use]
    pub fn get(&self, index: ArenaIndex) -> Option<&ObligationRecord> {
        self.obligations.get(index)
    }

    /// Returns a mutable reference to an obligation record by arena index.
    #[inline]
    pub fn get_mut(&mut self, index: ArenaIndex) -> Option<&mut ObligationRecord> {
        self.obligations.get_mut(index)
    }

    /// Inserts a new obligation record into the arena.
    pub fn insert(&mut self, mut record: ObligationRecord) -> ArenaIndex {
        let is_pending = record.is_pending();
        let holder = record.holder;
        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let idx = self.obligations.insert_with(|idx| {
            // The arena slot defines the canonical obligation ID. Normalize the
            // stored record so low-level callers cannot desynchronize `record.id`
            // from the holder index or later lifecycle operations.
            record.id = ObligationId::from_arena(idx);
            record
        });
        self.push_holder_id(holder, ObligationId::from_arena(idx));
        if is_pending {
            self.note_pending_added(kind, reserved_at);
        }
        self.debug_assert_pending_counters_match();
        idx
    }

    #[inline]
    fn push_holder_id(&mut self, holder: TaskId, ob_id: ObligationId) {
        let slot = holder.arena_index().index() as usize;
        if slot >= self.by_holder.len() {
            self.by_holder.resize_with(slot + 1, SmallVec::new);
        }
        let entries = &mut self.by_holder[slot];
        if let Some((_, ids)) = entries.iter_mut().find(|(task_id, _)| *task_id == holder) {
            ids.push(ob_id);
            return;
        }

        let mut ids = SmallVec::new();
        ids.push(ob_id);
        entries.push((holder, ids));
    }

    /// Inserts a new obligation record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    pub fn insert_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> ObligationRecord,
    {
        let idx = self.obligations.insert_with(|idx| {
            let mut record = f(idx);
            // Mirror `insert()`: the assigned arena slot is the only stable ID.
            record.id = ObligationId::from_arena(idx);
            record
        });
        let note = self.obligations.get(idx).map(|record| {
            (
                record.holder,
                record.kind,
                record.reserved_at,
                record.is_pending(),
            )
        });
        if let Some((holder, kind, reserved_at, is_pending)) = note {
            self.push_holder_id(holder, ObligationId::from_arena(idx));
            if is_pending {
                self.note_pending_added(kind, reserved_at);
            }
        }
        self.debug_assert_pending_counters_match();
        idx
    }

    /// Removes an obligation record from the arena.
    #[inline]
    pub fn remove(&mut self, index: ArenaIndex) -> Option<ObligationRecord> {
        let record = self.obligations.remove(index)?;
        if record.is_pending() {
            self.note_pending_removed(record.kind, record.reserved_at);
        }
        let ob_id = ObligationId::from_arena(index);
        let slot = record.holder.arena_index().index() as usize;
        if let Some(entries) = self.by_holder.get_mut(slot) {
            if let Some(entry_index) = entries
                .iter()
                .position(|(holder, _)| *holder == record.holder)
            {
                let (_, ids) = &mut entries[entry_index];
                if let Some(pos) = ids.iter().position(|id| *id == ob_id) {
                    ids.swap_remove(pos);
                }
                if ids.is_empty() {
                    entries.swap_remove(entry_index);
                }
            }
        }
        self.debug_assert_pending_counters_match();
        Some(record)
    }

    /// Returns an iterator over all obligation records.
    pub fn iter(&self) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations.iter()
    }

    /// Returns the number of obligation records in the table.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns `true` if the obligation table is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obligations.is_empty()
    }

    // =========================================================================
    // Domain-level obligation operations
    // =========================================================================

    /// Creates a new obligation and returns its ID.
    ///
    /// Callers are responsible for checking region admission limits
    /// (via `RegionTable::try_reserve_obligation`) before calling this.
    /// Callers are also responsible for emitting trace events.
    #[track_caller]
    pub fn create(&mut self, args: ObligationCreateArgs) -> ObligationId {
        let ObligationCreateArgs {
            kind,
            holder,
            region,
            now,
            description,
            acquired_at,
            acquire_backtrace,
        } = args;

        let idx = if let Some(desc) = description {
            self.obligations.insert_with(|idx| {
                ObligationRecord::with_description_and_context(
                    ObligationId::from_arena(idx),
                    kind,
                    holder,
                    region,
                    now,
                    desc,
                    acquired_at,
                    acquire_backtrace,
                )
            })
        } else {
            self.obligations.insert_with(|idx| {
                ObligationRecord::new_with_context(
                    ObligationId::from_arena(idx),
                    kind,
                    holder,
                    region,
                    now,
                    acquired_at,
                    acquire_backtrace,
                )
            })
        };
        let ob_id = ObligationId::from_arena(idx);
        self.push_holder_id(holder, ob_id);
        let reserved_at = self
            .obligations
            .get(idx)
            .map_or(now, |record| record.reserved_at);
        self.note_pending_added(kind, reserved_at);
        self.debug_assert_pending_counters_match();
        ob_id
    }

    /// Commits an obligation, transitioning it from Reserved to Committed.
    ///
    /// Returns commit info for the caller to emit trace events.
    /// Callers are responsible for calling `RegionTable::resolve_obligation`
    /// and `advance_region_state` after this.
    #[allow(clippy::result_large_err)]
    pub fn commit(
        &mut self,
        obligation: ObligationId,
        now: Time,
    ) -> Result<ObligationCommitInfo, Error> {
        let record = self
            .obligations
            .get_mut(obligation.arena_index())
            .ok_or_else(|| {
                Error::new(ErrorKind::ObligationAlreadyResolved)
                    .with_message("obligation not found")
            })?;

        if !record.is_pending() {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
        }

        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let duration = record.commit(now);
        let info = ObligationCommitInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind,
            duration,
        };
        self.note_pending_removed(kind, reserved_at);
        self.debug_assert_pending_counters_match();
        Ok(info)
    }

    /// Aborts an obligation, transitioning it from Reserved to Aborted.
    ///
    /// Returns abort info for the caller to emit trace events.
    /// Callers are responsible for calling `RegionTable::resolve_obligation`
    /// and `advance_region_state` after this.
    #[allow(clippy::result_large_err)]
    pub fn abort(
        &mut self,
        obligation: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> Result<ObligationAbortInfo, Error> {
        let record = self
            .obligations
            .get_mut(obligation.arena_index())
            .ok_or_else(|| {
                Error::new(ErrorKind::ObligationAlreadyResolved)
                    .with_message("obligation not found")
            })?;

        if !record.is_pending() {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
        }

        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let duration = record.abort(now, reason);
        let info = ObligationAbortInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind,
            duration,
            reason,
        };
        self.note_pending_removed(kind, reserved_at);
        self.debug_assert_pending_counters_match();
        Ok(info)
    }

    /// Marks an obligation as leaked, transitioning it from Reserved to Leaked.
    ///
    /// Returns leak info for the caller to emit trace/error events.
    #[allow(clippy::result_large_err)]
    pub fn mark_leaked(
        &mut self,
        obligation: ObligationId,
        now: Time,
    ) -> Result<ObligationLeakInfo, Error> {
        let record = self
            .obligations
            .get_mut(obligation.arena_index())
            .ok_or_else(|| {
                Error::new(ErrorKind::ObligationAlreadyResolved)
                    .with_message("obligation not found")
            })?;

        if !record.is_pending() {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
        }

        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let duration = record.mark_leaked(now);
        let info = ObligationLeakInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind,
            duration,
            acquired_at: record.acquired_at,
            acquire_backtrace: record.acquire_backtrace.clone(),
            description: record.description.clone(),
        };
        self.note_pending_removed(kind, reserved_at);
        self.debug_assert_pending_counters_match();
        Ok(info)
    }

    /// Returns obligation IDs held by a specific task (O(1) lookup via index).
    ///
    /// Returns all obligation IDs for the task, including resolved ones.
    /// Callers should filter by `is_pending()` if only active obligations are needed.
    #[must_use]
    pub fn ids_for_holder(&self, task_id: TaskId) -> &[ObligationId] {
        let slot = task_id.arena_index().index() as usize;
        if let Some(entries) = self.by_holder.get(slot) {
            if let Some((_, ids)) = entries.iter().find(|(holder, _)| *holder == task_id) {
                return ids.as_slice();
            }
        }
        &[]
    }

    /// Collects pending obligation IDs for a task using the holder index.
    ///
    /// Sorted by `ObligationId` for deterministic processing order.
    #[must_use]
    pub fn sorted_pending_ids_for_holder(&self, task_id: TaskId) -> SmallVec<[ObligationId; 4]> {
        let mut result: SmallVec<[ObligationId; 4]> = self
            .ids_for_holder(task_id)
            .iter()
            .copied()
            .filter(|id| {
                self.obligations
                    .get(id.arena_index())
                    .is_some_and(ObligationRecord::is_pending)
            })
            .collect();
        result.sort_unstable();
        result
    }

    /// Returns an iterator over obligations held by a specific task.
    pub fn for_task(
        &self,
        task_id: TaskId,
    ) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations
            .iter()
            .filter(move |(_, r)| r.holder == task_id)
    }

    /// Returns an iterator over obligations belonging to a specific region.
    pub fn for_region(
        &self,
        region: RegionId,
    ) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations
            .iter()
            .filter(move |(_, r)| r.region == region)
    }

    /// Returns an iterator over pending obligations held by a specific task.
    pub fn pending_for_task(
        &self,
        task_id: TaskId,
    ) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations
            .iter()
            .filter(move |(_, r)| r.holder == task_id && r.is_pending())
    }

    /// Returns an iterator over pending obligations in a specific region.
    pub fn pending_for_region(
        &self,
        region: RegionId,
    ) -> impl Iterator<Item = (ArenaIndex, &ObligationRecord)> {
        self.obligations
            .iter()
            .filter(move |(_, r)| r.region == region && r.is_pending())
    }

    /// Returns the count of pending obligations across all regions.
    ///
    /// O(1) — maintained incrementally via `cached_pending`.
    #[inline]
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.debug_assert_pending_counters_match();
        self.cached_pending
    }

    /// Returns the pending count for a specific [`ObligationKind`].
    ///
    /// O(1) — maintained incrementally alongside `cached_pending`
    /// (br-asupersync-xxcss5). The Lyapunov governor reads these counters
    /// instead of iterating the arena on every snapshot.
    #[inline]
    #[must_use]
    pub fn pending_count_for_kind(&self, kind: ObligationKind) -> usize {
        self.debug_assert_pending_counters_match();
        self.pending_by_kind[kind_index(kind)]
    }

    /// Returns the running sum of `reserved_at.as_nanos()` across all pending
    /// obligations. Combined with the current virtual time, yields the total
    /// obligation age in O(1) — see
    /// [`StateSnapshot::from_runtime_state`](crate::obligation::lyapunov::StateSnapshot::from_runtime_state).
    #[inline]
    #[must_use]
    pub fn pending_reserved_at_sum_ns(&self) -> u128 {
        self.debug_assert_pending_counters_match();
        self.pending_reserved_at_sum_ns
    }

    /// Collects IDs of pending obligations held by a specific task.
    #[must_use]
    pub fn pending_obligation_ids_for_task(&self, task_id: TaskId) -> Vec<ObligationId> {
        self.sorted_pending_ids_for_holder(task_id).into_vec()
    }

    /// Collects IDs of pending obligations in a specific region.
    #[must_use]
    pub fn pending_obligation_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {
        let mut ids: Vec<ObligationId> = self
            .obligations
            .iter()
            .filter(|(_, r)| r.region == region && r.is_pending())
            .map(|(idx, _)| ObligationId::from_arena(idx))
            .collect();
        ids.sort_unstable();
        ids
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
    use crate::record::ObligationState;

    fn make_obligation(
        table: &mut ObligationTable,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) -> ObligationId {
        table.create(ObligationCreateArgs {
            kind,
            holder,
            region,
            now: Time::ZERO,
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        })
    }

    fn test_task_id(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn test_task_id_with_generation(n: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, generation))
    }

    fn test_region_id(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    #[test]
    fn create_and_query_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        assert_eq!(table.len(), 1);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.kind, ObligationKind::SendPermit);
        assert_eq!(record.holder, task);
        assert_eq!(record.region, region);
        assert!(record.is_pending());
    }

    #[test]
    fn commit_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let info = table.commit(id, Time::from_nanos(1000)).unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.holder, task);
        assert_eq!(info.region, region);
        assert_eq!(info.kind, ObligationKind::Ack);
        assert_eq!(info.duration, 1000);

        let record = table.get(id.arena_index()).unwrap();
        assert!(!record.is_pending());
        assert_eq!(record.state, ObligationState::Committed);
    }

    #[test]
    fn abort_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(2);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::Lease, task, region);
        let info = table
            .abort(id, Time::from_nanos(500), ObligationAbortReason::Cancel)
            .unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.reason, ObligationAbortReason::Cancel);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.state, ObligationState::Aborted);
    }

    #[test]
    fn mark_leaked_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(3);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::IoOp, task, region);
        let info = table.mark_leaked(id, Time::from_nanos(2000)).unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.kind, ObligationKind::IoOp);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.state, ObligationState::Leaked);
    }

    #[test]
    fn double_commit_fails() {
        let mut table = ObligationTable::new();
        let id = make_obligation(
            &mut table,
            ObligationKind::SendPermit,
            test_task_id(1),
            test_region_id(1),
        );

        assert!(table.commit(id, Time::from_nanos(100)).is_ok());
        assert!(table.commit(id, Time::from_nanos(200)).is_err());
    }

    #[test]
    fn nonexistent_obligation_fails() {
        let mut table = ObligationTable::new();
        let fake = ObligationId::from_arena(ArenaIndex::new(99, 0));

        assert!(table.commit(fake, Time::from_nanos(100)).is_err());
        assert!(
            table
                .abort(fake, Time::from_nanos(100), ObligationAbortReason::Cancel)
                .is_err()
        );
        assert!(table.mark_leaked(fake, Time::from_nanos(100)).is_err());
    }

    #[test]
    fn query_by_task_and_region() {
        let mut table = ObligationTable::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let region1 = test_region_id(1);
        let region2 = test_region_id(2);

        make_obligation(&mut table, ObligationKind::SendPermit, task1, region1);
        make_obligation(&mut table, ObligationKind::Ack, task1, region2);
        make_obligation(&mut table, ObligationKind::Lease, task2, region1);

        assert_eq!(table.for_task(task1).count(), 2);
        assert_eq!(table.for_task(task2).count(), 1);
        assert_eq!(table.for_region(region1).count(), 2);
        assert_eq!(table.for_region(region2).count(), 1);
    }

    #[test]
    fn pending_count_decreases_on_resolve() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id1 = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        let id2 = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let _id3 = make_obligation(&mut table, ObligationKind::Lease, task, region);

        assert_eq!(table.pending_count(), 3);

        table.commit(id1, Time::from_nanos(100)).unwrap();
        assert_eq!(table.pending_count(), 2);

        table
            .abort(id2, Time::from_nanos(200), ObligationAbortReason::Cancel)
            .unwrap();
        assert_eq!(table.pending_count(), 1);
    }

    #[test]
    fn pending_obligation_ids_for_task() {
        let mut table = ObligationTable::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let region = test_region_id(1);

        let id1 = make_obligation(&mut table, ObligationKind::SendPermit, task1, region);
        let _id2 = make_obligation(&mut table, ObligationKind::Ack, task2, region);
        let id3 = make_obligation(&mut table, ObligationKind::Lease, task1, region);

        table.commit(id1, Time::from_nanos(100)).unwrap();

        let pending = table.pending_obligation_ids_for_task(task1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], id3);
    }

    #[test]
    fn holder_index_preserves_same_slot_task_generations() {
        let mut table = ObligationTable::new();
        let older = test_task_id_with_generation(9, 0);
        let newer = test_task_id_with_generation(9, 1);
        let region = test_region_id(1);

        let older_id = make_obligation(&mut table, ObligationKind::SendPermit, older, region);
        let newer_id = make_obligation(&mut table, ObligationKind::Ack, newer, region);

        assert_eq!(table.ids_for_holder(older), &[older_id]);
        assert_eq!(table.ids_for_holder(newer), &[newer_id]);
        assert_eq!(
            table.sorted_pending_ids_for_holder(older).as_slice(),
            &[older_id]
        );
        assert_eq!(table.pending_obligation_ids_for_task(newer), vec![newer_id]);
    }

    #[test]
    fn pending_obligation_ids_for_task_is_sorted_after_slot_reuse() {
        let mut table = ObligationTable::new();
        let task = test_task_id(7);
        let region = test_region_id(1);

        let id0 = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        let id1 = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let id2 = make_obligation(&mut table, ObligationKind::Lease, task, region);

        // Reuse a hole at id1's arena slot so insertion order diverges from ID order.
        let _removed = table.remove(id1.arena_index()).expect("obligation exists");
        let id1_reused = make_obligation(&mut table, ObligationKind::IoOp, task, region);

        let pending = table.pending_obligation_ids_for_task(task);
        assert_eq!(pending.len(), 3);

        let mut expected = vec![id0, id2, id1_reused];
        expected.sort_unstable();
        assert_eq!(pending, expected, "pending IDs should be canonicalized");
    }

    #[test]
    fn holder_index_100_obligations_10_tasks() {
        let mut table = ObligationTable::new();
        let region = test_region_id(1);
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        // Create 100 obligations across 10 tasks (10 per task)
        for task_n in 0..10 {
            let task = test_task_id(task_n);
            for i in 0..10 {
                let kind = kinds[(task_n as usize * 10 + i) % kinds.len()];
                let id = make_obligation(&mut table, kind, task, region);
                let _ = id;
            }
        }
        assert_eq!(table.len(), 100);

        // Verify index returns correct counts
        for task_n in 0..10 {
            let task = test_task_id(task_n);
            assert_eq!(table.ids_for_holder(task).len(), 10);
            assert_eq!(table.sorted_pending_ids_for_holder(task).len(), 10);
        }

        // Commit half the obligations for task 0
        let task0 = test_task_id(0);
        let task0_ids: Vec<_> = table.ids_for_holder(task0).to_vec();
        for id in &task0_ids[..5] {
            table.commit(*id, Time::from_nanos(100)).unwrap();
        }
        // Index still has all 10, but pending only 5
        assert_eq!(table.ids_for_holder(task0).len(), 10);
        assert_eq!(table.sorted_pending_ids_for_holder(task0).len(), 5);

        // Abort remaining for task 0
        for id in &task0_ids[5..] {
            table
                .abort(*id, Time::from_nanos(200), ObligationAbortReason::Cancel)
                .unwrap();
        }
        assert_eq!(table.sorted_pending_ids_for_holder(task0).len(), 0);

        // Other tasks unaffected
        for task_n in 1..10 {
            let task = test_task_id(task_n);
            assert_eq!(table.sorted_pending_ids_for_holder(task).len(), 10);
        }

        // Remove one obligation via arena remove
        let task5 = test_task_id(5);
        let task5_first_id = table.ids_for_holder(task5)[0];
        table.remove(task5_first_id.arena_index());
        assert_eq!(table.ids_for_holder(task5).len(), 9);

        // sorted_pending_ids_for_holder is sorted by ObligationId
        let task3 = test_task_id(3);
        let sorted = table.sorted_pending_ids_for_holder(task3);
        for window in sorted.windows(2) {
            assert!(window[0] < window[1], "should be sorted");
        }
    }

    #[test]
    fn insert_normalizes_record_id_to_assigned_slot() {
        let mut table = ObligationTable::new();
        let task = test_task_id(11);
        let region = test_region_id(4);
        let stale_id = ObligationId::from_arena(ArenaIndex::new(99, 0));

        let idx = table.insert(ObligationRecord::new(
            stale_id,
            ObligationKind::SendPermit,
            task,
            region,
            Time::ZERO,
        ));
        let canonical = ObligationId::from_arena(idx);
        let record = table.get(idx).expect("obligation exists");

        assert_eq!(record.id, canonical);
        assert_ne!(record.id, stale_id);
        assert_eq!(table.ids_for_holder(task), &[canonical]);
    }

    #[test]
    fn insert_with_normalizes_record_id_to_assigned_slot() {
        let mut table = ObligationTable::new();
        let task = test_task_id(12);
        let region = test_region_id(5);
        let stale_id = ObligationId::from_arena(ArenaIndex::new(77, 1));

        let idx = table.insert_with(|_| {
            ObligationRecord::new(stale_id, ObligationKind::Ack, task, region, Time::ZERO)
        });
        let canonical = ObligationId::from_arena(idx);
        let record = table.get(idx).expect("obligation exists");

        assert_eq!(record.id, canonical);
        assert_ne!(record.id, stale_id);
        assert_eq!(table.pending_obligation_ids_for_task(task), vec![canonical]);
    }

    #[test]
    fn metamorphic_resolution_reordering_preserves_table_invariants() {
        #[derive(Clone, Copy)]
        enum Resolution {
            Commit(ObligationId, Time),
            Abort(ObligationId, Time, ObligationAbortReason),
            Leak(ObligationId, Time),
        }

        fn apply_resolutions(table: &mut ObligationTable, resolutions: &[Resolution]) {
            for resolution in resolutions {
                match *resolution {
                    Resolution::Commit(id, now) => {
                        table.commit(id, now).expect("commit should succeed");
                    }
                    Resolution::Abort(id, now, reason) => {
                        table.abort(id, now, reason).expect("abort should succeed");
                    }
                    Resolution::Leak(id, now) => {
                        table.mark_leaked(id, now).expect("leak should succeed");
                    }
                }
            }
        }

        fn build_table() -> (
            ObligationTable,
            [ObligationId; 5],
            TaskId,
            TaskId,
            RegionId,
            RegionId,
        ) {
            let mut table = ObligationTable::new();
            let task_a = test_task_id(21);
            let task_b = test_task_id(22);
            let region_x = test_region_id(7);
            let region_y = test_region_id(8);

            let ids = [
                make_obligation(&mut table, ObligationKind::SendPermit, task_a, region_x),
                make_obligation(&mut table, ObligationKind::Ack, task_a, region_y),
                make_obligation(&mut table, ObligationKind::Lease, task_b, region_x),
                make_obligation(&mut table, ObligationKind::IoOp, task_b, region_y),
                make_obligation(&mut table, ObligationKind::SendPermit, task_b, region_y),
            ];

            (table, ids, task_a, task_b, region_x, region_y)
        }

        let (mut baseline, ids, task_a, task_b, region_x, region_y) = build_table();
        let resolutions = [
            Resolution::Commit(ids[0], Time::from_nanos(100)),
            Resolution::Abort(ids[2], Time::from_nanos(200), ObligationAbortReason::Cancel),
            Resolution::Leak(ids[4], Time::from_nanos(300)),
        ];
        apply_resolutions(&mut baseline, &resolutions);

        let (mut reordered, reordered_ids, _, _, _, _) = build_table();
        let reversed = [
            Resolution::Leak(reordered_ids[4], Time::from_nanos(300)),
            Resolution::Abort(
                reordered_ids[2],
                Time::from_nanos(200),
                ObligationAbortReason::Cancel,
            ),
            Resolution::Commit(reordered_ids[0], Time::from_nanos(100)),
        ];
        apply_resolutions(&mut reordered, &reversed);

        assert_eq!(baseline.pending_count(), reordered.pending_count());
        assert_eq!(
            baseline.pending_obligation_ids_for_task(task_a),
            reordered.pending_obligation_ids_for_task(task_a)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_task(task_b),
            reordered.pending_obligation_ids_for_task(task_b)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_region(region_x),
            reordered.pending_obligation_ids_for_region(region_x)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_region(region_y),
            reordered.pending_obligation_ids_for_region(region_y)
        );
        assert_eq!(
            baseline.ids_for_holder(task_a),
            reordered.ids_for_holder(task_a)
        );
        assert_eq!(
            baseline.ids_for_holder(task_b),
            reordered.ids_for_holder(task_b)
        );

        for id in ids {
            let baseline_record = baseline.get(id.arena_index()).expect("record exists");
            let reordered_record = reordered.get(id.arena_index()).expect("record exists");
            assert_eq!(baseline_record.state, reordered_record.state);
            assert_eq!(baseline_record.holder, reordered_record.holder);
            assert_eq!(baseline_record.region, reordered_record.region);
            assert_eq!(baseline_record.kind, reordered_record.kind);
        }
    }

    // Pure data-type tests (wave 34 – CyanBarn)

    #[test]
    fn obligation_commit_info_debug_clone() {
        let info = ObligationCommitInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(1),
            region: test_region_id(1),
            kind: ObligationKind::SendPermit,
            duration: 42,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationCommitInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 42);
        assert_eq!(cloned.kind, ObligationKind::SendPermit);
    }

    #[test]
    fn obligation_abort_info_debug_clone() {
        let info = ObligationAbortInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(2),
            region: test_region_id(1),
            kind: ObligationKind::Ack,
            duration: 500,
            reason: ObligationAbortReason::Cancel,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationAbortInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 500);
        assert_eq!(cloned.reason, ObligationAbortReason::Cancel);
    }

    #[test]
    fn obligation_leak_info_debug_clone() {
        let info = ObligationLeakInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(3),
            region: test_region_id(1),
            kind: ObligationKind::IoOp,
            duration: 2000,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
            description: Some("test leak".into()),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationLeakInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 2000);
        assert_eq!(cloned.description.as_deref(), Some("test leak"));
    }

    #[test]
    fn obligation_create_args_debug_clone() {
        let args = ObligationCreateArgs {
            kind: ObligationKind::Lease,
            holder: test_task_id(5),
            region: test_region_id(2),
            now: Time::ZERO,
            description: Some("test create".into()),
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("ObligationCreateArgs"));
        let cloned = args;
        assert_eq!(cloned.kind, ObligationKind::Lease);
        assert_eq!(cloned.description.as_deref(), Some("test create"));
    }

    #[test]
    fn obligation_table_debug() {
        let table = ObligationTable::new();
        let dbg = format!("{table:?}");
        assert!(dbg.contains("ObligationTable"));
    }

    #[test]
    fn obligation_table_default() {
        let table = ObligationTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn obligation_table_new_empty() {
        let table = ObligationTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.pending_count(), 0);
    }

    /// Regression for br-asupersync-xxcss5: per-kind pending counters and the
    /// running reserved_at sum stay consistent with the arena across
    /// create/commit/abort/leak/remove, so the Lyapunov governor can read
    /// them directly instead of scanning obligations on every snapshot.
    #[test]
    fn incremental_counters_track_all_mutations() {
        let mut table = ObligationTable::new();
        let task_a = test_task_id(10);
        let task_b = test_task_id(11);
        let region = test_region_id(3);

        let send = table.create(ObligationCreateArgs {
            kind: ObligationKind::SendPermit,
            holder: task_a,
            region,
            now: Time::from_nanos(100),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let ack = table.create(ObligationCreateArgs {
            kind: ObligationKind::Ack,
            holder: task_a,
            region,
            now: Time::from_nanos(150),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let lease = table.create(ObligationCreateArgs {
            kind: ObligationKind::Lease,
            holder: task_b,
            region,
            now: Time::from_nanos(200),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let sem = table.create(ObligationCreateArgs {
            kind: ObligationKind::SemaphorePermit,
            holder: task_b,
            region,
            now: Time::from_nanos(250),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });

        assert_eq!(table.pending_count(), 4);
        assert_eq!(table.pending_count_for_kind(ObligationKind::SendPermit), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Ack), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Lease), 1);
        assert_eq!(
            table.pending_count_for_kind(ObligationKind::SemaphorePermit),
            1
        );
        assert_eq!(table.pending_count_for_kind(ObligationKind::IoOp), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 100 + 150 + 200 + 250);

        // Commit → pending count & kind bucket decrement, and reserved_at sum
        // loses exactly the committed obligation's nanos.
        table.commit(send, Time::from_nanos(300)).unwrap();
        assert_eq!(table.pending_count(), 3);
        assert_eq!(table.pending_count_for_kind(ObligationKind::SendPermit), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 150 + 200 + 250);

        // Abort decrements the Ack bucket.
        table
            .abort(ack, Time::from_nanos(400), ObligationAbortReason::Cancel)
            .unwrap();
        assert_eq!(table.pending_count(), 2);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Ack), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 200 + 250);

        // Mark-leaked decrements the Lease bucket.
        table.mark_leaked(lease, Time::from_nanos(500)).unwrap();
        assert_eq!(table.pending_count(), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Lease), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 250);

        // Removing a still-pending obligation must also decrement.
        let removed = table.remove(sem.arena_index()).unwrap();
        assert_eq!(removed.kind, ObligationKind::SemaphorePermit);
        assert_eq!(table.pending_count(), 0);
        assert_eq!(
            table.pending_count_for_kind(ObligationKind::SemaphorePermit),
            0
        );
        assert_eq!(table.pending_reserved_at_sum_ns(), 0);

        // Per-kind counters must bottom out at zero on saturating_sub paths.
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
        ] {
            assert_eq!(table.pending_count_for_kind(kind), 0);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "pending counter underflow")]
    fn pending_counter_underflow_is_not_silent_in_debug() {
        let mut table = ObligationTable::new();
        table.note_pending_removed(ObligationKind::Ack, Time::ZERO);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "pending counter drift")]
    fn pending_counter_scan_catches_cached_count_drift_in_debug() {
        let mut table = ObligationTable::new();
        let task = test_task_id(12);
        let region = test_region_id(4);

        make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        table.cached_pending = 0;

        table.debug_assert_pending_counters_match();
    }
}
