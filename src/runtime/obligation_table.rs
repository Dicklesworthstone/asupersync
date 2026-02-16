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
use std::collections::BTreeMap;
use std::sync::Arc;

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
    /// Secondary index: task → obligation IDs held by that task.
    by_holder: BTreeMap<TaskId, SmallVec<[ObligationId; 4]>>,
}

impl ObligationTable {
    /// Creates an empty obligation table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: Arena::new(),
            by_holder: BTreeMap::new(),
        }
    }

    // =========================================================================
    // Low-level arena access
    // =========================================================================

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
        let holder = record.holder;
        let idx = self.obligations.insert(record);
        self.by_holder
            .entry(holder)
            .or_default()
            .push(ObligationId::from_arena(idx));
        idx
    }

    /// Inserts a new obligation record produced by `f` into the arena.
    ///
    /// The closure receives the assigned `ArenaIndex`.
    pub fn insert_with<F>(&mut self, f: F) -> ArenaIndex
    where
        F: FnOnce(ArenaIndex) -> ObligationRecord,
    {
        let idx = self.obligations.insert_with(f);
        if let Some(record) = self.obligations.get(idx) {
            self.by_holder
                .entry(record.holder)
                .or_default()
                .push(ObligationId::from_arena(idx));
        }
        idx
    }

    /// Removes an obligation record from the arena.
    pub fn remove(&mut self, index: ArenaIndex) -> Option<ObligationRecord> {
        let record = self.obligations.remove(index)?;
        let ob_id = ObligationId::from_arena(index);
        if let Some(ids) = self.by_holder.get_mut(&record.holder) {
            ids.retain(|id| *id != ob_id);
            if ids.is_empty() {
                self.by_holder.remove(&record.holder);
            }
        }
        Some(record)
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
        self.by_holder.entry(holder).or_default().push(ob_id);
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

        let duration = record.commit(now);
        Ok(ObligationCommitInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind: record.kind,
            duration,
        })
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

        let duration = record.abort(now, reason);
        Ok(ObligationAbortInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind: record.kind,
            duration,
            reason,
        })
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

        let duration = record.mark_leaked(now);
        Ok(ObligationLeakInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind: record.kind,
            duration,
            acquired_at: record.acquired_at,
            acquire_backtrace: record.acquire_backtrace.clone(),
            description: record.description.clone(),
        })
    }

    /// Returns obligation IDs held by a specific task (O(1) lookup via index).
    ///
    /// Returns all obligation IDs for the task, including resolved ones.
    /// Callers should filter by `is_pending()` if only active obligations are needed.
    #[must_use]
    pub fn ids_for_holder(&self, task_id: TaskId) -> &[ObligationId] {
        self.by_holder.get(&task_id).map_or(&[], SmallVec::as_slice)
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
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.obligations
            .iter()
            .filter(|(_, r)| r.is_pending())
            .count()
    }

    /// Collects IDs of pending obligations held by a specific task.
    #[must_use]
    pub fn pending_obligation_ids_for_task(&self, task_id: TaskId) -> Vec<ObligationId> {
        let mut ids: Vec<ObligationId> = self
            .ids_for_holder(task_id)
            .iter()
            .copied()
            .filter(|id| {
                self.obligations
                    .get(id.arena_index())
                    .is_some_and(ObligationRecord::is_pending)
            })
            .collect();
        ids.sort_unstable();
        ids
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
        assert!(table
            .abort(fake, Time::from_nanos(100), ObligationAbortReason::Cancel)
            .is_err());
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
}
