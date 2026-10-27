//! Obligation table for tracked resource obligations.
//!
//! Encapsulates the obligation arena and provides domain-level operations for
//! obligation lifecycle management. This separation enables finer-grained locking
//! in the sharded runtime state (each table behind its own lock).

use super::obligation_conservation::{
    ObligationConservationCheckpoint, ObligationConservationViolation, ObligationLifetimeLedger,
    ObligationLifetimeReport, ObligationLifetimeTransition,
};
use crate::error::{Error, ErrorKind};
use crate::obligation::ledger::{ObligationAuditRecord, ObligationCounts};
use crate::record::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationResolution, SourceLocation,
};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::{Arena, ArenaIndex};
use smallvec::SmallVec;
use std::backtrace::Backtrace;
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

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
const OBLIGATION_KIND_COUNT: usize = 6;

/// Committed and aborted records the table keeps queryable before reclaiming
/// the oldest (br-asupersync-fu6cr0). Every mpsc send, oneshot,
/// permit and lease resolves an obligation, so keeping every resolved record
/// grew the table, its holder index and every full scan without bound.
/// Leaked records are never reclaimed: leak diagnostics read them.
const RESOLVED_RETENTION: usize = 4096;

/// Finalized regions the fence remembers, most recent first. A finalized
/// region has no pending obligation (region close requires none), so an older
/// region's records already refuse commit and abort as resolved; the fence
/// only keeps the more specific `RegionFinalized` error for recent regions.
const FINALIZED_FENCE_RETENTION: usize = 4096;

/// Debug builds compare the cached pending counters with a full scan on every
/// call while the table is small, then every this-many calls.
#[cfg(debug_assertions)]
const COUNTER_CHECK_ALWAYS_UP_TO: usize = 64;
#[cfg(debug_assertions)]
const COUNTER_CHECK_INTERVAL: usize = 4096;

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
    /// Opt-in history independent of resolved-record retention.
    lifetime: Option<Box<ObligationLifetimeLedger>>,
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
    /// Regions that have been finalized and should reject further obligation operations.
    ///
    /// This implements the region finalization fence pattern from ObligationLedger
    /// to prevent drop-late commit/abort after region close. Obligations for
    /// finalized regions are rejected with RegionFinalized error.
    finalized_regions: BTreeSet<RegionId>,
    /// `finalized_regions` in finalization order, for bounded retention.
    finalized_order: VecDeque<RegionId>,
    /// Committed and aborted obligations, oldest first, for bounded retention.
    resolved_order: VecDeque<ObligationId>,
    /// Calls of the debug counter check, for sampling.
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    counter_checks: AtomicUsize,
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
        ObligationKind::Transaction => 5,
    }
}

impl ObligationTable {
    /// Creates an empty obligation table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: Arena::new(),
            by_holder: Vec::with_capacity(32),
            lifetime: None,
            cached_pending: 0,
            pending_by_kind: [0; OBLIGATION_KIND_COUNT],
            pending_reserved_at_sum_ns: 0,
            finalized_regions: BTreeSet::new(),
            finalized_order: VecDeque::new(),
            resolved_order: VecDeque::new(),
            counter_checks: AtomicUsize::new(0),
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
            lifetime: None,
            cached_pending: 0,
            pending_by_kind: [0; OBLIGATION_KIND_COUNT],
            pending_reserved_at_sum_ns: 0,
            finalized_regions: BTreeSet::new(),
            finalized_order: VecDeque::new(),
            resolved_order: VecDeque::new(),
            counter_checks: AtomicUsize::new(0),
        }
    }

    /// Starts a lifetime epoch from the currently pending arena marking.
    /// Repeated enablement preserves all historical counts.
    pub(crate) fn enable_lifetime_checks(&mut self) {
        if self.lifetime.is_some() {
            return;
        }
        let mut ledger = ObligationLifetimeLedger::default();
        for (index, record) in self
            .obligations
            .iter()
            .filter(|(_, record)| record.is_pending())
        {
            ledger.note(
                ObligationId::from_arena(index),
                record.region,
                record.kind,
                ObligationLifetimeTransition::Baseline,
            );
        }
        self.lifetime = Some(Box::new(ledger));
    }

    pub(crate) fn inspect_lifetime(
        &self,
        checkpoint: ObligationConservationCheckpoint,
    ) -> Option<(
        ObligationLifetimeReport,
        Option<ObligationConservationViolation>,
    )> {
        self.lifetime
            .as_ref()
            .map(|ledger| ledger.inspect(self, checkpoint))
    }

    pub(crate) fn lifetime_violation_at_close(
        &self,
        region: RegionId,
    ) -> Option<ObligationConservationViolation> {
        self.lifetime
            .as_ref()
            .and_then(|ledger| ledger.check_close(region, self))
    }

    /// Returns the reserved obligation arena capacity.
    #[cfg(any(test, feature = "test-internals"))]
    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub(crate) fn capacity(&self) -> usize {
        self.obligations.capacity()
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
        let kind_slot = kind_index(kind);
        let reserved_at_ns = u128::from(reserved_at.as_nanos());

        let cached_pending = self.cached_pending.checked_sub(1).unwrap_or_else(|| {
            panic!(
                "pending counter underflow removing {kind:?} obligation reserved at {reserved_at:?}"
            )
        });
        let pending_for_kind = self.pending_by_kind[kind_slot]
            .checked_sub(1)
            .unwrap_or_else(|| {
                panic!(
                    "per-kind pending counter underflow removing {kind:?} obligation reserved at {reserved_at:?}"
                )
            });
        let pending_reserved_at_sum_ns = self
            .pending_reserved_at_sum_ns
            .checked_sub(reserved_at_ns)
            .unwrap_or_else(|| {
                panic!(
                    "pending reserved-at sum underflow removing {kind:?} obligation reserved at {reserved_at:?}"
                )
            });

        self.cached_pending = cached_pending;
        self.pending_by_kind[kind_slot] = pending_for_kind;
        self.pending_reserved_at_sum_ns = pending_reserved_at_sum_ns;
    }

    #[cfg(debug_assertions)]
    fn debug_assert_pending_counters_match(&self) {
        let calls = self
            .counter_checks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.obligations.len() > COUNTER_CHECK_ALWAYS_UP_TO
            && !calls.is_multiple_of(COUNTER_CHECK_INTERVAL)
        {
            return;
        }
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
        let region = record.region;
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
            if let Some(ledger) = self.lifetime.as_mut() {
                ledger.note(
                    ObligationId::from_arena(idx),
                    region,
                    kind,
                    ObligationLifetimeTransition::Reserve,
                );
            }
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

    /// Rebind an accepted handoff without changing identity, age, or counts.
    #[allow(clippy::result_large_err)]
    pub(crate) fn rebind_pending(
        &mut self,
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
    ) -> Result<(), Error> {
        let record = self
            .obligations
            .get(id.arena_index())
            .filter(|record| record.is_pending())
            .ok_or_else(|| Error::new(ErrorKind::ObligationAlreadyResolved))?;
        let old_holder = record.holder;
        let old_region = record.region;
        let kind = record.kind;
        // Allocate the destination index before retiring the old index.
        self.push_holder_id(holder, id);
        let slot = old_holder.arena_index().index() as usize;
        if let Some(entries) = self.by_holder.get_mut(slot) {
            if let Some(entry) = entries.iter().position(|(task, _)| *task == old_holder) {
                let (_, ids) = &mut entries[entry];
                if let Some(index) = ids.iter().position(|candidate| *candidate == id) {
                    ids.swap_remove(index);
                }
                if ids.is_empty() {
                    entries.swap_remove(entry);
                }
            }
        }
        let record = self
            .obligations
            .get_mut(id.arena_index())
            .expect("pending record retained across index update");
        record.holder = holder;
        record.region = region;
        if let Some(ledger) = self.lifetime.as_mut() {
            ledger.transferred(id, old_region, region, kind);
        }
        self.debug_assert_pending_counters_match();
        Ok(())
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
                record.region,
                record.kind,
                record.reserved_at,
                record.is_pending(),
            )
        });
        if let Some((holder, region, kind, reserved_at, is_pending)) = note {
            self.push_holder_id(holder, ObligationId::from_arena(idx));
            if is_pending {
                self.note_pending_added(kind, reserved_at);
                if let Some(ledger) = self.lifetime.as_mut() {
                    ledger.note(
                        ObligationId::from_arena(idx),
                        region,
                        kind,
                        ObligationLifetimeTransition::Reserve,
                    );
                }
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
            if let Some(ledger) = self.lifetime.as_mut() {
                ledger.note(
                    ObligationId::from_arena(index),
                    record.region,
                    record.kind,
                    ObligationLifetimeTransition::RemovePending,
                );
            }
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
        if let Some(ledger) = self.lifetime.as_mut() {
            ledger.note(ob_id, region, kind, ObligationLifetimeTransition::Reserve);
        }
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
        // First check if obligation exists and get region for finalization check
        let region = {
            let record = self
                .obligations
                .get(obligation.arena_index())
                .ok_or_else(|| {
                    Error::new(ErrorKind::ObligationAlreadyResolved)
                        .with_message("obligation not found")
                })?;
            record.region
        };

        // Region finalization fence: reject commits after region close
        if self.is_region_finalized(region) {
            return Err(Error::new(ErrorKind::RegionFinalized)
                .with_message("cannot commit obligation: region has been finalized"));
        }

        // Now get mutable reference for the actual commit
        let record = self.obligations.get_mut(obligation.arena_index()).unwrap();

        if !record.is_pending() {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
        }

        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let duration = record.resolve(now, ObligationResolution::Commit);
        let info = ObligationCommitInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind,
            duration,
        };
        self.note_pending_removed(kind, reserved_at);
        if let Some(ledger) = self.lifetime.as_mut() {
            ledger.resolved(obligation, region, kind, ObligationResolution::Commit);
        }
        self.retain_resolved(info.id);
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
        // First check if obligation exists and get region for finalization check
        let region = {
            let record = self
                .obligations
                .get(obligation.arena_index())
                .ok_or_else(|| {
                    Error::new(ErrorKind::ObligationAlreadyResolved)
                        .with_message("obligation not found")
                })?;
            record.region
        };

        // Region finalization fence: reject aborts after region close
        if self.is_region_finalized(region) {
            return Err(Error::new(ErrorKind::RegionFinalized)
                .with_message("cannot abort obligation: region has been finalized"));
        }

        // Now get mutable reference for the actual abort
        let record = self.obligations.get_mut(obligation.arena_index()).unwrap();

        if !record.is_pending() {
            return Err(Error::new(ErrorKind::ObligationAlreadyResolved));
        }

        let kind = record.kind;
        let reserved_at = record.reserved_at;
        let duration = record.resolve(now, ObligationResolution::Abort(reason));
        let info = ObligationAbortInfo {
            id: record.id,
            holder: record.holder,
            region: record.region,
            kind,
            duration,
            reason,
        };
        self.note_pending_removed(kind, reserved_at);
        if let Some(ledger) = self.lifetime.as_mut() {
            ledger.resolved(
                obligation,
                region,
                kind,
                ObligationResolution::Abort(reason),
            );
        }
        self.retain_resolved(info.id);
        self.debug_assert_pending_counters_match();
        Ok(info)
    }

    /// Keeps a committed or aborted record queryable for the next
    /// [`RESOLVED_RETENTION`] resolutions, then reclaims it with its holder
    /// index entry. A reclaimed id reads as absent, and commit or abort on it
    /// fails as already resolved, which it is.
    fn retain_resolved(&mut self, obligation: ObligationId) {
        self.resolved_order.push_back(obligation);
        while self.resolved_order.len() > RESOLVED_RETENTION {
            let Some(oldest) = self.resolved_order.pop_front() else {
                break;
            };
            if self
                .obligations
                .get(oldest.arena_index())
                .is_some_and(|record| !record.is_pending())
            {
                let _ = self.remove(oldest.arena_index());
            }
        }
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
        let duration = record.resolve(now, ObligationResolution::Leak);
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
        if let Some(ledger) = self.lifetime.as_mut() {
            ledger.resolved(obligation, info.region, kind, ObligationResolution::Leak);
        }
        self.debug_assert_pending_counters_match();
        Ok(info)
    }

    /// Returns obligation IDs held by a specific task (O(1) lookup via index).
    ///
    /// Returns all obligation IDs for the task, including the resolved ones
    /// the table still retains.
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

    /// Returns counts across all obligations in the table.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::record::{ObligationKind, SourceLocation};
    /// use asupersync::runtime::ObligationTable;
    /// use asupersync::runtime::obligation_table::ObligationCreateArgs;
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut table = ObligationTable::new();
    /// let task = TaskId::testing_default();
    /// let region = RegionId::testing_default();
    /// let base = |kind, region, now| ObligationCreateArgs {
    ///     kind,
    ///     holder: task,
    ///     region,
    ///     now,
    ///     description: None,
    ///     acquired_at: SourceLocation::unknown(),
    ///     acquire_backtrace: None,
    /// };
    ///
    /// table.create(base(ObligationKind::Lease, region, Time::from_nanos(10)));
    /// let ack = table.create(base(ObligationKind::Ack, region, Time::from_nanos(20)));
    /// table.commit(ack, Time::from_nanos(30))?;
    ///
    /// assert_eq!(table.counts().total(), 2);
    /// assert_eq!(table.counts_for_region(region).pending, 1);
    /// assert_eq!(table.counts_for_task(task).total(), 2);
    /// assert_eq!(table.counts_for_kind(ObligationKind::Ack).committed, 1);
    /// assert_eq!(
    ///     table
    ///         .counts_for_region_and_kind(region, ObligationKind::Lease)
    ///         .pending,
    ///     1
    /// );
    /// # Ok::<(), asupersync::error::Error>(())
    /// ```
    #[must_use]
    pub fn counts(&self) -> ObligationCounts {
        ObligationCounts::from_records(self.obligations.iter().map(|(_, record)| record))
    }

    /// Returns counts for obligations belonging to `region`.
    #[must_use]
    pub fn counts_for_region(&self, region: RegionId) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .iter()
                .map(|(_, record)| record)
                .filter(|record| record.region == region),
        )
    }

    /// Returns counts for obligations held by `task`.
    #[must_use]
    pub fn counts_for_task(&self, task: TaskId) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .iter()
                .map(|(_, record)| record)
                .filter(|record| record.holder == task),
        )
    }

    /// Returns counts for obligations of `kind`.
    #[must_use]
    pub fn counts_for_kind(&self, kind: ObligationKind) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .iter()
                .map(|(_, record)| record)
                .filter(|record| record.kind == kind),
        )
    }

    /// Returns counts for obligations matching both `region` and `kind`.
    #[must_use]
    pub fn counts_for_region_and_kind(
        &self,
        region: RegionId,
        kind: ObligationKind,
    ) -> ObligationCounts {
        ObligationCounts::from_records(
            self.obligations
                .iter()
                .map(|(_, record)| record)
                .filter(|record| record.region == region && record.kind == kind),
        )
    }

    /// Returns the lifecycle state for `id`, if it is known to this table.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::record::{ObligationKind, ObligationState, SourceLocation};
    /// use asupersync::runtime::ObligationTable;
    /// use asupersync::runtime::obligation_table::ObligationCreateArgs;
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut table = ObligationTable::new();
    /// let id = table.create(ObligationCreateArgs {
    ///     kind: ObligationKind::Lease,
    ///     holder: TaskId::testing_default(),
    ///     region: RegionId::testing_default(),
    ///     now: Time::from_nanos(10),
    ///     description: None,
    ///     acquired_at: SourceLocation::unknown(),
    ///     acquire_backtrace: None,
    /// });
    ///
    /// assert_eq!(table.obligation_state(id), Some(ObligationState::Reserved));
    /// ```
    #[must_use]
    pub fn obligation_state(&self, id: ObligationId) -> Option<crate::record::ObligationState> {
        self.obligations
            .get(id.arena_index())
            .map(|record| record.state)
    }

    /// Returns owned audit snapshots for every obligation.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::record::{ObligationKind, SourceLocation};
    /// use asupersync::runtime::ObligationTable;
    /// use asupersync::runtime::obligation_table::ObligationCreateArgs;
    /// use asupersync::types::{RegionId, TaskId, Time};
    ///
    /// let mut table = ObligationTable::new();
    /// let task = TaskId::testing_default();
    /// let region = RegionId::testing_default();
    /// let base = |kind, holder| ObligationCreateArgs {
    ///     kind,
    ///     holder,
    ///     region,
    ///     now: Time::from_nanos(10),
    ///     description: None,
    ///     acquired_at: SourceLocation::unknown(),
    ///     acquire_backtrace: None,
    /// };
    ///
    /// table.create(base(ObligationKind::Lease, task));
    /// table.create(base(ObligationKind::Ack, task));
    ///
    /// assert_eq!(table.audit(Time::from_nanos(30)).len(), 2);
    /// assert_eq!(table.audit_region(region, Time::from_nanos(30)).len(), 2);
    /// assert_eq!(table.audit_task(task, Time::from_nanos(30)).len(), 2);
    /// assert_eq!(table.audit_kind(ObligationKind::Lease, Time::from_nanos(30)).len(), 1);
    /// ```
    #[must_use]
    pub fn audit(&self, now: Time) -> Vec<ObligationAuditRecord> {
        let mut records: Vec<_> = self
            .obligations
            .iter()
            .map(|(_, record)| ObligationAuditRecord::from_record(record, now))
            .collect();
        records.sort_unstable_by_key(|record| record.id);
        records
    }

    /// Returns owned audit snapshots for obligations belonging to `region`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_region(&self, region: RegionId, now: Time) -> Vec<ObligationAuditRecord> {
        let mut records: Vec<_> = self
            .obligations
            .iter()
            .map(|(_, record)| record)
            .filter(|record| record.region == region)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect();
        records.sort_unstable_by_key(|record| record.id);
        records
    }

    /// Returns owned audit snapshots for obligations held by `task`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_task(&self, task: TaskId, now: Time) -> Vec<ObligationAuditRecord> {
        let mut records: Vec<_> = self
            .obligations
            .iter()
            .map(|(_, record)| record)
            .filter(|record| record.holder == task)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect();
        records.sort_unstable_by_key(|record| record.id);
        records
    }

    /// Returns owned audit snapshots for obligations of `kind`.
    ///
    /// Results are ordered by [`ObligationId`] for deterministic diagnostics.
    #[must_use]
    pub fn audit_kind(&self, kind: ObligationKind, now: Time) -> Vec<ObligationAuditRecord> {
        let mut records: Vec<_> = self
            .obligations
            .iter()
            .map(|(_, record)| record)
            .filter(|record| record.kind == kind)
            .map(|record| ObligationAuditRecord::from_record(record, now))
            .collect();
        records.sort_unstable_by_key(|record| record.id);
        records
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

    /// Marks a region as finalized to prevent further obligation operations.
    ///
    /// After this call, all `commit()` and `abort()` operations for obligations
    /// belonging to this region will fail with `ErrorKind::RegionFinalized`.
    /// This implements the region finalization fence to ensure structured
    /// concurrency invariants: no obligation mutations after region close.
    ///
    /// Idempotent - calling multiple times on the same region is safe.
    ///
    /// The fence remembers the most recent `FINALIZED_FENCE_RETENTION`
    /// regions. An older region's obligations are all resolved or leaked (a
    /// region closes with none pending), so `commit()` and `abort()` still
    /// refuse them, as already resolved.
    pub fn mark_region_finalized(&mut self, region: RegionId) {
        // Bound per-region history by regions still needing verification.
        // Never erase an unconserved or nonempty marking, even if a low-level
        // caller bypassed the runtime's region-close barrier.
        let retire_lifetime = self.lifetime.as_ref().is_some_and(|ledger| {
            !self
                .obligations
                .iter()
                .any(|(_, record)| record.region == region && record.is_pending())
                && ledger.check_close(region, self).is_none()
        });
        if retire_lifetime {
            if let Some(ledger) = self.lifetime.as_mut() {
                ledger.retire_region(region);
            }
        }
        if self.finalized_regions.insert(region) {
            self.finalized_order.push_back(region);
            while self.finalized_order.len() > FINALIZED_FENCE_RETENTION {
                if let Some(oldest) = self.finalized_order.pop_front() {
                    self.finalized_regions.remove(&oldest);
                }
            }
        }
    }

    /// Returns `true` if the given region has been marked as finalized.
    #[must_use]
    pub fn is_region_finalized(&self, region: RegionId) -> bool {
        self.finalized_regions.contains(&region)
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
#[path = "obligation_table_inline_tests.rs"]
mod tests;
