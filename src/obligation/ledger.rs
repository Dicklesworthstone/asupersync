//! Runtime obligation ledger — central registry for linear token tracking.
//!
//! The ledger is the runtime's single source of truth for obligation lifecycle.
//! Every acquire/commit/abort flows through here, making leaks structurally
//! impossible when the ledger is used correctly.
//!
//! # Invariants
//!
//! 1. Every obligation ID is unique and issued exactly once.
//! 2. Every obligation transitions through exactly one path:
//!    `Reserved → Committed` or `Reserved → Aborted` or `Reserved → Leaked`.
//! 3. Region close requires zero pending obligations for that region.
//! 4. Double-resolve panics (enforced by `ObligationRecord`).
//!
//! # Integration
//!
//! The ledger is designed to be held by the runtime state and queried by:
//! - The scheduler (to check quiescence conditions)
//! - The leak oracle (to verify invariants in lab mode)
//! - The cancellation protocol (to abort obligations during drain)

use crate::record::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState, SourceLocation,
};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::ArenaIndex;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A linear token representing a live obligation.
///
/// This token must be consumed by calling [`ObligationLedger::commit`] or
/// [`ObligationLedger::abort`]. Dropping it without resolution is a logic
/// error caught by the ledger's leak check.
///
/// The token is intentionally `!Clone` and `!Copy` to approximate linearity.
#[must_use = "obligation tokens must be committed or aborted; dropping leaks the obligation"]
#[derive(Debug)]
pub struct ObligationToken {
    id: ObligationId,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
}

impl ObligationToken {
    /// Returns the obligation ID.
    #[must_use]
    pub fn id(&self) -> ObligationId {
        self.id
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// Returns the holder task ID.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// Returns the owning region ID.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }
}

/// Statistics about the ledger's obligation tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerStats {
    /// Total obligations ever acquired.
    pub total_acquired: u64,
    /// Total obligations committed.
    pub total_committed: u64,
    /// Total obligations aborted.
    pub total_aborted: u64,
    /// Total obligations leaked.
    pub total_leaked: u64,
    /// Currently pending (reserved, not yet resolved).
    pub pending: u64,
}

impl LedgerStats {
    /// Returns true if all obligations have been resolved.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.pending == 0 && self.total_leaked == 0
    }
}

/// A leaked obligation diagnostic for the leak oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedObligation {
    /// The obligation ID.
    pub id: ObligationId,
    /// The obligation kind.
    pub kind: ObligationKind,
    /// The task that held it.
    pub holder: TaskId,
    /// The region it belonged to.
    pub region: RegionId,
    /// When it was reserved.
    pub reserved_at: Time,
    /// Description, if any.
    pub description: Option<String>,
    /// Source location of acquisition.
    pub acquired_at: SourceLocation,
}

/// Result of a ledger leak check.
#[derive(Debug, Clone)]
pub struct LeakCheckResult {
    /// Leaked obligations found.
    pub leaked: Vec<LeakedObligation>,
}

impl LeakCheckResult {
    /// Returns true if no leaks were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.leaked.is_empty()
    }
}

/// The obligation ledger: central registry for obligation lifecycle.
///
/// All obligation acquire/commit/abort operations flow through the ledger.
/// It maintains a `BTreeMap` for deterministic iteration order (required for
/// lab-mode reproducibility).
#[derive(Debug)]
pub struct ObligationLedger {
    /// All obligations, keyed by ID. BTreeMap for deterministic iteration.
    obligations: BTreeMap<ObligationId, ObligationRecord>,
    /// Next slot index for ID allocation within the current ledger generation.
    next_index: u32,
    /// Current generation for obligation IDs issued by this ledger epoch.
    generation: u32,
    /// Running statistics.
    stats: LedgerStats,
}

impl Default for ObligationLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ObligationLedger {
    fn pending_record_for_id_mut(
        &mut self,
        id: ObligationId,
        operation: &'static str,
    ) -> &mut ObligationRecord {
        let record = self
            .obligations
            .get_mut(&id)
            .unwrap_or_else(|| panic!("{operation}: obligation {id:?} not found in ledger"));
        assert!(
            record.is_pending(),
            "{operation}: obligation {id:?} is not pending (state={:?})",
            record.state
        );
        record
    }

    fn resolve_one_pending(&mut self, operation: &'static str) {
        self.stats.pending =
            self.stats.pending.checked_sub(1).unwrap_or_else(|| {
                panic!("{operation}: obligation ledger pending stats underflow")
            });
    }

    fn record_for_token_mut(&mut self, token: &ObligationToken) -> &mut ObligationRecord {
        let record = self.pending_record_for_id_mut(token.id, "token resolve");
        assert_eq!(
            record.kind, token.kind,
            "obligation token kind does not match ledger record"
        );
        assert_eq!(
            record.holder, token.holder,
            "obligation token holder does not match ledger record"
        );
        assert_eq!(
            record.region, token.region,
            "obligation token region does not match ledger record"
        );
        record
    }

    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
            next_index: 0,
            generation: 0,
            stats: LedgerStats::default(),
        }
    }

    /// Acquires a new obligation, returning a linear token.
    ///
    /// The token must be passed to [`commit`](Self::commit) or
    /// [`abort`](Self::abort) to resolve the obligation.
    pub fn acquire(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> ObligationToken {
        self.acquire_with_context(
            kind,
            holder,
            region,
            now,
            SourceLocation::unknown(),
            None,
            None,
        )
    }

    /// Acquires a new obligation with full context.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire_with_context(
        &mut self,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
        location: SourceLocation,
        backtrace: Option<Arc<std::backtrace::Backtrace>>,
        description: Option<String>,
    ) -> ObligationToken {
        let idx = ArenaIndex::new(self.next_index, self.generation);
        self.next_index = self
            .next_index
            .checked_add(1)
            .expect("obligation ledger index overflow within current generation; reset required");
        let id = ObligationId::from_arena(idx);

        let record = if let Some(desc) = description {
            ObligationRecord::with_description_and_context(
                id, kind, holder, region, now, desc, location, backtrace,
            )
        } else {
            ObligationRecord::new_with_context(id, kind, holder, region, now, location, backtrace)
        };

        self.obligations.insert(id, record);
        self.stats.total_acquired += 1;
        self.stats.pending += 1;

        ObligationToken {
            id,
            kind,
            holder,
            region,
        }
    }

    /// Commits an obligation, consuming the token.
    ///
    /// Returns the duration the obligation was held (in nanoseconds).
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn commit(&mut self, token: ObligationToken, now: Time) -> u64 {
        let record = self.record_for_token_mut(&token);
        let duration = record.commit(now);
        self.stats.total_committed += 1;
        self.resolve_one_pending("commit");
        duration
    }

    /// Aborts an obligation, consuming the token.
    ///
    /// Returns the duration the obligation was held (in nanoseconds).
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    #[allow(clippy::needless_pass_by_value)] // Token consumed intentionally to prevent reuse
    pub fn abort(
        &mut self,
        token: ObligationToken,
        now: Time,
        reason: ObligationAbortReason,
    ) -> u64 {
        let record = self.record_for_token_mut(&token);
        let duration = record.abort(now, reason);
        self.stats.total_aborted += 1;
        self.resolve_one_pending("abort");
        duration
    }

    /// Aborts an obligation by ID.
    ///
    /// This is intended for external drain and recovery paths that enumerate
    /// pending obligations by ID after the original linear token is no longer
    /// available to the caller.
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    pub fn abort_by_id(
        &mut self,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> u64 {
        let record = self.pending_record_for_id_mut(id, "abort_by_id");
        let duration = record.abort(now, reason);
        self.stats.total_aborted += 1;
        self.resolve_one_pending("abort_by_id");
        duration
    }

    /// Marks an obligation as leaked (runtime detected the holder completed
    /// without resolving).
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    pub fn mark_leaked(&mut self, id: ObligationId, now: Time) -> u64 {
        let record = self.pending_record_for_id_mut(id, "mark_leaked");
        let duration = record.mark_leaked(now);
        self.stats.total_leaked += 1;
        self.resolve_one_pending("mark_leaked");
        duration
    }

    /// Returns the current ledger statistics.
    #[must_use]
    pub fn stats(&self) -> LedgerStats {
        self.stats
    }

    /// Returns the number of currently pending obligations.
    #[must_use]
    pub fn pending_count(&self) -> u64 {
        self.stats.pending
    }

    /// Returns the number of pending obligations for a specific region.
    #[must_use]
    pub fn pending_for_region(&self, region: RegionId) -> usize {
        self.obligations
            .values()
            .filter(|o| o.region == region && o.state == ObligationState::Reserved)
            .count()
    }

    /// Returns the number of pending obligations for a specific task.
    #[must_use]
    pub fn pending_for_task(&self, task: TaskId) -> usize {
        self.obligations
            .values()
            .filter(|o| o.holder == task && o.state == ObligationState::Reserved)
            .count()
    }

    /// Returns IDs of all pending obligations for a region.
    ///
    /// Callers performing cancellation drain can feed the returned IDs into
    /// [`abort_by_id`](Self::abort_by_id) to resolve them deterministically
    /// without needing to recover the original linear tokens.
    #[must_use]
    pub fn pending_ids_for_region(&self, region: RegionId) -> Vec<ObligationId> {
        self.obligations
            .iter()
            .filter(|(_, o)| o.region == region && o.state == ObligationState::Reserved)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns true if the region has no pending obligations (quiescence check).
    #[must_use]
    pub fn is_region_clean(&self, region: RegionId) -> bool {
        self.pending_for_region(region) == 0
    }

    /// Checks all obligations for leaks.
    ///
    /// Returns a deterministic leak report. In lab mode, the test should fail
    /// if leaks are found.
    #[must_use]
    pub fn check_leaks(&self) -> LeakCheckResult {
        let leaked: Vec<LeakedObligation> = self
            .obligations
            .iter()
            .filter(|(_, o)| o.is_pending() || o.is_leaked())
            .map(|(_, o)| LeakedObligation {
                id: o.id,
                kind: o.kind,
                holder: o.holder,
                region: o.region,
                reserved_at: o.reserved_at,
                description: o.description.clone(),
                acquired_at: o.acquired_at,
            })
            .collect();

        LeakCheckResult { leaked }
    }

    /// Checks for leaks in a specific region.
    #[must_use]
    pub fn check_region_leaks(&self, region: RegionId) -> LeakCheckResult {
        let leaked: Vec<LeakedObligation> = self
            .obligations
            .iter()
            .filter(|(_, o)| o.region == region && (o.is_pending() || o.is_leaked()))
            .map(|(_, o)| LeakedObligation {
                id: o.id,
                kind: o.kind,
                holder: o.holder,
                region: o.region,
                reserved_at: o.reserved_at,
                description: o.description.clone(),
                acquired_at: o.acquired_at,
            })
            .collect();

        LeakCheckResult { leaked }
    }

    /// Returns a reference to an obligation record by ID.
    #[must_use]
    pub fn get(&self, id: ObligationId) -> Option<&ObligationRecord> {
        self.obligations.get(&id)
    }

    /// Returns the total number of obligations (all states).
    #[must_use]
    pub fn len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns true if the ledger has no obligations at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obligations.is_empty()
    }

    /// Resets the ledger to empty state.
    ///
    /// # Panics
    ///
    /// Panics if any obligations are still pending or leaked. Reset is only
    /// valid once every obligation has been resolved cleanly (committed or
    /// aborted); otherwise it would silently hide active obligations or erase
    /// leak diagnostics.
    ///
    /// Reset clears the live set, rewinds slot allocation back to index `0`,
    /// and bumps the ledger generation. Post-reset obligations can therefore
    /// reuse compact index space without allowing stale pre-reset IDs or
    /// tokens to resolve newly allocated records.
    pub fn reset(&mut self) {
        assert!(
            !self.obligations.values().any(ObligationRecord::is_pending),
            "cannot reset obligation ledger with pending obligations"
        );
        assert!(
            !self.obligations.values().any(ObligationRecord::is_leaked),
            "cannot reset obligation ledger with leaked obligations"
        );
        self.obligations.clear();
        self.stats = LedgerStats::default();
        self.next_index = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .expect("obligation ledger generation overflow");
    }

    /// Iterates over all obligations in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&ObligationId, &ObligationRecord)> {
        self.obligations.iter()
    }
}

// ============================================================================
// Tests
// ============================================================================

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
    use crate::record::ObligationKind;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_task() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(1, 0))
    }

    fn make_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LedgerObservation {
        stats: LedgerStats,
        len: usize,
        pending_count: u64,
        pending_for_region: usize,
        pending_for_task: usize,
        pending_ids_for_region: usize,
        region_clean: bool,
        leak_count: usize,
        region_leak_count: usize,
    }

    fn observe_ledger(
        ledger: &ObligationLedger,
        task: TaskId,
        region: RegionId,
    ) -> LedgerObservation {
        LedgerObservation {
            stats: ledger.stats(),
            len: ledger.len(),
            pending_count: ledger.pending_count(),
            pending_for_region: ledger.pending_for_region(region),
            pending_for_task: ledger.pending_for_task(task),
            pending_ids_for_region: ledger.pending_ids_for_region(region).len(),
            region_clean: ledger.is_region_clean(region),
            leak_count: ledger.check_leaks().leaked.len(),
            region_leak_count: ledger.check_region_leaks(region).leaked.len(),
        }
    }

    // ---- Basic lifecycle ---------------------------------------------------

    #[test]
    fn acquire_commit_clean() {
        init_test("acquire_commit_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(10),
        );
        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending", 1, pending);

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 15, "duration", 15, duration);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 0, "pending after commit", 0, pending);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(
            stats.total_acquired == 1,
            "acquired",
            1,
            stats.total_acquired
        );
        crate::assert_with_log!(
            stats.total_committed == 1,
            "committed",
            1,
            stats.total_committed
        );
        crate::test_complete!("acquire_commit_clean");
    }

    #[test]
    fn acquire_abort_clean() {
        init_test("acquire_abort_clean");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(5));
        let duration = ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 5, "duration", 5, duration);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::test_complete!("acquire_abort_clean");
    }

    // ---- Leak detection ---------------------------------------------------

    #[test]
    fn leak_check_detects_pending() {
        init_test("leak_check_detects_pending");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let _token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        // Intentionally not resolving — simulate a lost token.

        let result = ledger.check_leaks();
        let is_clean = result.is_clean();
        crate::assert_with_log!(!is_clean, "not clean", false, is_clean);
        let len = result.leaked.len();
        crate::assert_with_log!(len == 1, "leaked count", 1, len);
        let kind = result.leaked[0].kind;
        crate::assert_with_log!(
            kind == ObligationKind::Lease,
            "leaked kind",
            ObligationKind::Lease,
            kind
        );
        crate::test_complete!("leak_check_detects_pending");
    }

    #[test]
    fn leak_check_clean_after_resolve() {
        init_test("leak_check_clean_after_resolve");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        ledger.commit(t1, Time::from_nanos(1));
        ledger.abort(t2, Time::from_nanos(1), ObligationAbortReason::Explicit);

        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::test_complete!("leak_check_clean_after_resolve");
    }

    // ---- Region queries ---------------------------------------------------

    #[test]
    fn pending_for_region() {
        init_test("pending_for_region");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r2 = RegionId::from_arena(ArenaIndex::new(1, 0));

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, r1, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, r2, Time::ZERO);

        let r1_pending = ledger.pending_for_region(r1);
        crate::assert_with_log!(r1_pending == 2, "r1 pending", 2, r1_pending);

        let r2_pending = ledger.pending_for_region(r2);
        crate::assert_with_log!(r2_pending == 1, "r2 pending", 1, r2_pending);

        let r1_clean = ledger.is_region_clean(r1);
        crate::assert_with_log!(!r1_clean, "r1 not clean", false, r1_clean);
        crate::test_complete!("pending_for_region");
    }

    #[test]
    fn pending_ids_for_region_returns_sorted() {
        init_test("pending_ids_for_region_returns_sorted");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);

        let ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(ids.len() == 2, "ids len", 2, ids.len());
        // BTreeMap ensures deterministic order.
        crate::assert_with_log!(ids[0] == t1.id(), "first id", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second id", t2.id(), ids[1]);

        crate::test_complete!("pending_ids_for_region_returns_sorted");
    }

    // ---- Mark leaked -----------------------------------------------------

    #[test]
    fn mark_leaked_updates_stats() {
        init_test("mark_leaked_updates_stats");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(0));
        let id = token.id();
        // Intentionally not resolving token; mark as leaked below.

        ledger.mark_leaked(id, Time::from_nanos(100));

        let stats = ledger.stats();
        crate::assert_with_log!(!stats.is_clean(), "not clean", false, stats.is_clean());
        crate::assert_with_log!(stats.total_leaked == 1, "leaked", 1, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("mark_leaked_updates_stats");
    }

    #[test]
    fn check_leaks_includes_marked_leaked_obligations() {
        init_test("check_leaks_includes_marked_leaked_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = token.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(10));

        let result = ledger.check_leaks();
        crate::assert_with_log!(!result.is_clean(), "not clean", false, result.is_clean());
        crate::assert_with_log!(
            result.leaked.len() == 1,
            "leak count",
            1,
            result.leaked.len()
        );
        crate::assert_with_log!(
            result.leaked[0].id == leaked_id,
            "leaked id",
            leaked_id,
            result.leaked[0].id
        );
        crate::test_complete!("check_leaks_includes_marked_leaked_obligations");
    }

    // ---- Task queries ----------------------------------------------------

    #[test]
    fn pending_for_task() {
        init_test("pending_for_task");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region = make_region();

        let _tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let _tok2 = ledger.acquire(ObligationKind::Ack, t1, region, Time::ZERO);
        let _tok3 = ledger.acquire(ObligationKind::Lease, t2, region, Time::ZERO);

        let t1_pending = ledger.pending_for_task(t1);
        crate::assert_with_log!(t1_pending == 2, "t1 pending", 2, t1_pending);

        let t2_pending = ledger.pending_for_task(t2);
        crate::assert_with_log!(t2_pending == 1, "t2 pending", 1, t2_pending);

        crate::test_complete!("pending_for_task");
    }

    // ---- Region leak check -----------------------------------------------

    #[test]
    fn check_region_leaks_scoped() {
        init_test("check_region_leaks_scoped");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r1 = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r2 = RegionId::from_arena(ArenaIndex::new(1, 0));

        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, r1, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, r2, Time::ZERO);
        ledger.commit(t2, Time::from_nanos(1));

        let r1_result = ledger.check_region_leaks(r1);
        crate::assert_with_log!(
            !r1_result.is_clean(),
            "r1 leaks",
            false,
            r1_result.is_clean()
        );

        let r2_result = ledger.check_region_leaks(r2);
        crate::assert_with_log!(r2_result.is_clean(), "r2 clean", true, r2_result.is_clean());

        crate::test_complete!("check_region_leaks_scoped");
    }

    // ---- Empty ledger is clean -------------------------------------------

    #[test]
    fn empty_ledger_is_clean() {
        init_test("empty_ledger_is_clean");
        let ledger = ObligationLedger::new();
        let result = ledger.check_leaks();
        crate::assert_with_log!(result.is_clean(), "clean", true, result.is_clean());
        crate::assert_with_log!(ledger.is_empty(), "empty", true, ledger.is_empty());
        let len = ledger.len();
        crate::assert_with_log!(len == 0, "len", 0, len);
        crate::test_complete!("empty_ledger_is_clean");
    }

    // ---- Reset -----------------------------------------------------------

    #[test]
    fn reset_clears_everything() {
        init_test("reset_clears_everything");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        ledger.commit(token, Time::from_nanos(1));

        crate::assert_with_log!(ledger.len() == 1, "len before reset", 1, ledger.len());
        ledger.reset();
        crate::assert_with_log!(
            ledger.is_empty(),
            "empty after reset",
            true,
            ledger.is_empty()
        );
        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_acquired == 0,
            "acquired",
            0,
            stats.total_acquired
        );
        crate::test_complete!("reset_clears_everything");
    }

    #[test]
    fn reset_panics_if_pending_obligation_exists() {
        init_test("reset_panics_if_pending_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let stale_id = stale.id();

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 1, "pending preserved", 1, pending);

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == stale_id,
            "stale id tracked",
            stale_id,
            leaks.leaked[0].id
        );

        let region_leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(
            !region_leaks.is_clean(),
            "region leak report still non-clean",
            false,
            region_leaks.is_clean()
        );

        ledger.commit(stale, Time::from_nanos(2));
        crate::test_complete!("reset_panics_if_pending_obligation_exists");
    }

    #[test]
    fn reset_panics_if_leaked_obligation_exists() {
        init_test("reset_panics_if_leaked_obligation_exists");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let leaked = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let leaked_id = leaked.id();
        ledger.mark_leaked(leaked_id, Time::from_nanos(5));

        let reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ledger.reset()));
        crate::assert_with_log!(reset.is_err(), "reset rejected", true, reset.is_err());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending preserved", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_leaked == 1,
            "leaked preserved",
            1,
            stats.total_leaked
        );
        crate::assert_with_log!(
            !stats.is_clean(),
            "still not clean",
            false,
            stats.is_clean()
        );

        let leaks = ledger.check_leaks();
        crate::assert_with_log!(
            !leaks.is_clean(),
            "leak report still non-clean",
            false,
            leaks.is_clean()
        );
        crate::assert_with_log!(leaks.leaked.len() == 1, "leak count", 1, leaks.leaked.len());
        crate::assert_with_log!(
            leaks.leaked[0].id == leaked_id,
            "leaked id tracked",
            leaked_id,
            leaks.leaked[0].id
        );
        crate::test_complete!("reset_panics_if_leaked_obligation_exists");
    }

    #[test]
    fn reset_reuses_index_with_bumped_generation() {
        init_test("reset_reuses_index_with_bumped_generation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let old = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let old_id = old.id();
        let old_idx = old_id.arena_index();
        ledger.commit(old, Time::from_nanos(1));

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(2));
        let fresh_idx = fresh.id().arena_index();
        crate::assert_with_log!(
            fresh.id() != old_id,
            "fresh id differs",
            true,
            fresh.id() != old_id
        );
        crate::assert_with_log!(
            fresh_idx.index() == old_idx.index(),
            "index reused after clean reset",
            old_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() == old_idx.generation().saturating_add(1),
            "generation bumped after clean reset",
            old_idx.generation().saturating_add(1),
            fresh_idx.generation()
        );

        ledger.commit(fresh, Time::from_nanos(3));
        crate::test_complete!("reset_reuses_index_with_bumped_generation");
    }

    #[test]
    fn stale_id_from_previous_generation_cannot_touch_post_reset_obligation() {
        init_test("stale_id_from_previous_generation_cannot_touch_post_reset_obligation");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let stale = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let stale_id = stale.id();
        ledger.abort_by_id(
            stale_id,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        ledger.reset();

        let fresh = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(20));
        let fresh_id = fresh.id();
        let fresh_idx = fresh_id.arena_index();
        let stale_idx = stale_id.arena_index();
        crate::assert_with_log!(
            fresh_idx.index() == stale_idx.index(),
            "slot index reused",
            stale_idx.index(),
            fresh_idx.index()
        );
        crate::assert_with_log!(
            fresh_idx.generation() != stale_idx.generation(),
            "generation differs",
            true,
            fresh_idx.generation() != stale_idx.generation()
        );

        let stale_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(
                stale_id,
                Time::from_nanos(30),
                ObligationAbortReason::Cancel,
            )
        }));
        crate::assert_with_log!(
            stale_abort.is_err(),
            "stale id rejected",
            true,
            stale_abort.is_err()
        );

        let fresh_record = ledger.get(fresh_id).expect("fresh obligation exists");
        crate::assert_with_log!(
            fresh_record.is_pending(),
            "fresh obligation remains pending",
            true,
            fresh_record.is_pending()
        );

        ledger.commit(fresh, Time::from_nanos(40));
        crate::test_complete!(
            "stale_id_from_previous_generation_cannot_touch_post_reset_obligation"
        );
    }

    #[test]
    fn metamorphic_reset_advances_generation_monotonically() {
        init_test("metamorphic_reset_advances_generation_monotonically");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let first = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        let first_idx = first.id().arena_index();
        ledger.commit(first, Time::from_nanos(2));
        ledger.reset();

        let second = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(3),
        );
        let second_idx = second.id().arena_index();
        ledger.commit(second, Time::from_nanos(4));
        ledger.reset();

        let third = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(5),
        );
        let third_idx = third.id().arena_index();
        ledger.commit(third, Time::from_nanos(6));

        crate::assert_with_log!(
            first_idx.index() == second_idx.index(),
            "reset reuses slot after first epoch",
            first_idx.index(),
            second_idx.index()
        );
        crate::assert_with_log!(
            second_idx.index() == third_idx.index(),
            "reset reuses slot after second epoch",
            second_idx.index(),
            third_idx.index()
        );
        crate::assert_with_log!(
            second_idx.generation() == first_idx.generation().saturating_add(1),
            "first reset bumps generation by one",
            first_idx.generation().saturating_add(1),
            second_idx.generation()
        );
        crate::assert_with_log!(
            third_idx.generation() == second_idx.generation().saturating_add(1),
            "second reset bumps generation by one",
            second_idx.generation().saturating_add(1),
            third_idx.generation()
        );

        crate::test_complete!("metamorphic_reset_advances_generation_monotonically");
    }

    #[test]
    fn metamorphic_post_reset_commit_matches_fresh_epoch_observables() {
        init_test("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
        let task = make_task();
        let region = make_region();

        let mut fresh = ObligationLedger::new();
        let fresh_token = fresh.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let fresh_idx = fresh_token.id().arena_index();
        fresh.commit(fresh_token, Time::from_nanos(20));
        let fresh_observation = observe_ledger(&fresh, task, region);

        let mut recycled = ObligationLedger::new();
        let old = recycled.acquire(ObligationKind::Lease, task, region, Time::from_nanos(1));
        recycled.abort(old, Time::from_nanos(2), ObligationAbortReason::Cancel);
        recycled.reset();

        let recycled_token =
            recycled.acquire(ObligationKind::Ack, task, region, Time::from_nanos(10));
        let recycled_idx = recycled_token.id().arena_index();
        recycled.commit(recycled_token, Time::from_nanos(20));
        let recycled_observation = observe_ledger(&recycled, task, region);

        crate::assert_with_log!(
            fresh_observation == recycled_observation,
            "post-reset epoch observables match fresh epoch",
            fresh_observation,
            recycled_observation
        );
        crate::assert_with_log!(
            recycled_idx.index() == fresh_idx.index(),
            "post-reset epoch rewinds slot allocation",
            fresh_idx.index(),
            recycled_idx.index()
        );
        crate::assert_with_log!(
            recycled_idx.generation() == fresh_idx.generation().saturating_add(1),
            "post-reset epoch bumps generation",
            fresh_idx.generation().saturating_add(1),
            recycled_idx.generation()
        );

        crate::test_complete!("metamorphic_post_reset_commit_matches_fresh_epoch_observables");
    }

    #[test]
    fn metamorphic_failed_reset_then_commit_matches_commit_then_reset() {
        init_test("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
        let task = make_task();
        let region = make_region();

        let mut raced = ObligationLedger::new();
        let raced_token = raced.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );

        let early_reset = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| raced.reset()));
        crate::assert_with_log!(
            early_reset.is_err(),
            "early reset rejected",
            true,
            early_reset.is_err()
        );

        raced.commit(raced_token, Time::from_nanos(110));
        raced.reset();
        let raced_post_reset =
            raced.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let raced_idx = raced_post_reset.id().arena_index();
        raced.commit(raced_post_reset, Time::from_nanos(130));
        let raced_observation = observe_ledger(&raced, task, region);

        let mut canonical = ObligationLedger::new();
        let canonical_token = canonical.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(100),
        );
        canonical.commit(canonical_token, Time::from_nanos(110));
        canonical.reset();
        let canonical_post_reset =
            canonical.acquire(ObligationKind::Ack, task, region, Time::from_nanos(120));
        let canonical_idx = canonical_post_reset.id().arena_index();
        canonical.commit(canonical_post_reset, Time::from_nanos(130));
        let canonical_observation = observe_ledger(&canonical, task, region);

        crate::assert_with_log!(
            raced_observation == canonical_observation,
            "failed reset leaves eventual epoch observables unchanged",
            canonical_observation,
            raced_observation
        );
        crate::assert_with_log!(
            raced_idx == canonical_idx,
            "failed reset does not advance generation or slot allocation",
            canonical_idx,
            raced_idx
        );

        crate::test_complete!("metamorphic_failed_reset_then_commit_matches_commit_then_reset");
    }

    // ---- Deterministic iteration -----------------------------------------

    #[test]
    fn iteration_is_deterministic() {
        init_test("iteration_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire multiple obligations.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        // Iteration order should be by ID (BTreeMap).
        let ids: Vec<ObligationId> = ledger.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(ids.len() == 3, "len", 3, ids.len());
        // IDs are monotonically increasing since we allocate sequentially.
        crate::assert_with_log!(ids[0] == t1.id(), "first", t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == t2.id(), "second", t2.id(), ids[1]);
        crate::assert_with_log!(ids[2] == t3.id(), "third", t3.id(), ids[2]);
        crate::test_complete!("iteration_is_deterministic");
    }

    // ---- Get by ID -------------------------------------------------------

    #[test]
    fn get_by_id() {
        init_test("get_by_id");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::IoOp, task, region, Time::from_nanos(42));
        let id = token.id();

        let record = ledger.get(id).expect("should exist");
        crate::assert_with_log!(
            record.kind == ObligationKind::IoOp,
            "kind",
            ObligationKind::IoOp,
            record.kind
        );
        crate::assert_with_log!(record.is_pending(), "pending", true, record.is_pending());

        ledger.commit(token, Time::from_nanos(50));
        let record = ledger.get(id).expect("still exists");
        crate::assert_with_log!(!record.is_pending(), "resolved", false, record.is_pending());
        crate::test_complete!("get_by_id");
    }

    // ---- Acquire with description ----------------------------------------

    #[test]
    fn acquire_with_context_captures_description() {
        init_test("acquire_with_context_captures_description");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire_with_context(
            ObligationKind::Lease,
            task,
            region,
            Time::ZERO,
            SourceLocation::unknown(),
            None,
            Some("my lease description".to_string()),
        );
        let id = token.id();

        let record = ledger.get(id).expect("exists");
        crate::assert_with_log!(
            record.description == Some("my lease description".to_string()),
            "description",
            Some("my lease description".to_string()),
            record.description
        );

        ledger.commit(token, Time::from_nanos(1));
        crate::test_complete!("acquire_with_context_captures_description");
    }

    // ---- Multiple kinds in one ledger ------------------------------------

    #[test]
    fn multiple_obligation_kinds() {
        init_test("multiple_obligation_kinds");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let t_send = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t_ack = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t_lease = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t_io = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        let pending = ledger.pending_count();
        crate::assert_with_log!(pending == 4, "pending", 4, pending);

        ledger.commit(t_send, Time::from_nanos(1));
        ledger.abort(t_ack, Time::from_nanos(1), ObligationAbortReason::Cancel);
        ledger.commit(t_lease, Time::from_nanos(1));
        ledger.abort(t_io, Time::from_nanos(1), ObligationAbortReason::Error);

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 2,
            "committed",
            2,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 2, "aborted", 2, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("multiple_obligation_kinds");
    }

    // ---- Cancel drain: abort all pending obligations for a region --------

    #[test]
    fn cancel_drain_aborts_all_region_obligations() {
        init_test("cancel_drain_aborts_all_region_obligations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Simulate: task holds three obligations when cancel is requested.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        let pending = ledger.pending_for_region(region);
        crate::assert_with_log!(pending == 3, "pre-drain pending", 3, pending);

        // Drain: enumerate pending IDs and abort each one.
        let drain_time = Time::from_nanos(100);
        let pending_ids = ledger.pending_ids_for_region(region);
        crate::assert_with_log!(pending_ids.len() == 3, "drain ids", 3, pending_ids.len());

        for id in &pending_ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        // Region should now be clean.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean after drain", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "global pending", 0, stats.pending);
        crate::assert_with_log!(
            stats.total_aborted == 3,
            "aborted count",
            3,
            stats.total_aborted
        );
        crate::assert_with_log!(
            stats.total_leaked == 0,
            "leaked count",
            0,
            stats.total_leaked
        );
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_aborts_all_region_obligations");
    }

    // ---- Cancel drain: multi-task region --------------------------------

    #[test]
    fn cancel_drain_multi_task_region() {
        init_test("cancel_drain_multi_task_region");
        let mut ledger = ObligationLedger::new();
        let t1 = TaskId::from_arena(ArenaIndex::new(0, 0));
        let t2 = TaskId::from_arena(ArenaIndex::new(1, 0));
        let t3 = TaskId::from_arena(ArenaIndex::new(2, 0));
        let region = make_region();

        // Three tasks in the same region, each with an obligation.
        let tok1 = ledger.acquire(ObligationKind::SendPermit, t1, region, Time::ZERO);
        let tok2 = ledger.acquire(ObligationKind::Ack, t2, region, Time::ZERO);
        let tok3 = ledger.acquire(ObligationKind::Lease, t3, region, Time::ZERO);

        // During drain, abort all obligations in the region.
        let drain_time = Time::from_nanos(50);
        ledger.abort(tok1, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok2, drain_time, ObligationAbortReason::Cancel);
        ledger.abort(tok3, drain_time, ObligationAbortReason::Cancel);

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "region clean", true, is_clean);

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.is_clean(), "ledger clean", true, stats.is_clean());
        crate::test_complete!("cancel_drain_multi_task_region");
    }

    // ---- Region isolation: drain one region, other unaffected -----------

    #[test]
    fn region_isolation_during_drain() {
        init_test("region_isolation_during_drain");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let r_cancel = RegionId::from_arena(ArenaIndex::new(0, 0));
        let r_alive = RegionId::from_arena(ArenaIndex::new(1, 0));

        // Obligations in region being cancelled.
        let tok_cancel = ledger.acquire(ObligationKind::SendPermit, task, r_cancel, Time::ZERO);
        // Obligations in region that is still alive.
        let _tok_alive = ledger.acquire(ObligationKind::Ack, task, r_alive, Time::ZERO);

        // Drain only the cancelled region.
        ledger.abort(
            tok_cancel,
            Time::from_nanos(10),
            ObligationAbortReason::Cancel,
        );

        // Cancelled region is clean.
        let cancel_clean = ledger.is_region_clean(r_cancel);
        crate::assert_with_log!(cancel_clean, "cancelled region clean", true, cancel_clean);

        // Alive region still has its obligation.
        let alive_pending = ledger.pending_for_region(r_alive);
        crate::assert_with_log!(alive_pending == 1, "alive region pending", 1, alive_pending);

        // Global ledger still has a pending obligation.
        let global_pending = ledger.pending_count();
        crate::assert_with_log!(global_pending == 1, "global pending", 1, global_pending);
        crate::test_complete!("region_isolation_during_drain");
    }

    // ---- Deterministic drain ordering -----------------------------------

    #[test]
    fn drain_ordering_is_deterministic() {
        init_test("drain_ordering_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire obligations in a known order.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(2));

        // IDs should be monotonically increasing (BTreeMap).
        let ids = ledger.pending_ids_for_region(region);
        for window in ids.windows(2) {
            crate::assert_with_log!(window[0] < window[1], "monotonic ids", true, true);
        }

        // Drain in the deterministic order returned by pending_ids_for_region.
        let drain_time = Time::from_nanos(100);
        for id in &ids {
            ledger.abort_by_id(*id, drain_time, ObligationAbortReason::Cancel);
        }

        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "clean after ordered drain", true, is_clean);
        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 3, "aborted", 3, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::test_complete!("drain_ordering_is_deterministic");
    }

    // ---- Quiescence: region clean implies zero pending obligations ------

    #[test]
    fn region_quiescence_after_mixed_resolution() {
        init_test("region_quiescence_after_mixed_resolution");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire four obligations of different kinds.
        let t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let t4 = ledger.acquire(ObligationKind::IoOp, task, region, Time::ZERO);

        // Resolve them via different paths (commit, abort, cancel-abort).
        ledger.commit(t1, Time::from_nanos(10));
        ledger.abort(t2, Time::from_nanos(20), ObligationAbortReason::Explicit);
        ledger.abort(t3, Time::from_nanos(30), ObligationAbortReason::Cancel);
        ledger.commit(t4, Time::from_nanos(40));

        // Region should be clean regardless of resolution path.
        let is_clean = ledger.is_region_clean(region);
        crate::assert_with_log!(is_clean, "quiescent", true, is_clean);

        let leaks = ledger.check_region_leaks(region);
        crate::assert_with_log!(leaks.is_clean(), "no leaks", true, leaks.is_clean());

        let stats = ledger.stats();
        crate::assert_with_log!(stats.pending == 0, "pending zero", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "stats clean", true, stats.is_clean());
        crate::test_complete!("region_quiescence_after_mixed_resolution");
    }

    // ---- Abort reason preserved -----------------------------------------

    #[test]
    fn abort_reason_preserved_in_record() {
        init_test("abort_reason_preserved_in_record");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        ledger.abort(token, Time::from_nanos(10), ObligationAbortReason::Cancel);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );
        crate::test_complete!("abort_reason_preserved_in_record");
    }

    #[test]
    fn forged_token_metadata_panics_without_mutating_ledger() {
        init_test("forged_token_metadata_panics_without_mutating_ledger");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();
        let forged = ObligationToken {
            id,
            kind: ObligationKind::Ack,
            holder: task,
            region,
        };

        let commit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(forged, Time::from_nanos(10));
        }));
        crate::assert_with_log!(
            commit.is_err(),
            "forged token rejected",
            true,
            commit.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Reserved,
            "state unchanged",
            ObligationState::Reserved,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(
            stats.total_committed == 0,
            "committed",
            0,
            stats.total_committed
        );
        crate::assert_with_log!(stats.total_aborted == 0, "aborted", 0, stats.total_aborted);
        crate::assert_with_log!(stats.pending == 1, "pending", 1, stats.pending);
        crate::test_complete!("forged_token_metadata_panics_without_mutating_ledger");
    }

    #[test]
    fn abort_by_id_double_resolve_panics_without_pending_underflow() {
        init_test("abort_by_id_double_resolve_panics_without_pending_underflow");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let second_abort = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, Time::from_nanos(30), ObligationAbortReason::Cancel);
        }));
        crate::assert_with_log!(
            second_abort.is_err(),
            "double resolve rejected",
            true,
            second_abort.is_err()
        );

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state remains aborted",
            ObligationState::Aborted,
            record.state
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("abort_by_id_double_resolve_panics_without_pending_underflow");
    }

    #[test]
    fn abort_by_id_supports_cancel_drain_without_leak_accounting() {
        init_test("abort_by_id_supports_cancel_drain_without_leak_accounting");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort_by_id(id, Time::from_nanos(25), ObligationAbortReason::Cancel);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let record = ledger.get(id).expect("record exists");
        crate::assert_with_log!(
            record.state == ObligationState::Aborted,
            "state aborted",
            ObligationState::Aborted,
            record.state
        );
        crate::assert_with_log!(
            record.abort_reason == Some(ObligationAbortReason::Cancel),
            "abort reason",
            Some(ObligationAbortReason::Cancel),
            record.abort_reason
        );

        let stats = ledger.stats();
        crate::assert_with_log!(stats.total_aborted == 1, "aborted", 1, stats.total_aborted);
        crate::assert_with_log!(stats.total_leaked == 0, "leaked", 0, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::assert_with_log!(stats.is_clean(), "clean", true, stats.is_clean());
        crate::test_complete!("abort_by_id_supports_cancel_drain_without_leak_accounting");
    }

    fn observable_resolution_state(
        ledger: &ObligationLedger,
        id: ObligationId,
    ) -> (
        ObligationId,
        ObligationKind,
        TaskId,
        RegionId,
        Time,
        ObligationState,
        Option<Time>,
        Option<ObligationAbortReason>,
        LedgerStats,
    ) {
        let record = ledger.get(id).expect("record exists");
        (
            record.id,
            record.kind,
            record.holder,
            record.region,
            record.reserved_at,
            record.state,
            record.resolved_at,
            record.abort_reason,
            ledger.stats(),
        )
    }

    #[test]
    fn commit_once_and_replayed_commit_attempts_preserve_observable_state() {
        init_test("commit_once_and_replayed_commit_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(25));
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.commit(
                    ObligationToken {
                        id,
                        kind: ObligationKind::Lease,
                        holder: task,
                        region,
                    },
                    now,
                );
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("commit_once_and_replayed_commit_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_once_and_replayed_abort_attempts_preserve_observable_state() {
        init_test("abort_once_and_replayed_abort_attempts_preserve_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.abort(token, Time::from_nanos(25), ObligationAbortReason::Explicit);
        crate::assert_with_log!(duration == 25, "duration", 25, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(26),
            Time::from_nanos(40),
            Time::from_nanos(100),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "replayed abort rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "observable state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_once_and_replayed_abort_attempts_preserve_observable_state");
    }

    #[test]
    fn abort_after_commit_replay_preserves_committed_observable_state() {
        init_test("abort_after_commit_replay_preserves_committed_observable_state");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        let token = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let id = token.id();

        let duration = ledger.commit(token, Time::from_nanos(50));
        crate::assert_with_log!(duration == 50, "duration", 50, duration);

        let expected = observable_resolution_state(&ledger, id);
        for now in [
            Time::from_nanos(51),
            Time::from_nanos(60),
            Time::from_nanos(75),
        ] {
            let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ledger.abort_by_id(id, now, ObligationAbortReason::Cancel);
            }));
            crate::assert_with_log!(
                replay.is_err(),
                "abort after commit rejected",
                true,
                replay.is_err()
            );
            crate::assert_with_log!(
                observable_resolution_state(&ledger, id) == expected,
                "committed state preserved",
                expected,
                observable_resolution_state(&ledger, id)
            );
        }

        crate::test_complete!("abort_after_commit_replay_preserves_committed_observable_state");
    }

    fn replay_commit_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.commit(
                ObligationToken {
                    id,
                    kind,
                    holder,
                    region,
                },
                now,
            );
        }))
        .is_err()
    }

    fn replay_abort_attempt(
        ledger: &mut ObligationLedger,
        id: ObligationId,
        now: Time,
        reason: ObligationAbortReason,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.abort_by_id(id, now, reason);
        }))
        .is_err()
    }

    #[test]
    fn metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables() {
        init_test(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables",
        );
        let task = make_task();
        let region = make_region();

        let mut commit_then_abort = ObligationLedger::new();
        let token = commit_then_abort.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        commit_then_abort.commit(token, Time::from_nanos(10));
        let committed_expected = observable_resolution_state(&commit_then_abort, id);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(11),
            ),
            replay_abort_attempt(
                &mut commit_then_abort,
                id,
                Time::from_nanos(12),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut commit_then_abort,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(13),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_then_abort, id) == committed_expected,
                "commit-first observable state preserved",
                committed_expected,
                observable_resolution_state(&commit_then_abort, id)
            );
        }

        let mut abort_then_commit = ObligationLedger::new();
        let token = abort_then_commit.acquire(ObligationKind::Lease, task, region, Time::ZERO);
        let id = token.id();
        abort_then_commit.commit(token, Time::from_nanos(10));
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(11),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_then_commit,
                id,
                ObligationKind::Lease,
                task,
                region,
                Time::from_nanos(12),
            ),
            replay_abort_attempt(
                &mut abort_then_commit,
                id,
                Time::from_nanos(13),
                ObligationAbortReason::Explicit,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort-first replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_then_commit, id) == committed_expected,
                "abort-first observable state preserved",
                committed_expected,
                observable_resolution_state(&abort_then_commit, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&commit_then_abort, id)
                == observable_resolution_state(&abort_then_commit, id),
            "committed replay schedules converge",
            observable_resolution_state(&commit_then_abort, id),
            observable_resolution_state(&abort_then_commit, id)
        );

        let mut abort_only_then_commit = ObligationLedger::new();
        let token = abort_only_then_commit.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        abort_only_then_commit.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        let aborted_expected = observable_resolution_state(&abort_only_then_commit, id);
        for (idx, rejected) in [
            replay_abort_attempt(
                &mut abort_only_then_commit,
                id,
                Time::from_nanos(21),
                ObligationAbortReason::Cancel,
            ),
            replay_commit_attempt(
                &mut abort_only_then_commit,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(22),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "abort terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&abort_only_then_commit, id) == aborted_expected,
                "abort terminal state preserved",
                aborted_expected,
                observable_resolution_state(&abort_only_then_commit, id)
            );
        }

        let mut commit_only_then_abort = ObligationLedger::new();
        let token = commit_only_then_abort.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let id = token.id();
        commit_only_then_abort.abort(token, Time::from_nanos(20), ObligationAbortReason::Explicit);
        for (idx, rejected) in [
            replay_commit_attempt(
                &mut commit_only_then_abort,
                id,
                ObligationKind::Ack,
                task,
                region,
                Time::from_nanos(21),
            ),
            replay_abort_attempt(
                &mut commit_only_then_abort,
                id,
                Time::from_nanos(22),
                ObligationAbortReason::Error,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            crate::assert_with_log!(rejected, "commit terminal replay rejected", idx, rejected);
            crate::assert_with_log!(
                observable_resolution_state(&commit_only_then_abort, id) == aborted_expected,
                "commit terminal state preserved",
                aborted_expected,
                observable_resolution_state(&commit_only_then_abort, id)
            );
        }

        crate::assert_with_log!(
            observable_resolution_state(&abort_only_then_commit, id)
                == observable_resolution_state(&commit_only_then_abort, id),
            "aborted replay schedules converge",
            observable_resolution_state(&abort_only_then_commit, id),
            observable_resolution_state(&commit_only_then_abort, id)
        );

        crate::test_complete!(
            "metamorphic_commit_and_abort_replay_schedules_converge_on_same_terminal_observables"
        );
    }

    // =========================================================================
    // Wave 55 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn ledger_stats_debug_clone_copy_eq_default() {
        let stats = LedgerStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("LedgerStats"), "{dbg}");
        let copied = stats;
        let cloned = stats;
        assert_eq!(copied, cloned);
        assert_eq!(stats.total_acquired, 0);
        assert!(stats.is_clean());
    }

    #[test]
    fn leak_check_result_debug_clone() {
        let result = LeakCheckResult { leaked: vec![] };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("LeakCheckResult"), "{dbg}");
        let cloned = result;
        assert!(cloned.is_clean());
    }

    // =========================================================================
    // Conservation-of-acquired metamorphic relation
    //
    // For any sequence of ledger operations, the invariant
    //
    //     total_acquired == total_committed + total_aborted + total_leaked + pending
    //
    // must hold. This catches off-by-one and miscategorization bugs across
    // acquire / commit / abort / abort_by_id / mark_leaked / reset paths
    // without needing an oracle for the expected pending count after a
    // mixed-operation sequence.
    // =========================================================================

    #[track_caller]
    fn assert_conservation(ledger: &ObligationLedger, step: &str) {
        let s = ledger.stats();
        let rhs = s.total_committed + s.total_aborted + s.total_leaked + s.pending;
        assert_eq!(
            s.total_acquired, rhs,
            "conservation violated after {step}: \
             acquired={} vs committed({})+aborted({})+leaked({})+pending({}) = {}",
            s.total_acquired, s.total_committed, s.total_aborted, s.total_leaked, s.pending, rhs,
        );
    }

    #[test]
    fn metamorphic_conservation_of_acquired_across_mixed_operations() {
        init_test("metamorphic_conservation_of_acquired_across_mixed_operations");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        assert_conservation(&ledger, "initial");

        // ---- Pre-reset phase: exercise all token-consuming + by-id paths ----

        let t1 = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(1),
        );
        assert_conservation(&ledger, "acquire t1");

        let t2 = ledger.acquire_with_context(
            ObligationKind::Ack,
            task,
            region,
            Time::from_nanos(2),
            SourceLocation::unknown(),
            None,
            Some("ctx".to_string()),
        );
        assert_conservation(&ledger, "acquire_with_context t2");

        let t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::from_nanos(3));
        assert_conservation(&ledger, "acquire t3");

        let t3_id = t3.id();
        let pre_reset_acquired = ledger.stats().total_acquired;
        assert_eq!(pre_reset_acquired, 3);

        ledger.commit(t1, Time::from_nanos(10));
        assert_conservation(&ledger, "commit t1");

        ledger.abort(t2, Time::from_nanos(11), ObligationAbortReason::Cancel);
        assert_conservation(&ledger, "abort t2");

        // By-id resolution after original token has been dropped.
        drop(t3);
        ledger.abort_by_id(t3_id, Time::from_nanos(12), ObligationAbortReason::Explicit);
        assert_conservation(&ledger, "abort_by_id t3");

        let pre_reset = ledger.stats();
        assert_eq!(pre_reset.pending, 0);
        assert!(pre_reset.is_clean());
        assert_eq!(
            pre_reset.total_acquired,
            pre_reset.total_committed + pre_reset.total_aborted + pre_reset.total_leaked,
            "fully-resolved ledger satisfies conservation trivially with pending=0",
        );

        // ---- Reset midstream: counters zero, conservation holds trivially ----

        ledger.reset();
        assert_conservation(&ledger, "reset");
        let post_reset = ledger.stats();
        assert_eq!(post_reset, LedgerStats::default());

        // ---- Post-reset phase: re-acquire, include mark_leaked path ----

        let t4 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        assert_conservation(&ledger, "post-reset acquire t4");

        let t5 = ledger.acquire(ObligationKind::Ack, task, region, Time::from_nanos(1));
        assert_conservation(&ledger, "post-reset acquire t5");

        ledger.commit(t4, Time::from_nanos(5));
        assert_conservation(&ledger, "post-reset commit t4");

        let t5_id = t5.id();
        drop(t5);
        ledger.mark_leaked(t5_id, Time::from_nanos(6));
        assert_conservation(&ledger, "mark_leaked t5");

        let final_stats = ledger.stats();
        assert_eq!(final_stats.total_acquired, 2);
        assert_eq!(final_stats.total_committed, 1);
        assert_eq!(final_stats.total_aborted, 0);
        assert_eq!(final_stats.total_leaked, 1);
        assert_eq!(final_stats.pending, 0);
        assert!(
            !final_stats.is_clean(),
            "leaked obligation keeps ledger dirty"
        );
        assert_eq!(ledger.check_leaks().leaked.len(), 1);

        crate::test_complete!("metamorphic_conservation_of_acquired_across_mixed_operations");
    }

    // --- Metamorphic: conservation-of-acquired ------------------------------
    //
    // MR (conservation / flow invariant):
    //   stats.total_acquired
    //     == stats.total_committed
    //      + stats.total_aborted
    //      + stats.total_leaked
    //      + stats.pending
    //
    // Every acquired obligation is in exactly one of four terminal buckets —
    // committed, aborted, leaked, or still pending — so the sum of those
    // four counters must equal the running total of acquisitions at every
    // observable point. reset() zeros all five fields simultaneously, so
    // the equation stays 0 == 0 across the epoch boundary and can be driven
    // to hold again in the new epoch.
    //
    // Bug classes caught:
    //   * miscounted acquire/commit/abort/abort_by_id/mark_leaked paths
    //     (off-by-one, skipped increment, double increment)
    //   * mis-routing between terminal buckets (e.g. mark_leaked bumping
    //     total_aborted instead of total_leaked)
    //   * pending not decremented on a resolution path
    //   * reset() leaving one of the five fields non-zero
    //
    // Independence: orthogonal to region-partition, permutation-invariance,
    // and reset-generation MRs already in this module — those check
    // geometric or temporal relations, this one checks flow conservation.
    #[test]
    fn metamorphic_conservation_acquired_equals_resolved_plus_pending() {
        init_test("metamorphic_conservation_acquired_equals_resolved_plus_pending");
        let task = make_task();
        let region = make_region();

        fn check_conservation(ledger: &ObligationLedger, step: &str) {
            let s = ledger.stats();
            let resolved_plus_pending = s
                .total_committed
                .saturating_add(s.total_aborted)
                .saturating_add(s.total_leaked)
                .saturating_add(s.pending);
            assert_eq!(
                s.total_acquired,
                resolved_plus_pending,
                "conservation violated at {step}: \
                 total_acquired={} vs committed+aborted+leaked+pending={} \
                 (committed={}, aborted={}, leaked={}, pending={})",
                s.total_acquired,
                resolved_plus_pending,
                s.total_committed,
                s.total_aborted,
                s.total_leaked,
                s.pending
            );
        }

        let mut ledger = ObligationLedger::new();
        check_conservation(&ledger, "empty");

        // Phase 1: staggered acquisitions — conservation must hold after each.
        let mut live_tokens: Vec<ObligationToken> = Vec::new();
        for i in 0..6 {
            let kind = match i % 3 {
                0 => ObligationKind::SendPermit,
                1 => ObligationKind::Ack,
                _ => ObligationKind::Lease,
            };
            let tok = ledger.acquire(kind, task, region, Time::from_nanos(10 + i));
            live_tokens.push(tok);
            check_conservation(&ledger, "phase1.acquire");
        }
        assert_eq!(ledger.stats().total_acquired, 6);
        assert_eq!(ledger.stats().pending, 6);

        // Phase 2: mixed terminal resolutions across all four paths —
        // commit via token, abort via token, abort_by_id via id,
        // and mark_leaked via id. Conservation must hold after each.
        let tok_commit = live_tokens.remove(0);
        ledger.commit(tok_commit, Time::from_nanos(100));
        check_conservation(&ledger, "phase2.commit");

        let tok_abort = live_tokens.remove(0);
        ledger.abort(
            tok_abort,
            Time::from_nanos(110),
            ObligationAbortReason::Cancel,
        );
        check_conservation(&ledger, "phase2.abort");

        let tok_abort_by_id = live_tokens.remove(0);
        let id_for_abort_by_id = tok_abort_by_id.id();
        // Drop the token so only the ID path resolves the obligation.
        drop(tok_abort_by_id);
        ledger.abort_by_id(
            id_for_abort_by_id,
            Time::from_nanos(120),
            ObligationAbortReason::Error,
        );
        check_conservation(&ledger, "phase2.abort_by_id");

        let tok_leak = live_tokens.remove(0);
        let id_for_leak = tok_leak.id();
        drop(tok_leak);
        ledger.mark_leaked(id_for_leak, Time::from_nanos(130));
        check_conservation(&ledger, "phase2.mark_leaked");

        // Two obligations remain pending — conservation must still balance.
        assert_eq!(ledger.stats().pending, 2);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().total_aborted, 2);
        assert_eq!(ledger.stats().total_leaked, 1);

        // Phase 3: reset zeros all five counters simultaneously. Conservation
        // must hold trivially (0 == 0) and the ledger must be clean.
        ledger.reset();
        check_conservation(&ledger, "phase3.reset");
        assert_eq!(ledger.stats().total_acquired, 0);
        assert!(ledger.stats().is_clean());

        // Phase 4: re-acquire after reset and resolve one to confirm the
        // invariant tracks across the epoch boundary (the token held across
        // reset has been invalidated by the generation bump; any attempt to
        // commit it would panic — see metamorphic_post_reset_* tests).
        let post_reset = ledger.acquire(
            ObligationKind::SendPermit,
            task,
            region,
            Time::from_nanos(200),
        );
        check_conservation(&ledger, "phase4.post_reset_acquire");
        ledger.commit(post_reset, Time::from_nanos(210));
        check_conservation(&ledger, "phase4.post_reset_commit");
        assert_eq!(ledger.stats().total_acquired, 1);
        assert_eq!(ledger.stats().total_committed, 1);
        assert_eq!(ledger.stats().pending, 0);

        crate::test_complete!("metamorphic_conservation_acquired_equals_resolved_plus_pending");
    }
}
