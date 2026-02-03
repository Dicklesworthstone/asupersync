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
    /// Next generation counter for ID allocation.
    next_gen: u32,
    /// Running statistics.
    stats: LedgerStats,
}

impl Default for ObligationLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ObligationLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
            next_gen: 0,
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
        let gen = self.next_gen;
        self.next_gen += 1;
        let idx = ArenaIndex::new(gen, 0);
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
        let record = self
            .obligations
            .get_mut(&token.id)
            .expect("obligation not found in ledger");
        let duration = record.commit(now);
        self.stats.total_committed += 1;
        self.stats.pending -= 1;
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
        let record = self
            .obligations
            .get_mut(&token.id)
            .expect("obligation not found in ledger");
        let duration = record.abort(now, reason);
        self.stats.total_aborted += 1;
        self.stats.pending -= 1;
        duration
    }

    /// Marks an obligation as leaked (runtime detected the holder completed
    /// without resolving).
    ///
    /// # Panics
    ///
    /// Panics if the obligation was already resolved or does not exist.
    pub fn mark_leaked(&mut self, id: ObligationId, now: Time) -> u64 {
        let record = self
            .obligations
            .get_mut(&id)
            .expect("obligation not found in ledger");
        let duration = record.mark_leaked(now);
        self.stats.total_leaked += 1;
        self.stats.pending -= 1;
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

    /// Returns IDs of all pending obligations for a region (for cancellation drain).
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
            .filter(|(_, o)| o.state == ObligationState::Reserved)
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
            .filter(|(_, o)| o.region == region && o.state == ObligationState::Reserved)
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
    pub fn reset(&mut self) {
        self.obligations.clear();
        self.next_gen = 0;
        self.stats = LedgerStats::default();
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
        // Intentionally not resolving — simulate dropping the token.
        std::mem::forget(_token);

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

        // Clean up to avoid leak panic.
        std::mem::forget(_t1);
        std::mem::forget(_t2);
        std::mem::forget(_t3);
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

        std::mem::forget(t1);
        std::mem::forget(t2);
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
        std::mem::forget(token); // Simulate lost token.

        ledger.mark_leaked(id, Time::from_nanos(100));

        let stats = ledger.stats();
        crate::assert_with_log!(!stats.is_clean(), "not clean", false, stats.is_clean());
        crate::assert_with_log!(stats.total_leaked == 1, "leaked", 1, stats.total_leaked);
        crate::assert_with_log!(stats.pending == 0, "pending", 0, stats.pending);
        crate::test_complete!("mark_leaked_updates_stats");
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

        std::mem::forget(_tok1);
        std::mem::forget(_tok2);
        std::mem::forget(_tok3);
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

        std::mem::forget(_t1);
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
        crate::assert_with_log!(ledger.len() == 0, "len", 0, ledger.len());
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

    // ---- Deterministic iteration -----------------------------------------

    #[test]
    fn iteration_is_deterministic() {
        init_test("iteration_is_deterministic");
        let mut ledger = ObligationLedger::new();
        let task = make_task();
        let region = make_region();

        // Acquire multiple obligations.
        let _t1 = ledger.acquire(ObligationKind::SendPermit, task, region, Time::ZERO);
        let _t2 = ledger.acquire(ObligationKind::Ack, task, region, Time::ZERO);
        let _t3 = ledger.acquire(ObligationKind::Lease, task, region, Time::ZERO);

        // Iteration order should be by ID (BTreeMap).
        let ids: Vec<ObligationId> = ledger.iter().map(|(id, _)| *id).collect();
        crate::assert_with_log!(ids.len() == 3, "len", 3, ids.len());
        // IDs are monotonically increasing since we allocate sequentially.
        crate::assert_with_log!(ids[0] == _t1.id(), "first", _t1.id(), ids[0]);
        crate::assert_with_log!(ids[1] == _t2.id(), "second", _t2.id(), ids[1]);
        crate::assert_with_log!(ids[2] == _t3.id(), "third", _t3.id(), ids[2]);

        std::mem::forget(_t1);
        std::mem::forget(_t2);
        std::mem::forget(_t3);
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
}
