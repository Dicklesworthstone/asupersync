//! Symbol obligation integration with the core obligation tracking system.
//!
//! Bridges the RaptorQ symbol layer with the runtime's existing two-phase
//! obligation protocol ([`ObligationRecord`]). Provides epoch-aware validity
//! windows, deadline-based expiry, and RAII guards for automatic resolution.

use std::collections::HashMap;

use crate::record::obligation::{
    ObligationAbortReason, ObligationKind, ObligationRecord, ObligationState,
};
use crate::types::symbol::{ObjectId, SymbolId};
use crate::types::{ObligationId, RegionId, TaskId, Time};

// ============================================================================
// EpochId and EpochWindow
// ============================================================================

/// Identifier for an epoch in the distributed system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochId(pub u64);

/// Window of epochs during which an obligation is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochWindow {
    /// Starting epoch (inclusive).
    pub start: EpochId,
    /// Ending epoch (inclusive).
    pub end: EpochId,
}

// ============================================================================
// SymbolObligationKind
// ============================================================================

/// Extended obligation kinds for symbol operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolObligationKind {
    /// Obligation to transmit a symbol to a destination.
    /// Committed when acknowledged, aborted on timeout/failure.
    SymbolTransmit {
        /// The symbol being transmitted.
        symbol_id: SymbolId,
        /// Destination region.
        destination: RegionId,
    },

    /// Obligation to acknowledge receipt of a symbol.
    /// Must be committed before region close.
    SymbolAck {
        /// The symbol being acknowledged.
        symbol_id: SymbolId,
        /// Source region.
        source: RegionId,
    },

    /// Obligation representing a decoding operation in progress.
    /// Committed when object is fully decoded.
    DecodingInProgress {
        /// Object being decoded.
        object_id: ObjectId,
        /// Symbols received so far.
        symbols_received: u32,
        /// Total symbols needed.
        symbols_needed: u32,
    },

    /// Obligation for holding an encoding session open.
    /// Must be resolved before session resources are released.
    EncodingSession {
        /// Object being encoded.
        object_id: ObjectId,
        /// Symbols encoded so far.
        symbols_encoded: u32,
    },

    /// Lease obligation for remote resource access.
    /// Must be renewed or released before expiry.
    SymbolLease {
        /// The leased object.
        object_id: ObjectId,
        /// When the lease expires.
        lease_expires: Time,
    },
}

// ============================================================================
// SymbolObligation
// ============================================================================

/// A symbol obligation that wraps the core [`ObligationRecord`] with
/// symbol-specific metadata.
///
/// Bridges between the distributed symbol layer and the runtime's existing
/// two-phase obligation protocol.
#[derive(Debug)]
pub struct SymbolObligation {
    /// The underlying obligation record.
    inner: ObligationRecord,
    /// Symbol-specific obligation details.
    kind: SymbolObligationKind,
    /// The epoch window during which this obligation is valid.
    /// None means valid for any epoch (local-only obligation).
    valid_epoch: Option<EpochWindow>,
    /// Optional deadline for automatic abort if not resolved.
    deadline: Option<Time>,
}

impl SymbolObligation {
    /// Creates a new symbol transmit obligation.
    #[must_use]
    pub fn transmit(
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
        symbol_id: SymbolId,
        destination: RegionId,
        deadline: Option<Time>,
        epoch_window: Option<EpochWindow>,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::IoOp, holder, region, Time::ZERO),
            kind: SymbolObligationKind::SymbolTransmit {
                symbol_id,
                destination,
            },
            valid_epoch: epoch_window,
            deadline,
        }
    }

    /// Creates a new symbol acknowledgment obligation.
    #[must_use]
    pub fn ack(
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
        symbol_id: SymbolId,
        source: RegionId,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::Ack, holder, region, Time::ZERO),
            kind: SymbolObligationKind::SymbolAck { symbol_id, source },
            valid_epoch: None,
            deadline: None,
        }
    }

    /// Creates a decoding progress obligation.
    #[must_use]
    pub fn decoding(
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
        object_id: ObjectId,
        symbols_needed: u32,
        epoch_window: EpochWindow,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::IoOp, holder, region, Time::ZERO),
            kind: SymbolObligationKind::DecodingInProgress {
                object_id,
                symbols_received: 0,
                symbols_needed,
            },
            valid_epoch: Some(epoch_window),
            deadline: None,
        }
    }

    /// Creates a lease obligation.
    #[must_use]
    pub fn lease(
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
        object_id: ObjectId,
        lease_expires: Time,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::Lease, holder, region, Time::ZERO),
            kind: SymbolObligationKind::SymbolLease {
                object_id,
                lease_expires,
            },
            valid_epoch: None,
            deadline: Some(lease_expires),
        }
    }

    /// Returns true if this obligation is pending (not resolved).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.inner.is_pending()
    }

    /// Returns true if this obligation is within its valid epoch window.
    #[must_use]
    pub fn is_epoch_valid(&self, current_epoch: EpochId) -> bool {
        self.valid_epoch
            .is_none_or(|window| current_epoch >= window.start && current_epoch <= window.end)
    }

    /// Returns true if this obligation has passed its deadline.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        self.deadline.is_some_and(|deadline| now > deadline)
    }

    /// Commits the obligation (successful resolution).
    ///
    /// # Panics
    /// Panics if already resolved.
    pub fn commit(&mut self, now: Time) {
        self.inner.commit(now);
    }

    /// Aborts the obligation (clean cancellation).
    ///
    /// # Panics
    /// Panics if already resolved.
    pub fn abort(&mut self, now: Time) {
        self.inner.abort(now, ObligationAbortReason::Explicit);
    }

    /// Marks the obligation as leaked.
    ///
    /// Called by the runtime when it detects that an obligation holder
    /// completed without resolving the obligation.
    ///
    /// # Panics
    /// Panics if already resolved.
    pub fn mark_leaked(&mut self, now: Time) {
        self.inner.mark_leaked(now);
    }

    /// Updates decoding progress.
    ///
    /// # Panics
    /// Panics if this is not a decoding obligation.
    pub fn update_decoding_progress(&mut self, symbols_received: u32) {
        if let SymbolObligationKind::DecodingInProgress {
            symbols_received: ref mut count,
            ..
        } = self.kind
        {
            *count = symbols_received;
        } else {
            panic!("not a decoding obligation");
        }
    }

    /// Returns the symbol-specific obligation kind.
    #[must_use]
    pub fn symbol_kind(&self) -> &SymbolObligationKind {
        &self.kind
    }

    /// Returns the underlying obligation state.
    #[must_use]
    pub fn state(&self) -> ObligationState {
        self.inner.state
    }

    /// Returns the obligation ID.
    #[must_use]
    pub fn id(&self) -> ObligationId {
        self.inner.id
    }
}

// ============================================================================
// SymbolObligationTracker
// ============================================================================

/// Tracker for managing symbolic obligations within a region.
///
/// Maintains indices by symbol ID and object ID for fast lookup.
/// Supports epoch-based and deadline-based expiry.
#[derive(Debug)]
pub struct SymbolObligationTracker {
    /// Pending obligations indexed by ID.
    obligations: HashMap<ObligationId, SymbolObligation>,
    /// Index by symbol ID for fast lookup.
    by_symbol: HashMap<SymbolId, Vec<ObligationId>>,
    /// Index by object ID for decoding/encoding obligations.
    by_object: HashMap<ObjectId, Vec<ObligationId>>,
    /// The region this tracker belongs to.
    region_id: RegionId,
}

impl SymbolObligationTracker {
    /// Creates a new tracker for the given region.
    #[must_use]
    pub fn new(region_id: RegionId) -> Self {
        Self {
            obligations: HashMap::new(),
            by_symbol: HashMap::new(),
            by_object: HashMap::new(),
            region_id,
        }
    }

    /// Returns the region ID for this tracker.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Registers a new symbolic obligation.
    pub fn register(&mut self, obligation: SymbolObligation) -> ObligationId {
        let id = obligation.id();

        // Index by symbol or object
        match &obligation.kind {
            SymbolObligationKind::SymbolTransmit { symbol_id, .. }
            | SymbolObligationKind::SymbolAck { symbol_id, .. } => {
                self.by_symbol.entry(*symbol_id).or_default().push(id);
            }
            SymbolObligationKind::DecodingInProgress { object_id, .. }
            | SymbolObligationKind::EncodingSession { object_id, .. }
            | SymbolObligationKind::SymbolLease { object_id, .. } => {
                self.by_object.entry(*object_id).or_default().push(id);
            }
        }

        self.obligations.insert(id, obligation);
        id
    }

    /// Resolves an obligation by ID.
    ///
    /// If `commit` is true, commits the obligation; otherwise aborts it.
    pub fn resolve(
        &mut self,
        id: ObligationId,
        commit: bool,
        now: Time,
    ) -> Option<SymbolObligation> {
        self.obligations.remove(&id).map(|mut ob| {
            if commit {
                ob.commit(now);
            } else {
                ob.abort(now);
            }
            ob
        })
    }

    /// Returns an iterator over all pending obligations.
    pub fn pending(&self) -> impl Iterator<Item = &SymbolObligation> {
        self.obligations.values().filter(|o| o.is_pending())
    }

    /// Returns obligations for a specific symbol.
    #[must_use]
    pub fn by_symbol(&self, symbol_id: SymbolId) -> Vec<&SymbolObligation> {
        self.by_symbol
            .get(&symbol_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.obligations.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the count of pending obligations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.obligations.values().filter(|o| o.is_pending()).count()
    }

    /// Checks for leaked obligations and marks them.
    /// Called during region close.
    pub fn check_leaks(&mut self, now: Time) -> Vec<ObligationId> {
        let mut leaked = Vec::new();
        for (id, ob) in &mut self.obligations {
            if ob.is_pending() {
                ob.mark_leaked(now);
                leaked.push(*id);
            }
        }
        leaked
    }

    /// Aborts all pending obligations outside the given epoch window.
    pub fn abort_expired_epoch(&mut self, current_epoch: EpochId, now: Time) -> Vec<ObligationId> {
        let mut aborted = Vec::new();
        for (id, ob) in &mut self.obligations {
            if ob.is_pending() && !ob.is_epoch_valid(current_epoch) {
                ob.abort(now);
                aborted.push(*id);
            }
        }
        aborted
    }

    /// Aborts all pending obligations that have passed their deadline.
    pub fn abort_expired_deadlines(&mut self, now: Time) -> Vec<ObligationId> {
        let mut aborted = Vec::new();
        for (id, ob) in &mut self.obligations {
            if ob.is_pending() && ob.is_expired(now) {
                ob.abort(now);
                aborted.push(*id);
            }
        }
        aborted
    }
}

// ============================================================================
// ObligationGuard
// ============================================================================

/// Guard that aborts an obligation on drop if not explicitly resolved.
///
/// Provides RAII-style automatic resolution. If the guard is dropped without
/// calling `commit()` or `abort()`, the obligation is aborted.
pub struct ObligationGuard<'a> {
    /// The tracker holding the obligation.
    tracker: &'a mut SymbolObligationTracker,
    /// The obligation ID.
    id: ObligationId,
    /// Whether the obligation has been explicitly resolved.
    resolved: bool,
}

impl<'a> ObligationGuard<'a> {
    /// Creates a new guard for the given obligation.
    pub fn new(tracker: &'a mut SymbolObligationTracker, id: ObligationId) -> Self {
        Self {
            tracker,
            id,
            resolved: false,
        }
    }

    /// Commits the obligation and marks the guard as resolved.
    pub fn commit(mut self, now: Time) {
        self.tracker.resolve(self.id, true, now);
        self.resolved = true;
    }

    /// Aborts the obligation and marks the guard as resolved.
    pub fn abort(mut self, now: Time) {
        self.tracker.resolve(self.id, false, now);
        self.resolved = true;
    }
}

impl Drop for ObligationGuard<'_> {
    fn drop(&mut self) {
        if !self.resolved {
            // Best-effort abort with zero time (runtime can set proper time)
            self.tracker.resolve(self.id, false, Time::ZERO);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn test_ids() -> (ObligationId, TaskId, RegionId) {
        (
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            RegionId::from_arena(ArenaIndex::new(0, 0)),
        )
    }

    // Test 1: Basic obligation creation and commit
    #[test]
    fn test_transmit_obligation_lifecycle_commit() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(oid, tid, rid, symbol_id, dest, None, None);

        assert!(ob.is_pending());
        ob.commit(Time::from_millis(100));
        assert!(!ob.is_pending());
        assert_eq!(ob.state(), ObligationState::Committed);
    }

    // Test 2: Basic obligation abort
    #[test]
    fn test_transmit_obligation_lifecycle_abort() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(oid, tid, rid, symbol_id, dest, None, None);

        ob.abort(Time::from_millis(100));
        assert_eq!(ob.state(), ObligationState::Aborted);
    }

    // Test 3: Epoch validity checking
    #[test]
    fn test_epoch_window_validity() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(10),
            end: EpochId(20),
        };

        let ob = SymbolObligation::decoding(oid, tid, rid, object_id, 10, window);

        assert!(!ob.is_epoch_valid(EpochId(5))); // Before window
        assert!(ob.is_epoch_valid(EpochId(10))); // Start of window
        assert!(ob.is_epoch_valid(EpochId(15))); // Middle of window
        assert!(ob.is_epoch_valid(EpochId(20))); // End of window
        assert!(!ob.is_epoch_valid(EpochId(25))); // After window
    }

    // Test 4: Deadline expiry detection
    #[test]
    fn test_deadline_expiry() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let deadline = Time::from_millis(1000);

        let ob = SymbolObligation::lease(oid, tid, rid, object_id, deadline);

        assert!(!ob.is_expired(Time::from_millis(500)));
        assert!(!ob.is_expired(Time::from_millis(1000)));
        assert!(ob.is_expired(Time::from_millis(1001)));
    }

    // Test 5: Tracker registration and lookup
    #[test]
    fn test_tracker_registration() {
        let rid = RegionId::from_arena(ArenaIndex::new(0, 0));
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob = SymbolObligation::transmit(oid, tid, rid, symbol_id, dest, None, None);

        let id = tracker.register(ob);
        assert_eq!(tracker.pending_count(), 1);

        let found = tracker.by_symbol(symbol_id);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), id);
    }

    // Test 6: Tracker resolution (commit)
    #[test]
    fn test_tracker_resolve_commit() {
        let rid = RegionId::from_arena(ArenaIndex::new(0, 0));
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob = SymbolObligation::transmit(oid, tid, rid, symbol_id, dest, None, None);

        let id = tracker.register(ob);
        let resolved = tracker.resolve(id, true, Time::from_millis(100));

        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().state(), ObligationState::Committed);
        assert_eq!(tracker.pending_count(), 0);
    }

    // Test 7: Leak detection during region close
    #[test]
    fn test_leak_detection() {
        let rid = RegionId::from_arena(ArenaIndex::new(0, 0));
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid1, tid, _) = test_ids();
        let oid2 = ObligationId::from_arena(ArenaIndex::new(1, 0));
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let ob1 = SymbolObligation::transmit(oid1, tid, rid, symbol_id, dest, None, None);
        let ob2 = SymbolObligation::ack(oid2, tid, rid, symbol_id, dest);

        tracker.register(ob1);
        let id2 = tracker.register(ob2);

        // Resolve one, leave the other
        tracker.resolve(id2, true, Time::from_millis(100));

        let leaked = tracker.check_leaks(Time::from_millis(200));
        assert_eq!(leaked.len(), 1);
    }

    // Test 8: Epoch-based abort
    #[test]
    fn test_abort_expired_epoch() {
        let rid = RegionId::from_arena(ArenaIndex::new(0, 0));
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(10),
            end: EpochId(20),
        };

        let ob = SymbolObligation::decoding(oid, tid, rid, object_id, 10, window);
        tracker.register(ob);

        // Epoch 15 is valid, nothing aborted
        let aborted = tracker.abort_expired_epoch(EpochId(15), Time::from_millis(100));
        assert_eq!(aborted.len(), 0);

        // Epoch 25 is past window, obligation aborted
        let aborted = tracker.abort_expired_epoch(EpochId(25), Time::from_millis(200));
        assert_eq!(aborted.len(), 1);
    }

    // Test 9: Deadline-based abort
    #[test]
    fn test_abort_expired_deadlines() {
        let rid = RegionId::from_arena(ArenaIndex::new(0, 0));
        let mut tracker = SymbolObligationTracker::new(rid);

        let (oid, tid, _) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let deadline = Time::from_millis(1000);

        let ob = SymbolObligation::lease(oid, tid, rid, object_id, deadline);
        tracker.register(ob);

        // Before deadline
        let aborted = tracker.abort_expired_deadlines(Time::from_millis(500));
        assert_eq!(aborted.len(), 0);

        // After deadline
        let aborted = tracker.abort_expired_deadlines(Time::from_millis(1500));
        assert_eq!(aborted.len(), 1);
    }

    // Test 10: Decoding progress updates
    #[test]
    fn test_decoding_progress_update() {
        let (oid, tid, rid) = test_ids();
        let object_id = ObjectId::new_for_test(1);
        let window = EpochWindow {
            start: EpochId(1),
            end: EpochId(100),
        };

        let mut ob = SymbolObligation::decoding(oid, tid, rid, object_id, 10, window);

        // Initial state
        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 0);
        }

        // Update progress
        ob.update_decoding_progress(5);

        if let SymbolObligationKind::DecodingInProgress {
            symbols_received, ..
        } = ob.symbol_kind()
        {
            assert_eq!(*symbols_received, 5);
        }
    }

    // Test 11: Double resolution panics
    #[test]
    #[should_panic(expected = "obligation already resolved")]
    fn test_double_commit_panics() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);
        let dest = RegionId::from_arena(ArenaIndex::new(1, 0));

        let mut ob = SymbolObligation::transmit(oid, tid, rid, symbol_id, dest, None, None);

        ob.commit(Time::from_millis(100));
        ob.commit(Time::from_millis(200)); // Should panic
    }

    // Test 12: No epoch constraint means always valid
    #[test]
    fn test_no_epoch_constraint_always_valid() {
        let (oid, tid, rid) = test_ids();
        let symbol_id = SymbolId::new_for_test(1, 0, 0);

        let ob = SymbolObligation::ack(oid, tid, rid, symbol_id, rid);

        assert!(ob.is_epoch_valid(EpochId(0)));
        assert!(ob.is_epoch_valid(EpochId(u64::MAX)));
    }
}
