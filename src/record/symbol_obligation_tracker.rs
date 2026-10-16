//! Symbol obligation integration with the core obligation tracking system.
//!
//! Bridges the RaptorQ symbol layer with the runtime's existing two-phase
//! obligation protocol ([`ObligationRecord`]). Provides epoch-aware validity
//! windows, deadline-based expiry, and RAII guards for automatic resolution.

use smallvec::{SmallVec, smallvec};
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

/// Error returned when updating decoding progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodingProgressUpdateError {
    /// Progress updates are only valid for decoding obligations.
    NotDecodingObligation,
    /// Reported progress exceeds the required symbol count.
    SymbolsReceivedExceedsNeeded {
        /// The number of symbols received so far.
        received: u32,
        /// The total number of symbols needed to complete decoding.
        needed: u32,
    },
    /// Reported progress moved backwards from the previously observed count.
    SymbolsReceivedRegressed {
        /// The previously recorded number of symbols received.
        previous: u32,
        /// The newly reported number of symbols received.
        attempted: u32,
    },
}

impl std::fmt::Display for DecodingProgressUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDecodingObligation => {
                write!(
                    f,
                    "decoding progress can only be updated for decoding obligations"
                )
            }
            Self::SymbolsReceivedExceedsNeeded { received, needed } => write!(
                f,
                "symbols_received ({received}) exceeds symbols_needed ({needed})"
            ),
            Self::SymbolsReceivedRegressed {
                previous,
                attempted,
            } => write!(
                f,
                "symbols_received regressed from {previous} to {attempted}"
            ),
        }
    }
}

impl std::error::Error for DecodingProgressUpdateError {}

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
    #[allow(clippy::too_many_arguments)]
    pub fn transmit(
        id: ObligationId,
        holder: TaskId,
        region: RegionId,
        symbol_id: SymbolId,
        destination: RegionId,
        deadline: Option<Time>,
        epoch_window: Option<EpochWindow>,
        now: Time,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::IoOp, holder, region, now),
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
        now: Time,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::Ack, holder, region, now),
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
        now: Time,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::IoOp, holder, region, now),
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
        now: Time,
    ) -> Self {
        Self {
            inner: ObligationRecord::new(id, ObligationKind::Lease, holder, region, now),
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
    #[inline]
    pub fn is_pending(&self) -> bool {
        self.inner.is_pending()
    }

    /// Returns true if this obligation is within its valid epoch window.
    #[must_use]
    pub fn is_epoch_valid(&self, current_epoch: EpochId) -> bool {
        self.valid_epoch
            .is_none_or(|window| current_epoch >= window.start && current_epoch <= window.end)
    }

    /// Returns true if this obligation has reached or passed its deadline.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
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
    /// Returns an error when called for a non-decoding obligation or when the
    /// provided count exceeds the decode target or moves backwards.
    pub fn update_decoding_progress(
        &mut self,
        symbols_received: u32,
    ) -> Result<(), DecodingProgressUpdateError> {
        if let SymbolObligationKind::DecodingInProgress {
            symbols_received: ref mut count,
            symbols_needed,
            ..
        } = self.kind
        {
            if symbols_received > symbols_needed {
                return Err(DecodingProgressUpdateError::SymbolsReceivedExceedsNeeded {
                    received: symbols_received,
                    needed: symbols_needed,
                });
            }
            if symbols_received < *count {
                return Err(DecodingProgressUpdateError::SymbolsReceivedRegressed {
                    previous: *count,
                    attempted: symbols_received,
                });
            }
            *count = symbols_received;
            Ok(())
        } else {
            Err(DecodingProgressUpdateError::NotDecodingObligation)
        }
    }

    /// Returns the symbol-specific obligation kind.
    #[must_use]
    #[inline]
    pub fn symbol_kind(&self) -> &SymbolObligationKind {
        &self.kind
    }

    /// Returns the underlying obligation state.
    #[must_use]
    #[inline]
    pub fn state(&self) -> ObligationState {
        self.inner.state
    }

    /// Returns the obligation ID.
    #[must_use]
    #[inline]
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
    by_symbol: HashMap<SymbolId, SmallVec<[ObligationId; 2]>>,
    /// Index by object ID for decoding/encoding obligations.
    by_object: HashMap<ObjectId, SmallVec<[ObligationId; 2]>>,
    /// The region this tracker belongs to.
    region_id: RegionId,
}

impl SymbolObligationTracker {
    fn assert_registration_valid(&self, obligation: &SymbolObligation) {
        assert_eq!(
            obligation.inner.region, self.region_id,
            "symbol obligation tracker region mismatch"
        );
        assert!(
            !self.obligations.contains_key(&obligation.id()),
            "duplicate symbol obligation id registered"
        );
    }

    fn index_obligation_id(&mut self, id: ObligationId, kind: &SymbolObligationKind) {
        match kind {
            SymbolObligationKind::SymbolTransmit { symbol_id, .. }
            | SymbolObligationKind::SymbolAck { symbol_id, .. } => {
                self.by_symbol
                    .entry(*symbol_id)
                    .or_insert_with(|| smallvec![])
                    .push(id);
            }
            SymbolObligationKind::DecodingInProgress { object_id, .. }
            | SymbolObligationKind::EncodingSession { object_id, .. }
            | SymbolObligationKind::SymbolLease { object_id, .. } => {
                self.by_object
                    .entry(*object_id)
                    .or_insert_with(|| smallvec![])
                    .push(id);
            }
        }
    }

    fn remove_indexed_obligation_id(&mut self, id: ObligationId, kind: &SymbolObligationKind) {
        match kind {
            SymbolObligationKind::SymbolTransmit { symbol_id, .. }
            | SymbolObligationKind::SymbolAck { symbol_id, .. } => {
                if let Some(ids) = self.by_symbol.get_mut(symbol_id) {
                    ids.retain(|i| *i != id);
                    if ids.is_empty() {
                        self.by_symbol.remove(symbol_id);
                    }
                }
            }
            SymbolObligationKind::DecodingInProgress { object_id, .. }
            | SymbolObligationKind::EncodingSession { object_id, .. }
            | SymbolObligationKind::SymbolLease { object_id, .. } => {
                if let Some(ids) = self.by_object.get_mut(object_id) {
                    ids.retain(|i| *i != id);
                    if ids.is_empty() {
                        self.by_object.remove(object_id);
                    }
                }
            }
        }
    }

    fn remove_obligation(&mut self, id: ObligationId) -> Option<SymbolObligation> {
        let obligation = self.obligations.remove(&id)?;
        self.remove_indexed_obligation_id(id, &obligation.kind);
        Some(obligation)
    }

    /// Creates a new tracker for the given region.
    #[must_use]
    pub fn new(region_id: RegionId) -> Self {
        Self {
            obligations: HashMap::with_capacity(16),
            by_symbol: HashMap::with_capacity(16),
            by_object: HashMap::with_capacity(16),
            region_id,
        }
    }

    /// Returns the region ID for this tracker.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Registers a new symbolic obligation.
    ///
    /// # Panics
    /// Panics if the obligation belongs to a different region or reuses an
    /// already-pending obligation ID.
    pub fn register(&mut self, obligation: SymbolObligation) -> ObligationId {
        self.assert_registration_valid(&obligation);
        let id = obligation.id();
        self.index_obligation_id(id, &obligation.kind);
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
        self.remove_obligation(id).map(|mut ob| {
            if ob.is_pending() {
                if commit {
                    ob.commit(now);
                } else {
                    ob.abort(now);
                }
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
                    .filter_map(|id| self.obligations.get(id).filter(|ob| ob.is_pending()))
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
        let leaked: Vec<ObligationId> = self
            .obligations
            .iter()
            .filter_map(|(id, ob)| ob.is_pending().then_some(*id))
            .collect();

        for id in &leaked {
            if let Some(mut ob) = self.remove_obligation(*id) {
                ob.mark_leaked(now);
            }
        }
        leaked
    }

    /// Aborts all pending obligations outside the given epoch window.
    pub fn abort_expired_epoch(&mut self, current_epoch: EpochId, now: Time) -> Vec<ObligationId> {
        let aborted: Vec<ObligationId> = self
            .obligations
            .iter()
            .filter_map(|(id, ob)| {
                (ob.is_pending() && !ob.is_epoch_valid(current_epoch)).then_some(*id)
            })
            .collect();

        for id in &aborted {
            if let Some(mut ob) = self.remove_obligation(*id) {
                ob.abort(now);
            }
        }
        aborted
    }

    /// Aborts all pending obligations that have passed their deadline.
    pub fn abort_expired_deadlines(&mut self, now: Time) -> Vec<ObligationId> {
        let aborted: Vec<ObligationId> = self
            .obligations
            .iter()
            .filter_map(|(id, ob)| (ob.is_pending() && ob.is_expired(now)).then_some(*id))
            .collect();

        for id in &aborted {
            if let Some(mut ob) = self.remove_obligation(*id) {
                ob.abort(now);
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
            self.tracker
                .resolve(self.id, false, Time::from_nanos(1_000_000_000));
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "symbol_obligation_tracker_inline_tests.rs"]
mod tests;
