//! Linear obligation type for symbol delivery and partial fulfillment.
//!
//! Extends the obligation system to the RaptorQ distributed layer, ensuring
//! that every symbol has a clear owner, partial fulfillment is tracked, and
//! leaked obligations are detected when tasks complete without resolution.
//!
//! # Linear Type Semantics
//!
//! [`SymbolicObligation`] implements "use exactly once" semantics:
//! - Created by `reserve()` operations on the registry
//! - Must be resolved by `commit()`, `abort()`, or `commit_or_abort()`
//! - Cannot be cloned (each obligation is unique)
//! - Dropping without resolution triggers leak detection

use core::fmt;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::types::symbol::{ObjectId, ObjectParams, SymbolId};
use crate::types::{ObligationId, RegionId, TaskId, Time};
use crate::util::ArenaIndex;

// ─── SymbolicObligationKind ─────────────────────────────────────────────────

/// The kind of symbolic obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicObligationKind {
    /// Obligation to send all symbols for an object.
    SendObject,
    /// Obligation to send a specific symbol.
    SendSymbol,
    /// Obligation to acknowledge receipt of symbols.
    AcknowledgeReceipt,
    /// Obligation to decode and process received symbols.
    DecodeObject,
    /// Obligation to deliver repair symbols if needed.
    RepairDelivery,
}

impl SymbolicObligationKind {
    /// Returns a short string for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendObject => "send_object",
            Self::SendSymbol => "send_symbol",
            Self::AcknowledgeReceipt => "ack_receipt",
            Self::DecodeObject => "decode_object",
            Self::RepairDelivery => "repair_delivery",
        }
    }
}

impl fmt::Display for SymbolicObligationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── SymbolicObligationState ────────────────────────────────────────────────

/// State of a symbolic obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicObligationState {
    /// Obligation is reserved, awaiting fulfillment.
    Reserved,
    /// Obligation is being fulfilled (partial progress).
    InProgress,
    /// Obligation was fully committed.
    Committed,
    /// Obligation was cleanly aborted.
    Aborted,
    /// Obligation was leaked (dropped without resolution).
    Leaked,
}

impl SymbolicObligationState {
    /// Returns true if the obligation is in a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted | Self::Leaked)
    }

    /// Returns true if the obligation is successfully resolved.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }

    /// Returns true if the obligation leaked.
    #[must_use]
    pub const fn is_leaked(self) -> bool {
        matches!(self, Self::Leaked)
    }
}

// ─── FulfillmentProgress ────────────────────────────────────────────────────

/// Tracks progress toward fulfilling an obligation.
pub struct FulfillmentProgress {
    /// Total symbols required.
    total: u32,
    /// Symbols fulfilled so far.
    fulfilled: AtomicU32,
}

impl FulfillmentProgress {
    /// Creates new progress tracker.
    #[must_use]
    pub fn new(total: u32) -> Self {
        Self {
            total,
            fulfilled: AtomicU32::new(0),
        }
    }

    /// Increments the fulfilled count by one.
    pub fn increment(&self) {
        self.fulfilled.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments by a specific amount.
    pub fn add(&self, count: u32) {
        self.fulfilled.fetch_add(count, Ordering::Relaxed);
    }

    /// Returns the total required.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Returns the current fulfilled count.
    #[must_use]
    pub fn fulfilled(&self) -> u32 {
        self.fulfilled.load(Ordering::Relaxed)
    }

    /// Returns true if fulfillment is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.fulfilled() >= self.total
    }

    /// Returns the percentage complete (0.0 to 1.0).
    #[must_use]
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            f64::from(self.fulfilled()) / f64::from(self.total)
        }
    }

    /// Returns a snapshot of the current progress.
    #[must_use]
    pub fn snapshot(&self) -> FulfillmentSnapshot {
        let fulfilled = self.fulfilled();
        FulfillmentSnapshot {
            total: self.total,
            fulfilled,
            percent: self.percent(),
            complete: fulfilled >= self.total,
        }
    }

    /// Returns the remaining count.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.total.saturating_sub(self.fulfilled())
    }
}

impl fmt::Debug for FulfillmentProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FulfillmentProgress")
            .field("fulfilled", &self.fulfilled())
            .field("total", &self.total)
            .field("complete", &self.is_complete())
            .finish()
    }
}

/// A snapshot of fulfillment progress.
#[derive(Clone, Debug)]
pub struct FulfillmentSnapshot {
    /// Total symbols required.
    pub total: u32,
    /// Symbols fulfilled so far.
    pub fulfilled: u32,
    /// Percentage complete (0.0 to 1.0).
    pub percent: f64,
    /// Whether fulfillment is complete.
    pub complete: bool,
}

// ─── ObligationInner ────────────────────────────────────────────────────────

/// Internal state for a symbolic obligation.
struct ObligationInner {
    /// Unique ID for this obligation.
    id: ObligationId,
    /// The kind of obligation.
    kind: SymbolicObligationKind,
    /// The object this obligation relates to.
    object_id: ObjectId,
    /// The task holding this obligation.
    holder: TaskId,
    /// The region owning this obligation.
    region: RegionId,
    /// Current state.
    state: RwLock<SymbolicObligationState>,
    /// Fulfillment progress.
    progress: FulfillmentProgress,
    /// Creation timestamp.
    created_at: Time,
    /// Description for debugging.
    description: Option<String>,
}

// ─── SymbolicObligation ─────────────────────────────────────────────────────

/// A linear obligation to deliver or acknowledge symbols.
///
/// Represents a resource that must be explicitly resolved (committed or aborted)
/// before the owning task or region can complete. Dropping an unresolved
/// obligation triggers leak detection.
///
/// # Linear Type Semantics
///
/// - Created by `reserve()` operations on [`SymbolicObligationRegistry`]
/// - Must be resolved by `commit()`, `abort()`, or `commit_or_abort()`
/// - Cannot be cloned (each obligation is unique)
/// - Dropping without resolution triggers leak detection
pub struct SymbolicObligation {
    /// Shared state for this obligation.
    state: Arc<ObligationInner>,
    /// Whether this handle has resolved the obligation.
    resolved: bool,
}

// SymbolicObligation is NOT Clone - it's a linear type

impl SymbolicObligation {
    /// Creates a new obligation for sending an object.
    #[must_use]
    pub(crate) fn new_send_object(
        id: ObligationId,
        object_id: ObjectId,
        params: &ObjectParams,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
    ) -> Self {
        let total_symbols = params.total_source_symbols();

        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::SendObject,
                object_id,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(total_symbols),
                created_at,
                description: None,
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for sending a single symbol.
    #[must_use]
    pub(crate) fn new_send_symbol(
        id: ObligationId,
        symbol_id: SymbolId,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::SendSymbol,
                object_id: symbol_id.object_id(),
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(1),
                created_at,
                description: Some(format!("symbol {symbol_id}")),
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for acknowledging receipt.
    #[must_use]
    pub(crate) fn new_acknowledge(
        id: ObligationId,
        object_id: ObjectId,
        expected_count: u32,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::AcknowledgeReceipt,
                object_id,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(expected_count),
                created_at,
                description: None,
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for decoding.
    #[must_use]
    pub(crate) fn new_decode(
        id: ObligationId,
        object_id: ObjectId,
        min_symbols: u32,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::DecodeObject,
                object_id,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(min_symbols),
                created_at,
                description: None,
            }),
            resolved: false,
        }
    }

    /// Returns the obligation ID.
    #[must_use]
    pub fn id(&self) -> ObligationId {
        self.state.id
    }

    /// Returns the obligation kind.
    #[must_use]
    pub fn kind(&self) -> SymbolicObligationKind {
        self.state.kind
    }

    /// Returns the object ID.
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.state.object_id
    }

    /// Returns the holder task ID.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.state.holder
    }

    /// Returns the owning region ID.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.state.region
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> SymbolicObligationState {
        *self.state.state.read()
    }

    /// Returns true if the obligation is pending (not yet resolved).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.state().is_terminal()
    }

    /// Returns the fulfillment progress.
    #[must_use]
    pub fn progress(&self) -> FulfillmentSnapshot {
        self.state.progress.snapshot()
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> Time {
        self.state.created_at
    }

    /// Marks progress on partial fulfillment.
    ///
    /// Call this as symbols are sent/received to track progress.
    pub fn fulfill_one(&self, _symbol_id: SymbolId) {
        self.state.progress.increment();

        // Transition to InProgress if still Reserved
        let mut state = self.state.state.write();
        if *state == SymbolicObligationState::Reserved {
            *state = SymbolicObligationState::InProgress;
        }
    }

    /// Marks multiple symbols as fulfilled.
    pub fn fulfill_many(&self, count: u32) {
        self.state.progress.add(count);

        let mut state = self.state.state.write();
        if *state == SymbolicObligationState::Reserved {
            *state = SymbolicObligationState::InProgress;
        }
    }

    /// Commits the obligation (successful completion).
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn commit(mut self) {
        assert!(self.is_pending(), "obligation already resolved");

        *self.state.state.write() = SymbolicObligationState::Committed;
        self.resolved = true;
    }

    /// Aborts the obligation (clean cancellation).
    ///
    /// Use this when cancellation is requested before completion.
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn abort(mut self) {
        assert!(self.is_pending(), "obligation already resolved");

        *self.state.state.write() = SymbolicObligationState::Aborted;
        self.resolved = true;
    }

    /// Commits if fulfillment is complete, otherwise aborts.
    ///
    /// Useful for cleanup scenarios where partial progress may exist.
    pub fn commit_or_abort(self) {
        if self.state.progress.is_complete() {
            self.commit();
        } else {
            self.abort();
        }
    }

    /// Marks the obligation as leaked (internal use by runtime).
    pub(crate) fn mark_leaked(&self) {
        *self.state.state.write() = SymbolicObligationState::Leaked;
    }

    /// Creates an obligation for testing.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(id: u64, object_id: ObjectId, total: u32) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id: ObligationId::from_arena(ArenaIndex::new(id as u32, 0)),
                kind: SymbolicObligationKind::SendObject,
                object_id,
                holder: TaskId::from_arena(ArenaIndex::new(0, 0)),
                region: RegionId::from_arena(ArenaIndex::new(0, 0)),
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(total),
                created_at: Time::ZERO,
                description: None,
            }),
            resolved: false,
        }
    }
}

impl Drop for SymbolicObligation {
    fn drop(&mut self) {
        if !self.resolved && self.is_pending() {
            self.mark_leaked();

            #[cfg(debug_assertions)]
            panic!(
                "SymbolicObligation leaked: {:?} for object {} was dropped without resolution",
                self.kind(),
                self.object_id()
            );

            #[cfg(not(debug_assertions))]
            crate::tracing_compat::error!(
                kind = ?self.kind(),
                object_id = %self.object_id(),
                "symbolic obligation leaked"
            );
        }
    }
}

impl fmt::Debug for SymbolicObligation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolicObligation")
            .field("id", &self.id())
            .field("kind", &self.kind())
            .field("object_id", &self.object_id())
            .field("state", &self.state())
            .field("progress", &self.progress())
            .finish()
    }
}

// ─── ObligationSummary ──────────────────────────────────────────────────────

/// Summary of an obligation for diagnostics.
#[derive(Clone, Debug)]
pub struct ObligationSummary {
    /// The obligation ID.
    pub id: ObligationId,
    /// The kind of obligation.
    pub kind: SymbolicObligationKind,
    /// The object this obligation relates to.
    pub object_id: ObjectId,
    /// The holder task.
    pub holder: TaskId,
    /// Current state.
    pub state: SymbolicObligationState,
}

// ─── SymbolicObligationRegistry ─────────────────────────────────────────────

/// Entry in the obligation registry.
struct ObligationEntry {
    id: ObligationId,
    kind: SymbolicObligationKind,
    object_id: ObjectId,
    holder: TaskId,
    region: RegionId,
    #[allow(dead_code)]
    created_at: Time,
    state: SymbolicObligationState,
}

/// Registry that tracks all active symbolic obligations.
///
/// Provides indexed lookup by ID, object, task, and region. Used by the
/// runtime to detect leaked obligations and check region quiescence.
pub struct SymbolicObligationRegistry {
    /// Obligations by ID.
    by_id: RwLock<HashMap<ObligationId, ObligationEntry>>,
    /// Obligations by object ID.
    by_object: RwLock<HashMap<ObjectId, Vec<ObligationId>>>,
    /// Obligations by holder task (arena-slot indexed).
    by_holder: RwLock<Vec<Option<Vec<ObligationId>>>>,
    /// Obligations by region (arena-slot indexed).
    by_region: RwLock<Vec<Option<Vec<ObligationId>>>>,
    /// Next obligation ID.
    next_id: AtomicU64,
}

impl SymbolicObligationRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_id: RwLock::new(HashMap::new()),
            by_object: RwLock::new(HashMap::new()),
            by_holder: RwLock::new(Vec::new()),
            by_region: RwLock::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Creates a send-object obligation and registers it.
    pub fn create_send_object(
        &self,
        object_id: ObjectId,
        params: &ObjectParams,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> SymbolicObligation {
        let id = self.allocate_id();
        let obligation =
            SymbolicObligation::new_send_object(id, object_id, params, holder, region, now);
        self.register(
            id,
            SymbolicObligationKind::SendObject,
            object_id,
            holder,
            region,
            now,
        );
        obligation
    }

    /// Creates a send-symbol obligation and registers it.
    pub fn create_send_symbol(
        &self,
        symbol_id: SymbolId,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> SymbolicObligation {
        let id = self.allocate_id();
        let obligation = SymbolicObligation::new_send_symbol(id, symbol_id, holder, region, now);
        self.register(
            id,
            SymbolicObligationKind::SendSymbol,
            symbol_id.object_id(),
            holder,
            region,
            now,
        );
        obligation
    }

    /// Creates an acknowledge obligation and registers it.
    pub fn create_acknowledge(
        &self,
        object_id: ObjectId,
        expected_count: u32,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> SymbolicObligation {
        let id = self.allocate_id();
        let obligation =
            SymbolicObligation::new_acknowledge(id, object_id, expected_count, holder, region, now);
        self.register(
            id,
            SymbolicObligationKind::AcknowledgeReceipt,
            object_id,
            holder,
            region,
            now,
        );
        obligation
    }

    /// Creates a decode obligation and registers it.
    pub fn create_decode(
        &self,
        object_id: ObjectId,
        min_symbols: u32,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> SymbolicObligation {
        let id = self.allocate_id();
        let obligation =
            SymbolicObligation::new_decode(id, object_id, min_symbols, holder, region, now);
        self.register(
            id,
            SymbolicObligationKind::DecodeObject,
            object_id,
            holder,
            region,
            now,
        );
        obligation
    }

    /// Updates the state of a registered obligation.
    pub fn update_state(&self, id: ObligationId, state: SymbolicObligationState) {
        if let Some(entry) = self.by_id.write().get_mut(&id) {
            entry.state = state;
        }
    }

    /// Returns obligation IDs for a region.
    #[must_use]
    pub fn obligations_for_region(&self, region: RegionId) -> Vec<ObligationId> {
        let slot = region.arena_index().index() as usize;
        let guard = self.by_region.read();
        guard
            .get(slot)
            .and_then(Option::as_ref)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns obligation IDs for a task.
    #[must_use]
    pub fn obligations_for_task(&self, task: TaskId) -> Vec<ObligationId> {
        let slot = task.arena_index().index() as usize;
        let guard = self.by_holder.read();
        guard
            .get(slot)
            .and_then(Option::as_ref)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns obligation IDs for an object.
    #[must_use]
    pub fn obligations_for_object(&self, object_id: ObjectId) -> Vec<ObligationId> {
        self.by_object
            .read()
            .get(&object_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Checks for pending obligations in a region (blocks region close).
    #[must_use]
    pub fn has_pending_in_region(&self, region: RegionId) -> bool {
        let slot = region.arena_index().index() as usize;
        let ids = {
            let by_region = self.by_region.read();
            by_region.get(slot).and_then(Option::as_ref).cloned()
        };

        let Some(ids) = ids else {
            return false;
        };

        let by_id = self.by_id.read();
        for id in &ids {
            if let Some(entry) = by_id.get(id) {
                if !entry.state.is_terminal() {
                    return true;
                }
            }
        }

        false
    }

    /// Gets pending obligations in a region.
    #[must_use]
    pub fn pending_in_region(&self, region: RegionId) -> Vec<ObligationSummary> {
        let mut result = Vec::new();

        let slot = region.arena_index().index() as usize;
        let ids = {
            let by_region = self.by_region.read();
            by_region.get(slot).and_then(Option::as_ref).cloned()
        };

        let Some(ids) = ids else {
            return result;
        };

        let by_id = self.by_id.read();
        for id in &ids {
            if let Some(entry) = by_id.get(id) {
                if !entry.state.is_terminal() {
                    result.push(ObligationSummary {
                        id: entry.id,
                        kind: entry.kind,
                        object_id: entry.object_id,
                        holder: entry.holder,
                        state: entry.state,
                    });
                }
            }
        }

        result
    }

    fn allocate_id(&self) -> ObligationId {
        let raw = self.next_id.fetch_add(1, Ordering::Relaxed);
        ObligationId::from_arena(ArenaIndex::new(raw as u32, 0))
    }

    fn register(
        &self,
        id: ObligationId,
        kind: SymbolicObligationKind,
        object_id: ObjectId,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
    ) {
        let entry = ObligationEntry {
            id,
            kind,
            object_id,
            holder,
            region,
            created_at,
            state: SymbolicObligationState::Reserved,
        };

        self.by_id.write().insert(id, entry);
        self.by_object
            .write()
            .entry(object_id)
            .or_default()
            .push(id);
        {
            let holder_slot = holder.arena_index().index() as usize;
            let mut by_holder = self.by_holder.write();
            if holder_slot >= by_holder.len() {
                by_holder.resize_with(holder_slot + 1, || None);
            }
            by_holder[holder_slot].get_or_insert_with(Vec::new).push(id);
        }
        {
            let region_slot = region.arena_index().index() as usize;
            let mut by_region = self.by_region.write();
            if region_slot >= by_region.len() {
                by_region.resize_with(region_slot + 1, || None);
            }
            by_region[region_slot].get_or_insert_with(Vec::new).push(id);
        }
    }
}

impl Default for SymbolicObligationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_object_id() -> ObjectId {
        ObjectId::new_for_test(1)
    }

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(1, 0))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(1, 0))
    }

    fn test_params() -> ObjectParams {
        ObjectParams::new(test_object_id(), 5120, 1280, 1, 4)
    }

    #[test]
    fn obligation_lifecycle_commit() {
        let obj = SymbolicObligation::new_for_test(1, test_object_id(), 4);

        assert_eq!(obj.state(), SymbolicObligationState::Reserved);
        assert!(obj.is_pending());
        assert_eq!(obj.progress().total, 4);
        assert_eq!(obj.progress().fulfilled, 0);
        assert!(!obj.progress().complete);

        obj.commit();
    }

    #[test]
    fn obligation_lifecycle_abort() {
        let obj = SymbolicObligation::new_for_test(2, test_object_id(), 4);
        assert!(obj.is_pending());
        obj.abort();
    }

    #[test]
    fn partial_fulfillment_tracking() {
        let obj = SymbolicObligation::new_for_test(3, test_object_id(), 3);

        let sym1 = SymbolId::new(test_object_id(), 0, 0);
        let sym2 = SymbolId::new(test_object_id(), 0, 1);

        obj.fulfill_one(sym1);
        assert_eq!(obj.state(), SymbolicObligationState::InProgress);
        assert_eq!(obj.progress().fulfilled, 1);

        obj.fulfill_one(sym2);
        assert_eq!(obj.progress().fulfilled, 2);
        assert!(!obj.progress().complete);

        obj.fulfill_many(1);
        assert!(obj.progress().complete);

        obj.commit();
    }

    #[test]
    fn commit_or_abort_complete() {
        let obj = SymbolicObligation::new_for_test(4, test_object_id(), 2);
        obj.fulfill_many(2);
        obj.commit_or_abort();
        // If complete, should commit (no panic)
    }

    #[test]
    fn commit_or_abort_incomplete() {
        let obj = SymbolicObligation::new_for_test(5, test_object_id(), 10);
        obj.fulfill_many(3);
        obj.commit_or_abort();
        // If incomplete, should abort (no panic)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "SymbolicObligation leaked")]
    fn leak_detection_panics_in_debug() {
        let _obj = SymbolicObligation::new_for_test(6, test_object_id(), 1);
        // Dropping without resolution triggers panic in debug
    }

    #[test]
    fn fulfillment_progress_zero_total() {
        let progress = FulfillmentProgress::new(0);
        assert!(progress.is_complete());
        assert!((progress.percent() - 1.0).abs() < f64::EPSILON);
        assert_eq!(progress.remaining(), 0);
    }

    #[test]
    fn fulfillment_progress_snapshot() {
        let progress = FulfillmentProgress::new(10);
        progress.add(7);
        let snap = progress.snapshot();
        assert_eq!(snap.total, 10);
        assert_eq!(snap.fulfilled, 7);
        assert!(!snap.complete);
        assert!((snap.percent - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn obligation_kind_display() {
        assert_eq!(SymbolicObligationKind::SendObject.as_str(), "send_object");
        assert_eq!(
            SymbolicObligationKind::AcknowledgeReceipt.as_str(),
            "ack_receipt"
        );
    }

    #[test]
    fn obligation_state_properties() {
        assert!(!SymbolicObligationState::Reserved.is_terminal());
        assert!(!SymbolicObligationState::InProgress.is_terminal());
        assert!(SymbolicObligationState::Committed.is_terminal());
        assert!(SymbolicObligationState::Aborted.is_terminal());
        assert!(SymbolicObligationState::Leaked.is_terminal());

        assert!(SymbolicObligationState::Committed.is_success());
        assert!(SymbolicObligationState::Aborted.is_success());
        assert!(!SymbolicObligationState::Leaked.is_success());

        assert!(SymbolicObligationState::Leaked.is_leaked());
        assert!(!SymbolicObligationState::Committed.is_leaked());
    }

    #[test]
    fn registry_create_and_lookup() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();
        let params = test_params();

        let obligation = registry.create_send_object(object, &params, holder, region, Time::ZERO);

        // Registry should have indexed it.
        assert_eq!(registry.obligations_for_region(region).len(), 1);
        assert_eq!(registry.obligations_for_task(holder).len(), 1);
        assert_eq!(registry.obligations_for_object(object).len(), 1);
        assert!(registry.has_pending_in_region(region));

        let pending = registry.pending_in_region(region);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].kind, SymbolicObligationKind::SendObject);

        // Commit resolves - update registry state.
        let oid = obligation.id();
        obligation.commit();
        registry.update_state(oid, SymbolicObligationState::Committed);

        assert!(!registry.has_pending_in_region(region));
    }

    #[test]
    fn registry_multiple_obligations() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let sym1 = SymbolId::new(object, 0, 0);
        let sym2 = SymbolId::new(object, 0, 1);

        let o1 = registry.create_send_symbol(sym1, holder, region, Time::ZERO);
        let o2 = registry.create_send_symbol(sym2, holder, region, Time::ZERO);

        assert_eq!(registry.obligations_for_object(object).len(), 2);
        assert!(registry.has_pending_in_region(region));

        let o1_id = o1.id();
        let o2_id = o2.id();
        o1.commit();
        registry.update_state(o1_id, SymbolicObligationState::Committed);

        // Still has pending because o2 is unresolved.
        assert!(registry.has_pending_in_region(region));

        o2.abort();
        registry.update_state(o2_id, SymbolicObligationState::Aborted);

        assert!(!registry.has_pending_in_region(region));
    }

    #[test]
    fn registry_decode_obligation() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let obligation = registry.create_decode(object, 4, holder, region, Time::ZERO);
        assert_eq!(obligation.kind(), SymbolicObligationKind::DecodeObject);
        assert_eq!(obligation.progress().total, 4);

        obligation.fulfill_many(4);
        assert!(obligation.progress().complete);
        obligation.commit();
    }

    #[test]
    fn registry_acknowledge_obligation() {
        let registry = SymbolicObligationRegistry::new();
        let holder = test_task_id();
        let region = test_region_id();
        let object = test_object_id();

        let obligation = registry.create_acknowledge(object, 8, holder, region, Time::ZERO);
        assert_eq!(
            obligation.kind(),
            SymbolicObligationKind::AcknowledgeReceipt
        );
        assert_eq!(obligation.progress().total, 8);

        obligation.abort();
    }
}
