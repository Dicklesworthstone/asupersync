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

use crate::util::DetHashMap;
use core::fmt;
use parking_lot::RwLock;
use smallvec::SmallVec;
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
        self.add(1);
    }

    /// Increments by a specific amount.
    pub fn add(&self, count: u32) {
        let _ = self
            .fulfilled
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(count))
            });
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
        percent_complete(self.total, self.fulfilled())
    }

    /// Returns a snapshot of the current progress.
    #[must_use]
    pub fn snapshot(&self) -> FulfillmentSnapshot {
        let fulfilled = self.fulfilled();
        FulfillmentSnapshot {
            total: self.total,
            fulfilled,
            percent: percent_complete(self.total, fulfilled),
            complete: fulfilled >= self.total,
        }
    }

    /// Returns the remaining count.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.total.saturating_sub(self.fulfilled())
    }
}

fn percent_complete(total: u32, fulfilled: u32) -> f64 {
    if total == 0 {
        1.0
    } else {
        f64::from(fulfilled.min(total)) / f64::from(total)
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
    /// Exact symbol identity when this obligation targets a single symbol.
    expected_symbol: Option<SymbolId>,
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
    /// Optional registry mirror for state synchronization and deregistration.
    registry: Option<RegistryMirror>,
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
    fn new_send_object(
        id: ObligationId,
        object_id: ObjectId,
        params: &ObjectParams,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        registry: Option<RegistryMirror>,
    ) -> Self {
        let total_symbols = params.total_source_symbols();

        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::SendObject,
                object_id,
                expected_symbol: None,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(total_symbols),
                created_at,
                registry,
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for sending a single symbol.
    #[must_use]
    fn new_send_symbol(
        id: ObligationId,
        symbol_id: SymbolId,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        registry: Option<RegistryMirror>,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::SendSymbol,
                object_id: symbol_id.object_id(),
                expected_symbol: Some(symbol_id),
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(1),
                created_at,
                registry,
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for acknowledging receipt.
    #[must_use]
    fn new_acknowledge(
        id: ObligationId,
        object_id: ObjectId,
        expected_count: u32,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        registry: Option<RegistryMirror>,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::AcknowledgeReceipt,
                object_id,
                expected_symbol: None,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(expected_count),
                created_at,
                registry,
            }),
            resolved: false,
        }
    }

    /// Creates a new obligation for decoding.
    #[must_use]
    fn new_decode(
        id: ObligationId,
        object_id: ObjectId,
        min_symbols: u32,
        holder: TaskId,
        region: RegionId,
        created_at: Time,
        registry: Option<RegistryMirror>,
    ) -> Self {
        Self {
            state: Arc::new(ObligationInner {
                id,
                kind: SymbolicObligationKind::DecodeObject,
                object_id,
                expected_symbol: None,
                holder,
                region,
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(min_symbols),
                created_at,
                registry,
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

    fn sync_registry_state(&self, state: SymbolicObligationState) {
        if let Some(registry) = &self.state.registry {
            if state.is_terminal() {
                registry.unregister(self.id(), self.object_id(), self.holder(), self.region());
            } else if let Some(entry) = registry.by_id.write().get_mut(&self.id()) {
                entry.state = state;
            }
        }
    }

    fn set_state(&self, state: SymbolicObligationState) {
        *self.state.state.write() = state;
        self.sync_registry_state(state);
    }

    fn validate_fulfilled_symbol(&self, symbol_id: SymbolId) {
        assert_eq!(
            symbol_id.object_id(),
            self.object_id(),
            "fulfilled symbol object mismatch: expected {}, got {}",
            self.object_id(),
            symbol_id.object_id()
        );
        if let Some(expected_symbol) = self.state.expected_symbol {
            assert_eq!(
                symbol_id, expected_symbol,
                "fulfilled symbol mismatch: expected {expected_symbol}, got {symbol_id}"
            );
        }
    }

    /// Marks progress on partial fulfillment.
    ///
    /// Call this as symbols are sent/received to track progress.
    pub fn fulfill_one(&self, symbol_id: SymbolId) {
        self.validate_fulfilled_symbol(symbol_id);
        self.state.progress.increment();

        // Transition to InProgress if still Reserved
        let mut state = self.state.state.write();
        if *state == SymbolicObligationState::Reserved {
            *state = SymbolicObligationState::InProgress;
            drop(state);
            self.sync_registry_state(SymbolicObligationState::InProgress);
        }
    }

    /// Marks multiple symbols as fulfilled.
    pub fn fulfill_many(&self, count: u32) {
        assert!(
            self.state.expected_symbol.is_none(),
            "fulfill_many is invalid for single-symbol obligations; use fulfill_one with the expected SymbolId"
        );
        self.state.progress.add(count);

        let mut state = self.state.state.write();
        if *state == SymbolicObligationState::Reserved {
            *state = SymbolicObligationState::InProgress;
            drop(state);
            self.sync_registry_state(SymbolicObligationState::InProgress);
        }
    }

    /// Commits the obligation (successful completion).
    ///
    /// # Panics
    ///
    /// Panics if already resolved.
    pub fn commit(mut self) {
        assert!(self.is_pending(), "obligation already resolved");

        self.set_state(SymbolicObligationState::Committed);
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

        self.set_state(SymbolicObligationState::Aborted);
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
        self.set_state(SymbolicObligationState::Leaked);
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
                expected_symbol: None,
                holder: TaskId::from_arena(ArenaIndex::new(0, 0)),
                region: RegionId::from_arena(ArenaIndex::new(0, 1)),
                state: RwLock::new(SymbolicObligationState::Reserved),
                progress: FulfillmentProgress::new(total),
                created_at: Time::from_nanos(1_000_000_000),
                registry: None,
            }),
            resolved: false,
        }
    }
}

impl Drop for SymbolicObligation {
    fn drop(&mut self) {
        if !self.resolved && self.is_pending() {
            self.mark_leaked();

            // If the thread is already panicking, we don't want to double-panic and abort.
            if std::thread::panicking() {
                return;
            }

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
pub(crate) struct ObligationEntry {
    id: ObligationId,
    kind: SymbolicObligationKind,
    object_id: ObjectId,
    holder: TaskId,
    #[allow(dead_code)]
    created_at: Time,
    state: SymbolicObligationState,
}

#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct RegistryMirror {
    by_id: Arc<RwLock<DetHashMap<ObligationId, ObligationEntry>>>,
    by_object: Arc<RwLock<DetHashMap<ObjectId, Vec<ObligationId>>>>,
    by_holder: Arc<RwLock<Vec<HolderSlot>>>,
    by_region: Arc<RwLock<Vec<RegionSlot>>>,
}

impl RegistryMirror {
    fn unregister(&self, id: ObligationId, object_id: ObjectId, holder: TaskId, region: RegionId) {
        self.by_id.write().remove(&id);

        let mut by_object = self.by_object.write();
        let remove_object_entry = by_object.get_mut(&object_id).is_some_and(|ids| {
            ids.retain(|current| *current != id);
            ids.is_empty()
        });
        if remove_object_entry {
            by_object.remove(&object_id);
        }
        drop(by_object);

        remove_obligation_from_holder_slot(&self.by_holder, holder, id);
        remove_obligation_from_region_slot(&self.by_region, region, id);
    }
}

type ObligationIds = SmallVec<[ObligationId; 4]>;
type HolderSlot = SmallVec<[(TaskId, ObligationIds); 1]>;
type RegionSlot = SmallVec<[(RegionId, ObligationIds); 1]>;

#[allow(clippy::significant_drop_tightening)]
fn remove_obligation_from_holder_slot(
    by_holder: &Arc<RwLock<Vec<HolderSlot>>>,
    holder: TaskId,
    id: ObligationId,
) {
    let holder_slot = holder.arena_index().index() as usize;
    let mut guard = by_holder.write();
    let Some(entries) = guard.get_mut(holder_slot) else {
        return;
    };
    let Some(position) = entries
        .iter()
        .position(|(stored_holder, _)| *stored_holder == holder)
    else {
        return;
    };
    entries[position].1.retain(|current| *current != id);
    if entries[position].1.is_empty() {
        entries.remove(position);
    }
}

#[allow(clippy::significant_drop_tightening)]
fn remove_obligation_from_region_slot(
    by_region: &Arc<RwLock<Vec<RegionSlot>>>,
    region: RegionId,
    id: ObligationId,
) {
    let region_slot = region.arena_index().index() as usize;
    let mut guard = by_region.write();
    let Some(entries) = guard.get_mut(region_slot) else {
        return;
    };
    let Some(position) = entries
        .iter()
        .position(|(stored_region, _)| *stored_region == region)
    else {
        return;
    };
    entries[position].1.retain(|current| *current != id);
    if entries[position].1.is_empty() {
        entries.remove(position);
    }
}

/// Registry that tracks all active symbolic obligations.
///
/// Provides indexed lookup by ID, object, task, and region. Used by the
/// runtime to detect leaked obligations and check region quiescence.
///
/// br-asupersync-zhtjy9: backed by [`DetHashMap`] (project-fixed
/// SipHash seed) instead of `std::collections::HashMap` (random
/// per-process seed). The pre-fix shape produced different
/// iteration orders across processes, so leak-detection reports
/// and region-quiescence summaries diverged across replays;
/// crashpack hashes that incorporated the registry contents were
/// instable. Same fix-shape as the closed asupersync-q6vujm /
/// asupersync-ks0t6j / asupersync-jg4yyx (sibling
/// `types/symbol_set.rs` fix in this same commit).
pub struct SymbolicObligationRegistry {
    /// Obligations by ID.
    by_id: Arc<RwLock<DetHashMap<ObligationId, ObligationEntry>>>,
    /// Obligations by object ID.
    by_object: Arc<RwLock<DetHashMap<ObjectId, Vec<ObligationId>>>>,
    /// Obligations by holder task (arena-slot indexed, generation-safe).
    by_holder: Arc<RwLock<Vec<HolderSlot>>>,
    /// Obligations by region (arena-slot indexed, generation-safe).
    by_region: Arc<RwLock<Vec<RegionSlot>>>,
    /// Next obligation ID.
    next_id: AtomicU64,
}

impl SymbolicObligationRegistry {
    /// Creates a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_id: Arc::new(RwLock::new(DetHashMap::default())),
            by_object: Arc::new(RwLock::new(DetHashMap::default())),
            by_holder: Arc::new(RwLock::new(Vec::new())),
            by_region: Arc::new(RwLock::new(Vec::new())),
            next_id: AtomicU64::new(1),
        }
    }

    fn registry_mirror(&self) -> RegistryMirror {
        RegistryMirror {
            by_id: Arc::clone(&self.by_id),
            by_object: Arc::clone(&self.by_object),
            by_holder: Arc::clone(&self.by_holder),
            by_region: Arc::clone(&self.by_region),
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
        let obligation = SymbolicObligation::new_send_object(
            id,
            object_id,
            params,
            holder,
            region,
            now,
            Some(self.registry_mirror()),
        );
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
        let obligation = SymbolicObligation::new_send_symbol(
            id,
            symbol_id,
            holder,
            region,
            now,
            Some(self.registry_mirror()),
        );
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
        let obligation = SymbolicObligation::new_acknowledge(
            id,
            object_id,
            expected_count,
            holder,
            region,
            now,
            Some(self.registry_mirror()),
        );
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
        let obligation = SymbolicObligation::new_decode(
            id,
            object_id,
            min_symbols,
            holder,
            region,
            now,
            Some(self.registry_mirror()),
        );
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
        if let Some(entries) = guard.get(slot) {
            if let Some((_, ids)) = entries
                .iter()
                .find(|(stored_region, _)| *stored_region == region)
            {
                return ids.to_vec();
            }
        }
        drop(guard);
        Vec::new()
    }

    /// Returns obligation IDs for a task.
    #[must_use]
    pub fn obligations_for_task(&self, task: TaskId) -> Vec<ObligationId> {
        let slot = task.arena_index().index() as usize;
        let guard = self.by_holder.read();
        if let Some(entries) = guard.get(slot) {
            if let Some((_, ids)) = entries.iter().find(|(stored_task, _)| *stored_task == task) {
                return ids.to_vec();
            }
        }
        drop(guard);
        Vec::new()
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
            by_region.get(slot).and_then(|entries| {
                entries
                    .iter()
                    .find(|(stored_region, _)| *stored_region == region)
                    .map(|(_, ids)| ids.clone())
            })
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
            by_region.get(slot).and_then(|entries| {
                entries
                    .iter()
                    .find(|(stored_region, _)| *stored_region == region)
                    .map(|(_, ids)| ids.clone())
            })
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
        let index = u32::try_from(raw)
            .expect("symbolic obligation id overflow: arena index exhausted for obligations");
        ObligationId::from_arena(ArenaIndex::new(index, 0))
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
                by_holder.resize_with(holder_slot + 1, SmallVec::new);
            }
            let entries = &mut by_holder[holder_slot];
            if let Some((_, ids)) = entries
                .iter_mut()
                .find(|(stored_holder, _)| *stored_holder == holder)
            {
                ids.push(id);
            } else {
                let mut ids = SmallVec::new();
                ids.push(id);
                entries.push((holder, ids));
            }
            drop(by_holder);
        }
        {
            let region_slot = region.arena_index().index() as usize;
            let mut by_region = self.by_region.write();
            if region_slot >= by_region.len() {
                by_region.resize_with(region_slot + 1, SmallVec::new);
            }
            let entries = &mut by_region[region_slot];
            if let Some((_, ids)) = entries
                .iter_mut()
                .find(|(stored_region, _)| *stored_region == region)
            {
                ids.push(id);
            } else {
                let mut ids = SmallVec::new();
                ids.push(id);
                entries.push((region, ids));
            }
            drop(by_region);
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
#[path = "symbolic_obligation_inline_tests.rs"]
mod tests;
