//! Symbol broadcast cancellation protocol implementation.
//!
//! Provides [`SymbolCancelToken`] for embedding cancellation in symbol metadata,
//! [`CancelMessage`] for broadcast propagation, [`CancelBroadcaster`] for
//! coordinating cancellation across peers, and [`CleanupCoordinator`] for
//! managing partial symbol set cleanup.

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::types::symbol::{ObjectId, Symbol};
use crate::types::{Budget, CancelKind, CancelReason, Time};
use crate::util::DetRng;

// ============================================================================
// CancelKind wire-format helpers
// ============================================================================

fn cancel_kind_to_u8(kind: CancelKind) -> u8 {
    match kind {
        CancelKind::User => 0,
        CancelKind::Timeout => 1,
        CancelKind::Deadline => 2,
        CancelKind::PollQuota => 3,
        CancelKind::CostBudget => 4,
        CancelKind::FailFast => 5,
        CancelKind::RaceLost => 6,
        CancelKind::ParentCancelled => 7,
        CancelKind::ResourceUnavailable => 8,
        CancelKind::Shutdown => 9,
    }
}

fn cancel_kind_from_u8(b: u8) -> Option<CancelKind> {
    match b {
        0 => Some(CancelKind::User),
        1 => Some(CancelKind::Timeout),
        2 => Some(CancelKind::Deadline),
        3 => Some(CancelKind::PollQuota),
        4 => Some(CancelKind::CostBudget),
        5 => Some(CancelKind::FailFast),
        6 => Some(CancelKind::RaceLost),
        7 => Some(CancelKind::ParentCancelled),
        8 => Some(CancelKind::ResourceUnavailable),
        9 => Some(CancelKind::Shutdown),
        _ => None,
    }
}

// ============================================================================
// Cancel Listener
// ============================================================================

/// Trait for cancellation listeners.
pub trait CancelListener: Send + Sync {
    /// Called when cancellation is requested.
    fn on_cancel(&self, reason: &CancelReason, at: Time);
}

impl<F> CancelListener for F
where
    F: Fn(&CancelReason, Time) + Send + Sync,
{
    fn on_cancel(&self, reason: &CancelReason, at: Time) {
        self(reason, at);
    }
}

// ============================================================================
// SymbolCancelToken
// ============================================================================

/// Internal shared state for a cancellation token.
struct CancelTokenState {
    /// Unique token ID.
    token_id: u64,
    /// The object this token relates to.
    object_id: ObjectId,
    /// Whether cancellation has been requested.
    cancelled: AtomicBool,
    /// When cancellation was requested (nanos since epoch, 0 = not cancelled).
    cancelled_at: AtomicU64,
    /// The cancellation reason (set when cancelled).
    reason: RwLock<Option<CancelReason>>,
    /// Cleanup budget for this cancellation.
    cleanup_budget: Budget,
    /// Child tokens (for hierarchical cancellation).
    children: RwLock<Vec<SymbolCancelToken>>,
    /// Listeners to notify on cancellation.
    listeners: RwLock<Vec<Box<dyn CancelListener>>>,
}

/// A cancellation token that can be embedded in symbol metadata.
///
/// Tokens are lightweight identifiers that reference a shared cancellation
/// state. They can be cloned and distributed across symbol transmissions.
/// When cancelled, all children and listeners are notified.
#[derive(Clone)]
pub struct SymbolCancelToken {
    /// Shared state for this cancellation token.
    state: Arc<CancelTokenState>,
}

impl SymbolCancelToken {
    /// Creates a new cancellation token for an object.
    #[must_use]
    pub fn new(object_id: ObjectId, rng: &mut DetRng) -> Self {
        Self {
            state: Arc::new(CancelTokenState {
                token_id: rng.next_u64(),
                object_id,
                cancelled: AtomicBool::new(false),
                cancelled_at: AtomicU64::new(0),
                reason: RwLock::new(None),
                cleanup_budget: Budget::default(),
                children: RwLock::new(Vec::new()),
                listeners: RwLock::new(Vec::new()),
            }),
        }
    }

    /// Creates a token with a specific cleanup budget.
    #[must_use]
    pub fn with_budget(object_id: ObjectId, budget: Budget, rng: &mut DetRng) -> Self {
        Self {
            state: Arc::new(CancelTokenState {
                token_id: rng.next_u64(),
                object_id,
                cancelled: AtomicBool::new(false),
                cancelled_at: AtomicU64::new(0),
                reason: RwLock::new(None),
                cleanup_budget: budget,
                children: RwLock::new(Vec::new()),
                listeners: RwLock::new(Vec::new()),
            }),
        }
    }

    /// Returns the token ID.
    #[must_use]
    pub fn token_id(&self) -> u64 {
        self.state.token_id
    }

    /// Returns the object ID this token relates to.
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.state.object_id
    }

    /// Returns true if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
    }

    /// Returns the cancellation reason, if cancelled.
    #[must_use]
    pub fn reason(&self) -> Option<CancelReason> {
        self.state.reason.read().expect("lock poisoned").clone()
    }

    /// Returns when cancellation was requested, if cancelled.
    #[must_use]
    pub fn cancelled_at(&self) -> Option<Time> {
        let nanos = self.state.cancelled_at.load(Ordering::SeqCst);
        if nanos == 0 {
            None
        } else {
            Some(Time::from_nanos(nanos))
        }
    }

    /// Returns the cleanup budget.
    #[must_use]
    pub fn cleanup_budget(&self) -> Budget {
        self.state.cleanup_budget
    }

    /// Requests cancellation with the given reason.
    ///
    /// Returns true if this call triggered the cancellation (first caller wins).
    #[allow(clippy::must_use_candidate)]
    pub fn cancel(&self, reason: &CancelReason, now: Time) -> bool {
        if self
            .state
            .cancelled
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.state
                .cancelled_at
                .store(now.as_nanos(), Ordering::SeqCst);
            *self.state.reason.write().expect("lock poisoned") = Some(reason.clone());

            // Notify listeners
            for listener in self.state.listeners.read().expect("lock poisoned").iter() {
                listener.on_cancel(reason, now);
            }

            // Cancel children
            for child in self.state.children.read().expect("lock poisoned").iter() {
                let parent_reason = CancelReason::parent_cancelled();
                child.cancel(&parent_reason, now);
            }

            true
        } else {
            false
        }
    }

    /// Creates a child token linked to this one.
    ///
    /// When this token is cancelled, the child is also cancelled.
    #[must_use]
    pub fn child(&self, rng: &mut DetRng) -> Self {
        let child = Self::new(self.state.object_id, rng);

        // If already cancelled, cancel child immediately
        if self.is_cancelled() {
            if let Some(at) = self.cancelled_at() {
                let parent_reason = CancelReason::parent_cancelled();
                child.cancel(&parent_reason, at);
            }
        } else {
            // Register child for future propagation
            self.state
                .children
                .write()
                .expect("lock poisoned")
                .push(child.clone());
        }

        child
    }

    /// Adds a listener to be notified on cancellation.
    pub fn add_listener(&self, listener: impl CancelListener + 'static) {
        // If already cancelled, notify immediately
        if self.is_cancelled() {
            if let (Some(reason), Some(at)) = (self.reason(), self.cancelled_at()) {
                listener.on_cancel(&reason, at);
                return;
            }
        }

        self.state
            .listeners
            .write()
            .expect("lock poisoned")
            .push(Box::new(listener));
    }

    /// Serializes the token for embedding in symbol metadata.
    ///
    /// Wire format (25 bytes): token_id(8) + object_high(8) + object_low(8) + cancelled(1).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TOKEN_WIRE_SIZE);

        buf.extend_from_slice(&self.state.token_id.to_be_bytes());
        buf.extend_from_slice(&self.state.object_id.high().to_be_bytes());
        buf.extend_from_slice(&self.state.object_id.low().to_be_bytes());
        buf.push(u8::from(self.is_cancelled()));

        buf
    }

    /// Deserializes a token from bytes.
    ///
    /// Note: This creates a new token state; it does not link to the original.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < TOKEN_WIRE_SIZE {
            return None;
        }

        let token_id = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let high = u64::from_be_bytes(data[8..16].try_into().ok()?);
        let low = u64::from_be_bytes(data[16..24].try_into().ok()?);
        let cancelled = data[24] != 0;

        Some(Self {
            state: Arc::new(CancelTokenState {
                token_id,
                object_id: ObjectId::new(high, low),
                cancelled: AtomicBool::new(cancelled),
                cancelled_at: AtomicU64::new(0),
                reason: RwLock::new(None),
                cleanup_budget: Budget::default(),
                children: RwLock::new(Vec::new()),
                listeners: RwLock::new(Vec::new()),
            }),
        })
    }

    /// Creates a token for testing.
    #[doc(hidden)]
    #[must_use]
    pub fn new_for_test(token_id: u64, object_id: ObjectId) -> Self {
        Self {
            state: Arc::new(CancelTokenState {
                token_id,
                object_id,
                cancelled: AtomicBool::new(false),
                cancelled_at: AtomicU64::new(0),
                reason: RwLock::new(None),
                cleanup_budget: Budget::default(),
                children: RwLock::new(Vec::new()),
                listeners: RwLock::new(Vec::new()),
            }),
        }
    }
}

impl fmt::Debug for SymbolCancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolCancelToken")
            .field("token_id", &format!("{:016x}", self.state.token_id))
            .field("object_id", &self.state.object_id)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Token wire format size: token_id(8) + high(8) + low(8) + cancelled(1) = 25.
const TOKEN_WIRE_SIZE: usize = 25;

// ============================================================================
// CancelMessage
// ============================================================================

/// A cancellation message that can be broadcast to peers.
///
/// Messages include a hop counter to prevent infinite propagation and a
/// sequence number for deduplication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelMessage {
    /// The token ID being cancelled.
    token_id: u64,
    /// The object ID being cancelled.
    object_id: ObjectId,
    /// The cancellation kind.
    kind: CancelKind,
    /// When the cancellation was initiated.
    initiated_at: Time,
    /// Sequence number for deduplication.
    sequence: u64,
    /// Hop count (for limiting propagation).
    hops: u8,
    /// Maximum hops allowed.
    max_hops: u8,
}

/// Message wire format size: token_id(8) + high(8) + low(8) + kind(1) +
/// initiated_at(8) + sequence(8) + hops(1) + max_hops(1) = 43.
const MESSAGE_WIRE_SIZE: usize = 43;

impl CancelMessage {
    /// Creates a new cancellation message.
    #[must_use]
    pub fn new(
        token_id: u64,
        object_id: ObjectId,
        kind: CancelKind,
        initiated_at: Time,
        sequence: u64,
    ) -> Self {
        Self {
            token_id,
            object_id,
            kind,
            initiated_at,
            sequence,
            hops: 0,
            max_hops: 10,
        }
    }

    /// Returns the token ID.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// Returns the object ID.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the cancellation kind.
    #[must_use]
    pub const fn kind(&self) -> CancelKind {
        self.kind
    }

    /// Returns when the cancellation was initiated.
    #[must_use]
    pub const fn initiated_at(&self) -> Time {
        self.initiated_at
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the current hop count.
    #[must_use]
    pub const fn hops(&self) -> u8 {
        self.hops
    }

    /// Returns true if the message can be forwarded (not at max hops).
    #[must_use]
    pub const fn can_forward(&self) -> bool {
        self.hops < self.max_hops
    }

    /// Creates a forwarded copy with incremented hop count.
    #[must_use]
    pub fn forwarded(&self) -> Option<Self> {
        if !self.can_forward() {
            return None;
        }

        Some(Self {
            hops: self.hops + 1,
            ..self.clone()
        })
    }

    /// Sets the maximum hops.
    #[must_use]
    pub const fn with_max_hops(mut self, max: u8) -> Self {
        self.max_hops = max;
        self
    }

    /// Serializes to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MESSAGE_WIRE_SIZE);

        buf.extend_from_slice(&self.token_id.to_be_bytes());
        buf.extend_from_slice(&self.object_id.high().to_be_bytes());
        buf.extend_from_slice(&self.object_id.low().to_be_bytes());
        buf.push(cancel_kind_to_u8(self.kind));
        buf.extend_from_slice(&self.initiated_at.as_nanos().to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.push(self.hops);
        buf.push(self.max_hops);

        buf
    }

    /// Deserializes from bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < MESSAGE_WIRE_SIZE {
            return None;
        }

        let token_id = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let high = u64::from_be_bytes(data[8..16].try_into().ok()?);
        let low = u64::from_be_bytes(data[16..24].try_into().ok()?);
        let kind = cancel_kind_from_u8(data[24])?;
        let initiated_at = Time::from_nanos(u64::from_be_bytes(data[25..33].try_into().ok()?));
        let sequence = u64::from_be_bytes(data[33..41].try_into().ok()?);
        let hops = data[41];
        let max_hops = data[42];

        Some(Self {
            token_id,
            object_id: ObjectId::new(high, low),
            kind,
            initiated_at,
            sequence,
            hops,
            max_hops,
        })
    }
}

// ============================================================================
// PeerId
// ============================================================================

/// Peer identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(String);

impl PeerId {
    /// Creates a new peer ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ============================================================================
// CancelSink trait
// ============================================================================

/// Trait for sending cancellation messages to peers.
pub trait CancelSink: Send + Sync {
    /// Sends a cancellation message to a specific peer.
    fn send_to(
        &self,
        peer: &PeerId,
        msg: &CancelMessage,
    ) -> impl std::future::Future<Output = crate::error::Result<()>> + Send;

    /// Broadcasts a cancellation message to all peers.
    fn broadcast(
        &self,
        msg: &CancelMessage,
    ) -> impl std::future::Future<Output = crate::error::Result<usize>> + Send;
}

// ============================================================================
// CancelBroadcastMetrics
// ============================================================================

/// Metrics for cancellation broadcast.
#[derive(Clone, Debug, Default)]
pub struct CancelBroadcastMetrics {
    /// Cancellations initiated locally.
    pub initiated: u64,
    /// Cancellations received from peers.
    pub received: u64,
    /// Cancellations forwarded to peers.
    pub forwarded: u64,
    /// Duplicate cancellations ignored.
    pub duplicates: u64,
    /// Cancellations that reached max hops.
    pub max_hops_reached: u64,
}

// ============================================================================
// CancelBroadcaster
// ============================================================================

/// Coordinates cancellation broadcast across peers.
///
/// The broadcaster tracks active cancellation tokens, deduplicates messages,
/// and forwards cancellations within hop limits. Sync methods
/// ([`prepare_cancel`][Self::prepare_cancel], [`receive_message`][Self::receive_message])
/// handle the core logic; async methods ([`cancel`][Self::cancel],
/// [`handle_message`][Self::handle_message]) add network dispatch.
pub struct CancelBroadcaster<S: CancelSink> {
    /// Known peers.
    peers: RwLock<Vec<PeerId>>,
    /// Active cancellation tokens by object ID.
    active_tokens: RwLock<HashMap<ObjectId, SymbolCancelToken>>,
    /// Seen message sequences for deduplication.
    seen_sequences: RwLock<HashSet<(u64, u64)>>,
    /// Maximum seen sequences to retain.
    max_seen: usize,
    /// Broadcast sink for sending messages.
    sink: S,
    /// Local sequence counter.
    next_sequence: AtomicU64,
    /// Metrics.
    metrics: RwLock<CancelBroadcastMetrics>,
}

impl<S: CancelSink> CancelBroadcaster<S> {
    /// Creates a new broadcaster with the given sink.
    pub fn new(sink: S) -> Self {
        Self {
            peers: RwLock::new(Vec::new()),
            active_tokens: RwLock::new(HashMap::new()),
            seen_sequences: RwLock::new(HashSet::new()),
            max_seen: 10_000,
            sink,
            next_sequence: AtomicU64::new(0),
            metrics: RwLock::new(CancelBroadcastMetrics::default()),
        }
    }

    /// Registers a peer.
    pub fn add_peer(&self, peer: PeerId) {
        let mut peers = self.peers.write().expect("lock poisoned");
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }

    /// Removes a peer.
    pub fn remove_peer(&self, peer: &PeerId) {
        self.peers
            .write()
            .expect("lock poisoned")
            .retain(|p| p != peer);
    }

    /// Registers a cancellation token for an object.
    pub fn register_token(&self, token: SymbolCancelToken) {
        self.active_tokens
            .write()
            .expect("lock poisoned")
            .insert(token.object_id(), token);
    }

    /// Unregisters a token.
    pub fn unregister_token(&self, object_id: &ObjectId) {
        self.active_tokens
            .write()
            .expect("lock poisoned")
            .remove(object_id);
    }

    /// Cancels a local token and creates a broadcast message.
    ///
    /// This is the synchronous core of [`cancel`][Self::cancel]. It cancels the
    /// local token, creates a dedup-tracked message, and returns it for dispatch.
    pub fn prepare_cancel(
        &self,
        object_id: ObjectId,
        reason: &CancelReason,
        now: Time,
    ) -> CancelMessage {
        // Cancel local token
        if let Some(token) = self
            .active_tokens
            .read()
            .expect("lock poisoned")
            .get(&object_id)
        {
            token.cancel(reason, now);
        }

        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);
        let msg = CancelMessage::new(
            object_id.as_u128() as u64,
            object_id,
            reason.kind(),
            now,
            sequence,
        );

        self.mark_seen(msg.token_id(), sequence);
        self.metrics.write().expect("lock poisoned").initiated += 1;

        msg
    }

    /// Handles a received cancellation message synchronously.
    ///
    /// Returns the forwarded message if the message should be relayed, or `None`
    /// if the message was a duplicate or reached max hops. This is the
    /// synchronous core of [`handle_message`][Self::handle_message].
    pub fn receive_message(&self, msg: &CancelMessage, now: Time) -> Option<CancelMessage> {
        // Check for duplicate
        if self.is_seen(msg.token_id(), msg.sequence()) {
            self.metrics.write().expect("lock poisoned").duplicates += 1;
            return None;
        }

        self.mark_seen(msg.token_id(), msg.sequence());
        self.metrics.write().expect("lock poisoned").received += 1;

        // Cancel local token if present
        if let Some(token) = self
            .active_tokens
            .read()
            .expect("lock poisoned")
            .get(&msg.object_id())
        {
            let reason = CancelReason::new(msg.kind());
            token.cancel(&reason, now);
        }

        // Forward if allowed
        msg.forwarded().map_or_else(
            || {
                self.metrics
                    .write()
                    .expect("lock poisoned")
                    .max_hops_reached += 1;
                None
            },
            |forwarded| {
                self.metrics.write().expect("lock poisoned").forwarded += 1;
                Some(forwarded)
            },
        )
    }

    /// Initiates cancellation and broadcasts to peers.
    pub async fn cancel(
        &self,
        object_id: ObjectId,
        reason: &CancelReason,
        now: Time,
    ) -> crate::error::Result<usize> {
        let msg = self.prepare_cancel(object_id, reason, now);
        self.sink.broadcast(&msg).await
    }

    /// Handles a received cancellation message and forwards if appropriate.
    pub async fn handle_message(&self, msg: CancelMessage, now: Time) -> crate::error::Result<()> {
        if let Some(forwarded) = self.receive_message(&msg, now) {
            self.sink.broadcast(&forwarded).await?;
        }
        Ok(())
    }

    /// Returns a snapshot of current metrics.
    #[must_use]
    pub fn metrics(&self) -> CancelBroadcastMetrics {
        self.metrics.read().expect("lock poisoned").clone()
    }

    fn is_seen(&self, token_id: u64, sequence: u64) -> bool {
        self.seen_sequences
            .read()
            .expect("lock poisoned")
            .contains(&(token_id, sequence))
    }

    fn mark_seen(&self, token_id: u64, sequence: u64) {
        let mut seen = self.seen_sequences.write().expect("lock poisoned");
        seen.insert((token_id, sequence));

        // Simple eviction when capacity exceeded
        if seen.len() > self.max_seen {
            let to_remove: Vec<_> = seen.iter().take(self.max_seen / 2).copied().collect();
            for key in to_remove {
                seen.remove(&key);
            }
        }
    }
}

// ============================================================================
// Cleanup types
// ============================================================================

/// Trait for cleanup handlers.
pub trait CleanupHandler: Send + Sync {
    /// Called to clean up symbols for a cancelled object.
    ///
    /// Returns the number of symbols cleaned up.
    #[allow(clippy::result_large_err)]
    fn cleanup(&self, object_id: ObjectId, symbols: Vec<Symbol>) -> crate::error::Result<usize>;

    /// Returns the name of this handler (for logging).
    fn name(&self) -> &str;
}

/// A set of symbols pending cleanup.
struct PendingSymbolSet {
    /// The object ID.
    object_id: ObjectId,
    /// Accumulated symbols.
    symbols: Vec<Symbol>,
    /// Total bytes.
    total_bytes: usize,
    /// When the set was created.
    _created_at: Time,
}

/// Result of a cleanup operation.
#[derive(Clone, Debug)]
pub struct CleanupResult {
    /// The object ID.
    pub object_id: ObjectId,
    /// Number of symbols cleaned up.
    pub symbols_cleaned: usize,
    /// Bytes freed.
    pub bytes_freed: usize,
    /// Whether cleanup completed within budget.
    pub within_budget: bool,
    /// Handlers that ran.
    pub handlers_run: Vec<String>,
}

/// Statistics about pending cleanups.
#[derive(Clone, Debug, Default)]
pub struct CleanupStats {
    /// Number of objects with pending symbols.
    pub pending_objects: usize,
    /// Total pending symbols.
    pub pending_symbols: usize,
    /// Total pending bytes.
    pub pending_bytes: usize,
}

/// Coordinates cleanup of partial symbol sets.
pub struct CleanupCoordinator {
    /// Pending symbol sets by object ID.
    pending: RwLock<HashMap<ObjectId, PendingSymbolSet>>,
    /// Cleanup handlers by object ID.
    handlers: RwLock<HashMap<ObjectId, Box<dyn CleanupHandler>>>,
    /// Default cleanup budget.
    default_budget: Budget,
}

impl CleanupCoordinator {
    /// Creates a new cleanup coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            handlers: RwLock::new(HashMap::new()),
            default_budget: Budget::new().with_poll_quota(1000),
        }
    }

    /// Sets the default cleanup budget.
    #[must_use]
    pub fn with_default_budget(mut self, budget: Budget) -> Self {
        self.default_budget = budget;
        self
    }

    /// Registers symbols as pending for an object.
    #[allow(clippy::significant_drop_tightening)]
    pub fn register_pending(&self, object_id: ObjectId, symbol: Symbol, now: Time) {
        let mut pending = self.pending.write().expect("lock poisoned");
        let set = pending
            .entry(object_id)
            .or_insert_with(|| PendingSymbolSet {
                object_id,
                symbols: Vec::new(),
                total_bytes: 0,
                _created_at: now,
            });

        set.total_bytes += symbol.len();
        set.symbols.push(symbol);
    }

    /// Registers a cleanup handler for an object.
    pub fn register_handler(&self, object_id: ObjectId, handler: impl CleanupHandler + 'static) {
        self.handlers
            .write()
            .expect("lock poisoned")
            .insert(object_id, Box::new(handler));
    }

    /// Clears pending symbols for an object (e.g., after successful decode).
    pub fn clear_pending(&self, object_id: &ObjectId) -> Option<usize> {
        self.pending
            .write()
            .expect("lock poisoned")
            .remove(object_id)
            .map(|set| set.symbols.len())
    }

    /// Triggers cleanup for a cancelled object.
    pub fn cleanup(&self, object_id: ObjectId, budget: Option<Budget>) -> CleanupResult {
        let budget = budget.unwrap_or(self.default_budget);
        let mut symbols_cleaned = 0;
        let mut bytes_freed = 0;
        let mut handlers_run = Vec::new();
        let mut polls_used: u32 = 0;

        // Get pending symbols
        let pending_set = self
            .pending
            .write()
            .expect("lock poisoned")
            .remove(&object_id);

        if let Some(set) = pending_set {
            symbols_cleaned = set.symbols.len();
            bytes_freed = set.total_bytes;

            // Run registered handler
            if let Some(handler) = self.handlers.read().expect("lock poisoned").get(&object_id) {
                handlers_run.push(handler.name().to_string());
                polls_used += 1;

                if polls_used < budget.poll_quota {
                    let _ = handler.cleanup(object_id, set.symbols);
                }
            }
        }

        // Remove handler
        self.handlers
            .write()
            .expect("lock poisoned")
            .remove(&object_id);

        CleanupResult {
            object_id,
            symbols_cleaned,
            bytes_freed,
            within_budget: polls_used < budget.poll_quota,
            handlers_run,
        }
    }

    /// Returns statistics about pending cleanups.
    #[must_use]
    pub fn stats(&self) -> CleanupStats {
        let pending = self.pending.read().expect("lock poisoned");

        let mut total_symbols = 0;
        let mut total_bytes = 0;

        for set in pending.values() {
            total_symbols += set.symbols.len();
            total_bytes += set.total_bytes;
        }

        CleanupStats {
            pending_objects: pending.len(),
            pending_symbols: total_symbols,
            pending_bytes: total_bytes,
        }
    }
}

impl Default for CleanupCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::symbol::{ObjectId, Symbol};

    struct NullSink;

    impl CancelSink for NullSink {
        fn send_to(
            &self,
            _peer: &PeerId,
            _msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<()>> + Send {
            std::future::ready(Ok(()))
        }

        fn broadcast(
            &self,
            _msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<usize>> + Send {
            std::future::ready(Ok(0))
        }
    }

    #[test]
    fn test_token_creation() {
        let mut rng = DetRng::new(42);
        let obj = ObjectId::new_for_test(1);
        let token = SymbolCancelToken::new(obj, &mut rng);

        assert_eq!(token.object_id(), obj);
        assert!(!token.is_cancelled());
        assert!(token.reason().is_none());
        assert!(token.cancelled_at().is_none());
    }

    #[test]
    fn test_token_cancel_once() {
        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let now = Time::from_millis(100);
        let reason = CancelReason::user("test");

        // First cancel succeeds
        assert!(token.cancel(&reason, now));
        assert!(token.is_cancelled());
        assert_eq!(token.reason().unwrap().kind, CancelKind::User);
        assert_eq!(token.cancelled_at(), Some(now));

        // Second cancel returns false
        assert!(!token.cancel(&CancelReason::timeout(), Time::from_millis(200)));

        // Reason unchanged
        assert_eq!(token.reason().unwrap().kind, CancelKind::User);
    }

    #[test]
    fn test_token_reason_propagates() {
        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let reason = CancelReason::timeout().with_message("timed out");
        token.cancel(&reason, Time::from_millis(500));

        let stored = token.reason().unwrap();
        assert_eq!(stored.kind, CancelKind::Timeout);
        assert_eq!(stored.message, Some("timed out"));
    }

    #[test]
    fn test_token_child_inherits_cancellation() {
        let mut rng = DetRng::new(42);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        let child = parent.child(&mut rng);

        assert!(!child.is_cancelled());

        // Cancel parent
        parent.cancel(&CancelReason::user("test"), Time::from_millis(100));

        // Child should be cancelled too
        assert!(child.is_cancelled());
        assert_eq!(child.reason().unwrap().kind, CancelKind::ParentCancelled);
    }

    #[test]
    fn test_token_listener_notified() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut rng = DetRng::new(42);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let notified = Arc::new(AtomicBool::new(false));
        let notified_clone = notified.clone();

        token.add_listener(move |_reason: &CancelReason, _at: Time| {
            notified_clone.store(true, Ordering::SeqCst);
        });

        assert!(!notified.load(Ordering::SeqCst));

        token.cancel(&CancelReason::user("test"), Time::from_millis(100));

        assert!(notified.load(Ordering::SeqCst));
    }

    #[test]
    fn test_token_serialization() {
        let mut rng = DetRng::new(42);
        let obj = ObjectId::new(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210);
        let token = SymbolCancelToken::new(obj, &mut rng);

        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), TOKEN_WIRE_SIZE);

        let parsed = SymbolCancelToken::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.token_id(), token.token_id());
        assert_eq!(parsed.object_id(), token.object_id());
        assert!(!parsed.is_cancelled());
    }

    #[test]
    fn test_message_serialization() {
        let msg = CancelMessage::new(
            0x1234_5678_9abc_def0,
            ObjectId::new_for_test(42),
            CancelKind::Timeout,
            Time::from_millis(1000),
            999,
        )
        .with_max_hops(5);

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), MESSAGE_WIRE_SIZE);

        let parsed = CancelMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.token_id(), msg.token_id());
        assert_eq!(parsed.object_id(), msg.object_id());
        assert_eq!(parsed.kind(), msg.kind());
        assert_eq!(parsed.initiated_at(), msg.initiated_at());
        assert_eq!(parsed.sequence(), msg.sequence());
    }

    #[test]
    fn test_message_hop_limit() {
        let msg = CancelMessage::new(
            1,
            ObjectId::new_for_test(1),
            CancelKind::User,
            Time::from_millis(100),
            0,
        )
        .with_max_hops(3);

        assert!(msg.can_forward());
        assert_eq!(msg.hops(), 0);

        let msg1 = msg.forwarded().unwrap();
        assert_eq!(msg1.hops(), 1);

        let msg2 = msg1.forwarded().unwrap();
        assert_eq!(msg2.hops(), 2);

        let msg3 = msg2.forwarded().unwrap();
        assert_eq!(msg3.hops(), 3);

        // At max hops, can't forward
        assert!(msg3.forwarded().is_none());
        assert!(!msg3.can_forward());
    }

    #[test]
    fn test_broadcaster_deduplication() {
        let broadcaster = CancelBroadcaster::new(NullSink);
        let msg = CancelMessage::new(
            1,
            ObjectId::new_for_test(1),
            CancelKind::User,
            Time::from_millis(100),
            0,
        );
        let now = Time::from_millis(100);

        // First receive should process
        let _ = broadcaster.receive_message(&msg, now);

        // Second receive should be duplicate
        let result = broadcaster.receive_message(&msg, now);
        assert!(result.is_none());

        let metrics = broadcaster.metrics();
        assert_eq!(metrics.received, 1);
        assert_eq!(metrics.duplicates, 1);
    }

    #[test]
    fn test_broadcaster_forwards_message() {
        let broadcaster = CancelBroadcaster::new(NullSink);
        let msg = CancelMessage::new(
            1,
            ObjectId::new_for_test(1),
            CancelKind::User,
            Time::from_millis(100),
            0,
        );

        let forwarded = broadcaster.receive_message(&msg, Time::from_millis(100));
        assert!(forwarded.is_some());
        assert_eq!(forwarded.unwrap().hops(), 1);

        let metrics = broadcaster.metrics();
        assert_eq!(metrics.received, 1);
        assert_eq!(metrics.forwarded, 1);
    }

    #[test]
    fn test_cleanup_pending_symbols() {
        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(1);
        let now = Time::from_millis(100);

        // Register some symbols
        for i in 0..5 {
            let symbol = Symbol::new_for_test(1, 0, i, &[1, 2, 3, 4]);
            coordinator.register_pending(object_id, symbol, now);
        }

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 1);
        assert_eq!(stats.pending_symbols, 5);
        assert_eq!(stats.pending_bytes, 20); // 5 * 4 bytes

        // Cleanup
        let result = coordinator.cleanup(object_id, None);
        assert_eq!(result.symbols_cleaned, 5);
        assert_eq!(result.bytes_freed, 20);
        assert!(result.within_budget);

        // Stats should be zero
        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 0);
    }

    #[test]
    fn test_cleanup_within_budget() {
        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(1);
        let now = Time::from_millis(100);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3, 4]);
        coordinator.register_pending(object_id, symbol, now);

        // Generous budget
        let budget = Budget::new().with_poll_quota(1000);
        let result = coordinator.cleanup(object_id, Some(budget));
        assert!(result.within_budget);
    }

    #[test]
    fn test_cleanup_handler_called() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct TestHandler {
            called: Arc<AtomicBool>,
        }

        impl CleanupHandler for TestHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                self.called.store(true, Ordering::SeqCst);
                Ok(0)
            }

            fn name(&self) -> &str {
                "test"
            }
        }

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(1);
        let now = Time::from_millis(100);

        let called = Arc::new(AtomicBool::new(false));
        coordinator.register_handler(
            object_id,
            TestHandler {
                called: called.clone(),
            },
        );

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2]);
        coordinator.register_pending(object_id, symbol, now);

        let result = coordinator.cleanup(object_id, None);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(result.handlers_run, vec!["test"]);
    }

    #[test]
    fn test_cleanup_stats_accurate() {
        let coordinator = CleanupCoordinator::new();
        let now = Time::from_millis(100);

        // Empty stats
        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 0);
        assert_eq!(stats.pending_symbols, 0);
        assert_eq!(stats.pending_bytes, 0);

        // Add symbols for two objects
        let obj1 = ObjectId::new_for_test(1);
        let obj2 = ObjectId::new_for_test(2);

        coordinator.register_pending(obj1, Symbol::new_for_test(1, 0, 0, &[1, 2, 3]), now);
        coordinator.register_pending(obj1, Symbol::new_for_test(1, 0, 1, &[4, 5, 6]), now);
        coordinator.register_pending(obj2, Symbol::new_for_test(2, 0, 0, &[7, 8]), now);

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 2);
        assert_eq!(stats.pending_symbols, 3);
        assert_eq!(stats.pending_bytes, 8); // 3 + 3 + 2

        // Clear one object
        coordinator.clear_pending(&obj1);

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 1);
        assert_eq!(stats.pending_symbols, 1);
        assert_eq!(stats.pending_bytes, 2);
    }
}
