//! Symbol broadcast cancellation protocol implementation.
//!
//! Provides [`SymbolCancelToken`] for embedding cancellation in symbol metadata,
//! [`CancelMessage`] for broadcast propagation, [`CancelBroadcaster`] for
//! coordinating cancellation across peers, and [`CleanupCoordinator`] for
//! managing partial symbol set cleanup.

use core::fmt;
use parking_lot::RwLock;
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

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
        CancelKind::LinkedExit => 10,
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
        10 => Some(CancelKind::LinkedExit),
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
    children: RwLock<SmallVec<[SymbolCancelToken; 2]>>,
    /// Listeners to notify on cancellation.
    listeners: RwLock<SmallVec<[Box<dyn CancelListener>; 2]>>,
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
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
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
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
            }),
        }
    }

    /// Returns the token ID.
    #[must_use]
    pub fn token_id(&self) -> u64 {
        self.state.token_id
    }

    /// Returns the object ID this token relates to.
    #[inline]
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.state.object_id
    }

    /// Returns true if cancellation has been requested.
    #[inline]
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    /// Returns the cancellation reason, if cancelled.
    #[must_use]
    pub fn reason(&self) -> Option<CancelReason> {
        self.state.reason.read().clone()
    }

    /// Returns when cancellation was requested, if cancelled.
    #[inline]
    #[must_use]
    pub fn cancelled_at(&self) -> Option<Time> {
        let nanos = self.state.cancelled_at.load(Ordering::Acquire);
        if nanos == 0 {
            if self.is_cancelled() {
                Some(Time::ZERO)
            } else {
                None
            }
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
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.state
                .cancelled_at
                .store(now.as_nanos(), Ordering::Release);
            *self.state.reason.write() = Some(reason.clone());

            let listeners = {
                let mut listeners = self.state.listeners.write();
                std::mem::take(&mut *listeners)
            };

            // Notify listeners without holding the lock to avoid reentrancy deadlocks.
            for listener in listeners {
                listener.on_cancel(reason, now);
            }

            // Drain children without holding the lock. Safe because
            // `cancelled` is already true (CAS above), so any concurrent
            // `child()` will observe the flag and cancel directly instead
            // of pushing into this vec.
            let children = {
                let mut children = self.state.children.write();
                std::mem::take(&mut *children)
            };
            let parent_reason = CancelReason::parent_cancelled();
            for child in children {
                child.cancel(&parent_reason, now);
            }

            true
        } else {
            // Already cancelled. Strengthen the stored reason if the new
            // one is more severe, preserving the monotone-severity
            // invariant required by the cancellation protocol.
            let mut reason_guard = self.state.reason.write();
            match *reason_guard {
                Some(ref mut stored) => {
                    stored.strengthen(reason);
                }
                None => {
                    *reason_guard = Some(reason.clone());
                }
            }
            false
        }
    }

    /// Creates a child token linked to this one.
    ///
    /// When this token is cancelled, the child is also cancelled.
    #[must_use]
    pub fn child(&self, rng: &mut DetRng) -> Self {
        let child = Self::new(self.state.object_id, rng);

        // Hold the children lock across the cancelled check to avoid a TOCTOU
        // race: cancel() sets the `cancelled` flag (Release) *before* reading
        // children, so if we observe !cancelled (Acquire) under the write lock
        // the subsequent cancel() will see our child when it reads the list.
        let mut children = self.state.children.write();
        if self.is_cancelled() {
            drop(children);
            if let Some(at) = self.cancelled_at() {
                let parent_reason = CancelReason::parent_cancelled();
                child.cancel(&parent_reason, at);
            }
        } else {
            children.push(child.clone());
        }

        child
    }

    /// Adds a listener to be notified on cancellation.
    pub fn add_listener(&self, listener: impl CancelListener + 'static) {
        // Hold the listeners lock across the cancelled check to avoid a TOCTOU
        // race: cancel() sets the `cancelled` flag (Release) *before* draining
        // listeners, so if we observe !cancelled (Acquire) under the write lock
        // the subsequent cancel() will find our listener when it drains.
        let mut listeners = self.state.listeners.write();
        if self.is_cancelled() {
            drop(listeners);
            let reason = self
                .reason()
                .unwrap_or_else(|| CancelReason::new(CancelKind::User));
            if let Some(at) = self.cancelled_at() {
                listener.on_cancel(&reason, at);
            }
        } else {
            listeners.push(Box::new(listener));
        }
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
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
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
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
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
    peers: RwLock<SmallVec<[PeerId; 4]>>,
    /// Active cancellation tokens by object ID.
    active_tokens: RwLock<HashMap<ObjectId, SymbolCancelToken>>,
    /// Seen message sequences for deduplication (with insertion order).
    seen_sequences: RwLock<SeenSequences>,
    /// Maximum seen sequences to retain.
    max_seen: usize,
    /// Broadcast sink for sending messages.
    sink: S,
    /// Local sequence counter.
    next_sequence: AtomicU64,
    /// Atomic metrics counters.
    initiated: AtomicU64,
    received: AtomicU64,
    forwarded: AtomicU64,
    duplicates: AtomicU64,
    max_hops_reached: AtomicU64,
}

/// Deterministic dedup tracking with bounded memory.
type SeenKey = (ObjectId, u64, u64);

#[derive(Debug, Default)]
struct SeenSequences {
    set: HashSet<SeenKey>,
    order: VecDeque<SeenKey>,
}

impl SeenSequences {
    fn insert(&mut self, key: SeenKey) -> bool {
        if self.set.insert(key) {
            self.order.push_back(key);
            true
        } else {
            false
        }
    }

    fn remove_oldest(&mut self) -> Option<SeenKey> {
        let oldest = self.order.pop_front()?;
        self.set.remove(&oldest);
        Some(oldest)
    }
}

impl<S: CancelSink> CancelBroadcaster<S> {
    /// Creates a new broadcaster with the given sink.
    pub fn new(sink: S) -> Self {
        Self {
            peers: RwLock::new(SmallVec::new()),
            active_tokens: RwLock::new(HashMap::new()),
            seen_sequences: RwLock::new(SeenSequences::default()),
            max_seen: 10_000,
            sink,
            next_sequence: AtomicU64::new(0),
            initiated: AtomicU64::new(0),
            received: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            max_hops_reached: AtomicU64::new(0),
        }
    }

    /// Registers a peer.
    pub fn add_peer(&self, peer: PeerId) {
        let mut peers = self.peers.write();
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }

    /// Removes a peer.
    pub fn remove_peer(&self, peer: &PeerId) {
        self.peers.write().retain(|p| p != peer);
    }

    /// Registers a cancellation token for an object.
    pub fn register_token(&self, token: SymbolCancelToken) {
        self.active_tokens.write().insert(token.object_id(), token);
    }

    /// Unregisters a token.
    pub fn unregister_token(&self, object_id: &ObjectId) {
        self.active_tokens.write().remove(object_id);
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
        // Single read lock: cancel local token + extract token_id.
        let token_id = {
            let tokens = self.active_tokens.read();
            if let Some(token) = tokens.get(&object_id) {
                token.cancel(reason, now);
                token.token_id()
            } else {
                object_id.high() ^ object_id.low()
            }
        };

        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let msg = CancelMessage::new(token_id, object_id, reason.kind(), now, sequence);

        self.mark_seen(object_id, msg.token_id(), sequence);
        self.initiated.fetch_add(1, Ordering::Relaxed);

        msg
    }

    /// Handles a received cancellation message synchronously.
    ///
    /// Returns the forwarded message if the message should be relayed, or `None`
    /// if the message was a duplicate or reached max hops. This is the
    /// synchronous core of [`handle_message`][Self::handle_message].
    pub fn receive_message(&self, msg: &CancelMessage, now: Time) -> Option<CancelMessage> {
        // Check for duplicate
        if self.is_seen(msg.object_id(), msg.token_id(), msg.sequence()) {
            self.duplicates.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        self.mark_seen(msg.object_id(), msg.token_id(), msg.sequence());
        self.received.fetch_add(1, Ordering::Relaxed);

        // Cancel local token if present
        if let Some(token) = self.active_tokens.read().get(&msg.object_id()) {
            let reason = CancelReason::new(msg.kind());
            token.cancel(&reason, now);
        }

        // Forward if allowed
        msg.forwarded().map_or_else(
            || {
                self.max_hops_reached.fetch_add(1, Ordering::Relaxed);
                None
            },
            |forwarded| {
                self.forwarded.fetch_add(1, Ordering::Relaxed);
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
        CancelBroadcastMetrics {
            initiated: self.initiated.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            max_hops_reached: self.max_hops_reached.load(Ordering::Relaxed),
        }
    }

    fn is_seen(&self, object_id: ObjectId, token_id: u64, sequence: u64) -> bool {
        self.seen_sequences
            .read()
            .set
            .contains(&(object_id, token_id, sequence))
    }

    fn mark_seen(&self, object_id: ObjectId, token_id: u64, sequence: u64) {
        let mut seen = self.seen_sequences.write();
        let inserted = seen.insert((object_id, token_id, sequence));
        if !inserted {
            return;
        }

        // Deterministic eviction: remove oldest until under cap.
        while seen.set.len() > self.max_seen {
            if seen.remove_oldest().is_none() {
                break;
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
    fn name(&self) -> &'static str;
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
        let mut pending = self.pending.write();
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
        self.handlers.write().insert(object_id, Box::new(handler));
    }

    /// Clears pending symbols for an object (e.g., after successful decode).
    pub fn clear_pending(&self, object_id: &ObjectId) -> Option<usize> {
        self.pending
            .write()
            .remove(object_id)
            .map(|set| set.symbols.len())
    }

    /// Triggers cleanup for a cancelled object.
    #[allow(unused_assignments)] // polls_used tracking for future multi-handler support
    pub fn cleanup(&self, object_id: ObjectId, budget: Option<Budget>) -> CleanupResult {
        let budget = budget.unwrap_or(self.default_budget);
        let mut symbols_cleaned = 0;
        let mut bytes_freed = 0;
        let mut handlers_run = Vec::new();
        let mut polls_used: u32 = 0;
        let mut within_budget = true;
        // Remove the handler up front so callback execution never happens
        // while holding the handlers lock (avoids re-entrant deadlocks).
        let handler = self.handlers.write().remove(&object_id);

        // Get pending symbols
        let pending_set = self.pending.write().remove(&object_id);

        if let Some(set) = pending_set {
            symbols_cleaned = set.symbols.len();
            bytes_freed = set.total_bytes;

            // Run registered handler
            if let Some(handler) = handler {
                if polls_used < budget.poll_quota {
                    polls_used += 1;
                    handlers_run.push(handler.name().to_string());
                    let _ = handler.cleanup(object_id, set.symbols);
                } else {
                    within_budget = false;
                }
            }
        }

        CleanupResult {
            object_id,
            symbols_cleaned,
            bytes_freed,
            within_budget,
            handlers_run,
        }
    }

    /// Returns statistics about pending cleanups.
    #[must_use]
    pub fn stats(&self) -> CleanupStats {
        let pending = self.pending.read();

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
        let cancel_handle = SymbolCancelToken::new(obj, &mut rng);

        assert_eq!(cancel_handle.object_id(), obj);
        assert!(!cancel_handle.is_cancelled());
        assert!(cancel_handle.reason().is_none());
        assert!(cancel_handle.cancelled_at().is_none());
    }

    #[test]
    fn test_token_cancel_once() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let now = Time::from_millis(100);
        let reason = CancelReason::user("test");

        // First cancel succeeds
        assert!(cancel_handle.cancel(&reason, now));
        assert!(cancel_handle.is_cancelled());
        assert_eq!(cancel_handle.reason().unwrap().kind, CancelKind::User);
        assert_eq!(cancel_handle.cancelled_at(), Some(now));

        // Second cancel returns false (not first caller) but strengthens
        assert!(!cancel_handle.cancel(&CancelReason::timeout(), Time::from_millis(200)));

        // Reason strengthened to Timeout (more severe than User)
        assert_eq!(cancel_handle.reason().unwrap().kind, CancelKind::Timeout);
    }

    #[test]
    fn test_token_reason_propagates() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let reason = CancelReason::timeout().with_message("timed out");
        cancel_handle.cancel(&reason, Time::from_millis(500));

        let stored = cancel_handle.reason().unwrap();
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
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let notified = Arc::new(AtomicBool::new(false));
        let notified_clone = notified.clone();

        cancel_handle.add_listener(move |_reason: &CancelReason, _at: Time| {
            notified_clone.store(true, Ordering::SeqCst);
        });

        assert!(!notified.load(Ordering::SeqCst));

        cancel_handle.cancel(&CancelReason::user("test"), Time::from_millis(100));

        assert!(notified.load(Ordering::SeqCst));
    }

    #[test]
    fn test_token_serialization() {
        let mut rng = DetRng::new(42);
        let obj = ObjectId::new(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210);
        let cancel_handle = SymbolCancelToken::new(obj, &mut rng);

        let bytes = cancel_handle.to_bytes();
        assert_eq!(bytes.len(), TOKEN_WIRE_SIZE);

        let parsed = SymbolCancelToken::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.token_id(), cancel_handle.token_id());
        assert_eq!(parsed.object_id(), cancel_handle.object_id());
        assert!(!parsed.is_cancelled());
    }

    #[test]
    fn test_token_cancel_sets_reason_when_already_cancelled() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        cancel_handle.cancel(&CancelReason::user("initial"), Time::from_millis(100));

        let parsed = SymbolCancelToken::from_bytes(&cancel_handle.to_bytes()).unwrap();
        assert!(parsed.is_cancelled());
        assert!(parsed.reason().is_none());

        let reason = CancelReason::timeout();
        assert!(!parsed.cancel(&reason, Time::from_millis(200)));
        assert_eq!(parsed.reason().unwrap().kind, CancelKind::Timeout);
    }

    #[test]
    fn test_deserialized_cancelled_token_notifies_listener() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        cancel_handle.cancel(&CancelReason::user("initial"), Time::from_millis(100));

        let parsed = SymbolCancelToken::from_bytes(&cancel_handle.to_bytes()).unwrap();
        assert!(parsed.is_cancelled());

        let notified = Arc::new(AtomicBool::new(false));
        let notified_clone = Arc::clone(&notified);
        parsed.add_listener(move |_reason: &CancelReason, _at: Time| {
            notified_clone.store(true, Ordering::SeqCst);
        });

        assert!(notified.load(Ordering::SeqCst));
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
    fn test_prepare_cancel_uses_token_id() {
        let mut rng = DetRng::new(7);
        let object_id = ObjectId::new_for_test(42);
        let cancel_handle = SymbolCancelToken::new(object_id, &mut rng);
        let token_id = cancel_handle.token_id();

        let broadcaster = CancelBroadcaster::new(NullSink);
        broadcaster.register_token(cancel_handle);

        let msg = broadcaster.prepare_cancel(
            object_id,
            &CancelReason::user("cancel"),
            Time::from_millis(10),
        );
        assert_eq!(msg.token_id(), token_id);
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
    fn test_broadcaster_seen_eviction_is_fifo() {
        let mut broadcaster = CancelBroadcaster::new(NullSink);
        broadcaster.max_seen = 3;
        let object_id = ObjectId::new_for_test(1);

        // Insert 4 distinct sequences; oldest should be evicted.
        for seq in 0..4 {
            broadcaster.mark_seen(object_id, 1, seq);
        }

        let (len, has_10, has_11, front) = {
            let seen = broadcaster.seen_sequences.read();
            let len = seen.set.len();
            let has_10 = seen.set.contains(&(object_id, 1, 0));
            let has_11 = seen.set.contains(&(object_id, 1, 1));
            let front = seen.order.front().copied();
            drop(seen);
            (len, has_10, has_11, front)
        };
        assert_eq!(len, 3);
        assert!(!has_10);
        assert!(has_11);
        assert_eq!(front, Some((object_id, 1, 1)));
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

            fn name(&self) -> &'static str {
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
    fn test_cleanup_handler_invoked_without_holding_handler_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct LockCheckHandler {
            coordinator: Arc<CleanupCoordinator>,
            write_lock_available: Arc<AtomicBool>,
        }

        impl CleanupHandler for LockCheckHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                let can_acquire_write = self.coordinator.handlers.try_write().is_some();
                self.write_lock_available
                    .store(can_acquire_write, Ordering::SeqCst);
                Ok(0)
            }

            fn name(&self) -> &'static str {
                "lock-check"
            }
        }

        let coordinator = Arc::new(CleanupCoordinator::new());
        let object_id = ObjectId::new_for_test(99);
        let now = Time::from_millis(100);
        let write_lock_available = Arc::new(AtomicBool::new(false));

        coordinator.register_handler(
            object_id,
            LockCheckHandler {
                coordinator: Arc::clone(&coordinator),
                write_lock_available: Arc::clone(&write_lock_available),
            },
        );

        coordinator.register_pending(object_id, Symbol::new_for_test(99, 0, 0, &[1]), now);
        let _ = coordinator.cleanup(object_id, None);

        assert!(
            write_lock_available.load(Ordering::SeqCst),
            "cleanup handler callback should execute without handlers lock held"
        );
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

    // ---- Cancel propagation: grandchild inherits cancellation -----------

    #[test]
    fn test_grandchild_inherits_cancellation() {
        let mut rng = DetRng::new(42);
        let grandparent = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        let parent = grandparent.child(&mut rng);
        let child = parent.child(&mut rng);

        assert!(!child.is_cancelled());

        // Cancel grandparent — should propagate to grandchild.
        grandparent.cancel(&CancelReason::user("cascade"), Time::from_millis(100));

        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
        assert_eq!(child.reason().unwrap().kind, CancelKind::ParentCancelled);
    }

    #[test]
    fn test_cancel_drains_children_and_late_child_is_not_queued() {
        let mut rng = DetRng::new(7);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(5), &mut rng);
        let child_a = parent.child(&mut rng);
        let child_b = parent.child(&mut rng);

        assert_eq!(
            parent.state.children.read().len(),
            2,
            "precondition: both children should be queued under parent"
        );

        let now = Time::from_millis(100);
        assert!(
            parent.cancel(&CancelReason::user("drain"), now),
            "first caller should trigger cancellation"
        );
        assert!(child_a.is_cancelled(), "queued child A must be cancelled");
        assert!(child_b.is_cancelled(), "queued child B must be cancelled");
        assert_eq!(
            parent.state.children.read().len(),
            0,
            "children vector must be drained after parent cancel"
        );

        let late_child = parent.child(&mut rng);
        assert!(
            late_child.is_cancelled(),
            "late child should be cancelled immediately when parent already cancelled"
        );
        assert_eq!(
            parent.state.children.read().len(),
            0,
            "late child should not be retained in parent children vector"
        );
    }

    // ---- Cancel propagation: child cancel does not affect parent --------

    #[test]
    fn test_child_cancel_does_not_propagate_upward() {
        let mut rng = DetRng::new(42);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        let child = parent.child(&mut rng);

        // Cancel the child directly.
        child.cancel(&CancelReason::user("child only"), Time::from_millis(100));

        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }

    // ---- Cancel severity ordering: stronger reason wins -----------------

    #[test]
    fn test_cancel_strengthens_reason() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        // First cancel with User reason.
        let first = cancel_handle.cancel(&CancelReason::user("first"), Time::from_millis(100));
        assert!(first);

        // Second cancel with Shutdown reason — should strengthen.
        let second = cancel_handle.cancel(
            &CancelReason::new(CancelKind::Shutdown),
            Time::from_millis(200),
        );
        assert!(!second); // not the first caller

        // Reason strengthened to Shutdown (more severe).
        assert_eq!(cancel_handle.reason().unwrap().kind, CancelKind::Shutdown);
        // Timestamp unchanged (first cancel time preserved).
        assert_eq!(cancel_handle.cancelled_at(), Some(Time::from_millis(100)));
    }

    #[test]
    fn test_cancel_does_not_weaken_reason() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        // First cancel with Shutdown reason.
        let first = cancel_handle.cancel(
            &CancelReason::new(CancelKind::Shutdown),
            Time::from_millis(100),
        );
        assert!(first);

        // Second cancel with weaker User reason — should not weaken.
        let second = cancel_handle.cancel(&CancelReason::user("gentle"), Time::from_millis(200));
        assert!(!second);

        // Reason stays at Shutdown.
        assert_eq!(cancel_handle.reason().unwrap().kind, CancelKind::Shutdown);
    }

    // ---- Multiple listeners notified on cancel --------------------------

    #[test]
    fn test_multiple_listeners_all_notified() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let count = Arc::new(AtomicU32::new(0));

        for _ in 0..3 {
            let c = count.clone();
            cancel_handle.add_listener(move |_: &CancelReason, _: Time| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        cancel_handle.cancel(&CancelReason::timeout(), Time::from_millis(100));

        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    // ---- Cleanup coordinator: multiple objects cleaned independently -----

    #[test]
    fn test_cleanup_multiple_objects_independent() {
        let coordinator = CleanupCoordinator::new();
        let now = Time::from_millis(100);
        let obj1 = ObjectId::new_for_test(1);
        let obj2 = ObjectId::new_for_test(2);

        // Register symbols for two separate objects.
        for i in 0..3 {
            coordinator.register_pending(obj1, Symbol::new_for_test(1, 0, i, &[1, 2]), now);
        }
        for i in 0..2 {
            coordinator.register_pending(obj2, Symbol::new_for_test(2, 0, i, &[3, 4, 5]), now);
        }

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 2);
        assert_eq!(stats.pending_symbols, 5);

        // Cleanup only obj1.
        let result = coordinator.cleanup(obj1, None);
        assert_eq!(result.symbols_cleaned, 3);
        assert_eq!(result.bytes_freed, 6); // 3 * 2

        // obj2 still has its symbols.
        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 1);
        assert_eq!(stats.pending_symbols, 2);
        assert_eq!(stats.pending_bytes, 6); // 2 * 3
    }

    // ---- Token serialization roundtrip preserves all fields -------------

    #[test]
    fn test_token_serialization_roundtrip_deterministic() {
        let mut rng = DetRng::new(99);
        let obj = ObjectId::new(0xdead_beef_cafe_babe, 0x1234_5678_9abc_def0);
        let cancel_handle = SymbolCancelToken::new(obj, &mut rng);

        // Serialize and deserialize twice — should produce identical results.
        let bytes1 = cancel_handle.to_bytes();
        let parsed1 = SymbolCancelToken::from_bytes(&bytes1).unwrap();
        let bytes2 = parsed1.to_bytes();

        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
        assert_eq!(parsed1.token_id(), cancel_handle.token_id());
        assert_eq!(parsed1.object_id(), cancel_handle.object_id());
    }

    // ---- Message forwarding exhaustion ----------------------------------

    #[test]
    fn test_message_forwarding_exhausts_at_zero_hops() {
        let msg = CancelMessage::new(
            1,
            ObjectId::new_for_test(1),
            CancelKind::User,
            Time::from_millis(100),
            0,
        )
        .with_max_hops(0);

        // Cannot forward when max_hops is 0.
        assert!(!msg.can_forward());
        assert!(msg.forwarded().is_none());
    }

    // ---- Broadcaster: separate token IDs not conflated ------------------

    #[test]
    fn test_broadcaster_separate_tokens_independent() {
        let broadcaster = CancelBroadcaster::new(NullSink);

        let msg1 = CancelMessage::new(
            1,
            ObjectId::new_for_test(1),
            CancelKind::User,
            Time::from_millis(100),
            0,
        );
        let msg2 = CancelMessage::new(
            2,
            ObjectId::new_for_test(2),
            CancelKind::Timeout,
            Time::from_millis(200),
            0,
        );

        let now = Time::from_millis(100);
        let r1 = broadcaster.receive_message(&msg1, now);
        let r2 = broadcaster.receive_message(&msg2, now);

        // Both should be processed (different token IDs).
        assert!(r1.is_some());
        assert!(r2.is_some());

        let metrics = broadcaster.metrics();
        assert_eq!(metrics.received, 2);
        assert_eq!(metrics.duplicates, 0);
    }
}
