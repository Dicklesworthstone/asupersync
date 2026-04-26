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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    /// When cancellation was requested (nanos since epoch).
    /// `u64::MAX` is the "not yet recorded" sentinel; legitimate timestamps
    /// are clamped to `u64::MAX - 1` at store time so the sentinel cannot
    /// collide with a real cancellation time.
    cancelled_at: AtomicU64,
    /// The cancellation reason (set when cancelled).
    reason: RwLock<Option<CancelReason>>,
    /// Cleanup budget for this cancellation.
    cleanup_budget: Budget,
    /// Child tokens (for hierarchical cancellation).
    children: RwLock<SmallVec<[SymbolCancelToken; 2]>>,
    /// Listeners to notify on cancellation.
    ///
    /// br-asupersync-frm9u9: listeners are retained (not drained) after
    /// the first cancel so a later `cancel()` whose reason strictly
    /// strengthens the stored severity (e.g., Timeout → Shutdown) can
    /// re-fire them with the new reason. The `notified_severity` field
    /// below records the highest severity each listener has already
    /// observed so re-notification is monotone — listeners only see
    /// progressively-stronger reasons, never the same severity twice.
    listeners: RwLock<SmallVec<[ListenerEntry; 2]>>,
}

/// One registered cancel listener plus the severity at which it was
/// most recently notified. `0` means the listener has not yet been
/// notified (e.g., registered while `cancelled == false`).
struct ListenerEntry {
    listener: Box<dyn CancelListener>,
    /// Last severity the listener was notified at. Updated under the
    /// `listeners` write lock + `reason` write lock to keep the
    /// "every listener saw at least the current stored reason"
    /// invariant.
    notified_severity: u8,
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
                cancelled_at: AtomicU64::new(u64::MAX),
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
                cancelled_at: AtomicU64::new(u64::MAX),
                reason: RwLock::new(None),
                cleanup_budget: budget,
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
            }),
        }
    }

    /// Returns the token ID.
    #[inline]
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
        if nanos == u64::MAX {
            if self.is_cancelled() {
                // If it's cancelled but nanos is u64::MAX, we caught it in the middle of
                // the cancel() function. Wait for the reason lock to ensure
                // the cancel() function has finished updating cancelled_at.
                let _guard = self.state.reason.read();
                let nanos_sync = self.state.cancelled_at.load(Ordering::Acquire);
                if nanos_sync == u64::MAX {
                    None // Should only happen if parsed from bytes and reason never set
                } else {
                    Some(Time::from_nanos(nanos_sync))
                }
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
    ///
    /// # Listener re-notification on strengthened reason
    /// (br-asupersync-frm9u9)
    ///
    /// Listeners are retained across cancel calls (not drained on the
    /// first call). On the first call, every listener is notified with
    /// the supplied reason. On subsequent calls, the stored reason is
    /// strengthened via `CancelReason::strengthen`; if the strengthen
    /// strictly raised severity, every listener whose most-recently-
    /// notified severity is now below the new severity is re-notified
    /// with the strengthened reason. A listener is therefore guaranteed
    /// to observe at least the strongest cancel kind that ever arrived,
    /// in monotone order — same severity is never delivered twice.
    #[allow(clippy::must_use_candidate)]
    pub fn cancel(&self, reason: &CancelReason, now: Time) -> bool {
        // Hold the reason lock to serialize updates and ensure visibility consistency.
        // This prevents a race where a listener observes cancelled=true but reason=None.
        let mut reason_guard = self.state.reason.write();

        if self
            .state
            .cancelled
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .is_ok()
        {
            // We won the race. State is now cancelled.
            // Clamp to u64::MAX - 1 to avoid colliding with the
            // "not yet recorded" sentinel in cancelled_at queries.
            let stored_nanos = now.as_nanos().min(u64::MAX - 1);
            self.state
                .cancelled_at
                .store(stored_nanos, Ordering::Release);
            *reason_guard = Some(reason.clone());

            // Drop the reason lock before notifying to avoid reentrancy
            // deadlocks. The listeners write lock is held across the
            // notification (not drained) so add_listener that races
            // with cancel observes a consistent state — a listener
            // either lands here and is notified, or lands after the
            // notification loop finishes and finds is_cancelled=true,
            // at which point it self-notifies under the same lock.
            drop(reason_guard);

            let new_severity = reason.kind.severity();
            {
                let mut listeners = self.state.listeners.write();
                for entry in listeners.iter_mut() {
                    // Catch panics per-listener so a single misbehaving
                    // listener cannot prevent the rest from running.
                    let listener = &entry.listener;
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        listener.on_cancel(reason, now);
                    }));
                    entry.notified_severity = new_severity;
                }
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
            //
            // Since we hold the write lock, and the winner releases the lock
            // only after writing Some(reason), we are guaranteed to see
            // the existing reason here.
            let prior_severity;
            let strengthened_reason;
            if let Some(ref mut stored) = *reason_guard {
                prior_severity = stored.kind.severity();
                stored.strengthen(reason);
                strengthened_reason = stored.clone();
            } else {
                // Unreachable under the new locking protocol; handle
                // safely for the from_bytes-then-cancel edge.
                prior_severity = 0;
                *reason_guard = Some(reason.clone());
                strengthened_reason = reason.clone();
                let stored_nanos = now.as_nanos().min(u64::MAX - 1);
                self.state
                    .cancelled_at
                    .compare_exchange(u64::MAX, stored_nanos, Ordering::Release, Ordering::Relaxed)
                    .ok();
            }
            let new_severity = strengthened_reason.kind.severity();

            drop(reason_guard);

            // br-asupersync-frm9u9: re-notify any listener whose last
            // observed severity is strictly below the new (strengthened)
            // severity. Listeners that already saw an equal-or-stronger
            // reason are skipped to keep delivery monotone and
            // idempotent at each severity level.
            if new_severity > prior_severity {
                let mut listeners = self.state.listeners.write();
                for entry in listeners.iter_mut() {
                    if entry.notified_severity < new_severity {
                        let listener = &entry.listener;
                        let reason_ref = &strengthened_reason;
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            listener.on_cancel(reason_ref, now);
                        }));
                        entry.notified_severity = new_severity;
                    }
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
            let at = self.cancelled_at().unwrap_or(Time::ZERO);
            let parent_reason = CancelReason::parent_cancelled();
            child.cancel(&parent_reason, at);
        } else {
            children.push(child.clone());
        }

        child
    }

    /// Adds a listener to be notified on cancellation.
    ///
    /// # Race-free reason snapshot (br-asupersync-2bm1a3)
    ///
    /// Previous behaviour: `add_listener` checked `is_cancelled()`, then
    /// dropped the listeners lock and called `self.reason()` which only
    /// took a *read* lock. Between `cancel()`'s release of the
    /// `cancelled` Release-CAS and its write of the reason under the
    /// `reason.write()` lock, a racing `add_listener` could observe
    /// `cancelled == true` but read `reason() == None`. The fallback
    /// `unwrap_or_else(|| CancelReason::new(CancelKind::User))` then
    /// fabricated a `CancelKind::User @ Time::ZERO` notification — a
    /// silent protocol-misclassification (a cleanup handler that
    /// distinguishes `User` from `Timeout`/`Shutdown` would route the
    /// task down the wrong branch).
    ///
    /// New behaviour: this method takes the `reason.write()` lock
    /// itself, mirroring the discipline `cancel()` uses. Either it
    /// observes `cancelled == false` and pushes the listener (cancel
    /// will pick it up under the same lock), or it observes
    /// `cancelled == true` AND finds the stored reason already
    /// written. If the stored reason is somehow `None` despite
    /// `cancelled == true` (e.g., a `from_bytes` round-trip without
    /// `cancel()` ever being called locally), the function falls back
    /// to the parent-cancel reason and asserts in debug builds — never
    /// fabricates a `CancelKind::User`.
    pub fn add_listener(&self, listener: impl CancelListener + 'static) {
        // Take the reason lock first (mirrors cancel()'s ordering:
        // reason → listeners → drop reason → take listeners). Holding
        // the reason lock here makes the cancelled-check race-free:
        // cancel() can only flip `cancelled` while holding this same
        // write lock, so we either see (false, _) or (true, Some(_)).
        let reason_guard = self.state.reason.write();
        let mut listeners = self.state.listeners.write();
        if self.state.cancelled.load(Ordering::Acquire) {
            // We're cancelled. The reason MUST be Some at this point
            // because cancel() writes the reason under this same
            // write lock before flipping the cancelled flag (CAS at
            // line ~218 with the reason write held). The from_bytes
            // path is the only way to reach Some(cancelled)+None
            // (parsed-from-wire token never had cancel() called
            // locally); in that case fall back to parent_cancelled
            // — never to the silent CancelKind::User fabrication.
            let reason = reason_guard.clone().unwrap_or_else(|| {
                debug_assert!(
                    false,
                    "add_listener observed cancelled=true with reason=None — \
                     locking discipline violated (br-asupersync-2bm1a3)"
                );
                CancelReason::parent_cancelled()
            });
            let at = self.cancelled_at().unwrap_or_else(|| Time::from_nanos(0));
            // Drop both locks before invoking the listener so a
            // listener that re-enters the token (e.g., to read
            // reason()) does not deadlock on this thread. The
            // listener fires synchronously on the calling thread
            // here and is NOT retained — re-notification on a later
            // strengthen does not apply to listeners added after
            // cancel completed. This mirrors the pre-fix
            // post-cancel-add semantic; documented in the
            // type-level rustdoc.
            drop(listeners);
            drop(reason_guard);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                listener.on_cancel(&reason, at);
            }));
        } else {
            listeners.push(ListenerEntry {
                listener: Box::new(listener),
                notified_severity: 0,
            });
            drop(listeners);
            drop(reason_guard);
        }
    }

    /// Serializes the token for embedding in symbol metadata.
    ///
    /// Wire format (25 bytes): token_id(8) + object_high(8) + object_low(8) + cancelled(1).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TOKEN_WIRE_SIZE] {
        let mut buf = [0u8; TOKEN_WIRE_SIZE];

        buf[0..8].copy_from_slice(&self.state.token_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.state.object_id.high().to_be_bytes());
        buf[16..24].copy_from_slice(&self.state.object_id.low().to_be_bytes());
        buf[24] = u8::from(self.is_cancelled());

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
                cancelled_at: AtomicU64::new(u64::MAX),
                reason: RwLock::new(None),
                cleanup_budget: Budget::default(),
                children: RwLock::new(SmallVec::new()),
                listeners: RwLock::new(SmallVec::new()),
            }),
        })
    }

    /// Creates a token for testing.
    ///
    /// br-asupersync-wm9h2a: previously this was an unconditionally
    /// `pub` constructor — gated only by `#[doc(hidden)]`, which
    /// hides the method from rustdoc but does NOT prevent production
    /// callers from invoking it. That left an open capability-
    /// boundary hole: any code in the dependency graph could mint a
    /// `SymbolCancelToken` with arbitrary `(token_id, object_id)`
    /// values, bypass the `CancelBroadcaster::register` /
    /// `prepare_cancel` issuance path, and forge cancels for objects
    /// it never owned. The asupersync 'no ambient authority'
    /// invariant requires every capability-bearing token to flow
    /// through an explicit issuance ceremony.
    ///
    /// The fix is to gate the constructor behind
    /// `#[cfg(any(test, feature = "test-internals"))]`. The
    /// `test-internals` feature is the project's documented escape
    /// hatch for test scaffolding (see Cargo.toml feature flags) —
    /// production builds (which do NOT enable `test-internals`) lose
    /// access to this constructor entirely, eliminating the forgery
    /// path. Tests that need to mint synthetic tokens either:
    ///   1. live in `#[cfg(test)]` modules inside this crate, or
    ///   2. enable the `test-internals` feature in their Cargo deps.
    /// Both are already the project's stated convention.
    #[doc(hidden)]
    #[must_use]
    #[cfg(any(test, feature = "test-internals"))]
    pub fn new_for_test(token_id: u64, object_id: ObjectId) -> Self {
        Self {
            state: Arc::new(CancelTokenState {
                token_id,
                object_id,
                cancelled: AtomicBool::new(false),
                cancelled_at: AtomicU64::new(u64::MAX),
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
    #[inline]
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// Returns the object ID.
    #[inline]
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the cancellation kind.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> CancelKind {
        self.kind
    }

    /// Returns when the cancellation was initiated.
    #[inline]
    #[must_use]
    pub const fn initiated_at(&self) -> Time {
        self.initiated_at
    }

    /// Returns the sequence number.
    #[inline]
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the current hop count.
    #[inline]
    #[must_use]
    pub const fn hops(&self) -> u8 {
        self.hops
    }

    /// Returns true if the message can be forwarded (not at max hops).
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn with_max_hops(mut self, max: u8) -> Self {
        self.max_hops = max;
        self
    }

    /// Serializes to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MESSAGE_WIRE_SIZE] {
        let mut buf = [0u8; MESSAGE_WIRE_SIZE];

        buf[0..8].copy_from_slice(&self.token_id.to_be_bytes());
        buf[8..16].copy_from_slice(&self.object_id.high().to_be_bytes());
        buf[16..24].copy_from_slice(&self.object_id.low().to_be_bytes());
        buf[24] = cancel_kind_to_u8(self.kind);
        buf[25..33].copy_from_slice(&self.initiated_at.as_nanos().to_be_bytes());
        buf[33..41].copy_from_slice(&self.sequence.to_be_bytes());
        buf[41] = self.hops;
        buf[42] = self.max_hops;

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
    #[inline]
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Returns the ID as a string slice.
    #[inline]
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
        // Extract token and ID without holding the lock during cancel.
        let (token, token_id) = {
            let tokens = self.active_tokens.read();
            tokens.get(&object_id).map_or_else(
                || (None, object_id.high() ^ object_id.low()),
                |token| (Some(token.clone()), token.token_id()),
            )
        };

        if let Some(token) = token {
            token.cancel(reason, now);
        }

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
        let token = self.active_tokens.read().get(&msg.object_id()).cloned(); // ubs:ignore - internal cancellation token, not a secret
        if let Some(token) = token {
            let reason = CancelReason::new(msg.kind()).with_timestamp(msg.initiated_at());
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
    ///
    /// Return `Err(...)` if the batch could not be completed. The coordinator
    /// preserves the pending set for a later retry on the error path.
    #[allow(clippy::result_large_err)]
    fn cleanup(&self, object_id: ObjectId, symbols: Vec<Symbol>) -> crate::error::Result<usize>;

    /// Returns the name of this handler (for logging).
    fn name(&self) -> &'static str;
}

/// A set of symbols pending cleanup.
#[derive(Clone)]
struct PendingSymbolSet {
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
    /// Whether cleanup fully completed and no retry state was retained.
    pub completed: bool,
    /// Handlers that ran.
    pub handlers_run: Vec<String>,
    /// Errors returned by cleanup handlers.
    pub handler_errors: Vec<String>,
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
    /// Completed object IDs that no longer accept pending symbols.
    completed: RwLock<HashSet<ObjectId>>,
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
            completed: RwLock::new(HashSet::new()),
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
        // Check completion while holding the pending map lock so retry-state
        // restoration can reopen an object without a lost-symbol race.
        if self.completed.read().contains(&object_id) {
            return;
        }

        let set = pending
            .entry(object_id)
            .or_insert_with(|| PendingSymbolSet {
                symbols: Vec::new(),
                total_bytes: 0,
                _created_at: now,
            });

        set.total_bytes = set.total_bytes.saturating_add(symbol.len());
        set.symbols.push(symbol);
    }

    #[allow(clippy::significant_drop_tightening)]
    fn restore_retry_state(
        &self,
        object_id: ObjectId,
        handler: Box<dyn CleanupHandler>,
        pending_set: PendingSymbolSet,
    ) {
        self.handlers.write().insert(object_id, handler);
        // Keep `pending` held while clearing `completed` so reopening retry
        // state is atomic with respect to register_pending() and cannot drop
        // symbols in the reopen window.
        let mut pending = self.pending.write();
        pending.insert(object_id, pending_set);
        self.completed.write().remove(&object_id);
    }

    /// Registers a cleanup handler for an object.
    pub fn register_handler(&self, object_id: ObjectId, handler: impl CleanupHandler + 'static) {
        self.handlers.write().insert(object_id, Box::new(handler));
    }

    /// Clears pending symbols for an object (e.g., after successful decode).
    pub fn clear_pending(&self, object_id: &ObjectId) -> Option<usize> {
        let mut pending = self.pending.write();
        self.completed.write().insert(*object_id);
        pending.remove(object_id).map(|set| set.symbols.len())
    }

    /// Triggers cleanup for a cancelled object.
    pub fn cleanup(&self, object_id: ObjectId, budget: Option<Budget>) -> CleanupResult {
        let budget = budget.unwrap_or(self.default_budget);
        let mut result = CleanupResult {
            object_id,
            symbols_cleaned: 0,
            bytes_freed: 0,
            within_budget: true,
            completed: true,
            handlers_run: Vec::new(),
            handler_errors: Vec::new(),
        };

        // Atomically extract the handler and pending symbols while marking as completed.
        // The lock hierarchy (handlers -> pending -> completed) prevents deadlocks,
        // and holding them all prevents concurrent cleanup calls from interleaving and
        // losing symbols by finding a pending set without its handler.
        let handler = { self.handlers.write().remove(&object_id) };
        let pending_set = { self.pending.write().remove(&object_id) };
        self.completed.write().insert(object_id);

        if let Some(set) = pending_set {
            let symbol_count = set.symbols.len();
            let total_bytes = set.total_bytes;

            // Run registered handler.
            if let Some(handler) = handler {
                if budget.poll_quota == 0 {
                    // No budget to even attempt the handler; keep the pending state
                    // and handler for an explicit retry.
                    self.restore_retry_state(object_id, handler, set);
                    result.within_budget = false;
                    result.completed = false;
                } else {
                    let handler_name = handler.name().to_string();
                    let retry_set = set.clone();

                    result.handlers_run.push(handler_name.clone());
                    match handler.cleanup(object_id, set.symbols) {
                        Ok(_) => {
                            result.symbols_cleaned = symbol_count;
                            result.bytes_freed = total_bytes;
                        }
                        Err(err) => {
                            // The cleanup attempt failed; retain the pending set and
                            // handler so the caller can retry deterministically.
                            self.restore_retry_state(object_id, handler, retry_set);
                            result.completed = false;
                            result.handler_errors.push(format!("{handler_name}: {err}"));
                        }
                    }
                }
            } else {
                // br-asupersync-batcyw: pending symbols exist but no
                // CleanupHandler is registered for this object_id.
                // Previous behaviour set symbols_cleaned = N and
                // bytes_freed = total — silently REPORTING the
                // symbols as cleaned even though no handler ever
                // ran. This is the observable shape callers used to
                // distinguish "release was acked by the application"
                // from "release dropped on the floor", and the bug
                // collapsed the two into the same "success" record.
                //
                // New behaviour: leave symbols_cleaned and
                // bytes_freed at zero, mark the result as not
                // completed, push a typed error into handler_errors
                // identifying the missing-handler condition, and
                // restore the pending set so a later
                // register_handler + retry can drive cleanup to
                // completion. The completed-set entry inserted at
                // line 1015 above is rolled back here too — a
                // missing-handler outcome is NOT a completion.
                result.completed = false;
                result.handler_errors.push(format!(
                    "no cleanup handler registered for object {object_id:?}; \
                     {symbol_count} symbol(s) / {total_bytes} byte(s) deferred \
                     (br-asupersync-batcyw)"
                ));
                // Restore pending; un-mark completed.
                self.pending.write().insert(object_id, set);
                self.completed.write().remove(&object_id);
            }
        }

        result
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now;
    use crate::test_utils::init_test_logging;
    use crate::types::symbol::{ObjectId, Symbol};
    use serde_json::Value;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

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

    struct RecordingSink {
        label: &'static str,
        checkpoints: Arc<StdMutex<Vec<Value>>>,
        messages: Arc<StdMutex<Vec<CancelMessage>>>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TokenSnapshot {
        token_id: u64,
        cancelled: bool,
        reason_kind: Option<CancelKind>,
        cancelled_at_nanos: Option<u64>,
        queued_children: usize,
        queued_listeners: usize,
    }

    fn snapshot_token(token: &SymbolCancelToken) -> TokenSnapshot {
        TokenSnapshot {
            token_id: token.token_id(),
            cancelled: token.is_cancelled(),
            reason_kind: token.reason().map(|reason| reason.kind),
            cancelled_at_nanos: token.cancelled_at().map(Time::as_nanos),
            queued_children: token.state.children.read().len(),
            queued_listeners: token.state.listeners.read().len(),
        }
    }

    fn attach_order_listener(token: &SymbolCancelToken, order: &Arc<StdMutex<Vec<u64>>>) {
        let token_id = token.token_id();
        let order = Arc::clone(order);
        token.add_listener(move |_: &CancelReason, _: Time| {
            order.lock().unwrap().push(token_id);
        });
    }

    fn attach_named_order_listener(
        token: &SymbolCancelToken,
        label: &'static str,
        order: &Arc<StdMutex<Vec<&'static str>>>,
    ) {
        let order = Arc::clone(order);
        token.add_listener(move |_: &CancelReason, _: Time| {
            order.lock().unwrap().push(label);
        });
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ReasonSnapshot {
        cancelled: bool,
        kind: Option<CancelKind>,
        cancelled_at_nanos: Option<u64>,
        cause_chain: Vec<CancelKind>,
    }

    fn snapshot_reason(token: &SymbolCancelToken) -> ReasonSnapshot {
        let reason = token.reason();
        let cause_chain = reason
            .as_ref()
            .map(|reason| reason.chain().map(|reason| reason.kind).collect())
            .unwrap_or_default();
        ReasonSnapshot {
            cancelled: token.is_cancelled(),
            kind: reason.as_ref().map(|reason| reason.kind),
            cancelled_at_nanos: token.cancelled_at().map(Time::as_nanos),
            cause_chain,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DescendantInvariantScenario {
        creation_order: Vec<&'static str>,
        observed_order: Vec<&'static str>,
        left_before_parent: ReasonSnapshot,
        left_after_parent: ReasonSnapshot,
        right_child_after_parent: ReasonSnapshot,
        right_leaf_after_parent: ReasonSnapshot,
    }

    fn run_descendant_invariant_scenario(
        swap_creation_order: bool,
        drop_right_child_handle: bool,
    ) -> DescendantInvariantScenario {
        let mut rng = DetRng::new(0xCACE_1001);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(77), &mut rng);
        let order = Arc::new(StdMutex::new(Vec::<&'static str>::new()));
        let creation_order = if swap_creation_order {
            vec!["right", "left"]
        } else {
            vec!["left", "right"]
        };

        let mut left_child: Option<SymbolCancelToken> = None;
        let mut left_leaf: Option<SymbolCancelToken> = None;
        let mut right_child: Option<SymbolCancelToken> = None;
        let mut right_leaf: Option<SymbolCancelToken> = None;

        for label in &creation_order {
            let child = parent.child(&mut rng);
            attach_named_order_listener(&child, label, &order);
            let leaf = child.child(&mut rng);
            match *label {
                "left" => {
                    left_child = Some(child);
                    left_leaf = Some(leaf);
                }
                "right" => {
                    right_child = Some(child);
                    right_leaf = Some(leaf);
                }
                _ => unreachable!("unexpected branch label"),
            }
        }

        let left_leaf = left_leaf.expect("left leaf should be created");
        let right_leaf_observer = right_leaf.expect("right leaf should be created");
        let right_child_observer = right_child
            .as_ref()
            .expect("right child should be created")
            .clone();

        let descendant_reason = CancelReason::shutdown()
            .with_cause(CancelReason::timeout().with_cause(CancelReason::user("left-root-cause")));
        let descendant_at = Time::from_millis(15);
        assert!(left_leaf.cancel(&descendant_reason, descendant_at));
        let left_before_parent = snapshot_reason(&left_leaf);

        if drop_right_child_handle {
            drop(right_child.take());
        }
        drop(left_child);

        assert!(parent.cancel(&CancelReason::user("parent-cascade"), Time::from_millis(30)));

        DescendantInvariantScenario {
            creation_order,
            observed_order: order.lock().unwrap().clone(),
            left_before_parent,
            left_after_parent: snapshot_reason(&left_leaf),
            right_child_after_parent: snapshot_reason(&right_child_observer),
            right_leaf_after_parent: snapshot_reason(&right_leaf_observer),
        }
    }

    impl CancelSink for RecordingSink {
        fn send_to(
            &self,
            _peer: &PeerId,
            _msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<()>> + Send {
            std::future::ready(Ok(()))
        }

        fn broadcast(
            &self,
            msg: &CancelMessage,
        ) -> impl std::future::Future<Output = crate::error::Result<usize>> + Send {
            let label = self.label;
            let checkpoints = Arc::clone(&self.checkpoints);
            let messages = Arc::clone(&self.messages);
            let message = msg.clone();

            async move {
                let event = serde_json::json!({
                    "phase": format!("{label}_broadcast"),
                    "kind": format!("{:?}", message.kind()),
                    "sequence": message.sequence(),
                    "hops": message.hops(),
                });
                tracing::info!(event = %event, "symbol_cancel_lab_checkpoint");
                checkpoints.lock().unwrap().push(event);
                messages.lock().unwrap().push(message);
                yield_now().await;
                Ok(1)
            }
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

    // br-asupersync-wm9h2a: SymbolCancelToken::new_for_test is now
    // gated behind `#[cfg(any(test, feature = "test-internals"))]`.
    // Inside this `#[cfg(test)]` module the gate's positive arm is
    // active, so the constructor is reachable and we can pin its
    // forgery-shape behaviour:
    //   1. The constructor accepts arbitrary token_id / object_id
    //      values without going through the broadcaster issuance
    //      ceremony — exactly what makes it a forgery primitive
    //      and exactly why production must NOT have access.
    //   2. The constructor mints distinct Arc<CancelTokenState>
    //      instances for every call, so two synthesized tokens with
    //      the same (token_id, object_id) are NOT aliased — proving
    //      the constructor is not a deduplicating issuer that
    //      could coincidentally mimic a real broadcaster lookup.
    //
    // The negative arm of the gate (production builds compile-failing
    // on any reference to new_for_test) cannot be tested from inside
    // a `#[cfg(test)]` block by definition — by the time the test
    // compiles, the gate's positive arm is on. The compile-fail
    // contract is documented above the constructor and is enforced
    // by the cfg attribute itself.
    #[test]
    fn test_new_for_test_is_a_forgery_primitive_and_must_be_gated_wm9h2a() {
        let object_id = ObjectId::new_for_test(0xdead_beef);
        let forged_a = SymbolCancelToken::new_for_test(0x1111_2222_3333_4444, object_id);
        let forged_b = SymbolCancelToken::new_for_test(0x1111_2222_3333_4444, object_id);

        // Property (1): forged tokens carry exactly the values the
        // caller supplied, with no broadcaster involvement.
        assert_eq!(forged_a.object_id(), object_id);
        assert_eq!(forged_b.object_id(), object_id);

        // Property (2): two forgeries with identical (token_id,
        // object_id) inputs are still distinct Arc instances — they
        // share neither cancellation state nor listener slabs. A
        // production caller that obtained both could cancel one
        // without affecting the other, which is the textbook shape
        // of a capability-boundary breach.
        forged_a.cancel(&CancelReason::user("forgery-A"), Time::from_millis(1));
        assert!(forged_a.is_cancelled());
        assert!(
            !forged_b.is_cancelled(),
            "two new_for_test tokens with the same id must not share state — \
             this confirms the constructor is a forgery primitive that MUST \
             stay gated behind test or test-internals"
        );
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
    fn test_token_cancel_clamps_time_max_away_from_sentinel() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        assert!(cancel_handle.cancel(&CancelReason::timeout(), Time::MAX));
        assert!(cancel_handle.is_cancelled());
        assert_eq!(cancel_handle.reason().unwrap().kind, CancelKind::Timeout);
        assert_eq!(
            cancel_handle.cancelled_at(),
            Some(Time::from_nanos(u64::MAX - 1))
        );
    }

    #[test]
    fn test_token_reason_propagates() {
        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        let reason = CancelReason::timeout().with_message("timed out");
        cancel_handle.cancel(&reason, Time::from_millis(500));

        let stored = cancel_handle.reason().unwrap();
        assert_eq!(stored.kind, CancelKind::Timeout);
        assert_eq!(stored.message, Some("timed out".to_string()));
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
    fn metamorphic_descendant_cancellation_observable_under_reorder_and_drop() {
        let baseline = run_descendant_invariant_scenario(false, false);
        let swapped = run_descendant_invariant_scenario(true, false);
        let dropped = run_descendant_invariant_scenario(false, true);

        for scenario in [&baseline, &swapped, &dropped] {
            assert_eq!(
                scenario.observed_order, scenario.creation_order,
                "sibling cancellation listener order should follow child registration order"
            );
            assert_eq!(
                scenario.left_before_parent, scenario.left_after_parent,
                "a self-cancelled descendant must remain observable with the same cause chain after parent cancellation"
            );
            assert_eq!(
                scenario.right_child_after_parent.kind,
                Some(CancelKind::ParentCancelled),
                "uncancelled sibling should be cancelled by the parent cascade"
            );
            assert_eq!(
                scenario.right_leaf_after_parent.kind,
                Some(CancelKind::ParentCancelled),
                "grandchild under the uncancelled sibling should inherit parent cancellation"
            );
            assert_eq!(
                scenario.right_child_after_parent.cause_chain,
                vec![CancelKind::ParentCancelled],
                "sibling child should not gain spurious causes during cascade"
            );
            assert_eq!(
                scenario.right_leaf_after_parent.cause_chain,
                vec![CancelKind::ParentCancelled],
                "dropped-handle descendant should preserve the canonical parent-cancelled cause chain"
            );
        }

        assert_eq!(
            baseline.left_after_parent.kind,
            Some(CancelKind::Shutdown),
            "the stronger descendant cancellation should not be weakened by a later parent cascade"
        );
        assert_eq!(
            baseline.left_after_parent.cause_chain,
            vec![CancelKind::Shutdown, CancelKind::Timeout, CancelKind::User],
            "descendant cause chain should remain intact"
        );
        assert_eq!(
            baseline.left_after_parent, swapped.left_after_parent,
            "sibling creation order should not change descendant observability"
        );
        assert_eq!(
            baseline.left_after_parent, dropped.left_after_parent,
            "dropping a sibling handle must not corrupt an already-cancelled descendant"
        );
        assert_eq!(
            baseline.right_child_after_parent, swapped.right_child_after_parent,
            "sibling reordering should not change cascade outcome"
        );
        assert_eq!(
            baseline.right_child_after_parent, dropped.right_child_after_parent,
            "dropping the sibling handle must preserve child cancellation outcome"
        );
        assert_eq!(
            baseline.right_leaf_after_parent, swapped.right_leaf_after_parent,
            "sibling reordering should not change leaf cascade outcome"
        );
        assert_eq!(
            baseline.right_leaf_after_parent, dropped.right_leaf_after_parent,
            "dropping the sibling handle must preserve descendant cascade outcome"
        );
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
    fn cancel_broadcast_drains_remote_children_under_lab_runtime() {
        init_test_logging();
        crate::test_phase!("cancel_broadcast_drains_remote_children_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0xCAA0_CE11)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));
        let local_messages = Arc::new(StdMutex::new(Vec::<CancelMessage>::new()));
        let remote_messages = Arc::new(StdMutex::new(Vec::<CancelMessage>::new()));

        let (
            local_cancelled,
            remote_cancelled,
            remote_child_cancelled,
            late_child_cancelled,
            remote_reason,
            remote_metrics,
            checkpoints,
        ) = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = crate::cx::Cx::current().expect("lab runtime should install a current Cx");
            let local_spawn_cx = cx.clone();
            let remote_spawn_cx = cx.clone();
            let object_id = ObjectId::new_for_test(44);

            let local_sink = RecordingSink {
                label: "local",
                checkpoints: Arc::clone(&checkpoints),
                messages: Arc::clone(&local_messages),
            };
            let remote_sink = RecordingSink {
                label: "remote",
                checkpoints: Arc::clone(&checkpoints),
                messages: Arc::clone(&remote_messages),
            };

            let local_broadcaster = Arc::new(CancelBroadcaster::new(local_sink));
            let remote_broadcaster = Arc::new(CancelBroadcaster::new(remote_sink));

            let mut local_rng = DetRng::new(101);
            let local_token = SymbolCancelToken::new(object_id, &mut local_rng);
            local_broadcaster.register_token(local_token.clone());

            let mut remote_rng = DetRng::new(202);
            let remote_token = SymbolCancelToken::new(object_id, &mut remote_rng);
            let remote_child = remote_token.child(&mut remote_rng);
            let late_child = Arc::new(StdMutex::new(None::<SymbolCancelToken>));
            let late_child_listener = Arc::clone(&late_child);
            let listener_checkpoints = Arc::clone(&checkpoints);
            let remote_token_for_listener = remote_token.clone();
            remote_token.add_listener(move |reason: &CancelReason, at: Time| {
                let listener_event = serde_json::json!({
                    "phase": "remote_listener_invoked",
                    "kind": format!("{:?}", reason.kind),
                    "at_millis": at.as_millis(),
                });
                tracing::info!(event = %listener_event, "symbol_cancel_lab_checkpoint");
                listener_checkpoints.lock().unwrap().push(listener_event);

                let mut child_rng = DetRng::new(303);
                let child = remote_token_for_listener.child(&mut child_rng);
                *late_child_listener.lock().unwrap() = Some(child);
            });
            remote_broadcaster.register_token(remote_token.clone());

            let local_task = LabRuntimeTarget::spawn(&local_spawn_cx, Budget::INFINITE, {
                let local_broadcaster = Arc::clone(&local_broadcaster);
                let local_token = local_token.clone();
                let checkpoints = Arc::clone(&checkpoints);
                async move {
                    let request = serde_json::json!({
                        "phase": "local_cancel_requested",
                        "object_high": object_id.high(),
                    });
                    tracing::info!(event = %request, "symbol_cancel_lab_checkpoint");
                    checkpoints.lock().unwrap().push(request);

                    let sent = local_broadcaster
                        .cancel(object_id, &CancelReason::shutdown(), Time::from_millis(100))
                        .await
                        .expect("local cancel should broadcast successfully");

                    let completed = serde_json::json!({
                        "phase": "local_cancel_completed",
                        "sent": sent,
                    });
                    tracing::info!(event = %completed, "symbol_cancel_lab_checkpoint");
                    checkpoints.lock().unwrap().push(completed);
                    local_token.is_cancelled()
                }
            });

            let local_outcome = local_task.await;
            crate::assert_with_log!(
                matches!(local_outcome, crate::types::Outcome::Ok(true)),
                "local cancel task completes successfully",
                true,
                matches!(local_outcome, crate::types::Outcome::Ok(true))
            );
            let crate::types::Outcome::Ok(local_cancelled) = local_outcome else {
                panic!("local cancel task should finish successfully");
            };

            let forwarded = local_messages
                .lock()
                .unwrap()
                .first()
                .cloned()
                .expect("local cancel should emit a broadcast message");

            let remote_task = LabRuntimeTarget::spawn(&remote_spawn_cx, Budget::INFINITE, {
                let remote_broadcaster = Arc::clone(&remote_broadcaster);
                let remote_token = remote_token.clone();
                let remote_child = remote_child.clone();
                let late_child = Arc::clone(&late_child);
                let checkpoints = Arc::clone(&checkpoints);
                async move {
                    let received = serde_json::json!({
                        "phase": "remote_handle_started",
                        "sequence": forwarded.sequence(),
                    });
                    tracing::info!(event = %received, "symbol_cancel_lab_checkpoint");
                    checkpoints.lock().unwrap().push(received);

                    remote_broadcaster
                        .handle_message(forwarded, Time::from_millis(125))
                        .await
                        .expect("remote handle_message should succeed");

                    let completed = serde_json::json!({
                        "phase": "remote_handle_completed",
                        "forwarded_count": remote_broadcaster.metrics().forwarded,
                    });
                    tracing::info!(event = %completed, "symbol_cancel_lab_checkpoint");
                    checkpoints.lock().unwrap().push(completed);

                    (
                        remote_token.is_cancelled(),
                        remote_child.is_cancelled(),
                        late_child
                            .lock()
                            .unwrap()
                            .clone()
                            .expect("late child should be created by remote listener")
                            .is_cancelled(),
                        remote_token
                            .reason()
                            .expect("remote token should have a reason")
                            .kind,
                        remote_broadcaster.metrics(),
                    )
                }
            });

            let remote_outcome = remote_task.await;
            crate::assert_with_log!(
                matches!(remote_outcome, crate::types::Outcome::Ok(_)),
                "remote handle task completes successfully",
                true,
                matches!(remote_outcome, crate::types::Outcome::Ok(_))
            );
            let crate::types::Outcome::Ok((
                remote_cancelled,
                remote_child_cancelled,
                late_child_cancelled,
                remote_reason,
                remote_metrics,
            )) = remote_outcome
            else {
                panic!("remote handle task should finish successfully");
            };

            assert_eq!(
                remote_token.state.children.read().len(),
                0,
                "remote cancellation should drain queued children before returning"
            );
            assert_eq!(
                remote_token.state.listeners.read().len(),
                0,
                "remote cancellation should drain listeners before returning"
            );

            (
                local_cancelled,
                remote_cancelled,
                remote_child_cancelled,
                late_child_cancelled,
                remote_reason,
                remote_metrics,
                checkpoints.lock().unwrap().clone(),
            )
        });

        assert!(
            local_cancelled,
            "local token should be cancelled by broadcaster.cancel"
        );
        assert!(
            remote_cancelled,
            "remote token should be cancelled by forwarded message"
        );
        assert!(
            remote_child_cancelled,
            "remote pre-existing child should be drained during cancellation"
        );
        assert!(
            late_child_cancelled,
            "listener-spawned child should be cancelled before handle_message returns"
        );
        assert_eq!(remote_reason, CancelKind::Shutdown);
        assert_eq!(remote_metrics.received, 1);
        assert_eq!(remote_metrics.forwarded, 1);
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "local_broadcast"),
            "local broadcast checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "remote_listener_invoked"),
            "remote listener checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "remote_handle_completed"),
            "remote completion checkpoint should be recorded"
        );

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "symbol cancel lab-runtime test should leave runtime invariants clean: {violations:?}"
        );
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
        assert!(result.completed);
        assert!(result.handler_errors.is_empty());
    }

    #[test]
    fn test_cleanup_handler_error_preserves_retry_state() {
        struct FailingHandler;

        impl CleanupHandler for FailingHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                Err(crate::error::Error::new(crate::error::ErrorKind::Internal)
                    .with_message("cleanup failed"))
            }

            fn name(&self) -> &'static str {
                "failing"
            }
        }

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(7);
        let now = Time::from_millis(100);

        coordinator.register_handler(object_id, FailingHandler);
        coordinator.register_pending(object_id, Symbol::new_for_test(7, 0, 0, &[1, 2, 3]), now);

        let result = coordinator.cleanup(object_id, None);
        assert!(
            !result.completed,
            "failed handler must not report completion"
        );
        assert_eq!(
            result.symbols_cleaned, 0,
            "failed cleanup must not report cleaned symbols"
        );
        assert_eq!(
            result.bytes_freed, 0,
            "failed cleanup must not report freed bytes"
        );
        assert_eq!(result.handlers_run, vec!["failing"]);
        assert_eq!(result.handler_errors.len(), 1);
        assert!(
            result.handler_errors[0].contains("cleanup failed"),
            "{}",
            result.handler_errors[0]
        );

        let stats = coordinator.stats();
        assert_eq!(
            stats.pending_objects, 1,
            "failed cleanup must remain retryable"
        );
        assert_eq!(stats.pending_symbols, 1);
        assert_eq!(stats.pending_bytes, 3);
    }

    #[test]
    fn test_cleanup_handler_error_reopens_object_for_new_pending_symbols() {
        struct FailingHandler;

        impl CleanupHandler for FailingHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                Err(crate::error::Error::new(crate::error::ErrorKind::Internal)
                    .with_message("cleanup failed"))
            }

            fn name(&self) -> &'static str {
                "failing"
            }
        }

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(8);
        let now = Time::from_millis(100);

        coordinator.register_handler(object_id, FailingHandler);
        coordinator.register_pending(object_id, Symbol::new_for_test(8, 0, 0, &[1, 2, 3]), now);

        let result = coordinator.cleanup(object_id, None);
        assert!(
            !result.completed,
            "failed cleanup must leave object retryable"
        );

        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(8, 0, 1, &[4, 5]),
            Time::from_millis(101),
        );

        let stats = coordinator.stats();
        assert_eq!(
            stats.pending_symbols, 2,
            "retryable cleanup must continue accepting pending symbols"
        );
        assert_eq!(stats.pending_bytes, 5);
    }

    #[test]
    fn test_cleanup_budget_exhaustion_reopens_object_for_new_pending_symbols() {
        struct RecordingHandler;

        impl CleanupHandler for RecordingHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                Ok(1)
            }

            fn name(&self) -> &'static str {
                "recording"
            }
        }

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(9);
        let now = Time::from_millis(100);

        coordinator.register_handler(object_id, RecordingHandler);
        coordinator.register_pending(object_id, Symbol::new_for_test(9, 0, 0, &[1]), now);

        let budget = Budget::new().with_poll_quota(0);
        let result = coordinator.cleanup(object_id, Some(budget));
        assert!(
            !result.completed,
            "budget-exhausted cleanup must leave object retryable"
        );
        assert!(
            !result.within_budget,
            "zero-poll budget should report budget exhaustion"
        );

        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(9, 0, 1, &[2, 3]),
            Time::from_millis(101),
        );

        let stats = coordinator.stats();
        assert_eq!(
            stats.pending_symbols, 2,
            "budget-exhausted cleanup must continue accepting pending symbols"
        );
        assert_eq!(stats.pending_bytes, 3);
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

    #[test]
    fn test_listener_spawned_child_is_drained_inline() {
        let mut rng = DetRng::new(91);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(6), &mut rng);
        let observed_child = Arc::new(std::sync::Mutex::new(None::<SymbolCancelToken>));
        let observed_child_clone = Arc::clone(&observed_child);
        let parent_for_listener = parent.clone();

        parent.add_listener(move |_: &CancelReason, _: Time| {
            let mut child_rng = DetRng::new(92);
            let child = parent_for_listener.child(&mut child_rng);
            *observed_child_clone.lock().unwrap() = Some(child);
        });

        let now = Time::from_millis(150);
        assert!(
            parent.cancel(&CancelReason::user("listener-child"), now),
            "first caller should trigger cancellation"
        );

        let late_child = observed_child
            .lock()
            .unwrap()
            .clone()
            .expect("listener should create a child during cancellation");
        assert!(
            late_child.is_cancelled(),
            "child created during listener callback must be cancelled before cancel() returns"
        );
        assert_eq!(
            late_child.reason().unwrap().kind,
            CancelKind::ParentCancelled,
            "late child should inherit parent-cancelled semantics"
        );
        assert_eq!(
            late_child.cancelled_at(),
            Some(now),
            "late child should observe the parent cancellation timestamp"
        );
        assert_eq!(
            parent.state.children.read().len(),
            0,
            "listener-spawned child must not be retained after drain completes"
        );
    }

    #[test]
    fn test_listener_registered_during_cancel_not_requeued() {
        let mut rng = DetRng::new(93);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(7), &mut rng);
        let notification_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_kind = Arc::new(std::sync::Mutex::new(None::<CancelKind>));
        let seen_time = Arc::new(std::sync::Mutex::new(None::<Time>));

        let token_for_listener = token.clone();
        let notification_count_clone = Arc::clone(&notification_count);
        let seen_kind_clone = Arc::clone(&seen_kind);
        let seen_time_clone = Arc::clone(&seen_time);
        token.add_listener(move |_: &CancelReason, _: Time| {
            token_for_listener.add_listener({
                let notification_count_clone = Arc::clone(&notification_count_clone);
                let seen_kind_clone = Arc::clone(&seen_kind_clone);
                let seen_time_clone = Arc::clone(&seen_time_clone);
                move |reason: &CancelReason, at: Time| {
                    notification_count_clone.fetch_add(1, Ordering::SeqCst);
                    *seen_kind_clone.lock().unwrap() = Some(reason.kind);
                    *seen_time_clone.lock().unwrap() = Some(at);
                }
            });
        });

        let now = Time::from_millis(175);
        assert!(
            token.cancel(&CancelReason::timeout(), now),
            "first caller should trigger listener drain"
        );
        assert_eq!(
            notification_count.load(Ordering::SeqCst),
            1,
            "listener registered during cancellation should be invoked inline exactly once"
        );
        assert_eq!(
            *seen_kind.lock().unwrap(),
            Some(CancelKind::Timeout),
            "late listener should observe the current cancellation kind"
        );
        assert_eq!(
            *seen_time.lock().unwrap(),
            Some(now),
            "late listener should observe the current cancellation timestamp"
        );
        assert_eq!(
            token.state.listeners.read().len(),
            0,
            "late listener should not remain queued after cancellation drain"
        );

        token.cancel(&CancelReason::shutdown(), Time::from_millis(200));
        assert_eq!(
            notification_count.load(Ordering::SeqCst),
            1,
            "drained late listener must not be re-notified by strengthened cancellations"
        );
        assert_eq!(
            token.state.listeners.read().len(),
            0,
            "strengthened cancellations must not repopulate drained listeners"
        );
    }

    #[test]
    fn test_listener_registered_during_cancel_can_spawn_child_without_leak() {
        let mut rng = DetRng::new(94);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(8), &mut rng);
        let spawned_child = Arc::new(std::sync::Mutex::new(None::<SymbolCancelToken>));
        let spawned_child_clone = Arc::clone(&spawned_child);
        let child_notification_count = Arc::new(AtomicUsize::new(0));
        let child_notification_count_clone = Arc::clone(&child_notification_count);
        let token_for_listener = token.clone();

        token.add_listener(move |_: &CancelReason, _: Time| {
            token_for_listener.add_listener({
                let spawned_child_clone = Arc::clone(&spawned_child_clone);
                let child_notification_count_clone = Arc::clone(&child_notification_count_clone);
                let token_for_listener = token_for_listener.clone();
                move |reason: &CancelReason, at: Time| {
                    child_notification_count_clone.fetch_add(1, Ordering::SeqCst);
                    let mut child_rng = DetRng::new(95);
                    let child = token_for_listener.child(&mut child_rng);
                    assert!(
                        child.is_cancelled(),
                        "child created from a late listener must be cancelled inline"
                    );
                    assert_eq!(
                        child.reason().unwrap().kind,
                        CancelKind::ParentCancelled,
                        "late child should inherit parent-cancelled semantics"
                    );
                    assert_eq!(
                        child.cancelled_at(),
                        Some(at),
                        "late child should observe the current cancellation timestamp"
                    );
                    assert_eq!(
                        reason.kind,
                        CancelKind::Shutdown,
                        "late listener should observe the active cancellation reason"
                    );
                    *spawned_child_clone.lock().unwrap() = Some(child);
                }
            });
        });

        let now = Time::from_millis(250);
        assert!(
            token.cancel(&CancelReason::shutdown(), now),
            "first caller should trigger cancellation"
        );

        let child = spawned_child
            .lock()
            .unwrap()
            .clone()
            .expect("late listener should have spawned a child");
        assert_eq!(
            child_notification_count.load(Ordering::SeqCst),
            1,
            "late listener should run exactly once during drain"
        );
        assert!(child.is_cancelled(), "spawned child must remain cancelled");
        assert_eq!(
            child.cancelled_at(),
            Some(now),
            "spawned child should be cancelled before cancel() returns"
        );
        assert_eq!(
            token.state.listeners.read().len(),
            0,
            "drain must leave no late listeners queued"
        );
        assert_eq!(
            token.state.children.read().len(),
            0,
            "drain must leave no late children queued"
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

    // =========================================================================
    // Metamorphic Testing: Cascade Invariants (META-CANCEL)
    // =========================================================================

    /// META-CANCEL-001: Transitive Cascade Property
    /// If A→B→C (chain), then cancel(A) = {A,B,C} all cancelled
    /// Metamorphic relation: cancel_depth(chain, root) = all_descendants_cancelled(root)
    #[test]
    fn meta_transitive_cascade_property() {
        let mut rng = DetRng::new(12345);
        let root = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        let level1 = root.child(&mut rng);
        let level2 = level1.child(&mut rng);
        let level3 = level2.child(&mut rng);

        // Create reference chain for comparison
        let mut rng2 = DetRng::new(12345); // Same seed = same behavior
        let ref_root = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng2);
        let ref_level1 = ref_root.child(&mut rng2);
        let ref_level2 = ref_level1.child(&mut rng2);
        let ref_level3 = ref_level2.child(&mut rng2);

        let now = Time::from_millis(500);

        // Metamorphic relation: cancelling at any depth should produce same cascade pattern
        root.cancel(&CancelReason::user("cascade_test"), now);
        ref_root.cancel(&CancelReason::user("cascade_test"), now);

        // All descendants should be cancelled in both chains
        assert_eq!(root.is_cancelled(), ref_root.is_cancelled());
        assert_eq!(level1.is_cancelled(), ref_level1.is_cancelled());
        assert_eq!(level2.is_cancelled(), ref_level2.is_cancelled());
        assert_eq!(level3.is_cancelled(), ref_level3.is_cancelled());

        // All should have ParentCancelled except root
        assert_eq!(root.reason().unwrap().kind, CancelKind::User);
        assert_eq!(level1.reason().unwrap().kind, CancelKind::ParentCancelled);
        assert_eq!(level2.reason().unwrap().kind, CancelKind::ParentCancelled);
        assert_eq!(level3.reason().unwrap().kind, CancelKind::ParentCancelled);
    }

    /// META-CANCEL-002: Order Independence Property
    /// Children added in different orders should be cancelled identically
    /// Metamorphic relation: cancel(permute(children)) = same_cancelled_set
    #[test]
    fn meta_order_independence_cascade() {
        // Setup 1: Add children in order A, B, C
        let mut rng1 = DetRng::new(67890);
        let parent1 = SymbolCancelToken::new(ObjectId::new_for_test(10), &mut rng1);
        let child1a = parent1.child(&mut rng1);
        let child1b = parent1.child(&mut rng1);
        let child1c = parent1.child(&mut rng1);

        // Setup 2: Add children in order C, A, B (permuted)
        let mut rng2 = DetRng::new(67890); // Same initial seed
        let _parent2 = SymbolCancelToken::new(ObjectId::new_for_test(10), &mut rng2);
        // Skip ahead to same RNG state as after child1c creation
        let _ = rng2.next_u64(); // child1a token_id
        let _ = rng2.next_u64(); // child1b token_id
        let _ = rng2.next_u64(); // child1c token_id

        // Reset and create in different order
        let mut rng2 = DetRng::new(67890);
        let parent2 = SymbolCancelToken::new(ObjectId::new_for_test(10), &mut rng2);
        // Create children in permuted order but with same logical identity
        let child2a = parent2.child(&mut rng2);
        let child2c = parent2.child(&mut rng2);
        let child2b = parent2.child(&mut rng2);

        let now = Time::from_millis(1000);

        // Cancel both parents
        parent1.cancel(&CancelReason::timeout(), now);
        parent2.cancel(&CancelReason::timeout(), now);

        // Metamorphic relation: cancellation results should be identical regardless of creation order
        assert_eq!(parent1.is_cancelled(), parent2.is_cancelled());
        assert_eq!(child1a.is_cancelled(), child2a.is_cancelled());
        assert_eq!(child1b.is_cancelled(), child2b.is_cancelled());
        assert_eq!(child1c.is_cancelled(), child2c.is_cancelled());

        // All children should have same reason kind
        assert_eq!(
            child1a.reason().unwrap().kind,
            child2a.reason().unwrap().kind
        );
        assert_eq!(
            child1b.reason().unwrap().kind,
            child2b.reason().unwrap().kind
        );
        assert_eq!(
            child1c.reason().unwrap().kind,
            child2c.reason().unwrap().kind
        );
    }

    /// META-CANCEL-003: Reason Monotonicity Property
    /// Multiple cancellations should only strengthen, never weaken reason severity
    /// Metamorphic relation: strength(apply_sequence(reasons)) = max(strength(reasons))
    #[test]
    fn meta_reason_monotonicity_cascade() {
        let mut rng = DetRng::new(11111);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(20), &mut rng);

        // Create sequence of reasons with different severities
        let weak_reasons = vec![CancelReason::user("weak1"), CancelReason::user("weak2")];
        let strong_reasons = vec![
            CancelReason::timeout(),
            CancelReason::new(CancelKind::Shutdown),
        ];

        let now = Time::from_millis(2000);

        // Apply weak reasons first
        for reason in &weak_reasons {
            token.cancel(reason, now);
        }
        let after_weak = token.reason().unwrap().kind;

        // Apply strong reasons
        for reason in &strong_reasons {
            token.cancel(reason, now);
        }
        let after_strong = token.reason().unwrap().kind;

        // Metamorphic relation: final reason should be strongest applied
        assert_eq!(after_strong, CancelKind::Shutdown); // Strongest
        // Monotonicity: strength never decreases
        assert!(matches!(
            (after_weak, after_strong),
            (
                CancelKind::User | CancelKind::Timeout | CancelKind::Shutdown,
                CancelKind::Shutdown
            )
        ));
    }

    /// META-CANCEL-003B: Idempotent Repeat-Cancel Property
    /// Re-applying the same cancellation should not change the observable state.
    /// Metamorphic relation: cancel_once(tree) = cancel_n_times(tree, same_reason)
    #[test]
    fn meta_repeat_cancel_matches_single_cancel_observable_state() {
        let mut once_rng = DetRng::new(16_777_216);
        let once_root = SymbolCancelToken::new(ObjectId::new_for_test(21), &mut once_rng);
        let once_child_a = once_root.child(&mut once_rng);
        let once_child_b = once_root.child(&mut once_rng);
        let once_grandchild = once_child_a.child(&mut once_rng);

        let once_order = Arc::new(StdMutex::new(Vec::new()));
        for token in [&once_root, &once_child_a, &once_child_b, &once_grandchild] {
            attach_order_listener(token, &once_order);
        }

        let mut repeated_rng = DetRng::new(16_777_216);
        let repeated_root = SymbolCancelToken::new(ObjectId::new_for_test(21), &mut repeated_rng);
        let repeated_child_a = repeated_root.child(&mut repeated_rng);
        let repeated_child_b = repeated_root.child(&mut repeated_rng);
        let repeated_grandchild = repeated_child_a.child(&mut repeated_rng);

        let repeated_order = Arc::new(StdMutex::new(Vec::new()));
        for token in [
            &repeated_root,
            &repeated_child_a,
            &repeated_child_b,
            &repeated_grandchild,
        ] {
            attach_order_listener(token, &repeated_order);
        }

        let reason = CancelReason::timeout();
        let now = Time::from_millis(2_500);

        assert!(
            once_root.cancel(&reason, now),
            "first cancellation should win for single-cancel fixture"
        );
        assert!(
            repeated_root.cancel(&reason, now),
            "first cancellation should win for repeated-cancel fixture"
        );
        for _ in 0..3 {
            assert!(
                !repeated_root.cancel(&reason, now),
                "subsequent identical cancellations must be idempotent"
            );
        }

        assert_eq!(snapshot_token(&once_root), snapshot_token(&repeated_root));
        assert_eq!(
            snapshot_token(&once_child_a),
            snapshot_token(&repeated_child_a)
        );
        assert_eq!(
            snapshot_token(&once_child_b),
            snapshot_token(&repeated_child_b)
        );
        assert_eq!(
            snapshot_token(&once_grandchild),
            snapshot_token(&repeated_grandchild)
        );
        assert_eq!(
            *once_order.lock().unwrap(),
            *repeated_order.lock().unwrap(),
            "identical repeated cancellations must not perturb drain order"
        );
    }

    /// META-CANCEL-004: Upward Isolation Property
    /// Child cancellation should never affect parent or siblings
    /// Metamorphic relation: cancel(child) ∩ affect(parent ∪ siblings) = ∅
    #[test]
    fn meta_upward_isolation_property() {
        let mut rng = DetRng::new(22222);
        let parent = SymbolCancelToken::new(ObjectId::new_for_test(30), &mut rng);
        let child_a = parent.child(&mut rng);
        let child_b = parent.child(&mut rng);
        let child_c = parent.child(&mut rng);

        // Take snapshots before child cancellation
        let parent_before = parent.is_cancelled();
        let sibling_b_before = child_b.is_cancelled();
        let sibling_c_before = child_c.is_cancelled();

        // Cancel only child_a
        child_a.cancel(&CancelReason::user("isolated"), Time::from_millis(3000));

        // Metamorphic relation: isolation should preserve parent and siblings
        assert_eq!(parent.is_cancelled(), parent_before);
        assert_eq!(child_b.is_cancelled(), sibling_b_before);
        assert_eq!(child_c.is_cancelled(), sibling_c_before);

        // Only the cancelled child should be affected
        assert!(child_a.is_cancelled());
        assert!(!parent.is_cancelled());
        assert!(!child_b.is_cancelled());
        assert!(!child_c.is_cancelled());
    }

    /// META-CANCEL-004B: Sibling Subtree Isolation Property
    /// Cancelling one subtree parent should affect only that subtree.
    /// Metamorphic relation: cancel(parent_a) ∩ affect(subtree_b) = ∅
    #[test]
    fn meta_sibling_subtrees_are_isolated_from_local_parent_cancel() {
        let mut rng = DetRng::new(22_223);
        let root = SymbolCancelToken::new(ObjectId::new_for_test(31), &mut rng);
        let branch_a = root.child(&mut rng);
        let branch_b = root.child(&mut rng);
        let leaf_a = branch_a.child(&mut rng);
        let leaf_b = branch_b.child(&mut rng);

        let now = Time::from_millis(3_100);
        branch_a.cancel(&CancelReason::user("branch_a_only"), now);

        assert!(
            branch_a.is_cancelled(),
            "the locally cancelled subtree root must be cancelled"
        );
        assert!(
            leaf_a.is_cancelled(),
            "descendants of the locally cancelled subtree must cascade"
        );
        assert!(
            !root.is_cancelled(),
            "local subtree cancellation must not bubble up to the shared root"
        );
        assert!(
            !branch_b.is_cancelled(),
            "sibling subtree root must remain untouched"
        );
        assert!(
            !leaf_b.is_cancelled(),
            "sibling subtree descendants must remain untouched"
        );
        assert_eq!(branch_a.reason().unwrap().kind, CancelKind::User);
        assert_eq!(leaf_a.reason().unwrap().kind, CancelKind::ParentCancelled);
        assert!(branch_b.reason().is_none());
        assert!(leaf_b.reason().is_none());
    }

    /// META-CANCEL-005: Listener Multiplicativity Property
    /// N listeners should all be notified exactly once per cancellation
    /// Metamorphic relation: notifications_received = listeners_count × cancellations_count
    #[test]
    fn meta_listener_multiplicativity() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let mut rng = DetRng::new(33333);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(40), &mut rng);

        let notification_count = Arc::new(AtomicU32::new(0));
        let listener_count = 5u32;

        // Add N listeners
        for _ in 0..listener_count {
            let count_clone = notification_count.clone();
            token.add_listener(move |_: &CancelReason, _: Time| {
                count_clone.fetch_add(1, Ordering::SeqCst);
            });
        }

        // Cancel once
        token.cancel(&CancelReason::timeout(), Time::from_millis(4000));

        // Metamorphic relation: exactly N notifications for 1 cancellation
        assert_eq!(notification_count.load(Ordering::SeqCst), listener_count);

        // Additional cancellation attempts should not trigger more notifications (listeners drained)
        let before_second = notification_count.load(Ordering::SeqCst);
        token.cancel(
            &CancelReason::new(CancelKind::Shutdown),
            Time::from_millis(5000),
        );
        let after_second = notification_count.load(Ordering::SeqCst);

        assert_eq!(before_second, after_second); // No additional notifications
    }

    /// META-CANCEL-006: Broadcast Deduplication Property
    /// Identical messages should be deduplicated regardless of processing order
    /// Metamorphic relation: process(permute(duplicates)) = process_once(unique)
    #[test]
    fn meta_broadcast_deduplication_invariant() {
        let broadcaster = CancelBroadcaster::new(NullSink);

        let msg = CancelMessage::new(
            12345,
            ObjectId::new_for_test(50),
            CancelKind::Timeout,
            Time::from_millis(6000),
            777,
        );

        let now = Time::from_millis(6000);

        // Process same message multiple times in different patterns
        let results: Vec<_> = (0..5)
            .map(|_| broadcaster.receive_message(&msg, now))
            .collect();

        // Metamorphic relation: only first should succeed, rest should be None (duplicate)
        assert!(results[0].is_some(), "first message should be processed");
        assert!(
            results[1..].iter().all(|r| r.is_none()),
            "subsequent messages should be duplicates"
        );

        let metrics = broadcaster.metrics();
        assert_eq!(
            metrics.received, 1,
            "only one message should be counted as received"
        );
        assert_eq!(metrics.duplicates, 4, "four duplicates should be detected");
    }

    /// META-CANCEL-007: Cascade Depth Invariance Property
    /// Cancellation effects should be invariant to tree structure depth
    /// Metamorphic relation: cancel(flatten(tree)) = cancel(nested(tree))
    #[test]
    fn meta_cascade_depth_invariance() {
        let mut rng = DetRng::new(44444);

        // Flat structure: root with 3 direct children
        let flat_root = SymbolCancelToken::new(ObjectId::new_for_test(60), &mut rng);
        let flat_children: Vec<_> = (0..3).map(|_| flat_root.child(&mut rng)).collect();

        // Nested structure: root → child1 → child2 → child3 (3 levels deep)
        let mut rng2 = DetRng::new(44444); // Same seed for comparison
        let nested_root = SymbolCancelToken::new(ObjectId::new_for_test(60), &mut rng2);
        let nested_l1 = nested_root.child(&mut rng2);
        let nested_l2 = nested_l1.child(&mut rng2);
        let nested_l3 = nested_l2.child(&mut rng2);

        let now = Time::from_millis(7000);

        // Cancel both structures
        flat_root.cancel(&CancelReason::new(CancelKind::Deadline), now);
        nested_root.cancel(&CancelReason::new(CancelKind::Deadline), now);

        // Metamorphic relation: all descendants cancelled regardless of structure
        assert!(flat_root.is_cancelled());
        assert!(nested_root.is_cancelled());

        // All children/descendants should be cancelled
        assert!(flat_children.iter().all(|child| child.is_cancelled()));
        assert!(nested_l1.is_cancelled());
        assert!(nested_l2.is_cancelled());
        assert!(nested_l3.is_cancelled());

        // All derived cancellations should have ParentCancelled reason
        assert!(
            flat_children
                .iter()
                .all(|child| child.reason().unwrap().kind == CancelKind::ParentCancelled)
        );
        assert_eq!(
            nested_l1.reason().unwrap().kind,
            CancelKind::ParentCancelled
        );
        assert_eq!(
            nested_l2.reason().unwrap().kind,
            CancelKind::ParentCancelled
        );
        assert_eq!(
            nested_l3.reason().unwrap().kind,
            CancelKind::ParentCancelled
        );
    }

    /// META-CANCEL-007B: Seeded Drain Determinism Property
    /// Equivalent seeded setups must drain listeners in the same order.
    /// Metamorphic relation: drain_order(seed, setup_a) = drain_order(seed, setup_b)
    #[test]
    fn meta_seeded_cascade_order_is_deterministic() {
        let mut rng_a = DetRng::new(44_445);
        let root_a = SymbolCancelToken::new(ObjectId::new_for_test(61), &mut rng_a);
        let left_a = root_a.child(&mut rng_a);
        let right_a = root_a.child(&mut rng_a);
        let left_leaf_a = left_a.child(&mut rng_a);
        let right_leaf_a = right_a.child(&mut rng_a);

        let mut rng_b = DetRng::new(44_445);
        let root_b = SymbolCancelToken::new(ObjectId::new_for_test(61), &mut rng_b);
        let left_b = root_b.child(&mut rng_b);
        let right_b = root_b.child(&mut rng_b);
        let left_leaf_b = left_b.child(&mut rng_b);
        let right_leaf_b = right_b.child(&mut rng_b);

        let order_a = Arc::new(StdMutex::new(Vec::new()));
        for token in [&root_a, &left_a, &right_a, &left_leaf_a, &right_leaf_a] {
            attach_order_listener(token, &order_a);
        }

        let order_b = Arc::new(StdMutex::new(Vec::new()));
        for token in [&root_b, &left_b, &right_b, &left_leaf_b, &right_leaf_b] {
            attach_order_listener(token, &order_b);
        }

        let now = Time::from_millis(7_100);
        let reason = CancelReason::new(CancelKind::Deadline);
        root_a.cancel(&reason, now);
        root_b.cancel(&reason, now);

        let order_a = order_a.lock().unwrap().clone();
        let order_b = order_b.lock().unwrap().clone();

        assert_eq!(
            order_a, order_b,
            "identical seeded cancellation trees must drain in the same observable order"
        );
        assert_eq!(
            order_a,
            vec![
                root_a.token_id(),
                left_a.token_id(),
                left_leaf_a.token_id(),
                right_a.token_id(),
                right_leaf_a.token_id(),
            ],
            "seeded drain order should follow deterministic parent-before-child traversal"
        );
    }

    /// META-CANCEL-008: Cleanup Coordinator Independence Property
    /// Object cleanup should be independent across different objects
    /// Metamorphic relation: cleanup(O1 ∪ O2) = cleanup(O1) + cleanup(O2)
    #[test]
    fn meta_cleanup_independence_property() {
        let coordinator = CleanupCoordinator::new();
        let now = Time::from_millis(8000);

        let obj1 = ObjectId::new_for_test(70);
        let obj2 = ObjectId::new_for_test(71);

        // Register symbols for both objects
        for i in 0..3 {
            coordinator.register_pending(obj1, Symbol::new_for_test(70, 0, i, &[1, 2]), now);
        }
        for i in 0..2 {
            coordinator.register_pending(obj2, Symbol::new_for_test(71, 0, i, &[3, 4, 5]), now);
        }

        // Create separate coordinators for independent cleanup comparison
        let coord1 = CleanupCoordinator::new();
        let coord2 = CleanupCoordinator::new();

        // Register same symbols in separate coordinators
        for i in 0..3 {
            coord1.register_pending(obj1, Symbol::new_for_test(70, 0, i, &[1, 2]), now);
        }
        for i in 0..2 {
            coord2.register_pending(obj2, Symbol::new_for_test(71, 0, i, &[3, 4, 5]), now);
        }

        // Cleanup obj1 in both scenarios
        let combined_result1 = coordinator.cleanup(obj1, None);
        let independent_result1 = coord1.cleanup(obj1, None);

        // Metamorphic relation: obj1 cleanup should be identical regardless of obj2 presence
        assert_eq!(
            combined_result1.symbols_cleaned,
            independent_result1.symbols_cleaned
        );
        assert_eq!(
            combined_result1.bytes_freed,
            independent_result1.bytes_freed
        );
        assert_eq!(combined_result1.completed, independent_result1.completed);

        // obj2 should be unaffected in combined coordinator
        let stats_after = coordinator.stats();
        assert_eq!(stats_after.pending_objects, 1); // only obj2 remains
        assert_eq!(stats_after.pending_symbols, 2); // obj2 symbols still there
    }

    // =========================================================================
    // Wave 58 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn cancel_broadcast_metrics_debug_clone_default() {
        let m = CancelBroadcastMetrics::default();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("CancelBroadcastMetrics"), "{dbg}");
        let cloned = m;
        assert_eq!(cloned.initiated, 0);
    }

    #[test]
    fn cleanup_stats_debug_clone_default() {
        let s = CleanupStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CleanupStats"), "{dbg}");
        let cloned = s;
        assert_eq!(cloned.pending_objects, 0);
    }

    #[test]
    fn cleanup_result_debug_clone() {
        let r = CleanupResult {
            object_id: ObjectId::new_for_test(1),
            symbols_cleaned: 5,
            bytes_freed: 1024,
            within_budget: true,
            completed: true,
            handlers_run: vec!["h1".to_string()],
            handler_errors: Vec::new(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CleanupResult"), "{dbg}");
        let cloned = r;
        assert_eq!(cloned.symbols_cleaned, 5);
        assert!(cloned.completed);
    }

    // --- br-asupersync-frm9u9: re-notify on strengthened reason ----

    #[test]
    fn cancel_strengthen_re_notifies_listeners_with_stronger_reason() {
        // br-asupersync-frm9u9: a listener registered before any
        // cancel must observe BOTH the initial weaker reason AND a
        // subsequent strengthened reason. Equal-severity cancels do
        // not re-fire (idempotence at each level). The observed
        // sequence must be monotone-non-decreasing in severity.
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;
        let mut rng = DetRng::new(0x_face_d00d);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(7), &mut rng);
        let observed: Arc<StdMutex<Vec<crate::types::CancelKind>>> =
            Arc::new(StdMutex::new(Vec::new()));
        {
            let observed = Arc::clone(&observed);
            token.add_listener(move |reason: &CancelReason, _at: Time| {
                observed.lock().unwrap().push(reason.kind);
            });
        }

        // Initial cancel: lower severity (User).
        let weak = CancelReason::new(crate::types::CancelKind::User);
        token.cancel(&weak, Time::from_nanos(100));
        // Same severity again — must NOT re-notify.
        token.cancel(&weak, Time::from_nanos(150));
        // Stronger cancel (Shutdown is the strongest fixed kind in
        // the lattice) — MUST re-notify.
        let strong = CancelReason::new(crate::types::CancelKind::Shutdown);
        token.cancel(&strong, Time::from_nanos(200));

        let log = observed.lock().unwrap().clone();
        assert!(
            log.len() >= 2,
            "listener must observe both the initial cancel and the strengthen, got {log:?}"
        );
        assert_eq!(
            log.first().copied(),
            Some(crate::types::CancelKind::User),
            "first notification must carry the initial weak reason, got {log:?}"
        );
        assert!(
            log.iter().any(|k| *k == crate::types::CancelKind::Shutdown),
            "listener must be re-notified with the strengthened reason, got {log:?}"
        );
        // No duplicate same-severity notifications.
        let user_count = log
            .iter()
            .filter(|k| **k == crate::types::CancelKind::User)
            .count();
        assert_eq!(
            user_count, 1,
            "same-severity cancel must not re-fire listeners, got {log:?}"
        );
    }

    // --- br-asupersync-2bm1a3: add_listener race fix ---------------

    #[test]
    fn add_listener_post_cancel_uses_real_reason_not_fabricated_user() {
        // br-asupersync-2bm1a3: a listener registered AFTER a cancel
        // already fired must observe the actual stored reason, not a
        // fabricated `CancelKind::User @ Time::ZERO` from the
        // pre-fix race window. This test exercises the
        // happens-before-cancel-completed branch directly: the
        // listener is added strictly after `cancel()` returns, so
        // the reason is fully written; the new locking discipline
        // returns the real reason (Timeout) instead of the
        // fabricated User.
        use std::sync::Arc;
        use std::sync::Mutex as StdMutex;
        let mut rng = DetRng::new(0x_dead_beef);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(11), &mut rng);
        let timeout = CancelReason::new(crate::types::CancelKind::Timeout);
        token.cancel(&timeout, Time::from_nanos(42));

        let observed: Arc<StdMutex<Vec<(crate::types::CancelKind, u64)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        {
            let observed = Arc::clone(&observed);
            token.add_listener(move |reason: &CancelReason, at: Time| {
                observed.lock().unwrap().push((reason.kind, at.as_nanos()));
            });
        }

        let log = observed.lock().unwrap().clone();
        assert_eq!(
            log.len(),
            1,
            "post-cancel add_listener must fire exactly once, got {log:?}"
        );
        let (kind, at_nanos) = log[0];
        assert_eq!(
            kind,
            crate::types::CancelKind::Timeout,
            "listener must observe the real reason (Timeout), \
             not the fabricated CancelKind::User"
        );
        assert_eq!(
            at_nanos, 42,
            "listener must observe the real cancelled_at time, not Time::ZERO"
        );
    }

    // --- br-asupersync-batcyw: missing-handler is not "cleaned" ----

    #[test]
    fn cleanup_with_pending_but_no_handler_surfaces_typed_error() {
        // br-asupersync-batcyw: a CleanupCoordinator that holds a
        // pending symbol set but no registered handler must NOT
        // report the symbols as cleaned. The previous behaviour
        // silently set symbols_cleaned = N, hiding application-side
        // handler-registration bugs that drop release receipts.
        // The fix: leave counters at zero, mark completed=false,
        // push a typed error into handler_errors, and restore the
        // pending set so a later register_handler + retry succeeds.
        let coord = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(99);
        let now = Time::from_nanos(0);

        // Register three pending symbols WITHOUT registering any
        // CleanupHandler — the exact pre-condition for the bug.
        coord.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 0, &[1, 2, 3, 4]),
            now,
        );
        coord.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 1, &[5, 6, 7, 8]),
            now,
        );
        coord.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 2, &[9, 10, 11, 12]),
            now,
        );

        let result = coord.cleanup(object_id, None);

        // Symbols-without-handler must NOT be reported as cleaned.
        assert_eq!(
            result.symbols_cleaned, 0,
            "no-handler outcome must not claim symbols cleaned, got {result:?}"
        );
        assert_eq!(
            result.bytes_freed, 0,
            "no-handler outcome must not claim bytes freed, got {result:?}"
        );
        assert!(
            !result.completed,
            "no-handler outcome must mark completed=false, got {result:?}"
        );
        assert!(
            result
                .handler_errors
                .iter()
                .any(|e| e.contains("no cleanup handler")),
            "missing-handler condition must surface as a typed error, got {:?}",
            result.handler_errors
        );

        // Pending set was restored so a retry can succeed.
        let stats = coord.stats();
        assert_eq!(
            stats.pending_objects, 1,
            "pending set must be restored for retry, got {stats:?}"
        );
        assert!(
            !coord.completed.read().contains(&object_id),
            "object_id must NOT be in completed set after no-handler outcome"
        );
    }
}
