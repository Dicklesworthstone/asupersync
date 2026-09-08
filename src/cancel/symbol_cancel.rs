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
use crate::types::{Budget, CancelAttributionConfig, CancelKind, CancelReason, Time};
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
    /// br-asupersync-mzamuo — Count of listener `on_cancel` callbacks
    /// (and listener-Drop side effects routed through them) that
    /// panicked and were caught via `catch_unwind`. Surfaced via
    /// [`SymbolCancelToken::listener_panic_count`] so silently-
    /// swallowed listener-reentrancy panics become observable
    /// instead of remaining invisible. Every such panic also emits
    /// a `tracing::warn!` (when the `tracing-integration` feature
    /// is on) carrying the panic message.
    listener_panic_count: AtomicU64,
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
                listener_panic_count: AtomicU64::new(0),
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
                listener_panic_count: AtomicU64::new(0),
            }),
        }
    }

    /// br-asupersync-mzamuo — Number of listener `on_cancel` calls
    /// that panicked and were recovered via `catch_unwind`. A
    /// non-zero value indicates that a listener (or its Drop impl)
    /// raised a panic during cancel notification — most commonly a
    /// listener whose Drop re-entered the originating token's cancel
    /// path. The runtime keeps running because of the `catch_unwind`
    /// guard, but operators can poll this counter to detect the
    /// invariant violation that would otherwise be silenced.
    #[must_use]
    pub fn listener_panic_count(&self) -> u64 {
        self.state.listener_panic_count.load(Ordering::Relaxed)
    }

    fn record_listener_panic(
        state: &CancelTokenState,
        panic_payload: Box<dyn std::any::Any + Send>,
    ) {
        // Always increment the counter first - this is the most critical operation
        // and least likely to panic (atomic operation on existing memory)
        state.listener_panic_count.fetch_add(1, Ordering::Relaxed);

        // Protect tracing operations from double-panic by wrapping in catch_unwind
        #[cfg(feature = "tracing-integration")]
        {
            let _trace_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                tracing::warn!(
                    object_id = ?state.object_id,
                    token_id = state.token_id,
                    panic = %panic_msg,
                    "cancel listener panicked during on_cancel — caught and logged \
                     instead of silently swallowed (br-asupersync-mzamuo)"
                );
            }));
            // If tracing itself panics, silently continue - we've already recorded the count
        }
        #[cfg(not(feature = "tracing-integration"))]
        {
            let _ = panic_payload;
        }
    }

    /// br-asupersync-mzamuo — Invoke a listener's `on_cancel` under
    /// `catch_unwind`. On panic, increment the per-token listener-
    /// panic counter and emit a `tracing::warn!`. Replaces the
    /// previous bare `let _ = catch_unwind(...)` shape that silently
    /// swallowed every panic, masking listener-Drop re-entrancy bugs
    /// (the scenario the bead exists to surface).
    fn notify_listener_with_panic_logging(
        state: &CancelTokenState,
        listener: &dyn CancelListener,
        reason: &CancelReason,
        now: Time,
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            listener.on_cancel(reason, now);
        }));
        if let Err(panic_payload) = result {
            Self::record_listener_panic(state, panic_payload);
        }
    }

    /// Late-add listeners are not retained, so this variant also
    /// covers any panic in the listener's `Drop` path by ensuring the
    /// owned box is dropped inside the `catch_unwind` boundary.
    fn notify_owned_listener_with_panic_logging(
        state: &CancelTokenState,
        listener: Box<dyn CancelListener>,
        reason: &CancelReason,
        now: Time,
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            listener.on_cancel(reason, now);
            drop(listener);
        }));
        if let Err(panic_payload) = result {
            Self::record_listener_panic(state, panic_payload);
        }
    }

    fn notify_retained_listeners_until_current(
        state: &CancelTokenState,
        target_reason: &CancelReason,
        target_severity: u8,
        force_target_notification: bool,
    ) {
        let notify_at_nanos = state.cancelled_at.load(Ordering::Acquire);
        let notify_at = if notify_at_nanos == u64::MAX {
            Time::ZERO
        } else {
            Time::from_nanos(notify_at_nanos)
        };
        let mut retained = {
            let mut listeners = state.listeners.write();
            std::mem::take(&mut *listeners)
        };

        for entry in &mut retained {
            if force_target_notification || entry.notified_severity < target_severity {
                Self::notify_listener_with_panic_logging(
                    state,
                    entry.listener.as_ref(),
                    target_reason,
                    notify_at,
                );
                entry.notified_severity = target_severity;
            }
        }

        // br-asupersync-4txkrb: Bound iteration count to prevent livelock
        // if concurrent threads keep strengthening the reason. After MAX_CATCH_UP_ITERATIONS
        // we yield and use snapshot semantics to avoid chasing a moving target.
        const MAX_CATCH_UP_ITERATIONS: u32 = 8;

        for iteration in 0..MAX_CATCH_UP_ITERATIONS {
            let reason_guard = state.reason.write();
            let Some(current_reason) = reason_guard.clone() else {
                let mut listeners = state.listeners.write();
                listeners.extend(retained);
                return;
            };
            let current_severity = current_reason.kind.severity();
            if retained
                .iter()
                .all(|entry| entry.notified_severity >= current_severity)
            {
                let mut listeners = state.listeners.write();
                listeners.extend(retained);
                return;
            }
            drop(reason_guard);

            for entry in &mut retained {
                if entry.notified_severity < current_severity {
                    Self::notify_listener_with_panic_logging(
                        state,
                        entry.listener.as_ref(),
                        &current_reason,
                        notify_at,
                    );
                    entry.notified_severity = current_severity;
                }
            }

            // Yield after each iteration except the last to allow other threads to progress
            if iteration < MAX_CATCH_UP_ITERATIONS - 1 {
                // Use cooperative yielding hint instead of async yield to avoid
                // changing function signature and breaking callers
                std::hint::spin_loop();
            }
        }

        // If we reach here, we've hit the iteration limit. Use snapshot semantics:
        // notify listeners with the final observed severity and return. This prevents
        // livelock while ensuring listeners see a reasonably recent severity level.
        let final_reason = {
            let reason_guard = state.reason.write();
            reason_guard
                .clone()
                .unwrap_or_else(CancelReason::parent_cancelled)
        };
        let final_severity = final_reason.kind.severity();

        for entry in &mut retained {
            if entry.notified_severity < final_severity {
                Self::notify_listener_with_panic_logging(
                    state,
                    entry.listener.as_ref(),
                    &final_reason,
                    notify_at,
                );
                entry.notified_severity = final_severity;
            }
        }

        // Restore retained listeners to the listener slab
        let mut listeners = state.listeners.write();
        listeners.extend(retained);
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

    fn parent_cancelled_with_cause(parent_reason: &CancelReason, at: Time) -> CancelReason {
        CancelReason::parent_cancelled()
            .with_timestamp(at)
            .with_cause_limited(parent_reason.clone(), &CancelAttributionConfig::default())
    }

    fn parent_cascade_reason_at(&self, at: Time) -> CancelReason {
        self.state.reason.read().as_ref().map_or_else(
            || CancelReason::parent_cancelled().with_timestamp(at),
            |reason| Self::parent_cancelled_with_cause(reason, at),
        )
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

        if !self.state.cancelled.load(Ordering::Acquire) {
            // First cancel(). Every writer of `cancelled` holds this write
            // lock, so no other cancel() can interleave here. Publish the
            // timestamp and the reason BEFORE the flag: a thread that
            // observes `cancelled == true` (Acquire) is then guaranteed to
            // see `cancelled_at` and the reason as well, so readers never
            // have to wait out an in-flight publication (the former
            // flag-first order forced a wall-clock bounded spin in
            // `child()`; br-asupersync-bi2462.22). Clamp to u64::MAX - 1 to
            // avoid colliding with the "not yet recorded" sentinel.
            let stored_nanos = now.as_nanos().min(u64::MAX - 1);
            self.state
                .cancelled_at
                .store(stored_nanos, Ordering::Release);
            *reason_guard = Some(reason.clone());
            self.state.cancelled.store(true, Ordering::Release);

            // Drop the reason lock before notifying to avoid reentrancy
            // deadlocks. Retained listeners are moved out of the listener
            // slab before callbacks run, then reinserted after catching up
            // to any concurrently strengthened reason. This lets a listener
            // re-enter `add_listener`: the late listener self-notifies via
            // the post-cancel path and is not retained.
            drop(reason_guard);

            let new_severity = reason.kind.severity();
            Self::notify_retained_listeners_until_current(&self.state, reason, new_severity, true);

            // Drain children without holding the lock. Safe because
            // `cancelled` is already true (CAS above), so any concurrent
            // `child()` will observe the flag and cancel directly instead
            // of pushing into this vec.
            let children = {
                let mut children = self.state.children.write();
                std::mem::take(&mut *children)
            };
            let parent_reason = self.parent_cascade_reason_at(now);
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
                Self::notify_retained_listeners_until_current(
                    &self.state,
                    &strengthened_reason,
                    new_severity,
                    false,
                );
            }

            false
        }
    }

    /// Returns the cancellation timestamp a `child()` inherits once
    /// `cancelled == true` has been observed under the `children` lock.
    ///
    /// `cancel()` publishes `cancelled_at` (and the reason) before it
    /// flips `cancelled`, both with Release ordering, so a flag observed
    /// with Acquire guarantees the timestamp is visible: there is no
    /// in-flight window to wait out (br-asupersync-n1a1br and
    /// br-asupersync-wze4x9 fixed the symptoms of the old flag-first
    /// order with a wall-clock bounded spin; br-asupersync-bi2462.22
    /// removed the window instead). The only reachable "cancelled
    /// without a timestamp" state is a token parsed from the wire
    /// (`from_bytes`) that no local `cancel()` has touched; its
    /// timestamp is `Time::ZERO` by definition. Never waits, never
    /// sleeps, takes no lock.
    fn inherited_cancelled_at(&self) -> Time {
        let nanos = self.state.cancelled_at.load(Ordering::Acquire);
        if nanos == u64::MAX {
            Time::ZERO
        } else {
            Time::from_nanos(nanos)
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
        //
        // br-asupersync-7yjuw7: Fix race condition where a child could be added
        // after parent cancellation. The original code dropped the children lock
        // and re-acquired it, creating a window where cancellation could complete
        // between the two lock acquisitions. Fixed by holding children lock during
        // the entire cancelled_at check sequence to ensure atomicity.
        let mut children = self.state.children.write();
        if !self.state.cancelled.load(Ordering::Acquire) {
            children.push(child.clone());
            return child;
        }

        // Parent is cancelled. Drop the children lock before resolving the
        // timestamp and the cascade reason, so other child creation is never
        // queued behind the reason lock (br-asupersync-53nvge). The flag
        // never resets, so the timestamp is final (or the wire-shape
        // `Time::ZERO`); nothing here waits or sleeps
        // (br-asupersync-bi2462.22).
        drop(children);

        let at = self.inherited_cancelled_at();
        let parent_reason = self.parent_cascade_reason_at(at);
        child.cancel(&parent_reason, at);

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
    /// written. If the stored reason is `None` despite `cancelled == true`
    /// (the valid `from_bytes` round-trip shape where `cancel()` was never
    /// called locally), the function falls back to the parent-cancel reason —
    /// never fabricates a `CancelKind::User`.
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
            let reason = reason_guard
                .clone()
                .unwrap_or_else(CancelReason::parent_cancelled);
            let at_nanos = self.state.cancelled_at.load(Ordering::Acquire);
            debug_assert!(
                at_nanos != u64::MAX || reason_guard.is_none(),
                "add_listener must not observe reason=Some(_) with unpublished cancelled_at"
            );
            let at = if at_nanos == u64::MAX {
                Time::ZERO
            } else {
                Time::from_nanos(at_nanos)
            };
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
            // br-asupersync-mzamuo — same panic-logging discipline as
            // the cancel/strengthen paths. The listener is not boxed
            // here so we route through the helper via a transient
            // Box<dyn> indirection; the cost is amortised because
            // this path only runs on add-after-cancel.
            let boxed: Box<dyn CancelListener> = Box::new(listener);
            Self::notify_owned_listener_with_panic_logging(&self.state, boxed, &reason, at);
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
                listener_panic_count: AtomicU64::new(0),
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
    /// br-asupersync-evpqdt — the wm9h2a fix originally gated this
    /// behind `#[cfg(any(test, feature = "test-internals"))]`. That
    /// gate was ILLUSORY in default builds because Cargo.toml has
    /// `default = ["test-internals", "proc-macros"]` — `test-internals`
    /// is enabled by default for any consumer who adds asupersync to
    /// their `Cargo.toml` without `default-features = false`. The
    /// constructor remained freely callable from any external crate,
    /// reopening the exact forgery surface wm9h2a was supposed to
    /// close.
    ///
    /// The current gate is `#[cfg(test)]` only — strict in-crate
    /// test compilation. External crates that need to mint synthetic
    /// `SymbolCancelToken` values for their own tests must go
    /// through the legitimate issuance ceremony
    /// (`CancelBroadcaster::register` / `prepare_cancel`); there is
    /// no longer any cross-crate-reachable forgery path. The only
    /// internal callers are the wm9h2a regression test and the
    /// listener-uniqueness test inside this file.
    #[doc(hidden)]
    #[must_use]
    #[cfg(test)]
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
                listener_panic_count: AtomicU64::new(0),
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
    /// Failed broadcast messages pending retry.
    /// br-asupersync-dm6ci4: Track count of messages queued for retry
    /// after failed broadcast attempts.
    pub pending_retries: u64,
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
    /// Failed broadcast messages pending retry.
    /// br-asupersync-dm6ci4: Preserve failed forward broadcasts for retry
    /// instead of dropping them on broadcast errors. The retry queue maintains
    /// failed messages in order for deterministic re-attempt behavior.
    pending_retries: RwLock<VecDeque<CancelMessage>>,
    /// Ensures only one retry pass drains the retry queue at a time.
    /// Concurrent retry callers otherwise can split the queue and violate
    /// the FIFO "stop on first failure" contract documented below.
    retry_in_progress: AtomicBool,
    /// br-asupersync-ml5ba5 — Per-broadcaster random tag mixed into
    /// the synthetic token_id `prepare_cancel` mints when no local
    /// `SymbolCancelToken` exists for an object. Without this,
    /// every broadcaster computed the same synthetic
    /// `object_id.high ^ object_id.low`, which (1) collided across
    /// senders that both cancelled the same object without holding a
    /// local token, causing the receiver's `(object_id, token_id,
    /// sequence)` dedup set to incorrectly suppress the second
    /// sender's cancel when sequence numbers happened to overlap
    /// (each broadcaster's `next_sequence` starts from 0); and
    /// (2) was publicly derivable from the on-the-wire ObjectId, so
    /// an attacker could mint cancels with the predictable token_id
    /// and arbitrary sequence numbers to flush the dedup set or
    /// pre-poison it. Sender_tag is OS-random per-broadcaster, so
    /// two different broadcasters produce distinct synthetic
    /// token_ids for the same ObjectId — preserving the
    /// single-sender contract (same broadcaster + same object →
    /// same synthetic, since `sender_tag` is stable for the
    /// broadcaster's lifetime) while defeating cross-sender
    /// collision.
    sender_tag: u64,
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
        // br-asupersync-ml5ba5 — Mint a per-broadcaster random
        // sender_tag from the OS entropy source. The tag is stable
        // for the broadcaster's lifetime and is mixed into synthetic
        // token_ids when no local token exists for an object.
        let mut tag_buf = [0u8; 8];
        getrandom::fill(&mut tag_buf).expect("OS entropy source unavailable");
        let sender_tag = u64::from_ne_bytes(tag_buf);
        Self {
            peers: RwLock::new(SmallVec::new()),
            active_tokens: RwLock::new(HashMap::new()),
            seen_sequences: RwLock::new(SeenSequences::default()),
            max_seen: 10_000,
            sink,
            next_sequence: AtomicU64::new(0),
            sender_tag,
            pending_retries: RwLock::new(VecDeque::new()),
            retry_in_progress: AtomicBool::new(false),
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
        // br-asupersync-ml5ba5 — synthetic fallback now mixes
        // self.sender_tag so two broadcasters cancelling the same
        // ObjectId without a local token produce distinct token_ids,
        // defeating the cross-sender dedup collision and the
        // publicly-derivable token_id attack.
        let (token, token_id) = {
            let tokens = self.active_tokens.read();
            tokens.get(&object_id).map_or_else(
                || (None, self.sender_tag ^ object_id.high() ^ object_id.low()),
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
    pub fn receive_message(
        &self,
        msg: &CancelMessage,
        _received_at: Time,
    ) -> Option<CancelMessage> {
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
            // br-asupersync-zmeazg: a forwarded cancel must preserve the origin
            // timestamp carried on the wire. Using the local receipt time here
            // skews cancelled_at/listener observations on every downstream peer.
            token.cancel(&reason, msg.initiated_at());
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
        match self.sink.broadcast(&msg).await {
            Ok(count) => Ok(count),
            Err(err) => {
                // br-asupersync-dm6ci4: On broadcast failure, preserve the message
                // for retry instead of dropping it. This ensures failed forward
                // broadcasts can be re-attempted later via retry_failed_broadcasts().
                self.pending_retries.write().push_back(msg);
                Err(err)
            }
        }
    }

    /// Handles a received cancellation message and forwards if appropriate.
    pub async fn handle_message(&self, msg: CancelMessage, now: Time) -> crate::error::Result<()> {
        if let Some(forwarded) = self.receive_message(&msg, now) {
            match self.sink.broadcast(&forwarded).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    // br-asupersync-dm6ci4: On forward broadcast failure, preserve
                    // the forwarded message for retry instead of dropping it.
                    self.pending_retries.write().push_back(forwarded);
                    Err(err)
                }
            }
        } else {
            Ok(())
        }
    }

    /// Retries failed broadcast messages.
    ///
    /// br-asupersync-dm6ci4: Re-attempts broadcasting of messages that previously
    /// failed due to network or sink errors. Messages are retried in FIFO order
    /// to preserve temporal causality. Successfully broadcast messages are removed
    /// from the retry queue; failed messages remain queued for subsequent retries.
    /// Only one retry pass may run at a time; concurrent callers return without
    /// consuming queue state so they cannot reorder pending messages.
    ///
    /// Returns the number of messages successfully retried and any error from the
    /// last failed retry attempt.
    pub async fn retry_failed_broadcasts(&self) -> (usize, Option<crate::error::Error>) {
        struct RetryGuard<'a>(&'a AtomicBool);

        impl Drop for RetryGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }

        if self
            .retry_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return (0, None);
        }
        let _retry_guard = RetryGuard(&self.retry_in_progress);

        let mut retried_count = 0;
        let mut last_error = None;

        // Process retry queue until empty or we hit a failure
        loop {
            let (msg, original_queue_len) = {
                let mut retries = self.pending_retries.write();
                let msg = retries.pop_front();
                let queue_len = retries.len();
                (msg, queue_len)
            };

            let Some(msg) = msg else {
                break; // No more messages to retry
            };

            match self.sink.broadcast(&msg).await {
                Ok(_) => {
                    retried_count += 1;
                    // Successfully retried, continue with next message
                }
                Err(err) => {
                    // Failed again, put message back preserving FIFO order.
                    // Insert at the position it would have been if we hadn't removed it,
                    // accounting for any messages added during the async broadcast.
                    {
                        let mut retries = self.pending_retries.write();
                        let current_len = retries.len();
                        if current_len > original_queue_len {
                            // New messages were added during broadcast, insert after original messages
                            // but before the newly added ones to preserve temporal ordering
                            retries.insert(original_queue_len, msg);
                        } else {
                            // No new messages added, safe to put back at front
                            retries.push_front(msg);
                        }
                    }
                    last_error = Some(err);
                    break; // Stop retrying on first failure to preserve order
                }
            }
        }

        (retried_count, last_error)
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
            pending_retries: self.pending_retries.read().len() as u64,
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
        if seen.set.contains(&(object_id, token_id, sequence)) {
            return;
        }

        // br-asupersync-as12cf — evict BEFORE insert, not after.
        // The previous shape (insert -> evict-while-over-cap) left
        // the set holding `max_seen + 1` entries during the brief
        // window between the insert and the eviction loop. Although
        // the write lock prevents any other thread from observing
        // the over-allocated state, the bounded-memory contract is
        // a documentation invariant that future maintainers (and
        // peak-memory accounting tools) read literally. Evicting
        // first keeps `seen.set.len()` strictly within `max_seen`
        // at every observable point in time.
        while seen.set.len() >= self.max_seen {
            if seen.remove_oldest().is_none() {
                break;
            }
        }

        seen.insert((object_id, token_id, sequence));
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

struct ActiveCleanupGuard<'a> {
    object_id: ObjectId,
    active: &'a RwLock<HashSet<ObjectId>>,
}

impl Drop for ActiveCleanupGuard<'_> {
    fn drop(&mut self) {
        self.active.write().remove(&self.object_id);
    }
}

/// Coordinates cleanup of partial symbol sets.
pub struct CleanupCoordinator {
    /// Pending symbol sets by object ID.
    pending: RwLock<HashMap<ObjectId, PendingSymbolSet>>,
    /// Cleanup handlers by object ID.
    handlers: RwLock<HashMap<ObjectId, Box<dyn CleanupHandler>>>,
    /// Completed object IDs that no longer accept pending symbols.
    completed: RwLock<HashSet<ObjectId>>,
    /// Symbols buffered during cleanup attempts (to prevent drops during retry).
    cleanup_buffer: RwLock<HashMap<ObjectId, Vec<Symbol>>>,
    /// Object IDs currently executing a cleanup attempt.
    cleanup_active: RwLock<HashSet<ObjectId>>,
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
            cleanup_buffer: RwLock::new(HashMap::new()),
            cleanup_active: RwLock::new(HashSet::new()),
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

        // Check if object is in cleanup buffer (mid-retry); if so, buffer the symbol
        // rather than dropping it, so it can be replayed when retry completes.
        let mut cleanup_buffer = self.cleanup_buffer.write();
        if cleanup_buffer.contains_key(&object_id) {
            cleanup_buffer.entry(object_id).or_default().push(symbol);
            return;
        }
        drop(cleanup_buffer); // Release buffer lock before modifying pending

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
        mut pending_set: PendingSymbolSet,
    ) {
        // Take the handler table before the retry-state locks. Keeping this
        // acquisition out of the pending/completed critical path avoids a
        // future handlers->pending caller turning this path into an AB-BA cycle.
        let mut handlers = self.handlers.write();

        // Keep `pending` held while draining the cleanup buffer and clearing
        // `completed` so reopening retry state is atomic with respect to
        // register_pending() and cannot drop symbols in the reopen window.
        let mut pending = self.pending.write();
        let mut completed = self.completed.write();

        // If clear_pending was called concurrently during a cleanup attempt,
        // the object has been successfully decoded. We must not restore the
        // retry state (which would un-complete the object and cause memory leaks).
        if completed.contains(&object_id) {
            // Also clean up any trailing buffered symbols that arrived late
            self.cleanup_buffer.write().remove(&object_id);
            return;
        }

        handlers.insert(object_id, handler);

        let mut cleanup_buffer = self.cleanup_buffer.write();
        if let Some(buffered_symbols) = cleanup_buffer.remove(&object_id) {
            for symbol in buffered_symbols {
                pending_set.total_bytes = pending_set.total_bytes.saturating_add(symbol.len());
                pending_set.symbols.push(symbol);
            }
        }
        pending.insert(object_id, pending_set);
        completed.remove(&object_id);
    }

    #[allow(clippy::significant_drop_tightening)]
    fn restore_pending_only_state(&self, object_id: ObjectId, mut pending_set: PendingSymbolSet) {
        let mut pending = self.pending.write();
        let mut completed = self.completed.write();

        if completed.contains(&object_id) {
            self.cleanup_buffer.write().remove(&object_id);
            return;
        }

        let mut cleanup_buffer = self.cleanup_buffer.write();
        if let Some(buffered_symbols) = cleanup_buffer.remove(&object_id) {
            for symbol in buffered_symbols {
                pending_set.total_bytes = pending_set.total_bytes.saturating_add(symbol.len());
                pending_set.symbols.push(symbol);
            }
        }
        pending.insert(object_id, pending_set);
        completed.remove(&object_id);
    }

    /// Registers a cleanup handler for an object.
    pub fn register_handler(&self, object_id: ObjectId, handler: impl CleanupHandler + 'static) {
        self.handlers.write().insert(object_id, Box::new(handler));
    }

    #[inline]
    fn empty_pending_set() -> PendingSymbolSet {
        PendingSymbolSet {
            symbols: Vec::new(),
            total_bytes: 0,
            _created_at: Time::ZERO,
        }
    }

    /// Clears pending symbols for an object (e.g., after successful decode).
    pub fn clear_pending(&self, object_id: &ObjectId) -> Option<usize> {
        // A successfully decoded object no longer needs its cleanup handler;
        // retaining it would leak per-object handler state indefinitely.
        self.handlers.write().remove(object_id);
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

        let _active_guard = {
            let mut active = self.cleanup_active.write();
            if !active.insert(object_id) {
                result.completed = false;
                result.handler_errors.push(format!(
                    "cleanup already in progress for object {object_id:?}; \
                     rejecting reentrant cleanup attempt (br-asupersync-a19xwn)"
                ));
                return result;
            }
            ActiveCleanupGuard {
                object_id,
                active: &self.cleanup_active,
            }
        };

        // Create the cleanup buffer entry before extracting pending symbols so
        // register_pending() callers racing with cleanup() are captured in the
        // buffer rather than silently repopulating `pending` behind this pass.
        self.cleanup_buffer.write().entry(object_id).or_default();

        // Atomically extract the handler and pending symbols. Don't mark as
        // completed until handler succeeds.
        let handler = { self.handlers.write().remove(&object_id) };
        let pending_set = { self.pending.write().remove(&object_id) };
        let had_handler = handler.is_some();

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
                    // A CleanupHandler is contracted to report failure via `Err`.
                    // If it panics instead, `set.symbols` is moved into the call and
                    // lost to the unwind while neither match arm runs — stranding
                    // the pre-created `cleanup_buffer` entry with the object neither
                    // completed nor restorable, and (for a Probe permit elsewhere)
                    // leaving the caller unable to recover it. Wrap the call so a
                    // panic is handled exactly like `Err`: fail closed and restore
                    // the retry state from the pre-move clone, so the object stays
                    // retryable. Mirrors `notify_owned_listener_with_panic_logging`
                    // (br-asupersync-l6i6i8).
                    let symbols = set.symbols;
                    let cleanup_outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            handler.cleanup(object_id, symbols)
                        }));
                    match cleanup_outcome {
                        Ok(Ok(_)) => {
                            // Handler succeeded - mark as completed and clean up buffer
                            self.completed.write().insert(object_id);
                            self.cleanup_buffer.write().remove(&object_id);
                            result.symbols_cleaned = symbol_count;
                            result.bytes_freed = total_bytes;
                        }
                        Ok(Err(err)) => {
                            // The cleanup attempt failed; retain the pending set and
                            // handler so the caller can retry deterministically.
                            // The cleanup buffer is preserved by restore_retry_state.
                            self.restore_retry_state(object_id, handler, retry_set);
                            result.completed = false;
                            result.handler_errors.push(format!("{handler_name}: {err}"));
                        }
                        Err(panic_payload) => {
                            // Handler violated its Result contract by panicking.
                            // Recover identically to the Err path so the object is
                            // retryable, not stranded.
                            let panic_msg = panic_payload
                                .downcast_ref::<&str>()
                                .map(|s| (*s).to_string())
                                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "unknown panic".to_string());
                            self.restore_retry_state(object_id, handler, retry_set);
                            result.completed = false;
                            result
                                .handler_errors
                                .push(format!("{handler_name}: cleanup panicked: {panic_msg}"));
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
                // completion. No completion is recorded on this path
                // (the `completed` set is only written on handler
                // success above), so there is nothing to roll back.
                result.completed = false;
                result.handler_errors.push(format!(
                    "no cleanup handler registered for object {object_id:?}; \
                     {symbol_count} symbol(s) / {total_bytes} byte(s) deferred \
                     (br-asupersync-batcyw)"
                ));

                // Restore the pending set through the shared helper. Unlike the
                // previous inline insert, this holds `pending` -> `completed`
                // and REFUSES to resurrect an object that a concurrent
                // `clear_pending()` (successful decode) already marked
                // completed. Re-inserting pending onto a completed object was a
                // permanent leak: `register_pending()` rejects completed
                // objects and, with no handler registered, no retry path can
                // ever drain the resurrected set. The helper also drains any
                // buffered late-arriving symbols back into the restored set.
                self.restore_pending_only_state(object_id, set);
            }
        } else {
            // No pending symbols. Decide completion under the SAME lock
            // discipline as `restore_*` — hold `pending` -> `completed` ->
            // `cleanup_buffer` across the empty-buffer check, the buffer removal,
            // and the `completed` insert. `register_pending()` holds
            // `pending.write()` for its entire body (checking `completed` and
            // `cleanup_buffer` under it), so serializing here is what prevents a
            // concurrently-registered symbol from being (a) dropped together
            // with the buffer entry we remove, or (b) inserted into `pending`
            // just before we mark the object completed and then stranded there
            // forever after its handler is gone (qivp4o). The `> 0` restore path
            // runs OUTSIDE this guard because `restore_*` re-acquires the chain.
            let buffered_symbol_count = {
                let _pending_guard = self.pending.write();
                let mut completed = self.completed.write();
                let mut cleanup_buffer = self.cleanup_buffer.write();
                let count = cleanup_buffer.get(&object_id).map_or(0, Vec::len);
                if count == 0 {
                    cleanup_buffer.remove(&object_id);
                    if result.completed && had_handler {
                        // A registered handler with no pending or buffered
                        // symbols still represents a fully completed cleanup
                        // lifecycle. Record that completion so late
                        // register_pending() calls cannot silently reopen the
                        // object after its handler has been dropped.
                        completed.insert(object_id);
                    }
                }
                count
            };
            if buffered_symbol_count > 0 {
                let new_set = Self::empty_pending_set();
                if let Some(handler) = handler {
                    self.restore_retry_state(object_id, handler, new_set);
                } else {
                    self.restore_pending_only_state(object_id, new_set);
                }
                result.completed = false; // Can't complete without symbols to clean
            }
        }

        if result.completed {
            // Reentrant or concurrent register_handler() calls during cleanup
            // must not leak stale per-object handlers after the object has
            // reached a completed terminal state.
            self.handlers.write().remove(&object_id);
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
include!("symbol_cancel_tests.rs");

#[cfg(test)]
#[path = "symbol_cancel_metamorphic.rs"]
mod symbol_cancel_metamorphic;
