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

    /// Returns the cancellation timestamp to inherit in `child()`
    /// after `cancelled == true` has been observed under the
    /// `children` lock.
    ///
    /// br-asupersync-n1a1br: if a local `cancel()` is in flight, the
    /// flag can become visible before `cancelled_at` is written. In
    /// that window the reason write lock is still held, so `try_read`
    /// fails and we spin until the timestamp is published. For
    /// deserialized remote tokens (`from_bytes`) there is no local
    /// writer and `reason == None`, so the fallback remains
    /// `Time::ZERO`.
    fn cancelled_at_snapshot_for_child(&self) -> Option<Time> {
        if !self.is_cancelled() {
            return None;
        }

        // br-asupersync-wze4x9: Replace infinite spin with bounded retry + yield
        // to prevent livelock under thread contention. The race window should
        // resolve quickly under normal circumstances.
        const MAX_RETRIES: u32 = 1000;
        for _attempt in 0..MAX_RETRIES {
            let nanos = self.state.cancelled_at.load(Ordering::Acquire);
            if nanos != u64::MAX {
                return Some(Time::from_nanos(nanos));
            }

            if let Some(reason_guard) = self.state.reason.try_read() {
                if reason_guard.is_none() {
                    return Some(Time::ZERO);
                }

                let synced = self.state.cancelled_at.load(Ordering::Acquire);
                debug_assert_ne!(
                    synced,
                    u64::MAX,
                    "cancelled_at must be published before reason write lock is released"
                );
                return Some(if synced == u64::MAX {
                    Time::ZERO
                } else {
                    Time::from_nanos(synced)
                });
            }

            // Yield control instead of spinning to prevent livelock
            std::thread::sleep(std::time::Duration::from_nanos(100));
        }

        // If we exceed retry limit, fall back to Time::ZERO (cancelled but unknown timestamp)
        // This should be extremely rare and indicates a pathological contention scenario.
        Some(Time::ZERO)
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

        // Parent is cancelled. Drop the children lock before waiting for timestamp
        // to avoid blocking other child creation during the timestamp resolution.
        drop(children);

        if let Some(at) = self.cancelled_at_snapshot_for_child() {
            let parent_reason = self.parent_cascade_reason_at(at);
            child.cancel(&parent_reason, at);
        } else {
            // Timestamp not yet available. Re-acquire children lock and check again.
            // This ensures we don't add a child if cancellation completed while
            // we were waiting for the timestamp.
            let mut children = self.state.children.write();
            if !self.state.cancelled.load(Ordering::Acquire) {
                children.push(child.clone());
            } else {
                // Parent became fully cancelled while we waited. Cancel the child.
                drop(children);
                // Wait for timestamp with exponential backoff to avoid busy spinning
                let mut backoff_ms = 1;
                for _ in 0..10 {
                    if let Some(at) = self.cancelled_at_snapshot_for_child() {
                        let parent_reason = self.parent_cascade_reason_at(at);
                        child.cancel(&parent_reason, at);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = (backoff_ms * 2).min(16);
                }
            }
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
                    match handler.cleanup(object_id, set.symbols) {
                        Ok(_) => {
                            // Handler succeeded - mark as completed and clean up buffer
                            self.completed.write().insert(object_id);
                            self.cleanup_buffer.write().remove(&object_id);
                            result.symbols_cleaned = symbol_count;
                            result.bytes_freed = total_bytes;
                        }
                        Err(err) => {
                            // The cleanup attempt failed; retain the pending set and
                            // handler so the caller can retry deterministically.
                            // The cleanup buffer is preserved by restore_retry_state.
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

                // Merge any buffered symbols back into the pending set
                let mut cleanup_buffer = self.cleanup_buffer.write();
                let mut restored_set = set;
                if let Some(buffered_symbols) = cleanup_buffer.remove(&object_id) {
                    for symbol in buffered_symbols {
                        restored_set.total_bytes =
                            restored_set.total_bytes.saturating_add(symbol.len());
                        restored_set.symbols.push(symbol);
                    }
                }
                drop(cleanup_buffer);

                // Restore pending; don't mark completed (no handler to retry with).
                self.pending.write().insert(object_id, restored_set);
            }
        } else {
            // No pending symbols, but check cleanup buffer for symbols that arrived
            // during a previous cleanup attempt
            let buffered_symbol_count = self
                .cleanup_buffer
                .read()
                .get(&object_id)
                .map_or(0, Vec::len);
            if buffered_symbol_count > 0 {
                let new_set = Self::empty_pending_set();
                if let Some(handler) = handler {
                    self.restore_retry_state(object_id, handler, new_set);
                } else {
                    self.restore_pending_only_state(object_id, new_set);
                }
                result.completed = false; // Can't complete without symbols to clean
            } else {
                self.cleanup_buffer.write().remove(&object_id);
            }
            if result.completed && had_handler {
                // A registered handler with no pending or buffered symbols still
                // represents a fully completed cleanup lifecycle. Record that
                // completion so late register_pending() calls cannot silently
                // reopen the object after its handler has been dropped.
                self.completed.write().insert(object_id);
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

    struct CountingCleanupHandler;
    impl CleanupHandler for CountingCleanupHandler {
        fn cleanup(
            &self,
            _object_id: ObjectId,
            symbols: Vec<Symbol>,
        ) -> crate::error::Result<usize> {
            Ok(symbols.len())
        }

        fn name(&self) -> &'static str {
            "counting"
        }
    }

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
            order.lock().unwrap().push(token_id); // ubs:ignore - test helper
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

    fn reason_chain_kinds(token: &SymbolCancelToken) -> Vec<CancelKind> {
        token
            .reason()
            .map(|reason| reason.chain().map(|reason| reason.kind).collect())
            .unwrap_or_default()
    }

    fn observable_token_state_json(token: &SymbolCancelToken) -> Value {
        serde_json::json!({
            "cancelled": token.is_cancelled(),
            "cancelled_at_nanos": token.cancelled_at().map(Time::as_nanos),
            "queued_children": token.state.children.read().len(),
            "queued_listeners": token.state.listeners.read().len(),
            "reason_kind": token.reason().map(|reason| format!("{:?}", reason.kind)),
        })
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
                {
                    checkpoints.lock().unwrap().push(event);
                    messages.lock().unwrap().push(message); // ubs:ignore - test helper
                } // Drop mutex guards before yield
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
        assert_eq!(
            reason_chain_kinds(&child),
            vec![CancelKind::ParentCancelled, CancelKind::User],
            "child cancellation should carry the root parent reason as a cause"
        );
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
                vec![CancelKind::ParentCancelled, CancelKind::User],
                "sibling child should retain the parent cancellation as its cause"
            );
            assert_eq!(
                scenario.right_leaf_after_parent.cause_chain,
                vec![
                    CancelKind::ParentCancelled,
                    CancelKind::ParentCancelled,
                    CancelKind::User,
                ],
                "dropped-handle descendant should preserve the full parent-cancelled cause chain"
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
    fn test_cancel_token_transition_serialization_golden() {
        let mut rng = DetRng::new(0x1337_beef_cafe_dead);

        // Test different token states for golden snapshot stability
        let scenarios = vec![
            ("fresh_token", {
                let obj = ObjectId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
                SymbolCancelToken::new(obj, &mut rng)
            }),
            ("cancelled_token", {
                let obj = ObjectId::new(0xaaaa_bbbb_cccc_dddd, 0xeeee_ffff_0000_1111);
                let token = SymbolCancelToken::new(obj, &mut rng);
                token.cancel(
                    &CancelReason::timeout(),
                    crate::types::Time::from_millis(1000),
                );
                token
            }),
            ("test_token_minimal", {
                SymbolCancelToken::new_for_test(0x1234_5678_9abc_def0, ObjectId::new(0x0, 0x1))
            }),
            ("test_token_max_values", {
                let token = SymbolCancelToken::new_for_test(
                    0xffff_ffff_ffff_ffff,
                    ObjectId::new(0xdead_beef_cafe_babe, 0x1337_1337_1337_1337),
                );
                token.cancel(
                    &CancelReason::user("test"),
                    crate::types::Time::from_millis(9999),
                );
                token
            }),
        ];

        // Capture wire format serialization as stable golden artifacts
        for (name, token) in scenarios {
            let bytes = token.to_bytes();

            // Create deterministic hex representation for golden comparison
            let hex_output = format!(
                "Token: {}\n\
                Token ID: 0x{:016x}\n\
                Object ID: 0x{:016x}:0x{:016x}\n\
                Cancelled: {}\n\
                Wire bytes: [{}]\n\
                Hex: {}",
                name,
                token.token_id(),
                token.object_id().high(),
                token.object_id().low(),
                token.is_cancelled(),
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(", "),
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );

            let expected = match name {
                "fresh_token" => concat!(
                    "Token: fresh_token\n",
                    "Token ID: 0xc35d712d21a92850\n",
                    "Object ID: 0x1111222233334444:0x5555666677778888\n",
                    "Cancelled: false\n",
                    "Wire bytes: [c3, 5d, 71, 2d, 21, a9, 28, 50, 11, 11, 22, 22, 33, 33, 44, 44, 55, 55, 66, 66, 77, 77, 88, 88, 00]\n",
                    "Hex: c35d712d21a928501111222233334444555566667777888800"
                ),
                "cancelled_token" => concat!(
                    "Token: cancelled_token\n",
                    "Token ID: 0x24c64de6e8aa6e00\n",
                    "Object ID: 0xaaaabbbbccccdddd:0xeeeeffff00001111\n",
                    "Cancelled: true\n",
                    "Wire bytes: [24, c6, 4d, e6, e8, aa, 6e, 00, aa, aa, bb, bb, cc, cc, dd, dd, ee, ee, ff, ff, 00, 00, 11, 11, 01]\n",
                    "Hex: 24c64de6e8aa6e00aaaabbbbccccddddeeeeffff0000111101"
                ),
                "test_token_minimal" => concat!(
                    "Token: test_token_minimal\n",
                    "Token ID: 0x123456789abcdef0\n",
                    "Object ID: 0x0000000000000000:0x0000000000000001\n",
                    "Cancelled: false\n",
                    "Wire bytes: [12, 34, 56, 78, 9a, bc, de, f0, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 01, 00]\n",
                    "Hex: 123456789abcdef00000000000000000000000000000000100"
                ),
                "test_token_max_values" => concat!(
                    "Token: test_token_max_values\n",
                    "Token ID: 0xffffffffffffffff\n",
                    "Object ID: 0xdeadbeefcafebabe:0x1337133713371337\n",
                    "Cancelled: true\n",
                    "Wire bytes: [ff, ff, ff, ff, ff, ff, ff, ff, de, ad, be, ef, ca, fe, ba, be, 13, 37, 13, 37, 13, 37, 13, 37, 01]\n",
                    "Hex: ffffffffffffffffdeadbeefcafebabe133713371337133701"
                ),
                _ => unreachable!("unknown cancel token serialization scenario: {name}"),
            };

            assert_eq!(hex_output, expected);
        }
    }

    #[test]
    fn cancel_token_phase_transition_trace_canonical() {
        let mut rng = DetRng::new(0x53A9_0001_0002_0003);
        let parent = SymbolCancelToken::new(
            ObjectId::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888),
            &mut rng,
        );
        let preexisting_child = parent.child(&mut rng);
        let listener_events = Arc::new(StdMutex::new(Vec::<Value>::new()));
        let listener_events_for_callback = Arc::clone(&listener_events);
        parent.add_listener(move |reason: &CancelReason, at: Time| {
            listener_events_for_callback
                .lock()
                .unwrap()
                .push(serde_json::json!({
                    "at_nanos": at.as_nanos(),
                    "kind": format!("{:?}", reason.kind),
                }));
        });

        let fresh_parent = observable_token_state_json(&parent);
        let fresh_preexisting_child = observable_token_state_json(&preexisting_child);

        let first_cancel_at = Time::from_nanos(991);
        assert!(
            parent.cancel(&CancelReason::user("phase-zero"), first_cancel_at),
            "first cancel should transition the token"
        );

        let after_first_cancel_events = listener_events.lock().unwrap().clone();
        let after_first_cancel_parent = observable_token_state_json(&parent);
        let after_first_cancel_preexisting_child = observable_token_state_json(&preexisting_child);

        let late_child = parent.child(&mut rng);
        let after_late_child_parent = observable_token_state_json(&parent);
        let after_late_child_late_child = observable_token_state_json(&late_child);

        let strengthened_returned_first_caller =
            parent.cancel(&CancelReason::shutdown(), Time::from_nanos(4096));

        let after_strengthen_events = listener_events.lock().unwrap().clone();
        let after_strengthen_parent = observable_token_state_json(&parent);
        let after_strengthen_preexisting_child = observable_token_state_json(&preexisting_child);
        let after_strengthen_late_child = observable_token_state_json(&late_child);

        let trace = serde_json::json!({
            "fresh": {
                "parent": fresh_parent,
                "preexisting_child": fresh_preexisting_child,
            },
            "after_first_cancel": {
                "listener_events": after_first_cancel_events,
                "parent": after_first_cancel_parent,
                "preexisting_child": after_first_cancel_preexisting_child,
            },
            "after_late_child": {
                "late_child": after_late_child_late_child,
                "parent": after_late_child_parent,
            },
            "after_strengthen": {
                "late_child": after_strengthen_late_child,
                "listener_events": after_strengthen_events,
                "parent": after_strengthen_parent,
                "preexisting_child": after_strengthen_preexisting_child,
                "strengthened_returned_first_caller": strengthened_returned_first_caller,
            },
        });

        insta::assert_json_snapshot!("cancel_token_phase_transition_trace_canonical", trace);
    }

    /// br-asupersync-64ijds — Conformance: a panic inside a registered
    /// `CancelListener::on_cancel` MUST NOT propagate to the caller of
    /// `SymbolCancelToken::cancel`. The implementation wraps each
    /// listener invocation in `std::panic::catch_unwind` (3 sites:
    /// the cancel hot path, the strengthen-and-renotify path, and the
    /// late-add notification path) — this test pins that contract so
    /// a future refactor can't accidentally remove the catch_unwind
    /// and propagate a malicious-listener panic up to the caller, who
    /// would then have its own protocol state corrupted by an
    /// unwinding stack.
    #[test]
    fn listener_panic_does_not_propagate_to_cancel_caller() {
        struct PanickingListener;
        impl CancelListener for PanickingListener {
            fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
                panic!("br-asupersync-64ijds: listener intentionally panics");
            }
        }

        struct CountingListener {
            calls: Arc<std::sync::atomic::AtomicU64>,
        }
        impl CancelListener for CountingListener {
            fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let mut rng = DetRng::new(64);
        let token = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);

        // Attach panicking listener FIRST, then counting listener
        // SECOND. If catch_unwind ever regressed, the panicking
        // listener would short-circuit notification of subsequent
        // listeners — testing this proves the isolation extends past
        // the panic and reaches the next listener in the slot list.
        token.add_listener(PanickingListener);
        let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        token.add_listener(CountingListener {
            calls: Arc::clone(&calls),
        });

        // Path 1: initial cancel. The panicking listener fires first;
        // catch_unwind absorbs the panic; the counting listener still
        // fires; cancel() returns true to the caller without unwinding.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.cancel(&CancelReason::user("initial"), Time::from_millis(100))
        }));
        assert!(
            result.is_ok(),
            "br-asupersync-64ijds: cancel must not propagate listener panic"
        );
        assert_eq!(result.unwrap(), true, "first cancel should return true");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "br-asupersync-64ijds: counting listener must fire even when prior listener panicked"
        );
        assert!(token.is_cancelled());

        // Path 2: strengthen-and-renotify. A higher-severity reason
        // hits the renotification path which has its own catch_unwind;
        // verify the same isolation invariant.
        let result2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.cancel(&CancelReason::timeout(), Time::from_millis(200))
        }));
        assert!(
            result2.is_ok(),
            "br-asupersync-64ijds: renotification must not propagate listener panic"
        );
        // Both listeners fire on renotify; counting listener should
        // see at least one more call.
        assert!(
            calls.load(std::sync::atomic::Ordering::Relaxed) >= 2,
            "counting listener must fire on renotification"
        );

        // Path 3: late-attach replay. Adding a listener AFTER the
        // token is already cancelled triggers the catch_unwind'd
        // late-add notification path. A panicking listener attached
        // post-cancel must not propagate either.
        let result3 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.add_listener(PanickingListener);
        }));
        assert!(
            result3.is_ok(),
            "br-asupersync-64ijds: late-add must not propagate listener panic"
        );
    }

    #[test]
    fn test_deserialized_cancelled_token_notifies_listener() {
        use std::sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        };

        let mut rng = DetRng::new(42);
        let cancel_handle = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
        cancel_handle.cancel(&CancelReason::user("initial"), Time::from_millis(100));

        let parsed = SymbolCancelToken::from_bytes(&cancel_handle.to_bytes()).unwrap();
        assert!(parsed.is_cancelled());

        let notified = Arc::new(AtomicBool::new(false));
        let notified_clone = Arc::clone(&notified);
        let seen_at = Arc::new(Mutex::new(None::<Time>));
        let seen_at_clone = Arc::clone(&seen_at);
        parsed.add_listener(move |_reason: &CancelReason, at: Time| {
            notified_clone.store(true, Ordering::SeqCst);
            *seen_at_clone.lock().unwrap() = Some(at);
        });

        assert!(notified.load(Ordering::SeqCst));
        assert_eq!(
            *seen_at.lock().unwrap(),
            Some(Time::ZERO),
            "deserialized cancelled tokens must replay with Time::ZERO instead of deadlocking"
        );
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

    /// br-asupersync-ml5ba5 — Two distinct broadcasters cancelling
    /// the same ObjectId without holding a local token must produce
    /// distinct synthetic token_ids. The previous fallback
    /// `object_id.high() ^ object_id.low()` collapsed both to the
    /// same value, so a receiver dedup keyed on `(object_id,
    /// token_id, sequence)` could incorrectly suppress the second
    /// broadcaster's cancel when both sender's `next_sequence`
    /// happened to overlap (each starts from 0). The fix mixes a
    /// per-broadcaster random `sender_tag`.
    #[test]
    fn cross_sender_synthetic_token_id_does_not_collide() {
        let object_id = ObjectId::new_for_test(0xCAFE);
        let reason = CancelReason::user("cross-sender test");

        // Two broadcasters, no local tokens registered.
        let bcast_a = CancelBroadcaster::new(NullSink);
        let bcast_b = CancelBroadcaster::new(NullSink);

        let msg_a = bcast_a.prepare_cancel(object_id, &reason, Time::from_millis(10));
        let msg_b = bcast_b.prepare_cancel(object_id, &reason, Time::from_millis(20));

        // The synthetic token_ids differ across senders. (Tiny chance
        // — 2^-64 — of a random sender_tag collision; cosmically
        // unlikely.)
        assert_ne!(
            msg_a.token_id(),
            msg_b.token_id(),
            "br-asupersync-ml5ba5: two broadcasters must produce distinct synthetic token_ids"
        );

        // Receiver dedup contract: a fresh broadcaster receiving both
        // messages must NOT classify the second as a duplicate of
        // the first. Since the seen-key is (object_id, token_id,
        // sequence) and the token_ids differ, both messages survive
        // dedup independently.
        let receiver = CancelBroadcaster::new(NullSink);
        let f_a = receiver.receive_message(&msg_a, Time::from_millis(30));
        let f_b = receiver.receive_message(&msg_b, Time::from_millis(40));
        assert!(f_a.is_some(), "first cancel must forward");
        assert!(
            f_b.is_some(),
            "br-asupersync-ml5ba5: second sender's cancel must NOT be suppressed as duplicate"
        );
    }

    /// br-asupersync-ml5ba5 — Same-broadcaster path: two
    /// `prepare_cancel` calls on the same broadcaster + same
    /// ObjectId without a local token MUST mint the same synthetic
    /// token_id (the dedup contract that lets the receiver see them
    /// as the same logical cancel). `sender_tag` is stable per
    /// broadcaster, so this holds.
    #[test]
    fn same_sender_synthetic_token_id_is_stable() {
        let object_id = ObjectId::new_for_test(0xBEEF);
        let reason = CancelReason::user("stable");

        let bcast = CancelBroadcaster::new(NullSink);
        let msg1 = bcast.prepare_cancel(object_id, &reason, Time::from_millis(10));
        let msg2 = bcast.prepare_cancel(object_id, &reason, Time::from_millis(20));

        assert_eq!(
            msg1.token_id(),
            msg2.token_id(),
            "br-asupersync-ml5ba5: same broadcaster must produce stable synthetic token_id"
        );
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
    fn receive_message_preserves_origin_initiated_at_for_local_tokens() {
        let mut rng = DetRng::new(88);
        let object_id = ObjectId::new_for_test(88);
        let token = SymbolCancelToken::new(object_id, &mut rng);
        let child = token.child(&mut rng);
        let seen_at = Arc::new(StdMutex::new(None::<Time>));
        let seen_at_clone = Arc::clone(&seen_at);
        token.add_listener(move |_reason: &CancelReason, at: Time| {
            *seen_at_clone.lock().unwrap() = Some(at);
        });

        let broadcaster = CancelBroadcaster::new(NullSink);
        broadcaster.register_token(token.clone());

        let initiated_at = Time::from_millis(125);
        let received_at = Time::from_millis(500);
        let msg = CancelMessage::new(
            token.token_id(),
            object_id,
            CancelKind::Shutdown,
            initiated_at,
            0,
        );

        let forwarded = broadcaster.receive_message(&msg, received_at);
        assert!(forwarded.is_some(), "fresh cancel should still forward");
        assert_eq!(
            token.cancelled_at(),
            Some(initiated_at),
            "br-asupersync-zmeazg: remote cancel must preserve origin initiated_at"
        );
        assert_eq!(
            child.cancelled_at(),
            Some(initiated_at),
            "child cascade should inherit the same origin initiated_at"
        );
        assert_eq!(
            *seen_at.lock().unwrap(),
            Some(initiated_at),
            "listener callbacks must observe the origin initiated_at, not local receipt time"
        );
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
                1,
                "remote cancellation should retain only the original listener before returning"
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

        coordinator.register_handler(object_id, CountingCleanupHandler);

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
    fn test_cleanup_with_handler_and_no_symbols_marks_completed() {
        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(10);

        coordinator.register_handler(object_id, CountingCleanupHandler);

        let result = coordinator.cleanup(object_id, None);
        assert!(result.completed, "empty cleanup should complete");
        assert!(
            coordinator.completed.read().contains(&object_id),
            "successful empty cleanup must mark object completed"
        );
        assert_eq!(
            coordinator
                .handlers
                .read()
                .get(&object_id)
                .map(|handler| handler.name()),
            None,
            "cleanup should drop the registered handler"
        );

        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(10, 0, 0, &[1, 2, 3]),
            Time::from_millis(101),
        );

        let stats = coordinator.stats();
        assert_eq!(
            stats.pending_objects, 0,
            "late pending symbols must be rejected after completed empty cleanup"
        );
        assert_eq!(stats.pending_symbols, 0);
    }

    #[test]
    fn test_clear_pending_drops_registered_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropCountingHandler {
            drops: Arc<AtomicUsize>,
        }

        impl Drop for DropCountingHandler {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl CleanupHandler for DropCountingHandler {
            fn cleanup(
                &self,
                _object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                Ok(0)
            }

            fn name(&self) -> &'static str {
                "drop-counting"
            }
        }

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(6);
        let now = Time::from_millis(100);
        let drops = Arc::new(AtomicUsize::new(0));

        coordinator.register_handler(
            object_id,
            DropCountingHandler {
                drops: Arc::clone(&drops),
            },
        );
        coordinator.register_pending(object_id, Symbol::new_for_test(6, 0, 0, &[1, 2, 3]), now);

        assert_eq!(coordinator.handlers.read().len(), 1);
        assert_eq!(coordinator.clear_pending(&object_id), Some(1));
        assert_eq!(coordinator.handlers.read().len(), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
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
    fn restore_retry_state_acquires_handler_table_before_pending_state() {
        use std::sync::Barrier;
        use std::time::{Duration, Instant};

        let coordinator = Arc::new(CleanupCoordinator::new());
        let object_id = ObjectId::new_for_test(70);
        let pending_set = PendingSymbolSet {
            symbols: vec![Symbol::new_for_test(70, 0, 0, &[1, 2, 3])],
            total_bytes: 3,
            _created_at: Time::from_millis(100),
        };
        let pending_guard = coordinator.pending.write();
        let started = Arc::new(Barrier::new(2));
        let restore_started = Arc::clone(&started);
        let restore_coordinator = Arc::clone(&coordinator);

        let handle = std::thread::spawn(move || {
            restore_started.wait();
            restore_coordinator.restore_retry_state(
                object_id,
                Box::new(CountingCleanupHandler),
                pending_set,
            );
        });

        started.wait();
        let mut saw_handler_table_locked = false;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if coordinator.handlers.try_write().is_none() {
                saw_handler_table_locked = true;
                break;
            }
            std::thread::yield_now();
        }

        drop(pending_guard);
        handle
            .join()
            .expect("retry-state restoration thread should finish");

        assert!(
            saw_handler_table_locked,
            "restore_retry_state must acquire handlers before waiting for pending; \
             otherwise a handlers->pending caller can form an AB-BA lock cycle"
        );
        assert!(
            coordinator.handlers.read().contains_key(&object_id),
            "retry restoration should preserve the cleanup handler"
        );
        assert_eq!(
            coordinator.stats().pending_symbols,
            1,
            "retry restoration should preserve pending symbols"
        );
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
        assert_eq!(
            reason_chain_kinds(&child),
            vec![
                CancelKind::ParentCancelled,
                CancelKind::ParentCancelled,
                CancelKind::User,
            ],
            "grandchild cancellation should validate the full parent chain"
        );
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
            reason_chain_kinds(&late_child),
            vec![CancelKind::ParentCancelled, CancelKind::User],
            "late child created inside listener should retain the parent reason as a cause"
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
            1,
            "the original retained listener remains, but the late listener must not be queued"
        );

        token.cancel(&CancelReason::shutdown(), Time::from_millis(200));
        assert_eq!(
            notification_count.load(Ordering::SeqCst),
            2,
            "the retained original listener should run again on strengthen and self-notify one late listener"
        );
        assert_eq!(
            *seen_kind.lock().unwrap(),
            Some(CancelKind::Shutdown),
            "late listener should observe the strengthened cancellation kind"
        );
        assert_eq!(
            *seen_time.lock().unwrap(),
            Some(now),
            "late listener should observe the canonical first-cancel timestamp after strengthen"
        );
        assert_eq!(
            token.state.listeners.read().len(),
            1,
            "strengthened cancellations retain only the original listener"
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
            1,
            "drain must retain only the original listener, not the late listener"
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

        coordinator.register_handler(obj1, CountingCleanupHandler);

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
        assert_eq!(
            reason_chain_kinds(&level3),
            vec![
                CancelKind::ParentCancelled,
                CancelKind::ParentCancelled,
                CancelKind::ParentCancelled,
                CancelKind::User,
            ],
            "deep descendant should retain every parent-cancelled hop plus the root cause"
        );
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
    /// Retained listeners are notified once per strictly stronger cancellation severity.
    /// Metamorphic relation: notifications_received = listeners_count × severity_levels_seen
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

        // A stronger cancellation re-notifies retained listeners once.
        let before_second = notification_count.load(Ordering::SeqCst);
        token.cancel(
            &CancelReason::new(CancelKind::Shutdown),
            Time::from_millis(5000),
        );
        let after_second = notification_count.load(Ordering::SeqCst);

        assert_eq!(before_second, listener_count);
        assert_eq!(after_second, listener_count * 2);

        // Same-severity repeats must remain idempotent.
        token.cancel(
            &CancelReason::new(CancelKind::Shutdown),
            Time::from_millis(6000),
        );
        assert_eq!(notification_count.load(Ordering::SeqCst), after_second);
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

        coordinator.register_handler(obj1, CountingCleanupHandler);

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
        coord1.register_handler(obj1, CountingCleanupHandler);

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
        let observed: Arc<StdMutex<Vec<(crate::types::CancelKind, Time)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        {
            let observed = Arc::clone(&observed);
            token.add_listener(move |reason: &CancelReason, at: Time| {
                observed.lock().unwrap().push((reason.kind, at));
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
            log.first().map(|(kind, _)| *kind),
            Some(crate::types::CancelKind::User),
            "first notification must carry the initial weak reason, got {log:?}"
        );
        assert!(
            log.iter()
                .any(|(kind, at)| *kind == crate::types::CancelKind::Shutdown
                    && *at == Time::from_nanos(100)),
            "listener must be re-notified with the strengthened reason, got {log:?}"
        );
        // No duplicate same-severity notifications.
        let user_count = log
            .iter()
            .filter(|(kind, _)| *kind == crate::types::CancelKind::User)
            .count();
        assert_eq!(
            user_count, 1,
            "same-severity cancel must not re-fire listeners, got {log:?}"
        );
        assert!(
            log.iter().all(|(_, at)| *at == Time::from_nanos(100)),
            "all retained-listener notifications must use the canonical first-cancel timestamp, got {log:?}"
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

    /// br-asupersync-mzamuo — A panicking listener must (a) NOT
    /// crash the cancel path, (b) increment the per-token panic
    /// counter so the silent-swallow becomes observable.
    #[test]
    fn cancel_listener_panic_logged_via_counter() {
        struct PanickingListener;
        impl CancelListener for PanickingListener {
            fn on_cancel(&self, _reason: &CancelReason, _at: Time) {
                panic!("simulated listener panic (mzamuo)");
            }
        }

        let mut rng = DetRng::new(0xc0ffee);
        let token = SymbolCancelToken::new(ObjectId::new(1, 1), &mut rng);
        token.add_listener(PanickingListener);

        // First cancel fires the listener → panic → caught + counted.
        let reason = CancelReason::new(CancelKind::User);
        token.cancel(&reason, Time::from_nanos(100));
        assert!(
            token.listener_panic_count() >= 1,
            "expected listener_panic_count >= 1, got {}",
            token.listener_panic_count()
        );

        // Strengthen path: re-fires the listener for severity uplift.
        let stronger = CancelReason::new(CancelKind::Shutdown);
        token.cancel(&stronger, Time::from_nanos(200));
        assert!(
            token.listener_panic_count() >= 2,
            "strengthen path must also count panics, got {}",
            token.listener_panic_count()
        );
    }

    #[test]
    fn late_add_listener_drop_panic_logged_via_counter() {
        struct DropPanickingListener;
        impl CancelListener for DropPanickingListener {
            fn on_cancel(&self, _reason: &CancelReason, _at: Time) {}
        }
        impl Drop for DropPanickingListener {
            fn drop(&mut self) {
                panic!("simulated late-add drop panic (mzamuo)"); // ubs:ignore - test helper
            }
        }

        let mut rng = DetRng::new(0xd00d);
        let token = SymbolCancelToken::new(ObjectId::new(4, 4), &mut rng);
        token.cancel(&CancelReason::new(CancelKind::User), Time::from_nanos(1));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            token.add_listener(DropPanickingListener);
        }));
        assert!(
            result.is_ok(),
            "late-add path must not propagate listener drop panic"
        );
        assert_eq!(token.listener_panic_count(), 1);
    }

    /// br-asupersync-as12cf — `mark_seen` must NEVER let
    /// `seen_sequences.set.len()` exceed `max_seen` even
    /// transiently. The harness mirrors the production fix
    /// (evict-before-insert) so the invariant can be exercised
    /// without standing up the full coordinator.
    #[test]
    fn mark_seen_never_exceeds_max_seen_transiently() {
        let mut rng = DetRng::new(0xbeef);
        let token = SymbolCancelToken::new(ObjectId::new(7, 7), &mut rng);
        let coord = CancelMarkSeenHarness {
            seen_sequences: parking_lot::RwLock::new(SeenSequences::default()),
            max_seen: 5,
        };
        for i in 0..15u64 {
            coord.mark_seen(token.object_id(), token.token_id(), i);
            let len = coord.seen_sequences.read().set.len();
            assert!(
                len <= coord.max_seen,
                "seen.set.len()={len} exceeded max_seen={} after insert {i}",
                coord.max_seen
            );
        }
    }

    struct CancelMarkSeenHarness {
        seen_sequences: parking_lot::RwLock<SeenSequences>,
        max_seen: usize,
    }

    impl CancelMarkSeenHarness {
        fn mark_seen(&self, object_id: ObjectId, token_id: u64, sequence: u64) {
            let mut seen = self.seen_sequences.write();
            if seen.set.contains(&(object_id, token_id, sequence)) {
                return;
            }
            while seen.set.len() >= self.max_seen {
                if seen.remove_oldest().is_none() {
                    break;
                }
            }
            seen.insert((object_id, token_id, sequence));
        }
    }

    /// br-asupersync-n1a1br — child() must observe a consistent
    /// (is_cancelled, cancelled_at) pair. After the parent is
    /// cancelled, every child created via `child()` must inherit
    /// the parent's cancelled_at value as it was at the moment of
    /// the cancel decision — not a later strengthened value.
    #[test]
    fn child_inherits_parent_cancelled_at_atomically() {
        let mut rng = DetRng::new(0x1234);
        let parent = SymbolCancelToken::new(ObjectId::new(2, 2), &mut rng);
        let cancel_time = Time::from_nanos(500);
        let reason = CancelReason::new(CancelKind::User);
        parent.cancel(&reason, cancel_time);

        // Now create a child after the parent is already cancelled.
        let child = parent.child(&mut rng);
        assert!(child.is_cancelled());
        assert_eq!(
            child.cancelled_at().map(Time::as_nanos),
            Some(cancel_time.as_nanos()),
            "child must inherit the cancelled_at the parent had \
             at the moment of the is_cancelled check (snapshot under lock)"
        );
    }

    /// br-asupersync-n1a1br — if `cancelled` becomes visible before
    /// `cancelled_at` is published, `child()` must wait out that
    /// local-cancel window rather than fabricating `Time::ZERO`.
    #[test]
    fn child_waits_for_inflight_cancelled_at_publication() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let mut rng = DetRng::new(0x5678);
        let parent = SymbolCancelToken::new(ObjectId::new(3, 3), &mut rng);
        let cancel_time = Time::from_nanos(777);
        let started = Arc::new(AtomicBool::new(false));

        let mut reason_guard = parent.state.reason.write();
        *reason_guard = Some(CancelReason::new(CancelKind::User));
        parent.state.cancelled.store(true, Ordering::Release);
        parent.state.cancelled_at.store(u64::MAX, Ordering::Release);

        let parent_for_child = parent.clone();
        let started_for_child = started.clone();
        let join = std::thread::spawn(move || {
            started_for_child.store(true, Ordering::Release);
            let mut child_rng = DetRng::new(0x9abc);
            let child = parent_for_child.child(&mut child_rng);
            child.cancelled_at().map(Time::as_nanos)
        });

        // br-asupersync-wze4x9: Replace infinite spin with bounded retry to prevent test hangs
        const MAX_WAIT_RETRIES: u32 = 10000;
        for _attempt in 0..MAX_WAIT_RETRIES {
            if started.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_nanos(100));
        }
        assert!(
            started.load(Ordering::Acquire),
            "Test thread failed to start within timeout"
        );

        parent
            .state
            .cancelled_at
            .store(cancel_time.as_nanos(), Ordering::Release);
        drop(reason_guard);

        let child_cancelled_at = join.join().expect("child thread must complete");
        assert_eq!(child_cancelled_at, Some(cancel_time.as_nanos()));
    }

    /// br-asupersync-53nvge — a late `child()` call may need to wait for
    /// `cancelled_at` publication, but that wait must not monopolize the
    /// `children` lock. Other threads still need that lock for drain/metrics
    /// work in the same handoff window.
    #[test]
    fn child_wait_for_cancelled_at_does_not_hold_children_lock() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let mut rng = DetRng::new(0x53A9_0001);
        let parent = SymbolCancelToken::new(ObjectId::new(4, 4), &mut rng);
        let started = Arc::new(AtomicBool::new(false));

        let mut reason_guard = parent.state.reason.write();
        *reason_guard = Some(CancelReason::new(CancelKind::User));
        parent.state.cancelled.store(true, Ordering::Release);
        parent.state.cancelled_at.store(u64::MAX, Ordering::Release);

        let parent_for_child = parent.clone();
        let started_for_child = Arc::clone(&started);
        let join = std::thread::spawn(move || {
            started_for_child.store(true, Ordering::Release);
            let mut child_rng = DetRng::new(0x53A9_0002);
            let child = parent_for_child.child(&mut child_rng);
            child.cancelled_at().map(Time::as_nanos)
        });

        const MAX_WAIT_RETRIES: u32 = 10_000;
        for _attempt in 0..MAX_WAIT_RETRIES {
            if started.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_nanos(100));
        }
        assert!(
            started.load(Ordering::Acquire),
            "child thread failed to start within timeout"
        );

        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(
            parent.state.children.try_write().is_some(),
            "late child creation must not hold children.write() while waiting for cancelled_at"
        );

        let cancel_time = Time::from_nanos(991);
        parent
            .state
            .cancelled_at
            .store(cancel_time.as_nanos(), Ordering::Release);
        drop(reason_guard);

        let child_cancelled_at = join.join().expect("child thread must complete");
        assert_eq!(child_cancelled_at, Some(cancel_time.as_nanos()));
    }

    /// Regression test for asupersync-4txkrb: notify_retained_listeners_until_current()
    /// infinite loop livelock bug. Tests that bounded iteration prevents CPU burnout
    /// when concurrent threads keep strengthening cancel reasons.
    #[test]
    fn notify_listeners_bounded_iteration_prevents_livelock() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU32, Ordering},
        };
        use std::thread;
        use std::time::{Duration, Instant};

        let mut rng = DetRng::new(0x4321);
        let token = SymbolCancelToken::new(ObjectId::new(42, 0), &mut rng);

        // Add several listeners that track notification count
        let notification_count = Arc::new(AtomicU32::new(0));
        for _i in 0..5 {
            let count = Arc::clone(&notification_count);
            token.add_listener(move |_reason: &CancelReason, _time: Time| {
                count.fetch_add(1, Ordering::Relaxed);
                // Simulate listener work to make race condition more likely
                std::hint::spin_loop();
            });
        }

        // Initial cancel with low severity
        let initial_time = Time::from_nanos(1000);
        token.cancel(&CancelReason::new(CancelKind::Timeout), initial_time);

        // Track if the notification process completes in reasonable time
        let completed = Arc::new(AtomicBool::new(false));
        let completed_for_thread = Arc::clone(&completed);

        // Spawn thread that continuously strengthens the reason to trigger
        // the race condition that would cause infinite loop
        let token_for_strengthener = token.clone();
        let strengthener_thread = thread::spawn(move || {
            for severity in [
                CancelKind::Deadline,
                CancelKind::Shutdown,
                CancelKind::FailFast,
            ]
            .iter()
            {
                thread::sleep(Duration::from_millis(1));
                token_for_strengthener.cancel(&CancelReason::new(*severity), initial_time);
            }
        });

        // Main test: trigger listener notification which could previously livelock
        let start = Instant::now();
        let token_for_notify = token.clone();
        let notification_thread = thread::spawn(move || {
            // This call would previously infinite loop if reasons keep strengthening
            // Now it should complete in bounded time due to iteration limit
            token_for_notify.cancel(&CancelReason::new(CancelKind::User), initial_time);
            completed_for_thread.store(true, Ordering::Release);
        });

        // Wait for threads to complete or timeout
        strengthener_thread
            .join()
            .expect("strengthener thread should complete");
        notification_thread
            .join()
            .expect("notification thread should complete");

        let elapsed = start.elapsed();

        // Verify the fix: operation should complete quickly (under 100ms)
        // and not hang indefinitely as it would with the original infinite loop
        assert!(
            elapsed < Duration::from_millis(100),
            "Notification should complete quickly, took {:?}",
            elapsed
        );

        assert!(
            completed.load(Ordering::Acquire),
            "Notification process should have completed"
        );

        // Verify listeners were actually notified (at least once)
        let final_count = notification_count.load(Ordering::Relaxed);
        assert!(
            final_count > 0,
            "Listeners should have been notified, count: {}",
            final_count
        );
    }

    #[test]
    fn cancelled_at_snapshot_for_child_livelock_regression() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::{Duration, Instant};

        // br-asupersync-wze4x9: Regression test for infinite spin loop livelock
        // in cancelled_at_snapshot_for_child() when the cancelled flag is visible
        // before the timestamp is written.

        let mut rng = DetRng::new(0x1234_5678);
        let object_id = ObjectId::new_for_test(0x1234_5678);
        let token = SymbolCancelToken::new(object_id, &mut rng);

        // Create a barrier to synchronize the race condition setup
        let barrier = Arc::new(Barrier::new(2));
        let cancel_started = Arc::new(AtomicBool::new(false));
        let child_created = Arc::new(AtomicBool::new(false));

        let token_for_cancel = token.clone();
        let barrier_for_cancel = Arc::clone(&barrier);
        let cancel_started_for_cancel = Arc::clone(&cancel_started);

        // Thread 1: Start cancel process but hold the write lock longer to create race
        let cancel_thread = thread::spawn(move || {
            barrier_for_cancel.wait(); // Sync with child thread

            // Acquire the reason write lock and set cancelled flag
            let reason = CancelReason::user("livelock test");
            let mut reason_guard = token_for_cancel.state.reason.write();

            // Signal that cancel has started (flag will be visible)
            token_for_cancel
                .state
                .cancelled
                .store(true, Ordering::Release);
            cancel_started_for_cancel.store(true, Ordering::Release);

            // Hold the lock for a bit to ensure race condition
            thread::sleep(Duration::from_millis(10));

            // Set the timestamp (this will unblock the child creation)
            token_for_cancel.state.cancelled_at.store(
                crate::types::Time::from_millis(12345).as_nanos(),
                Ordering::Release,
            );

            // Complete the same reason publication cancel() performs
            // before releasing the write lock so the final token state
            // is reachable in production.
            *reason_guard = Some(reason);

            // Lock will be dropped here, completing the cancel
        });

        let token_for_child = token.clone();
        let barrier_for_child = Arc::clone(&barrier);
        let cancel_started_for_child = Arc::clone(&cancel_started);
        let child_created_for_child = Arc::clone(&child_created);

        // Thread 2: Try to create child during the race window
        let child_thread = thread::spawn(move || {
            barrier_for_child.wait(); // Sync with cancel thread

            // Wait for cancel to start but timestamp not yet set
            while !cancel_started_for_child.load(Ordering::Acquire) {
                thread::sleep(Duration::from_nanos(100));
            }

            // This would previously cause infinite livelock in cancelled_at_snapshot_for_child
            let start = Instant::now();
            let mut child_rng = DetRng::new(0x8765_4321);
            let child = token_for_child.child(&mut child_rng);
            let elapsed = start.elapsed();

            // With the fix, this should complete in bounded time
            assert!(
                elapsed < Duration::from_millis(500),
                "Child creation should not livelock, took {:?}",
                elapsed
            );

            child_created_for_child.store(true, Ordering::Release);
            child
        });

        // Wait for both threads with timeout
        let start = Instant::now();
        cancel_thread.join().expect("Cancel thread should complete");
        let child = child_thread.join().expect("Child thread should complete");
        let total_elapsed = start.elapsed();

        // Verify the test completed quickly (no livelock)
        assert!(
            total_elapsed < Duration::from_secs(1),
            "Test should complete quickly, took {:?}",
            total_elapsed
        );

        // Verify both operations completed successfully
        assert!(
            cancel_started.load(Ordering::Acquire),
            "Cancel should have started"
        );
        assert!(
            child_created.load(Ordering::Acquire),
            "Child should have been created without livelock"
        );

        // Verify final state is consistent
        assert!(token.is_cancelled(), "Token should be cancelled");
        assert!(
            token.cancelled_at().is_some(),
            "Cancelled timestamp should be available"
        );
        assert_eq!(
            token.reason(),
            Some(CancelReason::user("livelock test")),
            "manual race setup must still publish a real final cancel reason"
        );
        assert_eq!(
            child.cancelled_at(),
            Some(crate::types::Time::from_millis(12345)),
            "child created during in-flight cancel must inherit the canonical parent timestamp"
        );
    }

    // --- br-asupersync-9a0x8n: CleanupCoordinator symbol drop fix ---

    #[test]
    fn cleanup_coordinator_buffers_symbols_during_retry() {
        // br-asupersync-9a0x8n: symbols arriving during cleanup retry
        // attempts should be buffered and replayed when retry state
        // is restored, not dropped.

        use std::sync::Arc;
        use std::sync::Mutex;

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(42);
        let now = Time::from_nanos(1000);

        // Register initial symbols
        coordinator.register_pending(object_id, Symbol::new_for_test(42, 0, 0, b"initial1"), now);
        coordinator.register_pending(object_id, Symbol::new_for_test(42, 0, 1, b"initial2"), now);

        // Create a failing handler
        #[derive(Debug)]
        struct FailingHandler {
            attempts: Arc<Mutex<u32>>,
        }

        impl CleanupHandler for FailingHandler {
            fn name(&self) -> &'static str {
                "failing_test_handler"
            }

            fn cleanup(
                &self,
                _object_id: ObjectId,
                symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                let mut attempts = self.attempts.lock().unwrap();
                *attempts += 1;

                if *attempts == 1 {
                    // First attempt fails, triggering retry logic
                    Err(
                        crate::error::Error::new(crate::error::ErrorKind::ConnectionLost)
                            .with_message("simulated failure"),
                    )
                } else {
                    // Second attempt succeeds
                    assert_eq!(symbols.len(), 4, "Should have initial + buffered symbols");
                    let data: Vec<&[u8]> = symbols.iter().map(Symbol::data).collect();
                    // Should contain initial symbols plus symbols added during first cleanup
                    assert!(data.iter().any(|payload| *payload == b"initial1"));
                    assert!(data.iter().any(|payload| *payload == b"initial2"));
                    assert!(data.iter().any(|payload| *payload == b"during_cleanup1"));
                    assert!(data.iter().any(|payload| *payload == b"during_cleanup2"));
                    Ok(4) // Return count of cleaned symbols
                }
            }
        }

        let attempts = Arc::new(Mutex::new(0u32));
        let handler = FailingHandler {
            attempts: Arc::clone(&attempts),
        };
        coordinator.register_handler(object_id, handler);

        // Start first cleanup (will fail)
        let result1 = coordinator.cleanup(object_id, None);
        assert!(
            !result1.completed,
            "First cleanup should fail and not complete"
        );
        assert!(
            !result1.handler_errors.is_empty(),
            "Should have handler error"
        );

        // Add symbols during retry state (these used to be dropped)
        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(42, 0, 2, b"during_cleanup1"),
            now,
        );
        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(42, 0, 3, b"during_cleanup2"),
            now,
        );

        // Verify symbols are in cleanup buffer, not dropped
        let stats = coordinator.stats();
        assert_eq!(
            stats.pending_objects, 1,
            "Should have pending object after failure"
        );

        // Retry cleanup (will succeed and include buffered symbols)
        let result2 = coordinator.cleanup(object_id, None);
        assert!(result2.completed, "Second cleanup should succeed");
        assert!(
            result2.handler_errors.is_empty(),
            "Should have no handler errors"
        );
        assert_eq!(
            result2.symbols_cleaned, 4,
            "Should clean initial + buffered symbols"
        );

        // Verify no pending symbols remain
        let final_stats = coordinator.stats();
        assert_eq!(
            final_stats.pending_objects, 0,
            "Should have no pending objects"
        );
        assert_eq!(
            final_stats.pending_symbols, 0,
            "Should have no pending symbols"
        );

        // Verify handler was called twice (fail, then success)
        assert_eq!(
            *attempts.lock().unwrap(),
            2,
            "Handler should be called twice"
        );
    }

    #[test]
    fn cleanup_coordinator_no_symbols_lost_during_concurrent_registration() {
        // Regression test for the specific race: symbols registered
        // during the window between cleanup start and retry restoration
        // should not be lost.

        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(99);
        let now = Time::from_nanos(2000);

        // Register initial symbol
        coordinator.register_pending(object_id, Symbol::new_for_test(99, 0, 0, b"original"), now);

        // Create handler that always fails (forces retry)
        #[derive(Debug)]
        struct AlwaysFailHandler;

        impl CleanupHandler for AlwaysFailHandler {
            fn name(&self) -> &'static str {
                "always_fail"
            }
            fn cleanup(&self, _: ObjectId, _: Vec<Symbol>) -> crate::error::Result<usize> {
                Err(crate::error::Error::new(crate::error::ErrorKind::Internal)
                    .with_message("always fails"))
            }
        }

        coordinator.register_handler(object_id, AlwaysFailHandler);

        // Start cleanup (will fail and create cleanup buffer)
        let result = coordinator.cleanup(object_id, None);
        assert!(!result.completed);

        // Register more symbols during retry state
        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 1, b"during_retry1"),
            now,
        );
        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 2, b"during_retry2"),
            now,
        );

        // Verify all symbols are preserved (not dropped)
        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 1);
        // Original symbol + two added during retry should all be preserved
        assert!(
            stats.pending_symbols >= 3,
            "All symbols should be preserved, got {}",
            stats.pending_symbols
        );

        // Additional symbols after restoration should also work
        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(99, 0, 3, b"after_retry"),
            now,
        );

        let final_stats = coordinator.stats();
        assert!(
            final_stats.pending_symbols >= 4,
            "All symbols including post-retry should be preserved"
        );
    }

    #[test]
    fn cleanup_reentrant_attempt_is_rejected_without_stealing_retry_state() {
        use std::sync::{Arc, Mutex};

        struct ReentrantHandler {
            coordinator: Arc<CleanupCoordinator>,
            nested_result: Arc<Mutex<Option<CleanupResult>>>,
        }

        impl CleanupHandler for ReentrantHandler {
            fn name(&self) -> &'static str {
                "reentrant"
            }

            fn cleanup(
                &self,
                object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                self.coordinator.register_pending(
                    object_id,
                    Symbol::new_for_test(123, 0, 1, b"late-symbol"),
                    Time::from_millis(101),
                );
                let nested = self.coordinator.cleanup(object_id, None);
                *self.nested_result.lock().unwrap() = Some(nested);
                Ok(1)
            }
        }

        let coordinator = Arc::new(CleanupCoordinator::new());
        let nested_result = Arc::new(Mutex::new(None));
        let object_id = ObjectId::new_for_test(123);

        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(123, 0, 0, b"initial"),
            Time::from_millis(100),
        );
        coordinator.register_handler(
            object_id,
            ReentrantHandler {
                coordinator: Arc::clone(&coordinator),
                nested_result: Arc::clone(&nested_result),
            },
        );

        let outer = coordinator.cleanup(object_id, None);
        assert!(outer.completed, "outer cleanup should still complete");

        let nested = nested_result
            .lock()
            .unwrap()
            .clone()
            .expect("nested cleanup result should be recorded");
        assert!(
            !nested.completed,
            "reentrant cleanup attempt must fail closed"
        );
        assert_eq!(nested.symbols_cleaned, 0);
        assert_eq!(nested.bytes_freed, 0);
        assert!(
            nested
                .handler_errors
                .iter()
                .any(|err| err.contains("cleanup already in progress")),
            "expected reentrant cleanup error, got {:?}",
            nested.handler_errors
        );

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 0);
        assert_eq!(stats.pending_symbols, 0);
        assert_eq!(stats.pending_bytes, 0);
        assert!(coordinator.completed.read().contains(&object_id));
    }

    #[test]
    fn cleanup_completed_path_scrubs_reentrant_handler_re_registration() {
        use std::sync::Arc;

        struct ReRegisteringHandler {
            coordinator: Arc<CleanupCoordinator>,
        }

        impl CleanupHandler for ReRegisteringHandler {
            fn name(&self) -> &'static str {
                "re-registering"
            }

            fn cleanup(
                &self,
                object_id: ObjectId,
                _symbols: Vec<Symbol>,
            ) -> crate::error::Result<usize> {
                self.coordinator
                    .register_handler(object_id, CountingCleanupHandler);
                Ok(1)
            }
        }

        let coordinator = Arc::new(CleanupCoordinator::new());
        let object_id = ObjectId::new_for_test(1234);

        coordinator.register_pending(
            object_id,
            Symbol::new_for_test(1234, 0, 0, b"initial"),
            Time::from_millis(200),
        );
        coordinator.register_handler(
            object_id,
            ReRegisteringHandler {
                coordinator: Arc::clone(&coordinator),
            },
        );

        let result = coordinator.cleanup(object_id, None);
        assert!(result.completed, "cleanup should still complete");
        assert_eq!(result.symbols_cleaned, 1);
        assert_eq!(result.bytes_freed, b"initial".len());
        assert!(
            !coordinator.handlers.read().contains_key(&object_id),
            "completed cleanup must scrub handlers re-registered during the callback"
        );
        assert!(coordinator.completed.read().contains(&object_id));
    }

    #[test]
    fn cleanup_buffered_only_reopen_restores_handler_for_retry() {
        let coordinator = CleanupCoordinator::new();
        let object_id = ObjectId::new_for_test(124);

        coordinator.register_handler(object_id, CountingCleanupHandler);
        coordinator.cleanup_buffer.write().insert(
            object_id,
            vec![Symbol::new_for_test(124, 0, 0, b"buffered-only")],
        );

        let first = coordinator.cleanup(object_id, None);
        assert!(
            !first.completed,
            "buffered symbols arriving during an otherwise empty cleanup must reopen retry state"
        );
        assert!(
            coordinator.handlers.read().contains_key(&object_id),
            "buffered-only reopen must restore the per-object handler"
        );

        let stats = coordinator.stats();
        assert_eq!(stats.pending_objects, 1);
        assert_eq!(stats.pending_symbols, 1);
        assert_eq!(stats.pending_bytes, b"buffered-only".len());

        let second = coordinator.cleanup(object_id, None);
        assert!(
            second.completed,
            "restored handler should allow retry to finish"
        );
        assert_eq!(second.symbols_cleaned, 1);
        assert_eq!(second.bytes_freed, b"buffered-only".len());
    }

    /// Basic integration test for br-asupersync-dm6ci4: CancelBroadcaster retry mechanism.
    ///
    /// Verifies that the pending_retries field is properly tracked in metrics.
    /// More complex retry scenarios are tested via integration tests.
    #[test]
    fn cancel_broadcaster_tracks_pending_retries_in_metrics() {
        // Test sink is only needed to satisfy the broadcaster type parameter.
        #[derive(Debug)]
        struct TestSink;

        impl CancelSink for TestSink {
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
                std::future::ready(Ok(1))
            }
        }

        let broadcaster = CancelBroadcaster::new(TestSink);
        let object_id = ObjectId::new_for_test(123);

        // Initially no pending retries
        let initial_metrics = broadcaster.metrics();
        assert_eq!(
            initial_metrics.pending_retries, 0,
            "Should start with no pending retries"
        );

        // Manually add a message to retry queue (simulating failed broadcast)
        let test_message =
            CancelMessage::new(42, object_id, CancelKind::User, Time::from_nanos(1000), 1);
        broadcaster.pending_retries.write().push_back(test_message);

        // Metrics should reflect the pending retry
        let metrics_with_pending = broadcaster.metrics();
        assert_eq!(
            metrics_with_pending.pending_retries, 1,
            "Should show 1 pending retry"
        );

        // Clear the retry queue
        broadcaster.pending_retries.write().clear();

        // Metrics should show no pending retries again
        let final_metrics = broadcaster.metrics();
        assert_eq!(
            final_metrics.pending_retries, 0,
            "Should show no pending retries after clear"
        );
    }

    #[test]
    fn cancel_broadcaster_serializes_concurrent_retry_passes() {
        use std::sync::Condvar;
        use std::sync::mpsc;
        use std::time::Duration;

        #[derive(Debug)]
        struct BlockingFirstRetrySink {
            broadcast_calls: Arc<AtomicUsize>,
            first_call_entered: std::sync::Mutex<Option<mpsc::Sender<()>>>,
            release_gate: Arc<(std::sync::Mutex<bool>, Condvar)>,
        }

        impl CancelSink for BlockingFirstRetrySink {
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
                let call_index = self.broadcast_calls.fetch_add(1, Ordering::SeqCst);
                let entered = if call_index == 0 {
                    self.first_call_entered.lock().unwrap().take()
                } else {
                    None
                };
                let release_gate = Arc::clone(&self.release_gate);

                async move {
                    if let Some(entered) = entered {
                        entered.send(()).expect("first retry should signal entry");
                        let (released_lock, released_cv) = &*release_gate;
                        let mut released = released_lock.lock().unwrap();
                        while !*released {
                            released = released_cv.wait(released).unwrap();
                        }
                    }

                    Ok(1)
                }
            }
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let release_gate = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
        let broadcast_calls = Arc::new(AtomicUsize::new(0));
        let sink = BlockingFirstRetrySink {
            broadcast_calls: Arc::clone(&broadcast_calls),
            first_call_entered: std::sync::Mutex::new(Some(entered_tx)),
            release_gate: Arc::clone(&release_gate),
        };
        let broadcaster = Arc::new(CancelBroadcaster::new(sink));
        let object_id = ObjectId::new_for_test(321);
        broadcaster
            .pending_retries
            .write()
            .push_back(CancelMessage::new(
                1,
                object_id,
                CancelKind::User,
                Time::from_nanos(10),
                0,
            ));
        broadcaster
            .pending_retries
            .write()
            .push_back(CancelMessage::new(
                1,
                object_id,
                CancelKind::User,
                Time::from_nanos(20),
                1,
            ));

        let retry_owner = Arc::clone(&broadcaster);
        let retry_handle = std::thread::spawn(move || {
            futures_lite::future::block_on(retry_owner.retry_failed_broadcasts())
        });

        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("primary retry loop should enter first broadcast");

        let concurrent_result =
            futures_lite::future::block_on(broadcaster.retry_failed_broadcasts());
        assert_eq!(
            concurrent_result.0, 0,
            "concurrent retry callers must not steal later messages from the FIFO queue"
        );
        assert!(
            concurrent_result.1.is_none(),
            "concurrent retry callers must return without surfacing an error: {:?}",
            concurrent_result.1
        );
        assert_eq!(
            broadcaster.pending_retries.read().len(),
            1,
            "the second message should remain queued for the active retry loop"
        );

        let (released_lock, released_cv) = &*release_gate;
        *released_lock.lock().unwrap() = true;
        released_cv.notify_all();

        let owner_result = retry_handle.join().expect("retry thread should join");
        assert_eq!(
            owner_result.0, 2,
            "the owning retry pass should drain both queued messages in order"
        );
        assert!(
            owner_result.1.is_none(),
            "the owning retry pass should complete without surfacing an error: {:?}",
            owner_result.1
        );
        assert_eq!(
            broadcaster.pending_retries.read().len(),
            0,
            "all retry messages should be drained after the owner completes"
        );
        assert_eq!(
            broadcast_calls.load(Ordering::SeqCst),
            2,
            "only the owning retry pass should broadcast the queued messages"
        );
    }
}

#[cfg(test)]
#[path = "symbol_cancel_metamorphic.rs"]
mod symbol_cancel_metamorphic;
