//! Two-phase watch channel for state broadcasting.
//!
//! A watch channel is a single-value channel where multiple receivers see the
//! latest value. Essential for configuration propagation, state sharing, and
//! shutdown signals.
//!
//! # Watch Semantics
//!
//! - Single producer broadcasts state changes
//! - Multiple receivers observe the latest value
//! - Receivers can wait for changes
//! - No queue - only the latest value matters
//!
//! # Cancel Safety
//!
//! The `changed()` method is cancel-safe:
//! - Cancel during wait: clean abort, version not updated
//! - Resume: continue waiting for same version
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::watch;
//!
//! // Create a watch channel with initial value
//! let (tx, mut rx) = watch::channel(Config::default());
//!
//! // Receiver waits for changes
//! scope.spawn(cx, async move |cx| {
//!     loop {
//!         rx.changed(cx).await?;
//!         let config = rx.borrow_and_clone();
//!         apply_config(config);
//!     }
//! });
//!
//! // Sender updates the value
//! tx.send(new_config)?;
//! ```

use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;
use crate::util::{Arena, ArenaIndex};

/// Waiter entry with deduplication flag to prevent unbounded growth.
///
/// The `queued` flag is shared between the entry and the owning `Receiver`,
/// so the future can skip re-registration while still queued.
struct WatchWaiter {
    waker: Waker,
    queued: Arc<AtomicBool>,
}

impl std::fmt::Debug for WatchWaiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchWaiter")
            .field("waker", &self.waker)
            .field("queued", &self.queued.load(Ordering::Relaxed))
            .finish()
    }
}

/// Error returned when sending fails.
///
/// A live sender preserves the latest watch value even if there are currently
/// no active receivers. This error is therefore reserved for genuinely invalid
/// send attempts rather than the ordinary zero-receiver case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<T> {
    /// The sender has been dropped or closed.
    Closed(T),
}

impl<T> std::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(_) => write!(f, "sending on a closed watch channel"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

/// Error returned when receiving fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The sender was dropped.
    Closed,
    /// The receive operation was cancelled.
    Cancelled,
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "receiving on a closed watch channel"),
            Self::Cancelled => write!(f, "receive operation cancelled"),
            Self::PolledAfterCompletion => write!(f, "watch future polled after completion"),
        }
    }
}

impl std::error::Error for RecvError {}

/// Error returned when modifying fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifyError;

impl std::fmt::Display for ModifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "modifying a closed watch channel")
    }
}

impl std::error::Error for ModifyError {}

/// Opt-in, redacted telemetry snapshot for a watch channel.
///
/// The caller supplies `channel_id`, which keeps identifiers deterministic and
/// avoids ambient globals or pointer-derived IDs. Payload values are never
/// exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchTelemetrySnapshot {
    /// Caller-provided deterministic channel identifier.
    pub channel_id: u64,
    /// Stable channel kind label.
    pub channel_kind: &'static str,
    /// Watch channels retain exactly one latest value.
    pub capacity: usize,
    /// Whether the latest value is waiting to be observed by this view.
    pub queued_messages: usize,
    /// Watch updates are committed synchronously without send reservations.
    pub reserved_uncommitted_obligations: usize,
    /// Watch has no sender-side capacity waiters.
    pub send_waiter_count: usize,
    /// Receiver-side waiters waiting for a change or closure.
    pub recv_waiter_count: usize,
    /// Number of active receivers.
    pub receiver_count: usize,
    /// Redacted receiver state for this snapshot view.
    pub receiver_health: &'static str,
    /// Number of tracked receivers that have not observed the latest version.
    pub lagged_receiver_count: Option<usize>,
    /// Cancel/abort events observed by the channel.
    pub cancellation_count: u64,
    /// Whether this channel has reached a closed state.
    pub closed: bool,
}

/// Internal state shared between sender and receivers.
#[derive(Debug)]
struct WatchInner<T> {
    /// The current value and its version number.
    value: RwLock<(T, u64)>,
    // NOTE: Previously had version: AtomicU64 shadow counter, but this
    // created race conditions. Now we read version from value RwLock directly.
    /// Number of active receivers (excluding sender's implicit subscription).
    receiver_count: AtomicUsize,
    /// Whether the sender has been dropped.
    sender_dropped: AtomicBool,
    /// Wakers for receivers waiting on value changes.
    waiters: Mutex<SmallVec<[WatchWaiter; 4]>>,
    /// Last observed version for each active receiver.
    receiver_versions: Mutex<Arena<u64>>,
    /// Number of cancellation/abort events observed by this channel.
    cancellation_count: AtomicU64,
}

impl<T> WatchInner<T> {
    fn new(initial: T) -> Self {
        Self {
            value: RwLock::new((initial, 0)),
            receiver_count: AtomicUsize::new(1), // Counts the Receiver returned by channel()
            sender_dropped: AtomicBool::new(false),
            waiters: Mutex::new(SmallVec::new()),
            receiver_versions: Mutex::new(Arena::new()),
            cancellation_count: AtomicU64::new(0),
        }
    }

    fn is_sender_dropped(&self) -> bool {
        self.sender_dropped.load(Ordering::Acquire)
    }

    fn current_version(&self) -> u64 {
        self.value.read().1
    }

    fn insert_receiver_version(&self, version: u64) -> ArenaIndex {
        self.receiver_versions.lock().insert(version)
    }

    fn update_receiver_version(&self, token: ArenaIndex, version: u64) {
        if let Some(seen_version) = self.receiver_versions.lock().get_mut(token) {
            *seen_version = version;
        }
    }

    fn remove_receiver_version(&self, token: ArenaIndex) {
        self.receiver_versions.lock().remove(token);
    }

    fn lagged_receiver_count(&self, current_version: u64) -> usize {
        self.receiver_versions
            .lock()
            .iter()
            .filter(|(_, seen_version)| **seen_version != current_version)
            .count()
    }

    fn recv_waiter_count(&self) -> usize {
        self.waiters
            .lock()
            .iter()
            .filter(|entry| {
                entry.queued.load(Ordering::Acquire) && Arc::strong_count(&entry.queued) > 1
            })
            .count()
    }

    fn record_cancellation(&self) {
        self.cancellation_count.fetch_add(1, Ordering::Relaxed);
    }

    fn telemetry_snapshot(
        &self,
        channel_id: u64,
        receiver_seen_version: Option<u64>,
    ) -> WatchTelemetrySnapshot {
        let current_version = self.current_version();
        let receiver_count = self.receiver_count.load(Ordering::Acquire);
        let recv_waiter_count = self.recv_waiter_count();
        let lagged_receiver_count = self.lagged_receiver_count(current_version);
        let sender_dropped = self.is_sender_dropped();
        let receiver_has_change =
            receiver_seen_version.is_some_and(|seen_version| seen_version != current_version);
        let closed = receiver_count == 0 || sender_dropped;

        let receiver_health = if receiver_count == 0 {
            "receiver_dropped"
        } else if receiver_has_change {
            "changed"
        } else if sender_dropped {
            "sender_closed"
        } else if recv_waiter_count > 0 {
            "waiting"
        } else if receiver_seen_version.is_some() {
            "unchanged"
        } else if lagged_receiver_count > 0 {
            "lagged"
        } else {
            "open"
        };

        WatchTelemetrySnapshot {
            channel_id,
            channel_kind: "watch",
            capacity: 1,
            queued_messages: usize::from(receiver_has_change || lagged_receiver_count > 0),
            reserved_uncommitted_obligations: 0,
            send_waiter_count: 0,
            recv_waiter_count,
            receiver_count,
            receiver_health,
            lagged_receiver_count: Some(lagged_receiver_count),
            cancellation_count: self.cancellation_count.load(Ordering::Relaxed),
            closed,
        }
    }

    fn wake_all_waiters(&self) {
        let waiters: SmallVec<[WatchWaiter; 4]> = {
            let mut w = self.waiters.lock();
            std::mem::take(&mut *w)
        };
        for w in waiters {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
        }
    }

    fn register_waker(&self, waiter: WatchWaiter) {
        let mut waiters = self.waiters.lock();
        // Single pass: prune stale entries and update existing in one traversal.
        let mut found = false;
        waiters.retain_mut(|entry| {
            if Arc::strong_count(&entry.queued) <= 1 {
                return false;
            }
            if !found && Arc::ptr_eq(&entry.queued, &waiter.queued) {
                if !entry.waker.will_wake(&waiter.waker) {
                    entry.waker.clone_from(&waiter.waker);
                }
                found = true;
            }
            true
        });
        if !found {
            waiters.push(waiter);
        }
    }

    /// Update the waker for an already-queued waiter without pre-cloning.
    /// Returns `true` if the waiter was found and refreshed, `false` if not found
    /// (caller should fall back to `register_waker` with a new `WatchWaiter`).
    fn refresh_waker(&self, queued: &Arc<AtomicBool>, new_waker: &Waker) -> bool {
        let mut waiters = self.waiters.lock();
        // Single pass: prune stale entries and refresh target in one traversal.
        let mut found = false;
        waiters.retain_mut(|entry| {
            if Arc::strong_count(&entry.queued) <= 1 {
                return false;
            }
            if !found && Arc::ptr_eq(&entry.queued, queued) {
                if !entry.waker.will_wake(new_waker) {
                    entry.waker.clone_from(new_waker);
                }
                found = true;
            }
            true
        });
        found
    }
}

/// Creates a new watch channel with an initial value.
///
/// Returns the sender and receiver halves. Additional receivers can be
/// created by calling `subscribe()` on the sender or `clone()` on a receiver.
///
/// # Example
///
/// ```ignore
/// let (tx, rx) = watch::channel(42);
/// ```
#[inline]
#[must_use]
pub fn channel<T>(initial: T) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(WatchInner::new(initial));
    let receiver_token = inner.insert_receiver_version(0);
    (
        Sender {
            inner: Arc::clone(&inner),
        },
        Receiver {
            inner,
            seen_version: 0,
            receiver_token,
            waiter: None,
        },
    )
}

/// The sending half of a watch channel.
///
/// Only one `Sender` exists per channel. When dropped, all receivers
/// waiting on `changed()` will receive a `Closed` error.
#[derive(Debug)]
pub struct Sender<T> {
    inner: Arc<WatchInner<T>>,
}

impl<T> Sender<T> {
    /// Sends a new value, notifying all waiting receivers.
    ///
    /// This atomically updates the value and increments the version number.
    /// All receivers waiting on `changed()` will be woken.
    ///
    /// Stores a new latest value for current and future subscribers.
    ///
    /// This preserves the watch cell even when there are no active receivers.
    /// New subscribers created after a zero-receiver gap observe the most
    /// recent value.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use asupersync::Cx;
    /// use asupersync::channel::watch;
    ///
    /// #[derive(Clone, Debug, PartialEq, Eq)]
    /// struct Config {
    ///     generation: u64,
    ///     enabled: bool,
    /// }
    ///
    /// # async fn apply_update(cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
    /// let (tx, mut rx) = watch::channel(Config {
    ///     generation: 0,
    ///     enabled: false,
    /// });
    ///
    /// tx.send(Config {
    ///     generation: 1,
    ///     enabled: true,
    /// })?;
    ///
    /// rx.changed(cx).await?;
    /// let updated = rx.borrow_and_update_clone();
    ///
    /// assert_eq!(
    ///     updated,
    ///     Config {
    ///         generation: 1,
    ///         enabled: true,
    ///     }
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed(value)` only if the sender has already been
    /// marked closed.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        if self.inner.is_sender_dropped() {
            return Err(SendError::Closed(value));
        }

        let _old_value = {
            let mut guard = self.inner.value.write();
            let old = std::mem::replace(&mut guard.0, value);
            guard.1 = guard.1.wrapping_add(1);
            old
        };

        if self.inner.receiver_count.load(Ordering::Acquire) != 0 {
            self.inner.wake_all_waiters();
        }

        Ok(())
    }

    /// Modifies the current value.
    ///
    /// To avoid deadlocks, this method clones the current value, releases the lock,
    /// applies the closure to the clone, then reacquires the lock to update the value.
    /// This prevents user closures from running while holding the write lock.
    ///
    /// Applies an in-place update to the latest value for current and future
    /// subscribers.
    ///
    /// Like [`Sender::send`], this preserves the watch cell even if there are
    /// no active receivers at the instant of mutation.
    ///
    /// # Errors
    ///
    /// Returns `Err(ModifyError)` only if the sender has already been marked
    /// closed.
    pub fn send_modify<F>(&self, f: F) -> Result<(), ModifyError>
    where
        T: Clone,
        F: FnOnce(&mut T),
    {
        if self.inner.is_sender_dropped() {
            return Err(ModifyError);
        }

        // Clone current value while holding read lock to avoid calling user code under write lock
        let mut value = {
            let guard = self.inner.value.read();
            guard.0.clone()
        };

        // Call user closure without holding any locks to prevent deadlocks
        f(&mut value);

        // Update the value atomically
        {
            let mut guard = self.inner.value.write();
            guard.0 = value;
            guard.1 = guard.1.wrapping_add(1);
        }

        if self.inner.receiver_count.load(Ordering::Acquire) != 0 {
            self.inner.wake_all_waiters();
        }

        Ok(())
    }

    /// Returns a reference to the current value.
    ///
    /// This acquires a read lock on the value. The returned `Ref` holds
    /// the lock and provides access to the value.
    #[inline]
    #[must_use]
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.inner.value.read(),
        }
    }

    /// Creates a new receiver subscribed to this channel.
    ///
    /// The new receiver starts with `seen_version` equal to the current
    /// version, so it will only see future changes.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<T> {
        // Hold the value read-lock while incrementing receiver_count and
        // sampling the version.  send() holds the write-lock when it
        // updates the version, so this guarantees we cannot observe a
        // post-send version while the sender believed there were fewer
        // receivers (the same TOCTOU class fixed in broadcast subscribe
        // by commit e9314df5).
        let (current_version, receiver_token) = {
            let guard = self.inner.value.read();
            self.inner.receiver_count.fetch_add(1, Ordering::Relaxed);
            let receiver_token = self.inner.insert_receiver_version(guard.1);
            (guard.1, receiver_token)
        };
        Receiver {
            inner: Arc::clone(&self.inner),
            seen_version: current_version,
            receiver_token,
            waiter: None,
        }
    }

    /// Returns the number of active receivers (excluding sender).
    #[inline]
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.inner.receiver_count.load(Ordering::Relaxed)
    }

    /// Returns true if all receivers have been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.receiver_count.load(Ordering::Acquire) == 0
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[must_use]
    #[inline]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> WatchTelemetrySnapshot {
        self.inner.telemetry_snapshot(channel_id, None)
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.inner.sender_dropped.store(true, Ordering::Release);
        // Wake all waiting receivers so they see Closed.
        // Collect wakers under lock, wake outside.
        let waiters: SmallVec<[WatchWaiter; 4]> = {
            let mut w = self.inner.waiters.lock();
            std::mem::take(&mut *w)
        };
        for w in waiters {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
        }
    }
}

/// The receiving half of a watch channel.
///
/// Multiple receivers can exist for the same channel. Each receiver
/// independently tracks which version it has seen.
#[derive(Debug)]
pub struct Receiver<T> {
    inner: Arc<WatchInner<T>>,
    /// The version number last seen by this receiver.
    seen_version: u64,
    /// Token for this receiver's shared telemetry version cursor.
    receiver_token: ArenaIndex,
    /// Deduplication flag shared with our entry in the waiters vec.
    /// Prevents unbounded waker growth between sends.
    waiter: Option<Arc<AtomicBool>>,
}

impl<T> Receiver<T> {
    /// Waits until a new value is available.
    ///
    /// Returns a future that resolves when the channel's version differs from
    /// `seen_version`, then updates `seen_version` to the current version.
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe. If the future is dropped before completion,
    /// the receiver's `seen_version` is unchanged and the wait can be retried.
    ///
    /// # Errors
    ///
    /// Returns `RecvError::Closed` if the sender was dropped.
    /// Returns `RecvError::Cancelled` if the operation was cancelled.
    pub fn changed<'a, 'b, Caps>(&'a mut self, cx: &'b Cx<Caps>) -> ChangedFuture<'a, 'b, T, Caps> {
        cx.trace("watch::changed starting wait");
        ChangedFuture {
            receiver: self,
            cx,
            completed: false,
        }
    }

    pub(crate) fn poll_changed<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        context: &Context<'_>,
    ) -> Poll<Result<(), RecvError>> {
        if cx.checkpoint().is_err() {
            cx.trace("watch::changed cancelled");
            self.inner.record_cancellation();
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        let current = self.inner.current_version();
        if current != self.seen_version {
            self.seen_version = current;
            self.inner
                .update_receiver_version(self.receiver_token, self.seen_version);
            cx.trace("watch::changed received update");
            return Poll::Ready(Ok(()));
        }

        if self.inner.is_sender_dropped() {
            let current = self.inner.current_version();
            if current != self.seen_version {
                self.seen_version = current;
                self.inner
                    .update_receiver_version(self.receiver_token, self.seen_version);
                return Poll::Ready(Ok(()));
            }
            cx.trace("watch::changed sender dropped");
            return Poll::Ready(Err(RecvError::Closed));
        }

        match self.waiter.as_ref() {
            Some(w) if !w.load(Ordering::Acquire) => {
                w.store(true, Ordering::Release);
                self.inner.register_waker(WatchWaiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(w),
                });
            }
            Some(w) => {
                if !self.inner.refresh_waker(w, context.waker()) {
                    self.inner.register_waker(WatchWaiter {
                        waker: context.waker().clone(),
                        queued: Arc::clone(w),
                    });
                }
            }
            None => {
                let w = Arc::new(AtomicBool::new(true));
                self.inner.register_waker(WatchWaiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(&w),
                });
                self.waiter = Some(w);
            }
        }

        // We must check ONE MORE TIME after registering the waker to avoid race conditions
        // where a value was sent between our initial check and adding ourselves to the wait queue.
        let current_after_register = self.inner.current_version();
        if current_after_register != self.seen_version {
            self.seen_version = current_after_register;
            self.inner
                .update_receiver_version(self.receiver_token, self.seen_version);
            cx.trace("watch::changed received update after register");

            // Fast path: we registered, but actually the value arrived.
            // We should mark ourselves as no longer waiting so our drop doesn't take the lock.
            if let Some(w) = self.waiter.as_ref() {
                w.store(false, Ordering::Release);
            }
            return Poll::Ready(Ok(()));
        }

        if self.inner.is_sender_dropped() {
            // Also fast path for drop
            if let Some(w) = self.waiter.as_ref() {
                w.store(false, Ordering::Release);
            }
            return Poll::Ready(Err(RecvError::Closed));
        }

        Poll::Pending
    }

    /// Returns a reference to the current value.
    ///
    /// This does NOT update `seen_version`.
    ///
    /// If you need the returned snapshot and the acknowledgement to refer to
    /// the same version, use [`Receiver::borrow_and_update`] instead.
    /// Calling [`Receiver::mark_seen`] later acknowledges whatever version is
    /// current at that later instant and can therefore skip an intervening send.
    #[inline]
    #[must_use]
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.inner.value.read(),
        }
    }

    /// Borrows the current value and marks it as seen in a single operation.
    ///
    /// This prevents race conditions where a new value arrives between calling
    /// `changed()` and `borrow()`, ensuring the receiver doesn't miss updates
    /// or process the same value multiple times.
    #[inline]
    #[must_use]
    pub fn borrow_and_update(&mut self) -> Ref<'_, T> {
        let guard = self.inner.value.read();
        self.seen_version = guard.1;
        self.inner
            .update_receiver_version(self.receiver_token, self.seen_version);
        Ref { guard }
    }

    /// Returns a clone of the current value.
    ///
    /// Convenience method that borrows and clones in one operation.
    /// Does NOT update `seen_version`.
    #[inline]
    #[must_use]
    pub fn borrow_and_clone(&self) -> T
    where
        T: Clone,
    {
        self.borrow().clone()
    }

    /// Returns a clone of the current value and marks it as seen.
    ///
    /// Convenience method that borrows, updates the seen version, and clones
    /// in one operation.
    #[inline]
    #[must_use]
    pub fn borrow_and_update_clone(&mut self) -> T
    where
        T: Clone,
    {
        self.borrow_and_update().clone_inner()
    }

    /// Marks the current value as seen.
    ///
    /// This acknowledges the latest currently published version, not a
    /// previously borrowed snapshot. If you need snapshot-aligned
    /// acknowledgement, use [`Receiver::borrow_and_update`] or
    /// [`Receiver::borrow_and_update_clone`].
    ///
    /// After this call, `changed()` will only return when a newer value is
    /// available.
    #[inline]
    pub fn mark_seen(&mut self) {
        self.seen_version = self.inner.current_version();
        self.inner
            .update_receiver_version(self.receiver_token, self.seen_version);
    }

    /// Returns true if there's a new value since last seen.
    #[inline]
    #[must_use]
    pub fn has_changed(&self) -> bool {
        self.inner.current_version() != self.seen_version
    }

    /// Returns true if the sender has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_sender_dropped()
    }

    /// Returns the version number last seen by this receiver.
    #[inline]
    #[must_use]
    pub fn seen_version(&self) -> u64 {
        self.seen_version
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[must_use]
    #[inline]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> WatchTelemetrySnapshot {
        self.inner
            .telemetry_snapshot(channel_id, Some(self.seen_version))
    }
}

/// Future returned by [`Receiver::changed`].
///
/// Resolves when a new value is available or the channel closes.
pub struct ChangedFuture<'a, 'b, T, Caps = crate::cx::cap::All> {
    receiver: &'a mut Receiver<T>,
    cx: &'b Cx<Caps>,
    completed: bool,
}

impl<T, Caps> Future for ChangedFuture<'_, '_, T, Caps> {
    type Output = Result<(), RecvError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        match this.receiver.poll_changed(this.cx, context) {
            Poll::Ready(result) => {
                this.completed = true;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T, Caps> Drop for ChangedFuture<'_, '_, T, Caps> {
    fn drop(&mut self) {
        let mut removed_pending_waiter = false;
        if let Some(waiter) = self.receiver.waiter.as_ref() {
            // The post-register fast paths can clear the queued flag before Drop runs
            // while the waiter entry is still linked from the shared waiter list.
            if waiter.load(Ordering::Acquire) || Arc::strong_count(waiter) > 1 {
                waiter.store(false, Ordering::Release);
                let mut waiters = self.receiver.inner.waiters.lock();
                waiters.retain(|entry| {
                    let remove = Arc::ptr_eq(&entry.queued, waiter);
                    removed_pending_waiter |= remove;
                    !remove && Arc::strong_count(&entry.queued) > 1
                });
            }
        }
        if !self.completed && removed_pending_waiter {
            self.receiver.inner.record_cancellation();
        }
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        let receiver_token = self.inner.insert_receiver_version(self.seen_version);
        self.inner.receiver_count.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
            seen_version: self.seen_version,
            receiver_token,
            waiter: None,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.inner.receiver_count.fetch_sub(1, Ordering::Release);
        self.inner.remove_receiver_version(self.receiver_token);

        // Eagerly remove this receiver's waiter entry so dropped receivers do not
        // leave stale wakers behind until a later send/re-registration.
        if let Some(waiter) = self.waiter.take() {
            let mut waiters = self.inner.waiters.lock();
            waiters.retain(|entry| {
                !Arc::ptr_eq(&entry.queued, &waiter) && Arc::strong_count(&entry.queued) > 1
            });
        }
    }
}

/// A reference to the value in a watch channel.
///
/// This holds a read lock on the value. Multiple `Ref`s can exist
/// simultaneously for reading.
#[derive(Debug)]
pub struct Ref<'a, T> {
    guard: RwLockReadGuard<'a, (T, u64)>,
}

impl<T> std::ops::Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard.0
    }
}

impl<T: Clone> Ref<'_, T> {
    /// Clones the referenced value.
    #[must_use]
    pub fn clone_inner(&self) -> T {
        self.guard.0.clone()
    }
}

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
    use std::sync::atomic::AtomicUsize;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    /// Polls a future that should be immediately ready (e.g., after send).
    fn poll_ready<F: Future + Unpin>(f: &mut F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match Pin::new(f).poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("expected Ready, got Pending"),
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn changed_accepts_detached_no_cap_context() {
        init_test("changed_accepts_detached_no_cap_context");
        let cx = Cx::<crate::cx::cap::None>::detached_cancel_context();
        let (tx, mut rx) = channel(0);

        tx.send(47).expect("send should succeed");
        block_on(rx.changed(&cx)).expect("changed should accept cap::None Cx");
        let value = *rx.borrow();

        crate::assert_with_log!(value == 47, "watch value", 47, value);
        crate::test_complete!("changed_accepts_detached_no_cap_context");
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        tx.send(42).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn initial_value_visible() {
        init_test("initial_value_visible");
        let (tx, rx) = channel(42);
        let rx_value = *rx.borrow();
        crate::assert_with_log!(rx_value == 42, "rx initial", 42, rx_value);
        let tx_value = *tx.borrow();
        crate::assert_with_log!(tx_value == 42, "tx initial", 42, tx_value);
        crate::test_complete!("initial_value_visible");
    }

    #[test]
    fn multiple_updates() {
        init_test("multiple_updates");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        for i in 1..=10 {
            tx.send(i).expect("send failed");
            poll_ready(&mut rx.changed(&cx)).expect("changed failed");
            let value = *rx.borrow();
            crate::assert_with_log!(value == i, "rx value", i, value);
        }
        crate::test_complete!("multiple_updates");
    }

    #[test]
    fn latest_value_wins() {
        init_test("latest_value_wins");
        let (tx, rx) = channel(0);

        for i in 1..=100 {
            tx.send(i).expect("send failed");
        }

        // Watch holds only the latest value, not a queue.
        let value = *rx.borrow();
        crate::assert_with_log!(value == 100, "latest value", 100, value);
        crate::test_complete!("latest_value_wins");
    }

    #[test]
    fn send_modify() {
        init_test("send_modify");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        tx.send_modify(|v| *v = 42).expect("send_modify failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let first = *rx.borrow();
        crate::assert_with_log!(first == 42, "after first modify", 42, first);

        tx.send_modify(|v| *v += 10).expect("send_modify failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let second = *rx.borrow();
        crate::assert_with_log!(second == 52, "after second modify", 52, second);
        crate::test_complete!("send_modify");
    }

    #[test]
    fn borrow_and_clone() {
        init_test("borrow_and_clone");
        let (_tx, rx) = channel(42);
        let value: i32 = rx.borrow_and_clone();
        crate::assert_with_log!(value == 42, "borrow_and_clone", 42, value);
        crate::test_complete!("borrow_and_clone");
    }

    #[test]
    fn mark_seen() {
        init_test("mark_seen");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Send value
        tx.send(1).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "has_changed after send", true, changed);

        // Mark seen without calling changed()
        rx.mark_seen();
        let changed = rx.has_changed();
        crate::assert_with_log!(!changed, "has_changed after mark", false, changed);

        // Need new value for changed() to return
        tx.send(2).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 2, "after second send", 2, value);
        crate::test_complete!("mark_seen");
    }

    #[test]
    fn changed_returns_only_on_new_value() {
        init_test("changed_returns_only_on_new_value");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Initial version is 0, seen_version is 0
        // changed() should block until version > 0

        // Send first update
        tx.send(1).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");

        // Now version=1, seen_version=1
        // has_changed should be false
        let changed = rx.has_changed();
        crate::assert_with_log!(!changed, "has_changed false", false, changed);

        // Send another
        tx.send(2).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "has_changed true", true, changed);
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 2, "value", 2, value);
        crate::test_complete!("changed_returns_only_on_new_value");
    }

    #[test]
    fn multiple_receivers() {
        init_test("multiple_receivers");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);
        let mut rx2 = rx1.clone();

        tx.send(42).expect("send failed");

        // Subscribe AFTER send - rx3 starts at current version (1)
        let rx3 = tx.subscribe();

        // rx1 and rx2 see the update (they were created before send)
        poll_ready(&mut rx1.changed(&cx)).expect("changed failed");
        poll_ready(&mut rx2.changed(&cx)).expect("changed failed");

        // rx3 was subscribed after send, so it already sees version 1
        // and its seen_version was set to current (1), so no change pending
        let changed = rx3.has_changed();
        crate::assert_with_log!(!changed, "rx3 has_changed", false, changed);

        let v1 = *rx1.borrow();
        crate::assert_with_log!(v1 == 42, "rx1 value", 42, v1);
        let v2 = *rx2.borrow();
        crate::assert_with_log!(v2 == 42, "rx2 value", 42, v2);
        let v3 = *rx3.borrow();
        crate::assert_with_log!(v3 == 42, "rx3 value", 42, v3);
        crate::test_complete!("multiple_receivers");
    }

    #[test]
    fn receiver_count() {
        init_test("receiver_count");
        let (tx, rx1) = channel::<i32>(0);
        let count = tx.receiver_count();
        crate::assert_with_log!(count == 1, "count 1", 1, count);

        let rx2 = rx1.clone();
        let count = tx.receiver_count();
        crate::assert_with_log!(count == 2, "count 2", 2, count);

        let rx3 = tx.subscribe();
        let count = tx.receiver_count();
        crate::assert_with_log!(count == 3, "count 3", 3, count);

        drop(rx1);
        let count = tx.receiver_count();
        crate::assert_with_log!(count == 2, "count 2 after drop", 2, count);

        drop(rx2);
        drop(rx3);
        let count = tx.receiver_count();
        crate::assert_with_log!(count == 0, "count 0", 0, count);
        let closed = tx.is_closed();
        crate::assert_with_log!(closed, "tx closed", true, closed);
        crate::test_complete!("receiver_count");
    }

    #[test]
    fn sender_dropped() {
        init_test("sender_dropped");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Send before drop
        tx.send(42).expect("send failed");
        drop(tx);

        // Receiver should still see the value
        let closed = rx.is_closed();
        crate::assert_with_log!(closed, "rx closed", true, closed);
        poll_ready(&mut rx.changed(&cx)).expect("should see final update");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 42, "borrow value", 42, value);

        // Now changed() should return error
        let result = poll_ready(&mut rx.changed(&cx));
        crate::assert_with_log!(
            result.is_err(),
            "changed returns error",
            true,
            result.is_err()
        );
        crate::test_complete!("sender_dropped");
    }

    #[test]
    fn send_without_receivers_preserves_latest_value() {
        init_test("send_without_receivers_preserves_latest_value");
        let (tx, rx) = channel(0);
        drop(rx);

        let closed = tx.is_closed();
        crate::assert_with_log!(closed, "tx closed", true, closed);
        let result = tx.send(42);
        crate::assert_with_log!(
            result.is_ok(),
            "send still preserves state",
            true,
            result.is_ok()
        );

        let rx2 = tx.subscribe();
        let value = *rx2.borrow();
        crate::assert_with_log!(value == 42, "subscriber sees preserved state", 42, value);
        let changed = rx2.has_changed();
        crate::assert_with_log!(
            !changed,
            "new subscriber starts at current version",
            false,
            changed
        );
        crate::test_complete!("send_without_receivers_preserves_latest_value");
    }

    #[test]
    fn send_modify_without_receivers_preserves_latest_value() {
        init_test("send_modify_without_receivers_preserves_latest_value");
        let (tx, rx) = channel(10);
        drop(rx);

        let result = tx.send_modify(|value| *value += 32);
        crate::assert_with_log!(
            result.is_ok(),
            "send_modify preserves state",
            true,
            result.is_ok()
        );

        let rx2 = tx.subscribe();
        let value = *rx2.borrow();
        crate::assert_with_log!(value == 42, "subscriber sees modified state", 42, value);
        crate::test_complete!("send_modify_without_receivers_preserves_latest_value");
    }

    #[test]
    fn version_tracking() {
        init_test("version_tracking");
        let (_tx, rx) = channel(0);
        let version = rx.seen_version();
        crate::assert_with_log!(version == 0, "seen_version", 0, version);
        crate::test_complete!("version_tracking");
    }

    #[test]
    fn version_wraparound_still_detects_changes() {
        init_test("version_wraparound_still_detects_changes");
        let cx = test_cx();
        let (tx, mut rx) = channel(0_u8);

        {
            let mut guard = tx.inner.value.write();
            guard.1 = u64::MAX - 1;
            drop(guard);
        }
        rx.seen_version = u64::MAX - 1;

        tx.send(1).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "has_changed at u64::MAX", true, changed);
        poll_ready(&mut rx.changed(&cx)).expect("changed at u64::MAX failed");
        let first = *rx.borrow();
        crate::assert_with_log!(first == 1, "value at u64::MAX", 1, first);

        tx.send(2).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "has_changed after wrap", true, changed);
        poll_ready(&mut rx.changed(&cx)).expect("changed after wrap failed");
        let second = *rx.borrow();
        crate::assert_with_log!(second == 2, "value after wrap", 2, second);

        let seen = rx.seen_version();
        crate::assert_with_log!(seen == 0, "seen_version wrapped", 0, seen);
        crate::test_complete!("version_wraparound_still_detects_changes");
    }

    #[test]
    fn has_changed_reflects_state() {
        init_test("has_changed_reflects_state");
        let (tx, rx) = channel(0);

        // Initial: no change since initial value
        let changed = rx.has_changed();
        crate::assert_with_log!(!changed, "initial has_changed", false, changed);

        tx.send(1).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "has_changed after send", true, changed);
        crate::test_complete!("has_changed_reflects_state");
    }

    #[test]
    fn cloned_receiver_inherits_version() {
        init_test("cloned_receiver_inherits_version");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);

        tx.send(1).expect("send failed");
        poll_ready(&mut rx1.changed(&cx)).expect("changed failed");

        // Clone after rx1 has seen the update
        let rx2 = rx1.clone();

        // rx2 inherits seen_version from rx1, so no pending change
        let changed = rx2.has_changed();
        crate::assert_with_log!(!changed, "rx2 inherits version", false, changed);
        crate::test_complete!("cloned_receiver_inherits_version");
    }

    #[test]
    fn subscribe_gets_current_version() {
        init_test("subscribe_gets_current_version");
        let (tx, _rx) = channel(0);

        tx.send(1).expect("send failed");
        tx.send(2).expect("send failed");

        // Subscribe after updates
        let rx2 = tx.subscribe();

        // rx2 starts with current version, so no pending change
        let changed = rx2.has_changed();
        crate::assert_with_log!(!changed, "rx2 no change", false, changed);
        let value = *rx2.borrow();
        crate::assert_with_log!(value == 2, "rx2 value", 2, value);
        crate::test_complete!("subscribe_gets_current_version");
    }

    #[test]
    fn send_error_display() {
        init_test("send_error_display");
        let err = SendError::Closed(42);
        let text = err.to_string();
        crate::assert_with_log!(
            text == "sending on a closed watch channel",
            "display",
            "sending on a closed watch channel",
            text
        );
        crate::test_complete!("send_error_display");
    }

    #[test]
    fn recv_error_display() {
        init_test("recv_error_display");
        let closed_text = RecvError::Closed.to_string();
        crate::assert_with_log!(
            closed_text == "receiving on a closed watch channel",
            "display",
            "receiving on a closed watch channel",
            closed_text
        );
        let cancelled_text = RecvError::Cancelled.to_string();
        crate::assert_with_log!(
            cancelled_text == "receive operation cancelled",
            "display",
            "receive operation cancelled",
            cancelled_text
        );
        crate::test_complete!("recv_error_display");
    }

    #[test]
    fn ref_deref() {
        init_test("ref_deref");
        let (_tx, rx) = channel(42);
        let r = rx.borrow();
        let _: &i32 = &r;
        let value = *r;
        crate::assert_with_log!(value == 42, "deref", 42, value);
        drop(r);
        crate::test_complete!("ref_deref");
    }

    #[test]
    fn ref_clone_inner() {
        init_test("ref_clone_inner");
        let (_tx, rx) = channel(String::from("hello"));
        let cloned: String = rx.borrow().clone_inner();
        crate::assert_with_log!(cloned == "hello", "clone_inner", "hello", cloned);
        crate::test_complete!("ref_clone_inner");
    }

    #[test]
    fn cancel_during_wait_preserves_version() {
        init_test("cancel_during_wait_preserves_version");
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let (tx, mut rx) = channel(0);

        // changed() should return error due to cancellation
        let result = poll_ready(&mut rx.changed(&cx));
        crate::assert_with_log!(
            result.is_err(),
            "changed error on cancel",
            true,
            result.is_err()
        );

        // seen_version should be unchanged (still 0)
        let version = rx.seen_version();
        crate::assert_with_log!(version == 0, "seen_version", 0, version);

        // After cancellation cleared, should see the update
        cx.set_cancel_requested(false);
        tx.send(1).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let version = rx.seen_version();
        crate::assert_with_log!(version == 1, "seen_version after", 1, version);
        crate::test_complete!("cancel_during_wait_preserves_version");
    }

    #[test]
    fn cancel_after_pending_repoll_reuses_waiter_slot() {
        init_test("cancel_after_pending_repoll_reuses_waiter_slot");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);
        {
            let mut future = rx.changed(&cx);

            let first_poll = Pin::new(&mut future).poll(&mut task_cx);
            crate::assert_with_log!(
                first_poll.is_pending(),
                "first poll pending",
                true,
                first_poll.is_pending()
            );

            let waiter_count = tx.inner.waiters.lock().len();
            crate::assert_with_log!(waiter_count == 1, "waiter registered", 1, waiter_count);

            cx.set_cancel_requested(true);
            let cancelled_poll = Pin::new(&mut future).poll(&mut task_cx);
            crate::assert_with_log!(
                matches!(cancelled_poll, Poll::Ready(Err(RecvError::Cancelled))),
                "pending waiter observes cancellation",
                "Ready(Err(Cancelled))",
                format!("{cancelled_poll:?}")
            );
        }

        // ChangedFuture::drop eagerly cleans up the waiter entry from the shared list.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "cancelled future drop cleans up waiter entry",
            0,
            waiter_count
        );

        cx.set_cancel_requested(false);
        {
            let mut future = rx.changed(&cx);
            let repoll = Pin::new(&mut future).poll(&mut task_cx);
            crate::assert_with_log!(
                repoll.is_pending(),
                "recreated future pending",
                true,
                repoll.is_pending()
            );

            // While alive, the re-registered waiter is present.
            let waiter_count = tx.inner.waiters.lock().len();
            crate::assert_with_log!(
                waiter_count == 1,
                "re-poll re-registers waiter",
                1,
                waiter_count
            );
        }

        // After future drop, waiter is cleaned up again.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "future drop cleans up re-registered waiter",
            0,
            waiter_count
        );

        tx.send(1).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed after send");
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "waiters drained after send",
            0,
            waiter_count
        );
        crate::test_complete!("cancel_after_pending_repoll_reuses_waiter_slot");
    }

    #[test]
    fn changed_returns_pending_then_ready_after_send() {
        init_test("changed_returns_pending_then_ready_after_send");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // No send yet — changed() should return Pending
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        {
            let mut future = rx.changed(&cx);
            let poll_result = Pin::new(&mut future).poll(&mut task_cx);
            crate::assert_with_log!(
                poll_result.is_pending(),
                "first poll pending",
                true,
                poll_result.is_pending()
            );
        }

        // Send a value
        tx.send(42).expect("send failed");

        // Now poll again — should be Ready(Ok(()))
        poll_ready(&mut rx.changed(&cx)).expect("changed after send");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 42, "value after send", 42, value);
        crate::test_complete!("changed_returns_pending_then_ready_after_send");
    }

    #[test]
    fn sender_drop_wakes_pending_receiver() {
        init_test("sender_drop_wakes_pending_receiver");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Poll — should be Pending
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);
        {
            let mut future = rx.changed(&cx);
            let poll_result = Pin::new(&mut future).poll(&mut task_cx);
            crate::assert_with_log!(
                poll_result.is_pending(),
                "pending before drop",
                true,
                poll_result.is_pending()
            );
        }

        // Drop sender
        drop(tx);

        // Poll again — should be Ready(Err(Closed))
        let result = poll_ready(&mut rx.changed(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Closed)),
            "closed after sender drop",
            true,
            matches!(result, Err(RecvError::Closed))
        );
        crate::test_complete!("sender_drop_wakes_pending_receiver");
    }

    #[test]
    fn sender_drop_wakes_all_pending_receivers() {
        init_test("sender_drop_wakes_all_pending_receivers");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);
        let mut rx2 = tx.subscribe();
        let inner = Arc::clone(&tx.inner);

        let wake_count1 = Arc::new(AtomicUsize::new(0));
        let waker1 = Waker::from(Arc::new(CountWake {
            count: Arc::clone(&wake_count1),
        }));
        let mut task_cx1 = Context::from_waker(&waker1);
        let mut future1 = rx1.changed(&cx);
        let first_poll = Pin::new(&mut future1).poll(&mut task_cx1);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "receiver 1 pending before sender drop",
            true,
            first_poll.is_pending()
        );

        let wake_count2 = Arc::new(AtomicUsize::new(0));
        let waker2 = Waker::from(Arc::new(CountWake {
            count: Arc::clone(&wake_count2),
        }));
        let mut task_cx2 = Context::from_waker(&waker2);
        let mut future2 = rx2.changed(&cx);
        let second_poll = Pin::new(&mut future2).poll(&mut task_cx2);
        crate::assert_with_log!(
            second_poll.is_pending(),
            "receiver 2 pending before sender drop",
            true,
            second_poll.is_pending()
        );

        let waiter_count = inner.waiters.lock().len();
        crate::assert_with_log!(waiter_count == 2, "two waiters registered", 2, waiter_count);

        drop(tx);

        let woken1 = wake_count1.load(Ordering::SeqCst);
        crate::assert_with_log!(woken1 > 0, "receiver 1 woken on close", "> 0", woken1);
        let woken2 = wake_count2.load(Ordering::SeqCst);
        crate::assert_with_log!(woken2 > 0, "receiver 2 woken on close", "> 0", woken2);

        let waiter_count = inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "close drains all waiters",
            0,
            waiter_count
        );

        let result1 = Pin::new(&mut future1).poll(&mut task_cx1);
        crate::assert_with_log!(
            matches!(result1, Poll::Ready(Err(RecvError::Closed))),
            "receiver 1 sees closed",
            "Ready(Err(Closed))",
            format!("{result1:?}")
        );

        let result2 = Pin::new(&mut future2).poll(&mut task_cx2);
        crate::assert_with_log!(
            matches!(result2, Poll::Ready(Err(RecvError::Closed))),
            "receiver 2 sees closed",
            "Ready(Err(Closed))",
            format!("{result2:?}")
        );
        crate::test_complete!("sender_drop_wakes_all_pending_receivers");
    }

    #[test]
    fn no_unbounded_waker_growth() {
        init_test("no_unbounded_waker_growth");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        // Poll the same future many times without any send.
        // Before the fix, each poll added a waker entry → unbounded growth.
        {
            let mut future = rx.changed(&cx);
            for _ in 0..100 {
                let result = Pin::new(&mut future).poll(&mut task_cx);
                assert!(result.is_pending());
            }

            // While the future is alive, the waiters vec should have exactly 1 entry, not 100.
            let waiter_count = tx.inner.waiters.lock().len();
            crate::assert_with_log!(
                waiter_count == 1,
                "waiter count after repeated polls (future alive)",
                1,
                waiter_count
            );
        }

        // ChangedFuture::drop eagerly cleans up the waiter entry.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "waiter cleaned up after future drop",
            0,
            waiter_count
        );

        // After send (which drains waiters), re-poll should add at most 1 again.
        tx.send(42).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 42, "value after send", 42, value);

        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "waiter count after drain",
            0,
            waiter_count
        );
        crate::test_complete!("no_unbounded_waker_growth");
    }

    #[test]
    fn cancel_and_recreate_bounded_waiters() {
        init_test("cancel_and_recreate_bounded_waiters");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        // Create and drop futures 50 times without sending.
        // ChangedFuture::drop eagerly cleans up each waiter entry,
        // so after the last drop the count is 0.
        for _ in 0..50 {
            let mut future = rx.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());
            // Verify bounded while alive.
            let waiter_count = tx.inner.waiters.lock().len();
            assert!(waiter_count <= 1, "at most 1 waiter while future alive");
            // future dropped here → waiter entry cleaned up
        }

        // All futures dropped → waiter entries cleaned up.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "all waiter entries cleaned up after future drops",
            0,
            waiter_count
        );

        // A single send drains all stale entries.
        tx.send(1).expect("send failed");
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(waiter_count == 0, "all drained after send", 0, waiter_count);
        crate::test_complete!("cancel_and_recreate_bounded_waiters");
    }

    #[test]
    fn dropped_receiver_waiter_is_pruned_on_next_registration() {
        init_test("dropped_receiver_waiter_is_pruned_on_next_registration");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);
        let mut rx2 = tx.subscribe();
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        // Register rx1 waiter, then drop future and rx1 without any send.
        // ChangedFuture::drop eagerly removes the waiter entry.
        {
            let mut future = rx1.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());
        }
        drop(rx1);

        // rx2 registers its own waiter — verify it's present while alive.
        {
            let mut future = rx2.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());

            let waiter_count = tx.inner.waiters.lock().len();
            crate::assert_with_log!(
                waiter_count == 1,
                "rx2 waiter registered while future alive",
                1,
                waiter_count
            );
        }

        // After rx2's future drops, waiter is cleaned up.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "rx2 waiter cleaned up after future drop",
            0,
            waiter_count
        );
        crate::test_complete!("dropped_receiver_waiter_is_pruned_on_next_registration");
    }

    #[test]
    fn dropped_receiver_eagerly_removes_pending_waiter() {
        init_test("dropped_receiver_eagerly_removes_pending_waiter");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        {
            let mut future = rx.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());

            // Waiter is present while future is alive.
            let waiter_count = tx.inner.waiters.lock().len();
            crate::assert_with_log!(waiter_count == 1, "waiter registered", 1, waiter_count);
        }

        // ChangedFuture::drop already cleaned up the waiter entry.
        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "waiter cleaned by future drop",
            0,
            waiter_count
        );

        drop(rx);

        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "waiter removed on receiver drop",
            0,
            waiter_count
        );
        let receiver_count = tx.receiver_count();
        crate::assert_with_log!(
            receiver_count == 0,
            "receiver count after drop",
            0,
            receiver_count
        );
        crate::test_complete!("dropped_receiver_eagerly_removes_pending_waiter");
    }

    #[test]
    fn completed_future_drop_cleans_false_flag_waiter_entry() {
        init_test("completed_future_drop_cleans_false_flag_waiter_entry");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waiter = Arc::new(AtomicBool::new(false));
        let waiter_waker = Waker::from(Arc::new(CountWake {
            count: Arc::clone(&wake_count),
        }));

        // This state is reachable when poll_changed() registers a waiter and then
        // returns Ready from the post-register update/close fast path.
        tx.inner.register_waker(WatchWaiter {
            waker: waiter_waker,
            queued: Arc::clone(&waiter),
        });
        rx.waiter = Some(Arc::clone(&waiter));

        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 1,
            "stale waiter entry present before drop",
            1,
            waiter_count
        );
        crate::assert_with_log!(
            !waiter.load(Ordering::Acquire),
            "queued flag already cleared before drop",
            false,
            waiter.load(Ordering::Acquire)
        );

        let future = ChangedFuture {
            receiver: &mut rx,
            cx: &cx,
            completed: true,
        };
        drop(future);

        let waiter_count = tx.inner.waiters.lock().len();
        crate::assert_with_log!(
            waiter_count == 0,
            "completed future drop removes stale waiter entry",
            0,
            waiter_count
        );
        let wake_total = wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            wake_total == 0,
            "drop does not spuriously wake",
            0,
            wake_total
        );
        crate::test_complete!("completed_future_drop_cleans_false_flag_waiter_entry");
    }

    struct CountWake {
        count: Arc<AtomicUsize>,
    }

    impl std::task::Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn changed_updates_waiter_waker_on_repoll() {
        init_test("changed_updates_waiter_waker_on_repoll");
        let cx = test_cx();
        let (tx, mut rx) = channel(0);
        let mut future = rx.changed(&cx);

        let first_count = Arc::new(AtomicUsize::new(0));
        let first_waker = Waker::from(Arc::new(CountWake {
            count: Arc::clone(&first_count),
        }));
        let mut first_cx = Context::from_waker(&first_waker);
        let first_poll = Pin::new(&mut future).poll(&mut first_cx);
        crate::assert_with_log!(
            first_poll.is_pending(),
            "first poll pending",
            true,
            first_poll.is_pending()
        );

        let second_count = Arc::new(AtomicUsize::new(0));
        let second_waker = Waker::from(Arc::new(CountWake {
            count: Arc::clone(&second_count),
        }));
        let mut second_cx = Context::from_waker(&second_waker);
        let second_poll = Pin::new(&mut future).poll(&mut second_cx);
        crate::assert_with_log!(
            second_poll.is_pending(),
            "second poll pending",
            true,
            second_poll.is_pending()
        );

        tx.send(1).expect("send failed");

        let second_wake_count = second_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            second_wake_count > 0,
            "latest waker notified",
            "> 0",
            second_wake_count
        );
        let first_wake_count = first_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            first_wake_count == 0,
            "stale waker not notified",
            0,
            first_wake_count
        );

        poll_ready(&mut future).expect("changed should complete after send");
        crate::test_complete!("changed_updates_waiter_waker_on_repoll");
    }

    #[test]
    fn shutdown_signal_pattern() {
        init_test("shutdown_signal_pattern");
        let cx = test_cx();
        let (shutdown_tx, mut shutdown_rx) = channel(false);

        // Check initial state
        let initial = *shutdown_rx.borrow();
        crate::assert_with_log!(!initial, "initial false", false, initial);

        // Trigger shutdown
        shutdown_tx.send(true).expect("send failed");
        poll_ready(&mut shutdown_rx.changed(&cx)).expect("changed failed");

        // Worker would check this
        let value = *shutdown_rx.borrow();
        crate::assert_with_log!(value, "shutdown true", true, value);
        crate::test_complete!("shutdown_signal_pattern");
    }

    #[test]
    fn sender_drop_sets_sender_dropped_atomically() {
        init_test("sender_drop_sets_sender_dropped_atomically");
        let (tx, rx) = channel::<i32>(0);

        let dropped = tx.inner.sender_dropped.load(Ordering::Acquire);
        crate::assert_with_log!(!dropped, "sender not dropped yet", false, dropped);

        drop(tx);

        let dropped = rx.inner.sender_dropped.load(Ordering::Acquire);
        crate::assert_with_log!(dropped, "sender dropped after drop", true, dropped);
        crate::test_complete!("sender_drop_sets_sender_dropped_atomically");
    }

    #[test]
    fn receiver_drop_decrements_count_atomically() {
        init_test("receiver_drop_decrements_count_atomically");
        let (tx, rx) = channel::<i32>(0);

        let count = tx.inner.receiver_count.load(Ordering::Acquire);
        crate::assert_with_log!(count == 1, "initial count", 1usize, count);

        drop(rx);

        let count = tx.inner.receiver_count.load(Ordering::Acquire);
        crate::assert_with_log!(count == 0, "count after drop", 0usize, count);
        crate::test_complete!("receiver_drop_decrements_count_atomically");
    }

    #[test]
    fn subscribe_version_is_consistent_with_send() {
        // Regression test: subscribe() must sample the version under the
        // value read-lock so a concurrent send cannot slip a version bump
        // between the receiver_count increment and the version read.
        //
        // We cannot perfectly reproduce the race in a single thread, but
        // we CAN verify the structural invariant: a freshly subscribed
        // receiver's seen_version equals the current channel version at
        // the instant the receiver becomes visible (receiver_count > 0).
        init_test("subscribe_version_is_consistent_with_send");
        let (tx, _rx) = channel(0i32);

        // Send a few values to advance the version.
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();

        let pre_version = tx.inner.current_version();
        let rx2 = tx.subscribe();
        let post_version = tx.inner.current_version();

        // The subscribed receiver must see a version in [pre, post].
        // Without concurrent sends they should all be equal.
        crate::assert_with_log!(
            rx2.seen_version == pre_version,
            "subscribe version matches current",
            pre_version,
            rx2.seen_version
        );
        crate::assert_with_log!(
            pre_version == post_version,
            "no concurrent version change",
            pre_version,
            post_version
        );

        // The new receiver should NOT see a pending change (it starts
        // at the current version).
        assert!(!rx2.has_changed());

        // After a new send the receiver should observe the change.
        tx.send(4).unwrap();
        assert!(rx2.has_changed());
        crate::test_complete!("subscribe_version_is_consistent_with_send");
    }

    #[test]
    fn subscribe_under_read_lock_blocks_concurrent_send() {
        // Demonstrates the lock ordering: subscribe holds value.read()
        // so a concurrent send (which needs value.write()) must wait,
        // ensuring the version + count are consistent.
        init_test("subscribe_under_read_lock_blocks_concurrent_send");
        let (tx, _rx) = channel(0i32);

        // Grab a read lock manually to simulate the window.
        let guard = tx.inner.value.read();
        let version_under_lock = guard.1;

        // While the read lock is held, receiver_count can be bumped
        // but send() cannot advance the version.
        tx.inner.receiver_count.fetch_add(1, Ordering::Relaxed);
        let count = tx.inner.receiver_count.load(Ordering::Acquire);
        crate::assert_with_log!(count == 2, "count bumped under lock", 2usize, count);

        // Version cannot have changed while we hold the read lock.
        let version_still = tx.inner.current_version();
        crate::assert_with_log!(
            version_still == version_under_lock,
            "version stable under read lock",
            version_under_lock,
            version_still
        );

        // Clean up the extra receiver_count we added.
        tx.inner.receiver_count.fetch_sub(1, Ordering::Release);
        drop(guard);
        crate::test_complete!("subscribe_under_read_lock_blocks_concurrent_send");
    }

    #[test]
    fn watch_send_error_debug_clone_copy_eq() {
        let e = SendError::Closed(42);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        let copied: SendError<i32> = e;
        let cloned = e;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn watch_recv_error_debug_clone_copy_eq() {
        let e = RecvError::Closed;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        let copied: RecvError = e;
        let cloned = e;
        assert_eq!(copied, cloned);
        assert_ne!(e, RecvError::Cancelled);
    }

    #[test]
    fn modify_error_debug_clone_copy_eq() {
        let e = ModifyError;
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ModifyError"), "{dbg}");
        let copied: ModifyError = e;
        let cloned = e;
        assert_eq!(copied, cloned);
    }

    #[test]
    fn modify_error_display_matches_closed_sender_semantics() {
        init_test("modify_error_display_matches_closed_sender_semantics");
        let text = ModifyError.to_string();
        crate::assert_with_log!(
            text == "modifying a closed watch channel",
            "display",
            "modifying a closed watch channel",
            text
        );
        crate::test_complete!("modify_error_display_matches_closed_sender_semantics");
    }

    // =========================================================================
    // Metamorphic watch channel consistency tests (bead asupersync-8jjrl0)
    // =========================================================================

    /// MR1: borrow_and_update() consistency - returns the most recent send()'d
    /// value regardless of timing. Property: borrow_and_update() always reflects
    /// the latest successful send(), even under concurrent operations.
    #[test]
    fn metamorphic_borrow_and_update_consistency() {
        init_test("metamorphic_borrow_and_update_consistency");
        let _cx = test_cx();
        let (tx, mut rx) = channel(0u64);

        // Initial state - should see the initial value
        {
            let initial = rx.borrow_and_update();
            crate::assert_with_log!(*initial == 0, "initial value", 0u64, *initial);
        }
        crate::assert_with_log!(
            rx.seen_version == 0,
            "initial seen version",
            0u64,
            rx.seen_version
        );

        // Single send - borrow_and_update should see the new value
        tx.send(42).expect("send failed");
        {
            let value1 = rx.borrow_and_update();
            crate::assert_with_log!(*value1 == 42, "after send(42)", 42u64, *value1);
        }
        crate::assert_with_log!(
            rx.seen_version == 1,
            "version after first send",
            1u64,
            rx.seen_version
        );

        // Multiple sends in sequence - should always see the latest
        for i in 1..10 {
            let val = 100 + i;
            tx.send(val).expect("send failed");
            {
                let observed = rx.borrow_and_update();
                crate::assert_with_log!(
                    *observed == val,
                    &format!("sequence send {} value", i),
                    val,
                    *observed
                );
            }
            crate::assert_with_log!(
                rx.seen_version == i + 1,
                &format!("sequence send {} version", i),
                i + 1,
                rx.seen_version
            );
        }

        // Transform: Multiple receivers should independently see latest value
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        // All start at current version (won't see existing values until new send)
        tx.send(999).expect("send failed");

        {
            let val1 = rx.borrow_and_update();
            let val2 = rx2.borrow_and_update();
            let val3 = rx3.borrow_and_update();

            crate::assert_with_log!(*val1 == 999, "rx1 sees latest", 999u64, *val1);
            crate::assert_with_log!(*val2 == 999, "rx2 sees latest", 999u64, *val2);
            crate::assert_with_log!(*val3 == 999, "rx3 sees latest", 999u64, *val3);
        }

        // Transform: borrow vs borrow_and_update consistency
        tx.send(1234).expect("send failed");

        // borrow_and_update should update seen version
        {
            let val_update = rx.borrow_and_update();
            crate::assert_with_log!(
                *val_update == 1234,
                "borrow_and_update value",
                1234u64,
                *val_update
            );
        }

        // Subsequent borrow should see the same value without updating version
        {
            let val_borrow = rx.borrow();
            crate::assert_with_log!(
                *val_borrow == 1234,
                "subsequent borrow value",
                1234u64,
                *val_borrow
            );
        }

        // Version should not have changed from the borrow. The preceding
        // borrow_and_update observed version 12 after the final send(1234).
        let version_after_borrow = rx.seen_version;
        crate::assert_with_log!(
            version_after_borrow == 12,
            "version unchanged by borrow",
            12u64,
            version_after_borrow
        );

        crate::test_complete!("metamorphic_borrow_and_update_consistency");
    }

    /// MR2: Receiver isolation - multiple receivers observing concurrent sends
    /// never see each other's intermediate states. Property: recv1.seen_version
    /// and recv2.seen_version are independent and never interfere.
    #[test]
    fn metamorphic_receiver_isolation() {
        init_test("metamorphic_receiver_isolation");
        let _cx = test_cx();
        let (tx, rx1_base) = channel(0u32);

        // Create multiple independent receivers
        let mut rx1 = rx1_base;
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        // Initial state - all receivers start independently
        let init1 = rx1.seen_version();
        let init2 = rx2.seen_version();
        let init3 = rx3.seen_version();

        crate::assert_with_log!(init1 == 0, "rx1 initial version", 0u64, init1);
        // rx2 and rx3 start at current version since they subscribed later
        crate::assert_with_log!(init2 == init3, "rx2 rx3 same start version", init2, init3);

        // Send a value - all receivers should be able to observe it
        tx.send(100).expect("send failed");

        // Each receiver can independently choose when to observe
        {
            let val1 = rx1.borrow_and_update();
            crate::assert_with_log!(*val1 == 100, "rx1 observes send", 100u32, *val1);
        }
        let _rx1_version = rx1.seen_version();

        // rx2 should still have its old version (hasn't updated yet)
        let rx2_version_before = rx2.seen_version();
        crate::assert_with_log!(
            rx2_version_before == init2,
            "rx2 version independent of rx1",
            init2,
            rx2_version_before
        );

        // rx2 observes independently
        {
            let val2 = rx2.borrow_and_update();
            crate::assert_with_log!(*val2 == 100, "rx2 observes same value", 100u32, *val2);
        }
        let _rx2_version_after = rx2.seen_version();

        // rx3 hasn't observed yet, should still have old version
        let rx3_version_before = rx3.seen_version();
        crate::assert_with_log!(
            rx3_version_before == init3,
            "rx3 version independent of rx1/rx2",
            init3,
            rx3_version_before
        );

        // Transform: Staggered observations with multiple sends
        tx.send(200).expect("send failed");
        tx.send(300).expect("send failed");

        // rx1 observes after multiple sends - should see latest
        {
            let val1_latest = rx1.borrow_and_update();
            crate::assert_with_log!(
                *val1_latest == 300,
                "rx1 sees latest after multiple sends",
                300u32,
                *val1_latest
            );
        }

        // rx3 observes for first time - should also see latest
        {
            let val3_first = rx3.borrow_and_update();
            crate::assert_with_log!(
                *val3_first == 300,
                "rx3 sees latest on first observation",
                300u32,
                *val3_first
            );
        }

        // Versions should be independent but current
        let v1 = rx1.seen_version();
        let v2 = rx2.seen_version();
        let v3 = rx3.seen_version();

        // rx1 and rx3 should have latest version (3 sends total)
        crate::assert_with_log!(v1 == 3, "rx1 latest version", 3u64, v1);
        crate::assert_with_log!(v3 == 3, "rx3 latest version", 3u64, v3);

        // rx2 should still have version from earlier observation
        crate::assert_with_log!(v2 == 1, "rx2 independent version", 1u64, v2);

        // Transform: Independent has_changed() behavior
        tx.send(400).expect("send failed");

        let has_changed1 = rx1.has_changed();
        let has_changed2 = rx2.has_changed();
        let has_changed3 = rx3.has_changed();

        crate::assert_with_log!(has_changed1, "rx1 has changes", true, has_changed1);
        crate::assert_with_log!(has_changed2, "rx2 has changes", true, has_changed2);
        crate::assert_with_log!(has_changed3, "rx3 has changes", true, has_changed3);

        // After one receiver marks seen, others should still see changes
        rx1.mark_seen();
        let has_changed1_after = rx1.has_changed();
        let has_changed2_after = rx2.has_changed();
        let has_changed3_after = rx3.has_changed();

        crate::assert_with_log!(
            !has_changed1_after,
            "rx1 no changes after mark",
            false,
            has_changed1_after
        );
        crate::assert_with_log!(
            has_changed2_after,
            "rx2 still has changes",
            true,
            has_changed2_after
        );
        crate::assert_with_log!(
            has_changed3_after,
            "rx3 still has changes",
            true,
            has_changed3_after
        );

        crate::test_complete!("metamorphic_receiver_isolation");
    }

    #[test]
    fn borrow_and_update_acknowledges_the_snapshot_it_returns() {
        init_test("borrow_and_update_acknowledges_the_snapshot_it_returns");
        let (tx, mut rx) = channel(10u32);

        tx.send(20).expect("send failed");
        let current_version = tx.inner.current_version();
        let snapshot_value = {
            let snapshot = rx.borrow_and_update();
            *snapshot
        };

        crate::assert_with_log!(
            snapshot_value == 20,
            "snapshot value",
            20u32,
            snapshot_value
        );
        crate::assert_with_log!(
            rx.seen_version() == current_version,
            "borrow_and_update aligns seen version",
            current_version,
            rx.seen_version()
        );

        let changed = rx.has_changed();
        crate::assert_with_log!(
            !changed,
            "no unread change after snapshot-aligned ack",
            false,
            changed
        );

        tx.send(30).expect("send failed");
        let changed = rx.has_changed();
        crate::assert_with_log!(changed, "new send becomes visible", true, changed);
        crate::test_complete!("borrow_and_update_acknowledges_the_snapshot_it_returns");
    }

    #[test]
    fn metamorphic_borrow_and_update_clone_matches_explicit_snapshot_clone() {
        init_test("metamorphic_borrow_and_update_clone_matches_explicit_snapshot_clone");
        let (tx, mut rx_explicit) = channel(1u32);
        let mut rx_clone = tx.subscribe();

        tx.send(10).expect("send failed");
        tx.send(20).expect("send failed");

        let current_version = tx.inner.current_version();
        let explicit_value = {
            let snapshot = rx_explicit.borrow_and_update();
            snapshot.clone_inner()
        };
        let clone_value = rx_clone.borrow_and_update_clone();

        crate::assert_with_log!(
            explicit_value == clone_value,
            "clone helper matches explicit snapshot clone",
            explicit_value,
            clone_value
        );
        crate::assert_with_log!(
            explicit_value == 20,
            "both paths observe latest unread value",
            20u32,
            explicit_value
        );
        crate::assert_with_log!(
            rx_explicit.seen_version() == current_version,
            "explicit path acknowledges current version",
            current_version,
            rx_explicit.seen_version()
        );
        crate::assert_with_log!(
            rx_clone.seen_version() == current_version,
            "clone helper acknowledges current version",
            current_version,
            rx_clone.seen_version()
        );

        let explicit_changed = rx_explicit.has_changed();
        let clone_changed = rx_clone.has_changed();
        crate::assert_with_log!(
            !explicit_changed,
            "explicit path has no duplicate change after acknowledgement",
            false,
            explicit_changed
        );
        crate::assert_with_log!(
            !clone_changed,
            "clone helper has no duplicate change after acknowledgement",
            false,
            clone_changed
        );

        tx.send(30).expect("send failed");

        let explicit_next = {
            let snapshot = rx_explicit.borrow_and_update();
            snapshot.clone_inner()
        };
        let clone_next = rx_clone.borrow_and_update_clone();
        let next_version = tx.inner.current_version();

        crate::assert_with_log!(
            explicit_next == clone_next,
            "next send remains aligned across both acknowledgement paths",
            explicit_next,
            clone_next
        );
        crate::assert_with_log!(
            explicit_next == 30,
            "next send value observed by both paths",
            30u32,
            explicit_next
        );
        crate::assert_with_log!(
            rx_explicit.seen_version() == next_version,
            "explicit path advances on next send",
            next_version,
            rx_explicit.seen_version()
        );
        crate::assert_with_log!(
            rx_clone.seen_version() == next_version,
            "clone helper advances on next send",
            next_version,
            rx_clone.seen_version()
        );

        crate::test_complete!(
            "metamorphic_borrow_and_update_clone_matches_explicit_snapshot_clone"
        );
    }

    #[test]
    fn mark_seen_acknowledges_latest_version_not_prior_borrow_snapshot() {
        init_test("mark_seen_acknowledges_latest_version_not_prior_borrow_snapshot");
        let (tx, mut rx) = channel(1u32);

        tx.send(2).expect("send failed");
        let borrowed_snapshot = rx.borrow().clone_inner();
        crate::assert_with_log!(
            borrowed_snapshot == 2,
            "borrowed snapshot before later send",
            2u32,
            borrowed_snapshot
        );

        tx.send(3).expect("send failed");
        rx.mark_seen();

        let seen_version = rx.seen_version();
        let current_version = tx.inner.current_version();
        crate::assert_with_log!(
            seen_version == current_version,
            "mark_seen advances to current version",
            current_version,
            seen_version
        );

        let changed = rx.has_changed();
        crate::assert_with_log!(
            !changed,
            "mark_seen cleared both pending versions",
            false,
            changed
        );

        let latest = *rx.borrow();
        crate::assert_with_log!(
            latest == 3,
            "latest borrow reflects post-mark version",
            3u32,
            latest
        );
        crate::test_complete!("mark_seen_acknowledges_latest_version_not_prior_borrow_snapshot");
    }

    #[test]
    fn metamorphic_subscription_snapshot_ordering() {
        init_test("metamorphic_subscription_snapshot_ordering");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0u32);

        tx.send(10).expect("send failed");
        let rx1_snapshot = rx1.borrow().clone_inner();
        crate::assert_with_log!(
            rx1_snapshot == 10,
            "existing receiver sees first value via borrow",
            10u32,
            rx1_snapshot
        );

        let mut rx2 = tx.subscribe();
        crate::assert_with_log!(
            *rx2.borrow() == 10,
            "new subscriber borrows current snapshot immediately",
            10u32,
            *rx2.borrow()
        );
        crate::assert_with_log!(
            !rx2.has_changed(),
            "new subscriber starts caught up to current version",
            false,
            rx2.has_changed()
        );

        tx.send(20).expect("send failed");
        tx.send(30).expect("send failed");

        let mut rx2_changed = rx2.changed(&cx);
        let rx2_change = poll_ready(&mut rx2_changed);
        drop(rx2_changed);
        crate::assert_with_log!(
            rx2_change.is_ok(),
            "subscriber observes burst as a single pending change",
            true,
            rx2_change.is_ok()
        );
        crate::assert_with_log!(
            *rx2.borrow() == 30,
            "subscriber lands on latest burst value",
            30u32,
            *rx2.borrow()
        );

        let rx1_latest = {
            let snapshot = rx1.borrow_and_update();
            *snapshot
        };
        crate::assert_with_log!(
            rx1_latest == 30,
            "older receiver also lands on latest burst value",
            30u32,
            rx1_latest
        );
        crate::assert_with_log!(
            !rx1.has_changed(),
            "borrow_and_update fully acknowledges latest snapshot",
            false,
            rx1.has_changed()
        );

        let mut rx2_pending = rx2.changed(&cx);
        let pending_waker = Waker::noop();
        let mut pending_cx = Context::from_waker(pending_waker);
        let pending_poll = Pin::new(&mut rx2_pending).poll(&mut pending_cx);
        crate::assert_with_log!(
            matches!(pending_poll, Poll::Pending),
            "subscriber receives no duplicate notification after acknowledging burst",
            true,
            matches!(pending_poll, Poll::Pending)
        );
        drop(rx2_pending);

        tx.send(40).expect("send failed");
        crate::assert_with_log!(
            rx1.has_changed(),
            "next send is visible to older receiver after prior acknowledgement",
            true,
            rx1.has_changed()
        );
        crate::assert_with_log!(
            rx2.has_changed(),
            "next send is visible to subscriber after prior acknowledgement",
            true,
            rx2.has_changed()
        );

        crate::test_complete!("metamorphic_subscription_snapshot_ordering");
    }

    /// MR3: changed() exactness - returns Ok(()) exactly once per distinct send,
    /// never stutters. Property: count(changed() == Ok(())) == count(distinct sends)
    #[test]
    fn metamorphic_changed_exactness() {
        init_test("metamorphic_changed_exactness");
        let cx = test_cx();
        let (tx, mut rx) = channel(0i32);

        // Helper to poll a changed future to completion
        let poll_changed = |rx: &mut Receiver<i32>| -> Result<(), RecvError> {
            let mut future = rx.changed(&cx);
            poll_ready(&mut future)
        };

        // Initial state - no changes yet, should wait
        let initial_version = rx.seen_version();
        crate::assert_with_log!(
            initial_version == 0,
            "initial version",
            0u64,
            initial_version
        );

        // First send - changed() should return exactly once
        tx.send(1).expect("send failed");

        let change1 = poll_changed(&mut rx);
        crate::assert_with_log!(
            change1.is_ok(),
            "first changed() succeeds",
            true,
            change1.is_ok()
        );

        // Calling changed() again without a new send should block (no stutter)
        // We can't easily test blocking in a unit test, but we can verify the version is updated
        let version_after_change = rx.seen_version();
        crate::assert_with_log!(
            version_after_change == 1,
            "version updated after changed()",
            1u64,
            version_after_change
        );
        crate::assert_with_log!(
            !rx.has_changed(),
            "no changes after changed()",
            false,
            rx.has_changed()
        );

        // Multiple sends - each should trigger exactly one changed() notification
        let mut change_count = 1; // Already counted the first change
        for i in 2..=5 {
            tx.send(i).expect("send failed");

            let change = poll_changed(&mut rx);
            crate::assert_with_log!(
                change.is_ok(),
                &format!("changed() {} succeeds", i),
                true,
                change.is_ok()
            );
            change_count += 1;

            let version = rx.seen_version();
            crate::assert_with_log!(
                version == i as u64,
                &format!("version {} after send {}", i, i),
                i as u64,
                version
            );
        }

        crate::assert_with_log!(
            change_count == 5,
            "exactly 5 changes for 5 sends",
            5,
            change_count
        );

        // Transform: Rapid sends coalesce into a single observable change.
        for i in 10..15 {
            tx.send(i).expect("send failed");
        }

        let rapid_change = poll_changed(&mut rx);
        crate::assert_with_log!(
            rapid_change.is_ok(),
            "coalesced rapid burst detected",
            true,
            rapid_change.is_ok()
        );

        let final_version = rx.seen_version();
        crate::assert_with_log!(
            final_version == 10,
            "rapid burst advances to latest version",
            10u64,
            final_version
        );
        crate::assert_with_log!(
            *rx.borrow() == 14,
            "rapid burst exposes latest value",
            14i32,
            *rx.borrow()
        );

        let mut pending_after_burst = rx.changed(&cx);
        let burst_waker = Waker::noop();
        let mut burst_cx = Context::from_waker(burst_waker);
        let burst_poll = Pin::new(&mut pending_after_burst).poll(&mut burst_cx);
        crate::assert_with_log!(
            matches!(burst_poll, Poll::Pending),
            "no second notification after coalesced burst",
            true,
            matches!(burst_poll, Poll::Pending)
        );
        drop(pending_after_burst);

        // Transform: Same-value sends still bump the version, but they also
        // coalesce when observed after the burst.
        tx.send(999).expect("send failed");
        tx.send(999).expect("send failed"); // Same value
        tx.send(999).expect("send failed"); // Same value again

        let duplicate_burst = poll_changed(&mut rx);
        crate::assert_with_log!(
            duplicate_burst.is_ok(),
            "duplicate-value burst detected",
            true,
            duplicate_burst.is_ok()
        );
        crate::assert_with_log!(
            rx.seen_version() == 13,
            "duplicate sends still advance version",
            13u64,
            rx.seen_version()
        );

        let mut pending_after_duplicates = rx.changed(&cx);
        let duplicate_waker = Waker::noop();
        let mut duplicate_cx = Context::from_waker(duplicate_waker);
        let duplicate_poll = Pin::new(&mut pending_after_duplicates).poll(&mut duplicate_cx);
        crate::assert_with_log!(
            matches!(duplicate_poll, Poll::Pending),
            "duplicate burst also coalesces to one notification",
            true,
            matches!(duplicate_poll, Poll::Pending)
        );
        drop(pending_after_duplicates);

        let final_value = rx.borrow_and_update();
        crate::assert_with_log!(
            *final_value == 999,
            "final value correct",
            999i32,
            *final_value
        );

        crate::test_complete!("metamorphic_changed_exactness");
    }

    /// MR4: Closed sender behavior - closed sender causes all waiting changed()
    /// calls to return Err(Closed). Property: Drop(sender) → All waiting changed() → Err(Closed)
    #[test]
    fn metamorphic_closed_sender_behavior() {
        init_test("metamorphic_closed_sender_behavior");
        let cx = test_cx();
        let (tx, mut rx1) = channel(0u8);

        // Create multiple receivers
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        // Initial state - all receivers should see open channel
        crate::assert_with_log!(
            !rx1.is_closed(),
            "rx1 initially open",
            false,
            rx1.is_closed()
        );
        crate::assert_with_log!(
            !rx2.is_closed(),
            "rx2 initially open",
            false,
            rx2.is_closed()
        );
        crate::assert_with_log!(
            !rx3.is_closed(),
            "rx3 initially open",
            false,
            rx3.is_closed()
        );

        // Send initial value so receivers have something to observe
        tx.send(42).expect("send failed");

        // All receivers should be able to observe the value
        {
            let val1 = rx1.borrow_and_update();
            let val2 = rx2.borrow_and_update();
            let val3 = rx3.borrow_and_update();

            crate::assert_with_log!(*val1 == 42, "rx1 sees value", 42u8, *val1);
            crate::assert_with_log!(*val2 == 42, "rx2 sees value", 42u8, *val2);
            crate::assert_with_log!(*val3 == 42, "rx3 sees value", 42u8, *val3);
        }

        // Drop the sender
        drop(tx);

        // All receivers should now see the channel as closed
        crate::assert_with_log!(
            rx1.is_closed(),
            "rx1 closed after drop",
            true,
            rx1.is_closed()
        );
        crate::assert_with_log!(
            rx2.is_closed(),
            "rx2 closed after drop",
            true,
            rx2.is_closed()
        );
        crate::assert_with_log!(
            rx3.is_closed(),
            "rx3 closed after drop",
            true,
            rx3.is_closed()
        );

        // Any attempt to wait for changes should return Closed error
        let mut future1 = rx1.changed(&cx);
        let result1 = poll_ready(&mut future1);
        drop(future1);
        crate::assert_with_log!(
            matches!(result1, Err(RecvError::Closed)),
            "rx1 changed() returns Closed",
            true,
            matches!(result1, Err(RecvError::Closed))
        );

        let mut future2 = rx2.changed(&cx);
        let result2 = poll_ready(&mut future2);
        drop(future2);
        crate::assert_with_log!(
            matches!(result2, Err(RecvError::Closed)),
            "rx2 changed() returns Closed",
            true,
            matches!(result2, Err(RecvError::Closed))
        );

        let mut future3 = rx3.changed(&cx);
        let result3 = poll_ready(&mut future3);
        drop(future3);
        crate::assert_with_log!(
            matches!(result3, Err(RecvError::Closed)),
            "rx3 changed() returns Closed",
            true,
            matches!(result3, Err(RecvError::Closed))
        );

        // Transform: Values should still be readable even after close
        {
            let final1 = rx1.borrow();
            let final2 = rx2.borrow();
            let final3 = rx3.borrow();

            crate::assert_with_log!(*final1 == 42, "rx1 final value readable", 42u8, *final1);
            crate::assert_with_log!(*final2 == 42, "rx2 final value readable", 42u8, *final2);
            crate::assert_with_log!(*final3 == 42, "rx3 final value readable", 42u8, *final3);
        }

        // Transform: Test closed behavior during concurrent operations
        // Create a new channel to test dropping sender while receivers are actively waiting
        let (tx2, mut rx4) = channel(100i32);
        let mut rx5 = tx2.subscribe();

        // Send a value so receivers can observe it
        tx2.send(200).expect("send failed");

        // rx4 observes but rx5 doesn't
        {
            let val4 = rx4.borrow_and_update();
            crate::assert_with_log!(*val4 == 200, "rx4 initial value", 200i32, *val4);
        }

        // rx5 should have changes pending
        crate::assert_with_log!(
            rx5.has_changed(),
            "rx5 has pending changes",
            true,
            rx5.has_changed()
        );

        // Drop sender
        drop(tx2);

        // rx5 still has one unseen value. Close must surface that final update
        // before returning Closed on the next wait.
        let mut future5 = rx5.changed(&cx);
        let result5 = poll_ready(&mut future5);
        drop(future5);
        crate::assert_with_log!(
            matches!(result5, Ok(())),
            "rx5 receives final unseen update before Closed",
            true,
            matches!(result5, Ok(()))
        );

        let mut future5_closed = rx5.changed(&cx);
        let result5_closed = poll_ready(&mut future5_closed);
        drop(future5_closed);
        crate::assert_with_log!(
            matches!(result5_closed, Err(RecvError::Closed)),
            "rx5 returns Closed after draining final value",
            true,
            matches!(result5_closed, Err(RecvError::Closed))
        );

        // But rx5 should still be able to read the last value
        {
            let final5 = rx5.borrow();
            crate::assert_with_log!(
                *final5 == 200,
                "rx5 can still read last value",
                200i32,
                *final5
            );
        }

        crate::test_complete!("metamorphic_closed_sender_behavior");
    }

    // =========================================================================
    // Metamorphic tests for borrow_and_update after sender shutdown
    // =========================================================================

    /// MR1: Equivalence - borrow_and_update() after shutdown returns same value
    /// Property: f(shutdown_then_borrow1) = f(shutdown_then_borrow2)
    /// Detects: value corruption, inconsistent final state retention
    #[test]
    fn mr_borrow_and_update_equivalence_after_shutdown() {
        init_test("mr_borrow_and_update_equivalence_after_shutdown");
        let (tx, mut rx) = channel(42u32);

        // Send final value then shutdown
        tx.send(100).expect("send failed");
        let final_value = 100u32;
        drop(tx); // Shutdown

        // Multiple calls should return equivalent values
        let value1 = *rx.borrow_and_update();
        let value2 = *rx.borrow_and_update();
        let value3 = *rx.borrow_and_update();

        crate::assert_with_log!(
            value1 == final_value && value2 == final_value && value3 == final_value,
            "equivalent values after shutdown",
            (final_value, final_value, final_value),
            (value1, value2, value3)
        );

        crate::assert_with_log!(
            value1 == value2 && value2 == value3,
            "all calls return same value",
            value1,
            (value2, value3)
        );

        crate::test_complete!("mr_borrow_and_update_equivalence_after_shutdown");
    }

    /// MR2: Additive Version Monotonicity
    /// Property: seen_version never decreases, even after shutdown
    /// Transformation: multiple borrow_and_update calls
    /// Relation: version(call_n+1) >= version(call_n)
    #[test]
    fn mr_version_monotonicity_after_shutdown() {
        init_test("mr_version_monotonicity_after_shutdown");
        let (tx, mut rx) = channel(0u32);

        tx.send(1).expect("send failed");
        tx.send(2).expect("send failed");
        let version_before_drop = tx.inner.current_version();
        drop(tx); // Shutdown

        let mut versions = Vec::new();

        // Multiple calls to collect version progression
        for i in 0..5 {
            let _value = rx.borrow_and_update();
            drop(_value);
            let version = rx.seen_version();
            versions.push(version);

            if i > 0 {
                crate::assert_with_log!(
                    version >= versions[i - 1],
                    &format!("version monotonic at call {}", i),
                    versions[i - 1],
                    version
                );
            }
        }

        // Final version should match the version before drop
        let final_version = versions.last().copied().unwrap();
        crate::assert_with_log!(
            final_version == version_before_drop,
            "final version matches pre-drop version",
            version_before_drop,
            final_version
        );

        crate::test_complete!("mr_version_monotonicity_after_shutdown");
    }

    /// MR3: Permutative - Receiver Isolation
    /// Property: Multiple receivers calling borrow_and_update after shutdown
    /// should not interfere with each other
    /// Transformation: permute order of receiver operations
    /// Relation: results should be independent of order
    #[test]
    fn mr_receiver_isolation_after_shutdown() {
        init_test("mr_receiver_isolation_after_shutdown");
        let (tx, mut rx1) = channel(10u32);
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();

        tx.send(200).expect("send failed");
        drop(tx); // Shutdown

        // Test permutation 1: rx1 -> rx2 -> rx3
        let value1a = *rx1.borrow_and_update();
        let version1a = rx1.seen_version();
        let value2a = *rx2.borrow_and_update();
        let version2a = rx2.seen_version();
        let value3a = *rx3.borrow_and_update();
        let version3a = rx3.seen_version();

        // Reset for permutation 2
        let (tx, mut rx1) = channel(10u32);
        let mut rx2 = tx.subscribe();
        let mut rx3 = tx.subscribe();
        tx.send(200).expect("send failed");
        drop(tx);

        // Test permutation 2: rx3 -> rx1 -> rx2
        let value3b = *rx3.borrow_and_update();
        let version3b = rx3.seen_version();
        let value1b = *rx1.borrow_and_update();
        let version1b = rx1.seen_version();
        let value2b = *rx2.borrow_and_update();
        let version2b = rx2.seen_version();

        // Values should be equivalent regardless of order
        crate::assert_with_log!(
            (value1a, value2a, value3a) == (value1b, value2b, value3b),
            "values independent of call order",
            (value1a, value2a, value3a),
            (value1b, value2b, value3b)
        );

        // Versions should be equivalent regardless of order
        crate::assert_with_log!(
            (version1a, version2a, version3a) == (version1b, version2b, version3b),
            "versions independent of call order",
            (version1a, version2a, version3a),
            (version1b, version2b, version3b)
        );

        crate::test_complete!("mr_receiver_isolation_after_shutdown");
    }

    /// MR4: Equivalence - State Consistency
    /// Property: borrow_and_update() and borrow() return same value after shutdown
    /// Transformation: method substitution
    /// Relation: f(borrow_and_update) value == f(borrow) value
    #[test]
    fn mr_state_consistency_borrow_vs_borrow_and_update_after_shutdown() {
        init_test("mr_state_consistency_borrow_vs_borrow_and_update_after_shutdown");
        let (tx, mut rx1) = channel(5u32);
        let rx2 = tx.subscribe();

        tx.send(300).expect("send failed");
        drop(tx); // Shutdown

        // One receiver uses borrow_and_update
        let value_update = *rx1.borrow_and_update();

        // Other receiver uses borrow
        let value_borrow = *rx2.borrow();

        crate::assert_with_log!(
            value_update == value_borrow,
            "borrow_and_update and borrow return same value after shutdown",
            value_update,
            value_borrow
        );

        // Both should see the same final value
        crate::assert_with_log!(
            value_update == 300 && value_borrow == 300,
            "both see final sent value",
            300u32,
            (value_update, value_borrow)
        );

        crate::test_complete!("mr_state_consistency_borrow_vs_borrow_and_update_after_shutdown");
    }

    /// Regression test for deadlock prevention in send_modify.
    ///
    /// This test verifies that user closures in send_modify cannot cause deadlocks
    /// by trying to access watch channels while the closure runs. The old implementation
    /// would deadlock because the closure ran while holding the write lock.
    #[test]
    fn send_modify_deadlock_prevention() {
        init_test("send_modify_deadlock_prevention");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        let (_tx1, rx1) = channel(0u32);
        let (tx2, rx2) = channel(String::from("initial"));

        // Create a scenario where send_modify closure tries to read from another watch channel.
        // This would deadlock in the old implementation but should work in the new one.
        let (task_id, _task_handle) = runtime
            .state
            .create_task(region, crate::types::Budget::INFINITE, async move {
                // This closure reads from rx1 while send_modify holds a lock on tx2's value.
                // In the old implementation, this would deadlock if rx1's read attempted
                // to acquire any locks that send_modify was holding.
                let result = tx2.send_modify(|s| {
                    // Try to read from another watch channel inside the closure
                    let current_value = *rx1.borrow();
                    *s = format!("modified_with_{}", current_value);
                });

                result.map_err(|_| {
                    crate::error::Error::cancelled(&crate::types::CancelReason::default())
                })
            })
            .unwrap();

        // Schedule and run the task
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // Verify the modification worked correctly
        let final_value = rx2.borrow();
        crate::assert_with_log!(
            *final_value == "modified_with_0",
            "send_modify closure executed without deadlock",
            "modified_with_0",
            &*final_value
        );

        // If we reach this point without hanging, the deadlock was avoided

        crate::test_complete!("send_modify_deadlock_prevention");
    }

    /// Audit test for concurrent send + borrow_and_update behavior.
    ///
    /// Verifies that when sender does watch.send(v) while receiver is mid-borrow_and_update(),
    /// the receiver observes a consistent value/version pair and no values are "lost".
    /// Per spec, borrow_and_update returns LATEST sent value, but no values may be lost
    /// between markings.
    #[test]
    fn audit_concurrent_send_during_borrow_and_update() {
        init_test("audit_concurrent_send_during_borrow_and_update");

        let (tx, mut rx) = channel::<u32>(0);

        // Test 1: Verify atomic read of value/version pair
        // Send a value, then verify borrow_and_update gets consistent pair
        tx.send(42).unwrap();

        let borrowed = rx.borrow_and_update();
        let observed_value = *borrowed;
        drop(borrowed);

        assert_eq!(
            observed_value, 42,
            "borrow_and_update should observe sent value"
        );
        assert_eq!(
            rx.seen_version, 1,
            "seen_version should be updated to version of observed value"
        );

        // Test 2: Multiple rapid sends - verify no values are "lost" from receiver's perspective
        // Send sequence: 100, 200, 300 rapidly
        tx.send(100).unwrap();
        tx.send(200).unwrap();
        tx.send(300).unwrap();

        // borrow_and_update should see the LATEST value (300)
        let latest = *rx.borrow_and_update();
        assert_eq!(
            latest, 300,
            "borrow_and_update should see latest value after rapid sends"
        );

        // Test 3: Verify version consistency during concurrent access
        // This tests the key race condition scenario
        tx.send(500).unwrap();

        // Start borrow_and_update, which will:
        // 1. Acquire read lock
        // 2. Read value (500) and version (4)
        // 3. Update seen_version to 4
        // 4. Return reference to value 500
        let concurrent_borrow = rx.borrow_and_update();
        let concurrent_value = *concurrent_borrow;
        drop(concurrent_borrow);

        // After borrow_and_update completes, send another value
        tx.send(600).unwrap();

        // The receiver should have marked version 4 as seen (when it observed 500)
        assert_eq!(
            concurrent_value, 500,
            "concurrent borrow should see consistent value"
        );

        // Now check if receiver correctly identifies new changes
        assert!(
            rx.has_changed(),
            "receiver should detect new value after marking previous as seen"
        );

        // Test 4: Verify that rapid sends don't cause version skipping
        let initial_version = rx.seen_version;

        // Send 3 more values rapidly
        tx.send(700).unwrap(); // version 6
        tx.send(800).unwrap(); // version 7
        tx.send(900).unwrap(); // version 8

        // borrow_and_update should see version 8 with value 900
        let final_value = *rx.borrow_and_update();
        assert_eq!(
            final_value, 900,
            "should see final value after rapid sequence"
        );
        assert!(
            rx.seen_version > initial_version,
            "seen_version should advance"
        );

        // Test 5: Value loss verification - ensure intermediate values aren't "lost"
        // in the sense that they can't be observed
        let (tx2, mut rx2) = channel::<String>("initial".to_string());

        // Send sequence where each value builds on the previous
        tx2.send("step1".to_string()).unwrap();
        tx2.send("step2".to_string()).unwrap();
        tx2.send("step3".to_string()).unwrap();

        // borrow_and_update should see the latest consistent state
        let final_state = rx2.borrow_and_update();
        assert_eq!(
            *final_state, "step3",
            "should observe latest consistent state"
        );
        drop(final_state);

        // No more changes should be detectable
        assert!(
            !rx2.has_changed(),
            "no changes should remain after observing latest"
        );

        crate::test_complete!("audit_concurrent_send_during_borrow_and_update");
    }

    /// Audit test for concurrent receiver count tracking.
    ///
    /// Verifies that when N receivers exist and one is dropped concurrently,
    /// receiver_count() decrements immediately (correct) rather than lazily (incorrect).
    /// Per asupersync cancel-aware semantics, resource counts must reflect reality immediately.
    #[test]
    fn audit_receiver_count_immediate_decrement() {
        init_test("audit_receiver_count_immediate_decrement");

        let (tx, rx1) = channel::<u32>(0);

        // Create multiple receivers concurrently
        let rx2 = rx1.clone();
        let rx3 = tx.subscribe();
        let rx4 = tx.subscribe();

        // Verify initial count
        assert_eq!(tx.receiver_count(), 4, "initial receiver count");

        // Test concurrent drops with immediate count checks
        std::thread::scope(|s| {
            let tx_ref = &tx;

            // Spawn threads that drop receivers and immediately check counts
            let handle1 = s.spawn(|| {
                drop(rx2);
                // Count should be decremented immediately due to Drop impl
                // using fetch_sub with Release ordering
                tx_ref.receiver_count()
            });

            let handle2 = s.spawn(|| {
                drop(rx3);
                tx_ref.receiver_count()
            });

            // Drop one receiver in main thread
            drop(rx4);
            let main_count = tx.receiver_count();

            // Collect results from other threads
            let count1 = handle1.join().unwrap();
            let count2 = handle2.join().unwrap();

            // At least one thread should see the decrement
            // All observed counts should be <= 3 (less than initial 4)
            assert!(count1 <= 3, "thread1 saw decremented count: {}", count1);
            assert!(count2 <= 3, "thread2 saw decremented count: {}", count2);
            assert!(
                main_count <= 3,
                "main thread saw decremented count: {}",
                main_count
            );

            // Final count check - only rx1 should remain
            let final_count = tx.receiver_count();
            assert_eq!(final_count, 1, "final count after concurrent drops");
        });

        // Verify rx1 is still functional
        tx.send(42).unwrap();
        let value = *rx1.borrow();
        assert_eq!(value, 42, "remaining receiver still functional");

        // Drop last receiver
        drop(rx1);
        assert_eq!(
            tx.receiver_count(),
            0,
            "count zero after dropping all receivers"
        );

        crate::test_complete!("audit_receiver_count_immediate_decrement");
    }

    /// Audit test for watch channel lagging-receiver behavior.
    ///
    /// Verifies that slow receivers do NOT cause memory leaks via unbounded buffering.
    /// Per asupersync semantics, watch channels keep only the LATEST value - intermediate
    /// values are lost forever when a receiver lags behind the sender. This is by design
    /// and prevents memory exhaustion from slow consumers.
    #[test]
    fn audit_watch_no_buffering_latest_only() {
        init_test("audit_watch_no_buffering_latest_only");
        let cx = test_cx();
        let (tx, mut rx) = channel(0u32);

        // Receiver starts at version 0, value 0
        let initial_version = rx.seen_version;
        crate::assert_with_log!(
            initial_version == 0,
            "receiver starts at initial version",
            0,
            initial_version
        );
        crate::assert_with_log!(
            *rx.borrow() == 0,
            "receiver sees initial value",
            0,
            *rx.borrow()
        );

        // Send multiple rapid updates: 1, 2, 3, 4, 5
        // Receiver does NOT call changed() between these sends
        for i in 1..=5 {
            tx.send(i).expect("send should succeed");
        }

        // Receiver can only see the LATEST value (5), not intermediate values (1,2,3,4)
        let current_value = *rx.borrow();
        crate::assert_with_log!(
            current_value == 5,
            "receiver sees only latest value, intermediate values lost",
            5,
            current_value
        );

        // Calling changed() once should see the jump from version 0 to 5
        let changed_result = block_on(rx.changed(&cx));
        crate::assert_with_log!(
            changed_result.is_ok(),
            "changed() succeeds for version jump",
            true,
            changed_result.is_ok()
        );
        crate::assert_with_log!(
            rx.seen_version == 5,
            "receiver version jumps directly to latest",
            5,
            rx.seen_version
        );
        crate::assert_with_log!(
            *rx.borrow() == 5,
            "receiver sees latest value after changed",
            5,
            *rx.borrow()
        );

        // Verify memory efficiency: no matter how many values sent,
        // watch channel uses O(1) memory (just the latest value + version)
        for i in 6..=1000 {
            tx.send(i).expect("send should succeed");
        }

        // After 1000 sends, receiver can still only see the latest value
        let final_value = *rx.borrow();
        crate::assert_with_log!(
            final_value == 1000,
            "receiver sees latest of many rapid updates",
            1000,
            final_value
        );

        // One changed() call jumps directly from version 5 to 1000
        let changed_result = block_on(rx.changed(&cx));
        crate::assert_with_log!(
            changed_result.is_ok(),
            "changed() succeeds for large version jump",
            true,
            changed_result.is_ok()
        );
        crate::assert_with_log!(
            rx.seen_version == 1000,
            "receiver version jumps directly to 1000",
            1000,
            rx.seen_version
        );

        crate::test_complete!("audit_watch_no_buffering_latest_only");
    }

    /// Audit test: Sender::send_modify() panic safety semantics.
    ///
    /// Per asupersync spec, there should be no Mutex-style poisoning.
    /// When the modifier closure panics, the Sender must remain usable
    /// and the channel state must be unchanged (panic-safe).
    #[test]
    fn audit_send_modify_panic_safe_semantics() {
        init_test("audit_send_modify_panic_safe_semantics");

        let (tx, mut rx) = channel(42);

        // Phase 1: Verify initial state
        crate::assert_with_log!(*rx.borrow() == 42, "initial value is 42", 42, *rx.borrow());

        // Phase 2: Test successful modify (baseline)
        let modify_result = tx.send_modify(|x| *x += 1);
        crate::assert_with_log!(
            modify_result.is_ok(),
            "successful modify returns Ok",
            true,
            modify_result.is_ok()
        );

        crate::assert_with_log!(
            *rx.borrow() == 43,
            "value updated to 43 after successful modify",
            43,
            *rx.borrow()
        );

        // Phase 3: Test panic during modify (critical test)
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tx.send_modify(|x| {
                *x = 999; // This change should NOT be committed due to panic
                panic!("intentional panic during modify");
            })
        }));

        // Verify the panic was caught
        crate::assert_with_log!(
            panic_result.is_err(),
            "modify closure panic was caught",
            true,
            panic_result.is_err()
        );

        // CRITICAL: Verify panic-safe behavior
        crate::assert_with_log!(
            *rx.borrow() == 43,
            "value unchanged after panic (panic-safe)",
            43,
            *rx.borrow()
        );

        // Phase 4: Test Sender usability after panic (critical test)
        let post_panic_result = tx.send_modify(|x| *x += 10);
        crate::assert_with_log!(
            post_panic_result.is_ok(),
            "Sender remains usable after panic (no poisoning)",
            true,
            post_panic_result.is_ok()
        );

        crate::assert_with_log!(
            *rx.borrow() == 53,
            "value updated to 53 after post-panic modify",
            53,
            *rx.borrow()
        );

        // Phase 5: Test multiple panic recovery cycles
        for i in 1..=3 {
            // Panic
            let _panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tx.send_modify(|_x| panic!("panic cycle {}", i))
            }));

            // Verify still works
            let recovery_result = tx.send_modify(|x| *x += 1);
            crate::assert_with_log!(
                recovery_result.is_ok(),
                &format!("Sender recovers after panic cycle {}", i),
                true,
                recovery_result.is_ok()
            );
        }

        let final_value = *rx.borrow();
        crate::assert_with_log!(
            final_value == 56, // 53 + 3 increments
            "final value correct after multiple panic cycles",
            56,
            final_value
        );

        // Phase 6: Test receiver still works normally
        let cx = test_cx();
        let changed_future = rx.changed(&cx);
        tx.send_modify(|x| *x = 100)
            .expect("final modify should work");

        // Verify change notification works
        poll_ready(&mut Box::pin(changed_future))
            .expect("changed future should observe the final send_modify");
        crate::assert_with_log!(
            *rx.borrow() == 100,
            "receiver notifications work after panic recovery",
            100,
            *rx.borrow()
        );

        crate::test_complete!("audit_send_modify_panic_safe_semantics");
    }
}
