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

use super::cancel_registration::CancelRegistration;
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
            Self::Cancelled => write!(f, "[ASUP-E203] receive operation cancelled"),
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
    /// Serializes writers (`send` / `send_modify`) so a read-modify-write in
    /// `send_modify` cannot be annihilated by a concurrent write (lost update).
    ///
    /// This is held across the whole clone -> closure -> writeback of
    /// `send_modify` and across the atomic write of `send`, but the value
    /// `RwLock` is deliberately NOT held while the user closure runs. That
    /// keeps the no-reentrancy-deadlock / no-reader-stall contract
    /// (`send_modify_deadlock_prevention`) intact while still making concurrent
    /// writers mutually exclusive. Lock order is always `send_lock` -> `value`;
    /// nothing takes `value` before `send_lock`, so no deadlock is introduced.
    send_lock: Mutex<()>,
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
            send_lock: Mutex::new(()),
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

    #[inline]
    fn receiver_count_snapshot(&self) -> usize {
        // Telemetry and public count APIs report an observational counter only;
        // value/version state remains protected by `value`.
        self.receiver_count.load(Ordering::Relaxed)
    }

    #[inline]
    fn has_receivers_snapshot(&self) -> bool {
        self.receiver_count_snapshot() != 0
    }

    fn current_version(&self) -> u64 {
        // Recursive: the caller may already hold a `Ref`. The lock is fair, so
        // a plain read queues behind a waiting writer that is itself waiting
        // for that `Ref`, and both threads deadlock.
        self.value.read_recursive().1
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
        let receiver_count = self.receiver_count_snapshot();
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
        wake_waiters(waiters);
    }

    fn register_waker(&self, waiter: WatchWaiter) {
        let mut incoming = Some(waiter);
        let mut retired = SmallVec::<[WatchWaiter; 4]>::new();
        {
            let mut waiters = self.waiters.lock();
            // Single pass: prune stale entries and update an existing waiter.
            // Removed and replaced Wakers are carried beyond the mutex before
            // destruction because a safe Waker payload may re-enter this channel.
            let mut found = false;
            let mut index = 0;
            while index < waiters.len() {
                if Arc::strong_count(&waiters[index].queued) <= 1 {
                    retired.push(waiters.remove(index));
                    continue;
                }

                let incoming = incoming
                    .as_mut()
                    .expect("incoming watch waiter remains available until registration");
                let entry = &mut waiters[index];
                if !found && Arc::ptr_eq(&entry.queued, &incoming.queued) {
                    if !entry.waker.will_wake(&incoming.waker) {
                        std::mem::swap(&mut entry.waker, &mut incoming.waker);
                    }
                    found = true;
                }
                index += 1;
            }
            if !found {
                waiters.push(
                    incoming
                        .take()
                        .expect("unregistered watch waiter remains available"),
                );
            }
        }
        drop(retired);
        drop(incoming);
    }

    /// Update the waker for an already-queued waiter.
    ///
    /// `new_waker` is owned so its clone is completed before the waiter mutex is
    /// acquired. Any replaced, stale, or unused Waker is destroyed only after
    /// the mutex has been released.
    /// Returns `true` if the waiter was found and refreshed, `false` if not found
    /// (caller should fall back to `register_waker` with a new `WatchWaiter`).
    fn refresh_waker(&self, queued: &Arc<AtomicBool>, new_waker: Waker) -> bool {
        let mut incoming = Some(new_waker);
        let mut retired = SmallVec::<[WatchWaiter; 4]>::new();
        let found = {
            let mut waiters = self.waiters.lock();
            // Single pass: prune stale entries and refresh the target.
            let mut found = false;
            let mut index = 0;
            while index < waiters.len() {
                if Arc::strong_count(&waiters[index].queued) <= 1 {
                    retired.push(waiters.remove(index));
                    continue;
                }

                let entry = &mut waiters[index];
                if !found && Arc::ptr_eq(&entry.queued, queued) {
                    let incoming = incoming
                        .as_mut()
                        .expect("incoming watch Waker remains available during refresh");
                    if !entry.waker.will_wake(incoming) {
                        std::mem::swap(&mut entry.waker, incoming);
                    }
                    found = true;
                }
                index += 1;
            }
            found
        };
        drop(retired);
        drop(incoming);
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
    /// This method does not take a [`Cx`] because it never waits for capacity
    /// and never holds a deferred send obligation across a cancellation point.
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

        // Serialize against any concurrent `send_modify` read-modify-write so a
        // blind `send` cannot land inside another writer's RMW window and be
        // silently annihilated (see `send_lock` docs). The value guard drops at
        // the end of the block, then `send_lock`, then the old value.
        let _old_value = {
            let _write_serialize = self.inner.send_lock.lock();
            let mut guard = self.inner.value.write();
            let old = std::mem::replace(&mut guard.0, value);
            guard.1 = guard.1.wrapping_add(1);
            old
        };

        if self.inner.has_receivers_snapshot() {
            self.inner.wake_all_waiters();
        }

        Ok(())
    }

    /// Modifies the current value.
    ///
    /// This method clones the current value, applies the closure to the clone
    /// and writes it back, so the closure never runs under the value lock and
    /// readers are not stalled. The clone and the closure do run under the
    /// sender's write-serialization lock: a closure (or `T::clone`) that sends
    /// on this channel deadlocks, and concurrent `send` calls wait for it.
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

        // Serialize the whole read-modify-write against other writers. Held
        // across clone -> closure -> writeback so a concurrent `send` /
        // `send_modify` cannot commit between our read and write and be lost
        // (the closure still runs WITHOUT the value `RwLock` held, so the
        // no-reentrancy-deadlock / no-reader-stall contract is preserved).
        // The lock is released before the waiters are woken and the previous
        // value is dropped, as in `send()`: a waker that polls inline, or a
        // `T::Drop` that sends on this channel, would otherwise deadlock on it.
        // Declare the speculative clone OUTSIDE the serialization-lock scope.
        // During panic unwinding Rust destroys locals in reverse declaration
        // order. A clone allocated within the lock scope would run T::drop
        // before releasing send_lock, deadlocking a reentrant destructor.
        let mut candidate: Option<T>;
        let _old_value = {
            let _write_serialize = self.inner.send_lock.lock();

            candidate = Some({
                let guard = self.inner.value.read();
                guard.0.clone()
            });

            // Execute the caller's closure without the value lock, while
            // serializing against concurrent send and send_modify operations.
            f(candidate.as_mut().expect("candidate initialized before mutation"));

            let mut guard = self.inner.value.write();
            let old = std::mem::replace(
                &mut guard.0,
                candidate.take().expect("candidate initialized before publication"),
            );
            guard.1 = guard.1.wrapping_add(1);
            old
        };

        if self.inner.has_receivers_snapshot() {
            self.inner.wake_all_waiters();
        }

        Ok(())
    }

    /// Returns a reference to the current value.
    ///
    /// This acquires a read lock on the value. The returned `Ref` holds
    /// the lock and provides access to the value. Keep it short-lived: a send
    /// waits for it, and another `borrow` queues behind that waiting send.
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
            // Recursive for the same reason as `current_version`.
            let guard = self.inner.value.read_recursive();
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
    ///
    /// This is an observational snapshot for telemetry and routing decisions,
    /// not a synchronization primitive. The send path keeps its own liveness
    /// check before waking waiters.
    #[inline]
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.inner.receiver_count_snapshot()
    }

    /// Returns true if all receivers have been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        !self.inner.has_receivers_snapshot()
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
        wake_waiters(waiters);
    }
}

/// Wakes every drained waiter behind its own unwind boundary, so one panicking
/// waker, or its destructor, cannot strand the rest parked forever. Every
/// `queued` flag is cleared first. The first panic resumes afterwards; during
/// an existing unwind the later payloads are forgotten, never dropped.
fn wake_waiters(waiters: SmallVec<[WatchWaiter; 4]>) {
    for waiter in &waiters {
        waiter.queued.store(false, Ordering::Release);
    }
    let already_panicking = std::thread::panicking();
    let mut first_panic = None;
    let mut record = |result: std::thread::Result<()>| {
        if let Err(payload) = result {
            if already_panicking || first_panic.is_some() {
                std::mem::forget(payload);
            } else {
                first_panic = Some(payload);
            }
        }
    };
    for waiter in waiters {
        record(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || waiter.waker.wake_by_ref(),
        )));
        record(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            move || drop(waiter),
        )));
    }
    if let Some(payload) = first_panic {
        std::panic::resume_unwind(payload);
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
    fn clear_waiter_registration(&self, cancelled: bool) {
        let mut removed_pending_waiter = false;
        let mut retired = SmallVec::<[WatchWaiter; 4]>::new();
        if let Some(waiter) = self.waiter.as_ref() {
            // A ready post-register path can clear the flag while its entry
            // remains linked. Remove that entry before returning or dropping.
            if waiter.load(Ordering::Acquire) || Arc::strong_count(waiter) > 1 {
                waiter.store(false, Ordering::Release);
                let mut waiters = self.inner.waiters.lock();
                let mut index = 0;
                while index < waiters.len() {
                    let remove = Arc::ptr_eq(&waiters[index].queued, waiter);
                    removed_pending_waiter |= remove;
                    if remove || Arc::strong_count(&waiters[index].queued) <= 1 {
                        retired.push(waiters.remove(index));
                    } else {
                        index += 1;
                    }
                }
            }
        }
        if cancelled && removed_pending_waiter {
            // Account before arbitrary Waker destructors can unwind.
            self.inner.record_cancellation();
        }
        drop(retired);
    }

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
            cancel: CancelRegistration::new(cx),
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
                if !self.inner.refresh_waker(w, context.waker().clone()) {
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

        #[cfg(test)]
        BEFORE_FINAL_CLOSED_CHECK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });

        if self.inner.is_sender_dropped() {
            // Also fast path for drop
            if let Some(w) = self.waiter.as_ref() {
                w.store(false, Ordering::Release);
            }
            // The sender may have sent a final value and dropped since the
            // version was read above: report that value before Closed, as the
            // first check does.
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

        Poll::Pending
    }

    /// Waits until the value satisfies `predicate`, then returns it borrowed
    /// and marks it seen.
    ///
    /// The current value is checked first, so a value that already matches
    /// returns at once without waiting for a change. Otherwise every newer
    /// value is checked as it is published. The predicate runs under the
    /// value's read lock, and the returned [`Ref`] is the value it accepted:
    /// no send can slip in between. So the predicate must not send on this
    /// channel or borrow it: a send would wait for the lock the predicate
    /// holds.
    ///
    /// While it waits, it holds one more receiver of the channel, which
    /// [`Sender::receiver_count`] counts (br-asupersync-973voq).
    ///
    /// ```ignore
    /// let ready = rx.wait_for(&cx, |state| *state == State::Ready).await?;
    /// ```
    ///
    /// # Cancel Safety
    ///
    /// Cancel-safe: if the future is dropped before it resolves, the
    /// receiver's `seen_version` is unchanged.
    ///
    /// # Errors
    ///
    /// Returns `RecvError::Closed` if the sender is dropped while no value
    /// satisfies the predicate, and `RecvError::Cancelled` if `cx` is
    /// cancelled while waiting.
    pub async fn wait_for<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        mut predicate: impl FnMut(&T) -> bool,
    ) -> Result<Ref<'_, T>, RecvError> {
        // Changes are awaited on a clone, so the value can be returned
        // borrowed from `self.inner` while this loop still waits through
        // another receiver; `seen_version` is written as a disjoint field.
        let mut waiter: Option<Self> = None;
        loop {
            let checked = {
                let guard = self.inner.value.read();
                if predicate(&guard.0) {
                    self.seen_version = guard.1;
                    self.inner
                        .update_receiver_version(self.receiver_token, guard.1);
                    return Ok(Ref { guard });
                }
                guard.1
            };
            let waiter = waiter.get_or_insert_with(|| self.clone());
            // Wait for a version newer than the one just checked, not newer
            // than whatever is current now: a send since the check must
            // still wake this loop.
            waiter.seen_version = checked;
            waiter
                .inner
                .update_receiver_version(waiter.receiver_token, checked);
            waiter.changed(cx).await?;
        }
    }

    /// Returns a reference to the current value.
    ///
    /// This does NOT update `seen_version`.
    ///
    /// If you need the returned snapshot and the acknowledgement to refer to
    /// the same version, use [`Receiver::borrow_and_update`] instead.
    /// Calling [`Receiver::mark_seen`] later acknowledges whatever version is
    /// current at that later instant and can therefore skip an intervening send.
    ///
    /// The `Ref` holds the value's read lock. Keep it short-lived: a send
    /// waits for it, and another `borrow` queues behind that waiting send.
    /// [`Receiver::has_changed`] is safe to call while it is held.
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
    cancel: CancelRegistration<'b, Caps>,
    completed: bool,
}

impl<T, Caps> Future for ChangedFuture<'_, '_, T, Caps> {
    type Output = Result<(), RecvError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.completed {
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        let result = this.receiver.poll_changed(this.cx, context);
        if result.is_ready() {
            this.completed = true;
            this.receiver.clear_waiter_registration(false);
            this.cancel.clear();
            return result;
        }
        this.cancel.refresh(context.waker());
        // Cancellation may arrive while the data or cancellation Waker is
        // registered or retired. It must not require a later producer event.
        if this.cx.is_cancel_requested() && this.cx.checkpoint().is_err() {
            this.completed = true;
            this.receiver.inner.record_cancellation();
            this.cx.trace("watch::changed cancelled");
            this.receiver.clear_waiter_registration(false);
            this.cancel.clear();
            Poll::Ready(Err(RecvError::Cancelled))
        } else {
            Poll::Pending
        }
    }
}

impl<T, Caps> Drop for ChangedFuture<'_, '_, T, Caps> {
    fn drop(&mut self) {
        self.receiver.clear_waiter_registration(!self.completed);
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
            let mut retired = SmallVec::<[WatchWaiter; 4]>::new();
            let mut waiters = self.inner.waiters.lock();
            let mut index = 0;
            while index < waiters.len() {
                if Arc::ptr_eq(&waiters[index].queued, &waiter)
                    || Arc::strong_count(&waiters[index].queued) <= 1
                {
                    retired.push(waiters.remove(index));
                } else {
                    index += 1;
                }
            }
            drop(waiters);
            drop(retired);
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
thread_local! {
    /// Runs once on this thread just before `poll_changed`'s final
    /// sender-dropped check, so a test can send and drop in that window.
    static BEFORE_FINAL_CLOSED_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
#[path = "watch_inline_tests.rs"]
mod tests;
