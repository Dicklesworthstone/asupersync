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

use smallvec::SmallVec;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<T> {
    /// All receivers have been dropped.
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
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "watch channel sender was dropped"),
            Self::Cancelled => write!(f, "watch receive operation cancelled"),
        }
    }
}

impl std::error::Error for RecvError {}

/// Error returned when modifying fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifyError;

impl std::fmt::Display for ModifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "watch channel has no receivers")
    }
}

impl std::error::Error for ModifyError {}

/// Internal state shared between sender and receivers.
#[derive(Debug)]
struct WatchInner<T> {
    /// The current value and its version number.
    value: RwLock<(T, u64)>,
    /// Number of active receivers (excluding sender's implicit subscription).
    receiver_count: Mutex<usize>,
    /// Whether the sender has been dropped.
    sender_dropped: Mutex<bool>,
    /// Wakers for receivers waiting on value changes.
    waiters: Mutex<SmallVec<[WatchWaiter; 4]>>,
}

impl<T> WatchInner<T> {
    fn new(initial: T) -> Self {
        Self {
            value: RwLock::new((initial, 0)),
            receiver_count: Mutex::new(1), // Counts the Receiver returned by channel()
            sender_dropped: Mutex::new(false),
            waiters: Mutex::new(SmallVec::new()),
        }
    }

    fn is_sender_dropped(&self) -> bool {
        *self.sender_dropped.lock().expect("watch lock poisoned")
    }

    fn mark_sender_dropped(&self) {
        *self.sender_dropped.lock().expect("watch lock poisoned") = true;
    }

    fn current_version(&self) -> u64 {
        self.value.read().expect("watch lock poisoned").1
    }

    fn wake_all_waiters(&self) {
        let waiters: SmallVec<[WatchWaiter; 4]> = {
            let mut w = self.waiters.lock().expect("watch lock poisoned");
            std::mem::take(&mut *w)
        };
        for w in waiters {
            w.queued.store(false, Ordering::Release);
            w.waker.wake();
        }
    }

    fn register_waker(&self, waiter: WatchWaiter) {
        let mut waiters = self.waiters.lock().expect("watch lock poisoned");
        // Stale entries can remain after cancelled/dropped wait futures.
        // They have no owner `Receiver` reference, so only the waiters vec
        // holds their flag (`strong_count == 1`). Prune before inserting.
        waiters.retain(|entry| Arc::strong_count(&entry.queued) > 1);
        if let Some(existing) = waiters
            .iter_mut()
            .find(|entry| Arc::ptr_eq(&entry.queued, &waiter.queued))
        {
            if !existing.waker.will_wake(&waiter.waker) {
                existing.waker = waiter.waker;
            }
            return;
        }
        waiters.push(waiter);
    }

    /// Update the waker for an already-queued waiter without pre-cloning.
    /// Returns `true` if the waiter was found and refreshed, `false` if not found
    /// (caller should fall back to `register_waker` with a new `WatchWaiter`).
    fn refresh_waker(&self, queued: &Arc<AtomicBool>, new_waker: &Waker) -> bool {
        let mut waiters = self.waiters.lock().expect("watch lock poisoned");
        waiters.retain(|entry| Arc::strong_count(&entry.queued) > 1);
        if let Some(existing) = waiters
            .iter_mut()
            .find(|entry| Arc::ptr_eq(&entry.queued, queued))
        {
            if !existing.waker.will_wake(new_waker) {
                existing.waker.clone_from(new_waker);
            }
            return true;
        }
        drop(waiters);
        false
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
#[must_use]
pub fn channel<T>(initial: T) -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(WatchInner::new(initial));
    (
        Sender {
            inner: Arc::clone(&inner),
        },
        Receiver {
            inner,
            seen_version: 0,
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
    /// # Errors
    ///
    /// Returns `SendError::Closed(value)` if all receivers have been dropped.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        let receiver_count = *self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");

        // Check if anyone is listening (receiver_count includes implicit sender subscription)
        if receiver_count == 0 {
            return Err(SendError::Closed(value));
        }

        {
            let mut guard = self.inner.value.write().expect("watch lock poisoned");
            guard.0 = value;
            guard.1 += 1;
        }

        self.inner.wake_all_waiters();

        Ok(())
    }

    /// Modifies the current value in place.
    ///
    /// This is more efficient than `borrow()` + modify + `send()` when
    /// the value is large, as it avoids cloning.
    ///
    /// # Errors
    ///
    /// Returns `Err(ModifyError::Closed)` if all receivers have been dropped.
    pub fn send_modify<F>(&self, f: F) -> Result<(), ModifyError>
    where
        F: FnOnce(&mut T),
    {
        let receiver_count = *self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");

        if receiver_count == 0 {
            return Err(ModifyError);
        }

        {
            let mut guard = self.inner.value.write().expect("watch lock poisoned");
            f(&mut guard.0);
            guard.1 += 1;
        }

        self.inner.wake_all_waiters();

        Ok(())
    }

    /// Returns a reference to the current value.
    ///
    /// This acquires a read lock on the value. The returned `Ref` holds
    /// the lock and provides access to the value.
    #[must_use]
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.inner.value.read().expect("watch lock poisoned"),
        }
    }

    /// Creates a new receiver subscribed to this channel.
    ///
    /// The new receiver starts with `seen_version` equal to the current
    /// version, so it will only see future changes.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<T> {
        {
            let mut count = self
                .inner
                .receiver_count
                .lock()
                .expect("watch lock poisoned");
            *count += 1;
        }

        let current_version = self.inner.current_version();
        Receiver {
            inner: Arc::clone(&self.inner),
            seen_version: current_version,
            waiter: None,
        }
    }

    /// Returns the number of active receivers (excluding sender).
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        *self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned")
    }

    /// Returns true if all receivers have been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned")
            == 0
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.inner.mark_sender_dropped();
        // Wake all waiting receivers so they see Closed
        self.inner.wake_all_waiters();
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
    /// Deduplication flag shared with our entry in the waiters vec.
    /// Prevents unbounded waker growth between sends.
    waiter: Option<Arc<AtomicBool>>,
}

impl<T> Receiver<T> {
    /// Waits until a new value is available.
    ///
    /// Returns a future that resolves when the channel's version exceeds
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
    pub fn changed<'a, 'b>(&'a mut self, cx: &'b Cx) -> ChangedFuture<'a, 'b, T> {
        cx.trace("watch::changed starting wait");
        // Invalidate any stale waiter from a previous cancelled future so
        // the new future re-registers with a fresh waker.
        self.waiter = None;
        ChangedFuture { receiver: self, cx }
    }

    /// Returns a reference to the current value.
    ///
    /// This does NOT update `seen_version`. Use `mark_seen()` after
    /// if you want to acknowledge seeing the value.
    #[must_use]
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref {
            guard: self.inner.value.read().expect("watch lock poisoned"),
        }
    }

    /// Returns a clone of the current value.
    ///
    /// Convenience method that borrows and clones in one operation.
    /// Does NOT update `seen_version`.
    #[must_use]
    pub fn borrow_and_clone(&self) -> T
    where
        T: Clone,
    {
        self.borrow().clone()
    }

    /// Marks the current value as seen.
    ///
    /// After this call, `changed()` will only return when a newer
    /// value is available.
    pub fn mark_seen(&mut self) {
        self.seen_version = self.inner.current_version();
    }

    /// Returns true if there's a new value since last seen.
    #[must_use]
    pub fn has_changed(&self) -> bool {
        self.inner.current_version() > self.seen_version
    }

    /// Returns true if the sender has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_sender_dropped()
    }

    /// Returns the version number last seen by this receiver.
    #[must_use]
    pub fn seen_version(&self) -> u64 {
        self.seen_version
    }
}

/// Future returned by [`Receiver::changed`].
///
/// Resolves when a new value is available or the channel closes.
pub struct ChangedFuture<'a, 'b, T> {
    receiver: &'a mut Receiver<T>,
    cx: &'b Cx,
}

impl<T> Future for ChangedFuture<'_, '_, T> {
    type Output = Result<(), RecvError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // Check cancellation
        if this.cx.checkpoint().is_err() {
            this.cx.trace("watch::changed cancelled");
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        // Check sender dropped
        if this.receiver.inner.is_sender_dropped() {
            let current = this.receiver.inner.current_version();
            if current > this.receiver.seen_version {
                this.receiver.seen_version = current;
                return Poll::Ready(Ok(()));
            }
            this.cx.trace("watch::changed sender dropped");
            return Poll::Ready(Err(RecvError::Closed));
        }

        // Check version
        let current = this.receiver.inner.current_version();
        if current > this.receiver.seen_version {
            this.receiver.seen_version = current;
            this.cx.trace("watch::changed received update");
            return Poll::Ready(Ok(()));
        }

        // Register waker before re-checking (avoids missed notification).
        // Use Arc<AtomicBool> dedup to prevent unbounded Vec growth when
        // the future is re-polled without an intervening send().
        match this.receiver.waiter.as_ref() {
            Some(w) if !w.load(Ordering::Acquire) => {
                // We were woken (queued=false) but version hasn't changed yet.
                // Re-register with a fresh waker.
                w.store(true, Ordering::Release);
                this.receiver.inner.register_waker(WatchWaiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(w),
                });
            }
            Some(w) => {
                // Still queued, but the task's waker may have changed.
                // Refresh in-place without pre-cloning — avoids Waker clone +
                // Arc::clone on the common re-poll path.
                if !this.receiver.inner.refresh_waker(w, context.waker()) {
                    // Waiter was pruned (stale); re-register with a fresh entry.
                    this.receiver.inner.register_waker(WatchWaiter {
                        waker: context.waker().clone(),
                        queued: Arc::clone(w),
                    });
                }
            }
            None => {
                // First poll — create a new waiter.
                let w = Arc::new(AtomicBool::new(true));
                this.receiver.inner.register_waker(WatchWaiter {
                    waker: context.waker().clone(),
                    queued: Arc::clone(&w),
                });
                this.receiver.waiter = Some(w);
            }
        }

        // Re-check after registration to close the race window
        let current = this.receiver.inner.current_version();
        if current > this.receiver.seen_version {
            this.receiver.seen_version = current;
            this.cx.trace("watch::changed received update");
            return Poll::Ready(Ok(()));
        }

        if this.receiver.inner.is_sender_dropped() {
            let current = this.receiver.inner.current_version();
            if current > this.receiver.seen_version {
                this.receiver.seen_version = current;
                return Poll::Ready(Ok(()));
            }
            this.cx.trace("watch::changed sender dropped");
            return Poll::Ready(Err(RecvError::Closed));
        }

        Poll::Pending
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        {
            let mut count = self
                .inner
                .receiver_count
                .lock()
                .expect("watch lock poisoned");
            *count += 1;
        }
        Self {
            inner: Arc::clone(&self.inner),
            seen_version: self.seen_version,
            waiter: None,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut count = self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");
        *count = count.saturating_sub(1);
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
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::sync::atomic::AtomicUsize;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
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
    fn send_error_when_no_receivers() {
        init_test("send_error_when_no_receivers");
        let (tx, rx) = channel(0);
        drop(rx);

        let closed = tx.is_closed();
        crate::assert_with_log!(closed, "tx closed", true, closed);
        let err = tx.send(42);
        crate::assert_with_log!(
            matches!(err, Err(SendError::Closed(42))),
            "send closed",
            "Err(Closed(42))",
            format!("{:?}", err)
        );
        crate::test_complete!("send_error_when_no_receivers");
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
            closed_text == "watch channel sender was dropped",
            "display",
            "watch channel sender was dropped",
            closed_text
        );
        let cancelled_text = RecvError::Cancelled.to_string();
        crate::assert_with_log!(
            cancelled_text == "watch receive operation cancelled",
            "display",
            "watch receive operation cancelled",
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
        }

        // The waiters vec should have exactly 1 entry, not 100.
        let waiter_count = tx.inner.waiters.lock().unwrap().len();
        crate::assert_with_log!(
            waiter_count == 1,
            "waiter count after repeated polls",
            1,
            waiter_count
        );

        // After send (which drains waiters), re-poll should add at most 1 again.
        tx.send(42).expect("send failed");
        poll_ready(&mut rx.changed(&cx)).expect("changed failed");
        let value = *rx.borrow();
        crate::assert_with_log!(value == 42, "value after send", 42, value);

        let waiter_count = tx.inner.waiters.lock().unwrap().len();
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
        // Stale entries should be pruned on each re-registration.
        for _ in 0..50 {
            let mut future = rx.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());
            // future dropped here
        }

        let waiter_count = tx.inner.waiters.lock().unwrap().len();
        crate::assert_with_log!(
            waiter_count == 1,
            "stale entries pruned across cancel cycles",
            1,
            waiter_count
        );

        // A single send drains all stale entries.
        tx.send(1).expect("send failed");
        let waiter_count = tx.inner.waiters.lock().unwrap().len();
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

        // Register rx1 waiter, then drop rx1 without any send.
        {
            let mut future = rx1.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());
        }
        drop(rx1);

        // Next registration should prune dropped receiver's stale waiter.
        {
            let mut future = rx2.changed(&cx);
            let result = Pin::new(&mut future).poll(&mut task_cx);
            assert!(result.is_pending());
        }

        let waiter_count = tx.inner.waiters.lock().unwrap().len();
        crate::assert_with_log!(
            waiter_count == 1,
            "dropped receiver waiter pruned",
            1,
            waiter_count
        );
        crate::test_complete!("dropped_receiver_waiter_is_pruned_on_next_registration");
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
}
