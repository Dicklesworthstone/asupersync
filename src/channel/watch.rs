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

use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockReadGuard};

use crate::cx::Cx;

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
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "watch channel sender was dropped"),
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
    /// Notification for value changes.
    notify: Condvar,
}

impl<T> WatchInner<T> {
    fn new(initial: T) -> Self {
        Self {
            value: RwLock::new((initial, 0)),
            receiver_count: Mutex::new(1), // Sender starts with one implicit receiver
            sender_dropped: Mutex::new(false),
            notify: Condvar::new(),
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

        // Notify all waiting receivers
        // We take the lock briefly to coordinate with condvar
        let _guard = self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");
        self.inner.notify.notify_all();

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

        // Notify all waiting receivers
        let _guard = self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");
        self.inner.notify.notify_all();

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
        let _guard = self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");
        self.inner.notify.notify_all();
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
}

impl<T> Receiver<T> {
    /// Waits until a new value is available.
    ///
    /// This method blocks until the channel's version exceeds `seen_version`,
    /// then updates `seen_version` to the current version.
    ///
    /// # Cancel Safety
    ///
    /// This method is cancel-safe. If cancelled during the wait, the receiver's
    /// `seen_version` is unchanged and the wait can be retried.
    ///
    /// # Errors
    ///
    /// Returns `RecvError::Closed` if the sender was dropped.
    pub fn changed(&mut self, cx: &Cx) -> Result<(), RecvError> {
        cx.trace("watch::changed starting wait");

        let mut lock = self
            .inner
            .receiver_count
            .lock()
            .expect("watch lock poisoned");

        loop {
            // Check if sender dropped
            if self.inner.is_sender_dropped() {
                // Still return change if value was updated before drop
                let current = self.inner.current_version();
                if current > self.seen_version {
                    self.seen_version = current;
                    return Ok(());
                }
                cx.trace("watch::changed sender dropped");
                return Err(RecvError::Closed);
            }

            // Check if there's a new value
            let current_version = self.inner.current_version();
            if current_version > self.seen_version {
                self.seen_version = current_version;
                cx.trace("watch::changed received update");
                return Ok(());
            }

            // Check cancellation before waiting
            if cx.checkpoint().is_err() {
                cx.trace("watch::changed cancelled while waiting");
                return Err(RecvError::Closed);
            }

            // Wait for notification
            // Use wait_timeout to allow periodic cancellation checks
            let (guard, _timeout) = self
                .inner
                .notify
                .wait_timeout(lock, std::time::Duration::from_millis(10))
                .expect("watch lock poisoned");
            lock = guard;
        }
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

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn basic_send_recv() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        tx.send(42).expect("send failed");
        rx.changed(&cx).expect("changed failed");
        assert_eq!(*rx.borrow(), 42);
    }

    #[test]
    fn initial_value_visible() {
        let (tx, rx) = channel(42);
        assert_eq!(*rx.borrow(), 42);
        assert_eq!(*tx.borrow(), 42);
    }

    #[test]
    fn multiple_updates() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        for i in 1..=10 {
            tx.send(i).expect("send failed");
            rx.changed(&cx).expect("changed failed");
            assert_eq!(*rx.borrow(), i);
        }
    }

    #[test]
    fn latest_value_wins() {
        let (tx, rx) = channel(0);

        for i in 1..=100 {
            tx.send(i).expect("send failed");
        }

        // Watch holds only the latest value, not a queue.
        assert_eq!(*rx.borrow(), 100);
    }

    #[test]
    fn send_modify() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        tx.send_modify(|v| *v = 42).expect("send_modify failed");
        rx.changed(&cx).expect("changed failed");
        assert_eq!(*rx.borrow(), 42);

        tx.send_modify(|v| *v += 10).expect("send_modify failed");
        rx.changed(&cx).expect("changed failed");
        assert_eq!(*rx.borrow(), 52);
    }

    #[test]
    fn borrow_and_clone() {
        let (_tx, rx) = channel(42);
        let value: i32 = rx.borrow_and_clone();
        assert_eq!(value, 42);
    }

    #[test]
    fn mark_seen() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Send value
        tx.send(1).expect("send failed");
        assert!(rx.has_changed());

        // Mark seen without calling changed()
        rx.mark_seen();
        assert!(!rx.has_changed());

        // Need new value for changed() to return
        tx.send(2).expect("send failed");
        rx.changed(&cx).expect("changed failed");
        assert_eq!(*rx.borrow(), 2);
    }

    #[test]
    fn changed_returns_only_on_new_value() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Initial version is 0, seen_version is 0
        // changed() should block until version > 0

        // Send first update
        tx.send(1).expect("send failed");
        rx.changed(&cx).expect("changed failed");

        // Now version=1, seen_version=1
        // has_changed should be false
        assert!(!rx.has_changed());

        // Send another
        tx.send(2).expect("send failed");
        assert!(rx.has_changed());
        rx.changed(&cx).expect("changed failed");
        assert_eq!(*rx.borrow(), 2);
    }

    #[test]
    fn multiple_receivers() {
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);
        let mut rx2 = rx1.clone();

        tx.send(42).expect("send failed");

        // Subscribe AFTER send - rx3 starts at current version (1)
        let rx3 = tx.subscribe();

        // rx1 and rx2 see the update (they were created before send)
        rx1.changed(&cx).expect("changed failed");
        rx2.changed(&cx).expect("changed failed");

        // rx3 was subscribed after send, so it already sees version 1
        // and its seen_version was set to current (1), so no change pending
        assert!(!rx3.has_changed());

        assert_eq!(*rx1.borrow(), 42);
        assert_eq!(*rx2.borrow(), 42);
        assert_eq!(*rx3.borrow(), 42);
    }

    #[test]
    fn receiver_count() {
        let (tx, rx1) = channel::<i32>(0);
        assert_eq!(tx.receiver_count(), 1);

        let rx2 = rx1.clone();
        assert_eq!(tx.receiver_count(), 2);

        let rx3 = tx.subscribe();
        assert_eq!(tx.receiver_count(), 3);

        drop(rx1);
        assert_eq!(tx.receiver_count(), 2);

        drop(rx2);
        drop(rx3);
        assert_eq!(tx.receiver_count(), 0);
        assert!(tx.is_closed());
    }

    #[test]
    fn sender_dropped() {
        let cx = test_cx();
        let (tx, mut rx) = channel(0);

        // Send before drop
        tx.send(42).expect("send failed");
        drop(tx);

        // Receiver should still see the value
        assert!(rx.is_closed());
        rx.changed(&cx).expect("should see final update");
        assert_eq!(*rx.borrow(), 42);

        // Now changed() should return error
        assert!(rx.changed(&cx).is_err());
    }

    #[test]
    fn send_error_when_no_receivers() {
        let (tx, rx) = channel(0);
        drop(rx);

        assert!(tx.is_closed());
        let err = tx.send(42);
        assert!(matches!(err, Err(SendError::Closed(42))));
    }

    #[test]
    fn version_tracking() {
        let (_tx, rx) = channel(0);
        assert_eq!(rx.seen_version(), 0);
    }

    #[test]
    fn has_changed_reflects_state() {
        let (tx, rx) = channel(0);

        // Initial: no change since initial value
        assert!(!rx.has_changed());

        tx.send(1).expect("send failed");
        assert!(rx.has_changed());
    }

    #[test]
    fn cloned_receiver_inherits_version() {
        let cx = test_cx();
        let (tx, mut rx1) = channel(0);

        tx.send(1).expect("send failed");
        rx1.changed(&cx).expect("changed failed");

        // Clone after rx1 has seen the update
        let rx2 = rx1.clone();

        // rx2 inherits seen_version from rx1, so no pending change
        assert!(!rx2.has_changed());
    }

    #[test]
    fn subscribe_gets_current_version() {
        let (tx, _rx) = channel(0);

        tx.send(1).expect("send failed");
        tx.send(2).expect("send failed");

        // Subscribe after updates
        let rx2 = tx.subscribe();

        // rx2 starts with current version, so no pending change
        assert!(!rx2.has_changed());
        assert_eq!(*rx2.borrow(), 2);
    }

    #[test]
    fn send_error_display() {
        let err = SendError::Closed(42);
        assert_eq!(err.to_string(), "sending on a closed watch channel");
    }

    #[test]
    fn recv_error_display() {
        assert_eq!(
            RecvError::Closed.to_string(),
            "watch channel sender was dropped"
        );
    }

    #[test]
    fn ref_deref() {
        let (_tx, rx) = channel(42);
        let r = rx.borrow();
        let _: &i32 = &r;
        assert_eq!(*r, 42);
        drop(r);
    }

    #[test]
    fn ref_clone_inner() {
        let (_tx, rx) = channel(String::from("hello"));
        let cloned: String = rx.borrow().clone_inner();
        assert_eq!(cloned, "hello");
    }

    #[test]
    fn cancel_during_wait_preserves_version() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let (tx, mut rx) = channel(0);

        // changed() should return error due to cancellation
        let result = rx.changed(&cx);
        assert!(result.is_err());

        // seen_version should be unchanged (still 0)
        assert_eq!(rx.seen_version(), 0);

        // After cancellation cleared, should see the update
        cx.set_cancel_requested(false);
        tx.send(1).expect("send failed");
        rx.changed(&cx).expect("changed failed");
        assert_eq!(rx.seen_version(), 1);
    }

    #[test]
    fn shutdown_signal_pattern() {
        let cx = test_cx();
        let (shutdown_tx, mut shutdown_rx) = channel(false);

        // Check initial state
        assert!(!*shutdown_rx.borrow());

        // Trigger shutdown
        shutdown_tx.send(true).expect("send failed");
        shutdown_rx.changed(&cx).expect("changed failed");

        // Worker would check this
        assert!(*shutdown_rx.borrow());
    }
}
