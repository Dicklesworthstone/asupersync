//! Two-phase oneshot (single-use) channel.
//!
//! This channel uses the reserve/commit pattern to ensure cancel-safety:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                     ONESHOT RESERVE/COMMIT                         │
//! │                                                                    │
//! │   Sender                                  Receiver                 │
//! │     │                                        │                     │
//! │     │─── reserve() ──► SendPermit            │                     │
//! │     │                      │                 │                     │
//! │     │                      │─── send(v) ────►├── recv() ──► Ok(v)  │
//! │     │                      │                 │                     │
//! │     │                      │─── abort() ────►├── recv() ──► Err    │
//! │     │                                        │                     │
//! │   (drop) ────────────────────────────────────► recv() ──► Err      │
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Cancel Safety
//!
//! The two-phase pattern ensures cancellation at any point is clean:
//!
//! - If cancelled during reserve: sender is consumed, receiver sees Closed
//! - If cancelled after reserve but before send: permit drop aborts cleanly
//! - The commit operation (`send`) cannot fail
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::oneshot;
//!
//! // Create a oneshot channel
//! let (tx, rx) = oneshot::channel::<i32>();
//!
//! // Two-phase send pattern (explicit reserve)
//! let permit = tx.reserve(&cx);
//! permit.send(42);
//!
//! // Or convenience method
//! // tx.send(42);  // reserve + send in one step
//!
//! // Receive
//! let value = rx.recv(&cx).await?;
//! ```

use crate::cx::Cx;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// Error returned when sending fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<T> {
    /// The receiver was dropped before the value could be sent.
    Disconnected(T),
}

impl<T> std::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected(_) => write!(f, "sending on a closed oneshot channel"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

/// Error returned when receiving fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The sender was dropped without sending a value.
    Closed,
    /// The receive operation was cancelled.
    Cancelled,
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "receiving on a closed oneshot channel"),
            Self::Cancelled => write!(f, "receive operation cancelled"),
        }
    }
}

impl std::error::Error for RecvError {}

/// Error returned when `try_recv` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    /// No value available yet, but sender still exists.
    Empty,
    /// The sender was dropped without sending a value.
    Closed,
}

impl std::fmt::Display for TryRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "oneshot channel is empty"),
            Self::Closed => write!(f, "oneshot channel is closed"),
        }
    }
}

impl std::error::Error for TryRecvError {}

/// Internal state for a oneshot channel.
#[derive(Debug)]
struct OneShotInner<T> {
    /// The value, if sent.
    value: Option<T>,
    /// Whether the sender has been consumed (dropped or reserved).
    sender_consumed: bool,
    /// Whether the receiver has been dropped.
    receiver_dropped: bool,
    /// Whether a permit is currently outstanding.
    permit_outstanding: bool,
    /// The waker to notify when a value is sent or the channel is closed.
    waker: Option<Waker>,
    /// Monotonic waiter identity for the registered waker.
    ///
    /// This lets us clear a waiter only if the same `RecvFuture` that
    /// registered it is being cancelled/dropped.
    waker_id: Option<u64>,
    /// Next waiter identity to assign.
    next_waiter_id: u64,
}

impl<T> OneShotInner<T> {
    fn new() -> Self {
        Self {
            value: None,
            sender_consumed: false,
            receiver_dropped: false,
            permit_outstanding: false,
            waker: None,
            waker_id: None,
            next_waiter_id: 0,
        }
    }

    /// Returns true if the channel is closed (sender gone and no value).
    fn is_closed(&self) -> bool {
        self.sender_consumed && !self.permit_outstanding && self.value.is_none()
    }

    /// Returns true if a value is ready to receive.
    fn is_ready(&self) -> bool {
        self.value.is_some()
    }

    /// Clears the registered waker and its waiter identity.
    fn clear_waker(&mut self) {
        self.waker = None;
        self.waker_id = None;
    }

    /// Takes the registered waker and clears its waiter identity.
    fn take_waker(&mut self) -> Option<Waker> {
        self.waker_id = None;
        self.waker.take()
    }
}

/// Creates a new oneshot channel, returning the sender and receiver halves.
///
/// Unlike MPSC channels, oneshot channels have exactly one sender and one receiver,
/// and can only transmit a single value.
///
/// # Example
///
/// ```ignore
/// let (tx, rx) = oneshot::channel::<i32>();
/// tx.send(42);
/// let value = rx.recv(&cx).await?;
/// ```
#[must_use]
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Arc::new(Mutex::new(OneShotInner::new()));
    (
        Sender {
            inner: Arc::clone(&inner),
        },
        Receiver { inner },
    )
}

/// The sending half of a oneshot channel.
///
/// This can only be used once - either via `reserve()` + `SendPermit::send()`,
/// or via the convenience `send()` method which does both in one step.
///
/// # Cancel Safety
///
/// If the sender is dropped without sending, the receiver will receive a `Closed` error.
#[derive(Debug)]
pub struct Sender<T> {
    inner: Arc<Mutex<OneShotInner<T>>>,
}

impl<T> Sender<T> {
    /// Reserves the channel for sending, returning a permit.
    ///
    /// This consumes the sender. The permit must be used to either:
    /// - `send(value)` - commits the send
    /// - `abort()` - cancels the send
    /// - (dropped) - equivalent to `abort()`
    ///
    /// # Cancel Safety
    ///
    /// This operation is cancel-safe: if dropped before returning,
    /// the sender is still available. After returning, the permit
    /// owns the obligation.
    #[must_use]
    pub fn reserve(self, cx: &Cx) -> SendPermit<T> {
        cx.trace("oneshot::reserve creating permit");

        {
            let mut inner = self.inner.lock();
            inner.sender_consumed = true;
            inner.permit_outstanding = true;
        }

        SendPermit {
            inner: Arc::clone(&self.inner),
            sent: false,
        }
    }

    /// Convenience method: reserves and sends in one step.
    ///
    /// Equivalent to `self.reserve(cx).send(value)` but more ergonomic.
    ///
    /// # Errors
    ///
    /// Returns `Err(SendError::Disconnected(value))` if the receiver was dropped.
    pub fn send(self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        let permit = self.reserve(cx);
        permit.send(value)
    }

    /// Checks if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_dropped
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut inner = self.inner.lock();
            if inner.sender_consumed {
                None
            } else {
                inner.sender_consumed = true;
                // Take waker under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                inner.take_waker()
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A permit to send a value on a oneshot channel.
///
/// Created by [`Sender::reserve`]. Must be consumed by calling either
/// `send()` or `abort()`. If dropped without calling either, behaves
/// as if `abort()` was called.
///
/// # Linearity
///
/// This type represents a linear obligation - it must be resolved
/// (either by sending or aborting) before the owning task/region completes.
#[derive(Debug)]
pub struct SendPermit<T> {
    inner: Arc<Mutex<OneShotInner<T>>>,
    /// Whether the value has been sent.
    sent: bool,
}

impl<T> SendPermit<T> {
    /// Sends a value through the channel.
    ///
    /// This consumes the permit and commits the send. The value will be
    /// available to the receiver.
    ///
    /// # Errors
    ///
    /// Returns `Err(SendError::Disconnected(value))` if the receiver was dropped.
    pub fn send(mut self, value: T) -> Result<(), SendError<T>> {
        let (result, waker) = {
            let mut inner = self.inner.lock();

            if inner.receiver_dropped {
                // Receiver gone, return the value.  Clear stale waker
                // and release the lock as early as possible (mirrors the
                // Ok path).
                inner.permit_outstanding = false;
                inner.clear_waker();
                drop(inner);
                (Err(value), None)
            } else {
                inner.value = Some(value);
                inner.permit_outstanding = false;
                // Take waker under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                let waker = inner.take_waker();
                drop(inner);
                (Ok(()), waker)
            }
        };

        if let Some(waker) = waker {
            waker.wake();
        }

        self.sent = true;
        result.map_err(SendError::Disconnected)
    }

    /// Aborts the send operation.
    ///
    /// This consumes the permit without sending a value. The receiver
    /// will see a `Closed` error when attempting to receive.
    pub fn abort(mut self) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.permit_outstanding = false;
            // Take waker under lock, wake outside.
            inner.take_waker()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        self.sent = true; // Prevent drop from double-aborting
    }

    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_dropped
    }
}

impl<T> Drop for SendPermit<T> {
    fn drop(&mut self) {
        if !self.sent {
            // Permit dropped without sending - abort
            let waker = {
                let mut inner = self.inner.lock();
                inner.permit_outstanding = false;
                inner.take_waker()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

/// Future returned by [`Receiver::recv`].
pub struct RecvFuture<'a, T> {
    receiver: &'a Receiver<T>,
    cx: &'a Cx,
    waiter_id: Option<u64>,
}

impl<T> Future for RecvFuture<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut inner = this.receiver.inner.lock();

        // 1. Check if value is ready
        if let Some(value) = inner.value.take() {
            // Clear the stale waker so we don't retain executor state
            // after the channel is done.
            inner.clear_waker();
            this.waiter_id = None;
            drop(inner);
            this.cx.trace("oneshot::recv received value");
            return Poll::Ready(Ok(value));
        }

        // 2. Check if channel is closed
        if inner.is_closed() {
            inner.clear_waker();
            this.waiter_id = None;
            drop(inner);
            this.cx.trace("oneshot::recv channel closed");
            return Poll::Ready(Err(RecvError::Closed));
        }

        // 3. Check cancellation
        if this.cx.checkpoint().is_err() {
            // Clear stale waiter if this future registered it.
            if this
                .waiter_id
                .is_some_and(|waiter_id| inner.waker_id == Some(waiter_id))
            {
                inner.clear_waker();
            }
            this.waiter_id = None;
            drop(inner);
            this.cx.trace("oneshot::recv cancelled while waiting");
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        // 4. Register waker (skip clone if unchanged and still owned by this waiter)
        match (&inner.waker, inner.waker_id, this.waiter_id) {
            (Some(existing), Some(inner_waiter_id), Some(my_waiter_id))
                if inner_waiter_id == my_waiter_id && existing.will_wake(ctx.waker()) => {}
            _ => {
                let waiter_id = inner.next_waiter_id;
                inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);
                inner.waker = Some(ctx.waker().clone());
                inner.waker_id = Some(waiter_id);
                this.waiter_id = Some(waiter_id);
            }
        }
        drop(inner);
        Poll::Pending
    }
}

impl<T> Drop for RecvFuture<'_, T> {
    fn drop(&mut self) {
        // If dropped while Pending (e.g., select/race loser), clear
        // the registered waker to avoid retaining stale executor state.
        {
            let mut inner = self.receiver.inner.lock();
            // Clear only if this future still owns the registered waiter slot.
            if self
                .waiter_id
                .is_some_and(|waiter_id| inner.waker_id == Some(waiter_id))
            {
                inner.clear_waker();
            }
        }
        self.waiter_id = None;
    }
}

/// The receiving half of a oneshot channel.
///
/// Can only receive a single value. After receiving (or getting an error),
/// the receiver is consumed.
///
/// # Cancel Safety
///
/// If cancelled during `recv()`, the receiver can be retried. The channel
/// remains in a consistent state.
#[derive(Debug)]
pub struct Receiver<T> {
    inner: Arc<Mutex<OneShotInner<T>>>,
}

impl<T> Receiver<T> {
    /// Receives a value from the channel, waiting if necessary.
    ///
    /// This method returns a future that yields the value or an error.
    ///
    /// # Cancel Safety
    ///
    /// If cancelled, the channel state is unchanged and `recv` can be retried.
    /// This is a key property of the two-phase pattern: cancellation during
    /// the wait phase is always clean.
    ///
    /// # Errors
    ///
    /// Returns `Err(RecvError::Closed)` if the sender was dropped without sending.
    #[must_use]
    pub fn recv<'a>(&'a self, cx: &'a Cx) -> RecvFuture<'a, T> {
        RecvFuture {
            receiver: self,
            cx,
            waiter_id: None,
        }
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `TryRecvError::Empty` if no value is available yet but sender exists
    /// - `TryRecvError::Closed` if the sender was dropped without sending
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut inner = self.inner.lock();

        if let Some(value) = inner.value.take() {
            // Terminal success path: clear stale waiter registration.
            inner.clear_waker();
            drop(inner);
            return Ok(value);
        }

        if inner.is_closed() {
            // Terminal closed path: clear stale waiter registration.
            inner.clear_waker();
            drop(inner);
            return Err(TryRecvError::Closed);
        }

        Err(TryRecvError::Empty)
    }

    /// Returns true if a value is ready to receive.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.lock().is_ready()
    }

    /// Returns true if the sender has been dropped without sending.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().is_closed()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.inner.lock().receiver_dropped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

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

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Debug)]
    struct NonClone(i32);

    #[derive(Debug)]
    struct TestNoopWaker;

    impl std::task::Wake for TestNoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        tx.send(&cx, 42).expect("send should succeed");
        let value = block_on(rx.recv(&cx)).expect("recv should succeed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn reserve_then_send() {
        init_test("reserve_then_send");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx);
        permit.send(42).expect("send should succeed");

        let value = block_on(rx.recv(&cx)).expect("recv should succeed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("reserve_then_send");
    }

    #[test]
    fn reserve_then_abort() {
        init_test("reserve_then_abort");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx);
        permit.abort();

        let err = rx.try_recv();
        crate::assert_with_log!(
            matches!(err, Err(TryRecvError::Closed)),
            "try_recv closed",
            "Err(Closed)",
            format!("{:?}", err)
        );
        crate::test_complete!("reserve_then_abort");
    }

    #[test]
    fn permit_drop_is_abort() {
        init_test("permit_drop_is_abort");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        {
            let _permit = tx.reserve(&cx);
            // permit dropped here without send or abort
        }

        let err = rx.try_recv();
        crate::assert_with_log!(
            matches!(err, Err(TryRecvError::Closed)),
            "try_recv closed",
            "Err(Closed)",
            format!("{:?}", err)
        );
        crate::test_complete!("permit_drop_is_abort");
    }

    #[test]
    fn sender_dropped_without_send() {
        init_test("sender_dropped_without_send");
        let (tx, rx) = channel::<i32>();
        // Explicitly drop sender without sending
        drop(tx);

        let err = rx.try_recv();
        crate::assert_with_log!(
            matches!(err, Err(TryRecvError::Closed)),
            "try_recv closed",
            "Err(Closed)",
            format!("{:?}", err)
        );
        crate::test_complete!("sender_dropped_without_send");
    }

    #[test]
    fn receiver_dropped_before_send() {
        init_test("receiver_dropped_before_send");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        // Drop receiver first
        drop(rx);

        // Sender should detect disconnection
        let closed = tx.is_closed();
        crate::assert_with_log!(closed, "sender closed", true, closed);

        // Send should fail with value returned
        let err = tx.send(&cx, 42);
        crate::assert_with_log!(
            matches!(err, Err(SendError::Disconnected(42))),
            "send disconnected",
            "Err(Disconnected(42))",
            format!("{:?}", err)
        );
        crate::test_complete!("receiver_dropped_before_send");
    }

    #[test]
    fn try_recv_empty() {
        init_test("try_recv_empty");
        let (tx, rx) = channel::<i32>();

        // Nothing sent yet
        let err = rx.try_recv();
        crate::assert_with_log!(
            matches!(err, Err(TryRecvError::Empty)),
            "try_recv empty",
            "Err(Empty)",
            format!("{:?}", err)
        );

        // Now we don't have receiver, drop sender
        drop(tx);
        crate::test_complete!("try_recv_empty");
    }

    #[test]
    fn try_recv_ready() {
        init_test("try_recv_ready");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        tx.send(&cx, 42).expect("send should succeed");

        let value = rx.try_recv().expect("try_recv should succeed");
        crate::assert_with_log!(value == 42, "try_recv value", 42, value);
        crate::test_complete!("try_recv_ready");
    }

    #[test]
    fn is_ready_and_is_closed() {
        init_test("is_ready_and_is_closed");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let ready = rx.is_ready();
        crate::assert_with_log!(!ready, "not ready", false, ready);
        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "not closed", false, closed);

        tx.send(&cx, 42).expect("send should succeed");

        let ready = rx.is_ready();
        crate::assert_with_log!(ready, "ready after send", true, ready);
        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "still open", false, closed);
        crate::test_complete!("is_ready_and_is_closed");
    }

    #[test]
    fn sender_is_closed() {
        init_test("sender_is_closed");
        let (tx, rx) = channel::<i32>();

        let closed = tx.is_closed();
        crate::assert_with_log!(!closed, "tx open", false, closed);
        drop(rx);
        let closed = tx.is_closed();
        crate::assert_with_log!(closed, "tx closed", true, closed);
        crate::test_complete!("sender_is_closed");
    }

    #[test]
    fn send_error_display() {
        init_test("send_error_display");
        let err = SendError::Disconnected(42);
        let text = err.to_string();
        crate::assert_with_log!(
            text == "sending on a closed oneshot channel",
            "display",
            "sending on a closed oneshot channel",
            text
        );
        crate::test_complete!("send_error_display");
    }

    #[test]
    fn recv_error_display() {
        init_test("recv_error_display");
        let text = RecvError::Closed.to_string();
        crate::assert_with_log!(
            text == "receiving on a closed oneshot channel",
            "display",
            "receiving on a closed oneshot channel",
            text
        );
        crate::test_complete!("recv_error_display");
    }

    #[test]
    fn try_recv_error_display() {
        init_test("try_recv_error_display");
        let empty = TryRecvError::Empty.to_string();
        crate::assert_with_log!(
            empty == "oneshot channel is empty",
            "empty display",
            "oneshot channel is empty",
            empty
        );
        let closed = TryRecvError::Closed.to_string();
        crate::assert_with_log!(
            closed == "oneshot channel is closed",
            "closed display",
            "oneshot channel is closed",
            closed
        );
        crate::test_complete!("try_recv_error_display");
    }

    #[test]
    fn value_is_moved_not_cloned() {
        init_test("value_is_moved_not_cloned");
        // Test that non-Clone types work
        let cx = test_cx();
        let (tx, rx) = channel::<NonClone>();

        tx.send(&cx, NonClone(42)).expect("send should succeed");
        let value = block_on(rx.recv(&cx)).expect("recv should succeed");
        crate::assert_with_log!(value.0 == 42, "value", 42, value.0);
        crate::test_complete!("value_is_moved_not_cloned");
    }

    #[test]
    fn permit_send_returns_error_with_value() {
        init_test("permit_send_returns_error_with_value");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        drop(rx);

        let permit = tx.reserve(&cx);
        let err = permit.send(42);
        crate::assert_with_log!(
            matches!(err, Err(SendError::Disconnected(42))),
            "permit send disconnected",
            "Err(Disconnected(42))",
            format!("{:?}", err)
        );
        crate::test_complete!("permit_send_returns_error_with_value");
    }

    #[test]
    fn recv_with_cancel_pending() {
        init_test("recv_with_cancel_pending");
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let (tx, rx) = channel::<i32>();

        // Sender sends but receiver is cancelled
        tx.send(&cx, 42).expect("send should succeed");

        // Recv should still work because value is ready before checkpoint
        // Actually let me check - the value is ready, so recv should get it
        // before hitting the checkpoint in the wait loop

        // First iteration finds the value
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(result.is_ok(), "recv ok", true, result.is_ok());
        let value = result.unwrap();
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("recv_with_cancel_pending");
    }

    #[test]
    fn recv_cancel_during_wait() {
        init_test("recv_cancel_during_wait");
        let cx = test_cx();

        let (tx, rx) = channel::<i32>();

        // Start with cancel requested - recv will fail at checkpoint
        cx.set_cancel_requested(true);

        // Don't send anything, so recv will hit checkpoint
        let err = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(err, Err(RecvError::Cancelled)),
            "recv cancelled",
            "Err(Cancelled)",
            format!("{:?}", err)
        );

        // Sender should still be usable
        drop(tx);
        crate::test_complete!("recv_cancel_during_wait");
    }

    #[test]
    fn recv_cancel_after_pending_clears_registered_waker() {
        init_test("recv_cancel_after_pending_clears_registered_waker");
        let cx = test_cx();
        let (_tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_poll, Poll::Pending)
        );

        let registered_before_cancel = {
            let inner = rx.inner.lock();
            inner.waker.is_some()
        };
        crate::assert_with_log!(
            registered_before_cancel,
            "waker registered before cancel",
            true,
            registered_before_cancel
        );

        cx.set_cancel_requested(true);
        let cancelled = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(cancelled, Poll::Ready(Err(RecvError::Cancelled))),
            "recv cancelled",
            "Ready(Err(Cancelled))",
            format!("{cancelled:?}")
        );

        let registered_after_cancel = {
            let inner = rx.inner.lock();
            inner.waker.is_some()
        };
        crate::assert_with_log!(
            !registered_after_cancel,
            "waker cleared on cancel",
            false,
            registered_after_cancel
        );

        crate::test_complete!("recv_cancel_after_pending_clears_registered_waker");
    }

    /// Verify that a successful recv clears the stale waker from inner state.
    /// Without this, the waker allocation would be retained until the last Arc
    /// reference drops, unnecessarily pinning executor-internal memory.
    #[test]
    fn recv_value_ready_clears_stale_waker() {
        init_test("recv_value_ready_clears_stale_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        // First poll: no value yet → registers waker, returns Pending
        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(
            rx.inner.lock().waker.is_some(),
            "waker should be registered after Pending"
        );

        // Sender sends
        tx.send(&cx, 99).unwrap();

        // Second poll: value ready → returns Ready(Ok(99))
        let second = fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(second, Poll::Ready(Ok(99))),
            "should receive value"
        );

        // Waker must be cleared
        assert!(
            rx.inner.lock().waker.is_none(),
            "waker should be cleared after successful recv"
        );

        crate::test_complete!("recv_value_ready_clears_stale_waker");
    }

    /// Verify that recv returning Closed clears the stale waker.
    #[test]
    fn recv_closed_clears_stale_waker() {
        init_test("recv_closed_clears_stale_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        // First poll: Pending
        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(rx.inner.lock().waker.is_some());

        // Drop sender → channel closes
        drop(tx);

        // Second poll: Closed
        let second = fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(second, Poll::Ready(Err(RecvError::Closed))),
            "should get Closed"
        );

        // Waker must be cleared
        assert!(
            rx.inner.lock().waker.is_none(),
            "waker should be cleared after Closed recv"
        );

        crate::test_complete!("recv_closed_clears_stale_waker");
    }

    #[test]
    fn try_recv_value_ready_clears_stale_waker() {
        init_test("try_recv_value_ready_clears_stale_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(rx.inner.lock().waker.is_some());

        tx.send(&cx, 99).unwrap();
        let value = rx.try_recv().unwrap();
        crate::assert_with_log!(value == 99, "try_recv value", 99, value);

        assert!(
            rx.inner.lock().waker.is_none(),
            "waker should be cleared after try_recv Ok"
        );

        drop(fut);
        crate::test_complete!("try_recv_value_ready_clears_stale_waker");
    }

    #[test]
    fn try_recv_closed_clears_stale_waker() {
        init_test("try_recv_closed_clears_stale_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(rx.inner.lock().waker.is_some());

        drop(tx);
        let closed = rx.try_recv();
        assert!(matches!(closed, Err(TryRecvError::Closed)));

        assert!(
            rx.inner.lock().waker.is_none(),
            "waker should be cleared after try_recv Closed"
        );

        drop(fut);
        crate::test_complete!("try_recv_closed_clears_stale_waker");
    }

    /// Verify that SendPermit::send handles receiver-already-dropped
    /// path correctly (returns Disconnected, doesn't panic or deadlock).
    #[test]
    fn permit_send_receiver_dropped_clears_waker() {
        init_test("permit_send_receiver_dropped_clears_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        // Poll recv to register a waker, then drop the future.
        // RecvFuture::Drop now clears the stale waker (correct behavior).
        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));
        let poll = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(poll, Poll::Pending));
        drop(fut);

        // Waker was cleared by RecvFuture::Drop
        assert!(
            tx.inner.lock().waker.is_none(),
            "RecvFuture::Drop should clear stale waker"
        );

        // Drop receiver
        drop(rx);

        // Reserve a permit and send (should fail because receiver dropped)
        let permit = tx.reserve(&cx);
        let result = permit.send(42);
        assert!(matches!(result, Err(SendError::Disconnected(42))));

        crate::test_complete!("permit_send_receiver_dropped_clears_waker");
    }

    #[test]
    fn sender_drop_on_poisoned_mutex_does_not_panic() {
        init_test("sender_drop_on_poisoned_mutex_does_not_panic");
        let (tx, _rx) = channel::<i32>();

        // Poison the mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.inner.lock();
            panic!("intentional poison");
        }));

        // Dropping tx should NOT panic.
        drop(tx);
        crate::test_complete!("sender_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn permit_drop_on_poisoned_mutex_does_not_panic() {
        init_test("permit_drop_on_poisoned_mutex_does_not_panic");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>();

        let permit = tx.reserve(&cx);

        // Poison the mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = permit.inner.lock();
            panic!("intentional poison");
        }));

        // Dropping permit should NOT panic.
        drop(permit);
        crate::test_complete!("permit_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn receiver_drop_on_poisoned_mutex_does_not_panic() {
        init_test("receiver_drop_on_poisoned_mutex_does_not_panic");
        let (tx, rx) = channel::<i32>();

        // Poison the mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.inner.lock();
            panic!("intentional poison");
        }));

        // Dropping rx should NOT panic.
        drop(rx);
        drop(tx);
        crate::test_complete!("receiver_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn recv_future_drop_clears_stale_waker() {
        init_test("recv_future_drop_clears_stale_waker");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let waker = Waker::from(std::sync::Arc::new(TestNoopWaker));
        let mut task_cx = Context::from_waker(&waker);

        {
            let mut fut = Box::pin(rx.recv(&cx));
            let poll = fut.as_mut().poll(&mut task_cx);
            assert!(matches!(poll, Poll::Pending));
            assert!(
                rx.inner.lock().waker.is_some(),
                "waker registered after Pending"
            );
            // fut dropped here
        }

        // Waker should be cleared by RecvFuture::Drop
        assert!(
            rx.inner.lock().waker.is_none(),
            "waker cleared after RecvFuture drop"
        );

        // Channel should still work
        tx.send(&cx, 99).unwrap();
        let value = rx.try_recv().unwrap();
        crate::assert_with_log!(value == 99, "recv after drop", 99, value);

        crate::test_complete!("recv_future_drop_clears_stale_waker");
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn recv_returns_value_even_when_cancelled() {
        // Value-ready takes priority over cancellation.
        init_test("recv_returns_value_even_when_cancelled");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        tx.send(&cx, 77).unwrap();
        cx.set_cancel_requested(true);

        // Value is already available → should return Ok, not Cancelled.
        let result = block_on(rx.recv(&cx));
        let ok = matches!(result, Ok(77));
        crate::assert_with_log!(ok, "value over cancel", true, ok);
        crate::test_complete!("recv_returns_value_even_when_cancelled");
    }

    #[test]
    fn is_closed_after_permit_abort() {
        // After reserve + abort, is_closed should be true (no sender, no permit, no value).
        init_test("is_closed_after_permit_abort");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx);
        // At this point: sender_consumed=true, permit_outstanding=true
        let closed_during_permit = rx.is_closed();
        crate::assert_with_log!(
            !closed_during_permit,
            "not closed during permit",
            false,
            closed_during_permit
        );

        permit.abort();
        // Now: sender_consumed=true, permit_outstanding=false, value=None → closed
        let closed_after_abort = rx.is_closed();
        crate::assert_with_log!(
            closed_after_abort,
            "closed after abort",
            true,
            closed_after_abort
        );
        crate::test_complete!("is_closed_after_permit_abort");
    }

    #[test]
    fn try_recv_returns_empty_while_permit_outstanding() {
        // With permit outstanding but no value, try_recv should return Empty (not Closed).
        init_test("try_recv_returns_empty_while_permit_outstanding");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx);

        let result = rx.try_recv();
        let empty_ok = matches!(result, Err(TryRecvError::Empty));
        crate::assert_with_log!(empty_ok, "empty while permit outstanding", true, empty_ok);

        permit.send(42).unwrap();
        let value = rx.try_recv().unwrap();
        crate::assert_with_log!(value == 42, "value after send", 42, value);
        crate::test_complete!("try_recv_returns_empty_while_permit_outstanding");
    }

    #[test]
    fn sender_drop_wakes_pending_receiver() {
        struct CountWaker(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl std::task::Wake for CountWaker {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Dropping the sender should wake a pending receiver.
        init_test("sender_drop_wakes_pending_receiver");

        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let notify_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let poll_waker = Waker::from(std::sync::Arc::new(CountWaker(std::sync::Arc::clone(
            &notify_count,
        ))));
        let mut task_cx = Context::from_waker(&poll_waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let poll = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(poll, Poll::Pending));

        drop(tx); // Should wake the receiver.

        let notifications = notify_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(notifications == 1, "woken once", 1usize, notifications);

        let result = fut.as_mut().poll(&mut task_cx);
        let closed_ok = matches!(result, Poll::Ready(Err(RecvError::Closed)));
        crate::assert_with_log!(closed_ok, "closed after sender drop", true, closed_ok);
        crate::test_complete!("sender_drop_wakes_pending_receiver");
    }

    #[test]
    fn dropping_stale_recv_future_does_not_clear_new_waiter() {
        struct CountWaker(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl std::task::Wake for CountWaker {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        init_test("dropping_stale_recv_future_does_not_clear_new_waiter");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let wake_counter_1 = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_counter_2 = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let recv_waker_1 = Waker::from(std::sync::Arc::new(CountWaker(std::sync::Arc::clone(
            &wake_counter_1,
        ))));
        let recv_waker_2 = Waker::from(std::sync::Arc::new(CountWaker(std::sync::Arc::clone(
            &wake_counter_2,
        ))));

        let mut task_cx_1 = Context::from_waker(&recv_waker_1);
        let mut task_cx_2 = Context::from_waker(&recv_waker_2);
        let mut fut_1 = Box::pin(rx.recv(&cx));
        let mut fut_2 = Box::pin(rx.recv(&cx));

        let poll_1 = fut_1.as_mut().poll(&mut task_cx_1);
        let poll_2 = fut_2.as_mut().poll(&mut task_cx_2);
        crate::assert_with_log!(
            matches!(poll_1, Poll::Pending),
            "first recv pending",
            true,
            matches!(poll_1, Poll::Pending)
        );
        crate::assert_with_log!(
            matches!(poll_2, Poll::Pending),
            "second recv pending",
            true,
            matches!(poll_2, Poll::Pending)
        );

        // Drop stale future; this must not clear fut_2's waiter registration.
        drop(fut_1);

        tx.send(&cx, 5).expect("send should succeed");

        let wake_count_1 = wake_counter_1.load(std::sync::atomic::Ordering::SeqCst);
        let wake_count_2 = wake_counter_2.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(
            wake_count_1 == 0,
            "stale waiter not woken",
            0usize,
            wake_count_1
        );
        crate::assert_with_log!(
            wake_count_2 == 1,
            "active waiter woken once",
            1usize,
            wake_count_2
        );

        let result = fut_2.as_mut().poll(&mut task_cx_2);
        crate::assert_with_log!(
            matches!(result, Poll::Ready(Ok(5))),
            "active future receives value",
            "Ready(Ok(5))",
            format!("{result:?}")
        );
        crate::test_complete!("dropping_stale_recv_future_does_not_clear_new_waiter");
    }
}
