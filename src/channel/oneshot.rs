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
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
}

impl<T> OneShotInner<T> {
    fn new() -> Self {
        Self {
            value: None,
            sender_consumed: false,
            receiver_dropped: false,
            permit_outstanding: false,
            waker: None,
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
            let mut inner = self.inner.lock().expect("oneshot lock poisoned");
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
        self.inner
            .lock()
            .expect("oneshot lock poisoned")
            .receiver_dropped
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut inner = self.inner.lock().expect("oneshot lock poisoned");
            if inner.sender_consumed {
                None
            } else {
                inner.sender_consumed = true;
                // Take waker under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                inner.waker.take()
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
            let mut inner = self.inner.lock().expect("oneshot lock poisoned");

            if inner.receiver_dropped {
                // Receiver gone, return the value
                inner.permit_outstanding = false;
                (Err(value), None)
            } else {
                inner.value = Some(value);
                inner.permit_outstanding = false;
                // Take waker under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                let waker = inner.waker.take();
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
            let mut inner = self.inner.lock().expect("oneshot lock poisoned");
            inner.permit_outstanding = false;
            // Take waker under lock, wake outside.
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        self.sent = true; // Prevent drop from double-aborting
    }

    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .expect("oneshot lock poisoned")
            .receiver_dropped
    }
}

impl<T> Drop for SendPermit<T> {
    fn drop(&mut self) {
        if !self.sent {
            // Permit dropped without sending - abort
            let waker = {
                let mut inner = self.inner.lock().expect("oneshot lock poisoned");
                inner.permit_outstanding = false;
                inner.waker.take()
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
}

impl<T> Future for RecvFuture<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.receiver.inner.lock().expect("oneshot lock poisoned");

        // 1. Check if value is ready
        if let Some(value) = inner.value.take() {
            self.cx.trace("oneshot::recv received value");
            return Poll::Ready(Ok(value));
        }

        // 2. Check if channel is closed
        if inner.is_closed() {
            self.cx.trace("oneshot::recv channel closed");
            return Poll::Ready(Err(RecvError::Closed));
        }

        // 3. Check cancellation
        if self.cx.checkpoint().is_err() {
            // Clear stale waiter if this future registered it.
            if inner
                .waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(ctx.waker()))
            {
                inner.waker = None;
            }
            self.cx.trace("oneshot::recv cancelled while waiting");
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        // 4. Register waker (skip clone if unchanged — common on re-poll)
        match &inner.waker {
            Some(existing) if existing.will_wake(ctx.waker()) => {}
            _ => inner.waker = Some(ctx.waker().clone()),
        }
        Poll::Pending
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
        RecvFuture { receiver: self, cx }
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `TryRecvError::Empty` if no value is available yet but sender exists
    /// - `TryRecvError::Closed` if the sender was dropped without sending
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut inner = self.inner.lock().expect("oneshot lock poisoned");

        inner.value.take().map_or_else(
            || {
                if inner.is_closed() {
                    Err(TryRecvError::Closed)
                } else {
                    Err(TryRecvError::Empty)
                }
            },
            Ok,
        )
    }

    /// Returns true if a value is ready to receive.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.lock().expect("oneshot lock poisoned").is_ready()
    }

    /// Returns true if the sender has been dropped without sending.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .expect("oneshot lock poisoned")
            .is_closed()
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("oneshot lock poisoned");
        inner.receiver_dropped = true;
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
            let inner = rx.inner.lock().expect("oneshot lock poisoned");
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
            let inner = rx.inner.lock().expect("oneshot lock poisoned");
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
}
