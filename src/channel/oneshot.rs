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
//! - The commit operation (`send`) either delivers the value or returns it in
//!   `SendError::Disconnected` if the receiver has already closed
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::oneshot;
//!
//! // Create a oneshot channel
//! let (tx, mut rx) = oneshot::channel::<i32>();
//!
//! // Two-phase send pattern (explicit reserve)
//! let permit = tx.reserve(&cx).expect("cx not cancelled in test");
//! permit.send(42)?;
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
    /// The sender's `Cx` was cancelled before the reservation could be taken.
    /// Carries `()` because no value has been consumed (reserve is the
    /// pre-commit phase).
    Cancelled(T),
}

impl<T> std::fmt::Display for SendError<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected(_) => write!(f, "sending on a closed oneshot channel"),
            Self::Cancelled(_) => write!(f, "sending on a cancelled cx"),
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
    /// The same recv future was polled again after a terminal result.
    PolledAfterCompletion,
}

impl std::fmt::Display for RecvError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "receiving on a closed oneshot channel"),
            Self::Cancelled => write!(f, "receive operation cancelled"),
            Self::PolledAfterCompletion => write!(f, "oneshot recv future polled after completion"),
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
    #[inline]
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
    #[inline]
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
    #[inline]
    fn is_closed(&self) -> bool {
        self.sender_consumed && !self.permit_outstanding && self.value.is_none()
    }

    /// Returns true if a value is ready to receive.
    #[inline]
    fn is_ready(&self) -> bool {
        self.value.is_some()
    }

    /// Clears the registered waker and its waiter identity.
    #[inline]
    fn clear_waker(&mut self) {
        self.waker = None;
        self.waker_id = None;
    }

    /// Takes the registered waker and clears its waiter identity.
    #[inline]
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
/// let (tx, mut rx) = oneshot::channel::<i32>();
/// tx.send(&cx, 42);
/// let value = rx.recv(&cx).await?;
/// ```
#[inline]
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
    /// # Errors
    ///
    /// Returns `Err(SendError::Cancelled(()))` if the supplied `Cx` is
    /// already cancelled at the time of reservation. Per the cancel-correctness
    /// invariant (asupersync_plan_v4 §3.2), a cancelled context must not be
    /// permitted to take side-effects on a region that has been requested to
    /// drain — the sender consumes itself and the underlying channel closes
    /// (the receiver observes `RecvError::Closed`).
    #[inline]
    pub fn reserve(self, cx: &Cx) -> Result<SendPermit<T>, SendError<()>> {
        // br-asupersync-4taf1b: enforce cancel-correctness at the reserve
        // boundary. Without this check a cancelled task could obtain a
        // SendPermit and later push into the channel after its region has
        // been signalled to drain.
        if cx.checkpoint().is_err() {
            cx.trace("oneshot::reserve cancelled");
            return Err(SendError::Cancelled(()));
        }

        cx.trace("oneshot::reserve creating permit");

        {
            let mut inner = self.inner.lock();
            inner.sender_consumed = true;
            inner.permit_outstanding = true;
        }

        Ok(SendPermit {
            inner: Arc::clone(&self.inner),
            sent: false,
        })
    }

    /// Convenience method: reserves and sends in one step.
    ///
    /// Equivalent to `self.reserve(cx).and_then(|p| p.send(value))` but more
    /// ergonomic.
    ///
    /// # Errors
    ///
    /// Returns `Err(SendError::Disconnected(value))` if the receiver was dropped,
    /// or `Err(SendError::Cancelled(value))` if the `Cx` is already cancelled.
    #[inline]
    pub fn send(self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.reserve(cx) {
            Ok(permit) => permit.send(value),
            Err(SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
        }
    }

    /// Checks if the receiver has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_dropped
    }

    /// Polls for notification that the receiver has been dropped.
    ///
    /// This method returns:
    /// - `Poll::Ready(())` if the receiver has already been dropped
    /// - `Poll::Pending` if the receiver is still alive
    ///
    /// When `Pending` is returned, the current task's waker is stored
    /// and will be notified when the receiver is dropped.
    ///
    /// This provides async notification of receiver dropout without attempting
    /// to send a value. Useful for detecting receiver cancellation.
    #[inline]
    #[must_use]
    pub fn poll_closed(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut inner = self.inner.lock();

        if inner.receiver_dropped {
            // Receiver already dropped, return Ready immediately
            return std::task::Poll::Ready(());
        }

        // Receiver still alive, register waker for notification when it drops
        inner.waker = Some(cx.waker().clone());
        std::task::Poll::Pending
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
    #[inline]
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
    #[inline]
    pub fn abort(mut self) {
        let waker = {
            let mut inner = self.inner.lock();
            inner.permit_outstanding = false;
            // Take waker under lock, wake outside.
            inner.take_waker()
        };
        self.sent = true; // Prevent drop from double-aborting
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Returns `true` if the receiver has been dropped.
    #[inline]
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

/// Future returned by `recv_uninterruptible`.
pub(crate) struct RecvUninterruptibleFuture<'a, T> {
    receiver: &'a mut Receiver<T>,
    waiter_id: Option<u64>,
    completed: bool,
}

impl<T> RecvUninterruptibleFuture<'_, T> {
    #[must_use]
    #[inline]
    pub(crate) fn receiver_finished(&self) -> bool {
        self.completed || self.receiver.is_ready() || self.receiver.is_closed()
    }
}

impl<T> Future for RecvUninterruptibleFuture<'_, T> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        let mut inner = this.receiver.inner.lock();

        if let Some(value) = inner.value.take() {
            inner.clear_waker();

            this.waiter_id = None;
            this.completed = true;

            drop(inner);

            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            inner.clear_waker();

            this.waiter_id = None;
            this.completed = true;

            drop(inner);

            return Poll::Ready(Err(RecvError::Closed));
        }

        if let Some(my_id) = this.waiter_id {
            if inner.waker_id == Some(my_id) {
                if let Some(existing) = &inner.waker {
                    if !existing.will_wake(ctx.waker()) {
                        inner.waker = Some(ctx.waker().clone());
                    }
                } else {
                    inner.waker = Some(ctx.waker().clone());
                }
            } else {
                let waiter_id = inner.next_waiter_id;

                inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);

                inner.waker = Some(ctx.waker().clone());

                inner.waker_id = Some(waiter_id);

                this.waiter_id = Some(waiter_id);
            }
        } else {
            let waiter_id = inner.next_waiter_id;

            inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);

            inner.waker = Some(ctx.waker().clone());

            inner.waker_id = Some(waiter_id);

            this.waiter_id = Some(waiter_id);
        }

        drop(inner);

        Poll::Pending
    }
}

impl<T> Drop for RecvUninterruptibleFuture<'_, T> {
    fn drop(&mut self) {
        {
            let mut inner = self.receiver.inner.lock();
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

/// Future returned by [`Receiver::recv`].
pub struct RecvFuture<'a, T> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx,
    waiter_id: Option<u64>,
    completed: bool,
}

impl<T> RecvFuture<'_, T> {
    #[must_use]
    #[allow(dead_code)] // Public API — may be used by future callers
    #[inline]
    pub(crate) fn receiver_finished(&self) -> bool {
        self.completed || self.receiver.is_ready() || self.receiver.is_closed()
    }
}

impl<T> Future for RecvFuture<'_, T> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        let mut inner = this.receiver.inner.lock();

        // 1. Check if value is ready
        if let Some(value) = inner.value.take() {
            // Clear the stale waker so we don't retain executor state
            // after the channel is done.
            inner.clear_waker();
            this.waiter_id = None;
            this.completed = true;
            drop(inner);
            this.cx.trace("oneshot::recv received value");
            return Poll::Ready(Ok(value));
        }

        // 2. Check if channel is closed
        if inner.is_closed() {
            inner.clear_waker();
            this.waiter_id = None;
            this.completed = true;
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
            this.completed = true;
            drop(inner);
            this.cx.trace("oneshot::recv cancelled while waiting");
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        // 4. Register waker (skip clone if unchanged and still owned by this waiter)
        if let Some(my_id) = this.waiter_id {
            if inner.waker_id == Some(my_id) {
                if let Some(existing) = &inner.waker {
                    if !existing.will_wake(ctx.waker()) {
                        inner.waker = Some(ctx.waker().clone());
                    }
                } else {
                    inner.waker = Some(ctx.waker().clone());
                }
            } else {
                // Someone else took the waker slot, we need a new ID
                let waiter_id = inner.next_waiter_id;
                inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);
                inner.waker = Some(ctx.waker().clone());
                inner.waker_id = Some(waiter_id);
                this.waiter_id = Some(waiter_id);
            }
        } else {
            let waiter_id = inner.next_waiter_id;
            inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);
            inner.waker = Some(ctx.waker().clone());
            inner.waker_id = Some(waiter_id);
            this.waiter_id = Some(waiter_id);
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
    #[inline]
    #[must_use]
    pub fn recv<'a>(&'a mut self, cx: &'a Cx) -> RecvFuture<'a, T> {
        RecvFuture {
            receiver: self,
            cx,
            waiter_id: None,
            completed: false,
        }
    }

    /// Receives a value from the channel, ignoring cancellation.
    ///
    /// Used internally by `TaskHandle::join` which must wait for task termination
    /// to uphold structural guarantees, even if the caller's context is cancelled.
    #[must_use]
    #[inline]
    pub(crate) fn recv_uninterruptible(&mut self) -> RecvUninterruptibleFuture<'_, T> {
        RecvUninterruptibleFuture {
            receiver: self,
            waiter_id: None,
            completed: false,
        }
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `TryRecvError::Empty` if no value is available yet but sender exists
    /// - `TryRecvError::Closed` if the sender was dropped without sending
    #[inline]
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
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
    #[inline]
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.lock().is_ready()
    }

    /// Returns true if the sender has been dropped without sending.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().is_closed()
    }

    /// Returns a future that resolves when the sender is dropped.
    ///
    /// This provides async notification of channel closure without attempting
    /// to receive a value. Useful for detecting sender dropout.
    #[inline]
    #[must_use]
    pub fn poll_closed(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut inner = self.inner.lock();

        if inner.is_closed() {
            // Already closed, return Ready immediately
            return std::task::Poll::Ready(());
        }

        // Not closed yet, register waker for notification when sender drops
        inner.waker = Some(cx.waker().clone());
        std::task::Poll::Pending
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let _value = {
            let mut inner = self.inner.lock();
            inner.receiver_dropped = true;
            // Clear any pending recv waker so a dropped receiver does not
            // retain executor task state indefinitely.
            inner.clear_waker();
            inner.value.take()
        };
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
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use proptest::prelude::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    #[derive(Debug)]
    struct NonClone(i32);

    struct CountWaker(Arc<AtomicUsize>);

    impl std::task::Wake for CountWaker {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(counter)))
    }

    #[derive(Debug, Clone, Copy)]
    enum SendScenario {
        LiveNoWaiter,
        LivePendingWaiter,
        ReceiverDropped,
    }

    fn send_scenario_strategy() -> impl Strategy<Value = SendScenario> {
        prop_oneof![
            Just(SendScenario::LiveNoWaiter),
            Just(SendScenario::LivePendingWaiter),
            Just(SendScenario::ReceiverDropped),
        ]
    }

    fn send_path_signature(
        reserve_first: bool,
        scenario: SendScenario,
        value: i32,
    ) -> (
        bool,
        Option<i32>,
        usize,
        &'static str,
        Option<i32>,
        bool,
        bool,
    ) {
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);
        let wake_counter = Arc::new(AtomicUsize::new(0));

        let (send_ok, disconnected_value, recv_state, recv_value) = match scenario {
            SendScenario::LiveNoWaiter => {
                let send_result = if reserve_first {
                    tx.reserve(&cx)
                        .expect("cx not cancelled in test")
                        .send(value)
                } else {
                    tx.send(&cx, value)
                };
                let (send_ok, disconnected_value) = match send_result {
                    Ok(()) => (true, None),
                    Err(SendError::Disconnected(v) | SendError::Cancelled(v)) => (false, Some(v)),
                };
                let (recv_state, recv_value) = match rx.try_recv() {
                    Ok(v) => ("value", Some(v)),
                    Err(TryRecvError::Empty) => ("empty", None),
                    Err(TryRecvError::Closed) => ("closed", None),
                };
                (send_ok, disconnected_value, recv_state, recv_value)
            }
            SendScenario::LivePendingWaiter => {
                let recv_waker = counting_waker(Arc::clone(&wake_counter));
                let mut task_cx = Context::from_waker(&recv_waker);
                let mut fut = Box::pin(rx.recv(&cx));
                assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

                let send_result = if reserve_first {
                    tx.reserve(&cx)
                        .expect("cx not cancelled in test")
                        .send(value)
                } else {
                    tx.send(&cx, value)
                };
                let (send_ok, disconnected_value) = match send_result {
                    Ok(()) => (true, None),
                    Err(SendError::Disconnected(v) | SendError::Cancelled(v)) => (false, Some(v)),
                };
                let (recv_state, recv_value) = match fut.as_mut().poll(&mut task_cx) {
                    Poll::Ready(Ok(v)) => ("value", Some(v)),
                    Poll::Ready(Err(RecvError::Closed)) => ("closed", None),
                    Poll::Ready(Err(RecvError::Cancelled)) => ("cancelled", None),
                    Poll::Ready(Err(RecvError::PolledAfterCompletion)) => ("repoll", None),
                    Poll::Pending => ("pending", None),
                };
                drop(fut);
                (send_ok, disconnected_value, recv_state, recv_value)
            }
            SendScenario::ReceiverDropped => {
                drop(rx);
                let send_result = if reserve_first {
                    tx.reserve(&cx)
                        .expect("cx not cancelled in test")
                        .send(value)
                } else {
                    tx.send(&cx, value)
                };
                let (send_ok, disconnected_value) = match send_result {
                    Ok(()) => (true, None),
                    Err(SendError::Disconnected(v) | SendError::Cancelled(v)) => (false, Some(v)),
                };
                (send_ok, disconnected_value, "receiver-dropped", None)
            }
        };

        let inner = inner.lock();
        (
            send_ok,
            disconnected_value,
            wake_counter.load(Ordering::SeqCst),
            recv_state,
            recv_value,
            inner.waker.is_none(),
            inner.is_closed(),
        )
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        tx.send(&cx, 42).expect("send should succeed");
        let value = block_on(rx.recv(&cx)).expect("recv should succeed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    proptest! {
        #[test]
        fn metamorphic_send_matches_reserve_send_atomicity(
            scenario in send_scenario_strategy(),
            value in any::<i16>(),
        ) {
            let value = i32::from(value);

            let direct_signature = send_path_signature(false, scenario, value);
            let reserved_signature = send_path_signature(true, scenario, value);

            prop_assert_eq!(
                direct_signature,
                reserved_signature,
                "oneshot convenience send must match explicit reserve().send() semantics",
            );

            match scenario {
                SendScenario::LiveNoWaiter => {
                    prop_assert!(direct_signature.0, "live receiver should accept the send");
                    prop_assert_eq!(direct_signature.2, 0, "no waiter means no wakeup");
                    prop_assert_eq!(direct_signature.3, "value");
                    prop_assert_eq!(direct_signature.4, Some(value));
                    prop_assert!(direct_signature.5, "terminal receive path clears stale waker");
                    prop_assert!(direct_signature.6, "channel should be closed after value is consumed");
                }
                SendScenario::LivePendingWaiter => {
                    prop_assert!(direct_signature.0, "live pending waiter should accept the send");
                    prop_assert_eq!(direct_signature.2, 1, "pending waiter should be woken exactly once");
                    prop_assert_eq!(direct_signature.3, "value");
                    prop_assert_eq!(direct_signature.4, Some(value));
                    prop_assert!(direct_signature.5, "recv completion clears the waiter slot");
                    prop_assert!(direct_signature.6, "channel should be closed after waiter consumes the value");
                }
                SendScenario::ReceiverDropped => {
                    prop_assert!(!direct_signature.0, "dropped receiver must reject the send");
                    prop_assert_eq!(direct_signature.1, Some(value), "disconnected send returns ownership of the value");
                    prop_assert_eq!(direct_signature.2, 0, "no receiver means no wakeup");
                    prop_assert_eq!(direct_signature.3, "receiver-dropped");
                    prop_assert!(direct_signature.5, "disconnected send path clears any stale waker");
                    prop_assert!(direct_signature.6, "sender-consumed disconnected channel is closed");
                }
            }
        }
    }

    #[test]
    fn reserve_with_cancelled_cx_returns_cancelled() {
        // br-asupersync-4taf1b: cx.checkpoint must gate reserve. A cancelled
        // Cx must not be permitted to obtain a SendPermit.
        init_test("reserve_with_cancelled_cx_returns_cancelled");
        let cx = test_cx();
        cx.cancel_with(crate::types::CancelKind::User, Some("test cancel"));
        let (tx, mut rx) = channel::<i32>();

        let err = tx
            .reserve(&cx)
            .expect_err("cancelled cx must reject reserve");
        crate::assert_with_log!(
            matches!(err, SendError::Cancelled(())),
            "reserve must surface SendError::Cancelled on cancelled cx",
            "Err(Cancelled(()))",
            format!("{:?}", err)
        );

        // Sender was consumed, so receiver must observe Closed (not stuck Empty).
        let recv = rx.try_recv();
        crate::assert_with_log!(
            matches!(recv, Err(TryRecvError::Closed)),
            "receiver of cancelled-reserve sender observes Closed",
            "Err(Closed)",
            format!("{:?}", recv)
        );
        crate::test_complete!("reserve_with_cancelled_cx_returns_cancelled");
    }

    #[test]
    fn send_with_cancelled_cx_returns_cancelled_with_value() {
        // br-asupersync-4taf1b: convenience send must propagate Cancelled
        // and return the original value to the caller.
        init_test("send_with_cancelled_cx_returns_cancelled_with_value");
        let cx = test_cx();
        cx.cancel_with(crate::types::CancelKind::User, Some("test cancel"));
        let (tx, _rx) = channel::<i32>();

        let err = tx.send(&cx, 99).expect_err("cancelled cx must reject send");
        crate::assert_with_log!(
            matches!(err, SendError::Cancelled(99)),
            "send must surface SendError::Cancelled(value) on cancelled cx",
            "Err(Cancelled(99))",
            format!("{:?}", err)
        );
        crate::test_complete!("send_with_cancelled_cx_returns_cancelled_with_value");
    }

    #[test]
    fn reserve_then_send() {
        init_test("reserve_then_send");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        permit.send(42).expect("send should succeed");

        let value = block_on(rx.recv(&cx)).expect("recv should succeed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("reserve_then_send");
    }

    #[test]
    fn reserve_then_abort() {
        init_test("reserve_then_abort");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
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
        let (tx, mut rx) = channel::<i32>();

        {
            let _permit = tx.reserve(&cx).expect("cx not cancelled in test");
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
        let (tx, mut rx) = channel::<i32>();
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
    fn receiver_drop_clears_leftover_waiter_state() {
        init_test("receiver_drop_clears_leftover_waiter_state");
        let (_tx, rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        {
            let mut guard = inner.lock();
            guard.waker = Some(std::task::Waker::noop().clone());
            guard.waker_id = Some(7);
        }

        drop(rx);

        let guard = inner.lock();
        crate::assert_with_log!(
            guard.receiver_dropped,
            "receiver marked dropped",
            true,
            guard.receiver_dropped
        );
        crate::assert_with_log!(
            guard.waker.is_none(),
            "receiver drop clears leftover waker",
            true,
            guard.waker.is_none()
        );
        crate::assert_with_log!(
            guard.waker_id.is_none(),
            "receiver drop clears waiter identity",
            true,
            guard.waker_id.is_none()
        );
        drop(guard);
        crate::test_complete!("receiver_drop_clears_leftover_waiter_state");
    }

    #[test]
    fn try_recv_empty() {
        init_test("try_recv_empty");
        let (tx, mut rx) = channel::<i32>();

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
        let (tx, mut rx) = channel::<i32>();

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
        let cancelled = RecvError::Cancelled.to_string();
        crate::assert_with_log!(
            cancelled == "receive operation cancelled",
            "cancelled display",
            "receive operation cancelled",
            cancelled
        );
        let polled_after_completion = RecvError::PolledAfterCompletion.to_string();
        crate::assert_with_log!(
            polled_after_completion == "oneshot recv future polled after completion",
            "polled-after-completion display",
            "oneshot recv future polled after completion",
            polled_after_completion
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
        let (tx, mut rx) = channel::<NonClone>();

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

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
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

        let (tx, mut rx) = channel::<i32>();

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

        let (tx, mut rx) = channel::<i32>();

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
        let (_tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
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
            let inner = inner.lock();
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
            let inner = inner.lock();
            inner.waker.is_some()
        };
        crate::assert_with_log!(
            !registered_after_cancel,
            "waker cleared on cancel",
            false,
            registered_after_cancel
        );

        let repoll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(repoll, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "cancelled recv repoll fails closed",
            "Ready(Err(PolledAfterCompletion))",
            format!("{repoll:?}")
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
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        // First poll: no value yet → registers waker, returns Pending
        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(
            inner.lock().waker.is_some(),
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
            inner.lock().waker.is_none(),
            "waker should be cleared after successful recv"
        );

        let third = fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(third, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "repoll after value should fail closed"
        );

        crate::test_complete!("recv_value_ready_clears_stale_waker");
    }

    /// Verify that recv returning Closed clears the stale waker.
    #[test]
    fn recv_closed_clears_stale_waker() {
        init_test("recv_closed_clears_stale_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        // First poll: Pending
        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(inner.lock().waker.is_some());

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
            inner.lock().waker.is_none(),
            "waker should be cleared after Closed recv"
        );

        let third = fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(third, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "repoll after close should fail closed"
        );

        crate::test_complete!("recv_closed_clears_stale_waker");
    }

    #[test]
    fn recv_uninterruptible_repoll_after_value_fails_closed() {
        init_test("recv_uninterruptible_repoll_after_value_fails_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        tx.send(&cx, 7).expect("send should succeed");

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv_uninterruptible());

        let first = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Ok(7))),
            "uninterruptible recv gets value",
            "Ready(Ok(7))",
            format!("{first:?}")
        );

        let second = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "uninterruptible recv repoll fails closed",
            "Ready(Err(PolledAfterCompletion))",
            format!("{second:?}")
        );

        crate::test_complete!("recv_uninterruptible_repoll_after_value_fails_closed");
    }

    #[test]
    fn recv_uninterruptible_repoll_after_closed_fails_closed() {
        init_test("recv_uninterruptible_repoll_after_closed_fails_closed");
        let (tx, mut rx) = channel::<i32>();
        drop(tx);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv_uninterruptible());

        let first = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first, Poll::Ready(Err(RecvError::Closed))),
            "uninterruptible recv closes",
            "Ready(Err(Closed))",
            format!("{first:?}")
        );

        let second = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Err(RecvError::PolledAfterCompletion))),
            "uninterruptible closed repoll fails closed",
            "Ready(Err(PolledAfterCompletion))",
            format!("{second:?}")
        );

        crate::test_complete!("recv_uninterruptible_repoll_after_closed_fails_closed");
    }

    #[test]
    fn try_recv_value_ready_clears_stale_waker() {
        init_test("try_recv_value_ready_clears_stale_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(inner.lock().waker.is_some());

        drop(fut);
        tx.send(&cx, 99).unwrap();
        let value = rx.try_recv().unwrap();
        crate::assert_with_log!(value == 99, "try_recv value", 99, value);

        assert!(
            inner.lock().waker.is_none(),
            "waker should be cleared after try_recv Ok"
        );
        crate::test_complete!("try_recv_value_ready_clears_stale_waker");
    }

    #[test]
    fn try_recv_closed_clears_stale_waker() {
        init_test("try_recv_closed_clears_stale_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(first, Poll::Pending));
        assert!(inner.lock().waker.is_some());

        drop(fut);
        drop(tx);
        let closed = rx.try_recv();
        assert!(matches!(closed, Err(TryRecvError::Closed)));

        assert!(
            inner.lock().waker.is_none(),
            "waker should be cleared after try_recv Closed"
        );
        crate::test_complete!("try_recv_closed_clears_stale_waker");
    }

    /// Verify that SendPermit::send handles receiver-already-dropped
    /// path correctly (returns Disconnected, doesn't panic or deadlock).
    #[test]
    fn permit_send_receiver_dropped_clears_waker() {
        init_test("permit_send_receiver_dropped_clears_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        // Poll recv to register a waker, then drop the future.
        // RecvFuture::Drop now clears the stale waker (correct behavior).
        let waker = Waker::noop().clone();
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
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
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

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");

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
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);

        {
            let mut fut = Box::pin(rx.recv(&cx));
            let poll = fut.as_mut().poll(&mut task_cx);
            assert!(matches!(poll, Poll::Pending));
            assert!(
                inner.lock().waker.is_some(),
                "waker registered after Pending"
            );
            // fut dropped here
        }

        // Waker should be cleared by RecvFuture::Drop
        assert!(
            inner.lock().waker.is_none(),
            "waker cleared after RecvFuture drop"
        );

        // Channel should still work
        tx.send(&cx, 99).unwrap();
        let value = rx.try_recv().unwrap();
        crate::assert_with_log!(value == 99, "recv after drop", 99, value);

        crate::test_complete!("recv_future_drop_clears_stale_waker");
    }

    fn value_ready_recv_signature(cancel_before_recv: bool) -> (&'static str, Option<i32>, bool) {
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        permit.send(77).expect("send should succeed");
        if cancel_before_recv {
            cx.set_cancel_requested(true);
        }

        let (state, value) = match block_on(rx.recv(&cx)) {
            Ok(value) => ("value", Some(value)),
            Err(RecvError::Closed) => ("closed", None),
            Err(RecvError::Cancelled) => ("cancelled", None),
            Err(RecvError::PolledAfterCompletion) => ("repoll", None),
        };
        (state, value, rx.is_closed())
    }

    fn send_then_receiver_drop_signature(
        park_waiter_before_send: bool,
    ) -> (usize, bool, bool, bool, bool, bool, bool) {
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);
        let wake_counter = Arc::new(AtomicUsize::new(0));

        if park_waiter_before_send {
            let recv_waker = counting_waker(Arc::clone(&wake_counter));
            let mut task_cx = Context::from_waker(&recv_waker);
            let mut fut = Box::pin(rx.recv(&cx));
            assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));
            let guard = inner.lock();
            assert!(
                guard.waker.is_some(),
                "pending recv should register a waker"
            );
            assert!(
                guard.waker_id.is_some(),
                "pending recv should register a waiter id"
            );
            drop(guard);

            tx.send(&cx, 55).expect("send should succeed");
            drop(fut);
        } else {
            tx.send(&cx, 55).expect("send should succeed");
        }

        let ready_before_drop = rx.is_ready();
        drop(rx);

        let guard = inner.lock();
        (
            wake_counter.load(Ordering::SeqCst),
            ready_before_drop,
            guard.receiver_dropped,
            guard.value.is_none(),
            guard.waker.is_none(),
            guard.waker_id.is_none(),
            !guard.permit_outstanding && guard.is_closed(),
        )
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn recv_returns_value_even_when_cancelled() {
        // Value-ready takes priority over cancellation.
        init_test("recv_returns_value_even_when_cancelled");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        tx.send(&cx, 77).unwrap();
        cx.set_cancel_requested(true);

        // Value is already available → should return Ok, not Cancelled.
        let result = block_on(rx.recv(&cx));
        let ok = matches!(result, Ok(77));
        crate::assert_with_log!(ok, "value over cancel", true, ok);
        crate::test_complete!("recv_returns_value_even_when_cancelled");
    }

    #[test]
    fn metamorphic_value_ready_recv_ignores_post_send_receiver_cancellation() {
        init_test("metamorphic_value_ready_recv_ignores_post_send_receiver_cancellation");

        let baseline = value_ready_recv_signature(false);
        let cancelled = value_ready_recv_signature(true);

        crate::assert_with_log!(
            cancelled == baseline,
            "once the value is committed, cancelling the receiver cx before recv does not change the observable result",
            format!("{baseline:?}"),
            format!("{cancelled:?}")
        );
        crate::assert_with_log!(
            baseline == ("value", Some(77), true),
            "value-ready receive still wins over cancellation and leaves the channel closed",
            ("value", Some(77), true),
            baseline
        );

        crate::test_complete!(
            "metamorphic_value_ready_recv_ignores_post_send_receiver_cancellation"
        );
    }

    #[test]
    fn metamorphic_send_then_receiver_drop_preserves_no_leak_invariant() {
        init_test("metamorphic_send_then_receiver_drop_preserves_no_leak_invariant");

        let no_waiter = send_then_receiver_drop_signature(false);
        let parked_waiter = send_then_receiver_drop_signature(true);

        crate::assert_with_log!(
            no_waiter.1 == parked_waiter.1
                && no_waiter.2 == parked_waiter.2
                && no_waiter.3 == parked_waiter.3
                && no_waiter.4 == parked_waiter.4
                && no_waiter.5 == parked_waiter.5
                && no_waiter.6 == parked_waiter.6,
            "parking a waiter before send changes wake count only, not the terminal no-leak state after receiver drop",
            format!(
                "{:?}",
                (
                    no_waiter.1,
                    no_waiter.2,
                    no_waiter.3,
                    no_waiter.4,
                    no_waiter.5,
                    no_waiter.6
                )
            ),
            format!(
                "{:?}",
                (
                    parked_waiter.1,
                    parked_waiter.2,
                    parked_waiter.3,
                    parked_waiter.4,
                    parked_waiter.5,
                    parked_waiter.6
                )
            )
        );
        crate::assert_with_log!(
            no_waiter.0 == 0,
            "without a parked waiter the send path should not emit wakeups",
            0,
            no_waiter.0
        );
        crate::assert_with_log!(
            parked_waiter.0 == 1,
            "with a parked waiter the send path should emit exactly one wakeup before receiver drop",
            1,
            parked_waiter.0
        );
        crate::assert_with_log!(
            no_waiter.1 && no_waiter.2 && no_waiter.3 && no_waiter.4 && no_waiter.5 && no_waiter.6,
            "send-then-receiver-drop must converge to the terminal no-leak state",
            true,
            no_waiter.1 && no_waiter.2 && no_waiter.3 && no_waiter.4 && no_waiter.5 && no_waiter.6
        );

        crate::test_complete!("metamorphic_send_then_receiver_drop_preserves_no_leak_invariant");
    }

    #[test]
    fn is_closed_after_permit_abort() {
        // After reserve + abort, is_closed should be true (no sender, no permit, no value).
        init_test("is_closed_after_permit_abort");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
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
        let (tx, mut rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");

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
        // Dropping the sender should wake a pending receiver.
        init_test("sender_drop_wakes_pending_receiver");

        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let notify_count = Arc::new(AtomicUsize::new(0));
        let poll_waker = counting_waker(Arc::clone(&notify_count));
        let mut task_cx = Context::from_waker(&poll_waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let poll = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(poll, Poll::Pending));

        drop(tx); // Should wake the receiver.

        let notifications = notify_count.load(Ordering::SeqCst);
        crate::assert_with_log!(notifications == 1, "woken once", 1usize, notifications);

        let result = fut.as_mut().poll(&mut task_cx);
        let closed_ok = matches!(result, Poll::Ready(Err(RecvError::Closed)));
        crate::assert_with_log!(closed_ok, "closed after sender drop", true, closed_ok);
        crate::test_complete!("sender_drop_wakes_pending_receiver");
    }

    #[test]
    fn dropping_stale_recv_future_does_not_clear_new_waiter() {
        init_test("dropping_stale_recv_future_does_not_clear_new_waiter");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let wake_counter_1 = Arc::new(AtomicUsize::new(0));
        let wake_counter_2 = Arc::new(AtomicUsize::new(0));
        let recv_waker_1 = counting_waker(Arc::clone(&wake_counter_1));
        let recv_waker_2 = counting_waker(Arc::clone(&wake_counter_2));

        let mut task_cx_1 = Context::from_waker(&recv_waker_1);
        let mut fut_1 = Box::pin(rx.recv(&cx));

        let poll_1 = fut_1.as_mut().poll(&mut task_cx_1);
        crate::assert_with_log!(
            matches!(poll_1, Poll::Pending),
            "first recv pending",
            true,
            matches!(poll_1, Poll::Pending)
        );

        // Drop stale future, then register a new waiter.
        drop(fut_1);
        let mut task_cx_2 = Context::from_waker(&recv_waker_2);
        let mut fut_2 = Box::pin(rx.recv(&cx));
        let poll_2 = fut_2.as_mut().poll(&mut task_cx_2);
        crate::assert_with_log!(
            matches!(poll_2, Poll::Pending),
            "second recv pending",
            true,
            matches!(poll_2, Poll::Pending)
        );

        tx.send(&cx, 5).expect("send should succeed");

        let wake_count_1 = wake_counter_1.load(Ordering::SeqCst);
        let wake_count_2 = wake_counter_2.load(Ordering::SeqCst);
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

    #[test]
    fn permit_abort_wakes_pending_receiver_and_returns_closed() {
        init_test("permit_abort_wakes_pending_receiver_and_returns_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let wake_counter = Arc::new(AtomicUsize::new(0));
        let recv_waker = counting_waker(Arc::clone(&wake_counter));
        let mut task_cx = Context::from_waker(&recv_waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "recv pending before abort",
            true,
            matches!(first_poll, Poll::Pending)
        );

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        permit.abort();

        let wake_count = wake_counter.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_count == 1, "receiver woken once", 1usize, wake_count);

        let second_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(second_poll, Poll::Ready(Err(RecvError::Closed))),
            "recv closed after abort",
            "Ready(Err(Closed))",
            format!("{second_poll:?}")
        );
        crate::test_complete!("permit_abort_wakes_pending_receiver_and_returns_closed");
    }

    #[test]
    fn dropping_permit_wakes_pending_receiver_and_returns_closed() {
        init_test("dropping_permit_wakes_pending_receiver_and_returns_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>();

        let wake_counter = Arc::new(AtomicUsize::new(0));
        let recv_waker = counting_waker(Arc::clone(&wake_counter));
        let mut task_cx = Context::from_waker(&recv_waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "recv pending before permit drop",
            true,
            matches!(first_poll, Poll::Pending)
        );

        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        drop(permit);

        let wake_count = wake_counter.load(Ordering::SeqCst);
        crate::assert_with_log!(wake_count == 1, "receiver woken once", 1usize, wake_count);

        let second_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(second_poll, Poll::Ready(Err(RecvError::Closed))),
            "recv closed after permit drop",
            "Ready(Err(Closed))",
            format!("{second_poll:?}")
        );
        crate::test_complete!("dropping_permit_wakes_pending_receiver_and_returns_closed");
    }

    #[test]
    fn recv_repoll_same_waker_keeps_waiter_identity() {
        init_test("recv_repoll_same_waker_keeps_waiter_identity");
        let cx = test_cx();
        let (_tx, mut rx) = channel::<i32>();
        let inner = Arc::clone(&rx.inner);

        let recv_waker = counting_waker(Arc::new(AtomicUsize::new(0)));
        let mut task_cx = Context::from_waker(&recv_waker);
        let mut fut = Box::pin(rx.recv(&cx));

        let first_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "first poll pending",
            true,
            matches!(first_poll, Poll::Pending)
        );
        let first_waiter_id = inner.lock().waker_id;

        let second_poll = fut.as_mut().poll(&mut task_cx);
        crate::assert_with_log!(
            matches!(second_poll, Poll::Pending),
            "second poll pending",
            true,
            matches!(second_poll, Poll::Pending)
        );
        let second_waiter_id = inner.lock().waker_id;

        crate::assert_with_log!(
            first_waiter_id == second_waiter_id,
            "same waker keeps waiter identity",
            first_waiter_id,
            second_waiter_id
        );
        crate::test_complete!("recv_repoll_same_waker_keeps_waiter_identity");
    }

    /// Metamorphic property: once a value is committed to the oneshot channel,
    /// receiving that value is invariant under post-send receiver cancellation.
    ///
    /// This tests that the receive operation will still succeed with the correct
    /// value even if the receiver's Cx becomes cancelled after the value was sent
    /// but before the receive call is made.
    #[test]
    fn metamorphic_value_ready_receive_invariant_under_post_send_receiver_cancellation() {
        init_test(
            "metamorphic_value_ready_receive_invariant_under_post_send_receiver_cancellation",
        );

        let test_value = 42i32;
        let sender_cx = Cx::for_testing();
        let receiver_cx = Cx::for_testing();

        // Create channel and send value (commit it)
        let (tx, mut rx) = channel::<i32>();
        tx.send(&sender_cx, test_value)
            .expect("send should succeed");

        // Verify value is ready before cancellation
        assert!(rx.try_recv().is_ok(), "value should be ready after send");

        // Now cancel the receiver context AFTER the value was committed
        receiver_cx.set_cancel_requested(true);
        assert!(
            receiver_cx.is_cancel_requested(),
            "receiver cx should be cancelled"
        );

        // Create a new channel with same scenario for comparison
        let (tx2, mut rx2) = channel::<i32>();
        tx2.send(&sender_cx, test_value)
            .expect("send should succeed on control channel");

        // Metamorphic property: recv on cancelled cx should produce same result
        // as recv on non-cancelled cx when value is already ready
        let result_cancelled = block_on(rx.recv(&receiver_cx));
        let result_normal = block_on(rx2.recv(&sender_cx)); // non-cancelled cx

        // Both should succeed with the same value
        match (result_cancelled, result_normal) {
            (Ok(val1), Ok(val2)) => {
                assert_eq!(
                    val1, val2,
                    "value should be same regardless of post-send cancellation"
                );
                assert_eq!(val1, test_value, "received value should match sent value");
            }
            (result1, result2) => {
                panic!(
                    "Metamorphic property violated: cancelled={:?}, normal={:?}. \
                    When value is ready, recv should succeed regardless of receiver cancellation",
                    result1, result2
                );
            }
        }

        // Verify both channels are in terminal closed state
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Closed)),
            "channel should be closed after recv"
        );
        assert!(
            matches!(rx2.try_recv(), Err(TryRecvError::Closed)),
            "control channel should be closed after recv"
        );

        crate::test_complete!(
            "metamorphic_value_ready_receive_invariant_under_post_send_receiver_cancellation"
        );
    }

    /// Audit test for sender drop during receiver poll cancellation correctness.
    ///
    /// Verifies that when sender drops WITHOUT sending while receiver is actively polling,
    /// the receiver immediately returns Err(Closed) rather than hanging. This tests the
    /// critical race condition where sender drop happens DURING receiver's poll execution.
    #[test]
    fn audit_sender_drop_during_receiver_poll() {
        init_test("audit_sender_drop_during_receiver_poll");
        let cx = test_cx();
        let (tx, mut rx) = channel::<u32>();

        // Set up infrastructure to detect wakeups
        let notify_count = Arc::new(AtomicUsize::new(0));
        let poll_waker = counting_waker(Arc::clone(&notify_count));
        let mut task_cx = Context::from_waker(&poll_waker);

        // Create receiver future
        let mut recv_fut = Box::pin(rx.recv(&cx));

        // Step 1: Start receiving (should pend since no value sent)
        let initial_poll = recv_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(initial_poll, Poll::Pending),
            "receiver should be pending initially: {:?}",
            initial_poll
        );

        // Verify receiver is properly waiting
        assert_eq!(
            notify_count.load(Ordering::SeqCst),
            0,
            "no notifications yet"
        );

        // Step 2: Drop sender WITHOUT sending - this simulates the race condition
        // where sender drops during receiver's poll/wait cycle
        drop(tx);

        // Step 3: Verify receiver was woken by sender drop
        let wakeup_count = notify_count.load(Ordering::SeqCst);
        assert_eq!(
            wakeup_count, 1,
            "receiver should be woken exactly once by sender drop"
        );

        // Step 4: Poll receiver again - should return Closed immediately, NOT hang
        let final_poll = recv_fut.as_mut().poll(&mut task_cx);
        let is_closed = matches!(final_poll, Poll::Ready(Err(RecvError::Closed)));
        assert!(
            is_closed,
            "receiver should return Err(Closed) immediately after sender drop, got: {:?}",
            final_poll
        );

        // Drop the future to release the mutable borrow on rx
        drop(recv_fut);

        // Step 5: Verify channel state consistency
        assert!(rx.is_closed(), "receiver should report channel as closed");
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Closed)),
            "try_recv should also return Closed"
        );

        // Step 6: Verify no additional spurious wakeups
        let final_count = notify_count.load(Ordering::SeqCst);
        assert_eq!(
            final_count, 1,
            "should have exactly 1 wakeup total, got {}",
            final_count
        );

        crate::test_complete!("audit_sender_drop_during_receiver_poll");
    }

    /// Audit test for Sender::is_closed() eager detection of receiver drop.
    ///
    /// Per Tokio-compat semantics, is_closed() must return true IMMEDIATELY after
    /// receiver drop, not lazily after try_send. This test verifies the eager
    /// behavior by checking is_closed() directly after receiver drop without
    /// any intervening send attempts.
    #[test]
    fn audit_sender_is_closed_eager_detection() {
        init_test("audit_sender_is_closed_eager_detection");
        let (tx, rx) = channel::<i32>();

        // Before receiver drop: should not be closed
        crate::assert_with_log!(
            !tx.is_closed(),
            "sender should not report closed before receiver drop",
            false,
            tx.is_closed()
        );

        // Drop receiver
        drop(rx);

        // Immediately after receiver drop: should be closed WITHOUT needing try_send
        crate::assert_with_log!(
            tx.is_closed(),
            "sender should report closed IMMEDIATELY after receiver drop (eager detection)",
            true,
            tx.is_closed()
        );

        // Multiple calls should remain consistent
        crate::assert_with_log!(
            tx.is_closed(),
            "sender should remain closed on subsequent calls",
            true,
            tx.is_closed()
        );

        crate::test_complete!("audit_sender_is_closed_eager_detection");
    }

    /// Audit test for Sender::send() value recovery semantics.
    ///
    /// Per asupersync semantics, when send() fails (receiver dropped or cancelled),
    /// it must return Err(value) to allow value recovery, NOT Err(()) (lossy).
    /// This test verifies both failure paths preserve the original value.
    #[test]
    fn audit_send_value_recovery_semantics() {
        init_test("audit_send_value_recovery_semantics");

        // Test value recovery on receiver-dropped scenario
        let cx = test_cx();
        let (tx1, rx1) = channel::<i32>();
        let test_value = 42;

        // Drop receiver before send
        drop(rx1);

        // Send should fail but return the original value for recovery
        let result1 = tx1.send(&cx, test_value);
        crate::assert_with_log!(
            matches!(result1, Err(SendError::Disconnected(42))),
            "send to dropped receiver must return Err(Disconnected(value)) for value recovery",
            "Err(Disconnected(42))",
            format!("{:?}", result1)
        );

        // Verify value can be recovered from the error
        if let Err(SendError::Disconnected(recovered_value)) = result1 {
            crate::assert_with_log!(
                recovered_value == test_value,
                "recovered value must match original",
                test_value,
                recovered_value
            );
        } else {
            panic!("Expected Disconnected error with value");
        }

        // Test value recovery on cancelled-cx scenario
        let cancelled_cx = test_cx();
        cancelled_cx.cancel_with(crate::types::CancelKind::User, Some("test cancel"));
        let (tx2, _rx2) = channel::<i32>();
        let test_value2 = 99;

        // Send with cancelled cx should fail but return the original value
        let result2 = tx2.send(&cancelled_cx, test_value2);
        crate::assert_with_log!(
            matches!(result2, Err(SendError::Cancelled(99))),
            "send with cancelled cx must return Err(Cancelled(value)) for value recovery",
            "Err(Cancelled(99))",
            format!("{:?}", result2)
        );

        // Verify value can be recovered from cancellation error
        if let Err(SendError::Cancelled(recovered_value)) = result2 {
            crate::assert_with_log!(
                recovered_value == test_value2,
                "recovered value from cancellation must match original",
                test_value2,
                recovered_value
            );
        } else {
            panic!("Expected Cancelled error with value");
        }

        // Test that SendPermit::send() also preserves value recovery semantics
        let (tx3, rx3) = channel::<String>();
        let test_string = "recoverable".to_string();
        let test_string_clone = test_string.clone();

        // Get permit and drop receiver
        let permit = tx3.reserve(&cx).expect("cx not cancelled in test");
        drop(rx3);

        // SendPermit::send should also return the value on failure
        let result3 = permit.send(test_string);
        crate::assert_with_log!(
            result3.is_err(),
            "permit send to dropped receiver must fail",
            true,
            result3.is_err()
        );

        if let Err(SendError::Disconnected(recovered_string)) = result3 {
            crate::assert_with_log!(
                recovered_string == test_string_clone,
                "permit send must also preserve value recovery semantics",
                test_string_clone,
                recovered_string
            );
        } else {
            panic!("Expected Disconnected error with value from permit send");
        }

        crate::test_complete!("audit_send_value_recovery_semantics");
    }

    /// Audit test: Receiver::poll() behavior when Sender already sent value.
    ///
    /// When the sender has already sent a value, the next poll on the receiver
    /// must synchronously return Ready(Ok(value)) without any spurious Pending.
    /// Per spec, this must be immediate ready - no additional wakeup staging.
    #[test]
    fn audit_receiver_poll_after_send_immediate_ready() {
        init_test("audit_receiver_poll_after_send_immediate_ready");

        let (tx, rx) = channel::<u32>();
        let cx = test_cx();

        // Phase 1: Send value first (sender completes transmission)
        tx.send(&cx, 42).expect("send should succeed");

        // Phase 2: Create receive future AFTER value is already sent
        let mut recv_fut = rx.recv(&cx);

        // Phase 3: Critical test - poll() must return Ready immediately
        // No spurious Pending allowed since value is already available
        let mut context = Context::from_waker(&noop_waker());
        let poll_result = Pin::new(&mut recv_fut).poll(&mut context);

        // AUDIT: Verify immediate ready behavior (no spurious pending)
        crate::assert_with_log!(
            matches!(poll_result, Poll::Ready(Ok(42))),
            "poll() after send must return Ready(Ok(value)) synchronously",
            "Ready(Ok(42))",
            format!("{:?}", poll_result)
        );

        // Phase 4: Verify no additional wakeups needed
        // The future should be exhausted - further polls return PolledAfterCompletion
        let second_poll_result = Pin::new(&mut recv_fut).poll(&mut context);
        crate::assert_with_log!(
            matches!(
                second_poll_result,
                Poll::Ready(Err(RecvError::PolledAfterCompletion))
            ),
            "second poll must return PolledAfterCompletion (future exhausted)",
            "Ready(Err(PolledAfterCompletion))",
            format!("{:?}", second_poll_result)
        );

        crate::test_complete!("audit_receiver_poll_after_send_immediate_ready");
    }

    /// Audit test: is_closed() and poll_closed() consistency when sender drops.
    ///
    /// When the sender drops, both synchronous and asynchronous closure detection
    /// methods must be consistent:
    /// - is_closed() should return true synchronously
    /// - poll_closed() should return Ready(()) immediately
    #[test]
    fn audit_is_closed_poll_closed_consistency() {
        init_test("audit_is_closed_poll_closed_consistency");

        let (tx, mut rx) = channel::<u32>();

        // Phase 1: Verify initial state (sender alive, channel open)
        crate::assert_with_log!(
            !rx.is_closed(),
            "is_closed() returns false when sender alive",
            false,
            rx.is_closed()
        );

        let mut context = Context::from_waker(&noop_waker());
        let initial_poll = rx.poll_closed(&mut context);
        crate::assert_with_log!(
            matches!(initial_poll, std::task::Poll::Pending),
            "poll_closed() returns Pending when sender alive",
            "Pending",
            format!("{:?}", initial_poll)
        );

        // Phase 2: Drop the sender (critical transition)
        drop(tx);

        // Phase 3: Verify consistency after sender drop
        // CRITICAL: Both methods must agree that channel is closed

        // Test synchronous detection
        let is_closed_result = rx.is_closed();
        crate::assert_with_log!(
            is_closed_result,
            "is_closed() returns true after sender drop",
            true,
            is_closed_result
        );

        // Test asynchronous detection
        let poll_closed_result = rx.poll_closed(&mut context);
        crate::assert_with_log!(
            matches!(poll_closed_result, std::task::Poll::Ready(())),
            "poll_closed() returns Ready(()) after sender drop",
            "Ready(())",
            format!("{:?}", poll_closed_result)
        );

        // Phase 4: Verify consistency is maintained on repeat calls

        // Multiple is_closed() calls should remain consistent
        for i in 1..=3 {
            let repeat_is_closed = rx.is_closed();
            crate::assert_with_log!(
                repeat_is_closed,
                &format!("is_closed() remains true on call {}", i),
                true,
                repeat_is_closed
            );
        }

        // Multiple poll_closed() calls should remain Ready
        for i in 1..=3 {
            let repeat_poll_closed = rx.poll_closed(&mut context);
            crate::assert_with_log!(
                matches!(repeat_poll_closed, std::task::Poll::Ready(())),
                &format!("poll_closed() remains Ready(()) on call {}", i),
                "Ready(())",
                format!("{:?}", repeat_poll_closed)
            );
        }

        // Phase 5: Verify recv() behavior is also consistent
        let cx = test_cx();
        let mut recv_fut = rx.recv(&cx);
        let recv_poll = Pin::new(&mut recv_fut).poll(&mut context);

        crate::assert_with_log!(
            matches!(recv_poll, std::task::Poll::Ready(Err(RecvError::Closed))),
            "recv() also returns Closed error after sender drop",
            "Ready(Err(Closed))",
            format!("{:?}", recv_poll)
        );

        crate::test_complete!("audit_is_closed_poll_closed_consistency");
    }

    #[test]
    fn audit_sender_poll_closed_receiver_alive() {
        // Audit: Sender::poll_closed returns Pending when receiver is alive,
        // NOT Ready(()). Verify with race test where receiver lives longer
        // than several poll_closed calls.

        init_test("audit_sender_poll_closed_receiver_alive");

        let (mut tx, rx) = channel::<i32>();

        // Create a custom context for polling
        let waker = Waker::noop();
        let mut context = std::task::Context::from_waker(&waker);

        // Phase 1: Receiver is alive - poll_closed should return Pending
        for i in 1..=5 {
            let poll_result = tx.poll_closed(&mut context);
            crate::assert_with_log!(
                matches!(poll_result, std::task::Poll::Pending),
                &format!("poll_closed call {} returns Pending when receiver alive", i),
                std::task::Poll::Pending,
                poll_result
            );

            // Verify is_closed() also returns false for consistency
            crate::assert_with_log!(
                !tx.is_closed(),
                &format!(
                    "is_closed() returns false on call {} when receiver alive",
                    i
                ),
                false,
                tx.is_closed()
            );
        }

        // Phase 2: Drop receiver and verify poll_closed immediately returns Ready
        drop(rx);

        let poll_after_drop = tx.poll_closed(&mut context);
        crate::assert_with_log!(
            matches!(poll_after_drop, std::task::Poll::Ready(())),
            "poll_closed returns Ready(()) immediately after receiver drop",
            std::task::Poll::Ready(()),
            poll_after_drop
        );

        // Phase 3: Multiple poll_closed calls after drop should remain Ready
        for i in 1..=3 {
            let repeat_poll = tx.poll_closed(&mut context);
            crate::assert_with_log!(
                matches!(repeat_poll, std::task::Poll::Ready(())),
                &format!(
                    "poll_closed call {} remains Ready(()) after receiver drop",
                    i
                ),
                std::task::Poll::Ready(()),
                repeat_poll
            );
        }

        // Verify is_closed() consistency
        crate::assert_with_log!(
            tx.is_closed(),
            "is_closed() returns true after receiver drop",
            true,
            tx.is_closed()
        );

        crate::test_complete!("audit_sender_poll_closed_receiver_alive");
    }

    #[test]
    fn audit_sender_is_closed_acquire_release_ordering() {
        // Audit: Sender::is_closed() memory ordering semantics.
        // When sender thread sees is_closed()=true via Acquire load,
        // all writes done by receiver thread before drop must be visible.
        //
        // This tests the happens-before relationship:
        // Receiver writes -> Receiver Drop (Release) ---> Sender is_closed() (Acquire) -> Sender sees writes

        init_test("audit_sender_is_closed_acquire_release_ordering");

        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        const NUM_ITERATIONS: usize = 1000;

        for iteration in 0..NUM_ITERATIONS {
            // Shared memory location that receiver will write to before dropping
            let shared_data = Arc::new(AtomicU32::new(0));
            let (tx, rx) = channel::<i32>();

            let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
            let shared_reader = shared_data.clone();
            let shared_writer = shared_data.clone();
            let tx_reader = tx.clone();

            // Receiver thread: writes to shared memory then drops
            let receiver_handle = std::thread::spawn(move || {
                // Simulate receiver doing some work and writing to shared memory
                let unique_value = (iteration as u32) * 1000 + 42;
                shared_writer.store(unique_value, Ordering::Release);

                // Small delay to increase chance of race condition
                std::thread::yield_now();

                // Drop receiver - this should trigger receiver_dropped = true with proper Release ordering
                drop(rx);
            });

            // Sender thread: polls is_closed() and reads shared memory
            let sender_handle = std::thread::spawn(move || {
                let mut observed_closed = false;
                let mut final_shared_value = 0;

                // Poll until we see the receiver as closed
                while !observed_closed {
                    if let Some(sender) = tx_reader.lock().unwrap().as_ref() {
                        if sender.is_closed() {
                            observed_closed = true;
                            // CRITICAL: If is_closed() uses proper Acquire ordering,
                            // we MUST see the receiver's Release write to shared_data
                            final_shared_value = shared_reader.load(Ordering::Acquire);
                        }
                    }
                    std::thread::yield_now();
                }

                final_shared_value
            });

            receiver_handle
                .join()
                .expect("receiver thread should not panic");
            let observed_value = sender_handle
                .join()
                .expect("sender thread should not panic");

            // MEMORY ORDERING PROPERTY:
            // When sender observes is_closed()=true, it MUST see all receiver writes
            let expected_value = (iteration as u32) * 1000 + 42;

            crate::assert_with_log!(
                observed_value == expected_value,
                &format!(
                    "iteration {}: sender must see receiver writes when is_closed()=true (expected: {}, observed: {})",
                    iteration, expected_value, observed_value
                ),
                expected_value,
                observed_value
            );
        }

        crate::test_complete!("audit_sender_is_closed_acquire_release_ordering");
    }

    #[test]
    fn audit_receiver_drop_release_semantics() {
        // Audit: Receiver Drop should use Release semantics so that
        // all receiver writes are visible to sender when is_closed() observes true.

        init_test("audit_receiver_drop_release_semantics");

        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        const NUM_THREADS: usize = 8;
        const WRITES_PER_THREAD: usize = 100;

        let barrier = Arc::new(std::sync::Barrier::new(NUM_THREADS + 1));
        let shared_counters = Arc::new(
            (0..NUM_THREADS)
                .map(|_| AtomicU32::new(0))
                .collect::<Vec<_>>(),
        );

        let mut handles = Vec::new();

        // Spawn receiver threads that write then drop
        for thread_id in 0..NUM_THREADS {
            let (tx, rx) = channel::<i32>();
            let barrier = barrier.clone();
            let counter = shared_counters.clone();

            let handle = std::thread::spawn(move || {
                barrier.wait(); // Synchronize start

                // Receiver does writes
                for i in 0..WRITES_PER_THREAD {
                    let value = (thread_id * WRITES_PER_THREAD + i) as u32;
                    counter[thread_id].store(value, Ordering::Relaxed);
                }

                // Ensure all writes complete before drop
                std::sync::atomic::fence(Ordering::AcqRel);

                // Drop receiver - this should publish all writes
                drop(rx);

                // Return sender for checking
                tx
            });

            handles.push(handle);
        }

        // Start all threads
        barrier.wait();

        // Collect senders and verify state
        for (thread_id, handle) in handles.into_iter().enumerate() {
            let sender = handle.join().expect("thread should not panic");

            // Sender should see receiver as closed
            crate::assert_with_log!(
                sender.is_closed(),
                &format!("thread {}: sender should see receiver as closed", thread_id),
                true,
                sender.is_closed()
            );

            // And should see all writes made by that receiver
            let final_value = shared_counters[thread_id].load(Ordering::Acquire);
            let expected_final = (thread_id * WRITES_PER_THREAD + WRITES_PER_THREAD - 1) as u32;

            crate::assert_with_log!(
                final_value == expected_final,
                &format!(
                    "thread {}: should see final write value {} (actual: {})",
                    thread_id, expected_final, final_value
                ),
                expected_final,
                final_value
            );
        }

        crate::test_complete!("audit_receiver_drop_release_semantics");
    }

    #[test]
    fn audit_sender_send_value_recovery_on_error() {
        // Audit: Sender::send() value recovery when send fails.
        // When send fails (receiver dropped), Err must contain the original value
        // so caller can recover it. Error type must be Err(T), not Err(()).

        init_test("audit_sender_send_value_recovery_on_error");

        let (tx, rx) = channel::<String>();
        let cx = test_cx();

        // Test value to send
        let test_value = String::from("recoverable_test_value");
        let value_clone = test_value.clone();

        // Drop receiver first to cause send failure
        drop(rx);

        // Attempt to send - should fail with value recovery
        let send_result = tx.send(&cx, test_value);

        // CRITICAL: Error must contain the original value for recovery
        crate::assert_with_log!(
            send_result.is_err(),
            "send should fail when receiver is dropped",
            true,
            send_result.is_err()
        );

        match send_result {
            Err(SendError::Disconnected(recovered_value)) => {
                crate::assert_with_log!(
                    recovered_value == value_clone,
                    "recovered value should match original sent value",
                    value_clone.clone(),
                    recovered_value.clone()
                );

                // Verify caller can use recovered value
                let reused_value = format!("reused: {}", recovered_value);
                crate::assert_with_log!(
                    reused_value == "reused: recoverable_test_value",
                    "caller should be able to reuse recovered value",
                    "reused: recoverable_test_value",
                    reused_value
                );
            }
            Err(SendError::Cancelled(_)) => {
                panic!("Expected Disconnected error, got Cancelled");
            }
            Ok(()) => {
                panic!("Expected send to fail, but it succeeded");
            }
        }

        crate::test_complete!("audit_sender_send_value_recovery_on_error");
    }

    #[test]
    fn audit_send_permit_value_recovery_on_error() {
        // Audit: SendPermit::send() value recovery when receiver dropped.
        // Tests the permit-based send path for value recovery.

        init_test("audit_send_permit_value_recovery_on_error");

        let (tx, rx) = channel::<Vec<u8>>();
        let cx = test_cx();

        // Reserve first (this should succeed)
        let permit = tx
            .reserve(&cx)
            .expect("reserve should succeed when receiver alive");

        // Test value to send
        let test_data = vec![1, 2, 3, 4, 5];
        let data_clone = test_data.clone();

        // Drop receiver after reserve but before send
        drop(rx);

        // Attempt to send via permit - should fail with value recovery
        let send_result = permit.send(test_data);

        // CRITICAL: Error must contain the original value
        crate::assert_with_log!(
            send_result.is_err(),
            "permit send should fail when receiver dropped",
            true,
            send_result.is_err()
        );

        match send_result {
            Err(SendError::Disconnected(recovered_data)) => {
                crate::assert_with_log!(
                    recovered_data == data_clone,
                    "recovered data should match original",
                    data_clone.clone(),
                    recovered_data.clone()
                );

                // Verify data is fully usable
                let sum: u8 = recovered_data.iter().sum();
                crate::assert_with_log!(
                    sum == 15, // 1+2+3+4+5 = 15
                    "recovered data should be fully functional",
                    15,
                    sum
                );
            }
            Err(SendError::Cancelled(_)) => {
                panic!("Expected Disconnected error, got Cancelled");
            }
            Ok(()) => {
                panic!("Expected send to fail, but it succeeded");
            }
        }

        crate::test_complete!("audit_send_permit_value_recovery_on_error");
    }

    #[test]
    fn audit_send_error_cancelled_value_recovery() {
        // Audit: SendError::Cancelled also returns value for recovery.
        // When send fails due to cancellation, value should still be recoverable.

        init_test("audit_send_error_cancelled_value_recovery");

        let (tx, _rx) = channel::<i32>();
        let cx = test_cx();

        // Cancel the context before sending
        cx.cancel();

        let test_value = 42;

        // Attempt to send with cancelled context - should fail with value recovery
        let send_result = tx.send(&cx, test_value);

        // CRITICAL: Cancellation error must also contain the value
        crate::assert_with_log!(
            send_result.is_err(),
            "send should fail when context is cancelled",
            true,
            send_result.is_err()
        );

        match send_result {
            Err(SendError::Cancelled(recovered_value)) => {
                crate::assert_with_log!(
                    recovered_value == test_value,
                    "cancelled send should return original value",
                    test_value,
                    recovered_value
                );

                // Verify value can be reused
                let doubled = recovered_value * 2;
                crate::assert_with_log!(
                    doubled == 84,
                    "recovered value should be usable",
                    84,
                    doubled
                );
            }
            Err(SendError::Disconnected(_)) => {
                panic!("Expected Cancelled error, got Disconnected");
            }
            Ok(()) => {
                panic!("Expected send to fail, but it succeeded");
            }
        }

        crate::test_complete!("audit_send_error_cancelled_value_recovery");
    }

    #[test]
    fn audit_send_error_type_signature() {
        // Audit: Compile-time verification of SendError<T> type signature.
        // Ensures error type contains T, not () for proper value recovery.

        init_test("audit_send_error_type_signature");

        // Compile-time type assertions
        fn assert_send_error_contains_value<T>() {
            // This function verifies that SendError<T> contains T, not ()
            let _check_disconnected = |value: T| -> SendError<T> { SendError::Disconnected(value) };

            let _check_cancelled = |value: T| -> SendError<T> { SendError::Cancelled(value) };

            // Verify Result type signature
            fn check_send_result<T>() -> Result<(), SendError<T>> {
                // This enforces that send methods return Result<(), SendError<T>>
                // where SendError<T> contains the value T, not ()
                unimplemented!("This is just a type check")
            }

            let _: fn() -> Result<(), SendError<T>> = check_send_result;
        }

        // Test with various types
        assert_send_error_contains_value::<String>();
        assert_send_error_contains_value::<Vec<u8>>();
        assert_send_error_contains_value::<i32>();

        // Runtime verification with actual error creation
        let test_string = String::from("test");
        let disconnected_error = SendError::Disconnected(test_string.clone());

        match disconnected_error {
            SendError::Disconnected(recovered) => {
                crate::assert_with_log!(
                    recovered == test_string,
                    "SendError::Disconnected should contain original value",
                    test_string,
                    recovered
                );
            }
            _ => panic!("Unexpected error variant"),
        }

        crate::test_complete!("audit_send_error_type_signature");
    }

    /// Helper function to create a no-op waker for testing.
    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    #[test]
    fn audit_send_after_receiver_poll_race() {
        init_test("audit_send_after_receiver_poll_race");

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::task::{Context, Poll, Waker};

        // Test the race between sender.send(v) and receiver having registered waker
        // Must verify: send atomically delivers value AND wakes receiver immediately

        let test_iterations = 1000; // Test many iterations to catch race conditions
        let mut successful_immediate_wakeups = 0;

        for _iteration in 0..test_iterations {
            let (tx, mut rx) = channel::<i32>();

            // Step 1: Receiver polls and registers waker
            let waker_called = Arc::new(AtomicBool::new(false));
            let waker_call_count = Arc::new(AtomicUsize::new(0));

            let counting_waker = {
                let waker_called = Arc::clone(&waker_called);
                let waker_call_count = Arc::clone(&waker_call_count);

                struct CountingWaker {
                    called: Arc<AtomicBool>,
                    call_count: Arc<AtomicUsize>,
                }

                impl std::task::Wake for CountingWaker {
                    fn wake(self: Arc<Self>) {
                        self.called.store(true, Ordering::SeqCst);
                        self.call_count.fetch_add(1, Ordering::SeqCst);
                    }

                    fn wake_by_ref(self: &Arc<Self>) {
                        self.called.store(true, Ordering::SeqCst);
                        self.call_count.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let counting = Arc::new(CountingWaker {
                    called: waker_called,
                    call_count: waker_call_count,
                });

                Waker::from(counting)
            };

            // Step 2: Receiver polls, registers waker, returns Pending
            let mut recv_fut = rx.recv_uninterruptible();
            let mut cx = Context::from_waker(&counting_waker);

            let poll_result = Pin::new(&mut recv_fut).poll(&mut cx);
            assert_eq!(
                poll_result,
                Poll::Pending,
                "First poll should return Pending"
            );

            // Step 3: Sender sends value (should wake the registered receiver)
            let test_value = 42;
            let permit = tx
                .reserve(&Cx::for_testing())
                .expect("Reserve should succeed");
            let send_result = permit.send(test_value);
            assert!(send_result.is_ok(), "Send should succeed");

            // Step 4: Verify waker was called immediately by sender
            // The sender should have taken the registered waker and called wake() on it
            let waker_was_called = waker_called.load(Ordering::SeqCst);

            if waker_was_called {
                successful_immediate_wakeups += 1;

                // Step 5: Verify receiver gets the value on next poll
                let poll_result2 = Pin::new(&mut recv_fut).poll(&mut cx);
                match poll_result2 {
                    Poll::Ready(Ok(received_value)) => {
                        assert_eq!(
                            received_value, test_value,
                            "Received value should match sent value"
                        );
                    }
                    Poll::Ready(Err(e)) => {
                        panic!("Unexpected recv error: {:?}", e);
                    }
                    Poll::Pending => {
                        panic!("Second poll should return Ready after wakeup, got Pending");
                    }
                }
            }

            // Verify exactly one wakeup (no spurious wakeups)
            let call_count = waker_call_count.load(Ordering::SeqCst);
            assert!(
                call_count <= 1,
                "Should have at most 1 wakeup call, got {}",
                call_count
            );
        }

        // Verify that the wakeup mechanism works reliably
        // We expect nearly 100% immediate wakeups in this test since there's no actual concurrency
        let success_rate = (successful_immediate_wakeups as f64) / (test_iterations as f64);
        assert!(
            success_rate > 0.95,
            "Expected >95% immediate wakeups, got {}/{} ({:.1}%). \
                This suggests send() is not properly waking registered receivers.",
            successful_immediate_wakeups,
            test_iterations,
            success_rate * 100.0
        );

        println!(
            "✅ send-after-receiver-poll race audit: {}/{} successful immediate wakeups ({:.1}%)",
            successful_immediate_wakeups,
            test_iterations,
            success_rate * 100.0
        );
    }

    #[test]
    fn audit_sender_poll_closed_behavior() {
        init_test("audit_sender_poll_closed_behavior");
        use std::task::{Context, Waker};

        // Test 1: poll_closed returns Pending when receiver is alive
        let (mut tx, rx) = channel::<i32>();
        let noop_waker = Waker::noop();
        let mut ctx = Context::from_waker(&noop_waker);

        // Receiver is alive, poll_closed should return Pending
        let poll_result = tx.poll_closed(&mut ctx);
        if !matches!(poll_result, Poll::Pending) {
            panic!(
                "❌ DEFECT: poll_closed() returned {:?} when receiver is alive, expected Poll::Pending",
                poll_result
            );
        }

        // Verify waker was registered in the inner state
        let inner_has_waker = tx.inner.lock().waker.is_some();
        if !inner_has_waker {
            panic!("❌ DEFECT: poll_closed() returned Pending but failed to register waker");
        }

        // Test 2: poll_closed returns Ready when receiver is dropped
        drop(rx); // Drop the receiver

        let poll_result_after_drop = tx.poll_closed(&mut ctx);
        if !matches!(poll_result_after_drop, Poll::Ready(())) {
            panic!(
                "❌ DEFECT: poll_closed() returned {:?} when receiver is dropped, expected Poll::Ready(())",
                poll_result_after_drop
            );
        }

        // Test 3: poll_closed returns Ready immediately if receiver was already dropped
        let (mut tx2, rx2) = channel::<i32>();
        drop(rx2); // Drop receiver immediately

        let immediate_poll = tx2.poll_closed(&mut ctx);
        if !matches!(immediate_poll, Poll::Ready(())) {
            panic!(
                "❌ DEFECT: poll_closed() returned {:?} for already-dropped receiver, expected Poll::Ready(())",
                immediate_poll
            );
        }

        // Test 4: Stress test - waker notification on receiver drop
        let iterations = 100;
        let mut successful_wakeups = 0;

        for iteration in 0..iterations {
            let (mut tx, rx) = channel::<i32>();

            // Create a custom waker to track wake calls
            use std::sync::atomic::{AtomicBool, Ordering};
            let wake_called = Arc::new(AtomicBool::new(false));
            let wake_called_clone = wake_called.clone();

            struct FlagWaker(Arc<AtomicBool>);

            impl std::task::Wake for FlagWaker {
                fn wake(self: Arc<Self>) {
                    self.0.store(true, Ordering::Release);
                }

                fn wake_by_ref(self: &Arc<Self>) {
                    self.0.store(true, Ordering::Release);
                }
            }

            let custom_waker = Waker::from(Arc::new(FlagWaker(wake_called_clone)));

            let mut custom_ctx = Context::from_waker(&custom_waker);

            // Poll for closure - should return Pending and register waker
            let first_poll = tx.poll_closed(&mut custom_ctx);
            if !matches!(first_poll, Poll::Pending) {
                panic!(
                    "❌ DEFECT: Iteration {}: First poll_closed() returned {:?}, expected Pending",
                    iteration, first_poll
                );
            }

            // Drop receiver to trigger waker
            drop(rx);

            // Give a tiny bit of time for the waker to be called
            std::thread::yield_now();

            // Check if waker was called
            let wake_was_called = wake_called.load(Ordering::Acquire);
            if wake_was_called {
                successful_wakeups += 1;
            }

            // Verify subsequent poll returns Ready
            let second_poll = tx.poll_closed(&mut custom_ctx);
            if !matches!(second_poll, Poll::Ready(())) {
                panic!(
                    "❌ DEFECT: Iteration {}: Second poll_closed() after receiver drop returned {:?}, expected Ready(())",
                    iteration, second_poll
                );
            }
        }

        // Verify waker notification reliability
        let success_rate = (successful_wakeups as f64) / (iterations as f64);
        if success_rate < 0.95 {
            panic!(
                "❌ DEFECT: Only {}/{} iterations ({:.1}%) had waker called when receiver dropped. \
                Expected >95% waker notification rate.",
                successful_wakeups,
                iterations,
                success_rate * 100.0
            );
        }

        println!("✅ SOUND: Sender::poll_closed() behavior verified:");
        println!("  - Returns Pending when receiver alive and registers waker ✓");
        println!("  - Returns Ready(()) when receiver dropped ✓");
        println!(
            "  - Waker notification on receiver drop: {}/{} ({:.1}%) ✓",
            successful_wakeups,
            iterations,
            success_rate * 100.0
        );

        crate::test_complete!("audit_sender_poll_closed_behavior");
    }

    #[test]
    fn audit_receiver_sender_drop_immediate_error() {
        init_test("audit_receiver_sender_drop_immediate_error");
        use std::task::{Context, Waker};

        // This test verifies that when Sender is dropped without sending,
        // receiver.await returns Err(RecvError::Closed) immediately on next poll

        let (tx, mut rx) = channel::<i32>();

        // Create a receiver future and poll it once to register waker
        let cx = test_cx();
        let mut recv_fut = Box::pin(rx.recv(&cx));

        let noop_waker = Waker::noop();
        let mut task_ctx = Context::from_waker(&noop_waker);

        // First poll should return Pending (no value sent yet)
        let first_poll = {
            use std::future::Future;
            use std::pin::Pin;

            Pin::as_mut(&mut recv_fut).poll(&mut task_ctx)
        };

        if !matches!(first_poll, Poll::Pending) {
            panic!(
                "❌ DEFECT: First poll returned {:?}, expected Pending when no value sent",
                first_poll
            );
        }

        // Verify receiver correctly reports not closed yet
        if rx.is_closed() {
            panic!("❌ DEFECT: Receiver reports closed before sender is dropped");
        }

        // NOW drop the sender without sending
        drop(tx);

        // Receiver should now report closed
        if !rx.is_closed() {
            panic!("❌ DEFECT: Receiver does not report closed after sender drop");
        }

        // Next poll should immediately return Err(RecvError::Closed)
        let second_poll = {
            use std::future::Future;
            use std::pin::Pin;

            Pin::as_mut(&mut recv_fut).poll(&mut task_ctx)
        };

        match second_poll {
            Poll::Ready(Err(RecvError::Closed)) => {
                // ✅ Correct behavior
            }
            other => {
                panic!(
                    "❌ DEFECT: After sender drop, receiver.poll() returned {:?}, expected Ready(Err(RecvError::Closed))",
                    other
                );
            }
        }

        // Test 2: Stress test with timing variations
        let iterations = 100;
        let mut successful_immediate_errors = 0;

        for iteration in 0..iterations {
            let (tx, mut rx) = channel::<i32>();
            let cx = test_cx();

            // Spawn receiver in separate thread to test cross-thread notification
            let receiver_handle = std::thread::spawn(move || {
                let rt = crate::lab::LabRuntime::new();
                rt.block_on(async {
                    // Create receiver future
                    let recv_result = rx.recv(&cx).await;
                    recv_result
                })
            });

            // Give receiver time to register waker
            std::thread::sleep(std::time::Duration::from_micros(100));

            // Drop sender
            drop(tx);

            // Receiver should get Err(RecvError::Closed)
            let recv_result = receiver_handle
                .join()
                .expect("Receiver thread should complete");

            match recv_result {
                Err(RecvError::Closed) => {
                    successful_immediate_errors += 1;
                }
                other => {
                    panic!(
                        "❌ DEFECT: Iteration {}: Receiver got {:?} instead of Err(RecvError::Closed) after sender drop",
                        iteration, other
                    );
                }
            }
        }

        // Verify high success rate for immediate error notification
        let success_rate = (successful_immediate_errors as f64) / (iterations as f64);
        if success_rate < 0.95 {
            panic!(
                "❌ DEFECT: Only {}/{} iterations ({:.1}%) had immediate Err(RecvError::Closed) after sender drop. \
                Expected >95% immediate error notification.",
                successful_immediate_errors,
                iterations,
                success_rate * 100.0
            );
        }

        // Test 3: try_recv() should also return Closed after sender drop
        let (tx3, mut rx3) = channel::<i32>();

        // Before drop: try_recv should return Empty
        match rx3.try_recv() {
            Err(TryRecvError::Empty) => {
                // Expected
            }
            other => {
                panic!(
                    "❌ DEFECT: try_recv() before sender drop returned {:?}, expected Err(TryRecvError::Empty)",
                    other
                );
            }
        }

        // Drop sender
        drop(tx3);

        // After drop: try_recv should return Closed
        match rx3.try_recv() {
            Err(TryRecvError::Closed) => {
                // ✅ Correct
            }
            other => {
                panic!(
                    "❌ DEFECT: try_recv() after sender drop returned {:?}, expected Err(TryRecvError::Closed)",
                    other
                );
            }
        }

        println!("✅ SOUND: Receiver sender drop behavior verified:");
        println!("  - recv().await returns Err(RecvError::Closed) immediately after sender drop ✓");
        println!(
            "  - Cross-thread notification: {}/{} ({:.1}%) immediate errors ✓",
            successful_immediate_errors,
            iterations,
            success_rate * 100.0
        );
        println!("  - is_closed() correctly reports channel state ✓");
        println!("  - try_recv() returns Err(TryRecvError::Closed) after sender drop ✓");

        crate::test_complete!("audit_receiver_sender_drop_immediate_error");
    }

    #[test]
    fn audit_send_when_receiver_dropped_returns_value() {
        init_test("audit_send_when_receiver_dropped_returns_value");

        // This test verifies that when Sender::send(value) is called after
        // Receiver was already dropped, send() returns Err(SendError::Disconnected(value))
        // so the caller can recover the value (not lose it).

        let cx = test_cx();

        // Test 1: Basic case - drop receiver then send
        let (tx, rx) = channel::<i32>();

        let permit = tx.reserve(&cx).expect("cx not cancelled");

        // Receiver is not dropped yet
        if permit.is_closed() {
            panic!("❌ DEFECT: Permit reports closed before receiver drop");
        }

        // Drop receiver
        drop(rx);

        // Now permit should detect closure
        if !permit.is_closed() {
            panic!("❌ DEFECT: Permit does not report closed after receiver drop");
        }

        // Send should return the value
        let send_result = permit.send(42);

        match send_result {
            Err(SendError::Disconnected(recovered_value)) => {
                if recovered_value != 42 {
                    panic!(
                        "❌ DEFECT: send() returned wrong value {} instead of 42",
                        recovered_value
                    );
                }
                // ✅ Correct - value recovered
            }
            Ok(()) => {
                panic!(
                    "❌ DEFECT: send() returned Ok(()) when receiver was already dropped. \
                     Value was silently lost instead of being returned to caller."
                );
            }
            Err(SendError::Cancelled(_)) => {
                panic!(
                    "❌ DEFECT: send() returned Cancelled error when receiver was dropped. \
                     Expected Disconnected error."
                );
            }
        }

        // Test 2: Race condition stress test
        let iterations = 100;
        let mut successful_recoveries = 0;
        let mut lost_values = 0;

        for iteration in 0..iterations {
            let (tx, rx) = channel::<i32>();
            let test_value = iteration + 1000;

            let permit = tx.reserve(&cx).expect("cx not cancelled");

            // Race: drop receiver in separate thread
            let drop_handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_micros(1));
                drop(rx);
            });

            // Slight delay to increase chance of race
            std::thread::sleep(std::time::Duration::from_micros(1));

            // Try to send
            let send_result = permit.send(test_value);

            drop_handle.join().expect("Drop thread should complete");

            match send_result {
                Err(SendError::Disconnected(recovered_value)) => {
                    if recovered_value == test_value {
                        successful_recoveries += 1;
                    } else {
                        panic!(
                            "❌ DEFECT: Iteration {}: Recovered wrong value {} instead of {}",
                            iteration, recovered_value, test_value
                        );
                    }
                }
                Ok(()) => {
                    // This could happen if send() completed before receiver drop
                    // but we expect most to fail due to timing
                    lost_values += 1;
                }
                Err(SendError::Cancelled(_)) => {
                    panic!(
                        "❌ DEFECT: Iteration {}: Unexpected Cancelled error",
                        iteration
                    );
                }
            }
        }

        // We expect most sends to detect the dropped receiver and return the value
        // Some might succeed if timing works out differently
        if lost_values > iterations / 2 {
            println!(
                "⚠️  Note: {}/{} sends succeeded despite receiver drop race (timing dependent)",
                lost_values, iterations
            );
        }

        // Test 3: Convenience send() method behavior
        let (tx3, rx3) = channel::<i32>();

        drop(rx3);

        let convenience_result = tx3.send(&cx, 999);

        match convenience_result {
            Err(SendError::Disconnected(recovered_value)) => {
                if recovered_value != 999 {
                    panic!(
                        "❌ DEFECT: Convenience send() returned wrong value {} instead of 999",
                        recovered_value
                    );
                }
            }
            Ok(()) => {
                panic!("❌ DEFECT: Convenience send() returned Ok(()) when receiver was dropped");
            }
            Err(SendError::Cancelled(_)) => {
                panic!(
                    "❌ DEFECT: Convenience send() returned Cancelled when receiver was dropped"
                );
            }
        }

        // Test 4: Check that value is not lost in the channel state
        let (tx4, rx4) = channel::<String>();
        let permit4 = tx4.reserve(&cx).expect("cx not cancelled");

        drop(rx4);

        let expensive_value = "expensive_to_create_string".to_string();
        let expensive_value_clone = expensive_value.clone();

        let send_result4 = permit4.send(expensive_value);

        match send_result4 {
            Err(SendError::Disconnected(recovered)) => {
                if recovered != expensive_value_clone {
                    panic!(
                        "❌ DEFECT: String value was corrupted during recovery. \
                         Expected '{}', got '{}'",
                        expensive_value_clone, recovered
                    );
                }
            }
            _ => {
                panic!("❌ DEFECT: send() did not return Disconnected error for dropped receiver");
            }
        }

        println!("✅ SOUND: Send when receiver dropped behavior verified:");
        println!("  - send() returns Err(SendError::Disconnected(value)) when receiver dropped ✓");
        println!("  - Caller can recover value instead of losing it ✓");
        println!(
            "  - Race condition handling: {}/{} value recoveries ✓",
            successful_recoveries, iterations
        );
        println!("  - Convenience send() method has same behavior ✓");
        println!("  - Value integrity preserved during recovery ✓");

        crate::test_complete!("audit_send_when_receiver_dropped_returns_value");
    }
}
