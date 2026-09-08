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

use crate::cx::{CancelWakerToken, Cx};
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

/// A checked send refused publication and retained the caller's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckedSendError<T> {
    /// The channel refused the operation.
    Channel(SendError<T>),
    /// Runtime obligation admission failed before a permit was returned.
    Admission {
        /// The authoritative admission refusal.
        error: crate::runtime::obligation_mailbox::ObligationAdmissionError,
        /// The value which was not published.
        value: T,
    },
}

impl<T> std::fmt::Display for CheckedSendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Channel(error) => write!(f, "{error}"),
            Self::Admission { error, .. } => write!(f, "{error}"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for CheckedSendError<T> {}

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
            Self::Cancelled => write!(f, "[ASUP-E203] receive operation cancelled"),
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

/// Opt-in, redacted telemetry snapshot for a oneshot channel.
///
/// The caller supplies `channel_id`, which keeps identifiers deterministic and
/// avoids ambient globals or pointer-derived IDs. Payload values are never
/// exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneshotTelemetrySnapshot {
    /// Caller-provided deterministic channel identifier.
    pub channel_id: u64,
    /// Stable channel kind label.
    pub channel_kind: &'static str,
    /// Oneshot channels can queue at most one committed value.
    pub capacity: usize,
    /// Number of committed values waiting for the receiver.
    pub queued_messages: usize,
    /// Number of reserved-but-uncommitted send obligations.
    pub reserved_uncommitted_obligations: usize,
    /// Sender-side waiters observing receiver closure.
    pub send_waiter_count: usize,
    /// Receiver-side waiters observing value or sender closure.
    pub recv_waiter_count: usize,
    /// Redacted receiver state.
    pub receiver_health: &'static str,
    /// Oneshot has no lagging receiver concept.
    pub lagged_receiver_count: Option<usize>,
    /// Cancel/abort events observed by the channel.
    pub cancellation_count: u64,
    /// Whether this channel has reached a terminal closed state.
    pub closed: bool,
    /// Redacted terminal reason, when closed.
    pub closed_reason: Option<&'static str>,
}

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
    /// Used by receiver futures with coordinated waiter identity system.
    waker: Option<Waker>,
    /// Monotonic waiter identity for the registered waker.
    ///
    /// This lets us clear a waiter only if the same `RecvFuture` that
    /// registered it is being cancelled/dropped.
    waker_id: Option<u64>,
    /// Next waiter identity to assign.
    next_waiter_id: u64,
    /// The waker to notify sender when receiver is dropped.
    /// Used by Sender::poll_closed, separate from receiver waker system.
    sender_waker: Option<Waker>,
    /// The waker to notify receiver when sender is dropped.
    /// Used by Receiver::poll_closed, separate from receiver waker system.
    receiver_closed_waker: Option<Waker>,
    /// Number of cancellation/abort events observed by this channel.
    cancellation_count: u64,
    /// Redacted terminal reason once the channel has closed.
    closed_reason: Option<&'static str>,
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
            sender_waker: None,
            receiver_closed_waker: None,
            cancellation_count: 0,
            closed_reason: None,
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

    /// Takes the registered waker and clears its waiter identity.
    #[inline]
    fn take_waker(&mut self) -> Option<Waker> {
        self.waker_id = None;
        self.waker.take()
    }

    /// Records a cancellation or abort event without exposing payloads.
    #[inline]
    fn record_cancellation(&mut self) {
        self.cancellation_count = self.cancellation_count.saturating_add(1);
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[inline]
    fn telemetry_snapshot(&self, channel_id: u64) -> OneshotTelemetrySnapshot {
        let queued_messages = usize::from(self.value.is_some());
        let reserved_uncommitted_obligations = usize::from(self.permit_outstanding);
        let recv_waiter_count =
            usize::from(self.waker.is_some()) + usize::from(self.receiver_closed_waker.is_some());
        let closed = self.receiver_dropped
            || (self.sender_consumed && !self.permit_outstanding && self.value.is_none());

        let receiver_health = if self.receiver_dropped {
            "receiver_dropped"
        } else if self.value.is_some() {
            "value_ready"
        } else if self.is_closed() {
            "sender_closed"
        } else if recv_waiter_count > 0 {
            "waiting"
        } else {
            "open"
        };

        OneshotTelemetrySnapshot {
            channel_id,
            channel_kind: "oneshot",
            capacity: 1,
            queued_messages,
            reserved_uncommitted_obligations,
            send_waiter_count: usize::from(self.sender_waker.is_some()),
            recv_waiter_count,
            receiver_health,
            lagged_receiver_count: None,
            cancellation_count: self.cancellation_count,
            closed,
            closed_reason: closed.then_some(self.closed_reason).flatten(),
        }
    }
}

#[inline]
fn receive_waker_is_current<T>(
    inner: &OneShotInner<T>,
    waiter_id: Option<u64>,
    task_waker: &Waker,
) -> bool {
    waiter_id.is_some_and(|waiter_id| {
        inner.waker_id == Some(waiter_id)
            && inner
                .waker
                .as_ref()
                .is_some_and(|stored| stored.will_wake(task_waker))
    })
}

/// Installs a receive Waker that was cloned before the caller acquired the
/// channel mutex. Returns the displaced Waker for post-unlock retirement.
#[inline]
fn install_receive_waker<T>(
    inner: &mut OneShotInner<T>,
    waiter_id: &mut Option<u64>,
    task_waker: &Waker,
    incoming_waker: &mut Option<Waker>,
) -> Option<Waker> {
    if receive_waker_is_current(inner, *waiter_id, task_waker) {
        return None;
    }

    let incoming_waker = incoming_waker
        .take()
        .expect("prepared receive Waker must be available");
    if (*waiter_id).is_some_and(|waiter_id| inner.waker_id == Some(waiter_id)) {
        return inner.waker.replace(incoming_waker);
    }

    let new_waiter_id = inner.next_waiter_id;
    inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);
    let retired_waker = inner.waker.replace(incoming_waker);
    inner.waker_id = Some(new_waiter_id);
    *waiter_id = Some(new_waiter_id);
    retired_waker
}

/// Retires a stored Waker after its channel mutex has been released.
///
/// Safe custom Waker payloads may run arbitrary destructor code, including
/// channel re-entry or a panic. Contain each retirement independently so a
/// stale registration cannot deadlock the channel or discard a value that has
/// already committed to a terminal receive result.
#[inline]
fn retire_waker_after_unlock(waker: Option<Waker>) {
    let Some(waker) = waker else {
        return;
    };
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker))) {
        // Dropping an arbitrary panic payload can itself panic. The channel is
        // already authoritative, so leak only that opaque payload and preserve
        // progress for the caller.
        std::mem::forget(payload);
    }
}

/// Dispatches a stored Waker after its channel mutex has been released.
///
/// A custom wake callback can re-enter the channel or panic. Keep each
/// callback independent so one hostile waiter cannot prevent another waiter
/// from observing an already-committed state transition.
#[inline]
fn wake_waker_after_unlock(waker: Option<Waker>) {
    let Some(waker) = waker else {
        return;
    };
    // Keep the stored owner alive while the callback unwinds. For safe
    // `Arc<impl Wake>` Wakers this prevents a callback panic and a final-owner
    // destructor panic from combining into an abort inside one unwind.
    if let Err(payload) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake_by_ref()))
    {
        std::mem::forget(payload);
    }
    retire_waker_after_unlock(Some(waker));
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
        Receiver {
            inner,
            poll_waiter_id: None,
        },
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
    /// Reserves after synchronous runtime obligation admission.
    ///
    /// Closed-region, retired-holder and quota refusals consume this sender
    /// without publishing a permit; the receiver observes closure. A context
    /// deliberately constructed without a runtime remains untracked. Existing
    /// [`Self::reserve`] behavior is retained for compatibility.
    pub fn reserve_checked(self, cx: &Cx) -> Result<SendPermit<T>, CheckedSendError<()>> {
        if cx.checkpoint().is_err() {
            return self.reserve(cx).map_err(CheckedSendError::Channel);
        }
        // Keep the sender authoritative until admission succeeds. If admission
        // refuses or its notifier unwinds, Sender::drop closes the channel;
        // permit_outstanding has never become observable.
        let obligation = cx
            .try_register_obligation_checked(
                crate::record::ObligationKind::SendPermit,
                cx.task_id(),
            )
            .map_err(|error| CheckedSendError::Admission { error, value: () })?;
        let permit = SendPermit {
            inner: Arc::clone(&self.inner),
            sent: false,
            obligation,
        };
        {
            let mut inner = self.inner.lock();
            inner.sender_consumed = true;
            inner.permit_outstanding = true;
        }
        Ok(permit)
    }

    /// Sends after checked admission, returning the unpublished value on error.
    pub fn send_checked(self, cx: &Cx, value: T) -> Result<(), CheckedSendError<T>> {
        match self.reserve_checked(cx) {
            Ok(permit) => permit.send(value).map_err(CheckedSendError::Channel),
            Err(CheckedSendError::Channel(SendError::Cancelled(()))) => {
                Err(CheckedSendError::Channel(SendError::Cancelled(value)))
            }
            Err(CheckedSendError::Channel(SendError::Disconnected(()))) => {
                Err(CheckedSendError::Channel(SendError::Disconnected(value)))
            }
            Err(CheckedSendError::Admission { error, value: () }) => {
                Err(CheckedSendError::Admission { error, value })
            }
        }
    }

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
            let (waker, receiver_closed_waker) = {
                let mut inner = self.inner.lock();
                inner.sender_consumed = true;
                inner.permit_outstanding = false;
                inner.record_cancellation();
                inner.closed_reason = Some("cancelled_reserve");
                (inner.take_waker(), inner.receiver_closed_waker.take())
            };
            wake_waker_after_unlock(waker);
            wake_waker_after_unlock(receiver_closed_waker);
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
            obligation: cx
                .try_register_obligation(crate::record::ObligationKind::SendPermit, cx.task_id()),
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
    ///
    /// # Example
    ///
    /// ```
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::channel::oneshot;
    ///
    /// let (tx, mut rx) = oneshot::channel();
    /// tx.send(cx, "finished").unwrap();
    ///
    /// assert_eq!(rx.try_recv().ok(), Some("finished"));
    /// # }
    /// ```
    #[inline]
    pub fn send(self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.reserve(cx) {
            Ok(permit) => permit.send(value),
            Err(SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
        }
    }

    /// Synchronously sends a value without requiring an async [`Cx`].
    ///
    /// This is a sync bridge for non-async callers. It does not park the
    /// current thread, wait for a receiver poll, or run the runtime; it only
    /// commits the value into the existing oneshot state machine and wakes any
    /// registered receiver. Because the operation is immediate, calling it from
    /// an asupersync runtime worker cannot deadlock that worker.
    ///
    /// # Errors
    ///
    /// Returns `Err(SendError::Disconnected(value))` if the receiver was
    /// dropped. This method never returns `SendError::Cancelled` because it has
    /// no [`Cx`] to observe.
    #[inline]
    pub fn send_blocking(self, value: T) -> Result<(), SendError<T>> {
        let permit = {
            let mut inner = self.inner.lock();
            inner.sender_consumed = true;
            inner.permit_outstanding = true;
            SendPermit {
                inner: Arc::clone(&self.inner),
                sent: false,
                obligation: None,
            }
        };

        permit.send(value)
    }

    /// Checks if the receiver has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_dropped
    }

    /// Returns an opt-in redacted telemetry snapshot for this oneshot sender.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> OneshotTelemetrySnapshot {
        self.inner.lock().telemetry_snapshot(channel_id)
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
    pub fn poll_closed(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut incoming_waker = None;
        loop {
            let mut inner = self.inner.lock();

            if inner.receiver_dropped {
                let retired_waker = inner.sender_waker.take();
                drop(inner);
                retire_waker_after_unlock(retired_waker);
                retire_waker_after_unlock(incoming_waker);
                return std::task::Poll::Ready(());
            }
            if inner
                .sender_waker
                .as_ref()
                .is_some_and(|stored| stored.will_wake(cx.waker()))
            {
                drop(inner);
                retire_waker_after_unlock(incoming_waker);
                return std::task::Poll::Pending;
            }
            let Some(prepared) = incoming_waker.take() else {
                drop(inner);
                // RawWaker cloning may run arbitrary user code. Prepare the
                // replacement without the channel mutex, then recheck state.
                incoming_waker = Some(cx.waker().clone());
                continue;
            };

            // Use a separate sender Waker so receiver waiter identity is
            // unaffected by poll_closed registration.
            let retired_waker = inner.sender_waker.replace(prepared);
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            return std::task::Poll::Pending;
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let (waker, receiver_closed_waker, retired_sender_waker) = {
            let mut inner = self.inner.lock();
            let retired_sender_waker = inner.sender_waker.take();
            if inner.sender_consumed {
                (None, None, retired_sender_waker)
            } else {
                inner.sender_consumed = true;
                inner.closed_reason = Some("sender_drop");
                // Take wakers under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                let waker = inner.take_waker();
                let receiver_closed_waker = inner.receiver_closed_waker.take();
                (waker, receiver_closed_waker, retired_sender_waker)
            }
        };
        retire_waker_after_unlock(retired_sender_waker);
        wake_waker_after_unlock(waker);
        // Wake receiver's poll_closed waiters independently.
        wake_waker_after_unlock(receiver_closed_waker);
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
    /// Runtime-tracked obligation for this reservation
    /// (br-asupersync-bi2462.14).
    ///
    /// Minted through the reserving `Cx`'s obligation mailbox, committed on
    /// a delivered send, aborted on a refused send, `abort()` or an unsent
    /// drop. `None` for `send_blocking` (no `Cx`) or a hand-built `Cx`.
    obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
}

/// Keep both closure notifications owned across obligation-settlement unwind.
struct ReleasedOneshotWake {
    receiver: Option<Waker>,
    closed: Option<Waker>,
    retired: Option<Waker>,
}

impl Drop for ReleasedOneshotWake {
    fn drop(&mut self) {
        retire_waker_after_unlock(self.retired.take());
        wake_waker_after_unlock(self.receiver.take());
        wake_waker_after_unlock(self.closed.take());
    }
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
        let (result, waker, retired_waker) = {
            let mut inner = self.inner.lock();

            if inner.receiver_dropped {
                // Receiver gone, return the value.  Clear stale waker
                // and release the lock as early as possible (mirrors the
                // Ok path).
                inner.permit_outstanding = false;
                let retired_waker = inner.take_waker();
                (Err(value), None, retired_waker)
            } else {
                inner.value = Some(value);
                inner.permit_outstanding = false;
                inner.closed_reason = None;
                // Take waker under lock, wake outside to avoid deadlock
                // with inline-polling executors.
                let waker = inner.take_waker();
                (Ok(()), waker, None)
            }
        };

        self.sent = true;
        let _wake = ReleasedOneshotWake {
            receiver: waker,
            closed: None,
            retired: retired_waker,
        };
        if let Some(token) = self.obligation.take() {
            if result.is_ok() {
                let _ = token.commit();
            } else {
                let _ = token.abort(crate::record::ObligationAbortReason::Error);
            }
        }
        result.map_err(SendError::Disconnected)
    }

    /// Aborts the send operation.
    ///
    /// This consumes the permit without sending a value. The receiver
    /// will see a `Closed` error when attempting to receive.
    #[inline]
    pub fn abort(mut self) {
        self.sent = true;
        let _wake = self.release_reservation("abort");
        if let Some(token) = self.obligation.take() {
            let _ = token.abort(crate::record::ObligationAbortReason::Explicit);
        }
    }

    fn release_reservation(&self, reason: &'static str) -> ReleasedOneshotWake {
        let (waker, receiver_closed_waker) = {
            let mut inner = self.inner.lock();
            inner.permit_outstanding = false;
            inner.record_cancellation();
            inner.closed_reason = Some(reason);
            // Take waker under lock, wake outside.
            (inner.take_waker(), inner.receiver_closed_waker.take())
        };
        ReleasedOneshotWake {
            receiver: waker,
            closed: receiver_closed_waker,
            retired: None,
        }
    }

    /// Returns `true` if the receiver has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_dropped
    }

    /// Returns an opt-in redacted telemetry snapshot for this send permit.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> OneshotTelemetrySnapshot {
        self.inner.lock().telemetry_snapshot(channel_id)
    }
}

impl<T> Drop for SendPermit<T> {
    fn drop(&mut self) {
        if !self.sent {
            // Permit dropped without sending - abort
            self.sent = true;
            let _wake = self.release_reservation("permit_drop");
            if let Some(token) = self.obligation.take() {
                let _ = token.abort(crate::record::ObligationAbortReason::Cancel);
            }
        }
    }
}

/// Polls an uninterruptible receive, registering `waiter_id` in the channel's
/// single receive-waiter slot.
///
/// The waiter identity is owned by the caller so both registration lifetimes
/// are expressible over one implementation:
///
/// - [`RecvUninterruptibleFuture`] keeps it in the future, so the future's
///   `Drop` retires the registration when the caller stops waiting.
/// - [`Receiver::poll_recv_uninterruptible`] keeps it on the long-lived
///   receiver, so a `Pending` registration *survives* the poll. A poll-based
///   join API needs that: it may scan several receivers in one poll and keep
///   none of the futures alive (br-asupersync-tncxj9).
fn poll_recv_uninterruptible_with_waiter<T>(
    channel: &Mutex<OneShotInner<T>>,
    waiter_id: &mut Option<u64>,
    ctx: &mut Context<'_>,
) -> Poll<Result<T, RecvError>> {
    {
        let mut inner = channel.lock();

        if let Some(value) = inner.value.take() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            inner.closed_reason = Some("committed");
            *waiter_id = None;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            *waiter_id = None;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            return Poll::Ready(Err(RecvError::Closed));
        }

        if receive_waker_is_current(&inner, *waiter_id, ctx.waker()) {
            return Poll::Pending;
        }
    }

    // RawWaker cloning may re-enter or panic. Prepare it without the
    // channel mutex, then recheck terminal state and ownership.
    let mut incoming_waker = Some(ctx.waker().clone());
    let mut inner = channel.lock();

    if let Some(value) = inner.value.take() {
        let retired_waker = inner.take_waker();
        let retired_closed_waker = inner.receiver_closed_waker.take();
        inner.closed_reason = Some("committed");
        *waiter_id = None;
        drop(inner);
        retire_waker_after_unlock(retired_waker);
        wake_waker_after_unlock(retired_closed_waker);
        retire_waker_after_unlock(incoming_waker);
        return Poll::Ready(Ok(value));
    }

    if inner.is_closed() {
        let retired_waker = inner.take_waker();
        let retired_closed_waker = inner.receiver_closed_waker.take();
        *waiter_id = None;
        drop(inner);
        retire_waker_after_unlock(retired_waker);
        wake_waker_after_unlock(retired_closed_waker);
        retire_waker_after_unlock(incoming_waker);
        return Poll::Ready(Err(RecvError::Closed));
    }

    let retired_waker =
        install_receive_waker(&mut inner, waiter_id, ctx.waker(), &mut incoming_waker);
    drop(inner);
    retire_waker_after_unlock(retired_waker);
    retire_waker_after_unlock(incoming_waker);
    Poll::Pending
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

        let polled =
            poll_recv_uninterruptible_with_waiter(&this.receiver.inner, &mut this.waiter_id, ctx);
        if polled.is_ready() {
            this.completed = true;
        }
        polled
    }
}

impl<T> Drop for RecvUninterruptibleFuture<'_, T> {
    fn drop(&mut self) {
        let retired_waker = {
            let mut inner = self.receiver.inner.lock();
            if self
                .waiter_id
                .is_some_and(|waiter_id| inner.waker_id == Some(waiter_id))
            {
                inner.take_waker()
            } else {
                None
            }
        };
        retire_waker_after_unlock(retired_waker);
        self.waiter_id = None;
    }
}

/// Future returned by [`Receiver::recv`].
#[derive(Debug)]
struct RegisteredCancelWaker {
    waker: Waker,
    token: CancelWakerToken,
}

pub struct RecvFuture<'a, T, Caps = crate::cx::cap::All> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx<Caps>,
    waiter_id: Option<u64>,
    cancel_waker: Option<RegisteredCancelWaker>,
    completed: bool,
}

impl<T, Caps> RecvFuture<'_, T, Caps> {
    #[must_use]
    #[allow(dead_code)] // Public API — may be used by future callers
    #[inline]
    pub(crate) fn receiver_finished(&self) -> bool {
        self.completed || self.receiver.is_ready() || self.receiver.is_closed()
    }

    /// Keep exactly one cancellation-Waker registration owned by this future.
    fn refresh_cancel_waker(&mut self, waker: &Waker) {
        let same_local_waker = self
            .cancel_waker
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming_waker = (!same_local_waker).then(|| waker.clone());
        let previous_token = self
            .cancel_waker
            .as_ref()
            .map(|registered| registered.token);
        let token = self.cx.refresh_cancel_waker(previous_token, waker);
        let retired_waker = if let Some(incoming_waker) = incoming_waker {
            self.cancel_waker
                .replace(RegisteredCancelWaker {
                    waker: incoming_waker,
                    token,
                })
                .map(|registered| registered.waker)
        } else {
            self.cancel_waker
                .as_mut()
                .expect("same local Waker requires an existing registration")
                .token = token;
            None
        };
        retire_waker_after_unlock(retired_waker);
    }

    /// Release this future's exact cancellation-Waker registration.
    fn clear_cancel_waker(&mut self) {
        let Some(registered) = self.cancel_waker.take() else {
            return;
        };
        self.cx.clear_cancel_waker(registered.token);
        retire_waker_after_unlock(Some(registered.waker));
    }

    /// Finish a cancelled poll after rechecking terminal channel state.
    fn finish_cancelled(&mut self, incoming_waker: Option<Waker>) -> Poll<Result<T, RecvError>> {
        let mut inner = self.receiver.inner.lock();

        if let Some(value) = inner.value.take() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            inner.closed_reason = Some("committed");
            self.waiter_id = None;
            self.completed = true;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            retire_waker_after_unlock(incoming_waker);
            self.clear_cancel_waker();
            self.cx.trace("oneshot::recv received value");
            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            self.waiter_id = None;
            self.completed = true;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            retire_waker_after_unlock(incoming_waker);
            self.clear_cancel_waker();
            self.cx.trace("oneshot::recv channel closed");
            return Poll::Ready(Err(RecvError::Closed));
        }

        let retired_waker = if self
            .waiter_id
            .is_some_and(|waiter_id| inner.waker_id == Some(waiter_id))
        {
            inner.take_waker()
        } else {
            None
        };
        inner.record_cancellation();
        self.waiter_id = None;
        self.completed = true;
        drop(inner);
        retire_waker_after_unlock(retired_waker);
        retire_waker_after_unlock(incoming_waker);
        self.clear_cancel_waker();
        self.cx.trace("oneshot::recv cancelled while waiting");
        Poll::Ready(Err(RecvError::Cancelled))
    }
}

impl<T, Caps> Future for RecvFuture<'_, T, Caps> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.completed {
            this.clear_cancel_waker();
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        let needs_waker = {
            let mut inner = this.receiver.inner.lock();

            // Value and closure retain precedence over cancellation.
            if let Some(value) = inner.value.take() {
                let retired_waker = inner.take_waker();
                let retired_closed_waker = inner.receiver_closed_waker.take();
                inner.closed_reason = Some("committed");
                this.waiter_id = None;
                this.completed = true;
                drop(inner);
                retire_waker_after_unlock(retired_waker);
                wake_waker_after_unlock(retired_closed_waker);
                this.clear_cancel_waker();
                this.cx.trace("oneshot::recv received value");
                return Poll::Ready(Ok(value));
            }

            if inner.is_closed() {
                let retired_waker = inner.take_waker();
                let retired_closed_waker = inner.receiver_closed_waker.take();
                this.waiter_id = None;
                this.completed = true;
                drop(inner);
                retire_waker_after_unlock(retired_waker);
                wake_waker_after_unlock(retired_closed_waker);
                this.clear_cancel_waker();
                this.cx.trace("oneshot::recv channel closed");
                return Poll::Ready(Err(RecvError::Closed));
            }

            !receive_waker_is_current(&inner, this.waiter_id, ctx.waker())
        };

        // Check before cloning so a pre-cancelled receive fails closed without
        // invoking an arbitrary RawWaker clone callback. The channel mutex is
        // not held because checkpoint evidence sinks may re-enter the channel.
        if this.cx.checkpoint().is_err() {
            return this.finish_cancelled(None);
        }

        // Prepare the channel registration outside its mutex, then establish
        // an owned Cx cancellation registration. A second checkpoint closes
        // the race across both clone callbacks and registration.
        let mut incoming_waker = needs_waker.then(|| ctx.waker().clone());
        this.refresh_cancel_waker(ctx.waker());
        if this.cx.checkpoint().is_err() {
            return this.finish_cancelled(incoming_waker);
        }

        let mut inner = this.receiver.inner.lock();

        if let Some(value) = inner.value.take() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            inner.closed_reason = Some("committed");
            this.waiter_id = None;
            this.completed = true;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            retire_waker_after_unlock(incoming_waker);
            this.clear_cancel_waker();
            this.cx.trace("oneshot::recv received value");
            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            let retired_waker = inner.take_waker();
            let retired_closed_waker = inner.receiver_closed_waker.take();
            this.waiter_id = None;
            this.completed = true;
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            wake_waker_after_unlock(retired_closed_waker);
            retire_waker_after_unlock(incoming_waker);
            this.clear_cancel_waker();
            this.cx.trace("oneshot::recv channel closed");
            return Poll::Ready(Err(RecvError::Closed));
        }

        if receive_waker_is_current(&inner, this.waiter_id, ctx.waker()) {
            drop(inner);
            retire_waker_after_unlock(incoming_waker);
            return Poll::Pending;
        }

        let retired_waker = install_receive_waker(
            &mut inner,
            &mut this.waiter_id,
            ctx.waker(),
            &mut incoming_waker,
        );
        drop(inner);
        retire_waker_after_unlock(retired_waker);
        retire_waker_after_unlock(incoming_waker);
        Poll::Pending
    }
}

impl<T, Caps> Drop for RecvFuture<'_, T, Caps> {
    fn drop(&mut self) {
        // If dropped while Pending (e.g., select/race loser), clear
        // the registered waker to avoid retaining stale executor state.
        let retired_waker = {
            let mut inner = self.receiver.inner.lock();
            // Clear only if this future still owns the registered waiter slot.
            if self
                .waiter_id
                .is_some_and(|waiter_id| inner.waker_id == Some(waiter_id))
            {
                inner.take_waker()
            } else {
                None
            }
        };
        retire_waker_after_unlock(retired_waker);
        self.waiter_id = None;
        self.clear_cancel_waker();
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
    /// Waiter identity for [`Receiver::poll_recv_uninterruptible`].
    ///
    /// Living on the receiver rather than in a per-poll future is what keeps a
    /// `Pending` registration alive across polls (br-asupersync-tncxj9).
    /// `Receiver::drop` retires the registration, so no executor state is
    /// retained past the receiver's own lifetime.
    poll_waiter_id: Option<u64>,
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
    pub fn recv<'a, Caps>(&'a mut self, cx: &'a Cx<Caps>) -> RecvFuture<'a, T, Caps> {
        RecvFuture {
            receiver: self,
            cx,
            waiter_id: None,
            cancel_waker: None,
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

    /// Polls for a value, ignoring cancellation, keeping the wake registration
    /// on the receiver itself.
    ///
    /// This is the poll-based form of
    /// [`recv_uninterruptible`](Self::recv_uninterruptible) for callers that
    /// cannot hold a future across polls. The difference that matters is the
    /// registration lifetime: a `Pending` result leaves this receiver's waiter
    /// installed, whereas dropping a `RecvUninterruptibleFuture` retires it. A
    /// caller that builds a fresh future per poll therefore ends its scan with
    /// no waker registered anywhere and never wakes (br-asupersync-tncxj9).
    ///
    /// A terminal result drains the channel, so a later call observes
    /// [`RecvError::Closed`] rather than a distinct already-completed signal.
    /// Callers that need to tell those apart track terminality themselves; see
    /// [`TaskHandle::poll_join`](crate::runtime::TaskHandle::poll_join).
    #[inline]
    pub(crate) fn poll_recv_uninterruptible(
        &mut self,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<T, RecvError>> {
        let Self {
            inner,
            poll_waiter_id,
        } = self;
        poll_recv_uninterruptible_with_waiter(inner, poll_waiter_id, ctx)
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `TryRecvError::Empty` if no value is available yet but sender exists
    /// - `TryRecvError::Closed` if the sender was dropped without sending
    #[inline]
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let (result, retired_waker, retired_closed_waker) = {
            let mut inner = self.inner.lock();

            if let Some(value) = inner.value.take() {
                // Terminal success path: detach stale waiter registration.
                let retired_waker = inner.take_waker();
                let retired_closed_waker = inner.receiver_closed_waker.take();
                inner.closed_reason = Some("committed");
                (Ok(value), retired_waker, retired_closed_waker)
            } else if inner.is_closed() {
                // Terminal closed path: detach stale waiter registration.
                let retired_waker = inner.take_waker();
                let retired_closed_waker = inner.receiver_closed_waker.take();
                (
                    Err(TryRecvError::Closed),
                    retired_waker,
                    retired_closed_waker,
                )
            } else {
                (Err(TryRecvError::Empty), None, None)
            }
        };
        retire_waker_after_unlock(retired_waker);
        // A terminal value drain (or observing an already-closed channel) makes
        // `is_closed()` true, so any registered `poll_closed` waiter must be
        // WOKEN, not silently dropped — otherwise it parks forever
        // (br-asupersync-0i8acc). For the `Empty` path this is None (no-op).
        wake_waker_after_unlock(retired_closed_waker);
        result
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

    /// Returns an opt-in redacted telemetry snapshot for this oneshot receiver.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> OneshotTelemetrySnapshot {
        self.inner.lock().telemetry_snapshot(channel_id)
    }

    /// Returns a future that resolves when the sender is dropped.
    ///
    /// This provides async notification of channel closure without attempting
    /// to receive a value. Useful for detecting sender dropout.
    #[inline]
    pub fn poll_closed(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let mut incoming_waker = None;
        loop {
            let mut inner = self.inner.lock();

            if inner.is_closed() {
                let retired_waker = inner.receiver_closed_waker.take();
                drop(inner);
                retire_waker_after_unlock(retired_waker);
                retire_waker_after_unlock(incoming_waker);
                return std::task::Poll::Ready(());
            }
            if inner
                .receiver_closed_waker
                .as_ref()
                .is_some_and(|stored| stored.will_wake(cx.waker()))
            {
                drop(inner);
                retire_waker_after_unlock(incoming_waker);
                return std::task::Poll::Pending;
            }
            let Some(prepared) = incoming_waker.take() else {
                drop(inner);
                incoming_waker = Some(cx.waker().clone());
                continue;
            };

            // Keep closure notification separate from the main receiver
            // waiter identity slot.
            let retired_waker = inner.receiver_closed_waker.replace(prepared);
            drop(inner);
            retire_waker_after_unlock(retired_waker);
            return std::task::Poll::Pending;
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (sender_waker, retired_recv_waker, retired_closed_waker, closed_after_drop, _value) = {
            let mut inner = self.inner.lock();
            inner.receiver_dropped = true;
            inner.closed_reason = Some("receiver_drop");
            // Clear any pending recv waker so a dropped receiver does not
            // retain executor task state indefinitely.
            let retired_recv_waker = inner.take_waker();
            // Take sender waker to notify poll_closed waiters
            let sender_waker = inner.sender_waker.take();
            // Always retire the receiver-closed slot so a dropped receiver keeps
            // no executor state, but capture whether the channel is terminal
            // AFTER the drop so a still-registered `poll_closed` waiter is only
            // woken when its awaited predicate actually holds
            // (br-asupersync-0i8acc).
            let retired_closed_waker = inner.receiver_closed_waker.take();
            let value = inner.value.take();
            let closed_after_drop = inner.is_closed();
            (
                sender_waker,
                retired_recv_waker,
                retired_closed_waker,
                closed_after_drop,
                value,
            )
        };
        retire_waker_after_unlock(retired_recv_waker);
        if closed_after_drop {
            wake_waker_after_unlock(retired_closed_waker);
        } else {
            retire_waker_after_unlock(retired_closed_waker);
        }
        // Wake sender waker outside lock to avoid deadlock.
        wake_waker_after_unlock(sender_waker);
    }
}

#[cfg(test)]
include!("oneshot_tests.rs");
