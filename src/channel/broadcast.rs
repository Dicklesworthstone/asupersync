#![allow(clippy::cast_possible_wrap)]
//! Two-phase broadcast channel (Async).
//!
//! A multi-producer, multi-consumer channel where each message is sent to all
//! active receivers. Useful for event buses, chat systems, and fan-out updates.
//!
//! # Semantics
//!
//! - **Bounded**: The channel has a fixed capacity.
//! - **Lagging**: If a receiver falls behind by more than `capacity` messages,
//!   it will miss messages and receive a `RecvError::Lagged` error.
//! - **Fan-out**: Every message sent is seen by all active receivers.
//! - **Two-phase**: Senders use `reserve` + `send` for cancel-safety.
//!
//! # Cancel Safety
//!
//! - `reserve` is cancel-safe: if cancelled, no slot is consumed.
//! - `recv` is cancel-safe: if cancelled, no message is consumed (cursor not advanced).

use crate::cx::Cx;
use crate::util::{Arena, ArenaIndex};
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Error returned when sending fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError<T> {
    /// There are no active receivers. The message is returned.
    Closed(T),
    /// The capability context was cancelled before the reservation
    /// could be granted. No slot was consumed; no receiver observed
    /// the message. (br-asupersync-bed5oh)
    Cancelled(T),
}

impl<T> std::fmt::Display for SendError<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(_) => write!(f, "sending on a closed broadcast channel"),
            Self::Cancelled(_) => write!(f, "broadcast send cancelled by Cx"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

/// A checked send failed before publication, retaining the caller's value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckedSendError<T> {
    /// The channel refused the operation.
    Channel(SendError<T>),
    /// The runtime refused the obligation before returning a permit.
    Admission {
        /// The authoritative admission refusal.
        error: crate::runtime::obligation_mailbox::ObligationAdmissionError,
        /// The value which was not published.
        value: T,
    },
}

impl<T> From<SendError<T>> for CheckedSendError<T> {
    fn from(error: SendError<T>) -> Self {
        Self::Channel(error)
    }
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

impl CheckedSendError<()> {
    fn with_value<T>(self, value: T) -> CheckedSendError<T> {
        match self {
            Self::Channel(SendError::Closed(())) => {
                CheckedSendError::Channel(SendError::Closed(value))
            }
            Self::Channel(SendError::Cancelled(())) => {
                CheckedSendError::Channel(SendError::Cancelled(value))
            }
            Self::Admission { error, value: () } => CheckedSendError::Admission { error, value },
        }
    }
}

/// Error returned when receiving fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The receiver fell behind and missed messages.
    /// The value is the number of skipped messages.
    Lagged(u64),
    /// All senders have been dropped.
    Closed,
    /// The receive operation was cancelled.
    Cancelled,
    /// The receive future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for RecvError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lagged(n) => write!(f, "receiver lagged by {n} messages"),
            Self::Closed => write!(f, "broadcast channel closed"),
            Self::Cancelled => write!(f, "[ASUP-E203] receive operation cancelled"),
            Self::PolledAfterCompletion => {
                write!(f, "broadcast receive future polled after completion")
            }
        }
    }
}

impl std::error::Error for RecvError {}

/// Error returned by [`Receiver::try_recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    /// The channel buffer is empty; no message is available right now.
    Empty,
    /// The receiver fell behind and missed messages.
    /// The value is the number of skipped messages.
    Lagged(u64),
    /// All senders have been dropped and the buffer is drained.
    Closed,
}

impl std::fmt::Display for TryRecvError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "broadcast channel empty"),
            Self::Lagged(n) => write!(f, "receiver lagged by {n} messages"),
            Self::Closed => write!(f, "broadcast channel closed"),
        }
    }
}

impl std::error::Error for TryRecvError {}

/// Opt-in, redacted telemetry snapshot for a broadcast channel.
///
/// The caller supplies `channel_id`, which keeps identifiers deterministic and
/// avoids ambient globals or pointer-derived IDs. Payload values are never
/// exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BroadcastTelemetrySnapshot {
    /// Caller-provided deterministic channel identifier.
    pub channel_id: u64,
    /// Stable channel kind label.
    pub channel_kind: &'static str,
    /// Maximum number of committed messages retained for lagging receivers.
    pub capacity: usize,
    /// Number of committed values retained in the broadcast ring.
    pub queued_messages: usize,
    /// Broadcast reservations do not consume ring capacity before commit.
    pub reserved_uncommitted_obligations: usize,
    /// Broadcast has no sender-side capacity waiters.
    pub send_waiter_count: usize,
    /// Receiver-side waiters waiting for messages or closure.
    pub recv_waiter_count: usize,
    /// Number of active receivers.
    pub receiver_count: usize,
    /// Redacted receiver state for this snapshot view.
    pub receiver_health: &'static str,
    /// Number of tracked receivers whose cursor has fallen behind the ring.
    pub lagged_receiver_count: Option<usize>,
    /// Cancel/abort events observed by the channel.
    pub cancellation_count: u64,
    /// Whether either endpoint class has closed.
    ///
    /// Retained ring entries may still be readable after the last sender drops;
    /// `queued_messages` therefore need not be zero when this is `true`.
    pub closed: bool,
}

/// Internal state shared between senders and receivers.
#[derive(Debug)]
struct Shared<T> {
    /// The ring buffer of messages.
    buffer: VecDeque<Slot<T>>,
    /// Maximum capacity of the buffer.
    capacity: usize,
    /// Total number of messages ever sent (for lag detection).
    total_sent: u64,
    /// Waiting receivers.
    wakers: Arena<Waker>,
    /// Active receiver cursors used for explicit lag telemetry.
    receiver_cursors: Arena<u64>,
    /// Number of cancellation/abort events observed by this channel.
    cancellation_count: u64,
}

struct Slot<T> {
    /// Shared ownership lets receivers retain a message while cloning `T`
    /// outside the channel-wide mutex. The per-message mutex preserves the
    /// channel's `T: Send + Clone` contract without adding a `T: Sync` bound.
    msg: Arc<Mutex<T>>,
    /// The cumulative index of this message.
    index: u64,
}

impl<T> std::fmt::Debug for Slot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("msg", &"<redacted>")
            .field("index", &self.index)
            .finish()
    }
}

/// Shared wrapper.
struct Channel<T> {
    /// Number of active senders (lock-free for clone/drop).
    sender_count: AtomicUsize,
    /// Number of active receivers (lock-free for reserve/clone/drop).
    receiver_count: AtomicUsize,
    inner: Mutex<Shared<T>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Channel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Ring slots allocated up front; a larger capacity grows as messages arrive.
const PREALLOCATED_SLOTS: usize = 1024;

/// Creates a new broadcast channel with the given capacity.
///
/// The ring allocates at most 1024 slots up front and grows as messages
/// arrive, so a capacity larger than any backlog (even `usize::MAX`) costs
/// only what is actually buffered.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
#[inline]
pub fn channel<T: Clone>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "capacity must be non-zero");
    let mut receiver_cursors = Arena::new();
    let receiver_token = receiver_cursors.insert(0);

    let shared = Arc::new(Channel {
        sender_count: AtomicUsize::new(1),
        receiver_count: AtomicUsize::new(1),
        inner: Mutex::new(Shared {
            buffer: VecDeque::with_capacity(capacity.min(PREALLOCATED_SLOTS)),
            capacity,
            total_sent: 0,
            wakers: Arena::new(),
            receiver_cursors,
            cancellation_count: 0,
        }),
    });

    let sender = Sender {
        channel: Arc::clone(&shared),
    };

    let receiver = Receiver {
        channel: shared,
        next_index: 0,
        receiver_token,
    };

    (sender, receiver)
}

impl<T> Shared<T> {
    #[inline]
    fn earliest_index(&self) -> u64 {
        self.buffer
            .front()
            .map_or(self.total_sent, |slot| slot.index)
    }

    #[inline]
    fn is_message_ready_for(&self, next_index: u64) -> bool {
        let earliest = self.earliest_index();
        let delta = next_index.saturating_sub(earliest);
        usize::try_from(delta).is_ok_and(|offset| self.buffer.get(offset).is_some())
    }

    #[inline]
    fn update_receiver_cursor(&mut self, token: ArenaIndex, next_index: u64) {
        if let Some(cursor) = self.receiver_cursors.get_mut(token) {
            *cursor = next_index;
        }
    }

    #[inline]
    fn lagged_receiver_count(&self) -> usize {
        let earliest = self.earliest_index();
        self.receiver_cursors
            .iter()
            .filter(|(_, next_index)| **next_index < earliest)
            .count()
    }

    #[inline]
    fn record_cancellation(&mut self) {
        self.cancellation_count = self.cancellation_count.saturating_add(1);
    }
}

impl<T> Channel<T> {
    #[inline]
    fn receiver_count_snapshot(&self) -> usize {
        // Telemetry and public count APIs report an observational counter only;
        // receiver cursor state remains protected by `inner`.
        self.receiver_count.load(Ordering::Relaxed)
    }

    #[inline]
    fn has_receivers_snapshot(&self) -> bool {
        self.receiver_count_snapshot() != 0
    }

    #[inline]
    fn record_cancellation(&self) {
        self.inner.lock().record_cancellation();
    }

    #[inline]
    fn telemetry_snapshot(
        &self,
        channel_id: u64,
        receiver_next_index: Option<u64>,
    ) -> BroadcastTelemetrySnapshot {
        let inner = self.inner.lock();
        let receiver_count = self.receiver_count_snapshot();
        let sender_count = self.sender_count.load(Ordering::Relaxed);
        let queued_messages = inner.buffer.len();
        let recv_waiter_count = inner.wakers.len();
        let lagged_receiver_count = inner.lagged_receiver_count();
        let closed = receiver_count == 0 || sender_count == 0;

        let receiver_health = if receiver_count == 0 {
            "receiver_dropped"
        } else if receiver_next_index.is_some_and(|next_index| next_index < inner.earliest_index())
        {
            "lagged"
        } else if receiver_next_index
            .is_some_and(|next_index| inner.is_message_ready_for(next_index))
        {
            "value_ready"
        } else if sender_count == 0 {
            "sender_closed"
        } else if recv_waiter_count > 0 {
            "waiting"
        } else if receiver_next_index.is_some() {
            "caught_up"
        } else {
            "open"
        };

        BroadcastTelemetrySnapshot {
            channel_id,
            channel_kind: "broadcast",
            capacity: inner.capacity,
            queued_messages,
            reserved_uncommitted_obligations: 0,
            send_waiter_count: 0,
            recv_waiter_count,
            receiver_count,
            receiver_health,
            lagged_receiver_count: Some(lagged_receiver_count),
            cancellation_count: inner.cancellation_count,
            closed,
        }
    }
}

/// The sending side of a broadcast channel.
#[derive(Debug)]
pub struct Sender<T> {
    channel: Arc<Channel<T>>,
}

impl<T: Clone> Sender<T> {
    /// Reserves a slot to send a message.
    ///
    /// This is cancel-safe. Broadcast channels are never "full" for senders;
    /// old messages are overwritten if capacity is exceeded.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed(())` if there are no active receivers.
    #[inline]
    pub fn reserve(&self, cx: &Cx) -> Result<SendPermit<'_, T>, SendError<()>> {
        // br-asupersync-bed5oh: cancel-correctness invariant. The previous
        // implementation only TRACED the cancel and fell through to grant
        // the permit. Per AGENTS.md ("cancellation is a protocol — request
        // → drain → finalize, not a silent drop") and the broadcast
        // contract above ("reserve is cancel-safe: if cancelled, no slot
        // is consumed"), reserve MUST surface the cancel as an error so
        // the caller doesn't proceed to commit a message under a cancelled
        // Cx.
        if cx.checkpoint().is_err() {
            self.channel.record_cancellation();
            return Err(SendError::Cancelled(()));
        }

        if !self.channel.has_receivers_snapshot() {
            return Err(SendError::Closed(()));
        }

        Ok(SendPermit {
            sender: self,
            obligation: cx
                .try_register_obligation(crate::record::ObligationKind::SendPermit, cx.task_id()),
            checked: false,
        })
    }

    /// Reserves a send permit after authoritative runtime obligation admission.
    ///
    /// Like [`Self::reserve`], this is synchronous and never waits for ring
    /// capacity. Admission does not publish or evict a message. A deliberately
    /// stateless `Cx` may return an untracked permit; a runtime-associated
    /// context must have a live holder and available regional obligation quota.
    ///
    /// # Errors
    ///
    /// Returns [`CheckedSendError::Channel`] on cancellation or when no receiver
    /// is active, and [`CheckedSendError::Admission`] if the runtime refuses the
    /// obligation. Dropping an admitted permit returns its quota immediately.
    #[inline]
    pub fn reserve_checked(&self, cx: &Cx) -> Result<SendPermit<'_, T>, CheckedSendError<()>> {
        if cx.checkpoint().is_err() {
            self.channel.record_cancellation();
            return Err(CheckedSendError::Channel(SendError::Cancelled(())));
        }
        if !self.channel.has_receivers_snapshot() {
            return Err(CheckedSendError::Channel(SendError::Closed(())));
        }

        let obligation = cx
            .try_register_obligation_checked(
                crate::record::ObligationKind::SendPermit,
                cx.task_id(),
            )
            .map_err(|error| CheckedSendError::Admission { error, value: () })?;
        Ok(SendPermit {
            sender: self,
            obligation,
            checked: true,
        })
    }

    /// Sends a message to all receivers.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed(msg)` if there are no active receivers
    /// when reservation is attempted. Returns `SendError::Cancelled(msg)` if
    /// the capability context was cancelled before the permit was granted
    /// (the message is returned). Returns
    /// `Ok(0)` if all receivers drop between reservation and commit.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::channel::broadcast;
    ///
    /// let (tx, mut rx) = broadcast::channel(4);
    /// let delivered = tx.send(cx, "config-updated").unwrap();
    ///
    /// assert_eq!(delivered, 1);
    /// assert_eq!(rx.try_recv().ok(), Some("config-updated"));
    /// # }
    /// ```
    #[inline]
    pub fn send(&self, cx: &Cx, msg: T) -> Result<usize, SendError<T>> {
        let permit = match self.reserve(cx) {
            Ok(p) => p,
            Err(SendError::Closed(())) => return Err(SendError::Closed(msg)),
            Err(SendError::Cancelled(())) => return Err(SendError::Cancelled(msg)),
        };
        Ok(permit.send(msg))
    }

    /// Sends synchronously after checked obligation admission.
    ///
    /// The receiver count and last-receiver race follow [`Self::send`]. Runtime
    /// quota is settled before invoking notification callbacks, so another
    /// checked send may reuse it without waiting for a mailbox drain.
    ///
    /// # Errors
    ///
    /// Returns the unpublished message with any refusal from
    /// [`Self::reserve_checked`].
    #[inline]
    pub fn send_checked(&self, cx: &Cx, msg: T) -> Result<usize, CheckedSendError<T>> {
        match self.reserve_checked(cx) {
            Ok(permit) => Ok(permit.send(msg)),
            Err(error) => Err(error.with_value(msg)),
        }
    }

    /// Returns the number of active receivers.
    ///
    /// This is an observational snapshot for telemetry and routing decisions,
    /// not a synchronization primitive. Receiver cursor state remains protected
    /// by the channel mutex.
    #[must_use]
    #[inline]
    pub fn receiver_count(&self) -> usize {
        self.channel.receiver_count_snapshot()
    }

    /// Returns the number of messages currently buffered in the channel.
    ///
    /// # Tokio Divergence
    ///
    /// Unlike Tokio's broadcast channel (which eagerly clears individual slots once
    /// all active receivers have read them), `asupersync` retains messages in the
    /// ring buffer until overwritten upon reaching capacity (eviction) or when the
    /// channel is dropped. Therefore, `len()` reports the count of ring buffer slots
    /// currently occupied rather than unread messages for a specific receiver, and
    /// a `while !tx.is_empty()` loop will not drain the channel (br-asupersync-lh4z78 L2).
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.channel.inner.lock().buffer.len()
    }

    /// Returns `true` if no messages are buffered.
    ///
    /// See [`len`](Self::len) for ring buffer retention semantics.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[must_use]
    #[inline]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> BroadcastTelemetrySnapshot {
        self.channel.telemetry_snapshot(channel_id, None)
    }

    /// Creates a new receiver subscribed to this channel.
    #[must_use]
    #[inline]
    pub fn subscribe(&self) -> Receiver<T> {
        let (total_sent, receiver_token, _to_drop) = {
            let mut inner = self.channel.inner.lock();
            let total_sent = inner.total_sent;
            let receiver_token = inner.receiver_cursors.insert(total_sent);
            let to_drop = if self.channel.receiver_count.fetch_add(1, Ordering::Relaxed) == 0 {
                Some(std::mem::take(&mut inner.buffer))
            } else {
                None
            };
            (total_sent, receiver_token, to_drop)
        };

        Receiver {
            channel: Arc::clone(&self.channel),
            next_index: total_sent,
            receiver_token,
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.channel.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            channel: Arc::clone(&self.channel),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // Lock-free decrement; only acquire the mutex when the last sender
        // drops and receivers need waking.
        if self.channel.sender_count.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let wakers_to_wake: SmallVec<[Waker; 4]> = {
            let mut inner = self.channel.inner.lock();
            inner.wakers.drain_values().collect()
        };
        // Each receiver is woken behind its own unwind boundary, so one
        // panicking waker cannot leave the others parked with no sender left.
        drop(CheckedSendNotifications {
            obligation: None,
            receivers: wakers_to_wake,
        });
    }
}

/// A permit to send a message.
///
/// Consuming this permit sends the message.
#[must_use = "SendPermit must be consumed via send()"]
pub struct SendPermit<'a, T> {
    sender: &'a Sender<T>,
    /// Runtime-tracked obligation for this reservation
    /// (br-asupersync-bi2462.14).
    ///
    /// Minted through the reserving `Cx`'s obligation mailbox, committed
    /// when `send` runs (even to zero live receivers: the permit was
    /// honoured), aborted on an unsent drop.
    obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    /// Preserve legacy callback ordering while checked sends settle before
    /// callbacks and finish waking detached receivers even if a callback panics.
    checked: bool,
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if let Some(token) = self.obligation.take() {
            let _ = token.abort(crate::record::ObligationAbortReason::Cancel);
        }
    }
}

enum FinalLivenessAction {
    Normal,
    #[cfg(test)]
    ForceZeroReceivers,
}

/// Own every detached callback before invoking user payload destructors. The
/// first panic remains visible, and later callbacks still get one attempt.
/// During an existing unwind, secondary panic payloads must not be dropped.
struct CheckedSendNotifications {
    obligation: Option<Arc<crate::runtime::obligation_mailbox::ObligationGateway>>,
    receivers: SmallVec<[Waker; 4]>,
}

impl Drop for CheckedSendNotifications {
    fn drop(&mut self) {
        let already_panicking = std::thread::panicking();
        let mut first_panic = None;
        let mut record = |result| {
            if let Err(payload) = result {
                if already_panicking || first_panic.is_some() {
                    std::mem::forget(payload);
                } else {
                    first_panic = Some(payload);
                }
            }
        };
        if let Some(gateway) = self.obligation.take() {
            record(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || gateway.notify(),
            )));
        }
        for waker in self.receivers.drain(..) {
            // Keep the owning waker outside the wake callback's unwind. Its
            // final payload destructor may also panic, and must run only after
            // the first unwind has been caught.
            record(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || waker.wake_by_ref(),
            )));
            record(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || drop(waker),
            )));
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }
}

impl<T: Clone> SendPermit<'_, T> {
    fn checked_notifications(
        &mut self,
        receivers: SmallVec<[Waker; 4]>,
    ) -> CheckedSendNotifications {
        CheckedSendNotifications {
            obligation: self
                .obligation
                .take()
                .and_then(|token| token.commit_deferred().1),
            receivers,
        }
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[must_use]
    #[inline]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> BroadcastTelemetrySnapshot {
        self.sender.telemetry_snapshot(channel_id)
    }

    /// Sends the message.
    ///
    /// Returns the number of receivers that were live at commit time.
    ///
    /// If all receivers drop before the final commit snapshot, this returns `0`
    /// and leaves channel state unchanged.
    #[inline]
    pub fn send(self, msg: T) -> usize {
        self.send_impl(msg, FinalLivenessAction::Normal)
    }

    #[cfg(test)]
    #[inline]
    fn send_forcing_zero_at_final_liveness(self, msg: T) -> usize {
        self.send_impl(msg, FinalLivenessAction::ForceZeroReceivers)
    }

    #[inline]
    fn send_impl(mut self, msg: T, final_liveness_action: FinalLivenessAction) -> usize {
        if !self.checked
            && let Some(token) = self.obligation.take()
        {
            let _ = token.commit();
        }
        let mut inner = self.sender.channel.inner.lock();

        // Re-check receiver liveness under the same lock used for commit.
        // This closes the race where the last receiver drops while a sender
        // is waiting to acquire `inner`.
        if self.sender.channel.receiver_count.load(Ordering::Acquire) == 0 {
            drop(inner);
            let _notifications = self
                .checked
                .then(|| self.checked_notifications(SmallVec::new()));
            drop(msg);
            return 0;
        }

        let popped = if inner.buffer.len() == inner.capacity {
            inner.buffer.pop_front()
        } else {
            None
        };

        let index = inner.total_sent;
        inner.buffer.push_back(Slot {
            msg: Arc::new(Mutex::new(msg)),
            index,
        });

        // Snapshot receiver liveness before unlocking so late subscribers are
        // never counted for a message that committed before they existed.
        let live_receivers = match final_liveness_action {
            FinalLivenessAction::Normal => {
                self.sender.channel.receiver_count.load(Ordering::Acquire)
            }
            #[cfg(test)]
            FinalLivenessAction::ForceZeroReceivers => 0,
        };
        if live_receivers == 0 {
            let rolled_back = inner.buffer.pop_back();
            if let Some(slot) = popped {
                inner.buffer.push_front(slot);
            }
            drop(inner);
            let _notifications = self
                .checked
                .then(|| self.checked_notifications(SmallVec::new()));
            drop(rolled_back);
            return 0;
        }

        inner.total_sent += 1;

        // Drain wakers under lock (by ownership, no clone), wake outside
        // to avoid deadlock with inline-polling executors.
        let wakers_to_wake: SmallVec<[Waker; 4]> = inner.wakers.drain_values().collect();

        drop(inner);
        // Own the wakers before the evicted message's destructor runs: a
        // panicking `T::drop`, or waker, must still wake every receiver.
        let _notifications = if self.checked {
            self.checked_notifications(wakers_to_wake)
        } else {
            CheckedSendNotifications {
                obligation: None,
                receivers: wakers_to_wake,
            }
        };
        drop(popped);

        live_receivers
    }
}

/// The receiving side of a broadcast channel.
#[derive(Debug)]
pub struct Receiver<T> {
    channel: Arc<Channel<T>>,
    next_index: u64,
    receiver_token: ArenaIndex,
}

impl<T> Receiver<T> {
    pub(crate) fn clear_waiter_registration(&self, waiter: &mut Option<ArenaIndex>) {
        let retired_waker = waiter.take().and_then(|token| {
            let mut inner = self.channel.inner.lock();
            inner.wakers.remove(token)
        });
        drop(retired_waker);
    }

    fn clear_waiter_registration_and_record_cancellation(&self, waiter: &mut Option<ArenaIndex>) {
        let retired_waker = {
            let mut inner = self.channel.inner.lock();
            let retired_waker = waiter.take().and_then(|token| inner.wakers.remove(token));
            inner.record_cancellation();
            retired_waker
        };
        drop(retired_waker);
    }

    /// Builds an opt-in redacted telemetry snapshot.
    #[must_use]
    #[inline]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> BroadcastTelemetrySnapshot {
        self.channel
            .telemetry_snapshot(channel_id, Some(self.next_index))
    }
}

impl<T: Clone> Receiver<T> {
    /// Attempts to receive the next message without blocking.
    ///
    /// # Errors
    ///
    /// - `TryRecvError::Empty`: No message available right now.
    /// - `TryRecvError::Lagged(n)`: The receiver fell behind. The cursor is
    ///   advanced to the earliest available message; the next call may succeed.
    /// - `TryRecvError::Closed`: All senders have been dropped and the buffer
    ///   is drained.
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let mut inner = self.channel.inner.lock();

        // 1. Check for lag
        let earliest = inner.buffer.front().map_or(inner.total_sent, |s| s.index);
        if self.next_index < earliest {
            let missed = earliest - self.next_index;
            self.next_index = earliest;
            inner.update_receiver_cursor(self.receiver_token, self.next_index);
            return Err(TryRecvError::Lagged(missed));
        }

        // 2. Try to get the message at the current cursor position.
        let delta = self.next_index.saturating_sub(earliest);
        if let Ok(offset) = usize::try_from(delta) {
            if let Some(slot) = inner.buffer.get(offset) {
                let msg = Arc::clone(&slot.msg);
                let index = slot.index;
                drop(inner);

                // `T::clone` is arbitrary user code and may block, panic, or
                // re-enter the channel. The retained Arc keeps this exact
                // message alive if a concurrent send evicts its ring slot.
                // A per-message mutex serializes clones for `T: !Sync`
                // without holding the channel-wide mutex.
                let msg = msg.lock().clone();

                let mut inner = self.channel.inner.lock();
                debug_assert_eq!(self.next_index, index);
                self.next_index = index + 1;
                inner.update_receiver_cursor(self.receiver_token, self.next_index);
                return Ok(msg);
            }
        }

        // 3. No message available — closed or empty?
        if self.channel.sender_count.load(Ordering::Acquire) == 0 {
            Err(TryRecvError::Closed)
        } else {
            Err(TryRecvError::Empty)
        }
    }

    /// Receives the next message.
    ///
    /// # Errors
    ///
    /// - `RecvError::Lagged(n)`: The receiver fell behind.
    /// - `RecvError::Closed`: All senders dropped.
    /// - `RecvError::PolledAfterCompletion`: This specific future was already resolved.
    #[inline]
    pub fn recv<'a, Caps>(&'a mut self, cx: &'a Cx<Caps>) -> Recv<'a, T, Caps> {
        Recv {
            receiver: self,
            cx,
            waiter: None,
            completed: false,
        }
    }

    #[inline]
    #[allow(clippy::too_many_lines)]
    pub(crate) fn poll_recv_with_waiter<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        task_cx: &Context<'_>,
        waiter: &mut Option<ArenaIndex>,
    ) -> Poll<Result<T, RecvError>> {
        // br-asupersync-h0id2o: a Waker's clone and destructor vtables are
        // arbitrary external callbacks. Keep both operations outside `inner`,
        // then revalidate the receive state after cloning so a send in the
        // unlocked window cannot be missed. Keeping every transition in this
        // loop makes that revalidation protocol explicit.
        let mut replacement_waker = None;
        loop {
            if cx.checkpoint().is_err() {
                cx.trace("broadcast::recv cancelled");
                self.clear_waiter_registration_and_record_cancellation(waiter);
                drop(replacement_waker);
                return Poll::Ready(Err(RecvError::Cancelled));
            }

            let mut inner = self.channel.inner.lock();

            // 1. Check for lag
            let earliest = inner.buffer.front().map_or(inner.total_sent, |s| s.index);

            if self.next_index < earliest {
                let missed = earliest - self.next_index;
                self.next_index = earliest;
                inner.update_receiver_cursor(self.receiver_token, self.next_index);
                let retired_waker = waiter.take().and_then(|token| inner.wakers.remove(token));
                drop(inner);
                drop(retired_waker);
                drop(replacement_waker);
                return Poll::Ready(Err(RecvError::Lagged(missed)));
            }

            // 2. Try to get message.
            //
            // Use checked conversion to avoid `u64 -> usize` truncation on 32-bit
            // targets. A large `next_index - earliest` delta must not wrap and
            // incorrectly index into the front of the ring buffer.
            let delta = self.next_index.saturating_sub(earliest);
            if let Ok(offset) = usize::try_from(delta) {
                if let Some(slot) = inner.buffer.get(offset) {
                    let msg = Arc::clone(&slot.msg);
                    let index = slot.index;
                    drop(inner);

                    // `T::clone` is arbitrary user code and may block, panic, or
                    // re-enter the channel. The retained Arc keeps this exact
                    // message alive if a concurrent send evicts its ring slot.
                    let msg = msg.lock().clone();

                    let mut inner = self.channel.inner.lock();
                    debug_assert_eq!(self.next_index, index);
                    self.next_index = index + 1;
                    inner.update_receiver_cursor(self.receiver_token, self.next_index);
                    let retired_waker = waiter.take().and_then(|token| inner.wakers.remove(token));
                    drop(inner);
                    drop(retired_waker);
                    drop(replacement_waker);
                    return Poll::Ready(Ok(msg));
                }
            }

            // 3. Check if closed
            if self.channel.sender_count.load(Ordering::Acquire) == 0 {
                let retired_waker = waiter.take().and_then(|token| inner.wakers.remove(token));
                drop(inner);
                drop(retired_waker);
                drop(replacement_waker);
                return Poll::Ready(Err(RecvError::Closed));
            }

            // 4. Wait - register or update waker.
            //
            // The common same-waker repoll performs no clone. A new candidate
            // is cloned only after releasing `inner`; the loop then rechecks
            // lag/value/close before moving the candidate into the arena.
            let current_waker = task_cx.waker();
            match *waiter {
                Some(token) => match inner.wakers.get_mut(token) {
                    Some(stored_waker) if stored_waker.will_wake(current_waker) => {
                        drop(inner);
                        drop(replacement_waker);
                        return Poll::Pending;
                    }
                    Some(stored_waker) => {
                        if let Some(replacement) = replacement_waker.take() {
                            let retired_waker = std::mem::replace(stored_waker, replacement);
                            drop(inner);
                            drop(retired_waker);
                            return Poll::Pending;
                        }
                    }
                    None => {
                        if let Some(replacement) = replacement_waker.take() {
                            let token = inner.wakers.insert(replacement);
                            *waiter = Some(token);
                            drop(inner);
                            return Poll::Pending;
                        }
                    }
                },
                None => {
                    if let Some(replacement) = replacement_waker.take() {
                        let token = inner.wakers.insert(replacement);
                        *waiter = Some(token);
                        drop(inner);
                        return Poll::Pending;
                    }
                }
            }

            drop(inner);
            replacement_waker = Some(current_waker.clone());
        }
    }
}

/// Future returned by [`Receiver::recv`].
pub struct Recv<'a, T, Caps = crate::cx::cap::All> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx<Caps>,
    /// Token for the registered waiter in the arena.
    waiter: Option<ArenaIndex>,
    completed: bool,
}

impl<T, Caps> Recv<'_, T, Caps> {
    fn clear_waiter_registration(&mut self) {
        self.receiver.clear_waiter_registration(&mut self.waiter);
    }
}

impl<T: Clone, Caps> Future for Recv<'_, T, Caps> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if this.completed {
            return Poll::Ready(Err(RecvError::PolledAfterCompletion));
        }

        let poll = this
            .receiver
            .poll_recv_with_waiter(this.cx, ctx, &mut this.waiter);
        if poll.is_ready() {
            this.completed = true;
        }
        poll
    }
}

impl<T, Caps> Drop for Recv<'_, T, Caps> {
    fn drop(&mut self) {
        // If the future is dropped while Pending (e.g. select/race loser),
        // ensure we don't leave stale waiters behind.
        if !self.completed && self.waiter.is_some() {
            self.receiver
                .clear_waiter_registration_and_record_cancellation(&mut self.waiter);
        } else {
            self.clear_waiter_registration();
        }
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        let receiver_token = {
            let mut inner = self.channel.inner.lock();
            let token = inner.receiver_cursors.insert(self.next_index);
            self.channel.receiver_count.fetch_add(1, Ordering::Relaxed);
            token
        };
        Self {
            channel: Arc::clone(&self.channel),
            next_index: self.next_index,
            receiver_token,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let was_last_receiver = self.channel.receiver_count.fetch_sub(1, Ordering::AcqRel) == 1;
        let mut to_drop = None;
        {
            let mut inner = self.channel.inner.lock();
            inner.receiver_cursors.remove(self.receiver_token);
            if was_last_receiver {
                // Re-check under lock in case a sender concurrently called `subscribe`.
                if self.channel.receiver_count.load(Ordering::Acquire) == 0 {
                    to_drop = Some(std::mem::take(&mut inner.buffer));
                }
            }
        }
        drop(to_drop);
    }
}

#[cfg(test)]
#[path = "broadcast_inline_tests.rs"]
mod tests;
