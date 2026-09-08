//! Two-phase MPSC (multi-producer, single-consumer) channel.
//!
//! This channel uses the reserve/commit pattern to ensure cancel-safety:
//!
//! ```text
//! Traditional (NOT cancel-safe):
//!   tx.send(message).await?;  // If cancelled here, message may be lost!
//!
//! Asupersync (cancel-safe):
//!   let permit = tx.reserve(cx).await?;  // Phase 1: reserve slot
//!   permit.send(message)?;               // Phase 2: commit (surfaces disconnection)
//! ```
//!
//! For work that explicitly accepts caller-owned memory growth, [`unbounded_channel`]
//! returns dedicated [`UnboundedSender`] / [`UnboundedReceiver`] handles. The
//! unbounded sender has a synchronous [`UnboundedSender::send`] method because
//! capacity reservation cannot wait; it still shares the same close, wake, and
//! receiver-drain behavior as the bounded channel.
//!
//! # Obligation Tracking
//!
//! Each `SendPermit` represents an obligation that must be resolved:
//! - `permit.send(value)`: Commits the obligation (surfaces disconnection as Outcome)
//! - `permit.abort()`: Aborts the obligation
//! - `drop(permit)`: Equivalent to abort (RAII cleanup)
//!
//! # Why a `parking_lot::Mutex<ChannelInner>` and not a lock-free queue?
//!
//! br-asupersync-p81v6d evaluation (follow-up to vgw2yw): the obvious
//! "swap `VecDeque<T>` for `crossbeam_queue::ArrayQueue<T>` and only
//! lock for waker registration" refactor is **rejected** as the wrong
//! trade-off for this channel's cancel-correctness contract. Recorded
//! here so a future agent does not re-litigate the same proposal.
//!
//! The mutex protects four pieces of state that *must* linearize
//! together for cancel-safety:
//!
//! 1. `queue: VecDeque<T>`              — the message buffer
//! 2. `reserved: usize`                 — outstanding permits
//! 3. `send_wakers` + `waiter_queue` — generational O(1) waker storage
//!    plus FIFO ordering with **mid-queue removal on cancel** (a `Reserve`
//!    future dropped during `.await` removes its own waiter)
//! 4. `recv_waker` — receiver registration
//!
//! The reserve/commit invariants require:
//!
//! * **Atomic capacity test + reserve**: `reserve()` evaluates
//!   `queue.len() + reserved < capacity` *and* increments `reserved`
//!   under one linearization point. A racy snapshot (e.g.,
//!   `ArrayQueue::len()` is **not** linearizable with a separate
//!   atomic `reserved` counter) lets two reservers both observe
//!   `len + reserved < capacity` and both succeed, oversubscribing.
//! * **Atomic commit**: `permit.send(v)` decrements `reserved` and
//!   pushes to `queue` in one linearization point. Splitting the
//!   ops admits a window where a cancelled-but-already-pushed value
//!   has no claimant.
//! * **FIFO waker pool with cancel removal**: `crossbeam`'s
//!   `ArrayQueue` and `SegQueue` do *not* support mid-queue removal,
//!   which the cancel path requires (a dropped `Reserve` future must
//!   delete its specific waiter so a later wake doesn't fire into a
//!   stolen permit). Replicating that with a lock-free intrusive
//!   linked list is tokio-mpsc-class effort (~1 KLOC of CAS-based
//!   code with ABA-free index discipline) and would still need a
//!   mutex around list metadata for safe traversal under cancel.
//!
//! **Net cost of the swap**: ~1 KLOC of new safety-critical code to
//! replicate cancel-correctness (atomic ring buffer + intrusive
//! waker pool) for a contention reduction that is largely already
//! claimed by the wlf0xh work (commit f49630a8e), which made the
//! waiter ops O(1) so the critical section is dominated by the
//! `VecDeque` op itself. The bead's required microbench gate
//! (N >= 8 fan-in throughput vs current) was not run because the
//! design analysis already showed the swap is unsound without
//! parallel-capacity-tracking compromises.
//!
//! **Conclusion**: keep the `Mutex<ChannelInner<T>>` design. It is
//! the project's distinctive cancel-correctness contract; degrading
//! its lock-protected atomicity to chase synthetic-benchmark
//! throughput is a bad trade for the asupersync use-case.

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;
use crate::runtime::reactor::token::{SlabToken, TokenSlab};
use crate::types::outcome::Outcome;

/// Error returned when sending fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError<T> {
    /// The receiver was dropped before the value could be sent.
    Disconnected(T),
    /// The operation was cancelled.
    Cancelled(T),
    /// The channel is full (for try_send).
    Full(T),
}

impl<T> std::fmt::Display for SendError<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected(_) => write!(f, "sending on a closed mpsc channel"),
            Self::Cancelled(_) => write!(f, "send operation cancelled"),
            Self::Full(_) => write!(f, "mpsc channel is full"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

/// A checked send failed before publication, retaining the caller's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            Self::Channel(SendError::Disconnected(())) => {
                CheckedSendError::Channel(SendError::Disconnected(value))
            }
            Self::Channel(SendError::Cancelled(())) => {
                CheckedSendError::Channel(SendError::Cancelled(value))
            }
            Self::Channel(SendError::Full(())) => CheckedSendError::Channel(SendError::Full(value)),
            Self::Admission { error, value: () } => CheckedSendError::Admission { error, value },
        }
    }
}

/// Error returned when receiving fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The sender was dropped without sending a value.
    Disconnected,
    /// The receive operation was cancelled.
    Cancelled,
    /// The channel is empty (for try_recv).
    Empty,
}

impl std::fmt::Display for RecvError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "receiving on a closed mpsc channel"),
            Self::Cancelled => write!(f, "[ASUP-E203] receive operation cancelled"),
            Self::Empty => write!(f, "mpsc channel is empty"),
        }
    }
}

impl std::error::Error for RecvError {}

/// Opt-in, redacted telemetry snapshot for an MPSC channel.
///
/// The caller supplies `channel_id`, which keeps identifiers deterministic and
/// avoids ambient globals or pointer-derived IDs. Payload values are never
/// exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpscTelemetrySnapshot {
    /// Caller-provided deterministic channel identifier.
    pub channel_id: u64,
    /// Stable channel kind label.
    pub channel_kind: &'static str,
    /// Maximum number of queued or reserved slots.
    pub capacity: usize,
    /// Number of committed values waiting for the receiver.
    pub queued_messages: usize,
    /// Number of reserved-but-uncommitted send obligations.
    pub reserved_uncommitted_obligations: usize,
    /// Sender-side waiters waiting for capacity.
    pub send_waiter_count: usize,
    /// Receiver-side waiters waiting for messages or closure.
    pub recv_waiter_count: usize,
    /// Redacted receiver state.
    pub receiver_health: &'static str,
    /// MPSC has no lagging receiver concept.
    pub lagged_receiver_count: Option<usize>,
    /// Cancel/abort events observed by the channel.
    pub cancellation_count: u64,
    /// Whether this channel has reached a closed state.
    pub closed: bool,
}

/// Arc-owned executor waker registration used inside the channel mutex.
#[derive(Debug)]
struct RegisteredWaker {
    waker: Waker,
}

impl RegisteredWaker {
    /// Clones an executor-provided waker into an Arc-owned registration.
    ///
    /// Callers must invoke this without holding `ChannelShared::inner`: a
    /// custom `RawWaker` clone callback may execute arbitrary code.
    #[inline]
    fn new(waker: &Waker) -> Arc<Self> {
        Arc::new(Self {
            waker: waker.clone(),
        })
    }

    #[inline]
    fn will_wake(&self, waker: &Waker) -> bool {
        self.waker.will_wake(waker)
    }

    /// Delegates a wake while retaining the registration owner.
    #[inline]
    fn wake_by_ref(&self) {
        self.waker.wake_by_ref();
    }
}

/// Receiver registration prepared outside the channel mutex, paired with the
/// out-of-band wake epoch observed immediately before that unlocked window.
struct PreparedReceiverWaker {
    registration: Arc<RegisteredWaker>,
    wake_epoch: u64,
}

/// Internal channel state shared between senders and receivers.
#[derive(Debug)]
struct ChannelInner<T> {
    /// Buffered messages waiting to be received.
    queue: VecDeque<T>,
    /// Number of reserved slots (permits outstanding).
    reserved: usize,
    /// Arc-owned wakers for senders waiting for capacity (O(1) access by token).
    send_wakers: TokenSlab<Arc<RegisteredWaker>>,
    /// FIFO queue of waiter tokens to maintain fair ordering.
    waiter_queue: VecDeque<SlabToken>,
    /// Arc-owned waker for the receiver waiting for messages.
    recv_waker: Option<Arc<RegisteredWaker>>,
    /// Out-of-band receiver wake generation.
    ///
    /// `wake_receiver()` has no persistent queue/close state for a receiver
    /// poll to observe after temporarily releasing the mutex to clone a new
    /// executor waker. Advancing this epoch lets that poll replay an edge that
    /// arrived during its unlocked preparation window.
    recv_wake_epoch: u64,
    /// Number of cancellation/abort events observed by this channel.
    cancellation_count: u64,
}

/// Shared state wrapper.
struct ChannelShared<T> {
    /// Protected channel state.
    inner: Mutex<ChannelInner<T>>,
    /// Number of active senders. Atomic so `Sender::clone` avoids the mutex
    /// and `Receiver::is_closed` can read without locking.
    sender_count: AtomicUsize,
    /// Whether the receiver has been dropped. Atomic so `Sender::is_closed`
    /// can read without locking. Monotone: transitions `false → true` once.
    receiver_dropped: AtomicBool,
    /// Maximum capacity of the queue. Write-once (set at construction),
    /// stored outside the mutex so `capacity()` is lock-free.
    capacity: usize,
}

impl<T: std::fmt::Debug> std::fmt::Debug for ChannelShared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelShared")
            .field("inner", &self.inner)
            .field("sender_count", &self.sender_count.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl<T> ChannelInner<T> {
    #[inline]
    fn new(capacity: usize) -> Self {
        let queue = if capacity == usize::MAX {
            VecDeque::new()
        } else {
            VecDeque::with_capacity(capacity)
        };

        Self {
            queue,
            reserved: 0,
            send_wakers: TokenSlab::with_capacity(4),
            waiter_queue: VecDeque::with_capacity(4),
            recv_waker: None,
            recv_wake_epoch: 0,
            cancellation_count: 0,
        }
    }

    /// Returns the number of used slots (queued + reserved).
    #[inline]
    fn used_slots(&self) -> usize {
        self.queue.len().saturating_add(self.reserved)
    }

    /// Returns true if there's capacity for another reservation.
    #[inline]
    fn has_capacity(&self, capacity: usize) -> bool {
        self.used_slots() < capacity
    }

    /// Drops stale FIFO tokens whose slab entry has already been removed.
    #[inline]
    fn prune_stale_waiter_front(&mut self) {
        while let Some(&token) = self.waiter_queue.front() {
            if self.send_wakers.get(token).is_some() {
                break;
            }
            self.waiter_queue.pop_front();
        }
    }

    /// Returns true when at least one live sender is queued.
    #[inline]
    fn has_waiting_sender(&mut self) -> bool {
        self.prune_stale_waiter_front();
        !self.waiter_queue.is_empty()
    }

    /// Returns the waker for the next waiting sender, if any.
    /// The caller must invoke the registered waker **after** releasing the channel
    /// lock to avoid wake-under-lock deadlocks.
    ///
    /// This does NOT remove the waiter from the queue. The waiter is responsible
    /// for removing itself upon successfully acquiring a permit.
    #[inline]
    fn take_next_sender_waker(&mut self) -> Option<Arc<RegisteredWaker>> {
        self.prune_stale_waiter_front();
        // `send_wakers` stores Arc-owned registrations, so this clone cannot
        // invoke an executor-provided RawWaker callback while the channel is
        // locked. The underlying waker is only invoked after lock release.
        self.waiter_queue
            .front()
            .and_then(|&token| self.send_wakers.get(token))
            .cloned()
    }

    /// Returns distinct live sender wakers for slots that are currently free.
    ///
    /// The waiters stay queued until their `Reserve` futures actually poll and
    /// acquire capacity; this only broadcasts the newly available capacity.
    #[inline]
    fn sender_wakers_for_freed_slots(
        &mut self,
        freed_slots: usize,
        capacity: usize,
    ) -> SmallVec<[Arc<RegisteredWaker>; 4]> {
        let wake_budget = freed_slots.min(capacity.saturating_sub(self.used_slots()));
        if wake_budget == 0 {
            return SmallVec::new();
        }

        self.prune_stale_waiter_front();
        let mut wakers = SmallVec::new();
        for &token in &self.waiter_queue {
            if wakers.len() == wake_budget {
                break;
            }
            if let Some(waker) = self.send_wakers.get(token) {
                wakers.push(Arc::clone(waker));
            }
        }
        wakers
    }

    /// Drains all sender registrations without running a Waker destructor.
    ///
    /// Capacity is reserved before the first state mutation. If allocation
    /// panics, every registration therefore remains owned by the slab; after
    /// reservation, moving the exact waiter count into this vector is
    /// allocation-free. Callers must drop or wake the returned owners only
    /// after releasing the channel mutex.
    fn drain_sender_wakers(&mut self) -> SmallVec<[Arc<RegisteredWaker>; 4]> {
        let mut wakers = SmallVec::with_capacity(self.waiter_queue.len());
        while let Some(token) = self.waiter_queue.pop_front() {
            if let Some(waker) = self.send_wakers.remove(token) {
                wakers.push(waker);
            }
        }
        wakers
    }

    /// Records a cancellation or abort event without exposing payloads.
    #[inline]
    fn record_cancellation(&mut self) {
        self.cancellation_count = self.cancellation_count.saturating_add(1);
    }

    /// Removes the first occurrence of `token` from the waiter queue.
    #[inline]
    fn remove_waiter_token(&mut self, token: crate::runtime::reactor::token::SlabToken) -> bool {
        if self.waiter_queue.front().copied() == Some(token) {
            self.waiter_queue.pop_front();
            return true;
        }

        if self.waiter_queue.back().copied() == Some(token) {
            self.waiter_queue.pop_back();
            return true;
        }

        let mut found = false;
        self.waiter_queue.retain(|&t| {
            if !found && t == token {
                found = true;
                false // Remove this element
            } else {
                true // Keep this element
            }
        });
        found
    }
}

/// Test/benchmark fixture for isolating MPSC waiter-queue cancellation cost.
#[cfg(any(test, feature = "test-internals"))]
#[doc(hidden)]
pub struct MpscWaiterCancelFixture {
    inner: ChannelInner<()>,
    token: SlabToken,
}

#[cfg(any(test, feature = "test-internals"))]
impl MpscWaiterCancelFixture {
    /// Builds a queue where the cancellation target is the oldest waiter.
    #[must_use]
    pub fn oldest(waiter_count: usize) -> Self {
        let waiter_count = waiter_count.max(1);
        let mut inner = ChannelInner::new(usize::MAX);
        let waker = Arc::new(RegisteredWaker {
            waker: Waker::noop().clone(),
        });
        let mut target = None;

        for index in 0..waiter_count {
            let token = inner.send_wakers.insert(Arc::clone(&waker));
            if index == 0 {
                target = Some(token);
            }
            inner.waiter_queue.push_back(token);
        }

        Self {
            inner,
            token: target.expect("oldest waiter fixture always inserts a target"),
        }
    }

    /// Removes the target waiter and consumes the fixture.
    pub fn remove_target(mut self) -> bool {
        self.inner.remove_waiter_token(self.token)
    }
}

impl<T> ChannelShared<T> {
    /// Builds an opt-in redacted telemetry snapshot.
    #[inline]
    fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        let mut inner = self.inner.lock();
        let sender_count = self.sender_count.load(Ordering::Acquire);
        let receiver_dropped = self.receiver_dropped.load(Ordering::Acquire);
        let queued_messages = inner.queue.len();
        let recv_waiter_count = usize::from(inner.recv_waker.is_some());
        let send_waiter_count = {
            inner.prune_stale_waiter_front();
            inner.waiter_queue.len()
        };
        let closed = receiver_dropped || sender_count == 0;

        let receiver_health = if receiver_dropped {
            "receiver_dropped"
        } else if queued_messages > 0 {
            "value_ready"
        } else if sender_count == 0 {
            "sender_closed"
        } else if recv_waiter_count > 0 {
            "waiting"
        } else {
            "open"
        };

        MpscTelemetrySnapshot {
            channel_id,
            channel_kind: "mpsc",
            capacity: self.capacity,
            queued_messages,
            reserved_uncommitted_obligations: inner.reserved,
            send_waiter_count,
            recv_waiter_count,
            receiver_health,
            lagged_receiver_count: None,
            cancellation_count: inner.cancellation_count,
            closed,
        }
    }
}

/// Creates a bounded MPSC channel with the given capacity.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[inline]
#[must_use]
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "channel capacity must be non-zero");

    let shared = Arc::new(ChannelShared {
        inner: Mutex::new(ChannelInner::new(capacity)),
        sender_count: AtomicUsize::new(1),
        receiver_dropped: AtomicBool::new(false),
        capacity,
    });
    let sender = Sender {
        shared: Arc::clone(&shared),
    };
    let receiver = Receiver { shared };

    (sender, receiver)
}

/// Creates an unbounded MPSC channel.
///
/// This channel never applies sender-side capacity backpressure. Prefer
/// [`channel`] by default; use this constructor only when the caller owns a
/// separate memory-pressure policy.
///
/// # Example
///
/// ```
/// use asupersync::channel::mpsc;
///
/// let (tx, mut rx) = mpsc::unbounded_channel();
/// assert!(tx.send("ready").is_ok());
/// assert_eq!(rx.try_recv().ok(), Some("ready"));
/// ```
#[inline]
#[must_use]
pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (sender, receiver) = channel(usize::MAX);
    (
        UnboundedSender { inner: sender },
        UnboundedReceiver { inner: receiver },
    )
}

/// Alias for [`unbounded_channel`].
///
/// # Example
///
/// ```
/// use asupersync::channel::mpsc;
///
/// let (tx, mut rx) = mpsc::unbounded();
/// assert!(tx.send(7).is_ok());
/// assert_eq!(rx.try_recv().ok(), Some(7));
/// ```
#[inline]
#[must_use]
pub fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    unbounded_channel()
}

/// The sending side of an MPSC channel.
#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<ChannelShared<T>>,
}

impl<T> Sender<T> {
    /// Reserves a slot in the channel for sending.
    #[inline]
    #[must_use]
    pub fn reserve<'a>(&'a self, cx: &'a Cx) -> Reserve<'a, T> {
        Reserve {
            sender: self,
            cx,
            waiter_token: None,
            completed: false,
        }
    }

    /// Reserves channel capacity and synchronously admits its runtime obligation.
    ///
    /// Unlike [`Self::reserve`], this reports closed-region, retired-holder and
    /// quota refusals before returning a permit. A deliberately stateless `Cx`
    /// remains untracked. Waiting preserves the same FIFO and cancellation rules.
    #[must_use]
    pub fn reserve_checked<'a>(&'a self, cx: &'a Cx) -> CheckedReserve<'a, T> {
        CheckedReserve {
            inner: self.reserve(cx),
        }
    }

    /// Sends after checked obligation admission, retaining the value on refusal.
    pub async fn send_checked(&self, cx: &Cx, value: T) -> Result<(), CheckedSendError<T>> {
        match self.reserve_checked(cx).await {
            Ok(permit) => permit.try_send(value).map_err(CheckedSendError::Channel),
            Err(error) => Err(error.with_value(value)),
        }
    }

    /// Attempts checked reservation without waiting or bypassing queued senders.
    pub fn try_reserve_checked(&self, cx: &Cx) -> Result<SendPermit<'_, T>, CheckedSendError<()>> {
        if cx.checkpoint().is_err() {
            return Err(CheckedSendError::Channel(SendError::Cancelled(())));
        }
        // The physical permit owns rollback before the gateway may notify user
        // code. Admission runs outside the channel mutex.
        let mut permit = self.try_reserve().map_err(CheckedSendError::Channel)?;
        permit.obligation = cx
            .try_register_obligation_checked(
                crate::record::ObligationKind::SendPermit,
                cx.task_id(),
            )
            .map_err(|error| CheckedSendError::Admission { error, value: () })?;
        Ok(permit)
    }

    /// Attempts a checked send without waiting, returning an unpublished value.
    pub fn try_send_checked(&self, cx: &Cx, value: T) -> Result<(), CheckedSendError<T>> {
        match self.try_reserve_checked(cx) {
            Ok(permit) => permit.try_send(value).map_err(CheckedSendError::Channel),
            Err(error) => Err(error.with_value(value)),
        }
    }

    /// Convenience method: reserve and send in one step.
    #[inline]
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        let result = self.reserve(cx).await;
        match result {
            Ok(permit) => permit.try_send(value),
            Err(SendError::<()>::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::<()>::Full(())) => Err(SendError::Full(value)),
            Err(SendError::<()>::Cancelled(())) => Err(SendError::Cancelled(value)),
        }
    }

    /// Attempts to reserve a slot without blocking.
    ///
    /// Returns `Full` when waiting senders exist, to preserve FIFO ordering.
    #[inline]
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        let mut inner = self.shared.inner.lock();

        if self.shared.receiver_dropped.load(Ordering::Relaxed) {
            return Err(SendError::<()>::Disconnected(()));
        }

        if inner.has_waiting_sender() {
            return Err(SendError::<()>::Full(()));
        }

        if inner.has_capacity(self.shared.capacity) {
            inner.reserved += 1;
            drop(inner);
            Ok(SendPermit {
                sender: self,
                sent: false,
                obligation: None,
            })
        } else {
            Err(SendError::<()>::Full(()))
        }
    }

    /// Attempts to send a value without blocking.
    ///
    /// Single-lock fast path (br-asupersync-lej99f). The previous shape went
    /// through `try_reserve()` + `permit.try_send(value)`, which took the
    /// channel mutex twice (once to bump `reserved`, once to push the value
    /// and decrement `reserved`). On the uncontended path this is wasted
    /// work — there is no observable state in which a `SendPermit` exists
    /// between the two locks for an immediate-commit caller.
    ///
    /// Here we lock once, commit-or-fail, and never touch the `reserved`
    /// counter at all.
    ///
    /// Strict sender FIFO semantics. Returns `Full` while live reserve waiters
    /// exist, even if a receiver has just freed physical capacity. That freed
    /// slot belongs to the head queued reserver until it polls and either
    /// claims or cancels its reservation; a later `try_send` must not steal it.
    #[inline]
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        let recv_waker = {
            let mut inner = self.shared.inner.lock();

            if self.shared.receiver_dropped.load(Ordering::Relaxed) {
                return Err(SendError::Disconnected(value));
            }

            if inner.has_waiting_sender() || !inner.has_capacity(self.shared.capacity) {
                return Err(SendError::Full(value));
            }

            inner.queue.push_back(value);
            // Extract the recv waker before dropping the lock so we can
            // wake outside the critical section.
            inner.recv_waker.take()
        };
        if let Some(waker) = recv_waker {
            waker.wake_by_ref();
        }
        Ok(())
    }

    /// Returns true if the receiver has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.receiver_dropped.load(Ordering::Acquire)
    }

    /// Wakes the receiver if it is currently waiting in `recv()`.
    ///
    /// This does not enqueue a message. It's intended for out-of-band protocols
    /// (like cancellation) that need to interrupt a blocked receiver.
    #[inline]
    pub fn wake_receiver(&self) {
        let mut inner = self.shared.inner.lock();
        inner.recv_wake_epoch = inner.recv_wake_epoch.wrapping_add(1);
        let waker = inner.recv_waker.take();
        drop(inner);
        if let Some(waker) = waker {
            waker.wake_by_ref();
        }
    }

    /// Seals the receiver side of the channel from the sender side.
    ///
    /// Existing queued messages remain available to the receiver, but no new
    /// reservations or sends will succeed. Pending senders and receivers are
    /// woken so shutdown protocols cannot stall behind a full mailbox.
    pub(crate) fn close_receiver(&self) {
        let (send_wakers, recv_waker) = {
            let mut inner = self.shared.inner.lock();
            if self.shared.receiver_dropped.load(Ordering::Relaxed) {
                return;
            }
            let send_wakers = inner.drain_sender_wakers();
            self.shared.receiver_dropped.store(true, Ordering::Release);
            let recv_waker = inner.recv_waker.take();
            drop(inner);
            (send_wakers, recv_waker)
        };

        for waker in send_wakers {
            waker.wake_by_ref();
        }
        if let Some(waker) = recv_waker {
            waker.wake_by_ref();
        }
    }

    /// Returns the channel's capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Returns an opt-in redacted telemetry snapshot for this MPSC sender.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        self.shared.telemetry_snapshot(channel_id)
    }

    #[cfg(test)]
    pub(crate) fn debug_counts(&self) -> (usize, usize) {
        let inner = self.shared.inner.lock();
        (inner.queue.len(), inner.reserved)
    }

    /// Sends a value, evicting the oldest queued message if the channel is full.
    ///
    /// Returns `Ok(None)` if the value was sent without eviction,
    /// `Ok(Some(evicted))` if the oldest message was evicted to make room,
    /// `Err(SendError::Full(value))` if all capacity is consumed by reserved
    /// slots, or if a queued waiter already owns the next free slot and there
    /// is nothing evictable to displace, or
    /// `Err(SendError::Disconnected(value))` if the receiver has dropped.
    ///
    /// This is used by the `DropOldest` backpressure policy. The evicted
    /// message is returned so callers can trace or log the drop.
    #[inline]
    pub fn send_evict_oldest(&self, value: T) -> Result<Option<T>, SendError<T>> {
        self.send_evict_oldest_where(value, |_| true)
    }

    /// Sends a value, evicting the oldest queued message that matches `predicate`
    /// if the channel is full.
    ///
    /// Returns `Ok(None)` if the value was sent without eviction,
    /// `Ok(Some(evicted))` if a matching queued message was evicted to make room,
    /// `Err(SendError::Full(value))` if the channel is physically full, or
    /// logically full because a queued waiter owns the next free slot, and no
    /// matching queued message is evictable, or `Err(SendError::Disconnected(value))`
    /// if the receiver has dropped.
    pub fn send_evict_oldest_where<F>(
        &self,
        value: T,
        mut predicate: F,
    ) -> Result<Option<T>, SendError<T>>
    where
        F: FnMut(&T) -> bool,
    {
        let mut inner = self.shared.inner.lock();

        if self.shared.receiver_dropped.load(Ordering::Relaxed) {
            return Err(SendError::Disconnected(value));
        }

        let has_physical_capacity = inner.has_capacity(self.shared.capacity);
        let waiter_owns_available_slot = has_physical_capacity && inner.has_waiting_sender();

        let evicted = if waiter_owns_available_slot {
            return Err(SendError::Full(value));
        } else if has_physical_capacity {
            None
        } else if let Some(index) = inner.queue.iter().position(&mut predicate) {
            // Evict the oldest committed message (not a reserved slot) that the
            // caller explicitly allows us to drop.
            Some(
                inner
                    .queue
                    .remove(index)
                    .expect("position() returned a valid queue index"),
            )
        } else {
            // Either all capacity is consumed by reserved slots (and waiters), or
            // every queued value is protected by the caller's predicate.
            return Err(SendError::Full(value));
        };

        inner.queue.push_back(value);

        let waker = inner.recv_waker.take();
        drop(inner);

        // Wake receiver if waiting. Drop the lock first to avoid contention/deadlocks.
        if let Some(waker) = waker {
            waker.wake_by_ref();
        }

        Ok(evicted)
    }

    /// Returns a weak reference to this sender.
    #[inline]
    #[must_use]
    pub fn downgrade(&self) -> WeakSender<T> {
        WeakSender {
            shared: Arc::downgrade(&self.shared),
        }
    }
}

/// Future returned by [`Sender::reserve`].
///
/// Polling the same future again after it returns [`Poll::Ready`] panics.
pub struct Reserve<'a, T> {
    sender: &'a Sender<T>,
    cx: &'a Cx,
    waiter_token: Option<SlabToken>,
    completed: bool,
}

impl<T> Reserve<'_, T> {
    fn cleanup_waiter(&mut self) {
        if let Some(token) = self.waiter_token.take() {
            let (next_waker, retired_waker) = {
                let mut inner = self.sender.shared.inner.lock();

                if self.sender.shared.receiver_dropped.load(Ordering::Relaxed) {
                    (None, inner.send_wakers.remove(token))
                } else {
                    let retired_waker = inner.send_wakers.remove(token);
                    if retired_waker.is_none() {
                        // Stale waiter: the token is no longer registered, so this
                        // future does not own a queue position to release. Waking the
                        // next waiter here fabricates a capacity handoff and can
                        // spuriously notify later senders.
                        (None, None)
                    } else {
                        // We were still registered in the slab. Only pass the baton
                        // if we also owned a FIFO position; a slab-only stale token
                        // must not fabricate a capacity handoff.
                        let removed_from_queue = inner.remove_waiter_token(token);
                        let next_waker = if removed_from_queue
                            && inner.has_capacity(self.sender.shared.capacity)
                        {
                            inner.take_next_sender_waker()
                        } else {
                            None
                        };
                        (next_waker, retired_waker)
                    }
                }
            };
            // A final Arc release can destroy the executor-provided Waker.
            // Retire it only after releasing the non-reentrant channel mutex.
            drop(retired_waker);
            if let Some(w) = next_waker {
                w.wake_by_ref();
            }
        }
    }
}

impl<'a, T> Reserve<'a, T> {
    fn poll_with_registration<E>(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        register: impl FnOnce(
            &Cx,
        )
            -> Result<Option<crate::runtime::obligation_mailbox::ObligationToken>, E>,
    ) -> Poll<Result<SendPermit<'a, T>, E>>
    where
        E: From<SendError<()>>,
    {
        assert!(
            !self.completed,
            "mpsc reserve future polled after completion"
        );
        let mut prepared_waker = None;

        loop {
            // Recheck cancellation after preparing a replacement waker: its
            // arbitrary clone callback ran without the channel lock and may
            // have changed cancellation or channel state.
            if self.cx.checkpoint().is_err() {
                self.completed = true;
                self.cx.trace("mpsc::reserve cancelled");
                self.sender.shared.inner.lock().record_cancellation();
                self.cleanup_waiter();
                drop(prepared_waker);
                return Poll::Ready(Err(SendError::<()>::Cancelled(()).into()));
            }

            let mut inner = self.sender.shared.inner.lock();

            if self.sender.shared.receiver_dropped.load(Ordering::Relaxed) {
                // Receiver close/drop already drained the waiter slab and FIFO.
                drop(inner);
                self.waiter_token = None;
                self.completed = true;
                drop(prepared_waker);
                return Poll::Ready(Err(SendError::<()>::Disconnected(()).into()));
            }

            let is_first = self.waiter_token.map_or_else(
                || inner.waiter_queue.is_empty(),
                |token| inner.waiter_queue.front().copied() == Some(token),
            );

            if is_first && inner.has_capacity(self.sender.shared.capacity) {
                inner.reserved += 1;
                let mut retired_waker = None;
                let mut cascade_waker = None;

                if let Some(token) = self.waiter_token {
                    if inner.waiter_queue.front().copied() == Some(token) {
                        inner.waiter_queue.pop_front();
                    } else {
                        inner.remove_waiter_token(token);
                    }

                    retired_waker = inner.send_wakers.remove(token);
                    if inner.has_capacity(self.sender.shared.capacity) {
                        cascade_waker = inner.take_next_sender_waker();
                    }
                }

                drop(inner);
                // Update future state before any user-owned Waker destructor or
                // wake callback can reenter the channel.
                self.waiter_token = None;
                self.completed = true;
                // Own physical rollback before retiring or invoking arbitrary
                // wakers and before the admission gateway can notify a runtime.
                let mut permit = SendPermit {
                    sender: self.sender,
                    sent: false,
                    obligation: None,
                };
                permit.obligation = match register(self.cx) {
                    Ok(obligation) => obligation,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                drop(retired_waker);
                drop(prepared_waker);
                if let Some(waker) = cascade_waker {
                    waker.wake_by_ref();
                }

                return Poll::Ready(Ok(permit));
            }

            let current_waker = self
                .waiter_token
                .and_then(|token| inner.send_wakers.get(token));
            if current_waker.is_some_and(|waker| waker.will_wake(ctx.waker())) {
                drop(inner);
                drop(prepared_waker);
                return Poll::Pending;
            }

            let Some(new_waker) = prepared_waker.as_ref() else {
                // Keep an existing registration installed while the arbitrary
                // RawWaker clone callback runs. The next loop iteration fully
                // rechecks capacity, close, cancellation, FIFO, and identity.
                drop(inner);
                prepared_waker = Some(RegisteredWaker::new(ctx.waker()));
                continue;
            };

            let (retired_waker, inserted_token) = if let Some(token) = self.waiter_token {
                let retired_waker = inner
                    .send_wakers
                    .get_mut(token)
                    .map(|slot| std::mem::replace(slot, Arc::clone(new_waker)));
                (retired_waker, None)
            } else {
                // Keep `new_waker` alive outside the mutex so an allocation
                // panic cannot final-drop its executor Waker under the guard.
                let token = inner.send_wakers.insert(Arc::clone(new_waker));
                inner.waiter_queue.push_back(token);
                (None, Some(token))
            };

            drop(inner);
            if let Some(token) = inserted_token {
                self.waiter_token = Some(token);
            }
            let new_waker = prepared_waker
                .take()
                .expect("prepared sender waker remains owned until after unlock");
            drop(retired_waker);
            drop(new_waker);
            return Poll::Pending;
        }
    }
}

impl<'a, T> Future for Reserve<'a, T> {
    type Output = Result<SendPermit<'a, T>, SendError<()>>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_with_registration(ctx, |cx| {
            Ok(cx.try_register_obligation(crate::record::ObligationKind::SendPermit, cx.task_id()))
        })
    }
}

/// Future returned by [`Sender::reserve_checked`].
///
/// Capacity and runtime quota are both owned before success is returned.
/// Polling after a terminal result panics, as it does for [`Reserve`].
pub struct CheckedReserve<'a, T> {
    inner: Reserve<'a, T>,
}

impl<'a, T> Future for CheckedReserve<'a, T> {
    type Output = Result<SendPermit<'a, T>, CheckedSendError<()>>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll_with_registration(ctx, |cx| {
            cx.try_register_obligation_checked(
                crate::record::ObligationKind::SendPermit,
                cx.task_id(),
            )
            .map_err(|error| CheckedSendError::Admission { error, value: () })
        })
    }
}

impl<T> Drop for Reserve<'_, T> {
    fn drop(&mut self) {
        self.cleanup_waiter();
    }
}

impl<T> Clone for Sender<T> {
    #[inline]
    fn clone(&self) -> Self {
        self.shared.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let old = self.shared.sender_count.fetch_sub(1, Ordering::Release);
        debug_assert!(old > 0, "sender_count underflow in Sender::drop");
        if old == 1 {
            // Last sender dropped — always wake the receiver regardless of races.
            // Even if a WeakSender::upgrade increments the count back up after our
            // decrement, the receiver should still be woken for the transition to zero.
            let recv_waker = {
                let mut inner = self.shared.inner.lock();
                inner.recv_waker.take()
            };
            if let Some(waker) = recv_waker {
                waker.wake_by_ref();
            }
        }
    }
}

/// A weak reference to a sender.
pub struct WeakSender<T> {
    shared: Weak<ChannelShared<T>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for WeakSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakSender").finish_non_exhaustive()
    }
}

impl<T> WeakSender<T> {
    /// Attempts to upgrade this weak sender to a strong sender.
    ///
    /// Returns `None` if all senders have been dropped.
    #[inline]
    #[must_use]
    pub fn upgrade(&self) -> Option<Sender<T>> {
        self.shared.upgrade().and_then(|shared| {
            // CAS loop avoids touching the channel mutex on upgrade while still
            // preventing resurrection from zero senders.
            //
            // `sender_count` is a liveness counter only; channel data/wakers are
            // synchronized by `inner` mutexes. We only need atomicity here to
            // prevent zero->nonzero resurrection, not cross-thread data visibility.
            let mut observed = shared.sender_count.load(Ordering::Relaxed);
            loop {
                if observed == 0 {
                    return None;
                }
                match shared.sender_count.compare_exchange_weak(
                    observed,
                    observed + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(Sender { shared }),
                    Err(actual) => observed = actual,
                }
            }
        })
    }
}

impl<T> Clone for WeakSender<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// The sending side of an unbounded MPSC channel.
#[derive(Debug)]
pub struct UnboundedSender<T> {
    inner: Sender<T>,
}

impl<T> UnboundedSender<T> {
    /// Reserves a slot for an explicit two-phase unbounded send.
    #[inline]
    #[must_use]
    pub fn reserve<'a>(&'a self, cx: &'a Cx) -> Reserve<'a, T> {
        self.inner.reserve(cx)
    }

    /// Reserves with authoritative runtime obligation admission.
    #[must_use]
    pub fn reserve_checked<'a>(&'a self, cx: &'a Cx) -> CheckedReserve<'a, T> {
        self.inner.reserve_checked(cx)
    }

    /// Attempts a checked reservation using the supplied capability context.
    pub fn try_reserve_checked(&self, cx: &Cx) -> Result<SendPermit<'_, T>, CheckedSendError<()>> {
        self.inner.try_reserve_checked(cx)
    }

    /// Sends after checked admission, retaining the value on refusal.
    pub fn send_checked(&self, cx: &Cx, value: T) -> Result<(), CheckedSendError<T>> {
        self.inner.try_send_checked(cx, value)
    }

    /// Attempts to reserve a slot without blocking.
    #[inline]
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        self.inner.try_reserve()
    }

    /// Sends a value into the channel without waiting for capacity.
    ///
    /// Returns [`SendError::Disconnected`] with the original value if the
    /// receiver has been dropped.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::channel::mpsc;
    ///
    /// let (tx, mut rx) = mpsc::unbounded_channel();
    /// tx.send("message").expect("receiver is live");
    /// assert_eq!(rx.try_recv().ok(), Some("message"));
    /// ```
    #[inline]
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        match self.try_reserve() {
            Ok(permit) => permit.try_send(value),
            Err(SendError::<()>::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::<()>::Full(())) => Err(SendError::Full(value)),
            Err(SendError::<()>::Cancelled(())) => Err(SendError::Cancelled(value)),
        }
    }

    /// Returns true if the receiver has been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Returns the unbounded capacity sentinel.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns an opt-in redacted telemetry snapshot for this sender.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        self.inner.telemetry_snapshot(channel_id)
    }

    /// Returns a weak reference to this sender.
    #[inline]
    #[must_use]
    pub fn downgrade(&self) -> WeakUnboundedSender<T> {
        WeakUnboundedSender {
            inner: self.inner.downgrade(),
        }
    }
}

impl<T> Clone for UnboundedSender<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A weak reference to an unbounded sender.
#[derive(Debug)]
pub struct WeakUnboundedSender<T> {
    inner: WeakSender<T>,
}

impl<T> WeakUnboundedSender<T> {
    /// Attempts to upgrade this weak sender to a strong sender.
    #[inline]
    #[must_use]
    pub fn upgrade(&self) -> Option<UnboundedSender<T>> {
        self.inner.upgrade().map(|inner| UnboundedSender { inner })
    }
}

impl<T> Clone for WeakUnboundedSender<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Detached receiver notification returned by an internal permit commit.
///
/// Invoke `wake` after releasing every external lock. It dispatches both the
/// runtime's obligation notification and the receiver's wake; neither callback
/// may run inside an adapter's commit lock.
#[derive(Debug)]
#[must_use = "deferred receiver wake must be consumed after releasing external locks"]
pub(crate) struct DeferredReceiverWake {
    receiver: Option<Arc<RegisteredWaker>>,
    obligation: Option<Arc<crate::runtime::obligation_mailbox::ObligationGateway>>,
}

impl DeferredReceiverWake {
    /// Invokes detached notifications after all adapter locks are released.
    #[inline]
    pub(crate) fn wake(mut self) {
        let _wake = ReleasedCapacityWake(self.receiver.take());
        if let Some(gateway) = self.obligation.take() {
            gateway.notify();
        }
    }
}

/// A permit to send a single value.
#[derive(Debug)]
#[must_use = "SendPermit must be consumed via send() or abort()"]
pub struct SendPermit<'a, T> {
    sender: &'a Sender<T>,
    sent: bool,
    /// Runtime-tracked obligation for this reservation
    /// (br-asupersync-bi2462.14).
    ///
    /// Minted through the reserving `Cx`'s obligation mailbox, committed on
    /// send, aborted on `abort()` or an unsent drop. `None` when the permit
    /// was reserved without a runtime context (`try_reserve`, or a
    /// hand-built `Cx`).
    obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
}

/// Resolve a permit's runtime obligation: committed when the value was
/// delivered, aborted as an error when the channel refused it.
#[inline]
fn resolve_send_obligation(
    token: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    delivered: bool,
) -> Option<Arc<crate::runtime::obligation_mailbox::ObligationGateway>> {
    token.and_then(|token| {
        if delivered {
            token.commit_deferred().1
        } else {
            token
                .abort_deferred(crate::record::ObligationAbortReason::Error)
                .1
        }
    })
}

/// Deliver a released slot's notification even when obligation settlement
/// unwinds. Neither callback nor final waker destruction runs under a lock.
struct ReleasedCapacityWake(Option<Arc<RegisteredWaker>>);

impl Drop for ReleasedCapacityWake {
    fn drop(&mut self) {
        let Some(waker) = self.0.take() else {
            return;
        };
        let already_unwinding = std::thread::panicking();
        let notified =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake_by_ref()));
        let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)));
        let failure = match (notified, retired) {
            (Err(primary), Err(secondary)) => {
                // An arbitrary secondary panic payload may itself panic on
                // drop. Preserve the first failure without a double unwind.
                std::mem::forget(secondary);
                Some(primary)
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Some(error),
            (Ok(()), Ok(())) => None,
        };
        if let Some(payload) = failure {
            if already_unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

impl<T> SendPermit<'_, T> {
    /// Commits the reserved slot, enqueuing the value.
    ///
    /// Returns an Outcome indicating success or failure. When the receiver has been
    /// dropped, returns Err(SendError::Disconnected(value)) to surface the disconnection
    /// rather than silently dropping the value.
    #[inline]
    pub fn send(self, value: T) -> Outcome<(), SendError<T>> {
        match self.try_send(value) {
            Ok(()) => Outcome::Ok(()),
            Err(error) => Outcome::Err(error),
        }
    }

    /// Commits the reserved slot, returning an error if the receiver was dropped.
    #[inline]
    pub fn try_send(self, value: T) -> Result<(), SendError<T>> {
        let (result, recv_waker) = self.try_send_deferred_wake(value);
        recv_waker.wake();
        result
    }

    /// Commits the reserved slot while returning any detached receiver waker.
    ///
    /// This crate-private split lets an adapter commit under its own state lock,
    /// release that lock, and only then invoke the arbitrary receiver callback.
    /// Invoke `wake` on the returned token after releasing all external locks
    /// to notify both the obligation drainer and the receiver. Quota settlement
    /// and queue publication are already synchronous when this method returns.
    #[inline]
    pub(crate) fn try_send_deferred_wake(
        mut self,
        value: T,
    ) -> (Result<(), SendError<T>>, DeferredReceiverWake) {
        self.sent = true;
        let obligation = self.obligation.take();
        let mut inner = self.sender.shared.inner.lock();

        if inner.reserved == 0 {
            debug_assert!(false, "send permit without reservation");
        } else {
            inner.reserved -= 1;
        }

        if self.sender.shared.receiver_dropped.load(Ordering::Relaxed) {
            // Receiver is gone; drop the value and release capacity.
            // Note: Receiver::drop already drained and woke any pending send_wakers.
            drop(inner);
            let obligation = resolve_send_obligation(obligation, false);
            return (
                Err(SendError::Disconnected(value)),
                DeferredReceiverWake {
                    receiver: None,
                    obligation,
                },
            );
        }

        inner.queue.push_back(value);

        // Extract waker before dropping the lock to avoid wake-under-lock.
        let recv_waker = inner.recv_waker.take();
        drop(inner);
        let obligation = resolve_send_obligation(obligation, true);
        (
            Ok(()),
            DeferredReceiverWake {
                receiver: recv_waker,
                obligation,
            },
        )
    }

    /// Aborts the reserved slot without sending.
    #[inline]
    pub fn abort(mut self) {
        self.sent = true;
        let _wake = self.release_capacity();
        if let Some(token) = self.obligation.take() {
            let _ = token.abort(crate::record::ObligationAbortReason::Explicit);
        }
    }

    fn release_capacity(&self) -> ReleasedCapacityWake {
        let next_waker = {
            let mut inner = self.sender.shared.inner.lock();
            if inner.reserved == 0 {
                debug_assert!(false, "abort permit without reservation");
            } else {
                inner.reserved -= 1;
            }
            inner.record_cancellation();
            inner.take_next_sender_waker()
        };
        ReleasedCapacityWake(next_waker)
    }

    /// Returns an opt-in redacted telemetry snapshot for this send permit.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        self.sender.shared.telemetry_snapshot(channel_id)
    }
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if !self.sent {
            self.sent = true;
            let _wake = self.release_capacity();
            if let Some(token) = self.obligation.take() {
                let _ = token.abort(crate::record::ObligationAbortReason::Cancel);
            }
        }
    }
}

/// The receiving side of an MPSC channel.
pub struct Receiver<T> {
    shared: Arc<ChannelShared<T>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver")
            .field("shared", &self.shared)
            .finish()
    }
}

impl<T> Receiver<T> {
    pub(crate) fn clear_recv_waker(&mut self) {
        let retired_waker = self.shared.inner.lock().recv_waker.take();
        drop(retired_waker);
    }

    /// Closes the channel, preventing any further messages from being sent.
    ///
    /// Existing messages in the queue remain available for receiving.
    /// Any pending senders will be woken and receive a `Disconnected` error.
    pub fn close(&mut self) {
        let wakers = {
            let mut inner = self.shared.inner.lock();
            if self.shared.receiver_dropped.load(Ordering::Relaxed) {
                return;
            }
            let wakers = inner.drain_sender_wakers();
            self.shared.receiver_dropped.store(true, Ordering::Release);
            drop(inner);
            wakers
        };
        for waker in wakers {
            waker.wake_by_ref();
        }
    }

    /// Creates a receive future for the next value.
    #[inline]
    #[must_use]
    pub fn recv<'a, Caps>(&'a mut self, cx: &'a Cx<Caps>) -> Recv<'a, T, Caps> {
        Recv {
            receiver: self,
            cx,
            polled: false,
        }
    }

    /// Creates a receive future that appends up to `limit` values into `buffer`.
    ///
    /// The future waits until at least one value is available unless `limit` is
    /// zero or the channel is closed and fully drained. It returns the number of
    /// appended values. A return value of zero means either `limit == 0` or no
    /// more values can arrive.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::channel::mpsc;
    ///
    /// let (tx, mut rx) = mpsc::channel(4);
    /// tx.try_send(1).unwrap();
    /// tx.try_send(2).unwrap();
    ///
    /// let mut batch = Vec::new();
    /// let count = rx.recv_many(cx, &mut batch, 8).await.unwrap();
    /// assert_eq!(count, 2);
    /// assert_eq!(batch, vec![1, 2]);
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn recv_many<'a, Caps>(
        &'a mut self,
        cx: &'a Cx<Caps>,
        buffer: &'a mut Vec<T>,
        limit: usize,
    ) -> RecvMany<'a, T, Caps> {
        RecvMany {
            receiver: self,
            cx,
            buffer,
            limit,
            polled: false,
        }
    }

    /// Polls the receive operation directly without constructing a temporary future.
    ///
    /// This is useful in manual `poll_*` implementations that need to avoid
    /// creating-and-dropping transient `Recv` futures each poll cycle.
    #[inline]
    pub fn poll_recv<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<T, RecvError>> {
        let mut prepared_waker: Option<PreparedReceiverWaker> = None;

        loop {
            if cx.checkpoint().is_err() {
                cx.trace("mpsc::recv cancelled");
                let retired_waker = {
                    let mut inner = self.shared.inner.lock();
                    let retired_waker = inner.recv_waker.take();
                    inner.record_cancellation();
                    retired_waker
                };
                drop(retired_waker);
                drop(prepared_waker);
                return Poll::Ready(Err(RecvError::Cancelled));
            }

            let mut inner = self.shared.inner.lock();

            if let Some(value) = inner.queue.pop_front() {
                let retired_waker = inner.recv_waker.take();
                let next_waker = inner.take_next_sender_waker();
                drop(inner);
                drop(retired_waker);
                drop(prepared_waker);
                if let Some(waker) = next_waker {
                    waker.wake_by_ref();
                }
                return Poll::Ready(Ok(value));
            }

            if self.shared.sender_count.load(Ordering::Acquire) == 0
                || self.shared.receiver_dropped.load(Ordering::Relaxed)
            {
                let retired_waker = inner.recv_waker.take();
                drop(inner);
                drop(retired_waker);
                drop(prepared_waker);
                return Poll::Ready(Err(RecvError::Disconnected));
            }

            if inner
                .recv_waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(task_cx.waker()))
            {
                drop(inner);
                drop(prepared_waker);
                return Poll::Pending;
            }

            let Some(prepared) = prepared_waker.as_ref() else {
                // Clone only on the pending changed/absent slow path, without
                // the channel lock. The next iteration rechecks persistent
                // state and the wake epoch so no event during the gap is lost.
                let wake_epoch = inner.recv_wake_epoch;
                drop(inner);
                prepared_waker = Some(PreparedReceiverWaker {
                    registration: RegisteredWaker::new(task_cx.waker()),
                    wake_epoch,
                });
                continue;
            };

            let replay_wake = inner.recv_wake_epoch != prepared.wake_epoch;
            let retired_waker = inner.recv_waker.replace(Arc::clone(&prepared.registration));
            drop(inner);
            let prepared = prepared_waker
                .take()
                .expect("prepared receiver waker remains owned until after unlock");
            drop(retired_waker);
            if replay_wake {
                prepared.registration.wake_by_ref();
            }
            drop(prepared);
            return Poll::Pending;
        }
    }

    /// Polls a batch receive operation directly.
    ///
    /// See [`Receiver::recv_many`] for completion semantics.
    #[inline]
    pub fn poll_recv_many<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        buffer: &mut Vec<T>,
        limit: usize,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<usize, RecvError>> {
        if limit == 0 {
            return Poll::Ready(Ok(0));
        }

        let mut prepared_waker: Option<PreparedReceiverWaker> = None;

        loop {
            if cx.checkpoint().is_err() {
                cx.trace("mpsc::recv_many cancelled");
                let retired_waker = {
                    let mut inner = self.shared.inner.lock();
                    let retired_waker = inner.recv_waker.take();
                    inner.record_cancellation();
                    retired_waker
                };
                drop(retired_waker);
                drop(prepared_waker);
                return Poll::Ready(Err(RecvError::Cancelled));
            }

            let mut inner = self.shared.inner.lock();
            let target = limit.min(inner.queue.len());

            if target > 0 {
                buffer.extend(inner.queue.drain(..target));
                let sender_wakers =
                    inner.sender_wakers_for_freed_slots(target, self.shared.capacity);
                let retired_waker = inner.recv_waker.take();
                drop(inner);
                drop(retired_waker);
                drop(prepared_waker);
                for waker in sender_wakers {
                    waker.wake_by_ref();
                }
                return Poll::Ready(Ok(target));
            }

            if self.shared.sender_count.load(Ordering::Acquire) == 0
                || self.shared.receiver_dropped.load(Ordering::Relaxed)
            {
                let retired_waker = inner.recv_waker.take();
                drop(inner);
                drop(retired_waker);
                drop(prepared_waker);
                return Poll::Ready(Ok(0));
            }

            if inner
                .recv_waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(task_cx.waker()))
            {
                drop(inner);
                drop(prepared_waker);
                return Poll::Pending;
            }

            let Some(prepared) = prepared_waker.as_ref() else {
                let wake_epoch = inner.recv_wake_epoch;
                drop(inner);
                prepared_waker = Some(PreparedReceiverWaker {
                    registration: RegisteredWaker::new(task_cx.waker()),
                    wake_epoch,
                });
                continue;
            };

            let replay_wake = inner.recv_wake_epoch != prepared.wake_epoch;
            let retired_waker = inner.recv_waker.replace(Arc::clone(&prepared.registration));
            drop(inner);
            let prepared = prepared_waker
                .take()
                .expect("prepared receiver waker remains owned until after unlock");
            drop(retired_waker);
            if replay_wake {
                prepared.registration.wake_by_ref();
            }
            drop(prepared);
            return Poll::Pending;
        }
    }

    /// Attempts to receive a value without blocking.
    #[inline]
    pub fn try_recv(&mut self) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock();
        if let Some(value) = inner.queue.pop_front() {
            let retired_waker = inner.recv_waker.take();
            let next_waker = inner.take_next_sender_waker();
            drop(inner);
            drop(retired_waker);
            if let Some(w) = next_waker {
                w.wake_by_ref();
            }
            Ok(value)
        } else {
            let disconnected = self.shared.sender_count.load(Ordering::Acquire) == 0
                || self.shared.receiver_dropped.load(Ordering::Relaxed);
            let retired_waker = if disconnected {
                inner.recv_waker.take()
            } else {
                None
            };
            drop(inner);
            drop(retired_waker);
            if disconnected {
                Err(RecvError::Disconnected)
            } else {
                Err(RecvError::Empty)
            }
        }
    }

    /// Returns true if all senders have been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.sender_count.load(Ordering::Acquire) == 0
    }

    /// Returns true if there are any queued messages.
    #[inline]
    #[must_use]
    pub fn has_messages(&self) -> bool {
        !self.shared.inner.lock().queue.is_empty()
    }

    /// Returns the number of queued messages.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared.inner.lock().queue.len()
    }

    /// Returns true if the queue is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.inner.lock().queue.is_empty()
    }

    /// Returns the channel capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Returns an opt-in redacted telemetry snapshot for this MPSC receiver.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        self.shared.telemetry_snapshot(channel_id)
    }
}

/// Future returned by [`Receiver::recv`].
pub struct Recv<'a, T, Caps = crate::cx::cap::All> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx<Caps>,
    polled: bool,
}

impl<T, Caps> Future for Recv<'_, T, Caps> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.polled = true;
        this.receiver.poll_recv(this.cx, ctx)
    }
}

impl<T, Caps> Drop for Recv<'_, T, Caps> {
    fn drop(&mut self) {
        // Clear the registered waker to avoid retaining stale executor state
        // if this future is dropped (e.g., cancelled by select!).
        // Only clear if this future was actually polled, so we don't clobber
        // wakers registered by previous direct `poll_recv` calls.
        if self.polled {
            let retired_waker = self.receiver.shared.inner.lock().recv_waker.take();
            drop(retired_waker);
        }
    }
}

/// Future returned by [`Receiver::recv_many`].
pub struct RecvMany<'a, T, Caps = crate::cx::cap::All> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx<Caps>,
    buffer: &'a mut Vec<T>,
    limit: usize,
    polled: bool,
}

impl<T, Caps> Future for RecvMany<'_, T, Caps> {
    type Output = Result<usize, RecvError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.polled = true;
        this.receiver
            .poll_recv_many(this.cx, this.buffer, this.limit, ctx)
    }
}

impl<T, Caps> Drop for RecvMany<'_, T, Caps> {
    fn drop(&mut self) {
        if self.polled {
            let retired_waker = self.receiver.shared.inner.lock().recv_waker.take();
            drop(retired_waker);
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (wakers, _items, recv_waker) = {
            let mut inner = self.shared.inner.lock();
            // Drain before taking `recv_waker` or mutating close state. The
            // helper reserves first, so an allocation panic cannot retire any
            // executor Waker under `inner`.
            let wakers = inner.drain_sender_wakers();
            self.shared.receiver_dropped.store(true, Ordering::Release);
            // Clear any pending recv waker so a dropped receiver does not
            // retain executor task state indefinitely.
            let recv_waker = inner.recv_waker.take();
            // Drain queued items to prevent memory leaks when senders are
            // long-lived (they hold Arc refs that keep the queue alive).
            // We extract them using std::mem::take to drop them outside the lock,
            // preventing deadlocks if T::drop requires the same channel lock.
            let items = std::mem::take(&mut inner.queue);
            drop(inner);
            (wakers, items, recv_waker)
        };
        drop(recv_waker);
        // Wake senders outside the lock to avoid wake-under-lock deadlocks.
        for waker in wakers {
            waker.wake_by_ref();
        }
    }
}

/// The receiving side of an unbounded MPSC channel.
pub struct UnboundedReceiver<T> {
    inner: Receiver<T>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for UnboundedReceiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnboundedReceiver")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<T> UnboundedReceiver<T> {
    /// Closes the channel, preventing any further messages from being sent.
    #[inline]
    pub fn close(&mut self) {
        self.inner.close();
    }

    /// Creates a receive future for the next value.
    #[inline]
    #[must_use]
    pub fn recv<'a, Caps>(&'a mut self, cx: &'a Cx<Caps>) -> Recv<'a, T, Caps> {
        self.inner.recv(cx)
    }

    /// Creates a receive future that appends up to `limit` values into `buffer`.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::channel::mpsc;
    ///
    /// let (tx, mut rx) = mpsc::unbounded_channel();
    /// tx.send("a").unwrap();
    /// tx.send("b").unwrap();
    ///
    /// let mut batch = Vec::new();
    /// let count = rx.recv_many(cx, &mut batch, 1).await.unwrap();
    /// assert_eq!(count, 1);
    /// assert_eq!(batch, vec!["a"]);
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub fn recv_many<'a, Caps>(
        &'a mut self,
        cx: &'a Cx<Caps>,
        buffer: &'a mut Vec<T>,
        limit: usize,
    ) -> RecvMany<'a, T, Caps> {
        self.inner.recv_many(cx, buffer, limit)
    }

    /// Polls the receive operation directly without constructing a temporary future.
    #[inline]
    pub fn poll_recv<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<T, RecvError>> {
        self.inner.poll_recv(cx, task_cx)
    }

    /// Polls a batch receive operation directly.
    #[inline]
    pub fn poll_recv_many<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        buffer: &mut Vec<T>,
        limit: usize,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<usize, RecvError>> {
        self.inner.poll_recv_many(cx, buffer, limit, task_cx)
    }

    /// Attempts to receive a value without blocking.
    #[inline]
    pub fn try_recv(&mut self) -> Result<T, RecvError> {
        self.inner.try_recv()
    }

    /// Returns true if all senders have been dropped.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Returns true if there are any queued messages.
    #[inline]
    #[must_use]
    pub fn has_messages(&self) -> bool {
        self.inner.has_messages()
    }

    /// Returns the number of queued messages.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the queue is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the unbounded capacity sentinel.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Returns an opt-in redacted telemetry snapshot for this receiver.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, channel_id: u64) -> MpscTelemetrySnapshot {
        self.inner.telemetry_snapshot(channel_id)
    }
}

#[cfg(test)]
include!("mpsc_tests.rs");
