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
//!   permit.send(message);                 // Phase 2: commit (cannot fail)
//! ```
//!
//! # Obligation Tracking
//!
//! Each `SendPermit` represents an obligation that must be resolved:
//! - `permit.send(value)`: Commits the obligation
//! - `permit.abort()`: Aborts the obligation
//! - `drop(permit)`: Equivalent to abort (RAII cleanup)

use parking_lot::Mutex;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

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
            Self::Cancelled => write!(f, "receive operation cancelled"),
            Self::Empty => write!(f, "mpsc channel is empty"),
        }
    }
}

impl std::error::Error for RecvError {}

/// A queued waiter for channel capacity.
///
/// Waker is stored inline (no inner `Mutex`) because all access occurs while
/// the outer `ChannelInner` lock is held, making a per-waiter mutex pure overhead.
/// Identity is a monotonic `u64` instead of `Arc::ptr_eq`, eliminating one `Arc`
/// allocation per waiter.
#[derive(Debug)]
struct SendWaiter {
    id: u64,
    waker: Waker,
}

/// Internal channel state shared between senders and receivers.
#[derive(Debug)]
struct ChannelInner<T> {
    /// Buffered messages waiting to be received.
    queue: VecDeque<T>,
    /// Number of reserved slots (permits outstanding).
    reserved: usize,
    /// Wakers for senders waiting for capacity.
    send_wakers: VecDeque<SendWaiter>,
    /// Waker for the receiver waiting for messages.
    recv_waker: Option<Waker>,
    /// Monotonic counter for waiter identity (replaces Arc::ptr_eq).
    next_waiter_id: u64,
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
        Self {
            queue: VecDeque::with_capacity(capacity),
            reserved: 0,
            send_wakers: VecDeque::with_capacity(4),
            recv_waker: None,
            next_waiter_id: 0,
        }
    }

    /// Returns the number of used slots (queued + reserved).
    #[inline]
    fn used_slots(&self) -> usize {
        self.queue.len() + self.reserved
    }

    /// Returns true if there's capacity for another reservation.
    #[inline]
    fn has_capacity(&self, capacity: usize) -> bool {
        self.used_slots() < capacity
    }

    /// Returns the waker for the next waiting sender, if any.
    /// The caller must invoke `waker.wake()` **after** releasing the channel
    /// lock to avoid wake-under-lock deadlocks.
    ///
    /// This does NOT remove the waiter from the queue. The waiter is responsible
    /// for removing itself upon successfully acquiring a permit.
    #[inline]
    fn take_next_sender_waker(&self) -> Option<Waker> {
        self.send_wakers.front().map(|waiter| waiter.waker.clone())
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
            waiter_id: None,
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

        if !inner.send_wakers.is_empty() {
            return Err(SendError::<()>::Full(()));
        }

        if inner.has_capacity(self.shared.capacity) {
            inner.reserved += 1;
            drop(inner);
            Ok(SendPermit {
                sender: self,
                sent: false,
            })
        } else {
            Err(SendError::<()>::Full(()))
        }
    }

    /// Attempts to send a value without blocking.
    #[inline]
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        match self.try_reserve() {
            Ok(permit) => permit.try_send(value),
            Err(SendError::<()>::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::<()>::Full(())) => Err(SendError::Full(value)),
            Err(SendError::<()>::Cancelled(())) => unreachable!(),
        }
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
        let waker = inner.recv_waker.take();
        drop(inner);
        if let Some(waker) = waker {
            waker.wake();
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
            self.shared.receiver_dropped.store(true, Ordering::Release);
            let send_wakers: SmallVec<[Waker; 4]> = inner
                .send_wakers
                .drain(..)
                .map(|waiter| waiter.waker)
                .collect();
            let recv_waker = inner.recv_waker.take();
            drop(inner);
            (send_wakers, recv_waker)
        };

        for waker in send_wakers {
            waker.wake();
        }
        if let Some(waker) = recv_waker {
            waker.wake();
        }
    }

    /// Returns the channel's capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
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
        let has_logical_capacity = has_physical_capacity && inner.send_wakers.is_empty();

        let evicted = if has_logical_capacity {
            None
        } else if has_physical_capacity {
            // A queued waiter already owns the next free slot. Preserve FIFO
            // ordering by treating the channel as logically full, but do not
            // evict a committed message when there is still real capacity.
            return Err(SendError::Full(value));
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
            waker.wake();
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
pub struct Reserve<'a, T> {
    sender: &'a Sender<T>,
    cx: &'a Cx,
    waiter_id: Option<u64>,
}

impl<T> Reserve<'_, T> {
    fn cleanup_waiter(&mut self) {
        if let Some(id) = self.waiter_id.take() {
            let next_waker = {
                let mut inner = self.sender.shared.inner.lock();

                if self.sender.shared.receiver_dropped.load(Ordering::Relaxed) {
                    // Channel closed. We either were drained (no reservation)
                    // or pre-granted (reservation leaked, but channel is dead anyway).
                    // Safest to just do nothing.
                    None
                } else if let Some(pos) = inner.send_wakers.iter().position(|w| w.id == id) {
                    // We are in the queue. We haven't been granted a reservation.
                    inner.send_wakers.remove(pos);
                    // CASCADE: A receiver may have freed capacity and woken us,
                    // but we never polled. Pass the baton to the next waiter.
                    if inner.has_capacity(self.sender.shared.capacity) {
                        inner.take_next_sender_waker()
                    } else {
                        None
                    }
                } else {
                    // Stale waiter: not in queue, channel alive.
                    // Another agent or cleanup already removed us. We have no
                    // resource ownership to transfer, so do nothing.
                    None
                }
            };
            if let Some(w) = next_waker {
                w.wake();
            }
        }
    }
}

impl<'a, T> Future for Reserve<'a, T> {
    type Output = Result<SendPermit<'a, T>, SendError<()>>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // Check cancellation
        if self.cx.checkpoint().is_err() {
            self.cx.trace("mpsc::reserve cancelled");
            self.cleanup_waiter();
            return Poll::Ready(Err(SendError::<()>::Cancelled(())));
        }

        let mut inner = self.sender.shared.inner.lock();

        if self.sender.shared.receiver_dropped.load(Ordering::Relaxed) {
            self.waiter_id = None; // Waiter is already cleared by Receiver::drop
            return Poll::Ready(Err(SendError::<()>::Disconnected(())));
        }

        let is_first = self.waiter_id.map_or_else(
            || inner.send_wakers.is_empty(),
            |id| inner.send_wakers.front().is_some_and(|w| w.id == id),
        );

        if is_first && inner.has_capacity(self.sender.shared.capacity) {
            inner.reserved += 1;
            // Remove self from queue
            if let Some(id) = self.waiter_id {
                let is_head = inner.send_wakers.front().is_some_and(|w| w.id == id);

                if is_head {
                    inner.send_wakers.pop_front();
                } else if let Some(pos) = inner.send_wakers.iter().position(|w| w.id == id) {
                    inner.send_wakers.remove(pos);
                }

                // CASCADE: If there is still capacity, wake the *next* waiter.
                // Extract waker now; wake after releasing the lock.
                let cascade_waker = if inner.has_capacity(self.sender.shared.capacity) {
                    inner.take_next_sender_waker()
                } else {
                    None
                };
                drop(inner);
                if let Some(w) = cascade_waker {
                    w.wake();
                }

                // Clear waiter_id so Drop doesn't uselessly lock and search the queue
                self.waiter_id = None;
            } else {
                drop(inner);
            }

            return Poll::Ready(Ok(SendPermit {
                sender: self.sender,
                sent: false,
            }));
        }

        // Register/update waiter (all access under outer lock — no inner Mutex needed)
        if let Some(id) = self.waiter_id {
            // Already queued. Update waker inline.
            if let Some(entry) = inner.send_wakers.iter_mut().find(|w| w.id == id) {
                if !entry.waker.will_wake(ctx.waker()) {
                    entry.waker.clone_from(ctx.waker());
                }
            }
        } else {
            // New waiter — assign monotonic id, store waker inline.
            let id = inner.next_waiter_id;
            inner.next_waiter_id = inner.next_waiter_id.wrapping_add(1);
            inner.send_wakers.push_back(SendWaiter {
                id,
                waker: ctx.waker().clone(),
            });
            self.waiter_id = Some(id);
        }

        drop(inner);
        Poll::Pending
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
            // Last sender dropped — acquire lock to take recv_waker.
            // Re-check under lock in case a WeakSender::upgrade raced.
            let recv_waker = {
                let mut inner = self.shared.inner.lock();
                if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                    inner.recv_waker.take()
                } else {
                    None
                }
            };
            if let Some(waker) = recv_waker {
                waker.wake();
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

/// A permit to send a single value.
#[derive(Debug)]
#[must_use = "SendPermit must be consumed via send() or abort()"]
pub struct SendPermit<'a, T> {
    sender: &'a Sender<T>,
    sent: bool,
}

impl<T> SendPermit<'_, T> {
    /// Commits the reserved slot, enqueuing the value.
    #[inline]
    pub fn send(self, value: T) {
        let _ = self.try_send(value);
    }

    /// Commits the reserved slot, returning an error if the receiver was dropped.
    #[inline]
    pub fn try_send(mut self, value: T) -> Result<(), SendError<T>> {
        self.sent = true;
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
            return Err(SendError::Disconnected(value));
        }

        inner.queue.push_back(value);

        // Extract waker before dropping the lock to avoid wake-under-lock.
        let recv_waker = inner.recv_waker.take();
        drop(inner);
        if let Some(waker) = recv_waker {
            waker.wake();
        }
        Ok(())
    }

    /// Aborts the reserved slot without sending.
    #[inline]
    pub fn abort(mut self) {
        self.sent = true;
        let next_waker = {
            let mut inner = self.sender.shared.inner.lock();
            if inner.reserved == 0 {
                debug_assert!(false, "abort permit without reservation");
            } else {
                inner.reserved -= 1;
            }
            inner.take_next_sender_waker()
        };
        // Wake outside the lock.
        if let Some(w) = next_waker {
            w.wake();
        }
    }
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if !self.sent {
            let next_waker = {
                let mut inner = self.sender.shared.inner.lock();
                if inner.reserved == 0 {
                    debug_assert!(false, "dropped permit without reservation");
                } else {
                    inner.reserved -= 1;
                }
                inner.take_next_sender_waker()
            };
            // Wake outside the lock.
            if let Some(w) = next_waker {
                w.wake();
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
        self.shared.inner.lock().recv_waker = None;
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
            self.shared.receiver_dropped.store(true, Ordering::Release);
            let wakers: SmallVec<[Waker; 4]> = inner
                .send_wakers
                .drain(..)
                .map(|waiter| waiter.waker)
                .collect();
            drop(inner);
            wakers
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// Creates a receive future for the next value.
    #[inline]
    #[must_use]
    pub fn recv<'a>(&'a mut self, cx: &'a Cx) -> Recv<'a, T> {
        Recv {
            receiver: self,
            cx,
            polled: false,
        }
    }

    /// Polls the receive operation directly without constructing a temporary future.
    ///
    /// This is useful in manual `poll_*` implementations that need to avoid
    /// creating-and-dropping transient `Recv` futures each poll cycle.
    #[inline]
    pub fn poll_recv(&mut self, cx: &Cx, task_cx: &mut Context<'_>) -> Poll<Result<T, RecvError>> {
        if cx.checkpoint().is_err() {
            cx.trace("mpsc::recv cancelled");
            self.shared.inner.lock().recv_waker = None;
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        let mut inner = self.shared.inner.lock();

        if let Some(value) = inner.queue.pop_front() {
            inner.recv_waker = None;
            let next_waker = inner.take_next_sender_waker();
            drop(inner);
            if let Some(w) = next_waker {
                w.wake();
            }
            return Poll::Ready(Ok(value));
        }

        if self.shared.sender_count.load(Ordering::Acquire) == 0
            || self.shared.receiver_dropped.load(Ordering::Relaxed)
        {
            inner.recv_waker = None;
            return Poll::Ready(Err(RecvError::Disconnected));
        }

        // Skip waker clone if unchanged — common on re-poll.
        match &inner.recv_waker {
            Some(existing) if existing.will_wake(task_cx.waker()) => {}
            _ => inner.recv_waker = Some(task_cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Attempts to receive a value without blocking.
    #[inline]
    pub fn try_recv(&mut self) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock();
        if let Some(value) = inner.queue.pop_front() {
            inner.recv_waker = None;
            let next_waker = inner.take_next_sender_waker();
            drop(inner);
            if let Some(w) = next_waker {
                w.wake();
            }
            Ok(value)
        } else {
            let disconnected = self.shared.sender_count.load(Ordering::Acquire) == 0
                || self.shared.receiver_dropped.load(Ordering::Relaxed);
            if disconnected {
                inner.recv_waker = None;
            }
            drop(inner);
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
}

/// Future returned by [`Receiver::recv`].
pub struct Recv<'a, T> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx,
    polled: bool,
}

impl<T> Future for Recv<'_, T> {
    type Output = Result<T, RecvError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.polled = true;
        this.receiver.poll_recv(this.cx, ctx)
    }
}

impl<T> Drop for Recv<'_, T> {
    fn drop(&mut self) {
        // Clear the registered waker to avoid retaining stale executor state
        // if this future is dropped (e.g., cancelled by select!).
        // Only clear if this future was actually polled, so we don't clobber
        // wakers registered by previous direct `poll_recv` calls.
        if self.polled {
            let mut inner = self.receiver.shared.inner.lock();
            inner.recv_waker = None;
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (wakers, _items) = {
            let mut inner = self.shared.inner.lock();
            self.shared.receiver_dropped.store(true, Ordering::Release);
            // Clear any pending recv waker so a dropped receiver does not
            // retain executor task state indefinitely.
            inner.recv_waker = None;
            // Drain queued items to prevent memory leaks when senders are
            // long-lived (they hold Arc refs that keep the queue alive).
            // We extract them using std::mem::take to drop them outside the lock,
            // preventing deadlocks if T::drop requires the same channel lock.
            let items = std::mem::take(&mut inner.queue);
            let wakers: SmallVec<[Waker; 4]> = inner
                .send_wakers
                .drain(..)
                .map(|waiter| waiter.waker)
                .collect();
            drop(inner);
            (wakers, items)
        };
        // Wake senders outside the lock to avoid wake-under-lock deadlocks.
        for waker in wakers {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let waker = Waker::from(std::sync::Arc::new(NoopWaker));
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
    fn channel_capacity_must_be_nonzero() {
        init_test("channel_capacity_must_be_nonzero");
        let result = std::panic::catch_unwind(|| channel::<i32>(0));
        crate::assert_with_log!(result.is_err(), "capacity 0 panics", true, result.is_err());
        crate::test_complete!("channel_capacity_must_be_nonzero");
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        block_on(tx.send(&cx, 42)).expect("send failed");
        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn fifo_ordering_single_sender() {
        init_test("fifo_ordering_single_sender");
        let cx = test_cx();
        let (tx, mut rx) = channel::<usize>(128);

        for i in 0..100 {
            block_on(tx.send(&cx, i)).expect("send failed");
        }
        drop(tx);

        let mut received = Vec::new();
        loop {
            match block_on(rx.recv(&cx)) {
                Ok(value) => received.push(value),
                Err(RecvError::Disconnected) => break,
                Err(other) => {
                    crate::assert_with_log!(
                        false,
                        "unexpected recv error",
                        "Disconnected",
                        format!("{other:?}")
                    );
                    break;
                }
            }
        }

        let expected: Vec<_> = (0..100).collect();
        crate::assert_with_log!(received == expected, "fifo order", expected, received);
        crate::test_complete!("fifo_ordering_single_sender");
    }

    #[test]
    fn backpressure_blocks_until_recv() {
        init_test("backpressure_blocks_until_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        block_on(tx.send(&cx, 1)).expect("send failed");

        let finished = Arc::new(AtomicBool::new(false));
        let finished_clone = Arc::clone(&finished);
        let tx_clone = tx;
        let cx_clone = cx.clone();

        let handle = std::thread::spawn(move || {
            block_on(tx_clone.send(&cx_clone, 2)).expect("send in worker failed");
            finished_clone.store(true, Ordering::SeqCst);
        });

        for _ in 0..1_000 {
            std::thread::yield_now();
        }
        let finished_now = finished.load(Ordering::SeqCst);
        crate::assert_with_log!(
            !finished_now,
            "send completed despite full channel",
            false,
            finished_now
        );

        let first = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(first == 1, "first recv", 1, first);

        // Wait for worker
        for _ in 0..10_000 {
            if finished.load(Ordering::SeqCst) {
                break;
            }
            std::thread::yield_now();
        }
        let finished_now = finished.load(Ordering::SeqCst);
        crate::assert_with_log!(finished_now, "worker finished", true, finished_now);
        let second = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(second == 2, "second recv", 2, second);

        handle.join().expect("sender thread panicked");
        crate::test_complete!("backpressure_blocks_until_recv");
    }

    #[test]
    fn two_phase_send_recv() {
        init_test("two_phase_send_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        // Phase 1: reserve
        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");

        // Phase 2: commit
        permit.send(42);

        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("two_phase_send_recv");
    }

    #[test]
    fn permit_abort_releases_slot() {
        init_test("permit_abort_releases_slot");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");

        let try_reserve = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_reserve, Err(SendError::<()>::Full(()))),
            "try_reserve full",
            "Err(Full(()))",
            format!("{:?}", try_reserve)
        );

        permit.abort();

        let permit2 = block_on(tx.reserve(&cx));
        crate::assert_with_log!(
            permit2.is_ok(),
            "reserve after abort",
            true,
            permit2.is_ok()
        );
        crate::test_complete!("permit_abort_releases_slot");
    }

    #[test]
    fn permit_drop_releases_slot() {
        init_test("permit_drop_releases_slot");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        {
            let _permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        }

        let permit = block_on(tx.reserve(&cx));
        crate::assert_with_log!(permit.is_ok(), "reserve after drop", true, permit.is_ok());
        crate::test_complete!("permit_drop_releases_slot");
    }

    #[test]
    fn try_send_when_full() {
        init_test("try_send_when_full");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        block_on(tx.send(&cx, 1)).expect("send failed");

        let result = tx.try_send(2);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Full(2))),
            "try_send full",
            "Err(Full(2))",
            format!("{:?}", result)
        );
        crate::test_complete!("try_send_when_full");
    }

    #[test]
    fn try_recv_when_empty() {
        init_test("try_recv_when_empty");
        let (tx, mut rx) = channel::<i32>(10);

        let empty = rx.try_recv();
        crate::assert_with_log!(
            matches!(empty, Err(RecvError::Empty)),
            "try_recv empty",
            "Err(Empty)",
            format!("{:?}", empty)
        );

        let cx = test_cx();
        block_on(tx.send(&cx, 42)).expect("send failed");

        let value = rx.try_recv();
        let ok = matches!(value, Ok(42));
        crate::assert_with_log!(ok, "try_recv value", true, ok);
        crate::test_complete!("try_recv_when_empty");
    }

    #[test]
    fn recv_after_sender_dropped_drains_queue() {
        init_test("recv_after_sender_dropped_drains_queue");
        let (tx, mut rx) = channel::<i32>(10);
        let cx = test_cx();

        block_on(tx.send(&cx, 1)).expect("send failed");
        block_on(tx.send(&cx, 2)).expect("send failed");
        drop(tx);

        let first = block_on(rx.recv(&cx));
        let first_ok = matches!(first, Ok(1));
        crate::assert_with_log!(first_ok, "recv first", true, first_ok);
        let second = block_on(rx.recv(&cx));
        let second_ok = matches!(second, Ok(2));
        crate::assert_with_log!(second_ok, "recv second", true, second_ok);

        let disconnected = rx.try_recv();
        let is_disconnected = matches!(disconnected, Err(RecvError::Disconnected));
        crate::assert_with_log!(is_disconnected, "recv disconnected", true, is_disconnected);
        crate::test_complete!("recv_after_sender_dropped_drains_queue");
    }

    #[test]
    fn multiple_senders() {
        init_test("multiple_senders");
        let (tx1, mut rx) = channel::<i32>(10);
        let tx2 = tx1.clone();
        let cx = test_cx();

        block_on(tx1.send(&cx, 1)).expect("send1 failed");
        block_on(tx2.send(&cx, 2)).expect("send2 failed");

        let v1 = block_on(rx.recv(&cx)).expect("recv1 failed");
        let v2 = block_on(rx.recv(&cx)).expect("recv2 failed");

        let ok = (v1 == 1 && v2 == 2) || (v1 == 2 && v2 == 1);
        crate::assert_with_log!(ok, "both messages received", true, (v1, v2));
        crate::test_complete!("multiple_senders");
    }

    fn cancelled_cx() -> Cx {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        cx
    }

    fn noop_waker() -> Waker {
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        Waker::from(std::sync::Arc::new(NoopWaker))
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<AtomicUsize>,
        }

        impl std::task::Wake for CountingWaker {
            fn wake(self: std::sync::Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        Waker::from(std::sync::Arc::new(CountingWaker { counter }))
    }

    #[test]
    fn reserve_cancelled_returns_error() {
        init_test("reserve_cancelled_returns_error");
        let (tx, _rx) = channel::<i32>(1);
        let cx = cancelled_cx();
        let result = block_on(tx.reserve(&cx));
        crate::assert_with_log!(
            matches!(result, Err(SendError::<()>::Cancelled(()))),
            "reserve cancelled",
            "Err(Cancelled(()))",
            format!("{:?}", result)
        );
        crate::test_complete!("reserve_cancelled_returns_error");
    }

    #[test]
    fn recv_cancelled_returns_error() {
        init_test("recv_cancelled_returns_error");
        let (_tx, mut rx) = channel::<i32>(1);
        let cx = cancelled_cx();
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Cancelled)),
            "recv cancelled",
            "Err(Cancelled)",
            format!("{:?}", result)
        );
        crate::test_complete!("recv_cancelled_returns_error");
    }

    #[test]
    fn recv_cancelled_does_not_consume_message() {
        init_test("recv_cancelled_does_not_consume_message");
        let (tx, mut rx) = channel::<i32>(1);
        let cx = test_cx();

        block_on(tx.send(&cx, 9)).expect("send");

        cx.set_cancel_requested(true);
        let cancelled = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(cancelled, Err(RecvError::Cancelled)),
            "recv cancelled",
            "Err(Cancelled)",
            format!("{:?}", cancelled)
        );

        cx.set_cancel_requested(false);
        let value = block_on(rx.recv(&cx)).expect("recv");
        crate::assert_with_log!(value == 9, "recv value after cancel", 9, value);
        crate::test_complete!("recv_cancelled_does_not_consume_message");
    }

    #[test]
    fn dropped_permit_releases_capacity() {
        init_test("dropped_permit_releases_capacity");
        let (tx, mut rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve");
        drop(permit);

        let permit2 = tx.try_reserve().expect("try_reserve after drop");
        permit2.send(5);

        let value = block_on(rx.recv(&cx)).expect("recv");
        crate::assert_with_log!(value == 5, "recv value", 5, value);
        crate::test_complete!("dropped_permit_releases_capacity");
    }

    #[test]
    fn send_after_receiver_drop_returns_disconnected() {
        init_test("send_after_receiver_drop_returns_disconnected");
        let (tx, rx) = channel::<i32>(1);
        let cx = test_cx();
        drop(rx);
        let result = block_on(tx.send(&cx, 7));
        crate::assert_with_log!(
            matches!(result, Err(SendError::Disconnected(7))),
            "send after drop",
            "Err(Disconnected(7))",
            format!("{:?}", result)
        );
        crate::test_complete!("send_after_receiver_drop_returns_disconnected");
    }

    #[test]
    fn try_reserve_full_when_waiter_queued() {
        init_test("try_reserve_full_when_waiter_queued");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve");

        let mut reserve_fut = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);
        let poll = reserve_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(poll, Poll::Pending),
            "reserve pending",
            "Pending",
            format!("{:?}", poll)
        );

        permit.abort();

        let try_reserve = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_reserve, Err(SendError::<()>::Full(()))),
            "try_reserve full due to waiter",
            "Err(Full(()))",
            format!("{:?}", try_reserve)
        );

        let poll2 = reserve_fut.as_mut().poll(&mut cx_task);
        let waiter_acquired = match poll2 {
            Poll::Ready(Ok(permit2)) => {
                permit2.abort();
                true
            }
            _ => false,
        };
        crate::assert_with_log!(waiter_acquired, "waiter acquires", true, waiter_acquired);

        drop(reserve_fut);
        crate::test_complete!("try_reserve_full_when_waiter_queued");
    }

    #[test]
    fn receiver_close_returns_disconnected_on_empty() {
        init_test("receiver_close_returns_disconnected_on_empty");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        block_on(tx.send(&cx, 1)).expect("send failed");
        rx.close();

        // Should receive the message that was sent before close.
        let value = rx.try_recv();
        crate::assert_with_log!(
            matches!(value, Ok(1)),
            "try_recv gets message",
            "Ok(1)",
            format!("{:?}", value)
        );

        // Now empty, should return Disconnected, not Empty.
        let empty_try = rx.try_recv();
        crate::assert_with_log!(
            matches!(empty_try, Err(RecvError::Disconnected)),
            "try_recv returns Disconnected",
            "Err(Disconnected)",
            format!("{:?}", empty_try)
        );

        let empty_recv = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(empty_recv, Err(RecvError::Disconnected)),
            "recv returns Disconnected",
            "Err(Disconnected)",
            format!("{:?}", empty_recv)
        );

        crate::test_complete!("receiver_close_returns_disconnected_on_empty");
    }

    #[test]
    fn try_recv_disconnected_when_closed_and_empty() {
        init_test("try_recv_disconnected_when_closed_and_empty");
        let (tx, mut rx) = channel::<i32>(1);
        drop(tx);
        let result = rx.try_recv();
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Disconnected)),
            "try_recv disconnected",
            "Err(Disconnected)",
            format!("{:?}", result)
        );
        crate::test_complete!("try_recv_disconnected_when_closed_and_empty");
    }

    #[test]
    fn permit_send_after_receiver_drop_does_not_enqueue() {
        init_test("permit_send_after_receiver_drop_does_not_enqueue");
        let (tx, rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve failed");
        drop(rx);
        permit.send(5);

        let (queue_empty, reserved) = {
            let inner = tx.shared.inner.lock();
            let queue_empty = inner.queue.is_empty();
            let reserved = inner.reserved;
            drop(inner);
            (queue_empty, reserved)
        };
        crate::assert_with_log!(queue_empty, "queue empty", true, queue_empty);
        crate::assert_with_log!(reserved == 0, "reserved cleared", 0, reserved);
        crate::test_complete!("permit_send_after_receiver_drop_does_not_enqueue");
    }

    #[test]
    fn weak_sender_upgrade_fails_after_drop() {
        init_test("weak_sender_upgrade_fails_after_drop");
        let (tx, _rx) = channel::<i32>(1);
        let weak = tx.downgrade();
        drop(tx);
        let upgraded = weak.upgrade();
        crate::assert_with_log!(upgraded.is_none(), "upgrade none", true, upgraded.is_none());
        crate::test_complete!("weak_sender_upgrade_fails_after_drop");
    }

    #[test]
    fn send_evict_oldest_returns_full_when_all_capacity_reserved() {
        // Regression: send_evict_oldest must not exceed capacity when all
        // slots are consumed by outstanding permits (reserved slots).
        init_test("send_evict_oldest_returns_full_when_all_capacity_reserved");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(2);

        // Reserve both slots.
        let p1 = block_on(tx.reserve(&cx)).expect("reserve 1");
        let p2 = block_on(tx.reserve(&cx)).expect("reserve 2");

        // send_evict_oldest cannot evict reserved slots — must return Full.
        let result = tx.send_evict_oldest(99);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Full(99))),
            "send_evict_oldest full when reserved",
            "Err(Full(99))",
            format!("{:?}", result)
        );

        // Verify capacity invariant: used_slots <= capacity.
        {
            let inner = tx.shared.inner.lock();
            let used = inner.used_slots();
            let cap = tx.shared.capacity;
            drop(inner);
            crate::assert_with_log!(used <= cap, "capacity invariant", true, used <= cap);
        }

        p1.abort();
        p2.abort();
        crate::test_complete!("send_evict_oldest_returns_full_when_all_capacity_reserved");
    }

    #[test]
    fn send_evict_oldest_evicts_committed_not_reserved() {
        // When queue has committed messages AND reserved slots consume the
        // rest, eviction should pop a committed message.
        init_test("send_evict_oldest_evicts_committed_not_reserved");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(2);

        // Commit one message, reserve one slot.
        block_on(tx.send(&cx, 10)).expect("send");
        let permit = block_on(tx.reserve(&cx)).expect("reserve");

        // Channel: queue=[10], reserved=1, used=2, capacity=2.
        // send_evict_oldest should evict 10 and enqueue the new value.
        let result = tx.send_evict_oldest(20);
        crate::assert_with_log!(
            matches!(result, Ok(Some(10))),
            "evicted oldest",
            "Ok(Some(10))",
            format!("{:?}", result)
        );

        // Verify: queue=[20], reserved=1, used=2, capacity=2.
        {
            let inner = tx.shared.inner.lock();
            let used = inner.used_slots();
            let cap = tx.shared.capacity;
            let qlen = inner.queue.len();
            drop(inner);
            crate::assert_with_log!(used <= cap, "capacity after eviction", true, used <= cap);
            crate::assert_with_log!(qlen == 1, "queue len after eviction", 1, qlen);
        }

        permit.abort();
        crate::test_complete!("send_evict_oldest_evicts_committed_not_reserved");
    }

    #[test]
    fn send_evict_oldest_where_skips_protected_messages() {
        init_test("send_evict_oldest_where_skips_protected_messages");
        let (tx, mut rx) = channel::<i32>(2);

        tx.try_send(10).expect("send 10");
        tx.try_send(20).expect("send 20");

        let result = tx.send_evict_oldest_where(30, |value| *value == 20);
        crate::assert_with_log!(
            matches!(result, Ok(Some(20))),
            "evicted matching value",
            "Ok(Some(20))",
            format!("{:?}", result)
        );

        let first = block_on(rx.recv(&test_cx())).expect("recv 10");
        let second = block_on(rx.recv(&test_cx())).expect("recv 30");
        crate::assert_with_log!(first == 10, "first recv preserved", 10, first);
        crate::assert_with_log!(second == 30, "second recv new value", 30, second);
        crate::test_complete!("send_evict_oldest_where_skips_protected_messages");
    }

    #[test]
    fn send_evict_oldest_where_returns_full_without_match() {
        init_test("send_evict_oldest_where_returns_full_without_match");
        let (tx, mut rx) = channel::<i32>(1);

        tx.try_send(10).expect("send 10");

        let result = tx.send_evict_oldest_where(20, |value| *value == 99);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Full(20))),
            "full without matching eviction candidate",
            "Err(Full(20))",
            format!("{:?}", result)
        );

        let preserved = block_on(rx.recv(&test_cx())).expect("recv preserved");
        crate::assert_with_log!(preserved == 10, "preserved queued value", 10, preserved);
        crate::test_complete!("send_evict_oldest_where_returns_full_without_match");
    }

    #[test]
    fn send_evict_oldest_no_eviction_with_capacity() {
        init_test("send_evict_oldest_no_eviction_with_capacity");
        let (tx, _rx) = channel::<i32>(3);

        // Channel has capacity — should enqueue without eviction.
        let result = tx.send_evict_oldest(1);
        crate::assert_with_log!(
            matches!(result, Ok(None)),
            "no eviction with capacity",
            "Ok(None)",
            format!("{:?}", result)
        );

        let qlen = {
            let inner = tx.shared.inner.lock();
            let qlen = inner.queue.len();
            drop(inner);
            qlen
        };
        crate::assert_with_log!(qlen == 1, "queue len", 1, qlen);
        crate::test_complete!("send_evict_oldest_no_eviction_with_capacity");
    }

    #[test]
    fn send_evict_oldest_does_not_drop_messages_when_waiter_owns_free_slot() {
        init_test("send_evict_oldest_does_not_drop_messages_when_waiter_owns_free_slot");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(2);

        tx.try_send(10).expect("send 10");
        tx.try_send(11).expect("send 11");

        let mut reserve = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        assert!(reserve.as_mut().poll(&mut task_cx).is_pending());

        let first = rx.try_recv().expect("recv 10");
        crate::assert_with_log!(first == 10, "first recv", 10, first);

        let result = tx.send_evict_oldest(99);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Full(99))),
            "logical full when waiter owns free slot",
            "Err(Full(99))",
            format!("{:?}", result)
        );

        let preserved = rx.try_recv().expect("recv preserved 11");
        crate::assert_with_log!(preserved == 11, "preserved queued value", 11, preserved);

        drop(reserve);
        crate::test_complete!(
            "send_evict_oldest_does_not_drop_messages_when_waiter_owns_free_slot"
        );
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn send_evict_oldest_wakes_receiver() {
        // Verify send_evict_oldest wakes a pending receiver.
        init_test("send_evict_oldest_wakes_receiver");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(2);

        block_on(tx.send(&cx, 1)).expect("send 1");
        block_on(tx.send(&cx, 2)).expect("send 2");

        // Evict oldest and send new value.
        let result = tx.send_evict_oldest(3);
        let evicted_ok = matches!(result, Ok(Some(1)));
        crate::assert_with_log!(evicted_ok, "evicted 1", true, evicted_ok);

        // Receiver should get 2, then 3.
        let v1 = block_on(rx.recv(&cx)).expect("recv 1");
        let v2 = block_on(rx.recv(&cx)).expect("recv 2");
        crate::assert_with_log!(v1 == 2, "first recv after evict", 2, v1);
        crate::assert_with_log!(v2 == 3, "second recv after evict", 3, v2);
        crate::test_complete!("send_evict_oldest_wakes_receiver");
    }

    #[test]
    fn weak_sender_upgrade_increments_sender_count() {
        // Verify upgrade correctly tracks sender_count.
        init_test("weak_sender_upgrade_increments_sender_count");
        let (tx, rx) = channel::<i32>(1);
        let weak = tx.downgrade();

        let tx2 = weak.upgrade().expect("upgrade while sender alive");
        drop(tx);

        // Channel should NOT be closed — tx2 is still alive.
        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "not closed", false, closed);

        drop(tx2);
        let closed = rx.is_closed();
        crate::assert_with_log!(closed, "closed after all senders dropped", true, closed);
        crate::test_complete!("weak_sender_upgrade_increments_sender_count");
    }

    #[test]
    fn capacity_invariant_across_reserve_send_abort() {
        // Verify used_slots never exceeds capacity through mixed operations.
        init_test("capacity_invariant_across_reserve_send_abort");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(3);

        // Reserve 2 slots.
        let p1 = block_on(tx.reserve(&cx)).expect("reserve 1");
        let p2 = block_on(tx.reserve(&cx)).expect("reserve 2");

        // Check: reserved=2, queue=0, used=2
        let used = {
            let inner = tx.shared.inner.lock();
            inner.used_slots()
        };
        crate::assert_with_log!(used == 2, "used after 2 reserves", 2, used);

        // Commit one, abort one.
        p1.send(10);
        p2.abort();

        // Check: reserved=0, queue=1, used=1
        let (used, reserved) = {
            let inner = tx.shared.inner.lock();
            (inner.used_slots(), inner.reserved)
        };
        crate::assert_with_log!(used == 1, "used after send+abort", 1, used);
        crate::assert_with_log!(reserved == 0, "reserved cleared", 0, reserved);

        let v = block_on(rx.recv(&cx)).expect("recv");
        crate::assert_with_log!(v == 10, "received committed value", 10, v);
        crate::test_complete!("capacity_invariant_across_reserve_send_abort");
    }

    #[test]
    fn try_reserve_respects_fifo_over_capacity() {
        // try_reserve must return Full when waiters exist, even if capacity
        // is available (FIFO fairness).
        init_test("try_reserve_respects_fifo_over_capacity");
        let (tx, rx) = channel::<i32>(1);
        let cx = test_cx();

        // Fill the channel.
        let permit = block_on(tx.reserve(&cx)).expect("reserve fills channel");

        // Create a pending reserve future (adds to send_wakers).
        let mut reserve_fut = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);
        let poll = reserve_fut.as_mut().poll(&mut cx_task);
        assert!(matches!(poll, Poll::Pending));

        // Free capacity by aborting the first permit.
        permit.abort();

        // Now capacity exists, but a waiter is queued. try_reserve must
        // refuse to jump the queue.
        let try_result = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_result, Err(SendError::<()>::Full(()))),
            "try_reserve respects FIFO",
            "Err(Full)",
            format!("{:?}", try_result)
        );

        let poll2 = reserve_fut.as_mut().poll(&mut cx_task);
        let waiter_acquired = match poll2 {
            Poll::Ready(Ok(permit2)) => {
                permit2.abort();
                true
            }
            _ => false,
        };
        crate::assert_with_log!(waiter_acquired, "waiter acquires", true, waiter_acquired);

        drop(reserve_fut);
        drop(rx);
        crate::test_complete!("try_reserve_respects_fifo_over_capacity");
    }

    #[test]
    fn send_evict_oldest_disconnected_after_receiver_drop() {
        init_test("send_evict_oldest_disconnected_after_receiver_drop");
        let (tx, rx) = channel::<i32>(1);
        drop(rx);

        let result = tx.send_evict_oldest(42);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Disconnected(42))),
            "evict after rx drop",
            "Err(Disconnected(42))",
            format!("{:?}", result)
        );
        crate::test_complete!("send_evict_oldest_disconnected_after_receiver_drop");
    }

    #[test]
    fn reserve_pending_then_cancelled_cleans_waiter_queue() {
        init_test("reserve_pending_then_cancelled_cleans_waiter_queue");
        let cx = test_cx();
        let wait_cx = test_cx();
        let (tx, _rx) = channel::<i32>(1);

        let permit = block_on(tx.reserve(&cx)).expect("initial reserve");
        let mut reserve_fut = Box::pin(tx.reserve(&wait_cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let first_poll = reserve_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "pending waiter queued",
            "Pending",
            format!("{:?}", first_poll)
        );

        let queued_waiters = tx.shared.inner.lock().send_wakers.len();
        crate::assert_with_log!(queued_waiters == 1, "one waiter queued", 1, queued_waiters);

        wait_cx.set_cancel_requested(true);
        let cancelled_poll = reserve_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(
                cancelled_poll,
                Poll::Ready(Err(SendError::<()>::Cancelled(())))
            ),
            "pending waiter observes cancellation",
            "Ready(Err(Cancelled(())))",
            format!("{:?}", cancelled_poll)
        );

        drop(reserve_fut);
        let queued_after_cancel = tx.shared.inner.lock().send_wakers.len();
        crate::assert_with_log!(
            queued_after_cancel == 0,
            "cancelled waiter removed from queue",
            0,
            queued_after_cancel
        );

        permit.abort();
        let permit2 = tx.try_reserve().expect("phantom waiter blocks capacity");
        permit2.abort();
        crate::test_complete!("reserve_pending_then_cancelled_cleans_waiter_queue");
    }

    #[test]
    fn receiver_drop_unblocks_pending_reserve_without_leak() {
        init_test("receiver_drop_unblocks_pending_reserve_without_leak");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(1);

        let permit = block_on(tx.reserve(&cx)).expect("initial reserve");
        let mut reserve_fut = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);

        let first_poll = reserve_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "reserve future pending before receiver drop",
            "Pending",
            format!("{:?}", first_poll)
        );

        let queued_waiters = tx.shared.inner.lock().send_wakers.len();
        crate::assert_with_log!(queued_waiters == 1, "one waiter queued", 1, queued_waiters);

        drop(rx);
        let second_poll = reserve_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(
                second_poll,
                Poll::Ready(Err(SendError::<()>::Disconnected(())))
            ),
            "pending reserve sees disconnect after receiver drop",
            "Ready(Err(Disconnected(())))",
            format!("{:?}", second_poll)
        );
        drop(reserve_fut);

        let queued_after_drop = tx.shared.inner.lock().send_wakers.len();
        crate::assert_with_log!(
            queued_after_drop == 0,
            "receiver drop drains waiter queue",
            0,
            queued_after_drop
        );

        let try_reserve = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_reserve, Err(SendError::<()>::Disconnected(()))),
            "try_reserve reports disconnected",
            "Err(Disconnected(()))",
            format!("{:?}", try_reserve)
        );

        permit.abort();
        crate::test_complete!("receiver_drop_unblocks_pending_reserve_without_leak");
    }

    #[test]
    fn receiver_drop_clears_registered_recv_waker() {
        init_test("receiver_drop_clears_registered_recv_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let first_poll = rx.poll_recv(&cx, &mut task_cx);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "recv poll pending on empty channel",
            "Pending",
            format!("{:?}", first_poll)
        );

        let has_waker_before_drop = tx.shared.inner.lock().recv_waker.is_some();
        crate::assert_with_log!(
            has_waker_before_drop,
            "recv waker registered",
            true,
            has_waker_before_drop
        );

        drop(rx);

        let has_waker_after_drop = tx.shared.inner.lock().recv_waker.is_some();
        crate::assert_with_log!(
            !has_waker_after_drop,
            "recv waker cleared on receiver drop",
            true,
            !has_waker_after_drop
        );
        crate::test_complete!("receiver_drop_clears_registered_recv_waker");
    }

    #[test]
    fn wake_receiver_notifies_pending_recv_waker() {
        init_test("wake_receiver_notifies_pending_recv_waker");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut cx_task = Context::from_waker(&waker);
        let mut recv_fut = Box::pin(rx.recv(&cx));

        let first_poll = recv_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(first_poll, Poll::Pending),
            "recv initially pending",
            "Pending",
            format!("{:?}", first_poll)
        );

        tx.wake_receiver();
        let wakes_after_signal = wake_count.load(Ordering::SeqCst);
        crate::assert_with_log!(
            wakes_after_signal == 1,
            "wake_receiver triggered recv waker",
            1,
            wakes_after_signal
        );

        let second_poll = recv_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(second_poll, Poll::Pending),
            "recv remains pending without message",
            "Pending",
            format!("{:?}", second_poll)
        );

        tx.try_send(7).expect("try_send after wake");
        let third_poll = recv_fut.as_mut().poll(&mut cx_task);
        crate::assert_with_log!(
            matches!(third_poll, Poll::Ready(Ok(7))),
            "recv completes after message send",
            "Ready(Ok(7))",
            format!("{:?}", third_poll)
        );
        crate::test_complete!("wake_receiver_notifies_pending_recv_waker");
    }

    #[test]
    fn lost_wakeup_test() {
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        // Fill capacity.
        let permit = tx.try_reserve().unwrap();
        permit.send(1);

        // Queue A.
        let mut reserve_a = Box::pin(tx.reserve(&cx));
        let waker_a = noop_waker();
        let mut ctx_a = Context::from_waker(&waker_a);
        assert!(reserve_a.as_mut().poll(&mut ctx_a).is_pending());

        // Queue B.
        let mut reserve_b = Box::pin(tx.reserve(&cx));

        let wake_count_b = Arc::new(AtomicUsize::new(0));
        let reserve_waker_b = counting_waker(Arc::clone(&wake_count_b));
        let mut ctx_b = Context::from_waker(&reserve_waker_b);
        assert!(reserve_b.as_mut().poll(&mut ctx_b).is_pending());

        // Receiver takes message, which pops A and wakes it.
        let val = rx.try_recv().unwrap();
        assert_eq!(val, 1);

        // A drops before polling.
        drop(reserve_a);

        // B should be woken.
        assert!(wake_count_b.load(Ordering::Relaxed) > 0, "B was not woken!");
    }

    #[test]
    fn stale_missing_waiter_drop_does_not_wake_next_sender() {
        init_test("stale_missing_waiter_drop_does_not_wake_next_sender");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(1);

        let permit = tx.try_reserve().expect("fill capacity");
        permit.send(1);

        let mut reserve_a = Box::pin(tx.reserve(&cx));
        let waker_a = noop_waker();
        let mut ctx_a = Context::from_waker(&waker_a);
        assert!(reserve_a.as_mut().poll(&mut ctx_a).is_pending());

        let wake_count_b = Arc::new(AtomicUsize::new(0));
        let mut reserve_b = Box::pin(tx.reserve(&cx));
        let reserve_waker_b = counting_waker(Arc::clone(&wake_count_b));
        let mut ctx_b = Context::from_waker(&reserve_waker_b);
        assert!(reserve_b.as_mut().poll(&mut ctx_b).is_pending());

        {
            let mut inner = tx.shared.inner.lock();
            let waiter_id_a = reserve_a.waiter_id.expect("waiter id for A");
            let waiter_pos_a = inner
                .send_wakers
                .iter()
                .position(|w| w.id == waiter_id_a)
                .expect("A queued");
            inner.send_wakers.remove(waiter_pos_a);
            inner.queue.clear();
        }

        drop(reserve_a);

        let wakes_after_drop = wake_count_b.load(Ordering::SeqCst);
        crate::assert_with_log!(
            wakes_after_drop == 0,
            "stale drop does not spuriously wake next waiter",
            0,
            wakes_after_drop
        );

        drop(reserve_b);
        crate::test_complete!("stale_missing_waiter_drop_does_not_wake_next_sender");
    }
}

/// Metamorphic Testing: MPSC backpressure flow invariants
///
/// This module implements comprehensive metamorphic relations for MPSC channel
/// backpressure behavior, verifying that capacity management, ordering guarantees,
/// and cancel-safety remain correct under various load scenarios.
///
/// # Metamorphic Relations
///
/// 1. **Capacity Conservation** (MR1): total_capacity = queued + reserved + available
/// 2. **FIFO Ordering Preservation** (MR2): message order invariant under backpressure
/// 3. **Reserve-Send Equivalence** (MR3): reserve/send ≃ try_send (when capacity available)
/// 4. **Cancellation Idempotence** (MR4): cancel during reserve doesn't leak capacity
/// 5. **Eviction Policy Correctness** (MR5): evict_oldest maintains queue discipline
/// 6. **Receiver Drain Correctness** (MR6): receiver drop unblocks all pending sends
///
/// # Testing Strategy
///
/// Each metamorphic relation is implemented as a property-based test using `proptest`,
/// with LabRuntime for deterministic execution and comprehensive scenario coverage
/// including concurrent senders, varying load patterns, and cancellation timing.
#[cfg(test)]
pub mod backpressure_metamorphic {
    use super::*;
    use crate::types::{Budget, CancelReason};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Configuration for MPSC backpressure metamorphic tests.
    #[derive(Debug, Clone)]
    pub struct BackpressureTestConfig {
        /// Channel capacity.
        pub capacity: usize,
        /// Number of concurrent senders.
        pub sender_count: usize,
        /// Messages per sender.
        pub messages_per_sender: usize,
        /// Whether to inject cancellation during reserves.
        pub inject_cancellation: bool,
        /// Probability of cancellation (0.0 to 1.0).
        pub cancel_probability: f64,
        /// Random seed for deterministic execution.
        pub seed: u64,
        /// Whether to use eviction policy.
        pub use_eviction: bool,
        /// Whether to drop receiver early.
        pub drop_receiver_early: bool,
    }

    /// Generate valid backpressure test configurations.
    fn backpressure_config_strategy() -> impl Strategy<Value = BackpressureTestConfig> {
        (
            1..=16usize,   // capacity
            1..=8usize,    // sender_count
            1..=20usize,   // messages_per_sender
            any::<bool>(), // inject_cancellation
            0.0..=1.0f64,  // cancel_probability
            any::<u64>(),  // seed
            any::<bool>(), // use_eviction
            any::<bool>(), // drop_receiver_early
        )
            .prop_map(
                |(
                    capacity,
                    sender_count,
                    messages_per_sender,
                    inject_cancellation,
                    cancel_probability,
                    seed,
                    use_eviction,
                    drop_receiver_early,
                )| {
                    BackpressureTestConfig {
                        capacity,
                        sender_count,
                        messages_per_sender,
                        inject_cancellation,
                        cancel_probability,
                        seed,
                        use_eviction,
                        drop_receiver_early,
                    }
                },
            )
    }

    /// Helper to observe channel internal state.
    fn observe_channel_state<T>(sender: &Sender<T>) -> (usize, usize, usize, usize) {
        let inner = sender.shared.inner.lock();
        let queued = inner.queue.len();
        let reserved = inner.reserved;
        let waiting_senders = inner.send_wakers.len();
        let capacity = sender.shared.capacity;
        let available = capacity.saturating_sub(queued + reserved);
        (queued, reserved, available, waiting_senders)
    }

    /// MR1: Capacity Conservation
    ///
    /// Invariant: total_capacity = queued + reserved + available
    /// This must hold at all times regardless of backpressure state.
    #[test]
    fn mr1_capacity_conservation_invariant() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let _cx = crate::cx::Cx::for_testing();
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {
                        let (sender, mut receiver) = channel::<u32>(config.capacity);

                        // Baseline: empty channel should conserve capacity
                        let (queued, reserved, available, _) = observe_channel_state(&sender);
                        assert_eq!(
                            queued + reserved + available,
                            config.capacity,
                            "Empty channel capacity conservation failed"
                        );

                        // Fill channel progressively and verify conservation at each step
                        let mut sent_count = 0;
                        let target_fills = std::cmp::min(config.capacity * 2, 50);

                        for i in 0..target_fills {
                            // Try to send
                            match sender.try_send(i as u32) {
                                Ok(()) => {
                                    sent_count += 1;
                                }
                                Err(SendError::Full(_)) => {
                                    // Channel full - capacity should still be conserved
                                }
                                _ => panic!("Unexpected send error"),
                            }

                            let (queued, reserved, available, _) = observe_channel_state(&sender);
                            assert_eq!(
                                queued + reserved + available,
                                config.capacity,
                                "Capacity conservation failed at step {} (sent: {})",
                                i,
                                sent_count
                            );

                            // Occasionally receive to create capacity
                            if i % 3 == 0 && queued > 0 {
                                let _ = receiver.try_recv();
                                let (queued_after, reserved_after, available_after, _) =
                                    observe_channel_state(&sender);
                                assert_eq!(
                                    queued_after + reserved_after + available_after,
                                    config.capacity,
                                    "Capacity conservation failed after recv at step {}",
                                    i
                                );
                            }
                        }

                        Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// MR2: FIFO Ordering Preservation
    ///
    /// Property: Messages received in same order as sent, regardless of backpressure.
    /// Even with blocking, eviction, or cancellation, FIFO ordering must be preserved.
    #[test]
    fn mr2_fifo_ordering_preservation() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let cx = crate::cx::Cx::for_testing();
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {
            let (sender, mut receiver) = channel::<u32>(config.capacity);
            let sent_messages = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let received_messages = Arc::new(parking_lot::Mutex::new(Vec::new()));

            // Single sender to ensure clear ordering
            let sent_ref = Arc::clone(&sent_messages);
            let send_cx = cx.clone();
            let send_handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                for i in 0..config.messages_per_sender {
                    let value = i as u32;
                    match sender.send(&send_cx, value).await {
                        Ok(()) => {
                            sent_ref.lock().push(value);
                        },
                        Err(SendError::Disconnected(_)) => break,
                        Err(_) => {}, // Other errors don't affect ordering
                    }
                }
                })});

            // Receiver collects all messages
            let recv_ref = Arc::clone(&received_messages);
            let recv_cx = cx.clone();
            let recv_handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                loop {
                    match receiver.recv(&recv_cx).await {
                        Ok(value) => {
                            recv_ref.lock().push(value);
                        },
                        Err(RecvError::Disconnected) => break,
                        Err(_) => {},
                    }
                }
                })});

            send_handle.join().unwrap();
            recv_handle.join().unwrap();

            // Compare ordering
            let sent = sent_messages.lock().clone();
            let received = received_messages.lock().clone();

            // Received messages must be a prefix of sent messages in same order
            let min_len = std::cmp::min(sent.len(), received.len());
            for i in 0..min_len {
                assert_eq!(
                    sent[i], received[i],
                    "FIFO ordering violated at position {} (sent: {:?}, received: {:?})",
                    i, &sent[0..min_len], received
                );
            }

            Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// MR3: Reserve-Send Equivalence
    ///
    /// Property: reserve().await.send(value) ≃ send(value).await when capacity available.
    /// Both paths should have identical observable effects.
    #[test]
    fn mr3_reserve_send_equivalence() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let cx = crate::cx::Cx::for_testing();
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {
                        // Path 1: reserve then send
                        let (sender1, mut receiver1) = channel::<u32>(config.capacity);
                        let received1 = Arc::new(parking_lot::Mutex::new(Vec::new()));

                        let recv1_ref = Arc::clone(&received1);
                        let recv1_cx = cx.clone();
                        let recv1_handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                            while let Ok(value) = receiver1.recv(&recv1_cx).await {
                                recv1_ref.lock().push(value);
                            }
                })});

                        // Send via reserve/send
                        for i in 0..std::cmp::min(config.messages_per_sender, config.capacity) {
                            if let Ok(permit) = sender1.try_reserve() {
                                permit.send(i as u32);
                            }
                        }
                        drop(sender1);
                        recv1_handle.join().unwrap();

                        // Path 2: direct send
                        let (sender2, mut receiver2) = channel::<u32>(config.capacity);
                        let received2 = Arc::new(parking_lot::Mutex::new(Vec::new()));

                        let recv2_ref = Arc::clone(&received2);
                        let recv2_cx = cx.clone();
                        let recv2_handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                            while let Ok(value) = receiver2.recv(&recv2_cx).await {
                                recv2_ref.lock().push(value);
                            }
                })});

                        // Send via try_send
                        for i in 0..std::cmp::min(config.messages_per_sender, config.capacity) {
                            let _ = sender2.try_send(i as u32);
                        }
                        drop(sender2);
                        recv2_handle.join().unwrap();

                        // Results should be equivalent
                        let result1 = received1.lock().clone();
                        let result2 = received2.lock().clone();

                        assert_eq!(
                            result1, result2,
                            "Reserve-send vs direct send produced different results: {:?} vs {:?}",
                            result1, result2
                        );

                        Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// MR4: Cancellation Idempotence
    ///
    /// Property: Cancelling during reserve doesn't leak capacity.
    /// Capacity conservation must hold even with cancellation.
    #[test]
    fn mr4_cancellation_idempotence() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                if !config.inject_cancellation || config.cancel_probability < 0.1 {
                    return Ok(()); // Skip if cancellation not meaningful
                }

                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab
                        .state
                        .create_task(root, Budget::INFINITE, async move {
                            let cx = crate::cx::Cx::for_testing();
                            let _test_res: Result<(), proptest::test_runner::TestCaseError> =
                                async {
                                    let (sender, mut receiver) = channel::<u32>(config.capacity);

                                    // Fill channel to force reserves to block
                                    for i in 0..config.capacity {
                                        sender.try_send(i as u32).expect("Fill channel");
                                    }

                                    let initial_state = observe_channel_state(&sender);

                                    // Create multiple reserves that will block
                                    let cancelled_count = Arc::new(AtomicUsize::new(0));
                                    let mut reserve_handles = Vec::new();
                                    for i in 0..config.sender_count {
                                        let sender_clone = sender.clone();
                                        let cancelled_clone = Arc::clone(&cancelled_count);
                                        let reserve_cx = cx.clone();
                                        let handle = std::thread::spawn(move || {
                                            futures_lite::future::block_on(async move {
                                                match sender_clone.reserve(&reserve_cx).await {
                                                    Err(SendError::Cancelled(_)) => {
                                                        cancelled_clone.fetch_add(1, Ordering::SeqCst);
                                                    }
                                                    Ok(permit) => {
                                                        permit.send(i as u32);
                                                    }
                                                    Err(other) => {
                                                        panic!(
                                                            "reserve observed unexpected outcome after cancellation: {other:?}"
                                                        );
                                                    }
                                                }
                                            })
                                        });
                                        reserve_handles.push(handle);
                                    }

                                    // Reserve futures observe cancellation via the shared Cx, but
                                    // blocked senders need one capacity transition to be re-polled.
                                    cx.set_cancel_reason(CancelReason::user("test cancellation"));
                                    let _ = receiver.try_recv();

                                    // Collect results
                                    for handle in reserve_handles {
                                        handle.join().unwrap();
                                    }

                                    let final_state = observe_channel_state(&sender);

                                    // Capacity conservation must hold despite cancellation
                                    assert_eq!(
                                        initial_state.0 + initial_state.1 + initial_state.2,
                                        final_state.0 + final_state.1 + final_state.2,
                                        "Cancellation leaked capacity: initial {:?} vs final {:?}",
                                        initial_state,
                                        final_state
                                    );
                                    assert!(
                                        cancelled_count.load(Ordering::SeqCst) > 0,
                                        "cancellation MR failed to observe any cancelled reserves"
                                    );

                                    Ok(())
                                }
                                .await;
                        })
                        .unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// MR5: Eviction Policy Correctness
    ///
    /// Property: send_evict_oldest removes oldest message while preserving FIFO for remaining.
    #[test]
    fn mr5_eviction_policy_correctness() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                if !config.use_eviction || config.capacity < 2 {
                    return Ok(()); // Skip if eviction not meaningful
                }

                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let _cx = crate::cx::Cx::for_testing();
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {
                        let (sender, mut receiver) = channel::<u32>(config.capacity);

                        // Fill channel completely
                        for i in 0..config.capacity {
                            sender.try_send(i as u32).expect("Fill channel");
                        }

                        // Record initial queue state
                        let initial_messages: Vec<u32> =
                            (0..config.capacity).map(|i| i as u32).collect();

                        // Evict oldest with new message
                        let new_value = 999u32;
                        match sender.send_evict_oldest(new_value) {
                            Ok(Some(evicted)) => {
                                assert_eq!(evicted, 0u32, "Oldest message should be evicted");
                            }
                            Ok(None) => panic!("Expected eviction but none occurred"),
                            Err(_) => panic!("Eviction failed unexpectedly"),
                        }

                        // Receive all and verify order
                        let mut received = Vec::new();
                        while let Ok(value) = receiver.try_recv() {
                            received.push(value);
                        }

                        // Expected: [1, 2, ..., capacity-1, 999]
                        let mut expected = initial_messages[1..].to_vec();
                        expected.push(new_value);

                        assert_eq!(
                            received, expected,
                            "Eviction didn't preserve FIFO order: got {:?}, expected {:?}",
                            received, expected
                        );

                        Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// MR6: Receiver Drain Correctness
    ///
    /// Property: Dropping receiver unblocks all pending sends with Disconnected.
    #[test]
    fn mr6_receiver_drain_correctness() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab
                        .state
                        .create_task(root, Budget::INFINITE, async move {
                            let cx = crate::cx::Cx::for_testing();
                            let _test_res: Result<(), proptest::test_runner::TestCaseError> =
                                async {
                                    let (sender, receiver) = channel::<u32>(config.capacity);

                                    // Fill channel
                                    for i in 0..config.capacity {
                                        sender.try_send(i as u32).expect("Fill channel");
                                    }

                                    // Start multiple blocking reserves
                                    let disconnected_count = Arc::new(AtomicUsize::new(0));
                                    let mut reserve_handles = Vec::new();

                                    for _i in 0..config.sender_count {
                                        let sender_clone = sender.clone();
                                        let counter_clone = Arc::clone(&disconnected_count);
                                        let reserve_cx = cx.clone();
                                        let handle = std::thread::spawn(move || {
                                            futures_lite::future::block_on(async move {
                                                match sender_clone.reserve(&reserve_cx).await {
                                                    Err(SendError::Disconnected(_)) => {
                                                        counter_clone
                                                            .fetch_add(1, Ordering::SeqCst);
                                                    }
                                                    _ => {}
                                                }
                                            })
                                        });
                                        reserve_handles.push(handle);
                                    }

                                    // Let reserves queue up
                                    crate::runtime::yield_now().await;

                                    // Verify reserves are queued
                                    let queued_before = observe_channel_state(&sender).3;
                                    assert!(queued_before > 0, "No reserves queued");

                                    // Drop receiver - should unblock all pending reserves
                                    drop(receiver);

                                    // Wait for all reserves to complete
                                    for handle in reserve_handles {
                                        handle.join().unwrap();
                                    }

                                    // All queued senders should have been disconnected
                                    let disconnected = disconnected_count.load(Ordering::SeqCst);
                                    assert!(
                                        disconnected > 0,
                                        "No senders received Disconnected after receiver drop"
                                    );

                                    // No waiters should remain
                                    let queued_after = observe_channel_state(&sender).3;
                                    assert_eq!(
                                        queued_after, 0,
                                        "Waiters remain queued after receiver drop: {}",
                                        queued_after
                                    );

                                    Ok(())
                                }
                                .await;
                        })
                        .unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }

    /// Composite metamorphic test: All relations together
    ///
    /// Tests multiple properties in combination to catch interaction bugs.
    #[test]
    fn composite_backpressure_properties() {
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::default();
        runner
            .run(&backpressure_config_strategy(), |config| {
                crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let cx = crate::cx::Cx::for_testing();
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {
                        let (sender, mut receiver) = channel::<u32>(config.capacity);
                        let received_messages = Arc::new(parking_lot::Mutex::new(Vec::new()));
                        let sent_messages = Arc::new(parking_lot::Mutex::new(Vec::new()));

                        // MR1 + MR2: Capacity conservation + FIFO under mixed load
                        let recv_ref = Arc::clone(&received_messages);
                        let recv_cx = cx.clone();
                        let recv_handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                            while let Ok(value) = receiver.recv(&recv_cx).await {
                                recv_ref.lock().push(value);
                            }
                })});

                        // Multiple senders with different patterns
                        let mut send_handles = Vec::new();
                        for sender_id in 0..config.sender_count {
                            let sender_clone = sender.clone();
                            let sent_ref = Arc::clone(&sent_messages);
                            let send_cx = cx.clone();
                            let handle = std::thread::spawn(move || {
                    futures_lite::future::block_on(async move {
                                for i in 0..config.messages_per_sender {
                                    let value = (sender_id * 1000 + i) as u32;
                                    match sender_clone.send(&send_cx, value).await {
                                        Ok(()) => {
                                            sent_ref.lock().push((sender_id, value));
                                        }
                                        Err(_) => break,
                                    }

                                    // MR1: Check capacity conservation
                                    let (queued, reserved, available, _) =
                                        observe_channel_state(&sender_clone);
                                    assert_eq!(
                                        queued + reserved + available,
                                        config.capacity,
                                        "Capacity conservation violated during concurrent sends"
                                    );
                                }
                })});
                            send_handles.push(handle);
                        }

                        // Complete all sends
                        for handle in send_handles {
                            handle.join().unwrap();
                        }
                        drop(sender);

                        recv_handle.join().unwrap();

                        // MR2: Verify ordering within each sender
                        let sent = sent_messages.lock().clone();
                        let received = received_messages.lock().clone();

                        // Group by sender and verify each sender's messages are in order
                        let mut sender_sequences: HashMap<usize, Vec<u32>> = HashMap::new();
                        for (sender_id, value) in sent {
                            sender_sequences
                                .entry(sender_id)
                                .or_insert_with(Vec::new)
                                .push(value);
                        }

                        for value in received {
                            if let Some(sender_id) = value.checked_div(1000) {
                                if let Some(sequence) =
                                    sender_sequences.get_mut(&(sender_id as usize))
                                {
                                    if let Some(expected) = sequence.first() {
                                        assert_eq!(
                                            value, *expected,
                                            "FIFO violation for sender {}: expected {}, got {}",
                                            sender_id, expected, value
                                        );
                                        sequence.remove(0);
                                    }
                                }
                            }
                        }

                        Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    let _ = lab.run_until_quiescent_with_report();
                });
                Ok(())
            })
            .expect("Property test failed");
    }
}
