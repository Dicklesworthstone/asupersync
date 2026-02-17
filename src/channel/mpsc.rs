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

use smallvec::SmallVec;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;

#[inline]
fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

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
    /// Maximum capacity of the queue.
    capacity: usize,
    /// Number of reserved slots (permits outstanding).
    reserved: usize,
    /// Whether the receiver has been dropped.
    receiver_dropped: bool,
    /// Number of active senders.
    sender_count: usize,
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
}

impl<T: std::fmt::Debug> std::fmt::Debug for ChannelShared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelShared")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<T> ChannelInner<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            reserved: 0,
            receiver_dropped: false,
            sender_count: 1,
            send_wakers: VecDeque::new(),
            recv_waker: None,
            next_waiter_id: 0,
        }
    }

    /// Returns the number of used slots (queued + reserved).
    fn used_slots(&self) -> usize {
        self.queue.len() + self.reserved
    }

    /// Returns true if there's capacity for another reservation.
    fn has_capacity(&self) -> bool {
        self.used_slots() < self.capacity
    }

    /// Returns true if the channel is closed (all senders dropped).
    fn is_closed(&self) -> bool {
        self.sender_count == 0
    }

    /// Returns the waker for the next waiting sender, if any.
    /// The caller must invoke `waker.wake()` **after** releasing the channel
    /// lock to avoid wake-under-lock deadlocks.
    ///
    /// This does NOT remove the waiter from the queue. The waiter is responsible
    /// for removing itself upon successfully acquiring a permit.
    fn take_next_sender_waker(&self) -> Option<Waker> {
        self.send_wakers.front().map(|waiter| waiter.waker.clone())
    }
}

/// Creates a bounded MPSC channel with the given capacity.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "channel capacity must be non-zero");

    let shared = Arc::new(ChannelShared {
        inner: Mutex::new(ChannelInner::new(capacity)),
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
    #[must_use]
    pub fn reserve<'a>(&'a self, cx: &'a Cx) -> Reserve<'a, T> {
        Reserve {
            sender: self,
            cx,
            waiter_id: None,
        }
    }

    /// Convenience method: reserve and send in one step.
    pub async fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.reserve(cx).await {
            Ok(permit) => {
                permit.send(value);
                Ok(())
            }
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::Full(())) => Err(SendError::Full(value)),
            Err(SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
        }
    }

    /// Attempts to reserve a slot without blocking.
    ///
    /// Returns `Full` when waiting senders exist, to preserve FIFO ordering.
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        if inner.receiver_dropped {
            return Err(SendError::Disconnected(()));
        }

        if !inner.send_wakers.is_empty() {
            return Err(SendError::Full(()));
        }

        if inner.has_capacity() {
            inner.reserved += 1;
            drop(inner);
            Ok(SendPermit {
                sender: self,
                sent: false,
            })
        } else {
            Err(SendError::Full(()))
        }
    }

    /// Attempts to send a value without blocking.
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        match self.try_reserve() {
            Ok(permit) => {
                permit.send(value);
                Ok(())
            }
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::Full(())) => Err(SendError::Full(value)),
            Err(SendError::Cancelled(())) => unreachable!(),
        }
    }

    /// Returns true if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .receiver_dropped
    }

    /// Wakes the receiver if it is currently waiting in `recv()`.
    ///
    /// This does not enqueue a message. It's intended for out-of-band protocols
    /// (like cancellation) that need to interrupt a blocked receiver.
    pub fn wake_receiver(&self) {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
        let waker = inner.recv_waker.take();
        drop(inner);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Returns the channel's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .capacity
    }

    /// Sends a value, evicting the oldest queued message if the channel is full.
    ///
    /// Returns `Ok(None)` if the value was sent without eviction,
    /// `Ok(Some(evicted))` if the oldest message was evicted to make room,
    /// `Err(SendError::Full(value))` if all capacity is consumed by reserved
    /// slots and there is nothing to evict, or
    /// `Err(SendError::Disconnected(value))` if the receiver has dropped.
    ///
    /// This is used by the `DropOldest` backpressure policy. The evicted
    /// message is returned so callers can trace or log the drop.
    pub fn send_evict_oldest(&self, value: T) -> Result<Option<T>, SendError<T>> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        if inner.receiver_dropped {
            return Err(SendError::Disconnected(value));
        }

        let evicted = if inner.has_capacity() {
            None
        } else if let Some(oldest) = inner.queue.pop_front() {
            // Evict the oldest committed message (not a reserved slot).
            Some(oldest)
        } else {
            // All capacity consumed by reserved slots — nothing to evict.
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

impl<'a, T> Future for Reserve<'a, T> {
    type Output = Result<SendPermit<'a, T>, SendError<()>>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // Check cancellation
        if self.cx.checkpoint().is_err() {
            self.cx.trace("mpsc::reserve cancelled");
            return Poll::Ready(Err(SendError::Cancelled(())));
        }

        let mut inner = self
            .sender
            .shared
            .inner
            .lock()
            .expect("channel lock poisoned");

        if inner.receiver_dropped {
            return Poll::Ready(Err(SendError::Disconnected(())));
        }

        if inner.has_capacity() {
            inner.reserved += 1;
            // Remove self from queue
            if let Some(id) = self.waiter_id {
                let is_head = inner.send_wakers.front().is_some_and(|w| w.id == id);

                if is_head {
                    inner.send_wakers.pop_front();
                } else {
                    inner.send_wakers.retain(|w| w.id != id);
                }

                // CASCADE: If there is still capacity, wake the *next* waiter.
                // Extract waker now; wake after releasing the lock.
                let cascade_waker = if inner.has_capacity() {
                    inner.take_next_sender_waker()
                } else {
                    None
                };
                drop(inner);
                if let Some(w) = cascade_waker {
                    w.wake();
                }
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
            inner.next_waiter_id += 1;
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
        // If we have a waiter, we need to remove it from the sender's queue.
        if let Some(id) = self.waiter_id {
            let next_waker = {
                let mut inner = lock_recover(&self.sender.shared.inner);

                // Remove ourselves by id.
                let is_head = inner.send_wakers.front().is_some_and(|w| w.id == id);

                if is_head {
                    inner.send_wakers.pop_front();
                } else {
                    inner.send_wakers.retain(|w| w.id != id);
                }

                // Propagate wake if we were blocking capacity.
                if inner.has_capacity() {
                    inner.take_next_sender_waker()
                } else {
                    None
                }
            };
            // Wake outside the lock.
            if let Some(w) = next_waker {
                w.wake();
            }
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        {
            let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
            inner.sender_count += 1;
        }
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let recv_waker = {
            let mut inner = lock_recover(&self.shared.inner);
            if inner.sender_count == 0 {
                debug_assert!(false, "sender_count underflow in Sender::drop");
            } else {
                inner.sender_count -= 1;
            }
            if inner.sender_count == 0 {
                inner.recv_waker.take()
            } else {
                None
            }
        };
        // Wake receiver outside the lock to avoid wake-under-lock deadlocks.
        if let Some(waker) = recv_waker {
            waker.wake();
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
    #[must_use]
    pub fn upgrade(&self) -> Option<Sender<T>> {
        self.shared.upgrade().and_then(|shared| {
            {
                let mut guard = shared.inner.lock().expect("channel lock poisoned");
                if guard.sender_count == 0 {
                    return None;
                }
                guard.sender_count += 1;
            }
            Some(Sender { shared })
        })
    }
}

impl<T> Clone for WeakSender<T> {
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
    pub fn send(mut self, value: T) {
        self.sent = true;
        let mut inner = self
            .sender
            .shared
            .inner
            .lock()
            .expect("channel lock poisoned");

        if inner.reserved == 0 {
            debug_assert!(false, "send permit without reservation");
        } else {
            inner.reserved -= 1;
        }

        if inner.receiver_dropped {
            // Receiver is gone; drop the value and release capacity.
            // Collect wakers before dropping the lock to avoid wake-under-lock.
            if inner.send_wakers.is_empty() {
                drop(inner);
                return;
            }
            let wakers: SmallVec<[Waker; 4]> = inner
                .send_wakers
                .drain(..)
                .map(|waiter| waiter.waker)
                .collect();
            drop(inner);
            for waker in wakers {
                waker.wake();
            }
            return;
        }

        inner.queue.push_back(value);

        // Extract waker before dropping the lock to avoid wake-under-lock.
        let recv_waker = inner.recv_waker.take();
        drop(inner);
        if let Some(waker) = recv_waker {
            waker.wake();
        }
    }

    /// Aborts the reserved slot without sending.
    pub fn abort(mut self) {
        self.sent = true;
        let next_waker = {
            let mut inner = self
                .sender
                .shared
                .inner
                .lock()
                .expect("channel lock poisoned");
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
                let mut inner = lock_recover(&self.sender.shared.inner);
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
    /// Creates a receive future for the next value.
    #[must_use]
    pub fn recv<'a>(&'a self, cx: &'a Cx) -> Recv<'a, T> {
        Recv { receiver: self, cx }
    }

    /// Attempts to receive a value without blocking.
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        match inner.queue.pop_front() {
            Some(value) => {
                let next_waker = inner.take_next_sender_waker();
                drop(inner);
                if let Some(w) = next_waker {
                    w.wake();
                }
                Ok(value)
            }
            None => {
                if inner.is_closed() {
                    Err(RecvError::Disconnected)
                } else {
                    Err(RecvError::Empty)
                }
            }
        }
    }

    /// Returns true if all senders have been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .is_closed()
    }

    /// Returns true if there are any queued messages.
    #[must_use]
    pub fn has_messages(&self) -> bool {
        !self
            .shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .is_empty()
    }

    /// Returns the number of queued messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .len()
    }

    /// Returns true if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .is_empty()
    }

    /// Returns the channel capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .capacity
    }
}

/// Future returned by [`Receiver::recv`].
pub struct Recv<'a, T> {
    receiver: &'a Receiver<T>,
    cx: &'a Cx,
}

impl<T> Future for Recv<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            self.cx.trace("mpsc::recv cancelled");
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        let mut inner = self
            .receiver
            .shared
            .inner
            .lock()
            .expect("channel lock poisoned");

        if let Some(value) = inner.queue.pop_front() {
            let next_waker = inner.take_next_sender_waker();
            drop(inner);
            if let Some(w) = next_waker {
                w.wake();
            }
            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            return Poll::Ready(Err(RecvError::Disconnected));
        }

        // Skip waker clone if unchanged — common on re-poll.
        match &inner.recv_waker {
            Some(existing) if existing.will_wake(ctx.waker()) => {}
            _ => inner.recv_waker = Some(ctx.waker().clone()),
        }
        Poll::Pending
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let wakers: SmallVec<[Waker; 4]> = {
            let mut inner = lock_recover(&self.shared.inner);
            inner.receiver_dropped = true;
            // Drain queued items to prevent memory leaks when senders are
            // long-lived (they hold Arc refs that keep the queue alive).
            inner.queue.clear();
            inner
                .send_wakers
                .drain(..)
                .map(|waiter| waiter.waker)
                .collect()
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
    use std::sync::atomic::{AtomicBool, Ordering};

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
        let (tx, rx) = channel::<i32>(10);

        block_on(tx.send(&cx, 42)).expect("send failed");
        let value = block_on(rx.recv(&cx)).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn fifo_ordering_single_sender() {
        init_test("fifo_ordering_single_sender");
        let cx = test_cx();
        let (tx, rx) = channel::<usize>(128);

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
        let (tx, rx) = channel::<i32>(1);

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
        let (tx, rx) = channel::<i32>(10);

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
            matches!(try_reserve, Err(SendError::Full(()))),
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
        let (tx, rx) = channel::<i32>(10);

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
        let (tx, rx) = channel::<i32>(10);
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
        let (tx1, rx) = channel::<i32>(10);
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

    fn recover_lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn reserve_cancelled_returns_error() {
        init_test("reserve_cancelled_returns_error");
        let (tx, _rx) = channel::<i32>(1);
        let cx = cancelled_cx();
        let result = block_on(tx.reserve(&cx));
        crate::assert_with_log!(
            matches!(result, Err(SendError::Cancelled(()))),
            "reserve cancelled",
            "Err(Cancelled(()))",
            format!("{:?}", result)
        );
        crate::test_complete!("reserve_cancelled_returns_error");
    }

    #[test]
    fn recv_cancelled_returns_error() {
        init_test("recv_cancelled_returns_error");
        let (_tx, rx) = channel::<i32>(1);
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
        let (tx, rx) = channel::<i32>(1);
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
        let (tx, rx) = channel::<i32>(1);
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

        let try_reserve = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_reserve, Err(SendError::Full(()))),
            "try_reserve full due to waiter",
            "Err(Full(()))",
            format!("{:?}", try_reserve)
        );

        drop(reserve_fut);
        permit.abort();
        crate::test_complete!("try_reserve_full_when_waiter_queued");
    }

    #[test]
    fn try_recv_disconnected_when_closed_and_empty() {
        init_test("try_recv_disconnected_when_closed_and_empty");
        let (tx, rx) = channel::<i32>(1);
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
            let inner = tx.shared.inner.lock().expect("channel lock poisoned");
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
            let inner = tx.shared.inner.lock().expect("lock");
            let used = inner.used_slots();
            let cap = inner.capacity;
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
            let inner = tx.shared.inner.lock().expect("lock");
            let used = inner.used_slots();
            let cap = inner.capacity;
            let qlen = inner.queue.len();
            drop(inner);
            crate::assert_with_log!(used <= cap, "capacity after eviction", true, used <= cap);
            crate::assert_with_log!(qlen == 1, "queue len after eviction", 1, qlen);
        }

        permit.abort();
        crate::test_complete!("send_evict_oldest_evicts_committed_not_reserved");
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
            let inner = tx.shared.inner.lock().expect("lock");
            let qlen = inner.queue.len();
            drop(inner);
            qlen
        };
        crate::assert_with_log!(qlen == 1, "queue len", 1, qlen);
        crate::test_complete!("send_evict_oldest_no_eviction_with_capacity");
    }

    #[test]
    fn sender_drop_on_poisoned_mutex_does_not_panic() {
        // Regression: Sender::Drop must not double-panic if the channel mutex
        // is poisoned (e.g., during stack unwinding from another panic).
        init_test("sender_drop_on_poisoned_mutex_does_not_panic");
        let (tx, _rx) = channel::<i32>(1);

        // Poison the mutex by panicking while holding it.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        // Sender::Drop must not panic even though the mutex is poisoned.
        drop(tx);
        crate::test_complete!("sender_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn sender_drop_on_poisoned_mutex_still_updates_sender_count() {
        init_test("sender_drop_on_poisoned_mutex_still_updates_sender_count");
        let (tx, rx) = channel::<i32>(1);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        drop(tx);

        let sender_count = {
            let inner = recover_lock(&rx.shared.inner);
            inner.sender_count
        };
        crate::assert_with_log!(sender_count == 0, "sender count cleared", 0, sender_count);
        crate::test_complete!("sender_drop_on_poisoned_mutex_still_updates_sender_count");
    }

    #[test]
    fn receiver_drop_on_poisoned_mutex_does_not_panic() {
        // Regression: Receiver::Drop must not double-panic if the channel mutex
        // is poisoned.
        init_test("receiver_drop_on_poisoned_mutex_does_not_panic");
        let (_tx, rx) = channel::<i32>(1);

        // Poison the mutex.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = rx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        drop(rx);
        crate::test_complete!("receiver_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn receiver_drop_on_poisoned_mutex_still_marks_closed() {
        init_test("receiver_drop_on_poisoned_mutex_still_marks_closed");
        let (tx, rx) = channel::<i32>(2);
        let cx = test_cx();
        block_on(tx.send(&cx, 1)).expect("send");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = rx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        drop(rx);

        let (receiver_dropped, queue_len) = {
            let inner = recover_lock(&tx.shared.inner);
            (inner.receiver_dropped, inner.queue.len())
        };
        crate::assert_with_log!(
            receiver_dropped,
            "receiver dropped flag set",
            true,
            receiver_dropped
        );
        crate::assert_with_log!(queue_len == 0, "queue cleared", 0, queue_len);
        crate::test_complete!("receiver_drop_on_poisoned_mutex_still_marks_closed");
    }

    #[test]
    fn reserve_future_drop_on_poisoned_mutex_does_not_panic() {
        // Regression: Reserve future's Drop must not double-panic if the
        // channel mutex is poisoned while the future is pending.
        init_test("reserve_future_drop_on_poisoned_mutex_does_not_panic");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        // Fill the channel so reserve will pend and register a waiter.
        let _permit = block_on(tx.reserve(&cx)).expect("reserve");

        let mut reserve_fut = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);
        let poll = reserve_fut.as_mut().poll(&mut cx_task);
        assert!(matches!(poll, Poll::Pending));

        // Poison the mutex.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        // Dropping the pending Reserve future must not panic.
        drop(reserve_fut);
        crate::test_complete!("reserve_future_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn reserve_future_drop_on_poisoned_mutex_still_removes_waiter() {
        init_test("reserve_future_drop_on_poisoned_mutex_still_removes_waiter");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve");

        let mut reserve_fut = Box::pin(tx.reserve(&cx));
        let waker = noop_waker();
        let mut cx_task = Context::from_waker(&waker);
        let poll = reserve_fut.as_mut().poll(&mut cx_task);
        assert!(matches!(poll, Poll::Pending));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        drop(reserve_fut);

        let queued_waiters = {
            let inner = recover_lock(&tx.shared.inner);
            inner.send_wakers.len()
        };
        crate::assert_with_log!(
            queued_waiters == 0,
            "poisoned reserve drop removes waiter",
            0,
            queued_waiters
        );

        drop(permit);
        crate::test_complete!("reserve_future_drop_on_poisoned_mutex_still_removes_waiter");
    }

    #[test]
    fn send_permit_drop_on_poisoned_mutex_does_not_panic() {
        // Regression: SendPermit::Drop must not double-panic if the channel
        // mutex is poisoned while the permit is outstanding.
        init_test("send_permit_drop_on_poisoned_mutex_does_not_panic");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve");

        // Poison the mutex.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        // Dropping the permit must not panic.
        drop(permit);
        crate::test_complete!("send_permit_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn send_permit_drop_on_poisoned_mutex_still_releases_capacity() {
        init_test("send_permit_drop_on_poisoned_mutex_still_releases_capacity");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        let permit = block_on(tx.reserve(&cx)).expect("reserve");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.shared.inner.lock().expect("lock");
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        drop(permit);

        let reserved = {
            let inner = recover_lock(&tx.shared.inner);
            inner.reserved
        };
        crate::assert_with_log!(
            reserved == 0,
            "poisoned permit drop clears reservation",
            0,
            reserved
        );

        crate::test_complete!("send_permit_drop_on_poisoned_mutex_still_releases_capacity");
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn send_evict_oldest_wakes_receiver() {
        // Verify send_evict_oldest wakes a pending receiver.
        init_test("send_evict_oldest_wakes_receiver");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(2);

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
        let (tx, rx) = channel::<i32>(3);

        // Reserve 2 slots.
        let p1 = block_on(tx.reserve(&cx)).expect("reserve 1");
        let p2 = block_on(tx.reserve(&cx)).expect("reserve 2");

        // Check: reserved=2, queue=0, used=2
        let used = {
            let inner = tx.shared.inner.lock().expect("lock");
            inner.used_slots()
        };
        crate::assert_with_log!(used == 2, "used after 2 reserves", 2, used);

        // Commit one, abort one.
        p1.send(10);
        p2.abort();

        // Check: reserved=0, queue=1, used=1
        let (used, reserved) = {
            let inner = tx.shared.inner.lock().expect("lock");
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
            matches!(try_result, Err(SendError::Full(()))),
            "try_reserve respects FIFO",
            "Err(Full)",
            format!("{:?}", try_result)
        );

        // The queued waiter should succeed on next poll.
        let poll2 = reserve_fut.as_mut().poll(&mut cx_task);
        let ready = matches!(poll2, Poll::Ready(Ok(_)));
        crate::assert_with_log!(ready, "waiter acquires", true, ready);

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
}
