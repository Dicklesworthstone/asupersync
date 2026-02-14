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

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
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

/// Shared state between the future and the wait queue.
#[derive(Debug)]
struct SharedWaiter {
    waker: Mutex<Waker>,
    queued: AtomicBool,
}

/// A queued waiter for channel capacity.
#[derive(Debug)]
struct SendWaiter {
    shared: Arc<SharedWaiter>,
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

    /// Wakes the next waiting sender, if any.
    ///
    /// This does NOT remove the waiter from the queue. The waiter is responsible
    /// for removing itself upon successfully acquiring a permit.
    fn wake_next_sender(&self) {
        if let Some(waiter) = self.send_wakers.front() {
            waiter.shared.queued.store(false, Ordering::Release);
            let waker = waiter.shared.waker.lock().expect("waiter lock poisoned");
            waker.wake_by_ref();
        }
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
            waiter: None,
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
    /// or `Err(SendError::Disconnected(value))` if the receiver has dropped.
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
        } else {
            // Evict the oldest committed message (not a reserved slot).
            inner.queue.pop_front()
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
    waiter: Option<Arc<SharedWaiter>>,
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
            if let Some(waiter) = self.waiter.as_ref() {
                let is_head = inner
                    .send_wakers
                    .front()
                    .is_some_and(|w| Arc::ptr_eq(&w.shared, waiter));

                if is_head {
                    inner.send_wakers.pop_front();
                } else {
                    inner
                        .send_wakers
                        .retain(|w| !Arc::ptr_eq(&w.shared, waiter));
                }

                // CASCADE: If there is still capacity, wake the *next* waiter.
                if inner.has_capacity() {
                    inner.wake_next_sender();
                }
            }

            return Poll::Ready(Ok(SendPermit {
                sender: self.sender,
                sent: false,
            }));
        }

        // Register/update waiter
        if let Some(waiter) = self.waiter.as_ref() {
            // Already queued. Update waker.
            if let Ok(mut waker_guard) = waiter.waker.lock() {
                if !waker_guard.will_wake(ctx.waker()) {
                    waker_guard.clone_from(ctx.waker());
                }
            }
            waiter.queued.store(true, Ordering::Release);
        } else {
            // New waiter
            let waiter = Arc::new(SharedWaiter {
                waker: Mutex::new(ctx.waker().clone()),
                queued: AtomicBool::new(true),
            });
            inner.send_wakers.push_back(SendWaiter {
                shared: Arc::clone(&waiter),
            });
            self.waiter = Some(waiter);
        }

        drop(inner);
        Poll::Pending
    }
}

impl<T> Drop for Reserve<'_, T> {
    fn drop(&mut self) {
        // If we have a waiter, we need to remove it from the sender's queue.
        if let Some(waiter) = self.waiter.as_ref() {
            let mut inner = self
                .sender
                .shared
                .inner
                .lock()
                .expect("channel lock poisoned");

            // We need to remove ourselves.
            let is_head = inner
                .send_wakers
                .front()
                .is_some_and(|w| Arc::ptr_eq(&w.shared, waiter));

            if is_head {
                inner.send_wakers.pop_front();
            } else {
                inner
                    .send_wakers
                    .retain(|w| !Arc::ptr_eq(&w.shared, waiter));
            }

            // Propagate wake if we were blocking capacity
            if inner.has_capacity() {
                inner.wake_next_sender();
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
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
        inner.sender_count -= 1;
        let all_senders_gone = inner.sender_count == 0;

        if all_senders_gone {
            if let Some(waker) = inner.recv_waker.take() {
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
            for waiter in inner.send_wakers.drain(..) {
                waiter.shared.queued.store(false, Ordering::Release);
                let waker = waiter.shared.waker.lock().expect("waiter lock poisoned");
                waker.wake_by_ref();
            }
            return;
        }

        inner.queue.push_back(value);

        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }

    /// Aborts the reserved slot without sending.
    pub fn abort(mut self) {
        self.sent = true;
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

        inner.wake_next_sender();
    }
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if !self.sent {
            let mut inner = self
                .sender
                .shared
                .inner
                .lock()
                .expect("channel lock poisoned");
            if inner.reserved == 0 {
                debug_assert!(false, "dropped permit without reservation");
            } else {
                inner.reserved -= 1;
            }

            inner.wake_next_sender();
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

        inner.queue.pop_front().map_or_else(
            || {
                if inner.is_closed() {
                    Err(RecvError::Disconnected)
                } else {
                    Err(RecvError::Empty)
                }
            },
            |value| {
                inner.wake_next_sender();
                Ok(value)
            },
        )
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
            inner.wake_next_sender();
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
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
        inner.receiver_dropped = true;
        // Drain queued items to prevent memory leaks when senders are
        // long-lived (they hold Arc refs that keep the queue alive).
        inner.queue.clear();
        for waiter in inner.send_wakers.drain(..) {
            waiter.shared.queued.store(false, Ordering::Release);
            let waker = waiter.shared.waker.lock().expect("waiter lock poisoned");
            waker.wake_by_ref();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

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
}
