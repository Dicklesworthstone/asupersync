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
    send_wakers: VecDeque<Waker>,
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
    pub fn reserve<'a>(&'a self, cx: &'a Cx) -> Reserve<'a, T> {
        Reserve { sender: self, cx }
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
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        if inner.receiver_dropped {
            return Err(SendError::Disconnected(()));
        }

        if inner.has_capacity() {
            inner.reserved += 1;
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

    /// Returns the channel's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .capacity
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
}

impl<'a, T> Future for Reserve<'a, T> {
    type Output = Result<SendPermit<'a, T>, SendError<()>>;

    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
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
            return Poll::Ready(Ok(SendPermit {
                sender: self.sender,
                sent: false,
            }));
        }

        // Register waker
        inner.send_wakers.push_back(ctx.waker().clone());
        Poll::Pending
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

        inner.reserved -= 1;
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
        inner.reserved -= 1;

        // Wake all waiting senders (simple strategy)
        for waker in inner.send_wakers.drain(..) {
            waker.wake();
        }
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
            inner.reserved -= 1;

            for waker in inner.send_wakers.drain(..) {
                waker.wake();
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
    pub fn recv<'a>(&'a self, cx: &'a Cx) -> Recv<'a, T> {
        Recv { receiver: self, cx }
    }

    /// Attempts to receive a value without blocking.
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        match inner.queue.pop_front() {
            Some(value) => {
                for waker in inner.send_wakers.drain(..) {
                    waker.wake();
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
    pub fn is_closed(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .is_closed()
    }

    /// Returns true if there are any queued messages.
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
    pub fn len(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .is_empty()
    }

    /// Returns the channel capacity.
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

impl<'a, T> Future for Recv<'a, T> {
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
            for waker in inner.send_wakers.drain(..) {
                waker.wake();
            }
            return Poll::Ready(Ok(value));
        }

        if inner.is_closed() {
            return Poll::Ready(Err(RecvError::Disconnected));
        }

        inner.recv_waker = Some(ctx.waker().clone());
        Poll::Pending
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
        inner.receiver_dropped = true;
        for waker in inner.send_wakers.drain(..) {
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
    use std::sync::Arc;

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
                Err(other) => panic!("unexpected recv error: {other:?}"),
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
}
