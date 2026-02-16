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
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Error returned when sending fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError<T> {
    /// There are no active receivers. The message is returned.
    Closed(T),
}

impl<T> std::fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(_) => write!(f, "sending on a closed broadcast channel"),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for SendError<T> {}

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
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lagged(n) => write!(f, "receiver lagged by {n} messages"),
            Self::Closed => write!(f, "broadcast channel closed"),
            Self::Cancelled => write!(f, "receive operation cancelled"),
        }
    }
}

impl std::error::Error for RecvError {}

/// Internal state shared between senders and receivers.
#[derive(Debug)]
struct Shared<T> {
    /// The ring buffer of messages.
    buffer: VecDeque<Slot<T>>,
    /// Maximum capacity of the buffer.
    capacity: usize,
    /// Total number of messages ever sent (for lag detection).
    total_sent: u64,
    /// Number of active receivers.
    receiver_count: usize,
    /// Number of active senders.
    sender_count: usize,
    /// Waiting receivers.
    wakers: Arena<Waker>,
}

#[derive(Debug)]
struct Slot<T> {
    msg: T,
    /// The cumulative index of this message.
    index: u64,
}

/// Shared wrapper.
struct Channel<T> {
    inner: Mutex<Shared<T>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Channel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

/// Creates a new broadcast channel with the given capacity.
///
/// # Panics
///
/// Panics if `capacity` is 0.
#[must_use]
pub fn channel<T: Clone>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "capacity must be non-zero");

    let shared = Arc::new(Channel {
        inner: Mutex::new(Shared {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            total_sent: 0,
            receiver_count: 1,
            sender_count: 1,
            wakers: Arena::new(),
        }),
    });

    let sender = Sender {
        channel: Arc::clone(&shared),
    };

    let receiver = Receiver {
        channel: shared,
        next_index: 0,
    };

    (sender, receiver)
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
    pub fn reserve(&self, cx: &Cx) -> Result<SendPermit<'_, T>, SendError<()>> {
        if cx.is_cancel_requested() {
            cx.trace("broadcast::reserve called with cancel pending");
        }

        {
            let inner = self.channel.inner.lock().expect("broadcast lock poisoned");
            if inner.receiver_count == 0 {
                return Err(SendError::Closed(()));
            }
        }

        Ok(SendPermit { sender: self })
    }

    /// Sends a message to all receivers.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed(msg)` if there are no active receivers when
    /// reservation is attempted.
    ///
    /// Returns `Ok(0)` if all receivers drop between reservation and commit.
    pub fn send(&self, cx: &Cx, msg: T) -> Result<usize, SendError<T>> {
        let permit = match self.reserve(cx) {
            Ok(p) => p,
            Err(SendError::Closed(())) => return Err(SendError::Closed(msg)),
        };
        Ok(permit.send(msg))
    }

    /// Creates a new receiver subscribed to this channel.
    #[must_use]
    pub fn subscribe(&self) -> Receiver<T> {
        let total_sent = {
            let mut inner = self.channel.inner.lock().expect("broadcast lock poisoned");
            inner.receiver_count += 1;
            inner.total_sent
        };

        Receiver {
            channel: Arc::clone(&self.channel),
            next_index: total_sent,
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.channel
            .inner
            .lock()
            .expect("broadcast lock poisoned")
            .sender_count += 1;
        Self {
            channel: Arc::clone(&self.channel),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut wakers_to_wake = Vec::new();
        {
            let Ok(mut inner) = self.channel.inner.lock() else {
                // Mutex poisoned — another thread panicked while holding the
                // lock.  We cannot safely update sender_count, but waking
                // through a poisoned lock would be unsound anyway.  Bail out
                // to avoid a double-panic abort during unwinding.
                return;
            };
            inner.sender_count -= 1;
            if inner.sender_count == 0 {
                inner.wakers.retain(|waker| {
                    wakers_to_wake.push(waker.clone());
                    false
                });
            }
        }
        for waker in wakers_to_wake {
            waker.wake();
        }
    }
}

/// A permit to send a message.
///
/// Consuming this permit sends the message.
#[must_use = "SendPermit must be consumed via send()"]
pub struct SendPermit<'a, T> {
    sender: &'a Sender<T>,
}

impl<T: Clone> SendPermit<'_, T> {
    /// Sends the message.
    ///
    /// Returns the number of receivers that will see this message.
    ///
    /// If all receivers drop after reservation but before commit, this returns
    /// `0` and does not mutate channel state.
    pub fn send(self, msg: T) -> usize {
        let mut inner = self
            .sender
            .channel
            .inner
            .lock()
            .expect("broadcast lock poisoned");

        // A reservation can outlive the last receiver dropping.
        // In that case, do not enqueue an unobservable message.
        if inner.receiver_count == 0 {
            return 0;
        }

        if inner.buffer.len() == inner.capacity {
            inner.buffer.pop_front();
        }

        let index = inner.total_sent;
        inner.buffer.push_back(Slot { msg, index });
        inner.total_sent += 1;

        let receiver_count = inner.receiver_count;

        // Collect wakers under lock, wake outside to avoid deadlock
        // with inline-polling executors.
        let mut wakers_to_wake = Vec::new();
        inner.wakers.retain(|waker| {
            wakers_to_wake.push(waker.clone());
            false
        });

        drop(inner);

        for waker in wakers_to_wake {
            waker.wake();
        }

        receiver_count
    }
}

/// The receiving side of a broadcast channel.
#[derive(Debug)]
pub struct Receiver<T> {
    channel: Arc<Channel<T>>,
    next_index: u64,
}

impl<T: Clone> Receiver<T> {
    /// Receives the next message.
    ///
    /// # Errors
    ///
    /// - `RecvError::Lagged(n)`: The receiver fell behind.
    /// - `RecvError::Closed`: All senders dropped.
    pub fn recv<'a>(&'a mut self, cx: &'a Cx) -> Recv<'a, T> {
        Recv {
            receiver: self,
            cx,
            waiter: None,
        }
    }
}

/// Future returned by [`Receiver::recv`].
pub struct Recv<'a, T> {
    receiver: &'a mut Receiver<T>,
    cx: &'a Cx,
    /// Token for the registered waiter in the arena.
    waiter: Option<ArenaIndex>,
}

impl<T> Recv<'_, T> {
    fn clear_waiter_registration(&mut self) {
        if let Some(token) = self.waiter.take() {
            let Ok(mut inner) = self.receiver.channel.inner.lock() else {
                // Mutex poisoned — bail out to avoid a double-panic abort
                // during unwinding (this method is called from Drop).
                return;
            };
            inner.wakers.remove(token);
        }
    }
}

impl<T: Clone> Future for Recv<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if this.cx.checkpoint().is_err() {
            this.cx.trace("broadcast::recv cancelled");
            this.clear_waiter_registration();
            return Poll::Ready(Err(RecvError::Cancelled));
        }

        let mut inner = this
            .receiver
            .channel
            .inner
            .lock()
            .expect("broadcast lock poisoned");

        // 1. Check for lag
        let earliest = inner.buffer.front().map_or(inner.total_sent, |s| s.index);

        if this.receiver.next_index < earliest {
            let missed = earliest - this.receiver.next_index;
            this.receiver.next_index = earliest;
            // Clear waiter if we had one
            if let Some(token) = this.waiter.take() {
                inner.wakers.remove(token);
            }
            return Poll::Ready(Err(RecvError::Lagged(missed)));
        }

        // 2. Try to get message.
        //
        // Use checked conversion to avoid `u64 -> usize` truncation on 32-bit
        // targets. A large `next_index - earliest` delta must not wrap and
        // incorrectly index into the front of the ring buffer.
        let delta = this.receiver.next_index.saturating_sub(earliest);
        if let Ok(offset) = usize::try_from(delta) {
            if let Some(slot) = inner.buffer.get(offset) {
                let msg = slot.msg.clone();
                this.receiver.next_index += 1;
                // Clear waiter
                if let Some(token) = this.waiter.take() {
                    inner.wakers.remove(token);
                }
                return Poll::Ready(Ok(msg));
            }
        }

        // 3. Check if closed
        if inner.sender_count == 0 {
            // Clear waiter before returning (matches other Ready paths).
            // When the last Sender drops, retain() already removed our
            // entry and bumped the arena generation, so this is a no-op,
            // but clearing the token avoids a redundant remove in Drop.
            if let Some(token) = this.waiter.take() {
                inner.wakers.remove(token);
            }
            return Poll::Ready(Err(RecvError::Closed));
        }

        // 4. Wait - register or update waker
        let current_waker = ctx.waker();

        if let Some(token) = this.waiter {
            if let Some(waker) = inner.wakers.get_mut(token) {
                // If waker changed, update it in place
                if !waker.will_wake(current_waker) {
                    waker.clone_from(current_waker);
                }
            } else {
                // Token invalid (woken and removed from arena), re-register
                let token = inner.wakers.insert(current_waker.clone());
                this.waiter = Some(token);
            }
        } else {
            // Not registered
            let token = inner.wakers.insert(current_waker.clone());
            this.waiter = Some(token);
        }

        drop(inner);
        Poll::Pending
    }
}

impl<T> Drop for Recv<'_, T> {
    fn drop(&mut self) {
        // If the future is dropped while Pending (e.g. select/race loser),
        // ensure we don't leave stale waiters behind.
        self.clear_waiter_registration();
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        self.channel
            .inner
            .lock()
            .expect("broadcast lock poisoned")
            .receiver_count += 1;
        Self {
            channel: Arc::clone(&self.channel),
            next_index: self.next_index,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let Ok(mut inner) = self.channel.inner.lock() else {
            // Mutex poisoned — bail out to avoid a double-panic abort.
            return;
        };
        inner.receiver_count -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Arc;
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

    #[derive(Debug)]
    struct CountingWaker {
        wakes: AtomicUsize,
    }

    impl CountingWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wakes: AtomicUsize::new(0),
            })
        }

        fn wake_count(&self) -> usize {
            self.wakes.load(AtomicOrdering::Acquire)
        }
    }

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, AtomicOrdering::AcqRel);
        }
    }

    #[test]
    fn basic_send_recv() {
        init_test("basic_send_recv");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);
        let mut rx2 = tx.subscribe();

        tx.send(&cx, 10).expect("send failed");
        tx.send(&cx, 20).expect("send failed");

        let rx1_first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_first == 10, "rx1 first", 10, rx1_first);
        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 20, "rx1 second", 20, rx1_second);

        let rx2_first = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_first == 10, "rx2 first", 10, rx2_first);
        let rx2_second = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_second == 20, "rx2 second", 20, rx2_second);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn lag_detection() {
        init_test("lag_detection");
        let cx = test_cx();
        let (tx, mut rx) = channel(2);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();
        tx.send(&cx, 3).unwrap(); // overwrites 1

        // rx expected 1 (index 0), but earliest is 2 (index 1)
        let result = block_on(rx.recv(&cx));
        match result {
            Err(RecvError::Lagged(n)) => {
                crate::assert_with_log!(n == 1, "lagged count", 1, n);
            }
            other => unreachable!("expected lagged, got {other:?}"),
        }

        // next should be 2
        let second = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(second == 2, "second", 2, second);
        let third = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(third == 3, "third", 3, third);
        crate::test_complete!("lag_detection");
    }

    #[test]
    fn closed_send() {
        init_test("closed_send");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);
        drop(rx);
        let result = tx.send(&cx, 1);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Closed(1))),
            "send after close",
            "Err(Closed(1))",
            format!("{:?}", result)
        );
        crate::test_complete!("closed_send");
    }

    #[test]
    fn closed_recv() {
        init_test("closed_recv");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);
        drop(tx);
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Closed)),
            "recv after close",
            "Err(Closed)",
            format!("{:?}", result)
        );
        crate::test_complete!("closed_recv");
    }

    #[test]
    fn subscribe_sees_future() {
        init_test("subscribe_sees_future");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);

        tx.send(&cx, 1).unwrap();

        let mut rx2 = tx.subscribe();

        tx.send(&cx, 2).unwrap();

        let rx1_first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_first == 1, "rx1 first", 1, rx1_first);
        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 2, "rx1 second", 2, rx1_second);

        // rx2 should skip 1
        let rx2_first = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_first == 2, "rx2 first", 2, rx2_first);
        crate::test_complete!("subscribe_sees_future");
    }

    #[test]
    fn send_returns_live_receiver_count() {
        init_test("send_returns_live_receiver_count");
        let cx = test_cx();
        let (tx, rx1) = channel::<i32>(10);
        let rx2 = tx.subscribe();
        let rx3 = rx2.clone();

        let count = tx.send(&cx, 1).expect("send failed");
        crate::assert_with_log!(count == 3, "receiver count", 3, count);

        drop(rx1);
        let count2 = tx.send(&cx, 2).expect("send failed");
        crate::assert_with_log!(count2 == 2, "receiver count after drop", 2, count2);

        drop(rx2);
        drop(rx3);
        let closed = tx.send(&cx, 3);
        crate::assert_with_log!(
            matches!(closed, Err(SendError::Closed(3))),
            "send closed when no receivers",
            "Err(Closed(3))",
            format!("{:?}", closed)
        );

        crate::test_complete!("send_returns_live_receiver_count");
    }

    #[test]
    fn recv_waiter_dedup_and_wake_on_send() {
        init_test("recv_waiter_dedup_and_wake_on_send");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));

        // No message yet: should pend and register exactly one waiter.
        let first_pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(first_pending, "first poll pending", true, first_pending);
        let second_pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(second_pending, "second poll pending", true, second_pending);

        tx.send(&cx, 123).expect("send failed");

        // Waiter list should not contain duplicates: a single send wakes once.
        let wake_count = wake_state.wake_count();
        crate::assert_with_log!(wake_count == 1, "wake count", 1, wake_count);

        let got = match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Ok(v)) => v,
            other => {
                unreachable!("expected Ready(Ok), got {other:?}");
            }
        };
        crate::assert_with_log!(got == 123, "received", 123, got);

        crate::test_complete!("recv_waiter_dedup_and_wake_on_send");
    }

    #[test]
    fn pending_recv_woken_on_sender_drop_returns_closed() {
        init_test("pending_recv_woken_on_sender_drop_returns_closed");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));
        let pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(pending, "poll pending", true, pending);

        drop(tx);

        let wake_count = wake_state.wake_count();
        crate::assert_with_log!(wake_count == 1, "wake count", 1, wake_count);

        let got = match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(Err(e)) => e,
            other => {
                unreachable!("expected Ready(Err), got {other:?}");
            }
        };
        crate::assert_with_log!(
            got == RecvError::Closed,
            "recv closed after sender drop",
            RecvError::Closed,
            got
        );

        crate::test_complete!("pending_recv_woken_on_sender_drop_returns_closed");
    }

    #[test]
    fn recv_cancelled_does_not_advance_cursor() {
        init_test("recv_cancelled_does_not_advance_cursor");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        cx.set_cancel_requested(true);
        let cancelled = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(cancelled, Err(RecvError::Cancelled)),
            "recv cancelled",
            "Err(Cancelled)",
            format!("{:?}", cancelled)
        );

        // Clear cancellation and ensure the cursor didn't advance past the first message.
        cx.set_cancel_requested(false);
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after cancel", 7, got);

        crate::test_complete!("recv_cancelled_does_not_advance_cursor");
    }

    #[test]
    fn recv_cancelled_clears_waiter_registration() {
        init_test("recv_cancelled_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));

        // No message yet: should pend and register exactly one waiter.
        crate::assert_with_log!(
            matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
            "poll pending",
            true,
            true
        );
        let wakers_len = {
            let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
            inner.wakers.len()
        };
        crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);

        // Cancel: poll should return Cancelled and clear the waiter entry.
        cx.set_cancel_requested(true);
        let res = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(res, Poll::Ready(Err(RecvError::Cancelled))),
            "cancelled",
            "Ready(Err(Cancelled))",
            format!("{res:?}")
        );
        let cleared = {
            let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
            inner.wakers.is_empty()
        };
        crate::assert_with_log!(cleared, "waiter cleared", true, cleared);

        drop(fut);

        // Cursor must not have advanced.
        cx.set_cancel_requested(false);
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after cancel", 7, got);

        crate::test_complete!("recv_cancelled_clears_waiter_registration");
    }

    #[test]
    fn recv_drop_clears_waiter_registration() {
        init_test("recv_drop_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        {
            let mut fut = Box::pin(rx.recv(&cx));

            // No message yet: should pend and register exactly one waiter.
            crate::assert_with_log!(
                matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
                "poll pending",
                true,
                true
            );

            let wakers_len = {
                let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
                inner.wakers.len()
            };
            crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);
        } // drop fut

        let cleared = {
            let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
            inner.wakers.is_empty()
        };
        crate::assert_with_log!(cleared, "waiter cleared on drop", true, cleared);

        // Cursor must not have advanced.
        tx.send(&cx, 7).expect("send failed");
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 7, "received after drop", 7, got);

        crate::test_complete!("recv_drop_clears_waiter_registration");
    }

    #[test]
    fn broadcast_cloned_sender_both_deliver() {
        init_test("broadcast_cloned_sender_both_deliver");
        let cx = test_cx();
        let (tx1, mut rx) = channel(10);
        let tx2 = tx1.clone();

        tx1.send(&cx, 1).unwrap();
        tx2.send(&cx, 2).unwrap();

        let first = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(first == 1, "first", 1, first);
        let second = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(second == 2, "second", 2, second);
        crate::test_complete!("broadcast_cloned_sender_both_deliver");
    }

    #[test]
    fn broadcast_heavy_lag_overwrite() {
        init_test("broadcast_heavy_lag_overwrite");
        let cx = test_cx();
        let (tx, mut rx) = channel(4);

        // Send 10 messages into capacity-4 buffer, overwriting 6.
        for i in 0..10 {
            tx.send(&cx, i).unwrap();
        }

        // First recv should detect lag.
        let result = block_on(rx.recv(&cx));
        match result {
            Err(RecvError::Lagged(n)) => {
                crate::assert_with_log!(n == 6, "lagged 6", 6u64, n);
            }
            other => unreachable!("expected lagged, got {other:?}"),
        }

        // Now should receive 6, 7, 8, 9.
        for expected in 6..10 {
            let got = block_on(rx.recv(&cx)).unwrap();
            crate::assert_with_log!(got == expected, "post-lag msg", expected, got);
        }

        crate::test_complete!("broadcast_heavy_lag_overwrite");
    }

    #[test]
    fn broadcast_clone_receiver_shares_position() {
        init_test("broadcast_clone_receiver_shares_position");
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);

        tx.send(&cx, 10).unwrap();
        tx.send(&cx, 20).unwrap();

        // Advance rx1 past the first message.
        let first = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(first == 10, "rx1 first", 10, first);

        // Clone after advancing — rx2 should start at the same cursor.
        let mut rx2 = rx1.clone();

        let rx1_second = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(rx1_second == 20, "rx1 second", 20, rx1_second);

        let rx2_second = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(rx2_second == 20, "rx2 second", 20, rx2_second);

        crate::test_complete!("broadcast_clone_receiver_shares_position");
    }

    #[test]
    fn broadcast_reserve_then_send() {
        init_test("broadcast_reserve_then_send");
        let cx = test_cx();
        let (tx, mut rx) = channel(10);

        let permit = tx.reserve(&cx).expect("reserve failed");
        let count = permit.send(42);
        crate::assert_with_log!(count == 1, "receiver count", 1usize, count);

        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 42, "received", 42, got);
        crate::test_complete!("broadcast_reserve_then_send");
    }

    #[test]
    fn broadcast_drop_all_senders_closes() {
        init_test("broadcast_drop_all_senders_closes");
        let cx = test_cx();
        let (tx1, mut rx) = channel::<i32>(10);
        let tx2 = tx1.clone();

        // Drop first sender — channel still open (tx2 alive).
        drop(tx1);

        tx2.send(&cx, 5).unwrap();
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 5, "still open", 5, got);

        // Drop last sender — channel closed.
        drop(tx2);
        let result = block_on(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(result, Err(RecvError::Closed)),
            "closed after all senders drop",
            true,
            true
        );
        crate::test_complete!("broadcast_drop_all_senders_closes");
    }

    #[test]
    fn recv_closed_clears_waiter_registration() {
        init_test("recv_closed_clears_waiter_registration");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        // Poll to register a waiter (no messages available).
        let mut fut = Box::pin(rx.recv(&cx));
        crate::assert_with_log!(
            matches!(fut.as_mut().poll(&mut ctx), Poll::Pending),
            "poll pending",
            true,
            true
        );
        let wakers_len = {
            let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
            inner.wakers.len()
        };
        crate::assert_with_log!(wakers_len == 1, "one waiter registered", 1usize, wakers_len);

        // Drop sender — channel closes, retain() wakes and removes all waiters.
        drop(tx);

        // Re-poll: should return Closed and clear the stale waiter token.
        let res = fut.as_mut().poll(&mut ctx);
        crate::assert_with_log!(
            matches!(res, Poll::Ready(Err(RecvError::Closed))),
            "closed",
            "Ready(Err(Closed))",
            format!("{res:?}")
        );

        // Drop the future — Drop handler should not panic even though
        // the waiter was already removed by retain() + cleared by poll.
        drop(fut);

        crate::test_complete!("recv_closed_clears_waiter_registration");
    }

    #[test]
    fn permit_send_after_last_receiver_drop_is_noop() {
        init_test("permit_send_after_last_receiver_drop_is_noop");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(4);

        let permit = tx.reserve(&cx).expect("reserve should succeed");
        drop(rx);

        let delivered = permit.send(42);
        crate::assert_with_log!(delivered == 0, "delivered count", 0usize, delivered);

        let inner = tx.channel.inner.lock().expect("broadcast lock poisoned");
        crate::assert_with_log!(
            inner.total_sent == 0,
            "total_sent unchanged",
            0u64,
            inner.total_sent
        );
        crate::assert_with_log!(
            inner.buffer.is_empty(),
            "buffer remains empty",
            true,
            inner.buffer.is_empty()
        );
        drop(inner);

        let closed = tx.send(&cx, 7);
        crate::assert_with_log!(
            matches!(closed, Err(SendError::Closed(7))),
            "send sees closed after receiver drop",
            "Err(Closed(7))",
            format!("{closed:?}")
        );

        crate::test_complete!("permit_send_after_last_receiver_drop_is_noop");
    }

    #[test]
    fn sender_drop_on_poisoned_mutex_does_not_panic() {
        init_test("sender_drop_on_poisoned_mutex_does_not_panic");
        let (tx, _rx) = channel::<i32>(4);

        // Poison the mutex by panicking inside a lock scope.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.channel.inner.lock().expect("lock");
            panic!("intentional poison");
        }));

        // Dropping tx should NOT panic (it should bail gracefully).
        drop(tx);
        crate::test_complete!("sender_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn receiver_drop_on_poisoned_mutex_does_not_panic() {
        init_test("receiver_drop_on_poisoned_mutex_does_not_panic");
        let (tx, rx) = channel::<i32>(4);

        // Poison the mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.channel.inner.lock().expect("lock");
            panic!("intentional poison");
        }));

        // Dropping rx should NOT panic.
        drop(rx);
        // tx drop also should not panic.
        drop(tx);
        crate::test_complete!("receiver_drop_on_poisoned_mutex_does_not_panic");
    }

    #[test]
    fn recv_drop_on_poisoned_mutex_does_not_panic() {
        // Regression: clear_waiter_registration used expect() which would
        // panic-in-Drop if the mutex was poisoned, causing an abort.
        init_test("recv_drop_on_poisoned_mutex_does_not_panic");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(4);

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        // Create a Recv future and poll it to register a waiter.
        let mut fut = Box::pin(rx.recv(&cx));
        assert!(matches!(fut.as_mut().poll(&mut ctx), Poll::Pending));

        // Poison the mutex.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = tx.channel.inner.lock().expect("lock");
            panic!("intentional poison");
        }));

        // Dropping the Recv future (which has a registered waiter) must NOT
        // panic even though the mutex is poisoned.
        drop(fut);

        // Clean up — these drops should also be graceful.
        drop(rx);
        drop(tx);
        crate::test_complete!("recv_drop_on_poisoned_mutex_does_not_panic");
    }

    // --- Audit tests (SapphireHill, 2026-02-15) ---

    #[test]
    fn total_sent_advances_even_when_buffer_evicts() {
        // Verify total_sent is a monotonic sequence number independent of buffer size.
        init_test("total_sent_advances_even_when_buffer_evicts");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(2);

        for i in 0..10 {
            tx.send(&cx, i).unwrap();
        }

        let (total_sent, buffer_len, first_idx) = {
            let inner = tx.channel.inner.lock().expect("lock");
            (
                inner.total_sent,
                inner.buffer.len(),
                inner.buffer.front().unwrap().index,
            )
        };
        crate::assert_with_log!(total_sent == 10, "total_sent", 10u64, total_sent);
        crate::assert_with_log!(buffer_len == 2, "buffer len", 2usize, buffer_len);
        // Buffer should hold the last 2 messages (indices 8, 9).
        crate::assert_with_log!(first_idx == 8, "first buffer index", 8u64, first_idx);
        crate::test_complete!("total_sent_advances_even_when_buffer_evicts");
    }

    #[test]
    fn subscribe_from_lagged_position_gets_only_future() {
        // New subscribers should only see messages sent after subscription.
        init_test("subscribe_from_lagged_position_gets_only_future");
        let cx = test_cx();
        let (tx, _rx) = channel::<i32>(4);

        // Send some messages before subscribing.
        for i in 0..5 {
            tx.send(&cx, i).unwrap();
        }

        let mut rx2 = tx.subscribe();

        // rx2 shouldn't see any existing messages (it starts at total_sent=5).
        tx.send(&cx, 99).unwrap();
        let got = block_on(rx2.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 99, "subscriber sees only future", 99, got);
        crate::test_complete!("subscribe_from_lagged_position_gets_only_future");
    }

    #[test]
    fn multiple_receivers_independent_lag() {
        // Each receiver tracks its own lag independently.
        init_test("multiple_receivers_independent_lag");
        let cx = test_cx();
        let (tx, mut rx1) = channel::<i32>(2);
        let mut rx2 = tx.subscribe();

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();

        // Advance rx1 but not rx2.
        let v = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(v == 1, "rx1 reads 1", 1, v);

        // Overwrite buffer.
        tx.send(&cx, 3).unwrap(); // evicts 1

        // rx1 should get 2 (still in buffer).
        let v = block_on(rx1.recv(&cx)).unwrap();
        crate::assert_with_log!(v == 2, "rx1 reads 2", 2, v);

        // rx2 has next_index=0, but earliest is now 1 → lagged by 1.
        let result = block_on(rx2.recv(&cx));
        let lagged_ok = matches!(result, Err(RecvError::Lagged(1)));
        crate::assert_with_log!(lagged_ok, "rx2 lagged by 1", true, lagged_ok);
        crate::test_complete!("multiple_receivers_independent_lag");
    }

    #[test]
    fn permit_send_returns_zero_after_all_receivers_drop() {
        // Verify that SendPermit::send does not mutate state when no receivers.
        init_test("permit_send_returns_zero_after_all_receivers_drop");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(4);
        let permit = tx.reserve(&cx).expect("reserve");

        drop(rx);
        let count = permit.send(42);
        crate::assert_with_log!(count == 0, "no receivers", 0usize, count);

        // total_sent and buffer should be untouched.
        let (total_sent, buffer_empty) = {
            let inner = tx.channel.inner.lock().expect("lock");
            (inner.total_sent, inner.buffer.is_empty())
        };
        crate::assert_with_log!(total_sent == 0, "total_sent", 0u64, total_sent);
        crate::assert_with_log!(buffer_empty, "buffer empty", true, buffer_empty);
        crate::test_complete!("permit_send_returns_zero_after_all_receivers_drop");
    }

    #[test]
    fn capacity_one_overwrites_correctly() {
        // Edge case: capacity=1 means every send overwrites the previous.
        init_test("capacity_one_overwrites_correctly");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(1);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap(); // evicts 1
        tx.send(&cx, 3).unwrap(); // evicts 2

        // rx should detect lag (missed 1 and 2).
        let result = block_on(rx.recv(&cx));
        let lagged_ok = matches!(result, Err(RecvError::Lagged(2)));
        crate::assert_with_log!(lagged_ok, "lagged by 2", true, lagged_ok);

        // Then receive 3.
        let got = block_on(rx.recv(&cx)).unwrap();
        crate::assert_with_log!(got == 3, "last message", 3, got);
        crate::test_complete!("capacity_one_overwrites_correctly");
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn recv_large_delta_does_not_truncate_offset() {
        // Regression: on 32-bit, casting `u64` delta to `usize` truncated and
        // could incorrectly return a buffered message at offset 0.
        init_test("recv_large_delta_does_not_truncate_offset");
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(2);
        tx.send(&cx, 7).unwrap();

        // Simulate a receiver cursor far beyond the current window.
        rx.next_index = u64::from(u32::MAX) + 1;

        let wake_state = CountingWaker::new();
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut ctx = Context::from_waker(&waker);

        let mut fut = Box::pin(rx.recv(&cx));
        let pending = matches!(fut.as_mut().poll(&mut ctx), Poll::Pending);
        crate::assert_with_log!(pending, "poll pending", true, pending);

        crate::test_complete!("recv_large_delta_does_not_truncate_offset");
    }
}
