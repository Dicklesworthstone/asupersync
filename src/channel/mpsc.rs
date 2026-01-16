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
use std::sync::{Arc, Mutex, Weak};

use crate::cx::Cx;
use crate::error::{RecvError, SendError};

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
    /// Waiters to wake when space becomes available.
    send_waiters: Vec<std::sync::atomic::AtomicBool>,
    /// Waiters to wake when messages become available.
    recv_waiters: Vec<std::sync::atomic::AtomicBool>,
}

impl<T> ChannelInner<T> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            reserved: 0,
            receiver_dropped: false,
            sender_count: 1,
            send_waiters: Vec::new(),
            recv_waiters: Vec::new(),
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
///
/// # Example
///
/// ```ignore
/// let (tx, rx) = channel::<i32>(10);
/// ```
#[must_use]
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "channel capacity must be non-zero");

    let inner = Arc::new(Mutex::new(ChannelInner::new(capacity)));
    let sender = Sender {
        inner: Arc::clone(&inner),
    };
    let receiver = Receiver { inner };

    (sender, receiver)
}

/// The sending side of an MPSC channel.
///
/// Multiple `Sender`s can be cloned to allow multiple producers.
/// All `Sender`s share the same underlying channel.
#[derive(Debug)]
pub struct Sender<T> {
    inner: Arc<Mutex<ChannelInner<T>>>,
}

impl<T> Sender<T> {
    /// Reserves a slot in the channel for sending.
    ///
    /// This is **Phase 1** of the two-phase send pattern. The returned
    /// `SendPermit` represents an obligation to either send a value or abort.
    ///
    /// This method is cancel-safe: if cancelled before returning, no slot
    /// is reserved and no resources are consumed.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Disconnected(())` if the receiver has been dropped.
    ///
    /// # Blocking
    ///
    /// If the channel is at capacity, this will wait until space is available.
    /// (In Phase 0, this uses spin-waiting. Future phases will integrate with
    /// the scheduler for proper async waiting.)
    pub fn reserve(&self, cx: &Cx) -> Result<SendPermit<'_, T>, SendError<()>> {
        // Check for cancellation at the start
        if cx.is_cancel_requested() {
            // Note: We don't return an error here because reserve itself
            // should be cancel-safe. The checkpoint will be checked by the
            // caller. But we can trace it.
            cx.trace("mpsc::reserve called with cancel pending");
        }

        loop {
            // Try to reserve within a tight scope
            let reservation_result = {
                let mut inner = self.inner.lock().expect("channel lock poisoned");

                // Check if receiver is gone
                if inner.receiver_dropped {
                    return Err(SendError::Disconnected(()));
                }

                // Try to reserve a slot
                if inner.has_capacity() {
                    inner.reserved += 1;
                    drop(inner);
                    Some(())
                } else {
                    None
                }
            }; // Lock released here

            // If we got a reservation, return the permit
            if reservation_result.is_some() {
                // In full implementation, we would register an obligation here:
                // let obligation_id = state.obligations.insert(
                //     ObligationRecord::new(id, ObligationKind::SendPermit, cx.task_id(), cx.region_id())
                // );

                return Ok(SendPermit {
                    sender: self,
                    sent: false,
                });
            }

            // No capacity - will need to wait

            // Check cancellation before waiting
            if cx.checkpoint().is_err() {
                cx.trace("mpsc::reserve cancelled while waiting for capacity");
                return Err(SendError::Disconnected(()));
            }

            // Phase 0: Simple spin-wait with yield
            // Future: integrate with scheduler via proper waker
            std::thread::yield_now();
        }
    }

    /// Convenience method: reserve and send in one step.
    ///
    /// This is equivalent to `reserve(cx)?.send(value)` but more ergonomic
    /// for simple cases. The two-phase pattern is still used internally.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Disconnected(value)` if the receiver has been dropped.
    pub fn send(&self, cx: &Cx, value: T) -> Result<(), SendError<T>> {
        match self.reserve(cx) {
            Ok(permit) => {
                permit.send(value);
                Ok(())
            }
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::Full(())) => Err(SendError::Full(value)),
        }
    }

    /// Attempts to reserve a slot without blocking.
    ///
    /// # Errors
    ///
    /// - `SendError::Disconnected(())` if the receiver has been dropped
    /// - `SendError::Full(())` if the channel is at capacity
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        let reservation_result = {
            let mut inner = self.inner.lock().expect("channel lock poisoned");

            if inner.receiver_dropped {
                return Err(SendError::Disconnected(()));
            }

            if inner.has_capacity() {
                inner.reserved += 1;
                true
            } else {
                false
            }
        }; // Lock released here

        if reservation_result {
            Ok(SendPermit {
                sender: self,
                sent: false,
            })
        } else {
            Err(SendError::Full(()))
        }
    }

    /// Attempts to send a value without blocking.
    ///
    /// # Errors
    ///
    /// - `SendError::Disconnected(value)` if the receiver has been dropped
    /// - `SendError::Full(value)` if the channel is at capacity
    pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
        match self.try_reserve() {
            Ok(permit) => {
                permit.send(value);
                Ok(())
            }
            Err(SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
            Err(SendError::Full(())) => Err(SendError::Full(value)),
        }
    }

    /// Returns true if the receiver has been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .expect("channel lock poisoned")
            .receiver_dropped
    }

    /// Returns the channel's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().expect("channel lock poisoned").capacity
    }

    /// Returns a weak reference to this sender.
    ///
    /// Useful for checking if the channel is still alive without
    /// preventing cleanup.
    #[must_use]
    pub fn downgrade(&self) -> WeakSender<T> {
        WeakSender {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        {
            let mut inner = self.inner.lock().expect("channel lock poisoned");
            inner.sender_count += 1;
        }
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("channel lock poisoned");
        inner.sender_count -= 1;

        // If all senders are gone, wake any waiting receivers
        if inner.sender_count == 0 {
            // In full implementation, we'd wake recv waiters here
            // For now, they'll see is_closed() on next poll
        }
    }
}

/// A weak reference to a sender.
///
/// Does not prevent the channel from being closed, but can be upgraded
/// to a `Sender` if the channel is still alive.
#[derive(Debug)]
pub struct WeakSender<T> {
    inner: Weak<Mutex<ChannelInner<T>>>,
}

impl<T> WeakSender<T> {
    /// Attempts to upgrade to a `Sender`.
    ///
    /// Returns `None` if all senders and the receiver have been dropped.
    #[must_use]
    pub fn upgrade(&self) -> Option<Sender<T>> {
        self.inner.upgrade().map(|inner| {
            {
                let mut guard = inner.lock().expect("channel lock poisoned");
                guard.sender_count += 1;
            }
            Sender { inner }
        })
    }
}

impl<T> Clone for WeakSender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A permit to send a single value into the channel.
///
/// This is the result of `Sender::reserve()` and represents an obligation
/// to either send a value or abort. The permit:
///
/// - Must be consumed by calling `send()` or `abort()`
/// - Will automatically abort if dropped without calling `send()`
/// - Holds a reserved slot in the channel's capacity
///
/// # Obligation Semantics
///
/// `SendPermit` is a **linear resource**: it must be consumed exactly once.
/// The two valid consumption paths are:
///
/// - `permit.send(value)`: Commits the obligation (message is sent)
/// - `permit.abort()`: Aborts the obligation (slot is released)
/// - `drop(permit)`: Equivalent to abort (RAII cleanup)
#[derive(Debug)]
#[must_use = "SendPermit must be consumed via send() or abort()"]
pub struct SendPermit<'a, T> {
    sender: &'a Sender<T>,
    /// Whether `send()` has been called.
    sent: bool,
}

impl<T> SendPermit<'_, T> {
    /// Sends a value using this permit.
    ///
    /// This is **Phase 2** of the two-phase send pattern. Once you have
    /// a permit, sending cannot fail (the slot is already reserved).
    ///
    /// This consumes the permit, resolving the obligation as committed.
    pub fn send(mut self, value: T) {
        self.sent = true;

        let mut inner = self.sender.inner.lock().expect("channel lock poisoned");

        // Release the reservation
        inner.reserved -= 1;

        // Add to queue
        inner.queue.push_back(value);

        // In full implementation, we would:
        // 1. Resolve the obligation as Committed
        // 2. Wake any waiting receivers
    }

    /// Aborts the send, releasing the reserved slot.
    ///
    /// This consumes the permit, resolving the obligation as aborted.
    /// No message is sent and the capacity is returned to the channel.
    pub fn abort(mut self) {
        self.sent = true; // Prevent double-release in Drop

        let mut inner = self.sender.inner.lock().expect("channel lock poisoned");
        inner.reserved -= 1;

        // In full implementation, we would:
        // 1. Resolve the obligation as Aborted
        // 2. Wake any waiting senders (capacity freed)
    }
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if !self.sent {
            // Permit dropped without send() - abort the reservation
            let mut inner = self.sender.inner.lock().expect("channel lock poisoned");
            inner.reserved -= 1;

            // In full implementation, we would:
            // 1. Resolve the obligation as Aborted
            // 2. Wake any waiting senders
        }
    }
}

/// The receiving side of an MPSC channel.
///
/// Only one `Receiver` exists per channel (single-consumer).
/// When the `Receiver` is dropped, the channel is closed.
#[derive(Debug)]
pub struct Receiver<T> {
    inner: Arc<Mutex<ChannelInner<T>>>,
}

impl<T> Receiver<T> {
    /// Receives a value from the channel.
    ///
    /// This method is cancel-safe: if cancelled while waiting, no
    /// message is consumed.
    ///
    /// # Errors
    ///
    /// Returns `RecvError::Disconnected` if all senders have been dropped
    /// and the queue is empty.
    ///
    /// # Blocking
    ///
    /// If the channel is empty, this will wait until a message is available.
    /// (In Phase 0, this uses spin-waiting. Future phases will integrate with
    /// the scheduler for proper async waiting.)
    pub fn recv(&self, cx: &Cx) -> Result<T, RecvError> {
        loop {
            {
                let mut inner = self.inner.lock().expect("channel lock poisoned");

                // Try to receive a message
                if let Some(value) = inner.queue.pop_front() {
                    // In full implementation, we'd wake any waiting senders
                    return Ok(value);
                }

                // Queue is empty - check if channel is closed
                if inner.is_closed() {
                    return Err(RecvError::Disconnected);
                }

                // Need to wait for messages
            }

            // Check cancellation before waiting
            if let Err(_e) = cx.checkpoint() {
                cx.trace("mpsc::recv cancelled while waiting for message");
                return Err(RecvError::Disconnected);
            }

            // Phase 0: Simple spin-wait with yield
            // Future: integrate with scheduler via proper waker
            std::thread::yield_now();
        }
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `RecvError::Empty` if the channel is empty but senders exist
    /// - `RecvError::Disconnected` if all senders dropped and queue is empty
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let mut inner = self.inner.lock().expect("channel lock poisoned");

        inner.queue.pop_front().map_or_else(
            || {
                if inner.is_closed() {
                    Err(RecvError::Disconnected)
                } else {
                    Err(RecvError::Empty)
                }
            },
            Ok,
        )
    }

    /// Returns true if all senders have been dropped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .expect("channel lock poisoned")
            .is_closed()
    }

    /// Returns true if there are messages waiting.
    #[must_use]
    pub fn has_messages(&self) -> bool {
        !self
            .inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .is_empty()
    }

    /// Returns the number of messages waiting in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .len()
    }

    /// Returns true if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("channel lock poisoned")
            .queue
            .is_empty()
    }

    /// Returns the channel's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().expect("channel lock poisoned").capacity
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("channel lock poisoned");
        inner.receiver_dropped = true;

        // In full implementation, we'd wake all waiting senders
        // so they can observe the disconnection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;

    fn test_cx() -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 0)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn channel_capacity_must_be_nonzero() {
        let result = std::panic::catch_unwind(|| channel::<i32>(0));
        assert!(result.is_err());
    }

    #[test]
    fn basic_send_recv() {
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);

        tx.send(&cx, 42).expect("send failed");
        let value = rx.recv(&cx).expect("recv failed");
        assert_eq!(value, 42);
    }

    #[test]
    fn two_phase_send_recv() {
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);

        // Phase 1: reserve
        let permit = tx.reserve(&cx).expect("reserve failed");

        // Permit is held - capacity is reserved
        assert_eq!(tx.capacity(), 10);

        // Phase 2: commit
        permit.send(42);

        let value = rx.recv(&cx).expect("recv failed");
        assert_eq!(value, 42);
    }

    #[test]
    fn permit_abort_releases_slot() {
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        // Reserve the only slot
        let permit = tx.reserve(&cx).expect("reserve failed");

        // Can't reserve another (capacity 1)
        assert!(matches!(tx.try_reserve(), Err(SendError::Full(()))));

        // Abort releases the slot
        permit.abort();

        // Now we can reserve again
        let _permit2 = tx.reserve(&cx).expect("reserve after abort failed");
    }

    #[test]
    fn permit_drop_releases_slot() {
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        {
            let _permit = tx.reserve(&cx).expect("reserve failed");
            // Permit dropped here without send()
        }

        // Slot should be released
        let _permit = tx.reserve(&cx).expect("reserve after drop failed");
    }

    #[test]
    fn try_send_when_full() {
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        // Fill the channel
        tx.send(&cx, 1).expect("send failed");

        // Try to send should fail with Full
        assert!(matches!(tx.try_send(2), Err(SendError::Full(2))));
    }

    #[test]
    fn try_recv_when_empty() {
        let (tx, rx) = channel::<i32>(10);

        // Channel is empty but sender exists
        assert!(matches!(rx.try_recv(), Err(RecvError::Empty)));

        // Send something
        let cx = test_cx();
        tx.send(&cx, 42).expect("send failed");

        // Now should succeed
        assert_eq!(rx.try_recv(), Ok(42));
    }

    #[test]
    fn sender_close_detected_by_receiver() {
        let (tx, rx) = channel::<i32>(10);

        assert!(!rx.is_closed());
        drop(tx);
        assert!(rx.is_closed());
    }

    #[test]
    fn receiver_close_detected_by_sender() {
        let (tx, rx) = channel::<i32>(10);

        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
    }

    #[test]
    fn recv_after_sender_dropped_drains_queue() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        tx.send(&cx, 1).expect("send failed");
        tx.send(&cx, 2).expect("send failed");
        drop(tx);

        // Should still receive the queued messages
        assert_eq!(rx.recv(&cx), Ok(1));
        assert_eq!(rx.recv(&cx), Ok(2));

        // Now should get Disconnected
        assert_eq!(rx.try_recv(), Err(RecvError::Disconnected));
    }

    #[test]
    fn send_after_receiver_dropped() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        drop(rx);

        // Send should fail
        assert!(matches!(tx.send(&cx, 42), Err(SendError::Disconnected(42))));
    }

    #[test]
    fn reserve_after_receiver_dropped() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        drop(rx);

        // Reserve should fail
        assert!(matches!(tx.reserve(&cx), Err(SendError::Disconnected(()))));
    }

    #[test]
    fn multiple_senders() {
        let (tx1, rx) = channel::<i32>(10);
        let tx2 = tx1.clone();
        let cx = test_cx();

        tx1.send(&cx, 1).expect("send1 failed");
        tx2.send(&cx, 2).expect("send2 failed");

        // Messages arrive in order they were sent
        let v1 = rx.recv(&cx).expect("recv1 failed");
        let v2 = rx.recv(&cx).expect("recv2 failed");

        // Both messages received (order depends on send order)
        assert!((v1 == 1 && v2 == 2) || (v1 == 2 && v2 == 1));
    }

    #[test]
    fn sender_count_tracking() {
        let (tx1, rx) = channel::<i32>(10);

        assert!(!rx.is_closed());

        let tx2 = tx1.clone();
        assert!(!rx.is_closed());

        drop(tx1);
        assert!(!rx.is_closed()); // tx2 still alive

        drop(tx2);
        assert!(rx.is_closed()); // all senders gone
    }

    #[test]
    fn weak_sender_upgrade() {
        let (tx, rx) = channel::<i32>(10);
        let weak = tx.downgrade();

        // Can upgrade while sender exists
        assert!(weak.upgrade().is_some());

        drop(tx);

        // Note: weak upgrade depends on Arc being alive (inner still held by rx)
        // In full impl, WeakSender would work differently

        drop(rx);
        // After rx dropped, inner is gone
    }

    #[test]
    fn fifo_ordering() {
        let (tx, rx) = channel::<i32>(100);
        let cx = test_cx();

        for i in 0..50 {
            tx.send(&cx, i).expect("send failed");
        }

        for i in 0..50 {
            assert_eq!(rx.recv(&cx), Ok(i));
        }
    }

    #[test]
    fn capacity_query() {
        let (tx, rx) = channel::<i32>(42);
        assert_eq!(tx.capacity(), 42);
        assert_eq!(rx.capacity(), 42);
    }

    #[test]
    fn len_and_is_empty() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        assert!(rx.is_empty());
        assert_eq!(rx.len(), 0);

        tx.send(&cx, 1).expect("send failed");
        assert!(!rx.is_empty());
        assert_eq!(rx.len(), 1);

        tx.send(&cx, 2).expect("send failed");
        assert_eq!(rx.len(), 2);

        rx.try_recv().expect("recv failed");
        assert_eq!(rx.len(), 1);
    }

    #[test]
    fn has_messages() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        assert!(!rx.has_messages());
        tx.send(&cx, 1).expect("send failed");
        assert!(rx.has_messages());
    }

    #[test]
    fn permit_consumed_only_once() {
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        let permit = tx.reserve(&cx).expect("reserve failed");
        permit.send(42);
        // Permit is consumed - cannot call send() or abort() again
        // (This is enforced by taking `self` not `&self`)

        assert_eq!(rx.recv(&cx), Ok(42));
    }

    #[test]
    fn reserved_slot_counts_against_capacity() {
        let (tx, _rx) = channel::<i32>(2);
        let cx = test_cx();

        // Reserve one slot
        let permit1 = tx.reserve(&cx).expect("reserve1 failed");

        // Send to another slot
        tx.send(&cx, 1).expect("send failed");

        // Now at capacity (1 reserved + 1 queued = 2)
        assert!(matches!(tx.try_reserve(), Err(SendError::Full(()))));

        // Use the permit
        permit1.send(2);

        // Still at capacity (2 queued)
        assert!(matches!(tx.try_reserve(), Err(SendError::Full(()))));
    }
}
