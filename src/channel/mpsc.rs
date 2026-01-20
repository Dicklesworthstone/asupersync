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
use std::sync::{Arc, Condvar, Mutex, Weak};

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
}

/// Shared state wrapper with condition variables for notification.
struct ChannelShared<T> {
    /// Protected channel state.
    inner: Mutex<ChannelInner<T>>,
    /// Notifies senders when space becomes available.
    space_available: Condvar,
    /// Notifies receivers when messages become available.
    message_available: Condvar,
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

    let shared = Arc::new(ChannelShared {
        inner: Mutex::new(ChannelInner::new(capacity)),
        space_available: Condvar::new(),
        message_available: Condvar::new(),
    });
    let sender = Sender {
        shared: Arc::clone(&shared),
    };
    let receiver = Receiver { shared };

    (sender, receiver)
}

/// The sending side of an MPSC channel.
///
/// Multiple `Sender`s can be cloned to allow multiple producers.
/// All `Sender`s share the same underlying channel.
#[derive(Debug)]
pub struct Sender<T> {
    shared: Arc<ChannelShared<T>>,
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

        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        loop {
            // Check if receiver is gone
            if inner.receiver_dropped {
                return Err(SendError::Disconnected(()));
            }

            // Try to reserve a slot
            if inner.has_capacity() {
                inner.reserved += 1;
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
                return Err(SendError::Cancelled(()));
            }

            // Wait for space to become available using condvar
            // Use wait_timeout to allow periodic cancellation checks
            let (guard, _timeout_result) = self
                .shared
                .space_available
                .wait_timeout(inner, std::time::Duration::from_millis(10))
                .expect("channel lock poisoned");
            inner = guard;
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
            Err(SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
        }
    }

    /// Attempts to reserve a slot without blocking.
    ///
    /// # Errors
    ///
    /// - `SendError::Disconnected(())` if the receiver has been dropped
    /// - `SendError::Full(())` if the channel is at capacity
    pub fn try_reserve(&self) -> Result<SendPermit<'_, T>, SendError<()>> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        if inner.receiver_dropped {
            return Err(SendError::Disconnected(()));
        }

        if inner.has_capacity() {
            inner.reserved += 1;
            drop(inner); // Release lock before returning
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
            Err(SendError::Cancelled(())) => {
                unreachable!("try_reserve does not check cancellation")
            }
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
    ///
    /// Useful for checking if the channel is still alive without
    /// preventing cleanup.
    #[must_use]
    pub fn downgrade(&self) -> WeakSender<T> {
        WeakSender {
            shared: Arc::downgrade(&self.shared),
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
        drop(inner); // Release lock before notifying

        // If all senders are gone, wake any waiting receivers
        if all_senders_gone {
            self.shared.message_available.notify_all();
        }
    }
}

/// A weak reference to a sender.
///
/// Does not prevent the channel from being closed, but can be upgraded
/// to a `Sender` if the channel is still alive.
pub struct WeakSender<T> {
    shared: Weak<ChannelShared<T>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for WeakSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakSender").finish_non_exhaustive()
    }
}

impl<T> WeakSender<T> {
    /// Attempts to upgrade to a `Sender`.
    ///
    /// Returns `None` if all senders and the receiver have been dropped.
    #[must_use]
    pub fn upgrade(&self) -> Option<Sender<T>> {
        self.shared.upgrade().and_then(|shared| {
            {
                let mut guard = shared.inner.lock().expect("channel lock poisoned");
                if guard.sender_count == 0 {
                    return None;
                }
                guard.sender_count += 1;
                drop(guard);
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

        {
            let mut inner = self
                .sender
                .shared
                .inner
                .lock()
                .expect("channel lock poisoned");

            // Release the reservation
            inner.reserved -= 1;

            // Add to queue
            inner.queue.push_back(value);
        }

        // Notify any waiting receivers that a message is available
        self.sender.shared.message_available.notify_one();
    }

    /// Aborts the send, releasing the reserved slot.
    ///
    /// This consumes the permit, resolving the obligation as aborted.
    /// No message is sent and the capacity is returned to the channel.
    pub fn abort(mut self) {
        self.sent = true; // Prevent double-release in Drop

        {
            let mut inner = self
                .sender
                .shared
                .inner
                .lock()
                .expect("channel lock poisoned");
            inner.reserved -= 1;
        }

        // Notify any waiting senders that capacity is freed
        self.sender.shared.space_available.notify_one();
    }
}

impl<T> Drop for SendPermit<'_, T> {
    fn drop(&mut self) {
        if !self.sent {
            // Permit dropped without send() - abort the reservation
            {
                let mut inner = self
                    .sender
                    .shared
                    .inner
                    .lock()
                    .expect("channel lock poisoned");
                inner.reserved -= 1;
            }

            // Notify any waiting senders that capacity is freed
            self.sender.shared.space_available.notify_one();
        }
    }
}

/// The receiving side of an MPSC channel.
///
/// Only one `Receiver` exists per channel (single-consumer).
/// When the `Receiver` is dropped, the channel is closed.
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
    /// Uses condvar-based waiting for efficient notification.
    pub fn recv(&self, cx: &Cx) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        loop {
            // Try to receive a message
            if let Some(value) = inner.queue.pop_front() {
                drop(inner); // Release lock before notifying
                             // Notify any waiting senders that space is available
                self.shared.space_available.notify_one();
                return Ok(value);
            }

            // Queue is empty - check if channel is closed
            if inner.is_closed() {
                return Err(RecvError::Disconnected);
            }

            // Check cancellation before waiting
            if let Err(_e) = cx.checkpoint() {
                cx.trace("mpsc::recv cancelled while waiting for message");
                return Err(RecvError::Cancelled);
            }

            // Wait for a message to become available using condvar
            // Use wait_timeout to allow periodic cancellation checks
            let (guard, _timeout_result) = self
                .shared
                .message_available
                .wait_timeout(inner, std::time::Duration::from_millis(10))
                .expect("channel lock poisoned");
            inner = guard;
        }
    }

    /// Attempts to receive a value without blocking.
    ///
    /// # Errors
    ///
    /// - `RecvError::Empty` if the channel is empty but senders exist
    /// - `RecvError::Disconnected` if all senders dropped and queue is empty
    pub fn try_recv(&self) -> Result<T, RecvError> {
        let mut inner = self.shared.inner.lock().expect("channel lock poisoned");

        match inner.queue.pop_front() {
            Some(value) => {
                drop(inner); // Release lock before notifying
                             // Notify any waiting senders that space is available
                self.shared.space_available.notify_one();
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

    /// Returns true if there are messages waiting.
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

    /// Returns the number of messages waiting in the queue.
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

    /// Returns the channel's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared
            .inner
            .lock()
            .expect("channel lock poisoned")
            .capacity
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        {
            let mut inner = self.shared.inner.lock().expect("channel lock poisoned");
            inner.receiver_dropped = true;
        }

        // Wake all waiting senders so they can observe the disconnection
        self.shared.space_available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx() -> Cx {
        Cx::new(
            crate::types::RegionId::from_arena(ArenaIndex::new(0, 0)),
            crate::types::TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
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

        tx.send(&cx, 42).expect("send failed");
        let value = rx.recv(&cx).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("basic_send_recv");
    }

    #[test]
    fn fifo_ordering_single_sender() {
        init_test("fifo_ordering_single_sender");
        let cx = test_cx();
        let (tx, rx) = channel::<usize>(128);

        for i in 0..100 {
            tx.send(&cx, i).expect("send failed");
        }
        drop(tx);

        let mut received = Vec::new();
        loop {
            match rx.recv(&cx) {
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
    fn multi_producer_all_messages_received() {
        init_test("multi_producer_all_messages_received");
        let cx = test_cx();
        let (tx, rx) = channel::<usize>(512);

        let mut handles = Vec::new();
        for producer_id in 0..8 {
            let tx = tx.clone();
            let cx = cx.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..50 {
                    tx.send(&cx, producer_id * 100 + i).expect("send failed");
                }
            }));
        }

        drop(tx);

        for handle in handles {
            handle.join().expect("producer thread panicked");
        }

        let mut received = Vec::new();
        loop {
            match rx.recv(&cx) {
                Ok(value) => received.push(value),
                Err(RecvError::Disconnected) => break,
                Err(other) => panic!("unexpected recv error: {other:?}"),
            }
        }

        crate::assert_with_log!(
            received.len() == 400,
            "received length",
            400,
            received.len()
        );
        received.sort_unstable();

        let mut expected = Vec::new();
        for producer_id in 0..8 {
            for i in 0..50 {
                expected.push(producer_id * 100 + i);
            }
        }
        expected.sort_unstable();
        crate::assert_with_log!(
            received == expected,
            "received matches expected",
            expected,
            received
        );
        crate::test_complete!("multi_producer_all_messages_received");
    }

    #[test]
    fn backpressure_blocks_until_recv() {
        init_test("backpressure_blocks_until_recv");
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(1);

        tx.send(&cx, 1).expect("send failed");

        let finished = Arc::new(AtomicBool::new(false));
        let finished_clone = Arc::clone(&finished);
        let tx_clone = tx;
        let cx_clone = cx.clone();

        let handle = std::thread::spawn(move || {
            tx_clone.send(&cx_clone, 2).expect("send in worker failed");
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

        let first = rx.recv(&cx).expect("recv failed");
        crate::assert_with_log!(first == 1, "first recv", 1, first);

        for _ in 0..10_000 {
            if finished.load(Ordering::SeqCst) {
                break;
            }
            std::thread::yield_now();
        }
        let finished_now = finished.load(Ordering::SeqCst);
        crate::assert_with_log!(finished_now, "worker finished", true, finished_now);
        let second = rx.recv(&cx).expect("recv failed");
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
        let permit = tx.reserve(&cx).expect("reserve failed");

        // Permit is held - capacity is reserved
        let capacity = tx.capacity();
        crate::assert_with_log!(capacity == 10, "capacity", 10, capacity);

        // Phase 2: commit
        permit.send(42);

        let value = rx.recv(&cx).expect("recv failed");
        crate::assert_with_log!(value == 42, "recv value", 42, value);
        crate::test_complete!("two_phase_send_recv");
    }

    #[test]
    fn permit_abort_releases_slot() {
        init_test("permit_abort_releases_slot");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        // Reserve the only slot
        let permit = tx.reserve(&cx).expect("reserve failed");

        // Can't reserve another (capacity 1)
        let try_reserve = tx.try_reserve();
        crate::assert_with_log!(
            matches!(try_reserve, Err(SendError::Full(()))),
            "try_reserve full",
            "Err(Full(()))",
            format!("{:?}", try_reserve)
        );

        // Abort releases the slot
        permit.abort();

        // Now we can reserve again
        let permit2 = tx.reserve(&cx);
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
            let _permit = tx.reserve(&cx).expect("reserve failed");
            // Permit dropped here without send()
        }

        // Slot should be released
        let permit = tx.reserve(&cx);
        crate::assert_with_log!(permit.is_ok(), "reserve after drop", true, permit.is_ok());
        crate::test_complete!("permit_drop_releases_slot");
    }

    #[test]
    fn try_send_when_full() {
        init_test("try_send_when_full");
        let (tx, _rx) = channel::<i32>(1);
        let cx = test_cx();

        // Fill the channel
        tx.send(&cx, 1).expect("send failed");

        // Try to send should fail with Full
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

        // Channel is empty but sender exists
        let empty = rx.try_recv();
        crate::assert_with_log!(
            matches!(empty, Err(RecvError::Empty)),
            "try_recv empty",
            "Err(Empty)",
            format!("{:?}", empty)
        );

        // Send something
        let cx = test_cx();
        tx.send(&cx, 42).expect("send failed");

        // Now should succeed
        let value = rx.try_recv();
        let ok = matches!(value, Ok(42));
        crate::assert_with_log!(ok, "try_recv value", true, ok);
        crate::test_complete!("try_recv_when_empty");
    }

    #[test]
    fn sender_close_detected_by_receiver() {
        init_test("sender_close_detected_by_receiver");
        let (tx, rx) = channel::<i32>(10);

        let closed_before = rx.is_closed();
        crate::assert_with_log!(!closed_before, "receiver open", false, closed_before);
        drop(tx);
        let closed_after = rx.is_closed();
        crate::assert_with_log!(closed_after, "receiver closed", true, closed_after);
        crate::test_complete!("sender_close_detected_by_receiver");
    }

    #[test]
    fn receiver_close_detected_by_sender() {
        init_test("receiver_close_detected_by_sender");
        let (tx, rx) = channel::<i32>(10);

        let closed_before = tx.is_closed();
        crate::assert_with_log!(!closed_before, "sender open", false, closed_before);
        drop(rx);
        let closed_after = tx.is_closed();
        crate::assert_with_log!(closed_after, "sender closed", true, closed_after);
        crate::test_complete!("receiver_close_detected_by_sender");
    }

    #[test]
    fn recv_after_sender_dropped_drains_queue() {
        init_test("recv_after_sender_dropped_drains_queue");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        tx.send(&cx, 1).expect("send failed");
        tx.send(&cx, 2).expect("send failed");
        drop(tx);

        // Should still receive the queued messages
        let first = rx.recv(&cx);
        let first_ok = matches!(first, Ok(1));
        crate::assert_with_log!(first_ok, "recv first", true, first_ok);
        let second = rx.recv(&cx);
        let second_ok = matches!(second, Ok(2));
        crate::assert_with_log!(second_ok, "recv second", true, second_ok);

        // Now should get Disconnected
        let disconnected = rx.try_recv();
        let is_disconnected = matches!(disconnected, Err(RecvError::Disconnected));
        crate::assert_with_log!(is_disconnected, "recv disconnected", true, is_disconnected);
        crate::test_complete!("recv_after_sender_dropped_drains_queue");
    }

    #[test]
    fn send_after_receiver_dropped() {
        init_test("send_after_receiver_dropped");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        drop(rx);

        // Send should fail
        let result = tx.send(&cx, 42);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Disconnected(42))),
            "send disconnected",
            "Err(Disconnected(42))",
            format!("{:?}", result)
        );
        crate::test_complete!("send_after_receiver_dropped");
    }

    #[test]
    fn reserve_after_receiver_dropped() {
        init_test("reserve_after_receiver_dropped");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        drop(rx);

        // Reserve should fail
        let result = tx.reserve(&cx);
        crate::assert_with_log!(
            matches!(result, Err(SendError::Disconnected(()))),
            "reserve disconnected",
            "Err(Disconnected(()))",
            format!("{:?}", result)
        );
        crate::test_complete!("reserve_after_receiver_dropped");
    }

    #[test]
    fn multiple_senders() {
        init_test("multiple_senders");
        let (tx1, rx) = channel::<i32>(10);
        let tx2 = tx1.clone();
        let cx = test_cx();

        tx1.send(&cx, 1).expect("send1 failed");
        tx2.send(&cx, 2).expect("send2 failed");

        // Messages arrive in order they were sent
        let v1 = rx.recv(&cx).expect("recv1 failed");
        let v2 = rx.recv(&cx).expect("recv2 failed");

        // Both messages received (order depends on send order)
        let ok = (v1 == 1 && v2 == 2) || (v1 == 2 && v2 == 1);
        crate::assert_with_log!(ok, "both messages received", true, (v1, v2));
        crate::test_complete!("multiple_senders");
    }

    #[test]
    fn sender_count_tracking() {
        init_test("sender_count_tracking");
        let (tx1, rx) = channel::<i32>(10);

        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "rx open", false, closed);

        let tx2 = tx1.clone();
        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "rx still open", false, closed);

        drop(tx1);
        let closed = rx.is_closed();
        crate::assert_with_log!(!closed, "rx open with tx2", false, closed);

        drop(tx2);
        let closed = rx.is_closed();
        crate::assert_with_log!(closed, "rx closed", true, closed);
        crate::test_complete!("sender_count_tracking");
    }

    #[test]
    fn weak_sender_upgrade() {
        init_test("weak_sender_upgrade");
        let (tx, rx) = channel::<i32>(10);
        let weak = tx.downgrade();

        // Can upgrade while sender exists
        let upgraded = weak.upgrade().is_some();
        crate::assert_with_log!(upgraded, "upgrade while sender exists", true, upgraded);

        drop(tx);

        // Note: weak upgrade depends on Arc being alive (inner still held by rx)
        // In full impl, WeakSender would work differently

        drop(rx);
        // After rx dropped, inner is gone
        crate::test_complete!("weak_sender_upgrade");
    }

    #[test]
    fn fifo_ordering() {
        init_test("fifo_ordering");
        let (tx, rx) = channel::<i32>(100);
        let cx = test_cx();

        for i in 0..50 {
            tx.send(&cx, i).expect("send failed");
        }

        for i in 0..50 {
            let value = rx.recv(&cx);
            let ok = matches!(value, Ok(v) if v == i);
            crate::assert_with_log!(ok, "fifo recv", true, ok);
        }
        crate::test_complete!("fifo_ordering");
    }

    #[test]
    fn capacity_query() {
        init_test("capacity_query");
        let (tx, rx) = channel::<i32>(42);
        let tx_cap = tx.capacity();
        crate::assert_with_log!(tx_cap == 42, "tx capacity", 42, tx_cap);
        let rx_cap = rx.capacity();
        crate::assert_with_log!(rx_cap == 42, "rx capacity", 42, rx_cap);
        crate::test_complete!("capacity_query");
    }

    #[test]
    fn len_and_is_empty() {
        init_test("len_and_is_empty");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        let empty = rx.is_empty();
        crate::assert_with_log!(empty, "rx empty", true, empty);
        let len = rx.len();
        crate::assert_with_log!(len == 0, "len 0", 0, len);

        tx.send(&cx, 1).expect("send failed");
        let empty = rx.is_empty();
        crate::assert_with_log!(!empty, "rx not empty", false, empty);
        let len = rx.len();
        crate::assert_with_log!(len == 1, "len 1", 1, len);

        tx.send(&cx, 2).expect("send failed");
        let len = rx.len();
        crate::assert_with_log!(len == 2, "len 2", 2, len);

        rx.try_recv().expect("recv failed");
        let len = rx.len();
        crate::assert_with_log!(len == 1, "len 1 after recv", 1, len);
        crate::test_complete!("len_and_is_empty");
    }

    #[test]
    fn has_messages() {
        init_test("has_messages");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        let has_messages = rx.has_messages();
        crate::assert_with_log!(!has_messages, "no messages", false, has_messages);
        tx.send(&cx, 1).expect("send failed");
        let has_messages = rx.has_messages();
        crate::assert_with_log!(has_messages, "has messages", true, has_messages);
        crate::test_complete!("has_messages");
    }

    #[test]
    fn permit_consumed_only_once() {
        init_test("permit_consumed_only_once");
        let (tx, rx) = channel::<i32>(10);
        let cx = test_cx();

        let permit = tx.reserve(&cx).expect("reserve failed");
        permit.send(42);
        // Permit is consumed - cannot call send() or abort() again
        // (This is enforced by taking `self` not `&self`)

        let value = rx.recv(&cx);
        let ok = matches!(value, Ok(42));
        crate::assert_with_log!(ok, "recv value", true, ok);
        crate::test_complete!("permit_consumed_only_once");
    }

    #[test]
    fn reserved_slot_counts_against_capacity() {
        init_test("reserved_slot_counts_against_capacity");
        let (tx, _rx) = channel::<i32>(2);
        let cx = test_cx();

        // Reserve one slot
        let permit1 = tx.reserve(&cx).expect("reserve1 failed");

        // Send to another slot
        tx.send(&cx, 1).expect("send failed");

        // Now at capacity (1 reserved + 1 queued = 2)
        let full = tx.try_reserve();
        crate::assert_with_log!(
            matches!(full, Err(SendError::Full(()))),
            "full after reserve + send",
            "Err(Full(()))",
            format!("{:?}", full)
        );

        // Use the permit
        permit1.send(2);

        // Still at capacity (2 queued)
        let full_again = tx.try_reserve();
        crate::assert_with_log!(
            matches!(full_again, Err(SendError::Full(()))),
            "full after permit send",
            "Err(Full(()))",
            format!("{:?}", full_again)
        );
        crate::test_complete!("reserved_slot_counts_against_capacity");
    }

    #[test]
    fn test_channel_resurrection() {
        init_test("test_channel_resurrection");
        let (tx, rx) = channel::<i32>(10);
        let weak = tx.downgrade();
        let cx = test_cx();

        drop(tx);
        // Now sender_count is 0. Channel is closed.
        let closed = rx.is_closed();
        crate::assert_with_log!(closed, "rx closed", true, closed);
        let disconnected = rx.recv(&cx);
        let is_disconnected = matches!(disconnected, Err(RecvError::Disconnected));
        crate::assert_with_log!(is_disconnected, "recv disconnected", true, is_disconnected);

        // Upgrade weak sender
        if let Some(tx2) = weak.upgrade() {
            // If upgrade succeeds, we resurrected the channel
            let closed = rx.is_closed();
            crate::assert_with_log!(!closed, "channel open if sender exists", false, closed);
            tx2.send(&cx, 99).unwrap();

            // Receiver sees message after Disconnected?
            match rx.recv(&cx) {
                Ok(99) => panic!("Channel resurrected! Recv returned Ok after Disconnected"),
                Err(RecvError::Disconnected) => {} // This is what we want (but implementation might behave otherwise)
                _ => panic!("Unexpected result"),
            }
        } else {
            // Upgrade failed - this is good behavior (if intended)
            tracing::info!("Weak sender upgrade failed as expected");
        }
        crate::test_complete!("test_channel_resurrection");
    }
}
