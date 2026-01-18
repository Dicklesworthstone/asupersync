//! Two-phase broadcast channel.
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
//!
//! # Example
//!
//! ```ignore
//! use asupersync::channel::broadcast;
//!
//! let (tx, mut rx1) = broadcast::channel(16);
//! let mut rx2 = tx.subscribe();
//!
//! tx.send(&cx, 10).expect("send failed");
//!
//! assert_eq!(rx1.recv(&cx).await?, 10);
//! assert_eq!(rx2.recv(&cx).await?, 10);
//! ```

use crate::cx::Cx;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

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
}

impl std::fmt::Display for RecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lagged(n) => write!(f, "receiver lagged by {n} messages"),
            Self::Closed => write!(f, "broadcast channel closed"),
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
}

#[derive(Debug)]
struct Slot<T> {
    msg: T,
    /// The cumulative index of this message.
    index: u64,
}

/// Shared wrapper with condition variable.
struct Channel<T> {
    inner: Mutex<Shared<T>>,
    /// Notifies receivers when new messages arrive.
    notify: Condvar,
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
            receiver_count: 1, // Start with one receiver
            sender_count: 1,   // Start with one sender
        }),
        notify: Condvar::new(),
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

        // We don't really "reserve" space in the ring buffer in the same way
        // as MPSC because we always have space (by dropping old items).
        // But to maintain the API consistency and two-phase commit, we return
        // a permit that holds the lock? No, holding lock across await is bad.
        //
        // Actually, broadcast sends are non-blocking for senders (except lock contention).
        // So `reserve` is just a check for receivers.

        Ok(SendPermit { sender: self })
    }

    /// Sends a message to all receivers.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed(msg)` if there are no active receivers.
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

        // New receiver starts at the *current* tail of the buffer?
        // Typically broadcast receivers start seeing *future* messages.
        // Or they can see buffered messages.
        // Tokio's subscribe sees future messages.

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
        let mut inner = self.channel.inner.lock().expect("broadcast lock poisoned");
        inner.sender_count -= 1;
        if inner.sender_count == 0 {
            self.channel.notify.notify_all();
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
    pub fn send(self, msg: T) -> usize {
        let mut inner = self
            .sender
            .channel
            .inner
            .lock()
            .expect("broadcast lock poisoned");

        if inner.buffer.len() == inner.capacity {
            inner.buffer.pop_front();
        }

        let index = inner.total_sent;
        inner.buffer.push_back(Slot { msg, index });
        inner.total_sent += 1;

        let receiver_count = inner.receiver_count;
        drop(inner);
        self.sender.channel.notify.notify_all();

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
    pub fn recv(&mut self, cx: &Cx) -> Result<T, RecvError> {
        let mut inner = self.channel.inner.lock().expect("broadcast lock poisoned");

        loop {
            // 1. Check for lag
            // The earliest available index is:
            let earliest = inner.buffer.front().map_or(inner.total_sent, |s| s.index);

            if self.next_index < earliest {
                let missed = earliest - self.next_index;
                self.next_index = earliest;
                return Err(RecvError::Lagged(missed));
            }

            // 2. Try to get message
            // We want the message with index == self.next_index
            // Since buffer is ordered, we can calculate offset
            let offset = self.next_index.saturating_sub(earliest) as usize;

            if let Some(slot) = inner.buffer.get(offset) {
                // Found it
                self.next_index += 1;
                return Ok(slot.msg.clone());
            }

            // 3. Check if closed
            if inner.sender_count == 0 {
                return Err(RecvError::Closed);
            }

            // 4. Wait
            if let Err(_e) = cx.checkpoint() {
                cx.trace("broadcast::recv cancelled while waiting");
                // Don't consume anything
                return Err(RecvError::Closed); // Or some Cancelled error if we had one in RecvError
            }

            let (guard, _) = self
                .channel
                .notify
                .wait_timeout(inner, std::time::Duration::from_millis(10))
                .expect("broadcast lock poisoned");
            inner = guard;
        }
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
        let mut inner = self.channel.inner.lock().expect("broadcast lock poisoned");
        inner.receiver_count -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn basic_send_recv() {
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);
        let mut rx2 = tx.subscribe();

        tx.send(&cx, 10).expect("send failed");
        tx.send(&cx, 20).expect("send failed");

        assert_eq!(rx1.recv(&cx).unwrap(), 10);
        assert_eq!(rx1.recv(&cx).unwrap(), 20);

        assert_eq!(rx2.recv(&cx).unwrap(), 10);
        assert_eq!(rx2.recv(&cx).unwrap(), 20);
    }

    #[test]
    fn lag_detection() {
        let cx = test_cx();
        let (tx, mut rx) = channel(2);

        tx.send(&cx, 1).unwrap();
        tx.send(&cx, 2).unwrap();
        tx.send(&cx, 3).unwrap(); // overwrites 1

        // rx expected 1 (index 0), but earliest is 2 (index 1)
        match rx.recv(&cx) {
            Err(RecvError::Lagged(n)) => assert_eq!(n, 1),
            _ => panic!("expected lagged"),
        }

        // next should be 2
        assert_eq!(rx.recv(&cx).unwrap(), 2);
        assert_eq!(rx.recv(&cx).unwrap(), 3);
    }

    #[test]
    fn closed_send() {
        let cx = test_cx();
        let (tx, rx) = channel::<i32>(10);
        drop(rx);
        assert!(matches!(tx.send(&cx, 1), Err(SendError::Closed(1))));
    }

    #[test]
    fn closed_recv() {
        let cx = test_cx();
        let (tx, mut rx) = channel::<i32>(10);
        drop(tx);
        assert!(matches!(rx.recv(&cx), Err(RecvError::Closed)));
    }

    #[test]
    fn subscribe_sees_future() {
        let cx = test_cx();
        let (tx, mut rx1) = channel(10);

        tx.send(&cx, 1).unwrap();

        let mut rx2 = tx.subscribe();

        tx.send(&cx, 2).unwrap();

        assert_eq!(rx1.recv(&cx).unwrap(), 1);
        assert_eq!(rx1.recv(&cx).unwrap(), 2);

        // rx2 should skip 1
        assert_eq!(rx2.recv(&cx).unwrap(), 2);
    }
}
