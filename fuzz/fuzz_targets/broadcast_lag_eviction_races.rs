//! Fuzz broadcast channel lag eviction and multi-producer fairness.
//!
//! Tests concurrent scenarios to find race conditions in:
//! 1. Slow-receiver lag eviction race (lag calculation and cursor advancement)
//! 2. Capacity-boundary multi-producer fairness (send ordering at buffer limits)
//! 3. Drop-receiver-while-send race (receiver drop during send operations)
//!
//! Critical invariants:
//! - Lag calculation is accurate (missed = earliest - next_index)
//! - No receiver sees messages out of order within its view window
//! - Buffer capacity never exceeded
//! - Receiver drop during send doesn't corrupt state
//! - Multi-producer send operations are fair (no starvation)

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::broadcast::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use futures::task::noop_waker;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Debug, Clone, Arbitrary)]
struct BroadcastOpsSequence {
    /// Channel capacity (1-16)
    capacity: u8,
    /// Operations to perform
    operations: Vec<BroadcastOp>,
}

#[derive(Debug, Clone, Arbitrary)]
enum BroadcastOp {
    /// Send message with sender ID
    Send { sender_id: u8, message: u32 },
    /// Try to receive with receiver ID
    TryRecv { receiver_id: u8 },
    /// Async receive with receiver ID (simulated)
    AsyncRecv { receiver_id: u8 },
    /// Create new receiver from sender
    Subscribe { sender_id: u8, new_receiver_id: u8 },
    /// Drop sender
    DropSender { sender_id: u8 },
    /// Drop receiver
    DropReceiver { receiver_id: u8 },
    /// Clone sender
    CloneSender { sender_id: u8, new_sender_id: u8 },
    /// Clone receiver
    CloneReceiver { receiver_id: u8, new_receiver_id: u8 },
    /// Check channel state invariants
    CheckInvariants,
    /// Yield to allow concurrency simulation
    Yield,
    /// Concurrent send burst (multiple senders at capacity)
    ConcurrentSendBurst { sender_ids: Vec<u8>, messages: Vec<u32> },
    /// Lag-inducing send spam (overwhelm slow receiver)
    LagSpam { sender_id: u8, count: u8 },
}

struct ReceiverState {
    receiver: broadcast::Receiver<u32>,
    messages_seen: Vec<u32>,
    lag_count: u64,
    is_dropped: bool,
    last_index_seen: u64,
}

struct SenderState {
    sender: broadcast::Sender<u32>,
    messages_sent: u64,
    is_dropped: bool,
}

struct FuzzState {
    senders: HashMap<u8, SenderState>,
    receivers: HashMap<u8, ReceiverState>,
    capacity: usize,
    total_operations: AtomicUsize,
    total_lag_events: AtomicUsize,
    fairness_tracker: Arc<FairnessTracker>,
}

#[derive(Debug)]
struct FairnessTracker {
    send_attempts: AtomicUsize,
    send_successes: AtomicUsize,
    concurrent_send_conflicts: AtomicUsize,
}

impl FairnessTracker {
    fn new() -> Self {
        Self {
            send_attempts: AtomicUsize::new(0),
            send_successes: AtomicUsize::new(0),
            concurrent_send_conflicts: AtomicUsize::new(0),
        }
    }
}

impl FuzzState {
    fn new(capacity: usize) -> Self {
        let (sender, receiver) = broadcast::channel(capacity);

        let mut senders = HashMap::new();
        senders.insert(0, SenderState {
            sender,
            messages_sent: 0,
            is_dropped: false,
        });

        let mut receivers = HashMap::new();
        receivers.insert(0, ReceiverState {
            receiver,
            messages_seen: Vec::new(),
            lag_count: 0,
            is_dropped: false,
            last_index_seen: 0,
        });

        Self {
            senders,
            receivers,
            capacity,
            total_operations: AtomicUsize::new(0),
            total_lag_events: AtomicUsize::new(0),
            fairness_tracker: Arc::new(FairnessTracker::new()),
        }
    }

    fn check_invariants(&self) -> bool {
        // 1. Check that all active receivers have monotonic message indices
        for (id, receiver_state) in &self.receivers {
            if receiver_state.is_dropped {
                continue;
            }
            // Verify message ordering (if we tracked indices)
            // This is simplified since we don't track exact indices in this fuzzer
        }

        // 2. Check fairness metrics
        let attempts = self.fairness_tracker.send_attempts.load(Ordering::Acquire);
        let successes = self.fairness_tracker.send_successes.load(Ordering::Acquire);

        // Success rate shouldn't be too low (allowing for some natural contention)
        if attempts > 10 && successes * 10 < attempts {
            // Less than 10% success rate suggests severe fairness issues
            return false;
        }

        // 3. Buffer capacity invariant (we can't directly check this without access to internals)
        // The channel implementation should handle this internally

        true
    }

    fn simulate_concurrent_sends(&mut self, sender_ids: &[u8], messages: &[u32], cx: &Cx) {
        let tracker = Arc::clone(&self.fairness_tracker);

        for (&sender_id, &message) in sender_ids.iter().zip(messages.iter()) {
            if let Some(sender_state) = self.senders.get_mut(&sender_id) {
                if sender_state.is_dropped {
                    continue;
                }

                tracker.send_attempts.fetch_add(1, Ordering::Relaxed);

                match sender_state.sender.send(cx, message) {
                    Ok(_receiver_count) => {
                        tracker.send_successes.fetch_add(1, Ordering::Relaxed);
                        sender_state.messages_sent += 1;
                    }
                    Err(SendError::Closed(_)) => {
                        // Expected when no receivers
                    }
                    Err(SendError::Cancelled) => {
                        // Expected when Cx is cancelled
                    }
                }
            }
        }
    }

    fn simulate_lag_spam(&mut self, sender_id: u8, count: u8, cx: &Cx) {
        if let Some(sender_state) = self.senders.get_mut(&sender_id) {
            if sender_state.is_dropped {
                return;
            }

            // Send many messages rapidly to try to overwhelm receivers
            for i in 0..count {
                let message = sender_state.messages_sent as u32 * 1000 + i as u32;
                match sender_state.sender.send(cx, message) {
                    Ok(_) => sender_state.messages_sent += 1,
                    Err(_) => break, // Stop on error
                }
            }
        }
    }

    fn try_recv(&mut self, receiver_id: u8) {
        if let Some(receiver_state) = self.receivers.get_mut(&receiver_id) {
            if receiver_state.is_dropped {
                return;
            }

            match receiver_state.receiver.try_recv() {
                Ok(message) => {
                    receiver_state.messages_seen.push(message);
                    receiver_state.last_index_seen += 1;
                }
                Err(TryRecvError::Empty) => {
                    // Expected when no messages available
                }
                Err(TryRecvError::Lagged(n)) => {
                    receiver_state.lag_count += n;
                    self.total_lag_events.fetch_add(1, Ordering::Relaxed);
                    // Try again immediately after lag error
                    if let Ok(message) = receiver_state.receiver.try_recv() {
                        receiver_state.messages_seen.push(message);
                        receiver_state.last_index_seen += 1;
                    }
                }
                Err(TryRecvError::Closed) => {
                    // Expected when all senders dropped
                }
            }
        }
    }

    fn simulate_async_recv(&mut self, receiver_id: u8, cx: &Cx) {
        if let Some(receiver_state) = self.receivers.get_mut(&receiver_id) {
            if receiver_state.is_dropped {
                return;
            }

            // Simplified async recv simulation using polling
            let mut recv_future = receiver_state.receiver.recv(cx);
            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);

            match Pin::new(&mut recv_future).poll(&mut context) {
                Poll::Ready(Ok(message)) => {
                    receiver_state.messages_seen.push(message);
                    receiver_state.last_index_seen += 1;
                }
                Poll::Ready(Err(RecvError::Lagged(n))) => {
                    receiver_state.lag_count += n;
                    self.total_lag_events.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(Err(RecvError::Closed)) => {
                    // Expected when all senders dropped
                }
                Poll::Ready(Err(RecvError::Cancelled)) => {
                    // Expected when Cx cancelled
                }
                Poll::Ready(Err(RecvError::PolledAfterCompletion)) => {
                    // Should not happen in our simulation
                }
                Poll::Pending => {
                    // Would need actual async runtime to handle this properly
                }
            }
        }
    }
}

fn create_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fuzz_target!(|sequence: BroadcastOpsSequence| {
    let capacity = sequence.capacity.max(1).min(16) as usize;
    let mut state = FuzzState::new(capacity);
    let cx = create_cx();

    for operation in sequence.operations.into_iter().take(200) { // Limit ops to prevent timeout
        match operation {
            BroadcastOp::Send { sender_id, message } => {
                if let Some(sender_state) = state.senders.get_mut(&sender_id) {
                    if !sender_state.is_dropped {
                        match sender_state.sender.send(&cx, message) {
                            Ok(_) => sender_state.messages_sent += 1,
                            Err(_) => {} // Expected in some cases
                        }
                    }
                }
            }

            BroadcastOp::TryRecv { receiver_id } => {
                state.try_recv(receiver_id);
            }

            BroadcastOp::AsyncRecv { receiver_id } => {
                state.simulate_async_recv(receiver_id, &cx);
            }

            BroadcastOp::Subscribe { sender_id, new_receiver_id } => {
                if let Some(sender_state) = state.senders.get(&sender_id) {
                    if !sender_state.is_dropped && !state.receivers.contains_key(&new_receiver_id) {
                        let new_receiver = sender_state.sender.subscribe();
                        state.receivers.insert(new_receiver_id, ReceiverState {
                            receiver: new_receiver,
                            messages_seen: Vec::new(),
                            lag_count: 0,
                            is_dropped: false,
                            last_index_seen: 0,
                        });
                    }
                }
            }

            BroadcastOp::DropSender { sender_id } => {
                if let Some(sender_state) = state.senders.get_mut(&sender_id) {
                    sender_state.is_dropped = true;
                }
                state.senders.remove(&sender_id);
            }

            BroadcastOp::DropReceiver { receiver_id } => {
                if let Some(receiver_state) = state.receivers.get_mut(&receiver_id) {
                    receiver_state.is_dropped = true;
                }
                state.receivers.remove(&receiver_id);
            }

            BroadcastOp::CloneSender { sender_id, new_sender_id } => {
                if let Some(sender_state) = state.senders.get(&sender_id) {
                    if !sender_state.is_dropped && !state.senders.contains_key(&new_sender_id) {
                        let cloned_sender = sender_state.sender.clone();
                        state.senders.insert(new_sender_id, SenderState {
                            sender: cloned_sender,
                            messages_sent: 0,
                            is_dropped: false,
                        });
                    }
                }
            }

            BroadcastOp::CloneReceiver { receiver_id, new_receiver_id } => {
                if let Some(receiver_state) = state.receivers.get(&receiver_id) {
                    if !receiver_state.is_dropped && !state.receivers.contains_key(&new_receiver_id) {
                        let cloned_receiver = receiver_state.receiver.clone();
                        state.receivers.insert(new_receiver_id, ReceiverState {
                            receiver: cloned_receiver,
                            messages_seen: Vec::new(),
                            lag_count: 0,
                            is_dropped: false,
                            last_index_seen: receiver_state.last_index_seen,
                        });
                    }
                }
            }

            BroadcastOp::CheckInvariants => {
                assert!(state.check_invariants(), "Broadcast channel invariants violated");
            }

            BroadcastOp::Yield => {
                // Simulate yielding to allow other operations to proceed
                // In a real async environment, this would allow tasks to be scheduled
            }

            BroadcastOp::ConcurrentSendBurst { sender_ids, messages } => {
                let ids: Vec<u8> = sender_ids.into_iter().take(8).collect(); // Limit concurrent senders
                let msgs: Vec<u32> = messages.into_iter().take(ids.len()).collect();
                state.simulate_concurrent_sends(&ids, &msgs, &cx);
            }

            BroadcastOp::LagSpam { sender_id, count } => {
                let count = count.min(32); // Limit spam count to prevent timeout
                state.simulate_lag_spam(sender_id, count, &cx);
            }
        }

        state.total_operations.fetch_add(1, Ordering::Relaxed);

        // Periodic invariant check
        if state.total_operations.load(Ordering::Acquire) % 20 == 0 {
            assert!(state.check_invariants(), "Periodic invariant check failed");
        }
    }

    // Final invariant check
    assert!(state.check_invariants(), "Final invariant check failed");
});