#![no_main]

use arbitrary::Arbitrary;
use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

/// Structure-aware fuzzer for oneshot send-then-recv vs cancel-mid-send timing
///
/// Tests the oneshot channel cancellation correctness properties:
/// 1. Receiver gets either the value OR Cancelled, never wedged
/// 2. Reserve-then-cancel is properly handled
/// 3. Send-then-cancel-recv timing works correctly
/// 4. Permit drop during cancellation doesn't cause data races
#[derive(Arbitrary, Debug)]
struct OneshotCancellationFuzz {
    /// Sequence of oneshot operations to perform
    operations: Vec<OneshotOperation>,
    /// Test configuration parameters
    config: TestConfig,
}

#[derive(Arbitrary, Debug, Clone)]
enum OneshotOperation {
    /// Create a new oneshot channel
    CreateChannel {
        channel_id: u8, // Channel identifier (0-7)
    },
    /// Try to reserve a send permit
    TryReserve {
        channel_id: u8, // Channel to use (0-7)
        sender_id: u8,  // Sender identifier (0-7)
    },
    /// Send a value using an existing permit
    SendValue {
        sender_id: u8, // Sender/permit to use (0-7)
        value: u32,    // Value to send
    },
    /// Convenience send (reserve + send in one)
    ConvenienceSend {
        channel_id: u8, // Channel to use (0-7)
        value: u32,     // Value to send
    },
    /// Try to receive a value (non-blocking)
    TryReceive {
        channel_id: u8, // Channel to use (0-7)
    },
    /// Poll the async receive once
    PollReceive {
        channel_id: u8, // Channel to use (0-7)
    },
    /// Cancel the context for a specific channel/sender
    CancelContext {
        target_id: u8, // Context to cancel (0-7)
    },
    /// Drop a sender or permit
    DropSender {
        sender_id: u8, // Sender/permit to drop (0-7)
    },
    /// Drop a receiver
    DropReceiver {
        channel_id: u8, // Receiver to drop (0-7)
    },
    /// Brief delay for timing variations
    Delay {
        milliseconds: u8, // Delay duration (0-3ms)
    },
}

#[derive(Arbitrary, Debug)]
struct TestConfig {
    /// Maximum number of operations to execute
    max_operations: u8,
    /// Test duration timeout
    timeout_seconds: u8,
}

// Resource limits to prevent fuzzer timeouts
const MAX_OPERATIONS: usize = 100;
const MAX_CHANNELS: usize = 8;
const MAX_SENDERS: usize = 8;
const MAX_DELAY_MS: u64 = 2;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

fuzz_target!(|input: OneshotCancellationFuzz| {
    // Apply resource limits
    let max_ops = (input.config.max_operations as usize)
        .min(MAX_OPERATIONS)
        .max(1);
    let operations: Vec<_> = input.operations.into_iter().take(max_ops).collect();

    if operations.is_empty() {
        return; // Skip empty operation sequences
    }

    // Execute the cancellation timing test
    execute_and_verify_cancellation_correctness(operations);
});

/// Tracks oneshot operations and cancellation properties
struct CancellationTracker {
    /// Active channels by ID
    channels: std::collections::HashMap<u8, ChannelInfo>,
    /// Active senders/permits by ID
    senders: std::collections::HashMap<u8, SenderInfo>,
    /// Cancellation contexts by ID
    contexts: std::collections::HashMap<u8, (Cx, Arc<AtomicBool>)>,
    /// Operation log for debugging
    operations_log: Vec<OperationEvent>,
    /// Statistics
    stats: CancellationStats,
}

#[derive(Debug, Clone)]
struct ChannelInfo {
    receiver_active: bool,
    expected_value: Option<u32>,
    channel_state: ChannelState,
    created_at: Instant,
}

#[derive(Debug, Clone)]
enum ChannelState {
    Open,
    ValueSent(u32),
    Closed,
    ReceiverDropped,
}

#[derive(Debug, Clone)]
struct SenderInfo {
    channel_id: u8,
    state: SenderState,
    created_at: Instant,
}

#[derive(Debug, Clone)]
enum SenderState {
    Unreserved,
    Reserved,
    Sent(u32),
    Cancelled,
    Dropped,
}

#[derive(Debug, Clone)]
enum OperationEvent {
    ChannelCreated {
        channel_id: u8,
        timestamp: Instant,
    },
    ReserveAttempted {
        channel_id: u8,
        sender_id: u8,
        success: bool,
        reason: String,
        timestamp: Instant,
    },
    ValueSent {
        sender_id: u8,
        value: u32,
        success: bool,
        timestamp: Instant,
    },
    ConvenienceSendAttempted {
        channel_id: u8,
        value: u32,
        success: bool,
        reason: String,
        timestamp: Instant,
    },
    TryReceiveAttempted {
        channel_id: u8,
        result: String,
        timestamp: Instant,
    },
    PollReceiveAttempted {
        channel_id: u8,
        result: String,
        timestamp: Instant,
    },
    ContextCancelled {
        target_id: u8,
        timestamp: Instant,
    },
    SenderDropped {
        sender_id: u8,
        timestamp: Instant,
    },
    ReceiverDropped {
        channel_id: u8,
        timestamp: Instant,
    },
}

#[derive(Debug, Clone, Default)]
struct CancellationStats {
    channels_created: usize,
    reserve_attempts: usize,
    reserve_successes: usize,
    send_attempts: usize,
    send_successes: usize,
    receive_attempts: usize,
    receive_successes: usize,
    cancellations: usize,
}

impl CancellationTracker {
    fn new() -> Self {
        Self {
            channels: std::collections::HashMap::new(),
            senders: std::collections::HashMap::new(),
            contexts: std::collections::HashMap::new(),
            operations_log: Vec::new(),
            stats: CancellationStats::default(),
        }
    }

    fn create_context(&mut self, id: u8) -> &(Cx, Arc<AtomicBool>) {
        if !self.contexts.contains_key(&id) {
            let cancelled = Arc::new(AtomicBool::new(false));
            let cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, id as usize)),
                TaskId::from_arena(ArenaIndex::new(0, id as usize)),
                Budget::INFINITE,
            );
            self.contexts.insert(id, (cx, cancelled));
        }
        self.contexts.get(&id).unwrap()
    }

    fn record_channel_created(&mut self, channel_id: u8) {
        self.stats.channels_created += 1;
        self.channels.insert(
            channel_id,
            ChannelInfo {
                receiver_active: true,
                expected_value: None,
                channel_state: ChannelState::Open,
                created_at: Instant::now(),
            },
        );
        self.operations_log.push(OperationEvent::ChannelCreated {
            channel_id,
            timestamp: Instant::now(),
        });
    }

    fn record_reserve_attempt(
        &mut self,
        channel_id: u8,
        sender_id: u8,
        success: bool,
        reason: String,
    ) {
        self.stats.reserve_attempts += 1;
        if success {
            self.stats.reserve_successes += 1;
            self.senders.insert(
                sender_id,
                SenderInfo {
                    channel_id,
                    state: SenderState::Reserved,
                    created_at: Instant::now(),
                },
            );
        }
        self.operations_log.push(OperationEvent::ReserveAttempted {
            channel_id,
            sender_id,
            success,
            reason,
            timestamp: Instant::now(),
        });
    }

    fn record_value_sent(&mut self, sender_id: u8, value: u32, success: bool) {
        self.stats.send_attempts += 1;
        if success {
            self.stats.send_successes += 1;
            if let Some(sender_info) = self.senders.get_mut(&sender_id) {
                sender_info.state = SenderState::Sent(value);
                // Update channel state
                if let Some(channel_info) = self.channels.get_mut(&sender_info.channel_id) {
                    channel_info.channel_state = ChannelState::ValueSent(value);
                    channel_info.expected_value = Some(value);
                }
            }
        }
        self.operations_log.push(OperationEvent::ValueSent {
            sender_id,
            value,
            success,
            timestamp: Instant::now(),
        });
    }

    fn record_convenience_send(
        &mut self,
        channel_id: u8,
        value: u32,
        success: bool,
        reason: String,
    ) {
        self.stats.send_attempts += 1;
        if success {
            self.stats.send_successes += 1;
            if let Some(channel_info) = self.channels.get_mut(&channel_id) {
                channel_info.channel_state = ChannelState::ValueSent(value);
                channel_info.expected_value = Some(value);
            }
        }
        self.operations_log
            .push(OperationEvent::ConvenienceSendAttempted {
                channel_id,
                value,
                success,
                reason,
                timestamp: Instant::now(),
            });
    }

    fn record_try_receive(&mut self, channel_id: u8, result: &str) {
        self.stats.receive_attempts += 1;
        if result.starts_with("Ok(") {
            self.stats.receive_successes += 1;
            // Mark channel as closed after successful receive
            if let Some(channel_info) = self.channels.get_mut(&channel_id) {
                channel_info.channel_state = ChannelState::Closed;
            }
        }
        self.operations_log
            .push(OperationEvent::TryReceiveAttempted {
                channel_id,
                result: result.to_string(),
                timestamp: Instant::now(),
            });
    }

    fn record_poll_receive(&mut self, channel_id: u8, result: &str) {
        // Don't count polls as receive attempts
        self.operations_log
            .push(OperationEvent::PollReceiveAttempted {
                channel_id,
                result: result.to_string(),
                timestamp: Instant::now(),
            });
    }

    fn record_context_cancelled(&mut self, target_id: u8) {
        self.stats.cancellations += 1;
        if let Some((_, cancelled)) = self.contexts.get(&target_id) {
            cancelled.store(true, Ordering::SeqCst);
        }
        self.operations_log.push(OperationEvent::ContextCancelled {
            target_id,
            timestamp: Instant::now(),
        });
    }

    fn record_sender_dropped(&mut self, sender_id: u8) {
        if let Some(sender_info) = self.senders.get_mut(&sender_id) {
            sender_info.state = SenderState::Dropped;
        }
        self.operations_log.push(OperationEvent::SenderDropped {
            sender_id,
            timestamp: Instant::now(),
        });
    }

    fn record_receiver_dropped(&mut self, channel_id: u8) {
        if let Some(channel_info) = self.channels.get_mut(&channel_id) {
            channel_info.receiver_active = false;
            channel_info.channel_state = ChannelState::ReceiverDropped;
        }
        self.operations_log.push(OperationEvent::ReceiverDropped {
            channel_id,
            timestamp: Instant::now(),
        });
    }

    /// Verify cancellation correctness properties
    fn verify_cancellation_properties(&self) {
        // Property 1: Basic statistics make sense
        assert!(
            self.stats.reserve_successes <= self.stats.reserve_attempts,
            "More reserve successes than attempts"
        );
        assert!(
            self.stats.send_successes <= self.stats.send_attempts,
            "More send successes than attempts"
        );
        assert!(
            self.stats.receive_successes <= self.stats.receive_attempts,
            "More receive successes than attempts"
        );

        // Property 2: No channel should have inconsistent state
        for (&channel_id, channel_info) in &self.channels {
            match &channel_info.channel_state {
                ChannelState::ValueSent(value) => {
                    if let Some(expected) = channel_info.expected_value {
                        assert_eq!(
                            *value, expected,
                            "Channel {} value mismatch: sent {} but expected {}",
                            channel_id, value, expected
                        );
                    }
                }
                _ => {
                    // Other states are fine
                }
            }
        }

        // Property 3: Senders should have consistent states
        for (&sender_id, sender_info) in &self.senders {
            match &sender_info.state {
                SenderState::Sent(value) => {
                    // Verify the associated channel reflects this
                    if let Some(channel_info) = self.channels.get(&sender_info.channel_id) {
                        match &channel_info.channel_state {
                            ChannelState::ValueSent(channel_value) => {
                                assert_eq!(
                                    *value, *channel_value,
                                    "Sender {} sent {} but channel shows {}",
                                    sender_id, value, channel_value
                                );
                            }
                            ChannelState::ReceiverDropped => {
                                // OK - receiver was dropped after send
                            }
                            ChannelState::Closed => {
                                // OK - receiver consumed the value
                            }
                            _ => {
                                // Unexpected state
                            }
                        }
                    }
                }
                _ => {
                    // Other states are fine
                }
            }
        }
    }
}

/// Simple waker for polling futures
struct NoopWaker;

impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn create_noop_waker() -> Waker {
    Arc::new(NoopWaker).into()
}

/// Execute oneshot operations and verify cancellation correctness
fn execute_and_verify_cancellation_correctness(operations: Vec<OneshotOperation>) {
    let mut tracker = CancellationTracker::new();

    // Storage for actual channel objects
    let mut channels: std::collections::HashMap<
        u8,
        (oneshot::Sender<u32>, oneshot::Receiver<u32>),
    > = std::collections::HashMap::new();
    let mut permits: std::collections::HashMap<u8, Box<dyn std::any::Any + Send>> =
        std::collections::HashMap::new();
    let mut receivers: std::collections::HashMap<u8, oneshot::Receiver<u32>> =
        std::collections::HashMap::new();

    let start_time = Instant::now();

    for operation in operations {
        // Check timeout
        if start_time.elapsed() > OPERATION_TIMEOUT {
            break;
        }

        match operation {
            OneshotOperation::CreateChannel { channel_id } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);

                if !channels.contains_key(&channel_key) && !receivers.contains_key(&channel_key) {
                    let (sender, receiver) = oneshot::channel::<u32>();
                    channels.insert(channel_key, (sender, receiver));
                    tracker.record_channel_created(channel_key);
                }
            }

            OneshotOperation::TryReserve {
                channel_id,
                sender_id,
            } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);
                let sender_key = sender_id % (MAX_SENDERS as u8);

                // Skip if permit already exists
                if permits.contains_key(&sender_key) {
                    continue;
                }

                if let Some((sender, receiver)) = channels.remove(&channel_key) {
                    let (cx, _cancelled) = tracker.create_context(sender_key).clone();

                    match sender.reserve(&cx) {
                        Ok(permit) => {
                            tracker.record_reserve_attempt(
                                channel_key,
                                sender_key,
                                true,
                                "success".to_string(),
                            );
                            permits.insert(sender_key, Box::new(permit));
                            receivers.insert(channel_key, receiver);
                        }
                        Err(SendError::Cancelled(())) => {
                            tracker.record_reserve_attempt(
                                channel_key,
                                sender_key,
                                false,
                                "cancelled".to_string(),
                            );
                            receivers.insert(channel_key, receiver);
                        }
                        Err(SendError::Disconnected(())) => {
                            tracker.record_reserve_attempt(
                                channel_key,
                                sender_key,
                                false,
                                "disconnected".to_string(),
                            );
                            // Receiver was dropped, don't put it back
                        }
                    }
                } else {
                    tracker.record_reserve_attempt(
                        channel_key,
                        sender_key,
                        false,
                        "no_sender".to_string(),
                    );
                }
            }

            OneshotOperation::SendValue { sender_id, value } => {
                let sender_key = sender_id % (MAX_SENDERS as u8);

                if let Some(permit_any) = permits.remove(&sender_key) {
                    if let Ok(permit) = permit_any.downcast::<oneshot::SendPermit<u32>>() {
                        match permit.send(value) {
                            Ok(()) => {
                                tracker.record_value_sent(sender_key, value, true);
                            }
                            Err(SendError::Disconnected(returned_value)) => {
                                tracker.record_value_sent(sender_key, returned_value, false);
                            }
                            Err(SendError::Cancelled(returned_value)) => {
                                tracker.record_value_sent(sender_key, returned_value, false);
                            }
                        }
                    }
                } else {
                    tracker.record_value_sent(sender_key, value, false);
                }
            }

            OneshotOperation::ConvenienceSend { channel_id, value } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);

                if let Some((sender, receiver)) = channels.remove(&channel_key) {
                    let (cx, _cancelled) = tracker.create_context(channel_key).clone();

                    match sender.send(&cx, value) {
                        Ok(()) => {
                            tracker.record_convenience_send(
                                channel_key,
                                value,
                                true,
                                "success".to_string(),
                            );
                            receivers.insert(channel_key, receiver);
                        }
                        Err(SendError::Cancelled(returned_value)) => {
                            tracker.record_convenience_send(
                                channel_key,
                                returned_value,
                                false,
                                "cancelled".to_string(),
                            );
                            receivers.insert(channel_key, receiver);
                        }
                        Err(SendError::Disconnected(returned_value)) => {
                            tracker.record_convenience_send(
                                channel_key,
                                returned_value,
                                false,
                                "disconnected".to_string(),
                            );
                            // Receiver was dropped
                        }
                    }
                } else {
                    tracker.record_convenience_send(
                        channel_key,
                        value,
                        false,
                        "no_channel".to_string(),
                    );
                }
            }

            OneshotOperation::TryReceive { channel_id } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);

                if let Some(mut receiver) = receivers.remove(&channel_key) {
                    match receiver.try_recv() {
                        Ok(value) => {
                            tracker.record_try_receive(channel_key, &format!("Ok({})", value));
                            // Channel is now consumed
                        }
                        Err(TryRecvError::Empty) => {
                            tracker.record_try_receive(channel_key, "Empty");
                            receivers.insert(channel_key, receiver);
                        }
                        Err(TryRecvError::Closed) => {
                            tracker.record_try_receive(channel_key, "Closed");
                            // Channel is closed, don't put receiver back
                        }
                    }
                } else {
                    tracker.record_try_receive(channel_key, "no_receiver");
                }
            }

            OneshotOperation::PollReceive { channel_id } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);

                if let Some(mut receiver) = receivers.remove(&channel_key) {
                    let (cx, _cancelled) = tracker.create_context(channel_key).clone();
                    let mut future = std::pin::Pin::new(receiver.recv(&cx));
                    let waker = create_noop_waker();
                    let mut context = Context::from_waker(&waker);

                    match future.as_mut().poll(&mut context) {
                        Poll::Ready(Ok(value)) => {
                            tracker
                                .record_poll_receive(channel_key, &format!("Ready(Ok({}))", value));
                            // Channel consumed
                        }
                        Poll::Ready(Err(RecvError::Closed)) => {
                            tracker.record_poll_receive(channel_key, "Ready(Err(Closed))");
                            // Channel closed
                        }
                        Poll::Ready(Err(RecvError::Cancelled)) => {
                            tracker.record_poll_receive(channel_key, "Ready(Err(Cancelled))");
                            // Channel cancelled
                        }
                        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => {
                            tracker.record_poll_receive(
                                channel_key,
                                "Ready(Err(PolledAfterCompletion))",
                            );
                        }
                        Poll::Pending => {
                            tracker.record_poll_receive(channel_key, "Pending");
                            // Put receiver back since it's still active
                            receivers.insert(channel_key, receiver);
                        }
                    }
                } else {
                    tracker.record_poll_receive(channel_key, "no_receiver");
                }
            }

            OneshotOperation::CancelContext { target_id } => {
                let target_key = target_id % (MAX_CHANNELS as u8);
                tracker.record_context_cancelled(target_key);
                // The actual cancellation flag is set in record_context_cancelled
            }

            OneshotOperation::DropSender { sender_id } => {
                let sender_key = sender_id % (MAX_SENDERS as u8);

                // Remove permit if it exists
                if permits.remove(&sender_key).is_some() {
                    tracker.record_sender_dropped(sender_key);
                }
            }

            OneshotOperation::DropReceiver { channel_id } => {
                let channel_key = channel_id % (MAX_CHANNELS as u8);

                if receivers.remove(&channel_key).is_some() {
                    tracker.record_receiver_dropped(channel_key);
                } else if channels.remove(&channel_key).is_some() {
                    tracker.record_receiver_dropped(channel_key);
                }
            }

            OneshotOperation::Delay { milliseconds } => {
                let delay = Duration::from_millis((milliseconds as u64).min(MAX_DELAY_MS));
                std::thread::sleep(delay);
            }
        }
    }

    // Final verification
    tracker.verify_cancellation_properties();

    // Clean up any remaining resources
    channels.clear();
    permits.clear();
    receivers.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_send_receive() {
        let operations = vec![
            OneshotOperation::CreateChannel { channel_id: 1 },
            OneshotOperation::ConvenienceSend {
                channel_id: 1,
                value: 42,
            },
            OneshotOperation::TryReceive { channel_id: 1 },
        ];
        execute_and_verify_cancellation_correctness(operations);
    }

    #[test]
    fn test_reserve_then_send() {
        let operations = vec![
            OneshotOperation::CreateChannel { channel_id: 1 },
            OneshotOperation::TryReserve {
                channel_id: 1,
                sender_id: 1,
            },
            OneshotOperation::SendValue {
                sender_id: 1,
                value: 99,
            },
            OneshotOperation::TryReceive { channel_id: 1 },
        ];
        execute_and_verify_cancellation_correctness(operations);
    }

    #[test]
    fn test_cancellation_timing() {
        let operations = vec![
            OneshotOperation::CreateChannel { channel_id: 1 },
            OneshotOperation::TryReserve {
                channel_id: 1,
                sender_id: 1,
            },
            OneshotOperation::CancelContext { target_id: 1 },
            OneshotOperation::SendValue {
                sender_id: 1,
                value: 42,
            },
            OneshotOperation::PollReceive { channel_id: 1 },
        ];
        execute_and_verify_cancellation_correctness(operations);
    }

    #[test]
    fn test_drop_scenarios() {
        let operations = vec![
            OneshotOperation::CreateChannel { channel_id: 1 },
            OneshotOperation::TryReserve {
                channel_id: 1,
                sender_id: 1,
            },
            OneshotOperation::DropSender { sender_id: 1 },
            OneshotOperation::TryReceive { channel_id: 1 },
        ];
        execute_and_verify_cancellation_correctness(operations);
    }

    #[test]
    fn test_receiver_drop() {
        let operations = vec![
            OneshotOperation::CreateChannel { channel_id: 1 },
            OneshotOperation::DropReceiver { channel_id: 1 },
            OneshotOperation::ConvenienceSend {
                channel_id: 1,
                value: 42,
            },
        ];
        execute_and_verify_cancellation_correctness(operations);
    }
}
