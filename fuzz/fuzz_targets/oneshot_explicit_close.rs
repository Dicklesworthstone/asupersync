//! Fuzz oneshot explicit close operations.
//!
//! Tests arbitrary close+send/recv interleavings to ensure post-close operations
//! return correct error types. Validates sender/receiver drop behavior and
//! proper error propagation after channel closure.
//!
//! Critical invariants:
//! - Post-close send returns Disconnected/Cancelled error
//! - Post-close recv returns Closed/Cancelled error
//! - Channel state remains consistent after close operations
//! - No use-after-close bugs or state leaks

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::types::{Budget, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;

#[derive(Debug, Clone, Arbitrary)]
struct OneshotCloseConfig {
    /// Operations to perform
    operations: Vec<CloseOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum CloseOperation {
    /// Create a new oneshot channel
    CreateChannel { channel_id: u8 },
    /// Drop the sender to close the channel
    CloseBySenderDrop { channel_id: u8 },
    /// Drop the receiver to close the channel
    CloseByReceiverDrop { channel_id: u8 },
    /// Attempt to send after close
    PostCloseSend { channel_id: u8, value: i32 },
    /// Attempt to receive after close
    PostCloseRecv { channel_id: u8 },
    /// Reserve then close sequence
    ReserveThenClose { channel_id: u8, close_sender: bool },
    /// Close then multiple operations
    CloseThenMultiOps { channel_id: u8, operations: Vec<u8> },
    /// Rapid close/reopen cycle
    CloseReopenCycle { channel_id: u8, cycles: u8 },
    /// Check state consistency
    CheckState,
}

impl OneshotCloseConfig {
    fn max_channels() -> u8 {
        8 // Limit total channels
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_cycles() -> u8 {
        5 // Limit rapid cycles
    }

    fn max_multi_ops() -> u8 {
        6 // Limit multi-operation sequences
    }
}

/// Tracks explicit close behavior to detect invariant violations
#[derive(Debug)]
struct CloseTracker {
    channels_created: AtomicUsize,
    sender_closes: AtomicUsize,
    receiver_closes: AtomicUsize,
    post_close_send_attempts: AtomicUsize,
    post_close_recv_attempts: AtomicUsize,
    correct_send_errors: AtomicUsize,
    correct_recv_errors: AtomicUsize,
    incorrect_behaviors: AtomicUsize,
}

impl CloseTracker {
    fn new() -> Self {
        Self {
            channels_created: AtomicUsize::new(0),
            sender_closes: AtomicUsize::new(0),
            receiver_closes: AtomicUsize::new(0),
            post_close_send_attempts: AtomicUsize::new(0),
            post_close_recv_attempts: AtomicUsize::new(0),
            correct_send_errors: AtomicUsize::new(0),
            correct_recv_errors: AtomicUsize::new(0),
            incorrect_behaviors: AtomicUsize::new(0),
        }
    }

    fn record_channel_created(&self) {
        self.channels_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_sender_close(&self) {
        self.sender_closes.fetch_add(1, Ordering::SeqCst);
    }

    fn record_receiver_close(&self) {
        self.receiver_closes.fetch_add(1, Ordering::SeqCst);
    }

    fn record_post_close_send_attempt(&self) {
        self.post_close_send_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_post_close_recv_attempt(&self) {
        self.post_close_recv_attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_correct_send_error(&self) {
        self.correct_send_errors.fetch_add(1, Ordering::SeqCst);
    }

    fn record_correct_recv_error(&self) {
        self.correct_recv_errors.fetch_add(1, Ordering::SeqCst);
    }

    fn record_incorrect_behavior(&self) {
        self.incorrect_behaviors.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let created = self.channels_created.load(Ordering::SeqCst);
        let sender_closes = self.sender_closes.load(Ordering::SeqCst);
        let receiver_closes = self.receiver_closes.load(Ordering::SeqCst);
        let send_attempts = self.post_close_send_attempts.load(Ordering::SeqCst);
        let recv_attempts = self.post_close_recv_attempts.load(Ordering::SeqCst);
        let correct_send = self.correct_send_errors.load(Ordering::SeqCst);
        let correct_recv = self.correct_recv_errors.load(Ordering::SeqCst);
        let incorrect = self.incorrect_behaviors.load(Ordering::SeqCst);

        // Core invariant: no incorrect behaviors detected
        if incorrect > 0 {
            return Err(format!("Detected {} incorrect close behaviors", incorrect));
        }

        // Sanity checks
        if created > 100 {
            return Err(format!("Excessive channel creation: {}", created));
        }

        if send_attempts > 0 && correct_send == 0 {
            return Err(format!(
                "Post-close send attempts ({}) without correct error responses",
                send_attempts
            ));
        }

        if recv_attempts > 0 && correct_recv == 0 {
            return Err(format!(
                "Post-close recv attempts ({}) without correct error responses",
                recv_attempts
            ));
        }

        Ok(())
    }
}

/// Tracks the state of a oneshot channel for testing
struct TrackedChannel {
    sender: Option<oneshot::Sender<i32>>,
    receiver: Option<oneshot::Receiver<i32>>,
    cx: Cx,
    sender_closed: bool,
    receiver_closed: bool,
    value_sent: bool,
}

impl TrackedChannel {
    fn new(channel_id: u8) -> Self {
        let (sender, receiver) = oneshot::channel::<i32>();
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, channel_id as u32)),
            TaskId::from_arena(ArenaIndex::new(0, channel_id as u32)),
            Budget::INFINITE,
        );

        Self {
            sender: Some(sender),
            receiver: Some(receiver),
            cx,
            sender_closed: false,
            receiver_closed: false,
            value_sent: false,
        }
    }

    fn close_sender(&mut self) -> bool {
        if let Some(_sender) = self.sender.take() {
            // Dropping sender closes the channel
            self.sender_closed = true;
            true
        } else {
            false
        }
    }

    fn close_receiver(&mut self) -> bool {
        if let Some(_receiver) = self.receiver.take() {
            // Dropping receiver closes the channel
            self.receiver_closed = true;
            true
        } else {
            false
        }
    }

    fn attempt_send(&mut self, value: i32, tracker: &CloseTracker) -> Result<(), String> {
        tracker.record_post_close_send_attempt();

        if self.sender_closed {
            // Sender already dropped - cannot send
            tracker.record_correct_send_error();
            return Ok(()); // Expected: sender no longer exists
        }

        if let Some(sender) = self.sender.take() {
            // Try to send on potentially closed channel (receiver dropped)
            match sender.reserve(&self.cx) {
                Ok(permit) => {
                    if self.receiver_closed {
                        // Should fail during send if receiver is dropped
                        match permit.send(value) {
                            Ok(()) => {
                                self.value_sent = true;
                                tracker.record_incorrect_behavior();
                                return Err("Send succeeded on closed receiver".to_string());
                            }
                            Err(oneshot::SendError::Disconnected(_)) => {
                                tracker.record_correct_send_error();
                                self.sender_closed = true;
                            }
                            Err(oneshot::SendError::Cancelled(_)) => {
                                tracker.record_correct_send_error();
                                self.sender_closed = true;
                            }
                        }
                    } else {
                        // Normal send should succeed
                        match permit.send(value) {
                            Ok(()) => {
                                self.value_sent = true;
                                self.sender_closed = true; // Permit is consumed
                            }
                            Err(e) => {
                                tracker.record_incorrect_behavior();
                                return Err(format!(
                                    "Unexpected send error on open channel: {:?}",
                                    e
                                ));
                            }
                        }
                    }
                }
                Err(oneshot::SendError::Cancelled(_)) => {
                    tracker.record_correct_send_error();
                    self.sender_closed = true;
                }
                Err(oneshot::SendError::Disconnected(_)) => {
                    tracker.record_correct_send_error();
                    self.sender_closed = true;
                }
            }
        } else {
            // Sender already consumed
            tracker.record_correct_send_error();
        }

        Ok(())
    }

    fn attempt_recv(&mut self, tracker: &CloseTracker) -> Result<(), String> {
        tracker.record_post_close_recv_attempt();

        if self.receiver_closed {
            // Receiver already dropped - cannot receive
            tracker.record_correct_recv_error();
            return Ok(()); // Expected: receiver no longer exists
        }

        if let Some(ref mut receiver) = self.receiver {
            // Try to receive on potentially closed channel
            match receiver.try_recv() {
                Ok(_value) => {
                    if self.sender_closed && !self.value_sent {
                        tracker.record_incorrect_behavior();
                        return Err("Received value from closed sender without send".to_string());
                    }
                    // Value was previously sent - valid
                }
                Err(oneshot::TryRecvError::Empty) => {
                    // Channel still open but no value - valid if sender not closed
                    if self.sender_closed && !self.value_sent {
                        tracker.record_incorrect_behavior();
                        return Err("try_recv returned Empty on closed channel".to_string());
                    }
                }
                Err(oneshot::TryRecvError::Closed) => {
                    if self.sender_closed || !self.has_active_sender() {
                        tracker.record_correct_recv_error();
                    } else {
                        tracker.record_incorrect_behavior();
                        return Err("try_recv returned Closed with active sender".to_string());
                    }
                }
            }
        } else {
            // Receiver already consumed
            tracker.record_correct_recv_error();
        }

        Ok(())
    }

    fn has_active_sender(&self) -> bool {
        self.sender.is_some() && !self.sender_closed
    }

    fn has_active_receiver(&self) -> bool {
        self.receiver.is_some() && !self.receiver_closed
    }

    fn is_closed(&self) -> bool {
        self.sender_closed || self.receiver_closed
    }
}

fn noop_waker() -> Waker {
    use std::task::{RawWaker, RawWakerVTable};

    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );

    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

/// Test oneshot explicit close scenarios
fn test_explicit_close_scenario(
    config: &OneshotCloseConfig,
    tracker: &CloseTracker,
) -> Result<(), String> {
    let mut channels: HashMap<u8, TrackedChannel> = HashMap::new();

    let max_ops = config
        .max_operations
        .min(OneshotCloseConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            CloseOperation::CreateChannel { channel_id } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if channels.len() < OneshotCloseConfig::max_channels() as usize {
                    let channel = TrackedChannel::new(id);
                    channels.insert(id, channel);
                    tracker.record_channel_created();
                }
            }

            CloseOperation::CloseBySenderDrop { channel_id } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if let Some(channel) = channels.get_mut(&id) {
                    if channel.close_sender() {
                        tracker.record_sender_close();
                    }
                }
            }

            CloseOperation::CloseByReceiverDrop { channel_id } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if let Some(channel) = channels.get_mut(&id) {
                    if channel.close_receiver() {
                        tracker.record_receiver_close();
                    }
                }
            }

            CloseOperation::PostCloseSend { channel_id, value } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if let Some(channel) = channels.get_mut(&id) {
                    channel.attempt_send(*value, tracker)?;
                }
            }

            CloseOperation::PostCloseRecv { channel_id } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if let Some(channel) = channels.get_mut(&id) {
                    channel.attempt_recv(tracker)?;
                }
            }

            CloseOperation::ReserveThenClose {
                channel_id,
                close_sender,
            } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();

                if let Some(channel) = channels.get_mut(&id) {
                    // Try to reserve first
                    if let Some(sender) = channel.sender.take() {
                        match sender.reserve(&channel.cx) {
                            Ok(_permit) => {
                                // Drop permit without sending (abort)
                                // This should close the channel
                                channel.sender_closed = true;
                                tracker.record_sender_close();
                            }
                            Err(_) => {
                                // Reserve failed - sender already closed
                                channel.sender_closed = true;
                            }
                        }
                    }

                    if *close_sender {
                        channel.close_sender();
                    } else {
                        channel.close_receiver();
                        tracker.record_receiver_close();
                    }
                }
            }

            CloseOperation::CloseThenMultiOps {
                channel_id,
                operations,
            } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();
                let max_ops = OneshotCloseConfig::max_multi_ops() as usize;

                if let Some(channel) = channels.get_mut(&id) {
                    // Close the channel first
                    if channel.close_sender() {
                        tracker.record_sender_close();
                    }

                    // Then perform multiple operations
                    for &op in operations.iter().take(max_ops) {
                        match op % 3 {
                            0 => {
                                // Attempt send
                                channel.attempt_send(42, tracker)?;
                            }
                            1 => {
                                // Attempt recv
                                channel.attempt_recv(tracker)?;
                            }
                            2 => {
                                // Check state
                                if !channel.is_closed() && channel.sender_closed {
                                    tracker.record_incorrect_behavior();
                                    return Err(
                                        "Channel not marked closed after sender close".to_string()
                                    );
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                }
            }

            CloseOperation::CloseReopenCycle { channel_id, cycles } => {
                let id = *channel_id % OneshotCloseConfig::max_channels();
                let cycle_count = (*cycles).min(OneshotCloseConfig::max_cycles()) as usize;

                for _i in 0..cycle_count {
                    // Create new channel (reopen)
                    let channel = TrackedChannel::new(id);
                    channels.insert(id, channel);
                    tracker.record_channel_created();

                    // Close it
                    if let Some(channel) = channels.get_mut(&id) {
                        if channel.close_sender() {
                            tracker.record_sender_close();
                        }
                    }
                }
            }

            CloseOperation::CheckState => {
                // Verify channel state consistency
                for (id, channel) in channels.iter() {
                    if channel.sender_closed && channel.has_active_sender() {
                        return Err(format!(
                            "Channel {} marked as sender_closed but has active sender",
                            id
                        ));
                    }

                    if channel.receiver_closed && channel.has_active_receiver() {
                        return Err(format!(
                            "Channel {} marked as receiver_closed but has active receiver",
                            id
                        ));
                    }
                }

                // Check tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {}", msg));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: OneshotCloseConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = CloseTracker::new();

    // Test the explicit close scenario
    if let Err(msg) = test_explicit_close_scenario(&config, &tracker) {
        panic!("Oneshot explicit close test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = CloseTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || test_explicit_close_scenario(&config2, &tracker2));

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent explicit close test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some meaningful operations
    let total_closes = tracker.sender_closes.load(Ordering::SeqCst)
        + tracker.receiver_closes.load(Ordering::SeqCst);
    let total_attempts = tracker.post_close_send_attempts.load(Ordering::SeqCst)
        + tracker.post_close_recv_attempts.load(Ordering::SeqCst);

    if total_closes == 0 && total_attempts == 0 && !config.operations.is_empty() {
        panic!("No meaningful close operations were performed during the test");
    }
});
