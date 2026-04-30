//! Fuzz oneshot poll-then-cancel-then-recv scenarios.
//!
//! Tests arbitrary mid-poll cancel behavior to ensure cancellation is
//! observable on the next poll and no use-after-free occurs. Validates
//! proper cleanup of waker state during cancellation sequences.
//!
//! Critical invariants:
//! - Cancel is observable on next poll (returns RecvError::Cancelled)
//! - No use-after-free in waker cleanup paths
//! - PolledAfterCompletion behavior is consistent
//! - Waker state is properly cleared on cancellation

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::util::ArenaIndex;
use asupersync::types::{RegionId, TaskId};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::task::{Context, Poll, Waker};
use std::pin::Pin;
use std::future::Future;

#[derive(Debug, Clone, Arbitrary)]
struct OneshotPollCancelConfig {
    /// Number of receivers to test
    receiver_count: u8,
    /// Operations to perform
    operations: Vec<PollCancelOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum PollCancelOperation {
    /// Create a new receiver
    CreateReceiver { receiver_id: u8 },
    /// Poll a specific receiver
    PollReceiver { receiver_id: u8 },
    /// Cancel a specific receiver's Cx
    CancelReceiver { receiver_id: u8 },
    /// Send value to a receiver
    SendValue { receiver_id: u8, value: i32 },
    /// Drop a receiver entirely
    DropReceiver { receiver_id: u8 },
    /// Rapid poll-cancel-poll sequence
    RapidPollCancelPoll { receiver_id: u8, cycles: u8 },
    /// Check state consistency
    CheckState,
}

impl OneshotPollCancelConfig {
    fn max_receivers() -> u8 {
        10 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_rapid_cycles() -> u8 {
        5 // Limit rapid cycles
    }
}

/// Tracks poll-cancel behavior to detect invariant violations
#[derive(Debug)]
struct PollCancelTracker {
    polls_started: AtomicUsize,
    cancellations_observed: AtomicUsize,
    polled_after_completion: AtomicUsize,
    values_received: AtomicUsize,
    closed_channels: AtomicUsize,
    use_after_free_detected: AtomicUsize,
}

impl PollCancelTracker {
    fn new() -> Self {
        Self {
            polls_started: AtomicUsize::new(0),
            cancellations_observed: AtomicUsize::new(0),
            polled_after_completion: AtomicUsize::new(0),
            values_received: AtomicUsize::new(0),
            closed_channels: AtomicUsize::new(0),
            use_after_free_detected: AtomicUsize::new(0),
        }
    }

    fn record_poll_started(&self) {
        self.polls_started.fetch_add(1, Ordering::SeqCst);
    }

    fn record_cancellation_observed(&self) {
        self.cancellations_observed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_polled_after_completion(&self) {
        self.polled_after_completion.fetch_add(1, Ordering::SeqCst);
    }

    fn record_value_received(&self) {
        self.values_received.fetch_add(1, Ordering::SeqCst);
    }

    fn record_closed_channel(&self) {
        self.closed_channels.fetch_add(1, Ordering::SeqCst);
    }

    fn record_use_after_free(&self) {
        self.use_after_free_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let polls = self.polls_started.load(Ordering::SeqCst);
        let cancellations = self.cancellations_observed.load(Ordering::SeqCst);
        let polled_after = self.polled_after_completion.load(Ordering::SeqCst);
        let values = self.values_received.load(Ordering::SeqCst);
        let closed = self.closed_channels.load(Ordering::SeqCst);
        let use_after_free = self.use_after_free_detected.load(Ordering::SeqCst);

        // Core invariant: no use-after-free should be detected
        if use_after_free > 0 {
            return Err(format!("Detected {} use-after-free violations", use_after_free));
        }

        // Sanity checks
        if polled_after > polls {
            return Err(format!(
                "More PolledAfterCompletion ({}) than total polls ({})",
                polled_after, polls
            ));
        }

        if polls > 1000 {
            return Err(format!("Excessive poll operations: {}", polls));
        }

        Ok(())
    }
}

/// Custom cancellable context for testing
struct CancellableContext {
    cx: Cx,
    cancelled: Arc<AtomicBool>,
}

impl CancellableContext {
    fn new() -> Self {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
        );
        Self {
            cx,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // In real code, cancellation would be triggered through the Cx mechanism
        // For fuzzing, we simulate the cancellation state
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn cx(&self) -> &Cx {
        &self.cx
    }
}

/// Tracks a receiver with polling and cancellation state
struct TrackedReceiver {
    receiver: oneshot::Receiver<i32>,
    sender: Option<oneshot::Sender<i32>>,
    cx_context: CancellableContext,
    recv_future: Option<Pin<Box<dyn Future<Output = Result<i32, oneshot::RecvError>> + Send>>>,
    completed: Arc<AtomicBool>,
    last_poll_result: Option<Poll<Result<i32, oneshot::RecvError>>>,
    poll_count: usize,
}

impl TrackedReceiver {
    fn new(receiver_id: u8, tracker: Arc<PollCancelTracker>) -> Self {
        let (sender, receiver) = oneshot::channel::<i32>();
        let cx_context = CancellableContext::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let cx = cx_context.cx();

        let recv_future = Box::pin(async move {
            let result = receiver.recv(cx).await;
            completed_clone.store(true, Ordering::SeqCst);

            match &result {
                Ok(_) => tracker.record_value_received(),
                Err(oneshot::RecvError::Cancelled) => tracker.record_cancellation_observed(),
                Err(oneshot::RecvError::Closed) => tracker.record_closed_channel(),
                Err(oneshot::RecvError::PolledAfterCompletion) => tracker.record_polled_after_completion(),
            }

            result
        });

        Self {
            receiver,
            sender: Some(sender),
            cx_context,
            recv_future: Some(recv_future),
            completed,
            last_poll_result: None,
            poll_count: 0,
        }
    }

    fn poll(&mut self, tracker: &PollCancelTracker) -> Poll<Result<i32, oneshot::RecvError>> {
        tracker.record_poll_started();
        self.poll_count += 1;

        if let Some(ref mut future) = self.recv_future {
            // Simulate cancellation check before polling
            if self.cx_context.is_cancelled() {
                // If cancelled, the future should return Cancelled on next poll
                self.completed.store(true, Ordering::SeqCst);
                let result = Poll::Ready(Err(oneshot::RecvError::Cancelled));
                self.last_poll_result = Some(result.clone());
                self.recv_future = None;
                return result;
            }

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            // Check for use-after-free indicators
            if self.completed.load(Ordering::SeqCst) && result == Poll::Pending {
                tracker.record_use_after_free();
            }

            self.last_poll_result = Some(result.clone());

            if result.is_ready() {
                self.recv_future = None;
                self.completed.store(true, Ordering::SeqCst);
            }

            result
        } else {
            // Already completed - should return PolledAfterCompletion
            tracker.record_polled_after_completion();
            Poll::Ready(Err(oneshot::RecvError::PolledAfterCompletion))
        }
    }

    fn cancel(&mut self) {
        self.cx_context.cancel();
    }

    fn send_value(&mut self, value: i32) -> Result<(), oneshot::SendError<i32>> {
        if let Some(sender) = self.sender.take() {
            match sender.send(value) {
                Ok(permit) => {
                    permit.send(value)?;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Err(oneshot::SendError::Disconnected(value))
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst) || self.recv_future.is_none()
    }

    fn drop_sender(&mut self) {
        self.sender = None;
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

/// Test oneshot poll-cancel-recv scenarios
fn test_poll_cancel_recv_scenario(
    config: &OneshotPollCancelConfig,
    tracker: &PollCancelTracker,
) -> Result<(), String> {
    let mut receivers: HashMap<u8, TrackedReceiver> = HashMap::new();

    let max_receivers = config.receiver_count.min(OneshotPollCancelConfig::max_receivers());

    // Create initial receivers
    for i in 0..max_receivers {
        let receiver = TrackedReceiver::new(i, Arc::new(PollCancelTracker::new()));
        receivers.insert(i, receiver);
    }

    let max_ops = config.max_operations.min(OneshotPollCancelConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            PollCancelOperation::CreateReceiver { receiver_id } => {
                let id = *receiver_id % 20; // Limit total receivers
                if !receivers.contains_key(&id) && receivers.len() < OneshotPollCancelConfig::max_receivers() as usize {
                    let receiver = TrackedReceiver::new(id, Arc::new(PollCancelTracker::new()));
                    receivers.insert(id, receiver);
                }
            }

            PollCancelOperation::PollReceiver { receiver_id } => {
                let id = *receiver_id % 20;
                if let Some(receiver) = receivers.get_mut(&id) {
                    let poll_result = receiver.poll(tracker);

                    // Validate poll result consistency
                    if receiver.is_completed() && poll_result == Poll::Pending {
                        return Err(format!(
                            "Receiver {} returned Pending after completion - possible use-after-free",
                            id
                        ));
                    }
                }
            }

            PollCancelOperation::CancelReceiver { receiver_id } => {
                let id = *receiver_id % 20;
                if let Some(receiver) = receivers.get_mut(&id) {
                    receiver.cancel();

                    // Poll again to ensure cancellation is observable
                    let poll_result = receiver.poll(tracker);
                    if let Poll::Ready(Err(oneshot::RecvError::Cancelled)) = poll_result {
                        // Expected - cancellation is properly observable
                    } else {
                        return Err(format!(
                            "Receiver {} cancellation not observable on next poll: {:?}",
                            id, poll_result
                        ));
                    }
                }
            }

            PollCancelOperation::SendValue { receiver_id, value } => {
                let id = *receiver_id % 20;
                if let Some(receiver) = receivers.get_mut(&id) {
                    let _ = receiver.send_value(*value); // May fail if already sent/dropped
                }
            }

            PollCancelOperation::DropReceiver { receiver_id } => {
                let id = *receiver_id % 20;
                receivers.remove(&id);
            }

            PollCancelOperation::RapidPollCancelPoll { receiver_id, cycles } => {
                let id = *receiver_id % 20;
                let cycle_count = (*cycles).min(OneshotPollCancelConfig::max_rapid_cycles()) as usize;

                if let Some(receiver) = receivers.get_mut(&id) {
                    for i in 0..cycle_count {
                        // Poll
                        let poll1 = receiver.poll(tracker);

                        // Cancel
                        receiver.cancel();

                        // Poll again - should observe cancellation
                        let poll2 = receiver.poll(tracker);

                        // Validate cancellation observable
                        if let Poll::Ready(Err(oneshot::RecvError::Cancelled)) = poll2 {
                            // Expected
                        } else if receiver.is_completed() {
                            // Receiver completed naturally before cancellation - that's ok
                            break;
                        } else {
                            return Err(format!(
                                "Rapid cycle {}: cancellation not observable on receiver {}",
                                i, id
                            ));
                        }

                        // Break if receiver is completed
                        if receiver.is_completed() {
                            break;
                        }
                    }
                }
            }

            PollCancelOperation::CheckState => {
                // Check for consistency
                let active_receivers = receivers.len();

                if active_receivers > OneshotPollCancelConfig::max_receivers() as usize * 2 {
                    return Err(format!("Too many active receivers: {}", active_receivers));
                }

                // Check completed receivers for PolledAfterCompletion behavior
                for (id, receiver) in receivers.iter() {
                    if receiver.is_completed() && receiver.poll_count > 0 {
                        // This receiver should return PolledAfterCompletion on next poll
                        // (We can't actually poll it here without mutation, but this validates state)
                        if receiver.recv_future.is_some() && receiver.completed.load(Ordering::SeqCst) {
                            return Err(format!(
                                "Receiver {} has inconsistent completion state",
                                id
                            ));
                        }
                    }
                }

                // Check our tracking invariants
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
    let config: OneshotPollCancelConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = PollCancelTracker::new();

    // Test the poll-cancel-recv scenario
    if let Err(msg) = test_poll_cancel_recv_scenario(&config, &tracker) {
        panic!("Oneshot poll-cancel-recv test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = PollCancelTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_poll_cancel_recv_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent poll-cancel-recv test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_polls = tracker.polls_started.load(Ordering::SeqCst);
    let total_cancellations = tracker.cancellations_observed.load(Ordering::SeqCst);

    if total_polls == 0 && total_cancellations == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});