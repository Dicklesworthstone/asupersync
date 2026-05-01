#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

use asupersync::channel::oneshot;
use asupersync::channel::oneshot::{SendError, RecvError};
use asupersync::cx::Cx;
use asupersync::types::cap;

#[derive(Debug, Clone)]
struct DetachedSendTracker {
    operations: Arc<Mutex<Vec<String>>>,
    send_results: Arc<Mutex<Vec<SendResult>>>,
    invariant_violations: Arc<Mutex<Vec<InvariantViolation>>>,
}

#[derive(Debug, Clone)]
struct SendResult {
    operation_id: usize,
    value_attempted: u32,
    result: SendOutcome,
    receiver_detached_before: bool,
    sender_type: SenderType,
}

#[derive(Debug, Clone, PartialEq)]
enum SendOutcome {
    Success,
    Disconnected(u32),
    Cancelled(u32),
    Panicked,
}

#[derive(Debug, Clone, PartialEq)]
enum SenderType {
    Direct,       // sender.send()
    ReserveCommit, // sender.reserve() + permit.send()
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    violation_type: String,
    description: String,
    operation_id: usize,
}

impl DetachedSendTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(Vec::new())),
            send_results: Arc::new(Mutex::new(Vec::new())),
            invariant_violations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_send_result(&self, result: SendResult) {
        if let Ok(mut results) = self.send_results.lock() {
            results.push(result);
        }
    }

    fn record_violation(&self, violation: InvariantViolation) {
        if let Ok(mut violations) = self.invariant_violations.lock() {
            violations.push(violation);
        }
    }

    fn validate_detached_send_invariants(&self) {
        if let Ok(results) = self.send_results.lock() {
            for result in results.iter() {
                // Core invariant: sending to detached receiver returns Disconnected error
                if result.receiver_detached_before {
                    match &result.result {
                        SendOutcome::Success => {
                            self.record_violation(InvariantViolation {
                                violation_type: "send_success_to_detached".to_string(),
                                description: format!(
                                    "Operation {} succeeded when sending to detached receiver",
                                    result.operation_id
                                ),
                                operation_id: result.operation_id,
                            });
                        }
                        SendOutcome::Disconnected(_) => {
                            // This is correct behavior
                        }
                        SendOutcome::Cancelled(_) => {
                            // This can happen if cx is cancelled, acceptable
                        }
                        SendOutcome::Panicked => {
                            self.record_violation(InvariantViolation {
                                violation_type: "panic_on_detached_send".to_string(),
                                description: format!(
                                    "Operation {} panicked when sending to detached receiver",
                                    result.operation_id
                                ),
                                operation_id: result.operation_id,
                            });
                        }
                    }
                }

                // Invariant: Disconnected error should return the original value
                if let SendOutcome::Disconnected(returned_value) = &result.result {
                    if *returned_value != result.value_attempted {
                        self.record_violation(InvariantViolation {
                            violation_type: "incorrect_disconnected_value".to_string(),
                            description: format!(
                                "Operation {} returned {} but attempted {}",
                                result.operation_id, returned_value, result.value_attempted
                            ),
                            operation_id: result.operation_id,
                        });
                    }
                }

                // Invariant: Cancelled error should return the original value
                if let SendOutcome::Cancelled(returned_value) = &result.result {
                    if *returned_value != result.value_attempted {
                        self.record_violation(InvariantViolation {
                            violation_type: "incorrect_cancelled_value".to_string(),
                            description: format!(
                                "Operation {} cancelled returned {} but attempted {}",
                                result.operation_id, returned_value, result.value_attempted
                            ),
                            operation_id: result.operation_id,
                        });
                    }
                }
            }
        }

        // Check for any violations and panic if found
        if let Ok(violations) = self.invariant_violations.lock() {
            if !violations.is_empty() {
                for violation in violations.iter() {
                    self.record_operation(&format!(
                        "VIOLATION: {} - {}",
                        violation.violation_type, violation.description
                    ));
                }
                panic!("Oneshot detached send invariant violations detected: {} violations", violations.len());
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct DetachedSendConfig {
    pattern: DetachPattern,
    value_range: u8, // Range for test values (0..value_range)
}

#[derive(Debug, Clone, Arbitrary)]
enum DetachPattern {
    SimpleDetachThenSend,
    SendThenDetach,
    ConcurrentDetachSend { delay_us: u16 },
    MultipleDetachSend { attempts: Vec<SendAttempt> },
    InterleavedOperations { operations: Vec<Operation> },
    ReserveDetachSend { detach_timing: DetachTiming },
    RapidSequence { sequence: Vec<RapidOp> },
}

#[derive(Debug, Clone, Arbitrary)]
struct SendAttempt {
    value: u8,
    delay_us: u16,
    use_reserve: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    CreateChannel,
    DetachReceiver,
    DirectSend { value: u8 },
    ReserveSend { value: u8 },
    CheckClosed,
    Sleep { duration_us: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
enum DetachTiming {
    BeforeReserve,
    AfterReserve,
    DuringReserve, // Concurrent
}

#[derive(Debug, Clone, Arbitrary)]
enum RapidOp {
    Send { value: u8 },
    Detach,
    CheckClosed,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: DetachedSendConfig = u.arbitrary().unwrap_or(DetachedSendConfig {
        pattern: DetachPattern::SimpleDetachThenSend,
        value_range: 10,
    });

    if config.value_range == 0 {
        return; // Avoid empty ranges
    }

    let tracker = DetachedSendTracker::new();

    // Execute the pattern
    match config.pattern {
        DetachPattern::SimpleDetachThenSend => {
            test_simple_detach_then_send(&tracker, config.value_range);
        }

        DetachPattern::SendThenDetach => {
            test_send_then_detach(&tracker, config.value_range);
        }

        DetachPattern::ConcurrentDetachSend { delay_us } => {
            test_concurrent_detach_send(&tracker, config.value_range, delay_us);
        }

        DetachPattern::MultipleDetachSend { attempts } => {
            test_multiple_detach_send(&tracker, &attempts, config.value_range);
        }

        DetachPattern::InterleavedOperations { operations } => {
            test_interleaved_operations(&tracker, operations, config.value_range);
        }

        DetachPattern::ReserveDetachSend { detach_timing } => {
            test_reserve_detach_send(&tracker, config.value_range, detach_timing);
        }

        DetachPattern::RapidSequence { sequence } => {
            test_rapid_sequence(&tracker, sequence, config.value_range);
        }
    }

    // Validate all invariants
    tracker.validate_detached_send_invariants();
});

fn test_simple_detach_then_send(tracker: &DetachedSendTracker, value_range: u8) {
    tracker.record_operation("test_simple_detach_then_send");

    let cx = Cx::<cap::All>::new();
    let (sender, receiver) = oneshot::channel::<u32>();

    // Detach receiver by dropping it
    drop(receiver);
    tracker.record_operation("receiver_detached");

    // Attempt to send - should return Disconnected error
    let value = (value_range / 2) as u32;
    let result = catch_unwind(AssertUnwindSafe(|| {
        sender.send(&cx, value)
    }));

    let outcome = match result {
        Ok(Ok(())) => SendOutcome::Success,
        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
        Err(_) => SendOutcome::Panicked,
    };

    tracker.record_send_result(SendResult {
        operation_id: 1,
        value_attempted: value,
        result: outcome,
        receiver_detached_before: true,
        sender_type: SenderType::Direct,
    });
}

fn test_send_then_detach(tracker: &DetachedSendTracker, value_range: u8) {
    tracker.record_operation("test_send_then_detach");

    let cx = Cx::<cap::All>::new();
    let (sender, receiver) = oneshot::channel::<u32>();

    // Send first - should succeed
    let value = (value_range / 2) as u32;
    let result = catch_unwind(AssertUnwindSafe(|| {
        sender.send(&cx, value)
    }));

    let outcome = match result {
        Ok(Ok(())) => SendOutcome::Success,
        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
        Err(_) => SendOutcome::Panicked,
    };

    tracker.record_send_result(SendResult {
        operation_id: 1,
        value_attempted: value,
        result: outcome,
        receiver_detached_before: false,
        sender_type: SenderType::Direct,
    });

    // Then detach receiver
    drop(receiver);
    tracker.record_operation("receiver_detached_after_send");
}

fn test_concurrent_detach_send(tracker: &DetachedSendTracker, value_range: u8, delay_us: u16) {
    tracker.record_operation("test_concurrent_detach_send");

    let cx = Cx::<cap::All>::new();
    let (sender, receiver) = oneshot::channel::<u32>();

    let tracker_clone = tracker.clone();
    let value = (value_range / 2) as u32;

    // Spawn detach thread
    let detach_handle = thread::spawn(move || {
        if delay_us > 0 {
            thread::sleep(Duration::from_micros(delay_us.min(1000) as u64));
        }
        drop(receiver);
        tracker_clone.record_operation("concurrent_receiver_detached");
    });

    // Attempt send on main thread
    let result = catch_unwind(AssertUnwindSafe(|| {
        sender.send(&cx, value)
    }));

    let outcome = match result {
        Ok(Ok(())) => SendOutcome::Success,
        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
        Err(_) => SendOutcome::Panicked,
    };

    // Wait for detach thread
    let _ = detach_handle.join();

    tracker.record_send_result(SendResult {
        operation_id: 1,
        value_attempted: value,
        result: outcome,
        receiver_detached_before: false, // We don't know the timing for concurrent case
        sender_type: SenderType::Direct,
    });
}

fn test_multiple_detach_send(tracker: &DetachedSendTracker, attempts: &[SendAttempt], value_range: u8) {
    tracker.record_operation("test_multiple_detach_send");

    if attempts.is_empty() {
        return;
    }

    let cx = Cx::<cap::All>::new();
    let (sender, receiver) = oneshot::channel::<u32>();

    // Detach receiver first
    drop(receiver);
    tracker.record_operation("receiver_detached");

    // Attempt multiple sends (only first can work due to oneshot nature, but test the pattern)
    let attempt = &attempts[0]; // Use first attempt only since sender is consumed
    let value = (attempt.value % value_range.max(1)) as u32;

    if attempt.delay_us > 0 {
        thread::sleep(Duration::from_micros(attempt.delay_us.min(1000) as u64));
    }

    let (outcome, sender_type) = if attempt.use_reserve {
        // Use reserve/commit pattern
        let reserve_result = catch_unwind(AssertUnwindSafe(|| {
            sender.reserve(&cx)
        }));

        match reserve_result {
            Ok(Ok(permit)) => {
                let send_result = catch_unwind(AssertUnwindSafe(|| {
                    permit.send(value)
                }));

                let outcome = match send_result {
                    Ok(Ok(())) => SendOutcome::Success,
                    Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                    Err(_) => SendOutcome::Panicked,
                };

                (outcome, SenderType::ReserveCommit)
            }
            Ok(Err(oneshot::SendError::Cancelled(()))) => {
                (SendOutcome::Cancelled(value), SenderType::ReserveCommit)
            }
            Ok(Err(oneshot::SendError::Disconnected(()))) => {
                (SendOutcome::Disconnected(value), SenderType::ReserveCommit)
            }
            Err(_) => (SendOutcome::Panicked, SenderType::ReserveCommit),
        }
    } else {
        // Use direct send
        let result = catch_unwind(AssertUnwindSafe(|| {
            sender.send(&cx, value)
        }));

        let outcome = match result {
            Ok(Ok(())) => SendOutcome::Success,
            Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
            Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
            Err(_) => SendOutcome::Panicked,
        };

        (outcome, SenderType::Direct)
    };

    tracker.record_send_result(SendResult {
        operation_id: 1,
        value_attempted: value,
        result: outcome,
        receiver_detached_before: true,
        sender_type,
    });
}

fn test_interleaved_operations(tracker: &DetachedSendTracker, operations: Vec<Operation>, value_range: u8) {
    tracker.record_operation("test_interleaved_operations");

    let cx = Cx::<cap::All>::new();
    let mut sender = None;
    let mut receiver = None;
    let mut receiver_detached = false;
    let mut operation_id = 0;

    for operation in operations.iter().take(20) { // Limit operations
        operation_id += 1;

        match operation {
            Operation::CreateChannel => {
                if sender.is_none() {
                    let (tx, rx) = oneshot::channel::<u32>();
                    sender = Some(tx);
                    receiver = Some(rx);
                    receiver_detached = false;
                    tracker.record_operation("channel_created");
                }
            }

            Operation::DetachReceiver => {
                if let Some(rx) = receiver.take() {
                    drop(rx);
                    receiver_detached = true;
                    tracker.record_operation("receiver_detached");
                }
            }

            Operation::DirectSend { value } => {
                if let Some(tx) = sender.take() {
                    let val = (*value % value_range.max(1)) as u32;
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        tx.send(&cx, val)
                    }));

                    let outcome = match result {
                        Ok(Ok(())) => SendOutcome::Success,
                        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
                        Err(_) => SendOutcome::Panicked,
                    };

                    tracker.record_send_result(SendResult {
                        operation_id,
                        value_attempted: val,
                        result: outcome,
                        receiver_detached_before: receiver_detached,
                        sender_type: SenderType::Direct,
                    });
                }
            }

            Operation::ReserveSend { value } => {
                if let Some(tx) = sender.take() {
                    let val = (*value % value_range.max(1)) as u32;
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        match tx.reserve(&cx) {
                            Ok(permit) => permit.send(val),
                            Err(oneshot::SendError::Cancelled(())) => Err(SendError::Cancelled(val)),
                            Err(oneshot::SendError::Disconnected(())) => Err(SendError::Disconnected(val)),
                        }
                    }));

                    let outcome = match result {
                        Ok(Ok(())) => SendOutcome::Success,
                        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
                        Err(_) => SendOutcome::Panicked,
                    };

                    tracker.record_send_result(SendResult {
                        operation_id,
                        value_attempted: val,
                        result: outcome,
                        receiver_detached_before: receiver_detached,
                        sender_type: SenderType::ReserveCommit,
                    });
                }
            }

            Operation::CheckClosed => {
                if let Some(tx) = &sender {
                    let is_closed = tx.is_closed();
                    tracker.record_operation(&format!("is_closed_{}", is_closed));
                }
            }

            Operation::Sleep { duration_us } => {
                if *duration_us > 0 {
                    thread::sleep(Duration::from_micros((*duration_us).min(500) as u64));
                }
            }
        }
    }
}

fn test_reserve_detach_send(tracker: &DetachedSendTracker, value_range: u8, detach_timing: DetachTiming) {
    tracker.record_operation("test_reserve_detach_send");

    let cx = Cx::<cap::All>::new();
    let (sender, receiver) = oneshot::channel::<u32>();
    let value = (value_range / 2) as u32;

    match detach_timing {
        DetachTiming::BeforeReserve => {
            // Detach before reserve
            drop(receiver);
            tracker.record_operation("receiver_detached_before_reserve");

            let result = catch_unwind(AssertUnwindSafe(|| {
                match sender.reserve(&cx) {
                    Ok(permit) => permit.send(value),
                    Err(oneshot::SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
                    Err(oneshot::SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
                }
            }));

            let outcome = match result {
                Ok(Ok(())) => SendOutcome::Success,
                Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
                Err(_) => SendOutcome::Panicked,
            };

            tracker.record_send_result(SendResult {
                operation_id: 1,
                value_attempted: value,
                result: outcome,
                receiver_detached_before: true,
                sender_type: SenderType::ReserveCommit,
            });
        }

        DetachTiming::AfterReserve => {
            // Reserve first
            let permit_result = catch_unwind(AssertUnwindSafe(|| {
                sender.reserve(&cx)
            }));

            match permit_result {
                Ok(Ok(permit)) => {
                    // Detach after reserve
                    drop(receiver);
                    tracker.record_operation("receiver_detached_after_reserve");

                    let result = catch_unwind(AssertUnwindSafe(|| {
                        permit.send(value)
                    }));

                    let outcome = match result {
                        Ok(Ok(())) => SendOutcome::Success,
                        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                        Err(_) => SendOutcome::Panicked,
                    };

                    tracker.record_send_result(SendResult {
                        operation_id: 1,
                        value_attempted: value,
                        result: outcome,
                        receiver_detached_before: false, // Detached after reserve
                        sender_type: SenderType::ReserveCommit,
                    });
                }
                Ok(Err(err)) => {
                    drop(receiver);
                    let outcome = match err {
                        oneshot::SendError::Cancelled(()) => SendOutcome::Cancelled(value),
                        oneshot::SendError::Disconnected(()) => SendOutcome::Disconnected(value),
                    };

                    tracker.record_send_result(SendResult {
                        operation_id: 1,
                        value_attempted: value,
                        result: outcome,
                        receiver_detached_before: true,
                        sender_type: SenderType::ReserveCommit,
                    });
                }
                Err(_) => {
                    drop(receiver);
                    tracker.record_send_result(SendResult {
                        operation_id: 1,
                        value_attempted: value,
                        result: SendOutcome::Panicked,
                        receiver_detached_before: true,
                        sender_type: SenderType::ReserveCommit,
                    });
                }
            }
        }

        DetachTiming::DuringReserve => {
            // Concurrent detach during reserve
            let tracker_clone = tracker.clone();
            let detach_handle = thread::spawn(move || {
                thread::sleep(Duration::from_micros(100)); // Small delay
                drop(receiver);
                tracker_clone.record_operation("receiver_detached_during_reserve");
            });

            let result = catch_unwind(AssertUnwindSafe(|| {
                match sender.reserve(&cx) {
                    Ok(permit) => permit.send(value),
                    Err(oneshot::SendError::Cancelled(())) => Err(SendError::Cancelled(value)),
                    Err(oneshot::SendError::Disconnected(())) => Err(SendError::Disconnected(value)),
                }
            }));

            let _ = detach_handle.join();

            let outcome = match result {
                Ok(Ok(())) => SendOutcome::Success,
                Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
                Err(_) => SendOutcome::Panicked,
            };

            tracker.record_send_result(SendResult {
                operation_id: 1,
                value_attempted: value,
                result: outcome,
                receiver_detached_before: false, // Concurrent timing unknown
                sender_type: SenderType::ReserveCommit,
            });
        }
    }
}

fn test_rapid_sequence(tracker: &DetachedSendTracker, sequence: Vec<RapidOp>, value_range: u8) {
    tracker.record_operation("test_rapid_sequence");

    let cx = Cx::<cap::All>::new();
    let mut current_channel: Option<(oneshot::Sender<u32>, Option<oneshot::Receiver<u32>>)> = None;
    let mut operation_id = 0;

    for op in sequence.iter().take(15) {
        operation_id += 1;

        match op {
            RapidOp::Send { value } => {
                if let Some((sender, receiver)) = current_channel.take() {
                    let val = (*value % value_range.max(1)) as u32;
                    let receiver_detached = receiver.is_none();

                    // Drop receiver if still present
                    drop(receiver);

                    let result = catch_unwind(AssertUnwindSafe(|| {
                        sender.send(&cx, val)
                    }));

                    let outcome = match result {
                        Ok(Ok(())) => SendOutcome::Success,
                        Ok(Err(SendError::Disconnected(returned_value))) => SendOutcome::Disconnected(returned_value),
                        Ok(Err(SendError::Cancelled(returned_value))) => SendOutcome::Cancelled(returned_value),
                        Err(_) => SendOutcome::Panicked,
                    };

                    tracker.record_send_result(SendResult {
                        operation_id,
                        value_attempted: val,
                        result: outcome,
                        receiver_detached_before: receiver_detached,
                        sender_type: SenderType::Direct,
                    });
                }
            }

            RapidOp::Detach => {
                if let Some((sender, receiver)) = current_channel.as_mut() {
                    if let Some(rx) = receiver.take() {
                        drop(rx);
                        tracker.record_operation("rapid_detach");
                    }
                }
            }

            RapidOp::CheckClosed => {
                if current_channel.is_none() {
                    let (tx, rx) = oneshot::channel::<u32>();
                    current_channel = Some((tx, Some(rx)));
                }

                if let Some((sender, _)) = &current_channel {
                    let is_closed = sender.is_closed();
                    tracker.record_operation(&format!("rapid_check_closed_{}", is_closed));
                }
            }
        }
    }
}