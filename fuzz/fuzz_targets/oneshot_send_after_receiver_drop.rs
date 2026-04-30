#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use asupersync::{Cx, RegionId, Budget};
use asupersync::channel::oneshot::{self, SendError};
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;

#[derive(Debug, Clone)]
struct SendDropTracker {
    operations_completed: Arc<Mutex<Vec<String>>>,
    send_result: Arc<Mutex<Option<Result<(), SendError<u32>>>>>,
    test_value: u32,
    panic_occurred: Arc<Mutex<bool>>,
}

impl SendDropTracker {
    fn new(test_value: u32) -> Self {
        Self {
            operations_completed: Arc::new(Mutex::new(Vec::new())),
            send_result: Arc::new(Mutex::new(None)),
            test_value,
            panic_occurred: Arc::new(Mutex::new(false)),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations_completed.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_send_result(&self, result: Result<(), SendError<u32>>) {
        if let Ok(mut send_result) = self.send_result.lock() {
            *send_result = Some(result);
        }
    }

    fn record_panic(&self) {
        if let Ok(mut panic_occurred) = self.panic_occurred.lock() {
            *panic_occurred = true;
        }
    }

    fn validate_invariants(&self) {
        // Check no panic occurred
        let panic_occurred = self.panic_occurred.lock().unwrap();
        assert!(!*panic_occurred, "Panic occurred during send after receiver drop");

        // Check send result
        let send_result = self.send_result.lock().unwrap();
        if let Some(result) = send_result.as_ref() {
            match result {
                Ok(()) => {
                    // This should not happen when receiver is dropped first
                    let ops = self.operations_completed.lock().unwrap();
                    panic!("Send succeeded unexpectedly. Operations: {:?}", *ops);
                }
                Err(SendError::Disconnected(value)) => {
                    // Expected: value should be preserved
                    assert_eq!(*value, self.test_value,
                        "Send error did not preserve original value. Expected: {}, got: {}",
                        self.test_value, *value);
                }
                Err(SendError::Cancelled(value)) => {
                    // This could happen if Cx is cancelled, value should still be preserved
                    assert_eq!(*value, self.test_value,
                        "Send cancelled error did not preserve original value. Expected: {}, got: {}",
                        self.test_value, *value);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
enum SendDropOperation {
    DropReceiver,
    SendValue,
    DropReceiverThenSend,
    SendThenDropReceiver,
    RapidSequence,
    DelayedOperations { send_delay_us: u16, drop_delay_us: u16 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Generate arbitrary test parameters
    let test_value: u32 = u.arbitrary().unwrap_or(42);
    let operations: Vec<SendDropOperation> = u.arbitrary().unwrap_or_else(|_| {
        vec![SendDropOperation::DropReceiverThenSend]
    });

    if operations.is_empty() {
        return;
    }

    // Create tracking infrastructure
    let tracker = SendDropTracker::new(test_value);

    // Create oneshot channel
    let cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::infinite(),
    );
    let (sender, receiver) = oneshot::channel::<u32>();

    // Execute operations based on fuzz input
    for operation in operations {
        match operation {
            SendDropOperation::DropReceiver => {
                tracker.record_operation("drop_receiver");
                drop(receiver);
                break; // Receiver dropped, further operations will fail
            }

            SendDropOperation::SendValue => {
                tracker.record_operation("send_value");
                // Install panic handler
                let tracker_clone = tracker.clone();
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |_| {
                    tracker_clone.record_panic();
                }));

                let result = std::panic::catch_unwind(|| {
                    sender.send(&cx, test_value)
                });

                std::panic::set_hook(prev_hook);

                match result {
                    Ok(send_result) => tracker.record_send_result(send_result),
                    Err(_) => tracker.record_panic(),
                }
                break; // Sender consumed
            }

            SendDropOperation::DropReceiverThenSend => {
                tracker.record_operation("drop_receiver_then_send");
                drop(receiver);

                // Install panic handler for send operation
                let tracker_clone = tracker.clone();
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |_| {
                    tracker_clone.record_panic();
                }));

                let result = std::panic::catch_unwind(|| {
                    sender.send(&cx, test_value)
                });

                std::panic::set_hook(prev_hook);

                match result {
                    Ok(send_result) => tracker.record_send_result(send_result),
                    Err(_) => tracker.record_panic(),
                }
                break;
            }

            SendDropOperation::SendThenDropReceiver => {
                tracker.record_operation("send_then_drop_receiver");

                // Install panic handler for send operation
                let tracker_clone = tracker.clone();
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |_| {
                    tracker_clone.record_panic();
                }));

                let result = std::panic::catch_unwind(|| {
                    sender.send(&cx, test_value)
                });

                std::panic::set_hook(prev_hook);

                match result {
                    Ok(send_result) => {
                        tracker.record_send_result(send_result);
                        // Drop receiver after successful send - this is the normal case
                        drop(receiver);
                    }
                    Err(_) => tracker.record_panic(),
                }
                break;
            }

            SendDropOperation::RapidSequence => {
                tracker.record_operation("rapid_sequence");

                let tracker1 = tracker.clone();
                let tracker2 = tracker.clone();

                // Spawn concurrent operations
                let send_handle = thread::spawn(move || {
                    let prev_hook = std::panic::take_hook();
                    std::panic::set_hook(Box::new(move |_| {
                        tracker1.record_panic();
                    }));

                    let result = std::panic::catch_unwind(|| {
                        sender.send(&cx, test_value)
                    });

                    std::panic::set_hook(prev_hook);

                    match result {
                        Ok(send_result) => tracker1.record_send_result(send_result),
                        Err(_) => tracker1.record_panic(),
                    }
                });

                let drop_handle = thread::spawn(move || {
                    tracker2.record_operation("concurrent_drop");
                    drop(receiver);
                });

                let _ = send_handle.join();
                let _ = drop_handle.join();
                break;
            }

            SendDropOperation::DelayedOperations { send_delay_us, drop_delay_us } => {
                tracker.record_operation("delayed_operations");

                let tracker1 = tracker.clone();
                let tracker2 = tracker.clone();

                let send_delay = Duration::from_micros(send_delay_us.min(10000) as u64);
                let drop_delay = Duration::from_micros(drop_delay_us.min(10000) as u64);

                let send_handle = thread::spawn(move || {
                    thread::sleep(send_delay);

                    let prev_hook = std::panic::take_hook();
                    std::panic::set_hook(Box::new(move |_| {
                        tracker1.record_panic();
                    }));

                    let result = std::panic::catch_unwind(|| {
                        sender.send(&cx, test_value)
                    });

                    std::panic::set_hook(prev_hook);

                    match result {
                        Ok(send_result) => tracker1.record_send_result(send_result),
                        Err(_) => tracker1.record_panic(),
                    }
                });

                let drop_handle = thread::spawn(move || {
                    thread::sleep(drop_delay);
                    tracker2.record_operation("delayed_drop");
                    drop(receiver);
                });

                let _ = send_handle.join();
                let _ = drop_handle.join();
                break;
            }
        }
    }

    // Validate all invariants
    tracker.validate_invariants();
});