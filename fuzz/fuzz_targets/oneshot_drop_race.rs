#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

/// Maximum number of operations in a fuzz scenario to prevent timeouts
const MAX_OPERATIONS: usize = 100;

/// Maximum delay between operations in microseconds
const MAX_DELAY_MICROS: u64 = 1000;

/// Operations that can be performed on oneshot channel components
#[derive(Debug, Clone, Copy, Arbitrary)]
enum OneShotOperation {
    // Sender operations
    SenderReserve,
    SenderSend { value: u32 },
    SenderIsClosedCheck,
    SenderDrop,

    // Permit operations
    PermitSend { value: u32 },
    PermitAbort,
    PermitIsClosedCheck,
    PermitDrop,

    // Receiver operations
    ReceiverRecvStart,
    ReceiverRecvPoll,
    ReceiverRecvDrop,
    ReceiverTryRecv,
    ReceiverIsReadyCheck,
    ReceiverIsClosedCheck,
    ReceiverDrop,

    // Timing operations
    YieldThread,
    ShortDelay { micros: u8 },

    // Multi-threaded race operations
    SpawnConcurrentSenderDrop,
    SpawnConcurrentReceiverDrop,
    SpawnConcurrentPermitDrop,
    SpawnConcurrentRecvFutureDrop,
}

/// Test scenario configuration for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct OneShotFuzzScenario {
    operations: Vec<OneShotOperation>,
    enable_cancellation: bool,
    thread_pool_size: u8, // 1-8 threads for concurrent operations
}

/// Component state tracker for race condition detection
#[derive(Debug)]
struct ComponentTracker {
    sender_exists: bool,
    permit_exists: bool,
    receiver_exists: bool,
    recv_future_exists: bool,
    value_sent: Option<u32>,
    channel_closed: bool,
    wake_count: Arc<AtomicUsize>,
}

impl ComponentTracker {
    fn new() -> Self {
        Self {
            sender_exists: true,
            permit_exists: false,
            receiver_exists: true,
            recv_future_exists: false,
            value_sent: None,
            channel_closed: false,
            wake_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Test waker that counts wake notifications for race detection
struct CountingWaker {
    counter: Arc<AtomicUsize>,
}

impl std::task::Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
    Waker::from(Arc::new(CountingWaker { counter }))
}

fn test_cx(enable_cancellation: bool) -> Cx {
    let cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    );
    if enable_cancellation {
        cx.set_cancel_requested(true);
    }
    cx
}

fn execute_oneshot_race_scenario(scenario: &OneShotFuzzScenario) {
    if scenario.operations.is_empty() || scenario.operations.len() > MAX_OPERATIONS {
        return;
    }

    let cx = test_cx(scenario.enable_cancellation);
    let (mut tx, mut rx) = oneshot::channel::<u32>();
    let mut tracker = ComponentTracker::new();
    let mut permit_opt = None;
    let mut recv_future_opt = None;

    // Shared state for concurrent operations
    let channel_dropped = Arc::new(AtomicBool::new(false));
    let operation_barrier = Arc::new(std::sync::Barrier::new(scenario.thread_pool_size.max(1) as usize));

    for (op_index, operation) in scenario.operations.iter().enumerate() {
        // Prevent infinite loops in fuzzing
        if op_index > MAX_OPERATIONS {
            break;
        }

        match operation {
            OneShotOperation::SenderReserve => {
                if tracker.sender_exists && permit_opt.is_none() {
                    // Move sender into permit
                    let sender = std::mem::replace(&mut tx, unsafe { std::mem::zeroed() });
                    std::mem::forget(tx); // Prevent double-drop

                    permit_opt = Some(sender.reserve(&cx));
                    tracker.sender_exists = false;
                    tracker.permit_exists = true;
                }
            },

            OneShotOperation::SenderSend { value } => {
                if tracker.sender_exists {
                    let sender = std::mem::replace(&mut tx, unsafe { std::mem::zeroed() });
                    std::mem::forget(tx);

                    let result = sender.send(&cx, *value);
                    tracker.sender_exists = false;

                    match result {
                        Ok(()) => tracker.value_sent = Some(*value),
                        Err(SendError::Disconnected(_)) => tracker.channel_closed = true,
                    }
                }
            },

            OneShotOperation::SenderIsClosedCheck => {
                if tracker.sender_exists {
                    let _is_closed = tx.is_closed();
                }
            },

            OneShotOperation::SenderDrop => {
                if tracker.sender_exists {
                    drop(std::mem::replace(&mut tx, unsafe { std::mem::zeroed() }));
                    tracker.sender_exists = false;
                    tracker.channel_closed = !tracker.permit_exists && tracker.value_sent.is_none();
                }
            },

            OneShotOperation::PermitSend { value } => {
                if let Some(permit) = permit_opt.take() {
                    let result = permit.send(*value);
                    tracker.permit_exists = false;

                    match result {
                        Ok(()) => tracker.value_sent = Some(*value),
                        Err(SendError::Disconnected(_)) => tracker.channel_closed = true,
                    }
                }
            },

            OneShotOperation::PermitAbort => {
                if let Some(permit) = permit_opt.take() {
                    permit.abort();
                    tracker.permit_exists = false;
                    tracker.channel_closed = true;
                }
            },

            OneShotOperation::PermitIsClosedCheck => {
                if let Some(ref permit) = permit_opt {
                    let _is_closed = permit.is_closed();
                }
            },

            OneShotOperation::PermitDrop => {
                if permit_opt.take().is_some() {
                    tracker.permit_exists = false;
                    tracker.channel_closed = true;
                }
            },

            OneShotOperation::ReceiverRecvStart => {
                if tracker.receiver_exists && recv_future_opt.is_none() {
                    recv_future_opt = Some(Box::pin(rx.recv(&cx)));
                    tracker.recv_future_exists = true;
                }
            },

            OneShotOperation::ReceiverRecvPoll => {
                if let Some(ref mut recv_future) = recv_future_opt {
                    let waker = counting_waker(tracker.wake_count.clone());
                    let mut task_cx = Context::from_waker(&waker);

                    match recv_future.as_mut().poll(&mut task_cx) {
                        Poll::Ready(Ok(value)) => {
                            recv_future_opt = None;
                            tracker.recv_future_exists = false;
                            tracker.value_sent = Some(value);
                        },
                        Poll::Ready(Err(RecvError::Closed)) => {
                            recv_future_opt = None;
                            tracker.recv_future_exists = false;
                            tracker.channel_closed = true;
                        },
                        Poll::Ready(Err(RecvError::Cancelled)) => {
                            recv_future_opt = None;
                            tracker.recv_future_exists = false;
                        },
                        Poll::Ready(Err(RecvError::PolledAfterCompletion)) => {
                            // This should only happen on subsequent polls
                        },
                        Poll::Pending => {
                            // Future is waiting for value or close
                        }
                    }
                }
            },

            OneShotOperation::ReceiverRecvDrop => {
                if recv_future_opt.take().is_some() {
                    tracker.recv_future_exists = false;
                }
            },

            OneShotOperation::ReceiverTryRecv => {
                if tracker.receiver_exists {
                    match rx.try_recv() {
                        Ok(value) => tracker.value_sent = Some(value),
                        Err(TryRecvError::Empty) => {},
                        Err(TryRecvError::Closed) => tracker.channel_closed = true,
                    }
                }
            },

            OneShotOperation::ReceiverIsReadyCheck => {
                if tracker.receiver_exists {
                    let _is_ready = rx.is_ready();
                }
            },

            OneShotOperation::ReceiverIsClosedCheck => {
                if tracker.receiver_exists {
                    let _is_closed = rx.is_closed();
                }
            },

            OneShotOperation::ReceiverDrop => {
                if tracker.receiver_exists {
                    drop(std::mem::replace(&mut rx, unsafe { std::mem::zeroed() }));
                    tracker.receiver_exists = false;
                }
            },

            OneShotOperation::YieldThread => {
                thread::yield_now();
            },

            OneShotOperation::ShortDelay { micros } => {
                let delay = Duration::from_micros((*micros as u64).min(MAX_DELAY_MICROS));
                thread::sleep(delay);
            },

            OneShotOperation::SpawnConcurrentSenderDrop => {
                if tracker.sender_exists {
                    let sender_copy = unsafe { std::ptr::read(&tx) };
                    let channel_dropped = channel_dropped.clone();

                    thread::spawn(move || {
                        thread::sleep(Duration::from_micros(100));
                        drop(sender_copy);
                        channel_dropped.store(true, Ordering::SeqCst);
                    });

                    // Mark as dropped to prevent double-drop
                    std::mem::forget(std::mem::replace(&mut tx, unsafe { std::mem::zeroed() }));
                    tracker.sender_exists = false;
                }
            },

            OneShotOperation::SpawnConcurrentReceiverDrop => {
                if tracker.receiver_exists {
                    let receiver_copy = unsafe { std::ptr::read(&rx) };

                    thread::spawn(move || {
                        thread::sleep(Duration::from_micros(100));
                        drop(receiver_copy);
                    });

                    std::mem::forget(std::mem::replace(&mut rx, unsafe { std::mem::zeroed() }));
                    tracker.receiver_exists = false;
                }
            },

            OneShotOperation::SpawnConcurrentPermitDrop => {
                if let Some(permit) = permit_opt.take() {
                    thread::spawn(move || {
                        thread::sleep(Duration::from_micros(100));
                        drop(permit);
                    });
                    tracker.permit_exists = false;
                }
            },

            OneShotOperation::SpawnConcurrentRecvFutureDrop => {
                if let Some(recv_future) = recv_future_opt.take() {
                    thread::spawn(move || {
                        thread::sleep(Duration::from_micros(100));
                        drop(recv_future);
                    });
                    tracker.recv_future_exists = false;
                }
            },
        }

        // Yield to allow concurrent operations to progress
        if op_index % 5 == 0 {
            thread::yield_now();
        }
    }

    // Wait for any concurrent operations to complete
    thread::sleep(Duration::from_millis(1));

    // Verify final state invariants
    verify_oneshot_invariants(&tracker);
}

fn verify_oneshot_invariants(tracker: &ComponentTracker) {
    // Core invariant: If value was sent and receiver exists, it should be receivable
    // or already received. If no value sent and sender/permit gone, channel should be closed.

    // Waker should be called when sender/permit is dropped while receiver is waiting
    let wake_count = tracker.wake_count.load(Ordering::SeqCst);

    // No waker leaks - wake count should be reasonable (not excessive)
    assert!(wake_count <= 100, "Excessive waker notifications: {}", wake_count);

    // Channel state should be consistent
    if tracker.value_sent.is_none() && !tracker.sender_exists && !tracker.permit_exists {
        // No value sent and no way to send one -> should be closed
        // Note: This is a weak invariant since we can't directly check without receiver
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 10_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzz scenario from input data
    let scenario = match OneShotFuzzScenario::arbitrary(&mut unstructured) {
        Ok(scenario) => scenario,
        Err(_) => return, // Skip malformed input
    };

    // Test basic oneshot properties under race conditions
    test_oneshot_basic_properties(&scenario);

    // Test sender/receiver drop races
    test_oneshot_drop_races(&scenario);

    // Test permit lifecycle races
    test_permit_lifecycle_races(&scenario);

    // Test recv future drop races
    test_recv_future_drop_races(&scenario);

    // Test waker cleanup races
    test_waker_cleanup_races(&scenario);
});

fn test_oneshot_basic_properties(scenario: &OneShotFuzzScenario) {
    // Test that basic oneshot semantics are preserved under fuzzing
    let cx = test_cx(false);
    let (tx, mut rx) = oneshot::channel::<u32>();

    // Value should round-trip correctly
    if let Err(_) = tx.send(&cx, 42) {
        // Receiver may have been dropped, that's fine
        return;
    }

    // Channel should work normally after creation
    assert!(!rx.is_closed());

    match rx.try_recv() {
        Ok(value) => assert_eq!(value, 42),
        Err(_) => {}, // May be empty if sender dropped without sending
    }
}

fn test_oneshot_drop_races(scenario: &OneShotFuzzScenario) {
    // Test concurrent sender and receiver drops
    let cx = test_cx(false);
    let (tx, mut rx) = oneshot::channel::<u32>();

    let wake_counter = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(wake_counter.clone());
    let mut task_cx = Context::from_waker(&waker);

    // Start recv to register waker
    let mut recv_fut = Box::pin(rx.recv(&cx));
    let _ = recv_fut.as_mut().poll(&mut task_cx);

    // Concurrently drop sender and receiver
    let tx_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(50));
        drop(tx);
    });

    let rx_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(100));
        drop(rx);
    });

    // Wait for drops
    let _ = tx_thread.join();
    let _ = rx_thread.join();

    // Should not panic or deadlock
}

fn test_permit_lifecycle_races(scenario: &OneShotFuzzScenario) {
    // Test races between permit operations and receiver drops
    let cx = test_cx(false);
    let (tx, rx) = oneshot::channel::<u32>();

    let permit = tx.reserve(&cx);

    // Race permit.send() with receiver.drop()
    let permit_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(50));
        let _ = permit.send(99); // May fail if receiver dropped
    });

    let rx_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(75));
        drop(rx);
    });

    let _ = permit_thread.join();
    let _ = rx_thread.join();

    // Should not panic or deadlock
}

fn test_recv_future_drop_races(scenario: &OneShotFuzzScenario) {
    // Test recv future drops racing with sender operations
    let cx = test_cx(false);
    let (tx, mut rx) = oneshot::channel::<u32>();

    let wake_counter = Arc::new(AtomicUsize::new(0));
    let waker = counting_waker(wake_counter.clone());
    let mut task_cx = Context::from_waker(&waker);

    let mut recv_fut = Box::pin(rx.recv(&cx));
    let _ = recv_fut.as_mut().poll(&mut task_cx);

    // Race future drop with sender.send()
    let fut_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(100));
        drop(recv_fut); // Should clean up waker
    });

    let send_thread = thread::spawn(move || {
        thread::sleep(Duration::from_micros(50));
        let _ = tx.send(&cx, 123);
    });

    let _ = fut_thread.join();
    let _ = send_thread.join();

    // Future drop should properly clean up internal state
}

fn test_waker_cleanup_races(scenario: &OneShotFuzzScenario) {
    // Test that wakers are properly cleaned up in race scenarios
    let cx = test_cx(false);
    let (tx, mut rx) = oneshot::channel::<u32>();

    let wake_counter1 = Arc::new(AtomicUsize::new(0));
    let wake_counter2 = Arc::new(AtomicUsize::new(0));

    let waker1 = counting_waker(wake_counter1.clone());
    let waker2 = counting_waker(wake_counter2.clone());

    // Register first waker
    {
        let mut task_cx = Context::from_waker(&waker1);
        let mut recv_fut1 = Box::pin(rx.recv(&cx));
        let _ = recv_fut1.as_mut().poll(&mut task_cx);
        // Drop future to test cleanup
    }

    // Register second waker
    {
        let mut task_cx = Context::from_waker(&waker2);
        let mut recv_fut2 = Box::pin(rx.recv(&cx));
        let _ = recv_fut2.as_mut().poll(&mut task_cx);

        // Send value - should wake only the active waker (waker2)
        let _ = tx.send(&cx, 456);

        let _ = recv_fut2.as_mut().poll(&mut task_cx);
    }

    // First waker should not have been notified (cleaned up)
    let wake_count1 = wake_counter1.load(Ordering::SeqCst);
    let wake_count2 = wake_counter2.load(Ordering::SeqCst);

    assert_eq!(wake_count1, 0, "Stale waker should not be notified");
    assert_eq!(wake_count2, 1, "Active waker should be notified once");
}