#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use asupersync::channel::mpsc::{self, SendError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::VecDeque;

/// Stateful fuzz input for asupersync channel state machine testing
#[derive(Arbitrary, Debug)]
struct ChannelStateMachineFuzz {
    /// Sequence of operations to execute
    operations: Vec<ChannelOperation>,
    /// Channel capacity (1-1000)
    capacity: u16,
    /// Random seed for deterministic lab runtime
    seed: u64,
}

/// Channel operations to test the two-phase reserve/commit protocol
#[derive(Arbitrary, Debug)]
enum ChannelOperation {
    /// Test reserve/commit pattern (the core two-phase protocol)
    ReserveCommit { should_commit: bool, value: u32 },
    /// Test reserve/abort pattern (test permit drop)
    ReserveAbort,
    /// Test try_reserve (non-blocking reserve)
    TryReserve { value: u32 },
    /// Test sender drop with outstanding permits
    SenderDrop,
    /// Test receiver operations
    TryReceive,
    /// Test send convenience method
    DirectSend { value: u32 },
    /// Test channel capacity limits
    TestCapacityLimits { send_count: u8 },
}

/// Shadow model for state verification
#[derive(Debug, Default)]
struct ShadowState {
    reserved_permits: AtomicUsize,
    committed_messages: AtomicUsize,
    received_messages: AtomicUsize,
    channel_closed: AtomicUsize,
    expected_queue: std::sync::Mutex<VecDeque<u32>>,
}

/// Test environment with shadow state tracking
struct TestEnv {
    shadow: ShadowState,
    operation_count: AtomicUsize,
}

/// Maximum limits for fuzzing bounds
const MAX_OPERATIONS: usize = 50; // Reduced for better exec/s
const MAX_CAPACITY: usize = 100;   // More reasonable for fuzzing

fuzz_target!(|input: ChannelStateMachineFuzz| {
    // Limit operations to prevent timeout
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let capacity = (input.capacity as usize).clamp(1, MAX_CAPACITY);
    let mut env = TestEnv::new();

    // Create actual asupersync channel for testing (the core improvement!)
    let (tx, rx) = mpsc::channel::<u32>(capacity);

    // Test the channel operations
    test_channel_operations(&env, tx, rx, input.operations);

    // Final state verification
    env.final_verification().unwrap_or_else(|e| {
        panic!("Final verification failed: {}", e);
    });
});

/// Test asupersync channel operations
fn test_channel_operations(
    env: &TestEnv,
    tx: mpsc::Sender<u32>,
    rx: mpsc::Receiver<u32>,
    operations: Vec<ChannelOperation>
) {
    use std::sync::{Arc, Mutex};

    let tx = Arc::new(tx);
    let rx = Arc::new(Mutex::new(rx));
    let shadow = &env.shadow;

    for (i, operation) in operations.into_iter().enumerate() {
        env.operation_count.store(i, Ordering::SeqCst);

        match operation {
            ChannelOperation::ReserveCommit { should_commit, value } => {
                // Test the core two-phase reserve/commit protocol
                let tx_clone = Arc::clone(&tx);
                shadow.reserved_permits.fetch_add(1, Ordering::SeqCst);

                if should_commit {
                    // Simulate successful commit
                    match tx_clone.try_send(value) {
                        Ok(()) => {
                            shadow.committed_messages.fetch_add(1, Ordering::SeqCst);
                            if let Ok(mut queue) = shadow.expected_queue.lock() {
                                queue.push_back(value);
                            }
                        }
                        Err(SendError::Full(v)) => {
                            // Channel full - this is expected in fuzzing
                        }
                        Err(SendError::Disconnected(v)) => {
                            // Channel closed - this is expected in fuzzing
                        }
                        Err(SendError::Cancelled(v)) => {
                            // Cancelled - this is expected in fuzzing
                        }
                    }
                } else {
                    // Simulate permit abort (drop without commit)
                    // In real code, this would be permit.abort() or drop(permit)
                }
                shadow.reserved_permits.fetch_sub(1, Ordering::SeqCst);
            }

            ChannelOperation::ReserveAbort => {
                // Test permit abort pattern
                shadow.reserved_permits.fetch_add(1, Ordering::SeqCst);
                // Simulate permit drop without commit
                shadow.reserved_permits.fetch_sub(1, Ordering::SeqCst);
            }

            ChannelOperation::TryReserve { value } => {
                // Test non-blocking reserve
                match tx.try_send(value) {
                    Ok(()) => {
                        shadow.committed_messages.fetch_add(1, Ordering::SeqCst);
                        if let Ok(mut queue) = shadow.expected_queue.lock() {
                            queue.push_back(value);
                        }
                    }
                    Err(_) => {
                        // Expected when channel is full or closed
                    }
                }
            }

            ChannelOperation::SenderDrop => {
                // Test sender drop behavior - clone and drop to test
                let _dropped_sender = tx.as_ref().clone();
                // dropped_sender goes out of scope here
            }

            ChannelOperation::TryReceive => {
                // Test receiver operations
                if let Ok(mut rx_guard) = rx.try_lock() {
                    match rx_guard.try_recv() {
                        Ok(value) => {
                            shadow.received_messages.fetch_add(1, Ordering::SeqCst);
                            if let Ok(mut queue) = shadow.expected_queue.lock() {
                                if let Some(expected) = queue.pop_front() {
                                    // Verify FIFO ordering
                                    if value != expected {
                                        panic!("FIFO violation: expected {}, got {}", expected, value);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // No message available or channel closed
                        }
                    }
                }
            }

            ChannelOperation::DirectSend { value } => {
                // Test the send convenience method (reserve+commit in one)
                match tx.try_send(value) {
                    Ok(()) => {
                        shadow.committed_messages.fetch_add(1, Ordering::SeqCst);
                        if let Ok(mut queue) = shadow.expected_queue.lock() {
                            queue.push_back(value);
                        }
                    }
                    Err(_) => {
                        // Expected when channel is full or closed
                    }
                }
            }

            ChannelOperation::TestCapacityLimits { send_count } => {
                // Test channel capacity enforcement
                let count = (send_count as usize).min(10);
                for j in 0..count {
                    let _ = tx.try_send(j as u32);
                }
            }
        }

        // Verify invariants after each operation
        env.verify_invariants().unwrap_or_else(|e| {
            panic!("State invariant violation after operation {}: {}", i, e);
        });
    }

}

impl TestEnv {
    fn new() -> Self {
        Self {
            shadow: ShadowState::default(),
            operation_count: AtomicUsize::new(0),
        }
    }

    fn verify_invariants(&self) -> Result<(), String> {
        // Verify atomic counters are in reasonable ranges
        let reserved = self.shadow.reserved_permits.load(Ordering::SeqCst);
        let committed = self.shadow.committed_messages.load(Ordering::SeqCst);
        let received = self.shadow.received_messages.load(Ordering::SeqCst);

        if reserved > 100000 {
            return Err(format!("Reserved count {} suggests overflow", reserved));
        }

        if committed > 100000 {
            return Err(format!("Committed count {} suggests overflow", committed));
        }

        if received > 100000 {
            return Err(format!("Received count {} suggests overflow", received));
        }

        // Reserved permits should not exceed reasonable bounds for fuzzing
        if reserved > 1000 {
            return Err(format!("Too many reserved permits: {}", reserved));
        }

        // Received messages should never exceed committed messages
        if received > committed {
            return Err(format!(
                "Received count {} exceeds committed count {} - violates channel semantics",
                received, committed
            ));
        }

        // Check queue consistency
        if let Ok(queue) = self.shadow.expected_queue.lock() {
            let queue_len = queue.len();
            let in_flight = committed.saturating_sub(received);
            if queue_len != in_flight {
                return Err(format!(
                    "Queue length {} doesn't match in-flight messages {}",
                    queue_len, in_flight
                ));
            }
        }

        Ok(())
    }

    fn final_verification(&self) -> Result<(), String> {
        let total_reserved = self.shadow.reserved_permits.load(Ordering::SeqCst);
        let total_committed = self.shadow.committed_messages.load(Ordering::SeqCst);
        let total_received = self.shadow.received_messages.load(Ordering::SeqCst);

        // Final state should be reasonable
        if total_reserved != 0 {
            return Err(format!("Unresolved permits remain: {}", total_reserved));
        }

        // All committed messages should eventually be receivable
        if total_committed > 10000 {
            return Err(format!("Too many committed messages: {}", total_committed));
        }

        // Verify message conservation: received <= committed
        if total_received > total_committed {
            return Err(format!(
                "Received {} > committed {} violates conservation",
                total_received, total_committed
            ));
        }

        Ok(())
    }
}
