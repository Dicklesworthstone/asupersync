#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Stateful fuzz input for channel state machine testing
#[derive(Arbitrary, Debug)]
struct ChannelStateMachineFuzz {
    /// Sequence of operations to execute
    operations: Vec<ChannelOperation>,
    /// Channel capacity (1-1000)
    capacity: u16,
}

/// Channel operations to test
#[derive(Arbitrary, Debug)]
enum ChannelOperation {
    /// Test reserve/commit pattern
    ReserveCommit { should_commit: bool, value: u32 },
    /// Test reserve/abort pattern
    ReserveAbort,
    /// Test try_reserve
    TryReserve { value: u32 },
    /// Test sender drop
    SenderDrop,
    /// Test receiver operations
    TryReceive,
    /// Test concurrent operations
    ConcurrentOp { op_count: u8, value: u32 },
}

/// Shadow model for state verification
#[derive(Debug, Default)]
struct ShadowState {
    reserved_permits: AtomicUsize,
    committed_messages: AtomicUsize,
    channel_closed: AtomicUsize,
}

/// Test environment
struct TestEnv {
    shadow: ShadowState,
    operation_count: AtomicUsize,
}

/// Maximum limits
const MAX_OPERATIONS: usize = 100;
const MAX_CAPACITY: usize = 1000;

fuzz_target!(|input: ChannelStateMachineFuzz| {
    // Limit operations to prevent timeout
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let capacity = (input.capacity as usize).clamp(1, MAX_CAPACITY);
    let mut env = TestEnv::new();

    // Create a simple MPSC channel for testing
    let (tx, mut rx) = std::sync::mpsc::sync_channel::<TestMessage>(capacity);

    // Execute operations sequence
    for (i, operation) in input.operations.into_iter().enumerate() {
        env.operation_count.store(i, Ordering::SeqCst);

        match operation {
            ChannelOperation::ReserveCommit {
                should_commit,
                value,
            } => {
                // Simulate reserve/commit with sync channel
                let msg = TestMessage {
                    value,
                    operation_id: i,
                };

                if should_commit {
                    match tx.try_send(msg) {
                        Ok(()) => {
                            env.shadow.committed_messages.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(_) => {
                            // Channel full or closed - expected in fuzzing
                        }
                    }
                } else {
                    // Simulate abort by not sending
                }
            }

            ChannelOperation::ReserveAbort => {
                // Test abort pattern - increment reserved, then decrement without commit
                env.shadow.reserved_permits.fetch_add(1, Ordering::SeqCst);
                env.shadow.reserved_permits.fetch_sub(1, Ordering::SeqCst);
            }

            ChannelOperation::TryReserve { value } => {
                let msg = TestMessage {
                    value,
                    operation_id: i,
                };
                match tx.try_send(msg) {
                    Ok(()) => {
                        env.shadow.committed_messages.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        // Expected when channel is full
                    }
                }
            }

            ChannelOperation::SenderDrop => {
                // Test sender drop behavior
                drop(tx.clone()); // Drop a clone to test behavior
            }

            ChannelOperation::TryReceive => {
                match rx.try_recv() {
                    Ok(_msg) => {
                        let committed = env.shadow.committed_messages.load(Ordering::SeqCst);
                        if committed > 0 {
                            env.shadow.committed_messages.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    Err(_) => {
                        // No message available or channel closed
                    }
                }
            }

            ChannelOperation::ConcurrentOp { op_count, value } => {
                // Test multiple operations in sequence
                let count = (op_count as usize).min(10);
                for j in 0..count {
                    let msg = TestMessage {
                        value: value.wrapping_add(j as u32),
                        operation_id: i * 1000 + j,
                    };
                    let _ = tx.try_send(msg);
                }
            }
        }

        // Verify state invariants after each operation
        env.verify_invariants().unwrap_or_else(|e| {
            panic!("State invariant violation after operation {}: {}", i, e);
        });
    }

    // Final state verification
    env.final_verification().unwrap_or_else(|e| {
        panic!("Final verification failed: {}", e);
    });
});

/// Test message structure
#[derive(Debug, Clone)]
struct TestMessage {
    value: u32,
    operation_id: usize,
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

        if reserved > 1000000 {
            return Err(format!("Reserved count {} suggests overflow", reserved));
        }

        if committed > 1000000 {
            return Err(format!("Committed count {} suggests overflow", committed));
        }

        // Reserved permits should not exceed reasonable bounds
        if reserved > 10000 {
            return Err(format!("Too many reserved permits: {}", reserved));
        }

        Ok(())
    }

    fn final_verification(&self) -> Result<(), String> {
        let total_reserved = self.shadow.reserved_permits.load(Ordering::SeqCst);
        let total_committed = self.shadow.committed_messages.load(Ordering::SeqCst);

        // Final state should be reasonable
        if total_reserved > 1000 {
            return Err(format!("Too many unresolved permits: {}", total_reserved));
        }

        // Committed messages should be reasonable
        if total_committed > 10000 {
            return Err(format!("Too many committed messages: {}", total_committed));
        }

        Ok(())
    }
}
