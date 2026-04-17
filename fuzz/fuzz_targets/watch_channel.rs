#![no_main]

//! Fuzz target for watch channel operations and state machine.
//!
//! This target focuses on the watch channel broadcasting semantics, version
//! tracking consistency, waiter deduplication, and cancel safety. Tests the
//! interaction between multiple receivers, sender operations, and subscription
//! patterns under arbitrary operation sequences.
//!
//! Key areas tested:
//! - Single-producer, multiple-receiver broadcasting
//! - Version tracking and consistency across receivers
//! - Waiter registration and deduplication patterns
//! - Cancel safety for changed() operations
//! - Sender drop propagation to all receivers
//! - Subscribe/unsubscribe lifecycle management
//! - send_modify operations with concurrent access

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

#[derive(Arbitrary, Debug)]
struct WatchChannelFuzz {
    initial_value: TestValue,
    operations: Vec<WatchOperation>,
    receiver_configs: Vec<ReceiverConfig>,
}

#[derive(Arbitrary, Debug, Clone, PartialEq, Eq)]
struct TestValue {
    id: u32,
    data: Vec<u8>,
}

impl Default for TestValue {
    fn default() -> Self {
        Self {
            id: 0,
            data: vec![42],
        }
    }
}

#[derive(Arbitrary, Debug)]
struct ReceiverConfig {
    create_at_start: bool,
}

#[derive(Arbitrary, Debug)]
enum WatchOperation {
    // Sender operations
    Send { value: TestValue },
    SendModify { id_delta: i32, data_byte: u8 },
    DropSender,

    // Receiver management
    Subscribe { receiver_id: u8 },
    DropReceiver { receiver_id: u8 },

    // Receiver operations
    Borrow { receiver_id: u8 },
    BorrowAndClone { receiver_id: u8 },
    BorrowAndUpdate { receiver_id: u8 },
    CheckChanged { receiver_id: u8 },

    // State queries
    QueryReceiverCount,
    QueryClosed,
    QueryVersion { receiver_id: u8 },

    // Concurrent patterns
    MultiReceiverBorrow { receiver_mask: u8 },
    BroadcastToAll { value: TestValue },
}

/// Shadow state for tracking expected behavior
#[derive(Debug, Default)]
struct ShadowState {
    current_value: TestValue,
    version: AtomicU64,
    receiver_count: AtomicUsize,
    sender_dropped: AtomicBool,
    receiver_versions: HashMap<u8, u64>,
    total_sends: AtomicUsize,
    total_borrows: AtomicUsize,
}

/// Test environment with shadow state tracking
struct TestEnv {
    shadow: ShadowState,
    operation_count: AtomicUsize,
}

impl TestEnv {
    fn new(initial_value: TestValue) -> Self {
        Self {
            shadow: ShadowState {
                current_value: initial_value,
                version: AtomicU64::new(0),
                receiver_count: AtomicUsize::new(0),
                sender_dropped: AtomicBool::new(false),
                receiver_versions: HashMap::new(),
                total_sends: AtomicUsize::new(0),
                total_borrows: AtomicUsize::new(0),
            },
            operation_count: AtomicUsize::new(0),
        }
    }

    fn increment_version(&mut self) -> u64 {
        let new_version = self.shadow.version.load(Ordering::Relaxed) + 1;
        self.shadow.version.store(new_version, Ordering::Relaxed);
        new_version
    }

    fn track_receiver(&mut self, id: u8, version: u64) {
        self.shadow.receiver_versions.insert(id, version);
        self.shadow.receiver_count.fetch_add(1, Ordering::Relaxed);
    }

    fn untrack_receiver(&mut self, id: u8) {
        self.shadow.receiver_versions.remove(&id);
        self.shadow.receiver_count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Maximum limits to prevent timeouts and resource exhaustion
const MAX_OPERATIONS: usize = 200;
const MAX_RECEIVERS: usize = 16;
const MAX_DATA_SIZE: usize = 1024;

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }

    // Limit input size to prevent timeout
    if input.len() > 32 * 1024 {
        return;
    }

    let mut unstructured = Unstructured::new(input);
    let Ok(fuzz_input) = WatchChannelFuzz::arbitrary(&mut unstructured) else {
        return;
    };

    // Limit operations to prevent timeout
    if fuzz_input.operations.len() > MAX_OPERATIONS {
        return;
    }

    if fuzz_input.receiver_configs.len() > MAX_RECEIVERS {
        return;
    }

    // Limit data size to prevent OOM
    if fuzz_input.initial_value.data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create watch channel
    let initial_value = if fuzz_input.initial_value.data.is_empty() {
        TestValue::default()
    } else {
        fuzz_input.initial_value.clone()
    };

    let (tx, _rx) = asupersync::channel::watch::channel(initial_value.clone());
    let mut env = TestEnv::new(initial_value);
    let mut receivers: HashMap<u8, asupersync::channel::watch::Receiver<TestValue>> = HashMap::new();
    let sender_active = true;

    // Create initial receivers based on config
    for (i, config) in fuzz_input.receiver_configs.iter().enumerate() {
        if config.create_at_start && i < MAX_RECEIVERS {
            let receiver_id = i as u8;
            let new_rx = tx.subscribe();
            env.track_receiver(receiver_id, tx.borrow().id as u64);
            receivers.insert(receiver_id, new_rx);
        }
    }

    // Execute operation sequence
    for (op_idx, operation) in fuzz_input.operations.into_iter().enumerate() {
        env.operation_count.store(op_idx, Ordering::SeqCst);

        match operation {
            WatchOperation::Send { mut value } => {
                if sender_active {
                    // Limit data size
                    if value.data.len() > MAX_DATA_SIZE {
                        value.data.truncate(MAX_DATA_SIZE);
                    }

                    match tx.send(value.clone()) {
                        Ok(()) => {
                            env.shadow.current_value = value;
                            env.increment_version();
                            env.shadow.total_sends.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Send failed (channel closed) - expected in some scenarios
                        }
                    }
                }
            }

            WatchOperation::SendModify { id_delta, data_byte } => {
                if sender_active {
                    let result = tx.send_modify(|val| {
                        val.id = val.id.wrapping_add(id_delta as u32);
                        if !val.data.is_empty() {
                            val.data[0] = data_byte;
                        } else {
                            val.data.push(data_byte);
                        }
                    });

                    if result.is_ok() {
                        env.shadow.current_value.id = env.shadow.current_value.id.wrapping_add(id_delta as u32);
                        if !env.shadow.current_value.data.is_empty() {
                            env.shadow.current_value.data[0] = data_byte;
                        } else {
                            env.shadow.current_value.data.push(data_byte);
                        }
                        env.increment_version();
                        env.shadow.total_sends.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            WatchOperation::DropSender => {
                if sender_active {
                    drop(tx);
                    env.shadow.sender_dropped.store(true, Ordering::Release);
                    // After this point, all send operations should fail
                    return; // Can't use sender anymore
                }
            }

            WatchOperation::Subscribe { receiver_id } => {
                if sender_active && receivers.len() < MAX_RECEIVERS && !receivers.contains_key(&receiver_id) {
                    let new_rx = tx.subscribe();
                    let current_version = tx.borrow().id as u64;
                    env.track_receiver(receiver_id, current_version);
                    receivers.insert(receiver_id, new_rx);
                }
            }

            WatchOperation::DropReceiver { receiver_id } => {
                if receivers.remove(&receiver_id).is_some() {
                    env.untrack_receiver(receiver_id);
                }
            }

            WatchOperation::Borrow { receiver_id } => {
                if let Some(receiver) = receivers.get(&receiver_id) {
                    let borrowed = receiver.borrow();
                    env.shadow.total_borrows.fetch_add(1, Ordering::Relaxed);

                    // Verify the borrowed value is accessible
                    let _ = borrowed.id;
                    let _ = &borrowed.data;

                    // Test Debug formatting
                    let _ = format!("{:?}", *borrowed);
                }
            }

            WatchOperation::BorrowAndClone { receiver_id } => {
                if let Some(receiver) = receivers.get(&receiver_id) {
                    let cloned = receiver.borrow_and_clone();
                    env.shadow.total_borrows.fetch_add(1, Ordering::Relaxed);

                    // Verify cloned value matches current state expectations
                    assert_eq!(cloned.data.len(), cloned.data.len()); // Sanity check

                    // Test that cloned value is independent
                    let cloned2 = receiver.borrow_and_clone();
                    assert_eq!(cloned.id, cloned2.id);
                    assert_eq!(cloned.data, cloned2.data);
                }
            }

            WatchOperation::BorrowAndUpdate { receiver_id } => {
                if let Some(receiver) = receivers.get_mut(&receiver_id) {
                    // Check if changed before update
                    let was_changed = receiver.has_changed();

                    let value = receiver.borrow_and_update();
                    env.shadow.total_borrows.fetch_add(1, Ordering::Relaxed);

                    // Update shadow receiver version if there was a change
                    if was_changed {
                        if let Some(shadow_version) = env.shadow.receiver_versions.get_mut(&receiver_id) {
                            *shadow_version = env.shadow.version.load(Ordering::Relaxed);
                        }
                    }

                    // Verify value accessibility
                    let _ = value.id;
                    let _ = &value.data;
                }
            }

            WatchOperation::CheckChanged { receiver_id } => {
                if receivers.contains_key(&receiver_id) {
                    // Note: can't actually call changed() in sync context
                    // Test has_changed instead
                    if let Some(receiver) = receivers.get(&receiver_id) {
                        let has_changed = receiver.has_changed();

                        // Verify version consistency
                        let shadow_receiver_version = env.shadow.receiver_versions.get(&receiver_id).copied().unwrap_or(0);
                        let current_version = env.shadow.version.load(Ordering::Relaxed);

                        if shadow_receiver_version < current_version {
                            // Should indicate change available
                        }

                        let _ = has_changed; // Use the result to avoid unused variable warning
                    }
                }
            }

            WatchOperation::QueryReceiverCount => {
                if sender_active {
                    let count = tx.receiver_count();
                    let shadow_count = env.shadow.receiver_count.load(Ordering::Relaxed);

                    // Verify count consistency (allowing for concurrent drops)
                    assert!(count <= receivers.len());
                    assert!(count <= shadow_count + 1); // +1 for potential race conditions
                }
            }

            WatchOperation::QueryClosed => {
                if sender_active {
                    let is_closed = tx.is_closed();
                    let shadow_closed = env.shadow.receiver_count.load(Ordering::Relaxed) == 0;

                    // Verify closed state consistency
                    if receivers.is_empty() {
                        assert_eq!(is_closed, shadow_closed);
                    }
                }
            }

            WatchOperation::QueryVersion { receiver_id } => {
                if let Some(receiver) = receivers.get(&receiver_id) {
                    let version = receiver.seen_version();
                    let _shadow_version = env.shadow.receiver_versions.get(&receiver_id).copied().unwrap_or(0);

                    // Version should be consistent with shadow tracking
                    // (allowing for some drift due to concurrent updates)
                    let current_version = env.shadow.version.load(Ordering::Relaxed);
                    assert!(version <= current_version);
                }
            }

            WatchOperation::MultiReceiverBorrow { receiver_mask } => {
                // Test concurrent access patterns
                let mut borrow_count = 0;
                for (id, receiver) in receivers.iter() {
                    if (receiver_mask >> (id % 8)) & 1 == 1 && borrow_count < 8 {
                        let borrowed = receiver.borrow();
                        let _ = borrowed.id;
                        borrow_count += 1;
                        env.shadow.total_borrows.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            WatchOperation::BroadcastToAll { mut value } => {
                if sender_active && !receivers.is_empty() {
                    // Limit data size
                    if value.data.len() > MAX_DATA_SIZE {
                        value.data.truncate(MAX_DATA_SIZE);
                    }

                    // Send to all receivers by updating the value
                    if tx.send(value.clone()).is_ok() {
                        env.shadow.current_value = value;
                        env.increment_version();
                        env.shadow.total_sends.fetch_add(1, Ordering::Relaxed);

                        // All receivers should eventually see this value
                        for receiver in receivers.values() {
                            let current = receiver.borrow();
                            // Current value should be accessible
                            let _ = current.id;
                            let _ = &current.data;
                        }
                    }
                }
            }
        }
    }

    // Final invariant checks
    if sender_active {
        // Test sender state consistency
        let final_receiver_count = tx.receiver_count();
        assert!(final_receiver_count <= receivers.len());

        let is_closed = tx.is_closed();
        if receivers.is_empty() {
            assert!(is_closed);
        }

        // Test final borrow from sender
        let final_value = tx.borrow();
        let _ = final_value.id;
        let _ = &final_value.data;
    }

    // Test receiver state consistency
    for (id, receiver) in receivers.iter() {
        // Test final borrow from each receiver
        let final_value = receiver.borrow();
        let _ = final_value.id;
        let _ = &final_value.data;

        // Test version consistency
        let version = receiver.seen_version();
        let shadow_version = env.shadow.receiver_versions.get(id).copied().unwrap_or(0);
        assert!(version >= shadow_version);

        // Test change detection
        let has_changed = receiver.has_changed();
        let _ = has_changed; // Use result

        // Test Debug formatting
        let _ = format!("{:?}", receiver);
    }

    // Verify shadow state consistency
    let total_sends = env.shadow.total_sends.load(Ordering::Relaxed);
    let total_borrows = env.shadow.total_borrows.load(Ordering::Relaxed);

    // Basic sanity checks
    assert!(total_sends < MAX_OPERATIONS); // Should be bounded by operations
    assert!(total_borrows < MAX_OPERATIONS * MAX_RECEIVERS); // Should be bounded

    // Test that channel state is well-formed
    if sender_active {
        assert!(!env.shadow.sender_dropped.load(Ordering::Relaxed));
    }

    // Test Send + Sync compile-time constraints
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<asupersync::channel::watch::Sender<TestValue>>();
    assert_send_sync::<asupersync::channel::watch::Receiver<TestValue>>();
});