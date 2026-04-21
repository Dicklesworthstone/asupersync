#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic property tests for MPSC channel fan-out/fan-in invariants.
//!
//! These tests verify MPSC channel behavior in multi-sender scenarios where
//! multiple producers send to a single consumer. Unlike unit tests that check
//! exact outcomes, metamorphic tests verify relationships between different
//! execution scenarios using LabRuntime DPOR for deterministic scheduling
//! exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **Multi-Sender Delivery** (MR1): multiple senders deliver to single receiver (connectivity)
//! 2. **Per-Sender Ordering** (MR2): order within each sender is preserved (temporal)
//! 3. **Fair Interleaving** (MR3): order across senders is interleaved fairly (fairness)
//! 4. **Count Preservation** (MR4): fan-in preserves total message count (conservation)
//! 5. **Last Sender Disconnect** (MR5): close of last sender signals disconnect (lifecycle)

use asupersync::channel::mpsc::{self, RecvError, SendError};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Create a test context with specific slot for concurrent testing.
fn test_cx_with_slot(slot: u32) -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, slot)),
        TaskId::from_arena(ArenaIndex::new(0, slot)),
        Budget::INFINITE,
    )
}

/// Configuration for MPSC fan-out/fan-in metamorphic tests.
#[derive(Debug, Clone)]
pub struct MpscFanoutConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Channel capacity for backpressure testing.
    pub capacity: usize,
    /// Number of concurrent senders (fan-out degree).
    pub sender_count: u8,
    /// Values each sender should send.
    pub sender_values: Vec<Vec<i64>>,
    /// Whether to test early sender drops.
    pub test_early_drops: bool,
    /// Which senders to drop early (by index).
    pub early_drop_senders: Vec<u8>,
    /// Whether to inject cancellation during operations.
    pub inject_cancellation: bool,
    /// Delay before cancellation (virtual milliseconds).
    pub cancel_delay_ms: u64,
    /// Whether to use reserve/commit pattern vs direct send.
    pub use_reserve_pattern: bool,
    /// Whether to test fairness across senders.
    pub test_fairness: bool,
    /// Send rate limit per sender (messages per virtual second).
    pub sender_rate_limit: Option<u32>,
}

impl Arbitrary for MpscFanoutConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<u64>(),                                    // seed
            1usize..=32,                                     // capacity
            2u8..=8,                                         // sender_count
            prop::collection::vec(                           // sender_values
                prop::collection::vec(0i64..1000, 1..10),
                1..8
            ),
            any::<bool>(),                                   // test_early_drops
            prop::collection::vec(0u8..8, 0..4),           // early_drop_senders
            any::<bool>(),                                   // inject_cancellation
            1u64..=100,                                      // cancel_delay_ms
            any::<bool>(),                                   // use_reserve_pattern
            any::<bool>(),                                   // test_fairness
            prop::option::of(1u32..=100),                   // sender_rate_limit
        )
        .prop_map(|(
            seed,
            capacity,
            sender_count,
            mut sender_values,
            test_early_drops,
            early_drop_senders,
            inject_cancellation,
            cancel_delay_ms,
            use_reserve_pattern,
            test_fairness,
            sender_rate_limit,
        )| {
            // Ensure we have enough sender values for all senders
            sender_values.resize(sender_count as usize, Vec::new());
            for values in &mut sender_values {
                if values.is_empty() {
                    values.push(1); // Ensure each sender has at least one value
                }
            }

            MpscFanoutConfig {
                seed,
                capacity,
                sender_count: sender_count.max(2), // Ensure at least 2 senders for fan-out
                sender_values,
                test_early_drops,
                early_drop_senders: early_drop_senders.into_iter()
                    .filter(|&idx| idx < sender_count)
                    .collect(),
                inject_cancellation,
                cancel_delay_ms,
                use_reserve_pattern,
                test_fairness,
                sender_rate_limit,
            }
        })
        .boxed()
    }
}

/// Test harness for MPSC fan-out operations with DPOR scheduling.
#[derive(Debug)]
struct MpscFanoutHarness {
    runtime: LabRuntime,
    messages_sent: Arc<AtomicU64>,
    messages_received: Arc<AtomicU64>,
    sender_completion_order: Arc<parking_lot::Mutex<Vec<usize>>>,
    received_messages: Arc<parking_lot::Mutex<Vec<(usize, i64)>>>, // (sender_id, value)
}

impl MpscFanoutHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed)
            .with_deterministic_time()
            .with_exhaustive_dpor();

        Self {
            runtime: LabRuntime::new(config),
            messages_sent: Arc::new(AtomicU64::new(0)),
            messages_received: Arc::new(AtomicU64::new(0)),
            sender_completion_order: Arc::new(parking_lot::Mutex::new(Vec::new())),
            received_messages: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    /// Execute a fan-out test scenario
    fn execute<F>(&mut self, test_fn: F) -> Outcome<F::Output, ()>
    where
        F: FnOnce(&Cx) -> Pin<Box<dyn Future<Output = F::Output> + '_>> + Send,
    {
        self.runtime.block_on(|cx| async {
            cx.region(|region| async {
                let scope = Scope::new(region, "mpsc_fanout_test");
                test_fn(&scope.cx())
            }).await
        })
    }

    /// Reset harness state for a new test
    fn reset(&mut self) {
        self.messages_sent.store(0, Ordering::SeqCst);
        self.messages_received.store(0, Ordering::SeqCst);
        self.sender_completion_order.lock().clear();
        self.received_messages.lock().clear();
    }
}

// ============================================================================
// Metamorphic Relation 1: Multi-Sender Delivery
// ============================================================================

/// **MR1: Multi-Sender Delivery**
///
/// Property: Multiple senders can deliver messages to a single receiver.
///
/// Test: All senders successfully deliver their messages to the receiver.
#[test]
fn mr1_multi_sender_delivery() {
    proptest!(|(config: MpscFanoutConfig)| {
        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity);

            // Create multiple senders
            let mut senders = Vec::new();
            for i in 0..config.sender_count {
                senders.push((i as usize, tx.clone()));
            }
            drop(tx); // Drop original sender

            let messages_sent = harness.messages_sent.clone();
            let messages_received = harness.messages_received.clone();

            // Spawn sender tasks
            for (sender_id, sender) in senders {
                if sender_id < config.sender_values.len() {
                    let sender_values = config.sender_values[sender_id].clone();
                    let messages_sent = messages_sent.clone();
                    let sender_cx = test_cx_with_slot(sender_id as u32);

                    cx.spawn(format!("sender_{}", sender_id), async move {
                        for &value in &sender_values {
                            if config.use_reserve_pattern {
                                let permit = sender.reserve(&sender_cx).await?;
                                permit.send(value);
                            } else {
                                sender.send(value, &sender_cx).await?;
                            }
                            messages_sent.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok(())
                    })?;
                }
            }

            // Receive all messages
            let mut total_expected = 0;
            for values in &config.sender_values {
                total_expected += values.len();
            }

            for _ in 0..total_expected {
                match rx.recv(cx).await {
                    Ok(_value) => {
                        messages_received.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(RecvError::Disconnected) => break,
                    Err(e) => return Err(format!("Unexpected receive error: {:?}", e)),
                }
            }

            // MR1 Assertion: All messages delivered
            let sent = messages_sent.load(Ordering::SeqCst);
            let received = messages_received.load(Ordering::SeqCst);

            prop_assert_eq!(
                sent, received,
                "Multi-sender delivery failed: sent {} != received {}",
                sent, received
            );

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 2: Per-Sender Ordering
// ============================================================================

/// **MR2: Per-Sender Ordering**
///
/// Property: Order within each sender is preserved at the receiver.
///
/// Test: Messages from each individual sender arrive in the same order they were sent.
#[test]
fn mr2_per_sender_ordering() {
    proptest!(|(config: MpscFanoutConfig)| {
        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity);

            // Create senders with unique sequential values
            let mut expected_sequences = HashMap::new();
            let mut senders = Vec::new();

            for sender_id in 0..config.sender_count as usize {
                if sender_id < config.sender_values.len() {
                    let base_value = (sender_id * 1000) as i64;
                    let sequence: Vec<i64> = (0..config.sender_values[sender_id].len())
                        .map(|i| base_value + i as i64)
                        .collect();
                    expected_sequences.insert(sender_id, sequence.clone());
                    senders.push((sender_id, tx.clone(), sequence));
                }
            }
            drop(tx);

            let received_messages = harness.received_messages.clone();

            // Spawn sender tasks
            for (sender_id, sender, values) in senders {
                let received_messages = received_messages.clone();
                let sender_cx = test_cx_with_slot(sender_id as u32);

                cx.spawn(format!("sender_{}", sender_id), async move {
                    for &value in &values {
                        if config.use_reserve_pattern {
                            let permit = sender.reserve(&sender_cx).await?;
                            permit.send(value);
                        } else {
                            sender.send(value, &sender_cx).await?;
                        }
                    }
                    Ok(())
                })?;
            }

            // Collect all received messages with sender identification
            let mut total_expected = 0;
            for values in &config.sender_values {
                total_expected += values.len();
            }

            for _ in 0..total_expected {
                match rx.recv(cx).await {
                    Ok(value) => {
                        // Determine sender ID from value (base_value / 1000)
                        let sender_id = (value / 1000) as usize;
                        received_messages.lock().push((sender_id, value));
                    }
                    Err(RecvError::Disconnected) => break,
                    Err(e) => return Err(format!("Unexpected receive error: {:?}", e)),
                }
            }

            // MR2 Assertion: Per-sender ordering preserved
            let received = received_messages.lock();
            let mut sender_sequences: HashMap<usize, Vec<i64>> = HashMap::new();

            for &(sender_id, value) in &*received {
                sender_sequences.entry(sender_id).or_default().push(value);
            }

            for (sender_id, expected) in &expected_sequences {
                let actual = sender_sequences.get(sender_id).unwrap_or(&Vec::new());
                prop_assert_eq!(
                    *actual, *expected,
                    "Per-sender ordering violated for sender {}: expected {:?}, got {:?}",
                    sender_id, expected, actual
                );
            }

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 3: Fair Interleaving
// ============================================================================

/// **MR3: Fair Interleaving**
///
/// Property: Order across senders is interleaved fairly (no starvation).
///
/// Test: No single sender monopolizes the channel when multiple senders are active.
#[test]
fn mr3_fair_interleaving() {
    proptest!(|(config: MpscFanoutConfig)| {
        if !config.test_fairness || config.sender_count < 2 {
            return Ok(());
        }

        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity.max(config.sender_count as usize));

            // Create senders with equal message counts for fairness testing
            let messages_per_sender = 10;
            let mut senders = Vec::new();

            for sender_id in 0..config.sender_count as usize {
                let base_value = (sender_id * 1000) as i64;
                let values: Vec<i64> = (0..messages_per_sender)
                    .map(|i| base_value + i as i64)
                    .collect();
                senders.push((sender_id, tx.clone(), values));
            }
            drop(tx);

            let received_messages = harness.received_messages.clone();

            // Spawn sender tasks with rate limiting for fairness
            for (sender_id, sender, values) in senders {
                let received_messages = received_messages.clone();
                let sender_cx = test_cx_with_slot(sender_id as u32);

                cx.spawn(format!("sender_{}", sender_id), async move {
                    for (i, &value) in values.iter().enumerate() {
                        // Add small delay to encourage interleaving
                        if let Some(rate_limit) = config.sender_rate_limit {
                            let delay = Duration::from_millis(1000 / rate_limit as u64);
                            asupersync::time::sleep(delay).await;
                        }

                        if config.use_reserve_pattern {
                            let permit = sender.reserve(&sender_cx).await?;
                            permit.send(value);
                        } else {
                            sender.send(value, &sender_cx).await?;
                        }
                    }
                    Ok(())
                })?;
            }

            // Receive messages and analyze interleaving
            let total_expected = config.sender_count as usize * messages_per_sender;
            for _ in 0..total_expected {
                match rx.recv(cx).await {
                    Ok(value) => {
                        let sender_id = (value / 1000) as usize;
                        received_messages.lock().push((sender_id, value));
                    }
                    Err(RecvError::Disconnected) => break,
                    Err(e) => return Err(format!("Unexpected receive error: {:?}", e)),
                }
            }

            // MR3 Assertion: Fair interleaving (no excessive consecutive messages from same sender)
            let received = received_messages.lock();
            let mut max_consecutive = 0;
            let mut current_consecutive = 1;
            let mut last_sender = None;

            for &(sender_id, _) in &*received {
                if Some(sender_id) == last_sender {
                    current_consecutive += 1;
                    max_consecutive = max_consecutive.max(current_consecutive);
                } else {
                    current_consecutive = 1;
                    last_sender = Some(sender_id);
                }
            }

            // Allow some consecutive messages but not excessive monopolization
            let fairness_threshold = (messages_per_sender / 2).max(3);
            prop_assert!(
                max_consecutive <= fairness_threshold,
                "Fair interleaving violated: max consecutive from same sender = {} (threshold = {})",
                max_consecutive, fairness_threshold
            );

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 4: Count Preservation
// ============================================================================

/// **MR4: Count Preservation**
///
/// Property: Fan-in preserves total message count (conservation law).
///
/// Test: Total messages received equals total messages sent across all senders.
#[test]
fn mr4_count_preservation() {
    proptest!(|(config: MpscFanoutConfig)| {
        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity);

            let messages_sent = harness.messages_sent.clone();
            let messages_received = harness.messages_received.clone();

            // Calculate expected total
            let expected_total: usize = config.sender_values.iter()
                .take(config.sender_count as usize)
                .map(|values| values.len())
                .sum();

            // Spawn sender tasks
            for sender_id in 0..config.sender_count as usize {
                let sender = tx.clone();
                let values = if sender_id < config.sender_values.len() {
                    config.sender_values[sender_id].clone()
                } else {
                    vec![sender_id as i64] // Fallback value
                };
                let messages_sent = messages_sent.clone();
                let sender_cx = test_cx_with_slot(sender_id as u32);

                cx.spawn(format!("sender_{}", sender_id), async move {
                    for &value in &values {
                        if config.use_reserve_pattern {
                            let permit = sender.reserve(&sender_cx).await?;
                            permit.send(value);
                        } else {
                            sender.send(value, &sender_cx).await?;
                        }
                        messages_sent.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(())
                })?;
            }
            drop(tx); // Close channel after all senders created

            // Receive all messages
            while let Ok(_value) = rx.recv(cx).await {
                messages_received.fetch_add(1, Ordering::SeqCst);
            }

            // MR4 Assertion: Count preservation
            let sent = messages_sent.load(Ordering::SeqCst);
            let received = messages_received.load(Ordering::SeqCst);

            prop_assert_eq!(
                sent, expected_total as u64,
                "Sender count mismatch: sent {} != expected {}",
                sent, expected_total
            );

            prop_assert_eq!(
                received, expected_total as u64,
                "Count preservation violated: received {} != expected {}",
                received, expected_total
            );

            prop_assert_eq!(
                sent, received,
                "Send/receive count mismatch: sent {} != received {}",
                sent, received
            );

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Metamorphic Relation 5: Last Sender Disconnect
// ============================================================================

/// **MR5: Last Sender Disconnect**
///
/// Property: Close of last sender signals disconnect to receiver.
///
/// Test: Receiver gets Disconnected error after all senders are dropped.
#[test]
fn mr5_last_sender_disconnect() {
    proptest!(|(config: MpscFanoutConfig)| {
        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity);

            let sender_completion_order = harness.sender_completion_order.clone();

            // Create multiple senders that will complete at different times
            let mut sender_handles = Vec::new();
            for sender_id in 0..config.sender_count as usize {
                let sender = tx.clone();
                let values = if sender_id < config.sender_values.len() {
                    config.sender_values[sender_id].clone()
                } else {
                    vec![sender_id as i64]
                };
                let completion_order = sender_completion_order.clone();
                let sender_cx = test_cx_with_slot(sender_id as u32);

                let handle = cx.spawn(format!("sender_{}", sender_id), async move {
                    // Send messages
                    for &value in &values {
                        if config.use_reserve_pattern {
                            let permit = sender.reserve(&sender_cx).await?;
                            permit.send(value);
                        } else {
                            sender.send(value, &sender_cx).await?;
                        }
                    }

                    // Record completion order
                    completion_order.lock().push(sender_id);

                    // Drop sender implicitly when task completes
                    Ok(())
                })?;
                sender_handles.push(handle);
            }

            drop(tx); // Drop original sender

            // Wait for all senders to complete
            for handle in sender_handles {
                let _ = handle.await;
            }

            // MR5 Assertion: After all senders complete, receiver should get Disconnected
            let mut disconnected = false;
            let mut timeout_count = 0;
            while !disconnected && timeout_count < 10 {
                match asupersync::time::timeout(
                    cx,
                    Duration::from_millis(10),
                    rx.recv(cx)
                ).await {
                    Ok(Ok(_)) => {
                        // Received a message, continue
                    }
                    Ok(Err(RecvError::Disconnected)) => {
                        disconnected = true;
                        break;
                    }
                    Ok(Err(e)) => {
                        return Err(format!("Unexpected receive error: {:?}", e));
                    }
                    Err(_) => {
                        // Timeout - check if all senders completed
                        timeout_count += 1;
                        if sender_completion_order.lock().len() == config.sender_count as usize {
                            // All senders completed, expect disconnect soon
                            continue;
                        }
                    }
                }
            }

            prop_assert!(
                disconnected,
                "Last sender disconnect failed: receiver should get Disconnected after all senders drop"
            );

            // Verify completion order is recorded
            let completion_order = sender_completion_order.lock();
            prop_assert_eq!(
                completion_order.len(), config.sender_count as usize,
                "Not all senders completed: {} of {}",
                completion_order.len(), config.sender_count
            );

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}

// ============================================================================
// Composite Metamorphic Relations
// ============================================================================

/// **Composite MR: All Fan-out Invariants Combined**
///
/// Property: All five metamorphic relations hold simultaneously under realistic workloads.
///
/// Test: Execute complex fan-out scenario and verify all MRs hold together.
#[test]
fn composite_all_fanout_invariants() {
    proptest!(|(config: MpscFanoutConfig)| {
        let mut harness = MpscFanoutHarness::new(config.seed);
        let result = harness.execute(|cx| Box::pin(async {
            let (tx, mut rx) = mpsc::channel(config.capacity);

            let messages_sent = harness.messages_sent.clone();
            let messages_received = harness.messages_received.clone();
            let received_messages = harness.received_messages.clone();
            let sender_completion_order = harness.sender_completion_order.clone();

            // Calculate expected totals
            let expected_total: usize = config.sender_values.iter()
                .take(config.sender_count as usize)
                .map(|values| values.len())
                .sum();

            // Create senders with unique identifiable values
            let mut expected_sequences = HashMap::new();
            for sender_id in 0..config.sender_count as usize {
                if sender_id < config.sender_values.len() {
                    let base_value = (sender_id * 10000) as i64;
                    let sequence: Vec<i64> = (0..config.sender_values[sender_id].len())
                        .map(|i| base_value + i as i64)
                        .collect();
                    expected_sequences.insert(sender_id, sequence.clone());
                }
            }

            // Spawn sender tasks
            let mut sender_handles = Vec::new();
            for sender_id in 0..config.sender_count as usize {
                let sender = tx.clone();
                let values = expected_sequences.get(&sender_id).cloned().unwrap_or_default();
                if values.is_empty() {
                    continue;
                }

                let messages_sent = messages_sent.clone();
                let completion_order = sender_completion_order.clone();
                let sender_cx = test_cx_with_slot(sender_id as u32);

                let handle = cx.spawn(format!("sender_{}", sender_id), async move {
                    for &value in &values {
                        if config.use_reserve_pattern {
                            let permit = sender.reserve(&sender_cx).await?;
                            permit.send(value);
                        } else {
                            sender.send(value, &sender_cx).await?;
                        }
                        messages_sent.fetch_add(1, Ordering::SeqCst);
                    }
                    completion_order.lock().push(sender_id);
                    Ok(())
                })?;
                sender_handles.push(handle);
            }
            drop(tx);

            // Receive all messages
            for _ in 0..expected_total {
                match rx.recv(cx).await {
                    Ok(value) => {
                        let sender_id = (value / 10000) as usize;
                        received_messages.lock().push((sender_id, value));
                        messages_received.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(RecvError::Disconnected) => break,
                    Err(e) => return Err(format!("Unexpected receive error: {:?}", e)),
                }
            }

            // Wait for all senders to complete
            for handle in sender_handles {
                let _ = handle.await;
            }

            // Verify all MRs hold

            // MR1 & MR4: Multi-sender delivery and count preservation
            let sent = messages_sent.load(Ordering::SeqCst);
            let received_count = messages_received.load(Ordering::SeqCst);

            prop_assert_eq!(
                sent, expected_total as u64,
                "MR1/MR4: sent count {} != expected {}",
                sent, expected_total
            );

            prop_assert_eq!(
                received_count, expected_total as u64,
                "MR1/MR4: received count {} != expected {}",
                received_count, expected_total
            );

            // MR2: Per-sender ordering preserved
            let received = received_messages.lock();
            let mut sender_sequences: HashMap<usize, Vec<i64>> = HashMap::new();

            for &(sender_id, value) in &*received {
                sender_sequences.entry(sender_id).or_default().push(value);
            }

            for (sender_id, expected) in &expected_sequences {
                if let Some(actual) = sender_sequences.get(sender_id) {
                    prop_assert_eq!(
                        *actual, *expected,
                        "MR2: Per-sender ordering violated for sender {}: expected {:?}, got {:?}",
                        sender_id, expected, actual
                    );
                }
            }

            // MR3: Fair interleaving (basic check - no excessive monopolization)
            if config.test_fairness && config.sender_count >= 2 {
                let mut max_consecutive = 0;
                let mut current_consecutive = 1;
                let mut last_sender = None;

                for &(sender_id, _) in &*received {
                    if Some(sender_id) == last_sender {
                        current_consecutive += 1;
                        max_consecutive = max_consecutive.max(current_consecutive);
                    } else {
                        current_consecutive = 1;
                        last_sender = Some(sender_id);
                    }
                }

                let fairness_threshold = (expected_total / config.sender_count as usize / 2).max(5);
                prop_assert!(
                    max_consecutive <= fairness_threshold,
                    "MR3: Fair interleaving violated: max consecutive = {} (threshold = {})",
                    max_consecutive, fairness_threshold
                );
            }

            // MR5: Last sender disconnect (verify all senders completed)
            let completion_order = sender_completion_order.lock();
            prop_assert_eq!(
                completion_order.len(),
                expected_sequences.len(),
                "MR5: Not all senders completed: {} of {}",
                completion_order.len(), expected_sequences.len()
            );

            Ok(())
        }));

        prop_assert!(matches!(result, Outcome::Ok(_)));
    });
}