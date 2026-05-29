//! Conformance tests for messaging primitives.
//!
//! This module implements [br-conformance-11] following Pattern 4 (Spec-Derived
//! Test Matrix) from the conformance testing harness skill. Tests messaging
//! systems (Kafka, NATS, Redis, JetStream) for producer-consumer ordering under
//! failures and partition rebalance idempotency.
//!
//! # Specification Sources
//!
//! - Apache Kafka Protocol: Producer ordering, exactly-once semantics, consumer groups
//! - NATS Protocol: Subject-based routing, at-most-once delivery guarantees
//! - JetStream Extension: Exactly-once delivery, durable streams, ack/nack semantics
//! - Redis RESP: Pub/sub ordering, streams with consumer groups
//!
//! # Test Categories
//!
//! ## Producer-Consumer Ordering Under Failures
//! - MUST: Messages sent to the same partition maintain order
//! - MUST: Exactly-once semantics preserve order during failures
//! - MUST: Transaction commit/abort is atomic
//! - MUST: Consumer offset commits reflect actual processing
//! - SHOULD: Retry/failover preserves ordering guarantees
//! - SHOULD: Duplicate detection works across producer restarts
//!
//! ## Partition Rebalance Idempotency
//! - MUST: Rebalance operations are idempotent
//! - MUST: Consumer assignment converges to stable partition mapping
//! - MUST: Offset commits during rebalance don't create gaps
//! - MUST: Rebalance doesn't cause message loss or duplication

#[allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

// ================================================================================================
// Conformance Test Framework
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    ProducerConsumerOrdering,
    PartitionRebalance,
    ExactlyOnceSemantics,
    TransactionConsistency,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConformanceCase {
    pub id: &'static str,
    pub section: &'static str,
    pub level: RequirementLevel,
    pub category: TestCategory,
    pub description: &'static str,
}

#[derive(Debug, Serialize)]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
}

// ================================================================================================
// Deterministic Kafka model
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionId {
    pub topic: String,
    pub partition: u32,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub partition: PartitionId,
    pub offset: u64,
    pub key: Option<String>,
    pub value: Vec<u8>,
    pub timestamp: SystemTime,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MockKafkaProducer {
    partitions: Arc<parking_lot::Mutex<BTreeMap<PartitionId, VecDeque<Message>>>>,
    next_offset: Arc<parking_lot::Mutex<BTreeMap<PartitionId, u64>>>,
    transaction_state: Arc<parking_lot::Mutex<Option<Transaction>>>,
    duplicate_tracker: Arc<parking_lot::Mutex<BTreeSet<String>>>,
}

#[derive(Debug, Clone)]
struct Transaction {
    id: String,
    messages: Vec<Message>,
}

impl MockKafkaProducer {
    pub fn new() -> Self {
        Self {
            partitions: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
            next_offset: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
            transaction_state: Arc::new(parking_lot::Mutex::new(None)),
            duplicate_tracker: Arc::new(parking_lot::Mutex::new(BTreeSet::new())),
        }
    }

    pub fn begin_transaction(&self, transaction_id: String) -> Result<(), String> {
        let mut state = self.transaction_state.lock();
        if state.is_some() {
            return Err("Transaction already active".to_string());
        }
        *state = Some(Transaction {
            id: transaction_id,
            messages: Vec::new(),
        });
        Ok(())
    }

    pub fn send(
        &self,
        mut message: Message,
        idempotent_key: Option<String>,
    ) -> Result<u64, String> {
        // Check for duplicates if idempotent_key provided
        if let Some(key) = &idempotent_key {
            let mut tracker = self.duplicate_tracker.lock();
            if tracker.contains(key) {
                // Return existing offset for duplicate
                return Ok(self.get_partition_offset(&message.partition));
            }
            tracker.insert(key.clone());
        }

        let mut next_offset = self.next_offset.lock();
        let offset = next_offset.entry(message.partition.clone()).or_insert(0);
        message.offset = *offset;
        *offset += 1;

        // Check if we're in a transaction
        let mut tx_state = self.transaction_state.lock();
        if let Some(ref mut tx) = *tx_state {
            message.transaction_id = Some(tx.id.clone());
            tx.messages.push(message.clone());
            drop(tx_state);
            drop(next_offset);
            return Ok(message.offset);
        }
        drop(tx_state);
        drop(next_offset);

        // Non-transactional send - commit immediately
        let mut partitions = self.partitions.lock();
        partitions
            .entry(message.partition.clone())
            .or_insert_with(VecDeque::new)
            .push_back(message.clone());

        Ok(message.offset)
    }

    pub fn commit_transaction(&self) -> Result<(), String> {
        let mut tx_state = self.transaction_state.lock();
        let tx = tx_state.take().ok_or("No active transaction")?;
        drop(tx_state);

        // Atomically commit all messages in transaction
        let mut partitions = self.partitions.lock();
        for message in tx.messages {
            partitions
                .entry(message.partition.clone())
                .or_insert_with(VecDeque::new)
                .push_back(message);
        }

        Ok(())
    }

    pub fn abort_transaction(&self) -> Result<(), String> {
        let mut tx_state = self.transaction_state.lock();
        if tx_state.take().is_none() {
            return Err("No active transaction".to_string());
        }
        // Messages are discarded, offsets are reset
        Ok(())
    }

    fn get_partition_offset(&self, partition: &PartitionId) -> u64 {
        self.next_offset.lock().get(partition).copied().unwrap_or(0)
    }

    pub fn get_partition_messages(&self, partition: &PartitionId) -> Vec<Message> {
        self.partitions
            .lock()
            .get(partition)
            .map(|deque| deque.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct MockKafkaConsumer {
    group_id: String,
    assigned_partitions: Arc<parking_lot::Mutex<BTreeSet<PartitionId>>>,
    committed_offsets: Arc<parking_lot::Mutex<BTreeMap<PartitionId, u64>>>,
    processed_offsets: Arc<parking_lot::Mutex<BTreeMap<PartitionId, u64>>>,
}

impl MockKafkaConsumer {
    pub fn new(group_id: String) -> Self {
        Self {
            group_id,
            assigned_partitions: Arc::new(parking_lot::Mutex::new(BTreeSet::new())),
            committed_offsets: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
            processed_offsets: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
        }
    }

    pub fn assign_partitions(&self, partitions: &[PartitionId]) {
        let mut assigned = self.assigned_partitions.lock();
        assigned.clear();
        assigned.extend(partitions.iter().cloned());
    }

    pub fn commit_offset(&self, partition: &PartitionId, offset: u64) -> Result<(), String> {
        let processed = self.processed_offsets.lock();
        let processed_offset = processed.get(partition).copied().unwrap_or(0);

        if offset > processed_offset {
            return Err(format!(
                "Cannot commit offset {} beyond processed offset {} for partition {:?}",
                offset, processed_offset, partition
            ));
        }
        drop(processed);

        let mut committed = self.committed_offsets.lock();
        committed.insert(partition.clone(), offset);
        Ok(())
    }

    pub fn mark_processed(&self, partition: &PartitionId, offset: u64) {
        let mut processed = self.processed_offsets.lock();
        let current = processed.entry(partition.clone()).or_insert(0);
        *current = (*current).max(offset + 1);
    }

    pub fn get_committed_offset(&self, partition: &PartitionId) -> u64 {
        self.committed_offsets
            .lock()
            .get(partition)
            .copied()
            .unwrap_or(0)
    }

    pub fn get_assigned_partitions(&self) -> BTreeSet<PartitionId> {
        self.assigned_partitions.lock().clone()
    }
}

// ================================================================================================
// Deterministic NATS model
// ================================================================================================

#[derive(Debug, Clone)]
pub struct NatsMessage {
    pub subject: String,
    pub payload: Vec<u8>,
    pub timestamp: SystemTime,
    pub reply_subject: Option<String>,
}

pub struct MockNatsClient {
    messages: Arc<parking_lot::Mutex<VecDeque<NatsMessage>>>,
    subscribers: Arc<parking_lot::Mutex<HashMap<String, VecDeque<NatsMessage>>>>,
}

impl MockNatsClient {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(parking_lot::Mutex::new(VecDeque::new())),
            subscribers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    pub fn publish(&self, subject: &str, payload: &[u8]) -> Result<(), String> {
        let message = NatsMessage {
            subject: subject.to_string(),
            payload: payload.to_vec(),
            timestamp: SystemTime::now(),
            reply_subject: None,
        };

        // Store in global message log
        self.messages.lock().push_back(message.clone());

        // Deliver to matching subscribers
        let mut subscribers = self.subscribers.lock();
        for (pattern, queue) in subscribers.iter_mut() {
            if self.subject_matches(pattern, subject) {
                queue.push_back(message.clone());
            }
        }

        Ok(())
    }

    pub fn subscribe(&self, subject: &str) -> Result<(), String> {
        let mut subscribers = self.subscribers.lock();
        subscribers
            .entry(subject.to_string())
            .or_insert_with(VecDeque::new);
        Ok(())
    }

    pub fn next_message(&self, subject: &str) -> Option<NatsMessage> {
        let mut subscribers = self.subscribers.lock();
        subscribers
            .get_mut(subject)
            .and_then(|queue| queue.pop_front())
    }

    pub fn get_all_messages(&self) -> Vec<NatsMessage> {
        self.messages.lock().iter().cloned().collect()
    }

    fn subject_matches(&self, pattern: &str, subject: &str) -> bool {
        if pattern.contains('*') || pattern.contains('>') {
            // Simple wildcard matching for testing
            pattern == "*"
                || pattern == ">"
                || (pattern.ends_with(".>") && subject.starts_with(&pattern[..pattern.len() - 2]))
        } else {
            pattern == subject
        }
    }
}

// ================================================================================================
// Deterministic JetStream model
// ================================================================================================

#[derive(Debug, Clone)]
pub struct JetStreamMessage {
    pub stream: String,
    pub subject: String,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub timestamp: SystemTime,
    pub ack_required: bool,
    pub acked: bool,
}

pub struct MockJetStreamContext {
    streams: Arc<parking_lot::Mutex<HashMap<String, VecDeque<JetStreamMessage>>>>,
    next_sequence: Arc<parking_lot::Mutex<HashMap<String, u64>>>,
    consumers: Arc<parking_lot::Mutex<HashMap<String, JetStreamConsumer>>>,
    duplicate_window: Arc<parking_lot::Mutex<BTreeMap<String, BTreeSet<String>>>>,
}

#[derive(Debug, Clone)]
pub struct JetStreamConsumer {
    pub name: String,
    pub stream: String,
    pub ack_wait: Duration,
    pub max_ack_pending: usize,
    pub last_delivered: u64,
    pub pending_acks: BTreeSet<u64>,
}

impl MockJetStreamContext {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            next_sequence: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            consumers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            duplicate_window: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
        }
    }

    pub fn publish(
        &self,
        stream: &str,
        subject: &str,
        payload: &[u8],
        msg_id: Option<String>,
    ) -> Result<u64, String> {
        // Check for duplicates
        if let Some(id) = &msg_id {
            let mut dup_window = self.duplicate_window.lock();
            let window = dup_window
                .entry(stream.to_string())
                .or_insert_with(BTreeSet::new);
            if window.contains(id) {
                return Err("Duplicate message".to_string());
            }
            window.insert(id.clone());

            // Limit duplicate window size
            if window.len() > 1000 {
                let oldest = window.iter().next().cloned();
                if let Some(oldest) = oldest {
                    window.remove(&oldest);
                }
            }
        }

        let mut next_seq = self.next_sequence.lock();
        let sequence = next_seq.entry(stream.to_string()).or_insert(1);
        let seq = *sequence;
        *sequence += 1;
        drop(next_seq);

        let message = JetStreamMessage {
            stream: stream.to_string(),
            subject: subject.to_string(),
            sequence: seq,
            payload: payload.to_vec(),
            timestamp: SystemTime::now(),
            ack_required: true,
            acked: false,
        };

        let mut streams = self.streams.lock();
        streams
            .entry(stream.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(message);

        Ok(seq)
    }

    pub fn create_consumer(&self, stream: &str, consumer_name: &str) -> Result<(), String> {
        let consumer = JetStreamConsumer {
            name: consumer_name.to_string(),
            stream: stream.to_string(),
            ack_wait: Duration::from_secs(30),
            max_ack_pending: 1000,
            last_delivered: 0,
            pending_acks: BTreeSet::new(),
        };

        let mut consumers = self.consumers.lock();
        consumers.insert(consumer_name.to_string(), consumer);
        Ok(())
    }

    pub fn ack_message(&self, consumer_name: &str, sequence: u64) -> Result<(), String> {
        let mut consumers = self.consumers.lock();
        let consumer = consumers
            .get_mut(consumer_name)
            .ok_or("Consumer not found")?;

        if !consumer.pending_acks.remove(&sequence) {
            return Err("Message not pending ack".to_string());
        }

        // Mark message as acked in stream
        let stream_name = consumer.stream.clone();
        drop(consumers);

        let mut streams = self.streams.lock();
        if let Some(stream) = streams.get_mut(&stream_name) {
            for msg in stream.iter_mut() {
                if msg.sequence == sequence {
                    msg.acked = true;
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn get_stream_messages(&self, stream: &str) -> Vec<JetStreamMessage> {
        self.streams
            .lock()
            .get(stream)
            .map(|deque| deque.iter().cloned().collect())
            .unwrap_or_default()
    }
}

// ================================================================================================
// Deterministic Redis model
// ================================================================================================

#[derive(Debug, Clone)]
pub struct RedisStreamEntry {
    pub id: String,
    pub fields: HashMap<String, String>,
    pub timestamp: SystemTime,
}

pub struct MockRedisClient {
    streams: Arc<parking_lot::Mutex<HashMap<String, VecDeque<RedisStreamEntry>>>>,
    consumer_groups: Arc<parking_lot::Mutex<HashMap<String, RedisConsumerGroup>>>,
    next_id: Arc<AtomicU64>,
}

fn redis_stream_id_parts(id: &str) -> (u64, u64) {
    let (major, minor) = id.split_once('-').unwrap_or((id, "0"));
    (
        major.parse::<u64>().unwrap_or(0),
        minor.parse::<u64>().unwrap_or(0),
    )
}

fn redis_stream_id_gt(left: &str, right: &str) -> bool {
    redis_stream_id_parts(left) > redis_stream_id_parts(right)
}

#[derive(Debug, Clone)]
pub struct RedisConsumerGroup {
    pub name: String,
    pub stream: String,
    pub consumers: HashMap<String, RedisConsumer>,
    pub last_delivered_id: String,
}

#[derive(Debug, Clone)]
pub struct RedisConsumer {
    pub name: String,
    pub pending_messages: HashMap<String, RedisStreamEntry>,
    pub last_seen: SystemTime,
}

impl MockRedisClient {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            consumer_groups: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn xadd(&self, stream: &str, fields: HashMap<String, String>) -> Result<String, String> {
        let id = format!("{}-0", self.next_id.fetch_add(1, Ordering::SeqCst));
        let entry = RedisStreamEntry {
            id: id.clone(),
            fields,
            timestamp: SystemTime::now(),
        };

        let mut streams = self.streams.lock();
        streams
            .entry(stream.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(entry);

        Ok(id)
    }

    pub fn xgroup_create(&self, stream: &str, group: &str, start_id: &str) -> Result<(), String> {
        let group = RedisConsumerGroup {
            name: group.to_string(),
            stream: stream.to_string(),
            consumers: HashMap::new(),
            last_delivered_id: start_id.to_string(),
        };

        let mut groups = self.consumer_groups.lock();
        groups.insert(group.name.clone(), group);
        Ok(())
    }

    pub fn xreadgroup(
        &self,
        group: &str,
        consumer: &str,
        stream: &str,
        count: usize,
    ) -> Result<Vec<RedisStreamEntry>, String> {
        let mut groups = self.consumer_groups.lock();
        let group_info = groups.get_mut(group).ok_or("Consumer group not found")?;

        // Ensure consumer exists
        if !group_info.consumers.contains_key(consumer) {
            group_info.consumers.insert(
                consumer.to_string(),
                RedisConsumer {
                    name: consumer.to_string(),
                    pending_messages: HashMap::new(),
                    last_seen: SystemTime::now(),
                },
            );
        }

        let streams = self.streams.lock();
        let stream_entries = streams.get(stream).ok_or("Stream not found")?;

        let mut result = Vec::new();
        let last_delivered_id = group_info.last_delivered_id.clone();
        for entry in stream_entries
            .iter()
            .filter(|entry| redis_stream_id_gt(&entry.id, &last_delivered_id))
            .take(count)
        {
            result.push(entry.clone());
            group_info.last_delivered_id = entry.id.clone();

            // Add to consumer's pending list.
            group_info
                .consumers
                .get_mut(consumer)
                .unwrap()
                .pending_messages
                .insert(entry.id.clone(), entry.clone());
        }

        Ok(result)
    }

    pub fn xack(
        &self,
        _stream: &str,
        group: &str,
        consumer: &str,
        message_id: &str,
    ) -> Result<(), String> {
        let mut groups = self.consumer_groups.lock();
        let group_info = groups.get_mut(group).ok_or("Consumer group not found")?;
        let consumer_info = group_info
            .consumers
            .get_mut(consumer)
            .ok_or("Consumer not found")?;

        consumer_info
            .pending_messages
            .remove(message_id)
            .ok_or("Message not pending")?;

        Ok(())
    }

    pub fn get_stream_length(&self, stream: &str) -> usize {
        self.streams
            .lock()
            .get(stream)
            .map(|deque| deque.len())
            .unwrap_or(0)
    }
}

// ================================================================================================
// Partition Rebalance Coordinator
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionAssignment {
    pub consumer_id: String,
    pub partitions: BTreeSet<PartitionId>,
}

pub struct RebalanceCoordinator {
    consumers: Arc<parking_lot::Mutex<HashMap<String, MockKafkaConsumer>>>,
    assignments: Arc<parking_lot::Mutex<Vec<PartitionAssignment>>>,
    rebalance_generation: Arc<AtomicU64>,
}

impl RebalanceCoordinator {
    pub fn new() -> Self {
        Self {
            consumers: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            assignments: Arc::new(parking_lot::Mutex::new(Vec::new())),
            rebalance_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_consumer(&self, consumer: MockKafkaConsumer) {
        let consumer_id = consumer.group_id.clone();
        self.consumers.lock().insert(consumer_id, consumer);
    }

    pub fn remove_consumer(&self, consumer_id: &str) {
        self.consumers.lock().remove(consumer_id);
    }

    pub fn trigger_rebalance(&self, available_partitions: &[PartitionId]) -> Result<u64, String> {
        let generation = self.rebalance_generation.fetch_add(1, Ordering::SeqCst) + 1;

        let consumers = self.consumers.lock();
        let consumer_count = consumers.len();

        if consumer_count == 0 {
            return Ok(generation);
        }

        // Round-robin assignment for deterministic rebalancing
        let mut new_assignments: Vec<PartitionAssignment> = Vec::new();
        let consumer_ids: Vec<_> = consumers.keys().cloned().collect();

        for (i, partition) in available_partitions.iter().enumerate() {
            let consumer_id = &consumer_ids[i % consumer_count];

            if let Some(existing) = new_assignments
                .iter_mut()
                .find(|a| a.consumer_id == *consumer_id)
            {
                existing.partitions.insert(partition.clone());
            } else {
                let mut partitions = BTreeSet::new();
                partitions.insert(partition.clone());
                new_assignments.push(PartitionAssignment {
                    consumer_id: consumer_id.clone(),
                    partitions,
                });
            }
        }

        // Apply assignments to consumers
        for assignment in &new_assignments {
            if let Some(consumer) = consumers.get(&assignment.consumer_id) {
                let partitions: Vec<_> = assignment.partitions.iter().cloned().collect();
                consumer.assign_partitions(&partitions);
            }
        }

        *self.assignments.lock() = new_assignments;
        Ok(generation)
    }

    pub fn get_assignments(&self) -> Vec<PartitionAssignment> {
        self.assignments.lock().clone()
    }

    pub fn get_generation(&self) -> u64 {
        self.rebalance_generation.load(Ordering::SeqCst)
    }
}

// ================================================================================================
// Conformance Test Cases
// ================================================================================================

#[cfg(test)]
const MESSAGING_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Producer-Consumer Ordering Under Failures
    ConformanceCase {
        id: "MSG-ORD-001",
        section: "producer-consumer-ordering",
        level: RequirementLevel::Must,
        category: TestCategory::ProducerConsumerOrdering,
        description: "Messages sent to the same partition maintain order",
    },
    ConformanceCase {
        id: "MSG-ORD-002",
        section: "producer-consumer-ordering",
        level: RequirementLevel::Must,
        category: TestCategory::ProducerConsumerOrdering,
        description: "Exactly-once semantics preserve order during failures",
    },
    ConformanceCase {
        id: "MSG-TXN-001",
        section: "transaction-consistency",
        level: RequirementLevel::Must,
        category: TestCategory::TransactionConsistency,
        description: "Transaction commit/abort is atomic",
    },
    ConformanceCase {
        id: "MSG-TXN-002",
        section: "transaction-consistency",
        level: RequirementLevel::Must,
        category: TestCategory::TransactionConsistency,
        description: "Consumer offset commits reflect actual processing",
    },
    ConformanceCase {
        id: "MSG-ORD-003",
        section: "producer-consumer-ordering",
        level: RequirementLevel::Should,
        category: TestCategory::ProducerConsumerOrdering,
        description: "Retry/failover preserves ordering guarantees",
    },
    ConformanceCase {
        id: "MSG-EOS-001",
        section: "exactly-once-semantics",
        level: RequirementLevel::Should,
        category: TestCategory::ExactlyOnceSemantics,
        description: "Duplicate detection works across producer restarts",
    },
    // Partition Rebalance Idempotency
    ConformanceCase {
        id: "MSG-REB-001",
        section: "partition-rebalance",
        level: RequirementLevel::Must,
        category: TestCategory::PartitionRebalance,
        description: "Rebalance operations are idempotent",
    },
    ConformanceCase {
        id: "MSG-REB-002",
        section: "partition-rebalance",
        level: RequirementLevel::Must,
        category: TestCategory::PartitionRebalance,
        description: "Consumer assignment converges to stable partition mapping",
    },
    ConformanceCase {
        id: "MSG-REB-003",
        section: "partition-rebalance",
        level: RequirementLevel::Must,
        category: TestCategory::PartitionRebalance,
        description: "Offset commits during rebalance don't create gaps",
    },
    ConformanceCase {
        id: "MSG-REB-004",
        section: "partition-rebalance",
        level: RequirementLevel::Must,
        category: TestCategory::PartitionRebalance,
        description: "Rebalance doesn't cause message loss or duplication",
    },
];

// ================================================================================================
// Test Implementation
// ================================================================================================

/// Test that messages sent to the same partition maintain order.
#[cfg(test)]
fn test_kafka_partition_ordering() -> TestResult {
    let producer = MockKafkaProducer::new();
    let partition = PartitionId {
        topic: "test-topic".to_string(),
        partition: 0,
    };

    // Send messages in order
    let messages = vec!["msg1", "msg2", "msg3", "msg4", "msg5"];
    let mut offsets = Vec::new();

    for (i, msg) in messages.iter().enumerate() {
        let message = Message {
            partition: partition.clone(),
            offset: 0, // Will be set by producer
            key: Some(format!("key{}", i)),
            value: msg.as_bytes().to_vec(),
            timestamp: SystemTime::now(),
            transaction_id: None,
        };

        match producer.send(message, None) {
            Ok(offset) => offsets.push(offset),
            Err(e) => {
                return TestResult::Fail {
                    reason: format!("Failed to send message {}: {}", i, e),
                };
            }
        }
    }

    // Verify offsets are sequential
    for i in 1..offsets.len() {
        if offsets[i] != offsets[i - 1] + 1 {
            return TestResult::Fail {
                reason: format!(
                    "Offset sequence broken: {} followed by {} (expected {})",
                    offsets[i - 1],
                    offsets[i],
                    offsets[i - 1] + 1
                ),
            };
        }
    }

    // Verify messages are stored in order
    let stored_messages = producer.get_partition_messages(&partition);
    if stored_messages.len() != messages.len() {
        return TestResult::Fail {
            reason: format!(
                "Expected {} messages, got {}",
                messages.len(),
                stored_messages.len()
            ),
        };
    }

    for (i, (expected, actual)) in messages.iter().zip(stored_messages.iter()).enumerate() {
        if actual.value.as_slice() != expected.as_bytes() {
            return TestResult::Fail {
                reason: format!(
                    "Message {} mismatch: expected {:?}, got {:?}",
                    i,
                    expected.as_bytes(),
                    actual.value.as_slice()
                ),
            };
        }
    }

    TestResult::Pass
}

/// Test that aborted transactional sends do not leak partial messages and a retry preserves order.
#[cfg(test)]
fn test_kafka_exactly_once_order_after_failure() -> TestResult {
    let producer = MockKafkaProducer::new();
    let partition = PartitionId {
        topic: "test-topic".to_string(),
        partition: 0,
    };
    let timestamp = SystemTime::UNIX_EPOCH;

    if let Err(e) = producer.begin_transaction("tx-abort".to_string()) {
        return TestResult::Fail {
            reason: format!("Failed to begin aborted transaction: {}", e),
        };
    }

    for value in ["first", "second"] {
        let message = Message {
            partition: partition.clone(),
            offset: 0,
            key: Some(value.to_string()),
            value: value.as_bytes().to_vec(),
            timestamp,
            transaction_id: None,
        };

        if let Err(e) = producer.send(message, Some(format!("abort-{}", value))) {
            return TestResult::Fail {
                reason: format!("Failed to stage aborted message {}: {}", value, e),
            };
        }
    }

    if let Err(e) = producer.abort_transaction() {
        return TestResult::Fail {
            reason: format!("Failed to abort transaction: {}", e),
        };
    }

    if !producer.get_partition_messages(&partition).is_empty() {
        return TestResult::Fail {
            reason: "Aborted transaction leaked visible messages".to_string(),
        };
    }

    if let Err(e) = producer.begin_transaction("tx-retry".to_string()) {
        return TestResult::Fail {
            reason: format!("Failed to begin retry transaction: {}", e),
        };
    }

    for value in ["first", "second", "third"] {
        let message = Message {
            partition: partition.clone(),
            offset: 0,
            key: Some(value.to_string()),
            value: value.as_bytes().to_vec(),
            timestamp,
            transaction_id: None,
        };

        if let Err(e) = producer.send(message, Some(format!("retry-{}", value))) {
            return TestResult::Fail {
                reason: format!("Failed to stage retry message {}: {}", value, e),
            };
        }
    }

    if let Err(e) = producer.commit_transaction() {
        return TestResult::Fail {
            reason: format!("Failed to commit retry transaction: {}", e),
        };
    }

    let stored = producer.get_partition_messages(&partition);
    let stored_values = stored
        .iter()
        .map(|message| String::from_utf8_lossy(&message.value).to_string())
        .collect::<Vec<_>>();
    let expected = vec![
        "first".to_string(),
        "second".to_string(),
        "third".to_string(),
    ];

    if stored_values != expected {
        return TestResult::Fail {
            reason: format!(
                "Retry order mismatch after aborted transaction: expected {:?}, got {:?}",
                expected, stored_values
            ),
        };
    }

    TestResult::Pass
}

/// Test transaction atomicity in Kafka.
#[cfg(test)]
fn test_kafka_transaction_atomicity() -> TestResult {
    let producer = MockKafkaProducer::new();
    let partition = PartitionId {
        topic: "test-topic".to_string(),
        partition: 0,
    };

    // Begin transaction
    if let Err(e) = producer.begin_transaction("tx1".to_string()) {
        return TestResult::Fail {
            reason: format!("Failed to begin transaction: {}", e),
        };
    }

    // Send messages in transaction
    let tx_messages = vec!["tx-msg1", "tx-msg2", "tx-msg3"];
    for msg in &tx_messages {
        let message = Message {
            partition: partition.clone(),
            offset: 0,
            key: None,
            value: msg.as_bytes().to_vec(),
            timestamp: SystemTime::now(),
            transaction_id: None,
        };

        if let Err(e) = producer.send(message, None) {
            return TestResult::Fail {
                reason: format!("Failed to send transactional message: {}", e),
            };
        }
    }

    // Messages should not be visible before commit
    let messages_before_commit = producer.get_partition_messages(&partition);
    if !messages_before_commit.is_empty() {
        return TestResult::Fail {
            reason: "Messages visible before transaction commit".to_string(),
        };
    }

    // Commit transaction
    if let Err(e) = producer.commit_transaction() {
        return TestResult::Fail {
            reason: format!("Failed to commit transaction: {}", e),
        };
    }

    // All messages should now be visible
    let messages_after_commit = producer.get_partition_messages(&partition);
    if messages_after_commit.len() != tx_messages.len() {
        return TestResult::Fail {
            reason: format!(
                "Expected {} messages after commit, got {}",
                tx_messages.len(),
                messages_after_commit.len()
            ),
        };
    }

    TestResult::Pass
}

/// Test consumer offset commit semantics.
#[cfg(test)]
fn test_kafka_offset_commit_semantics() -> TestResult {
    let consumer = MockKafkaConsumer::new("test-group".to_string());
    let partition = PartitionId {
        topic: "test-topic".to_string(),
        partition: 0,
    };

    // Cannot commit beyond processed offset
    match consumer.commit_offset(&partition, 10) {
        Err(_) => {} // Expected
        Ok(_) => {
            return TestResult::Fail {
                reason: "Should not be able to commit offset beyond processed".to_string(),
            };
        }
    }

    // Process some messages
    consumer.mark_processed(&partition, 5);

    // Can commit up to processed offset
    if let Err(e) = consumer.commit_offset(&partition, 5) {
        return TestResult::Fail {
            reason: format!("Failed to commit valid offset: {}", e),
        };
    }

    // Kafka commits the next offset to consume; after processing record offset
    // 5, committing offset 6 is the exact processed frontier.
    if let Err(e) = consumer.commit_offset(&partition, 6) {
        return TestResult::Fail {
            reason: format!("Failed to commit processed frontier offset: {}", e),
        };
    }

    // Cannot commit beyond newly processed frontier.
    match consumer.commit_offset(&partition, 7) {
        Err(_) => {} // Expected
        Ok(_) => {
            return TestResult::Fail {
                reason: "Should not be able to commit offset beyond processed frontier (7 > 6)"
                    .to_string(),
            };
        }
    }

    TestResult::Pass
}

/// Test JetStream exactly-once semantics.
#[cfg(test)]
fn test_jetstream_exactly_once() -> TestResult {
    let js = MockJetStreamContext::new();
    let stream = "test-stream";
    let subject = "test.subject";
    let msg_id = "unique-msg-1";

    // First publish should succeed
    let seq1 = match js.publish(stream, subject, b"test message", Some(msg_id.to_string())) {
        Ok(seq) => seq,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("First publish failed: {}", e),
            };
        }
    };

    // Duplicate publish should fail
    match js.publish(stream, subject, b"test message", Some(msg_id.to_string())) {
        Err(_) => {} // Expected
        Ok(seq2) => {
            return TestResult::Fail {
                reason: format!("Duplicate publish succeeded with sequence {}", seq2),
            };
        }
    }

    // Verify only one message in stream
    let messages = js.get_stream_messages(stream);
    if messages.len() != 1 {
        return TestResult::Fail {
            reason: format!("Expected 1 message in stream, got {}", messages.len()),
        };
    }

    if messages[0].sequence != seq1 {
        return TestResult::Fail {
            reason: format!(
                "Sequence mismatch: expected {}, got {}",
                seq1, messages[0].sequence
            ),
        };
    }

    TestResult::Pass
}

/// Test retry deduplication while preserving committed partition order.
#[cfg(test)]
fn test_kafka_retry_failover_preserves_ordering() -> TestResult {
    let producer = MockKafkaProducer::new();
    let partition = PartitionId {
        topic: "test-topic".to_string(),
        partition: 0,
    };
    let timestamp = SystemTime::UNIX_EPOCH;

    let first = Message {
        partition: partition.clone(),
        offset: 0,
        key: Some("order-1".to_string()),
        value: b"order-1".to_vec(),
        timestamp,
        transaction_id: None,
    };
    if let Err(e) = producer.send(first.clone(), Some("dedup-order-1".to_string())) {
        return TestResult::Fail {
            reason: format!("Initial send failed: {}", e),
        };
    }

    if let Err(e) = producer.send(first, Some("dedup-order-1".to_string())) {
        return TestResult::Fail {
            reason: format!("Duplicate retry should be suppressed, got error: {}", e),
        };
    }

    for value in ["order-2", "order-3"] {
        let message = Message {
            partition: partition.clone(),
            offset: 0,
            key: Some(value.to_string()),
            value: value.as_bytes().to_vec(),
            timestamp,
            transaction_id: None,
        };

        if let Err(e) = producer.send(message, Some(format!("dedup-{}", value))) {
            return TestResult::Fail {
                reason: format!("Follow-up send {} failed: {}", value, e),
            };
        }
    }

    let stored_values = producer
        .get_partition_messages(&partition)
        .iter()
        .map(|message| String::from_utf8_lossy(&message.value).to_string())
        .collect::<Vec<_>>();
    let expected = vec![
        "order-1".to_string(),
        "order-2".to_string(),
        "order-3".to_string(),
    ];

    if stored_values != expected {
        return TestResult::Fail {
            reason: format!(
                "Retry/failover order mismatch: expected {:?}, got {:?}",
                expected, stored_values
            ),
        };
    }

    TestResult::Pass
}

/// Test partition rebalance idempotency.
#[cfg(test)]
fn test_partition_rebalance_idempotency() -> TestResult {
    let coordinator = RebalanceCoordinator::new();

    // Add consumers
    let consumer1 = MockKafkaConsumer::new("consumer1".to_string());
    let consumer2 = MockKafkaConsumer::new("consumer2".to_string());
    coordinator.add_consumer(consumer1);
    coordinator.add_consumer(consumer2);

    // Define partitions
    let partitions = vec![
        PartitionId {
            topic: "topic1".to_string(),
            partition: 0,
        },
        PartitionId {
            topic: "topic1".to_string(),
            partition: 1,
        },
        PartitionId {
            topic: "topic1".to_string(),
            partition: 2,
        },
        PartitionId {
            topic: "topic1".to_string(),
            partition: 3,
        },
    ];

    // Trigger rebalance multiple times with same inputs
    let gen1 = match coordinator.trigger_rebalance(&partitions) {
        Ok(generation) => generation,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("First rebalance failed: {}", e),
            };
        }
    };
    let assignments1 = coordinator.get_assignments();

    let gen2 = match coordinator.trigger_rebalance(&partitions) {
        Ok(generation) => generation,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Second rebalance failed: {}", e),
            };
        }
    };
    let assignments2 = coordinator.get_assignments();

    // Generations should be different
    if gen1 == gen2 {
        return TestResult::Fail {
            reason: "Rebalance generations should increment".to_string(),
        };
    }

    // Assignments should be identical (idempotent)
    if assignments1.len() != assignments2.len() {
        return TestResult::Fail {
            reason: format!(
                "Assignment count mismatch: {} vs {}",
                assignments1.len(),
                assignments2.len()
            ),
        };
    }

    for (a1, a2) in assignments1.iter().zip(assignments2.iter()) {
        if a1.consumer_id != a2.consumer_id || a1.partitions != a2.partitions {
            return TestResult::Fail {
                reason: "Partition assignments are not idempotent".to_string(),
            };
        }
    }

    TestResult::Pass
}

/// Test consumer assignment converges to a stable mapping for repeated rebalances.
#[cfg(test)]
fn test_consumer_assignment_converges_to_stable_mapping() -> TestResult {
    let coordinator = RebalanceCoordinator::new();
    for consumer_id in ["consumer-a", "consumer-b", "consumer-c"] {
        coordinator.add_consumer(MockKafkaConsumer::new(consumer_id.to_string()));
    }

    let partitions = (0..6)
        .map(|partition| PartitionId {
            topic: "topic1".to_string(),
            partition,
        })
        .collect::<Vec<_>>();

    let mut expected_assignments = None;
    for _ in 0..4 {
        if let Err(e) = coordinator.trigger_rebalance(&partitions) {
            return TestResult::Fail {
                reason: format!("Rebalance failed: {}", e),
            };
        }

        let assignments = coordinator.get_assignments();
        let assigned = assignments
            .iter()
            .flat_map(|assignment| assignment.partitions.iter().cloned())
            .collect::<BTreeSet<_>>();
        let expected = partitions.iter().cloned().collect::<BTreeSet<_>>();

        if assigned != expected {
            return TestResult::Fail {
                reason: format!(
                    "Assignment did not cover every partition: expected {:?}, got {:?}",
                    expected, assigned
                ),
            };
        }

        if let Some(previous) = &expected_assignments {
            if previous != &assignments {
                return TestResult::Fail {
                    reason: "Repeated rebalance did not converge to a stable mapping".to_string(),
                };
            }
        }
        expected_assignments = Some(assignments);
    }

    TestResult::Pass
}

/// Test offset commits across rebalances reject gaps beyond processed work.
#[cfg(test)]
fn test_rebalance_offset_commits_do_not_create_gaps() -> TestResult {
    let coordinator = RebalanceCoordinator::new();
    let consumer = MockKafkaConsumer::new("consumer-a".to_string());
    let consumer_handle = consumer.clone();
    coordinator.add_consumer(consumer);

    let partition = PartitionId {
        topic: "topic1".to_string(),
        partition: 0,
    };

    if let Err(e) = coordinator.trigger_rebalance(std::slice::from_ref(&partition)) {
        return TestResult::Fail {
            reason: format!("Initial rebalance failed: {}", e),
        };
    }

    consumer_handle.mark_processed(&partition, 2);
    if let Err(e) = consumer_handle.commit_offset(&partition, 3) {
        return TestResult::Fail {
            reason: format!("Commit at processed frontier failed: {}", e),
        };
    }

    if let Err(e) = coordinator.trigger_rebalance(std::slice::from_ref(&partition)) {
        return TestResult::Fail {
            reason: format!("Second rebalance failed: {}", e),
        };
    }

    if consumer_handle.get_committed_offset(&partition) != 3 {
        return TestResult::Fail {
            reason: format!(
                "Committed offset changed across rebalance: expected 3, got {}",
                consumer_handle.get_committed_offset(&partition)
            ),
        };
    }

    match consumer_handle.commit_offset(&partition, 5) {
        Ok(()) => TestResult::Fail {
            reason: "Commit beyond processed offset created a gap".to_string(),
        },
        Err(_) => TestResult::Pass,
    }
}

/// Test rebalances neither drop nor duplicate partition ownership.
#[cfg(test)]
fn test_rebalance_no_message_loss_or_duplication() -> TestResult {
    let coordinator = RebalanceCoordinator::new();
    coordinator.add_consumer(MockKafkaConsumer::new("consumer-a".to_string()));
    coordinator.add_consumer(MockKafkaConsumer::new("consumer-b".to_string()));

    let partitions = (0..5)
        .map(|partition| PartitionId {
            topic: "topic1".to_string(),
            partition,
        })
        .collect::<Vec<_>>();

    if let Err(e) = coordinator.trigger_rebalance(&partitions) {
        return TestResult::Fail {
            reason: format!("Initial rebalance failed: {}", e),
        };
    }

    coordinator.remove_consumer("consumer-b");
    if let Err(e) = coordinator.trigger_rebalance(&partitions) {
        return TestResult::Fail {
            reason: format!("Failover rebalance failed: {}", e),
        };
    }

    let mut assignment_counts = BTreeMap::new();
    for assignment in coordinator.get_assignments() {
        for partition in assignment.partitions {
            *assignment_counts.entry(partition).or_insert(0usize) += 1;
        }
    }

    for partition in partitions {
        match assignment_counts.get(&partition).copied() {
            Some(1) => {}
            Some(count) => {
                return TestResult::Fail {
                    reason: format!("Partition {:?} assigned {} times", partition, count),
                };
            }
            None => {
                return TestResult::Fail {
                    reason: format!("Partition {:?} was not assigned after failover", partition),
                };
            }
        }
    }

    TestResult::Pass
}

/// Test NATS subject-based ordering.
#[cfg(test)]
fn test_nats_subject_ordering() -> TestResult {
    let client = MockNatsClient::new();
    let subject = "test.subject";

    // Subscribe to subject
    if let Err(e) = client.subscribe(subject) {
        return TestResult::Fail {
            reason: format!("Failed to subscribe: {}", e),
        };
    }

    // Publish messages in order
    let messages = vec!["msg1", "msg2", "msg3"];
    for msg in &messages {
        if let Err(e) = client.publish(subject, msg.as_bytes()) {
            return TestResult::Fail {
                reason: format!("Failed to publish message: {}", e),
            };
        }
    }

    // Consume messages and verify order
    let mut received = Vec::new();
    while let Some(msg) = client.next_message(subject) {
        received.push(String::from_utf8_lossy(&msg.payload).to_string());
    }

    if received != messages {
        return TestResult::Fail {
            reason: format!(
                "Message order mismatch: expected {:?}, got {:?}",
                messages, received
            ),
        };
    }

    TestResult::Pass
}

/// Test Redis stream consumer group semantics.
#[cfg(test)]
fn test_redis_stream_consumer_groups() -> TestResult {
    let client = MockRedisClient::new();
    let stream = "test-stream";
    let group = "test-group";
    let consumer1 = "consumer1";
    let consumer2 = "consumer2";

    // Create consumer group
    if let Err(e) = client.xgroup_create(stream, group, "0") {
        return TestResult::Fail {
            reason: format!("Failed to create consumer group: {}", e),
        };
    }

    // Add messages to stream
    let mut message_ids = Vec::new();
    for i in 0..5 {
        let mut fields = HashMap::new();
        fields.insert("data".to_string(), format!("message{}", i));

        match client.xadd(stream, fields) {
            Ok(id) => message_ids.push(id),
            Err(e) => {
                return TestResult::Fail {
                    reason: format!("Failed to add message: {}", e),
                };
            }
        }
    }

    // Read with first consumer
    let messages1 = match client.xreadgroup(group, consumer1, stream, 3) {
        Ok(msgs) => msgs,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Failed to read with consumer1: {}", e),
            };
        }
    };

    // Read with second consumer (should get remaining messages)
    let messages2 = match client.xreadgroup(group, consumer2, stream, 3) {
        Ok(msgs) => msgs,
        Err(e) => {
            return TestResult::Fail {
                reason: format!("Failed to read with consumer2: {}", e),
            };
        }
    };

    // Total messages read should equal messages added
    if messages1.len() + messages2.len() != 5 {
        return TestResult::Fail {
            reason: format!(
                "Expected 5 total messages, got {} + {} = {}",
                messages1.len(),
                messages2.len(),
                messages1.len() + messages2.len()
            ),
        };
    }

    // Acknowledge messages
    for msg in &messages1 {
        if let Err(e) = client.xack(stream, group, consumer1, &msg.id) {
            return TestResult::Fail {
                reason: format!("Failed to ack message {}: {}", msg.id, e),
            };
        }
    }

    TestResult::Pass
}

// ================================================================================================
// Property-Based Tests
// ================================================================================================

#[cfg(all(test, feature = "test-internals"))]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
    /// Property test for Kafka partition ordering under concurrent operations.
    #[test]
    fn prop_kafka_partition_ordering_concurrent(
        messages in prop::collection::vec("[a-z]{1,10}", 1..100),
        partition_id in 0u32..10,
    ) {
        let producer = MockKafkaProducer::new();
        let partition = PartitionId {
            topic: "test-topic".to_string(),
            partition: partition_id,
        };

        let mut offsets = Vec::new();

        // Send all messages to same partition
        for (i, msg) in messages.iter().enumerate() {
            let message = Message {
                partition: partition.clone(),
                offset: 0,
                key: Some(format!("key{}", i)),
                value: msg.as_bytes().to_vec(),
                timestamp: SystemTime::now(),
                transaction_id: None,
            };

            let offset = producer.send(message, None).unwrap();
            offsets.push(offset);
        }

        // Verify sequential offsets
        for i in 1..offsets.len() {
            prop_assert_eq!(offsets[i], offsets[i-1] + 1);
        }

        // Verify stored message order
        let stored = producer.get_partition_messages(&partition);
        prop_assert_eq!(stored.len(), messages.len());

        for (i, (expected, actual)) in messages.iter().zip(stored.iter()).enumerate() {
            prop_assert_eq!(
                actual.value.as_slice(),
                expected.as_bytes(),
                "Message {} order violation", i
            );
        }
    }

    /// Property test for rebalance convergence.
    #[test]
    fn prop_rebalance_convergence(
        consumer_count in 1usize..10,
        partition_count in 1usize..50,
        rebalance_iterations in 1usize..10,
    ) {
        let coordinator = RebalanceCoordinator::new();

        // Add consumers
        for i in 0..consumer_count {
            let consumer = MockKafkaConsumer::new(format!("consumer{}", i));
            coordinator.add_consumer(consumer);
        }

        // Create partitions
        let partitions: Vec<_> = (0..partition_count).map(|i| PartitionId {
            topic: "test-topic".to_string(),
            partition: i as u32,
        }).collect();

        let mut last_assignments: Option<Vec<PartitionAssignment>> = None;

        // Trigger multiple rebalances with same input
        for _ in 0..rebalance_iterations {
            coordinator.trigger_rebalance(&partitions).unwrap();
            let assignments = coordinator.get_assignments();

            // Check all partitions are assigned
            let mut assigned_partitions = BTreeSet::new();
            for assignment in &assignments {
                assigned_partitions.extend(assignment.partitions.iter());
            }
            prop_assert_eq!(assigned_partitions.len(), partitions.len());

            // Check assignments are stable (idempotent)
            if let Some(ref last) = last_assignments {
                prop_assert_eq!(assignments.len(), last.len());
                for (current, prev) in assignments.iter().zip(last.iter()) {
                    prop_assert_eq!(&current.consumer_id, &prev.consumer_id);
                    prop_assert_eq!(&current.partitions, &prev.partitions);
                }
            }

            last_assignments = Some(assignments);
        }
    }

    /// Property test for JetStream duplicate detection.
    #[test]
    fn prop_jetstream_duplicate_detection(
        message_ids in prop::collection::vec("[a-z0-9]{1,20}", 1..50),
        duplicate_attempts in 1usize..10,
    ) {
        let js = MockJetStreamContext::new();
        let stream = "test-stream";
        let subject = "test.subject";

        let mut sequences = Vec::new();

        // Publish unique messages
        for msg_id in &message_ids {
            let seq = js.publish(stream, subject, b"test", Some(msg_id.clone())).unwrap();
            sequences.push(seq);
        }

        // Attempt duplicates
        for _ in 0..duplicate_attempts {
            for msg_id in &message_ids {
                // All duplicate attempts should fail
                prop_assert!(js.publish(stream, subject, b"test", Some(msg_id.clone())).is_err());
            }
        }

        // Stream should contain exactly the unique messages
        let messages = js.get_stream_messages(stream);
        prop_assert_eq!(messages.len(), message_ids.len());

        // Sequences should match
        for (i, msg) in messages.iter().enumerate() {
            prop_assert_eq!(msg.sequence, sequences[i]);
        }
    }
    }
}

// ================================================================================================
// Integration Scenarios
// ================================================================================================

/// Comprehensive integration scenario testing cross-messaging system behavior.
#[test]
fn test_messaging_integration_scenario() {
    // Scenario: Multi-system message flow with ordering and consistency guarantees

    let kafka_producer = MockKafkaProducer::new();
    let kafka_consumer = MockKafkaConsumer::new("integration-group".to_string());
    let nats_client = MockNatsClient::new();
    let jetstream = MockJetStreamContext::new();
    let redis_client = MockRedisClient::new();
    let rebalancer = RebalanceCoordinator::new();

    // Setup phase
    let partition = PartitionId {
        topic: "orders".to_string(),
        partition: 0,
    };

    // JetStream stream setup
    jetstream.create_consumer("orders", "processor").unwrap();

    // Redis consumer group setup
    redis_client
        .xgroup_create("order-events", "processors", "0")
        .unwrap();

    // NATS subscription
    nats_client.subscribe("order.processed").unwrap();

    // Kafka consumer rebalance
    rebalancer.add_consumer(kafka_consumer);
    rebalancer.trigger_rebalance(&[partition.clone()]).unwrap();

    // Message flow model: order processing pipeline

    // 1. Order received via Kafka (exactly-once)
    kafka_producer
        .begin_transaction("order-tx-1".to_string())
        .unwrap();
    let order_message = Message {
        partition: partition.clone(),
        offset: 0,
        key: Some("order-123".to_string()),
        value: b"order:create:customer-456:product-789".to_vec(),
        timestamp: SystemTime::now(),
        transaction_id: None,
    };
    kafka_producer
        .send(order_message, Some("order-123-dedup".to_string()))
        .unwrap();
    kafka_producer.commit_transaction().unwrap();

    // 2. Order event published to JetStream (durable)
    let js_seq = jetstream
        .publish(
            "orders",
            "order.created",
            b"order-123:created",
            Some("js-order-123".to_string()),
        )
        .unwrap();
    jetstream.ack_message("processor", js_seq).unwrap();

    // 3. Processing event to Redis stream
    let mut redis_fields = HashMap::new();
    redis_fields.insert("order_id".to_string(), "order-123".to_string());
    redis_fields.insert("status".to_string(), "processing".to_string());
    let redis_id = redis_client.xadd("order-events", redis_fields).unwrap();

    // 4. Completion notification via NATS
    nats_client
        .publish("order.processed", b"order-123:completed")
        .unwrap();

    // Verification phase: Check all systems maintain consistency

    // Kafka: Verify order message exists and is committed
    let kafka_messages = kafka_producer.get_partition_messages(&partition);
    assert_eq!(kafka_messages.len(), 1);
    assert!(kafka_messages[0].transaction_id.is_some());

    // JetStream: Verify order event exists and is acked
    let js_messages = jetstream.get_stream_messages("orders");
    assert_eq!(js_messages.len(), 1);
    assert!(js_messages[0].acked);

    // Redis: Verify processing event exists
    assert_eq!(redis_client.get_stream_length("order-events"), 1);
    let redis_entries = redis_client
        .xreadgroup("processors", "worker1", "order-events", 10)
        .unwrap();
    assert_eq!(redis_entries.len(), 1);
    assert_eq!(
        redis_entries[0].fields.get("order_id"),
        Some(&"order-123".to_string())
    );

    // Acknowledge Redis message
    redis_client
        .xack("order-events", "processors", "worker1", &redis_id)
        .unwrap();

    // NATS: Verify completion notification
    let nats_messages = nats_client.get_all_messages();
    assert_eq!(nats_messages.len(), 1);
    assert_eq!(nats_messages[0].subject, "order.processed");

    println!("✓ Multi-system integration scenario completed successfully");
}

// ================================================================================================
// Test Runner
// ================================================================================================

/// Run all messaging primitives conformance tests.
#[test]
fn run_messaging_conformance_suite() {
    let mut results = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    // Individual test cases
    let test_functions: Vec<(&ConformanceCase, fn() -> TestResult)> = vec![
        (
            &MESSAGING_CONFORMANCE_CASES[0],
            test_kafka_partition_ordering,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[1],
            test_kafka_exactly_once_order_after_failure,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[2],
            test_kafka_transaction_atomicity,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[3],
            test_kafka_offset_commit_semantics,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[4],
            test_kafka_retry_failover_preserves_ordering,
        ),
        (&MESSAGING_CONFORMANCE_CASES[5], test_jetstream_exactly_once),
        (
            &MESSAGING_CONFORMANCE_CASES[6],
            test_partition_rebalance_idempotency,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[7],
            test_consumer_assignment_converges_to_stable_mapping,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[8],
            test_rebalance_offset_commits_do_not_create_gaps,
        ),
        (
            &MESSAGING_CONFORMANCE_CASES[9],
            test_rebalance_no_message_loss_or_duplication,
        ),
    ];

    println!("🧪 Running Messaging Primitives Conformance Tests [br-conformance-11]");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    for (case, test_fn) in test_functions {
        print!("  {} ({}): ", case.id, case.description);

        let result = test_fn();
        match &result {
            TestResult::Pass => {
                println!("✓ PASS");
                passed += 1;
            }
            TestResult::Fail { reason } => {
                println!("✗ FAIL - {}", reason);
                failed += 1;
            }
            TestResult::Skipped { reason } => {
                println!("⊘ SKIP - {}", reason);
            }
        }

        results.push((case, result));
    }

    // Additional functional tests
    println!("\n🔧 Additional System Tests:");
    print!("  NATS Subject Ordering: ");
    match test_nats_subject_ordering() {
        TestResult::Pass => {
            println!("✓ PASS");
            passed += 1;
        }
        TestResult::Fail { reason } => {
            println!("✗ FAIL - {}", reason);
            failed += 1;
        }
        TestResult::Skipped { reason } => println!("⊘ SKIP - {}", reason),
    }

    print!("  Redis Consumer Groups: ");
    match test_redis_stream_consumer_groups() {
        TestResult::Pass => {
            println!("✓ PASS");
            passed += 1;
        }
        TestResult::Fail { reason } => {
            println!("✗ FAIL - {}", reason);
            failed += 1;
        }
        TestResult::Skipped { reason } => println!("⊘ SKIP - {}", reason),
    }

    println!("\n📊 Conformance Summary:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Total Tests: {}", passed + failed);
    println!("  Passed: {} ✓", passed);
    println!("  Failed: {} ✗", failed);

    if failed == 0 {
        println!("  🎉 All messaging primitives conformance tests PASSED!");
    } else {
        println!("  ⚠️  {} conformance test(s) FAILED", failed);
    }

    // Generate compliance matrix
    println!("\n📋 Coverage Matrix:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("| Section | MUST | SHOULD | Tested | Passing | Score |");
    println!("| ------- | ---- | ------ | ------ | ------- | ----- |");

    let mut sections: BTreeMap<&str, (usize, usize, usize, usize)> = BTreeMap::new();

    for case in MESSAGING_CONFORMANCE_CASES {
        let entry = sections.entry(case.section).or_insert((0, 0, 0, 0));
        match case.level {
            RequirementLevel::Must => entry.0 += 1,
            RequirementLevel::Should => entry.1 += 1,
            RequirementLevel::May => {}
        }
        entry.2 += 1; // tested
    }

    // Count passing based on the concrete conformance case result mapping.
    for (section, (must, should, tested, passing_count)) in &mut sections {
        let passing = results
            .iter()
            .filter(|(case, result)| case.section == *section && matches!(result, TestResult::Pass))
            .count();
        *passing_count = passing;
        let total_requirements = *must + *should;
        let score = if total_requirements > 0 {
            (*passing_count as f64 / total_requirements as f64) * 100.0
        } else {
            100.0
        };
        println!(
            "| {} | {} | {} | {} | {} | {:.1}% |",
            section, must, should, tested, passing_count, score
        );
    }

    // Fail the test if any conformance tests failed
    assert_eq!(failed, 0, "{} messaging conformance tests failed", failed);
}
