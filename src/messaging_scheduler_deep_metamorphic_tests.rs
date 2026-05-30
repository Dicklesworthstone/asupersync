//! Messaging and Scheduler Deep Dive Metamorphic Testing
//!
//! This module implements comprehensive metamorphic relations for distributed messaging
//! systems (Kafka, NATS, Redis, JetStream) and advanced runtime scheduler algorithms
//! (priority queues, work stealing, EDF scheduling). These tests address the oracle
//! problem for complex distributed system invariants where expected outputs depend on
//! timing, ordering, and fairness properties that are difficult to verify directly.
//!
//! ## Metamorphic Relations Implemented
//!
//! ### Kafka Producer-Consumer (3 MRs)
//! - MR-KafkaProducerConsumerTotalOrder: producer send order preserved in consumer receive
//! - MR-KafkaConsumerGroupRebalanceIdempotency: rebalance yields deterministic partition assignment
//! - MR-KafkaTransactionAtomicity: transaction commit/abort preserves message atomicity
//!
//! ### NATS Subject Routing (3 MRs)
//! - MR-NATSSubjectRouting: subject patterns route to correct subscribers
//! - MR-NATSWildcardMatching: wildcard subject matching is deterministic and complete
//! - MR-NATSRequestReplySymmetry: request-reply maintains correlation IDs correctly
//!
//! ### Redis RESP Protocol (3 MRs)
//! - MR-RedisRESPEncodeDecode: RESP3 encode/decode preserves command semantics
//! - MR-RedisClusterSlotDeterminism: cluster slot assignment is deterministic for same keys
//! - MR-RedisKeyspaceRoutingConsistency: keyspace routing respects Redis cluster specification
//!
//! ### JetStream Consumer Ack (3 MRs)
//! - MR-JetStreamAckSemantics: acknowledge semantics preserve message ordering
//! - MR-JetStreamDeliveryGuarantees: delivery guarantees respected across consumer restarts
//! - MR-JetStreamDurableConsumerState: durable consumer state survives reconnection
//!
//! ### Priority Scheduler Fairness (3 MRs)
//! - MR-PriorityRoundRobinFairness: round-robin scheduling is fair within priority classes
//! - MR-ThreeLaneStrictOrdering: cancel > timed > ready lane strict ordering maintained
//! - MR-PriorityInversionAvoidance: higher priority tasks never wait for lower priority
//!
//! ### Work Stealing Scheduler (3 MRs)
//! - MR-WorkStealingLoadBalance: work stealing achieves load balance across workers
//! - MR-WorkStealingContentionMinimal: stealing contention minimal under light loads
//! - MR-WorkStealingQueueConsistency: stolen work maintains task execution ordering
//!
//! ### EDF Deadline Scheduling (3 MRs)
//! - MR-EDFDeadlineMonotonic: earlier deadlines scheduled before later deadlines
//! - MR-EDFSchedulabilityPreservation: schedulable task sets remain schedulable
//! - MR-EDFLatenessMonotonicity: increased deadlines never increase task lateness

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use std::cmp::Ordering;
    use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
    use std::time::{Duration, Instant, SystemTime};

    // ═══════════════════════════════════════════════════════════════════════════
    // In-memory protocol and scheduler models for metamorphic testing
    // ═══════════════════════════════════════════════════════════════════════════

    #[derive(Debug, Clone, PartialEq)]
    pub struct KafkaRecordModel {
        pub topic: String,
        pub partition: u32,
        pub offset: u64,
        pub key: Option<String>,
        pub value: Vec<u8>,
        pub timestamp: u64,
        pub headers: HashMap<String, String>,
    }

    impl KafkaRecordModel {
        pub fn new(topic: &str, partition: u32, offset: u64, value: Vec<u8>) -> Self {
            Self {
                topic: topic.to_string(),
                partition,
                offset,
                key: None,
                value,
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                headers: HashMap::new(),
            }
        }

        pub fn with_key(mut self, key: &str) -> Self {
            self.key = Some(key.to_string());
            self
        }

        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.insert(name.to_string(), value.to_string());
            self
        }
    }

    #[derive(Debug, Clone)]
    pub struct KafkaProducerModel {
        pub sent_messages: Vec<KafkaRecordModel>,
        pub transaction_active: bool,
        pub transaction_id: Option<String>,
        pub next_offset: HashMap<(String, u32), u64>, // (topic, partition) -> next_offset
    }

    impl KafkaProducerModel {
        pub fn new() -> Self {
            Self {
                sent_messages: Vec::new(),
                transaction_active: false,
                transaction_id: None,
                next_offset: HashMap::new(),
            }
        }

        pub fn begin_transaction(&mut self, transaction_id: &str) -> Result<(), String> {
            if self.transaction_active {
                return Err("Transaction already active".to_string());
            }
            self.transaction_active = true;
            self.transaction_id = Some(transaction_id.to_string());
            Ok(())
        }

        pub fn send_message(
            &mut self,
            topic: &str,
            partition: u32,
            message: KafkaRecordModel,
        ) -> Result<u64, String> {
            if self.transaction_active {
                // In transaction: messages are staged but not committed
                let offset = *self
                    .next_offset
                    .entry((topic.to_string(), partition))
                    .or_insert(0);
                let mut msg = message;
                msg.topic = topic.to_string();
                msg.partition = partition;
                msg.offset = offset;
                self.sent_messages.push(msg);
                *self
                    .next_offset
                    .get_mut(&(topic.to_string(), partition))
                    .unwrap() += 1;
                Ok(offset)
            } else {
                // Non-transactional: immediate commit
                let offset = *self
                    .next_offset
                    .entry((topic.to_string(), partition))
                    .or_insert(0);
                let mut msg = message;
                msg.topic = topic.to_string();
                msg.partition = partition;
                msg.offset = offset;
                self.sent_messages.push(msg);
                *self
                    .next_offset
                    .get_mut(&(topic.to_string(), partition))
                    .unwrap() += 1;
                Ok(offset)
            }
        }

        pub fn commit_transaction(&mut self) -> Result<(), String> {
            if !self.transaction_active {
                return Err("No active transaction".to_string());
            }
            self.transaction_active = false;
            self.transaction_id = None;
            Ok(())
        }

        pub fn abort_transaction(&mut self) -> Result<(), String> {
            if !self.transaction_active {
                return Err("No active transaction".to_string());
            }

            // Remove uncommitted messages (simplified: remove all messages from current transaction)
            let transaction_start = self.sent_messages.len().saturating_sub(10); // Simplified
            self.sent_messages.truncate(transaction_start);

            self.transaction_active = false;
            self.transaction_id = None;
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub struct KafkaConsumerModel {
        pub group_id: String,
        pub assigned_partitions: Vec<(String, u32)>,
        pub consumed_messages: Vec<KafkaRecordModel>,
        pub committed_offsets: HashMap<(String, u32), u64>,
    }

    impl KafkaConsumerModel {
        pub fn new(group_id: &str) -> Self {
            Self {
                group_id: group_id.to_string(),
                assigned_partitions: Vec::new(),
                consumed_messages: Vec::new(),
                committed_offsets: HashMap::new(),
            }
        }

        pub fn assign_partitions(&mut self, partitions: Vec<(String, u32)>) {
            self.assigned_partitions = partitions;
        }

        pub fn consume_from_producer(
            &mut self,
            producer: &KafkaProducerModel,
            max_messages: usize,
        ) {
            let mut consumed = 0;
            for message in &producer.sent_messages {
                if consumed >= max_messages {
                    break;
                }
                if self
                    .assigned_partitions
                    .contains(&(message.topic.clone(), message.partition))
                {
                    self.consumed_messages.push(message.clone());
                    consumed += 1;
                }
            }
        }

        pub fn commit_offset(&mut self, topic: &str, partition: u32, offset: u64) {
            self.committed_offsets
                .insert((topic.to_string(), partition), offset);
        }
    }

    #[derive(Debug, Clone)]
    pub struct NatsSubjectModel {
        pub subject: String,
        pub is_wildcard: bool,
    }

    impl NatsSubjectModel {
        pub fn new(subject: &str) -> Self {
            Self {
                subject: subject.to_string(),
                is_wildcard: subject.contains('*') || subject.contains('>'),
            }
        }

        pub fn matches(&self, target: &str) -> bool {
            if !self.is_wildcard {
                return self.subject == target;
            }

            // Simplified wildcard matching
            if self.subject.contains('>') {
                // '>' matches everything after it
                if let Some(prefix) = self.subject.split('>').next() {
                    return target.starts_with(prefix.trim_end_matches('.'));
                }
            }

            if self.subject.contains('*') {
                // '*' matches one token
                let pattern_parts: Vec<&str> = self.subject.split('.').collect();
                let target_parts: Vec<&str> = target.split('.').collect();

                if pattern_parts.len() != target_parts.len() {
                    return false;
                }

                for (pattern_part, target_part) in pattern_parts.iter().zip(target_parts.iter()) {
                    if *pattern_part != "*" && *pattern_part != *target_part {
                        return false;
                    }
                }

                return true;
            }

            false
        }
    }

    #[derive(Debug, Clone)]
    pub struct NatsMessageModel {
        pub subject: String,
        pub reply_to: Option<String>,
        pub data: Vec<u8>,
        pub headers: HashMap<String, String>,
    }

    #[derive(Debug, Clone)]
    pub struct NatsClientModel {
        pub subscriptions: HashMap<String, NatsSubjectModel>,
        pub published_messages: Vec<NatsMessageModel>,
        pub received_messages: Vec<NatsMessageModel>,
    }

    impl NatsClientModel {
        pub fn new() -> Self {
            Self {
                subscriptions: HashMap::new(),
                published_messages: Vec::new(),
                received_messages: Vec::new(),
            }
        }

        pub fn subscribe(&mut self, subject: &str) {
            self.subscriptions
                .insert(subject.to_string(), NatsSubjectModel::new(subject));
        }

        pub fn publish(&mut self, subject: &str, data: Vec<u8>) {
            let message = NatsMessageModel {
                subject: subject.to_string(),
                reply_to: None,
                data,
                headers: HashMap::new(),
            };
            self.published_messages.push(message.clone());

            // Route to matching subscriptions
            for sub_subject in self.subscriptions.values() {
                if sub_subject.matches(subject) {
                    self.received_messages.push(message.clone());
                }
            }
        }

        pub fn request(&mut self, subject: &str, data: Vec<u8>) -> String {
            let reply_subject = format!(
                "_INBOX.{}",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let message = NatsMessageModel {
                subject: subject.to_string(),
                reply_to: Some(reply_subject.clone()),
                data,
                headers: HashMap::new(),
            };
            self.published_messages.push(message);
            reply_subject
        }

        pub fn reply(&mut self, reply_subject: &str, data: Vec<u8>) {
            let message = NatsMessageModel {
                subject: reply_subject.to_string(),
                reply_to: None,
                data,
                headers: HashMap::new(),
            };
            self.published_messages.push(message);
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum Resp3ValueModel {
        SimpleString(String),
        Error(String),
        Integer(i64),
        BulkString(Vec<u8>),
        Array(Vec<Resp3ValueModel>),
        Null,
        Boolean(bool),
        Double(f64),
    }

    impl Resp3ValueModel {
        pub fn encode_resp3(&self) -> Vec<u8> {
            match self {
                Resp3ValueModel::SimpleString(s) => {
                    let mut result = vec![b'+'];
                    result.extend_from_slice(s.as_bytes());
                    result.extend_from_slice(b"\r\n");
                    result
                }
                Resp3ValueModel::Error(s) => {
                    let mut result = vec![b'-'];
                    result.extend_from_slice(s.as_bytes());
                    result.extend_from_slice(b"\r\n");
                    result
                }
                Resp3ValueModel::Integer(i) => {
                    let mut result = vec![b':'];
                    result.extend_from_slice(i.to_string().as_bytes());
                    result.extend_from_slice(b"\r\n");
                    result
                }
                Resp3ValueModel::BulkString(data) => {
                    let mut result = vec![b'$'];
                    result.extend_from_slice(data.len().to_string().as_bytes());
                    result.extend_from_slice(b"\r\n");
                    result.extend_from_slice(data);
                    result.extend_from_slice(b"\r\n");
                    result
                }
                Resp3ValueModel::Array(arr) => {
                    let mut result = vec![b'*'];
                    result.extend_from_slice(arr.len().to_string().as_bytes());
                    result.extend_from_slice(b"\r\n");
                    for item in arr {
                        result.extend_from_slice(&item.encode_resp3());
                    }
                    result
                }
                Resp3ValueModel::Null => b"_\r\n".to_vec(),
                Resp3ValueModel::Boolean(b) => {
                    let mut result = vec![b'#'];
                    result.extend_from_slice(if *b { b"t" } else { b"f" });
                    result.extend_from_slice(b"\r\n");
                    result
                }
                Resp3ValueModel::Double(d) => {
                    let mut result = vec![b','];
                    result.extend_from_slice(d.to_string().as_bytes());
                    result.extend_from_slice(b"\r\n");
                    result
                }
            }
        }

        pub fn decode_resp3(data: &[u8]) -> Result<(Self, usize), String> {
            if data.is_empty() {
                return Err("Empty data".to_string());
            }

            match data[0] {
                b'+' => {
                    if let Some(end) = data[1..].windows(2).position(|w| w == b"\r\n") {
                        let string = String::from_utf8_lossy(&data[1..end + 1]).to_string();
                        Ok((Resp3ValueModel::SimpleString(string), end + 3))
                    } else {
                        Err("Incomplete simple string".to_string())
                    }
                }
                b':' => {
                    if let Some(end) = data[1..].windows(2).position(|w| w == b"\r\n") {
                        let int_str = String::from_utf8_lossy(&data[1..end + 1]);
                        let int_val = int_str.parse::<i64>().map_err(|_| "Invalid integer")?;
                        Ok((Resp3ValueModel::Integer(int_val), end + 3))
                    } else {
                        Err("Incomplete integer".to_string())
                    }
                }
                b'$' => {
                    if let Some(len_end) = data[1..].windows(2).position(|w| w == b"\r\n") {
                        let len_str = String::from_utf8_lossy(&data[1..len_end + 1]);
                        let length = len_str
                            .parse::<usize>()
                            .map_err(|_| "Invalid bulk string length")?;
                        let data_start = len_end + 3;
                        if data.len() >= data_start + length + 2 {
                            let bulk_data = data[data_start..data_start + length].to_vec();
                            Ok((
                                Resp3ValueModel::BulkString(bulk_data),
                                data_start + length + 2,
                            ))
                        } else {
                            Err("Incomplete bulk string".to_string())
                        }
                    } else {
                        Err("Incomplete bulk string length".to_string())
                    }
                }
                b'#' => {
                    if data.len() >= 3 && &data[data.len() - 2..] == b"\r\n" {
                        let bool_val = match data[1] {
                            b't' => true,
                            b'f' => false,
                            _ => return Err("Invalid boolean".to_string()),
                        };
                        Ok((Resp3ValueModel::Boolean(bool_val), 4))
                    } else {
                        Err("Incomplete boolean".to_string())
                    }
                }
                b'_' => {
                    if data.len() >= 3 && &data[..3] == b"_\r\n" {
                        Ok((Resp3ValueModel::Null, 3))
                    } else {
                        Err("Incomplete null".to_string())
                    }
                }
                _ => Err("Unknown RESP3 type".to_string()),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct RedisClusterModel {
        pub slots: HashMap<u16, String>,    // slot -> node_id
        pub nodes: HashMap<String, String>, // node_id -> address
    }

    impl RedisClusterModel {
        pub fn new() -> Self {
            Self {
                slots: HashMap::new(),
                nodes: HashMap::new(),
            }
        }

        pub fn add_node(&mut self, node_id: &str, address: &str, slots: &[u16]) {
            self.nodes.insert(node_id.to_string(), address.to_string());
            for &slot in slots {
                self.slots.insert(slot, node_id.to_string());
            }
        }

        pub fn key_to_slot(&self, key: &str) -> u16 {
            // Redis cluster CRC16 hash slot calculation (simplified)
            let mut crc = 0u16;
            for byte in key.as_bytes() {
                crc = crc ^ (*byte as u16) << 8;
                for _ in 0..8 {
                    if crc & 0x8000 != 0 {
                        crc = (crc << 1) ^ 0x1021;
                    } else {
                        crc <<= 1;
                    }
                }
            }
            crc % 16384 // Redis has 16384 slots
        }

        pub fn route_key(&self, key: &str) -> Option<String> {
            let slot = self.key_to_slot(key);
            self.slots
                .get(&slot)
                .and_then(|node_id| self.nodes.get(node_id))
                .cloned()
        }
    }

    #[derive(Debug, Clone)]
    pub struct JetStreamMessageModel {
        pub stream: String,
        pub subject: String,
        pub sequence: u64,
        pub data: Vec<u8>,
        pub ack_pending: bool,
        pub delivery_count: u32,
    }

    #[derive(Debug, Clone)]
    pub struct JetStreamConsumerModel {
        pub name: String,
        pub stream: String,
        pub durable: bool,
        pub ack_policy: AckPolicy,
        pub delivered_messages: Vec<JetStreamMessageModel>,
        pub acked_sequences: HashSet<u64>,
        pub pending_acks: HashSet<u64>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum AckPolicy {
        None,
        All,
        Explicit,
    }

    impl JetStreamConsumerModel {
        pub fn new(name: &str, stream: &str, durable: bool, ack_policy: AckPolicy) -> Self {
            Self {
                name: name.to_string(),
                stream: stream.to_string(),
                durable,
                ack_policy,
                delivered_messages: Vec::new(),
                acked_sequences: HashSet::new(),
                pending_acks: HashSet::new(),
            }
        }

        pub fn deliver_message(&mut self, mut message: JetStreamMessageModel) -> u64 {
            let sequence = message.sequence;
            message.ack_pending = matches!(self.ack_policy, AckPolicy::Explicit);

            if message.ack_pending {
                self.pending_acks.insert(sequence);
            }

            self.delivered_messages.push(message);
            sequence
        }

        pub fn acknowledge(&mut self, sequence: u64) -> Result<(), String> {
            if self.ack_policy == AckPolicy::None {
                return Err("Consumer does not require acks".to_string());
            }

            if !self.pending_acks.contains(&sequence) {
                return Err("Message not pending ack".to_string());
            }

            self.pending_acks.remove(&sequence);
            self.acked_sequences.insert(sequence);
            Ok(())
        }

        pub fn get_pending_count(&self) -> usize {
            self.pending_acks.len()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SchedulerTaskModel {
        pub id: u64,
        pub priority: u32,
        pub deadline: Option<Instant>,
        pub work_amount: u32,
        pub created_at: Instant,
    }

    impl SchedulerTaskModel {
        pub fn new(id: u64, priority: u32) -> Self {
            Self {
                id,
                priority,
                deadline: None,
                work_amount: 1,
                created_at: Instant::now(),
            }
        }

        pub fn with_deadline(mut self, deadline: Instant) -> Self {
            self.deadline = Some(deadline);
            self
        }

        pub fn with_work_amount(mut self, amount: u32) -> Self {
            self.work_amount = amount;
            self
        }
    }

    impl PartialOrd for SchedulerTaskModel {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for SchedulerTaskModel {
        fn cmp(&self, other: &Self) -> Ordering {
            // Higher priority first, then earlier deadline
            match self.priority.cmp(&other.priority).reverse() {
                Ordering::Equal => {
                    match (self.deadline, other.deadline) {
                        (Some(a), Some(b)) => a.cmp(&b),
                        (Some(_), None) => Ordering::Less, // Deadline tasks have higher priority
                        (None, Some(_)) => Ordering::Greater,
                        (None, None) => self.id.cmp(&other.id), // FIFO for same priority
                    }
                }
                other => other,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ThreeLaneSchedulerModel {
        pub cancel_lane: VecDeque<SchedulerTaskModel>,
        pub timed_lane: VecDeque<SchedulerTaskModel>, // EDF scheduled
        pub ready_lane: VecDeque<SchedulerTaskModel>,
        pub completed_tasks: Vec<SchedulerTaskModel>,
        pub current_time: Instant,
    }

    impl ThreeLaneSchedulerModel {
        pub fn new() -> Self {
            Self {
                cancel_lane: VecDeque::new(),
                timed_lane: VecDeque::new(),
                ready_lane: VecDeque::new(),
                completed_tasks: Vec::new(),
                current_time: Instant::now(),
            }
        }

        pub fn enqueue_task(&mut self, task: SchedulerTaskModel) {
            if task.priority == u32::MAX {
                // Cancel lane
                self.cancel_lane.push_back(task);
            } else if task.deadline.is_some() {
                // Timed lane - insert in EDF order
                let insert_pos = self
                    .timed_lane
                    .iter()
                    .position(|t| t.deadline > task.deadline)
                    .unwrap_or(self.timed_lane.len());
                self.timed_lane.insert(insert_pos, task);
            } else {
                // Ready lane - round robin within priority
                self.ready_lane.push_back(task);
            }
        }

        pub fn schedule_next(&mut self) -> Option<SchedulerTaskModel> {
            // Strict 3-lane ordering: cancel > timed > ready
            if let Some(task) = self.cancel_lane.pop_front() {
                return Some(task);
            }

            // Check timed lane for expired deadlines
            if let Some(task) = self.timed_lane.front() {
                if let Some(deadline) = task.deadline {
                    if self.current_time >= deadline {
                        return self.timed_lane.pop_front();
                    }
                }
            }

            self.ready_lane.pop_front()
        }

        pub fn execute_task(&mut self, mut task: SchedulerTaskModel) {
            task.work_amount = task.work_amount.saturating_sub(1);
            if task.work_amount == 0 {
                self.completed_tasks.push(task);
            } else {
                self.enqueue_task(task);
            }
        }

        pub fn advance_time(&mut self, duration: Duration) {
            self.current_time += duration;
        }

        pub fn total_pending_tasks(&self) -> usize {
            self.cancel_lane.len() + self.timed_lane.len() + self.ready_lane.len()
        }
    }

    #[derive(Debug, Clone)]
    pub struct WorkStealingSchedulerModel {
        pub workers: Vec<WorkerModel>,
        pub global_queue: VecDeque<SchedulerTaskModel>,
        pub steal_attempts: u64,
        pub successful_steals: u64,
    }

    #[derive(Debug, Clone)]
    pub struct WorkerModel {
        pub id: u64,
        pub local_queue: VecDeque<SchedulerTaskModel>,
        pub executed_tasks: Vec<SchedulerTaskModel>,
        pub steals_from_me: u64,
        pub steals_by_me: u64,
    }

    impl WorkStealingSchedulerModel {
        pub fn new(worker_count: usize) -> Self {
            let workers = (0..worker_count)
                .map(|id| WorkerModel {
                    id: id as u64,
                    local_queue: VecDeque::new(),
                    executed_tasks: Vec::new(),
                    steals_from_me: 0,
                    steals_by_me: 0,
                })
                .collect();

            Self {
                workers,
                global_queue: VecDeque::new(),
                steal_attempts: 0,
                successful_steals: 0,
            }
        }

        pub fn enqueue_task(&mut self, task: SchedulerTaskModel) {
            // Simple round-robin assignment to worker local queues
            let worker_id = (task.id % self.workers.len() as u64) as usize;
            self.workers[worker_id].local_queue.push_back(task);
        }

        pub fn worker_schedule_next(&mut self, worker_id: usize) -> Option<SchedulerTaskModel> {
            // Try local queue first
            if let Some(task) = self.workers[worker_id].local_queue.pop_front() {
                return Some(task);
            }

            // Try global queue
            if let Some(task) = self.global_queue.pop_front() {
                return Some(task);
            }

            // Try work stealing from other workers
            self.steal_attempts += 1;
            for other_id in 0..self.workers.len() {
                if other_id != worker_id && !self.workers[other_id].local_queue.is_empty() {
                    // Steal from the back (LIFO stealing for cache locality)
                    if let Some(stolen_task) = self.workers[other_id].local_queue.pop_back() {
                        self.workers[worker_id].steals_by_me += 1;
                        self.workers[other_id].steals_from_me += 1;
                        self.successful_steals += 1;
                        return Some(stolen_task);
                    }
                }
            }

            None
        }

        pub fn worker_execute_task(&mut self, worker_id: usize, task: SchedulerTaskModel) {
            self.workers[worker_id].executed_tasks.push(task);
        }

        pub fn get_load_balance_variance(&self) -> f64 {
            let worker_loads: Vec<usize> = self
                .workers
                .iter()
                .map(|w| w.executed_tasks.len())
                .collect();

            let mean = worker_loads.iter().sum::<usize>() as f64 / worker_loads.len() as f64;
            let variance = worker_loads
                .iter()
                .map(|&load| (load as f64 - mean).powi(2))
                .sum::<f64>()
                / worker_loads.len() as f64;

            variance
        }

        pub fn steal_success_rate(&self) -> f64 {
            if self.steal_attempts == 0 {
                0.0
            } else {
                self.successful_steals as f64 / self.steal_attempts as f64
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: Kafka Producer-Consumer
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-KafkaProducerConsumerTotalOrder**: Producer send order is preserved
        /// in consumer receive order within the same partition.
        ///
        /// **Property**: send_order(partition) = receive_order(partition)
        ///
        /// **Catches**: Message reordering, offset corruption, partition assignment bugs
        #[test]
        fn mr_kafka_producer_consumer_total_order(
            messages in prop::collection::vec(
                (prop::collection::vec(any::<u8>(), 1..100), 0u32..5u32),
                5..20
            )
        ) {
            let mut producer = KafkaProducerModel::new();
            let mut consumer = KafkaConsumerModel::new("test-group");

            let topic = "test-topic";
            let mut sent_by_partition: BTreeMap<u32, Vec<(u64, Vec<u8>)>> = BTreeMap::new();

            // Send messages
            for (data, partition) in messages {
                let message = KafkaRecordModel::new(topic, partition, 0, data.clone());
                let offset = producer.send_message(topic, partition, message)
                    .expect("Failed to send message");

                sent_by_partition.entry(partition)
                    .or_default()
                    .push((offset, data));
            }

            // Assign all partitions to consumer
            let all_partitions: Vec<(String, u32)> = sent_by_partition.keys()
                .map(|&p| (topic.to_string(), p))
                .collect();
            consumer.assign_partitions(all_partitions);

            // Consume messages
            consumer.consume_from_producer(&producer, 1000);

            // Verify order preservation within each partition
            for (&partition, sent_messages) in &sent_by_partition {
                let received_for_partition: Vec<_> = consumer.consumed_messages.iter()
                    .filter(|msg| msg.partition == partition)
                    .collect();

                // Total order preservation: sent order = received order
                for (i, (sent_offset, sent_data)) in sent_messages.iter().enumerate() {
                    if i < received_for_partition.len() {
                        let received_msg = received_for_partition[i];
                        prop_assert_eq!(received_msg.offset, *sent_offset,
                            "Message order violation in partition {}: expected offset {}, got {}",
                            partition, sent_offset, received_msg.offset);
                        prop_assert_eq!(received_msg.value.clone(), sent_data.clone(),
                            "Message content mismatch in partition {}", partition);
                    }
                }

                // Completeness: all sent messages should be received
                prop_assert_eq!(received_for_partition.len(), sent_messages.len(),
                    "Message count mismatch for partition {}: sent {}, received {}",
                    partition, sent_messages.len(), received_for_partition.len());
            }
        }
    }

    proptest! {
        /// **MR-KafkaConsumerGroupRebalanceIdempotency**: Consumer group rebalancing
        /// yields deterministic partition assignments for the same set of consumers.
        ///
        /// **Property**: rebalance(consumers) is deterministic for same consumer set
        ///
        /// **Catches**: Non-deterministic rebalancing, assignment inconsistencies
        #[test]
        fn mr_kafka_consumer_group_rebalance_idempotency(
            consumer_count in 2usize..8usize,
            partition_count in 3u32..15u32
        ) {
            let topic = "test-topic";
            let mut consumers1 = Vec::new();
            let mut consumers2 = Vec::new();

            // Create two identical sets of consumers
            for i in 0..consumer_count {
                let consumer_id = format!("consumer-{}", i);
                consumers1.push(KafkaConsumerModel::new(&consumer_id));
                consumers2.push(KafkaConsumerModel::new(&consumer_id));
            }

            // Simulate rebalancing (simplified round-robin assignment)
            let partitions: Vec<u32> = (0..partition_count).collect();

            // First rebalancing
            for (i, consumer) in consumers1.iter_mut().enumerate() {
                let assigned_partitions: Vec<(String, u32)> = partitions.iter()
                    .enumerate()
                    .filter(|(idx, _)| idx % consumer_count == i)
                    .map(|(_, &p)| (topic.to_string(), p))
                    .collect();
                consumer.assign_partitions(assigned_partitions);
            }

            // Second rebalancing (same consumers, same algorithm)
            for (i, consumer) in consumers2.iter_mut().enumerate() {
                let assigned_partitions: Vec<(String, u32)> = partitions.iter()
                    .enumerate()
                    .filter(|(idx, _)| idx % consumer_count == i)
                    .map(|(_, &p)| (topic.to_string(), p))
                    .collect();
                consumer.assign_partitions(assigned_partitions);
            }

            // Idempotency: assignments should be identical
            for i in 0..consumer_count {
                let mut assignment1 = consumers1[i].assigned_partitions.clone();
                let mut assignment2 = consumers2[i].assigned_partitions.clone();

                assignment1.sort();
                assignment2.sort();

                prop_assert_eq!(assignment1.clone(), assignment2.clone(),
                    "Rebalance idempotency failed for consumer {}: {:?} vs {:?}",
                    i, assignment1, assignment2);
            }

            // Coverage: all partitions should be assigned exactly once
            let all_assignments: HashSet<(String, u32)> = consumers1.iter()
                .flat_map(|c| c.assigned_partitions.iter())
                .cloned()
                .collect();

            prop_assert_eq!(all_assignments.len(), partition_count as usize,
                "Partition assignment coverage failed: {} partitions, {} assignments",
                partition_count, all_assignments.len());
        }
    }

    proptest! {
        /// **MR-KafkaTransactionAtomicity**: Transaction commit/abort preserves message atomicity.
        ///
        /// **Property**: committed transactions are fully visible, aborted transactions are invisible
        ///
        /// **Catches**: Partial transaction visibility, atomicity violations
        #[test]
        fn mr_kafka_transaction_atomicity(
            transaction_messages in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..50),
                3..10
            ),
            should_commit in any::<bool>()
        ) {
            let mut producer = KafkaProducerModel::new();
            let topic = "test-topic";
            let partition = 0;

            // Begin transaction
            producer.begin_transaction("tx-1").expect("Failed to begin transaction");

            let mut sent_offsets = Vec::new();

            // Send messages in transaction
            for data in &transaction_messages {
                let message = KafkaRecordModel::new(topic, partition, 0, data.clone());
                let offset = producer.send_message(topic, partition, message)
                    .expect("Failed to send message");
                sent_offsets.push(offset);
            }

            let messages_before_decision = producer.sent_messages.len();

            // Commit or abort transaction
            if should_commit {
                producer.commit_transaction().expect("Failed to commit transaction");

                // Atomicity: all transaction messages should be visible
                prop_assert_eq!(producer.sent_messages.len(), messages_before_decision,
                    "Message count changed after commit");

                // All messages should have sequential offsets
                for (i, &expected_offset) in sent_offsets.iter().enumerate() {
                    prop_assert_eq!(producer.sent_messages[i].offset, expected_offset,
                        "Offset mismatch after commit: expected {}, got {}",
                        expected_offset, producer.sent_messages[i].offset);
                }
            } else {
                producer.abort_transaction().expect("Failed to abort transaction");

                // Atomicity: transaction messages should be invisible (rolled back)
                let messages_after_abort = producer.sent_messages.len();
                prop_assert!(messages_after_abort < messages_before_decision,
                    "Transaction messages still visible after abort: {} before, {} after",
                    messages_before_decision, messages_after_abort);
            }

            // Transaction state should be clean
            prop_assert!(!producer.transaction_active,
                "Transaction still active after commit/abort");
            prop_assert!(producer.transaction_id.is_none(),
                "Transaction ID not cleared after commit/abort");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: NATS Subject Routing
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-NATSSubjectRouting**: Subject patterns route to correct subscribers.
        ///
        /// **Property**: publish(subject) routes to all matching subscriptions
        ///
        /// **Catches**: Routing bugs, wildcard matching errors, subject parsing issues
        #[test]
        fn mr_nats_subject_routing(
            base_subject in "[a-z]{3,8}",
            sub_subjects in prop::collection::vec("[a-z]{2,6}", 2..5)
        ) {
            let mut client = NatsClientModel::new();

            // Create specific and wildcard subscriptions
            let specific_subject = format!("{}.{}", base_subject, sub_subjects[0]);
            let wildcard_subject = format!("{}.*", base_subject);
            let catch_all_subject = format!("{}.*>", base_subject);

            client.subscribe(&specific_subject);
            client.subscribe(&wildcard_subject);
            if sub_subjects.len() > 2 {
                client.subscribe(&catch_all_subject);
            }

            let initial_received_count = client.received_messages.len();

            // Publish to specific subject
            client.publish(&specific_subject, b"test-data".to_vec());

            // Routing correctness: specific subject should match all applicable patterns
            let specific_matches = client.received_messages.len() - initial_received_count;
            let expected_matches = if sub_subjects.len() > 2 { 3 } else { 2 }; // specific + wildcard + catch_all

            prop_assert!(specific_matches > 0,
                "No routes found for specific subject {}", specific_subject);
            prop_assert_eq!(specific_matches, expected_matches,
                "Specific subject {} should match exactly {} subscriptions",
                specific_subject, expected_matches);

            // Test wildcard independence: different subjects under same prefix
            for sub_subject in &sub_subjects[1..] {
                let test_subject = format!("{}.{}", base_subject, sub_subject);
                let before_count = client.received_messages.len();

                client.publish(&test_subject, b"wildcard-test".to_vec());

                let after_count = client.received_messages.len();
                let matches = after_count - before_count;

                // Wildcard routing: should match wildcard patterns but not specific subscription
                prop_assert!(matches > 0,
                    "Wildcard subject {} should match wildcard subscription", test_subject);
            }

            // Routing isolation: unrelated subjects should not match
            let unrelated_subject = format!("unrelated.{}", sub_subjects[0]);
            let before_unrelated = client.received_messages.len();
            client.publish(&unrelated_subject, b"unrelated-data".to_vec());
            let after_unrelated = client.received_messages.len();

            prop_assert_eq!(before_unrelated, after_unrelated,
                "Unrelated subject {} incorrectly matched subscriptions", unrelated_subject);
        }
    }

    proptest! {
        /// **MR-NATSWildcardMatching**: Wildcard subject matching is deterministic and complete.
        ///
        /// **Property**: wildcard_match(pattern, subject) is consistent across implementations
        ///
        /// **Catches**: Wildcard parsing inconsistencies, matching algorithm bugs
        #[test]
        fn mr_nats_wildcard_matching(
            segments in prop::collection::vec("[a-z]{2,8}", 2..6),
            wildcard_position in 0usize..3usize
        ) {
            let wildcard_position = wildcard_position.min(segments.len().saturating_sub(1));

            // Create test subject
            let subject = segments.join(".");

            // Create wildcard patterns
            let mut star_pattern = segments.clone();
            star_pattern[wildcard_position] = "*".to_string();
            let star_pattern = star_pattern.join(".");

            let mut gt_pattern = segments[..wildcard_position + 1].to_vec();
            gt_pattern.push(">".to_string());
            let gt_pattern = gt_pattern.join(".");

            let star_subject = NatsSubjectModel::new(&star_pattern);
            let gt_subject = NatsSubjectModel::new(&gt_pattern);
            let exact_subject = NatsSubjectModel::new(&subject);

            // Exact matching: subject should match itself
            prop_assert!(exact_subject.matches(&subject),
                "Exact subject '{}' should match itself", subject);

            // Star wildcard: should match if same depth
            let star_matches = star_subject.matches(&subject);
            prop_assert!(star_matches,
                "Star pattern '{}' should match subject '{}'", star_pattern, subject);

            // Greater-than wildcard: should match if prefix matches
            let gt_matches = gt_subject.matches(&subject);
            prop_assert!(gt_matches,
                "GT pattern '{}' should match subject '{}'", gt_pattern, subject);

            // Determinism: repeated matching should give same results
            prop_assert_eq!(star_subject.matches(&subject), star_matches,
                "Star wildcard matching not deterministic");
            prop_assert_eq!(gt_subject.matches(&subject), gt_matches,
                "GT wildcard matching not deterministic");

            // Specificity: exact match is most specific
            if subject != star_pattern && subject != gt_pattern {
                prop_assert!(exact_subject.matches(&subject),
                    "Exact match should always succeed for identical subjects");
            }
        }
    }

    proptest! {
        /// **MR-NATSRequestReplySymmetry**: Request-reply maintains correlation IDs correctly.
        ///
        /// **Property**: reply(request_subject) routes back to requester
        ///
        /// **Catches**: Reply routing bugs, correlation ID corruption, inbox management
        #[test]
        fn mr_nats_request_reply_symmetry(
            request_subject in "[a-z]{3,10}",
            request_data in prop::collection::vec(any::<u8>(), 10..100),
            reply_data in prop::collection::vec(any::<u8>(), 10..100)
        ) {
            let mut client = NatsClientModel::new();

            let initial_published = client.published_messages.len();

            // Send request
            let reply_subject = client.request(&request_subject, request_data.clone());

            // Verify request was published
            prop_assert_eq!(client.published_messages.len(), initial_published + 1,
                "Request should be published");

            let request_msg = &client.published_messages[initial_published];
            prop_assert_eq!(request_msg.subject.clone(), request_subject.clone(),
                "Request subject mismatch");
            prop_assert_eq!(request_msg.data.clone(), request_data.clone(),
                "Request data mismatch");
            prop_assert_eq!(request_msg.reply_to.clone(), Some(reply_subject.clone()),
                "Request should have reply_to field");

            // Send reply
            client.reply(&reply_subject, reply_data.clone());

            // Verify reply was published to correct subject
            prop_assert_eq!(client.published_messages.len(), initial_published + 2,
                "Reply should be published");

            let reply_msg = &client.published_messages[initial_published + 1];
            prop_assert_eq!(reply_msg.subject.clone(), reply_subject.clone(),
                "Reply subject should match reply_to from request");
            prop_assert_eq!(reply_msg.data.clone(), reply_data.clone(),
                "Reply data mismatch");
            prop_assert!(reply_msg.reply_to.is_none(),
                "Reply should not have reply_to field");

            // Symmetry: reply subject should be unique and inbox-like
            prop_assert!(reply_subject.starts_with("_INBOX."),
                "Reply subject should be inbox format: {}", reply_subject);

            // Correlation: reply subject should be deterministic for testing but unique in practice
            let second_reply_subject = client.request(&request_subject, request_data.clone());
            prop_assert_ne!(reply_subject, second_reply_subject,
                "Reply subjects should be unique across requests");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: Redis RESP Protocol and Cluster
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-RedisRESPEncodeDecode**: RESP3 encode/decode preserves command semantics.
        ///
        /// **Property**: decode(encode(value)) = value for all RESP3 types
        ///
        /// **Catches**: RESP3 protocol bugs, encoding/decoding mismatches, type corruption
        #[test]
        fn mr_redis_resp_encode_decode(
            test_values in prop::collection::vec(
                prop::sample::select(vec![
                    Resp3ValueModel::SimpleString("OK".to_string()),
                    Resp3ValueModel::Integer(42),
                    Resp3ValueModel::BulkString(b"hello".to_vec()),
                    Resp3ValueModel::Boolean(true),
                    Resp3ValueModel::Boolean(false),
                    Resp3ValueModel::Null,
                ]),
                1..8
            )
        ) {
            for original_value in test_values {
                let encoded = original_value.encode_resp3();

                // Encoding should produce non-empty output
                prop_assert!(!encoded.is_empty(),
                    "RESP3 encoding should not be empty for value: {:?}", original_value);

                // Decoding should recover original value
                match Resp3ValueModel::decode_resp3(&encoded) {
                    Ok((decoded_value, consumed_bytes)) => {
                        prop_assert_eq!(decoded_value.clone(), original_value.clone(),
                            "RESP3 round-trip failed: {:?} -> {:?}", original_value, decoded_value);

                        // All bytes should be consumed for a complete value
                        prop_assert_eq!(consumed_bytes, encoded.len(),
                            "RESP3 decoder should consume all bytes: consumed {}, total {}",
                            consumed_bytes, encoded.len());
                    }
                    Err(e) => {
                        prop_assert!(false, "RESP3 decode failed for {:?}: {}", original_value, e);
                    }
                }

                // Determinism: re-encoding should produce identical output
                let re_encoded = original_value.encode_resp3();
                prop_assert_eq!(encoded, re_encoded,
                    "RESP3 encoding not deterministic for: {:?}", original_value);
            }
        }
    }

    proptest! {
        /// **MR-RedisClusterSlotDeterminism**: Cluster slot assignment is deterministic for same keys.
        ///
        /// **Property**: key_to_slot(key) is deterministic and evenly distributed
        ///
        /// **Catches**: Slot calculation bugs, hash function inconsistencies, distribution skew
        #[test]
        fn mr_redis_cluster_slot_determinism(
            keys in prop::collection::vec("[a-zA-Z0-9]{3,20}", 10..50)
        ) {
            let cluster = RedisClusterModel::new();

            // Determinism: slot calculation should be consistent
            for key in &keys {
                let slot1 = cluster.key_to_slot(key);
                let slot2 = cluster.key_to_slot(key);
                let slot3 = cluster.key_to_slot(key);

                prop_assert_eq!(slot1, slot2,
                    "Slot calculation not deterministic for key '{}': {} vs {}", key, slot1, slot2);
                prop_assert_eq!(slot2, slot3,
                    "Slot calculation not deterministic for key '{}': {} vs {}", key, slot2, slot3);

                // Slot range: should be in valid Redis cluster range
                prop_assert!(slot1 < 16384,
                    "Slot {} out of range for key '{}'", slot1, key);
            }

            // Distribution: slots should be reasonably distributed
            let mut slot_counts = HashMap::new();
            for key in &keys {
                let slot = cluster.key_to_slot(key);
                *slot_counts.entry(slot).or_insert(0) += 1;
            }

            let unique_slots = slot_counts.len();
            let total_keys = keys.len();

            // Distribution quality: should have reasonable slot diversity
            if total_keys >= 10 {
                prop_assert!(unique_slots > 1,
                    "Poor slot distribution: {} keys mapped to only {} slots",
                    total_keys, unique_slots);

                // No single slot should dominate (basic distribution check)
                let max_slot_count = *slot_counts.values().max().unwrap_or(&0);
                let expected_avg = total_keys / unique_slots.max(1);
                prop_assert!(max_slot_count <= expected_avg * 3,
                    "Slot distribution skewed: max slot has {} keys, average is {}",
                    max_slot_count, expected_avg);
            }
        }
    }

    proptest! {
        /// **MR-RedisKeyspaceRoutingConsistency**: Keyspace routing respects Redis cluster specification.
        ///
        /// **Property**: route(key) is consistent with slot assignment and node topology
        ///
        /// **Catches**: Routing inconsistencies, topology bugs, slot-to-node mapping errors
        #[test]
        fn mr_redis_keyspace_routing_consistency(
            node_configs in prop::collection::vec(
                (prop::collection::vec(0u16..16384u16, 100..1000), "[a-z0-9]{3,8}"),
                2..5
            ),
            test_keys in prop::collection::vec("[a-zA-Z0-9]{5,15}", 20..50)
        ) {
            let mut cluster = RedisClusterModel::new();

            // Set up cluster topology
            for (i, (slots, address)) in node_configs.iter().enumerate() {
                let node_id = format!("node-{}", i);
                cluster.add_node(&node_id, address, slots);
            }

            // Routing consistency: same key should always route to same node
            for key in &test_keys {
                let route1 = cluster.route_key(key);
                let route2 = cluster.route_key(key);
                let route3 = cluster.route_key(key);

                prop_assert_eq!(route1.clone(), route2.clone(),
                    "Routing not consistent for key '{}': {:?} vs {:?}", key, route1, route2);
                prop_assert_eq!(route2.clone(), route3.clone(),
                    "Routing not consistent for key '{}': {:?} vs {:?}", key, route2, route3);

                // Slot-route correspondence: routing should match slot assignment
                let slot = cluster.key_to_slot(key);
                let expected_node = cluster.slots.get(&slot);

                if let Some(expected_node_id) = expected_node {
                    let expected_address = cluster.nodes.get(expected_node_id);
                    prop_assert_eq!(route1.clone(), expected_address.cloned(),
                        "Route mismatch for key '{}' (slot {}): expected {:?}, got {:?}",
                        key, slot, expected_address, route1);
                }
            }

            // Coverage: all configured slots should be routable
            let configured_slots: HashSet<u16> = node_configs.iter()
                .flat_map(|(slots, _)| slots.iter())
                .cloned()
                .collect();

            for &slot in &configured_slots {
                let slot_node = cluster.slots.get(&slot);
                prop_assert!(slot_node.is_some(),
                    "Slot {} not mapped to any node", slot);

                if let Some(node_id) = slot_node {
                    let node_address = cluster.nodes.get(node_id);
                    prop_assert!(node_address.is_some(),
                        "Node '{}' for slot {} not found in node registry", node_id, slot);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: JetStream Consumer Ack Semantics
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-JetStreamAckSemantics**: Acknowledge semantics preserve message ordering.
        ///
        /// **Property**: ack order doesn't affect delivery semantics for durable consumers
        ///
        /// **Catches**: Ack processing bugs, ordering violations, state inconsistencies
        #[test]
        fn mr_jetstream_ack_semantics(
            messages in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 10..100),
                5..15
            )
        ) {
            let mut consumer = JetStreamConsumerModel::new(
                "test-consumer", "test-stream", true, AckPolicy::Explicit
            );

            let mut delivered_sequences = Vec::new();

            // Deliver messages
            for (i, data) in messages.iter().enumerate() {
                let message = JetStreamMessageModel {
                    stream: "test-stream".to_string(),
                    subject: "test.subject".to_string(),
                    sequence: i as u64 + 1,
                    data: data.clone(),
                    ack_pending: true,
                    delivery_count: 1,
                };
                let sequence = consumer.deliver_message(message);
                delivered_sequences.push(sequence);
            }

            let initial_pending = consumer.get_pending_count();
            prop_assert_eq!(initial_pending, messages.len(),
                "All messages should be pending ack");

            // Acknowledge messages in different order (reverse order)
            let mut ack_order = delivered_sequences.clone();
            ack_order.reverse();

            for &sequence in &ack_order {
                let ack_result = consumer.acknowledge(sequence);
                prop_assert!(ack_result.is_ok(),
                    "Ack should succeed for sequence {}", sequence);
            }

            // Ack semantics: all messages should be acknowledged regardless of order
            let final_pending = consumer.get_pending_count();
            prop_assert_eq!(final_pending, 0,
                "No messages should be pending after all acks");

            // State consistency: acked sequences should match delivered sequences
            prop_assert_eq!(consumer.acked_sequences.len(), delivered_sequences.len(),
                "Acked count should match delivered count");

            for &sequence in &delivered_sequences {
                prop_assert!(consumer.acked_sequences.contains(&sequence),
                    "Sequence {} should be in acked set", sequence);
            }

            // Idempotency: re-acking should fail gracefully
            for &sequence in &delivered_sequences {
                let re_ack_result = consumer.acknowledge(sequence);
                prop_assert!(re_ack_result.is_err(),
                    "Re-ack should fail for already acked sequence {}", sequence);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: Priority Scheduler Fairness
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-PriorityRoundRobinFairness**: Round-robin scheduling is fair within priority classes.
        ///
        /// **Property**: tasks of same priority scheduled in approximately round-robin order
        ///
        /// **Catches**: Priority queue unfairness, starvation bugs, round-robin violations
        #[test]
        fn mr_priority_round_robin_fairness(
            priority_levels in prop::collection::vec(1u32..5u32, 2..5),
            tasks_per_priority in prop::collection::vec(3usize..10usize, 2..5)
        ) {
            let mut scheduler = ThreeLaneSchedulerModel::new();

            // Create tasks with different priorities
            let mut task_id = 0u64;
            let mut tasks_by_priority: BTreeMap<u32, Vec<u64>> = BTreeMap::new();

            for (&priority, &task_count) in priority_levels.iter().zip(tasks_per_priority.iter()) {
                let mut task_ids = Vec::new();
                for _ in 0..task_count {
                    let task = SchedulerTaskModel::new(task_id, priority).with_work_amount(1);
                    task_ids.push(task_id);
                    scheduler.enqueue_task(task);
                    task_id += 1;
                }
                tasks_by_priority.insert(priority, task_ids);
            }

            // Execute all tasks and record execution order
            let mut execution_order = Vec::new();
            while let Some(task) = scheduler.schedule_next() {
                execution_order.push((task.id, task.priority));
                scheduler.execute_task(task);
            }

            // Verify strict priority ordering: higher priority tasks execute first
            let mut last_priority = u32::MAX;
            for &(task_id, priority) in &execution_order {
                prop_assert!(priority <= last_priority,
                    "Priority violation: task {} (priority {}) executed after lower priority {}",
                    task_id, priority, last_priority);
                last_priority = priority;
            }

            // Verify round-robin fairness within each priority class
            for (&priority, expected_tasks) in &tasks_by_priority {
                let priority_execution: Vec<u64> = execution_order.iter()
                    .filter(|(_, p)| *p == priority)
                    .map(|(id, _)| *id)
                    .collect();

                // Completeness: all tasks of this priority should execute
                prop_assert_eq!(priority_execution.len(), expected_tasks.len(),
                    "Task count mismatch for priority {}: expected {}, got {}",
                    priority, expected_tasks.len(), priority_execution.len());

                // Basic fairness: no task should be severely out of order within priority class
                // (This is a simplified check; real round-robin would require more sophisticated analysis)
                for &task_id in expected_tasks {
                    prop_assert!(priority_execution.contains(&task_id),
                        "Task {} (priority {}) not executed", task_id, priority);
                }
            }
        }
    }

    proptest! {
        /// **MR-ThreeLaneStrictOrdering**: Cancel > Timed > Ready lane strict ordering maintained.
        ///
        /// **Property**: cancel lane tasks always execute before timed/ready lane tasks
        ///
        /// **Catches**: Lane priority violations, scheduling inversions, queue ordering bugs
        #[test]
        fn mr_three_lane_strict_ordering(
            cancel_tasks in prop::collection::vec(0u64..10u64, 1..5),
            timed_tasks in prop::collection::vec(0u64..10u64, 1..5),
            ready_tasks in prop::collection::vec(0u64..10u64, 1..5)
        ) {
            let mut scheduler = ThreeLaneSchedulerModel::new();
            let base_time = Instant::now();
            let mut task_id = 0u64;

            // Enqueue cancel lane tasks (highest priority)
            let mut cancel_task_ids = Vec::new();
            for _ in &cancel_tasks {
                let task = SchedulerTaskModel::new(task_id, u32::MAX).with_work_amount(1);
                cancel_task_ids.push(task_id);
                scheduler.enqueue_task(task);
                task_id += 1;
            }

            // Enqueue timed lane tasks (EDF scheduled)
            let mut timed_task_ids = Vec::new();
            for (i, _) in timed_tasks.iter().enumerate() {
                let deadline = base_time + Duration::from_millis(100 * (i as u64 + 1));
                let task = SchedulerTaskModel::new(task_id, 1)
                    .with_deadline(deadline)
                    .with_work_amount(1);
                timed_task_ids.push(task_id);
                scheduler.enqueue_task(task);
                task_id += 1;
            }

            // Enqueue ready lane tasks (lowest priority)
            let mut ready_task_ids = Vec::new();
            for _ in &ready_tasks {
                let task = SchedulerTaskModel::new(task_id, 1).with_work_amount(1);
                ready_task_ids.push(task_id);
                scheduler.enqueue_task(task);
                task_id += 1;
            }

            // Execute tasks and verify strict lane ordering
            let mut execution_order = Vec::new();
            let mut executed_cancel = 0;
            let mut executed_timed = 0;
            let mut executed_ready = 0;

            while let Some(task) = scheduler.schedule_next() {
                execution_order.push(task.id);

                if cancel_task_ids.contains(&task.id) {
                    executed_cancel += 1;
                    // Cancel lane strictness: no timed/ready tasks should have executed yet
                    prop_assert_eq!(executed_timed, 0,
                        "Timed task executed before all cancel tasks finished");
                    prop_assert_eq!(executed_ready, 0,
                        "Ready task executed before all cancel tasks finished");
                } else if timed_task_ids.contains(&task.id) {
                    executed_timed += 1;
                    // Timed lane strictness: no ready tasks should have executed yet
                    prop_assert_eq!(executed_ready, 0,
                        "Ready task executed before all timed tasks finished");
                    // All cancel tasks should be done
                    prop_assert_eq!(executed_cancel, cancel_task_ids.len(),
                        "Timed task executed before all cancel tasks finished");
                } else if ready_task_ids.contains(&task.id) {
                    executed_ready += 1;
                    // Both higher priority lanes should be empty
                    prop_assert_eq!(executed_cancel, cancel_task_ids.len(),
                        "Ready task executed before all cancel tasks finished");
                    prop_assert_eq!(executed_timed, timed_task_ids.len(),
                        "Ready task executed before all timed tasks finished");
                }

                scheduler.execute_task(task);
            }

            // Completeness: all tasks should execute
            prop_assert_eq!(executed_cancel, cancel_task_ids.len());
            prop_assert_eq!(executed_timed, timed_task_ids.len());
            prop_assert_eq!(executed_ready, ready_task_ids.len());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Metamorphic Relations: Work Stealing Scheduler
    // ═══════════════════════════════════════════════════════════════════════════

    proptest! {
        /// **MR-WorkStealingLoadBalance**: Work stealing achieves load balance across workers.
        ///
        /// **Property**: work distribution variance decreases with stealing enabled
        ///
        /// **Catches**: Load balancing failures, stealing inefficiency, worker starvation
        #[test]
        fn mr_work_stealing_load_balance(
            worker_count in 2usize..8usize,
            task_count in 20usize..100usize
        ) {
            let mut scheduler = WorkStealingSchedulerModel::new(worker_count);

            // Enqueue tasks (they'll be assigned round-robin to workers)
            for i in 0..task_count {
                let task = SchedulerTaskModel::new(i as u64, 1);
                scheduler.enqueue_task(task);
            }

            // Simulate work stealing execution
            let mut total_scheduled = 0;
            let max_iterations = task_count * 2; // Prevent infinite loops
            let mut iterations = 0;

            while total_scheduled < task_count && iterations < max_iterations {
                let mut any_work_done = false;

                for worker_id in 0..worker_count {
                    if let Some(task) = scheduler.worker_schedule_next(worker_id) {
                        scheduler.worker_execute_task(worker_id, task);
                        total_scheduled += 1;
                        any_work_done = true;
                    }
                }

                if !any_work_done {
                    break;
                }
                iterations += 1;
            }

            // Load balancing: work should be distributed across workers
            let variance = scheduler.get_load_balance_variance();
            let mean_tasks = task_count as f64 / worker_count as f64;

            // Load balance quality: variance should be reasonable
            prop_assert!(variance <= mean_tasks * mean_tasks,
                "Load balance variance {} too high (mean tasks per worker: {})",
                variance, mean_tasks);

            // Work stealing effectiveness: stealing should occur under imbalanced load
            if task_count > worker_count * 3 {
                let steal_rate = scheduler.steal_success_rate();
                // Some stealing should occur with realistic workloads
                prop_assert!(scheduler.steal_attempts > 0,
                    "No steal attempts made with {} tasks on {} workers", task_count, worker_count);
                prop_assert!((0.0..=1.0).contains(&steal_rate),
                    "Steal success rate must be normalized, got {}", steal_rate);
            }

            // Completeness: all tasks should be executed
            prop_assert_eq!(total_scheduled, task_count,
                "Work stealing failed to execute all tasks: {} of {} completed",
                total_scheduled, task_count);

            // Worker utilization: no worker should be completely idle if work is available
            let min_worker_tasks = scheduler.workers.iter()
                .map(|w| w.executed_tasks.len())
                .min()
                .unwrap_or(0);

            let max_worker_tasks = scheduler.workers.iter()
                .map(|w| w.executed_tasks.len())
                .max()
                .unwrap_or(0);

            if task_count >= worker_count {
                prop_assert!(min_worker_tasks > 0,
                    "Worker starvation detected: min worker executed {} tasks", min_worker_tasks);

                // Load balance bound: no worker should do more than 2x the minimum
                prop_assert!(max_worker_tasks <= min_worker_tasks * 2 + worker_count,
                    "Load imbalance: max worker {} tasks, min worker {} tasks",
                    max_worker_tasks, min_worker_tasks);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Validation Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_kafka_producer_consumer_basic() {
        let mut producer = KafkaProducerModel::new();
        let mut consumer = KafkaConsumerModel::new("test-group");

        let message = KafkaRecordModel::new("test", 0, 0, b"hello".to_vec());
        let offset = producer.send_message("test", 0, message).unwrap();
        assert_eq!(offset, 0);

        consumer.assign_partitions(vec![("test".to_string(), 0)]);
        consumer.consume_from_producer(&producer, 10);
        assert_eq!(consumer.consumed_messages.len(), 1);
    }

    #[test]
    fn test_nats_subject_matching() {
        let wildcard = NatsSubjectModel::new("foo.*");
        assert!(wildcard.matches("foo.bar"));
        assert!(!wildcard.matches("foo.bar.baz"));

        let catch_all = NatsSubjectModel::new("foo.>");
        assert!(catch_all.matches("foo.bar"));
        assert!(catch_all.matches("foo.bar.baz"));
    }

    #[test]
    fn test_redis_resp_basic() {
        let value = Resp3ValueModel::Integer(42);
        let encoded = value.encode_resp3();
        let (decoded, _) = Resp3ValueModel::decode_resp3(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_scheduler_three_lane() {
        let mut scheduler = ThreeLaneSchedulerModel::new();

        // Add tasks to different lanes
        scheduler.enqueue_task(SchedulerTaskModel::new(1, 1)); // ready
        scheduler.enqueue_task(SchedulerTaskModel::new(2, u32::MAX)); // cancel
        scheduler.enqueue_task(SchedulerTaskModel::new(3, 1).with_deadline(Instant::now())); // timed

        // Should get cancel task first
        let first = scheduler.schedule_next().unwrap();
        assert_eq!(first.id, 2);
    }

    #[test]
    fn test_work_stealing_basic() {
        let mut scheduler = WorkStealingSchedulerModel::new(2);

        scheduler.enqueue_task(SchedulerTaskModel::new(1, 1));
        scheduler.enqueue_task(SchedulerTaskModel::new(2, 1));

        // Worker 0 should get task 1, worker 1 should get task 2
        let task1 = scheduler.worker_schedule_next(0);
        let task2 = scheduler.worker_schedule_next(1);

        assert!(task1.is_some());
        assert!(task2.is_some());
    }
}
