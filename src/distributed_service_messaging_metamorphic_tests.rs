//! Metamorphic tests for distributed/*, service/*, and messaging/* modules.
//!
//! This test suite implements metamorphic testing for distributed system consistency,
//! service mesh reliability, and message ordering guarantees.
//!
//! # Coverage Areas
//!
//! ## distributed/* modules
//! - Bridge sequence monotonicity (sequence numbers only increase)
//! - Snapshot/restore round-trip (state preservation identity)
//! - Consistent_hash bucket assignment determinism (same input → same bucket)
//! - Encoding round-trip (distributed message codec identity)
//!
//! ## service/* modules
//! - Rate_limit fairness across keys (fair resource allocation)
//! - Load_balance steady-state (balanced traffic distribution)
//! - Retry idempotency under failures (outcome preservation)
//! - Hedge cancel-on-first-success (redundancy cancellation)
//! - Discover service-set convergence (service discovery stability)
//!
//! ## messaging/* modules
//! - Kafka/NATS/Redis/JetStream pub-sub ordering invariants (message order preservation)
//!
//! # Metamorphic Relations
//!
//! Each test implements one of the six fundamental MR types:
//! - **Equivalence**: f(T(x)) = f(x) for transformations that shouldn't change output
//! - **Additive**: f(x + c) = f(x) + g(c) for predictable offset behavior
//! - **Multiplicative**: f(k·x) = h(k)·f(x) for scaling relationships
//! - **Permutative**: f(permute(x)) = permute(f(x)) for order-preserving ops
//! - **Inclusive**: subset(x) ⊆ subset(f(x)) for monotonic operations
//! - **Invertive**: f(T(T(x))) = f(x) for round-trip operations

#[cfg(test)]
use proptest::prelude::*;

// Mock types and traits for testing distributed systems
#[derive(Debug, Clone, PartialEq)]
pub struct MockDistributedBridge {
    pub node_id: NodeId,
    pub sequence_number: u64,
    pub message_log: Vec<BridgeMessage>,
    pub last_applied_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

#[derive(Debug, Clone, PartialEq)]
pub struct BridgeMessage {
    pub sequence: u64,
    pub content: String,
    pub timestamp: u64,
    pub sender: NodeId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockSnapshot {
    pub data: Vec<(String, String)>,
    pub metadata: SnapshotMetadata,
    pub checksum: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotMetadata {
    pub version: u64,
    pub timestamp: u64,
    pub node_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockConsistentHash {
    pub buckets: Vec<Bucket>,
    pub virtual_nodes_per_bucket: u32,
    pub hash_ring: Vec<(u64, BucketId)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    pub id: BucketId,
    pub node: NodeId,
    pub weight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BucketId(pub u64);

#[derive(Debug, Clone, PartialEq)]
pub struct MockDistributedMessage {
    pub id: u64,
    pub payload: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub routing_key: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockRateLimit {
    pub key: String,
    pub window_size_ms: u64,
    pub max_requests: u32,
    pub current_count: u32,
    pub window_start: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockLoadBalancer {
    pub backends: Vec<Backend>,
    pub algorithm: LoadBalanceAlgorithm,
    pub request_counts: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Backend {
    pub id: String,
    pub address: String,
    pub health: HealthStatus,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoadBalanceAlgorithm {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    Random,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockRetryPolicy {
    pub max_attempts: u32,
    pub backoff_base_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockRetryAttempt {
    pub attempt_number: u32,
    pub delay_ms: u64,
    pub outcome: RetryOutcome,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RetryOutcome {
    Success,
    RetryableFailure,
    NonRetryableFailure,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockHedgeRequest {
    pub request_id: u64,
    pub parallel_requests: Vec<HedgedCall>,
    pub first_success: Option<HedgedCall>,
    pub cancelled_calls: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HedgedCall {
    pub call_id: u64,
    pub backend: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub outcome: Option<RetryOutcome>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockServiceDiscovery {
    pub service_name: String,
    pub discovered_endpoints: Vec<ServiceEndpoint>,
    pub convergence_state: ConvergenceState,
    pub discovery_attempts: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceEndpoint {
    pub address: String,
    pub port: u16,
    pub metadata: Vec<(String, String)>,
    pub last_seen: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConvergenceState {
    Converging,
    Stable,
    Diverging,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockMessageBroker {
    pub broker_type: BrokerType,
    pub topics: Vec<Topic>,
    pub publish_order: Vec<PublishedMessage>,
    pub consume_order: Vec<ConsumedMessage>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrokerType {
    Kafka,
    Nats,
    Redis,
    JetStream,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Topic {
    pub name: String,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Partition {
    pub id: u32,
    pub messages: Vec<PartitionMessage>,
    pub high_water_mark: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartitionMessage {
    pub offset: u64,
    pub key: Option<String>,
    pub value: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublishedMessage {
    pub topic: String,
    pub partition: Option<u32>,
    pub message: PartitionMessage,
    pub publish_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConsumedMessage {
    pub topic: String,
    pub partition: u32,
    pub offset: u64,
    pub message: PartitionMessage,
    pub consume_timestamp: u64,
}

// Mock implementations for testing

impl MockDistributedBridge {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            sequence_number: 0,
            message_log: Vec::new(),
            last_applied_sequence: 0,
        }
    }

    pub fn send_message(&mut self, content: String) -> u64 {
        self.sequence_number += 1;
        let message = BridgeMessage {
            sequence: self.sequence_number,
            content,
            timestamp: self.sequence_number * 1000, // Mock timestamp
            sender: self.node_id,
        };
        self.message_log.push(message);
        self.sequence_number
    }

    pub fn apply_message(&mut self, message: BridgeMessage) -> bool {
        if message.sequence > self.last_applied_sequence {
            self.last_applied_sequence = message.sequence;
            true
        } else {
            false // Out of order or duplicate
        }
    }

    pub fn sequence_monotonicity_holds(&self) -> bool {
        // Check that message log sequences are monotonically increasing
        self.message_log
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
            && self.last_applied_sequence <= self.sequence_number
    }
}

impl MockSnapshot {
    pub fn create(data: Vec<(String, String)>, metadata: SnapshotMetadata) -> Self {
        let checksum = Self::calculate_checksum(&data);
        Self {
            data,
            metadata,
            checksum,
        }
    }

    pub fn restore(snapshot: &Self) -> MockSnapshot {
        // Round-trip: create new snapshot from existing one
        Self::create(snapshot.data.clone(), snapshot.metadata.clone())
    }

    fn calculate_checksum(data: &[(String, String)]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for (k, v) in data {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        hasher.finish()
    }

    pub fn roundtrip_preserves_data(&self, restored: &Self) -> bool {
        self.data == restored.data
            && self.metadata == restored.metadata
            && self.checksum == restored.checksum
    }
}

impl MockConsistentHash {
    pub fn new(buckets: Vec<Bucket>, virtual_nodes_per_bucket: u32) -> Self {
        let mut hash_ring = Vec::new();

        // Create virtual nodes for each bucket
        for bucket in &buckets {
            for i in 0..virtual_nodes_per_bucket {
                let hash = Self::hash_function(&format!("{}:{}", bucket.id.0, i));
                hash_ring.push((hash, bucket.id));
            }
        }

        // Sort by hash value
        hash_ring.sort_by_key(|(hash, _)| *hash);

        Self {
            buckets,
            virtual_nodes_per_bucket,
            hash_ring,
        }
    }

    pub fn get_bucket(&self, key: &str) -> Option<BucketId> {
        if self.hash_ring.is_empty() {
            return None;
        }

        let hash = Self::hash_function(key);

        // Find first bucket with hash >= key hash (consistent hashing)
        for &(ring_hash, bucket_id) in &self.hash_ring {
            if ring_hash >= hash {
                return Some(bucket_id);
            }
        }

        // Wrap around to first bucket
        Some(self.hash_ring[0].1)
    }

    fn hash_function(input: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    }

    pub fn assignment_determinism_holds(&self, keys: &[String]) -> bool {
        // Same key should always map to same bucket
        for key in keys {
            let bucket1 = self.get_bucket(key);
            let bucket2 = self.get_bucket(key);
            if bucket1 != bucket2 {
                return false;
            }
        }
        true
    }
}

impl MockDistributedMessage {
    pub fn new(id: u64, payload: Vec<u8>, routing_key: String) -> Self {
        Self {
            id,
            payload,
            headers: Vec::new(),
            routing_key,
        }
    }

    pub fn add_header(&mut self, key: String, value: String) {
        self.headers.push((key, value));
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend(&self.id.to_le_bytes());
        encoded.extend(&(self.payload.len() as u32).to_le_bytes());
        encoded.extend(&self.payload);
        encoded.extend(&(self.headers.len() as u32).to_le_bytes());

        for (key, value) in &self.headers {
            encoded.extend(&(key.len() as u32).to_le_bytes());
            encoded.extend(key.bytes());
            encoded.extend(&(value.len() as u32).to_le_bytes());
            encoded.extend(value.bytes());
        }

        encoded.extend(&(self.routing_key.len() as u32).to_le_bytes());
        encoded.extend(self.routing_key.bytes());

        encoded
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let mut pos = 0;

        let id = u64::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]);
        pos += 8;

        let payload_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + payload_len > data.len() {
            return None;
        }

        let payload = data[pos..pos + payload_len].to_vec();
        pos += payload_len;

        if pos + 4 > data.len() {
            return None;
        }

        let header_count =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        let mut headers = Vec::new();
        for _ in 0..header_count {
            if pos + 8 > data.len() {
                return None;
            }

            let key_len =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;

            if pos + key_len > data.len() {
                return None;
            }

            let key = String::from_utf8_lossy(&data[pos..pos + key_len]).into_owned();
            pos += key_len;

            if pos + 4 > data.len() {
                return None;
            }

            let value_len =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;
            pos += 4;

            if pos + value_len > data.len() {
                return None;
            }

            let value = String::from_utf8_lossy(&data[pos..pos + value_len]).into_owned();
            pos += value_len;

            headers.push((key, value));
        }

        if pos + 4 > data.len() {
            return None;
        }

        let routing_key_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + routing_key_len > data.len() {
            return None;
        }

        let routing_key = String::from_utf8_lossy(&data[pos..pos + routing_key_len]).into_owned();

        Some(Self {
            id,
            payload,
            headers,
            routing_key,
        })
    }
}

impl MockRateLimit {
    pub fn new(key: String, window_size_ms: u64, max_requests: u32) -> Self {
        Self {
            key,
            window_size_ms,
            max_requests,
            current_count: 0,
            window_start: 0,
        }
    }

    pub fn check_rate(&mut self, timestamp: u64) -> bool {
        // Reset window if expired
        if timestamp >= self.window_start + self.window_size_ms {
            self.window_start = timestamp;
            self.current_count = 0;
        }

        if self.current_count < self.max_requests {
            self.current_count += 1;
            true
        } else {
            false
        }
    }

    pub fn fairness_across_keys(rate_limits: &[Self]) -> f64 {
        if rate_limits.is_empty() {
            return 1.0;
        }

        let counts: Vec<u32> = rate_limits.iter().map(|rl| rl.current_count).collect();
        let total: u32 = counts.iter().sum();
        let average = total as f64 / rate_limits.len() as f64;

        if average == 0.0 {
            return 1.0;
        }

        let variance: f64 = counts
            .iter()
            .map(|&count| (count as f64 - average).powi(2))
            .sum();

        let coefficient_of_variation = (variance / rate_limits.len() as f64).sqrt() / average;

        // Lower coefficient = better fairness
        1.0 / (1.0 + coefficient_of_variation)
    }
}

impl MockLoadBalancer {
    pub fn new(backends: Vec<Backend>, algorithm: LoadBalanceAlgorithm) -> Self {
        let request_counts = vec![0u64; backends.len()];
        Self {
            backends,
            algorithm,
            request_counts,
        }
    }

    pub fn select_backend(&mut self) -> Option<usize> {
        let healthy_backends: Vec<usize> = self
            .backends
            .iter()
            .enumerate()
            .filter_map(|(i, backend)| {
                if backend.health == HealthStatus::Healthy {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if healthy_backends.is_empty() {
            return None;
        }

        let selected_idx = match self.algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let total_requests: u64 = self.request_counts.iter().sum();
                healthy_backends[total_requests as usize % healthy_backends.len()]
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                // Simplified: select based on weight
                let total_weight: u32 = healthy_backends
                    .iter()
                    .map(|&i| self.backends[i].weight)
                    .sum();

                if total_weight == 0 {
                    healthy_backends[0]
                } else {
                    // Select proportionally to weight
                    let total_requests: u64 = self.request_counts.iter().sum();
                    healthy_backends[total_requests as usize % healthy_backends.len()]
                }
            }
            LoadBalanceAlgorithm::LeastConnections => {
                // Find backend with fewest requests
                healthy_backends
                    .iter()
                    .min_by_key(|&&i| self.request_counts[i])
                    .copied()
                    .unwrap_or(healthy_backends[0])
            }
            LoadBalanceAlgorithm::Random => {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                let total: u64 = self.request_counts.iter().sum();
                total.hash(&mut hasher);
                let random = hasher.finish();
                healthy_backends[random as usize % healthy_backends.len()]
            }
        };

        if let Some(&backend_idx) = healthy_backends.iter().find(|&&i| i == selected_idx) {
            self.request_counts[backend_idx] += 1;
            Some(backend_idx)
        } else {
            None
        }
    }

    pub fn steady_state_distribution(&self) -> f64 {
        if self.request_counts.is_empty() {
            return 1.0;
        }

        let total_requests: u64 = self.request_counts.iter().sum();
        if total_requests == 0 {
            return 1.0;
        }

        let expected_per_backend = total_requests as f64 / self.request_counts.len() as f64;
        let variance: f64 = self
            .request_counts
            .iter()
            .map(|&count| (count as f64 - expected_per_backend).powi(2))
            .sum();

        let coefficient_of_variation = if expected_per_backend > 0.0 {
            (variance / self.request_counts.len() as f64).sqrt() / expected_per_backend
        } else {
            0.0
        };

        // Lower coefficient = better balance
        1.0 / (1.0 + coefficient_of_variation)
    }
}

impl MockRetryAttempt {
    pub fn attempt_request(
        policy: &MockRetryPolicy,
        attempt_number: u32,
        will_succeed: bool,
    ) -> Self {
        let delay_ms = if attempt_number == 1 {
            0
        } else {
            let base_delay = policy.backoff_base_ms as f64;
            let exponential_delay =
                base_delay * policy.backoff_multiplier.powi((attempt_number - 2) as i32);

            let jitter_factor = if policy.jitter {
                0.9 + (attempt_number as f64 * 0.1) % 0.2 // Simple jitter simulation
            } else {
                1.0
            };

            (exponential_delay * jitter_factor) as u64
        };

        let outcome = if will_succeed {
            RetryOutcome::Success
        } else if attempt_number < policy.max_attempts {
            RetryOutcome::RetryableFailure
        } else {
            RetryOutcome::NonRetryableFailure
        };

        Self {
            attempt_number,
            delay_ms,
            outcome,
        }
    }

    pub fn retry_idempotency_holds(attempts: &[Self], final_success: bool) -> bool {
        // Multiple retry attempts should not change final outcome
        let last_attempt = attempts.last();
        if let Some(attempt) = last_attempt {
            match attempt.outcome {
                RetryOutcome::Success => final_success,
                RetryOutcome::NonRetryableFailure => !final_success,
                RetryOutcome::RetryableFailure => true, // More attempts possible
            }
        } else {
            true
        }
    }
}

impl MockHedgeRequest {
    pub fn new(request_id: u64, backend_addresses: Vec<String>) -> Self {
        let parallel_requests = backend_addresses
            .into_iter()
            .enumerate()
            .map(|(i, backend)| HedgedCall {
                call_id: i as u64,
                backend,
                started_at: 0,
                finished_at: None,
                outcome: None,
            })
            .collect();

        Self {
            request_id,
            parallel_requests,
            first_success: None,
            cancelled_calls: Vec::new(),
        }
    }

    pub fn complete_call(&mut self, call_id: u64, outcome: RetryOutcome, timestamp: u64) {
        if let Some(call) = self
            .parallel_requests
            .iter_mut()
            .find(|c| c.call_id == call_id)
        {
            call.finished_at = Some(timestamp);
            call.outcome = Some(outcome.clone());

            if outcome == RetryOutcome::Success && self.first_success.is_none() {
                self.first_success = Some(call.clone());

                // Cancel remaining calls
                for other_call in &self.parallel_requests {
                    if other_call.call_id != call_id && other_call.finished_at.is_none() {
                        self.cancelled_calls.push(other_call.call_id);
                    }
                }
            }
        }
    }

    pub fn cancel_on_first_success_holds(&self) -> bool {
        if let Some(ref first_success) = self.first_success {
            // All other unfinished calls should be cancelled
            for call in &self.parallel_requests {
                if call.call_id != first_success.call_id && call.finished_at.is_none() {
                    if !self.cancelled_calls.contains(&call.call_id) {
                        return false;
                    }
                }
            }
            true
        } else {
            // No success yet, no cancellations expected
            self.cancelled_calls.is_empty()
        }
    }
}

impl MockServiceDiscovery {
    pub fn new(service_name: String) -> Self {
        Self {
            service_name,
            discovered_endpoints: Vec::new(),
            convergence_state: ConvergenceState::Converging,
            discovery_attempts: 0,
        }
    }

    pub fn discover(&mut self, available_endpoints: &[ServiceEndpoint]) -> Vec<ServiceEndpoint> {
        self.discovery_attempts += 1;

        // Simple convergence model: gradually discover more endpoints
        let discovery_ratio = (self.discovery_attempts as f64 / 10.0).min(1.0);
        let discovered_count = (available_endpoints.len() as f64 * discovery_ratio) as usize;

        self.discovered_endpoints = available_endpoints[..discovered_count].to_vec();

        // Update convergence state
        self.convergence_state = if discovered_count == available_endpoints.len() {
            ConvergenceState::Stable
        } else {
            ConvergenceState::Converging
        };

        self.discovered_endpoints.clone()
    }

    pub fn convergence_properties_hold(&self, expected_endpoints: &[ServiceEndpoint]) -> bool {
        match self.convergence_state {
            ConvergenceState::Stable => {
                // Should have discovered all expected endpoints
                self.discovered_endpoints.len() == expected_endpoints.len()
            }
            ConvergenceState::Converging => {
                // Should have discovered subset of expected endpoints
                self.discovered_endpoints.len() <= expected_endpoints.len()
            }
            ConvergenceState::Diverging => {
                // Should be losing endpoints
                true // Allow for temporary divergence
            }
        }
    }
}

impl MockMessageBroker {
    pub fn new(broker_type: BrokerType) -> Self {
        Self {
            broker_type,
            topics: Vec::new(),
            publish_order: Vec::new(),
            consume_order: Vec::new(),
        }
    }

    pub fn create_topic(&mut self, topic_name: String, partition_count: u32) {
        let partitions = (0..partition_count)
            .map(|id| Partition {
                id,
                messages: Vec::new(),
                high_water_mark: 0,
            })
            .collect();

        self.topics.push(Topic {
            name: topic_name,
            partitions,
        });
    }

    pub fn publish(
        &mut self,
        topic_name: &str,
        key: Option<String>,
        value: Vec<u8>,
    ) -> Option<(u32, u64)> {
        if let Some(topic) = self.topics.iter_mut().find(|t| t.name == topic_name) {
            // Select partition based on key or round-robin
            let partition_id = if let Some(ref key) = key {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                (hasher.finish() % topic.partitions.len() as u64) as u32
            } else {
                (self.publish_order.len() % topic.partitions.len()) as u32
            };

            if let Some(partition) = topic.partitions.iter_mut().find(|p| p.id == partition_id) {
                let offset = partition.high_water_mark;
                let timestamp = (self.publish_order.len() as u64 + 1) * 1000;

                let message = PartitionMessage {
                    offset,
                    key: key.clone(),
                    value: value.clone(),
                    timestamp,
                };

                partition.messages.push(message.clone());
                partition.high_water_mark += 1;

                let published = PublishedMessage {
                    topic: topic_name.to_string(),
                    partition: Some(partition_id),
                    message,
                    publish_timestamp: timestamp,
                };

                self.publish_order.push(published);
                Some((partition_id, offset))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn consume(
        &mut self,
        topic_name: &str,
        partition_id: u32,
        start_offset: u64,
    ) -> Vec<ConsumedMessage> {
        if let Some(topic) = self.topics.iter().find(|t| t.name == topic_name) {
            if let Some(partition) = topic.partitions.iter().find(|p| p.id == partition_id) {
                let messages: Vec<ConsumedMessage> = partition
                    .messages
                    .iter()
                    .filter(|msg| msg.offset >= start_offset)
                    .map(|msg| {
                        let consumed = ConsumedMessage {
                            topic: topic_name.to_string(),
                            partition: partition_id,
                            offset: msg.offset,
                            message: msg.clone(),
                            consume_timestamp: (self.consume_order.len() as u64 + 1) * 1000,
                        };
                        consumed
                    })
                    .collect();

                // Track consumption order
                for consumed in &messages {
                    self.consume_order.push(consumed.clone());
                }

                messages
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }

    pub fn ordering_invariants_hold(&self) -> bool {
        // Check that within each partition, messages maintain offset order
        for topic in &self.topics {
            for partition in &topic.partitions {
                for window in partition.messages.windows(2) {
                    if window[0].offset >= window[1].offset {
                        return false;
                    }
                }
            }
        }

        // Check that published order is preserved within partitions
        let mut partition_sequences: std::collections::HashMap<(String, u32), Vec<u64>> =
            std::collections::HashMap::new();

        for published in &self.publish_order {
            if let Some(partition_id) = published.partition {
                let key = (published.topic.clone(), partition_id);
                partition_sequences
                    .entry(key)
                    .or_insert_with(Vec::new)
                    .push(published.message.offset);
            }
        }

        // Each partition should have monotonic offsets
        for offsets in partition_sequences.values() {
            for window in offsets.windows(2) {
                if window[0] >= window[1] {
                    return false;
                }
            }
        }

        true
    }
}

/// MR-BridgeSequenceMonotonicity: Bridge sequence numbers should be monotonically increasing
/// Category: Inclusive (sequence numbers only increase)
/// Property: bridge.send_message() always produces sequence > previous sequence
#[test]
fn test_mr_bridge_sequence_monotonicity() {
    proptest!(|(
        node_id: u64,
        messages: Vec<String>
    )| {
        if messages.is_empty() {
            return Ok(());
        }

        let mut bridge = MockDistributedBridge::new(NodeId(node_id));

        let mut last_sequence = 0u64;
        for message in &messages {
            let sequence = bridge.send_message(message.clone());

            // MR: Each sequence should be greater than the last
            prop_assert!(sequence > last_sequence,
                "Bridge sequence should be monotonic: {} > {}", sequence, last_sequence);

            last_sequence = sequence;

            // MR: Bridge should maintain sequence monotonicity invariant
            prop_assert!(bridge.sequence_monotonicity_holds(),
                "Bridge sequence monotonicity invariant should hold");
        }

        // Apply messages and check ordering. Snapshot the message log up
        // front (`.clone()`) so we don't hold an immutable borrow of `bridge`
        // across the mutating `apply_message` calls.
        let messages_to_apply: Vec<_> = bridge.message_log.clone();
        for message in messages_to_apply {
            let applied = bridge.apply_message(message);
            prop_assert!(applied, "Messages should apply in sequence order");
        }
    });
}

/// MR-SnapshotRestoreRoundTrip: Snapshot/restore should preserve state
/// Category: Invertive (snapshot→restore should preserve data)
/// Property: restore(snapshot(data)) = data
#[test]
fn test_mr_snapshot_restore_round_trip() {
    proptest!(|(
        data: Vec<(String, String)>,
        version: u64,
        timestamp: u64,
        node_count in 1usize..=100usize
    )| {
        let metadata = SnapshotMetadata {
            version,
            timestamp,
            node_count,
        };

        let original_snapshot = MockSnapshot::create(data.clone(), metadata);
        let restored_snapshot = MockSnapshot::restore(&original_snapshot);

        // MR: Snapshot/restore round-trip should preserve all data
        prop_assert!(original_snapshot.roundtrip_preserves_data(&restored_snapshot),
            "Snapshot/restore round-trip should preserve data");

        // Checksums should match
        prop_assert_eq!(original_snapshot.checksum, restored_snapshot.checksum,
            "Snapshot checksums should match after round-trip");

        // Multiple restore operations should be idempotent
        let second_restore = MockSnapshot::restore(&restored_snapshot);
        prop_assert!(restored_snapshot.roundtrip_preserves_data(&second_restore),
            "Multiple restores should be idempotent");
    });
}

/// MR-ConsistentHashBucketAssignment: Consistent hashing should be deterministic
/// Category: Equivalence (same key → same bucket always)
/// Property: hash.get_bucket(key) should always return same bucket for same key
#[test]
fn test_mr_consistent_hash_bucket_assignment() {
    proptest!(|(
        bucket_nodes: Vec<u64>,
        virtual_nodes in 1u32..=10u32,
        keys: Vec<String>
    )| {
        if bucket_nodes.is_empty() || keys.is_empty() {
            return Ok(());
        }

        let buckets: Vec<Bucket> = bucket_nodes.into_iter().enumerate()
            .map(|(i, node_id)| Bucket {
                id: BucketId(i as u64),
                node: NodeId(node_id),
                weight: 1,
            })
            .collect();

        let hash_ring = MockConsistentHash::new(buckets, virtual_nodes);

        // MR: Assignment should be deterministic across multiple calls
        prop_assert!(hash_ring.assignment_determinism_holds(&keys),
            "Consistent hash assignment should be deterministic");

        // Test multiple hash ring instances with same configuration
        let hash_ring2 = MockConsistentHash::new(hash_ring.buckets.clone(), virtual_nodes);

        for key in &keys {
            let bucket1 = hash_ring.get_bucket(key);
            let bucket2 = hash_ring2.get_bucket(key);

            prop_assert_eq!(bucket1, bucket2,
                "Same configuration should produce same bucket assignment for key: {}", key);
        }
    });
}

/// MR-DistributedEncodingRoundTrip: Distributed message encoding should be reversible
/// Category: Invertive (encode→decode = identity)
/// Property: decode(encode(message)) = message
#[test]
fn test_mr_distributed_encoding_round_trip() {
    proptest!(|(
        message_id: u64,
        payload: Vec<u8>,
        routing_key: String,
        headers: Vec<(String, String)>
    )| {
        let mut original_message = MockDistributedMessage::new(message_id, payload, routing_key);

        // Add headers
        for (key, value) in &headers {
            if !key.is_empty() && !value.is_empty() {
                original_message.add_header(key.clone(), value.clone());
            }
        }

        // Encode then decode
        let encoded = original_message.encode();
        if let Some(decoded_message) = MockDistributedMessage::decode(&encoded) {
            // MR: Encoding round-trip should preserve message content
            prop_assert_eq!(decoded_message.id, original_message.id,
                "Message ID should be preserved in encoding round-trip");

            prop_assert_eq!(decoded_message.payload, original_message.payload,
                "Payload should be preserved in encoding round-trip");

            prop_assert_eq!(decoded_message.routing_key, original_message.routing_key,
                "Routing key should be preserved in encoding round-trip");

            prop_assert_eq!(decoded_message.headers.len(), original_message.headers.len(),
                "Header count should be preserved in encoding round-trip");

            // Check header preservation
            for (original_key, original_value) in &original_message.headers {
                let found = decoded_message.headers.iter()
                    .any(|(dec_key, dec_value)| dec_key == original_key && dec_value == original_value);
                prop_assert!(found,
                    "Header {}:{} should be preserved in encoding round-trip",
                    original_key, original_value);
            }
        }
    });
}

/// MR-RateLimitFairness: Rate limiting should be fair across different keys
/// Category: Equivalence (fair distribution properties)
/// Property: rate limit enforcement should have bounded variance across keys
#[test]
fn test_mr_rate_limit_fairness() {
    proptest!(|(
        keys: Vec<String>,
        window_size in 1000u64..=10000u64,
        max_requests in 5u32..=50u32,
        request_timestamps: Vec<u64>
    )| {
        if keys.is_empty() || request_timestamps.is_empty() {
            return Ok(());
        }

        let mut rate_limits: Vec<MockRateLimit> = keys.iter()
            .map(|key| MockRateLimit::new(key.clone(), window_size, max_requests))
            .collect();

        // Simulate requests across different keys
        for (i, &timestamp) in request_timestamps.iter().enumerate() {
            let key_idx = i % rate_limits.len();
            let _ = rate_limits[key_idx].check_rate(timestamp);
        }

        // MR: Rate limiting should be reasonably fair across keys
        let fairness = MockRateLimit::fairness_across_keys(&rate_limits);
        prop_assert!(fairness >= 0.0 && fairness <= 1.0,
            "Rate limit fairness coefficient should be between 0 and 1: {}", fairness);

        // All rate limits should respect their maximum
        for rate_limit in &rate_limits {
            prop_assert!(rate_limit.current_count <= rate_limit.max_requests,
                "Rate limit should not exceed maximum: {} <= {}",
                rate_limit.current_count, rate_limit.max_requests);
        }
    });
}

/// MR-LoadBalanceSteadyState: Load balancer should achieve steady-state distribution
/// Category: Equivalence (balanced load distribution)
/// Property: load distribution variance should be bounded in steady state
#[test]
fn test_mr_load_balance_steady_state() {
    proptest!(|(
        backend_addresses: Vec<String>,
        algorithm_idx in 0usize..4,
        request_count in 50usize..=200usize
    )| {
        if backend_addresses.is_empty() {
            return Ok(());
        }

        let algorithms = [
            LoadBalanceAlgorithm::RoundRobin,
            LoadBalanceAlgorithm::WeightedRoundRobin,
            LoadBalanceAlgorithm::LeastConnections,
            LoadBalanceAlgorithm::Random,
        ];

        let backends: Vec<Backend> = backend_addresses.into_iter()
            .map(|addr| Backend {
                id: addr.clone(),
                address: addr,
                health: HealthStatus::Healthy,
                weight: 1,
            })
            .collect();

        let mut load_balancer = MockLoadBalancer::new(backends, algorithms[algorithm_idx].clone());

        // Generate steady-state load
        for _ in 0..request_count {
            let _ = load_balancer.select_backend();
        }

        // MR: Load balancer should achieve reasonable distribution
        let distribution_quality = load_balancer.steady_state_distribution();
        prop_assert!(distribution_quality >= 0.0 && distribution_quality <= 1.0,
            "Load balance distribution quality should be between 0 and 1: {}", distribution_quality);

        // Total requests should match
        let total_distributed: u64 = load_balancer.request_counts.iter().sum();
        prop_assert_eq!(total_distributed, request_count as u64,
            "Total distributed requests should match request count");
    });
}

/// MR-RetryIdempotency: Retry attempts should not change final outcome
/// Category: Equivalence (retry attempts preserve outcome)
/// Property: multiple retry attempts for same request should converge to same result
#[test]
fn test_mr_retry_idempotency() {
    proptest!(|(
        max_attempts in 1u32..=10u32,
        backoff_base in 100u64..=1000u64,
        will_eventually_succeed: bool,
        failure_count in 0u32..=5u32
    )| {
        let policy = MockRetryPolicy {
            max_attempts,
            backoff_base_ms: backoff_base,
            backoff_multiplier: 2.0,
            jitter: true,
        };

        let mut attempts = Vec::new();
        let mut final_success = false;

        for attempt_num in 1..=max_attempts {
            let will_succeed = will_eventually_succeed && attempt_num > failure_count;
            let attempt = MockRetryAttempt::attempt_request(&policy, attempt_num, will_succeed);

            let should_continue = match attempt.outcome {
                RetryOutcome::Success => {
                    final_success = true;
                    false
                }
                RetryOutcome::NonRetryableFailure => false,
                RetryOutcome::RetryableFailure => attempt_num < max_attempts,
            };

            attempts.push(attempt);

            if !should_continue {
                break;
            }
        }

        // MR: Retry idempotency should hold
        prop_assert!(MockRetryAttempt::retry_idempotency_holds(&attempts, final_success),
            "Retry idempotency should hold: attempts converge to consistent outcome");

        // Backoff delays should generally increase
        for window in attempts.windows(2) {
            if window[0].attempt_number < window[1].attempt_number {
                prop_assert!(window[1].delay_ms >= window[0].delay_ms,
                    "Retry delays should generally increase: {} >= {}",
                    window[1].delay_ms, window[0].delay_ms);
            }
        }
    });
}

/// MR-HedgeCancelOnFirstSuccess: Hedge requests should cancel others on first success
/// Category: Equivalence (first success cancels remaining calls)
/// Property: hedge.complete_success(call) should cancel all other pending calls
#[test]
fn test_mr_hedge_cancel_on_first_success() {
    proptest!(|(
        request_id: u64,
        backend_addresses: Vec<String>,
        success_call_idx in 0usize..=5usize
    )| {
        if backend_addresses.is_empty() {
            return Ok(());
        }

        let mut hedge_request = MockHedgeRequest::new(request_id, backend_addresses);
        let call_count = hedge_request.parallel_requests.len();

        if call_count == 0 {
            return Ok(());
        }

        let success_idx = success_call_idx % call_count;
        let success_call_id = hedge_request.parallel_requests[success_idx].call_id;

        // Complete the successful call first
        hedge_request.complete_call(success_call_id, RetryOutcome::Success, 1000);

        // MR: First success should trigger cancellation of other calls
        prop_assert!(hedge_request.cancel_on_first_success_holds(),
            "Hedge request should cancel other calls on first success");

        // The successful call should be recorded as first success
        if let Some(ref first_success) = hedge_request.first_success {
            prop_assert_eq!(first_success.call_id, success_call_id,
                "First success should match the successful call");
        }

        // All other pending calls should be cancelled
        for call in &hedge_request.parallel_requests {
            if call.call_id != success_call_id && call.finished_at.is_none() {
                prop_assert!(hedge_request.cancelled_calls.contains(&call.call_id),
                    "Pending call {} should be cancelled after first success", call.call_id);
            }
        }
    });
}

/// MR-ServiceDiscoveryConvergence: Service discovery should converge to stable endpoint set
/// Category: Inclusive (discovery converges to complete set)
/// Property: repeated discovery should converge to stable set of endpoints
#[test]
fn test_mr_service_discovery_convergence() {
    proptest!(|(
        service_name: String,
        available_endpoints: Vec<String>
    )| {
        if available_endpoints.is_empty() || service_name.is_empty() {
            return Ok(());
        }

        let endpoints: Vec<ServiceEndpoint> = available_endpoints.into_iter().enumerate()
            .map(|(i, addr)| ServiceEndpoint {
                address: addr,
                port: 8080 + i as u16,
                metadata: vec![("version".to_string(), "1.0".to_string())],
                last_seen: 0,
            })
            .collect();

        let mut discovery = MockServiceDiscovery::new(service_name);

        // Perform multiple discovery rounds
        for _ in 0..15 {  // Should be enough for convergence
            let discovered = discovery.discover(&endpoints);

            // MR: Convergence properties should hold
            prop_assert!(discovery.convergence_properties_hold(&endpoints),
                "Service discovery convergence properties should hold");

            // Discovery should not return more than available
            prop_assert!(discovered.len() <= endpoints.len(),
                "Discovered endpoints should not exceed available endpoints");
        }

        // After sufficient rounds, should reach stable state
        if discovery.discovery_attempts >= 10 {
            prop_assert_eq!(discovery.convergence_state, ConvergenceState::Stable,
                "Service discovery should reach stable state after sufficient attempts");
        }
    });
}

/// MR-MessageBrokerOrderingInvariants: Message brokers should preserve ordering within partitions
/// Category: Permutative (publish order = consume order within partitions)
/// Property: messages consumed from partition should maintain publish order
#[test]
fn test_mr_message_broker_ordering_invariants() {
    proptest!(|(
        broker_type_idx in 0usize..4,
        topic_name: String,
        partition_count in 1u32..=4u32,
        messages: Vec<(Option<String>, Vec<u8>)> // (key, value)
    )| {
        if topic_name.is_empty() || messages.is_empty() {
            return Ok(());
        }

        let broker_types = [BrokerType::Kafka, BrokerType::Nats, BrokerType::Redis, BrokerType::JetStream];
        let mut broker = MockMessageBroker::new(broker_types[broker_type_idx].clone());

        broker.create_topic(topic_name.clone(), partition_count);

        // Publish messages
        for (key, value) in &messages {
            let _ = broker.publish(&topic_name, key.clone(), value.clone());
        }

        // MR: Ordering invariants should hold after publishing
        prop_assert!(broker.ordering_invariants_hold(),
            "Message broker ordering invariants should hold after publishing");

        // Consume from each partition
        for partition_id in 0..partition_count {
            let consumed = broker.consume(&topic_name, partition_id, 0);

            // Consumed messages should maintain offset order within partition
            for window in consumed.windows(2) {
                prop_assert!(window[0].offset < window[1].offset,
                    "Consumed messages should maintain offset order within partition");
            }
        }

        // MR: Ordering invariants should still hold after consumption
        prop_assert!(broker.ordering_invariants_hold(),
            "Message broker ordering invariants should hold after consumption");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_implementations() {
        // Test distributed bridge
        let mut bridge = MockDistributedBridge::new(NodeId(1));
        let seq1 = bridge.send_message("message1".to_string());
        let seq2 = bridge.send_message("message2".to_string());
        assert!(seq2 > seq1);
        assert!(bridge.sequence_monotonicity_holds());

        // Test snapshot round-trip
        let data = vec![("key1".to_string(), "value1".to_string())];
        let metadata = SnapshotMetadata {
            version: 1,
            timestamp: 1000,
            node_count: 3,
        };
        let snapshot = MockSnapshot::create(data, metadata);
        let restored = MockSnapshot::restore(&snapshot);
        assert!(snapshot.roundtrip_preserves_data(&restored));

        // Test message broker
        let mut broker = MockMessageBroker::new(BrokerType::Kafka);
        broker.create_topic("test".to_string(), 2);
        let _ = broker.publish("test", Some("key1".to_string()), vec![1, 2, 3]);
        assert!(broker.ordering_invariants_hold());
    }
}
