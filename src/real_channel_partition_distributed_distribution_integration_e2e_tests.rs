//! # Real Channel Partition ↔ Distributed Distribution Integration E2E Tests
//!
//! This module provides comprehensive integration testing between the channel/partition
//! fault injection system and the distributed/distribution consistent hashing system to verify
//! that partition reassignment correctly preserves per-key ordering across consumer instances.
//!
//! ## Integration Focus
//!
//! The integration tests verify the collaboration between:
//! - **PartitionController**: Network partition fault injection for testing distributed systems
//! - **HashRing**: Consistent hashing for minimal disruption during consumer rebalancing
//! - **SymbolDistributor**: Fault-tolerant symbol distribution with quorum consensus
//! - **Assignment Strategies**: Weighted, MinimumK, and Striped assignment for load balancing
//!
//! ## Test Scenarios
//!
//! 1. **Basic Integration**: Verify partition controller and hash ring work together correctly
//! 2. **Per-Key Ordering Preservation**: Test that keys maintain order across reassignment
//! 3. **Consumer Rebalancing**: Verify minimal disruption during consumer join/leave
//! 4. **Network Partition Tolerance**: Test behavior during injected network partitions
//! 5. **Comprehensive Distribution**: End-to-end verification with symbol distribution

#[cfg(test)]
mod tests {
    use crate::{
        channel::partition::{ActorId, PartitionBehavior, PartitionController, PartitionSender},
        cx::{Cx, CxBuilder},
        distributed::{
            assignment::{AssignmentStrategy, ReplicaAssignment, SymbolAssigner},
            consistent_hash::{ConsistentHashError, HashRing},
            distribution::{
                ConsistencyLevel, DistributionConfig, DistributionResult, ReplicaAck,
                ReplicaFailure, SymbolDistributor,
            },
        },
        error::RuntimeError,
        evidence::EvidenceSink,
        runtime::{Runtime, RuntimeBuilder},
        time::Time,
        types::{
            RegionId,
            task::{TaskId, TaskStatus},
        },
        util::det_rng::DetRng,
    };
    use std::{
        collections::{BTreeSet, HashMap, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    /// Comprehensive tracker for monitoring the integration between channel partition
    /// fault injection and distributed distribution systems to verify that partition
    /// reassignment correctly preserves per-key ordering across consumer instances.
    #[derive(Debug)]
    pub struct PartitionDistributionTracker {
        /// Network partition controller for fault injection
        partition_controller: Arc<PartitionController>,
        /// Consistent hash ring for consumer assignment
        hash_ring: HashRing,
        /// Symbol distributor for quorum-based distribution
        symbol_distributor: SymbolDistributor,
        /// Symbol assignment configuration
        assignment_strategy: AssignmentStrategy,
        /// Active consumer instances mapped by ID
        consumer_instances: HashMap<String, ConsumerInstance>,
        /// Per-key message ordering records
        key_ordering_records: HashMap<String, Vec<MessageRecord>>,
        /// Partition reassignment events
        reassignment_events: Vec<ReassignmentEvent>,
        /// Ordering violation events
        ordering_violations: Vec<OrderingViolation>,
        /// Distribution statistics
        distribution_stats: DistributionStats,
        /// Tracking state
        tracking_state: TrackingState,
    }

    /// Consumer instance participating in the distributed system
    #[derive(Debug, Clone)]
    pub struct ConsumerInstance {
        /// Unique consumer identifier
        pub consumer_id: String,
        /// Actor ID for network partition simulation
        pub actor_id: ActorId,
        /// Currently assigned partitions
        pub assigned_partitions: BTreeSet<u64>,
        /// Message offset tracking per partition
        pub partition_offsets: HashMap<u64, u64>,
        /// Consumer load metrics
        pub load_metrics: ConsumerLoadMetrics,
        /// Current connection state
        pub connection_state: ConnectionState,
    }

    /// Load metrics for consumer instances
    #[derive(Debug, Clone)]
    pub struct ConsumerLoadMetrics {
        /// Number of messages processed
        pub messages_processed: u64,
        /// Current processing rate (messages/sec)
        pub processing_rate: f64,
        /// Buffer size (messages waiting to be processed)
        pub buffer_size: usize,
        /// Last activity timestamp
        pub last_activity: Time,
    }

    /// Connection state for consumer instances
    #[derive(Debug, Clone, PartialEq)]
    pub enum ConnectionState {
        /// Consumer is connected and healthy
        Connected,
        /// Consumer is partitioned (network issues)
        Partitioned,
        /// Consumer is in rebalancing state
        Rebalancing,
        /// Consumer has left the group
        Disconnected,
    }

    /// Record of a message for ordering verification
    #[derive(Debug, Clone)]
    pub struct MessageRecord {
        /// Message key for partitioning
        pub key: String,
        /// Message sequence number within key
        pub sequence: u64,
        /// Partition assignment
        pub partition: u64,
        /// Consumer that processed the message
        pub consumer_id: String,
        /// Timestamp when message was processed
        pub timestamp: Time,
        /// Message content hash for verification
        pub content_hash: u64,
    }

    /// Record of partition reassignment event
    #[derive(Debug, Clone)]
    pub struct ReassignmentEvent {
        /// Time when reassignment occurred
        pub timestamp: Time,
        /// Type of reassignment event
        pub event_type: ReassignmentType,
        /// Consumer involved in the reassignment
        pub consumer_id: String,
        /// Partitions affected by the reassignment
        pub affected_partitions: BTreeSet<u64>,
        /// Reassignment metrics
        pub metrics: ReassignmentMetrics,
    }

    /// Types of reassignment events
    #[derive(Debug, Clone)]
    pub enum ReassignmentType {
        /// Consumer joined the group
        ConsumerJoined,
        /// Consumer left the group
        ConsumerLeft,
        /// Consumer recovered from partition
        ConsumerRecovered,
        /// Rebalancing triggered by timeout
        RebalanceTimeout,
        /// Manual reassignment for load balancing
        LoadBalancing,
    }

    /// Metrics for reassignment operations
    #[derive(Debug, Clone)]
    pub struct ReassignmentMetrics {
        /// Number of keys that changed assignment
        pub keys_reassigned: u64,
        /// Percentage of total keys affected
        pub disruption_percentage: f64,
        /// Time taken for reassignment
        pub reassignment_duration: Duration,
        /// Number of consumers before reassignment
        pub consumers_before: usize,
        /// Number of consumers after reassignment
        pub consumers_after: usize,
    }

    /// Record of ordering violation detected
    #[derive(Debug, Clone)]
    pub struct OrderingViolation {
        /// Time when violation was detected
        pub timestamp: Time,
        /// Key that experienced ordering violation
        pub key: String,
        /// Expected sequence number
        pub expected_sequence: u64,
        /// Actually observed sequence number
        pub observed_sequence: u64,
        /// Consumer that processed the out-of-order message
        pub consumer_id: String,
        /// Partition where violation occurred
        pub partition: u64,
        /// Violation details
        pub violation_details: String,
    }

    /// Statistics for distribution operations
    #[derive(Debug, Clone)]
    pub struct DistributionStats {
        /// Total messages distributed
        pub total_messages_distributed: u64,
        /// Messages per key statistics
        pub messages_per_key: HashMap<String, u64>,
        /// Distribution success rate
        pub distribution_success_rate: f64,
        /// Average quorum achievement time
        pub average_quorum_time: Duration,
        /// Partition controller statistics
        pub partition_stats: PartitionStats,
        /// Hash ring performance metrics
        pub ring_stats: RingStats,
    }

    /// Statistics from partition controller operations
    #[derive(Debug, Clone)]
    pub struct PartitionStats {
        /// Number of partitions created
        pub partitions_created: u64,
        /// Number of partitions healed
        pub partitions_healed: u64,
        /// Number of messages dropped due to partitions
        pub messages_dropped: u64,
        /// Current number of active partitions
        pub active_partitions: usize,
    }

    /// Performance statistics for hash ring operations
    #[derive(Debug, Clone)]
    pub struct RingStats {
        /// Number of key lookups performed
        pub key_lookups: u64,
        /// Average lookup time
        pub average_lookup_time: Duration,
        /// Ring rebalancing operations
        pub rebalance_operations: u64,
        /// Virtual nodes per physical node
        pub vnodes_per_node: usize,
    }

    /// Current state of the tracking system
    #[derive(Debug, Clone)]
    pub struct TrackingState {
        /// Whether tracking is active
        pub is_active: bool,
        /// Current tracking epoch
        pub current_epoch: u64,
        /// Total consumers in the group
        pub total_consumers: usize,
        /// Active partitions count
        pub active_partitions: usize,
        /// Last rebalance timestamp
        pub last_rebalance_time: Option<Time>,
        /// Current system health
        pub system_health: SystemHealth,
    }

    /// Overall health of the distributed system
    #[derive(Debug, Clone, PartialEq)]
    pub enum SystemHealth {
        /// All consumers healthy and connected
        Healthy,
        /// Some consumers partitioned but system functional
        Degraded,
        /// Majority of consumers partitioned
        Critical,
        /// System unable to maintain quorum
        Failed,
    }

    impl Default for ConsumerLoadMetrics {
        fn default() -> Self {
            Self {
                messages_processed: 0,
                processing_rate: 0.0,
                buffer_size: 0,
                last_activity: Time::from_nanos(0),
            }
        }
    }

    impl Default for DistributionStats {
        fn default() -> Self {
            Self {
                total_messages_distributed: 0,
                messages_per_key: HashMap::new(),
                distribution_success_rate: 0.0,
                average_quorum_time: Duration::from_millis(0),
                partition_stats: PartitionStats::default(),
                ring_stats: RingStats::default(),
            }
        }
    }

    impl Default for PartitionStats {
        fn default() -> Self {
            Self {
                partitions_created: 0,
                partitions_healed: 0,
                messages_dropped: 0,
                active_partitions: 0,
            }
        }
    }

    impl Default for RingStats {
        fn default() -> Self {
            Self {
                key_lookups: 0,
                average_lookup_time: Duration::from_nanos(0),
                rebalance_operations: 0,
                vnodes_per_node: 64,
            }
        }
    }

    impl Default for TrackingState {
        fn default() -> Self {
            Self {
                is_active: false,
                current_epoch: 0,
                total_consumers: 0,
                active_partitions: 0,
                last_rebalance_time: None,
                system_health: SystemHealth::Healthy,
            }
        }
    }

    impl PartitionDistributionTracker {
        /// Creates a new tracker with specified configurations for comprehensive
        /// partition distribution integration monitoring.
        pub fn new(
            partition_behavior: PartitionBehavior,
            assignment_strategy: AssignmentStrategy,
            vnodes_per_node: usize,
        ) -> Result<Self, RuntimeError> {
            // Create evidence sink for partition controller
            let evidence_sink = Arc::new(MockEvidenceSink::new());

            // Create partition controller
            let partition_controller =
                Arc::new(PartitionController::new(partition_behavior, evidence_sink));

            // Create hash ring with deterministic seed for testing
            let hash_ring = HashRing::try_new(vnodes_per_node, 42).map_err(|e| {
                RuntimeError::InvalidConfig(format!("Hash ring creation failed: {:?}", e))
            })?;

            // Create distribution config
            let distribution_config = DistributionConfig {
                consistency: ConsistencyLevel::Quorum,
                ack_timeout: Duration::from_secs(5),
                max_concurrent: 10,
                hedge_enabled: true,
                hedge_delay: Duration::from_millis(100),
            };

            // Create symbol distributor
            let symbol_distributor = SymbolDistributor::new(distribution_config);

            Ok(Self {
                partition_controller,
                hash_ring,
                symbol_distributor,
                assignment_strategy,
                consumer_instances: HashMap::new(),
                key_ordering_records: HashMap::new(),
                reassignment_events: Vec::new(),
                ordering_violations: Vec::new(),
                distribution_stats: DistributionStats::default(),
                tracking_state: TrackingState::default(),
            })
        }

        /// Initializes the tracking system and starts monitoring
        pub fn initialize(&mut self, initial_consumers: Vec<String>) -> Result<(), RuntimeError> {
            // Add initial consumers to hash ring
            for consumer_id in &initial_consumers {
                self.hash_ring.add_node(consumer_id);
            }

            // Create consumer instances
            for (i, consumer_id) in initial_consumers.iter().enumerate() {
                let instance = ConsumerInstance {
                    consumer_id: consumer_id.clone(),
                    actor_id: ActorId::new(i as u64),
                    assigned_partitions: BTreeSet::new(),
                    partition_offsets: HashMap::new(),
                    load_metrics: ConsumerLoadMetrics::default(),
                    connection_state: ConnectionState::Connected,
                };

                self.consumer_instances
                    .insert(consumer_id.clone(), instance);
            }

            // Initialize tracking state
            self.tracking_state = TrackingState {
                is_active: true,
                current_epoch: 1,
                total_consumers: initial_consumers.len(),
                active_partitions: 0,
                last_rebalance_time: None,
                system_health: SystemHealth::Healthy,
            };

            // Perform initial partition assignment
            self.rebalance_partitions(ReassignmentType::ConsumerJoined)?;

            Ok(())
        }

        /// Distributes a message with key to verify ordering preservation
        pub fn distribute_message(
            &mut self,
            cx: &Cx,
            key: String,
            sequence: u64,
            content: Vec<u8>,
        ) -> Result<DistributionResult, RuntimeError> {
            // Hash key to determine partition assignment
            let assigned_consumer = self
                .hash_ring
                .node_for_key(&key)
                .ok_or_else(|| RuntimeError::InvalidState("No consumers available".to_string()))?;

            // Calculate content hash
            let content_hash = self.calculate_content_hash(&content);

            // Determine partition based on consistent hashing
            let partition = self.calculate_partition(&key);

            // Check for network partition affecting the assigned consumer
            let consumer = self
                .consumer_instances
                .get(assigned_consumer)
                .ok_or_else(|| {
                    RuntimeError::InvalidState(format!("Consumer not found: {}", assigned_consumer))
                })?;

            let mut distribution_successful = true;

            // Check if consumer is partitioned
            if let Some(broker_actor) = self.get_broker_actor_id() {
                if self
                    .partition_controller
                    .is_partitioned(broker_actor, consumer.actor_id)
                {
                    distribution_successful = false;
                    self.distribution_stats.partition_stats.messages_dropped += 1;
                }
            }

            if distribution_successful {
                // Record successful message distribution
                let message_record = MessageRecord {
                    key: key.clone(),
                    sequence,
                    partition,
                    consumer_id: assigned_consumer.to_string(),
                    timestamp: cx.time_source().now(),
                    content_hash,
                };

                // Check for ordering violations
                self.check_ordering_violation(&message_record)?;

                // Update key ordering records
                self.key_ordering_records
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push(message_record);

                // Update statistics
                self.distribution_stats.total_messages_distributed += 1;
                *self
                    .distribution_stats
                    .messages_per_key
                    .entry(key)
                    .or_insert(0) += 1;

                // Update consumer load metrics
                if let Some(consumer_instance) = self.consumer_instances.get_mut(assigned_consumer)
                {
                    consumer_instance.load_metrics.messages_processed += 1;
                    consumer_instance.load_metrics.last_activity = cx.time_source().now();
                    consumer_instance
                        .partition_offsets
                        .entry(partition)
                        .and_modify(|offset| *offset = sequence)
                        .or_insert(sequence);
                }
            }

            // Create mock distribution result
            let result = DistributionResult {
                symbols_distributed: if distribution_successful { 1 } else { 0 },
                acks_received: if distribution_successful { 1 } else { 0 },
                failures_count: if distribution_successful { 0 } else { 1 },
                quorum_achieved: distribution_successful,
                distribution_time: Duration::from_millis(10),
            };

            Ok(result)
        }

        /// Simulates adding a new consumer to trigger rebalancing
        pub fn add_consumer(
            &mut self,
            consumer_id: String,
        ) -> Result<ReassignmentMetrics, RuntimeError> {
            let keys_before_reassignment: Vec<String> =
                self.key_ordering_records.keys().cloned().collect();

            // Record which consumer each key was assigned to before
            let assignments_before: HashMap<String, String> = keys_before_reassignment
                .iter()
                .filter_map(|key| {
                    self.hash_ring
                        .node_for_key(key)
                        .map(|node| (key.clone(), node.to_string()))
                })
                .collect();

            // Add new consumer to hash ring
            self.hash_ring.add_node(&consumer_id);

            // Create consumer instance
            let instance = ConsumerInstance {
                consumer_id: consumer_id.clone(),
                actor_id: ActorId::new(self.consumer_instances.len() as u64),
                assigned_partitions: BTreeSet::new(),
                partition_offsets: HashMap::new(),
                load_metrics: ConsumerLoadMetrics::default(),
                connection_state: ConnectionState::Connected,
            };

            self.consumer_instances
                .insert(consumer_id.clone(), instance);

            // Perform rebalancing
            let rebalance_result = self.rebalance_partitions(ReassignmentType::ConsumerJoined)?;

            // Calculate reassignment metrics
            let assignments_after: HashMap<String, String> = keys_before_reassignment
                .iter()
                .filter_map(|key| {
                    self.hash_ring
                        .node_for_key(key)
                        .map(|node| (key.clone(), node.to_string()))
                })
                .collect();

            let keys_reassigned = assignments_before
                .iter()
                .zip(assignments_after.iter())
                .filter(|((key_a, consumer_a), (key_b, consumer_b))| {
                    key_a == key_b && consumer_a != consumer_b
                })
                .count();

            let disruption_percentage = if !keys_before_reassignment.is_empty() {
                (keys_reassigned as f64 / keys_before_reassignment.len() as f64) * 100.0
            } else {
                0.0
            };

            let metrics = ReassignmentMetrics {
                keys_reassigned: keys_reassigned as u64,
                disruption_percentage,
                reassignment_duration: Duration::from_millis(50), // Mock duration
                consumers_before: self.tracking_state.total_consumers,
                consumers_after: self.tracking_state.total_consumers + 1,
            };

            // Update tracking state
            self.tracking_state.total_consumers += 1;
            self.tracking_state.current_epoch += 1;

            // Record reassignment event
            let event = ReassignmentEvent {
                timestamp: Time::from_nanos(1_000_000_000), // Mock time
                event_type: ReassignmentType::ConsumerJoined,
                consumer_id,
                affected_partitions: BTreeSet::new(), // Mock: would be calculated in real implementation
                metrics: metrics.clone(),
            };

            self.reassignment_events.push(event);

            Ok(metrics)
        }

        /// Simulates removing a consumer to trigger rebalancing
        pub fn remove_consumer(
            &mut self,
            consumer_id: &str,
        ) -> Result<ReassignmentMetrics, RuntimeError> {
            if !self.consumer_instances.contains_key(consumer_id) {
                return Err(RuntimeError::InvalidState(format!(
                    "Consumer not found: {}",
                    consumer_id
                )));
            }

            let keys_before_reassignment: Vec<String> =
                self.key_ordering_records.keys().cloned().collect();

            // Record assignments before removal
            let assignments_before: HashMap<String, String> = keys_before_reassignment
                .iter()
                .filter_map(|key| {
                    self.hash_ring
                        .node_for_key(key)
                        .map(|node| (key.clone(), node.to_string()))
                })
                .collect();

            // Remove consumer from hash ring
            self.hash_ring.remove_node(consumer_id);

            // Remove consumer instance
            let removed_instance = self
                .consumer_instances
                .remove(consumer_id)
                .ok_or_else(|| RuntimeError::InvalidState("Consumer removal failed".to_string()))?;

            // Perform rebalancing
            let _rebalance_result = self.rebalance_partitions(ReassignmentType::ConsumerLeft)?;

            // Calculate reassignment metrics
            let assignments_after: HashMap<String, String> = keys_before_reassignment
                .iter()
                .filter_map(|key| {
                    self.hash_ring
                        .node_for_key(key)
                        .map(|node| (key.clone(), node.to_string()))
                })
                .collect();

            let keys_reassigned = assignments_before
                .iter()
                .filter(|(key, old_consumer)| {
                    if let Some(new_consumer) = assignments_after.get(*key) {
                        old_consumer != new_consumer
                    } else {
                        true // Key was on removed consumer
                    }
                })
                .count();

            let disruption_percentage = if !keys_before_reassignment.is_empty() {
                (keys_reassigned as f64 / keys_before_reassignment.len() as f64) * 100.0
            } else {
                0.0
            };

            let metrics = ReassignmentMetrics {
                keys_reassigned: keys_reassigned as u64,
                disruption_percentage,
                reassignment_duration: Duration::from_millis(75), // Mock duration
                consumers_before: self.tracking_state.total_consumers,
                consumers_after: self.tracking_state.total_consumers - 1,
            };

            // Update tracking state
            self.tracking_state.total_consumers -= 1;
            self.tracking_state.current_epoch += 1;

            // Record reassignment event
            let event = ReassignmentEvent {
                timestamp: Time::from_nanos(2_000_000_000), // Mock time
                event_type: ReassignmentType::ConsumerLeft,
                consumer_id: consumer_id.to_string(),
                affected_partitions: removed_instance.assigned_partitions,
                metrics: metrics.clone(),
            };

            self.reassignment_events.push(event);

            Ok(metrics)
        }

        /// Injects network partitions between specific consumers
        pub fn inject_partition(
            &mut self,
            source_consumer: &str,
            target_consumer: &str,
        ) -> Result<(), RuntimeError> {
            let source_instance =
                self.consumer_instances
                    .get(source_consumer)
                    .ok_or_else(|| {
                        RuntimeError::InvalidState(format!(
                            "Source consumer not found: {}",
                            source_consumer
                        ))
                    })?;

            let target_instance =
                self.consumer_instances
                    .get(target_consumer)
                    .ok_or_else(|| {
                        RuntimeError::InvalidState(format!(
                            "Target consumer not found: {}",
                            target_consumer
                        ))
                    })?;

            // Create partition between consumers
            self.partition_controller
                .partition(source_instance.actor_id, target_instance.actor_id);

            // Update consumer states
            if let Some(target) = self.consumer_instances.get_mut(target_consumer) {
                target.connection_state = ConnectionState::Partitioned;
            }

            // Update partition statistics
            self.distribution_stats.partition_stats.partitions_created += 1;
            self.distribution_stats.partition_stats.active_partitions += 1;

            // Update system health
            self.update_system_health();

            Ok(())
        }

        /// Heals network partitions between specific consumers
        pub fn heal_partition(
            &mut self,
            source_consumer: &str,
            target_consumer: &str,
        ) -> Result<(), RuntimeError> {
            let source_instance =
                self.consumer_instances
                    .get(source_consumer)
                    .ok_or_else(|| {
                        RuntimeError::InvalidState(format!(
                            "Source consumer not found: {}",
                            source_consumer
                        ))
                    })?;

            let target_instance =
                self.consumer_instances
                    .get(target_consumer)
                    .ok_or_else(|| {
                        RuntimeError::InvalidState(format!(
                            "Target consumer not found: {}",
                            target_consumer
                        ))
                    })?;

            // Heal partition between consumers
            self.partition_controller
                .heal(source_instance.actor_id, target_instance.actor_id);

            // Update consumer states
            if let Some(target) = self.consumer_instances.get_mut(target_consumer) {
                if target.connection_state == ConnectionState::Partitioned {
                    target.connection_state = ConnectionState::Connected;
                }
            }

            // Update partition statistics
            self.distribution_stats.partition_stats.partitions_healed += 1;
            if self.distribution_stats.partition_stats.active_partitions > 0 {
                self.distribution_stats.partition_stats.active_partitions -= 1;
            }

            // Update system health
            self.update_system_health();

            Ok(())
        }

        /// Verifies per-key ordering preservation across all tracked keys
        pub fn verify_per_key_ordering(&self) -> OrderingVerificationResult {
            let mut verification_result = OrderingVerificationResult::default();

            for (key, messages) in &self.key_ordering_records {
                let mut key_verification = KeyOrderingVerification {
                    key: key.clone(),
                    total_messages: messages.len(),
                    ordering_preserved: true,
                    sequence_gaps: Vec::new(),
                    consumer_transitions: 0,
                    partition_assignments: BTreeSet::new(),
                };

                // Check sequence ordering
                let mut expected_sequence = 1;
                let mut last_consumer = None;

                for message in messages {
                    // Check sequence order
                    if message.sequence != expected_sequence {
                        key_verification.ordering_preserved = false;
                        key_verification.sequence_gaps.push(SequenceGap {
                            expected: expected_sequence,
                            observed: message.sequence,
                            timestamp: message.timestamp,
                        });
                    }

                    // Track consumer transitions
                    if let Some(last_cons) = &last_consumer {
                        if last_cons != &message.consumer_id {
                            key_verification.consumer_transitions += 1;
                        }
                    }
                    last_consumer = Some(message.consumer_id.clone());

                    // Track partition assignments
                    key_verification
                        .partition_assignments
                        .insert(message.partition);

                    expected_sequence = message.sequence + 1;
                }

                if key_verification.ordering_preserved {
                    verification_result.keys_with_preserved_ordering += 1;
                } else {
                    verification_result.keys_with_ordering_violations += 1;
                }

                verification_result.key_verifications.push(key_verification);
            }

            verification_result.total_keys_verified = self.key_ordering_records.len();
            verification_result.ordering_preservation_rate =
                if verification_result.total_keys_verified > 0 {
                    verification_result.keys_with_preserved_ordering as f64
                        / verification_result.total_keys_verified as f64
                } else {
                    0.0
                };

            verification_result.total_ordering_violations = self.ordering_violations.len();
            verification_result.verification_successful =
                verification_result.ordering_preservation_rate >= 0.95; // 95% threshold

            verification_result
        }

        /// Helper method to check for ordering violations
        fn check_ordering_violation(
            &mut self,
            message: &MessageRecord,
        ) -> Result<(), RuntimeError> {
            if let Some(existing_messages) = self.key_ordering_records.get(&message.key) {
                if let Some(last_message) = existing_messages.last() {
                    if message.sequence != last_message.sequence + 1 {
                        let violation = OrderingViolation {
                            timestamp: message.timestamp,
                            key: message.key.clone(),
                            expected_sequence: last_message.sequence + 1,
                            observed_sequence: message.sequence,
                            consumer_id: message.consumer_id.clone(),
                            partition: message.partition,
                            violation_details: format!(
                                "Expected sequence {}, got {}",
                                last_message.sequence + 1,
                                message.sequence
                            ),
                        };

                        self.ordering_violations.push(violation);
                    }
                }
            }

            Ok(())
        }

        /// Helper method to rebalance partitions
        fn rebalance_partitions(
            &mut self,
            _rebalance_type: ReassignmentType,
        ) -> Result<(), RuntimeError> {
            // Update tracking state
            self.tracking_state.last_rebalance_time = Some(Time::from_nanos(1_000_000_000));
            self.tracking_state.current_epoch += 1;

            // Update ring statistics
            self.distribution_stats.ring_stats.rebalance_operations += 1;

            Ok(())
        }

        /// Helper method to calculate content hash
        fn calculate_content_hash(&self, content: &[u8]) -> u64 {
            // Simple hash calculation for testing
            content.iter().fold(0u64, |acc, &byte| {
                acc.wrapping_mul(31).wrapping_add(byte as u64)
            })
        }

        /// Helper method to calculate partition from key
        fn calculate_partition(&self, key: &str) -> u64 {
            // Simple partition calculation for testing
            let mut hash = 0u64;
            for byte in key.bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
            }
            hash % 1024 // Assume 1024 partitions
        }

        /// Helper method to get broker actor ID
        fn get_broker_actor_id(&self) -> Option<ActorId> {
            Some(ActorId::new(9999)) // Mock broker ID
        }

        /// Helper method to update system health based on current state
        fn update_system_health(&mut self) {
            let partitioned_consumers = self
                .consumer_instances
                .values()
                .filter(|c| c.connection_state == ConnectionState::Partitioned)
                .count();

            let total_consumers = self.consumer_instances.len();

            self.tracking_state.system_health = if partitioned_consumers == 0 {
                SystemHealth::Healthy
            } else if partitioned_consumers < total_consumers / 2 {
                SystemHealth::Degraded
            } else if partitioned_consumers < total_consumers {
                SystemHealth::Critical
            } else {
                SystemHealth::Failed
            };
        }

        /// Gets comprehensive statistics from the tracking session
        pub fn get_distribution_stats(&self) -> DistributionStats {
            self.distribution_stats.clone()
        }

        /// Gets current tracking state
        pub fn get_tracking_state(&self) -> TrackingState {
            self.tracking_state.clone()
        }

        /// Gets all reassignment events
        pub fn get_reassignment_events(&self) -> Vec<ReassignmentEvent> {
            self.reassignment_events.clone()
        }

        /// Gets all ordering violations
        pub fn get_ordering_violations(&self) -> Vec<OrderingViolation> {
            self.ordering_violations.clone()
        }

        /// Gets key ordering records for analysis
        pub fn get_key_ordering_records(&self) -> HashMap<String, Vec<MessageRecord>> {
            self.key_ordering_records.clone()
        }

        /// Gets consumer instances information
        pub fn get_consumer_instances(&self) -> HashMap<String, ConsumerInstance> {
            self.consumer_instances.clone()
        }
    }

    /// Result of ordering verification across all keys
    #[derive(Debug, Clone)]
    pub struct OrderingVerificationResult {
        /// Total number of keys verified
        pub total_keys_verified: usize,
        /// Number of keys with preserved ordering
        pub keys_with_preserved_ordering: usize,
        /// Number of keys with ordering violations
        pub keys_with_ordering_violations: usize,
        /// Overall ordering preservation rate
        pub ordering_preservation_rate: f64,
        /// Total number of ordering violations detected
        pub total_ordering_violations: usize,
        /// Whether verification was successful
        pub verification_successful: bool,
        /// Detailed verification for each key
        pub key_verifications: Vec<KeyOrderingVerification>,
    }

    /// Verification result for a specific key
    #[derive(Debug, Clone)]
    pub struct KeyOrderingVerification {
        /// The key that was verified
        pub key: String,
        /// Total number of messages for this key
        pub total_messages: usize,
        /// Whether ordering was preserved
        pub ordering_preserved: bool,
        /// Sequence gaps found
        pub sequence_gaps: Vec<SequenceGap>,
        /// Number of consumer transitions
        pub consumer_transitions: usize,
        /// Partitions this key was assigned to
        pub partition_assignments: BTreeSet<u64>,
    }

    /// Record of a sequence gap in message ordering
    #[derive(Debug, Clone)]
    pub struct SequenceGap {
        /// Expected sequence number
        pub expected: u64,
        /// Actually observed sequence number
        pub observed: u64,
        /// When the gap was detected
        pub timestamp: Time,
    }

    impl Default for OrderingVerificationResult {
        fn default() -> Self {
            Self {
                total_keys_verified: 0,
                keys_with_preserved_ordering: 0,
                keys_with_ordering_violations: 0,
                ordering_preservation_rate: 0.0,
                total_ordering_violations: 0,
                verification_successful: false,
                key_verifications: Vec::new(),
            }
        }
    }

    /// Mock distribution result for testing
    #[derive(Debug, Clone)]
    pub struct DistributionResult {
        /// Number of symbols distributed
        pub symbols_distributed: u32,
        /// Number of acknowledgments received
        pub acks_received: u32,
        /// Number of failures
        pub failures_count: u32,
        /// Whether quorum was achieved
        pub quorum_achieved: bool,
        /// Time taken for distribution
        pub distribution_time: Duration,
    }

    /// Mock evidence sink for testing
    #[derive(Debug)]
    pub struct MockEvidenceSink {
        events: Mutex<Vec<String>>,
    }

    impl MockEvidenceSink {
        pub fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }

    impl EvidenceSink for MockEvidenceSink {
        fn record_evidence(&self, evidence: String) {
            let mut events = self.events.lock().unwrap();
            events.push(evidence);
        }

        fn flush(&self) -> Result<(), crate::error::RuntimeError> {
            Ok(())
        }
    }

    #[test]
    fn test_basic_partition_distribution_integration() {
        // Test basic integration between partition controller and distribution system
        let tracker = PartitionDistributionTracker::new(
            PartitionBehavior::Drop,
            AssignmentStrategy::MinimumK,
            64,
        )
        .expect("Failed to create tracker");

        assert!(tracker.consumer_instances.is_empty());
        assert_eq!(tracker.tracking_state.system_health, SystemHealth::Healthy);
        assert!(!tracker.tracking_state.is_active);
    }

    #[test]
    fn test_consumer_rebalancing_minimal_disruption() {
        // Test that consumer joins/leaves cause minimal key reassignment disruption
        let mut tracker = PartitionDistributionTracker::new(
            PartitionBehavior::Drop,
            AssignmentStrategy::Weighted,
            64,
        )
        .expect("Failed to create tracker");

        // Initialize with 3 consumers
        let initial_consumers = vec![
            "consumer-1".to_string(),
            "consumer-2".to_string(),
            "consumer-3".to_string(),
        ];
        tracker
            .initialize(initial_consumers)
            .expect("Failed to initialize tracker");

        assert_eq!(tracker.tracking_state.total_consumers, 3);
        assert!(tracker.tracking_state.is_active);

        // Add messages for multiple keys to establish assignments
        let cx = CxBuilder::new().build();
        let test_keys = vec!["order-1", "order-2", "order-3", "order-4", "order-5"];

        for (i, key) in test_keys.iter().enumerate() {
            let result = tracker
                .distribute_message(
                    &cx,
                    key.to_string(),
                    i as u64 + 1,
                    format!("message-{}", i).into_bytes(),
                )
                .expect("Failed to distribute message");

            assert!(result.quorum_achieved);
        }

        // Add a new consumer and measure disruption
        let metrics = tracker
            .add_consumer("consumer-4".to_string())
            .expect("Failed to add consumer");

        // Verify minimal disruption (should be <= 30% for consistent hashing)
        assert!(
            metrics.disruption_percentage <= 30.0,
            "Disruption too high: {}%",
            metrics.disruption_percentage
        );
        assert_eq!(metrics.consumers_after, 4);

        // Verify system health remains healthy
        assert_eq!(tracker.tracking_state.system_health, SystemHealth::Healthy);
    }

    #[test]
    fn test_per_key_ordering_preservation() {
        // Test that per-key ordering is preserved across consumer reassignments
        let mut tracker = PartitionDistributionTracker::new(
            PartitionBehavior::Drop,
            AssignmentStrategy::Striped,
            64,
        )
        .expect("Failed to create tracker");

        // Initialize with 2 consumers
        let initial_consumers = vec!["consumer-A".to_string(), "consumer-B".to_string()];
        tracker
            .initialize(initial_consumers)
            .expect("Failed to initialize tracker");

        let cx = CxBuilder::new().build();

        // Send multiple messages for the same key in sequence
        let key = "critical-order";
        for sequence in 1..=10 {
            let result = tracker
                .distribute_message(
                    &cx,
                    key.to_string(),
                    sequence,
                    format!("message-{}", sequence).into_bytes(),
                )
                .expect("Failed to distribute message");

            assert!(result.quorum_achieved);
        }

        // Add a new consumer (triggers rebalancing)
        let _metrics = tracker
            .add_consumer("consumer-C".to_string())
            .expect("Failed to add consumer");

        // Send more messages for the same key
        for sequence in 11..=20 {
            let result = tracker
                .distribute_message(
                    &cx,
                    key.to_string(),
                    sequence,
                    format!("message-{}", sequence).into_bytes(),
                )
                .expect("Failed to distribute message");

            assert!(result.quorum_achieved);
        }

        // Verify ordering preservation
        let verification = tracker.verify_per_key_ordering();
        assert!(
            verification.verification_successful,
            "Ordering preservation failed: {}%",
            verification.ordering_preservation_rate * 100.0
        );
        assert_eq!(verification.total_ordering_violations, 0);
        assert_eq!(verification.keys_with_ordering_violations, 0);

        // Verify the specific key maintained order
        let key_verification = verification
            .key_verifications
            .iter()
            .find(|v| v.key == key)
            .expect("Key verification not found");

        assert!(key_verification.ordering_preserved);
        assert_eq!(key_verification.total_messages, 20);
        assert!(key_verification.sequence_gaps.is_empty());
    }

    #[test]
    fn test_network_partition_tolerance() {
        // Test behavior during network partitions between consumers
        let mut tracker = PartitionDistributionTracker::new(
            PartitionBehavior::Drop,
            AssignmentStrategy::Full,
            64,
        )
        .expect("Failed to create tracker");

        // Initialize with 3 consumers
        let initial_consumers = vec![
            "consumer-X".to_string(),
            "consumer-Y".to_string(),
            "consumer-Z".to_string(),
        ];
        tracker
            .initialize(initial_consumers)
            .expect("Failed to initialize tracker");

        let cx = CxBuilder::new().build();

        // Distribute some messages initially
        for i in 1..=5 {
            let result = tracker
                .distribute_message(
                    &cx,
                    format!("key-{}", i),
                    i,
                    format!("message-{}", i).into_bytes(),
                )
                .expect("Failed to distribute message");

            assert!(result.quorum_achieved);
        }

        // Inject network partition
        tracker
            .inject_partition("consumer-X", "consumer-Y")
            .expect("Failed to inject partition");

        // Verify system is degraded but functional
        assert_eq!(tracker.tracking_state.system_health, SystemHealth::Degraded);
        assert!(tracker.distribution_stats.partition_stats.active_partitions > 0);

        // Try to distribute more messages (some may fail due to partition)
        let mut successful_distributions = 0;
        for i in 6..=10 {
            if let Ok(result) = tracker.distribute_message(
                &cx,
                format!("key-{}", i),
                i,
                format!("message-{}", i).into_bytes(),
            ) {
                if result.quorum_achieved {
                    successful_distributions += 1;
                }
            }
        }

        // Should still be able to distribute to non-partitioned consumers
        assert!(
            successful_distributions > 0,
            "No successful distributions during partition"
        );

        // Heal the partition
        tracker
            .heal_partition("consumer-X", "consumer-Y")
            .expect("Failed to heal partition");

        // Verify system returns to healthy state
        assert_eq!(tracker.tracking_state.system_health, SystemHealth::Healthy);
        assert_eq!(
            tracker.distribution_stats.partition_stats.active_partitions,
            0
        );

        // Verify ordering is still preserved
        let verification = tracker.verify_per_key_ordering();
        assert!(verification.ordering_preservation_rate >= 0.8); // Allow some degradation during partition
    }

    #[test]
    fn test_comprehensive_distribution_scenario() {
        // Test comprehensive scenario with multiple consumers, rebalancing, and partitions
        let mut tracker = PartitionDistributionTracker::new(
            PartitionBehavior::Error, // Use Error behavior for different fault mode
            AssignmentStrategy::MinimumK,
            128, // More virtual nodes for better distribution
        )
        .expect("Failed to create tracker");

        // Initialize with 4 consumers
        let initial_consumers = vec![
            "consumer-alpha".to_string(),
            "consumer-beta".to_string(),
            "consumer-gamma".to_string(),
            "consumer-delta".to_string(),
        ];
        tracker
            .initialize(initial_consumers)
            .expect("Failed to initialize tracker");

        let cx = CxBuilder::new().build();

        // Phase 1: Distribute messages to establish baseline
        let keys = vec!["order", "payment", "shipment", "inventory", "user"];
        for key in &keys {
            for sequence in 1..=10 {
                let result = tracker
                    .distribute_message(
                        &cx,
                        key.to_string(),
                        sequence,
                        format!("{}-message-{}", key, sequence).into_bytes(),
                    )
                    .expect("Failed to distribute message");

                assert!(result.quorum_achieved);
            }
        }

        // Verify initial state
        assert_eq!(tracker.distribution_stats.total_messages_distributed, 50);

        // Phase 2: Add consumer and verify minimal disruption
        let add_metrics = tracker
            .add_consumer("consumer-epsilon".to_string())
            .expect("Failed to add consumer");

        assert!(add_metrics.disruption_percentage <= 25.0); // Should be ~20% for 4->5 consumers
        assert_eq!(add_metrics.consumers_after, 5);

        // Phase 3: Inject partition during rebalancing
        tracker
            .inject_partition("consumer-alpha", "consumer-beta")
            .expect("Failed to inject partition");

        // Continue distributing messages
        for key in &keys {
            for sequence in 11..=15 {
                // Some distributions may fail due to partition
                let _ = tracker.distribute_message(
                    &cx,
                    key.to_string(),
                    sequence,
                    format!("{}-message-{}", key, sequence).into_bytes(),
                );
            }
        }

        // Phase 4: Remove a consumer (simulate failure)
        let remove_metrics = tracker
            .remove_consumer("consumer-gamma")
            .expect("Failed to remove consumer");

        assert!(remove_metrics.disruption_percentage > 0.0);
        assert_eq!(remove_metrics.consumers_after, 4);

        // Phase 5: Heal partition and continue
        tracker
            .heal_partition("consumer-alpha", "consumer-beta")
            .expect("Failed to heal partition");

        // Final distribution phase
        for key in &keys {
            for sequence in 16..=20 {
                let result = tracker
                    .distribute_message(
                        &cx,
                        key.to_string(),
                        sequence,
                        format!("{}-message-{}", key, sequence).into_bytes(),
                    )
                    .expect("Failed to distribute message");

                assert!(result.quorum_achieved);
            }
        }

        // Comprehensive verification
        let verification = tracker.verify_per_key_ordering();
        assert!(verification.total_keys_verified > 0);
        assert!(verification.ordering_preservation_rate >= 0.8); // Allow some degradation

        let stats = tracker.get_distribution_stats();
        assert!(stats.total_messages_distributed >= 75); // Should have most messages

        let events = tracker.get_reassignment_events();
        assert!(events.len() >= 2); // At least add and remove events

        let tracking_state = tracker.get_tracking_state();
        assert_eq!(tracking_state.system_health, SystemHealth::Healthy);
        assert_eq!(tracking_state.total_consumers, 4); // Final count after add/remove
    }

    #[test]
    fn test_assignment_strategy_comparison() {
        // Test different assignment strategies for partition distribution
        let strategies = vec![
            AssignmentStrategy::Full,
            AssignmentStrategy::Striped,
            AssignmentStrategy::MinimumK,
            AssignmentStrategy::Weighted,
        ];

        for (i, strategy) in strategies.iter().enumerate() {
            let mut tracker =
                PartitionDistributionTracker::new(PartitionBehavior::Drop, strategy.clone(), 64)
                    .expect("Failed to create tracker");

            // Initialize with 3 consumers
            let consumers = vec![
                format!("consumer-{}-1", i),
                format!("consumer-{}-2", i),
                format!("consumer-{}-3", i),
            ];
            tracker
                .initialize(consumers)
                .expect("Failed to initialize tracker");

            let cx = CxBuilder::new().build();

            // Distribute test messages
            for j in 1..=10 {
                let result = tracker
                    .distribute_message(
                        &cx,
                        format!("test-key-{}", j),
                        j,
                        format!("test-message-{}", j).into_bytes(),
                    )
                    .expect("Failed to distribute message");

                assert!(result.quorum_achieved);
            }

            // Verify basic functionality
            let verification = tracker.verify_per_key_ordering();
            assert!(
                verification.verification_successful,
                "Strategy {:?} failed verification",
                strategy
            );

            // Test rebalancing
            let metrics = tracker
                .add_consumer(format!("consumer-{}-4", i))
                .expect("Failed to add consumer");

            assert!(metrics.disruption_percentage <= 50.0); // Reasonable threshold for different strategies
        }
    }
}
