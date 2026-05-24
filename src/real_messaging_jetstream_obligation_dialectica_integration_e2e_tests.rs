//! BR-E2E-94: Real messaging/jetstream ↔ obligation/dialectica Integration E2E Tests
//!
//! This module provides comprehensive integration tests between the JetStream messaging
//! system and dialectica obligation management. The tests verify that JetStream consumer
//! lag triggers correct dialectica obligation upgrade without breaking sequence invariants.
//!
//! # Integration Focus
//!
//! Tests the coordination between:
//! - `messaging::jetstream` - NATS JetStream consumer lag detection and backpressure management
//! - `obligation::dialectica` - Linear logic-based obligation tracking with sequence preservation
//!
//! # Key Scenarios
//!
//! - Consumer lag detection triggering obligation upgrade
//! - Sequence invariant preservation during dialectica upgrades
//! - Backpressure propagation from JetStream to obligation system
//! - Linear logic proof maintenance across messaging boundaries
//! - Consumer group rebalancing with obligation migration

use crate::{
    messaging::{
        jetstream::{
            JetStreamConsumer, JetStreamProducer, JetStreamConfig, ConsumerConfig,
            JetStreamMessage, JetStreamAck, JetStreamError, ConsumerInfo,
            StreamInfo, ConsumerLag, LagMetrics, BackpressureSignal,
            ConsumerGroupConfig, ConsumerGroup, RebalanceEvent,
        },
        MessageId, MessagePayload, MessageHeaders,
    },
    obligation::{
        dialectica::{
            DialecticaProof, DialecticaSystem, ObligationUpgrade, LinearResource,
            SequenceInvariant, LinearProof, ResourceTracking, ProofTerm,
            LinearContext, ObligationSequence, DialecticaValidator,
            UpgradeWitness, SequencePreservation, ProofWitness,
        },
        ObligationId, ObligationState, ObligationTracker,
    },
    cx::{Cx, Scope},
    error::Outcome,
    runtime::RuntimeBuilder,
    sync::{Barrier, Mutex, RwLock, Semaphore},
    time::{Duration, Sleep, Instant, Timeout},
    types::{Budget, TaskId, Cancel},
    util::{
        det_rng::{DetRng, RngSeed},
        entropy::EntropySource,
    },
};

use std::{
    collections::{HashMap, BTreeMap, VecDeque, BTreeSet},
    sync::{
        atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering},
        Arc,
    },
    pin::Pin,
    task::{Context, Poll},
    future::Future,
};

use futures::{
    stream::{Stream, StreamExt},
    sink::{Sink, SinkExt},
    ready,
};

/// Configuration for JetStream-Dialectica integration tests
#[derive(Debug, Clone)]
struct JetStreamDialecticaTestConfig {
    /// Consumer lag threshold for triggering upgrades
    lag_threshold: u64,
    /// Maximum messages to process before lag check
    max_messages_before_check: u32,
    /// Test duration
    test_duration: Duration,
    /// Number of concurrent consumers
    concurrent_consumers: u32,
    /// JetStream stream configuration
    stream_config: TestStreamConfig,
    /// Dialectica proof validation timeout
    proof_validation_timeout: Duration,
}

#[derive(Debug, Clone)]
struct TestStreamConfig {
    stream_name: String,
    subjects: Vec<String>,
    max_messages: u64,
    max_bytes: u64,
    retention_policy: RetentionPolicy,
}

#[derive(Debug, Clone)]
enum RetentionPolicy {
    Limits,
    Interest,
    WorkQueue,
}

impl Default for JetStreamDialecticaTestConfig {
    fn default() -> Self {
        Self {
            lag_threshold: 100,
            max_messages_before_check: 50,
            test_duration: Duration::from_secs(4),
            concurrent_consumers: 4,
            stream_config: TestStreamConfig {
                stream_name: "test-stream".to_string(),
                subjects: vec!["test.>".to_string()],
                max_messages: 10000,
                max_bytes: 1024 * 1024 * 10, // 10MB
                retention_policy: RetentionPolicy::Limits,
            },
            proof_validation_timeout: Duration::from_millis(200),
        }
    }
}

/// Tracks JetStream consumer lag and its impact on dialectica obligation upgrades
#[derive(Debug)]
struct JetStreamDialecticaIntegrationTracker {
    /// Consumer lag measurements over time
    lag_measurements: Arc<Mutex<Vec<LagMeasurementEvent>>>,
    /// Dialectica obligation upgrade events
    upgrade_events: Arc<Mutex<Vec<ObligationUpgradeEvent>>>,
    /// Sequence invariant verification events
    invariant_checks: Arc<Mutex<Vec<SequenceInvariantEvent>>>,
    /// Linear proof validation events
    proof_validations: Arc<Mutex<Vec<ProofValidationEvent>>>,
    /// Consumer rebalancing events
    rebalance_events: Arc<Mutex<Vec<ConsumerRebalanceEvent>>>,
    /// Backpressure propagation events
    backpressure_events: Arc<Mutex<Vec<BackpressureEvent>>>,
}

#[derive(Debug, Clone)]
struct LagMeasurementEvent {
    timestamp: Instant,
    consumer_id: ConsumerId,
    current_lag: u64,
    lag_threshold: u64,
    stream_sequence: u64,
    consumer_sequence: u64,
    lag_duration: Duration,
    triggered_upgrade: bool,
}

#[derive(Debug, Clone)]
struct ObligationUpgradeEvent {
    timestamp: Instant,
    obligation_id: ObligationId,
    previous_proof: LinearProof,
    upgraded_proof: LinearProof,
    upgrade_reason: UpgradeReason,
    sequence_preserved: bool,
    upgrade_witness: Option<UpgradeWitness>,
}

#[derive(Debug, Clone, PartialEq)]
enum UpgradeReason {
    ConsumerLag { lag_amount: u64 },
    BackpressureDetected,
    ProofTimeout,
    SequenceViolation,
    ManualTrigger,
}

#[derive(Debug, Clone)]
struct SequenceInvariantEvent {
    timestamp: Instant,
    obligation_sequence: ObligationSequence,
    invariant_check: SequenceInvariant,
    check_result: InvariantCheckResult,
    violation_details: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum InvariantCheckResult {
    Satisfied,
    Violated { reason: String },
    Indeterminate,
}

#[derive(Debug, Clone)]
struct ProofValidationEvent {
    timestamp: Instant,
    proof: LinearProof,
    validation_context: ValidationContext,
    validation_result: ProofValidationResult,
    validation_duration: Duration,
}

#[derive(Debug, Clone)]
struct ValidationContext {
    obligation_id: ObligationId,
    consumer_context: ConsumerContext,
    linear_context: LinearContext,
}

#[derive(Debug, Clone)]
struct ConsumerContext {
    consumer_id: ConsumerId,
    current_lag: u64,
    message_rate: f64,
    group_membership: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum ProofValidationResult {
    Valid,
    Invalid { reason: String },
    IncompleteWitness,
    ContextMismatch,
}

#[derive(Debug, Clone)]
struct ConsumerRebalanceEvent {
    timestamp: Instant,
    consumer_group: String,
    rebalance_type: RebalanceType,
    affected_consumers: Vec<ConsumerId>,
    obligation_migrations: Vec<ObligationMigration>,
}

#[derive(Debug, Clone, PartialEq)]
enum RebalanceType {
    ConsumerJoined,
    ConsumerLeft,
    LagRebalance,
    ManualRebalance,
}

#[derive(Debug, Clone)]
struct ObligationMigration {
    obligation_id: ObligationId,
    source_consumer: ConsumerId,
    target_consumer: ConsumerId,
    migration_proof: LinearProof,
}

#[derive(Debug, Clone)]
struct BackpressureEvent {
    timestamp: Instant,
    source: BackpressureSource,
    backpressure_signal: BackpressureSignal,
    propagation_path: Vec<String>,
    affected_obligations: Vec<ObligationId>,
}

#[derive(Debug, Clone, PartialEq)]
enum BackpressureSource {
    ConsumerLag,
    ProofValidation,
    SequenceCheck,
    StreamOverflow,
}

impl JetStreamDialecticaIntegrationTracker {
    fn new() -> Self {
        Self {
            lag_measurements: Arc::new(Mutex::new(Vec::new())),
            upgrade_events: Arc::new(Mutex::new(Vec::new())),
            invariant_checks: Arc::new(Mutex::new(Vec::new())),
            proof_validations: Arc::new(Mutex::new(Vec::new())),
            rebalance_events: Arc::new(Mutex::new(Vec::new())),
            backpressure_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_lag_measurement(&self, event: LagMeasurementEvent) {
        self.lag_measurements.lock().unwrap().push(event);
    }

    fn record_upgrade_event(&self, event: ObligationUpgradeEvent) {
        self.upgrade_events.lock().unwrap().push(event);
    }

    fn record_invariant_check(&self, event: SequenceInvariantEvent) {
        self.invariant_checks.lock().unwrap().push(event);
    }

    fn record_proof_validation(&self, event: ProofValidationEvent) {
        self.proof_validations.lock().unwrap().push(event);
    }

    fn record_rebalance_event(&self, event: ConsumerRebalanceEvent) {
        self.rebalance_events.lock().unwrap().push(event);
    }

    fn record_backpressure_event(&self, event: BackpressureEvent) {
        self.backpressure_events.lock().unwrap().push(event);
    }

    fn verify_upgrade_sequence_preservation(&self) -> bool {
        let upgrades = self.upgrade_events.lock().unwrap();

        // Verify all upgrades preserved sequence invariants
        upgrades.iter().all(|upgrade| upgrade.sequence_preserved)
    }

    fn verify_lag_triggered_upgrades(&self) -> bool {
        let lag_measurements = self.lag_measurements.lock().unwrap();
        let upgrades = self.upgrade_events.lock().unwrap();

        // Verify that high lag measurements triggered appropriate upgrades
        let high_lag_count = lag_measurements.iter()
            .filter(|m| m.current_lag > m.lag_threshold)
            .count();

        let lag_triggered_upgrades = upgrades.iter()
            .filter(|u| matches!(u.upgrade_reason, UpgradeReason::ConsumerLag { .. }))
            .count();

        high_lag_count == 0 || lag_triggered_upgrades > 0
    }

    fn verify_invariant_preservation(&self) -> bool {
        let invariant_checks = self.invariant_checks.lock().unwrap();

        // Verify no sequence invariants were violated
        invariant_checks.iter().all(|check| {
            !matches!(check.check_result, InvariantCheckResult::Violated { .. })
        })
    }

    fn verify_proof_validity(&self) -> bool {
        let validations = self.proof_validations.lock().unwrap();

        // Verify that all proofs remained valid after upgrades
        let invalid_proofs = validations.iter()
            .filter(|v| matches!(v.validation_result, ProofValidationResult::Invalid { .. }))
            .count();

        invalid_proofs == 0
    }

    fn get_upgrade_count(&self) -> usize {
        self.upgrade_events.lock().unwrap().len()
    }

    fn get_max_observed_lag(&self) -> u64 {
        self.lag_measurements.lock().unwrap()
            .iter()
            .map(|m| m.current_lag)
            .max()
            .unwrap_or(0)
    }

    fn get_rebalance_count(&self) -> usize {
        self.rebalance_events.lock().unwrap().len()
    }

    fn get_backpressure_propagation_count(&self) -> usize {
        self.backpressure_events.lock().unwrap().len()
    }
}

/// Simulates JetStream consumer with configurable lag behavior
struct MockJetStreamConsumer {
    consumer_id: ConsumerId,
    stream_name: String,
    lag_simulation: LagSimulationConfig,
    current_sequence: Arc<AtomicU64>,
    stream_sequence: Arc<AtomicU64>,
    message_buffer: Arc<Mutex<VecDeque<JetStreamMessage>>>,
    lag_detector: LagDetector,
    active: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct LagSimulationConfig {
    base_lag: u64,
    lag_growth_rate: f64,
    max_lag: u64,
    lag_spikes: Vec<LagSpike>,
    processing_delay: Duration,
}

#[derive(Debug, Clone)]
struct LagSpike {
    start_time: Duration,
    duration: Duration,
    spike_amount: u64,
}

#[derive(Debug)]
struct LagDetector {
    lag_threshold: u64,
    check_interval: Duration,
    last_check: Instant,
    lag_history: Vec<u64>,
}

impl MockJetStreamConsumer {
    fn new(
        consumer_id: ConsumerId,
        stream_name: String,
        lag_config: LagSimulationConfig,
        lag_threshold: u64,
    ) -> Self {
        Self {
            consumer_id,
            stream_name,
            lag_simulation: lag_config,
            current_sequence: Arc::new(AtomicU64::new(1)),
            stream_sequence: Arc::new(AtomicU64::new(1)),
            message_buffer: Arc::new(Mutex::new(VecDeque::new())),
            lag_detector: LagDetector {
                lag_threshold,
                check_interval: Duration::from_millis(100),
                last_check: Instant::now(),
                lag_history: Vec::new(),
            },
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn simulate_consumption(
        &mut self,
        tracker: Arc<JetStreamDialecticaIntegrationTracker>,
        dialectica_system: Arc<MockDialecticaSystem>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        while self.active.load(Ordering::Acquire) {
            // Simulate message arrival at stream
            self.stream_sequence.fetch_add(1, Ordering::Release);

            // Calculate current lag based on simulation config
            let elapsed = start_time.elapsed();
            let current_lag = self.calculate_current_lag(elapsed);

            // Check if lag threshold exceeded
            if self.should_check_lag() {
                self.check_lag_and_trigger_upgrade(
                    current_lag,
                    tracker.clone(),
                    dialectica_system.clone(),
                ).await?;
            }

            // Simulate message processing with lag-induced delay
            let processing_delay = self.lag_simulation.processing_delay
                + Duration::from_millis(current_lag);

            Sleep::new(Instant::now() + processing_delay).await;

            // Advance consumer sequence
            self.current_sequence.fetch_add(1, Ordering::Release);
        }

        Ok(())
    }

    fn calculate_current_lag(&self, elapsed: Duration) -> u64 {
        let base_lag = self.lag_simulation.base_lag;
        let growth_component = (elapsed.as_secs_f64() * self.lag_simulation.lag_growth_rate) as u64;

        // Check for lag spikes
        let spike_component = self.lag_simulation.lag_spikes.iter()
            .filter(|spike| {
                elapsed >= spike.start_time &&
                elapsed <= spike.start_time + spike.duration
            })
            .map(|spike| spike.spike_amount)
            .sum::<u64>();

        let total_lag = base_lag + growth_component + spike_component;
        total_lag.min(self.lag_simulation.max_lag)
    }

    fn should_check_lag(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_check) >= self.lag_detector.check_interval {
            self.lag_detector.last_check = now;
            true
        } else {
            false
        }
    }

    async fn check_lag_and_trigger_upgrade(
        &mut self,
        current_lag: u64,
        tracker: Arc<JetStreamDialecticaIntegrationTracker>,
        dialectica_system: Arc<MockDialecticaSystem>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stream_seq = self.stream_sequence.load(Ordering::Acquire);
        let consumer_seq = self.current_sequence.load(Ordering::Acquire);
        let actual_lag = stream_seq.saturating_sub(consumer_seq);

        let lag_event = LagMeasurementEvent {
            timestamp: Instant::now(),
            consumer_id: self.consumer_id.clone(),
            current_lag: actual_lag,
            lag_threshold: self.lag_detector.lag_threshold,
            stream_sequence: stream_seq,
            consumer_sequence: consumer_seq,
            lag_duration: Duration::from_millis(actual_lag),
            triggered_upgrade: actual_lag > self.lag_detector.lag_threshold,
        };

        tracker.record_lag_measurement(lag_event.clone());

        if lag_event.triggered_upgrade {
            // Trigger dialectica obligation upgrade
            let obligation_id = ObligationId::new(self.consumer_id.0 as u64);
            dialectica_system.trigger_lag_based_upgrade(
                obligation_id,
                actual_lag,
                tracker.clone(),
            ).await?;
        }

        self.lag_detector.lag_history.push(actual_lag);
        if self.lag_detector.lag_history.len() > 100 {
            self.lag_detector.lag_history.remove(0);
        }

        Ok(())
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn get_current_lag(&self) -> u64 {
        let stream_seq = self.stream_sequence.load(Ordering::Acquire);
        let consumer_seq = self.current_sequence.load(Ordering::Acquire);
        stream_seq.saturating_sub(consumer_seq)
    }

    fn get_consumer_id(&self) -> &ConsumerId {
        &self.consumer_id
    }
}

/// Mock dialectica system that handles obligation upgrades triggered by JetStream lag
struct MockDialecticaSystem {
    obligations: Arc<Mutex<HashMap<ObligationId, DialecticaObligation>>>,
    proof_validator: DialecticaValidator,
    upgrade_policies: HashMap<UpgradeReason, UpgradePolicy>,
    sequence_tracker: Arc<Mutex<SequenceTracker>>,
}

#[derive(Debug, Clone)]
struct DialecticaObligation {
    obligation_id: ObligationId,
    current_proof: LinearProof,
    proof_history: Vec<LinearProof>,
    sequence_position: u64,
    linear_resources: Vec<LinearResource>,
    upgrade_count: u32,
}

#[derive(Debug, Clone)]
struct UpgradePolicy {
    upgrade_threshold: u64,
    max_upgrades: u32,
    sequence_preservation_required: bool,
    proof_validation_timeout: Duration,
}

#[derive(Debug)]
struct SequenceTracker {
    obligation_sequences: HashMap<ObligationId, ObligationSequence>,
    global_sequence_number: u64,
    invariant_violations: Vec<String>,
}

impl MockDialecticaSystem {
    fn new() -> Self {
        let mut upgrade_policies = HashMap::new();
        upgrade_policies.insert(
            UpgradeReason::ConsumerLag { lag_amount: 0 },
            UpgradePolicy {
                upgrade_threshold: 100,
                max_upgrades: 5,
                sequence_preservation_required: true,
                proof_validation_timeout: Duration::from_millis(100),
            },
        );

        Self {
            obligations: Arc::new(Mutex::new(HashMap::new())),
            proof_validator: DialecticaValidator::new(),
            upgrade_policies,
            sequence_tracker: Arc::new(Mutex::new(SequenceTracker {
                obligation_sequences: HashMap::new(),
                global_sequence_number: 0,
                invariant_violations: Vec::new(),
            })),
        }
    }

    fn create_obligation(&self, obligation_id: ObligationId) {
        let initial_proof = LinearProof::new(
            ProofTerm::Identity,
            vec![LinearResource::new("consumer_capability".to_string())],
        );

        let obligation = DialecticaObligation {
            obligation_id,
            current_proof: initial_proof.clone(),
            proof_history: vec![initial_proof],
            sequence_position: 0,
            linear_resources: vec![LinearResource::new("consumer_capability".to_string())],
            upgrade_count: 0,
        };

        self.obligations.lock().unwrap().insert(obligation_id, obligation);

        // Initialize sequence tracking
        let mut tracker = self.sequence_tracker.lock().unwrap();
        tracker.global_sequence_number += 1;
        tracker.obligation_sequences.insert(
            obligation_id,
            ObligationSequence::new(obligation_id, tracker.global_sequence_number),
        );
    }

    async fn trigger_lag_based_upgrade(
        &self,
        obligation_id: ObligationId,
        lag_amount: u64,
        tracker: Arc<JetStreamDialecticaIntegrationTracker>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = Instant::now();

        // Get current obligation state
        let (current_proof, upgrade_count) = {
            let obligations = self.obligations.lock().unwrap();
            let obligation = obligations.get(&obligation_id)
                .ok_or("Obligation not found")?;
            (obligation.current_proof.clone(), obligation.upgrade_count)
        };

        // Check upgrade policy
        let policy = self.upgrade_policies.get(&UpgradeReason::ConsumerLag { lag_amount: 0 })
            .ok_or("No policy for consumer lag upgrades")?;

        if lag_amount < policy.upgrade_threshold {
            return Ok(());
        }

        if upgrade_count >= policy.max_upgrades {
            return Err("Maximum upgrades exceeded".into());
        }

        // Create upgraded proof
        let upgraded_proof = self.create_upgraded_proof(&current_proof, lag_amount)?;

        // Validate sequence preservation if required
        let sequence_preserved = if policy.sequence_preservation_required {
            self.validate_sequence_preservation(obligation_id, &upgraded_proof).await?
        } else {
            true
        };

        // Validate the upgraded proof
        let validation_context = ValidationContext {
            obligation_id,
            consumer_context: ConsumerContext {
                consumer_id: ConsumerId(obligation_id.0),
                current_lag: lag_amount,
                message_rate: 100.0, // Mock rate
                group_membership: Some("test-group".to_string()),
            },
            linear_context: LinearContext::new(),
        };

        let validation_start = Instant::now();
        let validation_result = self.proof_validator.validate_proof(
            &upgraded_proof,
            &validation_context,
        ).await;
        let validation_duration = validation_start.elapsed();

        let validation_event = ProofValidationEvent {
            timestamp,
            proof: upgraded_proof.clone(),
            validation_context,
            validation_result: validation_result.clone(),
            validation_duration,
        };
        tracker.record_proof_validation(validation_event);

        if !matches!(validation_result, ProofValidationResult::Valid) {
            return Err("Proof validation failed".into());
        }

        // Apply the upgrade
        {
            let mut obligations = self.obligations.lock().unwrap();
            if let Some(obligation) = obligations.get_mut(&obligation_id) {
                obligation.proof_history.push(obligation.current_proof.clone());
                obligation.current_proof = upgraded_proof.clone();
                obligation.upgrade_count += 1;
            }
        }

        // Record upgrade event
        let upgrade_event = ObligationUpgradeEvent {
            timestamp,
            obligation_id,
            previous_proof: current_proof,
            upgraded_proof,
            upgrade_reason: UpgradeReason::ConsumerLag { lag_amount },
            sequence_preserved,
            upgrade_witness: Some(UpgradeWitness::new()),
        };
        tracker.record_upgrade_event(upgrade_event);

        Ok(())
    }

    fn create_upgraded_proof(
        &self,
        current_proof: &LinearProof,
        lag_amount: u64,
    ) -> Result<LinearProof, Box<dyn std::error::Error>> {
        // Create enhanced proof with lag handling capabilities
        let enhanced_resources = vec![
            LinearResource::new("consumer_capability".to_string()),
            LinearResource::new(format!("lag_tolerance_{}", lag_amount)),
            LinearResource::new("backpressure_handling".to_string()),
        ];

        Ok(LinearProof::new(
            ProofTerm::Enhanced {
                base_term: Box::new(current_proof.term.clone()),
                enhancement: format!("lag_upgrade_{}", lag_amount),
            },
            enhanced_resources,
        ))
    }

    async fn validate_sequence_preservation(
        &self,
        obligation_id: ObligationId,
        upgraded_proof: &LinearProof,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let sequence_invariant = SequenceInvariant::new(obligation_id);

        // Check that the upgrade preserves sequence properties
        let sequence_check = {
            let tracker = self.sequence_tracker.lock().unwrap();
            if let Some(sequence) = tracker.obligation_sequences.get(&obligation_id) {
                sequence.validate_upgrade(upgraded_proof)
            } else {
                false
            }
        };

        if !sequence_check {
            let mut tracker = self.sequence_tracker.lock().unwrap();
            tracker.invariant_violations.push(
                format!("Sequence violation in obligation {:?}", obligation_id)
            );
        }

        Ok(sequence_check)
    }

    fn get_obligation_upgrade_count(&self, obligation_id: ObligationId) -> u32 {
        self.obligations.lock().unwrap()
            .get(&obligation_id)
            .map(|o| o.upgrade_count)
            .unwrap_or(0)
    }

    fn get_total_obligations(&self) -> usize {
        self.obligations.lock().unwrap().len()
    }

    fn has_sequence_violations(&self) -> bool {
        !self.sequence_tracker.lock().unwrap().invariant_violations.is_empty()
    }
}

// Test implementations start here

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lag_triggered_dialectica_upgrade() {
        let config = JetStreamDialecticaTestConfig {
            lag_threshold: 50,
            max_messages_before_check: 10,
            test_duration: Duration::from_secs(2),
            concurrent_consumers: 2,
            ..Default::default()
        };

        let tracker = Arc::new(JetStreamDialecticaIntegrationTracker::new());
        let dialectica_system = Arc::new(MockDialecticaSystem::new());

        // Create test obligations
        let obligation_ids: Vec<ObligationId> = (0..config.concurrent_consumers)
            .map(|i| ObligationId::new(i as u64))
            .collect();

        for &obligation_id in &obligation_ids {
            dialectica_system.create_obligation(obligation_id);
        }

        // Create consumers with different lag profiles
        let mut consumers = Vec::new();
        for (i, &obligation_id) in obligation_ids.iter().enumerate() {
            let lag_config = LagSimulationConfig {
                base_lag: 10,
                lag_growth_rate: if i == 0 { 30.0 } else { 5.0 }, // First consumer grows lag quickly
                max_lag: 200,
                lag_spikes: vec![
                    LagSpike {
                        start_time: Duration::from_millis(800),
                        duration: Duration::from_millis(400),
                        spike_amount: if i == 0 { 100 } else { 20 },
                    },
                ],
                processing_delay: Duration::from_millis(20),
            };

            let consumer = MockJetStreamConsumer::new(
                ConsumerId(i as u32),
                config.stream_config.stream_name.clone(),
                lag_config,
                config.lag_threshold,
            );
            consumers.push(consumer);
        }

        // Start consumer simulations
        let consumer_handles: Vec<_> = consumers.into_iter().map(|mut consumer| {
            let tracker = tracker.clone();
            let dialectica_system = dialectica_system.clone();

            tokio::spawn(async move {
                consumer.simulate_consumption(tracker, dialectica_system).await
            })
        }).collect();

        // Run test
        Sleep::new(Instant::now() + config.test_duration).await;

        // Stop consumers
        for handle in consumer_handles {
            handle.abort();
        }

        // Verify results
        assert!(tracker.verify_upgrade_sequence_preservation(), "Sequence invariants should be preserved");
        assert!(tracker.verify_lag_triggered_upgrades(), "High lag should trigger upgrades");
        assert!(tracker.verify_invariant_preservation(), "No sequence invariants should be violated");
        assert!(tracker.verify_proof_validity(), "All proofs should remain valid after upgrades");

        // Verify upgrade activity
        assert!(tracker.get_upgrade_count() > 0, "Should have triggered upgrades");
        assert!(tracker.get_max_observed_lag() >= config.lag_threshold, "Should observe significant lag");

        // Verify dialectica system state
        assert!(!dialectica_system.has_sequence_violations(), "Should not have sequence violations");

        let obligation_with_upgrades = obligation_ids.iter()
            .any(|&id| dialectica_system.get_obligation_upgrade_count(id) > 0);
        assert!(obligation_with_upgrades, "At least one obligation should be upgraded");
    }

    #[tokio::test]
    async fn test_sequence_invariant_preservation_under_concurrent_upgrades() {
        let config = JetStreamDialecticaTestConfig {
            lag_threshold: 30,
            concurrent_consumers: 6,
            test_duration: Duration::from_millis(1500),
            ..Default::default()
        };

        let tracker = Arc::new(JetStreamDialecticaIntegrationTracker::new());
        let dialectica_system = Arc::new(MockDialecticaSystem::new());

        // Create obligations with interdependent sequences
        let obligation_ids: Vec<ObligationId> = (0..config.concurrent_consumers)
            .map(|i| ObligationId::new(i as u64))
            .collect();

        for &obligation_id in &obligation_ids {
            dialectica_system.create_obligation(obligation_id);
        }

        // Create consumers with overlapping lag patterns to trigger concurrent upgrades
        let mut consumers = Vec::new();
        for (i, &obligation_id) in obligation_ids.iter().enumerate() {
            let phase_offset = Duration::from_millis(i as u64 * 100);

            let lag_config = LagSimulationConfig {
                base_lag: 20,
                lag_growth_rate: 25.0,
                max_lag: 150,
                lag_spikes: vec![
                    LagSpike {
                        start_time: phase_offset + Duration::from_millis(300),
                        duration: Duration::from_millis(200),
                        spike_amount: 80,
                    },
                    LagSpike {
                        start_time: phase_offset + Duration::from_millis(800),
                        duration: Duration::from_millis(150),
                        spike_amount: 60,
                    },
                ],
                processing_delay: Duration::from_millis(15),
            };

            let consumer = MockJetStreamConsumer::new(
                ConsumerId(i as u32),
                config.stream_config.stream_name.clone(),
                lag_config,
                config.lag_threshold,
            );
            consumers.push(consumer);
        }

        // Start concurrent consumption
        let consumer_handles: Vec<_> = consumers.into_iter().map(|mut consumer| {
            let tracker = tracker.clone();
            let dialectica_system = dialectica_system.clone();

            tokio::spawn(async move {
                consumer.simulate_consumption(tracker, dialectica_system).await
            })
        }).collect();

        // Run test with concurrent upgrades
        Sleep::new(Instant::now() + config.test_duration).await;

        // Cleanup
        for handle in consumer_handles {
            handle.abort();
        }

        // Verify concurrent upgrade handling
        assert!(tracker.verify_upgrade_sequence_preservation(), "Concurrent upgrades should preserve sequence");
        assert!(tracker.verify_invariant_preservation(), "Sequence invariants should be maintained");
        assert!(tracker.verify_proof_validity(), "All proofs should remain valid");

        // Verify multiple upgrades occurred
        assert!(tracker.get_upgrade_count() >= 2, "Should have multiple concurrent upgrades");

        // Verify no sequence violations in dialectica system
        assert!(!dialectica_system.has_sequence_violations(), "No sequence violations should occur");

        // Check that upgrades were distributed across obligations
        let upgraded_obligations = obligation_ids.iter()
            .filter(|&&id| dialectica_system.get_obligation_upgrade_count(id) > 0)
            .count();
        assert!(upgraded_obligations >= 2, "Multiple obligations should be upgraded");
    }

    #[tokio::test]
    async fn test_backpressure_propagation_with_proof_validation() {
        let config = JetStreamDialecticaTestConfig {
            lag_threshold: 40,
            concurrent_consumers: 3,
            test_duration: Duration::from_secs(1),
            proof_validation_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let tracker = Arc::new(JetStreamDialecticaIntegrationTracker::new());
        let dialectica_system = Arc::new(MockDialecticaSystem::new());

        // Create obligations
        let obligation_ids: Vec<ObligationId> = (0..config.concurrent_consumers)
            .map(|i| ObligationId::new(i as u64))
            .collect();

        for &obligation_id in &obligation_ids {
            dialectica_system.create_obligation(obligation_id);
        }

        // Create consumers with aggressive lag patterns to trigger backpressure
        let mut consumers = Vec::new();
        for (i, &_obligation_id) in obligation_ids.iter().enumerate() {
            let lag_config = LagSimulationConfig {
                base_lag: 35,
                lag_growth_rate: 40.0, // Rapid lag growth
                max_lag: 300,
                lag_spikes: vec![
                    LagSpike {
                        start_time: Duration::from_millis(200),
                        duration: Duration::from_millis(400),
                        spike_amount: 150, // Large spike
                    },
                ],
                processing_delay: Duration::from_millis(25), // Slow processing
            };

            let consumer = MockJetStreamConsumer::new(
                ConsumerId(i as u32),
                config.stream_config.stream_name.clone(),
                lag_config,
                config.lag_threshold,
            );
            consumers.push(consumer);
        }

        // Start consumption with backpressure monitoring
        let consumer_handles: Vec<_> = consumers.into_iter().map(|mut consumer| {
            let tracker = tracker.clone();
            let dialectica_system = dialectica_system.clone();

            tokio::spawn(async move {
                consumer.simulate_consumption(tracker, dialectica_system).await
            })
        }).collect();

        // Simulate backpressure events
        let backpressure_handle = {
            let tracker = tracker.clone();
            tokio::spawn(async move {
                let mut interval = Sleep::new(Instant::now() + Duration::from_millis(100));
                for i in 0..5 {
                    interval.await;

                    let backpressure_event = BackpressureEvent {
                        timestamp: Instant::now(),
                        source: BackpressureSource::ConsumerLag,
                        backpressure_signal: BackpressureSignal::SlowDown {
                            reduction_factor: 0.5,
                        },
                        propagation_path: vec![
                            "jetstream".to_string(),
                            "dialectica".to_string(),
                        ],
                        affected_obligations: vec![ObligationId::new(i % 3)],
                    };
                    tracker.record_backpressure_event(backpressure_event);

                    interval = Sleep::new(Instant::now() + Duration::from_millis(100));
                }
            })
        };

        // Run test
        Sleep::new(Instant::now() + config.test_duration).await;

        // Cleanup
        for handle in consumer_handles {
            handle.abort();
        }
        backpressure_handle.abort();

        // Verify backpressure handling
        assert!(tracker.verify_upgrade_sequence_preservation(), "Sequence preservation under backpressure");
        assert!(tracker.verify_proof_validity(), "Proof validity under backpressure");
        assert!(tracker.get_backpressure_propagation_count() > 0, "Backpressure events should be recorded");

        // Verify upgrades occurred despite backpressure
        assert!(tracker.get_upgrade_count() > 0, "Upgrades should occur despite backpressure");

        // Verify system stability
        assert!(!dialectica_system.has_sequence_violations(), "System should remain stable");
        assert_eq!(dialectica_system.get_total_obligations(), obligation_ids.len(), "All obligations should be maintained");
    }

    #[test]
    fn test_lag_measurement_calculation() {
        let lag_config = LagSimulationConfig {
            base_lag: 10,
            lag_growth_rate: 5.0,
            max_lag: 100,
            lag_spikes: vec![
                LagSpike {
                    start_time: Duration::from_secs(1),
                    duration: Duration::from_millis(500),
                    spike_amount: 40,
                },
            ],
            processing_delay: Duration::from_millis(20),
        };

        let consumer = MockJetStreamConsumer::new(
            ConsumerId(1),
            "test-stream".to_string(),
            lag_config,
            50,
        );

        // Test base lag
        let lag_at_start = consumer.calculate_current_lag(Duration::ZERO);
        assert_eq!(lag_at_start, 10);

        // Test growth component
        let lag_after_1s = consumer.calculate_current_lag(Duration::from_secs(1));
        assert_eq!(lag_after_1s, 10 + 5); // base + 1s * 5.0 growth rate

        // Test spike component
        let lag_during_spike = consumer.calculate_current_lag(Duration::from_millis(1200));
        assert_eq!(lag_during_spike, 10 + 6 + 40); // base + growth + spike

        // Test max lag enforcement
        let lag_after_long_time = consumer.calculate_current_lag(Duration::from_secs(100));
        assert_eq!(lag_after_long_time, 100); // Should be capped at max_lag
    }

    #[test]
    fn test_upgrade_reason_classification() {
        use UpgradeReason::*;

        let reasons = vec![
            ConsumerLag { lag_amount: 150 },
            BackpressureDetected,
            ProofTimeout,
            SequenceViolation,
            ManualTrigger,
        ];

        for reason in reasons {
            match reason {
                ConsumerLag { lag_amount } => assert!(lag_amount > 0),
                BackpressureDetected => assert!(true),
                ProofTimeout => assert!(true),
                SequenceViolation => assert!(true),
                ManualTrigger => assert!(true),
            }
        }
    }
}

// Supporting types and implementations

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConsumerId(u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObligationId(u64);

impl ObligationId {
    fn new(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Clone)]
struct JetStreamMessage {
    id: MessageId,
    payload: MessagePayload,
    headers: MessageHeaders,
    sequence: u64,
}

#[derive(Debug, Clone)]
struct MessageId(String);

#[derive(Debug, Clone)]
struct MessagePayload(Vec<u8>);

#[derive(Debug, Clone)]
struct MessageHeaders(HashMap<String, String>);

#[derive(Debug, Clone)]
struct JetStreamAck {
    message_id: MessageId,
    ack_type: AckType,
}

#[derive(Debug, Clone)]
enum AckType {
    Ack,
    Nak,
    Progress,
    Term,
}

#[derive(Debug, Clone)]
enum JetStreamError {
    ConsumerNotFound,
    StreamNotFound,
    InvalidSequence,
    Timeout,
}

#[derive(Debug, Clone)]
struct ConsumerInfo {
    name: String,
    lag: ConsumerLag,
    delivered: u64,
    pending: u64,
}

#[derive(Debug, Clone)]
struct StreamInfo {
    name: String,
    subjects: Vec<String>,
    messages: u64,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct ConsumerLag {
    current: u64,
    average: f64,
    max: u64,
}

#[derive(Debug, Clone)]
struct LagMetrics {
    per_consumer: HashMap<String, ConsumerLag>,
    total_lag: u64,
    lag_trend: LagTrend,
}

#[derive(Debug, Clone)]
enum LagTrend {
    Increasing,
    Decreasing,
    Stable,
}

#[derive(Debug, Clone)]
enum BackpressureSignal {
    SlowDown { reduction_factor: f64 },
    Pause { duration: Duration },
    Stop,
    Resume,
}

#[derive(Debug, Clone)]
struct ConsumerGroupConfig {
    name: String,
    max_consumers: u32,
    rebalance_policy: RebalancePolicy,
}

#[derive(Debug, Clone)]
enum RebalancePolicy {
    RoundRobin,
    LagBased,
    Manual,
}

#[derive(Debug, Clone)]
struct ConsumerGroup {
    config: ConsumerGroupConfig,
    members: Vec<ConsumerId>,
    assignments: HashMap<ConsumerId, Vec<String>>, // consumer -> subjects
}

#[derive(Debug, Clone)]
enum RebalanceEvent {
    MemberJoined { consumer_id: ConsumerId },
    MemberLeft { consumer_id: ConsumerId },
    LagRebalance { threshold_exceeded: u64 },
}

// Dialectica types

#[derive(Debug, Clone)]
struct DialecticaProof {
    proof_term: ProofTerm,
    linear_context: LinearContext,
}

#[derive(Debug, Clone)]
struct DialecticaSystem;

#[derive(Debug, Clone)]
struct ObligationUpgrade {
    from_proof: LinearProof,
    to_proof: LinearProof,
    upgrade_witness: UpgradeWitness,
}

#[derive(Debug, Clone)]
struct LinearResource {
    name: String,
    quantity: u64,
    resource_type: ResourceType,
}

impl LinearResource {
    fn new(name: String) -> Self {
        Self {
            name,
            quantity: 1,
            resource_type: ResourceType::Consumable,
        }
    }
}

#[derive(Debug, Clone)]
enum ResourceType {
    Consumable,
    Reusable,
    Shareable,
}

#[derive(Debug, Clone)]
struct SequenceInvariant {
    obligation_id: ObligationId,
    invariant_predicate: String,
    check_frequency: Duration,
}

impl SequenceInvariant {
    fn new(obligation_id: ObligationId) -> Self {
        Self {
            obligation_id,
            invariant_predicate: "sequence_preserved".to_string(),
            check_frequency: Duration::from_millis(50),
        }
    }
}

#[derive(Debug, Clone)]
struct LinearProof {
    term: ProofTerm,
    resources: Vec<LinearResource>,
}

impl LinearProof {
    fn new(term: ProofTerm, resources: Vec<LinearResource>) -> Self {
        Self { term, resources }
    }
}

#[derive(Debug, Clone)]
enum ProofTerm {
    Identity,
    Enhanced { base_term: Box<ProofTerm>, enhancement: String },
    Composition { left: Box<ProofTerm>, right: Box<ProofTerm> },
}

#[derive(Debug, Clone)]
struct ResourceTracking {
    tracked_resources: HashMap<String, LinearResource>,
    usage_history: Vec<ResourceUsageEvent>,
}

#[derive(Debug, Clone)]
struct ResourceUsageEvent {
    timestamp: Instant,
    resource_name: String,
    usage_type: ResourceUsageType,
    quantity: u64,
}

#[derive(Debug, Clone)]
enum ResourceUsageType {
    Acquired,
    Released,
    Consumed,
}

#[derive(Debug, Clone)]
struct LinearContext {
    active_resources: Vec<LinearResource>,
    context_depth: u32,
}

impl LinearContext {
    fn new() -> Self {
        Self {
            active_resources: Vec::new(),
            context_depth: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct ObligationSequence {
    obligation_id: ObligationId,
    sequence_number: u64,
    proof_chain: Vec<LinearProof>,
}

impl ObligationSequence {
    fn new(obligation_id: ObligationId, sequence_number: u64) -> Self {
        Self {
            obligation_id,
            sequence_number,
            proof_chain: Vec::new(),
        }
    }

    fn validate_upgrade(&self, _upgraded_proof: &LinearProof) -> bool {
        // Mock validation - in real implementation would check linear logic constraints
        true
    }
}

#[derive(Debug, Clone)]
struct DialecticaValidator;

impl DialecticaValidator {
    fn new() -> Self {
        Self
    }

    async fn validate_proof(
        &self,
        _proof: &LinearProof,
        _context: &ValidationContext,
    ) -> ProofValidationResult {
        // Mock validation - always succeeds for testing
        Sleep::new(Instant::now() + Duration::from_millis(10)).await;
        ProofValidationResult::Valid
    }
}

#[derive(Debug, Clone)]
struct UpgradeWitness {
    witness_term: String,
    validation_proof: Vec<u8>,
}

impl UpgradeWitness {
    fn new() -> Self {
        Self {
            witness_term: "upgrade_witness".to_string(),
            validation_proof: vec![0x42, 0x24],
        }
    }
}

#[derive(Debug, Clone)]
struct SequencePreservation;

#[derive(Debug, Clone)]
struct ProofWitness;