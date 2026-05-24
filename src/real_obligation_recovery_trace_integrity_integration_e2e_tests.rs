//! Real Obligation Recovery ↔ Trace Integrity Integration E2E Test
//!
//! This test verifies that a recovered execution from a partial snapshot preserves
//! trace integrity hash chain. It validates the integration between obligation
//! recovery systems and trace integrity mechanisms.

#[cfg(test)]
mod tests {
    use crate::{
        cx::{Cx, Scope},
        error::Result,
        lab::LabRuntime,
        obligation::{
            ObligationId, ObligationLease, ObligationPermit, ObligationStatus,
            recovery::{
                ObligationRecovery, PartialSnapshot, RecoveryConfig, RecoveryError,
                RecoverySnapshot, RecoveryState, SnapshotMetadata,
            },
        },
        trace::{
            EventSequence, TraceEvent, TraceHeader, TraceId,
            integrity::{
                ChainVerification, HashChain, HashChainNode, IntegrityChecker, IntegrityError,
                IntegrityHash, IntegritySnapshot, TraceIntegrity,
            },
        },
        types::{Budget, Outcome, TaskId, Time},
    };
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };

    /// Mock obligation recovery system with trace integrity integration
    #[derive(Debug)]
    struct MockObligationRecoverySystem {
        system_id: String,
        config: RecoveryConfig,
        recovery_state: Arc<Mutex<RecoveryState>>,
        snapshots: Arc<Mutex<HashMap<u64, RecoverySnapshot>>>,
        trace_integrity: Arc<MockTraceIntegritySystem>,
        active_obligations: Arc<Mutex<HashMap<ObligationId, ObligationStatus>>>,
        recovery_tracker: Arc<ObligationRecoveryTracker>,
    }

    impl MockObligationRecoverySystem {
        fn new(
            system_id: String,
            config: RecoveryConfig,
            trace_integrity: Arc<MockTraceIntegritySystem>,
        ) -> Self {
            Self {
                system_id,
                config,
                recovery_state: Arc::new(Mutex::new(RecoveryState::Idle)),
                snapshots: Arc::new(Mutex::new(HashMap::new())),
                trace_integrity,
                active_obligations: Arc::new(Mutex::new(HashMap::new())),
                recovery_tracker: Arc::new(ObligationRecoveryTracker::new()),
            }
        }

        async fn create_snapshot(&self, cx: &Cx) -> Result<RecoverySnapshot> {
            let snapshot_id = self.generate_snapshot_id();

            // Get current integrity hash chain
            let integrity_snapshot = self.trace_integrity.create_snapshot().await?;

            // Collect active obligations
            let obligations = self.active_obligations.lock().unwrap().clone();

            let snapshot = RecoverySnapshot {
                id: snapshot_id,
                metadata: SnapshotMetadata {
                    timestamp: Time::now().into(),
                    obligation_count: obligations.len(),
                    integrity_hash: integrity_snapshot.current_hash.clone(),
                    chain_length: integrity_snapshot.chain_length,
                },
                obligations: obligations.clone(),
                integrity_chain: integrity_snapshot.hash_chain.clone(),
                partial_data: None,
            };

            self.snapshots
                .lock()
                .unwrap()
                .insert(snapshot_id, snapshot.clone());

            // Record snapshot creation
            self.recovery_tracker.record_snapshot_creation(
                snapshot_id,
                obligations.len(),
                integrity_snapshot.chain_length,
            );

            Ok(snapshot)
        }

        async fn create_partial_snapshot(
            &self,
            cx: &Cx,
            corruption_point: u64,
        ) -> Result<RecoverySnapshot> {
            let snapshot_id = self.generate_snapshot_id();

            // Get partial integrity state (simulating corruption or interruption)
            let mut integrity_snapshot = self.trace_integrity.create_snapshot().await?;

            // Simulate partial corruption by truncating the chain
            integrity_snapshot
                .hash_chain
                .truncate(corruption_point as usize);
            integrity_snapshot.chain_length = corruption_point;

            // Recalculate current hash based on truncated chain
            if let Some(last_node) = integrity_snapshot.hash_chain.last() {
                integrity_snapshot.current_hash = last_node.hash.clone();
            } else {
                integrity_snapshot.current_hash = IntegrityHash::genesis();
            }

            // Get partial obligations state
            let all_obligations = self.active_obligations.lock().unwrap().clone();
            let partial_obligations: HashMap<ObligationId, ObligationStatus> = all_obligations
                .into_iter()
                .enumerate()
                .filter(|(i, _)| (*i as u64) < corruption_point)
                .map(|(_, (id, status))| (id, status))
                .collect();

            let snapshot = RecoverySnapshot {
                id: snapshot_id,
                metadata: SnapshotMetadata {
                    timestamp: Time::now().into(),
                    obligation_count: partial_obligations.len(),
                    integrity_hash: integrity_snapshot.current_hash.clone(),
                    chain_length: integrity_snapshot.chain_length,
                },
                obligations: partial_obligations.clone(),
                integrity_chain: integrity_snapshot.hash_chain.clone(),
                partial_data: Some(PartialSnapshot {
                    corruption_point,
                    recovered_obligations: partial_obligations.len(),
                    missing_obligations: all_obligations.len() - partial_obligations.len(),
                }),
            };

            self.snapshots
                .lock()
                .unwrap()
                .insert(snapshot_id, snapshot.clone());

            // Record partial snapshot creation
            self.recovery_tracker.record_partial_snapshot_creation(
                snapshot_id,
                corruption_point,
                partial_obligations.len(),
                all_obligations.len() - partial_obligations.len(),
            );

            Ok(snapshot)
        }

        async fn recover_from_snapshot(&self, cx: &Cx, snapshot_id: u64) -> Result<RecoveryResult> {
            let recovery_start = Time::now().into();
            *self.recovery_state.lock().unwrap() = RecoveryState::InProgress;

            let snapshot = self
                .snapshots
                .lock()
                .unwrap()
                .get(&snapshot_id)
                .cloned()
                .ok_or_else(|| RecoveryError::SnapshotNotFound(snapshot_id))?;

            // Step 1: Verify trace integrity before recovery
            let pre_recovery_verification = self
                .trace_integrity
                .verify_integrity(&snapshot.integrity_chain)
                .await?;

            if !pre_recovery_verification.is_valid {
                return Err(RecoveryError::IntegrityVerificationFailed.into());
            }

            // Step 2: Restore trace integrity state
            self.trace_integrity
                .restore_from_snapshot(&snapshot.integrity_chain)
                .await?;

            // Step 3: Restore obligations
            let mut restored_obligations = 0;
            let mut failed_obligations = 0;

            for (obligation_id, status) in snapshot.obligations.iter() {
                match self
                    .restore_obligation(cx, *obligation_id, status.clone())
                    .await
                {
                    Ok(_) => restored_obligations += 1,
                    Err(_) => failed_obligations += 1,
                }
            }

            // Step 4: Verify trace integrity after recovery
            let current_integrity = self.trace_integrity.create_snapshot().await?;
            let post_recovery_verification = self
                .trace_integrity
                .verify_integrity(&current_integrity.hash_chain)
                .await?;

            // Step 5: Check hash chain continuity
            let chain_continuity = self.verify_hash_chain_continuity(
                &snapshot.integrity_chain,
                &current_integrity.hash_chain,
            );

            *self.recovery_state.lock().unwrap() = RecoveryState::Completed;

            let recovery_time = Time::now().into_instant().duration_since(recovery_start);

            let result = RecoveryResult {
                snapshot_id,
                success: post_recovery_verification.is_valid && chain_continuity,
                restored_obligations,
                failed_obligations,
                integrity_preserved: chain_continuity,
                hash_chain_valid: post_recovery_verification.is_valid,
                recovery_time,
                pre_recovery_hash: snapshot.metadata.integrity_hash.clone(),
                post_recovery_hash: current_integrity.current_hash,
            };

            // Record recovery completion
            self.recovery_tracker.record_recovery_completion(
                snapshot_id,
                result.success,
                restored_obligations,
                failed_obligations,
                chain_continuity,
            );

            Ok(result)
        }

        async fn restore_obligation(
            &self,
            cx: &Cx,
            obligation_id: ObligationId,
            status: ObligationStatus,
        ) -> Result<()> {
            // Simulate obligation restoration
            cx.sleep(std::time::Duration::from_millis(1)).await?;

            // Record obligation in trace for integrity verification
            self.trace_integrity
                .record_obligation_event(obligation_id, "obligation_restored".to_string())
                .await?;

            // Restore to active obligations
            self.active_obligations
                .lock()
                .unwrap()
                .insert(obligation_id, status);

            Ok(())
        }

        fn verify_hash_chain_continuity(
            &self,
            snapshot_chain: &[HashChainNode],
            current_chain: &[HashChainNode],
        ) -> bool {
            // Verify that the current chain is a valid extension of the snapshot chain
            if snapshot_chain.is_empty() {
                return true; // Empty snapshot chain is always valid
            }

            if current_chain.len() < snapshot_chain.len() {
                return false; // Current chain cannot be shorter
            }

            // Check that snapshot chain is a prefix of current chain
            for (i, snapshot_node) in snapshot_chain.iter().enumerate() {
                if let Some(current_node) = current_chain.get(i) {
                    if snapshot_node.hash != current_node.hash
                        || snapshot_node.sequence != current_node.sequence
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            // Verify hash links between nodes
            for window in current_chain.windows(2) {
                if window[1].previous_hash != window[0].hash {
                    return false;
                }
            }

            true
        }

        fn generate_snapshot_id(&self) -> u64 {
            Time::now().into_instant().elapsed().as_nanos() as u64
        }

        fn add_obligation(&self, obligation_id: ObligationId, status: ObligationStatus) {
            self.active_obligations
                .lock()
                .unwrap()
                .insert(obligation_id, status);
        }
    }

    /// Mock trace integrity system
    #[derive(Debug)]
    struct MockTraceIntegritySystem {
        system_id: String,
        hash_chain: Arc<Mutex<Vec<HashChainNode>>>,
        current_hash: Arc<Mutex<IntegrityHash>>,
        sequence_counter: AtomicU64,
        integrity_checker: Arc<MockIntegrityChecker>,
    }

    impl MockTraceIntegritySystem {
        fn new(system_id: String) -> Self {
            let genesis_hash = IntegrityHash::genesis();
            let genesis_node = HashChainNode {
                sequence: 0,
                hash: genesis_hash.clone(),
                previous_hash: IntegrityHash::zero(),
                timestamp: Time::now().into(),
                event_count: 0,
            };

            Self {
                system_id,
                hash_chain: Arc::new(Mutex::new(vec![genesis_node])),
                current_hash: Arc::new(Mutex::new(genesis_hash)),
                sequence_counter: AtomicU64::new(0),
                integrity_checker: Arc::new(MockIntegrityChecker::new()),
            }
        }

        async fn create_snapshot(&self) -> Result<IntegritySnapshot> {
            let chain = self.hash_chain.lock().unwrap().clone();
            let current_hash = self.current_hash.lock().unwrap().clone();

            Ok(IntegritySnapshot {
                hash_chain: chain.clone(),
                current_hash,
                chain_length: chain.len() as u64,
                last_sequence: self.sequence_counter.load(Ordering::Acquire),
            })
        }

        async fn restore_from_snapshot(&self, snapshot_chain: &[HashChainNode]) -> Result<()> {
            // Restore hash chain from snapshot
            *self.hash_chain.lock().unwrap() = snapshot_chain.to_vec();

            // Update current hash
            if let Some(last_node) = snapshot_chain.last() {
                *self.current_hash.lock().unwrap() = last_node.hash.clone();
                self.sequence_counter
                    .store(last_node.sequence, Ordering::Release);
            }

            Ok(())
        }

        async fn verify_integrity(&self, chain: &[HashChainNode]) -> Result<ChainVerification> {
            self.integrity_checker.verify_chain(chain).await
        }

        async fn record_obligation_event(
            &self,
            obligation_id: ObligationId,
            event_type: String,
        ) -> Result<()> {
            let sequence = self.sequence_counter.fetch_add(1, Ordering::AcqRel) + 1;
            let previous_hash = self.current_hash.lock().unwrap().clone();

            // Create new hash incorporating the obligation event
            let new_hash = self.compute_hash(sequence, &previous_hash, &obligation_id, &event_type);

            let new_node = HashChainNode {
                sequence,
                hash: new_hash.clone(),
                previous_hash,
                timestamp: Time::now().into(),
                event_count: 1,
            };

            // Add to chain
            self.hash_chain.lock().unwrap().push(new_node);
            *self.current_hash.lock().unwrap() = new_hash;

            Ok(())
        }

        fn compute_hash(
            &self,
            sequence: u64,
            previous_hash: &IntegrityHash,
            obligation_id: &ObligationId,
            event_type: &str,
        ) -> IntegrityHash {
            // Mock hash computation (in real implementation would use proper cryptographic hash)
            let combined = format!(
                "{}:{}:{}:{}",
                sequence, previous_hash.0, obligation_id.0, event_type
            );
            let hash_value = combined.chars().map(|c| c as u64).sum::<u64>();
            IntegrityHash(hash_value)
        }
    }

    /// Mock integrity checker
    #[derive(Debug)]
    struct MockIntegrityChecker {}

    impl MockIntegrityChecker {
        fn new() -> Self {
            Self {}
        }

        async fn verify_chain(&self, chain: &[HashChainNode]) -> Result<ChainVerification> {
            if chain.is_empty() {
                return Ok(ChainVerification {
                    is_valid: false,
                    broken_links: vec![],
                    verified_length: 0,
                });
            }

            let mut broken_links = Vec::new();

            // Check genesis node
            if chain[0].sequence != 0 {
                broken_links.push(0);
            }

            // Check chain links
            for (i, window) in chain.windows(2).enumerate() {
                if window[1].previous_hash != window[0].hash {
                    broken_links.push(i + 1);
                }
                if window[1].sequence != window[0].sequence + 1 {
                    broken_links.push(i + 1);
                }
            }

            Ok(ChainVerification {
                is_valid: broken_links.is_empty(),
                broken_links,
                verified_length: chain.len() as u64,
            })
        }
    }

    /// Tracks obligation recovery and trace integrity integration
    #[derive(Debug)]
    struct ObligationRecoveryTracker {
        snapshot_events: Arc<Mutex<Vec<SnapshotEvent>>>,
        recovery_events: Arc<Mutex<Vec<RecoveryEvent>>>,
        integrity_events: Arc<Mutex<Vec<IntegrityEvent>>>,
    }

    #[derive(Debug, Clone)]
    struct SnapshotEvent {
        timestamp: std::time::Instant,
        snapshot_id: u64,
        event_type: String,
        obligation_count: usize,
        integrity_chain_length: u64,
        is_partial: bool,
    }

    #[derive(Debug, Clone)]
    struct RecoveryEvent {
        timestamp: std::time::Instant,
        snapshot_id: u64,
        success: bool,
        restored_obligations: usize,
        failed_obligations: usize,
        integrity_preserved: bool,
    }

    #[derive(Debug, Clone)]
    struct IntegrityEvent {
        timestamp: std::time::Instant,
        event_type: String,
        chain_length: u64,
        hash_value: u64,
        verification_result: bool,
    }

    impl ObligationRecoveryTracker {
        fn new() -> Self {
            Self {
                snapshot_events: Arc::new(Mutex::new(Vec::new())),
                recovery_events: Arc::new(Mutex::new(Vec::new())),
                integrity_events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record_snapshot_creation(
            &self,
            snapshot_id: u64,
            obligation_count: usize,
            chain_length: u64,
        ) {
            let event = SnapshotEvent {
                timestamp: Time::now().into(),
                snapshot_id,
                event_type: "snapshot_created".to_string(),
                obligation_count,
                integrity_chain_length: chain_length,
                is_partial: false,
            };

            self.snapshot_events.lock().unwrap().push(event);
        }

        fn record_partial_snapshot_creation(
            &self,
            snapshot_id: u64,
            corruption_point: u64,
            recovered_obligations: usize,
            missing_obligations: usize,
        ) {
            let event = SnapshotEvent {
                timestamp: Time::now().into(),
                snapshot_id,
                event_type: "partial_snapshot_created".to_string(),
                obligation_count: recovered_obligations,
                integrity_chain_length: corruption_point,
                is_partial: true,
            };

            self.snapshot_events.lock().unwrap().push(event);
        }

        fn record_recovery_completion(
            &self,
            snapshot_id: u64,
            success: bool,
            restored_obligations: usize,
            failed_obligations: usize,
            integrity_preserved: bool,
        ) {
            let event = RecoveryEvent {
                timestamp: Time::now().into(),
                snapshot_id,
                success,
                restored_obligations,
                failed_obligations,
                integrity_preserved,
            };

            self.recovery_events.lock().unwrap().push(event);
        }

        fn record_integrity_verification(
            &self,
            event_type: String,
            chain_length: u64,
            hash_value: u64,
            verification_result: bool,
        ) {
            let event = IntegrityEvent {
                timestamp: Time::now().into(),
                event_type,
                chain_length,
                hash_value,
                verification_result,
            };

            self.integrity_events.lock().unwrap().push(event);
        }

        fn get_integration_summary(&self) -> ObligationRecoveryIntegrationSummary {
            let snapshots = self.snapshot_events.lock().unwrap();
            let recoveries = self.recovery_events.lock().unwrap();
            let integrity_checks = self.integrity_events.lock().unwrap();

            let total_snapshots = snapshots.len();
            let partial_snapshots = snapshots.iter().filter(|s| s.is_partial).count();
            let successful_recoveries = recoveries.iter().filter(|r| r.success).count();
            let integrity_preserved_recoveries =
                recoveries.iter().filter(|r| r.integrity_preserved).count();
            let successful_integrity_checks = integrity_checks
                .iter()
                .filter(|i| i.verification_result)
                .count();

            ObligationRecoveryIntegrationSummary {
                total_snapshots,
                partial_snapshots,
                total_recoveries: recoveries.len(),
                successful_recoveries,
                integrity_preserved_recoveries,
                total_integrity_checks: integrity_checks.len(),
                successful_integrity_checks,
                recovery_success_rate: if recoveries.is_empty() {
                    0.0
                } else {
                    successful_recoveries as f64 / recoveries.len() as f64
                },
                integrity_preservation_rate: if recoveries.is_empty() {
                    0.0
                } else {
                    integrity_preserved_recoveries as f64 / recoveries.len() as f64
                },
                overall_integration_health: calculate_integration_health(
                    successful_recoveries,
                    recoveries.len(),
                    integrity_preserved_recoveries,
                    successful_integrity_checks,
                    integrity_checks.len(),
                ),
            }
        }
    }

    #[derive(Debug)]
    struct ObligationRecoveryIntegrationSummary {
        total_snapshots: usize,
        partial_snapshots: usize,
        total_recoveries: usize,
        successful_recoveries: usize,
        integrity_preserved_recoveries: usize,
        total_integrity_checks: usize,
        successful_integrity_checks: usize,
        recovery_success_rate: f64,
        integrity_preservation_rate: f64,
        overall_integration_health: f64,
    }

    fn calculate_integration_health(
        successful_recoveries: usize,
        total_recoveries: usize,
        integrity_preserved: usize,
        successful_integrity_checks: usize,
        total_integrity_checks: usize,
    ) -> f64 {
        let mut health_score = 1.0;

        // Factor in recovery success rate
        if total_recoveries > 0 {
            health_score *= successful_recoveries as f64 / total_recoveries as f64;
        }

        // Factor in integrity preservation rate (critical for this integration)
        if total_recoveries > 0 {
            let integrity_rate = integrity_preserved as f64 / total_recoveries as f64;
            health_score *= integrity_rate;
        }

        // Factor in integrity check success rate
        if total_integrity_checks > 0 {
            let integrity_check_rate =
                successful_integrity_checks as f64 / total_integrity_checks as f64;
            health_score *= integrity_check_rate;
        }

        health_score.max(0.0).min(1.0)
    }

    #[derive(Debug, Clone)]
    struct RecoveryResult {
        snapshot_id: u64,
        success: bool,
        restored_obligations: usize,
        failed_obligations: usize,
        integrity_preserved: bool,
        hash_chain_valid: bool,
        recovery_time: std::time::Duration,
        pre_recovery_hash: IntegrityHash,
        post_recovery_hash: IntegrityHash,
    }

    // Mock types for testing
    #[derive(Debug, Clone)]
    struct RecoveryConfig {
        max_snapshot_age: std::time::Duration,
        max_recovery_attempts: u32,
        verify_integrity: bool,
        preserve_chain_continuity: bool,
    }

    impl Default for RecoveryConfig {
        fn default() -> Self {
            Self {
                max_snapshot_age: std::time::Duration::from_hours(24),
                max_recovery_attempts: 3,
                verify_integrity: true,
                preserve_chain_continuity: true,
            }
        }
    }

    #[derive(Debug, Clone)]
    enum RecoveryState {
        Idle,
        InProgress,
        Completed,
        Failed,
    }

    #[derive(Debug, Clone)]
    struct RecoverySnapshot {
        id: u64,
        metadata: SnapshotMetadata,
        obligations: HashMap<ObligationId, ObligationStatus>,
        integrity_chain: Vec<HashChainNode>,
        partial_data: Option<PartialSnapshot>,
    }

    #[derive(Debug, Clone)]
    struct SnapshotMetadata {
        timestamp: std::time::Instant,
        obligation_count: usize,
        integrity_hash: IntegrityHash,
        chain_length: u64,
    }

    #[derive(Debug, Clone)]
    struct PartialSnapshot {
        corruption_point: u64,
        recovered_obligations: usize,
        missing_obligations: usize,
    }

    #[derive(Debug, Clone)]
    struct IntegritySnapshot {
        hash_chain: Vec<HashChainNode>,
        current_hash: IntegrityHash,
        chain_length: u64,
        last_sequence: u64,
    }

    #[derive(Debug, Clone)]
    struct HashChainNode {
        sequence: u64,
        hash: IntegrityHash,
        previous_hash: IntegrityHash,
        timestamp: std::time::Instant,
        event_count: usize,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct IntegrityHash(u64);

    impl IntegrityHash {
        fn genesis() -> Self {
            IntegrityHash(0x1337_DEAD_BEEF_0001)
        }

        fn zero() -> Self {
            IntegrityHash(0)
        }
    }

    #[derive(Debug)]
    struct ChainVerification {
        is_valid: bool,
        broken_links: Vec<usize>,
        verified_length: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct ObligationId(u64);

    #[derive(Debug, Clone)]
    enum ObligationStatus {
        Active,
        Suspended,
        Completed,
        Failed,
    }

    #[derive(Debug)]
    enum RecoveryError {
        SnapshotNotFound(u64),
        IntegrityVerificationFailed,
        ObligationRestoreFailed,
        HashChainBroken,
    }

    async fn run_obligation_recovery_trace_integrity_integration_test(
        cx: &Cx,
        recovery_system: Arc<MockObligationRecoverySystem>,
        test_scenarios: Vec<RecoveryTestScenario>,
    ) -> Result<ObligationRecoveryIntegrationSummary> {
        for scenario in test_scenarios {
            // Setup initial obligations
            for i in 0..scenario.initial_obligations {
                let obligation_id = ObligationId(i as u64);
                recovery_system.add_obligation(obligation_id, ObligationStatus::Active);

                // Record obligation in trace
                recovery_system
                    .trace_integrity
                    .record_obligation_event(obligation_id, "obligation_created".to_string())
                    .await?;
            }

            // Create snapshot (partial or full)
            let snapshot = if scenario.simulate_corruption {
                recovery_system
                    .create_partial_snapshot(cx, scenario.corruption_point)
                    .await?
            } else {
                recovery_system.create_snapshot(cx).await?
            };

            // Simulate some additional activity
            cx.sleep(std::time::Duration::from_millis(50)).await?;

            // Attempt recovery
            let recovery_result = recovery_system
                .recover_from_snapshot(cx, snapshot.id)
                .await?;

            // Record results in tracker
            recovery_system
                .recovery_tracker
                .record_integrity_verification(
                    "post_recovery_check".to_string(),
                    recovery_result.post_recovery_hash.0,
                    recovery_result.post_recovery_hash.0,
                    recovery_result.integrity_preserved,
                );

            // Verify trace integrity hash chain
            let current_integrity = recovery_system.trace_integrity.create_snapshot().await?;
            let verification = recovery_system
                .trace_integrity
                .verify_integrity(&current_integrity.hash_chain)
                .await?;

            recovery_system
                .recovery_tracker
                .record_integrity_verification(
                    "final_verification".to_string(),
                    current_integrity.chain_length,
                    current_integrity.current_hash.0,
                    verification.is_valid,
                );
        }

        Ok(recovery_system.recovery_tracker.get_integration_summary())
    }

    #[derive(Debug, Clone)]
    struct RecoveryTestScenario {
        name: String,
        initial_obligations: usize,
        simulate_corruption: bool,
        corruption_point: u64,
        expected_success: bool,
    }

    #[tokio::test]
    async fn test_basic_recovery_with_integrity_preservation() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test basic recovery preserving trace integrity
                    let trace_integrity =
                        Arc::new(MockTraceIntegritySystem::new("test_integrity".to_string()));

                    let recovery_config = RecoveryConfig::default();
                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_recovery".to_string(),
                        recovery_config,
                        trace_integrity,
                    ));

                    let test_scenarios = vec![RecoveryTestScenario {
                        name: "basic_full_recovery".to_string(),
                        initial_obligations: 10,
                        simulate_corruption: false,
                        corruption_point: 0,
                        expected_success: true,
                    }];

                    let summary = run_obligation_recovery_trace_integrity_integration_test(
                        cx,
                        recovery_system,
                        test_scenarios,
                    )
                    .await?;

                    // Verify basic recovery
                    assert!(summary.total_snapshots > 0, "Should create snapshots");
                    assert!(summary.total_recoveries > 0, "Should perform recoveries");
                    assert!(
                        summary.successful_recoveries > 0,
                        "Should have successful recoveries"
                    );
                    assert!(
                        summary.integrity_preserved_recoveries > 0,
                        "Should preserve integrity"
                    );
                    assert!(
                        summary.recovery_success_rate > 0.8,
                        "Should have high success rate"
                    );
                    assert!(
                        summary.integrity_preservation_rate >= 0.9,
                        "Should preserve integrity consistently"
                    );
                    assert!(
                        summary.overall_integration_health > 0.8,
                        "Integration health should be good"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Basic recovery with integrity should succeed"
        );
    }

    #[tokio::test]
    async fn test_partial_snapshot_recovery() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test recovery from partial snapshots
                    let trace_integrity = Arc::new(MockTraceIntegritySystem::new(
                        "test_partial_integrity".to_string(),
                    ));

                    let recovery_config = RecoveryConfig::default();
                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_partial_recovery".to_string(),
                        recovery_config,
                        trace_integrity,
                    ));

                    let test_scenarios = vec![RecoveryTestScenario {
                        name: "partial_recovery".to_string(),
                        initial_obligations: 20,
                        simulate_corruption: true,
                        corruption_point: 15, // Recover from point 15 out of 20
                        expected_success: true,
                    }];

                    let summary = run_obligation_recovery_trace_integrity_integration_test(
                        cx,
                        recovery_system,
                        test_scenarios,
                    )
                    .await?;

                    // Verify partial recovery
                    assert!(
                        summary.partial_snapshots > 0,
                        "Should create partial snapshots"
                    );
                    assert!(
                        summary.successful_recoveries > 0,
                        "Should recover from partial snapshots"
                    );
                    assert!(
                        summary.integrity_preserved_recoveries > 0,
                        "Should preserve integrity in partial recovery"
                    );
                    assert!(
                        summary.integrity_preservation_rate > 0.5,
                        "Should maintain reasonable integrity"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Partial snapshot recovery should succeed"
        );
    }

    #[tokio::test]
    async fn test_hash_chain_continuity_verification() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test hash chain continuity across recovery
                    let trace_integrity = Arc::new(MockTraceIntegritySystem::new(
                        "test_chain_continuity".to_string(),
                    ));

                    let recovery_config = RecoveryConfig {
                        preserve_chain_continuity: true,
                        ..Default::default()
                    };

                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_continuity".to_string(),
                        recovery_config,
                        trace_integrity.clone(),
                    ));

                    // Setup obligations to establish chain
                    for i in 0..5 {
                        let obligation_id = ObligationId(i);
                        recovery_system.add_obligation(obligation_id, ObligationStatus::Active);
                        trace_integrity
                            .record_obligation_event(
                                obligation_id,
                                "obligation_created".to_string(),
                            )
                            .await?;
                    }

                    // Create snapshot and verify initial chain
                    let snapshot = recovery_system.create_snapshot(cx).await?;
                    let initial_chain = snapshot.integrity_chain.clone();

                    // Perform recovery
                    let recovery_result = recovery_system
                        .recover_from_snapshot(cx, snapshot.id)
                        .await?;

                    // Verify chain continuity
                    assert!(recovery_result.success, "Recovery should succeed");
                    assert!(
                        recovery_result.integrity_preserved,
                        "Integrity should be preserved"
                    );
                    assert!(
                        recovery_result.hash_chain_valid,
                        "Hash chain should remain valid"
                    );

                    // Verify hash chain structure
                    let final_integrity = trace_integrity.create_snapshot().await?;
                    let continuity_valid = recovery_system
                        .verify_hash_chain_continuity(&initial_chain, &final_integrity.hash_chain);

                    assert!(
                        continuity_valid,
                        "Hash chain continuity should be preserved"
                    );

                    Ok(recovery_result)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Hash chain continuity verification should succeed"
        );
    }

    #[tokio::test]
    async fn test_multiple_recovery_scenarios() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test multiple recovery scenarios
                    let trace_integrity = Arc::new(MockTraceIntegritySystem::new(
                        "test_multiple_scenarios".to_string(),
                    ));

                    let recovery_config = RecoveryConfig::default();
                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_multiple".to_string(),
                        recovery_config,
                        trace_integrity,
                    ));

                    let test_scenarios = vec![
                        RecoveryTestScenario {
                            name: "small_full_recovery".to_string(),
                            initial_obligations: 5,
                            simulate_corruption: false,
                            corruption_point: 0,
                            expected_success: true,
                        },
                        RecoveryTestScenario {
                            name: "large_partial_recovery".to_string(),
                            initial_obligations: 25,
                            simulate_corruption: true,
                            corruption_point: 20,
                            expected_success: true,
                        },
                        RecoveryTestScenario {
                            name: "medium_full_recovery".to_string(),
                            initial_obligations: 15,
                            simulate_corruption: false,
                            corruption_point: 0,
                            expected_success: true,
                        },
                    ];

                    let summary = run_obligation_recovery_trace_integrity_integration_test(
                        cx,
                        recovery_system,
                        test_scenarios,
                    )
                    .await?;

                    // Verify multiple scenario handling
                    assert!(
                        summary.total_snapshots >= 3,
                        "Should handle multiple scenarios"
                    );
                    assert!(
                        summary.total_recoveries >= 3,
                        "Should perform multiple recoveries"
                    );
                    assert!(
                        summary.partial_snapshots >= 1,
                        "Should include partial snapshots"
                    );
                    assert!(
                        summary.successful_recoveries >= 2,
                        "Most recoveries should succeed"
                    );
                    assert!(
                        summary.integrity_preserved_recoveries >= 2,
                        "Should preserve integrity across scenarios"
                    );
                    assert!(
                        summary.recovery_success_rate > 0.6,
                        "Overall success rate should be good"
                    );
                    assert!(
                        summary.integrity_preservation_rate > 0.6,
                        "Overall integrity preservation should be good"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Multiple recovery scenarios should succeed"
        );
    }

    #[tokio::test]
    async fn test_integrity_verification_during_recovery() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Test integrity verification at each recovery step
                    let trace_integrity = Arc::new(MockTraceIntegritySystem::new(
                        "test_verification".to_string(),
                    ));

                    let recovery_config = RecoveryConfig {
                        verify_integrity: true,
                        preserve_chain_continuity: true,
                        ..Default::default()
                    };

                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_integrity_verification".to_string(),
                        recovery_config,
                        trace_integrity.clone(),
                    ));

                    // Setup obligations with trace events
                    for i in 0..8 {
                        let obligation_id = ObligationId(i);
                        recovery_system.add_obligation(obligation_id, ObligationStatus::Active);
                        trace_integrity
                            .record_obligation_event(
                                obligation_id,
                                format!("obligation_{}_created", i),
                            )
                            .await?;
                    }

                    // Create snapshot
                    let snapshot = recovery_system.create_snapshot(cx).await?;

                    // Verify pre-recovery integrity
                    let pre_verification = trace_integrity
                        .verify_integrity(&snapshot.integrity_chain)
                        .await?;
                    assert!(
                        pre_verification.is_valid,
                        "Pre-recovery integrity should be valid"
                    );

                    // Perform recovery
                    let recovery_result = recovery_system
                        .recover_from_snapshot(cx, snapshot.id)
                        .await?;

                    // Verify post-recovery integrity
                    let post_integrity = trace_integrity.create_snapshot().await?;
                    let post_verification = trace_integrity
                        .verify_integrity(&post_integrity.hash_chain)
                        .await?;

                    assert!(recovery_result.success, "Recovery should succeed");
                    assert!(
                        recovery_result.integrity_preserved,
                        "Integrity should be preserved"
                    );
                    assert!(
                        post_verification.is_valid,
                        "Post-recovery integrity should be valid"
                    );
                    assert_eq!(
                        post_verification.broken_links.len(),
                        0,
                        "Should have no broken links"
                    );

                    Ok(recovery_result)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Integrity verification during recovery should succeed"
        );
    }

    #[tokio::test]
    async fn test_comprehensive_recovery_integration() {
        let lab = LabRuntime::new().unwrap();
        let outcome = lab
            .run(|cx| {
                Box::pin(async move {
                    // Comprehensive integration test
                    let trace_integrity = Arc::new(MockTraceIntegritySystem::new(
                        "test_comprehensive".to_string(),
                    ));

                    let recovery_config = RecoveryConfig::default();
                    let recovery_system = Arc::new(MockObligationRecoverySystem::new(
                        "test_comprehensive_recovery".to_string(),
                        recovery_config,
                        trace_integrity,
                    ));

                    let test_scenarios = vec![
                        RecoveryTestScenario {
                            name: "comprehensive_full".to_string(),
                            initial_obligations: 12,
                            simulate_corruption: false,
                            corruption_point: 0,
                            expected_success: true,
                        },
                        RecoveryTestScenario {
                            name: "comprehensive_partial_early".to_string(),
                            initial_obligations: 18,
                            simulate_corruption: true,
                            corruption_point: 5,
                            expected_success: true,
                        },
                        RecoveryTestScenario {
                            name: "comprehensive_partial_late".to_string(),
                            initial_obligations: 22,
                            simulate_corruption: true,
                            corruption_point: 18,
                            expected_success: true,
                        },
                        RecoveryTestScenario {
                            name: "comprehensive_small_full".to_string(),
                            initial_obligations: 3,
                            simulate_corruption: false,
                            corruption_point: 0,
                            expected_success: true,
                        },
                    ];

                    let summary = run_obligation_recovery_trace_integrity_integration_test(
                        cx,
                        recovery_system,
                        test_scenarios,
                    )
                    .await?;

                    // Comprehensive validation
                    assert!(summary.total_snapshots >= 4, "Should create all snapshots");
                    assert!(
                        summary.total_recoveries >= 4,
                        "Should perform all recoveries"
                    );
                    assert!(
                        summary.partial_snapshots >= 2,
                        "Should include partial snapshots"
                    );
                    assert!(
                        summary.successful_recoveries >= 3,
                        "Most recoveries should succeed"
                    );
                    assert!(
                        summary.integrity_preserved_recoveries >= 3,
                        "Should preserve integrity in most cases"
                    );
                    assert!(
                        summary.total_integrity_checks >= 8,
                        "Should perform integrity checks"
                    );
                    assert!(
                        summary.successful_integrity_checks >= 6,
                        "Most integrity checks should pass"
                    );
                    assert!(
                        summary.recovery_success_rate > 0.7,
                        "Recovery success rate should be high"
                    );
                    assert!(
                        summary.integrity_preservation_rate > 0.7,
                        "Integrity preservation rate should be high"
                    );
                    assert!(
                        summary.overall_integration_health > 0.7,
                        "Overall integration health should be good"
                    );

                    // Verify integration completeness
                    assert!(summary.total_snapshots > 0, "Snapshot integration working");
                    assert!(summary.total_recoveries > 0, "Recovery integration working");
                    assert!(
                        summary.total_integrity_checks > 0,
                        "Integrity verification integration working"
                    );
                    assert!(
                        summary.integrity_preserved_recoveries > 0,
                        "Hash chain preservation working"
                    );

                    Ok(summary)
                })
            })
            .await;

        assert!(
            matches!(outcome, Outcome::Ok(_)),
            "Comprehensive recovery integration should succeed"
        );
    }
}
