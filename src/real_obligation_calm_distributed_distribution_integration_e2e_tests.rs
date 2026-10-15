//! Integration tests for obligation/calm ↔ distributed/distribution integration.
//!
//! These tests verify that CALM-conformant distribution operations preserve
//! idempotence across replica divergence and reconciliation scenarios, ensuring
//! consistency in distributed obligation processing.
//!
//! Key integration points tested:
//! - CALM operations maintaining idempotence across distributed replicas
//! - Replica divergence with eventual reconciliation convergence
//! - Complex distribution patterns with multi-node coordination
//! - Concurrent operations on diverged replicas with conflict resolution
//! - Stress testing under high divergence and reconciliation load
//! - Edge cases: network partitions, partial failures, split-brain scenarios

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::cx::Cx;
    use crate::distributed::consistency::{
        ConflictResolution, ConsistencyModel, EventualConsistency,
    };
    use crate::distributed::distribution::{
        DistributionManager, ReconciliationEngine, ReplicaId, ReplicaState,
    };
    use crate::error::AsupersyncError;
    use crate::obligation::calm::{CalmContext, CalmOperation, IdempotentOp, MonotonicState};
    use crate::obligation::{ObligationId, ObligationLedger, ObligationRecord, ObligationStatus};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::types::{Budget, Outcome, TaskId};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant};

    /// Test harness for CALM-distributed distribution integration testing.
    struct CalmDistributionTestHarness {
        runtime: Arc<Runtime>,
        distribution_manager: Arc<DistributionManager>,
        replicas: HashMap<ReplicaId, Arc<CalmReplica>>,
        reconciliation_engine: Arc<ReconciliationEngine>,
        calm_contexts: HashMap<ReplicaId, Arc<CalmContext>>,
        network_simulator: Arc<NetworkSimulator>,
        stats: Arc<Mutex<CalmDistributionStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct CalmDistributionStats {
        /// Total replicas created
        replicas_created: u64,
        /// CALM operations executed
        calm_operations_executed: u64,
        /// Replica divergence events
        divergence_events: u64,
        /// Reconciliation rounds completed
        reconciliation_rounds: u64,
        /// Idempotence violations detected
        idempotence_violations: u64,
        /// Successful convergence events
        successful_convergence: u64,
        /// Network partition events
        network_partitions: u64,
        /// Conflict resolution operations
        conflict_resolutions: u64,
        /// Total reconciliation time
        total_reconciliation_time: Duration,
    }

    /// Simulated replica with CALM-conformant operations
    struct CalmReplica {
        id: ReplicaId,
        state: Arc<Mutex<MonotonicState>>,
        obligation_ledger: Arc<ObligationLedger>,
        operation_log: Arc<Mutex<Vec<CalmOperation>>>,
        last_reconciliation: Arc<Mutex<Instant>>,
        network_partition_status: Arc<AtomicBool>,
        stats: Arc<Mutex<CalmDistributionStats>>,
    }

    impl CalmReplica {
        fn new(id: ReplicaId, stats: Arc<Mutex<CalmDistributionStats>>) -> Self {
            Self {
                id,
                state: Arc::new(Mutex::new(MonotonicState::new())),
                obligation_ledger: Arc::new(ObligationLedger::new().unwrap()),
                operation_log: Arc::new(Mutex::new(Vec::new())),
                last_reconciliation: Arc::new(Mutex::new(Instant::now())),
                network_partition_status: Arc::new(AtomicBool::new(false)),
                stats,
            }
        }

        async fn apply_calm_operation(
            &self,
            cx: &Cx,
            operation: CalmOperation,
        ) -> Result<(), AsupersyncError> {
            // CALM operations are idempotent and monotonic
            let mut state = self.state.lock().unwrap();
            let mut log = self.operation_log.lock().unwrap();

            // Check if operation was already applied (idempotence)
            if log.iter().any(|op| op.id() == operation.id()) {
                return Ok(()); // Already applied, idempotent
            }

            // Apply operation monotonically
            state.apply_monotonic_update(&operation)?;
            log.push(operation.clone());

            {
                let mut stats = self.stats.lock().unwrap();
                stats.calm_operations_executed += 1;
            }

            // Update obligation if applicable
            if let Some(obligation_id) = operation.obligation_id() {
                let record = ObligationRecord::new(
                    obligation_id,
                    format!("replica-{}", self.id),
                    ObligationStatus::from_calm_operation(&operation),
                );
                self.obligation_ledger.update_record(record).await?;
            }

            Ok(())
        }

        async fn reconcile_with(
            &self,
            cx: &Cx,
            other: &CalmReplica,
        ) -> Result<ReconciliationResult, AsupersyncError> {
            if self.network_partition_status.load(Ordering::Acquire) {
                return Err(AsupersyncError::NetworkPartition);
            }

            let reconcile_start = Instant::now();
            let mut conflicts_resolved = 0;
            let mut operations_merged = 0;

            // Get operation logs from both replicas
            let self_ops = self.operation_log.lock().unwrap().clone();
            let other_ops = other.operation_log.lock().unwrap().clone();

            // Find operations in other that are not in self
            let self_op_ids: HashSet<_> = self_ops.iter().map(|op| op.id()).collect();
            let missing_ops: Vec<_> = other_ops
                .into_iter()
                .filter(|op| !self_op_ids.contains(&op.id()))
                .collect();

            // Apply missing operations (CALM guarantees this is safe)
            for op in missing_ops {
                match self.apply_calm_operation(cx, op).await {
                    Ok(_) => operations_merged += 1,
                    Err(_) => conflicts_resolved += 1,
                }
            }

            // Update reconciliation timestamp
            *self.last_reconciliation.lock().unwrap() = Instant::now();

            let reconcile_duration = reconcile_start.elapsed();
            {
                let mut stats = self.stats.lock().unwrap();
                stats.reconciliation_rounds += 1;
                stats.total_reconciliation_time += reconcile_duration;
                stats.conflict_resolutions += conflicts_resolved;
                if operations_merged > 0 {
                    stats.successful_convergence += 1;
                }
            }

            Ok(ReconciliationResult {
                operations_merged,
                conflicts_resolved,
                duration: reconcile_duration,
                converged: self.check_convergence_with(other),
            })
        }

        fn check_convergence_with(&self, other: &CalmReplica) -> bool {
            let self_state = self.state.lock().unwrap();
            let other_state = other.state.lock().unwrap();
            self_state.is_equivalent(&*other_state)
        }

        fn simulate_network_partition(&self, partitioned: bool) {
            self.network_partition_status
                .store(partitioned, Ordering::Release);
            if partitioned {
                let mut stats = self.stats.lock().unwrap();
                stats.network_partitions += 1;
            }
        }

        fn get_operation_count(&self) -> usize {
            self.operation_log.lock().unwrap().len()
        }

        fn check_idempotence(&self) -> Result<(), IdempotenceViolation> {
            let ops = self.operation_log.lock().unwrap();
            let mut seen_ops = HashSet::new();

            for op in ops.iter() {
                if seen_ops.contains(&op.id()) {
                    return Err(IdempotenceViolation::DuplicateOperation(op.id()));
                }
                seen_ops.insert(op.id());
            }

            // Check monotonicity in state
            let state = self.state.lock().unwrap();
            if !state.is_monotonic() {
                return Err(IdempotenceViolation::NonMonotonicState);
            }

            Ok(())
        }
    }

    #[derive(Debug)]
    struct ReconciliationResult {
        operations_merged: usize,
        conflicts_resolved: usize,
        duration: Duration,
        converged: bool,
    }

    #[derive(Debug)]
    enum IdempotenceViolation {
        DuplicateOperation(u64),
        NonMonotonicState,
    }

    /// Network simulator for partition and latency testing
    struct NetworkSimulator {
        partitions: Arc<Mutex<HashMap<(ReplicaId, ReplicaId), bool>>>,
        latency_map: Arc<Mutex<HashMap<(ReplicaId, ReplicaId), Duration>>>,
    }

    impl NetworkSimulator {
        fn new() -> Self {
            Self {
                partitions: Arc::new(Mutex::new(HashMap::new())),
                latency_map: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn create_partition(&self, replica_a: ReplicaId, replica_b: ReplicaId) {
            let mut partitions = self.partitions.lock().unwrap();
            partitions.insert((replica_a, replica_b), true);
            partitions.insert((replica_b, replica_a), true);
        }

        fn heal_partition(&self, replica_a: ReplicaId, replica_b: ReplicaId) {
            let mut partitions = self.partitions.lock().unwrap();
            partitions.remove(&(replica_a, replica_b));
            partitions.remove(&(replica_b, replica_a));
        }

        fn set_latency(&self, replica_a: ReplicaId, replica_b: ReplicaId, latency: Duration) {
            let mut latency_map = self.latency_map.lock().unwrap();
            latency_map.insert((replica_a, replica_b), latency);
            latency_map.insert((replica_b, replica_a), latency);
        }

        fn is_partitioned(&self, replica_a: ReplicaId, replica_b: ReplicaId) -> bool {
            let partitions = self.partitions.lock().unwrap();
            partitions
                .get(&(replica_a, replica_b))
                .copied()
                .unwrap_or(false)
        }

        async fn simulate_network_delay(
            &self,
            cx: &Cx,
            replica_a: ReplicaId,
            replica_b: ReplicaId,
        ) {
            let latency = {
                let latency_map = self.latency_map.lock().unwrap();
                latency_map
                    .get(&(replica_a, replica_b))
                    .copied()
                    .unwrap_or(Duration::ZERO)
            };

            if latency > Duration::ZERO {
                cx.sleep(latency).await;
            }
        }
    }

    impl CalmDistributionTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let runtime = Arc::new(
                RuntimeBuilder::new()
                    .with_distributed_processing()
                    .with_obligation_tracking()
                    .build()?,
            );

            let distribution_manager = Arc::new(DistributionManager::new()?);
            let reconciliation_engine = Arc::new(ReconciliationEngine::new()?);
            let network_simulator = Arc::new(NetworkSimulator::new());

            Ok(Self {
                runtime,
                distribution_manager,
                replicas: HashMap::new(),
                reconciliation_engine,
                calm_contexts: HashMap::new(),
                network_simulator,
                stats: Arc::new(Mutex::new(CalmDistributionStats::default())),
            })
        }

        fn create_replica(&mut self, replica_id: ReplicaId) -> Arc<CalmReplica> {
            let replica = Arc::new(CalmReplica::new(replica_id, self.stats.clone()));
            self.replicas.insert(replica_id, replica.clone());

            let calm_context = Arc::new(CalmContext::new(replica_id));
            self.calm_contexts.insert(replica_id, calm_context);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.replicas_created += 1;
            }

            replica
        }

        async fn apply_operation_to_replica(
            &self,
            cx: &Cx,
            replica_id: ReplicaId,
            operation: CalmOperation,
        ) -> Result<(), AsupersyncError> {
            let replica = self
                .replicas
                .get(&replica_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Replica not found".into()))?;

            replica.apply_calm_operation(cx, operation).await
        }

        async fn reconcile_replicas(
            &self,
            cx: &Cx,
            replica_a: ReplicaId,
            replica_b: ReplicaId,
        ) -> Result<ReconciliationResult, AsupersyncError> {
            if self.network_simulator.is_partitioned(replica_a, replica_b) {
                return Err(AsupersyncError::NetworkPartition);
            }

            // Simulate network latency
            self.network_simulator
                .simulate_network_delay(cx, replica_a, replica_b)
                .await;

            let replica_a_ref = self
                .replicas
                .get(&replica_a)
                .ok_or_else(|| AsupersyncError::InvalidState("Replica A not found".into()))?;
            let replica_b_ref = self
                .replicas
                .get(&replica_b)
                .ok_or_else(|| AsupersyncError::InvalidState("Replica B not found".into()))?;

            replica_a_ref.reconcile_with(cx, replica_b_ref).await
        }

        async fn full_reconciliation_round(
            &self,
            cx: &Cx,
        ) -> Result<HashMap<(ReplicaId, ReplicaId), ReconciliationResult>, AsupersyncError>
        {
            let replica_ids: Vec<_> = self.replicas.keys().copied().collect();
            let mut results = HashMap::new();

            // Reconcile all pairs of replicas
            for i in 0..replica_ids.len() {
                for j in (i + 1)..replica_ids.len() {
                    let replica_a = replica_ids[i];
                    let replica_b = replica_ids[j];

                    if !self.network_simulator.is_partitioned(replica_a, replica_b) {
                        let result = self.reconcile_replicas(cx, replica_a, replica_b).await?;
                        results.insert((replica_a, replica_b), result);
                    }
                }
            }

            Ok(results)
        }

        fn create_network_partition(&self, replica_a: ReplicaId, replica_b: ReplicaId) {
            self.network_simulator
                .create_partition(replica_a, replica_b);
            if let Some(replica_a_ref) = self.replicas.get(&replica_a) {
                replica_a_ref.simulate_network_partition(true);
            }
            if let Some(replica_b_ref) = self.replicas.get(&replica_b) {
                replica_b_ref.simulate_network_partition(true);
            }
        }

        fn heal_network_partition(&self, replica_a: ReplicaId, replica_b: ReplicaId) {
            self.network_simulator.heal_partition(replica_a, replica_b);
            if let Some(replica_a_ref) = self.replicas.get(&replica_a) {
                replica_a_ref.simulate_network_partition(false);
            }
            if let Some(replica_b_ref) = self.replicas.get(&replica_b) {
                replica_b_ref.simulate_network_partition(false);
            }
        }

        fn check_global_convergence(&self) -> bool {
            let replica_refs: Vec<_> = self.replicas.values().collect();

            // Check that all replicas have converged with each other
            for i in 0..replica_refs.len() {
                for j in (i + 1)..replica_refs.len() {
                    if !replica_refs[i].check_convergence_with(replica_refs[j]) {
                        return false;
                    }
                }
            }

            true
        }

        fn check_idempotence_across_replicas(
            &self,
        ) -> Result<(), Vec<(ReplicaId, IdempotenceViolation)>> {
            let mut violations = Vec::new();

            for (replica_id, replica) in &self.replicas {
                if let Err(violation) = replica.check_idempotence() {
                    violations.push(*replica_id, violation);
                }
            }

            if violations.is_empty() {
                Ok(())
            } else {
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.idempotence_violations += violations.len() as u64;
                }
                Err(violations)
            }
        }

        fn get_stats(&self) -> CalmDistributionStats {
            self.stats.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn test_basic_calm_operations_preserve_idempotence() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create two replicas
                let replica_a = harness.create_replica(ReplicaId::new(1));
                let replica_b = harness.create_replica(ReplicaId::new(2));

                // Create CALM operations
                let operations = vec![
                    CalmOperation::new(1, "increment_counter", Some(ObligationId::new())),
                    CalmOperation::new(2, "add_element", Some(ObligationId::new())),
                    CalmOperation::new(3, "set_flag", None),
                ];

                // Apply operations to both replicas
                for operation in operations {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(1), operation.clone())
                        .await?;
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(2), operation)
                        .await?;
                }

                // Check idempotence
                harness
                    .check_idempotence_across_replicas()
                    .expect("Should maintain idempotence");

                // Verify both replicas have same operation count
                assert_eq!(replica_a.get_operation_count(), 3);
                assert_eq!(replica_b.get_operation_count(), 3);

                // Verify convergence
                assert!(
                    replica_a.check_convergence_with(&replica_b),
                    "Replicas should converge"
                );

                let stats = harness.get_stats();
                assert_eq!(stats.replicas_created, 2);
                assert_eq!(stats.calm_operations_executed, 6); // 3 ops × 2 replicas
                assert_eq!(stats.idempotence_violations, 0);

                println!(
                    "Basic CALM operations: {} operations across {} replicas",
                    stats.calm_operations_executed, stats.replicas_created
                );
                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_replica_divergence_and_reconciliation() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create three replicas
                let replica_a = harness.create_replica(ReplicaId::new(1));
                let replica_b = harness.create_replica(ReplicaId::new(2));
                let replica_c = harness.create_replica(ReplicaId::new(3));

                // Apply different operations to each replica (creating divergence)
                let ops_a = vec![
                    CalmOperation::new(1, "op_a1", Some(ObligationId::new())),
                    CalmOperation::new(2, "op_a2", Some(ObligationId::new())),
                ];
                let ops_b = vec![
                    CalmOperation::new(1, "op_a1", Some(ObligationId::new())), // Duplicate (idempotent)
                    CalmOperation::new(3, "op_b1", Some(ObligationId::new())),
                ];
                let ops_c = vec![
                    CalmOperation::new(4, "op_c1", None),
                    CalmOperation::new(5, "op_c2", Some(ObligationId::new())),
                ];

                // Apply operations to create divergence
                for op in ops_a {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(1), op)
                        .await?;
                }
                for op in ops_b {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(2), op)
                        .await?;
                }
                for op in ops_c {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(3), op)
                        .await?;
                }

                // Verify divergence
                assert!(
                    !harness.check_global_convergence(),
                    "Replicas should be diverged initially"
                );

                let mut stats = harness.stats.lock().unwrap();
                stats.divergence_events += 1;
                drop(stats);

                // Perform reconciliation round
                let reconciliation_results = harness.full_reconciliation_round(cx).await?;

                // Verify reconciliation happened
                assert!(
                    !reconciliation_results.is_empty(),
                    "Should have reconciliation results"
                );

                // Check final convergence
                assert!(
                    harness.check_global_convergence(),
                    "Should converge after reconciliation"
                );

                // Verify idempotence maintained
                harness
                    .check_idempotence_across_replicas()
                    .expect("Should maintain idempotence after reconciliation");

                // All replicas should have all unique operations
                assert_eq!(replica_a.get_operation_count(), 4); // 2 original + 2 from others
                assert_eq!(replica_b.get_operation_count(), 4); // 2 original + 2 from others
                assert_eq!(replica_c.get_operation_count(), 4); // 2 original + 2 from others

                let stats = harness.get_stats();
                println!(
                    "Divergence and reconciliation: {} reconciliation rounds, {} operations total",
                    stats.reconciliation_rounds, stats.calm_operations_executed
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_network_partitions_and_healing() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create four replicas
                let replicas = [
                    harness.create_replica(ReplicaId::new(1)),
                    harness.create_replica(ReplicaId::new(2)),
                    harness.create_replica(ReplicaId::new(3)),
                    harness.create_replica(ReplicaId::new(4)),
                ];

                // Create network partition: {1,2} vs {3,4}
                harness.create_network_partition(ReplicaId::new(1), ReplicaId::new(3));
                harness.create_network_partition(ReplicaId::new(1), ReplicaId::new(4));
                harness.create_network_partition(ReplicaId::new(2), ReplicaId::new(3));
                harness.create_network_partition(ReplicaId::new(2), ReplicaId::new(4));

                // Apply operations to each partition
                let partition_a_ops = vec![
                    CalmOperation::new(1, "partition_a_op1", Some(ObligationId::new())),
                    CalmOperation::new(2, "partition_a_op2", Some(ObligationId::new())),
                ];
                let partition_b_ops = vec![
                    CalmOperation::new(3, "partition_b_op1", Some(ObligationId::new())),
                    CalmOperation::new(4, "partition_b_op2", None),
                ];

                // Apply to partition A (replicas 1,2)
                for op in &partition_a_ops {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(1), op.clone())
                        .await?;
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(2), op.clone())
                        .await?;
                }

                // Apply to partition B (replicas 3,4)
                for op in &partition_b_ops {
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(3), op.clone())
                        .await?;
                    harness
                        .apply_operation_to_replica(cx, ReplicaId::new(4), op.clone())
                        .await?;
                }

                // Verify partitions cannot reconcile
                let partition_reconcile_result = harness
                    .reconcile_replicas(cx, ReplicaId::new(1), ReplicaId::new(3))
                    .await;
                assert!(
                    partition_reconcile_result.is_err(),
                    "Partitioned replicas should not reconcile"
                );

                // Heal network partition
                harness.heal_network_partition(ReplicaId::new(1), ReplicaId::new(3));
                harness.heal_network_partition(ReplicaId::new(1), ReplicaId::new(4));
                harness.heal_network_partition(ReplicaId::new(2), ReplicaId::new(3));
                harness.heal_network_partition(ReplicaId::new(2), ReplicaId::new(4));

                // Perform full reconciliation after healing
                let reconciliation_results = harness.full_reconciliation_round(cx).await?;

                // Verify reconciliation succeeded
                assert!(!reconciliation_results.is_empty());
                assert!(
                    harness.check_global_convergence(),
                    "Should converge after partition healing"
                );

                // All replicas should have all operations
                for replica in &replicas {
                    assert_eq!(replica.get_operation_count(), 4); // 2 from each partition
                }

                let stats = harness.get_stats();
                assert!(stats.network_partitions > 0);
                assert!(stats.successful_convergence > 0);

                println!(
                    "Partition healing: {} partitions, {} successful convergences",
                    stats.network_partitions, stats.successful_convergence
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_concurrent_operations_on_diverged_replicas() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create replicas
                let num_replicas = 5;
                let mut replica_ids = Vec::new();
                for i in 1..=num_replicas {
                    harness.create_replica(ReplicaId::new(i));
                    replica_ids.push(ReplicaId::new(i));
                }

                // Apply concurrent operations to different replicas
                let mut tasks = Vec::new();
                for (i, &replica_id) in replica_ids.iter().enumerate() {
                    let harness_ref = &harness; // Borrow for async block
                    let task = cx.spawn(async move {
                        let mut operations = Vec::new();
                        for j in 0..3 {
                            let op = CalmOperation::new(
                                (i * 10 + j) as u64,
                                &format!("concurrent_op_{}_{}", i, j),
                                Some(ObligationId::new()),
                            );
                            harness_ref
                                .apply_operation_to_replica(cx, replica_id, op)
                                .await?;
                            operations.push((i, j));
                        }
                        Ok::<Vec<(usize, usize)>, AsupersyncError>(operations)
                    });
                    tasks.push(task);
                }

                // Wait for all concurrent operations to complete
                let mut total_operations = 0;
                for task in tasks {
                    let ops = task.await??;
                    total_operations += ops.len();
                }

                // Verify divergence initially
                assert!(
                    !harness.check_global_convergence(),
                    "Should be diverged after concurrent operations"
                );

                // Perform multiple reconciliation rounds
                for round in 0..3 {
                    let _results = harness.full_reconciliation_round(cx).await?;
                    cx.sleep(Duration::from_millis(10)).await; // Brief pause between rounds

                    if harness.check_global_convergence() {
                        println!("Converged after {} reconciliation rounds", round + 1);
                        break;
                    }
                }

                // Verify final convergence
                assert!(
                    harness.check_global_convergence(),
                    "Should eventually converge"
                );

                // Verify idempotence maintained despite concurrency
                harness
                    .check_idempotence_across_replicas()
                    .expect("Should maintain idempotence");

                let stats = harness.get_stats();
                println!(
                    "Concurrent operations: {} total operations, {} reconciliation rounds",
                    total_operations, stats.reconciliation_rounds
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_complex_distribution_patterns() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime
            .region(Budget::default(), |cx| async move {
                // Create 6 replicas in different "regions"
                let regions = vec![
                    vec![ReplicaId::new(1), ReplicaId::new(2)], // Region A
                    vec![ReplicaId::new(3), ReplicaId::new(4)], // Region B
                    vec![ReplicaId::new(5), ReplicaId::new(6)], // Region C
                ];

                for region in &regions {
                    for &replica_id in region {
                        harness.create_replica(replica_id);
                    }
                }

                // Set up network latencies between regions
                for region_a in &regions {
                    for region_b in &regions {
                        if region_a != region_b {
                            for &replica_a in region_a {
                                for &replica_b in region_b {
                                    harness.network_simulator.set_latency(
                                        replica_a,
                                        replica_b,
                                        Duration::from_millis(50), // Inter-region latency
                                    );
                                }
                            }
                        }
                    }
                }

                // Apply region-specific operations
                for (region_idx, region) in regions.iter().enumerate() {
                    for (replica_idx, &replica_id) in region.iter().enumerate() {
                        let ops = vec![
                            CalmOperation::new(
                                (region_idx * 10 + replica_idx * 2) as u64,
                                &format!("region_{}_op_{}", region_idx, replica_idx * 2),
                                Some(ObligationId::new()),
                            ),
                            CalmOperation::new(
                                (region_idx * 10 + replica_idx * 2 + 1) as u64,
                                &format!("region_{}_op_{}", region_idx, replica_idx * 2 + 1),
                                Some(ObligationId::new()),
                            ),
                        ];

                        for op in ops {
                            harness
                                .apply_operation_to_replica(cx, replica_id, op)
                                .await?;
                        }
                    }
                }

                // Perform gradual reconciliation with latency
                let mut reconciliation_rounds = 0;
                while !harness.check_global_convergence() && reconciliation_rounds < 10 {
                    let _results = harness.full_reconciliation_round(cx).await?;
                    reconciliation_rounds += 1;

                    // Simulate processing time between rounds
                    cx.sleep(Duration::from_millis(20)).await;
                }

                // Verify eventual convergence despite complex topology
                assert!(
                    harness.check_global_convergence(),
                    "Complex topology should converge"
                );
                assert!(
                    reconciliation_rounds > 1,
                    "Should require multiple rounds due to latency"
                );

                let stats = harness.get_stats();
                println!(
                    "Complex distribution: {} replicas across 3 regions, {} rounds to convergence",
                    stats.replicas_created, reconciliation_rounds
                );

                Ok(())
            })
            .await
    }

    #[tokio::test]
    async fn test_stress_high_divergence_reconciliation() -> Result<(), AsupersyncError> {
        let mut harness = CalmDistributionTestHarness::new()?;
        let runtime = harness.runtime.clone();

        runtime.region(Budget::default(), |cx| async move {
            let num_replicas = 10;
            let ops_per_replica = 15;

            // Create many replicas
            let mut replica_ids = Vec::new();
            for i in 1..=num_replicas {
                harness.create_replica(ReplicaId::new(i));
                replica_ids.push(ReplicaId::new(i));
            }

            // Apply many operations to each replica to create high divergence
            for &replica_id in &replica_ids {
                for j in 0..ops_per_replica {
                    let op = CalmOperation::new(
                        (replica_id.as_u64() * 1000 + j) as u64,
                        &format!("stress_op_{}_{}", replica_id.as_u64(), j),
                        if j % 3 == 0 { Some(ObligationId::new()) } else { None },
                    );
                    harness.apply_operation_to_replica(cx, replica_id, op).await?;
                }
            }

            let stress_start = Instant::now();

            // Perform intensive reconciliation
            let mut total_rounds = 0;
            while !harness.check_global_convergence() && total_rounds < 20 {
                let reconciliation_results = harness.full_reconciliation_round(cx).await?;
                total_rounds += 1;

                // Log progress
                let converged_pairs = reconciliation_results.values().filter(|r| r.converged).count();
                println!("Round {}: {}/{} pairs converged",
                         total_rounds, converged_pairs, reconciliation_results.len());

                if total_rounds % 5 == 0 {
                    // Brief pause every 5 rounds
                    cx.sleep(Duration::from_millis(10)).await;
                }
            }

            let stress_duration = stress_start.elapsed();

            // Verify final state
            assert!(harness.check_global_convergence(), "Should converge under stress");
            harness.check_idempotence_across_replicas().expect("Should maintain idempotence under stress");

            // Verify all replicas have all operations
            let total_unique_ops = num_replicas * ops_per_replica;
            for &replica_id in &replica_ids {
                let replica = harness.replicas.get(&replica_id).unwrap();
                assert_eq!(replica.get_operation_count(), total_unique_ops);
            }

            let stats = harness.get_stats();
            println!("Stress test: {} replicas, {} operations each, {} reconciliation rounds in {:?}",
                     num_replicas, ops_per_replica, total_rounds, stress_duration);
            println!("Total operations processed: {}, avg reconciliation time: {:?}",
                     stats.calm_operations_executed,
                     stats.total_reconciliation_time / stats.reconciliation_rounds.max(1) as u32);

            // Performance assertions
            assert!(stress_duration < Duration::from_secs(10), "Stress test should complete reasonably quickly");
            assert_eq!(stats.idempotence_violations, 0, "Should have no idempotence violations");

            Ok(())
        }).await
    }
}
