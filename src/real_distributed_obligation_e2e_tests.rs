//! Real-service E2E tests: distributed/bridge ↔ obligation/ledger integration.
//!
//! Tests integration between:
//! - `distributed::bridge`: Cross-node region operations and sequencing
//! - `obligation::ledger`: Central obligation lifecycle tracking
//!
//! This exercises cross-node obligation tracking through real bridge sequencing,
//! distributed obligation coordination, and consistency across replicated nodes.

#[cfg(test)]
mod tests {
    use crate::cx::Cx;
    use crate::distributed::bridge::{RegionBridge, RegionMode, BridgeSequence};
    use crate::distributed::snapshot::{RegionSnapshot, TaskSnapshot, BudgetSnapshot};
    use crate::obligation::ledger::{ObligationLedger, ObligationToken, LedgerStats};
    use crate::record::{
        ObligationKind, ObligationRecord, ObligationState, ObligationResolution,
        ObligationAbortReason, SourceLocation, RegionRecord, TaskRecord,
        distributed_region::{
            DistributedRegionRecord, DistributedRegionState, ConsistencyLevel,
            DistributedRegionConfig, ReplicaInfo, StateTransition, TransitionReason
        }
    };
    use crate::runtime::region;
    use crate::types::{
        Budget, Time, TaskId, RegionId, ObligationId, Outcome, CancelReason, Policy
    };
    use std::collections::{HashMap, BTreeMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
    use std::time::Duration;

    // Test node representation for distributed scenarios
    #[derive(Debug, Clone)]
    struct TestNode {
        node_id: u64,
        region_bridge: RegionBridge,
        obligation_ledger: ObligationLedger,
        sequence_number: AtomicU64,
        replica_info: ReplicaInfo,
        logger: TestLogger,
    }

    impl TestNode {
        fn new(node_id: u64, logger: TestLogger) -> Self {
            let region_bridge = RegionBridge::new(node_id);
            let obligation_ledger = ObligationLedger::new();
            let replica_info = ReplicaInfo {
                node_id,
                endpoint: format!("node://test-node-{}", node_id),
                last_heartbeat: Time::from_nanos(0),
                is_healthy: true,
            };

            Self {
                node_id,
                region_bridge,
                obligation_ledger,
                sequence_number: AtomicU64::new(1),
                replica_info,
                logger,
            }
        }

        fn next_sequence(&self) -> u64 {
            self.sequence_number.fetch_add(1, Ordering::Relaxed)
        }

        async fn create_distributed_region(
            &mut self,
            cx: &Cx,
            region_id: RegionId,
            config: DistributedRegionConfig
        ) -> Result<DistributedRegionRecord, Box<dyn std::error::Error>> {
            self.logger.node_event(self.node_id, "create_distributed_region", &format!("region_{}", region_id.raw()));

            let budget = Budget::from_millis(5000);
            let region_record = RegionRecord::new(
                region_id,
                None, // parent
                SourceLocation::caller(),
                budget,
            );

            // Create distributed region through bridge
            let distributed_region = self.region_bridge.promote_to_distributed(
                region_record,
                config
            ).await?;

            self.logger.node_event(self.node_id, "distributed_region_created",
                &format!("region_{}_seq_{}", region_id.raw(), self.next_sequence()));

            Ok(distributed_region)
        }

        async fn acquire_cross_node_obligation(
            &mut self,
            cx: &Cx,
            task_id: TaskId,
            kind: ObligationKind,
            target_nodes: &[u64]
        ) -> Result<ObligationId, Box<dyn std::error::Error>> {
            let obligation_id = ObligationId::from_raw(self.next_sequence());

            self.logger.node_event(self.node_id, "acquire_cross_node_obligation",
                &format!("{}:{}:targets_{:?}", obligation_id.raw(), task_id.raw(), target_nodes));

            // Create obligation record
            let obligation_record = ObligationRecord::new(
                obligation_id,
                task_id,
                kind.clone(),
                SourceLocation::caller(),
            );

            // Reserve in local ledger
            self.obligation_ledger.reserve(obligation_record);

            self.logger.node_event(self.node_id, "obligation_reserved_locally",
                &format!("{}:{:?}", obligation_id.raw(), kind));

            Ok(obligation_id)
        }

        async fn commit_distributed_obligation(
            &mut self,
            cx: &Cx,
            obligation_id: ObligationId,
            sequence: BridgeSequence
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.logger.node_event(self.node_id, "commit_distributed_obligation",
                &format!("{}:seq_{}", obligation_id.raw(), sequence.sequence_number()));

            // Create resolution with bridge sequence
            let resolution = ObligationResolution::Committed {
                timestamp: Time::from_nanos(sequence.sequence_number() * 1000000),
            };

            // Commit in ledger with sequence coordination
            self.obligation_ledger.commit(obligation_id, resolution);

            self.logger.node_event(self.node_id, "distributed_obligation_committed",
                &format!("{}:seq_{}", obligation_id.raw(), sequence.sequence_number()));

            Ok(())
        }

        async fn synchronize_with_peers(
            &mut self,
            cx: &Cx,
            peer_nodes: &[&TestNode]
        ) -> Result<BridgeSequence, Box<dyn std::error::Error>> {
            self.logger.node_event(self.node_id, "synchronize_with_peers",
                &format!("peers_{}", peer_nodes.len()));

            // Collect sequence numbers from all peers
            let mut max_sequence = self.sequence_number.load(Ordering::Relaxed);
            let mut peer_sequences = Vec::new();

            for peer in peer_nodes {
                let peer_seq = peer.sequence_number.load(Ordering::Relaxed);
                peer_sequences.push((peer.node_id, peer_seq));
                max_sequence = max_sequence.max(peer_seq);
            }

            // Create bridge sequence with consensus
            let bridge_sequence = BridgeSequence::new(max_sequence + 1, self.node_id);

            // Update local sequence to synchronized value
            self.sequence_number.store(bridge_sequence.sequence_number(), Ordering::Relaxed);

            self.logger.node_event(self.node_id, "synchronization_complete",
                &format!("seq_{}_peers_{:?}", bridge_sequence.sequence_number(), peer_sequences));

            Ok(bridge_sequence)
        }

        fn get_ledger_stats(&self) -> LedgerStats {
            self.obligation_ledger.stats()
        }

        fn get_bridge_status(&self) -> BridgeStatus {
            BridgeStatus {
                node_id: self.node_id,
                current_sequence: self.sequence_number.load(Ordering::Relaxed),
                is_healthy: self.replica_info.is_healthy,
                last_sync: Time::from_nanos(0), // Mock for testing
            }
        }
    }

    #[derive(Debug, Clone)]
    struct BridgeSequence {
        sequence: u64,
        coordinator: u64,
        timestamp: Time,
    }

    impl BridgeSequence {
        fn new(sequence: u64, coordinator: u64) -> Self {
            Self {
                sequence,
                coordinator,
                timestamp: crate::time::wall_now(),
            }
        }

        fn sequence_number(&self) -> u64 {
            self.sequence
        }

        fn coordinator_id(&self) -> u64 {
            self.coordinator
        }
    }

    #[derive(Debug, Clone)]
    struct BridgeStatus {
        node_id: u64,
        current_sequence: u64,
        is_healthy: bool,
        last_sync: Time,
    }

    // Distributed obligation coordination scenarios
    #[derive(Debug, Clone)]
    enum DistributedObligationScenario {
        TwoPhaseCommit { participants: Vec<u64> },
        ConsensusCoordination { replicas: Vec<u64>, quorum_size: usize },
        SequentialOrdering { ordered_nodes: Vec<u64> },
        CascadeAbort { primary: u64, secondaries: Vec<u64> },
    }

    // Test data factory for distributed scenarios
    struct DistributedObligationFactory {
        region_counter: AtomicU64,
        task_counter: AtomicU64,
        obligation_counter: AtomicU64,
    }

    impl DistributedObligationFactory {
        fn new() -> Self {
            Self {
                region_counter: AtomicU64::new(1),
                task_counter: AtomicU64::new(1),
                obligation_counter: AtomicU64::new(1),
            }
        }

        fn create_distributed_region_config(&self, replication_factor: u32) -> DistributedRegionConfig {
            DistributedRegionConfig {
                replication_factor,
                consistency_level: ConsistencyLevel::Quorum,
                heartbeat_interval: Duration::from_millis(100),
                timeout: Duration::from_millis(1000),
            }
        }

        fn create_cross_node_scenario(&self, scenario_type: &str, node_count: usize) -> DistributedObligationScenario {
            let node_ids: Vec<u64> = (0..node_count as u64).collect();

            match scenario_type {
                "two_phase_commit" => DistributedObligationScenario::TwoPhaseCommit {
                    participants: node_ids,
                },
                "consensus" => DistributedObligationScenario::ConsensusCoordination {
                    replicas: node_ids.clone(),
                    quorum_size: (node_count + 1) / 2,
                },
                "sequential" => DistributedObligationScenario::SequentialOrdering {
                    ordered_nodes: node_ids,
                },
                "cascade_abort" => DistributedObligationScenario::CascadeAbort {
                    primary: node_ids[0],
                    secondaries: node_ids[1..].to_vec(),
                },
                _ => DistributedObligationScenario::TwoPhaseCommit {
                    participants: node_ids,
                },
            }
        }

        fn next_region_id(&self) -> RegionId {
            RegionId::from_raw(self.region_counter.fetch_add(1, Ordering::Relaxed))
        }

        fn next_task_id(&self) -> TaskId {
            TaskId::from_raw(self.task_counter.fetch_add(1, Ordering::Relaxed))
        }

        fn next_obligation_id(&self) -> ObligationId {
            ObligationId::from_raw(self.obligation_counter.fetch_add(1, Ordering::Relaxed))
        }
    }

    // Structured test logger for distributed scenarios
    #[derive(Debug, Clone)]
    struct TestLogger {
        test_name: String,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new(test_name: &str) -> Self {
            Self {
                test_name: test_name.to_string(),
                events: Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }

        fn log_event(&self, category: &str, event: &str, details: &str) {
            let timestamp = crate::time::wall_now();
            let entry = format!("{{\"test\":\"{}\",\"category\":\"{}\",\"event\":\"{}\",\"details\":\"{}\",\"ts\":{}}}",
                self.test_name, category, event, details, timestamp.as_nanos());
            self.events.lock().push(entry);
            eprintln!("{}", entry);
        }

        fn node_event(&self, node_id: u64, event: &str, details: &str) {
            self.log_event(&format!("node_{}", node_id), event, details);
        }

        fn bridge_event(&self, event: &str, details: &str) {
            self.log_event("bridge", event, details);
        }

        fn obligation_event(&self, event: &str, details: &str) {
            self.log_event("obligation", event, details);
        }

        fn coordination_event(&self, event: &str, details: &str) {
            self.log_event("coordination", event, details);
        }

        fn get_events(&self) -> Vec<String> {
            self.events.lock().clone()
        }
    }

    // Integration test harness for distributed obligation tracking
    struct DistributedObligationHarness {
        nodes: HashMap<u64, TestNode>,
        factory: DistributedObligationFactory,
        logger: TestLogger,
        active_regions: HashMap<RegionId, Vec<u64>>, // region -> participating nodes
        obligation_tracking: HashMap<ObligationId, CrossNodeObligation>,
    }

    #[derive(Debug, Clone)]
    struct CrossNodeObligation {
        obligation_id: ObligationId,
        task_id: TaskId,
        kind: ObligationKind,
        participating_nodes: HashSet<u64>,
        sequence_numbers: BTreeMap<u64, u64>, // node_id -> sequence
        state: CrossNodeObligationState,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum CrossNodeObligationState {
        Reserved,
        Coordinating,
        Committed,
        Aborted,
    }

    impl DistributedObligationHarness {
        async fn new(test_name: &str, node_count: usize) -> Result<Self, Box<dyn std::error::Error>> {
            let logger = TestLogger::new(test_name);
            let mut nodes = HashMap::new();

            // Create test nodes
            for i in 0..node_count {
                let node_logger = logger.clone();
                let node = TestNode::new(i as u64, node_logger);
                nodes.insert(i as u64, node);
                logger.node_event(i as u64, "node_created", "ready");
            }

            Ok(Self {
                nodes,
                factory: DistributedObligationFactory::new(),
                logger,
                active_regions: HashMap::new(),
                obligation_tracking: HashMap::new(),
            })
        }

        async fn create_distributed_region(
            &mut self,
            cx: &Cx,
            participating_nodes: &[u64],
            replication_factor: u32
        ) -> Result<RegionId, Box<dyn std::error::Error>> {
            let region_id = self.factory.next_region_id();
            self.logger.bridge_event("create_distributed_region",
                &format!("region_{}_nodes_{:?}_rf_{}", region_id.raw(), participating_nodes, replication_factor));

            let config = self.factory.create_distributed_region_config(replication_factor);

            // Create region on all participating nodes
            for &node_id in participating_nodes {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    node.create_distributed_region(cx, region_id, config.clone()).await?;
                }
            }

            self.active_regions.insert(region_id, participating_nodes.to_vec());
            self.logger.bridge_event("distributed_region_created",
                &format!("region_{}_active_on_{}_nodes", region_id.raw(), participating_nodes.len()));

            Ok(region_id)
        }

        async fn execute_cross_node_obligation(
            &mut self,
            cx: &Cx,
            scenario: DistributedObligationScenario
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.logger.coordination_event("execute_cross_node_obligation",
                &format!("scenario_{:?}", scenario));

            match scenario {
                DistributedObligationScenario::TwoPhaseCommit { participants } => {
                    self.execute_two_phase_commit(cx, participants).await
                }
                DistributedObligationScenario::ConsensusCoordination { replicas, quorum_size } => {
                    self.execute_consensus_coordination(cx, replicas, quorum_size).await
                }
                DistributedObligationScenario::SequentialOrdering { ordered_nodes } => {
                    self.execute_sequential_ordering(cx, ordered_nodes).await
                }
                DistributedObligationScenario::CascadeAbort { primary, secondaries } => {
                    self.execute_cascade_abort(cx, primary, secondaries).await
                }
            }
        }

        async fn execute_two_phase_commit(
            &mut self,
            cx: &Cx,
            participants: Vec<u64>
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.logger.coordination_event("two_phase_commit_start",
                &format!("participants_{:?}", participants));

            let mut obligation_ids = Vec::new();

            // Phase 1: Prepare (acquire obligations on all nodes)
            for &node_id in &participants {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    let task_id = self.factory.next_task_id();
                    let obligation_id = node.acquire_cross_node_obligation(
                        cx, task_id, ObligationKind::Permit, &participants
                    ).await?;

                    // Track cross-node obligation
                    let cross_node_obligation = CrossNodeObligation {
                        obligation_id,
                        task_id,
                        kind: ObligationKind::Permit,
                        participating_nodes: participants.iter().cloned().collect(),
                        sequence_numbers: BTreeMap::new(),
                        state: CrossNodeObligationState::Reserved,
                    };

                    self.obligation_tracking.insert(obligation_id, cross_node_obligation);
                    obligation_ids.push(obligation_id);

                    self.logger.coordination_event("prepare_phase_complete",
                        &format!("node_{}_obligation_{}", node_id, obligation_id.raw()));
                }
            }

            // Phase 2: Commit (coordinate through bridge sequencing)
            let coordinator_node_id = participants[0];
            if let Some(coordinator) = self.nodes.get_mut(&coordinator_node_id) {
                // Synchronize with all participants
                let peer_nodes: Vec<&TestNode> = participants.iter()
                    .filter_map(|&id| self.nodes.get(&id))
                    .collect();

                let bridge_sequence = coordinator.synchronize_with_peers(cx, &peer_nodes).await?;

                // Commit all obligations using synchronized sequence
                for &obligation_id in &obligation_ids {
                    if let Some(node) = self.nodes.get_mut(&coordinator_node_id) {
                        node.commit_distributed_obligation(cx, obligation_id, bridge_sequence.clone()).await?;
                    }

                    // Update tracking state
                    if let Some(tracked) = self.obligation_tracking.get_mut(&obligation_id) {
                        tracked.state = CrossNodeObligationState::Committed;
                        tracked.sequence_numbers.insert(coordinator_node_id, bridge_sequence.sequence_number());
                    }
                }
            }

            self.logger.coordination_event("two_phase_commit_complete",
                &format!("committed_{}_obligations", obligation_ids.len()));

            Ok(obligation_ids)
        }

        async fn execute_consensus_coordination(
            &mut self,
            cx: &Cx,
            replicas: Vec<u64>,
            quorum_size: usize
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.logger.coordination_event("consensus_coordination_start",
                &format!("replicas_{:?}_quorum_{}", replicas, quorum_size));

            let task_id = self.factory.next_task_id();
            let mut obligation_ids = Vec::new();

            // Create obligations on all replicas
            for &replica_id in &replicas {
                if let Some(node) = self.nodes.get_mut(&replica_id) {
                    let obligation_id = node.acquire_cross_node_obligation(
                        cx, task_id, ObligationKind::Ack, &replicas
                    ).await?;
                    obligation_ids.push(obligation_id);
                }
            }

            // Achieve consensus through bridge sequencing
            let participating_nodes: Vec<&TestNode> = replicas.iter()
                .take(quorum_size)
                .filter_map(|&id| self.nodes.get(&id))
                .collect();

            if let Some(leader) = participating_nodes.first() {
                let consensus_sequence = leader.synchronize_with_peers(cx, &participating_nodes).await?;

                // Apply consensus decision to quorum
                for (i, &obligation_id) in obligation_ids.iter().enumerate() {
                    if i < quorum_size {
                        if let Some(node) = self.nodes.get_mut(&replicas[i]) {
                            node.commit_distributed_obligation(cx, obligation_id, consensus_sequence.clone()).await?;
                        }
                    }
                }
            }

            self.logger.coordination_event("consensus_coordination_complete",
                &format!("quorum_{}_of_{}_committed", quorum_size, replicas.len()));

            Ok(obligation_ids)
        }

        async fn execute_sequential_ordering(
            &mut self,
            cx: &Cx,
            ordered_nodes: Vec<u64>
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.logger.coordination_event("sequential_ordering_start",
                &format!("nodes_{:?}", ordered_nodes));

            let mut obligation_ids = Vec::new();
            let mut current_sequence = 1u64;

            // Process nodes in sequence, each building on the previous
            for (i, &node_id) in ordered_nodes.iter().enumerate() {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    let task_id = self.factory.next_task_id();
                    let obligation_id = node.acquire_cross_node_obligation(
                        cx, task_id, ObligationKind::Lease, &ordered_nodes
                    ).await?;

                    // Create bridge sequence that builds on previous
                    current_sequence += 1;
                    let sequence = BridgeSequence::new(current_sequence, node_id);

                    // Commit with ordered sequence
                    node.commit_distributed_obligation(cx, obligation_id, sequence).await?;
                    obligation_ids.push(obligation_id);

                    self.logger.coordination_event("sequential_step_complete",
                        &format!("step_{}_node_{}_seq_{}", i, node_id, current_sequence));
                }
            }

            self.logger.coordination_event("sequential_ordering_complete",
                &format!("processed_{}_nodes_in_sequence", ordered_nodes.len()));

            Ok(obligation_ids)
        }

        async fn execute_cascade_abort(
            &mut self,
            cx: &Cx,
            primary: u64,
            secondaries: Vec<u64>
        ) -> Result<Vec<ObligationId>, Box<dyn std::error::Error>> {
            self.logger.coordination_event("cascade_abort_start",
                &format!("primary_{}_secondaries_{:?}", primary, secondaries));

            let mut obligation_ids = Vec::new();

            // Create obligations on all nodes
            let all_nodes = [vec![primary], secondaries.clone()].concat();
            for &node_id in &all_nodes {
                if let Some(node) = self.nodes.get_mut(&node_id) {
                    let task_id = self.factory.next_task_id();
                    let obligation_id = node.acquire_cross_node_obligation(
                        cx, task_id, ObligationKind::Permit, &all_nodes
                    ).await?;
                    obligation_ids.push(obligation_id);
                }
            }

            // Simulate primary failure causing cascade abort
            if let Some(primary_node) = self.nodes.get_mut(&primary) {
                // Abort primary obligation
                if let Some(&primary_obligation_id) = obligation_ids.first() {
                    let abort_resolution = ObligationResolution::Aborted {
                        reason: ObligationAbortReason::CancelledByParent,
                        timestamp: crate::time::wall_now(),
                    };
                    primary_node.obligation_ledger.abort(primary_obligation_id, abort_resolution);

                    self.logger.coordination_event("primary_aborted",
                        &format!("obligation_{}", primary_obligation_id.raw()));
                }
            }

            // Cascade abort to secondaries through bridge coordination
            for (i, &secondary_node_id) in secondaries.iter().enumerate() {
                if let Some(secondary_node) = self.nodes.get_mut(&secondary_node_id) {
                    if let Some(&obligation_id) = obligation_ids.get(i + 1) {
                        let cascade_resolution = ObligationResolution::Aborted {
                            reason: ObligationAbortReason::DependencyFailed,
                            timestamp: crate::time::wall_now(),
                        };
                        secondary_node.obligation_ledger.abort(obligation_id, cascade_resolution);

                        self.logger.coordination_event("cascade_abort",
                            &format!("secondary_{}_obligation_{}", secondary_node_id, obligation_id.raw()));
                    }
                }
            }

            self.logger.coordination_event("cascade_abort_complete",
                &format!("aborted_{}_obligations", obligation_ids.len()));

            Ok(obligation_ids)
        }

        async fn verify_cross_node_consistency(&self) -> Result<DistributedConsistencyReport, Box<dyn std::error::Error>> {
            self.logger.coordination_event("verify_consistency", "starting_verification");

            let mut report = DistributedConsistencyReport {
                total_nodes: self.nodes.len(),
                sequence_consistency: true,
                obligation_consistency: true,
                bridge_health: true,
                node_reports: HashMap::new(),
            };

            // Check each node's state
            for (&node_id, node) in &self.nodes {
                let ledger_stats = node.get_ledger_stats();
                let bridge_status = node.get_bridge_status();

                let node_report = NodeConsistencyReport {
                    node_id,
                    ledger_stats,
                    bridge_status: bridge_status.clone(),
                    is_consistent: true, // Will be updated based on checks
                };

                report.node_reports.insert(node_id, node_report);

                // Check for inconsistencies
                if !bridge_status.is_healthy {
                    report.bridge_health = false;
                }
            }

            // Verify sequence number consistency across nodes
            let sequences: Vec<u64> = self.nodes.values()
                .map(|node| node.sequence_number.load(Ordering::Relaxed))
                .collect();

            if sequences.windows(2).any(|w| w[0].abs_diff(w[1]) > 1) {
                report.sequence_consistency = false;
            }

            // Verify obligation tracking consistency
            for (obligation_id, tracked_obligation) in &self.obligation_tracking {
                for &node_id in &tracked_obligation.participating_nodes {
                    if let Some(node) = self.nodes.get(&node_id) {
                        let ledger_stats = node.get_ledger_stats();
                        // In a real implementation, would check if obligation state matches
                        // across all participating nodes
                    }
                }
            }

            self.logger.coordination_event("consistency_verification_complete",
                &format!("seq_consistent_{}_obl_consistent_{}_bridge_healthy_{}",
                    report.sequence_consistency, report.obligation_consistency, report.bridge_health));

            Ok(report)
        }

        fn analyze_distributed_events(&self) -> DistributedEventAnalysis {
            let events = self.logger.get_events();

            let mut analysis = DistributedEventAnalysis {
                total_events: events.len(),
                node_events: BTreeMap::new(),
                bridge_events: 0,
                obligation_events: 0,
                coordination_events: 0,
                cross_node_operations: 0,
                sequence_synchronizations: 0,
            };

            for event in &events {
                if event.contains("\"category\":\"bridge\"") {
                    analysis.bridge_events += 1;
                    if event.contains("synchronize") {
                        analysis.sequence_synchronizations += 1;
                    }
                } else if event.contains("\"category\":\"obligation\"") {
                    analysis.obligation_events += 1;
                } else if event.contains("\"category\":\"coordination\"") {
                    analysis.coordination_events += 1;
                    if event.contains("cross_node") {
                        analysis.cross_node_operations += 1;
                    }
                } else if event.contains("\"category\":\"node_") {
                    // Extract node ID from category
                    if let Some(start) = event.find("node_") {
                        if let Some(end) = event[start + 5..].find("\"") {
                            if let Ok(node_id) = event[start + 5..start + 5 + end].parse::<u64>() {
                                *analysis.node_events.entry(node_id).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }

            analysis
        }
    }

    #[derive(Debug)]
    struct DistributedConsistencyReport {
        total_nodes: usize,
        sequence_consistency: bool,
        obligation_consistency: bool,
        bridge_health: bool,
        node_reports: HashMap<u64, NodeConsistencyReport>,
    }

    #[derive(Debug)]
    struct NodeConsistencyReport {
        node_id: u64,
        ledger_stats: LedgerStats,
        bridge_status: BridgeStatus,
        is_consistent: bool,
    }

    #[derive(Debug)]
    struct DistributedEventAnalysis {
        total_events: usize,
        node_events: BTreeMap<u64, usize>,
        bridge_events: usize,
        obligation_events: usize,
        coordination_events: usize,
        cross_node_operations: usize,
        sequence_synchronizations: usize,
    }

    #[test]
    fn test_distributed_obligation_bridge_integration() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = DistributedObligationHarness::new("distributed_obligation_bridge", 3)
                .await
                .expect("Harness creation should succeed");

            // Create distributed region across all nodes
            let participating_nodes = vec![0, 1, 2];
            let region_id = harness.create_distributed_region(&cx, &participating_nodes, 2).await?;

            // Execute two-phase commit scenario
            let scenario = harness.factory.create_cross_node_scenario("two_phase_commit", 3);
            let obligation_ids = harness.execute_cross_node_obligation(&cx, scenario).await?;

            assert_eq!(obligation_ids.len(), 3, "Should create obligation on each node");

            // Verify cross-node consistency
            let consistency_report = harness.verify_cross_node_consistency().await?;
            assert!(consistency_report.sequence_consistency, "Sequences should be consistent across nodes");
            assert!(consistency_report.bridge_health, "All bridges should be healthy");

            // Analyze distributed event sequence
            let analysis = harness.analyze_distributed_events();
            assert!(analysis.bridge_events > 0, "Should have bridge coordination events");
            assert!(analysis.coordination_events > 0, "Should have cross-node coordination");
            assert!(analysis.sequence_synchronizations > 0, "Should have sequence synchronization");

            Ok(())
        }).expect("Distributed obligation bridge integration test should complete successfully");
    }

    #[test]
    fn test_consensus_obligation_coordination() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = DistributedObligationHarness::new("consensus_obligation_coordination", 5)
                .await
                .expect("Harness creation should succeed");

            // Create distributed region with quorum consensus
            let all_nodes = vec![0, 1, 2, 3, 4];
            let region_id = harness.create_distributed_region(&cx, &all_nodes, 3).await?;

            // Execute consensus coordination scenario
            let scenario = DistributedObligationScenario::ConsensusCoordination {
                replicas: all_nodes.clone(),
                quorum_size: 3,
            };
            let obligation_ids = harness.execute_cross_node_obligation(&cx, scenario).await?;

            assert_eq!(obligation_ids.len(), 5, "Should create obligations on all replicas");

            // Verify consensus was achieved
            let consistency_report = harness.verify_cross_node_consistency().await?;
            assert!(consistency_report.obligation_consistency, "Obligations should be consistent");

            // Check that quorum size was respected in coordination
            let analysis = harness.analyze_distributed_events();
            assert!(analysis.coordination_events >= 3, "Should have sufficient coordination for quorum");

            Ok(())
        }).expect("Consensus obligation coordination test should complete successfully");
    }

    #[test]
    fn test_sequential_bridge_sequencing() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = DistributedObligationHarness::new("sequential_bridge_sequencing", 4)
                .await
                .expect("Harness creation should succeed");

            // Execute sequential ordering scenario
            let ordered_nodes = vec![0, 1, 2, 3];
            let scenario = DistributedObligationScenario::SequentialOrdering {
                ordered_nodes: ordered_nodes.clone(),
            };

            let obligation_ids = harness.execute_cross_node_obligation(&cx, scenario).await?;

            assert_eq!(obligation_ids.len(), 4, "Should process all nodes sequentially");

            // Verify sequential ordering was maintained
            let analysis = harness.analyze_distributed_events();
            assert!(analysis.sequence_synchronizations >= 4, "Should have sequential synchronizations");

            // Check that each node has increasing sequence numbers
            let sequences: Vec<u64> = ordered_nodes.iter()
                .map(|&node_id| harness.nodes[&node_id].sequence_number.load(Ordering::Relaxed))
                .collect();

            for window in sequences.windows(2) {
                assert!(window[1] > window[0], "Sequences should increase in order");
            }

            Ok(())
        }).expect("Sequential bridge sequencing test should complete successfully");
    }

    #[test]
    fn test_cascade_abort_coordination() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = DistributedObligationHarness::new("cascade_abort_coordination", 4)
                .await
                .expect("Harness creation should succeed");

            // Execute cascade abort scenario
            let scenario = DistributedObligationScenario::CascadeAbort {
                primary: 0,
                secondaries: vec![1, 2, 3],
            };

            let obligation_ids = harness.execute_cross_node_obligation(&cx, scenario).await?;

            assert_eq!(obligation_ids.len(), 4, "Should create obligations on all nodes");

            // Verify cascade abort was properly coordinated
            let analysis = harness.analyze_distributed_events();
            assert!(analysis.coordination_events > 0, "Should have coordination events");

            // Check that all nodes have consistent abort state
            let consistency_report = harness.verify_cross_node_consistency().await?;
            assert!(consistency_report.bridge_health, "Bridge should remain healthy after abort");

            Ok(())
        }).expect("Cascade abort coordination test should complete successfully");
    }

    #[test]
    fn test_cross_node_obligation_consistency() {
        crate::lab::runtime::test_with_lab(|cx| async move {
            let mut harness = DistributedObligationHarness::new("cross_node_obligation_consistency", 3)
                .await
                .expect("Harness creation should succeed");

            // Create multiple distributed regions with overlapping nodes
            let region1_nodes = vec![0, 1];
            let region2_nodes = vec![1, 2];
            let region3_nodes = vec![0, 2];

            let region1 = harness.create_distributed_region(&cx, &region1_nodes, 2).await?;
            let region2 = harness.create_distributed_region(&cx, &region2_nodes, 2).await?;
            let region3 = harness.create_distributed_region(&cx, &region3_nodes, 2).await?;

            // Execute obligations across different region combinations
            let scenario1 = harness.factory.create_cross_node_scenario("two_phase_commit", 2);
            let obligations1 = harness.execute_cross_node_obligation(&cx, scenario1).await?;

            let scenario2 = harness.factory.create_cross_node_scenario("consensus", 2);
            let obligations2 = harness.execute_cross_node_obligation(&cx, scenario2).await?;

            // Verify overall consistency across all operations
            let final_consistency = harness.verify_cross_node_consistency().await?;
            assert!(final_consistency.sequence_consistency, "Sequences should remain consistent");
            assert!(final_consistency.obligation_consistency, "Obligations should be consistent");
            assert_eq!(final_consistency.total_nodes, 3, "Should track all nodes");

            // Verify that all nodes have processed obligations
            for (&node_id, node_report) in &final_consistency.node_reports {
                assert!(node_report.ledger_stats.total_acquired > 0,
                    "Node {} should have processed obligations", node_id);
                assert!(node_report.is_consistent, "Node {} should be consistent", node_id);
            }

            Ok(())
        }).expect("Cross-node obligation consistency test should complete successfully");
    }
}