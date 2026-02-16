//! E2E: Distributed RaptorQ encode/distribute/recover pipeline.
//!
//! Tests the actual distributed module end-to-end: encode region state into
//! RaptorQ symbols, distribute to replicas, recover from partial symbol sets.

mod common;

use std::time::Duration;

use asupersync::distributed::assignment::{AssignmentStrategy, SymbolAssigner};
use asupersync::distributed::bridge::{EffectiveState, RegionBridge, RegionMode};
use asupersync::distributed::distribution::{
    DistributionConfig, DistributionResult, ReplicaAck, ReplicaFailure, SymbolDistributor,
};
use asupersync::distributed::encoding::{EncodedState, EncodingConfig, StateEncoder};
use asupersync::distributed::recovery::{
    CollectedSymbol, CollectionConsistency, RecoveryCollector, RecoveryConfig,
    RecoveryDecodingConfig, RecoveryOrchestrator, RecoveryTrigger, StateDecoder,
};
use asupersync::distributed::snapshot::{BudgetSnapshot, RegionSnapshot, TaskSnapshot, TaskState};
use asupersync::distributed::HashRing;
use asupersync::error::ErrorKind;
use asupersync::record::distributed_region::{
    ConsistencyLevel, DistributedRegionConfig, DistributedRegionRecord, DistributedRegionState,
    ReplicaInfo, ReplicaStatus,
};
use asupersync::record::region::RegionState;
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag};
use asupersync::types::budget::Budget;
use asupersync::types::{Outcome, RegionId, TaskId, Time};
use asupersync::util::DetRng;

// =========================================================================
// Helpers
// =========================================================================

fn make_region_snapshot() -> RegionSnapshot {
    RegionSnapshot {
        region_id: RegionId::new_for_test(1, 0),
        state: RegionState::Open,
        timestamp: Time::from_secs(100),
        sequence: 7,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 10,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(2, 0),
                state: TaskState::Pending,
                priority: 5,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(3, 0),
                state: TaskState::Completed,
                priority: 1,
            },
        ],
        children: vec![RegionId::new_for_test(10, 0), RegionId::new_for_test(11, 0)],
        finalizer_count: 2,
        budget: BudgetSnapshot {
            deadline_nanos: Some(5_000_000_000),
            polls_remaining: Some(200),
            cost_remaining: Some(500),
        },
        cancel_reason: None,
        parent: Some(RegionId::new_for_test(0, 0)),
        metadata: vec![0xCA, 0xFE, 0xBA, 0xBE],
    }
}

fn encode_snapshot(snapshot: &RegionSnapshot) -> EncodedState {
    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 4,
        ..Default::default()
    };
    StateEncoder::new(config, DetRng::new(42))
        .encode(snapshot, Time::ZERO)
        .unwrap()
}

fn test_replicas(count: usize) -> Vec<ReplicaInfo> {
    (0..count)
        .map(|i| ReplicaInfo::new(&format!("node-{i}"), &format!("10.0.0.{i}:9000")))
        .collect()
}

fn make_ack(id: &str, count: u32) -> ReplicaAck {
    ReplicaAck {
        replica_id: id.to_string(),
        symbols_received: count,
        ack_time: Time::ZERO,
    }
}

fn make_failure(id: &str) -> ReplicaFailure {
    ReplicaFailure {
        replica_id: id.to_string(),
        error: "timeout".to_string(),
        error_kind: ErrorKind::NodeUnavailable,
    }
}

fn make_cluster_snapshot(region_id: RegionId, sequence: u64, timestamp: Time) -> RegionSnapshot {
    let mut snapshot = make_region_snapshot();
    snapshot.region_id = region_id;
    snapshot.sequence = sequence;
    snapshot.timestamp = timestamp;
    snapshot
}

fn replica_can_ack(replica: &ReplicaInfo) -> bool {
    matches!(
        replica.status,
        ReplicaStatus::Healthy | ReplicaStatus::Syncing
    )
}

struct TestCluster {
    record: DistributedRegionRecord,
    election_term: u64,
    leader_id: Option<String>,
}

impl TestCluster {
    fn bootstrap(
        id: RegionId,
        config: DistributedRegionConfig,
        replicas: Vec<ReplicaInfo>,
        now: Time,
    ) -> Self {
        let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());
        for replica in replicas {
            record.add_replica(replica).unwrap();
        }
        record.activate(now).unwrap();
        Self {
            record,
            election_term: 0,
            leader_id: None,
        }
    }

    fn elect_leader(&mut self) -> Option<String> {
        let mut ring = HashRing::new(8);
        for replica in self.record.replicas.iter().filter(|r| replica_can_ack(r)) {
            ring.add_node(replica.id.clone());
        }
        let leader = ring.node_for_key(&self.election_term).map(str::to_string);
        self.leader_id.clone_from(&leader);
        self.election_term = self.election_term.wrapping_add(1);
        leader
    }

    fn pick_follower(&self, leader_id: &str) -> Option<String> {
        self.record
            .replicas
            .iter()
            .find(|replica| replica.id != leader_id && replica_can_ack(replica))
            .map(|replica| replica.id.clone())
    }

    fn mark_unavailable(&mut self, replica_id: &str, now: Time) {
        match self.record.replica_lost(replica_id, now) {
            Ok(transition) => {
                tracing::info!(
                    replica = %replica_id,
                    state = ?transition.to,
                    "replica lost triggered state transition"
                );
            }
            Err(err) => {
                tracing::info!(
                    replica = %replica_id,
                    error = %err,
                    "replica lost but quorum maintained"
                );
            }
        }
    }

    fn heal_replica(&mut self, replica_id: &str, now: Time) {
        self.record
            .update_replica_status(replica_id, ReplicaStatus::Healthy, now)
            .unwrap();
    }

    fn healthy_count(&self) -> u32 {
        self.record.healthy_replicas()
    }

    fn read_quorum_ok(&self) -> bool {
        let required = SymbolDistributor::required_acks(
            self.record.config.read_consistency,
            self.record.replicas.len(),
        ) as u32;
        self.healthy_count() >= required
    }

    fn write_snapshot(&self, snapshot: &RegionSnapshot, now: Time) -> DistributionResult {
        let config = EncodingConfig {
            symbol_size: 128,
            min_repair_symbols: 4,
            ..Default::default()
        };
        let encoded = StateEncoder::new(config, DetRng::new(7))
            .encode(snapshot, now)
            .unwrap();

        let outcomes = self
            .record
            .replicas
            .iter()
            .map(|replica| {
                if replica_can_ack(replica) {
                    Outcome::Ok(make_ack(&replica.id, encoded.symbols.len() as u32))
                } else {
                    Outcome::Err(make_failure(&replica.id))
                }
            })
            .collect();

        let mut distributor = SymbolDistributor::new(DistributionConfig {
            consistency: self.record.config.write_consistency,
            ..Default::default()
        });
        distributor.evaluate_outcomes(
            &encoded,
            &self.record.replicas,
            outcomes,
            Duration::from_millis(12),
        )
    }
}

// =========================================================================
// Phase 1-7: Full Encode -> Distribute -> Recover Pipeline
// =========================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_full_encode_distribute_recover_pipeline() {
    common::init_test_logging();
    test_phase!("Setup");

    let snapshot = make_region_snapshot();
    let original_hash = snapshot.content_hash();
    tracing::info!(
        region_id = ?snapshot.region_id,
        tasks = snapshot.tasks.len(),
        children = snapshot.children.len(),
        sequence = snapshot.sequence,
        "created region snapshot"
    );

    // Phase 2: Encode
    test_phase!("Encode");
    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 4,
        ..Default::default()
    };
    let mut encoder = StateEncoder::new(config, DetRng::new(42));
    let encoded_state = encoder.encode(&snapshot, Time::from_secs(100)).unwrap();
    tracing::info!(
        source_count = encoded_state.source_count,
        repair_count = encoded_state.repair_count,
        total_symbols = encoded_state.symbols.len(),
        original_size = encoded_state.original_size,
        "encoding complete"
    );
    assert!(encoded_state.source_count >= 1);
    assert_eq!(encoded_state.repair_count, 4);

    // Phase 3: Assign with all 3 strategies
    test_phase!("Assign");
    let replicas = test_replicas(3);

    for strategy in [
        AssignmentStrategy::Full,
        AssignmentStrategy::Striped,
        AssignmentStrategy::MinimumK,
    ] {
        test_section!(&format!("Strategy: {strategy:?}"));
        let assigner = SymbolAssigner::new(strategy);
        let assignments = assigner.assign(
            &encoded_state.symbols,
            &replicas,
            encoded_state.source_count,
        );
        assert_eq!(assignments.len(), 3);

        for a in &assignments {
            tracing::debug!(
                replica = %a.replica_id,
                symbols = a.symbol_indices.len(),
                can_decode = a.can_decode,
                "assignment"
            );
        }

        match strategy {
            AssignmentStrategy::Full => {
                for a in &assignments {
                    assert_eq!(a.symbol_indices.len(), encoded_state.symbols.len());
                    assert!(a.can_decode);
                }
            }
            AssignmentStrategy::Striped => {
                let total: usize = assignments.iter().map(|a| a.symbol_indices.len()).sum();
                assert_eq!(total, encoded_state.symbols.len());
            }
            AssignmentStrategy::MinimumK => {
                for a in &assignments {
                    assert!(
                        a.symbol_indices.len() >= encoded_state.source_count as usize,
                        "MinimumK: expected >= {}, got {}",
                        encoded_state.source_count,
                        a.symbol_indices.len()
                    );
                }
            }
            AssignmentStrategy::Weighted => {}
        }
    }

    // Phase 4: Distribute with all 3 consistency levels
    test_phase!("Distribute");
    for consistency in [
        ConsistencyLevel::Local,
        ConsistencyLevel::Quorum,
        ConsistencyLevel::All,
    ] {
        test_section!(&format!("Consistency: {consistency:?}"));
        let dist_config = DistributionConfig {
            consistency,
            ..Default::default()
        };
        let mut distributor = SymbolDistributor::new(dist_config);

        // 2 of 3 succeed
        let outcomes = vec![
            Outcome::Ok(make_ack("node-0", encoded_state.symbols.len() as u32)),
            Outcome::Ok(make_ack("node-1", encoded_state.symbols.len() as u32)),
            Outcome::Err(make_failure("node-2")),
        ];
        let result = distributor.evaluate_outcomes(
            &encoded_state,
            &replicas,
            outcomes,
            Duration::from_millis(50),
        );

        tracing::info!(
            consistency = ?consistency,
            quorum_achieved = result.quorum_achieved,
            acks = result.acks.len(),
            failures = result.failures.len(),
            "distribution result"
        );

        match consistency {
            ConsistencyLevel::Local | ConsistencyLevel::One | ConsistencyLevel::Quorum => {
                assert!(result.quorum_achieved);
            } // 2/3 >= quorum
            ConsistencyLevel::All => assert!(!result.quorum_achieved), // 2/3 < all
        }
    }

    // Phase 5: Partition — remove 1 replica, verify quorum
    test_phase!("Partition");
    let id = RegionId::new_for_test(1, 0);
    let dist_config = DistributedRegionConfig {
        min_quorum: 2,
        replication_factor: 3,
        allow_degraded: true,
        ..Default::default()
    };
    let mut record = DistributedRegionRecord::new(id, dist_config, None, Budget::default());
    for i in 0..3 {
        record
            .add_replica(ReplicaInfo::new(
                &format!("node-{i}"),
                &format!("10.0.0.{i}:9000"),
            ))
            .unwrap();
    }
    record.activate(Time::from_secs(0)).unwrap();
    assert!(record.has_quorum());

    // Lose 1 — still has quorum
    let _ = record.replica_lost("node-2", Time::from_secs(10));
    assert!(record.has_quorum());
    tracing::info!(quorum = record.has_quorum(), "after losing 1 replica");

    // Phase 6: Recover
    test_phase!("Recover");
    let symbols: Vec<CollectedSymbol> = encoded_state
        .symbols
        .iter()
        .enumerate()
        .map(|(i, s)| CollectedSymbol {
            symbol: s.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: format!("node-{}", i % 2), // from surviving replicas
            collected_at: Time::from_secs(u64::try_from(i).unwrap()),
            verified: true,
        })
        .collect();

    let trigger = RecoveryTrigger::QuorumLost {
        region_id: snapshot.region_id,
        available_replicas: vec!["node-0".to_string(), "node-1".to_string()],
        required_quorum: 2,
    };

    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());
    let result = orchestrator
        .recover_from_symbols(
            &trigger,
            &symbols,
            encoded_state.params,
            Duration::from_millis(10),
        )
        .unwrap();

    tracing::info!(
        verified = result.verified,
        contributing_replicas = result.contributing_replicas.len(),
        "recovery complete"
    );

    // Phase 7: Verify
    test_phase!("Verify");
    assert_eq!(result.snapshot.region_id, snapshot.region_id);
    assert_eq!(result.snapshot.state, snapshot.state);
    assert_eq!(result.snapshot.timestamp, snapshot.timestamp);
    assert_eq!(result.snapshot.sequence, snapshot.sequence);
    assert_eq!(result.snapshot.tasks.len(), snapshot.tasks.len());
    for (r, o) in result.snapshot.tasks.iter().zip(snapshot.tasks.iter()) {
        assert_eq!(r.task_id, o.task_id);
        assert_eq!(r.state, o.state);
        assert_eq!(r.priority, o.priority);
    }
    assert_eq!(result.snapshot.children, snapshot.children);
    assert_eq!(result.snapshot.finalizer_count, snapshot.finalizer_count);
    assert_eq!(
        result.snapshot.budget.deadline_nanos,
        snapshot.budget.deadline_nanos
    );
    assert_eq!(
        result.snapshot.budget.polls_remaining,
        snapshot.budget.polls_remaining
    );
    assert_eq!(
        result.snapshot.budget.cost_remaining,
        snapshot.budget.cost_remaining
    );
    assert_eq!(result.snapshot.cancel_reason, snapshot.cancel_reason);
    assert_eq!(result.snapshot.parent, snapshot.parent);
    assert_eq!(result.snapshot.metadata, snapshot.metadata);
    assert_eq!(result.snapshot.content_hash(), original_hash);
    assert!(!result.verified);

    test_complete!(
        "e2e_full_pipeline",
        source_symbols = encoded_state.source_count,
        repair_symbols = encoded_state.repair_count,
        replicas = 3,
        recovered_hash_match = true,
    );
}

// =========================================================================
// Phase 5+6 focused: Quorum loss + recovery
// =========================================================================

#[test]
fn e2e_quorum_loss_and_recovery() {
    common::init_test_logging();
    test_phase!("Quorum Loss + Recovery");

    let id = RegionId::new_for_test(2, 0);
    let config = DistributedRegionConfig {
        min_quorum: 2,
        replication_factor: 3,
        allow_degraded: true,
        ..Default::default()
    };
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    for i in 0..3 {
        record
            .add_replica(ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .unwrap();
    }
    record.activate(Time::from_secs(0)).unwrap();

    test_section!("Lose 2 replicas -> degraded");
    let _ = record.replica_lost("r1", Time::from_secs(10));
    let _ = record.replica_lost("r2", Time::from_secs(11)).unwrap();
    assert!(!record.has_quorum());
    assert!(!record.state.can_write());
    tracing::info!(state = ?record.state, "degraded after losing 2 replicas");

    test_section!("Trigger recovery");
    record
        .trigger_recovery("admin", Time::from_secs(20))
        .unwrap();

    test_section!("Complete recovery");
    let _ = record.complete_recovery(8, Time::from_secs(30)).unwrap();
    assert!(record.state.can_write());
    tracing::info!(state = ?record.state, "recovered");

    test_complete!("e2e_quorum_loss_and_recovery");
}

// =========================================================================
// Phase 8: Heal — rejoin removed replica + re-sync
// =========================================================================

#[test]
fn e2e_replica_rejoin_after_partition() {
    common::init_test_logging();
    test_phase!("Replica Rejoin");

    let id = RegionId::new_for_test(3, 0);
    let config = DistributedRegionConfig {
        min_quorum: 2,
        replication_factor: 3,
        allow_degraded: true,
        ..Default::default()
    };
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    for i in 0..3 {
        record
            .add_replica(ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .unwrap();
    }
    record.activate(Time::from_secs(0)).unwrap();

    // Lose one
    let _ = record.replica_lost("r2", Time::from_secs(10));
    assert!(record.has_quorum()); // 2 >= 2

    // Rejoin
    record
        .update_replica_status("r2", ReplicaStatus::Healthy, Time::from_secs(20))
        .unwrap();
    assert!(record.has_quorum());
    tracing::info!("replica r2 rejoined successfully");

    test_complete!("e2e_replica_rejoin");
}

// =========================================================================
// Phase 9: Bridge Lifecycle — Local -> Distributed upgrade -> snapshot -> close
// =========================================================================

#[test]
fn e2e_bridge_upgrade_snapshot_close() {
    common::init_test_logging();
    test_phase!("Bridge Lifecycle");

    test_section!("Create local bridge with work");
    let mut bridge = RegionBridge::new_local(
        RegionId::new_for_test(5, 0),
        Some(RegionId::new_for_test(0, 0)),
        Budget::new().with_poll_quota(100),
    );
    bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
    bridge.add_task(TaskId::new_for_test(2, 0)).unwrap();
    bridge.add_child(RegionId::new_for_test(6, 0)).unwrap();
    assert!(bridge.has_live_work());
    let snap_before = bridge.create_snapshot();
    tracing::info!(
        tasks = snap_before.tasks.len(),
        children = snap_before.children.len(),
        sequence = snap_before.sequence,
        "snapshot before upgrade"
    );

    test_section!("Upgrade to distributed");
    let dist_config = DistributedRegionConfig {
        replication_factor: 3,
        ..Default::default()
    };
    let replicas = test_replicas(3);
    let upgrade = bridge
        .upgrade_to_distributed(dist_config, &replicas)
        .unwrap();
    assert_eq!(upgrade.previous_mode, RegionMode::Local);
    assert!(upgrade.new_mode.is_distributed());
    assert!(bridge.distributed().is_some());
    tracing::info!(
        replication_factor = upgrade.new_mode.replication_factor(),
        "upgraded to distributed"
    );

    test_section!("Snapshot after upgrade");
    let snap_after = bridge.create_snapshot();
    assert!(snap_after.sequence > snap_before.sequence);
    assert_eq!(snap_after.tasks.len(), snap_before.tasks.len());
    assert_eq!(snap_after.children.len(), snap_before.children.len());

    test_section!("Encode + decode upgraded snapshot");
    let encoded = encode_snapshot(&snap_after);
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig::default());
    for sym in &encoded.symbols {
        let sym = AuthenticatedSymbol::new_verified(sym.clone(), AuthenticationTag::zero());
        decoder.add_symbol(&sym).unwrap();
    }
    let recovered = decoder.decode_snapshot(&encoded.params).unwrap();
    assert_eq!(recovered.content_hash(), snap_after.content_hash());

    test_section!("Close bridge");
    bridge.remove_task(TaskId::new_for_test(1, 0));
    bridge.remove_task(TaskId::new_for_test(2, 0));
    bridge.remove_child(RegionId::new_for_test(6, 0));
    assert!(!bridge.has_live_work());

    let close = bridge.begin_close(None, Time::from_secs(50)).unwrap();
    assert_eq!(close.effective_state, EffectiveState::Closing);
    bridge.begin_drain().unwrap();
    bridge.begin_finalize().unwrap();
    let final_result = bridge.complete_close(Time::from_secs(51)).unwrap();
    assert_eq!(final_result.effective_state, EffectiveState::Closed);

    test_complete!(
        "e2e_bridge_lifecycle",
        snapshots_taken = 2,
        encode_decode_verified = true,
    );
}

// =========================================================================
// Collector deduplication under multi-replica collection
// =========================================================================

#[test]
fn e2e_collector_dedup_multi_replica() {
    common::init_test_logging();
    test_phase!("Collector Dedup");

    let snapshot = make_region_snapshot();
    let encoded = encode_snapshot(&snapshot);

    let mut collector = RecoveryCollector::new(RecoveryConfig {
        collection_consistency: CollectionConsistency::Quorum,
        ..Default::default()
    });
    collector.object_params = Some(encoded.params);

    // Simulate collecting from 3 replicas (Full assignment = duplicates)
    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for replica_idx in 0u64..3 {
        for sym in &encoded.symbols {
            let ok = collector.add_collected(CollectedSymbol {
                symbol: sym.clone(),
                tag: AuthenticationTag::zero(),
                source_replica: format!("node-{replica_idx}"),
                collected_at: Time::from_secs(replica_idx),
                verified: false,
            });
            if ok {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }

    tracing::info!(
        accepted,
        rejected,
        unique = collector.symbols().len(),
        duplicates = collector.metrics.symbols_duplicate,
        "collector stats"
    );

    // First replica's symbols accepted, rest are duplicates
    assert_eq!(accepted as usize, encoded.symbols.len());
    assert_eq!(rejected as usize, encoded.symbols.len() * 2);
    assert_eq!(
        collector.metrics.symbols_duplicate as usize,
        encoded.symbols.len() * 2
    );
    assert!(collector.can_decode());

    test_complete!(
        "e2e_collector_dedup",
        total_symbols = encoded.symbols.len() * 3,
        unique_symbols = collector.symbols().len(),
    );
}

// =========================================================================
// Recovery with source-only symbols (no repair)
// =========================================================================

#[test]
fn e2e_recover_source_only() {
    common::init_test_logging();
    test_phase!("Source-Only Recovery");

    let snapshot = make_region_snapshot();
    let encoded = encode_snapshot(&snapshot);

    let source_symbols: Vec<CollectedSymbol> = encoded
        .source_symbols()
        .map(|s| CollectedSymbol {
            symbol: s.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: "node-0".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        })
        .collect();

    tracing::info!(
        source_count = source_symbols.len(),
        total_available = encoded.symbols.len(),
        "recovering from source symbols only"
    );

    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: snapshot.region_id,
        initiator: "e2e-test".to_string(),
        reason: Some("source-only recovery test".to_string()),
    };

    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());
    let result = orchestrator
        .recover_from_symbols(
            &trigger,
            &source_symbols,
            encoded.params,
            Duration::from_millis(10),
        )
        .unwrap();

    assert_eq!(result.snapshot.content_hash(), snapshot.content_hash());
    assert!(!result.verified);

    test_complete!("e2e_recover_source_only");
}

// =========================================================================
// Insufficient symbols -> clear error
// =========================================================================

#[test]
fn e2e_insufficient_symbols_fails_cleanly() {
    common::init_test_logging();
    test_phase!("Insufficient Symbols");

    let snapshot = make_region_snapshot();
    let encoded = encode_snapshot(&snapshot);

    // Take only half the source symbols
    let partial: Vec<CollectedSymbol> = encoded
        .source_symbols()
        .take(encoded.source_count as usize / 2)
        .map(|s| CollectedSymbol {
            symbol: s.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: "node-0".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        })
        .collect();

    tracing::info!(
        provided = partial.len(),
        needed = encoded.source_count,
        "attempting recovery with insufficient symbols"
    );

    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: snapshot.region_id,
        initiator: "e2e-test".to_string(),
        reason: None,
    };

    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());
    let result = orchestrator.recover_from_symbols(
        &trigger,
        &partial,
        encoded.params,
        Duration::from_millis(10),
    );

    assert!(result.is_err());
    tracing::info!(error = ?result.unwrap_err(), "correctly rejected insufficient symbols");

    test_complete!("e2e_insufficient_symbols");
}

// =========================================================================
// Multi-node cluster: bootstrap, leader election, replication, partition, heal
// =========================================================================

#[test]
fn e2e_distributed_multi_node_cluster() {
    common::init_test_logging();
    test_phase!("Bootstrap");

    let region_id = RegionId::new_for_test(42, 0);
    let config = DistributedRegionConfig {
        min_quorum: 2,
        replication_factor: 3,
        read_consistency: ConsistencyLevel::Quorum,
        write_consistency: ConsistencyLevel::Quorum,
        ..Default::default()
    };
    let mut cluster =
        TestCluster::bootstrap(region_id, config, test_replicas(3), Time::from_secs(0));
    assert_eq!(cluster.record.state, DistributedRegionState::Active);
    assert!(cluster.record.has_quorum());

    test_phase!("Leader Election");
    let leader = cluster.elect_leader().expect("leader elected");
    tracing::info!(leader = %leader, "leader elected");

    test_phase!("Write Replication");
    let snapshot = make_cluster_snapshot(region_id, 10, Time::from_secs(1));
    let write_result = cluster.write_snapshot(&snapshot, Time::from_secs(1));
    assert!(write_result.quorum_achieved);

    test_phase!("Read Consistency");
    assert!(cluster.read_quorum_ok());

    test_phase!("Network Partition");
    let follower = cluster
        .pick_follower(&leader)
        .expect("follower available for partition");
    cluster.mark_unavailable(&follower, Time::from_secs(2));
    assert!(cluster.record.has_quorum());
    let write_after_partition = cluster.write_snapshot(&snapshot, Time::from_secs(2));
    assert!(write_after_partition.quorum_achieved);

    test_phase!("Leader Failure + Re-election");
    cluster.mark_unavailable(&leader, Time::from_secs(3));
    assert_eq!(cluster.record.state, DistributedRegionState::Degraded);
    assert!(cluster.healthy_count() < cluster.record.config.min_quorum);
    let new_leader = cluster.elect_leader().expect("leader after failure");
    assert_ne!(new_leader, leader);
    let write_after_leader_loss = cluster.write_snapshot(&snapshot, Time::from_secs(3));
    assert!(!write_after_leader_loss.quorum_achieved);
    assert!(!cluster.read_quorum_ok());

    test_phase!("Partition Heal");
    cluster
        .record
        .update_replica_status(&follower, ReplicaStatus::Syncing, Time::from_secs(4))
        .unwrap();
    cluster.heal_replica(&follower, Time::from_secs(5));
    cluster.heal_replica(&leader, Time::from_secs(5));
    assert!(cluster.record.has_quorum());
    assert_eq!(cluster.record.state, DistributedRegionState::Degraded);
    cluster
        .record
        .trigger_recovery("e2e-test", Time::from_secs(6))
        .unwrap();
    cluster
        .record
        .complete_recovery(8, Time::from_secs(7))
        .unwrap();
    assert_eq!(cluster.record.state, DistributedRegionState::Active);

    let healed_leader = cluster.elect_leader().expect("leader after heal");
    tracing::info!(leader = %healed_leader, "leader after heal");
    let write_after_heal = cluster.write_snapshot(&snapshot, Time::from_secs(7));
    assert!(write_after_heal.quorum_achieved);
    assert!(cluster.read_quorum_ok());

    test_complete!(
        "e2e_distributed_multi_node_cluster",
        initial_leader = leader,
        healed_leader = healed_leader,
    );
}
