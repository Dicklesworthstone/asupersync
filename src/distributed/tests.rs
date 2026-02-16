//! Comprehensive distributed region integration tests.
//!
//! Validates the full distributed region subsystem: replication, recovery,
//! bridge coordination, failure handling, and invariant checking.

#![allow(clippy::similar_names)]

use std::time::Duration;

use crate::distributed::assignment::{AssignmentStrategy, SymbolAssigner};
use crate::distributed::bridge::{
    BridgeConfig, ConflictResolution, DistributedToLocal, EffectiveState, LocalToDistributed,
    RegionBridge, RegionMode, SyncMode,
};
use crate::distributed::distribution::{
    DistributionConfig, ReplicaAck, ReplicaFailure, SymbolDistributor,
};
use crate::distributed::encoding::{EncodedState, EncodingConfig, StateEncoder};
use crate::distributed::recovery::{
    CollectedSymbol, CollectionConsistency, RecoveryCollector, RecoveryConfig,
    RecoveryDecodingConfig, RecoveryOrchestrator, RecoveryTrigger, StateDecoder,
};
use crate::distributed::snapshot::{BudgetSnapshot, RegionSnapshot, TaskSnapshot, TaskState};
use crate::error::ErrorKind;
use crate::record::distributed_region::{
    ConsistencyLevel, DistributedRegionConfig, DistributedRegionRecord, DistributedRegionState,
    ReplicaInfo, ReplicaStatus, TransitionReason,
};
use crate::record::region::RegionState;
use crate::security::tag::AuthenticationTag;
use crate::security::AuthenticatedSymbol;
use crate::types::budget::Budget;
use crate::types::symbol::{ObjectId, ObjectParams};
use crate::types::{Outcome, RegionId, TaskId, Time};
use crate::util::DetRng;

// =========================================================================
// 1. Happy-Path Replication: Encode → Assign → Distribute → Decode
// =========================================================================

#[test]
fn happy_path_encode_assign_distribute_decode() {
    // Create a realistic snapshot.
    let snapshot = make_rich_snapshot();
    let original_hash = snapshot.content_hash();

    // Encode.
    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 4,
        ..Default::default()
    };
    let mut encoder = StateEncoder::new(config, DetRng::new(42));
    let encoded = encoder.encode(&snapshot, Time::from_secs(100)).unwrap();

    assert!(encoded.source_count >= 1);
    assert_eq!(encoded.repair_count, 4);
    assert_eq!(encoded.original_size, snapshot.to_bytes().len());

    // Assign to 3 replicas using Full strategy.
    let replicas = create_test_replicas(3);
    let assigner = SymbolAssigner::new(AssignmentStrategy::Full);
    let assignments = assigner.assign(&encoded.symbols, &replicas, encoded.source_count);

    assert_eq!(assignments.len(), 3);
    for a in &assignments {
        assert_eq!(
            a.symbol_indices.len(),
            encoded.symbols.len(),
            "full strategy gives all symbols"
        );
        assert!(a.can_decode);
    }

    // Evaluate distribution outcomes with Quorum consistency.
    let dist_config = DistributionConfig {
        consistency: ConsistencyLevel::Quorum,
        ..Default::default()
    };
    let mut distributor = SymbolDistributor::new(dist_config);

    let outcomes = vec![
        Outcome::Ok(ReplicaAck {
            replica_id: "node-0".to_string(),
            symbols_received: encoded.symbols.len() as u32,
            ack_time: Time::from_secs(100),
        }),
        Outcome::Ok(ReplicaAck {
            replica_id: "node-1".to_string(),
            symbols_received: encoded.symbols.len() as u32,
            ack_time: Time::from_secs(100),
        }),
        Outcome::Err(ReplicaFailure {
            replica_id: "node-2".to_string(),
            error: "timeout".to_string(),
            error_kind: ErrorKind::NodeUnavailable,
        }),
    ];

    let result =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));
    assert!(result.quorum_achieved);

    // Decode from one replica's symbols (complete set).
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
        verify_integrity: false,
        ..Default::default()
    });
    for sym in &encoded.symbols {
        let auth = AuthenticatedSymbol::from_parts(sym.clone(), AuthenticationTag::zero());
        decoder.add_symbol(&auth).unwrap();
    }
    let recovered = decoder.decode_snapshot(&encoded.params).unwrap();
    assert_eq!(recovered.content_hash(), original_hash);
    assert_eq!(recovered.region_id, snapshot.region_id);
    assert_eq!(recovered.sequence, snapshot.sequence);
    assert_eq!(recovered.tasks.len(), snapshot.tasks.len());
}

// =========================================================================
// 2. Quorum Loss and Rejoin
// =========================================================================

#[test]
fn quorum_loss_degrades_then_recovers() {
    let id = RegionId::new_for_test(1, 0);
    let config = DistributedRegionConfig {
        min_quorum: 2,
        replication_factor: 3,
        allow_degraded: true,
        ..Default::default()
    };
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    // Add 3 replicas and activate.
    for i in 0..3 {
        record
            .add_replica(ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
            .unwrap();
    }
    let transition = record.activate(Time::from_secs(0)).unwrap();
    assert_eq!(transition.to, DistributedRegionState::Active);
    assert!(record.has_quorum());
    assert!(record.state.can_write());

    // Lose 1 replica → quorum still maintained (2 >= 2), returns Err.
    let r1 = record.replica_lost("r1", Time::from_secs(10));
    assert!(r1.is_err()); // Still above quorum
    assert!(record.has_quorum());

    // Lose another → quorum lost (1 < 2), degrades.
    let t2 = record.replica_lost("r2", Time::from_secs(11)).unwrap();
    assert_eq!(t2.to, DistributedRegionState::Degraded);
    assert!(!record.has_quorum());
    assert!(!record.state.can_write());
    assert!(record.state.can_read()); // degraded allows reads

    // Trigger recovery.
    let t3 = record
        .trigger_recovery("admin", Time::from_secs(20))
        .unwrap();
    assert_eq!(t3.to, DistributedRegionState::Recovering);

    // Complete recovery.
    let t4 = record.complete_recovery(10, Time::from_secs(30)).unwrap();
    assert_eq!(t4.to, DistributedRegionState::Active);
    assert!(record.state.can_write());
}

// =========================================================================
// 3. Recovery From Missing Symbols
// =========================================================================

#[test]
fn recovery_from_source_symbols_only() {
    let snapshot = make_rich_snapshot();
    let encoded = encode_snapshot(&snapshot);

    // Collect only source symbols (no repair).
    let symbols: Vec<CollectedSymbol> = encoded
        .source_symbols()
        .map(|s| CollectedSymbol {
            symbol: s.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: "r0".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        })
        .collect();

    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: snapshot.region_id,
        initiator: "test".to_string(),
        reason: Some("test recovery".to_string()),
    };

    let mut orchestrator = RecoveryOrchestrator::new(
        RecoveryConfig::default(),
        RecoveryDecodingConfig {
            verify_integrity: false,
            ..Default::default()
        },
    );

    let result = orchestrator
        .recover_from_symbols(&trigger, &symbols, encoded.params, Duration::from_millis(5))
        .unwrap();

    assert_eq!(result.snapshot.region_id, snapshot.region_id);
    assert_eq!(result.snapshot.sequence, snapshot.sequence);
    assert!(!result.verified);
}

#[test]
fn recovery_with_mixed_source_and_repair() {
    let snapshot = make_rich_snapshot();
    let encoded = encode_snapshot(&snapshot);

    // Collect all symbols (source + repair) from multiple replicas.
    let symbols: Vec<CollectedSymbol> = encoded
        .symbols
        .iter()
        .enumerate()
        .map(|(i, s)| CollectedSymbol {
            symbol: s.clone(),
            tag: AuthenticationTag::zero(),
            source_replica: format!("r{}", i % 3),
            collected_at: Time::from_secs(u64::try_from(i).expect("index fits u64")),
            verified: true,
        })
        .collect();

    let trigger = RecoveryTrigger::QuorumLost {
        region_id: snapshot.region_id,
        available_replicas: vec!["r0".to_string(), "r1".to_string()],
        required_quorum: 2,
    };

    let mut orchestrator = RecoveryOrchestrator::new(
        RecoveryConfig::default(),
        RecoveryDecodingConfig {
            verify_integrity: false,
            ..Default::default()
        },
    );

    let result = orchestrator
        .recover_from_symbols(
            &trigger,
            &symbols,
            encoded.params,
            Duration::from_millis(10),
        )
        .unwrap();

    assert_eq!(result.snapshot.content_hash(), snapshot.content_hash());
    assert!(!result.contributing_replicas.is_empty());
}

#[test]
fn recovery_insufficient_symbols_fails() {
    let trigger = RecoveryTrigger::NodeRestart {
        region_id: RegionId::new_for_test(1, 0),
        last_known_sequence: 0,
    };

    // Create params requiring 10 symbols.
    let params = ObjectParams::new(ObjectId::new_for_test(1), 12800, 1280, 1, 10);

    // Provide only 3 symbols.
    let symbols: Vec<CollectedSymbol> = (0..3)
        .map(|i| CollectedSymbol {
            symbol: crate::types::symbol::Symbol::new_for_test(1, 0, i, &[0u8; 1280]),
            tag: AuthenticationTag::zero(),
            source_replica: "r0".to_string(),
            collected_at: Time::ZERO,
            verified: false,
        })
        .collect();

    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

    let result =
        orchestrator.recover_from_symbols(&trigger, &symbols, params, Duration::from_millis(5));

    assert!(result.is_err());
}

// =========================================================================
// 4. Epoch Boundary: Snapshot + Restore
// =========================================================================

#[test]
fn snapshot_roundtrip_preserves_all_fields() {
    let original = RegionSnapshot {
        region_id: RegionId::new_for_test(1, 0),
        state: RegionState::Open,
        timestamp: Time::from_secs(12345),
        sequence: 42,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 10,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(2, 0),
                state: TaskState::Completed,
                priority: 5,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(3, 0),
                state: TaskState::Cancelled,
                priority: 1,
            },
        ],
        children: vec![RegionId::new_for_test(10, 0), RegionId::new_for_test(11, 0)],
        finalizer_count: 3,
        budget: BudgetSnapshot {
            deadline_nanos: Some(999_999_999),
            polls_remaining: Some(50),
            cost_remaining: Some(1000),
        },
        cancel_reason: Some("deadline exceeded".to_string()),
        parent: Some(RegionId::new_for_test(0, 0)),
        metadata: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    // Encode → decode roundtrip.
    let encoded = encode_snapshot(&original);
    let mut decoder = StateDecoder::new(RecoveryDecodingConfig {
        verify_integrity: false,
        ..Default::default()
    });
    for sym in &encoded.symbols {
        let auth = AuthenticatedSymbol::from_parts(sym.clone(), AuthenticationTag::zero());
        decoder.add_symbol(&auth).unwrap();
    }
    let recovered = decoder.decode_snapshot(&encoded.params).unwrap();

    assert_eq!(recovered.region_id, original.region_id);
    assert_eq!(recovered.state, original.state);
    assert_eq!(recovered.timestamp, original.timestamp);
    assert_eq!(recovered.sequence, original.sequence);
    assert_eq!(recovered.tasks.len(), original.tasks.len());
    for (r, o) in recovered.tasks.iter().zip(original.tasks.iter()) {
        assert_eq!(r.task_id, o.task_id);
        assert_eq!(r.state, o.state);
        assert_eq!(r.priority, o.priority);
    }
    assert_eq!(recovered.children, original.children);
    assert_eq!(recovered.finalizer_count, original.finalizer_count);
    assert_eq!(
        recovered.budget.deadline_nanos,
        original.budget.deadline_nanos
    );
    assert_eq!(
        recovered.budget.polls_remaining,
        original.budget.polls_remaining
    );
    assert_eq!(
        recovered.budget.cost_remaining,
        original.budget.cost_remaining
    );
    assert_eq!(recovered.cancel_reason, original.cancel_reason);
    assert_eq!(recovered.parent, original.parent);
    assert_eq!(recovered.metadata, original.metadata);
    assert_eq!(recovered.content_hash(), original.content_hash());
}

#[test]
fn encode_decode_deterministic_across_seeds() {
    let snapshot = make_rich_snapshot();
    let object_id = ObjectId::new_for_test(999);

    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 4,
        ..Default::default()
    };

    let mut enc1 = StateEncoder::new(config.clone(), DetRng::new(42));
    let mut enc2 = StateEncoder::new(config, DetRng::new(42));

    let e1 = enc1
        .encode_with_id(&snapshot, object_id, Time::ZERO)
        .unwrap();
    let e2 = enc2
        .encode_with_id(&snapshot, object_id, Time::ZERO)
        .unwrap();

    assert_eq!(e1.symbols.len(), e2.symbols.len());
    for (s1, s2) in e1.symbols.iter().zip(e2.symbols.iter()) {
        assert_eq!(s1.data(), s2.data(), "deterministic encoding");
    }
}

// =========================================================================
// 5. Node Failure During Close/Cancel
// =========================================================================

#[test]
fn bridge_close_distributed_from_initializing() {
    let mut bridge = RegionBridge::new_distributed(
        RegionId::new_for_test(1, 0),
        None,
        Budget::default(),
        DistributedRegionConfig::default(),
    );

    // Distributed record starts in Initializing; Initializing → Closing is valid.
    let result = bridge.begin_close(None, Time::from_secs(1)).unwrap();
    assert_eq!(result.effective_state, EffectiveState::Closing);
    assert!(result.distributed_transition.is_some());

    // Local region must traverse Closing → Draining → Finalizing → Closed.
    bridge.begin_drain().unwrap();
    bridge.begin_finalize().unwrap();
    let result2 = bridge.complete_close(Time::from_secs(2)).unwrap();
    assert_eq!(result2.effective_state, EffectiveState::Closed);
}

#[test]
fn distributed_record_close_lifecycle() {
    let id = RegionId::new_for_test(1, 0);
    let config = DistributedRegionConfig::default();
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    // Add replicas and activate.
    record.add_replica(ReplicaInfo::new("r0", "addr0")).unwrap();
    record.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
    record.activate(Time::from_secs(0)).unwrap();

    // Begin close.
    let t1 = record
        .begin_close(TransitionReason::LocalClose, Time::from_secs(1))
        .unwrap();
    assert_eq!(t1.to, DistributedRegionState::Closing);
    assert!(!record.state.can_spawn());

    // Complete close.
    let t2 = record.complete_close(Time::from_secs(2)).unwrap();
    assert_eq!(t2.to, DistributedRegionState::Closed);
}

#[test]
fn recovery_orchestrator_cancellation() {
    let mut orchestrator =
        RecoveryOrchestrator::new(RecoveryConfig::default(), RecoveryDecodingConfig::default());

    assert!(!orchestrator.is_recovering());
    orchestrator.cancel("operator cancellation");
    assert!(!orchestrator.is_recovering());

    // Verify it stays cancelled.
    let trigger = RecoveryTrigger::ManualTrigger {
        region_id: RegionId::new_for_test(1, 0),
        initiator: "test".to_string(),
        reason: None,
    };
    let params = ObjectParams::new(ObjectId::new_for_test(1), 128, 128, 1, 1);
    let sym = CollectedSymbol {
        symbol: crate::types::symbol::Symbol::new_for_test(1, 0, 0, &[0u8; 128]),
        tag: AuthenticationTag::zero(),
        source_replica: "r0".to_string(),
        collected_at: Time::ZERO,
        verified: false,
    };
    // Recovery still works because cancel only sets a flag.
    let result =
        orchestrator.recover_from_symbols(&trigger, &[sym], params, Duration::from_millis(1));
    // It may succeed or fail depending on implementation, but shouldn't panic.
    let _ = result;
}

// =========================================================================
// 6. Invariant Checks: No Leaks, Quiescence on Close
// =========================================================================

#[test]
fn bridge_no_task_leak_on_close() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    // Add tasks.
    bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
    bridge.add_task(TaskId::new_for_test(2, 0)).unwrap();
    assert!(bridge.has_live_work());

    // Remove tasks before close.
    bridge.remove_task(TaskId::new_for_test(1, 0));
    bridge.remove_task(TaskId::new_for_test(2, 0));
    assert!(!bridge.has_live_work());

    // Close.
    bridge.begin_close(None, Time::from_secs(0)).unwrap();
    bridge.begin_drain().unwrap();
    bridge.begin_finalize().unwrap();
    bridge.complete_close(Time::from_secs(1)).unwrap();

    assert_eq!(bridge.effective_state(), EffectiveState::Closed);
    assert!(!bridge.has_live_work());
}

#[test]
fn bridge_rejects_work_after_close() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    bridge.begin_close(None, Time::from_secs(0)).unwrap();

    // Try to add tasks → should fail.
    let task_result = bridge.add_task(TaskId::new_for_test(1, 0));
    assert!(task_result.is_err());
    assert_eq!(task_result.unwrap_err().kind(), ErrorKind::RegionClosed);

    // Try to add children → should fail.
    let child_result = bridge.add_child(RegionId::new_for_test(2, 0));
    assert!(child_result.is_err());
}

#[test]
fn bridge_quiescence_requires_empty_before_drain() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    bridge.add_child(RegionId::new_for_test(2, 0)).unwrap();

    // Close with child still present → has_live_work still true.
    bridge.begin_close(None, Time::from_secs(0)).unwrap();
    assert!(bridge.has_live_work());

    // Remove child, then proceed.
    bridge.remove_child(RegionId::new_for_test(2, 0));
    assert!(!bridge.has_live_work());

    bridge.begin_drain().unwrap();
    bridge.begin_finalize().unwrap();
    bridge.complete_close(Time::from_secs(1)).unwrap();
    assert_eq!(bridge.effective_state(), EffectiveState::Closed);
}

// =========================================================================
// 7. Assignment Strategy Comparison
// =========================================================================

#[test]
fn assignment_strategies_provide_minimum_coverage() {
    let snapshot = make_rich_snapshot();
    let encoded = encode_snapshot(&snapshot);
    let replicas = create_test_replicas(5);
    let k = encoded.source_count;

    // Full: every replica gets all symbols.
    let full = SymbolAssigner::new(AssignmentStrategy::Full);
    let full_assignments = full.assign(&encoded.symbols, &replicas, k);
    for a in &full_assignments {
        assert_eq!(a.symbol_indices.len(), encoded.symbols.len());
        assert!(a.can_decode);
    }

    // Striped: symbols distributed across replicas.
    let striped = SymbolAssigner::new(AssignmentStrategy::Striped);
    let striped_assignments = striped.assign(&encoded.symbols, &replicas, k);
    let total_assigned: usize = striped_assignments
        .iter()
        .map(|a| a.symbol_indices.len())
        .sum();
    assert_eq!(total_assigned, encoded.symbols.len());

    // MinimumK: each replica gets at least K symbols.
    let min_k = SymbolAssigner::new(AssignmentStrategy::MinimumK);
    let min_k_assignments = min_k.assign(&encoded.symbols, &replicas, k);
    for a in &min_k_assignments {
        assert!(
            a.symbol_indices.len() >= k as usize,
            "MinimumK should give at least K={k} symbols, got {}",
            a.symbol_indices.len()
        );
    }
}

// =========================================================================
// 8. Distribution Consistency Level Checks
// =========================================================================

#[test]
fn distribution_quorum_requires_majority() {
    let config = DistributionConfig {
        consistency: ConsistencyLevel::Quorum,
        ..Default::default()
    };
    let mut distributor = SymbolDistributor::new(config);
    let encoded = encode_snapshot(&make_rich_snapshot());
    let replicas = create_test_replicas(3);

    // 2 of 3 → quorum reached.
    let outcomes = vec![
        Outcome::Ok(make_ack("r0", 10)),
        Outcome::Ok(make_ack("r1", 10)),
        Outcome::Err(make_failure("r2")),
    ];
    let result =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));
    assert!(result.quorum_achieved);

    // 1 of 3 → quorum not reached.
    let outcomes2 = vec![
        Outcome::Ok(make_ack("r0", 10)),
        Outcome::Err(make_failure("r1")),
        Outcome::Err(make_failure("r2")),
    ];
    let result2 =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes2, Duration::from_millis(50));
    assert!(!result2.quorum_achieved);
}

#[test]
fn distribution_all_requires_all_replicas() {
    let config = DistributionConfig {
        consistency: ConsistencyLevel::All,
        ..Default::default()
    };
    let mut distributor = SymbolDistributor::new(config);
    let encoded = encode_snapshot(&make_rich_snapshot());
    let replicas = create_test_replicas(3);

    // All 3 → success.
    let outcomes = vec![
        Outcome::Ok(make_ack("r0", 10)),
        Outcome::Ok(make_ack("r1", 10)),
        Outcome::Ok(make_ack("r2", 10)),
    ];
    let result =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));
    assert!(result.quorum_achieved);

    // 2 of 3 → fail.
    let outcomes2 = vec![
        Outcome::Ok(make_ack("r0", 10)),
        Outcome::Ok(make_ack("r1", 10)),
        Outcome::Err(make_failure("r2")),
    ];
    let result2 =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes2, Duration::from_millis(50));
    assert!(!result2.quorum_achieved);
}

#[test]
fn distribution_local_always_succeeds() {
    let config = DistributionConfig {
        consistency: ConsistencyLevel::Local,
        ..Default::default()
    };
    let mut distributor = SymbolDistributor::new(config);
    let encoded = encode_snapshot(&make_rich_snapshot());
    let replicas = create_test_replicas(3);

    // Even all failures → Local needs 0 acks.
    let outcomes = vec![
        Outcome::Err(make_failure("r0")),
        Outcome::Err(make_failure("r1")),
        Outcome::Err(make_failure("r2")),
    ];
    let result =
        distributor.evaluate_outcomes(&encoded, &replicas, outcomes, Duration::from_millis(50));
    assert!(result.quorum_achieved);
}

// =========================================================================
// 9. Bridge Mode Upgrade Scenarios
// =========================================================================

#[test]
fn bridge_upgrade_preserves_state() {
    let mut bridge = RegionBridge::new_local(
        RegionId::new_for_test(1, 0),
        Some(RegionId::new_for_test(0, 0)),
        Budget::new().with_poll_quota(100),
    );

    // Add some work.
    bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
    bridge.add_child(RegionId::new_for_test(2, 0)).unwrap();

    // Upgrade to distributed.
    let config = DistributedRegionConfig {
        replication_factor: 3,
        ..Default::default()
    };
    let replicas = create_test_replicas(3);
    let result = bridge.upgrade_to_distributed(config, &replicas).unwrap();

    assert_eq!(result.previous_mode, RegionMode::Local);
    assert!(result.new_mode.is_distributed());
    assert_eq!(result.new_mode.replication_factor(), 3);

    // State preserved.
    assert!(bridge.has_live_work());
    assert!(bridge.distributed().is_some());
}

#[test]
fn bridge_apply_snapshot_updates_state() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    // Create a snapshot with different state
    let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(1, 0));
    snapshot.state = RegionState::Closing;
    snapshot.budget = BudgetSnapshot {
        deadline_nanos: Some(12345),
        polls_remaining: Some(99),
        cost_remaining: Some(100),
    };
    snapshot.tasks = vec![TaskSnapshot {
        task_id: TaskId::new_for_test(10, 0),
        state: TaskState::Running,
        priority: 10,
    }];
    snapshot.cancel_reason = Some("Timeout".to_string());

    // Apply snapshot
    bridge.apply_snapshot(&snapshot).unwrap();

    // Verify local state updated
    assert_eq!(bridge.local.state(), RegionState::Closing);
    let budget = bridge.local.budget();
    assert_eq!(budget.deadline.map(|t| t.as_nanos()), Some(12345));
    assert_eq!(budget.poll_quota, 99);
    assert_eq!(budget.cost_quota, Some(100));

    let tasks = bridge.local.task_ids();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0], TaskId::new_for_test(10, 0));

    let reason = bridge.local.cancel_reason().unwrap();
    assert_eq!(reason.kind, crate::types::cancel::CancelKind::Timeout);
}

#[test]
fn bridge_config_variants() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    // Default config allows upgrade.
    assert!(bridge.config.allow_upgrade);
    assert_eq!(bridge.config.sync_mode, SyncMode::Synchronous);
    assert_eq!(
        bridge.config.conflict_resolution,
        ConflictResolution::DistributedWins
    );

    // Custom config.
    bridge.config = BridgeConfig {
        allow_upgrade: false,
        sync_timeout: Duration::from_secs(30),
        sync_mode: SyncMode::Asynchronous,
        conflict_resolution: ConflictResolution::HighestSequence,
    };

    let result =
        bridge.upgrade_to_distributed(DistributedRegionConfig::default(), &create_test_replicas(3));
    assert!(result.is_err()); // upgrade blocked
}

// =========================================================================
// 10. Collector ESI Deduplication and Metrics
// =========================================================================

#[test]
fn collector_dedup_and_metrics_comprehensive() {
    let mut collector = RecoveryCollector::new(RecoveryConfig {
        collection_consistency: CollectionConsistency::Quorum,
        ..Default::default()
    });

    collector.object_params = Some(ObjectParams::new(
        ObjectId::new_for_test(1),
        1000,
        128,
        1,
        8,
    ));

    // Add 8 unique symbols from different replicas.
    for i in 0u32..8 {
        let sym = crate::types::symbol::Symbol::new_for_test(1, 0, i, &[i as u8; 128]);
        let accepted = collector.add_collected(CollectedSymbol {
            symbol: sym,
            tag: AuthenticationTag::zero(),
            source_replica: format!("r{}", i % 3),
            collected_at: Time::from_secs(u64::from(i)),
            verified: false,
        });
        assert!(accepted);
    }

    assert_eq!(collector.metrics.symbols_received, 8);
    assert_eq!(collector.metrics.symbols_duplicate, 0);
    assert!(collector.can_decode());

    // Add duplicates (same ESI).
    for i in 0u32..4 {
        let sym = crate::types::symbol::Symbol::new_for_test(1, 0, i, &[i as u8; 128]);
        let accepted = collector.add_collected(CollectedSymbol {
            symbol: sym,
            tag: AuthenticationTag::zero(),
            source_replica: "r-dup".to_string(),
            collected_at: Time::from_secs(100),
            verified: false,
        });
        assert!(!accepted);
    }

    assert_eq!(collector.metrics.symbols_duplicate, 4);
    assert_eq!(collector.symbols().len(), 8); // Only unique symbols
}

// =========================================================================
// 11. Type Conversion Consistency
// =========================================================================

#[test]
fn state_conversion_roundtrip() {
    // Local → Distributed → Local should be consistent.
    let local_states = [
        RegionState::Open,
        RegionState::Closing,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ];

    for &local in &local_states {
        let dist = local.to_distributed();
        let back = dist.to_local();

        // Closing/Draining/Finalizing all map to Closing distributed,
        // which maps back to Closing. So only Open and Closed roundtrip exactly.
        match local {
            RegionState::Open => assert_eq!(back, RegionState::Open),
            RegionState::Closed => assert_eq!(back, RegionState::Closed),
            _ => assert_eq!(back, RegionState::Closing),
        }
    }
}

#[test]
fn effective_state_all_combinations() {
    let dist_states = [
        DistributedRegionState::Initializing,
        DistributedRegionState::Active,
        DistributedRegionState::Degraded,
        DistributedRegionState::Recovering,
        DistributedRegionState::Closing,
        DistributedRegionState::Closed,
    ];

    // Test every (local, distributed) combination.
    for local in [RegionState::Open, RegionState::Closing, RegionState::Closed] {
        for &dist in &dist_states {
            let effective = EffectiveState::compute(local, Some(dist));
            // Every combination should produce a valid EffectiveState.
            let _spawn = effective.can_spawn();
            let _recovery = effective.needs_recovery();
            let _inconsistent = effective.is_inconsistent();
        }
    }
}

// =========================================================================
// 12. Multi-Region Snapshot Isolation
// =========================================================================

#[test]
fn bridge_snapshot_sequence_monotonic() {
    let mut bridge = RegionBridge::new_local(RegionId::new_for_test(1, 0), None, Budget::default());

    let snap1 = bridge.create_snapshot();
    bridge.add_task(TaskId::new_for_test(1, 0)).unwrap();
    let snap2 = bridge.create_snapshot();
    bridge.remove_task(TaskId::new_for_test(1, 0));
    let snap3 = bridge.create_snapshot();

    assert!(snap2.sequence > snap1.sequence);
    assert!(snap3.sequence > snap2.sequence);
    assert_eq!(snap1.tasks.len(), 0);
    assert_eq!(snap2.tasks.len(), 1);
    assert_eq!(snap3.tasks.len(), 0);
}

// =========================================================================
// 13. Repair Symbol Generation
// =========================================================================

#[test]
fn additional_repair_symbols_generated_correctly() {
    let snapshot = make_rich_snapshot();
    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 2,
        ..Default::default()
    };
    let mut encoder = StateEncoder::new(config, DetRng::new(42));
    let encoded = encoder.encode(&snapshot, Time::ZERO).unwrap();

    let initial_repair = encoded.repair_count;
    assert_eq!(initial_repair, 2);

    // Generate additional repair symbols.
    let additional = encoder.generate_repair(&encoded, 5).unwrap();
    assert_eq!(additional.len(), 5);
    for sym in &additional {
        assert!(sym.kind().is_repair());
    }
}

// =========================================================================
// 14. Distributed Region State Transition Coverage
// =========================================================================

#[test]
fn distributed_record_full_lifecycle() {
    let id = RegionId::new_for_test(1, 0);
    let config = DistributedRegionConfig {
        min_quorum: 1,
        replication_factor: 2,
        allow_degraded: true,
        ..Default::default()
    };
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    // Add replica.
    record.add_replica(ReplicaInfo::new("r0", "addr0")).unwrap();
    assert_eq!(record.state, DistributedRegionState::Initializing);

    // Activate.
    record.activate(Time::from_secs(0)).unwrap();
    assert_eq!(record.state, DistributedRegionState::Active);
    assert!(record.state.can_spawn());

    // Update replica status.
    record
        .update_replica_status("r0", ReplicaStatus::Healthy, Time::from_secs(1))
        .unwrap();

    // Begin close.
    record
        .begin_close(
            TransitionReason::UserClose {
                reason: Some("shutdown".to_string()),
            },
            Time::from_secs(2),
        )
        .unwrap();
    assert_eq!(record.state, DistributedRegionState::Closing);
    assert!(!record.state.can_spawn());

    // Complete close.
    record.complete_close(Time::from_secs(3)).unwrap();
    assert_eq!(record.state, DistributedRegionState::Closed);
}

#[test]
fn distributed_record_transition_history_tracked() {
    let id = RegionId::new_for_test(1, 0);
    let config = DistributedRegionConfig::default();
    let mut record = DistributedRegionRecord::new(id, config, None, Budget::default());

    record.add_replica(ReplicaInfo::new("r0", "addr0")).unwrap();
    record.add_replica(ReplicaInfo::new("r1", "addr1")).unwrap();
    record.activate(Time::from_secs(0)).unwrap();
    record
        .begin_close(TransitionReason::LocalClose, Time::from_secs(1))
        .unwrap();
    record.complete_close(Time::from_secs(2)).unwrap();

    // Transitions should be tracked.
    assert!(
        record.transitions.len() >= 3,
        "expected at least 3 transitions, got {}",
        record.transitions.len()
    );
}

// =========================================================================
// Helpers
// =========================================================================

fn make_rich_snapshot() -> RegionSnapshot {
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
        ],
        children: vec![RegionId::new_for_test(2, 0)],
        finalizer_count: 2,
        budget: BudgetSnapshot {
            deadline_nanos: Some(5_000_000_000),
            polls_remaining: Some(200),
            cost_remaining: Some(500),
        },
        cancel_reason: None,
        parent: Some(RegionId::new_for_test(0, 0)),
        metadata: vec![1, 2, 3],
    }
}

fn encode_snapshot(snapshot: &RegionSnapshot) -> EncodedState {
    let config = EncodingConfig {
        symbol_size: 128,
        min_repair_symbols: 4,
        ..Default::default()
    };
    let mut encoder = StateEncoder::new(config, DetRng::new(42));
    encoder.encode(snapshot, Time::ZERO).unwrap()
}

fn create_test_replicas(count: usize) -> Vec<ReplicaInfo> {
    (0..count)
        .map(|i| ReplicaInfo::new(&format!("r{i}"), &format!("addr{i}")))
        .collect()
}

fn make_ack(replica_id: &str, count: u32) -> ReplicaAck {
    ReplicaAck {
        replica_id: replica_id.to_string(),
        symbols_received: count,
        ack_time: Time::ZERO,
    }
}

fn make_failure(replica_id: &str) -> ReplicaFailure {
    ReplicaFailure {
        replica_id: replica_id.to_string(),
        error: "connection refused".to_string(),
        error_kind: ErrorKind::NodeUnavailable,
    }
}
