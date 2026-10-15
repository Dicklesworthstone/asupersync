//! Owned runtime-snapshot codec and migration composition contract.
//!
//! Bead: asupersync-5z2scg.3.3
//! Capabilities: CAP-PERSISTED-TRACE-SNAPSHOT, CAP-SERDE-GENERIC
//!
//! This exercises the public full/incremental codec, legacy JSON migration,
//! bounded malformed input, and composition with the cancel-safe atomic
//! filesystem staging boundary. It does not claim historical external corpus
//! coverage, broad trace-format migration, or dependency cutover.

#![allow(missing_docs)]

use asupersync::lab::{
    RestorableSnapshot, SNAPSHOT_ARTIFACT_MAGIC, SNAPSHOT_ARTIFACT_VERSION, SnapshotArtifact,
    SnapshotArtifactKind, SnapshotCodecError, SnapshotLimits,
};
use asupersync::runtime::RuntimeSnapshot;
use asupersync::runtime::state::{
    BudgetSnapshot, EventDataSnapshot, EventKindSnapshot, EventSnapshot, FinalizerHistoryEvent,
    IdSnapshot, LoserDrainHistoryEvent, ObligationKindSnapshot, ObligationSnapshot,
    ObligationStateSnapshot, RegionSnapshot, RegionStateSnapshot, TaskSnapshot, TaskStateSnapshot,
};
use asupersync::types::{RegionId, TaskId, Time};
use proptest::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(feature = "test-internals")]
use std::sync::Arc;
#[cfg(feature = "test-internals")]
use std::time::Duration;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

fn id(index: u32) -> IdSnapshot {
    IdSnapshot {
        index,
        generation: 0,
    }
}

fn region(index: u32, parent: Option<u32>, child_count: usize) -> RegionSnapshot {
    RegionSnapshot {
        id: id(index),
        parent_id: parent.map(id),
        state: RegionStateSnapshot::Open,
        budget: BudgetSnapshot {
            deadline: Some(10_000),
            poll_quota: 1_000,
            cost_quota: Some(5_000),
            priority: 7,
        },
        child_count,
        task_count: 0,
        name: Some(format!("region-{index}")),
    }
}

fn runtime_snapshot(timestamp: u64, regions: Vec<RegionSnapshot>) -> RuntimeSnapshot {
    RuntimeSnapshot {
        timestamp,
        regions,
        tasks: Vec::new(),
        obligations: Vec::new(),
        recent_events: Vec::new(),
        finalizer_history: Vec::new(),
        loser_drain_history: Vec::new(),
    }
}

fn populated_runtime_snapshot(timestamp: u64) -> RuntimeSnapshot {
    let region_id = id(1);
    let task_id = id(10);
    let obligation_id = id(20);
    let mut root = region(1, None, 0);
    root.task_count = 1;

    RuntimeSnapshot {
        timestamp,
        regions: vec![root],
        tasks: vec![TaskSnapshot {
            id: task_id,
            region_id,
            state: TaskStateSnapshot::Running,
            name: Some("snapshot-worker".to_owned()),
            poll_count: 17,
            created_at: timestamp - 5,
            obligations: vec![obligation_id],
        }],
        obligations: vec![ObligationSnapshot {
            id: obligation_id,
            kind: ObligationKindSnapshot::Ack,
            state: ObligationStateSnapshot::Committed,
            holder_task: task_id,
            owning_region: region_id,
            created_at: timestamp - 4,
        }],
        recent_events: vec![
            EventSnapshot {
                version: 1,
                seq: 2,
                time: timestamp - 2,
                kind: EventKindSnapshot::ObligationCommit,
                data: EventDataSnapshot::Obligation {
                    obligation: obligation_id,
                    task: task_id,
                    region: region_id,
                    kind: ObligationKindSnapshot::Ack,
                    state: ObligationStateSnapshot::Committed,
                    duration_ns: Some(2),
                    abort_reason: None,
                },
            },
            EventSnapshot {
                version: 1,
                seq: 1,
                time: timestamp - 3,
                kind: EventKindSnapshot::Spawn,
                data: EventDataSnapshot::Task {
                    task: task_id,
                    region: region_id,
                },
            },
        ],
        finalizer_history: vec![
            FinalizerHistoryEvent::Registered {
                id: 7,
                region: RegionId::new_for_test(1, 0),
                time: Time::from_nanos(timestamp - 3),
            },
            FinalizerHistoryEvent::Ran {
                id: 7,
                time: Time::from_nanos(timestamp - 1),
            },
        ],
        loser_drain_history: vec![
            LoserDrainHistoryEvent::RaceStarted {
                race_id: 9,
                region: RegionId::new_for_test(1, 0),
                participants: vec![TaskId::new_for_test(10, 0)],
                time: Time::from_nanos(timestamp - 3),
            },
            LoserDrainHistoryEvent::TaskCompleted {
                task: TaskId::new_for_test(10, 0),
                time: Time::from_nanos(timestamp - 1),
            },
            LoserDrainHistoryEvent::RaceCompleted {
                race_id: 9,
                winner: TaskId::new_for_test(10, 0),
                time: Time::from_nanos(timestamp),
            },
        ],
    }
}

fn legacy_snapshot(snapshot: RuntimeSnapshot) -> RestorableSnapshot {
    let mut hash = FNV_OFFSET;
    for byte in 1u32.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    for byte in serde_json::to_vec(&snapshot).expect("legacy snapshot JSON") {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    RestorableSnapshot {
        snapshot,
        schema_version: 1,
        content_hash: hash,
    }
}

fn semantic_json<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("snapshot value must serialize")
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[test]
fn full_envelope_is_byte_deterministic_and_reads_legacy_json() {
    let left = RestorableSnapshot::new(runtime_snapshot(
        99,
        vec![region(2, Some(1), 0), region(1, None, 1)],
    ));
    let right = RestorableSnapshot::new(runtime_snapshot(
        99,
        vec![region(1, None, 1), region(2, Some(1), 0)],
    ));
    assert_eq!(left.content_hash, right.content_hash);

    let left_bytes = SnapshotArtifact::full(left.clone(), SnapshotLimits::DEFAULT)
        .expect("valid full artifact")
        .to_bytes()
        .expect("encode full artifact");
    let right_bytes = SnapshotArtifact::full(right, SnapshotLimits::DEFAULT)
        .expect("valid full artifact")
        .to_bytes()
        .expect("encode full artifact");
    assert_eq!(left_bytes, right_bytes);
    assert_eq!(&left_bytes[..8], &SNAPSHOT_ARTIFACT_MAGIC);
    assert_eq!(
        u16::from_le_bytes(left_bytes[8..10].try_into().expect("version slice")),
        SNAPSHOT_ARTIFACT_VERSION
    );

    // This exact-byte golden freezes the new owned envelope, canonical entity
    // order, schema-v2 JSON payload, and SHA-256 payload checksum.
    assert_eq!(
        hex(&left_bytes),
        "41535550534e4150010000005402000000000000be11730b6f396de26bf907c604d2360effd03777342ce0139cc2e2afb33012157b22736e617073686f74223a7b2274696d657374616d70223a39392c22726567696f6e73223a5b7b226964223a7b22696e646578223a312c2267656e65726174696f6e223a307d2c22706172656e745f6964223a6e756c6c2c227374617465223a224f70656e222c22627564676574223a7b22646561646c696e65223a31303030302c22706f6c6c5f71756f7461223a313030302c22636f73745f71756f7461223a353030302c227072696f72697479223a377d2c226368696c645f636f756e74223a312c227461736b5f636f756e74223a302c226e616d65223a22726567696f6e2d31227d2c7b226964223a7b22696e646578223a322c2267656e65726174696f6e223a307d2c22706172656e745f6964223a7b22696e646578223a312c2267656e65726174696f6e223a307d2c227374617465223a224f70656e222c22627564676574223a7b22646561646c696e65223a31303030302c22706f6c6c5f71756f7461223a313030302c22636f73745f71756f7461223a353030302c227072696f72697479223a377d2c226368696c645f636f756e74223a302c227461736b5f636f756e74223a302c226e616d65223a22726567696f6e2d32227d5d2c227461736b73223a5b5d2c226f626c69676174696f6e73223a5b5d2c22726563656e745f6576656e7473223a5b5d2c2266696e616c697a65725f686973746f7279223a5b5d2c226c6f7365725f647261696e5f686973746f7279223a5b5d7d2c22736368656d615f76657273696f6e223a322c22636f6e74656e745f68617368223a353634343531333035353133353832333835357d"
    );

    let decoded = SnapshotArtifact::from_bytes(&left_bytes).expect("decode full artifact");
    assert_eq!(decoded.kind(), SnapshotArtifactKind::Full);
    let materialized = decoded
        .materialize(None, SnapshotLimits::DEFAULT)
        .expect("materialize full artifact");
    assert_eq!(semantic_json(&materialized), semantic_json(&left));

    let legacy = legacy_snapshot(runtime_snapshot(7, vec![region(4, None, 0)]));
    let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy JSON bytes");
    let decoded_legacy =
        SnapshotArtifact::from_bytes(&legacy_bytes).expect("read legacy schema-v1 JSON");
    let legacy_materialized = decoded_legacy
        .materialize(None, SnapshotLimits::DEFAULT)
        .expect("materialize legacy snapshot");
    assert_eq!(legacy_materialized.schema_version, 1);
    assert_eq!(semantic_json(&legacy_materialized), semantic_json(&legacy));
    let migrated = legacy_materialized
        .migrate_to_current()
        .expect("explicit migration to current schema");
    assert_eq!(migrated.schema_version, RestorableSnapshot::SCHEMA_VERSION);
    assert_ne!(migrated.content_hash, legacy.content_hash);
    assert_eq!(
        semantic_json(&migrated.snapshot),
        semantic_json(&legacy.snapshot)
    );
}

#[test]
fn incremental_envelope_materializes_exact_target_and_fences_base() {
    let base = RestorableSnapshot::new(runtime_snapshot(10, vec![region(1, None, 0)]));
    let target = RestorableSnapshot::new(runtime_snapshot(
        20,
        vec![region(2, Some(1), 0), region(1, None, 1)],
    ));
    let artifact = SnapshotArtifact::incremental(&base, &target, SnapshotLimits::DEFAULT)
        .expect("build incremental artifact");
    assert_eq!(artifact.kind(), SnapshotArtifactKind::Incremental);

    let bytes = artifact.to_bytes().expect("encode incremental");
    let decoded = SnapshotArtifact::from_bytes(&bytes).expect("decode incremental");
    let materialized = decoded
        .materialize(Some(&base), SnapshotLimits::DEFAULT)
        .expect("apply incremental");
    assert_eq!(semantic_json(&materialized), semantic_json(&target));

    let wrong_base = RestorableSnapshot::new(runtime_snapshot(11, Vec::new()));
    assert!(matches!(
        decoded.materialize(Some(&wrong_base), SnapshotLimits::DEFAULT),
        Err(SnapshotCodecError::BaseHashMismatch { .. })
    ));
    assert!(matches!(
        decoded.materialize(None, SnapshotLimits::DEFAULT),
        Err(SnapshotCodecError::MissingBase)
    ));

    let reduced = RestorableSnapshot::new(runtime_snapshot(30, vec![region(1, None, 0)]));
    let removal = SnapshotArtifact::incremental(&target, &reduced, SnapshotLimits::DEFAULT)
        .expect("build removal delta");
    let materialized = removal
        .materialize(Some(&target), SnapshotLimits::DEFAULT)
        .expect("apply removal delta");
    assert_eq!(semantic_json(&materialized), semantic_json(&reduced));
}

#[test]
fn full_and_incremental_artifacts_preserve_every_runtime_snapshot_field() {
    let base = RestorableSnapshot::new(populated_runtime_snapshot(100));
    let full = SnapshotArtifact::full(base.clone(), SnapshotLimits::DEFAULT)
        .expect("build populated full artifact");
    let decoded = SnapshotArtifact::from_bytes(&full.to_bytes().expect("encode populated state"))
        .expect("decode populated state")
        .materialize(None, SnapshotLimits::DEFAULT)
        .expect("materialize populated state");
    assert_eq!(semantic_json(&decoded), semantic_json(&base));

    let mut changed_state = populated_runtime_snapshot(200);
    changed_state.tasks[0].poll_count = 23;
    changed_state.obligations[0].state = ObligationStateSnapshot::Aborted;
    changed_state.recent_events.truncate(1);
    changed_state.finalizer_history.truncate(1);
    changed_state.loser_drain_history.truncate(2);
    let target = RestorableSnapshot::new(changed_state);
    let delta = SnapshotArtifact::incremental(&base, &target, SnapshotLimits::DEFAULT)
        .expect("build populated delta");
    let materialized =
        SnapshotArtifact::from_bytes(&delta.to_bytes().expect("encode populated delta"))
            .expect("decode populated delta")
            .materialize(Some(&base), SnapshotLimits::DEFAULT)
            .expect("materialize populated delta");
    assert_eq!(semantic_json(&materialized), semantic_json(&target));
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn canonical_bytes_and_incremental_state_are_order_invariant(
        base_ids in proptest::collection::btree_set(0u32..64, 0..16),
        target_ids in proptest::collection::btree_set(0u32..64, 0..16),
    ) {
        let base_regions: Vec<_> = base_ids
            .iter()
            .copied()
            .map(|index| region(index, None, 0))
            .collect();
        let target_regions: Vec<_> = target_ids
            .iter()
            .rev()
            .copied()
            .map(|index| region(index, None, 0))
            .collect();
        let mut reordered_base = base_regions.clone();
        reordered_base.reverse();

        let base = RestorableSnapshot::new(runtime_snapshot(10, base_regions));
        let reordered = RestorableSnapshot::new(runtime_snapshot(10, reordered_base));
        let base_bytes = SnapshotArtifact::full(base.clone(), SnapshotLimits::DEFAULT)
            .expect("property base artifact")
            .to_bytes()
            .expect("property base bytes");
        let reordered_bytes = SnapshotArtifact::full(reordered, SnapshotLimits::DEFAULT)
            .expect("property reordered artifact")
            .to_bytes()
            .expect("property reordered bytes");
        prop_assert_eq!(base_bytes, reordered_bytes);

        let target = RestorableSnapshot::new(runtime_snapshot(20, target_regions));
        let delta = SnapshotArtifact::incremental(&base, &target, SnapshotLimits::DEFAULT)
            .expect("property delta");
        let materialized = delta
            .materialize(Some(&base), SnapshotLimits::DEFAULT)
            .expect("property materialization");
        prop_assert_eq!(semantic_json(&materialized), semantic_json(&target));
    }
}

#[test]
fn malformed_truncated_corrupt_and_oversized_inputs_fail_closed() {
    let snapshot = RestorableSnapshot::new(runtime_snapshot(1, Vec::new()));
    let bytes = SnapshotArtifact::full(snapshot, SnapshotLimits::DEFAULT)
        .expect("full artifact")
        .to_bytes()
        .expect("encode");

    assert!(matches!(
        SnapshotArtifact::from_bytes(&bytes[..20]),
        Err(SnapshotCodecError::TruncatedHeader { .. } | SnapshotCodecError::LengthMismatch { .. })
    ));

    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 0xff;
    assert!(matches!(
        SnapshotArtifact::from_bytes(&bad_magic),
        Err(SnapshotCodecError::InvalidMagic)
    ));

    let mut bad_version = bytes.clone();
    bad_version[8..10].copy_from_slice(&(SNAPSHOT_ARTIFACT_VERSION + 1).to_le_bytes());
    assert!(matches!(
        SnapshotArtifact::from_bytes(&bad_version),
        Err(SnapshotCodecError::UnsupportedArtifactVersion { .. })
    ));

    let mut bad_kind = bytes.clone();
    bad_kind[10] = 9;
    assert!(matches!(
        SnapshotArtifact::from_bytes(&bad_kind),
        Err(SnapshotCodecError::InvalidArtifactKind { .. })
    ));

    let mut bad_flags = bytes.clone();
    bad_flags[11] = 1;
    assert!(matches!(
        SnapshotArtifact::from_bytes(&bad_flags),
        Err(SnapshotCodecError::UnsupportedFlags { .. })
    ));

    let mut corrupt = bytes.clone();
    *corrupt.last_mut().expect("payload byte") ^= 1;
    assert!(matches!(
        SnapshotArtifact::from_bytes(&corrupt),
        Err(SnapshotCodecError::ChecksumMismatch)
    ));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        SnapshotArtifact::from_bytes(&trailing),
        Err(SnapshotCodecError::LengthMismatch { .. })
    ));

    let small = SnapshotLimits {
        max_artifact_bytes: bytes.len() - 1,
        ..SnapshotLimits::DEFAULT
    };
    assert!(matches!(
        SnapshotArtifact::from_bytes_with_limits(&bytes, small),
        Err(SnapshotCodecError::ArtifactTooLarge { .. })
    ));

    let region_limited = SnapshotLimits {
        max_regions: 0,
        ..SnapshotLimits::DEFAULT
    };
    let one_region = RestorableSnapshot::new(runtime_snapshot(1, vec![region(1, None, 0)]));
    assert!(matches!(
        SnapshotArtifact::full(one_region, region_limited),
        Err(SnapshotCodecError::LimitExceeded {
            resource: "regions",
            ..
        })
    ));
}

#[test]
fn migration_composes_with_atomic_write_and_preserves_rollback_source() {
    let directory = tempfile::tempdir().expect("temporary migration directory");
    let legacy_path = directory.path().join("runtime-snapshot-v1.json");
    let target_path = directory.path().join("runtime-snapshot.asup");
    let legacy = legacy_snapshot(runtime_snapshot(77, vec![region(1, None, 0)]));
    let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("legacy JSON");
    std::fs::write(&legacy_path, &legacy_bytes).expect("write source fixture");

    let parsed =
        SnapshotArtifact::from_bytes(&std::fs::read(&legacy_path).expect("read legacy source"))
            .expect("decode legacy source")
            .materialize(None, SnapshotLimits::DEFAULT)
            .expect("materialize legacy source")
            .migrate_to_current()
            .expect("migrate to current");
    let target_bytes = SnapshotArtifact::full(parsed.clone(), SnapshotLimits::DEFAULT)
        .expect("current full artifact")
        .to_bytes()
        .expect("encode current artifact");

    futures_lite::future::block_on(async {
        asupersync::fs::write_atomic(&target_path, &target_bytes)
            .await
            .expect("atomic target write");
    });
    assert_eq!(
        std::fs::read(&legacy_path).expect("rollback source remains"),
        legacy_bytes,
        "migration must not delete or rewrite its rollback source"
    );
    let installed = SnapshotArtifact::from_bytes(
        &std::fs::read(&target_path).expect("read installed artifact"),
    )
    .expect("decode installed artifact")
    .materialize(None, SnapshotLimits::DEFAULT)
    .expect("materialize installed artifact");
    assert_eq!(semantic_json(&installed), semantic_json(&parsed));

    let partial_path = directory.path().join("partial.asup");
    std::fs::write(&partial_path, &target_bytes[..target_bytes.len() / 2])
        .expect("write partial fixture");
    assert!(
        SnapshotArtifact::from_bytes(&std::fs::read(&partial_path).expect("read partial fixture"))
            .is_err()
    );

    let corrupt_path = directory.path().join("corrupt.asup");
    let mut corrupt = target_bytes.clone();
    *corrupt.last_mut().expect("payload byte") ^= 1;
    std::fs::write(&corrupt_path, &corrupt).expect("write corrupt fixture");
    assert!(matches!(
        SnapshotArtifact::from_bytes(&std::fs::read(&corrupt_path).expect("read corrupt fixture")),
        Err(SnapshotCodecError::ChecksumMismatch)
    ));

    #[cfg(feature = "test-internals")]
    {
        use asupersync::fs::{FilesystemOperationProbe, stage_write_atomic_with_probe_for_test};

        let replacement = SnapshotArtifact::full(
            RestorableSnapshot::new(runtime_snapshot(88, Vec::new())),
            SnapshotLimits::DEFAULT,
        )
        .expect("replacement artifact")
        .to_bytes()
        .expect("replacement bytes");
        let before = std::fs::read(&target_path).expect("target before cancelled staging");
        let probe = Arc::new(FilesystemOperationProbe::new());
        futures_lite::future::block_on(async {
            let mut staged = Box::pin(stage_write_atomic_with_probe_for_test(
                &target_path,
                &replacement,
                Arc::clone(&probe),
            ));
            assert!(
                futures_lite::future::poll_once(staged.as_mut())
                    .await
                    .is_none()
            );
            assert!(
                probe.wait_until_blocked(Duration::from_secs(5)),
                "staging must reach its deterministic cancellation gate"
            );
            assert_eq!(
                std::fs::read(&target_path).expect("target while staging"),
                before
            );
            drop(staged);
            probe.release();
            assert!(
                probe.wait_until_completed(Duration::from_secs(5)),
                "discarded staging must finish cleanup"
            );
        });
        assert_eq!(
            std::fs::read(&target_path).expect("target after cancelled staging"),
            before,
            "cancellation before commit must preserve the installed artifact"
        );
    }

    // Stable structured receipt fields for forensic failure output.
    let receipt = serde_json::json!({
        "bead_id": "asupersync-5z2scg.3.3",
        "capability_id": "CAP-PERSISTED-TRACE-SNAPSHOT",
        "source_schema": 1,
        "target_schema": RestorableSnapshot::SCHEMA_VERSION,
        "source_sha256": hex(&Sha256::digest(&legacy_bytes)),
        "target_sha256": hex(&Sha256::digest(&target_bytes)),
        "rollback_source_preserved": true,
        "partial_rejected": true,
        "corrupt_rejected": true,
        "atomic_target_installed": true,
    });
    assert_eq!(receipt["rollback_source_preserved"], true);
}
