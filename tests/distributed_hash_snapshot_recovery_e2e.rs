#![cfg(feature = "distributed-hash-snapshot-recovery-e2e")]
//! Maintained real-filesystem recovery for the dormant distributed E2E rows.
//!
//! The source inventory called these journeys "distributed", but the dormant
//! implementation exercised only `HashRing`, authenticated `RegionSnapshot`
//! bytes, joined host threads, and real files. This lane preserves that exact
//! boundary instead of substituting a mock network or claiming a remote peer.

use asupersync::distributed::{
    BudgetSnapshot, HashRing, RegionSnapshot, SnapshotError, TaskSnapshot, TaskState,
};
use asupersync::security::AuthKey;
use asupersync::types::{RegionId, TaskId, Time};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

const BEAD_ID_DEFAULT: &str = "asupersync-d24mms.12.4";
const FEATURE: &str = "distributed-hash-snapshot-recovery-e2e";
const RING_SEED: u64 = 0xD15A_1B0A_4E2E_0004;
const AUTH_SEED: u64 = 0xA47A_5EED_0000_0004;
const REPLAY_COMMAND: &str =
    "RCH_REQUIRE_REMOTE=1 bash scripts/distributed_hash_snapshot_recovery_proof_runner.sh";

#[derive(Serialize)]
struct ScenarioReceipt {
    bead_id: String,
    scenario_id: &'static str,
    capability_ids: [&'static str; 2],
    feature_flags: [&'static str; 1],
    operation: &'static str,
    deterministic_seed: u64,
    expected: Value,
    actual: Value,
    lifecycle: Value,
    cleanup_status: Value,
    infrastructure_blocker: Option<&'static str>,
    verdict: &'static str,
    first_failure: Option<&'static str>,
    replay_command: &'static str,
    details: Value,
}

impl ScenarioReceipt {
    fn pass(
        scenario_id: &'static str,
        operation: &'static str,
        lifecycle: Value,
        cleanup_status: Value,
        details: Value,
    ) -> Self {
        let expected = json!({"outcome": "pass", "resource_state": "clean"});
        Self {
            bead_id: std::env::var("ASUPERSYNC_DISTRIBUTED_RECOVERY_BEAD_ID")
                .unwrap_or_else(|_| BEAD_ID_DEFAULT.to_owned()),
            scenario_id,
            capability_ids: ["CAP-REAL-SERVICE-E2E", "CAP-VERIFICATION-PROFILES"],
            feature_flags: [FEATURE],
            operation,
            deterministic_seed: RING_SEED,
            actual: expected.clone(),
            expected,
            lifecycle,
            cleanup_status,
            infrastructure_blocker: None,
            verdict: "pass",
            first_failure: None,
            replay_command: REPLAY_COMMAND,
            details,
        }
    }

    fn emit(&self) {
        println!(
            "{}",
            serde_json::to_string(self).expect("scenario receipt must serialize")
        );
    }
}

fn assignment_map(ring: &HashRing, keys: &[u64]) -> BTreeMap<u64, String> {
    keys.iter()
        .map(|key| {
            (
                *key,
                ring.node_for_key(key)
                    .expect("non-empty ring must assign every fixture key")
                    .to_owned(),
            )
        })
        .collect()
}

fn changed_key_count(before: &BTreeMap<u64, String>, after: &BTreeMap<u64, String>) -> usize {
    before
        .iter()
        .filter(|(key, node)| after.get(*key) != Some(*node))
        .count()
}

fn assert_addition_movement(
    before: &BTreeMap<u64, String>,
    after: &BTreeMap<u64, String>,
    added_node: &str,
) -> usize {
    let mut changed = 0;
    for (key, old_node) in before {
        let new_node = after.get(key).expect("post-addition assignment must exist");
        if new_node != old_node {
            changed += 1;
            assert_eq!(
                new_node, added_node,
                "key {key} moved between existing nodes during node addition"
            );
        }
    }
    assert!(
        changed > 0,
        "fixture must observe at least one added-node move"
    );
    changed
}

fn assert_removal_movement(
    before: &BTreeMap<u64, String>,
    after: &BTreeMap<u64, String>,
    removed_node: &str,
) -> usize {
    let mut changed = 0;
    for (key, old_node) in before {
        let new_node = after.get(key).expect("post-removal assignment must exist");
        if old_node == removed_node {
            changed += 1;
            assert_ne!(new_node, removed_node, "key {key} retained failed peer");
        } else {
            assert_eq!(
                new_node, old_node,
                "key {key} moved even though its prior peer remained live"
            );
        }
    }
    assert!(
        changed > 0,
        "fixture must assign at least one key to failed peer"
    );
    changed
}

fn fixture_snapshot(
    node_index: u32,
    sequence: u64,
    metadata: &[u8],
    key: &AuthKey,
) -> RegionSnapshot {
    let mut snapshot = RegionSnapshot::empty(RegionId::new_for_test(node_index, 1));
    snapshot.timestamp = Time::from_nanos(sequence.saturating_mul(1_000));
    snapshot.sequence = sequence;
    snapshot.origin_id = 10_000 + u64::from(node_index);
    snapshot.epoch = 4;
    snapshot.tasks = vec![
        TaskSnapshot {
            task_id: TaskId::new_for_test(node_index.saturating_mul(10), 1),
            state: TaskState::Running,
            priority: 1,
        },
        TaskSnapshot {
            task_id: TaskId::new_for_test(node_index.saturating_mul(10).saturating_add(1), 1),
            state: TaskState::Completed,
            priority: 2,
        },
    ];
    snapshot.children = vec![RegionId::new_for_test(node_index.saturating_add(100), 1)];
    snapshot.finalizer_count = 1;
    snapshot.budget = BudgetSnapshot {
        deadline_nanos: Some(sequence.saturating_mul(10_000)),
        polls_remaining: Some(64),
        cost_remaining: Some(4_096),
    };
    snapshot.parent = Some(RegionId::new_for_test(900_000, 1));
    snapshot.metadata = metadata.to_vec();
    snapshot.sign(key);
    snapshot
}

fn assert_snapshot_eq(expected: &RegionSnapshot, actual: &RegionSnapshot) {
    assert_eq!(actual.region_id, expected.region_id, "region id drift");
    assert_eq!(actual.state, expected.state, "region state drift");
    assert_eq!(actual.timestamp, expected.timestamp, "timestamp drift");
    assert_eq!(actual.sequence, expected.sequence, "sequence drift");
    assert_eq!(
        actual.vector_clock, expected.vector_clock,
        "vector-clock drift"
    );
    assert_eq!(actual.origin_id, expected.origin_id, "origin drift");
    assert_eq!(actual.epoch, expected.epoch, "epoch drift");
    assert_eq!(actual.tasks.len(), expected.tasks.len(), "task-count drift");
    for (expected_task, actual_task) in expected.tasks.iter().zip(&actual.tasks) {
        assert_eq!(actual_task.task_id, expected_task.task_id, "task id drift");
        assert_eq!(actual_task.state, expected_task.state, "task state drift");
        assert_eq!(
            actual_task.priority, expected_task.priority,
            "task priority drift"
        );
    }
    assert_eq!(actual.children, expected.children, "child-region drift");
    assert_eq!(
        actual.finalizer_count, expected.finalizer_count,
        "finalizer drift"
    );
    assert_eq!(
        actual.budget.deadline_nanos, expected.budget.deadline_nanos,
        "deadline budget drift"
    );
    assert_eq!(
        actual.budget.polls_remaining, expected.budget.polls_remaining,
        "poll budget drift"
    );
    assert_eq!(
        actual.budget.cost_remaining, expected.budget.cost_remaining,
        "cost budget drift"
    );
    assert_eq!(
        actual.cancel_reason, expected.cancel_reason,
        "cancel-reason drift"
    );
    assert_eq!(actual.parent, expected.parent, "parent drift");
    assert_eq!(actual.metadata, expected.metadata, "metadata drift");
    assert!(
        !actual.auth_tag.is_zero(),
        "restored snapshot must stay authenticated"
    );
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_all(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn scenario_consistent_hash_churn() -> ScenarioReceipt {
    let keys: Vec<u64> = (0..512).collect();
    let mut ring = HashRing::new(64, RING_SEED);
    for node in ["replica-a", "replica-b", "replica-c"] {
        assert!(ring.add_node(node), "initial peer identity must be unique");
    }
    let baseline = assignment_map(&ring, &keys);

    assert!(ring.add_node("replica-d"), "scale-up peer must be new");
    let after_add = assignment_map(&ring, &keys);
    let add_changes = assert_addition_movement(&baseline, &after_add, "replica-d");

    assert_eq!(
        ring.remove_node("replica-b"),
        64,
        "peer failure must remove 64 vnodes"
    );
    let after_failure = assignment_map(&ring, &keys);
    let failure_changes = assert_removal_movement(&after_add, &after_failure, "replica-b");
    assert_eq!(ring.node_count(), 3, "three live peers must remain");
    assert_eq!(
        ring.vnode_count(),
        192,
        "live peer vnode ownership must be exact"
    );

    ScenarioReceipt::pass(
        "DORMANT-DIST-001",
        "fixed-seed consistent-hash scale-up and peer-failure churn",
        json!({"initial_peers": 3, "scale_up_peers": 4, "post_failure_peers": 3}),
        json!({"ring_owned_in_test": true, "external_resources": 0}),
        json!({
            "key_count": keys.len(),
            "add_changed_keys": add_changes,
            "failure_changed_keys": failure_changes,
            "final_nodes": ring.nodes().collect::<Vec<_>>(),
        }),
    )
}

fn scenario_authenticated_file_roundtrip() -> ScenarioReceipt {
    let temp = TempDir::new().expect("roundtrip tempdir must be available");
    let root = temp.path().to_path_buf();
    let path = root.join("snapshot.bin");
    let key = AuthKey::from_seed(AUTH_SEED);
    let snapshot = fixture_snapshot(42, 123, b"authenticated-file-roundtrip", &key);
    let encoded = snapshot.to_bytes_with_key(&key);

    write_synced(&path, &encoded).expect("snapshot write and fsync must succeed");
    let persisted = read_all(&path).expect("snapshot read must succeed");
    assert_eq!(persisted, encoded, "filesystem bytes must be exact");
    let restored = RegionSnapshot::from_bytes_with_key(&persisted, &key)
        .expect("authenticated snapshot must restore");
    assert_snapshot_eq(&snapshot, &restored);
    let byte_len = persisted.len();

    temp.close()
        .expect("roundtrip tempdir cleanup must succeed");
    assert!(!root.exists(), "roundtrip tempdir must be removed");

    ScenarioReceipt::pass(
        "DORMANT-DIST-002",
        "authenticated RegionSnapshot binary roundtrip through real file I/O",
        json!({"write": "fsync", "read": "complete", "authentication": "verified"}),
        json!({"tempdir_removed": true, "open_files": 0}),
        json!({"serialized_bytes": byte_len, "sequence": restored.sequence, "task_count": restored.tasks.len()}),
    )
}

#[derive(Debug)]
struct WorkerOutcome {
    worker: usize,
    state: &'static str,
    serialized_bytes: usize,
}

fn scenario_concurrent_snapshot_workers() -> ScenarioReceipt {
    const WORKERS: usize = 6;
    const CANCELLED_WORKER: usize = WORKERS - 1;

    let temp = TempDir::new().expect("concurrent tempdir must be available");
    let root = temp.path().to_path_buf();
    let ready = Arc::new(Barrier::new(WORKERS + 1));
    let start = Arc::new(Barrier::new(WORKERS + 1));
    let cancellation = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel::<Result<WorkerOutcome, String>>();
    let mut handles = Vec::with_capacity(WORKERS);

    for worker in 0..WORKERS {
        let worker_root = root.clone();
        let worker_ready = Arc::clone(&ready);
        let worker_start = Arc::clone(&start);
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_sender = sender.clone();
        handles.push(thread::spawn(move || {
            worker_ready.wait();
            worker_start.wait();

            let outcome =
                if worker == CANCELLED_WORKER && worker_cancellation.load(Ordering::Acquire) {
                    Ok(WorkerOutcome {
                        worker,
                        state: "cancelled-before-create",
                        serialized_bytes: 0,
                    })
                } else {
                    let key = AuthKey::from_seed(AUTH_SEED + worker as u64);
                    let snapshot = fixture_snapshot(
                        100 + worker as u32,
                        1_000 + worker as u64,
                        format!("concurrent-worker-{worker}").as_bytes(),
                        &key,
                    );
                    let bytes = snapshot.to_bytes_with_key(&key);
                    let path = worker_root.join(format!("worker-{worker}.snap"));
                    write_synced(&path, &bytes)
                        .map_err(|error| format!("worker {worker} write failed: {error}"))?;
                    let persisted = read_all(&path)
                        .map_err(|error| format!("worker {worker} read failed: {error}"))?;
                    let restored = RegionSnapshot::from_bytes_with_key(&persisted, &key)
                        .map_err(|error| format!("worker {worker} restore failed: {error}"))?;
                    assert_snapshot_eq(&snapshot, &restored);
                    Ok(WorkerOutcome {
                        worker,
                        state: "committed",
                        serialized_bytes: persisted.len(),
                    })
                };
            let _ = worker_sender.send(outcome);
            Ok::<(), String>(())
        }));
    }
    drop(sender);

    ready.wait();
    cancellation.store(true, Ordering::Release);
    start.wait();

    let mut outcomes = Vec::with_capacity(WORKERS);
    let mut receive_error = None;
    while outcomes.len() < WORKERS {
        match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => {
                receive_error = Some(error);
                break;
            }
        }
    }

    let join_results: Vec<_> = handles.into_iter().map(thread::JoinHandle::join).collect();
    assert!(
        join_results.iter().all(Result::is_ok),
        "every concurrent snapshot worker must join, including cancellation"
    );
    for result in join_results.into_iter().flatten() {
        result.expect("worker body must complete without I/O error");
    }
    assert!(
        receive_error.is_none(),
        "worker receipt wait exceeded its bound: {receive_error:?}"
    );

    let mut outcomes: Vec<_> = outcomes
        .into_iter()
        .map(|result| result.expect("worker operation must succeed"))
        .collect();
    outcomes.sort_by_key(|outcome| outcome.worker);
    assert_eq!(outcomes.len(), WORKERS, "every admitted worker must report");
    assert_eq!(
        outcomes
            .iter()
            .filter(|row| row.state == "committed")
            .count(),
        WORKERS - 1,
        "all non-cancelled workers must commit"
    );
    assert_eq!(
        outcomes[CANCELLED_WORKER].state, "cancelled-before-create",
        "coordinator cancellation must win before filesystem creation"
    );
    assert!(
        !root
            .join(format!("worker-{CANCELLED_WORKER}.snap"))
            .exists(),
        "cancelled worker must not publish a snapshot file"
    );
    let committed_bytes: usize = outcomes.iter().map(|row| row.serialized_bytes).sum();

    temp.close()
        .expect("concurrent tempdir cleanup must succeed");
    assert!(!root.exists(), "concurrent tempdir must be removed");

    ScenarioReceipt::pass(
        "DORMANT-DIST-003",
        "joined concurrent snapshot writers with cancellation-before-commit",
        json!({"workers_admitted": WORKERS, "workers_committed": WORKERS - 1, "workers_cancelled": 1}),
        json!({"workers_joined": WORKERS, "tempdir_removed": true, "orphan_workers": 0, "open_files": 0}),
        json!({"receipt_count": outcomes.len(), "committed_bytes": committed_bytes, "cancelled_worker": CANCELLED_WORKER}),
    )
}

fn scenario_snapshot_failure_boundaries() -> ScenarioReceipt {
    let temp = TempDir::new().expect("failure-boundary tempdir must be available");
    let root = temp.path().to_path_buf();
    let key = AuthKey::from_seed(AUTH_SEED);
    let snapshot = fixture_snapshot(77, 777, b"failure-boundary", &key);
    let valid = snapshot.to_bytes_with_key(&key);

    let missing = root.join("missing.snap");
    assert_eq!(
        read_all(&missing)
            .expect_err("missing snapshot must fail")
            .kind(),
        std::io::ErrorKind::NotFound,
        "missing snapshot must preserve NotFound"
    );

    let empty = root.join("empty.snap");
    write_synced(&empty, &[]).expect("empty fixture write must succeed");
    let empty_error =
        RegionSnapshot::from_bytes_with_key(&read_all(&empty).expect("empty read"), &key)
            .expect_err("empty snapshot must fail as truncated");
    assert_eq!(empty_error, SnapshotError::UnexpectedEof);

    let truncated = root.join("truncated.snap");
    write_synced(&truncated, &valid[..31]).expect("truncated fixture write must succeed");
    let truncated_error =
        RegionSnapshot::from_bytes_with_key(&read_all(&truncated).expect("truncated read"), &key)
            .expect_err("short authenticated frame must fail before parsing");
    assert_eq!(truncated_error, SnapshotError::UnexpectedEof);

    let corrupt = root.join("corrupt.snap");
    let mut corrupted_bytes = valid.clone();
    corrupted_bytes[20] ^= 0x80;
    write_synced(&corrupt, &corrupted_bytes).expect("corrupt fixture write must succeed");
    let corrupt_error =
        RegionSnapshot::from_bytes_with_key(&read_all(&corrupt).expect("corrupt read"), &key)
            .expect_err("tampered authenticated snapshot must fail closed");
    assert_eq!(corrupt_error, SnapshotError::AuthenticationFailed);

    temp.close()
        .expect("failure-boundary tempdir cleanup must succeed");
    assert!(!root.exists(), "failure-boundary tempdir must be removed");

    ScenarioReceipt::pass(
        "DORMANT-DIST-004",
        "missing, empty, truncated, and authentication-corrupt snapshot files",
        json!({"missing": "not-found", "empty": "unexpected-eof", "truncated": "unexpected-eof", "corrupt": "authentication-failed"}),
        json!({"tempdir_removed": true, "open_files": 0, "published_invalid_snapshots": 0}),
        json!({"failure_cases": 4, "valid_fixture_bytes": valid.len()}),
    )
}

fn scenario_failure_migration_restart() -> ScenarioReceipt {
    let temp = TempDir::new().expect("migration tempdir must be available");
    let root = temp.path().to_path_buf();
    let key = AuthKey::from_seed(AUTH_SEED);
    let keys: Vec<u64> = (0..512).collect();
    let mut ring = HashRing::new(64, RING_SEED);
    let initial_nodes = ["replica-a", "replica-b", "replica-c"];
    let mut snapshots = BTreeMap::new();

    for (index, node) in initial_nodes.iter().enumerate() {
        assert!(ring.add_node(*node), "initial replica must be unique");
        let snapshot = fixture_snapshot(
            500 + index as u32,
            5_000 + index as u64,
            format!("owned-by-{node}").as_bytes(),
            &key,
        );
        let path = root.join(node).join("active.snap");
        write_synced(&path, &snapshot.to_bytes_with_key(&key))
            .expect("initial replica snapshot must persist");
        snapshots.insert((*node).to_owned(), snapshot);
    }

    assert!(ring.add_node("replica-d"), "replacement capacity must join");
    let before_failure = assignment_map(&ring, &keys);
    assert_eq!(
        ring.remove_node("replica-b"),
        64,
        "failed replica must leave ring"
    );
    let during_failure = assignment_map(&ring, &keys);
    let migrated_keys = assert_removal_movement(&before_failure, &during_failure, "replica-b");

    let failed_snapshot = snapshots
        .get("replica-b")
        .expect("failed replica snapshot fixture must exist");
    let transfer_bytes = read_all(&root.join("replica-b/active.snap"))
        .expect("failed peer's durable snapshot must remain readable for recovery");
    let incoming = root.join("replica-d/incoming.snap");
    let active = root.join("replica-d/recovered-from-b.snap");

    let mut tampered = transfer_bytes.clone();
    tampered[24] ^= 0x40;
    write_synced(&incoming, &tampered).expect("tampered transfer fixture must persist");
    let tampered_error =
        RegionSnapshot::from_bytes_with_key(&read_all(&incoming).expect("tampered read"), &key)
            .expect_err("tampered migration must fail authentication");
    assert_eq!(tampered_error, SnapshotError::AuthenticationFailed);
    assert!(
        !active.exists(),
        "failed transfer must not publish recovered state"
    );

    write_synced(&incoming, &transfer_bytes).expect("retry transfer must persist exact bytes");
    let recovered = RegionSnapshot::from_bytes_with_key(
        &read_all(&incoming).expect("retry transfer read"),
        &key,
    )
    .expect("retry transfer must authenticate");
    assert_snapshot_eq(failed_snapshot, &recovered);
    fs::rename(&incoming, &active).expect("verified transfer must publish atomically");
    assert!(active.exists(), "verified recovery must be published");

    assert!(
        ring.add_node("replica-b"),
        "failed replica restart must rejoin"
    );
    let after_restart = assignment_map(&ring, &keys);
    assert_eq!(
        after_restart, before_failure,
        "same fixed identity must restore the pre-failure assignment map"
    );
    let restarted_path = root.join("replica-b/restarted.snap");
    write_synced(
        &restarted_path,
        &read_all(&active).expect("published recovery read"),
    )
    .expect("restarted peer must receive recovered state");
    let restarted = RegionSnapshot::from_bytes_with_key(
        &read_all(&restarted_path).expect("restarted peer read"),
        &key,
    )
    .expect("restarted peer snapshot must authenticate");
    assert_snapshot_eq(failed_snapshot, &restarted);

    for node in ["replica-a", "replica-b", "replica-c", "replica-d"] {
        assert_eq!(
            ring.remove_node(node),
            64,
            "shutdown must release each peer's vnodes"
        );
    }
    assert!(ring.is_empty(), "shutdown must leave no ring ownership");
    assert!(
        ring.node_for_key(&0_u64).is_none(),
        "empty ring must route no data"
    );
    assert_eq!(changed_key_count(&before_failure, &after_restart), 0);

    temp.close()
        .expect("migration tempdir cleanup must succeed");
    assert!(!root.exists(), "migration tempdir must be removed");

    ScenarioReceipt::pass(
        "DORMANT-DIST-005",
        "peer failure, fail-closed snapshot migration, retry, and identity-stable restart",
        json!({"peer_failure": "rerouted", "corrupt_transfer": "rejected", "retry": "published", "restart": "assignment-equivalent", "shutdown": "empty"}),
        json!({"peers_remaining": 0, "vnodes_remaining": 0, "tempdir_removed": true, "processes": 0, "ports": 0, "sockets": 0, "tasks": 0, "obligations": 0}),
        json!({"migrated_keys": migrated_keys, "snapshot_sequence": restarted.sequence, "assignment_drift_after_restart": 0}),
    )
}

#[test]
fn dormant_distributed_hash_snapshot_recovery_emits_required_scenarios() {
    let receipts = [
        scenario_consistent_hash_churn(),
        scenario_authenticated_file_roundtrip(),
        scenario_concurrent_snapshot_workers(),
        scenario_snapshot_failure_boundaries(),
        scenario_failure_migration_restart(),
    ];

    assert_eq!(
        receipts.len(),
        5,
        "all dormant distributed rows must execute"
    );
    for receipt in receipts {
        receipt.emit();
    }
}
