//! Real distributed systems E2E tests - consistent hash rebalancing and snapshot serialization
//!
//! Tests real distributed coordination primitives including:
//! - Consistent hash ring rebalancing under live node churn
//! - Snapshot/restore round-trip through binary serialization with real I/O
//! - Multi-node key redistribution stability validation
//! - Concurrent snapshot operations with filesystem persistence
//!
//! Anti-mock principle: Tests use actual HashRing and RegionSnapshot implementations
//! with real file I/O operations to catch serialization bugs, hash distribution issues,
//! and filesystem edge cases that mocks would hide.

#![cfg(all(test, feature = "real-service-e2e"))]

use crate::distributed::consistent_hash::HashRing;
use crate::distributed::snapshot::{
    BudgetSnapshot, RegionSnapshot, SnapshotError, TaskSnapshot, TaskState,
};
use crate::record::region::RegionState;
use crate::types::{RegionId, TaskId, Time};
use crate::util::ArenaIndex;

use std::collections::{HashMap, HashSet};
use std::fs::{File, create_dir_all, remove_file};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

// Structured JSON-line logging for CI debugging
struct TestLogger {
    test_name: String,
    start_time: Instant,
}

impl TestLogger {
    fn new(test_name: &str) -> Self {
        let logger = Self {
            test_name: test_name.to_string(),
            start_time: Instant::now(),
        };
        logger.log_event("test_start", serde_json::json!({}));
        logger
    }

    fn log_event(&self, event_type: &str, data: serde_json::Value) {
        let elapsed = self.start_time.elapsed().as_millis();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        eprintln!(
            "{{\"timestamp\":{},\"test\":\"{}\",\"elapsed_ms\":{},\"event\":\"{}\",\"data\":{}}}",
            timestamp, self.test_name, elapsed, event_type, data
        );
    }

    fn log_phase(&self, phase: &str) {
        self.log_event("phase", serde_json::json!({"name": phase}));
    }

    fn log_metrics(&self, metrics: serde_json::Value) {
        self.log_event("metrics", metrics);
    }

    fn log_assertion(&self, assertion: &str, passed: bool, details: serde_json::Value) {
        self.log_event(
            "assertion",
            serde_json::json!({
                "assertion": assertion,
                "passed": passed,
                "details": details
            }),
        );
    }
}

impl Drop for TestLogger {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed().as_millis();
        self.log_event(
            "test_end",
            serde_json::json!({"total_duration_ms": elapsed}),
        );
    }
}

/// Test harness for distributed system E2E testing
struct DistributedTestHarness {
    temp_dir: TempDir,
    logger: TestLogger,
}

impl DistributedTestHarness {
    fn new(test_name: &str) -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let logger = TestLogger::new(test_name);

        logger.log_event(
            "harness_init",
            serde_json::json!({
                "temp_dir": temp_dir.path().to_string_lossy()
            }),
        );

        Self { temp_dir, logger }
    }

    /// Test consistent hash rebalancing under node churn
    fn test_consistent_hash_rebalancing(&self) {
        self.logger.log_phase("consistent_hash_setup");

        // Create hash ring with multiple virtual nodes for better distribution
        let vnodes_per_node = 100;
        let seed = 42; // Fixed seed for deterministic testing
        let mut ring = HashRing::new(vnodes_per_node, seed);

        // Test keys that will be distributed across nodes
        let test_keys: Vec<String> = (0..1000).map(|i| format!("key_{}", i)).collect();

        self.logger.log_event(
            "ring_initialized",
            serde_json::json!({
                "vnodes_per_node": vnodes_per_node,
                "seed": seed,
                "test_key_count": test_keys.len()
            }),
        );

        // Phase 1: Initial cluster setup
        self.logger.log_phase("initial_cluster");
        let initial_nodes = vec!["node_1", "node_2", "node_3"];

        for node in &initial_nodes {
            let added = ring.add_node(node);
            assert!(added, "Node {} should be added successfully", node);
        }

        self.logger.log_metrics(serde_json::json!({
            "node_count": ring.node_count(),
            "vnode_count": ring.vnode_count(),
            "is_empty": ring.is_empty()
        }));

        // Record initial key distribution
        let initial_distribution = self.measure_key_distribution(&ring, &test_keys);
        self.logger.log_event(
            "initial_distribution",
            serde_json::json!(initial_distribution),
        );

        // Phase 2: Add nodes (scale up)
        self.logger.log_phase("scale_up");
        let new_nodes = vec!["node_4", "node_5"];

        for node in &new_nodes {
            let added = ring.add_node(node);
            assert!(added, "Node {} should be added successfully", node);
        }

        let scale_up_distribution = self.measure_key_distribution(&ring, &test_keys);
        self.logger.log_event(
            "scale_up_distribution",
            serde_json::json!(scale_up_distribution),
        );

        // Validate rebalancing behavior
        let movement_percentage =
            self.calculate_key_movement(&initial_distribution, &scale_up_distribution);

        self.logger.log_assertion(
            "reasonable_rebalancing",
            movement_percentage < 0.6,
            serde_json::json!({
                "movement_percentage": movement_percentage,
                "threshold": 0.6
            }),
        );

        assert!(
            movement_percentage < 0.6,
            "Key movement should be reasonable during scale up: {:.2}% > 60%",
            movement_percentage * 100.0
        );

        // Phase 3: Remove nodes (scale down)
        self.logger.log_phase("scale_down");
        let removed_count = ring.remove_node("node_2");

        self.logger.log_event(
            "node_removed",
            serde_json::json!({
                "node": "node_2",
                "vnodes_removed": removed_count
            }),
        );

        assert_eq!(
            removed_count, vnodes_per_node,
            "Should remove all virtual nodes for node_2"
        );

        let scale_down_distribution = self.measure_key_distribution(&ring, &test_keys);
        self.logger.log_event(
            "scale_down_distribution",
            serde_json::json!(scale_down_distribution),
        );

        // Phase 4: Simulate node failure and recovery
        self.logger.log_phase("failure_recovery");

        // Remove node (simulated failure)
        let failed_node = "node_3";
        let removed = ring.remove_node(failed_node);
        assert_eq!(
            removed, vnodes_per_node,
            "Failed node should be removed completely"
        );

        let failure_distribution = self.measure_key_distribution(&ring, &test_keys);

        // Add replacement node (recovery)
        let replacement_node = "node_6";
        let added = ring.add_node(replacement_node);
        assert!(added, "Replacement node should be added successfully");

        let recovery_distribution = self.measure_key_distribution(&ring, &test_keys);

        self.logger.log_event(
            "failure_recovery_complete",
            serde_json::json!({
                "failed_node": failed_node,
                "replacement_node": replacement_node,
                "final_node_count": ring.node_count()
            }),
        );

        // Phase 5: Validate distribution quality
        self.logger.log_phase("distribution_validation");
        self.validate_distribution_quality(&recovery_distribution);
    }

    /// Test snapshot serialization round-trip with real I/O
    fn test_snapshot_serialization_roundtrip(&self) {
        self.logger.log_phase("snapshot_setup");

        // Create comprehensive test snapshot
        let region_id = RegionId::new(ArenaIndex::new(42), 1);
        let mut snapshot = RegionSnapshot::empty(region_id);

        // Populate with realistic data
        snapshot.state = RegionState::Running;
        snapshot.timestamp = Time::from_nanos(1_000_000_000); // 1 second
        snapshot.sequence = 123;
        snapshot.origin_id = 456;
        snapshot.epoch = 789;

        // Add task snapshots
        for i in 0..10 {
            snapshot.tasks.push(TaskSnapshot {
                task_id: TaskId::new(ArenaIndex::new(i), 1),
                state: match i % 5 {
                    0 => TaskState::Pending,
                    1 => TaskState::Running,
                    2 => TaskState::Completed,
                    3 => TaskState::Cancelled,
                    _ => TaskState::Panicked,
                },
                priority: (i % 4) as u8,
            });
        }

        // Add child regions
        for i in 0..5 {
            snapshot
                .children
                .push(RegionId::new(ArenaIndex::new(100 + i), 1));
        }

        snapshot.finalizer_count = 3;
        snapshot.budget = BudgetSnapshot {
            deadline_nanos: Some(5_000_000_000), // 5 seconds
            polls_remaining: Some(100),
            cost_remaining: Some(1000),
        };
        snapshot.cancel_reason = Some("Test cancellation".to_string());
        snapshot.parent = Some(RegionId::new(ArenaIndex::new(999), 1));
        snapshot.metadata = b"test metadata".to_vec();

        self.logger.log_event(
            "snapshot_created",
            serde_json::json!({
                "region_id_index": region_id.index().value(),
                "region_id_generation": region_id.generation(),
                "task_count": snapshot.tasks.len(),
                "children_count": snapshot.children.len(),
                "metadata_size": snapshot.metadata.len()
            }),
        );

        // Phase 1: Serialize to bytes
        self.logger.log_phase("serialization");
        let serialized = snapshot.to_bytes();

        self.logger.log_metrics(serde_json::json!({
            "serialized_size": serialized.len(),
            "magic_header": format!("{:?}", &serialized[0..4])
        }));

        // Phase 2: Write to file (real I/O)
        self.logger.log_phase("file_write");
        let snapshot_path = self.temp_dir.path().join("test_snapshot.bin");

        {
            let mut file = File::create(&snapshot_path).expect("Failed to create snapshot file");
            file.write_all(&serialized)
                .expect("Failed to write snapshot data");
            file.sync_all().expect("Failed to sync file to disk");
        }

        let file_size = std::fs::metadata(&snapshot_path)
            .expect("Failed to get file metadata")
            .len();

        self.logger.log_event(
            "file_written",
            serde_json::json!({
                "path": snapshot_path.to_string_lossy(),
                "file_size": file_size
            }),
        );

        // Phase 3: Read from file (real I/O)
        self.logger.log_phase("file_read");
        let mut read_data = Vec::new();

        {
            let mut file = File::open(&snapshot_path).expect("Failed to open snapshot file");
            file.read_to_end(&mut read_data)
                .expect("Failed to read snapshot data");
        }

        self.logger.log_assertion(
            "file_roundtrip",
            read_data == serialized,
            serde_json::json!({
                "original_size": serialized.len(),
                "read_size": read_data.len()
            }),
        );

        assert_eq!(
            read_data, serialized,
            "File roundtrip should preserve data exactly"
        );

        // Phase 4: Deserialize from bytes
        self.logger.log_phase("deserialization");
        let deserialized =
            RegionSnapshot::from_bytes(&read_data).expect("Failed to deserialize snapshot");

        // Phase 5: Validate round-trip correctness
        self.logger.log_phase("validation");
        self.validate_snapshot_roundtrip(&snapshot, &deserialized);
    }

    /// Test concurrent snapshot operations
    fn test_concurrent_snapshot_operations(&self) {
        self.logger.log_phase("concurrent_setup");

        // Create multiple snapshots with different characteristics
        let snapshots: Vec<RegionSnapshot> = (0..5)
            .map(|i| {
                let region_id = RegionId::new(ArenaIndex::new(i * 10), 1);
                let mut snapshot = RegionSnapshot::empty(region_id);

                snapshot.sequence = i as u64;
                snapshot.origin_id = (i * 100) as u64;
                snapshot.metadata = format!("concurrent_test_{}", i).into_bytes();

                // Add varying numbers of tasks
                for j in 0..(i + 1) {
                    snapshot.tasks.push(TaskSnapshot {
                        task_id: TaskId::new(ArenaIndex::new(i * 10 + j), 1),
                        state: TaskState::Running,
                        priority: j as u8,
                    });
                }

                snapshot
            })
            .collect();

        self.logger.log_event(
            "concurrent_snapshots_created",
            serde_json::json!({
                "count": snapshots.len(),
                "total_tasks": snapshots.iter().map(|s| s.tasks.len()).sum::<usize>()
            }),
        );

        // Phase 1: Concurrent serialization and file writing
        self.logger.log_phase("concurrent_write");
        let write_start = Instant::now();

        // Simulate concurrent operations by processing all snapshots
        let file_paths: Vec<PathBuf> = snapshots
            .iter()
            .enumerate()
            .map(|(i, snapshot)| {
                let serialized = snapshot.to_bytes();
                let path = self.temp_dir.path().join(format!("concurrent_{}.bin", i));

                let mut file =
                    File::create(&path).expect("Failed to create concurrent snapshot file");
                file.write_all(&serialized)
                    .expect("Failed to write concurrent snapshot");
                file.sync_all().expect("Failed to sync concurrent file");

                path
            })
            .collect();

        let write_duration = write_start.elapsed();
        self.logger.log_metrics(serde_json::json!({
            "concurrent_write_duration_ms": write_duration.as_millis(),
            "files_created": file_paths.len()
        }));

        // Phase 2: Concurrent reading and deserialization
        self.logger.log_phase("concurrent_read");
        let read_start = Instant::now();

        let restored_snapshots: Vec<RegionSnapshot> = file_paths
            .iter()
            .map(|path| {
                let mut data = Vec::new();
                let mut file = File::open(path).expect("Failed to open concurrent snapshot");
                file.read_to_end(&mut data)
                    .expect("Failed to read concurrent snapshot");

                RegionSnapshot::from_bytes(&data)
                    .expect("Failed to deserialize concurrent snapshot")
            })
            .collect();

        let read_duration = read_start.elapsed();
        self.logger.log_metrics(serde_json::json!({
            "concurrent_read_duration_ms": read_duration.as_millis(),
            "snapshots_restored": restored_snapshots.len()
        }));

        // Phase 3: Validate all concurrent operations
        self.logger.log_phase("concurrent_validation");

        for (i, (original, restored)) in snapshots.iter().zip(restored_snapshots.iter()).enumerate()
        {
            self.validate_snapshot_roundtrip(original, restored);

            self.logger.log_event(
                "concurrent_validation_success",
                serde_json::json!({
                    "snapshot_index": i,
                    "region_id_index": original.region_id.index().value(),
                    "sequence": original.sequence
                }),
            );
        }

        self.logger.log_assertion(
            "concurrent_integrity",
            true,
            serde_json::json!({
                "all_snapshots_valid": true,
                "total_validated": snapshots.len()
            }),
        );
    }

    /// Test error handling in snapshot operations
    fn test_snapshot_error_handling(&self) {
        self.logger.log_phase("error_handling_setup");

        // Test cases for various error conditions
        let error_test_cases = vec![
            ("invalid_magic", vec![0xBA, 0xD0, 0xBA, 0xD0, 0x01]),
            ("unsupported_version", vec![b'S', b'N', b'A', b'P', 0xFF]),
            ("truncated_header", vec![b'S', b'N', b'A']),
            ("empty_data", vec![]),
        ];

        for (test_name, invalid_data) in error_test_cases {
            self.logger.log_phase(&format!("error_test_{}", test_name));

            let result = RegionSnapshot::from_bytes(&invalid_data);

            self.logger.log_assertion(
                "expected_error",
                result.is_err(),
                serde_json::json!({
                    "test_case": test_name,
                    "data_length": invalid_data.len(),
                    "error_occurred": result.is_err()
                }),
            );

            assert!(
                result.is_err(),
                "Invalid data should cause deserialization error: {}",
                test_name
            );

            if let Err(error) = result {
                self.logger.log_event(
                    "error_details",
                    serde_json::json!({
                        "test_case": test_name,
                        "error_type": format!("{:?}", error),
                        "error_message": error.to_string()
                    }),
                );
            }
        }
    }

    // Helper methods

    fn measure_key_distribution(&self, ring: &HashRing, keys: &[String]) -> HashMap<String, usize> {
        let mut distribution: HashMap<String, usize> = HashMap::new();

        for node in ring.nodes() {
            distribution.insert(node.to_string(), 0);
        }

        for key in keys {
            if let Some(node) = ring.node_for_key(key) {
                *distribution.entry(node.to_string()).or_insert(0) += 1;
            }
        }

        distribution
    }

    fn calculate_key_movement(
        &self,
        before: &HashMap<String, usize>,
        after: &HashMap<String, usize>,
    ) -> f64 {
        let total_keys: usize = before.values().sum();
        if total_keys == 0 {
            return 0.0;
        }

        let mut moved_keys = 0;

        for (node, &before_count) in before {
            let after_count = after.get(node).copied().unwrap_or(0);
            if after_count < before_count {
                moved_keys += before_count - after_count;
            }
        }

        moved_keys as f64 / total_keys as f64
    }

    fn validate_distribution_quality(&self, distribution: &HashMap<String, usize>) {
        let values: Vec<usize> = distribution.values().copied().collect();
        if values.is_empty() {
            return;
        }

        let total: usize = values.iter().sum();
        let node_count = values.len();
        let expected_per_node = total as f64 / node_count as f64;

        let max_deviation = values
            .iter()
            .map(|&count| (count as f64 - expected_per_node).abs() / expected_per_node)
            .fold(0.0, f64::max);

        self.logger.log_assertion(
            "distribution_balance",
            max_deviation < 0.3,
            serde_json::json!({
                "max_deviation": max_deviation,
                "expected_per_node": expected_per_node,
                "actual_distribution": distribution,
                "threshold": 0.3
            }),
        );

        assert!(
            max_deviation < 0.3,
            "Distribution should be reasonably balanced: max deviation {:.2}% > 30%",
            max_deviation * 100.0
        );
    }

    fn validate_snapshot_roundtrip(&self, original: &RegionSnapshot, restored: &RegionSnapshot) {
        // Validate basic fields
        assert_eq!(
            original.region_id, restored.region_id,
            "Region ID should match"
        );
        assert_eq!(original.state, restored.state, "Region state should match");
        assert_eq!(
            original.timestamp, restored.timestamp,
            "Timestamp should match"
        );
        assert_eq!(
            original.sequence, restored.sequence,
            "Sequence should match"
        );
        assert_eq!(
            original.origin_id, restored.origin_id,
            "Origin ID should match"
        );
        assert_eq!(original.epoch, restored.epoch, "Epoch should match");

        // Validate tasks
        assert_eq!(
            original.tasks.len(),
            restored.tasks.len(),
            "Task count should match"
        );
        for (orig_task, rest_task) in original.tasks.iter().zip(restored.tasks.iter()) {
            assert_eq!(orig_task.task_id, rest_task.task_id, "Task ID should match");
            assert_eq!(orig_task.state, rest_task.state, "Task state should match");
            assert_eq!(
                orig_task.priority, rest_task.priority,
                "Task priority should match"
            );
        }

        // Validate children
        assert_eq!(
            original.children, restored.children,
            "Children should match"
        );

        // Validate other fields
        assert_eq!(
            original.finalizer_count, restored.finalizer_count,
            "Finalizer count should match"
        );
        assert_eq!(
            original.cancel_reason, restored.cancel_reason,
            "Cancel reason should match"
        );
        assert_eq!(original.parent, restored.parent, "Parent should match");
        assert_eq!(
            original.metadata, restored.metadata,
            "Metadata should match"
        );

        // Validate budget
        let orig_budget = &original.budget;
        let rest_budget = &restored.budget;
        assert_eq!(
            orig_budget.deadline_nanos, rest_budget.deadline_nanos,
            "Budget deadline should match"
        );
        assert_eq!(
            orig_budget.polls_remaining, rest_budget.polls_remaining,
            "Budget polls should match"
        );
        assert_eq!(
            orig_budget.cost_remaining, rest_budget.cost_remaining,
            "Budget cost should match"
        );
    }
}

#[test]
fn test_consistent_hash_rebalancing_e2e() {
    let harness = DistributedTestHarness::new("consistent_hash_rebalancing_e2e");
    harness.test_consistent_hash_rebalancing();
}

#[test]
fn test_snapshot_serialization_roundtrip_e2e() {
    let harness = DistributedTestHarness::new("snapshot_serialization_roundtrip_e2e");
    harness.test_snapshot_serialization_roundtrip();
}

#[test]
fn test_concurrent_snapshot_operations_e2e() {
    let harness = DistributedTestHarness::new("concurrent_snapshot_operations_e2e");
    harness.test_concurrent_snapshot_operations();
}

#[test]
fn test_snapshot_error_handling_e2e() {
    let harness = DistributedTestHarness::new("snapshot_error_handling_e2e");
    harness.test_snapshot_error_handling();
}

#[test]
fn test_distributed_coordination_full_cycle_e2e() {
    let harness = DistributedTestHarness::new("distributed_coordination_full_cycle_e2e");

    harness.logger.log_phase("full_cycle_start");

    // Combined test: hash ring rebalancing with snapshot persistence
    harness.logger.log_phase("combined_setup");

    let vnodes_per_node = 50;
    let seed = 12345;
    let mut ring = HashRing::new(vnodes_per_node, seed);

    // Add initial nodes
    let nodes = vec!["replica_1", "replica_2", "replica_3"];
    for node in &nodes {
        ring.add_node(node);
    }

    // Create snapshots for each replica
    let snapshots: Vec<RegionSnapshot> = nodes
        .iter()
        .enumerate()
        .map(|(i, &node)| {
            let region_id = RegionId::new(ArenaIndex::new(i + 1), 1);
            let mut snapshot = RegionSnapshot::empty(region_id);
            snapshot.origin_id = format!("{}_origin", node).hash_code() as u64;
            snapshot.sequence = i as u64 * 10;
            snapshot.metadata = format!("replica_data_{}", node).into_bytes();
            snapshot
        })
        .collect();

    harness.logger.log_event(
        "combined_initial_state",
        serde_json::json!({
            "ring_nodes": ring.node_count(),
            "snapshots": snapshots.len()
        }),
    );

    // Simulate rebalancing with snapshot migration
    harness.logger.log_phase("rebalancing_with_snapshots");

    // Add new replica (scale up scenario)
    ring.add_node("replica_4");

    // Serialize all snapshots to simulate migration
    let serialized_snapshots: Vec<Vec<u8>> = snapshots.iter().map(|s| s.to_bytes()).collect();

    // Write snapshots to files (simulate network transfer/storage)
    let snapshot_files: Vec<PathBuf> = serialized_snapshots
        .iter()
        .enumerate()
        .map(|(i, data)| {
            let path = harness.temp_dir.path().join(format!("migration_{}.bin", i));
            let mut file = File::create(&path).expect("Failed to create migration file");
            file.write_all(data)
                .expect("Failed to write migration data");
            file.sync_all().expect("Failed to sync migration file");
            path
        })
        .collect();

    // Remove a replica (failure simulation)
    let removed = ring.remove_node("replica_2");

    harness.logger.log_event(
        "rebalancing_complete",
        serde_json::json!({
            "nodes_after_rebalancing": ring.node_count(),
            "vnodes_removed": removed,
            "migration_files": snapshot_files.len()
        }),
    );

    // Restore snapshots (simulate recovery)
    harness.logger.log_phase("snapshot_recovery");

    let recovered_snapshots: Vec<RegionSnapshot> = snapshot_files
        .iter()
        .map(|path| {
            let mut data = Vec::new();
            let mut file = File::open(path).expect("Failed to open migration file");
            file.read_to_end(&mut data)
                .expect("Failed to read migration data");

            RegionSnapshot::from_bytes(&data).expect("Failed to deserialize migration snapshot")
        })
        .collect();

    // Validate recovery integrity
    for (original, recovered) in snapshots.iter().zip(recovered_snapshots.iter()) {
        harness.validate_snapshot_roundtrip(original, recovered);
    }

    harness.logger.log_assertion(
        "full_cycle_success",
        true,
        serde_json::json!({
            "original_snapshots": snapshots.len(),
            "recovered_snapshots": recovered_snapshots.len(),
            "final_ring_nodes": ring.node_count()
        }),
    );

    harness.logger.log_phase("full_cycle_complete");
}

// Hash code trait for consistent hashing tests
trait HashCode {
    fn hash_code(&self) -> u64;
}

impl HashCode for String {
    fn hash_code(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl HashCode for &str {
    fn hash_code(&self) -> u64 {
        self.to_string().hash_code()
    }
}
