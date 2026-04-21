//! Golden snapshot tests for distributed snapshot artifact format.
//!
//! These tests ensure the distributed snapshot serialization format remains
//! stable across code changes. Critical for maintaining binary compatibility
//! in distributed environments and consensus protocols.
//!
//! To update golden files after an intentional format change:
//!   1. Run `cargo test --test golden_distributed_snapshot`
//!   2. Review all changes via `cargo insta review`
//!   3. Accept changes with `cargo insta accept` if correct
//!   4. Commit with detailed explanation of format changes

use asupersync::distributed::snapshot::{
    BudgetSnapshot, RegionSnapshot, SnapshotError, TaskSnapshot, TaskState,
};
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, TaskId, Time};
use insta::{assert_debug_snapshot, Settings};

/// Complete snapshot format capture for golden testing
#[derive(Debug, Clone)]
pub struct SnapshotFormatCapture {
    /// Test scenario name
    pub scenario: String,
    /// The original snapshot before serialization
    pub original: RegionSnapshot,
    /// Serialized bytes (hex-encoded for readability)
    pub serialized_hex: String,
    /// Size in bytes
    pub size_bytes: usize,
    /// Deserialized snapshot (should match original)
    pub deserialized: Result<RegionSnapshot, SnapshotError>,
    /// Content hash for deduplication
    pub content_hash: u64,
    /// Generation metadata
    pub metadata: SnapshotCaptureMetadata,
}

/// Metadata about how the snapshot was captured
#[derive(Debug, Clone)]
pub struct SnapshotCaptureMetadata {
    /// Test name that generated this capture
    pub test_name: String,
    /// Description of the snapshot scenario
    pub description: String,
    /// Wire format version
    pub version: u8,
    /// Magic bytes (should always be "SNAP")
    pub magic: String,
}

/// Generate a complete format capture for a snapshot scenario
fn generate_snapshot_capture(
    scenario_name: &str,
    description: &str,
    snapshot: RegionSnapshot,
) -> SnapshotFormatCapture {
    let serialized = snapshot.to_bytes();
    let serialized_hex = serialized
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let content_hash = snapshot.content_hash();

    let deserialized = RegionSnapshot::from_bytes(&serialized);

    // Extract magic and version from serialized bytes
    let magic = if serialized.len() >= 4 {
        String::from_utf8_lossy(&serialized[0..4]).to_string()
    } else {
        "[invalid]".to_string()
    };
    let version = serialized.get(4).copied().unwrap_or(0);

    SnapshotFormatCapture {
        scenario: scenario_name.to_string(),
        original: snapshot,
        serialized_hex,
        size_bytes: serialized.len(),
        deserialized,
        content_hash,
        metadata: SnapshotCaptureMetadata {
            test_name: scenario_name.to_string(),
            description: description.to_string(),
            version,
            magic,
        },
    }
}

#[test]
fn snapshot_empty_region() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot::empty(RegionId::new_for_test(1, 0));

    let capture = generate_snapshot_capture(
        "empty_region",
        "Minimal empty region snapshot with no tasks, children, or metadata",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("empty_region", capture);
    });
}

#[test]
fn snapshot_simple_open_region() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(42, 3),
        state: RegionState::Open,
        timestamp: Time::from_secs(1000),
        sequence: 5,
        tasks: vec![TaskSnapshot {
            task_id: TaskId::new_for_test(10, 1),
            state: TaskState::Running,
            priority: 8,
        }],
        children: vec![RegionId::new_for_test(50, 0)],
        finalizer_count: 2,
        budget: BudgetSnapshot {
            deadline_nanos: Some(5_000_000_000), // 5 seconds
            polls_remaining: Some(100),
            cost_remaining: None,
        },
        cancel_reason: None,
        parent: None,
        metadata: vec![1, 2, 3, 4],
    };

    let capture = generate_snapshot_capture(
        "simple_open_region",
        "Basic open region with single task, child, and partial budget",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("simple_open_region", capture);
    });
}

#[test]
fn snapshot_complex_closing_region() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(99, 7),
        state: RegionState::Closing,
        timestamp: Time::from_millis(1_500_000), // 25 minutes
        sequence: 42,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(20, 2),
                state: TaskState::Completed,
                priority: 5,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(21, 0),
                state: TaskState::Cancelled,
                priority: 3,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(22, 1),
                state: TaskState::Panicked,
                priority: 10,
            },
        ],
        children: vec![
            RegionId::new_for_test(100, 1),
            RegionId::new_for_test(101, 2),
        ],
        finalizer_count: 7,
        budget: BudgetSnapshot {
            deadline_nanos: Some(10_000_000_000), // 10 seconds
            polls_remaining: Some(50),
            cost_remaining: Some(1024),
        },
        cancel_reason: Some("timeout_exceeded".to_string()),
        parent: Some(RegionId::new_for_test(0, 1)),
        metadata: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    };

    let capture = generate_snapshot_capture(
        "complex_closing_region",
        "Complex closing region with multiple tasks, cancellation, and full budget",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("complex_closing_region", capture);
    });
}

#[test]
fn snapshot_finalized_region() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(200, 15),
        state: RegionState::Closed,
        timestamp: Time::from_nanos(9_876_543_210_123), // Large timestamp
        sequence: 999,
        tasks: vec![], // No tasks in finalized region
        children: vec![], // No children in finalized region
        finalizer_count: 0,
        budget: BudgetSnapshot {
            deadline_nanos: None, // No deadline in finalized
            polls_remaining: None, // No polls remaining
            cost_remaining: None, // No cost remaining
        },
        cancel_reason: Some("region_completed".to_string()),
        parent: Some(RegionId::new_for_test(199, 14)),
        metadata: vec![], // Empty metadata
    };

    let capture = generate_snapshot_capture(
        "finalized_region",
        "Finalized region with no tasks or children, representing completed lifecycle",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("finalized_region", capture);
    });
}

#[test]
fn snapshot_draining_region() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(300, 8),
        state: RegionState::Draining,
        timestamp: Time::from_secs(7200), // 2 hours
        sequence: 128,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(1000, 10),
                state: TaskState::Pending,
                priority: 1,
            },
        ],
        children: vec![
            RegionId::new_for_test(301, 0),
            RegionId::new_for_test(302, 0),
            RegionId::new_for_test(303, 0),
        ],
        finalizer_count: 15,
        budget: BudgetSnapshot {
            deadline_nanos: Some(1_000_000_000), // 1 second deadline
            polls_remaining: Some(5), // Low poll count
            cost_remaining: Some(100),
        },
        cancel_reason: Some("user_cancel_request".to_string()),
        parent: Some(RegionId::new_for_test(299, 7)),
        metadata: b"drain_metadata".to_vec(),
    };

    let capture = generate_snapshot_capture(
        "draining_region",
        "Draining region with pending tasks and active cancellation",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("draining_region", capture);
    });
}

#[test]
fn snapshot_all_task_states() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(400, 20),
        state: RegionState::Open,
        timestamp: Time::from_millis(12345),
        sequence: 77,
        tasks: vec![
            TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Pending,
                priority: 1,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(2, 0),
                state: TaskState::Running,
                priority: 5,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(3, 0),
                state: TaskState::Completed,
                priority: 3,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(4, 0),
                state: TaskState::Cancelled,
                priority: 7,
            },
            TaskSnapshot {
                task_id: TaskId::new_for_test(5, 0),
                state: TaskState::Panicked,
                priority: 9,
            },
        ],
        children: vec![],
        finalizer_count: 3,
        budget: BudgetSnapshot {
            deadline_nanos: Some(2_500_000_000), // 2.5 seconds
            polls_remaining: Some(25),
            cost_remaining: Some(500),
        },
        cancel_reason: None,
        parent: None,
        metadata: b"all_states_test".to_vec(),
    };

    let capture = generate_snapshot_capture(
        "all_task_states",
        "Region demonstrating all possible task states in one snapshot",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("all_task_states", capture);
    });
}

#[test]
fn snapshot_maximum_complexity() {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path("tests/snapshots/distributed_snapshot");

    // Create a maximally complex snapshot with many elements
    let mut tasks = vec![];
    let mut children = vec![];

    // Add 10 tasks with varied states and priorities
    for i in 0..10 {
        tasks.push(TaskSnapshot {
            task_id: TaskId::new_for_test(1000 + i, i % 3),
            state: match i % 5 {
                0 => TaskState::Pending,
                1 => TaskState::Running,
                2 => TaskState::Completed,
                3 => TaskState::Cancelled,
                4 => TaskState::Panicked,
                _ => unreachable!(),
            },
            priority: (i % 11) as u8,
        });
    }

    // Add 5 children
    for i in 0..5 {
        children.push(RegionId::new_for_test(2000 + i, i % 4));
    }

    let snapshot = RegionSnapshot {
        region_id: RegionId::new_for_test(500, 99),
        state: RegionState::Finalizing,
        timestamp: Time::from_nanos(18_446_744_073_709_551_615), // Near u64::MAX
        sequence: u64::MAX,
        tasks,
        children,
        finalizer_count: 100,
        budget: BudgetSnapshot {
            deadline_nanos: Some(u64::MAX),
            polls_remaining: Some(u32::MAX),
            cost_remaining: Some(u64::MAX),
        },
        cancel_reason: Some("maximum_complexity_test_scenario_with_very_long_reason_string_to_test_string_serialization".to_string()),
        parent: Some(RegionId::new_for_test(499, 98)),
        metadata: (0..100u8).collect(), // 100 bytes of metadata
    };

    let capture = generate_snapshot_capture(
        "maximum_complexity",
        "Maximally complex snapshot testing boundary conditions and large data sets",
        snapshot,
    );

    settings.bind(|| {
        assert_debug_snapshot!("maximum_complexity", capture);
    });
}

/// Create a PROVENANCE.md file documenting golden file generation
#[allow(dead_code)]
fn create_provenance_file() -> std::io::Result<()> {
    use std::fs;

    let provenance_content = r#"# Distributed Snapshot Golden Snapshot Provenance

## How Golden Snapshots Are Generated

### Environment Requirements
- **Platform**: Any (snapshot format is platform-independent)
- **Rust Version**: Matches project MSRV (see Cargo.toml)
- **Dependencies**: Uses insta crate for snapshot testing

### Generation Commands
```bash
# Generate all snapshot files
cargo test --test golden_distributed_snapshot

# Review snapshots
cargo insta review

# Accept snapshots if correct
cargo insta accept
```

### Golden Snapshot Format
- **Format**: Debug representation of SnapshotFormatCapture structs
- **Content**: Original snapshots, hex-encoded serialized bytes, deserialization results
- **Binary Format**: Magic "SNAP" + version byte + deterministic little-endian encoding
- **Hash**: FNV-1a content hash for deduplication

### Validation Workflow
1. Run tests to generate/compare snapshots
2. Review snapshot changes via `cargo insta review`
3. Accept correct changes with `cargo insta accept`
4. Commit snapshot files with descriptive commit message

### Regeneration Triggers
- Changes to binary serialization format
- Updates to RegionSnapshot structure
- Changes to magic bytes or version
- Modifications to CRDT merge logic
- Wire protocol compatibility changes

### Last Generated
- **Date**: 2026-04-21
- **Test Suite**: golden_distributed_snapshot.rs
- **Format Version**: 1 (SNAP magic bytes)
- **Scenarios**: empty, simple_open, complex_closing, finalized, draining, all_task_states, maximum_complexity

### Test Scenarios

#### empty_region
- Minimal RegionSnapshot created via ::empty() constructor
- Tests baseline serialization with no tasks, children, or metadata

#### simple_open_region
- Basic open region with single task and child
- Tests typical active region state serialization

#### complex_closing_region
- Closing region with multiple tasks in different states
- Tests complex scenario with cancellation reason and full budget

#### finalized_region
- Closed region with no active tasks or children
- Tests end-of-lifecycle serialization format

#### draining_region
- Draining region with active cancellation
- Tests intermediate shutdown state serialization

#### all_task_states
- Region demonstrating all TaskState enum values
- Tests complete TaskState serialization coverage

#### maximum_complexity
- Maximally complex snapshot with boundary-condition values
- Tests large data sets, maximum values, and string handling

## Binary Format Stability

The distributed snapshot binary format is critical for consensus and replication:

1. **Magic Bytes**: Must remain "SNAP" for format detection
2. **Version Byte**: Must increment on breaking changes to wire format
3. **Field Ordering**: Little-endian encoding order must remain stable
4. **Optional Fields**: Presence flags (0/1) must maintain backward compatibility
5. **String Encoding**: UTF-8 with length prefix must remain consistent

## Usage Guidelines

When modifying snapshot serialization:
1. Run test suite to establish baseline
2. Make implementation changes
3. Re-run tests and review snapshot diffs carefully
4. Accept snapshots only if changes are intentional and protocol-compliant
5. Document breaking changes that affect distributed consensus

This ensures distributed snapshots maintain wire format compatibility across versions.
"#;

    fs::create_dir_all("tests/snapshots/distributed_snapshot")?;
    fs::write(
        "tests/snapshots/distributed_snapshot/PROVENANCE.md",
        provenance_content,
    )?;
    Ok(())
}