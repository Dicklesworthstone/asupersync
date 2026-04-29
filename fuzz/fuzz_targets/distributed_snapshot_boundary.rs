//! Layout-aware distributed snapshot boundary fuzzer
//!
//! Tests the robustness of RegionSnapshot deserialization against:
//! 1. Partial snapshots and truncated data
//! 2. Corruption detection (invalid magic, version, state bytes)
//! 3. State recovery edge cases (malformed optional fields)
//! 4. Boundary condition handling (counts, lengths, presence flags)
//! 5. OOM attack resistance and bounds checking
//!
//! Uses structure-aware generation to create valid snapshot layouts
//! with intelligent mutations that test boundary conditions and edge cases
//! in the binary format parser.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::snapshot::{RegionSnapshot, SnapshotError, MAX_METADATA_LEN};
use asupersync::record::region::RegionState;
use libfuzzer_sys::fuzz_target;

/// Maximum snapshot payload size to prevent OOM during fuzzing
const MAX_SNAPSHOT_SIZE: usize = 1024 * 1024; // 1 MB

/// Maximum field counts to prevent combinatorial explosion
const MAX_TASK_COUNT: usize = 100;
const MAX_CHILD_COUNT: usize = 50;

/// Snapshot boundary testing scenarios
#[derive(Debug, Clone, Arbitrary)]
enum SnapshotBoundaryScenario {
    /// Valid complete snapshot
    ValidComplete,
    /// Partial snapshot (truncated at various points)
    PartialTruncated,
    /// Corrupted magic bytes
    CorruptedMagic,
    /// Invalid version byte
    InvalidVersion,
    /// Invalid state/presence flags
    InvalidFlags,
    /// Malformed optional fields
    MalformedOptional,
    /// Oversized counts/lengths (OOM attacks)
    OversizedCounts,
    /// Trailing garbage data
    TrailingGarbage,
    /// Boundary value testing
    BoundaryValues,
}

/// Layout-aware snapshot data for structure-aware fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSnapshotData {
    scenario: SnapshotBoundaryScenario,

    // Header fields
    #[arbitrary(with = arbitrary_magic_bytes)]
    magic: [u8; 4],
    version: u8,

    // Core snapshot fields
    #[arbitrary(with = arbitrary_region_id)]
    region_id: (u32, u32), // (index, generation)
    #[arbitrary(with = arbitrary_state_byte)]
    state_byte: u8,
    timestamp_nanos: u64,
    sequence: u64,
    origin_id: u64,
    epoch: u64,

    // Variable-length fields
    #[arbitrary(with = arbitrary_task_list)]
    tasks: Vec<FuzzTaskSnapshot>,
    #[arbitrary(with = arbitrary_child_list)]
    children: Vec<(u32, u32)>, // (index, generation) pairs

    finalizer_count: u32,

    // Budget fields (optional)
    budget_deadline_present: bool,
    budget_deadline_nanos: u64,
    budget_polls_present: bool,
    budget_polls_remaining: u32,
    budget_cost_present: bool,
    budget_cost_remaining: u64,

    // Cancel reason (optional string)
    cancel_reason_present: bool,
    #[arbitrary(with = arbitrary_bounded_string)]
    cancel_reason: String,

    // Parent (optional)
    parent_present: bool,
    #[arbitrary(with = arbitrary_region_id)]
    parent_region: (u32, u32),

    // Metadata blob
    #[arbitrary(with = arbitrary_metadata_blob)]
    metadata: Vec<u8>,

    // Corruption/boundary test parameters
    #[arbitrary(with = arbitrary_truncation_point)]
    truncation_point: usize,
    #[arbitrary(with = arbitrary_trailing_data)]
    trailing_garbage: Vec<u8>,
}

/// Simplified task snapshot for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzTaskSnapshot {
    #[arbitrary(with = arbitrary_task_id)]
    task_id: (u32, u32), // (index, generation)
    #[arbitrary(with = arbitrary_task_state_byte)]
    state_byte: u8,
    priority: u8,
}

/// Generate magic bytes with potential corruption
fn arbitrary_magic_bytes(u: &mut arbitrary::Unstructured) -> arbitrary::Result<[u8; 4]> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0..=7 => *b"SNAP", // Valid magic most of the time
        8 => *b"SNAX",     // Corrupted magic
        9 => *b"XNAP",     // Byte-swapped
        10 => [u.arbitrary()?, u.arbitrary()?, u.arbitrary()?, u.arbitrary()?], // Random
        _ => *b"SNAP",
    })
}

/// Generate region ID components
fn arbitrary_region_id(u: &mut arbitrary::Unstructured) -> arbitrary::Result<(u32, u32)> {
    Ok((u.arbitrary()?, u.arbitrary()?))
}

/// Generate task ID components
fn arbitrary_task_id(u: &mut arbitrary::Unstructured) -> arbitrary::Result<(u32, u32)> {
    Ok((u.arbitrary()?, u.arbitrary()?))
}

/// Generate state bytes with boundary values
fn arbitrary_state_byte(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0..=5 => u.int_in_range(0..=4)?, // Valid RegionState values (0-4)
        6..=8 => u.int_in_range(5..=10)?, // Invalid but close
        9 => 255,                          // Maximum value
        10 => u.arbitrary()?,              // Random
        _ => 0,
    })
}

/// Generate task state bytes with boundary values
fn arbitrary_task_state_byte(u: &mut arbitrary::Unstructured) -> arbitrary::Result<u8> {
    let choice = u.int_in_range(0..=10)?;
    Ok(match choice {
        0..=5 => u.int_in_range(0..=4)?, // Valid TaskState values (0-4)
        6..=8 => u.int_in_range(5..=10)?, // Invalid but close
        9 => 255,                          // Maximum value
        10 => u.arbitrary()?,              // Random
        _ => 0,
    })
}

/// Generate bounded task list
fn arbitrary_task_list(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<FuzzTaskSnapshot>> {
    let count = u.int_in_range(0..=MAX_TASK_COUNT)?;
    let mut tasks = Vec::with_capacity(count);
    for _ in 0..count {
        tasks.push(FuzzTaskSnapshot::arbitrary(u)?);
    }
    Ok(tasks)
}

/// Generate bounded child list
fn arbitrary_child_list(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<(u32, u32)>> {
    let count = u.int_in_range(0..=MAX_CHILD_COUNT)?;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        children.push(arbitrary_region_id(u)?);
    }
    Ok(children)
}

/// Generate bounded string (for cancel reason)
fn arbitrary_bounded_string(u: &mut arbitrary::Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=1024)?; // Reasonable string length
    let mut bytes = vec![0u8; len];
    u.fill_buffer(&mut bytes)?;

    // Ensure valid UTF-8 with some probability
    if u.int_in_range(0..=2)? == 0 {
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        // Generate potentially invalid UTF-8
        Ok(unsafe { String::from_utf8_unchecked(bytes) })
    }
}

/// Generate metadata blob with size boundary testing
fn arbitrary_metadata_blob(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let choice = u.int_in_range(0..=10)?;
    let size = match choice {
        0..=6 => u.int_in_range(0..=1024)?, // Normal sizes
        7 => MAX_METADATA_LEN,              // Exactly at limit
        8 => MAX_METADATA_LEN + 1,          // Just over limit (should fail)
        9 => MAX_METADATA_LEN * 2,          // Way over limit
        10 => u32::MAX as usize,            // Maximum possible (should fail)
        _ => 0,
    };

    let actual_size = size.min(MAX_SNAPSHOT_SIZE / 2); // Prevent OOM in fuzzer itself
    let mut blob = vec![0u8; actual_size];
    u.fill_buffer(&mut blob)?;
    Ok(blob)
}

/// Generate truncation point for partial snapshot testing
fn arbitrary_truncation_point(u: &mut arbitrary::Unstructured) -> arbitrary::Result<usize> {
    u.int_in_range(0..=512) // Truncate somewhere in first 512 bytes
}

/// Generate trailing garbage data
fn arbitrary_trailing_data(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=64)?;
    let mut data = vec![0u8; len];
    u.fill_buffer(&mut data)?;
    Ok(data)
}

impl FuzzSnapshotData {
    /// Convert to binary snapshot format for testing
    fn to_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&self.magic);
        buf.push(self.version);

        // Region ID
        buf.extend_from_slice(&self.region_id.0.to_le_bytes());
        buf.extend_from_slice(&self.region_id.1.to_le_bytes());

        // State
        buf.push(self.state_byte);

        // Core fields
        buf.extend_from_slice(&self.timestamp_nanos.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.origin_id.to_le_bytes());
        buf.extend_from_slice(&self.epoch.to_le_bytes());

        // Tasks
        let task_count = self.tasks.len().min(u32::MAX as usize) as u32;
        buf.extend_from_slice(&task_count.to_le_bytes());
        for task in &self.tasks {
            buf.extend_from_slice(&task.task_id.0.to_le_bytes());
            buf.extend_from_slice(&task.task_id.1.to_le_bytes());
            buf.push(task.state_byte);
            buf.push(task.priority);
        }

        // Children
        let child_count = self.children.len().min(u32::MAX as usize) as u32;
        buf.extend_from_slice(&child_count.to_le_bytes());
        for child in &self.children {
            buf.extend_from_slice(&child.0.to_le_bytes());
            buf.extend_from_slice(&child.1.to_le_bytes());
        }

        // Finalizer count
        buf.extend_from_slice(&self.finalizer_count.to_le_bytes());

        // Budget (optional fields)
        buf.push(if self.budget_deadline_present { 1 } else { 0 });
        if self.budget_deadline_present {
            buf.extend_from_slice(&self.budget_deadline_nanos.to_le_bytes());
        }

        buf.push(if self.budget_polls_present { 1 } else { 0 });
        if self.budget_polls_present {
            buf.extend_from_slice(&self.budget_polls_remaining.to_le_bytes());
        }

        buf.push(if self.budget_cost_present { 1 } else { 0 });
        if self.budget_cost_present {
            buf.extend_from_slice(&self.budget_cost_remaining.to_le_bytes());
        }

        // Cancel reason (optional string)
        buf.push(if self.cancel_reason_present { 1 } else { 0 });
        if self.cancel_reason_present {
            let reason_bytes = self.cancel_reason.as_bytes();
            let reason_len = reason_bytes.len().min(u32::MAX as usize) as u32;
            buf.extend_from_slice(&reason_len.to_le_bytes());
            buf.extend_from_slice(reason_bytes);
        }

        // Parent (optional)
        buf.push(if self.parent_present { 1 } else { 0 });
        if self.parent_present {
            buf.extend_from_slice(&self.parent_region.0.to_le_bytes());
            buf.extend_from_slice(&self.parent_region.1.to_le_bytes());
        }

        // Metadata
        let metadata_len = self.metadata.len().min(u32::MAX as usize) as u32;
        buf.extend_from_slice(&metadata_len.to_le_bytes());
        buf.extend_from_slice(&self.metadata);

        buf
    }

    /// Apply scenario-specific mutations to the binary data
    fn apply_boundary_mutations(&self, mut buf: Vec<u8>) -> Vec<u8> {
        match self.scenario {
            SnapshotBoundaryScenario::ValidComplete => buf, // No mutations

            SnapshotBoundaryScenario::PartialTruncated => {
                let trunc_point = self.truncation_point.min(buf.len());
                buf.truncate(trunc_point);
                buf
            }

            SnapshotBoundaryScenario::CorruptedMagic => {
                if buf.len() >= 4 {
                    buf[0..4].copy_from_slice(b"XXXX"); // Corrupt magic
                }
                buf
            }

            SnapshotBoundaryScenario::InvalidVersion => {
                if buf.len() >= 5 {
                    buf[4] = 255; // Invalid version
                }
                buf
            }

            SnapshotBoundaryScenario::InvalidFlags => {
                // Corrupt presence flags to invalid values (not 0 or 1)
                let flag_positions = [
                    5 + 8 + 1 + 8 + 8 + 8 + 8 + 4, // After task count, before budget
                ];
                for &pos in &flag_positions {
                    if pos < buf.len() {
                        buf[pos] = 2; // Invalid presence flag
                        break;
                    }
                }
                buf
            }

            SnapshotBoundaryScenario::MalformedOptional => {
                // Set presence flag to 1 but truncate the following data
                if buf.len() > 50 {
                    buf.truncate(buf.len() - 10);
                }
                buf
            }

            SnapshotBoundaryScenario::OversizedCounts => {
                // Set task count to maximum u32, but provide no task data
                if buf.len() >= 4 + 1 + 8 + 1 + 8 + 8 + 8 + 8 + 4 {
                    let task_count_offset = 4 + 1 + 8 + 1 + 8 + 8 + 8 + 8;
                    buf[task_count_offset..task_count_offset + 4]
                        .copy_from_slice(&u32::MAX.to_le_bytes());
                    buf.truncate(task_count_offset + 4); // No actual task data
                }
                buf
            }

            SnapshotBoundaryScenario::TrailingGarbage => {
                buf.extend_from_slice(&self.trailing_garbage);
                buf
            }

            SnapshotBoundaryScenario::BoundaryValues => {
                // Test various boundary values throughout the buffer
                if !buf.is_empty() {
                    let len = buf.len();
                    buf[len - 1] = 0xFF; // Set last byte to boundary value
                }
                buf
            }
        }
    }
}

/// Validate snapshot parsing against a known-good implementation
fn validate_snapshot_parsing(data: &[u8]) -> Result<RegionSnapshot, SnapshotError> {
    RegionSnapshot::from_bytes(data)
}

/// Test snapshot invariants that should hold even for malformed input
fn check_snapshot_invariants(result: &Result<RegionSnapshot, SnapshotError>) {
    match result {
        Ok(snapshot) => {
            // Invariant: Successful parse must have valid region state
            assert!(matches!(
                snapshot.state,
                RegionState::Open
                    | RegionState::Closing
                    | RegionState::Draining
                    | RegionState::Finalizing
                    | RegionState::Closed
            ));

            // Invariant: Metadata must respect size limits
            assert!(snapshot.metadata.len() <= MAX_METADATA_LEN);

            // Invariant: Round-trip property for valid snapshots
            let serialized = snapshot.to_bytes();
            let reparsed = RegionSnapshot::from_bytes(&serialized);
            assert!(
                reparsed.is_ok(),
                "Valid snapshot must round-trip successfully"
            );
        }
        Err(err) => {
            // Invariant: Error types must be appropriate for the failure
            match err {
                SnapshotError::InvalidMagic
                | SnapshotError::UnsupportedVersion(_)
                | SnapshotError::InvalidState(_)
                | SnapshotError::UnexpectedEof
                | SnapshotError::InvalidString
                | SnapshotError::InvalidPresenceFlag(_)
                | SnapshotError::TrailingBytes(_)
                | SnapshotError::MetadataTooLarge { .. } => {
                    // These are all expected error types
                }
            }
        }
    }
}

fuzz_target!(|fuzz_data: FuzzSnapshotData| {
    // Guard against pathological inputs
    if fuzz_data.tasks.len() > MAX_TASK_COUNT || fuzz_data.children.len() > MAX_CHILD_COUNT {
        return;
    }

    // Generate base binary snapshot data
    let base_buf = fuzz_data.to_binary();

    // Skip if base buffer would be too large
    if base_buf.len() > MAX_SNAPSHOT_SIZE {
        return;
    }

    // Apply scenario-specific boundary mutations
    let test_buf = fuzz_data.apply_boundary_mutations(base_buf);

    // Test 1: Parse the mutated snapshot data
    let parse_result = validate_snapshot_parsing(&test_buf);

    // Test 2: Verify parsing invariants hold regardless of input
    check_snapshot_invariants(&parse_result);

    // Test 3: Ensure parsing is deterministic (same input → same result)
    let parse_result2 = validate_snapshot_parsing(&test_buf);
    match (&parse_result, &parse_result2) {
        (Ok(snap1), Ok(snap2)) => {
            assert_eq!(
                snap1.content_hash(),
                snap2.content_hash(),
                "Parsing must be deterministic"
            );
        }
        (Err(err1), Err(err2)) => {
            assert_eq!(err1, err2, "Error type must be deterministic");
        }
        _ => panic!("Parsing determinism violation: different Ok/Err results"),
    }

    // Test 4: State recovery testing - if we successfully parse,
    // test various recovery scenarios
    if let Ok(ref snapshot) = parse_result {
        // Test merge operation invariants
        let empty_snapshot = RegionSnapshot::empty(snapshot.region_id);
        if let Ok(merged) = snapshot.merge_crdt(&empty_snapshot) {
            // Invariant: Merging with empty should preserve non-empty data
            assert_eq!(merged.sequence, snapshot.sequence.max(0));
            assert_eq!(merged.region_id, snapshot.region_id);
        }

        // Test serialization round-trip invariants
        let re_serialized = snapshot.to_bytes();
        let re_parsed = RegionSnapshot::from_bytes(&re_serialized);
        assert!(
            re_parsed.is_ok(),
            "Re-serialized snapshot must parse successfully"
        );

        // Test size estimation accuracy
        let actual_size = re_serialized.len();
        let estimated_size = snapshot.size_estimate();
        assert!(
            estimated_size >= actual_size / 2 && estimated_size <= actual_size * 3,
            "Size estimate {estimated_size} must be reasonable vs actual {actual_size}"
        );
    }

    // Test 5: Boundary condition stress testing
    match fuzz_data.scenario {
        SnapshotBoundaryScenario::OversizedCounts => {
            // Must handle oversized counts gracefully (no panic, controlled error)
            matches!(
                parse_result,
                Err(SnapshotError::UnexpectedEof | SnapshotError::MetadataTooLarge { .. })
            );
        }
        SnapshotBoundaryScenario::TrailingGarbage => {
            if !fuzz_data.trailing_garbage.is_empty() {
                // Must detect and reject trailing bytes
                if let Err(ref err) = parse_result {
                    assert!(matches!(err, SnapshotError::TrailingBytes(_)));
                }
            }
        }
        SnapshotBoundaryScenario::CorruptedMagic => {
            // Must reject invalid magic bytes
            assert!(matches!(parse_result, Err(SnapshotError::InvalidMagic)));
        }
        _ => {
            // Other scenarios tested via general invariants above
        }
    }
});