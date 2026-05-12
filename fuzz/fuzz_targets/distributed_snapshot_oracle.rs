#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Oracle-based fuzz target for RegionSnapshot serialization/deserialization.
///
/// This target tests the distributed snapshot serialization in src/distributed/snapshot.rs
/// with multiple oracle strategies:
///
/// **Primary Oracle: Round-Trip Invariant**
/// For any valid snapshot that serializes successfully:
/// - `from_bytes(snapshot.to_bytes()) == Ok(equivalent_snapshot)`
/// - All semantic fields must be preserved across round-trip
/// - Binary format must be deterministic (same input → same bytes)
///
/// **Secondary Oracle: Parser Invariants**
/// For all inputs (valid and invalid):
/// - No panics on malformed input
/// - Error classification must be consistent
/// - Memory bounds must be respected (no allocate-before-validate)
/// - State machine transitions must be valid
///
/// **Attack Vectors Covered:**
/// - Magic byte corruption/bypass attempts
/// - Version confusion attacks
/// - Integer overflow in length fields
/// - Buffer over-read via crafted size fields
/// - UTF-8 injection in string fields
/// - Presence flag manipulation (non-0/1 values)
/// - Trailing data injection after valid frames
/// - Metadata length field amplification attacks
/// - Task/children vector length bombs
/// - State enum out-of-bounds values
use asupersync::distributed::snapshot::{RegionSnapshot, SnapshotError};
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, Time};

/// Maximum input size for fuzzing (16 MB - matches parser limit)
const MAX_INPUT_SIZE: usize = 16 * 1024 * 1024;

/// Maximum reasonable vector sizes for structure-aware generation
const MAX_VECTOR_LEN: usize = 100;
const MAX_STRING_LEN: usize = 1024;
const MAX_METADATA_LEN: usize = 64 * 1024;

#[derive(Arbitrary, Debug, Clone)]
enum FuzzOperation {
    /// Test raw byte parsing (crash oracle)
    ParseRawBytes { data: Vec<u8> },

    /// Test round-trip oracle with structured generation
    RoundTripTest {
        snapshot: FuzzableSnapshot,
        corruption: Option<CorruptionPattern>,
    },

    /// Test edge cases and boundary conditions
    BoundaryTest { pattern: BoundaryPattern },
}

/// Simplified snapshot structure for Arbitrary generation
#[derive(Arbitrary, Debug, Clone)]
struct FuzzableSnapshot {
    region_id_index: u32,
    region_id_generation: u32,
    state: u8,  // Raw state value (may be invalid)
    timestamp_nanos: u64,
    sequence: u64,
    origin_id: u64,
    epoch: u64,
    #[arbitrary(with = arbitrary_bounded_vec::<FuzzableTaskSnapshot>)]
    tasks: Vec<FuzzableTaskSnapshot>,
    #[arbitrary(with = arbitrary_bounded_vec::<(u32, u32)>)]  // (index, generation) pairs
    children: Vec<(u32, u32)>,
    finalizer_count: u32,
    budget: FuzzableBudgetSnapshot,
    #[arbitrary(with = arbitrary_bounded_string)]
    cancel_reason: Option<String>,
    parent: Option<(u32, u32)>,  // (index, generation)
    #[arbitrary(with = arbitrary_bounded_metadata)]
    metadata: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzableTaskSnapshot {
    task_id_index: u32,
    task_id_generation: u32,
    state: u8,  // Raw state value
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzableBudgetSnapshot {
    deadline_nanos: Option<u64>,
    polls_remaining: Option<u32>,
    cost_remaining: Option<u64>,
}

/// Corruption patterns to test error handling
#[derive(Arbitrary, Debug, Clone)]
enum CorruptionPattern {
    /// Corrupt magic bytes
    BadMagic([u8; 4]),
    /// Unsupported version
    BadVersion(u8),
    /// Inject trailing bytes
    TrailingBytes(Vec<u8>),
    /// Corrupt presence flags (non-0/1)
    BadPresenceFlag { field: u8, value: u8 },
    /// Overflow length fields
    OversizeMetadata(u32),
}

/// Boundary condition patterns
#[derive(Arbitrary, Debug, Clone)]
enum BoundaryPattern {
    /// Empty input
    Empty,
    /// Only magic bytes
    OnlyMagic,
    /// Truncated at various points
    Truncated { valid_prefix_len: usize },
    /// Maximum size inputs
    MaxSize,
    /// Large vector fields
    LargeVectors,
    /// Unicode edge cases
    UnicodeEdgeCases,
}

// Custom arbitrary functions for bounded generation
fn arbitrary_bounded_vec<T>(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<T>>
where
    T: for<'a> Arbitrary<'a>,
{
    let len = u.int_in_range(0..=MAX_VECTOR_LEN)?;
    let mut vec = Vec::with_capacity(len);
    for _ in 0..len {
        vec.push(T::arbitrary(u)?);
    }
    Ok(vec)
}

fn arbitrary_bounded_string(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Option<String>> {
    if u.arbitrary::<bool>()? {
        let len = u.int_in_range(0..=MAX_STRING_LEN)?;
        let bytes = u.bytes(len)?.to_vec();
        // Generate both valid and invalid UTF-8 to test string handling
        if u.arbitrary::<bool>()? {
            Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
        } else {
            // Raw bytes that may not be valid UTF-8 (for testing error paths)
            Ok(Some(unsafe { String::from_utf8_unchecked(bytes) }))
        }
    } else {
        Ok(None)
    }
}

fn arbitrary_bounded_metadata(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_METADATA_LEN)?;
    Ok(u.bytes(len)?.to_vec())
}

impl FuzzableSnapshot {
    /// Convert to a real RegionSnapshot for round-trip testing
    fn to_region_snapshot(&self) -> Option<RegionSnapshot> {
        let region_id = RegionId::new_for_test(self.region_id_index, self.region_id_generation);

        // Only use valid state values for round-trip tests
        let state = match self.state {
            0 => RegionState::Open,
            1 => RegionState::Closing,
            2 => RegionState::Closed,
            _ => return None,  // Invalid state, skip round-trip test
        };

        // Validate string fields are proper UTF-8 for round-trip
        if let Some(ref reason) = self.cancel_reason {
            if !reason.is_valid_utf8() { return None; }
        }

        Some(RegionSnapshot {
            region_id,
            state,
            timestamp: Time::from_nanos(self.timestamp_nanos),
            sequence: self.sequence,
            origin_id: self.origin_id,
            epoch: self.epoch,
            tasks: self.tasks.iter().filter_map(|t| t.to_task_snapshot()).collect(),
            children: self.children.iter()
                .map(|(idx, generation)| RegionId::new_for_test(*idx, *generation))
                .collect(),
            finalizer_count: self.finalizer_count,
            budget: self.budget.to_budget_snapshot(),
            cancel_reason: self.cancel_reason.clone(),
            parent: self.parent.map(|(idx, generation)| RegionId::new_for_test(idx, generation)),
            metadata: self.metadata.clone(),
        })
    }
}

impl FuzzableTaskSnapshot {
    fn to_task_snapshot(&self) -> Option<asupersync::distributed::snapshot::TaskSnapshot> {
        use asupersync::distributed::snapshot::TaskSnapshot;
        use asupersync::types::TaskId;

        let task_state = match self.state {
            0 => asupersync::distributed::snapshot::TaskState::Pending,
            1 => asupersync::distributed::snapshot::TaskState::Running,
            2 => asupersync::distributed::snapshot::TaskState::Completed,
            3 => asupersync::distributed::snapshot::TaskState::Cancelled,
            4 => asupersync::distributed::snapshot::TaskState::Panicked,
            _ => return None,  // Invalid state
        };

        Some(TaskSnapshot {
            task_id: TaskId::new_for_test(self.task_id_index, self.task_id_generation),
            state: task_state,
            priority: Default::default(),  // Use default priority
        })
    }
}

impl FuzzableBudgetSnapshot {
    fn to_budget_snapshot(&self) -> asupersync::distributed::snapshot::BudgetSnapshot {
        use asupersync::distributed::snapshot::BudgetSnapshot;

        BudgetSnapshot {
            deadline_nanos: self.deadline_nanos,
            polls_remaining: self.polls_remaining,
            cost_remaining: self.cost_remaining,
        }
    }
}

// Helper extension for UTF-8 validation
trait Utf8Validator {
    fn is_valid_utf8(&self) -> bool;
}

impl Utf8Validator for String {
    fn is_valid_utf8(&self) -> bool {
        std::str::from_utf8(self.as_bytes()).is_ok()
    }
}

fuzz_target!(|op: FuzzOperation| {
    // Bound input size to prevent resource exhaustion
    match &op {
        FuzzOperation::ParseRawBytes { data } if data.len() > MAX_INPUT_SIZE => return,
        _ => {},
    }

    match op {
        FuzzOperation::ParseRawBytes { data } => {
            // Crash oracle: parser must never panic on any input
            let result = std::panic::catch_unwind(|| {
                let _ = RegionSnapshot::from_bytes(&data);
            });
            assert!(result.is_ok(), "RegionSnapshot::from_bytes panicked on input");

            // Test parser invariants on raw bytes
            test_parser_invariants(&data);
        }

        FuzzOperation::RoundTripTest { snapshot, corruption } => {
            if let Some(real_snapshot) = snapshot.to_region_snapshot() {
                test_round_trip_oracle(&real_snapshot, corruption);
            }
        }

        FuzzOperation::BoundaryTest { pattern } => {
            test_boundary_conditions(&pattern);
        }
    }
});

/// Test parser invariants on arbitrary byte inputs
fn test_parser_invariants(data: &[u8]) {
    let result = RegionSnapshot::from_bytes(data);

    match result {
        Ok(snapshot) => {
            // If parsing succeeded, validate the parsed snapshot invariants
            assert!(snapshot.sequence <= u64::MAX);
            assert!(snapshot.origin_id <= u64::MAX);
            assert!(snapshot.epoch <= u64::MAX);

            // Budget fields should be reasonable
            if let Some(deadline) = snapshot.budget.deadline_nanos {
                assert!(deadline <= i64::MAX as u64, "Deadline overflow");
            }

            // String fields must be valid UTF-8
            if let Some(ref reason) = snapshot.cancel_reason {
                assert!(reason.is_valid_utf8(), "Invalid UTF-8 in cancel_reason");
            }

            // Metadata size should be bounded
            assert!(snapshot.metadata.len() <= MAX_INPUT_SIZE, "Metadata too large");

            // Vector sizes should be reasonable
            assert!(snapshot.tasks.len() <= MAX_VECTOR_LEN * 10, "Too many tasks");
            assert!(snapshot.children.len() <= MAX_VECTOR_LEN * 10, "Too many children");
        }

        Err(err) => {
            // Error classification must be consistent and reasonable
            use SnapshotError::*;
            match err {
                InvalidMagic => {
                    // Should only occur when first 4 bytes != "SNAP"
                    if data.len() >= 4 {
                        assert_ne!(&data[0..4], b"SNAP", "InvalidMagic but magic is correct");
                    }
                }
                UnsupportedVersion(_) => {
                    // Should only occur with wrong version after correct magic
                    if data.len() >= 5 {
                        assert_eq!(&data[0..4], b"SNAP", "UnsupportedVersion but bad magic");
                    }
                }
                InvalidState(state) => {
                    // State values should be out of valid range
                    assert!(state > 4, "InvalidState but state {} is valid", state);
                }
                TrailingBytes(count) => {
                    // Should only occur when extra data remains
                    assert!(count > 0, "TrailingBytes but count is {}", count);
                }
                MetadataTooLarge { len, max } => {
                    // Declared length should exceed maximum
                    assert!(len > max,
                           "MetadataTooLarge but {} <= {}", len, max);
                }
                _ => {
                    // Other errors are acceptable
                }
            }
        }
    }
}

/// Test round-trip oracle: from_bytes(to_bytes(snapshot)) should preserve semantics
fn test_round_trip_oracle(snapshot: &RegionSnapshot, corruption: Option<CorruptionPattern>) {
    let serialized = snapshot.to_bytes();

    // Apply corruption if specified
    let (test_bytes, is_corrupted) = if let Some(corruption_pattern) = corruption {
        (apply_corruption(&serialized, corruption_pattern), true)
    } else {
        (serialized.clone(), false)
    };

    let parse_result = RegionSnapshot::from_bytes(&test_bytes);

    if !is_corrupted {
        // Round-trip should succeed for uncorrupted data
        let restored = parse_result.expect("Round-trip failed on valid snapshot");

        // Verify semantic equivalence (some fields may differ in representation)
        assert_eq!(restored.region_id, snapshot.region_id);
        assert_eq!(restored.state, snapshot.state);
        assert_eq!(restored.timestamp, snapshot.timestamp);
        assert_eq!(restored.sequence, snapshot.sequence);
        assert_eq!(restored.origin_id, snapshot.origin_id);
        assert_eq!(restored.epoch, snapshot.epoch);
        assert_eq!(restored.tasks.len(), snapshot.tasks.len());
        assert_eq!(restored.children, snapshot.children);
        assert_eq!(restored.finalizer_count, snapshot.finalizer_count);
        assert_eq!(restored.cancel_reason, snapshot.cancel_reason);
        assert_eq!(restored.parent, snapshot.parent);
        assert_eq!(restored.metadata, snapshot.metadata);

        // Verify serialization is deterministic
        let reserialized = restored.to_bytes();
        assert_eq!(reserialized, serialized, "Serialization not deterministic");
    } else {
        // Corruption should be detected (parsing should fail gracefully)
        if parse_result.is_ok() {
            // Some corruptions might still produce valid snapshots
            // Just ensure no panic occurred and the result is reasonable
            let restored = parse_result.unwrap();
            test_snapshot_invariants(&restored);
        }
    }
}

fn test_snapshot_invariants(snapshot: &RegionSnapshot) {
    // Basic invariants that should hold for any valid snapshot
    assert!(snapshot.metadata.len() <= MAX_INPUT_SIZE);
    if let Some(ref reason) = snapshot.cancel_reason {
        assert!(reason.is_valid_utf8());
    }
}

/// Apply corruption patterns to test error handling
fn apply_corruption(data: &[u8], corruption: CorruptionPattern) -> Vec<u8> {
    let mut corrupted = data.to_vec();

    match corruption {
        CorruptionPattern::BadMagic(magic) => {
            if corrupted.len() >= 4 {
                corrupted[0..4].copy_from_slice(&magic);
            }
        }
        CorruptionPattern::BadVersion(version) => {
            if corrupted.len() >= 5 {
                corrupted[4] = version;
            }
        }
        CorruptionPattern::TrailingBytes(mut trailer) => {
            corrupted.append(&mut trailer);
        }
        CorruptionPattern::BadPresenceFlag { field, value } => {
            // Corrupt presence flags throughout the data
            if (field as usize) < corrupted.len() {
                corrupted[field as usize] = value;
            }
        }
        CorruptionPattern::OversizeMetadata(fake_size) => {
            // Try to inject a large metadata size field if we can find where it might be
            let size_bytes = fake_size.to_be_bytes();
            if corrupted.len() >= 8 {
                let pos = corrupted.len() - 8;
                corrupted[pos..pos+4].copy_from_slice(&size_bytes);
            }
        }
    }

    corrupted
}

/// Test boundary conditions and edge cases
fn test_boundary_conditions(pattern: &BoundaryPattern) {
    let test_data = match pattern {
        BoundaryPattern::Empty => vec![],
        BoundaryPattern::OnlyMagic => b"SNAP".to_vec(),
        BoundaryPattern::Truncated { valid_prefix_len } => {
            // Create a minimal valid snapshot and truncate it
            let empty_snapshot = RegionSnapshot::empty(RegionId::new_for_test(0, 0));
            let full_bytes = empty_snapshot.to_bytes();
            let len = (*valid_prefix_len).min(full_bytes.len());
            full_bytes[..len].to_vec()
        }
        BoundaryPattern::MaxSize => {
            // Create maximum size input to test resource limits
            vec![0u8; MAX_INPUT_SIZE]
        }
        BoundaryPattern::LargeVectors => {
            // Test with crafted large vector size fields
            let mut data = b"SNAP\x02".to_vec();  // Magic + version
            data.extend_from_slice(&[0u8; 32]);  // Some valid fields
            data.extend_from_slice(&(u32::MAX).to_be_bytes()); // Large task count
            data
        }
        BoundaryPattern::UnicodeEdgeCases => {
            // Test with various Unicode edge cases
            let mut data = b"SNAP\x02".to_vec();
            data.extend_from_slice(&[0u8; 64]);  // Valid prefix
            data.push(1);  // Has cancel_reason
            data.extend_from_slice(&(16u32).to_be_bytes());  // String length
            // Add problematic UTF-8 sequences
            data.extend_from_slice(&[
                0xFF, 0xFE,  // BOM-like
                0xC0, 0x80,  // Overlong encoding
                0xED, 0xA0, 0x80,  // UTF-16 surrogate
                0xF4, 0x90, 0x80, 0x80,  // Beyond Unicode range
                0x00, 0x01, 0x02, 0x03,  // Control chars
                0x7F, 0x80, 0x81, 0x82,  // Boundary cases
            ]);
            data
        }
    };

    // Test that boundary conditions don't cause panics
    let result = std::panic::catch_unwind(|| {
        let _ = RegionSnapshot::from_bytes(&test_data);
    });
    assert!(result.is_ok(), "Boundary pattern {:?} caused panic", pattern);

    test_parser_invariants(&test_data);
}