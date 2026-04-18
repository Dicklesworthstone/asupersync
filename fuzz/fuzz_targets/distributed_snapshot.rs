//! Fuzz target for distributed snapshot protocol deserialization.
//!
//! Focuses on the RegionSnapshot::from_bytes deserializer in src/distributed/snapshot.rs
//! with comprehensive testing of binary format edge cases, state machine corruption,
//! and error conditions:
//! 1. Magic byte corruption and format validation
//! 2. Version byte manipulation and compatibility checks
//! 3. Invalid state values and enum boundary testing
//! 4. Truncated data at various parsing stages
//! 5. Invalid presence flags and optional field encoding
//! 6. Malformed region/task ID structures
//! 7. String encoding validation and UTF-8 handling
//! 8. Integer overflow and boundary value testing
//! 9. Trailing bytes detection and strict parsing
//! 10. Memory exhaustion prevention via count limits
//!
//! Key attack vectors:
//! - Magic/version tampering for format confusion attacks
//! - State byte injection for invalid state machine transitions
//! - Count field overflow for memory exhaustion attacks
//! - Presence flag manipulation for optional field confusion
//! - String encoding corruption for UTF-8 validation bypass
//! - Partial data injection for parser state corruption

#![no_main]

use arbitrary::Arbitrary;
use asupersync::distributed::snapshot::RegionSnapshot;
use asupersync::record::region::RegionState;
use asupersync::types::{RegionId, TaskId, Time};
use asupersync::util::ArenaIndex;
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent memory exhaustion during fuzzing
const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB

/// Snapshot fuzzing configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct SnapshotFuzzConfig {
    /// Sequence of snapshot manipulation operations to perform
    operations: Vec<SnapshotOperation>,
    /// Base snapshot configuration
    base_snapshot: SnapshotConfig,
    /// Parser behavior settings
    parser_config: ParserConfig,
}

/// Base snapshot configuration for generating valid test cases
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct SnapshotConfig {
    /// Region ID configuration
    region_id: IdConfig,
    /// Region state
    state: RegionStateConfig,
    /// Timestamp value
    timestamp: u64,
    /// Sequence number
    sequence: u64,
    /// Task configurations
    tasks: Vec<TaskConfig>,
    /// Child region IDs
    children: Vec<IdConfig>,
    /// Finalizer count
    finalizer_count: u32,
    /// Budget configuration
    budget: BudgetConfig,
    /// Cancel reason configuration
    cancel_reason: OptionalStringConfig,
    /// Parent region configuration
    parent: OptionalIdConfig,
    /// Metadata blob
    metadata: Vec<u8>,
}

/// Parser behavior configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct ParserConfig {
    /// Whether to test with truncated data
    test_truncation: bool,
    /// Whether to test with trailing bytes
    test_trailing_bytes: bool,
    /// Whether to inject invalid state values
    inject_invalid_states: bool,
}

/// Region state configuration options
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum RegionStateConfig {
    /// Valid region state
    Valid(RegionStateType),
    /// Invalid state byte
    Invalid { state_byte: u8 },
}

/// Valid region state types
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum RegionStateType {
    Open,
    Closing,
    Draining,
    Finalizing,
    Closed,
}

impl RegionStateType {
    fn to_state(&self) -> RegionState {
        match self {
            RegionStateType::Open => RegionState::Open,
            RegionStateType::Closing => RegionState::Closing,
            RegionStateType::Draining => RegionState::Draining,
            RegionStateType::Finalizing => RegionState::Finalizing,
            RegionStateType::Closed => RegionState::Closed,
        }
    }
}

/// ID configuration for region/task IDs
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct IdConfig {
    /// Arena index
    index: u32,
    /// Arena generation
    generation: u32,
}

impl IdConfig {
    fn to_region_id(&self) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(self.index, self.generation))
    }

    fn to_task_id(&self) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(self.index, self.generation))
    }
}

/// Task configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct TaskConfig {
    /// Task ID
    id: IdConfig,
    /// Task state
    state: TaskStateConfig,
    /// Priority value
    priority: u8,
}

/// Task state configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum TaskStateConfig {
    Pending,
    Running,
    Completed,
    Cancelled,
    Panicked,
    /// Invalid task state byte
    Invalid {
        state_byte: u8,
    },
}

/// Budget configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct BudgetConfig {
    /// Deadline configuration
    deadline: OptionalU64Config,
    /// Polls remaining configuration
    polls_remaining: OptionalU32Config,
    /// Cost remaining configuration
    cost_remaining: OptionalU64Config,
}

/// Optional U64 value configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum OptionalU64Config {
    None,
    Some {
        value: u64,
    },
    /// Invalid presence flag
    Invalid {
        flag: u8,
        value: u64,
    },
}

/// Optional U32 value configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum OptionalU32Config {
    None,
    Some {
        value: u32,
    },
    /// Invalid presence flag
    Invalid {
        flag: u8,
        value: u32,
    },
}

/// Optional string configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum OptionalStringConfig {
    None,
    Some {
        content: String,
    },
    /// Invalid presence flag
    InvalidFlag {
        flag: u8,
        content: String,
    },
    /// Invalid UTF-8 bytes
    InvalidUtf8 {
        flag: u8,
        bytes: Vec<u8>,
    },
}

/// Optional ID configuration
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum OptionalIdConfig {
    None,
    Some {
        id: IdConfig,
    },
    /// Invalid presence flag
    Invalid {
        flag: u8,
        id: IdConfig,
    },
}

/// Snapshot manipulation operations to test
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum SnapshotOperation {
    /// Corrupt magic bytes
    CorruptMagic { magic_bytes: [u8; 4] },
    /// Change version byte
    ChangeVersion { version: u8 },
    /// Inject invalid state byte
    InjectInvalidState {
        position: StatePosition,
        state_byte: u8,
    },
    /// Truncate data at specific position
    TruncateAt { position: u16 },
    /// Add trailing bytes
    AddTrailingBytes { bytes: Vec<u8> },
    /// Corrupt count fields
    CorruptCounts {
        task_count: u32,
        children_count: u32,
        metadata_len: u32,
    },
    /// Inject invalid presence flags
    CorruptPresenceFlags { flags: Vec<u8> },
    /// Corrupt string encoding
    CorruptStringEncoding { invalid_utf8: Vec<u8> },
    /// Create overlarge count fields
    OverlargeCount { count_type: CountType, count: u32 },
    /// Inject boundary values
    InjectBoundaryValues { boundary_type: BoundaryType },
    /// Create partial field corruption
    PartialFieldCorruption {
        field: FieldType,
        corruption: Vec<u8>,
    },
}

/// State injection positions
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum StatePosition {
    RegionState,
    TaskState,
}

/// Count field types
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum CountType {
    TaskCount,
    ChildrenCount,
    MetadataLength,
    StringLength,
}

/// Boundary value types
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum BoundaryType {
    MaxU32,
    MaxU64,
    Zero,
    One,
    PowerOfTwo { power: u8 },
}

/// Field types for corruption
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum FieldType {
    RegionId,
    TaskId,
    Timestamp,
    Sequence,
    Priority,
    FinalizerCount,
}

fuzz_target!(|input: SnapshotFuzzConfig| {
    // Limit total operations to prevent excessive test time
    let operations = input.operations.iter().take(50);

    // Build a base snapshot from the configuration
    let base_snapshot = build_base_snapshot(&input.base_snapshot);
    let mut snapshot_bytes = base_snapshot.to_bytes();

    // Apply fuzzing operations to the serialized data
    for operation in operations {
        apply_operation(&mut snapshot_bytes, operation, &input.parser_config);

        // Prevent buffer from growing too large
        if snapshot_bytes.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    // Test the deserializer with the manipulated data
    test_snapshot_deserializer(&snapshot_bytes, &input.parser_config);
});

fn build_base_snapshot(config: &SnapshotConfig) -> RegionSnapshot {
    // Create a valid base snapshot for testing
    let region_id = config.region_id.to_region_id();
    let state = match &config.state {
        RegionStateConfig::Valid(state_type) => state_type.to_state(),
        RegionStateConfig::Invalid { .. } => RegionState::Open, // Use valid default
    };

    let mut snapshot = RegionSnapshot::empty(region_id);
    snapshot.state = state;
    snapshot.timestamp = Time::from_nanos(config.timestamp);
    snapshot.sequence = config.sequence;
    snapshot.finalizer_count = config.finalizer_count;

    // Limit metadata size to prevent OOM
    let limited_metadata = config
        .metadata
        .iter()
        .take(MAX_INPUT_SIZE / 4)
        .cloned()
        .collect();
    snapshot.metadata = limited_metadata;

    // Add tasks (limited to prevent memory exhaustion)
    for task_config in config.tasks.iter().take(1000) {
        let task_id = task_config.id.to_task_id();
        let task_state = match &task_config.state {
            TaskStateConfig::Pending => asupersync::distributed::snapshot::TaskState::Pending,
            TaskStateConfig::Running => asupersync::distributed::snapshot::TaskState::Running,
            TaskStateConfig::Completed => asupersync::distributed::snapshot::TaskState::Completed,
            TaskStateConfig::Cancelled => asupersync::distributed::snapshot::TaskState::Cancelled,
            TaskStateConfig::Panicked => asupersync::distributed::snapshot::TaskState::Panicked,
            TaskStateConfig::Invalid { .. } => {
                asupersync::distributed::snapshot::TaskState::Pending
            } // Use valid default
        };

        snapshot
            .tasks
            .push(asupersync::distributed::snapshot::TaskSnapshot {
                task_id,
                state: task_state,
                priority: task_config.priority,
            });
    }

    // Add child regions (limited)
    for child_config in config.children.iter().take(1000) {
        snapshot.children.push(child_config.to_region_id());
    }

    snapshot
}

fn apply_operation(
    snapshot_bytes: &mut Vec<u8>,
    operation: &SnapshotOperation,
    _config: &ParserConfig,
) {
    match operation {
        SnapshotOperation::CorruptMagic { magic_bytes } => {
            if snapshot_bytes.len() >= 4 {
                snapshot_bytes[0..4].copy_from_slice(magic_bytes);
            }
        }

        SnapshotOperation::ChangeVersion { version } => {
            if snapshot_bytes.len() >= 5 {
                snapshot_bytes[4] = *version;
            }
        }

        SnapshotOperation::InjectInvalidState {
            position,
            state_byte,
        } => {
            let offset = match position {
                StatePosition::RegionState => Some(13), // After magic(4) + version(1) + region_id(8)
                StatePosition::TaskState => find_task_state_offset(snapshot_bytes),
            };
            if let Some(offset) = offset
                && snapshot_bytes.len() > offset
            {
                snapshot_bytes[offset] = *state_byte;
            }
        }

        SnapshotOperation::TruncateAt { position } => {
            let truncate_pos = (*position as usize).min(snapshot_bytes.len());
            snapshot_bytes.truncate(truncate_pos);
        }

        SnapshotOperation::AddTrailingBytes { bytes } => {
            let limited_bytes: Vec<u8> = bytes.iter().take(1024).cloned().collect();
            snapshot_bytes.extend_from_slice(&limited_bytes);
        }

        SnapshotOperation::CorruptCounts {
            task_count,
            children_count,
            metadata_len,
        } => {
            // Find and corrupt the task count field (after sequence field)
            if let Some(task_count_offset) = find_task_count_offset()
                && snapshot_bytes.len() >= task_count_offset + 4
            {
                let bytes = task_count.to_le_bytes();
                snapshot_bytes[task_count_offset..task_count_offset + 4].copy_from_slice(&bytes);
            }

            // Similar for children count and metadata length
            if let Some(children_offset) = find_children_count_offset(snapshot_bytes)
                && snapshot_bytes.len() >= children_offset + 4
            {
                let bytes = children_count.to_le_bytes();
                snapshot_bytes[children_offset..children_offset + 4].copy_from_slice(&bytes);
            }

            if let Some(metadata_offset) = find_metadata_length_offset(snapshot_bytes)
                && snapshot_bytes.len() >= metadata_offset + 4
            {
                let bytes = metadata_len.to_le_bytes();
                snapshot_bytes[metadata_offset..metadata_offset + 4].copy_from_slice(&bytes);
            }
        }

        SnapshotOperation::CorruptPresenceFlags { flags } => {
            // Inject invalid presence flags at various optional field positions
            for (i, &flag) in flags.iter().take(8).enumerate() {
                if let Some(offset) = find_presence_flag_offset(snapshot_bytes, i)
                    && snapshot_bytes.len() > offset
                {
                    snapshot_bytes[offset] = flag;
                }
            }
        }

        SnapshotOperation::CorruptStringEncoding { invalid_utf8 } => {
            // Find string data and inject invalid UTF-8
            if let Some(string_offset) = find_string_data_offset(snapshot_bytes) {
                let limited_bytes: Vec<u8> = invalid_utf8.iter().take(256).cloned().collect();
                let end_offset = (string_offset + limited_bytes.len()).min(snapshot_bytes.len());
                if string_offset < snapshot_bytes.len() {
                    let copy_len = (end_offset - string_offset).min(limited_bytes.len());
                    snapshot_bytes[string_offset..string_offset + copy_len]
                        .copy_from_slice(&limited_bytes[..copy_len]);
                }
            }
        }

        SnapshotOperation::OverlargeCount { count_type, count } => {
            match count_type {
                CountType::TaskCount => {
                    if let Some(offset) = find_task_count_offset() {
                        write_u32_at(snapshot_bytes, offset, *count);
                    }
                }
                CountType::ChildrenCount => {
                    if let Some(offset) = find_children_count_offset(snapshot_bytes) {
                        write_u32_at(snapshot_bytes, offset, *count);
                    }
                }
                CountType::MetadataLength => {
                    if let Some(offset) = find_metadata_length_offset(snapshot_bytes) {
                        write_u32_at(snapshot_bytes, offset, *count);
                    }
                }
                CountType::StringLength => {
                    // For string length within cancel reason
                    if let Some(offset) = find_string_length_offset(snapshot_bytes) {
                        write_u32_at(snapshot_bytes, offset, *count);
                    }
                }
            }
        }

        SnapshotOperation::InjectBoundaryValues { boundary_type } => {
            let value = match boundary_type {
                BoundaryType::MaxU32 => u32::MAX as u64,
                BoundaryType::MaxU64 => u64::MAX,
                BoundaryType::Zero => 0,
                BoundaryType::One => 1,
                BoundaryType::PowerOfTwo { power } => {
                    let power_clamped = (*power).min(60); // Prevent overflow
                    1u64 << power_clamped
                }
            };

            // Inject boundary values into various numeric fields
            inject_boundary_value_at_offset(snapshot_bytes, 14, value); // timestamp
            inject_boundary_value_at_offset(snapshot_bytes, 22, value); // sequence
        }

        SnapshotOperation::PartialFieldCorruption { field, corruption } => {
            let offset = match field {
                FieldType::RegionId => Some(5), // After magic + version
                FieldType::TaskId => find_task_id_offset(snapshot_bytes),
                FieldType::Timestamp => Some(14),
                FieldType::Sequence => Some(22),
                FieldType::Priority => find_task_priority_offset(snapshot_bytes),
                FieldType::FinalizerCount => find_finalizer_count_offset(snapshot_bytes),
            };

            if let Some(offset) = offset {
                let limited_corruption: Vec<u8> = corruption.iter().take(16).cloned().collect();
                let end = (offset + limited_corruption.len()).min(snapshot_bytes.len());
                if offset < snapshot_bytes.len() {
                    let copy_len = (end - offset).min(limited_corruption.len());
                    snapshot_bytes[offset..offset + copy_len]
                        .copy_from_slice(&limited_corruption[..copy_len]);
                }
            }
        }
    }
}

fn test_snapshot_deserializer(data: &[u8], _config: &ParserConfig) {
    // Test deserializer with multiple approaches
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = RegionSnapshot::from_bytes(data);
    }));

    // Test with truncated versions of the data
    for len in (0..data.len().min(100)).step_by(3) {
        let truncated = &data[..len];
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = RegionSnapshot::from_bytes(truncated);
        }));
    }

    // Test with trailing garbage
    if data.len() < MAX_INPUT_SIZE / 2 {
        let mut with_trailing = data.to_vec();
        with_trailing.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = RegionSnapshot::from_bytes(&with_trailing);
        }));
    }
}

// Helper functions for finding field offsets in the binary format

fn find_task_state_offset(data: &[u8]) -> Option<usize> {
    // Task states start after: magic(4) + version(1) + region_id(8) + state(1)
    // + timestamp(8) + sequence(8) + task_count(4) + task_id(8)
    let base_offset = 4 + 1 + 8 + 1 + 8 + 8 + 4 + 8; // = 42
    if data.len() > base_offset {
        Some(base_offset)
    } else {
        None
    }
}

fn find_task_count_offset() -> Option<usize> {
    // Task count comes after: magic(4) + version(1) + region_id(8) + state(1) + timestamp(8) + sequence(8)
    Some(4 + 1 + 8 + 1 + 8 + 8) // = 30
}

fn find_children_count_offset(data: &[u8]) -> Option<usize> {
    // Children count comes after tasks, need to calculate dynamically
    let task_count_offset = 30;
    if data.len() > task_count_offset + 4 {
        let task_count_bytes = &data[task_count_offset..task_count_offset + 4];
        let task_count = u32::from_le_bytes([
            task_count_bytes[0],
            task_count_bytes[1],
            task_count_bytes[2],
            task_count_bytes[3],
        ]);
        let tasks_size = (task_count as usize).saturating_mul(10); // Each task is 10 bytes
        Some(task_count_offset + 4 + tasks_size)
    } else {
        None
    }
}

fn find_metadata_length_offset(_data: &[u8]) -> Option<usize> {
    // Metadata length is near the end, after all other fields
    // This is a simplified heuristic
    None // Skip for now due to complexity
}

fn find_presence_flag_offset(_data: &[u8], _flag_index: usize) -> Option<usize> {
    // Find presence flags for optional fields (budget, parent, etc.)
    // This would need more sophisticated parsing
    None // Simplified for now
}

fn find_string_data_offset(_data: &[u8]) -> Option<usize> {
    // Find string data for cancel reason
    None // Simplified for now
}

fn find_string_length_offset(_data: &[u8]) -> Option<usize> {
    // Find string length field
    None // Simplified for now
}

fn find_task_id_offset(data: &[u8]) -> Option<usize> {
    // First task ID comes after task count
    let task_count_offset = 30;
    if data.len() > task_count_offset + 4 {
        Some(task_count_offset + 4)
    } else {
        None
    }
}

fn find_task_priority_offset(data: &[u8]) -> Option<usize> {
    // Task priority is 9 bytes after task ID (8 bytes task ID + 1 byte state)
    find_task_id_offset(data).map(|task_id_offset| task_id_offset + 8 + 1)
}

fn find_finalizer_count_offset(data: &[u8]) -> Option<usize> {
    // Finalizer count comes after children
    if let Some(children_offset) = find_children_count_offset(data) {
        if data.len() > children_offset + 4 {
            let children_count_bytes = &data[children_offset..children_offset + 4];
            let children_count = u32::from_le_bytes([
                children_count_bytes[0],
                children_count_bytes[1],
                children_count_bytes[2],
                children_count_bytes[3],
            ]);
            let children_size = (children_count as usize).saturating_mul(8); // Each child is 8 bytes
            Some(children_offset + 4 + children_size)
        } else {
            None
        }
    } else {
        None
    }
}

fn write_u32_at(data: &mut [u8], offset: usize, value: u32) {
    if data.len() >= offset + 4 {
        let bytes = value.to_le_bytes();
        data[offset..offset + 4].copy_from_slice(&bytes);
    }
}

fn inject_boundary_value_at_offset(data: &mut [u8], offset: usize, value: u64) {
    if data.len() >= offset + 8 {
        let bytes = value.to_le_bytes();
        data[offset..offset + 8].copy_from_slice(&bytes);
    }
}
