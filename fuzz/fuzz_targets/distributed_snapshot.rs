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
const SNAP_MAGIC_LEN: usize = 4;
const SNAP_VERSION_LEN: usize = 1;
const REGION_ID_LEN: usize = 8;
const TASK_ID_LEN: usize = 8;
const REGION_STATE_LEN: usize = 1;
const U32_LEN: usize = 4;
const U64_LEN: usize = 8;
const TASK_ENTRY_LEN: usize = TASK_ID_LEN + 2;
const MAX_STRING_BYTES: usize = 256;

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
    /// Origin authority identifier
    origin_id: u64,
    /// Provenance epoch
    epoch: u64,
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
    OriginId,
    Epoch,
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
    snapshot.origin_id = config.origin_id;
    snapshot.epoch = config.epoch;
    snapshot.finalizer_count = config.finalizer_count;
    snapshot.budget.deadline_nanos = optional_u64_value(&config.budget.deadline);
    snapshot.budget.polls_remaining = optional_u32_value(&config.budget.polls_remaining);
    snapshot.budget.cost_remaining = optional_u64_value(&config.budget.cost_remaining);
    snapshot.cancel_reason = optional_string_value(&config.cancel_reason);
    snapshot.parent = optional_region_id(&config.parent);

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
                StatePosition::RegionState => find_region_state_offset(snapshot_bytes),
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
            if let Some(task_count_offset) = find_task_count_offset(snapshot_bytes)
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
                    if let Some(offset) = find_task_count_offset(snapshot_bytes) {
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
            if let Some(offset) = find_timestamp_offset(snapshot_bytes) {
                inject_boundary_value_at_offset(snapshot_bytes, offset, value);
            }
            if let Some(offset) = find_sequence_offset(snapshot_bytes) {
                inject_boundary_value_at_offset(snapshot_bytes, offset, value);
            }
            if let Some(offset) = find_origin_id_offset(snapshot_bytes) {
                inject_boundary_value_at_offset(snapshot_bytes, offset, value);
            }
            if let Some(offset) = find_epoch_offset(snapshot_bytes) {
                inject_boundary_value_at_offset(snapshot_bytes, offset, value);
            }
        }

        SnapshotOperation::PartialFieldCorruption { field, corruption } => {
            let offset = match field {
                FieldType::RegionId => find_region_id_offset(snapshot_bytes),
                FieldType::TaskId => find_task_id_offset(snapshot_bytes),
                FieldType::Timestamp => find_timestamp_offset(snapshot_bytes),
                FieldType::Sequence => find_sequence_offset(snapshot_bytes),
                FieldType::OriginId => find_origin_id_offset(snapshot_bytes),
                FieldType::Epoch => find_epoch_offset(snapshot_bytes),
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
    observe_snapshot_parse(data, "mutated snapshot");

    // Test with truncated versions of the data
    for len in (0..data.len().min(100)).step_by(3) {
        let truncated = &data[..len];
        observe_snapshot_parse(truncated, "truncated snapshot");
    }

    // Test with trailing garbage
    if data.len() < MAX_INPUT_SIZE / 2 {
        let mut with_trailing = data.to_vec();
        with_trailing.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        observe_snapshot_parse(&with_trailing, "trailing-garbage snapshot");
    }
}

fn observe_snapshot_parse(data: &[u8], context: &str) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        RegionSnapshot::from_bytes(data)
    })) {
        Ok(Ok(snapshot)) => {
            assert!(
                snapshot.metadata.len() <= data.len(),
                "{context} accepted metadata should remain input-bounded"
            );
            assert!(
                snapshot.tasks.len() <= data.len() / TASK_ENTRY_LEN,
                "{context} accepted task count should remain input-bounded"
            );
            assert!(
                snapshot.children.len() <= data.len() / REGION_ID_LEN,
                "{context} accepted child count should remain input-bounded"
            );
        }
        Ok(Err(error)) => assert!(
            !error.to_string().is_empty(),
            "{context} parser errors should remain observable"
        ),
        Err(_) => panic!("RegionSnapshot parser panicked on {context} input"),
    }
}

// Helper functions for finding field offsets in the binary format

#[derive(Debug, Clone, Copy)]
struct SnapshotLayout {
    region_id_offset: usize,
    region_state_offset: usize,
    timestamp_offset: usize,
    sequence_offset: usize,
    origin_id_offset: usize,
    epoch_offset: usize,
    task_count_offset: usize,
    task_count: u32,
    first_task_offset: usize,
    children_count_offset: usize,
    finalizer_count_offset: usize,
    deadline_presence_offset: usize,
    polls_presence_offset: usize,
    cost_presence_offset: usize,
    cancel_reason_presence_offset: usize,
    cancel_reason_length_offset: Option<usize>,
    cancel_reason_data_offset: Option<usize>,
    parent_presence_offset: usize,
    metadata_length_offset: usize,
}

fn optional_u64_value(config: &OptionalU64Config) -> Option<u64> {
    match config {
        OptionalU64Config::None => None,
        OptionalU64Config::Some { value } | OptionalU64Config::Invalid { value, .. } => {
            Some(*value)
        }
    }
}

fn optional_u32_value(config: &OptionalU32Config) -> Option<u32> {
    match config {
        OptionalU32Config::None => None,
        OptionalU32Config::Some { value } | OptionalU32Config::Invalid { value, .. } => {
            Some(*value)
        }
    }
}

fn optional_string_value(config: &OptionalStringConfig) -> Option<String> {
    match config {
        OptionalStringConfig::None => None,
        OptionalStringConfig::Some { content }
        | OptionalStringConfig::InvalidFlag { content, .. } => {
            Some(content.chars().take(MAX_STRING_BYTES).collect())
        }
        OptionalStringConfig::InvalidUtf8 { bytes, .. } => {
            let sanitized: Vec<u8> = bytes.iter().take(MAX_STRING_BYTES).copied().collect();
            Some(String::from_utf8_lossy(&sanitized).into_owned())
        }
    }
}

fn optional_region_id(config: &OptionalIdConfig) -> Option<RegionId> {
    match config {
        OptionalIdConfig::None => None,
        OptionalIdConfig::Some { id } | OptionalIdConfig::Invalid { id, .. } => {
            Some(id.to_region_id())
        }
    }
}

fn read_u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(U32_LEN)?;
    let bytes = data.get(offset..end)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn advance_optional_u64(data: &[u8], flag_offset: usize) -> Option<usize> {
    match *data.get(flag_offset)? {
        0 => flag_offset.checked_add(1),
        1 => flag_offset
            .checked_add(1 + U64_LEN)
            .filter(|end| *end <= data.len()),
        _ => None,
    }
}

fn advance_optional_u32(data: &[u8], flag_offset: usize) -> Option<usize> {
    match *data.get(flag_offset)? {
        0 => flag_offset.checked_add(1),
        1 => flag_offset
            .checked_add(1 + U32_LEN)
            .filter(|end| *end <= data.len()),
        _ => None,
    }
}

fn advance_optional_string(
    data: &[u8],
    flag_offset: usize,
) -> Option<(Option<usize>, Option<usize>, usize)> {
    match *data.get(flag_offset)? {
        0 => Some((None, None, flag_offset.checked_add(1)?)),
        1 => {
            let len_offset = flag_offset.checked_add(1)?;
            let len = usize::try_from(read_u32_at(data, len_offset)?).ok()?;
            let data_offset = len_offset.checked_add(U32_LEN)?;
            let next = data_offset.checked_add(len)?;
            if next > data.len() {
                return None;
            }
            Some((Some(len_offset), Some(data_offset), next))
        }
        _ => None,
    }
}

fn advance_optional_parent(data: &[u8], flag_offset: usize) -> Option<usize> {
    match *data.get(flag_offset)? {
        0 => flag_offset.checked_add(1),
        1 => flag_offset
            .checked_add(1 + REGION_ID_LEN)
            .filter(|end| *end <= data.len()),
        _ => None,
    }
}

fn derive_snapshot_layout(data: &[u8]) -> Option<SnapshotLayout> {
    let region_id_offset = SNAP_MAGIC_LEN.checked_add(SNAP_VERSION_LEN)?;
    let region_state_offset = region_id_offset.checked_add(REGION_ID_LEN)?;
    let timestamp_offset = region_state_offset.checked_add(REGION_STATE_LEN)?;
    let sequence_offset = timestamp_offset.checked_add(U64_LEN)?;
    let origin_id_offset = sequence_offset.checked_add(U64_LEN)?;
    let epoch_offset = origin_id_offset.checked_add(U64_LEN)?;
    let task_count_offset = epoch_offset.checked_add(U64_LEN)?;
    if data.len() < task_count_offset.checked_add(U32_LEN)? {
        return None;
    }

    let task_count = read_u32_at(data, task_count_offset)?;
    let first_task_offset = task_count_offset.checked_add(U32_LEN)?;
    let task_bytes = usize::try_from(task_count)
        .ok()?
        .checked_mul(TASK_ENTRY_LEN)?;
    let children_count_offset = first_task_offset.checked_add(task_bytes)?;
    let children_count = read_u32_at(data, children_count_offset)?;
    let first_child_offset = children_count_offset.checked_add(U32_LEN)?;
    let child_bytes = usize::try_from(children_count)
        .ok()?
        .checked_mul(REGION_ID_LEN)?;
    let finalizer_count_offset = first_child_offset.checked_add(child_bytes)?;
    if data.len() < finalizer_count_offset.checked_add(U32_LEN)? {
        return None;
    }

    let deadline_presence_offset = finalizer_count_offset.checked_add(U32_LEN)?;
    let polls_presence_offset = advance_optional_u64(data, deadline_presence_offset)?;
    let cost_presence_offset = advance_optional_u32(data, polls_presence_offset)?;
    let cancel_reason_presence_offset = advance_optional_u64(data, cost_presence_offset)?;
    let (cancel_reason_length_offset, cancel_reason_data_offset, parent_presence_offset) =
        advance_optional_string(data, cancel_reason_presence_offset)?;
    let metadata_length_offset = advance_optional_parent(data, parent_presence_offset)?;
    if data.len() < metadata_length_offset.checked_add(U32_LEN)? {
        return None;
    }

    Some(SnapshotLayout {
        region_id_offset,
        region_state_offset,
        timestamp_offset,
        sequence_offset,
        origin_id_offset,
        epoch_offset,
        task_count_offset,
        task_count,
        first_task_offset,
        children_count_offset,
        finalizer_count_offset,
        deadline_presence_offset,
        polls_presence_offset,
        cost_presence_offset,
        cancel_reason_presence_offset,
        cancel_reason_length_offset,
        cancel_reason_data_offset,
        parent_presence_offset,
        metadata_length_offset,
    })
}

fn find_region_id_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.region_id_offset)
}

fn find_region_state_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.region_state_offset)
}

fn find_timestamp_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.timestamp_offset)
}

fn find_sequence_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.sequence_offset)
}

fn find_origin_id_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.origin_id_offset)
}

fn find_epoch_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.epoch_offset)
}

fn find_task_state_offset(data: &[u8]) -> Option<usize> {
    let layout = derive_snapshot_layout(data)?;
    if layout.task_count == 0 {
        return None;
    }
    layout.first_task_offset.checked_add(TASK_ID_LEN)
}

fn find_task_count_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.task_count_offset)
}

fn find_children_count_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.children_count_offset)
}

fn find_metadata_length_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.metadata_length_offset)
}

fn find_presence_flag_offset(data: &[u8], flag_index: usize) -> Option<usize> {
    let layout = derive_snapshot_layout(data)?;
    match flag_index {
        0 => Some(layout.deadline_presence_offset),
        1 => Some(layout.polls_presence_offset),
        2 => Some(layout.cost_presence_offset),
        3 => Some(layout.cancel_reason_presence_offset),
        4 => Some(layout.parent_presence_offset),
        _ => None,
    }
}

fn find_string_data_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).and_then(|layout| layout.cancel_reason_data_offset)
}

fn find_string_length_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).and_then(|layout| layout.cancel_reason_length_offset)
}

fn find_task_id_offset(data: &[u8]) -> Option<usize> {
    let layout = derive_snapshot_layout(data)?;
    if layout.task_count == 0 {
        return None;
    }
    Some(layout.first_task_offset)
}

fn find_task_priority_offset(data: &[u8]) -> Option<usize> {
    find_task_id_offset(data).and_then(|task_id_offset| task_id_offset.checked_add(TASK_ID_LEN + 1))
}

fn find_finalizer_count_offset(data: &[u8]) -> Option<usize> {
    derive_snapshot_layout(data).map(|layout| layout.finalizer_count_offset)
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
