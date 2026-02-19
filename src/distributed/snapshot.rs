//! Snapshot of region state for encoding.
//!
//! Captures all information needed to reconstruct a region's state on a
//! remote replica. Supports deterministic binary serialization.

use crate::record::region::RegionState;
use crate::types::{RegionId, TaskId, Time};
use crate::util::ArenaIndex;

/// Magic bytes for snapshot binary format.
const SNAP_MAGIC: &[u8; 4] = b"SNAP";

/// Current binary format version.
const SNAP_VERSION: u8 = 1;

/// FNV-1a offset basis (64-bit).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime (64-bit).
const FNV_PRIME: u64 = 0x0100_0000_01b3;

// ---------------------------------------------------------------------------
// TaskState (simplified for snapshots)
// ---------------------------------------------------------------------------

/// Simplified task state for snapshot serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is pending execution.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task panicked.
    Panicked,
}

impl TaskState {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Running => 1,
            Self::Completed => 2,
            Self::Cancelled => 3,
            Self::Panicked => 4,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pending),
            1 => Some(Self::Running),
            2 => Some(Self::Completed),
            3 => Some(Self::Cancelled),
            4 => Some(Self::Panicked),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TaskSnapshot
// ---------------------------------------------------------------------------

/// Summary of task state within a region snapshot.
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    /// The task identifier.
    pub task_id: TaskId,
    /// Simplified state.
    pub state: TaskState,
    /// Task priority.
    pub priority: u8,
}

// ---------------------------------------------------------------------------
// BudgetSnapshot
// ---------------------------------------------------------------------------

/// Budget state captured at snapshot time.
#[derive(Debug, Clone)]
pub struct BudgetSnapshot {
    /// Optional deadline in nanoseconds.
    pub deadline_nanos: Option<u64>,
    /// Optional remaining poll count.
    pub polls_remaining: Option<u32>,
    /// Optional remaining cost budget.
    pub cost_remaining: Option<u64>,
}

// ---------------------------------------------------------------------------
// RegionSnapshot
// ---------------------------------------------------------------------------

/// A serializable snapshot of region state.
///
/// This captures all information needed to reconstruct a region's
/// state on a remote replica. Supports deterministic binary serialization
/// via [`to_bytes`](Self::to_bytes) and [`from_bytes`](Self::from_bytes).
#[derive(Debug, Clone)]
pub struct RegionSnapshot {
    /// Region identifier.
    pub region_id: RegionId,
    /// Current local state.
    pub state: RegionState,
    /// Snapshot timestamp.
    pub timestamp: Time,
    /// Snapshot sequence number (monotonic within region).
    pub sequence: u64,
    /// Task state summaries.
    pub tasks: Vec<TaskSnapshot>,
    /// Child region references.
    pub children: Vec<RegionId>,
    /// Finalizer count (count only, not serialized fully).
    pub finalizer_count: u32,
    /// Budget state.
    pub budget: BudgetSnapshot,
    /// Cancellation reason if any.
    pub cancel_reason: Option<String>,
    /// Parent region if nested.
    pub parent: Option<RegionId>,
    /// Custom metadata for application state.
    pub metadata: Vec<u8>,
}

impl RegionSnapshot {
    /// Creates an empty snapshot for testing and edge-case handling.
    #[must_use]
    pub fn empty(region_id: RegionId) -> Self {
        Self {
            region_id,
            state: RegionState::Open,
            timestamp: Time::ZERO,
            sequence: 0,
            tasks: Vec::new(),
            children: Vec::new(),
            finalizer_count: 0,
            budget: BudgetSnapshot {
                deadline_nanos: None,
                polls_remaining: None,
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: Vec::new(),
        }
    }

    /// Serializes the snapshot to a deterministic binary format.
    ///
    /// Format:
    /// - 4 bytes magic (`SNAP`)
    /// - 1 byte version
    /// - 8 bytes region_id (index u32 + generation u32)
    /// - 1 byte state
    /// - 8 bytes timestamp (nanos u64)
    /// - 8 bytes sequence (u64)
    /// - 4 bytes task count, then per task: 8+1+1 bytes
    /// - 4 bytes children count, then per child: 8 bytes
    /// - 4 bytes finalizer_count
    /// - budget: 3 optional fields
    /// - optional cancel_reason string
    /// - optional parent region_id
    /// - metadata blob
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size_estimate());

        // Header
        buf.extend_from_slice(SNAP_MAGIC);
        buf.push(SNAP_VERSION);

        // Region ID
        write_region_id(&mut buf, self.region_id);

        // State
        buf.push(self.state.as_u8());

        // Timestamp (nanos)
        buf.extend_from_slice(&self.timestamp.as_nanos().to_le_bytes());

        // Sequence
        buf.extend_from_slice(&self.sequence.to_le_bytes());

        // Tasks
        write_u32(&mut buf, self.tasks.len() as u32);
        for task in &self.tasks {
            write_task_id(&mut buf, task.task_id);
            buf.push(task.state.as_u8());
            buf.push(task.priority);
        }

        // Children
        write_u32(&mut buf, self.children.len() as u32);
        for child in &self.children {
            write_region_id(&mut buf, *child);
        }

        // Finalizer count
        write_u32(&mut buf, self.finalizer_count);

        // Budget
        write_optional_u64(&mut buf, self.budget.deadline_nanos);
        write_optional_u32(&mut buf, self.budget.polls_remaining);
        write_optional_u64(&mut buf, self.budget.cost_remaining);

        // Cancel reason
        write_optional_string(&mut buf, self.cancel_reason.as_deref());

        // Parent
        if let Some(parent) = self.parent {
            buf.push(1);
            write_region_id(&mut buf, parent);
        } else {
            buf.push(0);
        }

        // Metadata
        write_u32(&mut buf, self.metadata.len() as u32);
        buf.extend_from_slice(&self.metadata);

        buf
    }

    /// Deserializes a snapshot from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is malformed or the version is unsupported.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SnapshotError> {
        let mut cursor = Cursor::new(data);

        // Magic
        let magic = cursor.read_exact(4)?;
        if magic != SNAP_MAGIC {
            return Err(SnapshotError::InvalidMagic);
        }

        // Version
        let version = cursor.read_u8()?;
        if version != SNAP_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }

        // Region ID
        let region_id = cursor.read_region_id()?;

        // State
        let state_byte = cursor.read_u8()?;
        let state =
            RegionState::from_u8(state_byte).ok_or(SnapshotError::InvalidState(state_byte))?;

        // Timestamp
        let timestamp_nanos = cursor.read_u64()?;
        let timestamp = Time::from_nanos(timestamp_nanos);

        // Sequence
        let sequence = cursor.read_u64()?;

        // Tasks
        let task_count = cursor.read_u32()?;
        let mut tasks = Vec::with_capacity(task_count as usize);
        for _ in 0..task_count {
            let task_id = cursor.read_task_id()?;
            let task_state_byte = cursor.read_u8()?;
            let task_state = TaskState::from_u8(task_state_byte)
                .ok_or(SnapshotError::InvalidState(task_state_byte))?;
            let priority = cursor.read_u8()?;
            tasks.push(TaskSnapshot {
                task_id,
                state: task_state,
                priority,
            });
        }

        // Children
        let children_count = cursor.read_u32()?;
        let mut children = Vec::with_capacity(children_count as usize);
        for _ in 0..children_count {
            children.push(cursor.read_region_id()?);
        }

        // Finalizer count
        let finalizer_count = cursor.read_u32()?;

        // Budget
        let deadline_nanos = cursor.read_optional_u64()?;
        let polls_remaining = cursor.read_optional_u32()?;
        let cost_remaining = cursor.read_optional_u64()?;

        // Cancel reason
        let cancel_reason = cursor.read_optional_string()?;

        // Parent
        let has_parent = cursor.read_u8()?;
        let parent = if has_parent == 1 {
            Some(cursor.read_region_id()?)
        } else {
            None
        };

        // Metadata
        let metadata_len = cursor.read_u32()?;
        let metadata = cursor.read_exact(metadata_len as usize)?.to_vec();

        Ok(Self {
            region_id,
            state,
            timestamp,
            sequence,
            tasks,
            children,
            finalizer_count,
            budget: BudgetSnapshot {
                deadline_nanos,
                polls_remaining,
                cost_remaining,
            },
            cancel_reason,
            parent,
            metadata,
        })
    }

    /// Returns an estimated serialized size.
    #[must_use]
    pub fn size_estimate(&self) -> usize {
        let header = 5; // magic + version
        let region_id = 8;
        let state = 1;
        let timestamp = 8;
        let sequence = 8;
        let tasks = 4 + self.tasks.len() * 10; // count + per-task (8+1+1)
        let children = 4 + self.children.len() * 8;
        let finalizer = 4;
        let budget = 3 + 8 + 4 + 8; // worst case all present
        let cancel = 5 + self.cancel_reason.as_ref().map_or(0, String::len);
        let parent = 9; // worst case
        let metadata = 4 + self.metadata.len();

        header
            + region_id
            + state
            + timestamp
            + sequence
            + tasks
            + children
            + finalizer
            + budget
            + cancel
            + parent
            + metadata
    }

    /// Computes a deterministic hash for deduplication.
    ///
    /// Uses FNV-1a on the serialized bytes.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        let bytes = self.to_bytes();
        fnv1a_64(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error during snapshot deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Invalid magic bytes.
    InvalidMagic,
    /// Unsupported format version.
    UnsupportedVersion(u8),
    /// Invalid state value.
    InvalidState(u8),
    /// Unexpected end of data.
    UnexpectedEof,
    /// Invalid UTF-8 string.
    InvalidString,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid snapshot magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::InvalidState(s) => write!(f, "invalid state byte: {s}"),
            Self::UnexpectedEof => write!(f, "unexpected end of snapshot data"),
            Self::InvalidString => write!(f, "invalid UTF-8 in snapshot"),
        }
    }
}

impl std::error::Error for SnapshotError {}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_region_id(buf: &mut Vec<u8>, id: RegionId) {
    let ai = id.0;
    buf.extend_from_slice(&ai.index().to_le_bytes());
    buf.extend_from_slice(&ai.generation().to_le_bytes());
}

fn write_task_id(buf: &mut Vec<u8>, id: TaskId) {
    let ai = id.0;
    buf.extend_from_slice(&ai.index().to_le_bytes());
    buf.extend_from_slice(&ai.generation().to_le_bytes());
}

fn write_optional_u64(buf: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }
}

fn write_optional_u32(buf: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }
}

fn write_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(s) => {
            buf.push(1);
            let bytes = s.as_bytes();
            write_u32(buf, bytes.len() as u32);
            buf.extend_from_slice(bytes);
        }
        None => buf.push(0),
    }
}

/// FNV-1a 64-bit hash.
fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Deserialization cursor
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        if self.pos + n > self.data.len() {
            return Err(SnapshotError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, SnapshotError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u32(&mut self) -> Result<u32, SnapshotError> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, SnapshotError> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_region_id(&mut self) -> Result<RegionId, SnapshotError> {
        let index = self.read_u32()?;
        let generation = self.read_u32()?;
        Ok(RegionId::from_arena(ArenaIndex::new(index, generation)))
    }

    fn read_task_id(&mut self) -> Result<TaskId, SnapshotError> {
        let index = self.read_u32()?;
        let generation = self.read_u32()?;
        Ok(TaskId::from_arena(ArenaIndex::new(index, generation)))
    }

    fn read_optional_u64(&mut self) -> Result<Option<u64>, SnapshotError> {
        if self.read_u8()? == 1 {
            Ok(Some(self.read_u64()?))
        } else {
            Ok(None)
        }
    }

    fn read_optional_u32(&mut self) -> Result<Option<u32>, SnapshotError> {
        if self.read_u8()? == 1 {
            Ok(Some(self.read_u32()?))
        } else {
            Ok(None)
        }
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, SnapshotError> {
        if self.read_u8()? == 1 {
            let len = self.read_u32()? as usize;
            let bytes = self.read_exact(len)?;
            let s = std::str::from_utf8(bytes).map_err(|_| SnapshotError::InvalidString)?;
            Ok(Some(s.to_string()))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_snapshot() -> RegionSnapshot {
        RegionSnapshot {
            region_id: RegionId::new_for_test(1, 0),
            state: RegionState::Open,
            timestamp: Time::from_secs(100),
            sequence: 1,
            tasks: vec![TaskSnapshot {
                task_id: TaskId::new_for_test(1, 0),
                state: TaskState::Running,
                priority: 5,
            }],
            children: vec![],
            finalizer_count: 2,
            budget: BudgetSnapshot {
                deadline_nanos: Some(1_000_000_000),
                polls_remaining: Some(100),
                cost_remaining: None,
            },
            cancel_reason: None,
            parent: None,
            metadata: vec![],
        }
    }

    #[test]
    fn snapshot_roundtrip() {
        let snapshot = create_test_snapshot();
        let bytes = snapshot.to_bytes();
        let restored = RegionSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(snapshot.region_id, restored.region_id);
        assert_eq!(snapshot.state, restored.state);
        assert_eq!(snapshot.timestamp, restored.timestamp);
        assert_eq!(snapshot.sequence, restored.sequence);
        assert_eq!(snapshot.tasks.len(), restored.tasks.len());
        assert_eq!(snapshot.tasks[0].state, restored.tasks[0].state);
        assert_eq!(snapshot.tasks[0].priority, restored.tasks[0].priority);
        assert_eq!(snapshot.children.len(), restored.children.len());
        assert_eq!(snapshot.finalizer_count, restored.finalizer_count);
        assert_eq!(
            snapshot.budget.deadline_nanos,
            restored.budget.deadline_nanos
        );
        assert_eq!(
            snapshot.budget.polls_remaining,
            restored.budget.polls_remaining
        );
        assert_eq!(
            snapshot.budget.cost_remaining,
            restored.budget.cost_remaining
        );
        assert_eq!(snapshot.cancel_reason, restored.cancel_reason);
        assert_eq!(snapshot.parent, restored.parent);
        assert_eq!(snapshot.metadata, restored.metadata);
    }

    #[test]
    fn snapshot_deterministic_serialization() {
        let snapshot = create_test_snapshot();

        let bytes1 = snapshot.to_bytes();
        let bytes2 = snapshot.to_bytes();

        assert_eq!(bytes1, bytes2, "serialization must be deterministic");
    }

    #[test]
    fn snapshot_content_hash_stable() {
        let snapshot = create_test_snapshot();

        let hash1 = snapshot.content_hash();
        let hash2 = snapshot.content_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn snapshot_size_estimate_accurate() {
        let snapshot = create_test_snapshot();
        let actual_size = snapshot.to_bytes().len();
        let estimated = snapshot.size_estimate();

        // Estimate should be within 50% of actual (generous since optional
        // fields make exact estimation hard).
        assert!(
            estimated >= actual_size * 5 / 10,
            "estimate {estimated} too low vs actual {actual_size}"
        );
        assert!(
            estimated <= actual_size * 20 / 10,
            "estimate {estimated} too high vs actual {actual_size}"
        );
    }

    #[test]
    fn snapshot_empty_roundtrip() {
        let snapshot = RegionSnapshot::empty(RegionId::new_for_test(1, 0));
        let bytes = snapshot.to_bytes();
        let restored = RegionSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(snapshot.region_id, restored.region_id);
        assert_eq!(snapshot.sequence, restored.sequence);
        assert_eq!(restored.tasks.len(), 0);
        assert_eq!(restored.children.len(), 0);
        assert_eq!(restored.metadata.len(), 0);
    }

    #[test]
    fn snapshot_with_all_fields() {
        let snapshot = RegionSnapshot {
            region_id: RegionId::new_for_test(5, 2),
            state: RegionState::Closing,
            timestamp: Time::from_secs(999),
            sequence: 42,
            tasks: vec![
                TaskSnapshot {
                    task_id: TaskId::new_for_test(1, 0),
                    state: TaskState::Running,
                    priority: 5,
                },
                TaskSnapshot {
                    task_id: TaskId::new_for_test(2, 1),
                    state: TaskState::Completed,
                    priority: 3,
                },
            ],
            children: vec![RegionId::new_for_test(10, 0), RegionId::new_for_test(11, 0)],
            finalizer_count: 7,
            budget: BudgetSnapshot {
                deadline_nanos: Some(5_000_000_000),
                polls_remaining: Some(50),
                cost_remaining: Some(1000),
            },
            cancel_reason: Some("timeout".to_string()),
            parent: Some(RegionId::new_for_test(0, 0)),
            metadata: vec![1, 2, 3, 4, 5],
        };

        let bytes = snapshot.to_bytes();
        let restored = RegionSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(snapshot.region_id, restored.region_id);
        assert_eq!(snapshot.state, restored.state);
        assert_eq!(snapshot.tasks.len(), 2);
        assert_eq!(restored.tasks[1].state, TaskState::Completed);
        assert_eq!(restored.children.len(), 2);
        assert_eq!(restored.budget.cost_remaining, Some(1000));
        assert_eq!(restored.cancel_reason.as_deref(), Some("timeout"));
        assert!(restored.parent.is_some());
        assert_eq!(restored.metadata, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn snapshot_invalid_magic() {
        let result = RegionSnapshot::from_bytes(b"BADM\x01");
        assert_eq!(result.unwrap_err(), SnapshotError::InvalidMagic);
    }

    #[test]
    fn snapshot_unsupported_version() {
        let result = RegionSnapshot::from_bytes(b"SNAP\xFF");
        assert_eq!(result.unwrap_err(), SnapshotError::UnsupportedVersion(0xFF));
    }

    #[test]
    fn snapshot_truncated_data() {
        let result = RegionSnapshot::from_bytes(b"SNAP\x01");
        assert_eq!(result.unwrap_err(), SnapshotError::UnexpectedEof);
    }

    #[test]
    fn content_hash_differs_for_different_snapshots() {
        let snap1 = create_test_snapshot();
        let mut snap2 = create_test_snapshot();
        snap2.sequence = 999;

        assert_ne!(snap1.content_hash(), snap2.content_hash());
    }

    #[test]
    fn task_state_roundtrip() {
        for state in [
            TaskState::Pending,
            TaskState::Running,
            TaskState::Completed,
            TaskState::Cancelled,
            TaskState::Panicked,
        ] {
            assert_eq!(TaskState::from_u8(state.as_u8()), Some(state));
        }
        assert_eq!(TaskState::from_u8(255), None);
    }

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn task_state_debug() {
        let dbg = format!("{:?}", TaskState::Pending);
        assert!(dbg.contains("Pending"));
    }

    #[test]
    fn task_state_clone_copy() {
        let state = TaskState::Running;
        let cloned = state;
        let copied = state;
        assert_eq!(cloned, copied);
    }

    #[test]
    fn task_state_eq() {
        assert_eq!(TaskState::Completed, TaskState::Completed);
        assert_ne!(TaskState::Pending, TaskState::Cancelled);
    }

    #[test]
    fn task_state_as_u8_all() {
        assert_eq!(TaskState::Pending.as_u8(), 0);
        assert_eq!(TaskState::Running.as_u8(), 1);
        assert_eq!(TaskState::Completed.as_u8(), 2);
        assert_eq!(TaskState::Cancelled.as_u8(), 3);
        assert_eq!(TaskState::Panicked.as_u8(), 4);
    }

    #[test]
    fn task_state_from_u8_invalid_range() {
        for v in 5..=10 {
            assert_eq!(TaskState::from_u8(v), None);
        }
    }

    #[test]
    fn task_snapshot_debug() {
        let snap = TaskSnapshot {
            task_id: TaskId::new_for_test(1, 0),
            state: TaskState::Pending,
            priority: 5,
        };
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("TaskSnapshot"));
    }

    #[test]
    fn task_snapshot_clone() {
        let snap = TaskSnapshot {
            task_id: TaskId::new_for_test(2, 0),
            state: TaskState::Running,
            priority: 10,
        };
        let cloned = snap;
        assert_eq!(cloned.state, TaskState::Running);
        assert_eq!(cloned.priority, 10);
    }

    #[test]
    fn budget_snapshot_debug() {
        let budget = BudgetSnapshot {
            deadline_nanos: Some(1_000_000),
            polls_remaining: Some(100),
            cost_remaining: None,
        };
        let dbg = format!("{budget:?}");
        assert!(dbg.contains("BudgetSnapshot"));
    }

    #[test]
    fn budget_snapshot_clone() {
        let budget = BudgetSnapshot {
            deadline_nanos: None,
            polls_remaining: None,
            cost_remaining: Some(500),
        };
        let cloned = budget;
        assert_eq!(cloned.cost_remaining, Some(500));
        assert!(cloned.deadline_nanos.is_none());
    }

    #[test]
    fn budget_snapshot_all_none() {
        let budget = BudgetSnapshot {
            deadline_nanos: None,
            polls_remaining: None,
            cost_remaining: None,
        };
        assert!(budget.deadline_nanos.is_none());
        assert!(budget.polls_remaining.is_none());
        assert!(budget.cost_remaining.is_none());
    }

    #[test]
    fn region_snapshot_debug() {
        let snap = RegionSnapshot::empty(RegionId::new_for_test(1, 0));
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("RegionSnapshot"));
    }

    #[test]
    fn region_snapshot_clone() {
        let snap = RegionSnapshot::empty(RegionId::new_for_test(3, 0));
        let cloned = snap.clone();
        assert_eq!(cloned.region_id, snap.region_id);
        assert_eq!(cloned.sequence, 0);
    }

    #[test]
    fn region_snapshot_empty_fields() {
        let snap = RegionSnapshot::empty(RegionId::new_for_test(7, 0));
        assert_eq!(snap.state, RegionState::Open);
        assert_eq!(snap.timestamp, Time::ZERO);
        assert!(snap.tasks.is_empty());
        assert!(snap.children.is_empty());
        assert_eq!(snap.finalizer_count, 0);
        assert!(snap.cancel_reason.is_none());
        assert!(snap.parent.is_none());
        assert!(snap.metadata.is_empty());
    }

    #[test]
    fn snapshot_error_debug() {
        let err = SnapshotError::InvalidMagic;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidMagic"));
    }

    #[test]
    fn snapshot_error_clone_eq() {
        let err = SnapshotError::UnsupportedVersion(42);
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn snapshot_error_display_all() {
        let err = SnapshotError::InvalidMagic;
        assert!(err.to_string().contains("invalid snapshot magic"));

        let err = SnapshotError::UnsupportedVersion(99);
        assert!(err.to_string().contains("99"));

        let err = SnapshotError::InvalidState(0xFF);
        assert!(err.to_string().contains("invalid state byte"));

        let err = SnapshotError::UnexpectedEof;
        assert!(err.to_string().contains("unexpected end"));

        let err = SnapshotError::InvalidString;
        assert!(err.to_string().contains("invalid UTF-8"));
    }

    #[test]
    fn snapshot_error_eq_ne() {
        assert_eq!(SnapshotError::InvalidMagic, SnapshotError::InvalidMagic);
        assert_ne!(SnapshotError::InvalidMagic, SnapshotError::UnexpectedEof);
        assert_ne!(
            SnapshotError::UnsupportedVersion(1),
            SnapshotError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn snapshot_error_trait() {
        let err: &dyn std::error::Error = &SnapshotError::InvalidMagic;
        assert!(err.source().is_none());
    }
}
