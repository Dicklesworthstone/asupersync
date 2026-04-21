//! Snapshot of region state for encoding.
//!
//! Captures all information needed to reconstruct a region's state on a
//! remote replica. Supports deterministic binary serialization.

use crate::record::region::RegionState;
use crate::types::{RegionId, TaskId, Time};
use crate::util::ArenaIndex;
use std::collections::BTreeMap;

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
        write_u32(
            &mut buf,
            u32::try_from(self.tasks.len()).expect("tasks exceed u32::MAX"),
        );
        for task in &self.tasks {
            write_task_id(&mut buf, task.task_id);
            buf.push(task.state.as_u8());
            buf.push(task.priority);
        }

        // Children
        write_u32(
            &mut buf,
            u32::try_from(self.children.len()).expect("children exceed u32::MAX"),
        );
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
        write_u32(
            &mut buf,
            u32::try_from(self.metadata.len()).expect("metadata exceeds u32::MAX"),
        );
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
        // Each task reads at least 10 bytes (8 id + 1 state + 1 priority).
        // Cap pre-allocation to remaining data to prevent OOM from crafted payloads.
        let max_tasks = cursor.remaining() / 10;
        let mut tasks = Vec::with_capacity((task_count as usize).min(max_tasks));
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
        // Each child reads 8 bytes (4 index + 4 generation).
        let max_children = cursor.remaining() / 8;
        let mut children = Vec::with_capacity((children_count as usize).min(max_children));
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
        let parent = match has_parent {
            0 => None,
            1 => Some(cursor.read_region_id()?),
            flag => return Err(SnapshotError::InvalidPresenceFlag(flag)),
        };

        // Metadata
        let metadata_len = cursor.read_u32()?;
        let metadata = cursor.read_exact(metadata_len as usize)?.to_vec();

        if cursor.remaining() != 0 {
            return Err(SnapshotError::TrailingBytes(cursor.remaining()));
        }

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
        let budget = 1
            + self.budget.deadline_nanos.map_or(0, |_| 8)
            + 1
            + self.budget.polls_remaining.map_or(0, |_| 4)
            + 1
            + self.budget.cost_remaining.map_or(0, |_| 8);
        let cancel = 1 + self.cancel_reason.as_ref().map_or(0, |s| 4 + s.len());
        let parent = 1 + self.parent.map_or(0, |_| 8);
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

    /// Merges two snapshots for the same region using CRDT-style join semantics.
    ///
    /// The merged view keeps the maximum observed region and task states,
    /// unions task and child identities, prefers the most recent cancellation
    /// context, and deduplicates metadata bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotMergeError::RegionMismatch`] if the snapshots refer
    /// to different regions.
    pub fn merge_crdt(&self, other: &Self) -> Result<Self, SnapshotMergeError> {
        if self.region_id != other.region_id {
            return Err(SnapshotMergeError::RegionMismatch {
                left: self.region_id,
                right: other.region_id,
            });
        }

        let mut tasks: BTreeMap<(u32, u32), TaskSnapshot> = BTreeMap::new();
        for task in self.tasks.iter().chain(&other.tasks) {
            tasks
                .entry(task_key(task.task_id))
                .and_modify(|current| *current = merge_task_snapshots(current, task))
                .or_insert_with(|| task.clone());
        }

        let mut children: BTreeMap<(u32, u32), RegionId> = BTreeMap::new();
        for child in self.children.iter().chain(&other.children) {
            children.entry(region_key(*child)).or_insert(*child);
        }

        let mut metadata = self.metadata.clone();
        metadata.extend_from_slice(&other.metadata);
        metadata.sort_unstable();
        metadata.dedup();

        let preferred_cancel = if (self.sequence, self.timestamp.as_nanos(), self.state.as_u8())
            >= (
                other.sequence,
                other.timestamp.as_nanos(),
                other.state.as_u8(),
            ) {
            (&self.cancel_reason, &other.cancel_reason)
        } else {
            (&other.cancel_reason, &self.cancel_reason)
        };

        Ok(Self {
            region_id: self.region_id,
            state: max_region_state(self.state, other.state),
            timestamp: self.timestamp.max(other.timestamp),
            sequence: self.sequence.max(other.sequence),
            tasks: tasks.into_values().collect(),
            children: children.into_values().collect(),
            finalizer_count: self.finalizer_count.max(other.finalizer_count),
            budget: BudgetSnapshot {
                deadline_nanos: self.budget.deadline_nanos.max(other.budget.deadline_nanos),
                polls_remaining: self
                    .budget
                    .polls_remaining
                    .max(other.budget.polls_remaining),
                cost_remaining: self.budget.cost_remaining.max(other.budget.cost_remaining),
            },
            cancel_reason: preferred_cancel
                .0
                .clone()
                .or_else(|| preferred_cancel.1.clone()),
            parent: merge_parent_region(self.parent, other.parent),
            metadata,
        })
    }
}

fn task_key(task_id: TaskId) -> (u32, u32) {
    let arena = task_id.0;
    (arena.index(), arena.generation())
}

fn region_key(region_id: RegionId) -> (u32, u32) {
    let arena = region_id.0;
    (arena.index(), arena.generation())
}

fn max_region_state(left: RegionState, right: RegionState) -> RegionState {
    if left.as_u8() >= right.as_u8() {
        left
    } else {
        right
    }
}

fn max_task_state(left: TaskState, right: TaskState) -> TaskState {
    if left.as_u8() >= right.as_u8() {
        left
    } else {
        right
    }
}

fn merge_task_snapshots(left: &TaskSnapshot, right: &TaskSnapshot) -> TaskSnapshot {
    TaskSnapshot {
        task_id: left.task_id,
        state: max_task_state(left.state, right.state),
        priority: left.priority.max(right.priority),
    }
}

fn merge_parent_region(left: Option<RegionId>, right: Option<RegionId>) -> Option<RegionId> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if region_key(left) >= region_key(right) {
            left
        } else {
            right
        }),
        (Some(left), None) | (None, Some(left)) => Some(left),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error during snapshot merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotMergeError {
    /// The two snapshots refer to different regions.
    RegionMismatch {
        /// Region identifier from the left-hand snapshot.
        left: RegionId,
        /// Region identifier from the right-hand snapshot.
        right: RegionId,
    },
}

impl std::fmt::Display for SnapshotMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionMismatch { left, right } => write!(
                f,
                "cannot CRDT-merge snapshots from different regions: left={left:?}, right={right:?}"
            ),
        }
    }
}

impl std::error::Error for SnapshotMergeError {}

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
    /// Invalid optional/presence marker (must be 0 or 1).
    InvalidPresenceFlag(u8),
    /// Extra bytes remained after decoding a supposedly complete snapshot.
    TrailingBytes(usize),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid snapshot magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::InvalidState(s) => write!(f, "invalid state byte: {s}"),
            Self::UnexpectedEof => write!(f, "unexpected end of snapshot data"),
            Self::InvalidString => write!(f, "invalid UTF-8 in snapshot"),
            Self::InvalidPresenceFlag(flag) => {
                write!(f, "invalid presence flag: {flag} (expected 0 or 1)")
            }
            Self::TrailingBytes(count) => {
                write!(f, "snapshot contains {count} trailing byte(s)")
            }
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
            write_u32(
                buf,
                u32::try_from(bytes.len()).expect("string exceeds u32::MAX"), // ubs:ignore - infallible in practice
            );
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

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(SnapshotError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(SnapshotError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
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
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u64()?)),
            flag => Err(SnapshotError::InvalidPresenceFlag(flag)),
        }
    }

    fn read_optional_u32(&mut self) -> Result<Option<u32>, SnapshotError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_u32()?)),
            flag => Err(SnapshotError::InvalidPresenceFlag(flag)),
        }
    }

    fn read_optional_string(&mut self) -> Result<Option<String>, SnapshotError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => {
                let len = self.read_u32()? as usize;
                let bytes = self.read_exact(len)?;
                let s = std::str::from_utf8(bytes).map_err(|_| SnapshotError::InvalidString)?;
                Ok(Some(s.to_string()))
            }
            flag => Err(SnapshotError::InvalidPresenceFlag(flag)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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

    fn create_all_fields_snapshot() -> RegionSnapshot {
        RegionSnapshot {
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
        }
    }

    fn format_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn scrub_snapshot_wire_layout_for_snapshot_test(bytes: &[u8], task_count: usize) -> String {
        use std::fmt::Write;

        let mut cursor = 0usize;
        let mut out = String::new();

        let magic = &bytes[cursor..cursor + 4];
        cursor += 4;
        let version = bytes[cursor];
        cursor += 1;
        let region_id = &bytes[cursor..cursor + 8];
        cursor += 8;
        let state = bytes[cursor];
        cursor += 1;
        let timestamp = &bytes[cursor..cursor + 8];
        cursor += 8;
        let sequence = &bytes[cursor..cursor + 8];
        cursor += 8;
        let task_count_bytes = &bytes[cursor..cursor + 4];
        cursor += 4;

        let _ = writeln!(out, "magic: {}", format_hex(magic));
        let _ = writeln!(out, "version: {version:02x}");
        let _ = writeln!(out, "region_id: [{} bytes]", region_id.len());
        let _ = writeln!(out, "state: {state:02x}");
        let _ = writeln!(out, "timestamp_nanos: [{} bytes]", timestamp.len());
        let _ = writeln!(out, "sequence: {}", format_hex(sequence));
        let _ = writeln!(out, "task_count: {}", format_hex(task_count_bytes));

        for task_index in 0..task_count {
            let task_id = &bytes[cursor..cursor + 8];
            cursor += 8;
            let task_state = bytes[cursor];
            cursor += 1;
            let priority = bytes[cursor];
            cursor += 1;

            let _ = writeln!(out, "task[{task_index}].task_id: [{} bytes]", task_id.len());
            let _ = writeln!(out, "task[{task_index}].state: {task_state:02x}");
            let _ = writeln!(out, "task[{task_index}].priority: {priority:02x}");
        }

        let child_count =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        let child_count_bytes = &bytes[cursor..cursor + 4];
        cursor += 4;
        let _ = writeln!(out, "child_count: {}", format_hex(child_count_bytes));

        for child_index in 0..child_count {
            let child = &bytes[cursor..cursor + 8];
            cursor += 8;
            let _ = writeln!(out, "child[{child_index}]: [{} bytes]", child.len());
        }

        let finalizer_count = &bytes[cursor..cursor + 4];
        cursor += 4;
        let deadline_presence = bytes[cursor];
        cursor += 1;
        let deadline = &bytes[cursor..cursor + 8];
        cursor += 8;
        let polls_presence = bytes[cursor];
        cursor += 1;
        let polls_remaining = &bytes[cursor..cursor + 4];
        cursor += 4;
        let cost_presence = bytes[cursor];
        cursor += 1;
        let cost_remaining = &bytes[cursor..cursor + 8];
        cursor += 8;
        let cancel_presence = bytes[cursor];
        cursor += 1;
        let cancel_len = &bytes[cursor..cursor + 4];
        cursor += 4;
        let cancel_reason = &bytes[cursor..cursor + 7];
        cursor += 7;
        let parent_presence = bytes[cursor];
        cursor += 1;
        let parent = &bytes[cursor..cursor + 8];
        cursor += 8;
        let metadata_len = &bytes[cursor..cursor + 4];
        cursor += 4;
        let metadata = &bytes[cursor..cursor + 5];
        cursor += 5;

        let _ = writeln!(out, "finalizer_count: {}", format_hex(finalizer_count));
        let _ = writeln!(out, "budget.deadline_presence: {deadline_presence:02x}");
        let _ = writeln!(out, "budget.deadline_nanos: [{} bytes]", deadline.len());
        let _ = writeln!(out, "budget.polls_presence: {polls_presence:02x}");
        let _ = writeln!(
            out,
            "budget.polls_remaining: {}",
            format_hex(polls_remaining)
        );
        let _ = writeln!(out, "budget.cost_presence: {cost_presence:02x}");
        let _ = writeln!(out, "budget.cost_remaining: {}", format_hex(cost_remaining));
        let _ = writeln!(out, "cancel_reason.presence: {cancel_presence:02x}");
        let _ = writeln!(out, "cancel_reason.len: {}", format_hex(cancel_len));
        let _ = writeln!(out, "cancel_reason.utf8: {}", format_hex(cancel_reason));
        let _ = writeln!(out, "parent.presence: {parent_presence:02x}");
        let _ = writeln!(out, "parent.region_id: [{} bytes]", parent.len());
        let _ = writeln!(out, "metadata.len: {}", format_hex(metadata_len));
        let _ = writeln!(out, "metadata.bytes: {}", format_hex(metadata));

        assert_eq!(cursor, bytes.len(), "wire-layout scrubber missed bytes");
        out
    }

    fn scrub_snapshot_for_crdt_merge_snapshot_test(snapshot: &RegionSnapshot) -> serde_json::Value {
        json!({
            "region_id": "[region_id]",
            "state": format!("{:?}", snapshot.state),
            "timestamp_nanos": "[timestamp_nanos]",
            "sequence": snapshot.sequence,
            "tasks": snapshot.tasks.iter().enumerate().map(|(index, task)| {
                json!({
                    "task_id": format!("[task_{index}]"),
                    "state": format!("{:?}", task.state),
                    "priority": task.priority,
                })
            }).collect::<Vec<_>>(),
            "children": snapshot.children.iter().enumerate().map(|(index, _)| {
                format!("[child_{index}]")
            }).collect::<Vec<_>>(),
            "finalizer_count": snapshot.finalizer_count,
            "budget": {
                "deadline_nanos": snapshot.budget.deadline_nanos.map(|_| "[deadline_nanos]"),
                "polls_remaining": snapshot.budget.polls_remaining,
                "cost_remaining": snapshot.budget.cost_remaining,
            },
            "cancel_reason": snapshot.cancel_reason,
            "parent": snapshot.parent.map(|_| "[parent_region_id]"),
            "metadata": snapshot.metadata,
        })
    }

    fn scrub_snapshot_for_vector_clock_merge_snapshot_test(
        snapshot: &RegionSnapshot,
        expected_sequence: u64,
        expected_timestamp_secs: u64,
        expected_state: RegionState,
        expected_cancel_reason: Option<&str>,
    ) -> serde_json::Value {
        json!({
            "merged": scrub_snapshot_for_crdt_merge_snapshot_test(snapshot),
            "clock_invariants": {
                "sequence_is_max": snapshot.sequence == expected_sequence,
                "timestamp_is_max": snapshot.timestamp.as_nanos() == Time::from_secs(expected_timestamp_secs).as_nanos(),
                "state_is_max": snapshot.state == expected_state,
                "cancel_reason_matches_latest_clock": snapshot.cancel_reason.as_deref() == expected_cancel_reason,
            }
        })
    }

    fn merge_test_snapshot(
        region_id: RegionId,
        state: RegionState,
        timestamp_secs: u64,
        sequence: u64,
        tasks: &[(u32, u32, TaskState, u8)],
        children: &[(u32, u32)],
        finalizer_count: u32,
        budget: BudgetSnapshot,
        cancel_reason: Option<&str>,
        metadata: &[u8],
    ) -> RegionSnapshot {
        RegionSnapshot {
            region_id,
            state,
            timestamp: Time::from_secs(timestamp_secs),
            sequence,
            tasks: tasks
                .iter()
                .map(|(index, generation, state, priority)| TaskSnapshot {
                    task_id: TaskId::new_for_test(*index, *generation),
                    state: *state,
                    priority: *priority,
                })
                .collect(),
            children: children
                .iter()
                .map(|(index, generation)| RegionId::new_for_test(*index, *generation))
                .collect(),
            finalizer_count,
            budget,
            cancel_reason: cancel_reason.map(str::to_string),
            parent: Some(RegionId::new_for_test(0, 1)),
            metadata: metadata.to_vec(),
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
        let snapshot = create_all_fields_snapshot();

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
    fn snapshot_wire_layout_snapshot_scrubs_ids_and_timestamps() {
        let snapshot = create_all_fields_snapshot();
        let bytes = snapshot.to_bytes();

        insta::assert_snapshot!(
            "region_snapshot_wire_layout_scrubbed",
            scrub_snapshot_wire_layout_for_snapshot_test(&bytes, snapshot.tasks.len())
        );
    }

    #[test]
    fn crdt_merge_result_scrubbed() {
        let region_id = RegionId::new_for_test(42, 7);

        let inserts_left = merge_test_snapshot(
            region_id,
            RegionState::Open,
            10,
            3,
            &[(1, 0, TaskState::Pending, 1)],
            &[(10, 0)],
            1,
            BudgetSnapshot {
                deadline_nanos: Some(100),
                polls_remaining: Some(4),
                cost_remaining: Some(16),
            },
            None,
            &[1, 3],
        );
        let inserts_right = merge_test_snapshot(
            region_id,
            RegionState::Closing,
            12,
            4,
            &[(2, 0, TaskState::Running, 3)],
            &[(11, 0)],
            2,
            BudgetSnapshot {
                deadline_nanos: Some(150),
                polls_remaining: Some(8),
                cost_remaining: Some(32),
            },
            None,
            &[2, 3],
        );

        let deletes_left = merge_test_snapshot(
            region_id,
            RegionState::Draining,
            20,
            8,
            &[
                (1, 0, TaskState::Cancelled, 5),
                (2, 0, TaskState::Running, 2),
            ],
            &[(10, 0)],
            3,
            BudgetSnapshot {
                deadline_nanos: Some(200),
                polls_remaining: Some(5),
                cost_remaining: Some(64),
            },
            Some("Shutdown"),
            &[16],
        );
        let deletes_right = merge_test_snapshot(
            region_id,
            RegionState::Finalizing,
            22,
            9,
            &[
                (1, 0, TaskState::Pending, 1),
                (2, 0, TaskState::Completed, 4),
            ],
            &[(10, 0)],
            4,
            BudgetSnapshot {
                deadline_nanos: Some(220),
                polls_remaining: Some(7),
                cost_remaining: Some(96),
            },
            Some("Timeout"),
            &[32],
        );

        let mixed_left = merge_test_snapshot(
            region_id,
            RegionState::Closing,
            30,
            12,
            &[(1, 0, TaskState::Running, 2), (3, 0, TaskState::Pending, 6)],
            &[(10, 0), (12, 0)],
            2,
            BudgetSnapshot {
                deadline_nanos: Some(300),
                polls_remaining: Some(6),
                cost_remaining: Some(100),
            },
            None,
            &[48, 64],
        );
        let mixed_right = merge_test_snapshot(
            region_id,
            RegionState::Finalizing,
            31,
            13,
            &[
                (1, 0, TaskState::Running, 3),
                (2, 0, TaskState::Cancelled, 4),
            ],
            &[(10, 0), (13, 0)],
            5,
            BudgetSnapshot {
                deadline_nanos: Some(360),
                polls_remaining: Some(9),
                cost_remaining: Some(128),
            },
            Some("PollQuota"),
            &[64, 80],
        );

        let concurrent_inserts = inserts_left.merge_crdt(&inserts_right).unwrap();
        let concurrent_deletes = deletes_left.merge_crdt(&deletes_right).unwrap();
        let mixed_insert_delete = mixed_left.merge_crdt(&mixed_right).unwrap();

        crate::assert_with_log!(
            concurrent_inserts.to_bytes()
                == inserts_right.merge_crdt(&inserts_left).unwrap().to_bytes(),
            "concurrent insert merge should be commutative",
            scrub_snapshot_for_crdt_merge_snapshot_test(&concurrent_inserts),
            scrub_snapshot_for_crdt_merge_snapshot_test(
                &inserts_right.merge_crdt(&inserts_left).unwrap()
            )
        );
        crate::assert_with_log!(
            concurrent_deletes.to_bytes()
                == deletes_right.merge_crdt(&deletes_left).unwrap().to_bytes(),
            "concurrent delete merge should be commutative",
            scrub_snapshot_for_crdt_merge_snapshot_test(&concurrent_deletes),
            scrub_snapshot_for_crdt_merge_snapshot_test(
                &deletes_right.merge_crdt(&deletes_left).unwrap()
            )
        );
        crate::assert_with_log!(
            mixed_insert_delete.to_bytes()
                == mixed_right.merge_crdt(&mixed_left).unwrap().to_bytes(),
            "mixed merge should be commutative",
            scrub_snapshot_for_crdt_merge_snapshot_test(&mixed_insert_delete),
            scrub_snapshot_for_crdt_merge_snapshot_test(
                &mixed_right.merge_crdt(&mixed_left).unwrap()
            )
        );

        insta::assert_json_snapshot!(
            "crdt_merge_result_scrubbed",
            json!({
                "concurrent_inserts": scrub_snapshot_for_crdt_merge_snapshot_test(&concurrent_inserts),
                "concurrent_deletes": scrub_snapshot_for_crdt_merge_snapshot_test(&concurrent_deletes),
                "mixed_insert_delete": scrub_snapshot_for_crdt_merge_snapshot_test(&mixed_insert_delete),
            })
        );
    }

    #[test]
    fn vector_clock_merge_output_scrubbed() {
        let region_id = RegionId::new_for_test(91, 4);

        let replica_a = merge_test_snapshot(
            region_id,
            RegionState::Closing,
            40,
            7,
            &[(1, 0, TaskState::Pending, 1), (3, 0, TaskState::Running, 2)],
            &[(10, 0)],
            1,
            BudgetSnapshot {
                deadline_nanos: Some(400),
                polls_remaining: Some(2),
                cost_remaining: Some(24),
            },
            None,
            &[1, 4],
        );
        let replica_b = merge_test_snapshot(
            region_id,
            RegionState::Draining,
            44,
            9,
            &[(1, 0, TaskState::Running, 3), (2, 0, TaskState::Pending, 4)],
            &[(11, 0)],
            2,
            BudgetSnapshot {
                deadline_nanos: Some(440),
                polls_remaining: Some(6),
                cost_remaining: Some(48),
            },
            Some("retry-exhausted"),
            &[2, 4],
        );
        let replica_c = merge_test_snapshot(
            region_id,
            RegionState::Closed,
            46,
            11,
            &[
                (1, 0, TaskState::Completed, 3),
                (2, 0, TaskState::Cancelled, 5),
                (4, 0, TaskState::Panicked, 1),
            ],
            &[(12, 0), (13, 0)],
            4,
            BudgetSnapshot {
                deadline_nanos: Some(460),
                polls_remaining: Some(8),
                cost_remaining: Some(96),
            },
            Some("peer-closed"),
            &[3, 4, 5],
        );

        let three_replica_chain = replica_a
            .merge_crdt(&replica_b)
            .unwrap()
            .merge_crdt(&replica_c)
            .unwrap();
        let three_replica_alt = replica_a
            .merge_crdt(&replica_c)
            .unwrap()
            .merge_crdt(&replica_b)
            .unwrap();
        let three_replica_rev = replica_c
            .merge_crdt(&replica_b)
            .unwrap()
            .merge_crdt(&replica_a)
            .unwrap();

        crate::assert_with_log!(
            three_replica_chain.to_bytes() == three_replica_alt.to_bytes(),
            "three-replica merge should be order-independent",
            scrub_snapshot_for_crdt_merge_snapshot_test(&three_replica_chain),
            scrub_snapshot_for_crdt_merge_snapshot_test(&three_replica_alt)
        );
        crate::assert_with_log!(
            three_replica_chain.to_bytes() == three_replica_rev.to_bytes(),
            "three-replica merge should be associative",
            scrub_snapshot_for_crdt_merge_snapshot_test(&three_replica_chain),
            scrub_snapshot_for_crdt_merge_snapshot_test(&three_replica_rev)
        );

        let same_sequence_left = merge_test_snapshot(
            region_id,
            RegionState::Closing,
            50,
            12,
            &[(8, 0, TaskState::Running, 1)],
            &[(20, 0)],
            1,
            BudgetSnapshot {
                deadline_nanos: Some(500),
                polls_remaining: Some(5),
                cost_remaining: Some(32),
            },
            Some("stale-owner"),
            &[9],
        );
        let same_sequence_right = merge_test_snapshot(
            region_id,
            RegionState::Draining,
            55,
            12,
            &[(8, 0, TaskState::Cancelled, 7)],
            &[(21, 0)],
            3,
            BudgetSnapshot {
                deadline_nanos: Some(550),
                polls_remaining: Some(7),
                cost_remaining: Some(64),
            },
            Some("fresh-owner"),
            &[8, 9],
        );
        let same_sequence_later_timestamp =
            same_sequence_left.merge_crdt(&same_sequence_right).unwrap();

        let tied_clock_left = merge_test_snapshot(
            region_id,
            RegionState::Draining,
            60,
            15,
            &[(9, 0, TaskState::Cancelled, 4)],
            &[(30, 0)],
            2,
            BudgetSnapshot {
                deadline_nanos: Some(600),
                polls_remaining: Some(9),
                cost_remaining: Some(80),
            },
            Some("drain-phase"),
            &[10],
        );
        let tied_clock_right = merge_test_snapshot(
            region_id,
            RegionState::Closed,
            60,
            15,
            &[
                (9, 0, TaskState::Cancelled, 6),
                (10, 0, TaskState::Completed, 2),
            ],
            &[(31, 0)],
            5,
            BudgetSnapshot {
                deadline_nanos: Some(650),
                polls_remaining: Some(11),
                cost_remaining: Some(120),
            },
            Some("closed-phase"),
            &[10, 11],
        );
        let state_tiebreak_merge = tied_clock_left.merge_crdt(&tied_clock_right).unwrap();

        insta::assert_json_snapshot!(
            "vector_clock_merge_output_scrubbed",
            json!({
                "three_replica_chain": scrub_snapshot_for_vector_clock_merge_snapshot_test(
                    &three_replica_chain,
                    11,
                    46,
                    RegionState::Closed,
                    Some("peer-closed"),
                ),
                "same_sequence_later_timestamp": scrub_snapshot_for_vector_clock_merge_snapshot_test(
                    &same_sequence_later_timestamp,
                    12,
                    55,
                    RegionState::Draining,
                    Some("fresh-owner"),
                ),
                "state_tiebreak": scrub_snapshot_for_vector_clock_merge_snapshot_test(
                    &state_tiebreak_merge,
                    15,
                    60,
                    RegionState::Closed,
                    Some("closed-phase"),
                ),
            })
        );
    }

    #[test]
    fn crdt_merge_rejects_region_mismatch() {
        let left = RegionSnapshot::empty(RegionId::new_for_test(1, 0));
        let right = RegionSnapshot::empty(RegionId::new_for_test(2, 0));

        assert!(
            matches!(
                left.merge_crdt(&right),
                Err(SnapshotMergeError::RegionMismatch {
                    left: left_region,
                    right: right_region,
                }) if left_region == left.region_id && right_region == right.region_id
            ),
            "mismatched regions should be rejected cleanly",
        );
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
    fn snapshot_invalid_budget_presence_flag() {
        let mut bytes = RegionSnapshot::empty(RegionId::new_for_test(9, 0)).to_bytes();
        // Layout for empty snapshot:
        // header(5) + region_id(8) + state(1) + timestamp(8) + sequence(8)
        // + task_count(4) + child_count(4) + finalizer_count(4) = 42
        // Next byte is budget.deadline presence flag.
        bytes[42] = 2;
        let result = RegionSnapshot::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SnapshotError::InvalidPresenceFlag(2));
    }

    #[test]
    fn snapshot_invalid_parent_presence_flag() {
        let mut bytes = RegionSnapshot::empty(RegionId::new_for_test(9, 0)).to_bytes();
        // In empty snapshot, parent presence flag is at offset 46.
        bytes[46] = 2;
        let result = RegionSnapshot::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SnapshotError::InvalidPresenceFlag(2));
    }

    #[test]
    fn snapshot_rejects_trailing_bytes() {
        let mut bytes = create_test_snapshot().to_bytes();
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let result = RegionSnapshot::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SnapshotError::TrailingBytes(3));
    }

    #[test]
    fn snapshot_huge_task_count_with_truncated_payload_returns_eof() {
        // Corrupt task_count in an otherwise valid header to emulate a crafted
        // payload that claims an enormous number of tasks but provides no body.
        let mut bytes = create_test_snapshot().to_bytes();
        let task_count_offset = 4 + 1 + 8 + 1 + 8 + 8;
        bytes[task_count_offset..task_count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes.truncate(task_count_offset + 4);

        let result = RegionSnapshot::from_bytes(&bytes);
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

        let err = SnapshotError::InvalidPresenceFlag(7);
        assert!(err.to_string().contains("invalid presence flag"));

        let err = SnapshotError::TrailingBytes(3);
        assert!(err.to_string().contains("trailing byte"));
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

    // Pure data-type tests (wave 39 – CyanBarn)

    #[test]
    fn task_state_debug_clone_copy_eq() {
        for state in [
            TaskState::Pending,
            TaskState::Running,
            TaskState::Completed,
            TaskState::Cancelled,
            TaskState::Panicked,
        ] {
            let dbg = format!("{state:?}");
            assert!(!dbg.is_empty());

            let copied = state;
            assert_eq!(copied, state);

            let cloned = state;
            assert_eq!(cloned, state);
        }
        assert_ne!(TaskState::Pending, TaskState::Running);
    }

    #[test]
    fn task_snapshot_debug_clone() {
        let snap = TaskSnapshot {
            task_id: TaskId::new_for_test(1, 0),
            state: TaskState::Running,
            priority: 5,
        };
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("TaskSnapshot"));

        let cloned = snap;
        assert_eq!(cloned.priority, 5);
        assert_eq!(cloned.state, TaskState::Running);
    }

    #[test]
    fn budget_snapshot_debug_clone() {
        let snap = BudgetSnapshot {
            deadline_nanos: Some(1_000_000_000),
            polls_remaining: Some(100),
            cost_remaining: None,
        };
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("BudgetSnapshot"));

        let cloned = snap;
        assert_eq!(cloned.deadline_nanos, Some(1_000_000_000));
        assert_eq!(cloned.polls_remaining, Some(100));
        assert!(cloned.cost_remaining.is_none());
    }

    #[test]
    fn region_snapshot_debug_clone() {
        let snap = RegionSnapshot::empty(RegionId::new_for_test(0, 0));
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("RegionSnapshot"));

        let cloned = snap;
        assert_eq!(cloned.sequence, 0);
        assert!(cloned.tasks.is_empty());
    }

    #[test]
    fn snapshot_error_debug_clone() {
        let errors = [
            SnapshotError::InvalidMagic,
            SnapshotError::UnsupportedVersion(2),
            SnapshotError::InvalidState(0xFF),
            SnapshotError::UnexpectedEof,
            SnapshotError::InvalidString,
            SnapshotError::InvalidPresenceFlag(2),
            SnapshotError::TrailingBytes(1),
        ];
        for err in &errors {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());

            let cloned = err.clone();
            assert_eq!(&cloned, err);
        }
    }
}
