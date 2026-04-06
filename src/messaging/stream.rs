//! Region-owned FABRIC stream state machines.

use super::class::DeliveryClass;
use super::subject::{Subject, SubjectPattern};
use crate::types::{RegionId, Time};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

/// Retention semantics for a captured subject set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RetentionPolicy {
    /// Retain messages until configured resource limits evict them.
    #[default]
    Limits,
    /// Retain messages until work-queue delivery semantics consume them.
    ///
    /// This initial state-machine keeps the full log until follow-on consumer
    /// semantics are implemented in later FABRIC beads.
    WorkQueue,
    /// Retain messages while consumers still declare interest.
    ///
    /// This initial state-machine keeps the full log until explicit
    /// interest-tracking semantics land in later FABRIC beads.
    Interest,
}

/// Capture policy for durable stream ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CapturePolicy {
    /// Only explicitly configured subject-filter matches are captured.
    #[default]
    SubjectFilterOnly,
    /// Capture subject-filter matches plus reply-space inbox traffic.
    IncludeReplySubjects,
}

/// Static configuration for a region-owned FABRIC stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamConfig {
    /// Subject set whose traffic is durably captured.
    pub subject_filter: SubjectPattern,
    /// Retention mode applied to the captured log.
    pub retention: RetentionPolicy,
    /// Maximum retained messages; `0` means unbounded.
    pub max_msgs: u64,
    /// Maximum retained payload bytes; `0` means unbounded.
    pub max_bytes: u64,
    /// Maximum retained age for a message; `None` means unbounded.
    pub max_age: Option<Duration>,
    /// Duplicate-suppression horizon reserved for follow-on durability work.
    pub dedupe_window: Option<Duration>,
    /// Delivery class promised by this stream boundary.
    pub delivery_class: DeliveryClass,
    /// Capture behavior for subjects outside the explicit filter.
    pub capture_policy: CapturePolicy,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            subject_filter: SubjectPattern::new("fabric.default"),
            retention: RetentionPolicy::default(),
            max_msgs: 0,
            max_bytes: 0,
            max_age: None,
            dedupe_window: None,
            delivery_class: DeliveryClass::DurableOrdered,
            capture_policy: CapturePolicy::default(),
        }
    }
}

/// Mutable stream bookkeeping surfaced for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamState {
    /// Number of currently retained messages.
    pub msg_count: u64,
    /// Number of retained payload bytes.
    pub byte_count: u64,
    /// Lowest retained sequence number, or `0` when empty.
    pub first_seq: u64,
    /// Highest retained sequence number, or `0` when empty.
    pub last_seq: u64,
    /// Number of active consumer attachments.
    pub consumer_count: usize,
    /// Logical creation time of the stream.
    pub created_at: Time,
    /// Current lifecycle state.
    pub lifecycle: StreamLifecycle,
}

/// Lifecycle state for a region-owned stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StreamLifecycle {
    /// The stream is accepting new captures.
    #[default]
    Open,
    /// The stream is draining children before closure.
    Closing,
    /// The stream has reached quiescence and is closed.
    Closed,
}

/// A single durably retained stream record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamRecord {
    /// Monotonic stream-local sequence number.
    pub seq: u64,
    /// Captured subject for this entry.
    pub subject: Subject,
    /// Stored payload bytes.
    pub payload: Vec<u8>,
    /// Logical ingest time for retention and diagnostics.
    pub published_at: Time,
}

impl StreamRecord {
    fn payload_len(&self) -> Result<u64, StreamError> {
        u64::try_from(self.payload.len()).map_err(|_| StreamError::PayloadTooLarge {
            bytes: self.payload.len(),
        })
    }
}

/// Storage snapshot returned by a stream backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct StorageSnapshot {
    /// Retained records in stream order.
    pub records: Vec<StreamRecord>,
}

/// A snapshot of stream configuration, state, storage, and child-region links.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamSnapshot {
    /// Human-readable stream name.
    pub name: String,
    /// Region that owns the stream.
    pub region_id: RegionId,
    /// Stream configuration at snapshot time.
    pub config: StreamConfig,
    /// Stream state at snapshot time.
    pub state: StreamState,
    /// Storage contents at snapshot time.
    pub storage: StorageSnapshot,
    /// Active consumer attachments at snapshot time.
    pub consumer_ids: Vec<u64>,
    /// Mirror child regions currently attached to the stream.
    pub mirror_regions: Vec<RegionId>,
    /// Source child regions currently attached to the stream.
    pub source_regions: Vec<RegionId>,
}

impl StreamSnapshot {
    /// Return whether the captured stream had drained all live attachments.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.consumer_ids.is_empty()
            && self.mirror_regions.is_empty()
            && self.source_regions.is_empty()
    }
}

/// Storage backend used by a FABRIC stream.
pub trait StorageBackend {
    /// Append a new record to the backend.
    fn append(&mut self, record: StreamRecord) -> Result<(), StreamError>;

    /// Fetch a record by exact sequence number.
    fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError>;

    /// Fetch records in the inclusive sequence range.
    fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError>;

    /// Truncate all records up to and including `through_seq`.
    fn truncate_through(&mut self, through_seq: u64) -> Result<Vec<StreamRecord>, StreamError>;

    /// Return a full snapshot of retained records.
    fn snapshot(&self) -> Result<StorageSnapshot, StreamError>;
}

/// Deterministic in-memory storage backend for early FABRIC stream work.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InMemoryStorageBackend {
    records: VecDeque<StreamRecord>,
}

impl StorageBackend for InMemoryStorageBackend {
    fn append(&mut self, record: StreamRecord) -> Result<(), StreamError> {
        self.records.push_back(record);
        Ok(())
    }

    fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError> {
        Ok(self
            .records
            .iter()
            .find(|record| record.seq == seq)
            .cloned())
    }

    fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError> {
        Ok(self
            .records
            .iter()
            .filter(|record| seqs.contains(&record.seq))
            .cloned()
            .collect())
    }

    fn truncate_through(&mut self, through_seq: u64) -> Result<Vec<StreamRecord>, StreamError> {
        let mut removed = Vec::new();
        while self
            .records
            .front()
            .is_some_and(|record| record.seq <= through_seq)
        {
            if let Some(record) = self.records.pop_front() {
                removed.push(record);
            }
        }
        Ok(removed)
    }

    fn snapshot(&self) -> Result<StorageSnapshot, StreamError> {
        Ok(StorageSnapshot {
            records: self.records.iter().cloned().collect(),
        })
    }
}

impl InMemoryStorageBackend {
    /// Rehydrate the in-memory backend from a retained storage snapshot.
    pub fn from_snapshot(snapshot: &StorageSnapshot) -> Result<Self, StreamError> {
        validate_retained_records(snapshot.records.iter())?;
        Ok(Self {
            records: snapshot.records.iter().cloned().collect(),
        })
    }
}

fn validate_retained_records<'a, I>(records: I) -> Result<(), StreamError>
where
    I: IntoIterator<Item = &'a StreamRecord>,
{
    let mut previous_seq: Option<u64> = None;
    for record in records {
        match previous_seq {
            None => {
                if record.seq == 0 {
                    return Err(StreamError::InvalidRecoveredSequence {
                        previous_seq: None,
                        current_seq: record.seq,
                    });
                }
            }
            Some(previous_seq_value) => {
                if record.seq != previous_seq_value.saturating_add(1) {
                    return Err(StreamError::InvalidRecoveredSequence {
                        previous_seq: Some(previous_seq_value),
                        current_seq: record.seq,
                    });
                }
            }
        }
        previous_seq = Some(record.seq);
    }

    Ok(())
}

/// Durability policy used when advancing the on-disk WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalFsyncPolicy {
    /// Never force the WAL to stable storage automatically.
    Never,
    /// Force the active segment at rotation boundaries.
    SegmentBoundary,
    /// Force every append/truncate control entry before returning.
    Always,
}

impl WalFsyncPolicy {
    /// Select the default sync policy for a delivery class.
    #[must_use]
    pub const fn for_delivery_class(delivery_class: DeliveryClass) -> Self {
        match delivery_class {
            DeliveryClass::EphemeralInteractive => Self::Never,
            DeliveryClass::DurableOrdered => Self::SegmentBoundary,
            DeliveryClass::ObligationBacked
            | DeliveryClass::MobilitySafe
            | DeliveryClass::ForensicReplayable => Self::Always,
        }
    }
}

/// Configuration for the file-backed WAL storage backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalStorageConfig {
    root_dir: PathBuf,
    segment_max_bytes: u64,
    fsync_policy: WalFsyncPolicy,
}

impl WalStorageConfig {
    /// Default segment size used when callers do not provide one explicitly.
    pub const DEFAULT_SEGMENT_MAX_BYTES: u64 = 256 * 1024;

    /// Build a WAL config rooted at `root_dir` with defaults for `delivery_class`.
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>, delivery_class: DeliveryClass) -> Self {
        Self {
            root_dir: root_dir.into(),
            segment_max_bytes: Self::DEFAULT_SEGMENT_MAX_BYTES,
            fsync_policy: WalFsyncPolicy::for_delivery_class(delivery_class),
        }
    }

    /// Override the maximum size of a single segment before rotation.
    #[must_use]
    pub fn with_segment_max_bytes(mut self, segment_max_bytes: u64) -> Self {
        self.segment_max_bytes = segment_max_bytes;
        self
    }

    /// Override the sync policy derived from the delivery class.
    #[must_use]
    pub const fn with_fsync_policy(mut self, fsync_policy: WalFsyncPolicy) -> Self {
        self.fsync_policy = fsync_policy;
        self
    }

    /// Return the directory that stores WAL segments for the stream.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Return the configured maximum size of a single segment.
    #[must_use]
    pub const fn segment_max_bytes(&self) -> u64 {
        self.segment_max_bytes
    }

    /// Return the configured filesystem sync policy.
    #[must_use]
    pub const fn fsync_policy(&self) -> WalFsyncPolicy {
        self.fsync_policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WalSegmentMeta {
    id: u64,
    path: PathBuf,
    bytes: u64,
    record_count: usize,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
}

impl WalSegmentMeta {
    fn record_append(&mut self, record: &StreamRecord, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.record_count = self.record_count.saturating_add(1);
        self.first_seq.get_or_insert(record.seq);
        self.last_seq = Some(record.seq);
    }

    fn note_control_entry(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WalEntry {
    Append { record: StreamRecord },
    TruncateThrough { through_seq: u64 },
}

/// Append-only WAL-backed stream storage with deterministic recovery semantics.
#[derive(Debug, PartialEq, Eq)]
pub struct WalStorageBackend {
    config: WalStorageConfig,
    records: VecDeque<StreamRecord>,
    segments: Vec<WalSegmentMeta>,
    next_segment_id: u64,
}

impl WalStorageBackend {
    /// Open or create a WAL directory and replay retained stream state from it.
    pub fn open(config: WalStorageConfig) -> Result<Self, StreamError> {
        if config.segment_max_bytes == 0 {
            return Err(StreamError::InvalidWalConfig {
                field: "segment_max_bytes",
                detail: "segment size must be greater than zero".to_owned(),
            });
        }

        fs::create_dir_all(config.root_dir())
            .map_err(|error| StreamError::wal_io("create_dir_all", config.root_dir(), &error))?;

        let mut records = VecDeque::new();
        let mut segments = Vec::new();
        let mut next_segment_id = 0;

        for (segment_id, path) in Self::segment_paths(config.root_dir())? {
            let (segment, loaded_records) = Self::load_segment(segment_id, &path)?;
            Self::apply_entries(&mut records, &loaded_records);
            next_segment_id = next_segment_id.max(segment_id.saturating_add(1));
            segments.push(segment);
        }
        validate_retained_records(records.iter())?;

        Ok(Self {
            config,
            records,
            segments,
            next_segment_id,
        })
    }

    /// Create a new WAL backend from an in-memory storage snapshot.
    pub fn from_snapshot(
        config: WalStorageConfig,
        snapshot: &StorageSnapshot,
    ) -> Result<Self, StreamError> {
        fs::create_dir_all(config.root_dir())
            .map_err(|error| StreamError::wal_io("create_dir_all", config.root_dir(), &error))?;
        let has_existing_entries = fs::read_dir(config.root_dir())
            .map_err(|error| StreamError::wal_io("read_dir", config.root_dir(), &error))?
            .next()
            .transpose()
            .map_err(|error| StreamError::wal_io("read_dir_entry", config.root_dir(), &error))?
            .is_some();
        if has_existing_entries {
            return Err(StreamError::WalAlreadyInitialized {
                path: config.root_dir().display().to_string(),
            });
        }
        validate_retained_records(snapshot.records.iter())?;

        let mut backend = Self::open(config)?;
        for record in snapshot.records.iter().cloned() {
            backend.append(record)?;
        }
        Ok(backend)
    }

    /// Return the number of segment files currently known to the backend.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    fn apply_entries(records: &mut VecDeque<StreamRecord>, entries: &[WalEntry]) {
        for entry in entries {
            match entry {
                WalEntry::Append { record } => records.push_back(record.clone()),
                WalEntry::TruncateThrough { through_seq } => {
                    while records
                        .front()
                        .is_some_and(|record| record.seq <= *through_seq)
                    {
                        let _ = records.pop_front();
                    }
                }
            }
        }
    }

    fn load_segment(
        segment_id: u64,
        path: &Path,
    ) -> Result<(WalSegmentMeta, Vec<WalEntry>), StreamError> {
        let file = File::open(path).map_err(|error| StreamError::wal_io("open", path, &error))?;
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut line = Vec::new();
        let mut line_number = 0usize;
        let mut valid_len = 0_u64;

        loop {
            line.clear();
            let bytes_read = reader
                .read_until(b'\n', &mut line)
                .map_err(|error| StreamError::wal_io("read_until", path, &error))?;
            if bytes_read == 0 {
                break;
            }

            if !line.ends_with(b"\n") {
                break;
            }

            line_number = line_number.saturating_add(1);
            valid_len = valid_len.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
            let payload = &line[..line.len().saturating_sub(1)];
            if payload.is_empty() {
                continue;
            }

            let entry = serde_json::from_slice::<WalEntry>(payload).map_err(|error| {
                StreamError::WalFormat {
                    path: path.display().to_string(),
                    line: line_number,
                    detail: error.to_string(),
                }
            })?;
            entries.push(entry);
        }

        let mut writable = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| StreamError::wal_io("open_write", path, &error))?;
        writable
            .set_len(valid_len)
            .map_err(|error| StreamError::wal_io("set_len", path, &error))?;
        writable
            .seek(SeekFrom::Start(valid_len))
            .map_err(|error| StreamError::wal_io("seek", path, &error))?;

        let mut segment = WalSegmentMeta {
            id: segment_id,
            path: path.to_path_buf(),
            bytes: valid_len,
            record_count: 0,
            first_seq: None,
            last_seq: None,
        };
        for entry in &entries {
            if let WalEntry::Append { record } = entry {
                segment.record_count = segment.record_count.saturating_add(1);
                segment.first_seq.get_or_insert(record.seq);
                segment.last_seq = Some(record.seq);
            }
        }

        Ok((segment, entries))
    }

    fn segment_paths(root_dir: &Path) -> Result<Vec<(u64, PathBuf)>, StreamError> {
        let mut paths = fs::read_dir(root_dir)
            .map_err(|error| StreamError::wal_io("read_dir", root_dir, &error))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                if !file_type.is_file() {
                    return None;
                }
                let file_name = entry.file_name();
                let file_name = file_name.to_str()?;
                let id = file_name
                    .strip_prefix("segment-")?
                    .strip_suffix(".wal")?
                    .parse::<u64>()
                    .ok()?;
                Some((id, entry.path()))
            })
            .collect::<Vec<_>>();
        paths.sort_unstable_by_key(|(id, _)| *id);
        Ok(paths)
    }

    fn current_segment_needs_rotation(&self, entry_len: u64) -> bool {
        self.segments.last().is_some_and(|segment| {
            segment.bytes != 0
                && segment.bytes.saturating_add(entry_len) > self.config.segment_max_bytes()
        })
    }

    fn ensure_segment_for_entry(&mut self, entry_len: u64) -> Result<usize, StreamError> {
        if self.segments.is_empty() || self.current_segment_needs_rotation(entry_len) {
            if self.current_segment_needs_rotation(entry_len)
                && self.config.fsync_policy() == WalFsyncPolicy::SegmentBoundary
            {
                self.sync_last_segment()?;
            }

            let segment_id = self.next_segment_id;
            self.next_segment_id = self.next_segment_id.saturating_add(1);
            let path = self
                .config
                .root_dir()
                .join(format!("segment-{segment_id:020}.wal"));
            let _file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|error| StreamError::wal_io("create_segment", &path, &error))?;
            self.segments.push(WalSegmentMeta {
                id: segment_id,
                path,
                bytes: 0,
                record_count: 0,
                first_seq: None,
                last_seq: None,
            });
        }

        Ok(self.segments.len().saturating_sub(1))
    }

    fn sync_last_segment(&self) -> Result<(), StreamError> {
        let Some(segment) = self.segments.last() else {
            return Ok(());
        };
        let file = OpenOptions::new()
            .write(true)
            .open(&segment.path)
            .map_err(|error| StreamError::wal_io("open_sync", &segment.path, &error))?;
        file.sync_all()
            .map_err(|error| StreamError::wal_io("sync_all", &segment.path, &error))
    }

    fn append_entry(&mut self, entry: &WalEntry) -> Result<u64, StreamError> {
        let mut encoded = serde_json::to_vec(entry).map_err(|error| StreamError::WalFormat {
            path: self.config.root_dir().display().to_string(),
            line: 0,
            detail: error.to_string(),
        })?;
        encoded.push(b'\n');
        let entry_len = u64::try_from(encoded.len()).map_err(|_| StreamError::PayloadTooLarge {
            bytes: encoded.len(),
        })?;
        let segment_index = self.ensure_segment_for_entry(entry_len)?;
        let segment_path = self.segments[segment_index].path.clone();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .map_err(|error| StreamError::wal_io("open_append", &segment_path, &error))?;
        file.write_all(&encoded)
            .map_err(|error| StreamError::wal_io("write_all", &segment_path, &error))?;
        if self.config.fsync_policy() == WalFsyncPolicy::Always {
            file.sync_all()
                .map_err(|error| StreamError::wal_io("sync_all", &segment_path, &error))?;
        }
        Ok(entry_len)
    }

    fn garbage_collect_segments(&mut self, through_seq: u64) -> Result<(), StreamError> {
        let mut obsolete_prefix_len = 0usize;
        while self.segments.len().saturating_sub(obsolete_prefix_len) > 1 {
            let segment = &self.segments[obsolete_prefix_len];
            let obsolete = segment
                .last_seq
                .is_none_or(|last_seq| last_seq <= through_seq);
            if !obsolete {
                break;
            }
            obsolete_prefix_len = obsolete_prefix_len.saturating_add(1);
        }

        if obsolete_prefix_len == 0 {
            return Ok(());
        }

        let obsolete = self
            .segments
            .drain(0..obsolete_prefix_len)
            .collect::<Vec<_>>();
        for segment in obsolete {
            fs::remove_file(&segment.path)
                .map_err(|error| StreamError::wal_io("remove_file", &segment.path, &error))?;
        }

        Ok(())
    }
}

impl StorageBackend for WalStorageBackend {
    fn append(&mut self, record: StreamRecord) -> Result<(), StreamError> {
        let entry = WalEntry::Append {
            record: record.clone(),
        };
        let bytes = self.append_entry(&entry)?;
        let Some(segment) = self.segments.last_mut() else {
            return Err(StreamError::WalFormat {
                path: self.config.root_dir().display().to_string(),
                line: 0,
                detail: "append completed without an active WAL segment".to_owned(),
            });
        };
        segment.record_append(&record, bytes);
        self.records.push_back(record);
        Ok(())
    }

    fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError> {
        Ok(self
            .records
            .iter()
            .find(|record| record.seq == seq)
            .cloned())
    }

    fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError> {
        Ok(self
            .records
            .iter()
            .filter(|record| seqs.contains(&record.seq))
            .cloned()
            .collect())
    }

    fn truncate_through(&mut self, through_seq: u64) -> Result<Vec<StreamRecord>, StreamError> {
        let mut removed = Vec::new();
        while self
            .records
            .front()
            .is_some_and(|record| record.seq <= through_seq)
        {
            if let Some(record) = self.records.pop_front() {
                removed.push(record);
            }
        }
        if removed.is_empty() {
            return Ok(removed);
        }

        let entry = WalEntry::TruncateThrough { through_seq };
        let bytes = self.append_entry(&entry)?;
        if let Some(segment) = self.segments.last_mut() {
            segment.note_control_entry(bytes);
        }
        self.garbage_collect_segments(through_seq)?;
        Ok(removed)
    }

    fn snapshot(&self) -> Result<StorageSnapshot, StreamError> {
        Ok(StorageSnapshot {
            records: self.records.iter().cloned().collect(),
        })
    }
}

/// Errors returned by the FABRIC stream state machine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// The stream name was empty after trimming.
    #[error("stream name must not be empty")]
    EmptyName,
    /// A captured payload length could not be represented in stream counters.
    #[error("payload length {bytes} does not fit in u64 stream accounting")]
    PayloadTooLarge {
        /// Length of the payload in bytes.
        bytes: usize,
    },
    /// The subject did not satisfy the configured capture policy.
    #[error("subject `{subject}` is outside stream capture policy `{filter}`")]
    SubjectNotCaptured {
        /// Subject rejected by the stream filter.
        subject: String,
        /// Canonical capture filter.
        filter: String,
    },
    /// New traffic is not accepted once the stream begins closing.
    #[error("stream `{name}` is not accepting new messages because it is {lifecycle:?}")]
    NotAcceptingAppends {
        /// Human-readable stream name.
        name: String,
        /// Current lifecycle state.
        lifecycle: StreamLifecycle,
    },
    /// A child-region registration attempted to point back to the owner region.
    #[error("child region `{child}` must differ from owner region `{owner}`")]
    ChildRegionMustDiffer {
        /// Owning region for the stream.
        owner: RegionId,
        /// Region that was rejected.
        child: RegionId,
    },
    /// The stream cannot finish closing because descendants or consumers remain.
    #[error(
        "stream `{name}` is not quiescent: consumers={consumers} mirrors={mirrors} sources={sources}"
    )]
    NotQuiescent {
        /// Human-readable stream name.
        name: String,
        /// Active consumer attachments.
        consumers: usize,
        /// Active mirror child regions.
        mirrors: usize,
        /// Active source child regions.
        sources: usize,
    },
    /// The configured WAL backend options are not internally consistent.
    #[error("wal config field `{field}` is invalid: {detail}")]
    InvalidWalConfig {
        /// Offending configuration field.
        field: &'static str,
        /// Human-readable failure reason.
        detail: String,
    },
    /// Filesystem access for the WAL backend failed.
    #[error("wal {operation} failed for `{path}`: {detail}")]
    WalIo {
        /// Operation attempted on the WAL.
        operation: &'static str,
        /// File or directory path.
        path: String,
        /// Human-readable failure reason.
        detail: String,
    },
    /// A WAL segment contained malformed durable data.
    #[error("wal format error in `{path}` at line {line}: {detail}")]
    WalFormat {
        /// Segment path that failed to decode.
        path: String,
        /// 1-based line number within the segment, or 0 for out-of-band format faults.
        line: usize,
        /// Human-readable parse error.
        detail: String,
    },
    /// A snapshot-based restore requires an empty WAL directory.
    #[error("wal directory `{path}` must be empty before snapshot restore")]
    WalAlreadyInitialized {
        /// WAL root directory that already contains data.
        path: String,
    },
    /// Recovered storage contents violate stream sequence invariants.
    #[error("recovered storage contains invalid sequence {current_seq} after {previous_seq:?}")]
    InvalidRecoveredSequence {
        /// Previous retained sequence, or `None` when validating the first record.
        previous_seq: Option<u64>,
        /// Sequence number that violated the retained ordering invariant.
        current_seq: u64,
    },
    /// A stream append permit was committed more than once.
    #[error("stream append permit for seq {seq} has already been committed")]
    PermitAlreadyCommitted {
        /// Sequence number of the already-committed permit.
        seq: u64,
    },
    /// A stream append permit was committed against the wrong stream.
    #[error(
        "stream append permit for `{permit_name}` ({permit_region:?}) cannot commit into `{stream_name}` ({stream_region:?})"
    )]
    PermitStreamMismatch {
        /// Stream name captured when the permit was reserved.
        permit_name: String,
        /// Region captured when the permit was reserved.
        permit_region: RegionId,
        /// Stream name used for the commit attempt.
        stream_name: String,
        /// Region used for the commit attempt.
        stream_region: RegionId,
    },
    /// The message is a duplicate within the configured dedup window.
    #[error("duplicate detected for subject `{subject}` (existing seq {existing_seq})")]
    DuplicateDetected {
        /// Subject of the duplicate message.
        subject: String,
        /// Sequence number of the previously stored message.
        existing_seq: u64,
    },
}

impl StreamError {
    fn wal_io(operation: &'static str, path: &Path, error: &std::io::Error) -> Self {
        Self::WalIo {
            operation,
            path: path.display().to_string(),
            detail: error.to_string(),
        }
    }
}

/// Two-phase append permit for stream storage.
///
/// Represents reserved append authority for a specific stream. The
/// concrete sequence number is assigned only when
/// [`Stream::commit_append`] durably appends the record so aborted or
/// dropped permits cannot create retained-sequence gaps.
#[derive(Debug)]
#[must_use = "a StreamAppendPermit must be committed or explicitly dropped"]
pub struct StreamAppendPermit {
    /// Stream name captured when the permit was reserved.
    stream_name: String,
    /// Region id captured when the permit was reserved.
    region_id: RegionId,
    /// Subject for the record.
    subject: Subject,
    /// Logical publish time for retention.
    published_at: Time,
    /// Sequence assigned when the permit is successfully committed.
    committed_seq: Option<u64>,
}

impl StreamAppendPermit {
    /// Explicitly abort the permit without committing.
    pub fn abort(self) {}

    /// Returns true if the permit has been committed.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.committed_seq.is_some()
    }

    /// Returns the committed sequence, if the permit has been consumed.
    #[must_use]
    pub fn committed_seq(&self) -> Option<u64> {
        self.committed_seq
    }

    /// Returns the validated subject bound to this permit.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Returns the logical publish time bound to this permit.
    #[must_use]
    pub fn published_at(&self) -> Time {
        self.published_at
    }
}

/// Region-owned durable stream state machine for the FABRIC lane.
#[derive(Debug)]
pub struct Stream<B: StorageBackend = InMemoryStorageBackend> {
    name: String,
    region_id: RegionId,
    config: StreamConfig,
    state: StreamState,
    storage: B,
    next_seq: u64,
    next_consumer_id: u64,
    consumer_ids: BTreeSet<u64>,
    mirror_regions: BTreeSet<RegionId>,
    source_regions: BTreeSet<RegionId>,
    /// Dedup index: (subject_str, payload_hash) → (published_at, seq).
    /// Used when `config.dedupe_window` is `Some`.
    dedup_index: BTreeMap<(String, u64), (Time, u64)>,
}

impl<B: StorageBackend> Stream<B> {
    /// Construct a new region-owned stream with an explicit storage backend.
    pub fn new(
        name: impl Into<String>,
        region_id: RegionId,
        created_at: Time,
        config: StreamConfig,
        storage: B,
    ) -> Result<Self, StreamError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(StreamError::EmptyName);
        }

        let storage_snapshot = storage.snapshot()?;
        validate_retained_records(storage_snapshot.records.iter())?;
        let msg_count = u64::try_from(storage_snapshot.records.len()).map_err(|_| {
            StreamError::PayloadTooLarge {
                bytes: storage_snapshot.records.len(),
            }
        })?;
        let byte_count = storage_snapshot
            .records
            .iter()
            .try_fold(0_u64, |acc, record| {
                record.payload_len().map(|len| acc.saturating_add(len))
            })?;
        let first_seq = storage_snapshot
            .records
            .first()
            .map_or(0, |record| record.seq);
        let last_seq = storage_snapshot
            .records
            .last()
            .map_or(0, |record| record.seq);

        Ok(Self {
            name,
            region_id,
            config,
            state: StreamState {
                msg_count,
                byte_count,
                first_seq,
                last_seq,
                consumer_count: 0,
                created_at,
                lifecycle: StreamLifecycle::Open,
            },
            storage,
            next_seq: last_seq.saturating_add(1).max(1),
            next_consumer_id: 1,
            consumer_ids: BTreeSet::new(),
            mirror_regions: BTreeSet::new(),
            source_regions: BTreeSet::new(),
            dedup_index: BTreeMap::new(),
        })
    }

    /// Return the human-readable stream name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the region that owns the stream.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Return the stream configuration.
    #[must_use]
    pub fn config(&self) -> &StreamConfig {
        &self.config
    }

    /// Return the current stream state.
    #[must_use]
    pub fn state(&self) -> &StreamState {
        &self.state
    }

    /// Check whether a (subject, payload) pair is a duplicate within
    /// the configured dedup window.  Returns `Ok(())` if the message
    /// is fresh or dedup is disabled.
    fn check_dedup(
        &mut self,
        subject: &Subject,
        payload: &[u8],
        now: Time,
    ) -> Result<(), StreamError> {
        let Some(window) = self.config.dedupe_window else {
            return Ok(());
        };

        // Evict expired entries.
        let window_nanos = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        self.dedup_index
            .retain(|_, (ts, _)| now.duration_since(*ts) < window_nanos);

        let key = (subject.as_str().to_owned(), Self::payload_hash(payload));
        if let Some((_ts, existing_seq)) = self.dedup_index.get(&key) {
            return Err(StreamError::DuplicateDetected {
                subject: subject.as_str().to_owned(),
                existing_seq: *existing_seq,
            });
        }

        Ok(())
    }

    /// Record a message in the dedup index after successful commit.
    fn record_dedup(&mut self, subject: &Subject, payload: &[u8], published_at: Time, seq: u64) {
        if self.config.dedupe_window.is_some() {
            let key = (subject.as_str().to_owned(), Self::payload_hash(payload));
            self.dedup_index.insert(key, (published_at, seq));
        }
    }

    /// Simple non-cryptographic hash of a payload for dedup keying.
    fn payload_hash(payload: &[u8]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = crate::util::DetHasher::default();
        payload.hash(&mut hasher);
        hasher.finish()
    }

    /// Append a captured record to the stream.
    pub fn append(
        &mut self,
        subject: Subject,
        payload: impl Into<Vec<u8>>,
        published_at: Time,
    ) -> Result<StreamRecord, StreamError> {
        let mut permit = self.reserve_append(subject, published_at)?;
        self.commit_append(&mut permit, payload)
    }

    /// Reserve an append slot without committing payload.
    ///
    /// Returns a [`StreamAppendPermit`] that the caller must either
    /// commit with a payload or [`abort`](StreamAppendPermit::abort).
    /// Dropping the permit without committing aborts cleanly and does not
    /// allocate a sequence number.
    pub fn reserve_append(
        &mut self,
        subject: Subject,
        published_at: Time,
    ) -> Result<StreamAppendPermit, StreamError> {
        self.ensure_accepting_appends()?;

        if !self.captures(&subject) {
            return Err(StreamError::SubjectNotCaptured {
                subject: subject.as_str().to_owned(),
                filter: self.config.subject_filter.as_str().to_owned(),
            });
        }

        Ok(StreamAppendPermit {
            stream_name: self.name.clone(),
            region_id: self.region_id,
            subject,
            published_at,
            committed_seq: None,
        })
    }

    /// Commit a previously reserved append permit by writing the record
    /// to storage and enforcing retention.
    pub fn commit_append(
        &mut self,
        permit: &mut StreamAppendPermit,
        payload: impl Into<Vec<u8>>,
    ) -> Result<StreamRecord, StreamError> {
        let wrong_stream_name = permit.stream_name != self.name;
        let wrong_region = permit.region_id != self.region_id;
        if wrong_stream_name || wrong_region {
            return Err(StreamError::PermitStreamMismatch {
                permit_name: permit.stream_name.clone(),
                permit_region: permit.region_id,
                stream_name: self.name.clone(),
                stream_region: self.region_id,
            });
        }
        if let Some(seq) = permit.committed_seq {
            return Err(StreamError::PermitAlreadyCommitted { seq });
        }
        self.ensure_accepting_appends()?;

        let payload = payload.into();
        self.check_dedup(&permit.subject, &payload, permit.published_at)?;

        let record = StreamRecord {
            seq: self.next_seq,
            subject: permit.subject.clone(),
            payload,
            published_at: permit.published_at,
        };
        let payload_len = record.payload_len()?;

        self.storage.append(record.clone())?;
        self.record_dedup(
            &record.subject,
            &record.payload,
            permit.published_at,
            record.seq,
        );
        self.next_seq = self.next_seq.saturating_add(1);
        permit.committed_seq = Some(record.seq);

        self.state.msg_count = self.state.msg_count.saturating_add(1);
        self.state.byte_count = self.state.byte_count.saturating_add(payload_len);
        if self.state.first_seq == 0 {
            self.state.first_seq = record.seq;
        }
        self.state.last_seq = record.seq;

        self.enforce_retention(permit.published_at)?;
        Ok(record)
    }

    /// Fetch a retained record by sequence number.
    pub fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError> {
        self.storage.get(seq)
    }

    /// Fetch retained records within the inclusive sequence range.
    pub fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError> {
        self.storage.range(seqs)
    }

    /// Register a mirror child region owned by the stream region.
    pub fn add_mirror_region(&mut self, region: RegionId) -> Result<(), StreamError> {
        self.ensure_child_region(region)?;
        self.mirror_regions.insert(region);
        Ok(())
    }

    /// Remove a previously registered mirror child region.
    #[must_use]
    pub fn remove_mirror_region(&mut self, region: RegionId) -> bool {
        self.mirror_regions.remove(&region)
    }

    /// Register a source child region owned by the stream region.
    pub fn add_source_region(&mut self, region: RegionId) -> Result<(), StreamError> {
        self.ensure_child_region(region)?;
        self.source_regions.insert(region);
        Ok(())
    }

    /// Remove a previously registered source child region.
    #[must_use]
    pub fn remove_source_region(&mut self, region: RegionId) -> bool {
        self.source_regions.remove(&region)
    }

    /// Attach a consumer and return its stable local attachment id.
    #[must_use]
    pub fn attach_consumer(&mut self) -> u64 {
        let consumer_id = self.next_consumer_id;
        self.next_consumer_id = self.next_consumer_id.saturating_add(1);
        self.consumer_ids.insert(consumer_id);
        self.state.consumer_count = self.consumer_ids.len();
        consumer_id
    }

    /// Detach a previously attached consumer.
    #[must_use]
    pub fn detach_consumer(&mut self, consumer_id: u64) -> bool {
        let removed = self.consumer_ids.remove(&consumer_id);
        self.state.consumer_count = self.consumer_ids.len();
        removed
    }

    /// Transition the stream into closing state.
    pub fn begin_close(&mut self) {
        if self.state.lifecycle == StreamLifecycle::Open {
            self.state.lifecycle = StreamLifecycle::Closing;
        }
    }

    /// Return true when all mirrors, sources, and consumers have drained.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.consumer_ids.is_empty()
            && self.mirror_regions.is_empty()
            && self.source_regions.is_empty()
    }

    /// Finish stream closure once quiescence is reached.
    pub fn close(&mut self) -> Result<(), StreamError> {
        self.begin_close();
        if !self.is_quiescent() {
            return Err(StreamError::NotQuiescent {
                name: self.name.clone(),
                consumers: self.consumer_ids.len(),
                mirrors: self.mirror_regions.len(),
                sources: self.source_regions.len(),
            });
        }
        self.state.lifecycle = StreamLifecycle::Closed;
        Ok(())
    }

    /// Snapshot the current stream state and retained records.
    pub fn snapshot(&self) -> Result<StreamSnapshot, StreamError> {
        Ok(StreamSnapshot {
            name: self.name.clone(),
            region_id: self.region_id,
            config: self.config.clone(),
            state: self.state.clone(),
            storage: self.storage.snapshot()?,
            consumer_ids: self.consumer_ids.iter().copied().collect(),
            mirror_regions: self.mirror_regions.iter().copied().collect(),
            source_regions: self.source_regions.iter().copied().collect(),
        })
    }

    fn captures(&self, subject: &Subject) -> bool {
        self.config.subject_filter.matches(subject)
            || (self.config.capture_policy == CapturePolicy::IncludeReplySubjects
                && subject.as_str().starts_with("_INBOX."))
    }

    fn ensure_accepting_appends(&self) -> Result<(), StreamError> {
        if self.state.lifecycle == StreamLifecycle::Open {
            Ok(())
        } else {
            Err(StreamError::NotAcceptingAppends {
                name: self.name.clone(),
                lifecycle: self.state.lifecycle,
            })
        }
    }

    fn ensure_child_region(&self, region: RegionId) -> Result<(), StreamError> {
        if region == self.region_id {
            Err(StreamError::ChildRegionMustDiffer {
                owner: self.region_id,
                child: region,
            })
        } else {
            Ok(())
        }
    }

    fn enforce_retention(&mut self, now: Time) -> Result<(), StreamError> {
        if self.config.retention != RetentionPolicy::Limits {
            return Ok(());
        }

        let mut repaired_desync = false;
        while self.state.msg_count > 0 {
            let over_msg_limit =
                self.config.max_msgs != 0 && self.state.msg_count > self.config.max_msgs;
            let over_byte_limit =
                self.config.max_bytes != 0 && self.state.byte_count > self.config.max_bytes;

            let max_age_nanos = self
                .config
                .max_age
                .map(|age| u64::try_from(age.as_nanos()).unwrap_or(u64::MAX));

            let mut oldest_published_at = None;
            if max_age_nanos.is_some() {
                if let Some(oldest) = self.storage.get(self.state.first_seq)? {
                    oldest_published_at = Some(oldest.published_at);
                } else if !repaired_desync {
                    // The incremental counters fell out of sync with storage.
                    // Rebuild from the authoritative snapshot and retry once
                    // instead of silently leaving the stream over budget.
                    self.resync_from_storage()?;
                    repaired_desync = true;
                    continue;
                } else {
                    break;
                }
            }

            let over_age_limit = match (max_age_nanos, oldest_published_at) {
                (Some(limit), Some(published_at)) => now.duration_since(published_at) > limit,
                _ => false,
            };

            if !(over_msg_limit || over_byte_limit || over_age_limit) {
                return Ok(());
            }

            let removed = self.storage.truncate_through(self.state.first_seq)?;
            if removed.is_empty() {
                if !repaired_desync {
                    self.resync_from_storage()?;
                    repaired_desync = true;
                    continue;
                }
                break;
            }
            repaired_desync = false;

            for record in removed {
                let payload_len = record.payload_len()?;
                self.state.msg_count = self.state.msg_count.saturating_sub(1);
                self.state.byte_count = self.state.byte_count.saturating_sub(payload_len);
                self.state.first_seq = record.seq.saturating_add(1);

                let key = (
                    record.subject.as_str().to_owned(),
                    Self::payload_hash(&record.payload),
                );
                if self
                    .dedup_index
                    .get(&key)
                    .is_some_and(|(_, existing_seq)| *existing_seq == record.seq)
                {
                    self.dedup_index.remove(&key);
                }
            }

            if self.state.msg_count == 0 {
                self.state.first_seq = 0;
                self.state.last_seq = 0;
            } else if self.state.first_seq > self.state.last_seq {
                self.state.first_seq = self.state.last_seq;
            }
        }
        Ok(())
    }

    fn rebuild_state_from_snapshot(
        &mut self,
        snapshot: &StorageSnapshot,
    ) -> Result<(), StreamError> {
        self.state.msg_count =
            u64::try_from(snapshot.records.len()).map_err(|_| StreamError::PayloadTooLarge {
                bytes: snapshot.records.len(),
            })?;
        self.state.byte_count = snapshot.records.iter().try_fold(0_u64, |acc, record| {
            record.payload_len().map(|len| acc.saturating_add(len))
        })?;
        self.state.first_seq = snapshot.records.first().map_or(0, |record| record.seq);
        self.state.last_seq = snapshot.records.last().map_or(0, |record| record.seq);
        self.state.consumer_count = self.consumer_ids.len();
        Ok(())
    }

    fn resync_from_storage(&mut self) -> Result<(), StreamError> {
        let snapshot = self.storage.snapshot()?;
        self.rebuild_state_from_snapshot(&snapshot)?;
        self.rebuild_dedup_index_from_storage_snapshot(&snapshot);
        Ok(())
    }

    fn rebuild_dedup_index_from_storage_snapshot(&mut self, snapshot: &StorageSnapshot) {
        self.dedup_index.clear();
        if self.config.dedupe_window.is_none() {
            return;
        }

        for record in &snapshot.records {
            self.record_dedup(
                &record.subject,
                &record.payload,
                record.published_at,
                record.seq,
            );
        }
    }

    fn restore_with_storage(
        snapshot: &StreamSnapshot,
        region_id: RegionId,
        storage: B,
    ) -> Result<Self, StreamError> {
        let mut restored = Self::new(
            snapshot.name.clone(),
            region_id,
            snapshot.state.created_at,
            snapshot.config.clone(),
            storage,
        )?;
        restored.rebuild_dedup_index_from_storage_snapshot(&snapshot.storage);

        match snapshot.state.lifecycle {
            StreamLifecycle::Open => {}
            StreamLifecycle::Closing => restored.begin_close(),
            StreamLifecycle::Closed => {
                restored.begin_close();
                restored.close()?;
            }
        }

        Ok(restored)
    }
}

impl Stream<InMemoryStorageBackend> {
    /// Restore a captured stream into a fresh region using in-memory storage.
    ///
    /// Live consumer attachments and child-region leases are intentionally not
    /// reactivated during restore; callers must re-establish those explicit
    /// relationships in the new environment.
    pub fn restore_from_snapshot(
        snapshot: &StreamSnapshot,
        region_id: RegionId,
    ) -> Result<Self, StreamError> {
        let storage = InMemoryStorageBackend::from_snapshot(&snapshot.storage)?;
        Self::restore_with_storage(snapshot, region_id, storage)
    }
}

impl Stream<WalStorageBackend> {
    /// Restore a captured stream into a fresh region backed by a new WAL root.
    ///
    /// Live consumer attachments and child-region leases are intentionally not
    /// reactivated during restore; callers must re-establish those explicit
    /// relationships in the new environment.
    pub fn restore_from_snapshot_wal(
        snapshot: &StreamSnapshot,
        region_id: RegionId,
        config: WalStorageConfig,
    ) -> Result<Self, StreamError> {
        let storage = WalStorageBackend::from_snapshot(config, &snapshot.storage)?;
        Self::restore_with_storage(snapshot, region_id, storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    fn stream_config(filter: &str) -> StreamConfig {
        StreamConfig {
            subject_filter: SubjectPattern::new(filter),
            ..StreamConfig::default()
        }
    }

    fn make_default_stream() -> Stream<InMemoryStorageBackend> {
        Stream::new(
            "test-stream",
            test_region(1),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("create test stream")
    }

    #[derive(Debug, Default)]
    struct TruncateSkipsOnceBackend {
        inner: InMemoryStorageBackend,
        skip_next_truncate: bool,
    }

    impl StorageBackend for TruncateSkipsOnceBackend {
        fn append(&mut self, record: StreamRecord) -> Result<(), StreamError> {
            self.inner.append(record)
        }

        fn get(&self, seq: u64) -> Result<Option<StreamRecord>, StreamError> {
            self.inner.get(seq)
        }

        fn range(&self, seqs: RangeInclusive<u64>) -> Result<Vec<StreamRecord>, StreamError> {
            self.inner.range(seqs)
        }

        fn truncate_through(&mut self, through_seq: u64) -> Result<Vec<StreamRecord>, StreamError> {
            if self.skip_next_truncate {
                self.skip_next_truncate = false;
                return Ok(Vec::new());
            }
            self.inner.truncate_through(through_seq)
        }

        fn snapshot(&self) -> Result<StorageSnapshot, StreamError> {
            self.inner.snapshot()
        }
    }

    #[test]
    fn stream_lifecycle_append_read_and_close() {
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::from_secs(5),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let first = stream
            .append(
                Subject::new("orders.created"),
                b"alpha".to_vec(),
                Time::from_secs(6),
            )
            .expect("append first");
        let second = stream
            .append(
                Subject::new("orders.updated"),
                b"beta".to_vec(),
                Time::from_secs(7),
            )
            .expect("append second");

        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        assert_eq!(stream.get(1).expect("get first"), Some(first));
        assert_eq!(stream.range(1..=2).expect("range").len(), 2);
        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 1);
        assert_eq!(stream.state().last_seq, 2);

        stream.begin_close();
        assert!(stream.is_quiescent());
        stream.close().expect("close");
        assert_eq!(stream.state().lifecycle, StreamLifecycle::Closed);
    }

    #[test]
    fn stream_rejects_subjects_outside_capture_policy() {
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let error = stream
            .append(
                Subject::new("payments.created"),
                b"wrong-subject".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("subject outside capture policy");

        assert_eq!(
            error,
            StreamError::SubjectNotCaptured {
                subject: "payments.created".to_owned(),
                filter: "orders.>".to_owned(),
            }
        );
        assert_eq!(stream.state().msg_count, 0);
    }

    #[test]
    fn reply_capture_policy_accepts_inbox_subjects() {
        let mut config = stream_config("orders.>");
        config.capture_policy = CapturePolicy::IncludeReplySubjects;
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let record = stream
            .append(
                Subject::new("_INBOX.orders.worker.1"),
                b"reply".to_vec(),
                Time::from_secs(1),
            )
            .expect("reply capture");

        assert_eq!(record.seq, 1);
        assert_eq!(stream.state().msg_count, 1);
    }

    #[test]
    fn limits_retention_prunes_oldest_records() {
        let mut config = stream_config("orders.>");
        config.max_msgs = 2;
        let mut stream = Stream::new(
            "orders",
            test_region(1),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"one".to_vec(),
                Time::from_secs(1),
            )
            .expect("append one");
        stream
            .append(
                Subject::new("orders.updated"),
                b"two".to_vec(),
                Time::from_secs(2),
            )
            .expect("append two");
        stream
            .append(
                Subject::new("orders.cancelled"),
                b"three".to_vec(),
                Time::from_secs(3),
            )
            .expect("append three");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 3);
        assert!(stream.get(1).expect("get first").is_none());
        assert!(stream.get(2).expect("get second").is_some());
        assert!(stream.get(3).expect("get third").is_some());
    }

    #[test]
    fn limits_retention_prunes_by_byte_budget() {
        let mut config = stream_config("orders.>");
        config.max_bytes = 7;
        let mut stream = Stream::new(
            "orders",
            test_region(2),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"four".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("orders.updated"),
                b"five!".to_vec(),
                Time::from_secs(2),
            )
            .expect("append second");

        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().byte_count, 5);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 2);
        assert!(stream.get(1).expect("get first").is_none());
        assert_eq!(
            stream
                .get(2)
                .expect("get second")
                .expect("retained second")
                .payload,
            b"five!".to_vec()
        );
    }

    #[test]
    fn limits_retention_prunes_only_after_age_boundary_is_exceeded() {
        let mut config = stream_config("orders.>");
        config.max_age = Some(Duration::from_secs(5));
        let mut stream = Stream::new(
            "orders",
            test_region(3),
            Time::ZERO,
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"first".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("orders.updated"),
                b"second".to_vec(),
                Time::from_secs(6),
            )
            .expect("append boundary");

        assert_eq!(stream.state().msg_count, 2);
        assert!(
            stream.get(1).expect("get first").is_some(),
            "age equal to limit should be retained"
        );

        stream
            .append(
                Subject::new("orders.cancelled"),
                b"third".to_vec(),
                Time::from_secs(7),
            )
            .expect("append past boundary");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 3);
        assert!(
            stream.get(1).expect("get first").is_none(),
            "age above limit should prune oldest"
        );
        assert!(stream.get(2).expect("get second").is_some());
        assert!(stream.get(3).expect("get third").is_some());
    }

    #[test]
    fn non_limits_retention_modes_preserve_records_even_with_limits_set() {
        for retention in [RetentionPolicy::WorkQueue, RetentionPolicy::Interest] {
            let mut config = stream_config("orders.>");
            config.retention = retention;
            config.max_msgs = 1;
            config.max_bytes = 1;
            config.max_age = Some(Duration::from_secs(1));
            let mut stream = Stream::new(
                "orders",
                test_region(4),
                Time::ZERO,
                config,
                InMemoryStorageBackend::default(),
            )
            .expect("stream");

            stream
                .append(
                    Subject::new("orders.created"),
                    b"first".to_vec(),
                    Time::from_secs(1),
                )
                .expect("append first");
            stream
                .append(
                    Subject::new("orders.updated"),
                    b"second".to_vec(),
                    Time::from_secs(10),
                )
                .expect("append second");

            assert_eq!(stream.state().msg_count, 2, "retention={retention:?}");
            assert_eq!(stream.state().first_seq, 1, "retention={retention:?}");
            assert_eq!(stream.state().last_seq, 2, "retention={retention:?}");
            assert!(
                stream.get(1).expect("get first").is_some(),
                "retention={retention:?}"
            );
            assert!(
                stream.get(2).expect("get second").is_some(),
                "retention={retention:?}"
            );
        }
    }

    #[test]
    fn stream_rejects_appends_after_begin_close_and_after_close() {
        let mut stream = Stream::new(
            "orders",
            test_region(5),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream.begin_close();
        let closing_error = stream
            .append(
                Subject::new("orders.created"),
                b"late".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("closing stream must reject append");
        assert_eq!(
            closing_error,
            StreamError::NotAcceptingAppends {
                name: "orders".to_owned(),
                lifecycle: StreamLifecycle::Closing,
            }
        );

        let mut closed_stream = Stream::new(
            "payments",
            test_region(6),
            Time::ZERO,
            stream_config("payments.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        closed_stream.close().expect("close");

        let closed_error = closed_stream
            .append(
                Subject::new("payments.created"),
                b"late".to_vec(),
                Time::from_secs(1),
            )
            .expect_err("closed stream must reject append");
        assert_eq!(
            closed_error,
            StreamError::NotAcceptingAppends {
                name: "payments".to_owned(),
                lifecycle: StreamLifecycle::Closed,
            }
        );
    }

    #[test]
    fn consumer_ids_are_monotonic_and_unknown_detach_is_ignored() {
        let mut stream = Stream::new(
            "orders",
            test_region(7),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let first = stream.attach_consumer();
        let second = stream.attach_consumer();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(stream.state().consumer_count, 2);
        assert!(!stream.detach_consumer(999));
        assert_eq!(stream.state().consumer_count, 2);
        assert!(stream.detach_consumer(first));
        assert_eq!(stream.state().consumer_count, 1);
        assert!(stream.detach_consumer(second));
        assert_eq!(stream.state().consumer_count, 0);
    }

    #[test]
    fn close_waits_for_child_regions_and_consumers_to_drain() {
        let mut stream = Stream::new(
            "orders",
            test_region(10),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(11))
            .expect("mirror region");
        stream
            .add_source_region(test_region(12))
            .expect("source region");

        let error = stream.close().expect_err("not quiescent");
        assert_eq!(
            error,
            StreamError::NotQuiescent {
                name: "orders".to_owned(),
                consumers: 1,
                mirrors: 1,
                sources: 1,
            }
        );

        assert!(stream.detach_consumer(consumer));
        assert!(stream.remove_mirror_region(test_region(11)));
        assert!(stream.remove_source_region(test_region(12)));
        assert!(stream.is_quiescent());
        stream.close().expect("close after drain");
        assert_eq!(stream.state().lifecycle, StreamLifecycle::Closed);
    }

    #[test]
    fn child_regions_must_differ_from_owner_region() {
        let mut stream = Stream::new(
            "orders",
            test_region(10),
            Time::ZERO,
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        let error = stream
            .add_mirror_region(test_region(10))
            .expect_err("owner region cannot be its own child");
        assert_eq!(
            error,
            StreamError::ChildRegionMustDiffer {
                owner: test_region(10),
                child: test_region(10),
            }
        );
    }

    #[test]
    fn snapshot_captures_state_storage_and_child_regions() {
        let mut stream = Stream::new(
            "orders",
            test_region(20),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");

        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        stream
            .add_mirror_region(test_region(21))
            .expect("mirror region");
        stream
            .add_source_region(test_region(22))
            .expect("source region");
        let consumer = stream.attach_consumer();

        let snapshot = stream.snapshot().expect("snapshot");
        assert_eq!(snapshot.name, "orders");
        assert_eq!(snapshot.region_id, test_region(20));
        assert_eq!(snapshot.state.msg_count, 1);
        assert_eq!(snapshot.storage.records.len(), 1);
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        assert_eq!(snapshot.mirror_regions, vec![test_region(21)]);
        assert_eq!(snapshot.source_regions, vec![test_region(22)]);

        assert!(stream.detach_consumer(consumer));
    }

    #[test]
    fn restore_from_snapshot_scrubs_live_attachments_but_preserves_records() {
        let mut stream = Stream::new(
            "orders",
            test_region(30),
            Time::from_secs(10),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");
        let consumer = stream.attach_consumer();
        stream
            .add_mirror_region(test_region(31))
            .expect("mirror region");
        stream
            .add_source_region(test_region(32))
            .expect("source region");

        let snapshot = stream.snapshot().expect("snapshot");
        let restored = Stream::restore_from_snapshot(&snapshot, test_region(40)).expect("restore");
        let restored_snapshot = restored.snapshot().expect("restored snapshot");

        assert_eq!(snapshot.storage, restored_snapshot.storage);
        assert_eq!(restored_snapshot.name, "orders");
        assert_eq!(restored_snapshot.region_id, test_region(40));
        assert_eq!(restored_snapshot.config, snapshot.config);
        assert_eq!(
            restored_snapshot.state.created_at,
            snapshot.state.created_at
        );
        assert_eq!(restored_snapshot.state.msg_count, snapshot.state.msg_count);
        assert_eq!(
            restored_snapshot.state.byte_count,
            snapshot.state.byte_count
        );
        assert_eq!(restored_snapshot.state.first_seq, snapshot.state.first_seq);
        assert_eq!(restored_snapshot.state.last_seq, snapshot.state.last_seq);
        assert_eq!(restored_snapshot.consumer_ids, Vec::<u64>::new());
        assert!(restored_snapshot.is_quiescent());
        assert_eq!(snapshot.consumer_ids, vec![consumer]);
        assert_eq!(snapshot.mirror_regions, vec![test_region(31)]);
        assert_eq!(snapshot.source_regions, vec![test_region(32)]);
    }

    #[test]
    fn restore_from_snapshot_rebuilds_dedup_index() {
        let mut config = stream_config("orders.>");
        config.dedupe_window = Some(Duration::from_secs(60));

        let mut stream = Stream::new(
            "orders",
            test_region(50),
            Time::from_secs(10),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("stream");
        stream
            .append(
                Subject::new("orders.created"),
                b"same-payload".to_vec(),
                Time::from_secs(11),
            )
            .expect("append");

        let snapshot = stream.snapshot().expect("snapshot");
        let mut restored =
            Stream::restore_from_snapshot(&snapshot, test_region(51)).expect("restore");
        let err = restored
            .append(
                Subject::new("orders.created"),
                b"same-payload".to_vec(),
                Time::from_secs(20),
            )
            .expect_err("duplicate within dedupe window must be rejected");

        assert_eq!(
            err,
            StreamError::DuplicateDetected {
                subject: "orders.created".to_owned(),
                existing_seq: 1,
            }
        );
    }

    fn temp_wal_dir(test_name: &str) -> PathBuf {
        let unique = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "asupersync-stream-wal-{test_name}-{nanos}-{unique}"
        ));
        fs::create_dir_all(&path).expect("create temp wal dir");
        path
    }

    fn wal_record(seq: u64, subject: &str, payload: &[u8], published_at: Time) -> StreamRecord {
        StreamRecord {
            seq,
            subject: Subject::new(subject),
            payload: payload.to_vec(),
            published_at,
        }
    }

    #[test]
    fn wal_backend_round_trips_records_after_reopen() {
        let dir = temp_wal_dir("round-trip");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let first = wal_record(1, "orders.created", b"alpha", Time::from_secs(1));
        let second = wal_record(2, "orders.updated", b"beta", Time::from_secs(2));

        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        backend.append(first.clone()).expect("append first");
        backend.append(second.clone()).expect("append second");
        assert_eq!(backend.segment_count(), 1);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert_eq!(reopened.get(1).expect("get first"), Some(first));
        assert_eq!(reopened.get(2).expect("get second"), Some(second));
        assert_eq!(reopened.snapshot().expect("snapshot").records.len(), 2);
    }

    #[test]
    fn wal_backend_rotates_segments_and_replays_truncation_markers() {
        let dir = temp_wal_dir("rotate-truncate");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");

        backend
            .append(wal_record(1, "orders.created", b"one", Time::from_secs(1)))
            .expect("append one");
        backend
            .append(wal_record(2, "orders.updated", b"two", Time::from_secs(2)))
            .expect("append two");
        backend
            .append(wal_record(
                3,
                "orders.cancelled",
                b"three",
                Time::from_secs(3),
            ))
            .expect("append three");

        assert_eq!(backend.segment_count(), 3);
        let removed = backend.truncate_through(2).expect("truncate through");
        assert_eq!(removed.len(), 2);
        assert_eq!(backend.segment_count(), 2);
        let segment_files = fs::read_dir(&dir)
            .expect("read wal dir")
            .filter_map(Result::ok)
            .count();
        assert_eq!(segment_files, 2);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert!(reopened.get(1).expect("get first").is_none());
        assert!(reopened.get(2).expect("get second").is_none());
        assert_eq!(
            reopened
                .get(3)
                .expect("get third")
                .expect("retained third")
                .payload,
            b"three".to_vec()
        );
    }

    #[test]
    fn wal_backend_truncates_torn_tail_during_recovery() {
        let dir = temp_wal_dir("torn-tail");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        let record = wal_record(1, "orders.created", b"alpha", Time::from_secs(1));
        backend.append(record.clone()).expect("append record");

        let segment_path = backend.segments[0].path.clone();
        let valid_len = fs::metadata(&segment_path).expect("segment metadata").len();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&segment_path)
            .expect("open append");
        file.write_all(br#"{"kind":"append","record":"torn"#)
            .expect("write torn tail");
        drop(file);

        let recovered = WalStorageBackend::open(config).expect("recover wal");
        let repaired_len = fs::metadata(&segment_path).expect("segment metadata").len();
        assert_eq!(repaired_len, valid_len);
        assert_eq!(recovered.get(1).expect("get first"), Some(record));
        assert_eq!(recovered.snapshot().expect("snapshot").records.len(), 1);
    }

    #[test]
    fn wal_backend_can_restore_from_snapshot() {
        let dir = temp_wal_dir("snapshot-restore");
        let config = WalStorageConfig::new(&dir, DeliveryClass::ForensicReplayable)
            .with_segment_max_bytes(1024);
        let snapshot = StorageSnapshot {
            records: vec![
                wal_record(1, "orders.created", b"alpha", Time::from_secs(1)),
                wal_record(2, "orders.updated", b"beta", Time::from_secs(2)),
            ],
        };

        let restored = WalStorageBackend::from_snapshot(config.clone(), &snapshot)
            .expect("restore from snapshot");
        assert_eq!(restored.snapshot().expect("snapshot"), snapshot);

        let reopened = WalStorageBackend::open(config).expect("reopen wal");
        assert_eq!(reopened.snapshot().expect("snapshot"), snapshot);
    }

    #[test]
    fn wal_backend_restore_rejects_non_empty_directory() {
        let dir = temp_wal_dir("restore-non-empty");
        fs::write(dir.join("stray.txt"), b"occupied").expect("write stray file");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);

        let error = WalStorageBackend::from_snapshot(config, &StorageSnapshot::default())
            .expect_err("non-empty wal directory must be rejected");
        assert_eq!(
            error,
            StreamError::WalAlreadyInitialized {
                path: dir.display().to_string(),
            }
        );
    }

    #[test]
    fn wal_backend_open_rejects_non_contiguous_recovered_records() {
        let dir = temp_wal_dir("open-gap");
        let segment_path = dir.join("segment-00000000000000000000.wal");
        let first = serde_json::to_string(&WalEntry::Append {
            record: wal_record(1, "orders.created", b"alpha", Time::from_secs(1)),
        })
        .expect("serialize first");
        let third = serde_json::to_string(&WalEntry::Append {
            record: wal_record(3, "orders.updated", b"beta", Time::from_secs(2)),
        })
        .expect("serialize third");
        fs::write(&segment_path, format!("{first}\n{third}\n")).expect("write wal segment");

        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let error =
            WalStorageBackend::open(config).expect_err("corrupted recovered wal must be rejected");
        assert_eq!(
            error,
            StreamError::InvalidRecoveredSequence {
                previous_seq: Some(1),
                current_seq: 3,
            }
        );
    }

    #[test]
    fn stream_rejects_recovered_storage_with_non_contiguous_sequences() {
        let storage = InMemoryStorageBackend {
            records: VecDeque::from([
                wal_record(2, "orders.created", b"alpha", Time::from_secs(1)),
                wal_record(4, "orders.updated", b"beta", Time::from_secs(2)),
            ]),
        };

        let error = Stream::new(
            "orders",
            test_region(31),
            Time::from_secs(10),
            stream_config("orders.>"),
            storage,
        )
        .expect_err("corrupted retained window must be rejected");
        assert_eq!(
            error,
            StreamError::InvalidRecoveredSequence {
                previous_seq: Some(2),
                current_seq: 4,
            }
        );
    }

    #[test]
    fn stream_new_rehydrates_state_from_recovered_wal_storage() {
        let dir = temp_wal_dir("stream-rehydrate");
        let config =
            WalStorageConfig::new(&dir, DeliveryClass::DurableOrdered).with_segment_max_bytes(1024);
        let mut backend = WalStorageBackend::open(config.clone()).expect("open wal");
        backend
            .append(wal_record(
                1,
                "orders.created",
                b"alpha",
                Time::from_secs(1),
            ))
            .expect("append first");
        backend
            .append(wal_record(2, "orders.updated", b"beta", Time::from_secs(2)))
            .expect("append second");

        let reopened_backend = WalStorageBackend::open(config).expect("reopen wal");
        let mut stream = Stream::new(
            "orders",
            test_region(30),
            Time::from_secs(10),
            stream_config("orders.>"),
            reopened_backend,
        )
        .expect("stream");

        assert_eq!(stream.state().msg_count, 2);
        assert_eq!(stream.state().first_seq, 1);
        assert_eq!(stream.state().last_seq, 2);
        let appended = stream
            .append(
                Subject::new("orders.cancelled"),
                b"gamma".to_vec(),
                Time::from_secs(11),
            )
            .expect("append third");
        assert_eq!(appended.seq, 3);
    }

    // ── Two-phase append tests ────────────────────────────────────

    #[test]
    fn reserve_then_commit_append() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let record = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect("commit");

        assert_eq!(record.seq, 1);
        assert_eq!(record.payload, b"payload".to_vec());
        assert!(permit.is_committed());
        assert_eq!(permit.committed_seq(), Some(1));
        assert_eq!(stream.state().msg_count, 1);
    }

    #[test]
    fn reserve_then_abort_leaves_stream_empty() {
        let mut stream = make_default_stream();
        let permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        permit.abort();
        assert_eq!(
            stream.state().msg_count,
            0,
            "aborted permit must not store anything"
        );
        let record = stream
            .append(
                Subject::new("orders.created"),
                b"after-abort".to_vec(),
                Time::from_secs(2),
            )
            .expect("append after abort");
        assert_eq!(
            record.seq, 1,
            "aborted permits must not burn sequence numbers"
        );
    }

    #[test]
    fn reserve_then_drop_leaves_stream_empty() {
        let mut stream = make_default_stream();
        {
            let _permit = stream
                .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
                .expect("reserve");
            // dropped without commit
        }
        assert_eq!(
            stream.state().msg_count,
            0,
            "dropped permit must not store anything"
        );
        let record = stream
            .append(
                Subject::new("orders.created"),
                b"after-drop".to_vec(),
                Time::from_secs(2),
            )
            .expect("append after drop");
        assert_eq!(
            record.seq, 1,
            "dropped permits must not burn sequence numbers"
        );
    }

    #[test]
    fn double_commit_returns_error() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let _ = stream
            .commit_append(&mut permit, b"first".to_vec())
            .expect("first commit");

        let err = stream
            .commit_append(&mut permit, b"second".to_vec())
            .expect_err("second commit must fail");

        assert!(
            matches!(err, StreamError::PermitAlreadyCommitted { seq: 1 }),
            "expected PermitAlreadyCommitted, got {err:?}"
        );
    }

    #[test]
    fn out_of_order_commits_assign_sequences_in_commit_order() {
        let mut stream = make_default_stream();

        let mut permit1 = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve 1");
        let mut permit2 = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(2))
            .expect("reserve 2");

        // Commit in reverse order. The storage log should remain contiguous and
        // ordered by durable commit, not by reservation timing.
        let r2 = stream
            .commit_append(&mut permit2, b"second".to_vec())
            .expect("commit 2");
        let r1 = stream
            .commit_append(&mut permit1, b"first".to_vec())
            .expect("commit 1");

        assert_eq!(r2.seq, 1);
        assert_eq!(r1.seq, 2);
        assert_eq!(permit2.committed_seq(), Some(1));
        assert_eq!(permit1.committed_seq(), Some(2));
        assert_eq!(
            stream.range(1..=2).expect("range"),
            vec![r2.clone(), r1.clone()],
            "retained storage must stay ordered by committed sequence"
        );

        let snapshot = stream.snapshot().expect("snapshot");
        let reopened = Stream::new(
            "test-stream",
            test_region(1),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend {
                records: snapshot.storage.records.into(),
            },
        )
        .expect("reopen from contiguous retained records");
        assert_eq!(reopened.state().first_seq, 1);
        assert_eq!(reopened.state().last_seq, 2);
    }

    // ── Dedup window tests ────────────────────────────────────────

    #[test]
    fn dedup_window_rejects_duplicate_within_window() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"unique".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        let err = stream
            .append(
                Subject::new("fabric.default"),
                b"unique".to_vec(),
                Time::from_secs(2),
            )
            .expect_err("duplicate must be rejected");

        assert!(
            matches!(err, StreamError::DuplicateDetected { .. }),
            "expected DuplicateDetected, got {err:?}"
        );
    }

    #[test]
    fn dedup_window_allows_same_payload_after_window_expires() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(10)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-expire-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        // 15 seconds later — outside the 10s window.
        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(16),
            )
            .expect("append after window expiry should succeed");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_window_forgets_records_truncated_by_retention() {
        let config = StreamConfig {
            retention: RetentionPolicy::Limits,
            max_msgs: 1,
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-retention-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"same".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");
        stream
            .append(
                Subject::new("fabric.default"),
                b"other".to_vec(),
                Time::from_secs(2),
            )
            .expect("second append triggers retention");

        assert!(
            stream.get(1).expect("get truncated first").is_none(),
            "retention should remove the first record from storage"
        );

        let third = stream
            .append(
                Subject::new("fabric.default"),
                b"same".to_vec(),
                Time::from_secs(3),
            )
            .expect("dedup must forget records truncated by retention");

        assert_eq!(third.seq, 3);
        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().last_seq, 3);
        assert!(
            stream.get(2).expect("get truncated second").is_none(),
            "max_msgs=1 should retain only the newest record"
        );
        assert_eq!(
            stream
                .get(3)
                .expect("get retained third")
                .map(|record| record.payload),
            Some(b"same".to_vec())
        );
    }

    #[test]
    fn retention_recovers_after_transient_noop_truncate() {
        let config = StreamConfig {
            retention: RetentionPolicy::Limits,
            max_msgs: 1,
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "retention-repair-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            TruncateSkipsOnceBackend {
                inner: InMemoryStorageBackend::default(),
                skip_next_truncate: true,
            },
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"first".to_vec(),
                Time::from_secs(1),
            )
            .expect("append first");
        stream
            .append(
                Subject::new("fabric.default"),
                b"second".to_vec(),
                Time::from_secs(2),
            )
            .expect("append second should recover after transient truncate no-op");

        assert_eq!(stream.state().msg_count, 1);
        assert_eq!(stream.state().first_seq, 2);
        assert_eq!(stream.state().last_seq, 2);
        assert!(stream.get(1).expect("first removed").is_none());
        assert_eq!(
            stream
                .get(2)
                .expect("second retained")
                .map(|record| record.payload),
            Some(b"second".to_vec())
        );
    }

    #[test]
    fn dedup_window_allows_different_payload_same_subject() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-diff-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data-1".to_vec(),
                Time::from_secs(1),
            )
            .expect("first append");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data-2".to_vec(),
                Time::from_secs(2),
            )
            .expect("different payload should not be a dup");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_disabled_by_default() {
        let mut stream = make_default_stream();

        stream
            .append(
                Subject::new("orders.created"),
                b"same".to_vec(),
                Time::from_secs(1),
            )
            .expect("first");
        stream
            .append(
                Subject::new("orders.created"),
                b"same".to_vec(),
                Time::from_secs(2),
            )
            .expect("second — dedup disabled by default");

        assert_eq!(stream.state().msg_count, 2);
    }

    #[test]
    fn dedup_works_with_reserve_commit_path() {
        let config = StreamConfig {
            dedupe_window: Some(Duration::from_secs(60)),
            ..StreamConfig::default()
        };
        let mut stream = Stream::new(
            "dedup-reserve-stream",
            test_region(1),
            Time::from_secs(0),
            config,
            InMemoryStorageBackend::default(),
        )
        .expect("create stream");

        stream
            .append(
                Subject::new("fabric.default"),
                b"data".to_vec(),
                Time::from_secs(1),
            )
            .expect("direct append");

        let mut permit = stream
            .reserve_append(Subject::new("fabric.default"), Time::from_secs(2))
            .expect("reserve");

        let err = stream
            .commit_append(&mut permit, b"data".to_vec())
            .expect_err("dedup should catch duplicate at commit time");

        assert!(
            matches!(err, StreamError::DuplicateDetected { .. }),
            "expected DuplicateDetected, got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "permit should not be marked committed on dedup failure"
        );

        let unique = stream
            .append(
                Subject::new("fabric.default"),
                b"fresh".to_vec(),
                Time::from_secs(3),
            )
            .expect("append after dedup failure");
        assert_eq!(
            unique.seq, 2,
            "failed commit must not burn a sequence number"
        );
    }

    #[test]
    fn reserved_permit_cannot_commit_after_stream_begins_closing() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        stream.begin_close();
        let err = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("closing stream must reject commit from prior permit");

        assert!(
            matches!(
                err,
                StreamError::NotAcceptingAppends {
                    ref name,
                    lifecycle: StreamLifecycle::Closing,
                } if name == "test-stream"
            ),
            "expected NotAcceptingAppends(Closing), got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "failed close-boundary commit must leave permit uncommitted"
        );
    }

    #[test]
    fn reserved_permit_cannot_commit_after_stream_closes() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        stream.close().expect("close");
        let err = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("closed stream must reject commit from prior permit");

        assert!(
            matches!(
                err,
                StreamError::NotAcceptingAppends {
                    ref name,
                    lifecycle: StreamLifecycle::Closed,
                } if name == "test-stream"
            ),
            "expected NotAcceptingAppends(Closed), got {err:?}"
        );
        assert!(
            !permit.is_committed(),
            "failed closed-stream commit must leave permit uncommitted"
        );
    }

    #[test]
    fn consumed_permit_still_reports_already_committed_after_stream_closes() {
        let mut stream = make_default_stream();
        let mut permit = stream
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve");

        let record = stream
            .commit_append(&mut permit, b"payload".to_vec())
            .expect("commit");
        assert_eq!(record.seq, 1);

        stream.close().expect("close");
        let err = stream
            .commit_append(&mut permit, b"again".to_vec())
            .expect_err("consumed permit must stay consumed after close");

        assert!(
            matches!(err, StreamError::PermitAlreadyCommitted { seq: 1 }),
            "expected PermitAlreadyCommitted, got {err:?}"
        );
    }

    #[test]
    fn permit_cannot_commit_into_different_stream() {
        let mut left = make_default_stream();
        let mut right = Stream::new(
            "other-stream",
            test_region(2),
            Time::from_secs(0),
            stream_config("orders.>"),
            InMemoryStorageBackend::default(),
        )
        .expect("create second stream");

        let mut permit = left
            .reserve_append(Subject::new("orders.created"), Time::from_secs(1))
            .expect("reserve on left");
        let err = right
            .commit_append(&mut permit, b"payload".to_vec())
            .expect_err("permit must stay bound to the reserving stream");

        assert!(
            matches!(
                err,
                StreamError::PermitStreamMismatch {
                    ref permit_name,
                    permit_region,
                    ref stream_name,
                    stream_region,
                } if permit_name == "test-stream"
                    && permit_region == test_region(1)
                    && stream_name == "other-stream"
                    && stream_region == test_region(2)
            ),
            "expected PermitStreamMismatch, got {err:?}"
        );
    }
}
