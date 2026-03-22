//! Region-owned FABRIC stream state machines.

use super::class::DeliveryClass;
use super::subject::{Subject, SubjectPattern};
use crate::types::{RegionId, Time};
use std::collections::{BTreeSet, VecDeque};
use std::ops::RangeInclusive;
use std::time::Duration;
use thiserror::Error;

/// Retention semantics for a captured subject set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapturePolicy {
    /// Only explicitly configured subject-filter matches are captured.
    #[default]
    SubjectFilterOnly,
    /// Capture subject-filter matches plus reply-space inbox traffic.
    IncludeReplySubjects,
}

/// Static configuration for a region-owned FABRIC stream.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl StreamState {
    fn new(created_at: Time) -> Self {
        Self {
            msg_count: 0,
            byte_count: 0,
            first_seq: 0,
            last_seq: 0,
            consumer_count: 0,
            created_at,
            lifecycle: StreamLifecycle::Open,
        }
    }
}

/// Lifecycle state for a region-owned stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageSnapshot {
    /// Retained records in stream order.
    pub records: Vec<StreamRecord>,
}

/// A snapshot of stream configuration, state, storage, and child-region links.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Mirror child regions currently attached to the stream.
    pub mirror_regions: Vec<RegionId>,
    /// Source child regions currently attached to the stream.
    pub source_regions: Vec<RegionId>,
}

/// Storage backend used by a FABRIC stream.
pub trait StorageBackend {
    /// Append a new record to the backend.
    fn append(&mut self, record: StreamRecord);

    /// Fetch a record by exact sequence number.
    fn get(&self, seq: u64) -> Option<StreamRecord>;

    /// Fetch records in the inclusive sequence range.
    fn range(&self, seqs: RangeInclusive<u64>) -> Vec<StreamRecord>;

    /// Truncate all records up to and including `through_seq`.
    fn truncate_through(&mut self, through_seq: u64) -> Vec<StreamRecord>;

    /// Return a full snapshot of retained records.
    fn snapshot(&self) -> StorageSnapshot;
}

/// Deterministic in-memory storage backend for early FABRIC stream work.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InMemoryStorageBackend {
    records: VecDeque<StreamRecord>,
}

impl StorageBackend for InMemoryStorageBackend {
    fn append(&mut self, record: StreamRecord) {
        self.records.push_back(record);
    }

    fn get(&self, seq: u64) -> Option<StreamRecord> {
        self.records
            .iter()
            .find(|record| record.seq == seq)
            .cloned()
    }

    fn range(&self, seqs: RangeInclusive<u64>) -> Vec<StreamRecord> {
        self.records
            .iter()
            .filter(|record| seqs.contains(&record.seq))
            .cloned()
            .collect()
    }

    fn truncate_through(&mut self, through_seq: u64) -> Vec<StreamRecord> {
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
        removed
    }

    fn snapshot(&self) -> StorageSnapshot {
        StorageSnapshot {
            records: self.records.iter().cloned().collect(),
        }
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
}

/// Region-owned durable stream state machine for the FABRIC lane.
#[derive(Debug, Clone)]
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

        Ok(Self {
            name,
            region_id,
            config,
            state: StreamState::new(created_at),
            storage,
            next_seq: 1,
            next_consumer_id: 1,
            consumer_ids: BTreeSet::new(),
            mirror_regions: BTreeSet::new(),
            source_regions: BTreeSet::new(),
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

    /// Append a captured record to the stream.
    pub fn append(
        &mut self,
        subject: Subject,
        payload: impl Into<Vec<u8>>,
        published_at: Time,
    ) -> Result<StreamRecord, StreamError> {
        self.ensure_accepting_appends()?;

        if !self.captures(&subject) {
            return Err(StreamError::SubjectNotCaptured {
                subject: subject.as_str().to_owned(),
                filter: self.config.subject_filter.as_str().to_owned(),
            });
        }

        let record = StreamRecord {
            seq: self.next_seq,
            subject,
            payload: payload.into(),
            published_at,
        };
        let _ = record.payload_len()?;

        self.storage.append(record.clone());
        self.next_seq = self.next_seq.saturating_add(1);
        self.enforce_retention(published_at)?;
        self.rebuild_state()?;
        Ok(record)
    }

    /// Fetch a retained record by sequence number.
    #[must_use]
    pub fn get(&self, seq: u64) -> Option<StreamRecord> {
        self.storage.get(seq)
    }

    /// Fetch retained records within the inclusive sequence range.
    #[must_use]
    pub fn range(&self, seqs: RangeInclusive<u64>) -> Vec<StreamRecord> {
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
    #[must_use]
    pub fn snapshot(&self) -> StreamSnapshot {
        StreamSnapshot {
            name: self.name.clone(),
            region_id: self.region_id,
            config: self.config.clone(),
            state: self.state.clone(),
            storage: self.storage.snapshot(),
            mirror_regions: self.mirror_regions.iter().copied().collect(),
            source_regions: self.source_regions.iter().copied().collect(),
        }
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

        loop {
            let snapshot = self.storage.snapshot();
            let Some(oldest) = snapshot.records.first() else {
                return Ok(());
            };

            let msg_count = u64::try_from(snapshot.records.len()).map_err(|_| {
                StreamError::PayloadTooLarge {
                    bytes: snapshot.records.len(),
                }
            })?;
            let byte_count = snapshot.records.iter().try_fold(0_u64, |acc, record| {
                record.payload_len().map(|len| acc.saturating_add(len))
            })?;
            let max_age_nanos = self
                .config
                .max_age
                .map(|age| u64::try_from(age.as_nanos()).unwrap_or(u64::MAX));

            let over_msg_limit = self.config.max_msgs != 0 && msg_count > self.config.max_msgs;
            let over_byte_limit = self.config.max_bytes != 0 && byte_count > self.config.max_bytes;
            let over_age_limit =
                max_age_nanos.is_some_and(|limit| now.duration_since(oldest.published_at) > limit);

            if !(over_msg_limit || over_byte_limit || over_age_limit) {
                return Ok(());
            }

            let _removed = self.storage.truncate_through(oldest.seq);
        }
    }

    fn rebuild_state(&mut self) -> Result<(), StreamError> {
        let snapshot = self.storage.snapshot();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 1)
    }

    fn stream_config(filter: &str) -> StreamConfig {
        StreamConfig {
            subject_filter: SubjectPattern::new(filter),
            ..StreamConfig::default()
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
        assert_eq!(stream.get(1), Some(first));
        assert_eq!(stream.range(1..=2).len(), 2);
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
        assert!(stream.get(1).is_none());
        assert!(stream.get(2).is_some());
        assert!(stream.get(3).is_some());
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
        assert!(stream.get(1).is_none());
        assert_eq!(
            stream.get(2).expect("retained second").payload,
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
            stream.get(1).is_some(),
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
            stream.get(1).is_none(),
            "age above limit should prune oldest"
        );
        assert!(stream.get(2).is_some());
        assert!(stream.get(3).is_some());
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
            assert!(stream.get(1).is_some(), "retention={retention:?}");
            assert!(stream.get(2).is_some(), "retention={retention:?}");
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

        let snapshot = stream.snapshot();
        assert_eq!(snapshot.name, "orders");
        assert_eq!(snapshot.region_id, test_region(20));
        assert_eq!(snapshot.state.msg_count, 1);
        assert_eq!(snapshot.storage.records.len(), 1);
        assert_eq!(snapshot.mirror_regions, vec![test_region(21)]);
        assert_eq!(snapshot.source_regions, vec![test_region(22)]);

        assert!(stream.detach_consumer(consumer));
    }
}
