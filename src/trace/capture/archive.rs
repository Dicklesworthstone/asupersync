//! Portable native-capture archives, including outcome and cancellation evidence.
//!
//! Version 1 has an eight-byte magic, a little-endian u32 version, ten
//! little-endian u64 retention/count fields, six ordered sections of
//! length-prefixed canonical JSON records, and a SHA-256 digest of all preceding
//! bytes. It is separate from the existing TraceEvent and ReplayTrace formats.
//! The digest detects corruption; it does not authenticate the capture's origin.
//!
//! A decoded snapshot remains evidence supplied by its owner. Loading never
//! upgrades a partial capture or chooses a replay mode. The existing checked
//! projection methods still decide which replay claims its evidence supports.

use super::{ScheduleCaptureSnapshot, SchedulerEventContext, is_scheduler_observation};
use crate::trace::buffer::{
    CancellationPublication, CancellationPublicationSnapshot, TerminalCancellationState,
};
use crate::trace::event::{TRACE_EVENT_SCHEMA_VERSION, TraceData, TraceEvent, TraceEventKind};
use crate::types::{Budget, CancelReason, Severity, TaskId, Time};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPCAP\0";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 8 + 4 + 10 * 8;
const DIGEST_LEN: usize = 32;
// Match the maintained CancelReason wire bound before recursive serialization.
const MAX_REASON_DEPTH: usize = 64;

/// Explicit resource limits for encoding or opening a native-capture archive.
///
/// Counts are checked before reserving vectors. Record lengths are checked
/// before JSON deserialization, including all records capable of containing a
/// cancellation reason. These bound logical storage, not allocator overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleCaptureArchiveLimits {
    /// Maximum total encoded bytes, including framing and checksum.
    pub max_bytes: usize,
    /// Maximum canonical events, completion outcomes, and terminal witnesses
    /// in each of those three independently counted sections.
    pub max_events: usize,
    /// Maximum scheduler-context records.
    pub max_contexts: usize,
    /// Maximum caller-owned task identities.
    pub max_caller_tasks: usize,
    /// Maximum cancellation-publication spans.
    pub max_cancellation_spans: usize,
    /// Maximum JSON bytes in any one record, excluding its length prefix.
    pub max_record_bytes: usize,
    /// Additional maximum for a whole canonical event or terminal-witness
    /// record, enforced before parsing any cancellation reason it may contain.
    /// Applying this to every event avoids trusting an unparsed event tag.
    pub max_reason_bytes: usize,
}

impl ScheduleCaptureArchiveLimits {
    /// Set byte/record limits with every section initially bounded by max_events.
    /// Public count fields can then be tightened independently.
    #[must_use]
    pub const fn new(
        max_bytes: usize,
        max_events: usize,
        max_record_bytes: usize,
        max_reason_bytes: usize,
    ) -> Self {
        Self {
            max_bytes,
            max_events,
            max_contexts: max_events,
            max_caller_tasks: max_events,
            max_cancellation_spans: max_events,
            max_record_bytes,
            max_reason_bytes,
        }
    }
}

impl Default for ScheduleCaptureArchiveLimits {
    fn default() -> Self {
        Self::new(32 * 1024 * 1024, 65_536, 1024 * 1024, 64 * 1024)
    }
}

/// Corrupt, unsupported, or resource-inadmissible archive, without captured data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleCaptureArchiveError {
    /// A caller-selected bound was exceeded.
    #[error("native capture archive exceeded its {0} limit")]
    Limit(&'static str),
    /// Bounded storage could not be reserved.
    #[error("native capture archive allocation failed")]
    Allocation,
    /// The framing or a declared record was incomplete.
    #[error("native capture archive is truncated")]
    Truncated,
    /// The archive version is unsupported; no compatibility downgrade occurs.
    #[error("unsupported native capture archive version {0}")]
    Version(u32),
    /// The complete archive did not match its corruption-detection checksum.
    #[error("native capture archive checksum mismatch")]
    Integrity,
    /// Encoding, canonical form, or source-evidence joins were inconsistent.
    #[error("invalid native capture archive: {0}")]
    Invalid(&'static str),
    /// Caller-supplied I/O failed. The message never embeds provider diagnostics.
    #[error("native capture archive I/O failed: {0:?}")]
    Io(io::ErrorKind),
}

/// Owned archive bytes. Debug omits payloads and Drop zeroizes owned storage.
///
/// The archive can contain task identities, trace messages and full cancellation
/// reasons. A caller persisting as_bytes is responsible for access control and
/// the lifetime of that separate copy. Nothing is written automatically.
pub struct ScheduleCaptureArchive {
    bytes: Vec<u8>,
}

impl ScheduleCaptureArchive {
    /// Borrow the complete versioned representation for caller-owned storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for ScheduleCaptureArchive {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ScheduleCaptureArchive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScheduleCaptureArchive")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl Drop for ScheduleCaptureArchive {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContext {
    event_sequence: u64,
    worker_id: Option<u64>,
    worker_sequence: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBudget {
    deadline_ns: Option<u64>,
    poll_quota: u32,
    cost_quota: Option<u64>,
    priority: u8,
}

impl From<Budget> for WireBudget {
    fn from(budget: Budget) -> Self {
        Self {
            deadline_ns: budget.deadline.map(Time::as_nanos),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

impl From<WireBudget> for Budget {
    fn from(budget: WireBudget) -> Self {
        Self {
            deadline: budget.deadline_ns.map(Time::from_nanos),
            poll_quota: budget.poll_quota,
            cost_quota: budget.cost_quota,
            priority: budget.priority,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSpan {
    task: TaskId,
    start_sequence: u64,
    end_sequence: Option<u64>,
    request_sequence: Option<u64>,
    cleanup_budget: Option<WireBudget>,
    unsupported_mutation: bool,
}

impl From<&CancellationPublication> for WireSpan {
    fn from(span: &CancellationPublication) -> Self {
        Self {
            task: span.task,
            start_sequence: span.start_sequence,
            end_sequence: span.end_sequence,
            request_sequence: span.request_sequence,
            cleanup_budget: span.cleanup_budget.map(WireBudget::from),
            unsupported_mutation: span.unsupported_mutation,
        }
    }
}

impl From<WireSpan> for CancellationPublication {
    fn from(span: WireSpan) -> Self {
        Self {
            task: span.task,
            start_sequence: span.start_sequence,
            end_sequence: span.end_sequence,
            request_sequence: span.request_sequence,
            cleanup_budget: span.cleanup_budget.map(Budget::from),
            unsupported_mutation: span.unsupported_mutation,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTerminal<R> {
    requested: bool,
    reason: Option<R>,
}

#[derive(Clone, Copy)]
struct Header {
    total_events: u64,
    capacity: usize,
    worker_count: usize,
    dropped_spans: u64,
    counts: [usize; 6],
}

impl Header {
    fn from_snapshot(snapshot: &ScheduleCaptureSnapshot) -> Self {
        Self {
            total_events: snapshot.total_events,
            capacity: snapshot.capacity,
            worker_count: snapshot.worker_count,
            dropped_spans: snapshot.cancellation_publications.dropped_spans,
            counts: [
                snapshot.events.len(),
                snapshot.contexts.len(),
                snapshot.caller_tasks.len(),
                snapshot.completion_outcomes.len(),
                snapshot.cancellation_publications.spans.len(),
                snapshot.cancellation_publications.terminals.len(),
            ],
        }
    }

    fn admit(self, limits: ScheduleCaptureArchiveLimits) -> Result<(), ScheduleCaptureArchiveError> {
        for (count, maximum, resource) in [
            (self.counts[0], limits.max_events, "events"),
            (self.counts[1], limits.max_contexts, "contexts"),
            (self.counts[2], limits.max_caller_tasks, "caller tasks"),
            (self.counts[3], limits.max_events, "outcomes"),
            (self.counts[4], limits.max_cancellation_spans, "cancellation spans"),
            (self.counts[5], limits.max_events, "terminal witnesses"),
        ] {
            if count > maximum {
                return Err(ScheduleCaptureArchiveError::Limit(resource));
            }
            if count > self.capacity {
                return Err(ScheduleCaptureArchiveError::Invalid("count exceeds capture capacity"));
            }
        }
        if self.total_events < to_u64(self.counts[0])? {
            return Err(ScheduleCaptureArchiveError::Invalid("retention count exceeds insertion count"));
        }
        Ok(())
    }
}

/// Storage used for encoded data, including temporary canonicalization buffers.
/// Growth moves bytes deliberately, wiping the old buffer before releasing it.
struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
    resource: &'static str,
    failure: Option<ScheduleCaptureArchiveError>,
}

impl LimitedBytes {
    fn new(limit: usize, resource: &'static str) -> Self {
        Self { bytes: Vec::new(), limit, resource, failure: None }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), ScheduleCaptureArchiveError> {
        let needed = self.bytes.len().checked_add(bytes.len())
            .ok_or(ScheduleCaptureArchiveError::Limit(self.resource))?;
        if needed > self.limit {
            return Err(ScheduleCaptureArchiveError::Limit(self.resource));
        }
        if needed > self.bytes.capacity() {
            let capacity = needed.max(self.bytes.capacity().saturating_mul(2)).min(self.limit);
            let mut grown = Vec::new();
            grown.try_reserve_exact(capacity)
                .map_err(|_| ScheduleCaptureArchiveError::Allocation)?;
            grown.extend_from_slice(&self.bytes);
            self.bytes.zeroize();
            self.bytes = grown;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn integer(&mut self, value: u64) -> Result<(), ScheduleCaptureArchiveError> {
        self.append(&value.to_le_bytes())
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Write for LimitedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.append(bytes) {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.failure = Some(error);
                Err(io::Error::other("bounded native capture archive"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LimitedBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn to_u64(value: usize) -> Result<u64, ScheduleCaptureArchiveError> {
    u64::try_from(value).map_err(|_| ScheduleCaptureArchiveError::Limit("integer range"))
}

fn to_usize(value: u64) -> Result<usize, ScheduleCaptureArchiveError> {
    usize::try_from(value).map_err(|_| ScheduleCaptureArchiveError::Limit("integer range"))
}

fn reserve<T>(count: usize) -> Result<Vec<T>, ScheduleCaptureArchiveError> {
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| ScheduleCaptureArchiveError::Allocation)?;
    Ok(result)
}

fn json<T: Serialize>(
    record: &T,
    limit: usize,
    resource: &'static str,
) -> Result<LimitedBytes, ScheduleCaptureArchiveError> {
    let mut encoded = LimitedBytes::new(limit, resource);
    if serde_json::to_writer(&mut encoded, record).is_err() {
        return Err(encoded.failure.take().unwrap_or(
            ScheduleCaptureArchiveError::Invalid("record serialization failed"),
        ));
    }
    Ok(encoded)
}

fn write_record<T: Serialize>(
    output: &mut LimitedBytes,
    record: &T,
    limit: usize,
    resource: &'static str,
) -> Result<(), ScheduleCaptureArchiveError> {
    let encoded = json(record, limit, resource)?;
    output.integer(to_u64(encoded.bytes.len())?)?;
    output.append(&encoded.bytes)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ScheduleCaptureArchiveError> {
        let end = self.position.checked_add(count).ok_or(ScheduleCaptureArchiveError::Truncated)?;
        let bytes = self.bytes.get(self.position..end).ok_or(ScheduleCaptureArchiveError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn integer(&mut self) -> Result<u64, ScheduleCaptureArchiveError> {
        let bytes: [u8; 8] = self.take(8)?.try_into()
            .map_err(|_| ScheduleCaptureArchiveError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn count(&mut self) -> Result<usize, ScheduleCaptureArchiveError> {
        to_usize(self.integer()?)
    }

    fn record<T: Serialize + DeserializeOwned>(
        &mut self,
        limit: usize,
        resource: &'static str,
    ) -> Result<T, ScheduleCaptureArchiveError> {
        let size = self.count()?;
        if size > limit {
            return Err(ScheduleCaptureArchiveError::Limit(resource));
        }
        let bytes = self.take(size)?;
        let record = serde_json::from_slice::<T>(bytes)
            .map_err(|_| ScheduleCaptureArchiveError::Invalid("record JSON"))?;
        // Unknown/duplicate fields, alternative spellings, map-key repetition
        // and whitespace must never be silently normalized into new evidence.
        if json(&record, size, resource)?.bytes != bytes {
            return Err(ScheduleCaptureArchiveError::Invalid("noncanonical record"));
        }
        Ok(record)
    }
}

impl ScheduleCaptureSnapshot {
    /// Encode every retention, outcome and cancellation witness in a bounded,
    /// versioned archive. Partial snapshots remain partial diagnostic evidence.
    ///
    /// No replay mode is selected: reopening preserves the distinction between
    /// production_schedule and production_schedule_with_cancellation. The old
    /// ReplayTrace wire format is unchanged.
    ///
    /// # Example
    ///
    /// The owner supplies storage and later reconstructs the workload before
    /// passing the loaded schedule to the Lab strict driver.
    ///
    /// ```no_run
    /// use asupersync::trace::capture::{
    ///     ScheduleCaptureArchiveLimits, ScheduleCaptureSnapshot,
    /// };
    ///
    /// fn save_and_load(snapshot: &ScheduleCaptureSnapshot)
    ///     -> Result<(), Box<dyn std::error::Error>>
    /// {
    ///     let limits = ScheduleCaptureArchiveLimits::default();
    ///     let mut output = std::fs::File::create("failure.asucap")?;
    ///     snapshot.write_to(&mut output, limits)?;
    ///     let mut input = std::fs::File::open("failure.asucap")?;
    ///     let loaded = ScheduleCaptureSnapshot::read_from(&mut input, limits)?;
    ///     let schedule = loaded.production_schedule_with_cancellation()?;
    ///     // Reconstruct the same task bodies and explicit external inputs,
    ///     // then call LabRuntime::run_production_schedule_strict.
    ///     assert!(schedule.carries_outcomes());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Refuses resource limits, malformed metadata, or unencodable records.
    pub fn to_bytes(
        &self,
        limits: ScheduleCaptureArchiveLimits,
    ) -> Result<ScheduleCaptureArchive, ScheduleCaptureArchiveError> {
        let header = Header::from_snapshot(self);
        header.admit(limits)?;
        validate_structure(self)?;
        let mut output = LimitedBytes::new(limits.max_bytes, "bytes");
        output.append(MAGIC)?;
        output.append(&VERSION.to_le_bytes())?;
        for value in [
            header.total_events,
            to_u64(header.capacity)?,
            to_u64(header.worker_count)?,
            header.dropped_spans,
        ] {
            output.integer(value)?;
        }
        for count in header.counts {
            output.integer(to_u64(count)?)?;
        }
        let reason_limit = limits.max_record_bytes.min(limits.max_reason_bytes);
        for event in &self.events {
            write_record(&mut output, event, reason_limit, "reason-bearing record bytes")?;
        }
        for context in &self.contexts {
            let wire = WireContext {
                event_sequence: context.event_sequence,
                worker_id: context.worker_id.map(to_u64).transpose()?,
                worker_sequence: context.worker_sequence,
            };
            write_record(&mut output, &wire, limits.max_record_bytes, "record bytes")?;
        }
        for task in &self.caller_tasks {
            write_record(&mut output, task, limits.max_record_bytes, "record bytes")?;
        }
        for (&sequence, &severity) in &self.completion_outcomes {
            write_record(&mut output, &(sequence, severity.as_u8()), limits.max_record_bytes, "record bytes")?;
        }
        for span in &self.cancellation_publications.spans {
            write_record(&mut output, &WireSpan::from(span), limits.max_record_bytes, "record bytes")?;
        }
        for (sequence, terminal) in &self.cancellation_publications.terminals {
            let terminal = terminal.as_ref().map(|state| WireTerminal {
                requested: state.requested,
                reason: state.reason.as_ref(),
            });
            write_record(&mut output, &(sequence, terminal), reason_limit, "reason-bearing record bytes")?;
        }
        let checksum = Sha256::digest(&output.bytes);
        output.append(checksum.as_ref())?;
        Ok(ScheduleCaptureArchive { bytes: output.take() })
    }

    /// Open a complete archive after checking byte/count bounds and checksum.
    /// No user callback, runtime, entropy provider or live clock is consulted.
    ///
    /// All six sections are mandatory. Cancellation witnesses, including
    /// missing terminal witnesses and unsupported-publication markers, are
    /// retained; loading cannot silently downgrade them to a task-only receipt.
    /// The digest is corruption detection, not source authentication.
    ///
    /// # Errors
    /// Refuses unknown versions, corruption, noncanonical records, inconsistent
    /// metadata, exhausted storage limits and trailing or truncated data.
    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(
        bytes: &[u8],
        limits: ScheduleCaptureArchiveLimits,
    ) -> Result<Self, ScheduleCaptureArchiveError> {
        if bytes.len() > limits.max_bytes {
            return Err(ScheduleCaptureArchiveError::Limit("bytes"));
        }
        if bytes.len() < HEADER_LEN + DIGEST_LEN {
            return Err(ScheduleCaptureArchiveError::Truncated);
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(ScheduleCaptureArchiveError::Invalid("magic"));
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into()
            .map_err(|_| ScheduleCaptureArchiveError::Truncated)?);
        if version != VERSION {
            return Err(ScheduleCaptureArchiveError::Version(version));
        }
        let payload_len = bytes.len() - DIGEST_LEN;
        let checksum: [u8; DIGEST_LEN] = Sha256::digest(&bytes[..payload_len]).into();
        if checksum.as_slice() != &bytes[payload_len..] {
            return Err(ScheduleCaptureArchiveError::Integrity);
        }
        let mut decoder = Decoder { bytes: &bytes[..payload_len], position: 12 };
        let header = Header {
            total_events: decoder.integer()?,
            capacity: decoder.count()?,
            worker_count: decoder.count()?,
            dropped_spans: decoder.integer()?,
            counts: [
                decoder.count()?, decoder.count()?, decoder.count()?,
                decoder.count()?, decoder.count()?, decoder.count()?,
            ],
        };
        header.admit(limits)?;
        let records = header.counts.into_iter().try_fold(0_usize, |sum, count| sum.checked_add(count))
            .ok_or(ScheduleCaptureArchiveError::Limit("record count"))?;
        if records > (payload_len - HEADER_LEN) / 8 {
            return Err(ScheduleCaptureArchiveError::Truncated);
        }
        let [event_count, context_count, caller_count, outcome_count, span_count, terminal_count] =
            header.counts;
        let reason_limit = limits.max_record_bytes.min(limits.max_reason_bytes);
        let mut events = reserve(event_count)?;
        for _ in 0..event_count {
            events.push(decoder.record::<TraceEvent>(reason_limit, "reason-bearing record bytes")?);
        }
        let mut contexts = reserve(context_count)?;
        for _ in 0..context_count {
            let wire: WireContext = decoder.record(limits.max_record_bytes, "record bytes")?;
            contexts.push(SchedulerEventContext {
                event_sequence: wire.event_sequence,
                worker_id: wire.worker_id.map(to_usize).transpose()?,
                worker_sequence: wire.worker_sequence,
            });
        }
        let mut caller_tasks = reserve(caller_count)?;
        for _ in 0..caller_count {
            caller_tasks.push(decoder.record::<TaskId>(limits.max_record_bytes, "record bytes")?);
        }
        let mut completion_outcomes = BTreeMap::new();
        let mut last_outcome = None;
        for _ in 0..outcome_count {
            let (sequence, severity): (u64, u8) = decoder.record(limits.max_record_bytes, "record bytes")?;
            if last_outcome.is_some_and(|previous| sequence <= previous) {
                return Err(ScheduleCaptureArchiveError::Invalid("outcome order"));
            }
            let severity = Severity::from_u8(severity)
                .ok_or(ScheduleCaptureArchiveError::Invalid("outcome severity"))?;
            completion_outcomes.insert(sequence, severity);
            last_outcome = Some(sequence);
        }
        let mut spans = reserve(span_count)?;
        for _ in 0..span_count {
            let span: WireSpan = decoder.record(limits.max_record_bytes, "record bytes")?;
            spans.push(span.into());
        }
        let mut terminals = reserve(terminal_count)?;
        for _ in 0..terminal_count {
            let (sequence, terminal): (u64, Option<WireTerminal<CancelReason>>) =
                decoder.record(reason_limit, "reason-bearing record bytes")?;
            terminals.push((sequence, terminal.map(|state| TerminalCancellationState {
                requested: state.requested,
                reason: state.reason,
            })));
        }
        if decoder.position != payload_len {
            return Err(ScheduleCaptureArchiveError::Invalid("trailing bytes"));
        }
        let terminal_outcomes = terminal_outcomes(&events, &caller_tasks, &completion_outcomes);
        let snapshot = Self {
            events,
            contexts,
            caller_tasks,
            completion_outcomes,
            terminal_outcomes,
            cancellation_publications: CancellationPublicationSnapshot {
                spans, dropped_spans: header.dropped_spans, terminals,
            },
            total_events: header.total_events,
            capacity: header.capacity,
            worker_count: header.worker_count,
        };
        validate_structure(&snapshot)?;
        Ok(snapshot)
    }

    /// Encode through the same codec and write to a caller-supplied owner.
    /// A write error may leave a partial destination; no atomic replace, flush
    /// or durability promise is implied.
    ///
    /// # Errors
    /// Returns archive validation errors or the destination's error kind.
    pub fn write_to<W: Write + ?Sized>(
        &self,
        writer: &mut W,
        limits: ScheduleCaptureArchiveLimits,
    ) -> Result<(), ScheduleCaptureArchiveError> {
        let archive = self.to_bytes(limits)?;
        writer.write_all(archive.as_bytes()).map_err(|error| ScheduleCaptureArchiveError::Io(error.kind()))
    }

    /// Read one archive through EOF with a strict byte ceiling, then decode it.
    /// Reads at most one byte beyond the ceiling to detect an oversized input.
    /// The caller supplies any I/O timeout; a reader that never returns cannot
    /// be bounded by archive counters.
    ///
    /// # Errors
    /// Returns input I/O, archive validation, or allocation errors.
    pub fn read_from<R: Read + ?Sized>(
        reader: &mut R,
        limits: ScheduleCaptureArchiveLimits,
    ) -> Result<Self, ScheduleCaptureArchiveError> {
        let mut encoded = LimitedBytes::new(limits.max_bytes, "bytes");
        let mut chunk = [0_u8; 8192];
        loop {
            let remaining = limits.max_bytes - encoded.bytes.len();
            let requested = remaining.clamp(1, chunk.len());
            let read = loop {
                match reader.read(&mut chunk[..requested]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    result => break result,
                }
            };
            let count = match read {
                Ok(count) => count,
                Err(error) => {
                    chunk.zeroize();
                    return Err(ScheduleCaptureArchiveError::Io(error.kind()));
                }
            };
            if count == 0 {
                break;
            }
            let result = encoded.append(&chunk[..count]);
            chunk.zeroize();
            result?;
        }
        chunk.zeroize();
        Self::from_bytes(&encoded.bytes, limits)
    }
}

fn check_reason_depth(reason: &CancelReason) -> Result<(), ScheduleCaptureArchiveError> {
    let mut current = Some(reason);
    let mut depth = 0_usize;
    while let Some(reason) = current {
        depth += 1;
        if depth > MAX_REASON_DEPTH {
            return Err(ScheduleCaptureArchiveError::Limit("reason depth"));
        }
        current = reason.cause.as_deref();
    }
    Ok(())
}

fn terminal_outcomes(
    events: &[TraceEvent],
    caller_tasks: &[TaskId],
    outcomes: &BTreeMap<u64, Severity>,
) -> Vec<(TaskId, Severity)> {
    let mut terminal = events.iter().filter_map(|event| {
        if event.kind == TraceEventKind::Complete
            && let TraceData::Task { task, .. } = &event.data
            && caller_tasks.binary_search(task).is_err()
            && let Some(&outcome) = outcomes.get(&event.seq)
        {
            Some((*task, outcome))
        } else {
            None
        }
    }).collect::<Vec<_>>();
    // This field is derived, as in the recorder. Canonical source observations
    // and their witness sections are never sorted or deduplicated on import.
    terminal.sort_by_key(|(task, _)| *task);
    terminal
}

#[allow(clippy::too_many_lines)]
fn validate_structure(snapshot: &ScheduleCaptureSnapshot) -> Result<(), ScheduleCaptureArchiveError> {
    let invalid = ScheduleCaptureArchiveError::Invalid;
    if snapshot.events.windows(2).any(|pair| pair[0].seq >= pair[1].seq) {
        return Err(invalid("event order"));
    }
    if snapshot.events.iter().any(|event| event.version != TRACE_EVENT_SCHEMA_VERSION) {
        return Err(invalid("event schema version"));
    }
    if snapshot.contexts.windows(2).any(|pair| pair[0].event_sequence >= pair[1].event_sequence) {
        return Err(invalid("context order"));
    }
    if snapshot.caller_tasks.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid("caller identity order"));
    }
    let mut task_ids = BTreeSet::new();
    for event in &snapshot.events {
        let reason = match &event.data {
            TraceData::Cancel { reason, .. } | TraceData::RegionCancel { reason, .. } => Some(reason),
            TraceData::Down { reason: crate::monitor::DownReason::Cancelled(reason), .. }
            | TraceData::Exit { reason: crate::monitor::DownReason::Cancelled(reason), .. } => Some(reason),
            _ => None,
        };
        if let Some(reason) = reason {
            check_reason_depth(reason)?;
        }
        let payload_matches = match event.kind {
            TraceEventKind::Spawn | TraceEventKind::Complete | TraceEventKind::Poll
            | TraceEventKind::Schedule | TraceEventKind::Yield | TraceEventKind::Wake =>
                matches!(&event.data, TraceData::Task { .. }),
            TraceEventKind::CancelRequest | TraceEventKind::CancelAck =>
                matches!(&event.data, TraceData::Cancel { .. }),
            _ => true,
        };
        if !payload_matches {
            return Err(invalid("scheduler event payload"));
        }
        if let TraceData::Task { task, .. } = &event.data {
            task_ids.insert(*task);
            if event.kind == TraceEventKind::Poll && snapshot.caller_tasks.binary_search(task).is_ok() {
                return Err(invalid("caller identity has a worker poll"));
            }
        }
    }
    if snapshot.caller_tasks.iter().any(|task| !task_ids.contains(task)) {
        return Err(invalid("caller identity has no event"));
    }
    let event_at = |sequence| snapshot.events.binary_search_by_key(&sequence, |event| event.seq)
        .ok().map(|index| &snapshot.events[index]);
    let mut worker_sequences = BTreeMap::new();
    for context in &snapshot.contexts {
        let Some(event) = event_at(context.event_sequence) else {
            return Err(invalid("context has no canonical event"));
        };
        if !is_scheduler_observation(event.kind)
            || context.worker_id.is_some_and(|worker| worker >= snapshot.worker_count)
        {
            return Err(invalid("context worker or event category"));
        }
        if worker_sequences.insert(context.worker_id, context.worker_sequence)
            .is_some_and(|previous| previous >= context.worker_sequence)
        {
            return Err(invalid("worker sequence order"));
        }
    }
    for sequence in snapshot.completion_outcomes.keys() {
        if !event_at(*sequence).is_some_and(|event| {
            event.kind == TraceEventKind::Complete && matches!(&event.data, TraceData::Task { .. })
        }) {
            return Err(invalid("outcome has no completion"));
        }
    }
    if terminal_outcomes(&snapshot.events, &snapshot.caller_tasks, &snapshot.completion_outcomes)
        != snapshot.terminal_outcomes
    {
        return Err(invalid("derived terminal outcomes"));
    }
    let spans = &snapshot.cancellation_publications.spans;
    if spans.windows(2).any(|pair| pair[0].start_sequence >= pair[1].start_sequence) {
        return Err(invalid("publication order"));
    }
    for span in spans {
        if span.end_sequence.is_some_and(|end| end <= span.start_sequence)
            || span.request_sequence.is_some_and(|request| {
                request <= span.start_sequence || span.end_sequence.is_some_and(|end| request >= end)
            })
        {
            return Err(invalid("publication sequence bounds"));
        }
        if let Some(event) = span.request_sequence.and_then(event_at)
            && (event.kind != TraceEventKind::CancelRequest
                || !matches!(&event.data, TraceData::Cancel { task, .. } if *task == span.task))
        {
            return Err(invalid("publication request identity"));
        }
    }
    let terminals = &snapshot.cancellation_publications.terminals;
    if terminals.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(invalid("terminal witness order"));
    }
    for (sequence, terminal) in terminals {
        if let Some(reason) = terminal.as_ref().and_then(|state| state.reason.as_ref()) {
            check_reason_depth(reason)?;
        }
        // Retention follows insertion order, not sequence order: a deferred
        // admission can insert an old sequence after newer events are evicted.
        // Preserve any absent witness when eviction is reported, even inside
        // the retained sequence range. A retained match must still be Complete.
        match event_at(*sequence) {
            Some(event) if event.kind == TraceEventKind::Complete
                && matches!(&event.data, TraceData::Task { .. }) => {}
            None if snapshot.dropped_events() != 0 => {}
            _ => return Err(invalid("terminal witness has no completion")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
