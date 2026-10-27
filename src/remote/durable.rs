//! Persistent reservations and terminal outcomes for one named computation.
//!
//! A reservation is synced before a handler may execute, and a terminal outcome
//! is synced before it is returned. A process restart can replay a completed
//! outcome; an unresolved reservation remains in doubt indefinitely. Arbitrary
//! handler effects cannot be atomically committed with this journal, so this is
//! not an exactly-once execution protocol or automatic retry of uncertain work.
//! An explicit reconciliation permit lets a trusted application persist an
//! independently established terminal result for a pending request. It never
//! authorizes another execution or discovers external effects automatically.
//!
//! The caller supplies a regular read/write file, its access policy and durable
//! directory linkage. This module retains an exclusive lock and never opens a
//! path, truncates, repairs, deletes or compacts the file. Do not retain cloned
//! handles or permit writers that ignore the lock. Authentication is not
//! encryption or an external rollback witness: replacing a file with an older
//! authenticated prefix requires a separately retained head to detect.
//!
//! Every file operation is synchronous and belongs on a blocking worker. The
//! caller also supplies trusted milliseconds in one consistent epoch. No clock
//! or entropy authority is acquired here. Reopening restores the last persisted
//! timestamp; a later timestamp observed only by a read or refused call is an
//! in-process floor. The caller's clock must preserve its epoch across restart.

use super::{IdempotencyKey, NodeId, RemoteOutcome, RemoteServiceWireOutcome};
use crate::distributed::{ComputationRegistryFingerprint, ComputationSchemaRegistry, HasSchema};
use crate::security::{AuthKey, AuthenticationTag};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASUPRDJ\0";
const HEADER_DOMAIN: &[u8] = b"asupersync.remote-dedup.header.v1";
const LENGTH_DOMAIN: &[u8] = b"asupersync.remote-dedup.length.v1";
const RECORD_DOMAIN: &[u8] = b"asupersync.remote-dedup.record.v1";
const INPUT_DOMAIN: &[u8] = b"asupersync.remote-dedup.input.v1";
const TAG_BYTES: usize = 32;
const PREFIX_BYTES: usize = 8 + TAG_BYTES;
// Sequence, previous tag, clock, kind, peer-length, and idempotency key.
const COMMON_BYTES: usize = 8 + TAG_BYTES + 8 + 1 + 1 + 16;
const RESERVATION_BYTES: usize = 8 + 32;
const TERMINAL_BYTES: usize = 8 + 8 + 8;
const RESERVE: u8 = 0;
const COMPLETE: u8 = 1;

/// Immutable storage and admission limits, authenticated in the journal header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableRemoteLimits {
    /// Simultaneously retained pending and unexpired terminal keys.
    pub max_entries: usize,
    /// Retained keys belonging to any one authenticated peer.
    pub max_peer_entries: usize,
    /// Input bytes hashed before admitting a reservation. Raw inputs are not retained.
    pub max_input_bytes: usize,
    /// Maximum encoded terminal JSON bytes, reserved for every pending key.
    pub max_outcome_bytes: usize,
    /// Cached JSON allocation capacity plus the full outcome allowance for every pending key.
    ///
    /// Index metadata is separately bounded by `max_entries` and peer labels of
    /// at most 255 bytes. Record buffers, decoded and returned outcomes, and
    /// caller-owned reservation tokens are not part of this payload counter.
    pub max_retained_bytes: usize,
    /// Complete file, including header, framing and any incomplete tail.
    pub max_journal_bytes: u64,
    /// Positive terminal retention from completion time, in trusted epoch milliseconds.
    /// Pending reservations never expire.
    pub retention_ms: u64,
}

/// Append posture after opening or attempting a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRemoteJournalStatus {
    /// The complete authenticated prefix is synced and may accept bounded writes.
    Writable,
    /// An incomplete trailing record is preserved; only exact terminal replay is allowed.
    ReadOnlyTail,
    /// A write, sync or external-length check was uncertain; reopen before use.
    Poisoned,
}

/// Payload-free persistence and adapter failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DurableRemoteError {
    /// An invocation or a live reservation/reconciliation permit still owns
    /// this journal instance.
    #[error("durable remote computation is busy")]
    Busy,
    /// The caller lacks a required runtime or blocking-pool capability.
    #[error("durable remote computation is unavailable")]
    Unavailable,
    /// A reservation has no durable outcome; execution may already have happened.
    #[error("durable remote request is in doubt; automatic re-execution is refused")]
    InDoubt,
    /// An unexpired key belongs to different input bytes.
    #[error("durable remote idempotency key conflicts with its retained input")]
    Conflict,
    /// The trusted clock moved behind this owner's last observed/persisted timestamp.
    #[error("durable remote clock regressed")]
    ClockRegression,
    /// A checked size, time or sequence overflowed or exceeded an explicit bound.
    #[error("durable remote journal limit exceeded")]
    Limit,
    /// A token belongs to another journal instance or no longer names a pending entry.
    #[error("invalid durable remote reservation")]
    InvalidReservation,
    /// Computation, schema, application version or immutable limits do not match.
    #[error("invalid durable remote journal configuration")]
    Configuration,
    /// Complete framing, sequence or record semantics were invalid.
    #[error("invalid durable remote journal format")]
    Format,
    /// A journal header, length prefix or complete record failed authentication.
    #[error("durable remote journal authentication failed")]
    Authentication,
    /// A bounded allocation could not be satisfied.
    #[error("durable remote journal allocation failed")]
    Allocation,
    /// A handler outcome cannot round-trip through the existing strict wire codec.
    #[error("durable remote outcome encoding failed")]
    OutcomeEncoding,
    /// An I/O error is not evidence that an attempted append rolled back.
    #[error("durable remote journal I/O failed; an append may have committed")]
    Io(#[source] io::Error),
    /// Another owner holds an exclusive file lock.
    #[error("durable remote journal is locked")]
    Locked,
    /// The supplied file must be regular.
    #[error("durable remote journal requires a regular file")]
    NotRegular,
    /// Creation never overwrites existing data.
    #[error("durable remote journal creation requires an empty file")]
    NotEmpty,
    /// Another writer changed the file length outside its exclusive owner.
    #[error("durable remote journal changed outside its owner")]
    Changed,
    /// The journal cannot perform the requested mutation in its current posture.
    #[error("durable remote journal is not writable: {0:?}")]
    NotWritable(DurableRemoteJournalStatus),
}

impl From<io::Error> for DurableRemoteError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// One synced permission to execute. Dropping it leaves the key in doubt.
///
/// Tokens are neither cloneable nor recoverable from disk. A token from another
/// journal, including a reopened instance of the same file, cannot complete an
/// operation in this owner. It grants no authority to replay handler effects.
pub struct DurableRemoteReservation {
    instance: Arc<()>,
    peer: NodeId,
    key: IdempotencyKey,
    sequence: u64,
}

impl fmt::Debug for DurableRemoteReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRemoteReservation").finish_non_exhaustive()
    }
}

/// Admission either authorizes one execution or returns a retained terminal result.
#[derive(Debug)]
pub enum DurableRemoteAdmission {
    /// The reservation and its worst-case completion capacity are durable.
    Execute(DurableRemoteReservation),
    /// Exact input matched an unexpired terminal outcome; no execution is needed.
    Replay(RemoteOutcome),
}

/// A pending request may be reconciled, or its already saved result replayed.
/// This decision never grants permission to execute the original handler.
#[derive(Debug)]
pub enum DurableRemoteReconciliation {
    /// Persist only a terminal result independently established by the caller.
    Pending(DurableRemoteReconciliationPermit),
    /// The exact request already has a retained terminal outcome.
    Replay(RemoteOutcome),
}

/// Single-use permission to record a known outcome for an uncertain request.
///
/// Binds the current journal instance, application version, schemas, peer, key,
/// input digest and reservation sequence. It is distinct from execution
/// authority. Dropping it changes no durable state and leaves the original
/// request in doubt. Reopening the journal invalidates outstanding permits.
pub struct DurableRemoteReconciliationPermit {
    reservation: DurableRemoteReservation,
    input_len: u64,
    digest: [u8; 32],
    schema: ComputationRegistryFingerprint,
    application_version: [u8; 32],
}

impl fmt::Debug for DurableRemoteReconciliationPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRemoteReconciliationPermit").finish_non_exhaustive()
    }
}

/// Exclusive journal for a single registered computation, schema and application version.
///
/// Pending entries reserve both their full encoded outcome allowance and their
/// maximum terminal record on disk before `Execute` is returned. Later requests
/// cannot consume that completion capacity. Terminal expiry frees retained
/// memory and key admission, but append-only disk bytes are never reclaimed.
/// A read-only incomplete tail preserves exact terminal replay; complete corrupt
/// records fail the entire open. Poisoned owners refuse even cached replay.
pub struct DurableRemoteJournal {
    core: Journal<File>,
}

impl fmt::Debug for DurableRemoteJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRemoteJournal")
            .field("records", &self.records())
            .field("committed_bytes", &self.committed_bytes())
            .field("retained_entries", &self.retained_entries())
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl DurableRemoteJournal {
    /// Sync a new authenticated header in an empty caller-owned regular file.
    /// The caller must durably link the file before exposing the service.
    pub fn create<I: HasSchema, O: HasSchema>(
        file: File, computation: impl Into<String>, application_version: [u8; 32],
        journal_key: AuthKey, limits: DurableRemoteLimits,
    ) -> Result<Self, DurableRemoteError> {
        let config = Config::new::<I, O>(computation.into(), application_version, journal_key, limits)?;
        lock(&file)?;
        Ok(Self { core: Journal::create(file, config)? })
    }

    /// Authenticate and replay every bounded complete record, then sync before
    /// exposing outcomes. Provisioning must match the original header exactly.
    pub fn open<I: HasSchema, O: HasSchema>(
        file: File, computation: impl Into<String>, application_version: [u8; 32],
        journal_key: AuthKey, limits: DurableRemoteLimits,
    ) -> Result<Self, DurableRemoteError> {
        let config = Config::new::<I, O>(computation.into(), application_version, journal_key, limits)?;
        lock(&file)?;
        Ok(Self { core: Journal::open(file, config)? })
    }

    /// Immutable registered computation name.
    #[must_use]
    pub fn computation(&self) -> &str { &self.core.config.computation }
    /// Full fingerprint of this computation's name and canonical input/output schemas.
    #[must_use]
    pub fn schema_fingerprint(&self) -> ComputationRegistryFingerprint { self.core.config.schema }
    /// Header-bound limits, unchanged across all reopenings.
    #[must_use]
    pub fn limits(&self) -> DurableRemoteLimits { self.core.config.limits }
    /// Current append posture without a file operation.
    #[must_use]
    pub fn status(&self) -> DurableRemoteJournalStatus { self.core.status }
    /// End of the authenticated synced prefix, excluding an incomplete tail.
    #[must_use]
    pub fn committed_bytes(&self) -> u64 { self.core.offset }
    /// Persisted reservation and terminal records; replay does not append.
    #[must_use]
    pub fn records(&self) -> u64 { self.core.sequence }
    /// Pending and unexpired terminal entries as of the last observed timestamp.
    #[must_use]
    pub fn retained_entries(&self) -> usize { self.core.entries.len() }

    /// Reserve before executing, or replay an exact retained outcome.
    ///
    /// `peer` is local authority; network adapters must obtain it from the
    /// certificate-bound invocation. Inputs are length/domain-bound SHA-256
    /// digests, not retained plaintext. An unresolved key never expires, even
    /// after restart. Zero capacities refuse before any reservation is written.
    pub fn admit(
        &mut self, peer: &NodeId, key: IdempotencyKey, input: &[u8], now_millis: u64,
    ) -> Result<DurableRemoteAdmission, DurableRemoteError> {
        self.core.admit(peer, key, input, now_millis)
    }

    /// Sync the exact terminal outcome before publishing it or permitting replay.
    ///
    /// A failed/oversized completion leaves its consumed reservation in doubt.
    /// Write/sync uncertainty additionally poisons this owner. Neither case
    /// authorizes repeating the handler; reopening may recover a complete write.
    pub fn complete(
        &mut self, reservation: DurableRemoteReservation, outcome: RemoteOutcome, now_millis: u64,
    ) -> Result<RemoteOutcome, DurableRemoteError> {
        self.core.complete(reservation, outcome, now_millis)
    }

    /// Inspect an exact uncertain request before application-led reconciliation.
    ///
    /// Missing or expired entries refuse `InvalidReservation`; this never creates
    /// a reservation. A matching terminal result is returned unchanged. A pending
    /// request requires a writable journal and no live reservation or reconciliation
    /// permits from this journal instance. `Busy` is conservative across all keys.
    ///
    /// The caller must fence or drain the original external operation, then
    /// establish its actual result from authoritative application state. Dropping
    /// an execution token alone does not prove that external work has stopped.
    /// This API does not retry the operation, infer its result, or establish
    /// cross-system exactly-once effects. `peer` is trusted local authority,
    /// subject to the same authentication requirement as [`Self::admit`].
    pub fn prepare_reconciliation(
        &mut self, peer: &NodeId, key: IdempotencyKey, input: &[u8], now_millis: u64,
    ) -> Result<DurableRemoteReconciliation, DurableRemoteError> {
        self.core.prepare_reconciliation(peer, key, input, now_millis)
    }

    /// Sync an independently established result without running the original work.
    ///
    /// The permit is consumed even on refusal. A write/sync failure keeps the
    /// journal's existing poison/reopen rules; an oversized or invalid outcome
    /// leaves the original pending fence intact. This uses the unchanged terminal
    /// record format, so ordinary admission replays the reconciled result after
    /// restart. The retention window begins at this durable completion.
    pub fn complete_reconciliation(
        &mut self, permit: DurableRemoteReconciliationPermit,
        outcome: RemoteOutcome, now_millis: u64,
    ) -> Result<RemoteOutcome, DurableRemoteError> {
        self.core.complete_reconciliation(permit, outcome, now_millis)
    }
}

struct Config {
    computation: String,
    schema: ComputationRegistryFingerprint,
    application_version: [u8; 32],
    key: AuthKey,
    limits: DurableRemoteLimits,
}

impl Config {
    fn new<I: HasSchema, O: HasSchema>(
        computation: String, application_version: [u8; 32], key: AuthKey, limits: DurableRemoteLimits,
    ) -> Result<Self, DurableRemoteError> {
        if !valid_label(&computation) || limits.retention_ms == 0 {
            return Err(DurableRemoteError::Configuration);
        }
        let mut registry = ComputationSchemaRegistry::new();
        registry.register_typed::<I, O>(computation.clone()).map_err(|_| DurableRemoteError::Configuration)?;
        let config = Self { computation, schema: registry.fingerprint(), application_version, key, limits };
        let _ = config.max_body_bytes()?;
        Ok(config)
    }

    fn max_body_bytes(&self) -> Result<usize, DurableRemoteError> {
        add(add(COMMON_BYTES, 255)?, RESERVATION_BYTES.max(add(TERMINAL_BYTES, self.limits.max_outcome_bytes)?))
    }

    fn header(&self) -> Result<Zeroizing<Vec<u8>>, DurableRemoteError> {
        let size = add(165, self.computation.len())?;
        if size64(size)? > self.limits.max_journal_bytes { return Err(DurableRemoteError::Limit); }
        let mut bytes = buffer(size)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(self.computation.len() as u8);
        bytes.extend_from_slice(self.computation.as_bytes());
        bytes.extend_from_slice(self.schema.as_bytes());
        bytes.extend_from_slice(&self.application_version);
        for value in [self.limits.max_entries, self.limits.max_peer_entries, self.limits.max_input_bytes,
            self.limits.max_outcome_bytes, self.limits.max_retained_bytes]
        { bytes.extend_from_slice(&size64(value)?.to_le_bytes()); }
        bytes.extend_from_slice(&self.limits.max_journal_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.limits.retention_ms.to_le_bytes());
        let tag = AuthenticationTag::compute_for_domain_payload(&self.key, HEADER_DOMAIN, &bytes);
        bytes.extend_from_slice(tag.as_bytes());
        debug_assert_eq!(bytes.len(), size);
        Ok(bytes)
    }
}

enum EntryState {
    Pending,
    Terminal { expires_at: u64, outcome: Zeroizing<Vec<u8>> },
}

struct Entry {
    input_len: u64,
    digest: [u8; 32],
    reservation_sequence: u64,
    state: EntryState,
}

// Same engine for real File operations and bounded injected I/O failures. An
// in-memory test fixture does not establish filesystem or power-loss behavior.
trait JournalIo: Read + Write + Seek {
    fn length(&self) -> io::Result<u64>;
    fn sync(&mut self) -> io::Result<()>;
}

impl JournalIo for File {
    fn length(&self) -> io::Result<u64> { Ok(self.metadata()?.len()) }
    fn sync(&mut self) -> io::Result<()> { self.sync_all() }
}

struct Journal<F> {
    file: F,
    config: Config,
    instance: Arc<()>,
    entries: BTreeMap<(NodeId, u128), Entry>,
    retained_bytes: usize,
    reserved_terminal_bytes: u64,
    offset: u64,
    sequence: u64,
    last: AuthenticationTag,
    last_time: u64,
    status: DurableRemoteJournalStatus,
}

fn valid_label(value: &str) -> bool { !value.is_empty() && value.len() <= 255 }
fn add(left: usize, right: usize) -> Result<usize, DurableRemoteError> {
    left.checked_add(right).ok_or(DurableRemoteError::Limit)
}
fn add64(left: u64, right: u64) -> Result<u64, DurableRemoteError> {
    left.checked_add(right).ok_or(DurableRemoteError::Limit)
}
fn size64(value: usize) -> Result<u64, DurableRemoteError> {
    u64::try_from(value).map_err(|_| DurableRemoteError::Limit)
}
fn buffer(capacity: usize) -> Result<Zeroizing<Vec<u8>>, DurableRemoteError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(capacity).map_err(|_| DurableRemoteError::Allocation)?;
    Ok(bytes)
}
fn copy_bytes(source: &[u8]) -> Result<Zeroizing<Vec<u8>>, DurableRemoteError> {
    let mut bytes = buffer(source.len())?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}
fn lock(file: &File) -> Result<(), DurableRemoteError> {
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(DurableRemoteError::Locked),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    if !file.metadata()?.is_file() { return Err(DurableRemoteError::NotRegular); }
    Ok(())
}
fn record_size(peer_len: usize, payload_len: usize) -> Result<u64, DurableRemoteError> {
    size64(add(add(PREFIX_BYTES + COMMON_BYTES + TAG_BYTES, peer_len)?, payload_len)?)
}
fn prefix_payload(length: u64, sequence: u64, previous: AuthenticationTag) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&length.to_le_bytes());
    bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[16..].copy_from_slice(previous.as_bytes());
    bytes
}
fn input_digest(input: &[u8]) -> Result<(u64, [u8; 32]), DurableRemoteError> {
    let length = size64(input.len())?;
    let mut hash = Sha256::new();
    hash.update(INPUT_DOMAIN);
    hash.update(length.to_le_bytes());
    hash.update(input);
    Ok((length, hash.finalize().into()))
}

struct OutcomeWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
    error: Option<DurableRemoteError>,
}

impl Write for OutcomeWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let length = self.bytes.len().checked_add(input.len());
        let Some(length) = length.filter(|length| *length <= self.limit) else {
            self.error = Some(DurableRemoteError::Limit);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bounded remote outcome exceeded"));
        };
        if self.bytes.capacity() < length {
            let capacity = length.max(self.bytes.capacity().saturating_mul(2)).min(self.limit);
            let additional = capacity - self.bytes.len();
            if self.bytes.try_reserve_exact(additional).is_err() {
                self.error = Some(DurableRemoteError::Allocation);
                return Err(io::Error::other("bounded remote outcome allocation failed"));
            }
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn decode_outcome(bytes: &[u8]) -> Result<RemoteOutcome, DurableRemoteError> {
    serde_json::from_slice::<RemoteServiceWireOutcome>(bytes)
        .map(RemoteOutcome::from).map_err(|_| DurableRemoteError::OutcomeEncoding)
}

fn encode_outcome(outcome: RemoteOutcome, limit: usize)
    -> Result<(Zeroizing<Vec<u8>>, RemoteOutcome), DurableRemoteError>
{
    let wire = RemoteServiceWireOutcome::from(outcome);
    let mut writer = OutcomeWriter { bytes: buffer(limit.min(1024))?, limit, error: None };
    if serde_json::to_writer(&mut writer, &wire).is_err() {
        return Err(writer.error.unwrap_or(DurableRemoteError::OutcomeEncoding));
    }
    let decoded = serde_json::from_slice::<RemoteServiceWireOutcome>(&writer.bytes)
        .map_err(|_| DurableRemoteError::OutcomeEncoding)?;
    if decoded != wire { return Err(DurableRemoteError::OutcomeEncoding); }
    // The writer grows geometrically while encoding. Retain a compact bounded
    // allocation, and account for its reported capacity rather than just its
    // logical length so terminal caching cannot hide spare allocated bytes.
    let encoded = copy_bytes(&writer.bytes)?;
    if encoded.capacity() > limit { return Err(DurableRemoteError::Limit); }
    Ok((encoded, decoded.into()))
}

struct Cursor<'a> { bytes: &'a [u8], position: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], DurableRemoteError> {
        let end = add(self.position, length)?;
        let result = self.bytes.get(self.position..end).ok_or(DurableRemoteError::Format)?;
        self.position = end;
        Ok(result)
    }
    fn number(&mut self) -> Result<u64, DurableRemoteError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }
    fn done(&self) -> bool { self.position == self.bytes.len() }
}

impl<F: JournalIo> Journal<F> {
    fn empty(file: F, config: Config, offset: u64, last: AuthenticationTag) -> Self {
        Self { file, config, instance: Arc::new(()), entries: BTreeMap::new(), retained_bytes: 0,
            reserved_terminal_bytes: 0, offset, sequence: 0, last, last_time: 0,
            status: DurableRemoteJournalStatus::Writable }
    }

    fn create(mut file: F, config: Config) -> Result<Self, DurableRemoteError> {
        if file.length()? != 0 { return Err(DurableRemoteError::NotEmpty); }
        let header = config.header()?;
        let last = AuthenticationTag::from_bytes(header[header.len() - TAG_BYTES..].try_into().expect("header tag"));
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header)?;
        file.sync()?;
        Ok(Self::empty(file, config, size64(header.len())?, last))
    }

    fn open(mut file: F, config: Config) -> Result<Self, DurableRemoteError> {
        let length = file.length()?;
        if length > config.limits.max_journal_bytes { return Err(DurableRemoteError::Limit); }
        let expected = config.header()?;
        if length < size64(expected.len())? { return Err(DurableRemoteError::Format); }
        let mut header = buffer(expected.len())?;
        header.resize(expected.len(), 0);
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        let signed = header.len() - TAG_BYTES;
        let last = AuthenticationTag::from_bytes(header[signed..].try_into().expect("header tag"));
        if !last.verify_domain_payload(&config.key, HEADER_DOMAIN, &header[..signed]) {
            return Err(DurableRemoteError::Authentication);
        }
        if header[..signed] != expected[..signed] { return Err(DurableRemoteError::Configuration); }
        let mut log = Self::empty(file, config, size64(header.len())?, last);
        while log.offset < length {
            let remaining = length - log.offset;
            if remaining < PREFIX_BYTES as u64 { log.status = DurableRemoteJournalStatus::ReadOnlyTail; break; }
            let mut prefix = [0; PREFIX_BYTES];
            log.file.read_exact(&mut prefix)?;
            let body_len = u64::from_le_bytes(prefix[..8].try_into().expect("length"));
            let next = add64(log.sequence, 1)?;
            let length_tag = AuthenticationTag::from_bytes(prefix[8..].try_into().expect("length tag"));
            if !length_tag.verify_domain_payload(&log.config.key, LENGTH_DOMAIN, &prefix_payload(body_len, next, log.last)) {
                return Err(DurableRemoteError::Authentication);
            }
            if body_len < (COMMON_BYTES + 1 + TERMINAL_BYTES) as u64
                || body_len > size64(log.config.max_body_bytes()?)?
            { return Err(DurableRemoteError::Format); }
            let size = add64(body_len, (PREFIX_BYTES + TAG_BYTES) as u64)?;
            if size > remaining { log.status = DurableRemoteJournalStatus::ReadOnlyTail; break; }
            let size_usize = usize::try_from(size).map_err(|_| DurableRemoteError::Limit)?;
            let mut record = buffer(size_usize)?;
            record.extend_from_slice(&prefix);
            record.resize(size_usize, 0);
            log.file.read_exact(&mut record[PREFIX_BYTES..])?;
            let end = size_usize - TAG_BYTES;
            let tag = AuthenticationTag::from_bytes(record[end..].try_into().expect("record tag"));
            if !tag.verify_domain_payload(&log.config.key, RECORD_DOMAIN, &record[..end]) {
                return Err(DurableRemoteError::Authentication);
            }
            log.replay_record(&record[PREFIX_BYTES..end], next, size)?;
            log.offset = add64(log.offset, size)?;
            log.sequence = next;
            log.last = tag;
        }
        if log.file.length()? != length { return Err(DurableRemoteError::Changed); }
        log.file.sync()?;
        Ok(log)
    }

    fn observe(&mut self, now: u64) -> Result<(), DurableRemoteError> {
        if now < self.last_time { return Err(DurableRemoteError::ClockRegression); }
        self.last_time = now;
        let retained_bytes = &mut self.retained_bytes;
        self.entries.retain(|_, entry| {
            if let EntryState::Terminal { expires_at, outcome } = &entry.state
                && now >= *expires_at
            {
                *retained_bytes -= outcome.capacity();
                false
            } else { true }
        });
        Ok(())
    }

    fn terminal_reservation(&self, peer: &NodeId) -> Result<u64, DurableRemoteError> {
        record_size(peer.as_str().len(), add(TERMINAL_BYTES, self.config.limits.max_outcome_bytes)?)
    }

    fn pending_capacity(&self, peer: &NodeId, reservation_bytes: u64) -> Result<(usize, u64), DurableRemoteError> {
        let limits = self.config.limits;
        if limits.max_outcome_bytes == 0 || self.entries.len() >= limits.max_entries
            || self.entries.keys().filter(|(origin, _)| origin == peer).count() >= limits.max_peer_entries
        { return Err(DurableRemoteError::Limit); }
        let retained = add(self.retained_bytes, limits.max_outcome_bytes)?;
        if retained > limits.max_retained_bytes { return Err(DurableRemoteError::Limit); }
        let reserved = add64(self.reserved_terminal_bytes, self.terminal_reservation(peer)?)?;
        let required = add64(add64(self.offset, reservation_bytes)?, reserved)?;
        if required > limits.max_journal_bytes { return Err(DurableRemoteError::Limit); }
        Ok((retained, reserved))
    }

    fn admit(&mut self, peer: &NodeId, key: IdempotencyKey, input: &[u8], now: u64)
        -> Result<DurableRemoteAdmission, DurableRemoteError>
    {
        if self.status == DurableRemoteJournalStatus::Poisoned { return Err(DurableRemoteError::NotWritable(self.status)); }
        self.observe(now)?;
        if !valid_label(peer.as_str()) { return Err(DurableRemoteError::Configuration); }
        if input.len() > self.config.limits.max_input_bytes { return Err(DurableRemoteError::Limit); }
        let (input_len, digest) = input_digest(input)?;
        let id = (peer.clone(), key.raw());
        if let Some(entry) = self.entries.get(&id) {
            if entry.input_len != input_len || entry.digest != digest { return Err(DurableRemoteError::Conflict); }
            return match &entry.state {
                EntryState::Pending => Err(DurableRemoteError::InDoubt),
                EntryState::Terminal { outcome, .. } => Ok(DurableRemoteAdmission::Replay(decode_outcome(outcome)?)),
            };
        }
        if self.status != DurableRemoteJournalStatus::Writable { return Err(DurableRemoteError::NotWritable(self.status)); }
        // Check timestamp arithmetic before granting an operation which could
        // not represent even an immediate completion's retention horizon.
        let _ = add64(now, self.config.limits.retention_ms)?;
        let sequence = add64(self.sequence, 1)?;
        let (retained, reserved) = self.pending_capacity(peer, record_size(peer.as_str().len(), RESERVATION_BYTES)?)?;
        let mut payload = [0; RESERVATION_BYTES];
        payload[..8].copy_from_slice(&input_len.to_le_bytes());
        payload[8..].copy_from_slice(&digest);
        self.append_record(RESERVE, peer, key, &payload, now)?;
        self.entries.insert(id, Entry { input_len, digest, reservation_sequence: sequence, state: EntryState::Pending });
        self.retained_bytes = retained;
        self.reserved_terminal_bytes = reserved;
        Ok(DurableRemoteAdmission::Execute(DurableRemoteReservation {
            instance: Arc::clone(&self.instance), peer: peer.clone(), key, sequence,
        }))
    }

    fn prepare_reconciliation(&mut self, peer: &NodeId, key: IdempotencyKey, input: &[u8], now: u64)
        -> Result<DurableRemoteReconciliation, DurableRemoteError>
    {
        if self.status == DurableRemoteJournalStatus::Poisoned {
            return Err(DurableRemoteError::NotWritable(self.status));
        }
        self.observe(now)?;
        if !valid_label(peer.as_str()) { return Err(DurableRemoteError::Configuration); }
        if input.len() > self.config.limits.max_input_bytes { return Err(DurableRemoteError::Limit); }
        let (input_len, digest) = input_digest(input)?;
        let entry = self.entries.get(&(peer.clone(), key.raw()))
            .ok_or(DurableRemoteError::InvalidReservation)?;
        if entry.input_len != input_len || entry.digest != digest {
            return Err(DurableRemoteError::Conflict);
        }
        if let EntryState::Terminal { outcome, .. } = &entry.state {
            return Ok(DurableRemoteReconciliation::Replay(decode_outcome(outcome)?));
        }
        if self.status != DurableRemoteJournalStatus::Writable {
            return Err(DurableRemoteError::NotWritable(self.status));
        }
        // Only this owner can mint an instance reference; permits are not Clone.
        // Once the count reaches one, no outstanding token can reappear while
        // this mutable borrow excludes admission. Refuse live original owners
        // and competing resolvers instead of racing their terminal publication.
        if Arc::strong_count(&self.instance) != 1 { return Err(DurableRemoteError::Busy); }
        let _ = add64(now, self.config.limits.retention_ms)?;
        Ok(DurableRemoteReconciliation::Pending(DurableRemoteReconciliationPermit {
            reservation: DurableRemoteReservation {
                instance: Arc::clone(&self.instance), peer: peer.clone(), key,
                sequence: entry.reservation_sequence,
            },
            input_len, digest, schema: self.config.schema,
            application_version: self.config.application_version,
        }))
    }

    fn complete_reconciliation(&mut self, permit: DurableRemoteReconciliationPermit,
        outcome: RemoteOutcome, now: u64) -> Result<RemoteOutcome, DurableRemoteError>
    {
        if !Arc::ptr_eq(&permit.reservation.instance, &self.instance)
            || permit.schema != self.config.schema
            || permit.application_version != self.config.application_version
        { return Err(DurableRemoteError::InvalidReservation); }
        let entry = self.entries.get(&(permit.reservation.peer.clone(), permit.reservation.key.raw()))
            .ok_or(DurableRemoteError::InvalidReservation)?;
        if entry.input_len != permit.input_len || entry.digest != permit.digest {
            return Err(DurableRemoteError::InvalidReservation);
        }
        self.complete(permit.reservation, outcome, now)
    }

    fn complete(&mut self, reservation: DurableRemoteReservation, outcome: RemoteOutcome, now: u64)
        -> Result<RemoteOutcome, DurableRemoteError>
    {
        if !Arc::ptr_eq(&reservation.instance, &self.instance) { return Err(DurableRemoteError::InvalidReservation); }
        if self.status != DurableRemoteJournalStatus::Writable { return Err(DurableRemoteError::NotWritable(self.status)); }
        self.observe(now)?;
        let id = (reservation.peer.clone(), reservation.key.raw());
        let entry = self.entries.get(&id).ok_or(DurableRemoteError::InvalidReservation)?;
        if entry.reservation_sequence != reservation.sequence || !matches!(&entry.state, EntryState::Pending) {
            return Err(DurableRemoteError::InvalidReservation);
        }
        let expires_at = add64(now, self.config.limits.retention_ms)?;
        let (encoded, decoded) = encode_outcome(outcome, self.config.limits.max_outcome_bytes)?;
        let reserved = self.reserved_terminal_bytes.checked_sub(self.terminal_reservation(&reservation.peer)?)
            .ok_or(DurableRemoteError::Format)?;
        let retained = self.retained_bytes.checked_sub(self.config.limits.max_outcome_bytes)
            .and_then(|bytes| bytes.checked_add(encoded.capacity())).ok_or(DurableRemoteError::Format)?;
        let payload_size = add(TERMINAL_BYTES, encoded.len())?;
        let required = add64(add64(self.offset, record_size(reservation.peer.as_str().len(), payload_size)?)?, reserved)?;
        if required > self.config.limits.max_journal_bytes { return Err(DurableRemoteError::Limit); }
        let mut payload = buffer(payload_size)?;
        payload.extend_from_slice(&reservation.sequence.to_le_bytes());
        payload.extend_from_slice(&expires_at.to_le_bytes());
        payload.extend_from_slice(&size64(encoded.len())?.to_le_bytes());
        payload.extend_from_slice(&encoded);
        self.append_record(COMPLETE, &reservation.peer, reservation.key, &payload, now)?;
        self.entries.get_mut(&id).expect("validated pending reservation").state = EntryState::Terminal { expires_at, outcome: encoded };
        self.retained_bytes = retained;
        self.reserved_terminal_bytes = reserved;
        Ok(decoded)
    }

    fn append_record(&mut self, kind: u8, peer: &NodeId, key: IdempotencyKey, payload: &[u8], now: u64)
        -> Result<(), DurableRemoteError>
    {
        let sequence = add64(self.sequence, 1)?;
        let body_len = add(add(COMMON_BYTES, peer.as_str().len())?, payload.len())?;
        let size = add(PREFIX_BYTES + TAG_BYTES, body_len)?;
        let end = add64(self.offset, size64(size)?)?;
        if end > self.config.limits.max_journal_bytes { return Err(DurableRemoteError::Limit); }
        let mut record = buffer(size)?;
        record.extend_from_slice(&size64(body_len)?.to_le_bytes());
        let length_tag = AuthenticationTag::compute_for_domain_payload(&self.config.key, LENGTH_DOMAIN,
            &prefix_payload(size64(body_len)?, sequence, self.last));
        record.extend_from_slice(length_tag.as_bytes());
        record.extend_from_slice(&sequence.to_le_bytes());
        record.extend_from_slice(self.last.as_bytes());
        record.extend_from_slice(&now.to_le_bytes());
        record.push(kind);
        record.push(peer.as_str().len() as u8);
        record.extend_from_slice(&key.raw().to_le_bytes());
        record.extend_from_slice(peer.as_str().as_bytes());
        record.extend_from_slice(payload);
        let tag = AuthenticationTag::compute_for_domain_payload(&self.config.key, RECORD_DOMAIN, &record);
        record.extend_from_slice(tag.as_bytes());
        debug_assert_eq!(record.len(), size);
        self.status = DurableRemoteJournalStatus::Poisoned;
        if self.file.length()? != self.offset || self.file.seek(SeekFrom::End(0))? != self.offset {
            return Err(DurableRemoteError::Changed);
        }
        self.file.write_all(&record)?;
        self.file.sync()?;
        self.offset = end;
        self.sequence = sequence;
        self.last = tag;
        self.status = DurableRemoteJournalStatus::Writable;
        Ok(())
    }

    fn replay_record(&mut self, body: &[u8], sequence: u64, size: u64) -> Result<(), DurableRemoteError> {
        let mut cursor = Cursor { bytes: body, position: 0 };
        if cursor.number()? != sequence || cursor.take(TAG_BYTES)? != self.last.as_bytes() {
            return Err(DurableRemoteError::Format);
        }
        let now = cursor.number()?;
        let kind = cursor.take(1)?[0];
        let peer_len = usize::from(cursor.take(1)?[0]);
        let key = IdempotencyKey::from_raw(u128::from_le_bytes(cursor.take(16)?.try_into().expect("key")));
        let peer = std::str::from_utf8(cursor.take(peer_len)?).map_err(|_| DurableRemoteError::Format)?;
        if !valid_label(peer) { return Err(DurableRemoteError::Format); }
        let peer = NodeId::new(peer);
        self.observe(now)?;
        let id = (peer.clone(), key.raw());
        match kind {
            RESERVE => {
                let input_len = cursor.number()?;
                let digest = cursor.take(32)?.try_into().expect("digest");
                if !cursor.done() || input_len > size64(self.config.limits.max_input_bytes)? || self.entries.contains_key(&id) {
                    return Err(DurableRemoteError::Format);
                }
                let _ = add64(now, self.config.limits.retention_ms)?;
                let (retained, reserved) = self.pending_capacity(&peer, size)?;
                self.entries.insert(id, Entry { input_len, digest, reservation_sequence: sequence, state: EntryState::Pending });
                self.retained_bytes = retained;
                self.reserved_terminal_bytes = reserved;
            }
            COMPLETE => {
                let reservation_sequence = cursor.number()?;
                let expires_at = cursor.number()?;
                let outcome_len = usize::try_from(cursor.number()?).map_err(|_| DurableRemoteError::Limit)?;
                if outcome_len > self.config.limits.max_outcome_bytes || expires_at != add64(now, self.config.limits.retention_ms)? {
                    return Err(DurableRemoteError::Format);
                }
                let outcome = cursor.take(outcome_len)?;
                if !cursor.done() { return Err(DurableRemoteError::Format); }
                let entry = self.entries.get(&id).ok_or(DurableRemoteError::Format)?;
                if entry.reservation_sequence != reservation_sequence || !matches!(&entry.state, EntryState::Pending) {
                    return Err(DurableRemoteError::Format);
                }
                let _ = decode_outcome(outcome)?;
                let encoded = copy_bytes(outcome)?;
                if encoded.capacity() > self.config.limits.max_outcome_bytes {
                    return Err(DurableRemoteError::Limit);
                }
                let reserved = self.reserved_terminal_bytes.checked_sub(self.terminal_reservation(&peer)?)
                    .ok_or(DurableRemoteError::Format)?;
                let retained = self.retained_bytes.checked_sub(self.config.limits.max_outcome_bytes)
                    .and_then(|bytes| bytes.checked_add(encoded.capacity())).ok_or(DurableRemoteError::Format)?;
                if add64(add64(self.offset, size)?, reserved)? > self.config.limits.max_journal_bytes {
                    return Err(DurableRemoteError::Limit);
                }
                self.entries.get_mut(&id).expect("validated pending entry").state = EntryState::Terminal { expires_at, outcome: encoded };
                self.retained_bytes = retained;
                self.reserved_terminal_bytes = reserved;
            }
            _ => return Err(DurableRemoteError::Format),
        }
        Ok(())
    }
}

mod runtime;
pub use runtime::DurableRemoteComputation;

#[cfg(test)]
mod tests;
