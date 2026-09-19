//! Persistent authority decisions for restart-safe membership fencing.
//!
//! A caller-owned regular file retains authenticated membership decisions, not
//! tasks, leases, credentials, routes, or arbitrary application state. Append
//! and recovery sync before exposing a decision. A complete corrupt record fails
//! closed; an interrupted final record preserves a read-only valid prefix. This
//! never truncates, repairs, compacts, deletes, or opens another file.
//!
//! The caller must durably link the file and preserve its exclusive ownership.
//! Authentication is not encryption or an external anti-rollback witness: an
//! attacker who can replace the whole file with an older valid prefix can replay
//! history unless an independently retained head prevents that replacement.
//! All methods touching the file are synchronous; use a blocking worker.

use super::authority::{
    MAX_MEMBERSHIP_UPDATE_BYTES, MembershipApplied, MembershipControlError,
    MembershipControllerLimits, MembershipFloor, MembershipLeaseController, MembershipStamp,
};
use crate::remote::NodeId;
use crate::security::{AuthKey, AuthenticationTag};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASUPMJL\0";
const HEADER_DOMAIN: &[u8] = b"asupersync.membership-journal.header.v1";
const KEY_DOMAIN: &[u8] = b"asupersync.membership-journal.authority-key.v1";
const LENGTH_DOMAIN: &[u8] = b"asupersync.membership-journal.length.v1";
const RECORD_DOMAIN: &[u8] = b"asupersync.membership-journal.record.v1";
const TAG: usize = 32;
const PREFIX: usize = 8 + TAG;
const FIXED: usize = 8 + TAG;
const MIN_STATEMENT: usize = 73;

/// Independently provisioned initial authority; it must match on every reopen.
///
/// Floors are the journal's INITIAL floors, not its most recently accepted ones.
/// Its authenticated log restores those subsequent decisions. No local lease is
/// restored. Changing epoch, member labels/floors, or either key requires a new,
/// externally managed authority lifecycle, not silently resetting this file.
pub struct MembershipJournalConfig {
    /// Certificate-bound decision authority, independent of routing.
    pub authority: NodeId,
    /// Authority epoch, independently trusted rather than discovered from disk.
    pub epoch: u64,
    /// Key verifying each original authority statement.
    pub statement_key: AuthKey,
    /// Independent key authenticating the journal and its framing.
    pub journal_key: AuthKey,
    /// Fixed member allow-list and initial incarnation/sequence floors.
    pub floors: Vec<MembershipFloor>,
    /// Bounds for the policy and later runtime-owned leases.
    pub controller_limits: MembershipControllerLimits,
    /// Entire encoded file ceiling, including header and any incomplete tail.
    pub max_journal_bytes: u64,
}
impl fmt::Debug for MembershipJournalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipJournalConfig")
            .field("members", &self.floors.len())
            .field("max_journal_bytes", &self.max_journal_bytes)
            .finish_non_exhaustive()
    }
}

/// Append posture after recovery or a write attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipJournalStatus {
    /// All encoded records were complete and synced.
    Writable,
    /// The last append was incomplete; new decisions refuse without repairing it.
    ReadOnlyTail,
    /// A write, sync, or external-length check had an uncertain outcome.
    Poisoned,
}

/// Redacted persistence/admission error. Failed appends may have reached disk.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipJournalError {
    /// Existing membership authentication or monotonicity validation failed.
    #[error(transparent)]
    Control(#[from] MembershipControlError),
    /// A system call failed; this is not evidence that an append rolled back.
    #[error("membership journal I/O failed; an append may have committed")]
    Io(#[source] io::Error),
    /// The supplied file has another exclusive owner.
    #[error("membership journal is locked")]
    Locked,
    /// The supplied handle must denote a regular file.
    #[error("membership journal requires a regular file")]
    NotRegular,
    /// Creation refuses to overwrite any existing bytes.
    #[error("membership journal creation requires an empty file")]
    NotEmpty,
    /// Header, record length, chain, or replay structure was invalid.
    #[error("invalid membership journal format or provisioned configuration")]
    Format,
    /// Journal authentication failed independently of statement authentication.
    #[error("membership journal authentication failed")]
    Authentication,
    /// A size/count overflowed or exceeded the explicit encoded-byte limit.
    #[error("membership journal size limit exceeded")]
    Limit,
    /// A bounded allocation was refused.
    #[error("membership journal allocation failed")]
    Allocation,
    /// A non-owner changed the file length.
    #[error("membership journal changed outside its exclusive owner")]
    Changed,
    /// Only the existing last statement can be repeated in read-only recovery.
    #[error("membership journal is not writable: {0:?}")]
    NotWritable(MembershipJournalStatus),
}
impl From<io::Error> for MembershipJournalError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

/// Authenticated membership history with immutable initial provisioning.
///
/// Owns an exclusive file lock until drop. Do not clone/inherit its handle or
/// write through actors ignoring the lock. File/directory permissions, durable
/// linkage, device sync guarantees and encrypted storage are caller concerns.
/// The in-memory index retains at most one bounded signed statement per member.
/// Validating an append reconstructs a policy from that bounded index, so work
/// is proportional to the member ceiling, not the unbounded historical churn.
/// Replay is additionally bounded by `max_journal_bytes`.
pub struct MembershipJournal {
    core: Journal<File>,
}
impl fmt::Debug for MembershipJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipJournal")
            .field("records", &self.core.sequence)
            .field("committed_bytes", &self.core.offset)
            .field("status", &self.core.status).finish_non_exhaustive()
    }
}
impl MembershipJournal {
    /// Initialize and sync an empty caller-owned, durably linked read/write file.
    pub fn create(file: File, config: MembershipJournalConfig) -> Result<Self, MembershipJournalError> {
        lock(&file)?;
        Ok(Self { core: Journal::create(file, config)? })
    }
    /// Authenticate, replay and sync before exposing any recovered membership.
    /// No lease, runtime ID, or work item is recreated by opening the file.
    pub fn open(file: File, config: MembershipJournalConfig) -> Result<Self, MembershipJournalError> {
        lock(&file)?;
        Ok(Self { core: Journal::open(file, config)? })
    }
    /// Verify and sync a new authority decision. Latest identical repeats do not
    /// append, even at capacity or behind a partial tail. Rejected stale or forged
    /// decisions never mutate disk. A failed append poisons this owner.
    pub fn append(&mut self, statement: &[u8]) -> Result<MembershipApplied, MembershipJournalError> {
        self.core.append(statement)
    }
    /// Recovered last accepted state for an authorized member.
    pub fn stamp(&self, node: &NodeId) -> Option<MembershipStamp> { self.core.policy.stamp(node) }
    /// Current append posture, without any disk I/O.
    pub fn status(&self) -> MembershipJournalStatus { self.core.status }
    /// End of the complete synced prefix, excluding any interrupted tail.
    pub fn committed_bytes(&self) -> u64 { self.core.offset }
    /// Complete persisted decisions; identical repeated delivery is not counted.
    pub fn records(&self) -> u64 { self.core.sequence }
}

fn lock(file: &File) -> Result<(), MembershipJournalError> {
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(MembershipJournalError::Locked),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    if !file.metadata()?.is_file() { return Err(MembershipJournalError::NotRegular); }
    Ok(())
}
fn add(a: usize, b: usize) -> Result<usize, MembershipJournalError> {
    a.checked_add(b).ok_or(MembershipJournalError::Limit)
}
fn buffer(n: usize) -> Result<Zeroizing<Vec<u8>>, MembershipJournalError> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(n).map_err(|_| MembershipJournalError::Allocation)?;
    Ok(out)
}
fn fresh(config: &MembershipJournalConfig) -> Result<MembershipLeaseController, MembershipJournalError> {
    if config.floors.len() > config.controller_limits.max_members {
        return Err(MembershipControlError::Capacity.into());
    }
    if config.authority.as_str().is_empty() || config.authority.as_str().len() > 255
        || config.floors.iter().any(|floor| floor.node.as_str().is_empty() || floor.node.as_str().len() > 255)
    { return Err(MembershipControlError::Format.into()); }
    Ok(MembershipLeaseController::new(config.authority.clone(), config.epoch,
        config.statement_key.clone(), config.floors.clone(), config.controller_limits)?)
}
fn header(config: &MembershipJournalConfig) -> Result<Zeroizing<Vec<u8>>, MembershipJournalError> {
    let _ = fresh(config)?; // Validate labels, unique members and count before encoding.
    let mut size = add(25 + 2 * TAG, config.authority.as_str().len())?;
    for floor in &config.floors { size = add(size, add(17, floor.node.as_str().len())?)?; }
    if u64::try_from(size).map_err(|_| MembershipJournalError::Limit)? > config.max_journal_bytes {
        return Err(MembershipJournalError::Limit);
    }
    let count = u32::try_from(config.floors.len()).map_err(|_| MembershipJournalError::Limit)?;
    let mut ordered = Vec::new();
    ordered.try_reserve_exact(config.floors.len()).map_err(|_| MembershipJournalError::Allocation)?;
    ordered.extend(config.floors.iter());
    ordered.sort_unstable_by(|a, b| a.node.cmp(&b.node));
    let mut out = buffer(size)?;
    out.extend_from_slice(MAGIC); out.extend_from_slice(&1_u32.to_le_bytes());
    out.push(config.authority.as_str().len() as u8);
    out.extend_from_slice(config.authority.as_str().as_bytes());
    out.extend_from_slice(&config.epoch.to_le_bytes()); out.extend_from_slice(&count.to_le_bytes());
    for floor in ordered {
        out.push(floor.node.as_str().len() as u8); out.extend_from_slice(floor.node.as_str().as_bytes());
        out.extend_from_slice(&floor.incarnation.to_le_bytes()); out.extend_from_slice(&floor.sequence.to_le_bytes());
    }
    let key_tag = AuthenticationTag::compute_for_domain_payload(&config.statement_key, KEY_DOMAIN, &out);
    out.extend_from_slice(key_tag.as_bytes());
    let tag = AuthenticationTag::compute_for_domain_payload(&config.journal_key, HEADER_DOMAIN, &out);
    out.extend_from_slice(tag.as_bytes());
    debug_assert_eq!(out.len(), size);
    Ok(out)
}
fn prefix_input(length: u64, sequence: u64, previous: AuthenticationTag) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&length.to_le_bytes()); bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[16..].copy_from_slice(previous.as_bytes()); bytes
}

// Fault injection uses this same engine. It does not emulate filesystem durability.
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
    config: MembershipJournalConfig,
    policy: MembershipLeaseController,
    latest: BTreeMap<NodeId, Zeroizing<Vec<u8>>>,
    offset: u64,
    sequence: u64,
    last: AuthenticationTag,
    status: MembershipJournalStatus,
}
impl<F: JournalIo> Journal<F> {
    fn create(mut file: F, config: MembershipJournalConfig) -> Result<Self, MembershipJournalError> {
        if file.length()? != 0 { return Err(MembershipJournalError::NotEmpty); }
        let bytes = header(&config)?; let policy = fresh(&config)?;
        file.seek(SeekFrom::Start(0))?; file.write_all(&bytes)?; file.sync()?;
        let last = AuthenticationTag::from_bytes(bytes[bytes.len()-TAG..].try_into().expect("header tag"));
        Ok(Self { file, config, policy, latest: BTreeMap::new(), offset: bytes.len() as u64,
            sequence: 0, last, status: MembershipJournalStatus::Writable })
    }
    fn open(mut file: F, config: MembershipJournalConfig) -> Result<Self, MembershipJournalError> {
        let length = file.length()?;
        if length > config.max_journal_bytes { return Err(MembershipJournalError::Limit); }
        let expected = header(&config)?;
        if length < expected.len() as u64 { return Err(MembershipJournalError::Format); }
        let mut bytes = buffer(expected.len())?; bytes.resize(expected.len(), 0);
        file.seek(SeekFrom::Start(0))?; file.read_exact(&mut bytes)?;
        let signed = bytes.len() - TAG;
        let last = AuthenticationTag::from_bytes(bytes[signed..].try_into().expect("header tag"));
        if !last.verify_domain_payload(&config.journal_key, HEADER_DOMAIN, &bytes[..signed]) {
            return Err(MembershipJournalError::Authentication);
        }
        if bytes[..signed] != expected[..signed] { return Err(MembershipJournalError::Format); }
        let policy = fresh(&config)?;
        let mut log = Self { file, config, policy, latest: BTreeMap::new(), offset: bytes.len() as u64,
            sequence: 0, last, status: MembershipJournalStatus::Writable };
        while log.offset < length {
            let remaining = length - log.offset;
            if remaining < PREFIX as u64 { log.status = MembershipJournalStatus::ReadOnlyTail; break; }
            let mut prefix = [0; PREFIX]; log.file.read_exact(&mut prefix)?;
            let body_len = u64::from_le_bytes(prefix[..8].try_into().expect("length"));
            let next = log.sequence.checked_add(1).ok_or(MembershipJournalError::Limit)?;
            let length_tag = AuthenticationTag::from_bytes(prefix[8..].try_into().expect("length tag"));
            if !length_tag.verify_domain_payload(&log.config.journal_key, LENGTH_DOMAIN,
                &prefix_input(body_len, next, log.last)) { return Err(MembershipJournalError::Authentication); }
            if !((FIXED + MIN_STATEMENT) as u64..=(FIXED + MAX_MEMBERSHIP_UPDATE_BYTES) as u64).contains(&body_len) {
                return Err(MembershipJournalError::Format);
            }
            let size = body_len.checked_add((PREFIX + TAG) as u64).ok_or(MembershipJournalError::Limit)?;
            if size > remaining { log.status = MembershipJournalStatus::ReadOnlyTail; break; }
            let size = usize::try_from(size).map_err(|_| MembershipJournalError::Limit)?;
            let mut record = buffer(size)?; record.extend_from_slice(&prefix); record.resize(size, 0);
            log.file.read_exact(&mut record[PREFIX..])?;
            let end = size - TAG;
            let tag = AuthenticationTag::from_bytes(record[end..].try_into().expect("record tag"));
            if !tag.verify_domain_payload(&log.config.journal_key, RECORD_DOMAIN, &record[..end]) {
                return Err(MembershipJournalError::Authentication);
            }
            let body = &record[PREFIX..end];
            if body[..8] != next.to_le_bytes() || &body[8..FIXED] != log.last.as_bytes() {
                return Err(MembershipJournalError::Format);
            }
            let statement = &body[FIXED..];
            let (candidate, node, applied) = log.prepare(statement)?;
            if applied == MembershipApplied::Duplicate { return Err(MembershipJournalError::Format); }
            let mut retained = buffer(statement.len())?; retained.extend_from_slice(statement);
            log.latest.insert(node.expect("new statement has a changed member"), retained);
            log.policy = candidate; log.sequence = next; log.last = tag;
            log.offset += size as u64;
        }
        if log.file.length()? != length { return Err(MembershipJournalError::Changed); }
        log.file.sync()?; // Complete unacknowledged appends become durable before exposure.
        Ok(log)
    }
    fn prepare(&self, statement: &[u8]) -> Result<(MembershipLeaseController, Option<NodeId>, MembershipApplied), MembershipJournalError> {
        if !(MIN_STATEMENT..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&statement.len()) {
            return Err(MembershipControlError::Format.into());
        }
        let mut candidate = fresh(&self.config)?;
        for bytes in self.latest.values() { candidate.apply_authenticated(bytes)?; }
        let applied = candidate.apply_authenticated(statement)?;
        let node = self.config.floors.iter().find_map(|floor| {
            (self.policy.stamp(&floor.node) != candidate.stamp(&floor.node)).then(|| floor.node.clone())
        });
        if applied != MembershipApplied::Duplicate && node.is_none() { return Err(MembershipJournalError::Format); }
        Ok((candidate, node, applied))
    }
    fn append(&mut self, statement: &[u8]) -> Result<MembershipApplied, MembershipJournalError> {
        if self.status == MembershipJournalStatus::Poisoned { return Err(MembershipJournalError::NotWritable(self.status)); }
        let (candidate, node, applied) = self.prepare(statement)?;
        if applied == MembershipApplied::Duplicate { return Ok(applied); }
        if self.status != MembershipJournalStatus::Writable { return Err(MembershipJournalError::NotWritable(self.status)); }
        let next = self.sequence.checked_add(1).ok_or(MembershipJournalError::Limit)?;
        let body_len = add(FIXED, statement.len())?;
        let size = add(PREFIX + TAG, body_len)?;
        let end = self.offset.checked_add(size as u64).ok_or(MembershipJournalError::Limit)?;
        if end > self.config.max_journal_bytes { return Err(MembershipJournalError::Limit); }
        let mut retained = buffer(statement.len())?; retained.extend_from_slice(statement);
        let mut record = buffer(size)?;
        record.extend_from_slice(&(body_len as u64).to_le_bytes());
        let length_tag = AuthenticationTag::compute_for_domain_payload(&self.config.journal_key,
            LENGTH_DOMAIN, &prefix_input(body_len as u64, next, self.last));
        record.extend_from_slice(length_tag.as_bytes()); record.extend_from_slice(&next.to_le_bytes());
        record.extend_from_slice(self.last.as_bytes()); record.extend_from_slice(statement);
        let tag = AuthenticationTag::compute_for_domain_payload(&self.config.journal_key, RECORD_DOMAIN, &record);
        record.extend_from_slice(tag.as_bytes());
        self.status = MembershipJournalStatus::Poisoned;
        if self.file.length()? != self.offset || self.file.seek(SeekFrom::End(0))? != self.offset {
            return Err(MembershipJournalError::Changed);
        }
        self.file.write_all(&record)?; self.file.sync()?;
        self.latest.insert(node.expect("new statement has a changed member"), retained);
        self.policy = candidate; self.offset = end; self.sequence = next; self.last = tag;
        self.status = MembershipJournalStatus::Writable;
        Ok(applied)
    }
}

#[cfg(test)]
mod tests;
