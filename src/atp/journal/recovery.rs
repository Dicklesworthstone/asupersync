//! Recovery mechanisms for append-only journal and chunk bitmap.
//!
//! Handles crash recovery scenarios including torn appends, duplicate records,
//! checksum validation, and state reconstruction after process kill.

use super::{AppendJournal, ChunkBitmap, ChunkState, JournalConfig, JournalRecord};
use crate::security::AuthKey;
use crate::types::outcome::Outcome;

/// Identifier for a transfer chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(u64);

impl ChunkId {
    pub fn from_u64(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
use crate::cx::Cx;
use crate::fs;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Journal file corrupted: {0}")]
    JournalCorrupted(String),
    #[error("Checksum mismatch at offset {offset}: expected {expected:x}, got {actual:x}")]
    ChecksumMismatch {
        offset: u64,
        expected: u64,
        actual: u64,
    },
    #[error("Incomplete record at offset {0}: file truncated")]
    IncompleteRecord(u64),
    #[error("Invalid chunk state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: ChunkState, to: ChunkState },
    #[error("IO error during recovery: {0}")]
    Io(#[from] io::Error),
    #[error("Bitmap recovery failed: {0}")]
    BitmapRecovery(String),
    #[error("Record signature verification failed: invalid cryptographic signature")]
    InvalidSignature,
}

/// Recovery context for tracking state during crash recovery.
pub struct RecoveryContext {
    /// Current transfer states being recovered
    transfers: HashMap<String, TransferRecoveryState>,
    /// Duplicate record detection
    seen_records: HashSet<RecordFingerprint>,
    /// Recovery statistics
    stats: RecoveryStats,
}

#[derive(Debug)]
struct TransferRecoveryState {
    /// Chunk states being reconstructed
    chunk_states: HashMap<ChunkId, ChunkState>,
    /// Chunk sizes observed for each recovered chunk.
    chunk_sizes: BTreeMap<ChunkId, u64>,
    /// Offered transfer size recovered from the journal, when present.
    total_size: Option<u64>,
    /// First timestamp observed for this transfer.
    created_at: Option<u64>,
    /// Last seen commit intent timestamp
    commit_intent_time: Option<u64>,
    /// Whether this transfer was committed
    is_committed: bool,
    /// Whether this transfer was cancelled
    is_cancelled: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RecordFingerprint {
    transfer_id: String,
    record_type: u8,
    chunk_offset: Option<u64>,
    timestamp: u64,
    // Verified before duplicate lookup; binds every encoded payload field
    // without retaining or re-encoding the full record for the seen set.
    payload_tag: [u8; 32],
}

#[derive(Debug, Default)]
pub struct RecoveryStats {
    /// Total records processed
    pub total_records: usize,
    /// Duplicate records skipped
    pub duplicates_skipped: usize,
    /// Corrupted records skipped
    pub corrupted_skipped: usize,
    /// Transfers recovered
    pub transfers_recovered: usize,
    /// Chunks recovered
    pub chunks_recovered: usize,
}

impl RecoveryContext {
    /// Create a new recovery context.
    pub fn new() -> Self {
        Self {
            transfers: HashMap::new(),
            seen_records: HashSet::new(),
            stats: RecoveryStats::default(),
        }
    }

    /// Process a journal record during recovery.
    pub fn process_record(
        &mut self,
        record: &JournalRecord,
        auth_key: &AuthKey,
    ) -> Result<bool, RecoveryError> {
        self.stats.total_records += 1;

        // Verify cryptographic signature BEFORE any processing
        if !record.verify_signature(auth_key) {
            return Err(RecoveryError::InvalidSignature);
        }

        // Check for duplicates
        let fingerprint = self.create_fingerprint(record);
        if self.seen_records.contains(&fingerprint) {
            self.stats.duplicates_skipped += 1;
            return Ok(false);
        }
        let result = match record {
            JournalRecord::Offer {
                transfer_id,
                total_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                transfer.record_offer(*total_size, *timestamp);
                Ok(true)
            }
            JournalRecord::Accept { transfer_id, .. } => {
                self.ensure_transfer(transfer_id);
                Ok(true)
            }
            JournalRecord::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(
                    transfer,
                    *chunk_offset,
                    *chunk_size,
                    *timestamp,
                    ChunkState::Received,
                )?;
                Ok(true)
            }
            JournalRecord::ChunkVerified {
                transfer_id,
                chunk_offset,
                chunk_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(
                    transfer,
                    *chunk_offset,
                    *chunk_size,
                    *timestamp,
                    ChunkState::Verified,
                )?;
                Ok(true)
            }
            JournalRecord::ChunkWritten {
                transfer_id,
                chunk_offset,
                chunk_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(
                    transfer,
                    *chunk_offset,
                    *chunk_size,
                    *timestamp,
                    ChunkState::Written,
                )?;
                Ok(true)
            }
            JournalRecord::RepairDecode {
                transfer_id,
                chunk_offset,
                chunk_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(
                    transfer,
                    *chunk_offset,
                    *chunk_size,
                    *timestamp,
                    ChunkState::RepairDerived,
                )?;
                Ok(true)
            }
            JournalRecord::CommitIntent {
                transfer_id,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                transfer.commit_intent_time = Some(*timestamp);
                Ok(true)
            }
            JournalRecord::CommitComplete {
                transfer_id,
                committed_size,
                timestamp,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                transfer.record_offer(*committed_size, *timestamp);
                transfer.is_committed = true;
                Self::commit_all_chunks(transfer);
                Ok(true)
            }
            JournalRecord::Cancellation { transfer_id, .. } => {
                let transfer = self.ensure_transfer(transfer_id);
                transfer.is_cancelled = true;
                Ok(true)
            }
            JournalRecord::Rollback { transfer_id, .. } => {
                let transfer = self.ensure_transfer(transfer_id);
                transfer.is_committed = false;
                transfer.commit_intent_time = None;
                Self::rollback_uncommitted_chunks(transfer);
                Ok(true)
            }
            JournalRecord::CompactionBoundary { .. } => {
                // Compaction boundaries are metadata, don't affect state
                Ok(true)
            }
            JournalRecord::ProofDigest { transfer_id, .. } => {
                self.ensure_transfer(transfer_id);
                Ok(true)
            }
        };
        // A rejected transition has not been applied. Do not suppress a later
        // retry after its prerequisite arrives, or count another rejection as
        // a successfully deduplicated record.
        if result.is_ok() {
            self.seen_records.insert(fingerprint);
        }
        result
    }

    /// Finalize recovery and return a conservative fixed-grid view of records.
    ///
    /// A cell is present only when recorded ranges cover it completely. Mixed
    /// states use their least advanced state; a partial cell remains unknown.
    /// The grid uses the largest recorded chunk rather than a potentially
    /// byte-sized GCD, so variable-size records cannot cause byte-wise expansion.
    /// This view describes journal states, not revalidation of payload files.
    pub fn finalize(self) -> (HashMap<String, ChunkBitmap>, RecoveryStats) {
        let mut bitmaps = HashMap::new();
        let mut stats = self.stats;

        for (transfer_id, transfer_state) in self.transfers {
            if !transfer_state.chunk_states.is_empty() {
                let bitmap = transfer_state.into_bitmap(transfer_id.clone());
                stats.chunks_recovered += bitmap.entry_count();
                bitmaps.insert(transfer_id, bitmap);
                stats.transfers_recovered += 1;
            }
        }

        (bitmaps, stats)
    }

    // The public low-level finalizer is a diagnostic view of every record
    // state. Restart admission is narrower: only a resumable authenticated
    // summary AND an accepted Written transition can authorize reusable bytes.
    fn finalize_resumable(
        self,
        journal: &AppendJournal,
    ) -> Result<(HashMap<String, ChunkBitmap>, RecoveryStats), RecoveryError> {
        let mut bitmaps = HashMap::new();
        let mut stats = self.stats;
        let transfers: BTreeMap<_, _> = self.transfers.into_iter().collect();
        let mut names = HashSet::new();
        for (transfer_id, mut transfer) in transfers {
            let name = recovery_bitmap_name(&transfer_id)?;
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(RecoveryError::BitmapRecovery(
                    "transfer identifiers alias the same bitmap filename".to_owned(),
                ));
            }
            let summary = match journal.get_resume_summary(&transfer_id) {
                Outcome::Ok(summary) => summary,
                Outcome::Err(error) => {
                    return Err(RecoveryError::JournalCorrupted(error.to_string()));
                }
                Outcome::Cancelled(_) => {
                    return Err(RecoveryError::JournalCorrupted("resume summary cancelled".to_owned()));
                }
                Outcome::Panicked(_) => {
                    return Err(RecoveryError::JournalCorrupted("resume summary panicked".to_owned()));
                }
            };
            if !summary.is_resumable() {
                continue;
            }
            let Some(total_size) = summary.total_size else {
                // Chunk observations alone do not establish the offered object
                // extent. Keep them in the journal, not the active bitmap set.
                continue;
            };
            let mut durable = BTreeMap::new();
            for chunk in summary.durable_chunks {
                let id = ChunkId::from_u64(chunk.chunk_offset);
                if transfer.chunk_states.get(&id) == Some(&ChunkState::Written)
                    && transfer.chunk_sizes.get(&id) == Some(&chunk.chunk_size)
                {
                    durable.insert(id, chunk.chunk_size);
                }
            }
            transfer.chunk_sizes = durable;
            transfer.chunk_states.retain(|id, _| transfer.chunk_sizes.contains_key(id));
            transfer.total_size = Some(total_size);
            let bitmap = transfer.into_bitmap(transfer_id.clone());
            stats.chunks_recovered += bitmap.entry_count();
            stats.transfers_recovered += 1;
            bitmaps.insert(transfer_id, bitmap);
        }
        Ok((bitmaps, stats))
    }

    fn ensure_transfer(&mut self, transfer_id: &str) -> &mut TransferRecoveryState {
        self.transfers
            .entry(transfer_id.to_string())
            .or_insert_with(|| TransferRecoveryState {
                chunk_states: HashMap::new(),
                chunk_sizes: BTreeMap::new(),
                total_size: None,
                created_at: None,
                commit_intent_time: None,
                is_committed: false,
                is_cancelled: false,
            })
    }

    fn update_chunk_state(
        transfer: &mut TransferRecoveryState,
        chunk_offset: u64,
        chunk_size: u64,
        timestamp: u64,
        new_state: ChunkState,
    ) -> Result<(), RecoveryError> {
        let chunk_id = ChunkId::from_u64(chunk_offset);
        let current_state = transfer
            .chunk_states
            .get(&chunk_id)
            .copied()
            .unwrap_or(ChunkState::Wanted);

        // Validate state transition
        if !Self::is_valid_transition(current_state, new_state) {
            return Err(RecoveryError::InvalidStateTransition {
                from: current_state,
                to: new_state,
            });
        }

        // State advancement must never reuse a different range's geometry.
        // Check before mutation; a refused record is not deduplicated as applied.
        transfer.validate_chunk_geometry(chunk_id, chunk_size)?;
        transfer.record_chunk_geometry(chunk_id, chunk_size, timestamp);
        transfer.chunk_states.insert(chunk_id, new_state);
        Ok(())
    }

    fn is_valid_transition(from: ChunkState, to: ChunkState) -> bool {
        match (from, to) {
            // Initial transitions from Wanted
            (ChunkState::Wanted, ChunkState::Received) => true,
            (ChunkState::Wanted, ChunkState::RepairDerived) => true,

            // Forward progression
            (ChunkState::Received, ChunkState::Verified) => true,
            (ChunkState::Verified, ChunkState::Written) => true,
            (ChunkState::Written, ChunkState::Committed) => true,
            (ChunkState::RepairDerived, ChunkState::Verified) => true,

            // Error states
            (_, ChunkState::Quarantined) => true,
            (_, ChunkState::Invalidated) => true,

            // Stay in same state (idempotent)
            (a, b) if a == b => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    fn commit_all_chunks(transfer: &mut TransferRecoveryState) {
        for state in transfer.chunk_states.values_mut() {
            if *state == ChunkState::Written {
                *state = ChunkState::Committed;
            }
        }
    }

    fn rollback_uncommitted_chunks(transfer: &mut TransferRecoveryState) {
        transfer.chunk_states.retain(|_, state| {
            matches!(
                *state,
                ChunkState::Committed | ChunkState::Quarantined | ChunkState::Invalidated
            )
        });
        transfer
            .chunk_sizes
            .retain(|chunk_id, _| transfer.chunk_states.contains_key(chunk_id));
    }

    fn create_fingerprint(&self, record: &JournalRecord) -> RecordFingerprint {
        let (record_type, chunk_offset, timestamp) = match record {
            JournalRecord::Offer { timestamp, .. } => (0, None, *timestamp),
            JournalRecord::Accept { timestamp, .. } => (1, None, *timestamp),
            JournalRecord::ChunkReceived {
                chunk_offset,
                timestamp,
                ..
            } => (2, Some(*chunk_offset), *timestamp),
            JournalRecord::ChunkVerified {
                chunk_offset,
                timestamp,
                ..
            } => (3, Some(*chunk_offset), *timestamp),
            JournalRecord::ChunkWritten {
                chunk_offset,
                timestamp,
                ..
            } => (4, Some(*chunk_offset), *timestamp),
            JournalRecord::RepairDecode {
                chunk_offset,
                timestamp,
                ..
            } => (5, Some(*chunk_offset), *timestamp),
            JournalRecord::CommitIntent { timestamp, .. } => (6, None, *timestamp),
            JournalRecord::CommitComplete { timestamp, .. } => (7, None, *timestamp),
            JournalRecord::Cancellation { timestamp, .. } => (8, None, *timestamp),
            JournalRecord::Rollback { timestamp, .. } => (9, None, *timestamp),
            JournalRecord::CompactionBoundary { timestamp, .. } => (10, None, *timestamp),
            JournalRecord::ProofDigest { timestamp, .. } => (11, None, *timestamp),
        };

        RecordFingerprint {
            transfer_id: record.transfer_id().unwrap_or("").to_string(),
            record_type,
            chunk_offset,
            timestamp,
            payload_tag: *record.auth_tag().as_bytes(),
        }
    }
}

impl TransferRecoveryState {
    fn validate_chunk_geometry(&self, id: ChunkId, size: u64) -> Result<(), RecoveryError> {
        let invalid = || RecoveryError::JournalCorrupted(
            "recovery chunk ranges are empty, overflowing, overlapping, or inconsistent".to_owned(),
        );
        let start = id.as_u64();
        let end = start.checked_add(size).filter(|_| size != 0).ok_or_else(invalid)?;
        if let Some(previous_size) = self.chunk_sizes.get(&id) {
            return if *previous_size == size { Ok(()) } else { Err(invalid()) };
        }
        if let Some((previous, previous_size)) = self.chunk_sizes.range(..id).next_back()
            && previous.as_u64().checked_add(*previous_size).is_none_or(|end| end > start)
        {
            return Err(invalid());
        }
        if let Some((next, _)) = self.chunk_sizes.range(id..).next()
            && next.as_u64() < end
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn record_offer(&mut self, total_size: u64, timestamp: u64) {
        self.total_size = Some(self.total_size.unwrap_or(total_size).max(total_size));
        self.created_at.get_or_insert(timestamp);
    }

    fn record_chunk_geometry(&mut self, chunk_id: ChunkId, chunk_size: u64, timestamp: u64) {
        if chunk_size > 0 {
            self.chunk_sizes.entry(chunk_id).or_insert(chunk_size);
        }
        self.created_at.get_or_insert(timestamp);
    }

    fn recovered_bitmap_geometry(&self) -> (u64, u64, u64) {
        let chunk_size = self.recovered_chunk_size().unwrap_or(4096);
        let max_recovered_end = self
            .chunk_sizes
            .iter()
            .filter_map(|(chunk_id, chunk_size)| chunk_id.as_u64().checked_add(*chunk_size))
            .max()
            .unwrap_or(0);
        let total_size = self
            .total_size
            .unwrap_or(max_recovered_end)
            .max(max_recovered_end);
        let created_at = self.created_at.unwrap_or(0);

        (total_size, chunk_size, created_at)
    }

    fn recovered_chunk_size(&self) -> Option<u64> {
        self.chunk_sizes.values().copied().max()
    }

    fn into_bitmap(self, transfer_id: String) -> ChunkBitmap {
        let (total, width, created_at) = self.recovered_bitmap_geometry();
        let mut bitmap = ChunkBitmap::new(transfer_id, total, width, created_at);
        let mut cell = None;
        let mut covered = 0;
        let mut complete_prefix = false;
        let mut common_state = None;

        // Each validated interval has length <= width, so it intersects at most
        // two cells. Skip holes arithmetically; never enumerate missing bytes or
        // a coprime GCD grid. Output size and work are proportional to records.
        for (id, size) in self.chunk_sizes {
            let Some(state) = self.chunk_states.get(&id).copied() else { continue; };
            let mut cursor = id.as_u64();
            let end = cursor + size; // Validated before insertion.
            while cursor < end {
                let start = (cursor / width) * width;
                let cell_end = start.saturating_add(width).min(total);
                let stop = end.min(cell_end);
                if cell != Some(start) {
                    cell = Some(start);
                    covered = start;
                    complete_prefix = true;
                    common_state = None;
                }
                if cursor != covered {
                    complete_prefix = false;
                }
                if complete_prefix {
                    let combined = common_state.map_or(state, |old| common_chunk_state(old, state));
                    common_state = Some(combined);
                    covered = stop;
                    if covered == cell_end {
                        // No constituent hash authenticates a differently sized
                        // projected cell. Keep hashes absent, as before recovery.
                        bitmap.update_chunk_state(start, combined, 0, None);
                    }
                }
                cursor = stop;
            }
        }
        bitmap
    }
}

fn common_chunk_state(a: ChunkState, b: ChunkState) -> ChunkState {
    match (a, b) {
        (ChunkState::Invalidated, _) | (_, ChunkState::Invalidated) => ChunkState::Invalidated,
        (ChunkState::Quarantined, _) | (_, ChunkState::Quarantined) => ChunkState::Quarantined,
        _ if a.priority() <= b.priority() => a,
        _ => b,
    }
}

/// Reconstruct active resume bitmaps from authenticated journal evidence.
///
/// Only resumable transfers with an offered length are activated. A reusable
/// cell needs complete coverage by matching verified/written records and valid
/// replay transitions. Received-only data and terminal/uncertain transfers are
/// not advertised as reusable after restart. The returned journal retains their
/// status and evidence. This does not rehash or reopen the actual payload files.
///
/// Authentication, summary and filename validation precede bitmap mutations.
/// Each replacement uses the existing synced atomic-write helper; publication
/// is per bitmap, not transactional across transfers. Its rename and directory
/// sync are synchronous, and a post-rename sync error does not mean rollback.
pub async fn recover_journal_and_bitmap(
    cx: &Cx,
    journal_path: &Path,
    bitmap_dir: &Path,
    auth_key: &AuthKey,
) -> Result<(AppendJournal, HashMap<String, ChunkBitmap>), RecoveryError> {
    let config = JournalConfig {
        base_dir: journal_path.parent().unwrap_or(journal_path).to_path_buf(),
        ..Default::default()
    };
    let journal = match AppendJournal::new(config, auth_key.clone()) {
        Outcome::Ok(j) => j,
        Outcome::Err(e) => {
            return Err(RecoveryError::JournalCorrupted(format!(
                "Failed to create journal: {:?}",
                e
            )));
        }
        Outcome::Cancelled(_) => {
            return Err(RecoveryError::JournalCorrupted(
                "Journal creation was cancelled".to_string(),
            ));
        }
        Outcome::Panicked(_) => {
            return Err(RecoveryError::JournalCorrupted(
                "Journal creation panicked".to_string(),
            ));
        }
    };

    let mut context = RecoveryContext::new();

    // Process all journal entries
    let entries = match journal.get_all_entries(cx).await {
        Outcome::Ok(entries) => entries,
        Outcome::Err(e) => {
            return Err(RecoveryError::JournalCorrupted(format!(
                "Failed to read entries: {}",
                e
            )));
        }
        Outcome::Cancelled(_) => {
            return Err(RecoveryError::JournalCorrupted(
                "journal read cancelled".to_string(),
            ));
        }
        Outcome::Panicked(_) => {
            return Err(RecoveryError::JournalCorrupted(
                "journal read panicked".to_string(),
            ));
        }
    };

    for entry in entries {
        match context.process_record(&entry, auth_key) {
            Ok(_) => {}
            Err(RecoveryError::InvalidStateTransition { .. }) => {
                context.stats.corrupted_skipped += 1;
            }
            // Publication cannot silently omit an unauthenticated cancellation
            // or commit boundary and then reactivate an earlier valid prefix.
            Err(error) => return Err(error),
        }
    }

    let (bitmaps, stats) = context.finalize_resumable(&journal)?;

    fs::create_dir_all(bitmap_dir).await?;
    let stale_bitmaps_quarantined = quarantine_stale_bitmap_files(bitmap_dir, &bitmaps).await?;

    // Export recovered bitmaps to disk. Each bitmap is written atomically as
    // its canonical serialized form so a subsequent `load_recovered_or_create_bitmap`
    // call can reconstruct the exact same state — this is the on-disk side of
    // the crash-recovery contract.
    let ordered: BTreeMap<_, _> = bitmaps.iter().collect();
    for (transfer_id, bitmap) in ordered {
        let bitmap_path = bitmap_dir.join(recovery_bitmap_name(transfer_id)?);
        let exported = bitmap.serialize_to_bytes();
        fs::write_atomic(&bitmap_path, exported).await?;
    }

    cx.trace(&format!(
        "Recovery completed: {} transfers, {} chunks, {} records processed ({} duplicates, {} corrupted, {} stale bitmaps quarantined)",
        stats.transfers_recovered,
        stats.chunks_recovered,
        stats.total_records,
        stats.duplicates_skipped,
        stats.corrupted_skipped,
        stale_bitmaps_quarantined
    ));

    Ok((journal, bitmaps))
}

fn recovery_bitmap_name(transfer_id: &str) -> Result<String, RecoveryError> {
    // Transfer IDs are journal data, not paths. Reject separators on either OS,
    // Windows stream syntax and nonportable filename characters before joining.
    // Ordinary Unicode identifiers remain supported; this is not general
    // filesystem Unicode/alias normalization or parent-path confinement.
    if transfer_id.is_empty() || transfer_id.chars().any(|ch| {
        ch.is_control() || matches!(ch, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
    }) {
        return Err(RecoveryError::BitmapRecovery(
            "transfer identifier is not a portable bitmap filename component".to_owned(),
        ));
    }
    Ok(format!("transfer_{transfer_id}.bitmap"))
}

async fn quarantine_stale_bitmap_files(
    bitmap_dir: &Path,
    recovered_bitmaps: &HashMap<String, ChunkBitmap>,
) -> Result<usize, RecoveryError> {
    let mut entries = match fs::read_dir(bitmap_dir).await {
        Ok(entries) => entries,
        Err(e) => {
            if matches!(e.kind(), io::ErrorKind::NotFound) {
                return Ok(0);
            }
            return Err(RecoveryError::Io(e));
        }
    };

    let mut quarantined = 0usize;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(transfer_id) = transfer_id_from_bitmap_path(&path) else {
            continue;
        };
        if recovered_bitmaps.contains_key(transfer_id) {
            continue;
        }

        let quarantine_path = next_stale_bitmap_path(&path).await?;
        fs::rename(&path, &quarantine_path).await?;
        quarantined = quarantined.saturating_add(1);
    }

    Ok(quarantined)
}

fn transfer_id_from_bitmap_path(path: &Path) -> Option<&str> {
    let file_name = path.file_name()?.to_str()?;
    let transfer_id = file_name
        .strip_prefix("transfer_")?
        .strip_suffix(".bitmap")?;
    (!transfer_id.is_empty()).then_some(transfer_id)
}

async fn next_stale_bitmap_path(path: &Path) -> Result<PathBuf, RecoveryError> {
    let mut candidate = path.with_extension("bitmap.stale");
    if !fs::try_exists(&candidate).await? {
        return Ok(candidate);
    }

    for suffix in 1u32..=u32::MAX {
        candidate = path.with_extension(format!("bitmap.stale-{suffix}"));
        if !fs::try_exists(&candidate).await? {
            return Ok(candidate);
        }
    }

    Err(RecoveryError::BitmapRecovery(format!(
        "could not find non-conflicting stale bitmap quarantine path for {}",
        path.display()
    )))
}

// Legacy diagnostic replay may count invalid records and continue. The public
// disk recovery path above is deliberately stricter before publishing progress.
#[cfg(test)]
fn process_recovery_record(
    context: &mut RecoveryContext,
    record: &JournalRecord,
    auth_key: &AuthKey,
) -> Result<(), RecoveryError> {
    match context.process_record(record, auth_key) {
        Ok(_) => Ok(()),
        Err(RecoveryError::InvalidStateTransition { .. } | RecoveryError::InvalidSignature) => {
            // Skip individual corrupted or unverifiable records but keep replaying
            // later records so a single bad append does not discard the valid
            // committed prefix recovered before it.
            context.stats.corrupted_skipped += 1;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Load an existing chunk bitmap from disk when journal replay accepted it.
///
/// Returns `Ok(None)` when the transfer id derived from `bitmap_path` was not
/// reconstructed by the journal replay. That intentionally leaves stale bitmap
/// files on disk without trusting them: a rolled-back or empty transfer can no
/// longer resurrect old progress simply because `transfer_<id>.bitmap` still
/// exists.
///
/// Malformed, truncated, or mismatched accepted bitmaps fail closed with
/// `RecoveryError::BitmapRecovery` rather than silently degrading to an empty
/// bitmap; losing chunk state on restart would let a partially-completed
/// transfer re-fetch already-verified data and overwrite the disk image.
///
/// The fallback path constructs an empty bitmap that derives its `transfer_id`
/// from the on-disk filename (`transfer_<id>.bitmap`) only after the journal
/// replay admits that transfer id.
pub async fn load_recovered_or_create_bitmap<S: std::hash::BuildHasher + Sync>(
    bitmap_path: &Path,
    journal_recovered_transfers: &HashSet<String, S>,
) -> Result<Option<ChunkBitmap>, RecoveryError> {
    let transfer_id = required_transfer_id_from_bitmap_path(bitmap_path)?;
    if !journal_recovered_transfers.contains(&transfer_id) {
        return Ok(None);
    }

    match fs::read(bitmap_path).await {
        Ok(data) => {
            let bitmap = ChunkBitmap::deserialize_from_bytes(&data)
                .map_err(|e| RecoveryError::BitmapRecovery(e.to_string()))?;
            accept_recovered_bitmap(bitmap_path, bitmap, journal_recovered_transfers)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(Some(ChunkBitmap::new(transfer_id, 0, 4096, 0)))
        }
        Err(e) => Err(RecoveryError::Io(e)),
    }
}

fn accept_recovered_bitmap<S: std::hash::BuildHasher>(
    bitmap_path: &Path,
    bitmap: ChunkBitmap,
    journal_recovered_transfers: &HashSet<String, S>,
) -> Result<Option<ChunkBitmap>, RecoveryError> {
    let transfer_id = required_transfer_id_from_bitmap_path(bitmap_path)?;
    if !journal_recovered_transfers.contains(&transfer_id) {
        return Ok(None);
    }

    if bitmap.transfer_id() != transfer_id {
        return Err(RecoveryError::BitmapRecovery(format!(
            "bitmap transfer id mismatch: path declares {transfer_id}, payload declares {}",
            bitmap.transfer_id()
        )));
    }

    Ok(Some(bitmap))
}

fn required_transfer_id_from_bitmap_path(bitmap_path: &Path) -> Result<String, RecoveryError> {
    transfer_id_from_bitmap_path(bitmap_path)
        .map(str::to_string)
        .ok_or_else(|| {
            RecoveryError::BitmapRecovery(format!(
                "bitmap path does not use transfer_<id>.bitmap naming: {}",
                bitmap_path.display()
            ))
        })
}

#[cfg(test)]
#[path = "recovery/range_tests.rs"]
mod range_tests;

#[cfg(test)]
#[path = "recovery/resume_tests.rs"]
mod resume_tests;

#[cfg(test)]
#[path = "recovery_inline_tests.rs"]
mod tests;
