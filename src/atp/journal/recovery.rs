//! Recovery mechanisms for append-only journal and chunk bitmap.
//!
//! Handles crash recovery scenarios including torn appends, duplicate records,
//! checksum validation, and state reconstruction after process kill.

use super::{AppendJournal, ChunkBitmap, ChunkState, JournalRecord, JournalConfig};
use crate::atp::transfer::TransferId;

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
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use thiserror::Error;
use crate::fs;
use hex;
use bincode;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Journal file corrupted: {0}")]
    JournalCorrupted(String),
    #[error("Checksum mismatch at offset {offset}: expected {expected:x}, got {actual:x}")]
    ChecksumMismatch { offset: u64, expected: u64, actual: u64 },
    #[error("Incomplete record at offset {0}: file truncated")]
    IncompleteRecord(u64),
    #[error("Invalid chunk state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: ChunkState, to: ChunkState },
    #[error("IO error during recovery: {0}")]
    Io(#[from] io::Error),
    #[error("Bitmap recovery failed: {0}")]
    BitmapRecovery(String),
}

/// Recovery context for tracking state during crash recovery.
pub struct RecoveryContext {
    /// Current transfer states being recovered
    transfers: HashMap<TransferId, TransferRecoveryState>,
    /// Duplicate record detection
    seen_records: HashSet<RecordFingerprint>,
    /// Recovery statistics
    stats: RecoveryStats,
}

#[derive(Debug)]
struct TransferRecoveryState {
    /// Chunk states being reconstructed
    chunk_states: HashMap<ChunkId, ChunkState>,
    /// Last seen commit intent timestamp
    commit_intent_time: Option<u64>,
    /// Whether this transfer was committed
    is_committed: bool,
    /// Whether this transfer was cancelled
    is_cancelled: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RecordFingerprint {
    transfer_id: TransferId,
    record_type: u8,
    chunk_id: Option<ChunkId>,
    timestamp: u64,
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
    pub fn process_record(&mut self, record: &JournalRecord) -> Result<bool, RecoveryError> {
        self.stats.total_records += 1;

        // Check for duplicates
        let fingerprint = self.create_fingerprint(record);
        if self.seen_records.contains(&fingerprint) {
            self.stats.duplicates_skipped += 1;
            return Ok(false);
        }
        self.seen_records.insert(fingerprint);

        match record {
            JournalRecord::Offer { transfer_id, .. } => {
                self.ensure_transfer(*transfer_id);
                Ok(true)
            }
            JournalRecord::Accept { transfer_id, .. } => {
                self.ensure_transfer(*transfer_id);
                Ok(true)
            }
            JournalRecord::ChunkReceived { transfer_id, chunk_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                self.update_chunk_state(transfer, *chunk_id, ChunkState::Received)?;
                Ok(true)
            }
            JournalRecord::ChunkVerified { transfer_id, chunk_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                self.update_chunk_state(transfer, *chunk_id, ChunkState::Verified)?;
                Ok(true)
            }
            JournalRecord::ChunkWritten { transfer_id, chunk_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                self.update_chunk_state(transfer, *chunk_id, ChunkState::Written)?;
                Ok(true)
            }
            JournalRecord::RepairDecode { transfer_id, chunk_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                self.update_chunk_state(transfer, *chunk_id, ChunkState::RepairDerived)?;
                Ok(true)
            }
            JournalRecord::CommitIntent { transfer_id, timestamp, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                transfer.commit_intent_time = Some(*timestamp);
                Ok(true)
            }
            JournalRecord::CommitComplete { transfer_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                transfer.is_committed = true;
                self.commit_all_chunks(transfer);
                Ok(true)
            }
            JournalRecord::Cancellation { transfer_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                transfer.is_cancelled = true;
                Ok(true)
            }
            JournalRecord::Rollback { transfer_id, .. } => {
                let transfer = self.ensure_transfer(*transfer_id);
                transfer.is_committed = false;
                transfer.commit_intent_time = None;
                self.rollback_uncommitted_chunks(transfer);
                Ok(true)
            }
            JournalRecord::CompactionBoundary { .. } => {
                // Compaction boundaries are metadata, don't affect state
                Ok(true)
            }
            JournalRecord::ProofDigest { transfer_id, .. } => {
                self.ensure_transfer(*transfer_id);
                Ok(true)
            }
        }
    }

    /// Finalize recovery and return reconstructed state.
    pub fn finalize(self) -> (HashMap<TransferId, ChunkBitmap>, RecoveryStats) {
        let mut bitmaps = HashMap::new();
        let mut stats = self.stats;

        for (transfer_id, transfer_state) in self.transfers {
            if !transfer_state.chunk_states.is_empty() {
                let mut bitmap = ChunkBitmap::new(hex::encode(transfer_id.as_bytes()), 0, 4096, 0);
                for (chunk_id, state) in transfer_state.chunk_states {
                    let _ = bitmap.update_chunk_state(chunk_id, state);
                    stats.chunks_recovered += 1;
                }
                bitmaps.insert(transfer_id, bitmap);
                stats.transfers_recovered += 1;
            }
        }

        (bitmaps, stats)
    }

    fn ensure_transfer(&mut self, transfer_id: TransferId) -> &mut TransferRecoveryState {
        self.transfers.entry(transfer_id).or_insert_with(|| TransferRecoveryState {
            chunk_states: HashMap::new(),
            commit_intent_time: None,
            is_committed: false,
            is_cancelled: false,
        })
    }

    fn update_chunk_state(
        &mut self,
        transfer: &mut TransferRecoveryState,
        chunk_id: ChunkId,
        new_state: ChunkState,
    ) -> Result<(), RecoveryError> {
        let current_state = transfer.chunk_states.get(&chunk_id).copied().unwrap_or(ChunkState::Wanted);

        // Validate state transition
        if !self.is_valid_transition(current_state, new_state) {
            return Err(RecoveryError::InvalidStateTransition {
                from: current_state,
                to: new_state,
            });
        }

        transfer.chunk_states.insert(chunk_id, new_state);
        Ok(())
    }

    fn is_valid_transition(&self, from: ChunkState, to: ChunkState) -> bool {
        use ChunkState::*;
        match (from, to) {
            // Initial transitions from Wanted
            (Wanted, Received) => true,
            (Wanted, RepairDerived) => true,

            // Forward progression
            (Received, Verified) => true,
            (Verified, Written) => true,
            (Written, Committed) => true,
            (RepairDerived, Verified) => true,

            // Error states
            (_, Quarantined) => true,
            (_, Invalidated) => true,

            // Stay in same state (idempotent)
            (a, b) if a == b => true,

            // All other transitions are invalid
            _ => false,
        }
    }

    fn commit_all_chunks(&mut self, transfer: &mut TransferRecoveryState) {
        for (_, state) in transfer.chunk_states.iter_mut() {
            if *state == ChunkState::Written {
                *state = ChunkState::Committed;
            }
        }
    }

    fn rollback_uncommitted_chunks(&mut self, transfer: &mut TransferRecoveryState) {
        transfer.chunk_states.retain(|_, state| {
            matches!(*state, ChunkState::Committed | ChunkState::Quarantined | ChunkState::Invalidated)
        });
    }

    fn create_fingerprint(&self, record: &JournalRecord) -> RecordFingerprint {
        let (record_type, chunk_id, timestamp) = match record {
            JournalRecord::Offer { transfer_id, timestamp, .. } =>
                (0, None, *timestamp),
            JournalRecord::Accept { transfer_id, timestamp, .. } =>
                (1, None, *timestamp),
            JournalRecord::ChunkReceived { transfer_id, chunk_id, timestamp, .. } =>
                (2, Some(*chunk_id), *timestamp),
            JournalRecord::ChunkVerified { transfer_id, chunk_id, timestamp, .. } =>
                (3, Some(*chunk_id), *timestamp),
            JournalRecord::ChunkWritten { transfer_id, chunk_id, timestamp, .. } =>
                (4, Some(*chunk_id), *timestamp),
            JournalRecord::RepairDecode { transfer_id, chunk_id, timestamp, .. } =>
                (5, Some(*chunk_id), *timestamp),
            JournalRecord::CommitIntent { transfer_id, timestamp, .. } =>
                (6, None, *timestamp),
            JournalRecord::CommitComplete { transfer_id, timestamp, .. } =>
                (7, None, *timestamp),
            JournalRecord::Cancellation { transfer_id, timestamp, .. } =>
                (8, None, *timestamp),
            JournalRecord::Rollback { transfer_id, timestamp, .. } =>
                (9, None, *timestamp),
            JournalRecord::CompactionBoundary { timestamp, .. } =>
                (10, None, *timestamp),
            JournalRecord::ProofDigest { transfer_id, timestamp, .. } =>
                (11, None, *timestamp),
        };

        RecordFingerprint {
            transfer_id: match record {
                JournalRecord::CompactionBoundary { .. } => TransferId::from_u128(0), // Special case
                _ => *record.transfer_id(),
            },
            record_type,
            chunk_id,
            timestamp,
        }
    }
}

impl JournalRecord {
    fn transfer_id(&self) -> &TransferId {
        match self {
            JournalRecord::Offer { transfer_id, .. } => transfer_id,
            JournalRecord::Accept { transfer_id, .. } => transfer_id,
            JournalRecord::ChunkReceived { transfer_id, .. } => transfer_id,
            JournalRecord::ChunkVerified { transfer_id, .. } => transfer_id,
            JournalRecord::ChunkWritten { transfer_id, .. } => transfer_id,
            JournalRecord::RepairDecode { transfer_id, .. } => transfer_id,
            JournalRecord::CommitIntent { transfer_id, .. } => transfer_id,
            JournalRecord::CommitComplete { transfer_id, .. } => transfer_id,
            JournalRecord::Cancellation { transfer_id, .. } => transfer_id,
            JournalRecord::Rollback { transfer_id, .. } => transfer_id,
            JournalRecord::ProofDigest { transfer_id, .. } => transfer_id,
            JournalRecord::CompactionBoundary { .. } => panic!("CompactionBoundary has no transfer_id"),
        }
    }
}

/// Perform complete crash recovery for a journal and bitmap pair.
pub async fn recover_journal_and_bitmap(
    cx: &Cx,
    journal_path: &Path,
    bitmap_dir: &Path,
) -> Result<(AppendJournal, HashMap<TransferId, ChunkBitmap>), RecoveryError> {
    let config = JournalConfig {
        base_dir: journal_path.parent().unwrap_or(journal_path).to_path_buf(),
        ..Default::default()
    };
    let journal = match AppendJournal::new(config) {
        Outcome::Ok(j) => j,
        Outcome::Err(e) => return Err(RecoveryError::JournalCorrupted(format!("Failed to create journal: {:?}", e))),
        Outcome::Cancelled(_) => return Err(RecoveryError::JournalCorrupted("Journal creation was cancelled".to_string())),
        Outcome::Panicked(_) => return Err(RecoveryError::JournalCorrupted("Journal creation panicked".to_string())),
    };

    let mut context = RecoveryContext::new();

    // Process all journal entries
    let entries = journal.get_all_entries(cx).await.map_err(|e| {
        RecoveryError::JournalCorrupted(format!("Failed to read entries: {}", e))
    })?;

    for entry in entries {
        match context.process_record(&entry) {
            Ok(_) => {}
            Err(RecoveryError::InvalidStateTransition { .. }) => {
                // Log but continue - invalid transitions might be from corrupted records
                context.stats.corrupted_skipped += 1;
            }
            Err(e) => return Err(e),
        }
    }

    let (bitmaps, stats) = context.finalize();

    // Export recovered bitmaps to disk
    for (transfer_id, bitmap) in &bitmaps {
        let bitmap_path = bitmap_dir.join(format!("transfer_{}.bitmap", hex::encode(transfer_id.as_bytes())));
        let exported = bincode::serde::encode_to_vec(&bitmap.export_state(), bincode::config::legacy()).unwrap();
        fs::write(&bitmap_path, exported).await?;
    }

    tracing::info!(
        "Recovery completed: {} transfers, {} chunks, {} records processed ({} duplicates, {} corrupted)",
        stats.transfers_recovered,
        stats.chunks_recovered,
        stats.total_records,
        stats.duplicates_skipped,
        stats.corrupted_skipped
    );

    Ok((journal, bitmaps))
}

/// Load existing bitmap from disk or create new one.
pub async fn load_or_create_bitmap(
    bitmap_path: &Path,
) -> Result<ChunkBitmap, RecoveryError> {
    match fs::read(bitmap_path).await {
        Ok(data) => {
            let state: std::collections::HashMap<u64, (ChunkState, u64, Option<[u8; 32]>)> =
                bincode::serde::decode_from_slice(&data, bincode::config::legacy())
                .map_err(|e| RecoveryError::BitmapRecovery(format!("Failed to decode bitmap: {}", e)))?.0;

            let mut bitmap = ChunkBitmap::new("temp".to_string(), 0, 4096, 0);
            bitmap.import_state(state);
            Ok(bitmap)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(ChunkBitmap::new("temp".to_string(), 0, 4096, 0))
        }
        Err(e) => Err(RecoveryError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TransferId, ChunkId};
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_recovery_context_basic() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = TransferId::from_u128(1);
        let chunk_id = ChunkId::from_u64(1);

        // Process chunk progression
        assert!(ctx.process_record(&JournalRecord::Offer {
            transfer_id,
            timestamp: 1000,
            peer_id: vec![1, 2, 3],
            chunk_count: 10,
        }).unwrap());

        assert!(ctx.process_record(&JournalRecord::ChunkReceived {
            transfer_id,
            chunk_id,
            timestamp: 2000,
            hash: vec![0; 32],
            size: 1024,
        }).unwrap());

        assert!(ctx.process_record(&JournalRecord::ChunkVerified {
            transfer_id,
            chunk_id,
            timestamp: 3000,
            proof_hash: vec![0; 32],
        }).unwrap());

        let (bitmaps, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 3);
        assert_eq!(stats.transfers_recovered, 1);
        assert_eq!(stats.chunks_recovered, 1);

        let bitmap = &bitmaps[&transfer_id];
        assert_eq!(bitmap.get_chunk_state(chunk_id), Some(ChunkState::Verified));
    }

    #[tokio::test]
    async fn test_recovery_duplicate_detection() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = TransferId::from_u128(1);
        let chunk_id = ChunkId::from_u64(1);

        let record = JournalRecord::ChunkReceived {
            transfer_id,
            chunk_id,
            timestamp: 2000,
            hash: vec![0; 32],
            size: 1024,
        };

        // First occurrence
        assert!(ctx.process_record(&record).unwrap());
        // Duplicate
        assert!(!ctx.process_record(&record).unwrap());

        let (_, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.duplicates_skipped, 1);
    }

    #[tokio::test]
    async fn test_recovery_invalid_state_transition() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = TransferId::from_u128(1);
        let chunk_id = ChunkId::from_u64(1);

        // Set chunk to Committed first
        assert!(ctx.process_record(&JournalRecord::ChunkWritten {
            transfer_id,
            chunk_id,
            timestamp: 2000,
            path: "test".into(),
            size: 1024,
        }).unwrap());

        assert!(ctx.process_record(&JournalRecord::CommitComplete {
            transfer_id,
            timestamp: 3000,
        }).unwrap());

        // Now try to go backwards to Received - should fail
        let result = ctx.process_record(&JournalRecord::ChunkReceived {
            transfer_id,
            chunk_id,
            timestamp: 4000,
            hash: vec![0; 32],
            size: 1024,
        });

        assert!(matches!(result, Err(RecoveryError::InvalidStateTransition { .. })));
    }

    #[tokio::test]
    async fn test_recovery_commit_rollback() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = TransferId::from_u128(1);
        let chunk_id = ChunkId::from_u64(1);

        // Write chunk
        assert!(ctx.process_record(&JournalRecord::ChunkWritten {
            transfer_id,
            chunk_id,
            timestamp: 2000,
            path: "test".into(),
            size: 1024,
        }).unwrap());

        // Commit intent
        assert!(ctx.process_record(&JournalRecord::CommitIntent {
            transfer_id,
            timestamp: 3000,
        }).unwrap());

        // Rollback instead of commit
        assert!(ctx.process_record(&JournalRecord::Rollback {
            transfer_id,
            timestamp: 4000,
            reason: "timeout".into(),
        }).unwrap());

        let (bitmaps, _) = ctx.finalize();
        let bitmap = &bitmaps[&transfer_id];

        // Chunk should be removed by rollback
        assert_eq!(bitmap.get_chunk_state(chunk_id), None);
    }
}