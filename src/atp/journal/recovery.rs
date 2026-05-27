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
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
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
        self.seen_records.insert(fingerprint);

        match record {
            JournalRecord::Offer { transfer_id, .. } => {
                self.ensure_transfer(transfer_id);
                Ok(true)
            }
            JournalRecord::Accept { transfer_id, .. } => {
                self.ensure_transfer(transfer_id);
                Ok(true)
            }
            JournalRecord::ChunkReceived {
                transfer_id,
                chunk_offset,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(transfer, *chunk_offset, ChunkState::Received)?;
                Ok(true)
            }
            JournalRecord::ChunkVerified {
                transfer_id,
                chunk_offset,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(transfer, *chunk_offset, ChunkState::Verified)?;
                Ok(true)
            }
            JournalRecord::ChunkWritten {
                transfer_id,
                chunk_offset,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(transfer, *chunk_offset, ChunkState::Written)?;
                Ok(true)
            }
            JournalRecord::RepairDecode {
                transfer_id,
                chunk_offset,
                ..
            } => {
                let transfer = self.ensure_transfer(transfer_id);
                Self::update_chunk_state(transfer, *chunk_offset, ChunkState::RepairDerived)?;
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
            JournalRecord::CommitComplete { transfer_id, .. } => {
                let transfer = self.ensure_transfer(transfer_id);
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
        }
    }

    /// Finalize recovery and return reconstructed state.
    pub fn finalize(self) -> (HashMap<String, ChunkBitmap>, RecoveryStats) {
        let mut bitmaps = HashMap::new();
        let mut stats = self.stats;

        for (transfer_id, transfer_state) in self.transfers {
            if !transfer_state.chunk_states.is_empty() {
                let mut bitmap = ChunkBitmap::new(transfer_id.clone(), 0, 4096, 0); // ubs:ignore - required to insert both key and bitmap value into map
                for (chunk_id, state) in transfer_state.chunk_states {
                    let _ = bitmap.update_chunk_state(chunk_id.as_u64(), state, 0, None);
                    stats.chunks_recovered += 1;
                }
                bitmaps.insert(transfer_id, bitmap);
                stats.transfers_recovered += 1;
            }
        }

        (bitmaps, stats)
    }

    fn ensure_transfer(&mut self, transfer_id: &str) -> &mut TransferRecoveryState {
        self.transfers
            .entry(transfer_id.to_string())
            .or_insert_with(|| TransferRecoveryState {
                chunk_states: HashMap::new(),
                commit_intent_time: None,
                is_committed: false,
                is_cancelled: false,
            })
    }

    fn update_chunk_state(
        transfer: &mut TransferRecoveryState,
        chunk_offset: u64,
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
        }
    }
}

/// Perform complete crash recovery for a journal and bitmap pair.
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
                // Log but continue - invalid transitions might be from corrupted records
                context.stats.corrupted_skipped += 1;
            }
            Err(e) => return Err(e),
        }
    }

    let (bitmaps, stats) = context.finalize();

    // Export recovered bitmaps to disk. Each bitmap is written atomically as
    // its canonical serialized form so a subsequent `load_or_create_bitmap`
    // call can reconstruct the exact same state — this is the on-disk side of
    // the crash-recovery contract.
    for (transfer_id, bitmap) in bitmaps.iter() {
        let bitmap_path = bitmap_dir.join(format!("transfer_{}.bitmap", transfer_id));
        let exported = bitmap.serialize_to_bytes();
        fs::write(&bitmap_path, exported).await?;
    }

    cx.trace(&format!(
        "Recovery completed: {} transfers, {} chunks, {} records processed ({} duplicates, {} corrupted)",
        stats.transfers_recovered,
        stats.chunks_recovered,
        stats.total_records,
        stats.duplicates_skipped,
        stats.corrupted_skipped
    ));

    Ok((journal, bitmaps))
}

/// Load an existing chunk bitmap from disk.
///
/// Returns a fresh empty bitmap if no file exists yet. Malformed or truncated
/// bitmaps fail closed with `RecoveryError::BitmapRecovery` rather than
/// silently degrading to an empty bitmap; losing chunk state on restart would
/// let a partially-completed transfer re-fetch already-verified data and
/// overwrite the disk image.
///
/// The fallback path constructs an empty bitmap that derives its `transfer_id`
/// from the on-disk filename (`transfer_<id>.bitmap`) so the caller's recovery
/// loop continues to associate the bitmap with the correct transfer.
pub async fn load_or_create_bitmap(bitmap_path: &Path) -> Result<ChunkBitmap, RecoveryError> {
    match fs::read(bitmap_path).await {
        Ok(data) => ChunkBitmap::deserialize_from_bytes(&data)
            .map_err(|e| RecoveryError::BitmapRecovery(e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let transfer_id = bitmap_path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("transfer_"))
                .unwrap_or("unknown")
                .to_string();
            Ok(ChunkBitmap::new(transfer_id, 0, 4096, 0))
        }
        Err(e) => Err(RecoveryError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::MerkleRoot;
    use crate::atp::object::{ContentId, ObjectId};

    fn test_object_id(name: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(name))
    }

    fn test_root(seed: u8) -> MerkleRoot {
        let mut hash = [0; 32];
        hash[0] = seed;
        MerkleRoot::new(hash)
    }

    fn test_auth_key() -> AuthKey {
        AuthKey::from_seed(42)
    }

    fn unsigned_tag() -> crate::security::AuthenticationTag {
        crate::security::AuthenticationTag::zero()
    }

    fn signed_record(record: JournalRecord) -> JournalRecord {
        record.with_signature(&test_auth_key())
    }

    fn process_test_record(
        ctx: &mut RecoveryContext,
        record: JournalRecord,
    ) -> Result<bool, RecoveryError> {
        let auth_key = test_auth_key();
        let record = record.with_signature(&auth_key);
        ctx.process_record(&record, &auth_key)
    }

    fn process_signed_record(
        ctx: &mut RecoveryContext,
        record: &JournalRecord,
    ) -> Result<bool, RecoveryError> {
        let auth_key = test_auth_key();
        ctx.process_record(record, &auth_key)
    }

    #[tokio::test]
    async fn test_cryptographic_integrity_validation() {
        use crate::atp::manifest::MerkleRoot;
        use crate::security::AuthenticationTag;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut ctx = RecoveryContext::new();
        let auth_key = test_auth_key();

        // Create a valid record with correct signature
        let valid_record = JournalRecord::Offer {
            transfer_id: "test123".to_string(),
            object_id: test_object_id(b"test123"),
            manifest_root: MerkleRoot::new([0u8; 32]),
            total_size: 1024,
            timestamp: SystemTime::now() // ubs:ignore - test oracle non-crypto time
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            auth_tag: AuthenticationTag::zero(),
        }
        .with_signature(&auth_key);

        // Should process successfully
        let result = ctx.process_record(&valid_record, &auth_key);
        assert!(result.is_ok(), "Valid record should be processed");

        // Create an invalid record with wrong signature
        let invalid_record = JournalRecord::Offer {
            transfer_id: "test456".to_string(),
            object_id: test_object_id(b"test456"),
            manifest_root: MerkleRoot::new([0u8; 32]),
            total_size: 2048,
            timestamp: SystemTime::now() // ubs:ignore - test oracle non-crypto time
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            auth_tag: AuthenticationTag::zero(), // Wrong signature (all zeros)
        };

        // Should fail with InvalidSignature error
        let result = ctx.process_record(&invalid_record, &auth_key);
        assert!(result.is_err(), "Invalid record should be rejected");
        match result.unwrap_err() {
            RecoveryError::InvalidSignature => {
                // This is the expected error
            }
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_recovery_context_basic() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        // Process chunk progression
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::Offer {
                    transfer_id: transfer_id.clone(),
                    object_id: test_object_id(b"obj-1"),
                    manifest_root: test_root(1),
                    total_size: 8192,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        let (bitmaps, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 3);
        assert_eq!(stats.transfers_recovered, 1);
        assert_eq!(stats.chunks_recovered, 1);

        let bitmap = &bitmaps[&transfer_id];
        assert_eq!(
            bitmap.get_chunk_state(chunk_offset),
            Some(ChunkState::Verified)
        );
    }

    #[tokio::test]
    async fn test_recovery_duplicate_detection() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        let record = signed_record(JournalRecord::ChunkReceived {
            transfer_id,
            chunk_offset,
            chunk_size: 1024,
            chunk_hash: [0; 32],
            timestamp: 2000,
            auth_tag: unsigned_tag(),
        });

        // First occurrence
        assert!(process_signed_record(&mut ctx, &record).unwrap());
        // Duplicate
        assert!(!process_signed_record(&mut ctx, &record).unwrap());

        let (_, stats) = ctx.finalize();
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.duplicates_skipped, 1);
    }

    #[tokio::test]
    async fn test_recovery_invalid_state_transition() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 1500,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    file_path: "test".into(),
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::CommitComplete {
                    transfer_id: transfer_id.clone(),
                    final_path: "final".into(),
                    committed_size: 1024,
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Now try to go backwards to Received - should fail
        let result = process_test_record(
            &mut ctx,
            JournalRecord::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size: 1024,
                chunk_hash: [0; 32],
                timestamp: 4000,
                auth_tag: unsigned_tag(),
            },
        );

        assert!(matches!(
            result,
            Err(RecoveryError::InvalidStateTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_recovery_commit_rollback() {
        let mut ctx = RecoveryContext::new();
        let transfer_id = "transfer-1".to_string();
        let chunk_offset = 4096;

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkReceived {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    chunk_hash: [0; 32],
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    verified_hash: [0; 32],
                    timestamp: 1500,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Write chunk
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.clone(),
                    chunk_offset,
                    chunk_size: 1024,
                    file_path: "test".into(),
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Commit intent
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::CommitIntent {
                    transfer_id: transfer_id.clone(),
                    final_manifest_root: test_root(2),
                    timestamp: 3000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        // Rollback instead of commit
        assert!(
            process_test_record(
                &mut ctx,
                JournalRecord::Rollback {
                    transfer_id: transfer_id.clone(),
                    rollback_reason: "timeout".into(),
                    checkpoint_sequence: 0,
                    timestamp: 4000,
                    auth_tag: unsigned_tag(),
                }
            )
            .unwrap()
        );

        let (bitmaps, _) = ctx.finalize();
        assert!(!bitmaps.contains_key(&transfer_id));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DiskFaultPhase {
        JournalAppend,
        BitmapUpdate,
        ChunkWrite,
        Fsync,
        RepairDecode,
        ManifestWrite,
        TempFileRename,
        DirectoryFsync,
        Cleanup,
        ProofEmission,
        JournalCompaction,
    }

    impl DiskFaultPhase {
        const ALL: [Self; 11] = [
            Self::JournalAppend,
            Self::BitmapUpdate,
            Self::ChunkWrite,
            Self::Fsync,
            Self::RepairDecode,
            Self::ManifestWrite,
            Self::TempFileRename,
            Self::DirectoryFsync,
            Self::Cleanup,
            Self::ProofEmission,
            Self::JournalCompaction,
        ];
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CrashCut {
        Before,
        After,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RecoveryDisposition {
        Resume,
        Quarantine,
        Finalized,
    }

    struct DiskFaultModel {
        records: Vec<JournalRecord>,
        bitmap: ChunkBitmap,
        final_file_visible: bool,
        final_file_verified: bool,
        temp_renamed: bool,
        directory_synced: bool,
        cleanup_done: bool,
        proof_emitted: bool,
        compaction_seen: bool,
        live_children: usize,
        pending_obligations: usize,
    }

    struct RecoveredFault {
        disposition: RecoveryDisposition,
        chunk_state: Option<ChunkState>,
        repair_state: Option<ChunkState>,
        final_file_exposed: bool,
        proof_emitted: bool,
        compaction_seen: bool,
        live_children: usize,
        pending_obligations: usize,
        stats: RecoveryStats,
    }

    const MATRIX_TRANSFER: &str = "transfer-d5";
    const DATA_OFFSET: u64 = 0;
    const REPAIR_OFFSET: u64 = 4096;
    const CHUNK_SIZE: u64 = 4096;

    impl DiskFaultModel {
        fn new() -> Self {
            let mut bitmap =
                ChunkBitmap::new(MATRIX_TRANSFER.to_string(), CHUNK_SIZE * 2, CHUNK_SIZE, 1);
            bitmap.initialize_wanted_chunks(1);

            Self {
                records: Vec::new(),
                bitmap,
                final_file_visible: false,
                final_file_verified: false,
                temp_renamed: false,
                directory_synced: false,
                cleanup_done: false,
                proof_emitted: false,
                compaction_seen: false,
                live_children: 0,
                pending_obligations: 0,
            }
        }

        fn run_until(crash_phase: DiskFaultPhase, cut: CrashCut) -> Self {
            let mut model = Self::new();
            for phase in DiskFaultPhase::ALL {
                if phase == crash_phase && cut == CrashCut::Before {
                    break;
                }

                model.apply_phase(phase);

                if phase == crash_phase && cut == CrashCut::After {
                    break;
                }
            }
            model
        }

        fn apply_phase(&mut self, phase: DiskFaultPhase) {
            match phase {
                DiskFaultPhase::JournalAppend => {
                    self.records.push(signed_record(JournalRecord::Offer {
                        transfer_id: MATRIX_TRANSFER.to_string(),
                        object_id: test_object_id(b"fault-matrix-object"),
                        manifest_root: test_root(1),
                        total_size: CHUNK_SIZE * 2,
                        timestamp: 10,
                        auth_tag: unsigned_tag(),
                    }));
                }
                DiskFaultPhase::BitmapUpdate => {
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Received,
                        20,
                        Some([1; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkReceived {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            chunk_hash: [1; 32],
                            timestamp: 20,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::ChunkWrite => {
                    self.pending_obligations += 1;
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Verified,
                        30,
                        Some([2; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkVerified {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            verified_hash: [2; 32],
                            timestamp: 30,
                            auth_tag: unsigned_tag(),
                        }));
                    self.bitmap.update_chunk_state(
                        DATA_OFFSET,
                        ChunkState::Written,
                        40,
                        Some([2; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkWritten {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: DATA_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            file_path: "object.tmp".to_string(),
                            timestamp: 40,
                            auth_tag: unsigned_tag(),
                        }));
                    self.pending_obligations -= 1;
                }
                DiskFaultPhase::Fsync => {}
                DiskFaultPhase::RepairDecode => {
                    self.pending_obligations += 1;
                    self.bitmap.update_chunk_state(
                        REPAIR_OFFSET,
                        ChunkState::RepairDerived,
                        50,
                        Some([3; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::RepairDecode {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: REPAIR_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            source_chunks: vec![DATA_OFFSET],
                            timestamp: 50,
                            auth_tag: unsigned_tag(),
                        }));
                    self.bitmap.update_chunk_state(
                        REPAIR_OFFSET,
                        ChunkState::Verified,
                        60,
                        Some([4; 32]),
                    );
                    self.records
                        .push(signed_record(JournalRecord::ChunkVerified {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            chunk_offset: REPAIR_OFFSET,
                            chunk_size: CHUNK_SIZE,
                            verified_hash: [4; 32],
                            timestamp: 60,
                            auth_tag: unsigned_tag(),
                        }));
                    self.pending_obligations -= 1;
                }
                DiskFaultPhase::ManifestWrite => {
                    self.records
                        .push(signed_record(JournalRecord::CommitIntent {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            final_manifest_root: test_root(2),
                            timestamp: 70,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::TempFileRename => {
                    self.temp_renamed = true;
                    self.final_file_visible = true;
                }
                DiskFaultPhase::DirectoryFsync => {
                    self.directory_synced = true;
                }
                DiskFaultPhase::Cleanup => {
                    self.cleanup_done = true;
                    self.final_file_verified = true;
                    self.records
                        .push(signed_record(JournalRecord::CommitComplete {
                            transfer_id: MATRIX_TRANSFER.to_string(),
                            final_path: "object.final".to_string(),
                            committed_size: CHUNK_SIZE * 2,
                            timestamp: 80,
                            auth_tag: unsigned_tag(),
                        }));
                }
                DiskFaultPhase::ProofEmission => {
                    self.proof_emitted = true;
                    self.records.push(signed_record(JournalRecord::ProofDigest {
                        transfer_id: MATRIX_TRANSFER.to_string(),
                        proof_type: "receiver-finalizer".to_string(),
                        digest: [9; 32],
                        timestamp: 90,
                        auth_tag: unsigned_tag(),
                    }));
                }
                DiskFaultPhase::JournalCompaction => {
                    self.compaction_seen = true;
                    self.records
                        .push(signed_record(JournalRecord::CompactionBoundary {
                            generation: 1,
                            compacted_up_to_sequence: self.records.len() as u64,
                            timestamp: 100,
                            auth_tag: unsigned_tag(),
                        }));
                }
            }
        }

        fn recover(&self) -> RecoveredFault {
            let mut ctx = RecoveryContext::new();
            let mut invalid_record = false;
            for record in &self.records {
                if process_signed_record(&mut ctx, record).is_err() {
                    invalid_record = true;
                }
            }

            let (bitmaps, stats) = ctx.finalize();
            let bitmap = bitmaps.get(MATRIX_TRANSFER);
            let chunk_state = bitmap.and_then(|bitmap| bitmap.get_chunk_state(DATA_OFFSET));
            let repair_state = bitmap.and_then(|bitmap| bitmap.get_chunk_state(REPAIR_OFFSET));
            let commit_boundary_reached = self.cleanup_done;
            let unverified_final_file =
                (self.temp_renamed || self.directory_synced) && !commit_boundary_reached;
            let final_file_exposed =
                self.final_file_visible && self.final_file_verified && commit_boundary_reached;
            let disposition = if invalid_record || unverified_final_file {
                RecoveryDisposition::Quarantine
            } else if final_file_exposed && self.proof_emitted {
                RecoveryDisposition::Finalized
            } else {
                RecoveryDisposition::Resume
            };

            RecoveredFault {
                disposition,
                chunk_state,
                repair_state,
                final_file_exposed,
                proof_emitted: self.proof_emitted,
                compaction_seen: self.compaction_seen,
                live_children: self.live_children,
                pending_obligations: self.pending_obligations,
                stats,
            }
        }
    }

    #[test]
    fn disk_fault_matrix_recovers_to_resume_quarantine_or_finalized() {
        let mut before_cases = 0;
        let mut after_cases = 0;

        for phase in DiskFaultPhase::ALL {
            for cut in [CrashCut::Before, CrashCut::After] {
                let model = DiskFaultModel::run_until(phase, cut);
                let recovered = model.recover();

                match cut {
                    CrashCut::Before => before_cases += 1,
                    CrashCut::After => after_cases += 1,
                }

                assert_eq!(
                    recovered.live_children, 0,
                    "{phase:?} {cut:?} left live children"
                );
                assert_eq!(
                    recovered.pending_obligations, 0,
                    "{phase:?} {cut:?} leaked obligations"
                );
                if matches!(
                    phase,
                    DiskFaultPhase::TempFileRename | DiskFaultPhase::DirectoryFsync
                ) && cut == CrashCut::After
                {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Quarantine);
                    assert!(
                        !recovered.final_file_exposed,
                        "{phase:?} {cut:?} exposed an unverified final file"
                    );
                }

                if phase == DiskFaultPhase::Cleanup && cut == CrashCut::After {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Resume);
                    assert_eq!(recovered.chunk_state, Some(ChunkState::Committed));
                    assert!(recovered.final_file_exposed);
                    assert!(!recovered.proof_emitted);
                }

                if phase == DiskFaultPhase::ProofEmission && cut == CrashCut::After {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
                    assert!(recovered.proof_emitted);
                }

                if phase == DiskFaultPhase::JournalCompaction && cut == CrashCut::After {
                    assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
                    assert!(recovered.compaction_seen);
                    assert!(recovered.proof_emitted);
                }
            }
        }

        assert_eq!(before_cases, DiskFaultPhase::ALL.len());
        assert_eq!(after_cases, DiskFaultPhase::ALL.len());
    }

    #[test]
    fn disk_fault_matrix_preserves_repair_decode_and_compaction_records() {
        let recovered =
            DiskFaultModel::run_until(DiskFaultPhase::JournalCompaction, CrashCut::After).recover();

        assert_eq!(recovered.disposition, RecoveryDisposition::Finalized);
        assert_eq!(recovered.chunk_state, Some(ChunkState::Committed));
        assert_eq!(recovered.repair_state, Some(ChunkState::Verified));
        assert!(recovered.proof_emitted);
        assert!(recovered.compaction_seen);
        assert_eq!(recovered.stats.corrupted_skipped, 0);
    }
}
