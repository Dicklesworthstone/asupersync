//! Append-Only Journal for Crash-Safe Transfer Progress Tracking

use crate::atp::object::ObjectId;
use crate::atp::manifest::MerkleRoot;
use crate::types::outcome::Outcome;
use crate::cx::Cx;
use std::fs::{File, OpenOptions};
use std::io::{Write, Read, BufWriter, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Journal record types for tracking transfer progress
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    /// Transfer offer initiated
    Offer {
        transfer_id: String,
        object_id: ObjectId,
        manifest_root: MerkleRoot,
        total_size: u64,
        timestamp: u64,
    },
    /// Transfer offer accepted
    Accept {
        transfer_id: String,
        peer_id: String,
        timestamp: u64,
    },
    /// Chunk received from network
    ChunkReceived {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        chunk_hash: [u8; 32],
        timestamp: u64,
    },
    /// Chunk hash verified successfully
    ChunkVerified {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        verified_hash: [u8; 32],
        timestamp: u64,
    },
    /// Chunk written to disk
    ChunkWritten {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        file_path: String,
        timestamp: u64,
    },
    /// Chunk derived from repair decode
    RepairDecode {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        source_chunks: Vec<u64>,
        timestamp: u64,
    },
    /// Intent to commit transfer
    CommitIntent {
        transfer_id: String,
        final_manifest_root: MerkleRoot,
        timestamp: u64,
    },
    /// Transfer commit completed
    CommitComplete {
        transfer_id: String,
        final_path: String,
        committed_size: u64,
        timestamp: u64,
    },
    /// Transfer cancellation
    Cancellation {
        transfer_id: String,
        reason: String,
        timestamp: u64,
    },
    /// Transfer rollback due to error
    Rollback {
        transfer_id: String,
        rollback_reason: String,
        checkpoint_sequence: u64,
        timestamp: u64,
    },
    /// Journal compaction boundary
    CompactionBoundary {
        generation: u64,
        compacted_up_to_sequence: u64,
        timestamp: u64,
    },
    /// Proof digest for verification
    ProofDigest {
        transfer_id: String,
        proof_type: String,
        digest: [u8; 32],
        timestamp: u64,
    },
}

impl JournalRecord {

    /// Get the timestamp for this record
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Offer { timestamp, .. } |
            Self::Accept { timestamp, .. } |
            Self::ChunkReceived { timestamp, .. } |
            Self::ChunkVerified { timestamp, .. } |
            Self::ChunkWritten { timestamp, .. } |
            Self::RepairDecode { timestamp, .. } |
            Self::CommitIntent { timestamp, .. } |
            Self::CommitComplete { timestamp, .. } |
            Self::Cancellation { timestamp, .. } |
            Self::Rollback { timestamp, .. } |
            Self::CompactionBoundary { timestamp, .. } |
            Self::ProofDigest { timestamp, .. } => *timestamp,
        }
    }

    /// Get the record type name
    pub fn record_type(&self) -> &'static str {
        match self {
            Self::Offer { .. } => "offer",
            Self::Accept { .. } => "accept",
            Self::ChunkReceived { .. } => "chunk_received",
            Self::ChunkVerified { .. } => "chunk_verified",
            Self::ChunkWritten { .. } => "chunk_written",
            Self::RepairDecode { .. } => "repair_decode",
            Self::CommitIntent { .. } => "commit_intent",
            Self::CommitComplete { .. } => "commit_complete",
            Self::Cancellation { .. } => "cancellation",
            Self::Rollback { .. } => "rollback",
            Self::CompactionBoundary { .. } => "compaction_boundary",
            Self::ProofDigest { .. } => "proof_digest",
        }
    }
}

/// Journal entry with metadata
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Sequence number in journal
    pub sequence: u64,
    /// The actual record
    pub record: JournalRecord,
    /// Checksum of the entry
    pub checksum: u32,
    /// Entry size in bytes
    pub entry_size: u32,
}

impl JournalEntry {
    /// Create a new journal entry
    pub fn new(sequence: u64, record: JournalRecord) -> Self {
        let serialized = bincode::serde::encode_to_vec(&record, bincode::config::legacy()).expect("Failed to serialize record");
        let checksum = crc32fast::hash(&serialized);
        let entry_size = serialized.len() as u32;

        Self {
            sequence,
            record,
            checksum,
            entry_size,
        }
    }

    /// Validate the entry's checksum
    pub fn validate_checksum(&self) -> bool {
        let serialized = bincode::serde::encode_to_vec(&self.record, bincode::config::legacy()).expect("Failed to serialize record");
        let computed_checksum = crc32fast::hash(&serialized);
        computed_checksum == self.checksum
    }
}

/// Configuration for append-only journal
#[derive(Debug, Clone)]
pub struct JournalConfig {
    /// Base directory for journal files
    pub base_dir: PathBuf,
    /// Maximum size before triggering compaction
    pub max_journal_size: u64,
    /// Whether to fsync after every write
    pub force_sync: bool,
    /// Buffer size for writes
    pub write_buffer_size: usize,
    /// Maximum number of generations to keep
    pub max_generations: u32,
    /// Enable detailed logging
    pub enable_detailed_logs: bool,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            base_dir: std::env::temp_dir().join("atp_journal"),
            max_journal_size: 100 * 1024 * 1024, // 100MB
            force_sync: true,
            write_buffer_size: 64 * 1024, // 64KB
            max_generations: 10,
            enable_detailed_logs: true,
        }
    }
}

/// Append-only journal for crash-safe transfer tracking
pub struct AppendJournal {
    /// Configuration
    config: JournalConfig,
    /// Current generation number
    generation: u64,
    /// Current sequence number
    sequence: u64,
    /// Writer for current journal file
    writer: Option<BufWriter<File>>,
    /// Current journal file path
    current_file: Option<PathBuf>,
    /// In-memory cache of recent entries
    recent_entries: std::collections::VecDeque<JournalEntry>,
    /// Cache size limit
    cache_limit: usize,
}

impl AppendJournal {
    /// Create a new append-only journal
    pub fn new(config: JournalConfig) -> Outcome<Self, JournalError> {
        // Ensure base directory exists
        if let Err(e) = std::fs::create_dir_all(&config.base_dir) {
            return Outcome::Err(JournalError::DirectoryCreation(e.to_string()));
        }

        let mut journal = Self {
            config,
            generation: 0,
            sequence: 0,
            writer: None,
            current_file: None,
            recent_entries: std::collections::VecDeque::new(),
            cache_limit: 1000,
        };

        // Try to recover from existing journal
        if let Err(e) = journal.recover_from_disk() {
            // If recovery fails, start fresh but log the error
            if journal.config.enable_detailed_logs {
                eprintln!("Journal recovery failed: {:?}, starting fresh", e);
            }
            journal.generation = 0;
            journal.sequence = 0;
        }

        Outcome::Ok(journal)
    }

    /// Append a new record to the journal
    pub fn append(&mut self, record: JournalRecord) -> Outcome<u64, JournalError> {
        // Ensure we have an active writer
        self.ensure_writer()?;

        let entry = JournalEntry::new(self.sequence, record);

        // Serialize the entry
        let serialized = match bincode::serde::encode_to_vec(&entry, bincode::config::legacy()) {
            Ok(data) => data,
            Err(e) => return Outcome::Err(JournalError::Serialization(e.to_string())),
        };

        // Write to disk
        if let Some(ref mut writer) = self.writer {
            // Write length prefix
            let length = serialized.len() as u32;
            if let Err(e) = writer.write_all(&length.to_le_bytes()) {
                return Outcome::Err(JournalError::WriteFailure(e.to_string()));
            }

            // Write entry data
            if let Err(e) = writer.write_all(&serialized) {
                return Outcome::Err(JournalError::WriteFailure(e.to_string()));
            }

            // Optionally fsync
            if self.config.force_sync {
                if let Err(e) = writer.flush() {
                    return Outcome::Err(JournalError::SyncFailure(e.to_string()));
                }
                if let Err(e) = writer.get_ref().sync_data() {
                    return Outcome::Err(JournalError::SyncFailure(e.to_string()));
                }
            }
        }

        // Update in-memory state
        let current_sequence = self.sequence;
        self.sequence += 1;

        // Add to recent entries cache
        self.recent_entries.push_back(entry);
        if self.recent_entries.len() > self.cache_limit {
            self.recent_entries.pop_front();
        }

        // Check if compaction is needed
        if self.should_compact()? {
            self.trigger_compaction()?;
        }

        Outcome::Ok(current_sequence)
    }

    /// Flush any pending writes
    pub fn flush(&mut self) -> Outcome<(), JournalError> {
        if let Some(ref mut writer) = self.writer {
            if let Err(e) = writer.flush() {
                return Outcome::Err(JournalError::SyncFailure(e.to_string()));
            }
            if let Err(e) = writer.get_ref().sync_data() {
                return Outcome::Err(JournalError::SyncFailure(e.to_string()));
            }
        }
        Outcome::Ok(())
    }

    /// Get recent entries from cache
    pub fn get_recent_entries(&self, limit: usize) -> Vec<&JournalEntry> {
        self.recent_entries.iter().rev().take(limit).collect()
    }

    /// Read all entries from all generations
    pub async fn get_all_entries(&self, _cx: &Cx) -> Outcome<Vec<JournalRecord>, JournalError> {
        let mut all_entries = Vec::new();

        // Read from all generations
        for generation_num in 0..=self.generation {
            let file_path = self.config.base_dir.join(format!("journal_gen_{:06}.dat", generation_num));
            if file_path.exists() {
                let entries = self.read_entries_from_file(&file_path)?;
                for entry in entries {
                    all_entries.push(entry.record);
                }
            }
        }

        Outcome::Ok(all_entries)
    }

    /// Read all entries for a specific transfer ID
    pub fn get_transfer_entries(&self, transfer_id: &str) -> Outcome<Vec<JournalEntry>, JournalError> {
        let mut entries = Vec::new();

        // Check recent entries first
        for entry in &self.recent_entries {
            if entry.record.transfer_id() == Some(transfer_id) {
                entries.push(entry.clone());
            }
        }

        // If we need more entries, read from disk
        // This is a simplified implementation - in practice you'd want to index by transfer_id
        let disk_entries = self.read_all_entries_from_disk()?;
        for entry in disk_entries {
            if entry.record.transfer_id() == Some(transfer_id) {
                // Only add if not already in recent entries
                if !entries.iter().any(|e| e.sequence == entry.sequence) {
                    entries.push(entry);
                }
            }
        }

        entries.sort_by_key(|e| e.sequence);
        Outcome::Ok(entries)
    }

    /// Force compaction of the journal
    pub fn compact(&mut self) -> Outcome<(), JournalError> {
        self.trigger_compaction()
    }

    /// Get journal statistics
    pub fn get_stats(&self) -> JournalStats {
        let current_size = self.current_file.as_ref()
            .and_then(|path| std::fs::metadata(path).ok())
            .map(|meta| meta.len())
            .unwrap_or(0);

        JournalStats {
            generation: self.generation,
            sequence: self.sequence,
            current_file_size: current_size,
            recent_entries_count: self.recent_entries.len(),
            total_entries: self.sequence,
        }
    }

    // Private helper methods

    fn ensure_writer(&mut self) -> Outcome<(), JournalError> {
        if self.writer.is_some() {
            return Outcome::Ok(());
        }

        let file_path = self.config.base_dir.join(format!("journal_gen_{:06}.dat", self.generation));

        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(f) => f,
            Err(e) => return Outcome::Err(JournalError::FileOpen(e.to_string())),
        };

        self.writer = Some(BufWriter::with_capacity(self.config.write_buffer_size, file));
        self.current_file = Some(file_path);

        Outcome::Ok(())
    }

    fn should_compact(&self) -> Outcome<bool, JournalError> {
        let current_size = self.current_file.as_ref()
            .and_then(|path| std::fs::metadata(path).ok())
            .map(|meta| meta.len())
            .unwrap_or(0);

        Outcome::Ok(current_size >= self.config.max_journal_size)
    }

    fn trigger_compaction(&mut self) -> Outcome<(), JournalError> {
        // Flush current writer
        self.flush()?;

        // Create compaction boundary record
        let boundary_record = JournalRecord::CompactionBoundary {
            generation: self.generation + 1,
            compacted_up_to_sequence: self.sequence,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Write the boundary record
        self.append(boundary_record)?;

        // Close current writer
        self.writer = None;

        // Increment generation
        self.generation += 1;

        // Clean up old generations
        self.cleanup_old_generations()?;

        Outcome::Ok(())
    }

    fn cleanup_old_generations(&self) -> Outcome<(), JournalError> {
        if self.generation <= self.config.max_generations as u64 {
            return Outcome::Ok(());
        }

        let cutoff_generation = self.generation - self.config.max_generations as u64;

        for generation_num in 0..cutoff_generation {
            let old_file = self.config.base_dir.join(format!("journal_gen_{:06}.dat", generation_num));
            if old_file.exists() {
                if let Err(e) = std::fs::remove_file(&old_file) {
                    if self.config.enable_detailed_logs {
                        eprintln!("Failed to remove old journal generation {}: {}", generation_num, e);
                    }
                    // Continue cleanup despite errors
                }
            }
        }

        Outcome::Ok(())
    }

    fn recover_from_disk(&mut self) -> Outcome<(), JournalError> {
        let mut max_generation = 0;
        let mut max_sequence = 0;

        // Find the latest generation
        let entries = match std::fs::read_dir(&self.config.base_dir) {
            Ok(entries) => entries,
            Err(_) => return Outcome::Ok(()), // Directory doesn't exist yet
        };

        for entry in entries {
            let entry = entry.map_err(|e| JournalError::DirectoryRead(e.to_string()))?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Parse generation number from filename journal_gen_NNNNNN.dat
            if file_name_str.starts_with("journal_gen_") && file_name_str.ends_with(".dat") {
                let gen_part = &file_name_str[12..file_name_str.len()-4]; // Extract between "journal_gen_" and ".dat"
                if let Ok(generation_num) = gen_part.parse::<u64>() {
                    max_generation = max_generation.max(generation_num);
                }
            }
        }

        // Read the latest generation to find the maximum sequence
        let latest_file = self.config.base_dir.join(format!("journal_gen_{:06}.dat", max_generation));
        if latest_file.exists() {
            let entries = self.read_entries_from_file(&latest_file)?;
            for entry in &entries {
                max_sequence = max_sequence.max(entry.sequence);
            }

            // Load recent entries into cache
            let recent_start = if entries.len() > self.cache_limit {
                entries.len() - self.cache_limit
            } else {
                0
            };

            for entry in &entries[recent_start..] {
                self.recent_entries.push_back(entry.clone());
            }
        }

        self.generation = max_generation;
        self.sequence = max_sequence + 1;

        Outcome::Ok(())
    }

    fn read_entries_from_file(&self, file_path: &Path) -> Outcome<Vec<JournalEntry>, JournalError> {
        let file = File::open(file_path)
            .map_err(|e| JournalError::FileOpen(e.to_string()))?;
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();

        loop {
            // Read length prefix
            let mut length_bytes = [0u8; 4];
            match reader.read_exact(&mut length_bytes) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Outcome::Err(JournalError::ReadFailure(e.to_string())),
            }

            let length = u32::from_le_bytes(length_bytes) as usize;

            // Read entry data
            let mut entry_data = vec![0u8; length];
            reader.read_exact(&mut entry_data)
                .map_err(|e| JournalError::ReadFailure(e.to_string()))?;

            // Deserialize entry
            let (entry, _) = bincode::serde::decode_from_slice::<JournalEntry>(&entry_data, bincode::config::legacy())
                .map_err(|e| JournalError::Deserialization(e.to_string()))?;

            // Validate checksum
            if !entry.validate_checksum() {
                return Outcome::Err(JournalError::ChecksumMismatch(entry.sequence));
            }

            entries.push(entry);
        }

        Outcome::Ok(entries)
    }

    fn read_all_entries_from_disk(&self) -> Outcome<Vec<JournalEntry>, JournalError> {
        let mut all_entries = Vec::new();

        // Read from all generations
        for generation_num in 0..=self.generation {
            let file_path = self.config.base_dir.join(format!("journal_gen_{:06}.dat", generation_num));
            if file_path.exists() {
                let entries = self.read_entries_from_file(&file_path)?;
                all_entries.extend(entries);
            }
        }

        all_entries.sort_by_key(|e| e.sequence);
        Outcome::Ok(all_entries)
    }
}

/// Journal operation errors
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("Directory creation failed: {0}")]
    DirectoryCreation(String),

    #[error("File open failed: {0}")]
    FileOpen(String),

    #[error("Write failure: {0}")]
    WriteFailure(String),

    #[error("Read failure: {0}")]
    ReadFailure(String),

    #[error("Sync failure: {0}")]
    SyncFailure(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Checksum mismatch for entry {0}")]
    ChecksumMismatch(u64),

    #[error("Directory read failed: {0}")]
    DirectoryRead(String),

    #[error("Compaction failed: {0}")]
    CompactionFailed(String),
}

/// Journal statistics
#[derive(Debug, Clone)]
pub struct JournalStats {
    pub generation: u64,
    pub sequence: u64,
    pub current_file_size: u64,
    pub recent_entries_count: usize,
    pub total_entries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_entry_creation() {
        let record = JournalRecord::Offer {
            transfer_id: "test_transfer".to_string(),
            object_id: ObjectId::new("test_object"),
            manifest_root: MerkleRoot::new(&[1, 2, 3, 4]),
            total_size: 1024,
            timestamp: 1234567890,
        };

        let entry = JournalEntry::new(0, record);
        assert_eq!(entry.sequence, 0);
        assert!(entry.validate_checksum());
    }

    #[test]
    fn test_journal_append() {
        let temp_dir = std::env::temp_dir().join("test_journal");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config).unwrap();

        let record = JournalRecord::Accept {
            transfer_id: "test_transfer".to_string(),
            peer_id: "peer123".to_string(),
            timestamp: 1234567890,
        };

        let sequence = journal.append(record).unwrap();
        assert_eq!(sequence, 0);

        let stats = journal.get_stats();
        assert_eq!(stats.sequence, 1);
        assert_eq!(stats.recent_entries_count, 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_journal_recovery() {
        let temp_dir = std::env::temp_dir().join("test_journal_recovery");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        // Create and populate journal
        {
            let mut journal = AppendJournal::new(config.clone()).unwrap();

            journal.append(JournalRecord::Offer {
                transfer_id: "test1".to_string(),
                object_id: ObjectId::new("obj1"),
                manifest_root: MerkleRoot::new(&[1, 2, 3]),
                total_size: 1024,
                timestamp: 1000,
            }).unwrap();

            journal.append(JournalRecord::Accept {
                transfer_id: "test1".to_string(),
                peer_id: "peer1".to_string(),
                timestamp: 1001,
            }).unwrap();

            journal.flush().unwrap();
        }

        // Recover and verify
        {
            let journal = AppendJournal::new(config).unwrap();
            let stats = journal.get_stats();
            assert_eq!(stats.sequence, 2);
            assert_eq!(stats.recent_entries_count, 2);
        }

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_transfer_entries() {
        let temp_dir = std::env::temp_dir().join("test_transfer_entries");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config).unwrap();

        // Add entries for different transfers
        journal.append(JournalRecord::Offer {
            transfer_id: "transfer_a".to_string(),
            object_id: ObjectId::new("obj_a"),
            manifest_root: MerkleRoot::new(&[1, 2, 3]),
            total_size: 1024,
            timestamp: 1000,
        }).unwrap();

        journal.append(JournalRecord::Offer {
            transfer_id: "transfer_b".to_string(),
            object_id: ObjectId::new("obj_b"),
            manifest_root: MerkleRoot::new(&[4, 5, 6]),
            total_size: 2048,
            timestamp: 1001,
        }).unwrap();

        journal.append(JournalRecord::Accept {
            transfer_id: "transfer_a".to_string(),
            peer_id: "peer1".to_string(),
            timestamp: 1002,
        }).unwrap();

        // Get entries for specific transfer
        let transfer_a_entries = journal.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(transfer_a_entries.len(), 2);

        let transfer_b_entries = journal.get_transfer_entries("transfer_b").unwrap();
        assert_eq!(transfer_b_entries.len(), 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}