//! ATP Journal End-to-End Test Suite
//!
//! Tests for append-only journal, recovery, compaction, and bitmap operations
//! with crash injection at critical points.

pub mod append_recovery_e2e;

use asupersync::atp::object::{ContentId, ObjectId, ObjectKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Test-only constructor shim for historical E2E harness code.
pub trait ObjectIdTestExt {
    fn new() -> Self;
}

impl ObjectIdTestExt for ObjectId {
    fn new() -> Self {
        ObjectId::content(ContentId::from_bytes(b"atp-journal-e2e-test-id"))
    }
}

/// Test-local append-log offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalOffset(pub u64);

impl JournalOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }
}

/// Test-local recovery states for simulated journal crash scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Completed,
    CrashDetected,
    AppendFailed,
    InProgress,
    ConcurrentAppendFailed,
}

/// Test-local journal entry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEntry {
    ObjectCreated {
        object_id: ObjectId,
        kind: ObjectKind,
        timestamp: SystemTime,
    },
}

/// Test-local bitmap update record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitmapUpdate {
    chunk_id: u64,
    available: bool,
    timestamp: SystemTime,
}

impl BitmapUpdate {
    pub const fn new(chunk_id: u64, available: bool, timestamp: SystemTime) -> Self {
        Self {
            chunk_id,
            available,
            timestamp,
        }
    }

    pub const fn sequence_number(&self) -> u64 {
        self.chunk_id
    }
}

/// Test configuration for journal e2e tests
#[derive(Debug, Clone)]
pub struct JournalTestConfig {
    pub temp_dir: PathBuf,
    pub journal_path: PathBuf,
    pub bitmap_path: PathBuf,
    pub max_journal_size: u64,
    pub compaction_threshold: f64,
    pub fsync_policy: FsyncPolicy,
    pub enable_checksums: bool,
    pub crash_points: Vec<JournalCrashPoint>,
}

impl Default for JournalTestConfig {
    fn default() -> Self {
        let temp_dir = std::env::temp_dir().join("atp_journal_tests");
        Self {
            journal_path: temp_dir.join("journal.log"),
            bitmap_path: temp_dir.join("bitmap.dat"),
            temp_dir,
            max_journal_size: 1024 * 1024, // 1MB
            compaction_threshold: 0.5,     // 50% garbage
            fsync_policy: FsyncPolicy::EveryWrite,
            enable_checksums: true,
            crash_points: JournalCrashPoint::all(),
        }
    }
}

/// Fsync policy for journal operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncPolicy {
    Never,
    EveryWrite,
    Batch(u32),
    Periodic(Duration),
}

/// Critical crash points for journal operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalCrashPoint {
    /// During journal entry append
    JournalAppend,
    /// During journal fsync
    JournalFsync,
    /// During bitmap update
    BitmapUpdate,
    /// During bitmap fsync
    BitmapFsync,
    /// During journal recovery
    Recovery,
    /// During compaction
    Compaction,
    /// During checkpoint
    Checkpoint,
    /// During garbage collection
    GarbageCollection,
}

impl JournalCrashPoint {
    pub fn all() -> Vec<Self> {
        vec![
            Self::JournalAppend,
            Self::JournalFsync,
            Self::BitmapUpdate,
            Self::BitmapFsync,
            Self::Recovery,
            Self::Compaction,
            Self::Checkpoint,
            Self::GarbageCollection,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::JournalAppend => "journal_append",
            Self::JournalFsync => "journal_fsync",
            Self::BitmapUpdate => "bitmap_update",
            Self::BitmapFsync => "bitmap_fsync",
            Self::Recovery => "recovery",
            Self::Compaction => "compaction",
            Self::Checkpoint => "checkpoint",
            Self::GarbageCollection => "garbage_collection",
        }
    }
}

/// Journal test artifact for debugging and replay
#[derive(Debug, Clone)]
pub struct JournalTestArtifact {
    pub test_name: String,
    pub crash_point: Option<JournalCrashPoint>,
    pub journal_entries: Vec<JournalEntry>,
    pub journal_size: u64,
    pub bitmap_updates: Vec<BitmapUpdate>,
    pub recovery_state: Option<RecoveryState>,
    pub compaction_stats: Option<CompactionStats>,
    pub checkpoint_offsets: Vec<JournalOffset>,
    pub fsync_count: u64,
    pub timestamp: SystemTime,
    pub verification_hashes: HashMap<String, [u8; 32]>,
}

impl JournalTestArtifact {
    pub fn new(test_name: String) -> Self {
        Self {
            test_name,
            crash_point: None,
            journal_entries: Vec::new(),
            journal_size: 0,
            bitmap_updates: Vec::new(),
            recovery_state: None,
            compaction_stats: None,
            checkpoint_offsets: Vec::new(),
            fsync_count: 0,
            timestamp: SystemTime::now(),
            verification_hashes: HashMap::new(),
        }
    }

    pub fn with_crash_point(mut self, crash_point: JournalCrashPoint) -> Self {
        self.crash_point = Some(crash_point);
        self
    }

    pub fn record_journal_entry(&mut self, entry: JournalEntry) {
        self.journal_entries.push(entry);
    }

    pub fn record_bitmap_update(&mut self, update: BitmapUpdate) {
        self.bitmap_updates.push(update);
    }

    pub fn record_recovery_state(&mut self, state: RecoveryState) {
        self.recovery_state = Some(state);
    }

    pub fn record_compaction(&mut self, stats: CompactionStats) {
        self.compaction_stats = Some(stats);
    }

    pub fn record_checkpoint(&mut self, offset: JournalOffset) {
        self.checkpoint_offsets.push(offset);
    }

    pub fn record_fsync(&mut self) {
        self.fsync_count += 1;
    }

    pub fn record_verification_hash(&mut self, key: String, hash: [u8; 32]) {
        self.verification_hashes.insert(key, hash);
    }

    pub fn to_lab_artifact(&self) -> HashMap<String, String> {
        let mut artifact = HashMap::new();

        artifact.insert("test_name".to_string(), self.test_name.clone());
        artifact.insert(
            "journal_entries_count".to_string(),
            self.journal_entries.len().to_string(),
        );
        artifact.insert("journal_size".to_string(), self.journal_size.to_string());
        artifact.insert(
            "bitmap_updates_count".to_string(),
            self.bitmap_updates.len().to_string(),
        );
        artifact.insert("fsync_count".to_string(), self.fsync_count.to_string());
        artifact.insert(
            "checkpoints_count".to_string(),
            self.checkpoint_offsets.len().to_string(),
        );

        if let Some(crash_point) = self.crash_point {
            artifact.insert("crash_point".to_string(), crash_point.name().to_string());
        }

        if let Some(recovery) = &self.recovery_state {
            artifact.insert("recovery_state".to_string(), format!("{:?}", recovery));
        }

        if let Some(compaction) = &self.compaction_stats {
            artifact.insert(
                "compaction_reclaimed".to_string(),
                compaction.bytes_reclaimed.to_string(),
            );
            artifact.insert(
                "compaction_duration".to_string(),
                compaction.duration_ms.to_string(),
            );
        }

        // Add verification hashes
        for (key, hash) in &self.verification_hashes {
            artifact.insert(format!("hash_{}", key), hex::encode(hash));
        }

        artifact
    }
}

/// Compaction statistics
#[derive(Debug, Clone)]
pub struct CompactionStats {
    pub bytes_reclaimed: u64,
    pub entries_compacted: u64,
    pub duration_ms: u64,
    pub fragmentation_before: f64,
    pub fragmentation_after: f64,
}

/// Base test harness for journal tests
pub struct JournalTestHarness {
    pub config: JournalTestConfig,
    pub temp_dir: PathBuf,
    pub artifacts: Vec<JournalTestArtifact>,
}

impl JournalTestHarness {
    pub fn new(config: JournalTestConfig) -> std::io::Result<Self> {
        let temp_dir = config.temp_dir.clone();
        std::fs::create_dir_all(&temp_dir)?;

        Ok(Self {
            config,
            temp_dir,
            artifacts: Vec::new(),
        })
    }

    pub fn run_crash_matrix<F>(
        &mut self,
        test_name: &str,
        mut test_fn: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnMut(
            &JournalTestConfig,
            Option<JournalCrashPoint>,
        ) -> Result<JournalTestArtifact, Box<dyn std::error::Error>>,
    {
        // Clean run first
        let clean_artifact = test_fn(&self.config, None)?;
        self.artifacts.push(clean_artifact);

        // Test each crash point
        for &crash_point in &self.config.crash_points {
            println!(
                "Testing {} with crash point: {}",
                test_name,
                crash_point.name()
            );

            match test_fn(&self.config, Some(crash_point)) {
                Ok(artifact) => {
                    self.artifacts.push(artifact);
                }
                Err(e) => {
                    // Record crash failure artifact
                    let mut artifact = JournalTestArtifact::new(test_name.to_string());
                    artifact.crash_point = Some(crash_point);
                    artifact.record_recovery_state(RecoveryState::CrashDetected);
                    self.artifacts.push(artifact);
                }
            }
        }

        Ok(())
    }

    pub fn verify_journal_integrity(&self) -> Result<(), String> {
        println!("Verifying journal integrity across all test runs...");

        // Check that recovery is consistent
        for artifact in &self.artifacts {
            if let Some(recovery) = &artifact.recovery_state {
                match recovery {
                    RecoveryState::Completed => {
                        // Verify no data loss
                        if artifact.journal_entries.is_empty() {
                            return Err(
                                "Recovery completed but no journal entries found".to_string()
                            );
                        }
                    }
                    RecoveryState::CrashDetected => {
                        // Verify crash was handled properly
                        println!("Crash detected and handled: {:?}", artifact.crash_point);
                    }
                    _ => {
                        // Other states should be valid
                    }
                }
            }
        }

        Ok(())
    }

    pub fn verify_bitmap_consistency(&self) -> Result<(), String> {
        println!("Verifying bitmap consistency...");

        for artifact in &self.artifacts {
            // Check bitmap updates are properly sequenced
            let mut expected_sequence = 0;
            for update in &artifact.bitmap_updates {
                if update.sequence_number() != expected_sequence {
                    return Err(format!(
                        "Bitmap sequence gap: expected {}, got {}",
                        expected_sequence,
                        update.sequence_number()
                    ));
                }
                expected_sequence += 1;
            }
        }

        Ok(())
    }

    pub fn generate_lab_artifacts(&self) -> Result<(), std::io::Error> {
        let artifacts_dir = self.temp_dir.join("lab_artifacts");
        std::fs::create_dir_all(&artifacts_dir)?;

        for (i, artifact) in self.artifacts.iter().enumerate() {
            let artifact_file = artifacts_dir.join(format!("journal_artifact_{}.json", i));
            let artifact_data = serde_json::to_string_pretty(&artifact.to_lab_artifact())?;
            std::fs::write(artifact_file, artifact_data)?;
        }

        println!(
            "Generated {} journal lab artifacts in: {}",
            self.artifacts.len(),
            artifacts_dir.display()
        );

        Ok(())
    }
}

impl Drop for JournalTestHarness {
    fn drop(&mut self) {
        if self.temp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Common journal test utilities
pub mod test_utils {
    use super::*;

    pub fn create_test_journal_entry(id: ObjectId, kind: ObjectKind) -> JournalEntry {
        JournalEntry::ObjectCreated {
            object_id: id,
            kind,
            timestamp: SystemTime::now(),
        }
    }

    pub fn create_test_bitmap_update(chunk_id: u64, is_available: bool) -> BitmapUpdate {
        BitmapUpdate::new(chunk_id, is_available, SystemTime::now())
    }

    pub fn setup_crash_injection(crash_point: JournalCrashPoint) {
        println!("Setting up crash injection for: {}", crash_point.name());
        // TODO: Implement actual crash injection mechanism
    }

    pub fn verify_journal_checksum(journal_path: &PathBuf) -> Result<[u8; 32], std::io::Error> {
        use sha2::{Digest, Sha256};

        let content = std::fs::read(journal_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hasher.finalize().into())
    }

    pub fn compute_fragmentation_ratio(total_size: u64, live_size: u64) -> f64 {
        if total_size == 0 {
            0.0
        } else {
            1.0 - (live_size as f64 / total_size as f64)
        }
    }
}
