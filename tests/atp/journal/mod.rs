//! ATP Journal End-to-End Test Suite
//!
//! Tests for append-only journal, recovery, compaction, and bitmap operations
//! with crash injection at critical points.

pub mod append_recovery_e2e;

use asupersync::atp::object::{ContentId, ObjectId, ObjectKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static TEMP_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
        .join(seq.to_string())
}

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
        let temp_dir = unique_temp_dir("atp_journal_tests");
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
    pub failure_message: Option<String>,
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
            failure_message: None,
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

    pub fn record_failure(&mut self, failure_message: String) {
        self.failure_message = Some(failure_message);
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

        if let Some(failure_message) = &self.failure_message {
            artifact.insert("failure_message".to_string(), failure_message.clone());
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
        test_utils::clear_crash_injection();

        // Clean run first
        let clean_artifact = test_fn(&self.config, None)?;
        self.artifacts.push(clean_artifact);

        // Test each crash point
        for &crash_point in &self.config.crash_points {
            let (result, crash_point_was_hit) = {
                let _guard = test_utils::setup_crash_injection(crash_point);
                let result = test_fn(&self.config, Some(crash_point));
                let crash_point_was_hit = test_utils::active_crash_injection_was_hit();
                (result, crash_point_was_hit)
            };

            match (result, crash_point_was_hit) {
                (Ok(artifact), true) => self.artifacts.push(artifact),
                (Ok(_), false) => {
                    return Err(format!(
                        "journal test {test_name} configured crash point {} but never exercised it",
                        crash_point.name()
                    )
                    .into());
                }
                (Err(e), true) => {
                    let mut artifact = JournalTestArtifact::new(test_name.to_string());
                    artifact.crash_point = Some(crash_point);
                    artifact.record_failure(e.to_string());
                    artifact.record_recovery_state(RecoveryState::CrashDetected);
                    artifact.journal_size = self
                        .config
                        .journal_path
                        .metadata()
                        .map_or(0, |metadata| metadata.len());
                    self.artifacts.push(artifact);
                }
                (Err(e), false) => {
                    return Err(format!(
                        "journal test {test_name} failed before exercising configured crash point {}: {e}",
                        crash_point.name()
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    pub fn verify_journal_integrity(&self) -> Result<(), String> {
        // Check that recovery is consistent
        for artifact in &self.artifacts {
            if artifact.crash_point.is_some() && artifact.recovery_state.is_none() {
                return Err(format!(
                    "crash artifact {} has no recovery state",
                    artifact.test_name
                ));
            }

            if let Some(recovery) = &artifact.recovery_state {
                match recovery {
                    RecoveryState::Completed => {
                        // Verify no data loss
                        if artifact.journal_entries.is_empty() {
                            return Err(
                                "Recovery completed but no journal entries found".to_string()
                            );
                        }
                        if let Some(failure_message) = &artifact.failure_message {
                            return Err(format!(
                                "recovery completed despite recorded failure: {failure_message}"
                            ));
                        }
                    }
                    RecoveryState::CrashDetected => {
                        if artifact.crash_point.is_none() {
                            return Err(format!(
                                "crash detected without a crash point in {}",
                                artifact.test_name
                            ));
                        }
                        if artifact.failure_message.is_none() {
                            return Err(format!(
                                "crash detected without failure message in {}",
                                artifact.test_name
                            ));
                        }
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
        for artifact in &self.artifacts {
            // Check bitmap updates are properly sequenced
            for (expected_sequence, update) in artifact.bitmap_updates.iter().enumerate() {
                let expected_sequence = u64::try_from(expected_sequence)
                    .expect("bitmap update sequence must fit in u64");
                if update.sequence_number() != expected_sequence {
                    return Err(format!(
                        "Bitmap sequence gap: expected {}, got {}",
                        expected_sequence,
                        update.sequence_number()
                    ));
                }
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
    use std::cell::RefCell;
    use std::fmt;
    use std::io::Write;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ActiveJournalCrashInjection {
        crash_point: JournalCrashPoint,
        was_hit: bool,
    }

    thread_local! {
        static ACTIVE_CRASH_INJECTION: RefCell<Option<ActiveJournalCrashInjection>> =
            const { RefCell::new(None) };
    }

    #[derive(Debug)]
    pub struct JournalCrashInjectionGuard {
        previous: Option<ActiveJournalCrashInjection>,
    }

    impl Drop for JournalCrashInjectionGuard {
        fn drop(&mut self) {
            ACTIVE_CRASH_INJECTION.with(|slot| {
                *slot.borrow_mut() = self.previous;
            });
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct JournalCrashInjection {
        pub crash_point: JournalCrashPoint,
    }

    impl fmt::Display for JournalCrashInjection {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "injected journal crash at {}",
                self.crash_point.name()
            )
        }
    }

    impl std::error::Error for JournalCrashInjection {}

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

    pub fn setup_crash_injection(crash_point: JournalCrashPoint) -> JournalCrashInjectionGuard {
        let previous = ACTIVE_CRASH_INJECTION.with(|slot| {
            slot.borrow_mut().replace(ActiveJournalCrashInjection {
                crash_point,
                was_hit: false,
            })
        });
        JournalCrashInjectionGuard { previous }
    }

    pub fn active_crash_injection() -> Option<JournalCrashPoint> {
        ACTIVE_CRASH_INJECTION.with(|slot| slot.borrow().map(|active| active.crash_point))
    }

    pub fn active_crash_injection_was_hit() -> bool {
        ACTIVE_CRASH_INJECTION.with(|slot| slot.borrow().is_some_and(|active| active.was_hit))
    }

    pub fn clear_crash_injection() {
        ACTIVE_CRASH_INJECTION.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }

    pub fn inject_if_active(crash_point: JournalCrashPoint) -> Result<(), JournalCrashInjection> {
        ACTIVE_CRASH_INJECTION.with(|slot| {
            let mut active = slot.borrow_mut();
            match active.as_mut() {
                Some(active) if active.crash_point == crash_point => {
                    active.was_hit = true;
                    Err(JournalCrashInjection { crash_point })
                }
                _ => Ok(()),
            }
        })
    }

    pub fn reset_test_files(config: &JournalTestConfig) -> std::io::Result<()> {
        std::fs::create_dir_all(&config.temp_dir)?;
        std::fs::write(&config.journal_path, b"")?;
        std::fs::write(&config.bitmap_path, b"")?;
        Ok(())
    }

    pub fn persist_journal_entry(
        config: &JournalTestConfig,
        sequence: u64,
        entry: &JournalEntry,
    ) -> std::io::Result<()> {
        let mut journal = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.journal_path)?;
        writeln!(journal, "{sequence}:{entry:?}")?;
        Ok(())
    }

    pub fn fsync_journal(config: &JournalTestConfig) -> std::io::Result<()> {
        let journal = std::fs::OpenOptions::new()
            .read(true)
            .open(&config.journal_path)?;
        journal.sync_data()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_crash_injection_records_only_matching_fault() {
        test_utils::clear_crash_injection();

        {
            let _guard = test_utils::setup_crash_injection(JournalCrashPoint::JournalAppend);

            assert_eq!(
                test_utils::active_crash_injection(),
                Some(JournalCrashPoint::JournalAppend)
            );
            assert!(!test_utils::active_crash_injection_was_hit());
            assert!(test_utils::inject_if_active(JournalCrashPoint::BitmapUpdate).is_ok());
            assert!(!test_utils::active_crash_injection_was_hit());

            let error = test_utils::inject_if_active(JournalCrashPoint::JournalAppend)
                .expect_err("matching crash point should inject a fault");
            assert_eq!(error.crash_point, JournalCrashPoint::JournalAppend);
            assert!(test_utils::active_crash_injection_was_hit());
        }

        assert_eq!(test_utils::active_crash_injection(), None);

        let update = test_utils::create_test_bitmap_update(7, true);
        assert_eq!(update.sequence_number(), 7);
        assert_eq!(test_utils::compute_fragmentation_ratio(100, 25), 0.75);
    }
}
