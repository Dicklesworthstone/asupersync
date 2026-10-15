//! ATP Object Graph End-to-End Proof Suite
//!
//! Comprehensive testing of object graph persistence, recovery, and verification
//! through crash injection and fault scenarios. Validates receiver trust boundary.

pub mod file_object_e2e;

use asupersync::atp::manifest::Manifest;
use asupersync::atp::object::{
    ContentId, MetadataPolicy, Object, ObjectEdge, ObjectGraph, ObjectId, ObjectKind,
};
use std::cell::RefCell;
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
        ObjectId::content(ContentId::from_bytes(b"atp-object-e2e-test-id"))
    }
}

/// Test-local journal offset used by the simulated E2E proof harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalOffset(pub u64);

impl JournalOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub const fn zero() -> Self {
        Self(0)
    }
}

/// Test-local recovery states for object/journal crash proof scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Quarantined,
    Resuming,
    RetryRequired,
    PartialCompletion,
    VerificationFailed,
    CommitFailed,
    RepairFailed,
    RenameRequired,
    Completed,
}

/// Test-local verification decision record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    Valid {
        object_id: ObjectId,
        content_hash: [u8; 32],
        verified_at: SystemTime,
    },
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

/// Test-local obligation lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationEvent {
    Opened(String),
    Committed(String),
    Aborted(String),
}

/// Test-local worker lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    Started(String),
    Finished(String),
    Aborted(String),
}

/// Test configuration for e2e object graph tests
#[derive(Debug, Clone)]
pub struct ObjectTestConfig {
    pub temp_dir: PathBuf,
    pub crash_points: Vec<CrashPoint>,
    pub verification_policy: MetadataPolicy,
    pub timeout: Duration,
    pub enable_trace: bool,
}

impl Default for ObjectTestConfig {
    fn default() -> Self {
        Self {
            temp_dir: unique_temp_dir("atp_object_tests"),
            crash_points: CrashPoint::all(),
            verification_policy: MetadataPolicy::full_preservation(),
            timeout: Duration::from_secs(30),
            enable_trace: true,
        }
    }
}

/// Critical crash injection points for object graph operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    /// Journal append operation
    JournalAppend,
    /// Bitmap update operation
    BitmapUpdate,
    /// Chunk write to disk
    ChunkWrite,
    /// Fsync operation
    Fsync,
    /// Repair decode operation
    RepairDecode,
    /// Final rename operation
    FinalRename,
    /// Proof emission
    ProofEmission,
    /// Journal compaction
    Compaction,
    /// Manifest generation.
    ManifestGeneration,
    /// Verification pipeline.
    VerificationPipeline,
    /// Atomic commit.
    AtomicCommit,
    /// Final commit.
    FinalCommit,
    /// Batch commit.
    BatchCommit,
}

impl CrashPoint {
    pub fn all() -> Vec<Self> {
        vec![
            Self::JournalAppend,
            Self::BitmapUpdate,
            Self::ChunkWrite,
            Self::Fsync,
            Self::RepairDecode,
            Self::FinalRename,
            Self::ProofEmission,
            Self::Compaction,
            Self::ManifestGeneration,
            Self::VerificationPipeline,
            Self::AtomicCommit,
            Self::FinalCommit,
            Self::BatchCommit,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::JournalAppend => "journal_append",
            Self::BitmapUpdate => "bitmap_update",
            Self::ChunkWrite => "chunk_write",
            Self::Fsync => "fsync",
            Self::RepairDecode => "repair_decode",
            Self::FinalRename => "final_rename",
            Self::ProofEmission => "proof_emission",
            Self::Compaction => "compaction",
            Self::ManifestGeneration => "manifest_generation",
            Self::VerificationPipeline => "verification_pipeline",
            Self::AtomicCommit => "atomic_commit",
            Self::FinalCommit => "final_commit",
            Self::BatchCommit => "batch_commit",
        }
    }
}

/// Test artifact for replaying and debugging failures
#[derive(Debug, Clone)]
pub struct TestArtifact {
    pub test_name: String,
    pub object_id: ObjectId,
    pub crash_point: Option<CrashPoint>,
    pub manifest_root: [u8; 32],
    pub chunk_ranges: Vec<(u64, u64)>,
    pub journal_offset: JournalOffset,
    pub bitmap_changes: Vec<u64>,
    pub verifier_decisions: Vec<VerificationResult>,
    pub final_commit_record: Option<String>,
    pub timestamp: SystemTime,
    pub recovery_state: Option<RecoveryState>,
    pub obligation_events: Vec<ObligationEvent>,
    pub worker_events: Vec<WorkerEvent>,
}

impl TestArtifact {
    pub fn new(test_name: String, object_id: ObjectId) -> Self {
        Self {
            test_name,
            object_id,
            crash_point: None,
            manifest_root: [0; 32],
            chunk_ranges: Vec::new(),
            journal_offset: JournalOffset::zero(),
            bitmap_changes: Vec::new(),
            verifier_decisions: Vec::new(),
            final_commit_record: None,
            timestamp: SystemTime::now(),
            recovery_state: None,
            obligation_events: Vec::new(),
            worker_events: Vec::new(),
        }
    }

    pub fn with_crash_point(mut self, crash_point: CrashPoint) -> Self {
        self.crash_point = Some(crash_point);
        self
    }

    pub fn record_manifest_root(&mut self, root: [u8; 32]) {
        self.manifest_root = root;
    }

    pub fn record_chunk_range(&mut self, start: u64, end: u64) {
        self.chunk_ranges.push((start, end));
        let id = format!("chunk:{start}-{end}");
        self.record_obligation_opened(id.clone());
        self.record_obligation_committed(id);
    }

    pub fn record_journal_offset(&mut self, offset: JournalOffset) {
        self.journal_offset = offset;
    }

    pub fn record_bitmap_change(&mut self, chunk_id: u64) {
        self.bitmap_changes.push(chunk_id);
        let id = format!("bitmap:{chunk_id}");
        self.record_obligation_opened(id.clone());
        self.record_obligation_committed(id);
    }

    pub fn record_verifier_decision(&mut self, result: VerificationResult) {
        let id = match &result {
            VerificationResult::Valid { object_id, .. } => format!("verify:{object_id}"),
        };
        self.record_obligation_opened(id.clone());
        self.verifier_decisions.push(result);
        self.record_obligation_committed(id);
    }

    pub fn record_final_commit(&mut self, record: String) {
        self.record_obligation_opened("final_commit".to_string());
        self.final_commit_record = Some(record);
        self.record_obligation_committed("final_commit".to_string());
    }

    pub fn record_recovery_state(&mut self, state: RecoveryState) {
        self.recovery_state = Some(state);
    }

    pub fn record_obligation_opened(&mut self, id: String) {
        self.obligation_events.push(ObligationEvent::Opened(id));
    }

    pub fn record_obligation_committed(&mut self, id: String) {
        self.obligation_events.push(ObligationEvent::Committed(id));
    }

    pub fn record_obligation_aborted(&mut self, id: String) {
        self.obligation_events.push(ObligationEvent::Aborted(id));
    }

    pub fn record_worker_started(&mut self, id: String) {
        self.worker_events.push(WorkerEvent::Started(id));
    }

    pub fn record_worker_finished(&mut self, id: String) {
        self.worker_events.push(WorkerEvent::Finished(id));
    }

    pub fn record_worker_aborted(&mut self, id: String) {
        self.worker_events.push(WorkerEvent::Aborted(id));
    }

    pub fn to_lab_artifact(&self) -> HashMap<String, String> {
        let mut artifact = HashMap::new();

        artifact.insert("test_name".to_string(), self.test_name.clone());
        artifact.insert("object_id".to_string(), format!("{:?}", self.object_id));
        artifact.insert("manifest_root".to_string(), hex::encode(self.manifest_root));
        artifact.insert(
            "journal_offset".to_string(),
            format!("{:?}", self.journal_offset),
        );
        artifact.insert(
            "timestamp".to_string(),
            self.timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
        );

        if let Some(crash_point) = self.crash_point {
            artifact.insert("crash_point".to_string(), crash_point.name().to_string());
        }

        if !self.chunk_ranges.is_empty() {
            let ranges = self
                .chunk_ranges
                .iter()
                .map(|(start, end)| format!("{}-{}", start, end))
                .collect::<Vec<_>>()
                .join(",");
            artifact.insert("chunk_ranges".to_string(), ranges);
        }

        if !self.bitmap_changes.is_empty() {
            let changes = self
                .bitmap_changes
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            artifact.insert("bitmap_changes".to_string(), changes);
        }

        if let Some(final_commit) = &self.final_commit_record {
            artifact.insert("final_commit_record".to_string(), final_commit.clone());
        }

        if let Some(recovery) = &self.recovery_state {
            artifact.insert("recovery_state".to_string(), format!("{:?}", recovery));
        }

        if !self.obligation_events.is_empty() {
            let events = self
                .obligation_events
                .iter()
                .map(|event| format!("{event:?}"))
                .collect::<Vec<_>>()
                .join(",");
            artifact.insert("obligation_events".to_string(), events);
        }

        if !self.worker_events.is_empty() {
            let events = self
                .worker_events
                .iter()
                .map(|event| format!("{event:?}"))
                .collect::<Vec<_>>()
                .join(",");
            artifact.insert("worker_events".to_string(), events);
        }

        artifact
    }

    fn has_verified_material(&self) -> bool {
        !self.verifier_decisions.is_empty()
            || self.manifest_root != [0; 32]
                && (!self.chunk_ranges.is_empty() || !self.bitmap_changes.is_empty())
    }

    fn is_injected_crash_record(&self) -> bool {
        self.final_commit_record
            .as_deref()
            .is_some_and(|record| record.starts_with("CRASH_INJECTED:"))
    }
}

/// Base test harness for object graph e2e tests
pub struct ObjectGraphTestHarness {
    pub config: ObjectTestConfig,
    pub temp_dir: PathBuf,
    pub artifacts: Vec<TestArtifact>,
}

impl ObjectGraphTestHarness {
    pub fn new(config: ObjectTestConfig) -> std::io::Result<Self> {
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
            &ObjectTestConfig,
            Option<CrashPoint>,
        ) -> Result<TestArtifact, Box<dyn std::error::Error>>,
    {
        // Run test without crash injection first
        let mut clean_artifact = test_fn(&self.config, None)?;
        if clean_artifact.worker_events.is_empty() {
            let worker_id = format!("{test_name}:clean");
            clean_artifact.record_worker_started(worker_id.clone());
            clean_artifact.record_worker_finished(worker_id);
        }
        self.artifacts.push(clean_artifact);

        // Run test with each crash point
        for &crash_point in &self.config.crash_points {
            match test_fn(&self.config, Some(crash_point)) {
                Ok(mut artifact) => {
                    if artifact.worker_events.is_empty() {
                        let worker_id = format!("{test_name}:{}", crash_point.name());
                        artifact.record_worker_started(worker_id.clone());
                        artifact.record_worker_finished(worker_id);
                    }
                    self.artifacts.push(artifact);
                }
                Err(e) => {
                    // Crash injection should cause controlled failures
                    // Record the failure artifact for analysis
                    let mut artifact = TestArtifact::new(test_name.to_string(), ObjectId::new());
                    artifact.crash_point = Some(crash_point);
                    let worker_id = format!("{test_name}:{}", crash_point.name());
                    artifact.record_worker_started(worker_id.clone());
                    artifact.record_worker_aborted(worker_id);
                    artifact.record_obligation_opened(format!("crash:{}", crash_point.name()));
                    artifact.record_obligation_aborted(format!("crash:{}", crash_point.name()));
                    artifact.final_commit_record = Some(format!("CRASH_INJECTED: {e}"));
                    self.artifacts.push(artifact);
                }
            }
        }

        Ok(())
    }

    pub fn assert_no_obligation_leaks(&self) -> Result<(), String> {
        let mut states = HashMap::<String, i32>::new();

        for artifact in &self.artifacts {
            for event in &artifact.obligation_events {
                match event {
                    ObligationEvent::Opened(id) => {
                        *states.entry(id.clone()).or_default() += 1;
                    }
                    ObligationEvent::Committed(id) | ObligationEvent::Aborted(id) => {
                        let count = states
                            .get_mut(id)
                            .ok_or_else(|| format!("obligation {id} closed before it opened"))?;
                        *count -= 1;
                        if *count < 0 {
                            return Err(format!("obligation {id} closed more often than opened"));
                        }
                    }
                }
            }
        }

        let leaked = states
            .into_iter()
            .filter_map(|(id, count)| (count != 0).then_some(format!("{id}:{count}")))
            .collect::<Vec<_>>();
        if !leaked.is_empty() {
            return Err(format!("unclosed obligations: {}", leaked.join(",")));
        }

        Ok(())
    }

    pub fn assert_no_live_workers(&self) -> Result<(), String> {
        let mut states = HashMap::<String, i32>::new();

        for artifact in &self.artifacts {
            for event in &artifact.worker_events {
                match event {
                    WorkerEvent::Started(id) => {
                        *states.entry(id.clone()).or_default() += 1;
                    }
                    WorkerEvent::Finished(id) | WorkerEvent::Aborted(id) => {
                        let count = states
                            .get_mut(id)
                            .ok_or_else(|| format!("worker {id} closed before it started"))?;
                        *count -= 1;
                        if *count < 0 {
                            return Err(format!("worker {id} closed more often than started"));
                        }
                    }
                }
            }
        }

        let live = states
            .into_iter()
            .filter_map(|(id, count)| (count != 0).then_some(format!("{id}:{count}")))
            .collect::<Vec<_>>();
        if !live.is_empty() {
            return Err(format!(
                "live workers after region close: {}",
                live.join(",")
            ));
        }

        Ok(())
    }

    pub fn assert_no_unverified_exposure(&self) -> Result<(), String> {
        for artifact in &self.artifacts {
            if artifact.final_commit_record.is_some()
                && !artifact.is_injected_crash_record()
                && !artifact.has_verified_material()
            {
                return Err(format!(
                    "final commit exposed without verification evidence: {}",
                    artifact.test_name
                ));
            }
        }

        Ok(())
    }

    pub fn generate_lab_compatible_artifacts(&self) -> Result<(), std::io::Error> {
        let artifacts_dir = self.temp_dir.join("lab_artifacts");
        std::fs::create_dir_all(&artifacts_dir)?;

        for (i, artifact) in self.artifacts.iter().enumerate() {
            let artifact_file = artifacts_dir.join(format!("artifact_{}.json", i));
            let artifact_data = serde_json::to_string_pretty(&artifact.to_lab_artifact())?;
            std::fs::write(artifact_file, artifact_data)?;
        }

        // Create a summary manifest
        let summary = self
            .artifacts
            .iter()
            .map(|a| {
                let mut summary = HashMap::new();
                summary.insert("test_name", a.test_name.clone());
                summary.insert(
                    "crash_point",
                    a.crash_point
                        .map(|cp| cp.name().to_string())
                        .unwrap_or_default(),
                );
                summary.insert(
                    "timestamp",
                    a.timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        .to_string(),
                );
                summary
            })
            .collect::<Vec<_>>();

        let summary_file = artifacts_dir.join("test_summary.json");
        let summary_data = serde_json::to_string_pretty(&summary)?;
        std::fs::write(summary_file, summary_data)?;

        Ok(())
    }
}

impl Drop for ObjectGraphTestHarness {
    fn drop(&mut self) {
        // Cleanup temp directory on drop
        if self.temp_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Common test utilities
pub mod test_utils {
    use super::*;

    thread_local! {
        static ACTIVE_CRASH_INJECTION: RefCell<Option<CrashPoint>> = const { RefCell::new(None) };
    }

    pub fn create_test_object_graph() -> ObjectGraph {
        let mut graph = ObjectGraph::new();

        let readme = Object::file(b"object graph e2e readme\n".to_vec());
        let manifest = Object::file(b"object graph e2e manifest\n".to_vec());
        let readme_id = readme.id.clone();
        let manifest_id = manifest.id.clone();
        graph
            .add_object(readme)
            .expect("readme object should be valid");
        graph
            .add_object(manifest)
            .expect("manifest object should be valid");

        let root = Object::directory(vec![
            ObjectEdge::new(readme_id, "README.txt".to_string()),
            ObjectEdge::new(manifest_id, "manifest.txt".to_string()),
        ]);
        graph
            .add_root(root)
            .expect("directory root should be valid");
        graph.validate().expect("test object graph should validate");
        graph
    }

    #[allow(dead_code)]
    pub fn create_test_manifest() -> Manifest {
        Manifest::from_graph(&ObjectGraph::new(), MetadataPolicy::portable())
            .expect("empty object graph should produce a manifest")
    }

    pub fn setup_crash_injection(crash_point: CrashPoint) {
        ACTIVE_CRASH_INJECTION.with(|slot| {
            *slot.borrow_mut() = Some(crash_point);
        });
    }

    pub fn active_crash_injection() -> Option<CrashPoint> {
        ACTIVE_CRASH_INJECTION.with(|slot| *slot.borrow())
    }

    pub fn clear_crash_injection() {
        ACTIVE_CRASH_INJECTION.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }

    pub fn verify_recovery_consistency(artifact: &TestArtifact) -> Result<(), String> {
        if artifact.crash_point.is_some()
            && artifact.recovery_state.is_none()
            && !artifact.is_injected_crash_record()
        {
            return Err(format!(
                "crash point recorded without recovery evidence: {}",
                artifact.test_name
            ));
        }

        match artifact.recovery_state {
            Some(RecoveryState::Completed) => {
                if artifact.final_commit_record.is_none() {
                    return Err("completed recovery missing final commit".to_string());
                }
                if !artifact.has_verified_material() {
                    return Err("completed recovery missing verification evidence".to_string());
                }
            }
            Some(RecoveryState::PartialCompletion | RecoveryState::Resuming) => {
                if artifact.chunk_ranges.is_empty() && artifact.bitmap_changes.is_empty() {
                    return Err("resumable recovery missing partial progress evidence".to_string());
                }
                if artifact.final_commit_record.is_some() {
                    return Err("partial recovery must not expose a final commit".to_string());
                }
            }
            Some(
                RecoveryState::VerificationFailed
                | RecoveryState::CommitFailed
                | RecoveryState::RepairFailed,
            ) => {
                if artifact.final_commit_record.is_some() {
                    return Err("failed recovery state must not expose a final commit".to_string());
                }
            }
            Some(RecoveryState::RenameRequired) => {
                if artifact.chunk_ranges.is_empty() {
                    return Err("rename recovery missing durable chunk evidence".to_string());
                }
            }
            Some(RecoveryState::Quarantined | RecoveryState::RetryRequired) | None => {}
        }

        Ok(())
    }

    pub fn check_final_state_integrity(artifact: &TestArtifact) -> Result<(), String> {
        for (start, end) in &artifact.chunk_ranges {
            if start >= end {
                return Err(format!(
                    "invalid empty or reversed chunk range: {start}-{end}"
                ));
            }
        }

        let mut bitmap_changes = artifact.bitmap_changes.clone();
        bitmap_changes.sort_unstable();
        if bitmap_changes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("duplicate bitmap change recorded".to_string());
        }

        if artifact.final_commit_record.is_some()
            && !artifact.is_injected_crash_record()
            && !artifact.has_verified_material()
        {
            return Err("final commit missing verified material".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committed_artifact() -> TestArtifact {
        let object_id = ObjectId::content(ContentId::from_bytes(b"committed-object"));
        let mut artifact = TestArtifact::new("committed".to_string(), object_id.clone());
        artifact.record_manifest_root(*object_id.hash_bytes());
        artifact.record_chunk_range(0, 16);
        artifact.record_bitmap_change(0);
        artifact.record_verifier_decision(VerificationResult::Valid {
            object_id,
            content_hash: [7; 32],
            verified_at: SystemTime::UNIX_EPOCH,
        });
        artifact.record_worker_started("worker:committed".to_string());
        artifact.record_worker_finished("worker:committed".to_string());
        artifact.record_final_commit("committed".to_string());
        artifact.record_recovery_state(RecoveryState::Completed);
        artifact
    }

    #[test]
    fn object_graph_fixture_uses_real_objects_and_manifest() {
        let graph = test_utils::create_test_object_graph();
        let roots = graph.roots().cloned().collect::<Vec<_>>();

        assert_eq!(graph.object_count(), 3);
        assert_eq!(roots.len(), 1);
        let root = graph.get_object(&roots[0]).expect("root object");
        assert_eq!(root.metadata.kind, ObjectKind::DirectoryObject);
        assert_eq!(root.children.len(), 2);
        assert!(Manifest::from_graph(&graph, MetadataPolicy::portable()).is_ok());
    }

    #[test]
    fn harness_detects_obligation_and_worker_leaks() {
        let mut harness = ObjectGraphTestHarness::new(ObjectTestConfig::default()).unwrap();
        let mut leaked = committed_artifact();
        leaked.record_obligation_opened("leaked-obligation".to_string());
        leaked.record_worker_started("leaked-worker".to_string());
        harness.artifacts.push(leaked);

        assert!(
            harness
                .assert_no_obligation_leaks()
                .expect_err("leaked obligation should fail")
                .contains("leaked-obligation")
        );
        assert!(
            harness
                .assert_no_live_workers()
                .expect_err("live worker should fail")
                .contains("leaked-worker")
        );
    }

    #[test]
    fn harness_rejects_unverified_final_exposure() {
        let mut harness = ObjectGraphTestHarness::new(ObjectTestConfig::default()).unwrap();
        let mut artifact = TestArtifact::new(
            "unverified".to_string(),
            ObjectId::content(ContentId::from_bytes(b"x")),
        );
        artifact.record_final_commit("exposed without verification".to_string());
        harness.artifacts.push(artifact);

        assert!(
            harness
                .assert_no_unverified_exposure()
                .expect_err("unverified exposure should fail")
                .contains("unverified")
        );
    }

    #[test]
    fn recovery_and_final_state_checks_are_executable() {
        let artifact = committed_artifact();
        test_utils::verify_recovery_consistency(&artifact).unwrap();
        test_utils::check_final_state_integrity(&artifact).unwrap();

        let mut partial = TestArtifact::new(
            "bad-partial".to_string(),
            ObjectId::content(ContentId::from_bytes(b"bad-partial")),
        )
        .with_crash_point(CrashPoint::ChunkWrite);
        partial.record_recovery_state(RecoveryState::PartialCompletion);

        assert!(
            test_utils::verify_recovery_consistency(&partial)
                .expect_err("partial recovery without progress should fail")
                .contains("partial progress")
        );
    }

    #[test]
    fn crash_injection_helper_records_active_point() {
        test_utils::clear_crash_injection();
        assert_eq!(test_utils::active_crash_injection(), None);

        test_utils::setup_crash_injection(CrashPoint::FinalRename);
        assert_eq!(
            test_utils::active_crash_injection(),
            Some(CrashPoint::FinalRename)
        );

        test_utils::clear_crash_injection();
        assert_eq!(test_utils::active_crash_injection(), None);
    }
}
