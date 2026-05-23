//! ATP Forensics and Failure Artifact Generation
//!
//! Captures and records failure artifacts that can be replayed
//! or reduced by the lab for crash-resume testing analysis.

use serde::{Deserialize, Serialize};
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ARTIFACT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// ATP failure artifact bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpFailureArtifact {
    /// Unique artifact ID
    pub artifact_id: String,
    /// Timestamp when failure occurred
    pub timestamp: u64,
    /// Failure context information
    pub context: FailureContext,
    /// Manifest root at time of failure
    pub manifest_root: Option<String>,
    /// Chunk ranges that were being processed
    pub chunk_ranges: Vec<ChunkRangeInfo>,
    /// Journal offsets at failure
    pub journal_offsets: JournalOffsets,
    /// Bitmap changes leading to failure
    pub bitmap_changes: Vec<BitmapChange>,
    /// Verifier decisions and state
    pub verifier_decisions: Vec<VerifierDecision>,
    /// Final commit record if available
    pub final_commit_record: Option<CommitRecord>,
    /// Environment and system state
    pub system_state: SystemState,
    /// Reproducible test case
    pub test_case: Option<ReproducibleTestCase>,
}

/// Failure context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureContext {
    /// Type of failure
    pub failure_type: String,
    /// Error message
    pub error_message: String,
    /// Stack trace if available
    pub stack_trace: Option<String>,
    /// Operation being performed
    pub operation: String,
    /// Object being processed
    pub object_info: Option<ObjectInfo>,
    /// Crash point if injected
    pub crash_point: Option<String>,
}

/// Information about chunk ranges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRangeInfo {
    /// Starting offset
    pub start_offset: u64,
    /// Length of range
    pub length: u64,
    /// Chunk hash
    pub chunk_hash: String,
    /// Processing state
    pub state: String,
    /// Verification status
    pub verified: bool,
}

/// Journal offset tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalOffsets {
    /// Last written offset
    pub last_written: u64,
    /// Last flushed offset
    pub last_flushed: u64,
    /// Last committed offset
    pub last_committed: u64,
    /// Recovery checkpoint offset
    pub recovery_checkpoint: u64,
}

impl JournalOffsets {
    pub fn validate_monotonic(&self) -> Result<(), String> {
        if self.last_committed > self.last_flushed {
            return Err(format!(
                "last_committed {} exceeds last_flushed {}",
                self.last_committed, self.last_flushed
            ));
        }
        if self.last_flushed > self.last_written {
            return Err(format!(
                "last_flushed {} exceeds last_written {}",
                self.last_flushed, self.last_written
            ));
        }
        if self.recovery_checkpoint > self.last_committed {
            return Err(format!(
                "recovery_checkpoint {} exceeds last_committed {}",
                self.recovery_checkpoint, self.last_committed
            ));
        }
        Ok(())
    }
}

/// Bitmap change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitmapChange {
    /// Chunk index
    pub chunk_index: u64,
    /// Previous state
    pub previous_state: String,
    /// New state
    pub new_state: String,
    /// Timestamp of change
    pub timestamp: u64,
}

/// Verifier decision record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierDecision {
    /// Verification stage
    pub stage: String,
    /// Object or chunk being verified
    pub target: String,
    /// Decision outcome
    pub decision: String,
    /// Reason for decision
    pub reason: Option<String>,
    /// Timestamp of decision
    pub timestamp: u64,
}

/// Final commit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Commit ID
    pub commit_id: String,
    /// Objects committed
    pub objects: Vec<String>,
    /// Manifest hash
    pub manifest_hash: String,
    /// Proof bundle hash
    pub proof_bundle_hash: Option<String>,
    /// Commit timestamp
    pub timestamp: u64,
}

/// Object information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectInfo {
    /// Object ID
    pub object_id: String,
    /// Object kind
    pub object_kind: String,
    /// Object size
    pub size: u64,
    /// Metadata
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// System state at failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    /// Available disk space
    pub disk_space_bytes: u64,
    /// Memory usage
    pub memory_usage_bytes: u64,
    /// CPU load
    pub cpu_load: f64,
    /// Open file descriptors
    pub open_fds: u32,
    /// Environment variables
    pub env_vars: BTreeMap<String, String>,
    /// Process ID
    pub pid: u32,
}

/// Reproducible test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibleTestCase {
    /// Test function name
    pub test_function: String,
    /// Test parameters
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// Random seed used
    pub random_seed: u64,
    /// Lab configuration
    pub lab_config: Option<serde_json::Value>,
    /// Minimal reproduction steps
    pub reproduction_steps: Vec<String>,
}

/// ATP forensics collector
pub struct AtpForensics {
    /// Output directory for artifacts
    output_dir: PathBuf,
    /// Current artifact being built
    current_artifact: Option<AtpFailureArtifact>,
}

impl AtpForensics {
    /// Create new forensics collector
    pub fn new<P: AsRef<Path>>(output_dir: P) -> Result<Self, std::io::Error> {
        let output_dir = output_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&output_dir)?;

        Ok(Self {
            output_dir,
            current_artifact: None,
        })
    }

    /// Start capturing failure artifact
    pub fn start_capture(&mut self, failure_type: &str, error_message: &str, operation: &str) {
        let artifact_id = generate_artifact_id();
        let timestamp = current_timestamp();

        self.current_artifact = Some(AtpFailureArtifact {
            artifact_id,
            timestamp,
            context: FailureContext {
                failure_type: failure_type.to_string(),
                error_message: error_message.to_string(),
                stack_trace: capture_stack_trace(),
                operation: operation.to_string(),
                object_info: None,
                crash_point: None,
            },
            manifest_root: None,
            chunk_ranges: Vec::new(),
            journal_offsets: capture_journal_offsets(),
            bitmap_changes: Vec::new(),
            verifier_decisions: Vec::new(),
            final_commit_record: None,
            system_state: capture_system_state(&self.output_dir),
            test_case: None,
        });
    }

    /// Record manifest root
    pub fn record_manifest_root(&mut self, root: &str) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.manifest_root = Some(root.to_string());
        }
    }

    /// Record chunk range information
    pub fn record_chunk_range(&mut self, range: ChunkRangeInfo) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.chunk_ranges.push(range);
        }
    }

    /// Record bitmap change
    pub fn record_bitmap_change(&mut self, change: BitmapChange) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.bitmap_changes.push(change);
        }
    }

    /// Record verifier decision
    pub fn record_verifier_decision(&mut self, decision: VerifierDecision) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.verifier_decisions.push(decision);
        }
    }

    /// Record journal offsets observed at the failure boundary.
    pub fn record_journal_offsets(
        &mut self,
        offsets: JournalOffsets,
    ) -> Result<(), Box<dyn std::error::Error>> {
        offsets.validate_monotonic()?;
        if let Some(artifact) = &mut self.current_artifact {
            artifact.journal_offsets = offsets;
            Ok(())
        } else {
            Err("No active capture session".into())
        }
    }

    /// Record final commit
    pub fn record_final_commit(&mut self, commit: CommitRecord) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.final_commit_record = Some(commit);
        }
    }

    /// Set crash point
    pub fn set_crash_point(&mut self, crash_point: &str) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.context.crash_point = Some(crash_point.to_string());
        }
    }

    /// Set object information
    pub fn set_object_info(&mut self, object_info: ObjectInfo) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.context.object_info = Some(object_info);
        }
    }

    /// Set reproducible test case
    pub fn set_test_case(&mut self, test_case: ReproducibleTestCase) {
        if let Some(artifact) = &mut self.current_artifact {
            artifact.test_case = Some(test_case);
        }
    }

    /// Finish capture and save artifact
    pub fn finish_capture(&mut self) -> Result<PathBuf, std::io::Error> {
        if let Some(artifact) = self.current_artifact.take() {
            validate_artifact(&artifact).map_err(invalid_data)?;

            let filename = format!("atp_failure_{}.json", artifact.artifact_id);
            let path = self.output_dir.join(&filename);

            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            serde_json::to_writer_pretty(&mut file, &artifact).map_err(invalid_data)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            sync_directory(&self.output_dir)?;

            tracing::info!("ATP failure artifact saved: {}", path.display());
            Ok(path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No active capture session",
            ))
        }
    }

    /// Load artifact from file
    pub fn load_artifact<P: AsRef<Path>>(
        path: P,
    ) -> Result<AtpFailureArtifact, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let artifact: AtpFailureArtifact = serde_json::from_str(&content)?;
        Ok(artifact)
    }

    /// Generate replay command for artifact
    pub fn generate_replay_command(artifact: &AtpFailureArtifact) -> String {
        let mut args = vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "asupersync".to_string(),
            "--test".to_string(),
            "atp_e2e_proof_suite".to_string(),
        ];

        if let Some(test_case) = &artifact.test_case {
            args.push(test_case.test_function.clone());
            args.push("--".to_string());
            args.push("--exact".to_string());
            args.push("--seed".to_string());
            args.push(test_case.random_seed.to_string());
            args.push("--artifact".to_string());
            args.push(artifact.artifact_id.clone());
        }

        args.into_iter()
            .map(|arg| quote_shell_arg(&arg))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Create minimizer for reducing failure case
    pub fn create_minimizer(artifact: &AtpFailureArtifact) -> AtpMinimizer {
        AtpMinimizer::new(artifact.clone())
    }
}

/// ATP test case minimizer
pub struct AtpMinimizer {
    original_artifact: AtpFailureArtifact,
    minimized_parameters: BTreeMap<String, serde_json::Value>,
}

impl AtpMinimizer {
    /// Create new minimizer
    pub fn new(artifact: AtpFailureArtifact) -> Self {
        let minimized_parameters = artifact
            .test_case
            .as_ref()
            .map(|tc| tc.parameters.clone())
            .unwrap_or_default();

        Self {
            original_artifact: artifact,
            minimized_parameters,
        }
    }

    /// Attempt to minimize test case
    pub fn minimize(&mut self) -> Result<ReproducibleTestCase, Box<dyn std::error::Error>> {
        if let Some(original_test) = &self.original_artifact.test_case {
            self.minimized_parameters =
                minimize_replay_parameters(&original_test.parameters, &self.original_artifact);
            Ok(ReproducibleTestCase {
                test_function: original_test.test_function.clone(),
                parameters: self.minimized_parameters.clone(),
                random_seed: original_test.random_seed,
                lab_config: original_test.lab_config.clone(),
                reproduction_steps: self.generate_minimal_steps(),
            })
        } else {
            Err("No test case to minimize".into())
        }
    }

    /// Generate minimal reproduction steps
    fn generate_minimal_steps(&self) -> Vec<String> {
        let artifact = &self.original_artifact;
        let mut steps = vec![format!(
            "run {} during {}",
            artifact
                .test_case
                .as_ref()
                .map(|test_case| test_case.test_function.as_str())
                .unwrap_or("<unknown-test>"),
            artifact.context.operation
        )];

        if let Some(object_info) = &artifact.context.object_info {
            steps.push(format!(
                "materialize {} object {} with {} bytes",
                object_info.object_kind, object_info.object_id, object_info.size
            ));
        }
        if let Some(root) = &artifact.manifest_root {
            steps.push(format!("pin manifest root {root}"));
        }
        if !artifact.chunk_ranges.is_empty() {
            steps.push(format!(
                "replay {} chunk range witness(es)",
                artifact.chunk_ranges.len()
            ));
        }
        if let Some(crash_point) = &artifact.context.crash_point {
            steps.push(format!("inject crash at {crash_point}"));
        }
        if !artifact.verifier_decisions.is_empty() {
            steps.push(format!(
                "assert {} verifier decision witness(es)",
                artifact.verifier_decisions.len()
            ));
        }
        steps.push(format!(
            "validate journal offsets committed={} flushed={} written={}",
            artifact.journal_offsets.last_committed,
            artifact.journal_offsets.last_flushed,
            artifact.journal_offsets.last_written
        ));
        steps
    }
}

// Helper functions

fn validate_artifact(artifact: &AtpFailureArtifact) -> Result<(), String> {
    if artifact.artifact_id.trim().is_empty() {
        return Err("artifact_id must not be empty".to_string());
    }
    if artifact.context.failure_type.trim().is_empty() {
        return Err("failure_type must not be empty".to_string());
    }
    if artifact.context.operation.trim().is_empty() {
        return Err("operation must not be empty".to_string());
    }
    artifact.journal_offsets.validate_monotonic()?;
    for range in &artifact.chunk_ranges {
        if range.length == 0 {
            return Err(format!(
                "chunk range at offset {} must have nonzero length",
                range.start_offset
            ));
        }
        if range.chunk_hash.trim().is_empty() {
            return Err(format!(
                "chunk range at offset {} must record a chunk hash",
                range.start_offset
            ));
        }
        if range.state.trim().is_empty() {
            return Err(format!(
                "chunk range at offset {} must record a state",
                range.start_offset
            ));
        }
    }
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, error.to_string())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn generate_artifact_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let timestamp = current_timestamp_nanos();
    let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    counter.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn current_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn capture_stack_trace() -> Option<String> {
    let stack_trace = format!("{:#}", Backtrace::force_capture());
    if stack_trace.trim().is_empty() {
        None
    } else {
        Some(stack_trace)
    }
}

fn capture_journal_offsets() -> JournalOffsets {
    JournalOffsets {
        last_written: 0,
        last_flushed: 0,
        last_committed: 0,
        recovery_checkpoint: 0,
    }
}

fn capture_system_state(output_dir: &Path) -> SystemState {
    use std::process;

    SystemState {
        disk_space_bytes: available_disk_space(output_dir).unwrap_or_default(),
        memory_usage_bytes: resident_memory_bytes().unwrap_or_default(),
        cpu_load: system_load_average().unwrap_or_default(),
        open_fds: open_fd_count().unwrap_or_default(),
        env_vars: std::env::vars().collect(),
        pid: process::id(),
    }
}

#[cfg(unix)]
fn available_disk_space(path: &Path) -> Option<u64> {
    let stat = nix::sys::statvfs::statvfs(path).ok()?;
    stat.blocks_available().checked_mul(stat.fragment_size())
}

#[cfg(not(unix))]
fn available_disk_space(_path: &Path) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn resident_memory_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("VmRSS:")?;
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        kb.checked_mul(1024)
    })
}

#[cfg(not(target_os = "linux"))]
fn resident_memory_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn system_load_average() -> Option<f64> {
    let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
    loadavg.split_whitespace().next()?.parse::<f64>().ok()
}

#[cfg(not(target_os = "linux"))]
fn system_load_average() -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn open_fd_count() -> Option<u32> {
    let count = std::fs::read_dir("/proc/self/fd").ok()?.count();
    u32::try_from(count).ok()
}

#[cfg(not(target_os = "linux"))]
fn open_fd_count() -> Option<u32> {
    None
}

fn quote_shell_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn minimize_replay_parameters(
    parameters: &BTreeMap<String, serde_json::Value>,
    artifact: &AtpFailureArtifact,
) -> BTreeMap<String, serde_json::Value> {
    let mut minimized = BTreeMap::new();
    for (key, value) in parameters {
        if is_diagnostic_parameter(key) {
            continue;
        }
        if is_replay_parameter(key, artifact) || !is_default_json(value) {
            minimized.insert(key.clone(), minimize_json_value(key, value));
        }
    }
    minimized
}

fn minimize_json_value(key: &str, value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .filter(|item| {
                    is_replay_parameter(key, empty_artifact_ref()) || !is_default_json(item)
                })
                .map(|item| minimize_json_value(key, item))
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .filter(|(field, item)| {
                    !is_diagnostic_parameter(field)
                        && (is_replay_parameter(field, empty_artifact_ref())
                            || !is_default_json(item))
                })
                .map(|(field, item)| (field.clone(), minimize_json_value(field, item)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn is_default_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(false) => true,
        serde_json::Value::Number(number) => number.as_i64() == Some(0),
        serde_json::Value::String(text) => text.is_empty(),
        serde_json::Value::Array(items) => items.is_empty(),
        serde_json::Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn is_replay_parameter(key: &str, artifact: &AtpFailureArtifact) -> bool {
    let key = key.to_ascii_lowercase();
    key == "seed"
        || key.contains("crash")
        || key.contains("fault")
        || key.contains("manifest")
        || key.contains("object")
        || key.contains("chunk")
        || key.contains("offset")
        || key.contains("range")
        || key.contains("stage")
        || key.contains("transfer")
        || key.contains("journal")
        || key.contains("proof")
        || artifact
            .context
            .object_info
            .as_ref()
            .is_some_and(|object| object.metadata.contains_key(key.as_str()))
}

fn is_diagnostic_parameter(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("debug")
        || key.starts_with("diagnostic")
        || key.starts_with("log")
        || key.starts_with("trace_dump")
        || key.starts_with("unused")
}

fn empty_artifact_ref() -> &'static AtpFailureArtifact {
    static EMPTY: std::sync::OnceLock<AtpFailureArtifact> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| AtpFailureArtifact {
        artifact_id: "empty".to_string(),
        timestamp: 0,
        context: FailureContext {
            failure_type: "empty".to_string(),
            error_message: String::new(),
            stack_trace: None,
            operation: "empty".to_string(),
            object_info: None,
            crash_point: None,
        },
        manifest_root: None,
        chunk_ranges: Vec::new(),
        journal_offsets: capture_journal_offsets(),
        bitmap_changes: Vec::new(),
        verifier_decisions: Vec::new(),
        final_commit_record: None,
        system_state: SystemState {
            disk_space_bytes: 0,
            memory_usage_bytes: 0,
            cpu_load: 0.0,
            open_fds: 0,
            env_vars: BTreeMap::new(),
            pid: 0,
        },
        test_case: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_forensics_creation() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let _forensics = AtpForensics::new(temp_dir.path())?;
        assert!(temp_dir.path().exists());
        Ok(())
    }

    #[test]
    fn test_failure_artifact_capture() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut forensics = AtpForensics::new(temp_dir.path())?;

        forensics.start_capture("crash", "Test crash", "file_transfer");
        forensics.record_manifest_root("abc123");
        forensics.record_journal_offsets(JournalOffsets {
            last_written: 64,
            last_flushed: 64,
            last_committed: 32,
            recovery_checkpoint: 32,
        })?;
        forensics.record_chunk_range(ChunkRangeInfo {
            start_offset: 0,
            length: 32,
            chunk_hash: "sha256:chunk-a".to_string(),
            state: "verified".to_string(),
            verified: true,
        });

        let artifact_path = forensics.finish_capture()?;
        assert!(artifact_path.exists());

        let loaded = AtpForensics::load_artifact(&artifact_path)?;
        assert_eq!(loaded.context.failure_type, "crash");
        assert_eq!(loaded.manifest_root.unwrap(), "abc123");
        assert_eq!(loaded.journal_offsets.last_written, 64);
        assert_eq!(loaded.journal_offsets.last_flushed, 64);
        assert_eq!(loaded.journal_offsets.last_committed, 32);
        assert_eq!(loaded.journal_offsets.recovery_checkpoint, 32);
        assert_eq!(loaded.chunk_ranges.len(), 1);
        assert_eq!(loaded.system_state.pid, std::process::id());
        #[cfg(target_os = "linux")]
        {
            assert!(
                loaded.system_state.open_fds > 0,
                "linux artifact should record open fd count"
            );
            assert!(
                loaded.system_state.memory_usage_bytes > 0,
                "linux artifact should record resident memory"
            );
            assert!(
                loaded.system_state.disk_space_bytes > 0,
                "linux artifact should record available disk space for the artifact dir"
            );
        }
        let stack_trace = loaded
            .context
            .stack_trace
            .as_deref()
            .expect("failure artifact should include captured stack trace");
        let legacy_stack_trace_marker = ["Stack trace capture ", "not ", "implemented"].concat();
        assert!(
            !stack_trace.contains(&legacy_stack_trace_marker),
            "stack trace regressed to legacy sentinel text: {stack_trace}"
        );
        assert!(
            stack_trace.lines().count() > 1,
            "stack trace should include more than a single marker line: {stack_trace}"
        );

        Ok(())
    }

    #[test]
    fn test_journal_offsets_reject_non_monotonic_capture() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp_dir = TempDir::new()?;
        let mut forensics = AtpForensics::new(temp_dir.path())?;
        forensics.start_capture("crash", "bad journal offsets", "file_transfer");

        let err = forensics
            .record_journal_offsets(JournalOffsets {
                last_written: 8,
                last_flushed: 16,
                last_committed: 8,
                recovery_checkpoint: 8,
            })
            .expect_err("flushed offset beyond written offset must fail");

        assert!(
            err.to_string().contains("last_flushed"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn test_artifact_ids_do_not_overwrite_same_second_captures()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut first = AtpForensics::new(temp_dir.path())?;
        first.start_capture("crash", "first", "file_transfer");
        let first_path = first.finish_capture()?;

        let mut second = AtpForensics::new(temp_dir.path())?;
        second.start_capture("crash", "second", "file_transfer");
        let second_path = second.finish_capture()?;

        assert_ne!(first_path, second_path);
        let first_artifact = AtpForensics::load_artifact(first_path)?;
        let second_artifact = AtpForensics::load_artifact(second_path)?;
        assert_ne!(first_artifact.artifact_id, second_artifact.artifact_id);
        assert_eq!(first_artifact.context.error_message, "first");
        assert_eq!(second_artifact.context.error_message, "second");
        Ok(())
    }

    #[test]
    fn test_stack_trace_capture_records_backtrace_text() {
        let stack_trace = capture_stack_trace().expect("stack trace should be captured");
        assert!(
            !stack_trace.trim().is_empty(),
            "stack trace should not be empty"
        );
        let legacy_stack_trace_marker = ["Stack trace capture ", "not ", "implemented"].concat();
        assert!(
            !stack_trace.contains(&legacy_stack_trace_marker),
            "stack trace must not use legacy sentinel text"
        );
        assert!(
            stack_trace.lines().count() > 1,
            "forced backtrace should contain frame-oriented text: {stack_trace}"
        );
    }

    fn replay_artifact() -> AtpFailureArtifact {
        let parameters = BTreeMap::from([
            ("seed".to_string(), serde_json::json!(42)),
            ("crash_point".to_string(), serde_json::json!("post_fsync")),
            ("object_id".to_string(), serde_json::json!("obj-7")),
            (
                "diagnostic_blob".to_string(),
                serde_json::json!({"verbose": true, "frames": ["noise"]}),
            ),
            ("unused_empty".to_string(), serde_json::json!("")),
        ]);

        AtpFailureArtifact {
            artifact_id: "test123".to_string(),
            timestamp: 0,
            context: FailureContext {
                failure_type: "crash".to_string(),
                error_message: "test".to_string(),
                stack_trace: None,
                operation: "test".to_string(),
                object_info: Some(ObjectInfo {
                    object_id: "obj-7".to_string(),
                    object_kind: "file".to_string(),
                    size: 4096,
                    metadata: BTreeMap::new(),
                }),
                crash_point: Some("post_fsync".to_string()),
            },
            manifest_root: Some("manifest-root".to_string()),
            chunk_ranges: vec![ChunkRangeInfo {
                start_offset: 0,
                length: 4096,
                chunk_hash: "sha256:chunk".to_string(),
                state: "verified".to_string(),
                verified: true,
            }],
            journal_offsets: JournalOffsets {
                last_written: 64,
                last_flushed: 64,
                last_committed: 32,
                recovery_checkpoint: 32,
            },
            bitmap_changes: Vec::new(),
            verifier_decisions: vec![VerifierDecision {
                stage: "ChunkHash".to_string(),
                target: "obj-7:0".to_string(),
                decision: "accepted".to_string(),
                reason: Some("digest matched".to_string()),
                timestamp: 1,
            }],
            final_commit_record: None,
            system_state: SystemState {
                disk_space_bytes: 0,
                memory_usage_bytes: 0,
                cpu_load: 0.0,
                open_fds: 0,
                env_vars: BTreeMap::new(),
                pid: 0,
            },
            test_case: Some(ReproducibleTestCase {
                test_function: "test_file_transfer".to_string(),
                parameters,
                random_seed: 42,
                lab_config: None,
                reproduction_steps: Vec::new(),
            }),
        }
    }

    #[test]
    fn test_replay_command_generation() {
        let artifact = replay_artifact();

        let cmd = AtpForensics::generate_replay_command(&artifact);
        assert!(cmd.contains("-p asupersync"));
        assert!(cmd.contains("--test atp_e2e_proof_suite"));
        assert!(cmd.contains("test_file_transfer"));
        assert!(cmd.contains("--exact"));
        assert!(cmd.contains("--seed 42"));
        assert!(cmd.contains("test123"));
    }

    #[test]
    fn test_minimizer_preserves_replay_witness_and_strips_diagnostics()
    -> Result<(), Box<dyn std::error::Error>> {
        let artifact = replay_artifact();
        let mut minimizer = AtpForensics::create_minimizer(&artifact);

        let minimized = minimizer.minimize()?;

        assert_eq!(minimized.test_function, "test_file_transfer");
        assert_eq!(minimized.random_seed, 42);
        assert_eq!(
            minimized.parameters.get("seed"),
            Some(&serde_json::json!(42))
        );
        assert_eq!(
            minimized.parameters.get("crash_point"),
            Some(&serde_json::json!("post_fsync"))
        );
        assert_eq!(
            minimized.parameters.get("object_id"),
            Some(&serde_json::json!("obj-7"))
        );
        assert!(!minimized.parameters.contains_key("diagnostic_blob"));
        assert!(!minimized.parameters.contains_key("unused_empty"));
        assert!(
            minimized
                .reproduction_steps
                .iter()
                .any(|step| step.contains("inject crash at post_fsync")),
            "reproduction steps should preserve crash point: {:?}",
            minimized.reproduction_steps
        );
        assert!(
            minimized
                .reproduction_steps
                .iter()
                .any(|step| step.contains("validate journal offsets")),
            "reproduction steps should preserve journal evidence: {:?}",
            minimized.reproduction_steps
        );
        Ok(())
    }
}
