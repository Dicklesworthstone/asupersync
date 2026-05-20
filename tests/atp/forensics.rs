//! ATP Forensics and Failure Artifact Generation
//!
//! Captures and records failure artifacts that can be replayed
//! or reduced by the lab for crash-resume testing analysis.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// ATP failure artifact bundle
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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

/// Bitmap change record
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
            system_state: capture_system_state(),
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
            let filename = format!("atp_failure_{}.json", artifact.artifact_id);
            let path = self.output_dir.join(&filename);

            let json = serde_json::to_string_pretty(&artifact)?;
            std::fs::write(&path, json)?;

            tracing::info!("ATP failure artifact saved: {}", path.display());
            Ok(path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No active capture session"
            ))
        }
    }

    /// Load artifact from file
    pub fn load_artifact<P: AsRef<Path>>(path: P) -> Result<AtpFailureArtifact, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let artifact: AtpFailureArtifact = serde_json::from_str(&content)?;
        Ok(artifact)
    }

    /// Generate replay command for artifact
    pub fn generate_replay_command(artifact: &AtpFailureArtifact) -> String {
        let mut cmd = String::from("cargo test");

        if let Some(test_case) = &artifact.test_case {
            cmd.push_str(&format!(" {}", test_case.test_function));

            // Add environment variables
            if let Some(seed) = test_case.parameters.get("seed") {
                cmd.push_str(&format!(" -- --seed {}", seed));
            }
        }

        cmd.push_str(&format!(" # Replay artifact {}", artifact.artifact_id));
        cmd
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
        let minimized_parameters = artifact.test_case
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
        // Implement test case minimization logic
        // This would try reducing data sizes, simplifying operations, etc.

        if let Some(original_test) = &self.original_artifact.test_case {
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
        vec![
            "1. Create ATP context".to_string(),
            "2. Configure fault injection".to_string(),
            "3. Execute transfer operation".to_string(),
            "4. Trigger crash".to_string(),
            "5. Attempt recovery".to_string(),
            "6. Validate state".to_string(),
        ]
    }
}

// Helper functions

fn generate_artifact_id() -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let timestamp = current_timestamp();
    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn capture_stack_trace() -> Option<String> {
    // In a real implementation, this would capture the actual stack trace
    // For now, return a placeholder
    Some("Stack trace capture not implemented".to_string())
}

fn capture_journal_offsets() -> JournalOffsets {
    // In a real implementation, this would query the actual journal
    JournalOffsets {
        last_written: 0,
        last_flushed: 0,
        last_committed: 0,
        recovery_checkpoint: 0,
    }
}

fn capture_system_state() -> SystemState {
    use std::process;

    SystemState {
        disk_space_bytes: 0, // Would query actual disk space
        memory_usage_bytes: 0, // Would query actual memory usage
        cpu_load: 0.0, // Would query actual CPU load
        open_fds: 0, // Would query actual open FDs
        env_vars: std::env::vars().collect(),
        pid: process::id(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_forensics_creation() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let forensics = AtpForensics::new(temp_dir.path())?;
        assert!(temp_dir.path().exists());
        Ok(())
    }

    #[test]
    fn test_failure_artifact_capture() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let mut forensics = AtpForensics::new(temp_dir.path())?;

        forensics.start_capture("crash", "Test crash", "file_transfer");
        forensics.record_manifest_root("abc123");

        let artifact_path = forensics.finish_capture()?;
        assert!(artifact_path.exists());

        let loaded = AtpForensics::load_artifact(&artifact_path)?;
        assert_eq!(loaded.context.failure_type, "crash");
        assert_eq!(loaded.manifest_root.unwrap(), "abc123");

        Ok(())
    }

    #[test]
    fn test_replay_command_generation() {
        let artifact = AtpFailureArtifact {
            artifact_id: "test123".to_string(),
            timestamp: 0,
            context: FailureContext {
                failure_type: "crash".to_string(),
                error_message: "test".to_string(),
                stack_trace: None,
                operation: "test".to_string(),
                object_info: None,
                crash_point: None,
            },
            manifest_root: None,
            chunk_ranges: Vec::new(),
            journal_offsets: JournalOffsets {
                last_written: 0,
                last_flushed: 0,
                last_committed: 0,
                recovery_checkpoint: 0,
            },
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
            test_case: Some(ReproducibleTestCase {
                test_function: "test_file_transfer".to_string(),
                parameters: [("seed".to_string(), serde_json::Value::Number(42.into()))]
                    .iter().cloned().collect(),
                random_seed: 42,
                lab_config: None,
                reproduction_steps: Vec::new(),
            }),
        };

        let cmd = AtpForensics::generate_replay_command(&artifact);
        assert!(cmd.contains("test_file_transfer"));
        assert!(cmd.contains("test123"));
    }
}