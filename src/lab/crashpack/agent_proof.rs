//! Agent task proof bundles for replayable agent work evidence.
//!
//! This module implements ASW-6 requirements for agent task run reproduction:
//!
//! - **AgentTaskProofBundle**: Serializable evidence for agent work sessions
//! - **Replay instructions**: Safe replay guidance with permission levels
//! - **Redaction policy**: Token/path/content filtering for privacy
//! - **ASW integration**: Validation frontier and lab harness coordination
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::crashpack::agent_proof::{AgentTaskProofBundleBuilder, ReplaySafetyLevel};
//!
//! // Create proof bundle for agent task
//! let bundle = AgentTaskProofBundleBuilder::new()
//!     .with_objective("Fix bug in stream handler")
//!     .with_agent_id("SapphireHill")
//!     .with_bead_id("asupersync-abc123")
//!     .with_command("cargo test --lib stream", 0)
//!     .with_rch_worker("worker-456")
//!     .with_commit_id("abc123def")
//!     .build()?;
//!
//! bundle.emit_proof_artifacts("proof_bundles/task_123/")?;
//! ```

use super::{AtpEvidenceLedger, CrashpackError};
use crate::lab::oracle::evidence::EvidenceEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Schema version for agent task proof bundles.
pub const AGENT_PROOF_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Maximum command output length before redaction (16KB).
const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024;

/// Maximum file path length in proof bundles.
const MAX_PATH_LENGTH: usize = 512;

/// Serializable proof bundle for agent task runs and coordination failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTaskProofBundle {
    /// Schema version for compatibility.
    pub schema_version: u32,

    /// Objective description of what the agent was trying to accomplish.
    pub objective: String,

    /// Agent identifier that performed the work.
    pub agent_id: String,

    /// Bead IDs claimed or worked on during this task.
    pub bead_ids: Vec<String>,

    /// File reservations held during the task.
    pub file_reservations: Vec<FileReservationRecord>,

    /// File paths touched during the task.
    pub touched_paths: Vec<PathBuf>,

    /// Commands executed with outputs and exit statuses.
    pub commands: Vec<CommandRecord>,

    /// RCH worker admission and refusal details.
    pub rch_details: Option<RchRecord>,

    /// Git commit IDs before and after the task.
    pub commit_ids: CommitRecord,

    /// Validation frontier summary when the task started.
    pub validation_frontier: ValidationFrontierRecord,

    /// Agent Mail thread IDs related to this task.
    pub mail_thread_ids: Vec<String>,

    /// Proof artifact paths generated during the task.
    pub artifact_paths: Vec<PathBuf>,

    /// First blocker that prevented task completion (if any).
    pub first_blocker: Option<BlockerRecord>,

    /// Replay instructions for this task.
    pub replay_instructions: ReplayInstructions,

    /// Evidence ledger for validation.
    pub evidence_ledger: AtpEvidenceLedger,

    /// Session metadata.
    pub metadata: BTreeMap<String, String>,
}

/// File reservation record for proof bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReservationRecord {
    /// Path that was reserved.
    pub path: PathBuf,
    /// Agent that held the reservation.
    pub holder: String,
    /// Reservation timestamp or ID.
    pub reservation_id: String,
    /// Whether the reservation was released cleanly.
    pub released_cleanly: bool,
}

/// Command execution record with redacted outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    /// Command that was executed.
    pub command: String,
    /// Working directory when command was run.
    pub working_dir: PathBuf,
    /// Exit status code.
    pub exit_status: i32,
    /// Stdout output (redacted if necessary).
    pub stdout: String,
    /// Stderr output (redacted if necessary).
    pub stderr: String,
    /// Whether outputs were redacted due to size or content.
    pub outputs_redacted: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// RCH worker details for proof bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchRecord {
    /// RCH worker ID that handled the task (if admitted).
    pub worker_id: Option<String>,
    /// Whether the task was admitted or refused.
    pub admitted: bool,
    /// Refusal reason if not admitted.
    pub refusal_reason: Option<String>,
    /// RCH queue position when submitted.
    pub queue_position: Option<u32>,
    /// Total time spent waiting for RCH.
    pub wait_time_ms: Option<u64>,
}

/// Git commit record for before/after state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Commit ID before the task started.
    pub before_commit: String,
    /// Commit ID after the task completed (if any).
    pub after_commit: Option<String>,
    /// Whether the working tree was dirty before starting.
    pub dirty_tree_before: bool,
    /// Whether the working tree was dirty after completion.
    pub dirty_tree_after: bool,
    /// Changed files if available.
    pub changed_files: Vec<PathBuf>,
}

/// Validation frontier record at task start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFrontierRecord {
    /// Main branch commit being validated against.
    pub main_commit: String,
    /// Known compilation failures.
    pub compile_failures: Vec<String>,
    /// Test failures on the frontier.
    pub test_failures: Vec<String>,
    /// Whether production lib lane was green.
    pub production_lib_green: bool,
}

/// Blocker that prevented task completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockerRecord {
    /// Type of blocker (e.g., "compile_error", "test_failure", "reservation_conflict").
    pub blocker_type: String,
    /// Human-readable description of the blocker.
    pub description: String,
    /// File or component that caused the blocker.
    pub source_location: Option<String>,
    /// Whether this blocker was due to concurrent changes.
    pub concurrent_change: bool,
}

/// Replay instructions with safety levels and permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayInstructions {
    /// Safety level for replay.
    pub safety_level: ReplaySafetyLevel,
    /// Commands that can be replayed safely.
    pub safe_commands: Vec<String>,
    /// Commands that require remote worker.
    pub remote_required_commands: Vec<String>,
    /// Commands that require explicit user approval.
    pub approval_required_commands: Vec<String>,
    /// Environment variables needed for replay.
    pub environment_variables: BTreeMap<String, String>,
    /// Files that must be restored before replay.
    pub required_file_state: Vec<PathBuf>,
    /// Instructions for manual preparation.
    pub manual_setup_instructions: Vec<String>,
}

/// Safety level for replay operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplaySafetyLevel {
    /// Replay is completely safe locally.
    Safe,
    /// Replay requires remote worker but no special permissions.
    RemoteRequired,
    /// Replay has environment-specific dependencies.
    EnvironmentDependent,
    /// Replay requires explicit user approval for destructive operations.
    ApprovalRequired,
}

/// Builder for agent task proof bundles.
#[derive(Debug, Default)]
pub struct AgentTaskProofBundleBuilder {
    objective: Option<String>,
    agent_id: Option<String>,
    bead_ids: Vec<String>,
    file_reservations: Vec<FileReservationRecord>,
    touched_paths: Vec<PathBuf>,
    commands: Vec<CommandRecord>,
    rch_details: Option<RchRecord>,
    commit_ids: Option<CommitRecord>,
    validation_frontier: Option<ValidationFrontierRecord>,
    mail_thread_ids: Vec<String>,
    artifact_paths: Vec<PathBuf>,
    first_blocker: Option<BlockerRecord>,
    replay_instructions: Option<ReplayInstructions>,
    evidence_ledger: AtpEvidenceLedger,
    metadata: BTreeMap<String, String>,
}

impl AgentTaskProofBundleBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the objective for this task.
    pub fn with_objective(mut self, objective: impl Into<String>) -> Self {
        self.objective = Some(objective.into());
        self
    }

    /// Set the agent ID.
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Add a bead ID that was worked on.
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_ids.push(bead_id.into());
        self
    }

    /// Add a file reservation record.
    pub fn with_file_reservation(mut self, reservation: FileReservationRecord) -> Self {
        self.file_reservations.push(reservation);
        self
    }

    /// Add a touched file path.
    pub fn with_touched_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if !self.touched_paths.contains(&path) {
            self.touched_paths.push(path); // ubs:ignore - pushing to vector, not path join
        }
        self
    }

    /// Add a command execution record.
    pub fn with_command(mut self, command: impl Into<String>, exit_status: i32) -> Self {
        let record = CommandRecord {
            command: command.into(),
            working_dir: std::env::current_dir().unwrap_or_default(),
            exit_status,
            stdout: String::new(),
            stderr: String::new(),
            outputs_redacted: false,
            duration_ms: 0,
        };
        self.commands.push(record);
        self
    }

    /// Add a complete command record with outputs.
    pub fn with_command_record(mut self, record: CommandRecord) -> Self {
        self.commands.push(record);
        self
    }

    /// Set RCH details.
    pub fn with_rch_details(mut self, rch: RchRecord) -> Self {
        self.rch_details = Some(rch);
        self
    }

    /// Convenience method to set RCH worker.
    pub fn with_rch_worker(mut self, worker_id: impl Into<String>) -> Self {
        self.rch_details = Some(RchRecord {
            worker_id: Some(worker_id.into()),
            admitted: true,
            refusal_reason: None,
            queue_position: None,
            wait_time_ms: None,
        });
        self
    }

    /// Set commit record.
    pub fn with_commit_record(mut self, commits: CommitRecord) -> Self {
        self.commit_ids = Some(commits);
        self
    }

    /// Convenience method to set commit ID.
    pub fn with_commit_id(mut self, commit_id: impl Into<String>) -> Self {
        self.commit_ids = Some(CommitRecord {
            before_commit: commit_id.into(),
            after_commit: None,
            dirty_tree_before: false,
            dirty_tree_after: false,
            changed_files: Vec::new(),
        });
        self
    }

    /// Set validation frontier.
    pub fn with_validation_frontier(mut self, frontier: ValidationFrontierRecord) -> Self {
        self.validation_frontier = Some(frontier);
        self
    }

    /// Add mail thread ID.
    pub fn with_mail_thread_id(mut self, thread_id: impl Into<String>) -> Self {
        self.mail_thread_ids.push(thread_id.into());
        self
    }

    /// Add artifact path.
    pub fn with_artifact_path(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if !self.artifact_paths.contains(&path) {
            self.artifact_paths.push(path); // ubs:ignore - pushing to vector, not path join
        }
        self
    }

    /// Set first blocker.
    pub fn with_first_blocker(mut self, blocker: BlockerRecord) -> Self {
        self.first_blocker = Some(blocker);
        self
    }

    /// Set replay instructions.
    pub fn with_replay_instructions(mut self, instructions: ReplayInstructions) -> Self {
        self.replay_instructions = Some(instructions);
        self
    }

    /// Add evidence to the ledger.
    pub fn with_evidence(
        mut self,
        oracle_name: impl Into<String>,
        evidence: EvidenceEntry,
    ) -> Self {
        self.evidence_ledger
            .record_oracle_result(oracle_name, evidence, None);
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the proof bundle.
    pub fn build(self) -> Result<AgentTaskProofBundle, AgentProofError> {
        let objective = self
            .objective
            .ok_or(AgentProofError::MissingField("objective"))?;
        let agent_id = self
            .agent_id
            .ok_or(AgentProofError::MissingField("agent_id"))?;

        // Provide default values for required fields
        let commit_ids = self.commit_ids.unwrap_or_else(|| CommitRecord {
            before_commit: "unknown".to_string(),
            after_commit: None,
            dirty_tree_before: false,
            dirty_tree_after: false,
            changed_files: Vec::new(),
        });

        let validation_frontier =
            self.validation_frontier
                .unwrap_or_else(|| ValidationFrontierRecord {
                    main_commit: "unknown".to_string(),
                    compile_failures: Vec::new(),
                    test_failures: Vec::new(),
                    production_lib_green: false,
                });

        let replay_instructions = self
            .replay_instructions
            .unwrap_or_else(|| ReplayInstructions {
                safety_level: ReplaySafetyLevel::ApprovalRequired,
                safe_commands: Vec::new(),
                remote_required_commands: Vec::new(),
                approval_required_commands: self
                    .commands
                    .iter()
                    .map(|c| c.command.clone())
                    .collect(),
                environment_variables: BTreeMap::new(),
                required_file_state: Vec::new(),
                manual_setup_instructions: vec![
                    "Review commands before replay".to_string(),
                    "Ensure clean working directory".to_string(),
                ],
            });

        let bundle = AgentTaskProofBundle {
            schema_version: AGENT_PROOF_BUNDLE_SCHEMA_VERSION,
            objective,
            agent_id,
            bead_ids: self.bead_ids,
            file_reservations: self.file_reservations,
            touched_paths: self.touched_paths,
            commands: apply_redaction_policy(self.commands),
            rch_details: self.rch_details,
            commit_ids,
            validation_frontier,
            mail_thread_ids: self.mail_thread_ids,
            artifact_paths: self.artifact_paths,
            first_blocker: self.first_blocker,
            replay_instructions,
            evidence_ledger: self.evidence_ledger,
            metadata: self.metadata,
        };

        validate_bundle(&bundle)?;
        Ok(bundle)
    }
}

impl AgentTaskProofBundle {
    /// Emit proof artifacts to the specified directory.
    pub fn emit_proof_artifacts(
        &self,
        output_dir: impl AsRef<Path>,
    ) -> Result<(), AgentProofError> {
        let output_dir = output_dir.as_ref();
        std::fs::create_dir_all(output_dir)?;

        // Emit main proof bundle
        let bundle_path = output_dir.join("agent_proof_bundle.json");
        let bundle_json = serde_json::to_string_pretty(self)?;
        std::fs::write(&bundle_path, bundle_json)?;

        // Emit evidence ledger
        let evidence_path = output_dir.join("evidence_ledger.json");
        std::fs::write(&evidence_path, self.evidence_ledger.export_json()?)?;

        // Emit replay script
        let replay_script = self.generate_replay_script()?;
        let replay_path = output_dir.join("replay.sh");
        std::fs::write(&replay_path, replay_script)?;

        // Make replay script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&replay_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&replay_path, perms)?;
        }

        // Emit command summary
        let command_summary = self.generate_command_summary();
        let commands_path = output_dir.join("commands.txt");
        std::fs::write(&commands_path, command_summary)?;

        // Emit blocker report if there was one
        if let Some(ref blocker) = self.first_blocker {
            let blocker_report = self.generate_blocker_report(blocker);
            let blocker_path = output_dir.join("blocker_report.txt");
            std::fs::write(&blocker_path, blocker_report)?;
        }

        Ok(())
    }

    fn generate_replay_script(&self) -> Result<String, AgentProofError> {
        let mut script = String::from("#!/bin/bash\n");
        script.push_str("# Agent Task Proof Bundle Replay Script\n");
        script.push_str(&format!("# Generated for agent: {}\n", self.agent_id));
        script.push_str(&format!("# Objective: {}\n", self.objective));
        script.push_str(&format!(
            "# Safety level: {:?}\n",
            self.replay_instructions.safety_level
        ));
        script.push('\n');

        script.push_str("set -euo pipefail\n\n");

        // Add safety warning
        script.push_str("echo \"WARNING: This replay script contains agent task commands.\"\n");
        script.push_str(&format!(
            "echo \"Safety level: {:?}\"\n",
            self.replay_instructions.safety_level
        ));

        match self.replay_instructions.safety_level {
            ReplaySafetyLevel::Safe => {
                script.push_str("echo \"All commands are safe to run.\"\n");
            }
            ReplaySafetyLevel::RemoteRequired => {
                script.push_str("echo \"Some commands require remote worker.\"\n");
            }
            ReplaySafetyLevel::EnvironmentDependent => {
                script.push_str("echo \"Commands depend on specific environment setup.\"\n");
            }
            ReplaySafetyLevel::ApprovalRequired => {
                script.push_str("echo \"Commands require explicit approval before execution.\"\n");
                script.push_str("read -p \"Continue? (y/N) \" -n 1 -r\n");
                script.push_str("echo\n");
                script.push_str("if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi\n");
            }
        }
        script.push('\n');

        // Set environment variables
        if !self.replay_instructions.environment_variables.is_empty() {
            script.push_str("# Environment variables\n");
            for (key, value) in &self.replay_instructions.environment_variables {
                script.push_str(&format!("export {}={}\n", key, shell_escape(value)));
            }
            script.push('\n');
        }

        // Add manual setup instructions
        if !self
            .replay_instructions
            .manual_setup_instructions
            .is_empty()
        {
            script.push_str("# Manual setup required:\n");
            for instruction in &self.replay_instructions.manual_setup_instructions {
                script.push_str(&format!("# - {}\n", instruction));
            }
            script.push('\n');
        }

        // Add commands by safety category
        if !self.replay_instructions.safe_commands.is_empty() {
            script.push_str("# Safe commands\n");
            for cmd in &self.replay_instructions.safe_commands {
                script.push_str(&format!("echo \"Running: {}\"\n", cmd));
                script.push_str(&format!("{}\n", cmd));
            }
            script.push('\n');
        }

        if !self.replay_instructions.remote_required_commands.is_empty() {
            script.push_str("# Remote worker required commands\n");
            for cmd in &self.replay_instructions.remote_required_commands {
                script.push_str(&format!("echo \"Remote required: {}\"\n", cmd));
                script.push_str(&format!("# {}\n", cmd));
            }
            script.push('\n');
        }

        if !self
            .replay_instructions
            .approval_required_commands
            .is_empty()
        {
            script.push_str("# Approval required commands\n");
            for cmd in &self.replay_instructions.approval_required_commands {
                script.push_str(&format!("read -p \"Execute '{}'? (y/N) \" -n 1 -r\n", cmd));
                script.push_str("echo\n");
                script.push_str("if [[ $REPLY =~ ^[Yy]$ ]]; then\n");
                script.push_str(&format!("    {}\n", cmd));
                script.push_str("else\n");
                script.push_str(&format!("    echo \"Skipped: {}\"\n", cmd));
                script.push_str("fi\n");
            }
        }

        script.push_str("\necho \"Replay complete.\"\n");
        Ok(script)
    }

    fn generate_command_summary(&self) -> String {
        let mut summary = "Agent Task Command Summary\n".to_string();
        summary.push_str(&format!("Agent: {}\n", self.agent_id));
        summary.push_str(&format!("Objective: {}\n", self.objective));
        summary.push_str(&format!("Commands executed: {}\n\n", self.commands.len()));

        for (i, cmd) in self.commands.iter().enumerate() {
            summary.push_str(&format!("Command {}: {}\n", i + 1, cmd.command));
            summary.push_str(&format!("  Exit status: {}\n", cmd.exit_status));
            summary.push_str(&format!("  Duration: {}ms\n", cmd.duration_ms));
            summary.push_str(&format!("  Working dir: {}\n", cmd.working_dir.display()));

            if cmd.outputs_redacted {
                summary.push_str("  Outputs: [REDACTED]\n");
            } else {
                if !cmd.stdout.is_empty() {
                    summary.push_str(&format!(
                        "  Stdout: {}\n",
                        truncate_output(&cmd.stdout, 200)
                    ));
                }
                if !cmd.stderr.is_empty() {
                    summary.push_str(&format!(
                        "  Stderr: {}\n",
                        truncate_output(&cmd.stderr, 200)
                    ));
                }
            }
            summary.push('\n');
        }

        summary
    }

    fn generate_blocker_report(&self, blocker: &BlockerRecord) -> String {
        let mut report = String::from("Agent Task Blocker Report\n");
        report.push_str("========================\n\n");
        report.push_str(&format!("Blocker Type: {}\n", blocker.blocker_type));
        report.push_str(&format!("Description: {}\n", blocker.description));

        if let Some(ref location) = blocker.source_location {
            report.push_str(&format!("Source: {}\n", location));
        }

        report.push_str(&format!(
            "Concurrent Change: {}\n",
            blocker.concurrent_change
        ));
        report.push('\n');

        if blocker.concurrent_change {
            report.push_str(
                "This blocker was likely caused by concurrent changes to the codebase.\n",
            );
            report.push_str("Consider retrying the task after syncing with the latest changes.\n");
        }

        report
    }
}

/// Apply redaction policy to command records.
fn apply_redaction_policy(commands: Vec<CommandRecord>) -> Vec<CommandRecord> {
    commands
        .into_iter()
        .map(|mut cmd| {
            let stdout_redacted = should_redact_output(&cmd.stdout);
            let stderr_redacted = should_redact_output(&cmd.stderr);

            if stdout_redacted || stderr_redacted {
                cmd.outputs_redacted = true;

                if stdout_redacted {
                    cmd.stdout =
                        "[REDACTED - output too long or contains sensitive content]".to_string();
                }

                if stderr_redacted {
                    cmd.stderr =
                        "[REDACTED - output too long or contains sensitive content]".to_string();
                }
            }

            // Redact sensitive patterns in command itself
            cmd.command = redact_sensitive_patterns(cmd.command);

            cmd
        })
        .collect()
}

/// Check if output should be redacted.
fn should_redact_output(output: &str) -> bool {
    // Redact if too long
    if output.len() > MAX_COMMAND_OUTPUT_BYTES {
        return true;
    }

    // Redact if contains sensitive patterns
    let sensitive_patterns = [
        "token=",
        "password=",
        "secret=",
        "key=",
        "auth=",
        "bearer ",
        "api_key",
    ];

    let output_lower = output.to_ascii_lowercase();
    sensitive_patterns
        .iter()
        .any(|pattern| output_lower.contains(pattern))
}

/// Redact sensitive patterns from command strings.
fn redact_sensitive_patterns(command: String) -> String {
    let mut result = command;

    // Simple pattern matching for sensitive flags
    let sensitive_patterns = [
        "--token=",
        "--password=",
        "--secret=",
        "--api-key=",
        "--auth=",
    ];

    for pattern in &sensitive_patterns {
        if let Some(start) = result.find(pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = result[value_start..].find(' ').map(|i| value_start + i) {
                result.replace_range(value_start..end, "[REDACTED]");
            } else {
                // Value extends to end of string
                result.replace_range(value_start.., "[REDACTED]");
            }
        }
    }

    // Handle special case of -p flag with space-separated value
    if let Some(p_idx) = result.find(" -p ") {
        let value_start = p_idx + 4;
        if let Some(end) = result[value_start..].find(' ').map(|i| value_start + i) {
            result.replace_range(value_start..end, "[REDACTED]");
        } else {
            result.replace_range(value_start.., "[REDACTED]");
        }
    }

    result
}

/// Validate proof bundle before creation.
fn validate_bundle(bundle: &AgentTaskProofBundle) -> Result<(), AgentProofError> {
    if bundle.objective.is_empty() {
        return Err(AgentProofError::InvalidBundle(
            "Objective cannot be empty".to_string(),
        ));
    }

    if bundle.agent_id.is_empty() {
        return Err(AgentProofError::InvalidBundle(
            "Agent ID cannot be empty".to_string(),
        ));
    }

    // Validate path lengths
    for path in &bundle.touched_paths {
        if path.as_os_str().len() > MAX_PATH_LENGTH {
            return Err(AgentProofError::InvalidBundle(format!(
                "Path too long: {}",
                path.display()
            )));
        }
    }

    for path in &bundle.artifact_paths {
        if path.as_os_str().len() > MAX_PATH_LENGTH {
            return Err(AgentProofError::InvalidBundle(format!(
                "Artifact path too long: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Shell-escape a string for safe inclusion in scripts.
fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Truncate output to a reasonable length for summaries.
fn truncate_output(output: &str, max_chars: usize) -> String {
    if output.len() <= max_chars {
        output.replace('\n', "\\n")
    } else {
        format!(
            "{}... [truncated]",
            output[..max_chars].replace('\n', "\\n")
        )
    }
}

/// Errors for agent proof bundle operations.
#[derive(Debug, Error)]
pub enum AgentProofError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Crashpack error: {0}")]
    Crashpack(#[from] CrashpackError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_objective_and_agent_id() {
        let result = AgentTaskProofBundleBuilder::new().build();
        assert!(matches!(
            result,
            Err(AgentProofError::MissingField("objective"))
        ));

        let result = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .build();
        assert!(matches!(
            result,
            Err(AgentProofError::MissingField("agent_id"))
        ));

        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .build()
            .expect("should build with required fields");

        assert_eq!(bundle.objective, "test task");
        assert_eq!(bundle.agent_id, "TestAgent");
    }

    #[test]
    fn commands_are_redacted_for_sensitive_content() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("curl --token=secret123 https://api.example.com", 0)
            .build()
            .expect("should build");

        assert_eq!(bundle.commands.len(), 1);
        assert!(bundle.commands[0].command.contains("[REDACTED]"));
        assert!(!bundle.commands[0].command.contains("secret123"));
    }

    #[test]
    fn replay_instructions_default_to_approval_required() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("cargo test", 0)
            .build()
            .expect("should build");

        assert_eq!(
            bundle.replay_instructions.safety_level,
            ReplaySafetyLevel::ApprovalRequired
        );
        assert_eq!(
            bundle.replay_instructions.approval_required_commands,
            vec!["cargo test"]
        );
    }

    #[test]
    fn touched_paths_are_deduplicated() {
        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_touched_path("src/main.rs")
            .with_touched_path("src/main.rs")
            .with_touched_path("src/lib.rs")
            .build()
            .expect("should build");

        assert_eq!(bundle.touched_paths.len(), 2);
        assert!(bundle.touched_paths.contains(&PathBuf::from("src/main.rs")));
        assert!(bundle.touched_paths.contains(&PathBuf::from("src/lib.rs")));
    }

    #[test]
    fn bundle_validation_rejects_empty_fields() {
        let result = AgentTaskProofBundle {
            schema_version: AGENT_PROOF_BUNDLE_SCHEMA_VERSION,
            objective: String::new(),
            agent_id: "TestAgent".to_string(),
            bead_ids: Vec::new(),
            file_reservations: Vec::new(),
            touched_paths: Vec::new(),
            commands: Vec::new(),
            rch_details: None,
            commit_ids: CommitRecord {
                before_commit: "abc123".to_string(),
                after_commit: None,
                dirty_tree_before: false,
                dirty_tree_after: false,
                changed_files: Vec::new(),
            },
            validation_frontier: ValidationFrontierRecord {
                main_commit: "def456".to_string(),
                compile_failures: Vec::new(),
                test_failures: Vec::new(),
                production_lib_green: true,
            },
            mail_thread_ids: Vec::new(),
            artifact_paths: Vec::new(),
            first_blocker: None,
            replay_instructions: ReplayInstructions {
                safety_level: ReplaySafetyLevel::Safe,
                safe_commands: Vec::new(),
                remote_required_commands: Vec::new(),
                approval_required_commands: Vec::new(),
                environment_variables: BTreeMap::new(),
                required_file_state: Vec::new(),
                manual_setup_instructions: Vec::new(),
            },
            evidence_ledger: AtpEvidenceLedger::new(),
            metadata: BTreeMap::new(),
        };

        assert!(matches!(
            validate_bundle(&result),
            Err(AgentProofError::InvalidBundle(_))
        ));
    }

    #[test]
    fn proof_bundle_can_emit_artifacts() {
        use tempfile::TempDir;

        let bundle = AgentTaskProofBundleBuilder::new()
            .with_objective("test task")
            .with_agent_id("TestAgent")
            .with_command("echo hello", 0)
            .build()
            .expect("should build");

        let temp_dir = TempDir::new().expect("should create temp dir");
        bundle
            .emit_proof_artifacts(temp_dir.path())
            .expect("should emit artifacts");

        // Check that expected files were created
        assert!(temp_dir.path().join("agent_proof_bundle.json").exists());
        assert!(temp_dir.path().join("evidence_ledger.json").exists());
        assert!(temp_dir.path().join("replay.sh").exists());
        assert!(temp_dir.path().join("commands.txt").exists());

        // Verify replay script is executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(temp_dir.path().join("replay.sh"))
                .expect("should read permissions");
            assert!(perms.permissions().mode() & 0o111 != 0);
        }
    }
}
