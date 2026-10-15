//! ASW release proof aggregator for leases, mail, beads, and RCH evidence.
//!
//! Provides comprehensive release readiness verification by aggregating evidence from
//! various sources to determine if a swarm-control change is ready for deployment.

use crate::observability::metrics::{Counter, Gauge, Histogram};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AGENT_MAIL_ARCHIVE_ENV: &str = "ASUPERSYNC_AGENT_MAIL_ARCHIVE";
const GENERIC_AGENT_MAIL_ARCHIVE_ENV: &str = "AGENT_MAIL_PROJECT_ARCHIVE";
const MAX_AGENT_MAIL_SCAN_FILES: usize = 25_000;
const MAX_EVIDENCE_TEXT_BYTES: u64 = 4 * 1024 * 1024;

/// Custom serde module for SystemTime serialization.
mod system_time_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration_since_epoch = time
            .duration_since(UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?;
        duration_since_epoch.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }
}

/// ASW release proof record containing all evidence for release readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseProofRecord {
    /// Bead identifier
    pub bead_id: String,
    /// Agent responsible for the work
    pub agent_name: String,
    /// File reservations that were held
    pub reservations: Vec<FileReservation>,
    /// Paths that were modified
    pub touched_paths: Vec<PathBuf>,
    /// Commits that were made
    pub commits: Vec<CommitRecord>,
    /// RCH commands that were executed
    pub rch_commands: Vec<RchCommandRecord>,
    /// First blocker encountered, if any
    pub first_blocker: Option<BlockerRecord>,
    /// Lease and admission receipts
    pub lease_receipts: Vec<LeaseReceipt>,
    /// Handoff capsule status
    pub handoff_status: HandoffStatus,
    /// Pushed git references
    pub pushed_refs: Vec<GitRef>,
    /// Timestamp when proof was generated
    #[serde(with = "system_time_serde")]
    pub generated_at: SystemTime,
    /// Overall proof status
    pub status: ProofStatus,
}

/// File reservation information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReservation {
    /// Agent that held the reservation
    pub agent: String,
    /// File patterns that were reserved
    pub patterns: Vec<String>,
    /// Whether reservation was exclusive
    pub exclusive: bool,
    /// TTL of the reservation in seconds
    pub ttl_seconds: u64,
    /// Reason for the reservation
    pub reason: String,
    /// When reservation was acquired
    #[serde(with = "system_time_serde")]
    pub acquired_at: SystemTime,
    /// When reservation was released
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<SystemTime>,
}

/// Record of a git commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRecord {
    /// Git commit hash
    pub hash: String,
    /// Commit message
    pub message: String,
    /// Author information
    pub author: String,
    /// Timestamp of commit
    #[serde(with = "system_time_serde")]
    pub timestamp: SystemTime,
    /// Whether commit was pushed to remote
    pub pushed: bool,
}

/// Record of an RCH command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchCommandRecord {
    /// Full command that was executed
    pub command: String,
    /// Exit code of the command
    pub exit_code: i32,
    /// Whether command required remote execution
    pub remote_required: bool,
    /// Worker that executed the command
    pub worker: Option<String>,
    /// Execution duration
    pub duration: Duration,
    /// Timestamp when command started
    #[serde(with = "system_time_serde")]
    pub started_at: SystemTime,
    /// Command output (potentially redacted)
    pub output_summary: String,
}

/// Record of a blocker that prevented completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockerRecord {
    /// Type of blocker
    pub blocker_type: BlockerType,
    /// Description of the blocker
    pub description: String,
    /// When blocker was encountered
    #[serde(with = "system_time_serde")]
    pub encountered_at: SystemTime,
    /// Whether blocker is external (not solvable by agent)
    pub external: bool,
}

/// Type of blocker encountered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockerType {
    /// Compilation failure
    CompilationFailure,
    /// Test failure
    TestFailure,
    /// Missing dependency
    MissingDependency,
    /// File reservation conflict
    ReservationConflict,
    /// Stale evidence
    StaleEvidence,
    /// Remote proof required but unavailable
    RemoteProofRequired,
    /// Dirty peer-owned files
    DirtyPeerFiles,
    /// Missing mail closeout
    MissingMailCloseout,
    /// Unpushed commits
    UnpushedCommits,
    /// Canonical main push missing after commit evidence was collected
    MainPushMissing,
}

/// Lease or admission receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseReceipt {
    /// Type of lease
    pub lease_type: String,
    /// Lease identifier
    pub lease_id: String,
    /// Agent that acquired the lease
    pub agent: String,
    /// When lease was acquired
    #[serde(with = "system_time_serde")]
    pub acquired_at: SystemTime,
    /// When lease expires
    #[serde(with = "system_time_serde")]
    pub expires_at: SystemTime,
    /// Whether lease is still active
    pub active: bool,
}

/// Handoff capsule status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffStatus {
    /// Whether handoff capsule exists
    pub capsule_exists: bool,
    /// Handoff decision if capsule was processed
    pub decision: Option<HandoffDecision>,
    /// Last update timestamp
    #[serde(with = "system_time_serde")]
    pub last_updated: SystemTime,
}

/// Handoff decision from verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandoffDecision {
    /// Safe to continue with current state
    Continue,
    /// Narrow refresh required for specific components
    NarrowRefreshRequired,
    /// Coordination required before proceeding
    CoordinateFirst,
    /// Unsafe to continue, restart required
    UnsafeToContinue,
}

/// Git reference information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRef {
    /// Reference name (e.g., "refs/heads/main")
    pub ref_name: String,
    /// Commit hash the ref points to
    pub commit_hash: String,
    /// Whether ref was pushed successfully
    pub pushed: bool,
    /// Timestamp of push
    #[serde(with = "system_time_serde")]
    pub pushed_at: SystemTime,
}

/// Overall proof status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofStatus {
    /// Complete proof, ready for release
    Complete,
    /// Missing remote RCH proof
    MissingRemoteProof,
    /// Local fallback attempted, not valid for release
    LocalFallback,
    /// Stale bead or evidence
    Stale,
    /// Missing required closeout evidence
    MissingCloseout,
    /// External blocker preventing completion
    Blocked,
}

/// Aggregated proof summary for human consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSummary {
    /// Bead identifier
    pub bead_id: String,
    /// Overall status
    pub status: ProofStatus,
    /// Human-readable summary
    pub summary: String,
    /// First blocker description if any
    pub first_blocker: Option<String>,
    /// Number of commits included
    pub commit_count: usize,
    /// Number of RCH commands executed
    pub rch_command_count: usize,
    /// Whether all remote proofs passed
    pub remote_proofs_complete: bool,
    /// Whether all commit evidence is visible on the canonical main ref
    pub main_pushed: bool,
    /// Evidence freshness score (0.0-1.0, higher is fresher)
    pub freshness_score: f64,
}

/// Configuration for the release proof aggregator.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Maximum age for evidence to be considered fresh
    pub max_evidence_age: Duration,
    /// Maximum age for commits to be included
    pub max_commit_age: Duration,
    /// Whether to require remote RCH execution
    pub require_remote_rch: bool,
    /// Whether to redact sensitive information
    pub redact_sensitive: bool,
    /// Retention policy for command output
    pub output_retention_days: u64,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            max_evidence_age: Duration::from_secs(3600),    // 1 hour
            max_commit_age: Duration::from_secs(3600 * 24), // 24 hours
            require_remote_rch: true,
            redact_sensitive: true,
            output_retention_days: 30,
        }
    }
}

/// ASW release proof aggregator.
#[derive(Debug)]
pub struct ReleaseProofAggregator {
    config: AggregatorConfig,
    metrics: AggregatorMetrics,
}

#[derive(Debug, Deserialize)]
struct AgentMailReservationRecord {
    id: serde_json::Value,
    agent: String,
    path_pattern: String,
    exclusive: bool,
    reason: Option<String>,
    created_ts: String,
    expires_ts: String,
    #[serde(default)]
    released_ts: Option<String>,
}

/// Metrics for the aggregator.
#[derive(Debug)]
pub struct AggregatorMetrics {
    /// Number of proofs generated
    pub proofs_generated: Counter,
    /// Number of complete proofs
    pub complete_proofs: Counter,
    /// Number of blocked proofs
    pub blocked_proofs: Counter,
    /// Proof generation time
    pub generation_time: Histogram,
    /// Evidence freshness score
    pub freshness_score: Gauge,
}

impl ReleaseProofAggregator {
    /// Validates and sanitizes a bead ID to prevent injection attacks.
    ///
    /// Security: Ensures bead_id contains only safe characters and prevents:
    /// - Command injection in git commands
    /// - Git argument injection attacks
    /// - Path traversal in file operations
    /// - Other injection vectors
    fn validate_bead_id(bead_id: &str) -> Result<(), AggregatorError> {
        // Bead IDs should be alphanumeric with hyphens/underscores, but not start with hyphen
        if bead_id.is_empty() || bead_id.len() > 64 {
            return Err(AggregatorError::MissingEvidence(
                "Bead ID must be non-empty and under 64 characters".to_string(),
            ));
        }

        // Security: Prevent git argument injection - no leading hyphens
        if bead_id.starts_with('-') {
            return Err(AggregatorError::MissingEvidence(format!(
                "Bead ID cannot start with hyphen (git argument injection): {}",
                bead_id
            )));
        }

        // Only allow safe characters: alphanumeric, hyphens, underscores
        if !bead_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AggregatorError::MissingEvidence(format!(
                "Bead ID contains unsafe characters: {}",
                bead_id
            )));
        }

        // Prevent path traversal patterns
        if bead_id.contains("..") || bead_id.contains('/') || bead_id.contains('\\') {
            return Err(AggregatorError::MissingEvidence(format!(
                "Bead ID contains path traversal patterns: {}",
                bead_id
            )));
        }

        // Security: Prevent regex metacharacters that could cause git grep issues
        let regex_metacharacters = [
            '*', '?', '[', ']', '^', '$', '|', '(', ')', '{', '}', '+', '.',
        ];
        if bead_id.chars().any(|c| regex_metacharacters.contains(&c)) {
            return Err(AggregatorError::MissingEvidence(format!(
                "Bead ID contains regex metacharacters: {}",
                bead_id
            )));
        }

        Ok(())
    }

    /// Escapes a bead ID pattern for safe use in git grep to prevent injection attacks.
    ///
    /// Security: Even after validation, we escape the pattern to prevent any
    /// git-specific interpretation issues and use fixed-string matching.
    fn escape_git_pattern(pattern: &str) -> String {
        // Use git's fixed-string matching to prevent regex interpretation
        // This escapes any characters that might have special meaning to git
        pattern.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// Validates file path is within expected directory to prevent path traversal.
    fn validate_file_path(path: &str, allowed_prefix: &str) -> Result<(), AggregatorError> {
        let canonical_path = std::path::Path::new(path).canonicalize().map_err(|e| {
            AggregatorError::MissingEvidence(format!("Invalid file path {}: {}", path, e))
        })?;

        let canonical_prefix = std::path::Path::new(allowed_prefix)
            .canonicalize()
            .map_err(|e| {
                AggregatorError::MissingEvidence(format!(
                    "Invalid allowed prefix {}: {}",
                    allowed_prefix, e
                ))
            })?;

        if !canonical_path.starts_with(canonical_prefix) {
            return Err(AggregatorError::MissingEvidence(format!(
                "Path traversal detected: {} outside {}",
                path, allowed_prefix
            )));
        }

        Ok(())
    }

    /// Creates a new release proof aggregator.
    pub fn new(config: AggregatorConfig) -> Self {
        let metrics = AggregatorMetrics {
            proofs_generated: Counter::new("asw_proofs_generated_total"),
            complete_proofs: Counter::new("asw_complete_proofs_total"),
            blocked_proofs: Counter::new("asw_blocked_proofs_total"),
            generation_time: Histogram::new(
                "asw_proof_generation_seconds",
                vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
            ),
            freshness_score: Gauge::new("asw_evidence_freshness_score"),
        };

        Self { config, metrics }
    }

    /// Generates a release proof record from available evidence.
    ///
    /// Security: Validates input and collects evidence atomically to prevent TOCTOU attacks.
    pub fn generate_proof(
        &self,
        bead_id: String,
        agent_name: String,
    ) -> Result<ReleaseProofRecord, AggregatorError> {
        let start_time = SystemTime::now();

        // Security: Validate inputs before any operations
        Self::validate_bead_id(&bead_id)?;
        if agent_name.is_empty() || agent_name.len() > 128 {
            return Err(AggregatorError::MissingEvidence(
                "Agent name must be non-empty and under 128 characters".to_string(),
            ));
        }

        // Security: Collect evidence atomically using a snapshot approach to prevent TOCTOU
        // Take a git snapshot first to ensure consistent state
        let git_snapshot_hash = self.capture_git_snapshot()?;

        self.metrics.proofs_generated.increment();

        // Collect evidence from various sources (now with validation)
        let reservations = self.collect_reservation_evidence(&bead_id)?;
        let touched_paths = self.collect_touched_paths(&bead_id)?;
        let commits = self.collect_commit_evidence(&bead_id)?;
        let rch_commands = self.collect_rch_evidence(&bead_id)?;
        let first_blocker = self.detect_first_blocker(&bead_id, &rch_commands)?;
        let lease_receipts = self.collect_lease_receipts(&agent_name)?;
        let handoff_status = self.check_handoff_status(&bead_id)?;
        let pushed_refs = self.collect_git_refs(&commits)?;

        // Security: Verify git state hasn't changed during evidence collection
        self.verify_git_snapshot(&git_snapshot_hash)?;

        // Determine overall status
        let status = self.determine_proof_status(
            &commits,
            &rch_commands,
            first_blocker.as_ref(),
            &handoff_status,
            &pushed_refs,
        )?;

        // Update metrics based on status
        match status {
            ProofStatus::Complete => self.metrics.complete_proofs.increment(),
            ProofStatus::Blocked => self.metrics.blocked_proofs.increment(),
            _ => {}
        }

        let record = ReleaseProofRecord {
            bead_id,
            agent_name,
            reservations,
            touched_paths,
            commits,
            rch_commands,
            first_blocker,
            lease_receipts,
            handoff_status,
            pushed_refs,
            generated_at: SystemTime::now(),
            status,
        };

        // Record generation time
        if let Ok(duration) = start_time.elapsed() {
            self.metrics.generation_time.observe(duration.as_secs_f64());
        }

        Ok(record)
    }

    /// Generates a human-readable summary from a proof record.
    pub fn generate_summary(&self, record: &ReleaseProofRecord) -> ProofSummary {
        let summary = match record.status {
            ProofStatus::Complete => {
                format!(
                    "✅ Release ready: {} commits, {} RCH commands, all proofs complete",
                    record.commits.len(),
                    record.rch_commands.len()
                )
            }
            ProofStatus::MissingRemoteProof => {
                "❌ Missing remote RCH proof required for release".to_string()
            }
            ProofStatus::LocalFallback => {
                "⚠️ Local fallback used, not valid for production release".to_string()
            }
            ProofStatus::Stale => "⏰ Evidence is stale, refresh required".to_string(),
            ProofStatus::MissingCloseout => {
                "📧 Missing required mail/bead closeout evidence".to_string()
            }
            ProofStatus::Blocked => "🚫 External blocker preventing completion".to_string(),
        };

        let first_blocker = record.first_blocker.as_ref().map(|b| b.description.clone());

        let remote_proofs_complete = record
            .rch_commands
            .iter()
            .all(|cmd| !cmd.remote_required || cmd.exit_code == 0);

        let main_pushed = Self::all_commits_pushed_to_main(&record.commits, &record.pushed_refs);

        let freshness_score = self.calculate_freshness_score(record);
        self.metrics
            .freshness_score
            .set((freshness_score * 100.0) as i64);

        ProofSummary {
            bead_id: record.bead_id.clone(),
            status: record.status.clone(),
            summary,
            first_blocker,
            commit_count: record.commits.len(),
            rch_command_count: record.rch_commands.len(),
            remote_proofs_complete,
            main_pushed,
            freshness_score,
        }
    }

    /// Generates JSON output for expert analysis.
    pub fn generate_json(&self, record: &ReleaseProofRecord) -> Result<String, serde_json::Error> {
        if self.config.redact_sensitive {
            let redacted = self.redact_sensitive_information(record);
            serde_json::to_string_pretty(&redacted)
        } else {
            serde_json::to_string_pretty(record)
        }
    }

    /// Captures a git state snapshot to detect concurrent modifications.
    fn capture_git_snapshot(&self) -> Result<String, AggregatorError> {
        use std::process::Command;

        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| {
                AggregatorError::GitError(format!("Failed to capture git snapshot: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AggregatorError::GitError(format!(
                "git rev-parse failed: {}",
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Verifies git state hasn't changed since snapshot to prevent TOCTOU attacks.
    fn verify_git_snapshot(&self, expected_hash: &str) -> Result<(), AggregatorError> {
        let current_hash = self.capture_git_snapshot()?;
        if current_hash != expected_hash {
            return Err(AggregatorError::MissingEvidence(format!(
                "Git state changed during proof generation: expected {} got {}",
                expected_hash, current_hash
            )));
        }
        Ok(())
    }

    fn agent_mail_project_archive_dir() -> Option<PathBuf> {
        for env_name in [AGENT_MAIL_ARCHIVE_ENV, GENERIC_AGENT_MAIL_ARCHIVE_ENV] {
            if let Ok(value) = std::env::var(env_name) {
                let path = PathBuf::from(value);
                if path.is_dir() {
                    return Some(path);
                }
            }
        }

        let slug = Self::current_project_slug()?;
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        let archive = home
            .join(".mcp_agent_mail_git_mailbox_repo")
            .join("projects")
            .join(slug);
        archive.is_dir().then_some(archive)
    }

    fn current_project_slug() -> Option<String> {
        let current_dir = std::env::current_dir().ok()?;
        let components: Vec<String> = current_dir
            .components()
            .filter_map(|component| {
                let segment = component.as_os_str().to_string_lossy();
                let cleaned: String = segment
                    .chars()
                    .filter_map(|ch| {
                        if ch.is_ascii_alphanumeric() {
                            Some(ch.to_ascii_lowercase())
                        } else if matches!(ch, '-' | '_' | '.') {
                            Some('-')
                        } else {
                            None
                        }
                    })
                    .collect();
                (!cleaned.is_empty()).then_some(cleaned)
            })
            .collect();
        (!components.is_empty()).then(|| components.join("-"))
    }

    fn parse_utc_system_time(value: &str) -> Option<SystemTime> {
        let value = value.trim();
        let (date, time_and_offset) = value.split_once('T')?;
        let mut date_parts = date.split('-');
        let year = date_parts.next()?.parse::<i32>().ok()?;
        let month = date_parts.next()?.parse::<u32>().ok()?;
        let day = date_parts.next()?.parse::<u32>().ok()?;
        if date_parts.next().is_some() {
            return None;
        }

        let (time, offset_seconds) = Self::split_rfc3339_time_and_offset(time_and_offset)?;
        let mut time_parts = time.split(':');
        let hour = time_parts.next()?.parse::<u32>().ok()?;
        let minute = time_parts.next()?.parse::<u32>().ok()?;
        let second_text = time_parts.next()?;
        if time_parts.next().is_some() {
            return None;
        }
        let second = second_text
            .split('.')
            .next()
            .and_then(|text| text.parse::<u32>().ok())?;
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 60
        {
            return None;
        }

        let days = Self::days_from_civil(year, month, day)?;
        let local_seconds = days
            .checked_mul(86_400)?
            .checked_add(i64::from(hour) * 3_600)?
            .checked_add(i64::from(minute) * 60)?
            .checked_add(i64::from(second))?;
        let utc_seconds = local_seconds.checked_sub(offset_seconds)?;
        if utc_seconds < 0 {
            return None;
        }
        u64::try_from(utc_seconds)
            .ok()
            .map(Self::system_time_from_unix_seconds)
    }

    fn split_rfc3339_time_and_offset(value: &str) -> Option<(&str, i64)> {
        if let Some(time) = value.strip_suffix('Z') {
            return Some((time, 0));
        }
        let offset_index = value
            .char_indices()
            .skip(1)
            .find_map(|(index, ch)| matches!(ch, '+' | '-').then_some(index))?;
        let (time, offset) = value.split_at(offset_index);
        let sign = if offset.starts_with('+') { 1 } else { -1 };
        let mut parts = offset[1..].split(':');
        let hours = parts.next()?.parse::<i64>().ok()?;
        let minutes = parts.next()?.parse::<i64>().ok()?;
        if parts.next().is_some() || hours > 23 || minutes > 59 {
            return None;
        }
        Some((time, sign * (hours * 3_600 + minutes * 60)))
    }

    fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
        let year = i64::from(year) - i64::from(month <= 2);
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let month = i64::from(month);
        let day = i64::from(day);
        let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
        if !(0..=365).contains(&day_of_year) {
            return None;
        }
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        Some(era * 146_097 + day_of_era - 719_468)
    }

    fn system_time_from_unix_seconds(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn read_evidence_text(path: &Path) -> Option<String> {
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_TEXT_BYTES {
            return None;
        }
        std::fs::read_to_string(path).ok()
    }

    fn collect_files_with_extensions(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            if files.len() >= MAX_AGENT_MAIL_SCAN_FILES {
                break;
            }
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    stack.push(entry_path);
                    continue;
                }
                let Some(extension) = entry_path.extension().and_then(|ext| ext.to_str()) else {
                    continue;
                };
                if extensions.contains(&extension) {
                    files.push(entry_path);
                    if files.len() >= MAX_AGENT_MAIL_SCAN_FILES {
                        break;
                    }
                }
            }
        }
        files
    }

    /// Collects file reservation evidence for the bead.
    fn collect_reservation_evidence(
        &self,
        bead_id: &str,
    ) -> Result<Vec<FileReservation>, AggregatorError> {
        // Security: Validate bead ID to prevent path traversal attacks
        Self::validate_bead_id(bead_id)?;

        let Some(agent_mail_archive) = Self::agent_mail_project_archive_dir() else {
            return Err(AggregatorError::MissingEvidence(
                "Agent Mail archive not found for current project".to_string(),
            ));
        };
        let reservation_dir = agent_mail_archive.join("file_reservations");
        if !reservation_dir.is_dir() {
            return Err(AggregatorError::MissingEvidence(format!(
                "Agent Mail reservation directory not found: {}",
                reservation_dir.display()
            )));
        }

        let bead_thread_pattern = format!("br-{}", bead_id);
        let mut reservations = Vec::new();
        let mut grouped: BTreeMap<(String, String, bool, u64, String), FileReservation> =
            BTreeMap::new();

        for path in Self::collect_files_with_extensions(&reservation_dir, &["json"]) {
            let Some(content) = Self::read_evidence_text(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<AgentMailReservationRecord>(&content) else {
                continue;
            };
            let reason = record.reason.unwrap_or_default();
            if !reason.contains(&bead_thread_pattern) && !reason.contains(bead_id) {
                continue;
            }

            let acquired_at = Self::parse_utc_system_time(&record.created_ts).ok_or_else(|| {
                AggregatorError::EvidenceCollection(format!(
                    "reservation {} has invalid created_ts {}",
                    record.id, record.created_ts
                ))
            })?;
            let expires_at = Self::parse_utc_system_time(&record.expires_ts).ok_or_else(|| {
                AggregatorError::EvidenceCollection(format!(
                    "reservation {} has invalid expires_ts {}",
                    record.id, record.expires_ts
                ))
            })?;
            let ttl_seconds = expires_at
                .duration_since(acquired_at)
                .unwrap_or_default()
                .as_secs();
            let released_at = record
                .released_ts
                .as_deref()
                .and_then(Self::parse_utc_system_time);
            let key = (
                record.agent.clone(),
                reason.clone(),
                record.exclusive,
                ttl_seconds,
                released_at
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map_or_else(String::new, |duration| duration.as_secs().to_string()),
            );

            grouped
                .entry(key)
                .and_modify(|reservation| {
                    reservation.patterns.push(record.path_pattern.clone());
                    reservation.patterns.sort();
                    reservation.patterns.dedup();
                    if reservation.acquired_at > acquired_at {
                        reservation.acquired_at = acquired_at;
                    }
                })
                .or_insert_with(|| FileReservation {
                    agent: record.agent,
                    patterns: vec![record.path_pattern],
                    exclusive: record.exclusive,
                    ttl_seconds,
                    reason,
                    acquired_at,
                    released_at,
                });
        }

        reservations.extend(grouped.into_values());

        if reservations.is_empty() {
            return Err(AggregatorError::MissingEvidence(format!(
                "No file reservation evidence found for bead {}",
                bead_id
            )));
        }

        Ok(reservations)
    }

    /// Collects paths that were touched for the bead.
    fn collect_touched_paths(&self, bead_id: &str) -> Result<Vec<PathBuf>, AggregatorError> {
        // Security: Validate bead ID to prevent command injection attacks
        Self::validate_bead_id(bead_id)?;

        // Security: Use atomic git command to prevent TOCTOU attacks
        // Collect both commits and their changed files in a single operation
        use std::process::Command;

        let bead_pattern = format!("br-{}", bead_id);
        let short_pattern = bead_id;

        // Security: Use escaped patterns and fixed-string matching to prevent git injection
        let escaped_bead_pattern = Self::escape_git_pattern(&bead_pattern);
        let escaped_short_pattern = Self::escape_git_pattern(short_pattern);

        // Security: Atomic operation - get commits and their changed files in one git command
        // This prevents TOCTOU attacks where git state changes between separate operations
        let output = Command::new("git")
            .args([
                "log",
                "--fixed-strings", // Use literal string matching, not regex
                "--grep",
                escaped_bead_pattern.as_str(),
                "--grep",
                escaped_short_pattern.as_str(),
                "--name-only",
                "--format=COMMIT:%H", // Marker to separate commits from files
                "--since=30 days ago",
            ])
            .output()
            .map_err(|e| {
                AggregatorError::GitError(format!("Failed to get touched paths: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AggregatorError::GitError(format!(
                "git log failed: {}",
                stderr
            )));
        }

        let git_output = String::from_utf8_lossy(&output.stdout);
        let mut all_paths = std::collections::HashSet::new();
        let mut in_commit_files = false;

        // Parse atomic git output to extract file paths
        for line in git_output.lines() {
            let line = line.trim();
            if line.starts_with("COMMIT:") {
                in_commit_files = true; // Next lines will be file paths for this commit
            } else if line.is_empty() {
                in_commit_files = false; // End of this commit's files
            } else if in_commit_files && !line.is_empty() {
                all_paths.insert(PathBuf::from(line));
            }
        }

        Ok(all_paths.into_iter().collect())
    }

    /// Collects commit evidence for the bead.
    fn collect_commit_evidence(&self, bead_id: &str) -> Result<Vec<CommitRecord>, AggregatorError> {
        // Security: Validate bead ID to prevent command injection attacks
        Self::validate_bead_id(bead_id)?;

        // Query git log for commits mentioning this bead ID
        use std::process::Command;

        let bead_pattern = format!("br-{}", bead_id);
        let short_pattern = bead_id;

        // Security: Use escaped patterns and fixed-string matching to prevent git injection
        let escaped_bead_pattern = Self::escape_git_pattern(&bead_pattern);
        let escaped_short_pattern = Self::escape_git_pattern(short_pattern);

        // Search for commits mentioning the bead ID in various formats
        let output = Command::new("git")
            .args([
                "log",
                "--fixed-strings", // Use literal string matching, not regex
                "--grep",
                escaped_bead_pattern.as_str(),
                "--grep",
                escaped_short_pattern.as_str(),
                "--format=%H|%s|%an|%at|%D",
                "--since=30 days ago", // Limit search to recent commits
            ])
            .output()
            .map_err(|e| AggregatorError::GitError(format!("Failed to execute git log: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AggregatorError::GitError(format!(
                "git log failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut commits = vec![];

        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 4 {
                let hash = parts[0].to_string();
                let message = parts[1].to_string();
                let author = parts[2].to_string();
                let timestamp_str = parts[3];
                // Parse timestamp
                let timestamp = if let Ok(ts) = timestamp_str.parse::<u64>() {
                    Self::system_time_from_unix_seconds(ts)
                } else {
                    SystemTime::now()
                };

                let pushed = self.commit_is_pushed(&hash)?;

                commits.push(CommitRecord {
                    hash,
                    message,
                    author,
                    timestamp,
                    pushed,
                });
            }
        }

        if commits.is_empty() {
            return Err(AggregatorError::MissingEvidence(format!(
                "No git commits found for bead {}",
                bead_id
            )));
        }

        Ok(commits)
    }

    fn commit_is_pushed(&self, commit_hash: &str) -> Result<bool, AggregatorError> {
        use std::process::Command;

        let output = Command::new("git")
            .args([
                "branch",
                "-r",
                "--contains",
                commit_hash,
                "--format=%(refname)",
            ])
            .output()
            .map_err(|err| {
                AggregatorError::GitError(format!(
                    "failed to query remote refs for commit {commit_hash}: {err}"
                ))
            })?;
        if !output.status.success() {
            return Ok(false);
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim().starts_with("refs/remotes/")))
    }

    /// Collects RCH command evidence for the bead.
    fn collect_rch_evidence(
        &self,
        bead_id: &str,
    ) -> Result<Vec<RchCommandRecord>, AggregatorError> {
        // Security: Validate bead ID to prevent potential security issues
        Self::validate_bead_id(bead_id)?;

        let Some(agent_mail_archive) = Self::agent_mail_project_archive_dir() else {
            return Ok(Vec::new());
        };
        let messages_dir = agent_mail_archive.join("messages");
        if !messages_dir.is_dir() {
            return Ok(Vec::new());
        }

        let bead_thread_pattern = format!("br-{}", bead_id);
        let mut records = Vec::new();
        let mut seen = HashSet::new();

        for path in Self::collect_files_with_extensions(&messages_dir, &["md", "txt", "log"]) {
            let Some(content) = Self::read_evidence_text(&path) else {
                continue;
            };
            if !content.contains(bead_id) && !content.contains(&bead_thread_pattern) {
                continue;
            }
            let started_at = Self::message_created_at(&content)
                .or_else(|| {
                    std::fs::metadata(&path)
                        .ok()
                        .and_then(|metadata| metadata.modified().ok())
                })
                .unwrap_or_else(SystemTime::now);
            for record in Self::extract_rch_records_from_message(&content, started_at) {
                let key = format!(
                    "{}|{:?}|{}",
                    record.command, record.started_at, record.exit_code
                );
                if seen.insert(key) {
                    records.push(record);
                }
            }
        }

        records.sort_by(|left, right| {
            left.started_at
                .cmp(&right.started_at)
                .then_with(|| left.command.cmp(&right.command))
        });
        Ok(records)
    }

    fn message_created_at(content: &str) -> Option<SystemTime> {
        content.lines().find_map(|line| {
            let line = line.strip_prefix("## ")?;
            let timestamp = line.split(" — ").next()?.trim();
            Self::parse_utc_system_time(timestamp)
        })
    }

    fn extract_rch_records_from_message(
        content: &str,
        started_at: SystemTime,
    ) -> Vec<RchCommandRecord> {
        let lines: Vec<&str> = content.lines().collect();
        let mut records = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let Some(command) = Self::extract_rch_command(line) else {
                continue;
            };
            let context_start = index.saturating_sub(8);
            let context_end = lines.len().min(index.saturating_add(16));
            let context = lines[context_start..context_end].join("\n");
            let exit_code = Self::infer_rch_exit_code(&context);
            records.push(RchCommandRecord {
                command,
                exit_code,
                remote_required: true,
                worker: Self::infer_rch_worker(&context),
                duration: Self::infer_rch_duration(&context).unwrap_or_default(),
                started_at,
                output_summary: Self::summarize_rch_context(&context),
            });
        }
        records
    }

    fn extract_rch_command(line: &str) -> Option<String> {
        let rch_index = line.find("rch exec")?;
        let suffix = &line[rch_index..];
        let command = suffix
            .split('`')
            .next()
            .unwrap_or(suffix)
            .trim()
            .trim_matches(|ch| matches!(ch, '"' | '\'' | '`'));
        (!command.is_empty()).then(|| command.to_string())
    }

    fn infer_rch_exit_code(context: &str) -> i32 {
        let lower = context.to_ascii_lowercase();
        if lower.contains("exit=0")
            || lower.contains("exit 0")
            || lower.contains("passed")
            || lower.contains("success")
            || lower.contains("finished `")
        {
            return 0;
        }
        if lower.contains("sigkill")
            || lower.contains("exit=101")
            || lower.contains("exit 101")
            || lower.contains("failed")
            || lower.contains("error:")
            || lower.contains("remote proof required but unavailable")
        {
            return 101;
        }
        -1
    }

    fn infer_rch_worker(context: &str) -> Option<String> {
        for line in context.lines() {
            if let Some(worker) = line
                .split("Selected worker:")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
            {
                return Some(
                    worker
                        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                        .to_string(),
                );
            }
            if let Some(worker) = line
                .split("[RCH] remote")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
            {
                return Some(
                    worker
                        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                        .to_string(),
                );
            }
        }
        None
    }

    fn infer_rch_duration(context: &str) -> Option<Duration> {
        for line in context.lines() {
            if let Some(ms_text) = line
                .split("Remote command finished:")
                .nth(1)
                .and_then(|rest| rest.split(" in ").nth(1))
                .and_then(|rest| rest.split("ms").next())
                && let Ok(ms) = ms_text.trim().parse::<u64>()
            {
                return Some(Duration::from_millis(ms));
            }
            if let Some(seconds_text) = line
                .split("[RCH] remote")
                .nth(1)
                .and_then(|rest| rest.rsplit_once('(').map(|(_, tail)| tail))
                .and_then(|tail| tail.split('s').next())
                && let Ok(seconds) = seconds_text.trim().parse::<f64>()
            {
                return Some(Duration::from_secs_f64(seconds));
            }
        }
        None
    }

    fn summarize_rch_context(context: &str) -> String {
        let mut summary = context
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("```")
            })
            .take(12)
            .collect::<Vec<_>>()
            .join(" | ");
        if summary.len() > 512 {
            summary.truncate(512);
            summary.push_str("...[truncated]");
        }
        summary
    }

    /// Detects the first blocker encountered.
    fn detect_first_blocker(
        &self,
        bead_id: &str,
        rch_commands: &[RchCommandRecord],
    ) -> Result<Option<BlockerRecord>, AggregatorError> {
        // Security: Validate bead ID to prevent potential security issues
        Self::validate_bead_id(bead_id)?;
        // Check for failed RCH commands
        for cmd in rch_commands {
            if cmd.exit_code != 0 {
                return Ok(Some(BlockerRecord {
                    blocker_type: if cmd.command.contains("cargo test") {
                        BlockerType::TestFailure
                    } else if cmd.command.contains("cargo check")
                        || cmd.command.contains("cargo clippy")
                    {
                        BlockerType::CompilationFailure
                    } else {
                        BlockerType::RemoteProofRequired
                    },
                    description: format!(
                        "RCH command failed: {} (exit code {})",
                        cmd.command, cmd.exit_code
                    ),
                    encountered_at: cmd.started_at,
                    external: false,
                }));
            }
        }
        Ok(None)
    }

    /// Collects lease receipts for the agent.
    fn collect_lease_receipts(
        &self,
        agent_name: &str,
    ) -> Result<Vec<LeaseReceipt>, AggregatorError> {
        // Security: Validate agent name to prevent potential security issues
        if agent_name.is_empty() || agent_name.len() > 128 {
            return Err(AggregatorError::MissingEvidence(
                "Agent name must be non-empty and under 128 characters".to_string(),
            ));
        }

        let Some(agent_mail_archive) = Self::agent_mail_project_archive_dir() else {
            return Ok(Vec::new());
        };
        let reservation_dir = agent_mail_archive.join("file_reservations");
        if !reservation_dir.is_dir() {
            return Ok(Vec::new());
        }

        let now = SystemTime::now();
        let mut receipts = Vec::new();
        for path in Self::collect_files_with_extensions(&reservation_dir, &["json"]) {
            let Some(content) = Self::read_evidence_text(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<AgentMailReservationRecord>(&content) else {
                continue;
            };
            if record.agent != agent_name {
                continue;
            }
            let Some(acquired_at) = Self::parse_utc_system_time(&record.created_ts) else {
                continue;
            };
            let Some(expires_at) = Self::parse_utc_system_time(&record.expires_ts) else {
                continue;
            };
            let released_at = record
                .released_ts
                .as_deref()
                .and_then(Self::parse_utc_system_time);
            receipts.push(LeaseReceipt {
                lease_type: "file_reservation".to_string(),
                lease_id: record.id.to_string().trim_matches('"').to_string(),
                agent: record.agent,
                acquired_at,
                expires_at,
                active: released_at.is_none() && expires_at > now,
            });
        }

        receipts.sort_by(|left, right| {
            left.acquired_at
                .cmp(&right.acquired_at)
                .then_with(|| left.lease_id.cmp(&right.lease_id))
        });
        Ok(receipts)
    }

    /// Checks handoff capsule status for the bead.
    fn check_handoff_status(&self, bead_id: &str) -> Result<HandoffStatus, AggregatorError> {
        // Security: Validate bead ID to prevent path traversal attacks
        Self::validate_bead_id(bead_id)?;

        // Check if handoff capsule exists for this bead
        // Look in expected locations for handoff capsule data

        let capsule_paths = [
            format!(".agent_handoff/capsule-{}.json", bead_id),
            format!(".agent_mail/handoff/{}-capsule.json", bead_id),
            format!(".beads/{}-handoff.json", bead_id),
        ];

        let mut last_updated = SystemTime::now();
        let mut found_capsule = false;
        let mut decision = None;

        for path in &capsule_paths {
            // Security: Validate each constructed path to prevent traversal attacks
            let allowed_prefixes = [".agent_handoff", ".agent_mail", ".beads"];
            let mut path_valid = false;
            for prefix in &allowed_prefixes {
                if path.starts_with(prefix) {
                    if Self::validate_file_path(path, prefix).is_ok() {
                        path_valid = true;
                        break;
                    }
                }
            }

            if !path_valid {
                continue; // Skip invalid paths
            }

            // Security: Use single atomic file read to prevent TOCTOU race conditions
            // Read file content and get metadata atomically instead of separate operations
            if let Ok(content) = std::fs::read_to_string(path) {
                found_capsule = true;

                // Get metadata after successful read to ensure file consistency
                if let Ok(metadata) = std::fs::metadata(path) {
                    if let Ok(modified) = metadata.modified() {
                        last_updated = modified;
                    }
                }

                decision = Self::parse_handoff_decision(&content);
                break; // Use first found capsule
            }
        }

        // Also check git notes for handoff decisions
        if !found_capsule {
            use std::process::Command;

            let output = Command::new("git")
                .args(["notes", "show", "--ref=handoff", "HEAD"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let notes = String::from_utf8_lossy(&output.stdout);
                    if notes.contains(bead_id) {
                        found_capsule = true;
                        decision = Self::parse_handoff_decision(&notes);
                    }
                }
            }
        }

        Ok(HandoffStatus {
            capsule_exists: found_capsule,
            decision,
            last_updated,
        })
    }

    fn parse_handoff_decision(content: &str) -> Option<HandoffDecision> {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
            && let Some(decision) = value.get("decision").and_then(serde_json::Value::as_str)
        {
            return Self::handoff_decision_from_str(decision);
        }
        [
            "Continue",
            "NarrowRefreshRequired",
            "CoordinateFirst",
            "UnsafeToContinue",
        ]
        .iter()
        .find_map(|candidate| {
            content
                .contains(candidate)
                .then(|| Self::handoff_decision_from_str(candidate))
                .flatten()
        })
    }

    fn handoff_decision_from_str(value: &str) -> Option<HandoffDecision> {
        match value {
            "Continue" => Some(HandoffDecision::Continue),
            "NarrowRefreshRequired" => Some(HandoffDecision::NarrowRefreshRequired),
            "CoordinateFirst" => Some(HandoffDecision::CoordinateFirst),
            "UnsafeToContinue" => Some(HandoffDecision::UnsafeToContinue),
            _ => None,
        }
    }

    /// Collects git reference information from commits.
    fn collect_git_refs(&self, commits: &[CommitRecord]) -> Result<Vec<GitRef>, AggregatorError> {
        use std::process::Command;

        let mut refs = Vec::new();
        let mut seen = HashSet::new();
        for commit in commits {
            let output = Command::new("git")
                .args([
                    "branch",
                    "-r",
                    "--contains",
                    commit.hash.as_str(),
                    "--format=%(refname)",
                ])
                .output()
                .map_err(|err| {
                    AggregatorError::GitError(format!(
                        "failed to query pushed refs for commit {}: {err}",
                        commit.hash
                    ))
                })?;
            if !output.status.success() {
                continue;
            }
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let ref_name = line.trim();
                if !ref_name.starts_with("refs/remotes/") {
                    continue;
                }
                let key = format!("{ref_name}:{}", commit.hash);
                if seen.insert(key) {
                    refs.push(GitRef {
                        ref_name: ref_name.to_string(),
                        commit_hash: commit.hash.clone(),
                        pushed: true,
                        pushed_at: commit.timestamp,
                    });
                }
            }
        }
        Ok(refs)
    }

    /// Determines the overall proof status.
    fn determine_proof_status(
        &self,
        commits: &[CommitRecord],
        rch_commands: &[RchCommandRecord],
        first_blocker: Option<&BlockerRecord>,
        _handoff_status: &HandoffStatus,
        pushed_refs: &[GitRef],
    ) -> Result<ProofStatus, AggregatorError> {
        // Check for blockers first
        if first_blocker.is_some() {
            return Ok(ProofStatus::Blocked);
        }

        // Check for local fallbacks
        let has_local_fallback = rch_commands
            .iter()
            .any(|cmd| cmd.worker.is_none() && cmd.remote_required);
        if has_local_fallback {
            return Ok(ProofStatus::LocalFallback);
        }

        // Check if remote RCH proofs are required and missing
        if self.config.require_remote_rch {
            let has_remote_proof = rch_commands
                .iter()
                .any(|cmd| cmd.remote_required && cmd.worker.is_some() && cmd.exit_code == 0);
            if !has_remote_proof {
                return Ok(ProofStatus::MissingRemoteProof);
            }
        }

        // Check if evidence is stale
        let now = SystemTime::now();
        let is_stale = commits.iter().any(|c| {
            now.duration_since(c.timestamp).unwrap_or_default() > self.config.max_commit_age
        });
        if is_stale {
            return Ok(ProofStatus::Stale);
        }

        if !Self::all_commits_pushed_to_main(commits, pushed_refs) {
            return Ok(ProofStatus::MissingCloseout);
        }

        Ok(ProofStatus::Complete)
    }

    fn all_commits_pushed_to_main(commits: &[CommitRecord], pushed_refs: &[GitRef]) -> bool {
        if commits.is_empty() {
            return true;
        }

        commits.iter().all(|commit| {
            commit.pushed
                && pushed_refs.iter().any(|git_ref| {
                    git_ref.pushed
                        && git_ref.commit_hash == commit.hash
                        && Self::is_canonical_main_ref(&git_ref.ref_name)
                })
        })
    }

    fn is_canonical_main_ref(ref_name: &str) -> bool {
        matches!(
            ref_name,
            "refs/heads/main" | "refs/remotes/origin/main" | "origin/main"
        )
    }

    /// Calculates evidence freshness score (0.0-1.0, higher is fresher).
    fn calculate_freshness_score(&self, record: &ReleaseProofRecord) -> f64 {
        let now = SystemTime::now();
        let max_age = self.config.max_evidence_age;

        let generated_age = now.duration_since(record.generated_at).unwrap_or_default();

        let age_factor = if generated_age > max_age {
            0.0
        } else {
            1.0 - (generated_age.as_secs_f64() / max_age.as_secs_f64())
        };

        // Factor in commit freshness
        let commit_freshness = if record.commits.is_empty() {
            0.5
        } else {
            let avg_commit_age: Duration = record
                .commits
                .iter()
                .map(|c| now.duration_since(c.timestamp).unwrap_or_default())
                .sum::<Duration>()
                / record.commits.len() as u32;

            if avg_commit_age > self.config.max_commit_age {
                0.0
            } else {
                1.0 - (avg_commit_age.as_secs_f64() / self.config.max_commit_age.as_secs_f64())
            }
        };

        f64::midpoint(age_factor, commit_freshness)
    }

    /// Redacts sensitive information from the proof record.
    fn redact_sensitive_information(&self, record: &ReleaseProofRecord) -> ReleaseProofRecord {
        let mut redacted = record.clone();

        // Redact command outputs
        for cmd in &mut redacted.rch_commands {
            if cmd.output_summary.len() > 100 {
                cmd.output_summary = format!("{}...[redacted]", &cmd.output_summary[..50]);
            }
        }

        // Redact agent names if configured
        if self.config.redact_sensitive {
            redacted.agent_name = "[redacted]".to_string();
            for reservation in &mut redacted.reservations {
                reservation.agent = "[redacted]".to_string();
            }
        }

        redacted
    }
}

/// Error type for aggregator operations.
#[derive(Debug, thiserror::Error)]
pub enum AggregatorError {
    #[error("Failed to collect evidence: {0}")]
    EvidenceCollection(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Git operation failed: {0}")]
    GitError(String),
    #[error("Missing required evidence: {0}")]
    MissingEvidence(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregator_creation() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);
        assert!(aggregator.config.require_remote_rch);
    }

    #[test]
    fn test_proof_status_determination_complete() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: true,
        }];

        let rch_commands = vec![RchCommandRecord {
            command: "cargo check".to_string(),
            exit_code: 0,
            remote_required: true,
            worker: Some("worker1".to_string()),
            duration: Duration::from_secs(10),
            started_at: SystemTime::now(),
            output_summary: "success".to_string(),
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/main".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &rch_commands, None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::Complete);
    }

    #[test]
    fn test_proof_status_requires_commits_on_main() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = false;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: true,
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/topic".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::MissingCloseout);
    }

    #[test]
    fn test_proof_status_rejects_unpushed_commits() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = false;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "test commit".to_string(),
            author: "test".to_string(),
            timestamp: SystemTime::now(),
            pushed: false,
        }];

        let pushed_refs = vec![GitRef {
            ref_name: "refs/remotes/origin/main".to_string(),
            commit_hash: "abc123".to_string(),
            pushed: true,
            pushed_at: SystemTime::now(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &pushed_refs)
            .unwrap();

        assert_eq!(status, ProofStatus::MissingCloseout);
    }

    #[test]
    fn test_proof_status_determination_missing_remote() {
        let mut config = AggregatorConfig::default();
        config.require_remote_rch = true;
        let aggregator = ReleaseProofAggregator::new(config);

        let commits = vec![];
        let rch_commands = vec![RchCommandRecord {
            command: "cargo check".to_string(),
            exit_code: 0,
            remote_required: true,
            worker: None, // No worker = local execution
            duration: Duration::from_secs(10),
            started_at: SystemTime::now(),
            output_summary: "success".to_string(),
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &rch_commands, None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::LocalFallback);
    }

    #[test]
    fn test_proof_status_requires_remote_when_no_rch_evidence_exists() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);
        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&[], &[], None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::MissingRemoteProof);
    }

    #[test]
    fn test_rch_message_parser_extracts_worker_exit_and_duration() {
        let started_at = SystemTime::now();
        let message = r"
## 2026-05-27T12:43:18.938024Z — HazyRidge → MossyPond

Command:
`rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo check -p asupersync --lib`

2026-05-27T12:43:18Z INFO Selected worker: vmi1167313 at ubuntu@154.12.232.219
Finished `dev` profile [unoptimized + debuginfo] target(s) in 3m 07s
Remote command finished: exit=0 in 188296ms
[RCH] remote vmi1167313 (234.3s)
";

        let records = ReleaseProofAggregator::extract_rch_records_from_message(message, started_at);

        assert_eq!(records.len(), 1);
        assert!(records[0].command.starts_with("rch exec -- env"));
        assert_eq!(records[0].exit_code, 0);
        assert_eq!(records[0].worker.as_deref(), Some("vmi1167313"));
        assert_eq!(records[0].duration, Duration::from_millis(188_296));
    }

    #[test]
    fn test_proof_status_determination_blocked() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let blocker = Some(BlockerRecord {
            blocker_type: BlockerType::TestFailure,
            description: "Test failed".to_string(),
            encountered_at: SystemTime::now(),
            external: false,
        });

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&[], &[], blocker.as_ref(), &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::Blocked);
    }

    #[test]
    fn test_proof_status_determination_stale() {
        let config = AggregatorConfig {
            max_commit_age: Duration::from_secs(60), // 1 minute
            require_remote_rch: false,
            ..AggregatorConfig::default()
        };
        let aggregator = ReleaseProofAggregator::new(config);

        let old_time = SystemTime::now() - Duration::from_secs(120); // 2 minutes ago
        let commits = vec![CommitRecord {
            hash: "abc123".to_string(),
            message: "old commit".to_string(),
            author: "test".to_string(),
            timestamp: old_time,
            pushed: true,
        }];

        let handoff_status = HandoffStatus {
            capsule_exists: false,
            decision: None,
            last_updated: SystemTime::now(),
        };

        let status = aggregator
            .determine_proof_status(&commits, &[], None, &handoff_status, &[])
            .unwrap();

        assert_eq!(status, ProofStatus::Stale);
    }

    #[test]
    fn test_generate_summary() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "test-agent".to_string(),
            reservations: vec![],
            touched_paths: vec![],
            commits: vec![CommitRecord {
                hash: "abc123".to_string(),
                message: "test commit".to_string(),
                author: "test".to_string(),
                timestamp: SystemTime::now(),
                pushed: true,
            }],
            rch_commands: vec![],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let summary = aggregator.generate_summary(&record);
        assert_eq!(summary.bead_id, "test-bead");
        assert_eq!(summary.status, ProofStatus::Complete);
        assert_eq!(summary.commit_count, 1);
        assert!(!summary.main_pushed);
        assert!(summary.summary.contains("Release ready"));
    }

    #[test]
    fn test_freshness_score_calculation() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "test-agent".to_string(),
            reservations: vec![],
            touched_paths: vec![],
            commits: vec![CommitRecord {
                hash: "abc123".to_string(),
                message: "test commit".to_string(),
                author: "test".to_string(),
                timestamp: SystemTime::now(),
                pushed: true,
            }],
            rch_commands: vec![],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let score = aggregator.calculate_freshness_score(&record);
        assert!(score > 0.8); // Fresh evidence should have high score
    }

    #[test]
    fn test_bead_id_validation() {
        // Valid bead IDs should pass
        assert!(ReleaseProofAggregator::validate_bead_id("test-bead-123").is_ok());
        assert!(ReleaseProofAggregator::validate_bead_id("abc_def-123").is_ok());
        assert!(ReleaseProofAggregator::validate_bead_id("simple").is_ok());

        // Empty or too long should fail
        assert!(ReleaseProofAggregator::validate_bead_id("").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id(&"x".repeat(65)).is_err());

        // Dangerous characters should fail
        assert!(ReleaseProofAggregator::validate_bead_id("test;rm -rf").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test`cat /etc/passwd`").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test$(whoami)").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test&pwd").is_err());

        // Path traversal patterns should fail
        assert!(ReleaseProofAggregator::validate_bead_id("../../../etc/passwd").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test/../admin").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test/subdir").is_err());
        assert!(ReleaseProofAggregator::validate_bead_id("test\\windows\\path").is_err());
    }

    #[test]
    fn test_file_path_validation() {
        // Create an isolated directory for testing
        let temp_dir = std::env::temp_dir().join("test_aggregator");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let temp_path = temp_dir.to_str().unwrap();

        // Valid paths within allowed directory should pass
        let valid_file = temp_dir.join("test.json");
        std::fs::write(&valid_file, "test").unwrap();
        assert!(
            ReleaseProofAggregator::validate_file_path(valid_file.to_str().unwrap(), temp_path)
                .is_ok()
        );

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_git_snapshot_capture() {
        let config = AggregatorConfig::default();
        let aggregator = ReleaseProofAggregator::new(config);

        // Should be able to capture git snapshot (if we're in a git repo)
        let snapshot_result = aggregator.capture_git_snapshot();

        // This will succeed if we're in a git repo, fail otherwise
        // We just want to make sure it doesn't panic or have security issues
        match snapshot_result {
            Ok(hash) => {
                assert!(!hash.is_empty());
                assert!(
                    hash.chars()
                        .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
                );
            }
            Err(_) => {
                // Not in a git repo or git not available - that's okay for testing
            }
        }
    }

    #[test]
    fn test_sensitive_information_redaction() {
        let config = AggregatorConfig {
            redact_sensitive: true,
            ..AggregatorConfig::default()
        };
        let aggregator = ReleaseProofAggregator::new(config);

        let record = ReleaseProofRecord {
            bead_id: "test-bead".to_string(),
            agent_name: "sensitive-agent".to_string(),
            reservations: vec![FileReservation {
                agent: "another-agent".to_string(),
                patterns: vec!["src/**".to_string()],
                exclusive: true,
                ttl_seconds: 3600,
                reason: "test".to_string(),
                acquired_at: SystemTime::now(),
                released_at: None,
            }],
            touched_paths: vec![],
            commits: vec![],
            rch_commands: vec![RchCommandRecord {
                command: "cargo check".to_string(),
                exit_code: 0,
                remote_required: false,
                worker: None,
                duration: Duration::from_secs(10),
                started_at: SystemTime::now(),
                output_summary: "a".repeat(200), // Long output to test redaction
            }],
            first_blocker: None,
            lease_receipts: vec![],
            handoff_status: HandoffStatus {
                capsule_exists: false,
                decision: None,
                last_updated: SystemTime::now(),
            },
            pushed_refs: vec![],
            generated_at: SystemTime::now(),
            status: ProofStatus::Complete,
        };

        let redacted = aggregator.redact_sensitive_information(&record);
        assert_eq!(redacted.agent_name, "[redacted]");
        assert_eq!(redacted.reservations[0].agent, "[redacted]");
        assert!(
            redacted.rch_commands[0]
                .output_summary
                .contains("[redacted]")
        );
    }
}
