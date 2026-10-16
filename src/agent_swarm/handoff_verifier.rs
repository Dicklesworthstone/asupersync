//! Agent handoff capsule verifier for compaction-safe session resumption.
//!
//! Implements ASW-10: verification logic to determine whether a compacted or resumed
//! agent session has enough evidence to continue safely without restarting from
//! stale inputs.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

/// Agent handoff capsule containing session state for safe resumption verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffCapsule {
    /// Session metadata
    pub session_meta: SessionMetadata,
    /// Git repository state
    pub git_state: GitState,
    /// Agent inbox and acknowledgment state
    pub inbox_state: InboxState,
    /// Active file reservations
    pub active_reservations: Vec<FileReservation>,
    /// Claimed beads and their status
    pub claimed_beads: Vec<BeadClaim>,
    /// Dirty path ownership summary
    pub dirty_paths: DirtyPathSummary,
    /// Exact proof commands in flight
    pub proof_commands: Vec<ProofCommand>,
    /// First blocker or dependency issue
    pub first_blocker: Option<BlockerInfo>,
    /// Recently pushed commits not yet fully processed
    pub pushed_commits: Vec<CommitInfo>,
    /// Assessed remaining risks for continuation
    pub remaining_risks: Vec<RiskAssessment>,
    /// Timestamp when capsule was created
    pub created_at: SystemTime,
    /// Hash of the capsule content for integrity
    pub content_hash: String,
}

/// Session metadata for the agent handoff.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct SessionMetadata {
    /// Agent identifier (may be redacted)
    pub agent_id: String,
    /// Session duration at handoff
    pub session_duration: Duration,
    /// Last active timestamp
    pub last_active: SystemTime,
    /// Session type (interactive, automated, etc.)
    pub session_type: SessionType,
    /// Documentation read receipts
    pub docs_receipts: Vec<DocReceipt>,
}

/// Type of agent session.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum SessionType {
    /// Interactive session with human oversight
    Interactive,
    /// Automated session following predefined workflow
    Automated,
    /// Background maintenance or monitoring session
    Background,
    /// Emergency response or recovery session
    Emergency,
}

/// Documentation read receipt.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct DocReceipt {
    /// Document path or identifier
    pub doc_path: String,
    /// Content hash when read
    pub content_hash: String,
    /// Timestamp when read
    pub read_at: SystemTime,
}

/// Git repository state at handoff time.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct GitState {
    /// Current branch (should be main per RULE 2)
    pub current_branch: String,
    /// Current main/HEAD commit hash
    pub main_hash: String,
    /// Working tree status
    pub working_tree_clean: bool,
    /// Staged changes summary
    pub staged_changes: Vec<String>,
    /// Untracked files
    pub untracked_files: Vec<String>,
    /// Last sync with remote
    pub last_remote_sync: Option<SystemTime>,
}

/// Agent inbox and acknowledgment state.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct InboxState {
    /// Unread message count
    pub unread_count: u32,
    /// Pending acknowledgments
    pub pending_acks: Vec<String>,
    /// Last inbox check
    pub last_check: SystemTime,
    /// Critical unacknowledged messages
    pub critical_unacked: Vec<MessageRef>,
}

/// Reference to a message requiring acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct MessageRef {
    /// Message ID
    pub message_id: String,
    /// Sender agent
    pub sender: String,
    /// Message priority
    pub priority: MessagePriority,
    /// Received timestamp
    pub received_at: SystemTime,
}

/// Message priority levels.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum MessagePriority {
    /// Low priority, non-urgent messages
    Low,
    /// Normal priority, standard workflow messages
    Normal,
    /// High priority, requires prompt attention
    High,
    /// Critical priority, immediate action required
    Critical,
}

/// Active file reservation.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct FileReservation {
    /// Reservation ID
    pub id: String,
    /// File paths or patterns
    pub paths: Vec<String>,
    /// Whether reservation is exclusive
    pub exclusive: bool,
    /// Expiration time
    pub expires_at: SystemTime,
    /// Reason for reservation
    pub reason: String,
}

/// Claimed bead information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeadClaim {
    /// Bead ID
    pub bead_id: String,
    /// Bead title
    pub title: String,
    /// Current status
    pub status: BeadStatus,
    /// Time when claimed
    pub claimed_at: SystemTime,
    /// Progress estimate (0.0-1.0)
    pub progress: f64,
}

/// Bead status.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum BeadStatus {
    /// Bead is available for work
    Open,
    /// Bead is actively being worked on
    InProgress,
    /// Bead is blocked by dependencies or issues
    Blocked,
    /// Bead is completed
    Closed,
}

/// Summary of dirty path ownership.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct DirtyPathSummary {
    /// Files owned by this agent
    pub owned_files: BTreeSet<String>,
    /// Files modified by peer agents
    pub peer_modified: BTreeMap<String, String>, // file -> agent
    /// Potential conflicts
    pub potential_conflicts: Vec<ConflictInfo>,
}

/// Information about potential file conflicts.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct ConflictInfo {
    /// Conflicting file path
    pub file_path: String,
    /// Competing agents
    pub competing_agents: Vec<String>,
    /// Conflict severity
    pub severity: ConflictSeverity,
}

/// Conflict severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum ConflictSeverity {
    /// Minor conflict, can likely be resolved automatically
    Low,
    /// Moderate conflict, requires careful review
    Medium,
    /// Serious conflict, may require coordination between agents
    High,
    /// Critical conflict, requires immediate attention
    Critical,
}

/// Proof command in flight.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct ProofCommand {
    /// Command ID
    pub command_id: String,
    /// Full command line
    pub command_line: String,
    /// Started timestamp
    pub started_at: SystemTime,
    /// Expected completion time
    pub expected_completion: Option<SystemTime>,
    /// Command type
    pub command_type: ProofCommandType,
}

/// Type of proof command.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum ProofCommandType {
    /// Compilation check (cargo check/build)
    Compile,
    /// Test execution (cargo test)
    Test,
    /// Linting analysis (cargo clippy)
    Lint,
    /// Code formatting (cargo fmt)
    Format,
    /// Performance benchmarking (cargo bench)
    Benchmark,
    /// Other custom command type
    Other(String),
}

/// Information about a blocking issue.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct BlockerInfo {
    /// Blocker type
    pub blocker_type: BlockerType,
    /// Description of the issue
    pub description: String,
    /// Potential resolution time
    pub estimated_resolution: Option<Duration>,
    /// Dependencies or conditions needed
    pub dependencies: Vec<String>,
}

/// Types of blocking issues.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum BlockerType {
    /// Git merge conflict or repository state issue
    GitConflict,
    /// File reservation conflict with another agent
    FileReservation,
    /// Waiting for dependency bead completion
    BeadDependency,
    /// Proof command (test/lint/build) failure
    ProofFailure,
    /// Network connectivity or resource access issue
    NetworkIssue,
    /// Resource contention (CPU, memory, disk)
    ResourceContention,
    /// Other unclassified blocking issue
    Other(String),
}

/// Information about a pushed commit.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct CommitInfo {
    /// Commit hash
    pub commit_hash: String,
    /// Commit message summary
    pub message_summary: String,
    /// Files changed
    pub files_changed: Vec<String>,
    /// Push timestamp
    pub pushed_at: SystemTime,
    /// Whether beads have been updated
    pub beads_synced: bool,
}

/// Risk assessment for continuation.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct RiskAssessment {
    /// Risk category
    pub category: RiskCategory,
    /// Risk level
    pub level: RiskLevel,
    /// Description of the risk
    pub description: String,
    /// Mitigation suggestions
    pub mitigations: Vec<String>,
}

/// Categories of continuation risks.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum RiskCategory {
    /// Documentation may be outdated or stale
    StaleDocumentation,
    /// Unread or unacknowledged messages exist
    UnacknowledgedMessages,
    /// Potential file conflicts with other agents
    FileConflicts,
    /// Dependencies or external state has changed
    DependencyChanges,
    /// Proof commands have failed or are invalid
    ProofCommandFailure,
    /// Resources or reservations may expire
    ResourceExpiration,
    /// Other unclassified risk category
    Other(String),
}

/// Risk severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum RiskLevel {
    /// Low risk, can proceed with minor precautions
    Low,
    /// Medium risk, requires careful monitoring
    Medium,
    /// High risk, requires significant mitigation
    High,
    /// Critical risk, strongly consider restart
    Critical,
}

/// Verifier decision for handoff continuation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandoffDecision {
    /// Safe to continue with current state
    Continue,
    /// Can continue but needs targeted refresh
    NarrowRefreshRequired {
        /// Specific areas needing refresh
        refresh_targets: Vec<RefreshTarget>,
    },
    /// Must coordinate with other agents first
    CoordinateFirst {
        /// Coordination requirements
        coordination_needed: Vec<CoordinationRequirement>,
    },
    /// Unsafe to continue, must restart
    UnsafeToContinue {
        /// Specific reasons why unsafe
        reasons: Vec<SafetyViolation>,
    },
}

/// Specific area requiring refresh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefreshTarget {
    /// Re-read AGENTS.md and other key documentation
    Documentation,
    /// Check agent mail inbox for new messages
    InboxMessages,
    /// Verify current file reservations status
    FileReservations,
    /// Update knowledge of bead status changes
    BeadStatus,
    /// Refresh git repository state and branches
    GitState,
    /// Check status of running proof commands
    ProofCommands,
}

/// Coordination requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationRequirement {
    /// Type of coordination needed
    pub requirement_type: CoordinationType,
    /// Target agents to coordinate with
    pub target_agents: Vec<String>,
    /// Expected coordination time
    pub estimated_time: Duration,
}

/// Types of coordination needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinationType {
    /// Transfer file reservation to another agent
    FileReservationHandoff,
    /// Transfer bead ownership to another agent
    BeadTransfer,
    /// Resolve merge or editing conflicts
    ConflictResolution,
    /// Synchronize proof command status with other agents
    ProofCommandSync,
}

/// Safety violation preventing continuation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyViolation {
    /// Violation category
    pub category: ViolationCategory,
    /// Detailed reason
    pub reason: String,
    /// Evidence or context
    pub evidence: String,
}

/// Categories of safety violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationCategory {
    /// Git repository state is too stale to continue safely
    StaleGitState,
    /// File reservations have expired
    ExpiredReservations,
    /// Merge conflicts remain unresolved
    UnresolvedConflicts,
    /// Critical messages require immediate attention
    CriticalUnacknowledgedMessages,
    /// Essential proof commands have failed
    FailedProofCommands,
    /// Capsule integrity verification failed
    IntegrityCheckFailure,
}

/// Handoff capsule verifier.
#[derive(Debug)]
pub struct HandoffVerifier {
    /// Maximum acceptable staleness for various components
    staleness_thresholds: StalenessThresholds,
}

/// Configurable staleness thresholds.
#[derive(Debug, Clone)]
pub struct StalenessThresholds {
    /// Maximum age for documentation reads
    pub docs_max_age: Duration,
    /// Maximum age for inbox checks
    pub inbox_max_age: Duration,
    /// Maximum time for proof commands
    pub proof_command_timeout: Duration,
    /// Maximum time since git sync
    pub git_sync_max_age: Duration,
}

impl Default for StalenessThresholds {
    fn default() -> Self {
        Self {
            docs_max_age: Duration::from_secs(3600),          // 1 hour
            inbox_max_age: Duration::from_secs(300),          // 5 minutes
            proof_command_timeout: Duration::from_secs(1800), // 30 minutes
            git_sync_max_age: Duration::from_secs(600),       // 10 minutes
        }
    }
}

impl HandoffVerifier {
    /// Creates a new verifier with default thresholds.
    pub fn new() -> Self {
        Self {
            staleness_thresholds: StalenessThresholds::default(),
        }
    }

    /// Creates a verifier with custom thresholds.
    pub fn with_thresholds(thresholds: StalenessThresholds) -> Self {
        Self {
            staleness_thresholds: thresholds,
        }
    }

    /// Verifies a handoff capsule and returns a decision.
    pub fn verify_handoff(&self, capsule: &HandoffCapsule) -> HandoffDecision {
        let mut violations = Vec::new();
        let mut refresh_targets = BTreeSet::new();
        let mut coordination_requirements = Vec::new();

        // Check capsule integrity
        if let Some(violation) = self.check_integrity(capsule) {
            violations.push(violation);
        }

        // Check git state
        if let Some(violation) = self.check_git_state(&capsule.git_state) {
            violations.push(violation);
        } else if self.is_git_state_stale(&capsule.git_state) {
            refresh_targets.insert(RefreshTarget::GitState);
        }

        // Check documentation freshness
        if self.are_docs_stale(&capsule.session_meta.docs_receipts) {
            if self.is_critically_stale(&capsule.session_meta.docs_receipts) {
                violations.push(SafetyViolation {
                    category: ViolationCategory::StaleGitState,
                    reason: "Documentation critically out of date".to_string(),
                    evidence: "Docs not read in over 24 hours".to_string(),
                });
            } else {
                refresh_targets.insert(RefreshTarget::Documentation);
            }
        }

        // Check inbox state
        if self.is_inbox_critical(&capsule.inbox_state) {
            violations.push(SafetyViolation {
                category: ViolationCategory::CriticalUnacknowledgedMessages,
                reason: "Critical messages require immediate attention".to_string(),
                evidence: format!(
                    "{} critical unacknowledged messages",
                    capsule.inbox_state.critical_unacked.len()
                ),
            });
        } else if self.is_inbox_stale(&capsule.inbox_state) {
            refresh_targets.insert(RefreshTarget::InboxMessages);
        }

        // Check file reservations
        if let Some(coord_req) = self.check_file_reservations(&capsule.active_reservations) {
            coordination_requirements.push(coord_req);
        }

        // Check bead claims
        if let Some(coord_req) = self.check_bead_claims(capsule) {
            coordination_requirements.push(coord_req);
        }

        // Check proof commands
        if let Some(violation) = self.check_proof_commands(&capsule.proof_commands) {
            violations.push(violation);
        } else if self.are_proof_commands_stale(&capsule.proof_commands) {
            refresh_targets.insert(RefreshTarget::ProofCommands);
        }

        // Check for file conflicts
        if let Some(coord_req) = self.check_file_conflicts(&capsule.dirty_paths) {
            coordination_requirements.push(coord_req);
        }

        // Make decision based on findings
        if !violations.is_empty() {
            HandoffDecision::UnsafeToContinue {
                reasons: violations,
            }
        } else if !coordination_requirements.is_empty() {
            HandoffDecision::CoordinateFirst {
                coordination_needed: coordination_requirements,
            }
        } else if !refresh_targets.is_empty() {
            HandoffDecision::NarrowRefreshRequired {
                refresh_targets: refresh_targets.into_iter().collect(),
            }
        } else {
            HandoffDecision::Continue
        }
    }

    fn check_integrity(&self, capsule: &HandoffCapsule) -> Option<SafetyViolation> {
        // Check if content hash is present
        if capsule.content_hash.is_empty() {
            return Some(SafetyViolation {
                category: ViolationCategory::IntegrityCheckFailure,
                reason: "Missing content hash".to_string(),
                evidence: "Capsule integrity cannot be verified".to_string(),
            });
        }

        // Compute actual content hash and verify against stored hash
        let computed_hash = self.compute_content_hash(capsule);
        if computed_hash != capsule.content_hash {
            Some(SafetyViolation {
                category: ViolationCategory::IntegrityCheckFailure,
                reason: "Content hash mismatch".to_string(),
                evidence: format!(
                    "Expected: {}, Computed: {}",
                    capsule.content_hash, computed_hash
                ),
            })
        } else {
            None
        }
    }

    /// Computes SHA-256 hash of capsule content for integrity verification.
    fn compute_content_hash(&self, capsule: &HandoffCapsule) -> String {
        use sha2::{Digest, Sha256};

        // Create a capsule copy without the content_hash field for hashing
        let mut capsule_for_hash = capsule.clone();
        capsule_for_hash.content_hash = String::new(); // Exclude hash field itself

        if let Ok(json_bytes) = serde_json::to_vec(&capsule_for_hash) {
            let mut hasher = Sha256::new();
            hasher.update(b"asupersync.agent_swarm.handoff_capsule.v1\0");
            hasher.update(json_bytes);
            hex::encode(hasher.finalize())
        } else {
            "serialization-failed".to_string()
        }
    }

    fn check_git_state(&self, git_state: &GitState) -> Option<SafetyViolation> {
        // Enforce RULE 2: main-only
        if git_state.current_branch != "main" {
            return Some(SafetyViolation {
                category: ViolationCategory::StaleGitState,
                reason: "Not on main branch".to_string(),
                evidence: format!("Current branch: {}", git_state.current_branch),
            });
        }

        // Check for uncommitted changes that could cause conflicts
        if !git_state.working_tree_clean && !git_state.staged_changes.is_empty() {
            return Some(SafetyViolation {
                category: ViolationCategory::UnresolvedConflicts,
                reason: "Uncommitted staged changes".to_string(),
                evidence: format!("{} staged files", git_state.staged_changes.len()),
            });
        }

        None
    }

    fn is_git_state_stale(&self, git_state: &GitState) -> bool {
        if let Some(last_sync) = git_state.last_remote_sync {
            SystemTime::now()
                .duration_since(last_sync)
                .unwrap_or(Duration::MAX)
                > self.staleness_thresholds.git_sync_max_age
        } else {
            true // No sync info is considered stale
        }
    }

    fn are_docs_stale(&self, docs_receipts: &[DocReceipt]) -> bool {
        if docs_receipts.is_empty() {
            return true;
        }

        docs_receipts.iter().any(|receipt| {
            SystemTime::now()
                .duration_since(receipt.read_at)
                .unwrap_or(Duration::MAX)
                > self.staleness_thresholds.docs_max_age
        })
    }

    fn is_critically_stale(&self, docs_receipts: &[DocReceipt]) -> bool {
        docs_receipts.iter().any(|receipt| {
            SystemTime::now()
                .duration_since(receipt.read_at)
                .unwrap_or(Duration::MAX)
                > Duration::from_secs(24 * 3600) // 24 hours
        })
    }

    fn is_inbox_critical(&self, inbox_state: &InboxState) -> bool {
        !inbox_state.critical_unacked.is_empty()
    }

    fn is_inbox_stale(&self, inbox_state: &InboxState) -> bool {
        SystemTime::now()
            .duration_since(inbox_state.last_check)
            .unwrap_or(Duration::MAX)
            > self.staleness_thresholds.inbox_max_age
    }

    fn check_file_reservations(
        &self,
        reservations: &[FileReservation],
    ) -> Option<CoordinationRequirement> {
        let now = SystemTime::now();
        let expired_count = reservations.iter().filter(|r| r.expires_at < now).count();

        if expired_count > 0 {
            let mut targets: Vec<String> = reservations
                .iter()
                .filter(|reservation| reservation.expires_at < now)
                .map(|reservation| format!("reservation:{}", reservation.id))
                .collect();
            targets.sort();
            targets.dedup();

            Some(CoordinationRequirement {
                requirement_type: CoordinationType::FileReservationHandoff,
                target_agents: targets,
                estimated_time: Duration::from_secs(300), // 5 minutes
            })
        } else {
            None
        }
    }

    fn check_bead_claims(&self, capsule: &HandoffCapsule) -> Option<CoordinationRequirement> {
        let now = SystemTime::now();
        let mut needs_coordination = Vec::new();

        for claim in &capsule.claimed_beads {
            let bead_id = claim.bead_id.trim();
            if bead_id.is_empty() {
                needs_coordination.push("bead:<blank>".to_string());
                continue;
            }
            if !claim.progress.is_finite() || !(0.0..=1.0).contains(&claim.progress) {
                needs_coordination.push(format!("bead:{bead_id}:invalid-progress"));
                continue;
            }

            match claim.status {
                BeadStatus::Open => {
                    needs_coordination.push(format!("bead:{bead_id}:not-claimed"));
                }
                BeadStatus::InProgress => {
                    let claim_age = now
                        .duration_since(claim.claimed_at)
                        .unwrap_or(Duration::MAX);
                    let has_recent_evidence = capsule
                        .proof_commands
                        .iter()
                        .any(|cmd| cmd.command_line.contains(bead_id))
                        || capsule
                            .pushed_commits
                            .iter()
                            .any(|commit| commit.message_summary.contains(bead_id));
                    if claim_age > self.staleness_thresholds.git_sync_max_age
                        && !has_recent_evidence
                    {
                        needs_coordination.push(format!("bead:{bead_id}:stale-claim"));
                    }
                }
                BeadStatus::Blocked => {
                    let blocker_matches = capsule.first_blocker.as_ref().is_some_and(|blocker| {
                        blocker
                            .dependencies
                            .iter()
                            .any(|dependency| dependency.contains(bead_id))
                            || blocker.description.contains(bead_id)
                    });
                    if !blocker_matches {
                        needs_coordination.push(format!("bead:{bead_id}:missing-blocker"));
                    }
                }
                BeadStatus::Closed => {
                    if claim.progress < 1.0 {
                        needs_coordination.push(format!("bead:{bead_id}:closed-without-progress"));
                    }
                }
            }
        }

        if needs_coordination.is_empty() {
            None
        } else {
            needs_coordination.sort();
            needs_coordination.dedup();
            Some(CoordinationRequirement {
                requirement_type: CoordinationType::BeadTransfer,
                target_agents: needs_coordination,
                estimated_time: Duration::from_secs(300),
            })
        }
    }

    fn check_proof_commands(&self, commands: &[ProofCommand]) -> Option<SafetyViolation> {
        let now = SystemTime::now();
        let timed_out = commands.iter().any(|cmd| {
            now.duration_since(cmd.started_at).unwrap_or(Duration::MAX)
                > self.staleness_thresholds.proof_command_timeout
        });

        if timed_out {
            Some(SafetyViolation {
                category: ViolationCategory::FailedProofCommands,
                reason: "Proof commands timed out".to_string(),
                evidence: "Commands running longer than threshold".to_string(),
            })
        } else {
            None
        }
    }

    fn are_proof_commands_stale(&self, commands: &[ProofCommand]) -> bool {
        !commands.is_empty() // Any in-flight commands need refresh
    }

    fn check_file_conflicts(
        &self,
        dirty_paths: &DirtyPathSummary,
    ) -> Option<CoordinationRequirement> {
        if !dirty_paths.potential_conflicts.is_empty() {
            Some(CoordinationRequirement {
                requirement_type: CoordinationType::ConflictResolution,
                target_agents: dirty_paths
                    .potential_conflicts
                    .iter()
                    .flat_map(|c| c.competing_agents.clone())
                    .collect(),
                estimated_time: Duration::from_secs(600), // 10 minutes
            })
        } else {
            None
        }
    }
}

impl Default for HandoffVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "handoff_verifier_inline_tests.rs"]
mod tests;
