//! Agent handoff capsule verifier for compaction-safe session resumption.
//!
//! Implements ASW-10: verification logic to determine whether a compacted or resumed
//! agent session has enough evidence to continue safely without restarting from
//! stale assumptions.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionType {
    Interactive,
    Automated,
    Background,
    Emergency,
}

/// Documentation read receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocReceipt {
    /// Document path or identifier
    pub doc_path: String,
    /// Content hash when read
    pub content_hash: String,
    /// Timestamp when read
    pub read_at: SystemTime,
}

/// Git repository state at handoff time.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Active file reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BeadStatus {
    Open,
    InProgress,
    Blocked,
    Closed,
}

/// Summary of dirty path ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirtyPathSummary {
    /// Files owned by this agent
    pub owned_files: BTreeSet<String>,
    /// Files modified by peer agents
    pub peer_modified: BTreeMap<String, String>, // file -> agent
    /// Potential conflicts
    pub potential_conflicts: Vec<ConflictInfo>,
}

/// Information about potential file conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictInfo {
    /// Conflicting file path
    pub file_path: String,
    /// Competing agents
    pub competing_agents: Vec<String>,
    /// Conflict severity
    pub severity: ConflictSeverity,
}

/// Conflict severity levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Proof command in flight.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofCommandType {
    Compile,
    Test,
    Lint,
    Format,
    Benchmark,
    Other(String),
}

/// Information about a blocking issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockerType {
    GitConflict,
    FileReservation,
    BeadDependency,
    ProofFailure,
    NetworkIssue,
    ResourceContention,
    Other(String),
}

/// Information about a pushed commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    StaleDocumentation,
    UnacknowledgedMessages,
    FileConflicts,
    DependencyChanges,
    ProofCommandFailure,
    ResourceExpiration,
    Other(String),
}

/// Risk severity levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
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
    Documentation,
    InboxMessages,
    FileReservations,
    BeadStatus,
    GitState,
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
    FileReservationHandoff,
    BeadTransfer,
    ConflictResolution,
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
    StaleGitState,
    ExpiredReservations,
    UnresolvedConflicts,
    CriticalUnacknowledgedMessages,
    FailedProofCommands,
    IntegrityCheckFailure,
}

/// Handoff capsule verifier.
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
            docs_max_age: Duration::from_secs(3600), // 1 hour
            inbox_max_age: Duration::from_secs(300),  // 5 minutes
            proof_command_timeout: Duration::from_secs(1800), // 30 minutes
            git_sync_max_age: Duration::from_secs(600), // 10 minutes
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
                evidence: format!("{} critical unacknowledged messages",
                                capsule.inbox_state.critical_unacked.len()),
            });
        } else if self.is_inbox_stale(&capsule.inbox_state) {
            refresh_targets.insert(RefreshTarget::InboxMessages);
        }

        // Check file reservations
        if let Some(coord_req) = self.check_file_reservations(&capsule.active_reservations) {
            coordination_requirements.push(coord_req);
        }

        // Check bead claims
        if let Some(coord_req) = self.check_bead_claims(&capsule.claimed_beads) {
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
        // Simple integrity check - in practice would verify content hash
        if capsule.content_hash.is_empty() {
            Some(SafetyViolation {
                category: ViolationCategory::IntegrityCheckFailure,
                reason: "Missing content hash".to_string(),
                evidence: "Capsule integrity cannot be verified".to_string(),
            })
        } else {
            None
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

    fn check_file_reservations(&self, reservations: &[FileReservation]) -> Option<CoordinationRequirement> {
        let now = SystemTime::now();
        let expired_count = reservations.iter()
            .filter(|r| r.expires_at < now)
            .count();

        if expired_count > 0 {
            Some(CoordinationRequirement {
                requirement_type: CoordinationType::FileReservationHandoff,
                target_agents: vec!["system".to_string()], // Placeholder
                estimated_time: Duration::from_secs(300), // 5 minutes
            })
        } else {
            None
        }
    }

    fn check_bead_claims(&self, _claims: &[BeadClaim]) -> Option<CoordinationRequirement> {
        // For now, assume bead claims are always valid
        // In practice, would check against current bead state
        None
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

    fn check_file_conflicts(&self, dirty_paths: &DirtyPathSummary) -> Option<CoordinationRequirement> {
        if !dirty_paths.potential_conflicts.is_empty() {
            Some(CoordinationRequirement {
                requirement_type: CoordinationType::ConflictResolution,
                target_agents: dirty_paths.potential_conflicts.iter()
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
mod tests {
    use super::*;

    fn create_test_capsule() -> HandoffCapsule {
        HandoffCapsule {
            session_meta: SessionMetadata {
                agent_id: "test-agent".to_string(),
                session_duration: Duration::from_secs(3600),
                last_active: SystemTime::now(),
                session_type: SessionType::Interactive,
                docs_receipts: vec![DocReceipt {
                    doc_path: "AGENTS.md".to_string(),
                    content_hash: "abc123".to_string(),
                    read_at: SystemTime::now(),
                }],
            },
            git_state: GitState {
                current_branch: "main".to_string(),
                main_hash: "deadbeef".to_string(),
                working_tree_clean: true,
                staged_changes: vec![],
                untracked_files: vec![],
                last_remote_sync: Some(SystemTime::now()),
            },
            inbox_state: InboxState {
                unread_count: 0,
                pending_acks: vec![],
                last_check: SystemTime::now(),
                critical_unacked: vec![],
            },
            active_reservations: vec![],
            claimed_beads: vec![],
            dirty_paths: DirtyPathSummary {
                owned_files: BTreeSet::new(),
                peer_modified: BTreeMap::new(),
                potential_conflicts: vec![],
            },
            proof_commands: vec![],
            first_blocker: None,
            pushed_commits: vec![],
            remaining_risks: vec![],
            created_at: SystemTime::now(),
            content_hash: "valid-hash".to_string(),
        }
    }

    #[test]
    fn test_fresh_handoff_continues() {
        let verifier = HandoffVerifier::new();
        let capsule = create_test_capsule();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::Continue => {},
            other => panic!("Expected Continue, got {:?}", other),
        }
    }

    #[test]
    fn test_stale_docs_requires_refresh() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        // Make docs receipt old
        capsule.session_meta.docs_receipts[0].read_at =
            SystemTime::now() - Duration::from_secs(7200); // 2 hours ago

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::NarrowRefreshRequired { refresh_targets } => {
                assert!(refresh_targets.contains(&RefreshTarget::Documentation));
            },
            other => panic!("Expected NarrowRefreshRequired, got {:?}", other),
        }
    }

    #[test]
    fn test_wrong_branch_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.git_state.current_branch = "feature-branch".to_string();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(reasons.iter().any(|r| matches!(r.category, ViolationCategory::StaleGitState)));
            },
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_critical_messages_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.inbox_state.critical_unacked.push(MessageRef {
            message_id: "critical-msg".to_string(),
            sender: "admin".to_string(),
            priority: MessagePriority::Critical,
            received_at: SystemTime::now(),
        });

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(reasons.iter().any(|r| matches!(r.category, ViolationCategory::CriticalUnacknowledgedMessages)));
            },
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_expired_reservations_need_coordination() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.active_reservations.push(FileReservation {
            id: "expired-res".to_string(),
            paths: vec!["src/**".to_string()],
            exclusive: true,
            expires_at: SystemTime::now() - Duration::from_secs(60), // Expired
            reason: "test".to_string(),
        });

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::CoordinateFirst { coordination_needed } => {
                assert!(coordination_needed.iter().any(|c| matches!(c.requirement_type, CoordinationType::FileReservationHandoff)));
            },
            other => panic!("Expected CoordinateFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_file_conflicts_need_coordination() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.dirty_paths.potential_conflicts.push(ConflictInfo {
            file_path: "src/conflicted.rs".to_string(),
            competing_agents: vec!["agent1".to_string(), "agent2".to_string()],
            severity: ConflictSeverity::Medium,
        });

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::CoordinateFirst { coordination_needed } => {
                assert!(coordination_needed.iter().any(|c| matches!(c.requirement_type, CoordinationType::ConflictResolution)));
            },
            other => panic!("Expected CoordinateFirst, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_content_hash_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.content_hash = "".to_string();

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(reasons.iter().any(|r| matches!(r.category, ViolationCategory::IntegrityCheckFailure)));
            },
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_proof_command_timeout_unsafe() {
        let verifier = HandoffVerifier::new();
        let mut capsule = create_test_capsule();

        capsule.proof_commands.push(ProofCommand {
            command_id: "old-proof".to_string(),
            command_line: "cargo test".to_string(),
            started_at: SystemTime::now() - Duration::from_secs(3600), // 1 hour ago
            expected_completion: None,
            command_type: ProofCommandType::Test,
        });

        match verifier.verify_handoff(&capsule) {
            HandoffDecision::UnsafeToContinue { reasons } => {
                assert!(reasons.iter().any(|r| matches!(r.category, ViolationCategory::FailedProofCommands)));
            },
            other => panic!("Expected UnsafeToContinue, got {:?}", other),
        }
    }

    #[test]
    fn test_capsule_serialization() {
        let capsule = create_test_capsule();

        // Test that the capsule can be serialized and deserialized
        let json = serde_json::to_string(&capsule).unwrap();
        let deserialized: HandoffCapsule = serde_json::from_str(&json).unwrap();

        assert_eq!(capsule.session_meta.agent_id, deserialized.session_meta.agent_id);
        assert_eq!(capsule.git_state.current_branch, deserialized.git_state.current_branch);
    }
}