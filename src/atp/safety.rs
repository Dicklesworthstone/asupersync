//! Receive-side safety preflight for ATP offers.
//!
//! This module is intentionally pure and deterministic: callers provide the
//! observed destination state, quota/free-space evidence, consent source, and
//! object graph. The planner never probes the ambient filesystem.

use crate::atp::object::{Object, ObjectGraph, ObjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

const PLAN_DIGEST_DOMAIN: &[u8] = b"asupersync.atp.receive-plan.v1\0";

/// Destination posture for receive-side ATP preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationPolicy {
    /// Deny all materialization until a more specific policy is supplied.
    Deny,
    /// Store only in the local inbox root.
    InboxOnly {
        /// Absolute or daemon-rooted inbox path supplied by the caller.
        inbox_root: PathBuf,
    },
    /// Accept bytes into quarantine but do not expose final destination paths.
    QuarantineOnly {
        /// Quarantine root supplied by daemon policy.
        quarantine_root: PathBuf,
    },
    /// Allow final commit under one of the listed destination roots.
    AllowListed {
        /// Destination roots this policy may write under.
        allowed_roots: BTreeSet<PathBuf>,
        /// Quarantine is still required before final commit.
        require_quarantine: bool,
        /// Existing destination paths may be replaced only when this is true.
        allow_overwrite: bool,
        /// Symlink edges may be materialized only when this is true.
        allow_symlinks: bool,
        /// Executable permission bits may be materialized only when true.
        allow_executables: bool,
        /// Device, hard-link, and special file metadata may be materialized.
        allow_special_files: bool,
        /// Destination comparison is case-sensitive.
        case_sensitive: bool,
        /// Optional per-transfer byte ceiling.
        max_bytes: Option<u64>,
    },
}

impl DestinationPolicy {
    /// Conservative daemon default: never expose received bytes directly.
    #[must_use]
    pub const fn conservative_default() -> Self {
        Self::Deny
    }

    #[must_use]
    const fn allow_overwrite(&self) -> bool {
        matches!(
            self,
            Self::AllowListed {
                allow_overwrite: true,
                ..
            }
        )
    }

    #[must_use]
    const fn allow_symlinks(&self) -> bool {
        matches!(
            self,
            Self::AllowListed {
                allow_symlinks: true,
                ..
            }
        )
    }

    #[must_use]
    const fn allow_executables(&self) -> bool {
        matches!(
            self,
            Self::AllowListed {
                allow_executables: true,
                ..
            }
        )
    }

    #[must_use]
    const fn allow_special_files(&self) -> bool {
        matches!(
            self,
            Self::AllowListed {
                allow_special_files: true,
                ..
            }
        )
    }

    #[must_use]
    const fn case_sensitive(&self) -> bool {
        match self {
            Self::AllowListed { case_sensitive, .. } => *case_sensitive,
            Self::Deny | Self::InboxOnly { .. } | Self::QuarantineOnly { .. } => false,
        }
    }

    #[must_use]
    const fn max_bytes(&self) -> Option<u64> {
        match self {
            Self::AllowListed { max_bytes, .. } => *max_bytes,
            Self::Deny | Self::InboxOnly { .. } | Self::QuarantineOnly { .. } => None,
        }
    }

    #[must_use]
    fn permits_destination_root(&self, root: &Path) -> bool {
        match self {
            Self::Deny => false,
            Self::InboxOnly { inbox_root } => root.starts_with(inbox_root),
            Self::QuarantineOnly { quarantine_root } => root.starts_with(quarantine_root),
            Self::AllowListed {
                allowed_roots,
                case_sensitive,
                ..
            } => allowed_roots
                .iter()
                .any(|allowed| path_starts_with_policy(root, allowed, *case_sensitive)),
        }
    }

    #[must_use]
    const fn requires_quarantine(&self) -> bool {
        match self {
            Self::Deny | Self::InboxOnly { .. } | Self::QuarantineOnly { .. } => true,
            Self::AllowListed {
                require_quarantine, ..
            } => *require_quarantine,
        }
    }
}

/// Source that authorized, denied, or deferred receive consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveConsentSource {
    /// No consent was supplied.
    None,
    /// Interactive CLI confirmation.
    CliConfirmation {
        /// Stable consent token bound to plan digest inputs.
        token: String,
    },
    /// Non-interactive daemon rule.
    DaemonAllowRule {
        /// Stable allow-rule identifier.
        rule_id: String,
    },
    /// Receive grant selected from local inbox/grant state.
    ReceiveGrant {
        /// Grant identifier.
        grant_id: String,
    },
    /// Mailbox policy accepted quarantine-only storage.
    MailboxPolicy {
        /// Mailbox policy identifier.
        policy_id: String,
    },
}

impl ReceiveConsentSource {
    #[must_use]
    const fn is_authorizing(&self) -> bool {
        !matches!(self, Self::None)
    }

    #[must_use]
    const fn allows_quarantine_only(&self) -> bool {
        matches!(self, Self::MailboxPolicy { .. })
    }
}

/// Metadata materialization posture for a receive plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveMetadataPolicy {
    /// Preserve only portable metadata and verify graph integrity.
    PortableOnly,
    /// Preserve platform metadata after preflight admits the object classes.
    PreserveVerified,
    /// Store metadata in the proof bundle but do not materialize it.
    RecordOnly,
}

/// Final exposure behavior after quarantine validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveCommitPolicy {
    /// Never expose the final destination path.
    DenyFinalCommit,
    /// Keep received bytes in quarantine for explicit later action.
    QuarantineOnly,
    /// Atomically expose the destination after validation succeeds.
    AtomicAfterValidation,
}

/// Rollback and resume behavior recorded in a receive plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackResumePolicy {
    /// Delete no caller data and retain quarantine metadata for diagnostics.
    RetainQuarantineForReview,
    /// Roll back the incomplete quarantine state and keep journal resume data.
    RollbackQuarantineKeepJournal,
    /// Resume only from a verified sparse/journal checkpoint.
    ResumeFromVerifiedJournal,
}

/// Caller-provided storage evidence for a receive preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageEvidence {
    /// Bytes available under the destination/quarantine volume, if measured.
    pub available_bytes: Option<u64>,
    /// Bytes remaining in the applicable receive quota, if configured.
    pub quota_remaining_bytes: Option<u64>,
    /// Extra bytes reserved for journal, metadata, and rollback overhead.
    pub safety_margin_bytes: u64,
}

/// Result of quota and free-space arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePreflightResult {
    /// Both quota and free-space evidence admit the plan.
    Pass,
    /// Arithmetic overflow prevents a safe admission decision.
    Overflow,
    /// Free-space evidence was absent.
    UnknownFreeSpace,
    /// Available free space is insufficient.
    InsufficientFreeSpace,
    /// Quota evidence was absent.
    UnknownQuota,
    /// Remaining quota is insufficient.
    QuotaExceeded,
}

/// Storage preflight details embedded in `ReceivePlan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePreflight {
    /// Bytes expected from object graph metadata.
    pub expected_bytes: u64,
    /// Safety margin bytes required before receive starts.
    pub safety_margin_bytes: u64,
    /// Caller-measured available bytes.
    pub available_bytes: Option<u64>,
    /// Caller-measured quota bytes.
    pub quota_remaining_bytes: Option<u64>,
    /// Deterministic storage decision.
    pub result: StoragePreflightResult,
}

/// Existing destination action discovered before receive starts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestructiveAction {
    /// Existing path would be overwritten by receive commit.
    Overwrite(PathBuf),
}

/// Deterministic object graph summary used for consent and proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectGraphSummary {
    /// Root object id rendered for stable logs.
    pub manifest_root: String,
    /// Total object records reachable from the root.
    pub object_count: usize,
    /// Sum of leaf `size_bytes` fields.
    pub expected_bytes: u64,
    /// Object counts keyed by stable object-kind name.
    pub kind_counts: BTreeMap<String, usize>,
    /// Number of symlink edges.
    pub symlink_count: usize,
    /// Number of objects carrying executable mode bits.
    pub executable_count: usize,
    /// Maximum reachable edge depth.
    pub max_depth: usize,
}

/// Destination paths selected by the preflight layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationPlan {
    /// Caller-selected destination root.
    pub root: PathBuf,
    /// Normalized relative path under `root`.
    pub relative_path: PathBuf,
    /// Final destination path; never used directly until the plan is admitted.
    pub final_path: PathBuf,
}

/// Quarantine path selected by the preflight layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinePlan {
    /// Whether receive bytes must first land in quarantine.
    pub required: bool,
    /// Deterministic quarantine path for this plan.
    pub path: PathBuf,
}

/// Safety decision for the receive plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDecision {
    /// Nothing may be written.
    Deny,
    /// Bytes may be written only into quarantine.
    QuarantineOnly,
    /// Final commit may happen after quarantine validation.
    AllowFinalCommit,
}

/// Stable rejection reasons for logs, JSON, and proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveRejectReason {
    /// No explicit consent, grant, or allow rule was supplied.
    MissingConsent,
    /// Destination policy does not cover the requested root.
    DestinationPolicyDenied,
    /// Destination relative path is unsafe.
    UnsafeDestinationPath(String),
    /// Object graph path/name is unsafe.
    UnsafeObjectPath(String),
    /// Case-insensitive path collision.
    CaseCollision(String),
    /// Symlink materialization is not allowed.
    SymlinkDenied(String),
    /// Executable-bit materialization is not allowed.
    ExecutableDenied(String),
    /// Special file materialization is not allowed.
    SpecialFileDenied(String),
    /// Existing path would be overwritten.
    OverwriteDenied(String),
    /// Free-space or quota arithmetic did not pass.
    StorageDenied(StoragePreflightResult),
    /// Policy-specific max bytes was exceeded.
    PolicyMaxBytesExceeded,
    /// Consent token does not match the derived preflight token.
    ConsentTokenMismatch,
}

/// Complete receive-side plan emitted before any bytes are materialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivePlan {
    /// Peer identity reported by the authenticated session.
    pub sender_identity: String,
    /// Optional grant id used by daemon policy.
    pub grant_id: Option<String>,
    /// Human-readable capability scope summary.
    pub capability_scope: Option<String>,
    /// Object graph root.
    pub manifest_root: String,
    /// Stable object graph summary.
    pub object_graph_summary: ObjectGraphSummary,
    /// Destination decision.
    pub destination: DestinationPlan,
    /// Storage arithmetic.
    pub storage: StoragePreflight,
    /// Destructive actions that would happen at final commit.
    pub destructive_actions: Vec<DestructiveAction>,
    /// Metadata materialization policy.
    pub metadata_policy: ReceiveMetadataPolicy,
    /// Quarantine decision.
    pub quarantine: QuarantinePlan,
    /// Final commit posture.
    pub commit_policy: ReceiveCommitPolicy,
    /// Consent source used by this plan.
    pub consent_source: ReceiveConsentSource,
    /// Rollback/resume behavior.
    pub rollback_resume: RollbackResumePolicy,
    /// Final safety decision.
    pub decision: ReceiveDecision,
    /// Fail-closed rejection reasons, empty only for admitted plans.
    pub rejected_reasons: Vec<ReceiveRejectReason>,
    /// Optional Cx trace id supplied by caller.
    pub trace_id: Option<String>,
    /// Optional replay/proof bundle pointer supplied by caller.
    pub replay_pointer: Option<String>,
    /// Digest over safety-relevant plan fields.
    pub plan_digest: String,
}

impl ReceivePlan {
    /// Stable human lines for dry-run/status output.
    #[must_use]
    pub fn stable_human_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("decision {}", self.decision.as_str()),
            format!("sender {}", redact_token(&self.sender_identity)),
            format!("manifest_root {}", self.manifest_root),
            format!(
                "destination {}",
                self.destination.final_path.to_string_lossy()
            ),
            format!("quarantine {}", self.quarantine.path.to_string_lossy()),
            format!("expected_bytes {}", self.storage.expected_bytes),
            format!("storage {}", self.storage.result.as_str()),
            format!("commit {}", self.commit_policy.as_str()),
            format!("plan_digest {}", self.plan_digest),
        ];
        lines.extend(
            self.rejected_reasons
                .iter()
                .map(|reason| format!("reject {}", reason.stable_code())),
        );
        lines
    }

    /// Stable JSON value for CLI/daemon dry-run output.
    pub fn stable_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl ReceiveDecision {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::QuarantineOnly => "quarantine_only",
            Self::AllowFinalCommit => "allow_final_commit",
        }
    }
}

impl StoragePreflightResult {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Overflow => "overflow",
            Self::UnknownFreeSpace => "unknown_free_space",
            Self::InsufficientFreeSpace => "insufficient_free_space",
            Self::UnknownQuota => "unknown_quota",
            Self::QuotaExceeded => "quota_exceeded",
        }
    }
}

impl ReceiveCommitPolicy {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::DenyFinalCommit => "deny_final_commit",
            Self::QuarantineOnly => "quarantine_only",
            Self::AtomicAfterValidation => "atomic_after_validation",
        }
    }
}

impl ReceiveRejectReason {
    #[must_use]
    fn stable_code(&self) -> &'static str {
        match self {
            Self::MissingConsent => "missing_consent",
            Self::DestinationPolicyDenied => "destination_policy_denied",
            Self::UnsafeDestinationPath(_) => "unsafe_destination_path",
            Self::UnsafeObjectPath(_) => "unsafe_object_path",
            Self::CaseCollision(_) => "case_collision",
            Self::SymlinkDenied(_) => "symlink_denied",
            Self::ExecutableDenied(_) => "executable_denied",
            Self::SpecialFileDenied(_) => "special_file_denied",
            Self::OverwriteDenied(_) => "overwrite_denied",
            Self::StorageDenied(_) => "storage_denied",
            Self::PolicyMaxBytesExceeded => "policy_max_bytes_exceeded",
            Self::ConsentTokenMismatch => "consent_token_mismatch",
        }
    }
}

/// Caller input for a pure receive-side safety preflight.
#[derive(Debug)]
pub struct ReceivePreflightInput<'a> {
    /// Authenticated sender identity.
    pub sender_identity: String,
    /// Optional receive grant id.
    pub grant_id: Option<String>,
    /// Optional capability scope summary.
    pub capability_scope: Option<String>,
    /// Offered graph root.
    pub manifest_root: &'a ObjectId,
    /// Offered object graph.
    pub graph: &'a ObjectGraph,
    /// Destination policy selected by CLI or daemon.
    pub destination_policy: DestinationPolicy,
    /// Destination root selected by caller/policy.
    pub destination_root: PathBuf,
    /// Relative destination path for this receive.
    pub destination_relative_path: PathBuf,
    /// Paths that already exist under the destination root.
    pub existing_destination_paths: BTreeSet<PathBuf>,
    /// Caller-provided storage evidence.
    pub storage_evidence: StorageEvidence,
    /// Metadata policy requested for materialization.
    pub metadata_policy: ReceiveMetadataPolicy,
    /// Consent source.
    pub consent_source: ReceiveConsentSource,
    /// Rollback/resume behavior.
    pub rollback_resume: RollbackResumePolicy,
    /// Optional Cx trace id.
    pub trace_id: Option<String>,
    /// Optional replay/proof pointer.
    pub replay_pointer: Option<String>,
}

/// Deterministic quarantine queue for receive plans.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineQueue {
    items: BTreeMap<String, QuarantineQueueItem>,
}

impl QuarantineQueue {
    /// Create an empty quarantine queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: BTreeMap::new(),
        }
    }

    /// Add a quarantined receive plan.
    pub fn enqueue(&mut self, plan: &ReceivePlan) -> Result<(), ReceiveSafetyError> {
        if plan.quarantine.path.as_os_str().is_empty() {
            return Err(ReceiveSafetyError::InvalidQuarantinePath);
        }
        let item = QuarantineQueueItem {
            plan_digest: plan.plan_digest.clone(),
            quarantine_path: plan.quarantine.path.clone(),
            final_path: plan.destination.final_path.clone(),
            expected_bytes: plan.storage.expected_bytes,
            state: QuarantineQueueState::Pending,
        };
        self.items.insert(plan.plan_digest.clone(), item);
        Ok(())
    }

    /// Move a quarantined plan into the validation-ready state.
    pub fn mark_materialized(&mut self, plan_digest: &str) -> Result<(), ReceiveSafetyError> {
        let item = self
            .items
            .get_mut(plan_digest)
            .ok_or_else(|| ReceiveSafetyError::UnknownQuarantinePlan(plan_digest.to_string()))?;
        item.state = QuarantineQueueState::Materialized;
        Ok(())
    }

    /// Record a deterministic rollback.
    pub fn mark_rolled_back(&mut self, plan_digest: &str) -> Result<(), ReceiveSafetyError> {
        let item = self
            .items
            .get_mut(plan_digest)
            .ok_or_else(|| ReceiveSafetyError::UnknownQuarantinePlan(plan_digest.to_string()))?;
        item.state = QuarantineQueueState::RolledBack;
        Ok(())
    }

    /// Return queue items in stable digest order.
    #[must_use = "iterators are lazy; consume the returned iterator"]
    pub fn items(&self) -> impl Iterator<Item = &QuarantineQueueItem> {
        self.items.values()
    }
}

/// One deterministic quarantine queue record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineQueueItem {
    /// Receive plan digest.
    pub plan_digest: String,
    /// Quarantine path.
    pub quarantine_path: PathBuf,
    /// Final path guarded by this quarantine record.
    pub final_path: PathBuf,
    /// Expected receive bytes.
    pub expected_bytes: u64,
    /// Queue state.
    pub state: QuarantineQueueState,
}

/// Quarantine queue lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineQueueState {
    /// Planned but no bytes materialized yet.
    Pending,
    /// Quarantine data exists and awaits validation/consent.
    Materialized,
    /// Validation succeeded and final commit may be attempted.
    CommitReady,
    /// Receive was rolled back.
    RolledBack,
}

/// Errors from the pure receive-safety planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveSafetyError {
    /// The manifest root is not present in the object graph.
    UnknownManifestRoot(String),
    /// Object graph arithmetic overflowed.
    ObjectGraphOverflow,
    /// Quarantine path is empty.
    InvalidQuarantinePath,
    /// Quarantine plan digest was not present.
    UnknownQuarantinePlan(String),
}

impl fmt::Display for ReceiveSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownManifestRoot(root) => write!(f, "unknown manifest root {root}"),
            Self::ObjectGraphOverflow => f.write_str("object graph byte count overflow"),
            Self::InvalidQuarantinePath => f.write_str("invalid quarantine path"),
            Self::UnknownQuarantinePlan(digest) => {
                write!(f, "unknown quarantine plan {digest}")
            }
        }
    }
}

impl std::error::Error for ReceiveSafetyError {}

/// Build a receive plan without reading ambient OS state.
pub fn build_receive_plan(
    input: ReceivePreflightInput<'_>,
) -> Result<ReceivePlan, ReceiveSafetyError> {
    let case_sensitive = input.destination_policy.case_sensitive();
    let mut rejected_reasons = Vec::new();

    let relative_components = match normalize_relative_path(&input.destination_relative_path) {
        Ok(components) => components,
        Err(reason) => {
            rejected_reasons.push(ReceiveRejectReason::UnsafeDestinationPath(reason));
            Vec::new()
        }
    };

    if !input
        .destination_policy
        .permits_destination_root(&input.destination_root)
    {
        rejected_reasons.push(ReceiveRejectReason::DestinationPolicyDenied);
    }

    if !input.consent_source.is_authorizing() {
        rejected_reasons.push(ReceiveRejectReason::MissingConsent);
    }

    let graph_summary = summarize_graph(input.graph, input.manifest_root, case_sensitive)?;
    let graph_rejections = inspect_graph(
        input.graph,
        input.manifest_root,
        &input.destination_policy,
        case_sensitive,
    )?;
    rejected_reasons.extend(graph_rejections);

    let storage = evaluate_storage(graph_summary.expected_bytes, input.storage_evidence);
    if storage.result != StoragePreflightResult::Pass {
        rejected_reasons.push(ReceiveRejectReason::StorageDenied(storage.result));
    }

    if input
        .destination_policy
        .max_bytes()
        .is_some_and(|max_bytes| graph_summary.expected_bytes > max_bytes)
    {
        rejected_reasons.push(ReceiveRejectReason::PolicyMaxBytesExceeded);
    }

    let relative_path = components_to_path(&relative_components);
    let final_path = input.destination_root.join(&relative_path);
    let destructive_actions = destructive_actions_for(
        &final_path,
        &input.existing_destination_paths,
        case_sensitive,
    );
    if !destructive_actions.is_empty() && !input.destination_policy.allow_overwrite() {
        rejected_reasons.extend(destructive_actions.iter().map(|action| match action {
            DestructiveAction::Overwrite(path) => {
                ReceiveRejectReason::OverwriteDenied(path.to_string_lossy().into_owned())
            }
        }));
    }

    let quarantine_path = quarantine_path_for(&input.destination_policy, &input.destination_root);
    let commit_policy = commit_policy_for(&input.destination_policy, &input.consent_source);
    let decision = decision_for(&input.destination_policy, commit_policy, &rejected_reasons);

    let destination = DestinationPlan {
        root: input.destination_root,
        relative_path,
        final_path,
    };
    let quarantine = QuarantinePlan {
        required: input.destination_policy.requires_quarantine(),
        path: quarantine_path,
    };
    let manifest_root = input.manifest_root.to_string();

    let mut plan = ReceivePlan {
        sender_identity: input.sender_identity,
        grant_id: input.grant_id,
        capability_scope: input.capability_scope,
        manifest_root,
        object_graph_summary: graph_summary,
        destination,
        storage,
        destructive_actions,
        metadata_policy: input.metadata_policy,
        quarantine,
        commit_policy,
        consent_source: input.consent_source,
        rollback_resume: input.rollback_resume,
        decision,
        rejected_reasons,
        trace_id: input.trace_id,
        replay_pointer: input.replay_pointer,
        plan_digest: String::new(),
    };
    plan.plan_digest = plan_digest(&plan);

    if let ReceiveConsentSource::CliConfirmation { token } = &plan.consent_source {
        let expected = consent_token(&plan);
        if !constant_time_token_eq(token, &expected) {
            plan.rejected_reasons
                .push(ReceiveRejectReason::ConsentTokenMismatch);
            plan.decision = ReceiveDecision::Deny;
            plan.commit_policy = ReceiveCommitPolicy::DenyFinalCommit;
            plan.plan_digest = plan_digest(&plan);
        }
    }

    Ok(plan)
}

/// Return the CLI consent token expected for a plan.
#[must_use]
pub fn consent_token(plan: &ReceivePlan) -> String {
    let digest = plan_digest_without_consent(plan);
    format!("consent-{}", &digest[..16])
}

fn summarize_graph(
    graph: &ObjectGraph,
    root: &ObjectId,
    case_sensitive: bool,
) -> Result<ObjectGraphSummary, ReceiveSafetyError> {
    let mut summary = ObjectGraphSummary {
        manifest_root: root.to_string(),
        object_count: 0,
        expected_bytes: 0,
        kind_counts: BTreeMap::new(),
        symlink_count: 0,
        executable_count: 0,
        max_depth: 0,
    };
    let mut visited = BTreeSet::new();
    let mut seen_paths = BTreeMap::new();
    summarize_object(
        graph,
        root,
        0,
        &mut Vec::new(),
        &mut visited,
        &mut summary,
        case_sensitive,
        &mut seen_paths,
    )?;
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn summarize_object(
    graph: &ObjectGraph,
    id: &ObjectId,
    depth: usize,
    path: &mut Vec<String>,
    visited: &mut BTreeSet<ObjectId>,
    summary: &mut ObjectGraphSummary,
    case_sensitive: bool,
    seen_paths: &mut BTreeMap<String, String>,
) -> Result<(), ReceiveSafetyError> {
    if !visited.insert(id.clone()) {
        return Ok(());
    }
    let object = graph
        .get_object(id)
        .ok_or_else(|| ReceiveSafetyError::UnknownManifestRoot(id.to_string()))?;
    summary.object_count += 1;
    summary.max_depth = summary.max_depth.max(depth);
    *summary
        .kind_counts
        .entry(object.metadata.kind.to_string())
        .or_insert(0) += 1;
    if let Some(bytes) = object.metadata.size_bytes {
        summary.expected_bytes = summary
            .expected_bytes
            .checked_add(bytes)
            .ok_or(ReceiveSafetyError::ObjectGraphOverflow)?;
    }
    if object_is_executable(object) {
        summary.executable_count += 1;
    }

    for edge in &object.children {
        summary.symlink_count += usize::from(edge.is_symlink);
        path.push(edge.name.clone());
        let rendered = path.join("/");
        let folded = fold_path_key(&rendered, case_sensitive);
        if let Some(existing) = seen_paths.insert(folded, rendered.clone()) {
            if existing != rendered {
                summary.max_depth = summary.max_depth.max(depth + 1);
            }
        }
        summarize_object(
            graph,
            &edge.child_id,
            depth + 1,
            path,
            visited,
            summary,
            case_sensitive,
            seen_paths,
        )?;
        path.pop();
    }
    Ok(())
}

fn inspect_graph(
    graph: &ObjectGraph,
    root: &ObjectId,
    policy: &DestinationPolicy,
    case_sensitive: bool,
) -> Result<Vec<ReceiveRejectReason>, ReceiveSafetyError> {
    let mut rejected = Vec::new();
    let mut visited = BTreeSet::new();
    let mut seen_paths = BTreeMap::new();
    inspect_object(
        graph,
        root,
        policy,
        case_sensitive,
        &mut Vec::new(),
        &mut visited,
        &mut seen_paths,
        &mut rejected,
    )?;
    Ok(rejected)
}

#[allow(clippy::too_many_arguments)]
fn inspect_object(
    graph: &ObjectGraph,
    id: &ObjectId,
    policy: &DestinationPolicy,
    case_sensitive: bool,
    path: &mut Vec<String>,
    visited: &mut BTreeSet<ObjectId>,
    seen_paths: &mut BTreeMap<String, String>,
    rejected: &mut Vec<ReceiveRejectReason>,
) -> Result<(), ReceiveSafetyError> {
    if !visited.insert(id.clone()) {
        return Ok(());
    }
    let object = graph
        .get_object(id)
        .ok_or_else(|| ReceiveSafetyError::UnknownManifestRoot(id.to_string()))?;
    if object_is_executable(object) && !policy.allow_executables() {
        rejected.push(ReceiveRejectReason::ExecutableDenied(path.join("/")));
    }
    if object_has_special_metadata(object) && !policy.allow_special_files() {
        rejected.push(ReceiveRejectReason::SpecialFileDenied(path.join("/")));
    }
    for edge in &object.children {
        path.push(edge.name.clone());
        let rendered = path.join("/");
        if let Err(reason) = validate_component(&edge.name) {
            rejected.push(ReceiveRejectReason::UnsafeObjectPath(reason));
        }
        if let Err(reason) = normalize_relative_path(Path::new(&rendered)) {
            rejected.push(ReceiveRejectReason::UnsafeObjectPath(reason));
        }
        let folded = fold_path_key(&rendered, case_sensitive);
        if let Some(existing) = seen_paths.insert(folded, rendered.clone()) {
            if existing != rendered {
                rejected.push(ReceiveRejectReason::CaseCollision(format!(
                    "{existing} conflicts with {rendered}"
                )));
            }
        }
        if edge.is_symlink && !policy.allow_symlinks() {
            rejected.push(ReceiveRejectReason::SymlinkDenied(rendered.clone()));
        }
        inspect_object(
            graph,
            &edge.child_id,
            policy,
            case_sensitive,
            path,
            visited,
            seen_paths,
            rejected,
        )?;
        path.pop();
    }
    Ok(())
}

fn evaluate_storage(expected_bytes: u64, evidence: StorageEvidence) -> StoragePreflight {
    let result = match expected_bytes.checked_add(evidence.safety_margin_bytes) {
        None => StoragePreflightResult::Overflow,
        Some(required) => match (evidence.available_bytes, evidence.quota_remaining_bytes) {
            (None, _) => StoragePreflightResult::UnknownFreeSpace,
            (Some(available), _) if available < required => {
                StoragePreflightResult::InsufficientFreeSpace
            }
            (_, None) => StoragePreflightResult::UnknownQuota,
            (_, Some(quota)) if quota < required => StoragePreflightResult::QuotaExceeded,
            (Some(_), Some(_)) => StoragePreflightResult::Pass,
        },
    };
    StoragePreflight {
        expected_bytes,
        safety_margin_bytes: evidence.safety_margin_bytes,
        available_bytes: evidence.available_bytes,
        quota_remaining_bytes: evidence.quota_remaining_bytes,
        result,
    }
}

fn destructive_actions_for(
    final_path: &Path,
    existing_paths: &BTreeSet<PathBuf>,
    case_sensitive: bool,
) -> Vec<DestructiveAction> {
    let final_key = fold_path_key(&final_path.to_string_lossy(), case_sensitive);
    existing_paths
        .iter()
        .filter(|existing| fold_path_key(&existing.to_string_lossy(), case_sensitive) == final_key)
        .map(|existing| DestructiveAction::Overwrite(existing.clone()))
        .collect()
}

fn commit_policy_for(
    policy: &DestinationPolicy,
    consent: &ReceiveConsentSource,
) -> ReceiveCommitPolicy {
    match policy {
        DestinationPolicy::Deny => ReceiveCommitPolicy::DenyFinalCommit,
        DestinationPolicy::InboxOnly { .. } | DestinationPolicy::QuarantineOnly { .. } => {
            ReceiveCommitPolicy::QuarantineOnly
        }
        DestinationPolicy::AllowListed { .. } if consent.allows_quarantine_only() => {
            ReceiveCommitPolicy::QuarantineOnly
        }
        DestinationPolicy::AllowListed { .. } => ReceiveCommitPolicy::AtomicAfterValidation,
    }
}

fn decision_for(
    policy: &DestinationPolicy,
    commit_policy: ReceiveCommitPolicy,
    rejected_reasons: &[ReceiveRejectReason],
) -> ReceiveDecision {
    if !rejected_reasons.is_empty() || matches!(policy, DestinationPolicy::Deny) {
        return ReceiveDecision::Deny;
    }
    match commit_policy {
        ReceiveCommitPolicy::DenyFinalCommit => ReceiveDecision::Deny,
        ReceiveCommitPolicy::QuarantineOnly => ReceiveDecision::QuarantineOnly,
        ReceiveCommitPolicy::AtomicAfterValidation => ReceiveDecision::AllowFinalCommit,
    }
}

fn quarantine_path_for(policy: &DestinationPolicy, destination_root: &Path) -> PathBuf {
    let root = match policy {
        DestinationPolicy::Deny | DestinationPolicy::AllowListed { .. } => {
            destination_root.join(".atp-quarantine")
        }
        DestinationPolicy::InboxOnly { inbox_root } => inbox_root.join(".atp-quarantine"),
        DestinationPolicy::QuarantineOnly { quarantine_root } => quarantine_root.clone(),
    };
    root.join("pending")
}

fn normalize_relative_path(path: &Path) -> Result<Vec<String>, String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(raw) => {
                let Some(component) = raw.to_str() else {
                    return Err(path.to_string_lossy().into_owned());
                };
                validate_component(component)?;
                components.push(component.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(path.to_string_lossy().into_owned());
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(path.to_string_lossy().into_owned());
            }
        }
    }
    if components.is_empty() {
        return Err(path.to_string_lossy().into_owned());
    }
    Ok(components)
}

fn validate_component(component: &str) -> Result<(), String> {
    if component.is_empty()
        || component.contains('\0')
        || component.contains('/')
        || component.contains('\\')
        || component.contains(':')
        || component.ends_with('.')
        || component.ends_with(' ')
    {
        return Err(component.to_string());
    }
    let folded = component.to_ascii_uppercase();
    let reserved = matches!(
        folded.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if reserved {
        return Err(component.to_string());
    }
    Ok(())
}

fn components_to_path(components: &[String]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    path
}

fn object_is_executable(object: &Object) -> bool {
    object
        .metadata
        .platform
        .unix_mode
        .is_some_and(|mode| mode & 0o111 != 0)
}

fn object_has_special_metadata(object: &Object) -> bool {
    object
        .metadata
        .platform
        .unix_mode
        .is_some_and(|mode| mode & 0o170_000 != 0 && mode & 0o170_000 != 0o100_000)
}

fn fold_path_key(path: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        path.to_string()
    } else {
        path.to_ascii_lowercase()
    }
}

fn path_starts_with_policy(root: &Path, allowed: &Path, case_sensitive: bool) -> bool {
    if case_sensitive {
        return root.starts_with(allowed);
    }

    let mut root_components = root.components();
    for allowed_component in allowed.components() {
        let Some(root_component) = root_components.next() else {
            return false;
        };
        if !path_component_eq_policy(root_component, allowed_component) {
            return false;
        }
    }
    true
}

fn path_component_eq_policy(left: Component<'_>, right: Component<'_>) -> bool {
    fold_path_key(&left.as_os_str().to_string_lossy(), false)
        == fold_path_key(&right.as_os_str().to_string_lossy(), false)
}

fn plan_digest(plan: &ReceivePlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(plan_digest_material(plan, true));
    let digest = hasher.finalize();
    hex_bytes(&digest)
}

fn plan_digest_without_consent(plan: &ReceivePlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(plan_digest_material(plan, false));
    let digest = hasher.finalize();
    hex_bytes(&digest)
}

fn plan_digest_material(plan: &ReceivePlan, include_consent: bool) -> Vec<u8> {
    let mut material = Vec::new();
    push_field(&mut material, "sender", &plan.sender_identity);
    push_field(&mut material, "manifest", &plan.manifest_root);
    push_field(
        &mut material,
        "destination",
        &plan.destination.final_path.to_string_lossy(),
    );
    push_field(
        &mut material,
        "quarantine",
        &plan.quarantine.path.to_string_lossy(),
    );
    push_field(
        &mut material,
        "expected",
        &plan.storage.expected_bytes.to_string(),
    );
    push_field(&mut material, "decision", plan.decision.as_str());
    push_field(&mut material, "commit", plan.commit_policy.as_str());
    for reason in &plan.rejected_reasons {
        push_field(&mut material, "reject", reason.stable_code());
    }
    for (kind, count) in &plan.object_graph_summary.kind_counts {
        push_field(&mut material, "kind", kind);
        push_field(&mut material, "count", &count.to_string());
    }
    if include_consent {
        push_field(
            &mut material,
            "consent",
            &format!("{:?}", plan.consent_source),
        );
    }
    material
}

fn push_field(material: &mut Vec<u8>, key: &str, value: &str) {
    material.extend_from_slice(key.as_bytes());
    material.push(0);
    material.extend_from_slice(value.as_bytes());
    material.push(0xff);
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    subtle::ConstantTimeEq::ct_eq(left.as_bytes(), right.as_bytes()).into()
}

fn redact_token(token: &str) -> String {
    if token.len() <= 12 {
        return token.to_string();
    }
    format!("{}...", &token[..12])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::{ContentId, ObjectEdge, ObjectKind, PlatformMetadata};

    fn graph_with_file(name: &str, content: &[u8]) -> (ObjectGraph, ObjectId) {
        let file = Object::file(content.to_vec());
        let file_id = file.id.clone();
        let directory = Object::directory(vec![ObjectEdge::new(file_id, name.to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file object inserts");
        graph.add_root(directory).expect("directory root inserts");
        (graph, root)
    }

    fn allow_policy(root: &str) -> DestinationPolicy {
        DestinationPolicy::AllowListed {
            allowed_roots: BTreeSet::from([PathBuf::from(root)]),
            require_quarantine: true,
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            allow_special_files: false,
            case_sensitive: false,
            max_bytes: Some(1_000),
        }
    }

    fn input<'a>(
        graph: &'a ObjectGraph,
        root: &'a ObjectId,
        policy: DestinationPolicy,
    ) -> ReceivePreflightInput<'a> {
        ReceivePreflightInput {
            sender_identity: "peer-alpha-secret".to_string(),
            grant_id: Some("grant-1".to_string()),
            capability_scope: Some("path:/safe".to_string()),
            manifest_root: root,
            graph,
            destination_policy: policy,
            destination_root: PathBuf::from("/safe"),
            destination_relative_path: PathBuf::from("bundle"),
            existing_destination_paths: BTreeSet::new(),
            storage_evidence: StorageEvidence {
                available_bytes: Some(2_000),
                quota_remaining_bytes: Some(2_000),
                safety_margin_bytes: 10,
            },
            metadata_policy: ReceiveMetadataPolicy::PortableOnly,
            consent_source: ReceiveConsentSource::DaemonAllowRule {
                rule_id: "allow-1".to_string(),
            },
            rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
            trace_id: Some("trace-1".to_string()),
            replay_pointer: Some("proof://bundle".to_string()),
        }
    }

    #[test]
    fn default_policy_denies_before_materialization() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan = build_receive_plan(input(
            &graph,
            &root,
            DestinationPolicy::conservative_default(),
        ))
        .expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
        assert_eq!(plan.commit_policy, ReceiveCommitPolicy::DenyFinalCommit);
    }

    #[test]
    fn allow_listed_policy_with_daemon_consent_admits_final_commit() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert_eq!(plan.storage.result, StoragePreflightResult::Pass);
        assert!(plan.rejected_reasons.is_empty());
        assert_eq!(plan.object_graph_summary.expected_bytes, 5);
        assert_eq!(
            plan.object_graph_summary.kind_counts[&ObjectKind::FileObject.to_string()],
            1
        );
    }

    #[test]
    fn case_insensitive_allowlist_matches_destination_root_case() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/SAFE"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::AllowFinalCommit);
        assert!(
            !plan
                .rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
    }

    #[test]
    fn case_sensitive_allowlist_rejects_destination_root_case_mismatch() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let policy = DestinationPolicy::AllowListed {
            allowed_roots: BTreeSet::from([PathBuf::from("/SAFE")]),
            require_quarantine: true,
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            allow_special_files: false,
            case_sensitive: true,
            max_bytes: Some(1_000),
        };
        let plan = build_receive_plan(input(&graph, &root, policy)).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::DestinationPolicyDenied)
        );
    }

    #[test]
    fn mailbox_consent_keeps_receive_quarantine_only() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.consent_source = ReceiveConsentSource::MailboxPolicy {
            policy_id: "mailbox-only".to_string(),
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::QuarantineOnly);
        assert_eq!(plan.commit_policy, ReceiveCommitPolicy::QuarantineOnly);
    }

    #[test]
    fn path_traversal_fails_closed() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.destination_relative_path = PathBuf::from("../escape");

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::UnsafeDestinationPath(_)))
        );
    }

    #[test]
    fn case_insensitive_object_collision_fails_closed() {
        let file_a = Object::file(b"a".to_vec());
        let file_b = Object::file(b"b".to_vec());
        let directory = Object::directory(vec![
            ObjectEdge::new(file_a.id.clone(), "Readme".to_string()),
            ObjectEdge::new(file_b.id.clone(), "README".to_string()),
        ]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file_a).expect("file a inserts");
        graph.add_object(file_b).expect("file b inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::CaseCollision(_)))
        );
    }

    #[test]
    fn symlink_edges_fail_closed_unless_policy_allows_them() {
        let target = ObjectId::content(ContentId::from_bytes(b"target"));
        let file = Object::file(b"target".to_vec());
        let directory = Object::directory(vec![ObjectEdge::symlink(
            target,
            "link".to_string(),
            PathBuf::from("/etc/passwd"),
        )]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::SymlinkDenied(_)))
        );
    }

    #[test]
    fn executable_bits_fail_closed_under_portable_policy() {
        let mut file = Object::file(b"run".to_vec());
        file.metadata.platform = PlatformMetadata {
            unix_mode: Some(0o100_755),
            ..PlatformMetadata::default()
        };
        let directory =
            Object::directory(vec![ObjectEdge::new(file.id.clone(), "run".to_string())]);
        let root = directory.id.clone();
        let mut graph = ObjectGraph::new();
        graph.add_object(file).expect("file inserts");
        graph.add_root(directory).expect("directory root inserts");

        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        assert_eq!(plan.object_graph_summary.executable_count, 1);
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::ExecutableDenied(_)))
        );
    }

    #[test]
    fn quota_and_free_space_are_checked_with_safety_margin() {
        let (graph, root) = graph_with_file("large.bin", &[0; 32]);
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.storage_evidence = StorageEvidence {
            available_bytes: Some(100),
            quota_remaining_bytes: Some(40),
            safety_margin_bytes: 16,
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.storage.result, StoragePreflightResult::QuotaExceeded);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::StorageDenied(
                    StoragePreflightResult::QuotaExceeded
                ))
        );
    }

    #[test]
    fn existing_destination_requires_explicit_overwrite_policy() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive
            .existing_destination_paths
            .insert(PathBuf::from("/safe/bundle"));

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(
            plan.destructive_actions,
            vec![DestructiveAction::Overwrite(PathBuf::from("/safe/bundle"))]
        );
        assert!(
            plan.rejected_reasons
                .iter()
                .any(|reason| matches!(reason, ReceiveRejectReason::OverwriteDenied(_)))
        );
    }

    #[test]
    fn cli_confirmation_replay_is_plan_bound() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        let wrong_confirmation = String::from("not-bound-to-plan");
        receive.consent_source = ReceiveConsentSource::CliConfirmation {
            token: wrong_confirmation,
        };

        let plan = build_receive_plan(receive).expect("plan builds");

        assert_eq!(plan.decision, ReceiveDecision::Deny);
        assert!(
            plan.rejected_reasons
                .contains(&ReceiveRejectReason::ConsentTokenMismatch)
        );
    }

    #[test]
    fn quarantine_queue_is_stable_and_recoverable() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let mut receive = input(&graph, &root, allow_policy("/safe"));
        receive.consent_source = ReceiveConsentSource::MailboxPolicy {
            policy_id: "mailbox-only".to_string(),
        };
        let plan = build_receive_plan(receive).expect("plan builds");
        let mut queue = QuarantineQueue::new();

        queue.enqueue(&plan).expect("enqueue succeeds");
        queue
            .mark_materialized(&plan.plan_digest)
            .expect("materialize succeeds");

        let items = queue.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].state, QuarantineQueueState::Materialized);
        assert_eq!(items[0].plan_digest, plan.plan_digest);
    }

    #[test]
    fn human_and_json_output_are_stable() {
        let (graph, root) = graph_with_file("ok.txt", b"hello");
        let plan =
            build_receive_plan(input(&graph, &root, allow_policy("/safe"))).expect("plan builds");

        let human = plan.stable_human_lines();
        let json = plan.stable_json().expect("known plan serializes to json");

        assert_eq!(human[0], "decision allow_final_commit");
        assert_eq!(json["decision"], "allow_final_commit");
        assert_eq!(json["storage"]["expected_bytes"], 5);
    }
}
