//! Operator SLO policy bundle schema and fail-closed validation.
//!
//! SLO policy bundles are deterministic operator inputs. They describe service
//! objectives that later compiler beads can map into [`Budget`](crate::types::Budget),
//! admission thresholds, brownout tiers, and no-win fallback receipts.

use super::budget::Budget;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Current SLO policy bundle schema version.
pub const SLO_POLICY_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Current deterministic compiler contract for SLO policy bundles.
pub const SLO_POLICY_COMPILER_SCHEMA_VERSION: &str = "slo-budget-admission-compiler-v1";

/// Current operator proof report contract for SLO policy compilation and replay evidence.
pub const SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION: &str = "slo-proof-report-v1";

/// Current runtime application contract for compiled SLO policies.
pub const SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION: &str = "slo-runtime-policy-application-v1";

const MAX_ID_BYTES: usize = 128;
const MAX_FIELD_BYTES: usize = 1024;
const MAX_PATH_BYTES: usize = 512;
const SHA256_HEX_LEN: usize = 64;

const SECRET_KEY_FRAGMENTS: [&str; 10] = [
    "authorization",
    "cookie",
    "credential",
    "passwd",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
    "api_key",
];

const SECRET_VALUE_FRAGMENTS: [&str; 8] = [
    "bearer ",
    "basic ",
    "sk-",
    "ghp_",
    "akia",
    "-----begin",
    ".ssh",
    "id_rsa",
];

const PRIVATE_PATH_FRAGMENTS: [&str; 7] = [
    "/home/",
    "/users/",
    "c:\\users\\",
    "/.ssh/",
    "\\.ssh\\",
    "/appdata/",
    "\\appdata\\",
];

fn cargo_proof_command_has_target_dir(command: &str) -> bool {
    !command.contains("cargo ")
        || (command.contains("rch exec -- env ") && command.contains("CARGO_TARGET_DIR="))
}

/// Workload class vocabulary for SLO policy bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SloWorkloadClass {
    /// Control-plane or coordination-heavy runtime work.
    ControlPlane,
    /// Data-plane request/response traffic.
    DataPlane,
    /// Background maintenance work.
    Background,
    /// Massive agent swarm workloads.
    AgentSwarm,
    /// Unsupported workload tag preserved for fail-closed validation.
    Unsupported(String),
}

impl SloWorkloadClass {
    /// Return the stable workload tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ControlPlane => "control_plane",
            Self::DataPlane => "data_plane",
            Self::Background => "background",
            Self::AgentSwarm => "agent_swarm",
            Self::Unsupported(tag) => tag,
        }
    }

    /// Return `true` when this workload class is not supported by this schema version.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }

    fn from_tag(tag: &str) -> Self {
        match tag {
            "control_plane" => Self::ControlPlane,
            "data_plane" => Self::DataPlane,
            "background" => Self::Background,
            "agent_swarm" => Self::AgentSwarm,
            other => Self::Unsupported(other.to_string()),
        }
    }
}

impl Serialize for SloWorkloadClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SloWorkloadClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tag = String::deserialize(deserializer)?;
        Ok(Self::from_tag(&tag))
    }
}

/// Unit attached to a latency objective.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SloLatencyUnit {
    /// Millisecond objective values.
    Milliseconds,
    /// Microsecond objective values.
    Microseconds,
    /// Unsupported unit tag preserved for fail-closed validation.
    Unsupported(String),
}

impl SloLatencyUnit {
    /// Return the stable unit tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Milliseconds => "milliseconds",
            Self::Microseconds => "microseconds",
            Self::Unsupported(tag) => tag,
        }
    }

    /// Return `true` when this latency unit is not supported by this schema version.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }

    fn from_tag(tag: &str) -> Self {
        match tag {
            "milliseconds" => Self::Milliseconds,
            "microseconds" => Self::Microseconds,
            other => Self::Unsupported(other.to_string()),
        }
    }
}

impl Serialize for SloLatencyUnit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SloLatencyUnit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tag = String::deserialize(deserializer)?;
        Ok(Self::from_tag(&tag))
    }
}

/// Latency objective with monotonic percentile targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloLatencyObjective {
    /// Objective identifier unique within the policy bundle.
    pub objective_id: String,
    /// Unit for all percentile targets.
    pub unit: SloLatencyUnit,
    /// P50 target in the declared unit.
    pub p50: u64,
    /// P95 target in the declared unit.
    pub p95: u64,
    /// P99 target in the declared unit.
    pub p99: u64,
    /// P999 target in the declared unit.
    pub p999: u64,
}

/// Resource pressure thresholds that later compiler stages can map into admission policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloResourcePressureThresholds {
    /// Memory pressure limit in basis points.
    pub memory_basis_points: u16,
    /// File-descriptor pressure limit in basis points.
    pub fd_basis_points: u16,
    /// Maximum timer queue depth tolerated before policy fallback.
    pub timer_queue_depth: u64,
}

/// Optional work class and brownout order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloOptionalWorkClass {
    /// Stable optional work class identifier.
    pub class_id: String,
    /// Lower values brown out first.
    pub brownout_priority: u8,
    /// Human-readable degradation step.
    pub degradation_step: String,
}

/// Required no-win fallback declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloNoWinFallback {
    /// Fallback profile to pin when objectives cannot be satisfied.
    pub fallback_profile: String,
    /// Stable operator-facing reason.
    pub fallback_reason: String,
    /// Exact command expected to verify or reproduce the fallback proof.
    pub proof_command: String,
}

/// Provenance for a policy bundle and its backing profile evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyProvenance {
    /// Profile identifier supplied by the operator or planner.
    pub profile_id: String,
    /// Expected profile hash in `sha256:<64 lowercase hex>` form.
    pub profile_hash: String,
    /// Observed profile hash, if the bundle was produced from a concrete artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_profile_hash: Option<String>,
    /// Commit or source revision targeted by the policy.
    pub target_commit: String,
    /// Feature flags active for the policy.
    #[serde(default)]
    pub feature_flags: Vec<String>,
    /// Repo-relative source artifact, if file-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Related Beads issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_bead_id: Option<String>,
}

/// Redaction envelope for SLO policy bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyRedaction {
    /// Redaction policy identifier.
    pub policy_id: String,
    /// Whether the redaction pass completed.
    pub passed: bool,
}

/// Canonical SLO policy bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloPolicyBundle {
    /// Schema version. Must match [`SLO_POLICY_BUNDLE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable policy identifier.
    pub policy_id: String,
    /// Workload class.
    pub workload_class: SloWorkloadClass,
    /// Latency objectives with monotonic percentile targets.
    pub latency_objectives: Vec<SloLatencyObjective>,
    /// Cleanup deadline in milliseconds.
    pub cleanup_deadline_ms: u64,
    /// Maximum queue wait in milliseconds.
    pub max_queue_wait_ms: u64,
    /// Resource pressure thresholds.
    pub resource_pressure: SloResourcePressureThresholds,
    /// Optional work classes ordered by brownout priority.
    #[serde(default)]
    pub optional_work_classes: Vec<SloOptionalWorkClass>,
    /// Required fallback declaration when objectives cannot be satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_win_fallback: Option<SloNoWinFallback>,
    /// Provenance and evidence linkage.
    pub provenance: SloPolicyProvenance,
    /// Redaction status.
    pub redaction: SloPolicyRedaction,
    /// Additional deterministic metadata scanned for sensitive material.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// Capacity evidence consumed by the SLO policy compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyCapacityEvidence {
    /// Profile identifier this evidence certifies.
    pub profile_id: String,
    /// Profile hash in `sha256:<64 lowercase hex>` form.
    pub profile_hash: String,
    /// Workload class measured by the evidence.
    pub workload_class: SloWorkloadClass,
    /// Number of samples backing the evidence.
    pub sample_count: u32,
    /// Observed queue depth.
    pub queue_depth: u64,
    /// Observed memory pressure in basis points.
    pub memory_basis_points: u16,
    /// Observed file-descriptor pressure in basis points.
    pub fd_basis_points: u16,
    /// Observed timer queue depth.
    pub timer_queue_depth: u64,
}

impl SloPolicyCapacityEvidence {
    /// Compute a deterministic non-cryptographic fingerprint over the evidence JSON.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        fnv1a64(&bytes)
    }

    fn exceeds_thresholds(&self, bundle: &SloPolicyBundle) -> bool {
        self.queue_depth > bundle.resource_pressure.timer_queue_depth
            || self.memory_basis_points > bundle.resource_pressure.memory_basis_points
            || self.fd_basis_points > bundle.resource_pressure.fd_basis_points
            || self.timer_queue_depth > bundle.resource_pressure.timer_queue_depth
    }
}

/// Stable compiler outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloCompiledPolicyStatus {
    /// Policy compiled into executable Budget and admission projections.
    Compiled,
    /// Policy was valid, but available evidence proves the target cannot be met.
    NoWin,
    /// Policy compilation refused to produce an executable decision.
    Blocked,
}

impl SloCompiledPolicyStatus {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compiled => "compiled",
            Self::NoWin => "no_win",
            Self::Blocked => "blocked",
        }
    }
}

/// Stable compiler blocker kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloPolicyCompilerBlockerKind {
    /// The bundle failed validation as a whole.
    InvalidBundle,
    /// Latency, queue, or cleanup objectives cannot be satisfied.
    ImpossibleObjective,
    /// Capacity evidence is absent, stale, mismatched, or too weak to certify.
    MissingCapacityEvidence,
    /// The workload class is outside the compiler vocabulary.
    UnsupportedWorkloadClass,
    /// The fallback declaration is missing or conflicts with proof requirements.
    ConflictingFallbackDeclaration,
}

impl SloPolicyCompilerBlockerKind {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBundle => "invalid_bundle",
            Self::ImpossibleObjective => "impossible_objective",
            Self::MissingCapacityEvidence => "missing_capacity_evidence",
            Self::UnsupportedWorkloadClass => "unsupported_workload_class",
            Self::ConflictingFallbackDeclaration => "conflicting_fallback_declaration",
        }
    }
}

/// One compiler blocker attached to a blocked output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyCompilerBlocker {
    /// Blocker class.
    pub kind: SloPolicyCompilerBlockerKind,
    /// Source field associated with the blocker.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl SloPolicyCompilerBlocker {
    fn new(
        kind: SloPolicyCompilerBlockerKind,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Concrete Budget projection derived from a validated SLO bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledBudget {
    /// Cleanup deadline in milliseconds.
    pub cleanup_deadline_ms: u64,
    /// Cleanup deadline in nanoseconds for [`Budget`] construction.
    pub cleanup_deadline_ns: u64,
    /// Tightest p999 latency objective after unit normalization.
    pub p999_latency_budget_ms: u64,
    /// Queue wait threshold in milliseconds.
    pub max_queue_wait_ms: u64,
    /// Poll quota projected for cleanup/finalizer work.
    pub poll_quota: u32,
    /// Abstract cost quota projected from the latency target.
    pub cost_quota: u64,
    /// Scheduling priority projected from workload class.
    pub priority: u8,
}

impl SloCompiledBudget {
    /// Convert this projection into the runtime [`Budget`] type.
    #[must_use]
    pub fn to_budget(&self) -> Budget {
        Budget::with_deadline_ns(self.cleanup_deadline_ns)
            .with_poll_quota(self.poll_quota)
            .with_cost_quota(self.cost_quota)
            .with_priority(self.priority)
    }

    fn from_bundle(bundle: &SloPolicyBundle, p999_latency_budget_ms: u64) -> Self {
        let cleanup_deadline_ns = bundle.cleanup_deadline_ms.saturating_mul(1_000_000);
        let poll_quota = bundle
            .cleanup_deadline_ms
            .saturating_mul(4)
            .clamp(100, u64::from(u32::MAX)) as u32;
        let cost_quota = p999_latency_budget_ms
            .saturating_mul(100)
            .max(bundle.cleanup_deadline_ms);
        Self {
            cleanup_deadline_ms: bundle.cleanup_deadline_ms,
            cleanup_deadline_ns,
            p999_latency_budget_ms,
            max_queue_wait_ms: bundle.max_queue_wait_ms,
            poll_quota,
            cost_quota,
            priority: compiler_priority_for_workload(&bundle.workload_class),
        }
    }
}

/// Admission decision projected from SLO thresholds and capacity evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloCompiledAdmissionDecision {
    /// Work can be admitted under the supplied evidence.
    Admit,
    /// Optional work should brown out before admitting more load.
    Brownout,
    /// The evidence proves the policy cannot be satisfied.
    NoWin,
    /// The compiler refused to make an executable admission decision.
    Blocked,
}

impl SloCompiledAdmissionDecision {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Brownout => "brownout",
            Self::NoWin => "no_win",
            Self::Blocked => "blocked",
        }
    }
}

/// Admission threshold projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledAdmission {
    /// Queue wait threshold in milliseconds.
    pub queue_wait_threshold_ms: u64,
    /// Soft memory threshold in basis points.
    pub memory_soft_basis_points: u16,
    /// Hard memory threshold in basis points.
    pub memory_hard_basis_points: u16,
    /// Soft file-descriptor threshold in basis points.
    pub fd_soft_basis_points: u16,
    /// Hard file-descriptor threshold in basis points.
    pub fd_hard_basis_points: u16,
    /// Timer queue depth threshold.
    pub timer_queue_depth: u64,
    /// Observed queue depth from capacity evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_queue_depth: Option<u64>,
    /// Observed memory pressure from capacity evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_memory_basis_points: Option<u16>,
    /// Observed file-descriptor pressure from capacity evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_fd_basis_points: Option<u16>,
    /// Observed timer queue depth from capacity evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_timer_queue_depth: Option<u64>,
    /// Admission decision under the supplied evidence.
    pub decision: SloCompiledAdmissionDecision,
}

impl SloCompiledAdmission {
    fn from_bundle(
        bundle: &SloPolicyBundle,
        evidence: Option<&SloPolicyCapacityEvidence>,
        status: SloCompiledPolicyStatus,
    ) -> Self {
        let memory_soft_basis_points = bundle.resource_pressure.memory_basis_points;
        let fd_soft_basis_points = bundle.resource_pressure.fd_basis_points;
        let decision = match status {
            SloCompiledPolicyStatus::Compiled => SloCompiledAdmissionDecision::Admit,
            SloCompiledPolicyStatus::NoWin => SloCompiledAdmissionDecision::NoWin,
            SloCompiledPolicyStatus::Blocked => SloCompiledAdmissionDecision::Blocked,
        };
        Self {
            queue_wait_threshold_ms: bundle.max_queue_wait_ms,
            memory_soft_basis_points,
            memory_hard_basis_points: memory_soft_basis_points.saturating_add(500).min(10_000),
            fd_soft_basis_points,
            fd_hard_basis_points: fd_soft_basis_points.saturating_add(500).min(10_000),
            timer_queue_depth: bundle.resource_pressure.timer_queue_depth,
            evidence_queue_depth: evidence.map(|evidence| evidence.queue_depth),
            evidence_memory_basis_points: evidence.map(|evidence| evidence.memory_basis_points),
            evidence_fd_basis_points: evidence.map(|evidence| evidence.fd_basis_points),
            evidence_timer_queue_depth: evidence.map(|evidence| evidence.timer_queue_depth),
            decision,
        }
    }
}

/// Brownout stage vocabulary shared with capacity-envelope artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloCompiledBrownoutStage {
    /// No optional work gate is active.
    FullSurfaces,
    /// Optional work is degraded before core work is rejected.
    OptionalFirst,
    /// Priority-gated admission/shedding is active.
    PriorityGate,
    /// Conservative standalone fallback is active.
    StandaloneFallback,
}

impl SloCompiledBrownoutStage {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullSurfaces => "full_surfaces",
            Self::OptionalFirst => "optional_first",
            Self::PriorityGate => "priority_gate",
            Self::StandaloneFallback => "standalone_fallback",
        }
    }
}

/// One ordered optional-work brownout step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledBrownoutStep {
    /// Optional work class identifier.
    pub class_id: String,
    /// Lower values brown out first.
    pub brownout_priority: u8,
    /// Brownout stage that owns this degradation.
    pub stage: SloCompiledBrownoutStage,
    /// Human-readable degradation step.
    pub degradation_step: String,
}

/// No-win fallback receipt emitted by the compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledNoWinReceipt {
    /// Fallback profile selected by policy.
    pub fallback_profile: String,
    /// Declared operator-facing fallback reason.
    pub fallback_reason: String,
    /// Exact proof command attached to the fallback.
    pub proof_command: String,
    /// Compiler trigger that made the fallback necessary.
    pub triggered_by: String,
}

/// Provenance for a compiled SLO policy output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledPolicyProvenance {
    /// Fingerprint of the source policy bundle.
    pub policy_fingerprint: u64,
    /// Fingerprint of the capacity evidence, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_evidence_fingerprint: Option<u64>,
    /// Profile identifier carried from the source bundle.
    pub profile_id: String,
    /// Profile hash carried from the source bundle.
    pub profile_hash: String,
    /// Target commit carried from the source bundle.
    pub target_commit: String,
    /// Feature flags carried from the source bundle.
    pub feature_flags: Vec<String>,
    /// Related Beads issue carried from the source bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_bead_id: Option<String>,
}

/// Deterministic compiler output for Budget/admission policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloCompiledPolicy {
    /// Compiler schema version.
    pub compiler_schema_version: String,
    /// Source policy identifier.
    pub policy_id: String,
    /// Stable output identifier.
    pub output_id: String,
    /// Compile status.
    pub status: SloCompiledPolicyStatus,
    /// Budget projection.
    pub budget: SloCompiledBudget,
    /// Admission projection.
    pub admission: SloCompiledAdmission,
    /// Ordered optional-work brownout steps.
    pub brownout_order: Vec<SloCompiledBrownoutStep>,
    /// No-win fallback receipt, when the compiler proves fallback is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_win_fallback: Option<SloCompiledNoWinReceipt>,
    /// Typed blockers explaining why status is blocked.
    pub blockers: Vec<SloPolicyCompilerBlocker>,
    /// Provenance for proof reports.
    pub provenance: SloCompiledPolicyProvenance,
}

impl SloCompiledPolicy {
    /// Return `true` only when the output can drive runtime policy directly.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(self.status, SloCompiledPolicyStatus::Compiled)
    }
}

/// Runtime-facing decision produced by applying a compiled SLO policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloRuntimePolicyDecision {
    /// Admit core work under the compiled budget/admission projection.
    Admit,
    /// Admit core work only after optional work is browned out.
    Brownout,
    /// Reject the work at the admission boundary.
    Reject,
    /// Route work to an explicit no-win fallback receipt.
    NoWin,
    /// Refuse to apply policy because the compiled output is not executable.
    Blocked,
}

impl SloRuntimePolicyDecision {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Brownout => "brownout",
            Self::Reject => "reject",
            Self::NoWin => "no_win",
            Self::Blocked => "blocked",
        }
    }

    /// Return `true` when this is a complete runtime decision.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(
            self,
            Self::Admit | Self::Brownout | Self::Reject | Self::NoWin
        )
    }
}

/// Runtime action for one optional-work class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloRuntimeOptionalWorkDecision {
    /// Optional work may run normally.
    Run,
    /// Optional work is browned out before core work is rejected.
    Brownout,
}

impl SloRuntimeOptionalWorkDecision {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Brownout => "brownout",
        }
    }
}

/// Runtime application row for one optional-work class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimeOptionalWorkApplication {
    /// Optional work class identifier.
    pub class_id: String,
    /// Lower values brown out first.
    pub brownout_priority: u8,
    /// Brownout stage inherited from the compiled policy.
    pub stage: SloCompiledBrownoutStage,
    /// Runtime action for this optional work class.
    pub decision: SloRuntimeOptionalWorkDecision,
    /// Human-readable degradation step.
    pub degradation_step: String,
}

/// Provenance carried into a runtime SLO policy application decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimePolicyApplicationProvenance {
    /// Fingerprint of the source policy bundle.
    pub policy_fingerprint: u64,
    /// Fingerprint of capacity evidence, if supplied to the compiler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_evidence_fingerprint: Option<u64>,
    /// Profile identifier carried from the compiled policy.
    pub profile_id: String,
    /// Declared profile hash in `sha256:<64 lowercase hex>` form.
    pub profile_hash: String,
    /// Observed profile hash at the runtime application boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_profile_hash: Option<String>,
    /// Target commit or source revision.
    pub target_commit: String,
    /// Related Beads issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_bead_id: Option<String>,
}

/// Runtime-facing application of one compiled SLO policy output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloRuntimePolicyApplication {
    /// Runtime application schema version.
    pub schema_version: String,
    /// Compiler schema version consumed by this application.
    pub compiler_schema_version: String,
    /// Source policy identifier.
    pub policy_id: String,
    /// Stable compiled policy output identifier.
    pub compiled_output_id: String,
    /// Compiled policy status.
    pub compiled_status: SloCompiledPolicyStatus,
    /// Runtime workload class selected by the caller.
    pub workload_class: SloWorkloadClass,
    /// Runtime decision made from the compiled policy.
    pub decision: SloRuntimePolicyDecision,
    /// Budget projection supplied to admission/runtime seams.
    pub budget: SloCompiledBudget,
    /// Admission projection supplied to runtime seams.
    pub admission: SloCompiledAdmission,
    /// Optional-work decisions supplied to brownout seams.
    #[serde(default)]
    pub optional_work_decisions: Vec<SloRuntimeOptionalWorkApplication>,
    /// No-win fallback receipt, required for `no_win` decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_win_fallback: Option<SloCompiledNoWinReceipt>,
    /// Provenance and freshness evidence.
    pub provenance: SloRuntimePolicyApplicationProvenance,
    /// Exact proof command for this application contract.
    pub proof_command: SloProofCommand,
    /// Redaction status.
    pub redaction: SloPolicyRedaction,
    /// Additional deterministic metadata scanned for sensitive material.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// Runtime application fail-closed issue vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloRuntimePolicyApplicationIssueKind {
    /// The application JSON did not parse.
    MalformedApplication,
    /// The runtime application or compiler schema version is unsupported.
    UnsupportedSchemaVersion,
    /// A required field is missing or empty.
    MissingRequiredField,
    /// A proof command omitted the required `rch exec` routing.
    MissingRchCommand,
    /// Declared and observed profile hashes do not match.
    StaleProfileHash,
    /// Workload class is outside the supported runtime vocabulary.
    UnsupportedWorkloadClass,
    /// Compiled policy output is missing or blocked.
    MissingCompiledOutput,
    /// A no-win decision omitted the required fallback receipt.
    MissingNoWinReceipt,
    /// Redaction failed.
    RedactionFailure,
    /// Secret-like material was found in metadata or command fields.
    SecretLikeMaterial,
    /// Text field exceeds deterministic size limits.
    OversizedField,
}

impl SloRuntimePolicyApplicationIssueKind {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedApplication => "malformed_application",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::MissingRequiredField => "missing_required_field",
            Self::MissingRchCommand => "missing_rch_command",
            Self::StaleProfileHash => "stale_profile_hash",
            Self::UnsupportedWorkloadClass => "unsupported_workload_class",
            Self::MissingCompiledOutput => "missing_compiled_output",
            Self::MissingNoWinReceipt => "missing_no_win_receipt",
            Self::RedactionFailure => "redaction_failure",
            Self::SecretLikeMaterial => "secret_like_material",
            Self::OversizedField => "oversized_field",
        }
    }
}

/// One runtime policy application validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimePolicyApplicationIssue {
    /// Issue class.
    pub kind: SloRuntimePolicyApplicationIssueKind,
    /// Field associated with the issue.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl SloRuntimePolicyApplicationIssue {
    fn new(
        kind: SloRuntimePolicyApplicationIssueKind,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Fail-closed runtime policy application validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimePolicyApplicationValidation {
    /// Whether the runtime application can drive admission/brownout/no-win seams.
    pub accepted: bool,
    /// Runtime decision observed in the application.
    pub decision: SloRuntimePolicyDecision,
    /// Source policy identifier.
    pub policy_id: String,
    /// Stable compiled output identifier.
    pub compiled_output_id: String,
    /// Validation issues.
    pub issues: Vec<SloRuntimePolicyApplicationIssue>,
}

impl SloRuntimePolicyApplicationValidation {
    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_issue(&self, kind: SloRuntimePolicyApplicationIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Runtime admission request evidence supplied explicitly by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimeAdmissionRequest {
    /// Stable request or work-unit identifier.
    pub request_id: String,
    /// Number of work units represented by this request.
    pub work_units: u64,
    /// Optional work class, if this request is degradable optional work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_work_class: Option<String>,
    /// Current queue wait estimate in milliseconds.
    pub queue_wait_ms: u64,
    /// Current memory pressure in basis points.
    pub memory_basis_points: u16,
    /// Current file-descriptor pressure in basis points.
    pub fd_basis_points: u16,
    /// Current timer queue depth.
    pub timer_queue_depth: u64,
    /// Whether cancellation was already requested while admission was pending.
    pub cancel_requested: bool,
}

/// Runtime admission outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloRuntimeAdmissionStatus {
    /// Core work was admitted.
    Admitted,
    /// Work was rejected at the admission boundary.
    Rejected,
    /// Optional work was browned out before core work was rejected.
    Brownout,
    /// The request was routed to a no-win fallback receipt.
    NoWin,
    /// Admission was blocked by invalid or stale policy evidence.
    Blocked,
}

impl SloRuntimeAdmissionStatus {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
            Self::Brownout => "brownout",
            Self::NoWin => "no_win",
            Self::Blocked => "blocked",
        }
    }
}

/// Runtime admission issue/outcome reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloRuntimeAdmissionIssueKind {
    /// The runtime policy application failed validation.
    ApplicationInvalid,
    /// Admission was cancelled before work was started.
    Cancelled,
    /// Queue wait exceeded the compiled threshold.
    QueueWaitExceeded,
    /// Memory pressure exceeded the compiled hard threshold.
    MemoryPressureExceeded,
    /// File-descriptor pressure exceeded the compiled hard threshold.
    FdPressureExceeded,
    /// Timer queue depth exceeded the compiled threshold.
    TimerQueueExceeded,
    /// Optional work class was not declared by the compiled policy.
    UnsupportedOptionalWorkClass,
    /// Optional work was browned out.
    OptionalWorkBrownout,
    /// No-win fallback receipt was selected.
    NoWinFallback,
}

impl SloRuntimeAdmissionIssueKind {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationInvalid => "application_invalid",
            Self::Cancelled => "cancelled",
            Self::QueueWaitExceeded => "queue_wait_exceeded",
            Self::MemoryPressureExceeded => "memory_pressure_exceeded",
            Self::FdPressureExceeded => "fd_pressure_exceeded",
            Self::TimerQueueExceeded => "timer_queue_exceeded",
            Self::UnsupportedOptionalWorkClass => "unsupported_optional_work_class",
            Self::OptionalWorkBrownout => "optional_work_brownout",
            Self::NoWinFallback => "no_win_fallback",
        }
    }
}

/// Deterministic runtime admission/brownout/no-win evidence row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloRuntimeAdmissionOutcome {
    /// Stable request or work-unit identifier.
    pub request_id: String,
    /// Admission outcome status.
    pub status: SloRuntimeAdmissionStatus,
    /// Source policy identifier.
    pub policy_id: String,
    /// Workload class covered by the policy application.
    pub workload_class: SloWorkloadClass,
    /// Runtime policy decision that drove this outcome.
    pub decision: SloRuntimePolicyDecision,
    /// Optional work class, if evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_work_class: Option<String>,
    /// Optional work action, if evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_work_decision: Option<SloRuntimeOptionalWorkDecision>,
    /// Fallback reason, when status is `no_win`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Declared profile hash attached to the policy application.
    pub profile_hash: String,
    /// Exact rch-routed proof command attached to the application.
    pub proof_command: String,
    /// Cleanup/runtime budget projection used for admitted work.
    pub budget: SloCompiledBudget,
    /// Number of work units admitted.
    pub admitted_work_units: u64,
    /// Number of work units rejected, browned out, blocked, or routed away.
    pub rejected_work_units: u64,
    /// Machine-readable issue/outcome reason tags.
    #[serde(default)]
    pub issue_kinds: Vec<SloRuntimeAdmissionIssueKind>,
}

impl SloRuntimePolicyApplication {
    /// Build a runtime application payload from a compiled policy output.
    #[must_use]
    pub fn from_compiled_policy(
        compiled: &SloCompiledPolicy,
        workload_class: SloWorkloadClass,
        observed_profile_hash: Option<String>,
        proof_command: SloProofCommand,
        redaction: SloPolicyRedaction,
    ) -> Self {
        let decision = runtime_decision_for_compiled_policy(compiled);
        let optional_work_decisions = compiled
            .brownout_order
            .iter()
            .map(|step| SloRuntimeOptionalWorkApplication {
                class_id: step.class_id.clone(),
                brownout_priority: step.brownout_priority,
                stage: step.stage,
                decision: optional_work_decision_for_runtime_decision(decision),
                degradation_step: step.degradation_step.clone(),
            })
            .collect();

        Self {
            schema_version: SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION.to_string(),
            compiler_schema_version: compiled.compiler_schema_version.clone(),
            policy_id: compiled.policy_id.clone(),
            compiled_output_id: compiled.output_id.clone(),
            compiled_status: compiled.status,
            workload_class,
            decision,
            budget: compiled.budget.clone(),
            admission: compiled.admission.clone(),
            optional_work_decisions,
            no_win_fallback: compiled.no_win_fallback.clone(),
            provenance: SloRuntimePolicyApplicationProvenance {
                policy_fingerprint: compiled.provenance.policy_fingerprint,
                capacity_evidence_fingerprint: compiled.provenance.capacity_evidence_fingerprint,
                profile_id: compiled.provenance.profile_id.clone(),
                profile_hash: compiled.provenance.profile_hash.clone(),
                observed_profile_hash,
                target_commit: compiled.provenance.target_commit.clone(),
                related_bead_id: compiled.provenance.related_bead_id.clone(),
            },
            proof_command,
            redaction,
            metadata: BTreeMap::new(),
        }
    }

    /// Parse a runtime policy application from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize this application to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render the targeted proof command for runtime application contract tests.
    #[must_use]
    pub fn render_application_proof_command(test_filter: &str) -> String {
        let filter = if test_filter.is_empty() {
            "runtime_slo_policy_application"
        } else {
            test_filter
        };
        format!(
            "rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_slo_runtime_application cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals {filter} -- --nocapture"
        )
    }

    /// Validate this runtime application with fail-closed semantics.
    #[must_use]
    pub fn validate(&self) -> SloRuntimePolicyApplicationValidation {
        let mut issues = Vec::new();
        if self.schema_version != SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::UnsupportedSchemaVersion,
                "schema_version",
                format!(
                    "unsupported runtime application schema {}, expected {SLO_POLICY_RUNTIME_APPLICATION_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        if self.compiler_schema_version != SLO_POLICY_COMPILER_SCHEMA_VERSION {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::UnsupportedSchemaVersion,
                "compiler_schema_version",
                format!(
                    "unsupported compiler schema {}, expected {SLO_POLICY_COMPILER_SCHEMA_VERSION}",
                    self.compiler_schema_version
                ),
            ));
        }
        validate_runtime_required_text("policy_id", &self.policy_id, MAX_ID_BYTES, &mut issues);
        validate_runtime_required_text(
            "compiled_output_id",
            &self.compiled_output_id,
            MAX_FIELD_BYTES,
            &mut issues,
        );
        if self.workload_class.is_unsupported() {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::UnsupportedWorkloadClass,
                "workload_class",
                format!(
                    "unsupported workload class {}",
                    self.workload_class.as_str()
                ),
            ));
        }
        if self.compiled_output_id.is_empty()
            || self.compiled_status == SloCompiledPolicyStatus::Blocked
            || self.decision == SloRuntimePolicyDecision::Blocked
        {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::MissingCompiledOutput,
                "compiled_output_id",
                "compiled policy output is missing or blocked",
            ));
        }
        self.validate_runtime_provenance(&mut issues);
        self.validate_runtime_optional_work(&mut issues);
        self.validate_runtime_no_win_receipt(&mut issues);
        self.validate_runtime_proof_command(&mut issues);
        self.validate_runtime_redaction(&mut issues);
        scan_runtime_json_map("metadata", &self.metadata, &mut issues);

        SloRuntimePolicyApplicationValidation {
            accepted: self.decision.is_complete() && issues.is_empty(),
            decision: self.decision,
            policy_id: self.policy_id.clone(),
            compiled_output_id: self.compiled_output_id.clone(),
            issues,
        }
    }

    /// Evaluate a runtime admission request against this explicit policy application.
    #[must_use]
    pub fn evaluate_admission(
        &self,
        request: &SloRuntimeAdmissionRequest,
    ) -> SloRuntimeAdmissionOutcome {
        let validation = self.validate();
        if !validation.accepted {
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::Blocked,
                None,
                None,
                vec![SloRuntimeAdmissionIssueKind::ApplicationInvalid],
                0,
            );
        }

        if request.cancel_requested {
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::Rejected,
                None,
                None,
                vec![SloRuntimeAdmissionIssueKind::Cancelled],
                0,
            );
        }

        if self.decision == SloRuntimePolicyDecision::NoWin {
            let fallback_reason = self
                .no_win_fallback
                .as_ref()
                .map(|fallback| fallback.fallback_reason.clone());
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::NoWin,
                None,
                fallback_reason,
                vec![SloRuntimeAdmissionIssueKind::NoWinFallback],
                0,
            );
        }

        if self.decision == SloRuntimePolicyDecision::Reject {
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::Rejected,
                None,
                None,
                vec![SloRuntimeAdmissionIssueKind::ApplicationInvalid],
                0,
            );
        }

        let hard_rejection = self.hard_rejection_issue(request);
        if let Some(issue) = hard_rejection {
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::Rejected,
                None,
                None,
                vec![issue],
                0,
            );
        }

        if let Some(optional_class) = &request.optional_work_class {
            let optional_work = self
                .optional_work_decisions
                .iter()
                .find(|work| work.class_id == *optional_class);
            let Some(optional_work) = optional_work else {
                return self.admission_outcome(
                    request,
                    SloRuntimeAdmissionStatus::Rejected,
                    None,
                    None,
                    vec![SloRuntimeAdmissionIssueKind::UnsupportedOptionalWorkClass],
                    0,
                );
            };
            if optional_work.decision == SloRuntimeOptionalWorkDecision::Brownout
                || self.soft_brownout_pressure(request)
            {
                return self.admission_outcome(
                    request,
                    SloRuntimeAdmissionStatus::Brownout,
                    Some(SloRuntimeOptionalWorkDecision::Brownout),
                    None,
                    vec![SloRuntimeAdmissionIssueKind::OptionalWorkBrownout],
                    0,
                );
            }
            return self.admission_outcome(
                request,
                SloRuntimeAdmissionStatus::Admitted,
                Some(SloRuntimeOptionalWorkDecision::Run),
                None,
                Vec::new(),
                request.work_units,
            );
        }

        self.admission_outcome(
            request,
            SloRuntimeAdmissionStatus::Admitted,
            None,
            None,
            Vec::new(),
            request.work_units,
        )
    }

    fn hard_rejection_issue(
        &self,
        request: &SloRuntimeAdmissionRequest,
    ) -> Option<SloRuntimeAdmissionIssueKind> {
        if request.queue_wait_ms > self.admission.queue_wait_threshold_ms {
            return Some(SloRuntimeAdmissionIssueKind::QueueWaitExceeded);
        }
        if request.memory_basis_points > self.admission.memory_hard_basis_points {
            return Some(SloRuntimeAdmissionIssueKind::MemoryPressureExceeded);
        }
        if request.fd_basis_points > self.admission.fd_hard_basis_points {
            return Some(SloRuntimeAdmissionIssueKind::FdPressureExceeded);
        }
        if request.timer_queue_depth > self.admission.timer_queue_depth {
            return Some(SloRuntimeAdmissionIssueKind::TimerQueueExceeded);
        }
        None
    }

    fn soft_brownout_pressure(&self, request: &SloRuntimeAdmissionRequest) -> bool {
        request.memory_basis_points >= self.admission.memory_soft_basis_points
            || request.fd_basis_points >= self.admission.fd_soft_basis_points
            || request.timer_queue_depth >= self.admission.timer_queue_depth
            || request.queue_wait_ms >= self.admission.queue_wait_threshold_ms
    }

    fn admission_outcome(
        &self,
        request: &SloRuntimeAdmissionRequest,
        status: SloRuntimeAdmissionStatus,
        optional_work_decision: Option<SloRuntimeOptionalWorkDecision>,
        fallback_reason: Option<String>,
        issue_kinds: Vec<SloRuntimeAdmissionIssueKind>,
        admitted_work_units: u64,
    ) -> SloRuntimeAdmissionOutcome {
        SloRuntimeAdmissionOutcome {
            request_id: request.request_id.clone(),
            status,
            policy_id: self.policy_id.clone(),
            workload_class: self.workload_class.clone(),
            decision: self.decision,
            optional_work_class: request.optional_work_class.clone(),
            optional_work_decision,
            fallback_reason,
            profile_hash: self.provenance.profile_hash.clone(),
            proof_command: self.proof_command.command.clone(),
            budget: self.budget.clone(),
            admitted_work_units,
            rejected_work_units: request.work_units.saturating_sub(admitted_work_units),
            issue_kinds,
        }
    }

    fn validate_runtime_provenance(&self, issues: &mut Vec<SloRuntimePolicyApplicationIssue>) {
        validate_runtime_required_text(
            "provenance.profile_id",
            &self.provenance.profile_id,
            MAX_ID_BYTES,
            issues,
        );
        validate_runtime_content_hash(
            "provenance.profile_hash",
            &self.provenance.profile_hash,
            issues,
        );
        let Some(observed) = &self.provenance.observed_profile_hash else {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
                "provenance.observed_profile_hash",
                "runtime application requires observed profile hash freshness evidence",
            ));
            return;
        };
        validate_runtime_content_hash("provenance.observed_profile_hash", observed, issues);
        if observed != &self.provenance.profile_hash {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
                "provenance.observed_profile_hash",
                "observed profile hash does not match declared profile hash",
            ));
        }
        validate_runtime_required_text(
            "provenance.target_commit",
            &self.provenance.target_commit,
            MAX_FIELD_BYTES,
            issues,
        );
        if let Some(bead) = &self.provenance.related_bead_id {
            validate_runtime_text_size("provenance.related_bead_id", bead, MAX_ID_BYTES, issues);
        }
    }

    fn validate_runtime_optional_work(&self, issues: &mut Vec<SloRuntimePolicyApplicationIssue>) {
        let mut seen = BTreeSet::new();
        for (index, work) in self.optional_work_decisions.iter().enumerate() {
            let prefix = format!("optional_work_decisions[{index}]");
            validate_runtime_required_text(
                format!("{prefix}.class_id"),
                &work.class_id,
                MAX_ID_BYTES,
                issues,
            );
            validate_runtime_required_text(
                format!("{prefix}.degradation_step"),
                &work.degradation_step,
                MAX_FIELD_BYTES,
                issues,
            );
            if !work.class_id.is_empty() && !seen.insert(work.class_id.as_str()) {
                issues.push(SloRuntimePolicyApplicationIssue::new(
                    SloRuntimePolicyApplicationIssueKind::MissingRequiredField,
                    format!("{prefix}.class_id"),
                    format!("duplicate optional work class {}", work.class_id),
                ));
            }
        }
    }

    fn validate_runtime_no_win_receipt(&self, issues: &mut Vec<SloRuntimePolicyApplicationIssue>) {
        if self.compiled_status != SloCompiledPolicyStatus::NoWin
            && self.decision != SloRuntimePolicyDecision::NoWin
        {
            return;
        }
        let Some(receipt) = &self.no_win_fallback else {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::MissingNoWinReceipt,
                "no_win_fallback",
                "no-win runtime applications must include a fallback receipt",
            ));
            return;
        };
        validate_runtime_required_text(
            "no_win_fallback.fallback_profile",
            &receipt.fallback_profile,
            MAX_ID_BYTES,
            issues,
        );
        validate_runtime_required_text(
            "no_win_fallback.fallback_reason",
            &receipt.fallback_reason,
            MAX_FIELD_BYTES,
            issues,
        );
        validate_runtime_required_text(
            "no_win_fallback.proof_command",
            &receipt.proof_command,
            MAX_FIELD_BYTES,
            issues,
        );
        if !receipt.proof_command.contains("rch exec")
            || !cargo_proof_command_has_target_dir(&receipt.proof_command)
        {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::MissingRchCommand,
                "no_win_fallback.proof_command",
                "no-win receipt cargo proof command must be routed through rch exec -- env with CARGO_TARGET_DIR",
            ));
        }
    }

    fn validate_runtime_proof_command(&self, issues: &mut Vec<SloRuntimePolicyApplicationIssue>) {
        validate_runtime_required_text(
            "proof_command.label",
            &self.proof_command.label,
            MAX_ID_BYTES,
            issues,
        );
        validate_runtime_required_text(
            "proof_command.command",
            &self.proof_command.command,
            MAX_FIELD_BYTES,
            issues,
        );
        if !self.proof_command.command.contains("rch exec")
            || !cargo_proof_command_has_target_dir(&self.proof_command.command)
        {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::MissingRchCommand,
                "proof_command.command",
                "runtime application cargo proof command must be routed through rch exec -- env with CARGO_TARGET_DIR",
            ));
        }
    }

    fn validate_runtime_redaction(&self, issues: &mut Vec<SloRuntimePolicyApplicationIssue>) {
        validate_runtime_required_text(
            "redaction.policy_id",
            &self.redaction.policy_id,
            MAX_ID_BYTES,
            issues,
        );
        if !self.redaction.passed {
            issues.push(SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::RedactionFailure,
                "redaction.passed",
                "runtime application redaction pass must be true",
            ));
        }
    }
}

/// Parse and validate a runtime policy application JSON document.
#[must_use]
pub fn validate_slo_runtime_policy_application_json(
    json: &str,
) -> SloRuntimePolicyApplicationValidation {
    match serde_json::from_str::<SloRuntimePolicyApplication>(json) {
        Ok(application) => application.validate(),
        Err(error) => SloRuntimePolicyApplicationValidation {
            accepted: false,
            decision: SloRuntimePolicyDecision::Blocked,
            policy_id: String::new(),
            compiled_output_id: String::new(),
            issues: vec![SloRuntimePolicyApplicationIssue::new(
                SloRuntimePolicyApplicationIssueKind::MalformedApplication,
                "$",
                format!("SLO runtime policy application JSON did not parse: {error}"),
            )],
        },
    }
}

/// Operator-facing proof-report status vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloProofReportStatus {
    /// All required proof lanes passed and no degradation/no-win caveat applies.
    Pass,
    /// A proof lane or artifact invariant failed.
    Fail,
    /// The report is blocked before an executable decision can be made.
    Blocked,
    /// The policy is admitted only with explicit degradation/brownout.
    Degraded,
    /// The report proves a no-win fallback path with a receipt.
    NoWin,
    /// The report is for an unsupported workload/status lane.
    Unsupported,
    /// The report evidence is stale relative to the declared profile hash.
    StaleEvidence,
}

impl SloProofReportStatus {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Blocked => "blocked",
            Self::Degraded => "degraded",
            Self::NoWin => "no_win",
            Self::Unsupported => "unsupported",
            Self::StaleEvidence => "stale_evidence",
        }
    }

    /// Return `true` only for full success. Degraded and no-win are accepted
    /// gate outcomes only when their receipts are complete, but they are not success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Return `true` when the CI/report gate can accept the status if the
    /// report has no validation issues.
    #[must_use]
    pub const fn is_gate_acceptable(self) -> bool {
        matches!(self, Self::Pass | Self::Degraded | Self::NoWin)
    }
}

/// Proof-report fail-closed issue vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloProofReportIssueKind {
    /// The report JSON did not parse.
    MalformedReport,
    /// The proof report schema version is unsupported.
    UnsupportedSchemaVersion,
    /// A required report field is missing or empty.
    MissingRequiredField,
    /// A proof command omitted the required `rch exec` routing.
    MissingRchCommand,
    /// Declared and observed profile hashes do not match.
    StaleProfileHash,
    /// A no-win report omitted the required receipt.
    MissingNoWinReceipt,
    /// Redaction failed.
    RedactionFailure,
    /// Secret-like material was found in report text, metadata, or commands.
    SecretLikeMaterial,
    /// The report status is not an acceptable direct-main gate outcome.
    NonPassingStatus,
    /// Text field exceeds deterministic size limits.
    OversizedField,
}

impl SloProofReportIssueKind {
    /// Return the stable artifact tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedReport => "malformed_report",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::MissingRequiredField => "missing_required_field",
            Self::MissingRchCommand => "missing_rch_command",
            Self::StaleProfileHash => "stale_profile_hash",
            Self::MissingNoWinReceipt => "missing_no_win_receipt",
            Self::RedactionFailure => "redaction_failure",
            Self::SecretLikeMaterial => "secret_like_material",
            Self::NonPassingStatus => "non_passing_status",
            Self::OversizedField => "oversized_field",
        }
    }
}

/// Exact command rendered into an operator proof report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofCommand {
    /// Stable command label.
    pub label: String,
    /// Exact command string. Cargo-heavy commands must be routed through `rch exec`.
    pub command: String,
}

/// Provenance for an operator proof report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofReportProvenance {
    /// Profile identifier the proof report covers.
    pub profile_id: String,
    /// Declared profile hash in `sha256:<64 lowercase hex>` form.
    pub profile_hash: String,
    /// Observed profile hash from the latest evidence bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_profile_hash: Option<String>,
    /// Target commit or source revision.
    pub target_commit: String,
    /// Related Beads issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_bead_id: Option<String>,
}

/// No-win receipt required when a proof report status is `no_win`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofNoWinReceipt {
    /// Fallback profile selected by policy.
    pub fallback_profile: String,
    /// Operator-facing fallback reason.
    pub fallback_reason: String,
    /// Exact rch-routed proof command for the fallback receipt.
    pub proof_command: String,
}

/// One machine-readable row in an operator proof report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofReportRow {
    /// Stable row identifier.
    pub row_id: String,
    /// Row status.
    pub status: SloProofReportStatus,
    /// Evidence pointer or artifact path.
    pub evidence_ref: String,
    /// Concise row summary.
    pub summary: String,
}

/// Operator-facing SLO proof report and opt-in gate payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SloProofReport {
    /// Proof report schema version.
    pub schema_version: String,
    /// Stable report id.
    pub report_id: String,
    /// Source policy id.
    pub policy_id: String,
    /// Overall report status.
    pub status: SloProofReportStatus,
    /// Concise human summary.
    pub human_summary: String,
    /// Provenance and evidence freshness.
    pub provenance: SloProofReportProvenance,
    /// Exact proof commands represented by this report.
    #[serde(default)]
    pub proof_commands: Vec<SloProofCommand>,
    /// Required no-win receipt when status is `no_win`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_win_receipt: Option<SloProofNoWinReceipt>,
    /// Machine-readable report rows for aggregate proof packs.
    #[serde(default)]
    pub rows: Vec<SloProofReportRow>,
    /// Redaction status.
    pub redaction: SloPolicyRedaction,
    /// Additional deterministic metadata scanned for sensitive material.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// One proof-report validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofReportIssue {
    /// Issue class.
    pub kind: SloProofReportIssueKind,
    /// Field associated with the issue.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl SloProofReportIssue {
    fn new(
        kind: SloProofReportIssueKind,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Fail-closed proof-report validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofReportValidation {
    /// Whether the report is accepted by the opt-in gate.
    pub accepted: bool,
    /// Overall report status.
    pub status: SloProofReportStatus,
    /// Whether the report status is success, not merely accepted.
    pub success: bool,
    /// Whether the status is gate-acceptable before issue checks.
    pub gate_acceptable_status: bool,
    /// Stable report id.
    pub report_id: String,
    /// Source policy id.
    pub policy_id: String,
    /// Validation issues.
    pub issues: Vec<SloProofReportIssue>,
}

impl SloProofReportValidation {
    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_issue(&self, kind: SloProofReportIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Aggregate counts by proof-report status.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloProofReportStatusCounts {
    /// Fully passing reports.
    pub pass: u64,
    /// Failing reports.
    pub fail: u64,
    /// Blocked reports.
    pub blocked: u64,
    /// Degraded but accepted reports.
    pub degraded: u64,
    /// No-win fallback reports.
    pub no_win: u64,
    /// Unsupported reports.
    pub unsupported: u64,
    /// Stale-evidence reports.
    pub stale_evidence: u64,
}

impl SloProofReportStatusCounts {
    /// Add one status to the aggregate.
    pub fn record(&mut self, status: SloProofReportStatus) {
        match status {
            SloProofReportStatus::Pass => self.pass += 1,
            SloProofReportStatus::Fail => self.fail += 1,
            SloProofReportStatus::Blocked => self.blocked += 1,
            SloProofReportStatus::Degraded => self.degraded += 1,
            SloProofReportStatus::NoWin => self.no_win += 1,
            SloProofReportStatus::Unsupported => self.unsupported += 1,
            SloProofReportStatus::StaleEvidence => self.stale_evidence += 1,
        }
    }

    /// Total reports counted.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.pass
            + self.fail
            + self.blocked
            + self.degraded
            + self.no_win
            + self.unsupported
            + self.stale_evidence
    }
}

impl SloProofReport {
    /// Parse a proof report from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize this report to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render the deterministic opt-in CI gate command for this report lane.
    #[must_use]
    pub fn render_ci_gate_command(output_root: &str, run_id: &str) -> String {
        format!(
            "rch exec -- bash scripts/validate_slo_policy_bundle.sh --output-root {output_root} --run-id {run_id}"
        )
    }

    /// Validate this proof report with fail-closed gate semantics.
    #[must_use]
    pub fn validate(&self) -> SloProofReportValidation {
        let mut issues = Vec::new();
        if self.schema_version != SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::UnsupportedSchemaVersion,
                "schema_version",
                format!(
                    "unsupported proof report schema {}, expected {SLO_POLICY_PROOF_REPORT_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_proof_required_text("report_id", &self.report_id, MAX_ID_BYTES, &mut issues);
        validate_proof_required_text("policy_id", &self.policy_id, MAX_ID_BYTES, &mut issues);
        validate_proof_required_text(
            "human_summary",
            &self.human_summary,
            MAX_FIELD_BYTES,
            &mut issues,
        );
        self.validate_proof_provenance(&mut issues);
        self.validate_proof_commands(&mut issues);
        self.validate_no_win_receipt(&mut issues);
        self.validate_rows(&mut issues);
        self.validate_summary_status(&mut issues);
        self.validate_report_redaction(&mut issues);
        scan_proof_json_map("metadata", &self.metadata, &mut issues);

        if !self.status.is_gate_acceptable() {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::NonPassingStatus,
                "status",
                "proof report status is not accepted by the opt-in gate",
            ));
        }
        let accepted = self.status.is_gate_acceptable() && issues.is_empty();
        SloProofReportValidation {
            accepted,
            status: self.status,
            success: self.status.is_success() && issues.is_empty(),
            gate_acceptable_status: self.status.is_gate_acceptable(),
            report_id: self.report_id.clone(),
            policy_id: self.policy_id.clone(),
            issues,
        }
    }

    fn validate_proof_provenance(&self, issues: &mut Vec<SloProofReportIssue>) {
        validate_proof_required_text(
            "provenance.profile_id",
            &self.provenance.profile_id,
            MAX_ID_BYTES,
            issues,
        );
        validate_proof_content_hash(
            "provenance.profile_hash",
            &self.provenance.profile_hash,
            issues,
        );
        if let Some(observed) = &self.provenance.observed_profile_hash {
            validate_proof_content_hash("provenance.observed_profile_hash", observed, issues);
            if observed != &self.provenance.profile_hash {
                issues.push(SloProofReportIssue::new(
                    SloProofReportIssueKind::StaleProfileHash,
                    "provenance.observed_profile_hash",
                    "observed profile hash does not match declared profile hash",
                ));
            }
        }
        validate_proof_required_text(
            "provenance.target_commit",
            &self.provenance.target_commit,
            MAX_FIELD_BYTES,
            issues,
        );
        if let Some(bead) = &self.provenance.related_bead_id {
            validate_proof_text_size("provenance.related_bead_id", bead, MAX_ID_BYTES, issues);
        }
        if self.status == SloProofReportStatus::StaleEvidence {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::StaleProfileHash,
                "status",
                "stale_evidence status is not accepted by the opt-in gate",
            ));
        }
    }

    fn validate_proof_commands(&self, issues: &mut Vec<SloProofReportIssue>) {
        if self.proof_commands.is_empty() {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingRequiredField,
                "proof_commands",
                "proof report must include at least one exact proof command",
            ));
        }
        for (index, command) in self.proof_commands.iter().enumerate() {
            let prefix = format!("proof_commands[{index}]");
            validate_proof_required_text(
                format!("{prefix}.label"),
                &command.label,
                MAX_ID_BYTES,
                issues,
            );
            validate_proof_required_text(
                format!("{prefix}.command"),
                &command.command,
                MAX_FIELD_BYTES,
                issues,
            );
            if !command.command.contains("rch exec")
                || !cargo_proof_command_has_target_dir(&command.command)
            {
                issues.push(SloProofReportIssue::new(
                    SloProofReportIssueKind::MissingRchCommand,
                    format!("{prefix}.command"),
                    "cargo proof command must be routed through rch exec -- env with CARGO_TARGET_DIR",
                ));
            }
        }
    }

    fn validate_no_win_receipt(&self, issues: &mut Vec<SloProofReportIssue>) {
        if self.status != SloProofReportStatus::NoWin {
            return;
        }
        let Some(receipt) = &self.no_win_receipt else {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingNoWinReceipt,
                "no_win_receipt",
                "no_win reports must include a fallback receipt",
            ));
            return;
        };
        validate_proof_required_text(
            "no_win_receipt.fallback_profile",
            &receipt.fallback_profile,
            MAX_ID_BYTES,
            issues,
        );
        validate_proof_required_text(
            "no_win_receipt.fallback_reason",
            &receipt.fallback_reason,
            MAX_FIELD_BYTES,
            issues,
        );
        validate_proof_required_text(
            "no_win_receipt.proof_command",
            &receipt.proof_command,
            MAX_FIELD_BYTES,
            issues,
        );
        if !receipt.proof_command.contains("rch exec")
            || !cargo_proof_command_has_target_dir(&receipt.proof_command)
        {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingRchCommand,
                "no_win_receipt.proof_command",
                "no-win receipt cargo proof command must be routed through rch exec -- env with CARGO_TARGET_DIR",
            ));
        }
    }

    fn validate_rows(&self, issues: &mut Vec<SloProofReportIssue>) {
        if self.rows.is_empty() {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingRequiredField,
                "rows",
                "proof report must include at least one machine-readable row",
            ));
        }
        let mut seen = BTreeSet::new();
        for (index, row) in self.rows.iter().enumerate() {
            let prefix = format!("rows[{index}]");
            validate_proof_required_text(
                format!("{prefix}.row_id"),
                &row.row_id,
                MAX_ID_BYTES,
                issues,
            );
            validate_proof_required_text(
                format!("{prefix}.evidence_ref"),
                &row.evidence_ref,
                MAX_PATH_BYTES,
                issues,
            );
            validate_proof_required_text(
                format!("{prefix}.summary"),
                &row.summary,
                MAX_FIELD_BYTES,
                issues,
            );
            if !row.row_id.is_empty() && !seen.insert(row.row_id.as_str()) {
                issues.push(SloProofReportIssue::new(
                    SloProofReportIssueKind::MissingRequiredField,
                    format!("{prefix}.row_id"),
                    format!("duplicate proof report row {}", row.row_id),
                ));
            }
        }
    }

    fn validate_summary_status(&self, issues: &mut Vec<SloProofReportIssue>) {
        let summary = self.human_summary.to_ascii_lowercase();
        if self.status == SloProofReportStatus::Degraded && !summary.contains("degraded") {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingRequiredField,
                "human_summary",
                "degraded reports must say degraded in the summary",
            ));
        }
        if self.status == SloProofReportStatus::NoWin
            && !summary.contains("no-win")
            && !summary.contains("no win")
        {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::MissingRequiredField,
                "human_summary",
                "no_win reports must name the no-win outcome in the summary",
            ));
        }
    }

    fn validate_report_redaction(&self, issues: &mut Vec<SloProofReportIssue>) {
        validate_proof_required_text(
            "redaction.policy_id",
            &self.redaction.policy_id,
            MAX_ID_BYTES,
            issues,
        );
        if !self.redaction.passed {
            issues.push(SloProofReportIssue::new(
                SloProofReportIssueKind::RedactionFailure,
                "redaction.passed",
                "proof report redaction pass must be true",
            ));
        }
    }
}

/// Parse and validate a proof-report JSON document.
#[must_use]
pub fn validate_slo_proof_report_json(json: &str) -> SloProofReportValidation {
    match serde_json::from_str::<SloProofReport>(json) {
        Ok(report) => report.validate(),
        Err(error) => SloProofReportValidation {
            accepted: false,
            status: SloProofReportStatus::Blocked,
            success: false,
            gate_acceptable_status: false,
            report_id: String::new(),
            policy_id: String::new(),
            issues: vec![SloProofReportIssue::new(
                SloProofReportIssueKind::MalformedReport,
                "$",
                format!("SLO proof report JSON did not parse: {error}"),
            )],
        },
    }
}

/// Count proof-report statuses without collapsing degraded or no-win outcomes into success.
#[must_use]
pub fn slo_proof_report_status_counts<'a>(
    reports: impl IntoIterator<Item = &'a SloProofReport>,
) -> SloProofReportStatusCounts {
    let mut counts = SloProofReportStatusCounts::default();
    for report in reports {
        counts.record(report.status);
    }
    counts
}

impl SloPolicyBundle {
    /// Parse a policy bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the bundle to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Compute a deterministic non-cryptographic fingerprint over the bundle JSON.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        fnv1a64(&bytes)
    }

    /// Compile this bundle into deterministic Budget, admission, brownout, and fallback policy.
    #[must_use]
    pub fn compile_for_budget_admission(
        &self,
        capacity_evidence: Option<&SloPolicyCapacityEvidence>,
    ) -> SloCompiledPolicy {
        let validation = self.validate();
        let p999_latency_budget_ms = self.p999_latency_budget_ms();
        let budget = SloCompiledBudget::from_bundle(self, p999_latency_budget_ms);
        let mut blockers = compiler_blockers_from_validation(&validation);
        if self.cleanup_deadline_ms > 0 && p999_latency_budget_ms > self.cleanup_deadline_ms {
            push_compiler_blocker(
                &mut blockers,
                SloPolicyCompilerBlockerKind::ImpossibleObjective,
                "latency_objectives.p999",
                "normalized p999 objective exceeds cleanup deadline",
            );
        }
        let capacity_evidence_fingerprint =
            capacity_evidence.map(SloPolicyCapacityEvidence::fingerprint);
        self.add_capacity_evidence_blockers(capacity_evidence, &mut blockers);

        let no_win_trigger = capacity_evidence
            .filter(|evidence| evidence.exceeds_thresholds(self))
            .map(|_| "capacity-evidence-exceeds-thresholds");
        let status = if !blockers.is_empty() {
            SloCompiledPolicyStatus::Blocked
        } else if no_win_trigger.is_some() {
            SloCompiledPolicyStatus::NoWin
        } else {
            SloCompiledPolicyStatus::Compiled
        };
        let admission = SloCompiledAdmission::from_bundle(self, capacity_evidence, status);
        let no_win_fallback = match (status, no_win_trigger) {
            (SloCompiledPolicyStatus::NoWin, Some(triggered_by)) => {
                self.no_win_receipt(triggered_by)
            }
            _ => None,
        };
        let output_id = self.compiler_output_id(capacity_evidence_fingerprint);

        SloCompiledPolicy {
            compiler_schema_version: SLO_POLICY_COMPILER_SCHEMA_VERSION.to_string(),
            policy_id: self.policy_id.clone(),
            output_id,
            status,
            budget,
            admission,
            brownout_order: self.brownout_order(),
            no_win_fallback,
            blockers,
            provenance: SloCompiledPolicyProvenance {
                policy_fingerprint: self.fingerprint(),
                capacity_evidence_fingerprint,
                profile_id: self.provenance.profile_id.clone(),
                profile_hash: self.provenance.profile_hash.clone(),
                target_commit: self.provenance.target_commit.clone(),
                feature_flags: self.provenance.feature_flags.clone(),
                related_bead_id: self.provenance.related_bead_id.clone(),
            },
        }
    }

    /// Validate schema, objectives, redaction, provenance, paths, hashes, and metadata.
    #[must_use]
    pub fn validate(&self) -> SloPolicyValidationReport {
        let mut issues = Vec::new();

        if self.schema_version != SLO_POLICY_BUNDLE_SCHEMA_VERSION {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::UnsupportedSchemaVersion,
                "schema_version",
                format!(
                    "unsupported schema version {}, expected {SLO_POLICY_BUNDLE_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_required_text("policy_id", &self.policy_id, MAX_ID_BYTES, &mut issues);
        if self.workload_class.is_unsupported() {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::UnsupportedWorkloadClass,
                "workload_class",
                format!(
                    "unsupported workload class {}",
                    self.workload_class.as_str()
                ),
            ));
        }
        self.validate_latency_objectives(&mut issues);
        self.validate_deadlines(&mut issues);
        self.validate_resource_pressure(&mut issues);
        self.validate_optional_work(&mut issues);
        self.validate_no_win_fallback(&mut issues);
        self.validate_provenance(&mut issues);
        self.validate_redaction(&mut issues);
        scan_json_map("metadata", &self.metadata, &mut issues);

        SloPolicyValidationReport {
            accepted: issues.is_empty(),
            policy_id: self.policy_id.clone(),
            schema_version: self.schema_version,
            fingerprint: self.fingerprint(),
            issues,
        }
    }

    fn validate_latency_objectives(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        if self.latency_objectives.is_empty() {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::MissingRequiredField,
                "latency_objectives",
                "policy bundle must include at least one latency objective",
            ));
        }
        let mut seen = BTreeSet::new();
        for (index, objective) in self.latency_objectives.iter().enumerate() {
            let prefix = format!("latency_objectives[{index}]");
            validate_required_text(
                format!("{prefix}.objective_id"),
                &objective.objective_id,
                MAX_ID_BYTES,
                issues,
            );
            if !objective.objective_id.is_empty() && !seen.insert(objective.objective_id.as_str()) {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::DuplicateObjective,
                    format!("{prefix}.objective_id"),
                    format!("duplicate objective id {}", objective.objective_id),
                ));
            }
            if objective.unit.is_unsupported() {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::InvalidUnit,
                    format!("{prefix}.unit"),
                    format!("unsupported latency unit {}", objective.unit.as_str()),
                ));
            }
            if objective.p50 == 0 || objective.p95 == 0 || objective.p99 == 0 || objective.p999 == 0
            {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::ImpossibleDeadline,
                    format!("{prefix}.percentiles"),
                    "latency percentiles must be positive",
                ));
            }
            if objective.p50 > objective.p95
                || objective.p95 > objective.p99
                || objective.p99 > objective.p999
            {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::NonMonotonicPercentile,
                    format!("{prefix}.percentiles"),
                    "latency percentiles must be monotonic: p50 <= p95 <= p99 <= p999",
                ));
            }
            if matches!(objective.unit, SloLatencyUnit::Milliseconds)
                && self.cleanup_deadline_ms > 0
                && objective.p999 > self.cleanup_deadline_ms
            {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::ImpossibleDeadline,
                    format!("{prefix}.p999"),
                    "p999 objective cannot exceed cleanup deadline",
                ));
            }
        }
    }

    fn validate_deadlines(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        if self.cleanup_deadline_ms == 0 {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::ImpossibleDeadline,
                "cleanup_deadline_ms",
                "cleanup deadline must be positive",
            ));
        }
        if self.max_queue_wait_ms == 0 {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::ImpossibleDeadline,
                "max_queue_wait_ms",
                "queue wait objective must be positive",
            ));
        }
        if self.cleanup_deadline_ms > 0
            && self.max_queue_wait_ms > 0
            && self.max_queue_wait_ms > self.cleanup_deadline_ms
        {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::ImpossibleDeadline,
                "max_queue_wait_ms",
                "queue wait objective cannot exceed cleanup deadline",
            ));
        }
    }

    fn validate_resource_pressure(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        if self.resource_pressure.memory_basis_points > 10_000 {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::InvalidUnit,
                "resource_pressure.memory_basis_points",
                "memory pressure must be <= 10000 basis points",
            ));
        }
        if self.resource_pressure.fd_basis_points > 10_000 {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::InvalidUnit,
                "resource_pressure.fd_basis_points",
                "fd pressure must be <= 10000 basis points",
            ));
        }
        if self.resource_pressure.timer_queue_depth == 0 {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::ImpossibleDeadline,
                "resource_pressure.timer_queue_depth",
                "timer queue depth threshold must be positive",
            ));
        }
    }

    fn validate_optional_work(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        let mut seen = BTreeSet::new();
        for (index, work) in self.optional_work_classes.iter().enumerate() {
            let prefix = format!("optional_work_classes[{index}]");
            validate_required_text(
                format!("{prefix}.class_id"),
                &work.class_id,
                MAX_ID_BYTES,
                issues,
            );
            validate_required_text(
                format!("{prefix}.degradation_step"),
                &work.degradation_step,
                MAX_FIELD_BYTES,
                issues,
            );
            if !work.class_id.is_empty() && !seen.insert(work.class_id.as_str()) {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::DuplicateObjective,
                    format!("{prefix}.class_id"),
                    format!("duplicate optional work class {}", work.class_id),
                ));
            }
        }
    }

    fn validate_no_win_fallback(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        let Some(fallback) = &self.no_win_fallback else {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::MissingNoWinFallback,
                "no_win_fallback",
                "policy bundle must declare an explicit no-win fallback",
            ));
            return;
        };
        validate_required_text(
            "no_win_fallback.fallback_profile",
            &fallback.fallback_profile,
            MAX_ID_BYTES,
            issues,
        );
        validate_required_text(
            "no_win_fallback.fallback_reason",
            &fallback.fallback_reason,
            MAX_FIELD_BYTES,
            issues,
        );
        validate_required_text(
            "no_win_fallback.proof_command",
            &fallback.proof_command,
            MAX_FIELD_BYTES,
            issues,
        );
        if !fallback.proof_command.contains("rch exec")
            || !cargo_proof_command_has_target_dir(&fallback.proof_command)
        {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::MissingNoWinFallback,
                "no_win_fallback.proof_command",
                "fallback cargo proof command must name an rch exec -- env proof path with CARGO_TARGET_DIR",
            ));
        }
        if value_is_secret_like(&fallback.proof_command) {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::SecretLikeMaterial,
                "no_win_fallback.proof_command",
                "fallback proof command contains secret-like material",
            ));
        }
    }

    fn validate_provenance(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        validate_required_text(
            "provenance.profile_id",
            &self.provenance.profile_id,
            MAX_ID_BYTES,
            issues,
        );
        validate_content_hash(
            "provenance.profile_hash",
            &self.provenance.profile_hash,
            issues,
        );
        if let Some(observed) = &self.provenance.observed_profile_hash {
            validate_content_hash("provenance.observed_profile_hash", observed, issues);
            if observed != &self.provenance.profile_hash {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::StaleProfileHash,
                    "provenance.observed_profile_hash",
                    "observed profile hash does not match declared profile hash",
                ));
            }
        }
        validate_required_text(
            "provenance.target_commit",
            &self.provenance.target_commit,
            MAX_FIELD_BYTES,
            issues,
        );
        for (index, flag) in self.provenance.feature_flags.iter().enumerate() {
            validate_required_text(
                format!("provenance.feature_flags[{index}]"),
                flag,
                MAX_FIELD_BYTES,
                issues,
            );
        }
        if let Some(path) = &self.provenance.artifact_path {
            validate_repo_relative_path("provenance.artifact_path", path, issues);
        }
        if let Some(bead) = &self.provenance.related_bead_id {
            validate_text_size("provenance.related_bead_id", bead, MAX_ID_BYTES, issues);
        }
    }

    fn validate_redaction(&self, issues: &mut Vec<SloPolicyValidationIssue>) {
        validate_required_text(
            "redaction.policy_id",
            &self.redaction.policy_id,
            MAX_ID_BYTES,
            issues,
        );
        if !self.redaction.passed {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::RedactionFailure,
                "redaction.passed",
                "policy bundle redaction pass must be true",
            ));
        }
    }

    fn p999_latency_budget_ms(&self) -> u64 {
        self.latency_objectives
            .iter()
            .map(normalized_p999_ms)
            .max()
            .unwrap_or(0)
    }

    fn add_capacity_evidence_blockers(
        &self,
        capacity_evidence: Option<&SloPolicyCapacityEvidence>,
        blockers: &mut Vec<SloPolicyCompilerBlocker>,
    ) {
        let Some(evidence) = capacity_evidence else {
            push_compiler_blocker(
                blockers,
                SloPolicyCompilerBlockerKind::MissingCapacityEvidence,
                "capacity_evidence",
                "capacity evidence is required for an executable admission decision",
            );
            return;
        };
        if evidence.profile_id != self.provenance.profile_id {
            push_compiler_blocker(
                blockers,
                SloPolicyCompilerBlockerKind::MissingCapacityEvidence,
                "capacity_evidence.profile_id",
                "capacity evidence profile_id does not match policy provenance",
            );
        }
        if evidence.profile_hash != self.provenance.profile_hash {
            push_compiler_blocker(
                blockers,
                SloPolicyCompilerBlockerKind::MissingCapacityEvidence,
                "capacity_evidence.profile_hash",
                "capacity evidence profile_hash does not match policy provenance",
            );
        }
        if evidence.workload_class != self.workload_class {
            push_compiler_blocker(
                blockers,
                SloPolicyCompilerBlockerKind::UnsupportedWorkloadClass,
                "capacity_evidence.workload_class",
                "capacity evidence workload_class does not match policy workload_class",
            );
        }
        if evidence.sample_count == 0 {
            push_compiler_blocker(
                blockers,
                SloPolicyCompilerBlockerKind::MissingCapacityEvidence,
                "capacity_evidence.sample_count",
                "capacity evidence must contain at least one sample",
            );
        }
    }

    fn no_win_receipt(&self, triggered_by: &str) -> Option<SloCompiledNoWinReceipt> {
        self.no_win_fallback
            .as_ref()
            .map(|fallback| SloCompiledNoWinReceipt {
                fallback_profile: fallback.fallback_profile.clone(),
                fallback_reason: fallback.fallback_reason.clone(),
                proof_command: fallback.proof_command.clone(),
                triggered_by: triggered_by.to_string(),
            })
    }

    fn compiler_output_id(&self, capacity_evidence_fingerprint: Option<u64>) -> String {
        format!(
            "slo-compiled-{}-{:016x}-{:016x}",
            self.policy_id,
            self.fingerprint(),
            capacity_evidence_fingerprint.unwrap_or(0)
        )
    }

    fn brownout_order(&self) -> Vec<SloCompiledBrownoutStep> {
        let mut steps = self
            .optional_work_classes
            .iter()
            .map(|work| SloCompiledBrownoutStep {
                class_id: work.class_id.clone(),
                brownout_priority: work.brownout_priority,
                stage: SloCompiledBrownoutStage::OptionalFirst,
                degradation_step: work.degradation_step.clone(),
            })
            .collect::<Vec<_>>();
        steps.sort_by(|left, right| {
            left.brownout_priority
                .cmp(&right.brownout_priority)
                .then_with(|| left.class_id.cmp(&right.class_id))
        });
        steps
    }
}

/// Typed validation issue kind for SLO policy bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SloPolicyValidationIssueKind {
    /// The input JSON did not parse.
    MalformedJson,
    /// Schema version is not supported.
    UnsupportedSchemaVersion,
    /// A required field is missing or empty.
    MissingRequiredField,
    /// Percentile targets are not monotonic.
    NonMonotonicPercentile,
    /// Unit or basis-point value is invalid.
    InvalidUnit,
    /// Explicit no-win fallback declaration is missing or unusable.
    MissingNoWinFallback,
    /// Secret-like material was found in metadata or command fields.
    SecretLikeMaterial,
    /// Host-private or absolute path was supplied.
    ExternalPath,
    /// Observed profile hash is malformed or stale.
    StaleProfileHash,
    /// Workload class is unsupported.
    UnsupportedWorkloadClass,
    /// Objective or optional work class appears more than once.
    DuplicateObjective,
    /// Deadline or queue objective is impossible.
    ImpossibleDeadline,
    /// Text field exceeds deterministic size limits.
    OversizedField,
    /// Redaction pass failed.
    RedactionFailure,
}

impl SloPolicyValidationIssueKind {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedJson => "malformed_json",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::MissingRequiredField => "missing_required_field",
            Self::NonMonotonicPercentile => "non_monotonic_percentile",
            Self::InvalidUnit => "invalid_unit",
            Self::MissingNoWinFallback => "missing_no_win_fallback",
            Self::SecretLikeMaterial => "secret_like_material",
            Self::ExternalPath => "external_path",
            Self::StaleProfileHash => "stale_profile_hash",
            Self::UnsupportedWorkloadClass => "unsupported_workload_class",
            Self::DuplicateObjective => "duplicate_objective",
            Self::ImpossibleDeadline => "impossible_deadline",
            Self::OversizedField => "oversized_field",
            Self::RedactionFailure => "redaction_failure",
        }
    }
}

/// One SLO policy validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyValidationIssue {
    /// Issue class.
    pub kind: SloPolicyValidationIssueKind,
    /// Field associated with the issue.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl SloPolicyValidationIssue {
    fn new(
        kind: SloPolicyValidationIssueKind,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Complete fail-closed validation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloPolicyValidationReport {
    /// Whether the policy bundle is accepted.
    pub accepted: bool,
    /// Policy id observed in the bundle.
    pub policy_id: String,
    /// Schema version observed.
    pub schema_version: u32,
    /// Stable non-cryptographic fingerprint.
    pub fingerprint: u64,
    /// Typed validation issues.
    pub issues: Vec<SloPolicyValidationIssue>,
}

impl SloPolicyValidationReport {
    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_issue(&self, kind: SloPolicyValidationIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Parse and validate a policy bundle JSON document.
#[must_use]
pub fn validate_slo_policy_bundle_json(json: &str) -> SloPolicyValidationReport {
    match serde_json::from_str::<SloPolicyBundle>(json) {
        Ok(bundle) => bundle.validate(),
        Err(error) => SloPolicyValidationReport {
            accepted: false,
            policy_id: String::new(),
            schema_version: 0,
            fingerprint: 0,
            issues: vec![SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::MalformedJson,
                "$",
                format!("SLO policy bundle JSON did not parse: {error}"),
            )],
        },
    }
}

fn runtime_decision_for_compiled_policy(compiled: &SloCompiledPolicy) -> SloRuntimePolicyDecision {
    match compiled.status {
        SloCompiledPolicyStatus::Compiled => match compiled.admission.decision {
            SloCompiledAdmissionDecision::Admit => SloRuntimePolicyDecision::Admit,
            SloCompiledAdmissionDecision::Brownout => SloRuntimePolicyDecision::Brownout,
            SloCompiledAdmissionDecision::NoWin => SloRuntimePolicyDecision::NoWin,
            SloCompiledAdmissionDecision::Blocked => SloRuntimePolicyDecision::Blocked,
        },
        SloCompiledPolicyStatus::NoWin => SloRuntimePolicyDecision::NoWin,
        SloCompiledPolicyStatus::Blocked => SloRuntimePolicyDecision::Blocked,
    }
}

fn optional_work_decision_for_runtime_decision(
    decision: SloRuntimePolicyDecision,
) -> SloRuntimeOptionalWorkDecision {
    match decision {
        SloRuntimePolicyDecision::Admit | SloRuntimePolicyDecision::Blocked => {
            SloRuntimeOptionalWorkDecision::Run
        }
        SloRuntimePolicyDecision::Brownout
        | SloRuntimePolicyDecision::Reject
        | SloRuntimePolicyDecision::NoWin => SloRuntimeOptionalWorkDecision::Brownout,
    }
}

fn validate_runtime_required_text(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloRuntimePolicyApplicationIssue>,
) {
    let field = field.into();
    if value.is_empty() {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::MissingRequiredField,
            field.clone(),
            "required field must not be empty",
        ));
    }
    validate_runtime_text_size(&field, value, max_bytes, issues);
    if value_is_secret_like(value) {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::SecretLikeMaterial,
            field,
            "text field contains secret-like material",
        ));
    }
}

fn validate_runtime_text_size(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloRuntimePolicyApplicationIssue>,
) {
    let field = field.into();
    if value.len() > max_bytes {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::OversizedField,
            field,
            format!("field is {} bytes, limit is {max_bytes}", value.len()),
        ));
    }
}

fn validate_runtime_content_hash(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<SloRuntimePolicyApplicationIssue>,
) {
    let field = field.into();
    let Some(hex) = value.strip_prefix("sha256:") else {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
        return;
    };
    if hex.len() != SHA256_HEX_LEN || !hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
    }
}

fn scan_runtime_json_map(
    prefix: &str,
    map: &BTreeMap<String, Value>,
    issues: &mut Vec<SloRuntimePolicyApplicationIssue>,
) {
    for (key, value) in map {
        scan_runtime_json_value(&format!("{prefix}.{key}"), key, value, issues);
    }
}

fn scan_runtime_json_value(
    field: &str,
    key: &str,
    value: &Value,
    issues: &mut Vec<SloRuntimePolicyApplicationIssue>,
) {
    if key_is_secret_like(key) {
        issues.push(SloRuntimePolicyApplicationIssue::new(
            SloRuntimePolicyApplicationIssueKind::SecretLikeMaterial,
            field,
            "secret-like metadata key is not allowed",
        ));
    }
    match value {
        Value::String(text) => {
            validate_runtime_text_size(field, text, MAX_FIELD_BYTES, issues);
            if value_is_secret_like(text) {
                issues.push(SloRuntimePolicyApplicationIssue::new(
                    SloRuntimePolicyApplicationIssueKind::SecretLikeMaterial,
                    field,
                    "secret-like metadata value is not allowed",
                ));
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                scan_runtime_json_value(&format!("{field}[{index}]"), key, item, issues);
            }
        }
        Value::Object(object) => {
            for (child_key, child) in object {
                scan_runtime_json_value(&format!("{field}.{child_key}"), child_key, child, issues);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn validate_required_text(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    let field = field.into();
    if value.is_empty() {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::MissingRequiredField,
            field.clone(),
            "required field must not be empty",
        ));
    }
    validate_text_size(&field, value, max_bytes, issues);
    if value_is_secret_like(value) {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::SecretLikeMaterial,
            field,
            "text field contains secret-like material",
        ));
    }
}

fn validate_proof_required_text(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloProofReportIssue>,
) {
    let field = field.into();
    if value.is_empty() {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::MissingRequiredField,
            field.clone(),
            "required field must not be empty",
        ));
    }
    validate_proof_text_size(&field, value, max_bytes, issues);
    if value_is_secret_like(value) {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::SecretLikeMaterial,
            field,
            "text field contains secret-like material",
        ));
    }
}

fn validate_proof_text_size(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloProofReportIssue>,
) {
    let field = field.into();
    if value.len() > max_bytes {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::OversizedField,
            field,
            format!("field is {} bytes, limit is {max_bytes}", value.len()),
        ));
    }
}

fn validate_proof_content_hash(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<SloProofReportIssue>,
) {
    let field = field.into();
    let Some(hex) = value.strip_prefix("sha256:") else {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
        return;
    };
    if hex.len() != SHA256_HEX_LEN || !hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
    }
}

fn scan_proof_json_map(
    prefix: &str,
    map: &BTreeMap<String, Value>,
    issues: &mut Vec<SloProofReportIssue>,
) {
    for (key, value) in map {
        scan_proof_json_value(&format!("{prefix}.{key}"), key, value, issues);
    }
}

fn scan_proof_json_value(
    field: &str,
    key: &str,
    value: &Value,
    issues: &mut Vec<SloProofReportIssue>,
) {
    if key_is_secret_like(key) {
        issues.push(SloProofReportIssue::new(
            SloProofReportIssueKind::SecretLikeMaterial,
            field,
            "secret-like metadata key is not allowed",
        ));
    }
    match value {
        Value::String(text) => {
            validate_proof_text_size(field, text, MAX_FIELD_BYTES, issues);
            if value_is_secret_like(text) {
                issues.push(SloProofReportIssue::new(
                    SloProofReportIssueKind::SecretLikeMaterial,
                    field,
                    "secret-like metadata value is not allowed",
                ));
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                scan_proof_json_value(&format!("{field}[{index}]"), key, item, issues);
            }
        }
        Value::Object(object) => {
            for (child_key, child) in object {
                scan_proof_json_value(&format!("{field}.{child_key}"), child_key, child, issues);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn validate_text_size(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    let field = field.into();
    if value.len() > max_bytes {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::OversizedField,
            field,
            format!("field is {} bytes, limit is {max_bytes}", value.len()),
        ));
    }
}

fn validate_content_hash(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    let field = field.into();
    let Some(hex) = value.strip_prefix("sha256:") else {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
        return;
    };
    if hex.len() != SHA256_HEX_LEN || !hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::StaleProfileHash,
            field,
            "profile hash must use sha256:<64 lowercase hex> format",
        ));
    }
}

fn validate_repo_relative_path(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    let field = field.into();
    validate_text_size(&field, value, MAX_PATH_BYTES, issues);
    let lower = value.to_ascii_lowercase();
    let is_absolute = value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':');
    let has_parent = value.split(['/', '\\']).any(|part| part == "..");
    let has_private = PRIVATE_PATH_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment));
    if is_absolute || has_parent || has_private {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::ExternalPath,
            field,
            "path must be repository-relative and must not expose host-private directories",
        ));
    }
}

fn scan_json_map(
    prefix: &str,
    map: &BTreeMap<String, Value>,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    for (key, value) in map {
        scan_json_value(&format!("{prefix}.{key}"), key, value, issues);
    }
}

fn scan_json_value(
    field: &str,
    key: &str,
    value: &Value,
    issues: &mut Vec<SloPolicyValidationIssue>,
) {
    if key_is_secret_like(key) {
        issues.push(SloPolicyValidationIssue::new(
            SloPolicyValidationIssueKind::SecretLikeMaterial,
            field,
            "secret-like metadata key is not allowed",
        ));
    }
    match value {
        Value::String(text) => {
            validate_text_size(field, text, MAX_FIELD_BYTES, issues);
            if value_is_secret_like(text) {
                issues.push(SloPolicyValidationIssue::new(
                    SloPolicyValidationIssueKind::SecretLikeMaterial,
                    field,
                    "secret-like metadata value is not allowed",
                ));
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                scan_json_value(&format!("{field}[{index}]"), key, item, issues);
            }
        }
        Value::Object(object) => {
            for (child_key, child) in object {
                scan_json_value(&format!("{field}.{child_key}"), child_key, child, issues);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn key_is_secret_like(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn value_is_secret_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    SECRET_VALUE_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn compiler_priority_for_workload(workload_class: &SloWorkloadClass) -> u8 {
    match workload_class {
        SloWorkloadClass::ControlPlane => 224,
        SloWorkloadClass::DataPlane => 192,
        SloWorkloadClass::AgentSwarm => 208,
        SloWorkloadClass::Background => 96,
        SloWorkloadClass::Unsupported(_) => 0,
    }
}

fn normalized_p999_ms(objective: &SloLatencyObjective) -> u64 {
    match &objective.unit {
        SloLatencyUnit::Milliseconds | SloLatencyUnit::Unsupported(_) => objective.p999,
        SloLatencyUnit::Microseconds => objective.p999.saturating_add(999) / 1_000,
    }
}

fn compiler_blockers_from_validation(
    validation: &SloPolicyValidationReport,
) -> Vec<SloPolicyCompilerBlocker> {
    let mut blockers = Vec::new();
    for issue in &validation.issues {
        let kind = match issue.kind {
            SloPolicyValidationIssueKind::UnsupportedWorkloadClass => {
                SloPolicyCompilerBlockerKind::UnsupportedWorkloadClass
            }
            SloPolicyValidationIssueKind::NonMonotonicPercentile
            | SloPolicyValidationIssueKind::InvalidUnit
            | SloPolicyValidationIssueKind::ImpossibleDeadline => {
                SloPolicyCompilerBlockerKind::ImpossibleObjective
            }
            SloPolicyValidationIssueKind::MissingNoWinFallback => {
                SloPolicyCompilerBlockerKind::ConflictingFallbackDeclaration
            }
            SloPolicyValidationIssueKind::SecretLikeMaterial
                if issue.field.starts_with("no_win_fallback") =>
            {
                SloPolicyCompilerBlockerKind::ConflictingFallbackDeclaration
            }
            SloPolicyValidationIssueKind::MalformedJson
            | SloPolicyValidationIssueKind::UnsupportedSchemaVersion
            | SloPolicyValidationIssueKind::MissingRequiredField
            | SloPolicyValidationIssueKind::SecretLikeMaterial
            | SloPolicyValidationIssueKind::ExternalPath
            | SloPolicyValidationIssueKind::StaleProfileHash
            | SloPolicyValidationIssueKind::DuplicateObjective
            | SloPolicyValidationIssueKind::OversizedField
            | SloPolicyValidationIssueKind::RedactionFailure => {
                SloPolicyCompilerBlockerKind::InvalidBundle
            }
        };
        push_compiler_blocker(
            &mut blockers,
            kind,
            issue.field.clone(),
            issue.message.clone(),
        );
    }
    blockers
}

fn push_compiler_blocker(
    blockers: &mut Vec<SloPolicyCompilerBlocker>,
    kind: SloPolicyCompilerBlockerKind,
    field: impl Into<String>,
    message: impl Into<String>,
) {
    let field = field.into();
    if blockers
        .iter()
        .any(|blocker| blocker.kind == kind && blocker.field == field)
    {
        return;
    }
    blockers.push(SloPolicyCompilerBlocker::new(kind, field, message));
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
