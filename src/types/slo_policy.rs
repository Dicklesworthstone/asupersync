//! Operator SLO policy bundle schema and fail-closed validation.
//!
//! SLO policy bundles are deterministic operator inputs. They describe service
//! objectives that later compiler beads can map into [`Budget`](crate::types::Budget),
//! admission thresholds, brownout tiers, and no-win fallback receipts.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Current SLO policy bundle schema version.
pub const SLO_POLICY_BUNDLE_SCHEMA_VERSION: u32 = 1;

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
        if !fallback.proof_command.contains("rch exec") {
            issues.push(SloPolicyValidationIssue::new(
                SloPolicyValidationIssueKind::MissingNoWinFallback,
                "no_win_fallback.proof_command",
                "fallback proof command must name an rch exec proof path",
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

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
