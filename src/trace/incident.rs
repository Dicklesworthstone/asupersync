//! Production incident bundle schema and fail-closed redaction contract.
//!
//! Incident bundles are deterministic handoff artifacts. They connect field
//! reports, crash packs, trace logs, `rch` failures, README claim failures, and
//! manually supplied repro notes to the replay/minimization pipeline without
//! inventing a parallel replay format.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Current incident bundle schema version.
pub const INCIDENT_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Current replay package schema version emitted by the incident importer.
pub const INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION: u32 = 1;

/// Current minimized replay repro schema version.
pub const INCIDENT_MINIMIZED_REPRO_SCHEMA_VERSION: u32 = 1;

/// Current incident regression proof schema version.
pub const INCIDENT_REGRESSION_PROOF_SCHEMA_VERSION: u32 = 1;

/// Current operator-facing incident proof report schema version.
pub const INCIDENT_PROOF_REPORT_SCHEMA_VERSION: u32 = 1;

const MAX_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 512;
const MAX_FIELD_BYTES: usize = 1024;
const MAX_PAYLOAD_SNIPPET_BYTES: usize = 4096;
const SHA256_HEX_LEN: usize = 64;

const SUPPORTED_SOURCE_KIND_TAGS: [&str; 7] = [
    "crash_pack",
    "trace_log",
    "support_bundle",
    "readme_claim_failure",
    "conformance_failure",
    "rch_proof_failure",
    "repro_notes",
];

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

/// The kind of incident source represented by an [`IncidentSource`].
///
/// Unknown tags deserialize as [`IncidentSourceKind::Unsupported`] so importer
/// lanes can return typed blocked verdicts instead of failing open or losing
/// the raw source vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentSourceKind {
    /// Native deterministic crash pack.
    CrashPack,
    /// Trace event log or replay trace.
    TraceLog,
    /// Operator or support bundle.
    SupportBundle,
    /// README or support-matrix claim failure fixture.
    ReadmeClaimFailure,
    /// RFC or conformance harness failure.
    ConformanceFailure,
    /// Remote `rch` proof failure metadata.
    RchProofFailure,
    /// Manually supplied reproduction notes.
    ReproNotes,
    /// Source tag not understood by this schema version.
    Unsupported(String),
}

impl IncidentSourceKind {
    /// Return the canonical string tag for this source kind.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CrashPack => "crash_pack",
            Self::TraceLog => "trace_log",
            Self::SupportBundle => "support_bundle",
            Self::ReadmeClaimFailure => "readme_claim_failure",
            Self::ConformanceFailure => "conformance_failure",
            Self::RchProofFailure => "rch_proof_failure",
            Self::ReproNotes => "repro_notes",
            Self::Unsupported(tag) => tag,
        }
    }

    /// Return `true` when this tag is unsupported by this schema version.
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }

    /// Return all first-class source kind tags.
    #[must_use]
    pub const fn supported_tags() -> &'static [&'static str] {
        &SUPPORTED_SOURCE_KIND_TAGS
    }

    fn from_tag(tag: &str) -> Self {
        match tag {
            "crash_pack" => Self::CrashPack,
            "trace_log" => Self::TraceLog,
            "support_bundle" => Self::SupportBundle,
            "readme_claim_failure" => Self::ReadmeClaimFailure,
            "conformance_failure" => Self::ConformanceFailure,
            "rch_proof_failure" => Self::RchProofFailure,
            "repro_notes" => Self::ReproNotes,
            other => Self::Unsupported(other.to_string()),
        }
    }
}

impl Serialize for IncidentSourceKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IncidentSourceKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let tag = String::deserialize(deserializer)?;
        Ok(Self::from_tag(&tag))
    }
}

/// Privacy classification for an incident bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentPrivacyClass {
    /// Safe to share publicly after normal review.
    Public,
    /// Internal-only operational metadata.
    Internal,
    /// Contains customer, deployment, or sensitive operator context.
    Confidential,
    /// Contains or may contain credentials or secret-bearing material.
    Secret,
}

impl IncidentPrivacyClass {
    fn requires_redaction(self) -> bool {
        matches!(self, Self::Confidential | Self::Secret)
    }
}

/// Redaction status attached to bundles and source payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRedactionStatus {
    /// A redaction pass was performed under the named policy.
    Redacted,
    /// The source is known not to require redaction.
    NotRequired,
    /// The source requires redaction but no valid redaction pass exists.
    RequiredButMissing,
}

/// Top-level incident privacy envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentPrivacy {
    /// Bundle-level privacy classification.
    pub classification: IncidentPrivacyClass,
    /// Bundle-level redaction status.
    pub redaction_status: IncidentRedactionStatus,
    /// Deterministic policy identifier used for redaction.
    pub redaction_policy_id: String,
}

/// Environment variable captured for a reproduction command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEnvVar {
    /// Variable name.
    pub key: String,
    /// Variable value after redaction policy is applied.
    pub value: String,
}

/// Command metadata needed to reproduce or validate an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentCommand {
    /// Program name, for example `rch`.
    pub program: String,
    /// Command-line arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables required by the command.
    #[serde(default)]
    pub env: Vec<IncidentEnvVar>,
    /// Repository-relative working directory.
    pub working_dir: String,
}

/// Deterministic execution metadata carried by a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDeterminism {
    /// Lab or harness seed, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Schedule seed, if distinct from `seed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_seed: Option<u64>,
    /// Virtual timestamp associated with capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_time_nanos: Option<u64>,
    /// Deterministic runtime or harness config hash.
    pub config_hash: String,
    /// Feature flags active during capture.
    #[serde(default)]
    pub feature_flags: Vec<String>,
    /// Target triple for the capture or proof command.
    pub target_triple: String,
}

/// Provenance metadata for where an incident bundle came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentProvenance {
    /// Stable capture identifier supplied by the harness or operator.
    pub capture_id: String,
    /// Logical origin, for example `support_bundle` or `rch_failure`.
    pub origin: String,
    /// Reporter or automation source.
    pub reporter: String,
    /// Commit hash associated with the captured artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_commit: Option<String>,
    /// Related Beads issue, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_bead_id: Option<String>,
}

/// One incident input source inside a bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentSource {
    /// Stable source identifier unique within the bundle.
    pub source_id: String,
    /// Source kind vocabulary.
    pub kind: IncidentSourceKind,
    /// Repo-relative artifact path, if the source is file-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Content hash in `sha256:<64 lowercase hex>` form.
    pub content_hash: String,
    /// Size of the referenced source payload in bytes.
    pub content_bytes: u64,
    /// Source-level redaction status.
    pub redaction_status: IncidentRedactionStatus,
    /// Bounded human-readable snippet for triage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_snippet: Option<String>,
    /// Source metadata. Values are scanned for redaction violations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// Canonical production incident bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentBundle {
    /// Schema version. Must match [`INCIDENT_BUNDLE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable bundle identifier.
    pub bundle_id: String,
    /// One or more source artifacts or notes.
    pub sources: Vec<IncidentSource>,
    /// Reproduction or proof command metadata.
    pub command: IncidentCommand,
    /// Deterministic replay metadata.
    pub determinism: IncidentDeterminism,
    /// Privacy and redaction state.
    pub privacy: IncidentPrivacy,
    /// Capture provenance.
    pub provenance: IncidentProvenance,
    /// Additional deterministic metadata. Values are scanned for secrets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// Validation verdict for an incident bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentValidationVerdict {
    /// The bundle satisfies the schema/redaction contract.
    Accepted,
    /// The bundle must not be imported until issues are resolved.
    Blocked,
}

/// Structured class for a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentValidationIssueKind {
    /// The schema version is not supported.
    UnsupportedSchemaVersion,
    /// A required field is missing or empty.
    MissingRequiredField,
    /// A source identifier appears more than once.
    DuplicateSourceId,
    /// Source kind is unknown to this schema version.
    UnsupportedSourceKind,
    /// Redaction policy identifier is missing.
    MissingRedactionPolicy,
    /// Redaction is required but was not completed.
    RedactionRequiredButMissing,
    /// Secret-like key or value was found in unredacted material.
    SecretLikeMaterial,
    /// Field exceeds the deterministic contract limit.
    OversizedField,
    /// Host-specific or absolute path was supplied.
    ExternalPath,
    /// Hash field is malformed.
    MalformedContentHash,
    /// Binary-like payload was supplied in a text field.
    BinaryLikePayload,
    /// Duplicate feature flag was supplied.
    DuplicateFeatureFlag,
}

impl IncidentValidationIssueKind {
    /// Return the stable string tag for artifact comparisons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::MissingRequiredField => "missing_required_field",
            Self::DuplicateSourceId => "duplicate_source_id",
            Self::UnsupportedSourceKind => "unsupported_source_kind",
            Self::MissingRedactionPolicy => "missing_redaction_policy",
            Self::RedactionRequiredButMissing => "redaction_required_but_missing",
            Self::SecretLikeMaterial => "secret_like_material",
            Self::OversizedField => "oversized_field",
            Self::ExternalPath => "external_path",
            Self::MalformedContentHash => "malformed_content_hash",
            Self::BinaryLikePayload => "binary_like_payload",
            Self::DuplicateFeatureFlag => "duplicate_feature_flag",
        }
    }
}

/// One validation issue with a field path and message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentValidationIssue {
    /// Issue class.
    pub kind: IncidentValidationIssueKind,
    /// Dot/bracket path to the offending field.
    pub field: String,
    /// Human-readable blocked reason.
    pub message: String,
}

impl IncidentValidationIssue {
    fn new(
        kind: IncidentValidationIssueKind,
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

/// Complete validation report for an incident bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentValidationReport {
    /// Accepted or blocked verdict.
    pub verdict: IncidentValidationVerdict,
    /// Bundle identifier.
    pub bundle_id: String,
    /// Schema version observed.
    pub schema_version: u32,
    /// Blocking issues.
    pub issues: Vec<IncidentValidationIssue>,
    /// Stable bundle fingerprint.
    pub fingerprint: u64,
}

impl IncidentValidationReport {
    /// Return `true` when the bundle is safe for importer work.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self.verdict, IncidentValidationVerdict::Accepted)
    }

    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_kind(&self, kind: IncidentValidationIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Import verdict for converting a validated incident bundle into a replay package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayImportVerdict {
    /// A deterministic replay package was emitted.
    Imported,
    /// The input parsed but must not be imported until blockers are resolved.
    Blocked,
    /// The input was not a valid incident bundle JSON document.
    Malformed,
}

/// Structured blocker classes emitted by the incident replay importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayBlockReasonKind {
    /// The importer could not parse incident bundle JSON.
    MalformedJson,
    /// The bundle-level schema/redaction validator rejected the input.
    ValidationIssue,
    /// A source kind is not understood by this importer.
    UnsupportedSourceKind,
    /// A source lacks artifact path, snippet, or metadata payload evidence.
    MissingSourcePayload,
    /// A source carries an observed hash that does not match its declared hash.
    StaleContentHash,
    /// A source or bundle requires redaction before replay import.
    RedactionRequiredButMissing,
}

impl IncidentReplayBlockReasonKind {
    /// Return the stable string tag for artifact comparisons and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedJson => "malformed_json",
            Self::ValidationIssue => "validation_issue",
            Self::UnsupportedSourceKind => "unsupported_source_kind",
            Self::MissingSourcePayload => "missing_source_payload",
            Self::StaleContentHash => "stale_content_hash",
            Self::RedactionRequiredButMissing => "redaction_required_but_missing",
        }
    }
}

/// One typed blocker emitted by incident replay import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayBlockReason {
    /// Blocker class.
    pub kind: IncidentReplayBlockReasonKind,
    /// Source identifier, when the blocker is source-local.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Field path associated with the blocker.
    pub field: String,
    /// Human-readable blocked reason.
    pub message: String,
}

impl IncidentReplayBlockReason {
    fn new(
        kind: IncidentReplayBlockReasonKind,
        source_id: Option<String>,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            source_id,
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Replay role assigned to one imported incident source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplaySourceRole {
    /// Native crash pack source.
    CrashPack,
    /// Trace-log source already aligned with trace tooling.
    TraceLog,
    /// Support bundle source retained as provenance and payload evidence.
    SupportBundle,
    /// README claim-failure source.
    ReadmeClaimFailure,
    /// Conformance failure source.
    ConformanceFailure,
    /// Remote `rch` proof failure source.
    RchProofFailure,
    /// Manual reproduction notes.
    ReproNotes,
}

impl IncidentReplaySourceRole {
    fn from_kind(kind: &IncidentSourceKind) -> Option<Self> {
        match kind {
            IncidentSourceKind::CrashPack => Some(Self::CrashPack),
            IncidentSourceKind::TraceLog => Some(Self::TraceLog),
            IncidentSourceKind::SupportBundle => Some(Self::SupportBundle),
            IncidentSourceKind::ReadmeClaimFailure => Some(Self::ReadmeClaimFailure),
            IncidentSourceKind::ConformanceFailure => Some(Self::ConformanceFailure),
            IncidentSourceKind::RchProofFailure => Some(Self::RchProofFailure),
            IncidentSourceKind::ReproNotes => Some(Self::ReproNotes),
            IncidentSourceKind::Unsupported(_) => None,
        }
    }

    /// Return the stable string tag for deterministic package keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrashPack => "crash_pack",
            Self::TraceLog => "trace_log",
            Self::SupportBundle => "support_bundle",
            Self::ReadmeClaimFailure => "readme_claim_failure",
            Self::ConformanceFailure => "conformance_failure",
            Self::RchProofFailure => "rch_proof_failure",
            Self::ReproNotes => "repro_notes",
        }
    }
}

/// One imported source inside an [`IncidentReplayPackage`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReplaySource {
    /// Stable source identifier from the incident bundle.
    pub source_id: String,
    /// Source role used by replay package consumers.
    pub role: IncidentReplaySourceRole,
    /// Original source kind tag.
    pub kind: IncidentSourceKind,
    /// Repo-relative artifact path, when file-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Declared content hash in `sha256:<64 hex>` form.
    pub content_hash: String,
    /// Declared content size in bytes.
    pub content_bytes: u64,
    /// Optional trace fingerprint carried by source metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_fingerprint: Option<String>,
    /// Deterministic provenance edge from bundle capture to this source.
    pub provenance_edge: String,
}

/// Canonicalization summary for a replay package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayCanonicalization {
    /// FNV-1a digest of canonical source descriptors.
    pub source_digest: u64,
    /// Source IDs in canonical package order.
    pub source_order: Vec<String>,
    /// Trace fingerprints extracted from source metadata.
    pub trace_fingerprints: Vec<String>,
    /// Deterministic normalization strategy used by this importer.
    pub normalization_strategy: String,
}

/// Deterministic replay package emitted from one incident bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReplayPackage {
    /// Replay package schema version.
    pub schema_version: u32,
    /// Stable package identifier derived from replay-relevant content.
    pub package_id: String,
    /// Source incident bundle identifier.
    pub bundle_id: String,
    /// Stable local fingerprint of the source bundle.
    pub bundle_fingerprint: u64,
    /// Imported replay-capable sources.
    pub sources: Vec<IncidentReplaySource>,
    /// Replay metadata compatible with existing trace tooling.
    pub trace_metadata: crate::trace::replay::TraceMetadata,
    /// Reproduction or proof command metadata.
    pub command: IncidentCommand,
    /// Deterministic capture metadata from the source bundle.
    pub determinism: IncidentDeterminism,
    /// Capture provenance from the source bundle.
    pub provenance: IncidentProvenance,
    /// Canonicalization summary for stable package IDs.
    pub canonicalization: IncidentReplayCanonicalization,
}

impl IncidentReplayPackage {
    /// Serialize the replay package to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a replay package from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Minimize this replay package under a deterministic incident oracle.
    #[must_use]
    pub fn minimize_repro(
        &self,
        oracle: IncidentReplayOracle,
        config: IncidentReplayMinimizationConfig,
    ) -> IncidentReplayMinimizationReport {
        let mut issues = minimization_preflight_issues(self, &oracle);
        if !issues.is_empty() {
            let verdict = if issues
                .iter()
                .any(|issue| issue.kind == IncidentReplayMinimizationIssueKind::FlakyOracle)
            {
                IncidentReplayMinimizationVerdict::Inconclusive
            } else {
                IncidentReplayMinimizationVerdict::Blocked
            };
            return IncidentReplayMinimizationReport {
                verdict,
                package_id: self.package_id.clone(),
                repro: None,
                issues,
                steps: Vec::new(),
            };
        }

        let mut retained_sources = self.sources.clone();
        let mut removed_source_ids = Vec::new();
        let mut retained_feature_flags = sorted_strings(self.determinism.feature_flags.clone());
        let mut removed_feature_flags = Vec::new();
        let mut steps = Vec::new();
        let required_roles = oracle.normalized_required_roles();
        let mut exhausted = false;

        for candidate in removable_sources(self, &required_roles) {
            if steps.len() >= config.step_budget {
                exhausted = true;
                push_budget_step(
                    &mut steps,
                    replay_unit_count(&retained_sources, &retained_feature_flags),
                );
                break;
            }

            let before = replay_unit_count(&retained_sources, &retained_feature_flags);
            let mut trial = retained_sources.clone();
            trial.retain(|source| source.source_id != candidate.source_id);
            let preserved = oracle_preserved(&trial, &oracle);
            if preserved {
                retained_sources = trial;
                removed_source_ids.push(candidate.source_id.clone());
            }
            let after = replay_unit_count(&retained_sources, &retained_feature_flags);
            steps.push(IncidentReplayShrinkStep {
                step_index: steps.len(),
                kind: if preserved {
                    IncidentReplayShrinkStepKind::RemoveSource
                } else {
                    IncidentReplayShrinkStepKind::KeepRequired
                },
                candidate: candidate.source_id,
                accepted: preserved,
                before_units: before,
                after_units: after,
                oracle_preserved: preserved,
                reason: if preserved {
                    "source removal preserved incident oracle".to_string()
                } else {
                    "source retained because oracle would not hold".to_string()
                },
            });
        }

        if !exhausted && config.shrink_feature_flags {
            for flag in sorted_strings(retained_feature_flags.clone()) {
                if steps.len() >= config.step_budget {
                    exhausted = true;
                    push_budget_step(
                        &mut steps,
                        replay_unit_count(&retained_sources, &retained_feature_flags),
                    );
                    break;
                }

                let before = replay_unit_count(&retained_sources, &retained_feature_flags);
                retained_feature_flags.retain(|existing| existing != &flag);
                removed_feature_flags.push(flag.clone());
                let after = replay_unit_count(&retained_sources, &retained_feature_flags);
                steps.push(IncidentReplayShrinkStep {
                    step_index: steps.len(),
                    kind: IncidentReplayShrinkStepKind::RemoveFeatureFlag,
                    candidate: flag,
                    accepted: true,
                    before_units: before,
                    after_units: after,
                    oracle_preserved: true,
                    reason: "feature flag removal preserved source-defined oracle".to_string(),
                });
            }
        }

        if exhausted {
            issues.push(IncidentReplayMinimizationIssue::new(
                IncidentReplayMinimizationIssueKind::BudgetExhausted,
                "config.step_budget",
                "step budget exhausted before minimization reached a fixed point",
            ));
        }

        let summary = IncidentReplayMinimizationSummary {
            original_units: replay_unit_count(&self.sources, &self.determinism.feature_flags),
            minimized_units: replay_unit_count(&retained_sources, &retained_feature_flags),
            accepted_steps: steps.iter().filter(|step| step.accepted).count(),
            rejected_steps: steps.iter().filter(|step| !step.accepted).count(),
            budget_exhausted: exhausted,
        };
        let repro = build_minimized_repro(
            self,
            oracle,
            retained_sources,
            removed_source_ids,
            retained_feature_flags,
            removed_feature_flags,
            steps.clone(),
            summary.clone(),
        );
        let verdict = if exhausted {
            IncidentReplayMinimizationVerdict::BudgetExhausted
        } else if summary.minimized_units < summary.original_units {
            IncidentReplayMinimizationVerdict::Minimized
        } else {
            IncidentReplayMinimizationVerdict::AlreadyMinimal
        };

        IncidentReplayMinimizationReport {
            verdict,
            package_id: self.package_id.clone(),
            repro: Some(repro),
            issues,
            steps,
        }
    }
}

/// Full importer report for bundle-to-replay-package conversion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReplayImportReport {
    /// Import verdict.
    pub verdict: IncidentReplayImportVerdict,
    /// Bundle identifier, when parsing reached a bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    /// Replay package emitted for successful imports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<IncidentReplayPackage>,
    /// Blocking reasons for malformed or blocked imports.
    pub blocked_reasons: Vec<IncidentReplayBlockReason>,
}

impl IncidentReplayImportReport {
    /// Return `true` when the importer emitted a replay package.
    #[must_use]
    pub const fn is_imported(&self) -> bool {
        matches!(self.verdict, IncidentReplayImportVerdict::Imported)
    }

    /// Return `true` if any blocker has the supplied kind.
    #[must_use]
    pub fn contains_kind(&self, kind: IncidentReplayBlockReasonKind) -> bool {
        self.blocked_reasons
            .iter()
            .any(|reason| reason.kind == kind)
    }
}

/// Incident oracle class preserved by minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentOracleKind {
    /// Panic or panic-shaped failure.
    Panic,
    /// Cancellation protocol leak.
    CancellationLeak,
    /// Permit, ack, lease, or other obligation leak.
    ObligationLeak,
    /// Region close did not imply quiescence.
    QuiescenceViolation,
    /// Protocol-level error expectation.
    ProtocolError,
    /// README, support matrix, or documentation claim drift.
    ClaimDrift,
    /// Remote proof command failure.
    ProofCommandFailure,
}

impl IncidentOracleKind {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::CancellationLeak => "cancellation_leak",
            Self::ObligationLeak => "obligation_leak",
            Self::QuiescenceViolation => "quiescence_violation",
            Self::ProtocolError => "protocol_error",
            Self::ClaimDrift => "claim_drift",
            Self::ProofCommandFailure => "proof_command_failure",
        }
    }
}

/// Oracle contract used by incident replay-package minimization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayOracle {
    /// Oracle class.
    pub kind: IncidentOracleKind,
    /// Deterministic signal that must remain true after shrinking.
    pub expected_signal: String,
    /// Whether the oracle is stable enough to minimize.
    pub stable: bool,
    /// Source roles that must remain present for the oracle to be meaningful.
    #[serde(default)]
    pub required_source_roles: Vec<IncidentReplaySourceRole>,
    /// Trace fingerprint that must remain present, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_trace_fingerprint: Option<String>,
}

impl IncidentReplayOracle {
    fn normalized_required_roles(&self) -> BTreeSet<IncidentReplaySourceRole> {
        self.required_source_roles.iter().copied().collect()
    }
}

/// Configuration for deterministic incident replay-package minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayMinimizationConfig {
    /// Maximum shrink attempts before returning budget-exhausted.
    pub step_budget: usize,
    /// Whether feature flags may be removed after source shrink attempts.
    pub shrink_feature_flags: bool,
}

impl Default for IncidentReplayMinimizationConfig {
    fn default() -> Self {
        Self {
            step_budget: 64,
            shrink_feature_flags: true,
        }
    }
}

/// Result verdict for incident replay minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayMinimizationVerdict {
    /// A smaller repro was emitted.
    Minimized,
    /// The input already represented a minimal repro under the oracle.
    AlreadyMinimal,
    /// The minimizer stopped before reaching a fixed point.
    BudgetExhausted,
    /// The oracle was flaky or nondeterministic.
    Inconclusive,
    /// The input cannot be minimized.
    Blocked,
}

/// Typed blocker or inconclusive reason for replay minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayMinimizationIssueKind {
    /// Replay package has no source units.
    EmptyTrace,
    /// Oracle was not stable.
    FlakyOracle,
    /// Step budget was exhausted before reaching a fixed point.
    BudgetExhausted,
    /// Required oracle source role was absent.
    MissingOracleSourceRole,
    /// Required oracle trace fingerprint was absent.
    MissingOracleTraceFingerprint,
}

impl IncidentReplayMinimizationIssueKind {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyTrace => "empty_trace",
            Self::FlakyOracle => "flaky_oracle",
            Self::BudgetExhausted => "budget_exhausted",
            Self::MissingOracleSourceRole => "missing_oracle_source_role",
            Self::MissingOracleTraceFingerprint => "missing_oracle_trace_fingerprint",
        }
    }
}

/// One minimization blocker or inconclusive reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayMinimizationIssue {
    /// Issue class.
    pub kind: IncidentReplayMinimizationIssueKind,
    /// Field associated with the issue.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl IncidentReplayMinimizationIssue {
    fn new(
        kind: IncidentReplayMinimizationIssueKind,
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

/// Shrink operation kind recorded in minimization provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReplayShrinkStepKind {
    /// Attempted to remove one replay source.
    RemoveSource,
    /// Attempted to remove one feature flag.
    RemoveFeatureFlag,
    /// Candidate had to remain to preserve the oracle.
    KeepRequired,
    /// Budget was exhausted.
    BudgetExhausted,
}

/// One deterministic shrink decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayShrinkStep {
    /// Zero-based shrink step index.
    pub step_index: usize,
    /// Shrink operation.
    pub kind: IncidentReplayShrinkStepKind,
    /// Candidate unit considered.
    pub candidate: String,
    /// Whether the candidate removal was accepted.
    pub accepted: bool,
    /// Size before the decision.
    pub before_units: usize,
    /// Size after the decision.
    pub after_units: usize,
    /// Whether the oracle remained true for the candidate.
    pub oracle_preserved: bool,
    /// Deterministic reason for the decision.
    pub reason: String,
}

/// Summary of a minimization run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayMinimizationSummary {
    /// Input replay unit count.
    pub original_units: usize,
    /// Output replay unit count.
    pub minimized_units: usize,
    /// Number of accepted shrink steps.
    pub accepted_steps: usize,
    /// Number of rejected shrink steps.
    pub rejected_steps: usize,
    /// Whether budget was exhausted.
    pub budget_exhausted: bool,
}

/// Stable minimized repro package emitted by incident minimization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentMinimizedReplayRepro {
    /// Minimized repro schema version.
    pub schema_version: u32,
    /// Stable repro identifier.
    pub repro_id: String,
    /// Source replay package identifier.
    pub source_package_id: String,
    /// Source incident bundle identifier.
    pub bundle_id: String,
    /// Oracle preserved by this repro.
    pub oracle: IncidentReplayOracle,
    /// Sources retained in the repro.
    pub retained_sources: Vec<IncidentReplaySource>,
    /// Source IDs removed by minimization.
    pub removed_source_ids: Vec<String>,
    /// Feature flags retained in the repro.
    pub retained_feature_flags: Vec<String>,
    /// Feature flags removed by minimization.
    pub removed_feature_flags: Vec<String>,
    /// Original replay command metadata.
    pub command: IncidentCommand,
    /// Original replay determinism metadata, with retained feature flags.
    pub determinism: IncidentDeterminism,
    /// Original capture provenance.
    pub provenance: IncidentProvenance,
    /// Shrink decisions in deterministic order.
    pub steps: Vec<IncidentReplayShrinkStep>,
    /// Minimization summary.
    pub summary: IncidentReplayMinimizationSummary,
}

impl IncidentMinimizedReplayRepro {
    /// Serialize the minimized repro to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse a minimized repro from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Full minimization report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReplayMinimizationReport {
    /// Minimization verdict.
    pub verdict: IncidentReplayMinimizationVerdict,
    /// Source package identifier.
    pub package_id: String,
    /// Repro emitted for minimized or already-minimal inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro: Option<IncidentMinimizedReplayRepro>,
    /// Issues or inconclusive reasons.
    pub issues: Vec<IncidentReplayMinimizationIssue>,
    /// Shrink decisions, including rejected candidates and budget stop.
    pub steps: Vec<IncidentReplayShrinkStep>,
}

impl IncidentReplayMinimizationReport {
    /// Return `true` if a minimized or already-minimal repro was emitted.
    #[must_use]
    pub const fn has_repro(&self) -> bool {
        self.repro.is_some()
    }

    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_issue(&self, kind: IncidentReplayMinimizationIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Durable proof target selected for a minimized incident repro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRegressionProofTarget {
    /// Inline unit-level regression test.
    UnitTest,
    /// Repository integration test target.
    IntegrationTest,
    /// Golden artifact or snapshot fixture.
    GoldenArtifact,
    /// Fuzzer seed corpus entry.
    FuzzSeed,
    /// RFC or conformance fixture.
    ConformanceFixture,
    /// Deterministic fixture only; not executable as a normal regression yet.
    FixtureOnly,
    /// Follow-up blocker bead instead of a committed proof.
    BlockerBead,
}

impl IncidentRegressionProofTarget {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnitTest => "unit_test",
            Self::IntegrationTest => "integration_test",
            Self::GoldenArtifact => "golden_artifact",
            Self::FuzzSeed => "fuzz_seed",
            Self::ConformanceFixture => "conformance_fixture",
            Self::FixtureOnly => "fixture_only",
            Self::BlockerBead => "blocker_bead",
        }
    }
}

/// Promotion outcome for a minimized incident repro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRegressionPromotionVerdict {
    /// A normal executable proof artifact was emitted.
    Promoted,
    /// A fixture-only proof artifact was emitted.
    FixtureOnly,
    /// Promotion was blocked with typed reasons.
    Blocked,
}

/// Typed reason a minimized repro cannot be promoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentRegressionPromotionBlockKind {
    /// The requested proof target does not fit the repro oracle/source shape.
    UnsupportedPromotionTarget,
    /// A proof seed with the same deterministic identity already exists.
    DuplicateSeed,
    /// A retained fixture hash no longer matches the expected hash.
    StaleFixtureHash,
    /// No redaction policy was supplied for the promoted proof artifact.
    MissingRedactionPolicy,
    /// The repro command cannot be executed through `rch exec`.
    ProofCommandNotRch,
    /// A blocker-bead promotion target omitted the follow-up bead id.
    MissingBlockerBead,
}

impl IncidentRegressionPromotionBlockKind {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPromotionTarget => "unsupported_promotion_target",
            Self::DuplicateSeed => "duplicate_seed",
            Self::StaleFixtureHash => "stale_fixture_hash",
            Self::MissingRedactionPolicy => "missing_redaction_policy",
            Self::ProofCommandNotRch => "proof_command_not_rch",
            Self::MissingBlockerBead => "missing_blocker_bead",
        }
    }
}

/// One typed promotion blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRegressionPromotionBlock {
    /// Blocker class.
    pub kind: IncidentRegressionPromotionBlockKind,
    /// Field or source id associated with the blocker.
    pub field: String,
    /// Human-readable blocked reason.
    pub message: String,
}

impl IncidentRegressionPromotionBlock {
    fn new(
        kind: IncidentRegressionPromotionBlockKind,
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

/// Operator policy for promoting a minimized repro into durable regression proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRegressionPromotionPolicy {
    /// Optional explicit target. When absent, the target is selected from the oracle/source shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<IncidentRegressionProofTarget>,
    /// Seed identities that are already committed and must not be duplicated.
    #[serde(default)]
    pub existing_seed_ids: Vec<String>,
    /// Expected source hashes keyed by retained source id.
    #[serde(default)]
    pub expected_fixture_hashes: BTreeMap<String, String>,
    /// Redaction policy id to preserve in the emitted proof artifact.
    pub redaction_policy_id: String,
    /// Whether a fixture-only proof is allowed when the repro is not directly executable.
    #[serde(default)]
    pub allow_fixture_only: bool,
    /// Follow-up bead id used when the selected target is [`IncidentRegressionProofTarget::BlockerBead`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_bead_id: Option<String>,
}

impl Default for IncidentRegressionPromotionPolicy {
    fn default() -> Self {
        Self {
            target: None,
            existing_seed_ids: Vec::new(),
            expected_fixture_hashes: BTreeMap::new(),
            redaction_policy_id: "incident-redaction-v1".to_string(),
            allow_fixture_only: false,
            blocked_bead_id: None,
        }
    }
}

/// Reproduction command preserved in a regression proof artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRegressionProofCommand {
    /// Original command metadata.
    pub command: IncidentCommand,
    /// Deterministic single-line rendering for reports and operators.
    pub command_line: String,
    /// Whether the command satisfies the repository's remote-first proof rule.
    pub executable_through_rch: bool,
    /// Typed text when the command is not executable through `rch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
}

/// Stable proof artifact emitted by incident repro promotion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentRegressionProofArtifact {
    /// Proof schema version.
    pub schema_version: u32,
    /// Stable proof identifier.
    pub proof_id: String,
    /// Selected promotion target.
    pub target: IncidentRegressionProofTarget,
    /// Source minimized repro identifier.
    pub source_repro_id: String,
    /// Source replay package identifier.
    pub source_package_id: String,
    /// Source incident bundle identifier.
    pub bundle_id: String,
    /// Oracle preserved by the proof.
    pub oracle: IncidentReplayOracle,
    /// Minimization summary preserved from the repro.
    pub minimization_summary: IncidentReplayMinimizationSummary,
    /// Retained feature flags from the minimized repro.
    pub retained_feature_flags: Vec<String>,
    /// Retained source hashes keyed by source id.
    pub retained_source_hashes: BTreeMap<String, String>,
    /// Provenance edges from bundle source to replay role.
    pub source_provenance_edges: Vec<String>,
    /// Proof commands or blocked command rows.
    pub proof_commands: Vec<IncidentRegressionProofCommand>,
    /// Deterministic seed identity used for duplicate detection.
    pub seed_id: String,
    /// Redaction policy carried forward into the proof artifact.
    pub redaction_policy_id: String,
    /// Original capture provenance.
    pub provenance: IncidentProvenance,
    /// Follow-up blocker bead when promotion cannot become an executable proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_bead_id: Option<String>,
}

/// Full promotion report for a minimized incident repro.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentRegressionPromotionReport {
    /// Promotion verdict.
    pub verdict: IncidentRegressionPromotionVerdict,
    /// Selected or requested target.
    pub target: IncidentRegressionProofTarget,
    /// Source minimized repro identifier.
    pub repro_id: String,
    /// Proof artifact for promoted or fixture-only verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<IncidentRegressionProofArtifact>,
    /// Typed blockers for failed promotion.
    pub blocks: Vec<IncidentRegressionPromotionBlock>,
}

impl IncidentRegressionPromotionReport {
    /// Return `true` when this report emitted a proof artifact.
    #[must_use]
    pub const fn has_proof(&self) -> bool {
        self.proof.is_some()
    }

    /// Return `true` if any blocker has the supplied kind.
    #[must_use]
    pub fn contains_block(&self, kind: IncidentRegressionPromotionBlockKind) -> bool {
        self.blocks.iter().any(|block| block.kind == kind)
    }
}

/// Aggregate status for an operator-facing incident proof report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentProofReportStatus {
    /// Import, minimization, promotion, and proof command metadata are complete.
    Pass,
    /// An executable proof exists, but the proof is known to fail.
    Fail,
    /// The pipeline stopped on a typed blocker.
    Blocked,
    /// The evidence is deterministic but retained as a fixture instead of an executable regression.
    FixtureOnly,
    /// The minimizer or oracle was inconclusive.
    Flaky,
    /// The source or requested target is unsupported by this report schema.
    Unsupported,
    /// The pipeline reached an explicit no-win/fallback outcome.
    NoWin,
}

impl IncidentProofReportStatus {
    /// Return the stable string tag for JSONL and artifact catalogs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Blocked => "blocked",
            Self::FixtureOnly => "fixture_only",
            Self::Flaky => "flaky",
            Self::Unsupported => "unsupported",
            Self::NoWin => "no_win",
        }
    }
}

/// Operator support class derived from the aggregate proof status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentProofSupportClass {
    /// The report can be checked by an executable regression proof.
    ExecutableRegression,
    /// The report is a retained deterministic fixture.
    FixtureOnly,
    /// Human or follow-up agent work is required.
    FollowUpRequired,
    /// The source or target vocabulary is not supported.
    Unsupported,
    /// The pipeline reached an explicit no-win/fallback outcome.
    NoWin,
}

impl IncidentProofSupportClass {
    /// Return the stable string tag for JSONL and artifact catalogs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutableRegression => "executable_regression",
            Self::FixtureOnly => "fixture_only",
            Self::FollowUpRequired => "follow_up_required",
            Self::Unsupported => "unsupported",
            Self::NoWin => "no_win",
        }
    }
}

/// Evidence quality assigned to an operator-facing proof report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentProofEvidenceQuality {
    /// Evidence is complete enough to trust as a regression closeout.
    Trusted,
    /// Evidence is deterministic but incomplete or fixture-only.
    Partial,
    /// Evidence is blocked and must not be counted as success.
    Blocked,
    /// Evidence is rejected by a failing executable proof.
    Rejected,
}

impl IncidentProofEvidenceQuality {
    /// Return the stable string tag for JSONL and artifact catalogs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

/// Operator-facing closeout report linking incident input to replay, minimization, and proof output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentProofReport {
    /// Proof report schema version.
    pub schema_version: u32,
    /// Stable report identifier.
    pub report_id: String,
    /// Human or automation supplied incident identifier.
    pub incident_id: String,
    /// Source replay package identifier, when import succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_package_id: Option<String>,
    /// Source minimized repro identifier, when minimization emitted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repro_id: Option<String>,
    /// Source regression proof identifier, when promotion emitted one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_proof_id: Option<String>,
    /// Redaction policy id used for this proof report.
    pub redaction_policy_id: String,
    /// Whether the redaction pass is complete for all report material.
    pub redaction_passed: bool,
    /// Importer verdict.
    pub importer_verdict: IncidentReplayImportVerdict,
    /// Minimizer verdict.
    pub minimizer_verdict: IncidentReplayMinimizationVerdict,
    /// Regression promotion verdict.
    pub promotion_verdict: IncidentRegressionPromotionVerdict,
    /// Aggregate report status.
    pub status: IncidentProofReportStatus,
    /// Support class derived from the status.
    pub support_class: IncidentProofSupportClass,
    /// Evidence quality derived from the status.
    pub evidence_quality: IncidentProofEvidenceQuality,
    /// Oracle preserved by the minimized repro or promoted proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle: Option<IncidentReplayOracle>,
    /// Original capture provenance, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<IncidentProvenance>,
    /// Exact proof commands or blocked command rows.
    #[serde(default)]
    pub proof_commands: Vec<IncidentRegressionProofCommand>,
    /// Expected retained fixture hashes keyed by source id.
    #[serde(default)]
    pub expected_fixture_hashes: BTreeMap<String, String>,
    /// Actual retained source hashes keyed by source id.
    #[serde(default)]
    pub retained_source_hashes: BTreeMap<String, String>,
    /// Import, minimizer, or promotion block tags collected in deterministic order.
    #[serde(default)]
    pub block_kinds: Vec<String>,
    /// Concise human summary suitable for closeout mail or logs.
    pub human_summary: String,
}

/// Validation policy for incident proof report gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentProofReportGateConfig {
    /// Require executable `rch exec` proof commands for executable regression reports.
    pub require_executable_proof: bool,
}

impl Default for IncidentProofReportGateConfig {
    fn default() -> Self {
        Self {
            require_executable_proof: true,
        }
    }
}

/// Typed validation issue kind emitted by proof report gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentProofReportValidationIssueKind {
    /// The input report JSON did not parse.
    MalformedJson,
    /// The proof report schema version is not supported.
    UnsupportedSchemaVersion,
    /// A required field is missing or empty.
    MissingRequiredField,
    /// A report requiring executable proof omitted proof commands.
    MissingProofCommand,
    /// A proof command is not routed through `rch exec`.
    ProofCommandNotRch,
    /// A retained fixture hash does not match the expected hash.
    StaleFixtureHash,
    /// Redaction failed or sensitive material is present in unredacted report fields.
    RedactionFailure,
}

impl IncidentProofReportValidationIssueKind {
    /// Return the stable string tag for artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedJson => "malformed_json",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::MissingRequiredField => "missing_required_field",
            Self::MissingProofCommand => "missing_proof_command",
            Self::ProofCommandNotRch => "proof_command_not_rch",
            Self::StaleFixtureHash => "stale_fixture_hash",
            Self::RedactionFailure => "redaction_failure",
        }
    }
}

/// One proof report gate validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentProofReportValidationIssue {
    /// Issue class.
    pub kind: IncidentProofReportValidationIssueKind,
    /// Field associated with the issue.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

impl IncidentProofReportValidationIssue {
    fn new(
        kind: IncidentProofReportValidationIssueKind,
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

/// Fail-closed validation result for an incident proof report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentProofReportValidationReport {
    /// Whether the report is accepted by the configured gate.
    pub accepted: bool,
    /// Typed validation issues.
    pub issues: Vec<IncidentProofReportValidationIssue>,
}

impl IncidentProofReportValidationReport {
    /// Return `true` if any issue has the supplied kind.
    #[must_use]
    pub fn contains_issue(&self, kind: IncidentProofReportValidationIssueKind) -> bool {
        self.issues.iter().any(|issue| issue.kind == kind)
    }
}

/// Build an operator-facing proof report from importer, minimizer, and promotion output.
#[must_use]
pub fn build_incident_proof_report(
    incident_id: impl Into<String>,
    redaction_policy_id: impl Into<String>,
    import_report: &IncidentReplayImportReport,
    minimization_report: &IncidentReplayMinimizationReport,
    promotion_report: &IncidentRegressionPromotionReport,
    expected_fixture_hashes: BTreeMap<String, String>,
) -> IncidentProofReport {
    let incident_id = incident_id.into();
    let redaction_policy_id = redaction_policy_id.into();
    let status =
        aggregate_incident_proof_status(import_report, minimization_report, promotion_report);
    let support_class = support_class_for_status(status);
    let evidence_quality = evidence_quality_for_status(status);

    let proof = promotion_report.proof.as_ref();
    let source_package_id = proof
        .map(|proof| proof.source_package_id.clone())
        .or_else(|| {
            minimization_report
                .repro
                .as_ref()
                .map(|repro| repro.source_package_id.clone())
        })
        .or_else(|| {
            import_report
                .package
                .as_ref()
                .map(|package| package.package_id.clone())
        });
    let source_repro_id = proof
        .map(|proof| proof.source_repro_id.clone())
        .or_else(|| {
            minimization_report
                .repro
                .as_ref()
                .map(|repro| repro.repro_id.clone())
        });
    let source_proof_id = proof.map(|proof| proof.proof_id.clone());
    let oracle = proof.map(|proof| proof.oracle.clone()).or_else(|| {
        minimization_report
            .repro
            .as_ref()
            .map(|repro| repro.oracle.clone())
    });
    let provenance = proof.map(|proof| proof.provenance.clone()).or_else(|| {
        minimization_report
            .repro
            .as_ref()
            .map(|repro| repro.provenance.clone())
    });
    let proof_commands = proof
        .map(|proof| proof.proof_commands.clone())
        .unwrap_or_default();
    let retained_source_hashes = proof
        .map(|proof| proof.retained_source_hashes.clone())
        .or_else(|| {
            minimization_report.repro.as_ref().map(|repro| {
                repro
                    .retained_sources
                    .iter()
                    .map(|source| (source.source_id.clone(), source.content_hash.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
        })
        .unwrap_or_default();
    let block_kinds =
        collect_incident_report_block_kinds(import_report, minimization_report, promotion_report);

    let report_id = stable_incident_proof_report_id(
        &incident_id,
        source_package_id.as_deref(),
        source_repro_id.as_deref(),
        source_proof_id.as_deref(),
        status,
        &proof_commands,
        &expected_fixture_hashes,
        &retained_source_hashes,
        &block_kinds,
    );

    let mut report = IncidentProofReport {
        schema_version: INCIDENT_PROOF_REPORT_SCHEMA_VERSION,
        report_id,
        incident_id,
        source_package_id,
        source_repro_id,
        source_proof_id,
        redaction_policy_id,
        redaction_passed: true,
        importer_verdict: import_report.verdict,
        minimizer_verdict: minimization_report.verdict,
        promotion_verdict: promotion_report.verdict,
        status,
        support_class,
        evidence_quality,
        oracle,
        provenance,
        proof_commands,
        expected_fixture_hashes,
        retained_source_hashes,
        block_kinds,
        human_summary: String::new(),
    };
    report.human_summary = render_incident_proof_report_summary(&report);
    report
}

/// Render a concise human summary for closeout mail, CI logs, and operator review.
#[must_use]
pub fn render_incident_proof_report_summary(report: &IncidentProofReport) -> String {
    format!(
        "incident {} status={} support={} evidence={} import={} minimizer={} promotion={} proof_commands={} blocks={}",
        report.incident_id,
        report.status.as_str(),
        report.support_class.as_str(),
        report.evidence_quality.as_str(),
        serde_tag(&report.importer_verdict),
        serde_tag(&report.minimizer_verdict),
        serde_tag(&report.promotion_verdict),
        report.proof_commands.len(),
        if report.block_kinds.is_empty() {
            "none".to_string()
        } else {
            report.block_kinds.join(",")
        }
    )
}

/// Validate a report under a fail-closed gate policy.
#[must_use]
pub fn validate_incident_proof_report(
    report: &IncidentProofReport,
    config: IncidentProofReportGateConfig,
) -> IncidentProofReportValidationReport {
    let mut issues = Vec::new();

    if report.schema_version != INCIDENT_PROOF_REPORT_SCHEMA_VERSION {
        issues.push(IncidentProofReportValidationIssue::new(
            IncidentProofReportValidationIssueKind::UnsupportedSchemaVersion,
            "schema_version",
            format!(
                "unsupported schema version {}, expected {INCIDENT_PROOF_REPORT_SCHEMA_VERSION}",
                report.schema_version
            ),
        ));
    }
    validate_report_required_text("report_id", &report.report_id, &mut issues);
    validate_report_required_text("incident_id", &report.incident_id, &mut issues);
    validate_report_required_text(
        "redaction_policy_id",
        &report.redaction_policy_id,
        &mut issues,
    );
    validate_report_required_text("human_summary", &report.human_summary, &mut issues);

    if !report.redaction_passed {
        issues.push(IncidentProofReportValidationIssue::new(
            IncidentProofReportValidationIssueKind::RedactionFailure,
            "redaction_passed",
            "report redaction pass must be true",
        ));
    }
    if value_is_secret_like(&report.human_summary) {
        issues.push(IncidentProofReportValidationIssue::new(
            IncidentProofReportValidationIssueKind::RedactionFailure,
            "human_summary",
            "summary contains secret-like material",
        ));
    }
    for (index, command) in report.proof_commands.iter().enumerate() {
        let field = format!("proof_commands[{index}].command_line");
        if value_is_secret_like(&command.command_line) {
            issues.push(IncidentProofReportValidationIssue::new(
                IncidentProofReportValidationIssueKind::RedactionFailure,
                field.clone(),
                "proof command contains secret-like material",
            ));
        }
        if config.require_executable_proof
            && executable_report_requires_rch(report.status)
            && (!command.executable_through_rch
                || !command_line_is_rch_exec(&command.command_line)
                || command.command.program != "rch")
        {
            issues.push(IncidentProofReportValidationIssue::new(
                IncidentProofReportValidationIssueKind::ProofCommandNotRch,
                field,
                "executable proof command must be routed through rch exec",
            ));
        }
    }

    if config.require_executable_proof
        && executable_report_requires_rch(report.status)
        && report.proof_commands.is_empty()
    {
        issues.push(IncidentProofReportValidationIssue::new(
            IncidentProofReportValidationIssueKind::MissingProofCommand,
            "proof_commands",
            "executable proof report must include at least one proof command",
        ));
    }

    for (source_id, expected_hash) in &report.expected_fixture_hashes {
        let actual = report.retained_source_hashes.get(source_id);
        if actual != Some(expected_hash) {
            issues.push(IncidentProofReportValidationIssue::new(
                IncidentProofReportValidationIssueKind::StaleFixtureHash,
                format!("retained_source_hashes.{source_id}"),
                format!(
                    "expected retained source hash {expected_hash}, got {}",
                    actual.map_or("<missing>", String::as_str)
                ),
            ));
        }
    }

    IncidentProofReportValidationReport {
        accepted: issues.is_empty(),
        issues,
    }
}

/// Parse and validate a report JSON document under a fail-closed gate policy.
#[must_use]
pub fn validate_incident_proof_report_json(
    json: &str,
    config: IncidentProofReportGateConfig,
) -> IncidentProofReportValidationReport {
    match serde_json::from_str::<IncidentProofReport>(json) {
        Ok(report) => validate_incident_proof_report(&report, config),
        Err(error) => IncidentProofReportValidationReport {
            accepted: false,
            issues: vec![IncidentProofReportValidationIssue::new(
                IncidentProofReportValidationIssueKind::MalformedJson,
                "$",
                format!("incident proof report JSON did not parse: {error}"),
            )],
        },
    }
}

/// Promote a minimized repro into a regression proof artifact or typed blocker report.
#[must_use]
pub fn promote_minimized_incident_repro(
    repro: &IncidentMinimizedReplayRepro,
    policy: IncidentRegressionPromotionPolicy,
) -> IncidentRegressionPromotionReport {
    let target = policy
        .target
        .unwrap_or_else(|| select_regression_proof_target(repro, policy.allow_fixture_only));
    let seed_id = regression_seed_id(repro, target);
    let mut blocks = Vec::new();

    if !promotion_target_supported(repro, target, policy.allow_fixture_only) {
        blocks.push(IncidentRegressionPromotionBlock::new(
            IncidentRegressionPromotionBlockKind::UnsupportedPromotionTarget,
            "target",
            format!(
                "target {} does not preserve oracle {} for repro {}",
                target.as_str(),
                repro.oracle.kind.as_str(),
                repro.repro_id
            ),
        ));
    }
    if policy.existing_seed_ids.iter().any(|id| id == &seed_id) {
        blocks.push(IncidentRegressionPromotionBlock::new(
            IncidentRegressionPromotionBlockKind::DuplicateSeed,
            "determinism.seed",
            format!("promotion seed {seed_id} already exists"),
        ));
    }
    for (source_id, expected_hash) in &policy.expected_fixture_hashes {
        let actual_hash = repro
            .retained_sources
            .iter()
            .find(|source| source.source_id == *source_id)
            .map(|source| source.content_hash.as_str());
        if actual_hash != Some(expected_hash.as_str()) {
            blocks.push(IncidentRegressionPromotionBlock::new(
                IncidentRegressionPromotionBlockKind::StaleFixtureHash,
                format!("retained_sources.{source_id}.content_hash"),
                format!(
                    "expected retained source {source_id} hash {expected_hash}, got {:?}",
                    actual_hash.unwrap_or("<missing>")
                ),
            ));
        }
    }
    if policy.redaction_policy_id.is_empty() {
        blocks.push(IncidentRegressionPromotionBlock::new(
            IncidentRegressionPromotionBlockKind::MissingRedactionPolicy,
            "redaction_policy_id",
            "promotion requires an explicit redaction policy id",
        ));
    }

    let proof_command = regression_proof_command(&repro.command);
    if requires_executable_proof_command(target) && !proof_command.executable_through_rch {
        blocks.push(IncidentRegressionPromotionBlock::new(
            IncidentRegressionPromotionBlockKind::ProofCommandNotRch,
            "command",
            proof_command
                .blocked_reason
                .clone()
                .unwrap_or_else(|| "proof command must be executable through rch".to_string()),
        ));
    }
    if target == IncidentRegressionProofTarget::BlockerBead && policy.blocked_bead_id.is_none() {
        blocks.push(IncidentRegressionPromotionBlock::new(
            IncidentRegressionPromotionBlockKind::MissingBlockerBead,
            "blocked_bead_id",
            "blocker-bead promotion requires a follow-up bead id",
        ));
    }

    if !blocks.is_empty() {
        return IncidentRegressionPromotionReport {
            verdict: IncidentRegressionPromotionVerdict::Blocked,
            target,
            repro_id: repro.repro_id.clone(),
            proof: None,
            blocks,
        };
    }

    let proof = build_regression_proof_artifact(
        repro,
        target,
        seed_id,
        policy.redaction_policy_id,
        policy.blocked_bead_id,
        proof_command,
    );
    let verdict = if target == IncidentRegressionProofTarget::FixtureOnly {
        IncidentRegressionPromotionVerdict::FixtureOnly
    } else {
        IncidentRegressionPromotionVerdict::Promoted
    };

    IncidentRegressionPromotionReport {
        verdict,
        target,
        repro_id: repro.repro_id.clone(),
        proof: Some(proof),
        blocks,
    }
}

/// Minimize a replay package under a deterministic incident oracle.
#[must_use]
pub fn minimize_incident_replay_package(
    package: &IncidentReplayPackage,
    oracle: IncidentReplayOracle,
    config: IncidentReplayMinimizationConfig,
) -> IncidentReplayMinimizationReport {
    package.minimize_repro(oracle, config)
}

/// Import an incident bundle JSON document into a deterministic replay package report.
#[must_use]
pub fn import_incident_bundle_json(json: &str) -> IncidentReplayImportReport {
    match IncidentBundle::from_json(json) {
        Ok(bundle) => bundle.import_replay_package(),
        Err(error) => IncidentReplayImportReport {
            verdict: IncidentReplayImportVerdict::Malformed,
            bundle_id: None,
            package: None,
            blocked_reasons: vec![IncidentReplayBlockReason::new(
                IncidentReplayBlockReasonKind::MalformedJson,
                None,
                "$",
                format!("incident bundle JSON did not parse: {error}"),
            )],
        },
    }
}

impl IncidentBundle {
    /// Parse an incident bundle from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize the bundle to deterministic pretty JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate schema, determinism, provenance, paths, hashes, and redaction.
    #[must_use]
    pub fn validate(&self) -> IncidentValidationReport {
        let mut issues = Vec::new();
        self.validate_header(&mut issues);
        self.validate_sources(&mut issues);
        self.validate_command(&mut issues);
        self.validate_determinism(&mut issues);
        self.validate_privacy(&mut issues);
        self.validate_provenance(&mut issues);
        self.scan_metadata(&mut issues);

        let verdict = if issues.is_empty() {
            IncidentValidationVerdict::Accepted
        } else {
            IncidentValidationVerdict::Blocked
        };

        IncidentValidationReport {
            verdict,
            bundle_id: self.bundle_id.clone(),
            schema_version: self.schema_version,
            issues,
            fingerprint: self.fingerprint(),
        }
    }

    /// Import this bundle into a deterministic replay package or typed blocker report.
    #[must_use]
    pub fn import_replay_package(&self) -> IncidentReplayImportReport {
        let mut blockers = validation_blockers(&self.validate());
        append_import_source_blockers(self, &mut blockers);

        if !blockers.is_empty() {
            return IncidentReplayImportReport {
                verdict: IncidentReplayImportVerdict::Blocked,
                bundle_id: Some(self.bundle_id.clone()),
                package: None,
                blocked_reasons: blockers,
            };
        }

        let package = self.build_replay_package();
        IncidentReplayImportReport {
            verdict: IncidentReplayImportVerdict::Imported,
            bundle_id: Some(self.bundle_id.clone()),
            package: Some(package),
            blocked_reasons: Vec::new(),
        }
    }

    /// Compute a deterministic FNV-1a fingerprint over the bundle JSON.
    ///
    /// This is not a security hash. It is a stable local key for fixture
    /// comparison and replay package naming. Source payloads still carry
    /// explicit `sha256:` content hashes.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        fnv1a64(&bytes)
    }

    fn build_replay_package(&self) -> IncidentReplayPackage {
        let mut sources = self
            .sources
            .iter()
            .filter_map(import_source)
            .collect::<Vec<_>>();
        sources.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then_with(|| left.content_hash.cmp(&right.content_hash))
                .then_with(|| left.source_id.cmp(&right.source_id))
        });

        let source_digest = canonical_source_digest(&sources);
        let source_order = sources
            .iter()
            .map(|source| source.source_id.clone())
            .collect::<Vec<_>>();
        let trace_fingerprints = sources
            .iter()
            .filter_map(|source| source.trace_fingerprint.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let mut trace_metadata =
            crate::trace::replay::TraceMetadata::new(self.determinism.seed.unwrap_or(0))
                .with_config_hash(fnv1a64(self.determinism.config_hash.as_bytes()))
                .with_description(format!("incident:{}", self.bundle_id));
        trace_metadata.recorded_at = self.determinism.virtual_time_nanos.unwrap_or(0);

        let package_id = stable_replay_package_id(self, &sources, source_digest);
        IncidentReplayPackage {
            schema_version: INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION,
            package_id,
            bundle_id: self.bundle_id.clone(),
            bundle_fingerprint: self.fingerprint(),
            sources,
            trace_metadata,
            command: self.command.clone(),
            determinism: self.determinism.clone(),
            provenance: self.provenance.clone(),
            canonicalization: IncidentReplayCanonicalization {
                source_digest,
                source_order,
                trace_fingerprints,
                normalization_strategy: "stable-source-digest-for-geodesic-ready-trace-import"
                    .to_string(),
            },
        }
    }

    fn validate_header(&self, issues: &mut Vec<IncidentValidationIssue>) {
        if self.schema_version != INCIDENT_BUNDLE_SCHEMA_VERSION {
            issues.push(IncidentValidationIssue::new(
                IncidentValidationIssueKind::UnsupportedSchemaVersion,
                "schema_version",
                format!(
                    "unsupported schema version {}, expected {INCIDENT_BUNDLE_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_required_text("bundle_id", &self.bundle_id, MAX_ID_BYTES, issues);
        if self.sources.is_empty() {
            issues.push(IncidentValidationIssue::new(
                IncidentValidationIssueKind::MissingRequiredField,
                "sources",
                "incident bundle must include at least one source",
            ));
        }
    }

    fn validate_sources(&self, issues: &mut Vec<IncidentValidationIssue>) {
        let mut seen = BTreeSet::new();
        for (index, source) in self.sources.iter().enumerate() {
            let prefix = format!("sources[{index}]");
            validate_required_text(
                format!("{prefix}.source_id"),
                &source.source_id,
                MAX_ID_BYTES,
                issues,
            );
            if !source.source_id.is_empty() && !seen.insert(source.source_id.as_str()) {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::DuplicateSourceId,
                    format!("{prefix}.source_id"),
                    format!("duplicate source id {}", source.source_id),
                ));
            }
            if source.kind.is_unsupported() {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::UnsupportedSourceKind,
                    format!("{prefix}.kind"),
                    format!("unsupported source kind {}", source.kind.as_str()),
                ));
            }
            validate_content_hash(
                format!("{prefix}.content_hash"),
                &source.content_hash,
                issues,
            );
            if let Some(path) = &source.artifact_path {
                validate_repo_relative_path(format!("{prefix}.artifact_path"), path, issues);
            }
            if matches!(
                source.redaction_status,
                IncidentRedactionStatus::RequiredButMissing
            ) {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::RedactionRequiredButMissing,
                    format!("{prefix}.redaction_status"),
                    "source requires redaction but no completed pass is recorded",
                ));
            }
            if let Some(snippet) = &source.payload_snippet {
                validate_text_size(
                    format!("{prefix}.payload_snippet"),
                    snippet,
                    MAX_PAYLOAD_SNIPPET_BYTES,
                    issues,
                );
                validate_text_safety(format!("{prefix}.payload_snippet"), snippet, issues);
                if source.redaction_status != IncidentRedactionStatus::Redacted
                    && value_is_secret_like(snippet)
                {
                    issues.push(IncidentValidationIssue::new(
                        IncidentValidationIssueKind::SecretLikeMaterial,
                        format!("{prefix}.payload_snippet"),
                        "secret-like payload snippet is not marked redacted",
                    ));
                }
            }
            scan_json_map(
                &format!("{prefix}.metadata"),
                &source.metadata,
                source.redaction_status,
                issues,
            );
        }
    }

    fn validate_command(&self, issues: &mut Vec<IncidentValidationIssue>) {
        validate_required_text(
            "command.program",
            &self.command.program,
            MAX_FIELD_BYTES,
            issues,
        );
        validate_repo_relative_path("command.working_dir", &self.command.working_dir, issues);
        for (index, arg) in self.command.args.iter().enumerate() {
            let field = format!("command.args[{index}]");
            validate_text_size(&field, arg, MAX_FIELD_BYTES, issues);
            validate_text_safety(&field, arg, issues);
            if value_is_secret_like(arg) {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::SecretLikeMaterial,
                    field,
                    "secret-like command argument must not appear in incident bundles",
                ));
            }
        }
        for (index, env) in self.command.env.iter().enumerate() {
            let key_field = format!("command.env[{index}].key");
            let value_field = format!("command.env[{index}].value");
            validate_required_text(&key_field, &env.key, MAX_FIELD_BYTES, issues);
            validate_text_size(&value_field, &env.value, MAX_FIELD_BYTES, issues);
            validate_text_safety(&value_field, &env.value, issues);
            if key_is_secret_like(&env.key) || value_is_secret_like(&env.value) {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::SecretLikeMaterial,
                    value_field,
                    "secret-like environment variable must be redacted before bundling",
                ));
            }
        }
    }

    fn validate_determinism(&self, issues: &mut Vec<IncidentValidationIssue>) {
        validate_content_hash(
            "determinism.config_hash",
            &self.determinism.config_hash,
            issues,
        );
        validate_required_text(
            "determinism.target_triple",
            &self.determinism.target_triple,
            MAX_FIELD_BYTES,
            issues,
        );
        let mut seen = BTreeSet::new();
        for (index, flag) in self.determinism.feature_flags.iter().enumerate() {
            let field = format!("determinism.feature_flags[{index}]");
            validate_required_text(&field, flag, MAX_FIELD_BYTES, issues);
            if !seen.insert(flag.as_str()) {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::DuplicateFeatureFlag,
                    field,
                    format!("duplicate feature flag {flag}"),
                ));
            }
        }
    }

    fn validate_privacy(&self, issues: &mut Vec<IncidentValidationIssue>) {
        validate_required_text(
            "privacy.redaction_policy_id",
            &self.privacy.redaction_policy_id,
            MAX_ID_BYTES,
            issues,
        );
        if self.privacy.redaction_policy_id.is_empty() {
            issues.push(IncidentValidationIssue::new(
                IncidentValidationIssueKind::MissingRedactionPolicy,
                "privacy.redaction_policy_id",
                "redaction policy id is required for fail-closed import",
            ));
        }
        if self.privacy.classification.requires_redaction()
            && self.privacy.redaction_status != IncidentRedactionStatus::Redacted
        {
            issues.push(IncidentValidationIssue::new(
                IncidentValidationIssueKind::RedactionRequiredButMissing,
                "privacy.redaction_status",
                "confidential or secret incident bundle must be redacted",
            ));
        }
        if matches!(
            self.privacy.redaction_status,
            IncidentRedactionStatus::RequiredButMissing
        ) {
            issues.push(IncidentValidationIssue::new(
                IncidentValidationIssueKind::RedactionRequiredButMissing,
                "privacy.redaction_status",
                "bundle requires redaction but no completed pass is recorded",
            ));
        }
    }

    fn validate_provenance(&self, issues: &mut Vec<IncidentValidationIssue>) {
        validate_required_text(
            "provenance.capture_id",
            &self.provenance.capture_id,
            MAX_ID_BYTES,
            issues,
        );
        validate_required_text(
            "provenance.origin",
            &self.provenance.origin,
            MAX_FIELD_BYTES,
            issues,
        );
        validate_required_text(
            "provenance.reporter",
            &self.provenance.reporter,
            MAX_FIELD_BYTES,
            issues,
        );
        if let Some(commit) = &self.provenance.captured_commit {
            validate_text_size(
                "provenance.captured_commit",
                commit,
                MAX_FIELD_BYTES,
                issues,
            );
        }
        if let Some(bead) = &self.provenance.related_bead_id {
            validate_text_size("provenance.related_bead_id", bead, MAX_ID_BYTES, issues);
        }
    }

    fn scan_metadata(&self, issues: &mut Vec<IncidentValidationIssue>) {
        scan_json_map(
            "metadata",
            &self.metadata,
            self.privacy.redaction_status,
            issues,
        );
    }
}

fn validation_blockers(report: &IncidentValidationReport) -> Vec<IncidentReplayBlockReason> {
    report
        .issues
        .iter()
        .map(|issue| {
            let kind = match issue.kind {
                IncidentValidationIssueKind::UnsupportedSourceKind => {
                    IncidentReplayBlockReasonKind::UnsupportedSourceKind
                }
                IncidentValidationIssueKind::RedactionRequiredButMissing => {
                    IncidentReplayBlockReasonKind::RedactionRequiredButMissing
                }
                IncidentValidationIssueKind::UnsupportedSchemaVersion
                | IncidentValidationIssueKind::MissingRequiredField
                | IncidentValidationIssueKind::DuplicateSourceId
                | IncidentValidationIssueKind::MissingRedactionPolicy
                | IncidentValidationIssueKind::SecretLikeMaterial
                | IncidentValidationIssueKind::OversizedField
                | IncidentValidationIssueKind::ExternalPath
                | IncidentValidationIssueKind::MalformedContentHash
                | IncidentValidationIssueKind::BinaryLikePayload
                | IncidentValidationIssueKind::DuplicateFeatureFlag => {
                    IncidentReplayBlockReasonKind::ValidationIssue
                }
            };
            IncidentReplayBlockReason::new(
                kind,
                source_id_from_field(&issue.field),
                issue.field.clone(),
                issue.message.clone(),
            )
        })
        .collect()
}

fn append_import_source_blockers(
    bundle: &IncidentBundle,
    blockers: &mut Vec<IncidentReplayBlockReason>,
) {
    for (index, source) in bundle.sources.iter().enumerate() {
        let prefix = format!("sources[{index}]");
        if IncidentReplaySourceRole::from_kind(&source.kind).is_none() {
            blockers.push(IncidentReplayBlockReason::new(
                IncidentReplayBlockReasonKind::UnsupportedSourceKind,
                Some(source.source_id.clone()),
                format!("{prefix}.kind"),
                format!("source kind {} cannot be imported", source.kind.as_str()),
            ));
        }
        if !source_has_payload_evidence(source) {
            blockers.push(IncidentReplayBlockReason::new(
                IncidentReplayBlockReasonKind::MissingSourcePayload,
                Some(source.source_id.clone()),
                prefix.clone(),
                "source must include artifact_path, payload_snippet, or metadata payload evidence",
            ));
        }
        if let Some(observed_hash) = observed_content_hash(source)
            && observed_hash != source.content_hash
        {
            blockers.push(IncidentReplayBlockReason::new(
                IncidentReplayBlockReasonKind::StaleContentHash,
                Some(source.source_id.clone()),
                format!("{prefix}.metadata.observed_content_hash"),
                format!(
                    "observed source hash {observed_hash} does not match declared {}",
                    source.content_hash
                ),
            ));
        }
    }
}

fn import_source(source: &IncidentSource) -> Option<IncidentReplaySource> {
    let role = IncidentReplaySourceRole::from_kind(&source.kind)?;
    Some(IncidentReplaySource {
        source_id: source.source_id.clone(),
        role,
        kind: source.kind.clone(),
        artifact_path: source.artifact_path.clone(),
        content_hash: source.content_hash.clone(),
        content_bytes: source.content_bytes,
        trace_fingerprint: source
            .metadata
            .get("trace_fingerprint")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        provenance_edge: format!("{}->{}", source.source_id, role.as_str()),
    })
}

fn source_has_payload_evidence(source: &IncidentSource) -> bool {
    source.content_bytes > 0
        && (source
            .artifact_path
            .as_ref()
            .is_some_and(|path| !path.is_empty())
            || source
                .payload_snippet
                .as_ref()
                .is_some_and(|snippet| !snippet.is_empty())
            || !source.metadata.is_empty())
}

fn observed_content_hash(source: &IncidentSource) -> Option<String> {
    source
        .metadata
        .get("observed_content_hash")
        .or_else(|| source.metadata.get("computed_content_hash"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn source_id_from_field(field: &str) -> Option<String> {
    if !field.starts_with("sources[") {
        return None;
    }
    Some(field.to_string())
}

fn canonical_source_digest(sources: &[IncidentReplaySource]) -> u64 {
    let mut key = String::new();
    for source in sources {
        key.push_str(source.role.as_str());
        key.push('|');
        key.push_str(&source.source_id);
        key.push('|');
        key.push_str(&source.content_hash);
        key.push('|');
        key.push_str(source.artifact_path.as_deref().unwrap_or(""));
        key.push('|');
        key.push_str(source.trace_fingerprint.as_deref().unwrap_or(""));
        key.push('\n');
    }
    fnv1a64(key.as_bytes())
}

fn stable_replay_package_id(
    bundle: &IncidentBundle,
    sources: &[IncidentReplaySource],
    source_digest: u64,
) -> String {
    let mut feature_flags = bundle.determinism.feature_flags.clone();
    feature_flags.sort();

    let mut env = bundle
        .command
        .env
        .iter()
        .map(|var| format!("{}={}", var.key, var.value))
        .collect::<Vec<_>>();
    env.sort();

    let mut key = String::new();
    key.push_str("incident-replay-package-v1\n");
    key.push_str(&format!("source_digest={source_digest:016x}\n"));
    key.push_str(&format!("seed={:?}\n", bundle.determinism.seed));
    key.push_str(&format!(
        "schedule_seed={:?}\n",
        bundle.determinism.schedule_seed
    ));
    key.push_str(&format!(
        "virtual_time_nanos={:?}\n",
        bundle.determinism.virtual_time_nanos
    ));
    key.push_str(&format!("config_hash={}\n", bundle.determinism.config_hash));
    key.push_str(&format!("target={}\n", bundle.determinism.target_triple));
    key.push_str(&format!("features={}\n", feature_flags.join(",")));
    key.push_str(&format!("program={}\n", bundle.command.program));
    key.push_str(&format!("args={}\n", bundle.command.args.join("\u{1f}")));
    key.push_str(&format!("env={}\n", env.join("\u{1f}")));
    for source in sources {
        key.push_str(source.role.as_str());
        key.push('|');
        key.push_str(&source.content_hash);
        key.push('|');
        key.push_str(source.trace_fingerprint.as_deref().unwrap_or(""));
        key.push('\n');
    }

    format!("incident-replay-v1:{:016x}", fnv1a64(key.as_bytes()))
}

fn minimization_preflight_issues(
    package: &IncidentReplayPackage,
    oracle: &IncidentReplayOracle,
) -> Vec<IncidentReplayMinimizationIssue> {
    let mut issues = Vec::new();
    if package.sources.is_empty() {
        issues.push(IncidentReplayMinimizationIssue::new(
            IncidentReplayMinimizationIssueKind::EmptyTrace,
            "sources",
            "replay package has no source units to minimize",
        ));
    }
    if !oracle.stable {
        issues.push(IncidentReplayMinimizationIssue::new(
            IncidentReplayMinimizationIssueKind::FlakyOracle,
            "oracle.stable",
            "incident oracle is marked unstable; minimization would be nondeterministic",
        ));
    }

    let package_roles = package
        .sources
        .iter()
        .map(|source| source.role)
        .collect::<BTreeSet<_>>();
    for role in oracle.normalized_required_roles() {
        if !package_roles.contains(&role) {
            issues.push(IncidentReplayMinimizationIssue::new(
                IncidentReplayMinimizationIssueKind::MissingOracleSourceRole,
                "oracle.required_source_roles",
                format!("required oracle source role {} is absent", role.as_str()),
            ));
        }
    }
    if let Some(required) = &oracle.required_trace_fingerprint {
        let present = package.sources.iter().any(|source| {
            source
                .trace_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| fingerprint == required)
        });
        if !present {
            issues.push(IncidentReplayMinimizationIssue::new(
                IncidentReplayMinimizationIssueKind::MissingOracleTraceFingerprint,
                "oracle.required_trace_fingerprint",
                format!("required oracle trace fingerprint {required} is absent"),
            ));
        }
    }
    issues
}

fn removable_sources(
    package: &IncidentReplayPackage,
    required_roles: &BTreeSet<IncidentReplaySourceRole>,
) -> Vec<IncidentReplaySource> {
    let mut candidates = package
        .sources
        .iter()
        .filter(|source| !required_roles.contains(&source.role))
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.content_hash.cmp(&right.content_hash))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    candidates
}

fn oracle_preserved(sources: &[IncidentReplaySource], oracle: &IncidentReplayOracle) -> bool {
    let roles = sources
        .iter()
        .map(|source| source.role)
        .collect::<BTreeSet<_>>();
    if !oracle
        .normalized_required_roles()
        .iter()
        .all(|role| roles.contains(role))
    {
        return false;
    }
    if let Some(required) = &oracle.required_trace_fingerprint {
        return sources.iter().any(|source| {
            source
                .trace_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| fingerprint == required)
        });
    }
    true
}

fn replay_unit_count(sources: &[IncidentReplaySource], feature_flags: &[String]) -> usize {
    sources.len() + feature_flags.len()
}

fn push_budget_step(steps: &mut Vec<IncidentReplayShrinkStep>, units: usize) {
    steps.push(IncidentReplayShrinkStep {
        step_index: steps.len(),
        kind: IncidentReplayShrinkStepKind::BudgetExhausted,
        candidate: "step_budget".to_string(),
        accepted: false,
        before_units: units,
        after_units: units,
        oracle_preserved: true,
        reason: "step budget exhausted before fixed point".to_string(),
    });
}

#[allow(clippy::too_many_arguments)]
fn build_minimized_repro(
    package: &IncidentReplayPackage,
    oracle: IncidentReplayOracle,
    retained_sources: Vec<IncidentReplaySource>,
    mut removed_source_ids: Vec<String>,
    retained_feature_flags: Vec<String>,
    mut removed_feature_flags: Vec<String>,
    steps: Vec<IncidentReplayShrinkStep>,
    summary: IncidentReplayMinimizationSummary,
) -> IncidentMinimizedReplayRepro {
    removed_source_ids.sort();
    removed_feature_flags.sort();
    let mut determinism = package.determinism.clone();
    determinism
        .feature_flags
        .clone_from(&retained_feature_flags);
    let repro_id = stable_minimized_repro_id(
        package,
        &oracle,
        &retained_sources,
        &removed_source_ids,
        &retained_feature_flags,
    );

    IncidentMinimizedReplayRepro {
        schema_version: INCIDENT_MINIMIZED_REPRO_SCHEMA_VERSION,
        repro_id,
        source_package_id: package.package_id.clone(),
        bundle_id: package.bundle_id.clone(),
        oracle,
        retained_sources,
        removed_source_ids,
        retained_feature_flags,
        removed_feature_flags,
        command: package.command.clone(),
        determinism,
        provenance: package.provenance.clone(),
        steps,
        summary,
    }
}

fn stable_minimized_repro_id(
    package: &IncidentReplayPackage,
    oracle: &IncidentReplayOracle,
    retained_sources: &[IncidentReplaySource],
    removed_source_ids: &[String],
    retained_feature_flags: &[String],
) -> String {
    let mut key = String::new();
    key.push_str("incident-minimized-repro-v1\n");
    key.push_str(&package.package_id);
    key.push('\n');
    key.push_str(oracle.kind.as_str());
    key.push('|');
    key.push_str(&oracle.expected_signal);
    key.push('|');
    key.push_str(
        oracle
            .required_trace_fingerprint
            .as_deref()
            .unwrap_or_default(),
    );
    key.push('\n');
    for source in retained_sources {
        key.push_str(source.role.as_str());
        key.push('|');
        key.push_str(&source.source_id);
        key.push('|');
        key.push_str(&source.content_hash);
        key.push('\n');
    }
    for source_id in removed_source_ids {
        key.push_str("removed:");
        key.push_str(source_id);
        key.push('\n');
    }
    for flag in retained_feature_flags {
        key.push_str("flag:");
        key.push_str(flag);
        key.push('\n');
    }
    format!("incident-min-repro-v1:{:016x}", fnv1a64(key.as_bytes()))
}

fn select_regression_proof_target(
    repro: &IncidentMinimizedReplayRepro,
    allow_fixture_only: bool,
) -> IncidentRegressionProofTarget {
    let has_role = |role| {
        repro
            .retained_sources
            .iter()
            .any(|source| source.role == role)
    };
    if has_role(IncidentReplaySourceRole::ConformanceFailure)
        || repro.oracle.kind == IncidentOracleKind::ProtocolError
    {
        IncidentRegressionProofTarget::ConformanceFixture
    } else if has_role(IncidentReplaySourceRole::ReadmeClaimFailure)
        || repro.oracle.kind == IncidentOracleKind::ClaimDrift
    {
        IncidentRegressionProofTarget::GoldenArtifact
    } else if has_role(IncidentReplaySourceRole::TraceLog)
        || has_role(IncidentReplaySourceRole::RchProofFailure)
        || repro.oracle.kind == IncidentOracleKind::ProofCommandFailure
    {
        IncidentRegressionProofTarget::IntegrationTest
    } else if has_role(IncidentReplaySourceRole::ReproNotes) && allow_fixture_only {
        IncidentRegressionProofTarget::FixtureOnly
    } else {
        IncidentRegressionProofTarget::UnitTest
    }
}

fn promotion_target_supported(
    repro: &IncidentMinimizedReplayRepro,
    target: IncidentRegressionProofTarget,
    allow_fixture_only: bool,
) -> bool {
    let has_role = |role| {
        repro
            .retained_sources
            .iter()
            .any(|source| source.role == role)
    };
    match target {
        IncidentRegressionProofTarget::UnitTest => {
            matches!(
                repro.oracle.kind,
                IncidentOracleKind::Panic
                    | IncidentOracleKind::CancellationLeak
                    | IncidentOracleKind::ObligationLeak
                    | IncidentOracleKind::QuiescenceViolation
            ) && has_role(IncidentReplaySourceRole::CrashPack)
        }
        IncidentRegressionProofTarget::IntegrationTest => {
            has_role(IncidentReplaySourceRole::CrashPack)
                || has_role(IncidentReplaySourceRole::TraceLog)
                || has_role(IncidentReplaySourceRole::SupportBundle)
                || has_role(IncidentReplaySourceRole::RchProofFailure)
                || repro.oracle.kind == IncidentOracleKind::ProofCommandFailure
        }
        IncidentRegressionProofTarget::GoldenArtifact => {
            has_role(IncidentReplaySourceRole::ReadmeClaimFailure)
                || repro.oracle.kind == IncidentOracleKind::ClaimDrift
        }
        IncidentRegressionProofTarget::FuzzSeed => {
            has_role(IncidentReplaySourceRole::TraceLog)
                || has_role(IncidentReplaySourceRole::CrashPack)
        }
        IncidentRegressionProofTarget::ConformanceFixture => {
            has_role(IncidentReplaySourceRole::ConformanceFailure)
                || repro.oracle.kind == IncidentOracleKind::ProtocolError
        }
        IncidentRegressionProofTarget::FixtureOnly => allow_fixture_only,
        IncidentRegressionProofTarget::BlockerBead => true,
    }
}

fn requires_executable_proof_command(target: IncidentRegressionProofTarget) -> bool {
    !matches!(
        target,
        IncidentRegressionProofTarget::FixtureOnly | IncidentRegressionProofTarget::BlockerBead
    )
}

fn regression_proof_command(command: &IncidentCommand) -> IncidentRegressionProofCommand {
    let command_line = render_incident_command(command);
    let executable_through_rch = command.program == "rch"
        && command.args.first().is_some_and(|arg| arg == "exec")
        && command.args.iter().any(|arg| arg == "cargo")
        && command
            .args
            .iter()
            .any(|arg| matches!(arg.as_str(), "test" | "check"));
    let blocked_reason = (!executable_through_rch).then(|| {
        format!("proof command must use `rch exec` with cargo test/check: {command_line}")
    });

    IncidentRegressionProofCommand {
        command: command.clone(),
        command_line,
        executable_through_rch,
        blocked_reason,
    }
}

fn render_incident_command(command: &IncidentCommand) -> String {
    let mut parts = command
        .env
        .iter()
        .map(|var| format!("{}={}", var.key, var.value))
        .collect::<Vec<_>>();
    parts.push(command.program.clone());
    parts.extend(command.args.clone());
    parts.join(" ")
}

fn regression_seed_id(
    repro: &IncidentMinimizedReplayRepro,
    target: IncidentRegressionProofTarget,
) -> String {
    let mut flags = repro.retained_feature_flags.clone();
    flags.sort();
    format!(
        "incident-regression-seed-v1:{}:{:?}:{:?}:{}:{}",
        target.as_str(),
        repro.determinism.seed,
        repro.determinism.schedule_seed,
        repro.determinism.config_hash,
        flags.join(",")
    )
}

fn build_regression_proof_artifact(
    repro: &IncidentMinimizedReplayRepro,
    target: IncidentRegressionProofTarget,
    seed_id: String,
    redaction_policy_id: String,
    blocked_bead_id: Option<String>,
    proof_command: IncidentRegressionProofCommand,
) -> IncidentRegressionProofArtifact {
    let retained_source_hashes = repro
        .retained_sources
        .iter()
        .map(|source| (source.source_id.clone(), source.content_hash.clone()))
        .collect::<BTreeMap<_, _>>();
    let source_provenance_edges = repro
        .retained_sources
        .iter()
        .map(|source| source.provenance_edge.clone())
        .collect::<Vec<_>>();
    let proof_id = stable_regression_proof_id(
        repro,
        target,
        &seed_id,
        &redaction_policy_id,
        &retained_source_hashes,
    );

    IncidentRegressionProofArtifact {
        schema_version: INCIDENT_REGRESSION_PROOF_SCHEMA_VERSION,
        proof_id,
        target,
        source_repro_id: repro.repro_id.clone(),
        source_package_id: repro.source_package_id.clone(),
        bundle_id: repro.bundle_id.clone(),
        oracle: repro.oracle.clone(),
        minimization_summary: repro.summary.clone(),
        retained_feature_flags: repro.retained_feature_flags.clone(),
        retained_source_hashes,
        source_provenance_edges,
        proof_commands: vec![proof_command],
        seed_id,
        redaction_policy_id,
        provenance: repro.provenance.clone(),
        blocked_bead_id,
    }
}

fn stable_regression_proof_id(
    repro: &IncidentMinimizedReplayRepro,
    target: IncidentRegressionProofTarget,
    seed_id: &str,
    redaction_policy_id: &str,
    retained_source_hashes: &BTreeMap<String, String>,
) -> String {
    let mut key = String::new();
    key.push_str("incident-regression-proof-v1\n");
    key.push_str(target.as_str());
    key.push('\n');
    key.push_str(&repro.repro_id);
    key.push('\n');
    key.push_str(repro.oracle.kind.as_str());
    key.push('|');
    key.push_str(&repro.oracle.expected_signal);
    key.push('\n');
    key.push_str(seed_id);
    key.push('\n');
    key.push_str(redaction_policy_id);
    key.push('\n');
    for (source_id, hash) in retained_source_hashes {
        key.push_str(source_id);
        key.push('|');
        key.push_str(hash);
        key.push('\n');
    }
    format!(
        "incident-regression-proof-v1:{:016x}",
        fnv1a64(key.as_bytes())
    )
}

fn aggregate_incident_proof_status(
    import_report: &IncidentReplayImportReport,
    minimization_report: &IncidentReplayMinimizationReport,
    promotion_report: &IncidentRegressionPromotionReport,
) -> IncidentProofReportStatus {
    if import_report.verdict != IncidentReplayImportVerdict::Imported {
        return if import_report
            .blocked_reasons
            .iter()
            .any(|reason| reason.kind == IncidentReplayBlockReasonKind::UnsupportedSourceKind)
        {
            IncidentProofReportStatus::Unsupported
        } else {
            IncidentProofReportStatus::Blocked
        };
    }

    match minimization_report.verdict {
        IncidentReplayMinimizationVerdict::Inconclusive => return IncidentProofReportStatus::Flaky,
        IncidentReplayMinimizationVerdict::BudgetExhausted => {
            return IncidentProofReportStatus::NoWin;
        }
        IncidentReplayMinimizationVerdict::Blocked => return IncidentProofReportStatus::Blocked,
        IncidentReplayMinimizationVerdict::Minimized
        | IncidentReplayMinimizationVerdict::AlreadyMinimal => {}
    }

    match promotion_report.verdict {
        IncidentRegressionPromotionVerdict::Promoted => IncidentProofReportStatus::Pass,
        IncidentRegressionPromotionVerdict::FixtureOnly => IncidentProofReportStatus::FixtureOnly,
        IncidentRegressionPromotionVerdict::Blocked => {
            if promotion_report
                .contains_block(IncidentRegressionPromotionBlockKind::UnsupportedPromotionTarget)
            {
                IncidentProofReportStatus::Unsupported
            } else {
                IncidentProofReportStatus::Blocked
            }
        }
    }
}

fn support_class_for_status(status: IncidentProofReportStatus) -> IncidentProofSupportClass {
    match status {
        IncidentProofReportStatus::Pass | IncidentProofReportStatus::Fail => {
            IncidentProofSupportClass::ExecutableRegression
        }
        IncidentProofReportStatus::FixtureOnly => IncidentProofSupportClass::FixtureOnly,
        IncidentProofReportStatus::Unsupported => IncidentProofSupportClass::Unsupported,
        IncidentProofReportStatus::NoWin => IncidentProofSupportClass::NoWin,
        IncidentProofReportStatus::Blocked | IncidentProofReportStatus::Flaky => {
            IncidentProofSupportClass::FollowUpRequired
        }
    }
}

fn evidence_quality_for_status(status: IncidentProofReportStatus) -> IncidentProofEvidenceQuality {
    match status {
        IncidentProofReportStatus::Pass => IncidentProofEvidenceQuality::Trusted,
        IncidentProofReportStatus::Fail => IncidentProofEvidenceQuality::Rejected,
        IncidentProofReportStatus::FixtureOnly => IncidentProofEvidenceQuality::Partial,
        IncidentProofReportStatus::Blocked
        | IncidentProofReportStatus::Flaky
        | IncidentProofReportStatus::Unsupported
        | IncidentProofReportStatus::NoWin => IncidentProofEvidenceQuality::Blocked,
    }
}

fn collect_incident_report_block_kinds(
    import_report: &IncidentReplayImportReport,
    minimization_report: &IncidentReplayMinimizationReport,
    promotion_report: &IncidentRegressionPromotionReport,
) -> Vec<String> {
    let mut kinds = Vec::new();
    kinds.extend(
        import_report
            .blocked_reasons
            .iter()
            .map(|reason| reason.kind.as_str().to_string()),
    );
    kinds.extend(
        minimization_report
            .issues
            .iter()
            .map(|issue| issue.kind.as_str().to_string()),
    );
    kinds.extend(
        promotion_report
            .blocks
            .iter()
            .map(|block| block.kind.as_str().to_string()),
    );
    sorted_strings(kinds)
}

fn stable_incident_proof_report_id(
    incident_id: &str,
    source_package_id: Option<&str>,
    source_repro_id: Option<&str>,
    source_proof_id: Option<&str>,
    status: IncidentProofReportStatus,
    proof_commands: &[IncidentRegressionProofCommand],
    expected_fixture_hashes: &BTreeMap<String, String>,
    retained_source_hashes: &BTreeMap<String, String>,
    block_kinds: &[String],
) -> String {
    let mut key = String::new();
    key.push_str("incident-proof-report-v1\n");
    key.push_str(incident_id);
    key.push('\n');
    key.push_str(source_package_id.unwrap_or(""));
    key.push('\n');
    key.push_str(source_repro_id.unwrap_or(""));
    key.push('\n');
    key.push_str(source_proof_id.unwrap_or(""));
    key.push('\n');
    key.push_str(status.as_str());
    key.push('\n');
    for command in proof_commands {
        key.push_str(&command.command_line);
        key.push('\n');
        key.push_str(if command.executable_through_rch {
            "rch"
        } else {
            "blocked"
        });
        key.push('\n');
    }
    for (source_id, hash) in expected_fixture_hashes {
        key.push_str("expected|");
        key.push_str(source_id);
        key.push('|');
        key.push_str(hash);
        key.push('\n');
    }
    for (source_id, hash) in retained_source_hashes {
        key.push_str("retained|");
        key.push_str(source_id);
        key.push('|');
        key.push_str(hash);
        key.push('\n');
    }
    for kind in block_kinds {
        key.push_str("block|");
        key.push_str(kind);
        key.push('\n');
    }
    format!("incident-proof-report-v1:{:016x}", fnv1a64(key.as_bytes()))
}

fn serde_tag<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn validate_report_required_text(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<IncidentProofReportValidationIssue>,
) {
    if value.is_empty() {
        issues.push(IncidentProofReportValidationIssue::new(
            IncidentProofReportValidationIssueKind::MissingRequiredField,
            field,
            "required field must not be empty",
        ));
    }
}

fn executable_report_requires_rch(status: IncidentProofReportStatus) -> bool {
    matches!(
        status,
        IncidentProofReportStatus::Pass | IncidentProofReportStatus::Fail
    )
}

fn command_line_is_rch_exec(command_line: &str) -> bool {
    command_line
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|window| window == ["rch", "exec"])
}

fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn validate_required_text(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    let field = field.into();
    if value.is_empty() {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::MissingRequiredField,
            field.clone(),
            "required field must not be empty",
        ));
    }
    validate_text_size(&field, value, max_bytes, issues);
    validate_text_safety(field, value, issues);
}

fn validate_text_size(
    field: impl Into<String>,
    value: &str,
    max_bytes: usize,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    let field = field.into();
    if value.len() > max_bytes {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::OversizedField,
            field,
            format!("field is {} bytes, limit is {max_bytes}", value.len()),
        ));
    }
}

fn validate_text_safety(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    if value
        .chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\n' && c != '\t'))
    {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::BinaryLikePayload,
            field,
            "text field contains binary-like control bytes",
        ));
    }
}

fn validate_content_hash(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    let field = field.into();
    let Some(hex) = value.strip_prefix("sha256:") else {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::MalformedContentHash,
            field,
            "hash must use sha256:<64 lowercase hex> format",
        ));
        return;
    };
    if hex.len() != SHA256_HEX_LEN || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::MalformedContentHash,
            field,
            "hash must use sha256:<64 lowercase hex> format",
        ));
    }
}

fn validate_repo_relative_path(
    field: impl Into<String>,
    value: &str,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    let field = field.into();
    validate_required_text(&field, value, MAX_PATH_BYTES, issues);
    let lower = value.to_ascii_lowercase();
    let is_absolute = value.starts_with('/')
        || value.starts_with('\\')
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':');
    let has_parent = value.split(['/', '\\']).any(|part| part == "..");
    let has_private = PRIVATE_PATH_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment));
    if is_absolute || has_parent || has_private {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::ExternalPath,
            field,
            "path must be repository-relative and must not expose host-private directories",
        ));
    }
}

fn scan_json_map(
    prefix: &str,
    map: &BTreeMap<String, Value>,
    redaction_status: IncidentRedactionStatus,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    for (key, value) in map {
        let field = format!("{prefix}.{key}");
        scan_json_value(&field, key, value, redaction_status, issues);
    }
}

fn scan_json_value(
    field: &str,
    key: &str,
    value: &Value,
    redaction_status: IncidentRedactionStatus,
    issues: &mut Vec<IncidentValidationIssue>,
) {
    if key_is_secret_like(key) && redaction_status != IncidentRedactionStatus::Redacted {
        issues.push(IncidentValidationIssue::new(
            IncidentValidationIssueKind::SecretLikeMaterial,
            field,
            "secret-like metadata key is not marked redacted",
        ));
    }
    match value {
        Value::String(text) => {
            validate_text_size(field, text, MAX_FIELD_BYTES, issues);
            validate_text_safety(field, text, issues);
            if value_is_secret_like(text) && redaction_status != IncidentRedactionStatus::Redacted {
                issues.push(IncidentValidationIssue::new(
                    IncidentValidationIssueKind::SecretLikeMaterial,
                    field,
                    "secret-like metadata value is not marked redacted",
                ));
            }
        }
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                scan_json_value(
                    &format!("{field}[{index}]"),
                    key,
                    item,
                    redaction_status,
                    issues,
                );
            }
        }
        Value::Object(object) => {
            for (child_key, child) in object {
                scan_json_value(
                    &format!("{field}.{child_key}"),
                    child_key,
                    child,
                    redaction_status,
                    issues,
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn valid_bundle() -> IncidentBundle {
        IncidentBundle {
            schema_version: INCIDENT_BUNDLE_SCHEMA_VERSION,
            bundle_id: "incident-fixture-accepted".to_string(),
            sources: vec![IncidentSource {
                source_id: "crashpack-main".to_string(),
                kind: IncidentSourceKind::CrashPack,
                artifact_path: Some("artifacts/crashpacks/fixture.json".to_string()),
                content_hash: HASH_A.to_string(),
                content_bytes: 512,
                redaction_status: IncidentRedactionStatus::Redacted,
                payload_snippet: Some("panic after deterministic schedule seed 42".to_string()),
                metadata: BTreeMap::from([("trace_fingerprint".to_string(), json!("0xfeedbeef"))]),
            }],
            command: IncidentCommand {
                program: "rch".to_string(),
                args: vec![
                    "exec".to_string(),
                    "--".to_string(),
                    "cargo".to_string(),
                    "test".to_string(),
                    "-p".to_string(),
                    "asupersync".to_string(),
                ],
                env: vec![IncidentEnvVar {
                    key: "RUSTFLAGS".to_string(),
                    value: "-C debuginfo=0".to_string(),
                }],
                working_dir: ".".to_string(),
            },
            determinism: IncidentDeterminism {
                seed: Some(42),
                schedule_seed: Some(42),
                virtual_time_nanos: Some(0),
                config_hash: HASH_B.to_string(),
                feature_flags: vec!["test-internals".to_string()],
                target_triple: "x86_64-unknown-linux-gnu".to_string(),
            },
            privacy: IncidentPrivacy {
                classification: IncidentPrivacyClass::Internal,
                redaction_status: IncidentRedactionStatus::Redacted,
                redaction_policy_id: "incident-redaction-v1".to_string(),
            },
            provenance: IncidentProvenance {
                capture_id: "support-incident-fixture-accepted".to_string(),
                origin: "support_bundle".to_string(),
                reporter: "operator".to_string(),
                captured_commit: Some("34b057288".to_string()),
                related_bead_id: Some("asupersync-lkygsb.1".to_string()),
            },
            metadata: BTreeMap::from([("scenario".to_string(), json!("accepted"))]),
        }
    }

    #[test]
    fn valid_bundle_is_accepted() {
        let report = valid_bundle().validate();
        assert!(report.is_accepted(), "{report:#?}");
        assert_eq!(report.bundle_id, "incident-fixture-accepted");
    }

    #[test]
    fn malformed_json_is_rejected_before_validation() {
        let parsed = IncidentBundle::from_json("{not-json");
        assert!(parsed.is_err());
    }

    #[test]
    fn missing_required_fields_fail_during_parse_or_validation() {
        let parsed = IncidentBundle::from_json(r#"{"schema_version":1}"#);
        assert!(parsed.is_err());

        let mut bundle = valid_bundle();
        bundle.bundle_id.clear();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MissingRequiredField));
    }

    #[test]
    fn schema_version_mismatch_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.schema_version = INCIDENT_BUNDLE_SCHEMA_VERSION + 1;
        let report = bundle.validate();
        assert_eq!(report.verdict, IncidentValidationVerdict::Blocked);
        assert!(report.contains_kind(IncidentValidationIssueKind::UnsupportedSchemaVersion));
    }

    #[test]
    fn duplicate_source_ids_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources.push(bundle.sources[0].clone());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::DuplicateSourceId));
    }

    #[test]
    fn unknown_source_kind_deserializes_to_typed_blocker() {
        let json = valid_bundle()
            .to_json()
            .expect("valid bundle should serialize")
            .replace("\"crash_pack\"", "\"future_tool_bundle\"");
        let bundle = IncidentBundle::from_json(&json).expect("unknown kind should parse");
        assert!(matches!(
            bundle.sources[0].kind,
            IncidentSourceKind::Unsupported(_)
        ));
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::UnsupportedSourceKind));
    }

    #[test]
    fn malformed_hash_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].content_hash = "not-a-hash".to_string();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MalformedContentHash));
    }

    #[test]
    fn oversized_fields_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].payload_snippet = Some("x".repeat(MAX_PAYLOAD_SNIPPET_BYTES + 1));
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::OversizedField));
    }

    #[test]
    fn confidential_bundle_without_redaction_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.classification = IncidentPrivacyClass::Confidential;
        bundle.privacy.redaction_status = IncidentRedactionStatus::NotRequired;
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::RedactionRequiredButMissing));
    }

    #[test]
    fn missing_redaction_policy_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.redaction_policy_id.clear();
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::MissingRedactionPolicy));
    }

    #[test]
    fn secret_env_var_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.command.env.push(IncidentEnvVar {
            key: "API_TOKEN".to_string(),
            value: "sk-test-123".to_string(),
        });
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn private_host_paths_block_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].artifact_path = Some("/home/alice/.ssh/id_rsa".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::ExternalPath));
    }

    #[test]
    fn secret_payload_snippet_blocks_import_when_not_redacted() {
        let mut bundle = valid_bundle();
        bundle.sources[0].redaction_status = IncidentRedactionStatus::NotRequired;
        bundle.sources[0].payload_snippet = Some("Authorization: Bearer secret-token".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn nested_secret_metadata_blocks_import_when_not_redacted() {
        let mut bundle = valid_bundle();
        bundle.privacy.redaction_status = IncidentRedactionStatus::NotRequired;
        bundle.metadata = BTreeMap::from([(
            "headers".to_string(),
            json!({"authorization": "Bearer abc123"}),
        )]);
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::SecretLikeMaterial));
    }

    #[test]
    fn binary_like_payload_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].payload_snippet = Some("prefix\0suffix".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::BinaryLikePayload));
    }

    #[test]
    fn duplicate_feature_flags_block_import() {
        let mut bundle = valid_bundle();
        bundle
            .determinism
            .feature_flags
            .push("test-internals".to_string());
        let report = bundle.validate();
        assert!(report.contains_kind(IncidentValidationIssueKind::DuplicateFeatureFlag));
    }

    #[test]
    fn fingerprint_is_stable_for_same_bundle() {
        let bundle = valid_bundle();
        assert_eq!(bundle.fingerprint(), bundle.clone().fingerprint());
        let json = bundle.to_json().expect("valid bundle should serialize");
        let parsed = IncidentBundle::from_json(&json).expect("serialized bundle should parse");
        assert_eq!(bundle.fingerprint(), parsed.fingerprint());
    }

    #[test]
    fn imports_valid_crashpack_bundle_to_replay_package() {
        let report = valid_bundle().import_replay_package();
        assert!(report.is_imported(), "{report:#?}");
        let package = report.package.expect("valid import emits package");
        assert_eq!(
            package.schema_version,
            INCIDENT_REPLAY_PACKAGE_SCHEMA_VERSION
        );
        assert_eq!(package.bundle_id, "incident-fixture-accepted");
        assert_eq!(package.sources[0].role, IncidentReplaySourceRole::CrashPack);
        assert_eq!(package.trace_metadata.seed, 42);
        assert_eq!(package.trace_metadata.recorded_at, 0);
        assert_eq!(package.canonicalization.trace_fingerprints, ["0xfeedbeef"]);
    }

    #[test]
    fn imports_required_source_kinds_without_mock_downgrade() {
        for (kind, role) in [
            (
                IncidentSourceKind::CrashPack,
                IncidentReplaySourceRole::CrashPack,
            ),
            (
                IncidentSourceKind::TraceLog,
                IncidentReplaySourceRole::TraceLog,
            ),
            (
                IncidentSourceKind::RchProofFailure,
                IncidentReplaySourceRole::RchProofFailure,
            ),
            (
                IncidentSourceKind::ReadmeClaimFailure,
                IncidentReplaySourceRole::ReadmeClaimFailure,
            ),
        ] {
            let mut bundle = valid_bundle();
            bundle.sources[0].kind = kind;
            bundle.sources[0].source_id = role.as_str().to_string();
            let content_hash = bundle.sources[0].content_hash.clone();
            bundle.sources[0]
                .metadata
                .insert("observed_content_hash".to_string(), json!(content_hash));
            let report = bundle.import_replay_package();
            assert!(report.is_imported(), "{role:?}: {report:#?}");
            let package = report.package.expect("package emitted");
            assert_eq!(package.sources[0].role, role);
        }
    }

    #[test]
    fn malformed_bundle_json_returns_malformed_import_report() {
        let report = import_incident_bundle_json("{definitely-not-json");
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Malformed);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::MalformedJson));
    }

    #[test]
    fn schema_validation_failure_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.schema_version = INCIDENT_BUNDLE_SCHEMA_VERSION + 1;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::ValidationIssue));
    }

    #[test]
    fn missing_source_payload_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].artifact_path = None;
        bundle.sources[0].payload_snippet = None;
        bundle.sources[0].metadata.clear();
        bundle.sources[0].content_bytes = 0;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::MissingSourcePayload));
    }

    #[test]
    fn stale_observed_hash_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.sources[0].metadata.insert(
            "observed_content_hash".to_string(),
            json!("sha256:9999999999999999999999999999999999999999999999999999999999999999"),
        );
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::StaleContentHash));
    }

    #[test]
    fn redaction_required_blocks_import() {
        let mut bundle = valid_bundle();
        bundle.privacy.classification = IncidentPrivacyClass::Secret;
        bundle.privacy.redaction_status = IncidentRedactionStatus::RequiredButMissing;
        let report = bundle.import_replay_package();
        assert_eq!(report.verdict, IncidentReplayImportVerdict::Blocked);
        assert!(report.contains_kind(IncidentReplayBlockReasonKind::RedactionRequiredButMissing));
    }

    #[test]
    fn package_id_is_stable_for_equivalent_source_order() {
        let mut first = valid_bundle();
        first.sources.push(IncidentSource {
            source_id: "trace-log-main".to_string(),
            kind: IncidentSourceKind::TraceLog,
            artifact_path: Some("artifacts/traces/fixture.ndjson".to_string()),
            content_hash: HASH_B.to_string(),
            content_bytes: 128,
            redaction_status: IncidentRedactionStatus::Redacted,
            payload_snippet: None,
            metadata: BTreeMap::from([("trace_fingerprint".to_string(), json!("0xbead"))]),
        });

        let mut second = first.clone();
        second.sources.reverse();

        let first_package = first
            .import_replay_package()
            .package
            .expect("first import emits package");
        let second_package = second
            .import_replay_package()
            .package
            .expect("second import emits package");

        assert_eq!(first_package.package_id, second_package.package_id);
        assert_eq!(
            first_package.canonicalization.source_order,
            second_package.canonicalization.source_order
        );
    }

    #[test]
    fn replay_package_json_round_trip_is_stable() {
        let package = valid_bundle()
            .import_replay_package()
            .package
            .expect("valid import emits package");
        let json = package.to_json().expect("package serializes");
        let parsed = IncidentReplayPackage::from_json(&json).expect("package parses");
        assert_eq!(package.package_id, parsed.package_id);
        assert_eq!(package, parsed);
    }

    fn two_source_package() -> IncidentReplayPackage {
        let mut bundle = valid_bundle();
        bundle.sources.push(IncidentSource {
            source_id: "trace-log-main".to_string(),
            kind: IncidentSourceKind::TraceLog,
            artifact_path: Some("artifacts/traces/fixture.ndjson".to_string()),
            content_hash: HASH_B.to_string(),
            content_bytes: 128,
            redaction_status: IncidentRedactionStatus::Redacted,
            payload_snippet: None,
            metadata: BTreeMap::from([
                ("trace_fingerprint".to_string(), json!("0xbead")),
                ("observed_content_hash".to_string(), json!(HASH_B)),
            ]),
        });
        bundle
            .import_replay_package()
            .package
            .expect("fixture package imports")
    }

    fn panic_oracle() -> IncidentReplayOracle {
        IncidentReplayOracle {
            kind: IncidentOracleKind::Panic,
            expected_signal: "panic after deterministic schedule seed 42".to_string(),
            stable: true,
            required_source_roles: vec![IncidentReplaySourceRole::CrashPack],
            required_trace_fingerprint: Some("0xfeedbeef".to_string()),
        }
    }

    #[test]
    fn minimizer_preserves_oracle_and_shrinks_sources() {
        let package = two_source_package();
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(report.verdict, IncidentReplayMinimizationVerdict::Minimized);
        let repro = report.repro.expect("minimized repro emitted");
        assert_eq!(repro.retained_sources.len(), 1);
        assert_eq!(
            repro.retained_sources[0].role,
            IncidentReplaySourceRole::CrashPack
        );
        assert_eq!(repro.removed_source_ids, ["trace-log-main"]);
        assert!(repro.summary.minimized_units < repro.summary.original_units);
        assert!(repro.steps.iter().any(|step| step.accepted));
    }

    #[test]
    fn minimizer_is_monotonic_and_records_rejections() {
        let package = two_source_package();
        let report = package.minimize_repro(
            IncidentReplayOracle {
                required_trace_fingerprint: Some("0xbead".to_string()),
                ..panic_oracle()
            },
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );
        let repro = report.repro.expect("repro emitted");

        assert!(
            repro.summary.minimized_units <= repro.summary.original_units,
            "{repro:#?}"
        );
        assert!(repro.steps.iter().any(|step| !step.accepted));
    }

    #[test]
    fn minimizer_reports_budget_exhaustion() {
        let package = two_source_package();
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 0,
                shrink_feature_flags: true,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::BudgetExhausted
        );
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::BudgetExhausted));
        assert!(report.steps.iter().any(|step| {
            step.kind == IncidentReplayShrinkStepKind::BudgetExhausted && !step.accepted
        }));
    }

    #[test]
    fn flaky_oracle_is_inconclusive() {
        let package = two_source_package();
        let mut oracle = panic_oracle();
        oracle.stable = false;
        let report = package.minimize_repro(oracle, IncidentReplayMinimizationConfig::default());

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::Inconclusive
        );
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::FlakyOracle));
        assert!(report.repro.is_none());
    }

    #[test]
    fn empty_trace_blocks_minimization() {
        let mut package = two_source_package();
        package.sources.clear();
        let report =
            package.minimize_repro(panic_oracle(), IncidentReplayMinimizationConfig::default());

        assert_eq!(report.verdict, IncidentReplayMinimizationVerdict::Blocked);
        assert!(report.contains_issue(IncidentReplayMinimizationIssueKind::EmptyTrace));
    }

    #[test]
    fn single_event_trace_is_already_minimal() {
        let package = valid_bundle()
            .import_replay_package()
            .package
            .expect("single source imports");
        let report = package.minimize_repro(
            panic_oracle(),
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::AlreadyMinimal
        );
        let repro = report.repro.expect("already minimal repro emitted");
        assert_eq!(repro.retained_sources.len(), 1);
        assert!(repro.removed_source_ids.is_empty());
    }

    #[test]
    fn already_minimal_when_all_sources_are_required() {
        let package = two_source_package();
        let oracle = IncidentReplayOracle {
            kind: IncidentOracleKind::ProofCommandFailure,
            expected_signal: "remote proof command failed".to_string(),
            stable: true,
            required_source_roles: vec![
                IncidentReplaySourceRole::CrashPack,
                IncidentReplaySourceRole::TraceLog,
            ],
            required_trace_fingerprint: None,
        };
        let report = minimize_incident_replay_package(
            &package,
            oracle,
            IncidentReplayMinimizationConfig {
                step_budget: 8,
                shrink_feature_flags: false,
            },
        );

        assert_eq!(
            report.verdict,
            IncidentReplayMinimizationVerdict::AlreadyMinimal
        );
        assert!(report.steps.is_empty());
    }

    #[test]
    fn minimized_repro_json_round_trip_is_stable() {
        let package = two_source_package();
        let repro = package
            .minimize_repro(
                panic_oracle(),
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("repro emitted");
        let json = repro.to_json().expect("repro serializes");
        let parsed = IncidentMinimizedReplayRepro::from_json(&json).expect("repro parses");

        assert_eq!(repro.repro_id, parsed.repro_id);
        assert_eq!(repro, parsed);
    }

    fn minimized_crash_repro() -> IncidentMinimizedReplayRepro {
        two_source_package()
            .minimize_repro(
                panic_oracle(),
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("crash repro emitted")
    }

    #[test]
    fn promotion_class_selection_uses_oracle_and_sources() {
        let crash_report = promote_minimized_incident_repro(
            &minimized_crash_repro(),
            IncidentRegressionPromotionPolicy::default(),
        );
        assert_eq!(
            crash_report.verdict,
            IncidentRegressionPromotionVerdict::Promoted
        );
        assert_eq!(crash_report.target, IncidentRegressionProofTarget::UnitTest);

        let mut bundle = valid_bundle();
        bundle.sources[0].kind = IncidentSourceKind::ReadmeClaimFailure;
        bundle.sources[0].source_id = "readme-claim-main".to_string();
        let content_hash = bundle.sources[0].content_hash.clone();
        bundle.sources[0]
            .metadata
            .insert("observed_content_hash".to_string(), json!(content_hash));
        let package = bundle
            .import_replay_package()
            .package
            .expect("readme claim imports");
        let repro = package
            .minimize_repro(
                IncidentReplayOracle {
                    kind: IncidentOracleKind::ClaimDrift,
                    expected_signal: "region close claim drift".to_string(),
                    stable: true,
                    required_source_roles: vec![IncidentReplaySourceRole::ReadmeClaimFailure],
                    required_trace_fingerprint: None,
                },
                IncidentReplayMinimizationConfig {
                    step_budget: 8,
                    shrink_feature_flags: false,
                },
            )
            .repro
            .expect("claim drift repro emitted");
        let claim_report =
            promote_minimized_incident_repro(&repro, IncidentRegressionPromotionPolicy::default());

        assert_eq!(
            claim_report.target,
            IncidentRegressionProofTarget::GoldenArtifact
        );
        assert!(claim_report.has_proof());
    }

    #[test]
    fn unsupported_promotion_target_blocks() {
        let policy = IncidentRegressionPromotionPolicy {
            target: Some(IncidentRegressionProofTarget::ConformanceFixture),
            ..IncidentRegressionPromotionPolicy::default()
        };
        let report = promote_minimized_incident_repro(&minimized_crash_repro(), policy);

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(
            report.contains_block(IncidentRegressionPromotionBlockKind::UnsupportedPromotionTarget)
        );
        assert!(report.proof.is_none());
    }

    #[test]
    fn duplicate_seed_detection_blocks_repromotion() {
        let repro = minimized_crash_repro();
        let promoted =
            promote_minimized_incident_repro(&repro, IncidentRegressionPromotionPolicy::default());
        let seed_id = promoted
            .proof
            .as_ref()
            .expect("promotion proof emitted")
            .seed_id
            .clone();
        let report = promote_minimized_incident_repro(
            &repro,
            IncidentRegressionPromotionPolicy {
                existing_seed_ids: vec![seed_id],
                ..IncidentRegressionPromotionPolicy::default()
            },
        );

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(report.contains_block(IncidentRegressionPromotionBlockKind::DuplicateSeed));
    }

    #[test]
    fn stale_fixture_hash_rejects_promotion() {
        let repro = minimized_crash_repro();
        let report = promote_minimized_incident_repro(
            &repro,
            IncidentRegressionPromotionPolicy {
                expected_fixture_hashes: BTreeMap::from([(
                    "crashpack-main".to_string(),
                    "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                        .to_string(),
                )]),
                ..IncidentRegressionPromotionPolicy::default()
            },
        );

        assert_eq!(report.verdict, IncidentRegressionPromotionVerdict::Blocked);
        assert!(report.contains_block(IncidentRegressionPromotionBlockKind::StaleFixtureHash));
    }

    #[test]
    fn redaction_policy_is_preserved_without_payload_leakage() {
        let report = promote_minimized_incident_repro(
            &minimized_crash_repro(),
            IncidentRegressionPromotionPolicy {
                redaction_policy_id: "incident-redaction-v1".to_string(),
                ..IncidentRegressionPromotionPolicy::default()
            },
        );
        let proof = report.proof.expect("promotion proof emitted");
        let json = serde_json::to_string(&proof).expect("proof serializes");

        assert_eq!(proof.redaction_policy_id, "incident-redaction-v1");
        assert_eq!(
            proof.minimization_summary.accepted_steps,
            proof
                .proof_commands
                .iter()
                .filter(|command| command.executable_through_rch)
                .count()
        );
        assert!(
            !json.contains("panic after deterministic schedule seed 42"),
            "promotion proof must not reintroduce source payload snippets"
        );
    }
}
