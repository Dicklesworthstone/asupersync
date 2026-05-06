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
            bundle.sources[0].metadata.insert(
                "observed_content_hash".to_string(),
                json!(bundle.sources[0].content_hash.clone()),
            );
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
}
