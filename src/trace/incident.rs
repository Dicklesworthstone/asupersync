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
}
