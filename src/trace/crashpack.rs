//! Deterministic crash pack format for Spork failures.
//!
//! Crash packs are **repro artifacts**, not logs. They capture the minimal
//! information needed to reproduce a concurrency bug under `LabRuntime`:
//!
//! - Deterministic seed + configuration snapshot
//! - Canonical trace fingerprint
//! - Minimal divergent prefix (if available)
//! - Evidence ledger snapshot for key supervision/registry decisions
//!
//! # Format Goals
//!
//! - **Self-contained**: a crash pack plus the code at the pinned commit is
//!   sufficient to reproduce the failure.
//! - **Deterministic**: two crash packs from the same failure are byte-equal
//!   (modulo wall-clock `created_at`).
//! - **Versioned**: schema version for forward compatibility.
//! - **Compact**: trace prefix is bounded; full trace is referenced, not inlined.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::trace::crashpack::{CrashPack, CrashPackConfig, FailureInfo, FailureOutcome};
//! use asupersync::types::{TaskId, RegionId, Time};
//!
//! let pack = CrashPack::builder(CrashPackConfig {
//!     seed: 42,
//!     config_hash: 0xDEAD,
//!     ..Default::default()
//! })
//! .failure(FailureInfo {
//!     task: TaskId::testing_default(),
//!     region: RegionId::testing_default(),
//!     outcome: FailureOutcome::Panicked { message: "oops".to_string() },
//!     virtual_time: Time::from_secs(5),
//! })
//! .fingerprint(0xCAFE_BABE)
//! .build();
//!
//! assert_eq!(pack.manifest.schema_version, CRASHPACK_SCHEMA_VERSION);
//! ```
//!
//! # Bead
//!
//! bd-2md12 | Parent: bd-qbcnu

use crate::trace::canonicalize::{canonicalize, trace_event_key, trace_fingerprint, TraceEventKey};
use crate::trace::event::TraceEvent;
use crate::trace::replay::ReplayEvent;
use crate::trace::scoring::EvidenceEntry;
use crate::types::{CancelKind, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};

// =============================================================================
// Schema Version
// =============================================================================

/// Current schema version for crash packs.
///
/// Increment when making breaking changes to the format.
pub const CRASHPACK_SCHEMA_VERSION: u32 = 1;

// =============================================================================
// Configuration Snapshot
// =============================================================================

/// Minimal configuration snapshot embedded in a crash pack.
///
/// Captures the deterministic parameters needed to reproduce the execution.
/// Together with the code at `commit_hash`, this is sufficient to set up
/// a `LabRuntime` that replays the same schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashPackConfig {
    /// Deterministic seed for the `LabRuntime` scheduler.
    pub seed: u64,

    /// Hash of the runtime configuration (for compatibility checking).
    ///
    /// If this differs when replaying, the reproduction may not match.
    pub config_hash: u64,

    /// Number of virtual workers in the lab runtime.
    pub worker_count: usize,

    /// Maximum scheduler steps before forced termination (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<u64>,

    /// Git commit hash (hex) of the code that produced this crash pack.
    ///
    /// Optional; when present, allows exact code checkout for reproduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
}

impl Default for CrashPackConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            config_hash: 0,
            worker_count: 1,
            max_steps: None,
            commit_hash: None,
        }
    }
}

// =============================================================================
// Failure Info
// =============================================================================

/// Description of the triggering failure.
///
/// Captures which task failed, where, and what the outcome was.
#[derive(Debug, Clone, Serialize)]
pub struct FailureInfo {
    /// The task that failed.
    pub task: TaskId,

    /// The region containing the failed task.
    pub region: RegionId,

    /// The failure outcome.
    pub outcome: FailureOutcome,

    /// Virtual time at which the failure was observed.
    pub virtual_time: Time,
}

impl PartialEq for FailureInfo {
    fn eq(&self, other: &Self) -> bool {
        self.task == other.task
            && self.region == other.region
            && self.virtual_time == other.virtual_time
    }
}

impl Eq for FailureInfo {}

/// Minimal failure outcome for crash packs.
///
/// This is intentionally smaller than [`crate::types::Outcome`]. Crash packs are repro
/// artifacts, so we only record the deterministic summary needed for debugging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FailureOutcome {
    /// Application error.
    Err,
    /// Cancelled, recording only the cancellation kind.
    Cancelled {
        /// The kind of cancellation.
        cancel_kind: CancelKind,
    },
    /// Panicked, recording only the panic message.
    Panicked {
        /// The panic message.
        message: String,
    },
}

/// Serializable snapshot of an [`EvidenceEntry`] for crash packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntrySnapshot {
    /// Birth column index in the boundary matrix.
    pub birth: usize,
    /// Death column index (or `usize::MAX` for unpaired/infinite classes).
    pub death: usize,
    /// Whether this class is novel (not seen before).
    pub is_novel: bool,
    /// Persistence interval length (None = infinite).
    pub persistence: Option<u64>,
}

impl From<EvidenceEntry> for EvidenceEntrySnapshot {
    fn from(e: EvidenceEntry) -> Self {
        Self {
            birth: e.class.birth,
            death: e.class.death,
            is_novel: e.is_novel,
            persistence: e.persistence,
        }
    }
}

// =============================================================================
// Supervision Decision Snapshot
// =============================================================================

/// Snapshot of a supervision decision captured in the crash pack.
///
/// Records what the supervisor decided and why, providing the "evidence
/// ledger" for debugging supervision chain behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupervisionSnapshot {
    /// Virtual time when the decision was made.
    pub virtual_time: Time,

    /// The task involved in the decision.
    pub task: TaskId,

    /// The region containing the task.
    pub region: RegionId,

    /// Human-readable decision tag (e.g., "restart", "stop", "escalate").
    pub decision: String,

    /// Additional context (e.g., "attempt 3 of 5", "budget exhausted").
    pub context: Option<String>,
}

// =============================================================================
// Crash Pack Manifest (bd-35u33)
// =============================================================================

/// Minimum schema version this code can read.
///
/// Crash packs with `schema_version < MINIMUM_SUPPORTED_SCHEMA_VERSION` are
/// rejected during validation.
pub const MINIMUM_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// The kind of content described by a [`ManifestAttachment`].
///
/// Known kinds get first-class enum variants for type-safe matching.
/// Unknown or user-defined content uses `Custom`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AttachmentKind {
    /// Canonical trace prefix (Foata layers).
    CanonicalPrefix,
    /// Minimal divergent replay prefix.
    DivergentPrefix,
    /// Evidence ledger entries.
    EvidenceLedger,
    /// Supervision decision log.
    SupervisionLog,
    /// Oracle violation list.
    OracleViolations,
    /// User-defined or future attachment type.
    Custom {
        /// Free-form type tag.
        tag: String,
    },
}

/// Describes one attachment in the crash pack.
///
/// The manifest carries an attachment list so that tooling can inspect
/// what a crash pack contains without deserializing the full payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAttachment {
    /// What kind of content this attachment holds.
    #[serde(flatten)]
    pub kind: AttachmentKind,

    /// Number of top-level items (events, entries, layers, etc.).
    pub item_count: u64,

    /// Approximate serialized size in bytes (0 if unknown).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size_hint_bytes: u64,
}

// serde expects `skip_serializing_if` predicates to take `&T`.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if requires &T
fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// The crash pack manifest: top-level metadata and structural summary.
///
/// The manifest is the first thing read when opening a crash pack. It
/// provides enough information to:
/// 1. Check version compatibility
/// 2. Identify the failure at a glance
/// 3. Locate the detailed trace data
/// 4. Enumerate attachments without full deserialization
///
/// # Schema Versioning
///
/// The `schema_version` field enables forward compatibility. Use
/// [`validate()`](CrashPackManifest::validate) before processing a crash pack
/// to ensure the current code can interpret it correctly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashPackManifest {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Configuration snapshot for reproduction.
    pub config: CrashPackConfig,

    /// Canonical trace fingerprint (deterministic hash of the full trace).
    ///
    /// Two crash packs with the same fingerprint represent the same failure
    /// modulo configuration.
    pub fingerprint: u64,

    /// Total number of trace events in the execution.
    pub event_count: u64,

    /// Wall-clock timestamp when the crash pack was created (Unix epoch nanos).
    pub created_at: u64,

    /// Attachment table of contents.
    ///
    /// Lists the sections present in this crash pack so tooling can
    /// discover content without deserializing the full payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<ManifestAttachment>,
}

/// Errors from manifest schema validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// Schema version is newer than what this code supports.
    VersionTooNew {
        /// The manifest's schema version.
        manifest_version: u32,
        /// The maximum version this code supports.
        supported_version: u32,
    },
    /// Schema version is older than the minimum this code can read.
    VersionTooOld {
        /// The manifest's schema version.
        manifest_version: u32,
        /// The minimum version this code requires.
        minimum_version: u32,
    },
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionTooNew {
                manifest_version,
                supported_version,
            } => write!(
                f,
                "crash pack schema v{manifest_version} is newer than supported v{supported_version}"
            ),
            Self::VersionTooOld {
                manifest_version,
                minimum_version,
            } => write!(
                f,
                "crash pack schema v{manifest_version} is older than minimum v{minimum_version}"
            ),
        }
    }
}

impl std::error::Error for ManifestValidationError {}

impl CrashPackManifest {
    /// Create a new manifest with the given config and fingerprint.
    #[must_use]
    pub fn new(config: CrashPackConfig, fingerprint: u64, event_count: u64) -> Self {
        Self {
            schema_version: CRASHPACK_SCHEMA_VERSION,
            config,
            fingerprint,
            event_count,
            created_at: wall_clock_nanos(),
            attachments: Vec::new(),
        }
    }

    /// Validate that this manifest's schema version is compatible with the
    /// current code.
    ///
    /// Returns `Ok(())` if `MINIMUM_SUPPORTED_SCHEMA_VERSION <= schema_version <= CRASHPACK_SCHEMA_VERSION`.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.schema_version > CRASHPACK_SCHEMA_VERSION {
            return Err(ManifestValidationError::VersionTooNew {
                manifest_version: self.schema_version,
                supported_version: CRASHPACK_SCHEMA_VERSION,
            });
        }
        if self.schema_version < MINIMUM_SUPPORTED_SCHEMA_VERSION {
            return Err(ManifestValidationError::VersionTooOld {
                manifest_version: self.schema_version,
                minimum_version: MINIMUM_SUPPORTED_SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    /// Returns `true` if this manifest's schema version is compatible.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.validate().is_ok()
    }

    /// Look up an attachment by kind.
    #[must_use]
    pub fn attachment(&self, kind: &AttachmentKind) -> Option<&ManifestAttachment> {
        self.attachments.iter().find(|a| &a.kind == kind)
    }

    /// Returns `true` if the manifest lists an attachment of the given kind.
    #[must_use]
    pub fn has_attachment(&self, kind: &AttachmentKind) -> bool {
        self.attachment(kind).is_some()
    }
}

// =============================================================================
// Crash Pack
// =============================================================================

/// A complete crash pack: a self-contained repro artifact for a Spork failure.
///
/// # Structure
///
/// ```text
/// CrashPack
/// ├── manifest          — version, config, fingerprint, event count
/// ├── failure           — triggering failure (task, region, outcome, vt)
/// ├── canonical_prefix  — Foata layers of the trace prefix (deterministic)
/// ├── divergent_prefix  — minimal replay prefix to reach the divergence point
/// ├── evidence          — evidence ledger entries (supervision/registry decisions)
/// ├── supervision_log   — supervision decision snapshots
/// └── oracle_violations — invariant violations detected by oracles
/// ```
///
/// # Determinism
///
/// All fields except `manifest.created_at` are deterministic: given the same
/// seed, config, and code, the same crash pack is produced.
#[derive(Debug, Clone, Serialize)]
pub struct CrashPack {
    /// Top-level manifest with version, config, and fingerprint.
    pub manifest: CrashPackManifest,

    /// The triggering failure.
    pub failure: FailureInfo,

    /// Canonicalized trace prefix (Foata normal form layers of event keys).
    ///
    /// Bounded to avoid unbounded growth; the number of layers and events
    /// per layer are configurable at creation time.
    pub canonical_prefix: Vec<Vec<TraceEventKey>>,

    /// Minimal divergent prefix: the shortest replay event sequence that
    /// reaches the failure point.
    ///
    /// This is the primary repro artifact. Feed it to `TraceReplayer` to
    /// step through the execution up to the failure.
    pub divergent_prefix: Vec<ReplayEvent>,

    /// Evidence ledger entries capturing key runtime decisions.
    ///
    /// These are the "proof" entries from the scoring/evidence system
    /// that document why the runtime made particular choices.
    pub evidence: Vec<EvidenceEntrySnapshot>,

    /// Supervision decision log leading up to the failure.
    ///
    /// Ordered by virtual time; captures the chain of restart/stop/escalate
    /// decisions that preceded (or caused) the failure.
    pub supervision_log: Vec<SupervisionSnapshot>,

    /// Oracle invariant violations detected during the execution.
    ///
    /// Sorted and deduplicated. Empty if all invariants held.
    pub oracle_violations: Vec<String>,

    /// Verbatim replay command for reproducing this failure.
    ///
    /// When present, this can be copy-pasted into a shell to replay the
    /// exact execution that produced this crash pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayCommand>,
}

impl PartialEq for CrashPack {
    fn eq(&self, other: &Self) -> bool {
        // Equality ignores created_at (wall clock) per determinism contract
        self.manifest.schema_version == other.manifest.schema_version
            && self.manifest.config == other.manifest.config
            && self.manifest.fingerprint == other.manifest.fingerprint
            && self.manifest.event_count == other.manifest.event_count
            && self.failure == other.failure
            && self.canonical_prefix == other.canonical_prefix
            && self.oracle_violations == other.oracle_violations
    }
}

impl Eq for CrashPack {}

impl CrashPack {
    /// Start building a crash pack with the given configuration.
    #[must_use]
    pub fn builder(config: CrashPackConfig) -> CrashPackBuilder {
        CrashPackBuilder {
            config,
            failure: None,
            fingerprint: 0,
            event_count: 0,
            canonical_prefix: Vec::new(),
            divergent_prefix: Vec::new(),
            evidence: Vec::new(),
            supervision_log: Vec::new(),
            oracle_violations: Vec::new(),
            replay: None,
        }
    }

    /// Generate a replay command from this crash pack's configuration.
    ///
    /// This is a convenience method equivalent to
    /// `ReplayCommand::from_config(&pack.manifest.config, artifact_path)`.
    #[must_use]
    pub fn replay_command(&self, artifact_path: Option<&str>) -> ReplayCommand {
        ReplayCommand::from_config(&self.manifest.config, artifact_path)
    }

    /// Returns `true` if any oracle violations were detected.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        !self.oracle_violations.is_empty()
    }

    /// Returns `true` if a divergent prefix is available for replay.
    #[must_use]
    pub fn has_divergent_prefix(&self) -> bool {
        !self.divergent_prefix.is_empty()
    }

    /// Returns the seed from the configuration.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.manifest.config.seed
    }

    /// Returns the canonical trace fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.manifest.fingerprint
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing a [`CrashPack`] incrementally.
///
/// Required: `config` (provided at construction) and `failure` (via `.failure()`).
/// All other fields have sensible defaults (empty).
#[derive(Debug)]
pub struct CrashPackBuilder {
    config: CrashPackConfig,
    failure: Option<FailureInfo>,
    fingerprint: u64,
    event_count: u64,
    canonical_prefix: Vec<Vec<TraceEventKey>>,
    divergent_prefix: Vec<ReplayEvent>,
    evidence: Vec<EvidenceEntrySnapshot>,
    supervision_log: Vec<SupervisionSnapshot>,
    oracle_violations: Vec<String>,
    replay: Option<ReplayCommand>,
}

impl CrashPackBuilder {
    /// Set the triggering failure.
    #[must_use]
    pub fn failure(mut self, failure: FailureInfo) -> Self {
        self.failure = Some(failure);
        self
    }

    /// Set the canonical trace fingerprint.
    #[must_use]
    pub fn fingerprint(mut self, fingerprint: u64) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Set the total event count.
    #[must_use]
    pub fn event_count(mut self, count: u64) -> Self {
        self.event_count = count;
        self
    }

    /// Populate canonical prefix, fingerprint, and event count from raw trace events.
    ///
    /// This is the primary integration point for the canonicalization pipeline.
    /// It calls [`canonicalize()`] to compute the Foata normal form, extracts
    /// [`TraceEventKey`] layers for the canonical prefix, and computes a
    /// deterministic fingerprint via [`trace_fingerprint()`].
    ///
    /// Two different schedules that are equivalent modulo commutations of
    /// independent events will produce the same fingerprint and the same
    /// canonical prefix.
    #[must_use]
    pub fn from_trace(mut self, events: &[TraceEvent]) -> Self {
        let foata = canonicalize(events);
        self.canonical_prefix = foata
            .layers()
            .iter()
            .map(|layer| layer.iter().map(trace_event_key).collect())
            .collect();
        self.fingerprint = trace_fingerprint(events);
        self.event_count = events.len() as u64;
        self
    }

    /// Set the canonical Foata prefix.
    #[must_use]
    pub fn canonical_prefix(mut self, prefix: Vec<Vec<TraceEventKey>>) -> Self {
        self.canonical_prefix = prefix;
        self
    }

    /// Set the minimal divergent prefix for replay.
    #[must_use]
    pub fn divergent_prefix(mut self, prefix: Vec<ReplayEvent>) -> Self {
        self.divergent_prefix = prefix;
        self
    }

    /// Add evidence ledger entries.
    #[must_use]
    pub fn evidence(mut self, entries: Vec<EvidenceEntry>) -> Self {
        self.evidence = entries
            .into_iter()
            .map(EvidenceEntrySnapshot::from)
            .collect();
        self
    }

    /// Add a supervision decision snapshot.
    #[must_use]
    pub fn supervision_snapshot(mut self, snapshot: SupervisionSnapshot) -> Self {
        self.supervision_log.push(snapshot);
        self
    }

    /// Set oracle violations.
    #[must_use]
    pub fn oracle_violations(mut self, violations: Vec<String>) -> Self {
        let mut v = violations;
        v.sort();
        v.dedup();
        self.oracle_violations = v;
        self
    }

    /// Set the replay command for reproducing this failure.
    #[must_use]
    pub fn replay(mut self, command: ReplayCommand) -> Self {
        self.replay = Some(command);
        self
    }

    /// Build the crash pack.
    ///
    /// The manifest's attachment list is auto-populated from the crash pack
    /// content: non-empty sections are listed as attachments so that tooling
    /// can inspect the table of contents without full deserialization.
    ///
    /// # Panics
    ///
    /// Panics if `failure` has not been set.
    #[must_use]
    pub fn build(self) -> CrashPack {
        let failure = self.failure.expect("CrashPackBuilder requires a failure");

        // Sort supervision log by virtual time for determinism
        let mut supervision_log = self.supervision_log;
        supervision_log.sort_by_key(|s| s.virtual_time);

        // Build attachment table of contents from non-empty sections
        let mut attachments = Vec::new();
        if !self.canonical_prefix.is_empty() {
            let item_count: u64 = self
                .canonical_prefix
                .iter()
                .map(|layer| layer.len() as u64)
                .sum();
            attachments.push(ManifestAttachment {
                kind: AttachmentKind::CanonicalPrefix,
                item_count,
                size_hint_bytes: 0,
            });
        }
        if !self.divergent_prefix.is_empty() {
            attachments.push(ManifestAttachment {
                kind: AttachmentKind::DivergentPrefix,
                item_count: self.divergent_prefix.len() as u64,
                size_hint_bytes: 0,
            });
        }
        if !self.evidence.is_empty() {
            attachments.push(ManifestAttachment {
                kind: AttachmentKind::EvidenceLedger,
                item_count: self.evidence.len() as u64,
                size_hint_bytes: 0,
            });
        }
        if !supervision_log.is_empty() {
            attachments.push(ManifestAttachment {
                kind: AttachmentKind::SupervisionLog,
                item_count: supervision_log.len() as u64,
                size_hint_bytes: 0,
            });
        }
        if !self.oracle_violations.is_empty() {
            attachments.push(ManifestAttachment {
                kind: AttachmentKind::OracleViolations,
                item_count: self.oracle_violations.len() as u64,
                size_hint_bytes: 0,
            });
        }

        let mut manifest = CrashPackManifest::new(self.config, self.fingerprint, self.event_count);
        manifest.attachments = attachments;

        CrashPack {
            manifest,
            failure,
            canonical_prefix: self.canonical_prefix,
            divergent_prefix: self.divergent_prefix,
            evidence: self.evidence,
            supervision_log,
            oracle_violations: self.oracle_violations,
            replay: self.replay,
        }
    }
}

// =============================================================================
// Replay Command Contract (bd-1teda)
// =============================================================================

/// An environment variable required for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvVar {
    /// Variable name (e.g., `ASUPERSYNC_SEED`).
    pub key: String,
    /// Variable value.
    pub value: String,
}

/// A verbatim replay command that can reproduce the crash pack's failure.
///
/// The command is a fully-specified invocation that, given the same code
/// at the recorded commit, will reproduce the exact failure.
///
/// # Example JSON
///
/// ```json
/// {
///   "program": "cargo",
///   "args": ["test", "--lib", "--", "--seed", "42"],
///   "env": [{"key": "ASUPERSYNC_WORKERS", "value": "4"}],
///   "command_line": "ASUPERSYNC_WORKERS=4 cargo test --lib -- --seed 42"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCommand {
    /// The binary or program to invoke.
    pub program: String,

    /// Command-line arguments, each as a separate string.
    pub args: Vec<String>,

    /// Environment variables required for replay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<ReplayEnvVar>,

    /// Human-readable one-liner that can be copy-pasted into a shell.
    ///
    /// Includes env var prefixes, the program, and all arguments.
    pub command_line: String,
}

impl ReplayCommand {
    /// Build a replay command from a crash pack's configuration.
    ///
    /// Generates a `cargo test` invocation with the crash pack's seed
    /// and configuration parameters.
    #[must_use]
    pub fn from_config(config: &CrashPackConfig, artifact_path: Option<&str>) -> Self {
        let mut args = vec![
            "test".to_string(),
            "--lib".to_string(),
            "--".to_string(),
            "--seed".to_string(),
            config.seed.to_string(),
        ];

        let mut env = Vec::new();

        env.push(ReplayEnvVar {
            key: "ASUPERSYNC_WORKERS".to_string(),
            value: config.worker_count.to_string(),
        });

        if let Some(max_steps) = config.max_steps {
            env.push(ReplayEnvVar {
                key: "ASUPERSYNC_MAX_STEPS".to_string(),
                value: max_steps.to_string(),
            });
        }

        if let Some(path) = artifact_path {
            args.push("--crashpack".to_string());
            args.push(path.to_string());
        }

        let command_line = build_command_line("cargo", &args, &env);

        Self {
            program: "cargo".to_string(),
            args,
            env,
            command_line,
        }
    }

    /// Build a replay command for the `asupersync trace replay` CLI subcommand.
    #[must_use]
    pub fn from_config_cli(config: &CrashPackConfig, artifact_path: &str) -> Self {
        let mut args = vec![
            "trace".to_string(),
            "replay".to_string(),
            "--seed".to_string(),
            config.seed.to_string(),
            "--workers".to_string(),
            config.worker_count.to_string(),
        ];

        if let Some(max_steps) = config.max_steps {
            args.push("--max-steps".to_string());
            args.push(max_steps.to_string());
        }

        args.push(artifact_path.to_string());

        let command_line = build_command_line("asupersync", &args, &[]);

        Self {
            program: "asupersync".to_string(),
            args,
            env: Vec::new(),
            command_line,
        }
    }
}

impl std::fmt::Display for ReplayCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command_line)
    }
}

/// Build a shell-friendly command line string.
fn build_command_line(program: &str, args: &[String], env: &[ReplayEnvVar]) -> String {
    let mut parts = Vec::new();
    for var in env {
        parts.push(format!("{}={}", var.key, shell_escape(&var.value)));
    }
    parts.push(program.to_string());
    for arg in args {
        parts.push(shell_escape(arg));
    }
    parts.join(" ")
}

/// Minimally escape a string for shell embedding.
///
/// If the string contains shell-unsafe characters, wrap it in single quotes.
/// Otherwise, return it as-is.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | ','))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// =============================================================================
// Artifact Writer Capability (bd-1skcu)
// =============================================================================

/// Identifier for a written crash pack artifact.
///
/// Returned by [`CrashPackWriter::write`] to identify where the artifact was
/// stored. The path is deterministic: given the same seed and fingerprint, the
/// same artifact path is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactId {
    /// The full path or identifier of the written artifact.
    path: String,
}

impl ArtifactId {
    /// Returns the artifact path/identifier as a string.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

/// Error returned when writing a crash pack fails.
#[derive(Debug)]
pub enum CrashPackWriteError {
    /// Serialization failed.
    Serialize(String),
    /// I/O error while writing.
    Io(std::io::Error),
}

impl std::fmt::Display for CrashPackWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(msg) => write!(f, "crash pack serialization failed: {msg}"),
            Self::Io(e) => write!(f, "crash pack I/O error: {e}"),
        }
    }
}

impl std::error::Error for CrashPackWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Serialize(_) => None,
        }
    }
}

/// Capability for writing crash packs to persistent storage.
///
/// This is the **only** way to persist a crash pack. There are no ambient
/// filesystem writes — callers must hold an explicit `&dyn CrashPackWriter`
/// to write artifacts. This follows asupersync's capability-security model.
///
/// # Deterministic Paths
///
/// Artifact paths are deterministic: `crashpack-{seed:016x}-{fingerprint:016x}-v{version}.json`.
/// Two writes of the same crash pack produce the same path.
pub trait CrashPackWriter: Send + Sync + std::fmt::Debug {
    /// Write a crash pack, returning an [`ArtifactId`] identifying the artifact.
    fn write(&self, pack: &CrashPack) -> Result<ArtifactId, CrashPackWriteError>;

    /// Whether this writer persists to durable storage.
    fn is_persistent(&self) -> bool;

    /// Implementation name (e.g., `"file"`, `"memory"`).
    fn name(&self) -> &'static str;
}

/// Compute the deterministic artifact filename for a crash pack.
///
/// Format: `crashpack-{seed:016x}-{fingerprint:016x}-v{version}.json`
#[must_use]
pub fn artifact_filename(pack: &CrashPack) -> String {
    format!(
        "crashpack-{:016x}-{:016x}-v{}.json",
        pack.seed(),
        pack.fingerprint(),
        pack.manifest.schema_version,
    )
}

/// File-based crash pack writer.
///
/// Writes JSON crash packs to a specified directory with deterministic
/// filenames. The directory must exist; this writer does not create it
/// (explicit opt-in means the caller sets up the output directory).
#[derive(Debug)]
pub struct FileCrashPackWriter {
    base_dir: std::path::PathBuf,
}

impl FileCrashPackWriter {
    /// Create a writer targeting the given directory.
    ///
    /// The directory must already exist.
    #[must_use]
    pub fn new(base_dir: std::path::PathBuf) -> Self {
        Self { base_dir }
    }

    /// Returns the base directory for artifact output.
    #[must_use]
    pub fn base_dir(&self) -> &std::path::Path {
        &self.base_dir
    }
}

impl CrashPackWriter for FileCrashPackWriter {
    fn write(&self, pack: &CrashPack) -> Result<ArtifactId, CrashPackWriteError> {
        let filename = artifact_filename(pack);
        let path = self.base_dir.join(&filename);

        let json = serde_json::to_string_pretty(pack)
            .map_err(|e| CrashPackWriteError::Serialize(e.to_string()))?;

        std::fs::write(&path, json.as_bytes()).map_err(CrashPackWriteError::Io)?;

        Ok(ArtifactId {
            path: path.to_string_lossy().into_owned(),
        })
    }

    fn is_persistent(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "file"
    }
}

/// In-memory crash pack writer for testing.
///
/// Collects written packs in a `Vec` behind a mutex. Not persistent.
#[derive(Debug, Default)]
pub struct MemoryCrashPackWriter {
    packs: std::sync::Mutex<Vec<(ArtifactId, String)>>,
}

impl MemoryCrashPackWriter {
    /// Create an empty in-memory writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all written packs as `(artifact_id, json)` pairs.
    pub fn written(&self) -> Vec<(ArtifactId, String)> {
        self.packs.lock().expect("lock poisoned").clone()
    }

    /// Returns the number of packs written.
    #[must_use]
    pub fn count(&self) -> usize {
        self.packs.lock().expect("lock poisoned").len()
    }
}

impl CrashPackWriter for MemoryCrashPackWriter {
    fn write(&self, pack: &CrashPack) -> Result<ArtifactId, CrashPackWriteError> {
        let filename = artifact_filename(pack);
        let json = serde_json::to_string_pretty(pack)
            .map_err(|e| CrashPackWriteError::Serialize(e.to_string()))?;

        let artifact_id = ArtifactId { path: filename };
        self.packs
            .lock()
            .expect("lock poisoned")
            .push((artifact_id.clone(), json));

        Ok(artifact_id)
    }

    fn is_persistent(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "memory"
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Get wall-clock time as nanoseconds since Unix epoch.
fn wall_clock_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn sample_failure() -> FailureInfo {
        FailureInfo {
            task: tid(1),
            region: rid(0),
            outcome: FailureOutcome::Panicked {
                message: "test panic".to_string(),
            },
            virtual_time: Time::from_secs(5),
        }
    }

    fn sample_config() -> CrashPackConfig {
        CrashPackConfig {
            seed: 42,
            config_hash: 0xDEAD,
            worker_count: 4,
            max_steps: Some(1000),
            commit_hash: Some("abc123".to_string()),
        }
    }

    #[test]
    fn schema_version_is_set() {
        init_test("schema_version_is_set");

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .build();

        assert_eq!(pack.manifest.schema_version, CRASHPACK_SCHEMA_VERSION);
        assert_eq!(pack.manifest.schema_version, 1);

        crate::test_complete!("schema_version_is_set");
    }

    #[test]
    fn builder_sets_all_fields() {
        init_test("builder_sets_all_fields");

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0xCAFE_BABE)
            .event_count(500)
            .oracle_violations(vec!["inv-1".into(), "inv-2".into()])
            .build();

        assert_eq!(pack.manifest.config.seed, 42);
        assert_eq!(pack.manifest.config.config_hash, 0xDEAD);
        assert_eq!(pack.manifest.config.worker_count, 4);
        assert_eq!(pack.manifest.config.max_steps, Some(1000));
        assert_eq!(pack.manifest.config.commit_hash.as_deref(), Some("abc123"));
        assert_eq!(pack.manifest.fingerprint, 0xCAFE_BABE);
        assert_eq!(pack.manifest.event_count, 500);
        assert_eq!(pack.failure.task, tid(1));
        assert_eq!(pack.failure.region, rid(0));
        assert_eq!(pack.failure.virtual_time, Time::from_secs(5));
        assert!(pack.has_violations());
        assert_eq!(pack.oracle_violations, vec!["inv-1", "inv-2"]);
        assert!(!pack.has_divergent_prefix());

        crate::test_complete!("builder_sets_all_fields");
    }

    #[test]
    fn default_config() {
        init_test("default_config");

        let config = CrashPackConfig::default();
        assert_eq!(config.seed, 0);
        assert_eq!(config.config_hash, 0);
        assert_eq!(config.worker_count, 1);
        assert_eq!(config.max_steps, None);
        assert_eq!(config.commit_hash, None);

        crate::test_complete!("default_config");
    }

    #[test]
    fn seed_and_fingerprint_accessors() {
        init_test("seed_and_fingerprint_accessors");

        let pack = CrashPack::builder(CrashPackConfig {
            seed: 999,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0x1234)
        .build();

        assert_eq!(pack.seed(), 999);
        assert_eq!(pack.fingerprint(), 0x1234);

        crate::test_complete!("seed_and_fingerprint_accessors");
    }

    #[test]
    fn oracle_violations_sorted_and_deduped() {
        init_test("oracle_violations_sorted_and_deduped");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .oracle_violations(vec![
                "z-violation".into(),
                "a-violation".into(),
                "z-violation".into(), // duplicate
                "m-violation".into(),
            ])
            .build();

        assert_eq!(
            pack.oracle_violations,
            vec!["a-violation", "m-violation", "z-violation"]
        );

        crate::test_complete!("oracle_violations_sorted_and_deduped");
    }

    #[test]
    fn supervision_log_sorted_by_vt() {
        init_test("supervision_log_sorted_by_vt");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .supervision_snapshot(SupervisionSnapshot {
                virtual_time: Time::from_secs(10),
                task: tid(1),
                region: rid(0),
                decision: "restart".into(),
                context: Some("attempt 2 of 3".into()),
            })
            .supervision_snapshot(SupervisionSnapshot {
                virtual_time: Time::from_secs(5),
                task: tid(1),
                region: rid(0),
                decision: "restart".into(),
                context: Some("attempt 1 of 3".into()),
            })
            .supervision_snapshot(SupervisionSnapshot {
                virtual_time: Time::from_secs(15),
                task: tid(1),
                region: rid(0),
                decision: "stop".into(),
                context: Some("budget exhausted".into()),
            })
            .build();

        assert_eq!(pack.supervision_log.len(), 3);
        // Should be sorted by virtual_time
        assert_eq!(pack.supervision_log[0].virtual_time, Time::from_secs(5));
        assert_eq!(pack.supervision_log[1].virtual_time, Time::from_secs(10));
        assert_eq!(pack.supervision_log[2].virtual_time, Time::from_secs(15));

        crate::test_complete!("supervision_log_sorted_by_vt");
    }

    #[test]
    fn crash_pack_equality_ignores_created_at() {
        init_test("crash_pack_equality_ignores_created_at");

        let pack1 = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0xABCD)
            .build();

        // Build a second pack at a different wall-clock time
        let pack2 = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0xABCD)
            .build();

        // created_at will differ, but equality should still hold
        assert_eq!(pack1, pack2);

        crate::test_complete!("crash_pack_equality_ignores_created_at");
    }

    #[test]
    fn crash_pack_inequality_on_different_fingerprint() {
        init_test("crash_pack_inequality_on_different_fingerprint");

        let pack1 = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0x1111)
            .build();

        let pack2 = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0x2222)
            .build();

        assert_ne!(pack1, pack2);

        crate::test_complete!("crash_pack_inequality_on_different_fingerprint");
    }

    #[test]
    fn empty_pack_defaults() {
        init_test("empty_pack_defaults");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .build();

        assert!(pack.canonical_prefix.is_empty());
        assert!(pack.divergent_prefix.is_empty());
        assert!(pack.evidence.is_empty());
        assert!(pack.supervision_log.is_empty());
        assert!(pack.oracle_violations.is_empty());
        assert!(!pack.has_violations());
        assert!(!pack.has_divergent_prefix());

        crate::test_complete!("empty_pack_defaults");
    }

    #[test]
    fn failure_info_equality() {
        init_test("failure_info_equality");

        let f1 = FailureInfo {
            task: tid(1),
            region: rid(0),
            outcome: FailureOutcome::Panicked {
                message: "a".to_string(),
            },
            virtual_time: Time::from_secs(5),
        };
        let f2 = FailureInfo {
            task: tid(1),
            region: rid(0),
            outcome: FailureOutcome::Err, // different outcome
            virtual_time: Time::from_secs(5),
        };
        // Equality on (task, region, virtual_time)
        assert_eq!(f1, f2);

        let f3 = FailureInfo {
            task: tid(2), // different task
            region: rid(0),
            outcome: FailureOutcome::Panicked {
                message: "a".to_string(),
            },
            virtual_time: Time::from_secs(5),
        };
        assert_ne!(f1, f3);

        crate::test_complete!("failure_info_equality");
    }

    #[test]
    fn manifest_new_sets_version() {
        init_test("manifest_new_sets_version");

        let manifest = CrashPackManifest::new(CrashPackConfig::default(), 0xBEEF, 100);

        assert_eq!(manifest.schema_version, CRASHPACK_SCHEMA_VERSION);
        assert_eq!(manifest.fingerprint, 0xBEEF);
        assert_eq!(manifest.event_count, 100);
        assert!(manifest.created_at > 0);

        crate::test_complete!("manifest_new_sets_version");
    }

    #[test]
    fn with_divergent_prefix() {
        init_test("with_divergent_prefix");

        let prefix = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskScheduled {
                task: crate::trace::replay::CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .divergent_prefix(prefix)
            .build();

        assert!(pack.has_divergent_prefix());
        assert_eq!(pack.divergent_prefix.len(), 2);

        crate::test_complete!("with_divergent_prefix");
    }

    #[test]
    fn with_canonical_prefix() {
        init_test("with_canonical_prefix");

        let layer = vec![TraceEventKey {
            kind: 1,
            primary: 0,
            secondary: 0,
            tertiary: 0,
        }];

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .canonical_prefix(vec![layer])
            .build();

        assert_eq!(pack.canonical_prefix.len(), 1);

        crate::test_complete!("with_canonical_prefix");
    }

    #[test]
    fn supervision_snapshot_with_context() {
        init_test("supervision_snapshot_with_context");

        let snap = SupervisionSnapshot {
            virtual_time: Time::from_secs(10),
            task: tid(3),
            region: rid(1),
            decision: "escalate".into(),
            context: Some("parent region R0".into()),
        };

        assert_eq!(snap.decision, "escalate");
        assert_eq!(snap.context.as_deref(), Some("parent region R0"));

        crate::test_complete!("supervision_snapshot_with_context");
    }

    // =================================================================
    // Canonicalization pipeline integration (bd-zfxio)
    // =================================================================

    #[test]
    fn from_trace_populates_fields() {
        init_test("from_trace_populates_fields");

        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
        ];

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&events)
            .build();

        assert_eq!(pack.manifest.event_count, 3);
        assert_ne!(pack.manifest.fingerprint, 0);
        assert!(!pack.canonical_prefix.is_empty());

        crate::test_complete!("from_trace_populates_fields");
    }

    #[test]
    fn from_trace_equivalent_traces_same_fingerprint() {
        init_test("from_trace_equivalent_traces_same_fingerprint");

        // Two schedules that differ only in the order of independent events.
        // spawn(T1,R1) and spawn(T2,R2) are independent — swapping them
        // produces the same equivalence class.
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let trace_b = [
            TraceEvent::spawn(1, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];

        let pack_a = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_a)
            .build();
        let pack_b = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_b)
            .build();

        assert_eq!(pack_a.fingerprint(), pack_b.fingerprint());
        assert_eq!(pack_a.canonical_prefix, pack_b.canonical_prefix);
        assert_eq!(pack_a, pack_b);

        crate::test_complete!("from_trace_equivalent_traces_same_fingerprint");
    }

    #[test]
    fn from_trace_different_dependent_traces_different_fingerprint() {
        init_test("from_trace_different_dependent_traces_different_fingerprint");

        // Same-task events in different orders produce genuinely different
        // causal structures (spawn→complete vs complete→spawn).
        let trace_a = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];
        let trace_b = [
            TraceEvent::complete(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];

        let pack_a = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_a)
            .build();
        let pack_b = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_b)
            .build();

        assert_ne!(pack_a.fingerprint(), pack_b.fingerprint());
        assert_ne!(pack_a, pack_b);

        crate::test_complete!("from_trace_different_dependent_traces_different_fingerprint");
    }

    #[test]
    fn from_trace_canonical_prefix_matches_foata_layers() {
        init_test("from_trace_canonical_prefix_matches_foata_layers");

        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .from_trace(&events)
            .build();

        // Independently compute Foata layers and compare.
        let foata = canonicalize(&events);
        let expected_prefix: Vec<Vec<TraceEventKey>> = foata
            .layers()
            .iter()
            .map(|layer| layer.iter().map(trace_event_key).collect())
            .collect();

        assert_eq!(pack.canonical_prefix, expected_prefix);

        crate::test_complete!("from_trace_canonical_prefix_matches_foata_layers");
    }

    #[test]
    fn from_trace_empty_trace() {
        init_test("from_trace_empty_trace");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .from_trace(&[])
            .build();

        assert!(pack.canonical_prefix.is_empty());
        assert_eq!(pack.manifest.event_count, 0);

        crate::test_complete!("from_trace_empty_trace");
    }

    #[test]
    fn from_trace_three_independent_all_permutations() {
        init_test("from_trace_three_independent_all_permutations");

        // Three independent events in all 6 permutations must produce
        // identical crash packs (same fingerprint, same canonical prefix).
        let e1 = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let e2 = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        let e3 = TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3));

        let perms: Vec<Vec<TraceEvent>> = vec![
            vec![e1.clone(), e2.clone(), e3.clone()],
            vec![e1.clone(), e3.clone(), e2.clone()],
            vec![e2.clone(), e1.clone(), e3.clone()],
            vec![e2.clone(), e3.clone(), e1.clone()],
            vec![e3.clone(), e1.clone(), e2.clone()],
            vec![e3, e2, e1],
        ];

        let reference = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .from_trace(&perms[0])
            .build();

        for (i, perm) in perms.iter().enumerate().skip(1) {
            let pack = CrashPack::builder(CrashPackConfig::default())
                .failure(sample_failure())
                .from_trace(perm)
                .build();
            assert_eq!(
                pack.fingerprint(),
                reference.fingerprint(),
                "permutation {i} has different fingerprint"
            );
            assert_eq!(
                pack.canonical_prefix, reference.canonical_prefix,
                "permutation {i} has different canonical prefix"
            );
        }

        crate::test_complete!("from_trace_three_independent_all_permutations");
    }

    #[test]
    fn from_trace_diamond_dependency() {
        init_test("from_trace_diamond_dependency");

        // Region create → two independent spawns → two independent completes.
        // Swapping the independent pairs must produce the same crash pack.
        let trace_a = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(1)),
        ];
        let trace_b = [
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(1), rid(1)),
        ];

        let pack_a = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_a)
            .build();
        let pack_b = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&trace_b)
            .build();

        assert_eq!(pack_a.fingerprint(), pack_b.fingerprint());
        assert_eq!(pack_a.canonical_prefix, pack_b.canonical_prefix);
        // 3 layers: region_create | spawn×2 | complete×2
        assert_eq!(pack_a.canonical_prefix.len(), 3);

        crate::test_complete!("from_trace_diamond_dependency");
    }

    // =================================================================
    // Artifact Writer Capability (bd-1skcu)
    // =================================================================

    #[test]
    fn artifact_filename_is_deterministic() {
        init_test("artifact_filename_is_deterministic");

        let pack = CrashPack::builder(CrashPackConfig {
            seed: 42,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0xCAFE_BABE)
        .build();

        let name1 = artifact_filename(&pack);
        let name2 = artifact_filename(&pack);
        assert_eq!(name1, name2);
        assert_eq!(name1, "crashpack-000000000000002a-00000000cafebabe-v1.json");

        crate::test_complete!("artifact_filename_is_deterministic");
    }

    #[test]
    fn artifact_filename_varies_by_seed_and_fingerprint() {
        init_test("artifact_filename_varies_by_seed_and_fingerprint");

        let pack_a = CrashPack::builder(CrashPackConfig {
            seed: 1,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0xAAAA)
        .build();

        let pack_b = CrashPack::builder(CrashPackConfig {
            seed: 2,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0xBBBB)
        .build();

        assert_ne!(artifact_filename(&pack_a), artifact_filename(&pack_b));

        crate::test_complete!("artifact_filename_varies_by_seed_and_fingerprint");
    }

    #[test]
    fn memory_writer_collects_packs() {
        init_test("memory_writer_collects_packs");

        let writer = MemoryCrashPackWriter::new();
        assert_eq!(writer.count(), 0);
        assert!(!writer.is_persistent());
        assert_eq!(writer.name(), "memory");

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0x1234)
            .build();

        let artifact = writer.write(&pack).unwrap();
        assert_eq!(writer.count(), 1);
        assert!(artifact.path().contains("crashpack-"));
        assert!(artifact.path().contains("1234"));

        // Write a second pack
        let pack2 = CrashPack::builder(CrashPackConfig {
            seed: 99,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0x5678)
        .build();

        let artifact2 = writer.write(&pack2).unwrap();
        assert_eq!(writer.count(), 2);
        assert_ne!(artifact.path(), artifact2.path());

        crate::test_complete!("memory_writer_collects_packs");
    }

    #[test]
    fn memory_writer_produces_valid_json() {
        init_test("memory_writer_produces_valid_json");

        let writer = MemoryCrashPackWriter::new();
        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .fingerprint(0xDEAD)
            .event_count(42)
            .oracle_violations(vec!["inv-1".into()])
            .build();

        writer.write(&pack).unwrap();
        let written = writer.written();
        assert_eq!(written.len(), 1);

        let json = &written[0].1;
        // Must be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(parsed["manifest"]["config"]["seed"], 42);
        assert_eq!(parsed["manifest"]["fingerprint"], 0xDEAD_u64);
        assert_eq!(parsed["manifest"]["event_count"], 42);
        assert_eq!(parsed["oracle_violations"][0], "inv-1");

        crate::test_complete!("memory_writer_produces_valid_json");
    }

    #[test]
    fn file_writer_writes_to_disk() {
        init_test("file_writer_writes_to_disk");

        let dir = std::env::temp_dir().join("asupersync_test_crashpack");
        let _ = std::fs::create_dir_all(&dir);

        let writer = FileCrashPackWriter::new(dir.clone());
        assert!(writer.is_persistent());
        assert_eq!(writer.name(), "file");
        assert_eq!(writer.base_dir(), dir.as_path());

        let pack = CrashPack::builder(CrashPackConfig {
            seed: 7,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0xBEEF)
        .build();

        let artifact = writer.write(&pack).unwrap();
        let expected_name = artifact_filename(&pack);

        // Artifact path should contain the deterministic filename
        assert!(artifact.path().contains(&expected_name));

        // File should exist and contain valid JSON
        let contents = std::fs::read_to_string(artifact.path()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["manifest"]["config"]["seed"], 7);

        // Cleanup
        let _ = std::fs::remove_file(artifact.path());
        let _ = std::fs::remove_dir(&dir);

        crate::test_complete!("file_writer_writes_to_disk");
    }

    #[test]
    fn file_writer_fails_on_missing_dir() {
        init_test("file_writer_fails_on_missing_dir");

        let writer =
            FileCrashPackWriter::new(std::path::PathBuf::from("/nonexistent/crashpack/dir"));

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .build();

        let result = writer.write(&pack);
        assert!(result.is_err());

        crate::test_complete!("file_writer_fails_on_missing_dir");
    }

    #[test]
    fn artifact_id_display() {
        init_test("artifact_id_display");

        let id = ArtifactId {
            path: "some/path.json".to_string(),
        };
        assert_eq!(format!("{id}"), "some/path.json");
        assert_eq!(id.path(), "some/path.json");

        crate::test_complete!("artifact_id_display");
    }

    #[test]
    fn conformance_no_ambient_writes() {
        init_test("conformance_no_ambient_writes");

        // The CrashPack::builder().build() path never touches the filesystem.
        // Writing requires an explicit CrashPackWriter.
        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .build();

        // pack exists in memory - no writer means no writes
        assert_eq!(pack.seed(), 42);

        // Only a writer can persist
        let writer = MemoryCrashPackWriter::new();
        assert_eq!(writer.count(), 0);
        writer.write(&pack).unwrap();
        assert_eq!(writer.count(), 1);

        crate::test_complete!("conformance_no_ambient_writes");
    }

    #[test]
    fn conformance_same_pack_same_artifact_path() {
        init_test("conformance_same_pack_same_artifact_path");

        let writer = MemoryCrashPackWriter::new();

        let pack = CrashPack::builder(CrashPackConfig {
            seed: 100,
            ..Default::default()
        })
        .failure(sample_failure())
        .fingerprint(0xFACE)
        .build();

        let id1 = writer.write(&pack).unwrap();
        let id2 = writer.write(&pack).unwrap();

        // Same pack produces same artifact path (deterministic naming)
        assert_eq!(id1.path(), id2.path());

        crate::test_complete!("conformance_same_pack_same_artifact_path");
    }

    // =================================================================
    // Manifest Schema Tests (bd-35u33)
    // =================================================================

    #[test]
    fn manifest_validate_current_version() {
        init_test("manifest_validate_current_version");

        let manifest = CrashPackManifest::new(CrashPackConfig::default(), 0, 0);
        assert!(manifest.validate().is_ok());
        assert!(manifest.is_compatible());
        assert_eq!(manifest.schema_version, CRASHPACK_SCHEMA_VERSION);

        crate::test_complete!("manifest_validate_current_version");
    }

    #[test]
    fn manifest_validate_rejects_future_version() {
        init_test("manifest_validate_rejects_future_version");

        let mut manifest = CrashPackManifest::new(CrashPackConfig::default(), 0, 0);
        manifest.schema_version = CRASHPACK_SCHEMA_VERSION + 1;

        let err = manifest.validate().unwrap_err();
        assert!(!manifest.is_compatible());
        assert!(matches!(err, ManifestValidationError::VersionTooNew { .. }));
        // Display impl
        assert!(err.to_string().contains("newer than supported"));

        crate::test_complete!("manifest_validate_rejects_future_version");
    }

    #[test]
    fn manifest_validate_rejects_old_version() {
        init_test("manifest_validate_rejects_old_version");

        let mut manifest = CrashPackManifest::new(CrashPackConfig::default(), 0, 0);
        manifest.schema_version = 0; // below minimum

        let err = manifest.validate().unwrap_err();
        assert!(!manifest.is_compatible());
        assert!(matches!(err, ManifestValidationError::VersionTooOld { .. }));
        assert!(err.to_string().contains("older than minimum"));

        crate::test_complete!("manifest_validate_rejects_old_version");
    }

    #[test]
    fn manifest_attachments_auto_populated() {
        init_test("manifest_attachments_auto_populated");

        // A pack with canonical prefix, divergent prefix, and oracle violations
        // should have those listed as attachments.
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&events)
            .divergent_prefix(vec![ReplayEvent::RngSeed { seed: 42 }])
            .oracle_violations(vec!["inv-1".into()])
            .build();

        assert_eq!(pack.manifest.attachments.len(), 3);
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::CanonicalPrefix));
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::DivergentPrefix));
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::OracleViolations));
        assert!(!pack
            .manifest
            .has_attachment(&AttachmentKind::EvidenceLedger));
        assert!(!pack
            .manifest
            .has_attachment(&AttachmentKind::SupervisionLog));

        crate::test_complete!("manifest_attachments_auto_populated");
    }

    #[test]
    fn manifest_empty_pack_no_attachments() {
        init_test("manifest_empty_pack_no_attachments");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .build();

        assert!(pack.manifest.attachments.is_empty());

        crate::test_complete!("manifest_empty_pack_no_attachments");
    }

    #[test]
    fn manifest_attachment_item_counts() {
        init_test("manifest_attachment_item_counts");

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .canonical_prefix(vec![
                vec![TraceEventKey {
                    kind: 1,
                    primary: 0,
                    secondary: 0,
                    tertiary: 0,
                }],
                vec![
                    TraceEventKey {
                        kind: 2,
                        primary: 1,
                        secondary: 0,
                        tertiary: 0,
                    },
                    TraceEventKey {
                        kind: 2,
                        primary: 2,
                        secondary: 0,
                        tertiary: 0,
                    },
                ],
            ])
            .supervision_snapshot(SupervisionSnapshot {
                virtual_time: Time::from_secs(1),
                task: tid(1),
                region: rid(0),
                decision: "restart".into(),
                context: None,
            })
            .build();

        // Canonical prefix: 2 layers with 3 total events
        let cp = pack
            .manifest
            .attachment(&AttachmentKind::CanonicalPrefix)
            .unwrap();
        assert_eq!(cp.item_count, 3);

        // Supervision log: 1 entry
        let sl = pack
            .manifest
            .attachment(&AttachmentKind::SupervisionLog)
            .unwrap();
        assert_eq!(sl.item_count, 1);

        crate::test_complete!("manifest_attachment_item_counts");
    }

    #[test]
    fn manifest_attachment_kind_serde_round_trip() {
        init_test("manifest_attachment_kind_serde_round_trip");

        let kinds = vec![
            AttachmentKind::CanonicalPrefix,
            AttachmentKind::DivergentPrefix,
            AttachmentKind::EvidenceLedger,
            AttachmentKind::SupervisionLog,
            AttachmentKind::OracleViolations,
            AttachmentKind::Custom {
                tag: "heap-dump".into(),
            },
        ];

        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let parsed: AttachmentKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, kind, "round trip failed for {json}");
        }

        crate::test_complete!("manifest_attachment_kind_serde_round_trip");
    }

    #[test]
    fn manifest_serde_round_trip_with_attachments() {
        init_test("manifest_serde_round_trip_with_attachments");

        let mut manifest = CrashPackManifest::new(sample_config(), 0xBEEF, 100);
        manifest.attachments = vec![
            ManifestAttachment {
                kind: AttachmentKind::CanonicalPrefix,
                item_count: 10,
                size_hint_bytes: 2048,
            },
            ManifestAttachment {
                kind: AttachmentKind::Custom {
                    tag: "user-data".into(),
                },
                item_count: 1,
                size_hint_bytes: 0,
            },
        ];

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: CrashPackManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, CRASHPACK_SCHEMA_VERSION);
        assert_eq!(parsed.config.seed, 42);
        assert_eq!(parsed.fingerprint, 0xBEEF);
        assert_eq!(parsed.attachments.len(), 2);
        assert_eq!(parsed.attachments[0].kind, AttachmentKind::CanonicalPrefix);
        assert_eq!(parsed.attachments[0].item_count, 10);
        assert_eq!(parsed.attachments[0].size_hint_bytes, 2048);
        assert_eq!(
            parsed.attachments[1].kind,
            AttachmentKind::Custom {
                tag: "user-data".into()
            }
        );

        crate::test_complete!("manifest_serde_round_trip_with_attachments");
    }

    #[test]
    fn manifest_deserialize_without_attachments() {
        init_test("manifest_deserialize_without_attachments");

        // Simulate a v1 manifest JSON that was written before the attachments
        // field existed. The #[serde(default)] should handle this gracefully.
        let json = r#"{
            "schema_version": 1,
            "config": { "seed": 1, "config_hash": 0, "worker_count": 1 },
            "fingerprint": 999,
            "event_count": 50,
            "created_at": 0
        }"#;

        let manifest: CrashPackManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.fingerprint, 999);
        assert!(manifest.attachments.is_empty());
        assert!(manifest.is_compatible());

        crate::test_complete!("manifest_deserialize_without_attachments");
    }

    #[test]
    fn manifest_json_skips_empty_attachments() {
        init_test("manifest_json_skips_empty_attachments");

        let manifest = CrashPackManifest::new(CrashPackConfig::default(), 0, 0);
        let json = serde_json::to_string(&manifest).unwrap();

        // Empty attachments should be skipped by skip_serializing_if
        assert!(!json.contains("attachments"));

        crate::test_complete!("manifest_json_skips_empty_attachments");
    }

    #[test]
    fn manifest_json_skips_zero_size_hint() {
        init_test("manifest_json_skips_zero_size_hint");

        let attachment = ManifestAttachment {
            kind: AttachmentKind::CanonicalPrefix,
            item_count: 5,
            size_hint_bytes: 0,
        };
        let json = serde_json::to_string(&attachment).unwrap();
        assert!(!json.contains("size_hint_bytes"));

        let non_zero = ManifestAttachment {
            kind: AttachmentKind::CanonicalPrefix,
            item_count: 5,
            size_hint_bytes: 1024,
        };
        let json2 = serde_json::to_string(&non_zero).unwrap();
        assert!(json2.contains("size_hint_bytes"));

        crate::test_complete!("manifest_json_skips_zero_size_hint");
    }

    #[test]
    fn conformance_attachments_in_crash_pack_json() {
        init_test("conformance_attachments_in_crash_pack_json");

        // Full crash pack with all sections → attachments appear in JSON
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
        ];

        let pack = CrashPack::builder(sample_config())
            .failure(sample_failure())
            .from_trace(&events)
            .divergent_prefix(vec![ReplayEvent::RngSeed { seed: 42 }])
            .oracle_violations(vec!["v1".into()])
            .supervision_snapshot(SupervisionSnapshot {
                virtual_time: Time::from_secs(1),
                task: tid(1),
                region: rid(0),
                decision: "restart".into(),
                context: None,
            })
            .build();

        let writer = MemoryCrashPackWriter::new();
        writer.write(&pack).unwrap();
        let json_str = &writer.written()[0].1;
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

        let atts = parsed["manifest"]["attachments"].as_array().unwrap();
        assert_eq!(atts.len(), 4);

        // Verify kinds are tagged correctly
        let kinds: Vec<&str> = atts.iter().map(|a| a["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"CanonicalPrefix"));
        assert!(kinds.contains(&"DivergentPrefix"));
        assert!(kinds.contains(&"SupervisionLog"));
        assert!(kinds.contains(&"OracleViolations"));

        crate::test_complete!("conformance_attachments_in_crash_pack_json");
    }

    #[test]
    fn conformance_validation_error_is_std_error() {
        init_test("conformance_validation_error_is_std_error");

        let err = ManifestValidationError::VersionTooNew {
            manifest_version: 99,
            supported_version: 1,
        };

        // Must implement std::error::Error
        let _: &dyn std::error::Error = &err;
        assert!(err.to_string().contains("99"));

        crate::test_complete!("conformance_validation_error_is_std_error");
    }

    // =================================================================
    // Replay Command Contract Tests (bd-1teda)
    // =================================================================

    #[test]
    fn replay_command_from_config_basic() {
        init_test("replay_command_from_config_basic");

        let config = CrashPackConfig {
            seed: 42,
            config_hash: 0xDEAD,
            worker_count: 4,
            max_steps: Some(1000),
            commit_hash: Some("abc123".to_string()),
        };

        let cmd = ReplayCommand::from_config(&config, None);
        assert_eq!(cmd.program, "cargo");
        assert!(cmd.args.contains(&"--seed".to_string()));
        assert!(cmd.args.contains(&"42".to_string()));
        assert!(!cmd.env.is_empty());
        assert!(cmd.command_line.contains("cargo"));
        assert!(cmd.command_line.contains("--seed"));
        assert!(cmd.command_line.contains("42"));
        assert!(cmd.command_line.contains("ASUPERSYNC_WORKERS=4"));

        crate::test_complete!("replay_command_from_config_basic");
    }

    #[test]
    fn replay_command_from_config_with_artifact() {
        init_test("replay_command_from_config_with_artifact");

        let config = CrashPackConfig {
            seed: 99,
            worker_count: 2,
            ..Default::default()
        };

        let cmd = ReplayCommand::from_config(&config, Some("crashes/pack.json"));
        assert!(cmd.args.contains(&"--crashpack".to_string()));
        assert!(cmd.args.contains(&"crashes/pack.json".to_string()));
        assert!(cmd.command_line.contains("--crashpack"));
        assert!(cmd.command_line.contains("crashes/pack.json"));

        crate::test_complete!("replay_command_from_config_with_artifact");
    }

    #[test]
    fn replay_command_cli_mode() {
        init_test("replay_command_cli_mode");

        let config = CrashPackConfig {
            seed: 7,
            worker_count: 8,
            max_steps: Some(500),
            ..Default::default()
        };

        let cmd = ReplayCommand::from_config_cli(&config, "crashpack.json");
        assert_eq!(cmd.program, "asupersync");
        assert!(cmd.args.contains(&"trace".to_string()));
        assert!(cmd.args.contains(&"replay".to_string()));
        assert!(cmd.args.contains(&"--seed".to_string()));
        assert!(cmd.args.contains(&"7".to_string()));
        assert!(cmd.args.contains(&"--workers".to_string()));
        assert!(cmd.args.contains(&"8".to_string()));
        assert!(cmd.args.contains(&"--max-steps".to_string()));
        assert!(cmd.args.contains(&"500".to_string()));
        assert!(cmd.args.contains(&"crashpack.json".to_string()));
        assert!(cmd.env.is_empty());
        assert_eq!(
            cmd.command_line,
            "asupersync trace replay --seed 7 --workers 8 --max-steps 500 crashpack.json"
        );

        crate::test_complete!("replay_command_cli_mode");
    }

    #[test]
    fn replay_command_display() {
        init_test("replay_command_display");

        let cmd = ReplayCommand::from_config_cli(
            &CrashPackConfig {
                seed: 1,
                worker_count: 1,
                ..Default::default()
            },
            "test.json",
        );

        let displayed = format!("{cmd}");
        assert_eq!(displayed, cmd.command_line);

        crate::test_complete!("replay_command_display");
    }

    #[test]
    fn replay_command_serde_round_trip() {
        init_test("replay_command_serde_round_trip");

        let cmd = ReplayCommand::from_config(
            &CrashPackConfig {
                seed: 42,
                worker_count: 4,
                max_steps: Some(1000),
                ..Default::default()
            },
            Some("pack.json"),
        );

        let json = serde_json::to_string_pretty(&cmd).unwrap();
        let parsed: ReplayCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);

        crate::test_complete!("replay_command_serde_round_trip");
    }

    #[test]
    fn replay_command_in_crash_pack() {
        init_test("replay_command_in_crash_pack");

        let config = sample_config();
        let replay_cmd = ReplayCommand::from_config(&config, Some("crashes/test.json"));

        let pack = CrashPack::builder(config)
            .failure(sample_failure())
            .fingerprint(0xCAFE)
            .replay(replay_cmd.clone())
            .build();

        assert_eq!(pack.replay.as_ref(), Some(&replay_cmd));

        // Appears in JSON
        let writer = MemoryCrashPackWriter::new();
        writer.write(&pack).unwrap();
        let json_str = &writer.written()[0].1;
        let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert!(parsed["replay"]["program"].as_str().is_some());
        assert!(parsed["replay"]["command_line"]
            .as_str()
            .unwrap()
            .contains("--seed"));

        crate::test_complete!("replay_command_in_crash_pack");
    }

    #[test]
    fn replay_command_absent_by_default() {
        init_test("replay_command_absent_by_default");

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .build();

        assert!(pack.replay.is_none());

        // replay field should be absent from JSON
        let writer = MemoryCrashPackWriter::new();
        writer.write(&pack).unwrap();
        let json_str = &writer.written()[0].1;
        assert!(!json_str.contains("\"replay\""));

        crate::test_complete!("replay_command_absent_by_default");
    }

    #[test]
    fn replay_command_convenience_method() {
        init_test("replay_command_convenience_method");

        let pack = CrashPack::builder(CrashPackConfig {
            seed: 77,
            worker_count: 2,
            ..Default::default()
        })
        .failure(sample_failure())
        .build();

        let cmd = pack.replay_command(Some("output.json"));
        assert!(cmd.command_line.contains("--seed"));
        assert!(cmd.command_line.contains("77"));
        assert!(cmd.command_line.contains("output.json"));

        crate::test_complete!("replay_command_convenience_method");
    }

    #[test]
    fn replay_command_max_steps_included_when_set() {
        init_test("replay_command_max_steps_included_when_set");

        let with_steps = ReplayCommand::from_config(
            &CrashPackConfig {
                seed: 1,
                max_steps: Some(999),
                ..Default::default()
            },
            None,
        );
        assert!(with_steps.command_line.contains("ASUPERSYNC_MAX_STEPS=999"));

        let without_steps = ReplayCommand::from_config(
            &CrashPackConfig {
                seed: 1,
                max_steps: None,
                ..Default::default()
            },
            None,
        );
        assert!(!without_steps.command_line.contains("ASUPERSYNC_MAX_STEPS"));

        crate::test_complete!("replay_command_max_steps_included_when_set");
    }

    #[test]
    fn shell_escape_handles_special_chars() {
        init_test("shell_escape_handles_special_chars");

        // Safe strings pass through
        assert_eq!(shell_escape("hello"), "hello");
        assert_eq!(shell_escape("path/to/file.json"), "path/to/file.json");
        assert_eq!(shell_escape("42"), "42");

        // Strings with spaces get quoted
        assert_eq!(shell_escape("hello world"), "'hello world'");

        // Empty string
        assert_eq!(shell_escape(""), "''");

        crate::test_complete!("shell_escape_handles_special_chars");
    }

    // =================================================================
    // Golden Crashpack + Replay Tests (bd-3mfjw)
    // =================================================================

    /// A controlled failure scenario: two workers in a region, one panics.
    fn golden_failure_events() -> Vec<TraceEvent> {
        vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(100), tid(1), rid(1)),
            TraceEvent::poll(5, Time::from_nanos(100), tid(2), rid(1)),
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ]
    }

    fn golden_config() -> CrashPackConfig {
        CrashPackConfig {
            seed: 42,
            config_hash: 0xDEAD,
            worker_count: 4,
            max_steps: Some(1000),
            commit_hash: Some("abc123def".to_string()),
        }
    }

    fn golden_failure_info() -> FailureInfo {
        FailureInfo {
            task: tid(2),
            region: rid(1),
            outcome: FailureOutcome::Panicked {
                message: "worker panic in golden scenario".to_string(),
            },
            virtual_time: Time::from_nanos(200),
        }
    }

    #[test]
    fn golden_deterministic_emission() {
        init_test("golden_deterministic_emission");

        let events = golden_failure_events();

        // Build the same crash pack twice.
        let pack1 = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .build();

        let pack2 = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .build();

        // Determinism: same inputs → same pack (modulo created_at).
        assert_eq!(pack1, pack2);
        assert_eq!(pack1.fingerprint(), pack2.fingerprint());
        assert_eq!(pack1.canonical_prefix, pack2.canonical_prefix);
        assert_eq!(pack1.manifest.event_count, pack2.manifest.event_count);

        crate::test_complete!("golden_deterministic_emission");
    }

    #[test]
    fn golden_fingerprint_stability() {
        init_test("golden_fingerprint_stability");

        let events = golden_failure_events();
        let pack = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .build();

        // The fingerprint must be non-zero and consistent.
        let fp = pack.fingerprint();
        assert_ne!(fp, 0);

        // Rebuild from scratch — fingerprint must match exactly.
        let fp2 = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .build()
            .fingerprint();
        assert_eq!(fp, fp2);

        // Independently compute via trace_fingerprint().
        assert_eq!(fp, crate::trace::canonicalize::trace_fingerprint(&events));

        crate::test_complete!("golden_fingerprint_stability");
    }

    #[test]
    fn golden_canonical_prefix_structure() {
        init_test("golden_canonical_prefix_structure");

        let events = golden_failure_events();
        let pack = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .build();

        // Expected Foata structure for the golden scenario:
        //   Layer 0: region_created(R1) — no predecessors
        //   Layer 1: spawn(T1,R1), spawn(T2,R1) — depend on region_created
        //   Layer 2: poll(T1,R1), poll(T2,R1) — depend on respective spawns
        //   Layer 3: complete(T1,R1) — depends on poll(T1)
        assert_eq!(
            pack.canonical_prefix.len(),
            4,
            "expected 4 Foata layers, got {}",
            pack.canonical_prefix.len()
        );
        assert_eq!(pack.canonical_prefix[0].len(), 1); // region_created
        assert_eq!(pack.canonical_prefix[1].len(), 2); // spawn×2
        assert_eq!(pack.canonical_prefix[2].len(), 2); // poll×2
        assert_eq!(pack.canonical_prefix[3].len(), 1); // complete

        // Event count matches input.
        assert_eq!(pack.manifest.event_count, 6);

        crate::test_complete!("golden_canonical_prefix_structure");
    }

    #[test]
    fn golden_equivalent_schedule_same_pack() {
        init_test("golden_equivalent_schedule_same_pack");

        // The golden scenario with independent spawns/polls in swapped order.
        // This is a different schedule of the same concurrent execution.
        let events_a = golden_failure_events();
        let events_b = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1)), // T2 first
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)), // T1 second
            TraceEvent::poll(4, Time::from_nanos(100), tid(2), rid(1)),
            TraceEvent::poll(5, Time::from_nanos(100), tid(1), rid(1)),
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ];

        let pack_a = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events_a)
            .build();
        let pack_b = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events_b)
            .build();

        // Same equivalence class → same crash pack.
        assert_eq!(pack_a.fingerprint(), pack_b.fingerprint());
        assert_eq!(pack_a.canonical_prefix, pack_b.canonical_prefix);
        assert_eq!(pack_a, pack_b);

        crate::test_complete!("golden_equivalent_schedule_same_pack");
    }

    #[test]
    fn golden_replay_prefix_round_trip() {
        use crate::trace::replay::{
            CompactRegionId, CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata,
        };
        use crate::trace::replayer::TraceReplayer;

        init_test("golden_replay_prefix_round_trip");

        // Build a ReplayTrace matching the golden scenario.
        let replay_events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::RegionCreated {
                region: CompactRegionId(1),
                parent: None,
                at_tick: 0,
            },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(1),
                region: CompactRegionId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(2),
                region: CompactRegionId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(1),
                at_tick: 100,
            },
            ReplayEvent::TaskScheduled {
                task: CompactTaskId(2),
                at_tick: 100,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 0, // Ok
            },
        ];

        let trace = ReplayTrace {
            metadata: TraceMetadata::new(42),
            events: replay_events.clone(),
            cursor: 0,
        };

        // Build crash pack with the divergent prefix.
        let pack = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&golden_failure_events())
            .divergent_prefix(replay_events.clone())
            .build();

        assert!(pack.has_divergent_prefix());
        assert_eq!(pack.divergent_prefix.len(), 7);

        // Verify the replayer can step through the divergent prefix
        // without any divergence errors.
        let mut replayer = TraceReplayer::new(trace);
        for expected_event in &replay_events {
            let actual = replayer.next().expect("replayer should have more events");
            assert_eq!(actual, expected_event);
        }
        assert!(replayer.is_completed());

        crate::test_complete!("golden_replay_prefix_round_trip");
    }

    #[test]
    fn golden_replay_serialization_round_trip() {
        use crate::trace::replay::{
            CompactRegionId, CompactTaskId, ReplayEvent, ReplayTrace, TraceMetadata,
        };

        init_test("golden_replay_serialization_round_trip");

        let replay_events = vec![
            ReplayEvent::RngSeed { seed: 42 },
            ReplayEvent::TaskSpawned {
                task: CompactTaskId(1),
                region: CompactRegionId(1),
                at_tick: 0,
            },
            ReplayEvent::TaskCompleted {
                task: CompactTaskId(1),
                outcome: 3, // Panicked
            },
        ];

        let mut trace = ReplayTrace::new(TraceMetadata::new(42));
        for ev in &replay_events {
            trace.push(ev.clone());
        }

        // Serialize → deserialize round trip.
        let bytes = trace.to_bytes().expect("serialize");
        let loaded = ReplayTrace::from_bytes(&bytes).expect("deserialize");

        assert_eq!(loaded.metadata.seed, 42);
        assert_eq!(loaded.events.len(), 3);
        assert_eq!(loaded.events, replay_events);

        crate::test_complete!("golden_replay_serialization_round_trip");
    }

    #[test]
    fn golden_crash_pack_json_round_trip() {
        init_test("golden_crash_pack_json_round_trip");

        let events = golden_failure_events();
        let pack = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&events)
            .oracle_violations(vec!["invariant-x".into()])
            .build();

        let writer = MemoryCrashPackWriter::new();
        writer.write(&pack).unwrap();
        let written = writer.written();
        let json = &written[0].1;

        // Parse the JSON and verify key fields.
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(parsed["manifest"]["config"]["seed"], 42);
        assert_eq!(parsed["manifest"]["config"]["config_hash"], 0xDEAD_u64);
        assert_eq!(parsed["manifest"]["event_count"], 6);
        assert_ne!(parsed["manifest"]["fingerprint"], 0);
        assert_eq!(parsed["oracle_violations"][0], "invariant-x");

        // Canonical prefix should be present.
        let prefix = &parsed["canonical_prefix"];
        assert!(prefix.is_array());
        assert_eq!(prefix.as_array().unwrap().len(), 4); // 4 Foata layers

        crate::test_complete!("golden_crash_pack_json_round_trip");
    }

    #[test]
    fn golden_minimization_integration() {
        use crate::trace::divergence::{minimize_divergent_prefix, MinimizationConfig};
        use crate::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};

        init_test("golden_minimization_integration");

        // Build a replay prefix: the failure "happens" at event index 5+.
        let replay_events: Vec<_> = (0..20)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();

        let trace = ReplayTrace {
            metadata: TraceMetadata::new(42),
            events: replay_events,
            cursor: 0,
        };

        // Oracle: failure reproduces when prefix has >= 12 events.
        let threshold = 12;
        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= threshold
        });

        assert_eq!(result.minimized_len, threshold);
        assert_eq!(result.original_len, 20);
        assert!(!result.truncated);

        // The minimized prefix can be set on a crash pack.
        let pack = CrashPack::builder(golden_config())
            .failure(golden_failure_info())
            .from_trace(&golden_failure_events())
            .divergent_prefix(result.prefix.events)
            .build();

        assert!(pack.has_divergent_prefix());
        assert_eq!(pack.divergent_prefix.len(), threshold);

        crate::test_complete!("golden_minimization_integration");
    }

    // =========================================================================
    // Crash Pack Walkthrough (bd-16jzr)
    //
    // A self-contained walkthrough that demonstrates the crash pack lifecycle:
    //
    //   1. Forced failure    — a task panics during execution
    //   2. Crash pack emit   — build & write the repro artifact
    //   3. Fingerprint       — canonical fingerprint is schedule-independent
    //   4. Replay command    — copy-paste one-liner for reproduction
    //   5. Minimization      — shrink the divergent prefix
    //
    // Run with:  cargo test --lib crashpack::tests::walkthrough
    // =========================================================================

    /// Step 1: Build a crash pack from a simulated failure.
    ///
    /// A supervised task panics at virtual time 200ns. We record the
    /// deterministic seed, config hash, and trace events into a crash pack.
    #[test]
    fn walkthrough_01_forced_failure_and_emission() {
        init_test("walkthrough_01_forced_failure_and_emission");

        // -- Simulate execution producing trace events --
        //
        // In a real Spork app, these events are emitted by the LabRuntime.
        // Here we construct them directly to show the data flow.
        let events = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(100), tid(1), rid(1)),
            TraceEvent::poll(5, Time::from_nanos(100), tid(2), rid(1)),
            // Task 1 completes normally; task 2 will panic.
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ];

        // -- Record the failure --
        let failure = FailureInfo {
            task: tid(2),
            region: rid(1),
            outcome: FailureOutcome::Panicked {
                message: "assertion failed: balance >= 0".to_string(),
            },
            virtual_time: Time::from_nanos(200),
        };

        // -- Build the crash pack --
        //
        // The builder computes the canonical prefix (Foata normal form),
        // fingerprint, and event count from the raw trace.
        let config = CrashPackConfig {
            seed: 42,
            config_hash: 0xCAFE,
            worker_count: 2,
            max_steps: Some(500),
            commit_hash: Some("a1b2c3d".to_string()),
        };

        let pack = CrashPack::builder(config)
            .failure(failure)
            .from_trace(&events)
            .oracle_violations(vec!["balance-invariant".to_string()])
            .build();

        // -- Verify the crash pack --
        assert_eq!(pack.seed(), 42);
        assert_eq!(pack.manifest.schema_version, CRASHPACK_SCHEMA_VERSION);
        assert_eq!(pack.manifest.event_count, 6);
        assert!(
            pack.manifest.fingerprint != 0,
            "fingerprint should be non-zero"
        );
        assert!(pack.has_violations());
        assert_eq!(pack.oracle_violations, vec!["balance-invariant"]);

        // The canonical prefix is non-empty (Foata layers).
        assert!(
            !pack.canonical_prefix.is_empty(),
            "canonical prefix should have Foata layers"
        );

        // Manifest auto-populates the attachment table.
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::CanonicalPrefix));
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::OracleViolations));

        crate::test_complete!("walkthrough_01_forced_failure_and_emission");
    }

    /// Step 2: Write the crash pack to storage and read it back.
    ///
    /// The artifact filename is deterministic: same seed + fingerprint
    /// always produces the same path.
    #[test]
    fn walkthrough_02_write_and_read_artifact() {
        init_test("walkthrough_02_write_and_read_artifact");

        let pack = walkthrough_pack();

        // -- Write using the in-memory writer --
        let writer = MemoryCrashPackWriter::new();
        let artifact = writer.write(&pack).expect("write should succeed");

        // Deterministic filename: crashpack-{seed:016x}-{fingerprint:016x}-v{ver}.json
        assert!(
            artifact.path().starts_with("crashpack-000000000000002a-"),
            "path should encode seed 42 (0x2a): {}",
            artifact.path()
        );
        assert!(
            artifact.path().ends_with("-v1.json"),
            "path should end with schema version: {}",
            artifact.path()
        );

        // -- Read back and verify round-trip --
        let written = writer.written();
        assert_eq!(written.len(), 1);
        let json = &written[0].1;
        let parsed: serde_json::Value = serde_json::from_str(json).expect("valid JSON");

        // The manifest is at the top level.
        assert_eq!(parsed["manifest"]["config"]["seed"], 42);
        assert_eq!(parsed["manifest"]["schema_version"], 1);

        // The failure info is present.
        assert!(
            parsed["failure"]["outcome"]["Panicked"]["message"]
                .as_str()
                .unwrap()
                .contains("balance >= 0"),
            "failure message should be preserved"
        );

        crate::test_complete!("walkthrough_02_write_and_read_artifact");
    }

    /// Step 3: Canonical fingerprint is schedule-independent.
    ///
    /// Two schedules that differ only in the order of independent events
    /// produce the same fingerprint (same Foata normal form).
    #[test]
    fn walkthrough_03_fingerprint_interpretation() {
        use crate::trace::canonicalize::trace_fingerprint;

        init_test("walkthrough_03_fingerprint_interpretation");

        // Schedule A: task 1 polled before task 2
        let schedule_a = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(100), tid(1), rid(1)),
            TraceEvent::poll(5, Time::from_nanos(100), tid(2), rid(1)),
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ];

        // Schedule B: task 2 polled before task 1 (commuted independent events)
        let schedule_b = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(100), tid(2), rid(1)), // swapped
            TraceEvent::poll(5, Time::from_nanos(100), tid(1), rid(1)), // swapped
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ];

        let fp_a = trace_fingerprint(&schedule_a);
        let fp_b = trace_fingerprint(&schedule_b);

        // Same fingerprint: the two schedules are equivalent modulo
        // commutation of independent events (polls at the same virtual time
        // on different tasks in the same region).
        assert_eq!(
            fp_a, fp_b,
            "equivalent schedules should have the same canonical fingerprint"
        );

        crate::test_complete!("walkthrough_03_fingerprint_interpretation");
    }

    /// Step 4: Replay command generation.
    ///
    /// The crash pack generates a shell one-liner that reproduces the failure.
    /// Two modes: `cargo test` (development) and `asupersync trace replay` (CLI).
    #[test]
    fn walkthrough_04_replay_command() {
        init_test("walkthrough_04_replay_command");

        let pack = walkthrough_pack();

        // -- cargo test mode --
        let replay = pack.replay_command(None);
        assert_eq!(replay.program, "cargo");
        assert!(replay.args.contains(&"--seed".to_string()));
        assert!(replay.args.contains(&"42".to_string()));

        // The command_line is a shell-ready string.
        assert!(
            replay.command_line.contains("cargo test"),
            "command line should contain cargo test: {}",
            replay.command_line
        );
        assert!(
            replay.command_line.contains("--seed 42"),
            "command line should contain seed: {}",
            replay.command_line
        );

        // -- With artifact path --
        let replay_with_path = pack.replay_command(Some("/tmp/crashpacks/my_pack.json"));
        assert!(
            replay_with_path
                .command_line
                .contains("/tmp/crashpacks/my_pack.json"),
            "command line should reference artifact: {}",
            replay_with_path.command_line
        );

        // -- CLI mode --
        let cli_replay =
            ReplayCommand::from_config_cli(&pack.manifest.config, "/tmp/crashpack.json");
        assert_eq!(cli_replay.program, "asupersync");
        assert!(
            cli_replay.command_line.contains("trace replay"),
            "CLI mode should use 'trace replay' subcommand: {}",
            cli_replay.command_line
        );

        // -- Display shows the one-liner --
        let display = format!("{replay}");
        assert_eq!(display, replay.command_line);

        crate::test_complete!("walkthrough_04_replay_command");
    }

    /// Step 5: Prefix minimization shrinks the divergent prefix.
    ///
    /// Given a long replay trace, minimization finds the shortest prefix
    /// that still reproduces the failure. This is the "bisect" phase.
    #[test]
    fn walkthrough_05_minimization() {
        use crate::trace::divergence::{minimize_divergent_prefix, MinimizationConfig};
        use crate::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};

        init_test("walkthrough_05_minimization");

        // -- Simulate a long replay trace (50 events) --
        let replay_events: Vec<_> = (0..50)
            .map(|i| ReplayEvent::RngValue { value: i })
            .collect();

        let trace = ReplayTrace {
            metadata: TraceMetadata::new(42),
            events: replay_events,
            cursor: 0,
        };

        // Oracle: the failure reproduces when prefix length >= 15.
        let failure_threshold = 15;
        let result = minimize_divergent_prefix(&trace, &MinimizationConfig::default(), |prefix| {
            prefix.len() >= failure_threshold
        });

        assert_eq!(result.minimized_len, failure_threshold);
        assert_eq!(result.original_len, 50);

        // -- Embed the minimized prefix into a crash pack --
        let config = CrashPackConfig {
            seed: 42,
            config_hash: 0xCAFE,
            worker_count: 2,
            max_steps: Some(500),
            commit_hash: Some("a1b2c3d".to_string()),
        };

        let failure = FailureInfo {
            task: tid(2),
            region: rid(1),
            outcome: FailureOutcome::Panicked {
                message: "assertion failed: balance >= 0".to_string(),
            },
            virtual_time: Time::from_nanos(200),
        };

        let pack = CrashPack::builder(config)
            .failure(failure)
            .divergent_prefix(result.prefix.events)
            .fingerprint(0xABCD)
            .build();

        assert!(pack.has_divergent_prefix());
        assert_eq!(
            pack.divergent_prefix.len(),
            failure_threshold,
            "minimized prefix should be {failure_threshold} events, not {}",
            pack.divergent_prefix.len()
        );

        // Attachment table reflects the divergent prefix.
        assert!(pack
            .manifest
            .has_attachment(&AttachmentKind::DivergentPrefix));
        let att = pack
            .manifest
            .attachment(&AttachmentKind::DivergentPrefix)
            .unwrap();
        assert_eq!(att.item_count, failure_threshold as u64);

        crate::test_complete!("walkthrough_05_minimization");
    }

    /// Helper: build the walkthrough crash pack used by multiple steps.
    fn walkthrough_pack() -> CrashPack {
        let events = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(1)),
            TraceEvent::poll(4, Time::from_nanos(100), tid(1), rid(1)),
            TraceEvent::poll(5, Time::from_nanos(100), tid(2), rid(1)),
            TraceEvent::complete(6, Time::from_nanos(200), tid(1), rid(1)),
        ];

        let config = CrashPackConfig {
            seed: 42,
            config_hash: 0xCAFE,
            worker_count: 2,
            max_steps: Some(500),
            commit_hash: Some("a1b2c3d".to_string()),
        };

        let failure = FailureInfo {
            task: tid(2),
            region: rid(1),
            outcome: FailureOutcome::Panicked {
                message: "assertion failed: balance >= 0".to_string(),
            },
            virtual_time: Time::from_nanos(200),
        };

        CrashPack::builder(config)
            .failure(failure)
            .from_trace(&events)
            .oracle_violations(vec!["balance-invariant".to_string()])
            .build()
    }
}
