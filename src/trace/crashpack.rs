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
//! .build()
//! .expect("crash pack builder should have failure metadata");
//!
//! assert_eq!(pack.manifest.schema_version, CRASHPACK_SCHEMA_VERSION);
//! ```
//!
//! # Bead
//!
//! bd-2md12 | Parent: bd-qbcnu

use crate::trace::canonicalize::{TraceEventKey, canonicalize, trace_event_key, trace_fingerprint};
use crate::trace::event::TraceEvent;
use crate::trace::replay::ReplayEvent;
use crate::trace::scoring::EvidenceEntry;
use crate::types::{CancelKind, RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

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

    /// Exact libtest name that produced this crash pack.
    ///
    /// Optional for crash packs created outside a test harness and for
    /// backward compatibility with schema-v1 packs written before this field
    /// existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_name: Option<String>,

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
            test_name: None,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

    /// SHA-256 (hex) of the serialized crash pack body, excluding this field.
    ///
    /// The [`fingerprint`](Self::fingerprint) is derived from the *full* trace,
    /// which is not inlined in the pack, so a tampered or bit-rotted pack body
    /// would otherwise be indistinguishable from an intact one. This checksum
    /// seals the actual serialized bytes so [`CrashPack::verify_integrity`] can
    /// recompute and compare it. Optional so packs written before this field
    /// existed still deserialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_checksum: Option<String>,
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
    ///
    /// Stamps `created_at` from the wall clock. Deterministic-replay
    /// callers should use [`Self::new_with_created_at`] instead so the
    /// manifest is byte-stable across runs.
    #[must_use]
    pub fn new(config: CrashPackConfig, fingerprint: u64, event_count: u64) -> Self {
        Self::new_with_created_at(config, fingerprint, event_count, wall_clock_nanos())
    }

    /// br-asupersync-h0vru4 — Create a manifest with an explicit
    /// `created_at` timestamp (nanoseconds since UNIX epoch). Use this
    /// from deterministic-replay paths that have a `Cx`-scoped time
    /// (e.g. `cx.now().as_nanos()` under [`crate::lab::LabRuntime`]) so
    /// the resulting manifest is byte-identical across runs of the same
    /// scenario.
    #[must_use]
    pub fn new_with_created_at(
        config: CrashPackConfig,
        fingerprint: u64,
        event_count: u64,
        created_at: u64,
    ) -> Self {
        Self {
            schema_version: CRASHPACK_SCHEMA_VERSION,
            config,
            fingerprint,
            event_count,
            created_at,
            attachments: Vec::new(),
            content_checksum: None,
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
            && self.manifest.attachments == other.manifest.attachments
            && self.failure == other.failure
            && self.canonical_prefix == other.canonical_prefix
            && self.divergent_prefix == other.divergent_prefix
            && self.evidence == other.evidence
            && self.supervision_log == other.supervision_log
            && self.oracle_violations == other.oracle_violations
            && self.replay == other.replay
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
            created_at: None,
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
    /// `ReplayCommand::from_config(&pack.manifest.config)`.
    #[must_use]
    pub fn replay_command(&self) -> ReplayCommand {
        ReplayCommand::from_config(&self.manifest.config)
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

    /// Recompute the content checksum and compare it to the sealed value.
    ///
    /// Returns `true` iff the manifest carries a `content_checksum` that matches
    /// a fresh SHA-256 digest of this pack's serialized body. This detects
    /// tampering or bit rot of any body field — including sections (evidence,
    /// prefixes, supervision log) that the manifest `fingerprint` does not
    /// cover. A pack whose `content_checksum` is `None` (written before the
    /// field existed) returns `false`: there is nothing to verify against.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let Some(stored) = self.manifest.content_checksum.as_deref() else {
            return false;
        };
        let mut probe = self.clone();
        probe.manifest.content_checksum = None;
        compute_content_checksum(&probe).as_str() == stored
    }
}

/// Compute the content checksum of a crash pack: SHA-256 (hex) of the pack
/// serialized with `manifest.content_checksum` cleared.
///
/// The digest is over the body only. Callers pass a pack whose
/// `content_checksum` is `None`; the field's `skip_serializing_if` also keeps
/// it out of the serialized bytes, so the digest never covers itself and is
/// reproducible.
fn compute_content_checksum(pack: &CrashPack) -> String {
    let bytes = serde_json::to_vec(pack).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
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
    created_at: Option<u64>,
    canonical_prefix: Vec<Vec<TraceEventKey>>,
    divergent_prefix: Vec<ReplayEvent>,
    evidence: Vec<EvidenceEntrySnapshot>,
    supervision_log: Vec<SupervisionSnapshot>,
    oracle_violations: Vec<String>,
    replay: Option<ReplayCommand>,
}

/// Error returned when a [`CrashPackBuilder`] is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPackBuildError {
    /// The builder did not receive the required [`FailureInfo`].
    MissingFailure,
}

impl fmt::Display for CrashPackBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFailure => f.write_str("crash pack builder requires failure metadata"),
        }
    }
}

impl std::error::Error for CrashPackBuildError {}

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

    /// Set an explicit `created_at` timestamp for deterministic artifacts.
    ///
    /// Lab-driven crash packs should pass virtual time here so serialized
    /// artifacts are byte-stable across re-runs of the same seed.
    #[must_use]
    pub fn created_at(mut self, created_at: u64) -> Self {
        self.created_at = Some(created_at);
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
    pub fn build(self) -> Result<CrashPack, CrashPackBuildError> {
        let failure = self.failure.ok_or(CrashPackBuildError::MissingFailure)?;

        // Sort supervision log with a total order for determinism.
        // Equal virtual times are expected in practice; include stable
        // secondary keys so serialization does not depend on insertion order.
        let mut supervision_log = self.supervision_log;
        supervision_log.sort_by(|a, b| {
            a.virtual_time
                .cmp(&b.virtual_time)
                .then_with(|| a.task.cmp(&b.task))
                .then_with(|| a.region.cmp(&b.region))
                .then_with(|| a.decision.cmp(&b.decision))
                .then_with(|| a.context.cmp(&b.context))
        });

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

        let mut manifest = if let Some(created_at) = self.created_at {
            CrashPackManifest::new_with_created_at(
                self.config,
                self.fingerprint,
                self.event_count,
                created_at,
            )
        } else {
            CrashPackManifest::new(self.config, self.fingerprint, self.event_count)
        };
        manifest.attachments = attachments;

        let mut pack = CrashPack {
            manifest,
            failure,
            canonical_prefix: self.canonical_prefix,
            divergent_prefix: self.divergent_prefix,
            evidence: self.evidence,
            supervision_log,
            oracle_violations: self.oracle_violations,
            replay: self.replay,
        };
        // Seal the serialized body with a content checksum (over bytes with the
        // checksum field itself cleared) so a tampered/bit-rotted pack is
        // detectable via `CrashPack::verify_integrity`.
        let checksum = compute_content_checksum(&pack);
        pack.manifest.content_checksum = Some(checksum);
        Ok(pack)
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
///   "args": ["test", "lab::tests::case", "--", "--exact", "--nocapture"],
///   "env": [
///     {"key": "ASUPERSYNC_LAB_TEST_SEED", "value": "42"},
///     {"key": "ASUPERSYNC_WORKERS", "value": "4"}
///   ],
///   "command_line": "ASUPERSYNC_LAB_TEST_SEED=42 ASUPERSYNC_WORKERS=4 cargo test lab::tests::case -- --exact --nocapture"
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
    pub fn from_config(config: &CrashPackConfig) -> Self {
        let mut args = vec!["test".to_string()];
        if let Some(test_name) = config.test_name.as_deref().filter(|name| !name.is_empty()) {
            args.push(test_name.to_string());
        }
        args.extend([
            "--".to_string(),
            "--exact".to_string(),
            "--nocapture".to_string(),
        ]);

        let mut env = vec![ReplayEnvVar {
            key: "ASUPERSYNC_LAB_TEST_SEED".to_string(),
            value: config.seed.to_string(),
        }];
        env.push(ReplayEnvVar {
            key: "ASUPERSYNC_WORKERS".to_string(),
            value: config.worker_count.to_string(),
        });

        env.push(ReplayEnvVar {
            key: "ASUPERSYNC_MAX_STEPS".to_string(),
            value: config
                .max_steps
                .map_or_else(|| "none".to_string(), |steps| steps.to_string()),
        });

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
        parts.push(format!(
            "{}={}",
            shell_escape(&var.key),
            shell_escape(&var.value)
        ));
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
/// Artifact paths are deterministic:
/// `crashpack-{seed:016x}-{config_hash:016x}-{fingerprint:016x}-v{version}.json`.
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
/// Format: `crashpack-{seed:016x}-{config_hash:016x}-{fingerprint:016x}-v{version}.json`
#[must_use]
pub fn artifact_filename(pack: &CrashPack) -> String {
    format!(
        "crashpack-{:016x}-{:016x}-{:016x}-v{}.json",
        pack.seed(),
        pack.manifest.config.config_hash,
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
        let path = self.base_dir.join(&filename); // ubs:ignore - filename is deterministic hex string

        let json = serde_json::to_string_pretty(pack)
            .map_err(|e| CrashPackWriteError::Serialize(e.to_string()))?;

        // Atomic write: stage the JSON to a unique temp file in the same
        // directory, then rename it into place. `rename` is atomic on a single
        // filesystem, so a crash mid-write can only leave the temp file behind —
        // never a truncated JSON at the canonical, reader-visible path. The
        // temp name embeds the pid so concurrent writers of the same pack do
        // not clobber each other's staging file.
        let tmp_path = self
            .base_dir
            .join(format!(".{filename}.{}.tmp", std::process::id())); // ubs:ignore - staging path from deterministic filename

        std::fs::write(&tmp_path, json.as_bytes()).map_err(CrashPackWriteError::Io)?;
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            // Best-effort cleanup of the staged temp file on rename failure.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(CrashPackWriteError::Io(e));
        }

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
    packs: parking_lot::Mutex<Vec<(ArtifactId, String)>>,
}

impl MemoryCrashPackWriter {
    /// Create an empty in-memory writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all written packs as `(artifact_id, json)` pairs.
    pub fn written(&self) -> Vec<(ArtifactId, String)> {
        self.packs.lock().clone()
    }

    /// Returns the number of packs written.
    #[must_use]
    pub fn count(&self) -> usize {
        self.packs.lock().len()
    }
}

impl CrashPackWriter for MemoryCrashPackWriter {
    fn write(&self, pack: &CrashPack) -> Result<ArtifactId, CrashPackWriteError> {
        let filename = artifact_filename(pack);
        let json = serde_json::to_string_pretty(pack)
            .map_err(|e| CrashPackWriteError::Serialize(e.to_string()))?;

        let artifact_id = ArtifactId { path: filename };
        self.packs.lock().push((artifact_id.clone(), json));

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
        .map_or(0, |d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "crashpack_inline_tests.rs"]
mod tests;
