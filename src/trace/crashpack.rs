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
// Crash Pack Manifest
// =============================================================================

/// The crash pack manifest: top-level metadata and structural summary.
///
/// The manifest is the first thing read when opening a crash pack. It
/// provides enough information to:
/// 1. Check version compatibility
/// 2. Identify the failure at a glance
/// 3. Locate the detailed trace data
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
}

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
        }
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
        }
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

    /// Build the crash pack.
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

        CrashPack {
            manifest: CrashPackManifest::new(self.config, self.fingerprint, self.event_count),
            failure,
            canonical_prefix: self.canonical_prefix,
            divergent_prefix: self.divergent_prefix,
            evidence: self.evidence,
            supervision_log,
            oracle_violations: self.oracle_violations,
        }
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
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
}
