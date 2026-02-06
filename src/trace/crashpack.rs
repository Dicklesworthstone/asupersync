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
//! use asupersync::trace::crashpack::{CrashPack, CrashPackConfig, FailureInfo};
//! use asupersync::types::{TaskId, RegionId, Outcome, Time};
//!
//! let pack = CrashPack::builder(CrashPackConfig {
//!     seed: 42,
//!     config_hash: 0xDEAD,
//!     ..Default::default()
//! })
//! .failure(FailureInfo {
//!     task: TaskId::testing_default(),
//!     region: RegionId::testing_default(),
//!     outcome: Outcome::Panicked("oops".into()),
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

use crate::trace::canonicalize::TraceEventKey;
use crate::trace::replay::ReplayEvent;
use crate::trace::scoring::EvidenceEntry;
use crate::types::{Outcome, RegionId, TaskId, Time};
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureInfo {
    /// The task that failed.
    pub task: TaskId,

    /// The region containing the failed task.
    pub region: RegionId,

    /// The failure outcome (Err / Cancelled / Panicked).
    pub outcome: Outcome<(), ()>,

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

// =============================================================================
// Supervision Decision Snapshot
// =============================================================================

/// Snapshot of a supervision decision captured in the crash pack.
///
/// Records what the supervisor decided and why, providing the "evidence
/// ledger" for debugging supervision chain behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashPack {
    /// Top-level manifest with version, config, and fingerprint.
    pub manifest: CrashPackManifest,

    /// The triggering failure.
    pub failure: FailureInfo,

    /// Canonicalized trace prefix (Foata normal form layers of event keys).
    ///
    /// Bounded to avoid unbounded growth; the number of layers and events
    /// per layer are configurable at creation time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canonical_prefix: Vec<Vec<TraceEventKey>>,

    /// Minimal divergent prefix: the shortest replay event sequence that
    /// reaches the failure point.
    ///
    /// This is the primary repro artifact. Feed it to `TraceReplayer` to
    /// step through the execution up to the failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub divergent_prefix: Vec<ReplayEvent>,

    /// Evidence ledger entries capturing key runtime decisions.
    ///
    /// These are the "proof" entries from the scoring/evidence system
    /// that document why the runtime made particular choices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceEntry>,

    /// Supervision decision log leading up to the failure.
    ///
    /// Ordered by virtual time; captures the chain of restart/stop/escalate
    /// decisions that preceded (or caused) the failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supervision_log: Vec<SupervisionSnapshot>,

    /// Oracle invariant violations detected during the execution.
    ///
    /// Sorted and deduplicated. Empty if all invariants held.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    evidence: Vec<EvidenceEntry>,
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
        self.evidence = entries;
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
            manifest: CrashPackManifest::new(
                self.config,
                self.fingerprint,
                self.event_count,
            ),
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
    use crate::types::PanicPayload;
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
            outcome: Outcome::Panicked(PanicPayload::from("test panic")),
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
        assert_eq!(
            pack.manifest.config.commit_hash.as_deref(),
            Some("abc123")
        );
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
            outcome: Outcome::Panicked(PanicPayload::from("a")),
            virtual_time: Time::from_secs(5),
        };
        let f2 = FailureInfo {
            task: tid(1),
            region: rid(0),
            outcome: Outcome::Err(()), // different outcome
            virtual_time: Time::from_secs(5),
        };
        // Equality on (task, region, virtual_time)
        assert_eq!(f1, f2);

        let f3 = FailureInfo {
            task: tid(2), // different task
            region: rid(0),
            outcome: Outcome::Panicked(PanicPayload::from("a")),
            virtual_time: Time::from_secs(5),
        };
        assert_ne!(f1, f3);

        crate::test_complete!("failure_info_equality");
    }

    #[test]
    fn manifest_new_sets_version() {
        init_test("manifest_new_sets_version");

        let manifest =
            CrashPackManifest::new(CrashPackConfig::default(), 0xBEEF, 100);

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
                task_id: crate::trace::replay::CompactTaskId(1),
                at_tick: 0,
            },
        ];

        let pack = CrashPack::builder(CrashPackConfig::default())
            .failure(sample_failure())
            .divergent_prefix(prefix.clone())
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
}
