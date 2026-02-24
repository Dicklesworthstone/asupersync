//! Lab runtime for deterministic execution.
//!
//! The lab runtime executes tasks with:
//! - Virtual time (controlled advancement)
//! - Deterministic scheduling (seed-driven)
//! - Trace capture for replay
//! - Chaos injection for stress testing

use super::chaos::{ChaosRng, ChaosStats};
use super::config::LabConfig;
use super::oracle::OracleSuite;
use crate::record::ObligationKind;
use crate::record::task::TaskState;
use crate::runtime::RuntimeState;
use crate::runtime::config::ObligationLeakResponse;
use crate::runtime::deadline_monitor::{
    DeadlineMonitor, DeadlineWarning, MonitorConfig, default_warning_handler,
};
use crate::runtime::reactor::LabReactor;
use crate::runtime::scheduler::{DispatchLane, ScheduleCertificate};
use crate::time::VirtualClock;
use crate::trace::TraceBufferHandle;
use crate::trace::crashpack::{
    CrashPack, CrashPackConfig, FailureInfo, FailureOutcome, ReplayCommand, artifact_filename,
};
use crate::trace::event::TraceEventKind;
use crate::trace::recorder::TraceRecorder;
use crate::trace::replay::{ReplayEvent, ReplayTrace, TraceMetadata};
use crate::trace::scoring::seed_fingerprint;
use crate::trace::{TraceData, TraceEvent, check_refinement_firewall};
use crate::trace::{canonicalize::trace_fingerprint, certificate::TraceCertificate};
use crate::types::Time;
use crate::types::{ObligationId, RegionId, TaskId};
use crate::util::{DetEntropy, DetRng};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Summary of a trace certificate built from the current trace buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabTraceCertificateSummary {
    /// Incremental hash of witnessed events.
    pub event_hash: u64,
    /// Total number of events witnessed.
    pub event_count: u64,
    /// Hash of scheduling decisions (from [`ScheduleCertificate`]).
    pub schedule_hash: u64,
}

/// Report from a [`LabRuntime::run_with_auto_advance`] execution.
///
/// Captures statistics about automatic time advancement during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualTimeReport {
    /// Total scheduler steps executed.
    pub steps: u64,
    /// Number of times virtual time was auto-advanced to a timer deadline.
    pub auto_advances: u64,
    /// Total timer wakeups triggered by auto-advances.
    pub total_wakeups: u64,
    /// Virtual time at the start of the run.
    pub time_start: Time,
    /// Virtual time at the end of the run.
    pub time_end: Time,
    /// Total virtual nanoseconds elapsed during the run.
    pub virtual_elapsed_nanos: u64,
}

impl VirtualTimeReport {
    /// Returns the virtual elapsed time in milliseconds.
    #[must_use]
    pub const fn virtual_elapsed_ms(&self) -> u64 {
        self.virtual_elapsed_nanos / 1_000_000
    }

    /// Returns the virtual elapsed time in seconds.
    #[must_use]
    pub const fn virtual_elapsed_secs(&self) -> u64 {
        self.virtual_elapsed_nanos / 1_000_000_000
    }
}

/// Structured report for a single lab runtime run.
///
/// This is intended as a low-level building block for Spork app harnesses.
/// It contains canonical trace fingerprints and oracle outcomes, but it does
/// not write to stdout/stderr or persist artifacts.
#[derive(Debug, Clone)]
pub struct LabRunReport {
    /// Lab seed driving scheduling determinism.
    pub seed: u64,
    /// Steps executed during the `run_until_quiescent()` call that produced this report.
    pub steps_delta: u64,
    /// Total steps executed by the runtime so far.
    pub steps_total: u64,
    /// Whether the runtime is quiescent at report time.
    pub quiescent: bool,
    /// Virtual time (nanoseconds since epoch) at report time.
    pub now_nanos: u64,
    /// Number of events in the current trace buffer snapshot.
    pub trace_len: usize,
    /// Canonical fingerprint of the trace equivalence class (Foata / Mazurkiewicz).
    pub trace_fingerprint: u64,
    /// Trace certificate summary (event hash/count + schedule hash).
    pub trace_certificate: LabTraceCertificateSummary,
    /// Unified oracle report (stable ordering, serializable).
    pub oracle_report: crate::lab::oracle::OracleReport,
    /// Runtime invariant violations detected by `LabRuntime::check_invariants()`.
    ///
    /// This is distinct from the oracle suite: it's a small set of runtime-level
    /// checks (e.g., obligation leaks, futurelocks, quiescence violations).
    pub invariant_violations: Vec<String>,
    /// Temporal-oracle invariants that failed in this report.
    pub temporal_invariant_failures: Vec<String>,
    /// Minimized divergent-prefix length for temporal failures, when available.
    pub temporal_counterexample_prefix_len: Option<usize>,
    /// First failed refinement-firewall rule id, when present.
    pub refinement_firewall_rule_id: Option<String>,
    /// Event index where refinement-firewall first failed.
    pub refinement_firewall_event_index: Option<usize>,
    /// Event sequence where refinement-firewall first failed.
    pub refinement_firewall_event_seq: Option<u64>,
    /// Deterministic minimal counterexample prefix length for refinement failures.
    pub refinement_counterexample_prefix_len: Option<usize>,
    /// Whether refinement checks were skipped due to trace-buffer truncation.
    pub refinement_firewall_skipped_due_to_trace_truncation: bool,
}

impl LabRunReport {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "steps_delta": self.steps_delta,
            "steps_total": self.steps_total,
            "quiescent": self.quiescent,
            "now_nanos": self.now_nanos,
            "trace": {
                "len": self.trace_len,
                "fingerprint": self.trace_fingerprint,
                "certificate": {
                    "event_hash": self.trace_certificate.event_hash,
                    "event_count": self.trace_certificate.event_count,
                    "schedule_hash": self.trace_certificate.schedule_hash,
                }
            },
            "oracles": self.oracle_report.to_json(),
            "invariants": self.invariant_violations,
            "temporal": {
                "failed_invariants": self.temporal_invariant_failures,
                "counterexample_prefix_len": self.temporal_counterexample_prefix_len,
            },
            "refinement_firewall": {
                "rule_id": self.refinement_firewall_rule_id,
                "event_index": self.refinement_firewall_event_index,
                "event_seq": self.refinement_firewall_event_seq,
                "counterexample_prefix_len": self.refinement_counterexample_prefix_len,
                "skipped_due_to_trace_truncation": self.refinement_firewall_skipped_due_to_trace_truncation,
            },
        })
    }
}

const TEMPORAL_ORACLE_INVARIANTS: &[&str] = &[
    "task_leak",
    "obligation_leak",
    "quiescence",
    "cancellation_protocol",
    "loser_drain",
    "region_tree",
    "deadline_monotone",
];

// ---------------------------------------------------------------------------
// Spork app harness report schema (bd-11dm5)
// ---------------------------------------------------------------------------

/// Snapshot of a [`LabConfig`] captured into a stable, JSON-friendly schema.
///
/// This is intentionally a *summary* (not the raw config), so downstream tools
/// can depend on a stable field set without pulling in internal config types.
#[derive(Debug, Clone, PartialEq)]
pub struct LabConfigSummary {
    /// Random seed for deterministic scheduling.
    pub seed: u64,
    /// Seed for capability entropy sources (may be decoupled from `seed`).
    pub entropy_seed: u64,
    /// Number of modeled workers in the deterministic multi-worker simulation.
    pub worker_count: usize,
    /// Whether the runtime panics on obligation leaks in lab mode.
    pub panic_on_obligation_leak: bool,
    /// Capacity of the trace buffer.
    pub trace_capacity: usize,
    /// Maximum steps a task may remain unpolled while holding obligations before futurelock triggers.
    pub futurelock_max_idle_steps: u64,
    /// Whether the runtime panics when a futurelock is detected.
    pub panic_on_futurelock: bool,
    /// Optional maximum step limit for a run.
    pub max_steps: Option<u64>,
    /// Chaos configuration summary, when enabled.
    pub chaos: Option<ChaosConfigSummary>,
    /// Whether replay recording is enabled.
    pub replay_recording_enabled: bool,
}

impl LabConfigSummary {
    /// Build a config summary from the full [`LabConfig`].
    #[must_use]
    pub fn from_config(config: &LabConfig) -> Self {
        Self {
            seed: config.seed,
            entropy_seed: config.entropy_seed,
            worker_count: config.worker_count,
            panic_on_obligation_leak: config.panic_on_obligation_leak,
            trace_capacity: config.trace_capacity,
            futurelock_max_idle_steps: config.futurelock_max_idle_steps,
            panic_on_futurelock: config.panic_on_futurelock,
            max_steps: config.max_steps,
            chaos: config.chaos.as_ref().map(ChaosConfigSummary::from_config),
            replay_recording_enabled: config.replay_recording.is_some(),
        }
    }

    /// Compute a stable hash of the configuration for quick equivalence checking.
    ///
    /// Two configs with the same hash produced identical lab setups. Agents can
    /// compare config hashes across runs to confirm they used the same settings.
    #[must_use]
    pub fn config_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        // DefaultHasher is NOT stable across Rust versions; DetHasher uses a
        // fixed algorithm and seed for cross-version deterministic hashing.
        let mut h = crate::util::DetHasher::default();
        self.seed.hash(&mut h);
        self.entropy_seed.hash(&mut h);
        self.worker_count.hash(&mut h);
        self.panic_on_obligation_leak.hash(&mut h);
        self.trace_capacity.hash(&mut h);
        self.futurelock_max_idle_steps.hash(&mut h);
        self.panic_on_futurelock.hash(&mut h);
        self.max_steps.hash(&mut h);
        self.replay_recording_enabled.hash(&mut h);
        if let Some(ref c) = self.chaos {
            1u8.hash(&mut h);
            c.seed.hash(&mut h);
            c.cancel_probability.to_bits().hash(&mut h);
            c.delay_probability.to_bits().hash(&mut h);
            c.io_error_probability.to_bits().hash(&mut h);
            c.wakeup_storm_probability.to_bits().hash(&mut h);
            c.budget_exhaust_probability.to_bits().hash(&mut h);
        } else {
            0u8.hash(&mut h);
        }
        h.finish()
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "entropy_seed": self.entropy_seed,
            "worker_count": self.worker_count,
            "panic_on_obligation_leak": self.panic_on_obligation_leak,
            "trace_capacity": self.trace_capacity,
            "futurelock_max_idle_steps": self.futurelock_max_idle_steps,
            "panic_on_futurelock": self.panic_on_futurelock,
            "max_steps": self.max_steps,
            "chaos": self.chaos.as_ref().map(ChaosConfigSummary::to_json),
            "replay_recording_enabled": self.replay_recording_enabled,
        })
    }
}

/// JSON-friendly summary of chaos settings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChaosConfigSummary {
    /// Seed for deterministic chaos injection.
    pub seed: u64,
    /// Probability of injecting cancellation at each poll point.
    pub cancel_probability: f64,
    /// Probability of injecting delay at each poll point.
    pub delay_probability: f64,
    /// Probability of injecting an I/O error.
    pub io_error_probability: f64,
    /// Probability of triggering a spurious wakeup storm.
    pub wakeup_storm_probability: f64,
    /// Probability of injecting budget exhaustion.
    pub budget_exhaust_probability: f64,
}

impl ChaosConfigSummary {
    /// Build a chaos summary from the full chaos configuration.
    #[must_use]
    pub fn from_config(config: &super::chaos::ChaosConfig) -> Self {
        Self {
            seed: config.seed,
            cancel_probability: config.cancel_probability,
            delay_probability: config.delay_probability,
            io_error_probability: config.io_error_probability,
            wakeup_storm_probability: config.wakeup_storm_probability,
            budget_exhaust_probability: config.budget_exhaust_probability,
        }
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "seed": self.seed,
            "cancel_probability": self.cancel_probability,
            "delay_probability": self.delay_probability,
            "io_error_probability": self.io_error_probability,
            "wakeup_storm_probability": self.wakeup_storm_probability,
            "budget_exhaust_probability": self.budget_exhaust_probability,
        })
    }
}

/// Attachment kind for Spork harness reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HarnessAttachmentKind {
    /// Crash pack artifact (minimal repro pack).
    CrashPack,
    /// Replay trace artifact (recorded non-determinism for replay).
    ReplayTrace,
    /// Generic trace artifact (e.g., NDJSON/JSON trace snapshot).
    Trace,
    /// Other harness-defined artifact.
    Other,
}

impl fmt::Display for HarnessAttachmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrashPack => write!(f, "crashpack"),
            Self::ReplayTrace => write!(f, "replay_trace"),
            Self::Trace => write!(f, "trace"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Report attachment reference (path-only).
///
/// The lab runtime does not write artifacts; this is a schema hook that a harness
/// can fill in when it persists crash packs, replay traces, etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HarnessAttachmentRef {
    /// Attachment kind (used for deterministic ordering and downstream routing).
    pub kind: HarnessAttachmentKind,
    /// Artifact path (relative or absolute; interpreted by the harness).
    pub path: String,
}

impl HarnessAttachmentRef {
    /// Convenience constructor for crash pack attachments.
    #[must_use]
    pub fn crashpack(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::CrashPack,
            path: path.into(),
        }
    }

    /// Convenience constructor for replay trace attachments.
    #[must_use]
    pub fn replay_trace(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::ReplayTrace,
            path: path.into(),
        }
    }

    /// Convenience constructor for generic trace attachments.
    #[must_use]
    pub fn trace(path: impl Into<String>) -> Self {
        Self {
            kind: HarnessAttachmentKind::Trace,
            path: path.into(),
        }
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "kind": self.kind.to_string(),
            "path": self.path,
        })
    }
}

/// Deterministic crashpack linkage metadata exposed in harness reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashpackLink {
    /// Artifact path for the crashpack attachment.
    pub path: String,
    /// Stable crashpack identifier (seed + fingerprint tuple).
    pub id: String,
    /// Canonical trace fingerprint associated with this crashpack.
    pub fingerprint: u64,
    /// Reproduction command generated from the run config and crashpack path.
    pub replay: ReplayCommand,
}

impl CrashpackLink {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        json!({
            "path": self.path,
            "id": self.id,
            "fingerprint": self.fingerprint,
            "replay": self.replay,
        })
    }
}

/// Stable, JSON-first report schema for Spork app harness runs.
///
/// This wraps [`LabRunReport`] and adds:
/// - config snapshot (lab-side)
/// - stable fingerprint extraction points
/// - optional artifact attachment references (crash packs, replay traces, ...)
#[derive(Debug, Clone)]
pub struct SporkHarnessReport {
    /// Schema version for stable downstream parsing.
    pub schema_version: u32,
    /// Application identifier/name for the harness run.
    pub app: String,
    /// Lab configuration snapshot used for the run.
    pub config: LabConfigSummary,
    /// Low-level lab run report (trace fingerprints + oracles + invariants).
    pub run: LabRunReport,
    /// Optional attachment references (crash packs, replay traces, etc.).
    pub attachments: Vec<HarnessAttachmentRef>,
}

impl SporkHarnessReport {
    /// Current stable schema version.
    ///
    /// Increment when the JSON contract changes in a backward-incompatible way.
    /// Backward-compatible additions (new optional fields) do NOT require a bump.
    /// Breaking changes (field renames, type changes, removals) MUST bump this
    /// and document the migration in a comment here.
    ///
    /// # Version history
    ///
    /// - **v1**: Initial schema (bd-11dm5). Top-level keys: `schema_version`,
    ///   `app`, `lab`, `fingerprints`, `run`, `attachments`.
    /// - **v2**: Agent report contract (bd-f262i). Added `lab.config_hash` for
    ///   quick equivalence checking. Added `verdict` top-level key. No
    ///   breaking changes to existing fields.
    /// - **v3**: Crashpack linking contract (bd-1wen4). Added top-level
    ///   `crashpack` object with deterministic path/id/fingerprint/replay.
    pub const SCHEMA_VERSION: u32 = 3;

    /// Create a new harness report from a low-level lab run report.
    #[must_use]
    pub fn new(
        app: impl Into<String>,
        config: &LabConfig,
        run: LabRunReport,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            app: app.into(),
            config: LabConfigSummary::from_config(config),
            run,
            attachments,
        }
    }

    // -------------------------------------------------------------------------
    // Agent UX convenience methods (bd-f262i)
    // -------------------------------------------------------------------------

    /// Quick pass/fail verdict: all oracles passed and no invariant violations.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.run.oracle_report.all_passed() && self.run.invariant_violations.is_empty()
    }

    /// The canonical trace fingerprint for this run.
    #[must_use]
    pub fn trace_fingerprint(&self) -> u64 {
        self.run.trace_fingerprint
    }

    /// The lab seed that drove this run.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.run.seed
    }

    /// Config hash for quick equivalence checking across runs.
    #[must_use]
    pub fn config_hash(&self) -> u64 {
        self.config.config_hash()
    }

    /// Returns the path to the first crashpack attachment, if any.
    #[must_use]
    pub fn crashpack_path(&self) -> Option<&str> {
        self.attachments
            .iter()
            .find(|a| a.kind == HarnessAttachmentKind::CrashPack)
            .map(|a| a.path.as_str())
    }

    /// Deterministic crashpack linkage metadata when a crashpack is attached.
    #[must_use]
    pub fn crashpack_link(&self) -> Option<CrashpackLink> {
        let path = self.crashpack_path()?.to_string();
        let crash_config = CrashPackConfig {
            seed: self.seed(),
            config_hash: self.config_hash(),
            worker_count: self.config.worker_count,
            max_steps: self.config.max_steps,
            commit_hash: None,
        };
        let replay = ReplayCommand::from_config(&crash_config, Some(path.as_str()));
        Some(CrashpackLink {
            id: format!(
                "crashpack-{seed:016x}-{fingerprint:016x}",
                seed = self.seed(),
                fingerprint = self.trace_fingerprint()
            ),
            fingerprint: self.trace_fingerprint(),
            path,
            replay,
        })
    }

    /// Returns oracle failure descriptions, if any.
    #[must_use]
    pub fn oracle_failures(&self) -> Vec<String> {
        self.run
            .oracle_report
            .failures()
            .iter()
            .map(|e| {
                let desc = e
                    .violation
                    .as_ref()
                    .map_or_else(String::new, |v| format!(": {v}"));
                format!("{}{desc}", e.invariant)
            })
            .collect()
    }

    /// One-line human-readable summary suitable for agent log output.
    ///
    /// Format: `[PASS|FAIL] app="name" seed=N fingerprint=N oracles=P/T`
    #[must_use]
    pub fn summary_line(&self) -> String {
        let verdict = if self.passed() { "PASS" } else { "FAIL" };
        let oracle = &self.run.oracle_report;
        format!(
            "[{verdict}] app=\"{}\" seed={} fingerprint={} oracles={}/{} invariant_violations={}",
            self.app,
            self.run.seed,
            self.run.trace_fingerprint,
            oracle.passed,
            oracle.total,
            self.run.invariant_violations.len(),
        )
    }

    /// Convert to JSON for artifact storage.
    ///
    /// # Agent Report Contract (bd-f262i)
    ///
    /// This is the **single stable JSON schema** that agents rely on across:
    /// - Lab runs (`SporkAppHarness::run_to_report`)
    /// - DPOR exploration (`ExplorationReport` wraps these)
    /// - Conformance suites (test assertions against these fields)
    ///
    /// ## Top-level fields (v2)
    ///
    /// | Key              | Type    | Stable? | Description                              |
    /// |------------------|---------|---------|------------------------------------------|
    /// | `schema_version` | u32     | yes     | Schema version (bump on breaking change) |
    /// | `verdict`        | string  | yes     | `"pass"` or `"fail"`                     |
    /// | `app.name`       | string  | yes     | Application name from `AppSpec`           |
    /// | `lab.config`     | object  | yes     | Full config snapshot                      |
    /// | `lab.config_hash`| u64     | yes     | Quick config equivalence hash             |
    /// | `fingerprints.*` | u64     | yes     | Trace/schedule fingerprints               |
    /// | `run.*`          | object  | yes     | Full `LabRunReport` (oracles, invariants) |
    /// | `crashpack`      | object? | yes     | Deterministic crashpack linkage metadata  |
    /// | `attachments`    | array   | yes     | Sorted by (kind, path)                    |
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;

        // Ensure stable ordering regardless of insertion order.
        let mut attachments = self.attachments.clone();
        attachments.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));

        json!({
            "schema_version": self.schema_version,
            "verdict": if self.passed() { "pass" } else { "fail" },
            "app": { "name": self.app },
            "lab": {
                "config": self.config.to_json(),
                "config_hash": self.config.config_hash(),
            },
            "fingerprints": {
                "trace": self.run.trace_fingerprint,
                "event_hash": self.run.trace_certificate.event_hash,
                "event_count": self.run.trace_certificate.event_count,
                "schedule_hash": self.run.trace_certificate.schedule_hash,
            },
            "run": self.run.to_json(),
            "crashpack": self.crashpack_link().map(|link| link.to_json()),
            "attachments": attachments.iter().map(HarnessAttachmentRef::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The deterministic lab runtime.
///
/// This runtime is designed for testing and provides:
/// - Virtual time instead of wall-clock time
/// - Deterministic scheduling based on a seed
/// - Trace capture for debugging and replay
/// - Chaos injection for stress testing
#[derive(Debug)]
pub struct LabRuntime {
    /// Runtime state (public for tests and oracle access).
    pub state: RuntimeState,
    /// Lab reactor for deterministic I/O simulation.
    lab_reactor: Arc<LabReactor>,
    /// Tokens seen for I/O submissions (for trace emission).
    seen_io_tokens: HashSet<usize>,
    /// Scheduler.
    pub scheduler: Arc<Mutex<LabScheduler>>,
    /// Configuration.
    config: LabConfig,
    /// Deterministic RNG.
    rng: DetRng,
    /// Current virtual time.
    virtual_time: Time,
    /// Virtual clock backing the timer driver.
    virtual_clock: Arc<VirtualClock>,
    /// Number of steps executed.
    steps: u64,
    /// Chaos RNG for deterministic fault injection.
    chaos_rng: Option<ChaosRng>,
    /// Statistics about chaos injections.
    chaos_stats: ChaosStats,
    /// Replay recorder for deterministic trace capture.
    replay_recorder: TraceRecorder,
    /// Optional deadline monitor for warning callbacks.
    deadline_monitor: Option<DeadlineMonitor>,
    /// Oracle suite for invariant verification.
    pub oracles: OracleSuite,
    /// Schedule certificate for determinism verification.
    certificate: ScheduleCertificate,
}

impl LabRuntime {
    /// Creates a new lab runtime with the given configuration.
    #[must_use]
    pub fn new(config: LabConfig) -> Self {
        let rng = config.rng();
        let chaos_rng = config.chaos.as_ref().map(ChaosRng::from_config);
        let lab_reactor = config.chaos.as_ref().map_or_else(
            || Arc::new(LabReactor::new()),
            |chaos| Arc::new(LabReactor::with_chaos(chaos.clone())),
        );
        let mut state = RuntimeState::with_reactor(lab_reactor.clone());
        state.set_logical_clock_mode(crate::trace::distributed::LogicalClockMode::Lamport);
        state.set_obligation_leak_response(if config.panic_on_obligation_leak {
            ObligationLeakResponse::Panic
        } else {
            ObligationLeakResponse::Log
        });
        let virtual_clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
        state.set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(
            virtual_clock.clone(),
        ));
        state.set_entropy_source(Arc::new(DetEntropy::new(config.entropy_seed)));
        state.trace = TraceBufferHandle::new(config.trace_capacity);

        // Initialize replay recorder if configured
        let mut replay_recorder = if let Some(ref rec_config) = config.replay_recording {
            TraceRecorder::with_config(TraceMetadata::new(config.seed), rec_config.clone())
        } else {
            TraceRecorder::disabled()
        };

        // Record initial RNG seed
        replay_recorder.record_rng_seed(config.seed);

        crate::tracing_compat::info!("virtual clock initialized: start_time_ms=0");

        Self {
            state,
            lab_reactor,
            seen_io_tokens: HashSet::new(),
            scheduler: Arc::new(Mutex::new(LabScheduler::new(config.worker_count))),
            config,
            rng,
            virtual_time: Time::ZERO,
            virtual_clock,
            steps: 0,
            chaos_rng,
            chaos_stats: ChaosStats::new(),
            replay_recorder,
            deadline_monitor: None,
            oracles: OracleSuite::new(),
            certificate: ScheduleCertificate::new(),
        }
    }

    /// Creates a lab runtime with the default configuration.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new(LabConfig::new(seed))
    }

    /// Returns the current virtual time.
    #[must_use]
    pub const fn now(&self) -> Time {
        self.virtual_time
    }

    /// Returns the number of steps executed.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub const fn config(&self) -> &LabConfig {
        &self.config
    }

    /// Returns a handle to the lab reactor for deterministic I/O injection.
    #[must_use]
    pub fn lab_reactor(&self) -> &Arc<LabReactor> {
        &self.lab_reactor
    }

    /// Returns a reference to the trace buffer handle.
    #[must_use]
    pub fn trace(&self) -> &TraceBufferHandle {
        &self.state.trace
    }

    /// Returns a race report derived from the current trace buffer.
    #[must_use]
    pub fn detected_races(&self) -> crate::trace::dpor::RaceReport {
        crate::trace::dpor::detect_hb_races(&self.state.trace.snapshot())
    }

    /// Returns a reference to the chaos statistics.
    #[must_use]
    pub fn chaos_stats(&self) -> &ChaosStats {
        &self.chaos_stats
    }

    /// Returns the schedule certificate for determinism verification.
    #[must_use]
    pub fn certificate(&self) -> &ScheduleCertificate {
        &self.certificate
    }

    /// Returns true if replay recording is enabled.
    #[must_use]
    pub fn has_replay_recording(&self) -> bool {
        self.replay_recorder.is_enabled()
    }

    /// Returns a reference to the replay recorder.
    #[must_use]
    pub fn replay_recorder(&self) -> &TraceRecorder {
        &self.replay_recorder
    }

    /// Takes the replay trace, leaving an empty trace in place.
    ///
    /// Returns `None` if recording is disabled.
    pub fn take_replay_trace(&mut self) -> Option<ReplayTrace> {
        self.replay_recorder.take()
    }

    /// Finishes recording and returns the replay trace.
    ///
    /// This consumes the replay recorder. Returns `None` if recording is disabled.
    pub fn finish_replay_trace(&mut self) -> Option<ReplayTrace> {
        // Take ownership by replacing with a disabled recorder
        let recorder = std::mem::replace(&mut self.replay_recorder, TraceRecorder::disabled());
        recorder.finish()
    }

    /// Returns true if chaos injection is enabled.
    #[must_use]
    pub fn has_chaos(&self) -> bool {
        self.chaos_rng.is_some() && self.config.has_chaos()
    }

    /// Returns true if the runtime is quiescent.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.state.is_quiescent()
    }

    /// Advances virtual time by the given number of nanoseconds.
    pub fn advance_time(&mut self, nanos: u64) {
        let from = self.virtual_time;
        self.virtual_time = self.virtual_time.saturating_add_nanos(nanos);
        self.state.now = self.virtual_time;
        self.virtual_clock.advance(nanos);
        self.lab_reactor.advance_time(Duration::from_nanos(nanos));
        // Record time advancement
        self.replay_recorder
            .record_time_advanced(from, self.virtual_time);

        crate::tracing_compat::debug!(
            "virtual clock advanced: delta_ms={}, new_time_ms={}",
            nanos / 1_000_000,
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Advances time to the given absolute time.
    ///
    /// If the target time is before the current time, logs an error
    /// and does nothing (time cannot go backward).
    pub fn advance_time_to(&mut self, time: Time) {
        if time > self.virtual_time {
            let from = self.virtual_time;
            self.virtual_time = time;
            self.state.now = self.virtual_time;
            self.virtual_clock.advance_to(time);
            self.lab_reactor.advance_time_to(time);
            // Record time advancement
            self.replay_recorder
                .record_time_advanced(from, self.virtual_time);

            crate::tracing_compat::debug!(
                "virtual clock advanced: delta_ms={}, new_time_ms={}",
                (time.as_nanos() - from.as_nanos()) / 1_000_000,
                time.as_nanos() / 1_000_000
            );
        } else if time < self.virtual_time {
            crate::tracing_compat::error!(
                "virtual clock attempt to go backward: current_ms={}, requested_ms={}",
                self.virtual_time.as_nanos() / 1_000_000,
                time.as_nanos() / 1_000_000
            );
        }
    }

    // =========================================================================
    // Virtual time control (bd-1hu19.3)
    // =========================================================================

    /// Advances virtual time to the next timer deadline.
    ///
    /// If a timer is pending, advances time to its deadline, processes the
    /// expired timer(s), and returns the number of wakeups triggered.
    /// Returns 0 if no timers are pending.
    pub fn advance_to_next_timer(&mut self) -> usize {
        let next = self
            .state
            .timer_driver_handle()
            .and_then(|h| h.next_deadline());

        let Some(deadline) = next else {
            return 0;
        };

        if deadline <= self.virtual_time {
            // Timer already expired, just process it
            return self
                .state
                .timer_driver_handle()
                .map_or(0, |h| h.process_timers());
        }

        let delta_nanos = deadline.as_nanos() - self.virtual_time.as_nanos();
        self.advance_time(delta_nanos);

        let wakeups = self
            .state
            .timer_driver_handle()
            .map_or(0, |h| h.process_timers());

        crate::tracing_compat::debug!(
            "virtual clock auto-advance: reason=all_tasks_blocked, \
             next_wakeup_ms={}, delta_ms={}, wakeup_count={}",
            deadline.as_nanos() / 1_000_000,
            delta_nanos / 1_000_000,
            wakeups
        );

        wakeups
    }

    /// Returns the next timer deadline, if any timers are pending.
    #[must_use]
    pub fn next_timer_deadline(&self) -> Option<Time> {
        self.state
            .timer_driver_handle()
            .and_then(|h| h.next_deadline())
    }

    /// Returns the number of pending timers.
    #[must_use]
    pub fn pending_timer_count(&self) -> usize {
        self.state
            .timer_driver_handle()
            .map_or(0, |h| h.pending_count())
    }

    /// Runs until quiescent, automatically advancing virtual time to pending
    /// timer deadlines whenever all tasks are idle.
    ///
    /// This enables "instant timeout testing": a scenario that would take
    /// 24 hours of wall-clock time completes in <1 second because every
    /// `sleep`/`timeout` deadline is jumped to instantly.
    ///
    /// The loop is:
    /// 1. Run until idle (no runnable tasks in scheduler).
    /// 2. If timers are pending, advance time to next deadline → go to 1.
    /// 3. If no timers and quiescent → done.
    ///
    /// Returns a [`VirtualTimeReport`] with execution statistics.
    pub fn run_with_auto_advance(&mut self) -> VirtualTimeReport {
        let start_steps = self.steps;
        let mut auto_advances: u64 = 0;
        let mut total_wakeups: u64 = 0;
        let start_time = self.virtual_time;

        loop {
            // Check step limit
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }

            // Run until the scheduler is empty
            let is_empty = self.scheduler.lock().is_empty();
            if !is_empty {
                self.step();
                continue;
            }

            // Scheduler is empty — check if we should auto-advance
            if let Some(deadline) = self.next_timer_deadline() {
                if deadline > self.virtual_time {
                    let wakeups = self.advance_to_next_timer();
                    auto_advances += 1;
                    total_wakeups += wakeups as u64;
                    continue;
                }
                // Timer at or before current time — process and continue
                let wakeups = self
                    .state
                    .timer_driver_handle()
                    .map_or(0, |h| h.process_timers());
                if wakeups > 0 {
                    total_wakeups += wakeups as u64;
                    continue;
                }
            }

            // No runnable tasks and no pending timers → quiescent
            if self.is_quiescent() {
                break;
            }

            // Not quiescent but nothing to advance — try one more step
            // (there may be I/O or finalizers to process)
            self.step();
        }

        VirtualTimeReport {
            steps: self.steps - start_steps,
            auto_advances,
            total_wakeups,
            time_start: start_time,
            time_end: self.virtual_time,
            virtual_elapsed_nanos: self.virtual_time.as_nanos() - start_time.as_nanos(),
        }
    }

    /// Pauses the virtual clock, freezing time at the current value.
    ///
    /// While paused, `advance_time()` and timer processing still work at the
    /// `LabRuntime` level (they update the runtime's own `virtual_time` field),
    /// but the underlying `VirtualClock` visible to tasks via `Cx::now()` is
    /// frozen. This is useful for testing timeout detection: tasks that call
    /// `Cx::now()` will see time standing still while the runtime can still
    /// orchestrate scheduling.
    pub fn pause_clock(&self) {
        self.virtual_clock.pause();
        crate::tracing_compat::info!(
            "virtual clock paused at time_ms={}",
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Resumes a paused virtual clock.
    pub fn resume_clock(&self) {
        self.virtual_clock.resume();
        crate::tracing_compat::info!(
            "virtual clock resumed at time_ms={}",
            self.virtual_time.as_nanos() / 1_000_000
        );
    }

    /// Returns true if the virtual clock is currently paused.
    #[must_use]
    pub fn is_clock_paused(&self) -> bool {
        self.virtual_clock.is_paused()
    }

    /// Injects a clock skew by jumping time forward by `skew_nanos`.
    ///
    /// This simulates clock drift or NTP corrections. A warning is logged
    /// because large jumps may affect lease/timeout correctness.
    #[allow(clippy::no_effect_underscore_binding)]
    pub fn inject_clock_skew(&mut self, skew_nanos: u64) {
        let _old_time = self.virtual_time;
        self.advance_time(skew_nanos);

        crate::tracing_compat::warn!(
            "virtual clock jump detected: old_time_ms={}, new_time_ms={}, jump_ms={} \
             -- may affect lease/timeout correctness",
            _old_time.as_nanos() / 1_000_000,
            self.virtual_time.as_nanos() / 1_000_000,
            skew_nanos / 1_000_000
        );
    }

    /// Runs until quiescent or max steps reached.
    ///
    /// Returns the number of steps executed.
    pub fn run_until_quiescent(&mut self) -> u64 {
        let start_steps = self.steps;

        while !self.is_quiescent() {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }
            self.step();
        }

        self.steps - start_steps
    }

    /// Runs until there are no runnable tasks in the scheduler.
    ///
    /// This is intentionally weaker than [`Self::run_until_quiescent`]:
    /// - It does **not** require all tasks to complete.
    /// - It does **not** require all obligations to be resolved.
    ///
    /// Use this when a test wants to "poll once" until the system is *idle*
    /// (e.g. a task is blocked on a channel receive) without forcing full
    /// completion and drain.
    pub fn run_until_idle(&mut self) -> u64 {
        let start_steps = self.steps;

        loop {
            if let Some(max) = self.config.max_steps {
                if self.steps >= max {
                    break;
                }
            }

            let is_empty = self.scheduler.lock().is_empty();
            if is_empty {
                break;
            }

            self.step();
        }

        self.steps - start_steps
    }

    /// Runs until quiescent (or `max_steps` is reached) and returns a structured report.
    #[must_use]
    pub fn run_until_quiescent_with_report(&mut self) -> LabRunReport {
        let steps_delta = self.run_until_quiescent();
        self.report_with_steps_delta(steps_delta)
    }

    /// Build a structured report for the current runtime state.
    ///
    /// This does not advance execution.
    #[must_use]
    pub fn report(&mut self) -> LabRunReport {
        self.report_with_steps_delta(0)
    }

    /// Runs until quiescent (or `max_steps` is reached) and returns a Spork harness report.
    #[must_use]
    pub fn run_until_quiescent_spork_report(
        &mut self,
        app: impl Into<String>,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        let run = self.run_until_quiescent_with_report();
        self.build_spork_report(app.into(), run, attachments)
    }

    /// Build a Spork harness report for the current runtime state.
    ///
    /// This does not advance execution.
    #[must_use]
    pub fn spork_report(
        &mut self,
        app: impl Into<String>,
        attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        let run = self.report();
        self.build_spork_report(app.into(), run, attachments)
    }

    fn build_spork_report(
        &self,
        app: String,
        run: LabRunReport,
        mut attachments: Vec<HarnessAttachmentRef>,
    ) -> SporkHarnessReport {
        if let Some(auto_crashpack) = self.auto_crashpack_attachment(&run, &attachments) {
            attachments.push(auto_crashpack);
        }
        SporkHarnessReport::new(app, &self.config, run, attachments)
    }

    fn auto_crashpack_attachment(
        &self,
        run: &LabRunReport,
        attachments: &[HarnessAttachmentRef],
    ) -> Option<HarnessAttachmentRef> {
        if attachments
            .iter()
            .any(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack)
        {
            return None;
        }
        let crashpack = self.build_crashpack_for_report(run)?;
        Some(HarnessAttachmentRef::crashpack(artifact_filename(
            &crashpack,
        )))
    }

    /// Build an in-memory crashpack for a failing report.
    ///
    /// Returns `None` for passing reports.
    #[must_use]
    pub fn build_crashpack_for_report(&self, run: &LabRunReport) -> Option<CrashPack> {
        let has_failure = !run.oracle_report.all_passed()
            || !run.invariant_violations.is_empty()
            || run.refinement_firewall_rule_id.is_some();
        if !has_failure {
            return None;
        }

        let config_summary = LabConfigSummary::from_config(&self.config);
        let crash_config = CrashPackConfig {
            seed: run.seed,
            config_hash: config_summary.config_hash(),
            worker_count: self.config.worker_count,
            max_steps: self.config.max_steps,
            commit_hash: None,
        };

        let (task, region) = self
            .state
            .tasks_iter()
            .find(|(_, task)| !task.state.is_terminal())
            .map(|(_, task)| (task.id, task.owner))
            .or_else(|| {
                self.state
                    .obligations_iter()
                    .find(|(_, obligation)| obligation.is_pending())
                    .map(|(_, obligation)| (obligation.holder, obligation.region))
            })
            .or_else(|| {
                self.state
                    .regions_iter()
                    .next()
                    .map(|(_, region)| (TaskId::testing_default(), region.id))
            })
            .or_else(|| {
                self.state
                    .root_region
                    .map(|root| (TaskId::testing_default(), root))
            })
            .unwrap_or((TaskId::testing_default(), RegionId::testing_default()));

        let mut oracle_violations = run.invariant_violations.clone();
        oracle_violations.extend(
            run.oracle_report
                .failures()
                .iter()
                .map(|entry| entry.invariant.clone()),
        );
        if let Some(rule_id) = &run.refinement_firewall_rule_id {
            oracle_violations.push(format!("refinement_firewall:{rule_id}"));
        }
        if let Some(prefix_len) = run.refinement_counterexample_prefix_len {
            oracle_violations.push(format!(
                "refinement_firewall:minimal_counterexample_prefix_len={prefix_len}"
            ));
        }
        oracle_violations.sort();
        oracle_violations.dedup();

        let trace_events = self.trace().snapshot();
        let mut builder = CrashPack::builder(crash_config.clone())
            .failure(FailureInfo {
                task,
                region,
                outcome: FailureOutcome::Err,
                virtual_time: Time::from_nanos(run.now_nanos),
            })
            .oracle_violations(oracle_violations)
            .replay(ReplayCommand::from_config(&crash_config, None));

        let divergent_prefix = self.auto_divergent_prefix();
        if !divergent_prefix.is_empty() {
            builder = builder.divergent_prefix(divergent_prefix);
        }

        builder = if trace_events.is_empty() {
            builder
                .fingerprint(run.trace_fingerprint)
                .event_count(run.trace_certificate.event_count)
        } else {
            builder.from_trace(&trace_events)
        };

        Some(builder.build())
    }

    fn auto_divergent_prefix(&self) -> Vec<ReplayEvent> {
        let Some(replay_trace) = self.replay_recorder.snapshot() else {
            return Vec::new();
        };
        if replay_trace.events.is_empty() {
            return Vec::new();
        }

        let failure_index = replay_trace
            .events
            .iter()
            .position(
                |event| matches!(event, ReplayEvent::TaskCompleted { outcome, .. } if *outcome > 0),
            )
            .unwrap_or(replay_trace.events.len() - 1);

        crate::trace::minimal_divergent_prefix(&replay_trace, failure_index).events
    }

    fn report_with_steps_delta(&mut self, steps_delta: u64) -> LabRunReport {
        let seed = self.config.seed;
        let quiescent = self.is_quiescent();
        let now = self.now();

        let trace_events = self.trace().snapshot();
        let trace_len = trace_events.len();

        let trace_fingerprint = if trace_events.is_empty() {
            // Mirror explorer behavior: ensure the report fingerprint varies by seed
            // even if trace capture is effectively disabled / empty.
            seed_fingerprint(seed)
        } else {
            trace_fingerprint(&trace_events)
        };

        let schedule_hash = self.certificate().hash();
        let mut certificate = TraceCertificate::new();
        for e in &trace_events {
            certificate.record_event(e);
        }
        certificate.set_schedule_hash(schedule_hash);

        self.oracles.hydrate_temporal_from_state(&self.state, now);
        let oracle_report = self.oracles.report(now);
        let temporal_invariant_failures = oracle_report
            .failures()
            .into_iter()
            .filter(|entry| TEMPORAL_ORACLE_INVARIANTS.contains(&entry.invariant.as_str()))
            .map(|entry| entry.invariant.clone())
            .collect::<Vec<_>>();
        let temporal_counterexample_prefix_len = if temporal_invariant_failures.is_empty() {
            None
        } else {
            let prefix_len = self.auto_divergent_prefix().len();
            (prefix_len > 0).then_some(prefix_len)
        };
        let refinement_firewall_skipped_due_to_trace_truncation =
            self.trace().total_pushed() > trace_events.len() as u64;
        let refinement_violation = if refinement_firewall_skipped_due_to_trace_truncation {
            None
        } else {
            check_refinement_firewall(&trace_events).first_violation
        };
        let refinement_violation = refinement_violation.as_ref();
        let refinement_firewall_rule_id = refinement_violation.map(|v| v.rule_id.to_owned());
        let refinement_firewall_event_index = refinement_violation.map(|v| v.event_index);
        let refinement_firewall_event_seq = refinement_violation.map(|v| v.event_seq);
        let refinement_counterexample_prefix_len =
            refinement_firewall_event_index.map(|idx| idx + 1);

        let mut invariant_violations = self
            .check_invariants()
            .into_iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        for invariant in &temporal_invariant_failures {
            invariant_violations.push(format!("temporal:{invariant}"));
        }
        if let Some(prefix_len) = temporal_counterexample_prefix_len {
            invariant_violations.push(format!(
                "temporal:minimal_divergent_prefix_len={prefix_len}"
            ));
        }
        if let Some(rule_id) = &refinement_firewall_rule_id {
            invariant_violations.push(format!("refinement_firewall:{rule_id}"));
        }
        if let Some(prefix_len) = refinement_counterexample_prefix_len {
            invariant_violations.push(format!(
                "refinement_firewall:minimal_counterexample_prefix_len={prefix_len}"
            ));
        }
        invariant_violations.sort();
        invariant_violations.dedup();

        LabRunReport {
            seed,
            steps_delta,
            steps_total: self.steps(),
            quiescent,
            now_nanos: now.as_nanos(),
            trace_len,
            trace_fingerprint,
            trace_certificate: LabTraceCertificateSummary {
                event_hash: certificate.event_hash(),
                event_count: certificate.event_count(),
                schedule_hash: certificate.schedule_hash(),
            },
            oracle_report,
            invariant_violations,
            temporal_invariant_failures,
            temporal_counterexample_prefix_len,
            refinement_firewall_rule_id,
            refinement_firewall_event_index,
            refinement_firewall_event_seq,
            refinement_counterexample_prefix_len,
            refinement_firewall_skipped_due_to_trace_truncation,
        }
    }

    /// Enable deadline monitoring with the default warning handler.
    pub fn enable_deadline_monitoring(&mut self, config: MonitorConfig) {
        self.enable_deadline_monitoring_with_handler(config, default_warning_handler);
    }

    /// Enable deadline monitoring with a custom warning handler.
    pub fn enable_deadline_monitoring_with_handler<F>(&mut self, config: MonitorConfig, f: F)
    where
        F: Fn(DeadlineWarning) + Send + Sync + 'static,
    {
        let mut monitor = DeadlineMonitor::new(config);
        monitor.on_warning(f);
        self.deadline_monitor = Some(monitor);
    }

    /// Returns a mutable reference to the deadline monitor, if enabled.
    pub fn deadline_monitor_mut(&mut self) -> Option<&mut DeadlineMonitor> {
        self.deadline_monitor.as_mut()
    }

    /// Executes a single step.
    #[allow(clippy::too_many_lines)]
    fn step(&mut self) {
        self.steps += 1;
        // Consume RNG state so schedule tie-breaking is deterministic once we
        // start making scheduler decisions here.
        let rng_value = self.rng.next_u64();
        self.replay_recorder.record_rng_value(rng_value);
        self.check_futurelocks();
        if let Some(timer) = self.state.timer_driver_handle() {
            let _ = timer.process_timers();
        }
        self.poll_io();
        self.schedule_async_finalizers();

        // 1. Choose a worker and pop a task (deterministic multi-worker model)
        let worker_count = self.config.worker_count.max(1);
        let worker_hint = (rng_value as usize) % worker_count;
        let now = self.now();
        let (task_id, dispatch_lane) = {
            let mut sched = self.scheduler.lock();
            if let Some((tid, lane)) = sched.pop_for_worker(worker_hint, rng_value, now) {
                (tid, lane)
            } else if let Some(tid) = sched.steal_for_worker(worker_hint, rng_value.rotate_left(17))
            {
                (tid, DispatchLane::Stolen)
            } else {
                drop(sched);
                self.check_deadline_monitor();
                return;
            }
        };

        // Record task scheduling in certificate and replay recorder
        self.certificate.record(task_id, dispatch_lane, self.steps);
        self.replay_recorder
            .record_task_scheduled(task_id, self.steps);

        // 2. Pre-poll chaos injection
        if self.inject_pre_poll_chaos(task_id) {
            // Chaos caused the task to be skipped (e.g., cancelled, budget exhausted)
            return;
        }

        // 3. Prepare context and enforce budget
        let priority = self.state.task(task_id).map_or(0, |record| {
            record.cx_inner.as_ref().map_or(0, |inner| {
                let mut guard = inner.write();

                // Enforce poll quota
                if guard.budget.consume_poll().is_none() {
                    guard.cancel_requested = true;
                    if let Some(existing) = &mut guard.cancel_reason {
                        existing.strengthen(&crate::types::CancelReason::poll_quota());
                    } else {
                        guard.cancel_reason = Some(crate::types::CancelReason::poll_quota());
                    }
                }

                guard.budget.priority
            })
        });

        let waker = Waker::from(Arc::new(TaskWaker {
            task_id,
            priority,
            scheduler: self.scheduler.clone(),
        }));
        let mut cx = Context::from_waker(&waker);

        // Set cancel_waker so abort_with_reason can reschedule cancelled tasks.
        if let Some(record) = self.state.task(task_id) {
            if let Some(inner) = record.cx_inner.as_ref() {
                let cancel_waker = Waker::from(Arc::new(CancelTaskWaker {
                    task_id,
                    priority,
                    scheduler: self.scheduler.clone(),
                }));
                {
                    let mut guard = inner.write();
                    guard.cancel_waker = Some(cancel_waker);
                }
            }
        }

        let current_cx = self
            .state
            .task(task_id)
            .and_then(|record| record.cx.clone());
        let _cx_guard = crate::cx::Cx::set_current(current_cx);

        // 4. Poll the task
        let result = if let Some(stored) = self.state.get_stored_future(task_id) {
            stored.poll(&mut cx)
        } else {
            // Task lost (should not happen if consistent)
            return;
        };

        // Record the poll so futurelock detection uses the correct idle step count.
        if let Some(record) = self.state.task_mut(task_id) {
            record.mark_polled(self.steps);
        }

        let cancel_ack = self.consume_cancel_ack(task_id);

        // 5. Handle result
        match result {
            Poll::Ready(outcome) => {
                // Task completed
                self.state.remove_stored_future(task_id);
                self.scheduler.lock().forget_task(task_id);

                // Update state to Completed if not already terminal
                if let Some(record) = self.state.task_mut(task_id) {
                    if !record.state.is_terminal() {
                        let record_outcome = match outcome {
                            crate::types::Outcome::Ok(()) => crate::types::Outcome::Ok(()),
                            crate::types::Outcome::Err(()) => crate::types::Outcome::Err(
                                crate::error::Error::new(crate::error::ErrorKind::Internal),
                            ),
                            crate::types::Outcome::Cancelled(r) => {
                                crate::types::Outcome::Cancelled(r)
                            }
                            crate::types::Outcome::Panicked(p) => {
                                crate::types::Outcome::Panicked(p)
                            }
                        };
                        let mut completed_via_cancel = false;
                        if matches!(record_outcome, crate::types::Outcome::Ok(())) {
                            let should_cancel = matches!(
                                record.state,
                                TaskState::Cancelling { .. } | TaskState::Finalizing { .. }
                            ) || (cancel_ack
                                && matches!(record.state, TaskState::CancelRequested { .. }));
                            if should_cancel {
                                if matches!(record.state, TaskState::CancelRequested { .. }) {
                                    let _ = record.acknowledge_cancel();
                                }
                                if matches!(record.state, TaskState::Cancelling { .. }) {
                                    record.cleanup_done();
                                }
                                if matches!(record.state, TaskState::Finalizing { .. }) {
                                    record.finalize_done();
                                }
                                completed_via_cancel = matches!(
                                    record.state,
                                    TaskState::Completed(crate::types::Outcome::Cancelled(_))
                                );
                            }
                        }
                        if !completed_via_cancel {
                            record.complete(record_outcome);
                        }
                    }
                }

                // Record task completion with severity from the finalized task
                // record. Must happen AFTER state finalization above because
                // create_task wraps user futures to always return Outcome::Ok(())
                // — the real severity comes from the cancel protocol state machine.
                let final_severity =
                    self.state
                        .task(task_id)
                        .map_or(crate::types::Severity::Ok, |record| match &record.state {
                            TaskState::Completed(outcome) => outcome.severity(),
                            _ => crate::types::Severity::Ok,
                        });
                self.replay_recorder
                    .record_task_completed(task_id, final_severity);

                if let Some(monitor) = &mut self.deadline_monitor {
                    if let Some(record) = self.state.task(task_id) {
                        let now = self.state.now;
                        let duration =
                            Duration::from_nanos(now.duration_since(record.created_at()));
                        let (task_type, deadline) = record
                            .cx_inner
                            .as_ref()
                            .map(|inner| inner.read())
                            .map_or_else(
                                || ("default".to_string(), None),
                                |inner| {
                                    (
                                        inner
                                            .task_type
                                            .clone()
                                            .unwrap_or_else(|| "default".to_string()),
                                        inner.budget.deadline,
                                    )
                                },
                            );
                        monitor.record_completion(task_id, &task_type, duration, deadline, now);
                    }
                }

                // Notify waiters
                let waiters = self.state.task_completed(task_id);

                // Schedule waiters
                let mut sched = self.scheduler.lock();
                for waiter in waiters {
                    let prio = self
                        .state
                        .task(waiter)
                        .and_then(|t| t.cx_inner.as_ref())
                        .map_or(0, |inner| inner.read().budget.priority);
                    sched.schedule(waiter, prio);
                }
            }
            Poll::Pending => {
                // Task yielded. Waker will reschedule it when ready.
                // Note: If the task yielded via `cx.waker().wake_by_ref()`, it might already be scheduled.
                // If it yielded for I/O or other events, it won't be scheduled until that event fires.

                // Record task yielding
                self.replay_recorder.record_task_yielded(task_id);

                // 6. Post-poll chaos injection (spurious wakeups for pending tasks)
                self.inject_post_poll_chaos(task_id, priority);
            }
        }

        self.check_deadline_monitor();
    }

    fn check_deadline_monitor(&mut self) {
        if let Some(monitor) = &mut self.deadline_monitor {
            let now = self.state.now;
            monitor.check(now, self.state.tasks_iter().map(|(_, record)| record));
        }
    }

    fn poll_io(&mut self) {
        let Some(handle) = self.state.io_driver_handle() else {
            return;
        };
        let now = self.state.now;
        let (state, recorder, seen) = (
            &mut self.state,
            &mut self.replay_recorder,
            &mut self.seen_io_tokens,
        );
        if let Err(_error) = handle.turn_with(Some(Duration::ZERO), |event, interest| {
            let token = event.token.0;
            let interest = interest.unwrap_or(event.ready);
            if seen.insert(token) {
                let seq = state.next_trace_seq();
                state.trace.push_event(TraceEvent::io_requested(
                    seq,
                    now,
                    token as u64,
                    interest.bits(),
                ));
            }
            let seq = state.next_trace_seq();
            state.trace.push_event(TraceEvent::io_ready(
                seq,
                now,
                token as u64,
                event.ready.bits(),
            ));
            recorder.record_io_ready(
                token as u64,
                event.is_readable(),
                event.is_writable(),
                event.is_error(),
                event.is_hangup(),
            );
        }) {
            crate::tracing_compat::warn!(
                error = ?_error,
                "lab runtime io_driver poll failed"
            );
        }
    }

    /// Injects chaos before polling a task.
    ///
    /// Returns `true` if the task should be skipped (e.g., cancelled or budget exhausted).
    fn inject_pre_poll_chaos(&mut self, task_id: TaskId) -> bool {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return false;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return false;
        };

        let mut skip_poll = chaos_rng.should_inject_cancel(&chaos_config);

        // Check for delay injection
        let delay = chaos_rng
            .should_inject_delay(&chaos_config)
            .then(|| chaos_rng.next_delay(&chaos_config));

        // Check for budget exhaustion injection
        let budget_exhaust = chaos_rng.should_inject_budget_exhaust(&chaos_config);
        skip_poll |= budget_exhaust;

        // Now apply the injections (no more borrowing chaos_rng)
        if skip_poll && !budget_exhaust {
            // Cancellation was injected
            self.chaos_stats.record_cancel();
            self.inject_cancel(task_id);
        }

        if let Some(d) = delay {
            self.chaos_stats.record_delay(d);
            self.advance_time(Self::duration_nanos_saturating(d));
        }

        if budget_exhaust {
            self.chaos_stats.record_budget_exhaust();
            self.inject_budget_exhaust(task_id);
        }

        if skip_poll {
            self.reschedule_after_chaos_skip(task_id);
        } else {
            self.chaos_stats.record_no_injection();
        }

        skip_poll
    }

    #[inline]
    fn duration_nanos_saturating(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
    }

    /// Injects chaos after polling a task that returned Pending.
    fn inject_post_poll_chaos(&mut self, task_id: TaskId, priority: u8) {
        let Some(chaos_config) = self.config.chaos.clone() else {
            return;
        };
        let Some(chaos_rng) = &mut self.chaos_rng else {
            return;
        };

        // Check for spurious wakeup storm
        let wakeup_count = if chaos_rng.should_inject_wakeup_storm(&chaos_config) {
            Some(chaos_rng.next_wakeup_count(&chaos_config))
        } else {
            None
        };

        // Apply the injection (no more borrowing chaos_rng)
        if let Some(count) = wakeup_count {
            self.chaos_stats.record_wakeup_storm(count as u64);
            self.inject_spurious_wakes(task_id, priority, count);
        }
    }

    fn reschedule_after_chaos_skip(&self, task_id: TaskId) {
        let Some(record) = self.state.task(task_id) else {
            return;
        };
        if record.state.is_terminal() {
            return;
        }
        let priority = record
            .cx_inner
            .as_ref()
            .map_or(0, |inner| inner.read().budget.priority);
        let mut sched = self.scheduler.lock();
        sched.schedule_cancel(task_id, priority);
    }

    fn schedule_async_finalizers(&mut self) {
        let tasks = self.state.drain_ready_async_finalizers();
        if tasks.is_empty() {
            return;
        }
        let mut sched = self.scheduler.lock();
        for (task_id, priority) in tasks {
            sched.schedule(task_id, priority);
        }
    }

    fn consume_cancel_ack(&mut self, task_id: TaskId) -> bool {
        let Some(record) = self.state.task_mut(task_id) else {
            return false;
        };
        let Some(inner) = record.cx_inner.as_ref() else {
            return false;
        };
        let mut acknowledged = false;
        {
            let mut guard = inner.write();
            if guard.cancel_acknowledged {
                guard.cancel_acknowledged = false;
                drop(guard);
                acknowledged = true;
            }
        }
        if acknowledged {
            let _ = record.acknowledge_cancel();
        }
        acknowledged
    }

    /// Injects a cancellation for a task.
    fn inject_cancel(&mut self, task_id: TaskId) {
        use crate::types::{Budget, CancelReason};

        // Record replay event
        self.replay_recorder.record_cancel_injection(task_id);

        // Mark the task as cancel-requested with chaos reason
        if let Some(record) = self.state.task_mut(task_id) {
            if !record.state.is_terminal() {
                record
                    .request_cancel_with_budget(CancelReason::user("chaos-injected"), Budget::ZERO);
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push_event(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "cancel".to_string(),
                task: Some(task_id),
                detail: "chaos-injected cancellation".to_string(),
            },
        ));
    }

    /// Injects budget exhaustion for a task.
    fn inject_budget_exhaust(&mut self, task_id: TaskId) {
        // Record replay event
        self.replay_recorder
            .record_budget_exhaust_injection(task_id);

        // Set the task's budget quotas to zero
        if let Some(record) = self.state.task(task_id) {
            if let Some(cx_inner) = &record.cx_inner {
                let mut inner = cx_inner.write();
                inner.budget.poll_quota = 0;
                inner.budget.cost_quota = Some(0);
            }
        }

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push_event(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "budget_exhaust".to_string(),
                task: Some(task_id),
                detail: "chaos-injected budget exhaustion".to_string(),
            },
        ));
    }

    /// Injects spurious wakeups for a task.
    fn inject_spurious_wakes(&mut self, task_id: TaskId, priority: u8, count: usize) {
        // Record replay event
        self.replay_recorder
            .record_wakeup_storm_injection(task_id, count as u32);

        // Schedule the task multiple times (spurious wakeups)
        let mut sched = self.scheduler.lock();
        for _ in 0..count {
            sched.schedule(task_id, priority);
        }
        drop(sched);

        // Emit trace event
        let seq = self.state.next_trace_seq();
        self.state.trace.push_event(TraceEvent::new(
            seq,
            self.virtual_time,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "wakeup_storm".to_string(),
                task: Some(task_id),
                detail: format!("chaos-injected {count} spurious wakeups"),
            },
        ));
    }

    /// Public wrapper for `step()` for use in tests.
    ///
    /// This is useful for testing determinism across multiple step executions.
    pub fn step_for_test(&mut self) {
        self.step();
    }

    /// Checks invariants and returns any violations.
    #[must_use]
    pub fn check_invariants(&mut self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();

        // Check for obligation leaks
        let leaks = self.obligation_leaks();
        if !leaks.is_empty() {
            for leak in &leaks {
                let _ = self.state.mark_obligation_leaked(leak.obligation);
            }
            violations.push(InvariantViolation::ObligationLeak { leaks });
        }

        violations.extend(self.futurelock_violations());
        violations.extend(self.quiescence_violations());

        // Check for task leaks (non-terminal tasks)
        let task_leak_count = self.task_leaks();
        if task_leak_count > 0 {
            violations.push(InvariantViolation::TaskLeak {
                count: task_leak_count,
            });
        }

        violations
    }

    fn obligation_leaks(&self) -> Vec<ObligationLeak> {
        let mut leaks = Vec::new();

        for (_, obligation) in self.state.obligations_iter() {
            if !obligation.is_pending() {
                continue;
            }

            let holder_terminal = self
                .state
                .task(obligation.holder)
                .is_none_or(|t| t.state.is_terminal());
            let region_closed = self
                .state
                .region(obligation.region)
                .is_none_or(|r| r.state().is_terminal());

            if holder_terminal || region_closed {
                leaks.push(ObligationLeak {
                    obligation: obligation.id,
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                });
            }
        }

        leaks
    }

    fn task_leaks(&self) -> usize {
        self.state
            .tasks_iter()
            .filter(|(_, t)| !t.state.is_terminal())
            .count()
    }

    fn quiescence_violations(&self) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        for (_, region) in self.state.regions_iter() {
            if region.state().is_terminal() {
                // Check if any children or tasks are NOT terminal
                let live_tasks = region
                    .task_ids()
                    .iter()
                    .any(|&tid| self.state.task(tid).is_some_and(|t| !t.state.is_terminal()));

                let live_children = region.child_ids().iter().any(|&rid| {
                    self.state
                        .region(rid)
                        .is_some_and(|r| !r.state().is_terminal())
                });

                if live_tasks || live_children {
                    violations.push(InvariantViolation::QuiescenceViolation);
                }
            }
        }
        violations
    }

    fn futurelock_violations(&self) -> Vec<InvariantViolation> {
        let threshold = self.config.futurelock_max_idle_steps;
        if threshold == 0 {
            return Vec::new();
        }

        let current_step = self.steps;
        let mut violations = Vec::new();

        for (_, task) in self.state.tasks_iter() {
            if task.state.is_terminal() {
                continue;
            }

            let mut held = Vec::new();
            for (_, obligation) in self.state.obligations_iter() {
                if obligation.is_pending() && obligation.holder == task.id {
                    held.push(obligation.id);
                }
            }

            if held.is_empty() {
                continue;
            }

            let idle_steps = current_step.saturating_sub(task.last_polled_step);
            if idle_steps > threshold {
                violations.push(InvariantViolation::Futurelock {
                    task: task.id,
                    region: task.owner,
                    idle_steps,
                    held,
                });
            }
        }

        violations
    }

    fn check_futurelocks(&self) {
        let violations = self.futurelock_violations();
        if violations.is_empty() {
            return;
        }

        for v in violations {
            let InvariantViolation::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } = v
            else {
                continue;
            };

            let mut held_kinds = Vec::new();
            for oid in &held {
                for (_, obligation) in self.state.obligations_iter() {
                    if obligation.id == *oid {
                        held_kinds.push((obligation.id, obligation.kind));
                        break;
                    }
                }
            }

            let seq = self.state.next_trace_seq();
            self.state.trace.push_event(TraceEvent::new(
                seq,
                self.virtual_time,
                TraceEventKind::FuturelockDetected,
                TraceData::Futurelock {
                    task,
                    region,
                    idle_steps,
                    held: held_kinds,
                },
            ));

            assert!(
                !self.config.panic_on_futurelock,
                "futurelock detected: {task} in {region} idle={idle_steps} held={held:?}"
            );
        }
    }
}

const DEFAULT_LAB_CANCEL_STREAK_LIMIT: usize = 16;

#[derive(Debug)]
/// Deterministic lab scheduler with per-worker queues.
///
/// This is a single-threaded model of multi-worker scheduling used by the lab
/// runtime to simulate parallel execution deterministically.
pub struct LabScheduler {
    workers: Vec<crate::runtime::scheduler::PriorityScheduler>,
    scheduled: HashSet<TaskId>,
    /// Task → worker assignment, indexed by arena slot.
    assignments: Vec<Option<usize>>,
    next_worker: usize,
    cancel_streak: Vec<usize>,
    cancel_streak_limit: usize,
}

impl LabScheduler {
    fn new(worker_count: usize) -> Self {
        let count = if worker_count == 0 { 1 } else { worker_count };
        let cancel_streak_limit = DEFAULT_LAB_CANCEL_STREAK_LIMIT.max(1);
        Self {
            workers: (0..count)
                .map(|_| crate::runtime::scheduler::PriorityScheduler::new())
                .collect(),
            scheduled: HashSet::new(),
            assignments: Vec::new(),
            next_worker: 0,
            cancel_streak: vec![0; count],
            cancel_streak_limit,
        }
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Returns true if no tasks are currently scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scheduled.is_empty()
    }

    /// Returns the configured cancel streak limit for lab scheduling.
    #[must_use]
    pub fn cancel_streak_limit(&self) -> usize {
        self.cancel_streak_limit
    }

    #[inline]
    fn set_assignment(&mut self, task: TaskId, worker: usize) {
        let slot = task.arena_index().index() as usize;
        if slot >= self.assignments.len() {
            self.assignments.resize(slot + 1, None);
        }
        self.assignments[slot] = Some(worker);
    }

    fn assign_worker(&mut self, task: TaskId) -> usize {
        let slot = task.arena_index().index() as usize;
        if slot < self.assignments.len() {
            if let Some(worker) = self.assignments[slot] {
                return worker;
            }
        }
        let worker = self.next_worker % self.workers.len();
        self.next_worker = self.next_worker.wrapping_add(1);
        if slot >= self.assignments.len() {
            self.assignments.resize(slot + 1, None);
        }
        self.assignments[slot] = Some(worker);
        worker
    }

    /// Schedules a task in the ready lane on its assigned worker.
    pub fn schedule(&mut self, task: TaskId, priority: u8) {
        if !self.scheduled.insert(task) {
            return;
        }

        let worker = self.assign_worker(task);
        self.workers[worker].schedule(task, priority);
    }

    /// Schedules or promotes a task into the cancel lane.
    pub fn schedule_cancel(&mut self, task: TaskId, priority: u8) {
        if self.scheduled.insert(task) {
            let worker = self.assign_worker(task);
            self.workers[worker].schedule_cancel(task, priority);
            return;
        }

        let slot = task.arena_index().index() as usize;
        if let Some(&Some(worker)) = self.assignments.get(slot) {
            self.workers[worker].move_to_cancel_lane(task, priority);
        }
    }

    /// Schedules a task in the timed lane on its assigned worker.
    pub fn schedule_timed(&mut self, task: TaskId, deadline: Time) {
        if !self.scheduled.insert(task) {
            return;
        }

        let worker = self.assign_worker(task);
        self.workers[worker].schedule_timed(task, deadline);
    }

    fn pop_for_worker(
        &mut self,
        worker: usize,
        rng_hint: u64,
        now: Time,
    ) -> Option<(TaskId, DispatchLane)> {
        if self.workers.is_empty() {
            return None;
        }

        let worker = worker % self.workers.len();
        let cancel_streak = &mut self.cancel_streak[worker];

        if *cancel_streak < self.cancel_streak_limit {
            if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
                *cancel_streak += 1;
                self.scheduled.remove(&task);
                self.set_assignment(task, worker);
                return Some((task, lane));
            }
        }

        if let Some(task) = self.workers[worker].pop_timed_only_with_hint(rng_hint, now) {
            *cancel_streak = 0;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            return Some((task, DispatchLane::Timed));
        }

        if let Some(task) = self.workers[worker].pop_ready_only_with_hint(rng_hint) {
            *cancel_streak = 0;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            return Some((task, DispatchLane::Ready));
        }

        if let Some((task, lane)) = self.workers[worker].pop_cancel_with_rng(rng_hint) {
            *cancel_streak = 1;
            self.scheduled.remove(&task);
            self.set_assignment(task, worker);
            return Some((task, lane));
        }

        *cancel_streak = 0;
        None
    }

    fn steal_for_worker(&mut self, thief: usize, rng_hint: u64) -> Option<TaskId> {
        let count = self.workers.len();
        if count <= 1 {
            return None;
        }

        let thief = thief % count;
        let start = (rng_hint as usize) % count;

        for offset in 0..count {
            let victim = (start + offset) % count;
            if victim == thief {
                continue;
            }
            if let Some(task) =
                self.workers[victim].pop_ready_only_with_hint(rng_hint.wrapping_add(offset as u64))
            {
                self.scheduled.remove(&task);
                self.set_assignment(task, thief);
                return Some(task);
            }
        }

        None
    }

    fn forget_task(&mut self, task: TaskId) {
        self.scheduled.remove(&task);
        let slot = task.arena_index().index() as usize;
        if slot < self.assignments.len() {
            self.assignments[slot] = None;
        }
        for worker in &mut self.workers {
            worker.remove(task);
        }
    }
}

struct TaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler.lock().schedule(self.task_id, self.priority);
    }
}

/// Waker that reschedules a task into the cancel lane.
///
/// Set as `cancel_waker` on each task's `CxInner` before polling so that
/// `abort_with_reason` can wake cancelled tasks.
struct CancelTaskWaker {
    task_id: crate::types::TaskId,
    priority: u8,
    scheduler: Arc<Mutex<LabScheduler>>,
}

impl Wake for CancelTaskWaker {
    fn wake(self: Arc<Self>) {
        self.scheduler
            .lock()
            .schedule_cancel(self.task_id, self.priority);
    }
}

/// An invariant violation detected by the lab runtime.
#[derive(Debug, Clone)]
pub enum InvariantViolation {
    /// Obligations were not resolved.
    ObligationLeak {
        /// Leaked obligations and diagnostic metadata.
        leaks: Vec<ObligationLeak>,
    },
    /// Tasks were not drained.
    TaskLeak {
        /// Number of leaked tasks.
        count: usize,
    },
    /// Actors were not stopped before region close.
    ActorLeak {
        /// Number of leaked actors.
        count: usize,
    },
    /// A region closed with live children.
    QuiescenceViolation,
    /// A task held obligations but stopped being polled (futurelock).
    Futurelock {
        /// The task that futurelocked.
        task: crate::types::TaskId,
        /// The owning region.
        region: crate::types::RegionId,
        /// How many lab steps since last poll.
        idle_steps: u64,
        /// Held obligations.
        held: Vec<ObligationId>,
    },
}

/// Diagnostic details for a leaked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationLeak {
    /// The leaked obligation id.
    pub obligation: ObligationId,
    /// Kind of obligation (permit/ack/lease/io).
    pub kind: ObligationKind,
    /// Task that held the obligation.
    pub holder: crate::types::TaskId,
    /// Region that owned the obligation.
    pub region: crate::types::RegionId,
}

impl std::fmt::Display for ObligationLeak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} {:?} holder={:?} region={:?}",
            self.obligation, self.kind, self.holder, self.region
        )
    }
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObligationLeak { leaks } => {
                write!(f, "{} obligations leaked", leaks.len())
            }
            Self::TaskLeak { count } => write!(f, "{count} tasks leaked"),
            Self::ActorLeak { count } => write!(f, "{count} actors leaked"),
            Self::QuiescenceViolation => write!(f, "region closed without quiescence"),
            Self::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => write!(
                f,
                "futurelock: {task} in {region} idle={idle_steps} held={held:?}"
            ),
        }
    }
}

/// Convenience function for running a test with the lab runtime.
pub fn test<F, R>(seed: u64, f: F) -> R
where
    F: FnOnce(&mut LabRuntime) -> R,
{
    let mut runtime = LabRuntime::with_seed(seed);
    let result = f(&mut runtime);

    // Check invariants
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "Lab runtime invariant violations: {violations:?}"
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TaskRecord;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::runtime::deadline_monitor::{AdaptiveDeadlineConfig, WarningReason};
    use crate::runtime::reactor::{Event, Interest};
    use crate::types::{Budget, CxInner, Outcome, TaskId};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use parking_lot::RwLock;
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use std::time::Duration;

    #[cfg(unix)]
    struct TestFdSource;
    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[cfg(unix)]
    struct NoopWaker;
    #[cfg(unix)]
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    #[cfg(unix)]
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    /// Waker that sets an `AtomicBool` when woken (for virtual time tests).
    struct FlagWaker(Arc<std::sync::atomic::AtomicBool>);
    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Waker that increments an `AtomicU64` counter when woken.
    struct CountWaker(Arc<std::sync::atomic::AtomicU64>);
    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn empty_runtime_is_quiescent() {
        init_test("empty_runtime_is_quiescent");
        let runtime = LabRuntime::with_seed(42);
        let quiescent = runtime.is_quiescent();
        crate::assert_with_log!(quiescent, "quiescent", true, quiescent);
        crate::test_complete!("empty_runtime_is_quiescent");
    }

    #[test]
    fn advance_time() {
        init_test("advance_time");
        let mut runtime = LabRuntime::with_seed(42);
        let now = runtime.now();
        crate::assert_with_log!(now == Time::ZERO, "now", Time::ZERO, now);

        runtime.advance_time(1_000_000);
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_millis(1),
            "now",
            Time::from_millis(1),
            now
        );
        crate::test_complete!("advance_time");
    }

    #[test]
    fn duration_nanos_saturating_clamps_large_duration() {
        init_test("duration_nanos_saturating_clamps_large_duration");
        let huge = Duration::from_secs(u64::MAX);
        let saturated = LabRuntime::duration_nanos_saturating(huge);
        crate::assert_with_log!(
            saturated == u64::MAX,
            "huge duration saturates",
            u64::MAX,
            saturated
        );

        let small = Duration::from_nanos(123);
        let exact = LabRuntime::duration_nanos_saturating(small);
        crate::assert_with_log!(exact == 123, "small duration exact", 123u64, exact);
        crate::test_complete!("duration_nanos_saturating_clamps_large_duration");
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_records_io_ready_trace() {
        init_test("lab_runtime_records_io_ready_trace");

        let mut runtime = LabRuntime::with_seed(42);
        let handle = runtime.state.io_driver_handle().expect("io driver");
        let waker = noop_waker();
        let source = TestFdSource;

        let registration = handle
            .register(&source, Interest::READABLE, waker)
            .expect("register source");
        let token = registration.token();

        runtime
            .lab_reactor()
            .inject_event(token, Event::readable(token), Duration::from_millis(1));
        runtime.advance_time(1_000_000);
        runtime.step_for_test();

        let mut saw_requested = false;
        let mut saw_ready = false;
        for event in runtime.state.trace.snapshot() {
            if event.kind == TraceEventKind::IoRequested {
                saw_requested = true;
            }
            if event.kind == TraceEventKind::IoReady {
                saw_ready = true;
            }
        }
        crate::assert_with_log!(
            saw_requested,
            "io requested trace recorded",
            true,
            saw_requested
        );
        crate::assert_with_log!(saw_ready, "io ready trace recorded", true, saw_ready);
        crate::test_complete!("lab_runtime_records_io_ready_trace");
    }

    #[test]
    fn deterministic_rng() {
        init_test("deterministic_rng");
        let mut r1 = LabRuntime::with_seed(42);
        let mut r2 = LabRuntime::with_seed(42);

        let a = r1.rng.next_u64();
        let b = r2.rng.next_u64();
        crate::assert_with_log!(a == b, "rng", b, a);
        crate::test_complete!("deterministic_rng");
    }

    #[test]
    fn lab_scheduler_pop_for_worker_respects_timed_deadlines() {
        init_test("lab_scheduler_pop_for_worker_respects_timed_deadlines");
        let mut scheduler = LabScheduler::new(1);
        let timed = TaskId::from_arena(ArenaIndex::new(1, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(2, 0));

        scheduler.schedule_timed(timed, Time::from_nanos(100));
        scheduler.schedule(ready, 10);

        let first = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            first == Some((ready, DispatchLane::Ready)),
            "ready task dispatches before not-due timed task",
            Some((ready, DispatchLane::Ready)),
            first
        );

        let second = scheduler.pop_for_worker(0, 1, Time::ZERO);
        crate::assert_with_log!(
            second.is_none(),
            "future timed task stays queued before deadline",
            true,
            second.is_none()
        );

        let third = scheduler.pop_for_worker(0, 2, Time::from_nanos(100));
        crate::assert_with_log!(
            third == Some((timed, DispatchLane::Timed)),
            "timed task dispatches at deadline",
            Some((timed, DispatchLane::Timed)),
            third
        );

        crate::test_complete!("lab_scheduler_pop_for_worker_respects_timed_deadlines");
    }

    #[test]
    fn lab_scheduler_steal_for_worker_only_steals_ready_tasks() {
        init_test("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
        let mut scheduler = LabScheduler::new(2);
        let cancel = TaskId::from_arena(ArenaIndex::new(10, 0));
        let timed = TaskId::from_arena(ArenaIndex::new(11, 0));
        let ready = TaskId::from_arena(ArenaIndex::new(12, 0));

        // With 2 workers, assignment is round-robin: cancel->w0, timed->w1, ready->w0.
        scheduler.schedule_cancel(cancel, 100);
        scheduler.schedule_timed(timed, Time::ZERO);
        scheduler.schedule(ready, 50);

        let stolen = scheduler.steal_for_worker(1, 0);
        crate::assert_with_log!(
            stolen == Some(ready),
            "steal path takes only ready lane work",
            Some(ready),
            stolen
        );

        crate::assert_with_log!(
            scheduler.workers[0].has_cancel_work(),
            "victim cancel lane remains intact after steal",
            true,
            scheduler.workers[0].has_cancel_work()
        );

        let cancel_dispatch = scheduler.pop_for_worker(0, 0, Time::ZERO);
        crate::assert_with_log!(
            cancel_dispatch == Some((cancel, DispatchLane::Cancel)),
            "cancel lane still dispatches from victim worker",
            Some((cancel, DispatchLane::Cancel)),
            cancel_dispatch
        );

        let timed_dispatch = scheduler.pop_for_worker(1, 0, Time::ZERO);
        crate::assert_with_log!(
            timed_dispatch == Some((timed, DispatchLane::Timed)),
            "timed lane remains on owning worker",
            Some((timed, DispatchLane::Timed)),
            timed_dispatch
        );

        crate::test_complete!("lab_scheduler_steal_for_worker_only_steals_ready_tasks");
    }

    #[test]
    fn deterministic_multiworker_schedule() {
        init_test("deterministic_multiworker_schedule");
        let config = LabConfig::new(7).worker_count(4);

        crate::lab::assert_deterministic(config, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            runtime.run_until_quiescent();
        });

        crate::test_complete!("deterministic_multiworker_schedule");
    }

    #[test]
    fn run_until_quiescent_with_report_is_deterministic() {
        init_test("run_until_quiescent_with_report_is_deterministic");

        let config = LabConfig::new(123).worker_count(4).max_steps(10_000);
        let mut r1 = LabRuntime::new(config.clone());
        let mut r2 = LabRuntime::new(config);

        let setup = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..4 {
                let (task_id, _handle) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {
                        crate::runtime::yield_now::yield_now().await;
                    })
                    .expect("create task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
        };

        setup(&mut r1);
        setup(&mut r2);

        let rep1 = r1.run_until_quiescent_with_report();
        let rep2 = r2.run_until_quiescent_with_report();

        crate::assert_with_log!(rep1.quiescent, "quiescent", true, rep1.quiescent);
        crate::assert_with_log!(rep2.quiescent, "quiescent", true, rep2.quiescent);

        assert_eq!(rep1.trace_fingerprint, rep2.trace_fingerprint);
        assert_eq!(rep1.trace_certificate, rep2.trace_certificate);
        assert_eq!(rep1.oracle_report.to_json(), rep2.oracle_report.to_json());
        assert_eq!(rep1.invariant_violations, rep2.invariant_violations);

        crate::assert_with_log!(
            rep1.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep1.oracle_report.all_passed()
        );
        crate::assert_with_log!(
            rep2.oracle_report.all_passed(),
            "oracles passed",
            true,
            rep2.oracle_report.all_passed()
        );

        crate::test_complete!("run_until_quiescent_with_report_is_deterministic");
    }

    #[test]
    fn deadline_monitor_emits_warning() {
        init_test("deadline_monitor_emits_warning");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::from_secs(0),
            warning_threshold_fraction: 1.0,
            checkpoint_timeout: Duration::from_secs(0),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_millis(10));

        let task_idx = runtime.state.insert_task(TaskRecord::new_with_time(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            budget,
            runtime.state.now,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let mut inner = CxInner::new(root, task_id, budget);
        inner.checkpoint_state.last_checkpoint = None;
        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .set_cx_inner(Arc::new(RwLock::new(inner)));

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.region_id == root,
            "region_id",
            root,
            warning.region_id
        );
        let ok = matches!(
            warning.reason,
            WarningReason::ApproachingDeadline | WarningReason::ApproachingDeadlineNoProgress
        );
        crate::assert_with_log!(ok, "reason", true, ok);
        drop(warnings);
        crate::test_complete!("deadline_monitor_emits_warning");
    }

    #[test]
    fn deadline_monitor_e2e_stuck_detection() {
        init_test("deadline_monitor_e2e_stuck_detection");
        let mut runtime = LabRuntime::with_seed(42);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_clone = Arc::clone(&warnings);

        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        };

        runtime.enable_deadline_monitoring_with_handler(config, move |warning| {
            warnings_clone.lock().push(warning);
        });

        let root = runtime.state.create_root_region(Budget::INFINITE);
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let (task_id, _handle) = runtime
            .state
            .create_task(root, budget, async {})
            .expect("create task");

        {
            let task = runtime.state.task_mut(task_id).unwrap();
            let cx = task.cx.as_ref().expect("task cx");
            cx.checkpoint_with("starting work").expect("checkpoint");
        }

        runtime.step();

        let warnings = warnings.lock();
        let warning = warnings.first().expect("expected warning");
        crate::assert_with_log!(
            warning.task_id == task_id,
            "task_id",
            task_id,
            warning.task_id
        );
        crate::assert_with_log!(
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("starting work"),
            "checkpoint message",
            Some("starting work"),
            warning.last_checkpoint_message.as_deref()
        );
        drop(warnings);
        crate::test_complete!("deadline_monitor_e2e_stuck_detection");
    }

    #[test]
    fn futurelock_emits_trace_event() {
        init_test("futurelock_emits_trace_event");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(3)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task.
        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        // Create a pending obligation held by that task.
        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        for _ in 0..4 {
            runtime.step();
        }

        let futurelock = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::FuturelockDetected)
            .expect("expected futurelock trace event");

        match &futurelock.data {
            TraceData::Futurelock {
                task,
                region,
                idle_steps,
                held,
            } => {
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                let idle_ok = *idle_steps > 3;
                crate::assert_with_log!(idle_ok, "idle_steps > 3", true, idle_ok);
                let ok = held.as_slice() == [(obl_id, ObligationKind::SendPermit)];
                crate::assert_with_log!(
                    ok,
                    "held",
                    &[(obl_id, ObligationKind::SendPermit)],
                    held.as_slice()
                );
            }
            other => panic!("unexpected trace data: {other:?}"),
        }
        crate::test_complete!("futurelock_emits_trace_event");
    }

    #[test]
    #[should_panic(expected = "futurelock detected")]
    fn futurelock_can_panic() {
        init_test("futurelock_can_panic");
        let config = LabConfig::new(42).futurelock_max_idle_steps(1);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let _ = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Run enough steps to exceed threshold and trigger panic.
        for _ in 0..3 {
            runtime.step();
        }
    }

    /// Regression test: actively polled tasks must NOT be flagged as futurelocked.
    ///
    /// Before the fix, `mark_polled()` was never called from `step()`, so
    /// `last_polled_step` stayed at 0. After threshold+1 steps, even a
    /// task polled every single step would be falsely flagged.
    #[test]
    fn polled_task_not_flagged_as_futurelocked() {
        init_test("polled_task_not_flagged_as_futurelocked");
        let config = LabConfig::new(42)
            .futurelock_max_idle_steps(5)
            .panic_on_futurelock(false);
        let mut runtime = LabRuntime::new(config);

        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Create a task with a stored future that always yields (Pending).
        let (task_id, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {
                loop {
                    crate::runtime::yield_now::yield_now().await;
                }
            })
            .expect("create task");

        // Give the task a pending obligation so it's eligible for futurelock.
        let _obl = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        // Schedule and run well past the threshold.
        runtime.scheduler.lock().schedule(task_id, 0);
        for _ in 0..20 {
            runtime.step();
        }

        // The task was polled every step, so no futurelock should fire.
        let violations = runtime.futurelock_violations();
        crate::assert_with_log!(
            violations.is_empty(),
            "no futurelock for actively polled task",
            true,
            violations.is_empty()
        );
        crate::test_complete!("polled_task_not_flagged_as_futurelocked");
    }

    #[test]
    fn obligation_leak_detected_when_holder_completed() {
        init_test("obligation_leak_detected_when_holder_completed");
        let mut runtime = LabRuntime::with_seed(7);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        let mut found = false;
        for violation in violations {
            if let InvariantViolation::ObligationLeak { leaks } = violation {
                found = true;
                let len = leaks.len();
                crate::assert_with_log!(len == 1, "leaks len", 1, len);
                let leak = &leaks[0];
                crate::assert_with_log!(
                    leak.obligation == obl_id,
                    "obligation",
                    obl_id,
                    leak.obligation
                );
                crate::assert_with_log!(
                    leak.kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    leak.kind
                );
                crate::assert_with_log!(leak.holder == task_id, "holder", task_id, leak.holder);
                crate::assert_with_log!(leak.region == root, "region", root, leak.region);
            }
        }
        crate::assert_with_log!(found, "found leak", true, found);
        crate::test_complete!("obligation_leak_detected_when_holder_completed");
    }

    #[test]
    fn obligation_leak_ignored_when_resolved() {
        init_test("obligation_leak_ignored_when_resolved");
        let mut runtime = LabRuntime::with_seed(11);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        let obl_id = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        runtime
            .state
            .commit_obligation(obl_id)
            .expect("commit obligation");

        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(!has_leak, "no leak", false, has_leak);
        crate::test_complete!("obligation_leak_ignored_when_resolved");
    }

    #[test]
    fn report_hydrates_temporal_oracles_from_state_snapshot() {
        init_test("report_hydrates_temporal_oracles_from_state_snapshot");
        let mut runtime = LabRuntime::with_seed(31);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (_task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Force-close the region while a task is still live to simulate a
        // temporal invariant break that must be surfaced by report hydration.
        runtime
            .state
            .region(root)
            .expect("region exists")
            .set_state(crate::record::region::RegionState::Closed);

        let report = runtime.report();
        let task_leak = report
            .oracle_report
            .entry("task_leak")
            .expect("task_leak entry");
        let quiescence = report
            .oracle_report
            .entry("quiescence")
            .expect("quiescence entry");

        crate::assert_with_log!(
            !task_leak.passed,
            "task_leak failed",
            false,
            task_leak.passed
        );
        crate::assert_with_log!(
            !quiescence.passed,
            "quiescence failed",
            false,
            quiescence.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:task_leak");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal marker present",
            true,
            has_temporal_tag
        );
        let temporal_failed = report
            .temporal_invariant_failures
            .iter()
            .any(|v| v == "task_leak");
        crate::assert_with_log!(
            temporal_failed,
            "temporal failure surfaced",
            true,
            temporal_failed
        );
        crate::test_complete!("report_hydrates_temporal_oracles_from_state_snapshot");
    }

    #[test]
    fn report_hydrates_cancellation_propagation_from_state_snapshot() {
        init_test("report_hydrates_cancellation_propagation_from_state_snapshot");
        let mut runtime = LabRuntime::with_seed(32);
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let _child = runtime
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("create child");

        runtime
            .state
            .region(root)
            .expect("root exists")
            .cancel_request(crate::types::CancelReason::shutdown());

        let report = runtime.report();
        let cancellation = report
            .oracle_report
            .entry("cancellation_protocol")
            .expect("cancellation_protocol entry");
        crate::assert_with_log!(
            !cancellation.passed,
            "cancellation_protocol failed",
            false,
            cancellation.passed
        );
        let has_temporal_tag = report
            .invariant_violations
            .iter()
            .any(|v| v == "temporal:cancellation_protocol");
        crate::assert_with_log!(
            has_temporal_tag,
            "temporal cancellation marker present",
            true,
            has_temporal_tag
        );
        crate::test_complete!("report_hydrates_cancellation_propagation_from_state_snapshot");
    }

    #[test]
    fn report_surfaces_refinement_firewall_violation_from_trace_snapshot() {
        init_test("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
        let mut runtime = LabRuntime::with_seed(33);
        let region = RegionId::new_for_test(41, 0);
        let task = TaskId::new_for_test(7, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.as_deref() == Some("RFW-SPAWN-001"),
            "refinement rule id surfaced",
            Some("RFW-SPAWN-001"),
            report.refinement_firewall_rule_id.as_deref()
        );
        crate::assert_with_log!(
            report.refinement_firewall_event_index == Some(1),
            "refinement event index surfaced",
            Some(1usize),
            report.refinement_firewall_event_index
        );
        crate::assert_with_log!(
            report.refinement_counterexample_prefix_len == Some(2),
            "refinement prefix len surfaced",
            Some(2usize),
            report.refinement_counterexample_prefix_len
        );
        let has_marker = report
            .invariant_violations
            .iter()
            .any(|v| v == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_marker,
            "refinement invariant marker present",
            true,
            has_marker
        );
        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["rule_id"] == "RFW-SPAWN-001",
            "refinement json rule id",
            "RFW-SPAWN-001",
            json["refinement_firewall"]["rule_id"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["counterexample_prefix_len"] == 2,
            "refinement json prefix len",
            2,
            json["refinement_firewall"]["counterexample_prefix_len"]
        );
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == false,
            "refinement json not skipped",
            false,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_surfaces_refinement_firewall_violation_from_trace_snapshot");
    }

    #[test]
    fn report_skips_refinement_firewall_when_trace_buffer_is_truncated() {
        init_test("report_skips_refinement_firewall_when_trace_buffer_is_truncated");
        let config = LabConfig::new(35).trace_capacity(1);
        let mut runtime = LabRuntime::new(config);
        let region = RegionId::new_for_test(43, 0);
        let task = TaskId::new_for_test(9, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::complete(2, Time::ZERO, task, region));

        let report = runtime.report();
        crate::assert_with_log!(
            report.refinement_firewall_skipped_due_to_trace_truncation,
            "refinement skipped on truncated trace",
            true,
            report.refinement_firewall_skipped_due_to_trace_truncation
        );
        crate::assert_with_log!(
            report.refinement_firewall_rule_id.is_none(),
            "no refinement violation when skipped",
            true,
            report.refinement_firewall_rule_id.is_none()
        );
        let has_refinement_marker = report
            .invariant_violations
            .iter()
            .any(|v| v.starts_with("refinement_firewall:"));
        crate::assert_with_log!(
            !has_refinement_marker,
            "no refinement markers when skipped",
            false,
            has_refinement_marker
        );
        let json = report.to_json();
        crate::assert_with_log!(
            json["refinement_firewall"]["skipped_due_to_trace_truncation"] == true,
            "refinement skipped flag serialized",
            true,
            json["refinement_firewall"]["skipped_due_to_trace_truncation"]
        );
        crate::test_complete!("report_skips_refinement_firewall_when_trace_buffer_is_truncated");
    }

    #[test]
    fn crashpack_includes_refinement_firewall_markers() {
        init_test("crashpack_includes_refinement_firewall_markers");
        let mut runtime = LabRuntime::with_seed(34);
        let region = RegionId::new_for_test(42, 0);
        let task = TaskId::new_for_test(8, 0);

        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(1, Time::ZERO, task, region));
        runtime
            .state
            .trace
            .push_event(TraceEvent::spawn(2, Time::ZERO, task, region));

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("refinement-firewall failure should build crashpack");
        let has_rule_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:RFW-SPAWN-001");
        crate::assert_with_log!(
            has_rule_marker,
            "crashpack includes refinement rule marker",
            true,
            has_rule_marker
        );
        let has_prefix_marker = crashpack
            .oracle_violations
            .iter()
            .any(|entry| entry == "refinement_firewall:minimal_counterexample_prefix_len=2");
        crate::assert_with_log!(
            has_prefix_marker,
            "crashpack includes refinement prefix marker",
            true,
            has_prefix_marker
        );
        crate::test_complete!("crashpack_includes_refinement_firewall_markers");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn obligation_trace_events_emitted() {
        init_test("obligation_trace_events_emitted");
        let mut runtime = LabRuntime::with_seed(21);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(10));
        let ob1 = runtime
            .state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(25));
        runtime.state.commit_obligation(ob1).unwrap();

        runtime.advance_time_to(Time::from_nanos(30));
        let ob2 = runtime
            .state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(50));
        runtime
            .state
            .abort_obligation(ob2, ObligationAbortReason::Cancel)
            .unwrap();

        let commit_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationCommit)
            .expect("commit event");
        match &commit_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob1, "obligation", ob1, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::SendPermit,
                    "kind",
                    ObligationKind::SendPermit,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Committed,
                    "state",
                    crate::record::ObligationState::Committed,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(15),
                    "duration",
                    &Some(15),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected commit data: {other:?}"),
        }

        let abort_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationAbort)
            .expect("abort event");
        match &abort_event.data {
            TraceData::Obligation {
                obligation,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*obligation == ob2, "obligation", ob2, *obligation);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Ack,
                    "kind",
                    ObligationKind::Ack,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Aborted,
                    "state",
                    crate::record::ObligationState::Aborted,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(20),
                    "duration",
                    &Some(20),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason == &Some(ObligationAbortReason::Cancel),
                    "abort_reason",
                    &Some(ObligationAbortReason::Cancel),
                    abort_reason
                );
            }
            other => panic!("unexpected abort data: {other:?}"),
        }
        crate::test_complete!("obligation_trace_events_emitted");
    }

    #[test]
    fn obligation_leak_emits_trace_event() {
        init_test("obligation_leak_emits_trace_event");
        let mut runtime = LabRuntime::with_seed(22);
        let root = runtime.state.create_root_region(Budget::INFINITE);

        let task_idx = runtime.state.insert_task(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        runtime.state.task_mut(task_id).unwrap().id = task_id;

        runtime.advance_time_to(Time::from_nanos(100));
        let obligation = runtime
            .state
            .create_obligation(ObligationKind::Lease, task_id, root, None)
            .unwrap();

        runtime.advance_time_to(Time::from_nanos(140));
        runtime
            .state
            .task_mut(task_id)
            .unwrap()
            .complete(Outcome::Ok(()));

        let violations = runtime.check_invariants();
        let has_leak = violations
            .iter()
            .any(|v| matches!(v, InvariantViolation::ObligationLeak { .. }));
        crate::assert_with_log!(has_leak, "has leak", true, has_leak);

        let leak_event = runtime
            .trace()
            .snapshot()
            .into_iter()
            .find(|e| e.kind == TraceEventKind::ObligationLeak)
            .expect("leak event");
        match &leak_event.data {
            TraceData::Obligation {
                obligation: leaked,
                task,
                region,
                kind,
                state,
                duration_ns,
                abort_reason,
            } => {
                crate::assert_with_log!(*leaked == obligation, "obligation", obligation, *leaked);
                crate::assert_with_log!(*task == task_id, "task", task_id, *task);
                crate::assert_with_log!(*region == root, "region", root, *region);
                crate::assert_with_log!(
                    *kind == ObligationKind::Lease,
                    "kind",
                    ObligationKind::Lease,
                    *kind
                );
                crate::assert_with_log!(
                    *state == crate::record::ObligationState::Leaked,
                    "state",
                    crate::record::ObligationState::Leaked,
                    *state
                );
                crate::assert_with_log!(
                    duration_ns == &Some(40),
                    "duration",
                    &Some(40),
                    duration_ns
                );
                crate::assert_with_log!(
                    abort_reason.is_none(),
                    "abort_reason",
                    &None::<crate::record::ObligationAbortReason>,
                    abort_reason
                );
            }
            other => panic!("unexpected leak data: {other:?}"),
        }
        crate::test_complete!("obligation_leak_emits_trace_event");
    }

    // =========================================================================
    // Agent Report Contract tests (bd-f262i)
    // =========================================================================

    /// The JSON schema must contain all required top-level keys.
    #[test]
    fn contract_json_has_required_top_level_keys() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_has_required_top_level_keys");

        let app = crate::app::AppSpec::new("contract_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // Required top-level keys per bd-f262i contract.
        let required_keys = [
            "schema_version",
            "verdict",
            "app",
            "lab",
            "fingerprints",
            "run",
            "crashpack",
            "attachments",
        ];
        for key in &required_keys {
            assert!(
                json.get(key).is_some(),
                "missing required top-level key: {key}"
            );
        }

        // Nested required keys.
        assert!(json["app"]["name"].is_string(), "app.name must be a string");
        assert!(
            json["lab"]["config"].is_object(),
            "lab.config must be an object"
        );
        assert!(
            json["lab"]["config_hash"].is_u64(),
            "lab.config_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["trace"].is_u64(),
            "fingerprints.trace must be a u64"
        );
        assert!(
            json["fingerprints"]["event_hash"].is_u64(),
            "fingerprints.event_hash must be a u64"
        );
        assert!(
            json["fingerprints"]["event_count"].is_u64(),
            "fingerprints.event_count must be a u64"
        );
        assert!(
            json["fingerprints"]["schedule_hash"].is_u64(),
            "fingerprints.schedule_hash must be a u64"
        );
        assert!(json["run"]["seed"].is_u64(), "run.seed must be a u64");
        assert!(
            json["run"]["oracles"].is_object(),
            "run.oracles must be an object"
        );
        assert!(
            json["run"]["invariants"].is_array(),
            "run.invariants must be an array"
        );
        assert!(
            json["run"]["refinement_firewall"].is_object(),
            "run.refinement_firewall must be an object"
        );
        assert!(
            json["run"]["refinement_firewall"]["skipped_due_to_trace_truncation"].is_boolean(),
            "run.refinement_firewall.skipped_due_to_trace_truncation must be a boolean"
        );
        assert!(
            json["attachments"].is_array(),
            "attachments must be an array"
        );
        assert!(
            json["crashpack"].is_null(),
            "passing runs should have null crashpack linkage"
        );

        crate::test_complete!("contract_json_has_required_top_level_keys");
    }

    /// Schema version must be the current constant.
    #[test]
    fn contract_schema_version_is_current() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_schema_version_is_current");

        let app = crate::app::AppSpec::new("version_test");
        let harness = crate::lab::SporkAppHarness::with_seed(1, app).unwrap();
        let report = harness.run_to_report().unwrap();

        assert_eq!(report.schema_version, SporkHarnessReport::SCHEMA_VERSION);
        assert_eq!(
            report.to_json()["schema_version"],
            SporkHarnessReport::SCHEMA_VERSION
        );

        crate::test_complete!("contract_schema_version_is_current");
    }

    /// Config hash is deterministic: same config -> same hash.
    #[test]
    fn contract_config_hash_deterministic() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_config_hash_deterministic");

        let config = LabConfig::new(42);
        let summary_a = LabConfigSummary::from_config(&config);
        let summary_b = LabConfigSummary::from_config(&config);

        assert_eq!(summary_a.config_hash(), summary_b.config_hash());

        // Different seed -> different hash.
        let config_2 = LabConfig::new(99);
        let summary_c = LabConfigSummary::from_config(&config_2);
        assert_ne!(summary_a.config_hash(), summary_c.config_hash());

        crate::test_complete!("contract_config_hash_deterministic");
    }

    /// Verdict field correctly reflects pass/fail.
    #[test]
    fn contract_verdict_reflects_oracle_state() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_verdict_reflects_oracle_state");

        let app = crate::app::AppSpec::new("verdict_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();

        // Empty app should pass.
        assert!(report.passed());
        assert_eq!(report.to_json()["verdict"], "pass");
        assert!(report.summary_line().starts_with("[PASS]"));

        crate::test_complete!("contract_verdict_reflects_oracle_state");
    }

    /// Agent UX convenience methods return consistent values.
    #[test]
    fn contract_convenience_methods_consistent() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_convenience_methods_consistent");

        let app = crate::app::AppSpec::new("ux_test");
        let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
        let report = harness.run_to_report().unwrap();
        let json = report.to_json();

        // trace_fingerprint() matches JSON.
        assert_eq!(
            report.trace_fingerprint(),
            json["fingerprints"]["trace"].as_u64().unwrap()
        );

        // seed() matches JSON.
        assert_eq!(report.seed(), json["run"]["seed"].as_u64().unwrap());

        // config_hash() matches JSON.
        assert_eq!(
            report.config_hash(),
            json["lab"]["config_hash"].as_u64().unwrap()
        );

        // No crashpack by default.
        assert!(report.crashpack_path().is_none());

        // Empty app -> no oracle failures.
        assert!(report.oracle_failures().is_empty());

        crate::test_complete!("contract_convenience_methods_consistent");
    }

    /// Failing runs auto-attach a deterministic crashpack reference.
    #[test]
    fn contract_auto_crashpack_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_on_failure");

        let mut runtime = LabRuntime::with_seed(17);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime.run_until_quiescent();
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");

        let report = runtime.spork_report("failing_app", Vec::new());
        assert!(!report.passed(), "failing run must not report PASS");
        let crashpack_path = report
            .crashpack_path()
            .expect("failing run should include crashpack attachment");
        assert!(
            crashpack_path.starts_with("crashpack-"),
            "unexpected crashpack path: {crashpack_path}"
        );
        assert!(
            report
                .attachments
                .iter()
                .any(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack),
            "crashpack attachment kind must be present"
        );
        let crashpack_link = report
            .crashpack_link()
            .expect("failing run should expose crashpack link metadata");
        assert_eq!(crashpack_link.path, crashpack_path);
        assert_eq!(crashpack_link.fingerprint, report.trace_fingerprint());
        assert!(
            crashpack_link.id.starts_with("crashpack-"),
            "unexpected crashpack id: {}",
            crashpack_link.id
        );
        assert!(
            crashpack_link.replay.command_line.contains(crashpack_path),
            "replay command should include crashpack path"
        );

        crate::test_complete!("contract_auto_crashpack_on_failure");
    }

    /// Failing runs with replay recording enabled include a deterministic
    /// divergent prefix in the auto-built crashpack.
    #[test]
    fn contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled");

        let config = LabConfig::new(1701)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime.run_until_quiescent();
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");

        let run = runtime.report();
        let crashpack = runtime
            .build_crashpack_for_report(&run)
            .expect("failing run should build crashpack");

        assert!(crashpack.has_divergent_prefix());
        assert!(
            crashpack
                .manifest
                .has_attachment(&crate::trace::crashpack::AttachmentKind::DivergentPrefix),
            "manifest must include divergent prefix attachment"
        );
        assert!(
            crashpack.replay.is_some(),
            "crashpack should carry replay command metadata"
        );

        crate::test_complete!(
            "contract_auto_crashpack_contains_divergent_prefix_when_replay_enabled"
        );
    }

    /// Manual crashpack attachments are preserved without auto-duplication.
    #[test]
    fn contract_manual_crashpack_not_duplicated_on_failure() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_manual_crashpack_not_duplicated_on_failure");

        let mut runtime = LabRuntime::with_seed(18);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime.run_until_quiescent();
        runtime
            .state
            .create_obligation(
                ObligationKind::SendPermit,
                task,
                region,
                Some("intentional leak".to_string()),
            )
            .expect("create obligation");

        let report = runtime.spork_report(
            "failing_app_manual",
            vec![HarnessAttachmentRef::crashpack("manual-crashpack.json")],
        );
        let crashpack_count = report
            .attachments
            .iter()
            .filter(|attachment| attachment.kind == HarnessAttachmentKind::CrashPack)
            .count();
        assert_eq!(
            crashpack_count, 1,
            "manual crashpack should not be duplicated"
        );
        assert_eq!(report.crashpack_path(), Some("manual-crashpack.json"));
        let crashpack_link = report
            .crashpack_link()
            .expect("manual crashpack should still produce metadata");
        assert_eq!(crashpack_link.path, "manual-crashpack.json");
        assert!(
            crashpack_link
                .replay
                .command_line
                .contains("manual-crashpack.json"),
            "replay command should include manual crashpack path"
        );

        crate::test_complete!("contract_manual_crashpack_not_duplicated_on_failure");
    }

    /// JSON output is deterministic across runs with same seed.
    #[test]
    fn contract_json_deterministic_same_seed() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_json_deterministic_same_seed");

        let json_a = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        let json_b = {
            let app = crate::app::AppSpec::new("det_contract");
            let harness = crate::lab::SporkAppHarness::with_seed(42, app).unwrap();
            harness.run_to_report().unwrap().to_json()
        };

        assert_eq!(json_a, json_b, "same seed must produce identical JSON");

        crate::test_complete!("contract_json_deterministic_same_seed");
    }

    /// Attachments appear in the report, sorted by (kind, path).
    #[test]
    fn contract_attachments_sorted_in_json() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("contract_attachments_sorted_in_json");

        let app = crate::app::AppSpec::new("attach_contract");
        let mut harness = crate::lab::SporkAppHarness::with_seed(7, app).unwrap();
        // Add in reverse order to verify sorting.
        harness.attach(HarnessAttachmentRef::trace("z_trace.json"));
        harness.attach(HarnessAttachmentRef::crashpack("a_crash.tar"));

        let report = harness.run_to_report().unwrap();

        // crashpack_path() returns the crashpack.
        assert_eq!(report.crashpack_path(), Some("a_crash.tar"));

        let json = report.to_json();
        let attachments = json["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 2);

        // CrashPack sorts before Trace (enum ordering).
        assert_eq!(attachments[0]["kind"], "crashpack");
        assert_eq!(attachments[1]["kind"], "trace");

        crate::test_complete!("contract_attachments_sorted_in_json");
    }

    // =========================================================================
    // Virtual Time Control Tests (bd-1hu19.3)
    // =========================================================================

    #[test]
    fn advance_to_next_timer_empty() {
        init_test("advance_to_next_timer_empty");
        let mut runtime = LabRuntime::with_seed(42);

        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 0, "no timers → 0 wakeups", 0, wakeups);

        let deadline = runtime.next_timer_deadline();
        crate::assert_with_log!(
            deadline.is_none(),
            "no pending deadline",
            true,
            deadline.is_none()
        );
        crate::test_complete!("advance_to_next_timer_empty");
    }

    #[test]
    fn advance_to_next_timer_fires_timer() {
        init_test("advance_to_next_timer_fires_timer");
        let mut runtime = LabRuntime::with_seed(42);

        // Register a timer at t=1s via the timer driver handle
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let woken = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let waker = Waker::from(Arc::new(FlagWaker(woken.clone())));
        let _ = timer_handle.register(Time::from_secs(1), waker);

        // Should have 1 pending timer
        let count = runtime.pending_timer_count();
        crate::assert_with_log!(count == 1, "1 pending timer", 1, count);

        // Advance to next timer
        let wakeups = runtime.advance_to_next_timer();
        crate::assert_with_log!(wakeups == 1, "1 wakeup", 1, wakeups);

        // Time should now be at 1 second
        let now = runtime.now();
        crate::assert_with_log!(
            now == Time::from_secs(1),
            "time at 1s",
            Time::from_secs(1),
            now
        );

        // Waker should have been called
        let was_woken = woken.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(was_woken, "waker fired", true, was_woken);
        crate::test_complete!("advance_to_next_timer_fires_timer");
    }

    #[test]
    fn run_with_auto_advance_basic() {
        init_test("run_with_auto_advance_basic");
        let config = LabConfig::new(42).with_auto_advance();
        let mut runtime = LabRuntime::new(config);

        // No tasks, no timers → immediate quiescence
        let report = runtime.run_with_auto_advance();
        crate::assert_with_log!(report.steps == 0, "0 steps", 0u64, report.steps);
        crate::assert_with_log!(
            report.auto_advances == 0,
            "0 auto-advances",
            0u64,
            report.auto_advances
        );
        crate::test_complete!("run_with_auto_advance_basic");
    }

    #[test]
    fn run_with_auto_advance_jumps_past_timer_deadlines() {
        init_test("run_with_auto_advance_jumps_past_timer_deadlines");
        let config = LabConfig::new(42).with_auto_advance().max_steps(1_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers at 1s, 5s, and 10s via timer driver
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for secs in [1, 5, 10] {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(secs), waker);
        }

        let report = runtime.run_with_auto_advance();

        // All 3 timer deadlines should have been auto-advanced to
        crate::assert_with_log!(
            report.auto_advances >= 3,
            "at least 3 auto-advances",
            true,
            report.auto_advances >= 3
        );

        // Virtual time should be at or past 10 seconds
        let now = runtime.now();
        crate::assert_with_log!(
            now >= Time::from_secs(10),
            "time >= 10s",
            true,
            now >= Time::from_secs(10)
        );

        // All wakers should have been called
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 3, "3 wakeups", 3u64, count);
        crate::test_complete!("run_with_auto_advance_jumps_past_timer_deadlines");
    }

    #[test]
    fn virtual_time_24_hour_instant_test() {
        init_test("virtual_time_24_hour_instant_test");
        // Acceptance criterion: 24 hours of virtual time in <1 second wall time.
        let config = LabConfig::new(42).with_auto_advance().max_steps(100_000);
        let mut runtime = LabRuntime::new(config);

        // Register timers spread across 24 hours (every hour)
        let timer_handle = runtime.state.timer_driver_handle().unwrap();
        let wake_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for hour in 1..=24 {
            let waker = Waker::from(Arc::new(CountWaker(wake_count.clone())));
            let _ = timer_handle.register(Time::from_secs(hour * 3600), waker);
        }

        let wall_start = std::time::Instant::now();
        let report = runtime.run_with_auto_advance();
        let wall_elapsed = wall_start.elapsed();

        // Virtual time should span 24 hours = 86400 seconds
        crate::assert_with_log!(
            report.virtual_elapsed_secs() >= 86400,
            "24h virtual",
            true,
            report.virtual_elapsed_secs() >= 86400
        );

        // All 24 timers fired
        let count = wake_count.load(std::sync::atomic::Ordering::SeqCst);
        crate::assert_with_log!(count == 24, "24 wakeups", 24u64, count);

        // Wall time should be well under 1 second (typically <1ms)
        let wall_ms = wall_elapsed.as_millis();
        crate::assert_with_log!(wall_ms < 1000, "wall time < 1s", true, wall_ms < 1000);
        crate::test_complete!("virtual_time_24_hour_instant_test");
    }

    #[test]
    fn clock_pause_resume() {
        init_test("clock_pause_resume");
        let runtime = LabRuntime::with_seed(42);

        let not_paused = !runtime.is_clock_paused();
        crate::assert_with_log!(not_paused, "not paused initially", true, not_paused);

        runtime.pause_clock();
        let paused = runtime.is_clock_paused();
        crate::assert_with_log!(paused, "paused", true, paused);

        runtime.resume_clock();
        let resumed = !runtime.is_clock_paused();
        crate::assert_with_log!(resumed, "resumed", true, resumed);
        crate::test_complete!("clock_pause_resume");
    }

    #[test]
    fn inject_clock_skew() {
        init_test("inject_clock_skew");
        let mut runtime = LabRuntime::with_seed(42);

        runtime.advance_time(1_000_000_000); // 1 second
        let before = runtime.now();

        // Inject 5 second skew
        runtime.inject_clock_skew(5_000_000_000);
        let after = runtime.now();

        let delta = after.as_nanos() - before.as_nanos();
        crate::assert_with_log!(
            delta == 5_000_000_000,
            "5s skew applied",
            5_000_000_000u64,
            delta
        );

        crate::assert_with_log!(
            after == Time::from_secs(6),
            "time at 6s",
            Time::from_secs(6),
            after
        );
        crate::test_complete!("inject_clock_skew");
    }

    #[test]
    fn virtual_time_report_conversions() {
        init_test("virtual_time_report_conversions");
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_secs(3600),
            virtual_elapsed_nanos: 3_600_000_000_000,
        };

        let ms = report.virtual_elapsed_ms();
        crate::assert_with_log!(ms == 3_600_000, "3600000 ms", 3_600_000u64, ms);

        let secs = report.virtual_elapsed_secs();
        crate::assert_with_log!(secs == 3600, "3600 secs", 3600u64, secs);
        crate::test_complete!("virtual_time_report_conversions");
    }

    // =========================================================================
    // Replay severity correctness (bd-beuyd)
    // =========================================================================

    /// Regression test: replay recorder must capture the actual completion
    /// severity from the finalized task record, not always `Severity::Ok`.
    ///
    /// `create_task` wraps futures to always return `Outcome::Ok(())` — the
    /// real severity is determined by the cancel protocol state machine. This
    /// test puts a task through the cancel protocol and verifies the replay
    /// trace records the correct `Cancelled` severity.
    #[test]
    fn replay_records_correct_severity_for_cancelled_task() {
        init_test("replay_records_correct_severity_for_cancelled_task");

        let config = LabConfig::new(42)
            .panic_on_leak(false)
            .with_default_replay_recording();
        let mut runtime = LabRuntime::new(config);
        let root = runtime
            .state
            .create_root_region(crate::types::Budget::INFINITE);

        // Create a task that yields once then completes with Ok.
        // The yield allows us to cancel the task before it finishes.
        let (task_id, _) = runtime
            .state
            .create_task(root, crate::types::Budget::INFINITE, async {
                crate::runtime::yield_now::yield_now().await;
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);

        // Step once: task yields (Pending)
        runtime.step();

        // Put the task through cancel protocol: CancelRequested → Cancelling
        if let Some(record) = runtime.state.task_mut(task_id) {
            record.request_cancel(crate::types::CancelReason::user("test-cancel"));
            let _ = record.acknowledge_cancel();
            // Task is now in Cancelling state
            assert!(
                matches!(
                    record.state,
                    crate::record::task::TaskState::Cancelling { .. }
                ),
                "task should be in Cancelling state"
            );
        }

        // Reschedule and run to completion: the cancel protocol will
        // complete it as Cancelled when the wrapped future returns Ok.
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // Verify the task completed as Cancelled
        if let Some(record) = runtime.state.task(task_id) {
            assert!(
                matches!(
                    record.state,
                    crate::record::task::TaskState::Completed(crate::types::Outcome::Cancelled(_))
                ),
                "task should be Completed(Cancelled), got {:?}",
                record.state
            );
        }

        // Check the replay trace for the TaskCompleted event
        let replay = runtime
            .replay_recorder()
            .snapshot()
            .expect("replay recording enabled");
        let completed_events: Vec<_> = replay
            .events
            .iter()
            .filter(|e| matches!(e, crate::trace::replay::ReplayEvent::TaskCompleted { .. }))
            .collect();

        assert!(
            !completed_events.is_empty(),
            "should have at least one TaskCompleted event"
        );

        // The severity should be Cancelled (2), not Ok (0)
        for event in &completed_events {
            if let crate::trace::replay::ReplayEvent::TaskCompleted { outcome, .. } = event {
                let expected = crate::types::Severity::Cancelled.as_u8();
                crate::assert_with_log!(
                    *outcome == expected,
                    "severity should be Cancelled (2)",
                    expected,
                    *outcome
                );
            }
        }

        crate::test_complete!("replay_records_correct_severity_for_cancelled_task");
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn lab_trace_certificate_summary_debug_clone_copy_eq() {
        let summary = LabTraceCertificateSummary {
            event_hash: 123,
            event_count: 456,
            schedule_hash: 789,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        assert_ne!(
            summary,
            LabTraceCertificateSummary {
                event_hash: 0,
                event_count: 456,
                schedule_hash: 789,
            }
        );
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("LabTraceCertificateSummary"));
    }

    #[test]
    fn virtual_time_report_debug_clone_copy_eq() {
        let report = VirtualTimeReport {
            steps: 100,
            auto_advances: 5,
            total_wakeups: 10,
            time_start: Time::ZERO,
            time_end: Time::from_millis(500),
            virtual_elapsed_nanos: 500_000_000,
        };
        let copied = report;
        assert_eq!(copied, report);
        assert_eq!(report.virtual_elapsed_ms(), 500);
        assert_eq!(report.virtual_elapsed_secs(), 0);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("VirtualTimeReport"));
    }

    #[test]
    fn harness_attachment_kind_debug_clone_copy_eq_hash_ord_display() {
        use std::collections::HashSet;
        let kinds = [
            HarnessAttachmentKind::CrashPack,
            HarnessAttachmentKind::ReplayTrace,
            HarnessAttachmentKind::Trace,
            HarnessAttachmentKind::Other,
        ];
        // Display
        assert_eq!(format!("{}", kinds[0]), "crashpack");
        assert_eq!(format!("{}", kinds[1]), "replay_trace");
        assert_eq!(format!("{}", kinds[2]), "trace");
        assert_eq!(format!("{}", kinds[3]), "other");
        // Copy/Clone/Eq
        for &k in &kinds {
            let copied = k;
            let cloned = k;
            assert_eq!(copied, cloned);
        }
        // Hash
        let mut set = HashSet::new();
        for &k in &kinds {
            set.insert(k);
        }
        assert_eq!(set.len(), 4);
        // Ord (derive ordering: CrashPack < ReplayTrace < Trace < Other)
        assert!(HarnessAttachmentKind::CrashPack < HarnessAttachmentKind::ReplayTrace);
        assert!(HarnessAttachmentKind::ReplayTrace < HarnessAttachmentKind::Trace);
        assert!(HarnessAttachmentKind::Trace < HarnessAttachmentKind::Other);
        let mut sorted = [kinds[3], kinds[0], kinds[2], kinds[1]];
        sorted.sort();
        assert_eq!(sorted, kinds);
    }

    #[test]
    fn harness_attachment_ref_debug_clone_eq_hash() {
        use std::collections::HashSet;
        let ref1 = HarnessAttachmentRef::crashpack("crash.bin");
        let ref2 = HarnessAttachmentRef::replay_trace("replay.bin");
        let ref3 = HarnessAttachmentRef::trace("trace.ndjson");
        assert_eq!(ref1.kind, HarnessAttachmentKind::CrashPack);
        assert_eq!(ref2.kind, HarnessAttachmentKind::ReplayTrace);
        assert_eq!(ref3.kind, HarnessAttachmentKind::Trace);
        let cloned = ref1.clone();
        assert_eq!(cloned, ref1);
        assert_ne!(ref1, ref2);
        let dbg = format!("{ref1:?}");
        assert!(dbg.contains("HarnessAttachmentRef"));
        let mut set = HashSet::new();
        set.insert(ref1.clone());
        set.insert(ref2);
        set.insert(ref1); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn chaos_config_summary_debug_clone_copy_partial_eq() {
        let summary = ChaosConfigSummary {
            seed: 42,
            cancel_probability: 0.1,
            delay_probability: 0.2,
            io_error_probability: 0.05,
            wakeup_storm_probability: 0.01,
            budget_exhaust_probability: 0.03,
        };
        let copied = summary;
        let cloned = summary;
        assert_eq!(copied, cloned);
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("ChaosConfigSummary"));
    }

    #[test]
    fn obligation_leak_debug_clone_eq_display() {
        let leak = ObligationLeak {
            obligation: ObligationId::new_for_test(1, 0),
            kind: ObligationKind::SendPermit,
            holder: TaskId::from_arena(crate::util::ArenaIndex::new(1, 0)),
            region: RegionId::new_for_test(0, 0),
        };
        let cloned = leak.clone();
        assert_eq!(cloned, leak);
        let dbg = format!("{leak:?}");
        assert!(dbg.contains("ObligationLeak"));
        let display = format!("{leak}");
        assert!(!display.is_empty());
    }
}
