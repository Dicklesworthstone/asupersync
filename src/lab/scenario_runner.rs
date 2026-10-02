//! Scenario runner for FrankenLab deterministic testing (bd-1hu19.2).
//!
//! Bridges [`Scenario`] YAML specifications to [`LabRuntime`] execution, providing:
//!
//! - Participant workloads: `sender` and `receiver` roles become real lab tasks
//! - Timed fault injection based on scenario fault events
//! - Oracle filtering (only check oracles listed in the scenario)
//! - Seed exploration (run the same scenario across multiple seeds)
//! - Replay validation (run twice, verify identical trace certificates)
//!
//! # Participant workloads
//!
//! Before any fault fires, the runner spawns one lab task per participant
//! whose `role` is exactly `sender` or `receiver` (case-sensitive), all in
//! one root region:
//!
//! - each receiver owns a bounded [`mpsc`] channel
//!   (`properties.capacity`, default 4, at most 4096) and drains it until
//!   every sender is gone;
//! - each sender sends `properties.messages` values (default 16) to the
//!   receivers in round-robin order through the two-phase `reserve` and
//!   `send` API, so every value is a runtime-tracked `SendPermit`
//!   obligation;
//! - senders without any receiver race on one shared channel that an
//!   implicit sink task drains, and receivers without senders observe a
//!   closed channel at once.
//!
//! Lab chaos may cancel these tasks mid-protocol. A send or receive that
//! ends in cancellation is counted and stops that task; it is never retried.
//! The runner appends a `workload:` entry to the report's invariant
//! violations, which fails the run, when a bound task cannot be spawned,
//! meets an outcome the channel contract rules out, receives one sender's
//! values out of order, or drains its channel to close without receiving
//! every value committed into it. Timed faults stay trace and effect-summary
//! records; they do not partition the bound channels.
//!
//! Every other role is unbound: the runner validates the participant and
//! schedules no work for it. A scenario without bound participants still
//! runs an empty lab and reports zero steps.
//! [`ScenarioRunner::participant_bindings`] reports the split. The workload is
//! a pure function of the scenario and the lab seed.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::scenario_runner::{ScenarioRunner, ScenarioRunResult};
//! use asupersync::lab::scenario::Scenario;
//!
//! let yaml = std::fs::read_to_string("examples/scenarios/smoke_happy_path.yaml")?;
//! let scenario: Scenario = serde_yaml::from_str(&yaml)?;
//!
//! let result = ScenarioRunner::run(&scenario)?;
//! assert!(result.passed());
//! ```

use super::config::LabConfig;
use super::dual_run::{DualRunScenarioIdentity, ReplayMetadata, SeedLineageRecord};
use super::oracle::{OracleRegistry, OracleRegistryError, OracleReport};
use super::runtime::{LabRunReport, LabRuntime};
use super::scenario::{FaultAction, FaultEvent, Participant, Scenario, ValidationError};
use crate::channel::mpsc::{self, RecvError, SendError};
use crate::cx::Cx;
use crate::runtime::TaskHandle;
use crate::trace::replay::ReplayTrace;
use crate::types::{Budget, Outcome, RegionId, Time};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const REPLAY_DIVERGENCE_CODE: &str = "ASUP-E401";
const LAB_SCENARIO_RUNNER_ADAPTER: &str = "lab.scenario_runner";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the scenario runner.
#[derive(Debug)]
pub enum ScenarioRunnerError {
    /// Scenario validation failed.
    Validation {
        /// Scenario identifier that failed validation.
        scenario_id: String,
        /// Validation errors emitted by the scenario contract.
        errors: Vec<ValidationError>,
    },
    /// An oracle listed in the scenario is not recognized.
    UnknownOracle(String),
    /// Replay divergence: two runs with the same seed produced different traces.
    ReplayDivergence {
        /// The seed that diverged.
        seed: u64,
        /// Certificate from the first run.
        first: TraceCertificateSnapshot,
        /// Certificate from the second run.
        second: TraceCertificateSnapshot,
    },
}

impl std::fmt::Display for ScenarioRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation {
                scenario_id,
                errors,
            } => {
                write!(
                    f,
                    "scenario validation failed for {scenario_id} ({} issue(s)):",
                    errors.len()
                )?;
                for e in errors {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            Self::UnknownOracle(name) => {
                let detail = match OracleRegistry::validate_reported_selection(
                    std::slice::from_ref(name),
                ) {
                    Err(OracleRegistryError::UnknownOracle { .. }) => {
                        let suggestion = OracleRegistry::suggestion_for(name)
                            .map_or_else(String::new, |suggestion| {
                                format!("; did you mean `{suggestion}`")
                            });
                        format!(
                            "unknown oracle: {name}{suggestion}; valid names: {}",
                            OracleRegistry::reported_names().join(", ")
                        )
                    }
                    Err(OracleRegistryError::NotReportable { .. }) => format!(
                        "oracle `{name}` is registered but is not emitted by OracleSuite::report yet; valid scenario names: {}",
                        OracleRegistry::reported_names().join(", ")
                    ),
                    Err(OracleRegistryError::NotInstantiable { .. }) | Ok(()) => {
                        format!("unknown oracle: {name}")
                    }
                };
                f.write_str(&detail)
            }
            Self::ReplayDivergence {
                seed,
                first,
                second,
            } => write!(
                f,
                "[{REPLAY_DIVERGENCE_CODE}] replay divergence at seed {seed}: \
                 first(event_hash={}, schedule_hash={}, steps={}) != \
                 second(event_hash={}, schedule_hash={}, steps={})",
                first.event_hash,
                first.schedule_hash,
                first.steps,
                second.event_hash,
                second.schedule_hash,
                second.steps,
            ),
        }
    }
}

impl std::error::Error for ScenarioRunnerError {}

// ---------------------------------------------------------------------------
// Certificate snapshot (for replay validation)
// ---------------------------------------------------------------------------

/// Lightweight copy of trace identity for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceCertificateSnapshot {
    /// Hash of all trace events.
    pub event_hash: u64,
    /// Hash of scheduling decisions.
    pub schedule_hash: u64,
    /// Total steps executed.
    pub steps: u64,
    /// Trace fingerprint (Foata equivalence class).
    pub trace_fingerprint: u64,
}

/// Structured record for a scenario fault injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultInjectionLogEntry {
    /// Virtual time in milliseconds when the fault fired.
    pub at_ms: u64,
    /// Stable fault action name.
    pub action: String,
    /// Canonical, sorted argument summary.
    pub args_summary: String,
    /// Redacted trace message emitted into the lab trace buffer.
    pub trace_message: String,
}

impl FaultInjectionLogEntry {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "at_ms": self.at_ms,
            "action": self.action,
            "args_summary": self.args_summary,
            "trace_message": self.trace_message,
        })
    }
}

/// Deterministic effect accounting for scenario fault actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FaultEffectSummary {
    /// Active disk-pressure bytes after all scheduled faults have fired.
    pub active_disk_pressure_bytes: u64,
    /// Maximum active disk-pressure bytes observed during the run.
    pub max_disk_pressure_bytes: u64,
    /// Number of disk-pressure events applied.
    pub disk_pressure_events: usize,
    /// Active disk-pressure bytes by canonical path.
    pub disk_pressure_by_path: BTreeMap<String, u64>,
    /// Total cleanup delay requested by delayed-cleanup faults.
    pub delayed_cleanup_total_ms: u64,
    /// Cleanup delay requested by phase.
    pub delayed_cleanup_phases: BTreeMap<String, u64>,
    /// Total bounded process-stall duration requested by process-stall faults.
    pub process_stall_total_ms: u64,
    /// Participants still stalled after the scheduled fault stream.
    pub stalled_participants_until_ms: BTreeMap<String, u64>,
    /// Resource-cap breaches observed while applying fault effects.
    pub resource_cap_breaches: Vec<String>,
}

impl FaultEffectSummary {
    fn fault_string_arg<'a>(fault: &'a FaultEvent, key: &str) -> Option<&'a str> {
        fault.args.get(key).and_then(serde_json::Value::as_str)
    }

    fn fault_u64_arg(fault: &FaultEvent, key: &str) -> Option<u64> {
        fault.args.get(key).and_then(serde_json::Value::as_u64)
    }

    fn refresh_active_disk_pressure(&mut self, cap: Option<u64>) {
        self.active_disk_pressure_bytes = self.disk_pressure_by_path.values().copied().sum();
        self.max_disk_pressure_bytes = self
            .max_disk_pressure_bytes
            .max(self.active_disk_pressure_bytes);

        if let Some(cap) = cap {
            if self.active_disk_pressure_bytes > cap {
                self.resource_cap_breaches.push(format!(
                    "disk_pressure_bytes:{}>{cap}",
                    self.active_disk_pressure_bytes
                ));
            }
        }
    }

    fn expire_process_stalls(&mut self, now_ms: u64) {
        self.stalled_participants_until_ms
            .retain(|_, resume_at_ms| *resume_at_ms > now_ms);
    }

    fn apply_fault(&mut self, fault: &FaultEvent, max_artifact_bytes: Option<u64>) {
        self.expire_process_stalls(fault.at_ms);

        match fault.action {
            FaultAction::DiskPressure => {
                if let (Some(path), Some(bytes)) = (
                    Self::fault_string_arg(fault, "path"),
                    Self::fault_u64_arg(fault, "bytes"),
                ) {
                    self.disk_pressure_events += 1;
                    self.disk_pressure_by_path.insert(path.to_string(), bytes);
                    self.refresh_active_disk_pressure(max_artifact_bytes);
                }
            }
            FaultAction::DiskRecovered => {
                if let Some(path) = Self::fault_string_arg(fault, "path") {
                    self.disk_pressure_by_path.remove(path);
                    self.refresh_active_disk_pressure(max_artifact_bytes);
                }
            }
            FaultAction::DelayedCleanup => {
                if let (Some(phase), Some(delay_ms)) = (
                    Self::fault_string_arg(fault, "phase"),
                    Self::fault_u64_arg(fault, "delay_ms"),
                ) {
                    self.delayed_cleanup_total_ms =
                        self.delayed_cleanup_total_ms.saturating_add(delay_ms);
                    self.delayed_cleanup_phases
                        .entry(phase.to_string())
                        .and_modify(|total| *total = total.saturating_add(delay_ms))
                        .or_insert(delay_ms);
                }
            }
            FaultAction::ProcessStall => {
                if let (Some(host), Some(duration_ms)) = (
                    Self::fault_string_arg(fault, "host"),
                    Self::fault_u64_arg(fault, "duration_ms"),
                ) {
                    self.process_stall_total_ms =
                        self.process_stall_total_ms.saturating_add(duration_ms);
                    self.stalled_participants_until_ms
                        .insert(host.to_string(), fault.at_ms.saturating_add(duration_ms));
                }
            }
            FaultAction::ProcessResume => {
                if let Some(host) = Self::fault_string_arg(fault, "host") {
                    self.stalled_participants_until_ms.remove(host);
                }
            }
            FaultAction::Partition
            | FaultAction::Heal
            | FaultAction::HostCrash
            | FaultAction::HostRestart
            | FaultAction::ClockSkew
            | FaultAction::ClockReset => {}
        }
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let active_stalled_participants = self
            .stalled_participants_until_ms
            .keys()
            .cloned()
            .collect::<Vec<_>>();

        json!({
            "active_disk_pressure_bytes": self.active_disk_pressure_bytes,
            "max_disk_pressure_bytes": self.max_disk_pressure_bytes,
            "disk_pressure_events": self.disk_pressure_events,
            "disk_pressure_by_path": self.disk_pressure_by_path,
            "delayed_cleanup_total_ms": self.delayed_cleanup_total_ms,
            "delayed_cleanup_phases": self.delayed_cleanup_phases,
            "process_stall_total_ms": self.process_stall_total_ms,
            "active_stalled_participants": active_stalled_participants,
            "stalled_participants_until_ms": self.stalled_participants_until_ms,
            "resource_cap_breaches": self.resource_cap_breaches,
        })
    }
}

/// Deterministic minimized counterexample packet for unresolved scenario faults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedCounterexamplePacket {
    /// Scenario identifier that produced the counterexample.
    pub scenario_id: String,
    /// Stable reason for the packet.
    pub reason: String,
    /// Number of fault-log entries retained in the minimized packet.
    pub prefix_len: usize,
    /// Total scheduled fault count from the original scenario run.
    pub fault_count: usize,
    /// Configured maximum counterexample events.
    pub max_counterexample_events: usize,
    /// Participants still stalled at the end of the scheduled fault stream.
    pub active_stalled_participants: Vec<String>,
    /// Redacted fault-log entries retained for replay/debugging.
    pub fault_log_prefix: Vec<FaultInjectionLogEntry>,
    /// Whether the source scenario requested redacted projection.
    pub redacted: bool,
}

impl MinimizedCounterexamplePacket {
    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "scenario_id": self.scenario_id,
            "reason": self.reason,
            "prefix_len": self.prefix_len,
            "fault_count": self.fault_count,
            "max_counterexample_events": self.max_counterexample_events,
            "active_stalled_participants": self.active_stalled_participants,
            "fault_log_prefix": self
                .fault_log_prefix
                .iter()
                .map(FaultInjectionLogEntry::to_json)
                .collect::<Vec<_>>(),
            "redacted": self.redacted,
        })
    }
}

// ---------------------------------------------------------------------------
// Run result
// ---------------------------------------------------------------------------

/// Result of running a single scenario.
#[derive(Debug, Clone)]
pub struct ScenarioRunResult {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Seed used for this run.
    pub seed: u64,
    /// The underlying lab run report.
    pub lab_report: LabRunReport,
    /// Filtered oracle report (only oracles listed in the scenario).
    pub oracle_report: FilteredOracleReport,
    /// Number of fault events injected during the run.
    pub faults_injected: usize,
    /// Structured log of fault injections, in deterministic execution order.
    pub fault_log: Vec<FaultInjectionLogEntry>,
    /// Deterministic summary of effects applied by fault injection.
    pub fault_effect_summary: FaultEffectSummary,
    /// Minimized counterexample packet when bounded fault effects remain unresolved.
    pub minimized_counterexample: Option<MinimizedCounterexamplePacket>,
    /// Replay trace, if recording was enabled.
    pub replay_trace: Option<ReplayTrace>,
    /// Trace certificate snapshot for replay validation.
    pub certificate: TraceCertificateSnapshot,
    /// Adapter identity that produced this lab result.
    pub adapter: String,
    /// Shared dual-run replay metadata for this execution.
    pub replay_metadata: ReplayMetadata,
    /// Stable seed-lineage audit record for this execution.
    pub seed_lineage: SeedLineageRecord,
}

impl ScenarioRunResult {
    /// Returns true if all checked oracles passed and no invariant violations were found.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.lab_report.quiescent
            && self.oracle_report.all_passed
            && self.lab_report.invariant_violations.is_empty()
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "scenario_id": self.scenario_id,
            "surface_id": self.replay_metadata.family.surface_id,
            "surface_contract_version": self.replay_metadata.family.surface_contract_version,
            "seed": self.seed,
            "seed_lineage_id": self.seed_lineage.seed_lineage_id,
            "adapter": self.adapter,
            "execution_instance_id": self.replay_metadata.instance.key(),
            "passed": self.passed(),
            "steps": self.lab_report.steps_total,
            "faults_injected": self.faults_injected,
            "fault_log": self.fault_log.iter().map(FaultInjectionLogEntry::to_json).collect::<Vec<_>>(),
            "fault_effect_summary": self.fault_effect_summary.to_json(),
            "minimized_counterexample": self
                .minimized_counterexample
                .as_ref()
                .map(MinimizedCounterexamplePacket::to_json),
            "certificate": {
                "event_hash": self.certificate.event_hash,
                "schedule_hash": self.certificate.schedule_hash,
                "trace_fingerprint": self.certificate.trace_fingerprint,
            },
            "oracle_report": self.oracle_report.to_json(),
            "invariant_violations": self.lab_report.invariant_violations,
            "replay_metadata": &self.replay_metadata,
            "seed_lineage": &self.seed_lineage,
        })
    }
}

// ---------------------------------------------------------------------------
// Filtered oracle report
// ---------------------------------------------------------------------------

/// Oracle report filtered to only the oracles requested by the scenario.
#[derive(Debug, Clone)]
pub struct FilteredOracleReport {
    /// The full oracle report from the runtime.
    pub full_report: OracleReport,
    /// Which oracle names were checked.
    pub checked: Vec<String>,
    /// Which checked oracles passed.
    pub passed_count: usize,
    /// Which checked oracles failed.
    pub failed_count: usize,
    /// Whether all checked oracles passed.
    pub all_passed: bool,
    /// Entries for only the checked oracles.
    pub entries: Vec<super::oracle::OracleEntryReport>,
}

impl FilteredOracleReport {
    /// Build the filtered report honoring BOTH the scenario's declared oracle
    /// list AND (br-asupersync-7tcipb item 2) the operator's
    /// `LabConfig::with_oracles` selection.
    ///
    /// The two selections INTERSECT: a config selection can only *narrow* the
    /// scenario's set — a config must never make the lab report an oracle the
    /// scenario never declared. An empty `config_selection` (the default,
    /// produced for every scenario run since `Scenario::to_lab_config` does not
    /// populate it) applies no narrowing, so scenario-only behavior is
    /// unchanged. This is what wires the previously-inert `with_oracles` /
    /// `LabConfig::selected_oracles` knob into the live filtering path.
    fn from_full(
        full_report: OracleReport,
        scenario_oracles: &[String],
        config_selection: &[String],
    ) -> Self {
        let scenario_filter = Self::resolve_filter(scenario_oracles);
        // br-asupersync-7tcipb item 2: an empty selection means "no operator
        // narrowing" (a no-op), which is distinct from an empty *scenario* list
        // meaning "the scenario declares no oracles".
        let config_filter = if config_selection.is_empty() {
            None
        } else {
            Self::resolve_filter(config_selection)
        };
        Self::build(full_report, scenario_filter, config_filter)
    }

    /// br-asupersync-7tcipb item 2: build the report narrowed ONLY by the
    /// operator's `LabConfig::with_oracles` selection (no scenario context).
    ///
    /// This is what makes `with_oracles` / `LabConfig::selected_oracles` a real
    /// control instead of a parsed-and-ignored phantom: a `LabRuntime` built
    /// from a config that selected a subset of oracles can produce a report
    /// containing only those oracles, e.g.
    ///
    /// ```ignore
    /// let report = runtime.report();
    /// let selected = FilteredOracleReport::for_lab_config(report.oracle_report, runtime.config());
    /// ```
    ///
    /// An empty selection (or `"all"`) applies no narrowing and returns the full
    /// report. The selection was already validated by `with_oracles`, so
    /// `LabConfig::selected_oracles` cannot fail here.
    #[must_use]
    pub fn for_lab_config(full_report: OracleReport, config: &LabConfig) -> Self {
        let config_filter = if config.oracle_selection.is_empty()
            || OracleRegistry::is_all_selection(&config.oracle_selection)
        {
            None
        } else {
            Some(
                config
                    .selected_oracles()
                    .expect("LabConfig::with_oracles validated the oracle selection")
                    .into_iter()
                    .collect::<HashSet<_>>(),
            )
        };
        Self::build(full_report, None, config_filter)
    }

    /// Resolve a name list into a concrete reported-oracle set, or `None` when
    /// the list selects all reported oracles (so no filtering is applied).
    fn resolve_filter(names: &[String]) -> Option<HashSet<&'static str>> {
        if OracleRegistry::is_all_selection(names) {
            None
        } else {
            Some(
                OracleRegistry::select_reported(names)
                    .expect("oracle names are validated before filtering")
                    .into_iter()
                    .collect(),
            )
        }
    }

    /// Filter `full_report` to the entries permitted by both dimensions, where
    /// `None` means "no restriction from this dimension". Entry order from the
    /// full report is preserved.
    fn build(
        full_report: OracleReport,
        scenario_filter: Option<HashSet<&'static str>>,
        config_filter: Option<HashSet<&'static str>>,
    ) -> Self {
        let entries: Vec<_> = full_report
            .entries
            .iter()
            .filter(|e| {
                let name = e.invariant.as_str();
                scenario_filter.as_ref().is_none_or(|f| f.contains(name))
                    && config_filter.as_ref().is_none_or(|f| f.contains(name))
            })
            .cloned()
            .collect();

        let checked: Vec<String> = entries.iter().map(|e| e.invariant.clone()).collect();
        let passed_count = entries.iter().filter(|e| e.passed).count();
        let failed_count = entries.len() - passed_count;
        let all_passed = failed_count == 0;

        Self {
            full_report,
            checked,
            passed_count,
            failed_count,
            all_passed,
            entries,
        }
    }

    /// Number of checked oracles that `LabRuntime` does not feed (see
    /// [`OracleRegistry::is_fed_by_lab_runtime`]). They are counted in
    /// `passed_count`, but they observed nothing in this run.
    #[must_use]
    pub fn unfed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| !OracleRegistry::is_fed_by_lab_runtime(&e.invariant))
            .count()
    }

    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "checked": self.checked,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "all_passed": self.all_passed,
            "entries": self.entries.iter().map(|e| {
                let mut v = serde_json::Map::new();
                v.insert("invariant".into(), json!(e.invariant));
                v.insert("passed".into(), json!(e.passed));
                if let Some(ref violation) = e.violation {
                    v.insert("violation".into(), json!(violation));
                }
                serde_json::Value::Object(v)
            }).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Exploration result
// ---------------------------------------------------------------------------

/// Result of exploring a scenario across multiple seeds.
#[derive(Debug, Clone)]
pub struct ScenarioExplorationResult {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Number of seeds explored.
    pub seeds_explored: usize,
    /// Number of passing runs.
    pub passed: usize,
    /// Number of failing runs.
    pub failed: usize,
    /// Unique trace fingerprints observed.
    pub unique_fingerprints: usize,
    /// Per-seed results (seed → pass/fail + fingerprint).
    pub runs: Vec<ExplorationRunSummary>,
    /// First failing seed, if any.
    pub first_failure_seed: Option<u64>,
}

impl ScenarioExplorationResult {
    /// Returns true if all explored seeds passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "scenario_id": self.scenario_id,
            "seeds_explored": self.seeds_explored,
            "passed": self.passed,
            "failed": self.failed,
            "unique_fingerprints": self.unique_fingerprints,
            "first_failure_seed": self.first_failure_seed,
            "runs": self.runs.iter().map(ExplorationRunSummary::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Summary of a single exploration run.
#[derive(Debug, Clone)]
pub struct ExplorationRunSummary {
    /// Seed used.
    pub seed: u64,
    /// Whether the run passed.
    pub passed: bool,
    /// Steps executed.
    pub steps: u64,
    /// Trace fingerprint.
    pub fingerprint: u64,
    /// Failure descriptions, if any.
    pub failures: Vec<String>,
}

impl ExplorationRunSummary {
    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "seed": self.seed,
            "passed": self.passed,
            "steps": self.steps,
            "fingerprint": self.fingerprint,
            "failures": self.failures,
        })
    }
}

// ---------------------------------------------------------------------------
// Participant bindings
// ---------------------------------------------------------------------------

/// Participant role bound to a task that sends values.
const SENDER_ROLE: &str = "sender";
/// Participant role bound to a task that drains a channel.
const RECEIVER_ROLE: &str = "receiver";
/// Values a sender produces when `properties.messages` is absent.
const DEFAULT_SENDER_MESSAGES: u64 = 16;
/// Channel capacity a receiver offers when `properties.capacity` is absent.
const DEFAULT_RECEIVER_CAPACITY: usize = 4;
/// Largest accepted `properties.capacity`; the channel preallocates its queue.
const MAX_RECEIVER_CAPACITY: usize = 4096;
/// Name of the implicit sink task in `workload:` diagnostics.
const IMPLICIT_SINK_NAME: &str = "<implicit-sink>";
/// Role label printed for a participant whose `role` is empty.
const EMPTY_ROLE_LABEL: &str = "<none>";

/// One declared participant and its role.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ParticipantBinding {
    /// Participant name from the scenario.
    pub name: String,
    /// Participant role from the scenario; empty when the role was omitted.
    pub role: String,
}

/// Which declared participants the scenario runner executes.
///
/// Participants whose role is one of [`Self::BOUND_ROLES`] (exact,
/// case-sensitive) run as lab tasks; every other participant is validated but
/// schedules no work. Both lists keep declaration order.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ParticipantBindings {
    /// Participants the runner spawns as lab tasks.
    pub bound: Vec<ParticipantBinding>,
    /// Participants the runner validates but does not execute.
    pub unbound: Vec<ParticipantBinding>,
    /// True when senders have no receiver, so the runner adds a sink task.
    pub implicit_sink: bool,
}

impl ParticipantBindings {
    /// Roles the runner binds to lab tasks.
    pub const BOUND_ROLES: &'static [&'static str] = &[SENDER_ROLE, RECEIVER_ROLE];

    /// Returns true when the scenario declares no participants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bound.is_empty() && self.unbound.is_empty()
    }

    /// One-line human summary, or `None` when no participants are declared.
    ///
    /// The line reads `Participants: X bound (roles), Y unbound (roles)`. Each
    /// role list names the distinct roles in declaration order and is left out
    /// when its count is zero; an empty role prints as `<none>`.
    #[must_use]
    pub fn summary_line(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        Some(format!(
            "Participants: {} bound{}, {} unbound{}",
            self.bound.len(),
            Self::role_list(&self.bound),
            self.unbound.len(),
            Self::role_list(&self.unbound),
        ))
    }

    fn role_list(entries: &[ParticipantBinding]) -> String {
        let mut roles: Vec<&str> = Vec::new();
        for entry in entries {
            let role = if entry.role.is_empty() {
                EMPTY_ROLE_LABEL
            } else {
                entry.role.as_str()
            };
            if !roles.contains(&role) {
                roles.push(role);
            }
        }
        if roles.is_empty() {
            String::new()
        } else {
            format!(" ({})", roles.join(", "))
        }
    }
}

/// Planned work for one bound participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedWork {
    /// Send this many values.
    Send { messages: u64 },
    /// Drain a channel with this capacity.
    Drain { capacity: usize },
}

/// One bound participant, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedParticipant {
    name: String,
    work: PlannedWork,
}

/// Validated workload for the bound participants of one scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WorkloadPlan {
    participants: Vec<PlannedParticipant>,
}

impl WorkloadPlan {
    /// Builds the plan, rejecting malformed properties of bound participants.
    fn from_scenario(scenario: &Scenario) -> Result<Self, Vec<ValidationError>> {
        let mut participants = Vec::new();
        let mut errors = Vec::new();
        for participant in &scenario.participants {
            let work = match participant.role.as_str() {
                SENDER_ROLE => Self::sender_messages(participant)
                    .map(|messages| PlannedWork::Send { messages }),
                RECEIVER_ROLE => Self::receiver_capacity(participant)
                    .map(|capacity| PlannedWork::Drain { capacity }),
                _ => continue,
            };
            match work {
                Ok(work) => participants.push(PlannedParticipant {
                    name: participant.name.clone(),
                    work,
                }),
                Err(error) => errors.push(error),
            }
        }
        if errors.is_empty() {
            Ok(Self { participants })
        } else {
            Err(errors)
        }
    }

    fn property_error(participant: &Participant, key: &str, message: String) -> ValidationError {
        ValidationError {
            field: format!("participants.{}.properties.{key}", participant.name),
            message,
        }
    }

    fn sender_messages(participant: &Participant) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get("messages") else {
            return Ok(DEFAULT_SENDER_MESSAGES);
        };
        value.as_u64().ok_or_else(|| {
            Self::property_error(
                participant,
                "messages",
                "a bound sender's message count must be a non-negative integer".to_owned(),
            )
        })
    }

    fn receiver_capacity(participant: &Participant) -> Result<usize, ValidationError> {
        let Some(value) = participant.properties.get("capacity") else {
            return Ok(DEFAULT_RECEIVER_CAPACITY);
        };
        value
            .as_u64()
            .and_then(|capacity| usize::try_from(capacity).ok())
            .filter(|capacity| (1..=MAX_RECEIVER_CAPACITY).contains(capacity))
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "capacity",
                    format!(
                        "a bound receiver's channel capacity must be an integer from 1 to {MAX_RECEIVER_CAPACITY}"
                    ),
                )
            })
    }
}

// ---------------------------------------------------------------------------
// Participant workload execution
// ---------------------------------------------------------------------------

/// A value sent by a bound sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkloadMessage {
    /// Index of the producing sender among the bound senders.
    sender: usize,
    /// The sender's sequence number for this value, starting at zero.
    seq: u64,
}

/// What a bound task does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkloadRole {
    Sender,
    Receiver,
    Sink,
}

impl WorkloadRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Sender => SENDER_ROLE,
            Self::Receiver => RECEIVER_ROLE,
            Self::Sink => "sink",
        }
    }
}

/// Counters one bound task updates while it runs.
///
/// The lab polls every task on the thread that drives it, so relaxed atomics
/// are enough; they exist only because task futures must be `Send`.
#[derive(Debug, Default)]
struct WorkloadCounters {
    /// Sender: values committed through a reserved permit.
    committed: AtomicU64,
    /// Drain: values any sender committed into this task's channel.
    delivered: AtomicU64,
    /// Drain: values received.
    received: AtomicU64,
    /// Reserves or receives that ended in cancellation.
    cancelled: AtomicU64,
    /// Sender: reserves or sends that found the receiving end gone.
    disconnected: AtomicU64,
    /// Drain: values that arrived out of their sender's order.
    out_of_order: AtomicU64,
    /// Outcomes the channel contract rules out, or a missing task context.
    unexpected: AtomicU64,
    /// Drain: the receive loop ended because every sender was gone.
    drained_to_close: AtomicBool,
    /// The task body ran to its end.
    finished: AtomicBool,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn count(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn flag(value: &AtomicBool) -> u8 {
    u8::from(value.load(Ordering::Relaxed))
}

/// The sending half of one drain task's channel.
#[derive(Debug, Clone)]
struct WorkloadLane {
    tx: mpsc::Sender<WorkloadMessage>,
    /// Counters of the task that drains this channel.
    drain: Arc<WorkloadCounters>,
}

/// One bound task and its counters.
#[derive(Debug)]
struct BoundTask {
    name: String,
    role: WorkloadRole,
    /// Values the task was planned to send (zero for drains).
    planned: u64,
    /// Why the runtime refused to spawn the task, if it did.
    spawn_refusal: Option<String>,
    counters: Arc<WorkloadCounters>,
}

impl BoundTask {
    fn counter_summary(&self) -> String {
        let c = &self.counters;
        format!(
            "planned={},committed={},delivered={},received={},cancelled={},disconnected={},out_of_order={},unexpected={},drained_to_close={},finished={}",
            self.planned,
            count(&c.committed),
            count(&c.delivered),
            count(&c.received),
            count(&c.cancelled),
            count(&c.disconnected),
            count(&c.out_of_order),
            count(&c.unexpected),
            flag(&c.drained_to_close),
            flag(&c.finished),
        )
    }

    /// Appends one `workload:` violation per anomaly this task observed.
    fn collect_violations(&self, violations: &mut Vec<String>) {
        let label = format!("workload:{}:{}", self.role.label(), self.name);
        if let Some(refusal) = &self.spawn_refusal {
            violations.push(format!("{label}:spawn_refused:{refusal}"));
            return;
        }
        let c = &self.counters;
        if count(&c.unexpected) > 0 {
            violations.push(format!(
                "{label}:unexpected_outcome:{}",
                self.counter_summary()
            ));
        }
        if count(&c.out_of_order) > 0 {
            violations.push(format!("{label}:fifo_violation:{}", self.counter_summary()));
        }
        if c.drained_to_close.load(Ordering::Relaxed) && count(&c.received) != count(&c.delivered) {
            violations.push(format!("{label}:lost_values:{}", self.counter_summary()));
        }
    }
}

/// The bound participant tasks of one run.
#[derive(Debug, Default)]
struct ParticipantWorkload {
    tasks: Vec<BoundTask>,
    /// Join handles, held until the run is reported.
    handles: Vec<TaskHandle<()>>,
}

/// Work a bound participant was given before its task is spawned.
enum Endpoint {
    Send { messages: u64 },
    Drain { rx: mpsc::Receiver<WorkloadMessage> },
}

impl ParticipantWorkload {
    /// Spawns the planned tasks in a new root region and schedules them.
    ///
    /// An empty plan spawns nothing and creates no region, so a scenario
    /// without bound participants keeps the empty-lab trace it always had.
    fn spawn(runtime: &mut LabRuntime, plan: &WorkloadPlan) -> Self {
        let mut workload = Self::default();
        if plan.participants.is_empty() {
            return workload;
        }
        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Pass 1: a counter set per participant and a channel per receiver,
        // so that every sender sees the full lane list.
        let counters: Vec<Arc<WorkloadCounters>> = plan
            .participants
            .iter()
            .map(|_| Arc::new(WorkloadCounters::default()))
            .collect();
        let mut lanes = Vec::new();
        let mut endpoints = Vec::with_capacity(plan.participants.len());
        let mut sender_total = 0_usize;
        for (participant, participant_counters) in plan.participants.iter().zip(&counters) {
            match participant.work {
                PlannedWork::Send { messages } => {
                    sender_total += 1;
                    endpoints.push(Endpoint::Send { messages });
                }
                PlannedWork::Drain { capacity } => {
                    let (tx, rx) = mpsc::channel(capacity);
                    lanes.push(WorkloadLane {
                        tx,
                        drain: Arc::clone(participant_counters),
                    });
                    endpoints.push(Endpoint::Drain { rx });
                }
            }
        }
        let sink = if lanes.is_empty() && sender_total > 0 {
            let drain = Arc::new(WorkloadCounters::default());
            let (tx, rx) = mpsc::channel(DEFAULT_RECEIVER_CAPACITY);
            lanes.push(WorkloadLane {
                tx,
                drain: Arc::clone(&drain),
            });
            Some((rx, drain))
        } else {
            None
        };

        // Pass 2: spawn in declaration order, then the sink.
        let mut sender_index = 0_usize;
        for ((participant, endpoint), task_counters) in
            plan.participants.iter().zip(endpoints).zip(counters)
        {
            match endpoint {
                Endpoint::Send { messages } => {
                    let body = run_sender(
                        lanes.clone(),
                        sender_index,
                        messages,
                        Arc::clone(&task_counters),
                    );
                    sender_index += 1;
                    workload.spawn_task(
                        runtime,
                        root,
                        &participant.name,
                        WorkloadRole::Sender,
                        messages,
                        task_counters,
                        body,
                    );
                }
                Endpoint::Drain { rx } => {
                    let body = run_drain(rx, sender_total, Arc::clone(&task_counters));
                    workload.spawn_task(
                        runtime,
                        root,
                        &participant.name,
                        WorkloadRole::Receiver,
                        0,
                        task_counters,
                        body,
                    );
                }
            }
        }
        if let Some((rx, drain)) = sink {
            let body = run_drain(rx, sender_total, Arc::clone(&drain));
            workload.spawn_task(
                runtime,
                root,
                IMPLICIT_SINK_NAME,
                WorkloadRole::Sink,
                0,
                drain,
                body,
            );
        }
        // Release the spawner's own senders: once every sender task ends, the
        // drain tasks see their channels close.
        drop(lanes);
        workload
    }

    fn spawn_task<F>(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        role: WorkloadRole,
        planned: u64,
        counters: Arc<WorkloadCounters>,
        body: F,
    ) where
        F: Future<Output = ()> + Send + 'static,
    {
        let spawn_refusal = match runtime.state.create_task(root, Budget::INFINITE, body) {
            Ok((task, handle)) => {
                runtime.scheduler.lock().schedule(task, 0);
                self.handles.push(handle);
                None
            }
            Err(error) => Some(error.to_string()),
        };
        self.tasks.push(BoundTask {
            name: name.to_owned(),
            role,
            planned,
            spawn_refusal,
            counters,
        });
    }

    /// Releases the join handles and appends `workload:` violations.
    ///
    /// Returns the task records so callers can inspect the counters.
    fn finish(self, violations: &mut Vec<String>) -> Vec<BoundTask> {
        for task in &self.tasks {
            task.collect_violations(violations);
        }
        violations.sort();
        violations.dedup();
        drop(self.handles);
        self.tasks
    }
}

/// Body of a bound `sender` task.
///
/// Value `seq` goes to lane `(sender + seq) % lanes`, so senders start on
/// different receivers and then rotate through all of them.
async fn run_sender(
    lanes: Vec<WorkloadLane>,
    sender: usize,
    messages: u64,
    counters: Arc<WorkloadCounters>,
) {
    match Cx::current() {
        Some(cx) if !lanes.is_empty() => {
            let mut lane = sender % lanes.len();
            for seq in 0..messages {
                let WorkloadLane { tx, drain } = &lanes[lane];
                lane = (lane + 1) % lanes.len();
                let message = WorkloadMessage { sender, seq };
                // Two-phase send: the permit is a runtime obligation from the
                // reserve until `send` commits it.
                let stop = match tx.reserve(&cx).await {
                    Ok(permit) => match permit.send(message) {
                        Outcome::Ok(()) => {
                            bump(&counters.committed);
                            bump(&drain.delivered);
                            false
                        }
                        Outcome::Err(SendError::Disconnected(_)) => {
                            bump(&counters.disconnected);
                            false
                        }
                        Outcome::Err(SendError::Cancelled(_)) | Outcome::Cancelled(_) => {
                            bump(&counters.cancelled);
                            true
                        }
                        Outcome::Err(SendError::Full(_)) | Outcome::Panicked(_) => {
                            bump(&counters.unexpected);
                            false
                        }
                    },
                    Err(SendError::Cancelled(())) => {
                        bump(&counters.cancelled);
                        true
                    }
                    Err(SendError::Disconnected(())) => {
                        bump(&counters.disconnected);
                        false
                    }
                    Err(SendError::Full(())) => {
                        bump(&counters.unexpected);
                        false
                    }
                };
                if stop {
                    break;
                }
            }
        }
        // A bound task always runs with a task context and at least one lane.
        _ => bump(&counters.unexpected),
    }
    counters.finished.store(true, Ordering::Relaxed);
}

/// Body of a bound `receiver` task or the implicit sink.
async fn run_drain(
    mut rx: mpsc::Receiver<WorkloadMessage>,
    sender_total: usize,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        let mut last_seq: Vec<Option<u64>> = vec![None; sender_total];
        loop {
            match rx.recv(&cx).await {
                Ok(message) => {
                    bump(&counters.received);
                    if let Some(last) = last_seq.get_mut(message.sender) {
                        if last.is_some_and(|previous| message.seq <= previous) {
                            bump(&counters.out_of_order);
                        }
                        *last = Some(message.seq);
                    } else {
                        bump(&counters.unexpected);
                    }
                }
                Err(RecvError::Disconnected) => {
                    counters.drained_to_close.store(true, Ordering::Relaxed);
                    break;
                }
                Err(RecvError::Cancelled) => {
                    bump(&counters.cancelled);
                    break;
                }
                Err(RecvError::Empty) => {
                    bump(&counters.unexpected);
                    break;
                }
            }
        }
    } else {
        bump(&counters.unexpected);
    }
    counters.finished.store(true, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// ScenarioRunner
// ---------------------------------------------------------------------------

/// Execution engine for FrankenLab scenarios.
///
/// Bridges [`Scenario`] YAML specifications to deterministic runtime execution.
pub struct ScenarioRunner;

impl ScenarioRunner {
    fn scenario_surface_id(scenario: &Scenario) -> String {
        scenario
            .metadata
            .get("surface_id")
            .cloned()
            .unwrap_or_else(|| scenario.id.clone())
    }

    fn scenario_surface_contract_version(scenario: &Scenario) -> String {
        scenario
            .metadata
            .get("surface_contract_version")
            .cloned()
            .unwrap_or_else(|| format!("{}.v1", scenario.id))
    }

    fn scenario_seed_lineage_id(scenario: &Scenario) -> String {
        scenario
            .metadata
            .get("seed_lineage_id")
            .cloned()
            .unwrap_or_else(|| format!("seed.{}.v1", scenario.id))
    }

    fn scenario_identity(
        scenario: &Scenario,
        seed_override: Option<u64>,
    ) -> DualRunScenarioIdentity {
        let description = if scenario.description.trim().is_empty() {
            format!("Scenario {}", scenario.id)
        } else {
            scenario.description.clone()
        };
        let mut identity = DualRunScenarioIdentity::phase1(
            &scenario.id,
            Self::scenario_surface_id(scenario),
            Self::scenario_surface_contract_version(scenario),
            description,
            scenario.lab.seed,
        );
        let mut seed_plan = identity.seed_plan.clone();
        seed_plan.seed_lineage_id = Self::scenario_seed_lineage_id(scenario);
        if let Some(seed) = seed_override {
            seed_plan = seed_plan.with_lab_override(seed);
        }
        if let Some(entropy_seed) = scenario.lab.entropy_seed {
            seed_plan = seed_plan.with_entropy_seed(entropy_seed);
        }
        identity = identity.with_seed_plan(seed_plan);
        for (key, value) in &scenario.metadata {
            identity = identity.with_metadata(key.clone(), value.clone());
        }
        identity
    }

    fn replay_metadata_for_run(
        identity: &DualRunScenarioIdentity,
        lab_report: &LabRunReport,
    ) -> ReplayMetadata {
        identity
            .lab_replay_metadata()
            .with_lab_report(
                lab_report.trace_fingerprint,
                lab_report.trace_certificate.event_hash,
                lab_report.trace_certificate.event_count,
                lab_report.trace_certificate.schedule_hash,
                lab_report.steps_total,
            )
            .with_repro_command(format!(
                "ASUPERSYNC_SEED=0x{:X} rch exec -- cargo test {} -- --nocapture",
                lab_report.seed, identity.scenario_id
            ))
    }

    fn validation_error(scenario: &Scenario, errors: Vec<ValidationError>) -> ScenarioRunnerError {
        ScenarioRunnerError::Validation {
            scenario_id: scenario.id.clone(),
            errors,
        }
    }

    /// Validate oracle names in a scenario against the known oracle registry.
    fn validate_oracle_names(scenario: &Scenario) -> Result<(), ScenarioRunnerError> {
        OracleRegistry::validate_reported_selection(&scenario.oracles)
            .map_err(|err| ScenarioRunnerError::UnknownOracle(err.name().to_owned()))
    }

    /// Build the participant workload, rejecting malformed bound properties.
    fn workload_plan(scenario: &Scenario) -> Result<WorkloadPlan, ScenarioRunnerError> {
        WorkloadPlan::from_scenario(scenario)
            .map_err(|errors| Self::validation_error(scenario, errors))
    }

    /// Classify the scenario's participants into bound and unbound roles.
    ///
    /// This is a pure function of the scenario. It does not check the
    /// `messages` and `capacity` properties of bound participants; a run
    /// rejects malformed values as a validation error.
    #[must_use]
    pub fn participant_bindings(scenario: &Scenario) -> ParticipantBindings {
        let mut bindings = ParticipantBindings::default();
        let mut has_sender = false;
        let mut has_receiver = false;
        for participant in &scenario.participants {
            let binding = ParticipantBinding {
                name: participant.name.clone(),
                role: participant.role.clone(),
            };
            match participant.role.as_str() {
                SENDER_ROLE => {
                    has_sender = true;
                    bindings.bound.push(binding);
                }
                RECEIVER_ROLE => {
                    has_receiver = true;
                    bindings.bound.push(binding);
                }
                _ => bindings.unbound.push(binding),
            }
        }
        bindings.implicit_sink = has_sender && !has_receiver;
        bindings
    }

    /// Create a `LabConfig` from a scenario, always enabling replay recording.
    fn lab_config_for(scenario: &Scenario, seed_override: Option<u64>) -> LabConfig {
        let config = seed_override.map_or_else(
            || scenario.to_lab_config(),
            |seed| {
                let mut modified = scenario.clone();
                modified.lab.seed = seed;
                modified.to_lab_config()
            },
        );
        // Always enable replay recording so we get trace certificates
        config.with_default_replay_recording()
    }

    /// Create a `LabConfig` from a scenario plus an explicit dual-run identity.
    fn lab_config_for_identity(
        scenario: &Scenario,
        identity: &DualRunScenarioIdentity,
    ) -> LabConfig {
        let mut config = scenario.to_lab_config();
        let effective_seed = identity.seed_plan.effective_lab_seed();
        config.seed = effective_seed;
        config.entropy_seed = identity.seed_plan.effective_entropy_seed(effective_seed);
        config.with_default_replay_recording()
    }

    /// Inject timed fault events into the runtime.
    ///
    /// Processes faults in `at_ms` order, advancing virtual time and injecting
    /// each fault action. Between faults, the runtime runs to idle.
    fn inject_faults(
        runtime: &mut LabRuntime,
        scenario: &Scenario,
    ) -> (Vec<FaultInjectionLogEntry>, FaultEffectSummary) {
        let mut fault_log = Vec::with_capacity(scenario.faults.len());
        let mut fault_effect_summary = FaultEffectSummary::default();

        for fault in &scenario.faults {
            // Advance time to the fault trigger point
            let target_nanos = fault.at_ms.saturating_mul(1_000_000);
            let target_time = Time::from_nanos(target_nanos);
            if target_time > runtime.now() {
                let delta_nanos = target_time.as_nanos() - runtime.now().as_nanos();
                runtime.advance_time(delta_nanos);
            }

            // Run to idle so pending tasks respond to the current state
            runtime.run_until_idle();

            // Record the fault as a user_trace event
            let action_name = match fault.action {
                FaultAction::Partition => "partition",
                FaultAction::Heal => "heal",
                FaultAction::DiskPressure => "disk_pressure",
                FaultAction::DiskRecovered => "disk_recovered",
                FaultAction::DelayedCleanup => "delayed_cleanup",
                FaultAction::ProcessStall => "process_stall",
                FaultAction::ProcessResume => "process_resume",
                FaultAction::HostCrash => "host_crash",
                FaultAction::HostRestart => "host_restart",
                FaultAction::ClockSkew => "clock_skew",
                FaultAction::ClockReset => "clock_reset",
            };
            let args_summary = Self::fault_args_summary(&fault.args);
            let trace_message = format!("fault:{action_name}:{args_summary}");
            let now = runtime.now();
            let trace_message_for_event = trace_message.clone();
            runtime.state.record_trace_event(|seq| {
                crate::trace::TraceEvent::user_trace(seq, now, trace_message_for_event)
            });
            fault_log.push(FaultInjectionLogEntry {
                at_ms: fault.at_ms,
                action: action_name.to_string(),
                args_summary,
                trace_message,
            });
            fault_effect_summary.apply_fault(fault, scenario.resource_caps.max_artifact_bytes);
        }

        (fault_log, fault_effect_summary)
    }

    /// Summarize fault args for trace events.
    fn fault_args_summary(args: &BTreeMap<String, serde_json::Value>) -> String {
        let mut summary = String::new();
        for (index, (key, value)) in args.iter().enumerate() {
            if index > 0 {
                summary.push(',');
            }
            summary.push_str(key);
            summary.push('=');
            match value {
                serde_json::Value::String(s) => summary.push_str(s),
                other => {
                    let _ = write!(&mut summary, "{other}");
                }
            }
        }
        summary
    }

    fn minimized_counterexample_for(
        scenario: &Scenario,
        fault_log: &[FaultInjectionLogEntry],
        fault_effect_summary: &FaultEffectSummary,
    ) -> Option<MinimizedCounterexamplePacket> {
        if !scenario.minimization.enabled
            || fault_effect_summary
                .stalled_participants_until_ms
                .is_empty()
        {
            return None;
        }

        let active_stalled_participants = fault_effect_summary
            .stalled_participants_until_ms
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let first_stall_index = fault_log.iter().enumerate().find_map(|(index, entry)| {
            if entry.action != "process_stall" {
                return None;
            }
            let host_is_still_stalled = entry.args_summary.split(',').any(|arg| {
                arg.strip_prefix("host=").is_some_and(|host| {
                    fault_effect_summary
                        .stalled_participants_until_ms
                        .contains_key(host)
                })
            });
            host_is_still_stalled.then_some(index)
        })?;
        let max_counterexample_events = scenario
            .minimization
            .max_counterexample_events
            .or(scenario.resource_caps.max_counterexample_events)
            .unwrap_or(fault_log.len())
            .max(1);
        let required_prefix_len = first_stall_index.saturating_add(1).min(fault_log.len());
        let retained_len = required_prefix_len.min(max_counterexample_events);
        let retained_start = required_prefix_len.saturating_sub(retained_len);
        let fault_log_prefix = fault_log
            .iter()
            .skip(retained_start)
            .take(retained_len)
            .cloned()
            .collect::<Vec<_>>();
        let prefix_len = fault_log_prefix.len();

        Some(MinimizedCounterexamplePacket {
            scenario_id: scenario.id.clone(),
            reason: "unresolved_process_stall".to_string(),
            prefix_len,
            fault_count: fault_log.len(),
            max_counterexample_events,
            active_stalled_participants,
            fault_log_prefix,
            redacted: scenario.golden_projection.redacted,
        })
    }

    /// Build a certificate snapshot from a lab report.
    fn certificate_snapshot(report: &LabRunReport) -> TraceCertificateSnapshot {
        TraceCertificateSnapshot {
            event_hash: report.trace_certificate.event_hash,
            schedule_hash: report.trace_certificate.schedule_hash,
            steps: report.steps_total,
            trace_fingerprint: report.trace_fingerprint,
        }
    }

    /// Run a scenario with the default seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn run(scenario: &Scenario) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        Self::run_with_seed(scenario, None)
    }

    /// Run a scenario using an explicit dual-run identity and seed plan.
    ///
    /// This keeps scenario-family metadata stable while allowing the concrete
    /// lab execution seed to vary via the identity's seed plan.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn run_with_identity(
        scenario: &Scenario,
        identity: &DualRunScenarioIdentity,
    ) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(Self::validation_error(scenario, errors));
        }
        Self::validate_oracle_names(scenario)?;
        let plan = Self::workload_plan(scenario)?;

        let effective_seed = identity.seed_plan.effective_lab_seed();
        let config = Self::lab_config_for_identity(scenario, identity);
        let mut runtime = LabRuntime::new(config);
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan);

        let (fault_log, fault_effect_summary) = Self::inject_faults(&mut runtime, scenario);
        let faults_injected = fault_log.len();
        let minimized_counterexample =
            Self::minimized_counterexample_for(scenario, &fault_log, &fault_effect_summary);
        runtime.run_until_quiescent();

        let mut lab_report = runtime.report();
        workload.finish(&mut lab_report.invariant_violations);
        let certificate = Self::certificate_snapshot(&lab_report);
        let replay_metadata = Self::replay_metadata_for_run(identity, &lab_report);
        let seed_lineage = identity.seed_lineage();
        let oracle_report = FilteredOracleReport::from_full(
            lab_report.oracle_report.clone(),
            &scenario.oracles,
            &runtime.config().oracle_selection,
        );
        let replay_trace = runtime.finish_replay_trace();

        Ok(ScenarioRunResult {
            scenario_id: scenario.id.clone(),
            seed: effective_seed,
            lab_report,
            oracle_report,
            faults_injected,
            fault_log,
            fault_effect_summary,
            minimized_counterexample,
            replay_trace,
            certificate,
            adapter: LAB_SCENARIO_RUNNER_ADAPTER.to_string(),
            replay_metadata,
            seed_lineage,
        })
    }

    /// Run a scenario, optionally overriding the seed.
    ///
    /// Bound participants run as lab tasks (see the module docs). A malformed
    /// `messages` or `capacity` property on one of them is a validation error.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn run_with_seed(
        scenario: &Scenario,
        seed_override: Option<u64>,
    ) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        Self::run_seeded(scenario, seed_override).map(|(result, _tasks)| result)
    }

    /// [`Self::run_with_seed`], also returning the bound tasks' records.
    fn run_seeded(
        scenario: &Scenario,
        seed_override: Option<u64>,
    ) -> Result<(ScenarioRunResult, Vec<BoundTask>), ScenarioRunnerError> {
        // 1. Validate
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(Self::validation_error(scenario, errors));
        }
        Self::validate_oracle_names(scenario)?;
        let plan = Self::workload_plan(scenario)?;

        // 2. Build runtime and spawn the bound participants
        let effective_seed = seed_override.unwrap_or(scenario.lab.seed);
        let config = Self::lab_config_for(scenario, seed_override);
        let mut runtime = LabRuntime::new(config);
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan);

        // 3. Inject timed faults and run between them
        let (fault_log, fault_effect_summary) = Self::inject_faults(&mut runtime, scenario);
        let faults_injected = fault_log.len();
        let minimized_counterexample =
            Self::minimized_counterexample_for(scenario, &fault_log, &fault_effect_summary);

        // 4. Run to quiescence after all faults
        runtime.run_until_quiescent();

        // 5. Collect report, folding in workload anomalies
        let mut lab_report = runtime.report();
        let tasks = workload.finish(&mut lab_report.invariant_violations);
        let certificate = Self::certificate_snapshot(&lab_report);
        let identity = Self::scenario_identity(scenario, seed_override);
        let replay_metadata = Self::replay_metadata_for_run(&identity, &lab_report);
        let seed_lineage = identity.seed_lineage();

        // 6. Filter oracle results
        let oracle_report = FilteredOracleReport::from_full(
            lab_report.oracle_report.clone(),
            &scenario.oracles,
            &runtime.config().oracle_selection,
        );

        // 7. Extract replay trace
        let replay_trace = runtime.finish_replay_trace();

        let result = ScenarioRunResult {
            scenario_id: scenario.id.clone(),
            seed: effective_seed,
            lab_report,
            oracle_report,
            faults_injected,
            fault_log,
            fault_effect_summary,
            minimized_counterexample,
            replay_trace,
            certificate,
            adapter: LAB_SCENARIO_RUNNER_ADAPTER.to_string(),
            replay_metadata,
            seed_lineage,
        };
        Ok((result, tasks))
    }

    /// Explore a scenario across a range of seeds.
    ///
    /// Runs the scenario once per seed in `seed_start..seed_start+count` and
    /// collects results. Useful for finding schedule-dependent bugs.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn explore_seeds(
        scenario: &Scenario,
        seed_start: u64,
        count: usize,
    ) -> Result<ScenarioExplorationResult, ScenarioRunnerError> {
        // Validate once up front
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(Self::validation_error(scenario, errors));
        }
        Self::validate_oracle_names(scenario)?;

        let mut runs = Vec::with_capacity(count);
        let mut fingerprint_set = std::collections::HashSet::new();
        let mut first_failure_seed = None;

        for i in 0..count {
            let seed = seed_start.wrapping_add(i as u64);
            // Run with this seed (skip validation since we already validated)
            let result = Self::run_with_seed(scenario, Some(seed))?;

            fingerprint_set.insert(result.certificate.trace_fingerprint);

            let passed = result.passed();
            let failures: Vec<String> = if passed {
                Vec::new()
            } else {
                let mut f: Vec<String> = result
                    .oracle_report
                    .entries
                    .iter()
                    .filter(|e| !e.passed)
                    .map(|e| {
                        format!(
                            "{}: {}",
                            e.invariant,
                            e.violation.as_deref().unwrap_or("failed")
                        )
                    })
                    .collect();
                f.extend(result.lab_report.invariant_violations.clone());
                if !result.lab_report.quiescent {
                    f.push("runtime not quiescent at report boundary".to_string());
                }
                f
            };

            if !passed && first_failure_seed.is_none() {
                first_failure_seed = Some(seed);
            }

            runs.push(ExplorationRunSummary {
                seed,
                passed,
                steps: result.lab_report.steps_total,
                fingerprint: result.certificate.trace_fingerprint,
                failures,
            });
        }

        let passed = runs.iter().filter(|r| r.passed).count();
        let failed = runs.len() - passed;

        Ok(ScenarioExplorationResult {
            scenario_id: scenario.id.clone(),
            seeds_explored: count,
            passed,
            failed,
            unique_fingerprints: fingerprint_set.len(),
            runs,
            first_failure_seed,
        })
    }

    /// Validate replay determinism: run a scenario twice with the same seed
    /// and verify identical trace certificates.
    ///
    /// # Errors
    ///
    /// Returns `ReplayDivergence` if the two runs produce different certificates.
    pub fn validate_replay(scenario: &Scenario) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        let first = Self::run(scenario)?;
        let second = Self::run(scenario)?;

        if first.certificate != second.certificate {
            return Err(ScenarioRunnerError::ReplayDivergence {
                seed: first.seed,
                first: first.certificate,
                second: second.certificate,
            });
        }

        Ok(first)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::scenario::{
        ChaosSection, FaultAction, FaultEvent, LabSection, MinimizationSection, NetworkSection,
        Scenario,
    };
    use std::collections::BTreeMap;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn minimal_scenario() -> Scenario {
        Scenario {
            schema_version: 1,
            id: "test-minimal".to_string(),
            description: "Minimal test scenario".to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            ..Scenario::default()
        }
    }

    #[test]
    fn run_minimal_scenario() {
        init_test("run_minimal_scenario");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed(), "minimal scenario should pass");
        assert_eq!(result.scenario_id, "test-minimal");
        assert_eq!(result.seed, 42);
        assert_eq!(result.faults_injected, 0);
        assert_eq!(result.adapter, LAB_SCENARIO_RUNNER_ADAPTER);
        assert_eq!(result.replay_metadata.family.surface_id, "test-minimal");
        assert_eq!(
            result.replay_metadata.family.surface_contract_version,
            "test-minimal.v1"
        );
        assert_eq!(result.seed_lineage.seed_lineage_id, "seed.test-minimal.v1");
        crate::test_complete!("run_minimal_scenario");
    }

    #[test]
    fn run_with_seed_preserves_family_and_tracks_execution_seed() {
        init_test("run_with_seed_preserves_family_and_tracks_execution_seed");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run_with_seed(&scenario, Some(7)).unwrap();

        assert_eq!(result.seed, 7);
        assert_eq!(result.replay_metadata.family.id, "test-minimal");
        assert_eq!(result.replay_metadata.effective_seed, 7);
        assert_eq!(result.seed_lineage.canonical_seed, 42);
        assert_eq!(result.seed_lineage.lab_effective_seed, 7);

        crate::test_complete!("run_with_seed_preserves_family_and_tracks_execution_seed");
    }

    #[test]
    fn passed_requires_quiescence() {
        init_test("passed_requires_quiescence");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());

        let mut forced_non_quiescent = result;
        forced_non_quiescent.lab_report.quiescent = false;
        assert!(!forced_non_quiescent.passed());
        crate::test_complete!("passed_requires_quiescence");
    }

    #[test]
    fn run_with_seed_override() {
        init_test("run_with_seed_override");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run_with_seed(&scenario, Some(123)).unwrap();
        assert_eq!(result.seed, 123);
        assert!(result.passed());
        crate::test_complete!("run_with_seed_override");
    }

    #[test]
    fn run_with_faults() {
        init_test("run_with_faults");
        let mut scenario = minimal_scenario();
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::Heal,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 2);
        crate::test_complete!("run_with_faults");
    }

    #[test]
    fn run_with_all_fault_types() {
        init_test("run_with_all_fault_types");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            crate::lab::scenario::Participant {
                name: "alice".to_string(),
                role: "sender".to_string(),
                properties: BTreeMap::new(),
            },
            crate::lab::scenario::Participant {
                name: "bob".to_string(),
                role: "receiver".to_string(),
                properties: BTreeMap::new(),
            },
        ];
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 20,
                action: FaultAction::Heal,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 30,
                action: FaultAction::DiskPressure,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m.insert("bytes".into(), serde_json::json!(4096));
                    m
                },
            },
            FaultEvent {
                at_ms: 40,
                action: FaultAction::DiskRecovered,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m
                },
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::DelayedCleanup,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("phase".into(), serde_json::json!("finalizers"));
                    m.insert("delay_ms".into(), serde_json::json!(25));
                    m
                },
            },
            FaultEvent {
                at_ms: 60,
                action: FaultAction::ProcessStall,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("duration_ms".into(), serde_json::json!(40));
                    m
                },
            },
            FaultEvent {
                at_ms: 70,
                action: FaultAction::ProcessResume,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m
                },
            },
            FaultEvent {
                at_ms: 80,
                action: FaultAction::HostCrash,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 90,
                action: FaultAction::HostRestart,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 100,
                action: FaultAction::ClockSkew,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("skew_ms".into(), serde_json::json!(5));
                    m
                },
            },
            FaultEvent {
                at_ms: 110,
                action: FaultAction::ClockReset,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m
                },
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 11);
        crate::test_complete!("run_with_all_fault_types");
    }

    #[test]
    fn process_stall_counterexample_keeps_causal_event_under_small_cap() {
        init_test("process_stall_counterexample_keeps_causal_event_under_small_cap");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![crate::lab::scenario::Participant {
            name: "alice".to_string(),
            role: "worker".to_string(),
            properties: BTreeMap::new(),
        }];
        scenario.minimization = MinimizationSection {
            enabled: true,
            max_evaluations: Some(4),
            max_counterexample_events: Some(1),
        };
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::DiskPressure,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("path".into(), serde_json::json!("target/proof"));
                    m.insert("bytes".into(), serde_json::json!(4096));
                    m
                },
            },
            FaultEvent {
                at_ms: 20,
                action: FaultAction::DelayedCleanup,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("phase".into(), serde_json::json!("finalizers"));
                    m.insert("delay_ms".into(), serde_json::json!(25));
                    m
                },
            },
            FaultEvent {
                at_ms: 30,
                action: FaultAction::ProcessStall,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("host".into(), serde_json::json!("alice"));
                    m.insert("duration_ms".into(), serde_json::json!(1_000));
                    m
                },
            },
        ];

        let result = ScenarioRunner::run(&scenario).unwrap();
        let counterexample = result
            .minimized_counterexample
            .expect("active process stall should emit a counterexample");

        assert_eq!(counterexample.max_counterexample_events, 1);
        assert_eq!(counterexample.prefix_len, 1);
        assert_eq!(counterexample.fault_log_prefix.len(), 1);
        let retained = &counterexample.fault_log_prefix[0];
        assert_eq!(retained.action, "process_stall");
        assert!(
            retained
                .args_summary
                .split(',')
                .any(|arg| arg == "host=alice"),
            "counterexample must retain the causal stalled host"
        );
        crate::test_complete!("process_stall_counterexample_keeps_causal_event_under_small_cap");
    }

    #[test]
    fn validation_rejects_bad_scenario() {
        init_test("validation_rejects_bad_scenario");
        let mut scenario = minimal_scenario();
        scenario.id = String::new(); // invalid
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::Validation { .. }
        ));
        crate::test_complete!("validation_rejects_bad_scenario");
    }

    #[test]
    fn unknown_oracle_rejected() {
        init_test("unknown_oracle_rejected");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["nonexistent_oracle".to_string()];
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::UnknownOracle(_)
        ));
        crate::test_complete!("unknown_oracle_rejected");
    }

    #[test]
    fn oracle_filtering_works() {
        init_test("oracle_filtering_works");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["task_leak".to_string(), "obligation_leak".to_string()];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(result.oracle_report.checked.len(), 2);
        assert!(
            result
                .oracle_report
                .checked
                .contains(&"task_leak".to_string())
        );
        assert!(
            result
                .oracle_report
                .checked
                .contains(&"obligation_leak".to_string())
        );
        crate::test_complete!("oracle_filtering_works");
    }

    #[test]
    fn oracle_all_checks_everything() {
        init_test("oracle_all_checks_everything");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        // "all" should check every oracle
        assert_eq!(
            result.oracle_report.checked.len(),
            OracleRegistry::reported_names().len()
        );
        crate::test_complete!("oracle_all_checks_everything");
    }

    #[test]
    fn replay_determinism() {
        init_test("replay_determinism");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::validate_replay(&scenario).unwrap();
        assert!(result.passed());
        crate::test_complete!("replay_determinism");
    }

    #[test]
    fn explore_seeds_basic() {
        init_test("explore_seeds_basic");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 5).unwrap();
        assert_eq!(result.seeds_explored, 5);
        assert_eq!(result.passed, 5);
        assert_eq!(result.failed, 0);
        assert!(result.all_passed());
        assert!(result.unique_fingerprints >= 1);
        crate::test_complete!("explore_seeds_basic");
    }

    #[test]
    fn explore_seeds_reports_each_run() {
        init_test("explore_seeds_reports_each_run");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 100, 3).unwrap();
        assert_eq!(result.runs.len(), 3);
        assert_eq!(result.runs[0].seed, 100);
        assert_eq!(result.runs[1].seed, 101);
        assert_eq!(result.runs[2].seed, 102);
        crate::test_complete!("explore_seeds_reports_each_run");
    }

    #[test]
    fn result_to_json_roundtrip() {
        init_test("result_to_json_roundtrip");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        let json = result.to_json();
        assert_eq!(json["scenario_id"], "test-minimal");
        assert_eq!(json["seed"], 42);
        assert!(json["passed"].as_bool().unwrap());
        assert!(json["certificate"]["event_hash"].is_u64());
        crate::test_complete!("result_to_json_roundtrip");
    }

    #[test]
    fn exploration_to_json() {
        init_test("exploration_to_json");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 2).unwrap();
        let json = result.to_json();
        assert_eq!(json["seeds_explored"], 2);
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"].as_array().unwrap().len(), 2);
        crate::test_complete!("exploration_to_json");
    }

    #[test]
    fn replay_trace_available_when_enabled() {
        init_test("replay_trace_available_when_enabled");
        let mut scenario = minimal_scenario();
        scenario.lab.replay_recording = true;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // ScenarioRunner always enables replay recording
        assert!(result.replay_trace.is_some());
        crate::test_complete!("replay_trace_available_when_enabled");
    }

    #[test]
    fn certificates_stable_across_runs() {
        init_test("certificates_stable_across_runs");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run(&scenario).unwrap();
        let r2 = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(r1.certificate, r2.certificate);
        crate::test_complete!("certificates_stable_across_runs");
    }

    #[test]
    fn different_seeds_may_differ() {
        init_test("different_seeds_may_differ");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run_with_seed(&scenario, Some(1)).unwrap();
        let r2 = ScenarioRunner::run_with_seed(&scenario, Some(2)).unwrap();
        // Seeds 1 and 2 should both pass (empty scenario)
        assert!(r1.passed());
        assert!(r2.passed());
        // They may or may not have the same fingerprint (empty scenario probably same)
        crate::test_complete!("different_seeds_may_differ");
    }

    #[test]
    fn chaos_scenario_runs() {
        init_test("chaos_scenario_runs");
        let mut scenario = minimal_scenario();
        scenario.chaos = ChaosSection::Light;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // Light chaos with no tasks should still pass
        assert!(result.passed());
        crate::test_complete!("chaos_scenario_runs");
    }

    #[test]
    fn fault_args_summary_formatting() {
        init_test("fault_args_summary_formatting");
        let mut args = BTreeMap::new();
        args.insert("from".to_string(), serde_json::json!("alice"));
        args.insert("to".to_string(), serde_json::json!("bob"));
        let summary = ScenarioRunner::fault_args_summary(&args);
        assert!(summary.contains("from=alice"));
        assert!(summary.contains("to=bob"));
        crate::test_complete!("fault_args_summary_formatting");
    }

    #[test]
    fn error_display_validation() {
        init_test("error_display_validation");
        let err = ScenarioRunnerError::Validation {
            scenario_id: "invalid-smoke".into(),
            errors: vec![ValidationError {
                field: "id".into(),
                message: "empty".into(),
            }],
        };
        let msg = err.to_string();
        assert!(msg.contains("validation failed"));
        assert!(msg.contains("invalid-smoke"));
        assert!(msg.contains("1 issue(s)"));
        assert!(msg.contains("id"));
        crate::test_complete!("error_display_validation");
    }

    #[test]
    fn error_display_unknown_oracle() {
        init_test("error_display_unknown_oracle");
        let err = ScenarioRunnerError::UnknownOracle("bad_oracle".into());
        assert!(err.to_string().contains("bad_oracle"));
        assert!(err.to_string().contains("valid names:"));
        crate::test_complete!("error_display_unknown_oracle");
    }

    #[test]
    fn error_display_divergence() {
        init_test("error_display_divergence");
        let err = ScenarioRunnerError::ReplayDivergence {
            seed: 42,
            first: TraceCertificateSnapshot {
                event_hash: 1,
                schedule_hash: 2,
                steps: 100,
                trace_fingerprint: 3,
            },
            second: TraceCertificateSnapshot {
                event_hash: 4,
                schedule_hash: 5,
                steps: 100,
                trace_fingerprint: 6,
            },
        };
        let msg = err.to_string();
        assert!(msg.starts_with("[ASUP-E401]"));
        assert!(msg.contains("seed 42"));
        assert!(msg.contains("divergence"));
        crate::test_complete!("error_display_divergence");
    }

    // ── participant workloads (asupersync-39okzv) ────────────────────────

    fn participant(name: &str, role: &str) -> crate::lab::scenario::Participant {
        crate::lab::scenario::Participant {
            name: name.to_string(),
            role: role.to_string(),
            properties: BTreeMap::new(),
        }
    }

    fn participant_with(
        name: &str,
        role: &str,
        key: &str,
        value: serde_json::Value,
    ) -> crate::lab::scenario::Participant {
        let mut participant = participant(name, role);
        participant.properties.insert(key.to_string(), value);
        participant
    }

    /// Two senders and two receivers with default properties: 32 values.
    fn sender_receiver_scenario() -> Scenario {
        let mut scenario = minimal_scenario();
        scenario.id = "test-sender-receiver".to_string();
        scenario.participants = vec![
            participant("alice", "sender"),
            participant("bob", "receiver"),
            participant("carol", "sender"),
            participant("dave", "receiver"),
        ];
        scenario
    }

    fn tasks_with_role(tasks: &[BoundTask], role: WorkloadRole) -> Vec<&BoundTask> {
        tasks.iter().filter(|task| task.role == role).collect()
    }

    fn failure_detail(result: &ScenarioRunResult) -> String {
        let failed_oracles: Vec<_> = result
            .oracle_report
            .entries
            .iter()
            .filter(|entry| !entry.passed)
            .map(|entry| (entry.invariant.clone(), entry.violation.clone()))
            .collect();
        format!(
            "quiescent={} violations={:?} failed_oracles={failed_oracles:?}",
            result.lab_report.quiescent, result.lab_report.invariant_violations
        )
    }

    #[test]
    fn participant_bindings_classify_roles_exactly() {
        init_test("participant_bindings_classify_roles_exactly");
        let mut scenario = minimal_scenario();
        let none = ScenarioRunner::participant_bindings(&scenario);
        assert!(none.is_empty());
        assert_eq!(none.summary_line(), None);

        scenario.participants = vec![
            participant("alice", "sender"),
            participant("bob", "receiver"),
            participant("carol", "Sender"),
            participant("dave", "coordinator"),
            participant("erin", ""),
            participant("frank", "receiver"),
        ];
        let bindings = ScenarioRunner::participant_bindings(&scenario);
        let names = |entries: &[ParticipantBinding]| {
            entries
                .iter()
                .map(|entry| entry.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&bindings.bound), ["alice", "bob", "frank"]);
        assert_eq!(names(&bindings.unbound), ["carol", "dave", "erin"]);
        assert!(!bindings.implicit_sink);
        assert_eq!(
            bindings.summary_line().as_deref(),
            Some(
                "Participants: 3 bound (sender, receiver), 3 unbound (Sender, coordinator, <none>)"
            )
        );
        assert_eq!(ParticipantBindings::BOUND_ROLES, ["sender", "receiver"]);

        scenario.participants = vec![
            participant("producer-a", "sender"),
            participant("producer-b", "sender"),
        ];
        let senders_only = ScenarioRunner::participant_bindings(&scenario);
        assert!(senders_only.implicit_sink);
        assert_eq!(
            senders_only.summary_line().as_deref(),
            Some("Participants: 2 bound (sender), 0 unbound")
        );

        scenario.participants = vec![participant("node-a", "primary")];
        assert_eq!(
            ScenarioRunner::participant_bindings(&scenario)
                .summary_line()
                .as_deref(),
            Some("Participants: 0 bound, 1 unbound (primary)")
        );
        crate::test_complete!("participant_bindings_classify_roles_exactly");
    }

    #[test]
    fn unbound_participants_schedule_no_work() {
        init_test("unbound_participants_schedule_no_work");
        let baseline = ScenarioRunner::run(&minimal_scenario()).unwrap();
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant("node-a", "primary"),
            participant("node-b", "Receiver"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(tasks.is_empty());
        assert_eq!(result.lab_report.steps_total, 0);
        assert_eq!(
            result.certificate, baseline.certificate,
            "unbound participants must leave the empty-lab trace untouched"
        );
        assert!(result.passed());
        crate::test_complete!("unbound_participants_schedule_no_work");
    }

    #[test]
    fn sender_receiver_workload_executes_real_steps() {
        init_test("sender_receiver_workload_executes_real_steps");
        let scenario = sender_receiver_scenario();
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);
        assert_eq!(
            result.oracle_report.checked.len(),
            OracleRegistry::reported_names().len()
        );
        assert_eq!(result.oracle_report.failed_count, 0);

        let senders = tasks_with_role(&tasks, WorkloadRole::Sender);
        let receivers = tasks_with_role(&tasks, WorkloadRole::Receiver);
        assert_eq!((senders.len(), receivers.len(), tasks.len()), (2, 2, 4));
        let committed: u64 = senders
            .iter()
            .map(|task| count(&task.counters.committed))
            .sum();
        let delivered: u64 = receivers
            .iter()
            .map(|task| count(&task.counters.delivered))
            .sum();
        let received: u64 = receivers
            .iter()
            .map(|task| count(&task.counters.received))
            .sum();
        assert_eq!(committed, 2 * DEFAULT_SENDER_MESSAGES);
        assert_eq!(delivered, committed);
        assert_eq!(received, committed);
        for task in &tasks {
            let summary = task.counter_summary();
            assert!(task.spawn_refusal.is_none(), "{}: {summary}", task.name);
            assert!(
                task.counters.finished.load(Ordering::Relaxed),
                "{}: {summary}",
                task.name
            );
            assert_eq!(
                count(&task.counters.cancelled),
                0,
                "{}: {summary}",
                task.name
            );
            assert_eq!(
                count(&task.counters.unexpected),
                0,
                "{}: {summary}",
                task.name
            );
        }
        for receiver in &receivers {
            assert!(receiver.counters.drained_to_close.load(Ordering::Relaxed));
            // Two senders rotating over two receivers give each one half.
            assert_eq!(count(&receiver.counters.received), DEFAULT_SENDER_MESSAGES);
        }
        crate::test_complete!("sender_receiver_workload_executes_real_steps");
    }

    #[test]
    fn sender_receiver_workload_is_deterministic_and_replays() {
        init_test("sender_receiver_workload_is_deterministic_and_replays");
        let scenario = sender_receiver_scenario();
        let first = ScenarioRunner::run(&scenario).unwrap();
        let second = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(first.certificate, second.certificate);
        assert!(first.certificate.steps > 0);

        let empty = ScenarioRunner::run(&minimal_scenario()).unwrap();
        assert_ne!(
            first.certificate.event_hash, empty.certificate.event_hash,
            "the bound workload must leave events in the trace"
        );

        let replayed = ScenarioRunner::validate_replay(&scenario).expect("same seed must replay");
        assert_eq!(replayed.certificate, first.certificate);
        assert!(replayed.passed(), "{}", failure_detail(&replayed));

        let identity = ScenarioRunner::scenario_identity(&scenario, None);
        let via_identity = ScenarioRunner::run_with_identity(&scenario, &identity).unwrap();
        assert!(via_identity.certificate.steps > 0);
        assert!(via_identity.passed(), "{}", failure_detail(&via_identity));
        crate::test_complete!("sender_receiver_workload_is_deterministic_and_replays");
    }

    #[test]
    fn senders_without_receivers_drain_into_implicit_sink() {
        init_test("senders_without_receivers_drain_into_implicit_sink");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant("producer-a", "sender"),
            participant("producer-b", "sender"),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        let sinks = tasks_with_role(&tasks, WorkloadRole::Sink);
        assert_eq!(sinks.len(), 1);
        let sink = sinks[0];
        assert_eq!(sink.name, IMPLICIT_SINK_NAME);
        assert_eq!(
            count(&sink.counters.received),
            2 * DEFAULT_SENDER_MESSAGES,
            "{}",
            sink.counter_summary()
        );
        assert!(sink.counters.drained_to_close.load(Ordering::Relaxed));
        assert_eq!(count(&sink.counters.out_of_order), 0);
        crate::test_complete!("senders_without_receivers_drain_into_implicit_sink");
    }

    #[test]
    fn receivers_without_senders_see_a_closed_channel() {
        init_test("receivers_without_senders_see_a_closed_channel");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![participant("bob", "receiver")];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert!(result.lab_report.steps_total > 0);
        assert_eq!(tasks.len(), 1);
        assert_eq!(count(&tasks[0].counters.received), 0);
        assert!(tasks[0].counters.drained_to_close.load(Ordering::Relaxed));
        crate::test_complete!("receivers_without_senders_see_a_closed_channel");
    }

    #[test]
    fn bound_participant_properties_are_validated() {
        init_test("bound_participant_properties_are_validated");
        let mut scenario = minimal_scenario();
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!("many")),
            participant_with("bob", "receiver", "capacity", serde_json::json!(0)),
            participant_with(
                "carol",
                "receiver",
                "capacity",
                serde_json::json!(MAX_RECEIVER_CAPACITY + 1),
            ),
            // Unbound roles keep free-form properties.
            participant_with("dave", "coordinator", "capacity", serde_json::json!(0)),
        ];
        match ScenarioRunner::run(&scenario) {
            Err(ScenarioRunnerError::Validation { errors, .. }) => {
                let fields: Vec<_> = errors.iter().map(|error| error.field.as_str()).collect();
                assert_eq!(
                    fields,
                    [
                        "participants.alice.properties.messages",
                        "participants.bob.properties.capacity",
                        "participants.carol.properties.capacity",
                    ]
                );
            }
            other => panic!("expected a participant property validation error, got {other:?}"),
        }

        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(0)),
            participant_with(
                "bob",
                "receiver",
                "capacity",
                serde_json::json!(MAX_RECEIVER_CAPACITY),
            ),
        ];
        let (result, tasks) = ScenarioRunner::run_seeded(&scenario, None).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        assert_eq!(count(&tasks[0].counters.committed), 0);
        assert!(tasks[1].counters.drained_to_close.load(Ordering::Relaxed));
        crate::test_complete!("bound_participant_properties_are_validated");
    }

    /// Deliberate-failure control target (see the 39okzv notes): if the sender
    /// forgets its permit instead of sending it, this test must fail on the
    /// `obligation_leak` oracle.
    #[test]
    fn two_phase_permits_are_obligations_the_leak_oracle_sees() {
        init_test("two_phase_permits_are_obligations_the_leak_oracle_sees");
        let mut scenario = minimal_scenario();
        scenario.id = "test-permit-obligations".to_string();
        // A leak must surface as an oracle verdict, not as a runtime panic.
        scenario.lab.panic_on_obligation_leak = false;
        scenario.oracles = vec!["obligation_leak".to_string()];
        // messages <= capacity: the sender never waits, even if permits leak.
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(4)),
            participant_with("bob", "receiver", "capacity", serde_json::json!(4)),
        ];

        let plan = WorkloadPlan::from_scenario(&scenario).expect("valid plan");
        let mut runtime = LabRuntime::new(ScenarioRunner::lab_config_for(&scenario, None));
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan);
        runtime.run_until_quiescent();

        let report = runtime.report();
        let entry = report
            .oracle_report
            .entry("obligation_leak")
            .expect("obligation leak oracle is registered");
        assert!(
            entry.passed,
            "every reserved permit must be committed: {entry:?}"
        );
        assert_eq!(runtime.state.leak_count(), 0);
        let stats = runtime
            .state
            .obligation_gateway()
            .expect("the lab installs an obligation gateway")
            .mailbox()
            .stats();
        assert_eq!(stats.reserved, 4, "four permits were reserved: {stats:?}");
        assert_eq!(stats.committed, 4, "four permits were sent: {stats:?}");
        assert_eq!(stats.leaked, 0, "{stats:?}");
        assert_eq!(runtime.state.pending_obligation_count(), 0);

        let mut violations = Vec::new();
        let tasks = workload.finish(&mut violations);
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(count(&tasks[1].counters.received), 4);

        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed(), "{}", failure_detail(&result));
        crate::test_complete!("two_phase_permits_are_obligations_the_leak_oracle_sees");
    }

    #[test]
    fn cancellation_mid_protocol_still_resolves_every_obligation() {
        init_test("cancellation_mid_protocol_still_resolves_every_obligation");
        let mut scenario = minimal_scenario();
        scenario.id = "test-cancel-mid-protocol".to_string();
        scenario.chaos = ChaosSection::Custom {
            cancel_probability: 0.1,
            delay_probability: 0.0,
            delay_min_ms: 0,
            delay_max_ms: 10,
            io_error_probability: 0.0,
            wakeup_storm_probability: 0.0,
            budget_exhaustion_probability: 0.0,
        };
        scenario.participants = vec![
            participant_with("alice", "sender", "messages", serde_json::json!(24)),
            participant_with("bob", "receiver", "capacity", serde_json::json!(2)),
            participant_with("carol", "receiver", "capacity", serde_json::json!(2)),
        ];

        let mut cancelled = 0_u64;
        for seed in 0..8 {
            let (result, tasks) = ScenarioRunner::run_seeded(&scenario, Some(seed)).unwrap();
            assert!(result.passed(), "seed {seed}: {}", failure_detail(&result));
            let sender = &tasks[0];
            let c = &sender.counters;
            let committed = count(&c.committed);
            assert!(
                committed + count(&c.cancelled) + count(&c.disconnected) <= sender.planned,
                "seed {seed}: {}",
                sender.counter_summary()
            );
            let receivers = tasks_with_role(&tasks, WorkloadRole::Receiver);
            let delivered: u64 = receivers
                .iter()
                .map(|task| count(&task.counters.delivered))
                .sum();
            let received: u64 = receivers
                .iter()
                .map(|task| count(&task.counters.received))
                .sum();
            assert_eq!(delivered, committed, "seed {seed}");
            assert!(received <= delivered, "seed {seed}");
            cancelled += tasks
                .iter()
                .map(|task| count(&task.counters.cancelled))
                .sum::<u64>();
        }
        assert!(
            cancelled > 0,
            "a 10% per-dispatch cancel rate must cancel some reserve or receive across eight seeds"
        );
        crate::test_complete!("cancellation_mid_protocol_still_resolves_every_obligation");
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn trace_certificate_snapshot_debug_clone_copy_eq() {
        let cert = TraceCertificateSnapshot {
            event_hash: 111,
            schedule_hash: 222,
            steps: 333,
            trace_fingerprint: 444,
        };
        let cert2 = cert; // Copy
        let cert3 = cert;
        assert_eq!(cert, cert2);
        assert_eq!(cert2, cert3);
        let dbg = format!("{cert:?}");
        assert!(dbg.contains("TraceCertificateSnapshot"));
        assert!(dbg.contains("111"));
    }

    #[test]
    fn exploration_run_summary_debug_clone() {
        let s = ExplorationRunSummary {
            seed: 42,
            passed: true,
            steps: 100,
            fingerprint: 999,
            failures: vec![],
        };
        let s2 = s;
        assert_eq!(s2.seed, 42);
        assert!(s2.passed);
        assert_eq!(s2.steps, 100);
        assert_eq!(s2.fingerprint, 999);
        assert!(s2.failures.is_empty());
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("ExplorationRunSummary"));
    }

    #[test]
    fn scenario_exploration_result_debug_clone() {
        let r = ScenarioExplorationResult {
            scenario_id: "test-explore".to_string(),
            seeds_explored: 10,
            passed: 8,
            failed: 2,
            unique_fingerprints: 3,
            runs: vec![ExplorationRunSummary {
                seed: 0,
                passed: true,
                steps: 50,
                fingerprint: 1,
                failures: vec![],
            }],
            first_failure_seed: Some(5),
        };
        let r2 = r;
        assert_eq!(r2.scenario_id, "test-explore");
        assert_eq!(r2.seeds_explored, 10);
        assert_eq!(r2.first_failure_seed, Some(5));
        assert_eq!(r2.runs.len(), 1);
        let dbg = format!("{r2:?}");
        assert!(dbg.contains("ScenarioExplorationResult"));
    }
}
