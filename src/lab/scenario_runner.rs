//! Scenario runner for FrankenLab deterministic testing (bd-1hu19.2).
//!
//! Bridges [`Scenario`] YAML specifications to [`LabRuntime`] execution, providing:
//!
//! - Participant workloads: `sender`, `receiver`, `swarm`, `supervisor`,
//!   `worker`, `saga-coordinator`, `saga-participant`, `primary`, `replica`,
//!   `lease-grantor`, `lease-holder`, `hub` and `peer` roles become real lab
//!   tasks
//! - Timed fault injection based on scenario fault events
//! - Oracle filtering (only check oracles listed in the scenario)
//! - Seed exploration (run the same scenario across multiple seeds)
//! - Bounded exact schedule exploration with resumable frontiers and replay receipts
//! - Replay validation (run twice, verify identical trace certificates)
//!
//! [`ScenarioRunner::explore_schedules`] executes witnessed scheduling alternatives
//! for fully bound, single-worker scenarios without chaos, timed faults or a
//! cancellation campaign. It includes the same application checks as ordinary
//! runs. Search exhaustion is scoped to this deterministic schedule tree.
//!
//! # Participant workloads
//!
//! Before any fault fires, the runner spawns lab tasks for every participant
//! whose `role` is exactly `sender`, `receiver`, `swarm`, `supervisor`,
//! `worker`, `saga-coordinator`, `saga-participant`, `primary`, `replica`,
//! `lease-grantor`, `lease-holder`, `hub` or `peer` (case-sensitive), all in
//! one root region.
//!
//! Channel roles:
//!
//! - each receiver owns a bounded [`mpsc`] channel
//!   (`properties.capacity`, default 4, at most 4096) and drains it until
//!   every sender is gone;
//! - each sender sends `properties.messages` values (default 16, at most
//!   1000000) to the receivers in round-robin order through the two-phase
//!   `reserve` and `send` API, so every value is a runtime-tracked
//!   `SendPermit` obligation. It yields once while it holds each permit, so
//!   a cancellation can arrive mid-protocol; it then aborts the permit;
//! - senders without any receiver race on one shared channel that an
//!   implicit sink task drains, and receivers without senders observe a
//!   closed channel at once.
//!
//! Swarm role: a swarm spawns `properties.tasks` short member tasks (default
//! 100, from 1 to 20000). Each member yields twice and bumps a counter that
//! all members share; it checks for cancellation before every step.
//!
//! Supervision roles: each `supervisor` runs a [`ManagedSupervisor`] in its
//! task. Workers go to the supervisors round-robin in declaration order, and
//! workers without any supervisor share one implicit supervisor. Each worker
//! is a transient child under a one-for-one policy without backoff. A worker
//! generation yields once, then returns `Outcome::Err` until the worker has
//! failed `properties.fail_times` times (default 1, at most 1000), and
//! succeeds after that. A supervisor allows `properties.max_restarts`
//! restarts per minute across its workers; the default is the sum of their
//! `fail_times`. When the budget runs out, the failing worker stays stopped;
//! the supervisor does not escalate.
//!
//! A worker can opt into executable lifecycle faults with
//! `properties.lifecycle: { work_ms: 500 }`. Each generation then needs that
//! much active virtual time before its configured failure or success. A
//! `process_stall` pauses its progress until `duration_ms` expires or a
//! `process_resume` arrives. A `host_crash` terminates the current generation
//! with a failure, discarding its progress; the managed supervisor's replacement
//! waits for `host_restart` before doing new work. The optional lifecycle
//! `host` names a declared participant and defaults to the worker's own name,
//! allowing multiple workers to share one fault target. The derived restart
//! budget includes planned crash episodes; an explicit `max_restarts` still
//! governs. This models managed worker availability, not OS process death or
//! persistent state recovery. Work and each stall are bounded to 60000 ms.
//!
//! Saga roles: each `saga-coordinator` runs a [`Saga`] with one step per
//! `saga-participant`. Participants go to the coordinators round-robin in
//! declaration order, and participants without any coordinator share one
//! implicit coordinator. Before each step the coordinator sleeps
//! `properties.step_ms` of virtual time (default 50, at most 60000). It then
//! registers the step's compensation, sends the participant an apply request
//! on a bounded [`mpsc`] channel and waits at most `step_ms` for the
//! [`oneshot`] reply. A participant applies a request only if its step was
//! not compensated first. A refused, lost or late reply aborts the saga, which
//! runs the registered compensations in reverse order. A compensation undoes
//! an applied step or fences one that was never applied, so a request that
//! arrives after the abort is refused. A coordinator that is cancelled aborts
//! too.
//!
//! Replication roles: each `primary` appends `properties.writes` entries
//! (default 20, at most 10000), one per round of `properties.write_ms`
//! virtual milliseconds (default 50, from 1 to 60000). Replicas go to the
//! primaries round-robin in declaration order, and replicas without any
//! primary share one implicit primary. Each round the primary ships every
//! lagging replica its log from that replica's acknowledged length and waits
//! at most `write_ms` for the reply; a lost or late batch is shipped again
//! the next round. A replica applies only a batch that continues its log.
//! After the last write the primary keeps shipping for up to 40 rounds,
//! until every replica has the whole log; whether they converged is
//! recorded, not required.
//!
//! Lease roles: each `lease-grantor` grants one lease, for
//! `properties.initial_lease_ms` (default 100, from 1 to 60000) by its own
//! clock, to one holder at a time: it grants when nobody holds the lease,
//! when the requester already holds it, or when the holder's grant has run
//! out. Holders go to the grantors round-robin in declaration order, and
//! holders without any grantor share one implicit grantor. After
//! `properties.start_ms` (default 0) a `lease-holder` asks for the lease
//! every `properties.renew_ms` (default 40) until it gets it, renews it
//! `properties.renewals` times (default 4, at most 10000) at the same
//! interval, and releases it. It believes it holds the lease until the
//! grant's length less `properties.margin_ms` (default 10) after it sent the
//! request, by its own clock, and it holds a runtime-tracked `Lease`
//! obligation for as long as it believes so. A `clock_skew` fault sets its
//! `host`'s clock offset to `skew_ms`, and `clock_reset` sets it back to
//! zero; only lease roles read participant clocks.
//!
//! Hub roles: each `hub` pings its peers in turn every round, for
//! `properties.rounds` rounds (default 10, at most 10000) that start
//! `properties.interval_ms` apart (default 100), and waits at most
//! `properties.timeout_ms` (default 1000) for each echo. Peers go to the
//! hubs round-robin, and peers without any hub share one implicit hub. Each
//! `peer` echoes the ping's sequence number. The hub records each echo's
//! round trip and counts a lost or late ping or echo as lost.
//!
//! Saga, replication, lease and hub messages cross a simulated network. The
//! scenario's `network` preset sets every link's latency, jitter and packet
//! loss (the
//! [`crate::lab::network::NetworkConditions`] of the same name), and a
//! `links` entry keyed `"from->to"` overrides one direction's `latency` and
//! `packet_loss`; the other link fields are not modeled. `partition` and
//! `heal` faults whose `from` and `to` name two participants cut and restore
//! the link between them. A message that is dropped or sent over a cut link
//! is lost, and a coordinator, primary, holder or hub whose request or reply
//! is lost times out. When saga, replication, lease or hub roles are bound,
//! the runner fires due timers on its way to each fault and runs with
//! automatic virtual-time advance after the last one.
//!
//! Lab chaos may cancel these tasks mid-protocol. A send or receive, swarm
//! member, worker generation, supervisor or saga task that ends in
//! cancellation is counted and stops; it is never retried. The runner appends
//! a `workload:` entry to the report's invariant violations, which fails the
//! run, when:
//!
//! - a bound task cannot be spawned, or a supervisor topology is refused;
//! - a task meets an outcome its contract rules out;
//! - a receiver gets one sender's values out of order, or drains its channel
//!   to close without receiving every value committed into it;
//! - a swarm member neither completes nor ends cancelled;
//! - a worker never succeeds, or succeeds after a restart count other than
//!   its `fail_times`;
//! - a supervisor exits with an error or a panic, or its restart batches do
//!   not match its workers' restarts;
//! - a completed saga left a participant's step unapplied, an aborted saga
//!   left one applied, or its compensations did not run exactly once each in
//!   reverse step order;
//! - a replica's applied log is not a prefix of its primary's log, or a
//!   primary that was not cancelled never finished;
//! - two holders of one grantor believed they held its lease at the same
//!   virtual time, or a holder that was not cancelled never finished;
//! - a peer echoed another ping's sequence number, or a hub that was not
//!   cancelled never finished.
//!
//! Apart from cutting saga, replication, lease and hub links, skewing lease
//! clocks, and controlling opted-in workers, timed faults stay trace and
//! effect-summary records. Workers without `lifecycle` keep their original
//! behavior; channel roles are not partitioned by these faults.
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
use super::exact_explorer::{
    ExactScheduleCheckpoint, ExactScheduleCheckpointError, ExactScheduleCheckpointLimits,
    ExactScheduleConfigError, ExactScheduleExplorer, ExactScheduleLimits, ExactScheduleProgress,
    ExactScheduleResumeError, ExactScheduleRun, ExactScheduleSearchTermination,
    ExactScheduleTermination, ExactScheduleWorkloadKey,
};
use super::network::{LatencyModel, NetworkConditions};
use super::oracle::{OracleRegistry, OracleRegistryError, OracleReport};
use super::runtime::{
    ForcedScheduleError, ForcedScheduleLimits, ForcedScheduleReport, LabRunReport, LabRuntime,
};
use super::scenario::{
    FaultAction, FaultEvent, LatencySpec, NetworkPreset, NetworkSection, Participant, Scenario,
    ValidationError,
};
use crate::channel::mpsc::{self, RecvError, SendError};
use crate::channel::oneshot;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::remote::Saga;
use crate::runtime::{JoinError, TaskHandle, yield_now};
use crate::supervision::{
    BackoffStrategy, ChildSpec, EscalationPolicy, ManagedChildBinding, ManagedChildCompletion,
    ManagedGeneration, ManagedRestartMode, ManagedSupervisor, ManagedSupervisorReport,
    RestartPolicy, SupervisionConfig, SupervisorBuilder,
};
use crate::trace::replay::ReplayTrace;
use crate::types::{Budget, CancelReason, Outcome, RegionId, Time};
use crate::util::DetRng;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

mod cancellation;
mod lifecycle;
pub use cancellation::{
    ScenarioCancellationError, ScenarioCancellationInjection, ScenarioCancellationLimits,
    ScenarioCancellationReport, ScenarioCancellationTermination, ScenarioCancellationTrial,
};

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

    /// [`Self::to_json`] plus what the run executed, for command-line JSON
    /// output. `workload_ran` is true when the lab took at least one step;
    /// a passing run where it is false checked nothing. When the scenario
    /// declares participants, `participant_bindings` lists which ones ran.
    #[must_use]
    pub fn to_json_with_bindings(&self, bindings: &ParticipantBindings) -> serde_json::Value {
        let mut value = self.to_json();
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "workload_ran".to_owned(),
                serde_json::Value::Bool(self.lab_report.steps_total > 0),
            );
            if !bindings.is_empty() {
                object.insert(
                    "participant_bindings".to_owned(),
                    serde_json::to_value(bindings).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        value
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

/// Errors admitting or replaying exact scenario schedules.
///
/// Exploration failures are returned in [`ScenarioScheduleReport`], including
/// a partial search. Replay divergence is an error; a faithfully reproduced
/// workload failure remains an inspectable [`ScenarioScheduleReplayReport`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScenarioScheduleError {
    /// The ordinary scenario or workload contract is invalid.
    #[error(transparent)]
    Scenario(#[from] ScenarioRunnerError),
    /// A scenario effect is outside the exact scheduling model.
    #[error("exact scenario exploration does not support {reason}")]
    Unsupported {
        /// The unsupported input, never silently discarded.
        reason: &'static str,
    },
    /// The explorer configuration or its bounds are inadmissible.
    #[error("invalid exact scenario exploration configuration: {0:?}")]
    Configuration(ExactScheduleConfigError),
    /// The saved frontier cannot resume against this workload and configuration.
    #[error("exact scenario exploration cannot resume: {0:?}")]
    Resume(ExactScheduleResumeError),
    /// The source belongs to another effective scenario or implementation.
    #[error("exact scenario replay workload identity mismatch")]
    ReplayWorkloadMismatch,
    /// An incomplete exploration execution cannot serve as an exact receipt.
    #[error("exact scenario replay requires a complete schedule receipt")]
    MissingReplayReceipt,
    /// Forced execution rejected the receipt, exhausted limits, or diverged.
    #[error("exact scenario replay failed: {0}")]
    Replay(#[from] ForcedScheduleError),
    /// The scenario could not be serialized for its content identity.
    #[error("cannot identify exact scenario workload: {0}")]
    Identity(#[from] serde_json::Error),
}

const SCENARIO_CHECKPOINT_MAGIC: &[u8; 8] = b"ASUPSCN\0";
const SCENARIO_CHECKPOINT_HEADER: usize = 20;
const SCENARIO_CHECKPOINT_OVERHEAD: usize = SCENARIO_CHECKPOINT_HEADER + 32;

/// A scenario's exact frontier and its cumulative application-level failures.
///
/// The inner explorer counts kernel failures; this wrapper also remembers
/// failures detected by the scenario's real channel, supervision, saga, lease,
/// replication and peer workloads. A later passing batch cannot erase them.
/// Loading bytes validates integrity and bounds, not earlier execution claims.
/// A loaded checkpoint with prior runs therefore cannot prove whole-campaign
/// success, although its remaining branches can still execute and be inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioScheduleCheckpoint {
    inner: ExactScheduleCheckpoint,
    scenario_failed: u64,
    historical_progress_verified: bool,
}

impl ScenarioScheduleCheckpoint {
    /// Cumulative kernel progress, distinct from the scenario failure count.
    #[must_use]
    pub const fn progress(&self) -> ExactScheduleProgress {
        self.inner.progress()
    }

    /// Number of exact alternatives awaiting execution.
    #[must_use]
    pub fn pending_prefix_count(&self) -> usize {
        self.inner.pending_prefix_count()
    }

    /// All scenario failures observed by this campaign, across every batch.
    #[must_use]
    pub const fn scenario_failed(&self) -> u64 {
        self.scenario_failed
    }

    /// Whether earlier runs were observed by this process rather than decoded.
    #[must_use]
    pub const fn historical_progress_verified(&self) -> bool {
        self.historical_progress_verified
    }

    fn checksum(bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.lab.scenario-schedule-checkpoint.v1\0");
        hash.update(bytes);
        hash.finalize().into()
    }

    fn inner_limits(
        mut limits: ExactScheduleCheckpointLimits,
    ) -> Result<ExactScheduleCheckpointLimits, ExactScheduleCheckpointError> {
        limits.max_encoded_bytes = limits
            .max_encoded_bytes
            .checked_sub(SCENARIO_CHECKPOINT_OVERHEAD)
            .ok_or(ExactScheduleCheckpointError::ByteLimit)?;
        Ok(limits)
    }

    /// Encodes a bounded frontier without any completed trace or live future.
    ///
    /// The encoded-byte limit covers this wrapper and the nested checkpoint.
    /// Nested vector limits keep their original meaning. The integrity checksum
    /// is not an authentication mechanism or evidence that prior runs occurred.
    ///
    /// # Errors
    /// Rejects invalid counters, insufficient admission, or allocation failure.
    pub fn to_canonical_bytes(
        &self,
        limits: ExactScheduleCheckpointLimits,
    ) -> Result<Vec<u8>, ExactScheduleCheckpointError> {
        if self.scenario_failed > self.inner.progress().runs {
            return Err(ExactScheduleCheckpointError::Shape);
        }
        let inner = self.inner.to_canonical_bytes(Self::inner_limits(limits)?)?;
        let len = inner
            .len()
            .checked_add(SCENARIO_CHECKPOINT_OVERHEAD)
            .ok_or(ExactScheduleCheckpointError::Overflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ExactScheduleCheckpointError::Allocation)?;
        bytes.extend_from_slice(SCENARIO_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&self.scenario_failed.to_le_bytes());
        bytes.extend_from_slice(&inner);
        let checksum = Self::checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Loads an unverified frontier, retaining every prior scenario failure.
    ///
    /// The full byte limit, wrapper format and checksum are checked before
    /// decoding nested vectors. The nested codec checks their shape and
    /// aggregate storage limits before allocation. Fresh execution still checks
    /// the complete scenario identity, configuration and every enabled set.
    ///
    /// # Errors
    /// Rejects malformed, corrupted, unsupported, or over-budget checkpoints.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: ExactScheduleCheckpointLimits,
    ) -> Result<Self, ExactScheduleCheckpointError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(ExactScheduleCheckpointError::ByteLimit);
        }
        if bytes.len() < SCENARIO_CHECKPOINT_OVERHEAD {
            return Err(ExactScheduleCheckpointError::Length);
        }
        if bytes[..8] != *SCENARIO_CHECKPOINT_MAGIC || bytes[8..12] != 1_u32.to_le_bytes() {
            return Err(ExactScheduleCheckpointError::Format);
        }
        let end = bytes.len() - 32;
        if bytes[end..] != Self::checksum(&bytes[..end]) {
            return Err(ExactScheduleCheckpointError::Checksum);
        }
        let mut count = [0; 8];
        count.copy_from_slice(&bytes[12..SCENARIO_CHECKPOINT_HEADER]);
        let scenario_failed = u64::from_le_bytes(count);
        let inner = ExactScheduleCheckpoint::try_from_canonical_bytes(
            &bytes[SCENARIO_CHECKPOINT_HEADER..end],
            Self::inner_limits(limits)?,
        )?;
        if scenario_failed > inner.progress().runs {
            return Err(ExactScheduleCheckpointError::Shape);
        }
        let historical_progress_verified = inner.progress().runs == 0;
        Ok(Self {
            inner,
            scenario_failed,
            historical_progress_verified,
        })
    }
}

/// One exact execution with the same workload checks as an ordinary scenario.
#[derive(Debug, Clone)]
pub struct ScenarioScheduleRun {
    workload: ExactScheduleWorkloadKey,
    /// Actual enabled choices, termination, and optional complete replay receipt.
    /// Its invariant violations also include the scenario workload checks.
    pub execution: ExactScheduleRun,
    /// Only the oracles selected by the scenario and runtime configuration.
    pub oracle_report: FilteredOracleReport,
}

impl ScenarioScheduleRun {
    /// Whether real work completed with a replay receipt and no selected failure.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.execution.termination == ExactScheduleTermination::Quiescent
            && self.execution.schedule.is_some()
            && self.execution.lab.steps_total > 0
            && self.execution.lab.quiescent
            && self.execution.lab.invariant_violations.is_empty()
            && self.oracle_report.all_passed
    }

    /// A summary of the fresh execution, not a substitute for its replay receipt.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let termination = match &self.execution.termination {
            ExactScheduleTermination::Quiescent => "quiescent",
            ExactScheduleTermination::WorkLimit => "work_limit",
            ExactScheduleTermination::DispatchLimit => "dispatch_limit",
            ExactScheduleTermination::Stalled => "stalled",
            ExactScheduleTermination::Unsupported { .. } => "unsupported",
            ExactScheduleTermination::PrefixDiverged { .. } => "prefix_diverged",
            ExactScheduleTermination::ReplayRejected(_) => "replay_rejected",
        };
        serde_json::json!({
            "passed": self.passed(),
            "termination": termination,
            "termination_detail": format!("{:?}", self.execution.termination),
            "steps": self.execution.lab.steps_total,
            "work_units": self.execution.work_units,
            "dispatches": self.execution.execution.decisions().len(),
            "requested_prefix": self.execution.requested_prefix.decisions().len(),
            "quiescent": self.execution.lab.quiescent,
            "complete_receipt": self.execution.schedule.is_some(),
            "schedule_hash": self.execution.schedule.as_ref().map(|s| s.terminal_schedule_hash()),
            "oracle_report": self.oracle_report.to_json(),
            "invariant_violations": self.execution.lab.invariant_violations,
        })
    }
}

/// A fresh exact replay and its independently evaluated scenario verdict.
///
/// Constructing this report means the complete forced schedule executed and
/// matched its terminal certificate. The workload can still fail: replaying a
/// counterexample successfully returns a report whose [`Self::passed`] is false.
#[derive(Debug, Clone)]
pub struct ScenarioScheduleReplayReport {
    /// Complete exact replay receipt, including the terminal schedule hash.
    pub execution: ForcedScheduleReport,
    /// Fresh runtime observations, including the scenario's workload violations.
    pub lab: LabRunReport,
    /// Only the oracles selected by the scenario and runtime configuration.
    pub oracle_report: FilteredOracleReport,
}

impl ScenarioScheduleReplayReport {
    /// Whether replayed real work completed without a selected scenario failure.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.execution.quiescent
            && self.execution.steps > 0
            && self.lab.quiescent
            && self.lab.steps_total > 0
            && self.lab.invariant_violations.is_empty()
            && self.oracle_report.all_passed
    }

    /// Fresh replay observations, independent of the source execution's verdict.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "scenario-schedule-replay-v1",
            "passed": self.passed(),
            "dispatches": self.execution.dispatches,
            "steps": self.execution.steps,
            "terminal_nanos": self.execution.terminal_nanos,
            "schedule_hash": self.execution.schedule_hash,
            "lab": self.lab.to_json(),
            "oracle_report": self.oracle_report.to_json(),
        })
    }
}

/// Fresh scenario executions and cumulative exact-search progress.
///
/// Search exhaustion covers only the admitted deterministic schedule tree. It
/// is not optimal DPOR, a claim of one representative per equivalence class, or
/// coverage of external concurrency and fault choices (br-asupersync-bi2462.44).
#[derive(Debug, Clone)]
pub struct ScenarioScheduleReport {
    /// Identity of the scenario whose workload was executed.
    pub scenario_id: String,
    /// Fixed lab seed; exact alternatives vary choices rather than seeds.
    pub seed: u64,
    /// Why this batch stopped, including sticky incomplete-search conditions.
    pub termination: ExactScheduleSearchTermination,
    /// Cumulative kernel observations from all batches.
    pub progress: ExactScheduleProgress,
    /// Cumulative failures under the scenario's workload and oracle contract.
    pub scenario_failed: u64,
    /// Exact alternatives still pending after this batch.
    pub pending_prefixes: usize,
    /// Whether historical progress was observed, rather than loaded as claims.
    pub historical_progress_verified: bool,
    /// Complete observations for this batch only.
    pub runs: Vec<ScenarioScheduleRun>,
}

impl ScenarioScheduleReport {
    /// Requires exhausted search, real work, verified history and no failures.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.termination == ExactScheduleSearchTermination::SearchExhausted
            && self.progress.runs > 0
            && self.scenario_failed == 0
            && self.pending_prefixes == 0
            && self.historical_progress_verified
            && self.runs.iter().all(ScenarioScheduleRun::passed)
    }

    /// Stable command-line projection of search scope, coverage and failures.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let termination = match self.termination {
            ExactScheduleSearchTermination::SearchExhausted => "search_exhausted",
            ExactScheduleSearchTermination::RunLimit => "run_limit",
            ExactScheduleSearchTermination::PrefixQueueLimit => "prefix_queue_limit",
            ExactScheduleSearchTermination::IncompleteRun => "incomplete_run",
            ExactScheduleSearchTermination::Stopped => "stopped",
        };
        serde_json::json!({
            "schema": "scenario-schedule-exploration-v1",
            "model": "single_worker_deterministic_schedule_tree",
            "scenario_id": self.scenario_id,
            "seed": self.seed,
            "passed": self.passed(),
            "termination": termination,
            "historical_progress_verified": self.historical_progress_verified,
            "scenario_failed": self.scenario_failed,
            "pending_prefixes": self.pending_prefixes,
            "progress": {
                "runs": self.progress.runs,
                "completed": self.progress.completed,
                "incomplete": self.progress.incomplete,
                "failed": self.progress.failed,
                "omitted": self.progress.omitted,
            },
            "runs": self.runs.iter().map(ScenarioScheduleRun::to_json).collect::<Vec<_>>(),
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
/// Largest accepted `messages`; each value is a few lab steps.
const MAX_SENDER_MESSAGES: u64 = 1_000_000;
/// Channel capacity a receiver offers when `properties.capacity` is absent.
const DEFAULT_RECEIVER_CAPACITY: usize = 4;
/// Largest accepted `properties.capacity`; the channel preallocates its queue.
const MAX_RECEIVER_CAPACITY: usize = 4096;
/// Name of the implicit sink task in `workload:` diagnostics.
const IMPLICIT_SINK_NAME: &str = "<implicit-sink>";
/// Role label printed for a participant whose `role` is empty.
const EMPTY_ROLE_LABEL: &str = "<none>";
/// Participant role bound to a set of short member tasks.
const SWARM_ROLE: &str = "swarm";
/// Participant role bound to a managed supervisor running the workers.
const SUPERVISOR_ROLE: &str = "supervisor";
/// Participant role bound to a supervised child that fails, then succeeds.
const WORKER_ROLE: &str = "worker";
/// Members a swarm spawns when `properties.tasks` is absent.
const DEFAULT_SWARM_TASKS: usize = 100;
/// Largest accepted `properties.tasks`.
const MAX_SWARM_TASKS: usize = 20_000;
/// Yields each swarm member performs before it completes.
const SWARM_MEMBER_YIELDS: usize = 2;
/// Failures a worker returns when `properties.fail_times` is absent.
const DEFAULT_WORKER_FAIL_TIMES: u64 = 1;
/// Largest accepted `properties.fail_times`.
const MAX_WORKER_FAIL_TIMES: u64 = 1_000;
/// Sliding window, in minutes, of a supervisor's restart budget.
const SUPERVISOR_RESTART_WINDOW_MINS: u64 = 1;
/// Name of the implicit supervisor of workers without one.
const IMPLICIT_SUPERVISOR_NAME: &str = "<implicit-supervisor>";
/// Role of a participant that runs a saga over its participants.
const SAGA_COORDINATOR_ROLE: &str = "saga-coordinator";
/// Role of a participant that applies one saga step on request.
const SAGA_PARTICIPANT_ROLE: &str = "saga-participant";
/// Default virtual time a coordinator waits before each step and for its reply.
const DEFAULT_SAGA_STEP_MS: u64 = 50;
/// Largest accepted `step_ms`.
const MAX_SAGA_STEP_MS: u64 = 60_000;
/// Name of the coordinator that runs participants no coordinator owns.
const IMPLICIT_COORDINATOR_NAME: &str = "<implicit-coordinator>";
/// A participant's step: neither applied nor compensated.
const STEP_PENDING: u8 = 0;
/// The participant applied the step.
const STEP_APPLIED: u8 = 1;
/// The step was applied, then compensated.
const STEP_UNDONE: u8 = 2;
/// The step was compensated before it was applied; a later request is refused.
const STEP_FENCED: u8 = 3;
/// Role of a participant that appends to a log and ships it to its replicas.
const PRIMARY_ROLE: &str = "primary";
/// Role of a participant that applies the log its primary ships.
const REPLICA_ROLE: &str = "replica";
/// Default number of entries a primary appends.
const DEFAULT_PRIMARY_WRITES: u64 = 20;
/// Largest accepted `writes`.
const MAX_PRIMARY_WRITES: u64 = 10_000;
/// Default virtual time between a primary's rounds, and each batch's reply budget.
const DEFAULT_WRITE_MS: u64 = 50;
/// Rounds a primary keeps shipping after its last write, for lagging replicas.
const CATCH_UP_ROUNDS: usize = 40;
/// Name of the primary that serves replicas no primary owns.
const IMPLICIT_PRIMARY_NAME: &str = "<implicit-primary>";
/// Role of a participant that grants one lease to its holders, one at a time.
const LEASE_GRANTOR_ROLE: &str = "lease-grantor";
/// Role of a participant that acquires, renews and releases its grantor's lease.
const LEASE_HOLDER_ROLE: &str = "lease-holder";
/// Default length of each grant, when the grantor has no `initial_lease_ms`.
const DEFAULT_LEASE_MS: u64 = 100;
/// Default number of renewals a holder makes before it releases the lease.
const DEFAULT_LEASE_RENEWALS: u64 = 4;
/// Largest accepted `renewals`.
const MAX_LEASE_RENEWALS: u64 = 10_000;
/// Default virtual time between a holder's requests, and each request's reply budget.
const DEFAULT_RENEW_MS: u64 = 40;
/// Default time a holder takes off each grant to allow for clock skew.
const DEFAULT_LEASE_MARGIN_MS: u64 = 10;
/// Requests a holder makes for the lease before it gives up.
const MAX_ACQUIRE_ATTEMPTS: u32 = 100;
/// Name of the grantor that serves holders no grantor owns.
const IMPLICIT_GRANTOR_NAME: &str = "<implicit-grantor>";
/// Role of a participant that pings each of its peers every round and times the echoes.
const HUB_ROLE: &str = "hub";
/// Role of a participant that echoes its hub's pings.
const PEER_ROLE: &str = "peer";
/// Default number of rounds a hub pings its peers.
const DEFAULT_HUB_ROUNDS: u64 = 10;
/// Largest accepted `rounds`.
const MAX_HUB_ROUNDS: u64 = 10_000;
/// Default virtual time a hub waits before each round.
const DEFAULT_HUB_INTERVAL_MS: u64 = 100;
/// Default virtual time a hub waits for each echo.
const DEFAULT_HUB_TIMEOUT_MS: u64 = 1_000;
/// Name of the hub that pings peers no hub owns.
const IMPLICIT_HUB_NAME: &str = "<implicit-hub>";

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
    /// True when workers have no supervisor, so the runner adds one.
    pub implicit_supervisor: bool,
    /// True when saga participants have no coordinator, so the runner adds one.
    pub implicit_coordinator: bool,
    /// True when replicas have no primary, so the runner adds one.
    pub implicit_primary: bool,
    /// True when lease holders have no grantor, so the runner adds one.
    pub implicit_grantor: bool,
    /// True when peers have no hub, so the runner adds one.
    pub implicit_hub: bool,
}

impl ParticipantBindings {
    /// Roles the runner binds to lab tasks.
    pub const BOUND_ROLES: &'static [&'static str] = &[
        SENDER_ROLE,
        RECEIVER_ROLE,
        SWARM_ROLE,
        SUPERVISOR_ROLE,
        WORKER_ROLE,
        SAGA_COORDINATOR_ROLE,
        SAGA_PARTICIPANT_ROLE,
        PRIMARY_ROLE,
        REPLICA_ROLE,
        LEASE_GRANTOR_ROLE,
        LEASE_HOLDER_ROLE,
        HUB_ROLE,
        PEER_ROLE,
    ];

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
    /// Spawn this many swarm members.
    Swarm { tasks: usize },
    /// Supervise the assigned workers; `None` derives the restart budget.
    Supervise { max_restarts: Option<u32> },
    /// Fail this many times under a supervisor, then succeed.
    Work { fail_times: u64 },
    /// Run a saga over the assigned participants, one step every `step_ms`.
    Coordinate { step_ms: u64 },
    /// Apply one saga step on request.
    Participate,
    /// Append `writes` entries, one round every `write_ms`, and ship the log
    /// to the assigned replicas.
    Lead { writes: u64, write_ms: u64 },
    /// Apply the log a primary ships.
    Follow,
    /// Grant one lease of `lease_ms` at a time to the assigned holders.
    Grant { lease_ms: u64 },
    /// Acquire, renew and release the assigned grantor's lease.
    Hold(LeaseTerms),
    /// Ping the assigned peers every round and time their echoes.
    Ping(PingPlan),
    /// Echo the pings of a hub.
    Echo,
}

/// How a hub pings its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PingPlan {
    rounds: u64,
    interval_ms: u64,
    timeout_ms: u64,
}

/// How a lease holder uses its grantor's lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeaseTerms {
    /// Successful renewals before the holder releases the lease.
    renewals: u64,
    /// Virtual time between requests, and each request's reply budget.
    renew_ms: u64,
    /// Time taken off each grant to allow for clock skew.
    margin_ms: u64,
    /// Virtual time before the first request.
    start_ms: u64,
}

/// One bound participant, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedParticipant {
    name: String,
    work: PlannedWork,
    lifecycle: Option<lifecycle::Plan>,
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
                SWARM_ROLE => {
                    Self::swarm_tasks(participant).map(|tasks| PlannedWork::Swarm { tasks })
                }
                SUPERVISOR_ROLE => Self::supervisor_restarts(participant)
                    .map(|max_restarts| PlannedWork::Supervise { max_restarts }),
                WORKER_ROLE => Self::worker_fail_times(participant)
                    .map(|fail_times| PlannedWork::Work { fail_times }),
                SAGA_COORDINATOR_ROLE => Self::saga_step_ms(participant)
                    .map(|step_ms| PlannedWork::Coordinate { step_ms }),
                SAGA_PARTICIPANT_ROLE => Ok(PlannedWork::Participate),
                PRIMARY_ROLE => Self::primary_writes(participant).and_then(|writes| {
                    Self::primary_write_ms(participant)
                        .map(|write_ms| PlannedWork::Lead { writes, write_ms })
                }),
                REPLICA_ROLE => Ok(PlannedWork::Follow),
                LEASE_GRANTOR_ROLE => {
                    Self::lease_ms(participant).map(|lease_ms| PlannedWork::Grant { lease_ms })
                }
                LEASE_HOLDER_ROLE => Self::lease_terms(participant).map(PlannedWork::Hold),
                HUB_ROLE => Self::ping_plan(participant).map(PlannedWork::Ping),
                PEER_ROLE => Ok(PlannedWork::Echo),
                _ => continue,
            };
            match work {
                Ok(work) => {
                    let lifecycle = if matches!(work, PlannedWork::Work { .. }) {
                        match lifecycle::Plan::parse(participant, scenario) {
                            Ok(plan) => plan,
                            Err(error) => {
                                errors.push(error);
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    participants.push(PlannedParticipant {
                        name: participant.name.clone(),
                        work,
                        lifecycle,
                    });
                }
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
        value
            .as_u64()
            .filter(|messages| *messages <= MAX_SENDER_MESSAGES)
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "messages",
                    format!(
                        "a bound sender's message count must be an integer from 0 to {MAX_SENDER_MESSAGES}"
                    ),
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

    fn swarm_tasks(participant: &Participant) -> Result<usize, ValidationError> {
        let Some(value) = participant.properties.get("tasks") else {
            return Ok(DEFAULT_SWARM_TASKS);
        };
        value
            .as_u64()
            .and_then(|tasks| usize::try_from(tasks).ok())
            .filter(|tasks| (1..=MAX_SWARM_TASKS).contains(tasks))
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "tasks",
                    format!(
                        "a bound swarm's task count must be an integer from 1 to {MAX_SWARM_TASKS}"
                    ),
                )
            })
    }

    fn supervisor_restarts(participant: &Participant) -> Result<Option<u32>, ValidationError> {
        let Some(value) = participant.properties.get("max_restarts") else {
            return Ok(None);
        };
        value
            .as_u64()
            .and_then(|restarts| u32::try_from(restarts).ok())
            .map(Some)
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "max_restarts",
                    format!(
                        "a bound supervisor's restart budget must be an integer from 0 to {}",
                        u32::MAX
                    ),
                )
            })
    }

    fn worker_fail_times(participant: &Participant) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get("fail_times") else {
            return Ok(DEFAULT_WORKER_FAIL_TIMES);
        };
        value
            .as_u64()
            .filter(|fail_times| *fail_times <= MAX_WORKER_FAIL_TIMES)
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "fail_times",
                    format!(
                        "a bound worker's failure count must be an integer from 0 to {MAX_WORKER_FAIL_TIMES}"
                    ),
                )
            })
    }

    fn saga_step_ms(participant: &Participant) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get("step_ms") else {
            return Ok(DEFAULT_SAGA_STEP_MS);
        };
        value
            .as_u64()
            .filter(|step_ms| (1..=MAX_SAGA_STEP_MS).contains(step_ms))
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "step_ms",
                    format!(
                        "a bound saga coordinator's step interval must be an integer from 1 to {MAX_SAGA_STEP_MS} milliseconds"
                    ),
                )
            })
    }

    fn primary_writes(participant: &Participant) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get("writes") else {
            return Ok(DEFAULT_PRIMARY_WRITES);
        };
        value
            .as_u64()
            .filter(|writes| *writes <= MAX_PRIMARY_WRITES)
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "writes",
                    format!(
                        "a bound primary's write count must be an integer from 0 to {MAX_PRIMARY_WRITES}"
                    ),
                )
            })
    }

    fn primary_write_ms(participant: &Participant) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get("write_ms") else {
            return Ok(DEFAULT_WRITE_MS);
        };
        value
            .as_u64()
            .filter(|write_ms| (1..=MAX_SAGA_STEP_MS).contains(write_ms))
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    "write_ms",
                    format!(
                        "a bound primary's round interval must be an integer from 1 to {MAX_SAGA_STEP_MS} milliseconds"
                    ),
                )
            })
    }

    fn lease_ms(participant: &Participant) -> Result<u64, ValidationError> {
        Self::bounded_ms(
            participant,
            "initial_lease_ms",
            DEFAULT_LEASE_MS,
            1,
            "a bound lease grantor's lease length",
        )
    }

    fn lease_terms(participant: &Participant) -> Result<LeaseTerms, ValidationError> {
        let renewals = match participant.properties.get("renewals") {
            None => DEFAULT_LEASE_RENEWALS,
            Some(value) => value
                .as_u64()
                .filter(|renewals| *renewals <= MAX_LEASE_RENEWALS)
                .ok_or_else(|| {
                    Self::property_error(
                        participant,
                        "renewals",
                        format!(
                            "a bound lease holder's renewal count must be an integer from 0 to {MAX_LEASE_RENEWALS}"
                        ),
                    )
                })?,
        };
        let what = "a bound lease holder's";
        Ok(LeaseTerms {
            renewals,
            renew_ms: Self::bounded_ms(
                participant,
                "renew_ms",
                DEFAULT_RENEW_MS,
                1,
                &format!("{what} request interval"),
            )?,
            margin_ms: Self::bounded_ms(
                participant,
                "margin_ms",
                DEFAULT_LEASE_MARGIN_MS,
                0,
                &format!("{what} skew margin"),
            )?,
            start_ms: Self::bounded_ms(
                participant,
                "start_ms",
                0,
                0,
                &format!("{what} start delay"),
            )?,
        })
    }

    fn ping_plan(participant: &Participant) -> Result<PingPlan, ValidationError> {
        let rounds = match participant.properties.get("rounds") {
            None => DEFAULT_HUB_ROUNDS,
            Some(value) => value
                .as_u64()
                .filter(|rounds| *rounds <= MAX_HUB_ROUNDS)
                .ok_or_else(|| {
                    Self::property_error(
                        participant,
                        "rounds",
                        format!(
                            "a bound hub's round count must be an integer from 0 to {MAX_HUB_ROUNDS}"
                        ),
                    )
                })?,
        };
        Ok(PingPlan {
            rounds,
            interval_ms: Self::bounded_ms(
                participant,
                "interval_ms",
                DEFAULT_HUB_INTERVAL_MS,
                1,
                "a bound hub's round interval",
            )?,
            timeout_ms: Self::bounded_ms(
                participant,
                "timeout_ms",
                DEFAULT_HUB_TIMEOUT_MS,
                1,
                "a bound hub's echo timeout",
            )?,
        })
    }

    /// Reads a millisecond property from `min` to [`MAX_SAGA_STEP_MS`].
    fn bounded_ms(
        participant: &Participant,
        key: &str,
        default: u64,
        min: u64,
        what: &str,
    ) -> Result<u64, ValidationError> {
        let Some(value) = participant.properties.get(key) else {
            return Ok(default);
        };
        value
            .as_u64()
            .filter(|ms| (min..=MAX_SAGA_STEP_MS).contains(ms))
            .ok_or_else(|| {
                Self::property_error(
                    participant,
                    key,
                    format!(
                        "{what} must be an integer from {min} to {MAX_SAGA_STEP_MS} milliseconds"
                    ),
                )
            })
    }

    /// True when a role or an opted-in worker waits on virtual-time timers.
    fn is_timed(&self) -> bool {
        self.participants.iter().any(|participant| {
            participant.lifecycle.is_some()
                || matches!(
                    participant.work,
                    PlannedWork::Coordinate { .. }
                        | PlannedWork::Participate
                        | PlannedWork::Lead { .. }
                        | PlannedWork::Follow
                        | PlannedWork::Grant { .. }
                        | PlannedWork::Hold(_)
                        | PlannedWork::Ping(_)
                        | PlannedWork::Echo
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
    Swarm,
    Supervisor,
    Worker,
    SagaCoordinator,
    SagaParticipant,
    Primary,
    Replica,
    LeaseGrantor,
    LeaseHolder,
    Hub,
    Peer,
}

impl WorkloadRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Sender => SENDER_ROLE,
            Self::Receiver => RECEIVER_ROLE,
            Self::Sink => "sink",
            Self::Swarm => SWARM_ROLE,
            Self::Supervisor => SUPERVISOR_ROLE,
            Self::Worker => WORKER_ROLE,
            Self::SagaCoordinator => SAGA_COORDINATOR_ROLE,
            Self::SagaParticipant => SAGA_PARTICIPANT_ROLE,
            Self::Primary => PRIMARY_ROLE,
            Self::Replica => REPLICA_ROLE,
            Self::LeaseGrantor => LEASE_GRANTOR_ROLE,
            Self::LeaseHolder => LEASE_HOLDER_ROLE,
            Self::Hub => HUB_ROLE,
            Self::Peer => PEER_ROLE,
        }
    }
}

/// Counters one bound task updates while it runs.
///
/// The lab polls every task on the thread that drives it, so relaxed atomics
/// are enough; they exist only because task futures must be `Send`.
#[derive(Debug, Default)]
struct WorkloadCounters {
    /// Sender: values committed through a reserved permit. Saga participant:
    /// requests applied.
    committed: AtomicU64,
    /// Drain: values any sender committed into this task's channel.
    delivered: AtomicU64,
    /// Drain: values received. Saga participant: requests received.
    received: AtomicU64,
    /// Reserves or receives that ended in cancellation.
    cancelled: AtomicU64,
    /// Sender: reserves or sends that found the receiving end gone.
    disconnected: AtomicU64,
    /// Sender: disconnects from a drain that had reported its channel closed
    /// while this sender, which holds a sending handle, was still alive. A
    /// correct channel cannot produce one.
    premature_disconnects: AtomicU64,
    /// Sender: cancellations that arrived while it held a reserved permit,
    /// which it then aborted.
    cancelled_holding: AtomicU64,
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

/// Counts a sender's disconnect. It is premature when the drain had already
/// reported its channel closed: the sender still holds a sending handle, so
/// the channel cannot really be closed (br-asupersync-nq2dgn).
fn note_disconnect(sender: &WorkloadCounters, drain: &WorkloadCounters) {
    bump(&sender.disconnected);
    if drain.drained_to_close.load(Ordering::Relaxed) {
        bump(&sender.premature_disconnects);
    }
}

/// The sending half of one drain task's channel.
#[derive(Debug, Clone)]
struct WorkloadLane {
    tx: mpsc::Sender<WorkloadMessage>,
    /// Counters of the task that drains this channel.
    drain: Arc<WorkloadCounters>,
}

/// Terminal state of one spawned lab task, read from its join handle after
/// the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JoinState {
    /// The task returned.
    Completed,
    /// The task ended in cancellation, whether or not its body returned.
    Cancelled,
    /// The task panicked.
    Panicked,
    /// The task had not reached a terminal state.
    Running,
    /// The join result was already taken.
    Consumed,
}

impl JoinState {
    fn observe(handle: &mut TaskHandle<()>) -> Self {
        match handle.try_join() {
            Ok(Some(())) => Self::Completed,
            Ok(None) => Self::Running,
            Err(JoinError::Cancelled(_)) => Self::Cancelled,
            Err(JoinError::Panicked(_)) => Self::Panicked,
            Err(JoinError::PolledAfterCompletion) => Self::Consumed,
        }
    }
}

/// A swarm member's body has not ended.
const MEMBER_UNFINISHED: u8 = 0;
/// A swarm member ran every step.
const MEMBER_COMPLETED: u8 = 1;
/// A swarm member stopped at a cancellation checkpoint.
const MEMBER_CANCELLED: u8 = 2;
/// A swarm member ran without a task context.
const MEMBER_UNEXPECTED: u8 = 3;

/// State shared by the members of one swarm.
#[derive(Debug)]
struct SwarmMembers {
    /// One `MEMBER_*` outcome per member, written when its body ends.
    outcomes: Box<[AtomicU8]>,
    /// The counter every member bumps once per step it runs.
    touches: AtomicU64,
}

impl SwarmMembers {
    fn new(members: usize) -> Self {
        Self {
            outcomes: (0..members)
                .map(|_| AtomicU8::new(MEMBER_UNFINISHED))
                .collect(),
            touches: AtomicU64::new(0),
        }
    }
}

/// How the members of one swarm ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SwarmTally {
    /// Members the runtime accepted.
    spawned: u64,
    /// Members that ran every step.
    completed: u64,
    /// Members that ended in cancellation.
    cancelled: u64,
    /// Members that panicked before their body ended.
    panicked: u64,
    /// Members that neither ended nor were cancelled.
    unfinished: u64,
    /// Members that ran without a task context.
    unexpected: u64,
}

/// Counters one bound worker updates across its generations.
#[derive(Debug, Default)]
struct WorkerState {
    /// Generations whose body started.
    attempts: AtomicU64,
    /// Generations that returned `Outcome::Err`.
    failures: AtomicU64,
    /// Failures caused by a host crash, distinct from configured failures.
    crashes: AtomicU64,
    /// Generations that stopped at a cancellation checkpoint.
    cancelled: AtomicU64,
    /// Generations whose identity or active-time clock violated the contract.
    unexpected: AtomicU64,
}

/// A worker as its supervisor runs it.
#[derive(Debug)]
struct AssignedWorker {
    name: String,
    fail_times: u64,
    state: Arc<WorkerState>,
    lifecycle: Option<Arc<lifecycle::Control>>,
}

/// How a managed supervisor's controller ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControllerExit {
    Completed,
    Cancelled,
    Failed(String),
    Panicked(String),
}

/// How the last generation of a supervised worker ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildExit {
    Succeeded,
    /// Returned `Outcome::Err` with this attempt number.
    Failed(u64),
    Cancelled,
    Panicked,
}

impl ChildExit {
    fn of(completion: &ManagedChildCompletion<u64>) -> Self {
        match &completion.task_outcome {
            Err(JoinError::Cancelled(_)) => Self::Cancelled,
            Err(JoinError::Panicked(_) | JoinError::PolledAfterCompletion) => Self::Panicked,
            Ok(()) => match &completion.outcome {
                Outcome::Ok(()) => Self::Succeeded,
                Outcome::Err(attempt) => Self::Failed(*attempt),
                Outcome::Cancelled(_) => Self::Cancelled,
                Outcome::Panicked(_) => Self::Panicked,
            },
        }
    }

    fn label(self) -> String {
        match self {
            Self::Succeeded => "succeeded".to_owned(),
            Self::Failed(attempt) => format!("failed@{attempt}"),
            Self::Cancelled => "cancelled".to_owned(),
            Self::Panicked => "panicked".to_owned(),
        }
    }
}

/// The last generation of one supervised worker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChildSummary {
    name: String,
    /// Number of the last generation; generations start at one.
    generations: u64,
    exit: ChildExit,
}

/// What a managed supervisor reported when its controller returned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SupervisorSummary {
    exit: ControllerExit,
    /// Replacement batches the shared restart budget admitted.
    restart_batches: u64,
    /// The last generation of each worker that started.
    children: Vec<ChildSummary>,
}

impl SupervisorSummary {
    fn of(report: &ManagedSupervisorReport<u64>) -> Self {
        let exit = match &report.outcome {
            Outcome::Ok(()) => ControllerExit::Completed,
            Outcome::Err(error) => ControllerExit::Failed(format!("{error:?}")),
            Outcome::Cancelled(_) => ControllerExit::Cancelled,
            Outcome::Panicked(payload) => ControllerExit::Panicked(payload.message().to_owned()),
        };
        Self {
            exit,
            restart_batches: report.restart_batches,
            children: report
                .children
                .iter()
                .map(|completion| ChildSummary {
                    name: completion.name.as_str().to_owned(),
                    generations: completion.generation.number,
                    exit: ChildExit::of(completion),
                })
                .collect(),
        }
    }
}

/// A bound supervisor, the workers it runs, and its report once it returns.
#[derive(Debug)]
struct SupervisorState {
    workers: Vec<AssignedWorker>,
    summary: Mutex<Option<SupervisorSummary>>,
}

impl AssignedWorker {
    /// Appends this worker's anomalies, judged from its supervisor's report.
    fn collect_violations(
        &self,
        supervisor: Option<&SupervisorSummary>,
        supervisor_cancelled: bool,
        violations: &mut Vec<String>,
    ) {
        let label = format!("workload:{}:{}", WorkloadRole::Worker.label(), self.name);
        let child = supervisor.and_then(|summary| {
            summary
                .children
                .iter()
                .find(|child| child.name == self.name)
        });
        let s = &self.state;
        let detail = format!(
            "fail_times={},attempts={},failures={},cancelled={},unexpected={},generations={},exit={}",
            self.fail_times,
            count(&s.attempts),
            count(&s.failures),
            count(&s.cancelled),
            count(&s.unexpected),
            child.map_or(0, |child| child.generations),
            child.map_or_else(|| "none".to_owned(), |child| child.exit.label()),
        );
        let detail = if self.lifecycle.is_some() {
            format!("{detail},crashes={}", count(&s.crashes))
        } else {
            detail
        };
        if count(&s.unexpected) > 0 {
            violations.push(format!("{label}:unexpected_outcome:{detail}"));
        }
        match child {
            Some(child) if child.exit == ChildExit::Succeeded => {
                // One-for-one, transient: every failure restarts exactly this
                // worker, and success stops it.
                if child.generations.saturating_sub(1)
                    != self.fail_times.saturating_add(count(&s.crashes))
                {
                    violations.push(format!("{label}:restart_mismatch:{detail}"));
                }
                if count(&s.attempts) != child.generations {
                    violations.push(format!("{label}:attempt_mismatch:{detail}"));
                }
            }
            Some(child) if child.exit == ChildExit::Cancelled => {}
            _ if supervisor_cancelled || count(&s.cancelled) > 0 => {}
            _ => violations.push(format!("{label}:never_succeeded:{detail}")),
        }
    }
}

/// Mixed into the lab seed for the network model's own random stream.
const NETWORK_SEED_SALT: u64 = 0x6e65_7477_6f72_6b21;

/// Latency and loss for messages between participants, from the scenario's
/// `network` section. Every directed link uses the preset's conditions, and
/// a `"from->to"` entry in `links` overrides that link's latency model
/// (without jitter) and packet loss. Corruption, duplication, reordering and
/// bandwidth are not modeled. The random stream is seeded from the lab seed
/// and drawn in message order, so a run stays deterministic.
#[derive(Debug)]
struct NetworkModel {
    preset: NetworkConditions,
    links: BTreeMap<(String, String), NetworkConditions>,
    rng: Mutex<DetRng>,
}

impl Default for NetworkModel {
    fn default() -> Self {
        Self::new(&NetworkSection::default(), 0)
    }
}

impl NetworkModel {
    fn new(section: &NetworkSection, seed: u64) -> Self {
        let preset = match section.preset {
            NetworkPreset::Ideal => NetworkConditions::ideal(),
            NetworkPreset::Local => NetworkConditions::local(),
            NetworkPreset::Lan => NetworkConditions::lan(),
            NetworkPreset::Wan => NetworkConditions::wan(),
            NetworkPreset::Satellite => NetworkConditions::satellite(),
            NetworkPreset::Congested => NetworkConditions::congested(),
            NetworkPreset::Lossy => NetworkConditions::lossy(),
        };
        let links = section
            .links
            .iter()
            .filter_map(|(key, link)| {
                let (from, to) = key.split_once("->")?;
                let mut conditions = preset.clone();
                if let Some(latency) = &link.latency {
                    conditions.latency = Self::latency_model(latency);
                    conditions.jitter = None;
                }
                if let Some(loss) = link.packet_loss {
                    conditions.packet_loss = loss;
                }
                Some(((from.trim().to_owned(), to.trim().to_owned()), conditions))
            })
            .collect();
        Self {
            preset,
            links,
            rng: Mutex::new(DetRng::new(seed ^ NETWORK_SEED_SALT)),
        }
    }

    fn latency_model(spec: &LatencySpec) -> LatencyModel {
        match *spec {
            LatencySpec::Fixed { ms } => LatencyModel::Fixed(Duration::from_millis(ms)),
            LatencySpec::Uniform { min_ms, max_ms } => LatencyModel::Uniform {
                min: Duration::from_millis(min_ms),
                max: Duration::from_millis(max_ms),
            },
            LatencySpec::Normal { mean_ms, stddev_ms } => LatencyModel::Normal {
                mean: Duration::from_millis(mean_ms),
                std_dev: Duration::from_millis(stddev_ms),
            },
        }
    }

    /// How long a message from `from` to `to` takes, or `None` when the link
    /// drops it.
    fn transit(&self, from: &str, to: &str) -> Option<Duration> {
        let conditions = self
            .links
            .get(&(from.to_owned(), to.to_owned()))
            .unwrap_or(&self.preset);
        let mut rng = self.rng.lock();
        if conditions.packet_loss > 0.0 {
            // 53 random bits as a fraction in [0, 1).
            #[allow(clippy::cast_precision_loss)]
            let draw = (rng.next_u64() >> 11) as f64 / (1_u64 << 53) as f64;
            if draw < conditions.packet_loss {
                return None;
            }
        }
        let latency = conditions.latency.sample(&mut rng);
        let jitter = conditions
            .jitter
            .as_ref()
            .map_or(Duration::ZERO, |jitter| jitter.sample(&mut rng));
        Some(latency.saturating_add(jitter))
    }
}

/// Waits out a network delay; a zero delay does not touch the timer wheel.
async fn transit_delay(cx: &Cx, delay: Duration) {
    if !delay.is_zero() {
        crate::time::sleep(cx.now(), delay).await;
    }
}

/// Links between participants that a `partition` fault cut and no `heal`
/// restored yet, as unordered name pairs.
#[derive(Debug, Default)]
struct PartitionTable {
    cut: Mutex<BTreeSet<(String, String)>>,
}

impl PartitionTable {
    fn link(a: &str, b: &str) -> (String, String) {
        if a <= b {
            (a.to_owned(), b.to_owned())
        } else {
            (b.to_owned(), a.to_owned())
        }
    }

    /// Applies a `partition` or `heal` fault between two named participants.
    fn apply(&self, fault: &FaultEvent) {
        let endpoint = |key: &str| fault.args.get(key).and_then(serde_json::Value::as_str);
        let (Some(from), Some(to)) = (endpoint("from"), endpoint("to")) else {
            return;
        };
        let link = Self::link(from, to);
        match fault.action {
            FaultAction::Partition => {
                self.cut.lock().insert(link);
            }
            FaultAction::Heal => {
                self.cut.lock().remove(&link);
            }
            _ => {}
        }
    }

    fn is_cut(&self, a: &str, b: &str) -> bool {
        self.cut.lock().contains(&Self::link(a, b))
    }
}

/// Clock offsets of participants, in milliseconds. A `clock_skew` fault sets
/// its `host`'s offset to `skew_ms`, and `clock_reset` sets it back to zero.
/// A participant's clock reads the lab's virtual time plus its offset, and
/// never reads below zero.
#[derive(Debug, Default)]
struct ClockTable {
    offsets: Mutex<BTreeMap<String, i64>>,
}

impl ClockTable {
    /// Applies a `clock_skew` or `clock_reset` fault.
    fn apply(&self, fault: &FaultEvent) {
        let Some(host) = fault.args.get("host").and_then(serde_json::Value::as_str) else {
            return;
        };
        match fault.action {
            FaultAction::ClockSkew => {
                if let Some(skew) = fault
                    .args
                    .get("skew_ms")
                    .and_then(serde_json::Value::as_i64)
                {
                    self.offsets.lock().insert(host.to_owned(), skew);
                }
            }
            FaultAction::ClockReset => {
                self.offsets.lock().remove(host);
            }
            _ => {}
        }
    }

    /// The time `name`'s clock reads when the lab's virtual time is `now`.
    fn local(&self, name: &str, now: Time) -> Time {
        let offset_ms = self.offsets.lock().get(name).copied().unwrap_or(0);
        let nanos = i128::from(now.as_nanos()) + i128::from(offset_ms) * 1_000_000;
        Time::from_nanos(u64::try_from(nanos.max(0)).unwrap_or(u64::MAX))
    }
}

/// An apply request; the participant replies whether it applied its step.
#[derive(Debug)]
struct SagaRequest {
    reply: oneshot::Sender<bool>,
}

/// One saga participant as its coordinator drives it.
#[derive(Debug)]
struct SagaStepTarget {
    name: String,
    /// The participant's step state, `STEP_*`. It stands for the participant's
    /// durable record, which a compensation updates directly.
    step: Arc<AtomicU8>,
    requests: mpsc::Sender<SagaRequest>,
}

/// How a coordinator's saga ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SagaEnd {
    Completed,
    /// Aborted for this reason.
    Aborted(String),
    /// The coordinator was cancelled, and aborted.
    Cancelled,
}

impl SagaEnd {
    fn label(&self) -> String {
        match self {
            Self::Completed => "completed".to_owned(),
            Self::Aborted(reason) => format!("aborted({reason})"),
            Self::Cancelled => "cancelled".to_owned(),
        }
    }
}

/// A bound coordinator's participants and what its saga did.
#[derive(Debug)]
struct SagaRecord {
    /// Participant names and step states, in step order.
    participants: Vec<(String, Arc<AtomicU8>)>,
    /// Steps whose compensation the saga registered.
    registered: AtomicU64,
    /// Requests and replies lost on a cut link or dropped by the network.
    lost: AtomicU64,
    /// Step indices in the order their compensations ran.
    compensated: Mutex<Vec<usize>>,
    end: Mutex<Option<SagaEnd>>,
}

const fn step_label(state: u8) -> &'static str {
    match state {
        STEP_PENDING => "pending",
        STEP_APPLIED => "applied",
        STEP_UNDONE => "undone",
        STEP_FENCED => "fenced",
        _ => "invalid",
    }
}

/// Undoes an applied step, or fences one that was never applied so that a
/// request arriving later is refused.
fn compensate_step(step: &AtomicU8) -> String {
    // The participant's only write is pending -> applied, so an applied step
    // stays applied until this store.
    match step.compare_exchange(
        STEP_PENDING,
        STEP_FENCED,
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        Ok(_) => "fenced".to_owned(),
        Err(STEP_APPLIED) => {
            step.store(STEP_UNDONE, Ordering::Relaxed);
            "undone".to_owned()
        }
        Err(state) => format!("already {}", step_label(state)),
    }
}

impl SagaRecord {
    /// Appends this saga's anomalies. `cancelled` is true when the
    /// coordinator task ended cancelled.
    fn collect_violations(&self, label: &str, cancelled: bool, violations: &mut Vec<String>) {
        let end = self.end.lock().clone();
        let registered = usize::try_from(count(&self.registered)).unwrap_or(usize::MAX);
        let compensated = self.compensated.lock().clone();
        let states: Vec<(&str, u8)> = self
            .participants
            .iter()
            .map(|(name, step)| (name.as_str(), step.load(Ordering::Relaxed)))
            .collect();
        let detail = format!(
            "end={},registered={registered},lost={},compensated={compensated:?},steps=[{}]",
            end.as_ref()
                .map_or_else(|| "none".to_owned(), SagaEnd::label),
            count(&self.lost),
            states
                .iter()
                .map(|(name, state)| format!("{name}={}", step_label(*state)))
                .collect::<Vec<_>>()
                .join(","),
        );
        if end == Some(SagaEnd::Completed) {
            if states.iter().any(|(_, state)| *state != STEP_APPLIED) {
                violations.push(format!("{label}:incomplete_commit:{detail}"));
            }
            if !compensated.is_empty() {
                violations.push(format!("{label}:compensated_after_commit:{detail}"));
            }
            return;
        }
        // Aborted, cancelled, or never finished.
        if end.is_none() && !cancelled {
            violations.push(format!("{label}:no_end:{detail}"));
        }
        if states.iter().any(|(_, state)| *state == STEP_APPLIED) {
            violations.push(format!("{label}:applied_after_abort:{detail}"));
        }
        if compensated.iter().copied().ne((0..registered).rev()) {
            violations.push(format!("{label}:compensation_order:{detail}"));
        }
    }
}

/// Entries a primary ships to a replica: its log from index `from` on. The
/// replica replies with its log length after applying them.
#[derive(Debug)]
struct ReplicationBatch {
    from: usize,
    entries: Vec<u64>,
    reply: oneshot::Sender<usize>,
}

/// One replica as its primary ships to it.
#[derive(Debug)]
struct ReplicaTarget {
    name: String,
    batches: mpsc::Sender<ReplicationBatch>,
}

/// A bound primary's log, its replicas' applied logs, and how shipping went.
#[derive(Debug, Default)]
struct ReplicationRecord {
    /// The primary's log; entry `i` is `i`.
    log: Mutex<Vec<u64>>,
    /// Replica names and applied logs, in assignment order.
    replicas: Vec<(String, Arc<Mutex<Vec<u64>>>)>,
    /// Batches and replies lost on a cut link or dropped by the network.
    lost: AtomicU64,
    /// Every replica acknowledged the whole log before the primary stopped.
    converged: AtomicBool,
}

impl ReplicationRecord {
    /// Appends this primary's anomalies: a replica whose applied log is not
    /// a prefix of the primary's, or a primary that never finished although
    /// it was not cancelled. Convergence depends on the scenario's network
    /// and faults, so it is recorded, not required.
    fn collect_violations(
        &self,
        label: &str,
        finished: bool,
        cancelled: bool,
        violations: &mut Vec<String>,
    ) {
        let log = self.log.lock().clone();
        for (name, replica) in &self.replicas {
            let replica = replica.lock().clone();
            if !log.starts_with(&replica) {
                violations.push(format!(
                    "{label}:diverged:{name}:primary_len={},replica={replica:?}",
                    log.len()
                ));
            }
        }
        if !finished && !cancelled {
            violations.push(format!(
                "{label}:no_end:log_len={},lost={}",
                log.len(),
                count(&self.lost)
            ));
        }
    }
}

/// A holder's request to its grantor: acquire or renew the lease, or
/// release it. The grantor replies with the grant's length in milliseconds
/// when it grants, and `None` when another holder has the lease or the
/// request was a release.
#[derive(Debug)]
struct LeaseRequest {
    holder: String,
    release: bool,
    reply: oneshot::Sender<Option<u64>>,
}

/// One holder's grantor, as the holder reaches it.
#[derive(Debug, Clone)]
struct GrantorTarget {
    name: String,
    requests: mpsc::Sender<LeaseRequest>,
    record: Arc<LeaseRecord>,
}

/// How a holder's tenure ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenureEnd {
    /// It made its renewals and released the lease.
    Released,
    /// Its own clock reached the end of its last grant.
    Expired,
    /// It was cancelled while it held the lease.
    Cancelled,
}

/// When one holder believed it held the lease, in the lab's virtual time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tenure {
    holder: String,
    start: Time,
    end: Time,
    ending: TenureEnd,
}

/// A grantor's lease: its holders' tenures and how its requests went.
#[derive(Debug, Default)]
struct LeaseRecord {
    tenures: Mutex<Vec<Tenure>>,
    /// Acquisitions and renewals the grantor granted.
    grants: AtomicU64,
    /// Requests refused because another holder had the lease.
    refused: AtomicU64,
    /// Requests and replies lost on a cut link or dropped by the network.
    lost: AtomicU64,
}

impl LeaseRecord {
    /// Appends a violation for every two holders whose tenures overlap: for
    /// a while both believed they held the one lease.
    fn collect_violations(&self, label: &str, violations: &mut Vec<String>) {
        let tenures = self.tenures.lock().clone();
        for (index, a) in tenures.iter().enumerate() {
            for b in &tenures[index + 1..] {
                if a.holder != b.holder && a.start < b.end && b.start < a.end {
                    violations.push(format!(
                        "{label}:double_holder:{}@{}..{}ms,{}@{}..{}ms",
                        a.holder,
                        a.start.as_millis(),
                        a.end.as_millis(),
                        b.holder,
                        b.start.as_millis(),
                        b.end.as_millis(),
                    ));
                }
            }
        }
    }
}

/// A hub's ping; the peer echoes its sequence number.
#[derive(Debug)]
struct Ping {
    seq: u64,
    reply: oneshot::Sender<u64>,
}

/// One peer as its hub pings it.
#[derive(Debug)]
struct PeerTarget {
    name: String,
    pings: mpsc::Sender<Ping>,
}

/// What a hub saw of one peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeerStats {
    /// Pings whose echo came back in time.
    echoed: u64,
    /// Pings or echoes lost, late, or refused by a peer that was gone.
    lost: u64,
    /// Echoes that carried another ping's sequence number.
    mismatched: u64,
    /// Round trips of the echoed pings, in virtual time.
    round_trips: Vec<Duration>,
}

/// A bound hub's peers and what it saw of each.
#[derive(Debug, Default)]
struct HubRecord {
    /// Peer names and their statistics, in assignment order.
    peers: Vec<(String, Mutex<PeerStats>)>,
    /// Pings and echoes lost on a cut link or dropped by the network.
    lost: AtomicU64,
}

impl HubRecord {
    /// Appends this hub's anomalies: an echo of the wrong ping, or a hub
    /// that never finished although it was not cancelled.
    fn collect_violations(
        &self,
        label: &str,
        finished: bool,
        cancelled: bool,
        violations: &mut Vec<String>,
    ) {
        for (name, stats) in &self.peers {
            let stats = stats.lock();
            if stats.mismatched > 0 {
                violations.push(format!(
                    "{label}:echo_mismatch:{name}:mismatched={},echoed={}",
                    stats.mismatched, stats.echoed
                ));
            }
        }
        if !finished && !cancelled {
            violations.push(format!("{label}:no_end:lost={}", count(&self.lost)));
        }
    }
}

/// Role-specific state of one bound task.
#[derive(Debug)]
enum BoundDetail {
    /// Sender, receiver or sink: the task counters hold everything.
    Channel,
    /// The members of a swarm.
    Swarm(Arc<SwarmMembers>),
    /// A supervisor and the workers it runs.
    Supervisor(Arc<SupervisorState>),
    /// A worker; its supervisor runs its generations and reports on it.
    Worker,
    /// A saga coordinator and its participants' steps.
    SagaCoordinator(Arc<SagaRecord>),
    /// A saga participant; its coordinator's record holds its step.
    SagaParticipant,
    /// A primary and its replicas' logs.
    Primary(Arc<ReplicationRecord>),
    /// A replica; its primary's record holds its log.
    Replica,
    /// A lease grantor and its holders' tenures.
    LeaseGrantor(Arc<LeaseRecord>),
    /// A lease holder; its grantor's record holds its tenure.
    LeaseHolder,
    /// A hub and what it saw of its peers.
    Hub(Arc<HubRecord>),
    /// A peer; its hub's record holds what the hub saw of it.
    Peer,
}

/// One bound task and its counters.
#[derive(Debug)]
struct BoundTask {
    name: String,
    role: WorkloadRole,
    /// Planned work: values to send (sender), members (swarm), failures
    /// before success (worker) or the restart budget (supervisor); zero for
    /// drains.
    planned: u64,
    /// Why the runtime refused to spawn the task, if it did.
    spawn_refusal: Option<String>,
    counters: Arc<WorkloadCounters>,
    detail: BoundDetail,
    /// Terminal states of the lab tasks spawned for this participant, in
    /// spawn order, read after the run.
    joins: Vec<JoinState>,
}

impl BoundTask {
    fn counter_summary(&self) -> String {
        let c = &self.counters;
        format!(
            "planned={},committed={},delivered={},received={},cancelled={},cancelled_holding={},disconnected={},out_of_order={},unexpected={},drained_to_close={},finished={}",
            self.planned,
            count(&c.committed),
            count(&c.delivered),
            count(&c.received),
            count(&c.cancelled),
            count(&c.cancelled_holding),
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
        // A task that panicked never reached its own accounting, so its
        // counters can look clean; its join handle says what happened. A
        // swarm counts its members' panics itself (br-asupersync-nq2dgn).
        if !matches!(self.detail, BoundDetail::Swarm(_))
            && self.joins.contains(&JoinState::Panicked)
        {
            violations.push(format!("{label}:panicked:joins={:?}", self.joins));
        }
        match &self.detail {
            BoundDetail::Channel => self.collect_channel_violations(&label, violations),
            BoundDetail::Swarm(members) => {
                self.collect_swarm_violations(&label, members, violations);
            }
            BoundDetail::Supervisor(state) => {
                self.collect_supervisor_violations(&label, state, violations);
            }
            // The worker's supervisor judges it from the managed report.
            BoundDetail::Worker => {}
            BoundDetail::SagaCoordinator(record) => {
                if count(&self.counters.unexpected) > 0 {
                    violations.push(format!("{label}:unexpected_outcome:no_task_context"));
                }
                let cancelled = self.joins.first() == Some(&JoinState::Cancelled);
                record.collect_violations(&label, cancelled, violations);
            }
            BoundDetail::SagaParticipant => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 || count(&c.committed) > 1 {
                    violations.push(format!(
                        "{label}:unexpected_outcome:requests={},applied={},cancelled={},unexpected={}",
                        count(&c.received),
                        count(&c.committed),
                        count(&c.cancelled),
                        count(&c.unexpected),
                    ));
                }
            }
            BoundDetail::Primary(record) => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 {
                    violations.push(format!("{label}:unexpected_outcome:no_task_context"));
                }
                let cancelled =
                    count(&c.cancelled) > 0 || self.joins.first() == Some(&JoinState::Cancelled);
                record.collect_violations(
                    &label,
                    c.finished.load(Ordering::Relaxed),
                    cancelled,
                    violations,
                );
            }
            BoundDetail::Replica => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 {
                    violations.push(format!(
                        "{label}:unexpected_outcome:batches={},applied={},unexpected={}",
                        count(&c.received),
                        count(&c.committed),
                        count(&c.unexpected),
                    ));
                }
            }
            BoundDetail::LeaseGrantor(record) => {
                if count(&self.counters.unexpected) > 0 {
                    violations.push(format!("{label}:unexpected_outcome:no_task_context"));
                }
                record.collect_violations(&label, violations);
            }
            BoundDetail::LeaseHolder => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 {
                    violations.push(format!(
                        "{label}:unexpected_outcome:grants={},unexpected={}",
                        count(&c.received),
                        count(&c.unexpected),
                    ));
                }
                let cancelled =
                    count(&c.cancelled) > 0 || self.joins.first() == Some(&JoinState::Cancelled);
                if !c.finished.load(Ordering::Relaxed) && !cancelled {
                    violations.push(format!("{label}:no_end:grants={}", count(&c.received)));
                }
            }
            BoundDetail::Hub(record) => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 {
                    violations.push(format!("{label}:unexpected_outcome:no_task_context"));
                }
                let cancelled =
                    count(&c.cancelled) > 0 || self.joins.first() == Some(&JoinState::Cancelled);
                record.collect_violations(
                    &label,
                    c.finished.load(Ordering::Relaxed),
                    cancelled,
                    violations,
                );
            }
            BoundDetail::Peer => {
                let c = &self.counters;
                if count(&c.unexpected) > 0 {
                    violations.push(format!(
                        "{label}:unexpected_outcome:pings={},unexpected={}",
                        count(&c.received),
                        count(&c.unexpected),
                    ));
                }
            }
        }
    }

    /// Classifies every swarm member from its body outcome and join state.
    fn swarm_tally(&self, members: &SwarmMembers) -> SwarmTally {
        let mut tally = SwarmTally {
            spawned: u64::try_from(self.joins.len()).unwrap_or(u64::MAX),
            ..SwarmTally::default()
        };
        for (outcome, join) in members.outcomes.iter().zip(&self.joins) {
            let bucket = match outcome.load(Ordering::Relaxed) {
                MEMBER_COMPLETED => &mut tally.completed,
                MEMBER_CANCELLED => &mut tally.cancelled,
                MEMBER_UNEXPECTED => &mut tally.unexpected,
                // The body never ended: the join state says why.
                _ => match join {
                    JoinState::Cancelled => &mut tally.cancelled,
                    JoinState::Panicked => &mut tally.panicked,
                    JoinState::Completed | JoinState::Running | JoinState::Consumed => {
                        &mut tally.unfinished
                    }
                },
            };
            *bucket += 1;
        }
        tally
    }

    fn collect_swarm_violations(
        &self,
        label: &str,
        members: &SwarmMembers,
        violations: &mut Vec<String>,
    ) {
        let tally = self.swarm_tally(members);
        let summary = format!(
            "planned={},spawned={},completed={},cancelled={},panicked={},unfinished={},unexpected={},touches={}",
            self.planned,
            tally.spawned,
            tally.completed,
            tally.cancelled,
            tally.panicked,
            tally.unfinished,
            tally.unexpected,
            count(&members.touches),
        );
        if tally.unexpected > 0 {
            violations.push(format!("{label}:unexpected_outcome:{summary}"));
        }
        if tally.completed + tally.cancelled != tally.spawned {
            violations.push(format!("{label}:incomplete:{summary}"));
        }
    }

    fn collect_supervisor_violations(
        &self,
        label: &str,
        state: &SupervisorState,
        violations: &mut Vec<String>,
    ) {
        if count(&self.counters.unexpected) > 0 {
            violations.push(format!("{label}:unexpected_outcome:no_task_context"));
        }
        let summary = state.summary.lock().clone();
        let cancelled = match summary.as_ref().map(|summary| &summary.exit) {
            Some(ControllerExit::Completed) => false,
            Some(ControllerExit::Cancelled) => true,
            Some(ControllerExit::Failed(error)) => {
                violations.push(format!("{label}:supervisor_error:{error}"));
                false
            }
            Some(ControllerExit::Panicked(message)) => {
                violations.push(format!("{label}:supervisor_panicked:{message}"));
                false
            }
            // The controller returned no report: only cancellation excuses it.
            None => {
                let join = self.joins.first().copied();
                let cancelled = join == Some(JoinState::Cancelled);
                if !cancelled {
                    violations.push(format!("{label}:no_report:join={join:?}"));
                }
                cancelled
            }
        };
        if let Some(summary) = &summary {
            // One-for-one: each admitted batch restarts exactly one worker.
            // Cancellation may stop a batch after it was counted.
            let restarts: u64 = summary
                .children
                .iter()
                .map(|child| child.generations.saturating_sub(1))
                .sum();
            if summary.exit == ControllerExit::Completed && summary.restart_batches != restarts {
                violations.push(format!(
                    "{label}:restart_batches_mismatch:batches={},restarts={restarts}",
                    summary.restart_batches
                ));
            }
        }
        for worker in &state.workers {
            worker.collect_violations(summary.as_ref(), cancelled, violations);
        }
    }

    fn collect_channel_violations(&self, label: &str, violations: &mut Vec<String>) {
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
        if count(&c.premature_disconnects) > 0 {
            violations.push(format!(
                "{label}:premature_disconnect:premature={},{}",
                count(&c.premature_disconnects),
                self.counter_summary()
            ));
        }
    }
}

/// The bound participant tasks of one run.
#[derive(Debug, Default)]
struct ParticipantWorkload {
    tasks: Vec<BoundTask>,
    /// Join handles with the index of their task record, held until the run
    /// is reported.
    handles: Vec<(usize, TaskHandle<()>)>,
    /// Links cut by `partition` faults; saga coordinators consult it.
    partitions: Arc<PartitionTable>,
    /// Latency and loss of messages between participants.
    network: Arc<NetworkModel>,
    /// Participant clock offsets from `clock_skew` faults; lease roles read them.
    clocks: Arc<ClockTable>,
    /// Opted-in workers whose actual generations receive lifecycle faults.
    lifecycle: Vec<Arc<lifecycle::Control>>,
    /// True when some task waits on virtual-time timers.
    timed: bool,
}

/// Work a bound participant was given before its task is spawned.
enum Endpoint {
    Send {
        messages: u64,
    },
    Drain {
        rx: mpsc::Receiver<WorkloadMessage>,
    },
    Swarm {
        tasks: usize,
    },
    Supervise {
        max_restarts: Option<u32>,
    },
    Work {
        fail_times: u64,
    },
    Coordinate {
        step_ms: u64,
    },
    Participate {
        requests: mpsc::Receiver<SagaRequest>,
        step: Arc<AtomicU8>,
    },
    Lead {
        writes: u64,
        write_ms: u64,
    },
    Follow {
        batches: mpsc::Receiver<ReplicationBatch>,
        log: Arc<Mutex<Vec<u64>>>,
    },
    Grant {
        lease_ms: u64,
        requests: mpsc::Receiver<LeaseRequest>,
        record: Arc<LeaseRecord>,
    },
    Hold {
        terms: LeaseTerms,
        /// Index of the holder's grantor, chosen once every grantor exists.
        grantor: usize,
    },
    Ping {
        plan: PingPlan,
    },
    Echo {
        pings: mpsc::Receiver<Ping>,
    },
}

/// A replica's shipping endpoint and applied log, before its primary is spawned.
type AssignedReplica = (ReplicaTarget, Arc<Mutex<Vec<u64>>>);

impl ParticipantWorkload {
    /// Spawns the planned tasks in a new root region and schedules them.
    ///
    /// An empty plan spawns nothing and creates no region, so a scenario
    /// without bound participants keeps the empty-lab trace it always had.
    fn spawn(runtime: &mut LabRuntime, plan: &WorkloadPlan, network: &NetworkSection) -> Self {
        let mut workload = Self {
            network: Arc::new(NetworkModel::new(network, runtime.config().seed)),
            timed: plan.is_timed(),
            ..Self::default()
        };
        if plan.participants.is_empty() {
            return workload;
        }
        let root = runtime.state.create_root_region(Budget::INFINITE);

        // Pass 1: a counter set per participant, a channel per receiver and a
        // supervisor per worker, so that every sender sees the full lane list
        // and every supervisor its full worker list.
        let counters: Vec<Arc<WorkloadCounters>> = plan
            .participants
            .iter()
            .map(|_| Arc::new(WorkloadCounters::default()))
            .collect();
        let supervisor_count = plan
            .participants
            .iter()
            .filter(|participant| matches!(participant.work, PlannedWork::Supervise { .. }))
            .count();
        // Worker `n`, in declaration order, goes to supervisor
        // `n % supervisor_count`, also in declaration order.
        let mut supervised: Vec<Vec<AssignedWorker>> =
            (0..supervisor_count).map(|_| Vec::new()).collect();
        let mut orphans = Vec::new();
        // Saga participants go to the coordinators the same way.
        let coordinator_count = plan
            .participants
            .iter()
            .filter(|participant| matches!(participant.work, PlannedWork::Coordinate { .. }))
            .count();
        let mut coordinated: Vec<Vec<SagaStepTarget>> =
            (0..coordinator_count).map(|_| Vec::new()).collect();
        let mut uncoordinated = Vec::new();
        // Replicas go to the primaries the same way.
        let primary_count = plan
            .participants
            .iter()
            .filter(|participant| matches!(participant.work, PlannedWork::Lead { .. }))
            .count();
        let mut led: Vec<Vec<AssignedReplica>> = (0..primary_count).map(|_| Vec::new()).collect();
        let mut unled = Vec::new();
        // Lease holders go to the grantors the same way.
        let grantor_count = plan
            .participants
            .iter()
            .filter(|participant| matches!(participant.work, PlannedWork::Grant { .. }))
            .count();
        let mut grantors: Vec<GrantorTarget> = Vec::with_capacity(grantor_count.max(1));
        // Peers go to the hubs the same way.
        let hub_count = plan
            .participants
            .iter()
            .filter(|participant| matches!(participant.work, PlannedWork::Ping(_)))
            .count();
        let mut pinged: Vec<Vec<PeerTarget>> = (0..hub_count).map(|_| Vec::new()).collect();
        let mut unpinged = Vec::new();
        let mut peer_total = 0_usize;
        let mut lanes = Vec::new();
        let mut endpoints = Vec::with_capacity(plan.participants.len());
        let mut sender_total = 0_usize;
        let mut worker_total = 0_usize;
        let mut saga_participant_total = 0_usize;
        let mut replica_total = 0_usize;
        let mut holder_total = 0_usize;
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
                PlannedWork::Swarm { tasks } => endpoints.push(Endpoint::Swarm { tasks }),
                PlannedWork::Supervise { max_restarts } => {
                    endpoints.push(Endpoint::Supervise { max_restarts });
                }
                PlannedWork::Work { fail_times } => {
                    let lifecycle = participant.lifecycle.as_ref().map(|plan| {
                        let control = Arc::new(lifecycle::Control::new(plan.clone(), runtime.now()));
                        workload.lifecycle.push(Arc::clone(&control));
                        control
                    });
                    let worker = AssignedWorker {
                        name: participant.name.clone(),
                        fail_times,
                        state: Arc::new(WorkerState::default()),
                        lifecycle,
                    };
                    if supervisor_count == 0 {
                        orphans.push(worker);
                    } else {
                        supervised[worker_total % supervisor_count].push(worker);
                    }
                    worker_total += 1;
                    endpoints.push(Endpoint::Work { fail_times });
                }
                PlannedWork::Coordinate { step_ms } => {
                    endpoints.push(Endpoint::Coordinate { step_ms });
                }
                PlannedWork::Participate => {
                    let (tx, requests) = mpsc::channel(1);
                    let step = Arc::new(AtomicU8::new(STEP_PENDING));
                    let target = SagaStepTarget {
                        name: participant.name.clone(),
                        step: Arc::clone(&step),
                        requests: tx,
                    };
                    if coordinator_count == 0 {
                        uncoordinated.push(target);
                    } else {
                        coordinated[saga_participant_total % coordinator_count].push(target);
                    }
                    saga_participant_total += 1;
                    endpoints.push(Endpoint::Participate { requests, step });
                }
                PlannedWork::Lead { writes, write_ms } => {
                    endpoints.push(Endpoint::Lead { writes, write_ms });
                }
                PlannedWork::Follow => {
                    let (tx, batches) = mpsc::channel(1);
                    let log = Arc::new(Mutex::new(Vec::new()));
                    let target = ReplicaTarget {
                        name: participant.name.clone(),
                        batches: tx,
                    };
                    let replica = (target, Arc::clone(&log));
                    if primary_count == 0 {
                        unled.push(replica);
                    } else {
                        led[replica_total % primary_count].push(replica);
                    }
                    replica_total += 1;
                    endpoints.push(Endpoint::Follow { batches, log });
                }
                PlannedWork::Grant { lease_ms } => {
                    let (tx, requests) = mpsc::channel(1);
                    let record = Arc::new(LeaseRecord::default());
                    grantors.push(GrantorTarget {
                        name: participant.name.clone(),
                        requests: tx,
                        record: Arc::clone(&record),
                    });
                    endpoints.push(Endpoint::Grant {
                        lease_ms,
                        requests,
                        record,
                    });
                }
                PlannedWork::Hold(terms) => {
                    endpoints.push(Endpoint::Hold {
                        terms,
                        grantor: holder_total % grantor_count.max(1),
                    });
                    holder_total += 1;
                }
                PlannedWork::Ping(plan) => endpoints.push(Endpoint::Ping { plan }),
                PlannedWork::Echo => {
                    let (tx, pings) = mpsc::channel(1);
                    let target = PeerTarget {
                        name: participant.name.clone(),
                        pings: tx,
                    };
                    if hub_count == 0 {
                        unpinged.push(target);
                    } else {
                        pinged[peer_total % hub_count].push(target);
                    }
                    peer_total += 1;
                    endpoints.push(Endpoint::Echo { pings });
                }
            }
        }
        let implicit_grantor = if grantor_count == 0 && holder_total > 0 {
            let (tx, requests) = mpsc::channel(1);
            let record = Arc::new(LeaseRecord::default());
            grantors.push(GrantorTarget {
                name: IMPLICIT_GRANTOR_NAME.to_owned(),
                requests: tx,
                record: Arc::clone(&record),
            });
            Some((requests, record))
        } else {
            None
        };
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

        // Pass 2: spawn in declaration order, then the sink, then the
        // implicit supervisor, then the implicit coordinator.
        let mut sender_index = 0_usize;
        let mut supervised = supervised.into_iter();
        let mut coordinated = coordinated.into_iter();
        let mut led = led.into_iter();
        let mut pinged = pinged.into_iter();
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
                Endpoint::Swarm { tasks } => {
                    workload.spawn_swarm(runtime, root, &participant.name, tasks, task_counters);
                }
                Endpoint::Supervise { max_restarts } => {
                    let workers = supervised.next().unwrap_or_default();
                    workload.spawn_supervisor(
                        runtime,
                        root,
                        &participant.name,
                        max_restarts,
                        workers,
                        task_counters,
                    );
                }
                Endpoint::Work { fail_times } => {
                    // The worker's supervisor spawns its generations.
                    workload.push_task(
                        &participant.name,
                        WorkloadRole::Worker,
                        fail_times,
                        task_counters,
                        BoundDetail::Worker,
                    );
                }
                Endpoint::Coordinate { step_ms } => {
                    let targets = coordinated.next().unwrap_or_default();
                    workload.spawn_coordinator(
                        runtime,
                        root,
                        &participant.name,
                        step_ms,
                        targets,
                        task_counters,
                    );
                }
                Endpoint::Participate { requests, step } => {
                    let owner = workload.push_task(
                        &participant.name,
                        WorkloadRole::SagaParticipant,
                        1,
                        Arc::clone(&task_counters),
                        BoundDetail::SagaParticipant,
                    );
                    let body = run_saga_participant(requests, step, task_counters);
                    if let Err(refusal) = workload.spawn_owned(runtime, root, owner, body) {
                        workload.tasks[owner].spawn_refusal = Some(refusal);
                    }
                }
                Endpoint::Lead { writes, write_ms } => {
                    let replicas = led.next().unwrap_or_default();
                    workload.spawn_primary(
                        runtime,
                        root,
                        &participant.name,
                        writes,
                        write_ms,
                        replicas,
                        task_counters,
                    );
                }
                Endpoint::Follow { batches, log } => {
                    let owner = workload.push_task(
                        &participant.name,
                        WorkloadRole::Replica,
                        0,
                        Arc::clone(&task_counters),
                        BoundDetail::Replica,
                    );
                    let body = run_replica(batches, log, task_counters);
                    if let Err(refusal) = workload.spawn_owned(runtime, root, owner, body) {
                        workload.tasks[owner].spawn_refusal = Some(refusal);
                    }
                }
                Endpoint::Grant {
                    lease_ms,
                    requests,
                    record,
                } => {
                    workload.spawn_grantor(
                        runtime,
                        root,
                        &participant.name,
                        lease_ms,
                        requests,
                        record,
                        task_counters,
                    );
                }
                Endpoint::Hold { terms, grantor } => {
                    let owner = workload.push_task(
                        &participant.name,
                        WorkloadRole::LeaseHolder,
                        terms.renewals,
                        Arc::clone(&task_counters),
                        BoundDetail::LeaseHolder,
                    );
                    let Some(grantor) = grantors.get(grantor).cloned() else {
                        workload.tasks[owner].spawn_refusal = Some("no lease grantor".to_owned());
                        continue;
                    };
                    let body = run_lease_holder(
                        participant.name.clone(),
                        grantor,
                        terms,
                        Arc::clone(&workload.partitions),
                        Arc::clone(&workload.network),
                        Arc::clone(&workload.clocks),
                        task_counters,
                    );
                    if let Err(refusal) = workload.spawn_owned(runtime, root, owner, body) {
                        workload.tasks[owner].spawn_refusal = Some(refusal);
                    }
                }
                Endpoint::Ping { plan } => {
                    let peers = pinged.next().unwrap_or_default();
                    workload.spawn_hub(
                        runtime,
                        root,
                        &participant.name,
                        plan,
                        peers,
                        task_counters,
                    );
                }
                Endpoint::Echo { pings } => {
                    let owner = workload.push_task(
                        &participant.name,
                        WorkloadRole::Peer,
                        0,
                        Arc::clone(&task_counters),
                        BoundDetail::Peer,
                    );
                    let body = run_peer(pings, task_counters);
                    if let Err(refusal) = workload.spawn_owned(runtime, root, owner, body) {
                        workload.tasks[owner].spawn_refusal = Some(refusal);
                    }
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
        if !orphans.is_empty() {
            workload.spawn_supervisor(
                runtime,
                root,
                IMPLICIT_SUPERVISOR_NAME,
                None,
                orphans,
                Arc::new(WorkloadCounters::default()),
            );
        }
        if !uncoordinated.is_empty() {
            workload.spawn_coordinator(
                runtime,
                root,
                IMPLICIT_COORDINATOR_NAME,
                DEFAULT_SAGA_STEP_MS,
                uncoordinated,
                Arc::new(WorkloadCounters::default()),
            );
        }
        if !unled.is_empty() {
            workload.spawn_primary(
                runtime,
                root,
                IMPLICIT_PRIMARY_NAME,
                DEFAULT_PRIMARY_WRITES,
                DEFAULT_WRITE_MS,
                unled,
                Arc::new(WorkloadCounters::default()),
            );
        }
        if let Some((requests, record)) = implicit_grantor {
            workload.spawn_grantor(
                runtime,
                root,
                IMPLICIT_GRANTOR_NAME,
                DEFAULT_LEASE_MS,
                requests,
                record,
                Arc::new(WorkloadCounters::default()),
            );
        }
        if !unpinged.is_empty() {
            workload.spawn_hub(
                runtime,
                root,
                IMPLICIT_HUB_NAME,
                PingPlan {
                    rounds: DEFAULT_HUB_ROUNDS,
                    interval_ms: DEFAULT_HUB_INTERVAL_MS,
                    timeout_ms: DEFAULT_HUB_TIMEOUT_MS,
                },
                unpinged,
                Arc::new(WorkloadCounters::default()),
            );
        }
        // Release the spawner's own senders: once every sender task ends, the
        // drain tasks see their channels close, and once every holder ends,
        // its grantor does.
        drop(lanes);
        drop(grantors);
        workload
    }

    /// Records a bound participant and returns the index of its record.
    fn push_task(
        &mut self,
        name: &str,
        role: WorkloadRole,
        planned: u64,
        counters: Arc<WorkloadCounters>,
        detail: BoundDetail,
    ) -> usize {
        self.tasks.push(BoundTask {
            name: name.to_owned(),
            role,
            planned,
            spawn_refusal: None,
            counters,
            detail,
            joins: Vec::new(),
        });
        self.tasks.len() - 1
    }

    /// Spawns one lab task for the record at `owner` and schedules it.
    fn spawn_owned<F>(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        owner: usize,
        body: F,
    ) -> Result<(), String>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (task, handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, body)
            .map_err(|error| error.to_string())?;
        runtime.scheduler.lock().schedule(task, 0);
        self.handles.push((owner, handle));
        Ok(())
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
        let owner = self.push_task(name, role, planned, counters, BoundDetail::Channel);
        if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
            self.tasks[owner].spawn_refusal = Some(refusal);
        }
    }

    /// Spawns one lab task per swarm member, stopping at the first refusal.
    fn spawn_swarm(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        tasks: usize,
        counters: Arc<WorkloadCounters>,
    ) {
        let members = Arc::new(SwarmMembers::new(tasks));
        let owner = self.push_task(
            name,
            WorkloadRole::Swarm,
            u64::try_from(tasks).unwrap_or(u64::MAX),
            counters,
            BoundDetail::Swarm(Arc::clone(&members)),
        );
        for member in 0..tasks {
            let body = run_swarm_member(Arc::clone(&members), member);
            if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
                self.tasks[owner].spawn_refusal = Some(format!("member {member}: {refusal}"));
                break;
            }
        }
    }

    /// Spawns one lab task that runs a managed supervisor over `workers`.
    fn spawn_supervisor(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        max_restarts: Option<u32>,
        workers: Vec<AssignedWorker>,
        counters: Arc<WorkloadCounters>,
    ) {
        let budget = max_restarts.unwrap_or_else(|| {
            let failures = workers.iter().fold(0_u64, |total, worker| {
                total
                    .saturating_add(worker.fail_times)
                    .saturating_add(worker.lifecycle.as_ref().map_or(0, |control| {
                        control.plan.crash_allowance
                    }))
            });
            u32::try_from(failures).unwrap_or(u32::MAX)
        });
        let topology = managed_supervisor(name, &workers, budget);
        let state = Arc::new(SupervisorState {
            workers,
            summary: Mutex::new(None),
        });
        let owner = self.push_task(
            name,
            WorkloadRole::Supervisor,
            u64::from(budget),
            Arc::clone(&counters),
            BoundDetail::Supervisor(Arc::clone(&state)),
        );
        let refusal = match topology {
            Ok(supervisor) => {
                let body = run_supervisor(supervisor, state, counters);
                self.spawn_owned(runtime, root, owner, body).err()
            }
            Err(refusal) => Some(refusal),
        };
        self.tasks[owner].spawn_refusal = refusal;
    }

    /// Spawns one lab task that runs a saga over `targets`, in their order.
    fn spawn_coordinator(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        step_ms: u64,
        targets: Vec<SagaStepTarget>,
        counters: Arc<WorkloadCounters>,
    ) {
        let record = Arc::new(SagaRecord {
            participants: targets
                .iter()
                .map(|target| (target.name.clone(), Arc::clone(&target.step)))
                .collect(),
            registered: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            compensated: Mutex::new(Vec::new()),
            end: Mutex::new(None),
        });
        let owner = self.push_task(
            name,
            WorkloadRole::SagaCoordinator,
            u64::try_from(targets.len()).unwrap_or(u64::MAX),
            Arc::clone(&counters),
            BoundDetail::SagaCoordinator(Arc::clone(&record)),
        );
        let body = run_saga_coordinator(
            name.to_owned(),
            targets,
            step_ms,
            Arc::clone(&self.partitions),
            Arc::clone(&self.network),
            record,
            counters,
        );
        if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
            self.tasks[owner].spawn_refusal = Some(refusal);
        }
    }

    /// Spawns one lab task that appends `writes` entries and ships its log to
    /// `replicas`, in their order.
    #[allow(clippy::too_many_arguments)]
    fn spawn_primary(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        writes: u64,
        write_ms: u64,
        replicas: Vec<AssignedReplica>,
        counters: Arc<WorkloadCounters>,
    ) {
        let (targets, logs): (Vec<ReplicaTarget>, Vec<_>) = replicas.into_iter().unzip();
        let record = Arc::new(ReplicationRecord {
            replicas: targets
                .iter()
                .map(|target| target.name.clone())
                .zip(logs)
                .collect(),
            ..ReplicationRecord::default()
        });
        let owner = self.push_task(
            name,
            WorkloadRole::Primary,
            writes,
            Arc::clone(&counters),
            BoundDetail::Primary(Arc::clone(&record)),
        );
        let body = run_primary(
            name.to_owned(),
            targets,
            Replication { writes, write_ms },
            Arc::clone(&self.partitions),
            Arc::clone(&self.network),
            record,
            counters,
        );
        if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
            self.tasks[owner].spawn_refusal = Some(refusal);
        }
    }

    /// Spawns one lab task that pings `peers`, in their order, every round.
    fn spawn_hub(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        plan: PingPlan,
        peers: Vec<PeerTarget>,
        counters: Arc<WorkloadCounters>,
    ) {
        let record = Arc::new(HubRecord {
            peers: peers
                .iter()
                .map(|peer| (peer.name.clone(), Mutex::new(PeerStats::default())))
                .collect(),
            ..HubRecord::default()
        });
        let owner = self.push_task(
            name,
            WorkloadRole::Hub,
            plan.rounds,
            Arc::clone(&counters),
            BoundDetail::Hub(Arc::clone(&record)),
        );
        let body = run_hub(
            name.to_owned(),
            peers,
            plan,
            Arc::clone(&self.partitions),
            Arc::clone(&self.network),
            record,
            counters,
        );
        if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
            self.tasks[owner].spawn_refusal = Some(refusal);
        }
    }

    /// Spawns one lab task that grants its lease on `requests`.
    #[allow(clippy::too_many_arguments)]
    fn spawn_grantor(
        &mut self,
        runtime: &mut LabRuntime,
        root: RegionId,
        name: &str,
        lease_ms: u64,
        requests: mpsc::Receiver<LeaseRequest>,
        record: Arc<LeaseRecord>,
        counters: Arc<WorkloadCounters>,
    ) {
        let owner = self.push_task(
            name,
            WorkloadRole::LeaseGrantor,
            lease_ms,
            Arc::clone(&counters),
            BoundDetail::LeaseGrantor(Arc::clone(&record)),
        );
        let body = run_lease_grantor(
            name.to_owned(),
            requests,
            lease_ms,
            Arc::clone(&self.clocks),
            record,
            counters,
        );
        if let Err(refusal) = self.spawn_owned(runtime, root, owner, body) {
            self.tasks[owner].spawn_refusal = Some(refusal);
        }
    }

    /// Reads every join handle, then appends `workload:` violations.
    ///
    /// Returns the task records so callers can inspect the counters.
    fn finish(self, violations: &mut Vec<String>) -> Vec<BoundTask> {
        let mut tasks = self.tasks;
        for (owner, mut handle) in self.handles {
            let join = JoinState::observe(&mut handle);
            if let Some(task) = tasks.get_mut(owner) {
                task.joins.push(join);
            }
        }
        for task in &tasks {
            task.collect_violations(violations);
        }
        violations.sort();
        violations.dedup();
        tasks
    }
}

/// Legacy boot hook that the compiled supervisor topology requires.
///
/// The managed binding never calls it. If anything did, it would refuse
/// instead of starting an untracked task.
fn refuse_legacy_start(
    _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
    _state: &mut crate::runtime::RuntimeState,
    _cx: &Cx,
) -> Result<crate::types::TaskId, crate::runtime::SpawnError> {
    Err(crate::runtime::SpawnError::RuntimeUnavailable)
}

/// Builds the managed supervisor of a bound `supervisor` participant.
///
/// Every worker is an optional, transient child under a one-for-one policy
/// with no backoff. The restart budget allows `max_restarts` restarts per
/// window across all workers; an exhausted budget stops the failing worker.
fn managed_supervisor(
    name: &str,
    workers: &[AssignedWorker],
    max_restarts: u32,
) -> Result<ManagedSupervisor<u64>, String> {
    let mut builder = SupervisorBuilder::new(name).with_restart_policy(RestartPolicy::OneForOne);
    let mut bindings = Vec::with_capacity(workers.len());
    for worker in workers {
        // Not required: a generation that chaos cancels before it starts
        // stops this worker instead of failing the whole supervisor.
        builder = builder
            .child(ChildSpec::new(worker.name.as_str(), refuse_legacy_start).with_required(false));
        let fail_times = worker.fail_times;
        let state = Arc::clone(&worker.state);
        let lifecycle = worker.lifecycle.clone();
        bindings.push(ManagedChildBinding::new(
            worker.name.as_str(),
            ManagedRestartMode::Transient,
            move |cx: Cx, generation: ManagedGeneration| {
                run_worker_generation(
                    cx,
                    generation,
                    fail_times,
                    Arc::clone(&state),
                    lifecycle.clone(),
                )
            },
        ));
    }
    let config = SupervisionConfig::new(
        max_restarts,
        Duration::from_mins(SUPERVISOR_RESTART_WINDOW_MINS),
    )
    .with_restart_policy(RestartPolicy::OneForOne)
    .with_backoff(BackoffStrategy::None)
    .with_escalation(EscalationPolicy::Stop);
    builder
        .compile()
        .map_err(|error| format!("supervisor topology refused: {error}"))?
        .bind_managed(bindings, config)
        .map_err(|error| format!("supervisor binding refused: {error:?}"))
}

/// Body of a bound `supervisor` task: run the managed supervisor to its end
/// and keep a summary of its report.
async fn run_supervisor(
    supervisor: ManagedSupervisor<u64>,
    state: Arc<SupervisorState>,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        let report = supervisor.run(&cx).await;
        *state.summary.lock() = Some(SupervisorSummary::of(&report));
    } else {
        bump(&counters.unexpected);
    }
    counters.finished.store(true, Ordering::Relaxed);
}

/// Body of one generation of a bound `worker`, run by its supervisor.
///
/// A legacy generation yields once; an opted-in one performs its active-time
/// work. Configured failures and injected crashes both drive real replacements.
async fn run_worker_generation(
    cx: Cx,
    generation: ManagedGeneration,
    fail_times: u64,
    state: Arc<WorkerState>,
    lifecycle: Option<Arc<lifecycle::Control>>,
) -> Outcome<(), u64> {
    let attempt = state.attempts.fetch_add(1, Ordering::Relaxed) + 1;
    if generation.number != attempt {
        bump(&state.unexpected);
    }
    if let Some(control) = lifecycle {
        match control.work(&cx, generation.number).await {
            lifecycle::WorkExit::Crashed => {
                bump(&state.failures);
                bump(&state.crashes);
                return Outcome::Err(attempt);
            }
            lifecycle::WorkExit::Cancelled => {
                bump(&state.cancelled);
                return Outcome::Cancelled(
                    cx.cancel_reason().unwrap_or_else(|| {
                        CancelReason::user("worker generation cancelled")
                    }),
                );
            }
            lifecycle::WorkExit::ClockExhausted => {
                bump(&state.failures);
                bump(&state.unexpected);
                cx.trace("scenario worker active-time clock exhausted");
                return Outcome::Err(attempt);
            }
            lifecycle::WorkExit::Completed => {}
        }
    } else {
        yield_now().await;
    }
    if cx.checkpoint().is_err() {
        bump(&state.cancelled);
        return Outcome::Cancelled(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("worker generation cancelled")),
        );
    }
    if attempt.saturating_sub(count(&state.crashes)) <= fail_times {
        bump(&state.failures);
        Outcome::Err(attempt)
    } else {
        Outcome::Ok(())
    }
}

/// Body of one swarm member: a few cooperative steps, each behind a
/// cancellation checkpoint and counted on the swarm's shared counter.
async fn run_swarm_member(members: Arc<SwarmMembers>, member: usize) {
    let outcome = match Cx::current() {
        Some(cx) => swarm_member_steps(&cx, &members.touches).await,
        None => MEMBER_UNEXPECTED,
    };
    if let Some(slot) = members.outcomes.get(member) {
        slot.store(outcome, Ordering::Relaxed);
    }
}

async fn swarm_member_steps(cx: &Cx, touches: &AtomicU64) -> u8 {
    for _ in 0..SWARM_MEMBER_YIELDS {
        if cx.checkpoint().is_err() {
            return MEMBER_CANCELLED;
        }
        bump(touches);
        yield_now().await;
    }
    if cx.checkpoint().is_err() {
        return MEMBER_CANCELLED;
    }
    bump(touches);
    MEMBER_COMPLETED
}

/// Body of a bound `saga-coordinator`, or of the implicit one.
///
/// Before each step it sleeps `step_ms` of virtual time, registers the
/// step's compensation and asks the participant to apply the step. The saga
/// completes when every participant applied its step and aborts, running the
/// registered compensations in reverse, at the first refusal, lost reply or
/// cancellation.
async fn run_saga_coordinator(
    name: String,
    targets: Vec<SagaStepTarget>,
    step_ms: u64,
    partitions: Arc<PartitionTable>,
    network: Arc<NetworkModel>,
    record: Arc<SagaRecord>,
    counters: Arc<WorkloadCounters>,
) {
    let Some(cx) = Cx::current() else {
        bump(&counters.unexpected);
        counters.finished.store(true, Ordering::Relaxed);
        return;
    };
    let step = Duration::from_millis(step_ms);
    let mut saga = Saga::new();
    let mut end = SagaEnd::Completed;
    for (index, target) in targets.iter().enumerate() {
        crate::time::sleep(cx.now(), step).await;
        if cx.checkpoint().is_err() {
            end = SagaEnd::Cancelled;
            break;
        }
        // Register the compensation before the request can be applied: a
        // participant may apply a request whose reply never arrives.
        let compensated_step = Arc::clone(&target.step);
        let log = Arc::clone(&record);
        let registered = saga.step(
            &target.name,
            || Ok(()),
            move || {
                log.compensated.lock().push(index);
                compensate_step(&compensated_step)
            },
        );
        if registered.is_err() {
            bump(&counters.unexpected);
            end = SagaEnd::Aborted("registration failed".to_owned());
            break;
        }
        bump(&record.registered);
        let link = HubLink {
            hub: &name,
            partitions: &partitions,
            network: &network,
        };
        if let Err(stop) = request_step(&cx, link, target, step, &record).await {
            end = stop;
            break;
        }
    }
    if end == SagaEnd::Completed {
        saga.complete();
    } else {
        saga.abort();
    }
    *record.end.lock() = Some(end);
    counters.finished.store(true, Ordering::Relaxed);
    // Dropping `targets` closes every participant's request channel.
}

/// The links between one participant (a saga coordinator or a primary) and
/// its peers.
#[derive(Clone, Copy)]
struct HubLink<'a> {
    hub: &'a str,
    partitions: &'a PartitionTable,
    network: &'a NetworkModel,
}

impl HubLink<'_> {
    /// How long a message between the hub and `peer` takes, or `None` when
    /// it is lost: the link is cut or the network drops it.
    fn transit(self, from: &str, to: &str, peer: &str) -> Option<Duration> {
        if self.partitions.is_cut(self.hub, peer) {
            return None;
        }
        self.network.transit(from, to)
    }

    /// One request/reply exchange with `peer` that must finish within
    /// `budget`. `send` delivers the request once it has crossed the
    /// network; `None` from `send` means the peer is gone. The reply also
    /// crosses the network, and a lost message makes the exchange wait out
    /// the budget. `lost` counts lost messages.
    async fn exchange<T, S, F>(
        self,
        cx: &Cx,
        peer: &str,
        budget: Duration,
        lost: &AtomicU64,
        send: S,
    ) -> Exchange<T>
    where
        S: FnOnce(oneshot::Sender<T>) -> F,
        F: Future<Output = Result<(), ExchangeSendError>>,
    {
        let (reply, mut replies) = oneshot::channel();
        // The reply sender of a lost request. Keeping it makes the exchange
        // wait out its budget instead of seeing a closed reply.
        let mut unanswered = None;
        let attempt = async {
            let Some(delay) = self.transit(self.hub, peer, peer) else {
                unanswered = Some(reply);
                bump(lost);
                return std::future::pending().await;
            };
            transit_delay(cx, delay).await;
            match send(reply).await {
                Ok(()) => {}
                Err(ExchangeSendError::Cancelled) => return Exchange::Cancelled,
                Err(ExchangeSendError::Gone) => return Exchange::Gone,
            }
            let answer = replies.recv(cx).await;
            let Some(delay) = self.transit(peer, self.hub, peer) else {
                // The reply is lost, perhaps after the peer acted on the
                // request.
                bump(lost);
                return std::future::pending().await;
            };
            transit_delay(cx, delay).await;
            match answer {
                Ok(value) => Exchange::Replied(value),
                Err(oneshot::RecvError::Cancelled) => Exchange::Cancelled,
                Err(oneshot::RecvError::Closed | oneshot::RecvError::PolledAfterCompletion) => {
                    Exchange::NoReply
                }
            }
        };
        let outcome = crate::time::timeout(cx.now(), budget, attempt).await;
        drop(unanswered);
        outcome.unwrap_or(Exchange::TimedOut)
    }
}

/// Why a request could not be handed to its peer.
enum ExchangeSendError {
    Cancelled,
    Gone,
}

/// How a request/reply exchange ended.
enum Exchange<T> {
    Replied(T),
    /// The peer dropped the reply without answering.
    NoReply,
    /// The peer's request channel is closed.
    Gone,
    Cancelled,
    TimedOut,
}

/// Hands a request to a peer's bounded channel.
async fn send_request<T>(
    cx: &Cx,
    requests: &mpsc::Sender<T>,
    request: T,
) -> Result<(), ExchangeSendError> {
    match requests.send(cx, request).await {
        Ok(()) => Ok(()),
        Err(SendError::Cancelled(_)) => Err(ExchangeSendError::Cancelled),
        Err(SendError::Disconnected(_) | SendError::Full(_)) => Err(ExchangeSendError::Gone),
    }
}

/// Sends one apply request and waits at most `step` for its reply. Both
/// messages cross the network: each can be delayed or lost on the way.
async fn request_step(
    cx: &Cx,
    link: HubLink<'_>,
    target: &SagaStepTarget,
    step: Duration,
    record: &SagaRecord,
) -> Result<(), SagaEnd> {
    let participant = target.name.as_str();
    // A lost reply may follow an applied step; the compensation undoes it.
    let outcome = link
        .exchange(cx, participant, step, &record.lost, |reply| {
            send_request(cx, &target.requests, SagaRequest { reply })
        })
        .await;
    match outcome {
        Exchange::Replied(true) => Ok(()),
        Exchange::Replied(false) => Err(SagaEnd::Aborted(format!("{participant} refused"))),
        Exchange::NoReply => Err(SagaEnd::Aborted(format!("{participant} dropped the reply"))),
        Exchange::Gone => Err(SagaEnd::Aborted(format!("{participant} is gone"))),
        Exchange::Cancelled => Err(SagaEnd::Cancelled),
        Exchange::TimedOut => Err(SagaEnd::Aborted(format!("{participant} timed out"))),
    }
}

/// Body of a bound `saga-participant`: it applies each request unless its
/// step was compensated first, and replies whether it applied it.
async fn run_saga_participant(
    mut requests: mpsc::Receiver<SagaRequest>,
    step: Arc<AtomicU8>,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        loop {
            match requests.recv(&cx).await {
                Ok(request) => {
                    bump(&counters.received);
                    let applied = step
                        .compare_exchange(
                            STEP_PENDING,
                            STEP_APPLIED,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok();
                    if applied {
                        bump(&counters.committed);
                    }
                    // The coordinator may have stopped waiting for this reply.
                    let _ = request.reply.send(&cx, applied);
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

/// How much a primary writes, and how often.
#[derive(Debug, Clone, Copy)]
struct Replication {
    writes: u64,
    write_ms: u64,
}

/// Body of a bound `primary`, or of the implicit one.
///
/// Each round it sleeps `write_ms` of virtual time, appends the next entry
/// while writes remain, and ships every lagging replica the log from that
/// replica's acknowledged length, waiting at most `write_ms` for each reply.
/// A lost or late batch is shipped again the next round. After the last
/// write it keeps shipping for up to [`CATCH_UP_ROUNDS`] rounds, until every
/// replica has the whole log.
async fn run_primary(
    name: String,
    targets: Vec<ReplicaTarget>,
    plan: Replication,
    partitions: Arc<PartitionTable>,
    network: Arc<NetworkModel>,
    record: Arc<ReplicationRecord>,
    counters: Arc<WorkloadCounters>,
) {
    let Some(cx) = Cx::current() else {
        bump(&counters.unexpected);
        counters.finished.store(true, Ordering::Relaxed);
        return;
    };
    let interval = Duration::from_millis(plan.write_ms);
    let writes = usize::try_from(plan.writes).unwrap_or(usize::MAX);
    let link = HubLink {
        hub: &name,
        partitions: &partitions,
        network: &network,
    };
    let mut acked = vec![0_usize; targets.len()];
    let mut cancelled = false;
    'rounds: for round in 0..writes.saturating_add(CATCH_UP_ROUNDS) {
        crate::time::sleep(cx.now(), interval).await;
        if cx.checkpoint().is_err() {
            cancelled = true;
            break;
        }
        let log_len = {
            let mut log = record.log.lock();
            if round < writes {
                log.push(u64::try_from(round).unwrap_or(u64::MAX));
            }
            log.len()
        };
        if round >= writes && acked.iter().all(|len| *len >= log_len) {
            break;
        }
        for (target, acked) in targets.iter().zip(acked.iter_mut()) {
            if *acked >= log_len {
                continue;
            }
            let from = *acked;
            let entries = record.log.lock()[from..].to_vec();
            let cx_ref = &cx;
            let batches = &target.batches;
            let outcome = link
                .exchange(&cx, &target.name, interval, &record.lost, move |reply| {
                    let batch = ReplicationBatch {
                        from,
                        entries,
                        reply,
                    };
                    send_request(cx_ref, batches, batch)
                })
                .await;
            match outcome {
                Exchange::Replied(len) => *acked = len,
                Exchange::Cancelled => {
                    cancelled = true;
                    break 'rounds;
                }
                // Shipped again next round.
                Exchange::TimedOut | Exchange::NoReply | Exchange::Gone => {}
            }
        }
    }
    let log_len = record.log.lock().len();
    record.converged.store(
        !cancelled && acked.iter().all(|len| *len == log_len),
        Ordering::Relaxed,
    );
    if cancelled {
        bump(&counters.cancelled);
    }
    counters.finished.store(true, Ordering::Relaxed);
    // Dropping `targets` closes every replica's batch channel.
}

/// Body of a bound `replica`: it applies each batch that continues its log
/// and replies with its log length. A batch that would leave a gap is not
/// applied, and the primary ships again from the replied length.
async fn run_replica(
    mut batches: mpsc::Receiver<ReplicationBatch>,
    log: Arc<Mutex<Vec<u64>>>,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        loop {
            match batches.recv(&cx).await {
                Ok(batch) => {
                    bump(&counters.received);
                    let len = {
                        let mut log = log.lock();
                        if batch.from <= log.len() {
                            let overlap = log.len() - batch.from;
                            for entry in batch.entries.into_iter().skip(overlap) {
                                log.push(entry);
                                bump(&counters.committed);
                            }
                        }
                        log.len()
                    };
                    // The primary may have stopped waiting for this reply.
                    let _ = batch.reply.send(&cx, len);
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

/// Body of a bound `lease-grantor`, or of the implicit one.
///
/// It grants its one lease when nobody has it, when the requester already
/// has it (a renewal), or when the holder's grant has run out by the
/// grantor's own clock. Each grant lasts `lease_ms` from the moment the
/// grantor took the request. A release from the current holder frees the
/// lease at once.
async fn run_lease_grantor(
    name: String,
    mut requests: mpsc::Receiver<LeaseRequest>,
    lease_ms: u64,
    clocks: Arc<ClockTable>,
    record: Arc<LeaseRecord>,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        let lease = Duration::from_millis(lease_ms);
        // The current holder and the end of its grant, by this grantor's clock.
        let mut current: Option<(String, Time)> = None;
        loop {
            match requests.recv(&cx).await {
                Ok(request) => {
                    bump(&counters.received);
                    let now = clocks.local(&name, cx.now());
                    let held_by_requester = current
                        .as_ref()
                        .is_some_and(|(holder, _)| *holder == request.holder);
                    let answer = if request.release {
                        if held_by_requester {
                            current = None;
                        }
                        None
                    } else if held_by_requester
                        || current.as_ref().is_none_or(|(_, ends)| now >= *ends)
                    {
                        current = Some((request.holder, now + lease));
                        bump(&record.grants);
                        Some(lease_ms)
                    } else {
                        bump(&record.refused);
                        None
                    };
                    // The holder may have stopped waiting for this reply.
                    let _ = request.reply.send(&cx, answer);
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

/// How one lease request ended, as its holder sees it.
enum LeaseReply {
    /// Granted for this many milliseconds.
    Granted(u64),
    /// Another holder has the lease, or the release was taken.
    Busy,
    /// The request or its reply was lost, or came too late.
    Lost,
    /// The grantor is gone.
    Gone,
    Cancelled,
}

/// Sends one lease request to `grantor` and waits at most `budget` for the
/// reply. Both messages cross the network.
async fn lease_request(
    cx: &Cx,
    link: HubLink<'_>,
    grantor: &GrantorTarget,
    holder: &str,
    release: bool,
    budget: Duration,
) -> LeaseReply {
    let outcome = link
        .exchange(cx, &grantor.name, budget, &grantor.record.lost, |reply| {
            let request = LeaseRequest {
                holder: holder.to_owned(),
                release,
                reply,
            };
            send_request(cx, &grantor.requests, request)
        })
        .await;
    match outcome {
        Exchange::Replied(Some(lease_ms)) => LeaseReply::Granted(lease_ms),
        Exchange::Replied(None) => LeaseReply::Busy,
        Exchange::TimedOut | Exchange::NoReply => LeaseReply::Lost,
        Exchange::Gone => LeaseReply::Gone,
        Exchange::Cancelled => LeaseReply::Cancelled,
    }
}

/// Body of a bound `lease-holder`.
///
/// After `start_ms` it asks its grantor for the lease every `renew_ms`
/// until it gets it, at most [`MAX_ACQUIRE_ATTEMPTS`] times. It then renews
/// the lease every `renew_ms` until `renewals` renewals succeeded, and
/// releases it. From each grant it believes it holds the lease until the
/// grant's length minus `margin_ms` after it sent the request, by its own
/// clock. A renewal that is refused or lost leaves that deadline in place,
/// and the holder stops when its clock reaches it. While it holds the lease
/// it holds a runtime-tracked `Lease` obligation, which it commits when it
/// releases the lease and aborts when the lease runs out or it is cancelled.
async fn run_lease_holder(
    name: String,
    grantor: GrantorTarget,
    terms: LeaseTerms,
    partitions: Arc<PartitionTable>,
    network: Arc<NetworkModel>,
    clocks: Arc<ClockTable>,
    counters: Arc<WorkloadCounters>,
) {
    if let Some(cx) = Cx::current() {
        let link = HubLink {
            hub: &name,
            partitions: &partitions,
            network: &network,
        };
        hold_lease(&cx, &name, link, &grantor, terms, &clocks, &counters).await;
    } else {
        bump(&counters.unexpected);
    }
    counters.finished.store(true, Ordering::Relaxed);
    // Dropping `grantor` lets the grantor see its last holder leave.
}

async fn hold_lease(
    cx: &Cx,
    name: &str,
    link: HubLink<'_>,
    grantor: &GrantorTarget,
    terms: LeaseTerms,
    clocks: &ClockTable,
    counters: &WorkloadCounters,
) {
    let interval = Duration::from_millis(terms.renew_ms);
    let margin_nanos = terms.margin_ms.saturating_mul(1_000_000);
    // The end of a grant by this holder's clock: the grant's length after
    // the request was sent, less the margin.
    let grant_end = |sent: Time, lease_ms: u64| {
        (sent + Duration::from_millis(lease_ms)).saturating_sub_nanos(margin_nanos)
    };
    if terms.start_ms > 0 {
        crate::time::sleep(cx.now(), Duration::from_millis(terms.start_ms)).await;
    }
    let mut deadline = None;
    for _ in 0..MAX_ACQUIRE_ATTEMPTS {
        if cx.checkpoint().is_err() {
            bump(&counters.cancelled);
            return;
        }
        let began = cx.now();
        let sent = clocks.local(name, began);
        match lease_request(cx, link, grantor, name, false, interval).await {
            LeaseReply::Granted(lease_ms) => {
                bump(&counters.received);
                deadline = Some(grant_end(sent, lease_ms));
                break;
            }
            LeaseReply::Cancelled => {
                bump(&counters.cancelled);
                return;
            }
            LeaseReply::Gone => return,
            LeaseReply::Busy | LeaseReply::Lost => {}
        }
        // The next attempt starts one interval after this one began.
        let next = began + interval;
        if next > cx.now() {
            crate::time::sleep(
                cx.now(),
                Duration::from_nanos(next.duration_since(cx.now())),
            )
            .await;
        }
    }
    let Some(mut deadline) = deadline else {
        // Never granted: no tenure.
        return;
    };
    let token = cx
        .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
        .unwrap_or_else(|_| {
            bump(&counters.unexpected);
            None
        });
    let start = cx.now();
    let mut renewed = 0_u64;
    let ending = loop {
        let local = clocks.local(name, cx.now());
        if local >= deadline {
            break TenureEnd::Expired;
        }
        let left = Duration::from_nanos(deadline.duration_since(local));
        crate::time::sleep(cx.now(), interval.min(left)).await;
        if cx.checkpoint().is_err() {
            break TenureEnd::Cancelled;
        }
        let local = clocks.local(name, cx.now());
        if local >= deadline {
            break TenureEnd::Expired;
        }
        if renewed >= terms.renewals {
            break TenureEnd::Released;
        }
        // The renewal must end before the lease does.
        let left = Duration::from_nanos(deadline.duration_since(local));
        match lease_request(cx, link, grantor, name, false, interval.min(left)).await {
            LeaseReply::Granted(lease_ms) => {
                bump(&counters.received);
                deadline = grant_end(local, lease_ms);
                renewed += 1;
            }
            LeaseReply::Cancelled => break TenureEnd::Cancelled,
            // Try again next interval while the lease lasts.
            LeaseReply::Busy | LeaseReply::Lost | LeaseReply::Gone => {}
        }
    };
    // From here on the holder no longer believes it holds the lease.
    grantor.record.tenures.lock().push(Tenure {
        holder: name.to_owned(),
        start,
        end: cx.now(),
        ending,
    });
    match ending {
        TenureEnd::Released => {
            // A lost release lets the lease run out at the grantor instead.
            let _ = lease_request(cx, link, grantor, name, true, interval).await;
            if let Some(token) = token {
                token.commit();
            }
            bump(&counters.committed);
        }
        TenureEnd::Expired => {
            if let Some(token) = token {
                token.abort(ObligationAbortReason::Explicit);
            }
        }
        TenureEnd::Cancelled => {
            if let Some(token) = token {
                token.abort(ObligationAbortReason::Cancel);
            }
            bump(&counters.cancelled);
        }
    }
}

/// Body of a bound `hub`, or of the implicit one.
///
/// Each of its `rounds` rounds it sleeps `interval_ms` of virtual time and
/// then pings its peers in turn, waiting at most `timeout_ms` for each echo.
/// It records each echo's round trip, and counts a lost or late ping or echo
/// as lost.
async fn run_hub(
    name: String,
    peers: Vec<PeerTarget>,
    plan: PingPlan,
    partitions: Arc<PartitionTable>,
    network: Arc<NetworkModel>,
    record: Arc<HubRecord>,
    counters: Arc<WorkloadCounters>,
) {
    let Some(cx) = Cx::current() else {
        bump(&counters.unexpected);
        counters.finished.store(true, Ordering::Relaxed);
        return;
    };
    let link = HubLink {
        hub: &name,
        partitions: &partitions,
        network: &network,
    };
    let interval = Duration::from_millis(plan.interval_ms);
    let timeout = Duration::from_millis(plan.timeout_ms);
    'rounds: for seq in 0..plan.rounds {
        crate::time::sleep(cx.now(), interval).await;
        if cx.checkpoint().is_err() {
            bump(&counters.cancelled);
            break;
        }
        for (peer, (_, stats)) in peers.iter().zip(&record.peers) {
            let sent = cx.now();
            let cx_ref = &cx;
            let pings = &peer.pings;
            let outcome = link
                .exchange(&cx, &peer.name, timeout, &record.lost, move |reply| {
                    send_request(cx_ref, pings, Ping { seq, reply })
                })
                .await;
            let mut stats = stats.lock();
            match outcome {
                Exchange::Replied(echo) if echo == seq => {
                    stats.echoed += 1;
                    stats
                        .round_trips
                        .push(Duration::from_nanos(cx.now().duration_since(sent)));
                }
                Exchange::Replied(_) => stats.mismatched += 1,
                Exchange::TimedOut | Exchange::NoReply | Exchange::Gone => stats.lost += 1,
                Exchange::Cancelled => {
                    drop(stats);
                    bump(&counters.cancelled);
                    break 'rounds;
                }
            }
        }
    }
    counters.finished.store(true, Ordering::Relaxed);
    // Dropping `peers` closes every peer's ping channel.
}

/// Body of a bound `peer`: it echoes each ping's sequence number.
async fn run_peer(mut pings: mpsc::Receiver<Ping>, counters: Arc<WorkloadCounters>) {
    if let Some(cx) = Cx::current() {
        loop {
            match pings.recv(&cx).await {
                Ok(ping) => {
                    bump(&counters.received);
                    // The hub may have stopped waiting for this echo.
                    let _ = ping.reply.send(&cx, ping.seq);
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
                    Ok(permit) => {
                        // Hold the permit across a scheduling point, so lab
                        // chaos can cancel the sender while its obligation is
                        // live; the sender then aborts the permit
                        // (br-asupersync-nq2dgn).
                        yield_now().await;
                        if cx.checkpoint().is_err() {
                            permit.abort();
                            bump(&counters.cancelled);
                            bump(&counters.cancelled_holding);
                            true
                        } else {
                            send_reserved(permit, message, &counters, drain)
                        }
                    }
                    Err(SendError::Cancelled(())) => {
                        bump(&counters.cancelled);
                        true
                    }
                    Err(SendError::Disconnected(())) => {
                        note_disconnect(&counters, drain);
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

/// Commits `message` through a reserved permit. Returns true when the
/// sender must stop.
fn send_reserved(
    permit: mpsc::SendPermit<'_, WorkloadMessage>,
    message: WorkloadMessage,
    counters: &WorkloadCounters,
    drain: &WorkloadCounters,
) -> bool {
    match permit.send(message) {
        Outcome::Ok(()) => {
            bump(&counters.committed);
            bump(&drain.delivered);
            false
        }
        Outcome::Err(SendError::Disconnected(_)) => {
            note_disconnect(counters, drain);
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
    }
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
    /// properties of bound participants; a run rejects malformed values as a
    /// validation error.
    #[must_use]
    pub fn participant_bindings(scenario: &Scenario) -> ParticipantBindings {
        let mut bindings = ParticipantBindings::default();
        let mut has_sender = false;
        let mut has_receiver = false;
        let mut has_supervisor = false;
        let mut has_worker = false;
        let mut has_coordinator = false;
        let mut has_saga_participant = false;
        let mut has_primary = false;
        let mut has_replica = false;
        let mut has_grantor = false;
        let mut has_holder = false;
        let mut has_hub = false;
        let mut has_peer = false;
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
                SUPERVISOR_ROLE => {
                    has_supervisor = true;
                    bindings.bound.push(binding);
                }
                WORKER_ROLE => {
                    has_worker = true;
                    bindings.bound.push(binding);
                }
                SAGA_COORDINATOR_ROLE => {
                    has_coordinator = true;
                    bindings.bound.push(binding);
                }
                SAGA_PARTICIPANT_ROLE => {
                    has_saga_participant = true;
                    bindings.bound.push(binding);
                }
                PRIMARY_ROLE => {
                    has_primary = true;
                    bindings.bound.push(binding);
                }
                REPLICA_ROLE => {
                    has_replica = true;
                    bindings.bound.push(binding);
                }
                LEASE_GRANTOR_ROLE => {
                    has_grantor = true;
                    bindings.bound.push(binding);
                }
                LEASE_HOLDER_ROLE => {
                    has_holder = true;
                    bindings.bound.push(binding);
                }
                HUB_ROLE => {
                    has_hub = true;
                    bindings.bound.push(binding);
                }
                PEER_ROLE => {
                    has_peer = true;
                    bindings.bound.push(binding);
                }
                SWARM_ROLE => bindings.bound.push(binding),
                _ => bindings.unbound.push(binding),
            }
        }
        bindings.implicit_sink = has_sender && !has_receiver;
        bindings.implicit_supervisor = has_worker && !has_supervisor;
        bindings.implicit_coordinator = has_saga_participant && !has_coordinator;
        bindings.implicit_primary = has_replica && !has_primary;
        bindings.implicit_grantor = has_holder && !has_grantor;
        bindings.implicit_hub = has_peer && !has_hub;
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
        workload: &ParticipantWorkload,
    ) -> (Vec<FaultInjectionLogEntry>, FaultEffectSummary) {
        let mut fault_log = Vec::with_capacity(scenario.faults.len());
        let mut fault_effect_summary = FaultEffectSummary::default();

        for fault in &scenario.faults {
            let target_nanos = fault.at_ms.saturating_mul(1_000_000);
            let target_time = Time::from_nanos(target_nanos);
            if workload.timed {
                // Fire the timers due on the way, so timed tasks act at
                // their own deadlines rather than all at the fault time.
                Self::run_timed_until(runtime, target_time);
            } else {
                // Advance time to the fault trigger point
                if target_time > runtime.now() {
                    let delta_nanos = target_time.as_nanos() - runtime.now().as_nanos();
                    runtime.advance_time(delta_nanos);
                }

                // Run to idle so pending tasks respond to the current state
                runtime.run_until_idle();
            }

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
            workload.partitions.apply(fault);
            workload.clocks.apply(fault);
            for control in &workload.lifecycle {
                control.apply(fault, now);
            }
        }

        (fault_log, fault_effect_summary)
    }

    /// Injects the scenario's faults, running the lab between them, and then
    /// runs it to quiescence. Timed tasks need the clock to advance to their
    /// next timer whenever the lab is idle.
    fn drive(
        runtime: &mut LabRuntime,
        scenario: &Scenario,
        workload: &ParticipantWorkload,
    ) -> (Vec<FaultInjectionLogEntry>, FaultEffectSummary) {
        let injected = Self::inject_faults(runtime, scenario, workload);
        if workload.timed {
            runtime.run_with_auto_advance();
        } else {
            runtime.run_until_quiescent();
        }
        injected
    }

    /// Runs a timed workload up to virtual time `target`. It runs to idle,
    /// fires each timer due before `target` in deadline order, and then moves
    /// the clock to `target`. A timer due at `target` itself fires after the
    /// fault at `target` takes effect.
    fn run_timed_until(runtime: &mut LabRuntime, target: Time) {
        loop {
            runtime.run_until_idle();
            if runtime
                .config()
                .max_steps
                .is_some_and(|max| runtime.steps() >= max)
            {
                break;
            }
            let next = runtime
                .state
                .timer_driver_handle()
                .and_then(|timers| timers.next_deadline());
            let Some(deadline) = next.filter(|deadline| *deadline < target) else {
                break;
            };
            if deadline > runtime.now() {
                runtime.advance_time_to(deadline);
            }
            let fired = runtime
                .state
                .timer_driver_handle()
                .map_or(0, |timers| timers.process_timers());
            let after = runtime
                .state
                .timer_driver_handle()
                .and_then(|timers| timers.next_deadline());
            if fired == 0 && after == Some(deadline) {
                // Nothing fired and nothing moved: stop instead of spinning.
                break;
            }
        }
        if target > runtime.now() {
            runtime.advance_time_to(target);
        }
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
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan, &scenario.network);

        let (fault_log, fault_effect_summary) = Self::drive(&mut runtime, scenario, &workload);
        let faults_injected = fault_log.len();
        let minimized_counterexample =
            Self::minimized_counterexample_for(scenario, &fault_log, &fault_effect_summary);

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
    /// `messages`, `capacity`, `tasks`, `max_restarts`, `fail_times` or `lifecycle`
    /// property on one of them is a validation error.
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
        let config = Self::lab_config_for(scenario, seed_override);
        let mut runtime = LabRuntime::new(config);
        Ok(Self::run_prepared(scenario, seed_override, &plan, &mut runtime))
    }

    /// Shared execution path for an ordinary run and a bounded campaign trial.
    /// Validation and runtime configuration are supplied by the caller.
    fn run_prepared(
        scenario: &Scenario,
        seed_override: Option<u64>,
        plan: &WorkloadPlan,
        runtime: &mut LabRuntime,
    ) -> (ScenarioRunResult, Vec<BoundTask>) {
        let effective_seed = runtime.config().seed;
        let workload = ParticipantWorkload::spawn(runtime, plan, &scenario.network);

        // 3-4. Inject timed faults, running between them, then run to
        // quiescence
        let (fault_log, fault_effect_summary) = Self::drive(runtime, scenario, &workload);
        let faults_injected = fault_log.len();
        let minimized_counterexample =
            Self::minimized_counterexample_for(scenario, &fault_log, &fault_effect_summary);

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
        (result, tasks)
    }

    fn exact_workload(
        scenario: &Scenario,
        seed_override: Option<u64>,
    ) -> Result<(LabConfig, WorkloadPlan, ExactScheduleWorkloadKey), ScenarioScheduleError> {
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(Self::validation_error(scenario, errors).into());
        }
        Self::validate_oracle_names(scenario)?;
        let plan = Self::workload_plan(scenario)?;
        let unsupported = |reason| ScenarioScheduleError::Unsupported { reason };
        if !scenario.include.is_empty() {
            return Err(unsupported(
                "unresolved includes; load the composed scenario first",
            ));
        }
        if !scenario.faults.is_empty() {
            return Err(unsupported("timed scenario faults"));
        }
        if scenario.cancellation.is_some() {
            return Err(unsupported(
                "cancellation campaigns; use run_cancellation_campaign",
            ));
        }
        let bindings = Self::participant_bindings(scenario);
        if bindings.bound.is_empty() {
            return Err(unsupported("scenarios without executable participants"));
        }
        if !bindings.unbound.is_empty() {
            return Err(unsupported("unbound participant roles"));
        }

        let config = Self::lab_config_for(scenario, seed_override);
        // The engine checks these too; reject before constructing a checkpoint
        // or spawning any real workload, without silently reducing its scope.
        if config.worker_count != 1 {
            return Err(ScenarioScheduleError::Configuration(
                ExactScheduleConfigError::MultipleWorkers,
            ));
        }
        if config.has_chaos() {
            return Err(ScenarioScheduleError::Configuration(
                ExactScheduleConfigError::ChaosEnabled,
            ));
        }

        // A scenario ID alone does not identify its program. Bind all effective
        // inputs and the workload implementation. The source hashes also cover
        // dirty/API builds whose package version and build revision are equal.
        let mut effective = scenario.clone();
        effective.lab.seed = config.seed;
        let encoded = serde_json::to_vec(&effective)?;
        let mut hash = Sha256::new();
        hash.update(b"asupersync.lab.scenario-exact-workload.v1\0");
        for part in [
            env!("CARGO_PKG_VERSION").as_bytes(),
            option_env!("ASUPERSYNC_BUILD_GIT_COMMIT")
                .unwrap_or("unknown-revision")
                .as_bytes(),
            include_bytes!("scenario_runner.rs").as_slice(),
            include_bytes!("scenario_runner/lifecycle.rs").as_slice(),
            include_bytes!("exact_explorer.rs").as_slice(),
            include_bytes!("runtime.rs").as_slice(),
            encoded.as_slice(),
        ] {
            hash.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
            hash.update(part);
        }
        Ok((
            config,
            plan,
            ExactScheduleWorkloadKey(hash.finalize().into()),
        ))
    }

    /// Creates a fresh, bounded exact-schedule campaign without running tasks.
    ///
    /// The checkpoint binds the complete effective scenario and implementation.
    /// Limits may change between batches; inputs, seed and configuration may not.
    ///
    /// # Errors
    /// Rejects invalid scenarios or bounds, unbound participants, unresolved
    /// includes, timed faults, cancellation campaigns, chaos or multiple workers.
    pub fn new_schedule_checkpoint(
        scenario: &Scenario,
        seed_override: Option<u64>,
        limits: ExactScheduleLimits,
    ) -> Result<ScenarioScheduleCheckpoint, ScenarioScheduleError> {
        let (config, _plan, key) = Self::exact_workload(scenario, seed_override)?;
        let inner = ExactScheduleExplorer::new(config, limits)
            .new_checkpoint(key)
            .map_err(ScenarioScheduleError::Configuration)?;
        Ok(ScenarioScheduleCheckpoint {
            inner,
            scenario_failed: 0,
            historical_progress_verified: true,
        })
    }

    /// Executes the next bounded batch of exact scenario schedules.
    ///
    /// Each alternative gets fresh real participant tasks, channels and owned
    /// protocol state. It runs through the existing exact-prefix scheduler,
    /// which advances virtual time when idle and verifies every enabled set.
    /// The ordinary workload checks and selected oracles determine each verdict;
    /// their failures remain in the checkpoint across batches. Stopping on a
    /// failure preserves that run's unexplored alternatives.
    ///
    /// This enumerates the admitted single-worker deterministic schedule tree,
    /// not fault choices or Mazurkiewicz classes. Configured leak/futurelock
    /// panics retain the same behavior as ordinary scenario execution.
    ///
    /// # Errors
    /// Uses the admission of [`Self::new_schedule_checkpoint`] and rejects any
    /// checkpoint identity, configuration, frontier-bound or counter mismatch
    /// before invoking the workload factory or changing the checkpoint.
    pub fn resume_schedules(
        scenario: &Scenario,
        seed_override: Option<u64>,
        limits: ExactScheduleLimits,
        checkpoint: &mut ScenarioScheduleCheckpoint,
        stop_on_failure: bool,
    ) -> Result<ScenarioScheduleReport, ScenarioScheduleError> {
        let (config, plan, key) = Self::exact_workload(scenario, seed_override)?;
        let seed = config.seed;
        let selection = config.oracle_selection.clone();
        let explorer = ExactScheduleExplorer::new(config, limits);
        let active = RefCell::new(None);
        let mut observations = Vec::new();
        let scenario_failed = &mut checkpoint.scenario_failed;
        let batch = explorer
            .resume_until(
                &mut checkpoint.inner,
                key,
                |runtime| {
                    *active.borrow_mut() = Some(ParticipantWorkload::spawn(
                        runtime,
                        &plan,
                        &scenario.network,
                    ));
                },
                |run| {
                    let mut violations = run.lab.invariant_violations.clone();
                    if let Some(workload) = active.borrow_mut().take() {
                        workload.finish(&mut violations);
                    } else {
                        violations.push("workload: missing exact-run participant state".to_owned());
                    }
                    let oracles = FilteredOracleReport::from_full(
                        run.lab.oracle_report.clone(),
                        &scenario.oracles,
                        &selection,
                    );
                    let passed = run.termination == ExactScheduleTermination::Quiescent
                        && run.schedule.is_some()
                        && run.lab.steps_total > 0
                        && run.lab.quiescent
                        && violations.is_empty()
                        && oracles.all_passed;
                    if !passed {
                        // Core admission reserves headroom for every run. This
                        // counter is bounded by its cumulative run count.
                        *scenario_failed += 1;
                    }
                    observations.push((oracles, violations));
                    stop_on_failure && !passed
                },
            )
            .map_err(ScenarioScheduleError::Resume)?;
        let runs = batch
            .runs
            .into_iter()
            .zip(observations)
            .map(|(mut execution, (oracle_report, violations))| {
                execution.lab.invariant_violations = violations;
                ScenarioScheduleRun {
                    workload: key,
                    execution,
                    oracle_report,
                }
            })
            .collect();
        Ok(ScenarioScheduleReport {
            scenario_id: scenario.id.clone(),
            seed,
            termination: batch.termination,
            progress: batch.progress,
            scenario_failed: checkpoint.scenario_failed,
            pending_prefixes: checkpoint.inner.pending_prefix_count(),
            historical_progress_verified: checkpoint.historical_progress_verified,
            runs,
        })
    }

    /// Replays one complete exact scenario receipt on fresh real participants.
    ///
    /// The effective scenario, seed and implementation must match the source
    /// run's private workload identity. The runtime forces every recorded
    /// dispatch and checks its terminal certificate without scheduler fallback.
    /// Workload invariants and selected oracles are then evaluated afresh; no
    /// source verdict is trusted. A reproduced workload failure returns `Ok`
    /// with [`ScenarioScheduleReplayReport::passed`] false.
    ///
    /// # Errors
    /// Rejects unsupported scenarios, changed workload identity or a missing
    /// complete receipt before spawning participants. Forced execution returns
    /// an error for admission limits or any divergence, never a partial success.
    pub fn replay_schedule(
        scenario: &Scenario,
        seed_override: Option<u64>,
        source: &ScenarioScheduleRun,
        limits: ForcedScheduleLimits,
    ) -> Result<ScenarioScheduleReplayReport, ScenarioScheduleError> {
        let (config, plan, key) = Self::exact_workload(scenario, seed_override)?;
        if source.workload != key {
            return Err(ScenarioScheduleError::ReplayWorkloadMismatch);
        }
        let schedule = source
            .execution
            .schedule
            .as_ref()
            .ok_or(ScenarioScheduleError::MissingReplayReceipt)?;
        let selection = config.oracle_selection.clone();
        let mut runtime = LabRuntime::new_with_task_causality(config);
        let workload = ParticipantWorkload::spawn(&mut runtime, &plan, &scenario.network);
        let execution = runtime.run_forced_schedule(schedule, limits)?;
        let mut lab = runtime.report();
        lab.steps_delta = execution.steps;
        workload.finish(&mut lab.invariant_violations);
        let oracle_report = FilteredOracleReport::from_full(
            lab.oracle_report.clone(),
            &scenario.oracles,
            &selection,
        );
        Ok(ScenarioScheduleReplayReport {
            execution,
            lab,
            oracle_report,
        })
    }

    /// Starts and executes one bounded exact-schedule batch.
    ///
    /// Use [`Self::new_schedule_checkpoint`] and [`Self::resume_schedules`] to
    /// retain the frontier when the batch reaches a limit or finds a failure.
    /// Seeded exploration remains separately available as [`Self::explore_seeds`].
    ///
    /// # Errors
    /// Returns the same admission errors as [`Self::resume_schedules`].
    pub fn explore_schedules(
        scenario: &Scenario,
        seed_override: Option<u64>,
        limits: ExactScheduleLimits,
        stop_on_failure: bool,
    ) -> Result<ScenarioScheduleReport, ScenarioScheduleError> {
        let mut checkpoint = Self::new_schedule_checkpoint(scenario, seed_override, limits)?;
        Self::resume_schedules(
            scenario,
            seed_override,
            limits,
            &mut checkpoint,
            stop_on_failure,
        )
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
#[path = "scenario_runner_inline_tests.rs"]
mod tests;
