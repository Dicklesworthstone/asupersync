//! Replay and diff utilities for trace analysis.
//!
//! This module provides utilities for:
//! - Replaying a trace to reproduce an execution
//! - Comparing two traces to find divergences
//! - Replay validation with certificate checking
//! - **Trace normalization** for canonical replay ordering
//!
//! # Trace Normalization
//!
//! Use [`normalize_for_replay`] to reorder trace events into a canonical form
//! that minimizes context switches while preserving all happens-before
//! relationships. This is useful for:
//!
//! - Deterministic comparison of equivalent traces
//! - Debugging with reduced interleaving noise
//! - Trace minimization and simplification
//!
//! ```ignore
//! use asupersync::lab::replay::{normalize_for_replay, traces_equivalent};
//!
//! // Normalize a trace
//! let result = normalize_for_replay(&events);
//! println!("{}", result); // Shows switch count reduction
//!
//! // Compare two traces for equivalence
//! if traces_equivalent(&trace_a, &trace_b) {
//!     println!("Traces are equivalent under normalization");
//! }
//! ```

use crate::lab::config::LabConfig;
use crate::lab::runtime::{CrashpackLink, LabRuntime, SporkHarnessReport};
use crate::lab::spork_harness::{ScenarioRunnerError, SporkScenarioConfig, SporkScenarioRunner};
use crate::trace::{TraceBuffer, TraceBufferHandle, TraceEvent};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable schema for deterministic replay plans synthesized from coordination packs.
pub const COORDINATION_PRESSURE_REPLAY_SCHEMA_VERSION: &str =
    "asupersync.coordination-pressure-replay.v1";
/// Stable schema for deterministic swarm replay lab summaries.
pub const SWARM_REPLAY_LAB_SCHEMA_VERSION: &str = "asupersync.swarm-replay-lab.v1";

const COORDINATION_REQUIRED_FAMILIES: [&str; 7] = [
    "tracker_lock_contention",
    "concurrent_rch_proofs",
    "fail_closed_dirty_frontier",
    "artifact_retrieval_tail",
    "proof_runner_fanout",
    "stale_in_progress_reclaim",
    "coordination_latency_burst",
];

/// Runtime workload expansion pack emitted by the coordination synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationWorkloadExpansionPack {
    /// Expansion-pack schema version.
    pub schema_version: String,
    /// Stable expansion pack id.
    pub pack_id: String,
    /// Whether the pack mutates the core workload denominator.
    pub baseline_denominator: bool,
    /// Hash of the redacted source coordination bundle.
    pub source_bundle_hash: String,
    /// Source collector run id.
    pub source_run_id: String,
    /// Missing scenario families detected by the synthesizer.
    #[serde(default)]
    pub missing_scenario_families: Vec<String>,
    /// Synthesized coordination workload entries.
    #[serde(default)]
    pub workloads: Vec<CoordinationWorkloadExpansion>,
    /// Refused bundle records emitted by the synthesizer.
    #[serde(default)]
    pub refused_bundles: Vec<CoordinationRefusedBundle>,
}

/// One synthesized coordination workload entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationWorkloadExpansion {
    /// Runtime workload id.
    pub workload_id: String,
    /// Coordination scenario family.
    pub scenario_family: String,
    /// Scenario id used in logs and replay artifacts.
    pub scenario_id: String,
    /// Dimensions that become semantic runtime pressure.
    pub semantic_pressure: Vec<String>,
    /// Redacted context retained only for provenance and replay explanation.
    pub provenance_only_context: Vec<String>,
    /// Accepted source events folded into this workload.
    pub source_event_count: usize,
    /// Stable event hashes backing this workload.
    pub source_hashes: Vec<String>,
    /// Source bundle hash copied onto the workload.
    pub source_bundle_hash: String,
    /// Replay command for this workload.
    pub replay_command: String,
    /// Artifact globs expected from replay.
    #[serde(default)]
    pub expected_artifact_globs: Vec<String>,
}

/// Refused coordination bundle metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationRefusedBundle {
    /// Source run id that was refused.
    pub source_run_id: String,
    /// Stable refusal reason.
    pub refusal_reason: String,
    /// Scenario families whose absence caused refusal.
    #[serde(default)]
    pub missing_scenario_families: Vec<String>,
}

/// Deterministic replay plan for coordination-derived workload pressure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationPressureReplayPlan {
    /// Replay-plan schema version.
    pub schema_version: String,
    /// Seed used for deterministic replay stimulus synthesis.
    pub seed: u64,
    /// Source bundle hash backing all stimuli.
    pub source_bundle_hash: String,
    /// Canonicalized per-family stimuli.
    pub stimuli: Vec<CoordinationReplayStimulus>,
    /// Structured replay log summary.
    pub log: CoordinationReplayLog,
}

/// One deterministic coordination replay stimulus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationReplayStimulus {
    /// Runtime workload id that produced the stimulus.
    pub workload_id: String,
    /// Scenario id carried into replay logs.
    pub scenario_id: String,
    /// Coordination scenario family.
    pub scenario_family: String,
    /// Accepted source event count.
    pub source_event_count: usize,
    /// Synthesized task pressure.
    pub synthesized_task_count: usize,
    /// Synthesized queue pressure.
    pub queue_depth: usize,
    /// Synthesized timer pressure.
    pub timer_ticks: usize,
    /// Synthesized cancellation pressure.
    pub cancel_count: usize,
    /// Synthesized artifact-delay pressure.
    pub artifact_delay_ticks: usize,
    /// Stable source event hashes.
    pub source_hashes: Vec<String>,
    /// First fail-closed signal represented by this stimulus, if any.
    pub first_failure_or_refusal: Option<String>,
}

/// Structured log emitted for a coordination replay plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationReplayLog {
    /// Aggregate replay scenario id.
    pub scenario_id: String,
    /// Deterministic replay seed.
    pub seed: u64,
    /// Source bundle hash.
    pub source_bundle_hash: String,
    /// Total accepted source event count.
    pub event_count: usize,
    /// Total synthesized task pressure.
    pub synthesized_task_count: usize,
    /// Total queue pressure.
    pub queue_dimension: usize,
    /// Total timer pressure.
    pub timer_dimension: usize,
    /// Total cancellation pressure.
    pub cancel_dimension: usize,
    /// Total artifact-delay pressure.
    pub artifact_delay_dimension: usize,
    /// Stable trace fingerprint for the canonical stimuli.
    pub trace_fingerprint: u64,
    /// Number of stimuli removed during minimization.
    pub minimization_steps: usize,
    /// First failure or refusal preserved for counterexample diagnosis.
    pub first_failure_or_refusal: Option<String>,
}

/// Coordination replay synthesis failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationReplayError {
    /// The input pack used an unsupported schema.
    UnsupportedPackSchema {
        /// Schema that was expected.
        expected: &'static str,
        /// Schema that was found.
        found: String,
    },
    /// The source bundle hash was empty or not a sha256 reference.
    InvalidSourceBundleHash {
        /// Hash value that failed validation.
        found: String,
    },
    /// Required coordination scenario families were absent.
    MissingScenarioDimensions {
        /// Missing scenario families.
        missing: Vec<String>,
    },
    /// A workload used an unsupported scenario family.
    UnsupportedScenarioFamily {
        /// Unsupported family name.
        family: String,
    },
    /// A workload contained a scenario field that the replay hook does not model.
    UnsupportedScenarioField {
        /// Workload whose field failed validation.
        workload_id: String,
        /// Field that carried the unsupported value.
        field: &'static str,
        /// Unsupported field value.
        value: String,
    },
    /// A workload omitted a scenario field required by its family mapping.
    MissingScenarioField {
        /// Workload whose field failed validation.
        workload_id: String,
        /// Field with missing expected values.
        field: &'static str,
        /// Missing expected values.
        missing: Vec<String>,
    },
    /// A workload source bundle hash did not match the pack hash.
    MismatchedSourceBundleHash {
        /// Workload whose bundle hash failed validation.
        workload_id: String,
        /// Source bundle hash from the pack.
        expected: String,
        /// Source bundle hash from the workload.
        found: String,
    },
    /// A workload id was empty.
    EmptyWorkloadId,
    /// A workload did not declare semantic pressure dimensions.
    EmptySemanticPressure {
        /// Workload whose dimensions were empty.
        workload_id: String,
    },
    /// A workload did not declare provenance-only context.
    EmptyProvenanceContext {
        /// Workload whose context was empty.
        workload_id: String,
    },
    /// A workload had no accepted source events.
    ZeroSourceEvents {
        /// Workload with no accepted events.
        workload_id: String,
    },
    /// A workload source hash was empty or unstable.
    InvalidSourceHash {
        /// Workload whose hash failed validation.
        workload_id: String,
        /// Hash value that failed validation.
        found: String,
    },
}

impl std::fmt::Display for CoordinationReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPackSchema { expected, found } => {
                write!(
                    f,
                    "unsupported coordination pack schema: expected {expected}, found {found}"
                )
            }
            Self::InvalidSourceBundleHash { found } => {
                write!(f, "invalid coordination source bundle hash: {found}")
            }
            Self::MissingScenarioDimensions { missing } => {
                write!(
                    f,
                    "missing coordination scenario dimensions: {}",
                    missing.join(",")
                )
            }
            Self::UnsupportedScenarioFamily { family } => {
                write!(f, "unsupported coordination scenario family: {family}")
            }
            Self::UnsupportedScenarioField {
                workload_id,
                field,
                value,
            } => write!(
                f,
                "coordination workload {workload_id} has unsupported {field} value: {value}"
            ),
            Self::MissingScenarioField {
                workload_id,
                field,
                missing,
            } => write!(
                f,
                "coordination workload {workload_id} is missing {field} values: {}",
                missing.join(",")
            ),
            Self::MismatchedSourceBundleHash {
                workload_id,
                expected,
                found,
            } => write!(
                f,
                "coordination workload {workload_id} has source bundle hash {found}, expected {expected}"
            ),
            Self::EmptyWorkloadId => write!(f, "coordination workload id must not be empty"),
            Self::EmptySemanticPressure { workload_id } => {
                write!(
                    f,
                    "coordination workload {workload_id} has no semantic pressure dimensions"
                )
            }
            Self::EmptyProvenanceContext { workload_id } => {
                write!(
                    f,
                    "coordination workload {workload_id} has no provenance-only context"
                )
            }
            Self::ZeroSourceEvents { workload_id } => {
                write!(
                    f,
                    "coordination workload {workload_id} has no accepted source events"
                )
            }
            Self::InvalidSourceHash { workload_id, found } => {
                write!(
                    f,
                    "coordination workload {workload_id} has invalid source hash: {found}"
                )
            }
        }
    }
}

impl std::error::Error for CoordinationReplayError {}

/// Synthesize deterministic lab replay stimuli from a coordination expansion pack.
pub fn synthesize_coordination_pressure_replay(
    seed: u64,
    pack: &CoordinationWorkloadExpansionPack,
) -> Result<CoordinationPressureReplayPlan, CoordinationReplayError> {
    validate_coordination_pack(seed, pack)?;

    let mut workloads = pack.workloads.clone();
    for workload in &mut workloads {
        workload.source_hashes.sort();
        workload.source_hashes.dedup();
    }
    workloads.sort_by(|left, right| {
        (
            left.scenario_family.as_str(),
            left.workload_id.as_str(),
            left.source_hashes.as_slice(),
        )
            .cmp(&(
                right.scenario_family.as_str(),
                right.workload_id.as_str(),
                right.source_hashes.as_slice(),
            ))
    });

    let mut stimuli = Vec::with_capacity(workloads.len());
    for workload in &workloads {
        stimuli.push(stimulus_from_coordination_workload(workload)?);
    }

    let log = coordination_replay_log(
        seed,
        &pack.source_bundle_hash,
        &stimuli,
        0,
        first_failure(&stimuli),
    );

    Ok(CoordinationPressureReplayPlan {
        schema_version: COORDINATION_PRESSURE_REPLAY_SCHEMA_VERSION.to_string(),
        seed,
        source_bundle_hash: pack.source_bundle_hash.clone(),
        stimuli,
        log,
    })
}

/// Minimize a coordination replay plan while preserving the first fail-closed signal.
#[must_use]
pub fn minimize_coordination_pressure_replay(
    plan: &CoordinationPressureReplayPlan,
) -> CoordinationPressureReplayPlan {
    if plan.stimuli.len() <= 1 {
        return plan.clone();
    }

    let keep_index = plan
        .stimuli
        .iter()
        .position(|stimulus| stimulus.first_failure_or_refusal.is_some())
        .unwrap_or(0);
    let kept = vec![plan.stimuli[keep_index].clone()];
    let minimization_steps = plan.stimuli.len() - kept.len();
    let first_failure = first_failure(&kept).or_else(|| plan.log.first_failure_or_refusal.clone());
    let log = coordination_replay_log(
        plan.seed,
        &plan.source_bundle_hash,
        &kept,
        minimization_steps,
        first_failure,
    );

    CoordinationPressureReplayPlan {
        schema_version: plan.schema_version.clone(),
        seed: plan.seed,
        source_bundle_hash: plan.source_bundle_hash.clone(),
        stimuli: kept,
        log,
    }
}

fn validate_coordination_pack(
    _seed: u64,
    pack: &CoordinationWorkloadExpansionPack,
) -> Result<(), CoordinationReplayError> {
    if pack.schema_version != "runtime-workload-coordination-expansion-pack-v1" {
        return Err(CoordinationReplayError::UnsupportedPackSchema {
            expected: "runtime-workload-coordination-expansion-pack-v1",
            found: pack.schema_version.clone(),
        });
    }
    validate_coordination_hash(&pack.source_bundle_hash)
        .map_err(|found| CoordinationReplayError::InvalidSourceBundleHash { found })?;
    if !pack.refused_bundles.is_empty() || !pack.missing_scenario_families.is_empty() {
        let mut missing = pack.missing_scenario_families.clone();
        for refused in &pack.refused_bundles {
            missing.extend(refused.missing_scenario_families.iter().cloned());
        }
        missing.sort();
        missing.dedup();
        return Err(CoordinationReplayError::MissingScenarioDimensions { missing });
    }

    let present: BTreeSet<_> = pack
        .workloads
        .iter()
        .map(|workload| workload.scenario_family.as_str())
        .collect();
    let missing = COORDINATION_REQUIRED_FAMILIES
        .iter()
        .filter(|family| !present.contains(**family))
        .map(|family| (*family).to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CoordinationReplayError::MissingScenarioDimensions { missing });
    }
    for workload in &pack.workloads {
        if workload.source_bundle_hash != pack.source_bundle_hash {
            return Err(CoordinationReplayError::MismatchedSourceBundleHash {
                workload_id: workload.workload_id.clone(),
                expected: pack.source_bundle_hash.clone(),
                found: workload.source_bundle_hash.clone(),
            });
        }
        validate_coordination_field_set(
            workload,
            "semantic_pressure",
            &workload.semantic_pressure,
            coordination_allowed_semantic_pressure(&workload.scenario_family)?,
        )?;
        validate_coordination_field_set(
            workload,
            "provenance_only_context",
            &workload.provenance_only_context,
            coordination_allowed_provenance_context(&workload.scenario_family)?,
        )?;
    }

    Ok(())
}

fn stimulus_from_coordination_workload(
    workload: &CoordinationWorkloadExpansion,
) -> Result<CoordinationReplayStimulus, CoordinationReplayError> {
    if workload.workload_id.trim().is_empty() {
        return Err(CoordinationReplayError::EmptyWorkloadId);
    }
    if workload.semantic_pressure.is_empty()
        || workload
            .semantic_pressure
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CoordinationReplayError::EmptySemanticPressure {
            workload_id: workload.workload_id.clone(),
        });
    }
    if workload.provenance_only_context.is_empty()
        || workload
            .provenance_only_context
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CoordinationReplayError::EmptyProvenanceContext {
            workload_id: workload.workload_id.clone(),
        });
    }
    if workload.source_event_count == 0 {
        return Err(CoordinationReplayError::ZeroSourceEvents {
            workload_id: workload.workload_id.clone(),
        });
    }
    validate_coordination_hash(&workload.source_bundle_hash).map_err(|found| {
        CoordinationReplayError::InvalidSourceHash {
            workload_id: workload.workload_id.clone(),
            found,
        }
    })?;
    if workload.source_hashes.is_empty() {
        return Err(CoordinationReplayError::InvalidSourceHash {
            workload_id: workload.workload_id.clone(),
            found: String::new(),
        });
    }
    let mut source_hashes = workload.source_hashes.clone();
    source_hashes.sort();
    source_hashes.dedup();
    for hash in &source_hashes {
        validate_coordination_hash(hash).map_err(|found| {
            CoordinationReplayError::InvalidSourceHash {
                workload_id: workload.workload_id.clone(),
                found,
            }
        })?;
    }

    let events = workload.source_event_count;
    let (
        synthesized_task_count,
        queue_depth,
        timer_ticks,
        cancel_count,
        artifact_delay_ticks,
        first_failure_or_refusal,
    ) = match workload.scenario_family.as_str() {
        "tracker_lock_contention" => (events * 2, events * 3, events, 0, 0, None),
        "concurrent_rch_proofs" => (events * 3, events * 2, events, 0, events * 2, None),
        "fail_closed_dirty_frontier" => (
            events,
            events,
            0,
            events,
            0,
            Some("dirty_frontier_fail_closed".to_string()),
        ),
        "artifact_retrieval_tail" => (events, events, events * 3, 0, events * 5, None),
        "proof_runner_fanout" => (events * 4, events * 4, events, 0, events, None),
        "stale_in_progress_reclaim" => (
            events * 2,
            events * 2,
            events,
            events,
            0,
            Some("stale_in_progress_reclaim".to_string()),
        ),
        "coordination_latency_burst" => (events * 2, events, events * 4, 0, events, None),
        family => {
            return Err(CoordinationReplayError::UnsupportedScenarioFamily {
                family: family.to_string(),
            });
        }
    };

    Ok(CoordinationReplayStimulus {
        workload_id: workload.workload_id.clone(),
        scenario_id: workload.scenario_id.clone(),
        scenario_family: workload.scenario_family.clone(),
        source_event_count: events,
        synthesized_task_count,
        queue_depth,
        timer_ticks,
        cancel_count,
        artifact_delay_ticks,
        source_hashes,
        first_failure_or_refusal,
    })
}

fn validate_coordination_field_set(
    workload: &CoordinationWorkloadExpansion,
    field: &'static str,
    observed: &[String],
    expected: &'static [&'static str],
) -> Result<(), CoordinationReplayError> {
    for value in observed {
        if !expected.contains(&value.as_str()) {
            return Err(CoordinationReplayError::UnsupportedScenarioField {
                workload_id: workload.workload_id.clone(),
                field,
                value: value.clone(),
            });
        }
    }

    let observed_set = observed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let missing = expected
        .iter()
        .filter(|value| !observed_set.contains(**value))
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CoordinationReplayError::MissingScenarioField {
            workload_id: workload.workload_id.clone(),
            field,
            missing,
        });
    }

    Ok(())
}

fn coordination_allowed_semantic_pressure(
    family: &str,
) -> Result<&'static [&'static str], CoordinationReplayError> {
    match family {
        "tracker_lock_contention" => Ok(&[
            "metadata-lock-waiters",
            "ready-backlog-from-serialized-claims",
            "queue-residency-tail",
        ]),
        "concurrent_rch_proofs" => Ok(&[
            "validation-fanout",
            "remote-proof-queue-depth",
            "artifact-retrieval-tail",
        ]),
        "fail_closed_dirty_frontier" => Ok(&[
            "admission-refusal",
            "unsupported-dirty-frontier-count",
            "operator-retry-pressure",
        ]),
        "artifact_retrieval_tail" => Ok(&[
            "artifact-fetch-fanout",
            "result-materialization-tail",
            "summary-index-pressure",
        ]),
        "proof_runner_fanout" => Ok(&[
            "parallel-proof-launch",
            "ack-free-notification-burst",
            "ready-queue-burst",
        ]),
        "stale_in_progress_reclaim" => Ok(&[
            "stale-work-requeue",
            "tracker-priority-rebalance",
            "operator-recovery-loop",
        ]),
        "coordination_latency_burst" => Ok(&[
            "ack-required-message-burst",
            "coordination-round-trip-tail",
            "operator-latency-amplification",
        ]),
        family => Err(CoordinationReplayError::UnsupportedScenarioFamily {
            family: family.to_string(),
        }),
    }
}

fn coordination_allowed_provenance_context(
    family: &str,
) -> Result<&'static [&'static str], CoordinationReplayError> {
    match family {
        "tracker_lock_contention" => Ok(&[
            "hashed-lock-path",
            "pseudonymized-holder-agent",
            "thread-or-bead-id",
        ]),
        "concurrent_rch_proofs" => Ok(&["redacted-worker-pool", "hashed-proof-command", "bead-id"]),
        "fail_closed_dirty_frontier" => {
            Ok(&["path-hashes", "dirty-path-count", "redaction-verdict"])
        }
        "artifact_retrieval_tail" => Ok(&["artifact-kind", "artifact-path-hash", "source-bead-id"]),
        "proof_runner_fanout" => Ok(&["message-subject-hash", "pseudonymized-sender", "thread-id"]),
        "stale_in_progress_reclaim" => Ok(&[
            "pseudonymized-assignee",
            "updated-at-bucket",
            "dependency-count",
        ]),
        "coordination_latency_burst" => Ok(&["message-id", "thread-id", "ack-required-flag"]),
        family => Err(CoordinationReplayError::UnsupportedScenarioFamily {
            family: family.to_string(),
        }),
    }
}

fn coordination_replay_log(
    seed: u64,
    source_bundle_hash: &str,
    stimuli: &[CoordinationReplayStimulus],
    minimization_steps: usize,
    first_failure_or_refusal: Option<String>,
) -> CoordinationReplayLog {
    CoordinationReplayLog {
        scenario_id: "coordination-pressure-replay".to_string(),
        seed,
        source_bundle_hash: source_bundle_hash.to_string(),
        event_count: stimuli
            .iter()
            .map(|stimulus| stimulus.source_event_count)
            .sum(),
        synthesized_task_count: stimuli
            .iter()
            .map(|stimulus| stimulus.synthesized_task_count)
            .sum(),
        queue_dimension: stimuli.iter().map(|stimulus| stimulus.queue_depth).sum(),
        timer_dimension: stimuli.iter().map(|stimulus| stimulus.timer_ticks).sum(),
        cancel_dimension: stimuli.iter().map(|stimulus| stimulus.cancel_count).sum(),
        artifact_delay_dimension: stimuli
            .iter()
            .map(|stimulus| stimulus.artifact_delay_ticks)
            .sum(),
        trace_fingerprint: coordination_trace_fingerprint(seed, source_bundle_hash, stimuli),
        minimization_steps,
        first_failure_or_refusal,
    }
}

fn first_failure(stimuli: &[CoordinationReplayStimulus]) -> Option<String> {
    stimuli
        .iter()
        .find_map(|stimulus| stimulus.first_failure_or_refusal.clone())
}

fn validate_coordination_hash(hash: &str) -> Result<(), String> {
    if hash.trim().is_empty() || !hash.starts_with("sha256:") {
        return Err(hash.to_string());
    }
    Ok(())
}

fn coordination_trace_fingerprint(
    seed: u64,
    source_bundle_hash: &str,
    stimuli: &[CoordinationReplayStimulus],
) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    stable_hash_u64(&mut hash, seed);
    stable_hash_str(&mut hash, source_bundle_hash);
    for stimulus in stimuli {
        stable_hash_str(&mut hash, &stimulus.workload_id);
        stable_hash_str(&mut hash, &stimulus.scenario_id);
        stable_hash_str(&mut hash, &stimulus.scenario_family);
        stable_hash_u64(&mut hash, stimulus.source_event_count as u64);
        stable_hash_u64(&mut hash, stimulus.synthesized_task_count as u64);
        stable_hash_u64(&mut hash, stimulus.queue_depth as u64);
        stable_hash_u64(&mut hash, stimulus.timer_ticks as u64);
        stable_hash_u64(&mut hash, stimulus.cancel_count as u64);
        stable_hash_u64(&mut hash, stimulus.artifact_delay_ticks as u64);
        for source_hash in &stimulus.source_hashes {
            stable_hash_str(&mut hash, source_hash);
        }
        if let Some(first_failure) = &stimulus.first_failure_or_refusal {
            stable_hash_str(&mut hash, first_failure);
        }
    }
    hash
}

fn stable_hash_u64(hash: &mut u64, value: u64) {
    for byte in value.to_le_bytes() {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn stable_hash_str(hash: &mut u64, value: &str) {
    stable_hash_u64(hash, value.len() as u64);
    for byte in value.as_bytes() {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// Deterministic knobs for the swarm replay lab workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayScenarioKnobs {
    /// Number of deterministic scheduler workers to model.
    pub worker_count: usize,
    /// Number of child regions under the root region.
    pub region_count: usize,
    /// Number of tasks spawned into each child region.
    pub tasks_per_region: usize,
    /// Capacity of the modeled MPSC backlog.
    pub channel_capacity: usize,
    /// Number of logical messages generated per task.
    pub messages_per_task: usize,
    /// Every Nth region receives a cancellation cascade.
    pub cancellation_stride: usize,
    /// Deterministic CPU/blocking-pool pressure units per task.
    pub blocking_units: usize,
    /// Number of logical trace artifacts produced by the run.
    pub artifact_count: usize,
    /// Maximum lab runtime steps.
    pub max_steps: u64,
}

impl SwarmReplayScenarioKnobs {
    /// CI-sized workload that still exercises regions, mixed priorities,
    /// cancellation cascades, backlog pressure, and artifact logging.
    #[must_use]
    pub const fn ci() -> Self {
        Self {
            worker_count: 4,
            region_count: 4,
            tasks_per_region: 4,
            channel_capacity: 3,
            messages_per_task: 2,
            cancellation_stride: 2,
            blocking_units: 3,
            artifact_count: 2,
            max_steps: 16_384,
        }
    }

    #[must_use]
    fn normalized(&self) -> Self {
        Self {
            worker_count: self.worker_count.max(1),
            region_count: self.region_count.max(1),
            tasks_per_region: self.tasks_per_region.max(1),
            channel_capacity: self.channel_capacity.max(1),
            messages_per_task: self.messages_per_task.max(1),
            cancellation_stride: self.cancellation_stride.max(1),
            blocking_units: self.blocking_units.max(1),
            artifact_count: self.artifact_count.max(1),
            max_steps: self.max_steps,
        }
    }

    #[must_use]
    fn total_task_count(&self) -> usize {
        self.region_count * self.tasks_per_region
    }

    #[must_use]
    fn logical_message_count(&self) -> usize {
        self.total_task_count() * self.messages_per_task
    }
}

impl Default for SwarmReplayScenarioKnobs {
    fn default() -> Self {
        Self::ci()
    }
}

/// Resource deltas captured by a deterministic swarm replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayResourceDeltas {
    /// Child regions created under the root.
    pub regions_created: usize,
    /// Tasks created across all child regions.
    pub tasks_created: usize,
    /// Logical messages committed into the modeled MPSC backlog.
    pub messages_committed: usize,
    /// Logical messages drained from the modeled MPSC backlog.
    pub messages_drained: usize,
    /// Backpressure events observed while filling the modeled backlog.
    pub channel_backpressure_events: usize,
    /// Tasks scheduled onto the cancel lane by cancellation cascades.
    pub cancel_targets: usize,
    /// Deterministic blocking-pool pressure units represented in the run.
    pub blocking_units: usize,
    /// Logical trace artifacts emitted by the workload.
    pub trace_artifacts: usize,
    /// Trace events in the final lab report.
    pub trace_events: usize,
    /// Scheduler steps in the final lab report.
    pub scheduler_steps: u64,
}

/// Stable trace-certificate projection for swarm replay summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayTraceCertificate {
    /// Incremental hash of witnessed events.
    pub event_hash: u64,
    /// Total number of witnessed events.
    pub event_count: u64,
    /// Hash of scheduler decisions.
    pub schedule_hash: u64,
}

impl From<crate::lab::runtime::LabTraceCertificateSummary> for SwarmReplayTraceCertificate {
    fn from(value: crate::lab::runtime::LabTraceCertificateSummary) -> Self {
        Self {
            event_hash: value.event_hash,
            event_count: value.event_count,
            schedule_hash: value.schedule_hash,
        }
    }
}

/// Stable lab-run projection used by swarm replay summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayLabFacts {
    /// Whether the runtime reached quiescence.
    pub quiescent: bool,
    /// Steps executed during this replay call.
    pub steps_delta: u64,
    /// Total scheduler steps executed by the runtime.
    pub steps_total: u64,
    /// Virtual time in nanoseconds at report time.
    pub now_nanos: u64,
    /// Canonical replay trace fingerprint.
    pub trace_fingerprint: u64,
    /// Stable trace certificate summary.
    pub trace_certificate: SwarmReplayTraceCertificate,
    /// Number of oracle entries checked.
    pub oracle_total: usize,
    /// Number of oracle entries that passed.
    pub oracle_passed: usize,
    /// Number of oracle entries that failed.
    pub oracle_failed: usize,
    /// Runtime invariant violations.
    pub invariant_violations: Vec<String>,
    /// Temporal invariant failures.
    pub temporal_failures: Vec<String>,
}

/// Deterministic minimized failing schedule metadata for invariant failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayMinimizedSchedule {
    /// Invariant preserved by minimization.
    pub preserved_invariant: String,
    /// Prefix length that is sufficient to reproduce the failure.
    pub prefix_len: usize,
    /// Deterministic schedule replay steps retained in the minimized case.
    pub schedule_steps: Vec<String>,
}

/// Structured replay log for a deterministic swarm replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayLog {
    /// Log schema version.
    pub schema_version: String,
    /// Deterministic replay seed.
    pub seed: u64,
    /// Scenario knobs copied into the log for reproduction.
    pub scenario_knobs: SwarmReplayScenarioKnobs,
    /// Resource deltas copied into the log for diagnostics.
    pub resource_deltas: SwarmReplayResourceDeltas,
    /// Logical trace artifact references produced by the run.
    pub trace_artifact_refs: Vec<String>,
    /// Minimized failing schedule, present only when an invariant failed.
    pub minimized_failing_schedule: Option<SwarmReplayMinimizedSchedule>,
}

/// Byte-stable deterministic swarm replay summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmReplayRunSummary {
    /// Summary schema version.
    pub schema_version: String,
    /// Stable scenario id.
    pub scenario_id: String,
    /// Deterministic replay seed.
    pub seed: u64,
    /// Scenario knobs after normalization.
    pub knobs: SwarmReplayScenarioKnobs,
    /// Resource deltas observed during the run.
    pub resource_deltas: SwarmReplayResourceDeltas,
    /// Stable projection of the lab report.
    pub lab: SwarmReplayLabFacts,
    /// Structured replay log.
    pub log: SwarmReplayLog,
}

/// Run the deterministic swarm replay lab workload and return a byte-stable summary.
#[must_use]
pub fn run_swarm_replay_lab(seed: u64, knobs: &SwarmReplayScenarioKnobs) -> SwarmReplayRunSummary {
    let knobs = knobs.normalized();
    let mut config = LabConfig::new(seed)
        .worker_count(knobs.worker_count)
        .with_cancellation_oracle_warnings()
        .trace_capacity((knobs.total_task_count() * 32).max(2_048));
    if knobs.max_steps > 0 {
        config = config.max_steps(knobs.max_steps);
    }

    let mut runtime = LabRuntime::new(config);
    let mut resource_deltas = install_swarm_replay_workload(&mut runtime, &knobs);
    let report = runtime.run_until_quiescent_with_report();

    resource_deltas.trace_events = report.trace_len;
    resource_deltas.scheduler_steps = report.steps_total;

    let lab = SwarmReplayLabFacts {
        quiescent: report.quiescent,
        steps_delta: report.steps_delta,
        steps_total: report.steps_total,
        now_nanos: report.now_nanos,
        trace_fingerprint: report.trace_fingerprint,
        trace_certificate: report.trace_certificate.into(),
        oracle_total: report.oracle_report.total,
        oracle_passed: report.oracle_report.passed,
        oracle_failed: report.oracle_report.failed,
        invariant_violations: report.invariant_violations.clone(),
        temporal_failures: report.temporal_invariant_failures.clone(),
    };

    let minimized_failing_schedule =
        minimized_swarm_schedule(seed, &knobs, &resource_deltas, &report);
    let trace_artifact_refs = swarm_trace_artifact_refs(seed, &knobs);
    let log = SwarmReplayLog {
        schema_version: SWARM_REPLAY_LAB_SCHEMA_VERSION.to_string(),
        seed,
        scenario_knobs: knobs.clone(),
        resource_deltas: resource_deltas.clone(),
        trace_artifact_refs,
        minimized_failing_schedule,
    };

    SwarmReplayRunSummary {
        schema_version: SWARM_REPLAY_LAB_SCHEMA_VERSION.to_string(),
        scenario_id: "deterministic-swarm-replay-lab".to_string(),
        seed,
        knobs,
        resource_deltas,
        lab,
        log,
    }
}

fn install_swarm_replay_workload(
    runtime: &mut LabRuntime,
    knobs: &SwarmReplayScenarioKnobs,
) -> SwarmReplayResourceDeltas {
    let root = runtime
        .state
        .create_root_region(crate::types::Budget::INFINITE);
    let mut regions = Vec::with_capacity(knobs.region_count);
    for _ in 0..knobs.region_count {
        regions.push(
            runtime
                .state
                .create_child_region(root, crate::types::Budget::INFINITE)
                .expect("create swarm child region"),
        );
    }

    let mut tasks_created = 0usize;
    for (region_index, &region) in regions.iter().enumerate() {
        for task_index in 0..knobs.tasks_per_region {
            let blocking_units = knobs.blocking_units;
            let messages_per_task = knobs.messages_per_task;
            let (task, _, spawn_effects) = runtime
                .state
                .create_task_with_deferred_spawn_effects(
                    region,
                    crate::types::Budget::INFINITE,
                    async move {
                        let mut digest = ((region_index as u64) << 32)
                            ^ (task_index as u64)
                            ^ messages_per_task as u64;
                        for unit in 0..blocking_units {
                            digest = digest
                                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                                .wrapping_add(unit as u64);
                            if unit % 2 == 0 {
                                crate::runtime::yield_now::yield_now().await;
                            }
                        }
                        for _ in 0..=((region_index + task_index) % 2) {
                            crate::runtime::yield_now::yield_now().await;
                        }
                        digest
                    },
                )
                .expect("create swarm task");
            let priority = (((region_index + 1) * 11 + task_index * 5) % 10) as u8;
            runtime.scheduler.lock().schedule(task, priority);
            spawn_effects.dispatch();
            tasks_created += 1;
        }
    }

    let (messages_committed, messages_drained, channel_backpressure_events) =
        model_swarm_channel_backpressure(knobs);
    let now = runtime.now();
    runtime.trace().record_event(|seq| {
        TraceEvent::user_trace(
            seq,
            now,
            format!(
                "swarm.channel_backpressure committed={messages_committed} drained={messages_drained} backpressure={channel_backpressure_events}"
            ),
        )
    });

    let cancel_targets = schedule_swarm_cancellations(runtime, &regions, knobs.cancellation_stride);
    for artifact_ref in swarm_trace_artifact_refs(runtime.config().seed, knobs) {
        let now = runtime.now();
        runtime.trace().record_event(|seq| {
            TraceEvent::user_trace(seq, now, format!("swarm.trace_artifact {artifact_ref}"))
        });
    }

    SwarmReplayResourceDeltas {
        regions_created: regions.len(),
        tasks_created,
        messages_committed,
        messages_drained,
        channel_backpressure_events,
        cancel_targets,
        blocking_units: knobs.blocking_units * tasks_created,
        trace_artifacts: knobs.artifact_count,
        trace_events: 0,
        scheduler_steps: 0,
    }
}

fn model_swarm_channel_backpressure(knobs: &SwarmReplayScenarioKnobs) -> (usize, usize, usize) {
    let (sender, mut receiver) = crate::channel::mpsc::channel::<u64>(knobs.channel_capacity);
    let mut committed = 0usize;
    let mut drained = 0usize;
    let mut backpressure_events = 0usize;

    for message in 0..knobs.logical_message_count() {
        match sender.try_send(message as u64) {
            Ok(()) => committed += 1,
            Err(crate::channel::mpsc::SendError::Full(value)) => {
                backpressure_events += 1;
                if receiver.try_recv().is_ok() {
                    drained += 1;
                }
                sender
                    .try_send(value)
                    .expect("draining one slot should clear backpressure");
                committed += 1;
            }
            Err(
                crate::channel::mpsc::SendError::Disconnected(_)
                | crate::channel::mpsc::SendError::Cancelled(_),
            ) => {
                unreachable!("swarm replay keeps both channel halves alive")
            }
        }
    }

    while receiver.try_recv().is_ok() {
        drained += 1;
    }

    (committed, drained, backpressure_events)
}

fn schedule_swarm_cancellations(
    runtime: &mut LabRuntime,
    regions: &[crate::types::RegionId],
    cancellation_stride: usize,
) -> usize {
    let mut cancel_targets = 0usize;
    for (index, &region) in regions.iter().enumerate() {
        if (index + 1) % cancellation_stride != 0 {
            continue;
        }
        let cancel_reason = crate::types::CancelReason::user("swarm replay cancellation cascade");
        let effects = runtime.state.cancel_request(region, &cancel_reason, None);
        let (targets, wake_effects) = effects.into_parts();
        cancel_targets += targets.len();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task, priority) in targets {
                scheduler.schedule_cancel(task, priority);
            }
        }
        wake_effects.dispatch();
    }
    cancel_targets
}

fn swarm_trace_artifact_refs(seed: u64, knobs: &SwarmReplayScenarioKnobs) -> Vec<String> {
    (0..knobs.artifact_count)
        .map(|index| {
            format!(
                "target/lab-replay/swarm/seed-{seed:016x}/artifact-{index:02}-regions-{}-tasks-{}.json",
                knobs.region_count,
                knobs.total_task_count()
            )
        })
        .collect()
}

fn minimized_swarm_schedule(
    seed: u64,
    knobs: &SwarmReplayScenarioKnobs,
    resource_deltas: &SwarmReplayResourceDeltas,
    report: &crate::lab::runtime::LabRunReport,
) -> Option<SwarmReplayMinimizedSchedule> {
    if report.quiescent
        && report.invariant_violations.is_empty()
        && report.temporal_invariant_failures.is_empty()
    {
        return None;
    }

    let preserved_invariant = report
        .invariant_violations
        .first()
        .or_else(|| report.temporal_invariant_failures.first())
        .cloned()
        .unwrap_or_else(|| "quiescence".to_string());
    let prefix_len = report
        .refinement_counterexample_prefix_len
        .or(report.temporal_counterexample_prefix_len)
        .unwrap_or_else(|| report.trace_len.min(knobs.total_task_count()));
    let schedule_steps = vec![
        format!("seed={seed:016x}"),
        format!(
            "spawn regions={} tasks_per_region={}",
            knobs.region_count, knobs.tasks_per_region
        ),
        format!(
            "channel capacity={} committed={} drained={} backpressure={}",
            knobs.channel_capacity,
            resource_deltas.messages_committed,
            resource_deltas.messages_drained,
            resource_deltas.channel_backpressure_events
        ),
        format!(
            "cancel stride={} targets={}",
            knobs.cancellation_stride, resource_deltas.cancel_targets
        ),
        format!(
            "replay prefix_len={} trace_fingerprint={:016x}",
            prefix_len, report.trace_fingerprint
        ),
    ];

    Some(SwarmReplayMinimizedSchedule {
        preserved_invariant,
        prefix_len,
        schedule_steps,
    })
}

/// Compares two traces and returns the first divergence point.
///
/// Returns `None` if the traces are equivalent.
#[must_use]
pub fn find_divergence(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let a_events = a;
    let b_events = b;

    for (i, (a_event, b_event)) in a_events.iter().zip(b_events.iter()).enumerate() {
        if !events_match(a_event, b_event) {
            return Some(TraceDivergence {
                position: i,
                event_a: (*a_event).clone(),
                event_b: (*b_event).clone(),
            });
        }
    }

    // Check for length mismatch
    if a_events.len() != b_events.len() {
        let position = a_events.len().min(b_events.len());
        return Some(TraceDivergence {
            position,
            event_a: a_events.get(position).cloned().unwrap_or_else(|| {
                TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace A>")
            }),
            event_b: b_events.get(position).cloned().unwrap_or_else(|| {
                TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace B>")
            }),
        });
    }

    None
}

/// Checks if two events match (ignoring sequence numbers).
fn events_match(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.time == b.time && a.logical_time == b.logical_time && a.data == b.data
}

/// A divergence between two traces.
#[derive(Debug, Clone)]
pub struct TraceDivergence {
    /// Position in the trace where divergence occurred.
    pub position: usize,
    /// Event from trace A at the divergence point.
    pub event_a: TraceEvent,
    /// Event from trace B at the divergence point.
    pub event_b: TraceEvent,
}

impl std::fmt::Display for TraceDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Divergence at position {}:\n  A: {}\n  B: {}",
            self.position, self.event_a, self.event_b
        )
    }
}

/// Summary of a trace for quick comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSummary {
    /// Number of events.
    pub event_count: usize,
    /// Number of spawn events.
    pub spawn_count: usize,
    /// Number of complete events.
    pub complete_count: usize,
    /// Number of cancel events.
    pub cancel_count: usize,
}

impl TraceSummary {
    /// Creates a summary from a trace buffer.
    #[must_use]
    pub fn from_buffer(buffer: &TraceBuffer) -> Self {
        use crate::trace::event::TraceEventKind;

        let mut summary = Self {
            event_count: 0,
            spawn_count: 0,
            complete_count: 0,
            cancel_count: 0,
        };

        for event in buffer.iter() {
            summary.event_count += 1;
            match event.kind {
                TraceEventKind::Spawn => summary.spawn_count += 1,
                TraceEventKind::Complete => summary.complete_count += 1,
                TraceEventKind::CancelRequest | TraceEventKind::CancelAck => {
                    summary.cancel_count += 1;
                }
                _ => {}
            }
        }

        summary
    }
}

/// Result of a replay validation.
#[derive(Debug)]
pub struct ReplayValidation {
    /// Whether the replay matched the original.
    pub matched: bool,
    /// Certificate from the original run.
    pub original_certificate: u64,
    /// Certificate from the replay.
    pub replay_certificate: u64,
    /// First trace divergence (if any).
    pub divergence: Option<TraceDivergence>,
    /// Steps in original.
    pub original_steps: u64,
    /// Steps in replay.
    pub replay_steps: u64,
}

impl ReplayValidation {
    /// True if both certificate and trace matched.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.matched && self.divergence.is_none()
    }
}

impl std::fmt::Display for ReplayValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid() {
            write!(
                f,
                "Replay OK: {} steps, certificate {:#018x}",
                self.replay_steps, self.replay_certificate
            )
        } else {
            write!(f, "Replay DIVERGED:")?;
            if self.original_certificate != self.replay_certificate {
                write!(
                    f,
                    "\n  Certificate mismatch: original={:#018x} replay={:#018x}",
                    self.original_certificate, self.replay_certificate
                )?;
            }
            if let Some(ref div) = self.divergence {
                write!(f, "\n  {div}")?;
            }
            if self.original_steps != self.replay_steps {
                write!(
                    f,
                    "\n  Step count mismatch: original={} replay={}",
                    self.original_steps, self.replay_steps
                )?;
            }
            Ok(())
        }
    }
}

/// Replay a test with the same seed and validate determinism.
///
/// Runs the test twice with the same seed and checks:
/// 1. Schedule certificates match
/// 2. Traces match (no divergence)
/// 3. Step counts match
pub fn validate_replay<F>(seed: u64, worker_count: usize, test: F) -> ReplayValidation
where
    F: Fn(&mut LabRuntime),
{
    let run = |s: u64| -> (u64, u64, TraceBufferHandle) {
        let mut config = LabConfig::new(s);
        config = config.worker_count(worker_count);
        let mut runtime = LabRuntime::new(config);
        test(&mut runtime);
        let steps = runtime.steps();
        let cert = runtime.certificate().hash();
        let trace = runtime.trace().clone();
        (steps, cert, trace)
    };

    let (steps_a, cert_a, trace_a) = run(seed);
    let (steps_b, cert_b, trace_b) = run(seed);

    let events_a = trace_a.snapshot();
    let events_b = trace_b.snapshot();
    let divergence = find_divergence(&events_a, &events_b);
    let matched = cert_a == cert_b && steps_a == steps_b;

    ReplayValidation {
        matched,
        original_certificate: cert_a,
        replay_certificate: cert_b,
        divergence,
        original_steps: steps_a,
        replay_steps: steps_b,
    }
}

/// Validate replay across multiple seeds and report any failures.
pub fn validate_replay_multi<F>(
    seeds: &[u64],
    worker_count: usize,
    test: F,
) -> Vec<ReplayValidation>
where
    F: Fn(&mut LabRuntime),
{
    seeds
        .iter()
        .map(|&seed| validate_replay(seed, worker_count, &test))
        .collect()
}

/// Single seed-run summary for schedule exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical normalized-trace fingerprint for this run.
    pub trace_fingerprint: u64,
}

/// Deterministic fingerprint class produced by exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationFingerprintClass {
    /// Canonical normalized-trace fingerprint.
    pub trace_fingerprint: u64,
    /// Number of runs in this class.
    pub run_count: usize,
    /// Seeds observed in this class (sorted, deduplicated).
    pub seeds: Vec<u64>,
    /// Schedule hashes observed in this class (sorted, deduplicated).
    pub schedule_hashes: Vec<u64>,
}

/// Deterministic schedule-exploration report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationReport {
    /// Per-seed runs in stable order.
    pub runs: Vec<ExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl ExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }
}

/// Per-run deterministic summary for Spork app exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical trace fingerprint for this run.
    pub trace_fingerprint: u64,
    /// Whether all run invariants/oracles passed.
    pub passed: bool,
    /// Crashpack link metadata for failing runs when available.
    pub crashpack_link: Option<CrashpackLink>,
}

/// Deterministic DPOR-style report for Spork app seed exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationReport {
    /// Per-seed run summaries in stable order.
    pub runs: Vec<SporkExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl SporkExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }

    /// Number of failed runs.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.runs.iter().filter(|run| !run.passed).count()
    }

    /// True when every failed run includes crashpack linkage metadata.
    #[must_use]
    pub fn all_failures_linked_to_crashpacks(&self) -> bool {
        self.runs
            .iter()
            .filter(|run| !run.passed)
            .all(|run| run.crashpack_link.is_some())
    }
}

/// Classify run summaries by canonical fingerprint into deterministic classes.
#[must_use]
pub fn classify_fingerprint_classes(
    runs: &[ExplorationRunSummary],
) -> Vec<ExplorationFingerprintClass> {
    let mut grouped: BTreeMap<u64, (usize, Vec<u64>, Vec<u64>)> = BTreeMap::new();

    for run in runs {
        let entry = grouped
            .entry(run.trace_fingerprint)
            .or_insert_with(|| (0, Vec::new(), Vec::new()));
        entry.0 += 1;
        entry.1.push(run.seed);
        entry.2.push(run.schedule_hash);
    }

    grouped
        .into_iter()
        .map(
            |(trace_fingerprint, (run_count, mut seeds, mut schedule_hashes))| {
                seeds.sort_unstable();
                seeds.dedup();
                schedule_hashes.sort_unstable();
                schedule_hashes.dedup();
                ExplorationFingerprintClass {
                    trace_fingerprint,
                    run_count,
                    seeds,
                    schedule_hashes,
                }
            },
        )
        .collect()
}

/// Explore a seed-space and report deterministic canonical fingerprint classes.
///
/// This is a DPOR-style seed exploration helper: each seed produces one schedule
/// and one normalized-trace fingerprint; the report groups equivalent runs.
pub fn explore_seed_space<F>(seeds: &[u64], worker_count: usize, test: F) -> ExplorationReport
where
    F: Fn(&mut LabRuntime),
{
    let mut runs: Vec<ExplorationRunSummary> = seeds
        .iter()
        .map(|&seed| {
            let mut config = LabConfig::new(seed);
            config = config.worker_count(worker_count);
            let mut runtime = LabRuntime::new(config);
            test(&mut runtime);

            let trace_events = runtime.trace().snapshot();
            let normalized = normalize_for_replay(&trace_events);
            let trace_fingerprint =
                crate::trace::canonicalize::trace_fingerprint(&normalized.normalized);

            ExplorationRunSummary {
                seed,
                schedule_hash: runtime.certificate().hash(),
                trace_fingerprint,
            }
        })
        .collect();

    runs.sort_by_key(|run| run.seed);
    let fingerprint_classes = classify_fingerprint_classes(&runs);
    ExplorationReport {
        runs,
        fingerprint_classes,
    }
}

/// Build a deterministic Spork exploration report from completed harness reports.
#[must_use]
pub fn summarize_spork_reports(reports: &[SporkHarnessReport]) -> SporkExplorationReport {
    let mut runs: Vec<SporkExplorationRunSummary> = reports
        .iter()
        .map(|report| {
            let passed = report.passed();
            SporkExplorationRunSummary {
                seed: report.seed(),
                schedule_hash: report.run.trace_certificate.schedule_hash,
                trace_fingerprint: report.trace_fingerprint(),
                passed,
                crashpack_link: if passed {
                    None
                } else {
                    report.crashpack_link()
                },
            }
        })
        .collect();

    runs.sort_by_key(|run| (run.seed, run.schedule_hash, run.trace_fingerprint));

    let class_input: Vec<ExplorationRunSummary> = runs
        .iter()
        .map(|run| ExplorationRunSummary {
            seed: run.seed,
            schedule_hash: run.schedule_hash,
            trace_fingerprint: run.trace_fingerprint,
        })
        .collect();

    SporkExplorationReport {
        runs,
        fingerprint_classes: classify_fingerprint_classes(&class_input),
    }
}

/// Explore a Spork app seed-space and produce a deterministic DPOR-style report.
///
/// The caller provides one harness report per seed (typically by running
/// `SporkAppHarness`/`SporkScenarioRunner` with that seed). The result is
/// grouped by canonical fingerprint class and keeps failure-to-crashpack links.
pub fn explore_spork_seed_space<F>(seeds: &[u64], mut run_for_seed: F) -> SporkExplorationReport
where
    F: FnMut(u64) -> SporkHarnessReport,
{
    let reports: Vec<SporkHarnessReport> = seeds.iter().map(|&seed| run_for_seed(seed)).collect();
    summarize_spork_reports(&reports)
}

/// Run a registered Spork scenario across seeds and return deterministic
/// exploration classes with failure-to-crashpack linkage.
///
/// This is the glue between `SporkScenarioRunner` and DPOR-style exploration:
/// callers provide a scenario id and base config, and this helper handles
/// seed fan-out + deterministic report grouping.
pub fn explore_scenario_runner_seed_space(
    runner: &SporkScenarioRunner,
    scenario_id: &str,
    base_config: &SporkScenarioConfig,
    seeds: &[u64],
) -> Result<SporkExplorationReport, ScenarioRunnerError> {
    let mut reports = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        let mut config = base_config.clone();
        config.seed = seed;
        let result = runner.run_with_config(scenario_id, Some(config))?;
        reports.push(result.report);
    }
    Ok(summarize_spork_reports(&reports))
}

/// Schema version for the divergence corpus registry.
pub const DIVERGENCE_CORPUS_SCHEMA_VERSION: &str = "lab-live-divergence-corpus-v1";

/// Retention class for a divergence artifact bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceBundleLevel {
    /// Preserve the complete debugging bundle.
    Full,
    /// Preserve only the reduced summary bundle.
    Reduced,
}

/// Final differential policy class from the divergence taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialPolicyClass {
    /// Stable semantic mismatch on a supported surface.
    RuntimeSemanticBug,
    /// Lab model, mapping, or comparator bug.
    LabModelOrMappingBug,
    /// Required artifact schema or evidence is missing/malformed.
    ArtifactSchemaViolation,
    /// The surface lacks the observability needed for a strong claim.
    InsufficientObservability,
    /// The surface is outside the admitted differential scope.
    UnsupportedSurface,
    /// The mismatch looks like scheduling noise rather than semantics.
    SchedulerNoiseSuspected,
    /// The mismatch could not be stabilized by rerun policy.
    IrreproducibleDivergence,
}

impl DifferentialPolicyClass {
    /// Stable string form shared by docs, logs, and registry entries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeSemanticBug => "runtime_semantic_bug",
            Self::LabModelOrMappingBug => "lab_model_or_mapping_bug",
            Self::ArtifactSchemaViolation => "artifact_schema_violation",
            Self::InsufficientObservability => "insufficient_observability",
            Self::UnsupportedSurface => "unsupported_surface",
            Self::SchedulerNoiseSuspected => "scheduler_noise_suspected",
            Self::IrreproducibleDivergence => "irreproducible_divergence",
        }
    }

    /// Required bundle strength from the divergence taxonomy.
    #[must_use]
    pub fn bundle_level(self) -> DivergenceBundleLevel {
        match self {
            Self::RuntimeSemanticBug
            | Self::LabModelOrMappingBug
            | Self::ArtifactSchemaViolation
            | Self::IrreproducibleDivergence => DivergenceBundleLevel::Full,
            Self::InsufficientObservability
            | Self::UnsupportedSurface
            | Self::SchedulerNoiseSuspected => DivergenceBundleLevel::Reduced,
        }
    }
}

impl std::fmt::Display for DifferentialPolicyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state for a divergence corpus entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionPromotionState {
    /// Newly discovered divergence under investigation.
    Investigating,
    /// A minimized reproducer exists and preserves the same semantics.
    Minimized,
    /// Promoted into a durable regression artifact.
    PromotedRegression,
    /// Retained as a known-open investigation instead of a regression.
    KnownOpen,
    /// Explicitly rejected for promotion.
    Rejected,
}

/// Minimization/shrinker status for a divergence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceShrinkStatus {
    /// No shrinker has been requested yet.
    NotRequested,
    /// Shrinking is still in progress.
    Pending,
    /// A minimized reproducer exists and preserves the semantic class.
    PreservedSemanticClass,
    /// Shrinking failed to preserve the semantic class and must not replace the original.
    Rejected,
}

/// Stable artifact layout for a retained differential bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceArtifactBundle {
    /// Root directory for the retained bundle.
    pub bundle_root: String,
    /// Stable summary record path.
    pub differential_summary_path: String,
    /// Stable event-log path.
    pub differential_event_log_path: String,
    /// Stable failures path.
    pub differential_failures_path: String,
    /// Stable deviations path.
    pub differential_deviations_path: String,
    /// Stable repro manifest path.
    pub differential_repro_manifest_path: String,
    /// Stable lab normalized-record path.
    pub lab_normalized_path: String,
    /// Stable live normalized-record path.
    pub live_normalized_path: String,
}

impl DivergenceArtifactBundle {
    /// Build the canonical bundle layout under a root directory.
    #[must_use]
    pub fn under(root: impl Into<String>) -> Self {
        let bundle_root = root.into().trim_end_matches('/').to_string();
        let join = |name: &str| format!("{bundle_root}/{name}");
        Self {
            bundle_root: bundle_root.clone(),
            differential_summary_path: join("differential_summary.json"),
            differential_event_log_path: join("differential_event_log.jsonl"),
            differential_failures_path: join("differential_failures.json"),
            differential_deviations_path: join("differential_deviations.json"),
            differential_repro_manifest_path: join("differential_repro_manifest.json"),
            lab_normalized_path: join("lab_normalized.json"),
            live_normalized_path: join("live_normalized.json"),
        }
    }
}

/// Stable retention metadata for a divergence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceRetentionMetadata {
    /// Required bundle strength.
    pub bundle_level: DivergenceBundleLevel,
    /// Default local retention window in days.
    pub local_retention_days: u16,
    /// Default CI retention window in days.
    pub ci_retention_days: u16,
    /// Default redaction policy for retained artifacts.
    pub redaction_mode: String,
}

impl DivergenceRetentionMetadata {
    /// Retention defaults derived from the divergence taxonomy.
    #[must_use]
    pub fn for_policy_class(policy_class: DifferentialPolicyClass) -> Self {
        Self {
            bundle_level: policy_class.bundle_level(),
            local_retention_days: 14,
            ci_retention_days: 30,
            redaction_mode: "metadata_only".to_string(),
        }
    }
}

/// First-seen execution context for a divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceFirstSeenContext {
    /// Named runner profile such as `smoke`, `pilot_surface`, or `nightly`.
    pub runner_profile: String,
    /// Attempt index within the local run.
    pub attempt_index: u32,
    /// Number of reruns already attempted when this entry was recorded.
    pub rerun_count: u32,
}

/// Minimization lineage for a divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceMinimizationLineage {
    /// Original canonical seed from the first-seen run.
    pub original_seed: u64,
    /// Minimized seed when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimized_seed: Option<u64>,
    /// Named shrinker or minimization pass when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shrinker: Option<String>,
    /// Current shrink status.
    pub shrink_status: DivergenceShrinkStatus,
    /// Whether the minimized form preserved the same divergence class.
    pub preserved_divergence_class: bool,
    /// Whether the minimized form preserved the same policy class.
    pub preserved_policy_class: bool,
}

impl DivergenceMinimizationLineage {
    /// Start minimization lineage from a seed lineage record.
    #[must_use]
    pub fn from_seed_lineage(lineage: &crate::lab::dual_run::SeedLineageRecord) -> Self {
        Self {
            original_seed: lineage.canonical_seed,
            minimized_seed: None,
            shrinker: None,
            shrink_status: DivergenceShrinkStatus::NotRequested,
            preserved_divergence_class: true,
            preserved_policy_class: true,
        }
    }

    /// Record a minimized reproducer that preserves the same semantic meaning.
    #[must_use]
    pub fn with_minimized_seed(
        mut self,
        seed: u64,
        shrinker: impl Into<String>,
        preserved_divergence_class: bool,
        preserved_policy_class: bool,
    ) -> Self {
        self.minimized_seed = Some(seed);
        self.shrinker = Some(shrinker.into());
        self.shrink_status = if preserved_divergence_class && preserved_policy_class {
            DivergenceShrinkStatus::PreservedSemanticClass
        } else {
            DivergenceShrinkStatus::Rejected
        };
        self.preserved_divergence_class = preserved_divergence_class;
        self.preserved_policy_class = preserved_policy_class;
        self
    }
}

/// One retained divergence entry in the differential corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceCorpusEntry {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable entry identifier used for registry upsert.
    pub entry_id: String,
    /// Scenario id from the differential run.
    pub scenario_id: String,
    /// Surface id from the differential run.
    pub surface_id: String,
    /// Surface contract version from the differential run.
    pub surface_contract_version: String,
    /// Diagnostic divergence class for this entry.
    pub divergence_class: String,
    /// Final differential policy class for this entry.
    pub policy_class: DifferentialPolicyClass,
    /// First-seen execution context.
    pub first_seen: DivergenceFirstSeenContext,
    /// Full seed lineage from the originating run.
    pub seed_lineage: crate::lab::dual_run::SeedLineageRecord,
    /// Stable mismatch field names for semantic preservation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatch_fields: Vec<String>,
    /// Stable retained bundle layout.
    pub artifact_bundle: DivergenceArtifactBundle,
    /// Shrinker/minimization lineage.
    pub minimization_lineage: DivergenceMinimizationLineage,
    /// Current promotion state for this entry.
    pub regression_promotion_state: RegressionPromotionState,
    /// Stable retention metadata.
    pub retention: DivergenceRetentionMetadata,
    /// Additional machine-readable annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl DivergenceCorpusEntry {
    /// Create a registry entry from a differential result and retained bundle root.
    #[must_use]
    pub fn from_dual_run_result(
        result: &crate::lab::dual_run::DualRunResult,
        runner_profile: impl Into<String>,
        divergence_class: impl Into<String>,
        policy_class: DifferentialPolicyClass,
        bundle_root: impl Into<String>,
    ) -> Self {
        let seed_lineage = result.seed_lineage.clone();
        let entry_id = Self::entry_id_for(
            &result.verdict.surface_id,
            &result.verdict.scenario_id,
            &seed_lineage.seed_lineage_id,
            policy_class,
        );
        let mut mismatch_fields: Vec<String> = result
            .verdict
            .mismatches
            .iter()
            .map(|mismatch| mismatch.field.clone())
            .collect();
        mismatch_fields.sort_unstable();
        mismatch_fields.dedup();

        let mut metadata = BTreeMap::new();
        if let Some(path) = result.lab.provenance.artifact_path.as_deref() {
            metadata.insert("lab_artifact_path".to_string(), path.to_string());
        }
        if let Some(path) = result.live.provenance.artifact_path.as_deref() {
            metadata.insert("live_artifact_path".to_string(), path.to_string());
        }
        if let Some(cmd) = result.lab.provenance.repro_command.as_deref() {
            metadata.insert("lab_repro_command".to_string(), cmd.to_string());
        }
        if let Some(cmd) = result.live.provenance.repro_command.as_deref() {
            metadata.insert("live_repro_command".to_string(), cmd.to_string());
        }
        if !result.lab_invariant_violations.is_empty() {
            metadata.insert(
                "lab_invariant_violations".to_string(),
                result.lab_invariant_violations.join(","),
            );
        }
        if !result.live_invariant_violations.is_empty() {
            metadata.insert(
                "live_invariant_violations".to_string(),
                result.live_invariant_violations.join(","),
            );
        }

        Self {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id,
            scenario_id: result.verdict.scenario_id.clone(),
            surface_id: result.verdict.surface_id.clone(),
            surface_contract_version: result.lab.surface_contract_version.clone(),
            divergence_class: divergence_class.into(),
            policy_class,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: runner_profile.into(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: seed_lineage.clone(),
            mismatch_fields,
            artifact_bundle: DivergenceArtifactBundle::under(bundle_root),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(&seed_lineage),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(policy_class),
            metadata,
        }
    }

    /// Stable entry id from the surface, scenario, seed lineage, and final policy class.
    #[must_use]
    pub fn entry_id_for(
        surface_id: &str,
        scenario_id: &str,
        seed_lineage_id: &str,
        policy_class: DifferentialPolicyClass,
    ) -> String {
        format!(
            "{}.{}.{}.{}",
            sanitize_registry_component(surface_id),
            sanitize_registry_component(scenario_id),
            sanitize_registry_component(seed_lineage_id),
            policy_class.as_str()
        )
    }

    /// Default bundle root for this entry under `artifacts/differential/`.
    #[must_use]
    pub fn default_bundle_root(&self) -> String {
        format!(
            "artifacts/differential/{}/{}/{}/{}",
            sanitize_registry_component(&self.surface_id),
            sanitize_registry_component(&self.scenario_id),
            sanitize_registry_component(&self.seed_lineage.seed_lineage_id),
            self.policy_class.as_str()
        )
    }

    /// Update first-seen attempt/rerun counters.
    #[must_use]
    pub fn with_first_seen_attempt(mut self, attempt_index: u32, rerun_count: u32) -> Self {
        self.first_seen.attempt_index = attempt_index;
        self.first_seen.rerun_count = rerun_count;
        self
    }

    /// Update the minimization lineage.
    #[must_use]
    pub fn with_minimization_lineage(mut self, lineage: DivergenceMinimizationLineage) -> Self {
        self.minimization_lineage = lineage;
        self.regression_promotion_state = if self.minimization_lineage.minimized_seed.is_some() {
            RegressionPromotionState::Minimized
        } else {
            self.regression_promotion_state
        };
        self
    }

    /// Promote the entry into a durable regression artifact.
    #[must_use]
    pub fn promote_to_regression(mut self, promoted_scenario_id: impl Into<String>) -> Self {
        self.regression_promotion_state = RegressionPromotionState::PromotedRegression;
        self.metadata.insert(
            "promoted_scenario_id".to_string(),
            promoted_scenario_id.into(),
        );
        self
    }
}

/// Deterministic registry of retained divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceCorpusRegistry {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Entries sorted by stable entry id.
    pub entries: Vec<DivergenceCorpusEntry>,
}

impl DivergenceCorpusRegistry {
    /// Create an empty divergence corpus registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    /// Insert or replace an entry by stable id, preserving deterministic order.
    pub fn upsert(&mut self, entry: DivergenceCorpusEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|existing| existing.entry_id == entry.entry_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
            self.entries
                .sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
        }
    }
}

impl Default for DivergenceCorpusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema version for the retained divergence summary payload.
pub const DIFFERENTIAL_SUMMARY_SCHEMA_VERSION: &str = "lab-live-differential-summary-v1";
/// Schema version for runtime/failure artifact linkage.
pub const DIFFERENTIAL_FAILURES_SCHEMA_VERSION: &str = "lab-live-differential-failures-v1";
/// Schema version for mismatch/deviation details.
pub const DIFFERENTIAL_DEVIATIONS_SCHEMA_VERSION: &str = "lab-live-differential-deviations-v1";
/// Schema version for the replay/minimization repro manifest.
pub const DIFFERENTIAL_REPRO_MANIFEST_SCHEMA_VERSION: &str =
    "lab-live-differential-repro-manifest-v1";

/// Serializable crashpack linkage metadata for retained divergence bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialCrashpackReference {
    /// Crashpack artifact path.
    pub path: String,
    /// Stable crashpack identifier.
    pub id: String,
    /// Canonical trace fingerprint associated with the crashpack.
    pub fingerprint: u64,
    /// One-line replay command for the crashpack.
    pub replay_command: String,
}

impl DifferentialCrashpackReference {
    /// Convert an existing runtime crashpack link into the retained schema.
    #[must_use]
    pub fn from_runtime_link(link: &CrashpackLink) -> Self {
        Self {
            path: link.path.clone(),
            id: link.id.clone(),
            fingerprint: link.fingerprint,
            replay_command: link.replay.command_line.clone(),
        }
    }

    /// Infer crashpack linkage from normalized provenance when the artifact path
    /// already points at a crashpack-like artifact.
    #[must_use]
    pub fn from_provenance(provenance: &crate::lab::dual_run::ReplayMetadata) -> Option<Self> {
        let path = provenance.artifact_path.as_ref()?;
        let file_name = path.rsplit('/').next().unwrap_or(path);
        if !file_name.contains("crashpack") {
            return None;
        }
        let fingerprint = provenance.trace_fingerprint?;
        Some(Self {
            path: path.clone(),
            id: format!(
                "crashpack-{:016x}-{:016x}",
                provenance.effective_seed, fingerprint
            ),
            fingerprint,
            replay_command: provenance
                .repro_command
                .clone()
                .unwrap_or_else(|| provenance.default_repro_command()),
        })
    }
}

/// One runtime-side artifact record inside `differential_failures.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialFailureArtifact {
    /// Runtime side that produced the artifact.
    pub runtime_kind: String,
    /// Canonical normalized-record path inside the retained bundle.
    pub normalized_record_path: String,
    /// Optional source artifact path from the original execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Replay command for rerunning this side.
    pub repro_command: String,
    /// Crashpack metadata when the source artifact is a crashpack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crashpack_link: Option<DifferentialCrashpackReference>,
    /// Side-specific invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant_violations: Vec<String>,
}

impl DifferentialFailureArtifact {
    #[must_use]
    fn from_observable(
        observable: &crate::lab::dual_run::NormalizedObservable,
        normalized_record_path: impl Into<String>,
        invariant_violations: &[String],
    ) -> Self {
        let repro_command = observable
            .provenance
            .repro_command
            .clone()
            .unwrap_or_else(|| observable.provenance.default_repro_command());

        Self {
            runtime_kind: observable.runtime_kind.to_string(),
            normalized_record_path: normalized_record_path.into(),
            artifact_path: observable.provenance.artifact_path.clone(),
            repro_command,
            crashpack_link: DifferentialCrashpackReference::from_provenance(&observable.provenance),
            invariant_violations: invariant_violations.to_vec(),
        }
    }
}

/// Stable contents for `differential_summary.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialSummaryDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Surface contract version.
    pub surface_contract_version: String,
    /// Human-readable verdict summary.
    pub verdict_summary: String,
    /// Policy-layer summary.
    pub policy_summary: String,
    /// Divergence class retained for the bundle.
    pub divergence_class: String,
    /// Final policy class retained for the bundle.
    pub policy_class: DifferentialPolicyClass,
    /// Current promotion state.
    pub regression_promotion_state: RegressionPromotionState,
    /// Stable mismatch field names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatch_fields: Vec<String>,
    /// Number of mismatch fields retained in the summary.
    pub mismatch_count: usize,
    /// Whether the underlying run semantically passed.
    pub passed: bool,
    /// Number of lab-side invariant violations.
    pub lab_invariant_violation_count: usize,
    /// Number of live-side invariant violations.
    pub live_invariant_violation_count: usize,
    /// Retained bundle strength.
    pub bundle_level: DivergenceBundleLevel,
    /// Stable retained bundle root.
    pub bundle_root: String,
}

/// Stable contents for `differential_failures.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialFailuresDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Runtime-side artifact linkage records.
    pub failure_artifacts: Vec<DifferentialFailureArtifact>,
}

/// Stable contents for `differential_deviations.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialDeviationsDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Policy-layer summary for the mismatch.
    pub policy_summary: String,
    /// Provisional divergence class.
    pub provisional_class: String,
    /// Suggested final divergence class when already known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_final_class: Option<String>,
    /// Human-readable explanation for downstream reports.
    pub explanation: String,
    /// Stable semantic mismatches in field order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<crate::lab::dual_run::SemanticMismatch>,
    /// Lab-side invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lab_invariant_violations: Vec<String>,
    /// Live-side invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_invariant_violations: Vec<String>,
}

/// Stable contents for `differential_repro_manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialReproManifest {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Surface contract version.
    pub surface_contract_version: String,
    /// Divergence class retained for the bundle.
    pub divergence_class: String,
    /// Final policy class retained for the bundle.
    pub policy_class: DifferentialPolicyClass,
    /// Current promotion state.
    pub regression_promotion_state: RegressionPromotionState,
    /// Automatic rerun decision from the policy layer.
    pub rerun_decision: crate::lab::dual_run::RerunDecision,
    /// Original first-seen run context.
    pub first_seen: DivergenceFirstSeenContext,
    /// Seed lineage for replay/reproduction.
    pub seed_lineage: crate::lab::dual_run::SeedLineageRecord,
    /// Shrinker/minimization lineage.
    pub minimization_lineage: DivergenceMinimizationLineage,
    /// Stable retained bundle root.
    pub bundle_root: String,
    /// Stable retained summary path.
    pub summary_path: String,
    /// Stable retained deviations path.
    pub deviations_path: String,
    /// Stable retained failures path.
    pub failure_artifacts_path: String,
    /// Stable retained lab normalized observable path.
    pub lab_normalized_path: String,
    /// Stable retained live normalized observable path.
    pub live_normalized_path: String,
    /// Stable reproduction commands across both sides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repro_commands: Vec<String>,
    /// Promoted regression scenario identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_scenario_id: Option<String>,
}

/// Complete in-memory payload set for a retained divergence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialBundleArtifacts {
    /// Summary payload for `differential_summary.json`.
    pub summary: DifferentialSummaryDocument,
    /// Artifact linkage payload for `differential_failures.json`.
    pub failures: DifferentialFailuresDocument,
    /// Mismatch/deviation payload for `differential_deviations.json`.
    pub deviations: DifferentialDeviationsDocument,
    /// Replay/minimization manifest for `differential_repro_manifest.json`.
    pub repro_manifest: DifferentialReproManifest,
    /// Canonical lab-side normalized observable for `lab_normalized.json`.
    pub lab_normalized: crate::lab::dual_run::NormalizedObservable,
    /// Canonical live-side normalized observable for `live_normalized.json`.
    pub live_normalized: crate::lab::dual_run::NormalizedObservable,
}

impl DifferentialBundleArtifacts {
    /// Build the full retained bundle payload set from a divergence entry and
    /// the originating differential result.
    #[must_use]
    pub fn from_dual_run_result(
        entry: &DivergenceCorpusEntry,
        result: &crate::lab::dual_run::DualRunResult,
    ) -> Self {
        let failure_artifacts = vec![
            DifferentialFailureArtifact::from_observable(
                &result.lab,
                entry.artifact_bundle.lab_normalized_path.clone(),
                &result.lab_invariant_violations,
            ),
            DifferentialFailureArtifact::from_observable(
                &result.live,
                entry.artifact_bundle.live_normalized_path.clone(),
                &result.live_invariant_violations,
            ),
        ];
        let mut repro_commands: Vec<String> = failure_artifacts
            .iter()
            .map(|artifact| artifact.repro_command.clone())
            .collect();
        repro_commands.sort_unstable();
        repro_commands.dedup();

        let summary = DifferentialSummaryDocument {
            schema_version: DIFFERENTIAL_SUMMARY_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            surface_contract_version: entry.surface_contract_version.clone(),
            verdict_summary: result.verdict.summary(),
            policy_summary: result.policy.summary(),
            divergence_class: entry.divergence_class.clone(),
            policy_class: entry.policy_class,
            regression_promotion_state: entry.regression_promotion_state,
            mismatch_fields: entry.mismatch_fields.clone(),
            mismatch_count: entry.mismatch_fields.len(),
            passed: result.passed(),
            lab_invariant_violation_count: result.lab_invariant_violations.len(),
            live_invariant_violation_count: result.live_invariant_violations.len(),
            bundle_level: entry.retention.bundle_level,
            bundle_root: entry.artifact_bundle.bundle_root.clone(),
        };

        let failures = DifferentialFailuresDocument {
            schema_version: DIFFERENTIAL_FAILURES_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            failure_artifacts,
        };

        let deviations = DifferentialDeviationsDocument {
            schema_version: DIFFERENTIAL_DEVIATIONS_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            policy_summary: result.policy.summary(),
            provisional_class: result.policy.provisional_class.to_string(),
            suggested_final_class: result
                .policy
                .suggested_final_class
                .map(|class| class.to_string()),
            explanation: result.policy.explanation.clone(),
            mismatches: result.verdict.mismatches.clone(),
            lab_invariant_violations: result.lab_invariant_violations.clone(),
            live_invariant_violations: result.live_invariant_violations.clone(),
        };

        let repro_manifest = DifferentialReproManifest {
            schema_version: DIFFERENTIAL_REPRO_MANIFEST_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            surface_contract_version: entry.surface_contract_version.clone(),
            divergence_class: entry.divergence_class.clone(),
            policy_class: entry.policy_class,
            regression_promotion_state: entry.regression_promotion_state,
            rerun_decision: result.policy.rerun_decision,
            first_seen: entry.first_seen.clone(),
            seed_lineage: entry.seed_lineage.clone(),
            minimization_lineage: entry.minimization_lineage.clone(),
            bundle_root: entry.artifact_bundle.bundle_root.clone(),
            summary_path: entry.artifact_bundle.differential_summary_path.clone(),
            deviations_path: entry.artifact_bundle.differential_deviations_path.clone(),
            failure_artifacts_path: entry.artifact_bundle.differential_failures_path.clone(),
            lab_normalized_path: entry.artifact_bundle.lab_normalized_path.clone(),
            live_normalized_path: entry.artifact_bundle.live_normalized_path.clone(),
            repro_commands,
            promoted_scenario_id: entry.metadata.get("promoted_scenario_id").cloned(),
        };

        Self {
            summary,
            failures,
            deviations,
            repro_manifest,
            lab_normalized: result.lab.clone(),
            live_normalized: result.live.clone(),
        }
    }
}

fn sanitize_registry_component(input: &str) -> String {
    const ESCAPED_PREFIX: &str = "z-";

    let safe_literal = !input.is_empty()
        && !input.starts_with(ESCAPED_PREFIX)
        && input
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    if safe_literal {
        return input.to_string();
    }

    let mut escaped = String::with_capacity(input.len().saturating_mul(2).saturating_add(18));
    use std::fmt::Write as _;
    let _ = write!(&mut escaped, "{ESCAPED_PREFIX}{:x}-", input.len());
    for byte in input.as_bytes() {
        let _ = write!(&mut escaped, "{byte:02x}");
    }
    escaped
}

// ============================================================================
// Trace Normalization for Canonical Replay
// ============================================================================

/// Result of trace normalization.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// The normalized (reordered) trace events.
    pub normalized: Vec<TraceEvent>,
    /// Number of owner switches in the original trace.
    pub original_switches: usize,
    /// Number of owner switches after normalization.
    pub normalized_switches: usize,
    /// The algorithm used for normalization.
    pub algorithm: String,
}

impl NormalizationResult {
    /// Returns the reduction in switch count.
    #[must_use]
    pub fn switch_reduction(&self) -> usize {
        self.original_switches
            .saturating_sub(self.normalized_switches)
    }

    /// Returns the switch reduction as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn switch_reduction_pct(&self) -> f64 {
        if self.original_switches == 0 {
            0.0
        } else {
            (self.switch_reduction() as f64 / self.original_switches as f64) * 100.0
        }
    }
}

impl std::fmt::Display for NormalizationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Normalized {} events: {} → {} switches ({:.1}% reduction, {})",
            self.normalized.len(),
            self.original_switches,
            self.normalized_switches,
            self.switch_reduction_pct(),
            self.algorithm
        )
    }
}

/// Normalize a trace for canonical replay ordering.
///
/// This reorders trace events to minimize context switches while preserving
/// all happens-before relationships. The result is a canonical form suitable
/// for:
/// - Deterministic replay comparison
/// - Debugging (reduced noise from interleaving)
/// - Trace minimization
///
/// # Example
///
/// ```ignore
/// use asupersync::lab::replay::normalize_for_replay;
///
/// let events: Vec<TraceEvent> = /* captured trace */;
/// let result = normalize_for_replay(&events);
/// println!("{}", result); // Shows switch reduction
/// ```
#[must_use]
pub fn normalize_for_replay(events: &[TraceEvent]) -> NormalizationResult {
    normalize_for_replay_with_config(events, &crate::trace::GeodesicConfig::default())
}

/// Normalize a trace with custom configuration.
///
/// See [`crate::trace::GeodesicConfig`] for available options:
/// - `beam_threshold`: Trace size above which beam search is used
/// - `beam_width`: Width of beam search
/// - `step_budget`: Maximum search steps
#[must_use]
pub fn normalize_for_replay_with_config(
    events: &[TraceEvent],
    config: &crate::trace::GeodesicConfig,
) -> NormalizationResult {
    let original_switches = crate::trace::trace_switch_cost(events);
    let (normalized, geodesic_result) = crate::trace::normalize_trace(events, config);

    NormalizationResult {
        normalized,
        original_switches,
        normalized_switches: geodesic_result.switch_count,
        algorithm: format!("{:?}", geodesic_result.algorithm),
    }
}

/// Compare two traces for equivalence after normalization.
///
/// Two traces are considered equivalent if their normalized forms produce
/// the same sequence of events (respecting happens-before ordering).
///
/// Returns `None` if the traces are equivalent, or `Some(divergence)` if
/// they differ.
#[must_use]
pub fn compare_normalized(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let norm_a = normalize_for_replay(a);
    let norm_b = normalize_for_replay(b);
    find_divergence(&norm_a.normalized, &norm_b.normalized)
}

/// Check if two traces are equivalent under normalization.
///
/// This is a convenience wrapper around [`compare_normalized`].
#[must_use]
pub fn traces_equivalent(a: &[TraceEvent], b: &[TraceEvent]) -> bool {
    compare_normalized(a, b).is_none()
}

#[cfg(test)]
#[path = "replay_inline_tests.rs"]
mod tests;
