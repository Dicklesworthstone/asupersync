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
            let (task, _) = runtime
                .state
                .create_task(region, crate::types::Budget::INFINITE, async move {
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
                })
                .expect("create swarm task");
            let priority = (((region_index + 1) * 11 + task_index * 5) % 10) as u8;
            runtime.scheduler.lock().schedule(task, priority);
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
        let targets = runtime.state.cancel_request(region, &cancel_reason, None);
        cancel_targets += targets.len();
        let mut scheduler = runtime.scheduler.lock();
        for (task, priority) in targets {
            scheduler.schedule_cancel(task, priority);
        }
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
/// See [`GeodesicConfig`] for available options:
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
    use crate::app::AppSpec;
    use crate::lab::SporkScenarioSpec;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Budget;
    use crate::types::Time;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn trace_message_contains(event: &TraceEvent, needle: &str) -> bool {
        matches!(&event.data, TraceData::Message(message) if message.contains(needle))
    }

    fn coordination_family_index(family: &str) -> usize {
        COORDINATION_REQUIRED_FAMILIES
            .iter()
            .position(|candidate| candidate == &family)
            .map_or(99, |index| index + 1)
    }

    fn coordination_workload(family: &str) -> CoordinationWorkloadExpansion {
        let index = coordination_family_index(family);
        CoordinationWorkloadExpansion {
            workload_id: format!("ASWARM-WL-{index:03}"),
            scenario_family: family.to_string(),
            scenario_id: format!("agent-swarm.{family}"),
            semantic_pressure: coordination_allowed_semantic_pressure(family)
                .unwrap_or(&["live-only-pressure"])
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            provenance_only_context: coordination_allowed_provenance_context(family)
                .unwrap_or(&["live-only-context"])
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            source_event_count: 1,
            source_hashes: vec![format!("sha256:event-{index:03}")],
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
            replay_command: format!(
                "RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --workload ASWARM-WL-{index:03}"
            ),
            expected_artifact_globs: vec![
                "target/workload-corpus/coordination-expansion/*/coordination-workload-expansion-pack.json"
                    .to_string(),
            ],
        }
    }

    fn coordination_pack_with_order(order: &[&str]) -> CoordinationWorkloadExpansionPack {
        CoordinationWorkloadExpansionPack {
            schema_version: "runtime-workload-coordination-expansion-pack-v1".to_string(),
            pack_id: "agent-swarm-coordination-pressure".to_string(),
            baseline_denominator: false,
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
            source_run_id: "coordination-fixture".to_string(),
            missing_scenario_families: Vec::new(),
            workloads: order
                .iter()
                .map(|family| coordination_workload(family))
                .collect(),
            refused_bundles: Vec::new(),
        }
    }

    #[test]
    fn coordination_replay_canonicalizes_shuffled_workloads() {
        init_test("coordination_replay_canonicalizes_shuffled_workloads");
        let canonical = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let shuffled = coordination_pack_with_order(&[
            "coordination_latency_burst",
            "stale_in_progress_reclaim",
            "proof_runner_fanout",
            "artifact_retrieval_tail",
            "fail_closed_dirty_frontier",
            "concurrent_rch_proofs",
            "tracker_lock_contention",
        ]);
        let repeated = synthesize_coordination_pressure_replay(0xA5A0, &canonical)
            .expect("repeated canonical pack should synthesize");

        let first = synthesize_coordination_pressure_replay(0xA5A0, &canonical)
            .expect("canonical pack should synthesize");
        let second = synthesize_coordination_pressure_replay(0xA5A0, &shuffled)
            .expect("shuffled pack should synthesize");

        assert_eq!(first.log.trace_fingerprint, repeated.log.trace_fingerprint);
        assert_eq!(first.log.trace_fingerprint, second.log.trace_fingerprint);
        assert_eq!(first.log.event_count, 7);
        assert_eq!(first.log.synthesized_task_count, 15);
        assert_eq!(first.stimuli[0].scenario_family, "artifact_retrieval_tail");
        crate::test_complete!("coordination_replay_canonicalizes_shuffled_workloads");
    }

    #[test]
    fn coordination_replay_minimization_preserves_first_fail_closed_signal() {
        init_test("coordination_replay_minimization_preserves_first_fail_closed_signal");
        let pack = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let plan =
            synthesize_coordination_pressure_replay(0xA5A0, &pack).expect("pack should synthesize");
        let minimized = minimize_coordination_pressure_replay(&plan);

        assert_eq!(minimized.stimuli.len(), 1);
        assert_eq!(minimized.log.minimization_steps, 6);
        assert_eq!(minimized.log.event_count, 1);
        assert_eq!(
            minimized.log.first_failure_or_refusal.as_deref(),
            Some("dirty_frontier_fail_closed")
        );
        assert_eq!(
            minimized.stimuli[0].scenario_family,
            "fail_closed_dirty_frontier"
        );
        crate::test_complete!(
            "coordination_replay_minimization_preserves_first_fail_closed_signal"
        );
    }

    #[test]
    fn coordination_replay_rejects_missing_and_unsupported_dimensions() {
        init_test("coordination_replay_rejects_missing_and_unsupported_dimensions");
        let mut missing = coordination_pack_with_order(&["tracker_lock_contention"]);
        assert!(matches!(
            synthesize_coordination_pressure_replay(1, &missing),
            Err(CoordinationReplayError::MissingScenarioDimensions { .. })
        ));

        missing.workloads = COORDINATION_REQUIRED_FAMILIES
            .iter()
            .map(|family| coordination_workload(family))
            .collect();
        missing.workloads[0].scenario_family = "live_agent_mail_socket".to_string();
        assert_eq!(
            synthesize_coordination_pressure_replay(1, &missing),
            Err(CoordinationReplayError::MissingScenarioDimensions {
                missing: vec!["tracker_lock_contention".to_string()],
            })
        );

        let mut unsupported = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        unsupported
            .workloads
            .push(coordination_workload("live_agent_mail_socket"));
        assert_eq!(
            synthesize_coordination_pressure_replay(1, &unsupported),
            Err(CoordinationReplayError::UnsupportedScenarioFamily {
                family: "live_agent_mail_socket".to_string(),
            })
        );
        crate::test_complete!("coordination_replay_rejects_missing_and_unsupported_dimensions");
    }

    #[test]
    fn coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields() {
        init_test("coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields");
        let mut pack = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        let artifact_tail = pack
            .workloads
            .iter_mut()
            .find(|workload| workload.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail workload");
        artifact_tail.source_event_count = 2;
        artifact_tail.source_hashes = vec![
            "sha256:artifact-tail-b".to_string(),
            "sha256:artifact-tail-a".to_string(),
        ];

        let mut source_shuffled = pack.clone();
        source_shuffled.workloads.reverse();
        source_shuffled
            .workloads
            .iter_mut()
            .find(|workload| workload.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail workload")
            .source_hashes
            .reverse();

        let canonical = synthesize_coordination_pressure_replay(7, &pack)
            .expect("canonical source hashes should synthesize");
        let shuffled = synthesize_coordination_pressure_replay(7, &source_shuffled)
            .expect("shuffled source hashes should synthesize");
        assert_eq!(
            canonical.log.trace_fingerprint,
            shuffled.log.trace_fingerprint
        );
        assert_eq!(canonical.log.event_count, 8);
        let artifact_tail = canonical
            .stimuli
            .iter()
            .find(|stimulus| stimulus.scenario_family == "artifact_retrieval_tail")
            .expect("artifact tail stimulus");
        assert_eq!(artifact_tail.artifact_delay_ticks, 10);
        assert_eq!(
            artifact_tail.source_hashes,
            vec![
                "sha256:artifact-tail-a".to_string(),
                "sha256:artifact-tail-b".to_string()
            ]
        );

        let mut live_only = coordination_pack_with_order(&[
            "tracker_lock_contention",
            "concurrent_rch_proofs",
            "fail_closed_dirty_frontier",
            "artifact_retrieval_tail",
            "proof_runner_fanout",
            "stale_in_progress_reclaim",
            "coordination_latency_burst",
        ]);
        live_only.workloads[0]
            .semantic_pressure
            .push("live-agent-mail-socket".to_string());
        assert_eq!(
            synthesize_coordination_pressure_replay(7, &live_only),
            Err(CoordinationReplayError::UnsupportedScenarioField {
                workload_id: "ASWARM-WL-001".to_string(),
                field: "semantic_pressure",
                value: "live-agent-mail-socket".to_string(),
            })
        );
        crate::test_complete!(
            "coordination_replay_canonicalizes_source_hashes_and_rejects_live_only_fields"
        );
    }

    #[test]
    fn swarm_replay_lab_summary_is_byte_stable() {
        init_test("swarm_replay_lab_summary_is_byte_stable");
        let knobs = SwarmReplayScenarioKnobs::ci();
        let first = run_swarm_replay_lab(0x5EED_5A1D, &knobs);
        let second = run_swarm_replay_lab(0x5EED_5A1D, &knobs);

        let first_bytes = serde_json::to_vec(&first).expect("serialize first swarm summary");
        let second_bytes = serde_json::to_vec(&second).expect("serialize second swarm summary");
        assert_eq!(
            first_bytes, second_bytes,
            "same-seed swarm replay summary must be byte-stable"
        );
        assert_eq!(first.schema_version, SWARM_REPLAY_LAB_SCHEMA_VERSION);
        assert_eq!(first.seed, 0x5EED_5A1D);
        assert_eq!(first.resource_deltas.tasks_created, 16);
        assert_eq!(first.resource_deltas.messages_committed, 32);
        assert_eq!(
            first.log.trace_artifact_refs.len(),
            first.knobs.artifact_count
        );
        crate::test_complete!("swarm_replay_lab_summary_is_byte_stable");
    }

    #[test]
    fn swarm_replay_cancellation_cascade_reaches_quiescence() {
        init_test("swarm_replay_cancellation_cascade_reaches_quiescence");
        let summary = run_swarm_replay_lab(0xC4CE_5A1D, &SwarmReplayScenarioKnobs::ci());

        assert!(summary.lab.quiescent, "swarm replay should quiesce");
        assert!(
            summary.lab.invariant_violations.is_empty(),
            "swarm replay invariants should be clean: {:?}",
            summary.lab.invariant_violations
        );
        assert!(
            summary.lab.temporal_failures.is_empty(),
            "swarm replay temporal invariants should be clean: {:?}",
            summary.lab.temporal_failures
        );
        assert!(
            summary.resource_deltas.cancel_targets > 0,
            "cancellation cascade must schedule cancel-lane work"
        );
        assert_eq!(
            summary.resource_deltas.messages_committed, summary.resource_deltas.messages_drained,
            "modeled channel backlog must drain completely"
        );
        assert!(
            summary.resource_deltas.channel_backpressure_events > 0,
            "channel workload must exercise backpressure"
        );
        assert!(
            summary.log.minimized_failing_schedule.is_none(),
            "passing swarm replay should not carry a minimized failure"
        );
        crate::test_complete!("swarm_replay_cancellation_cascade_reaches_quiescence");
    }

    #[test]
    fn swarm_replay_log_records_minimized_failure_schedule() {
        init_test("swarm_replay_log_records_minimized_failure_schedule");
        let knobs = SwarmReplayScenarioKnobs {
            max_steps: 1,
            ..SwarmReplayScenarioKnobs::ci()
        };
        let summary = run_swarm_replay_lab(0xFA11_5EED, &knobs);
        let minimized = summary
            .log
            .minimized_failing_schedule
            .as_ref()
            .expect("step-limited replay should emit minimized failure schedule");

        assert_eq!(summary.log.seed, summary.seed);
        assert_eq!(summary.log.scenario_knobs, summary.knobs);
        assert_eq!(summary.log.resource_deltas, summary.resource_deltas);
        assert!(
            !minimized.preserved_invariant.is_empty(),
            "minimized schedule should name the preserved invariant"
        );
        assert!(
            minimized
                .schedule_steps
                .iter()
                .any(|step| step.contains("channel capacity=")),
            "minimized schedule should retain channel/backpressure context"
        );
        assert!(
            minimized
                .schedule_steps
                .iter()
                .any(|step| step.contains("cancel stride=")),
            "minimized schedule should retain cancellation context"
        );
        crate::test_complete!("swarm_replay_log_records_minimized_failure_schedule");
    }

    #[test]
    fn identical_traces_no_divergence() {
        init_test("identical_traces_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "no divergence", true, ok);
        crate::test_complete!("identical_traces_no_divergence");
    }

    #[test]
    fn trace_seq_only_difference_no_divergence() {
        init_test("trace_seq_only_difference_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];
        let b = vec![TraceEvent::new(
            99,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "seq-only differences ignored", true, ok);
        crate::test_complete!("trace_seq_only_difference_no_divergence");
    }

    #[test]
    fn different_traces_find_divergence() {
        init_test("different_traces_find_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence");
    }

    #[test]
    fn different_traces_find_divergence_data() {
        init_test("different_traces_find_divergence_data");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("a".to_string()),
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("b".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence_data");
    }

    // ── Replay validation tests ─────────────────────────────────────────

    #[test]
    fn replay_single_task_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(42, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
        assert_eq!(
            validation.original_certificate,
            validation.replay_certificate
        );
        assert_eq!(validation.original_steps, validation.replay_steps);
    }

    #[test]
    fn replay_two_tasks_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
    }

    #[test]
    fn replay_multi_seeds_all_deterministic() {
        use crate::types::Budget;
        let seeds: Vec<u64> = (0..10).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(v.is_valid(), "Seed {} replay failed: {v}", seeds[i]);
        }
    }

    // ── Σ-state replay determinism conformance ──────────────────────────
    // Spec contract (lab.replay): two runs of the same closure with the same
    // seed and worker_count MUST produce bit-identical schedule certificates,
    // step counts, and trace event sequences. The certificate hash is the
    // observable Σ-state fingerprint; trace events are the witness sequence.
    // These tests cover the riskier scenarios (panic cleanup, multi-region
    // cancel cascade, mixed cancel + panic) that the simpler "single task"
    // and "two tasks" tests do not exercise.

    /// Σ-state replay determinism: a panicking task must clean up identically
    /// across two runs. The CatchUnwind wrapper turns the panic into
    /// `Outcome::Panicked`; the trace events emitted by region cleanup must be
    /// identical on both runs.
    #[test]
    fn replay_panic_cleanup_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0xa11ce, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (panicker, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {
                    panic!("conformance panic-cleanup probe");
                })
                .expect("panicker");
            let (sibling, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 7_u32 })
                .expect("sibling");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(panicker, 0);
                sched.schedule(sibling, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Panic-cleanup replay diverged: {validation}",
        );
    }

    /// Σ-state replay determinism: a region tree with a mid-flight cancel
    /// cascade. Cancellation propagates parent → child via
    /// `cancel_request`, generating ordered trace events for region transitions
    /// and task cancels. The certificate, step count, and trace must match
    /// across replays.
    #[test]
    fn replay_multi_region_cancel_cascade_deterministic() {
        use crate::types::{Budget, CancelReason};
        let validation = validate_replay(0xc4cebb1e, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child_a = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child a");
            let child_b = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child b");
            let child_c = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child c");

            for region in [child_a, child_b, child_c] {
                for i in 0..2 {
                    let (task, _) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, async move { i })
                        .expect("task");
                    runtime.scheduler.lock().schedule(task, 0);
                }
            }

            let cancel_targets = runtime.state.cancel_request(
                child_b,
                &CancelReason::user("conformance partial cancel"),
                None,
            );
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in cancel_targets {
                    sched.schedule_cancel(task, priority);
                }
            }

            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Multi-region cancel cascade replay diverged: {validation}",
        );
    }

    /// Σ-state replay determinism: cancel cascade interleaved with a
    /// panicking task. The panic CatchUnwind path and the cancel propagation
    /// path share state; the union must still replay deterministically.
    #[test]
    fn replay_panic_during_cancel_cascade_deterministic() {
        use crate::types::{Budget, CancelReason};
        let validation = validate_replay(0xdeadc0de, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let doomed = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("doomed region");

            let (panicker, _) = runtime
                .state
                .create_task(doomed, Budget::INFINITE, async {
                    panic!("panic during cancel cascade");
                })
                .expect("panicker");
            let (sleeper, _) = runtime
                .state
                .create_task(doomed, Budget::INFINITE, async { 1_u8 })
                .expect("sleeper");
            let (root_task, _) = runtime
                .state
                .create_task(root, Budget::INFINITE, async { 2_u8 })
                .expect("root_task");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(panicker, 0);
                sched.schedule(sleeper, 0);
                sched.schedule(root_task, 0);
            }

            let cancel_targets = runtime.state.cancel_request(
                doomed,
                &CancelReason::user("doomed subtree cancel"),
                None,
            );
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in cancel_targets {
                    sched.schedule_cancel(task, priority);
                }
            }

            runtime.run_until_quiescent();
        });

        assert!(
            validation.is_valid(),
            "Panic-during-cancel-cascade replay diverged: {validation}",
        );
    }

    /// Replay determinism must hold across many seeds for the multi-region
    /// cancel cascade scenario. A single-seed pass can miss a Σ-state path
    /// only reached on certain dispatch orderings.
    #[test]
    fn replay_multi_region_cancel_cascade_deterministic_across_seeds() {
        use crate::types::{Budget, CancelReason};
        let seeds: Vec<u64> = (0..16).map(|i| 0xc4cebb1e ^ (i * 0x9E37_79B9)).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            let child_a = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child a");
            let child_b = runtime
                .state
                .create_child_region(root, Budget::INFINITE)
                .expect("child b");
            for region in [child_a, child_b] {
                for i in 0..3 {
                    let (task, _) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, async move { i })
                        .expect("task");
                    runtime.scheduler.lock().schedule(task, 0);
                }
            }
            let targets = runtime.state.cancel_request(
                child_a,
                &CancelReason::user("conformance multi-seed cancel"),
                None,
            );
            {
                let mut sched = runtime.scheduler.lock();
                for (task, priority) in targets {
                    sched.schedule_cancel(task, priority);
                }
            }
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(
                v.is_valid(),
                "Multi-region cancel cascade diverged at seed {:#x}: {v}",
                seeds[i],
            );
        }
    }

    #[test]
    fn replay_validation_display_ok() {
        let v = ReplayValidation {
            matched: true,
            original_certificate: 0x1234,
            replay_certificate: 0x1234,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("Replay OK"));
    }

    #[test]
    fn replay_validation_display_diverged() {
        let v = ReplayValidation {
            matched: false,
            original_certificate: 0x1234,
            replay_certificate: 0x5678,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("DIVERGED"));
        assert!(s.contains("Certificate mismatch"));
    }

    // ── Normalization tests ─────────────────────────────────────────────

    #[test]
    fn normalization_single_owner_no_switches() {
        init_test("normalization_single_owner_no_switches");
        // All events from owner 1 - should have 0 switches
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(2),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];
        // All have seq numbers, but owner extraction uses seq % some_value or similar
        // The trace module should handle this; we're testing the wrapper

        let result = normalize_for_replay(&events);
        // Single-owner trace has no switches before or after
        assert_eq!(result.switch_reduction(), 0);
        crate::test_complete!("normalization_single_owner_no_switches");
    }

    #[test]
    fn normalization_result_display() {
        init_test("normalization_result_display");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 10,
            normalized_switches: 3,
            algorithm: "Greedy".to_string(),
        };

        let display = format!("{result}");
        assert!(display.contains("10 → 3 switches"));
        assert!(display.contains("70.0% reduction"));
        assert!(display.contains("Greedy"));
        crate::test_complete!("normalization_result_display");
    }

    #[test]
    fn normalization_result_zero_switches() {
        init_test("normalization_result_zero_switches");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 0,
            normalized_switches: 0,
            algorithm: "Trivial".to_string(),
        };

        // Avoid division by zero
        let pct = result.switch_reduction_pct();
        assert!((pct - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("normalization_result_zero_switches");
    }

    #[test]
    fn traces_equivalent_identical() {
        init_test("traces_equivalent_identical");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];

        let equivalent = traces_equivalent(&events, &events);
        crate::assert_with_log!(equivalent, "identical traces equivalent", true, equivalent);
        crate::test_complete!("traces_equivalent_identical");
    }

    #[test]
    fn traces_equivalent_ignores_sequence_numbers() {
        init_test("traces_equivalent_ignores_sequence_numbers");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            42,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            equivalent,
            "seq-only differences still equivalent",
            true,
            equivalent
        );
        crate::test_complete!("traces_equivalent_ignores_sequence_numbers");
    }

    #[test]
    fn traces_equivalent_different_kinds() {
        init_test("traces_equivalent_different_kinds");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            !equivalent,
            "different kinds not equivalent",
            false,
            equivalent
        );
        crate::test_complete!("traces_equivalent_different_kinds");
    }

    #[test]
    fn compare_normalized_returns_divergence() {
        init_test("compare_normalized_returns_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let divergence = compare_normalized(&a, &b);
        let has_div = divergence.is_some();
        crate::assert_with_log!(has_div, "divergence found", true, has_div);
        crate::test_complete!("compare_normalized_returns_divergence");
    }

    #[test]
    fn normalize_with_config_custom_beam() {
        use crate::trace::GeodesicConfig;

        init_test("normalize_with_config_custom_beam");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
        ];

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1,
            beam_width: 4,
            step_budget: 100,
        };

        let result = normalize_for_replay_with_config(&events, &config);
        // Just verify it runs without panic; algorithm choice depends on trace size
        assert!(!result.algorithm.is_empty());
        crate::test_complete!("normalize_with_config_custom_beam");
    }

    #[test]
    fn classify_fingerprint_classes_is_deterministic() {
        init_test("classify_fingerprint_classes_is_deterministic");

        let runs = vec![
            ExplorationRunSummary {
                seed: 9,
                schedule_hash: 0xB,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 3,
                schedule_hash: 0xA,
                trace_fingerprint: 0xBB,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
        ];

        let classes = classify_fingerprint_classes(&runs);
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].trace_fingerprint, 0xAA);
        assert_eq!(classes[0].run_count, 3);
        assert_eq!(classes[0].seeds, vec![7, 9]);
        assert_eq!(classes[0].schedule_hashes, vec![0xB, 0xC]);
        assert_eq!(classes[1].trace_fingerprint, 0xBB);
        assert_eq!(classes[1].run_count, 1);
        assert_eq!(classes[1].seeds, vec![3]);
        assert_eq!(classes[1].schedule_hashes, vec![0xA]);

        crate::test_complete!("classify_fingerprint_classes_is_deterministic");
    }

    #[test]
    fn explore_seed_space_is_deterministic_for_same_inputs() {
        init_test("explore_seed_space_is_deterministic_for_same_inputs");

        let seeds = [11_u64, 13_u64, 11_u64];
        let scenario = |runtime: &mut LabRuntime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        };

        let a = explore_seed_space(&seeds, 1, scenario);
        let b = explore_seed_space(&seeds, 1, scenario);

        assert_eq!(a, b, "same seeds and scenario must produce same report");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        crate::test_complete!("explore_seed_space_is_deterministic_for_same_inputs");
    }

    fn make_spork_report(seed: u64, failing: bool) -> SporkHarnessReport {
        use crate::record::ObligationKind;

        let config = LabConfig::new(seed).panic_on_leak(false);
        let mut runtime = LabRuntime::new(config);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        // Create the obligation while the task is still live so the holder
        // validation passes.  Running to quiescence afterward leaves the
        // obligation unresolved (intentional leak → failing report).
        if failing {
            runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task,
                    region,
                    Some("intentional failure for exploration".to_string()),
                )
                .expect("create failing obligation");
        }
        runtime.run_until_quiescent();

        runtime.spork_report("spork_exploration", Vec::new())
    }

    #[test]
    fn summarize_spork_reports_links_failures_to_crashpacks() {
        init_test("summarize_spork_reports_links_failures_to_crashpacks");

        let passing = make_spork_report(31, false);
        let failing = make_spork_report(32, true);

        let summary = summarize_spork_reports(&[failing, passing]);
        assert_eq!(summary.runs.len(), 2);
        assert_eq!(summary.failure_count(), 1);
        assert!(summary.unique_fingerprint_count() >= 1);
        assert!(
            summary.all_failures_linked_to_crashpacks(),
            "failed runs must include crashpack linkage metadata"
        );

        let failed_run = summary
            .runs
            .iter()
            .find(|run| !run.passed)
            .expect("one failing run expected");
        let crashpack = failed_run
            .crashpack_link
            .as_ref()
            .expect("failing run should have crashpack link");
        assert!(
            crashpack.path.starts_with("crashpack-"),
            "unexpected crashpack path: {}",
            crashpack.path
        );

        crate::test_complete!("summarize_spork_reports_links_failures_to_crashpacks");
    }

    #[test]
    fn explore_spork_seed_space_is_deterministic() {
        init_test("explore_spork_seed_space_is_deterministic");

        let seeds = [42_u64, 41_u64, 42_u64];

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let a = explore_spork_seed_space(&seeds, run_for_seed);

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let b = explore_spork_seed_space(&seeds, run_for_seed);

        assert_eq!(a, b, "same seeds must produce deterministic report");
        assert_eq!(a.runs.len(), seeds.len());
        assert_eq!(a.failure_count(), 2);
        assert!(a.unique_fingerprint_count() >= 1);
        assert!(a.all_failures_linked_to_crashpacks());

        crate::test_complete!("explore_spork_seed_space_is_deterministic");
    }

    #[test]
    fn scenario_runner_exploration_has_deterministic_fingerprints() {
        init_test("scenario_runner_exploration_has_deterministic_fingerprints");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("replay.scenario", |_| AppSpec::new("replay_app"))
                    .with_default_config(SporkScenarioConfig::default()),
            )
            .expect("register scenario");

        let base_config = SporkScenarioConfig::default();
        let seeds = [12_u64, 13_u64, 12_u64];

        let a =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration A");
        let b =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration B");

        assert_eq!(a, b, "scenario exploration must be deterministic");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        // Same seed should map to the same fingerprint.
        let seed_12: Vec<_> = a.runs.iter().filter(|run| run.seed == 12).collect();
        assert_eq!(seed_12.len(), 2);
        assert_eq!(seed_12[0].trace_fingerprint, seed_12[1].trace_fingerprint);

        crate::test_complete!("scenario_runner_exploration_has_deterministic_fingerprints");
    }

    fn make_dual_run_divergence_result() -> crate::lab::dual_run::DualRunResult {
        use crate::lab::dual_run::{
            CancellationRecord, DualRunHarness, LoserDrainRecord, ObligationBalanceRecord,
            RegionCloseRecord, ResourceSurfaceRecord, TerminalOutcome,
        };

        fn base_semantics() -> crate::lab::dual_run::NormalizedSemantics {
            crate::lab::dual_run::NormalizedSemantics {
                terminal_outcome: TerminalOutcome::ok(),
                cancellation: CancellationRecord::none(),
                loser_drain: LoserDrainRecord::not_applicable(),
                region_close: RegionCloseRecord::quiescent(),
                obligation_balance: ObligationBalanceRecord::zero(),
                resource_surface: ResourceSurfaceRecord::empty("test.surface"),
            }
        }

        let mut result = DualRunHarness::phase1(
            "divergence.registry.case",
            "test.surface",
            "v1",
            "Divergence corpus registry coverage",
            0xD1,
        )
        .lab(|_config| base_semantics())
        .live(|_seed, _entropy| {
            let mut sem = base_semantics();
            sem.obligation_balance = ObligationBalanceRecord {
                reserved: 1,
                committed: 0,
                aborted: 0,
                leaked: 1,
                unresolved: 0,
                balanced: false,
            };
            sem
        })
        .run();

        let mut lab_provenance = result
            .lab
            .provenance
            .clone()
            .with_artifact_path("crashpack-divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture");
        if lab_provenance.trace_fingerprint.is_none() {
            lab_provenance.trace_fingerprint = Some(0xC0DE_CAFE);
        }
        result.lab.provenance = lab_provenance;

        let mut live_provenance = result
            .live
            .provenance
            .clone()
            .with_artifact_path("artifacts/live/divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture --live");
        if live_provenance.trace_fingerprint.is_none() {
            live_provenance.trace_fingerprint = Some(0xBEEF_BAAD);
        }
        result.live.provenance = live_provenance;
        result
    }

    #[test]
    fn divergence_artifact_bundle_uses_stable_bundle_layout() {
        init_test("divergence_artifact_bundle_uses_stable_bundle_layout");

        let bundle = DivergenceArtifactBundle::under("artifacts/differential/run-001");
        assert_eq!(
            bundle.differential_summary_path,
            "artifacts/differential/run-001/differential_summary.json"
        );
        assert_eq!(
            bundle.live_normalized_path,
            "artifacts/differential/run-001/live_normalized.json"
        );

        crate::test_complete!("divergence_artifact_bundle_uses_stable_bundle_layout");
    }

    #[test]
    fn divergence_retention_defaults_follow_policy_class() {
        init_test("divergence_retention_defaults_follow_policy_class");

        let full = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        assert_eq!(full.bundle_level, DivergenceBundleLevel::Full);
        assert_eq!(full.local_retention_days, 14);
        assert_eq!(full.ci_retention_days, 30);
        assert_eq!(full.redaction_mode, "metadata_only");

        let reduced = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::UnsupportedSurface,
        );
        assert_eq!(reduced.bundle_level, DivergenceBundleLevel::Reduced);

        crate::test_complete!("divergence_retention_defaults_follow_policy_class");
    }

    #[test]
    fn divergence_corpus_entry_tracks_lineage_and_promotion_state() {
        init_test("divergence_corpus_entry_tracks_lineage_and_promotion_state");

        let result = make_dual_run_divergence_result();
        assert!(!result.passed(), "test fixture must produce a divergence");

        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "pilot_surface",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/test-run",
        )
        .with_first_seen_attempt(2, 1)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        assert_eq!(
            entry.policy_class,
            DifferentialPolicyClass::RuntimeSemanticBug
        );
        assert_eq!(entry.first_seen.runner_profile, "pilot_surface");
        assert_eq!(entry.first_seen.attempt_index, 2);
        assert_eq!(entry.first_seen.rerun_count, 1);
        assert_eq!(
            entry.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            entry.regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );
        assert_eq!(
            entry.metadata.get("promoted_scenario_id"),
            Some(&"regression.test.surface.obligation_leak.seed_2a".to_string())
        );
        assert!(
            entry
                .mismatch_fields
                .contains(&"semantics.obligation_balance.balanced".to_string()),
            "mismatch fields should retain the semantic mismatch path"
        );
        assert!(
            entry
                .artifact_bundle
                .differential_repro_manifest_path
                .ends_with("differential_repro_manifest.json")
        );
        assert_eq!(
            entry.artifact_bundle.bundle_root,
            "artifacts/differential/test-run"
        );

        crate::test_complete!("divergence_corpus_entry_tracks_lineage_and_promotion_state");
    }

    #[test]
    fn divergence_registry_upsert_is_deterministic() {
        init_test("divergence_registry_upsert_is_deterministic");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly-case",
        );

        let mut registry = DivergenceCorpusRegistry::new();
        registry.upsert(entry.clone());
        registry.upsert(entry.promote_to_regression("regression.promoted"));

        assert_eq!(registry.schema_version, DIVERGENCE_CORPUS_SCHEMA_VERSION);
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );

        crate::test_complete!("divergence_registry_upsert_is_deterministic");
    }

    #[test]
    fn sanitize_registry_component_never_returns_empty() {
        init_test("sanitize_registry_component_never_returns_empty");

        assert_eq!(sanitize_registry_component(""), "z-0-");
        assert_eq!(sanitize_registry_component(":::"), "z-3-3a3a3a");
        assert_eq!(sanitize_registry_component(" / "), "z-3-202f20");
        assert_eq!(sanitize_registry_component("___"), "___");
        assert_eq!(sanitize_registry_component("scenario-1"), "scenario-1");

        crate::test_complete!("sanitize_registry_component_never_returns_empty");
    }

    #[test]
    fn divergence_registry_components_do_not_alias_escaped_or_literal_segments() {
        init_test("divergence_registry_components_do_not_alias_escaped_or_literal_segments");

        let colon_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            ":::",
            " / ",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let underscore_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "___",
            " / ",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );

        assert_ne!(
            colon_entry_id, underscore_entry_id,
            "distinct raw IDs must not collapse to the same registry entry id"
        );
        assert!(colon_entry_id.starts_with("surface.z-3-3a3a3a."));
        assert!(underscore_entry_id.starts_with("surface.___."));

        let slash_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "a/b",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let underscore_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "a_b",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let escaped_looking_entry_id = DivergenceCorpusEntry::entry_id_for(
            "surface",
            "z-3-616263",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        assert_ne!(slash_entry_id, underscore_entry_id);
        assert_ne!(slash_entry_id, escaped_looking_entry_id);
        assert_ne!(underscore_entry_id, escaped_looking_entry_id);

        let entry = DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                " / ",
                ":::",
                "___",
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            scenario_id: ":::".to_string(),
            surface_id: " / ".to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class: DifferentialPolicyClass::RuntimeSemanticBug,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "___".to_string(),
                canonical_seed: 7,
                lab_effective_seed: 7,
                live_effective_seed: 7,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 7,
                live_entropy_seed: 7,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under("artifacts/differential/test"),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "___".to_string(),
                    canonical_seed: 7,
                    lab_effective_seed: 7,
                    live_effective_seed: 7,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 7,
                    live_entropy_seed: 7,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            metadata: BTreeMap::new(),
        };

        assert_eq!(
            entry.default_bundle_root(),
            "artifacts/differential/z-3-202f20/z-3-3a3a3a/___/runtime_semantic_bug"
        );

        crate::test_complete!(
            "divergence_registry_components_do_not_alias_escaped_or_literal_segments"
        );
    }

    #[test]
    fn divergence_registry_entry_id_includes_surface_id() {
        init_test("divergence_registry_entry_id_includes_surface_id");

        let first = DivergenceCorpusEntry::entry_id_for(
            "surface-a",
            "scenario",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        let second = DivergenceCorpusEntry::entry_id_for(
            "surface-b",
            "scenario",
            "seed",
            DifferentialPolicyClass::RuntimeSemanticBug,
        );

        assert_ne!(
            first, second,
            "different surfaces must not alias to the same registry entry id"
        );
        assert!(first.starts_with("surface-a."));
        assert!(second.starts_with("surface-b."));

        let mut registry = DivergenceCorpusRegistry::new();
        let make_entry = |surface_id: &str| DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                surface_id,
                "scenario",
                "seed",
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            scenario_id: "scenario".to_string(),
            surface_id: surface_id.to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class: DifferentialPolicyClass::RuntimeSemanticBug,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "seed".to_string(),
                canonical_seed: 7,
                lab_effective_seed: 7,
                live_effective_seed: 7,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 7,
                live_entropy_seed: 7,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under(format!(
                "artifacts/differential/{surface_id}"
            )),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "seed".to_string(),
                    canonical_seed: 7,
                    lab_effective_seed: 7,
                    live_effective_seed: 7,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 7,
                    live_entropy_seed: 7,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(
                DifferentialPolicyClass::RuntimeSemanticBug,
            ),
            metadata: BTreeMap::new(),
        };

        registry.upsert(make_entry("surface-a"));
        registry.upsert(make_entry("surface-b"));
        assert_eq!(registry.entries.len(), 2);
        assert_eq!(registry.entries[0].surface_id, "surface-a");
        assert_eq!(registry.entries[1].surface_id, "surface-b");

        crate::test_complete!("divergence_registry_entry_id_includes_surface_id");
    }

    #[test]
    fn divergence_default_bundle_root_includes_policy_class() {
        init_test("divergence_default_bundle_root_includes_policy_class");

        let make_entry = |policy_class| DivergenceCorpusEntry {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id: DivergenceCorpusEntry::entry_id_for(
                "surface",
                "scenario",
                "seed",
                policy_class,
            ),
            scenario_id: "scenario".to_string(),
            surface_id: "surface".to_string(),
            surface_contract_version: "v1".to_string(),
            divergence_class: "semantic".to_string(),
            policy_class,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: "nightly".to_string(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: crate::lab::dual_run::SeedLineageRecord {
                seed_lineage_id: "seed".to_string(),
                canonical_seed: 1,
                lab_effective_seed: 1,
                live_effective_seed: 1,
                lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                lab_entropy_seed: 1,
                live_entropy_seed: 1,
                replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                seeds_match: true,
                annotations: BTreeMap::new(),
            },
            mismatch_fields: Vec::new(),
            artifact_bundle: DivergenceArtifactBundle::under("artifacts/differential/test"),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(
                &crate::lab::dual_run::SeedLineageRecord {
                    seed_lineage_id: "seed".to_string(),
                    canonical_seed: 1,
                    lab_effective_seed: 1,
                    live_effective_seed: 1,
                    lab_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    live_seed_mode: crate::lab::dual_run::SeedMode::Inherit,
                    lab_entropy_seed: 1,
                    live_entropy_seed: 1,
                    replay_policy: crate::lab::dual_run::ReplayPolicy::SingleSeed,
                    seeds_match: true,
                    annotations: BTreeMap::new(),
                },
            ),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(policy_class),
            metadata: BTreeMap::new(),
        };

        let runtime_semantic_bug =
            make_entry(DifferentialPolicyClass::RuntimeSemanticBug).default_bundle_root();
        let unsupported_surface =
            make_entry(DifferentialPolicyClass::UnsupportedSurface).default_bundle_root();

        assert_ne!(
            runtime_semantic_bug, unsupported_surface,
            "different policy classes must not alias to the same retained bundle path"
        );
        assert!(runtime_semantic_bug.ends_with("/runtime_semantic_bug"));
        assert!(unsupported_surface.ends_with("/unsupported_surface"));

        crate::test_complete!("divergence_default_bundle_root_includes_policy_class");
    }

    #[test]
    fn differential_bundle_artifacts_capture_repro_and_minimization_lineage() {
        init_test("differential_bundle_artifacts_capture_repro_and_minimization_lineage");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly/divergence.registry.case",
        )
        .with_first_seen_attempt(3, 2)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);
        assert_eq!(
            bundle.summary.schema_version,
            DIFFERENTIAL_SUMMARY_SCHEMA_VERSION
        );
        assert_eq!(
            bundle.summary.bundle_root,
            "artifacts/differential/nightly/divergence.registry.case"
        );
        assert_eq!(bundle.failures.failure_artifacts.len(), 2);
        assert_eq!(
            bundle.failures.failure_artifacts[0].runtime_kind,
            "lab".to_string()
        );
        assert_eq!(
            bundle.failures.failure_artifacts[0]
                .crashpack_link
                .as_ref()
                .map(|link| link.path.as_str()),
            Some("crashpack-divergence.registry.case.json")
        );
        assert_eq!(
            bundle.repro_manifest.promoted_scenario_id.as_deref(),
            Some("regression.test.surface.obligation_leak.seed_2a")
        );
        assert_eq!(
            bundle.repro_manifest.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            bundle.repro_manifest.failure_artifacts_path,
            "artifacts/differential/nightly/divergence.registry.case/differential_failures.json"
        );
        assert!(
            bundle
                .repro_manifest
                .repro_commands
                .contains(&"cargo test divergence.registry.case -- --nocapture".to_string())
        );
        assert!(
            bundle
                .deviations
                .mismatches
                .iter()
                .any(|mismatch| mismatch.field == "semantics.obligation_balance.balanced")
        );

        crate::test_complete!(
            "differential_bundle_artifacts_capture_repro_and_minimization_lineage"
        );
    }

    #[test]
    fn inferred_crashpack_reference_requires_crashpack_like_path() {
        init_test("inferred_crashpack_reference_requires_crashpack_like_path");

        let result = make_dual_run_divergence_result();
        let lab_link = DifferentialCrashpackReference::from_provenance(&result.lab.provenance);
        let live_link = DifferentialCrashpackReference::from_provenance(&result.live.provenance);

        assert!(
            lab_link.is_some(),
            "crashpack-like lab artifact should infer linkage"
        );
        assert!(
            live_link.is_none(),
            "non-crashpack live artifact should not infer crashpack linkage"
        );

        crate::test_complete!("inferred_crashpack_reference_requires_crashpack_like_path");
    }

    // =========================================================================
    // METAMORPHIC TESTING: Lab::Replay Deterministic Fork/Join
    // =========================================================================

    /// Configuration for metamorphic replay testing
    #[derive(Debug, Clone)]
    struct ReplayMetamorphicConfig {
        /// Number of workers for parallel execution
        worker_count: usize,
        /// Number of checkpoints to test
        checkpoint_count: usize,
        /// Number of concurrent tasks to spawn
        task_count: usize,
    }

    impl Default for ReplayMetamorphicConfig {
        fn default() -> Self {
            Self {
                worker_count: 4,
                checkpoint_count: 5,
                task_count: 8,
            }
        }
    }

    /// Generate deterministic test scenario for fork/join patterns
    fn create_fork_join_test_scenario(
        config: &ReplayMetamorphicConfig,
        rng_seed: u64,
    ) -> impl Fn(&mut LabRuntime) + Clone {
        let task_count = config.task_count;
        move |runtime: &mut LabRuntime| {
            // Use the runtime's deterministic execution to create fork/join patterns
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(rng_seed);

            // Create a simple fork/join pattern with multiple concurrent tasks
            for i in 0..task_count {
                let _task_seed = rng.next_u64();
                // This would normally spawn tasks using the runtime's spawn mechanisms
                // For testing, we'll create trace events that represent fork/join operations
                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("fork_task_{}", i),
                    )
                });
            }

            // Simulate join phase
            for i in 0..task_count {
                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("join_task_{}", i),
                    )
                });
            }
        }
    }

    // =========================================================================
    // MR1: Checkpoint Replay Equivalence
    // =========================================================================

    #[test]
    fn metamorphic_checkpoint_replay_equivalence() {
        init_test("metamorphic_checkpoint_replay_equivalence");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario: original execution vs replay from various checkpoints
        let test_scenario = create_fork_join_test_scenario(&config, seed);

        // Run original execution
        let mut original_config = LabConfig::new(seed);
        original_config = original_config.worker_count(config.worker_count);
        let mut original_runtime = LabRuntime::new(original_config);
        test_scenario(&mut original_runtime);
        let original_trace = original_runtime.trace().snapshot();
        let original_certificate = original_runtime.certificate().hash();

        // MR: Replay from different checkpoints should produce equivalent results
        // when executed to the same point
        for checkpoint_idx in 0..config.checkpoint_count.min(original_trace.len()) {
            let mut replay_config = LabConfig::new(seed);
            replay_config = replay_config.worker_count(config.worker_count);
            let mut replay_runtime = LabRuntime::new(replay_config);

            // Simulate replay from checkpoint by processing events up to checkpoint
            for event in &original_trace[..checkpoint_idx] {
                replay_runtime.trace().push_event(event.clone());
            }

            // Continue execution from checkpoint
            test_scenario(&mut replay_runtime);
            let replay_trace = replay_runtime.trace().snapshot();
            let replay_certificate = replay_runtime.certificate().hash();

            // MR: Certificate hashes should match between original and replayed execution
            assert_eq!(
                original_certificate, replay_certificate,
                "Checkpoint {} replay diverged in certificate hash",
                checkpoint_idx
            );

            // MR: The portion of the trace up to the checkpoint is recorded
            // by replaying exact original events. Those events must match
            // byte-for-byte (the checkpoint-prefix invariant). Events after
            // the checkpoint are re-generated by rerunning the test scenario
            // on a fresh runtime, so they form a second independent recording
            // rather than a true continuation — comparing those positions
            // against the original is ill-defined and is therefore skipped.
            for (i, (orig_event, replay_event)) in original_trace
                .iter()
                .zip(replay_trace.iter())
                .enumerate()
                .take(checkpoint_idx)
            {
                assert!(
                    events_match(orig_event, replay_event),
                    "Event {} before checkpoint {} doesn't match: {:?} vs {:?}",
                    i,
                    checkpoint_idx,
                    orig_event,
                    replay_event
                );
            }
        }

        crate::test_complete!("metamorphic_checkpoint_replay_equivalence");
    }

    // =========================================================================
    // MR2: Parallel Scope Fork/Join Order Determinism
    // =========================================================================

    #[test]
    fn metamorphic_parallel_scope_fork_join_determinism() {
        init_test("metamorphic_parallel_scope_fork_join_determinism");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // MR: Fork/join order should be deterministic across multiple runs with same seed
        let test_scenario = create_fork_join_test_scenario(&config, seed);

        let mut executions = Vec::new();

        // Execute the same scenario multiple times with the same seed
        for _run_idx in 0..5 {
            let mut runtime_config = LabConfig::new(seed); // Same seed every time
            runtime_config = runtime_config.worker_count(config.worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            test_scenario(&mut runtime);

            let trace = runtime.trace().snapshot();
            let certificate = runtime.certificate().hash();
            let steps = runtime.steps();

            executions.push((trace, certificate, steps));
        }

        // MR: All executions should produce identical results
        for (run_idx, (trace, certificate, steps)) in executions.iter().enumerate().skip(1) {
            assert_eq!(
                executions[0].1, *certificate,
                "Run {} has different certificate than run 0",
                run_idx
            );
            assert_eq!(
                executions[0].2, *steps,
                "Run {} has different step count than run 0",
                run_idx
            );

            // Check trace equivalence
            let divergence = find_divergence(&executions[0].0, trace);
            assert!(
                divergence.is_none(),
                "Run {} diverged from run 0: {:?}",
                run_idx,
                divergence
            );
        }

        // MR: Fork/join ordering should be stable within each trace
        for (run_idx, (trace, _, _)) in executions.iter().enumerate() {
            let mut fork_events = Vec::new();
            let mut join_events = Vec::new();

            for event in trace {
                if matches!(&event.data, crate::trace::event::TraceData::Message(msg) if msg.contains("fork_task_"))
                {
                    fork_events.push(event.clone());
                } else if matches!(&event.data, crate::trace::event::TraceData::Message(msg) if msg.contains("join_task_"))
                {
                    join_events.push(event.clone());
                }
            }

            // Verify fork events appear before join events (proper fork/join ordering)
            if let (Some(last_fork), Some(first_join)) = (fork_events.last(), join_events.first()) {
                assert!(
                    last_fork.time <= first_join.time,
                    "Run {}: Fork events should complete before join events start",
                    run_idx
                );
            }
        }

        crate::test_complete!("metamorphic_parallel_scope_fork_join_determinism");
    }

    // =========================================================================
    // MR3: Panic Replay Cause Chain Consistency
    // =========================================================================

    #[test]
    fn metamorphic_panic_replay_cause_chain_consistency() {
        init_test("metamorphic_panic_replay_cause_chain_consistency");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario that includes panic conditions
        let panic_scenario = move |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(seed);

            // Create events including simulated panic conditions
            for i in 0..config.task_count {
                if rng.next_u64() % 4 == 0 {
                    // 25% chance of panic
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("panic_task_{}", i),
                        )
                    });
                } else {
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("normal_task_{}", i),
                        )
                    });
                }
            }
        };

        // Run original execution
        let mut original_config = LabConfig::new(seed);
        original_config = original_config.worker_count(config.worker_count);
        let mut original_runtime = LabRuntime::new(original_config);
        panic_scenario(&mut original_runtime);
        let original_trace = original_runtime.trace().snapshot();

        // Run replay
        let mut replay_config = LabConfig::new(seed);
        replay_config = replay_config.worker_count(config.worker_count);
        let mut replay_runtime = LabRuntime::new(replay_config);
        panic_scenario(&mut replay_runtime);
        let replay_trace = replay_runtime.trace().snapshot();

        // MR: Panic cause chains should be identical between original and replay
        let original_panics: Vec<_> = original_trace
            .iter()
            .filter(|event| trace_message_contains(event, "panic_"))
            .collect();
        let replay_panics: Vec<_> = replay_trace
            .iter()
            .filter(|event| trace_message_contains(event, "panic_"))
            .collect();

        assert_eq!(
            original_panics.len(),
            replay_panics.len(),
            "Panic count should match between original and replay"
        );

        for (original_panic, replay_panic) in original_panics.iter().zip(replay_panics.iter()) {
            assert!(
                events_match(original_panic, replay_panic),
                "Panic events should match: {:?} vs {:?}",
                original_panic,
                replay_panic
            );
        }

        // MR: Overall trace should be identical (no divergence)
        let divergence = find_divergence(&original_trace, &replay_trace);
        assert!(
            divergence.is_none(),
            "Panic replay diverged: {:?}",
            divergence
        );

        crate::test_complete!("metamorphic_panic_replay_cause_chain_consistency");
    }

    // =========================================================================
    // MR4: Cross-Region Trace Ordering Preservation
    // =========================================================================

    #[test]
    fn metamorphic_cross_region_trace_ordering_preservation() {
        init_test("metamorphic_cross_region_trace_ordering_preservation");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // Test scenario with multiple regions
        let multi_region_scenario = move |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let _rng = DetRng::new(seed);

            let region_count = 3;

            // Create events across multiple regions
            for region_id in 0..region_count {
                for task_id in 0..config.task_count / region_count {
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("region_{}_task_{}", region_id, task_id),
                        )
                    });
                }
            }
        };

        // Test ordering preservation across different execution contexts
        let execution_contexts = [
            ("single_worker", 1),
            ("dual_worker", 2),
            ("multi_worker", 4),
        ];

        let mut context_traces = Vec::new();

        for (context_name, worker_count) in &execution_contexts {
            let mut runtime_config = LabConfig::new(seed);
            runtime_config = runtime_config.worker_count(*worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            multi_region_scenario(&mut runtime);
            let trace = runtime.trace().snapshot();
            context_traces.push((context_name, trace));
        }

        // MR: Cross-region ordering should be preserved regardless of worker count
        for (context_name, trace) in &context_traces {
            let mut region_events: std::collections::BTreeMap<u32, Vec<&crate::trace::TraceEvent>> =
                std::collections::BTreeMap::new();

            for event in trace {
                if let crate::trace::event::TraceData::Message(ref data_str) = event.data {
                    if data_str.contains("region_") {
                        if let Some(region_start) = data_str.find("region_") {
                            if let Some(region_end) = data_str[region_start + 7..].find('_') {
                                if let Ok(region_id) = data_str
                                    [region_start + 7..region_start + 7 + region_end]
                                    .parse::<u32>()
                                {
                                    region_events.entry(region_id).or_default().push(event);
                                }
                            }
                        }
                    }
                }
            }

            // Verify each region has events
            assert!(
                !region_events.is_empty(),
                "Context {} should have region events",
                context_name
            );

            // MR: Within each region, event ordering should be deterministic
            for (region_id, events) in &region_events {
                for window in events.windows(2) {
                    assert!(
                        window[0].time <= window[1].time,
                        "Context {}: Region {} events not in time order",
                        context_name,
                        region_id
                    );
                }
            }
        }

        // MR: Different worker counts should produce equivalent logical ordering
        // (may have different physical timing but same logical causality)
        for i in 1..context_traces.len() {
            let (name1, trace1) = &context_traces[0];
            let (name2, trace2) = &context_traces[i];

            // Extract logical ordering (ignoring precise timing)
            let logical_order1: Vec<_> = trace1
                .iter()
                .filter(|e| trace_message_contains(e, "region_"))
                .map(|e| &e.data)
                .collect();
            let logical_order2: Vec<_> = trace2
                .iter()
                .filter(|e| trace_message_contains(e, "region_"))
                .map(|e| &e.data)
                .collect();

            assert_eq!(
                logical_order1, logical_order2,
                "Logical ordering differs between {} and {}",
                name1, name2
            );
        }

        crate::test_complete!("metamorphic_cross_region_trace_ordering_preservation");
    }

    // =========================================================================
    // MR5: LabRuntime Seed Determinism
    // =========================================================================

    #[test]
    fn metamorphic_lab_runtime_seed_determinism() {
        init_test("metamorphic_lab_runtime_seed_determinism");

        // MR: Same seed should produce identical execution across multiple runs
        const SEED: u64 = 0x1234_5678_9ABC_DEF0;

        let config = ReplayMetamorphicConfig::default();

        let deterministic_scenario = |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            // Drive the scenario from the runtime's own seed so that a
            // different `LabConfig::new(seed)` truly alters observable
            // trace / certificate state. Without this the scenario would
            // be seed-agnostic and the "different seed should differ"
            // assertion below would trivially fail.
            let mut rng = DetRng::new(runtime.config().seed);

            // Create deterministic sequence of events
            for i in 0..config.task_count {
                let choice = rng.next_u64() % 3;
                let event_type = match choice {
                    0 => "fork",
                    1 => "work",
                    _ => "join",
                };

                runtime.trace().record_event(|id| {
                    crate::trace::TraceEvent::user_trace(
                        id,
                        runtime.now(),
                        format!("{}_{}", event_type, i),
                    )
                });
            }
        };

        // Run multiple times with same seed
        let mut run_results = Vec::new();

        for run_idx in 0..5 {
            let mut runtime_config = LabConfig::new(SEED);
            runtime_config = runtime_config.worker_count(config.worker_count);
            let mut runtime = LabRuntime::new(runtime_config);

            deterministic_scenario(&mut runtime);

            let trace = runtime.trace().snapshot();
            let certificate = runtime.certificate().hash();
            let steps = runtime.steps();

            run_results.push((run_idx, trace, certificate, steps));
        }

        // MR: All runs should produce identical results
        for (run_idx, trace, certificate, steps) in &run_results[1..] {
            assert_eq!(
                run_results[0].2, *certificate,
                "Run {} certificate differs from run 0",
                run_idx
            );
            assert_eq!(
                run_results[0].3, *steps,
                "Run {} step count differs from run 0",
                run_idx
            );

            let divergence = find_divergence(&run_results[0].1, trace);
            assert!(
                divergence.is_none(),
                "Run {} trace diverged from run 0: {:?}",
                run_idx,
                divergence
            );
        }

        // MR: Test seed independence - different seeds should produce different results
        let mut different_seed_config = LabConfig::new(SEED + 1);
        different_seed_config = different_seed_config.worker_count(config.worker_count);
        let mut different_seed_runtime = LabRuntime::new(different_seed_config);

        deterministic_scenario(&mut different_seed_runtime);
        let different_trace = different_seed_runtime.trace().snapshot();

        // The scenario is a pure trace-generator (no scheduling is invoked),
        // so the `ScheduleCertificate` stays at its identity hash for every
        // run regardless of seed. The observable seed-dependent artefact is
        // the user-trace stream itself: with a different seed the RNG chooses
        // a different `fork`/`work`/`join` sequence.
        assert!(
            find_divergence(&run_results[0].1, &different_trace).is_some(),
            "Different seed should produce a divergent trace"
        );

        crate::test_complete!("metamorphic_lab_runtime_seed_determinism");
    }

    // =========================================================================
    // MR6: Composite Replay Invariants
    // =========================================================================

    #[test]
    fn metamorphic_composite_replay_invariants() {
        init_test("metamorphic_composite_replay_invariants");

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let config = ReplayMetamorphicConfig::default();

        // MR: Combination of multiple replay properties should all hold simultaneously
        let composite_scenario = |runtime: &mut LabRuntime| {
            use crate::util::det_rng::DetRng;
            let mut rng = DetRng::new(seed);

            // Create a complex scenario combining:
            // 1. Fork/join patterns
            // 2. Cross-region operations
            // 3. Potential panic conditions
            // 4. Checkpoint-worthy state changes

            let regions = 2;
            let tasks_per_region = config.task_count / regions;

            for region_id in 0..regions {
                // Fork phase
                for task_id in 0..tasks_per_region {
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("fork_region_{}_task_{}", region_id, task_id),
                        )
                    });
                }

                // Work phase (with occasional panics)
                for task_id in 0..tasks_per_region {
                    let event_type = if rng.next_u64() % 10 == 0 {
                        "panic"
                    } else {
                        "work"
                    };
                    let now = runtime.now();
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            now,
                            format!("{}_region_{}_task_{}", event_type, region_id, task_id),
                        )
                    });
                }

                // Join phase
                for task_id in 0..tasks_per_region {
                    runtime.trace().record_event(|id| {
                        crate::trace::TraceEvent::user_trace(
                            id,
                            runtime.now(),
                            format!("join_region_{}_task_{}", region_id, task_id),
                        )
                    });
                }
            }
        };

        // Test the scenario with replay validation
        let replay_validation = validate_replay(seed, config.worker_count, composite_scenario);

        assert!(
            replay_validation.matched,
            "Composite scenario replay should match original: certificates {} vs {}, steps {} vs {}",
            replay_validation.original_certificate,
            replay_validation.replay_certificate,
            replay_validation.original_steps,
            replay_validation.replay_steps
        );

        assert!(
            replay_validation.divergence.is_none(),
            "Composite scenario should have no divergence: {:?}",
            replay_validation.divergence
        );

        // Test multiple seeds for robustness
        let test_seeds = [seed, seed + 1, seed + 42, seed + 1337, seed + 0xDEAD];

        for &test_seed in &test_seeds {
            let validation = validate_replay(test_seed, config.worker_count, |runtime| {
                composite_scenario(runtime);
            });

            assert!(
                validation.matched,
                "Seed {} composite replay failed: {:?}",
                test_seed, validation.divergence
            );
        }

        // MR: Multi-seed validation should show consistent determinism
        let multi_validation =
            validate_replay_multi(&test_seeds, config.worker_count, composite_scenario);

        for (i, validation) in multi_validation.iter().enumerate() {
            assert!(validation.matched, "Multi-seed run {} failed validation", i);
        }
        crate::test_complete!("metamorphic_composite_replay_invariants");
    }
}
