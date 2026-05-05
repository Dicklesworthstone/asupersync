//! Versioned scheduler evidence artifacts for swarm-host tuning.
//!
//! This module defines the compact, deterministic artifact contract consumed by
//! offline tuning workflows. It deliberately focuses on stable observables that
//! are already meaningful for large-host scheduler diagnosis: wake-to-run
//! latency, queue residency, backlog pressure, cancellation debt, and explicit
//! topology/knob metadata.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable version identifier for scheduler swarm-evidence artifacts.
pub const SCHEDULER_EVIDENCE_SCHEMA_VERSION: &str = "asupersync.scheduler-evidence.v1";

/// Compact evidence artifact describing one scheduler tuning run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvidenceArtifact {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Stable operator-provided run label.
    pub run_label: String,
    /// High-level workload shape that produced the evidence.
    pub workload_class: SchedulerWorkloadClass,
    /// Explicit host and cohort shape for this run.
    pub topology: SchedulerTopologyDescriptor,
    /// Scheduler knobs in effect when the evidence was captured.
    pub current_knobs: SchedulerKnobProfile,
    /// Tail and backlog metrics used by the offline recommendation pass.
    pub metrics: SchedulerEvidenceMetrics,
    /// Free-form deterministic notes.
    pub notes: Vec<String>,
}

impl SchedulerEvidenceArtifact {
    /// Validate the artifact before it is trusted by offline tooling.
    pub fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.schema_version != SCHEDULER_EVIDENCE_SCHEMA_VERSION {
            return Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
                expected: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
                found: self.schema_version.clone(),
            });
        }
        if self.run_label.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyRunLabel);
        }
        if self.topology.worker_threads == 0 {
            return Err(SchedulerEvidenceError::ZeroWorkerThreads);
        }
        if self.topology.cohort_count == 0 {
            return Err(SchedulerEvidenceError::ZeroCohortCount);
        }
        if self.topology.memory_budget_gib == 0 {
            return Err(SchedulerEvidenceError::ZeroMemoryBudget);
        }
        if self.current_knobs.worker_threads == 0 {
            return Err(SchedulerEvidenceError::ZeroCurrentWorkers);
        }
        if self.current_knobs.steal_batch_size == 0 {
            return Err(SchedulerEvidenceError::ZeroStealBatchSize);
        }
        if self.current_knobs.cancel_streak_limit == 0 {
            return Err(SchedulerEvidenceError::ZeroCancelStreakLimit);
        }
        self.metrics.validate()?;
        Ok(())
    }

    /// Produce a deterministic tuning report from the captured evidence.
    pub fn tune_report(&self) -> Result<SchedulerTuneReport, SchedulerEvidenceError> {
        self.validate()?;

        let mut recommended_knobs = self.current_knobs.clone();
        let mut reason_codes = Vec::new();
        let mut explanation = Vec::new();
        let mut global_queue_limit_hint = None;

        let backlog_scale_threshold = self.topology.worker_threads.saturating_mul(4);
        if self.metrics.wake_to_run_p99_ns >= 150_000
            && self.metrics.ready_backlog_p99 >= backlog_scale_threshold
        {
            reason_codes.push(SchedulerRecommendationReason::WorkersSaturated);
            recommended_knobs.worker_threads = recommended_knobs
                .worker_threads
                .saturating_add(self.topology.cohort_count.max(1));
            explanation.push(format!(
                "wake_to_run p99={}ns with ready_backlog_p99={} exceeded the worker saturation envelope",
                self.metrics.wake_to_run_p99_ns, self.metrics.ready_backlog_p99
            ));
        }

        if self.metrics.queue_residency_p99_ns >= self.metrics.wake_to_run_p99_ns.saturating_mul(2)
        {
            reason_codes.push(SchedulerRecommendationReason::QueueResidencyDominant);
            recommended_knobs.steal_batch_size =
                recommended_knobs.steal_batch_size.saturating_mul(2).min(64);
            global_queue_limit_hint = Some(
                self.metrics
                    .ready_backlog_p99
                    .saturating_mul(2)
                    .max(backlog_scale_threshold),
            );
            explanation.push(format!(
                "queue_residency p99={}ns dominated wake_to_run p99={}ns, suggesting deeper burst draining",
                self.metrics.queue_residency_p99_ns, self.metrics.wake_to_run_p99_ns
            ));
        }

        if self.metrics.cancel_debt_p99
            >= self
                .metrics
                .cancel_debt_p95
                .max(self.current_knobs.cancel_streak_limit)
        {
            reason_codes.push(SchedulerRecommendationReason::CancelDebtDominant);
            recommended_knobs.cancel_streak_limit = recommended_knobs
                .cancel_streak_limit
                .saturating_mul(2)
                .min(128);
            explanation.push(format!(
                "cancel_debt p99={} remained above the current drain envelope",
                self.metrics.cancel_debt_p99
            ));
        }

        if let Some(remote_steal_ratio_pct) = self.metrics.remote_steal_ratio_pct
            && self.topology.cohort_count > 1
            && remote_steal_ratio_pct >= 35
        {
            reason_codes.push(SchedulerRecommendationReason::RemoteStealPressure);
            explanation.push(format!(
                "remote steal ratio {}% indicates locality-aware follow-up work should stay enabled",
                remote_steal_ratio_pct
            ));
        }

        if reason_codes.is_empty() {
            reason_codes.push(SchedulerRecommendationReason::BalancedBaseline);
            explanation.push(
                "tail and backlog metrics stayed inside the conservative baseline envelope"
                    .to_string(),
            );
        }

        let profile_name = if reason_codes
            .contains(&SchedulerRecommendationReason::WorkersSaturated)
        {
            "scale_workers"
        } else if reason_codes.contains(&SchedulerRecommendationReason::QueueResidencyDominant) {
            "drain_ready_bursts"
        } else if reason_codes.contains(&SchedulerRecommendationReason::CancelDebtDominant) {
            "drain_cancel_pressure"
        } else {
            "conservative_baseline"
        };

        let confidence_percent = 55u8
            .saturating_add((reason_codes.len() as u8).saturating_mul(10))
            .min(90);

        Ok(SchedulerTuneReport {
            schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            source_run_label: self.run_label.clone(),
            workload_class: self.workload_class,
            profile_name: profile_name.to_string(),
            recommended_knobs,
            global_queue_limit_hint,
            fallback_profile: self.current_knobs.clone(),
            confidence_percent,
            reason_codes,
            explanation,
        })
    }
}

/// Explicit workload classes for swarm-host scheduler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerWorkloadClass {
    /// Interactive agent-swarm traffic with latency-sensitive bursts.
    InteractiveSwarm,
    /// Mixed ready/cancel bursts typical of general-purpose swarm hosts.
    MixedBurst,
    /// Cancellation-dominated storm or cleanup scenario.
    CancellationStorm,
    /// Long-running throughput-biased drain workload.
    ThroughputDrain,
}

/// Stable topology description for a scheduler evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerTopologyDescriptor {
    /// Number of scheduler workers participating in the run.
    pub worker_threads: usize,
    /// Number of explicit worker cohorts or locality groups.
    pub cohort_count: usize,
    /// Host memory budget captured with the evidence run.
    pub memory_budget_gib: usize,
}

/// Scheduler knobs subject to offline recommendations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerKnobProfile {
    /// Worker thread count in the profiled runtime.
    pub worker_threads: usize,
    /// Steal-batch size configured for burst draining.
    pub steal_batch_size: usize,
    /// Maximum consecutive cancel-lane dispatches before yielding.
    pub cancel_streak_limit: usize,
    /// Global queue limit in effect during the run (`0` = unbounded).
    pub global_queue_limit: usize,
    /// Whether worker parking was enabled.
    pub parking_enabled: bool,
}

/// Tail and backlog metrics captured for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvidenceMetrics {
    /// Wake-to-run latency median in nanoseconds.
    pub wake_to_run_p50_ns: u64,
    /// Wake-to-run latency p95 in nanoseconds.
    pub wake_to_run_p95_ns: u64,
    /// Wake-to-run latency p99 in nanoseconds.
    pub wake_to_run_p99_ns: u64,
    /// Queue-residency latency median in nanoseconds.
    pub queue_residency_p50_ns: u64,
    /// Queue-residency latency p95 in nanoseconds.
    pub queue_residency_p95_ns: u64,
    /// Queue-residency latency p99 in nanoseconds.
    pub queue_residency_p99_ns: u64,
    /// Ready-backlog p95 count.
    pub ready_backlog_p95: usize,
    /// Ready-backlog p99 count.
    pub ready_backlog_p99: usize,
    /// Cancel-debt p95 count.
    pub cancel_debt_p95: usize,
    /// Cancel-debt p99 count.
    pub cancel_debt_p99: usize,
    /// Percentage of steals that crossed cohort boundaries, if known.
    pub remote_steal_ratio_pct: Option<u8>,
    /// Cross-cohort wake-to-run p99 in nanoseconds, if measured.
    pub cross_cohort_wake_p99_ns: Option<u64>,
}

impl SchedulerEvidenceMetrics {
    fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        validate_percentiles(
            self.wake_to_run_p50_ns,
            self.wake_to_run_p95_ns,
            self.wake_to_run_p99_ns,
            "wake_to_run",
        )?;
        validate_percentiles(
            self.queue_residency_p50_ns,
            self.queue_residency_p95_ns,
            self.queue_residency_p99_ns,
            "queue_residency",
        )?;
        validate_percentiles(
            self.ready_backlog_p95,
            self.ready_backlog_p99,
            self.ready_backlog_p99,
            "ready_backlog",
        )?;
        validate_percentiles(
            self.cancel_debt_p95,
            self.cancel_debt_p99,
            self.cancel_debt_p99,
            "cancel_debt",
        )?;
        if let Some(remote_steal_ratio_pct) = self.remote_steal_ratio_pct
            && remote_steal_ratio_pct > 100
        {
            return Err(SchedulerEvidenceError::RemoteStealRatioOutOfRange(
                remote_steal_ratio_pct,
            ));
        }
        Ok(())
    }
}

/// Deterministic offline tuning report emitted from one evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerTuneReport {
    /// Output schema version for the tuning report.
    pub schema_version: String,
    /// Source run label copied from the input artifact.
    pub source_run_label: String,
    /// Workload class the recommendation is based on.
    pub workload_class: SchedulerWorkloadClass,
    /// Human-readable profile label for the recommendation.
    pub profile_name: String,
    /// Recommended worker/batch/cancel knobs.
    pub recommended_knobs: SchedulerKnobProfile,
    /// Optional queue-capacity hint derived from backlog pressure.
    pub global_queue_limit_hint: Option<usize>,
    /// Exact conservative fallback profile (the input knobs).
    pub fallback_profile: SchedulerKnobProfile,
    /// Coarse confidence score for operator triage.
    pub confidence_percent: u8,
    /// Stable reason codes explaining why the recommendation fired.
    pub reason_codes: Vec<SchedulerRecommendationReason>,
    /// Human-readable explanation lines for operators and artifacts.
    pub explanation: Vec<String>,
}

/// Stable reason codes for why a recommendation was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerRecommendationReason {
    /// Wake-to-run latency and ready backlog imply more workers are needed.
    WorkersSaturated,
    /// Queue residency dominates wake latency, suggesting deeper burst draining.
    QueueResidencyDominant,
    /// Cancel backlog remains high enough to justify stronger cancel draining.
    CancelDebtDominant,
    /// Cross-cohort stealing pressure suggests locality work should stay enabled.
    RemoteStealPressure,
    /// Current knobs remain appropriate for the observed envelope.
    BalancedBaseline,
}

/// Stable schema for synthesized scheduler inputs from coordination bundles.
pub const SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION: &str =
    "asupersync.scheduler-coordination-evidence-inputs.v1";

/// Scheduler-facing evidence inputs synthesized from coordination workload packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerCoordinationEvidenceInputs {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Expansion-pack identifier that produced the inputs.
    pub source_pack_id: String,
    /// Hash of the redacted source bundle used for deterministic replay.
    pub source_bundle_hash: String,
    /// Source collector run identifier.
    pub source_run_id: String,
    /// One evidence input per covered coordination-pressure family.
    pub evidence_inputs: Vec<SchedulerCoordinationEvidenceInput>,
}

impl SchedulerCoordinationEvidenceInputs {
    /// Validate that synthesized coordination inputs are complete enough for
    /// downstream tuning without promoting provenance-only context to semantics.
    pub fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.schema_version != SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION {
            return Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
                expected: SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION.to_string(),
                found: self.schema_version.clone(),
            });
        }
        validate_hash(&self.source_bundle_hash)?;
        if self.source_pack_id.trim().is_empty() || self.source_run_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyEvidenceInputId);
        }
        if self.evidence_inputs.is_empty() {
            return Err(SchedulerEvidenceError::EmptyEvidenceInputSet);
        }
        for input in &self.evidence_inputs {
            input.validate()?;
        }
        Ok(())
    }
}

/// One scheduler evidence input for a real coordination-pressure family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerCoordinationEvidenceInput {
    /// Stable input id used by planner and profile consumers.
    pub evidence_input_id: String,
    /// Runtime workload corpus id for replay.
    pub workload_id: String,
    /// Scheduler workload class used for recommendation grouping.
    pub workload_class: SchedulerWorkloadClass,
    /// Coordination family represented by this input.
    pub scenario_family: CoordinationPressureFamily,
    /// Dimensions that carry actual runtime pressure.
    pub semantic_pressure: Vec<String>,
    /// Redacted context retained only for replay/audit provenance.
    pub provenance_only_context: Vec<String>,
    /// Accepted source events folded into this input.
    pub source_event_count: usize,
    /// Stable event hashes backing the input.
    pub source_hashes: Vec<String>,
    /// Hash of the source bundle backing the input.
    pub source_bundle_hash: String,
}

impl SchedulerCoordinationEvidenceInput {
    /// Validate the semantic/provenance split and deterministic source anchors.
    pub fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.evidence_input_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyEvidenceInputId);
        }
        if self.workload_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyCoordinationWorkloadId);
        }
        if self.semantic_pressure.is_empty()
            || self
                .semantic_pressure
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(SchedulerEvidenceError::EmptySemanticPressure);
        }
        if self.provenance_only_context.is_empty()
            || self
                .provenance_only_context
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(SchedulerEvidenceError::EmptyProvenanceContext);
        }
        if self.source_event_count == 0 {
            return Err(SchedulerEvidenceError::ZeroSourceEventCount);
        }
        validate_hash(&self.source_bundle_hash)?;
        if self.source_hashes.is_empty() {
            return Err(SchedulerEvidenceError::EmptySourceHash);
        }
        for hash in &self.source_hashes {
            validate_hash(hash)?;
        }
        Ok(())
    }
}

/// Coordination pressure families that can be promoted into scheduler inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPressureFamily {
    /// Advisory tracker/file-lock contention.
    TrackerLockContention,
    /// Concurrent remote proof/build activity.
    ConcurrentRchProofs,
    /// Dirty-frontier refusal and retry pressure.
    FailClosedDirtyFrontier,
    /// Tail pressure from collecting and indexing proof artifacts.
    ArtifactRetrievalTail,
    /// Fan-out from proof runner and robot-plan work.
    ProofRunnerFanout,
    /// Stale in-progress issue reclaim loops.
    StaleInProgressReclaim,
    /// Mail acknowledgement and coordination latency bursts.
    CoordinationLatencyBurst,
}

/// Validation and recommendation failures for scheduler evidence artifacts.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchedulerEvidenceError {
    /// The artifact schema version does not match the supported contract.
    #[error("unsupported schema version: expected {expected}, found {found}")]
    UnsupportedSchemaVersion {
        /// Supported schema version for the current parser.
        expected: String,
        /// Schema version found in the provided artifact.
        found: String,
    },
    /// The run label was empty or whitespace-only.
    #[error("run label must not be empty")]
    EmptyRunLabel,
    /// The topology declared no worker threads.
    #[error("topology must declare at least one worker thread")]
    ZeroWorkerThreads,
    /// The topology declared no cohorts.
    #[error("topology must declare at least one cohort")]
    ZeroCohortCount,
    /// The topology declared a zero memory budget.
    #[error("topology must declare a non-zero memory budget")]
    ZeroMemoryBudget,
    /// The profiled knob set declared zero workers.
    #[error("current knob profile must declare at least one worker")]
    ZeroCurrentWorkers,
    /// The profiled knob set declared a zero steal batch size.
    #[error("current knob profile must declare a non-zero steal batch size")]
    ZeroStealBatchSize,
    /// The profiled knob set declared a zero cancel streak limit.
    #[error("current knob profile must declare a non-zero cancel streak limit")]
    ZeroCancelStreakLimit,
    /// One percentile trio regressed from sorted order.
    #[error("{field} percentiles must be monotonic (p50 <= p95 <= p99)")]
    NonMonotonicPercentiles {
        /// Percentile family that violated monotonic ordering.
        field: &'static str,
    },
    /// The remote-steal ratio fell outside the valid percentage range.
    #[error("remote steal ratio must be between 0 and 100 inclusive, found {0}")]
    RemoteStealRatioOutOfRange(u8),
    /// A coordination evidence document had no inputs.
    #[error("coordination evidence input set must not be empty")]
    EmptyEvidenceInputSet,
    /// A coordination evidence id was empty.
    #[error("coordination evidence input id must not be empty")]
    EmptyEvidenceInputId,
    /// A coordination workload id was empty.
    #[error("coordination workload id must not be empty")]
    EmptyCoordinationWorkloadId,
    /// Semantic pressure dimensions were absent.
    #[error("coordination evidence must declare semantic pressure dimensions")]
    EmptySemanticPressure,
    /// Provenance-only context was absent.
    #[error("coordination evidence must declare provenance-only context")]
    EmptyProvenanceContext,
    /// No accepted source event backed the input.
    #[error("coordination evidence must include at least one source event")]
    ZeroSourceEventCount,
    /// A source hash field was empty.
    #[error("coordination evidence source hashes must not be empty")]
    EmptySourceHash,
    /// A source hash was not a stable sha256 reference.
    #[error("coordination evidence source hash must start with sha256:, found {found}")]
    InvalidSourceHash {
        /// Hash value that failed validation.
        found: String,
    },
}

fn validate_percentiles<T: Ord>(
    p50: T,
    p95: T,
    p99: T,
    field: &'static str,
) -> Result<(), SchedulerEvidenceError> {
    if p50 > p95 || p95 > p99 {
        return Err(SchedulerEvidenceError::NonMonotonicPercentiles { field });
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), SchedulerEvidenceError> {
    if hash.trim().is_empty() {
        return Err(SchedulerEvidenceError::EmptySourceHash);
    }
    if !hash.starts_with("sha256:") {
        return Err(SchedulerEvidenceError::InvalidSourceHash {
            found: hash.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_artifact() -> SchedulerEvidenceArtifact {
        SchedulerEvidenceArtifact {
            schema_version: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
            run_label: "unit-baseline-64c".to_string(),
            workload_class: SchedulerWorkloadClass::InteractiveSwarm,
            topology: SchedulerTopologyDescriptor {
                worker_threads: 64,
                cohort_count: 2,
                memory_budget_gib: 256,
            },
            current_knobs: SchedulerKnobProfile {
                worker_threads: 64,
                steal_batch_size: 8,
                cancel_streak_limit: 16,
                global_queue_limit: 0,
                parking_enabled: true,
            },
            metrics: SchedulerEvidenceMetrics {
                wake_to_run_p50_ns: 5_000,
                wake_to_run_p95_ns: 20_000,
                wake_to_run_p99_ns: 60_000,
                queue_residency_p50_ns: 8_000,
                queue_residency_p95_ns: 30_000,
                queue_residency_p99_ns: 90_000,
                ready_backlog_p95: 32,
                ready_backlog_p99: 96,
                cancel_debt_p95: 4,
                cancel_debt_p99: 8,
                remote_steal_ratio_pct: Some(12),
                cross_cohort_wake_p99_ns: Some(70_000),
            },
            notes: vec!["unit".to_string()],
        }
    }

    fn coordination_input(
        family: CoordinationPressureFamily,
        workload_id: &str,
    ) -> SchedulerCoordinationEvidenceInput {
        SchedulerCoordinationEvidenceInput {
            evidence_input_id: format!("coordination-evidence-{workload_id}"),
            workload_id: workload_id.to_string(),
            workload_class: SchedulerWorkloadClass::InteractiveSwarm,
            scenario_family: family,
            semantic_pressure: vec![
                "ready-backlog".to_string(),
                "queue-residency-tail".to_string(),
            ],
            provenance_only_context: vec![
                "pseudonymized-agent".to_string(),
                "hashed-path".to_string(),
            ],
            source_event_count: 2,
            source_hashes: vec!["sha256:event-a".to_string(), "sha256:event-b".to_string()],
            source_bundle_hash: "sha256:coordination-bundle".to_string(),
        }
    }

    #[test]
    fn validate_rejects_schema_and_required_zero_fields() {
        let mut artifact = baseline_artifact();
        artifact.schema_version = "asupersync.scheduler-evidence.v0".to_string();
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
                expected: SCHEDULER_EVIDENCE_SCHEMA_VERSION.to_string(),
                found: "asupersync.scheduler-evidence.v0".to_string(),
            })
        );

        let mut artifact = baseline_artifact();
        artifact.run_label = "   ".to_string();
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::EmptyRunLabel)
        );

        let mut artifact = baseline_artifact();
        artifact.topology.worker_threads = 0;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::ZeroWorkerThreads)
        );

        let mut artifact = baseline_artifact();
        artifact.current_knobs.steal_batch_size = 0;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::ZeroStealBatchSize)
        );
    }

    #[test]
    fn validate_rejects_metric_boundary_violations() {
        let mut artifact = baseline_artifact();
        artifact.metrics.wake_to_run_p95_ns = artifact.metrics.wake_to_run_p50_ns - 1;
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::NonMonotonicPercentiles {
                field: "wake_to_run",
            })
        );

        let mut artifact = baseline_artifact();
        artifact.metrics.remote_steal_ratio_pct = Some(101);
        assert_eq!(
            artifact.validate(),
            Err(SchedulerEvidenceError::RemoteStealRatioOutOfRange(101))
        );
    }

    #[test]
    fn tune_report_keeps_conservative_fallback_for_balanced_baseline() {
        let artifact = baseline_artifact();
        let report = artifact
            .tune_report()
            .expect("balanced artifact should tune");

        assert_eq!(report.profile_name, "conservative_baseline");
        assert_eq!(report.recommended_knobs, artifact.current_knobs);
        assert_eq!(report.fallback_profile, artifact.current_knobs);
        assert_eq!(report.global_queue_limit_hint, None);
        assert_eq!(
            report.reason_codes,
            vec![SchedulerRecommendationReason::BalancedBaseline]
        );
        assert_eq!(report.confidence_percent, 65);
        assert!(
            report
                .explanation
                .iter()
                .any(|line| line.contains("conservative baseline envelope"))
        );
    }

    #[test]
    fn coordination_evidence_inputs_validate_all_pressure_families() {
        let evidence = SchedulerCoordinationEvidenceInputs {
            schema_version: SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION.to_string(),
            source_pack_id: "agent-swarm-coordination-pressure".to_string(),
            source_bundle_hash: "sha256:coordination-runtime-fixture".to_string(),
            source_run_id: "coordination-runtime-fixture-accepted-all-families".to_string(),
            evidence_inputs: vec![
                coordination_input(
                    CoordinationPressureFamily::TrackerLockContention,
                    "ASWARM-WL-LOCK-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ConcurrentRchProofs,
                    "ASWARM-WL-RCH-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::FailClosedDirtyFrontier,
                    "ASWARM-WL-DIRTY-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ArtifactRetrievalTail,
                    "ASWARM-WL-ARTIFACT-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::ProofRunnerFanout,
                    "ASWARM-WL-FANOUT-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::StaleInProgressReclaim,
                    "ASWARM-WL-STALE-001",
                ),
                coordination_input(
                    CoordinationPressureFamily::CoordinationLatencyBurst,
                    "ASWARM-WL-LATENCY-001",
                ),
            ],
        };

        evidence
            .validate()
            .expect("coordination evidence validates");
    }

    #[test]
    fn coordination_evidence_rejects_missing_semantics_and_unstable_hashes() {
        let mut evidence = SchedulerCoordinationEvidenceInputs {
            schema_version: SCHEDULER_COORDINATION_EVIDENCE_SCHEMA_VERSION.to_string(),
            source_pack_id: "agent-swarm-coordination-pressure".to_string(),
            source_bundle_hash: "sha256:coordination-runtime-fixture".to_string(),
            source_run_id: "coordination-runtime-fixture-accepted-all-families".to_string(),
            evidence_inputs: vec![coordination_input(
                CoordinationPressureFamily::TrackerLockContention,
                "ASWARM-WL-LOCK-001",
            )],
        };

        evidence.evidence_inputs[0].semantic_pressure.clear();
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::EmptySemanticPressure)
        );

        evidence.evidence_inputs[0].semantic_pressure = vec!["ready-backlog".to_string()];
        evidence.evidence_inputs[0].source_hashes = vec!["not-a-sha".to_string()];
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::InvalidSourceHash {
                found: "not-a-sha".to_string(),
            })
        );

        evidence.evidence_inputs.clear();
        assert_eq!(
            evidence.validate(),
            Err(SchedulerEvidenceError::EmptyEvidenceInputSet)
        );
    }
}
