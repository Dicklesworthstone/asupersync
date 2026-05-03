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
