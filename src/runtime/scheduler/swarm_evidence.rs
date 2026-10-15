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
            .saturating_add(
                (u8::try_from(reason_codes.len()).unwrap_or(u8::MAX)).saturating_mul(10),
            )
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

/// Stable schema for explicit host/resource snapshots used by swarm-scale policy.
pub const SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION: &str = "asupersync.swarm-capacity-snapshot.v1";

/// Stable schema for admission reports derived from swarm capacity snapshots.
pub const SWARM_ADMISSION_POLICY_REPORT_SCHEMA_VERSION: &str =
    "asupersync.swarm-admission-policy-report.v1";

/// Stable schema for memory budget plans derived from swarm capacity snapshots.
pub const SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION: &str = "asupersync.swarm-memory-budget-plan.v1";

/// Stable schema for memory residency and brownout policy plans.
pub const SWARM_MEMORY_RESIDENCY_POLICY_SCHEMA_VERSION: &str =
    "asupersync.swarm-memory-residency-policy.v1";

/// Deterministic, capability-supplied host capacity snapshot.
///
/// This type is intentionally inert: it records capacity and coordination
/// signals supplied by an adapter or fixture, but it never reads ambient OS
/// state and never authorizes cleanup by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmCapacitySnapshot {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Stable snapshot/run identifier.
    pub snapshot_id: String,
    /// CPU topology hints supplied by the caller.
    pub cpu: SwarmCpuTopologyHints,
    /// Memory availability and pressure tier.
    pub memory: SwarmMemoryCapacity,
    /// Disk availability and pressure tier.
    pub disk: SwarmDiskCapacity,
    /// Remote build/admission state for rch-backed proof work.
    pub rch: SwarmRchCapacity,
    /// Agent Mail and Beads coordination backlog signals.
    pub coordination: SwarmCoordinationBacklogSignals,
}

impl SwarmCapacitySnapshot {
    /// Validate that the snapshot is complete enough to feed deterministic
    /// admission or replay tests without implying ambient authority.
    pub fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.schema_version != SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION {
            return Err(SchedulerEvidenceError::UnsupportedSchemaVersion {
                expected: SWARM_CAPACITY_SNAPSHOT_SCHEMA_VERSION.to_string(),
                found: self.schema_version.clone(),
            });
        }
        if self.snapshot_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyCapacitySnapshotId);
        }
        self.cpu.validate()?;
        self.memory.validate()?;
        self.disk.validate()?;
        Ok(())
    }

    /// Classify work lanes from this explicit snapshot.
    ///
    /// The policy is work-conserving but fail-closed for local artifact and
    /// cleanup surfaces: disk pressure never blocks source-only planning, but
    /// it does defer artifact-heavy local work and requires explicit cleanup
    /// authorization.
    pub fn admission_report(&self) -> Result<SwarmAdmissionReport, SchedulerEvidenceError> {
        self.validate()?;

        let lanes = vec![
            self.classify_source_only_lane(),
            self.classify_tracker_planning_lane(),
            self.classify_remote_proof_lane(),
            self.classify_local_artifact_lane(),
            self.classify_cleanup_authorization_lane(),
        ];
        let recommended_lane = self.recommend_admission_lane(&lanes);

        Ok(SwarmAdmissionReport {
            schema_version: SWARM_ADMISSION_POLICY_REPORT_SCHEMA_VERSION.to_string(),
            source_snapshot_id: self.snapshot_id.clone(),
            recommended_lane,
            lanes,
        })
    }

    /// Derive explicit per-lane memory budgets from this snapshot.
    ///
    /// The planner is deterministic and capability-fed: it only consumes this
    /// snapshot, preserves an emergency reserve first, and reduces proof/cache
    /// growth before interactive runtime state when pressure rises.
    pub fn memory_budget_plan(&self) -> Result<SwarmMemoryBudgetPlan, SchedulerEvidenceError> {
        self.validate()?;

        let host_tier = SwarmMemoryHostTier::classify(self.memory.total_bytes);
        let available_bytes = self.memory.available_bytes.unwrap_or(0);
        let total_bytes = self.memory.total_bytes.unwrap_or(available_bytes);
        let emergency_reserve_bytes = host_tier.emergency_reserve_bytes(
            total_bytes,
            available_bytes,
            self.memory.pressure_tier,
        );
        let allocatable_bytes = available_bytes.saturating_sub(emergency_reserve_bytes);
        let (interactive_weight, trace_weight, proof_weight, cache_weight) =
            host_tier.budget_weights(self.memory.pressure_tier);
        let total_weight = interactive_weight + trace_weight + proof_weight + cache_weight;

        let lane_budget = |weight| {
            if total_weight == 0 {
                0
            } else {
                allocatable_bytes.saturating_mul(weight) / total_weight
            }
        };

        let interactive_runtime_bytes = lane_budget(interactive_weight);
        let trace_replay_bytes = lane_budget(trace_weight);
        let proof_artifact_staging_bytes = lane_budget(proof_weight);
        let compiler_cache_bytes = lane_budget(cache_weight);
        let total_planned_bytes = interactive_runtime_bytes
            .saturating_add(trace_replay_bytes)
            .saturating_add(proof_artifact_staging_bytes)
            .saturating_add(compiler_cache_bytes);

        Ok(SwarmMemoryBudgetPlan {
            schema_version: SWARM_MEMORY_BUDGET_PLAN_SCHEMA_VERSION.to_string(),
            source_snapshot_id: self.snapshot_id.clone(),
            host_tier,
            pressure_tier: self.memory.pressure_tier,
            available_bytes,
            total_bytes,
            emergency_reserve_bytes,
            interactive_runtime_bytes,
            trace_replay_bytes,
            proof_artifact_staging_bytes,
            compiler_cache_bytes,
            total_planned_bytes,
        })
    }

    /// Plan region/workload memory residency without reading ambient host state.
    ///
    /// The decision uses the explicit capacity snapshot plus a caller-supplied
    /// request. It never authorizes cleanup or disables critical runtime
    /// surfaces; when inputs are stale or contradictory it emits a no-win
    /// receipt instead of overclaiming available memory.
    pub fn memory_residency_policy(
        &self,
        request: &SwarmMemoryResidencyRequest,
    ) -> Result<SwarmMemoryResidencyPlan, SchedulerEvidenceError> {
        self.validate()?;
        request.validate()?;

        let budget = self.memory_budget_plan()?;
        let lane_budget_bytes = request.workload_class.lane_budget_bytes(&budget);
        let before = SwarmMemoryResidencyEnvelope {
            available_bytes: budget.available_bytes,
            emergency_reserve_bytes: budget.emergency_reserve_bytes,
            lane_budget_bytes,
            pressure_tier: budget.pressure_tier,
            host_tier: budget.host_tier,
        };
        let metrics_stale = request.metrics_age_secs > request.max_metrics_age_secs;
        let contradictory_policy = request.minimum_hot_bytes > request.requested_bytes;

        let (decision, fallback_reason) = if contradictory_policy {
            (
                SwarmMemoryResidencyDecision::RefuseNoWin,
                Some(SwarmMemoryResidencyFallbackReason::ContradictoryPolicy),
            )
        } else if metrics_stale {
            (
                SwarmMemoryResidencyDecision::RefuseNoWin,
                Some(SwarmMemoryResidencyFallbackReason::StaleMetrics),
            )
        } else if lane_budget_bytes == 0 && request.requested_bytes > 0 {
            (
                SwarmMemoryResidencyDecision::RefuseNoWin,
                Some(SwarmMemoryResidencyFallbackReason::EmptyBudget),
            )
        } else if request.requested_bytes <= lane_budget_bytes {
            (SwarmMemoryResidencyDecision::AdmitHot, None)
        } else if request.spill_allowed && request.minimum_hot_bytes <= lane_budget_bytes {
            (SwarmMemoryResidencyDecision::SpillCold, None)
        } else if request.brownout_allowed && request.workload_class.brownout_eligible() {
            (SwarmMemoryResidencyDecision::BrownoutOptional, None)
        } else {
            (
                SwarmMemoryResidencyDecision::RefuseNoWin,
                Some(SwarmMemoryResidencyFallbackReason::NoSafeResidencyTier),
            )
        };

        let minimum_hot_bytes = request.minimum_hot_bytes.min(request.requested_bytes);
        let (
            hot_resident_bytes,
            warm_resident_bytes,
            spilled_bytes,
            browned_out_bytes,
            refused_bytes,
        ) = memory_residency_counts(
            request.requested_bytes,
            minimum_hot_bytes,
            lane_budget_bytes,
            decision,
        );
        let after = SwarmMemoryResidencyEnvelope {
            available_bytes: before
                .available_bytes
                .saturating_sub(hot_resident_bytes.saturating_add(warm_resident_bytes)),
            emergency_reserve_bytes: before.emergency_reserve_bytes,
            lane_budget_bytes: before.lane_budget_bytes,
            pressure_tier: before.pressure_tier,
            host_tier: before.host_tier,
        };
        let residency_tier = residency_tier_for_decision(decision);
        let brownout_class = brownout_class_for_decision(decision, budget.pressure_tier);
        let no_win_decision = decision == SwarmMemoryResidencyDecision::RefuseNoWin;
        let explanation = memory_residency_explanation(
            request,
            decision,
            fallback_reason,
            lane_budget_bytes,
            hot_resident_bytes,
            warm_resident_bytes,
            spilled_bytes,
            browned_out_bytes,
            refused_bytes,
        );

        Ok(SwarmMemoryResidencyPlan {
            schema_version: SWARM_MEMORY_RESIDENCY_POLICY_SCHEMA_VERSION.to_string(),
            source_snapshot_id: self.snapshot_id.clone(),
            policy_id: request.policy_id.clone(),
            workload_id: request.workload_id.clone(),
            workload_class: request.workload_class,
            affected_region_id: request.affected_region_id.clone(),
            affected_task_ids: sorted_unique_strings(&request.affected_task_ids),
            proof_lane_id: request.proof_lane_id.clone(),
            proof_command: request.proof_command.clone(),
            decision,
            residency_tier,
            brownout_class,
            fallback_reason,
            before,
            after,
            requested_bytes: request.requested_bytes,
            minimum_hot_bytes,
            hot_resident_bytes,
            warm_resident_bytes,
            spilled_bytes,
            browned_out_bytes,
            refused_bytes,
            metrics_age_secs: request.metrics_age_secs,
            max_metrics_age_secs: request.max_metrics_age_secs,
            metrics_stale,
            no_win_decision,
            preserved_invariants: SwarmMemoryProtectedInvariant::all(),
            explanation,
        })
    }

    fn classify_source_only_lane(&self) -> SwarmLaneAdmission {
        let mut reason_codes = vec![SwarmAdmissionReasonCode::SourceOnlyAlwaysAvailable];
        if self.disk.pressure_level == SwarmDiskPressureLevel::Critical {
            reason_codes.push(SwarmAdmissionReasonCode::DiskCriticalPreferSourceOnly);
        }
        if self.coordination.active_dirty_paths > 0 {
            reason_codes.push(SwarmAdmissionReasonCode::PeerDirtyPathsRequireNarrowReservations);
        }
        if self.coordination.ready_beads == 0 {
            reason_codes.push(SwarmAdmissionReasonCode::SparseReadyQueueUseFallback);
        }
        SwarmLaneAdmission {
            lane: SwarmAdmissionLane::InteractiveSourceOnly,
            decision: SwarmAdmissionDecision::Admit,
            validation_class: SwarmValidationClass::SourceOnly,
            reason_codes,
        }
    }

    fn recommend_admission_lane(&self, lanes: &[SwarmLaneAdmission]) -> SwarmAdmissionLane {
        let is_admitted = |candidate| {
            lanes.iter().any(|lane| {
                lane.lane == candidate && lane.decision == SwarmAdmissionDecision::Admit
            })
        };

        if self.coordination.ready_beads == 0
            || self.disk.pressure_level == SwarmDiskPressureLevel::Critical
            || matches!(
                self.memory.pressure_tier,
                SwarmMemoryPressureTier::Saturated | SwarmMemoryPressureTier::Critical
            )
        {
            if is_admitted(SwarmAdmissionLane::InteractiveSourceOnly) {
                return SwarmAdmissionLane::InteractiveSourceOnly;
            }
        }

        if is_admitted(SwarmAdmissionLane::RemoteProof) {
            return SwarmAdmissionLane::RemoteProof;
        }
        if is_admitted(SwarmAdmissionLane::InteractiveSourceOnly) {
            return SwarmAdmissionLane::InteractiveSourceOnly;
        }
        if is_admitted(SwarmAdmissionLane::TrackerOnlyPlanning) {
            return SwarmAdmissionLane::TrackerOnlyPlanning;
        }

        SwarmAdmissionLane::TrackerOnlyPlanning
    }

    fn classify_tracker_planning_lane(&self) -> SwarmLaneAdmission {
        let mut reason_codes = vec![SwarmAdmissionReasonCode::TrackerPlanningAlwaysAvailable];
        if self.coordination.ready_beads == 0 {
            reason_codes.push(SwarmAdmissionReasonCode::SparseReadyQueueUseFallback);
        }
        SwarmLaneAdmission {
            lane: SwarmAdmissionLane::TrackerOnlyPlanning,
            decision: SwarmAdmissionDecision::Admit,
            validation_class: SwarmValidationClass::SourceOnly,
            reason_codes,
        }
    }

    fn classify_remote_proof_lane(&self) -> SwarmLaneAdmission {
        let mut reason_codes = Vec::new();
        let decision = match self.rch.admissibility {
            SwarmRchAdmissibility::Available => {
                reason_codes.push(SwarmAdmissionReasonCode::RchAvailable);
                SwarmAdmissionDecision::Admit
            }
            SwarmRchAdmissibility::Degraded => {
                reason_codes.push(SwarmAdmissionReasonCode::RchDegraded);
                SwarmAdmissionDecision::Admit
            }
            SwarmRchAdmissibility::Unavailable => {
                reason_codes.push(SwarmAdmissionReasonCode::RchUnavailable);
                SwarmAdmissionDecision::Defer
            }
            SwarmRchAdmissibility::DeferredByPolicy => {
                reason_codes.push(SwarmAdmissionReasonCode::RchDeferredByPolicy);
                SwarmAdmissionDecision::Defer
            }
            SwarmRchAdmissibility::Unknown => {
                reason_codes.push(SwarmAdmissionReasonCode::RchUnknown);
                SwarmAdmissionDecision::Defer
            }
        };
        if self.disk.pressure_level == SwarmDiskPressureLevel::Critical {
            reason_codes.push(SwarmAdmissionReasonCode::DiskCriticalRemoteOnly);
        }
        SwarmLaneAdmission {
            lane: SwarmAdmissionLane::RemoteProof,
            decision,
            validation_class: SwarmValidationClass::RemoteRch,
            reason_codes,
        }
    }

    fn classify_local_artifact_lane(&self) -> SwarmLaneAdmission {
        let mut reason_codes = Vec::new();
        let mut decision = SwarmAdmissionDecision::Admit;

        match self.disk.pressure_level {
            SwarmDiskPressureLevel::Healthy => {
                reason_codes.push(SwarmAdmissionReasonCode::DiskHealthy);
            }
            SwarmDiskPressureLevel::Low => {
                decision = SwarmAdmissionDecision::Defer;
                reason_codes.push(SwarmAdmissionReasonCode::DiskLowPreferRemoteOrSourceOnly);
            }
            SwarmDiskPressureLevel::Critical => {
                decision = SwarmAdmissionDecision::Defer;
                reason_codes.push(SwarmAdmissionReasonCode::DiskCriticalBlocksLocalArtifacts);
            }
            SwarmDiskPressureLevel::Unknown => {
                decision = SwarmAdmissionDecision::Defer;
                reason_codes.push(SwarmAdmissionReasonCode::DiskUnknownBlocksLocalArtifacts);
            }
        }
        if matches!(
            self.memory.pressure_tier,
            SwarmMemoryPressureTier::Saturated | SwarmMemoryPressureTier::Critical
        ) {
            decision = SwarmAdmissionDecision::Defer;
            reason_codes.push(SwarmAdmissionReasonCode::MemoryPressureBlocksArtifactGrowth);
        }

        SwarmLaneAdmission {
            lane: SwarmAdmissionLane::LocalArtifactRetrieval,
            decision,
            validation_class: SwarmValidationClass::LocalArtifact,
            reason_codes,
        }
    }

    fn classify_cleanup_authorization_lane(&self) -> SwarmLaneAdmission {
        let mut reason_codes = vec![SwarmAdmissionReasonCode::CleanupRequiresAuthorization];
        if self.disk.pressure_level == SwarmDiskPressureLevel::Critical {
            reason_codes.push(SwarmAdmissionReasonCode::DiskCriticalNeedsCleanupReview);
        }
        SwarmLaneAdmission {
            lane: SwarmAdmissionLane::CleanupAuthorization,
            decision: SwarmAdmissionDecision::RequireAuthorization,
            validation_class: SwarmValidationClass::HumanAuthorizedCleanup,
            reason_codes,
        }
    }
}

/// Memory host tier used by the deterministic budget planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryHostTier {
    /// Total memory was not reported.
    Unknown,
    /// Small or laptop-class host, up to roughly 64 GiB.
    Small,
    /// Workstation/server host below the high-memory threshold.
    Standard,
    /// High-memory swarm host, 256 GiB or more.
    HighMemory,
}

impl SwarmMemoryHostTier {
    fn classify(total_bytes: Option<u64>) -> Self {
        const GIB: u64 = 1_024 * 1_024 * 1_024;

        match total_bytes {
            None => Self::Unknown,
            Some(bytes) if bytes >= 256 * GIB => Self::HighMemory,
            Some(bytes) if bytes > 64 * GIB => Self::Standard,
            Some(_) => Self::Small,
        }
    }

    fn emergency_reserve_bytes(
        self,
        total_bytes: u64,
        available_bytes: u64,
        pressure_tier: SwarmMemoryPressureTier,
    ) -> u64 {
        const GIB: u64 = 1_024 * 1_024 * 1_024;

        let tier_floor = match self {
            Self::Unknown => 0,
            Self::Small => 4 * GIB,
            Self::Standard => 12 * GIB,
            Self::HighMemory => 32 * GIB,
        };
        let ratio_floor = total_bytes / 10;
        let healthy_reserve = tier_floor.max(ratio_floor);

        let pressure_reserve = match pressure_tier {
            SwarmMemoryPressureTier::Unknown => healthy_reserve.max(available_bytes / 4),
            SwarmMemoryPressureTier::Healthy => healthy_reserve,
            SwarmMemoryPressureTier::Low => healthy_reserve.max(available_bytes / 5),
            SwarmMemoryPressureTier::Saturated => healthy_reserve.max(available_bytes / 3),
            SwarmMemoryPressureTier::Critical => healthy_reserve.max(available_bytes / 2),
        };
        if available_bytes == 0 {
            0
        } else {
            pressure_reserve.min(available_bytes.saturating_sub(1))
        }
    }

    fn budget_weights(self, pressure_tier: SwarmMemoryPressureTier) -> (u64, u64, u64, u64) {
        match pressure_tier {
            SwarmMemoryPressureTier::Critical => (90, 10, 0, 0),
            SwarmMemoryPressureTier::Saturated => (70, 20, 5, 5),
            SwarmMemoryPressureTier::Low => (45, 30, 15, 10),
            SwarmMemoryPressureTier::Unknown => (80, 20, 0, 0),
            SwarmMemoryPressureTier::Healthy => match self {
                Self::Unknown => (80, 20, 0, 0),
                Self::Small => (45, 25, 15, 15),
                Self::Standard => (35, 30, 20, 15),
                Self::HighMemory => (25, 35, 25, 15),
            },
        }
    }
}

/// Deterministic per-lane memory budget plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmMemoryBudgetPlan {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Snapshot identifier copied from the source snapshot.
    pub source_snapshot_id: String,
    /// Host tier selected from explicit total memory.
    pub host_tier: SwarmMemoryHostTier,
    /// Pressure tier copied from the source snapshot.
    pub pressure_tier: SwarmMemoryPressureTier,
    /// Available memory supplied by the adapter.
    pub available_bytes: u64,
    /// Total memory supplied by the adapter, or available bytes if total is absent.
    pub total_bytes: u64,
    /// Reserve preserved before assigning any lane budget.
    pub emergency_reserve_bytes: u64,
    /// Interactive runtime state and source-only coordination budget.
    pub interactive_runtime_bytes: u64,
    /// Trace and replay buffer budget.
    pub trace_replay_bytes: u64,
    /// Proof artifact staging budget.
    pub proof_artifact_staging_bytes: u64,
    /// Reusable compiler/build cache budget.
    pub compiler_cache_bytes: u64,
    /// Sum of lane budgets, excluding emergency reserve.
    pub total_planned_bytes: u64,
}

/// Workload class for the memory residency planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryResidencyWorkloadClass {
    /// Region/task state that must stay resident for runtime progress.
    InteractiveRuntime,
    /// Trace replay buffers that can be resized but should not disappear.
    TraceReplay,
    /// Remote-proof artifacts that can spill to external artifact storage.
    ProofArtifact,
    /// Compiler/cache growth that is useful but noncritical.
    CompilerCache,
    /// Rich diagnostics and formatting that can be browned out first.
    OptionalDiagnostics,
}

impl SwarmMemoryResidencyWorkloadClass {
    const fn lane_budget_bytes(self, budget: &SwarmMemoryBudgetPlan) -> u64 {
        match self {
            Self::InteractiveRuntime => budget.interactive_runtime_bytes,
            Self::TraceReplay => budget.trace_replay_bytes,
            Self::ProofArtifact => budget.proof_artifact_staging_bytes,
            Self::CompilerCache | Self::OptionalDiagnostics => budget.compiler_cache_bytes,
        }
    }

    const fn brownout_eligible(self) -> bool {
        matches!(
            self,
            Self::ProofArtifact | Self::CompilerCache | Self::OptionalDiagnostics
        )
    }
}

/// Residency tier selected for a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryResidencyTier {
    /// The whole request remains hot and resident.
    Hot,
    /// The request remains resident, but not all bytes are hot-priority.
    Warm,
    /// Cold bytes should spill to an explicit artifact/cache surface.
    SpillEligible,
    /// Optional bytes should be browned out before runtime state is touched.
    BrownoutEligible,
    /// No safe residency tier exists for this request.
    Refused,
}

/// Brownout class selected by the residency planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryBrownoutClass {
    /// No brownout is needed.
    None,
    /// Inputs are healthy enough to observe only.
    Observe,
    /// Optional bytes are degraded under pressure.
    DegradeOptional,
    /// Optional bytes are shed or excluded.
    ShedOptional,
    /// The planner emitted a no-win receipt.
    NoWin,
}

/// Deterministic memory residency decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryResidencyDecision {
    /// Admit the whole request as hot resident state.
    AdmitHot,
    /// Keep hot/warm bytes resident and spill the cold remainder.
    SpillCold,
    /// Preserve hot/warm bytes and brown out optional remainder.
    BrownoutOptional,
    /// Refuse or defer with an explicit no-win reason.
    RefuseNoWin,
}

/// Fail-closed fallback reason for no-win memory decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryResidencyFallbackReason {
    /// The selected workload lane had no usable memory budget.
    EmptyBudget,
    /// Metrics were older than the request allows.
    StaleMetrics,
    /// The request contradicted itself.
    ContradictoryPolicy,
    /// No hot, spill, or brownout tier could preserve invariants.
    NoSafeResidencyTier,
}

/// Runtime invariants that memory brownout must preserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryProtectedInvariant {
    /// Scheduler and worker progress remain available.
    CoreScheduling,
    /// Cancellation request/drain/finalize remains available.
    CancellationDrain,
    /// Race losers remain drainable.
    LoserDrain,
    /// Region close still implies quiescence.
    RegionQuiescence,
    /// Permits, acks, and leases still resolve.
    ObligationCleanup,
}

impl SwarmMemoryProtectedInvariant {
    fn all() -> Vec<Self> {
        vec![
            Self::CoreScheduling,
            Self::CancellationDrain,
            Self::LoserDrain,
            Self::RegionQuiescence,
            Self::ObligationCleanup,
        ]
    }
}

/// Memory envelope before or after a residency decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmMemoryResidencyEnvelope {
    /// Available bytes from the explicit capacity snapshot.
    pub available_bytes: u64,
    /// Emergency reserve that must remain outside lane budgets.
    pub emergency_reserve_bytes: u64,
    /// Budget selected for the workload class.
    pub lane_budget_bytes: u64,
    /// Memory pressure tier copied from the capacity snapshot.
    pub pressure_tier: SwarmMemoryPressureTier,
    /// Host tier derived from the capacity snapshot.
    pub host_tier: SwarmMemoryHostTier,
}

/// Request for a deterministic memory residency decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmMemoryResidencyRequest {
    /// Stable policy/run identifier.
    pub policy_id: String,
    /// Stable workload identifier.
    pub workload_id: String,
    /// Class used to select the applicable lane budget.
    pub workload_class: SwarmMemoryResidencyWorkloadClass,
    /// Region affected by this decision, if known.
    pub affected_region_id: Option<String>,
    /// Task ids affected by this decision.
    pub affected_task_ids: Vec<String>,
    /// Bytes requested by the workload.
    pub requested_bytes: u64,
    /// Minimum bytes that must remain hot to preserve progress.
    pub minimum_hot_bytes: u64,
    /// Whether cold bytes may spill to a non-resident artifact/cache surface.
    pub spill_allowed: bool,
    /// Whether optional bytes may brown out.
    pub brownout_allowed: bool,
    /// Age of the capacity and scheduler metrics.
    pub metrics_age_secs: u64,
    /// Maximum accepted metrics age for this request.
    pub max_metrics_age_secs: u64,
    /// Proof lane that should validate this policy, if known.
    pub proof_lane_id: Option<String>,
    /// Exact proof command for handoff, if known.
    pub proof_command: Option<String>,
}

impl SwarmMemoryResidencyRequest {
    fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.policy_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyMemoryResidencyPolicyId);
        }
        if self.workload_id.trim().is_empty() {
            return Err(SchedulerEvidenceError::EmptyMemoryResidencyWorkloadId);
        }
        Ok(())
    }
}

/// Deterministic memory residency and brownout policy report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmMemoryResidencyPlan {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Capacity snapshot id copied from the source snapshot.
    pub source_snapshot_id: String,
    /// Policy id copied from the request.
    pub policy_id: String,
    /// Workload id copied from the request.
    pub workload_id: String,
    /// Workload class copied from the request.
    pub workload_class: SwarmMemoryResidencyWorkloadClass,
    /// Region affected by this decision, if known.
    pub affected_region_id: Option<String>,
    /// Task ids affected by this decision, sorted and deduplicated.
    pub affected_task_ids: Vec<String>,
    /// Proof lane that should validate this policy, if known.
    pub proof_lane_id: Option<String>,
    /// Exact proof command for handoff, if known.
    pub proof_command: Option<String>,
    /// Deterministic residency decision.
    pub decision: SwarmMemoryResidencyDecision,
    /// Residency tier selected for the workload.
    pub residency_tier: SwarmMemoryResidencyTier,
    /// Brownout class selected for optional work.
    pub brownout_class: SwarmMemoryBrownoutClass,
    /// Fail-closed fallback reason, if any.
    pub fallback_reason: Option<SwarmMemoryResidencyFallbackReason>,
    /// Memory envelope before applying the decision.
    pub before: SwarmMemoryResidencyEnvelope,
    /// Memory envelope after resident bytes are admitted.
    pub after: SwarmMemoryResidencyEnvelope,
    /// Requested bytes copied from the request.
    pub requested_bytes: u64,
    /// Minimum hot bytes after request normalization.
    pub minimum_hot_bytes: u64,
    /// Bytes kept in the hot resident tier.
    pub hot_resident_bytes: u64,
    /// Bytes kept in the warm resident tier.
    pub warm_resident_bytes: u64,
    /// Bytes assigned to an explicit spill surface.
    pub spilled_bytes: u64,
    /// Bytes browned out from optional surfaces.
    pub browned_out_bytes: u64,
    /// Bytes refused by a no-win decision.
    pub refused_bytes: u64,
    /// Age of the metrics used by the decision.
    pub metrics_age_secs: u64,
    /// Maximum metrics age accepted by the request.
    pub max_metrics_age_secs: u64,
    /// Whether metrics age exceeded the accepted bound.
    pub metrics_stale: bool,
    /// Whether this plan is a no-win receipt.
    pub no_win_decision: bool,
    /// Runtime invariants preserved by every decision.
    pub preserved_invariants: Vec<SwarmMemoryProtectedInvariant>,
    /// Deterministic operator-facing explanation lines.
    pub explanation: Vec<String>,
}

/// Work lanes that swarm-scale admission policy classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdmissionLane {
    /// Latency-sensitive source edits, code review, and lightweight checks.
    InteractiveSourceOnly,
    /// Tracker/mail/planning work that does not need build artifacts.
    TrackerOnlyPlanning,
    /// Remote `rch` proof work without local artifact-heavy retrieval.
    RemoteProof,
    /// Local proof-output retrieval or artifact-heavy analysis.
    LocalArtifactRetrieval,
    /// Cleanup work that may delete or truncate data and needs human approval.
    CleanupAuthorization,
}

/// Deterministic admission decision for one work lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdmissionDecision {
    /// Work may proceed under the attached validation class.
    Admit,
    /// Work should wait for pressure or capacity to recover.
    Defer,
    /// Work needs explicit human approval before it can proceed.
    RequireAuthorization,
}

/// Validation class an admitted lane should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmValidationClass {
    /// Source-only checks such as rustfmt, JSON parsing, or diff checks.
    SourceOnly,
    /// Remote `rch` build/test proof.
    RemoteRch,
    /// Local artifact retrieval or artifact inspection.
    LocalArtifact,
    /// Human-authorized cleanup/truncation path.
    HumanAuthorizedCleanup,
}

/// Stable reason codes for lane admission decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmAdmissionReasonCode {
    /// Source-only work remains available even under disk pressure.
    SourceOnlyAlwaysAvailable,
    /// Tracker/planning work remains available even when heavy work is unsafe.
    TrackerPlanningAlwaysAvailable,
    /// Red disk should bias agents toward source-only work.
    DiskCriticalPreferSourceOnly,
    /// Red disk does not block remote-only proof submission by itself.
    DiskCriticalRemoteOnly,
    /// Local artifact retrieval is allowed by disk state.
    DiskHealthy,
    /// Low disk should prefer remote or source-only work.
    DiskLowPreferRemoteOrSourceOnly,
    /// Red disk blocks local artifact-heavy work.
    DiskCriticalBlocksLocalArtifacts,
    /// Missing disk pressure data blocks local artifact-heavy work.
    DiskUnknownBlocksLocalArtifacts,
    /// Red disk means cleanup should be reviewed explicitly.
    DiskCriticalNeedsCleanupReview,
    /// rch workers are available.
    RchAvailable,
    /// rch workers are degraded but usable.
    RchDegraded,
    /// rch workers are unavailable.
    RchUnavailable,
    /// rch work was deferred by a higher-level policy.
    RchDeferredByPolicy,
    /// rch capacity is unknown, so remote proof work is deferred.
    RchUnknown,
    /// Memory pressure blocks cache/artifact growth.
    MemoryPressureBlocksArtifactGrowth,
    /// Shared dirty paths require narrow reservations before source work.
    PeerDirtyPathsRequireNarrowReservations,
    /// No ready work is visible; use a safe fallback lane.
    SparseReadyQueueUseFallback,
    /// Cleanup needs explicit authorization and cannot be auto-admitted.
    CleanupRequiresAuthorization,
}

/// Admission decision for one lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLaneAdmission {
    /// Lane being classified.
    pub lane: SwarmAdmissionLane,
    /// Deterministic decision for this lane.
    pub decision: SwarmAdmissionDecision,
    /// Validation/proof class that applies if this lane is taken.
    pub validation_class: SwarmValidationClass,
    /// Stable reason codes explaining the decision.
    pub reason_codes: Vec<SwarmAdmissionReasonCode>,
}

/// Full deterministic report derived from one capacity snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAdmissionReport {
    /// Version tag for this schema.
    pub schema_version: String,
    /// Snapshot identifier copied from the source snapshot.
    pub source_snapshot_id: String,
    /// Best work-conserving lane to take under current pressure.
    pub recommended_lane: SwarmAdmissionLane,
    /// Per-lane decisions in stable priority order.
    pub lanes: Vec<SwarmLaneAdmission>,
}

/// Explicit CPU topology hints for swarm-scale admission decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmCpuTopologyHints {
    /// Logical CPU count visible to the admission adapter.
    pub logical_cpus: usize,
    /// Physical core count, if the adapter can report it deterministically.
    pub physical_cores: Option<usize>,
    /// NUMA or locality group count, if known.
    pub numa_nodes: Option<usize>,
    /// Worker target that policy should consider for this host.
    pub scheduler_worker_target: Option<usize>,
}

impl SwarmCpuTopologyHints {
    fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        if self.logical_cpus == 0 {
            return Err(SchedulerEvidenceError::InvalidCapacityDimension {
                field: "cpu.logical_cpus",
            });
        }
        if self.physical_cores == Some(0) {
            return Err(SchedulerEvidenceError::InvalidCapacityDimension {
                field: "cpu.physical_cores",
            });
        }
        if self.numa_nodes == Some(0) {
            return Err(SchedulerEvidenceError::InvalidCapacityDimension {
                field: "cpu.numa_nodes",
            });
        }
        if self.scheduler_worker_target == Some(0) {
            return Err(SchedulerEvidenceError::InvalidCapacityDimension {
                field: "cpu.scheduler_worker_target",
            });
        }
        Ok(())
    }
}

/// Coarse memory-pressure tier for deterministic policy fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMemoryPressureTier {
    /// Adapter did not provide a memory-pressure classification.
    #[default]
    Unknown,
    /// Plenty of memory is available.
    Healthy,
    /// Memory is reduced but not yet blocking ordinary work.
    Low,
    /// Memory pressure should throttle cache/artifact growth.
    Saturated,
    /// Memory pressure should fail closed for memory-heavy lanes.
    Critical,
}

/// Explicit memory capacity inputs for swarm-scale policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SwarmMemoryCapacity {
    /// Available memory in bytes, if reported.
    pub available_bytes: Option<u64>,
    /// Total memory in bytes, if reported.
    pub total_bytes: Option<u64>,
    /// Coarse pressure tier supplied by the adapter or fixture.
    #[serde(default)]
    pub pressure_tier: SwarmMemoryPressureTier,
}

impl SwarmMemoryCapacity {
    fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        validate_optional_capacity_pair(
            self.available_bytes,
            self.total_bytes,
            "memory.available_bytes",
            "memory.total_bytes",
        )
    }
}

/// Coarse disk-pressure level for proof/artifact admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmDiskPressureLevel {
    /// Adapter did not provide a disk-pressure classification.
    #[default]
    Unknown,
    /// Disk has enough space for normal proof/artifact work.
    Healthy,
    /// Disk is low; source-only and remote-only lanes should be preferred.
    Low,
    /// Disk is red; local artifact retrieval and cleanup need explicit handling.
    Critical,
}

/// Explicit disk capacity inputs for swarm-scale policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SwarmDiskCapacity {
    /// Free bytes on the relevant project/artifact filesystem, if reported.
    pub free_bytes: Option<u64>,
    /// Total bytes on the relevant filesystem, if reported.
    pub total_bytes: Option<u64>,
    /// Coarse pressure level supplied by the adapter or fixture.
    #[serde(default)]
    pub pressure_level: SwarmDiskPressureLevel,
}

impl SwarmDiskCapacity {
    fn validate(&self) -> Result<(), SchedulerEvidenceError> {
        validate_optional_capacity_pair(
            self.free_bytes,
            self.total_bytes,
            "disk.free_bytes",
            "disk.total_bytes",
        )
    }
}

/// rch-backed proof-work availability from the coordinator's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmRchAdmissibility {
    /// Adapter did not provide an rch availability classification.
    #[default]
    Unknown,
    /// Remote proof work can be admitted.
    Available,
    /// Remote proof work is available but degraded.
    Degraded,
    /// Remote proof work should not be admitted now.
    Unavailable,
    /// A higher-level policy intentionally deferred remote proof work.
    DeferredByPolicy,
}

/// Explicit remote proof-worker state for swarm-scale policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SwarmRchCapacity {
    /// rch admission classification.
    #[serde(default)]
    pub admissibility: SwarmRchAdmissibility,
    /// Number of healthy remote workers, if known.
    pub healthy_worker_count: Option<usize>,
    /// Number of currently available remote build slots, if known.
    pub available_slots: Option<usize>,
    /// Stable reason labels explaining degraded/unavailable states.
    #[serde(default)]
    pub blocked_reason_codes: Vec<String>,
}

/// Coordination-control backlog signals that affect work-conserving decisions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SwarmCoordinationBacklogSignals {
    /// Ready Beads count.
    pub ready_beads: usize,
    /// Open Beads count.
    pub open_beads: usize,
    /// In-progress Beads count.
    pub in_progress_beads: usize,
    /// Active Agent Mail reservations relevant to this project.
    pub active_reservations: usize,
    /// Dirty paths currently visible in the shared worktree.
    pub active_dirty_paths: usize,
    /// Agents with recent activity in the coordination view.
    pub active_agents: usize,
    /// In-progress Beads that look stale to the coordinator.
    pub stale_in_progress_beads: usize,
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
    /// The capacity snapshot id was empty.
    #[error("swarm capacity snapshot id must not be empty")]
    EmptyCapacitySnapshotId,
    /// A memory residency policy id was empty.
    #[error("swarm memory residency policy id must not be empty")]
    EmptyMemoryResidencyPolicyId,
    /// A memory residency workload id was empty.
    #[error("swarm memory residency workload id must not be empty")]
    EmptyMemoryResidencyWorkloadId,
    /// A required capacity dimension was zero or otherwise invalid.
    #[error("swarm capacity dimension is invalid: {field}")]
    InvalidCapacityDimension {
        /// Stable field path for the invalid dimension.
        field: &'static str,
    },
    /// A free/available capacity value exceeded the corresponding total.
    #[error("swarm capacity available field {available_field} exceeds total field {total_field}")]
    CapacityAvailableExceedsTotal {
        /// Field that reported the available/free value.
        available_field: &'static str,
        /// Field that reported the total value.
        total_field: &'static str,
    },
}

fn memory_residency_counts(
    requested_bytes: u64,
    minimum_hot_bytes: u64,
    lane_budget_bytes: u64,
    decision: SwarmMemoryResidencyDecision,
) -> (u64, u64, u64, u64, u64) {
    match decision {
        SwarmMemoryResidencyDecision::AdmitHot => (requested_bytes, 0, 0, 0, 0),
        SwarmMemoryResidencyDecision::SpillCold => {
            let hot = minimum_hot_bytes.min(lane_budget_bytes);
            let warm = requested_bytes
                .saturating_sub(hot)
                .min(lane_budget_bytes.saturating_sub(hot));
            let spilled = requested_bytes.saturating_sub(hot).saturating_sub(warm);
            (hot, warm, spilled, 0, 0)
        }
        SwarmMemoryResidencyDecision::BrownoutOptional => {
            let hot = minimum_hot_bytes.min(lane_budget_bytes);
            let warm = requested_bytes
                .saturating_sub(hot)
                .min(lane_budget_bytes.saturating_sub(hot));
            let browned_out = requested_bytes.saturating_sub(hot).saturating_sub(warm);
            (hot, warm, 0, browned_out, 0)
        }
        SwarmMemoryResidencyDecision::RefuseNoWin => (0, 0, 0, 0, requested_bytes),
    }
}

const fn residency_tier_for_decision(
    decision: SwarmMemoryResidencyDecision,
) -> SwarmMemoryResidencyTier {
    match decision {
        SwarmMemoryResidencyDecision::AdmitHot => SwarmMemoryResidencyTier::Hot,
        SwarmMemoryResidencyDecision::SpillCold => SwarmMemoryResidencyTier::SpillEligible,
        SwarmMemoryResidencyDecision::BrownoutOptional => {
            SwarmMemoryResidencyTier::BrownoutEligible
        }
        SwarmMemoryResidencyDecision::RefuseNoWin => SwarmMemoryResidencyTier::Refused,
    }
}

const fn brownout_class_for_decision(
    decision: SwarmMemoryResidencyDecision,
    pressure_tier: SwarmMemoryPressureTier,
) -> SwarmMemoryBrownoutClass {
    match decision {
        SwarmMemoryResidencyDecision::BrownoutOptional => SwarmMemoryBrownoutClass::ShedOptional,
        SwarmMemoryResidencyDecision::RefuseNoWin => SwarmMemoryBrownoutClass::NoWin,
        SwarmMemoryResidencyDecision::AdmitHot | SwarmMemoryResidencyDecision::SpillCold => {
            match pressure_tier {
                SwarmMemoryPressureTier::Critical | SwarmMemoryPressureTier::Saturated => {
                    SwarmMemoryBrownoutClass::DegradeOptional
                }
                SwarmMemoryPressureTier::Low | SwarmMemoryPressureTier::Unknown => {
                    SwarmMemoryBrownoutClass::Observe
                }
                SwarmMemoryPressureTier::Healthy => SwarmMemoryBrownoutClass::None,
            }
        }
    }
}

fn memory_residency_explanation(
    request: &SwarmMemoryResidencyRequest,
    decision: SwarmMemoryResidencyDecision,
    fallback_reason: Option<SwarmMemoryResidencyFallbackReason>,
    lane_budget_bytes: u64,
    hot_resident_bytes: u64,
    warm_resident_bytes: u64,
    spilled_bytes: u64,
    browned_out_bytes: u64,
    refused_bytes: u64,
) -> Vec<String> {
    let mut explanation = vec![format!(
        "workload={} class={:?} requested={}B lane_budget={}B decision={:?}",
        request.workload_id,
        request.workload_class,
        request.requested_bytes,
        lane_budget_bytes,
        decision
    )];
    if let Some(reason) = fallback_reason {
        explanation.push(format!("fallback_reason={reason:?}"));
    }
    explanation.push(format!(
        "resident_hot={}B resident_warm={}B spilled={}B browned_out={}B refused={}B",
        hot_resident_bytes, warm_resident_bytes, spilled_bytes, browned_out_bytes, refused_bytes
    ));
    explanation.push(
        "core scheduling, cancellation drain, loser drain, region quiescence, and obligation cleanup remain preserved"
            .to_string(),
    );
    explanation
}

fn sorted_unique_strings(values: &[String]) -> Vec<String> {
    let mut sorted = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    sorted.sort();
    sorted.dedup();
    sorted
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

fn validate_optional_capacity_pair(
    available: Option<u64>,
    total: Option<u64>,
    available_field: &'static str,
    total_field: &'static str,
) -> Result<(), SchedulerEvidenceError> {
    if let (Some(available), Some(total)) = (available, total)
        && available > total
    {
        return Err(SchedulerEvidenceError::CapacityAvailableExceedsTotal {
            available_field,
            total_field,
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
