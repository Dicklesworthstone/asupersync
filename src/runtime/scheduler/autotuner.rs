//! Scheduler hot-path autotuner for performance optimization.
//!
//! Provides observe-first autotuning for scheduler hot paths including:
//! - Lane selection priority tuning
//! - Local/global queue handoff optimization
//! - Batch sizing for ready/steal/handoff operations
//! - Cancellation promotion threshold adjustment
//!
//! The autotuner operates in configuration-driven mode with deterministic
//! behavior under LabRuntime testing.

use std::time::{Duration, Instant};

use crate::runtime::config::{BlockingPoolAffinityProfile, SchedulerPlacementMode};
use crate::runtime::scheduler::three_lane::{AdaptiveBatchSizingProfile, PreemptionMetrics};

/// Configuration-driven scheduler autotuning parameters.
#[derive(Debug, Clone)]
pub struct AutotunerConfig {
    /// Enable adaptive batch size tuning.
    pub enable_batch_tuning: bool,
    /// Enable steal batch size adjustment.
    pub enable_steal_tuning: bool,
    /// Enable browser handoff limit tuning.
    pub enable_handoff_tuning: bool,
    /// Minimum observation window before making adjustments.
    pub observation_window_ms: u64,
    /// Maximum allowed batch size adjustment per iteration.
    pub max_batch_delta: usize,
    /// Target p95 latency threshold in microseconds.
    pub target_p95_latency_us: u64,
}

impl Default for AutotunerConfig {
    fn default() -> Self {
        Self {
            enable_batch_tuning: true,
            enable_steal_tuning: true,
            enable_handoff_tuning: false, // More conservative default
            observation_window_ms: 1000,  // 1 second observation window
            max_batch_delta: 4,           // Conservative adjustment steps
            target_p95_latency_us: 1000,  // 1ms target latency
        }
    }
}

/// Observed performance metrics from scheduler hot paths.
#[derive(Debug, Clone, Default)]
pub struct HotPathObservation {
    /// Timestamp when observation was recorded.
    pub timestamp: Option<Instant>,
    /// Cancel lane dispatch ratio (basis points).
    pub cancel_dispatch_ratio_bps: u16,
    /// Timed lane dispatch ratio (basis points).
    pub timed_dispatch_ratio_bps: u16,
    /// Ready lane dispatch ratio (basis points).
    pub ready_dispatch_ratio_bps: u16,
    /// Average batch size for global ready drains.
    pub mean_ready_batch_size: f64,
    /// Current steal batch size configuration.
    pub current_steal_batch_size: usize,
    /// Current browser handoff limit.
    pub current_handoff_limit: usize,
    /// Adaptive batch scale-up events count.
    pub adaptive_scale_up_events: u64,
    /// Cancel debt floor hits count.
    pub cancel_debt_floor_hits: u64,
    /// Estimated p95 task dispatch latency in microseconds.
    pub estimated_p95_latency_us: u64,
}

/// Autotuner recommendation for scheduler parameter adjustments.
#[derive(Debug, Clone)]
pub struct AutotunerRecommendation {
    /// Recommended steal batch size adjustment.
    pub steal_batch_size: Option<usize>,
    /// Recommended browser handoff limit adjustment.
    pub handoff_limit: Option<usize>,
    /// Recommended adaptive ready profile adjustments.
    pub adaptive_profile: Option<AdaptiveBatchSizingProfile>,
    /// Confidence level in recommendation (0-100).
    pub confidence_percentage: u8,
    /// Human-readable reasoning for the recommendation.
    pub reasoning: String,
}

/// Scheduler knobs that the dry-run feedback controller may recommend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerFeedbackKnob {
    /// Work-steal batch size.
    StealBatchSize,
    /// Adaptive ready combiner profile.
    ReadyCombinerThresholds,
    /// Global ready queue limit.
    GlobalQueueLimit,
    /// Worker cohort placement policy.
    WorkerCohortPolicy,
    /// Blocking-pool cohort affinity policy.
    BlockingPoolAffinity,
    /// Admission-control pressure thresholds.
    AdmissionControlThresholds,
    /// Pressure metric input.
    PressureMetric,
}

/// Toggle set for the knobs eligible for dry-run feedback recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerFeedbackKnobSet {
    /// Allow steal-batch-size recommendations.
    pub steal_batch_size: bool,
    /// Allow ready-combiner adaptive threshold recommendations.
    pub ready_combiner_thresholds: bool,
    /// Allow global-queue-limit recommendations.
    pub global_queue_limit: bool,
    /// Allow worker cohort placement policy recommendations.
    pub worker_cohort_policy: bool,
    /// Allow blocking-pool affinity recommendations.
    pub blocking_pool_affinity: bool,
    /// Allow admission-control threshold recommendations.
    pub admission_control_thresholds: bool,
}

impl Default for SchedulerFeedbackKnobSet {
    fn default() -> Self {
        Self {
            steal_batch_size: true,
            ready_combiner_thresholds: true,
            global_queue_limit: true,
            worker_cohort_policy: true,
            blocking_pool_affinity: true,
            admission_control_thresholds: true,
        }
    }
}

/// Policy bounds for deterministic scheduler feedback recommendations.
#[derive(Debug, Clone)]
pub struct SchedulerFeedbackPolicy {
    /// Eligible scheduler knobs for this dry-run pass.
    pub eligible_knobs: SchedulerFeedbackKnobSet,
    /// Minimum recommended steal batch size.
    pub min_steal_batch_size: usize,
    /// Maximum recommended steal batch size.
    pub max_steal_batch_size: usize,
    /// Minimum recommended adaptive ready batch size.
    pub min_ready_batch_size: usize,
    /// Maximum recommended adaptive ready batch size.
    pub max_ready_batch_size: usize,
    /// Minimum bounded global queue limit. Zero remains allowed only when the
    /// current config is unbounded and no pressure recommendation needs a bound.
    pub min_global_queue_limit: usize,
    /// Maximum bounded global queue limit.
    pub max_global_queue_limit: usize,
    /// Lowest safe admission-control threshold.
    pub min_admission_threshold: f64,
    /// Highest safe admission-control threshold.
    pub max_admission_threshold: f64,
    /// Pressure at which ready/backlog signals are treated as burst load.
    pub burst_pressure_threshold: f64,
    /// Pressure at which cancellation/cleanup signals dominate throughput tuning.
    pub cancellation_pressure_threshold: f64,
    /// Pressure at which memory budget signals dominate queue expansion.
    pub memory_pressure_threshold: f64,
}

impl Default for SchedulerFeedbackPolicy {
    fn default() -> Self {
        Self {
            eligible_knobs: SchedulerFeedbackKnobSet::default(),
            min_steal_batch_size: 1,
            max_steal_batch_size: 64,
            min_ready_batch_size: 1,
            max_ready_batch_size: 64,
            min_global_queue_limit: 256,
            max_global_queue_limit: 1_048_576,
            min_admission_threshold: 0.05,
            max_admission_threshold: 0.98,
            burst_pressure_threshold: 0.75,
            cancellation_pressure_threshold: 0.60,
            memory_pressure_threshold: 0.80,
        }
    }
}

/// Admission-control thresholds eligible for scheduler feedback.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SchedulerAdmissionControlThresholds {
    /// Runnable queue pressure threshold.
    pub runnable_queue: f64,
    /// Blocking-pool saturation threshold.
    pub blocking_pool: f64,
    /// Channel backlog threshold.
    pub channel_backlog: f64,
    /// Cleanup-debt threshold.
    pub cleanup_debt: f64,
    /// Memory-budget threshold.
    pub memory_budget: f64,
}

impl Default for SchedulerAdmissionControlThresholds {
    fn default() -> Self {
        Self {
            runnable_queue: 0.80,
            blocking_pool: 0.90,
            channel_backlog: 0.70,
            cleanup_debt: 0.80,
            memory_budget: 0.90,
        }
    }
}

/// Current scheduler knob values supplied to the dry-run controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SchedulerFeedbackCurrentKnobs {
    /// Configured worker thread count.
    pub worker_threads: usize,
    /// Configured worker cohort count.
    pub cohort_count: usize,
    /// Current steal batch size.
    pub steal_batch_size: usize,
    /// Current adaptive ready-batch profile.
    pub ready_batch_profile: AdaptiveBatchSizingProfile,
    /// Current global queue limit, where zero means unbounded.
    pub global_queue_limit: usize,
    /// Current scheduler placement mode.
    pub placement_mode: SchedulerPlacementMode,
    /// Current blocking-pool affinity profile.
    pub blocking_pool_affinity: BlockingPoolAffinityProfile,
    /// Current admission-control thresholds.
    pub admission_thresholds: SchedulerAdmissionControlThresholds,
}

impl Default for SchedulerFeedbackCurrentKnobs {
    fn default() -> Self {
        Self {
            worker_threads: 4,
            cohort_count: 1,
            steal_batch_size: 16,
            ready_batch_profile: AdaptiveBatchSizingProfile {
                enabled: false,
                min_batch_size: 1,
                max_batch_size: 16,
                scale_up_ready_depth: 64,
                scale_up_in_flight: 2,
                scale_up_claim_failures: 1,
                cancel_debt_floor: 16,
                cooldown_steps: 0,
            },
            global_queue_limit: 0,
            placement_mode: SchedulerPlacementMode::LocalityFirst,
            blocking_pool_affinity: BlockingPoolAffinityProfile::Disabled,
            admission_thresholds: SchedulerAdmissionControlThresholds::default(),
        }
    }
}

/// Pressure signal identifiers used in feedback evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerFeedbackSignal {
    /// Runnable queue pressure.
    RunnableQueue,
    /// Ready queue pressure.
    ReadyQueue,
    /// Blocking-pool saturation pressure.
    BlockingPool,
    /// Channel backlog pressure.
    ChannelBacklog,
    /// Cancellation backlog pressure.
    Cancellation,
    /// Cleanup-debt pressure.
    CleanupDebt,
    /// Memory-budget pressure.
    MemoryBudget,
    /// Dispatch latency signal.
    DispatchLatency,
}

/// Pressure metrics supplied by pressure-lab or runtime-local evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SchedulerFeedbackMetrics {
    /// Runnable queue pressure in the range 0.0..=1.0+, when available.
    pub runnable_queue_pressure: Option<f64>,
    /// Ready queue pressure in the range 0.0..=1.0+, when available.
    pub ready_queue_pressure: Option<f64>,
    /// Blocking-pool pressure in the range 0.0..=1.0+, when available.
    pub blocking_pool_pressure: Option<f64>,
    /// Channel backlog pressure in the range 0.0..=1.0+, when available.
    pub channel_backlog_pressure: Option<f64>,
    /// Cancellation backlog pressure in the range 0.0..=1.0+, when available.
    pub cancellation_pressure: Option<f64>,
    /// Cleanup-debt pressure in the range 0.0..=1.0+, when available.
    pub cleanup_debt_pressure: Option<f64>,
    /// Memory-budget pressure in the range 0.0..=1.0+, when available.
    pub memory_budget_pressure: Option<f64>,
    /// Estimated p95 dispatch latency in microseconds, when available.
    pub p95_dispatch_latency_us: Option<u64>,
    /// Estimated p99 dispatch latency in microseconds, when available.
    pub p99_dispatch_latency_us: Option<u64>,
}

/// Controller workload classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerFeedbackWorkloadClass {
    /// Metrics were invalid; no tuning recommendation is emitted.
    InvalidMetrics,
    /// Too many signals were unavailable; no tuning recommendation is emitted.
    InsufficientMetrics,
    /// Pressure is within stable bounds.
    Stable,
    /// Runnable/ready/channel backlog dominates.
    Burst,
    /// Cancellation or cleanup debt dominates.
    CancellationHeavy,
    /// Memory pressure dominates queue expansion.
    MemoryPressure,
}

/// Structured reason codes attached to dry-run feedback evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerFeedbackReason {
    /// No change is recommended for the current stable signal set.
    StableNoChange,
    /// Burst pressure supports more throughput-oriented knobs.
    BurstThroughput,
    /// Cancellation pressure requires responsiveness-first knobs.
    CancellationResponsiveness,
    /// Memory pressure requires conservative queue and batch bounds.
    MemoryConservation,
    /// Missing metrics caused observe-only behavior.
    MissingMetricsObserveOnly,
    /// Invalid metrics caused observe-only behavior.
    InvalidMetricsObserveOnly,
    /// Throughput-oriented knobs were suppressed by cancellation or memory pressure.
    ContradictoryThroughputSuppressed,
    /// Core runtime invariants remain pinned on.
    ProtectedInvariantsPinned,
}

/// Clamp reason for a recommendation or input signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerFeedbackClampReason {
    /// Requested value was below the policy minimum.
    BelowMinimum,
    /// Requested value was above the policy maximum.
    AboveMaximum,
    /// Metric was NaN, infinite, or negative.
    InvalidMetric,
    /// The knob is not enabled in the policy for this pass.
    KnobDisabled,
    /// A throughput recommendation contradicted cancellation or memory pressure.
    ContradictoryPressure,
    /// Requested value would disable a protected runtime invariant.
    WouldDisableProtectedInvariant,
}

/// Structured clamp evidence for operator review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerFeedbackClamp {
    /// Affected knob or pressure metric.
    pub knob: SchedulerFeedbackKnob,
    /// Deterministic clamp reason.
    pub reason: SchedulerFeedbackClampReason,
    /// Operator-facing requested value.
    pub requested: String,
    /// Operator-facing clamped value.
    pub clamped: String,
}

/// Runtime invariants the feedback controller is not allowed to disable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerFeedbackProtectedInvariants {
    /// Cancellation drain remains required.
    pub cancellation_drain: bool,
    /// Race loser drain remains required.
    pub loser_drain: bool,
    /// Obligation cleanup remains required.
    pub obligation_cleanup: bool,
    /// Region close still implies quiescence.
    pub region_quiescence: bool,
}

impl SchedulerFeedbackProtectedInvariants {
    /// All protected invariants pinned on.
    pub const PRESERVED: Self = Self {
        cancellation_drain: true,
        loser_drain: true,
        obligation_cleanup: true,
        region_quiescence: true,
    };
}

/// Structured evidence emitted by a dry-run scheduler feedback pass.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerFeedbackEvidence {
    /// Workload classification used for the recommendation.
    pub workload_class: SchedulerFeedbackWorkloadClass,
    /// Highest sanitized pressure score, in basis points.
    pub pressure_score_bps: u16,
    /// Confidence level in the recommendation, 0-100.
    pub confidence_percentage: u8,
    /// Deterministic reason codes.
    pub reasons: Vec<SchedulerFeedbackReason>,
    /// Missing pressure signals.
    pub missing_signals: Vec<SchedulerFeedbackSignal>,
    /// Invalid pressure signals.
    pub invalid_signals: Vec<SchedulerFeedbackSignal>,
    /// Clamp evidence for unsafe or disabled recommendations.
    pub clamps: Vec<SchedulerFeedbackClamp>,
}

impl Default for SchedulerFeedbackEvidence {
    fn default() -> Self {
        Self {
            workload_class: SchedulerFeedbackWorkloadClass::InsufficientMetrics,
            pressure_score_bps: 0,
            confidence_percentage: 0,
            reasons: Vec::new(),
            missing_signals: Vec::new(),
            invalid_signals: Vec::new(),
            clamps: Vec::new(),
        }
    }
}

/// Dry-run scheduler feedback recommendation.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerFeedbackRecommendation {
    /// Always true for this observe-first controller surface.
    pub dry_run: bool,
    /// Recommended steal batch size.
    pub steal_batch_size: Option<usize>,
    /// Recommended adaptive ready-batch profile.
    pub ready_batch_profile: Option<AdaptiveBatchSizingProfile>,
    /// Recommended bounded global queue limit.
    pub global_queue_limit: Option<usize>,
    /// Recommended placement mode.
    pub placement_mode: Option<SchedulerPlacementMode>,
    /// Recommended blocking-pool affinity profile.
    pub blocking_pool_affinity: Option<BlockingPoolAffinityProfile>,
    /// Recommended admission-control thresholds.
    pub admission_thresholds: Option<SchedulerAdmissionControlThresholds>,
    /// Protected invariants that remain pinned on.
    pub protected_invariants: SchedulerFeedbackProtectedInvariants,
    /// Structured recommendation evidence.
    pub evidence: SchedulerFeedbackEvidence,
}

impl SchedulerFeedbackRecommendation {
    /// Whether the dry-run pass emitted any knob recommendation.
    #[must_use]
    pub fn has_knob_changes(&self) -> bool {
        self.steal_batch_size.is_some()
            || self.ready_batch_profile.is_some()
            || self.global_queue_limit.is_some()
            || self.placement_mode.is_some()
            || self.blocking_pool_affinity.is_some()
            || self.admission_thresholds.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
struct EffectiveFeedbackPolicy {
    eligible_knobs: SchedulerFeedbackKnobSet,
    min_steal_batch_size: usize,
    max_steal_batch_size: usize,
    min_ready_batch_size: usize,
    max_ready_batch_size: usize,
    min_global_queue_limit: usize,
    max_global_queue_limit: usize,
    min_admission_threshold: f64,
    max_admission_threshold: f64,
    burst_pressure_threshold: f64,
    cancellation_pressure_threshold: f64,
    memory_pressure_threshold: f64,
}

#[derive(Debug, Clone, Copy)]
struct SanitizedFeedbackMetrics {
    runnable_queue_pressure: Option<f64>,
    ready_queue_pressure: Option<f64>,
    blocking_pool_pressure: Option<f64>,
    channel_backlog_pressure: Option<f64>,
    cancellation_pressure: Option<f64>,
    cleanup_debt_pressure: Option<f64>,
    memory_budget_pressure: Option<f64>,
    p95_dispatch_latency_us: Option<u64>,
    p99_dispatch_latency_us: Option<u64>,
}

impl SanitizedFeedbackMetrics {
    fn available_signal_count(self) -> usize {
        [
            self.runnable_queue_pressure,
            self.ready_queue_pressure,
            self.blocking_pool_pressure,
            self.channel_backlog_pressure,
            self.cancellation_pressure,
            self.cleanup_debt_pressure,
            self.memory_budget_pressure,
        ]
        .into_iter()
        .flatten()
        .count()
    }

    fn queue_pressure(self) -> Option<f64> {
        max_present([
            self.runnable_queue_pressure,
            self.ready_queue_pressure,
            self.channel_backlog_pressure,
        ])
    }

    fn cancellation_pressure(self) -> Option<f64> {
        max_present([self.cancellation_pressure, self.cleanup_debt_pressure])
    }

    fn max_pressure(self) -> f64 {
        max_present([
            self.runnable_queue_pressure,
            self.ready_queue_pressure,
            self.blocking_pool_pressure,
            self.channel_backlog_pressure,
            self.cancellation_pressure,
            self.cleanup_debt_pressure,
            self.memory_budget_pressure,
            self.latency_pressure(),
        ])
        .unwrap_or(0.0)
    }

    fn has_core_signals(self) -> bool {
        self.queue_pressure().is_some()
            && self.cancellation_pressure().is_some()
            && self.memory_budget_pressure.is_some()
    }

    fn latency_pressure(self) -> Option<f64> {
        max_present([
            self.p95_dispatch_latency_us
                .map(|latency| latency as f64 / 2_000.0),
            self.p99_dispatch_latency_us
                .map(|latency| latency as f64 / 5_000.0),
        ])
    }
}

/// Generate a deterministic dry-run scheduler feedback recommendation.
///
/// This function never mutates runtime configuration and never spawns a
/// background controller. Callers must supply explicit pressure metrics,
/// current knobs, and policy bounds for every pass.
#[must_use]
pub fn recommend_scheduler_feedback(
    metrics: SchedulerFeedbackMetrics,
    current: SchedulerFeedbackCurrentKnobs,
    policy: SchedulerFeedbackPolicy,
) -> SchedulerFeedbackRecommendation {
    let mut evidence = SchedulerFeedbackEvidence::default();
    evidence
        .reasons
        .push(SchedulerFeedbackReason::ProtectedInvariantsPinned);

    let policy = effective_feedback_policy(policy, &mut evidence);
    let current = normalized_current_knobs(current, &policy, &mut evidence);
    let metrics = sanitize_feedback_metrics(metrics, &mut evidence);

    evidence.pressure_score_bps = pressure_to_bps(metrics.max_pressure());

    if !evidence.invalid_signals.is_empty() {
        evidence.workload_class = SchedulerFeedbackWorkloadClass::InvalidMetrics;
        evidence.confidence_percentage = 0;
        evidence
            .reasons
            .push(SchedulerFeedbackReason::InvalidMetricsObserveOnly);
        return empty_feedback_recommendation(evidence);
    }

    if metrics.available_signal_count() < 3 || !metrics.has_core_signals() {
        evidence.workload_class = SchedulerFeedbackWorkloadClass::InsufficientMetrics;
        evidence.confidence_percentage = 20;
        evidence
            .reasons
            .push(SchedulerFeedbackReason::MissingMetricsObserveOnly);
        return empty_feedback_recommendation(evidence);
    }

    let queue_pressure = metrics.queue_pressure().unwrap_or(0.0);
    let cancellation_pressure = metrics.cancellation_pressure().unwrap_or(0.0);
    let memory_pressure = metrics.memory_budget_pressure.unwrap_or(0.0);
    let burst_load = queue_pressure >= policy.burst_pressure_threshold;
    let cancellation_heavy = cancellation_pressure >= policy.cancellation_pressure_threshold;
    let memory_heavy = memory_pressure >= policy.memory_pressure_threshold;

    let workload_class = if cancellation_heavy {
        if burst_load {
            record_contradictory_throughput_suppression(&mut evidence);
        }
        SchedulerFeedbackWorkloadClass::CancellationHeavy
    } else if memory_heavy {
        if burst_load {
            record_contradictory_throughput_suppression(&mut evidence);
        }
        SchedulerFeedbackWorkloadClass::MemoryPressure
    } else if burst_load {
        SchedulerFeedbackWorkloadClass::Burst
    } else {
        SchedulerFeedbackWorkloadClass::Stable
    };

    evidence.workload_class = workload_class;

    match workload_class {
        SchedulerFeedbackWorkloadClass::Stable => {
            evidence.confidence_percentage = 80;
            evidence
                .reasons
                .push(SchedulerFeedbackReason::StableNoChange);
            empty_feedback_recommendation(evidence)
        }
        SchedulerFeedbackWorkloadClass::Burst => {
            evidence.confidence_percentage = 75;
            evidence
                .reasons
                .push(SchedulerFeedbackReason::BurstThroughput);
            burst_feedback_recommendation(current, &policy, evidence)
        }
        SchedulerFeedbackWorkloadClass::CancellationHeavy => {
            evidence.confidence_percentage = 85;
            evidence
                .reasons
                .push(SchedulerFeedbackReason::CancellationResponsiveness);
            cancellation_feedback_recommendation(current, &policy, evidence)
        }
        SchedulerFeedbackWorkloadClass::MemoryPressure => {
            evidence.confidence_percentage = 85;
            evidence
                .reasons
                .push(SchedulerFeedbackReason::MemoryConservation);
            memory_feedback_recommendation(current, &policy, evidence)
        }
        SchedulerFeedbackWorkloadClass::InvalidMetrics
        | SchedulerFeedbackWorkloadClass::InsufficientMetrics => {
            empty_feedback_recommendation(evidence)
        }
    }
}

/// Observe-first autotuner for scheduler hot-path optimization.
pub struct SchedulerAutotuner {
    config: AutotunerConfig,
    last_observation: Option<HotPathObservation>,
    observation_history: Vec<HotPathObservation>,
    last_adjustment_time: Option<Instant>,
}

impl SchedulerAutotuner {
    /// Create a new scheduler autotuner with the given configuration.
    #[must_use]
    pub fn new(config: AutotunerConfig) -> Self {
        Self {
            config,
            last_observation: None,
            observation_history: Vec::new(),
            last_adjustment_time: None,
        }
    }

    /// Record a hot-path observation for analysis.
    pub fn observe(&mut self, observation: HotPathObservation) {
        self.observation_history.push(observation.clone());
        // Keep only recent observations to bound memory
        if self.observation_history.len() > 100 {
            // Remove oldest observations to maintain constant bound
            let excess = self.observation_history.len() - 100;
            self.observation_history.drain(0..excess);
        }
        self.last_observation = Some(observation);
    }

    /// Generate autotuning recommendations based on observed metrics.
    #[must_use]
    pub fn recommend(&self) -> Option<AutotunerRecommendation> {
        let last_obs = self.last_observation.as_ref()?;

        // Require minimum observation window
        if let Some(last_adj) = self.last_adjustment_time {
            let current_time = last_obs.timestamp?;
            // Protect against clock skew/inconsistent timestamps
            let elapsed = current_time
                .checked_duration_since(last_adj)
                .unwrap_or_else(|| Duration::from_secs(0));
            if elapsed < Duration::from_millis(self.config.observation_window_ms) {
                return None;
            }
        }

        let mut recommendation = AutotunerRecommendation {
            steal_batch_size: None,
            handoff_limit: None,
            adaptive_profile: None,
            confidence_percentage: 0,
            reasoning: String::new(),
        };

        let mut reasons = Vec::new();
        let mut confidence_factors = Vec::new();

        // Analyze steal batch sizing
        if self.config.enable_steal_tuning {
            if let Some((new_size, reason, conf)) = self.analyze_steal_batch_size(last_obs) {
                recommendation.steal_batch_size = Some(new_size);
                reasons.push(format!("Steal batch: {}", reason));
                confidence_factors.push(conf);
            }
        }

        // Analyze browser handoff tuning
        if self.config.enable_handoff_tuning {
            if let Some((new_limit, reason, conf)) = self.analyze_handoff_limit(last_obs) {
                recommendation.handoff_limit = Some(new_limit);
                reasons.push(format!("Handoff: {}", reason));
                confidence_factors.push(conf);
            }
        }

        // Analyze adaptive batch profile tuning
        if self.config.enable_batch_tuning {
            if let Some((profile, reason, conf)) = self.analyze_adaptive_profile(last_obs) {
                recommendation.adaptive_profile = Some(profile);
                reasons.push(format!("Adaptive: {}", reason));
                confidence_factors.push(conf);
            }
        }

        if reasons.is_empty() {
            return None;
        }

        recommendation.confidence_percentage = if confidence_factors.is_empty() {
            50 // Default moderate confidence
        } else {
            average_confidence(&confidence_factors)
        };

        recommendation.reasoning = reasons.join("; ");

        Some(recommendation)
    }

    /// Mark that autotuner recommendations were applied.
    pub fn mark_adjustment_applied(&mut self) {
        self.last_adjustment_time = Some(Instant::now());
    }

    /// Analyze steal batch size performance and recommend adjustments.
    fn analyze_steal_batch_size(&self, obs: &HotPathObservation) -> Option<(usize, String, u8)> {
        let current = obs.current_steal_batch_size;

        // High latency suggests oversized batches
        if obs.estimated_p95_latency_us > self.config.target_p95_latency_us.saturating_mul(2) {
            let new_size = (current / 2).max(1);
            return Some((
                new_size,
                format!(
                    "Reduce for latency: {}us > {}us",
                    obs.estimated_p95_latency_us, self.config.target_p95_latency_us
                ),
                80,
            ));
        }

        // High cancel dispatch ratio suggests smaller batches for responsiveness
        if obs.cancel_dispatch_ratio_bps > 3000 {
            let new_size = current.saturating_sub(self.config.max_batch_delta).max(1);
            return Some((
                new_size,
                format!(
                    "Reduce for cancel responsiveness: {}bps",
                    obs.cancel_dispatch_ratio_bps
                ),
                70,
            ));
        }

        // Low ready utilization with good latency suggests we can increase batch size
        // Keep a conservative upper bound while the tuner is observe-first.
        if obs.ready_dispatch_ratio_bps < 4000 // <40% ready work
            && obs.estimated_p95_latency_us < self.config.target_p95_latency_us / 2
            && current < 32
        {
            let new_size = current.saturating_add(self.config.max_batch_delta);
            return Some((
                new_size,
                format!(
                    "Increase for throughput: low ready util {}bps, good latency",
                    obs.ready_dispatch_ratio_bps
                ),
                60,
            ));
        }

        None
    }

    /// Analyze browser handoff limit and recommend adjustments.
    fn analyze_handoff_limit(&self, obs: &HotPathObservation) -> Option<(usize, String, u8)> {
        let current = obs.current_handoff_limit;

        // High ready dispatch suggests reducing handoff frequency for better batching
        if obs.ready_dispatch_ratio_bps > 7000 {
            let new_limit = current.saturating_mul(2).clamp(1, 64);
            if new_limit != current {
                return Some((
                    new_limit,
                    format!(
                        "Increase limit for ready batching: {}bps",
                        obs.ready_dispatch_ratio_bps
                    ),
                    65,
                ));
            }
        }

        // High cancel ratio suggests more frequent handoffs for responsiveness
        if obs.cancel_dispatch_ratio_bps > 2000 && current > 2 {
            let new_limit = (current / 2).max(1);
            if new_limit != current {
                return Some((
                    new_limit,
                    format!(
                        "Decrease limit for cancel responsiveness: {}bps",
                        obs.cancel_dispatch_ratio_bps
                    ),
                    75,
                ));
            }
        }

        None
    }

    /// Analyze adaptive batch profile and recommend adjustments.
    fn analyze_adaptive_profile(
        &self,
        obs: &HotPathObservation,
    ) -> Option<(AdaptiveBatchSizingProfile, String, u8)> {
        // This would contain logic to tune AdaptiveBatchSizingProfile parameters
        // based on scale-up events, cancel debt hits, and observed batch sizes

        // High cancel debt floor hits suggests lowering the threshold
        if obs.cancel_debt_floor_hits > 10 {
            let profile = AdaptiveBatchSizingProfile {
                enabled: true,
                min_batch_size: 1,
                max_batch_size: 16,
                scale_up_ready_depth: 8,
                scale_up_in_flight: 4,
                scale_up_claim_failures: 2,
                cancel_debt_floor: 2, // Lower threshold
                cooldown_steps: 5,
            };
            return Some((
                profile,
                format!(
                    "Lower cancel debt floor: {} hits",
                    obs.cancel_debt_floor_hits
                ),
                70,
            ));
        }

        // Few scale-up events with high ready load suggests more aggressive scaling
        if obs.adaptive_scale_up_events < 2 && obs.ready_dispatch_ratio_bps > 6000 {
            let profile = AdaptiveBatchSizingProfile {
                enabled: true,
                min_batch_size: 2,
                max_batch_size: 32,
                scale_up_ready_depth: 4, // Lower threshold for scaling
                scale_up_in_flight: 2,
                scale_up_claim_failures: 1,
                cancel_debt_floor: 5,
                cooldown_steps: 3,
            };
            return Some((
                profile,
                format!(
                    "Increase scaling aggressiveness: {} scale events, {}bps ready",
                    obs.adaptive_scale_up_events, obs.ready_dispatch_ratio_bps
                ),
                65,
            ));
        }

        None
    }

    /// Generate a dry-run pressure feedback recommendation.
    #[must_use]
    pub fn recommend_feedback(
        metrics: SchedulerFeedbackMetrics,
        current: SchedulerFeedbackCurrentKnobs,
        policy: SchedulerFeedbackPolicy,
    ) -> SchedulerFeedbackRecommendation {
        recommend_scheduler_feedback(metrics, current, policy)
    }
}

fn empty_feedback_recommendation(
    evidence: SchedulerFeedbackEvidence,
) -> SchedulerFeedbackRecommendation {
    SchedulerFeedbackRecommendation {
        dry_run: true,
        steal_batch_size: None,
        ready_batch_profile: None,
        global_queue_limit: None,
        placement_mode: None,
        blocking_pool_affinity: None,
        admission_thresholds: None,
        protected_invariants: SchedulerFeedbackProtectedInvariants::PRESERVED,
        evidence,
    }
}

fn burst_feedback_recommendation(
    current: SchedulerFeedbackCurrentKnobs,
    policy: &EffectiveFeedbackPolicy,
    mut evidence: SchedulerFeedbackEvidence,
) -> SchedulerFeedbackRecommendation {
    let worker_threads = current.worker_threads.max(1);
    let requested_steal = current.steal_batch_size.saturating_mul(2).max(2);
    let requested_global_queue = current
        .global_queue_limit
        .max(worker_threads.saturating_mul(4_096))
        .saturating_mul(if current.global_queue_limit == 0 {
            1
        } else {
            2
        });
    let requested_ready_profile = AdaptiveBatchSizingProfile {
        enabled: true,
        min_batch_size: policy.min_ready_batch_size,
        max_batch_size: current
            .steal_batch_size
            .saturating_mul(4)
            .max(policy.min_ready_batch_size),
        scale_up_ready_depth: worker_threads.saturating_mul(2).max(2),
        scale_up_in_flight: 2,
        scale_up_claim_failures: 1,
        cancel_debt_floor: 16,
        cooldown_steps: 4,
    };
    let requested_blocking_affinity = if current.cohort_count > 1 {
        BlockingPoolAffinityProfile::CohortBiased {
            local_queue_soft_limit: worker_threads.saturating_mul(128).max(1),
            spill_check_interval: 8,
        }
    } else {
        BlockingPoolAffinityProfile::Disabled
    };
    let requested_thresholds = SchedulerAdmissionControlThresholds {
        runnable_queue: current.admission_thresholds.runnable_queue + 0.05,
        blocking_pool: current.admission_thresholds.blocking_pool,
        channel_backlog: current.admission_thresholds.channel_backlog + 0.05,
        cleanup_debt: current.admission_thresholds.cleanup_debt,
        memory_budget: current.admission_thresholds.memory_budget,
    };

    feedback_recommendation_from_desired(
        current,
        policy,
        &mut evidence,
        DesiredFeedbackKnobs {
            steal_batch_size: Some(requested_steal),
            ready_batch_profile: Some(requested_ready_profile),
            global_queue_limit: Some(requested_global_queue),
            placement_mode: Some(SchedulerPlacementMode::ThroughputFirst),
            blocking_pool_affinity: Some(requested_blocking_affinity),
            admission_thresholds: Some(requested_thresholds),
        },
    )
}

fn cancellation_feedback_recommendation(
    current: SchedulerFeedbackCurrentKnobs,
    policy: &EffectiveFeedbackPolicy,
    mut evidence: SchedulerFeedbackEvidence,
) -> SchedulerFeedbackRecommendation {
    let worker_threads = current.worker_threads.max(1);
    let requested_global_queue =
        conservative_queue_limit(current.global_queue_limit, worker_threads);
    let requested_ready_profile = AdaptiveBatchSizingProfile {
        enabled: true,
        min_batch_size: policy.min_ready_batch_size,
        max_batch_size: current.steal_batch_size.max(policy.min_ready_batch_size),
        scale_up_ready_depth: worker_threads.saturating_mul(16).max(8),
        scale_up_in_flight: 4,
        scale_up_claim_failures: 2,
        cancel_debt_floor: 1,
        cooldown_steps: 1,
    };
    let requested_thresholds = SchedulerAdmissionControlThresholds {
        runnable_queue: current.admission_thresholds.runnable_queue - 0.05,
        blocking_pool: current.admission_thresholds.blocking_pool,
        channel_backlog: current.admission_thresholds.channel_backlog,
        cleanup_debt: current.admission_thresholds.cleanup_debt - 0.15,
        memory_budget: current.admission_thresholds.memory_budget,
    };

    feedback_recommendation_from_desired(
        current,
        policy,
        &mut evidence,
        DesiredFeedbackKnobs {
            steal_batch_size: Some(current.steal_batch_size / 2),
            ready_batch_profile: Some(requested_ready_profile),
            global_queue_limit: Some(requested_global_queue),
            placement_mode: Some(SchedulerPlacementMode::LatencyFirst),
            blocking_pool_affinity: Some(BlockingPoolAffinityProfile::Disabled),
            admission_thresholds: Some(requested_thresholds),
        },
    )
}

fn memory_feedback_recommendation(
    current: SchedulerFeedbackCurrentKnobs,
    policy: &EffectiveFeedbackPolicy,
    mut evidence: SchedulerFeedbackEvidence,
) -> SchedulerFeedbackRecommendation {
    let worker_threads = current.worker_threads.max(1);
    let requested_global_queue =
        conservative_queue_limit(current.global_queue_limit, worker_threads);
    let requested_ready_profile = AdaptiveBatchSizingProfile {
        enabled: true,
        min_batch_size: policy.min_ready_batch_size,
        max_batch_size: current.steal_batch_size.max(policy.min_ready_batch_size),
        scale_up_ready_depth: worker_threads.saturating_mul(32).max(16),
        scale_up_in_flight: 4,
        scale_up_claim_failures: 2,
        cancel_debt_floor: 2,
        cooldown_steps: 1,
    };
    let requested_thresholds = SchedulerAdmissionControlThresholds {
        runnable_queue: current.admission_thresholds.runnable_queue,
        blocking_pool: current.admission_thresholds.blocking_pool,
        channel_backlog: current.admission_thresholds.channel_backlog - 0.10,
        cleanup_debt: current.admission_thresholds.cleanup_debt,
        memory_budget: current.admission_thresholds.memory_budget - 0.15,
    };

    feedback_recommendation_from_desired(
        current,
        policy,
        &mut evidence,
        DesiredFeedbackKnobs {
            steal_batch_size: Some(current.steal_batch_size / 2),
            ready_batch_profile: Some(requested_ready_profile),
            global_queue_limit: Some(requested_global_queue),
            placement_mode: Some(SchedulerPlacementMode::LocalityFirst),
            blocking_pool_affinity: Some(BlockingPoolAffinityProfile::Disabled),
            admission_thresholds: Some(requested_thresholds),
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct DesiredFeedbackKnobs {
    steal_batch_size: Option<usize>,
    ready_batch_profile: Option<AdaptiveBatchSizingProfile>,
    global_queue_limit: Option<usize>,
    placement_mode: Option<SchedulerPlacementMode>,
    blocking_pool_affinity: Option<BlockingPoolAffinityProfile>,
    admission_thresholds: Option<SchedulerAdmissionControlThresholds>,
}

fn feedback_recommendation_from_desired(
    current: SchedulerFeedbackCurrentKnobs,
    policy: &EffectiveFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
    desired: DesiredFeedbackKnobs,
) -> SchedulerFeedbackRecommendation {
    let steal_batch_size = desired.steal_batch_size.and_then(|requested| {
        if !policy.eligible_knobs.steal_batch_size {
            record_disabled_knob(SchedulerFeedbackKnob::StealBatchSize, requested, evidence);
            return None;
        }
        let clamped = clamp_usize(
            SchedulerFeedbackKnob::StealBatchSize,
            requested,
            policy.min_steal_batch_size,
            policy.max_steal_batch_size,
            evidence,
        );
        (clamped != current.steal_batch_size).then_some(clamped)
    });

    let ready_batch_profile = desired.ready_batch_profile.and_then(|profile| {
        if !policy.eligible_knobs.ready_combiner_thresholds {
            record_disabled_profile(
                SchedulerFeedbackKnob::ReadyCombinerThresholds,
                "adaptive-ready-profile",
                evidence,
            );
            return None;
        }
        let clamped = clamp_ready_profile(profile, policy, evidence);
        (clamped != current.ready_batch_profile).then_some(clamped)
    });

    let global_queue_limit = desired.global_queue_limit.and_then(|requested| {
        if !policy.eligible_knobs.global_queue_limit {
            record_disabled_knob(SchedulerFeedbackKnob::GlobalQueueLimit, requested, evidence);
            return None;
        }
        let clamped = clamp_usize(
            SchedulerFeedbackKnob::GlobalQueueLimit,
            requested,
            policy.min_global_queue_limit,
            policy.max_global_queue_limit,
            evidence,
        );
        (clamped != current.global_queue_limit).then_some(clamped)
    });

    let placement_mode = desired.placement_mode.and_then(|mode| {
        if !policy.eligible_knobs.worker_cohort_policy {
            record_disabled_profile(
                SchedulerFeedbackKnob::WorkerCohortPolicy,
                mode.as_str(),
                evidence,
            );
            return None;
        }
        (mode != current.placement_mode).then_some(mode)
    });

    let blocking_pool_affinity = desired.blocking_pool_affinity.and_then(|profile| {
        if !policy.eligible_knobs.blocking_pool_affinity {
            record_disabled_profile(
                SchedulerFeedbackKnob::BlockingPoolAffinity,
                "blocking-affinity-profile",
                evidence,
            );
            return None;
        }
        (profile != current.blocking_pool_affinity).then_some(profile)
    });

    let admission_thresholds = desired.admission_thresholds.and_then(|thresholds| {
        if !policy.eligible_knobs.admission_control_thresholds {
            record_disabled_profile(
                SchedulerFeedbackKnob::AdmissionControlThresholds,
                "admission-thresholds",
                evidence,
            );
            return None;
        }
        let clamped = clamp_admission_thresholds(thresholds, policy, evidence);
        (clamped != current.admission_thresholds).then_some(clamped)
    });

    SchedulerFeedbackRecommendation {
        dry_run: true,
        steal_batch_size,
        ready_batch_profile,
        global_queue_limit,
        placement_mode,
        blocking_pool_affinity,
        admission_thresholds,
        protected_invariants: SchedulerFeedbackProtectedInvariants::PRESERVED,
        evidence: evidence.clone(),
    }
}

fn effective_feedback_policy(
    policy: SchedulerFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
) -> EffectiveFeedbackPolicy {
    let min_steal_batch_size = policy.min_steal_batch_size.max(1);
    let max_steal_batch_size = normalize_max_usize(
        SchedulerFeedbackKnob::StealBatchSize,
        policy.max_steal_batch_size,
        min_steal_batch_size,
        evidence,
    );
    let min_ready_batch_size = policy.min_ready_batch_size.max(1);
    let max_ready_batch_size = normalize_max_usize(
        SchedulerFeedbackKnob::ReadyCombinerThresholds,
        policy.max_ready_batch_size,
        min_ready_batch_size,
        evidence,
    );
    let min_global_queue_limit = policy.min_global_queue_limit.max(1);
    let max_global_queue_limit = normalize_max_usize(
        SchedulerFeedbackKnob::GlobalQueueLimit,
        policy.max_global_queue_limit,
        min_global_queue_limit,
        evidence,
    );
    let min_admission_threshold = normalize_policy_threshold(
        SchedulerFeedbackClampReason::BelowMinimum,
        policy.min_admission_threshold,
        SchedulerFeedbackPolicy::default().min_admission_threshold,
        evidence,
    );
    let requested_max_admission_threshold = normalize_policy_threshold(
        SchedulerFeedbackClampReason::AboveMaximum,
        policy.max_admission_threshold,
        SchedulerFeedbackPolicy::default().max_admission_threshold,
        evidence,
    );
    let max_admission_threshold = if requested_max_admission_threshold < min_admission_threshold {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::AdmissionControlThresholds,
            reason: SchedulerFeedbackClampReason::BelowMinimum,
            requested: format!("{requested_max_admission_threshold:.3}"),
            clamped: format!("{min_admission_threshold:.3}"),
        });
        min_admission_threshold
    } else {
        requested_max_admission_threshold
    };

    EffectiveFeedbackPolicy {
        eligible_knobs: policy.eligible_knobs,
        min_steal_batch_size,
        max_steal_batch_size,
        min_ready_batch_size,
        max_ready_batch_size,
        min_global_queue_limit,
        max_global_queue_limit,
        min_admission_threshold,
        max_admission_threshold,
        burst_pressure_threshold: sanitize_policy_pressure(
            policy.burst_pressure_threshold,
            SchedulerFeedbackPolicy::default().burst_pressure_threshold,
            evidence,
        ),
        cancellation_pressure_threshold: sanitize_policy_pressure(
            policy.cancellation_pressure_threshold,
            SchedulerFeedbackPolicy::default().cancellation_pressure_threshold,
            evidence,
        ),
        memory_pressure_threshold: sanitize_policy_pressure(
            policy.memory_pressure_threshold,
            SchedulerFeedbackPolicy::default().memory_pressure_threshold,
            evidence,
        ),
    }
}

fn normalized_current_knobs(
    mut current: SchedulerFeedbackCurrentKnobs,
    policy: &EffectiveFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
) -> SchedulerFeedbackCurrentKnobs {
    if current.worker_threads == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::WorkerCohortPolicy,
            SchedulerFeedbackClampReason::BelowMinimum,
            0,
            1,
            evidence,
        );
        current.worker_threads = 1;
    }
    if current.cohort_count == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::WorkerCohortPolicy,
            SchedulerFeedbackClampReason::BelowMinimum,
            0,
            1,
            evidence,
        );
        current.cohort_count = 1;
    }
    current.steal_batch_size = clamp_usize(
        SchedulerFeedbackKnob::StealBatchSize,
        current.steal_batch_size.max(1),
        policy.min_steal_batch_size,
        policy.max_steal_batch_size,
        evidence,
    );
    current.ready_batch_profile =
        normalize_current_ready_profile(current.ready_batch_profile, policy, evidence);
    current.admission_thresholds =
        clamp_admission_thresholds(current.admission_thresholds, policy, evidence);
    current
}

fn sanitize_feedback_metrics(
    metrics: SchedulerFeedbackMetrics,
    evidence: &mut SchedulerFeedbackEvidence,
) -> SanitizedFeedbackMetrics {
    SanitizedFeedbackMetrics {
        runnable_queue_pressure: sanitize_metric(
            SchedulerFeedbackSignal::RunnableQueue,
            metrics.runnable_queue_pressure,
            evidence,
        ),
        ready_queue_pressure: sanitize_metric(
            SchedulerFeedbackSignal::ReadyQueue,
            metrics.ready_queue_pressure,
            evidence,
        ),
        blocking_pool_pressure: sanitize_metric(
            SchedulerFeedbackSignal::BlockingPool,
            metrics.blocking_pool_pressure,
            evidence,
        ),
        channel_backlog_pressure: sanitize_metric(
            SchedulerFeedbackSignal::ChannelBacklog,
            metrics.channel_backlog_pressure,
            evidence,
        ),
        cancellation_pressure: sanitize_metric(
            SchedulerFeedbackSignal::Cancellation,
            metrics.cancellation_pressure,
            evidence,
        ),
        cleanup_debt_pressure: sanitize_metric(
            SchedulerFeedbackSignal::CleanupDebt,
            metrics.cleanup_debt_pressure,
            evidence,
        ),
        memory_budget_pressure: sanitize_metric(
            SchedulerFeedbackSignal::MemoryBudget,
            metrics.memory_budget_pressure,
            evidence,
        ),
        p95_dispatch_latency_us: metrics.p95_dispatch_latency_us,
        p99_dispatch_latency_us: metrics.p99_dispatch_latency_us,
    }
}

fn sanitize_metric(
    signal: SchedulerFeedbackSignal,
    value: Option<f64>,
    evidence: &mut SchedulerFeedbackEvidence,
) -> Option<f64> {
    let Some(value) = value else {
        evidence.missing_signals.push(signal);
        return None;
    };
    if !value.is_finite() || value.is_sign_negative() {
        evidence.invalid_signals.push(signal);
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::PressureMetric,
            reason: SchedulerFeedbackClampReason::InvalidMetric,
            requested: metric_value(value),
            clamped: "unavailable".to_string(),
        });
        return None;
    }
    if value > 2.0 {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::PressureMetric,
            reason: SchedulerFeedbackClampReason::AboveMaximum,
            requested: metric_value(value),
            clamped: "2.000".to_string(),
        });
        return Some(2.0);
    }
    Some(value)
}

fn max_present<const N: usize>(values: [Option<f64>; N]) -> Option<f64> {
    values.into_iter().flatten().fold(None, |max, value| {
        Some(max.map_or(value, |current| current.max(value)))
    })
}

fn conservative_queue_limit(current_limit: usize, worker_threads: usize) -> usize {
    if current_limit == 0 {
        return worker_threads.max(1).saturating_mul(2_048);
    }
    (current_limit / 2).max(1)
}

fn normalize_current_ready_profile(
    profile: AdaptiveBatchSizingProfile,
    policy: &EffectiveFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
) -> AdaptiveBatchSizingProfile {
    if profile.enabled {
        return clamp_ready_profile(profile, policy, evidence);
    }
    profile
}

fn clamp_ready_profile(
    mut profile: AdaptiveBatchSizingProfile,
    policy: &EffectiveFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
) -> AdaptiveBatchSizingProfile {
    if !profile.enabled {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::ReadyCombinerThresholds,
            reason: SchedulerFeedbackClampReason::WouldDisableProtectedInvariant,
            requested: "disabled".to_string(),
            clamped: "enabled".to_string(),
        });
        profile.enabled = true;
    }
    profile.min_batch_size = clamp_usize(
        SchedulerFeedbackKnob::ReadyCombinerThresholds,
        profile.min_batch_size,
        policy.min_ready_batch_size,
        policy.max_ready_batch_size,
        evidence,
    );
    profile.max_batch_size = clamp_usize(
        SchedulerFeedbackKnob::ReadyCombinerThresholds,
        profile.max_batch_size.max(profile.min_batch_size),
        profile.min_batch_size,
        policy.max_ready_batch_size,
        evidence,
    );
    if profile.scale_up_ready_depth == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::ReadyCombinerThresholds,
            SchedulerFeedbackClampReason::BelowMinimum,
            0,
            1,
            evidence,
        );
        profile.scale_up_ready_depth = 1;
    }
    if profile.scale_up_in_flight == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::ReadyCombinerThresholds,
            SchedulerFeedbackClampReason::BelowMinimum,
            0,
            1,
            evidence,
        );
        profile.scale_up_in_flight = 1;
    }
    if profile.scale_up_claim_failures == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::ReadyCombinerThresholds,
            SchedulerFeedbackClampReason::BelowMinimum,
            0,
            1,
            evidence,
        );
        profile.scale_up_claim_failures = 1;
    }
    if profile.cancel_debt_floor == 0 {
        record_usize_clamp(
            SchedulerFeedbackKnob::ReadyCombinerThresholds,
            SchedulerFeedbackClampReason::WouldDisableProtectedInvariant,
            0,
            1,
            evidence,
        );
        profile.cancel_debt_floor = 1;
    }
    profile
}

fn clamp_admission_thresholds(
    thresholds: SchedulerAdmissionControlThresholds,
    policy: &EffectiveFeedbackPolicy,
    evidence: &mut SchedulerFeedbackEvidence,
) -> SchedulerAdmissionControlThresholds {
    SchedulerAdmissionControlThresholds {
        runnable_queue: clamp_threshold(
            thresholds.runnable_queue,
            policy.min_admission_threshold,
            policy.max_admission_threshold,
            evidence,
        ),
        blocking_pool: clamp_threshold(
            thresholds.blocking_pool,
            policy.min_admission_threshold,
            policy.max_admission_threshold,
            evidence,
        ),
        channel_backlog: clamp_threshold(
            thresholds.channel_backlog,
            policy.min_admission_threshold,
            policy.max_admission_threshold,
            evidence,
        ),
        cleanup_debt: clamp_threshold(
            thresholds.cleanup_debt,
            policy.min_admission_threshold,
            policy.max_admission_threshold,
            evidence,
        ),
        memory_budget: clamp_threshold(
            thresholds.memory_budget,
            policy.min_admission_threshold,
            policy.max_admission_threshold,
            evidence,
        ),
    }
}

fn clamp_threshold(
    requested: f64,
    min: f64,
    max: f64,
    evidence: &mut SchedulerFeedbackEvidence,
) -> f64 {
    if !requested.is_finite() {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::AdmissionControlThresholds,
            reason: SchedulerFeedbackClampReason::InvalidMetric,
            requested: metric_value(requested),
            clamped: format!("{min:.3}"),
        });
        return min;
    }
    if requested < min {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::AdmissionControlThresholds,
            reason: SchedulerFeedbackClampReason::BelowMinimum,
            requested: format!("{requested:.3}"),
            clamped: format!("{min:.3}"),
        });
        return min;
    }
    if requested > max {
        evidence.clamps.push(SchedulerFeedbackClamp {
            knob: SchedulerFeedbackKnob::AdmissionControlThresholds,
            reason: SchedulerFeedbackClampReason::AboveMaximum,
            requested: format!("{requested:.3}"),
            clamped: format!("{max:.3}"),
        });
        return max;
    }
    requested
}

fn normalize_max_usize(
    knob: SchedulerFeedbackKnob,
    requested_max: usize,
    minimum: usize,
    evidence: &mut SchedulerFeedbackEvidence,
) -> usize {
    if requested_max >= minimum {
        return requested_max;
    }
    record_usize_clamp(
        knob,
        SchedulerFeedbackClampReason::BelowMinimum,
        requested_max,
        minimum,
        evidence,
    );
    minimum
}

fn clamp_usize(
    knob: SchedulerFeedbackKnob,
    requested: usize,
    min: usize,
    max: usize,
    evidence: &mut SchedulerFeedbackEvidence,
) -> usize {
    if requested < min {
        record_usize_clamp(
            knob,
            SchedulerFeedbackClampReason::BelowMinimum,
            requested,
            min,
            evidence,
        );
        return min;
    }
    if requested > max {
        record_usize_clamp(
            knob,
            SchedulerFeedbackClampReason::AboveMaximum,
            requested,
            max,
            evidence,
        );
        return max;
    }
    requested
}

fn normalize_policy_threshold(
    reason: SchedulerFeedbackClampReason,
    requested: f64,
    fallback: f64,
    evidence: &mut SchedulerFeedbackEvidence,
) -> f64 {
    if requested.is_finite() && (0.0..1.0).contains(&requested) {
        return requested;
    }
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob: SchedulerFeedbackKnob::AdmissionControlThresholds,
        reason,
        requested: metric_value(requested),
        clamped: format!("{fallback:.3}"),
    });
    fallback
}

fn sanitize_policy_pressure(
    requested: f64,
    fallback: f64,
    evidence: &mut SchedulerFeedbackEvidence,
) -> f64 {
    if requested.is_finite() && (0.0..=1.0).contains(&requested) {
        return requested;
    }
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob: SchedulerFeedbackKnob::PressureMetric,
        reason: SchedulerFeedbackClampReason::InvalidMetric,
        requested: metric_value(requested),
        clamped: format!("{fallback:.3}"),
    });
    fallback
}

fn record_usize_clamp(
    knob: SchedulerFeedbackKnob,
    reason: SchedulerFeedbackClampReason,
    requested: usize,
    clamped: usize,
    evidence: &mut SchedulerFeedbackEvidence,
) {
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob,
        reason,
        requested: requested.to_string(),
        clamped: clamped.to_string(),
    });
}

fn record_disabled_knob(
    knob: SchedulerFeedbackKnob,
    requested: usize,
    evidence: &mut SchedulerFeedbackEvidence,
) {
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob,
        reason: SchedulerFeedbackClampReason::KnobDisabled,
        requested: requested.to_string(),
        clamped: "unchanged".to_string(),
    });
}

fn record_disabled_profile(
    knob: SchedulerFeedbackKnob,
    requested: &str,
    evidence: &mut SchedulerFeedbackEvidence,
) {
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob,
        reason: SchedulerFeedbackClampReason::KnobDisabled,
        requested: requested.to_string(),
        clamped: "unchanged".to_string(),
    });
}

fn record_contradictory_throughput_suppression(evidence: &mut SchedulerFeedbackEvidence) {
    evidence
        .reasons
        .push(SchedulerFeedbackReason::ContradictoryThroughputSuppressed);
    evidence.clamps.push(SchedulerFeedbackClamp {
        knob: SchedulerFeedbackKnob::ReadyCombinerThresholds,
        reason: SchedulerFeedbackClampReason::ContradictoryPressure,
        requested: "throughput-expansion".to_string(),
        clamped: "conservative-profile".to_string(),
    });
}

fn pressure_to_bps(pressure: f64) -> u16 {
    let pressure = pressure.clamp(0.0, 1.0);
    (pressure * 10_000.0).round() as u16
}

fn metric_value(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        value.to_string()
    } else {
        format!("{value:.3}")
    }
}

fn average_confidence(confidence_factors: &[u8]) -> u8 {
    let sum: u16 = confidence_factors
        .iter()
        .map(|confidence| u16::from(*confidence))
        .sum();
    let count = u16::try_from(confidence_factors.len()).unwrap_or(1);
    u8::try_from((sum / count).min(100)).unwrap_or(100)
}

/// Extract hot-path observation from scheduler metrics.
#[must_use]
pub fn extract_observation(metrics: &PreemptionMetrics) -> HotPathObservation {
    let total_dispatches = metrics
        .cancel_dispatches
        .saturating_add(metrics.timed_dispatches)
        .saturating_add(metrics.ready_dispatches);

    let cancel_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.cancel_dispatches, total_dispatches)
    } else {
        0
    };

    let timed_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.timed_dispatches, total_dispatches)
    } else {
        0
    };

    let ready_ratio = if total_dispatches > 0 {
        ratio_bps(metrics.ready_dispatches, total_dispatches)
    } else {
        0
    };

    let mean_batch_size = if metrics.global_ready_batch_drains > 0 {
        metrics.global_ready_batch_tasks as f64 / metrics.global_ready_batch_drains as f64
    } else {
        0.0
    };

    let estimated_latency = metrics.avg_timeout_park_nanos() / 1000;

    HotPathObservation {
        timestamp: Some(Instant::now()),
        cancel_dispatch_ratio_bps: cancel_ratio,
        timed_dispatch_ratio_bps: timed_ratio,
        ready_dispatch_ratio_bps: ready_ratio,
        mean_ready_batch_size: mean_batch_size,
        current_steal_batch_size: 8, // Would be extracted from scheduler state
        current_handoff_limit: 0,    // Would be extracted from scheduler state
        adaptive_scale_up_events: metrics.adaptive_batch_scale_up_events,
        cancel_debt_floor_hits: metrics.adaptive_batch_cancel_floor_hits,
        estimated_p95_latency_us: estimated_latency,
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let raw = (u128::from(numerator)
        .saturating_mul(10_000)
        .saturating_div(u128::from(denominator)))
    .min(10_000);
    raw as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autotuner_reduces_batch_size_for_high_latency() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // 5ms - much higher than 1ms target
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() < 16);
        assert!(recommendation.reasoning.contains("latency"));
    }

    #[test]
    fn autotuner_reduces_batch_size_for_high_cancel_load() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            cancel_dispatch_ratio_bps: 4000, // 40% cancel work
            current_steal_batch_size: 12,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() < 12);
        assert!(recommendation.reasoning.contains("cancel responsiveness"));
    }

    #[test]
    fn autotuner_increases_batch_size_for_low_utilization() {
        let mut autotuner = SchedulerAutotuner::new(AutotunerConfig::default());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            ready_dispatch_ratio_bps: 2000, // 20% ready work - low utilization
            estimated_p95_latency_us: 200,  // Good latency
            current_steal_batch_size: 4,
            ..Default::default()
        };

        autotuner.observe(obs);
        let recommendation = autotuner.recommend().unwrap(); // ubs:ignore - test oracle

        assert!(recommendation.steal_batch_size.unwrap() > 4);
        assert!(recommendation.reasoning.contains("throughput"));
    }

    #[test]
    fn autotuner_respects_observation_window() {
        let config = AutotunerConfig {
            observation_window_ms: 5000, // 5 second window
            ..Default::default()
        };
        let mut autotuner = SchedulerAutotuner::new(config);

        autotuner.last_adjustment_time = Some(Instant::now());

        let obs = HotPathObservation {
            timestamp: Some(Instant::now()),
            estimated_p95_latency_us: 5000, // Should trigger recommendation
            current_steal_batch_size: 16,
            ..Default::default()
        };

        autotuner.observe(obs);

        // Should not recommend due to recent adjustment
        assert!(autotuner.recommend().is_none());
    }

    #[test]
    fn extract_observation_from_metrics() {
        let mut metrics = PreemptionMetrics::default();
        metrics.cancel_dispatches = 20;
        metrics.ready_dispatches = 80;
        metrics.global_ready_batch_drains = 10;
        metrics.global_ready_batch_tasks = 50;

        let obs = extract_observation(&metrics);

        assert_eq!(obs.cancel_dispatch_ratio_bps, 2000); // 20%
        assert_eq!(obs.ready_dispatch_ratio_bps, 8000); // 80%
        assert_eq!(obs.mean_ready_batch_size, 5.0); // 50/10
    }

    fn stable_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.30),
            ready_queue_pressure: Some(0.35),
            blocking_pool_pressure: Some(0.20),
            channel_backlog_pressure: Some(0.25),
            cancellation_pressure: Some(0.10),
            cleanup_debt_pressure: Some(0.10),
            memory_budget_pressure: Some(0.40),
            p95_dispatch_latency_us: Some(500),
            p99_dispatch_latency_us: Some(900),
        }
    }

    fn burst_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.91),
            ready_queue_pressure: Some(0.88),
            blocking_pool_pressure: Some(0.62),
            channel_backlog_pressure: Some(0.86),
            cancellation_pressure: Some(0.18),
            cleanup_debt_pressure: Some(0.15),
            memory_budget_pressure: Some(0.52),
            p95_dispatch_latency_us: Some(1_800),
            p99_dispatch_latency_us: Some(2_700),
        }
    }

    fn cancellation_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.70),
            ready_queue_pressure: Some(0.66),
            blocking_pool_pressure: Some(0.55),
            channel_backlog_pressure: Some(0.42),
            cancellation_pressure: Some(0.76),
            cleanup_debt_pressure: Some(0.72),
            memory_budget_pressure: Some(0.48),
            p95_dispatch_latency_us: Some(1_400),
            p99_dispatch_latency_us: Some(3_000),
        }
    }

    fn memory_feedback_metrics() -> SchedulerFeedbackMetrics {
        SchedulerFeedbackMetrics {
            runnable_queue_pressure: Some(0.68),
            ready_queue_pressure: Some(0.64),
            blocking_pool_pressure: Some(0.50),
            channel_backlog_pressure: Some(0.57),
            cancellation_pressure: Some(0.12),
            cleanup_debt_pressure: Some(0.14),
            memory_budget_pressure: Some(0.91),
            p95_dispatch_latency_us: Some(1_100),
            p99_dispatch_latency_us: Some(1_900),
        }
    }

    fn feedback_current_knobs() -> SchedulerFeedbackCurrentKnobs {
        SchedulerFeedbackCurrentKnobs {
            worker_threads: 8,
            cohort_count: 2,
            steal_batch_size: 16,
            global_queue_limit: 8_192,
            placement_mode: SchedulerPlacementMode::LocalityFirst,
            ..SchedulerFeedbackCurrentKnobs::default()
        }
    }

    fn assert_invariants_preserved(recommendation: &SchedulerFeedbackRecommendation) {
        assert!(recommendation.dry_run);
        assert!(recommendation.protected_invariants.cancellation_drain);
        assert!(recommendation.protected_invariants.loser_drain);
        assert!(recommendation.protected_invariants.obligation_cleanup);
        assert!(recommendation.protected_invariants.region_quiescence);
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::ProtectedInvariantsPinned)
        );
    }

    #[test]
    fn scheduler_feedback_stable_workload_observe_only() {
        let recommendation = recommend_scheduler_feedback(
            stable_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::Stable
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::StableNoChange)
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_burst_workload_recommends_throughput_knobs() {
        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::Burst
        );
        assert_eq!(recommendation.steal_batch_size, Some(32));
        assert_eq!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::ThroughputFirst)
        );
        assert!(recommendation.global_queue_limit.unwrap_or(0) > 8_192);
        assert!(recommendation.ready_batch_profile.unwrap().enabled);
        assert!(matches!(
            recommendation.blocking_pool_affinity,
            Some(BlockingPoolAffinityProfile::CohortBiased { .. })
        ));
        assert!(recommendation.admission_thresholds.is_some());
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_cancellation_heavy_workload_prioritizes_responsiveness() {
        let recommendation = recommend_scheduler_feedback(
            cancellation_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::CancellationHeavy
        );
        assert_eq!(recommendation.steal_batch_size, Some(8));
        assert_eq!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::LatencyFirst)
        );
        let profile = recommendation.ready_batch_profile.unwrap();
        assert_eq!(profile.cancel_debt_floor, 1);
        assert!(profile.scale_up_ready_depth > feedback_current_knobs().worker_threads);
        let thresholds = recommendation.admission_thresholds.unwrap();
        assert!(
            thresholds.cleanup_debt < feedback_current_knobs().admission_thresholds.cleanup_debt
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_memory_pressure_conserves_queue_growth() {
        let recommendation = recommend_scheduler_feedback(
            memory_feedback_metrics(),
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::MemoryPressure
        );
        assert_eq!(recommendation.steal_batch_size, Some(8));
        assert!(recommendation.global_queue_limit.unwrap_or(usize::MAX) < 8_192);
        let thresholds = recommendation.admission_thresholds.unwrap();
        assert!(
            thresholds.memory_budget < feedback_current_knobs().admission_thresholds.memory_budget
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_invalid_metrics_stay_observe_only_with_evidence() {
        let mut metrics = stable_feedback_metrics();
        metrics.runnable_queue_pressure = Some(f64::NAN);
        metrics.memory_budget_pressure = Some(-0.1);

        let recommendation = SchedulerAutotuner::recommend_feedback(
            metrics,
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::InvalidMetrics
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .invalid_signals
                .contains(&SchedulerFeedbackSignal::RunnableQueue)
        );
        assert!(
            recommendation
                .evidence
                .invalid_signals
                .contains(&SchedulerFeedbackSignal::MemoryBudget)
        );
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::PressureMetric
                && clamp.reason == SchedulerFeedbackClampReason::InvalidMetric
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_missing_metrics_stay_observe_only() {
        let recommendation = recommend_scheduler_feedback(
            SchedulerFeedbackMetrics {
                runnable_queue_pressure: Some(0.90),
                ..SchedulerFeedbackMetrics::default()
            },
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::InsufficientMetrics
        );
        assert!(!recommendation.has_knob_changes());
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::MissingMetricsObserveOnly)
        );
        assert!(recommendation.evidence.missing_signals.len() >= 4);
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_clamps_unsafe_recommendations() {
        let policy = SchedulerFeedbackPolicy {
            max_steal_batch_size: 24,
            max_ready_batch_size: 24,
            max_global_queue_limit: 1_024,
            max_admission_threshold: 0.82,
            ..SchedulerFeedbackPolicy::default()
        };

        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            policy,
        );

        assert_eq!(recommendation.steal_batch_size, Some(24));
        assert_eq!(recommendation.global_queue_limit, Some(1_024));
        assert!(
            recommendation
                .ready_batch_profile
                .is_some_and(|profile| profile.max_batch_size == 24)
        );
        assert!(
            recommendation
                .admission_thresholds
                .is_some_and(|thresholds| thresholds.runnable_queue <= 0.82)
        );
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::StealBatchSize
                && clamp.reason == SchedulerFeedbackClampReason::AboveMaximum
        }));
        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::GlobalQueueLimit
                && clamp.reason == SchedulerFeedbackClampReason::AboveMaximum
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_records_inverted_admission_threshold_policy() {
        let policy = SchedulerFeedbackPolicy {
            min_admission_threshold: 0.90,
            max_admission_threshold: 0.20,
            ..SchedulerFeedbackPolicy::default()
        };

        let recommendation = recommend_scheduler_feedback(
            burst_feedback_metrics(),
            feedback_current_knobs(),
            policy,
        );

        assert!(recommendation.evidence.clamps.iter().any(|clamp| {
            clamp.knob == SchedulerFeedbackKnob::AdmissionControlThresholds
                && clamp.reason == SchedulerFeedbackClampReason::BelowMinimum
                && clamp.requested == "0.200"
                && clamp.clamped == "0.900"
        }));
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_contradictory_pressure_suppresses_throughput_profile() {
        let mut metrics = burst_feedback_metrics();
        metrics.cancellation_pressure = Some(0.82);
        metrics.cleanup_debt_pressure = Some(0.78);

        let recommendation = recommend_scheduler_feedback(
            metrics,
            feedback_current_knobs(),
            SchedulerFeedbackPolicy::default(),
        );

        assert_eq!(
            recommendation.evidence.workload_class,
            SchedulerFeedbackWorkloadClass::CancellationHeavy
        );
        assert_ne!(
            recommendation.placement_mode,
            Some(SchedulerPlacementMode::ThroughputFirst)
        );
        assert!(
            recommendation
                .evidence
                .reasons
                .contains(&SchedulerFeedbackReason::ContradictoryThroughputSuppressed)
        );
        assert!(
            recommendation.evidence.clamps.iter().any(|clamp| {
                clamp.reason == SchedulerFeedbackClampReason::ContradictoryPressure
            })
        );
        assert_invariants_preserved(&recommendation);
    }

    #[test]
    fn scheduler_feedback_preserves_protected_invariants_across_scenarios() {
        let scenarios = [
            stable_feedback_metrics(),
            burst_feedback_metrics(),
            cancellation_feedback_metrics(),
            memory_feedback_metrics(),
            SchedulerFeedbackMetrics::default(),
        ];

        for metrics in scenarios {
            let recommendation = recommend_scheduler_feedback(
                metrics,
                feedback_current_knobs(),
                SchedulerFeedbackPolicy::default(),
            );
            assert_invariants_preserved(&recommendation);
        }
    }
}
