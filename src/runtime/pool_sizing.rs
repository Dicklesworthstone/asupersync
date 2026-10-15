//! Deterministic queueing-theoretic pool sizing substrate.
//!
//! This module is pure policy/math. It does not resize a blocking pool, open or
//! close database connections, spawn background workers, sample wall-clock time,
//! or emit logs. Runtime integrations feed already-collected observations and
//! decide whether to expose the resulting recommendation as advisory evidence
//! or apply it through an explicit managed-mode controller.
//!
//! # Galaxy-brain card
//!
//! A pool is a queueing system. The two live values that matter first are:
//!
//! ```text
//! offered_load R = arrival_rate_per_sec * mean_service_seconds
//! utilization   = R / k
//! ```
//!
//! `R = 6.4` means the observed workload would keep 6.4 workers busy forever.
//! A fixed "min 4, max 32" guess hides that fact; this module reports it. The
//! recommendation starts from square-root staffing,
//! `k ~= R + beta * sqrt(R)`, then verifies each candidate with an Erlang-C
//! wait-probability calculation and an Allen-Cunneen style service-variability
//! multiplier. The approximation boundary is intentional: this is an operator
//! and controller input, not a proof of real-host throughput.

/// Fixed-point scale used for rates, probabilities, utilization, and offered load.
pub const POOL_SIZING_SCALE: u64 = 1_000_000;

const POOL_SIZING_SCALE_U128: u128 = POOL_SIZING_SCALE as u128;
const BPS_SCALE: u128 = 10_000;
const DEFAULT_ESTIMATOR_ALPHA_PPM: u32 = 200_000;
const DEFAULT_HYSTERESIS_BPS: u16 = 2_000;
const DEFAULT_RESIZE_CADENCE_EPOCHS: u64 = 1;

/// Runtime behavior mode for a pool-sizing policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PoolSizingMode {
    /// Recommendation-only mode. Integrations expose the result but do not resize.
    #[default]
    Advisory,
    /// Opt-in mode. Integrations may apply resize decisions after hysteresis/cadence gates.
    Managed,
}

/// Operator or controller target used to select a pool size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSizingTarget {
    /// Bound the approximated probability that an arriving job must wait.
    MaxWaitProbabilityPpm(u32),
    /// Bound the approximated mean queue wait.
    MaxMeanWaitMicros(u64),
}

impl PoolSizingTarget {
    /// Conservative default: at most ten percent of arrivals should queue.
    #[must_use]
    pub const fn conservative_wait_probability() -> Self {
        Self::MaxWaitProbabilityPpm(100_000)
    }

    fn wait_probability_ppm(self) -> Option<u32> {
        match self {
            Self::MaxWaitProbabilityPpm(value) => Some(value.min(POOL_SIZING_SCALE as u32)),
            Self::MaxMeanWaitMicros(_) => None,
        }
    }

    fn is_met_by(self, metrics: PoolSizingCandidateMetrics) -> bool {
        match self {
            Self::MaxWaitProbabilityPpm(limit) => {
                metrics.wait_probability_ppm <= limit.min(POOL_SIZING_SCALE as u32)
            }
            Self::MaxMeanWaitMicros(limit) => metrics.mean_wait_micros <= limit,
        }
    }
}

/// Hard bounds applied to every recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingBounds {
    /// Smallest allowed size. A zero floor is valid for disabled/idle pools.
    pub min_size: usize,
    /// Largest allowed size.
    pub max_size: usize,
}

impl PoolSizingBounds {
    /// Build pool-size bounds. If `max_size < min_size`, the ceiling is clamped
    /// up to the floor so callers cannot create an inverted range.
    #[must_use]
    pub const fn new(min_size: usize, max_size: usize) -> Self {
        let max_size = if max_size < min_size {
            min_size
        } else {
            max_size
        };
        Self { min_size, max_size }
    }
}

/// EWMA-derived workload estimate for one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolWorkloadEstimate {
    /// Arrival rate in jobs/sec, scaled by [`POOL_SIZING_SCALE`].
    pub arrival_rate_per_sec_ppm: u64,
    /// Mean service duration in microseconds.
    pub service_time_mean_micros: u64,
    /// Service-time variance in square microseconds.
    pub service_time_variance_micros2: u128,
}

impl PoolWorkloadEstimate {
    /// Build an estimate from fixed-point arrival rate and service moments.
    #[must_use]
    pub const fn new(
        arrival_rate_per_sec_ppm: u64,
        service_time_mean_micros: u64,
        service_time_variance_micros2: u128,
    ) -> Self {
        Self {
            arrival_rate_per_sec_ppm,
            service_time_mean_micros,
            service_time_variance_micros2,
        }
    }

    /// Observed offered load, scaled by [`POOL_SIZING_SCALE`].
    #[must_use]
    pub fn offered_load_ppm(self) -> u64 {
        let load = u128::from(self.arrival_rate_per_sec_ppm)
            .saturating_mul(u128::from(self.service_time_mean_micros))
            / POOL_SIZING_SCALE_U128;
        clamp_u128_to_u64(load)
    }

    /// Squared coefficient of variation, scaled by [`POOL_SIZING_SCALE`].
    #[must_use]
    pub fn service_cv2_ppm(self) -> u64 {
        if self.service_time_mean_micros == 0 {
            return 0;
        }
        let mean_squared = u128::from(self.service_time_mean_micros)
            .saturating_mul(u128::from(self.service_time_mean_micros));
        if mean_squared == 0 {
            return 0;
        }
        let cv2 = self
            .service_time_variance_micros2
            .saturating_mul(POOL_SIZING_SCALE_U128)
            / mean_squared;
        clamp_u128_to_u64(cv2)
    }

    fn service_variability_bps(self) -> u64 {
        let cv2_bps = self.service_cv2_ppm() / 100;
        let allen_cunneen = (10_000_u64.saturating_add(cv2_bps)) / 2;
        allen_cunneen.max(10_000)
    }

    fn has_load(self) -> bool {
        self.arrival_rate_per_sec_ppm > 0 && self.service_time_mean_micros > 0
    }
}

/// Raw observation batch for deterministic EWMA estimation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingObservation {
    /// Observation window duration in microseconds.
    pub elapsed_micros: u64,
    /// Number of arrivals admitted to the pool during the window.
    pub arrivals: u64,
    /// Number of completed jobs with service samples during the window.
    pub completions: u64,
    /// Sum of sampled service times in microseconds.
    pub total_service_micros: u128,
    /// Sum of squared sampled service times in square microseconds.
    pub total_service_micros_squared: u128,
}

impl PoolSizingObservation {
    /// Build an observation batch.
    #[must_use]
    pub const fn new(
        elapsed_micros: u64,
        arrivals: u64,
        completions: u64,
        total_service_micros: u128,
        total_service_micros_squared: u128,
    ) -> Self {
        Self {
            elapsed_micros,
            arrivals,
            completions,
            total_service_micros,
            total_service_micros_squared,
        }
    }
}

/// Deterministic EWMA estimator for pool arrival and service moments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSizingEstimator {
    alpha_ppm: u32,
    arrival_rate_per_sec_ppm: Option<u64>,
    service_time_mean_micros: Option<u64>,
    service_time_second_moment_micros2: Option<u128>,
    sample_count: u64,
}

impl Default for PoolSizingEstimator {
    fn default() -> Self {
        Self::new(DEFAULT_ESTIMATOR_ALPHA_PPM)
    }
}

impl PoolSizingEstimator {
    /// Build an estimator with an EWMA alpha in parts per million.
    ///
    /// `alpha_ppm = 1_000_000` means "use the latest sample"; zero is clamped
    /// to one part per million so future observations can still move the state.
    #[must_use]
    pub const fn new(alpha_ppm: u32) -> Self {
        let alpha_ppm = if alpha_ppm == 0 {
            1
        } else if alpha_ppm > POOL_SIZING_SCALE as u32 {
            POOL_SIZING_SCALE as u32
        } else {
            alpha_ppm
        };
        Self {
            alpha_ppm,
            arrival_rate_per_sec_ppm: None,
            service_time_mean_micros: None,
            service_time_second_moment_micros2: None,
            sample_count: 0,
        }
    }

    /// Number of accepted observation batches.
    #[must_use]
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Drop all accumulated EWMA state while preserving the configured alpha.
    ///
    /// This is the handoff point for future regime-change detectors: after a
    /// confirmed workload phase change, integrations can clear stale learning
    /// before feeding the first observation from the new regime. The next
    /// positive observation is then accepted as the fresh baseline instead of
    /// being blended with the old regime.
    pub fn reset(&mut self) {
        self.arrival_rate_per_sec_ppm = None;
        self.service_time_mean_micros = None;
        self.service_time_second_moment_micros2 = None;
        self.sample_count = 0;
    }

    /// Fold one observation batch into the EWMA state.
    ///
    /// Returns the current estimate when both arrival and service moments are
    /// available. Zero-duration windows are ignored.
    pub fn observe(&mut self, observation: PoolSizingObservation) -> Option<PoolWorkloadEstimate> {
        if observation.elapsed_micros == 0 {
            return self.estimate();
        }

        let arrival_rate = u128::from(observation.arrivals)
            .saturating_mul(POOL_SIZING_SCALE_U128)
            .saturating_mul(1_000_000)
            / u128::from(observation.elapsed_micros);
        self.arrival_rate_per_sec_ppm = Some(ewma_u64(
            self.arrival_rate_per_sec_ppm,
            clamp_u128_to_u64(arrival_rate),
            self.alpha_ppm,
        ));

        if observation.completions > 0 {
            let completions = u128::from(observation.completions);
            let mean = observation.total_service_micros / completions;
            let second_moment = observation.total_service_micros_squared / completions;
            self.service_time_mean_micros = Some(ewma_u64(
                self.service_time_mean_micros,
                clamp_u128_to_u64(mean),
                self.alpha_ppm,
            ));
            self.service_time_second_moment_micros2 = Some(ewma_u128(
                self.service_time_second_moment_micros2,
                second_moment,
                self.alpha_ppm,
            ));
        }

        self.sample_count = self.sample_count.saturating_add(1);
        self.estimate()
    }

    /// Return the current EWMA estimate.
    #[must_use]
    pub fn estimate(&self) -> Option<PoolWorkloadEstimate> {
        let arrival_rate_per_sec_ppm = self.arrival_rate_per_sec_ppm?;
        let service_time_mean_micros = self.service_time_mean_micros?;
        let second_moment = self.service_time_second_moment_micros2?;
        let mean_squared = u128::from(service_time_mean_micros)
            .saturating_mul(u128::from(service_time_mean_micros));
        let variance = second_moment.saturating_sub(mean_squared);
        Some(PoolWorkloadEstimate {
            arrival_rate_per_sec_ppm,
            service_time_mean_micros,
            service_time_variance_micros2: variance,
        })
    }
}

/// Metrics calculated for one candidate pool size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingCandidateMetrics {
    /// Candidate pool size.
    pub size: usize,
    /// Offered load in busy workers, scaled by [`POOL_SIZING_SCALE`].
    pub offered_load_ppm: u64,
    /// Candidate utilization, scaled by [`POOL_SIZING_SCALE`].
    pub utilization_ppm: u32,
    /// Approximate probability of waiting, scaled by [`POOL_SIZING_SCALE`].
    pub wait_probability_ppm: u32,
    /// Approximate mean queue wait in microseconds.
    pub mean_wait_micros: u64,
    /// Service variability multiplier, in basis points.
    pub service_variability_bps: u64,
}

/// Why a recommendation selected its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSizingReason {
    /// The estimate had no positive arrival/service load; the floor wins.
    NoObservedLoad,
    /// The first candidate satisfying the target was selected.
    TargetMet,
    /// The target-satisfying candidate was below the configured floor.
    ClampedToFloor,
    /// No candidate satisfied the target before the configured ceiling.
    TargetUnmetAtCeiling,
}

/// Stable pool-size recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingRecommendation {
    /// Recommended pool size after floor/ceiling application.
    pub recommended_size: usize,
    /// Hard bounds used for the recommendation.
    pub bounds: PoolSizingBounds,
    /// Target used for the search.
    pub target: PoolSizingTarget,
    /// Square-root staffing hint before the exact candidate scan.
    pub square_root_staffing_size: usize,
    /// Metrics for the selected candidate.
    pub selected_metrics: PoolSizingCandidateMetrics,
    /// Whether the selected candidate satisfies the target.
    pub target_met: bool,
    /// Selection reason.
    pub reason: PoolSizingReason,
}

/// Compute the square-root staffing hint for an estimate and target.
#[must_use]
pub fn square_root_staffing_size(
    estimate: PoolWorkloadEstimate,
    target: PoolSizingTarget,
) -> usize {
    let load = u128::from(estimate.offered_load_ppm());
    if load == 0 {
        return 0;
    }

    let beta_bps = beta_bps_for_target(target);
    let sqrt_load = integer_sqrt(load.saturating_mul(POOL_SIZING_SCALE_U128));
    let variability = u128::from(estimate.service_variability_bps());
    let safety = u128::from(beta_bps)
        .saturating_mul(sqrt_load)
        .saturating_mul(variability)
        / BPS_SCALE
        / BPS_SCALE;
    let staffed = load.saturating_add(safety);
    ceil_scaled_to_usize(staffed, POOL_SIZING_SCALE_U128)
}

/// Compute metrics for one candidate size.
#[must_use]
pub fn pool_sizing_candidate_metrics(
    estimate: PoolWorkloadEstimate,
    size: usize,
) -> PoolSizingCandidateMetrics {
    let offered_load = u128::from(estimate.offered_load_ppm());
    let variability_bps = estimate.service_variability_bps();
    if size == 0 {
        return PoolSizingCandidateMetrics {
            size,
            offered_load_ppm: clamp_u128_to_u64(offered_load),
            utilization_ppm: POOL_SIZING_SCALE as u32,
            wait_probability_ppm: POOL_SIZING_SCALE as u32,
            mean_wait_micros: u64::MAX,
            service_variability_bps: variability_bps,
        };
    }
    if offered_load == 0 {
        return PoolSizingCandidateMetrics {
            size,
            offered_load_ppm: 0,
            utilization_ppm: 0,
            wait_probability_ppm: 0,
            mean_wait_micros: 0,
            service_variability_bps: variability_bps,
        };
    }

    let capacity = (size as u128).saturating_mul(POOL_SIZING_SCALE_U128);
    if offered_load >= capacity {
        return PoolSizingCandidateMetrics {
            size,
            offered_load_ppm: clamp_u128_to_u64(offered_load),
            utilization_ppm: POOL_SIZING_SCALE as u32,
            wait_probability_ppm: POOL_SIZING_SCALE as u32,
            mean_wait_micros: u64::MAX,
            service_variability_bps: variability_bps,
        };
    }

    let erlang_c = erlang_c_wait_probability_ppm(offered_load, size);
    let wait_probability = erlang_c.saturating_mul(u128::from(variability_bps)) / BPS_SCALE;
    let spare_capacity = capacity.saturating_sub(offered_load);
    let mean_wait = erlang_c
        .saturating_mul(u128::from(estimate.service_time_mean_micros))
        .saturating_mul(u128::from(variability_bps))
        / spare_capacity
        / BPS_SCALE;
    let utilization = offered_load.saturating_mul(POOL_SIZING_SCALE_U128) / capacity;

    PoolSizingCandidateMetrics {
        size,
        offered_load_ppm: clamp_u128_to_u64(offered_load),
        utilization_ppm: clamp_probability_to_u32(utilization),
        wait_probability_ppm: clamp_probability_to_u32(wait_probability),
        mean_wait_micros: clamp_u128_to_u64(mean_wait),
        service_variability_bps: variability_bps,
    }
}

/// Recommend a pool size by scanning candidates inside the configured bounds.
#[must_use]
pub fn recommend_pool_size(
    estimate: PoolWorkloadEstimate,
    bounds: PoolSizingBounds,
    target: PoolSizingTarget,
) -> PoolSizingRecommendation {
    let bounds = PoolSizingBounds::new(bounds.min_size, bounds.max_size);
    let square_root_staffing = square_root_staffing_size(estimate, target);
    if !estimate.has_load() {
        let metrics = pool_sizing_candidate_metrics(estimate, bounds.min_size);
        return PoolSizingRecommendation {
            recommended_size: bounds.min_size,
            bounds,
            target,
            square_root_staffing_size: square_root_staffing,
            selected_metrics: metrics,
            target_met: true,
            reason: PoolSizingReason::NoObservedLoad,
        };
    }

    for size in bounds.min_size..=bounds.max_size {
        let metrics = pool_sizing_candidate_metrics(estimate, size);
        if target.is_met_by(metrics) {
            let reason = if square_root_staffing < bounds.min_size && size == bounds.min_size {
                PoolSizingReason::ClampedToFloor
            } else {
                PoolSizingReason::TargetMet
            };
            return PoolSizingRecommendation {
                recommended_size: size,
                bounds,
                target,
                square_root_staffing_size: square_root_staffing,
                selected_metrics: metrics,
                target_met: true,
                reason,
            };
        }
    }

    let metrics = pool_sizing_candidate_metrics(estimate, bounds.max_size);
    PoolSizingRecommendation {
        recommended_size: bounds.max_size,
        bounds,
        target,
        square_root_staffing_size: square_root_staffing,
        selected_metrics: metrics,
        target_met: target.is_met_by(metrics),
        reason: PoolSizingReason::TargetUnmetAtCeiling,
    }
}

/// Policy used by a pure pool-sizing controller decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingPolicy {
    /// Advisory or managed behavior.
    pub mode: PoolSizingMode,
    /// Hard floor/ceiling.
    pub bounds: PoolSizingBounds,
    /// Wait target used by the recommendation scan.
    pub target: PoolSizingTarget,
    /// Minimum relative recommendation change required before managed resize.
    pub hysteresis_bps: u16,
    /// Minimum epochs between managed resize actions.
    pub resize_cadence_epochs: u64,
}

impl PoolSizingPolicy {
    /// Conservative advisory policy with a ten-percent wait-probability target.
    #[must_use]
    pub const fn advisory(bounds: PoolSizingBounds) -> Self {
        Self {
            mode: PoolSizingMode::Advisory,
            bounds,
            target: PoolSizingTarget::conservative_wait_probability(),
            hysteresis_bps: DEFAULT_HYSTERESIS_BPS,
            resize_cadence_epochs: DEFAULT_RESIZE_CADENCE_EPOCHS,
        }
    }

    /// Managed policy with default hysteresis and cadence gates.
    #[must_use]
    pub const fn managed(bounds: PoolSizingBounds, target: PoolSizingTarget) -> Self {
        Self {
            mode: PoolSizingMode::Managed,
            bounds,
            target,
            hysteresis_bps: DEFAULT_HYSTERESIS_BPS,
            resize_cadence_epochs: DEFAULT_RESIZE_CADENCE_EPOCHS,
        }
    }
}

/// Current pool-sizing controller state supplied by an integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingControllerState {
    /// Current live pool size.
    pub current_size: usize,
    /// Last epoch at which a managed resize action was applied.
    pub last_resize_epoch: u64,
}

/// Pure decision action for one controller tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSizingAction {
    /// Advisory mode: publish the recommendation only.
    ObserveOnly,
    /// Managed mode: resize from `from_size` to `to_size`.
    Resize { from_size: usize, to_size: usize },
    /// Managed mode: recommendation moved less than the hysteresis gate.
    HoldHysteresis,
    /// Managed mode: cadence gate has not elapsed.
    HoldCadence,
}

/// Pure controller decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingDecision {
    /// Recommendation computed for this tick.
    pub recommendation: PoolSizingRecommendation,
    /// Action allowed by mode, hysteresis, and cadence.
    pub action: PoolSizingAction,
}

/// Evaluate one pool-sizing controller tick without mutating runtime state.
#[must_use]
pub fn decide_pool_sizing(
    policy: PoolSizingPolicy,
    state: PoolSizingControllerState,
    estimate: PoolWorkloadEstimate,
    current_epoch: u64,
) -> PoolSizingDecision {
    let recommendation = recommend_pool_size(estimate, policy.bounds, policy.target);
    let action = match policy.mode {
        PoolSizingMode::Advisory => PoolSizingAction::ObserveOnly,
        PoolSizingMode::Managed if recommendation.recommended_size == state.current_size => {
            PoolSizingAction::HoldHysteresis
        }
        PoolSizingMode::Managed
            if !crosses_hysteresis(
                state.current_size,
                recommendation.recommended_size,
                policy.hysteresis_bps,
            ) =>
        {
            PoolSizingAction::HoldHysteresis
        }
        PoolSizingMode::Managed
            if current_epoch.saturating_sub(state.last_resize_epoch)
                < policy.resize_cadence_epochs =>
        {
            PoolSizingAction::HoldCadence
        }
        PoolSizingMode::Managed => PoolSizingAction::Resize {
            from_size: state.current_size,
            to_size: recommendation.recommended_size,
        },
    };
    PoolSizingDecision {
        recommendation,
        action,
    }
}

/// Default advisory-divergence threshold: warn when the live size differs from
/// the recommendation by a factor of two or more in either direction
/// (`20_000` basis points == 2.0x).
pub const DEFAULT_DIVERGENCE_WARN_BPS: u32 = 20_000;

/// Direction of an advisory divergence between the live size and the recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSizingDivergenceDirection {
    /// The live pool is smaller than the recommendation (under-provisioned).
    Undersized,
    /// The live pool is larger than the recommendation (over-provisioned).
    Oversized,
}

/// An advisory divergence between the recommended and the live pool size.
///
/// This is the AC2 signal: integrations compute it each epoch in advisory mode
/// and, when present, emit an operator warning / metric. It carries no logging
/// of its own so the policy layer stays pure and deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSizingDivergence {
    /// The size the controller recommends.
    pub recommended_size: usize,
    /// The live pool size that diverged from the recommendation.
    pub actual_size: usize,
    /// Divergence magnitude as the larger-over-smaller ratio in basis points
    /// (`BPS_SCALE` == 1.0x). A zero on the smaller side saturates to `u32::MAX`.
    pub factor_bps: u32,
    /// Whether the live pool is under- or over-provisioned versus the recommendation.
    pub direction: PoolSizingDivergenceDirection,
}

/// Compute an advisory divergence warning when the live size differs from the
/// recommendation by at least `warn_bps` (measured as the larger-over-smaller
/// ratio). Returns `None` when within tolerance.
///
/// Pure and side-effect free: an integration decides whether to log or expose a
/// metric. The default threshold [`DEFAULT_DIVERGENCE_WARN_BPS`] fires at a 2x
/// gap, matching the bead's "diverges >=2x from recommended" acceptance rule.
#[must_use]
pub fn pool_sizing_divergence(
    recommended_size: usize,
    actual_size: usize,
    warn_bps: u32,
) -> Option<PoolSizingDivergence> {
    if recommended_size == actual_size {
        return None;
    }
    let (smaller, larger, direction) = if actual_size < recommended_size {
        (
            actual_size,
            recommended_size,
            PoolSizingDivergenceDirection::Undersized,
        )
    } else {
        (
            recommended_size,
            actual_size,
            PoolSizingDivergenceDirection::Oversized,
        )
    };
    // A zero on the smaller side is an unbounded ratio; saturate so any positive
    // gap from zero always trips the warning.
    let factor_bps = if smaller == 0 {
        u32::MAX
    } else {
        let ratio = (larger as u128).saturating_mul(BPS_SCALE) / (smaller as u128);
        u32::try_from(ratio).unwrap_or(u32::MAX)
    };
    if factor_bps >= warn_bps {
        Some(PoolSizingDivergence {
            recommended_size,
            actual_size,
            factor_bps,
            direction,
        })
    } else {
        None
    }
}

/// Stateful managed pool-sizing controller — the "brain" of managed mode.
///
/// The controller owns an EWMA [`PoolSizingEstimator`], a [`PoolSizingPolicy`],
/// and the live controller state (tracked size + last resize epoch). On each
/// [`observe`](Self::observe) it folds the sample, evaluates [`decide_pool_sizing`],
/// and — in managed mode — applies an allowed [`PoolSizingAction::Resize`] to its
/// tracked size, advancing `last_resize_epoch` and counting the resize. The
/// hysteresis and cadence gates bound the number of resizes so a load ramp does
/// not flap (AC3); the tracked size is always clamped into the policy bounds so
/// floors and ceilings always win (AC5).
///
/// The controller never touches a real pool. An integration seeds it from
/// `pool.pool_sizing_bounds()` / `pool.pool_sizing_controller_state()`, feeds
/// already-collected observations, and reads [`current_size`](Self::current_size)
/// (or the returned decision) to apply the size through its own config surface.
/// Keeping application out of the controller keeps managed mode opt-in and the
/// controller deterministic for lab replay (AC4): identical observation/epoch
/// sequences produce identical size trajectories.
#[derive(Debug, Clone)]
pub struct ManagedPoolSizingController {
    policy: PoolSizingPolicy,
    estimator: PoolSizingEstimator,
    current_size: usize,
    last_resize_epoch: u64,
    applied_resizes: u64,
}

impl ManagedPoolSizingController {
    /// Build a controller from a policy, EWMA smoothing factor (parts per
    /// million), and the initial live pool size. The initial size is clamped
    /// into the policy bounds.
    ///
    /// Epochs passed to [`observe`](Self::observe) / [`tick`](Self::tick) must be
    /// monotonically non-decreasing; the first managed resize is permitted once
    /// `epoch >= policy.resize_cadence_epochs` (the cadence gate measures elapsed
    /// epochs since the last resize, treating construction as epoch zero).
    #[must_use]
    pub fn new(policy: PoolSizingPolicy, alpha_ppm: u32, initial_size: usize) -> Self {
        Self {
            estimator: PoolSizingEstimator::new(alpha_ppm),
            current_size: clamp_size_to_bounds(initial_size, policy.bounds),
            last_resize_epoch: 0,
            applied_resizes: 0,
            policy,
        }
    }

    /// The live size the controller currently tracks.
    #[must_use]
    pub const fn current_size(&self) -> usize {
        self.current_size
    }

    /// The epoch at which the controller last applied a resize.
    #[must_use]
    pub const fn last_resize_epoch(&self) -> u64 {
        self.last_resize_epoch
    }

    /// Number of resize actions applied over this controller's lifetime. A
    /// flapping controller would inflate this; a hysteresis proof bounds it.
    #[must_use]
    pub const fn applied_resizes(&self) -> u64 {
        self.applied_resizes
    }

    /// The policy bounds enforced on every decision.
    #[must_use]
    pub const fn bounds(&self) -> PoolSizingBounds {
        self.policy.bounds
    }

    /// The controller's behavior mode.
    #[must_use]
    pub const fn mode(&self) -> PoolSizingMode {
        self.policy.mode
    }

    /// The current EWMA workload estimate, if enough load has been observed.
    #[must_use]
    pub fn estimate(&self) -> Option<PoolWorkloadEstimate> {
        self.estimator.estimate()
    }

    /// Clear EWMA state after a confirmed workload regime change so the next
    /// observation seeds a fresh baseline. The live size is preserved, so a
    /// regime reset never itself resizes the pool (AC7 handoff for the
    /// change-point detector / H5 interference harness).
    pub fn reset_estimator(&mut self) {
        self.estimator.reset();
    }

    /// Controller state snapshot used by [`decide_pool_sizing`].
    #[must_use]
    pub const fn controller_state(&self) -> PoolSizingControllerState {
        PoolSizingControllerState {
            current_size: self.current_size,
            last_resize_epoch: self.last_resize_epoch,
        }
    }

    /// Fold one observation and evaluate a controller tick at `epoch`.
    ///
    /// In managed mode an allowed [`PoolSizingAction::Resize`] is applied to the
    /// tracked size and counted; hysteresis/cadence holds leave the size
    /// unchanged. Advisory mode never mutates state. The decision is returned so
    /// callers can publish the recommendation regardless of mode.
    pub fn observe(
        &mut self,
        observation: PoolSizingObservation,
        epoch: u64,
    ) -> PoolSizingDecision {
        self.estimator.observe(observation);
        self.tick(epoch)
    }

    /// Re-evaluate a controller tick against the current estimate without folding
    /// a new observation (e.g. on a cadence tick between observation windows).
    pub fn tick(&mut self, epoch: u64) -> PoolSizingDecision {
        let Some(estimate) = self.estimator.estimate() else {
            // Cold start: no estimate yet. Recommend the floor but take no
            // action — a managed controller must not resize on zero data.
            let recommendation = recommend_pool_size(
                PoolWorkloadEstimate::new(0, 0, 0),
                self.policy.bounds,
                self.policy.target,
            );
            return PoolSizingDecision {
                recommendation,
                action: PoolSizingAction::ObserveOnly,
            };
        };
        let decision = decide_pool_sizing(self.policy, self.controller_state(), estimate, epoch);
        if let PoolSizingAction::Resize { to_size, .. } = decision.action {
            // `decide_pool_sizing` only emits `Resize` in managed mode and only
            // when `to_size != current_size`. Clamp defensively so the bounds
            // win even if a caller mutated the policy fields directly (AC5).
            self.current_size = clamp_size_to_bounds(to_size, self.policy.bounds);
            self.last_resize_epoch = epoch;
            self.applied_resizes = self.applied_resizes.saturating_add(1);
        }
        decision
    }

    /// Advisory divergence between the live size and the latest recommendation,
    /// using [`DEFAULT_DIVERGENCE_WARN_BPS`]. Returns `None` before any estimate
    /// exists or when within tolerance (AC2).
    #[must_use]
    pub fn divergence(&self) -> Option<PoolSizingDivergence> {
        self.divergence_with_threshold(DEFAULT_DIVERGENCE_WARN_BPS)
    }

    /// Advisory divergence with an explicit threshold in basis points.
    #[must_use]
    pub fn divergence_with_threshold(&self, warn_bps: u32) -> Option<PoolSizingDivergence> {
        let estimate = self.estimator.estimate()?;
        let recommendation = recommend_pool_size(estimate, self.policy.bounds, self.policy.target);
        pool_sizing_divergence(recommendation.recommended_size, self.current_size, warn_bps)
    }

    /// Render the galaxy-brain transparency card for the latest estimate (AC6).
    #[must_use]
    pub fn explain(&self) -> String {
        match self.estimator.estimate() {
            Some(estimate) => {
                let recommendation =
                    recommend_pool_size(estimate, self.policy.bounds, self.policy.target);
                explain_pool_sizing(estimate, recommendation)
            }
            None => {
                String::from("pool-sizing card - no observed load yet; holding configured bounds")
            }
        }
    }
}

/// Render a plain-English "why N workers" transparency card (AC6).
///
/// The card states the live offered load, the square-root staffing formula with
/// substituted values, the Erlang-C wait probability at the selected size, the
/// target, and the selection reason. It is an operator artifact; integrations
/// log or surface it next to the recommendation.
#[must_use]
pub fn explain_pool_sizing(
    estimate: PoolWorkloadEstimate,
    recommendation: PoolSizingRecommendation,
) -> String {
    let metrics = recommendation.selected_metrics;
    let offered_load = format_ppm_units(estimate.offered_load_ppm());
    let arrival = format_ppm_units(estimate.arrival_rate_per_sec_ppm);
    let cv2 = format_ppm_units(estimate.service_cv2_ppm());
    let bounds = recommendation.bounds;
    let target = match recommendation.target {
        PoolSizingTarget::MaxWaitProbabilityPpm(p) => {
            format!("P(wait) <= {}", format_ppm_percent(p))
        }
        PoolSizingTarget::MaxMeanWaitMicros(w) => format!("E[wait] <= {w}us"),
    };
    let reason = match recommendation.reason {
        PoolSizingReason::NoObservedLoad => "no observed load; floor wins",
        PoolSizingReason::TargetMet => "first candidate meeting the target",
        PoolSizingReason::ClampedToFloor => "target met below floor; clamped up to floor",
        PoolSizingReason::TargetUnmetAtCeiling => "target unmet at ceiling; clamped to ceiling",
    };
    format!(
        "pool-sizing card - recommend {size} workers (bounds {min}..={max}, reason: {reason})\n  \
         offered load R = {offered_load} workers (arrival {arrival}/s x mean service {service_micros}us)\n  \
         square-root staffing k0 = R + beta*sqrt(R) = {staffing} workers\n  \
         at {size} workers: utilization {util}, P(wait) ~= {wait} (target {target}), mean wait ~= {mean_wait}us\n  \
         service variability multiplier {variability_x} (Allen-Cunneen, CV^2 = {cv2}){met}",
        size = recommendation.recommended_size,
        min = bounds.min_size,
        max = bounds.max_size,
        staffing = recommendation.square_root_staffing_size,
        service_micros = estimate.service_time_mean_micros,
        util = format_ppm_percent(metrics.utilization_ppm),
        wait = format_ppm_percent(metrics.wait_probability_ppm),
        mean_wait = metrics.mean_wait_micros,
        variability_x = format_bps_multiplier(metrics.service_variability_bps),
        met = if recommendation.target_met {
            ""
        } else {
            "\n  WARNING: target NOT met at the configured ceiling"
        },
    )
}

/// Clamp a size into bounds without risking `usize::clamp`'s min>max panic.
fn clamp_size_to_bounds(size: usize, bounds: PoolSizingBounds) -> usize {
    let bounds = PoolSizingBounds::new(bounds.min_size, bounds.max_size);
    size.max(bounds.min_size).min(bounds.max_size)
}

/// Format a [`POOL_SIZING_SCALE`]-scaled value as a 3-decimal-place number.
fn format_ppm_units(value_ppm: u64) -> String {
    let whole = value_ppm / POOL_SIZING_SCALE;
    let frac = (value_ppm % POOL_SIZING_SCALE) / 1_000;
    format!("{whole}.{frac:03}")
}

/// Format a [`POOL_SIZING_SCALE`]-scaled probability/utilization as a percentage.
fn format_ppm_percent(value_ppm: u32) -> String {
    let value = u64::from(value_ppm);
    let whole = value / 10_000;
    let frac = (value % 10_000) / 100;
    format!("{whole}.{frac:02}%")
}

/// Format a basis-point multiplier (10_000 == 1.0x) as a 2-decimal-place factor.
fn format_bps_multiplier(value_bps: u64) -> String {
    let whole = value_bps / 10_000;
    let frac = (value_bps % 10_000) / 100;
    format!("{whole}.{frac:02}x")
}

fn beta_bps_for_target(target: PoolSizingTarget) -> u32 {
    match target.wait_probability_ppm().unwrap_or(100_000) {
        0..=100 => 37_200,
        101..=1_000 => 30_900,
        1_001..=10_000 => 23_300,
        10_001..=50_000 => 16_500,
        50_001..=100_000 => 12_800,
        100_001..=250_000 => 6_700,
        _ => 0,
    }
}

fn erlang_c_wait_probability_ppm(offered_load: u128, size: usize) -> u128 {
    if size == 0 {
        return POOL_SIZING_SCALE_U128;
    }
    let capacity = (size as u128).saturating_mul(POOL_SIZING_SCALE_U128);
    if offered_load >= capacity {
        return POOL_SIZING_SCALE_U128;
    }

    // Run the Erlang-B/C recursion at a higher internal precision than the ppm
    // output scale. The earlier ppm-only recursion truncated on every step and
    // accumulated a ~2 ppm error, enough to under-report the wait probability
    // and tip the recommended server count down by one. Working in 1e12 units
    // with round-to-nearest divisions keeps the final ppm value accurate to a
    // sub-ppm tolerance (M/M/3 with R=2 now resolves to 4/9 = 444_444 ppm).
    const HP: u128 = 1_000_000_000_000;
    let hp_per_ppm = HP / POOL_SIZING_SCALE_U128;
    let offered_hp = offered_load.saturating_mul(hp_per_ppm);

    // Erlang-B recursion in HP units; B starts at 1.0 == HP.
    let mut erlang_b = HP;
    for server in 1..=size {
        let load_times_b = offered_hp.saturating_mul(erlang_b) / HP;
        let denominator = (server as u128)
            .saturating_mul(HP)
            .saturating_add(load_times_b);
        erlang_b = if denominator == 0 {
            0
        } else {
            load_times_b
                .saturating_mul(HP)
                .saturating_add(denominator / 2)
                / denominator
        };
    }

    // Erlang-C: C = (size*B) / (size - a + a*B), all in HP units.
    let load_times_b = offered_hp.saturating_mul(erlang_b) / HP;
    let capacity_hp = (size as u128).saturating_mul(HP);
    let numerator = (size as u128).saturating_mul(erlang_b).saturating_mul(HP);
    let denominator = capacity_hp
        .saturating_sub(offered_hp)
        .saturating_add(load_times_b);
    if denominator == 0 {
        return POOL_SIZING_SCALE_U128;
    }
    let wait_hp = numerator.saturating_add(denominator / 2) / denominator;
    // Downscale HP -> ppm with round-to-nearest.
    (wait_hp.saturating_add(hp_per_ppm / 2) / hp_per_ppm).min(POOL_SIZING_SCALE_U128)
}

fn crosses_hysteresis(current_size: usize, recommended_size: usize, hysteresis_bps: u16) -> bool {
    if current_size == 0 {
        return recommended_size > 0;
    }
    let delta = current_size.abs_diff(recommended_size);
    (delta as u128).saturating_mul(BPS_SCALE)
        >= (current_size as u128).saturating_mul(u128::from(hysteresis_bps))
}

fn ewma_u64(previous: Option<u64>, sample: u64, alpha_ppm: u32) -> u64 {
    previous.map_or(sample, |prev| {
        let alpha = u128::from(alpha_ppm);
        let retained = POOL_SIZING_SCALE_U128.saturating_sub(alpha);
        let next = u128::from(prev)
            .saturating_mul(retained)
            .saturating_add(u128::from(sample).saturating_mul(alpha))
            / POOL_SIZING_SCALE_U128;
        clamp_u128_to_u64(next)
    })
}

fn ewma_u128(previous: Option<u128>, sample: u128, alpha_ppm: u32) -> u128 {
    previous.map_or(sample, |prev| {
        let alpha = u128::from(alpha_ppm);
        let retained = POOL_SIZING_SCALE_U128.saturating_sub(alpha);
        prev.saturating_mul(retained)
            .saturating_add(sample.saturating_mul(alpha))
            / POOL_SIZING_SCALE_U128
    })
}

fn integer_sqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut low = 1_u128;
    let mut high = value.min(u128::from(u64::MAX));
    let mut answer = 1_u128;
    while low <= high {
        let mid = low + (high - low) / 2;
        match mid.checked_mul(mid) {
            Some(square) if square == value => return mid,
            Some(square) if square < value => {
                answer = mid;
                low = mid + 1;
            }
            _ => high = mid - 1,
        }
    }
    answer
}

fn ceil_scaled_to_usize(value: u128, scale: u128) -> usize {
    if scale == 0 {
        return usize::MAX;
    }
    let rounded = value.saturating_add(scale - 1) / scale;
    usize::try_from(rounded).unwrap_or(usize::MAX)
}

fn clamp_probability_to_u32(value: u128) -> u32 {
    let clamped = value.min(POOL_SIZING_SCALE_U128);
    u32::try_from(clamped).unwrap_or(POOL_SIZING_SCALE as u32)
}

fn clamp_u128_to_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate(arrivals_per_second: u64, service_micros: u64) -> PoolWorkloadEstimate {
        PoolWorkloadEstimate::new(
            arrivals_per_second.saturating_mul(POOL_SIZING_SCALE),
            service_micros,
            u128::from(service_micros).saturating_mul(u128::from(service_micros)),
        )
    }

    #[test]
    fn offered_load_and_cv2_are_fixed_point() {
        let workload = PoolWorkloadEstimate::new(25 * POOL_SIZING_SCALE, 200_000, 40_000_000_000);

        assert_eq!(workload.offered_load_ppm(), 5 * POOL_SIZING_SCALE);
        assert_eq!(workload.service_cv2_ppm(), POOL_SIZING_SCALE);
        assert_eq!(workload.service_variability_bps(), 10_000);
    }

    #[test]
    fn erlang_c_matches_known_mm_k_table_values() {
        let half_load_one_server = erlang_c_wait_probability_ppm(POOL_SIZING_SCALE_U128 / 2, 1);
        let one_load_two_servers = erlang_c_wait_probability_ppm(POOL_SIZING_SCALE_U128, 2);
        let two_load_three_servers = erlang_c_wait_probability_ppm(2 * POOL_SIZING_SCALE_U128, 3);

        assert!(
            (499_999..=500_000).contains(&half_load_one_server),
            "M/M/1 with R=0.5 should wait with probability 0.5, got {half_load_one_server}"
        );
        assert!(
            (333_333..=333_334).contains(&one_load_two_servers),
            "M/M/2 with R=1 should wait with probability 1/3, got {one_load_two_servers}"
        );
        assert!(
            (444_444..=444_445).contains(&two_load_three_servers),
            "M/M/3 with R=2 should wait with probability 4/9, got {two_load_three_servers}"
        );
    }

    #[test]
    fn recommendation_selects_first_candidate_that_meets_wait_probability() {
        let workload = estimate(5, 1_000_000);
        let recommendation = recommend_pool_size(
            workload,
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );

        assert_eq!(recommendation.reason, PoolSizingReason::TargetMet);
        assert!(recommendation.target_met);
        assert_eq!(recommendation.recommended_size, 9);
        assert!(recommendation.square_root_staffing_size >= 8);
        assert!(recommendation.selected_metrics.wait_probability_ppm <= 100_000);
    }

    #[test]
    fn floor_and_ceiling_are_hard_bounds() {
        let no_load = PoolWorkloadEstimate::new(0, 0, 0);
        let floor = recommend_pool_size(
            no_load,
            PoolSizingBounds::new(3, 12),
            PoolSizingTarget::MaxWaitProbabilityPpm(1),
        );
        assert_eq!(floor.recommended_size, 3);
        assert_eq!(floor.reason, PoolSizingReason::NoObservedLoad);

        let overloaded = estimate(100, 1_000_000);
        let ceiling = recommend_pool_size(
            overloaded,
            PoolSizingBounds::new(1, 4),
            PoolSizingTarget::MaxWaitProbabilityPpm(10_000),
        );
        assert_eq!(ceiling.recommended_size, 4);
        assert_eq!(ceiling.reason, PoolSizingReason::TargetUnmetAtCeiling);
        assert!(!ceiling.target_met);
    }

    #[test]
    fn mean_wait_target_uses_selected_candidate_metrics() {
        let workload = estimate(4, 250_000);
        let recommendation = recommend_pool_size(
            workload,
            PoolSizingBounds::new(1, 8),
            PoolSizingTarget::MaxMeanWaitMicros(50_000),
        );

        assert!(recommendation.target_met);
        assert!(recommendation.selected_metrics.mean_wait_micros <= 50_000);
        assert!(recommendation.recommended_size >= 2);
    }

    #[test]
    fn estimator_uses_virtual_time_observations_only() {
        let mut estimator = PoolSizingEstimator::new(500_000);
        let first = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                10,
                10,
                2_000_000,
                400_000_000_000,
            ))
            .expect("first completed window yields an estimate");

        assert_eq!(first.arrival_rate_per_sec_ppm, 10 * POOL_SIZING_SCALE);
        assert_eq!(first.service_time_mean_micros, 200_000);
        assert_eq!(first.service_time_variance_micros2, 0);

        let second = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                20,
                20,
                8_000_000,
                3_200_000_000_000,
            ))
            .expect("second completed window updates estimate");

        assert_eq!(estimator.sample_count(), 2);
        assert_eq!(second.arrival_rate_per_sec_ppm, 15 * POOL_SIZING_SCALE);
        assert_eq!(second.service_time_mean_micros, 300_000);
        assert_eq!(second.service_time_variance_micros2, 10_000_000_000);
    }

    #[test]
    fn estimator_reset_clears_old_regime_before_next_observation() {
        let mut estimator = PoolSizingEstimator::new(500_000);
        let old_regime = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                20,
                20,
                8_000_000,
                3_200_000_000_000,
            ))
            .expect("old regime yields an estimate");
        assert_eq!(old_regime.arrival_rate_per_sec_ppm, 20 * POOL_SIZING_SCALE);
        assert_eq!(old_regime.service_time_mean_micros, 400_000);
        assert_eq!(estimator.sample_count(), 1);

        estimator.reset();
        assert_eq!(estimator.sample_count(), 0);
        assert_eq!(estimator.estimate(), None);

        let new_regime = estimator
            .observe(PoolSizingObservation::new(
                1_000_000,
                2,
                2,
                200_000,
                20_000_000_000,
            ))
            .expect("first post-reset observation yields a fresh estimate");

        assert_eq!(estimator.sample_count(), 1);
        assert_eq!(new_regime.arrival_rate_per_sec_ppm, 2 * POOL_SIZING_SCALE);
        assert_eq!(new_regime.service_time_mean_micros, 100_000);
        assert_eq!(new_regime.service_time_variance_micros2, 0);
    }

    #[test]
    fn advisory_mode_never_requests_resize() {
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 16));
        let state = PoolSizingControllerState {
            current_size: 2,
            last_resize_epoch: 0,
        };

        let decision = decide_pool_sizing(policy, state, estimate(8, 1_000_000), 100);

        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert!(decision.recommendation.recommended_size > state.current_size);
    }

    #[test]
    fn managed_mode_respects_hysteresis_and_cadence() {
        let mut policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        policy.hysteresis_bps = 5_000;
        policy.resize_cadence_epochs = 4;
        let state = PoolSizingControllerState {
            current_size: 10,
            last_resize_epoch: 10,
        };

        let small_move = decide_pool_sizing(policy, state, estimate(5, 1_000_000), 20);
        assert_eq!(small_move.recommendation.recommended_size, 9);
        assert_eq!(small_move.action, PoolSizingAction::HoldHysteresis);

        let cadence_hold = decide_pool_sizing(policy, state, estimate(12, 1_000_000), 12);
        assert!(cadence_hold.recommendation.recommended_size > state.current_size);
        assert_eq!(cadence_hold.action, PoolSizingAction::HoldCadence);

        let resize = decide_pool_sizing(policy, state, estimate(12, 1_000_000), 15);
        assert_eq!(
            resize.action,
            PoolSizingAction::Resize {
                from_size: 10,
                to_size: resize.recommendation.recommended_size
            }
        );
    }

    #[test]
    fn recommendation_replays_identically_from_same_observations() {
        let observations = [
            PoolSizingObservation::new(1_000_000, 5, 5, 500_000, 50_000_000_000),
            PoolSizingObservation::new(1_000_000, 10, 10, 2_000_000, 400_000_000_000),
            PoolSizingObservation::new(2_000_000, 16, 16, 4_800_000, 1_440_000_000_000),
        ];

        let run = || {
            let mut estimator = PoolSizingEstimator::new(250_000);
            let mut last = None;
            for observation in observations {
                last = estimator.observe(observation);
            }
            recommend_pool_size(
                last.expect("observations should produce an estimate"),
                PoolSizingBounds::new(1, 16),
                PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
            )
        };

        assert_eq!(run(), run());
    }

    fn ramp_observation(arrivals_per_second: u64, service_micros: u64) -> PoolSizingObservation {
        // One-second window: arrivals == arrivals/sec, completions match arrivals.
        PoolSizingObservation::new(
            1_000_000,
            arrivals_per_second,
            arrivals_per_second,
            u128::from(arrivals_per_second).saturating_mul(u128::from(service_micros)),
            u128::from(arrivals_per_second)
                .saturating_mul(u128::from(service_micros))
                .saturating_mul(u128::from(service_micros)),
        )
    }

    #[test]
    fn divergence_fires_at_two_x_and_is_silent_within_tolerance() {
        // 4 vs 2 is exactly 2x => fires (undersized).
        let under = pool_sizing_divergence(4, 2, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("2x undersize must warn");
        assert_eq!(under.direction, PoolSizingDivergenceDirection::Undersized);
        assert_eq!(under.factor_bps, 20_000);

        // 2 vs 4 is 2x the other way => fires (oversized).
        let over = pool_sizing_divergence(2, 4, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("2x oversize must warn");
        assert_eq!(over.direction, PoolSizingDivergenceDirection::Oversized);

        // 4 vs 3 is ~1.33x => within tolerance.
        assert_eq!(
            pool_sizing_divergence(4, 3, DEFAULT_DIVERGENCE_WARN_BPS),
            None
        );
        // Equality never warns.
        assert_eq!(
            pool_sizing_divergence(5, 5, DEFAULT_DIVERGENCE_WARN_BPS),
            None
        );
        // Any positive size vs a zero floor is an unbounded divergence.
        let from_zero = pool_sizing_divergence(8, 0, DEFAULT_DIVERGENCE_WARN_BPS)
            .expect("nonzero recommendation vs zero size warns");
        assert_eq!(from_zero.factor_bps, u32::MAX);
        assert_eq!(
            from_zero.direction,
            PoolSizingDivergenceDirection::Undersized
        );
    }

    #[test]
    fn advisory_controller_warns_on_deliberate_undersizing() {
        // AC2: advisory mode publishes a divergence when the pool is far below
        // the recommendation under a heavy load, and never acts.
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 2);
        let decision = controller.observe(ramp_observation(40, 500_000), 1);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(controller.current_size(), 2, "advisory mode never resizes");
        let divergence = controller
            .divergence()
            .expect("a 2-worker pool under R=20 load must diverge from the recommendation");
        assert_eq!(
            divergence.direction,
            PoolSizingDivergenceDirection::Undersized
        );
        assert!(divergence.recommended_size >= 2 * divergence.actual_size);
    }

    #[test]
    fn managed_controller_follows_load_ramp_without_flapping() {
        // AC3: under a monotone load ramp the managed pool grows toward the
        // recommendation, settles, and the resize count stays small (no flap).
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        // alpha = 1.0 so the EWMA tracks each window exactly for a clean proof.
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);

        let mut sizes = Vec::new();
        // Ramp up over several epochs, then hold at the peak load.
        let ramp = [4_u64, 8, 12, 16, 20, 20, 20, 20];
        for (i, arrivals) in ramp.iter().enumerate() {
            let epoch = (i as u64) + 1;
            controller.observe(ramp_observation(*arrivals, 500_000), epoch);
            sizes.push(controller.current_size());
        }

        // Size grows monotonically during the ramp.
        for pair in sizes.windows(2) {
            assert!(
                pair[1] >= pair[0],
                "managed size should not shrink mid-ramp"
            );
        }
        // It actually grew above the floor.
        assert!(
            *sizes.last().unwrap() > 1,
            "managed pool should scale up under load"
        );
        // Once load is steady the controller stops acting (hysteresis holds).
        let resizes_after_ramp = controller.applied_resizes();
        controller.observe(ramp_observation(20, 500_000), 9);
        controller.observe(ramp_observation(20, 500_000), 10);
        assert_eq!(
            controller.applied_resizes(),
            resizes_after_ramp,
            "steady load must not trigger further resizes"
        );
        // Action count is bounded well below the number of ticks (no flapping).
        assert!(
            controller.applied_resizes() <= ramp.len() as u64,
            "resize count {} should be bounded by the ramp length",
            controller.applied_resizes()
        );
    }

    #[test]
    fn managed_controller_replays_identically() {
        // AC4: identical observation/epoch sequences yield identical trajectories.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        let ramp = [3_u64, 9, 15, 21, 21, 21];
        let run = || {
            let mut controller = ManagedPoolSizingController::new(policy, 400_000, 1);
            let mut trace = Vec::new();
            for (i, arrivals) in ramp.iter().enumerate() {
                controller.observe(ramp_observation(*arrivals, 400_000), (i as u64) + 1);
                trace.push(controller.current_size());
            }
            (
                trace,
                controller.applied_resizes(),
                controller.last_resize_epoch(),
            )
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn managed_controller_respects_floor_and_ceiling() {
        // AC5: a crushing load can never push the pool past the ceiling, and a
        // trickle of load can never pull it below the floor.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(4, 8),
            PoolSizingTarget::MaxWaitProbabilityPpm(10_000),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 4);
        for epoch in 1..=6 {
            controller.observe(ramp_observation(1_000, 1_000_000), epoch);
            assert!(
                controller.current_size() <= 8,
                "ceiling must always win, got {}",
                controller.current_size()
            );
            assert!(controller.current_size() >= 4, "floor must always hold");
        }
        assert_eq!(
            controller.current_size(),
            8,
            "crushing load pins at the ceiling"
        );

        // Now a near-idle workload: the floor still holds.
        let mut idle = ManagedPoolSizingController::new(policy, 1_000_000, 8);
        for epoch in 1..=4 {
            idle.observe(ramp_observation(1, 1_000), epoch);
            assert!(idle.current_size() >= 4, "floor must hold under idle load");
        }
    }

    #[test]
    fn controller_cold_start_observes_only() {
        // No estimate yet on the very first tick (no observation folded).
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 16),
            PoolSizingTarget::conservative_wait_probability(),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 500_000, 4);
        let decision = controller.tick(5);
        assert_eq!(decision.action, PoolSizingAction::ObserveOnly);
        assert_eq!(controller.current_size(), 4);
        assert_eq!(controller.applied_resizes(), 0);
    }

    #[test]
    fn reset_estimator_preserves_live_size() {
        // AC7: a regime reset clears learning but never resizes the pool itself.
        let policy = PoolSizingPolicy::managed(
            PoolSizingBounds::new(1, 32),
            PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
        );
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
        for epoch in 1..=4 {
            controller.observe(ramp_observation(16, 500_000), epoch);
        }
        let size_before = controller.current_size();
        assert!(size_before > 1);
        controller.reset_estimator();
        assert_eq!(
            controller.current_size(),
            size_before,
            "reset must not resize"
        );
        assert_eq!(controller.estimate(), None, "reset clears the estimate");
    }

    #[test]
    fn explain_card_substitutes_live_values() {
        // AC6: the galaxy-brain card names the recommendation and the inputs.
        let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
        let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
        controller.observe(ramp_observation(16, 400_000), 1);
        let card = controller.explain();
        assert!(card.contains("pool-sizing card"), "card header: {card}");
        assert!(
            card.contains("offered load R ="),
            "card shows offered load: {card}"
        );
        assert!(
            card.contains("square-root staffing"),
            "card shows the formula: {card}"
        );
        assert!(
            card.contains("P(wait)"),
            "card shows wait probability: {card}"
        );

        // Cold-start card is explicit about the lack of data.
        let cold = ManagedPoolSizingController::new(policy, 1_000_000, 1).explain();
        assert!(cold.contains("no observed load"), "cold card: {cold}");
    }
}
