//! Auditable progress diagnostics for cancellation drain.
//!
//! # Purpose
//!
//! Provides auditable diagnostics for cancellation drain progress toward
//! quiescence. Under explicit predictable-drift and step-range assumptions,
//! it evaluates conditional concentration tails; one observed trace does not
//! itself prove bounded-time termination.
//!
//! # Mathematical Boundary
//!
//! Let `Δᵢ = V(Σᵢ) - V(Σᵢ₋₁)` and signed net progress be `Yᵢ = -Δᵢ`.
//! When `Yᵢ ∈ [-c, c]` and its conditional mean is at least `μ`, the
//! Azuma–Hoeffding candidate for a progress shortfall is:
//!
//! ```text
//! P(V(Σₜ) > V(Σ₀) - t·μ + λ) ≤ exp(-λ² / (2·t·c²))
//! ```
//!
//! The displayed tails use `t ≥ 1`, `c > 0`, and `λ > 0`; the Freedman
//! event below additionally uses `q ≥ 0`.
//!
//! For the centered shortfall `Xᵢ = E[Yᵢ | Fᵢ₋₁] - Yᵢ`, let
//! `Sₜ = ΣXᵢ` and `Qₜ = ΣE[Xᵢ² | Fᵢ₋₁]`. The raw Freedman candidate is:
//!
//! ```text
//! P(Sₜ ≥ λ AND Qₜ ≤ q) ≤ exp(-λ² / (2(q + Bλ/3)))
//! ```
//!
//! The implementation uses the outcome-independent caps `Qₜ ≤ t·c²` and
//! `B = 2c`. Under those range-only caps, the Freedman denominator is never
//! smaller than Azuma's, so the selected envelope is always the Azuma
//! candidate (equal at zero deviation). The explicit Freedman calculation is
//! retained for auditability, not presented as stronger evidence. Both use an
//! empirical plug-in net-progress rate; the trace does not establish the
//! future-drift premise.
//!
//! The `converging` verdict is deliberately separate: it reports a favorable
//! empirical trend in the complete accepted finite non-negative observation history
//! represented by running statistics, subject to stall plus rebound count,
//! magnitude, and recency policy. It does not imply future drift, termination,
//! or a probabilistic guarantee, and none of the conditional tails gate it.
//! A dropped invalid sample (non-finite or materially negative) makes telemetry
//! incomplete: the verdict fails
//! empirical convergence closed, suppresses the remaining-step estimate,
//! disables concentration, and reports `Warmup` rather than an actionable
//! terminal phase until reset.
//!
//! Gross downward credit `max(0, -Δᵢ)` is bookkeeping for phase diagnostics.
//! The gross-credit-accounted quantity `V(Σₜ) + Σ max(0, -Δᵢ)` equals
//! `V(Σ₀) + Σ max(Δᵢ, 0)` and is therefore pathwise nondecreasing. It is not
//! used as a supermartingale, Ville, or optional-stopping certificate.
//!
//! # Integration Points
//!
//! - [`LyapunovGovernor`](crate::obligation::lyapunov::LyapunovGovernor) —
//!   provides `V(Σₜ)` potential values via
//!   [`PotentialRecord`](crate::obligation::lyapunov::PotentialRecord).
//! - [`EProcess`](crate::lab::oracle::eprocess::EProcess) — sister
//!   martingale monitoring framework for invariant checking.
//! - [`SymbolCancelToken`](super::symbol_cancel::SymbolCancelToken) —
//!   cancellation cascade system whose drain we certificate.
//! - [`Budget`](crate::types::Budget) — poll quotas constrain covered cleanup
//!   paths with published responsiveness assumptions; they do not create a
//!   universal wall-clock drain bound for non-cooperative work.
//!
//! # Usage
//!
//! ```
//! use asupersync::cancel::progress_certificate::{
//!     ProgressCertificate, ProgressConfig, CertificateVerdict,
//! };
//!
//! let config = ProgressConfig::default();
//! let mut cert = ProgressCertificate::new(config);
//!
//! // Feed potential values from successive drain steps.
//! cert.observe(100.0);
//! cert.observe(80.0);
//! cert.observe(55.0);
//! cert.observe(30.0);
//! cert.observe(10.0);
//! cert.observe(0.0);
//!
//! let verdict = cert.verdict();
//! assert!(verdict.converging);
//! assert!(verdict.confidence_bound > 0.95);
//! ```

use std::fmt;

/// Maximum observed fraction of positive-delta steps accepted by the
/// empirical `converging` policy.
///
/// This is an operator heuristic over the accepted finite non-negative
/// observation history represented by running statistics, not a probability
/// or confidence level.
const MAX_EMPIRICAL_REBOUND_RATE: f64 = 0.25;

/// Maximum gross rebound magnitude relative to net endpoint progress accepted
/// by the empirical `converging` policy.
///
/// This prevents a low-count but near-total rebound from being mislabeled as a
/// favorable current trend. It is an operator heuristic, not a probability.
const MAX_EMPIRICAL_REBOUND_TO_NET_RATIO: f64 = 1.0;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for progress certificate monitoring.
///
/// Carries the operational inputs for stall and range diagnostics plus
/// serialized caller reference metadata.
#[derive(Debug, Clone)]
pub struct ProgressConfig {
    /// Serialized caller reference threshold for interpreting the projected
    /// conditional confidence calculation (e.g. 0.95).
    ///
    /// Must be in `(0, 1)`. This value does not affect `converging`, either
    /// current-horizon tail, or `confidence_bound`; callers may compare it to
    /// `confidence_bound` externally subject to the plug-in assumptions.
    /// Changing only this field changes serialized configuration identity, not
    /// the computed verdict.
    pub confidence: f64,

    /// Upper bound on the absolute potential change in a single step.
    ///
    /// This is the `c` in the Azuma–Hoeffding inequality. Must be
    /// positive and finite. If a step exceeds this bound, the
    /// certificate logs an evidence entry and disables concentration claims
    /// for that verdict rather than retroactively widening the assumption.
    pub max_step_bound: f64,

    /// Number of consecutive non-decreasing steps before declaring a stall.
    ///
    /// Stall detection uses a sliding window: if the last
    /// `stall_threshold` steps all have `delta ≥ 0` (potential did not
    /// decrease), the certificate flags a stall. Must be ≥ 1.
    pub stall_threshold: usize,

    /// Minimum number of observations before issuing any verdict.
    ///
    /// Below this count, `verdict()` returns a provisional result with
    /// `converging = false` and no bounds. Must be ≥ 2 (need at least
    /// one delta).
    pub min_observations: usize,

    /// Small epsilon for floating-point comparisons.
    ///
    /// Two potentials are considered "equal" if they differ by less
    /// than this value. Prevents false stall detection from rounding.
    pub epsilon: f64,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            confidence: 0.95,
            max_step_bound: 100.0,
            stall_threshold: 10,
            min_observations: 5,
            epsilon: 1e-12,
        }
    }
}

impl ProgressConfig {
    /// Validates the configuration.
    ///
    /// Returns `Err` with a description if any constraint is violated.
    pub fn validate(&self) -> Result<(), String> {
        if !self.confidence.is_finite() || self.confidence <= 0.0 || self.confidence >= 1.0 {
            return Err(format!(
                "confidence must be in (0, 1), got {}",
                self.confidence
            ));
        }
        if !self.max_step_bound.is_finite() || self.max_step_bound <= 0.0 {
            return Err(format!(
                "max_step_bound must be positive and finite, got {}",
                self.max_step_bound
            ));
        }
        if self.stall_threshold == 0 {
            return Err("stall_threshold must be >= 1".to_owned());
        }
        if self.min_observations < 2 {
            return Err(format!(
                "min_observations must be >= 2, got {}",
                self.min_observations
            ));
        }
        if !self.epsilon.is_finite() || self.epsilon < 0.0 {
            return Err(format!(
                "epsilon must be non-negative and finite, got {}",
                self.epsilon
            ));
        }
        Ok(())
    }

    /// Configuration tuned for tight stall detection (aggressive monitoring).
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            confidence: 0.99,
            max_step_bound: 50.0,
            stall_threshold: 5,
            min_observations: 3,
            epsilon: 1e-12,
        }
    }

    /// Configuration tuned for long-running drains with high variance.
    #[must_use]
    pub fn tolerant() -> Self {
        Self {
            confidence: 0.90,
            max_step_bound: 500.0,
            stall_threshold: 25,
            min_observations: 10,
            epsilon: 1e-10,
        }
    }
}

// ============================================================================
// Observation
// ============================================================================

/// A single observation in the progress process.
///
/// Each observation records the Lyapunov potential at one drain step,
/// together with derived quantities used for progress diagnostics.
#[derive(Debug, Clone)]
pub struct ProgressObservation {
    /// Zero-based step index.
    pub step: usize,
    /// Lyapunov potential `V(Σₜ)` at this step.
    pub potential: f64,
    /// Change from previous step: `V(Σₜ) - V(Σₜ₋₁)`.
    ///
    /// Negative means progress (potential decreased). For the first
    /// observation this is `0.0`.
    pub delta: f64,
    /// Gross downward credit at this step: `max(0, -delta)`.
    /// Rebounds are tracked separately through the signed delta stream.
    pub credit: f64,
}

// ============================================================================
// Evidence
// ============================================================================

/// An auditable evidence entry in a progress certificate.
///
/// Evidence entries form an audit trail that callers can inspect to verify
/// exactly which deterministic observations and conditional calculations
/// contributed to a verdict.
#[derive(Debug, Clone)]
pub struct EvidenceEntry {
    /// Step at which this evidence was recorded.
    pub step: usize,
    /// Potential value at this step.
    pub potential: f64,
    /// Historical unit-interval evidence field.
    ///
    /// Its interpretation is carried by [`Self::description`]: entries may
    /// contain a conditional tail candidate, an observed diagnostic rate, or
    /// a deterministic terminal marker. It is not uniformly a probability
    /// bound.
    pub bound: f64,
    /// Human-readable description of the evidence.
    pub description: String,
}

impl fmt::Display for EvidenceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step={}: V={:.4}, bound={:.6} — {}",
            self.step, self.potential, self.bound, self.description,
        )
    }
}

// ============================================================================
// Drain Phase
// ============================================================================

/// Phase of the cancellation drain process.
///
/// Determined automatically from the credit stream using an exponential
/// moving average to detect transitions between rapid drain and slow
/// convergence tail. These deterministic observed-history labels can inform
/// phase-adaptive timeout policy, but are not by themselves sufficient proof
/// that an operator should wait or escalate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPhase {
    /// Insufficient observations or incomplete telemetry prevent a reliable
    /// phase classification.
    Warmup,
    /// Rapid initial drain: high credit per step, potential falling fast.
    RapidDrain,
    /// Slow tail convergence: diminishing returns per step.
    SlowTail,
    /// The configured consecutive non-decreasing-step threshold was reached,
    /// or accepted history has no meaningful gross downward credit.
    Stalled,
    /// Potential is at or near zero; drain is complete.
    Quiescent,
}

impl fmt::Display for DrainPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warmup => f.write_str("warmup"),
            Self::RapidDrain => f.write_str("rapid_drain"),
            Self::SlowTail => f.write_str("slow_tail"),
            Self::Stalled => f.write_str("stalled"),
            Self::Quiescent => f.write_str("quiescent"),
        }
    }
}

// ============================================================================
// Certificate Verdict
// ============================================================================

/// Certificate verdict with empirical diagnostics and conditional tails.
///
/// Summarises one progress trace under the assumptions and no-claim boundary
/// described in the module documentation.
#[derive(Debug, Clone)]
pub struct CertificateVerdict {
    /// Whether the complete accepted finite non-negative observation history
    /// represented by running statistics is empirically trending toward quiescence under the
    /// signed-progress, stall, and rebound count/magnitude/recency policy
    /// reported in the evidence trail.
    ///
    /// This is not a future-drift, termination, or probability guarantee.
    /// A range violation disables the conditional concentration candidates but
    /// does not erase separately observed empirical progress. A dropped
    /// invalid observation disables both the conditional candidates and this
    /// status because telemetry is incomplete.
    pub converging: bool,

    /// Estimated remaining steps to quiescence via the plug-in net-progress
    /// rate: `V(Σₜ) / mean_net_progress`. `None` if insufficient data or
    /// non-positive net progress, or if dropped telemetry made the observation
    /// history incomplete.
    pub estimated_remaining_steps: Option<f64>,

    /// Projected lower-tail confidence calculation for quiescence within
    /// twice the plug-in remaining-step estimate. The selected range-only
    /// envelope equals the Azuma candidate because the conservative Freedman
    /// candidate is never tighter under `Qₜ ≤ t·c²` and `B = 2c`. It is
    /// conditional on persistence of the empirical net-progress rate and lies
    /// in `[0, 1]`. A configured-range violation or dropped invalid sample
    /// disables this calculation to `0`.
    pub confidence_bound: f64,

    /// Whether a stall was detected (last `stall_threshold` steps all
    /// had non-decreasing potential).
    pub stall_detected: bool,

    /// The conditional Azuma–Hoeffding candidate at the current step.
    ///
    /// This is `exp(-λ² / (2·t·c²))` evaluated at the current
    /// deviation from expected progress. With the current same-history plug-in
    /// mean and non-negative potential, telescoping gives `λ = 0`, so this
    /// current-horizon field is algebraically `1`. It is also `1` when a range
    /// violation or dropped invalid sample disables concentration.
    pub azuma_bound: f64,

    /// Number of accepted finite non-negative observations processed. Dropped invalid
    /// samples are reported separately through evidence.
    pub total_steps: usize,

    /// Most recent accepted finite non-negative potential value. This may be
    /// stale when a later invalid sample was dropped; consult evidence before acting.
    pub current_potential: f64,

    /// Initial potential value (at step 0).
    pub initial_potential: f64,

    /// Mean gross downward credit per step. Positive potential changes are
    /// accounted for separately when concentration and remaining-step
    /// calculations derive the net progress rate.
    pub mean_credit: f64,

    /// Maximum single-step absolute change observed.
    pub max_observed_step: f64,

    /// Conditional Freedman/Azuma candidate envelope for signed net progress.
    ///
    /// ```text
    /// P(Sₜ ≥ λ) ≤ exp(-λ² / (2(Qₜ + Bλ/3)))
    /// ```
    ///
    /// where `Qₜ` is the predictable quadratic variation, `b` is the
    /// configured absolute step bound, and `B = 2b` is the centered upper
    /// increment bound. Signed progress lies in `[-b, b]`, so
    /// `Qₜ ≤ t·b²`.
    /// Despite the historical field name, this stores the selected envelope
    /// `min(raw_freedman, azuma)`, not the raw Freedman candidate. With the
    /// range-only cap above, raw Freedman is never tighter, so this field equals
    /// `azuma_bound`. Empirical delta variance is diagnostic-only and never
    /// enters either bound. Both candidates use the verdict's empirical plug-in
    /// net-progress rate and therefore do not establish persistence of future
    /// drift. At the current same-history horizon, telescoping makes this field
    /// `1`; the projected `confidence_bound` is the separately extrapolated
    /// diagnostic.
    pub freedman_bound: f64,

    /// Current drain phase classification.
    pub drain_phase: DrainPhase,

    /// Empirical variance of per-step deltas (`None` if < 2 observations).
    pub empirical_variance: Option<f64>,

    /// Auditable evidence trail.
    pub evidence: Vec<EvidenceEntry>,
}

impl fmt::Display for CertificateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Progress Certificate Verdict")?;
        writeln!(f, "============================")?;
        writeln!(f, "Converging:         {}", self.converging)?;
        writeln!(f, "Stall detected:     {}", self.stall_detected)?;
        writeln!(f, "Steps:              {}", self.total_steps)?;
        writeln!(f, "V(Σ₀):              {:.4}", self.initial_potential)?;
        writeln!(f, "V(Σₜ):              {:.4}", self.current_potential)?;
        writeln!(f, "Mean credit/step:   {:.4}", self.mean_credit)?;
        writeln!(f, "Max |Δ|:            {:.4}", self.max_observed_step)?;
        writeln!(f, "Drain phase:        {}", self.drain_phase)?;
        writeln!(f, "Confidence bound:   {:.6}", self.confidence_bound)?;
        writeln!(f, "Azuma bound:        {:.6}", self.azuma_bound)?;
        writeln!(f, "Selected tail:      {:.6}", self.freedman_bound)?;
        if let Some(var) = self.empirical_variance {
            writeln!(f, "Delta variance:     {var:.6}")?;
        }
        if let Some(est) = self.estimated_remaining_steps {
            writeln!(f, "Est. remaining:     {est:.1} steps")?;
        } else {
            writeln!(f, "Est. remaining:     N/A")?;
        }
        if !self.evidence.is_empty() {
            writeln!(f, "Evidence ({} entries):", self.evidence.len())?;
            for e in &self.evidence {
                writeln!(f, "  {e}")?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// Progress Certificate
// ============================================================================

/// Running progress certificate with auditable conditional diagnostics.
///
/// Tracks Lyapunov potential values from successive cancellation drain steps.
/// At any point, callers can request a [`CertificateVerdict`] with empirical
/// trend and phase diagnostics, a plug-in remaining-step estimate, conditional
/// range-bounded calculations, and deterministic stall detection.
///
/// # No-claim Boundary
///
/// The certificate does not infer predictable drift, turn gross credit into a
/// supermartingale, or prove eventual quiescence from one trace. Published
/// cooperative-path cleanup budgets remain separate from this diagnostic; the
/// certificate does not create a bound where none is specified.
///
/// # Bounded Memory
///
/// Observations are retained for audit. If memory is a concern, use
/// [`compact`](Self::compact) to discard old observations while
/// preserving sufficient statistics.
#[derive(Debug, Clone)]
pub struct ProgressCertificate {
    /// Retained observation history for audit/debug.
    ///
    /// This may be compacted via [`compact`](Self::compact). Aggregate
    /// statistics remain global across the full run.
    observations: Vec<ProgressObservation>,
    /// Configuration.
    config: ProgressConfig,
    /// Total number of observations recorded since last reset.
    ///
    /// This count is independent of retained history and is not affected by
    /// [`compact`](Self::compact).
    total_observations: usize,
    /// Number of observed deltas (always `total_observations - 1` when non-zero).
    total_deltas: usize,
    /// Initial potential `V(Σ₀)` for this certificate run.
    initial_potential: Option<f64>,
    /// Most recent accepted finite potential value, even if older observations
    /// were compacted.
    last_potential: Option<f64>,
    /// Most recent accepted finite delta, preserved across compaction.
    last_delta: Option<f64>,
    /// Running sum of deltas `ΣΔᵢ` across all observed steps.
    sum_delta: f64,
    /// Running sum of credits: `Σcᵢ`.
    total_credit: f64,
    /// Running sum of squared deltas for variance estimation.
    sum_delta_sq: f64,
    /// Maximum absolute delta observed.
    max_abs_delta: f64,
    /// Number of steps with potential increase (violations of monotone
    /// decrease).
    increase_count: usize,
    /// Length of the current non-decreasing tail (for stall detection).
    stall_run: usize,
    /// Exponential moving average of per-step credit for phase detection.
    ///
    /// Uses smoothing factor `alpha = 2 / (window + 1)` with `window = 8`.
    ema_credit: f64,
    /// Number of invalid potential samples dropped since the last reset.
    ///
    /// Non-finite or materially negative telemetry must not be coerced into
    /// synthetic progress because that can fabricate quiescence. We record the
    /// anomaly for audit and ignore the sample entirely.
    invalid_observation_count: usize,
}

impl ProgressCertificate {
    /// Creates a new progress certificate with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if `config` fails validation.
    #[must_use]
    pub fn new(config: ProgressConfig) -> Self {
        assert!(
            config.validate().is_ok(),
            "ProgressConfig validation failed: {}",
            config.validate().expect_err("expected validation to fail")
        );
        Self {
            observations: Vec::new(),
            config,
            total_observations: 0,
            total_deltas: 0,
            initial_potential: None,
            last_potential: None,
            last_delta: None,
            sum_delta: 0.0,
            total_credit: 0.0,
            sum_delta_sq: 0.0,
            max_abs_delta: 0.0,
            increase_count: 0,
            stall_run: 0,
            ema_credit: 0.0,
            invalid_observation_count: 0,
        }
    }

    /// Creates a new progress certificate with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ProgressConfig::default())
    }

    /// Records a potential observation.
    ///
    /// `potential` must be non-negative (Lyapunov functions are ≥ 0).
    /// Finite negative values within the configured epsilon are treated as
    /// roundoff and clamped to zero. Non-finite or more-negative samples are
    /// dropped entirely and surfaced through [`CertificateVerdict::evidence`].
    pub fn observe(&mut self, potential: f64) {
        if !potential.is_finite() || potential < -self.config.epsilon {
            self.invalid_observation_count += 1;
            return;
        }
        let potential = potential.max(0.0);
        let step = self.total_observations;

        let delta = self.last_potential.map_or(0.0, |prev| potential - prev);

        let credit = (-delta).max(0.0);

        self.total_credit += credit;
        if step > 0 {
            self.total_deltas += 1;
            self.sum_delta += delta;
            self.sum_delta_sq += delta * delta;
            self.last_delta = Some(delta);
        }

        let abs_delta = delta.abs();
        if abs_delta > self.max_abs_delta {
            self.max_abs_delta = abs_delta;
        }

        if step > 0 && delta > self.config.epsilon {
            self.increase_count += 1;
        }

        // Update exponential moving average of credit for phase detection.
        // Alpha = 2 / (8 + 1) ≈ 0.222. The EMA tracks whether the credit
        // rate is accelerating (rapid drain) or decelerating (slow tail).
        if step > 0 {
            if self.total_deltas == 1 {
                self.ema_credit = credit;
            } else {
                const EMA_ALPHA: f64 = 2.0 / 9.0;
                self.ema_credit = EMA_ALPHA.mul_add(credit, (1.0 - EMA_ALPHA) * self.ema_credit);
            }
        }

        // Stall run: count consecutive non-decreasing steps at the tail.
        if step > 0 && delta >= -self.config.epsilon {
            self.stall_run += 1;
        } else {
            self.stall_run = 0;
        }

        self.observations.push(ProgressObservation {
            step,
            potential,
            delta,
            credit,
        });
        if self.initial_potential.is_none() {
            self.initial_potential = Some(potential);
        }
        self.last_potential = Some(potential);
        self.total_observations += 1;
    }

    /// Records a potential value from a [`PotentialRecord`](crate::obligation::lyapunov::PotentialRecord).
    ///
    /// Convenience wrapper that extracts the total potential.
    pub fn observe_potential_record(
        &mut self,
        record: &crate::obligation::lyapunov::PotentialRecord,
    ) {
        self.observe(record.total);
    }

    /// Computes the Azuma–Hoeffding tail bound.
    ///
    /// Given `t` signed net-progress steps `-Δᵢ` in `[-c, c]`
    /// (`step_bound` is that two-sided max), with predictable mean progress
    /// `mu` per step, the probability that the potential exceeds
    /// `V₀ - t·mu + lambda` is bounded by:
    ///
    /// ```text
    /// P(excess ≥ lambda) ≤ exp(-lambda² / (2·t·c²))
    /// ```
    ///
    /// Hoeffding's lemma applied to the conditional range of width `2c`
    /// gives
    /// `exp(-2λ² / (t·(2c)²)) = exp(-λ² / (2·t·c²))`.
    ///
    /// The earlier `exp(-2λ² / (t·c²))` was a factor-of-4 error in the
    /// exponent (it reported the fourth power of the true bound), which
    /// understated the non-quiescence probability and overstated convergence
    /// confidence — an anti-conservative certificate.
    ///
    /// We compute this with `lambda` chosen such that `V₀ - t·mu + lambda = 0`
    /// (the critical threshold for quiescence), giving the probability that
    /// quiescence has NOT been reached by step `t` under the mean-progress
    /// assumption.
    #[must_use]
    fn azuma_hoeffding_bound(&self, t: usize, mean_progress: f64, step_bound: f64) -> f64 {
        if t == 0 || step_bound <= 0.0 {
            return 1.0;
        }

        let initial = self.initial_potential.unwrap_or(0.0);

        // Expected potential at step t: V₀ - t·mu.
        // We want lambda such that V₀ - t·mu + lambda = 0 (quiescence threshold)
        // Therefore: lambda = t·mu - V₀ (excess beyond expected progress)
        // But we cap lambda at 0 from below — if expected progress
        // already exceeds V₀, the bound is trivially satisfied.
        #[allow(clippy::cast_precision_loss)]
        let t_f = t as f64;
        let expected_remaining = t_f.mul_add(-mean_progress, initial);
        let lambda = (-expected_remaining).max(0.0);

        // Azuma–Hoeffding: P(Sₜ ≥ lambda) ≤ exp(-lambda² / (2·t·c²))
        let exponent = -lambda * lambda / (2.0 * t_f * step_bound * step_bound);

        // Protect against numerical underflow: if exponent is extremely negative,
        // saturate to 0.0 rather than relying on IEEE underflow behavior
        if exponent < -700.0 {
            0.0
        } else {
            exponent.exp()
        }
    }

    /// Computes the raw Freedman candidate for signed net progress.
    ///
    /// Freedman's inequality is a variance-sensitive analogue of
    /// Azuma–Hoeffding that replaces the worst-case `t·c²` term with the
    /// predictable quadratic variation `Qₜ = Σ E[Xᵢ² | Fᵢ₋₁]` for
    /// `Xᵢ = E[-Δᵢ | Fᵢ₋₁] + Δᵢ`. With `Sₜ = ΣXᵢ`:
    ///
    /// ```text
    /// P(Sₜ ≥ λ AND Qₜ ≤ q) ≤ exp(-λ² / (2(q + Bλ/3)))
    /// ```
    ///
    /// where signed progress `-Δᵢ` lies in `[-b, b]` and the centered upper
    /// increment bound is `B = 2b`. Popoviciu's inequality gives the
    /// predictable cap `Qₜ ≤ t·b²`. Realized sample variance is
    /// diagnostic data, not a valid substitute for `Qₜ` in the same-sample
    /// tail bound. This cap makes the raw Freedman denominator at least the
    /// Azuma denominator, so the raw candidate is never tighter.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    fn freedman_candidate_bound(&self, t: usize, mean_progress: f64, step_bound: f64) -> f64 {
        if t == 0 || step_bound <= 0.0 {
            return 1.0;
        }

        let initial = self.initial_potential.unwrap_or(0.0);
        let t_f = t as f64;
        let expected_remaining = t_f.mul_add(-mean_progress, initial);
        let lambda = (-expected_remaining).max(0.0);

        // Signed progress lies in [-step_bound, step_bound]. Its conditional
        // variance is therefore at most step_bound², and the centered upper
        // increment is at most 2·step_bound. Both are fixed independently of
        // the outcomes whose tail probability we are bounding.
        let predictable_variation = t_f * step_bound * step_bound;
        let centered_increment_bound = 2.0 * step_bound;

        let denom = 2.0 * centered_increment_bound.mul_add(lambda / 3.0, predictable_variation);

        if !denom.is_finite() || denom <= 0.0 {
            return 1.0;
        }

        let exponent = -lambda * lambda / denom;
        // Protect against numerical underflow: if exponent is extremely negative,
        // saturate to 0.0 rather than relying on IEEE underflow behavior
        if exponent < -700.0 {
            0.0
        } else {
            exponent.exp()
        }
    }

    /// Returns the current drain phase.
    ///
    /// Phase classification uses the exponential moving average of credit
    /// compared to the overall mean credit rate:
    ///
    /// - **Quiescent**: potential ≈ 0 (drain complete)
    /// - **Stalled**: stall run ≥ threshold, or mean gross credit ≤ epsilon
    /// - **RapidDrain**: EMA credit ≥ 50% of mean credit
    /// - **SlowTail**: EMA credit < 50% of mean credit
    /// - **Warmup**: insufficient data or incomplete telemetry
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn drain_phase(&self) -> DrainPhase {
        if self.invalid_observation_count > 0
            || self.total_observations < self.config.min_observations
        {
            return DrainPhase::Warmup;
        }
        let current = self.last_potential.unwrap_or(0.0);
        if current <= self.config.epsilon {
            return DrainPhase::Quiescent;
        }
        if self.stall_run >= self.config.stall_threshold {
            return DrainPhase::Stalled;
        }
        let mean_credit = if self.total_deltas > 0 {
            self.total_credit / self.total_deltas as f64
        } else {
            return DrainPhase::Warmup;
        };
        if mean_credit <= self.config.epsilon {
            return DrainPhase::Stalled;
        }
        if self.ema_credit >= 0.5 * mean_credit {
            DrainPhase::RapidDrain
        } else {
            DrainPhase::SlowTail
        }
    }

    /// Produces a certificate verdict from the current observation history.
    ///
    /// This is the main query interface. The verdict includes:
    /// - Empirical trend status (separate from the conditional tails)
    /// - Plug-in signed net-progress remaining-step estimate
    /// - Projected confidence calculation (selected Freedman/Azuma envelope)
    /// - Stall detection (sliding window)
    /// - Full evidence trail
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn verdict(&self) -> CertificateVerdict {
        let n = self.total_observations;
        let current_potential = self.last_potential.unwrap_or(0.0);

        // --- Insufficient data: provisional verdict ---
        if n < self.config.min_observations {
            return CertificateVerdict {
                converging: false,
                estimated_remaining_steps: None,
                confidence_bound: 0.0,
                stall_detected: false,
                azuma_bound: 1.0,
                total_steps: n,
                current_potential,
                initial_potential: self.initial_potential.unwrap_or(0.0),
                mean_credit: 0.0,
                max_observed_step: self.max_abs_delta,
                freedman_bound: 1.0,
                drain_phase: DrainPhase::Warmup,
                empirical_variance: None,
                evidence: self
                    .invalid_sample_evidence(n.saturating_sub(1), current_potential)
                    .into_iter()
                    .collect(),
            };
        }

        let v_initial = self.initial_potential.unwrap_or(0.0);
        let v_current = self.last_potential.unwrap_or(0.0);
        let steps_with_deltas = self.total_deltas;
        let mean_credit = if steps_with_deltas > 0 {
            self.total_credit / steps_with_deltas as f64
        } else {
            0.0
        };
        let mean_net_progress = if steps_with_deltas > 0 {
            -self.sum_delta / steps_with_deltas as f64
        } else {
            0.0
        };

        let step_bound_violated = self.max_abs_delta > self.config.max_step_bound;
        let telemetry_complete = self.invalid_observation_count == 0;
        let concentration_enabled = !step_bound_violated && telemetry_complete;
        let (azuma, freedman) = if !concentration_enabled {
            // Concentration assumptions must be fixed before observing the
            // trace. Retrospectively widening the configured range to the
            // largest realized step would not restore a probability bound,
            // and dropped invalid telemetry leaves the history incomplete.
            (1.0, 1.0)
        } else {
            let step_bound = self.config.max_step_bound;
            let azuma =
                self.azuma_hoeffding_bound(steps_with_deltas, mean_net_progress, step_bound);
            let freedman_candidate =
                self.freedman_candidate_bound(steps_with_deltas, mean_net_progress, step_bound);
            (azuma, azuma.min(freedman_candidate))
        };

        let estimated_remaining = (telemetry_complete && mean_net_progress > self.config.epsilon)
            .then(|| v_current / mean_net_progress);

        // Select the range-only envelope for the projected horizon. Under the
        // conservative Q cap, this equals Azuma; retaining the explicit raw
        // Freedman candidate keeps that dominance auditable.
        let confidence_bound = estimated_remaining.map_or(0.0, |t_rem| {
            if !concentration_enabled {
                return 0.0;
            }
            if v_current <= self.config.epsilon {
                return 1.0;
            }
            // Project across twice the plug-in remaining-step estimate.
            #[allow(clippy::cast_sign_loss)]
            let extra = (2.0 * t_rem).ceil().max(0.0) as usize;
            let total_t = steps_with_deltas.saturating_add(extra);
            let step_bound = self.config.max_step_bound;
            let azuma = self.azuma_hoeffding_bound(total_t, mean_net_progress, step_bound);
            let freedman_candidate =
                self.freedman_candidate_bound(total_t, mean_net_progress, step_bound);
            let tail = azuma.min(freedman_candidate);
            (1.0 - tail).clamp(0.0, 1.0)
        });

        let stall_detected = self.stall_run >= self.config.stall_threshold;

        // `converging` is an empirical status over the complete accepted
        // finite non-negative observation history represented by running statistics. The
        // current-horizon candidates cannot gate it: using this history's own
        // mean net progress gives
        // t·mean_net_progress = V₀ - Vₜ, hence lambda = max(0, -Vₜ) = 0
        // for every accepted non-negative potential and both tails equal 1.
        // The rebound count, magnitude, and recency thresholds are operator
        // policy, not statistical confidence levels.
        let violation_rate = if steps_with_deltas > 0 {
            self.increase_count as f64 / steps_with_deltas as f64
        } else {
            0.0
        };
        let (_, rebound_to_net) = self.rebound_diagnostics(v_initial, v_current);
        let latest_step_non_increasing = self
            .last_delta
            .is_some_and(|delta| delta <= self.config.epsilon);
        let converging = mean_net_progress > self.config.epsilon
            && !stall_detected
            && violation_rate <= MAX_EMPIRICAL_REBOUND_RATE
            && rebound_to_net.is_some_and(|ratio| ratio <= MAX_EMPIRICAL_REBOUND_TO_NET_RATIO)
            && latest_step_non_increasing
            && telemetry_complete;

        let evidence = self.build_evidence(
            n,
            v_initial,
            v_current,
            steps_with_deltas,
            mean_credit,
            mean_net_progress,
            azuma,
            stall_detected,
            step_bound_violated,
        );

        CertificateVerdict {
            converging,
            estimated_remaining_steps: estimated_remaining,
            confidence_bound,
            stall_detected,
            azuma_bound: azuma,
            total_steps: n,
            current_potential: v_current,
            initial_potential: v_initial,
            mean_credit,
            max_observed_step: self.max_abs_delta,
            freedman_bound: freedman,
            drain_phase: self.drain_phase(),
            empirical_variance: self.delta_variance(),
            evidence,
        }
    }

    /// Builds the auditable evidence trail for a verdict.
    #[allow(clippy::too_many_arguments, clippy::cast_precision_loss)]
    fn build_evidence(
        &self,
        n: usize,
        v_initial: f64,
        v_current: f64,
        steps_with_deltas: usize,
        mean_credit: f64,
        mean_net_progress: f64,
        azuma: f64,
        stall_detected: bool,
        step_bound_violated: bool,
    ) -> Vec<EvidenceEntry> {
        let mut evidence = Vec::new();
        let last_step = n - 1;

        if let Some(entry) = self.invalid_sample_evidence(last_step, v_current) {
            evidence.push(entry);
        }

        // Step bound exceeded.
        if step_bound_violated {
            let max_obs = self.max_abs_delta;
            let configured = self.config.max_step_bound;
            // Keep the historical evidence value in [0, 1]. Surface the
            // observed step magnitude in the description rather than mixing
            // incompatible units in the numeric field.
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: azuma,
                description: format!(
                    "configured step bound {configured:.4} was exceeded by observed step \
                     {max_obs:.4}; concentration bounds disabled",
                ),
            });
        }

        // Quiescence is actionable only when no telemetry was dropped.
        if self.invalid_observation_count == 0 && v_current <= self.config.epsilon {
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: 0.0,
                description: "quiescence reached (V ≈ 0)".to_owned(),
            });
        }

        // Stall evidence.
        if stall_detected {
            let run = self.stall_run;
            let threshold = self.config.stall_threshold;
            // Keep the historical evidence value in [0, 1] and surface the
            // run length through the description instead.
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: azuma.clamp(0.0, 1.0),
                description: format!(
                    "stall: {run} consecutive non-decreasing steps (threshold: {threshold})",
                ),
            });
        }

        // Monotonicity violations.
        if self.increase_count > 0 {
            let violation_rate = self.increase_count as f64 / steps_with_deltas as f64;
            let count = self.increase_count;
            let (total_rebound, rebound_to_net) = self.rebound_diagnostics(v_initial, v_current);
            let latest_delta = self.last_delta.unwrap_or(0.0);
            let recency_status = if latest_delta <= self.config.epsilon {
                "pass"
            } else {
                "fail"
            };
            let rebound_detail = rebound_to_net.map_or_else(
                || format!("total rebound: {total_rebound:.4}; no positive net progress"),
                |ratio| {
                    format!(
                        "total rebound: {total_rebound:.4}, rebound/net: {ratio:.4}, \
                         limit: {MAX_EMPIRICAL_REBOUND_TO_NET_RATIO:.4}",
                    )
                },
            );
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: violation_rate,
                description: format!(
                    "{count} monotonicity violations out of {steps_with_deltas} steps \
                     (rate: {violation_rate:.4}, empirical limit: \
                     {MAX_EMPIRICAL_REBOUND_RATE:.4}; {rebound_detail}; latest delta: \
                     {latest_delta:.4}, required <= {epsilon:.4}, recency gate: \
                     {recency_status})",
                    epsilon = self.config.epsilon,
                ),
            });
        }

        // Signed progress summary with the Azuma baseline.
        let total_progress = v_initial - v_current;
        evidence.push(EvidenceEntry {
            step: last_step,
            potential: v_current,
            bound: azuma,
            description: format!(
                "total progress {total_progress:.4} over {steps_with_deltas} steps, \
                 mean net progress {mean_net_progress:.4}/step, gross credit \
                 {mean_credit:.4}/step, Azuma tail P \u{2264} {azuma:.6}",
            ),
        });

        evidence
    }

    /// Returns the number of retained observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns whether no accepted observation or dropped-sample diagnostic
    /// has been recorded since construction or reset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_observations == 0 && self.invalid_observation_count == 0
    }

    /// Returns retained observation history (possibly compacted).
    #[must_use]
    pub fn observations(&self) -> &[ProgressObservation] {
        &self.observations
    }

    /// Returns the total number of observations recorded since last reset.
    ///
    /// Unlike [`len`](Self::len), this count is not reduced by
    /// [`compact`](Self::compact).
    #[must_use]
    pub fn total_observations(&self) -> usize {
        self.total_observations
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &ProgressConfig {
        &self.config
    }

    /// Returns the gross-credit-accounted potential
    /// `V(Σₜ) + Σ max(0, -Δᵢ)`.
    ///
    /// Despite the historical method name, this is a deterministic gross-flow
    /// diagnostic. Algebraically it equals `V(Σ₀) + Σ max(Δᵢ, 0)`, so it is
    /// pathwise nondecreasing and is not used as probability evidence.
    #[must_use]
    pub fn martingale_value(&self) -> f64 {
        let v = self.last_potential.unwrap_or(0.0);
        v + self.total_credit
    }

    /// Returns the total accumulated credit.
    #[must_use]
    pub fn total_credit(&self) -> f64 {
        self.total_credit
    }

    /// Returns the number of monotonicity violations observed.
    #[must_use]
    pub fn increase_count(&self) -> usize {
        self.increase_count
    }

    /// Discards observations older than `keep_last`, preserving
    /// sufficient statistics (totals, max, counts).
    ///
    /// This does NOT alter the statistical summaries — verdicts
    /// computed after compaction use the same totals as before.
    /// Only the per-step audit trail is truncated.
    pub fn compact(&mut self, keep_last: usize) {
        if self.observations.len() <= keep_last {
            return;
        }
        let drain_count = self.observations.len() - keep_last;
        self.observations.drain(..drain_count);
    }

    /// Resets the certificate to its initial (empty) state.
    pub fn reset(&mut self) {
        self.observations.clear();
        self.total_observations = 0;
        self.total_deltas = 0;
        self.initial_potential = None;
        self.last_potential = None;
        self.last_delta = None;
        self.sum_delta = 0.0;
        self.total_credit = 0.0;
        self.sum_delta_sq = 0.0;
        self.max_abs_delta = 0.0;
        self.increase_count = 0;
        self.stall_run = 0;
        self.ema_credit = 0.0;
        self.invalid_observation_count = 0;
    }

    /// Returns the empirical variance of the per-step deltas for diagnostics.
    ///
    /// Uses the biased estimator `(1/n) Σ(Δᵢ - μ)²` where `n` is
    /// the number of deltas (observations − 1). Returns `None` if
    /// fewer than 2 observations exist. This realized statistic is not used
    /// as predictable quadratic variation in the concentration bounds.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn delta_variance(&self) -> Option<f64> {
        if self.total_deltas == 0 {
            return None;
        }
        let steps = self.total_deltas as f64;
        let mean_delta = self.sum_delta / steps;

        // Var = E[Δ²] - (E[Δ])²
        let mean_sq = self.sum_delta_sq / steps;
        let variance = mean_delta.mul_add(-mean_delta, mean_sq);
        // Clamp numerical noise AND NaN (inf - inf from overflow) to 0.0.
        // NaN.max(0.0) returns NaN per IEEE 754, so we must check explicitly.
        Some(if variance.is_finite() && variance > 0.0 {
            variance
        } else {
            0.0
        })
    }

    /// Returns the gross-credit-accounted potential divided by `V(Σ₀)`.
    ///
    /// Despite the historical method name, this is a deterministic rebound
    /// diagnostic, not a supermartingale test. A value of `1` means no gross
    /// upward movement has occurred; values above `1` measure accumulated
    /// rebounds relative to the initial potential. Zero initial potential uses
    /// the conventional neutral value `1`.
    #[must_use]
    pub fn martingale_ratio(&self) -> f64 {
        let v0 = self.initial_potential.unwrap_or(0.0);
        if v0 <= 0.0 {
            return 1.0;
        }
        self.martingale_value() / v0
    }

    /// Returns gross upward rebound and its ratio to positive net endpoint
    /// progress for the accepted observation history.
    fn rebound_diagnostics(&self, v_initial: f64, v_current: f64) -> (f64, Option<f64>) {
        let raw_rebound = self.martingale_value() - v_initial;
        let total_rebound = if raw_rebound.is_finite() {
            raw_rebound.max(0.0)
        } else {
            f64::INFINITY
        };
        let net_progress = (v_initial - v_current).max(0.0);
        let rebound_to_net =
            (net_progress > self.config.epsilon).then(|| total_rebound / net_progress);
        (total_rebound, rebound_to_net)
    }

    fn invalid_sample_evidence(
        &self,
        step: usize,
        current_potential: f64,
    ) -> Option<EvidenceEntry> {
        (self.invalid_observation_count > 0).then(|| EvidenceEntry {
            step,
            potential: current_potential,
            bound: 1.0,
            description: format!(
                "dropped {} invalid potential sample(s); certificate ignored them instead of treating them as progress",
                self.invalid_observation_count
            ),
        })
    }

    /// Returns the number of dropped invalid potential samples.
    #[must_use]
    pub fn invalid_observation_count(&self) -> usize {
        self.invalid_observation_count
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops
)]
#[path = "progress_certificate_inline_tests.rs"]
mod tests;
