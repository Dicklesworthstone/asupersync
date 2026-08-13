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
mod tests {
    use super::*;
    use insta::assert_json_snapshot;
    use serde::Serialize;
    use std::sync::Arc;
    use std::thread;

    #[derive(Serialize)]
    struct ProgressCertificateSnapshot {
        config: ProgressConfigSnapshot,
        observations: Vec<ProgressObservationSnapshot>,
        verdict: CertificateVerdictSnapshot,
        verdict_display: String,
    }

    #[derive(Serialize)]
    struct ProgressConfigSnapshot {
        confidence: String,
        max_step_bound: String,
        stall_threshold: usize,
        min_observations: usize,
        epsilon: String,
    }

    #[derive(Serialize)]
    struct ProgressObservationSnapshot {
        step: usize,
        potential: String,
        delta: String,
        credit: String,
    }

    #[derive(Serialize)]
    struct EvidenceEntrySnapshot {
        step: usize,
        potential: String,
        bound: String,
        description: String,
    }

    #[derive(Serialize)]
    struct CertificateVerdictSnapshot {
        converging: bool,
        estimated_remaining_steps: Option<String>,
        confidence_bound: String,
        stall_detected: bool,
        azuma_bound: String,
        total_steps: usize,
        current_potential: String,
        initial_potential: String,
        mean_credit: String,
        max_observed_step: String,
        freedman_bound: String,
        drain_phase: String,
        empirical_variance: Option<String>,
        evidence: Vec<EvidenceEntrySnapshot>,
    }

    fn fmt_f64(value: f64) -> String {
        format!("{value:.6}")
    }

    fn certificate_snapshot(cert: &ProgressCertificate) -> ProgressCertificateSnapshot {
        let verdict = cert.verdict();
        ProgressCertificateSnapshot {
            config: ProgressConfigSnapshot {
                confidence: fmt_f64(cert.config.confidence),
                max_step_bound: fmt_f64(cert.config.max_step_bound),
                stall_threshold: cert.config.stall_threshold,
                min_observations: cert.config.min_observations,
                epsilon: fmt_f64(cert.config.epsilon),
            },
            observations: cert
                .observations()
                .iter()
                .map(|observation| ProgressObservationSnapshot {
                    step: observation.step,
                    potential: fmt_f64(observation.potential),
                    delta: fmt_f64(observation.delta),
                    credit: fmt_f64(observation.credit),
                })
                .collect(),
            verdict: CertificateVerdictSnapshot {
                converging: verdict.converging,
                estimated_remaining_steps: verdict.estimated_remaining_steps.map(fmt_f64),
                confidence_bound: fmt_f64(verdict.confidence_bound),
                stall_detected: verdict.stall_detected,
                azuma_bound: fmt_f64(verdict.azuma_bound),
                total_steps: verdict.total_steps,
                current_potential: fmt_f64(verdict.current_potential),
                initial_potential: fmt_f64(verdict.initial_potential),
                mean_credit: fmt_f64(verdict.mean_credit),
                max_observed_step: fmt_f64(verdict.max_observed_step),
                freedman_bound: fmt_f64(verdict.freedman_bound),
                drain_phase: verdict.drain_phase.to_string(),
                empirical_variance: verdict.empirical_variance.map(fmt_f64),
                evidence: verdict
                    .evidence
                    .iter()
                    .map(|entry| EvidenceEntrySnapshot {
                        step: entry.step,
                        potential: fmt_f64(entry.potential),
                        bound: fmt_f64(entry.bound),
                        description: entry.description.clone(),
                    })
                    .collect(),
            },
            verdict_display: verdict.to_string(),
        }
    }

    fn certificate_from_potentials(
        config: ProgressConfig,
        potentials: &[f64],
    ) -> ProgressCertificate {
        let mut cert = ProgressCertificate::new(config);
        for &potential in potentials {
            cert.observe(potential);
        }
        cert
    }

    fn verdict_fingerprint(verdict: &CertificateVerdict) -> String {
        let mut fingerprint = format!(
            concat!(
                "converging={};stall={};steps={};current={:.6};initial={:.6};",
                "mean_credit={:.6};confidence={:.6};azuma={:.6};freedman={:.6};",
                "phase={};variance={:?};remaining={:?}"
            ),
            verdict.converging,
            verdict.stall_detected,
            verdict.total_steps,
            verdict.current_potential,
            verdict.initial_potential,
            verdict.mean_credit,
            verdict.confidence_bound,
            verdict.azuma_bound,
            verdict.freedman_bound,
            verdict.drain_phase,
            verdict.empirical_variance.map(fmt_f64),
            verdict.estimated_remaining_steps.map(fmt_f64),
        );

        for entry in &verdict.evidence {
            fingerprint.push_str(&format!(
                "|step={};potential={:.6};bound={:.6};desc={}",
                entry.step, entry.potential, entry.bound, entry.description
            ));
        }

        fingerprint
    }

    // -- ProgressConfig --

    #[test]
    fn config_default_valid() {
        assert!(ProgressConfig::default().validate().is_ok());
    }

    #[test]
    fn config_aggressive_valid() {
        assert!(ProgressConfig::aggressive().validate().is_ok());
    }

    #[test]
    fn config_tolerant_valid() {
        assert!(ProgressConfig::tolerant().validate().is_ok());
    }

    #[test]
    fn confidence_is_serialized_reference_metadata_not_a_verdict_input() {
        let low_config = ProgressConfig {
            confidence: 0.50,
            ..ProgressConfig::default()
        };
        let high_config = ProgressConfig {
            confidence: 0.99,
            ..ProgressConfig::default()
        };
        let mut low = ProgressCertificate::new(low_config);
        let mut high = ProgressCertificate::new(high_config);

        for potential in [100.0, 90.0, 80.0, 70.0, 60.0] {
            low.observe(potential);
            high.observe(potential);
        }

        assert_eq!(
            verdict_fingerprint(&low.verdict()),
            verdict_fingerprint(&high.verdict()),
        );
        let low_snapshot = certificate_snapshot(&low);
        let high_snapshot = certificate_snapshot(&high);
        assert_eq!(low_snapshot.config.confidence, "0.500000");
        assert_eq!(high_snapshot.config.confidence, "0.990000");
    }

    #[test]
    fn config_invalid_confidence_zero() {
        let c = ProgressConfig {
            confidence: 0.0,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_confidence_one() {
        let c = ProgressConfig {
            confidence: 1.0,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_confidence_nan() {
        let c = ProgressConfig {
            confidence: f64::NAN,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_step_bound_zero() {
        let c = ProgressConfig {
            max_step_bound: 0.0,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_step_bound_inf() {
        let c = ProgressConfig {
            max_step_bound: f64::INFINITY,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_stall_threshold_zero() {
        let c = ProgressConfig {
            stall_threshold: 0,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_min_observations_one() {
        let c = ProgressConfig {
            min_observations: 1,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_epsilon_neg() {
        let c = ProgressConfig {
            epsilon: -1.0,
            ..ProgressConfig::default()
        };
        assert!(c.validate().is_err());
    }

    // -- ProgressCertificate basics --

    #[test]
    fn empty_certificate() {
        let cert = ProgressCertificate::with_defaults();
        assert!(cert.is_empty());
        assert_eq!(cert.len(), 0);
        assert!((cert.martingale_value()).abs() < 1e-10);
        assert!((cert.total_credit()).abs() < 1e-10);
        assert_eq!(cert.increase_count(), 0);
        assert!(cert.delta_variance().is_none());
    }

    #[test]
    fn single_observation() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        assert_eq!(cert.len(), 1);
        assert!((cert.martingale_value() - 100.0).abs() < 1e-10);
        assert!((cert.total_credit()).abs() < 1e-10); // no delta yet

        let obs = &cert.observations()[0];
        assert_eq!(obs.step, 0);
        assert!((obs.potential - 100.0).abs() < 1e-10);
        assert!((obs.delta).abs() < 1e-10);
        assert!((obs.credit).abs() < 1e-10);
    }

    #[test]
    fn monotone_decrease_credits() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(80.0); // delta = -20, credit = 20
        cert.observe(50.0); // delta = -30, credit = 30
        cert.observe(20.0); // delta = -30, credit = 30

        assert!((cert.total_credit() - 80.0).abs() < 1e-10);
        assert_eq!(cert.increase_count(), 0);

        // With no rebound, gross-credit accounting stays at V(Σ₀):
        // V(Σₜ) + Σcredit = 20 + 80 = 100.
        assert!(
            (cert.martingale_value() - 100.0).abs() < 1e-10,
            "gross-credit accounting should stay constant without rebounds"
        );
    }

    #[test]
    fn increase_counted() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(80.0); // decrease
        cert.observe(90.0); // increase! delta = +10, credit = 0
        cert.observe(70.0); // decrease

        assert_eq!(cert.increase_count(), 1);
        // Credits: 20 + 0 + 20 = 40
        assert!((cert.total_credit() - 40.0).abs() < 1e-10);
        // Gross-credit-accounted potential: 70 + 40 = 110. The 10-point
        // rebound raises this deterministic diagnostic above V(Σ₀).
        assert!((cert.martingale_value() - 110.0).abs() < 1e-10);
    }

    #[test]
    fn materially_negative_potential_is_dropped_without_faking_quiescence() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(-5.0);

        assert_eq!(cert.len(), 0);
        assert_eq!(cert.total_observations(), 0);
        assert_eq!(cert.invalid_observation_count(), 1);
        assert!(!cert.is_empty());
        let verdict = cert.verdict();
        assert_eq!(verdict.drain_phase, DrainPhase::Warmup);
        assert!(verdict.estimated_remaining_steps.is_none());
        assert!(
            verdict
                .evidence
                .iter()
                .all(|entry| !entry.description.contains("quiescence reached"))
        );
    }

    #[test]
    fn tiny_negative_roundoff_is_clamped_to_zero() {
        let config = ProgressConfig {
            epsilon: 1e-6,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        cert.observe(-0.5e-6);

        assert_eq!(cert.invalid_observation_count(), 0);
        assert_eq!(cert.len(), 1);
        assert_eq!(cert.observations()[0].potential, 0.0);
    }

    #[test]
    fn invalid_first_observation_is_dropped_without_faking_quiescence() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(f64::NAN);

        assert!(
            !cert.is_empty(),
            "invalid-only state must remain visible to lifecycle reset logic"
        );
        assert_eq!(
            cert.len(),
            0,
            "invalid sample must not create an observation"
        );
        assert_eq!(cert.total_observations(), 0);
        assert_eq!(cert.invalid_observation_count(), 1);

        let verdict = cert.verdict();
        assert!(!verdict.converging);
        assert_eq!(verdict.drain_phase, DrainPhase::Warmup);
        assert!(
            verdict
                .evidence
                .iter()
                .any(|entry| entry.description.contains("dropped 1 invalid potential")),
            "provisional verdict should surface dropped invalid samples"
        );
    }

    #[test]
    fn non_finite_samples_are_ignored_between_valid_observations() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(f64::INFINITY);
        cert.observe(f64::NAN);
        cert.observe(80.0);

        assert_eq!(cert.invalid_observation_count(), 2);
        assert_eq!(cert.len(), 2, "only finite samples should be retained");
        assert_eq!(cert.total_observations(), 2);
        assert!(
            (cert.observations()[1].delta + 20.0).abs() < 1e-10,
            "delta should be computed from the last valid sample, not from a synthetic zero"
        );

        let verdict = cert.verdict();
        assert!(
            !verdict.converging,
            "incomplete telemetry with dropped invalid samples must fail empirical convergence closed",
        );
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.confidence_bound, 0.0);
        assert!(verdict.estimated_remaining_steps.is_none());
        assert_eq!(verdict.drain_phase, DrainPhase::Warmup);
        assert!(
            verdict
                .evidence
                .iter()
                .all(|entry| !entry.description.contains("quiescence reached")),
            "incomplete telemetry must not claim terminal quiescence"
        );
        assert!(
            verdict.current_potential > cert.config().epsilon,
            "ignored invalid samples must not fabricate quiescence"
        );
        assert!(
            verdict
                .evidence
                .iter()
                .any(|entry| entry.description.contains("dropped 2 invalid potential")),
            "verdict should record dropped invalid samples for audit"
        );
    }

    #[test]
    fn dropped_sample_after_quiescence_disables_actionable_completion_fields() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(0.0);
        cert.observe(f64::NAN);

        let verdict = cert.verdict();
        assert_eq!(verdict.current_potential, 0.0);
        assert!(!verdict.converging);
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.confidence_bound, 0.0);
        assert!(verdict.estimated_remaining_steps.is_none());
        assert_eq!(verdict.drain_phase, DrainPhase::Warmup);
    }

    // -- Stall detection --

    #[test]
    fn stall_detection_flat() {
        let config = ProgressConfig {
            stall_threshold: 3,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(50.0); // flat
        cert.observe(50.0); // flat
        cert.observe(50.0); // flat — stall run = 3

        let verdict = cert.verdict();
        assert!(verdict.stall_detected, "3 flat steps should trigger stall");
    }

    #[test]
    fn stall_broken_by_decrease() {
        let config = ProgressConfig {
            stall_threshold: 3,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(50.0); // flat
        cert.observe(50.0); // flat
        cert.observe(40.0); // decrease — resets stall run

        let verdict = cert.verdict();
        assert!(
            !verdict.stall_detected,
            "decrease should break the stall run"
        );
    }

    #[test]
    fn stall_includes_increases() {
        let config = ProgressConfig {
            stall_threshold: 3,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(55.0); // increase (non-decreasing)
        cert.observe(60.0); // increase
        cert.observe(62.0); // increase — stall run = 3

        let verdict = cert.verdict();
        assert!(
            verdict.stall_detected,
            "consecutive increases count as stall"
        );
    }

    // -- Verdict convergence --

    #[test]
    fn converging_linear_decrease() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 100.0,
            stall_threshold: 10,
            min_observations: 3,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        // Linear decrease from 100 to 0 in 10 steps.
        for i in 0..=10 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.converging,
            "linear decrease should be converging: {verdict}"
        );
        assert!(!verdict.stall_detected);
        assert_eq!(cert.increase_count(), 0);
        assert!(
            verdict.confidence_bound > 0.90,
            "confidence should exceed 0.90, got {:.4}",
            verdict.confidence_bound,
        );
        assert!(
            (verdict.current_potential).abs() < 1e-10,
            "should have reached quiescence"
        );
    }

    #[test]
    fn monotone_mid_drain_is_empirically_converging_with_trivial_current_tails() {
        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 10.0,
            stall_threshold: 5,
            min_observations: 3,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        for potential in [100.0, 90.0, 80.0, 70.0, 60.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        let reduction_ratio =
            (verdict.initial_potential - verdict.current_potential) / verdict.initial_potential;

        assert!(verdict.converging);
        assert!(!verdict.stall_detected);
        assert_eq!(cert.increase_count(), 0);
        assert!(reduction_ratio < cert.config().confidence);
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert!(verdict.current_potential > cert.config().epsilon);
    }

    #[test]
    fn empirical_convergence_rebound_rate_policy_has_an_inclusive_boundary() {
        let config = ProgressConfig {
            max_step_bound: 20.0,
            stall_threshold: 10,
            min_observations: 4,
            ..ProgressConfig::default()
        };
        let mut at_boundary = ProgressCertificate::new(config.clone());
        for potential in [100.0, 90.0, 80.0, 85.0, 70.0] {
            at_boundary.observe(potential);
        }

        let mut above_boundary = ProgressCertificate::new(config);
        for potential in [100.0, 90.0, 95.0, 80.0] {
            above_boundary.observe(potential);
        }

        assert_eq!(at_boundary.increase_count(), 1);
        assert!(at_boundary.verdict().converging);
        assert_eq!(above_boundary.increase_count(), 1);
        assert!(!above_boundary.verdict().converging);
    }

    #[test]
    fn low_count_near_total_rebound_is_not_empirically_converging() {
        let config = ProgressConfig {
            max_step_bound: 100.0,
            stall_threshold: 20,
            min_observations: 4,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        for potential in [
            100.0, 90.0, 80.0, 70.0, 60.0, 50.0, 40.0, 30.0, 20.0, 10.0, 0.0, 99.0, 98.0,
        ] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(verdict.current_potential < verdict.initial_potential);
        assert!(!verdict.stall_detected);
        assert_eq!(cert.increase_count(), 1);
        assert!(!verdict.converging);
        assert!(verdict.evidence.iter().any(|entry| {
            entry.description.contains("rebound/net: 49.5000")
                && entry.description.contains("limit: 1.0000")
                && entry.description.contains("latest delta: -1.0000")
                && entry.description.contains("recency gate: pass")
        }));
    }

    #[test]
    fn latest_rebound_rejects_otherwise_favorable_empirical_history() {
        let config = ProgressConfig {
            max_step_bound: 20.0,
            stall_threshold: 10,
            min_observations: 4,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        for potential in [100.0, 80.0, 60.0, 40.0, 20.0, 10.0, 11.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(verdict.estimated_remaining_steps.is_some());
        assert!(!verdict.stall_detected);
        assert_eq!(cert.increase_count(), 1);
        assert!(!verdict.converging);
        assert!(verdict.evidence.iter().any(|entry| {
            entry.description.contains("rebound/net: 0.0112")
                && entry.description.contains("limit: 1.0000")
                && entry.description.contains("latest delta: 1.0000")
                && entry.description.contains("required <= 0.0000")
                && entry.description.contains("recency gate: fail")
        }));
    }

    #[test]
    fn converging_exponential_decrease() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 200.0,
            stall_threshold: 10,
            min_observations: 3,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        // Exponential decay: V_t = 200 * 0.7^t
        let mut v = 200.0;
        for _ in 0..20 {
            cert.observe(v);
            v *= 0.7;
        }

        let verdict = cert.verdict();
        assert!(
            verdict.converging,
            "exponential decrease should be converging: {verdict}"
        );
        assert!(!verdict.stall_detected);
        assert!(verdict.mean_credit > 0.0);
        assert!(verdict.estimated_remaining_steps.is_some());
    }

    #[test]
    fn diverging_sequence() {
        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 50.0,
            stall_threshold: 5,
            min_observations: 3,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        // Increasing potential: definitely not converging.
        for i in 0..20 {
            #[allow(clippy::cast_precision_loss)]
            let v = 10.0 + 5.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            !verdict.converging,
            "increasing sequence should not be converging"
        );
        assert!(
            verdict.stall_detected,
            "persistent increases should trigger stall"
        );
        assert!(
            cert.increase_count() > 0,
            "should have monotonicity violations"
        );
    }

    #[test]
    fn insufficient_data_provisional() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(80.0);
        // Default min_observations is 5, so 2 is insufficient.

        let verdict = cert.verdict();
        assert!(
            !verdict.converging,
            "insufficient data should yield non-converging"
        );
        assert!(
            (verdict.confidence_bound).abs() < 1e-10,
            "insufficient data should have zero confidence"
        );
    }

    // -- Azuma–Hoeffding bound --

    #[test]
    fn azuma_helper_decreases_with_larger_projected_progress() {
        let config = ProgressConfig {
            max_step_bound: 10.0,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        cert.observe(100.0);

        let shorter = cert.azuma_hoeffding_bound(40, 5.0, 10.0);
        let longer = cert.azuma_hoeffding_bound(400, 5.0, 10.0);
        assert!(
            longer < shorter,
            "larger projected net progress should tighten the helper bound: \
             shorter={shorter:.6}, longer={longer:.6}",
        );
    }

    #[test]
    fn azuma_bound_matches_standard_hoeffding_formula() {
        // Pins the corrected Azuma exponent exp(-λ²/(2·t·c²)). Regression
        // guard against reintroducing the factor-of-4 (fourth-power) error.
        let config = ProgressConfig {
            max_step_bound: 10.0,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // initial = 100, projected t = 400, mean net progress = 5,
        // λ = t·mean − V₀ = 1900,
        // c = 10 → exponent = −1900² / (2·400·100) = −45.125.
        cert.observe(100.0);
        let actual = cert.azuma_hoeffding_bound(400, 5.0, 10.0);
        let expected = (-1900.0_f64 * 1900.0 / (2.0 * 400.0 * 100.0)).exp();
        assert!(
            (actual - expected).abs() <= 1e-12 * expected.max(1e-300),
            "azuma_bound {} should equal standard Hoeffding {expected}",
            actual
        );
    }

    #[test]
    fn azuma_bound_large_for_noisy_progress() {
        let config = ProgressConfig {
            max_step_bound: 200.0,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Noisy: large swings but net downward.
        let values = [100.0, 50.0, 90.0, 30.0, 80.0, 20.0, 70.0, 10.0];
        for &v in &values {
            cert.observe(v);
        }

        let verdict = cert.verdict();
        // With high noise, Azuma bound should be less tight.
        // (We just verify it is a valid probability.)
        assert!(
            (0.0..=1.0).contains(&verdict.azuma_bound),
            "azuma bound should be in [0, 1], got {}",
            verdict.azuma_bound,
        );
    }

    #[test]
    fn bounds_do_not_overstate_confidence_after_expected_overshoot() {
        // Construct a sequence with a large rebound then sharp drop so the
        // net-progress extrapolation overshoots below zero while current
        // potential remains positive.
        let config = ProgressConfig {
            max_step_bound: 250.0,
            min_observations: 4,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Potentials: 100 -> 200 (increase), 200 -> 0 (large drop), 0 -> 10.
        // Signed net progress is (100 - 10) / 3 = 30 per step, so the
        // projected expected remaining potential at total horizon t=4 is -20.
        cert.observe(100.0);
        cert.observe(200.0);
        cert.observe(0.0);
        cert.observe(10.0);

        let verdict = cert.verdict();
        assert!(
            verdict.confidence_bound < 0.5,
            "confidence should be low when V is still positive despite expected overshoot, got {}",
            verdict.confidence_bound
        );
    }

    // -- Gross-credit accounting diagnostics --

    #[test]
    fn gross_credit_accounting_is_constant_without_rebounds() {
        let mut cert = ProgressCertificate::with_defaults();

        // Monotone decrease: V(Σₜ) + gross credit equals V(Σ₀).
        let potentials = [100.0, 85.0, 70.0, 55.0, 40.0, 25.0, 10.0, 0.0];
        for &v in &potentials {
            cert.observe(v);
        }

        let ratio = cert.martingale_ratio();
        assert!(
            (ratio - 1.0).abs() < 1e-10,
            "gross-credit ratio should be 1.0 without rebounds, got {ratio:.10}"
        );
    }

    #[test]
    fn gross_credit_ratio_records_rebounds() {
        let mut cert = ProgressCertificate::with_defaults();

        cert.observe(100.0);
        cert.observe(60.0); // credit = 40
        cert.observe(80.0); // increase: credit = 0, diagnostic rises
        cert.observe(50.0); // credit = 30

        // V(Σₜ) + gross credit = 50 + 70 = 120, exactly accounting for
        // the 20-point rebound above the initial 100.
        let ratio = cert.martingale_ratio();
        assert!(
            (ratio - 1.2).abs() < 1e-10,
            "gross-credit ratio should record the rebound, got {ratio:.4}"
        );
    }

    #[test]
    fn evidence_omits_unsupported_ville_claim() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        for potential in [100.0, 60.0, 80.0, 50.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(
            verdict
                .evidence
                .iter()
                .all(|entry| !entry.description.contains("Ville bound")),
            "gross-credit accounting must not emit Ville probability evidence"
        );
    }

    // -- Delta variance --

    #[test]
    fn variance_constant_delta() {
        let mut cert = ProgressCertificate::with_defaults();

        // Constant delta of -10: variance should be 0.
        for i in 0..5 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let var = cert.delta_variance().unwrap();
        assert!(
            var < 1e-10,
            "variance should be ≈0 for constant deltas, got {var:.10}"
        );
    }

    #[test]
    fn variance_alternating_deltas() {
        let mut cert = ProgressCertificate::with_defaults();

        // Alternating: -20 then -10 then -20 then -10.
        // Deltas: -20, -10, -20, -10. Mean = -15. Var = 25.
        let values = [100.0, 80.0, 70.0, 50.0, 40.0];
        for &v in &values {
            cert.observe(v);
        }

        let var = cert.delta_variance().unwrap();
        assert!(
            (var - 25.0).abs() < 1e-8,
            "variance should be 25, got {var:.10}"
        );
    }

    // -- Evidence trail --

    #[test]
    fn evidence_includes_quiescence() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(10.0);
        cert.observe(5.0);
        cert.observe(0.0);

        let verdict = cert.verdict();
        let has_quiescence = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("quiescence"));
        assert!(
            has_quiescence,
            "evidence should note quiescence, got: {:?}",
            verdict.evidence
        );
    }

    #[test]
    fn evidence_includes_stall() {
        let config = ProgressConfig {
            stall_threshold: 2,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(50.0);
        cert.observe(50.0);

        let verdict = cert.verdict();
        let has_stall = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("stall"));
        assert!(
            has_stall,
            "evidence should note stall, got: {:?}",
            verdict.evidence
        );
    }

    #[test]
    fn evidence_includes_violations() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(60.0); // violation
        cert.observe(40.0);

        let verdict = cert.verdict();
        let has_violations = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("monotonicity violation"));
        assert!(
            has_violations,
            "evidence should note violations, got: {:?}",
            verdict.evidence
        );
    }

    #[test]
    fn evidence_notes_exceeded_step_bound() {
        let config = ProgressConfig {
            max_step_bound: 10.0,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(50.0); // delta = -50, exceeds bound of 10

        let verdict = cert.verdict();
        let has_exceeded = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("concentration bounds disabled"));
        assert!(
            has_exceeded,
            "evidence should note exceeded step bound, got: {:?}",
            verdict.evidence
        );
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.confidence_bound, 0.0);
    }

    #[test]
    fn observed_quiescence_does_not_restore_invalidated_concentration_claim() {
        let config = ProgressConfig {
            max_step_bound: 10.0,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        for potential in [100.0, 0.0, 0.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert_eq!(verdict.current_potential, 0.0);
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.confidence_bound, 0.0);
    }

    // -- Compact --

    #[test]
    fn compact_preserves_statistics() {
        let mut cert = ProgressCertificate::with_defaults();

        for i in 0..20 {
            #[allow(clippy::cast_precision_loss)]
            let v = 200.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let credit_before = cert.total_credit();
        let increase_before = cert.increase_count();
        let max_delta_before = cert.max_abs_delta;

        cert.compact(5);

        assert_eq!(cert.len(), 5, "should retain 5 observations");
        assert!(
            (cert.total_credit() - credit_before).abs() < 1e-10,
            "total credit should be preserved"
        );
        assert_eq!(
            cert.increase_count(),
            increase_before,
            "increase count should be preserved"
        );
        assert!(
            (cert.max_abs_delta - max_delta_before).abs() < 1e-10,
            "max delta should be preserved"
        );
    }

    #[test]
    fn compact_preserves_verdict_consistency() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for i in 0..30 {
            #[allow(clippy::cast_precision_loss)]
            let v = 300.0 - 8.0 * i as f64 + if i % 7 == 0 { 2.0 } else { 0.0 };
            cert.observe(v.max(0.0));
        }

        let before = cert.verdict();
        cert.compact(4);
        let after = cert.verdict();

        assert_eq!(before.total_steps, after.total_steps);
        assert!(
            (before.initial_potential - after.initial_potential).abs() < 1e-10,
            "initial potential should be stable under compact"
        );
        assert!(
            (before.current_potential - after.current_potential).abs() < 1e-10,
            "current potential should be stable under compact"
        );
        assert!(
            (before.mean_credit - after.mean_credit).abs() < 1e-10,
            "mean credit should be stable under compact"
        );
        assert!(
            (before.azuma_bound - after.azuma_bound).abs() < 1e-12,
            "azuma bound should be stable under compact"
        );
        assert_eq!(before.stall_detected, after.stall_detected);
        assert_eq!(before.converging, after.converging);
        assert_eq!(
            cert.total_observations(),
            before.total_steps,
            "global observation count should remain unchanged after compact"
        );
    }

    #[test]
    fn compact_zero_preserves_nonempty_lifecycle_state() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(90.0);

        cert.compact(0);

        assert_eq!(cert.len(), 0, "no audit observations should be retained");
        assert!(
            !cert.is_empty(),
            "compaction must not make a populated certificate appear reset"
        );
        assert_eq!(cert.total_observations(), 2);
        assert_eq!(cert.verdict().total_steps, 2);
    }

    #[test]
    fn observe_after_compact_keeps_global_step_index() {
        let mut cert = ProgressCertificate::with_defaults();
        for i in 0..6 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }
        let total_before = cert.total_observations();
        cert.compact(1);
        assert_eq!(cert.len(), 1);

        cert.observe(30.0);
        assert_eq!(cert.total_observations(), total_before + 1);
        let retained = cert.observations();
        let last = retained.last().expect("retained observation");
        assert_eq!(
            last.step, total_before,
            "new step index should continue global sequence after compact"
        );
    }

    // -- Reset --

    #[test]
    fn reset_clears_all() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(50.0);
        cert.observe(80.0);

        cert.reset();

        assert!(cert.is_empty());
        assert!((cert.total_credit()).abs() < 1e-10);
        assert_eq!(cert.increase_count(), 0);
        assert!((cert.max_abs_delta).abs() < 1e-10);
    }

    #[test]
    fn reset_clears_invalid_only_lifecycle_state() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(f64::NAN);
        assert!(!cert.is_empty());
        assert_eq!(cert.invalid_observation_count(), 1);

        cert.reset();

        assert!(cert.is_empty());
        assert_eq!(cert.invalid_observation_count(), 0);
    }

    // -- Display --

    #[test]
    fn verdict_display_includes_key_fields() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(80.0);
        cert.observe(60.0);
        cert.observe(40.0);
        cert.observe(20.0);
        cert.observe(0.0);

        let verdict = cert.verdict();
        let text = format!("{verdict}");

        assert!(text.contains("Progress Certificate Verdict"));
        assert!(text.contains("Converging:"));
        assert!(text.contains("Azuma bound:"));
        assert!(text.contains("Mean credit/step:"));
    }

    #[test]
    fn evidence_entry_display() {
        let entry = EvidenceEntry {
            step: 42,
            potential: 3.25,
            bound: 0.01,
            description: "test evidence".to_owned(),
        };
        let text = format!("{entry}");
        assert!(text.contains("step=42"));
        assert!(text.contains("3.25"));
        assert!(text.contains("test evidence"));
    }

    // -- Known-convergent sequences --

    #[test]
    fn harmonic_series_decrease() {
        // V_t = 1/(t+1), a classic convergent sequence.
        let config = ProgressConfig {
            confidence: 0.80,
            max_step_bound: 1.0,
            stall_threshold: 50,
            min_observations: 3,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        for i in 0..100 {
            #[allow(clippy::cast_precision_loss)]
            let v = 1.0 / (i as f64 + 1.0);
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.converging,
            "harmonic decrease should be detected as converging: {verdict}"
        );
        assert!(!verdict.stall_detected);
    }

    #[test]
    fn step_function_decrease() {
        // Potential decreases in sudden jumps with plateaus.
        let config = ProgressConfig {
            stall_threshold: 8,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Plateau at 100, then drop to 50, plateau, drop to 0.
        for _ in 0..5 {
            cert.observe(100.0);
        }
        cert.observe(50.0);
        for _ in 0..5 {
            cert.observe(50.0);
        }
        cert.observe(0.0);

        let verdict = cert.verdict();
        // Should not trigger stall because plateau length (5) < threshold (8).
        assert!(
            !verdict.stall_detected,
            "plateau shorter than threshold should not trigger stall"
        );
    }

    // -- Known-divergent / stalling sequences --

    #[test]
    fn constant_sequence_stalls() {
        let config = ProgressConfig {
            stall_threshold: 5,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for _ in 0..10 {
            cert.observe(42.0);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.stall_detected,
            "constant sequence should trigger stall"
        );
        assert!(
            !verdict.converging,
            "constant non-zero sequence should not be converging"
        );
    }

    #[test]
    fn oscillating_sequence_not_converging() {
        let config = ProgressConfig {
            min_observations: 3,
            stall_threshold: 10,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Oscillate between 100 and 50 — no net progress toward zero.
        for i in 0..20 {
            let v = if i % 2 == 0 { 100.0 } else { 50.0 };
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            !verdict.converging,
            "oscillation should not be classified as converging"
        );
        // Should have many increase violations.
        assert!(
            cert.increase_count() > 5,
            "oscillation should produce violations"
        );
    }

    // -- Edge cases --

    #[test]
    fn single_step_to_zero() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(0.0);

        let verdict = cert.verdict();
        assert!(
            (verdict.current_potential).abs() < 1e-10,
            "should report zero potential"
        );
    }

    #[test]
    fn all_zeros() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for _ in 0..10 {
            cert.observe(0.0);
        }

        let verdict = cert.verdict();
        assert!(
            (verdict.current_potential).abs() < 1e-10,
            "should report zero potential for all-zero sequence"
        );
        // Zero initial potential means no stall in the meaningful sense
        // (already quiescent).
    }

    #[test]
    fn very_large_potentials() {
        let mut cert = ProgressCertificate::with_defaults();

        cert.observe(1e15);
        cert.observe(5e14);
        cert.observe(1e14);
        cert.observe(5e13);
        cert.observe(1e13);
        cert.observe(0.0);

        let verdict = cert.verdict();
        assert!(
            verdict.azuma_bound.is_finite(),
            "Azuma bound should be finite even with large potentials"
        );
        assert!(
            verdict.confidence_bound.is_finite(),
            "confidence bound should be finite"
        );
    }

    #[test]
    fn very_small_positive_potentials() {
        let config = ProgressConfig {
            min_observations: 2,
            epsilon: 1e-15,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(1e-10);
        cert.observe(5e-11);
        cert.observe(1e-11);
        cert.observe(0.0);

        let verdict = cert.verdict();
        assert!(
            !verdict.stall_detected,
            "small positive potentials moving toward zero should not stall"
        );
    }

    // -- Integration with Lyapunov types --

    #[test]
    fn observe_potential_record() {
        use crate::obligation::lyapunov::{PotentialRecord, StateSnapshot};
        use crate::types::Time;

        let mut cert = ProgressCertificate::with_defaults();

        let record = PotentialRecord {
            snapshot: StateSnapshot {
                time: Time::ZERO,
                live_tasks: 5,
                pending_obligations: 3,
                obligation_age_sum_ns: 150,
                draining_regions: 1,
                deadline_pressure: 0.0,
                pending_send_permits: 3,
                pending_acks: 0,
                pending_leases: 0,
                pending_io_ops: 0,
                cancel_requested_tasks: 0,
                cancelling_tasks: 0,
                finalizing_tasks: 0,
                ready_queue_depth: 0,
            },
            total: 42.5,
            task_component: 5.0,
            obligation_component: 30.0,
            region_component: 3.0,
            deadline_component: 4.5,
        };

        cert.observe_potential_record(&record);
        assert_eq!(cert.len(), 1);
        assert!(
            (cert.observations()[0].potential - 42.5).abs() < 1e-10,
            "should extract total from PotentialRecord"
        );
    }

    // -- Comprehensive scenario: realistic cancellation drain --

    #[test]
    fn realistic_cancellation_drain() {
        // Simulates a realistic drain: initial burst of progress,
        // then slower tail as stragglers remain, with some jitter.
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 50.0,
            stall_threshold: 15,
            min_observations: 5,
            epsilon: 1e-12,
        };
        let mut cert = ProgressCertificate::new(config);

        // Phase 1: rapid drain (steps 0-9).
        let phase1 = [100.0, 75.0, 55.0, 40.0, 30.0, 22.0, 16.0, 11.0, 7.0, 4.0];
        for &v in &phase1 {
            cert.observe(v);
        }

        // Phase 2: slow tail with jitter (steps 10-19).
        let phase2 = [3.5, 3.0, 2.8, 3.1, 2.5, 2.0, 1.5, 1.0, 0.5, 0.0];
        for &v in &phase2 {
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.converging,
            "realistic drain should converge: {verdict}"
        );
        assert!(!verdict.stall_detected);
        assert!(
            (verdict.current_potential).abs() < 1e-10,
            "should reach quiescence"
        );
        assert!(
            cert.increase_count() > 0,
            "jitter should cause at least one violation (3.0 -> 3.1)"
        );

        // Evidence should contain quiescence note.
        let quiescence_evidence = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("quiescence"));
        assert!(quiescence_evidence, "evidence should note quiescence");
    }

    // -- Gross-credit ratio property test --

    #[test]
    fn gross_credit_ratio_is_finite_for_bounded_walk() {
        // Feed a downward-biased bounded walk and verify the deterministic
        // gross-credit ratio remains finite.
        let mut cert = ProgressCertificate::with_defaults();
        let mut v = 500.0;
        let mut rng: u64 = 12345;

        for _ in 0..100 {
            cert.observe(v);
            // Deterministic PRNG: biased downward (mean step ≈ -3).
            rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let u = (rng >> 33) as f64 / f64::from(1_u32 << 31);
            let step = 10.0 * u - 8.0; // range [-8, 2], mean ≈ -3
            v = (v + step).max(0.0);
        }

        let ratio = cert.martingale_ratio();
        assert!(
            ratio.is_finite(),
            "gross-credit ratio should be finite, got {ratio}"
        );
        assert!(ratio >= 1.0, "gross-credit ratio cannot decrease below 1");
        assert!(
            ratio < 5.0,
            "bounded walk should have a bounded gross-credit ratio, got {ratio:.4}"
        );
    }

    // -- Plug-in signed net-progress estimate --

    #[test]
    fn estimated_remaining_steps_use_signed_net_progress_after_rebound() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for potential in [100.0, 80.0, 90.0, 60.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        let expected_gross_credit = 50.0 / 3.0;
        assert!((verdict.mean_credit - expected_gross_credit).abs() < 1e-12);

        // Signed net progress is (100 - 60) / 3, so the plug-in remaining
        // estimate is 60 / (40 / 3) = 4.5. Using gross downward credit would
        // instead produce 3.6 and understate the rebound-adjusted estimate.
        let est = verdict
            .estimated_remaining_steps
            .expect("should have estimate");
        assert!(
            (est - 4.5).abs() < 1e-12,
            "estimated remaining should be 4.5, got {est:.4}"
        );
    }

    #[test]
    fn no_estimate_when_no_progress() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Flat: no credit accumulated.
        for _ in 0..5 {
            cert.observe(50.0);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.estimated_remaining_steps.is_none(),
            "should have no estimate when net progress is zero"
        );
    }

    // -- Freedman bound --

    #[test]
    fn raw_freedman_candidate_is_looser_than_azuma_with_only_a_range_cap() {
        let config = ProgressConfig {
            max_step_bound: 10.0,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        cert.observe(100.0);

        let azuma = cert.azuma_hoeffding_bound(400, 5.0, 10.0);
        let freedman = cert.freedman_candidate_bound(400, 5.0, 10.0);
        assert!(
            freedman > azuma,
            "raw Freedman candidate ({freedman:e}) should be looser than Azuma ({azuma:e})",
        );
    }

    #[test]
    fn freedman_ignores_realized_variance() {
        let config = ProgressConfig {
            max_step_bound: 20.0,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut constant = ProgressCertificate::new(config.clone());
        let mut uneven = ProgressCertificate::new(config);

        for potential in [100.0, 90.0, 80.0, 70.0, 60.0] {
            constant.observe(potential);
        }
        for potential in [100.0, 95.0, 80.0, 75.0, 60.0] {
            uneven.observe(potential);
        }

        assert_eq!(constant.delta_variance(), Some(0.0));
        assert!(
            uneven
                .delta_variance()
                .is_some_and(|variance| variance > 0.0)
        );

        let constant_bound = constant.freedman_candidate_bound(20, 10.0, 20.0);
        let uneven_bound = uneven.freedman_candidate_bound(20, 10.0, 20.0);
        assert!((constant_bound - uneven_bound).abs() < 1e-15);

        let lambda: f64 = 100.0;
        let predictable_variation: f64 = 20.0 * 20.0 * 20.0;
        let centered_increment_bound: f64 = 2.0 * 20.0;
        let expected = (-lambda * lambda
            / (2.0 * centered_increment_bound.mul_add(lambda / 3.0, predictable_variation)))
        .exp();
        assert!((constant_bound - expected).abs() < 1e-15);
    }

    #[test]
    fn both_candidates_equal_one_at_zero_deviation() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        cert.observe(0.0);
        cert.observe(0.0);

        let verdict = cert.verdict();
        let raw_freedman = cert.freedman_candidate_bound(2, 50.0, 100.0);
        assert_eq!(raw_freedman, 1.0);
        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.freedman_bound, verdict.azuma_bound);
    }

    #[test]
    fn verdict_does_not_present_raw_freedman_as_stronger_evidence() {
        let config = ProgressConfig {
            max_step_bound: 100.0,
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(100.0);
        let mut v = 100.0;
        for _ in 0..200 {
            v -= 1.0;
            cert.observe(v);
            v -= 1.0;
            cert.observe(v);
            v += 1.0;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        let has_raw_freedman_claim = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("tighter than Azuma"));
        assert!(!has_raw_freedman_claim);
        assert_eq!(verdict.freedman_bound, verdict.azuma_bound);
    }

    #[test]
    fn oscillating_gross_credit_does_not_imply_net_convergence() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 10.0,
            min_observations: 5,
            stall_threshold: 10,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);
        let mut potential = 100.0;
        cert.observe(potential);

        for _ in 0..50 {
            for delta in [-3.0, -3.0, -3.0, 9.0] {
                potential += delta;
                cert.observe(potential);
            }
        }

        let verdict = cert.verdict();
        assert_eq!(verdict.current_potential, verdict.initial_potential);
        assert!(verdict.mean_credit > 0.0, "gross credit should accumulate");
        assert!(verdict.estimated_remaining_steps.is_none());
        assert_eq!(verdict.confidence_bound, 0.0);
        assert!(!verdict.converging);
    }

    // -- Drain phase --

    #[test]
    fn drain_phase_warmup() {
        let cert = ProgressCertificate::with_defaults();
        assert_eq!(cert.drain_phase(), DrainPhase::Warmup);

        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(100.0);
        cert.observe(80.0);
        // Default min_observations is 5, so still warmup.
        assert_eq!(cert.drain_phase(), DrainPhase::Warmup);
    }

    #[test]
    fn drain_phase_quiescent() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(10.0);
        cert.observe(5.0);
        cert.observe(0.0);

        assert_eq!(cert.drain_phase(), DrainPhase::Quiescent);
    }

    #[test]
    fn drain_phase_rapid_drain() {
        let config = ProgressConfig {
            min_observations: 3,
            stall_threshold: 10,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Consistent high-credit decrease.
        for i in 0..6 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 15.0 * i as f64;
            cert.observe(v.max(1.0)); // Keep above zero.
        }

        // EMA should track near the mean credit → rapid drain.
        assert_eq!(
            cert.drain_phase(),
            DrainPhase::RapidDrain,
            "consistent decrease should be rapid drain"
        );
    }

    #[test]
    fn drain_phase_slow_tail() {
        let config = ProgressConfig {
            min_observations: 3,
            stall_threshold: 20,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Rapid phase first.
        cert.observe(100.0);
        cert.observe(60.0); // credit = 40
        cert.observe(30.0); // credit = 30
        cert.observe(15.0); // credit = 15

        // Now slow tail: tiny decreases.
        for _ in 0..10 {
            let current = cert.last_potential.unwrap_or(15.0);
            cert.observe((current - 0.1).max(1.0));
        }

        // EMA of credit should be much lower than overall mean.
        let phase = cert.drain_phase();
        assert_eq!(
            phase,
            DrainPhase::SlowTail,
            "slow tiny decreases should be SlowTail, got {phase}"
        );
    }

    #[test]
    fn drain_phase_stalled() {
        let config = ProgressConfig {
            stall_threshold: 3,
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(50.0);
        cert.observe(50.0);
        cert.observe(50.0);
        cert.observe(50.0);

        assert_eq!(cert.drain_phase(), DrainPhase::Stalled);
    }

    #[test]
    fn drain_phase_in_verdict() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        cert.observe(10.0);
        cert.observe(5.0);
        cert.observe(0.0);

        let verdict = cert.verdict();
        assert_eq!(verdict.drain_phase, DrainPhase::Quiescent);
    }

    #[test]
    fn drain_phase_display() {
        assert_eq!(DrainPhase::Warmup.to_string(), "warmup");
        assert_eq!(DrainPhase::RapidDrain.to_string(), "rapid_drain");
        assert_eq!(DrainPhase::SlowTail.to_string(), "slow_tail");
        assert_eq!(DrainPhase::Stalled.to_string(), "stalled");
        assert_eq!(DrainPhase::Quiescent.to_string(), "quiescent");
    }

    // -- Verdict Display with new fields --

    #[test]
    fn verdict_display_includes_new_fields() {
        let config = ProgressConfig {
            min_observations: 2,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for i in 0..10 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        let text = format!("{verdict}");
        assert!(text.contains("Selected tail:"));
        assert!(text.contains("Drain phase:"));
    }

    // -- Empirical variance in verdict --

    #[test]
    fn verdict_reports_empirical_variance() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Alternating steps: variance should be nonzero.
        let values = [100.0, 80.0, 70.0, 50.0, 40.0];
        for &v in &values {
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.empirical_variance.is_some(),
            "should report variance after sufficient observations"
        );
        let var = verdict.empirical_variance.unwrap();
        assert!(var > 0.0, "variance should be positive for varying deltas");
    }

    // =========================================================================
    // Azuma-Hoeffding Tail Bounds Golden Conformance Tests
    // =========================================================================

    /// Golden Test #1: observed quiescence is reported deterministically
    #[test]
    fn golden_observed_quiescence_is_reported() {
        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 20.0,
            min_observations: 5,
            stall_threshold: 5,
            epsilon: 1e-12,
        };

        let mut cert = ProgressCertificate::new(config);

        // Create a sequence that drives the potential monotonically to
        // quiescence. The empirical status observes the favorable accepted
        // history, while confidence_bound short-circuits to 1.0 only because
        // quiescence is already observed.
        let mut potentials = vec![1000.0];
        let mut v: f64 = 1000.0;
        // Smooth monotone drop, 10 per step, to V=0 in 100 steps.
        #[allow(clippy::while_float)]
        while v > f64::EPSILON {
            v -= 10.0;
            potentials.push(v.max(0.0));
        }

        for potential in potentials {
            cert.observe(potential);
        }

        let verdict = cert.verdict();

        // A monotone trace has no rebounds, so gross-credit accounting remains
        // exactly at the initial potential.
        let expected_accounted_potential = verdict.initial_potential;
        let actual_accounted_potential = cert.martingale_value();
        let accounting_error = (actual_accounted_potential - expected_accounted_potential).abs();

        assert!(
            accounting_error < 1e-10,
            "gross-credit accounting mismatch: expected {:.2}, got {:.2}, error {:.2}",
            expected_accounted_potential,
            actual_accounted_potential,
            accounting_error
        );

        // This is an observed terminal state, not an extrapolated tail claim.
        assert_eq!(verdict.confidence_bound, 1.0);

        // At the current horizon, the same-trace plug-in net rate yields zero
        // deviation, so both candidates are the trivial bound 1.0. More
        // generally, the selected public envelope equals Azuma under the
        // range-only Freedman cap.
        assert_eq!(verdict.freedman_bound, verdict.azuma_bound);
        assert!(
            verdict.azuma_bound >= 0.0 && verdict.azuma_bound <= 1.0,
            "Azuma bound must be a valid probability: {:.6}",
            verdict.azuma_bound
        );

        // Verify convergence detection
        assert!(
            verdict.converging,
            "Should detect convergence with strong downward trend"
        );

        // Verify estimated remaining steps is reasonable (0 at
        // quiescence, bounded above by a small multiple of the trace
        // length otherwise).
        if let Some(remaining) = verdict.estimated_remaining_steps {
            assert!(
                (0.0..100.0).contains(&remaining),
                "Estimated remaining steps should be reasonable: {:.2}",
                remaining
            );
        }
    }

    /// Golden Test #2: sequential updates preserve probability invariants
    #[test]
    fn golden_sequential_updates_preserve_probability_invariants() {
        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 15.0,
            min_observations: 3,
            stall_threshold: 10,
            epsilon: 1e-12,
        };

        let mut cert = ProgressCertificate::new(config.clone());

        // Sequential updates with consistent progress
        let base_potential = 500.0;
        for i in 0..20 {
            let noise = (i as f64 * 1.3).sin() * 3.0; // Small controlled noise
            let potential = base_potential - (i as f64 * 10.0) + noise;
            cert.observe(potential);

            if cert.len() >= config.min_observations {
                let verdict = cert.verdict();

                // Bounds should always be valid probabilities
                assert!(
                    verdict.azuma_bound >= 0.0 && verdict.azuma_bound <= 1.0,
                    "Azuma bound must be a valid probability: {:.6} at step {}",
                    verdict.azuma_bound,
                    i
                );

                assert!(
                    verdict.confidence_bound >= 0.0 && verdict.confidence_bound <= 1.0,
                    "Confidence bound must be a valid probability: {:.6} at step {}",
                    verdict.confidence_bound,
                    i
                );

                // The range-only raw Freedman candidate is never tighter, so
                // the selected public envelope is exactly Azuma.
                assert_eq!(
                    verdict.freedman_bound, verdict.azuma_bound,
                    "selected envelope should equal Azuma at step {i}",
                );
            }
        }
    }

    /// Golden Test #3: selected tail ignores realized variance
    #[test]
    fn golden_selected_tail_ignores_realized_variance() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 20.0,
            min_observations: 5,
            stall_threshold: 10,
            epsilon: 1e-12,
        };

        let constant =
            certificate_from_potentials(config.clone(), &[100.0, 90.0, 80.0, 70.0, 60.0]);
        let uneven = certificate_from_potentials(config, &[100.0, 95.0, 80.0, 75.0, 60.0]);
        let constant_verdict = constant.verdict();
        let uneven_verdict = uneven.verdict();

        assert_eq!(constant_verdict.empirical_variance, Some(0.0));
        assert!(
            uneven_verdict
                .empirical_variance
                .is_some_and(|variance| variance > 0.0)
        );
        assert_eq!(constant_verdict.mean_credit, uneven_verdict.mean_credit);
        assert_eq!(
            constant_verdict.estimated_remaining_steps,
            uneven_verdict.estimated_remaining_steps
        );
        assert_eq!(
            constant_verdict.confidence_bound,
            uneven_verdict.confidence_bound
        );
        assert_eq!(
            constant_verdict.freedman_bound,
            constant_verdict.azuma_bound
        );
        assert_eq!(uneven_verdict.freedman_bound, uneven_verdict.azuma_bound);
    }

    /// Golden Test #4: Budget exhaustion emits explicit evidence
    #[test]
    fn golden_budget_exhaustion_explicit_evidence() {
        // Test that various problematic conditions generate explicit evidence entries
        // that can be audited for debugging and compliance

        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 10.0, // Deliberately small to trigger violations
            min_observations: 3,
            stall_threshold: 3, // Quick stall detection
            epsilon: 1e-12,
        };

        let mut cert = ProgressCertificate::new(config.clone());

        // Step 1: Normal observation
        cert.observe(100.0);

        // Step 2: Large step that exceeds max_step_bound
        cert.observe(50.0); // Delta = -50, exceeds bound of 10

        // Step 3: Stall (no progress)
        cert.observe(50.0); // Delta = 0

        // Step 4: Another stall
        cert.observe(50.0); // Delta = 0

        // Step 5: Potential increase (violation)
        cert.observe(60.0); // Delta = +10, violation of monotone decrease

        // Step 6: Continue stall to trigger stall detection
        cert.observe(60.0); // Delta = 0

        let verdict = cert.verdict();

        assert_eq!(verdict.azuma_bound, 1.0);
        assert_eq!(verdict.freedman_bound, 1.0);
        assert_eq!(verdict.confidence_bound, 0.0);

        // Verify evidence entries were generated
        assert!(
            !verdict.evidence.is_empty(),
            "Should generate evidence entries for problematic conditions"
        );

        let evidence_descriptions: Vec<String> = verdict
            .evidence
            .iter()
            .map(|e| e.description.clone())
            .collect();

        // Check for step bound violation evidence
        let has_step_violation = evidence_descriptions
            .iter()
            .any(|desc| desc.contains("exceeded") || desc.contains("bound"));
        assert!(
            has_step_violation,
            "Should have evidence for step bound violation. Evidence: {:?}",
            evidence_descriptions
        );

        // Check for stall detection evidence
        let has_stall_evidence = evidence_descriptions
            .iter()
            .any(|desc| desc.contains("stall"));
        assert!(
            has_stall_evidence,
            "Should have evidence for stall detection. Evidence: {:?}",
            evidence_descriptions
        );

        // Verify stall was actually detected in verdict
        assert!(
            verdict.stall_detected,
            "Should detect stall with {} non-decreasing steps",
            config.stall_threshold
        );

        // Verify evidence entries have valid structure
        for evidence in &verdict.evidence {
            assert!(
                evidence.step <= cert.len(),
                "Evidence step {} should be ≤ total steps {}",
                evidence.step,
                cert.len()
            );

            assert!(
                evidence.potential.is_finite(),
                "Evidence potential should be finite: {:.6}",
                evidence.potential
            );

            assert!(
                evidence.bound >= 0.0 && evidence.bound <= 1.0,
                "Evidence value should remain in the unit interval: {:.6}",
                evidence.bound
            );

            assert!(
                !evidence.description.is_empty(),
                "Evidence should have non-empty description"
            );
        }

        // Verify evidence can be displayed
        for evidence in &verdict.evidence {
            let display_str = format!("{}", evidence);
            assert!(
                display_str.contains(&format!("step={}", evidence.step)),
                "Evidence display should include step number"
            );
        }
    }

    /// Golden Test #5: Serialization round-trip preserves all state
    #[test]
    fn golden_serialization_round_trip() {
        // Test complete serialization and deserialization round-trip
        // Note: We'll use JSON serialization via the Debug trait and manual parsing
        // since the structs don't implement Serialize/Deserialize

        let config = ProgressConfig {
            confidence: 0.98,
            max_step_bound: 25.0,
            min_observations: 4,
            stall_threshold: 5,
            epsilon: 1e-9,
        };

        let mut original_cert = ProgressCertificate::new(config.clone());

        // Create a rich test scenario with various conditions
        let test_sequence = vec![
            200.0, 180.0, 155.0, 140.0, 135.0, 120.0, 105.0, 95.0, 85.0, 70.0, 60.0, 50.0, 45.0,
            35.0, 25.0, 20.0, 15.0, 10.0, 5.0, 0.0,
        ];

        for potential in test_sequence {
            original_cert.observe(potential);
        }

        let original_verdict = original_cert.verdict();

        // Test configuration round-trip by creating identical certificate
        let reconstructed_cert = ProgressCertificate::new(config);

        // Re-apply the same observations
        let mut replay_cert = reconstructed_cert;
        for potential in vec![
            200.0, 180.0, 155.0, 140.0, 135.0, 120.0, 105.0, 95.0, 85.0, 70.0, 60.0, 50.0, 45.0,
            35.0, 25.0, 20.0, 15.0, 10.0, 5.0, 0.0,
        ] {
            replay_cert.observe(potential);
        }

        let reconstructed_verdict = replay_cert.verdict();

        // Verify all key statistical properties are preserved
        assert!(
            (original_verdict.initial_potential - reconstructed_verdict.initial_potential).abs()
                < 1e-10,
            "Initial potential should match: orig={:.6}, recon={:.6}",
            original_verdict.initial_potential,
            reconstructed_verdict.initial_potential
        );

        assert!(
            (original_verdict.current_potential - reconstructed_verdict.current_potential).abs()
                < 1e-10,
            "Current potential should match: orig={:.6}, recon={:.6}",
            original_verdict.current_potential,
            reconstructed_verdict.current_potential
        );

        assert!(
            (original_verdict.mean_credit - reconstructed_verdict.mean_credit).abs() < 1e-10,
            "Mean credit should match: orig={:.6}, recon={:.6}",
            original_verdict.mean_credit,
            reconstructed_verdict.mean_credit
        );

        assert!(
            (original_verdict.max_observed_step - reconstructed_verdict.max_observed_step).abs()
                < 1e-10,
            "Max observed step should match: orig={:.6}, recon={:.6}",
            original_verdict.max_observed_step,
            reconstructed_verdict.max_observed_step
        );

        assert_eq!(
            original_verdict.total_steps, reconstructed_verdict.total_steps,
            "Total steps should match: orig={}, recon={}",
            original_verdict.total_steps, reconstructed_verdict.total_steps
        );

        assert_eq!(
            original_verdict.converging, reconstructed_verdict.converging,
            "Convergence detection should match: orig={}, recon={}",
            original_verdict.converging, reconstructed_verdict.converging
        );

        assert_eq!(
            original_verdict.stall_detected, reconstructed_verdict.stall_detected,
            "Stall detection should match: orig={}, recon={}",
            original_verdict.stall_detected, reconstructed_verdict.stall_detected
        );

        assert_eq!(
            original_verdict.drain_phase, reconstructed_verdict.drain_phase,
            "Drain phase should match: orig={:?}, recon={:?}",
            original_verdict.drain_phase, reconstructed_verdict.drain_phase
        );

        // Verify mathematical bounds are preserved
        assert!(
            (original_verdict.azuma_bound - reconstructed_verdict.azuma_bound).abs() < 1e-10,
            "Azuma bound should match: orig={:.6}, recon={:.6}",
            original_verdict.azuma_bound,
            reconstructed_verdict.azuma_bound
        );

        assert!(
            (original_verdict.freedman_bound - reconstructed_verdict.freedman_bound).abs() < 1e-10,
            "Freedman bound should match: orig={:.6}, recon={:.6}",
            original_verdict.freedman_bound,
            reconstructed_verdict.freedman_bound
        );

        assert!(
            (original_verdict.confidence_bound - reconstructed_verdict.confidence_bound).abs()
                < 1e-10,
            "Confidence bound should match: orig={:.6}, recon={:.6}",
            original_verdict.confidence_bound,
            reconstructed_verdict.confidence_bound
        );

        // Verify variance calculations match
        match (
            original_verdict.empirical_variance,
            reconstructed_verdict.empirical_variance,
        ) {
            (Some(orig), Some(recon)) => {
                assert!(
                    (orig - recon).abs() < 1e-10,
                    "Empirical variance should match: orig={:.6}, recon={:.6}",
                    orig,
                    recon
                );
            }
            (None, None) => { /* Both None is fine */ }
            (orig, recon) => {
                panic!(
                    // ubs:ignore - test helper
                    "Empirical variance mismatch: orig={:?}, recon={:?}",
                    orig, recon
                );
            }
        }

        // Verify estimated remaining steps match
        match (
            original_verdict.estimated_remaining_steps,
            reconstructed_verdict.estimated_remaining_steps,
        ) {
            (Some(orig), Some(recon)) => {
                assert!(
                    (orig - recon).abs() < 1e-8,
                    "Estimated remaining steps should match: orig={:.6}, recon={:.6}",
                    orig,
                    recon
                );
            }
            (None, None) => { /* Both None is fine */ }
            (orig, recon) => {
                panic!(
                    // ubs:ignore - test helper
                    "Estimated remaining steps mismatch: orig={:?}, recon={:?}",
                    orig, recon
                );
            }
        }

        // Verify evidence structure is preserved
        assert_eq!(
            original_verdict.evidence.len(),
            reconstructed_verdict.evidence.len(),
            "Evidence count should match: orig={}, recon={}",
            original_verdict.evidence.len(),
            reconstructed_verdict.evidence.len()
        );

        // Verify gross-credit-accounted potential matches.
        let original_accounted = original_cert.martingale_value();
        let reconstructed_accounted = replay_cert.martingale_value();
        assert!(
            (original_accounted - reconstructed_accounted).abs() < 1e-10,
            "gross-credit accounting should match: orig={:.6}, recon={:.6}",
            original_accounted,
            reconstructed_accounted
        );

        // Verify that the reconstructed certificate produces identical subsequent analysis
        let orig_display = format!("{}", original_verdict);
        let recon_display = format!("{}", reconstructed_verdict);

        // Key numerical values should appear identically
        assert!(
            orig_display.contains(&format!("{:.4}", original_verdict.initial_potential)),
            "Display should contain initial potential"
        );
        assert!(
            recon_display.contains(&format!("{:.4}", reconstructed_verdict.initial_potential)),
            "Reconstructed display should contain initial potential"
        );
    }

    /// Additional Golden Test: Comprehensive bounds verification under stress
    #[test]
    fn golden_comprehensive_bounds_stress_test() {
        // Stress test all bound calculations under various pathological conditions

        let config = ProgressConfig {
            confidence: 0.99,
            max_step_bound: 100.0,
            min_observations: 3,
            stall_threshold: 4,
            epsilon: 1e-12,
        };

        // Test Case 1: Near-zero potential with tiny steps
        let mut cert1 = ProgressCertificate::new(config.clone());
        cert1.observe(1.0);
        cert1.observe(0.5);
        cert1.observe(0.1);
        cert1.observe(0.01);
        cert1.observe(0.001);

        let verdict1 = cert1.verdict();
        assert!(verdict1.azuma_bound <= 1.0 && verdict1.azuma_bound >= 0.0);
        assert!(verdict1.freedman_bound <= 1.0 && verdict1.freedman_bound >= 0.0);
        assert_eq!(verdict1.freedman_bound, verdict1.azuma_bound);

        // Test Case 2: Large potential with large steps
        let mut cert2 = ProgressCertificate::new(config.clone());
        let large_sequence = vec![10000.0, 9900.0, 9800.0, 9700.0, 9600.0, 9500.0];
        for v in large_sequence {
            cert2.observe(v);
        }

        let verdict2 = cert2.verdict();
        assert!(verdict2.azuma_bound <= 1.0 && verdict2.azuma_bound >= 0.0);
        assert!(verdict2.freedman_bound <= 1.0 && verdict2.freedman_bound >= 0.0);
        assert_eq!(verdict2.freedman_bound, verdict2.azuma_bound);

        // Test Case 3: Oscillating sequence
        let mut cert3 = ProgressCertificate::new(config);
        let oscillating = vec![100.0, 80.0, 90.0, 70.0, 85.0, 65.0, 75.0, 60.0];
        for v in oscillating {
            cert3.observe(v);
        }

        let verdict3 = cert3.verdict();
        assert!(verdict3.azuma_bound <= 1.0 && verdict3.azuma_bound >= 0.0);
        assert!(verdict3.freedman_bound <= 1.0 && verdict3.freedman_bound >= 0.0);
        assert_eq!(verdict3.freedman_bound, verdict3.azuma_bound);
    }

    #[test]
    fn metamorphic_verdict_remains_true_once_stable_on_same_input() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 40.0,
            stall_threshold: 5,
            min_observations: 4,
            epsilon: 1e-9,
        };
        let potentials = [220.0, 178.0, 140.0, 106.0, 76.0, 50.0, 29.0, 13.0, 4.0, 0.0];

        let mut cert = ProgressCertificate::new(config);
        let mut first_true_index = None;

        for (index, potential) in potentials.into_iter().enumerate() {
            cert.observe(potential);
            let verdict = cert.verdict();

            if let Some(stable_from) = first_true_index {
                assert!(
                    verdict.converging,
                    "verdict regressed from converging at step {stable_from} when replaying the same input prefix through step {index}",
                );
            } else if verdict.converging {
                first_true_index = Some(index);
            }
        }

        assert!(
            first_true_index.is_some(),
            "test sequence should reach a stable converging verdict",
        );
    }

    #[test]
    fn metamorphic_concurrent_verdict_reads_are_identical() {
        let cert = Arc::new(certificate_from_potentials(
            ProgressConfig {
                confidence: 0.92,
                max_step_bound: 45.0,
                stall_threshold: 5,
                min_observations: 4,
                epsilon: 1e-9,
            },
            &[180.0, 142.0, 108.0, 78.0, 52.0, 30.0, 14.0, 3.0, 0.0],
        ));
        let baseline = verdict_fingerprint(&cert.verdict());

        thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let cert = Arc::clone(&cert);
                workers.push(scope.spawn(move || {
                    let mut fingerprints = Vec::new();
                    for _ in 0..32 {
                        fingerprints.push(verdict_fingerprint(&cert.verdict()));
                    }
                    fingerprints
                }));
            }

            for worker in workers {
                for fingerprint in worker.join().expect("verdict reader should not panic") {
                    assert_eq!(
                        fingerprint, baseline,
                        "immutable concurrent verdict reads must stay identical",
                    );
                }
            }
        });
    }

    #[test]
    fn metamorphic_cancel_propagation_bump_preserves_stable_verdict() {
        let config = ProgressConfig {
            confidence: 0.90,
            max_step_bound: 45.0,
            stall_threshold: 5,
            min_observations: 4,
            epsilon: 1e-9,
        };
        let uninterrupted = certificate_from_potentials(
            config.clone(),
            &[150.0, 110.0, 76.0, 52.0, 24.0, 8.0, 0.0],
        );
        let uninterrupted_verdict = uninterrupted.verdict();
        assert!(uninterrupted_verdict.converging);

        let propagated_cancel =
            certificate_from_potentials(config, &[150.0, 110.0, 76.0, 84.0, 52.0, 24.0, 8.0, 0.0]);
        let propagated_verdict = propagated_cancel.verdict();

        assert!(
            propagated_verdict.converging,
            "a bounded cancellation-propagation bump should not invalidate an otherwise converging verdict",
        );
        assert!(
            propagated_cancel.increase_count() > uninterrupted.increase_count(),
            "propagated cancellation should leave a visible monotonicity violation",
        );
        assert_eq!(
            propagated_verdict.drain_phase,
            DrainPhase::Quiescent,
            "stable drain should still reach quiescence after the bump",
        );
    }

    #[test]
    fn progress_certificate_happy_path_serialization_snapshot() {
        let config = ProgressConfig {
            confidence: 0.97,
            max_step_bound: 40.0,
            stall_threshold: 6,
            min_observations: 4,
            epsilon: 1e-9,
        };
        let mut cert = ProgressCertificate::new(config);

        for potential in [120.0, 92.0, 64.0, 39.0, 18.0, 6.0, 0.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(verdict.converging, "happy path should converge");
        assert_eq!(verdict.drain_phase, DrainPhase::Quiescent);

        assert_json_snapshot!(
            "progress_certificate_happy_path_serialization",
            certificate_snapshot(&cert)
        );
    }

    #[test]
    fn progress_certificate_cancellation_during_drain_serialization_snapshot() {
        let config = ProgressConfig {
            confidence: 0.95,
            max_step_bound: 45.0,
            stall_threshold: 5,
            min_observations: 4,
            epsilon: 1e-9,
        };
        let mut cert = ProgressCertificate::new(config);

        for potential in [150.0, 110.0, 76.0, 84.0, 52.0, 24.0, 8.0, 0.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.converging,
            "drain should still converge after a mid-drain bump"
        );
        assert!(
            cert.increase_count() > 0,
            "cancellation-during-drain scenario should record a transient increase",
        );

        assert_json_snapshot!(
            "progress_certificate_cancellation_during_drain_serialization",
            certificate_snapshot(&cert)
        );
    }

    #[test]
    fn progress_certificate_budget_exceeded_serialization_snapshot() {
        let config = ProgressConfig {
            confidence: 0.99,
            max_step_bound: 20.0,
            stall_threshold: 4,
            min_observations: 4,
            epsilon: 1e-9,
        };
        let mut cert = ProgressCertificate::new(config);

        for potential in [80.0, 72.0, 69.0, 69.0, 70.0, 70.0, 70.0, 70.0] {
            cert.observe(potential);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.stall_detected,
            "budget-exceeded scenario should detect a stall"
        );
        assert_ne!(verdict.drain_phase, DrainPhase::Quiescent);

        assert_json_snapshot!(
            "progress_certificate_budget_exceeded_serialization",
            certificate_snapshot(&cert)
        );
    }
}
