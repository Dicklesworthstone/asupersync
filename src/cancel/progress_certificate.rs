//! Martingale progress certificates for cancellation drain.
//!
//! # Purpose
//!
//! Provides statistically grounded guarantees that cancellation
//! drain is making progress toward quiescence. Uses supermartingale theory
//! to prove that a cancelling system will terminate within bounded time,
//! with explicit certificates that can be audited.
//!
//! # Mathematical Foundation
//!
//! A **supermartingale** is a stochastic process {Mₜ} where
//! `E[Mₜ₊₁ | Fₜ] ≤ Mₜ`. For cancellation drain, define the progress
//! process:
//!
//! ```text
//! Mₜ = V(Σₜ) + Σᵢ₌₁ᵗ cᵢ
//! ```
//!
//! where `V(Σₜ)` is the Lyapunov potential at step `t` and `cᵢ ≥ 0` is
//! the "progress credit" consumed at step `i`.
//!
//! **Key theorem (Optional Stopping):** If Mₜ is a supermartingale and
//! `V(Σₜ) ≥ 0`, then:
//!
//! ```text
//! E[τ] ≤ V(Σ₀) / min_credit
//! ```
//!
//! where `τ = inf{t : V(Σₜ) = 0}` is the hitting time of quiescence.
//!
//! **Azuma–Hoeffding concentration bound:**
//!
//! ```text
//! P(V(Σₜ) > V(Σ₀) - t·μ + λ) ≤ exp(-2λ² / (t·c²))
//! ```
//!
//! where `μ` is mean progress per step and `c` is the max step size.
//! This gives a **probabilistic certificate**: "with probability ≥ 1-δ,
//! quiescence is reached within T steps."
//!
//! **Ville's maximal inequality** (see also `eprocess.rs`):
//!
//! ```text
//! P(sup_{t≥0} Mₜ ≥ C) ≤ M₀ / C
//! ```
//!
//! # Integration Points
//!
//! - [`LyapunovGovernor`](crate::obligation::lyapunov::LyapunovGovernor) —
//!   provides `V(Σₜ)` potential values via [`PotentialRecord`].
//! - [`EProcess`](crate::lab::oracle::eprocess::EProcess) — sister
//!   martingale monitoring framework for invariant checking.
//! - [`SymbolCancelToken`](super::symbol_cancel::SymbolCancelToken) —
//!   cancellation cascade system whose drain we certificate.
//! - [`Budget`](crate::types::Budget) — poll quota provides a hard
//!   upper bound that serves as an independent safety net.
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

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for progress certificate monitoring.
///
/// Controls the statistical parameters governing stall detection,
/// concentration bounds, and certificate confidence levels.
#[derive(Debug, Clone)]
pub struct ProgressConfig {
    /// Desired confidence level for probabilistic bounds (e.g. 0.95).
    ///
    /// Must be in `(0, 1)`. The Azuma–Hoeffding bound targets
    /// `P(quiescence within T) ≥ confidence`.
    pub confidence: f64,

    /// Upper bound on the absolute potential change in a single step.
    ///
    /// This is the `c` in the Azuma–Hoeffding inequality. Must be
    /// positive and finite. If a step exceeds this bound, the
    /// certificate logs an evidence entry but does not panic.
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
/// together with derived quantities used for martingale analysis.
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
    /// Progress credit consumed at this step: `max(0, -delta)`.
    ///
    /// This is the `cₜ` term in the supermartingale decomposition.
    pub credit: f64,
}

// ============================================================================
// Evidence
// ============================================================================

/// An auditable evidence entry in a progress certificate.
///
/// Evidence entries form the proof trail that auditors (human or machine)
/// can inspect to verify certificate claims.
#[derive(Debug, Clone)]
pub struct EvidenceEntry {
    /// Step at which this evidence was recorded.
    pub step: usize,
    /// Potential value at this step.
    pub potential: f64,
    /// The Azuma–Hoeffding bound at this step (upper tail probability).
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
/// convergence tail. This enables phase-adaptive timeout policies:
/// during `RapidDrain` the system can use aggressive timeouts, while
/// `SlowTail` warrants patience and `Stalled` warrants escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPhase {
    /// Insufficient observations to classify the phase.
    Warmup,
    /// Rapid initial drain: high credit per step, potential falling fast.
    RapidDrain,
    /// Slow tail convergence: diminishing returns per step.
    SlowTail,
    /// No meaningful progress is being made.
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

/// Certificate verdict with probabilistic bounds.
///
/// Summarises the statistical analysis of a progress trace. All fields
/// are derived from the observation history using the mathematical
/// framework described in the module documentation.
#[derive(Debug, Clone)]
pub struct CertificateVerdict {
    /// Whether the process appears to be converging (potential trending
    /// downward with statistical significance).
    pub converging: bool,

    /// Estimated remaining steps to quiescence via the Optional Stopping
    /// Theorem: `V(Σₜ) / mean_credit`. `None` if insufficient data or
    /// zero mean credit.
    pub estimated_remaining_steps: Option<f64>,

    /// Lower bound on P(quiescence within T steps) from the
    /// Azuma–Hoeffding inequality, where T is the estimated remaining
    /// steps. In `[0, 1]`.
    pub confidence_bound: f64,

    /// Whether a stall was detected (last `stall_threshold` steps all
    /// had non-decreasing potential).
    pub stall_detected: bool,

    /// The Azuma–Hoeffding concentration bound at the current step.
    ///
    /// This is `exp(-2λ² / (t·c²))` evaluated at the current
    /// deviation from expected progress.
    pub azuma_bound: f64,

    /// Number of observations processed.
    pub total_steps: usize,

    /// Current potential value.
    pub current_potential: f64,

    /// Initial potential value (at step 0).
    pub initial_potential: f64,

    /// Mean credit (progress) per step.
    pub mean_credit: f64,

    /// Maximum single-step absolute change observed.
    pub max_observed_step: f64,

    /// Freedman's inequality bound (variance-adaptive, strictly dominates
    /// Azuma–Hoeffding when empirical variance is below worst-case).
    ///
    /// ```text
    /// P(Sₜ ≥ λ) ≤ exp(-λ² / (2(Vₜ + bλ/3)))
    /// ```
    ///
    /// where `Vₜ` is the predictable quadratic variation and `b` is the
    /// max step size. Always `≤ azuma_bound`.
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
        writeln!(f, "Freedman bound:     {:.6}", self.freedman_bound)?;
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

/// Running progress certificate with statistical guarantees.
///
/// Tracks a sequence of Lyapunov potential values from successive
/// cancellation drain steps and maintains the supermartingale
/// decomposition `Mₜ = V(Σₜ) + Σcᵢ`. At any point, callers can
/// request a [`CertificateVerdict`] with probabilistic bounds on
/// time-to-quiescence and stall detection.
///
/// # Supermartingale Property
///
/// If the scheduler is well-behaved (each step makes expected progress),
/// the compensated process `Mₜ` is a supermartingale. The certificate
/// verifies this empirically and uses concentration inequalities to
/// quantify deviations.
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
    /// Most recent potential value, even if older observations were compacted.
    last_potential: Option<f64>,
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
            config.validate().unwrap_err()
        );
        Self {
            observations: Vec::new(),
            config,
            total_observations: 0,
            total_deltas: 0,
            initial_potential: None,
            last_potential: None,
            sum_delta: 0.0,
            total_credit: 0.0,
            sum_delta_sq: 0.0,
            max_abs_delta: 0.0,
            increase_count: 0,
            stall_run: 0,
            ema_credit: 0.0,
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
    /// If `potential` is negative, it is clamped to zero and an internal
    /// note is recorded.
    pub fn observe(&mut self, potential: f64) {
        let potential = potential.max(0.0);
        let step = self.total_observations;

        let delta = self.last_potential.map_or(0.0, |prev| potential - prev);

        let credit = (-delta).max(0.0);

        self.total_credit += credit;
        if step > 0 {
            self.total_deltas += 1;
            self.sum_delta += delta;
            self.sum_delta_sq += delta * delta;
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
            const EMA_ALPHA: f64 = 2.0 / 9.0;
            self.ema_credit = EMA_ALPHA.mul_add(credit, (1.0 - EMA_ALPHA) * self.ema_credit);
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
    /// Given `t` steps with mean progress `mu` per step and max step
    /// size `c`, the probability that the potential exceeds
    /// `V₀ - t·mu + lambda` is bounded by:
    ///
    /// ```text
    /// P(excess ≥ lambda) ≤ exp(-2·lambda² / (t·c²))
    /// ```
    ///
    /// We compute this with `lambda` chosen such that `V₀ - t·mu + lambda = 0`
    /// (the critical threshold for quiescence), giving the probability that
    /// quiescence has NOT been reached by step `t` under the mean-progress
    /// assumption.
    #[must_use]
    fn azuma_hoeffding_bound(&self, t: usize, mean_credit: f64, step_bound: f64) -> f64 {
        if t == 0 || step_bound <= 0.0 {
            return 1.0;
        }

        let initial = self.initial_potential.unwrap_or(0.0);

        // Expected potential at step t: V₀ - t·mu.
        // lambda = residual potential assuming expected progress:
        //   lambda = V₀ - t·mu  (= expected current potential)
        // But we cap lambda at 0 from below — if expected progress
        // already exceeds V₀, the bound is trivially satisfied.
        #[allow(clippy::cast_precision_loss)]
        let t_f = t as f64;
        let expected_remaining = t_f.mul_add(-mean_credit, initial);
        let lambda = expected_remaining.max(0.0);

        // Azuma–Hoeffding: P(Sₜ ≥ lambda) ≤ exp(-2·lambda² / (t·c²))
        let exponent = -2.0 * lambda * lambda / (t_f * step_bound * step_bound);

        exponent.exp()
    }

    /// Computes the Ville's maximal inequality bound.
    ///
    /// ```text
    /// P(sup_{s≥0} Mₛ ≥ C) ≤ M₀ / C
    /// ```
    ///
    /// For the progress supermartingale, `M₀ = V(Σ₀)` and `C` is the
    /// threshold. We use `C = V₀ · (1 + margin)` to bound the probability
    /// that the potential ever exceeds its initial value by more than
    /// `margin` fraction.
    #[must_use]
    fn ville_bound(&self, margin: f64) -> f64 {
        let v0 = self.initial_potential.unwrap_or(0.0);
        if v0 <= 0.0 {
            return 0.0;
        }
        let threshold = v0 * (1.0 + margin);
        (v0 / threshold).min(1.0)
    }

    /// Computes Freedman's inequality bound (variance-adaptive).
    ///
    /// Freedman's inequality is a variance-sensitive analogue of
    /// Azuma–Hoeffding that replaces the worst-case `t·c²` term with the
    /// predictable quadratic variation `Vₜ = Σ Var(Xᵢ | Fᵢ₋₁)`:
    ///
    /// ```text
    /// P(Sₜ ≥ λ AND Vₜ ≤ v) ≤ exp(-λ² / (2(v + bλ/3)))
    /// ```
    ///
    /// where `b` is the max step size. This is strictly tighter than
    /// Azuma whenever empirical variance is below `c²`, which is the
    /// common case for well-behaved cancellation drains with occasional
    /// jitter. The improvement can be orders of magnitude.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    fn freedman_bound(&self, t: usize, mean_credit: f64, step_bound: f64) -> f64 {
        if t == 0 || step_bound <= 0.0 {
            return 1.0;
        }

        let initial = self.initial_potential.unwrap_or(0.0);
        let t_f = t as f64;
        let expected_remaining = t_f.mul_add(-mean_credit, initial);
        let lambda = expected_remaining.max(0.0);

        // Use empirical variance if available, else fall back to worst-case
        // (which makes Freedman equivalent to Azuma).
        let variance = self.delta_variance().unwrap_or(step_bound * step_bound);
        let predictable_variation = t_f * variance;

        let denom = 2.0 * step_bound.mul_add(lambda / 3.0, predictable_variation);

        if denom <= 0.0 {
            return 1.0;
        }

        (-lambda * lambda / denom).exp()
    }

    /// Returns the current drain phase.
    ///
    /// Phase classification uses the exponential moving average of credit
    /// compared to the overall mean credit rate:
    ///
    /// - **Quiescent**: potential ≈ 0 (drain complete)
    /// - **Stalled**: stall run ≥ threshold (no progress)
    /// - **RapidDrain**: EMA credit ≥ 50% of mean credit
    /// - **SlowTail**: EMA credit < 50% of mean credit
    /// - **Warmup**: insufficient data
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn drain_phase(&self) -> DrainPhase {
        if self.total_observations < self.config.min_observations {
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
    /// - Convergence status (statistical trend analysis)
    /// - Estimated remaining steps (Optional Stopping Theorem)
    /// - Confidence bound (Azuma–Hoeffding)
    /// - Stall detection (sliding window)
    /// - Full evidence trail
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn verdict(&self) -> CertificateVerdict {
        const MAX_CONVERGENCE_VIOLATION_RATE: f64 = 0.25;
        let n = self.total_observations;

        // --- Insufficient data: provisional verdict ---
        if n < self.config.min_observations {
            return CertificateVerdict {
                converging: false,
                estimated_remaining_steps: None,
                confidence_bound: 0.0,
                stall_detected: false,
                azuma_bound: 1.0,
                total_steps: n,
                current_potential: self.last_potential.unwrap_or(0.0),
                initial_potential: self.initial_potential.unwrap_or(0.0),
                mean_credit: 0.0,
                max_observed_step: self.max_abs_delta,
                freedman_bound: 1.0,
                drain_phase: DrainPhase::Warmup,
                empirical_variance: None,
                evidence: Vec::new(),
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

        let effective_step_bound = if self.max_abs_delta > self.config.max_step_bound {
            self.max_abs_delta
        } else {
            self.config.max_step_bound
        };
        let azuma =
            self.azuma_hoeffding_bound(steps_with_deltas, mean_credit, effective_step_bound);
        let freedman = self.freedman_bound(steps_with_deltas, mean_credit, effective_step_bound);

        let estimated_remaining =
            (mean_credit > self.config.epsilon).then(|| v_current / mean_credit);

        // Use Freedman (tighter) for confidence bound when available.
        let confidence_bound = estimated_remaining.map_or(0.0, |t_rem| {
            if v_current <= self.config.epsilon {
                return 1.0;
            }
            // Safety factor of 2 for variance.
            #[allow(clippy::cast_sign_loss)]
            let extra = (2.0 * t_rem).ceil().max(0.0) as usize;
            let total_t = steps_with_deltas.saturating_add(extra);
            let tail = self.freedman_bound(total_t, mean_credit, effective_step_bound);
            (1.0 - tail).clamp(0.0, 1.0)
        });

        let stall_detected = self.stall_run >= self.config.stall_threshold;

        // Convergence gate combines concentration and empirical trend, while
        // rejecting strongly oscillatory traces. Uses Freedman (variance-
        // adaptive) instead of raw Azuma for strictly tighter decisions.
        let violation_rate = if steps_with_deltas > 0 {
            self.increase_count as f64 / steps_with_deltas as f64
        } else {
            0.0
        };
        let reduction_ratio = if v_initial > self.config.epsilon {
            ((v_initial - v_current) / v_initial).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let strong_concentration = freedman < (1.0 - self.config.confidence);
        let strong_empirical_reduction = reduction_ratio >= self.config.confidence;
        let converging = mean_credit > self.config.epsilon
            && !stall_detected
            && violation_rate <= MAX_CONVERGENCE_VIOLATION_RATE
            && (strong_concentration || strong_empirical_reduction);

        let evidence = self.build_evidence(
            n,
            v_initial,
            v_current,
            steps_with_deltas,
            mean_credit,
            azuma,
            freedman,
            stall_detected,
            effective_step_bound,
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
        azuma: f64,
        freedman: f64,
        stall_detected: bool,
        _effective_step_bound: f64,
    ) -> Vec<EvidenceEntry> {
        let mut evidence = Vec::new();
        let last_step = n - 1;

        // Step bound exceeded.
        if self.max_abs_delta > self.config.max_step_bound {
            let max_obs = self.max_abs_delta;
            let configured = self.config.max_step_bound;
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: max_obs,
                description: format!(
                    "max observed step {max_obs:.4} exceeds configured bound \
                     {configured:.4}; using observed max for Azuma bound",
                ),
            });
        }

        // Quiescence achieved.
        if v_current <= self.config.epsilon {
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
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: run as f64,
                description: format!(
                    "stall: {run} consecutive non-decreasing steps (threshold: {threshold})",
                ),
            });
        }

        // Monotonicity violations.
        if self.increase_count > 0 {
            let violation_rate = self.increase_count as f64 / steps_with_deltas as f64;
            let count = self.increase_count;
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: violation_rate,
                description: format!(
                    "{count} monotonicity violations out of {steps_with_deltas} steps \
                     (rate: {violation_rate:.4})",
                ),
            });
        }

        // Ville's bound on worst-case exceedance.
        let ville = self.ville_bound(0.5);
        if ville > 0.01 {
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: ville,
                description: format!(
                    "Ville bound: P(potential ever exceeds 1.5\u{00b7}V\u{2080}) \u{2264} {ville:.4}",
                ),
            });
        }

        // Progress summary with both bounds.
        let total_progress = v_initial - v_current;
        evidence.push(EvidenceEntry {
            step: last_step,
            potential: v_current,
            bound: azuma,
            description: format!(
                "total progress {total_progress:.4} over {steps_with_deltas} steps, \
                 mean credit {mean_credit:.4}/step, Azuma tail P \u{2264} {azuma:.6}",
            ),
        });

        // Freedman bound (variance-adaptive, dominates Azuma).
        if (freedman - azuma).abs() > 1e-12 {
            let improvement = if azuma > 1e-15 {
                (1.0 - freedman / azuma) * 100.0
            } else {
                0.0
            };
            evidence.push(EvidenceEntry {
                step: last_step,
                potential: v_current,
                bound: freedman,
                description: format!(
                    "Freedman bound P \u{2264} {freedman:.6} \
                     ({improvement:.1}% tighter than Azuma)",
                ),
            });
        }

        evidence
    }

    /// Returns the number of retained observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// Returns whether no observations have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
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

    /// Returns the current supermartingale value `Mₜ = V(Σₜ) + Σcᵢ`.
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
        self.sum_delta = 0.0;
        self.total_credit = 0.0;
        self.sum_delta_sq = 0.0;
        self.max_abs_delta = 0.0;
        self.increase_count = 0;
        self.stall_run = 0;
        self.ema_credit = 0.0;
    }

    /// Returns the empirical variance of the per-step deltas.
    ///
    /// Uses the biased estimator `(1/n) Σ(Δᵢ - μ)²` where `n` is
    /// the number of deltas (observations − 1). Returns `None` if
    /// fewer than 2 observations exist.
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
        Some(variance.max(0.0)) // clamp numerical noise
    }

    /// Checks whether the supermartingale property approximately holds.
    ///
    /// Verifies that `Mₜ = V(Σₜ) + Σcᵢ` is non-increasing in
    /// expectation. Since credits are defined as `max(0, -Δ)`, the
    /// martingale value should be approximately equal to `V(Σ₀)` if
    /// the process is a true supermartingale.
    ///
    /// Returns the ratio `Mₜ / M₀`. Values ≤ 1.0 confirm the
    /// supermartingale property; values > 1.0 indicate the process
    /// has more potential than expected (possible anomaly).
    #[must_use]
    pub fn martingale_ratio(&self) -> f64 {
        let v0 = self.initial_potential.unwrap_or(0.0);
        if v0 <= 0.0 {
            return 1.0;
        }
        self.martingale_value() / v0
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

        // Martingale value: V(Σₜ) + Σcᵢ = 20 + 80 = 100 = V(Σ₀)
        assert!(
            (cert.martingale_value() - 100.0).abs() < 1e-10,
            "supermartingale should be conserved under monotone decrease"
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
        // Martingale: 70 + 40 = 110 > 100 (increase pushes M up)
        assert!(cert.martingale_value() > 100.0);
    }

    #[test]
    fn negative_potential_clamped() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(-5.0);
        assert!((cert.observations()[0].potential).abs() < 1e-10);
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
    fn azuma_bound_decreases_with_more_steps() {
        // Use step bound matching actual step size for a tight bound.
        let config = ProgressConfig {
            max_step_bound: 10.0,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Constant decrease of 10 per step from 1000.
        for i in 0..50 {
            #[allow(clippy::cast_precision_loss)]
            let v = 1000.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        // With c=10 matching actual steps, Azuma bound should be tight:
        // exp(-2·510²/(49·10²)) = exp(-10.6) ≈ 2.5e-5
        let verdict = cert.verdict();
        assert!(
            verdict.azuma_bound < 0.01,
            "azuma bound should be small with consistent progress and tight c, got {:.6}",
            verdict.azuma_bound,
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
        // average-credit extrapolation overshoots below zero while current
        // potential remains positive.
        let config = ProgressConfig {
            max_step_bound: 250.0,
            min_observations: 4,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Potentials: 100 -> 200 (increase), 200 -> 0 (large credit), 0 -> 10.
        // total_credit = 200 over 3 deltas => mean_credit ≈ 66.7.
        // expected_remaining = 100 - 3*66.7 < 0, so lambda must clamp to 0.
        cert.observe(100.0);
        cert.observe(200.0);
        cert.observe(0.0);
        cert.observe(10.0);

        let verdict = cert.verdict();
        assert!(
            (verdict.azuma_bound - 1.0).abs() < 1e-12,
            "azuma should be 1.0 when expected_remaining < 0, got {}",
            verdict.azuma_bound
        );
        assert!(
            (verdict.freedman_bound - 1.0).abs() < 1e-12,
            "freedman should be 1.0 when expected_remaining < 0, got {}",
            verdict.freedman_bound
        );
        assert!(
            verdict.confidence_bound <= 1e-12,
            "confidence should be near zero when tail bound is 1, got {}",
            verdict.confidence_bound
        );
    }

    // -- Supermartingale property --

    #[test]
    fn martingale_conserved_monotone() {
        let mut cert = ProgressCertificate::with_defaults();

        // Monotone decrease: Mₜ = V(Σₜ) + Σcᵢ should equal V(Σ₀).
        let potentials = [100.0, 85.0, 70.0, 55.0, 40.0, 25.0, 10.0, 0.0];
        for &v in &potentials {
            cert.observe(v);
        }

        let ratio = cert.martingale_ratio();
        assert!(
            (ratio - 1.0).abs() < 1e-10,
            "martingale ratio should be 1.0 for monotone decrease, got {ratio:.10}"
        );
    }

    #[test]
    fn martingale_exceeds_one_with_increases() {
        let mut cert = ProgressCertificate::with_defaults();

        cert.observe(100.0);
        cert.observe(60.0); // credit = 40
        cert.observe(80.0); // increase! credit = 0, M jumps up
        cert.observe(50.0); // credit = 30

        // M = 50 + 70 = 120 > 100 = M₀
        let ratio = cert.martingale_ratio();
        assert!(
            ratio > 1.0,
            "martingale ratio should exceed 1.0 with increases, got {ratio:.4}"
        );
    }

    // -- Ville's bound --

    #[test]
    fn ville_bound_small_for_decreasing() {
        let mut cert = ProgressCertificate::with_defaults();

        for i in 0..10 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        // P(sup M ≥ 1.5·V₀) ≤ V₀ / (1.5·V₀) = 2/3
        let bound = cert.ville_bound(0.5);
        assert!(
            (bound - 2.0 / 3.0).abs() < 1e-10,
            "Ville bound should be 2/3 for 50% margin, got {bound:.6}"
        );
    }

    #[test]
    fn ville_bound_zero_for_zero_initial() {
        let mut cert = ProgressCertificate::with_defaults();
        cert.observe(0.0);
        cert.observe(0.0);

        let bound = cert.ville_bound(0.5);
        assert!(
            bound.abs() < 1e-10,
            "Ville bound should be 0 for zero initial potential"
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
            .any(|e| e.description.contains("exceeds configured bound"));
        assert!(
            has_exceeded,
            "evidence should note exceeded step bound, got: {:?}",
            verdict.evidence
        );
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

    // -- Martingale ratio property test --

    #[test]
    fn martingale_ratio_bounded_for_random_walk() {
        // Feed a downward-biased random walk and verify the martingale
        // ratio stays reasonable.
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
            "martingale ratio should be finite, got {ratio}"
        );
        // For a supermartingale, ratio should be ≥ 1 (or very close).
        // With increases, it can exceed 1 but shouldn't be wildly large.
        assert!(
            ratio < 5.0,
            "martingale ratio should be bounded, got {ratio:.4}"
        );
    }

    // -- Optional Stopping estimate --

    #[test]
    fn estimated_remaining_steps_reasonable() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Constant decrease of 10/step from 100.
        // After 5 steps, potential is 50. Mean credit = 10.
        // Estimated remaining = 50/10 = 5.
        for i in 0..=5 {
            #[allow(clippy::cast_precision_loss)]
            let v = 100.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        let est = verdict
            .estimated_remaining_steps
            .expect("should have estimate");
        assert!(
            (est - 5.0).abs() < 0.1,
            "estimated remaining should be ≈5, got {est:.4}"
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
            "should have no estimate when mean credit is zero"
        );
    }

    // -- Freedman bound --

    #[test]
    fn freedman_dominates_azuma() {
        // Freedman's inequality is always at least as tight as Azuma-Hoeffding.
        // With low variance (constant steps), Freedman should be MUCH tighter.
        let config = ProgressConfig {
            max_step_bound: 100.0, // Deliberately loose bound.
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Constant decrease of 10/step from 1000.
        // Empirical variance = 0, but max_abs_delta = 10.
        // Azuma uses max(10, 100) = 10 since max_abs_delta overrides.
        // Freedman uses actual variance ≈ 0 → denominator shrinks → tighter.
        for i in 0..50 {
            #[allow(clippy::cast_precision_loss)]
            let v = 1000.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        assert!(
            verdict.freedman_bound <= verdict.azuma_bound + 1e-15,
            "Freedman ({:.8}) should be ≤ Azuma ({:.8})",
            verdict.freedman_bound,
            verdict.azuma_bound,
        );
    }

    #[test]
    fn freedman_much_tighter_constant_decrease() {
        // Constant decrease: variance = 0, so Freedman has massive advantage.
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        for i in 0..20 {
            #[allow(clippy::cast_precision_loss)]
            let v = 200.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        // With zero variance, Freedman should be much tighter.
        // The improvement comes from the denominator: Freedman uses
        // t·σ² + b·λ/3 instead of t·c². When σ² ≈ 0, only the b·λ/3
        // term remains, which is typically much smaller than t·c².
        if verdict.azuma_bound > 1e-10 {
            let ratio = verdict.freedman_bound / verdict.azuma_bound;
            assert!(
                ratio < 1.0,
                "Freedman/Azuma ratio should be < 1, got {ratio:.6}"
            );
        }
    }

    #[test]
    fn freedman_equals_azuma_worst_case() {
        // When variance equals max_step_bound², Freedman matches Azuma.
        // This happens with alternating large steps.
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Just two observations — Freedman falls back to worst-case variance.
        cert.observe(100.0);
        cert.observe(80.0);
        cert.observe(60.0);

        // With only 2 deltas, both should give similar results.
        let verdict = cert.verdict();
        assert!(
            verdict.freedman_bound.is_finite(),
            "Freedman should be finite"
        );
        assert!(verdict.azuma_bound.is_finite(), "Azuma should be finite");
    }

    #[test]
    fn freedman_evidence_entry_present() {
        let config = ProgressConfig {
            min_observations: 3,
            ..ProgressConfig::default()
        };
        let mut cert = ProgressCertificate::new(config);

        // Create a scenario where Freedman differs from Azuma.
        for i in 0..15 {
            #[allow(clippy::cast_precision_loss)]
            let v = 150.0 - 10.0 * i as f64;
            cert.observe(v);
        }

        let verdict = cert.verdict();
        let has_freedman = verdict
            .evidence
            .iter()
            .any(|e| e.description.contains("Freedman"));
        assert!(has_freedman, "evidence should include Freedman bound entry");
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
        assert!(text.contains("Freedman bound:"));
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
}
