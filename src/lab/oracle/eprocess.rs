//! Anytime-valid invariant monitoring via e-processes.
//!
//! # Theory
//!
//! An **e-process** `(E_t)` is a non-negative process adapted to a filtration
//! with `E_0 = 1` and `E[E_t | F_{t-1}] ≤ E_{t-1}` (supermartingale under H₀).
//!
//! **Key property (Ville's inequality):** For any stopping time τ and
//! significance level α,
//!
//! ```text
//!     P_H₀(∃ t : E_t ≥ 1/α) ≤ α
//! ```
//!
//! This means you can **peek at any time** and reject H₀ if `E_t ≥ 1/α`
//! without inflating the type-I error. No correction for multiple testing
//! over time is needed.
//!
//! # Invariant Monitoring
//!
//! We monitor three oracle invariants:
//!
//! | Invariant         | H₀ (holds)             | Betting strategy               |
//! |-------------------|------------------------|---------------------------------|
//! | **Task leak**     | All tasks complete     | Bet against completion rate     |
//! | **Obligation leak** | All obligations resolved | Bet against resolution rate   |
//! | **Quiescence**    | Regions close cleanly  | Bet against clean-close rate    |
//!
//! Each observation is an oracle check at a point in time. The e-value for
//! a single observation uses a **simple betting martingale**:
//!
//! ```text
//!     e_t = E_{t-1} × (1 + λ × (X_t − p₀))
//! ```
//!
//! where:
//! - `λ ∈ (-1/p₀, 1/(1−p₀))` is the bet size (chosen adaptively or fixed)
//! - `X_t ∈ {0, 1}` is the observation (1 = violation detected)
//! - `p₀` is the null hypothesis violation probability (e.g., 0.001)
//!
//! Under H₀, `E[X_t] = p₀`, so `E[e_t | E_{t-1}] = E_{t-1}` (martingale).
//! Under H₁ (actual violation rate `p₁ > p₀`), the e-process grows
//! exponentially at rate `KL(p₁ ∥ p₀)` per observation.
//!
//! # References
//!
//! - Ville (1939). *Étude critique de la notion de collectif.*
//! - Grünwald, de Heide, & Koolen (2024). *Safe Testing.*
//! - Ramdas, Grünwald, Vovk, & Shafer (2023). *Game-theoretic statistics.*
//! - Howard, Ramdas, McAuliffe, & Sekhon (2021). *Time-uniform Chernoff bounds.*

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::OracleReport;

// ---------------------------------------------------------------------------
// E-value and e-process core
// ---------------------------------------------------------------------------

/// A single e-value: the evidence against H₀ at a specific time.
///
/// `e ≥ 1/α` rejects H₀ at level α.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EValue {
    /// The e-value (non-negative, starts at 1.0).
    pub value: f64,
    /// Observation index (0-based).
    pub time: usize,
}

impl EValue {
    /// Returns true if this e-value rejects H₀ at the given significance level.
    #[must_use]
    pub fn rejects_at(&self, alpha: f64) -> bool {
        debug_assert!(alpha > 0.0 && alpha <= 1.0);
        self.value >= 1.0 / alpha
    }
}

/// Configuration for the betting martingale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EProcessConfig {
    /// Null hypothesis violation probability (default: 0.001).
    pub p0: f64,
    /// Bet size λ. Must satisfy `-1/(1−p₀) < λ < 1/p₀` to keep
    /// betting factors non-negative for binary observations.
    /// Default: 0.5 (moderate bet).
    pub lambda: f64,
    /// Significance level α for rejection (default: 0.05).
    pub alpha: f64,
    /// Maximum e-value to prevent numerical overflow (default: 1e15).
    pub max_evalue: f64,
}

impl Default for EProcessConfig {
    fn default() -> Self {
        Self {
            p0: 0.001,
            lambda: 0.5,
            alpha: 0.05,
            max_evalue: 1e15,
        }
    }
}

impl EProcessConfig {
    /// Validates the configuration.
    ///
    /// Returns `Err` if constraints are violated.
    pub fn validate(&self) -> Result<(), String> {
        // Guard against NaN/Inf first — IEEE 754 NaN comparisons always return
        // false, so range checks alone cannot reject NaN.
        if !self.p0.is_finite() {
            return Err(format!("p0 must be finite, got {}", self.p0));
        }
        if !self.lambda.is_finite() {
            return Err(format!("lambda must be finite, got {}", self.lambda));
        }
        if !self.alpha.is_finite() {
            return Err(format!("alpha must be finite, got {}", self.alpha));
        }
        if self.p0 <= 0.0 || self.p0 >= 1.0 {
            return Err(format!("p0 must be in (0, 1), got {}", self.p0));
        }
        // For binary X ∈ {0,1}, factor = 1 + λ(X - p0) must be ≥ 0:
        //   X=0 → 1 - λp0 ≥ 0 → λ < 1/p0
        //   X=1 → 1 + λ(1-p0) ≥ 0 → λ > -1/(1-p0)
        let lambda_min = -1.0 / (1.0 - self.p0);
        let lambda_max = 1.0 / self.p0;
        if self.lambda <= lambda_min || self.lambda >= lambda_max {
            return Err(format!(
                "lambda must be in ({:.4}, {:.4}), got {}",
                lambda_min, lambda_max, self.lambda
            ));
        }
        if self.alpha <= 0.0 || self.alpha > 1.0 {
            return Err(format!("alpha must be in (0, 1], got {}", self.alpha));
        }
        if !self.max_evalue.is_finite() || self.max_evalue < 1.0 {
            return Err(format!(
                "max_evalue must be finite and >= 1.0, got {}",
                self.max_evalue
            ));
        }
        let threshold = 1.0 / self.alpha;
        if self.max_evalue < threshold {
            return Err(format!(
                "max_evalue ({}) must be >= threshold 1/alpha ({:.1}), otherwise rejection is impossible",
                self.max_evalue, threshold
            ));
        }
        Ok(())
    }

    /// Computes the rejection threshold `1/α`.
    #[must_use]
    pub fn threshold(&self) -> f64 {
        1.0 / self.alpha
    }
}

/// An e-process tracker for a single invariant.
///
/// Maintains the running product martingale and history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EProcess {
    /// Invariant being monitored.
    pub invariant: String,
    /// Configuration.
    pub config: EProcessConfig,
    /// Current e-value (running product).
    pub current: f64,
    /// Number of observations processed.
    pub observations: usize,
    /// Number of violations observed.
    pub violations_observed: usize,
    /// Whether H₀ has been rejected at any point.
    pub rejected: bool,
    /// The observation at which rejection first occurred (if any).
    pub rejection_time: Option<usize>,
    /// History of e-values (optional, for diagnostics).
    pub history: Vec<EValue>,
    /// Whether to record full history.
    record_history: bool,
}

impl EProcess {
    /// Creates a new e-process for the given invariant.
    #[must_use]
    pub fn new(invariant: &str, config: EProcessConfig) -> Self {
        assert!(
            config.validate().is_ok(),
            "EProcessConfig validation failed: {}",
            config
                .validate()
                .expect_err("expected e-process config validation to fail")
        );
        Self {
            invariant: invariant.to_owned(),
            config,
            current: 1.0,
            observations: 0,
            violations_observed: 0,
            rejected: false,
            rejection_time: None,
            history: Vec::new(),
            record_history: true,
        }
    }

    /// Creates a new e-process without history recording (saves memory).
    #[must_use]
    pub fn new_without_history(invariant: &str, config: EProcessConfig) -> Self {
        let mut ep = Self::new(invariant, config);
        ep.record_history = false;
        ep
    }

    /// Processes a single observation.
    ///
    /// `violated` is true if the oracle detected a violation at this step.
    pub fn observe(&mut self, violated: bool) {
        let x = if violated { 1.0 } else { 0.0 };
        let factor = self.config.lambda.mul_add(x - self.config.p0, 1.0);

        // Clamp factor to prevent negative or zero values.
        let factor = factor.max(1e-15);

        // Guard against NaN propagation — if current or factor became NaN
        // (e.g., from corrupt config), clamp to max_evalue rather than silently
        // disabling rejection detection.
        let product = self.current * factor;
        self.current = if product.is_finite() {
            product.min(self.config.max_evalue)
        } else {
            self.config.max_evalue
        };
        self.observations += 1;
        if violated {
            self.violations_observed += 1;
        }

        if self.record_history {
            self.history.push(EValue {
                value: self.current,
                time: self.observations - 1,
            });
        }

        if !self.rejected && self.current >= self.config.threshold() {
            self.rejected = true;
            self.rejection_time = Some(self.observations - 1);
        }
    }

    /// Returns the current e-value.
    #[must_use]
    pub fn e_value(&self) -> f64 {
        self.current
    }

    /// Returns the current log₁₀ e-value.
    #[must_use]
    pub fn log10_e_value(&self) -> f64 {
        self.current.max(1e-300).log10()
    }

    /// Returns the empirical violation rate.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn empirical_rate(&self) -> f64 {
        if self.observations == 0 {
            0.0
        } else {
            self.violations_observed as f64 / self.observations as f64
        }
    }

    /// Resets the e-process to its initial state.
    pub fn reset(&mut self) {
        self.current = 1.0;
        self.observations = 0;
        self.violations_observed = 0;
        self.rejected = false;
        self.rejection_time = None;
        self.history.clear();
    }
}

// ---------------------------------------------------------------------------
// E-process monitor — multi-invariant
// ---------------------------------------------------------------------------

/// Result of monitoring a set of invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorResult {
    /// Invariant name.
    pub invariant: String,
    /// Final e-value.
    pub e_value: f64,
    /// log₁₀ of final e-value.
    pub log10_e_value: f64,
    /// Whether H₀ was rejected.
    pub rejected: bool,
    /// Rejection time (observation index), if any.
    pub rejection_time: Option<usize>,
    /// Total observations.
    pub observations: usize,
    /// Violations observed.
    pub violations_observed: usize,
    /// Empirical violation rate.
    pub empirical_rate: f64,
}

impl MonitorResult {
    fn from_eprocess(ep: &EProcess) -> Self {
        Self {
            invariant: ep.invariant.clone(),
            e_value: ep.current,
            log10_e_value: ep.log10_e_value(),
            rejected: ep.rejected,
            rejection_time: ep.rejection_time,
            observations: ep.observations,
            violations_observed: ep.violations_observed,
            empirical_rate: ep.empirical_rate(),
        }
    }
}

/// Monitors multiple invariants via e-processes.
///
/// Each invariant gets its own independent e-process. Feed observations
/// from oracle reports and query anytime-valid rejection status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EProcessMonitor {
    /// Per-invariant e-processes.
    processes: Vec<EProcess>,
    /// Shared configuration.
    config: EProcessConfig,
}

impl EProcessMonitor {
    /// Creates a monitor for the standard 3 invariants (task_leak, obligation_leak, quiescence).
    #[must_use]
    pub fn standard() -> Self {
        Self::standard_with_config(EProcessConfig::default())
    }

    /// Creates a monitor for the standard 3 invariants with custom config.
    #[must_use]
    pub fn standard_with_config(config: EProcessConfig) -> Self {
        let invariants = ["task_leak", "obligation_leak", "quiescence"];
        Self::new(&invariants, config)
    }

    /// Creates a monitor for arbitrary invariants.
    #[must_use]
    pub fn new(invariants: &[&str], config: EProcessConfig) -> Self {
        let processes = invariants
            .iter()
            .map(|inv| EProcess::new(inv, config.clone()))
            .collect();
        Self { processes, config }
    }

    /// Creates a monitor for all oracle invariants.
    #[must_use]
    pub fn all_invariants() -> Self {
        Self::all_invariants_with_config(EProcessConfig::default())
    }

    /// Creates a monitor for all oracle invariants with custom config.
    ///
    /// Tracks every name [`super::OracleSuite::report`] emits
    /// ([`super::registry::ALL_REPORTED_ORACLE_NAMES`]), so the FABRIC oracles
    /// are monitored when the `messaging-fabric` feature is enabled.
    #[must_use]
    pub fn all_invariants_with_config(config: EProcessConfig) -> Self {
        Self::new(super::registry::ALL_REPORTED_ORACLE_NAMES, config)
    }

    /// Feeds an oracle report into the monitor.
    ///
    /// Each invariant's e-process is updated based on whether a violation
    /// was detected in the report.
    pub fn observe_report(&mut self, report: &OracleReport) {
        for ep in &mut self.processes {
            // Only update invariants that actually appear in the report.
            // A missing entry means the oracle didn't check this invariant,
            // so we must not silently treat it as passing.
            if let Some(entry) = report.entries.iter().find(|e| e.invariant == ep.invariant) {
                ep.observe(!entry.passed);
            }
        }
    }

    /// Feeds a raw observation for a specific invariant.
    ///
    /// Returns `true` if the invariant was found and updated.
    pub fn observe(&mut self, invariant: &str, violated: bool) -> bool {
        self.processes
            .iter_mut()
            .find(|ep| ep.invariant == invariant)
            .is_some_and(|ep| {
                ep.observe(violated);
                true
            })
    }

    /// Returns whether any invariant has been rejected.
    #[must_use]
    pub fn any_rejected(&self) -> bool {
        self.processes.iter().any(|ep| ep.rejected)
    }

    /// Returns invariants that have been rejected.
    #[must_use]
    pub fn rejected_invariants(&self) -> Vec<&str> {
        self.processes
            .iter()
            .filter(|ep| ep.rejected)
            .map(|ep| ep.invariant.as_str())
            .collect()
    }

    /// Returns the e-process for a specific invariant.
    #[must_use]
    pub fn process(&self, invariant: &str) -> Option<&EProcess> {
        self.processes.iter().find(|ep| ep.invariant == invariant)
    }

    /// Returns results for all tracked invariants.
    #[must_use]
    pub fn results(&self) -> Vec<MonitorResult> {
        self.processes
            .iter()
            .map(MonitorResult::from_eprocess)
            .collect()
    }

    /// Returns the shared configuration.
    #[must_use]
    pub fn config(&self) -> &EProcessConfig {
        &self.config
    }

    /// Resets all e-processes.
    pub fn reset(&mut self) {
        for ep in &mut self.processes {
            ep.reset();
        }
    }

    /// Renders a text summary of the monitor state.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(&mut out, "E-Process Monitor (α = {})", self.config.alpha);
        let _ = writeln!(
            &mut out,
            "  Rejection threshold: {:.1}",
            self.config.threshold()
        );
        let _ = writeln!(&mut out, "  Invariants: {}", self.processes.len());
        let rejected = self.rejected_invariants();
        let _ = writeln!(&mut out, "  Rejected: {}", rejected.len());
        let _ = writeln!(&mut out);

        for ep in &self.processes {
            let status = if ep.rejected {
                "REJECTED"
            } else {
                "monitoring"
            };
            let _ = writeln!(
                &mut out,
                "  [{status}] {inv}: e={e:.4}, log₁₀(e)={log:.4}, n={n}, violations={v}",
                inv = ep.invariant,
                e = ep.current,
                log = ep.log10_e_value(),
                n = ep.observations,
                v = ep.violations_observed,
            );
            if let Some(t) = ep.rejection_time {
                let _ = writeln!(&mut out, "           → rejected at observation {t}");
            }
        }

        out
    }

    /// Serializes monitor state to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[path = "eprocess_inline_tests.rs"]
mod tests;
