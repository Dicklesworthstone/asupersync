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
    /// Bet size λ. Must satisfy `-1/p₀ < λ < 1/(1−p₀)`.
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
        if self.p0 <= 0.0 || self.p0 >= 1.0 {
            return Err(format!("p0 must be in (0, 1), got {}", self.p0));
        }
        let lambda_min = -1.0 / self.p0;
        let lambda_max = 1.0 / (1.0 - self.p0);
        if self.lambda <= lambda_min || self.lambda >= lambda_max {
            return Err(format!(
                "lambda must be in ({:.4}, {:.4}), got {}",
                lambda_min, lambda_max, self.lambda
            ));
        }
        if self.alpha <= 0.0 || self.alpha > 1.0 {
            return Err(format!("alpha must be in (0, 1], got {}", self.alpha));
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
        // (e.g., from corrupt config), clamp to 1.0 rather than silently
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

    /// Creates a monitor for all 12 oracle invariants.
    #[must_use]
    pub fn all_invariants() -> Self {
        Self::all_invariants_with_config(EProcessConfig::default())
    }

    /// Creates a monitor for all 12 oracle invariants with custom config.
    #[must_use]
    pub fn all_invariants_with_config(config: EProcessConfig) -> Self {
        let invariants = [
            "task_leak",
            "obligation_leak",
            "quiescence",
            "loser_drain",
            "finalizer",
            "region_tree",
            "ambient_authority",
            "deadline_monotone",
            "cancellation_protocol",
            "actor_leak",
            "supervision",
            "mailbox",
        ];
        Self::new(&invariants, config)
    }

    /// Feeds an oracle report into the monitor.
    ///
    /// Each invariant's e-process is updated based on whether a violation
    /// was detected in the report.
    pub fn observe_report(&mut self, report: &OracleReport) {
        for ep in &mut self.processes {
            let violated = report
                .entries
                .iter()
                .find(|e| e.invariant == ep.invariant)
                .is_some_and(|e| !e.passed);
            ep.observe(violated);
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
mod tests {
    use super::*;
    use crate::lab::oracle::{OracleEntryReport, OracleReport, OracleStats};

    fn make_clean_report(invariants: &[&str]) -> OracleReport {
        let entries = invariants
            .iter()
            .map(|inv| OracleEntryReport {
                invariant: inv.to_string(),
                passed: true,
                violation: None,
                stats: OracleStats {
                    entities_tracked: 5,
                    events_recorded: 10,
                },
            })
            .collect::<Vec<_>>();
        let total = entries.len();
        OracleReport {
            entries,
            total,
            passed: total,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_violation_report(invariants: &[&str], violated: &[&str]) -> OracleReport {
        let entries = invariants
            .iter()
            .map(|inv| {
                let is_violated = violated.contains(inv);
                OracleEntryReport {
                    invariant: inv.to_string(),
                    passed: !is_violated,
                    violation: if is_violated {
                        Some("test violation".into())
                    } else {
                        None
                    },
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                }
            })
            .collect::<Vec<_>>();
        let total = entries.len();
        let failed = entries.iter().filter(|e| !e.passed).count();
        OracleReport {
            entries,
            total,
            passed: total - failed,
            failed,
            check_time_nanos: 0,
        }
    }

    // -- EProcessConfig --

    #[test]
    fn config_default_valid() {
        assert!(EProcessConfig::default().validate().is_ok());
    }

    #[test]
    fn config_threshold() {
        let config = EProcessConfig::default();
        assert!((config.threshold() - 20.0).abs() < 1e-10);
    }

    #[test]
    fn config_invalid_p0() {
        let c = EProcessConfig {
            p0: 0.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            p0: 1.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            p0: -0.1,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_lambda() {
        let c = EProcessConfig {
            lambda: -2000.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            lambda: 2000.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_alpha() {
        let c = EProcessConfig {
            alpha: 0.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    // -- EValue --

    #[test]
    fn evalue_rejects() {
        let ev = EValue {
            value: 25.0,
            time: 0,
        };
        assert!(ev.rejects_at(0.05)); // 1/0.05 = 20, 25 >= 20
        assert!(!ev.rejects_at(0.01)); // 1/0.01 = 100, 25 < 100
    }

    // -- EProcess core --

    #[test]
    fn eprocess_starts_at_one() {
        let ep = EProcess::new("test", EProcessConfig::default());
        assert!((ep.current - 1.0).abs() < 1e-10);
        assert_eq!(ep.observations, 0);
        assert!(!ep.rejected);
    }

    #[test]
    fn eprocess_clean_observations_decrease() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // Under H0 with no violations, e-value should decrease slightly.
        for _ in 0..10 {
            ep.observe(false);
        }
        assert!(
            ep.current < 1.0,
            "clean observations should decrease e-value, got {}",
            ep.current
        );
        assert_eq!(ep.observations, 10);
        assert_eq!(ep.violations_observed, 0);
        assert!(!ep.rejected);
    }

    #[test]
    fn eprocess_violations_increase() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(true);
        assert!(
            ep.current > 1.0,
            "violation should increase e-value, got {}",
            ep.current
        );
        assert_eq!(ep.violations_observed, 1);
    }

    #[test]
    fn eprocess_many_violations_reject() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // With repeated violations, should eventually reject.
        for _ in 0..20 {
            ep.observe(true);
        }
        assert!(ep.rejected, "repeated violations should cause rejection");
        assert!(ep.rejection_time.is_some());
    }

    #[test]
    fn eprocess_rejection_is_sticky() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        for _ in 0..20 {
            ep.observe(true);
        }
        let rejection_time = ep.rejection_time;
        assert!(ep.rejected);

        // Further clean observations don't un-reject.
        for _ in 0..100 {
            ep.observe(false);
        }
        assert!(ep.rejected, "rejection should be sticky");
        assert_eq!(
            ep.rejection_time, rejection_time,
            "rejection time should not change"
        );
    }

    #[test]
    fn eprocess_history_recorded() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        ep.observe(false);
        assert_eq!(ep.history.len(), 3);
        assert_eq!(ep.history[0].time, 0);
        assert_eq!(ep.history[1].time, 1);
        assert_eq!(ep.history[2].time, 2);
    }

    #[test]
    fn eprocess_no_history() {
        let mut ep = EProcess::new_without_history("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        assert!(ep.history.is_empty());
    }

    #[test]
    fn eprocess_reset() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(true);
        ep.observe(true);
        assert!(ep.current > 1.0);
        ep.reset();
        assert!((ep.current - 1.0).abs() < 1e-10);
        assert_eq!(ep.observations, 0);
        assert_eq!(ep.violations_observed, 0);
        assert!(!ep.rejected);
        assert!(ep.history.is_empty());
    }

    #[test]
    fn eprocess_empirical_rate() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        ep.observe(false);
        ep.observe(true);
        assert!((ep.empirical_rate() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn eprocess_empirical_rate_zero_observations() {
        let ep = EProcess::new("test", EProcessConfig::default());
        assert!((ep.empirical_rate()).abs() < 1e-10);
    }

    #[test]
    fn eprocess_log10_evalue() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.current = 100.0;
        assert!((ep.log10_e_value() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn eprocess_evalue_capped() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // Drive e-value very high.
        for _ in 0..1000 {
            ep.observe(true);
        }
        assert!(
            ep.current <= ep.config.max_evalue,
            "e-value should be capped"
        );
        assert!(ep.current.is_finite());
    }

    // -- EProcessMonitor --

    #[test]
    fn monitor_standard_has_three_invariants() {
        let monitor = EProcessMonitor::standard();
        assert_eq!(monitor.processes.len(), 3);
        assert!(monitor.process("task_leak").is_some());
        assert!(monitor.process("obligation_leak").is_some());
        assert!(monitor.process("quiescence").is_some());
    }

    #[test]
    fn monitor_all_invariants_has_twelve() {
        let monitor = EProcessMonitor::all_invariants();
        assert_eq!(monitor.processes.len(), 12);
    }

    #[test]
    fn monitor_observe_report_clean() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);

        for _ in 0..10 {
            monitor.observe_report(&report);
        }

        assert!(!monitor.any_rejected());
        assert!(monitor.rejected_invariants().is_empty());

        // All e-values should be < 1 (evidence against violation).
        for ep in &monitor.processes {
            assert!(
                ep.current < 1.0,
                "clean reports should decrease e-value for '{}'",
                ep.invariant
            );
        }
    }

    #[test]
    fn monitor_observe_report_violation() {
        let mut monitor = EProcessMonitor::standard();
        let invariants = ["task_leak", "obligation_leak", "quiescence"];

        // Feed 20 reports with task_leak violated.
        for _ in 0..20 {
            let report = make_violation_report(&invariants, &["task_leak"]);
            monitor.observe_report(&report);
        }

        assert!(monitor.any_rejected());
        let rejected = monitor.rejected_invariants();
        assert!(rejected.contains(&"task_leak"));
        assert!(!rejected.contains(&"obligation_leak"));
        assert!(!rejected.contains(&"quiescence"));
    }

    #[test]
    fn monitor_observe_raw() {
        let mut monitor = EProcessMonitor::standard();

        assert!(monitor.observe("task_leak", true));
        assert!(monitor.observe("task_leak", false));
        assert!(!monitor.observe("nonexistent", true));

        let ep = monitor.process("task_leak").unwrap();
        assert_eq!(ep.observations, 2);
        assert_eq!(ep.violations_observed, 1);
    }

    #[test]
    fn monitor_results() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);

        let results = monitor.results();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.observations, 1);
            assert!(!r.rejected);
        }
    }

    #[test]
    fn monitor_reset() {
        let mut monitor = EProcessMonitor::standard();
        monitor.observe("task_leak", true);
        monitor.observe("task_leak", true);
        monitor.reset();

        for ep in &monitor.processes {
            assert!((ep.current - 1.0).abs() < 1e-10);
            assert_eq!(ep.observations, 0);
        }
    }

    #[test]
    fn monitor_to_text() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);

        let text = monitor.to_text();
        assert!(text.contains("E-Process Monitor"));
        assert!(text.contains("task_leak"));
        assert!(text.contains("monitoring"));
    }

    #[test]
    fn monitor_to_json() {
        let monitor = EProcessMonitor::standard();
        let json = monitor.to_json();
        assert!(json["processes"].is_array());
        assert!(json["config"].is_object());
    }

    #[test]
    fn monitor_json_roundtrip() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);
        monitor.observe_report(&report);

        let json_str = serde_json::to_string(&monitor).unwrap();
        let deserialized: EProcessMonitor = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.processes.len(), monitor.processes.len());
        for (orig, deser) in monitor.processes.iter().zip(deserialized.processes.iter()) {
            assert_eq!(orig.invariant, deser.invariant);
            assert!((orig.current - deser.current).abs() < 1e-10);
            assert_eq!(orig.observations, deser.observations);
        }
    }

    // -- Martingale property --

    #[test]
    fn eprocess_martingale_under_null() {
        // Under H0, the e-process should not grow systematically.
        // Run many trials and check the average final e-value is ≈ 1.
        let n_trials: u32 = 1000;
        let n_obs: u32 = 50;
        let config = EProcessConfig::default();
        let p0 = config.p0;

        let mut sum_final_e = 0.0;
        let mut rng_state: u64 = 42;

        for _ in 0..n_trials {
            let mut ep = EProcess::new_without_history("test", config.clone());
            for _ in 0..n_obs {
                // Simple PRNG for deterministic test.
                rng_state = rng_state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let u = f64::from((rng_state >> 33) as u32) / f64::from(1_u32 << 31);
                let violated = u < p0;
                ep.observe(violated);
            }
            sum_final_e += ep.current;
        }

        let avg_e = sum_final_e / f64::from(n_trials);
        // Under H0, E[E_T] ≤ 1 (supermartingale). Allow slack for finite samples.
        assert!(
            avg_e < 2.0,
            "average e-value under H0 should be ≤ 1 (got {avg_e:.4})"
        );
    }

    #[test]
    fn eprocess_detects_elevated_rate() {
        // Under H1 with violation rate 10%, should reject quickly.
        let config = EProcessConfig::default();
        let mut ep = EProcess::new("test", config);

        // Use a deterministic 10% violation pattern to avoid RNG flakiness.
        for i in 0..100 {
            let violated = i % 10 == 0;
            ep.observe(violated);
        }

        assert!(
            ep.rejected,
            "elevated violation rate (10%) should be detected within 100 observations"
        );
    }

    // -- Early stopping validity --

    #[test]
    fn early_stopping_valid() {
        // The key property: stopping when E_t first exceeds 1/α should give
        // type-I error ≤ α. Test over many null trials.
        let n_trials: u32 = 10_000;
        let n_obs: u32 = 100;
        let config = EProcessConfig {
            alpha: 0.05,
            ..EProcessConfig::default()
        };
        let p0 = config.p0;

        let mut false_rejections: u32 = 0;
        let mut rng_state: u64 = 999;

        for _ in 0..n_trials {
            let mut ep = EProcess::new_without_history("test", config.clone());
            for _ in 0..n_obs {
                rng_state = rng_state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let u = f64::from((rng_state >> 33) as u32) / f64::from(1_u32 << 31);
                let violated = u < p0;
                ep.observe(violated);
            }
            if ep.rejected {
                false_rejections += 1;
            }
        }

        let fpr = f64::from(false_rejections) / f64::from(n_trials);
        // By Ville's inequality, FPR ≤ α = 0.05. Allow generous slack.
        assert!(
            fpr < 0.10,
            "false positive rate under optional stopping should be ≤ α, got {fpr:.4}"
        );
    }

    // -- Integration with OracleSuite --

    #[test]
    fn monitor_with_oracle_suite() {
        let suite = crate::lab::oracle::OracleSuite::new();
        let report = suite.report(crate::types::Time::ZERO);

        let mut monitor = EProcessMonitor::all_invariants();
        for _ in 0..10 {
            monitor.observe_report(&report);
        }

        assert!(
            !monitor.any_rejected(),
            "clean suite should not trigger rejection"
        );
        for r in monitor.results() {
            assert!(!r.rejected);
            assert!(
                r.e_value < 1.0,
                "clean: e-value should be < 1 for {}",
                r.invariant
            );
        }
    }
}
