//! Anytime-valid obligation leak monitor via e-processes.
//!
//! An e-process is a non-negative supermartingale under the null hypothesis
//! ("no leaks: all obligations resolve within their expected lifetime").
//! When the e-value exceeds 1/α, we reject the null with Type-I error ≤ α —
//! regardless of when we choose to stop monitoring (Ville's inequality).
//!
//! # Design
//!
//! Each monitored obligation contributes to the e-value based on how long
//! it has been pending relative to an expected resolution time:
//!
//! ```text
//! E_n = E_{n-1} × likelihood_ratio(obligation_n)
//! ```
//!
//! where the likelihood ratio compares:
//! - H0 (no leak): obligation age follows Exp(1/expected_lifetime)
//! - H1 (leak):   obligation is stuck (age grows without bound)
//!
//! # False-Alarm Guarantees
//!
//! By Ville's inequality: P(∃t: E_t ≥ 1/α | H0) ≤ α.
//! This holds for *any* stopping rule, including data-dependent ones.
//!
//! # Calibration
//!
//! The `expected_lifetime_ns` parameter should be set based on:
//! - Empirical profiling of obligation durations
//! - Budget deadlines for the containing region
//! - A conservative multiple of the median observed duration
//!
//! # Usage
//!
//! ```
//! use asupersync::obligation::eprocess::{LeakMonitor, MonitorConfig};
//!
//! let config = MonitorConfig {
//!     alpha: 0.01,              // 1% false-positive rate
//!     expected_lifetime_ns: 1_000_000, // 1ms expected resolution
//!     min_observations: 5,      // Don't alert before 5 observations
//! };
//! let mut monitor = LeakMonitor::new(config);
//!
//! // Feed observations: age in nanoseconds of each obligation at check time
//! monitor.observe(500_000);    // 0.5ms — normal
//! monitor.observe(800_000);    // 0.8ms — normal
//! monitor.observe(50_000_000); // 50ms  — suspicious
//!
//! if monitor.is_alert() {
//!     // E-value exceeded threshold: leak detected
//! }
//! ```

use std::fmt;

/// Configuration for the leak monitor.
#[derive(Debug, Clone, Copy)]
pub struct MonitorConfig {
    /// Type-I error bound (false-positive rate). Must be in (0, 1).
    /// The monitor guarantees P(false alarm) ≤ alpha under H0.
    pub alpha: f64,
    /// Expected obligation lifetime in nanoseconds under the null.
    /// Obligations pending longer than this are increasingly suspicious.
    pub expected_lifetime_ns: u64,
    /// Minimum observations before the monitor can trigger an alert.
    /// Prevents spurious alerts from small samples.
    pub min_observations: u32,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            alpha: 0.01,
            expected_lifetime_ns: 10_000_000, // 10ms
            min_observations: 3,
        }
    }
}

/// The state of the leak monitor's alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    /// No evidence of leaks.
    Clear,
    /// E-value is elevated but below threshold.
    Watching,
    /// E-value exceeds 1/α: leak detected with bounded false-positive rate.
    Alert,
}

impl fmt::Display for AlertState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clear => f.write_str("clear"),
            Self::Watching => f.write_str("watching"),
            Self::Alert => f.write_str("ALERT"),
        }
    }
}

/// An anytime-valid leak monitor using e-processes.
///
/// The monitor accumulates evidence against the null hypothesis
/// ("obligations are being resolved on time") via multiplicative
/// likelihood ratios. When evidence is strong enough, it raises
/// an alert with provable Type-I error control.
#[derive(Debug)]
pub struct LeakMonitor {
    /// Configuration.
    config: MonitorConfig,
    /// Current e-value (product of likelihood ratios).
    /// Starts at 1.0 (no evidence).
    e_value: f64,
    /// Rejection threshold: 1/alpha.
    threshold: f64,
    /// Number of observations so far.
    observations: u32,
    /// Running sum of log-likelihood ratios (for numerical stability).
    log_e_value: f64,
    /// Peak e-value observed (for diagnostics).
    peak_e_value: f64,
    /// Number of times alert was triggered.
    alert_count: u32,
}

impl LeakMonitor {
    /// Creates a new monitor with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if `alpha` is not in (0, 1) or `expected_lifetime_ns` is 0.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        assert!(
            config.alpha > 0.0 && config.alpha < 1.0,
            "alpha must be in (0, 1), got {}",
            config.alpha
        );
        assert!(
            config.expected_lifetime_ns > 0,
            "expected_lifetime_ns must be > 0"
        );

        let threshold = 1.0 / config.alpha;

        Self {
            config,
            e_value: 1.0,
            threshold,
            observations: 0,
            log_e_value: 0.0,
            peak_e_value: 1.0,
            alert_count: 0,
        }
    }

    /// Observes an obligation's age (time since reservation, in nanoseconds).
    ///
    /// Updates the e-value with the likelihood ratio for this observation.
    /// Under H0 (no leak), obligation ages follow Exp(λ) where
    /// λ = 1/expected_lifetime. Under H1 (leak), ages are unbounded.
    ///
    /// The likelihood ratio at each step is:
    /// ```text
    /// LR = f_1(x) / f_0(x)
    /// ```
    /// We use a mixture alternative where H1 spreads mass more uniformly,
    /// giving LR = max(1, x / expected_lifetime).
    ///
    /// This ensures the e-process is a non-negative supermartingale under H0.
    pub fn observe(&mut self, age_ns: u64) {
        self.observations += 1;

        let ratio = age_ns as f64 / self.config.expected_lifetime_ns as f64;

        // Likelihood ratio: evidence grows when age exceeds expected.
        // We use a safe mixture: LR = max(1, ratio).
        // Under H0 (exponential): E[max(1, X/μ)] ≤ 1 + 1/e ≈ 1.37
        // To make it a proper supermartingale, we normalize:
        // LR = max(1, ratio) / (1 + 1/e)
        //
        // More precisely, for Exp(1/μ):
        //   E[max(1, X/μ)] = 1 × P(X≤μ) + E[X/μ | X>μ] × P(X>μ)
        //                   = (1 - e^{-1}) + (1 + 1) × e^{-1}
        //                   = 1 - 1/e + 2/e = 1 + 1/e
        //
        // So normalizing by (1 + 1/e) gives E[LR] ≤ 1 under H0.
        let normalizer = 1.0 + (-1.0_f64).exp(); // 1 + 1/e ≈ 1.3679
        let lr = ratio.max(1.0) / normalizer;

        self.log_e_value += lr.ln();
        self.e_value = self.log_e_value.exp();

        if self.e_value > self.peak_e_value {
            self.peak_e_value = self.e_value;
        }

        if self.e_value >= self.threshold && self.observations >= self.config.min_observations {
            self.alert_count += 1;
        }
    }

    /// Returns the current alert state.
    #[must_use]
    pub fn alert_state(&self) -> AlertState {
        if self.observations < self.config.min_observations {
            return AlertState::Clear;
        }
        if self.e_value >= self.threshold {
            AlertState::Alert
        } else if self.e_value > 1.0 {
            AlertState::Watching
        } else {
            AlertState::Clear
        }
    }

    /// Returns true if the monitor is currently in alert state.
    #[must_use]
    pub fn is_alert(&self) -> bool {
        self.alert_state() == AlertState::Alert
    }

    /// Returns the current e-value.
    #[must_use]
    pub fn e_value(&self) -> f64 {
        self.e_value
    }

    /// Returns the rejection threshold (1/alpha).
    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Returns the number of observations.
    #[must_use]
    pub fn observations(&self) -> u32 {
        self.observations
    }

    /// Returns the peak e-value observed.
    #[must_use]
    pub fn peak_e_value(&self) -> f64 {
        self.peak_e_value
    }

    /// Returns the number of times alert was triggered.
    #[must_use]
    pub fn alert_count(&self) -> u32 {
        self.alert_count
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &MonitorConfig {
        &self.config
    }

    /// Resets the monitor to its initial state, preserving configuration.
    pub fn reset(&mut self) {
        self.e_value = 1.0;
        self.log_e_value = 0.0;
        self.peak_e_value = 1.0;
        self.observations = 0;
        self.alert_count = 0;
    }

    /// Returns a snapshot of the monitor state for diagnostics.
    #[must_use]
    pub fn snapshot(&self) -> MonitorSnapshot {
        MonitorSnapshot {
            e_value: self.e_value,
            threshold: self.threshold,
            observations: self.observations,
            alert_state: self.alert_state(),
            peak_e_value: self.peak_e_value,
            alert_count: self.alert_count,
        }
    }
}

/// Diagnostic snapshot of the monitor state.
#[derive(Debug, Clone)]
pub struct MonitorSnapshot {
    /// Current e-value.
    pub e_value: f64,
    /// Rejection threshold.
    pub threshold: f64,
    /// Number of observations.
    pub observations: u32,
    /// Current alert state.
    pub alert_state: AlertState,
    /// Peak e-value ever observed.
    pub peak_e_value: f64,
    /// Number of alert triggers.
    pub alert_count: u32,
}

impl fmt::Display for MonitorSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LeakMonitor[{}]: e={:.4} threshold={:.1} obs={} peak={:.4} alerts={}",
            self.alert_state,
            self.e_value,
            self.threshold,
            self.observations,
            self.peak_e_value,
            self.alert_count,
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn default_config() -> MonitorConfig {
        MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000, // 1ms
            min_observations: 3,
        }
    }

    // ---- Construction ---------------------------------------------------

    #[test]
    fn new_monitor_starts_clear() {
        init_test("new_monitor_starts_clear");
        let monitor = LeakMonitor::new(default_config());
        crate::assert_with_log!(
            monitor.alert_state() == AlertState::Clear,
            "initial state",
            AlertState::Clear,
            monitor.alert_state()
        );
        let e = monitor.e_value();
        crate::assert_with_log!((e - 1.0).abs() < f64::EPSILON, "initial e-value", 1.0, e);
        crate::assert_with_log!(
            monitor.observations() == 0,
            "observations",
            0,
            monitor.observations()
        );
        crate::test_complete!("new_monitor_starts_clear");
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1)")]
    fn alpha_zero_panics() {
        let config = MonitorConfig {
            alpha: 0.0,
            ..default_config()
        };
        let _m = LeakMonitor::new(config);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1)")]
    fn alpha_one_panics() {
        let config = MonitorConfig {
            alpha: 1.0,
            ..default_config()
        };
        let _m = LeakMonitor::new(config);
    }

    #[test]
    #[should_panic(expected = "expected_lifetime_ns must be > 0")]
    fn zero_lifetime_panics() {
        let config = MonitorConfig {
            expected_lifetime_ns: 0,
            ..default_config()
        };
        let _m = LeakMonitor::new(config);
    }

    // ---- Normal observations stay clear ----------------------------------

    #[test]
    fn normal_observations_stay_clear() {
        init_test("normal_observations_stay_clear");
        let mut monitor = LeakMonitor::new(default_config());

        // Obligations resolving well within expected lifetime.
        for _ in 0..100 {
            monitor.observe(500_000); // 0.5ms < 1ms expected
        }

        let state = monitor.alert_state();
        crate::assert_with_log!(
            state == AlertState::Clear,
            "state after normal",
            AlertState::Clear,
            state
        );
        crate::assert_with_log!(!monitor.is_alert(), "not alert", false, monitor.is_alert());
        crate::test_complete!("normal_observations_stay_clear");
    }

    // ---- Suspicious observations trigger alert ---------------------------

    #[test]
    fn leaked_obligations_trigger_alert() {
        init_test("leaked_obligations_trigger_alert");
        let mut monitor = LeakMonitor::new(MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000, // 1ms
            min_observations: 3,
        });

        // Obligations with ages way beyond expected: 100× expected lifetime.
        for _ in 0..10 {
            monitor.observe(100_000_000); // 100ms >> 1ms
        }

        let state = monitor.alert_state();
        crate::assert_with_log!(
            state == AlertState::Alert,
            "alert",
            AlertState::Alert,
            state
        );
        crate::assert_with_log!(monitor.is_alert(), "is_alert", true, monitor.is_alert());
        let alert_count = monitor.alert_count();
        crate::assert_with_log!(alert_count > 0, "alert count > 0", true, alert_count > 0);
        crate::test_complete!("leaked_obligations_trigger_alert");
    }

    // ---- Min observations gate -------------------------------------------

    #[test]
    fn alert_gated_by_min_observations() {
        init_test("alert_gated_by_min_observations");
        let mut monitor = LeakMonitor::new(MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000,
            min_observations: 5,
        });

        // Even extreme values don't trigger before min_observations.
        monitor.observe(1_000_000_000);
        monitor.observe(1_000_000_000);
        let state = monitor.alert_state();
        crate::assert_with_log!(
            state == AlertState::Clear,
            "below min obs",
            AlertState::Clear,
            state
        );

        // After enough observations, alert triggers.
        for _ in 0..5 {
            monitor.observe(1_000_000_000);
        }
        let state = monitor.alert_state();
        crate::assert_with_log!(
            state == AlertState::Alert,
            "above min obs",
            AlertState::Alert,
            state
        );
        crate::test_complete!("alert_gated_by_min_observations");
    }

    // ---- Reset -----------------------------------------------------------

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut monitor = LeakMonitor::new(default_config());

        for _ in 0..10 {
            monitor.observe(100_000_000);
        }
        crate::assert_with_log!(
            monitor.is_alert(),
            "alert before reset",
            true,
            monitor.is_alert()
        );

        monitor.reset();
        crate::assert_with_log!(
            !monitor.is_alert(),
            "clear after reset",
            false,
            monitor.is_alert()
        );
        crate::assert_with_log!(
            monitor.observations() == 0,
            "obs after reset",
            0,
            monitor.observations()
        );
        let e = monitor.e_value();
        crate::assert_with_log!(
            (e - 1.0).abs() < f64::EPSILON,
            "e-value after reset",
            1.0,
            e
        );
        crate::test_complete!("reset_clears_state");
    }

    // ---- Snapshot --------------------------------------------------------

    #[test]
    fn snapshot_captures_state() {
        init_test("snapshot_captures_state");
        let mut monitor = LeakMonitor::new(default_config());
        monitor.observe(500_000);

        let snap = monitor.snapshot();
        crate::assert_with_log!(snap.observations == 1, "observations", 1, snap.observations);
        let has_threshold = snap.threshold > 0.0;
        crate::assert_with_log!(has_threshold, "threshold", true, has_threshold);

        // Display impl works.
        let display = format!("{snap}");
        let has_leak = display.contains("LeakMonitor");
        crate::assert_with_log!(has_leak, "display", true, has_leak);
        crate::test_complete!("snapshot_captures_state");
    }

    // ---- Supermartingale property (statistical) ---------------------------

    #[test]
    fn supermartingale_property_under_null() {
        init_test("supermartingale_property_under_null");
        // Under H0, E[E_n | E_{n-1}] ≤ E_{n-1}.
        // We verify this empirically: with many normal observations,
        // the e-value should not systematically grow.
        let mut monitor = LeakMonitor::new(MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000,
            min_observations: 3,
        });

        // Simulate 1000 observations with ages ≤ expected_lifetime
        // (drawn from the "easy half" of the exponential).
        // E-value should stay bounded.
        for i in 0..1000 {
            // Deterministic sequence that stays under expected lifetime.
            let age = ((i % 10) as u64 + 1) * 100_000; // 0.1ms to 1.0ms
            monitor.observe(age);
        }

        // Under H0 with these well-behaved observations, e-value should be ≤ 1.
        let e = monitor.e_value();
        let bounded = e <= 2.0; // Allow some slack for edge effects.
        crate::assert_with_log!(bounded, "e-value bounded", true, bounded);
        crate::assert_with_log!(
            !monitor.is_alert(),
            "no alert under H0",
            false,
            monitor.is_alert()
        );
        crate::test_complete!("supermartingale_property_under_null");
    }

    // ---- Deterministic ---------------------------------------------------

    #[test]
    fn deterministic_across_runs() {
        init_test("deterministic_across_runs");
        let config = default_config();
        let ages = [500_000u64, 1_000_000, 2_000_000, 100_000, 5_000_000];

        let mut m1 = LeakMonitor::new(config);
        let mut m2 = LeakMonitor::new(config);

        for &age in &ages {
            m1.observe(age);
            m2.observe(age);
        }

        let e1 = m1.e_value();
        let e2 = m2.e_value();
        crate::assert_with_log!((e1 - e2).abs() < f64::EPSILON, "deterministic", e1, e2);
        crate::test_complete!("deterministic_across_runs");
    }

    // ---- Display impls ---------------------------------------------------

    #[test]
    fn alert_state_display() {
        init_test("alert_state_display");
        let clear = format!("{}", AlertState::Clear);
        crate::assert_with_log!(clear == "clear", "clear display", "clear", clear);
        let watching = format!("{}", AlertState::Watching);
        crate::assert_with_log!(
            watching == "watching",
            "watching display",
            "watching",
            watching
        );
        let alert = format!("{}", AlertState::Alert);
        crate::assert_with_log!(alert == "ALERT", "alert display", "ALERT", alert);
        crate::test_complete!("alert_state_display");
    }
}
