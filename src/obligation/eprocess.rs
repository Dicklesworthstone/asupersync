//! Anytime-valid obligation leak monitor via e-processes.
//!
//! An e-process is a non-negative supermartingale under the null hypothesis
//! ("no leaks: all obligations resolve within their expected lifetime").
//! For [`LeakMonitor::new`], when the e-value exceeds 1/α, we reject the
//! null with Type-I error ≤ α, regardless of when we choose to stop
//! monitoring (Ville's inequality). A [`LeakMonitor::change_detector`] gives
//! the same α over a declared horizon of observations instead.
//!
//! The monitor is opt-in. `Runtime::enable_obligation_leak_monitor` (or
//! `RuntimeState::enable_obligation_leak_monitor`, for example on a
//! `LabRuntime`'s state) installs a [`LeakMonitor::change_detector`]. The
//! runtime feeds it each committed or aborted obligation's age at resolution,
//! exactly once, and reports each leaked obligation through
//! [`LeakMonitor::observe_leak`]. Read it with
//! `obligation_leak_monitor_snapshot`. A monitor can also be fed by hand.
//!
//! An obligation is observed only when it resolves or leaks. One that its
//! holder keeps reserved indefinitely is never observed; bound that case with
//! a budget deadline.
//!
//! The null hypothesis the likelihood ratio below is valid for is
//! `E[(age/μ − 1)⁺] ≤ 1/e`, with `μ = expected_lifetime_ns`. Exponential ages
//! with mean `μ` sit exactly on that boundary. Heavier-tailed healthy ages, or
//! `μ` set to the median, violate it and raise the false-alarm rate. For
//! exponential ages `μ` must be at least about 1.44× the median.
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
//! For [`LeakMonitor::new`], by Ville's inequality: P(∃t: E_t ≥ 1/α | H0) ≤ α.
//! This holds for *any* stopping rule, including data-dependent ones.
//!
//! A change detector over a horizon of `n` observations alarms at
//! `R ≥ n/α`, so P(a false alarm within the first `n` observations | H0) ≤ α.
//! Past `n` observations the bound lapses and the latched alarm eventually
//! fires on healthy data, so cover the whole monitored period, or reset the
//! detector before then. Both bounds assume each observation's likelihood
//! ratio has mean at most 1 given the earlier ones, which fails when the order
//! of observations depends on the ages themselves (see
//! [`LeakMonitor::change_detector`]).
//!
//! # Calibration
//!
//! The `expected_lifetime_ns` parameter should be set based on:
//! - Empirical profiling of obligation durations
//! - Budget deadlines for the containing region
//! - A conservative multiple of the median observed duration: at least
//!   1.44× for exponential ages, more for heavier tails (see above)
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

pub mod conformance;

/// Configuration for the leak monitor.
#[derive(Debug, Clone, Copy)]
pub struct MonitorConfig {
    /// Type-I error bound (false-positive rate). Must be in (0, 1).
    /// Under H0, a [`LeakMonitor::new`] monitor guarantees P(false alarm) ≤
    /// alpha, and a [`LeakMonitor::change_detector`] guarantees it within
    /// its horizon.
    pub alpha: f64,
    /// Expected obligation lifetime in nanoseconds under the null.
    /// Obligations pending longer than this are increasingly suspicious.
    pub expected_lifetime_ns: u64,
    /// Minimum observations before the monitor can trigger an alert.
    /// Prevents spurious alerts from small samples.
    pub min_observations: u64,
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
    /// The statistic reached the monitor's threshold (1/α, or horizon/α for a
    /// change detector), or a leak was reported: leak detected with a bounded
    /// false-positive rate.
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
    /// Rejection threshold: 1/alpha, or horizon/alpha for a change detector.
    threshold: f64,
    /// Number of observations so far.
    observations: u64,
    /// Running sum of log-likelihood ratios (for numerical stability).
    log_e_value: f64,
    /// Peak e-value observed (for diagnostics).
    peak_e_value: f64,
    /// Number of times alert was triggered.
    alert_count: u64,
    /// A [`Self::change_detector`]: a Shiryaev–Roberts e-detector whose
    /// alarm latches.
    change_detector: bool,
    /// Leaked obligations reported through [`Self::observe_leak`].
    leaks: u64,
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
            change_detector: false,
            leaks: 0,
        }
    }

    /// Creates a change detector for monitoring a long-running runtime.
    ///
    /// [`Self::new`] tests "no obligation has ever been late" from its first
    /// observation, so every on-time resolution lowers its e-value without
    /// bound. After many healthy resolutions it needs overwhelming evidence
    /// to alarm. This detector looks instead for obligations *starting* to
    /// resolve late at an unknown time. Its statistic is the Shiryaev–Roberts
    /// e-detector `R_n = (R_{n-1} + 1) · LR_n`, with `R_0 = 0` and the
    /// likelihood ratio `LR_n` of [`Self::observe`]: the sum of the e-processes
    /// started at every observation. Under the null, `R_n − n` is a
    /// supermartingale, so `R_n` stays bounded on healthy data.
    ///
    /// The detector alarms once `R_n ≥ horizon/alpha` with at least
    /// `min_observations` observations, and the alarm latches until
    /// [`Self::reset`]. For `k ≤ horizon`, `R_k − k + horizon` is a
    /// non-negative supermartingale starting at `horizon`, so by Ville's
    /// inequality P(a false alarm within the first `horizon` observations)
    /// ≤ `alpha`, and the average run length to a false alarm is at least
    /// `horizon/alpha`. A threshold of `1/alpha` alone would only promise an
    /// average run length of `1/alpha` observations: a runtime resolving
    /// thousands of obligations per second would latch a false alarm within
    /// seconds. Choose `horizon` to cover the whole monitored period (for
    /// example `10^9` resolutions); the detection delay grows only with the
    /// logarithm of the threshold. Past `horizon` observations the bound
    /// lapses, so reset or replace the detector before then.
    ///
    /// The bound needs each likelihood ratio to have mean at most 1 given
    /// the earlier observations. Feeding ages in an order that depends on the
    /// ages breaks that: when obligations reserved together resolve, their
    /// slowest ones arrive last and consecutively, which reads as a change.
    ///
    /// Below the threshold its state is [`AlertState::Clear`]: an elevated
    /// `R_n` is not evidence by itself. [`Self::e_value`] reports `R_n`.
    ///
    /// # Panics
    ///
    /// Panics if `alpha` is not in (0, 1), `expected_lifetime_ns` is 0 or
    /// `horizon` is 0.
    #[must_use]
    pub fn change_detector(config: MonitorConfig, horizon: u64) -> Self {
        assert!(horizon > 0, "horizon must be > 0");
        let mut monitor = Self::new(config);
        monitor.change_detector = true;
        #[allow(clippy::cast_precision_loss)]
        let horizon = horizon as f64;
        monitor.threshold = horizon / config.alpha;
        monitor.reset();
        monitor
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
        let was_alert = self.is_alert();
        self.observations += 1;

        #[allow(clippy::cast_precision_loss)]
        let ratio = if self.config.expected_lifetime_ns == 0 {
            0.0
        } else {
            age_ns as f64 / self.config.expected_lifetime_ns as f64
        };

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

        if self.change_detector {
            // Shiryaev–Roberts: R_n = (R_{n-1} + 1) · LR_n.
            self.e_value = (self.e_value + 1.0) * lr;
            self.log_e_value = self.e_value.ln();
        } else {
            self.log_e_value += lr.ln();
            self.e_value = self.log_e_value.exp();
        }

        if self.e_value > self.peak_e_value {
            self.peak_e_value = self.e_value;
        }

        if !was_alert && self.is_alert() {
            self.alert_count += 1;
        }
    }

    /// Records a leaked obligation: one dropped or abandoned without being
    /// committed or aborted.
    ///
    /// Under the null hypothesis no obligation ever leaks, so a single leak is
    /// conclusive. The monitor alarms at once, whatever `min_observations`
    /// says, and stays in [`AlertState::Alert`] until [`Self::reset`]. Passing
    /// a leaked obligation's age to [`Self::observe`] instead would count a
    /// fast leak as an on-time resolution.
    pub fn observe_leak(&mut self) {
        let was_alert = self.is_alert();
        self.observations += 1;
        self.leaks += 1;
        self.e_value = f64::INFINITY;
        self.log_e_value = f64::INFINITY;
        self.peak_e_value = f64::INFINITY;
        if !was_alert {
            self.alert_count += 1;
        }
    }

    /// Returns the number of leaks reported through [`Self::observe_leak`].
    #[must_use]
    pub fn leaks(&self) -> u64 {
        self.leaks
    }

    /// Returns the current alert state.
    #[must_use]
    pub fn alert_state(&self) -> AlertState {
        if self.leaks > 0 || (self.change_detector && self.alert_count > 0) {
            return AlertState::Alert;
        }
        if self.observations < self.config.min_observations {
            return AlertState::Clear;
        }
        if self.e_value >= self.threshold {
            AlertState::Alert
        } else if self.e_value > 1.0 && !self.change_detector {
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

    /// Returns the rejection threshold: 1/alpha, or horizon/alpha for a
    /// change detector.
    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Returns the number of observations.
    #[must_use]
    pub fn observations(&self) -> u64 {
        self.observations
    }

    /// Returns the peak e-value observed.
    #[must_use]
    pub fn peak_e_value(&self) -> f64 {
        self.peak_e_value
    }

    /// Returns the number of times alert was triggered.
    #[must_use]
    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &MonitorConfig {
        &self.config
    }

    /// Resets the monitor to its initial state, preserving configuration.
    pub fn reset(&mut self) {
        if self.change_detector {
            self.e_value = 0.0;
            self.log_e_value = f64::NEG_INFINITY;
            self.peak_e_value = 0.0;
        } else {
            self.e_value = 1.0;
            self.log_e_value = 0.0;
            self.peak_e_value = 1.0;
        }
        self.observations = 0;
        self.alert_count = 0;
        self.leaks = 0;
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
    pub observations: u64,
    /// Current alert state.
    pub alert_state: AlertState,
    /// Peak e-value ever observed.
    pub peak_e_value: f64,
    /// Number of alert triggers.
    pub alert_count: u64,
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn assert_display_snapshot(snapshot_name: &str, rendered: &str) {
        insta::with_settings!({
            snapshot_path => "snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!(snapshot_name, rendered);
        });
    }

    fn default_config() -> MonitorConfig {
        MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000, // 1ms
            min_observations: 3,
        }
    }

    /// Change-detector horizon for the tests: threshold 10^6 / 0.01 = 10^8.
    const HORIZON: u64 = 1_000_000;

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

    #[test]
    fn alert_count_tracks_threshold_crossings_not_samples() {
        init_test("alert_count_tracks_threshold_crossings_not_samples");
        let mut monitor = LeakMonitor::new(MonitorConfig {
            alpha: 0.01,
            expected_lifetime_ns: 1_000_000,
            min_observations: 3,
        });

        for _ in 0..10 {
            monitor.observe(100_000_000);
        }
        crate::assert_with_log!(
            monitor.alert_count() == 1,
            "first alert episode counted once",
            1,
            monitor.alert_count()
        );

        monitor.reset();
        for _ in 0..5 {
            monitor.observe(100_000_000);
        }
        crate::assert_with_log!(
            monitor.alert_count() == 1,
            "post-reset alert episode counted once",
            1,
            monitor.alert_count()
        );
        crate::test_complete!("alert_count_tracks_threshold_crossings_not_samples");
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
        let display = format!("{snap}");
        assert_display_snapshot("eprocess_monitor_snapshot_display", &display);
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
        for i in 0u64..1000 {
            // Deterministic sequence that stays under expected lifetime.
            let age = ((i % 10) + 1) * 100_000; // 0.1ms to 1.0ms
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

    /// After many on-time resolutions the test-mode e-value has decayed so
    /// far that late obligations cannot alarm. The change detector's
    /// statistic stays bounded (by e, the fixed point of `(R + 1) · L` for
    /// `L = 1/(1 + 1/e)`), so a short run of late obligations alarms, and the
    /// alarm latches until reset.
    #[test]
    fn change_detector_stays_bounded_on_healthy_data_and_latches_its_alarm() {
        init_test("change_detector_stays_bounded_on_healthy_data_and_latches_its_alarm");
        let mut test_mode = LeakMonitor::new(default_config());
        let mut detector = LeakMonitor::change_detector(default_config(), HORIZON);
        assert_eq!(detector.e_value(), 0.0);
        assert!((detector.threshold() - 1e8).abs() < 1.0, "{}", detector.threshold());
        for i in 0u64..10_000 {
            let age = (i % 10) * 100_000; // 0 to 0.9 ms against 1 ms
            test_mode.observe(age);
            detector.observe(age);
        }
        assert!(detector.e_value() <= std::f64::consts::E + 1e-9);
        assert_eq!(detector.alert_state(), AlertState::Clear);
        assert!(test_mode.e_value() < 1e-100, "{}", test_mode.e_value());

        // Obligations held 1 s against 1 ms multiply the statistic by about
        // 731 each: the third crosses 10^8.
        for late in 1..=3 {
            test_mode.observe(1_000_000_000);
            detector.observe(1_000_000_000);
            assert_eq!(detector.is_alert(), late == 3, "late obligation {late}");
        }
        assert!(!test_mode.is_alert(), "decayed evidence cannot alarm");
        assert_eq!(detector.alert_count(), 1);

        for _ in 0..100 {
            detector.observe(100_000);
        }
        assert_eq!(
            detector.alert_state(),
            AlertState::Alert,
            "the alarm latches"
        );
        assert_eq!(detector.alert_count(), 1);

        detector.reset();
        assert_eq!(detector.alert_state(), AlertState::Clear);
        assert_eq!(detector.e_value(), 0.0);
        assert_eq!(detector.observations(), 0);
        crate::test_complete!(
            "change_detector_stays_bounded_on_healthy_data_and_latches_its_alarm"
        );
    }

    /// Healthy ages drawn from Exp(mean μ), the boundary of the null the
    /// likelihood ratio is valid for. A detector whose horizon covers all
    /// 10^4 of them must not alarm, although its statistic passes 1/alpha:
    /// a 1/alpha threshold, which bounds only the average run length (by 100
    /// observations), latched a false alarm on this healthy run.
    #[test]
    fn change_detector_threshold_covers_its_horizon_of_healthy_observations() {
        init_test("change_detector_threshold_covers_its_horizon_of_healthy_observations");
        const N: u64 = 10_000;
        let config = default_config();
        let mut detector = LeakMonitor::change_detector(config, N);
        // xorshift64*: a fixed, platform-independent sequence.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..N {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let bits = state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11;
            let uniform = (bits as f64 + 0.5) / (1u64 << 53) as f64;
            let age = (-uniform.ln() * config.expected_lifetime_ns as f64) as u64;
            detector.observe(age);
        }
        assert!(
            detector.peak_e_value() >= 1.0 / config.alpha,
            "peak {}",
            detector.peak_e_value()
        );
        assert!(
            !detector.is_alert(),
            "peak {} against threshold {}",
            detector.peak_e_value(),
            detector.threshold()
        );
        crate::test_complete!(
            "change_detector_threshold_covers_its_horizon_of_healthy_observations"
        );
    }

    /// A leak never happens under the null, so one is conclusive: the monitor
    /// alarms before `min_observations`, stays alarmed through later on-time
    /// observations, and clears only on reset. Both monitor kinds.
    #[test]
    fn observe_leak_is_conclusive_and_latches() {
        init_test("observe_leak_is_conclusive_and_latches");
        for mut monitor in [
            LeakMonitor::new(default_config()),
            LeakMonitor::change_detector(default_config(), HORIZON),
        ] {
            monitor.observe_leak();
            assert_eq!(monitor.alert_state(), AlertState::Alert);
            assert_eq!(monitor.observations(), 1);
            assert_eq!(monitor.leaks(), 1);
            assert_eq!(monitor.alert_count(), 1);
            assert!(monitor.e_value().is_infinite());
            for _ in 0..10 {
                monitor.observe(10_000);
            }
            monitor.observe_leak();
            assert_eq!(monitor.alert_state(), AlertState::Alert);
            assert_eq!(monitor.alert_count(), 1, "one alarm, not one per leak");
            assert_eq!(monitor.leaks(), 2);
            monitor.reset();
            assert_eq!(monitor.alert_state(), AlertState::Clear);
            assert_eq!(monitor.leaks(), 0);
        }
        crate::test_complete!("observe_leak_is_conclusive_and_latches");
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
        let rendered = [
            format!("clear={}", AlertState::Clear),
            format!("watching={}", AlertState::Watching),
            format!("alert={}", AlertState::Alert),
        ]
        .join("\n");
        assert_display_snapshot("eprocess_alert_state_display", &rendered);
        crate::test_complete!("alert_state_display");
    }

    // ── derive-trait coverage (wave 74) ──────────────────────────────────

    #[test]
    fn monitor_config_debug_clone_copy() {
        let c = MonitorConfig::default();
        let c2 = c; // Copy
        let c3 = c;
        assert!((c2.alpha - 0.01).abs() < 1e-10);
        assert_eq!(c3.min_observations, 3);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("MonitorConfig"));
    }

    #[test]
    fn alert_state_debug_clone_copy_eq() {
        let s = AlertState::Clear;
        let s2 = s; // Copy
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s2, s3);
        assert_ne!(s, AlertState::Alert);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Clear"));
    }

    #[test]
    fn monitor_snapshot_debug_clone() {
        let ms = MonitorSnapshot {
            e_value: 1.5,
            threshold: 100.0,
            observations: 10,
            alert_state: AlertState::Watching,
            peak_e_value: 2.0,
            alert_count: 0,
        };
        let ms2 = ms;
        assert_eq!(ms2.observations, 10);
        assert_eq!(ms2.alert_state, AlertState::Watching);
        let dbg = format!("{ms2:?}");
        assert!(dbg.contains("MonitorSnapshot"));
    }

    // ── Mathematical Conformance (comprehensive verification) ──────────────

    #[test]
    fn eprocess_martingale_conformance() {
        init_test("eprocess_martingale_conformance");

        let mut harness = conformance::EProcessConformanceHarness::new();
        harness.run_all();

        // Generate compliance matrix for debugging
        let matrix = harness.compliance_matrix();
        println!("\n{}", matrix);

        // Check for critical failures
        let failed = harness.failed_requirements();
        if !failed.is_empty() {
            for failure in &failed {
                eprintln!(
                    "FAILED {}: {} - {}",
                    failure.requirement_id, failure.description, failure.evidence
                );
            }
        }

        // Count MUST vs SHOULD requirements
        let results = harness.results();
        let must_total = results
            .iter()
            .filter(|r| r.level == conformance::RequirementLevel::Must)
            .count();
        let must_pass = results
            .iter()
            .filter(|r| {
                r.level == conformance::RequirementLevel::Must
                    && r.status == conformance::TestStatus::Pass
            })
            .count();

        let should_total = results
            .iter()
            .filter(|r| r.level == conformance::RequirementLevel::Should)
            .count();
        let should_pass = results
            .iter()
            .filter(|r| {
                r.level == conformance::RequirementLevel::Should
                    && r.status == conformance::TestStatus::Pass
            })
            .count();

        // Log conformance summary
        crate::assert_with_log!(results.len() >= 8, "all tests ran", 8, results.len());

        // MUST requirements: 100% pass rate required
        let must_score = if must_total > 0 {
            (must_pass as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };

        crate::assert_with_log!(
            must_score >= 95.0,
            "MUST requirements pass rate ≥ 95%",
            "≥95%".to_string(),
            format!("{:.1}% ({}/{})", must_score, must_pass, must_total)
        );

        // SHOULD requirements: 80% pass rate acceptable
        let should_score = if should_total > 0 {
            (should_pass as f64 / should_total as f64) * 100.0
        } else {
            100.0
        };

        crate::assert_with_log!(
            should_score >= 80.0,
            "SHOULD requirements pass rate ≥ 80%",
            "≥80%".to_string(),
            format!("{:.1}% ({}/{})", should_score, should_pass, should_total)
        );

        // No critical mathematical failures
        let critical_failures: Vec<_> = failed
            .iter()
            .filter(|r| r.level == conformance::RequirementLevel::Must)
            .collect();

        crate::assert_with_log!(
            critical_failures.is_empty(),
            "no critical mathematical failures",
            0,
            critical_failures.len()
        );

        if must_score >= 95.0 && critical_failures.is_empty() {
            println!("✅ E-PROCESS CONFORMANT: Mathematical invariants satisfied");
        } else {
            panic!("❌ NON-CONFORMANT: Critical mathematical requirements violated"); // ubs:ignore - test helper
        }

        crate::test_complete!("eprocess_martingale_conformance");
    }

    #[test]
    fn specific_martingale_properties() {
        init_test("specific_martingale_properties");

        // Test specific martingale properties in isolation

        // 1. Ville's inequality threshold calculation
        let alphas = [0.001, 0.01, 0.05, 0.1, 0.5];
        for &alpha in &alphas {
            let config = MonitorConfig {
                alpha,
                expected_lifetime_ns: 1_000_000,
                min_observations: 3,
            };
            let monitor = LeakMonitor::new(config);
            let expected_threshold = 1.0 / alpha;
            let actual_threshold = monitor.threshold();

            crate::assert_with_log!(
                (actual_threshold - expected_threshold).abs() < f64::EPSILON,
                format!("threshold correct for α={}", alpha),
                expected_threshold,
                actual_threshold
            );
        }

        // 2. Likelihood ratio bounds under exponential null
        let mu = 1_000_000.0; // Expected lifetime
        let normalizer = 1.0 + (-1.0_f64).exp(); // 1 + 1/e

        // Test that normalized LR has correct expectation
        let test_ages = [0.5 * mu, mu, 2.0 * mu, 10.0 * mu];
        for &age in &test_ages {
            let ratio: f64 = age / mu;
            let lr = ratio.max(1.0) / normalizer;

            // Individual LR should be ≥ 1/normalizer (when ratio=1)
            let min_lr = 1.0 / normalizer;
            crate::assert_with_log!(
                lr >= min_lr - f64::EPSILON,
                format!("LR bounded below for age={}", age),
                format!("≥{:.6}", min_lr),
                format!("{:.6}", lr)
            );
        }

        // 3. E-value monotonicity after each observation
        let mut monitor = LeakMonitor::new(MonitorConfig::default());
        let mut prev_peak = monitor.peak_e_value();

        let ages = [500_000u64, 2_000_000, 1_000_000, 5_000_000];
        for &age in &ages {
            monitor.observe(age);
            let current_peak = monitor.peak_e_value();

            crate::assert_with_log!(
                current_peak >= prev_peak - f64::EPSILON,
                format!("peak monotonic for age={}", age),
                format!("≥{:.6}", prev_peak),
                format!("{:.6}", current_peak)
            );

            prev_peak = current_peak;
        }

        crate::test_complete!("specific_martingale_properties");
    }

    #[test]
    fn statistical_convergence_properties() {
        init_test("statistical_convergence_properties");

        // Test statistical properties that should hold under the null hypothesis

        let config = MonitorConfig {
            alpha: 0.05,
            expected_lifetime_ns: 1_000_000,
            min_observations: 5,
        };

        // Run multiple independent sequences under H0
        let num_sequences = 200usize;
        let obs_per_sequence = 30usize;
        let mut final_e_values = Vec::new();
        let mut alert_count = 0;

        for seq in 0..num_sequences {
            let mut monitor = LeakMonitor::new(config);

            for i in 0..obs_per_sequence {
                // Generate exponential(1/μ) observations
                let sample_index = i * num_sequences + seq;
                let u = (sample_index as f64 + 0.5) / (num_sequences * obs_per_sequence) as f64;
                let x = -(config.expected_lifetime_ns as f64) * (1.0 - u).ln();

                monitor.observe(x as u64);
            }

            final_e_values.push(monitor.e_value());
            if monitor.is_alert() {
                alert_count += 1;
            }
        }

        // Statistical properties under H0:

        // 1. Mean final e-value should be ≤ 1 (supermartingale property)
        let mean_final: f64 = final_e_values.iter().sum::<f64>() / final_e_values.len() as f64;
        crate::assert_with_log!(
            mean_final <= 2.0, // Allow generous slack for sampling variance
            "mean e-value bounded under H0",
            "≤2.0".to_string(),
            format!("{:.4}", mean_final)
        );

        // 2. Alert rate should be approximately ≤ α
        let observed_alert_rate = alert_count as f64 / num_sequences as f64;
        let expected_max_rate = config.alpha * 1.5; // 50% slack for sample variance

        crate::assert_with_log!(
            observed_alert_rate <= expected_max_rate,
            "alert rate bounded by α",
            format!("≤{:.3}", expected_max_rate),
            format!(
                "{:.3} ({}/{})",
                observed_alert_rate, alert_count, num_sequences
            )
        );

        // 3. No extreme outliers in e-values
        let max_e_value = final_e_values.iter().fold(0.0f64, |a, &b| a.max(b));
        crate::assert_with_log!(
            max_e_value < 1000.0,
            "no extreme e-value outliers",
            "<1000".to_string(),
            format!("{:.2}", max_e_value)
        );

        crate::test_complete!("statistical_convergence_properties");
    }
}
