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
#[path = "eprocess_inline_tests.rs"]
mod tests;
