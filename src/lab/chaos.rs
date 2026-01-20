//! Chaos testing configuration and injection hooks for the Lab runtime.
//!
//! This module provides configurable chaos injection for stress testing the runtime's
//! resilience to failures, delays, and other adverse conditions. All chaos is
//! deterministic given the same seed, making failures reproducible.
//!
//! # Chaos Types
//!
//! - **Cancellation**: Random cancellation injection at poll points
//! - **Delay**: Artificial delays during task execution
//! - **I/O Errors**: Simulated I/O failures with configurable error kinds
//! - **Wakeup Storms**: Spurious wakeups to test waker handling
//! - **Budget Exhaustion**: Simulate resource quota exhaustion
//!
//! # Determinism
//!
//! All chaos injection uses a deterministic RNG seeded from the configuration.
//! Running the same test with the same seed will produce identical chaos sequences.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::lab::chaos::{ChaosConfig, ChaosRng};
//!
//! // Create a light chaos configuration for CI
//! let config = ChaosConfig::light()
//!     .with_seed(42)
//!     .with_cancel_probability(0.01)
//!     .with_io_error_probability(0.05);
//!
//! // Use in Lab runtime
//! let mut rng = ChaosRng::from_config(&config);
//! if rng.should_inject_cancel(&config) {
//!     // Inject cancellation
//! }
//! ```

use std::io;
use std::ops::Range;
use std::time::Duration;

use crate::util::DetRng;

/// Configuration for chaos injection in the Lab runtime.
///
/// ChaosConfig controls what types of chaos are injected and with what probability.
/// All probabilities are in the range \[0.0, 1.0\].
///
/// # Presets
///
/// - [`ChaosConfig::off()`]: No chaos (all probabilities zero)
/// - [`ChaosConfig::light()`]: Light chaos suitable for CI (low probabilities)
/// - [`ChaosConfig::heavy()`]: Heavy chaos for thorough testing (higher probabilities)
#[derive(Debug, Clone)]
pub struct ChaosConfig {
    /// Seed for deterministic chaos (required).
    ///
    /// The same seed produces the same chaos sequence.
    pub seed: u64,

    /// Probability of injecting cancellation at each poll point.
    ///
    /// Range: \[0.0, 1.0\]. Default: 0.0 (no cancellation injection).
    pub cancel_probability: f64,

    /// Probability of adding delay at each poll point.
    ///
    /// Range: \[0.0, 1.0\]. Default: 0.0 (no delay injection).
    pub delay_probability: f64,

    /// Range of delays when delay is injected.
    ///
    /// A random duration in this range is selected uniformly.
    pub delay_range: Range<Duration>,

    /// Probability of I/O operation failing.
    ///
    /// Range: \[0.0, 1.0\]. Default: 0.0 (no I/O error injection).
    pub io_error_probability: f64,

    /// Error kinds to inject for I/O failures.
    ///
    /// When an I/O error is injected, one of these kinds is selected uniformly.
    pub io_error_kinds: Vec<io::ErrorKind>,

    /// Probability of triggering a spurious wakeup storm.
    ///
    /// Range: \[0.0, 1.0\]. Default: 0.0 (no wakeup storms).
    pub wakeup_storm_probability: f64,

    /// Number of spurious wakeups in a storm.
    ///
    /// When a storm is triggered, a random count in this range is selected.
    pub wakeup_storm_count: Range<usize>,

    /// Probability of budget exhaustion.
    ///
    /// Range: \[0.0, 1.0\]. Default: 0.0 (no budget exhaustion).
    pub budget_exhaust_probability: f64,
}

impl Default for ChaosConfig {
    /// Creates a ChaosConfig with all chaos disabled.
    fn default() -> Self {
        Self::off()
    }
}

impl ChaosConfig {
    /// Creates a new ChaosConfig with the given seed and all chaos disabled.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            cancel_probability: 0.0,
            delay_probability: 0.0,
            delay_range: Duration::ZERO..Duration::ZERO,
            io_error_probability: 0.0,
            io_error_kinds: Vec::new(),
            wakeup_storm_probability: 0.0,
            wakeup_storm_count: 1..5,
            budget_exhaust_probability: 0.0,
        }
    }

    /// Creates a ChaosConfig with all chaos disabled (same as default).
    ///
    /// Use this as a baseline, then enable specific chaos types.
    #[must_use]
    pub const fn off() -> Self {
        Self::new(0)
    }

    /// Preset for light chaos suitable for CI.
    ///
    /// Low probabilities to catch obvious issues without excessive flakiness.
    ///
    /// - Cancel: 1%
    /// - Delay: 5% (0-10ms)
    /// - I/O Error: 2%
    /// - Wakeup Storm: 1%
    /// - Budget Exhaust: 0.5%
    #[must_use]
    pub fn light() -> Self {
        Self {
            seed: 0,
            cancel_probability: 0.01,
            delay_probability: 0.05,
            delay_range: Duration::ZERO..Duration::from_millis(10),
            io_error_probability: 0.02,
            io_error_kinds: vec![
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::TimedOut,
                io::ErrorKind::WouldBlock,
            ],
            wakeup_storm_probability: 0.01,
            wakeup_storm_count: 1..5,
            budget_exhaust_probability: 0.005,
        }
    }

    /// Preset for heavy chaos for thorough testing.
    ///
    /// Higher probabilities to stress-test error handling.
    ///
    /// - Cancel: 10%
    /// - Delay: 20% (0-100ms)
    /// - I/O Error: 15%
    /// - Wakeup Storm: 5%
    /// - Budget Exhaust: 5%
    #[must_use]
    pub fn heavy() -> Self {
        Self {
            seed: 0,
            cancel_probability: 0.10,
            delay_probability: 0.20,
            delay_range: Duration::ZERO..Duration::from_millis(100),
            io_error_probability: 0.15,
            io_error_kinds: vec![
                io::ErrorKind::ConnectionReset,
                io::ErrorKind::ConnectionRefused,
                io::ErrorKind::ConnectionAborted,
                io::ErrorKind::TimedOut,
                io::ErrorKind::WouldBlock,
                io::ErrorKind::BrokenPipe,
                io::ErrorKind::NotConnected,
            ],
            wakeup_storm_probability: 0.05,
            wakeup_storm_count: 1..20,
            budget_exhaust_probability: 0.05,
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Builder methods
    // ───────────────────────────────────────────────────────────────────────────

    /// Sets the seed for deterministic chaos.
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Sets the probability of cancellation injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in \[0.0, 1.0\].
    #[must_use]
    pub fn with_cancel_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.cancel_probability = probability;
        self
    }

    /// Sets the probability of delay injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in \[0.0, 1.0\].
    #[must_use]
    pub fn with_delay_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.delay_probability = probability;
        self
    }

    /// Sets the range of delays when delay is injected.
    #[must_use]
    pub fn with_delay_range(mut self, range: Range<Duration>) -> Self {
        self.delay_range = range;
        self
    }

    /// Sets the probability of I/O error injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in \[0.0, 1.0\].
    #[must_use]
    pub fn with_io_error_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.io_error_probability = probability;
        self
    }

    /// Sets the error kinds to inject for I/O failures.
    #[must_use]
    pub fn with_io_error_kinds(mut self, kinds: Vec<io::ErrorKind>) -> Self {
        self.io_error_kinds = kinds;
        self
    }

    /// Sets the probability of wakeup storm injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in \[0.0, 1.0\].
    #[must_use]
    pub fn with_wakeup_storm_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.wakeup_storm_probability = probability;
        self
    }

    /// Sets the range of wakeup counts in a storm.
    #[must_use]
    pub fn with_wakeup_storm_count(mut self, range: Range<usize>) -> Self {
        self.wakeup_storm_count = range;
        self
    }

    /// Sets the probability of budget exhaustion injection.
    ///
    /// # Panics
    ///
    /// Panics if `probability` is not in \[0.0, 1.0\].
    #[must_use]
    pub fn with_budget_exhaust_probability(mut self, probability: f64) -> Self {
        assert!(
            (0.0..=1.0).contains(&probability),
            "probability must be in [0.0, 1.0], got {probability}"
        );
        self.budget_exhaust_probability = probability;
        self
    }

    // ───────────────────────────────────────────────────────────────────────────
    // Introspection
    // ───────────────────────────────────────────────────────────────────────────

    /// Returns true if any chaos is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.cancel_probability > 0.0
            || self.delay_probability > 0.0
            || self.io_error_probability > 0.0
            || self.wakeup_storm_probability > 0.0
            || self.budget_exhaust_probability > 0.0
    }

    /// Returns a summary of enabled chaos types.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.cancel_probability > 0.0 {
            parts.push(format!("cancel:{:.1}%", self.cancel_probability * 100.0));
        }
        if self.delay_probability > 0.0 {
            parts.push(format!("delay:{:.1}%", self.delay_probability * 100.0));
        }
        if self.io_error_probability > 0.0 {
            parts.push(format!("io_err:{:.1}%", self.io_error_probability * 100.0));
        }
        if self.wakeup_storm_probability > 0.0 {
            parts.push(format!(
                "wakeup:{:.1}%",
                self.wakeup_storm_probability * 100.0
            ));
        }
        if self.budget_exhaust_probability > 0.0 {
            parts.push(format!(
                "budget:{:.1}%",
                self.budget_exhaust_probability * 100.0
            ));
        }
        if parts.is_empty() {
            "off".to_string()
        } else {
            parts.join(",")
        }
    }

    /// Creates a [`ChaosRng`] from this configuration.
    #[must_use]
    pub fn rng(&self) -> ChaosRng {
        ChaosRng::from_config(self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chaos RNG
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic RNG for chaos injection decisions.
///
/// Uses the existing [`DetRng`] internally but provides chaos-specific methods.
#[derive(Debug, Clone)]
pub struct ChaosRng {
    inner: DetRng,
}

impl ChaosRng {
    /// Creates a new ChaosRng with the given seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            inner: DetRng::new(seed),
        }
    }

    /// Creates a ChaosRng from a [`ChaosConfig`].
    #[must_use]
    pub fn from_config(config: &ChaosConfig) -> Self {
        Self::new(config.seed)
    }

    /// Returns a random f64 in \[0.0, 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn next_f64(&mut self) -> f64 {
        // Convert u64 to f64 in [0.0, 1.0)
        // We use the upper 53 bits for best precision
        let bits = self.inner.next_u64() >> 11;
        bits as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Returns true with the given probability.
    #[must_use]
    pub fn should_inject(&mut self, probability: f64) -> bool {
        if probability <= 0.0 {
            return false;
        }
        if probability >= 1.0 {
            return true;
        }
        self.next_f64() < probability
    }

    /// Checks if cancellation should be injected based on config.
    #[must_use]
    pub fn should_inject_cancel(&mut self, config: &ChaosConfig) -> bool {
        self.should_inject(config.cancel_probability)
    }

    /// Checks if delay should be injected based on config.
    #[must_use]
    pub fn should_inject_delay(&mut self, config: &ChaosConfig) -> bool {
        self.should_inject(config.delay_probability)
    }

    /// Generates a random delay duration from the config's delay range.
    #[must_use]
    pub fn next_delay(&mut self, config: &ChaosConfig) -> Duration {
        let range = &config.delay_range;
        if range.is_empty() {
            return Duration::ZERO;
        }
        let start_nanos = range.start.as_nanos() as u64;
        let end_nanos = range.end.as_nanos() as u64;
        if end_nanos <= start_nanos {
            return range.start;
        }
        let delta = end_nanos - start_nanos;
        let offset = self.inner.next_u64() % delta;
        Duration::from_nanos(start_nanos + offset)
    }

    /// Checks if I/O error should be injected based on config.
    #[must_use]
    pub fn should_inject_io_error(&mut self, config: &ChaosConfig) -> bool {
        self.should_inject(config.io_error_probability)
    }

    /// Generates a random I/O error kind from the config's error kinds.
    ///
    /// Returns `None` if no error kinds are configured.
    #[must_use]
    pub fn next_io_error_kind(&mut self, config: &ChaosConfig) -> Option<io::ErrorKind> {
        if config.io_error_kinds.is_empty() {
            return None;
        }
        let idx = self.inner.next_usize(config.io_error_kinds.len());
        Some(config.io_error_kinds[idx])
    }

    /// Generates a random I/O error based on config.
    ///
    /// Returns `None` if no error kinds are configured.
    #[must_use]
    pub fn next_io_error(&mut self, config: &ChaosConfig) -> Option<io::Error> {
        self.next_io_error_kind(config)
            .map(|kind| io::Error::new(kind, "chaos-injected I/O error"))
    }

    /// Checks if wakeup storm should be triggered based on config.
    #[must_use]
    pub fn should_inject_wakeup_storm(&mut self, config: &ChaosConfig) -> bool {
        self.should_inject(config.wakeup_storm_probability)
    }

    /// Generates a random wakeup count from the config's storm range.
    #[must_use]
    pub fn next_wakeup_count(&mut self, config: &ChaosConfig) -> usize {
        let range = &config.wakeup_storm_count;
        if range.is_empty() {
            return 0;
        }
        if range.end <= range.start {
            return range.start;
        }
        let delta = range.end - range.start;
        range.start + self.inner.next_usize(delta)
    }

    /// Checks if budget exhaustion should be injected based on config.
    #[must_use]
    pub fn should_inject_budget_exhaust(&mut self, config: &ChaosConfig) -> bool {
        self.should_inject(config.budget_exhaust_probability)
    }

    /// Advances the internal RNG state, useful for synchronization.
    pub fn skip(&mut self, count: usize) {
        for _ in 0..count {
            let _ = self.inner.next_u64();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Injection Points (for documentation and future integration)
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies where chaos can be injected in the runtime.
///
/// This enum documents the injection points; actual injection is performed
/// by the respective components (Scheduler, Reactor, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionPoint {
    /// Before polling a task in the scheduler.
    SchedulerPoll,

    /// Before executing a task poll.
    TaskPoll,

    /// In the I/O reactor's poll operation.
    ReactorPoll,

    /// When a waker is invoked.
    WakerInvoke,

    /// When checking budget constraints.
    BudgetCheck,

    /// When a timer fires.
    TimerFire,

    /// Before acquiring a lock/semaphore.
    SyncAcquire,

    /// Before sending on a channel.
    ChannelSend,

    /// Before receiving on a channel.
    ChannelRecv,
}

impl InjectionPoint {
    /// Returns which chaos types are applicable at this injection point.
    #[must_use]
    pub fn applicable_chaos(&self) -> &'static [ChaosType] {
        use ChaosType::*;
        match self {
            InjectionPoint::SchedulerPoll => &[Cancel, Delay],
            InjectionPoint::TaskPoll => &[Cancel, Delay, BudgetExhaust],
            InjectionPoint::ReactorPoll => &[IoError, Delay],
            InjectionPoint::WakerInvoke => &[WakeupStorm, Delay],
            InjectionPoint::BudgetCheck => &[BudgetExhaust],
            InjectionPoint::TimerFire => &[Delay],
            InjectionPoint::SyncAcquire => &[Cancel, Delay],
            InjectionPoint::ChannelSend => &[Cancel, Delay],
            InjectionPoint::ChannelRecv => &[Cancel, Delay],
        }
    }
}

/// Types of chaos that can be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChaosType {
    /// Cancellation injection.
    Cancel,
    /// Delay injection.
    Delay,
    /// I/O error injection.
    IoError,
    /// Spurious wakeup storm.
    WakeupStorm,
    /// Budget exhaustion.
    BudgetExhaust,
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about chaos injection.
#[derive(Debug, Clone, Default)]
pub struct ChaosStats {
    /// Number of cancellations injected.
    pub cancellations: u64,
    /// Number of delays injected.
    pub delays: u64,
    /// Total delay time injected.
    pub total_delay: Duration,
    /// Number of I/O errors injected.
    pub io_errors: u64,
    /// Number of wakeup storms triggered.
    pub wakeup_storms: u64,
    /// Total spurious wakeups generated.
    pub spurious_wakeups: u64,
    /// Number of budget exhaustions injected.
    pub budget_exhaustions: u64,
    /// Total injection decision points encountered.
    pub decision_points: u64,
}

impl ChaosStats {
    /// Creates a new empty stats tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancellations: 0,
            delays: 0,
            total_delay: Duration::ZERO,
            io_errors: 0,
            wakeup_storms: 0,
            spurious_wakeups: 0,
            budget_exhaustions: 0,
            decision_points: 0,
        }
    }

    /// Records a cancellation injection.
    pub fn record_cancel(&mut self) {
        self.cancellations += 1;
        self.decision_points += 1;
    }

    /// Records a delay injection.
    pub fn record_delay(&mut self, delay: Duration) {
        self.delays += 1;
        self.total_delay += delay;
        self.decision_points += 1;
    }

    /// Records an I/O error injection.
    pub fn record_io_error(&mut self) {
        self.io_errors += 1;
        self.decision_points += 1;
    }

    /// Records a wakeup storm.
    pub fn record_wakeup_storm(&mut self, count: u64) {
        self.wakeup_storms += 1;
        self.spurious_wakeups += count;
        self.decision_points += 1;
    }

    /// Records a budget exhaustion.
    pub fn record_budget_exhaust(&mut self) {
        self.budget_exhaustions += 1;
        self.decision_points += 1;
    }

    /// Records a decision point where no chaos was injected.
    pub fn record_no_injection(&mut self) {
        self.decision_points += 1;
    }

    /// Merges another stats instance into this one.
    pub fn merge(&mut self, other: &ChaosStats) {
        self.cancellations += other.cancellations;
        self.delays += other.delays;
        self.total_delay += other.total_delay;
        self.io_errors += other.io_errors;
        self.wakeup_storms += other.wakeup_storms;
        self.spurious_wakeups += other.spurious_wakeups;
        self.budget_exhaustions += other.budget_exhaustions;
        self.decision_points += other.decision_points;
    }

    /// Returns the injection rate (injections / decision points).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn injection_rate(&self) -> f64 {
        if self.decision_points == 0 {
            return 0.0;
        }
        let injections = self.cancellations
            + self.delays
            + self.io_errors
            + self.wakeup_storms
            + self.budget_exhaustions;
        injections as f64 / self.decision_points as f64
    }
}

impl std::fmt::Display for ChaosStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChaosStats {{ decisions: {}, cancels: {}, delays: {} ({:?}), io_errors: {}, \
             wakeup_storms: {} ({} wakeups), budget_exhausts: {}, rate: {:.2}% }}",
            self.decision_points,
            self.cancellations,
            self.delays,
            self.total_delay,
            self.io_errors,
            self.wakeup_storms,
            self.spurious_wakeups,
            self.budget_exhaustions,
            self.injection_rate() * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_off_has_no_chaos() {
        let config = ChaosConfig::off();
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");
    }

    #[test]
    fn config_light_has_chaos() {
        let config = ChaosConfig::light();
        assert!(config.is_enabled());
        assert!(config.cancel_probability > 0.0);
        assert!(config.delay_probability > 0.0);
    }

    #[test]
    fn config_heavy_has_higher_probabilities() {
        let light = ChaosConfig::light();
        let heavy = ChaosConfig::heavy();
        assert!(heavy.cancel_probability > light.cancel_probability);
        assert!(heavy.delay_probability > light.delay_probability);
        assert!(heavy.io_error_probability > light.io_error_probability);
    }

    #[test]
    fn config_builder_pattern() {
        let config = ChaosConfig::new(42)
            .with_cancel_probability(0.1)
            .with_delay_probability(0.2)
            .with_delay_range(Duration::from_millis(5)..Duration::from_millis(50))
            .with_io_error_probability(0.05)
            .with_io_error_kinds(vec![io::ErrorKind::ConnectionReset])
            .with_wakeup_storm_probability(0.01)
            .with_wakeup_storm_count(1..10)
            .with_budget_exhaust_probability(0.02);

        assert_eq!(config.seed, 42);
        assert!((config.cancel_probability - 0.1).abs() < f64::EPSILON);
        assert!((config.delay_probability - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.delay_range.start, Duration::from_millis(5));
        assert_eq!(config.delay_range.end, Duration::from_millis(50));
        assert!((config.io_error_probability - 0.05).abs() < f64::EPSILON);
        assert_eq!(config.io_error_kinds.len(), 1);
        assert!((config.wakeup_storm_probability - 0.01).abs() < f64::EPSILON);
        assert_eq!(config.wakeup_storm_count, 1..10);
        assert!((config.budget_exhaust_probability - 0.02).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_probability() {
        let _ = ChaosConfig::new(42).with_cancel_probability(1.5);
    }

    #[test]
    fn config_summary() {
        let config = ChaosConfig::new(42)
            .with_cancel_probability(0.1)
            .with_io_error_probability(0.05);
        let summary = config.summary();
        assert!(summary.contains("cancel:10.0%"));
        assert!(summary.contains("io_err:5.0%"));
    }

    #[test]
    fn rng_deterministic() {
        let config = ChaosConfig::new(42).with_cancel_probability(0.5);

        let mut rng1 = ChaosRng::from_config(&config);
        let mut rng2 = ChaosRng::from_config(&config);

        // Same seed produces same sequence
        for _ in 0..100 {
            assert_eq!(
                rng1.should_inject_cancel(&config),
                rng2.should_inject_cancel(&config)
            );
        }
    }

    #[test]
    fn rng_f64_range() {
        let mut rng = ChaosRng::new(42);
        for _ in 0..1000 {
            let val = rng.next_f64();
            assert!((0.0..1.0).contains(&val), "f64 out of range: {val}");
        }
    }

    #[test]
    fn rng_should_inject_bounds() {
        let mut rng = ChaosRng::new(42);

        // 0% probability never injects
        for _ in 0..100 {
            assert!(!rng.should_inject(0.0));
        }

        // 100% probability always injects
        for _ in 0..100 {
            assert!(rng.should_inject(1.0));
        }
    }

    #[test]
    fn rng_delay_generation() {
        let config = ChaosConfig::new(42)
            .with_delay_range(Duration::from_millis(10)..Duration::from_millis(100));

        let mut rng = config.rng();
        for _ in 0..100 {
            let delay = rng.next_delay(&config);
            assert!(delay >= Duration::from_millis(10));
            assert!(delay < Duration::from_millis(100));
        }
    }

    #[test]
    fn rng_io_error_kind() {
        let config = ChaosConfig::new(42)
            .with_io_error_kinds(vec![io::ErrorKind::ConnectionReset, io::ErrorKind::TimedOut]);

        let mut rng = config.rng();
        for _ in 0..100 {
            let kind = rng.next_io_error_kind(&config).unwrap();
            assert!(
                kind == io::ErrorKind::ConnectionReset || kind == io::ErrorKind::TimedOut,
                "Unexpected error kind: {kind:?}"
            );
        }
    }

    #[test]
    fn rng_wakeup_count() {
        let config = ChaosConfig::new(42).with_wakeup_storm_count(5..15);

        let mut rng = config.rng();
        for _ in 0..100 {
            let count = rng.next_wakeup_count(&config);
            assert!((5..15).contains(&count), "Count out of range: {count}");
        }
    }

    #[test]
    fn injection_point_applicable_chaos() {
        // TaskPoll can inject Cancel, Delay, and BudgetExhaust
        let applicable = InjectionPoint::TaskPoll.applicable_chaos();
        assert!(applicable.contains(&ChaosType::Cancel));
        assert!(applicable.contains(&ChaosType::Delay));
        assert!(applicable.contains(&ChaosType::BudgetExhaust));
        assert!(!applicable.contains(&ChaosType::IoError));

        // ReactorPoll can inject IoError and Delay
        let applicable = InjectionPoint::ReactorPoll.applicable_chaos();
        assert!(applicable.contains(&ChaosType::IoError));
        assert!(applicable.contains(&ChaosType::Delay));
        assert!(!applicable.contains(&ChaosType::Cancel));
    }

    #[test]
    fn stats_tracking() {
        let mut stats = ChaosStats::new();
        stats.record_cancel();
        stats.record_delay(Duration::from_millis(10));
        stats.record_io_error();
        stats.record_wakeup_storm(5);
        stats.record_budget_exhaust();
        stats.record_no_injection();
        stats.record_no_injection();

        assert_eq!(stats.cancellations, 1);
        assert_eq!(stats.delays, 1);
        assert_eq!(stats.total_delay, Duration::from_millis(10));
        assert_eq!(stats.io_errors, 1);
        assert_eq!(stats.wakeup_storms, 1);
        assert_eq!(stats.spurious_wakeups, 5);
        assert_eq!(stats.budget_exhaustions, 1);
        assert_eq!(stats.decision_points, 7);

        // 5 injections out of 7 decision points
        let rate = stats.injection_rate();
        assert!((rate - 5.0 / 7.0).abs() < 0.001);
    }

    #[test]
    fn stats_merge() {
        let mut stats1 = ChaosStats::new();
        stats1.record_cancel();
        stats1.record_cancel();

        let mut stats2 = ChaosStats::new();
        stats2.record_io_error();
        stats2.record_delay(Duration::from_millis(5));

        stats1.merge(&stats2);

        assert_eq!(stats1.cancellations, 2);
        assert_eq!(stats1.io_errors, 1);
        assert_eq!(stats1.delays, 1);
        assert_eq!(stats1.decision_points, 4);
    }

    #[test]
    fn stats_display() {
        let mut stats = ChaosStats::new();
        stats.record_cancel();
        stats.record_delay(Duration::from_millis(10));

        let display = format!("{stats}");
        assert!(display.contains("cancels: 1"));
        assert!(display.contains("delays: 1"));
    }
}
