//! Configuration for the lab runtime.
//!
//! The lab configuration controls deterministic execution:
//! - Random seed for scheduling decisions
//! - Whether to panic on obligation leaks
//! - Trace buffer size
//! - Futurelock detection settings
//! - Chaos injection settings
//!
//! # Basic Usage
//!
//! ```ignore
//! use asupersync::lab::{LabConfig, LabRuntime};
//!
//! // Default configuration (seed=42)
//! let config = LabConfig::default();
//!
//! // Explicit seed for reproducibility
//! let config = LabConfig::new(12345);
//!
//! // Time-based seed for variety (useful in CI)
//! let config = LabConfig::from_time();
//! ```
//!
//! # Chaos Testing
//!
//! Enable chaos injection to stress-test error handling paths:
//!
//! ```ignore
//! use asupersync::lab::{LabConfig, LabRuntime};
//! use asupersync::lab::chaos::ChaosConfig;
//!
//! // Quick: use presets
//! let config = LabConfig::new(42).with_light_chaos();  // CI-friendly
//! let config = LabConfig::new(42).with_heavy_chaos();  // Thorough
//!
//! // Custom: fine-grained control
//! let chaos = ChaosConfig::new(42)
//!     .with_delay_probability(0.3)
//!     .with_cancel_probability(0.05);
//! let config = LabConfig::new(42).with_chaos(chaos);
//!
//! // Check if chaos is enabled
//! assert!(config.has_chaos());
//! ```
//!
//! # Futurelock Detection
//!
//! Detect tasks that hold obligations but stop being polled:
//!
//! ```ignore
//! let config = LabConfig::new(42)
//!     .futurelock_max_idle_steps(5000)  // Trigger after 5000 idle steps
//!     .panic_on_futurelock(true);       // Panic when detected
//! ```

use super::chaos::ChaosConfig;
use crate::trace::RecorderConfig;
use crate::util::DetRng;

/// Configuration for the lab runtime.
#[derive(Debug, Clone)]
pub struct LabConfig {
    /// Random seed for deterministic scheduling.
    pub seed: u64,
    /// Seed for deterministic entropy sources.
    ///
    /// By default this matches `seed`, but can be overridden to decouple
    /// scheduler decisions from entropy generation.
    pub entropy_seed: u64,
    /// Number of virtual workers to model in the lab scheduler.
    ///
    /// This does not spawn threads; it controls deterministic multi-worker simulation.
    /// Values less than 1 are clamped to 1.
    pub worker_count: usize,
    /// Whether to panic on obligation leaks.
    pub panic_on_obligation_leak: bool,
    /// Trace buffer capacity.
    pub trace_capacity: usize,
    /// Max lab steps a task may go unpolled while holding obligations.
    ///
    /// `0` disables the futurelock detector.
    pub futurelock_max_idle_steps: u64,
    /// Whether to panic when a futurelock is detected.
    pub panic_on_futurelock: bool,
    /// Maximum number of steps before forced termination.
    pub max_steps: Option<u64>,
    /// Chaos injection configuration.
    ///
    /// When enabled, the runtime will inject faults at various points
    /// to stress-test the system's resilience.
    pub chaos: Option<ChaosConfig>,
    /// Replay recording configuration.
    ///
    /// When enabled, the runtime will record all non-determinism sources
    /// for later replay.
    pub replay_recording: Option<RecorderConfig>,
}

impl LabConfig {
    /// Creates a new lab configuration with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            entropy_seed: seed,
            worker_count: 1,
            panic_on_obligation_leak: true,
            trace_capacity: 4096,
            futurelock_max_idle_steps: 10_000,
            panic_on_futurelock: true,
            max_steps: Some(100_000),
            chaos: None,
            replay_recording: None,
        }
    }

    /// Creates a lab configuration from the current time (for quick testing).
    #[must_use]
    pub fn from_time() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(42);
        Self::new(seed)
    }

    /// Sets whether to panic on obligation leaks.
    #[must_use]
    pub const fn panic_on_leak(mut self, value: bool) -> Self {
        self.panic_on_obligation_leak = value;
        self
    }

    /// Sets the trace buffer capacity.
    #[must_use]
    pub const fn trace_capacity(mut self, capacity: usize) -> Self {
        self.trace_capacity = capacity;
        self
    }

    /// Sets the number of virtual workers to model.
    ///
    /// Values less than 1 are clamped to 1.
    #[must_use]
    pub const fn worker_count(mut self, count: usize) -> Self {
        self.worker_count = if count == 0 { 1 } else { count };
        self
    }

    /// Sets the entropy seed used for capability-based randomness.
    #[must_use]
    pub const fn entropy_seed(mut self, seed: u64) -> Self {
        self.entropy_seed = seed;
        self
    }

    /// Sets the maximum idle steps before the futurelock detector triggers.
    #[must_use]
    pub const fn futurelock_max_idle_steps(mut self, steps: u64) -> Self {
        self.futurelock_max_idle_steps = steps;
        self
    }

    /// Sets whether to panic when a futurelock is detected.
    #[must_use]
    pub const fn panic_on_futurelock(mut self, value: bool) -> Self {
        self.panic_on_futurelock = value;
        self
    }

    /// Sets the maximum number of steps.
    #[must_use]
    pub const fn max_steps(mut self, steps: u64) -> Self {
        self.max_steps = Some(steps);
        self
    }

    /// Disables the step limit.
    #[must_use]
    pub const fn no_step_limit(mut self) -> Self {
        self.max_steps = None;
        self
    }

    /// Enables chaos injection with the given configuration.
    ///
    /// The chaos seed will be derived from the main seed for determinism.
    #[must_use]
    pub fn with_chaos(mut self, config: ChaosConfig) -> Self {
        // Derive chaos seed from main seed for determinism
        let chaos_seed = self.seed.wrapping_add(0xCAFE_BABE);
        self.chaos = Some(config.with_seed(chaos_seed));
        self
    }

    /// Enables light chaos (suitable for CI).
    #[must_use]
    pub fn with_light_chaos(self) -> Self {
        self.with_chaos(ChaosConfig::light())
    }

    /// Enables heavy chaos (thorough testing).
    #[must_use]
    pub fn with_heavy_chaos(self) -> Self {
        self.with_chaos(ChaosConfig::heavy())
    }

    /// Returns true if chaos injection is enabled.
    #[must_use]
    pub fn has_chaos(&self) -> bool {
        self.chaos.as_ref().is_some_and(ChaosConfig::is_enabled)
    }

    /// Enables replay recording with the given configuration.
    #[must_use]
    pub fn with_replay_recording(mut self, config: RecorderConfig) -> Self {
        self.replay_recording = Some(config);
        self
    }

    /// Enables replay recording with default configuration.
    #[must_use]
    pub fn with_default_replay_recording(self) -> Self {
        self.with_replay_recording(RecorderConfig::enabled())
    }

    /// Returns true if replay recording is enabled.
    #[must_use]
    pub fn has_replay_recording(&self) -> bool {
        self.replay_recording.as_ref().is_some_and(|c| c.enabled)
    }

    /// Creates a deterministic RNG from this configuration.
    #[must_use]
    pub fn rng(&self) -> DetRng {
        DetRng::new(self.seed)
    }
}

impl Default for LabConfig {
    fn default() -> Self {
        Self::new(42)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn default_config() {
        init_test("default_config");
        let config = LabConfig::default();
        let ok = config.seed == 42;
        crate::assert_with_log!(ok, "seed", 42, config.seed);
        crate::assert_with_log!(
            config.entropy_seed == 42,
            "entropy_seed",
            42,
            config.entropy_seed
        );
        crate::assert_with_log!(
            config.worker_count == 1,
            "worker_count",
            1,
            config.worker_count
        );
        crate::assert_with_log!(
            config.panic_on_obligation_leak,
            "panic_on_obligation_leak",
            true,
            config.panic_on_obligation_leak
        );
        crate::assert_with_log!(
            config.panic_on_futurelock,
            "panic_on_futurelock",
            true,
            config.panic_on_futurelock
        );
        crate::test_complete!("default_config");
    }

    #[test]
    fn rng_is_deterministic() {
        init_test("rng_is_deterministic");
        let config = LabConfig::new(12345);
        let mut rng1 = config.rng();
        let mut rng2 = config.rng();

        let a = rng1.next_u64();
        let b = rng2.next_u64();
        crate::assert_with_log!(a == b, "rng equal", b, a);
        crate::test_complete!("rng_is_deterministic");
    }

    #[test]
    fn worker_count_clamps_to_one() {
        init_test("worker_count_clamps_to_one");
        let config = LabConfig::new(7).worker_count(0);
        crate::assert_with_log!(
            config.worker_count == 1,
            "worker_count",
            1,
            config.worker_count
        );
        crate::test_complete!("worker_count_clamps_to_one");
    }
}
