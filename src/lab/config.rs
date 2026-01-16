//! Configuration for the lab runtime.
//!
//! The lab configuration controls deterministic execution:
//! - Random seed for scheduling decisions
//! - Whether to panic on obligation leaks
//! - Trace buffer size

use crate::util::DetRng;

/// Configuration for the lab runtime.
#[derive(Debug, Clone)]
pub struct LabConfig {
    /// Random seed for deterministic scheduling.
    pub seed: u64,
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
}

impl LabConfig {
    /// Creates a new lab configuration with the given seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            panic_on_obligation_leak: true,
            trace_capacity: 4096,
            futurelock_max_idle_steps: 10_000,
            panic_on_futurelock: true,
            max_steps: Some(100_000),
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

    #[test]
    fn default_config() {
        let config = LabConfig::default();
        assert_eq!(config.seed, 42);
        assert!(config.panic_on_obligation_leak);
        assert!(config.panic_on_futurelock);
    }

    #[test]
    fn rng_is_deterministic() {
        let config = LabConfig::new(12345);
        let mut rng1 = config.rng();
        let mut rng2 = config.rng();

        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}
