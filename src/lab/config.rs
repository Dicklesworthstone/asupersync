//! Configuration for the lab runtime.
//!
//! The lab configuration controls deterministic execution:
//! - Random seed for scheduling decisions
//! - Entropy seed for capability-based randomness
//! - Whether to panic on obligation leaks
//! - Trace buffer size
//! - Futurelock detection settings
//! - Chaos injection settings
//!
//! # Basic Usage
//!
//! ```
//! use asupersync::lab::{LabConfig, LabRuntime};
//!
//! // Default configuration (seed=42)
//! let config = LabConfig::default();
//!
//! // Explicit seed for reproducibility
//! let config = LabConfig::new(12345);
//!
//! // Wall-clock-derived seed (NON-REPLAYABLE — see deprecation note
//! // on LabConfig::from_time). Prefer LabConfig::new(seed) for
//! // replay-stable scenarios; from_time is retained as
//! // [`from_time_unstable`] only for genuinely-throwaway local
//! // experimentation.
//! ```
//!
//! # Chaos Testing
//!
//! Enable chaos injection to stress-test error handling paths:
//!
//! ```
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
//!
//! # Builder Style
//!
//! `LabConfig` uses a fluent, move-based builder style. Each method consumes
//! `self` and returns an updated configuration so you can chain options safely.
//!
//! # Configuration Examples
//!
//! ## Deterministic Multi-Worker Simulation
//!
//! ```
//! use asupersync::lab::{LabConfig, LabRuntime};
//!
//! let config = LabConfig::new(7)
//!     .worker_count(4)
//!     .trace_capacity(16_384);
//! let mut lab = LabRuntime::new(config);
//! lab.run_until_quiescent();
//! ```
//!
//! ## Replay Capture for Debugging
//!
//! ```
//! use asupersync::lab::{LabConfig, LabRuntime};
//!
//! let config = LabConfig::new(42).with_default_replay_recording();
//! let mut lab = LabRuntime::new(config);
//! lab.run_until_quiescent();
//! ```
//!
//! ## Entropy Decoupling
//!
//! ```
//! use asupersync::lab::LabConfig;
//!
//! // Keep scheduling deterministic but vary entropy-derived behavior.
//! let config = LabConfig::new(42).entropy_seed(7);
//! ```
//!
//! # Migration Guide (Struct Updates → Builder Style)
//!
//! ```
//! use asupersync::lab::LabConfig;
//!
//! // Old style: struct update
//! let config = LabConfig {
//!     seed: 42,
//!     worker_count: 4,
//!     ..LabConfig::new(42)
//! };
//!
//! // New style: builder methods
//! let config = LabConfig::new(42).worker_count(4);
//! ```

use crate::lab::chaos::ChaosConfig;
use crate::lab::oracle::{ORACLE_ALL, OracleRegistry, OracleRegistryError};
use crate::trace::RecorderConfig;
use crate::util::DetRng;

/// Configuration for the lab runtime.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
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
    /// When true, `LabRuntime::run_until_quiescent` (and so
    /// `run_async_under_lab` and async `#[lab_test]` bodies) jumps virtual
    /// time to the next timer or lab-reactor deadline whenever nothing can run
    /// before it. `LabRuntime::run_with_auto_advance` does so whether or not
    /// this is set.
    ///
    /// This enables "instant timeout testing" — a 24-hour wall-clock scenario
    /// completes in <1 second of real time because sleep/timeout deadlines
    /// are jumped to instantly rather than waited for.
    pub auto_advance_time: bool,
    /// Whether to enable real-time cancellation protocol oracle verification.
    ///
    /// When enabled, the runtime will continuously verify that the cancellation
    /// protocol is followed correctly during execution.
    pub enable_cancellation_oracle: bool,
    /// Whether to panic when cancellation protocol violations are detected.
    ///
    /// When false, violations are logged as warnings instead of panicking.
    pub panic_on_cancellation_violation: bool,
    /// Oracle names selected for report filtering and scenario-style lab runs.
    ///
    /// Empty means [`ORACLE_ALL`], preserving the historical "check every
    /// suite-reported oracle" default.
    pub oracle_selection: Vec<String>,
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
            auto_advance_time: false,
            enable_cancellation_oracle: true,
            panic_on_cancellation_violation: true,
            oracle_selection: Vec::new(),
        }
    }

    /// Creates a lab configuration from the current wall clock.
    ///
    /// br-asupersync-eij5e4: this constructor derives the PRNG seed
    /// from `SystemTime::now()` and is therefore **NOT replay-
    /// deterministic** — every call produces a different seed, every
    /// LabRuntime built from it produces a different schedule, and
    /// any test that asserts a deterministic outcome (oracle
    /// violations, trace fingerprints, certificate hashes) will be
    /// flaky in CI. The asupersync core invariant 'lab replay is
    /// byte-identical given the same seed' is silently violated.
    ///
    /// Prefer [`LabConfig::new`] with an explicit `seed` for
    /// every scenario where replay determinism matters (which is
    /// almost every CI test, every snapshot test, every crashpack
    /// reproduction). The constructor is retained ONLY for
    /// genuinely-throwaway local experimentation where the user is
    /// holding the seed in their head; the
    /// [`from_time_unstable`](Self::from_time_unstable) alias makes
    /// the non-replayability impossible to overlook at the call site.
    #[deprecated(
        since = "0.0.0",
        note = "from_time is non-replayable — use LabConfig::new(seed) with an \
                explicit seed for any test or production caller; if a wall-clock \
                seed is genuinely required, call from_time_unstable() so the \
                non-replayability is visible at the call site"
    )]
    #[must_use]
    pub fn from_time() -> Self {
        Self::from_time_unstable()
    }

    /// br-asupersync-eij5e4: wall-clock-derived LabConfig with a
    /// deliberately conspicuous name. Use this only when the test or
    /// experiment genuinely cannot be replayed (e.g., a one-off
    /// soak run), and prefer [`LabConfig::new`] with an explicit `seed`
    /// anywhere determinism matters.
    ///
    /// The `_unstable` suffix follows the asupersync convention for
    /// APIs whose behaviour is intentionally non-deterministic, so
    /// `grep -r from_time_unstable` enumerates every call site that
    /// has knowingly opted into wall-clock seeding.
    #[must_use]
    pub fn from_time_unstable() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(42, |d| d.as_nanos().min(u128::from(u64::MAX)) as u64);
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
    /// The chaos seed is honored as follows:
    /// - If the caller set an explicit, non-zero seed on the [`ChaosConfig`]
    ///   (e.g. via [`ChaosConfig::new`] or [`ChaosConfig::with_seed`], such as
    ///   from a `CHAOS_SEED` reproduction), that seed is used verbatim so the
    ///   run is byte-for-byte reproducible from the chaos seed alone.
    /// - Otherwise (the preset path — [`ChaosConfig::light`]/[`ChaosConfig::heavy`]
    ///   carry seed `0`), the chaos seed is derived deterministically from the
    ///   runtime seed so chaos is still reproducible from `LabConfig::new(seed)`.
    #[must_use]
    pub fn with_chaos(mut self, config: ChaosConfig) -> Self {
        // Honor an explicitly-set chaos seed (seed 0 is the preset "unset"
        // sentinel); only fall back to deriving from the main seed for presets.
        let chaos_seed = if config.seed == 0 {
            self.seed.wrapping_add(0xCAFE_BABE)
        } else {
            config.seed
        };
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

    /// Enables automatic time advancement when all tasks are idle.
    ///
    /// When enabled, `run_until_quiescent()` jumps virtual time to the next
    /// timer deadline whenever nothing can run before it, enabling instant
    /// timeout testing. `run_with_auto_advance()` always does.
    #[must_use]
    pub const fn with_auto_advance(mut self) -> Self {
        self.auto_advance_time = true;
        self
    }

    /// Returns true if replay recording is enabled.
    #[must_use]
    pub fn has_replay_recording(&self) -> bool {
        self.replay_recording.as_ref().is_some_and(|c| c.enabled)
    }

    /// Enables or disables real-time cancellation protocol oracle verification.
    #[must_use]
    pub const fn with_cancellation_oracle(mut self, enable: bool) -> Self {
        self.enable_cancellation_oracle = enable;
        self
    }

    /// Sets whether to panic on cancellation protocol violations.
    ///
    /// When false, violations are logged as warnings instead of panicking.
    #[must_use]
    pub const fn panic_on_cancellation_violation(mut self, value: bool) -> Self {
        self.panic_on_cancellation_violation = value;
        self
    }

    /// Enables cancellation oracle in warning mode (logs violations but doesn't panic).
    #[must_use]
    pub const fn with_cancellation_oracle_warnings(mut self) -> Self {
        self.enable_cancellation_oracle = true;
        self.panic_on_cancellation_violation = false;
        self
    }

    /// Returns true if real-time cancellation protocol oracle verification is enabled.
    #[must_use]
    pub const fn has_cancellation_oracle(&self) -> bool {
        self.enable_cancellation_oracle
    }

    /// Selects reportable lab oracles by registry name.
    ///
    /// Passing an empty slice or [`ORACLE_ALL`] selects every
    /// `OracleSuite::report` entry. Unknown names fail closed and return the
    /// registry error with a valid-name list and suggestion.
    pub fn with_oracles(mut self, names: &[&str]) -> Result<Self, OracleRegistryError> {
        let selected = OracleRegistry::select_reported_strs(names)?;
        if names.is_empty() || names.contains(&ORACLE_ALL) {
            self.oracle_selection.clear();
        } else {
            self.oracle_selection = selected.into_iter().map(str::to_owned).collect();
        }
        Ok(self)
    }

    /// Resolves the configured oracle selection to reportable registry names.
    pub fn selected_oracles(&self) -> Result<Vec<&'static str>, OracleRegistryError> {
        OracleRegistry::select_reported(&self.oracle_selection)
    }

    /// Creates a deterministic RNG from this configuration.
    ///
    /// # Determinism and Seed Stability
    ///
    /// Seeds [`DetRng::new`] with `self.seed` directly, without additional scrambling.
    /// This preserves schedule stability, trace certificates, and golden
    /// hashes established across test suites and lab replays (br-asupersync-dw3yqs).
    /// For chaos injection where unbiased first draws across small seeds (0..255)
    /// are required, [`crate::lab::chaos::ChaosRng`] applies a SplitMix64 scrambler.
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
#[path = "config_inline_tests.rs"]
mod tests;
