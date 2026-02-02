//! Supervision policies for actor failure handling.
//!
//! This module implements Erlang/OTP-style supervision semantics that are compatible
//! with asupersync's region ownership and cancellation model:
//!
//! - **Region-owned restarts**: Restarts happen within the same region scope
//! - **Budget-aware**: Restart loops consume budget and respect deadlines
//! - **Monotone escalation**: Cannot downgrade a worse outcome
//! - **Trace-visible**: All supervision decisions are logged for debugging
//!
//! # Supervision Strategies
//!
//! - [`SupervisionStrategy::Stop`]: Stop the actor on any error
//! - [`SupervisionStrategy::Restart`]: Restart on error with rate limiting
//! - [`SupervisionStrategy::Escalate`]: Propagate failure to parent region
//!
//! # Example
//!
//! ```ignore
//! use asupersync::supervision::{SupervisionStrategy, RestartConfig};
//! use std::time::Duration;
//!
//! // Stop on any error
//! let stop = SupervisionStrategy::Stop;
//!
//! // Restart up to 3 times in 60 seconds
//! let restart = SupervisionStrategy::Restart(RestartConfig {
//!     max_restarts: 3,
//!     window: Duration::from_secs(60),
//!     backoff: BackoffStrategy::Exponential {
//!         initial: Duration::from_millis(100),
//!         max: Duration::from_secs(10),
//!         multiplier: 2.0,
//!     },
//! });
//!
//! // Escalate to parent
//! let escalate = SupervisionStrategy::Escalate;
//! ```

use std::time::Duration;

use crate::types::{CancelReason, Outcome, RegionId, TaskId};

/// Supervision strategy for handling actor failures.
///
/// Strategies form a lattice compatible with the [`Outcome`] severity model:
/// - `Stop` is the default for unhandled failures
/// - `Restart` can recover from transient failures
/// - `Escalate` propagates failures up the region hierarchy
///
/// # Monotonicity
///
/// Supervision decisions are monotone: once an outcome is determined to be
/// severe (e.g., `Panicked`), it cannot be downgraded by supervision. A
/// restart that itself fails escalates the severity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SupervisionStrategy {
    /// Stop the actor immediately on any error.
    ///
    /// The actor's `on_stop` is called, and the failure is recorded.
    /// The region continues running other tasks.
    #[default]
    Stop,

    /// Restart the actor on error with configurable limits.
    ///
    /// Restarts are rate-limited by a sliding window. If the restart
    /// limit is exceeded, the strategy escalates to [`SupervisionStrategy::Stop`].
    Restart(RestartConfig),

    /// Escalate the failure to the parent region.
    ///
    /// The parent region's supervision policy handles the failure.
    /// If there is no parent (root region), this behaves like [`SupervisionStrategy::Stop`].
    Escalate,
}

/// Configuration for restart behavior.
///
/// Restarts are rate-limited using a sliding window: if more than
/// `max_restarts` occur within `window`, the restart budget is
/// exhausted and the actor stops permanently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartConfig {
    /// Maximum number of restarts allowed within the time window.
    ///
    /// Set to 0 to disable restarts (equivalent to `Stop`).
    pub max_restarts: u32,

    /// Time window for counting restarts.
    ///
    /// Restarts older than this window are forgotten.
    pub window: Duration,

    /// Backoff strategy between restart attempts.
    pub backoff: BackoffStrategy,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window: Duration::from_secs(60),
            backoff: BackoffStrategy::default(),
        }
    }
}

impl RestartConfig {
    /// Create a new restart config with the given limits.
    #[must_use]
    pub fn new(max_restarts: u32, window: Duration) -> Self {
        Self {
            max_restarts,
            window,
            backoff: BackoffStrategy::default(),
        }
    }

    /// Set the backoff strategy.
    #[must_use]
    pub fn with_backoff(mut self, backoff: BackoffStrategy) -> Self {
        self.backoff = backoff;
        self
    }
}

/// Backoff strategy for delays between restart attempts.
///
/// Backoff helps prevent thundering herd issues and gives transient
/// failures time to resolve.
#[derive(Debug, Clone, PartialEq)]
pub enum BackoffStrategy {
    /// No delay between restarts.
    None,

    /// Fixed delay between restarts.
    Fixed(Duration),

    /// Exponential backoff with jitter.
    Exponential {
        /// Initial delay for the first restart.
        initial: Duration,
        /// Maximum delay cap.
        max: Duration,
        /// Multiplier for each subsequent restart (typically 2.0).
        multiplier: f64,
    },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Exponential {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            multiplier: 2.0,
        }
    }
}

// Allow the lossy cast since precision loss in backoff is acceptable
impl Eq for BackoffStrategy {}

/// Restart policy for supervised children.
///
/// Determines how failures in one child affect other children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    /// Only the failed child is restarted.
    ///
    /// Other children are unaffected. Use when children are independent
    /// and don't share state.
    #[default]
    OneForOne,

    /// All children are restarted when one fails.
    ///
    /// Use when children have shared state dependencies that become
    /// inconsistent if one fails.
    OneForAll,

    /// The failed child and all children started after it are restarted.
    ///
    /// Use when children have ordered dependencies (later children depend
    /// on earlier ones).
    RestForOne,
}

/// Escalation policy when max_restarts is exceeded.
///
/// Determines what happens when the restart budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EscalationPolicy {
    /// Stop the failing actor permanently.
    ///
    /// The supervisor continues running other children.
    #[default]
    Stop,

    /// Propagate the failure to the parent supervisor.
    ///
    /// The parent's supervision policy handles the failure.
    Escalate,

    /// Reset the restart counter and try again.
    ///
    /// Use with caution - can lead to infinite restart loops.
    ResetCounter,
}

/// Full configuration for supervisor behavior.
///
/// Combines restart policy, rate limiting, backoff, and escalation.
#[derive(Debug, Clone, PartialEq)]
pub struct SupervisionConfig {
    /// Policy for how child failures affect other children.
    pub restart_policy: RestartPolicy,

    /// Maximum number of restarts allowed within the time window.
    pub max_restarts: u32,

    /// Time window for counting restarts.
    pub restart_window: Duration,

    /// Backoff strategy between restart attempts.
    pub backoff: BackoffStrategy,

    /// What to do when restart budget is exhausted.
    pub escalation: EscalationPolicy,
}

impl Default for SupervisionConfig {
    fn default() -> Self {
        Self {
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_secs(60),
            backoff: BackoffStrategy::default(),
            escalation: EscalationPolicy::Stop,
        }
    }
}

impl SupervisionConfig {
    /// Create a supervision config with the given limits.
    #[must_use]
    pub fn new(max_restarts: u32, restart_window: Duration) -> Self {
        Self {
            restart_policy: RestartPolicy::OneForOne,
            max_restarts,
            restart_window,
            backoff: BackoffStrategy::default(),
            escalation: EscalationPolicy::Stop,
        }
    }

    /// Set the restart policy.
    #[must_use]
    pub fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.restart_policy = policy;
        self
    }

    /// Set the backoff strategy.
    #[must_use]
    pub fn with_backoff(mut self, backoff: BackoffStrategy) -> Self {
        self.backoff = backoff;
        self
    }

    /// Set the escalation policy.
    #[must_use]
    pub fn with_escalation(mut self, escalation: EscalationPolicy) -> Self {
        self.escalation = escalation;
        self
    }

    /// Create a "one for all" supervision config.
    #[must_use]
    pub fn one_for_all(max_restarts: u32, restart_window: Duration) -> Self {
        Self::new(max_restarts, restart_window).with_restart_policy(RestartPolicy::OneForAll)
    }

    /// Create a "rest for one" supervision config.
    #[must_use]
    pub fn rest_for_one(max_restarts: u32, restart_window: Duration) -> Self {
        Self::new(max_restarts, restart_window).with_restart_policy(RestartPolicy::RestForOne)
    }
}

// Eq requires manual impl due to f64 in BackoffStrategy
impl Eq for SupervisionConfig {}

/// Specification for a supervised child actor.
///
/// Contains the child's configuration and optional custom supervision settings.
#[derive(Debug, Clone)]
pub struct ChildSpec {
    /// Unique name for the child (for logging and lookup).
    pub name: String,

    /// Supervision config for this specific child (overrides parent's default).
    pub config: Option<SupervisionConfig>,

    /// Whether the child should be started immediately.
    pub start_immediately: bool,

    /// Whether the child is required (supervisor fails if child can't start).
    pub required: bool,
}

impl Default for ChildSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            config: None,
            start_immediately: true,
            required: true,
        }
    }
}

impl ChildSpec {
    /// Create a new child spec with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Set a custom supervision config for this child.
    #[must_use]
    pub fn with_config(mut self, config: SupervisionConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set whether the child should start immediately.
    #[must_use]
    pub fn with_start_immediately(mut self, start: bool) -> Self {
        self.start_immediately = start;
        self
    }

    /// Set whether the child is required.
    #[must_use]
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

impl BackoffStrategy {
    /// Calculate the delay for a given restart attempt (0-indexed).
    ///
    /// Returns `None` if `BackoffStrategy::None` is used.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Option<Duration> {
        match self {
            Self::None => None,
            Self::Fixed(d) => Some(*d),
            Self::Exponential {
                initial,
                max,
                multiplier,
            } => {
                // Allow lossy cast - precision loss is acceptable for backoff timing
                #[allow(clippy::cast_precision_loss)]
                // Cap exponent to prevent overflow/infinity in powi
                let exp = i32::try_from(attempt).unwrap_or(30).min(30);
                let base = initial.as_secs_f64() * multiplier.powi(exp);
                let delay = Duration::from_secs_f64(base.min(max.as_secs_f64()));
                Some(delay)
            }
        }
    }
}

/// Tracks restart history for an actor.
///
/// This is used internally by the supervision runtime to enforce
/// restart limits within the configured window.
#[derive(Debug, Clone)]
pub struct RestartHistory {
    /// Timestamps of recent restarts (within window).
    restarts: Vec<u64>, // Virtual timestamps for determinism
    /// The configuration being tracked.
    config: RestartConfig,
}

impl RestartHistory {
    /// Create a new restart history with the given config.
    #[must_use]
    pub fn new(config: RestartConfig) -> Self {
        Self {
            restarts: Vec::new(),
            config,
        }
    }

    /// Check if a restart is allowed given the current virtual time.
    ///
    /// Returns `true` if the restart budget has not been exhausted.
    #[must_use]
    pub fn can_restart(&self, now: u64) -> bool {
        let window_nanos = self.config.window.as_nanos() as u64;
        let cutoff = now.saturating_sub(window_nanos);

        // Count restarts within the window
        let recent_count = self.restarts.iter().filter(|&&t| t >= cutoff).count();

        recent_count < self.config.max_restarts as usize
    }

    /// Record a restart at the given virtual time.
    ///
    /// Also prunes old entries outside the window.
    pub fn record_restart(&mut self, now: u64) {
        let window_nanos = self.config.window.as_nanos() as u64;
        let cutoff = now.saturating_sub(window_nanos);

        // Prune old entries
        self.restarts.retain(|&t| t >= cutoff);

        // Record new restart
        self.restarts.push(now);
    }

    /// Get the number of restarts within the current window.
    #[must_use]
    pub fn recent_restart_count(&self, now: u64) -> usize {
        let window_nanos = self.config.window.as_nanos() as u64;
        let cutoff = now.saturating_sub(window_nanos);
        self.restarts.iter().filter(|&&t| t >= cutoff).count()
    }

    /// Get the delay before the next restart attempt.
    #[must_use]
    pub fn next_delay(&self, now: u64) -> Option<Duration> {
        let attempt = self.recent_restart_count(now) as u32;
        self.config.backoff.delay_for_attempt(attempt)
    }

    /// Get the config.
    #[must_use]
    pub fn config(&self) -> &RestartConfig {
        &self.config
    }
}

/// Decision made by the supervision system.
///
/// This is emitted as a trace event for observability.
#[derive(Debug, Clone)]
pub enum SupervisionDecision {
    /// Actor will be restarted after the specified delay.
    Restart {
        /// The actor being restarted.
        task_id: TaskId,
        /// Region containing the actor.
        region_id: RegionId,
        /// Which restart attempt this is (1-indexed).
        attempt: u32,
        /// Delay before restart (if any).
        delay: Option<Duration>,
    },

    /// Actor will be stopped permanently.
    Stop {
        /// The actor being stopped.
        task_id: TaskId,
        /// Region containing the actor.
        region_id: RegionId,
        /// Reason for stopping.
        reason: StopReason,
    },

    /// Failure will be escalated to parent region.
    Escalate {
        /// The failing actor.
        task_id: TaskId,
        /// Region containing the actor.
        region_id: RegionId,
        /// Parent region to escalate to.
        parent_region_id: Option<RegionId>,
        /// The original failure outcome.
        outcome: Outcome<(), ()>,
    },
}

/// Reason for stopping an actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Stopped due to explicit strategy.
    ExplicitStop,
    /// Stopped because restart budget was exhausted.
    RestartBudgetExhausted {
        /// How many restarts occurred.
        total_restarts: u32,
        /// The window duration.
        window: Duration,
    },
    /// Stopped due to cancellation.
    Cancelled(CancelReason),
    /// Stopped due to panic.
    Panicked,
    /// Stopped because parent region is closing.
    RegionClosing,
}

/// Trace event for supervision system activity.
///
/// These events are recorded for debugging and observability.
#[derive(Debug, Clone)]
pub enum SupervisionEvent {
    /// An actor failure was detected.
    ActorFailed {
        /// The failing actor's task ID.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// The failure outcome.
        outcome: Outcome<(), ()>,
    },

    /// A supervision decision was made.
    DecisionMade {
        /// The actor affected by the decision.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// The supervision decision.
        decision: SupervisionDecision,
    },

    /// An actor restart is beginning.
    RestartBeginning {
        /// The actor being restarted.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// Which restart attempt this is.
        attempt: u32,
    },

    /// An actor restart completed successfully.
    RestartComplete {
        /// The restarted actor.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// Which restart attempt completed.
        attempt: u32,
    },

    /// An actor restart failed.
    RestartFailed {
        /// The actor that failed to restart.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// Which restart attempt failed.
        attempt: u32,
        /// The failure outcome.
        outcome: Outcome<(), ()>,
    },

    /// Restart budget was exhausted.
    BudgetExhausted {
        /// The actor whose budget was exhausted.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// Total restarts that occurred.
        total_restarts: u32,
        /// The time window for restart counting.
        window: Duration,
    },

    /// Failure is being escalated to parent.
    Escalating {
        /// The failing actor.
        task_id: TaskId,
        /// The region containing the actor.
        from_region: RegionId,
        /// The parent region to escalate to.
        to_region: Option<RegionId>,
    },
}

/// Supervisor for managing actor restarts.
///
/// Integrates with the supervision strategy to decide whether to
/// restart, stop, or escalate on failure.
#[derive(Debug)]
pub struct Supervisor {
    strategy: SupervisionStrategy,
    history: Option<RestartHistory>,
}

impl Supervisor {
    /// Create a new supervisor with the given strategy.
    #[must_use]
    pub fn new(strategy: SupervisionStrategy) -> Self {
        let history = match &strategy {
            SupervisionStrategy::Restart(config) => Some(RestartHistory::new(config.clone())),
            _ => None,
        };
        Self { strategy, history }
    }

    /// Get the supervision strategy.
    #[must_use]
    pub fn strategy(&self) -> &SupervisionStrategy {
        &self.strategy
    }

    /// Decide what to do when an actor fails.
    ///
    /// Returns the supervision decision and optionally records a restart.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The failing actor's task ID
    /// * `region_id` - The region containing the actor
    /// * `parent_region_id` - The parent region (for escalation)
    /// * `outcome` - The failure outcome
    /// * `now` - Current virtual time (nanoseconds)
    pub fn on_failure(
        &mut self,
        task_id: TaskId,
        region_id: RegionId,
        parent_region_id: Option<RegionId>,
        outcome: Outcome<(), ()>,
        now: u64,
    ) -> SupervisionDecision {
        // Check if outcome is severe enough that supervision cannot help
        if matches!(outcome, Outcome::Panicked(_)) {
            return SupervisionDecision::Stop {
                task_id,
                region_id,
                reason: StopReason::Panicked,
            };
        }

        match &mut self.strategy {
            SupervisionStrategy::Stop => SupervisionDecision::Stop {
                task_id,
                region_id,
                reason: StopReason::ExplicitStop,
            },

            SupervisionStrategy::Restart(config) => {
                let history = self.history.as_mut().expect("history exists for Restart");

                if history.can_restart(now) {
                    let attempt = history.recent_restart_count(now) as u32 + 1;
                    let delay = history.next_delay(now);
                    history.record_restart(now);

                    SupervisionDecision::Restart {
                        task_id,
                        region_id,
                        attempt,
                        delay,
                    }
                } else {
                    SupervisionDecision::Stop {
                        task_id,
                        region_id,
                        reason: StopReason::RestartBudgetExhausted {
                            total_restarts: config.max_restarts,
                            window: config.window,
                        },
                    }
                }
            }

            SupervisionStrategy::Escalate => SupervisionDecision::Escalate {
                task_id,
                region_id,
                parent_region_id,
                outcome,
            },
        }
    }

    /// Get the restart history (if using Restart strategy).
    #[must_use]
    pub fn history(&self) -> Option<&RestartHistory> {
        self.history.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PanicPayload;
    use crate::util::ArenaIndex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_task_id() -> TaskId {
        TaskId::from_arena(ArenaIndex::new(0, 1))
    }

    fn test_region_id() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn stop_strategy_always_stops() {
        init_test("stop_strategy_always_stops");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::ExplicitStop,
                ..
            }
        ));

        crate::test_complete!("stop_strategy_always_stops");
    }

    #[test]
    fn restart_strategy_allows_restarts() {
        init_test("restart_strategy_allows_restarts");

        let config = RestartConfig::new(3, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First failure should trigger restart
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second failure should also restart
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            1_000_000_000, // 1 second later
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 2, .. }
        ));

        crate::test_complete!("restart_strategy_allows_restarts");
    }

    #[test]
    fn restart_budget_exhaustion() {
        init_test("restart_budget_exhaustion");

        let config = RestartConfig::new(2, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            0,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            1_000_000_000,
        );

        // Third should stop
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            2_000_000_000,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("restart_budget_exhaustion");
    }

    #[test]
    fn restart_window_resets() {
        init_test("restart_window_resets");

        let config = RestartConfig::new(2, Duration::from_secs(1)); // 1 second window
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts within window
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            0,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            500_000_000, // 0.5 seconds
        );

        // Third failure after window should succeed (old ones expired)
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Cancelled(CancelReason::user("test")),
            2_000_000_000, // 2 seconds later - both old restarts outside window
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        crate::test_complete!("restart_window_resets");
    }

    #[test]
    fn escalate_strategy_escalates() {
        init_test("escalate_strategy_escalates");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Escalate {
                parent_region_id: Some(_),
                ..
            }
        ));

        crate::test_complete!("escalate_strategy_escalates");
    }

    #[test]
    fn panics_always_stop() {
        init_test("panics_always_stop");

        // Even with Restart strategy, panics should stop
        let config = RestartConfig::new(10, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            Outcome::Panicked(PanicPayload::new("test panic")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Panicked,
                ..
            }
        ));

        crate::test_complete!("panics_always_stop");
    }

    #[test]
    fn exponential_backoff() {
        init_test("exponential_backoff");

        let backoff = BackoffStrategy::Exponential {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            multiplier: 2.0,
        };

        // Attempt 0: 100ms
        let d0 = backoff.delay_for_attempt(0).unwrap();
        assert_eq!(d0.as_millis(), 100);

        // Attempt 1: 200ms
        let d1 = backoff.delay_for_attempt(1).unwrap();
        assert_eq!(d1.as_millis(), 200);

        // Attempt 2: 400ms
        let d2 = backoff.delay_for_attempt(2).unwrap();
        assert_eq!(d2.as_millis(), 400);

        // Attempt 10: should be capped at 10s
        let d10 = backoff.delay_for_attempt(10).unwrap();
        assert_eq!(d10.as_secs(), 10);

        crate::test_complete!("exponential_backoff");
    }

    #[test]
    fn fixed_backoff() {
        init_test("fixed_backoff");

        let backoff = BackoffStrategy::Fixed(Duration::from_millis(500));

        for attempt in 0..5 {
            let delay = backoff.delay_for_attempt(attempt).unwrap();
            assert_eq!(delay.as_millis(), 500);
        }

        crate::test_complete!("fixed_backoff");
    }

    #[test]
    fn no_backoff() {
        init_test("no_backoff");

        let backoff = BackoffStrategy::None;

        for attempt in 0..5 {
            assert!(backoff.delay_for_attempt(attempt).is_none());
        }

        crate::test_complete!("no_backoff");
    }

    #[test]
    fn restart_history_tracking() {
        init_test("restart_history_tracking");

        let config = RestartConfig::new(3, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // Initially can restart
        assert!(history.can_restart(0));
        assert_eq!(history.recent_restart_count(0), 0);

        // Record some restarts
        history.record_restart(1_000_000_000); // 1s
        history.record_restart(2_000_000_000); // 2s
        history.record_restart(3_000_000_000); // 3s

        // Now at budget
        assert_eq!(history.recent_restart_count(3_000_000_000), 3);
        assert!(!history.can_restart(3_000_000_000));

        // After window passes, old restarts expire
        assert_eq!(history.recent_restart_count(15_000_000_000), 0);
        assert!(history.can_restart(15_000_000_000));

        crate::test_complete!("restart_history_tracking");
    }

    // ---- Tests for new RestartPolicy, EscalationPolicy, SupervisionConfig ----

    #[test]
    fn restart_policy_defaults_to_one_for_one() {
        init_test("restart_policy_defaults_to_one_for_one");

        let policy = RestartPolicy::default();
        assert_eq!(policy, RestartPolicy::OneForOne);

        crate::test_complete!("restart_policy_defaults_to_one_for_one");
    }

    #[test]
    fn escalation_policy_defaults_to_stop() {
        init_test("escalation_policy_defaults_to_stop");

        let policy = EscalationPolicy::default();
        assert_eq!(policy, EscalationPolicy::Stop);

        crate::test_complete!("escalation_policy_defaults_to_stop");
    }

    #[test]
    fn supervision_config_defaults() {
        init_test("supervision_config_defaults");

        let config = SupervisionConfig::default();

        assert_eq!(config.restart_policy, RestartPolicy::OneForOne);
        assert_eq!(config.max_restarts, 3);
        assert_eq!(config.restart_window, Duration::from_secs(60));
        assert_eq!(config.escalation, EscalationPolicy::Stop);

        crate::test_complete!("supervision_config_defaults");
    }

    #[test]
    fn supervision_config_builder() {
        init_test("supervision_config_builder");

        let config = SupervisionConfig::new(5, Duration::from_secs(30))
            .with_restart_policy(RestartPolicy::OneForAll)
            .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100)))
            .with_escalation(EscalationPolicy::Escalate);

        assert_eq!(config.restart_policy, RestartPolicy::OneForAll);
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_secs(30));
        assert_eq!(
            config.backoff,
            BackoffStrategy::Fixed(Duration::from_millis(100))
        );
        assert_eq!(config.escalation, EscalationPolicy::Escalate);

        crate::test_complete!("supervision_config_builder");
    }

    #[test]
    fn supervision_config_one_for_all_helper() {
        init_test("supervision_config_one_for_all_helper");

        let config = SupervisionConfig::one_for_all(5, Duration::from_secs(120));

        assert_eq!(config.restart_policy, RestartPolicy::OneForAll);
        assert_eq!(config.max_restarts, 5);
        assert_eq!(config.restart_window, Duration::from_secs(120));

        crate::test_complete!("supervision_config_one_for_all_helper");
    }

    #[test]
    fn supervision_config_rest_for_one_helper() {
        init_test("supervision_config_rest_for_one_helper");

        let config = SupervisionConfig::rest_for_one(10, Duration::from_secs(300));

        assert_eq!(config.restart_policy, RestartPolicy::RestForOne);
        assert_eq!(config.max_restarts, 10);
        assert_eq!(config.restart_window, Duration::from_secs(300));

        crate::test_complete!("supervision_config_rest_for_one_helper");
    }

    #[test]
    fn child_spec_builder() {
        init_test("child_spec_builder");

        let spec = ChildSpec::new("worker-1")
            .with_config(SupervisionConfig::default())
            .with_start_immediately(false)
            .with_required(false);

        assert_eq!(spec.name, "worker-1");
        assert!(spec.config.is_some());
        assert!(!spec.start_immediately);
        assert!(!spec.required);

        crate::test_complete!("child_spec_builder");
    }

    #[test]
    fn child_spec_defaults() {
        init_test("child_spec_defaults");

        let spec = ChildSpec::new("default-child");

        assert_eq!(spec.name, "default-child");
        assert!(spec.config.is_none());
        assert!(spec.start_immediately);
        assert!(spec.required);

        crate::test_complete!("child_spec_defaults");
    }

    #[test]
    fn restart_policy_equality() {
        init_test("restart_policy_equality");

        assert_eq!(RestartPolicy::OneForOne, RestartPolicy::OneForOne);
        assert_ne!(RestartPolicy::OneForOne, RestartPolicy::OneForAll);
        assert_ne!(RestartPolicy::OneForAll, RestartPolicy::RestForOne);

        crate::test_complete!("restart_policy_equality");
    }

    #[test]
    fn escalation_policy_variants() {
        init_test("escalation_policy_variants");

        // Test all variants exist and are distinguishable
        let stop = EscalationPolicy::Stop;
        let escalate = EscalationPolicy::Escalate;
        let reset = EscalationPolicy::ResetCounter;

        assert_ne!(stop, escalate);
        assert_ne!(escalate, reset);
        assert_ne!(stop, reset);

        crate::test_complete!("escalation_policy_variants");
    }
}
