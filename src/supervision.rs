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
//! <!-- core-api-doctest: supervision-basics -->
//! ```
//! use asupersync::{Cx, main};
//! use asupersync::supervision::{BackoffStrategy, RestartConfig, SupervisionStrategy};
//! use std::time::Duration;
//!
//! #[main]
//! async fn main(cx: &Cx) {
//!     cx.checkpoint().expect("example starts active");
//!     let restart = RestartConfig::new(3, Duration::from_secs(60))
//!         .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(100)));
//!     let strategy = SupervisionStrategy::Restart(restart);
//!     assert!(matches!(strategy, SupervisionStrategy::Restart(_)));
//!
//!     let disabled = RestartConfig::new(0, Duration::from_secs(60));
//!     assert_eq!(disabled.max_restarts, 0);
//!     assert!(matches!(SupervisionStrategy::Stop, SupervisionStrategy::Stop));
//!     assert!(matches!(SupervisionStrategy::Escalate, SupervisionStrategy::Escalate));
//! }
//! ```

use std::collections::BTreeMap;
use std::hash::Hasher;
use std::sync::Arc;
use std::time::Duration;

use crate::runtime::{RegionCreateError, RuntimeState, SpawnError};
use crate::types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time};

// ============================================================================
// ChildName — reference-counted name for zero-cost cloning on hot paths
// ============================================================================

/// Shared, reference-counted child/supervisor name.
///
/// Cloning a `ChildName` is O(1) (atomic reference count bump) instead of
/// O(n) for a `String` clone. This eliminates heap allocations in the
/// supervisor restart-plan hot path where names are cloned into
/// `SupervisorRestartPlan` and `RegionOp` structures.
#[derive(Clone, Eq, Ord, PartialOrd)]
pub struct ChildName(Arc<str>);

impl ChildName {
    /// Create a new `ChildName`.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Self(name.into())
    }

    /// Borrow as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the number of strong references to the underlying `Arc`.
    ///
    /// Useful in gate tests to verify that hot-path clones share the
    /// same allocation rather than copying the string.
    #[must_use]
    pub fn strong_count(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}

impl std::ops::Deref for ChildName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ChildName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for ChildName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::hash::Hash for ChildName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (*self.0).hash(state);
    }
}

impl PartialEq for ChildName {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl PartialEq<str> for ChildName {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for ChildName {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl PartialEq<String> for ChildName {
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other.as_str()
    }
}

impl PartialEq<ChildName> for str {
    fn eq(&self, other: &ChildName) -> bool {
        self == &*other.0
    }
}

impl PartialEq<ChildName> for &str {
    fn eq(&self, other: &ChildName) -> bool {
        *self == &*other.0
    }
}

impl PartialEq<ChildName> for String {
    fn eq(&self, other: &ChildName) -> bool {
        self.as_str() == &*other.0
    }
}

impl From<&str> for ChildName {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl From<String> for ChildName {
    fn from(s: String) -> Self {
        Self(Arc::from(s))
    }
}

impl From<Arc<str>> for ChildName {
    fn from(s: Arc<str>) -> Self {
        Self(s)
    }
}

impl std::fmt::Debug for ChildName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &*self.0)
    }
}

impl std::fmt::Display for ChildName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

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
///
/// Restarts are also **budget-aware**: each restart attempt consumes
/// `restart_cost` from the parent region's cost quota, and restarts
/// are refused if the remaining time or poll budget is insufficient.
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

    /// Cost consumed from the parent budget per restart attempt.
    ///
    /// Each restart deducts this amount from the region's cost quota.
    /// If the remaining cost quota is less than this value, the restart
    /// is refused and the actor stops.
    ///
    /// Set to 0 (default) to disable cost-based restart limiting.
    pub restart_cost: u64,

    /// Minimum remaining time (relative to budget deadline) to allow a restart.
    ///
    /// If the budget deadline is closer than this duration, restarts are
    /// refused on the grounds that there isn't enough time for the child
    /// to do useful work. Uses virtual time for determinism.
    ///
    /// `None` (default) means no minimum-time constraint.
    pub min_remaining_for_restart: Option<Duration>,

    /// Minimum poll quota remaining to allow a restart.
    ///
    /// If fewer than this many polls remain in the budget, restarts are
    /// refused. Set to 0 (default) to disable poll-based restart limiting.
    pub min_polls_for_restart: u32,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window: Duration::from_mins(1),
            backoff: BackoffStrategy::default(),
            restart_cost: 0,
            min_remaining_for_restart: None,
            min_polls_for_restart: 0,
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
            restart_cost: 0,
            min_remaining_for_restart: None,
            min_polls_for_restart: 0,
        }
    }

    /// Set the backoff strategy.
    #[must_use]
    pub fn with_backoff(mut self, backoff: BackoffStrategy) -> Self {
        self.backoff = backoff;
        self
    }

    /// Set the cost consumed per restart attempt.
    #[must_use]
    pub fn with_restart_cost(mut self, cost: u64) -> Self {
        self.restart_cost = cost;
        self
    }

    /// Set the minimum remaining time required to allow a restart.
    #[must_use]
    pub fn with_min_remaining(mut self, min: Duration) -> Self {
        self.min_remaining_for_restart = Some(min);
        self
    }

    /// Set the minimum poll quota required to allow a restart.
    #[must_use]
    pub fn with_min_polls(mut self, min_polls: u32) -> Self {
        self.min_polls_for_restart = min_polls;
        self
    }
}

/// Backoff strategy for delays between restart attempts.
///
/// Backoff helps prevent thundering herd issues and gives transient
/// failures time to resolve.
#[derive(Debug, Clone)]
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
        /// Must be finite (not NaN or infinity).
        multiplier: f64,
    },
}

impl PartialEq for BackoffStrategy {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Fixed(a), Self::Fixed(b)) => a == b,
            (
                Self::Exponential {
                    initial: i1,
                    max: m1,
                    multiplier: mul1,
                },
                Self::Exponential {
                    initial: i2,
                    max: m2,
                    multiplier: mul2,
                },
            ) => i1 == i2 && m1 == m2 && mul1.to_bits() == mul2.to_bits(),
            _ => false,
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
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

    /// Optional storm detection threshold (restarts/second).
    ///
    /// When set, a [`RestartTracker`] created from this config will include
    /// intensity monitoring and e-process-based storm detection.
    pub storm_threshold: Option<f64>,
}

impl Default for SupervisionConfig {
    fn default() -> Self {
        Self {
            restart_policy: RestartPolicy::OneForOne,
            max_restarts: 3,
            restart_window: Duration::from_mins(1),
            backoff: BackoffStrategy::default(),
            escalation: EscalationPolicy::Stop,
            storm_threshold: None,
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
            storm_threshold: None,
        }
    }

    /// Enable storm detection with the given threshold (restarts/second).
    #[must_use]
    pub fn with_storm_threshold(mut self, threshold: f64) -> Self {
        validate_storm_threshold(threshold);
        self.storm_threshold = Some(threshold);
        self
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

    /// Build a [`RestartTracker`] from this supervision config.
    ///
    /// The tracker combines sliding-window counting, backoff, and optional
    /// storm detection into a single coordinator.
    #[must_use]
    pub fn restart_tracker(&self) -> RestartTracker {
        let restart = RestartConfig::new(self.max_restarts, self.restart_window)
            .with_backoff(self.backoff.clone());
        let mut tracker_config = RestartTrackerConfig::from_restart(restart);
        if let Some(threshold) = self.storm_threshold {
            tracker_config = tracker_config.with_storm_detection(threshold);
        }
        RestartTracker::new(tracker_config)
    }
}

// Eq requires manual impl due to f64 in BackoffStrategy
impl Eq for SupervisionConfig {}

/// Name registration policy for a child.
///
/// This is a **spec-level** field used by the SPORK supervisor builder to
/// define how children become discoverable. The actual registry capability
/// is planned (bd-3rpp8); until then this is carried through compilation
/// for determinism and UX contracts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NameRegistrationPolicy {
    /// Child is not registered.
    #[default]
    None,
    /// Child should be registered under `name`.
    Register {
        /// Registry key.
        name: String,
        /// Collision behavior when the name is already taken.
        collision: NameCollisionPolicy,
    },
}

/// Deterministic collision policy for name registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NameCollisionPolicy {
    /// Deterministically fail child start if name is taken.
    #[default]
    Fail,
    /// Deterministically replace the previous owner (requires proof hooks later).
    Replace,
    /// Deterministically wait (budget-aware) for the name to become free.
    Wait,
}

/// Start factory for a supervised child.
///
/// This is intentionally synchronous: child start should spawn tasks/actors
/// and return the *root* `TaskId` for the child. The supervisor runtime can
/// then track/wait/cancel by task identity.
///
/// The state-threaded signature is a deliberate boot-protocol decision
/// (br-asupersync-c6uw5y): boot must observe start failures inline and
/// needs the canonical task id immediately, which the asynchronous v2
/// gateway path cannot provide. Inside the started child, spawn further
/// work through the v2 surface ([`Cx::spawn`](crate::cx::Cx::spawn) and
/// friends), not by threading state onward.
pub trait ChildStart: Send {
    /// Start (or restart) the child inside `scope.region`.
    fn start(
        &mut self,
        scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        state: &mut RuntimeState,
        cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError>;
}

impl<F> ChildStart for F
where
    F: FnMut(
            &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            &mut RuntimeState,
            &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError>
        + Send,
{
    fn start(
        &mut self,
        scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        state: &mut RuntimeState,
        cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        (self)(scope, state, cx)
    }
}

/// Specification for a supervised child.
///
/// This is the **compiled topology input** for the SPORK supervisor builder.
/// It is intentionally explicit: all "ambient" behavior (naming, restart,
/// ordering) is specified in data so that the compiled runtime is deterministic.
pub struct ChildSpec {
    /// Unique child identifier (stable tie-break key).
    pub name: ChildName,
    /// Start factory (invoked at initial start and on restart).
    pub start: Box<dyn ChildStart>,
    /// Restart strategy for this child (Stop/Restart/Escalate).
    pub restart: SupervisionStrategy,
    /// Shutdown/cleanup budget for this child (used during supervisor stop).
    pub shutdown_budget: Budget,
    /// Explicit dependencies (child names). Used to compute deterministic start order.
    pub depends_on: Vec<ChildName>,
    /// Optional name registration policy.
    pub registration: NameRegistrationPolicy,
    /// Whether the child should be started immediately at supervisor boot.
    pub start_immediately: bool,
    /// Whether the child is required (supervisor fails if child can't start).
    pub required: bool,
}

impl std::fmt::Debug for ChildSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildSpec")
            .field("name", &self.name)
            .field("restart", &self.restart)
            .field("shutdown_budget", &self.shutdown_budget)
            .field("depends_on", &self.depends_on)
            .field("registration", &self.registration)
            .field("start_immediately", &self.start_immediately)
            .field("required", &self.required)
            .finish_non_exhaustive()
    }
}

impl ChildSpec {
    /// Create a new child spec.
    ///
    /// The child is `required` and `start_immediately` by default.
    pub fn new<F>(name: impl Into<ChildName>, start: F) -> Self
    where
        F: ChildStart + 'static,
    {
        Self {
            name: name.into(),
            start: Box::new(start),
            restart: SupervisionStrategy::default(),
            shutdown_budget: Budget::INFINITE,
            depends_on: Vec::new(),
            registration: NameRegistrationPolicy::None,
            start_immediately: true,
            required: true,
        }
    }

    /// Set the restart strategy for this child.
    #[must_use]
    pub fn with_restart(mut self, restart: SupervisionStrategy) -> Self {
        self.restart = restart;
        self
    }

    /// Set the shutdown budget for this child.
    #[must_use]
    pub fn with_shutdown_budget(mut self, budget: Budget) -> Self {
        self.shutdown_budget = budget;
        self
    }

    /// Add a dependency on another child by name.
    #[must_use]
    pub fn depends_on(mut self, name: impl Into<ChildName>) -> Self {
        self.depends_on.push(name.into());
        self
    }

    /// Set name registration policy for this child.
    #[must_use]
    pub fn with_registration(mut self, policy: NameRegistrationPolicy) -> Self {
        self.registration = policy;
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

    /// Compare two child specs by deterministic declarative surface only.
    ///
    /// This intentionally ignores the `start` factory closure and compares
    /// only pure spec fields so builder outputs can be compared in tests and
    /// tooling without depending on closure identity.
    #[must_use]
    pub fn spec_eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.restart == other.restart
            && self.shutdown_budget == other.shutdown_budget
            && self.depends_on == other.depends_on
            && self.registration == other.registration
            && self.start_immediately == other.start_immediately
            && self.required == other.required
    }

    /// Deterministic fingerprint of the declarative child spec fields.
    ///
    /// Like [`spec_eq`](Self::spec_eq), this excludes the `start` closure and
    /// hashes only pure spec data.
    #[must_use]
    pub fn spec_fingerprint(&self) -> u64 {
        let mut hasher = crate::util::DetHasher::default();
        hash_child_spec_fields(self, &mut hasher);
        std::hash::Hasher::finish(&hasher)
    }
}

/// Deterministic start-order tie-break policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartTieBreak {
    /// Choose the next ready child by insertion order (stable).
    #[default]
    InsertionOrder,
    /// Choose the next ready child lexicographically by name.
    NameLex,
}

/// Errors that can occur when compiling a supervisor topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorCompileError {
    /// Two children shared the same name.
    DuplicateChildName(ChildName),
    /// A dependency referenced an unknown child.
    UnknownDependency {
        /// Child name.
        child: ChildName,
        /// Dependency name that was not present in the child set.
        depends_on: ChildName,
    },
    /// An eagerly-started child depends on a deferred child.
    DeferredDependency {
        /// Child name.
        child: ChildName,
        /// Deferred dependency that cannot satisfy eager boot ordering.
        depends_on: ChildName,
    },
    /// Dependency graph contains a cycle.
    CycleDetected {
        /// Remaining nodes with non-zero in-degree (sorted).
        remaining: Vec<ChildName>,
    },
}

impl std::fmt::Display for SupervisorCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateChildName(name) => write!(f, "duplicate child name: {name}"),
            Self::UnknownDependency { child, depends_on } => {
                write!(f, "child {child} depends on unknown child {depends_on}")
            }
            Self::DeferredDependency { child, depends_on } => {
                write!(
                    f,
                    "child {child} is start_immediately but depends on deferred child {depends_on}"
                )
            }
            Self::CycleDetected { remaining } => {
                write!(f, "dependency cycle detected among children: ")?;
                for (i, name) in remaining.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{name}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for SupervisorCompileError {}

/// Errors that can occur when spawning a compiled supervisor.
#[derive(Debug)]
pub enum SupervisorSpawnError {
    /// Failed to create supervisor region.
    RegionCreate(RegionCreateError),
    /// Child start failed. The supervisor region has been closed (begin_close +
    /// begin_drain) so that previously-started children are not orphaned.
    ChildStartFailed {
        /// Child name.
        child: ChildName,
        /// Underlying spawn error.
        err: SpawnError,
        /// Region that was created for the supervisor. It has been closed but
        /// is returned for caller awareness / logging.
        region: RegionId,
    },
    /// A required child could not boot because one of its eager dependencies
    /// failed or was skipped during the same supervisor boot.
    DependencyUnavailable {
        /// Child that could not be started.
        child: ChildName,
        /// Direct dependency that was unavailable.
        dependency: ChildName,
        /// Root-cause start failure for that dependency, when available.
        dependency_error: Option<SpawnError>,
        /// Region that was created for the supervisor. It has been closed but
        /// is returned for caller awareness / logging.
        region: RegionId,
    },
}

impl std::fmt::Display for SupervisorSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionCreate(e) => write!(f, "supervisor region create failed: {e}"),
            Self::ChildStartFailed {
                child, err, region, ..
            } => {
                write!(
                    f,
                    "child start failed: child={child} region={region:?} err={err}"
                )
            }
            Self::DependencyUnavailable {
                child,
                dependency,
                dependency_error,
                region,
            } => match dependency_error {
                Some(err) => write!(
                    f,
                    "child start blocked: child={child} dependency={dependency} region={region:?} cause={err}"
                ),
                None => write!(
                    f,
                    "child start blocked: child={child} dependency={dependency} region={region:?}"
                ),
            },
        }
    }
}

impl std::error::Error for SupervisorSpawnError {}

impl From<RegionCreateError> for SupervisorSpawnError {
    fn from(value: RegionCreateError) -> Self {
        Self::RegionCreate(value)
    }
}

/// Builder for an OTP-style supervisor topology.
///
/// The builder is pure data + closures; `compile()` produces a deterministic start
/// order and validates dependencies.
#[derive(Debug)]
pub struct SupervisorBuilder {
    name: ChildName,
    budget: Option<Budget>,
    tie_break: StartTieBreak,
    restart_policy: RestartPolicy,
    children: Vec<ChildSpec>,
}

impl SupervisorBuilder {
    /// Create a new supervisor builder.
    #[must_use]
    pub fn new(name: impl Into<ChildName>) -> Self {
        Self {
            name: name.into(),
            budget: None,
            tie_break: StartTieBreak::InsertionOrder,
            restart_policy: RestartPolicy::OneForOne,
            children: Vec::new(),
        }
    }

    /// Override the supervisor region budget (met with the parent budget).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Set the deterministic tie-break policy for ready children.
    #[must_use]
    pub fn with_tie_break(mut self, tie_break: StartTieBreak) -> Self {
        self.tie_break = tie_break;
        self
    }

    /// Set the supervisor-level restart policy (one_for_one / one_for_all / rest_for_one).
    ///
    /// This controls which *set of children* are cancelled and restarted when a child fails.
    /// It is independent from per-child [`SupervisionStrategy`] (Stop/Restart/Escalate), which
    /// decides whether a given child failure is restartable at all.
    #[must_use]
    pub fn with_restart_policy(mut self, restart_policy: RestartPolicy) -> Self {
        self.restart_policy = restart_policy;
        self
    }

    /// Add a child spec.
    #[must_use]
    pub fn child(mut self, child: ChildSpec) -> Self {
        self.children.push(child);
        self
    }

    /// Compare two builders by deterministic declarative surface only.
    ///
    /// Child start factories are intentionally ignored; only pure spec fields
    /// are compared.
    #[must_use]
    pub fn spec_eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.budget == other.budget
            && self.tie_break == other.tie_break
            && self.restart_policy == other.restart_policy
            && self.children.len() == other.children.len()
            && self
                .children
                .iter()
                .zip(other.children.iter())
                .all(|(left, right)| left.spec_eq(right))
    }

    /// Deterministic fingerprint of the declarative builder surface.
    ///
    /// Child start factories are intentionally excluded so the result is stable
    /// across equivalent builder construction paths.
    #[must_use]
    pub fn spec_fingerprint(&self) -> u64 {
        let mut hasher = crate::util::DetHasher::default();
        hasher.write(self.name.as_str().as_bytes());
        hash_budget_option(&mut hasher, self.budget);
        hash_start_tie_break(&mut hasher, self.tie_break);
        hash_restart_policy(&mut hasher, self.restart_policy);
        hasher.write_u64(self.children.len() as u64);
        for child in &self.children {
            hash_child_spec_fields(child, &mut hasher);
        }
        std::hash::Hasher::finish(&hasher)
    }

    /// Compile the topology into a deterministic start order.
    pub fn compile(self) -> Result<CompiledSupervisor, SupervisorCompileError> {
        CompiledSupervisor::new(self)
    }
}

fn hash_child_spec_fields(spec: &ChildSpec, hasher: &mut crate::util::DetHasher) {
    hasher.write(spec.name.as_str().as_bytes());
    hash_supervision_strategy(hasher, &spec.restart);
    hash_budget(hasher, spec.shutdown_budget);
    hasher.write_u64(spec.depends_on.len() as u64);
    for dep in &spec.depends_on {
        hasher.write(dep.as_str().as_bytes());
    }
    hash_registration_policy(hasher, &spec.registration);
    hasher.write_u8(u8::from(spec.start_immediately));
    hasher.write_u8(u8::from(spec.required));
}

fn hash_budget_option(hasher: &mut crate::util::DetHasher, budget: Option<Budget>) {
    match budget {
        Some(value) => {
            hasher.write_u8(1);
            hash_budget(hasher, value);
        }
        None => hasher.write_u8(0),
    }
}

fn hash_budget(hasher: &mut crate::util::DetHasher, budget: Budget) {
    match budget.deadline {
        Some(deadline) => {
            hasher.write_u8(1);
            hasher.write_u64(deadline.as_nanos());
        }
        None => hasher.write_u8(0),
    }
    hasher.write_u32(budget.poll_quota);
    match budget.cost_quota {
        Some(cost) => {
            hasher.write_u8(1);
            hasher.write_u64(cost);
        }
        None => hasher.write_u8(0),
    }
    hasher.write_u8(budget.priority);
}

fn hash_supervision_strategy(hasher: &mut crate::util::DetHasher, strategy: &SupervisionStrategy) {
    match strategy {
        SupervisionStrategy::Stop => hasher.write_u8(0),
        SupervisionStrategy::Restart(config) => {
            hasher.write_u8(1);
            hash_restart_config(hasher, config);
        }
        SupervisionStrategy::Escalate => hasher.write_u8(2),
    }
}

fn duration_nanos_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn hash_restart_config(hasher: &mut crate::util::DetHasher, config: &RestartConfig) {
    hasher.write_u32(config.max_restarts);
    hasher.write_u64(duration_nanos_u64(config.window));
    hash_backoff_strategy(hasher, &config.backoff);
    hasher.write_u64(config.restart_cost);
    match config.min_remaining_for_restart {
        Some(value) => {
            hasher.write_u8(1);
            hasher.write_u64(duration_nanos_u64(value));
        }
        None => hasher.write_u8(0),
    }
    hasher.write_u32(config.min_polls_for_restart);
}

fn hash_backoff_strategy(hasher: &mut crate::util::DetHasher, strategy: &BackoffStrategy) {
    match strategy {
        BackoffStrategy::None => hasher.write_u8(0),
        BackoffStrategy::Fixed(value) => {
            hasher.write_u8(1);
            hasher.write_u64(duration_nanos_u64(*value));
        }
        BackoffStrategy::Exponential {
            initial,
            max,
            multiplier,
        } => {
            hasher.write_u8(2);
            hasher.write_u64(duration_nanos_u64(*initial));
            hasher.write_u64(duration_nanos_u64(*max));
            hasher.write_u64(multiplier.to_bits());
        }
    }
}

fn hash_registration_policy(hasher: &mut crate::util::DetHasher, policy: &NameRegistrationPolicy) {
    match policy {
        NameRegistrationPolicy::None => hasher.write_u8(0),
        NameRegistrationPolicy::Register { name, collision } => {
            hasher.write_u8(1);
            hasher.write(name.as_bytes());
            hash_collision_policy(hasher, *collision);
        }
    }
}

fn hash_collision_policy(hasher: &mut crate::util::DetHasher, policy: NameCollisionPolicy) {
    match policy {
        NameCollisionPolicy::Fail => hasher.write_u8(0),
        NameCollisionPolicy::Replace => hasher.write_u8(1),
        NameCollisionPolicy::Wait => hasher.write_u8(2),
    }
}

fn hash_restart_policy(hasher: &mut crate::util::DetHasher, policy: RestartPolicy) {
    match policy {
        RestartPolicy::OneForOne => hasher.write_u8(0),
        RestartPolicy::OneForAll => hasher.write_u8(1),
        RestartPolicy::RestForOne => hasher.write_u8(2),
    }
}

fn hash_start_tie_break(hasher: &mut crate::util::DetHasher, tie_break: StartTieBreak) {
    match tie_break {
        StartTieBreak::InsertionOrder => hasher.write_u8(0),
        StartTieBreak::NameLex => hasher.write_u8(1),
    }
}

/// A compiled supervisor topology with deterministic start order.
#[derive(Debug)]
pub struct CompiledSupervisor {
    /// Supervisor name (for trace/evidence output).
    pub name: ChildName,
    /// Optional supervisor region budget override.
    pub budget: Option<Budget>,
    /// Deterministic tie-break policy used during compilation.
    pub tie_break: StartTieBreak,
    /// Restart policy applied when a child fails.
    pub restart_policy: RestartPolicy,
    /// Child specifications (including start factories).
    pub children: Vec<ChildSpec>,
    /// Deterministic start order as indices into `children`.
    pub start_order: Vec<usize>,
}

/// A deterministic cancel/restart plan for a supervisor after a child failure.
///
/// This is a pure, replay-stable computation based on the compiled start order.
/// Runtime wiring (observing exits, draining losers, applying shutdown budgets)
/// is layered on top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorRestartPlan {
    /// Supervisor policy that produced this plan.
    pub policy: RestartPolicy,
    /// Children to cancel in order (dependents-first).
    pub cancel_order: Vec<ChildName>,
    /// Children to restart in order (dependencies-first).
    pub restart_order: Vec<ChildName>,
}

/// An atomic region operation emitted by strategy compilation.
///
/// These ops form a three-phase restart protocol:
/// 1. **Cancel** dependents-first (reverse start order).
/// 2. **Drain** each cancelled child (bounded by its shutdown budget).
/// 3. **Restart** dependencies-first (start order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionOp {
    /// Request cancellation for the named child, bounded by its shutdown budget.
    CancelChild {
        /// Child name.
        name: ChildName,
        /// Budget for shutdown/cleanup.
        shutdown_budget: Budget,
    },
    /// Drain/quiesce the named child after cancellation, bounded by its shutdown budget.
    DrainChild {
        /// Child name.
        name: ChildName,
        /// Budget for drain phase.
        shutdown_budget: Budget,
    },
    /// Restart the named child (re-invoke its `ChildStart`).
    RestartChild {
        /// Child name.
        name: ChildName,
    },
}

/// A compiled sequence of [`RegionOp`]s produced from a [`SupervisorRestartPlan`].
///
/// The ops are ordered: all cancels first, then all drains, then all restarts.
/// This three-phase ordering ensures no child is restarted while siblings are
/// still draining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRestartOps {
    /// The restart policy that produced this sequence.
    pub policy: RestartPolicy,
    /// Ordered operations to execute.
    pub ops: Vec<RegionOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadyKey {
    name: ChildName,
    idx: usize,
}

impl Ord for ReadyKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Deterministic ordering key for tie-breaks:
        // - `StartTieBreak::NameLex` uses (name, idx) directly via `BTreeSet` iteration.
        // - `StartTieBreak::InsertionOrder` selects the minimum idx explicitly (see below).
        self.name
            .cmp(&other.name)
            .then_with(|| self.idx.cmp(&other.idx))
    }
}

impl PartialOrd for ReadyKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl CompiledSupervisor {
    fn new(builder: SupervisorBuilder) -> Result<Self, SupervisorCompileError> {
        let mut name_to_idx = std::collections::HashMap::<ChildName, usize>::new();
        for (idx, child) in builder.children.iter().enumerate() {
            if name_to_idx.insert(child.name.clone(), idx).is_some() {
                return Err(SupervisorCompileError::DuplicateChildName(
                    child.name.clone(),
                ));
            }
        }

        let mut indeg = vec![0usize; builder.children.len()];
        let mut out = vec![Vec::<usize>::new(); builder.children.len()];

        for (idx, child) in builder.children.iter().enumerate() {
            // Deduplicate dependencies to prevent incorrect indegree calculation
            let mut seen_deps = std::collections::HashSet::new();
            for dep in &child.depends_on {
                // Skip duplicate dependencies
                if !seen_deps.insert(dep) {
                    continue;
                }

                let Some(&dep_idx) = name_to_idx.get(dep) else {
                    return Err(SupervisorCompileError::UnknownDependency {
                        child: child.name.clone(),
                        depends_on: dep.clone(),
                    });
                };
                if child.start_immediately && !builder.children[dep_idx].start_immediately {
                    return Err(SupervisorCompileError::DeferredDependency {
                        child: child.name.clone(),
                        depends_on: dep.clone(),
                    });
                }
                indeg[idx] += 1;
                out[dep_idx].push(idx);
            }
        }

        let mut ready = std::collections::BTreeSet::<ReadyKey>::new();
        for (idx, child) in builder.children.iter().enumerate() {
            if indeg[idx] == 0 {
                ready.insert(ReadyKey {
                    name: child.name.clone(),
                    idx,
                });
            }
        }

        let mut order = Vec::with_capacity(builder.children.len());
        while let Some(next) = match builder.tie_break {
            StartTieBreak::InsertionOrder => ready
                .iter()
                .min_by(|a, b| a.idx.cmp(&b.idx).then_with(|| a.name.cmp(&b.name)))
                .cloned(),
            StartTieBreak::NameLex => ready.iter().next().cloned(),
        } {
            ready.take(&next);
            order.push(next.idx);
            for &succ in &out[next.idx] {
                indeg[succ] = indeg[succ].saturating_sub(1);
                if indeg[succ] == 0 {
                    ready.insert(ReadyKey {
                        name: builder.children[succ].name.clone(),
                        idx: succ,
                    });
                }
            }
        }

        if order.len() != builder.children.len() {
            let mut remaining = Vec::new();
            for (idx, child) in builder.children.iter().enumerate() {
                if indeg[idx] > 0 {
                    remaining.push(child.name.clone());
                }
            }
            remaining.sort();
            return Err(SupervisorCompileError::CycleDetected { remaining });
        }

        Ok(Self {
            name: builder.name,
            budget: builder.budget,
            tie_break: builder.tie_break,
            restart_policy: builder.restart_policy,
            children: builder.children,
            start_order: order,
        })
    }

    /// Compute which children should be cancelled/restarted when `failed_child` fails.
    ///
    /// Semantics are OTP-style and based on the compiled start order:
    /// - `OneForOne`: cancel+restart only the failed child.
    /// - `OneForAll`: cancel all children (reverse start order), then restart all (start order).
    /// - `RestForOne`: cancel failed child and all children started after it, then restart that suffix.
    ///
    /// Notes:
    /// - This computation is deterministic and does not require any global locks.
    /// - It does not consult per-child restartability (that is handled by per-child
    ///   [`SupervisionStrategy`] in the runtime wiring).
    #[must_use]
    pub fn restart_plan_for(&self, failed_child: &str) -> Option<SupervisorRestartPlan> {
        let failed_idx = self
            .children
            .iter()
            .enumerate()
            .find_map(|(idx, child)| (child.name == failed_child).then_some(idx))?;

        self.restart_plan_for_idx(failed_idx)
    }

    /// Returns the deterministic start position (rank) for `child_name`.
    ///
    /// This is the core ordering key for supervisor-level determinism:
    /// - Restart sequencing is derived from start order (cancel = reverse, restart = forward).
    /// - If a runtime layer batches multiple logically-simultaneous child failures, it should
    ///   process them in ascending start position (and use `TaskId` as a stable tie-break if needed).
    #[must_use]
    pub fn child_start_pos(&self, child_name: &str) -> Option<usize> {
        let child_idx = self
            .children
            .iter()
            .enumerate()
            .find_map(|(idx, child)| (child.name == child_name).then_some(idx))?;
        self.start_pos_for_child_idx(child_idx)
    }

    /// Returns child names in deterministic start order.
    ///
    /// This is the concrete ordering contract used by supervisor startup
    /// (**SUP-START** in `docs/spork_deterministic_ordering.md`).
    #[must_use]
    pub fn child_start_order_names(&self) -> Vec<&str> {
        self.start_order
            .iter()
            .map(|&idx| self.children[idx].name.as_str())
            .collect()
    }

    /// Returns child names in deterministic stop/drain order.
    ///
    /// Stop/drain order is the reverse of start order, matching OTP-style
    /// dependency unwind (**SUP-STOP** in `docs/spork_deterministic_ordering.md`).
    #[must_use]
    pub fn child_stop_order_names(&self) -> Vec<&str> {
        self.start_order
            .iter()
            .rev()
            .map(|&idx| self.children[idx].name.as_str())
            .collect()
    }

    #[must_use]
    fn start_pos_for_child_idx(&self, child_idx: usize) -> Option<usize> {
        self.start_order.iter().position(|&idx| idx == child_idx)
    }

    /// Compute a restart plan for a concrete failure `outcome`.
    ///
    /// This enforces the monotone-severity contract:
    /// - `Ok` / `Cancelled` / `Panicked` outcomes never produce a restart plan.
    /// - Only `Err` outcomes are candidates for restart, and only when the child's per-child
    ///   [`SupervisionStrategy`] is `Restart(..)`.
    ///
    /// The returned plan is a deterministic cancel+restart ordering (dependents-first cancel,
    /// dependencies-first restart) that can be wired into the runtime's cancel protocol:
    /// request cancel for each child in `cancel_order`, fully drain/quiesce, then restart in
    /// `restart_order`.
    ///
    /// This plan excludes deferred siblings that were never booted by the
    /// supervisor's initial `start_immediately` pass. If a runtime later boots
    /// deferred children dynamically, it must layer concrete live-child
    /// knowledge on top when deciding whether they participate in a restart.
    ///
    /// Restart planning is failure-aware:
    /// - `cancel_order` still includes all siblings affected by the supervisor-level
    ///   [`RestartPolicy`], even if some of them are not restartable.
    /// - `restart_order` is pruned to children whose own [`SupervisionStrategy`] is
    ///   [`SupervisionStrategy::Restart`] and whose dependencies within the affected slice are
    ///   also being restarted. This preserves the documented `Stop` = temporary / never restart
    ///   contract and avoids scheduling dependents behind non-restarted dependencies.
    #[must_use]
    pub fn restart_plan_for_failure<E>(
        &self,
        failed_child: &str,
        outcome: &Outcome<(), E>,
    ) -> Option<SupervisorRestartPlan> {
        let failed_idx = self
            .children
            .iter()
            .enumerate()
            .find_map(|(idx, child)| (child.name == failed_child).then_some(idx))?;

        // Monotone severity: only errors are candidates for restart.
        if !matches!(outcome, Outcome::Err(_)) {
            return None;
        }

        match self.children[failed_idx].restart {
            SupervisionStrategy::Restart(_) => self.restart_plan_for_failure_idx(failed_idx),
            SupervisionStrategy::Stop | SupervisionStrategy::Escalate => None,
        }
    }

    #[must_use]
    fn affected_positions_for_idx(&self, failed_child_idx: usize) -> Option<Vec<usize>> {
        let failed_pos = self.start_pos_for_child_idx(failed_child_idx)?;

        let total = self.start_order.len();
        let affected_positions = match self.restart_policy {
            RestartPolicy::OneForOne => vec![failed_pos],
            RestartPolicy::OneForAll => (0..total).collect(),
            RestartPolicy::RestForOne => (failed_pos..total).collect(),
        }
        .into_iter()
        .filter(|&pos| {
            let child_idx = self.start_order[pos];
            let child = &self.children[child_idx];
            child.start_immediately || child_idx == failed_child_idx
        })
        .collect::<Vec<_>>();

        (!affected_positions.is_empty()).then_some(affected_positions)
    }

    #[must_use]
    fn restart_plan_for_failure_idx(
        &self,
        failed_child_idx: usize,
    ) -> Option<SupervisorRestartPlan> {
        let affected_positions = self.affected_positions_for_idx(failed_child_idx)?;

        let mut cancel_order = Vec::with_capacity(affected_positions.len());
        for &pos in affected_positions.iter().rev() {
            cancel_order.push(self.children[self.start_order[pos]].name.clone());
        }

        let child_index_by_name = self
            .children
            .iter()
            .enumerate()
            .map(|(idx, child)| (child.name.as_str(), idx))
            .collect::<std::collections::HashMap<_, _>>();
        let mut affected_children = vec![false; self.children.len()];
        for &pos in &affected_positions {
            affected_children[self.start_order[pos]] = true;
        }

        let mut scheduled_restart = vec![false; self.children.len()];
        let mut restart_order = Vec::with_capacity(affected_positions.len());
        for &pos in &affected_positions {
            let child_idx = self.start_order[pos];
            let child = &self.children[child_idx];

            if !matches!(child.restart, SupervisionStrategy::Restart(_)) {
                continue;
            }

            let dependencies_restartable = child.depends_on.iter().all(|dependency| {
                let dep_idx = *child_index_by_name
                    .get(dependency.as_str())
                    .expect("compiled supervisor dependency index missing");
                !affected_children[dep_idx] || scheduled_restart[dep_idx]
            });
            if !dependencies_restartable {
                continue;
            }

            scheduled_restart[child_idx] = true;
            restart_order.push(child.name.clone());
        }

        Some(SupervisorRestartPlan {
            policy: self.restart_policy,
            cancel_order,
            restart_order,
        })
    }

    #[must_use]
    fn restart_plan_for_idx(&self, failed_child_idx: usize) -> Option<SupervisorRestartPlan> {
        let affected_positions = self.affected_positions_for_idx(failed_child_idx)?;

        // Hot-path allocation gate: construct orders directly without an
        // intermediate positions Vec of child names, while preserving
        // deterministic order.
        let mut cancel_order = Vec::with_capacity(affected_positions.len());
        let mut restart_order = Vec::with_capacity(affected_positions.len());

        for &pos in affected_positions.iter().rev() {
            cancel_order.push(self.children[self.start_order[pos]].name.clone());
        }
        for &pos in &affected_positions {
            restart_order.push(self.children[self.start_order[pos]].name.clone());
        }

        Some(SupervisorRestartPlan {
            policy: self.restart_policy,
            cancel_order,
            restart_order,
        })
    }

    /// Compile a [`SupervisorRestartPlan`] into a sequence of [`RegionOp`]s.
    ///
    /// The output is a three-phase protocol:
    /// 1. `CancelChild` for each entry in `cancel_order` (dependents-first), bounded by
    ///    the child's `shutdown_budget`.
    /// 2. `DrainChild` for each cancelled child (same order), bounded by the same budget.
    /// 3. `RestartChild` for each entry in `restart_order` (dependencies-first).
    ///
    /// This is a pure function: no side effects, deterministic, replay-stable.
    #[must_use]
    pub fn compile_restart_ops(&self, plan: &SupervisorRestartPlan) -> CompiledRestartOps {
        let child_index_by_name = self
            .children
            .iter()
            .enumerate()
            .map(|(idx, child)| (child.name.as_str(), idx))
            .collect::<std::collections::HashMap<_, _>>();
        let child_by_name = |name: &str| -> Option<&ChildSpec> {
            child_index_by_name
                .get(name)
                .map(|&idx| &self.children[idx])
        };

        let mut ops = Vec::with_capacity(plan.cancel_order.len() * 2 + plan.restart_order.len());

        // Phase 1: Cancel in cancel_order (dependents-first)
        for name in &plan.cancel_order {
            let budget = child_by_name(name).map_or(Budget::INFINITE, |c| c.shutdown_budget);
            ops.push(RegionOp::CancelChild {
                name: name.clone(),
                shutdown_budget: budget,
            });
        }

        // Phase 2: Drain each cancelled child (bounded by shutdown budget)
        for name in &plan.cancel_order {
            let budget = child_by_name(name).map_or(Budget::INFINITE, |c| c.shutdown_budget);
            ops.push(RegionOp::DrainChild {
                name: name.clone(),
                shutdown_budget: budget,
            });
        }

        // Phase 3: Restart in restart_order (dependencies-first).
        //
        // br-asupersync-jkwhrd: filter by per-child SupervisionStrategy.
        // restart_plan_for(name: &str) deliberately produces an
        // unfiltered restart_order — its doc says "does not consult
        // per-child restartability (that is handled by per-child
        // SupervisionStrategy in the runtime wiring)." compile_restart_ops
        // IS that runtime-wiring layer, so the filter belongs here.
        // Without this filter, composing restart_plan_for +
        // compile_restart_ops emits a RestartChild op for children whose
        // strategy is Stop or Escalate — incorrect restart of a child
        // that should have stayed stopped. cancel + drain phases above
        // remain unfiltered: under OneForAll / RestForOne, Stop-strategy
        // children still need to be cancelled+drained alongside their
        // siblings, just not restarted.
        //
        // br-asupersync-730rc1: the strategy filter must also cascade through
        // dependencies within the affected slice. If an affected dependency
        // is not scheduled (for example, its strategy is Stop), restarting a
        // dependent behind it would revive a child whose dependency remains
        // stopped. Dependencies outside cancel_order remain live and do not
        // participate in this restart phase.
        let mut affected_children = vec![false; self.children.len()];
        for name in &plan.cancel_order {
            if let Some(&child_idx) = child_index_by_name.get(name.as_str()) {
                affected_children[child_idx] = true;
            }
        }

        let mut scheduled_restart = vec![false; self.children.len()];
        for name in &plan.restart_order {
            let Some(&child_idx) = child_index_by_name.get(name.as_str()) else {
                continue;
            };
            let child = &self.children[child_idx];
            if !matches!(child.restart, SupervisionStrategy::Restart(_)) {
                continue;
            }

            let dependencies_restartable = child.depends_on.iter().all(|dependency| {
                let dep_idx = *child_index_by_name
                    .get(dependency.as_str())
                    .expect("compiled supervisor dependency index missing");
                !affected_children[dep_idx] || scheduled_restart[dep_idx]
            });
            if !dependencies_restartable {
                continue;
            }

            scheduled_restart[child_idx] = true;
            ops.push(RegionOp::RestartChild { name: name.clone() });
        }

        CompiledRestartOps {
            policy: plan.policy,
            ops,
        }
    }

    /// Spawns the supervisor as a child region under `parent_region` and starts
    /// all `start_immediately` children in the compiled order.
    ///
    /// This method establishes the **region-owned structure** and deterministic start ordering.
    /// Runtime dependency availability is also enforced: if an eager dependency fails or is
    /// skipped during boot, its eager dependents are skipped as well, and any required dependent
    /// turns the whole boot into a deterministic supervisor spawn failure.
    /// Restart semantics are specified by [`RestartPolicy`] and computed by
    /// [`CompiledSupervisor::restart_plan_for`]; wiring it into a live restart loop is layered
    /// on top by follow-up work (asupersync-8y37kz.2; the earlier bd-1yv7a / bd-35iz1 ids are
    /// stale and no longer tracked). Today only per-actor supervision (`src/actor.rs`) drives
    /// live restart-on-failure — a child crash under a `CompiledSupervisor` tree is NOT restarted
    /// at runtime (asupersync-u2vgjg).
    ///
    /// # Why this keeps `&mut RuntimeState` (br-asupersync-c6uw5y)
    ///
    /// Supervisor boot is deliberately **not** routed through the v2 spawn
    /// gateway: dependency-ordered boot must observe each child's start
    /// failure *inline* (to mark dependents unavailable and to roll the
    /// whole region back deterministically), and the gateway path resolves
    /// spawn denials asynchronously through handles. Boot is runtime
    /// infrastructure in the same class as region creation, which also
    /// threads state. User-facing task spawning inside a running
    /// supervisor/child should use the v2 surface
    /// ([`Cx::spawn`](crate::cx::Cx::spawn) /
    /// [`Cx::spawn_registered_in`](crate::cx::Cx::spawn_registered_in));
    /// only the boot protocol itself stays state-threaded.
    pub fn spawn(
        mut self,
        state: &mut RuntimeState,
        cx: &crate::cx::Cx,
        parent_region: RegionId,
        parent_budget: Budget,
    ) -> Result<SupervisorHandle, SupervisorSpawnError> {
        let budget = self.budget.unwrap_or(parent_budget);
        let region = state.create_child_region(parent_region, budget)?;
        let effective_budget = state
            .region(region)
            .map_or(budget, crate::record::RegionRecord::budget);

        let scope: crate::cx::Scope<'static, crate::types::policy::FailFast> =
            crate::cx::Scope::<crate::types::policy::FailFast>::new(region, effective_budget);

        #[derive(Clone)]
        enum BootState {
            NotStarted,
            Deferred,
            Started,
            Failed(SpawnError),
            DependencyUnavailable {
                dependency_error: Option<SpawnError>,
            },
        }

        fn abort_supervisor_boot(state: &mut RuntimeState, region: RegionId) {
            let effects =
                state.cancel_request(region, &crate::types::CancelReason::shutdown(), None);
            state.defer_cancel_dispatch(effects);
            if let Some(r) = state.region(region) {
                r.begin_close(None);
            }
            state.advance_region_state(region);
        }

        let child_index_by_name = self
            .children
            .iter()
            .enumerate()
            .map(|(idx, child)| (child.name.clone(), idx))
            .collect::<std::collections::HashMap<_, _>>();
        let mut boot_states = vec![BootState::NotStarted; self.children.len()];
        let mut started = Vec::new();
        for &idx in &self.start_order {
            let (child_name, child_required, child_dependencies, start_immediately) = {
                let child = &self.children[idx];
                (
                    child.name.clone(),
                    child.required,
                    child.depends_on.clone(),
                    child.start_immediately,
                )
            };

            if !start_immediately {
                boot_states[idx] = BootState::Deferred;
                continue;
            }

            let dependency_unavailable = child_dependencies.iter().find_map(|dependency| {
                let dep_idx = *child_index_by_name
                    .get(dependency)
                    .expect("compiled supervisor dependency index missing");
                match &boot_states[dep_idx] {
                    BootState::Started => None,
                    BootState::Failed(err) => Some((dependency.clone(), Some(err.clone()))),
                    BootState::DependencyUnavailable { dependency_error } => {
                        Some((dependency.clone(), dependency_error.clone()))
                    }
                    BootState::NotStarted | BootState::Deferred => Some((dependency.clone(), None)),
                }
            });

            if let Some((dependency, dependency_error)) = dependency_unavailable {
                cx.trace("supervisor_child_start_blocked_dependency");
                if child_required {
                    abort_supervisor_boot(state, region);
                    return Err(SupervisorSpawnError::DependencyUnavailable {
                        child: child_name,
                        dependency,
                        dependency_error,
                        region,
                    });
                }
                boot_states[idx] = BootState::DependencyUnavailable { dependency_error };
                continue;
            }

            let child = &mut self.children[idx];
            match child.start.start(&scope, state, cx) {
                Ok(task_id) => started.push(StartedChild {
                    name: child_name.clone(),
                    task_id,
                }),
                Err(err) => {
                    boot_states[idx] = BootState::Failed(err.clone());
                    cx.trace("supervisor_child_start_failed");
                    if child_required {
                        // Drive the full cancel cascade so any already-started
                        // children transition into cancellation instead of
                        // remaining live under a failed supervisor boot.
                        abort_supervisor_boot(state, region);
                        return Err(SupervisorSpawnError::ChildStartFailed {
                            child: child_name,
                            err,
                            region,
                        });
                    }
                }
            }
            if matches!(boot_states[idx], BootState::NotStarted) {
                boot_states[idx] = BootState::Started;
            }
        }

        Ok(SupervisorHandle {
            name: self.name,
            region,
            started,
        })
    }
}

/// Result of spawning a compiled supervisor.
#[derive(Debug)]
pub struct SupervisorHandle {
    /// Supervisor name.
    pub name: ChildName,
    /// Region that owns the supervisor and its children.
    pub region: RegionId,
    /// Children that were started immediately (in start order).
    pub started: Vec<StartedChild>,
}

/// Information about a child started by a supervisor.
#[derive(Debug)]
pub struct StartedChild {
    /// Child name.
    pub name: ChildName,
    /// Root task id for the child.
    pub task_id: TaskId,
}

// The managed entry point is additive: the state-threaded ChildStart and the
// declarative restart planners above keep their original contracts.
pub use managed::{
    ManagedChildBinding, ManagedChildCompletion, ManagedChildFactory, ManagedChildFuture,
    ManagedGeneration, ManagedRestartMode, ManagedSupervisor, ManagedSupervisorBindError,
    ManagedSupervisorError, ManagedSupervisorHandle, ManagedSupervisorReport,
};

mod managed {
    use super::{
        Arc, BTreeMap, Budget, BudgetRefusal, CancelReason, ChildName, ChildSpec,
        CompiledSupervisor, Duration, EscalationPolicy, NameRegistrationPolicy, Outcome, RegionId,
        RestartPolicy, RestartTracker, RestartVerdict, SpawnError, SupervisionConfig,
        SupervisorBuilder, SupervisorCompileError, TaskId, Time,
    };
    use crate::cx::{ChildRegion, ChildRegionError, ChildRegionSpec, Cx};
    use crate::runtime::{JoinError, TaskHandle};
    use crate::types::PanicPayload;
    use parking_lot::Mutex;
    use std::future::{Future, poll_fn};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::pin::Pin;
    use std::task::{Poll, Waker};

    const SCAN_QUANTUM: usize = 32;

    /// Restart eligibility for the executing managed entry point.
    ///
    /// Stopping the controller or cancelling its parent never restarts a child.
    /// A replacement batch may restart live collateral siblings according to
    /// these modes. These modes do not change the legacy
    /// Err-only [`super::SupervisionStrategy`] planning functions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ManagedRestartMode {
        /// Restart any independently terminated generation, including success.
        Permanent,
        /// Restart application errors and panics; success and cancellation stop.
        Transient,
        /// Never replace this child, including collateral strategy shutdown.
        Temporary,
    }

    impl ManagedRestartMode {
        fn eligible<E>(self, completed: &ManagedChildCompletion<E>) -> bool {
            match self {
                Self::Permanent => true,
                Self::Transient => {
                    matches!(completed.outcome, Outcome::Panicked(_))
                        || matches!(completed.task_outcome, Err(JoinError::Panicked(_)))
                        || (completed.task_outcome.is_ok()
                            && matches!(completed.outcome, Outcome::Err(_)))
                }
                Self::Temporary => false,
            }
        }
    }

    /// Identity of one actually admitted child generation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ManagedGeneration {
        /// Monotone per-child generation, starting at one.
        pub number: u64,
        /// Region exclusively owning this generation and its descendants.
        pub region: RegionId,
        /// Canonical task ID, including its arena generation.
        pub task: TaskId,
    }

    /// A managed factory's owned asynchronous body.
    pub type ManagedChildFuture<E> = Pin<Box<dyn Future<Output = Outcome<(), E>> + Send + 'static>>;

    /// Retained factory invoked inside each real, region-owned child task.
    ///
    /// Invocation never holds RuntimeState or a supervisor lock. Its returned
    /// future need not be Sync. A new invocation cannot overlap an old
    /// generation's task or region finalizers.
    pub trait ManagedChildFactory<E>: Send + Sync + 'static {
        /// Construct one generation using its registered task authority.
        fn start(&self, cx: Cx, generation: ManagedGeneration) -> ManagedChildFuture<E>;
    }

    impl<E, F, Fut> ManagedChildFactory<E> for F
    where
        F: Fn(Cx, ManagedGeneration) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Outcome<(), E>> + Send + 'static,
    {
        fn start(&self, cx: Cx, generation: ManagedGeneration) -> ManagedChildFuture<E> {
            Box::pin(self(cx, generation))
        }
    }

    /// Binds a compiled child name to the additive managed factory contract.
    pub struct ManagedChildBinding<E> {
        name: ChildName,
        mode: ManagedRestartMode,
        factory: Arc<dyn ManagedChildFactory<E>>,
    }

    impl<E> std::fmt::Debug for ManagedChildBinding<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ManagedChildBinding")
                .field("name", &self.name)
                .field("mode", &self.mode)
                .finish_non_exhaustive()
        }
    }

    impl<E> ManagedChildBinding<E> {
        /// Retain a factory and its explicit managed restart mode.
        #[must_use]
        pub fn new(
            name: impl Into<ChildName>,
            mode: ManagedRestartMode,
            factory: impl ManagedChildFactory<E>,
        ) -> Self {
            Self {
                name: name.into(),
                mode,
                factory: Arc::new(factory),
            }
        }
    }

    /// Invalid binding or mutated public compiled topology.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ManagedSupervisorBindError {
        /// A compiled topology no longer passes its original validation.
        Topology(SupervisorCompileError),
        /// Public start_order was not the compiled topological order.
        StartOrder,
        /// A managed binding occurred twice.
        Duplicate(ChildName),
        /// A binding names no compiled child.
        Unknown(ChildName),
        /// A compiled child has no managed factory.
        Missing(ChildName),
        /// The two explicit supervisor strategies disagree.
        RestartPolicyMismatch,
        /// Registration requires the registry-owned implementation, not a no-op.
        UnsupportedRegistration(ChildName),
        /// The optional restart storm threshold is invalid.
        InvalidStormThreshold,
    }

    /// Infrastructure or policy reason for stopping the managed controller.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ManagedSupervisorError {
        /// Child-region admission or close failed.
        Region(ChildRegionError),
        /// The actual spawn gateway refused a task.
        Spawn(SpawnError),
        /// A returned task handle terminated before the managed factory ran.
        ChildNotStarted {
            /// Child whose admission/start failed.
            child: ChildName,
            /// Full terminal identity, including the failed generation.
            generation: ManagedGeneration,
            /// Runtime terminal reason, without inventing a domain error.
            outcome: Outcome<(), ()>,
        },
        /// A required child's dependency is unavailable.
        DependencyUnavailable {
            child: ChildName,
            dependency: ChildName,
        },
        /// Shared restart intensity refused another replacement batch.
        RestartLimit {
            child: ChildName,
            refusal: BudgetRefusal,
        },
        /// No representable successor generation remains.
        GenerationExhausted(ChildName),
        /// The old generation reached quiescence with unsuccessful cleanup.
        Cleanup {
            /// Child whose cleanup failed.
            child: ChildName,
            /// Actual retired generation.
            generation: ManagedGeneration,
            /// Explicit finalizer outcome, distinct from ordinary cancellation.
            outcome: crate::record::task::TaskOutcome,
        },
        /// The supervisor region itself reached quiescence with failed cleanup.
        SupervisorCleanup(crate::record::task::TaskOutcome),
        /// Parent escalation could not be enqueued to a live runtime.
        Escalation(SpawnError),
    }

    /// The last completed generation of a child, retained without E: Clone.
    #[derive(Debug)]
    pub struct ManagedChildCompletion<E> {
        /// Compiled child identity.
        pub name: ChildName,
        /// Exact generation that produced this result.
        pub generation: ManagedGeneration,
        /// User result, read only after the actual task terminal was joined.
        /// This raw return does not imply task success: cancellation may
        /// dominate it in the separately retained `task_outcome`.
        pub outcome: Outcome<(), E>,
        /// Actual classified TaskHandle terminal, including cancellation that
        /// dominated a cancellation-blind or unacknowledged user return.
        pub task_outcome: Result<(), JoinError>,
        /// Whether controller shutdown won the publication lock before this
        /// generation published its typed terminal. Used for collateral
        /// restart eligibility; later cancellation cannot rewrite this fact.
        pub shutdown_requested_before_completion: bool,
        /// User-return time, or join-observation time for a runtime panic/cancel.
        pub completed_at: Time,
        /// Canonical region outcome after actual quiescence, including the
        /// region's ordinary shutdown cancellation. None means close failed.
        pub region_outcome: Option<crate::record::task::TaskOutcome>,
        /// Explicit cleanup outcome, separate from ordinary child cancellation.
        /// A failed cleanup forbids replacement even when the region is closed.
        pub cleanup_outcome: Option<crate::record::task::TaskOutcome>,
    }

    /// Terminal controller receipt, available only after all owned regions close.
    #[derive(Debug)]
    pub struct ManagedSupervisorReport<E> {
        /// Supervisor name.
        pub name: ChildName,
        /// Supervisor child region, if admission succeeded.
        pub region: Option<RegionId>,
        /// Canonical supervisor-region outcome after quiescence.
        pub region_outcome: Option<crate::record::task::TaskOutcome>,
        /// Explicit supervisor-region cleanup outcome, when recorded.
        pub cleanup_outcome: Option<crate::record::task::TaskOutcome>,
        /// Controller stop reason. Child domain errors remain in `children`.
        /// Cancellation before successful close/report publication changes Ok
        /// to Cancelled; an explicit infrastructure/cleanup error or panic is
        /// retained. Cancellation after publication cannot rewrite the report.
        pub outcome: Outcome<(), ManagedSupervisorError>,
        /// Latest completed result per child, in compiled start order.
        ///
        /// Older generations are replaced only after their result is consumed
        /// by the controller; storage is bounded by the compiled child count.
        pub children: Vec<ManagedChildCompletion<E>>,
        /// Actual child tasks whose factory construction was attempted.
        pub started: u64,
        /// Actual child terminal joins, including cancellation before start.
        pub joined: u64,
        /// Replacement batches admitted by the shared restart tracker.
        pub restart_batches: u64,
        /// Successful parent-region escalation publications (zero or one).
        pub escalations: u8,
    }

    /// Retained factories and validated compiled supervisor metadata.
    pub struct ManagedSupervisor<E> {
        name: ChildName,
        budget: Option<Budget>,
        children: Vec<ChildSpec>,
        bindings: Vec<ManagedChildBinding<E>>,
        config: SupervisionConfig,
    }

    impl<E> std::fmt::Debug for ManagedSupervisor<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ManagedSupervisor")
                .field("name", &self.name)
                .field("children", &self.children.len())
                .field("config", &self.config)
                .finish_non_exhaustive()
        }
    }

    impl CompiledSupervisor {
        /// Bind retained managed factories without invoking legacy ChildStart.
        ///
        /// The compiled topology supplies names, order, dependencies, required/
        /// deferred flags, and shutdown budgets. The bindings supply restart
        /// modes; `config` supplies one shared intensity/backoff policy. Legacy
        /// per-child SupervisionStrategy remains exclusive to the old APIs.
        /// Registry-bearing specs are refused until an actual registry binding
        /// is supplied by a separate integration; they never silently register.
        pub fn bind_managed<E>(
            self,
            bindings: Vec<ManagedChildBinding<E>>,
            config: SupervisionConfig,
        ) -> Result<ManagedSupervisor<E>, ManagedSupervisorBindError> {
            if config.restart_policy != self.restart_policy {
                return Err(ManagedSupervisorBindError::RestartPolicyMismatch);
            }
            if config
                .storm_threshold
                .is_some_and(|n| !n.is_finite() || n <= 0.0)
            {
                return Err(ManagedSupervisorBindError::InvalidStormThreshold);
            }
            let supplied_order = self.start_order;
            let compiled = SupervisorBuilder {
                name: self.name,
                budget: self.budget,
                tie_break: self.tie_break,
                restart_policy: self.restart_policy,
                children: self.children,
            }
            .compile()
            .map_err(ManagedSupervisorBindError::Topology)?;
            if supplied_order != compiled.start_order {
                return Err(ManagedSupervisorBindError::StartOrder);
            }
            let mut by_name = BTreeMap::new();
            for binding in bindings {
                if !compiled.children.iter().any(|c| c.name == binding.name) {
                    return Err(ManagedSupervisorBindError::Unknown(binding.name));
                }
                let name = binding.name.clone();
                if by_name.insert(name.clone(), binding).is_some() {
                    return Err(ManagedSupervisorBindError::Duplicate(name));
                }
            }
            let mut children: Vec<_> = compiled.children.into_iter().map(Some).collect();
            let mut ordered = Vec::with_capacity(children.len());
            let mut factories = Vec::with_capacity(children.len());
            for index in compiled.start_order {
                let child = children[index]
                    .take()
                    .expect("validated unique start order");
                if !matches!(child.registration, NameRegistrationPolicy::None) {
                    return Err(ManagedSupervisorBindError::UnsupportedRegistration(
                        child.name,
                    ));
                }
                factories.push(
                    by_name
                        .remove(&child.name)
                        .ok_or_else(|| ManagedSupervisorBindError::Missing(child.name.clone()))?,
                );
                ordered.push(child);
            }
            Ok(ManagedSupervisor {
                name: compiled.name,
                budget: compiled.budget,
                children: ordered,
                bindings: factories,
                config,
            })
        }
    }

    struct ChildPublication<E> {
        started: bool,
        identity: Option<ManagedGeneration>,
        terminal: Option<(Time, Outcome<(), E>, bool)>,
        shutdown_requested: bool,
        waiter: Option<Waker>,
    }

    struct RunningChild<E> {
        number: u64,
        region: Option<ChildRegion>,
        handle: Option<TaskHandle<()>>,
        publication: Arc<Mutex<ChildPublication<E>>>,
        shutdown_budget: Budget,
        cancellation_sent: bool,
        start_observed: bool,
        terminal_observed: bool,
    }

    impl<E> RunningChild<E> {
        fn cancel(&mut self) -> Result<(), ChildRegionError> {
            if !self.cancellation_sent {
                self.cancellation_sent = true;
                // Share the terminal publication's lock: observation of a
                // TaskHandle alone cannot fence a concurrently returning child.
                self.publication.lock().shutdown_requested = true;
                if let Some(region) = &self.region {
                    let mut reason = CancelReason::with_origin(
                        crate::types::CancelKind::User,
                        region.region_id(),
                        region.cx().now(),
                    )
                    .with_message("managed supervisor generation drain");
                    if let Some(handle) = &self.handle {
                        reason = reason.with_task(handle.task_id());
                    }
                    region.cancel_with_budget(reason, self.shutdown_budget)?;
                }
            }
            Ok(())
        }
    }

    impl<E> Drop for RunningChild<E> {
        fn drop(&mut self) {
            let _ = self.cancel();
            if let Some(handle) = &self.handle {
                handle.abort();
            }
            // ChildRegion's Drop requests close. It cannot claim synchronous
            // quiescence; the enclosing runtime region remains the backstop.
        }
    }

    struct Controller<E> {
        supervisor: ManagedSupervisor<E>,
        cx: Cx,
        root: Option<ChildRegion>,
        running: Vec<Option<RunningChild<E>>>,
        latest: Vec<Option<ManagedChildCompletion<E>>>,
        numbers: Vec<u64>,
        ready: Vec<(usize, ManagedGeneration)>,
        cancel_waker: Option<crate::cx::cx::CancelWakerToken>,
        tracker: RestartTracker,
        report: ManagedSupervisorReport<E>,
    }

    fn panic_payload(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
        let message = crate::cx::scope::payload_to_string(&payload);
        std::mem::forget(payload);
        PanicPayload::new(message)
    }

    impl<E: Send + 'static> Controller<E> {
        fn new(supervisor: ManagedSupervisor<E>, cx: &Cx) -> Self {
            let count = supervisor.children.len();
            let tracker = supervisor.config.restart_tracker();
            let report = ManagedSupervisorReport {
                name: supervisor.name.clone(),
                region: None,
                region_outcome: None,
                cleanup_outcome: None,
                outcome: Outcome::Ok(()),
                children: Vec::new(),
                started: 0,
                joined: 0,
                restart_batches: 0,
                escalations: 0,
            };
            Self {
                supervisor,
                cx: cx.clone(),
                root: None,
                running: (0..count).map(|_| None).collect(),
                latest: (0..count).map(|_| None).collect(),
                numbers: vec![0; count],
                ready: Vec::new(),
                cancel_waker: None,
                tracker,
                report,
            }
        }

        fn cancelled(&self) -> bool {
            self.cx.checkpoint().is_err()
        }

        fn record_cancel(&mut self) {
            if !matches!(self.report.outcome, Outcome::Panicked(_)) {
                self.report.outcome = Outcome::Cancelled(
                    self.cx
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("managed supervisor cancelled")),
                );
            }
        }

        fn record_error(&mut self, error: ManagedSupervisorError) {
            let cleanup = match &error {
                ManagedSupervisorError::Cleanup { child, .. } => Some(
                    self.supervisor
                        .children
                        .iter()
                        .position(|spec| &spec.name == child),
                ),
                ManagedSupervisorError::SupervisorCleanup(_) => Some(None),
                _ => None,
            };
            let panic = match &error {
                ManagedSupervisorError::Cleanup {
                    outcome: Outcome::Panicked(payload),
                    ..
                }
                | ManagedSupervisorError::SupervisorCleanup(Outcome::Panicked(payload)) => {
                    Some(payload.clone())
                }
                _ => None,
            };
            if !matches!(self.report.outcome, Outcome::Panicked(_)) {
                self.report.outcome = panic.map_or_else(|| Outcome::Err(error), Outcome::Panicked);
            }
            if let Some(source) = cleanup {
                self.escalate(source);
            }
        }

        fn trace(&self, action: &str, index: usize, identity: ManagedGeneration) {
            if let Some(trace) = self.cx.trace_buffer() {
                let now = self.cx.now();
                let outcome = self.latest[index]
                    .as_ref()
                    .filter(|completed| completed.generation == identity)
                    .map_or("pending", |completed| match completed.outcome {
                        Outcome::Ok(()) => "ok",
                        Outcome::Err(_) => "err",
                        Outcome::Cancelled(_) => "cancelled",
                        Outcome::Panicked(_) => "panicked",
                    });
                let message = format!(
                    "managed_supervisor_v1 action={action} supervisor={:?} child={:?} generation={} region={:?} task={:?} outcome={outcome}",
                    self.supervisor.name,
                    self.supervisor.children[index].name,
                    identity.number,
                    identity.region,
                    identity.task,
                );
                trace.record_event(|seq| crate::trace::TraceEvent::user_trace(seq, now, &message));
            }
        }

        fn observe_start(&mut self, index: usize) {
            let Some(child) = self.running[index].as_mut() else {
                return;
            };
            let identity = {
                let publication = child.publication.lock();
                if child.start_observed || !publication.started {
                    return;
                }
                child.start_observed = true;
                publication
                    .identity
                    .expect("started generation has a canonical identity")
            };
            self.report.started += 1;
            self.trace("started", index, identity);
        }

        fn queue_terminal(&mut self, index: usize) {
            let identity = self.latest[index]
                .as_ref()
                .expect("joined terminal")
                .generation;
            self.ready.push((index, identity));
        }

        fn accepts_terminal(&self, index: usize, identity: ManagedGeneration) -> bool {
            self.running[index].as_ref().is_some_and(|child| {
                child.terminal_observed
                    && child.number == identity.number
                    && self.latest[index]
                        .as_ref()
                        .is_some_and(|completed| completed.generation == identity)
            })
        }

        fn joined(&mut self, index: usize, result: Result<(), JoinError>) {
            self.observe_start(index);
            let child = self.running[index]
                .as_mut()
                .expect("joined owned generation");
            child.terminal_observed = true;
            let handle = child.handle.take().expect("terminal is consumed once");
            let task_outcome = result.clone();
            let (identity, terminal, shutdown_requested) = {
                let mut publication = child.publication.lock();
                (
                    publication.identity.unwrap_or(ManagedGeneration {
                        number: child.number,
                        region: child.region.as_ref().expect("owned region").region_id(),
                        task: handle.task_id(),
                    }),
                    publication.terminal.take(),
                    publication.shutdown_requested,
                )
            };
            let (completed_at, outcome, shutdown_requested_before_completion) = match result {
                Err(JoinError::Panicked(payload)) => {
                    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(terminal))) {
                        std::mem::forget(secondary);
                    }
                    (
                        self.cx.now(),
                        Outcome::Panicked(payload),
                        shutdown_requested,
                    )
                }
                Err(JoinError::PolledAfterCompletion) => {
                    unreachable!("managed terminal consumed twice")
                }
                Ok(()) | Err(JoinError::Cancelled(_)) if terminal.is_some() => {
                    // A later region cancellation cannot rewrite a completed
                    // typed result, including an encoded Panicked outcome.
                    terminal.expect("checked terminal")
                }
                Err(JoinError::Cancelled(reason)) => (
                    self.cx.now(),
                    Outcome::Cancelled(reason),
                    shutdown_requested,
                ),
                Ok(()) => (
                    self.cx.now(),
                    Outcome::Panicked(PanicPayload::new(
                        "managed child returned without its terminal publication",
                    )),
                    shutdown_requested,
                ),
            };
            self.report.joined += 1;
            let previous = self.latest[index].replace(ManagedChildCompletion {
                name: self.supervisor.children[index].name.clone(),
                generation: identity,
                completed_at,
                outcome,
                task_outcome,
                shutdown_requested_before_completion,
                region_outcome: None,
                cleanup_outcome: None,
            });
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(previous))) {
                self.report.outcome = Outcome::Panicked(panic_payload(payload));
            }
            self.trace("terminal", index, identity);
        }

        async fn start(&mut self, index: usize) -> Result<(), ManagedSupervisorError> {
            if self.cancelled() {
                self.record_cancel();
                return Ok(());
            }
            let number = self.numbers[index].checked_add(1).ok_or_else(|| {
                ManagedSupervisorError::GenerationExhausted(
                    self.supervisor.children[index].name.clone(),
                )
            })?;
            let region = self
                .root
                .as_ref()
                .expect("admitted supervisor region")
                .cx()
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .map_err(ManagedSupervisorError::Region)?;
            if self.cancelled() {
                self.record_cancel();
                region
                    .close()
                    .await
                    .map_err(ManagedSupervisorError::Region)?;
                return Ok(());
            }
            let publication = Arc::new(Mutex::new(ChildPublication {
                started: false,
                identity: None,
                terminal: None,
                shutdown_requested: false,
                waiter: None,
            }));
            let child_publication = Arc::clone(&publication);
            let factory = Arc::clone(&self.supervisor.bindings[index].factory);
            let region_id = region.region_id();
            let handle = region
                .cx()
                .spawn(move |cx| async move {
                    let identity = ManagedGeneration {
                        number,
                        region: region_id,
                        task: cx.task_id(),
                    };
                    child_publication.lock().identity = Some(identity);
                    let constructed =
                        catch_unwind(AssertUnwindSafe(|| factory.start(cx.clone(), identity)));
                    let waiter = {
                        let mut publication = child_publication.lock();
                        publication.started = true;
                        publication.waiter.take()
                    };
                    if let Some(waiter) = waiter {
                        waiter.wake();
                    }
                    let outcome = match constructed {
                        Err(payload) => Outcome::Panicked(panic_payload(payload)),
                        Ok(future) => {
                            let mut execution =
                                Box::pin(crate::cx::scope::CatchUnwind { inner: future });
                            let returned = execution.as_mut().await;
                            let retired = catch_unwind(AssertUnwindSafe(|| drop(execution)));
                            match (returned, retired) {
                                (Err(payload), retirement) => {
                                    if let Err(secondary) = retirement {
                                        std::mem::forget(secondary);
                                    }
                                    Outcome::Panicked(panic_payload(payload))
                                }
                                (Ok(outcome), Err(payload)) => {
                                    if let Err(secondary) =
                                        catch_unwind(AssertUnwindSafe(|| drop(outcome)))
                                    {
                                        std::mem::forget(secondary);
                                    }
                                    Outcome::Panicked(panic_payload(payload))
                                }
                                (Ok(outcome), Ok(())) => outcome,
                            }
                        }
                    };
                    let completed_at = cx.now();
                    let mut publication = child_publication.lock();
                    let shutdown_requested = publication.shutdown_requested;
                    publication.terminal = Some((completed_at, outcome, shutdown_requested));
                })
                .map_err(ManagedSupervisorError::Spawn)?;
            self.numbers[index] = number;
            self.running[index] = Some(RunningChild {
                number,
                region: Some(region),
                handle: Some(handle),
                publication,
                shutdown_budget: self.supervisor.children[index].shutdown_budget,
                cancellation_sent: false,
                start_observed: false,
                terminal_observed: false,
            });
            // Start means actual factory construction, not a provisional
            // mailbox TaskId. A panic/admission denial also wakes via join.
            poll_fn(|poll_cx| {
                self.cancel_waker = Some(
                    self.cx
                        .refresh_cancel_waker(self.cancel_waker, poll_cx.waker()),
                );
                if self.cancelled() {
                    self.record_cancel();
                    return Poll::Ready(());
                }
                let child = self.running[index].as_mut().expect("owned child");
                if let Poll::Ready(result) = child
                    .handle
                    .as_mut()
                    .expect("unjoined child")
                    .poll_join(poll_cx)
                {
                    self.joined(index, result);
                    self.queue_terminal(index);
                    return Poll::Ready(());
                }
                let waiter = poll_cx.waker().clone();
                let (started, old) = {
                    let mut publication = child.publication.lock();
                    (publication.started, publication.waiter.replace(waiter))
                };
                drop(old);
                if started {
                    self.observe_start(index);
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            if self.running[index]
                .as_ref()
                .is_some_and(|child| child.terminal_observed && !child.start_observed)
            {
                let completed = self.latest[index]
                    .as_ref()
                    .expect("observed unstarted terminal");
                let outcome = match &completed.outcome {
                    Outcome::Ok(()) => Outcome::Ok(()),
                    Outcome::Err(_) => Outcome::Err(()),
                    Outcome::Cancelled(reason) => Outcome::Cancelled(reason.clone()),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload.clone()),
                };
                return Err(ManagedSupervisorError::ChildNotStarted {
                    child: completed.name.clone(),
                    generation: completed.generation,
                    outcome,
                });
            }
            Ok(())
        }

        async fn drain(&mut self, index: usize) -> Result<(), ManagedSupervisorError> {
            if self.running[index].is_none() {
                return Ok(());
            }
            self.running[index]
                .as_mut()
                .expect("owned child")
                .cancel()
                .map_err(ManagedSupervisorError::Region)?;
            if self.running[index]
                .as_ref()
                .expect("owned child")
                .handle
                .is_some()
            {
                let result = poll_fn(|cx| {
                    self.running[index]
                        .as_mut()
                        .expect("owned child")
                        .handle
                        .as_mut()
                        .expect("unjoined child")
                        .poll_join(cx)
                })
                .await;
                self.joined(index, result);
            }
            let mut child = self.running[index].take().expect("owned child");
            let region = child.region.take().expect("owned region");
            let receipt = region
                .close_with_outcome()
                .await
                .map_err(ManagedSupervisorError::Region)?;
            let completed = self.latest[index]
                .as_mut()
                .expect("joined generation before close");
            completed.region_outcome = Some(receipt.outcome);
            completed.cleanup_outcome = receipt.cleanup_outcome;
            let identity = completed.generation;
            let failure = completed
                .cleanup_outcome
                .as_ref()
                .filter(|outcome| !outcome.is_ok())
                .map(|outcome| ManagedSupervisorError::Cleanup {
                    child: completed.name.clone(),
                    generation: identity,
                    outcome: outcome.clone(),
                });
            self.trace("drained", index, identity);
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(())
        }

        fn cancel_children(&mut self, indices: impl Iterator<Item = usize>) -> bool {
            let mut accepted = true;
            for index in indices {
                if let Some(child) = self.running[index].as_mut() {
                    if let Err(error) = child.cancel() {
                        accepted = false;
                        self.record_error(ManagedSupervisorError::Region(error));
                    }
                }
            }
            accepted
        }

        fn dependency_unavailable(&self, index: usize) -> Option<ChildName> {
            self.supervisor.children[index]
                .depends_on
                .iter()
                .find(|name| {
                    let dependency = self
                        .supervisor
                        .children
                        .iter()
                        .position(|child| &child.name == *name)
                        .expect("validated dependency");
                    self.running[dependency].is_none()
                })
                .cloned()
        }

        async fn wait_exit(&mut self) -> Option<usize> {
            let mut cursor: usize = 0;
            poll_fn(|poll_cx| {
                self.cancel_waker = Some(
                    self.cx
                        .refresh_cancel_waker(self.cancel_waker, poll_cx.waker()),
                );
                if self.cancelled() {
                    self.record_cancel();
                    return Poll::Ready(None);
                }
                if !matches!(self.report.outcome, Outcome::Ok(())) {
                    return Poll::Ready(None);
                }
                let end = cursor.saturating_add(SCAN_QUANTUM).min(self.running.len());
                while cursor < end {
                    let index = cursor;
                    cursor += 1;
                    if let Some(child) = self.running[index].as_mut() {
                        if let Some(handle) = &mut child.handle {
                            if let Poll::Ready(result) = handle.poll_join(poll_cx) {
                                self.joined(index, result);
                                self.queue_terminal(index);
                            }
                        }
                    }
                }
                if cursor < self.running.len() {
                    poll_cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                cursor = 0;
                if !matches!(self.report.outcome, Outcome::Ok(())) {
                    return Poll::Ready(None);
                }
                let ready = std::mem::take(&mut self.ready);
                self.ready = ready
                    .into_iter()
                    .filter(|&(index, identity)| self.accepts_terminal(index, identity))
                    .collect();
                self.ready.sort_by_key(|&(index, _)| {
                    let completed = self.latest[index].as_ref().expect("current terminal");
                    (completed.completed_at, completed.generation.task)
                });
                if !self.ready.is_empty() {
                    return Poll::Ready(Some(self.ready.remove(0).0));
                }
                if self.running.iter().all(Option::is_none) {
                    Poll::Ready(None)
                } else {
                    Poll::Pending
                }
            })
            .await
        }

        async fn backoff(&mut self, delay: Option<Duration>) -> bool {
            if self.cancelled() {
                self.record_cancel();
                return false;
            }
            if let Some(delay) = delay.filter(|delay| !delay.is_zero()) {
                let mut sleep = Box::pin(crate::time::sleep(self.cx.now(), delay));
                let completed = poll_fn(|poll_cx| {
                    self.cancel_waker = Some(
                        self.cx
                            .refresh_cancel_waker(self.cancel_waker, poll_cx.waker()),
                    );
                    if self.cancelled() {
                        self.record_cancel();
                        return Poll::Ready(false);
                    }
                    sleep.as_mut().poll(poll_cx).map(|()| true)
                })
                .await;
                if !completed {
                    return false;
                }
            }
            if self.cancelled() {
                self.record_cancel();
                false
            } else {
                true
            }
        }

        fn escalate(&mut self, source: Option<usize>) {
            if self.report.escalations != 0 {
                return;
            }
            let identity = source.map_or(
                ManagedGeneration {
                    number: 0,
                    region: self.report.region.unwrap_or(self.cx.region_id()),
                    task: self.cx.task_id(),
                },
                |index| {
                    self.latest[index]
                        .as_ref()
                        .expect("escalating an observed terminal")
                        .generation
                },
            );
            let reason = CancelReason::with_origin(
                crate::types::CancelKind::FailFast,
                identity.region,
                self.cx.now(),
            )
            .with_task(identity.task)
            .with_message("managed supervisor restart intensity exhausted");
            let result = self
                .cx
                .spawn_gateway_handle()
                .ok_or(SpawnError::RuntimeUnavailable)
                .and_then(|gateway| {
                    gateway.enqueue_region_command(
                        crate::runtime::spawn_mailbox::RegionCommand::Cancel {
                            region_id: self.cx.region_id(),
                            reason,
                        },
                    )
                });
            match result {
                Ok(()) => {
                    self.report.escalations = 1;
                    if let Some(index) = source {
                        self.trace("parent_escalated", index, identity);
                    }
                }
                Err(error) => {
                    self.report.outcome = Outcome::Err(ManagedSupervisorError::Escalation(error))
                }
            }
        }

        async fn execute(&mut self) {
            if self.cancelled() {
                self.record_cancel();
                return;
            }
            let mut spec = ChildRegionSpec::inherit();
            spec.budget = self.supervisor.budget;
            match self.cx.open_child_region(spec).await {
                Ok(region) => {
                    self.report.region = Some(region.region_id());
                    self.root = Some(region);
                }
                Err(error) => {
                    self.report.outcome = Outcome::Err(ManagedSupervisorError::Region(error));
                    return;
                }
            }
            for index in 0..self.running.len() {
                if self.cancelled() {
                    self.record_cancel();
                    return;
                }
                if !self.supervisor.children[index].start_immediately {
                    continue;
                }
                if let Some(dependency) = self.dependency_unavailable(index) {
                    if self.supervisor.children[index].required {
                        self.report.outcome =
                            Outcome::Err(ManagedSupervisorError::DependencyUnavailable {
                                child: self.supervisor.children[index].name.clone(),
                                dependency,
                            });
                        return;
                    }
                    continue;
                }
                if let Err(error) = self.start(index).await {
                    if self.supervisor.children[index].required {
                        self.record_error(error);
                        return;
                    } else if let Err(cleanup) = self.drain(index).await {
                        self.record_error(cleanup);
                        return;
                    }
                }
                if !matches!(self.report.outcome, Outcome::Ok(())) {
                    return;
                }
            }
            while let Some(failed) = self.wait_exit().await {
                let eligible = self.supervisor.bindings[failed]
                    .mode
                    .eligible(self.latest[failed].as_ref().expect("joined terminal"));
                if !eligible {
                    if let Err(error) = self.drain(failed).await {
                        self.record_error(error);
                        return;
                    }
                    continue;
                }
                let now = self.cx.now().as_nanos();
                let mut verdict = self.tracker.evaluate_with_budget(now, &self.cx.budget());
                if matches!(verdict, RestartVerdict::Denied { .. })
                    && self.supervisor.config.escalation == EscalationPolicy::ResetCounter
                {
                    self.tracker.reset();
                    verdict = self.tracker.evaluate_with_budget(now, &self.cx.budget());
                }
                let delay = match verdict {
                    RestartVerdict::Allowed { delay, .. } => delay,
                    RestartVerdict::Denied { refusal } => {
                        if self.supervisor.config.escalation == EscalationPolicy::Stop {
                            if let Err(error) = self.drain(failed).await {
                                self.record_error(error);
                                return;
                            }
                            continue;
                        }
                        self.report.outcome = Outcome::Err(ManagedSupervisorError::RestartLimit {
                            child: self.supervisor.children[failed].name.clone(),
                            refusal,
                        });
                        if self.supervisor.config.escalation == EscalationPolicy::Escalate {
                            self.escalate(Some(failed));
                        }
                        return;
                    }
                };
                let affected: Vec<_> = (0..self.running.len())
                    .filter(|&index| {
                        self.running[index].is_some()
                            && match self.supervisor.config.restart_policy {
                                RestartPolicy::OneForOne => index == failed,
                                RestartPolicy::OneForAll => true,
                                RestartPolicy::RestForOne => index >= failed,
                            }
                    })
                    .collect();
                // Publish cancellation to every affected sibling before any
                // join: one child's asynchronous cleanup may require another
                // sibling to observe cancellation before it can finish.
                let cancelled = self.cancel_children(affected.iter().rev().copied());
                let mut drained = true;
                for &index in affected.iter().rev() {
                    if let Err(error) = self.drain(index).await {
                        self.record_error(error);
                        drained = false;
                    }
                }
                if !cancelled || !drained {
                    return;
                }
                // An already completed but unobserved normal transient child
                // must stay stopped. Derive eligibility only after real joins
                // using the atomic shutdown-versus-terminal ordering.
                let restart: Vec<_> = affected
                    .iter()
                    .copied()
                    .filter(|&index| {
                        let mode = self.supervisor.bindings[index].mode;
                        let completed = self.latest[index].as_ref().expect("drained generation");
                        mode != ManagedRestartMode::Temporary
                            && (completed.shutdown_requested_before_completion
                                || mode.eligible(completed))
                    })
                    .collect();
                if !self.backoff(delay).await {
                    return;
                }
                let mut counted = false;
                for index in restart {
                    if self.dependency_unavailable(index).is_some() {
                        continue;
                    }
                    if self.cancelled() {
                        self.record_cancel();
                        return;
                    }
                    if !counted {
                        self.tracker.record(self.cx.now().as_nanos());
                        self.report.restart_batches += 1;
                        counted = true;
                    }
                    if let Err(error) = self.start(index).await {
                        if self.supervisor.children[index].required {
                            self.record_error(error);
                            return;
                        } else if let Err(cleanup) = self.drain(index).await {
                            self.record_error(cleanup);
                            return;
                        }
                    }
                    if !matches!(self.report.outcome, Outcome::Ok(())) {
                        return;
                    }
                }
            }
        }

        async fn finish(&mut self) {
            self.cancel_children((0..self.running.len()).rev());
            for index in (0..self.running.len()).rev() {
                if let Err(error) = self.drain(index).await {
                    self.record_error(error);
                }
            }
            if let Some(region) = self.root.take() {
                match region.close_with_outcome().await {
                    Err(error) => self.record_error(ManagedSupervisorError::Region(error)),
                    Ok(receipt) => {
                        self.report.region_outcome = Some(receipt.outcome);
                        self.report.cleanup_outcome = receipt.cleanup_outcome;
                        let failure = self
                            .report
                            .cleanup_outcome
                            .as_ref()
                            .filter(|outcome| !outcome.is_ok())
                            .cloned();
                        if let Some(outcome) = failure {
                            self.record_error(ManagedSupervisorError::SupervisorCleanup(outcome));
                        }
                    }
                }
            }
            // The root's own finalizers can suspend after execute() has
            // finished all child generations. Cancellation during that close
            // precedes report publication, rather than being a late request
            // against an already completed report. Observe it once here;
            // preserve an explicit failure already diagnosed while draining.
            if matches!(self.report.outcome, Outcome::Ok(())) && self.cancelled() {
                self.record_cancel();
            }
            if let Some(token) = self.cancel_waker.take() {
                self.cx.clear_cancel_waker(token);
            }
            self.report
                .children
                .extend(self.latest.iter_mut().filter_map(Option::take));
        }
    }

    impl<E> Drop for Controller<E> {
        fn drop(&mut self) {
            if let Some(token) = self.cancel_waker.take() {
                self.cx.clear_cancel_waker(token);
            }
            for child in self.running.iter_mut().rev().flatten() {
                let _ = child.cancel();
            }
        }
    }

    /// Owned actual controller task, located outside every region it drains.
    pub struct ManagedSupervisorHandle<E> {
        task: TaskHandle<()>,
        report: Arc<Mutex<Option<ManagedSupervisorReport<E>>>>,
    }

    impl<E> std::fmt::Debug for ManagedSupervisorHandle<E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ManagedSupervisorHandle")
                .field("task", &self.task.task_id())
                .finish_non_exhaustive()
        }
    }

    impl<E> ManagedSupervisorHandle<E> {
        /// Canonical controller task ID after admission.
        #[must_use]
        pub fn task_id(&self) -> TaskId {
            self.task.task_id()
        }

        /// Request controller cancellation; joining still waits for child drain.
        pub fn abort(&self) {
            self.task.abort();
        }

        /// Await the actual controller terminal without cancellation shortcuts.
        /// A completed report survives a later controller cancellation.
        pub async fn join(&mut self) -> Result<ManagedSupervisorReport<E>, JoinError> {
            let terminal = poll_fn(|cx| self.task.poll_join(cx)).await;
            if let Some(mut report) = self.report.lock().take() {
                if let Err(JoinError::Panicked(payload)) = terminal {
                    report.outcome = Outcome::Panicked(payload);
                }
                return Ok(report);
            }
            match terminal {
                Err(error) => Err(error),
                Ok(()) => Err(JoinError::Panicked(PanicPayload::new(
                    "managed controller omitted its report",
                ))),
            }
        }
    }

    impl<E> Drop for ManagedSupervisorHandle<E> {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl<E: Send + 'static> ManagedSupervisor<E> {
        /// Run the controller in this task, outside its new supervisor region.
        ///
        /// Each replacement waits for the preceding actual task terminal and
        /// region quiescence (including finalizers). Cancellation during start
        /// or backoff stops admission and drains all generations. Dropping this
        /// future requests cancellation/close; it cannot synchronously drain.
        pub async fn run(self, cx: &Cx) -> ManagedSupervisorReport<E> {
            let mut controller = Controller::new(self, cx);
            controller.execute().await;
            controller.finish().await;
            let empty = ManagedSupervisorReport {
                name: controller.report.name.clone(),
                region: controller.report.region,
                region_outcome: None,
                cleanup_outcome: None,
                outcome: Outcome::Ok(()),
                children: Vec::new(),
                started: 0,
                joined: 0,
                restart_batches: 0,
                escalations: 0,
            };
            std::mem::replace(&mut controller.report, empty)
        }

        /// Spawn a retained controller in the caller's current parent region.
        /// The returned handle owns cancellation; all child work lives below a
        /// distinct supervisor region, never around the controller itself.
        pub fn spawn(self, cx: &Cx) -> Result<ManagedSupervisorHandle<E>, SpawnError> {
            let report = Arc::new(Mutex::new(None));
            let publication = Arc::clone(&report);
            let task = cx.spawn(move |controller_cx| async move {
                let result = self.run(&controller_cx).await;
                *publication.lock() = Some(result);
            })?;
            Ok(ManagedSupervisorHandle { task, report })
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]
        use super::super::{BackoffStrategy, NameCollisionPolicy, RuntimeState};
        use super::*;
        use crate::channel::{mpsc, oneshot};
        use crate::lab::{LabConfig, LabRuntime};
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn legacy_must_not_run(
            _: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _: &mut RuntimeState,
            _: &Cx,
        ) -> Result<TaskId, SpawnError> {
            panic!("managed binding must not invoke a consumed legacy ChildStart")
        }

        fn forbidden_generation(
            _: Cx,
            _: ManagedGeneration,
        ) -> std::future::Ready<Outcome<(), ()>> {
            panic!("second child must never be started after parent cancellation")
        }

        fn topology(names: &[&str], policy: RestartPolicy) -> CompiledSupervisor {
            let mut builder = SupervisorBuilder::new("managed-test").with_restart_policy(policy);
            for name in names {
                builder = builder.child(
                    ChildSpec::new(*name, legacy_must_not_run)
                        .with_shutdown_budget(Budget::new().with_poll_quota(17)),
                );
            }
            builder.compile().unwrap()
        }

        fn config(policy: RestartPolicy, restarts: u32) -> SupervisionConfig {
            SupervisionConfig::new(restarts, Duration::from_secs(60))
                .with_restart_policy(policy)
                .with_backoff(BackoffStrategy::None)
        }

        fn clean(lab: &mut LabRuntime, root: RegionId) {
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            if lab.state.region(root).is_some() {
                let (tasks, wakes) = lab
                    .state
                    .cancel_request(root, &CancelReason::user("managed test finished"), None)
                    .into_parts();
                assert!(tasks.is_empty());
                wakes.dispatch();
                lab.state.advance_region_state(root);
            }
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        }

        fn run_case<F, Fut, T>(factory: F) -> T
        where
            F: FnOnce(Cx) -> Fut + Send + 'static,
            Fut: Future<Output = T> + Send + 'static,
            T: Send + 'static,
        {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_0001).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    factory(Cx::current().expect("registered managed controller")).await
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            lab.run_until_idle();
            let result = join
                .try_join()
                .unwrap()
                .expect("actual managed controller finished");
            clean(&mut lab, root);
            result
        }

        #[test]
        fn managed_real_generations_cover_all_restart_modes_and_outcomes() {
            for mode in [
                ManagedRestartMode::Permanent,
                ManagedRestartMode::Transient,
                ManagedRestartMode::Temporary,
            ] {
                for first in 0..6 {
                    let report = run_case(move |cx| async move {
                        let binding = ManagedChildBinding::new(
                            "child",
                            mode,
                            move |_child: Cx, generation: ManagedGeneration| {
                                if first == 4 && generation.number == 1 {
                                    panic!("actual factory panic");
                                }
                                async move {
                                    if generation.number > 1 {
                                        return Outcome::Ok(());
                                    }
                                    match first {
                                        0 => Outcome::Ok(()),
                                        1 => Outcome::Err(String::from("domain failure")),
                                        2 => Outcome::Cancelled(CancelReason::user(
                                            "child finished cancelled",
                                        )),
                                        3 => Outcome::Panicked(PanicPayload::new("encoded panic")),
                                        5 => panic!("actual child future poll panic"),
                                        _ => unreachable!(),
                                    }
                                }
                            },
                        );
                        let managed = topology(&["child"], RestartPolicy::OneForOne)
                            .bind_managed(vec![binding], config(RestartPolicy::OneForOne, 1))
                            .unwrap();
                        let mut handle = managed.spawn(&cx).unwrap();
                        let report = handle.join().await.unwrap();
                        assert_ne!(handle.task_id(), report.children[0].generation.task);
                        report
                    });
                    let restarted = mode == ManagedRestartMode::Permanent
                        || (mode == ManagedRestartMode::Transient
                            && matches!(first, 1 | 3 | 4 | 5));
                    assert!(matches!(report.outcome, Outcome::Ok(())));
                    assert_eq!(report.started, 1 + u64::from(restarted));
                    assert_eq!(report.joined, report.started);
                    assert_eq!(report.restart_batches, u64::from(restarted));
                    assert_eq!(report.escalations, 0);
                    assert_eq!(report.children.len(), 1);
                    assert_eq!(report.children[0].generation.number, report.started);
                    if restarted || first == 0 {
                        assert!(report.children[0].outcome.is_ok());
                    } else if first == 1 {
                        assert!(
                            matches!(&report.children[0].outcome, Outcome::Err(error) if error == "domain failure")
                        );
                    } else if first == 2 {
                        assert!(report.children[0].outcome.is_cancelled());
                    } else {
                        assert!(report.children[0].outcome.is_panicked());
                    }
                }
            }
        }

        #[test]
        fn managed_empty_topology_and_send_only_error_need_no_fake_child() {
            let report = run_case(|cx| async move {
                let managed = topology(&[], RestartPolicy::OneForOne)
                    .bind_managed(
                        Vec::<ManagedChildBinding<std::cell::Cell<u8>>>::new(),
                        config(RestartPolicy::OneForOne, 1),
                    )
                    .unwrap();
                managed.run(&cx).await
            });
            assert!(report.outcome.is_ok());
            assert_eq!(report.started, 0);
            assert_eq!(report.joined, 0);
            assert!(report.region.is_some());
            assert!(report.children.is_empty());
        }

        type StartedLog = Arc<Mutex<Vec<(String, ManagedGeneration, mpsc::Sender<()>)>>>;

        fn parked_binding(
            name: &'static str,
            log: StartedLog,
        ) -> ManagedChildBinding<&'static str> {
            ManagedChildBinding::new(
                name,
                ManagedRestartMode::Transient,
                move |cx: Cx, generation| {
                    let (sender, mut receiver) = mpsc::channel(1);
                    log.lock().push((name.to_string(), generation, sender));
                    async move {
                        match receiver.recv(&cx).await {
                            Ok(()) => Outcome::Err("triggered child failure"),
                            Err(_) => Outcome::Cancelled(
                                cx.cancel_reason().expect("real region cancellation"),
                            ),
                        }
                    }
                },
            )
        }

        #[test]
        fn managed_three_strategies_drain_actual_finalizers_before_replacement() {
            for policy in [
                RestartPolicy::OneForOne,
                RestartPolicy::OneForAll,
                RestartPolicy::RestForOne,
            ] {
                let mut lab = LabRuntime::new(LabConfig::new(0x34_0002).max_steps(8192));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let log: StartedLog = Arc::new(Mutex::new(Vec::new()));
                let bindings = ["a", "b", "c"]
                    .into_iter()
                    .map(|name| parked_binding(name, Arc::clone(&log)))
                    .collect();
                let managed = topology(&["a", "b", "c"], policy)
                    .bind_managed(bindings, config(policy, 4))
                    .unwrap();
                let result = Arc::new(Mutex::new(None));
                let publication = Arc::clone(&result);
                let (parent, mut join) = lab
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        let cx = Cx::current().unwrap();
                        *publication.lock() = Some(managed.run(&cx).await);
                    })
                    .unwrap();
                let parent_cx = lab.state.task(parent).unwrap().cx.clone().unwrap();
                lab.scheduler.lock().schedule(parent, 0);
                lab.run_until_idle();
                assert_eq!(
                    log.lock()
                        .iter()
                        .map(|entry| entry.0.as_str())
                        .collect::<Vec<_>>(),
                    ["a", "b", "c"]
                );
                let old_b = log.lock()[1].1;
                let (release, mut wait) = oneshot::channel();
                let finalizer_polled = Arc::new(AtomicUsize::new(0));
                let finalizer_done = Arc::new(AtomicUsize::new(0));
                let polled = Arc::clone(&finalizer_polled);
                let done = Arc::clone(&finalizer_done);
                assert!(
                    lab.state
                        .register_async_finalizer(old_b.region, async move {
                            polled.fetch_add(1, Ordering::SeqCst);
                            wait.recv_uninterruptible().await.unwrap();
                            done.fetch_add(1, Ordering::SeqCst);
                        })
                );
                log.lock()[1].2.try_send(()).unwrap();
                lab.run_until_idle();
                assert_eq!(finalizer_polled.load(Ordering::SeqCst), 1);
                assert_eq!(finalizer_done.load(Ordering::SeqCst), 0);
                assert_eq!(
                    log.lock().len(),
                    3,
                    "replacement cannot start while an old region finalizer is Pending"
                );
                assert!(result.lock().is_none());
                assert!(join.try_join().unwrap().is_none());
                release.send(&parent_cx, ()).unwrap();
                lab.run_until_idle();
                let names: Vec<_> = log
                    .lock()
                    .iter()
                    .skip(3)
                    .map(|entry| entry.0.clone())
                    .collect();
                let expected: &[&str] = match policy {
                    RestartPolicy::OneForOne => &["b"],
                    RestartPolicy::OneForAll => &["a", "b", "c"],
                    RestartPolicy::RestForOne => &["b", "c"],
                };
                assert_eq!(names, expected);
                assert_eq!(finalizer_done.load(Ordering::SeqCst), 1);
                assert!(lab.state.region(old_b.region).is_none());
                for (_, replacement, _) in log.lock().iter().skip(3) {
                    assert_eq!(replacement.number, 2);
                    assert_ne!(replacement.region, old_b.region);
                    assert!(lab.state.task(replacement.task).is_some());
                }
                join.abort();
                lab.run_until_idle();
                assert!(matches!(join.try_join(), Err(JoinError::Cancelled(_))));
                let report = result
                    .lock()
                    .take()
                    .expect("cancelled controller drains then publishes report");
                assert!(report.outcome.is_cancelled());
                assert_eq!(report.restart_batches, 1);
                assert_eq!(report.started, (3 + expected.len()) as u64);
                assert_eq!(report.joined, report.started);
                assert_eq!(report.children.len(), 3);
                clean(&mut lab, root);
            }
        }

        #[test]
        fn managed_parent_cancellation_during_backoff_forbids_resurrection() {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_0003).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let started = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&started);
            let binding = ManagedChildBinding::new(
                "child",
                ManagedRestartMode::Permanent,
                move |_: Cx, _| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    async { Outcome::<(), ()>::Err(()) }
                },
            );
            let managed = topology(&["child"], RestartPolicy::OneForOne)
                .bind_managed(
                    vec![binding],
                    config(RestartPolicy::OneForOne, 4)
                        .with_backoff(BackoffStrategy::Fixed(Duration::from_secs(30))),
                )
                .unwrap();
            let result = Arc::new(Mutex::new(None));
            let publication = Arc::clone(&result);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    *publication.lock() = Some(managed.run(&Cx::current().unwrap()).await);
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(started.load(Ordering::SeqCst), 1);
            assert!(result.lock().is_none());
            assert!(join.try_join().unwrap().is_none());
            join.abort();
            lab.run_until_idle();
            assert!(matches!(join.try_join(), Err(JoinError::Cancelled(_))));
            let report = result.lock().take().unwrap();
            assert!(report.outcome.is_cancelled());
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert_eq!(started.load(Ordering::SeqCst), 1);
            assert!(matches!(report.children[0].outcome, Outcome::Err(())));
            clean(&mut lab, root);
        }

        #[test]
        fn managed_intensity_exhaustion_cancels_actual_parent_region_once() {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_0004).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (sender, mut receiver) = mpsc::channel::<()>(1);
            let cancelled_sibling = Arc::new(AtomicUsize::new(0));
            let witnessed = Arc::clone(&cancelled_sibling);
            let (sibling, mut sibling_join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    assert!(receiver.recv(&cx).await.is_err());
                    assert!(cx.cancel_reason().is_some());
                    witnessed.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            lab.scheduler.lock().schedule(sibling, 0);
            lab.run_until_idle();
            assert_eq!(sender.telemetry_snapshot(0).recv_waiter_count, 1);
            let bindings = ["a", "b"]
                .into_iter()
                .map(|name| {
                    ManagedChildBinding::new(
                        name,
                        ManagedRestartMode::Permanent,
                        |_: Cx, _| async { Outcome::<(), ()>::Err(()) },
                    )
                })
                .collect();
            let managed = topology(&["a", "b"], RestartPolicy::OneForOne)
                .bind_managed(
                    bindings,
                    config(RestartPolicy::OneForOne, 1).with_escalation(EscalationPolicy::Escalate),
                )
                .unwrap();
            let result = Arc::new(Mutex::new(None));
            let publication = Arc::clone(&result);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    *publication.lock() = Some(managed.run(&Cx::current().unwrap()).await);
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let report = result
                .lock()
                .take()
                .expect("parent escalation still drains controller children");
            assert!(matches!(
                report.outcome,
                Outcome::Err(ManagedSupervisorError::RestartLimit { .. })
            ));
            assert_eq!(report.escalations, 1);
            assert_eq!(
                report.restart_batches, 1,
                "two failing children share one allowance"
            );
            assert_eq!(report.started, 3);
            assert_eq!(report.joined, 3);
            assert_eq!(cancelled_sibling.load(Ordering::SeqCst), 1);
            assert_eq!(sender.telemetry_snapshot(0).recv_waiter_count, 0);
            assert!(matches!(
                sibling_join.try_join(),
                Err(JoinError::Cancelled(_))
            ));
            assert!(matches!(
                join.try_join(),
                Ok(Some(())) | Err(JoinError::Cancelled(_))
            ));
            let events = lab.state.trace_handle().snapshot();
            assert_eq!(events.iter().filter(|event| matches!(&event.data,
                crate::trace::TraceData::Message(message) if message.contains("action=parent_escalated"))).count(), 1);
            clean(&mut lab, root);
        }

        #[test]
        fn managed_old_generation_event_cannot_drain_a_live_replacement() {
            run_case(|cx| async move {
                let (sender, receiver) = mpsc::channel::<()>(1);
                let receiver = Arc::new(Mutex::new(Some(receiver)));
                let held = Arc::clone(&receiver);
                let binding = ManagedChildBinding::new(
                    "child",
                    ManagedRestartMode::Transient,
                    move |child: Cx, generation: ManagedGeneration| {
                        let receiver = (generation.number > 1).then(|| held.lock().take().unwrap());
                        async move {
                            let Some(mut receiver) = receiver else {
                                return Outcome::Err(());
                            };
                            assert!(receiver.recv(&child).await.is_err());
                            Outcome::Cancelled(child.cancel_reason().unwrap())
                        }
                    },
                );
                let managed = topology(&["child"], RestartPolicy::OneForOne)
                    .bind_managed(vec![binding], config(RestartPolicy::OneForOne, 2))
                    .unwrap();
                let mut controller = Controller::new(managed, &cx);
                controller.root = Some(
                    cx.open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap(),
                );
                controller.start(0).await.unwrap();
                assert_eq!(controller.wait_exit().await, Some(0));
                let old = controller.latest[0].as_ref().unwrap().generation;
                controller.drain(0).await.unwrap();
                controller.start(0).await.unwrap();
                controller.ready.push((0, old));
                assert!(!controller.accepts_terminal(0, old));
                let mut wait = Box::pin(controller.wait_exit());
                poll_fn(|poll_cx| {
                    assert!(wait.as_mut().poll(poll_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(wait);
                assert_eq!(
                    sender.telemetry_snapshot(0).recv_waiter_count,
                    1,
                    "stale event neither cancels nor consumes replacement"
                );
                assert_eq!(controller.running[0].as_ref().unwrap().number, 2);
                controller.finish().await;
                assert_eq!(controller.report.joined, 2);
                assert_eq!(controller.report.children[0].generation.number, 2);
                assert_eq!(sender.telemetry_snapshot(0).recv_waiter_count, 0);
            });
        }

        #[test]
        fn managed_binding_refuses_missing_duplicate_and_unimplemented_registration() {
            let binding = || {
                ManagedChildBinding::new("child", ManagedRestartMode::Temporary, |_: Cx, _| async {
                    Outcome::<(), ()>::Ok(())
                })
            };
            assert!(matches!(
                topology(&["child"], RestartPolicy::OneForOne).bind_managed(
                    Vec::<ManagedChildBinding<()>>::new(),
                    config(RestartPolicy::OneForOne, 1)
                ),
                Err(ManagedSupervisorBindError::Missing(_))
            ));
            assert!(matches!(
                topology(&["child"], RestartPolicy::OneForOne).bind_managed(
                    vec![binding(), binding()],
                    config(RestartPolicy::OneForOne, 1)
                ),
                Err(ManagedSupervisorBindError::Duplicate(_))
            ));
            let mut compiled = topology(&["child"], RestartPolicy::OneForOne);
            compiled.children[0].registration = NameRegistrationPolicy::Register {
                name: "actual-registry-required".to_string(),
                collision: NameCollisionPolicy::Fail,
            };
            assert!(matches!(
                compiled.bind_managed(vec![binding()], config(RestartPolicy::OneForOne, 1)),
                Err(ManagedSupervisorBindError::UnsupportedRegistration(_))
            ));
        }

        #[test]
        fn managed_cancellation_inside_factory_stops_next_start_and_joins_pending_cleanup() {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_0005).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let started = Arc::new(AtomicUsize::new(0));
            let cleanup_started = Arc::new(AtomicUsize::new(0));
            let cleanup_finished = Arc::new(AtomicUsize::new(0));
            let identity = Arc::new(Mutex::new(None));
            let (release, receiver) = oneshot::channel::<()>();
            let receiver = Arc::new(Mutex::new(Some(receiver)));
            let output = Arc::new(Mutex::new(None));
            let published = Arc::clone(&output);
            let factory_started = Arc::clone(&started);
            let child_entered = Arc::clone(&cleanup_started);
            let child_finished = Arc::clone(&cleanup_finished);
            let child_identity = Arc::clone(&identity);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let parent_cx = Cx::current().unwrap();
                    let cancel_parent = parent_cx.clone();
                    let first = ManagedChildBinding::new(
                        "a",
                        ManagedRestartMode::Permanent,
                        move |child: Cx, generation| {
                            factory_started.fetch_add(1, Ordering::SeqCst);
                            *child_identity.lock() = Some(generation);
                            let mut cleanup = receiver.lock().take().unwrap();
                            let entered = Arc::clone(&child_entered);
                            let finished = Arc::clone(&child_finished);
                            cancel_parent.cancel_with(
                                crate::types::CancelKind::User,
                                Some("cancel during actual start"),
                            );
                            async move {
                                let (_keep_sender, mut receiver) = mpsc::channel::<()>(1);
                                assert!(receiver.recv(&child).await.is_err());
                                entered.fetch_add(1, Ordering::SeqCst);
                                cleanup.recv_uninterruptible().await.unwrap();
                                finished.fetch_add(1, Ordering::SeqCst);
                                Outcome::<(), ()>::Cancelled(child.cancel_reason().unwrap())
                            }
                        },
                    );
                    let second = ManagedChildBinding::new(
                        "b",
                        ManagedRestartMode::Permanent,
                        forbidden_generation,
                    );
                    let managed = topology(&["a", "b"], RestartPolicy::OneForAll)
                        .bind_managed(vec![first, second], config(RestartPolicy::OneForAll, 4))
                        .unwrap();
                    *published.lock() = Some(managed.run(&parent_cx).await);
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_started.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 0);
            assert!(
                output.lock().is_none(),
                "controller must retain its actual Pending child"
            );
            assert!(join.try_join().unwrap().is_none());
            let generation = identity.lock().unwrap();
            let task = lab
                .state
                .task(generation.task)
                .expect("cleanup child remains runtime-owned");
            let cleanup_budget = task
                .cleanup_budget()
                .expect("real cancellation state installed");
            assert!(
                cleanup_budget.poll_quota <= 17,
                "compiled budget must constrain the actual task, got {cleanup_budget:?}"
            );
            release.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert!(matches!(join.try_join(), Err(JoinError::Cancelled(_))));
            let report = output
                .lock()
                .take()
                .expect("drained cancelled controller report");
            assert!(report.outcome.is_cancelled());
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert_eq!(cleanup_finished.load(Ordering::SeqCst), 1);
            assert!(lab.state.region(generation.region).is_none());
            clean(&mut lab, root);
        }

        #[test]
        fn managed_one_for_all_does_not_resurrect_completed_transient_or_temporary_children() {
            let starts = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&starts);
            let report = run_case(move |cx| async move {
                let mut bindings = Vec::new();
                for (name, mode) in [
                    ("a", ManagedRestartMode::Transient),
                    ("b", ManagedRestartMode::Transient),
                    ("c", ManagedRestartMode::Temporary),
                ] {
                    let log = Arc::clone(&starts);
                    bindings.push(ManagedChildBinding::new(
                        name,
                        mode,
                        move |_: Cx, generation: ManagedGeneration| {
                            log.lock().push((name, generation.number));
                            async move {
                                if name == "a" && generation.number == 1 {
                                    Outcome::Err(())
                                } else {
                                    Outcome::Ok(())
                                }
                            }
                        },
                    ));
                }
                topology(&["a", "b", "c"], RestartPolicy::OneForAll)
                    .bind_managed(bindings, config(RestartPolicy::OneForAll, 1))
                    .unwrap()
                    .run(&cx)
                    .await
            });
            assert_eq!(*observed.lock(), [("a", 1), ("b", 1), ("c", 1), ("a", 2)]);
            assert_eq!(report.started, 4);
            assert_eq!(report.joined, 4);
            assert_eq!(report.restart_batches, 1);
            assert!(report.children.iter().all(|child| child.outcome.is_ok()));
        }

        #[test]
        fn managed_shared_window_boundary_uses_actual_runtime_time() {
            for elapsed in [10_u64, 11] {
                let mut lab = LabRuntime::new(LabConfig::new(0x34_0006).max_steps(8192));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let trigger = Arc::new(Mutex::new(None));
                let published_trigger = Arc::clone(&trigger);
                let binding = ManagedChildBinding::new(
                    "child",
                    ManagedRestartMode::Transient,
                    move |child: Cx, generation: ManagedGeneration| {
                        let receiver = if generation.number == 2 {
                            let (sender, receiver) = mpsc::channel::<()>(1);
                            *published_trigger.lock() = Some(sender);
                            Some(receiver)
                        } else {
                            None
                        };
                        async move {
                            if generation.number == 1 {
                                return Outcome::Err(());
                            }
                            if let Some(mut receiver) = receiver {
                                receiver.recv(&child).await.unwrap();
                                return Outcome::Err(());
                            }
                            Outcome::Ok(())
                        }
                    },
                );
                let managed = topology(&["child"], RestartPolicy::OneForOne)
                    .bind_managed(
                        vec![binding],
                        SupervisionConfig::new(1, Duration::from_nanos(10))
                            .with_backoff(BackoffStrategy::None),
                    )
                    .unwrap();
                let (parent, mut join) = lab
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        managed.run(&Cx::current().unwrap()).await
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(parent, 0);
                lab.run_until_idle();
                assert!(join.try_join().unwrap().is_none());
                let sender = trigger
                    .lock()
                    .take()
                    .expect("actual second generation admitted");
                assert_eq!(sender.telemetry_snapshot(0).recv_waiter_count, 1);
                lab.advance_time(elapsed);
                sender.try_send(()).unwrap();
                lab.run_until_idle();
                let report = join
                    .try_join()
                    .unwrap()
                    .expect("window decision reaches terminal controller");
                let expired = elapsed == 11;
                assert_eq!(report.restart_batches, 1 + u64::from(expired));
                assert_eq!(report.started, 2 + u64::from(expired));
                assert_eq!(report.joined, report.started);
                assert_eq!(report.children[0].generation.number, report.started);
                assert_eq!(report.children[0].outcome.is_ok(), expired);
                assert_eq!(report.children[0].completed_at.as_nanos(), elapsed);
                assert!(report.children[0].region_outcome.is_some());
                clean(&mut lab, root);
            }
        }

        #[test]
        fn managed_actual_finalizer_panic_forbids_replacement_and_escalates_once() {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_0007).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let log: StartedLog = Arc::new(Mutex::new(Vec::new()));
            let binding = parked_binding("child", Arc::clone(&log));
            let managed = topology(&["child"], RestartPolicy::OneForOne)
                .bind_managed(vec![binding], config(RestartPolicy::OneForOne, 8))
                .unwrap();
            let output = Arc::new(Mutex::new(None));
            let published = Arc::clone(&output);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    *published.lock() = Some(managed.run(&Cx::current().unwrap()).await);
                })
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(log.lock().len(), 1);
            let generation = log.lock()[0].1;
            let finalized = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&finalized);
            assert!(
                lab.state
                    .register_async_finalizer(generation.region, async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        panic!("actual managed finalizer failure");
                    })
            );
            log.lock()[0].2.try_send(()).unwrap();
            lab.run_until_idle();
            assert!(matches!(
                join.try_join(),
                Ok(Some(())) | Err(JoinError::Cancelled(_))
            ));
            let report = output
                .lock()
                .take()
                .expect("failed cleanup still publishes an honest terminal receipt");
            assert!(report.outcome.is_panicked(), "{report:?}");
            assert_eq!(report.escalations, 1);
            assert_eq!(report.started, 1);
            assert_eq!(report.joined, 1);
            assert_eq!(report.restart_batches, 0);
            assert_eq!(
                log.lock().len(),
                1,
                "quiescent but failed cleanup cannot authorize replacement"
            );
            assert_eq!(finalized.load(Ordering::SeqCst), 1);
            assert!(matches!(
                report.children[0].outcome,
                Outcome::Err("triggered child failure")
            ));
            assert!(matches!(
                report.children[0].cleanup_outcome,
                Some(Outcome::Panicked(_))
            ));
            assert!(report.children[0].region_outcome.is_some());
            assert!(lab.state.region(generation.region).is_none());
            clean(&mut lab, root);
        }

        #[test]
        fn managed_parent_cancel_during_root_finalizer_precedes_success_publication() {
            for cancel_before_close in [true, false] {
                let mut lab = LabRuntime::new(LabConfig::new(0x34_0011).max_steps(8192));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let started: StartedLog = Arc::new(Mutex::new(Vec::new()));
                let child_started = Arc::clone(&started);
                let binding = ManagedChildBinding::new(
                    "child",
                    ManagedRestartMode::Temporary,
                    move |child: Cx, generation: ManagedGeneration| {
                        let (sender, mut receiver) = mpsc::channel::<()>(1);
                        child_started
                            .lock()
                            .push(("child".to_owned(), generation, sender));
                        async move {
                            receiver.recv(&child).await.unwrap();
                            Outcome::<(), ()>::Ok(())
                        }
                    },
                );
                let managed = topology(&["child"], RestartPolicy::OneForOne)
                    .bind_managed(vec![binding], config(RestartPolicy::OneForOne, 3))
                    .unwrap();
                let launched = Arc::new(Mutex::new(None));
                let publication = Arc::clone(&launched);
                let (launcher, mut launcher_join) = lab
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        let cx = Cx::current().unwrap();
                        *publication.lock() = Some(managed.spawn(&cx).unwrap());
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(launcher, 0);
                lab.run_until_idle();
                assert_eq!(launcher_join.try_join(), Ok(Some(())));
                let mut handle = launched
                    .lock()
                    .take()
                    .expect("actual managed controller admitted");
                assert_eq!(started.lock().len(), 1);
                let generation = started.lock()[0].1;
                let supervisor_region =
                    lab.state.region(generation.region).unwrap().parent.unwrap();
                assert_ne!(supervisor_region, root);
                assert_eq!(
                    started.lock()[0].2.telemetry_snapshot(0).recv_waiter_count,
                    1
                );
                let entered = Arc::new(AtomicUsize::new(0));
                let completed = Arc::new(AtomicUsize::new(0));
                let finalizer_entered = Arc::clone(&entered);
                let finalizer_completed = Arc::clone(&completed);
                let (release, mut finalizer_gate) = oneshot::channel::<()>();
                assert!(
                    lab.state
                        .register_async_finalizer(supervisor_region, async move {
                            finalizer_entered.fetch_add(1, Ordering::SeqCst);
                            finalizer_gate.recv_uninterruptible().await.unwrap();
                            finalizer_completed.fetch_add(1, Ordering::SeqCst);
                        })
                );
                started.lock()[0].2.try_send(()).unwrap();
                lab.run_until_idle();
                assert_eq!(entered.load(Ordering::SeqCst), 1);
                assert_eq!(completed.load(Ordering::SeqCst), 0);
                assert!(lab.state.task(generation.task).is_none());
                assert!(lab.state.region(generation.region).is_none());
                assert!(lab.state.region(supervisor_region).is_some());
                assert!(lab.state.task(handle.task_id()).is_some());
                let mut poll_cx = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(
                    Box::pin(handle.join())
                        .as_mut()
                        .poll(&mut poll_cx)
                        .is_pending(),
                    "a completed Temporary child is not a completed supervisor root close"
                );
                if cancel_before_close {
                    handle.abort();
                    lab.run_until_idle();
                    assert_eq!(completed.load(Ordering::SeqCst), 0);
                    assert!(lab.state.region(supervisor_region).is_some());
                    assert!(
                        Box::pin(handle.join())
                            .as_mut()
                            .poll(&mut poll_cx)
                            .is_pending()
                    );
                }
                release.send_blocking(()).unwrap();
                lab.run_until_idle();
                assert_eq!(completed.load(Ordering::SeqCst), 1);
                assert!(lab.state.region(supervisor_region).is_none());
                assert!(
                    lab.state.task(handle.task_id()).is_none(),
                    "actual controller terminal precedes the late-cancel branch"
                );
                if !cancel_before_close {
                    handle.abort();
                }
                let Poll::Ready(Ok(report)) = Box::pin(handle.join()).as_mut().poll(&mut poll_cx)
                else {
                    panic!("actual terminated controller must retain its completed report");
                };
                if cancel_before_close {
                    assert!(report.outcome.is_cancelled(), "{report:?}");
                } else {
                    assert!(
                        report.outcome.is_ok(),
                        "late cancellation cannot rewrite a published report: {report:?}"
                    );
                }
                assert_eq!(
                    (
                        report.started,
                        report.joined,
                        report.restart_batches,
                        report.escalations
                    ),
                    (1, 1, 0, 0)
                );
                assert_eq!(report.children.len(), 1);
                assert_eq!(report.children[0].generation, generation);
                assert!(report.children[0].outcome.is_ok());
                assert_eq!(report.children[0].task_outcome, Ok(()));
                assert!(report.children[0].region_outcome.is_some());
                assert!(report.region_outcome.is_some());
                assert!(
                    matches!(report.cleanup_outcome, Some(Outcome::Ok(()))),
                    "{report:?}"
                );
                let trace = lab.state.trace_handle().snapshot();
                for task in [generation.task, handle.task_id()] {
                    assert_eq!(trace.iter().filter(|event| event.kind == crate::trace::TraceEventKind::Complete &&
                        matches!(event.data, crate::trace::TraceData::Task { task: actual, .. } if actual == task)).count(), 1);
                }
                clean(&mut lab, root);
            }
        }

        #[test]
        fn managed_cancel_all_precedes_cleanup_that_waits_for_sibling_cancellation() {
            for restart_policy in [
                Some(RestartPolicy::OneForAll),
                Some(RestartPolicy::RestForOne),
                None,
            ] {
                let policy = restart_policy.unwrap_or(RestartPolicy::OneForOne);
                let mut lab = LabRuntime::new(LabConfig::new(0x34_0008).max_steps(8192));
                let root = lab.state.create_root_region(Budget::INFINITE);
                let starts = Arc::new(AtomicUsize::new(0));
                let b_cancelled = Arc::new(AtomicUsize::new(0));
                let c_pending = Arc::new(AtomicUsize::new(0));
                let c_finished = Arc::new(AtomicUsize::new(0));
                let trigger = Arc::new(Mutex::new(None));
                let published_trigger = Arc::clone(&trigger);
                let a_starts = Arc::clone(&starts);
                let a = ManagedChildBinding::new(
                    "a",
                    ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        a_starts.fetch_add(1, Ordering::SeqCst);
                        let (sender, mut receiver) = mpsc::channel::<()>(1);
                        *published_trigger.lock() = Some(sender);
                        async move {
                            if generation.number > 1 {
                                return Outcome::Ok(());
                            }
                            match receiver.recv(&cx).await {
                                Ok(()) => Outcome::Err("restart trigger"),
                                Err(_) => Outcome::Cancelled(cx.cancel_reason().unwrap()),
                            }
                        }
                    },
                );
                let (release_b, b_gate) = oneshot::channel::<()>();
                let (witness, c_gate) = oneshot::channel::<()>();
                let b_state = Arc::new(Mutex::new(Some((b_gate, witness))));
                let b_starts = Arc::clone(&starts);
                let b_observed = Arc::clone(&b_cancelled);
                let b = ManagedChildBinding::new(
                    "b",
                    ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        b_starts.fetch_add(1, Ordering::SeqCst);
                        let gates =
                            (generation.number == 1).then(|| b_state.lock().take().unwrap());
                        let observed = Arc::clone(&b_observed);
                        async move {
                            let Some((mut release, witness)) = gates else {
                                return Outcome::Ok(());
                            };
                            let (_keep_sender, mut receiver) = mpsc::channel::<()>(1);
                            assert!(receiver.recv(&cx).await.is_err());
                            assert!(cx.cancel_reason().is_some());
                            observed.fetch_add(1, Ordering::SeqCst);
                            release.recv_uninterruptible().await.unwrap();
                            witness.send_blocking(()).unwrap();
                            Outcome::<(), &'static str>::Cancelled(cx.cancel_reason().unwrap())
                        }
                    },
                );
                let c_state = Arc::new(Mutex::new(Some(c_gate)));
                let c_starts = Arc::clone(&starts);
                let c_waited = Arc::clone(&c_pending);
                let c_done = Arc::clone(&c_finished);
                let c = ManagedChildBinding::new(
                    "c",
                    ManagedRestartMode::Transient,
                    move |cx: Cx, generation: ManagedGeneration| {
                        c_starts.fetch_add(1, Ordering::SeqCst);
                        let gate = (generation.number == 1).then(|| c_state.lock().take().unwrap());
                        let waited = Arc::clone(&c_waited);
                        let done = Arc::clone(&c_done);
                        async move {
                            let Some(mut witness) = gate else {
                                return Outcome::Ok(());
                            };
                            let (_keep_sender, mut receiver) = mpsc::channel::<()>(1);
                            assert!(receiver.recv(&cx).await.is_err());
                            assert!(cx.cancel_reason().is_some());
                            let mut waiting = std::pin::pin!(witness.recv_uninterruptible());
                            poll_fn(|poll_cx| {
                                let result = waiting.as_mut().poll(poll_cx);
                                if result.is_pending() {
                                    waited.fetch_add(1, Ordering::SeqCst);
                                }
                                result
                            })
                            .await
                            .unwrap();
                            done.fetch_add(1, Ordering::SeqCst);
                            Outcome::<(), &'static str>::Cancelled(cx.cancel_reason().unwrap())
                        }
                    },
                );
                let managed = topology(&["a", "b", "c"], policy)
                    .bind_managed(vec![a, b, c], config(policy, 1))
                    .unwrap();
                let output = Arc::new(Mutex::new(None));
                let published = Arc::clone(&output);
                let (parent, mut join) = lab
                    .state
                    .create_task(root, Budget::INFINITE, async move {
                        *published.lock() = Some(managed.run(&Cx::current().unwrap()).await);
                    })
                    .unwrap();
                lab.scheduler.lock().schedule(parent, 0);
                lab.run_until_idle();
                assert_eq!(starts.load(Ordering::SeqCst), 3);
                assert!(join.try_join().unwrap().is_none());
                if restart_policy.is_some() {
                    trigger.lock().as_ref().unwrap().try_send(()).unwrap();
                } else {
                    join.abort();
                }
                lab.run_until_idle();
                assert!(
                    c_pending.load(Ordering::SeqCst) > 0,
                    "first drained child's actual cleanup must park"
                );
                assert_eq!(
                    b_cancelled.load(Ordering::SeqCst),
                    1,
                    "second sibling must observe cancellation while first cleanup is still Pending"
                );
                assert_eq!(c_finished.load(Ordering::SeqCst), 0);
                assert_eq!(
                    starts.load(Ordering::SeqCst),
                    3,
                    "no generation can replace undrained work"
                );
                assert!(output.lock().is_none());
                assert!(join.try_join().unwrap().is_none());
                release_b.send_blocking(()).unwrap();
                lab.run_until_idle();
                if restart_policy.is_some() {
                    assert!(matches!(join.try_join(), Ok(Some(()))));
                } else {
                    assert!(matches!(join.try_join(), Err(JoinError::Cancelled(_))));
                }
                let report = output
                    .lock()
                    .take()
                    .expect("all acknowledged cleanup joins before report");
                assert_eq!(c_finished.load(Ordering::SeqCst), 1);
                assert_eq!(b_cancelled.load(Ordering::SeqCst), 1);
                assert_eq!(report.restart_batches, u64::from(restart_policy.is_some()));
                assert_eq!(report.started, if restart_policy.is_some() { 6 } else { 3 });
                assert_eq!(report.joined, report.started);
                assert_eq!(report.outcome.is_ok(), restart_policy.is_some());
                assert_eq!(report.outcome.is_cancelled(), restart_policy.is_none());
                if restart_policy.is_none() {
                    for completed in report.children.iter().filter(|child| child.name != "a") {
                        assert!(completed.shutdown_requested_before_completion);
                        assert!(completed.outcome.is_cancelled());
                        assert!(
                            completed.task_outcome.is_ok(),
                            "acknowledged cleanup returns its actual task value"
                        );
                    }
                }
                clean(&mut lab, root);
            }
        }

        #[test]
        fn managed_raw_user_return_does_not_hide_actual_unacknowledged_cancellation() {
            for returned_error in [false, true] {
                let report = run_case(move |cx| async move {
                    let binding = ManagedChildBinding::new(
                        "child",
                        ManagedRestartMode::Transient,
                        move |child: Cx, _| async move {
                            child.cancel_with(
                                crate::types::CancelKind::User,
                                Some("independent unacknowledged cancellation"),
                            );
                            // Deliberately no checkpoint acknowledgement: the
                            // raw return must not become an actual task success.
                            if returned_error {
                                Outcome::Err("late domain error")
                            } else {
                                Outcome::Ok(())
                            }
                        },
                    );
                    topology(&["child"], RestartPolicy::OneForOne)
                        .bind_managed(vec![binding], config(RestartPolicy::OneForOne, 3))
                        .unwrap()
                        .run(&cx)
                        .await
                });
                assert_eq!(report.started, 1);
                assert_eq!(report.joined, 1);
                assert_eq!(
                    report.restart_batches, 0,
                    "transient cancellation cannot be recast as restartable raw Err"
                );
                let completed = &report.children[0];
                assert_eq!(completed.outcome.is_err(), returned_error);
                assert_eq!(completed.outcome.is_ok(), !returned_error);
                assert!(matches!(
                    completed.task_outcome,
                    Err(JoinError::Cancelled(_))
                ));
                assert!(!completed.shutdown_requested_before_completion);
            }
        }

        #[test]
        fn managed_transient_completion_during_bounded_scan_is_not_resurrected() {
            use std::sync::atomic::AtomicBool;

            let mut lab = LabRuntime::new(LabConfig::new(0x34_0009).max_steps(32_768));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let names: Vec<_> = (0..33).map(|index| format!("child-{index:02}")).collect();
            let name_refs: Vec<_> = names.iter().map(String::as_str).collect();
            let starts = Arc::new(Mutex::new(Vec::new()));
            let (release_first, wait_first) = oneshot::channel::<()>();
            let first_gate = Arc::new(Mutex::new(Some(wait_first)));
            let mut bindings = Vec::new();
            for (index, name) in names.iter().enumerate() {
                let log = Arc::clone(&starts);
                let gate = Arc::clone(&first_gate);
                let mode = if index == 0 || index == 32 {
                    ManagedRestartMode::Transient
                } else {
                    ManagedRestartMode::Temporary
                };
                bindings.push(ManagedChildBinding::new(
                    name.clone(),
                    mode,
                    move |child: Cx, generation: ManagedGeneration| {
                        log.lock().push((index, generation));
                        let first = (index == 0 && generation.number == 1)
                            .then(|| gate.lock().take().unwrap());
                        async move {
                            if generation.number > 1 {
                                return Outcome::Ok(());
                            }
                            if let Some(mut wait) = first {
                                wait.recv_uninterruptible().await.unwrap();
                                return Outcome::Ok(());
                            }
                            if index == 32 {
                                return Outcome::Err(());
                            }
                            let (_keep_sender, mut receiver) = mpsc::channel::<()>(1);
                            assert!(receiver.recv(&child).await.is_err());
                            Outcome::Cancelled(child.cancel_reason().unwrap())
                        }
                    },
                ));
            }
            let managed = topology(&name_refs, RestartPolicy::OneForAll)
                .bind_managed(bindings, config(RestartPolicy::OneForAll, 1))
                .unwrap();
            let permit_poll = Arc::new(AtomicBool::new(false));
            let permitted = Arc::clone(&permit_poll);
            let inner_polls = Arc::new(AtomicUsize::new(0));
            let observed_polls = Arc::clone(&inner_polls);
            let (parent, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let mut execution = Box::pin(managed.run(&cx));
                    poll_fn(|poll_cx| {
                        if !permitted.swap(false, Ordering::SeqCst) {
                            return Poll::Pending;
                        }
                        observed_polls.fetch_add(1, Ordering::SeqCst);
                        execution.as_mut().poll(poll_cx)
                    })
                    .await
                })
                .unwrap();
            // Host-controlled actual scheduler polls make the scan yield
            // observable without changing the engine or its event queue.
            for _ in 0..256 {
                if starts.lock().len() == 33 {
                    break;
                }
                permit_poll.store(true, Ordering::SeqCst);
                lab.scheduler.lock().schedule(parent, 0);
                lab.run_until_idle();
            }
            assert_eq!(starts.lock().len(), 33);
            let first = starts.lock()[0].1;
            let trigger = starts.lock()[32].1;
            assert!(lab.state.task(first.task).is_some());
            assert!(
                lab.state.task(trigger.task).is_none(),
                "actual final block's failing child already completed"
            );
            // Acknowledge the last start, then execute exactly the first
            // bounded 32-slot scan; the trigger is in the unscanned last slot.
            let before = inner_polls.load(Ordering::SeqCst);
            permit_poll.store(true, Ordering::SeqCst);
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            assert_eq!(inner_polls.load(Ordering::SeqCst), before + 1);
            assert!(join.try_join().unwrap().is_none());
            release_first.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(
                inner_polls.load(Ordering::SeqCst),
                before + 1,
                "normal completion occurs while the controller scan remains suspended"
            );
            assert!(lab.state.task(first.task).is_none());
            assert!(
                lab.state
                    .trace_handle()
                    .snapshot()
                    .iter()
                    .any(|event| event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                        if task == first.task && region == first.region)),
                "full canonical task/region completion is the causal witness"
            );
            let mut result = None;
            for _ in 0..512 {
                permit_poll.store(true, Ordering::SeqCst);
                lab.scheduler.lock().schedule(parent, 0);
                lab.run_until_idle();
                if let Some(report) = join.try_join().unwrap() {
                    result = Some(report);
                    break;
                }
            }
            let report = result.expect("bounded actual controller resumes, drains and finishes");
            assert_eq!(
                report.started, 34,
                "only the failed last child gets a replacement"
            );
            assert_eq!(report.joined, 34);
            assert_eq!(report.restart_batches, 1);
            assert_eq!(
                starts
                    .lock()
                    .iter()
                    .filter(|(index, _)| *index == 0)
                    .count(),
                1
            );
            assert_eq!(
                starts
                    .lock()
                    .iter()
                    .filter(|(index, _)| *index == 32)
                    .count(),
                2
            );
            let completed = &report.children[0];
            assert_eq!(completed.generation, first);
            assert!(completed.outcome.is_ok());
            assert!(completed.task_outcome.is_ok());
            assert!(!completed.shutdown_requested_before_completion);
            assert!(report.outcome.is_ok());
            clean(&mut lab, root);
        }
    }
}

/// Stable identifier for a dynamically supervised child.
///
/// The slot keeps lookup compact, while generation prevents stale handles from
/// naming a different child after a slot is reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChildId {
    slot: u32,
    generation: u32,
}

impl ChildId {
    /// Create a child id from a slot and generation.
    #[must_use]
    pub const fn new(slot: u32, generation: u32) -> Self {
        Self { slot, generation }
    }

    /// Slot index in the dynamic-child table.
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Generation for stale-handle detection.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Handle returned for a dynamically started child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildHandle {
    id: ChildId,
    name: ChildName,
    task_id: TaskId,
}

impl ChildHandle {
    /// Create a child handle from its stable id, name, and root task.
    #[must_use]
    pub fn new(id: ChildId, name: ChildName, task_id: TaskId) -> Self {
        Self { id, name, task_id }
    }

    /// Stable dynamic child id.
    #[must_use]
    pub const fn id(&self) -> ChildId {
        self.id
    }

    /// Child name.
    #[must_use]
    pub fn name(&self) -> &ChildName {
        &self.name
    }

    /// Root task id for the child.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }
}

/// Pure bookkeeping record for a live dynamic child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChildRecord {
    handle: ChildHandle,
    restart: SupervisionStrategy,
    shutdown_budget: Budget,
    start_sequence: u64,
}

impl DynamicChildRecord {
    /// Create a dynamic-child record.
    #[must_use]
    pub fn new(
        handle: ChildHandle,
        restart: SupervisionStrategy,
        shutdown_budget: Budget,
        start_sequence: u64,
    ) -> Self {
        Self {
            handle,
            restart,
            shutdown_budget,
            start_sequence,
        }
    }

    /// Child handle.
    #[must_use]
    pub const fn handle(&self) -> &ChildHandle {
        &self.handle
    }

    /// Stable dynamic child id.
    #[must_use]
    pub const fn id(&self) -> ChildId {
        self.handle.id()
    }

    /// Child name.
    #[must_use]
    pub fn name(&self) -> &ChildName {
        self.handle.name()
    }

    /// Root task id for the child.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.handle.task_id()
    }

    /// Restart strategy inherited by this dynamic child.
    #[must_use]
    pub const fn restart(&self) -> &SupervisionStrategy {
        &self.restart
    }

    /// Shutdown budget used by terminate/restart protocols.
    #[must_use]
    pub const fn shutdown_budget(&self) -> Budget {
        self.shutdown_budget
    }

    /// Monotone sequence assigned when the child was started.
    #[must_use]
    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }
}

/// Errors from pure dynamic-child bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicChildError {
    /// A live child already owns this name.
    DuplicateChildName(ChildName),
    /// The table cannot allocate another slot or generation.
    ChildIdExhausted,
    /// The deterministic start-sequence counter overflowed.
    StartSequenceExhausted,
}

impl std::fmt::Display for DynamicChildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateChildName(name) => {
                write!(f, "duplicate dynamic child name: {name}")
            }
            Self::ChildIdExhausted => write!(f, "dynamic child id space exhausted"),
            Self::StartSequenceExhausted => {
                write!(f, "dynamic child start sequence exhausted")
            }
        }
    }
}

impl std::error::Error for DynamicChildError {}

/// Deterministic table for children started after supervisor boot.
///
/// This is a pure model for the `start_child`/`terminate_child` management
/// surface. Runtime wiring still has to perform the actual spawn, cancellation,
/// drain, and restart protocol.
#[derive(Debug, Default)]
pub struct DynamicChildTable {
    entries: Vec<Option<DynamicChildRecord>>,
    generations: Vec<u32>,
    free_slots: Vec<usize>,
    by_name: BTreeMap<ChildName, ChildId>,
    next_start_sequence: u64,
}

impl DynamicChildTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live dynamic children.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the table has no live dynamic children.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Insert a child that was already started by runtime wiring.
    ///
    /// The returned handle is stable until the child is removed. If the same
    /// slot is later reused, its generation changes so the old handle no longer
    /// resolves.
    pub fn insert_started(
        &mut self,
        name: impl Into<ChildName>,
        task_id: TaskId,
        restart: SupervisionStrategy,
        shutdown_budget: Budget,
    ) -> Result<ChildHandle, DynamicChildError> {
        let name = name.into();
        if self.by_name.contains_key(name.as_str()) {
            return Err(DynamicChildError::DuplicateChildName(name));
        }

        let start_sequence = self.next_start_sequence;
        let next_start_sequence = self
            .next_start_sequence
            .checked_add(1)
            .ok_or(DynamicChildError::StartSequenceExhausted)?;

        let (slot, generation) = self.allocate_id_parts()?;
        let id = ChildId::new(slot, generation);
        let handle = ChildHandle::new(id, name.clone(), task_id);
        let record =
            DynamicChildRecord::new(handle.clone(), restart, shutdown_budget, start_sequence);

        let slot_index = usize::try_from(slot).map_err(|_| DynamicChildError::ChildIdExhausted)?;
        self.entries[slot_index] = Some(record);
        self.by_name.insert(name, id);
        self.next_start_sequence = next_start_sequence;

        Ok(handle)
    }

    /// Remove a live child by handle id.
    ///
    /// Returns `None` for stale handles or unknown children.
    pub fn remove(&mut self, id: ChildId) -> Option<DynamicChildRecord> {
        let slot = usize::try_from(id.slot()).ok()?;
        if self.generations.get(slot).copied()? != id.generation() {
            return None;
        }

        let record = self.entries.get_mut(slot)?.take()?;
        self.by_name.remove(record.name().as_str());
        self.free_slots.push(slot);
        Some(record)
    }

    /// Remove a live child by name.
    ///
    /// This is the pure bookkeeping half of `terminate_child(name)`: runtime
    /// wiring still has to drive cancellation/drain for the removed record.
    pub fn remove_by_name(&mut self, name: &str) -> Option<DynamicChildRecord> {
        let id = *self.by_name.get(name)?;
        self.remove(id)
    }

    /// Look up a child by handle id.
    #[must_use]
    pub fn get(&self, id: ChildId) -> Option<&DynamicChildRecord> {
        let slot = usize::try_from(id.slot()).ok()?;
        if self.generations.get(slot).copied()? != id.generation() {
            return None;
        }
        self.entries.get(slot)?.as_ref()
    }

    /// Look up a child by name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&DynamicChildRecord> {
        let id = *self.by_name.get(name)?;
        self.get(id)
    }

    /// Whether a live child currently owns `name`.
    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Return live children in deterministic start order.
    #[must_use]
    pub fn which_children(&self) -> Vec<&DynamicChildRecord> {
        let mut children = self
            .entries
            .iter()
            .filter_map(std::option::Option::as_ref)
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.start_sequence());
        children
    }

    fn allocate_id_parts(&mut self) -> Result<(u32, u32), DynamicChildError> {
        if let Some(&slot) = self.free_slots.last() {
            let next_generation = self.generations[slot]
                .checked_add(1)
                .ok_or(DynamicChildError::ChildIdExhausted)?;
            self.free_slots.pop();
            self.generations[slot] = next_generation;
            let slot = u32::try_from(slot).map_err(|_| DynamicChildError::ChildIdExhausted)?;
            return Ok((slot, next_generation));
        }

        let slot_index = self.entries.len();
        let slot = u32::try_from(slot_index).map_err(|_| DynamicChildError::ChildIdExhausted)?;
        self.entries.push(None);
        self.generations.push(0);
        Ok((slot, 0))
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
                // Sanitize multiplier to prevent panics in Duration conversion
                let safe_multiplier = if multiplier.is_finite() && *multiplier >= 0.0 {
                    *multiplier
                } else {
                    2.0
                };

                // Allow lossy cast - precision loss is acceptable for backoff timing
                #[allow(clippy::cast_precision_loss)]
                // Cap exponent to prevent overflow/infinity in powi
                let exp = i32::try_from(attempt).unwrap_or(30).min(30);

                let base_secs = initial.as_secs_f64() * safe_multiplier.powi(exp);

                // Ensure base_secs is valid (finite and non-negative) before creating Duration
                let safe_secs = if base_secs.is_finite() && base_secs >= 0.0 {
                    base_secs
                } else {
                    max.as_secs_f64()
                };

                let capped_secs = safe_secs.min(max.as_secs_f64());
                let delay = Duration::try_from_secs_f64(capped_secs)
                    .unwrap_or(*max)
                    .min(*max);
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
        let window_nanos = duration_nanos_u64(self.config.window);
        let cutoff = now.saturating_sub(window_nanos);

        // Count restarts within the window
        let recent_count = self.restarts.iter().filter(|&&t| t >= cutoff).count();

        recent_count < self.config.max_restarts as usize
    }

    /// Record a restart at the given virtual time.
    ///
    /// Also prunes old entries outside the window.
    pub fn record_restart(&mut self, now: u64) {
        let window_nanos = duration_nanos_u64(self.config.window);
        let cutoff = now.saturating_sub(window_nanos);

        // Prune old entries
        self.restarts.retain(|&t| t >= cutoff);

        // Record new restart
        self.restarts.push(now);
    }

    /// Atomically check if restart is allowed and record it if so.
    ///
    /// Returns the restart decision with attempt number and delay if restart is allowed,
    /// or None if restart budget is exhausted. This prevents race conditions during
    /// concurrent failures by combining the check-and-record operations atomically.
    pub fn try_record_restart(&mut self, now: u64) -> Option<(u32, Option<Duration>)> {
        // Check if restart is allowed first
        if !self.can_restart(now) {
            return None;
        }

        // Get attempt number and delay BEFORE recording to ensure consistency
        let attempt = self.recent_restart_count(now) as u32 + 1;
        let delay = self.next_delay(now);

        // Now record the restart
        self.record_restart(now);

        Some((attempt, delay))
    }

    /// Get the number of restarts within the current window.
    #[must_use]
    pub fn recent_restart_count(&self, now: u64) -> usize {
        let window_nanos = duration_nanos_u64(self.config.window);
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

    /// Check if a restart is allowed given the current virtual time and budget.
    ///
    /// This extends [`can_restart`](Self::can_restart) with budget-awareness:
    /// - Checks the sliding window restart count (same as `can_restart`)
    /// - Checks that remaining cost quota can cover `restart_cost`
    /// - Checks that remaining time exceeds `min_remaining_for_restart`
    /// - Checks that remaining poll quota exceeds `min_polls_for_restart`
    ///
    /// Returns `Ok(())` if the restart is allowed, or `Err(BudgetRefusal)` with
    /// the reason the restart was denied.
    pub fn can_restart_with_budget(&self, now: u64, budget: &Budget) -> Result<(), BudgetRefusal> {
        // First check the standard sliding-window limit
        if !self.can_restart(now) {
            return Err(BudgetRefusal::WindowExhausted {
                max_restarts: self.config.max_restarts,
                window: self.config.window,
            });
        }

        // Check cost quota
        if self.config.restart_cost > 0 {
            if let Some(remaining) = budget.cost_quota {
                if remaining < self.config.restart_cost {
                    return Err(BudgetRefusal::InsufficientCost {
                        required: self.config.restart_cost,
                        remaining,
                    });
                }
            }
        }

        // Check deadline
        if let Some(min_remaining) = self.config.min_remaining_for_restart {
            if let Some(deadline) = budget.deadline {
                let now_time = crate::types::id::Time::from_nanos(now);
                let remaining = budget.remaining_time(now_time);
                match remaining {
                    None => {
                        // Deadline already passed
                        return Err(BudgetRefusal::DeadlineTooClose {
                            min_required: min_remaining,
                            remaining: Duration::ZERO,
                        });
                    }
                    Some(rem) if rem < min_remaining => {
                        return Err(BudgetRefusal::DeadlineTooClose {
                            min_required: min_remaining,
                            remaining: rem,
                        });
                    }
                    _ => {} // enough time remaining
                }
                // Suppress unused variable warning - deadline is used for the check above
                let _ = deadline;
            }
        }

        // Check poll quota
        if self.config.min_polls_for_restart > 0
            && budget.poll_quota < self.config.min_polls_for_restart
        {
            return Err(BudgetRefusal::InsufficientPolls {
                min_required: self.config.min_polls_for_restart,
                remaining: budget.poll_quota,
            });
        }

        Ok(())
    }

    /// Compute the restart intensity (restarts per second) over the window.
    ///
    /// Returns 0.0 if no restarts have occurred or if the window is zero.
    #[must_use]
    pub fn intensity(&self, now: u64) -> f64 {
        let count = self.recent_restart_count(now);
        if count == 0 {
            return 0.0;
        }
        let window_secs = self.config.window.as_secs_f64();
        if window_secs <= 0.0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let intensity = count as f64 / window_secs;
        intensity
    }
}

/// Reason a restart was refused due to budget constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The sliding-window restart count was exhausted.
    WindowExhausted {
        /// Maximum restarts allowed.
        max_restarts: u32,
        /// Time window.
        window: Duration,
    },
    /// Remaining cost quota is insufficient for the restart cost.
    InsufficientCost {
        /// Cost required per restart.
        required: u64,
        /// Remaining cost quota.
        remaining: u64,
    },
    /// Remaining time until deadline is less than the minimum required.
    DeadlineTooClose {
        /// Minimum remaining time required.
        min_required: Duration,
        /// Actual remaining time.
        remaining: Duration,
    },
    /// Remaining poll quota is below the minimum required.
    InsufficientPolls {
        /// Minimum polls required.
        min_required: u32,
        /// Remaining poll quota.
        remaining: u32,
    },
}

impl std::fmt::Display for BudgetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowExhausted {
                max_restarts,
                window,
            } => write!(
                f,
                "restart window exhausted: {max_restarts} restarts in {window:?}"
            ),
            Self::InsufficientCost {
                required,
                remaining,
            } => write!(
                f,
                "insufficient cost budget: need {required}, have {remaining}"
            ),
            Self::DeadlineTooClose {
                min_required,
                remaining,
            } => write!(
                f,
                "deadline too close: need {min_required:?} remaining, have {remaining:?}"
            ),
            Self::InsufficientPolls {
                min_required,
                remaining,
            } => write!(
                f,
                "insufficient poll budget: need {min_required}, have {remaining}"
            ),
        }
    }
}

impl std::error::Error for BudgetRefusal {}

/// Deterministic restart intensity window.
///
/// Tracks restart rate over a configurable sliding window using virtual
/// timestamps. Computes intensity as restarts-per-second and compares
/// against configurable thresholds to detect restart storms.
///
/// All operations are deterministic and use virtual time (nanosecond u64),
/// making them safe for lab-runtime tests.
#[derive(Debug, Clone)]
pub struct RestartIntensityWindow {
    /// Restart timestamps within the observation window.
    timestamps: Vec<u64>,
    /// Observation window duration.
    window: Duration,
    /// Threshold intensity (restarts/second) above which a storm is detected.
    storm_threshold: f64,
}

impl RestartIntensityWindow {
    /// Create a new intensity window.
    ///
    /// # Arguments
    ///
    /// * `window` - Duration of the sliding observation window
    /// * `storm_threshold` - Restarts per second above which a storm is flagged
    #[must_use]
    pub fn new(window: Duration, storm_threshold: f64) -> Self {
        validate_storm_threshold(storm_threshold);
        Self {
            timestamps: Vec::new(),
            window,
            storm_threshold,
        }
    }

    /// Record a restart at the given virtual time and prune old entries.
    pub fn record(&mut self, now: u64) {
        let window_nanos = duration_nanos_u64(self.window);
        let cutoff = now.saturating_sub(window_nanos);
        self.timestamps.retain(|&t| t >= cutoff);
        self.timestamps.push(now);
    }

    /// Compute the current restart intensity (restarts per second).
    ///
    /// Returns 0.0 if no restarts have been recorded in the window.
    #[must_use]
    pub fn intensity(&self, now: u64) -> f64 {
        let window_nanos = duration_nanos_u64(self.window);
        let cutoff = now.saturating_sub(window_nanos);
        let count = self.timestamps.iter().filter(|&&t| t >= cutoff).count();
        if count == 0 {
            return 0.0;
        }
        let window_secs = self.window.as_secs_f64();
        if window_secs <= 0.0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let intensity = count as f64 / window_secs;
        intensity
    }

    /// Returns `true` if the current intensity exceeds the storm threshold.
    #[must_use]
    pub fn is_storm(&self, now: u64) -> bool {
        self.intensity(now) > self.storm_threshold
    }

    /// Number of restarts within the current window.
    #[must_use]
    pub fn count(&self, now: u64) -> usize {
        let window_nanos = duration_nanos_u64(self.window);
        let cutoff = now.saturating_sub(window_nanos);
        self.timestamps.iter().filter(|&&t| t >= cutoff).count()
    }

    /// The configured storm threshold.
    #[must_use]
    pub fn storm_threshold(&self) -> f64 {
        self.storm_threshold
    }

    /// The configured observation window.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }
}

// ============================================================================
// CUSUM-style restart storm detector (advisory; not anytime-valid — see docs)
// ============================================================================

/// Configuration for the restart storm e-process monitor.
#[derive(Debug, Clone, Copy)]
pub struct StormMonitorConfig {
    /// Type-I error bound (false-positive rate). Must be in (0, 1).
    /// The monitor guarantees P(false alarm) ≤ alpha under H0.
    pub alpha: f64,
    /// Expected restart rate (restarts per second) under normal operation.
    /// Intensities persistently above this accumulate evidence for a storm.
    pub expected_rate: f64,
    /// Minimum observations before the monitor can trigger an alert.
    pub min_observations: u64,
    /// Tolerance factor for intensity fluctuations (normalizer).
    ///
    /// Intensities below `tolerance * expected_rate` will cause the evidence to decay.
    /// Must be >= 1.0.
    ///
    /// The default is 1.2 (20% tolerance). A higher value reduces sensitivity to
    /// mild overloads but increases robustness against variance (false alarms).
    pub tolerance: f64,
}

impl Default for StormMonitorConfig {
    fn default() -> Self {
        Self {
            alpha: 0.01,
            expected_rate: 0.05, // 1 restart per 20 seconds
            min_observations: 3,
            tolerance: 1.2,
        }
    }
}

/// CUSUM-style restart storm detector (advisory).
///
/// Monitors restart intensity and accumulates log-evidence against the null
/// hypothesis ("restarts occur at the expected rate"). When the e-value
/// exceeds 1/α, [`Self::is_alert`] reports a storm.
///
/// # Guarantee scope (honest boundary)
///
/// This is **not** an anytime-valid e-process, and it does **not** provide a
/// Ville-inequality Type-I error ≤ α bound regardless of stopping time. Two
/// deliberate design choices break the supermartingale premise the Ville bound
/// requires:
///
/// 1. **Wealth floor.** `log_e_value` is floored at `0` (wealth reset to 1)
///    after each update so the detector reacts quickly to a storm even after a
///    long quiet period. A floored process is not a supermartingale, so under
///    H0 the false-alarm probability accumulates toward 1 over a long horizon
///    (CUSUM/ARL semantics, not anytime validity).
/// 2. **Overlapping-window intensities.** Successive intensities come from an
///    overlapping [`RestartIntensityWindow`], so observations are serially
///    correlated and the per-observation `E[LR] ≤ 1` premise holds only
///    approximately.
///
/// Treat the output as a responsive, calibration-tunable storm heuristic, not a
/// statistically guaranteed sequential test. The independent per-restart budget
/// check in [`Supervisor`] remains the hard bound on restart intensity.
///
/// # How it works
///
/// Each restart is an observation. The monitor takes the current restart
/// intensity (from a [`RestartIntensityWindow`]) and computes a likelihood
/// ratio comparing H1 (intensity above expected) against H0 (normal rate):
///
/// ```text
/// LR = max(1, intensity / expected_rate) / tolerance
/// ```
///
/// The tolerance (normalizer) scales the ratio; it does not restore the Ville
/// bound broken by the wealth floor above.
///
/// # Usage
///
/// ```
/// use asupersync::supervision::{RestartStormMonitor, StormMonitorConfig};
///
/// let config = StormMonitorConfig {
///     alpha: 0.01,          // 1% false-positive bound
///     expected_rate: 0.05,  // ~1 restart per 20 seconds
///     min_observations: 3,
///     tolerance: 1.2,       // Alert if intensity > 1.2 * expected
/// };
/// let mut monitor = RestartStormMonitor::new(config);
///
/// // Feed intensity observations (restarts per second)
/// monitor.observe_intensity(0.03); // normal
/// monitor.observe_intensity(0.04); // normal
/// monitor.observe_intensity(5.0);  // storm!
///
/// if monitor.is_alert() {
///     // E-value exceeded threshold: restart storm detected
/// }
/// ```
#[derive(Debug)]
pub struct RestartStormMonitor {
    config: StormMonitorConfig,
    /// Current e-value (product of normalized likelihood ratios).
    e_value: f64,
    /// Rejection threshold: 1/alpha.
    threshold: f64,
    /// Number of observations so far.
    observations: u64,
    /// Running sum of log-likelihood ratios (for numerical stability).
    log_e_value: f64,
    /// Peak e-value observed (for diagnostics).
    peak_e_value: f64,
    /// Number of times alert was triggered.
    alert_count: u64,
}

impl RestartStormMonitor {
    /// Creates a new storm monitor with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if `alpha` is not in (0, 1), `expected_rate` is not positive,
    /// or `tolerance` is less than 1.0.
    #[must_use]
    pub fn new(config: StormMonitorConfig) -> Self {
        assert!(
            config.alpha > 0.0 && config.alpha < 1.0,
            "alpha must be in (0, 1), got {}",
            config.alpha
        );
        assert!(
            config.expected_rate > 0.0,
            "expected_rate must be > 0, got {}",
            config.expected_rate
        );
        assert!(
            config.tolerance >= 1.0,
            "tolerance must be >= 1.0, got {}",
            config.tolerance
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

    /// Observe a restart intensity measurement (restarts per second).
    ///
    /// Updates the e-value with the likelihood ratio for this observation.
    /// Under H0 (no storm), intensity stays near `expected_rate`.
    /// Under H1 (storm), intensity exceeds `expected_rate` persistently.
    ///
    /// The likelihood ratio at each step is:
    /// ```text
    /// LR = max(1, intensity / expected_rate) / tolerance
    /// ```
    ///
    /// The tolerance normalizes the ratio; note that the wealth floor applied
    /// after this update (and overlapping-window intensities) mean the process
    /// is NOT a supermartingale and does NOT carry a Ville anytime-valid bound —
    /// see the type-level docs for the honest guarantee scope.
    pub fn observe_intensity(&mut self, intensity: f64) -> crate::obligation::eprocess::AlertState {
        let was_alert = self.is_alert();
        self.observations += 1;

        let ratio = intensity / self.config.expected_rate;

        // Likelihood ratio: evidence grows when intensity exceeds expected.
        // Normalizer (tolerance) scales the ratio (not a supermartingale
        // guarantee — the wealth floor below breaks that; see type docs).
        let normalizer = self.config.tolerance;
        let lr = ratio.max(1.0) / normalizer;

        self.log_e_value += lr.ln();
        // CUSUM-style wealth floor: reset evidence to its initial state if it
        // would drop below, so the monitor reacts quickly to storms even after
        // long quiet periods. NOTE: this floor is exactly what makes the process
        // NOT a supermartingale, so it forfeits the Ville anytime-valid Type-I
        // bound in exchange for responsiveness (see the type-level docs). This
        // is a deliberate ARL-oriented trade-off, not an oversight.
        if self.log_e_value < 0.0 {
            self.log_e_value = 0.0;
        }
        self.e_value = self.log_e_value.exp();

        if self.e_value > self.peak_e_value {
            self.peak_e_value = self.e_value;
        }

        if !was_alert
            && self.e_value >= self.threshold
            && self.observations >= self.config.min_observations
        {
            self.alert_count += 1;
        }

        self.alert_state()
    }

    /// Convenience: observe intensity from a [`RestartIntensityWindow`] at the
    /// given virtual time.
    pub fn observe_from_window(
        &mut self,
        window: &RestartIntensityWindow,
        now: u64,
    ) -> crate::obligation::eprocess::AlertState {
        self.observe_intensity(window.intensity(now))
    }

    /// Returns the current alert state.
    #[must_use]
    pub fn alert_state(&self) -> crate::obligation::eprocess::AlertState {
        use crate::obligation::eprocess::AlertState;
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
        self.alert_state() == crate::obligation::eprocess::AlertState::Alert
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
    pub fn config(&self) -> &StormMonitorConfig {
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
    pub fn snapshot(&self) -> StormMonitorSnapshot {
        StormMonitorSnapshot {
            e_value: self.e_value,
            threshold: self.threshold,
            observations: self.observations,
            alert_state: self.alert_state(),
            peak_e_value: self.peak_e_value,
            alert_count: self.alert_count,
        }
    }
}

/// Diagnostic snapshot of the restart storm monitor.
#[derive(Debug, Clone)]
pub struct StormMonitorSnapshot {
    /// Current e-value.
    pub e_value: f64,
    /// Rejection threshold.
    pub threshold: f64,
    /// Number of observations.
    pub observations: u64,
    /// Current alert state.
    pub alert_state: crate::obligation::eprocess::AlertState,
    /// Peak e-value ever observed.
    pub peak_e_value: f64,
    /// Number of alert triggers.
    pub alert_count: u64,
}

impl std::fmt::Display for StormMonitorSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StormMonitor[{}]: e={:.4} threshold={:.1} obs={} peak={:.4} alerts={}",
            self.alert_state,
            self.e_value,
            self.threshold,
            self.observations,
            self.peak_e_value,
            self.alert_count,
        )
    }
}

// =============================================================================
// Integrated Restart Tracker (bd-2106k)
//
// Combines RestartHistory (sliding-window + budget checks),
// RestartIntensityWindow (restarts/second), and RestartStormMonitor
// (e-process alerting) into a single coordinator that the supervisor
// runtime can use as one unit.
//
// All timestamps are virtual (nanosecond u64), making the tracker fully
// deterministic under lab-time scheduling.
// =============================================================================

/// Configuration for the integrated restart tracker.
///
/// Bundles `RestartConfig` (window + budget integration) with optional
/// storm detection parameters.
#[derive(Debug, Clone)]
pub struct RestartTrackerConfig {
    /// Core restart config (max_restarts, window, backoff, budget fields).
    pub restart: RestartConfig,
    /// Storm detection threshold in restarts/second.
    ///
    /// When `Some`, a [`RestartIntensityWindow`] and [`RestartStormMonitor`]
    /// are created and fed on every recorded restart.
    pub storm_threshold: Option<f64>,
    /// E-process monitor config (only used when `storm_threshold` is set).
    pub storm_monitor: StormMonitorConfig,
    /// Whether the tracker should derive the monitor's expected rate from the
    /// configured storm threshold.
    auto_align_storm_expected_rate: bool,
}

impl RestartTrackerConfig {
    /// Create a tracker config from a restart config with no storm detection.
    #[must_use]
    pub fn from_restart(restart: RestartConfig) -> Self {
        Self {
            restart,
            storm_threshold: None,
            storm_monitor: StormMonitorConfig::default(),
            auto_align_storm_expected_rate: true,
        }
    }

    /// Enable storm detection with the given threshold and default e-process config.
    #[must_use]
    pub fn with_storm_detection(mut self, threshold: f64) -> Self {
        validate_storm_threshold(threshold);
        self.storm_threshold = Some(threshold);
        self
    }

    /// Set a custom e-process monitor config for storm detection.
    ///
    /// This disables the default threshold-derived expected-rate inference so
    /// the supplied monitor configuration is preserved exactly.
    #[must_use]
    pub fn with_storm_monitor(mut self, config: StormMonitorConfig) -> Self {
        self.storm_monitor = config;
        self.auto_align_storm_expected_rate = false;
        self
    }
}

/// Outcome of a restart evaluation by the [`RestartTracker`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartVerdict {
    /// Restart is allowed. Includes the backoff delay (if any) and
    /// which attempt this represents.
    Allowed {
        /// 1-indexed attempt number within the current window.
        attempt: u32,
        /// Backoff delay before the restart should begin.
        delay: Option<Duration>,
    },
    /// Restart was denied by the sliding window or budget.
    Denied {
        /// The reason the restart was denied.
        refusal: BudgetRefusal,
    },
}

impl RestartVerdict {
    /// Returns `true` if the restart was allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// Integrated restart tracker combining window counting, budget checks,
/// intensity monitoring, and e-process storm detection.
///
/// This is the primary interface a supervisor uses to record restarts
/// and evaluate whether a new restart should be allowed.
///
/// # Determinism
///
/// All timestamps are virtual (`u64` nanoseconds). The tracker produces
/// identical verdicts given identical event sequences, regardless of
/// wall-clock timing. Safe for use under `LabRuntime`.
///
/// # Bead
///
/// bd-2106k | Parent: bd-h9lhl
#[derive(Debug)]
pub struct RestartTracker {
    /// Core sliding-window history + budget evaluation.
    history: RestartHistory,
    /// Intensity monitor (present when storm detection enabled).
    intensity: Option<RestartIntensityWindow>,
    /// E-process storm monitor (present when storm detection enabled).
    storm: Option<RestartStormMonitor>,
}

impl RestartTracker {
    /// Create a new tracker from the given config.
    #[must_use]
    pub fn new(config: RestartTrackerConfig) -> Self {
        let window = config.restart.window;
        let (intensity, storm) = match config.storm_threshold {
            Some(threshold) => (
                Some(RestartIntensityWindow::new(window, threshold)),
                Some(RestartStormMonitor::new({
                    let mut storm_monitor = config.storm_monitor;
                    if config.auto_align_storm_expected_rate {
                        storm_monitor.expected_rate = threshold / storm_monitor.tolerance;
                    }
                    storm_monitor
                })),
            ),
            None => (None, None),
        };
        let history = RestartHistory::new(config.restart);
        Self {
            history,
            intensity,
            storm,
        }
    }

    /// Create a tracker from just a `RestartConfig` (no storm detection).
    #[must_use]
    pub fn from_restart_config(config: RestartConfig) -> Self {
        Self::new(RestartTrackerConfig::from_restart(config))
    }

    /// Evaluate whether a restart is allowed at the given virtual time.
    ///
    /// Does **not** record the restart — call [`record`](Self::record)
    /// after the restart actually begins.
    #[must_use]
    pub fn evaluate(&self, now: u64) -> RestartVerdict {
        if !self.history.can_restart(now) {
            return RestartVerdict::Denied {
                refusal: BudgetRefusal::WindowExhausted {
                    max_restarts: self.history.config().max_restarts,
                    window: self.history.config().window,
                },
            };
        }
        let attempt = self.history.recent_restart_count(now) as u32 + 1;
        let delay = self.history.next_delay(now);
        RestartVerdict::Allowed { attempt, delay }
    }

    /// Evaluate whether a restart is allowed, considering budget constraints.
    #[must_use]
    pub fn evaluate_with_budget(&self, now: u64, budget: &Budget) -> RestartVerdict {
        if let Err(refusal) = self.history.can_restart_with_budget(now, budget) {
            return RestartVerdict::Denied { refusal };
        }
        let attempt = self.history.recent_restart_count(now) as u32 + 1;
        let delay = self.history.next_delay(now);
        RestartVerdict::Allowed { attempt, delay }
    }

    /// Record a restart at the given virtual time.
    ///
    /// Updates the sliding window, intensity monitor, and storm detector.
    pub fn record(&mut self, now: u64) {
        self.history.record_restart(now);
        if let Some(ref mut intensity) = self.intensity {
            intensity.record(now);
            if let Some(ref mut storm) = self.storm {
                storm.observe_from_window(intensity, now);
            }
        }
    }

    /// Number of restarts within the current window.
    #[must_use]
    pub fn recent_count(&self, now: u64) -> usize {
        self.history.recent_restart_count(now)
    }

    /// Restart intensity (restarts per second) over the window.
    ///
    /// Returns `None` if storm detection is not enabled.
    #[must_use]
    pub fn intensity(&self, now: u64) -> Option<f64> {
        self.intensity.as_ref().map(|w| w.intensity(now))
    }

    /// Whether a restart storm is currently detected.
    ///
    /// Returns `false` if storm detection is not enabled.
    #[must_use]
    pub fn is_storm(&self) -> bool {
        self.storm
            .as_ref()
            .is_some_and(RestartStormMonitor::is_alert)
    }

    /// Whether a storm is detected by the intensity window threshold.
    ///
    /// This is the simpler threshold check (not the e-process).
    /// Returns `false` if storm detection is not enabled.
    #[must_use]
    pub fn is_intensity_storm(&self, now: u64) -> bool {
        self.intensity.as_ref().is_some_and(|w| w.is_storm(now))
    }

    /// Access the underlying restart history.
    #[must_use]
    pub fn history(&self) -> &RestartHistory {
        &self.history
    }

    /// Access the storm monitor snapshot (if enabled).
    #[must_use]
    pub fn storm_snapshot(&self) -> Option<StormMonitorSnapshot> {
        self.storm.as_ref().map(RestartStormMonitor::snapshot)
    }

    /// Reset all state (useful after escalation/recovery).
    pub fn reset(&mut self) {
        self.history = RestartHistory::new(self.history.config().clone());
        if let Some(ref mut intensity) = self.intensity {
            *intensity =
                RestartIntensityWindow::new(intensity.window(), intensity.storm_threshold());
        }
        if let Some(ref mut storm) = self.storm {
            storm.reset();
        }
    }
}

fn validate_storm_threshold(threshold: f64) {
    assert!(
        threshold.is_finite() && threshold > 0.0,
        "storm threshold must be finite and > 0, got {threshold}"
    );
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
    /// Stopped because a budget constraint prevented restart.
    BudgetRefused(BudgetRefusal),
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

    /// A restart was refused due to budget constraints.
    BudgetRefusedRestart {
        /// The actor whose restart was refused.
        task_id: TaskId,
        /// The region containing the actor.
        region_id: RegionId,
        /// The reason the budget refused the restart.
        refusal: BudgetRefusal,
    },
}

// ---------------------------------------------------------------------------
// Evidence Ledger (bd-35iz1)
//
// Structured, deterministic, test-assertable record of *why* each supervision
// decision was made.  Every call to `Supervisor::on_failure_with_budget`
// appends exactly one `EvidenceEntry` whose `binding_constraint` field
// identifies the specific rule that determined the outcome.
// ---------------------------------------------------------------------------

/// The specific constraint that bound a supervision decision.
///
/// Each supervision decision is determined by exactly one binding constraint.
/// This enum captures which rule was decisive, along with the relevant
/// parameters, so that tests and observability tooling can verify the
/// reasoning chain without inspecting implementation details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingConstraint {
    /// Monotone severity: outcome is too severe for restart.
    ///
    /// `Panicked`, `Cancelled`, and `Ok` outcomes bypass strategy evaluation
    /// entirely — the decision is `Stop` regardless of the configured strategy.
    MonotoneSeverity {
        /// Human-readable label for the outcome kind (e.g. `"Panicked"`).
        outcome_kind: &'static str,
    },

    /// The supervision strategy is `Stop` — no restart attempted.
    ExplicitStopStrategy,

    /// The supervision strategy is `Escalate`.
    EscalateStrategy,

    /// Restart was allowed: window + budget checks passed.
    RestartAllowed {
        /// Which attempt this restart represents (1-indexed).
        attempt: u32,
    },

    /// Sliding-window restart count exhausted.
    WindowExhausted {
        /// Maximum restarts allowed in the window.
        max_restarts: u32,
        /// The window duration.
        window: Duration,
    },

    /// Cost quota insufficient for `restart_cost`.
    InsufficientCost {
        /// Cost required per restart.
        required: u64,
        /// Remaining cost quota.
        remaining: u64,
    },

    /// Remaining time until deadline is less than `min_remaining_for_restart`.
    DeadlineTooClose {
        /// Minimum remaining time required.
        min_required: Duration,
        /// Actual remaining time.
        remaining: Duration,
    },

    /// Poll quota insufficient for `min_polls_for_restart`.
    InsufficientPolls {
        /// Minimum polls required.
        min_required: u32,
        /// Remaining poll quota.
        remaining: u32,
    },
}

impl std::fmt::Display for BindingConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MonotoneSeverity { outcome_kind } => {
                write!(f, "monotone severity: {outcome_kind} is not restartable")
            }
            Self::ExplicitStopStrategy => write!(f, "strategy is Stop"),
            Self::EscalateStrategy => write!(f, "strategy is Escalate"),
            Self::RestartAllowed { attempt } => {
                write!(f, "restart allowed (attempt {attempt})")
            }
            Self::WindowExhausted {
                max_restarts,
                window,
            } => write!(f, "window exhausted: {max_restarts} restarts in {window:?}"),
            Self::InsufficientCost {
                required,
                remaining,
            } => write!(f, "insufficient cost: need {required}, have {remaining}"),
            Self::DeadlineTooClose {
                min_required,
                remaining,
            } => write!(
                f,
                "deadline too close: need {min_required:?}, have {remaining:?}"
            ),
            Self::InsufficientPolls {
                min_required,
                remaining,
            } => write!(
                f,
                "insufficient polls: need {min_required}, have {remaining}"
            ),
        }
    }
}

/// A single evidence entry recording why a supervision decision was made.
///
/// Each call to [`Supervisor::on_failure_with_budget`] produces exactly one
/// entry.  The entry captures the full context: what failed, what strategy
/// was in effect, what decision was made, and — crucially — which constraint
/// was binding.
#[derive(Debug, Clone)]
pub struct EvidenceEntry {
    /// Virtual timestamp (nanoseconds) when the decision was made.
    pub timestamp: u64,
    /// The failing task.
    pub task_id: TaskId,
    /// The region containing the task.
    pub region_id: RegionId,
    /// The failure outcome that triggered supervision.
    pub outcome: Outcome<(), ()>,
    /// Human-readable label for the strategy kind (`"Stop"`, `"Restart"`, `"Escalate"`).
    pub strategy_kind: &'static str,
    /// The resulting supervision decision.
    pub decision: SupervisionDecision,
    /// The specific constraint that determined the decision.
    pub binding_constraint: BindingConstraint,
}

impl EvidenceEntry {
    /// Convert this supervision-specific evidence entry into a generalized
    /// [`evidence::EvidenceRecord`](crate::evidence::EvidenceRecord).
    ///
    /// Maps [`BindingConstraint`] to the appropriate
    /// [`Verdict`](crate::evidence::Verdict) +
    /// [`SupervisionDetail`](crate::evidence::SupervisionDetail) pair.
    #[must_use]
    pub fn to_evidence_record(&self) -> crate::evidence::EvidenceRecord {
        use crate::evidence::{
            EvidenceDetail, EvidenceRecord, Subsystem, SupervisionDetail, Verdict,
        };

        let (verdict, detail) = match &self.binding_constraint {
            BindingConstraint::MonotoneSeverity { outcome_kind } => (
                Verdict::Stop,
                SupervisionDetail::MonotoneSeverity {
                    outcome_kind: outcome_kind.to_string(),
                },
            ),
            BindingConstraint::ExplicitStopStrategy => {
                (Verdict::Stop, SupervisionDetail::ExplicitStop)
            }
            BindingConstraint::EscalateStrategy => {
                (Verdict::Escalate, SupervisionDetail::ExplicitEscalate)
            }
            BindingConstraint::RestartAllowed { attempt } => {
                // Extract delay from the decision if it was a Restart.
                let delay = match &self.decision {
                    SupervisionDecision::Restart { delay, .. } => *delay,
                    _ => None,
                };
                (
                    Verdict::Restart,
                    SupervisionDetail::RestartAllowed {
                        attempt: *attempt,
                        delay,
                    },
                )
            }
            BindingConstraint::WindowExhausted {
                max_restarts,
                window,
            } => (
                Verdict::Stop,
                SupervisionDetail::WindowExhausted {
                    max_restarts: *max_restarts,
                    window: *window,
                },
            ),
            BindingConstraint::InsufficientCost {
                required,
                remaining,
            } => (
                Verdict::Stop,
                SupervisionDetail::BudgetRefused {
                    constraint: format!("insufficient cost: need {required}, have {remaining}"),
                },
            ),
            BindingConstraint::DeadlineTooClose {
                min_required,
                remaining,
            } => (
                Verdict::Stop,
                SupervisionDetail::BudgetRefused {
                    constraint: format!(
                        "deadline too close: need {min_required:?}, have {remaining:?}"
                    ),
                },
            ),
            BindingConstraint::InsufficientPolls {
                min_required,
                remaining,
            } => (
                Verdict::Stop,
                SupervisionDetail::BudgetRefused {
                    constraint: format!(
                        "insufficient polls: need {min_required}, have {remaining}"
                    ),
                },
            ),
        };

        EvidenceRecord {
            timestamp: self.timestamp,
            task_id: self.task_id,
            region_id: self.region_id,
            subsystem: Subsystem::Supervision,
            verdict,
            detail: EvidenceDetail::Supervision(detail),
        }
    }
}

/// Deterministic, append-only ledger of supervision evidence.
///
/// Collects structured [`EvidenceEntry`] records for every supervision
/// decision, making the full reasoning chain test-assertable.  Entries are
/// ordered by insertion (which is deterministic under virtual time).
///
/// # Test Usage
///
/// ```ignore
/// let ledger = supervisor.evidence();
/// assert_eq!(ledger.len(), 3);
/// assert!(matches!(
///     ledger.entries()[0].binding_constraint,
///     BindingConstraint::RestartAllowed { attempt: 1 },
/// ));
/// assert!(matches!(
///     ledger.entries()[2].binding_constraint,
///     BindingConstraint::WindowExhausted { .. },
/// ));
/// ```
#[derive(Debug, Clone, Default)]
pub struct EvidenceLedger {
    entries: Vec<EvidenceEntry>,
}

impl EvidenceLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an evidence entry.
    pub fn push(&mut self, entry: EvidenceEntry) {
        self.entries.push(entry);
    }

    /// All recorded entries, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Number of recorded entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries for a specific task.
    pub fn for_task(&self, task_id: TaskId) -> impl Iterator<Item = &EvidenceEntry> {
        self.entries.iter().filter(move |e| e.task_id == task_id)
    }

    /// Iterate over entries that resulted in a specific constraint kind.
    pub fn with_constraint<F>(&self, predicate: F) -> impl Iterator<Item = &EvidenceEntry>
    where
        F: Fn(&BindingConstraint) -> bool,
    {
        self.entries
            .iter()
            .filter(move |e| predicate(&e.binding_constraint))
    }

    /// Clear all entries (useful for test setup).
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Supervisor for managing actor restarts.
///
/// Integrates with the supervision strategy to decide whether to
/// restart, stop, or escalate on failure.
///
/// Every decision is recorded in an internal [`EvidenceLedger`], accessible
/// via [`evidence`](Self::evidence).  The ledger is deterministic and
/// test-assertable.
#[derive(Debug)]
pub struct Supervisor {
    strategy: SupervisionStrategy,
    history: Option<RestartHistory>,
    evidence: EvidenceLedger,
    generalized_evidence: crate::evidence::GeneralizedLedger,
}

impl Supervisor {
    /// Create a new supervisor with the given strategy.
    #[must_use]
    pub fn new(strategy: SupervisionStrategy) -> Self {
        let history = match &strategy {
            SupervisionStrategy::Restart(config) => Some(RestartHistory::new(config.clone())),
            _ => None,
        };
        Self {
            strategy,
            history,
            evidence: EvidenceLedger::new(),
            generalized_evidence: crate::evidence::GeneralizedLedger::new(),
        }
    }

    /// Get the supervision strategy.
    #[must_use]
    pub fn strategy(&self) -> &SupervisionStrategy {
        &self.strategy
    }

    fn record_evidence(&mut self, entry: EvidenceEntry) {
        let generalized_record = entry.to_evidence_record();
        self.evidence.push(entry);
        self.generalized_evidence.push(generalized_record);
    }

    #[allow(clippy::too_many_lines)]
    fn decide_err_with_budget(
        &mut self,
        task_id: TaskId,
        region_id: RegionId,
        parent_region_id: Option<RegionId>,
        now: u64,
        budget: Option<&mut Budget>,
    ) -> (SupervisionDecision, BindingConstraint) {
        match &mut self.strategy {
            SupervisionStrategy::Stop => (
                SupervisionDecision::Stop {
                    task_id,
                    region_id,
                    reason: StopReason::ExplicitStop,
                },
                BindingConstraint::ExplicitStopStrategy,
            ),
            SupervisionStrategy::Restart(config) => {
                let history = self.history.as_mut().expect("history exists for Restart");

                // Check budget constraints if a budget is provided.
                if let Some(b) = budget {
                    if let Err(refusal) = history.can_restart_with_budget(now, b) {
                        let constraint = match &refusal {
                            BudgetRefusal::WindowExhausted {
                                max_restarts,
                                window,
                            } => BindingConstraint::WindowExhausted {
                                max_restarts: *max_restarts,
                                window: *window,
                            },
                            BudgetRefusal::InsufficientCost {
                                required,
                                remaining,
                            } => BindingConstraint::InsufficientCost {
                                required: *required,
                                remaining: *remaining,
                            },
                            BudgetRefusal::DeadlineTooClose {
                                min_required,
                                remaining,
                            } => BindingConstraint::DeadlineTooClose {
                                min_required: *min_required,
                                remaining: *remaining,
                            },
                            BudgetRefusal::InsufficientPolls {
                                min_required,
                                remaining,
                            } => BindingConstraint::InsufficientPolls {
                                min_required: *min_required,
                                remaining: *remaining,
                            },
                        };

                        let decision = match refusal {
                            BudgetRefusal::WindowExhausted { .. } => SupervisionDecision::Stop {
                                task_id,
                                region_id,
                                reason: StopReason::RestartBudgetExhausted {
                                    total_restarts: u32::try_from(
                                        history.recent_restart_count(now),
                                    )
                                    .unwrap_or(u32::MAX),
                                    window: config.window,
                                },
                            },
                            _ => SupervisionDecision::Stop {
                                task_id,
                                region_id,
                                reason: StopReason::BudgetRefused(refusal),
                            },
                        };

                        return (decision, constraint);
                    }
                    if config.restart_cost > 0 {
                        b.consume_cost(config.restart_cost);
                    }
                } else if !history.can_restart(now) {
                    return (
                        SupervisionDecision::Stop {
                            task_id,
                            region_id,
                            reason: StopReason::RestartBudgetExhausted {
                                total_restarts: u32::try_from(history.recent_restart_count(now))
                                    .unwrap_or(u32::MAX),
                                window: config.window,
                            },
                        },
                        BindingConstraint::WindowExhausted {
                            max_restarts: config.max_restarts,
                            window: config.window,
                        },
                    );
                }

                // Atomically record restart and get attempt/delay to prevent race conditions
                // during concurrent failures where multiple threads could read the same
                // restart count and both record restarts, exceeding intended limits.
                let (attempt, delay) = match history.try_record_restart(now) {
                    Some((attempt, delay)) => (attempt, delay),
                    None => {
                        // Restart limit exceeded - this check should have been caught above
                        // but we double-check here for safety in concurrent scenarios
                        return (
                            SupervisionDecision::Stop {
                                task_id,
                                region_id,
                                reason: StopReason::RestartBudgetExhausted {
                                    total_restarts: u32::try_from(
                                        history.recent_restart_count(now),
                                    )
                                    .unwrap_or(u32::MAX),
                                    window: config.window,
                                },
                            },
                            BindingConstraint::WindowExhausted {
                                max_restarts: config.max_restarts,
                                window: config.window,
                            },
                        );
                    }
                };

                (
                    SupervisionDecision::Restart {
                        task_id,
                        region_id,
                        attempt,
                        delay,
                    },
                    BindingConstraint::RestartAllowed { attempt },
                )
            }
            SupervisionStrategy::Escalate => (
                SupervisionDecision::Escalate {
                    task_id,
                    region_id,
                    parent_region_id,
                    outcome: Outcome::Err(()),
                },
                BindingConstraint::EscalateStrategy,
            ),
        }
    }

    /// Decide what to do when an actor fails.
    ///
    /// Returns the supervision decision and optionally records a restart.
    /// This method checks only the sliding-window restart count; use
    /// [`on_failure_with_budget`](Self::on_failure_with_budget) for
    /// budget-aware decisions.
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
        outcome: &Outcome<(), ()>,
        now: u64,
    ) -> SupervisionDecision {
        self.on_failure_with_budget(task_id, region_id, parent_region_id, outcome, now, None)
    }

    /// Decide what to do when an actor fails, with budget awareness.
    ///
    /// Extends [`on_failure`](Self::on_failure) by checking the region's budget
    /// before allowing a restart:
    /// - Verifies cost quota can cover `restart_cost`
    /// - Verifies remaining time exceeds `min_remaining_for_restart`
    /// - Verifies poll quota exceeds `min_polls_for_restart`
    ///
    /// If the budget is `None`, only the sliding-window check is performed.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The failing actor's task ID
    /// * `region_id` - The region containing the actor
    /// * `parent_region_id` - The parent region (for escalation)
    /// * `outcome` - The failure outcome
    /// * `now` - Current virtual time (nanoseconds)
    /// * `budget` - Optional budget to check constraints against
    pub fn on_failure_with_budget(
        &mut self,
        task_id: TaskId,
        region_id: RegionId,
        parent_region_id: Option<RegionId>,
        outcome: &Outcome<(), ()>,
        now: u64,
        budget: Option<&mut Budget>,
    ) -> SupervisionDecision {
        let strategy_kind = match &self.strategy {
            SupervisionStrategy::Stop => "Stop",
            SupervisionStrategy::Restart(_) => "Restart",
            SupervisionStrategy::Escalate => "Escalate",
        };

        // SPORK monotone severity contract:
        // - Panics are never restartable.
        // - Cancellation is an external directive; it is not restartable.
        // - Only `Err` is eligible for `Restart(..)` and `Escalate`.
        let (decision, constraint) = match outcome {
            Outcome::Ok(()) => (
                SupervisionDecision::Stop {
                    task_id,
                    region_id,
                    reason: StopReason::ExplicitStop,
                },
                BindingConstraint::MonotoneSeverity { outcome_kind: "Ok" },
            ),
            Outcome::Cancelled(reason) => (
                SupervisionDecision::Stop {
                    task_id,
                    region_id,
                    reason: StopReason::Cancelled(reason.clone()),
                },
                BindingConstraint::MonotoneSeverity {
                    outcome_kind: "Cancelled",
                },
            ),
            Outcome::Panicked(_) => (
                SupervisionDecision::Stop {
                    task_id,
                    region_id,
                    reason: StopReason::Panicked,
                },
                BindingConstraint::MonotoneSeverity {
                    outcome_kind: "Panicked",
                },
            ),
            Outcome::Err(()) => {
                self.decide_err_with_budget(task_id, region_id, parent_region_id, now, budget)
            }
        };

        self.record_evidence(EvidenceEntry {
            timestamp: now,
            task_id,
            region_id,
            outcome: outcome.clone(),
            strategy_kind,
            decision: decision.clone(),
            binding_constraint: constraint,
        });

        decision
    }

    /// Get the restart history (if using Restart strategy).
    #[must_use]
    pub fn history(&self) -> Option<&RestartHistory> {
        self.history.as_ref()
    }

    /// Access the evidence ledger.
    ///
    /// Returns a reference to the append-only ledger containing one
    /// [`EvidenceEntry`] per supervision decision.
    #[must_use]
    pub fn evidence(&self) -> &EvidenceLedger {
        &self.evidence
    }

    /// Take ownership of the evidence ledger, replacing it with an empty one.
    ///
    /// Useful for draining evidence in test assertions.
    pub fn take_evidence(&mut self) -> EvidenceLedger {
        std::mem::take(&mut self.evidence)
    }

    /// Access the generalized evidence ledger.
    ///
    /// Returns a reference to the generalized ledger containing one
    /// [`EvidenceRecord`](crate::evidence::EvidenceRecord) per supervision
    /// decision.  This is the subsystem-agnostic format suitable for
    /// cross-subsystem rendering and analysis.
    #[must_use]
    pub fn generalized_evidence(&self) -> &crate::evidence::GeneralizedLedger {
        &self.generalized_evidence
    }

    /// Take ownership of the generalized evidence ledger.
    pub fn take_generalized_evidence(&mut self) -> crate::evidence::GeneralizedLedger {
        std::mem::take(&mut self.generalized_evidence)
    }
}

// ---------------------------------------------------------------------------
// Monitor + Down Notifications (bd-4r1ep)
//
// OTP-style monitors that deliver deterministic `Down` notifications when a
// monitored task terminates.  Ordering follows the deterministic ordering
// contracts from bd-12qan:
//
//   DOWN-ORDER:  sort by (vt(completion), tid)
//   DOWN-BATCH:  multiple downs in one quantum are sorted before enqueue
//   DOWN-CLEANUP: region close releases all monitors held by tasks in region
// ---------------------------------------------------------------------------

/// Opaque reference to an established monitor.
///
/// Returned when a monitor is created and included in the resulting
/// [`Down`] notification so the watcher can correlate which monitor fired.
///
/// `MonitorRef` values are globally unique within a runtime instance
/// (monotone counter).  They implement `Ord` for deterministic container use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonitorRef(u64);

impl MonitorRef {
    /// Create a `MonitorRef` for testing purposes.
    #[doc(hidden)]
    #[must_use]
    pub const fn new_for_test(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw id (useful for trace output).
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for MonitorRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mon{}", self.0)
    }
}

/// A `Down` notification delivered when a monitored task terminates.
///
/// # Deterministic Ordering (DOWN-ORDER)
///
/// When multiple downs are produced in the same scheduling quantum the
/// delivery order is `(completion_vt, monitored)` — virtual-time first,
/// then `TaskId` (ArenaIndex: generation, then slot) as tie-breaker.
///
/// # Fields
///
/// * `monitored` — the `TaskId` of the terminated process
/// * `reason`    — the termination `Outcome` (Ok / Err / Cancelled / Panicked)
/// * `monitor_ref` — the `MonitorRef` returned when the monitor was established
/// * `completion_vt` — virtual-time at which the termination was observed
#[derive(Debug, Clone)]
pub struct Down {
    /// The task that terminated.
    pub monitored: TaskId,
    /// The termination outcome.
    pub reason: Outcome<(), ()>,
    /// Reference identifying which monitor produced this notification.
    pub monitor_ref: MonitorRef,
    /// Virtual-time of the completion event (used for deterministic ordering).
    pub completion_vt: Time,
}

impl Down {
    /// Sorting key for deterministic batch delivery (DOWN-ORDER).
    ///
    /// Returns `(completion_vt, monitored)` so that `Vec<Down>` can be
    /// sorted with `.sort_by_key(|d| d.sort_key())`.
    #[must_use]
    pub fn sort_key(&self) -> (Time, TaskId) {
        (self.completion_vt, self.monitored)
    }
}

impl PartialEq for Down {
    fn eq(&self, other: &Self) -> bool {
        self.monitored == other.monitored
            && self.monitor_ref == other.monitor_ref
            && self.completion_vt == other.completion_vt
    }
}

impl Eq for Down {}

/// Internal bookkeeping for a single monitor relationship.
#[derive(Debug, Clone)]
struct MonitorEntry {
    /// The watching task.
    watcher: TaskId,
    /// Region that owns the watcher (for cleanup on region close).
    watcher_region: RegionId,
    /// The monitored task.
    monitored: TaskId,
}

/// Table managing all active monitors in a supervision context.
///
/// Provides:
/// - `monitor(watcher, monitored)` → `MonitorRef`
/// - `demonitor(ref)` — explicit removal
/// - `notify_down(task, &outcome, vt)` — produces sorted `Down` batch
/// - `cleanup_region(region)` — releases all monitors held by the region
///
/// # Determinism Invariants
///
/// - Uses `BTreeMap` keyed by `MonitorRef` for deterministic iteration.
/// - Down notifications are sorted by `(completion_vt, tid)` before return.
/// - No `HashMap` iteration order leaks into observable behavior.
#[derive(Debug)]
pub struct MonitorTable {
    /// Monotone counter for generating unique `MonitorRef` values.
    next_ref: u64,
    /// Active monitors indexed by `MonitorRef`.
    monitors: BTreeMap<MonitorRef, MonitorEntry>,
    /// Reverse index: monitored task → set of `MonitorRef` values watching it.
    /// Uses `Vec` (sorted on insertion) to avoid `HashSet` iteration order issues.
    by_monitored: BTreeMap<TaskId, Vec<MonitorRef>>,
    /// Reverse index: watcher region → set of `MonitorRef` values owned by it.
    by_region: BTreeMap<RegionId, Vec<MonitorRef>>,
}

impl Default for MonitorTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorTable {
    /// Create an empty monitor table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_ref: 0,
            monitors: BTreeMap::new(),
            by_monitored: BTreeMap::new(),
            by_region: BTreeMap::new(),
        }
    }

    /// Establish a monitor: `watcher` will be notified when `monitored` terminates.
    ///
    /// Returns a [`MonitorRef`] that uniquely identifies this monitor relationship.
    /// The same watcher may monitor the same task multiple times; each call
    /// returns a distinct `MonitorRef` (matching Erlang/OTP semantics).
    pub fn monitor(
        &mut self,
        watcher: TaskId,
        watcher_region: RegionId,
        monitored: TaskId,
    ) -> MonitorRef {
        let mref = MonitorRef(self.next_ref);
        self.next_ref += 1;

        let entry = MonitorEntry {
            watcher,
            watcher_region,
            monitored,
        };
        self.monitors.insert(mref, entry);

        // Maintain sorted reverse indices
        let refs = self.by_monitored.entry(monitored).or_default();
        let pos = refs.binary_search(&mref).unwrap_or_else(|p| p);
        refs.insert(pos, mref);

        let region_refs = self.by_region.entry(watcher_region).or_default();
        let pos = region_refs.binary_search(&mref).unwrap_or_else(|p| p);
        region_refs.insert(pos, mref);

        mref
    }

    /// Remove a specific monitor.
    ///
    /// Returns `true` if the monitor existed and was removed.
    pub fn demonitor(&mut self, mref: MonitorRef) -> bool {
        let Some(entry) = self.monitors.remove(&mref) else {
            return false;
        };
        Self::remove_from_index(&mut self.by_monitored, entry.monitored, mref);
        Self::remove_from_index(&mut self.by_region, entry.watcher_region, mref);
        true
    }

    /// Produce [`Down`] notifications for all monitors watching `task`.
    ///
    /// The returned `Vec<Down>` is sorted by `(completion_vt, monitored)`
    /// per the DOWN-BATCH contract.  All matching monitors are removed.
    pub fn notify_down(
        &mut self,
        task: TaskId,
        reason: &Outcome<(), ()>,
        completion_vt: Time,
    ) -> Vec<Down> {
        let refs = self.by_monitored.remove(&task).unwrap_or_default();
        let mut downs = Vec::with_capacity(refs.len());

        for mref in refs {
            if let Some(entry) = self.monitors.remove(&mref) {
                Self::remove_from_index(&mut self.by_region, entry.watcher_region, mref);
                downs.push(Down {
                    monitored: task,
                    reason: reason.clone(),
                    monitor_ref: mref,
                    completion_vt,
                });
            }
        }

        // DOWN-BATCH: sort by (vt, tid) before return
        downs.sort_by_key(Down::sort_key);
        downs
    }

    /// Produce a sorted batch of [`Down`] notifications for multiple tasks
    /// that terminated in the same scheduling quantum.
    ///
    /// Each `(TaskId, Outcome, Time)` triple is processed and the resulting
    /// notifications are merged into a single sorted batch (DOWN-BATCH).
    pub fn notify_down_batch(
        &mut self,
        terminations: &[(TaskId, Outcome<(), ()>, Time)],
    ) -> Vec<Down> {
        let mut all_downs = Vec::new();
        for (task, reason, vt) in terminations {
            all_downs.extend(self.notify_down(*task, reason, *vt));
        }
        // Final global sort to merge interleaved per-task batches
        all_downs.sort_by_key(Down::sort_key);
        all_downs
    }

    /// Release all monitors whose **watcher** belongs to `region`.
    ///
    /// This implements the DOWN-CLEANUP contract: when a region closes,
    /// all monitors held by tasks in that region are released.  No further
    /// `Down` notifications will be delivered for those monitors.
    ///
    /// Returns the number of monitors released.
    pub fn cleanup_region(&mut self, region: RegionId) -> usize {
        let refs = self.by_region.remove(&region).unwrap_or_default();
        let count = refs.len();
        for mref in refs {
            if let Some(entry) = self.monitors.remove(&mref) {
                Self::remove_from_index(&mut self.by_monitored, entry.monitored, mref);
            }
        }
        count
    }

    /// Number of active monitors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.monitors.len()
    }

    /// Returns `true` if there are no active monitors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.monitors.is_empty()
    }

    /// Returns all active `MonitorRef` values watching `task`.
    #[must_use]
    pub fn watchers_of(&self, task: TaskId) -> &[MonitorRef] {
        self.by_monitored.get(&task).map_or(&[], Vec::as_slice)
    }

    /// Look up the watcher for a given monitor reference.
    #[must_use]
    pub fn watcher_for(&self, mref: MonitorRef) -> Option<TaskId> {
        self.monitors.get(&mref).map(|e| e.watcher)
    }

    /// Look up the monitored task for a given monitor reference.
    #[must_use]
    pub fn monitored_for(&self, mref: MonitorRef) -> Option<TaskId> {
        self.monitors.get(&mref).map(|e| e.monitored)
    }

    /// Helper: remove a `MonitorRef` from a sorted `Vec`.
    fn remove_from_index<K>(index: &mut BTreeMap<K, Vec<MonitorRef>>, key: K, mref: MonitorRef)
    where
        K: Ord + Copy,
    {
        let remove_bucket = if let Some(bucket) = index.get_mut(&key) {
            if let Ok(pos) = bucket.binary_search(&mref) {
                bucket.remove(pos);
            }
            bucket.is_empty()
        } else {
            false
        };
        if remove_bucket {
            index.remove(&key);
        }
    }
}

/// Trace event for monitor activity.
///
/// Extends [`SupervisionEvent`] with monitor-specific events for observability.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    /// A monitor was established.
    Established {
        /// The monitoring task.
        watcher: TaskId,
        /// The monitored task.
        monitored: TaskId,
        /// The monitor reference.
        monitor_ref: MonitorRef,
    },

    /// A monitor was explicitly removed.
    Demonitored {
        /// The monitor reference that was removed.
        monitor_ref: MonitorRef,
    },

    /// A Down notification was produced.
    DownProduced {
        /// The terminated task.
        monitored: TaskId,
        /// The watching task that will receive the notification.
        watcher: TaskId,
        /// The monitor reference.
        monitor_ref: MonitorRef,
        /// Virtual time of the completion.
        completion_vt: Time,
    },

    /// Monitors were cleaned up due to region closure.
    RegionCleanup {
        /// The region that closed.
        region: RegionId,
        /// Number of monitors released.
        count: usize,
    },
}

#[cfg(test)]
include!("supervision_tests.rs");

// ============================================================================
// Conformance Tests
// ============================================================================

#[cfg(test)]
#[path = "supervision_conformance_tests.rs"]
mod supervision_conformance_tests;

#[cfg(test)]
mod conformance_integration {
    use super::supervision_conformance_tests::SupervisionConformanceHarness;

    #[test]
    fn supervision_conformance_suite() {
        crate::test_utils::init_test_logging();

        let harness = SupervisionConformanceHarness::new();

        // Run the full conformance test suite
        let report = harness.run_all_tests();

        let mut failures = Vec::new();
        let mut passes = 0;

        for result in report.results {
            if result.passed {
                passes += 1;
            } else {
                let reason = result
                    .error_message
                    .unwrap_or_else(|| "no failure reason reported".to_string());
                failures.push(format!("{}: {}", result.name, reason));
            }
        }

        assert!(
            failures.is_empty(),
            "Supervision conformance failures:\n{}",
            failures.join("\n")
        );

        assert!(
            passes > 0,
            "No conformance tests passed - harness may be broken"
        );

        crate::test_complete!("supervision_conformance_suite");
    }
}
