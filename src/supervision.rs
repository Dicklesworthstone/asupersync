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

use std::collections::BTreeMap;
use std::time::Duration;

use crate::runtime::{RegionCreateError, RuntimeState, SpawnError};
use crate::types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time};

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
            window: Duration::from_secs(60),
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
    pub name: String,
    /// Start factory (invoked at initial start and on restart).
    pub start: Box<dyn ChildStart>,
    /// Restart strategy for this child (Stop/Restart/Escalate).
    pub restart: SupervisionStrategy,
    /// Shutdown/cleanup budget for this child (used during supervisor stop).
    pub shutdown_budget: Budget,
    /// Explicit dependencies (child names). Used to compute deterministic start order.
    pub depends_on: Vec<String>,
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
    pub fn new<F>(name: impl Into<String>, start: F) -> Self
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
    pub fn depends_on(mut self, name: impl Into<String>) -> Self {
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
    DuplicateChildName(String),
    /// A dependency referenced an unknown child.
    UnknownDependency {
        /// Child name.
        child: String,
        /// Dependency name that was not present in the child set.
        depends_on: String,
    },
    /// Dependency graph contains a cycle.
    CycleDetected {
        /// Remaining nodes with non-zero in-degree (sorted).
        remaining: Vec<String>,
    },
}

impl std::fmt::Display for SupervisorCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateChildName(name) => write!(f, "duplicate child name: {name}"),
            Self::UnknownDependency { child, depends_on } => {
                write!(f, "child {child} depends on unknown child {depends_on}")
            }
            Self::CycleDetected { remaining } => write!(
                f,
                "dependency cycle detected among children: {}",
                remaining.join(", ")
            ),
        }
    }
}

impl std::error::Error for SupervisorCompileError {}

/// Errors that can occur when spawning a compiled supervisor.
#[derive(Debug)]
pub enum SupervisorSpawnError {
    /// Failed to create supervisor region.
    RegionCreate(RegionCreateError),
    /// Child start failed.
    ChildStartFailed {
        /// Child name.
        child: String,
        /// Underlying spawn error.
        err: SpawnError,
    },
}

impl std::fmt::Display for SupervisorSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionCreate(e) => write!(f, "supervisor region create failed: {e}"),
            Self::ChildStartFailed { child, err } => {
                write!(f, "child start failed: child={child} err={err}")
            }
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
    name: String,
    budget: Option<Budget>,
    tie_break: StartTieBreak,
    restart_policy: RestartPolicy,
    children: Vec<ChildSpec>,
}

impl SupervisorBuilder {
    /// Create a new supervisor builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
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

    /// Compile the topology into a deterministic start order.
    pub fn compile(self) -> Result<CompiledSupervisor, SupervisorCompileError> {
        CompiledSupervisor::new(self)
    }
}

/// A compiled supervisor topology with deterministic start order.
#[derive(Debug)]
pub struct CompiledSupervisor {
    /// Supervisor name (for trace/evidence output).
    pub name: String,
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
    pub cancel_order: Vec<String>,
    /// Children to restart in order (dependencies-first).
    pub restart_order: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadyKey {
    name: String,
    idx: usize,
}

impl Ord for ReadyKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.idx
            .cmp(&other.idx)
            .then_with(|| self.name.cmp(&other.name))
    }
}

impl PartialOrd for ReadyKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl CompiledSupervisor {
    fn new(builder: SupervisorBuilder) -> Result<Self, SupervisorCompileError> {
        let mut name_to_idx = std::collections::HashMap::<String, usize>::new();
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
            for dep in &child.depends_on {
                let Some(&dep_idx) = name_to_idx.get(dep) else {
                    return Err(SupervisorCompileError::UnknownDependency {
                        child: child.name.clone(),
                        depends_on: dep.clone(),
                    });
                };
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
            StartTieBreak::InsertionOrder => ready.iter().next().cloned(),
            StartTieBreak::NameLex => ready
                .iter()
                .min_by(|a, b| a.name.cmp(&b.name).then_with(|| a.idx.cmp(&b.idx)))
                .cloned(),
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
            SupervisionStrategy::Restart(_) => self.restart_plan_for_idx(failed_idx),
            SupervisionStrategy::Stop | SupervisionStrategy::Escalate => None,
        }
    }

    #[must_use]
    fn restart_plan_for_idx(&self, failed_child_idx: usize) -> Option<SupervisorRestartPlan> {
        let failed_pos = self
            .start_order
            .iter()
            .position(|&idx| idx == failed_child_idx)?;

        let positions: Vec<usize> = match self.restart_policy {
            RestartPolicy::OneForOne => vec![failed_pos],
            RestartPolicy::OneForAll => (0..self.start_order.len()).collect(),
            RestartPolicy::RestForOne => (failed_pos..self.start_order.len()).collect(),
        };

        let cancel_order = positions
            .iter()
            .rev()
            .map(|&pos| self.children[self.start_order[pos]].name.clone())
            .collect();

        let restart_order = positions
            .iter()
            .map(|&pos| self.children[self.start_order[pos]].name.clone())
            .collect();

        Some(SupervisorRestartPlan {
            policy: self.restart_policy,
            cancel_order,
            restart_order,
        })
    }

    /// Spawns the supervisor as a child region under `parent_region` and starts
    /// all `start_immediately` children in the compiled order.
    ///
    /// This method establishes the **region-owned structure** and deterministic start ordering.
    /// Restart semantics are specified by [`RestartPolicy`] and computed by
    /// [`CompiledSupervisor::restart_plan_for`]; wiring it into a live restart loop is layered
    /// on top by follow-up beads (bd-1yv7a, bd-35iz1).
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

        let mut started = Vec::new();
        for &idx in &self.start_order {
            let child = &mut self.children[idx];
            if !child.start_immediately {
                continue;
            }
            match child.start.start(&scope, state, cx) {
                Ok(task_id) => started.push(StartedChild {
                    name: child.name.clone(),
                    task_id,
                }),
                Err(err) => {
                    cx.trace("supervisor_child_start_failed");
                    if child.required {
                        return Err(SupervisorSpawnError::ChildStartFailed {
                            child: child.name.clone(),
                            err,
                        });
                    }
                }
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
    pub name: String,
    /// Region that owns the supervisor and its children.
    pub region: RegionId,
    /// Children that were started immediately (in start order).
    pub started: Vec<StartedChild>,
}

/// Information about a child started by a supervisor.
#[derive(Debug)]
pub struct StartedChild {
    /// Child name.
    pub name: String,
    /// Root task id for the child.
    pub task_id: TaskId,
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
#[derive(Debug, Clone, PartialEq)]
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

impl Eq for BudgetRefusal {}

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
        Self {
            timestamps: Vec::new(),
            window,
            storm_threshold,
        }
    }

    /// Record a restart at the given virtual time and prune old entries.
    pub fn record(&mut self, now: u64) {
        let window_nanos = self.window.as_nanos() as u64;
        let cutoff = now.saturating_sub(window_nanos);
        self.timestamps.retain(|&t| t >= cutoff);
        self.timestamps.push(now);
    }

    /// Compute the current restart intensity (restarts per second).
    ///
    /// Returns 0.0 if no restarts have been recorded in the window.
    #[must_use]
    pub fn intensity(&self, now: u64) -> f64 {
        let window_nanos = self.window.as_nanos() as u64;
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
        let window_nanos = self.window.as_nanos() as u64;
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
#[derive(Debug, Clone, PartialEq)]
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

impl Eq for BindingConstraint {}

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
                SupervisionDetail::MonotoneSeverity { outcome_kind },
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
        self.evidence.push(entry);
    }

    fn decide_err_with_budget(
        &mut self,
        task_id: TaskId,
        region_id: RegionId,
        parent_region_id: Option<RegionId>,
        now: u64,
        budget: Option<&Budget>,
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
                if let Some(budget) = budget {
                    if let Err(refusal) = history.can_restart_with_budget(now, budget) {
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
                                    total_restarts: config.max_restarts,
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
                } else if !history.can_restart(now) {
                    return (
                        SupervisionDecision::Stop {
                            task_id,
                            region_id,
                            reason: StopReason::RestartBudgetExhausted {
                                total_restarts: config.max_restarts,
                                window: config.window,
                            },
                        },
                        BindingConstraint::WindowExhausted {
                            max_restarts: config.max_restarts,
                            window: config.window,
                        },
                    );
                }

                let attempt = history.recent_restart_count(now) as u32 + 1;
                let delay = history.next_delay(now);
                history.record_restart(now);

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
        budget: Option<&Budget>,
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
    /// Unique reference for this monitor.
    monitor_ref: MonitorRef,
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
            monitor_ref: mref,
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
        Self::remove_from_vec(self.by_monitored.get_mut(&entry.monitored), mref);
        Self::remove_from_vec(self.by_region.get_mut(&entry.watcher_region), mref);
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
                Self::remove_from_vec(self.by_region.get_mut(&entry.watcher_region), mref);
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
                Self::remove_from_vec(self.by_monitored.get_mut(&entry.monitored), mref);
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
    fn remove_from_vec(vec: Option<&mut Vec<MonitorRef>>, mref: MonitorRef) {
        if let Some(v) = vec {
            if let Ok(pos) = v.binary_search(&mref) {
                v.remove(pos);
            }
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

    /// Helper: a `ChildStart`-compatible function that returns a dummy `TaskId`.
    /// Named functions satisfy the HRTB required by `ChildStart` where closures
    /// with inferred lifetimes do not.
    #[allow(clippy::unnecessary_wraps)]
    fn noop_start(
        _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
        _state: &mut RuntimeState,
        _cx: &crate::cx::Cx,
    ) -> Result<TaskId, SpawnError> {
        Ok(test_task_id())
    }

    use std::sync::{Arc, Mutex};

    struct LoggingStart {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl ChildStart for LoggingStart {
        fn start(
            &mut self,
            scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            state: &mut RuntimeState,
            cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            self.log
                .lock()
                .expect("poisoned")
                .push(self.name.to_string());
            let handle = scope.spawn_registered(state, cx, |_cx| async move { 0u8 })?;
            Ok(handle.task_id())
        }
    }

    #[test]
    fn stop_strategy_always_stops() {
        init_test("stop_strategy_always_stops");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
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

        // First error should trigger restart
        let decision =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second error should also restart
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000, // 1 second later
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 2, .. }
        ));

        crate::test_complete!("restart_strategy_allows_restarts");
    }

    #[test]
    fn restart_strategy_does_not_restart_cancelled() {
        init_test("restart_strategy_does_not_restart_cancelled");

        let config = RestartConfig::new(3, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
                ..
            }
        ));

        crate::test_complete!("restart_strategy_does_not_restart_cancelled");
    }

    #[test]
    fn restart_budget_exhaustion() {
        init_test("restart_budget_exhaustion");

        let config = RestartConfig::new(2, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed
        supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );

        // Third should stop
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
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
        supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            500_000_000, // 0.5 seconds
        );

        // Third failure after window should succeed (old ones expired)
        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
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
            &Outcome::Err(()),
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
    fn escalate_strategy_does_not_escalate_cancelled() {
        init_test("escalate_strategy_does_not_escalate_cancelled");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            &Outcome::Cancelled(CancelReason::user("test")),
            0,
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::Cancelled(_),
                ..
            }
        ));

        crate::test_complete!("escalate_strategy_does_not_escalate_cancelled");
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
            &Outcome::Panicked(PanicPayload::new("test panic")),
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

        let spec = ChildSpec::new("worker-1", noop_start)
            .with_restart(SupervisionStrategy::Restart(RestartConfig::default()))
            .with_shutdown_budget(Budget::with_deadline_secs(10))
            .with_registration(NameRegistrationPolicy::Register {
                name: "worker-1".to_string(),
                collision: NameCollisionPolicy::Fail,
            })
            .depends_on("db")
            .with_start_immediately(false)
            .with_required(false);

        assert_eq!(spec.name, "worker-1");
        assert!(matches!(spec.restart, SupervisionStrategy::Restart(_)));
        assert!(!spec.start_immediately);
        assert!(!spec.required);
        assert_eq!(spec.depends_on, vec!["db".to_string()]);

        crate::test_complete!("child_spec_builder");
    }

    #[test]
    fn child_spec_defaults() {
        init_test("child_spec_defaults");

        let spec = ChildSpec::new("default-child", noop_start);

        assert_eq!(spec.name, "default-child");
        assert!(matches!(spec.restart, SupervisionStrategy::Stop));
        assert_eq!(spec.shutdown_budget, Budget::INFINITE);
        assert!(spec.depends_on.is_empty());
        assert_eq!(spec.registration, NameRegistrationPolicy::None);
        assert!(spec.start_immediately);
        assert!(spec.required);

        crate::test_complete!("child_spec_defaults");
    }

    #[test]
    fn supervisor_builder_compile_order_insertion_tie_break() {
        init_test("supervisor_builder_compile_order_insertion_tie_break");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        assert_eq!(compiled.start_order, vec![0, 1, 2]);

        crate::test_complete!("supervisor_builder_compile_order_insertion_tie_break");
    }

    #[test]
    fn supervisor_builder_compile_detects_cycle() {
        init_test("supervisor_builder_compile_detects_cycle");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("b"))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let err = builder.compile().expect_err("should detect cycle");
        assert!(matches!(err, SupervisorCompileError::CycleDetected { .. }));

        crate::test_complete!("supervisor_builder_compile_detects_cycle");
    }

    #[test]
    fn compiled_supervisor_spawn_starts_children_in_order() {
        init_test("compiled_supervisor_spawn_starts_children_in_order");

        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let mk = |name: &'static str, log: &Arc<Mutex<Vec<String>>>| {
            ChildSpec::new(
                name,
                LoggingStart {
                    name,
                    log: Arc::clone(log),
                },
            )
        };

        let builder = SupervisorBuilder::new("sup")
            .child(mk("a", &log))
            .child(mk("b", &log).depends_on("a"))
            .child(mk("c", &log).depends_on("a"));

        let compiled = builder.compile().expect("compile");

        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();

        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("spawn");

        assert_eq!(handle.started.len(), 3);
        assert_eq!(
            *log.lock().expect("poisoned"),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );

        crate::test_complete!("compiled_supervisor_spawn_starts_children_in_order");
    }

    #[test]
    fn compiled_supervisor_restart_plan_one_for_one() {
        init_test("compiled_supervisor_restart_plan_one_for_one");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::OneForOne);
        assert_eq!(plan.cancel_order, vec!["b".to_string()]);
        assert_eq!(plan.restart_order, vec!["b".to_string()]);

        crate::test_complete!("compiled_supervisor_restart_plan_one_for_one");
    }

    #[test]
    fn compiled_supervisor_restart_plan_one_for_all() {
        init_test("compiled_supervisor_restart_plan_one_for_all");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::OneForAll);
        assert_eq!(
            plan.cancel_order,
            vec![
                "d".to_string(),
                "c".to_string(),
                "b".to_string(),
                "a".to_string()
            ]
        );
        assert_eq!(
            plan.restart_order,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );

        crate::test_complete!("compiled_supervisor_restart_plan_one_for_all");
    }

    #[test]
    fn compiled_supervisor_restart_plan_rest_for_one() {
        init_test("compiled_supervisor_restart_plan_rest_for_one");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"))
            .child(ChildSpec::new("d", noop_start).depends_on("c"));

        let compiled = builder.compile().expect("compile");
        let plan = compiled.restart_plan_for("b").expect("plan");

        assert_eq!(plan.policy, RestartPolicy::RestForOne);
        assert_eq!(
            plan.cancel_order,
            vec!["d".to_string(), "c".to_string(), "b".to_string()]
        );
        assert_eq!(
            plan.restart_order,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );

        crate::test_complete!("compiled_supervisor_restart_plan_rest_for_one");
    }

    #[test]
    fn compiled_supervisor_restart_plan_unknown_child_none() {
        init_test("compiled_supervisor_restart_plan_unknown_child_none");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        assert!(compiled.restart_plan_for("zzz").is_none());

        crate::test_complete!("compiled_supervisor_restart_plan_unknown_child_none");
    }

    #[test]
    fn compiled_supervisor_restart_plan_for_failure_monotone_severity() {
        init_test("compiled_supervisor_restart_plan_for_failure_monotone_severity");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(ChildSpec::new("a", noop_start))
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(ChildSpec::new("c", noop_start).depends_on("b"));

        let compiled = builder.compile().expect("compile");

        let ok: Outcome<(), ()> = Outcome::Ok(());
        let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::user("cancelled"));
        let panicked: Outcome<(), ()> = Outcome::Panicked(crate::types::PanicPayload::new("panic"));
        let err: Outcome<(), ()> = Outcome::Err(());

        assert!(compiled.restart_plan_for_failure("b", &ok).is_none());
        assert!(compiled.restart_plan_for_failure("b", &cancelled).is_none());
        assert!(compiled.restart_plan_for_failure("b", &panicked).is_none());

        let plan = compiled
            .restart_plan_for_failure("b", &err)
            .expect("restart plan");
        assert_eq!(plan.policy, RestartPolicy::OneForAll);

        crate::test_complete!("compiled_supervisor_restart_plan_for_failure_monotone_severity");
    }

    #[test]
    fn compiled_supervisor_restart_plan_for_failure_requires_restart_strategy() {
        init_test("compiled_supervisor_restart_plan_for_failure_requires_restart_strategy");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(ChildSpec::new("a", noop_start))
            .child(ChildSpec::new("b", noop_start).depends_on("a"));

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Default child strategy is Stop: no restart plan produced.
        assert!(compiled.restart_plan_for_failure("b", &err).is_none());

        crate::test_complete!(
            "compiled_supervisor_restart_plan_for_failure_requires_restart_strategy"
        );
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

    // ---- Tests for budget-aware restart decisions (bd-1yv7a) ----

    #[test]
    fn restart_config_budget_fields_default_to_disabled() {
        init_test("restart_config_budget_fields_default");

        let config = RestartConfig::default();
        assert_eq!(config.restart_cost, 0);
        assert_eq!(config.min_remaining_for_restart, None);
        assert_eq!(config.min_polls_for_restart, 0);

        crate::test_complete!("restart_config_budget_fields_default");
    }

    #[test]
    fn restart_config_budget_builders() {
        init_test("restart_config_budget_builders");

        let config = RestartConfig::new(5, Duration::from_secs(30))
            .with_restart_cost(100)
            .with_min_remaining(Duration::from_secs(5))
            .with_min_polls(50);

        assert_eq!(config.restart_cost, 100);
        assert_eq!(
            config.min_remaining_for_restart,
            Some(Duration::from_secs(5))
        );
        assert_eq!(config.min_polls_for_restart, 50);

        crate::test_complete!("restart_config_budget_builders");
    }

    #[test]
    fn budget_aware_restart_allowed_with_sufficient_budget() {
        init_test("budget_aware_restart_sufficient");

        let config = RestartConfig::new(3, Duration::from_secs(60))
            .with_restart_cost(10)
            .with_min_remaining(Duration::from_secs(5))
            .with_min_polls(100);

        let history = RestartHistory::new(config);

        // Budget with plenty of resources
        let budget = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(1000)
            .with_poll_quota(5000);

        // At t=0, should be allowed
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_sufficient");
    }

    #[test]
    fn budget_aware_restart_refused_insufficient_cost() {
        init_test("budget_aware_restart_insufficient_cost");

        let config = RestartConfig::new(3, Duration::from_secs(60)).with_restart_cost(100);

        let history = RestartHistory::new(config);

        // Budget with insufficient cost
        let budget = Budget::new().with_cost_quota(50);

        let result = history.can_restart_with_budget(0, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::InsufficientCost {
                required: 100,
                remaining: 50
            })
        ));

        crate::test_complete!("budget_aware_restart_insufficient_cost");
    }

    #[test]
    fn budget_aware_restart_refused_deadline_too_close() {
        init_test("budget_aware_restart_deadline_close");

        let config = RestartConfig::new(3, Duration::from_secs(60))
            .with_min_remaining(Duration::from_secs(10));

        let history = RestartHistory::new(config);

        // Budget with deadline 5 seconds from now, but we need 10 seconds
        let budget = Budget::with_deadline_secs(15); // deadline at t=15s

        // At t=12s (3 seconds remaining, need 10)
        let now_ns = 12_000_000_000u64;
        let result = history.can_restart_with_budget(now_ns, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::DeadlineTooClose { .. })
        ));

        crate::test_complete!("budget_aware_restart_deadline_close");
    }

    #[test]
    fn budget_aware_restart_refused_insufficient_polls() {
        init_test("budget_aware_restart_insufficient_polls");

        let config = RestartConfig::new(3, Duration::from_secs(60)).with_min_polls(500);

        let history = RestartHistory::new(config);

        // Budget with insufficient polls
        let budget = Budget::new().with_poll_quota(100);

        let result = history.can_restart_with_budget(0, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::InsufficientPolls {
                min_required: 500,
                remaining: 100
            })
        ));

        crate::test_complete!("budget_aware_restart_insufficient_polls");
    }

    #[test]
    fn budget_aware_restart_allowed_no_cost_quota_set() {
        init_test("budget_aware_restart_no_cost_quota");

        let config = RestartConfig::new(3, Duration::from_secs(60)).with_restart_cost(100);

        let history = RestartHistory::new(config);

        // Budget with no cost quota (unlimited)
        let budget = Budget::INFINITE;

        // Should succeed since no cost quota = unlimited
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_no_cost_quota");
    }

    #[test]
    fn budget_aware_restart_allowed_no_deadline() {
        init_test("budget_aware_restart_no_deadline");

        let config = RestartConfig::new(3, Duration::from_secs(60))
            .with_min_remaining(Duration::from_secs(10));

        let history = RestartHistory::new(config);

        // Budget with no deadline
        let budget = Budget::INFINITE;

        // Should succeed since no deadline = unlimited time
        assert!(history.can_restart_with_budget(0, &budget).is_ok());

        crate::test_complete!("budget_aware_restart_no_deadline");
    }

    #[test]
    fn supervisor_on_failure_with_budget_refuses_restart() {
        init_test("supervisor_on_failure_with_budget_refuses");

        let config = RestartConfig::new(10, Duration::from_secs(60)).with_restart_cost(100);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget with insufficient cost
        let budget = Budget::new().with_cost_quota(50);

        let decision = supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            0,
            Some(&budget),
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Stop {
                reason: StopReason::BudgetRefused(BudgetRefusal::InsufficientCost { .. }),
                ..
            }
        ));

        crate::test_complete!("supervisor_on_failure_with_budget_refuses");
    }

    #[test]
    fn supervisor_on_failure_with_budget_allows_restart() {
        init_test("supervisor_on_failure_with_budget_allows");

        let config = RestartConfig::new(3, Duration::from_secs(60)).with_restart_cost(10);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget with sufficient resources
        let budget = Budget::new().with_cost_quota(1000);

        let decision = supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            0,
            Some(&budget),
        );

        assert!(matches!(
            decision,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        crate::test_complete!("supervisor_on_failure_with_budget_allows");
    }

    #[test]
    fn supervisor_on_failure_without_budget_uses_window_only() {
        init_test("supervisor_on_failure_without_budget");

        let config = RestartConfig::new(2, Duration::from_secs(60)).with_restart_cost(10);

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed without budget checks
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Restart { attempt: 2, .. }
        ));

        // Third should be exhausted
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        assert!(matches!(
            d3,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("supervisor_on_failure_without_budget");
    }

    #[test]
    fn restart_intensity_basic() {
        init_test("restart_intensity_basic");

        let config = RestartConfig::new(10, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // No restarts = zero intensity
        assert!(history.intensity(0).abs() < f64::EPSILON);

        // 3 restarts in 10-second window = 0.3 restarts/second
        history.record_restart(1_000_000_000); // 1s
        history.record_restart(2_000_000_000); // 2s
        history.record_restart(3_000_000_000); // 3s

        let intensity = history.intensity(5_000_000_000);
        assert!((intensity - 0.3).abs() < 0.01);

        crate::test_complete!("restart_intensity_basic");
    }

    // ---- Tests for RestartIntensityWindow ----

    #[test]
    fn intensity_window_basic() {
        init_test("intensity_window_basic");

        let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 1.0);

        // No restarts
        assert_eq!(window.count(0), 0);
        assert!(window.intensity(0).abs() < f64::EPSILON);
        assert!(!window.is_storm(0));

        // Record some restarts
        window.record(1_000_000_000); // 1s
        window.record(2_000_000_000); // 2s
        window.record(3_000_000_000); // 3s

        assert_eq!(window.count(5_000_000_000), 3);
        let intensity = window.intensity(5_000_000_000);
        assert!((intensity - 0.3).abs() < 0.01); // 3 in 10s

        crate::test_complete!("intensity_window_basic");
    }

    #[test]
    fn intensity_window_storm_detection() {
        init_test("intensity_window_storm_detection");

        // Storm threshold: 2 restarts/second in a 5-second window
        let mut window = RestartIntensityWindow::new(Duration::from_secs(5), 2.0);

        // 5 restarts in first second
        for i in 0..5 {
            window.record(i * 200_000_000); // every 200ms
        }

        // 5 restarts in 5s = 1.0/s, below threshold
        assert!(!window.is_storm(1_000_000_000));

        // Add more restarts to exceed threshold
        for i in 0..10 {
            window.record(1_000_000_000 + i * 100_000_000); // every 100ms
        }

        // Now 15 restarts in 5s window = 3.0/s, above 2.0 threshold
        let now = 2_000_000_000;
        assert!(window.is_storm(now));

        crate::test_complete!("intensity_window_storm_detection");
    }

    #[test]
    fn intensity_window_prunes_old_entries() {
        init_test("intensity_window_prunes");

        let mut window = RestartIntensityWindow::new(Duration::from_secs(5), 1.0);

        // Record restarts at t=0s, 1s, 2s
        window.record(0);
        window.record(1_000_000_000);
        window.record(2_000_000_000);

        assert_eq!(window.count(3_000_000_000), 3);

        // At t=10s, old restarts should have expired
        // Record one more to trigger pruning
        window.record(10_000_000_000);
        assert_eq!(window.count(10_000_000_000), 1);

        crate::test_complete!("intensity_window_prunes");
    }

    #[test]
    fn budget_refusal_display() {
        init_test("budget_refusal_display");

        let refusals = vec![
            BudgetRefusal::WindowExhausted {
                max_restarts: 3,
                window: Duration::from_secs(60),
            },
            BudgetRefusal::InsufficientCost {
                required: 100,
                remaining: 50,
            },
            BudgetRefusal::DeadlineTooClose {
                min_required: Duration::from_secs(10),
                remaining: Duration::from_secs(3),
            },
            BudgetRefusal::InsufficientPolls {
                min_required: 500,
                remaining: 100,
            },
        ];

        for refusal in &refusals {
            let s = format!("{refusal}");
            assert!(!s.is_empty());
        }

        crate::test_complete!("budget_refusal_display");
    }

    #[test]
    fn deadline_already_passed_refuses_restart() {
        init_test("deadline_already_passed_refuses_restart");

        let config = RestartConfig::new(3, Duration::from_secs(60))
            .with_min_remaining(Duration::from_secs(1));

        let history = RestartHistory::new(config);

        // Budget with deadline already in the past
        let budget = Budget::with_deadline_secs(5); // deadline at t=5s

        // At t=10s, deadline has passed
        let result = history.can_restart_with_budget(10_000_000_000, &budget);
        assert!(matches!(
            result,
            Err(BudgetRefusal::DeadlineTooClose {
                remaining: Duration::ZERO,
                ..
            })
        ));

        crate::test_complete!("deadline_already_passed_refuses_restart");
    }

    #[test]
    fn budget_aware_checks_combined() {
        init_test("budget_aware_checks_combined");

        // Config requiring all budget constraints
        let config = RestartConfig::new(5, Duration::from_secs(60))
            .with_restart_cost(50)
            .with_min_remaining(Duration::from_secs(10))
            .with_min_polls(200);

        let history = RestartHistory::new(config);

        // Budget that passes all checks
        let good_budget = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(500)
            .with_poll_quota(1000);
        assert!(history.can_restart_with_budget(0, &good_budget).is_ok());

        // Budget that fails on cost
        let bad_cost = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(10)
            .with_poll_quota(1000);
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_cost),
            Err(BudgetRefusal::InsufficientCost { .. })
        ));

        // Budget that fails on deadline
        let bad_deadline = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(5))
            .with_cost_quota(500)
            .with_poll_quota(1000);
        // At t=0, 5 seconds remaining but we need 10
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_deadline),
            Err(BudgetRefusal::DeadlineTooClose { .. })
        ));

        // Budget that fails on polls
        let bad_polls = Budget::new()
            .with_deadline(crate::types::id::Time::from_secs(60))
            .with_cost_quota(500)
            .with_poll_quota(50);
        assert!(matches!(
            history.can_restart_with_budget(0, &bad_polls),
            Err(BudgetRefusal::InsufficientPolls { .. })
        ));

        crate::test_complete!("budget_aware_checks_combined");
    }

    // ---------------------------------------------------------------
    // Monitor + Down Notification tests (bd-4r1ep)
    // ---------------------------------------------------------------

    fn task_id(index: u32, gen: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(index, gen))
    }

    fn region_id(index: u32, gen: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(index, gen))
    }

    #[test]
    fn monitor_ref_display() {
        init_test("monitor_ref_display");
        let mref = MonitorRef::new_for_test(42);
        assert_eq!(format!("{mref}"), "Mon42");
        assert_eq!(mref.as_u64(), 42);
        crate::test_complete!("monitor_ref_display");
    }

    #[test]
    fn monitor_table_basic_lifecycle() {
        init_test("monitor_table_basic_lifecycle");

        let mut table = MonitorTable::new();
        assert!(table.is_empty());

        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);
        assert_eq!(table.len(), 1);
        assert_eq!(table.watchers_of(monitored), &[mref]);
        assert_eq!(table.watcher_for(mref), Some(watcher));
        assert_eq!(table.monitored_for(mref), Some(monitored));

        // Demonitor
        assert!(table.demonitor(mref));
        assert!(table.is_empty());
        assert!(table.watchers_of(monitored).is_empty());
        assert_eq!(table.watcher_for(mref), None);

        // Double demonitor is a no-op
        assert!(!table.demonitor(mref));

        crate::test_complete!("monitor_table_basic_lifecycle");
    }

    #[test]
    fn monitor_multiple_watchers_single_target() {
        init_test("monitor_multiple_watchers_single_target");

        let mut table = MonitorTable::new();
        let monitored = task_id(10, 0);
        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let region = region_id(0, 0);

        let ref_a = table.monitor(watcher_a, region, monitored);
        let ref_b = table.monitor(watcher_b, region, monitored);
        assert_eq!(table.len(), 2);

        let watchers = table.watchers_of(monitored);
        assert_eq!(watchers.len(), 2);
        assert!(watchers.contains(&ref_a));
        assert!(watchers.contains(&ref_b));

        crate::test_complete!("monitor_multiple_watchers_single_target");
    }

    #[test]
    fn monitor_same_pair_multiple_times() {
        init_test("monitor_same_pair_multiple_times");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let ref1 = table.monitor(watcher, region, monitored);
        let ref2 = table.monitor(watcher, region, monitored);
        assert_ne!(ref1, ref2);
        assert_eq!(table.len(), 2);

        crate::test_complete!("monitor_same_pair_multiple_times");
    }

    #[test]
    fn notify_down_basic() {
        init_test("notify_down_basic");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(5));
        assert_eq!(downs.len(), 1);
        assert_eq!(downs[0].monitored, monitored);
        assert_eq!(downs[0].monitor_ref, mref);
        assert_eq!(downs[0].completion_vt, Time::from_secs(5));

        assert!(table.is_empty());

        crate::test_complete!("notify_down_basic");
    }

    #[test]
    fn notify_down_multiple_watchers() {
        init_test("notify_down_multiple_watchers");

        let mut table = MonitorTable::new();
        let monitored = task_id(10, 0);
        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let region = region_id(0, 0);

        let _ref_a = table.monitor(watcher_a, region, monitored);
        let _ref_b = table.monitor(watcher_b, region, monitored);

        let downs = table.notify_down(monitored, &Outcome::Err(()), Time::from_secs(1));
        assert_eq!(downs.len(), 2);
        assert!(table.is_empty());

        crate::test_complete!("notify_down_multiple_watchers");
    }

    #[test]
    fn notify_down_ordering_by_vt_then_tid() {
        init_test("notify_down_ordering_by_vt_then_tid");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let t_low = task_id(1, 0);
        let t_high = task_id(5, 0);
        let t_mid = task_id(3, 0);

        table.monitor(watcher, region, t_low);
        table.monitor(watcher, region, t_high);
        table.monitor(watcher, region, t_mid);

        let terminations = vec![
            (t_high, Outcome::Ok(()), Time::from_secs(10)),
            (t_low, Outcome::Ok(()), Time::from_secs(10)),
            (t_mid, Outcome::Ok(()), Time::from_secs(10)),
        ];
        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 3);

        assert_eq!(downs[0].monitored, t_low);
        assert_eq!(downs[1].monitored, t_mid);
        assert_eq!(downs[2].monitored, t_high);

        crate::test_complete!("notify_down_ordering_by_vt_then_tid");
    }

    #[test]
    fn notify_down_ordering_vt_primary() {
        init_test("notify_down_ordering_vt_primary");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let t_early_high_id = task_id(99, 0);
        let t_late_low_id = task_id(1, 0);

        table.monitor(watcher, region, t_early_high_id);
        table.monitor(watcher, region, t_late_low_id);

        let terminations = vec![
            (t_late_low_id, Outcome::Ok(()), Time::from_secs(20)),
            (t_early_high_id, Outcome::Err(()), Time::from_secs(10)),
        ];
        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 2);

        assert_eq!(downs[0].monitored, t_early_high_id);
        assert_eq!(downs[0].completion_vt, Time::from_secs(10));
        assert_eq!(downs[1].monitored, t_late_low_id);
        assert_eq!(downs[1].completion_vt, Time::from_secs(20));

        crate::test_complete!("notify_down_ordering_vt_primary");
    }

    #[test]
    fn cleanup_region_releases_monitors() {
        init_test("cleanup_region_releases_monitors");

        let mut table = MonitorTable::new();
        let region_a = region_id(1, 0);
        let region_b = region_id(2, 0);

        let watcher_a = task_id(1, 0);
        let watcher_b = task_id(2, 0);
        let monitored = task_id(10, 0);

        table.monitor(watcher_a, region_a, monitored);
        table.monitor(watcher_b, region_b, monitored);
        assert_eq!(table.len(), 2);

        let released = table.cleanup_region(region_a);
        assert_eq!(released, 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.watchers_of(monitored).len(), 1);

        let released = table.cleanup_region(region_b);
        assert_eq!(released, 1);
        assert!(table.is_empty());

        crate::test_complete!("cleanup_region_releases_monitors");
    }

    #[test]
    fn cleanup_region_idempotent() {
        init_test("cleanup_region_idempotent");

        let mut table = MonitorTable::new();
        let region = region_id(1, 0);
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);

        table.monitor(watcher, region, monitored);
        assert_eq!(table.cleanup_region(region), 1);
        assert_eq!(table.cleanup_region(region), 0);

        crate::test_complete!("cleanup_region_idempotent");
    }

    #[test]
    fn notify_down_no_monitors_returns_empty() {
        init_test("notify_down_no_monitors_returns_empty");

        let mut table = MonitorTable::new();
        let task = task_id(99, 0);

        let downs = table.notify_down(task, &Outcome::Ok(()), Time::ZERO);
        assert!(downs.is_empty());

        crate::test_complete!("notify_down_no_monitors_returns_empty");
    }

    #[test]
    fn demonitor_prevents_down_delivery() {
        init_test("demonitor_prevents_down_delivery");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        let mref = table.monitor(watcher, region, monitored);
        assert!(table.demonitor(mref));

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(1));
        assert!(downs.is_empty());

        crate::test_complete!("demonitor_prevents_down_delivery");
    }

    #[test]
    fn region_cleanup_prevents_down_delivery() {
        init_test("region_cleanup_prevents_down_delivery");

        let mut table = MonitorTable::new();
        let watcher = task_id(1, 0);
        let monitored = task_id(2, 0);
        let region = region_id(0, 0);

        table.monitor(watcher, region, monitored);
        table.cleanup_region(region);

        let downs = table.notify_down(monitored, &Outcome::Ok(()), Time::from_secs(1));
        assert!(downs.is_empty());

        crate::test_complete!("region_cleanup_prevents_down_delivery");
    }

    #[test]
    fn down_sort_key_matches_contract() {
        init_test("down_sort_key_matches_contract");

        let d = Down {
            monitored: task_id(5, 2),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(0),
            completion_vt: Time::from_secs(42),
        };

        let (vt, tid) = d.sort_key();
        assert_eq!(vt, Time::from_secs(42));
        assert_eq!(tid, task_id(5, 2));

        crate::test_complete!("down_sort_key_matches_contract");
    }

    #[test]
    fn monitor_event_variants() {
        init_test("monitor_event_variants");

        let _established = MonitorEvent::Established {
            watcher: task_id(1, 0),
            monitored: task_id(2, 0),
            monitor_ref: MonitorRef::new_for_test(0),
        };
        let _demonitored = MonitorEvent::Demonitored {
            monitor_ref: MonitorRef::new_for_test(0),
        };
        let _down_produced = MonitorEvent::DownProduced {
            monitored: task_id(2, 0),
            watcher: task_id(1, 0),
            monitor_ref: MonitorRef::new_for_test(0),
            completion_vt: Time::from_secs(1),
        };
        let _cleanup = MonitorEvent::RegionCleanup {
            region: region_id(0, 0),
            count: 5,
        };

        crate::test_complete!("monitor_event_variants");
    }

    #[test]
    fn notify_down_batch_merges_and_sorts() {
        init_test("notify_down_batch_merges_and_sorts");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let tasks: Vec<TaskId> = (1..=5).map(|i| task_id(i, 0)).collect();
        for &t in &tasks {
            table.monitor(watcher, region, t);
        }

        let terminations = vec![
            (tasks[4], Outcome::Ok(()), Time::from_secs(3)),
            (tasks[0], Outcome::Err(()), Time::from_secs(1)),
            (tasks[2], Outcome::Ok(()), Time::from_secs(1)),
            (tasks[1], Outcome::Ok(()), Time::from_secs(2)),
            (tasks[3], Outcome::Err(()), Time::from_secs(1)),
        ];

        let downs = table.notify_down_batch(&terminations);
        assert_eq!(downs.len(), 5);

        // Expected order by (vt, tid):
        // vt=1: tid=1, tid=3, tid=4
        // vt=2: tid=2
        // vt=3: tid=5
        assert_eq!(downs[0].monitored, tasks[0]);
        assert_eq!(downs[1].monitored, tasks[2]);
        assert_eq!(downs[2].monitored, tasks[3]);
        assert_eq!(downs[3].monitored, tasks[1]);
        assert_eq!(downs[4].monitored, tasks[4]);

        assert!(table.is_empty());

        crate::test_complete!("notify_down_batch_merges_and_sorts");
    }

    #[test]
    fn monitor_ref_ordering_is_monotone() {
        init_test("monitor_ref_ordering_is_monotone");

        let mut table = MonitorTable::new();
        let watcher = task_id(0, 0);
        let region = region_id(0, 0);

        let ref1 = table.monitor(watcher, region, task_id(1, 0));
        let ref2 = table.monitor(watcher, region, task_id(2, 0));
        let ref3 = table.monitor(watcher, region, task_id(3, 0));

        assert!(ref1 < ref2);
        assert!(ref2 < ref3);

        crate::test_complete!("monitor_ref_ordering_is_monotone");
    }

    #[test]
    fn down_equality() {
        init_test("down_equality");

        let d1 = Down {
            monitored: task_id(1, 0),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        let d2 = Down {
            monitored: task_id(1, 0),
            reason: Outcome::Err(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        assert_eq!(d1, d2);

        let d3 = Down {
            monitored: task_id(2, 0),
            reason: Outcome::Ok(()),
            monitor_ref: MonitorRef::new_for_test(5),
            completion_vt: Time::from_secs(10),
        };
        assert_ne!(d1, d3);

        crate::test_complete!("down_equality");
    }

    // ---------------------------------------------------------------
    // Supervisor Conformance Suite (bd-1zpsd)
    //
    // Deterministic tests covering:
    // - Each restart policy with full decision chains
    // - Budget exhaustion behavior
    // - Escalation propagation
    // - Monotone severity enforcement
    // - Spawn integration with dependency ordering
    // ---------------------------------------------------------------

    /// Table-driven test: all `Outcome` variants crossed with all supervision
    /// strategies. Asserts the SPORK monotone-severity contract:
    /// - `Panicked` always stops.
    /// - `Cancelled` always stops (external directive; never restartable).
    /// - Only `Err` may restart (under `Restart`) or escalate (under `Escalate`).
    /// - `Ok` should not be routed into `on_failure`; we treat it as `Stop(ExplicitStop)`
    ///   as a deterministic fallback.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn conformance_monotone_severity_cross_product() {
        init_test("conformance_monotone_severity_cross_product");

        let outcomes: Vec<(&str, Outcome<(), ()>)> = vec![
            ("Ok", Outcome::Ok(())),
            ("Err", Outcome::Err(())),
            ("Cancelled", Outcome::Cancelled(CancelReason::user("test"))),
            (
                "Panicked",
                Outcome::Panicked(PanicPayload::new("test panic")),
            ),
        ];

        let strategies: Vec<(&str, SupervisionStrategy)> = vec![
            ("Stop", SupervisionStrategy::Stop),
            (
                "Restart",
                SupervisionStrategy::Restart(RestartConfig::new(10, Duration::from_secs(60))),
            ),
            ("Escalate", SupervisionStrategy::Escalate),
        ];

        let parent = RegionId::from_arena(ArenaIndex::new(0, 99));

        for (outcome_name, outcome) in &outcomes {
            for (strategy_name, strategy) in &strategies {
                let mut supervisor = Supervisor::new(strategy.clone());
                let decision = supervisor.on_failure(
                    test_task_id(),
                    test_region_id(),
                    Some(parent),
                    outcome,
                    0,
                );

                match (outcome_name, strategy_name) {
                    // Panicked always stops, regardless of strategy
                    (&"Panicked", _) => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::Panicked,
                                    ..
                                }
                            ),
                            "Panicked + {strategy_name} should Stop(Panicked)"
                        );
                    }
                    // Cancelled always stops, regardless of strategy
                    (&"Cancelled", _) => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::Cancelled(_),
                                    ..
                                }
                            ),
                            "Cancelled + {strategy_name} should Stop(Cancelled)"
                        );
                    }
                    // Stop strategy always stops
                    (_, &"Stop") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "{outcome_name} + Stop should Stop(ExplicitStop)"
                        );
                    }
                    // Escalate strategy escalates only on Err (Panicked/Cancelled handled above)
                    (&"Err", &"Escalate") => {
                        assert!(
                            matches!(decision, SupervisionDecision::Escalate { .. }),
                            "Err + Escalate should Escalate"
                        );
                    }
                    // Restart strategy restarts only on Err (Panicked/Cancelled handled above)
                    (&"Err", &"Restart") => {
                        assert!(
                            matches!(decision, SupervisionDecision::Restart { attempt: 1, .. }),
                            "Err + Restart should Restart(attempt=1)"
                        );
                    }
                    // Ok is a fallback (should not be treated as failure)
                    (&"Ok", &"Escalate") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "Ok + {strategy_name} should Stop(ExplicitStop) (fallback)"
                        );
                    }
                    (&"Ok", &"Restart") => {
                        assert!(
                            matches!(
                                decision,
                                SupervisionDecision::Stop {
                                    reason: StopReason::ExplicitStop,
                                    ..
                                }
                            ),
                            "Ok + {strategy_name} should Stop(ExplicitStop) (fallback)"
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }

        crate::test_complete!("conformance_monotone_severity_cross_product");
    }

    /// Conformance: OneForOne only cancels and restarts the failed child.
    /// Other children in the topology are untouched.
    #[test]
    fn conformance_one_for_one_isolates_failed_child() {
        init_test("conformance_one_for_one_isolates_failed_child");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForOne)
            .child(
                ChildSpec::new("db", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("cache", noop_start)
                    .depends_on("db")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("web", noop_start)
                    .depends_on("cache")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");

        // Fail "cache" — only "cache" should appear in the plan
        let err: Outcome<(), ()> = Outcome::Err(());
        let plan = compiled
            .restart_plan_for_failure("cache", &err)
            .expect("restart plan");

        assert_eq!(plan.policy, RestartPolicy::OneForOne);
        assert_eq!(plan.cancel_order, vec!["cache"]);
        assert_eq!(plan.restart_order, vec!["cache"]);

        // Fail "db" — only "db"
        let plan = compiled
            .restart_plan_for_failure("db", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["db"]);
        assert_eq!(plan.restart_order, vec!["db"]);

        // Fail "web" — only "web"
        let plan = compiled
            .restart_plan_for_failure("web", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["web"]);
        assert_eq!(plan.restart_order, vec!["web"]);

        crate::test_complete!("conformance_one_for_one_isolates_failed_child");
    }

    /// Conformance: OneForAll cancels all children in reverse start order and
    /// restarts all in start order, regardless of which child failed.
    #[test]
    fn conformance_one_for_all_restarts_all_children() {
        init_test("conformance_one_for_all_restarts_all_children");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("a", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("c", noop_start)
                    .depends_on("b")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Fail any child — ALL children are in the plan
        for failed in &["a", "b", "c"] {
            let plan = compiled
                .restart_plan_for_failure(failed, &err)
                .expect("restart plan");

            assert_eq!(plan.policy, RestartPolicy::OneForAll);
            // Cancel: reverse start order (c, b, a)
            assert_eq!(plan.cancel_order, vec!["c", "b", "a"]);
            // Restart: start order (a, b, c)
            assert_eq!(plan.restart_order, vec!["a", "b", "c"]);
        }

        crate::test_complete!("conformance_one_for_all_restarts_all_children");
    }

    /// Conformance: RestForOne cancels the failed child and all children started
    /// after it, then restarts that suffix in start order.
    #[test]
    fn conformance_rest_for_one_restarts_suffix() {
        init_test("conformance_rest_for_one_restarts_suffix");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::RestForOne)
            .child(
                ChildSpec::new("a", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("b", noop_start)
                    .depends_on("a")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("c", noop_start)
                    .depends_on("b")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("d", noop_start)
                    .depends_on("c")
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // Fail "b" — b, c, d are in the plan (suffix from b)
        let plan = compiled
            .restart_plan_for_failure("b", &err)
            .expect("restart plan");
        assert_eq!(plan.policy, RestartPolicy::RestForOne);
        assert_eq!(plan.cancel_order, vec!["d", "c", "b"]); // reverse start order
        assert_eq!(plan.restart_order, vec!["b", "c", "d"]); // start order

        // Fail "a" — all children (a is first)
        let plan = compiled
            .restart_plan_for_failure("a", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["d", "c", "b", "a"]);
        assert_eq!(plan.restart_order, vec!["a", "b", "c", "d"]);

        // Fail "d" — only d (last child, no suffix after it)
        let plan = compiled
            .restart_plan_for_failure("d", &err)
            .expect("restart plan");
        assert_eq!(plan.cancel_order, vec!["d"]);
        assert_eq!(plan.restart_order, vec!["d"]);

        crate::test_complete!("conformance_rest_for_one_restarts_suffix");
    }

    /// Conformance: escalation with no parent region (root-level supervisor).
    /// The decision should still be Escalate with parent_region_id = None.
    #[test]
    fn conformance_escalation_without_parent_region() {
        init_test("conformance_escalation_without_parent_region");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);

        let decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None, // no parent
            &Outcome::Err(()),
            0,
        );

        match decision {
            SupervisionDecision::Escalate {
                parent_region_id,
                task_id: tid,
                region_id: rid,
                ..
            } => {
                assert!(parent_region_id.is_none(), "root escalation has no parent");
                assert_eq!(tid, test_task_id());
                assert_eq!(rid, test_region_id());
            }
            other => unreachable!("expected Escalate, got {other:?}"),
        }

        crate::test_complete!("conformance_escalation_without_parent_region");
    }

    /// Conformance: after budget exhaustion, subsequent on_failure calls also
    /// return Stop (the supervisor doesn't magically recover restart ability).
    #[test]
    fn conformance_budget_exhaustion_idempotent_stop() {
        init_test("conformance_budget_exhaustion_idempotent_stop");

        let config = RestartConfig::new(1, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First failure: restarts
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second failure: budget exhausted → stop
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        // Third failure: still stop (exhaustion is sticky within window)
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        assert!(matches!(
            d3,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        crate::test_complete!("conformance_budget_exhaustion_idempotent_stop");
    }

    /// Conformance: budget refusal priority — window exhaustion is checked before
    /// per-constraint budget checks when no budget is provided.
    #[test]
    fn conformance_budget_refusal_checks_window_first() {
        init_test("conformance_budget_refusal_checks_window_first");

        let config = RestartConfig::new(1, Duration::from_secs(60))
            .with_restart_cost(100)
            .with_min_polls(500);

        let mut history = RestartHistory::new(config);

        // Exhaust the window
        history.record_restart(0);

        // Budget that would also fail on cost and polls
        let bad_budget = Budget::new().with_cost_quota(10).with_poll_quota(50);

        // Window exhaustion is checked first
        let result = history.can_restart_with_budget(1_000_000_000, &bad_budget);
        assert!(
            matches!(result, Err(BudgetRefusal::WindowExhausted { .. })),
            "window exhaustion should be checked before budget constraints"
        );

        crate::test_complete!("conformance_budget_refusal_checks_window_first");
    }

    /// Conformance: restart exactly at window boundary — restarts that fall
    /// exactly on the boundary of the sliding window are correctly counted or
    /// expired.
    #[test]
    fn conformance_restart_window_boundary_exact() {
        init_test("conformance_restart_window_boundary_exact");

        // Window of exactly 10 seconds, max 2 restarts
        let config = RestartConfig::new(2, Duration::from_secs(10));
        let mut history = RestartHistory::new(config);

        // Record restarts at t=0 and t=1s
        history.record_restart(0);
        history.record_restart(1_000_000_000);

        // At t=9.999s: both restarts still in window → cannot restart
        assert!(!history.can_restart(9_999_999_999));

        // At t=10s (exactly): the restart at t=0 is at the boundary
        // cutoff = 10_000_000_000 - 10_000_000_000 = 0
        // restart at t=0: 0 >= 0 → still counted
        // restart at t=1s: 1_000_000_000 >= 0 → still counted
        // → 2 restarts, cannot restart
        assert!(!history.can_restart(10_000_000_000));

        // At t=10.000000001s: restart at t=0 just expired
        // cutoff = 10_000_000_001 - 10_000_000_000 = 1
        // restart at t=0: 0 >= 1 → false, expired
        // restart at t=1s: 1_000_000_000 >= 1 → still counted
        // → 1 restart, can restart again
        assert!(history.can_restart(10_000_000_001));

        crate::test_complete!("conformance_restart_window_boundary_exact");
    }

    /// Conformance: supervision decision carries correct identifying fields.
    /// The task_id, region_id, and attempt numbers in the returned
    /// SupervisionDecision must exactly match the inputs and internal state.
    #[test]
    fn conformance_decision_carries_correct_ids() {
        init_test("conformance_decision_carries_correct_ids");

        let task = TaskId::from_arena(ArenaIndex::new(42, 7));
        let region = RegionId::from_arena(ArenaIndex::new(10, 3));
        let parent = RegionId::from_arena(ArenaIndex::new(0, 1));

        // Stop strategy
        {
            let mut sup = Supervisor::new(SupervisionStrategy::Stop);
            let decision = sup.on_failure(task, region, Some(parent), &Outcome::Err(()), 0);
            match decision {
                SupervisionDecision::Stop {
                    task_id: tid,
                    region_id: rid,
                    reason,
                } => {
                    assert_eq!(tid, task);
                    assert_eq!(rid, region);
                    assert_eq!(reason, StopReason::ExplicitStop);
                }
                other => unreachable!("expected Stop, got {other:?}"),
            }
        }

        // Restart strategy — verify attempt counter increments
        {
            let config = RestartConfig::new(5, Duration::from_secs(60));
            let mut sup = Supervisor::new(SupervisionStrategy::Restart(config));

            for expected_attempt in 1..=3u32 {
                let decision = sup.on_failure(
                    task,
                    region,
                    Some(parent),
                    &Outcome::Err(()),
                    u64::from(expected_attempt - 1) * 1_000_000_000,
                );
                match decision {
                    SupervisionDecision::Restart {
                        task_id: tid,
                        region_id: rid,
                        attempt,
                        ..
                    } => {
                        assert_eq!(tid, task);
                        assert_eq!(rid, region);
                        assert_eq!(attempt, expected_attempt);
                    }
                    other => {
                        unreachable!("expected Restart attempt={expected_attempt}, got {other:?}")
                    }
                }
            }
        }

        // Escalate strategy
        {
            let mut sup = Supervisor::new(SupervisionStrategy::Escalate);
            let decision = sup.on_failure(task, region, Some(parent), &Outcome::Err(()), 0);
            match decision {
                SupervisionDecision::Escalate {
                    task_id: tid,
                    region_id: rid,
                    parent_region_id,
                    ..
                } => {
                    assert_eq!(tid, task);
                    assert_eq!(rid, region);
                    assert_eq!(parent_region_id, Some(parent));
                }
                other => unreachable!("expected Escalate, got {other:?}"),
            }
        }

        crate::test_complete!("conformance_decision_carries_correct_ids");
    }

    /// Conformance: restart delay in the decision matches the backoff
    /// calculation for the correct attempt number.
    #[test]
    fn conformance_restart_delay_matches_backoff() {
        init_test("conformance_restart_delay_matches_backoff");

        let config = RestartConfig::new(5, Duration::from_secs(60)).with_backoff(
            BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(10),
                multiplier: 2.0,
            },
        );

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config.clone()));

        // Attempt 1: delay should be for attempt index 0 = 100ms
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        match d1 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 1);
                assert_eq!(delay, config.backoff.delay_for_attempt(0));
            }
            other => unreachable!("expected Restart, got {other:?}"),
        }

        // Attempt 2: delay should be for attempt index 1 = 200ms
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        match d2 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 2);
                assert_eq!(delay, config.backoff.delay_for_attempt(1));
            }
            other => unreachable!("expected Restart, got {other:?}"),
        }

        // Attempt 3: delay should be for attempt index 2 = 400ms
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2_000_000_000,
        );
        match d3 {
            SupervisionDecision::Restart { delay, attempt, .. } => {
                assert_eq!(attempt, 3);
                assert_eq!(delay, config.backoff.delay_for_attempt(2));
            }
            other => unreachable!("expected Restart, got {other:?}"),
        }

        crate::test_complete!("conformance_restart_delay_matches_backoff");
    }

    /// Conformance: spawn starts children in dependency order and
    /// skips non-start_immediately children.
    #[test]
    fn conformance_spawn_dependency_ordered_start() {
        init_test("conformance_spawn_dependency_ordered_start");

        let log = Arc::new(Mutex::new(Vec::new()));

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new(
                "db",
                LoggingStart {
                    name: "db",
                    log: Arc::clone(&log),
                },
            ))
            .child(
                ChildSpec::new(
                    "cache",
                    LoggingStart {
                        name: "cache",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("db"),
            )
            .child(
                ChildSpec::new(
                    "web",
                    LoggingStart {
                        name: "web",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("cache"),
            )
            .child(
                ChildSpec::new(
                    "deferred",
                    LoggingStart {
                        name: "deferred",
                        log: Arc::clone(&log),
                    },
                )
                .depends_on("db")
                .with_start_immediately(false),
            );

        let compiled = builder.compile().expect("compile");

        // Verify start order: db, cache, web (deferred is skipped)
        assert_eq!(compiled.start_order.len(), 4);
        assert_eq!(compiled.children[compiled.start_order[0]].name, "db");
        assert_eq!(compiled.children[compiled.start_order[1]].name, "cache");

        // Spawn with a minimal RuntimeState
        let mut state = RuntimeState::new();
        let parent = state.create_root_region(Budget::INFINITE);
        let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
        let handle = compiled
            .spawn(&mut state, &cx, parent, Budget::INFINITE)
            .expect("spawn");

        // Verify logged start order
        let started: Vec<String> = log.lock().expect("poisoned").clone();
        assert_eq!(started, vec!["db", "cache", "web"]);

        // deferred should not be started
        assert!(!started.contains(&"deferred".to_string()));

        // Supervisor handle has 3 started children (not deferred)
        assert_eq!(handle.started.len(), 3);
        assert_eq!(handle.started[0].name, "db");
        assert_eq!(handle.started[1].name, "cache");
        assert_eq!(handle.started[2].name, "web");

        crate::test_complete!("conformance_spawn_dependency_ordered_start");
    }

    /// Conformance: non-required child start failure doesn't fail the supervisor.
    /// Required child failure does fail the supervisor.
    #[test]
    fn conformance_spawn_required_vs_optional_child_failure() {
        #[allow(clippy::unnecessary_wraps)]
        fn failing_start(
            _scope: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _state: &mut RuntimeState,
            _cx: &crate::cx::Cx,
        ) -> Result<TaskId, SpawnError> {
            Err(SpawnError::RegionClosed(test_region_id()))
        }

        init_test("conformance_spawn_required_vs_optional_child_failure");

        // Optional child failure: supervisor succeeds
        {
            let builder = SupervisorBuilder::new("sup")
                .child(ChildSpec::new("ok_child", noop_start))
                .child(
                    ChildSpec::new("optional_fail", failing_start)
                        .with_required(false)
                        .depends_on("ok_child"),
                );

            let compiled = builder.compile().expect("compile");
            let mut state = RuntimeState::new();
            let parent = state.create_root_region(Budget::INFINITE);
            let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result = compiled.spawn(&mut state, &cx, parent, Budget::INFINITE);
            assert!(
                result.is_ok(),
                "optional child failure should not fail supervisor"
            );
        }

        // Required child failure: supervisor fails
        {
            let builder = SupervisorBuilder::new("sup")
                .child(ChildSpec::new("ok_child", noop_start))
                .child(
                    ChildSpec::new("required_fail", failing_start)
                        .with_required(true)
                        .depends_on("ok_child"),
                );

            let compiled = builder.compile().expect("compile");
            let mut state = RuntimeState::new();
            let parent = state.create_root_region(Budget::INFINITE);
            let cx: crate::cx::Cx = crate::cx::Cx::for_testing();
            let result = compiled.spawn(&mut state, &cx, parent, Budget::INFINITE);
            assert!(
                result.is_err(),
                "required child failure should fail supervisor"
            );
            match result.unwrap_err() {
                SupervisorSpawnError::ChildStartFailed { child, .. } => {
                    assert_eq!(child, "required_fail");
                }
                other @ SupervisorSpawnError::RegionCreate(_) => {
                    unreachable!("expected ChildStartFailed, got {other:?}");
                }
            }
        }

        crate::test_complete!("conformance_spawn_required_vs_optional_child_failure");
    }

    /// Conformance: CompiledSupervisor::restart_plan_for_failure returns
    /// None when the child has Stop strategy (even on Err outcome), and
    /// returns a plan when the child has Restart strategy on Err.
    /// Covers the interplay between per-child strategy and supervisor-level
    /// restart policy.
    #[test]
    fn conformance_per_child_strategy_vs_supervisor_policy() {
        init_test("conformance_per_child_strategy_vs_supervisor_policy");

        let builder = SupervisorBuilder::new("sup")
            .with_restart_policy(RestartPolicy::OneForAll)
            .child(
                ChildSpec::new("restartable", noop_start)
                    .with_restart(SupervisionStrategy::Restart(RestartConfig::default())),
            )
            .child(
                ChildSpec::new("stopper", noop_start)
                    .depends_on("restartable")
                    .with_restart(SupervisionStrategy::Stop),
            )
            .child(
                ChildSpec::new("escalator", noop_start)
                    .depends_on("restartable")
                    .with_restart(SupervisionStrategy::Escalate),
            );

        let compiled = builder.compile().expect("compile");
        let err: Outcome<(), ()> = Outcome::Err(());

        // restartable child with Err: plan exists (restart strategy)
        assert!(compiled
            .restart_plan_for_failure("restartable", &err)
            .is_some());

        // stopper child with Err: no plan (stop strategy)
        assert!(compiled.restart_plan_for_failure("stopper", &err).is_none());

        // escalator child with Err: no plan (escalate strategy, not restart)
        assert!(compiled
            .restart_plan_for_failure("escalator", &err)
            .is_none());

        crate::test_complete!("conformance_per_child_strategy_vs_supervisor_policy");
    }

    /// Conformance: after the restart window expires, the supervisor can
    /// restart again — demonstrating recovery from budget exhaustion.
    #[test]
    fn conformance_window_expiry_restores_restart_ability() {
        init_test("conformance_window_expiry_restores_restart_ability");

        // 1 restart allowed in a 5-second window
        let config = RestartConfig::new(1, Duration::from_secs(5));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // First failure at t=0: restart
        let d1 =
            supervisor.on_failure(test_task_id(), test_region_id(), None, &Outcome::Err(()), 0);
        assert!(matches!(
            d1,
            SupervisionDecision::Restart { attempt: 1, .. }
        ));

        // Second failure at t=1s: exhausted
        let d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1_000_000_000,
        );
        assert!(matches!(
            d2,
            SupervisionDecision::Stop {
                reason: StopReason::RestartBudgetExhausted { .. },
                ..
            }
        ));

        // Third failure at t=6s: window expired, can restart again
        let d3 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            6_000_000_000,
        );
        assert!(
            matches!(d3, SupervisionDecision::Restart { attempt: 1, .. }),
            "window expiry should restore restart ability"
        );

        crate::test_complete!("conformance_window_expiry_restores_restart_ability");
    }

    /// Conformance: RestartIntensityWindow storm detection threshold is exact.
    /// At exactly the threshold intensity, is_storm returns false; above
    /// the threshold it returns true.
    #[test]
    fn conformance_intensity_storm_threshold_boundary() {
        init_test("conformance_intensity_storm_threshold_boundary");

        // Threshold: 2.0 restarts/second in a 10-second window
        // → 20 restarts at threshold
        let mut window = RestartIntensityWindow::new(Duration::from_secs(10), 2.0);

        // Record exactly 20 restarts within the 10s window
        for i in 0u64..20 {
            window.record(i * 500_000_000); // every 0.5s
        }

        let now = 10_000_000_000; // t=10s
        let intensity = window.intensity(now);
        assert!(
            (intensity - 2.0).abs() < 0.01,
            "20 restarts in 10s should be ~2.0/s"
        );
        // At exactly the threshold: not a storm (uses > not >=)
        assert!(!window.is_storm(now));

        // One more restart pushes above threshold
        window.record(10_000_000_000);
        assert!(window.is_storm(10_000_000_000));

        crate::test_complete!("conformance_intensity_storm_threshold_boundary");
    }

    /// Conformance: compile detects duplicate child names.
    #[test]
    fn conformance_compile_rejects_duplicate_names() {
        init_test("conformance_compile_rejects_duplicate_names");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("worker", noop_start))
            .child(ChildSpec::new("worker", noop_start));

        let result = builder.compile();
        assert!(matches!(
            result,
            Err(SupervisorCompileError::DuplicateChildName(ref name)) if name == "worker"
        ));

        crate::test_complete!("conformance_compile_rejects_duplicate_names");
    }

    /// Conformance: compile detects unknown dependency references.
    #[test]
    fn conformance_compile_rejects_unknown_dependency() {
        init_test("conformance_compile_rejects_unknown_dependency");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("nonexistent"));

        let result = builder.compile();
        assert!(matches!(
            result,
            Err(SupervisorCompileError::UnknownDependency { ref child, ref depends_on })
                if child == "a" && depends_on == "nonexistent"
        ));

        crate::test_complete!("conformance_compile_rejects_unknown_dependency");
    }

    /// Conformance: compile detects dependency cycles.
    #[test]
    fn conformance_compile_rejects_cycles() {
        init_test("conformance_compile_rejects_cycles");

        let builder = SupervisorBuilder::new("sup")
            .child(ChildSpec::new("a", noop_start).depends_on("c"))
            .child(ChildSpec::new("b", noop_start).depends_on("a"))
            .child(ChildSpec::new("c", noop_start).depends_on("b"));

        let result = builder.compile();
        match result {
            Err(SupervisorCompileError::CycleDetected { remaining }) => {
                // All three are in the cycle
                assert_eq!(remaining.len(), 3);
                assert!(remaining.contains(&"a".to_string()));
                assert!(remaining.contains(&"b".to_string()));
                assert!(remaining.contains(&"c".to_string()));
            }
            other => unreachable!("expected CycleDetected, got {other:?}"),
        }

        crate::test_complete!("conformance_compile_rejects_cycles");
    }

    /// Conformance: NameLex tie-break produces alphabetical start order
    /// for children with no inter-dependencies.
    #[test]
    fn conformance_name_lex_tie_break() {
        init_test("conformance_name_lex_tie_break");

        let builder = SupervisorBuilder::new("sup")
            .with_tie_break(StartTieBreak::NameLex)
            .child(ChildSpec::new("zulu", noop_start))
            .child(ChildSpec::new("alpha", noop_start))
            .child(ChildSpec::new("mike", noop_start));

        let compiled = builder.compile().expect("compile");

        let names: Vec<&str> = compiled
            .start_order
            .iter()
            .map(|&idx| compiled.children[idx].name.as_str())
            .collect();

        assert_eq!(names, vec!["alpha", "mike", "zulu"]);

        crate::test_complete!("conformance_name_lex_tie_break");
    }

    // ---------------------------------------------------------------
    // Evidence Ledger Tests (bd-35iz1)
    // ---------------------------------------------------------------

    #[test]
    fn evidence_ledger_empty_on_creation() {
        init_test("evidence_ledger_empty_on_creation");

        let supervisor = Supervisor::new(SupervisionStrategy::Stop);
        assert!(supervisor.evidence().is_empty());
        assert_eq!(supervisor.evidence().len(), 0);

        crate::test_complete!("evidence_ledger_empty_on_creation");
    }

    #[test]
    fn evidence_records_explicit_stop_strategy() {
        init_test("evidence_records_explicit_stop_strategy");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let _decision = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 1);
        let entry = &ledger.entries()[0];
        assert_eq!(entry.timestamp, 1000);
        assert_eq!(entry.task_id, test_task_id());
        assert_eq!(entry.region_id, test_region_id());
        assert_eq!(entry.strategy_kind, "Stop");
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::ExplicitStopStrategy
        );

        crate::test_complete!("evidence_records_explicit_stop_strategy");
    }

    #[test]
    fn evidence_records_restart_allowed() {
        init_test("evidence_records_restart_allowed");

        let config = RestartConfig::new(3, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let _d1 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        let _d2 = supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 2);

        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 1 }
        );
        assert_eq!(ledger.entries()[0].timestamp, 1000);
        assert_eq!(ledger.entries()[0].strategy_kind, "Restart");

        assert_eq!(
            ledger.entries()[1].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 2 }
        );
        assert_eq!(ledger.entries()[1].timestamp, 2000);

        crate::test_complete!("evidence_records_restart_allowed");
    }

    #[test]
    fn evidence_records_window_exhaustion() {
        init_test("evidence_records_window_exhaustion");

        let window = Duration::from_secs(10);
        let config = RestartConfig::new(2, window);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts allowed
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );
        // Third should be window exhausted
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            3000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 3);

        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 1 }
        );
        assert_eq!(
            ledger.entries()[1].binding_constraint,
            BindingConstraint::RestartAllowed { attempt: 2 }
        );
        assert_eq!(
            ledger.entries()[2].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 2,
                window,
            }
        );

        crate::test_complete!("evidence_records_window_exhaustion");
    }

    #[test]
    fn evidence_records_monotone_severity_panicked() {
        init_test("evidence_records_monotone_severity_panicked");

        // Even with Restart strategy, panics produce MonotoneSeverity evidence
        let config = RestartConfig::new(5, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Panicked(PanicPayload::new("boom")),
            1000,
        );

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 1);
        assert_eq!(
            ledger.entries()[0].binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Panicked",
            }
        );
        assert_eq!(ledger.entries()[0].strategy_kind, "Restart");

        crate::test_complete!("evidence_records_monotone_severity_panicked");
    }

    #[test]
    fn evidence_records_monotone_severity_cancelled() {
        init_test("evidence_records_monotone_severity_cancelled");

        let config = RestartConfig::new(5, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Cancelled(CancelReason::user("test")),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::MonotoneSeverity {
                outcome_kind: "Cancelled",
            }
        );

        crate::test_complete!("evidence_records_monotone_severity_cancelled");
    }

    #[test]
    fn evidence_records_monotone_severity_ok() {
        init_test("evidence_records_monotone_severity_ok");

        let config = RestartConfig::new(5, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Ok(()),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::MonotoneSeverity { outcome_kind: "Ok" }
        );

        crate::test_complete!("evidence_records_monotone_severity_ok");
    }

    #[test]
    fn evidence_records_escalate_strategy() {
        init_test("evidence_records_escalate_strategy");

        let parent = RegionId::from_arena(ArenaIndex::new(0, 5));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);

        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            Some(parent),
            &Outcome::Err(()),
            1000,
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(entry.strategy_kind, "Escalate");
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::EscalateStrategy
        );

        crate::test_complete!("evidence_records_escalate_strategy");
    }

    #[test]
    fn evidence_records_budget_insufficient_cost() {
        init_test("evidence_records_budget_insufficient_cost");

        let config = RestartConfig::new(5, Duration::from_secs(60)).with_restart_cost(100);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let budget = Budget {
            cost_quota: Some(50),
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::InsufficientCost {
                required: 100,
                remaining: 50,
            }
        );

        crate::test_complete!("evidence_records_budget_insufficient_cost");
    }

    #[test]
    fn evidence_records_budget_insufficient_polls() {
        init_test("evidence_records_budget_insufficient_polls");

        let config = RestartConfig::new(5, Duration::from_secs(60)).with_min_polls(10);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        let budget = Budget {
            poll_quota: 5,
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert_eq!(
            entry.binding_constraint,
            BindingConstraint::InsufficientPolls {
                min_required: 10,
                remaining: 5,
            }
        );

        crate::test_complete!("evidence_records_budget_insufficient_polls");
    }

    #[test]
    fn evidence_records_budget_deadline_too_close() {
        init_test("evidence_records_budget_deadline_too_close");

        let config = RestartConfig::new(5, Duration::from_secs(60))
            .with_min_remaining(Duration::from_secs(10));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Budget deadline is 5 seconds from now but we need 10 seconds minimum
        let now_nanos = 1_000_000_000u64; // 1 second
        let deadline_nanos = 6_000_000_000u64; // 6 seconds (5 seconds remaining)
        let budget = Budget {
            deadline: Some(Time::from_nanos(deadline_nanos)),
            ..Budget::INFINITE
        };
        supervisor.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            now_nanos,
            Some(&budget),
        );

        let entry = &supervisor.evidence().entries()[0];
        assert!(matches!(
            entry.binding_constraint,
            BindingConstraint::DeadlineTooClose { .. }
        ));

        crate::test_complete!("evidence_records_budget_deadline_too_close");
    }

    #[test]
    fn evidence_full_lifecycle_restart_to_exhaustion() {
        init_test("evidence_full_lifecycle_restart_to_exhaustion");

        let window = Duration::from_secs(60);
        let config = RestartConfig::new(3, window);
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // 3 restarts, then exhaustion, then another attempt (still exhausted)
        for i in 0u64..5 {
            supervisor.on_failure(
                test_task_id(),
                test_region_id(),
                None,
                &Outcome::Err(()),
                i * 1_000_000_000,
            );
        }

        let ledger = supervisor.evidence();
        assert_eq!(ledger.len(), 5);

        // First 3: RestartAllowed
        for (idx, expected_attempt) in [(0, 1u32), (1, 2), (2, 3)] {
            assert_eq!(
                ledger.entries()[idx].binding_constraint,
                BindingConstraint::RestartAllowed {
                    attempt: expected_attempt,
                }
            );
        }

        // 4th and 5th: WindowExhausted
        for idx in 3..5 {
            assert_eq!(
                ledger.entries()[idx].binding_constraint,
                BindingConstraint::WindowExhausted {
                    max_restarts: 3,
                    window,
                }
            );
        }

        crate::test_complete!("evidence_full_lifecycle_restart_to_exhaustion");
    }

    #[test]
    fn evidence_for_task_filter() {
        init_test("evidence_for_task_filter");

        let config = RestartConfig::new(5, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));
        let task_a = TaskId::from_arena(ArenaIndex::new(0, 1));
        let task_b = TaskId::from_arena(ArenaIndex::new(0, 2));

        supervisor.on_failure(task_a, test_region_id(), None, &Outcome::Err(()), 1000);
        supervisor.on_failure(task_b, test_region_id(), None, &Outcome::Err(()), 2000);
        supervisor.on_failure(task_a, test_region_id(), None, &Outcome::Err(()), 3000);

        let a_entries: Vec<_> = supervisor.evidence().for_task(task_a).collect();
        assert_eq!(a_entries.len(), 2);
        assert_eq!(a_entries[0].timestamp, 1000);
        assert_eq!(a_entries[1].timestamp, 3000);

        assert_eq!(supervisor.evidence().for_task(task_b).count(), 1);

        crate::test_complete!("evidence_for_task_filter");
    }

    #[test]
    fn evidence_with_constraint_filter() {
        init_test("evidence_with_constraint_filter");

        let config = RestartConfig::new(2, Duration::from_secs(60));
        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(config));

        // Two restarts then a panicked outcome
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        );
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Panicked(PanicPayload::new("oops")),
            3000,
        );

        assert_eq!(
            supervisor
                .evidence()
                .with_constraint(|c| matches!(c, BindingConstraint::RestartAllowed { .. }))
                .count(),
            2
        );

        assert_eq!(
            supervisor
                .evidence()
                .with_constraint(|c| matches!(c, BindingConstraint::MonotoneSeverity { .. }))
                .count(),
            1
        );

        crate::test_complete!("evidence_with_constraint_filter");
    }

    #[test]
    fn evidence_take_drains_ledger() {
        init_test("evidence_take_drains_ledger");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        supervisor.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        );

        assert_eq!(supervisor.evidence().len(), 1);
        let taken = supervisor.take_evidence();
        assert_eq!(taken.len(), 1);
        assert!(supervisor.evidence().is_empty());

        crate::test_complete!("evidence_take_drains_ledger");
    }

    #[test]
    fn evidence_deterministic_across_strategies() {
        init_test("evidence_deterministic_across_strategies");

        // Verify that the same inputs always produce the same evidence,
        // regardless of strategy — evidence is a deterministic function of inputs.
        let outcomes = [
            Outcome::Ok(()),
            Outcome::Err(()),
            Outcome::Cancelled(CancelReason::user("test")),
            Outcome::Panicked(PanicPayload::new("boom")),
        ];

        for strategy in [
            SupervisionStrategy::Stop,
            SupervisionStrategy::Restart(RestartConfig::new(5, Duration::from_secs(60))),
            SupervisionStrategy::Escalate,
        ] {
            let mut sup_a = Supervisor::new(strategy.clone());
            let mut sup_b = Supervisor::new(strategy);

            for (i, outcome) in outcomes.iter().enumerate() {
                let t = (i as u64) * 1000;
                sup_a.on_failure(test_task_id(), test_region_id(), None, outcome, t);
                sup_b.on_failure(test_task_id(), test_region_id(), None, outcome, t);
            }

            let a = sup_a.evidence();
            let b = sup_b.evidence();
            assert_eq!(a.len(), b.len());
            for (ea, eb) in a.entries().iter().zip(b.entries().iter()) {
                assert_eq!(ea.timestamp, eb.timestamp);
                assert_eq!(ea.strategy_kind, eb.strategy_kind);
                assert_eq!(ea.binding_constraint, eb.binding_constraint);
            }
        }

        crate::test_complete!("evidence_deterministic_across_strategies");
    }

    #[test]
    fn evidence_binding_constraint_display() {
        init_test("evidence_binding_constraint_display");

        // Verify Display impls produce useful human-readable strings
        let constraints = vec![
            (
                BindingConstraint::MonotoneSeverity {
                    outcome_kind: "Panicked",
                },
                "monotone severity: Panicked is not restartable",
            ),
            (BindingConstraint::ExplicitStopStrategy, "strategy is Stop"),
            (BindingConstraint::EscalateStrategy, "strategy is Escalate"),
            (
                BindingConstraint::RestartAllowed { attempt: 3 },
                "restart allowed (attempt 3)",
            ),
            (
                BindingConstraint::WindowExhausted {
                    max_restarts: 5,
                    window: Duration::from_secs(60),
                },
                "window exhausted: 5 restarts in 60s",
            ),
            (
                BindingConstraint::InsufficientCost {
                    required: 100,
                    remaining: 42,
                },
                "insufficient cost: need 100, have 42",
            ),
            (
                BindingConstraint::InsufficientPolls {
                    min_required: 10,
                    remaining: 3,
                },
                "insufficient polls: need 10, have 3",
            ),
        ];

        for (constraint, expected) in constraints {
            assert_eq!(format!("{constraint}"), expected);
        }

        crate::test_complete!("evidence_binding_constraint_display");
    }

    #[test]
    fn evidence_window_exhaustion_with_budget_vs_without() {
        init_test("evidence_window_exhaustion_with_budget_vs_without");

        let window = Duration::from_secs(60);
        let config = RestartConfig::new(1, window);

        // Without budget: exhaust via can_restart(now)
        let mut sup_no_budget = Supervisor::new(SupervisionStrategy::Restart(config.clone()));
        sup_no_budget.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
        ); // restart
        sup_no_budget.on_failure(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
        ); // exhausted

        // With budget (sufficient): exhaust via can_restart_with_budget
        let mut sup_budget = Supervisor::new(SupervisionStrategy::Restart(config));
        let budget = Budget::INFINITE;
        sup_budget.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            1000,
            Some(&budget),
        ); // restart
        sup_budget.on_failure_with_budget(
            test_task_id(),
            test_region_id(),
            None,
            &Outcome::Err(()),
            2000,
            Some(&budget),
        ); // exhausted

        // Both should produce WindowExhausted as the binding constraint
        assert_eq!(
            sup_no_budget.evidence().entries()[1].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 1,
                window,
            }
        );
        assert_eq!(
            sup_budget.evidence().entries()[1].binding_constraint,
            BindingConstraint::WindowExhausted {
                max_restarts: 1,
                window,
            }
        );

        crate::test_complete!("evidence_window_exhaustion_with_budget_vs_without");
    }

    // -----------------------------------------------------------------------
    // Evidence Emission Wiring tests (bd-a7etx)
    //
    // Verify that every supervision decision also produces a generalized
    // EvidenceRecord consistent with the domain-specific EvidenceEntry.
    // -----------------------------------------------------------------------

    #[test]
    fn emission_wiring_restart_produces_generalized_record() {
        init_test("emission_wiring_restart_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, Subsystem, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 3,
            window: Duration::from_secs(60),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 1_000);

        // Domain-specific ledger should have the entry.
        assert_eq!(supervisor.evidence().len(), 1);
        // Generalized ledger should also have the entry.
        let gen = supervisor.generalized_evidence();
        assert_eq!(gen.len(), 1);

        let record = &gen.entries()[0];
        assert_eq!(record.subsystem, crate::evidence::Subsystem::Supervision);
        assert_eq!(record.verdict, Verdict::Restart);
        assert_eq!(record.task_id, task);
        assert_eq!(record.region_id, region);
        assert_eq!(record.timestamp, 1_000);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::RestartAllowed { attempt: 1, .. })
        ));

        crate::test_complete!("emission_wiring_restart_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_stop_produces_generalized_record() {
        init_test("emission_wiring_stop_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 2_000);

        let gen = supervisor.generalized_evidence();
        assert_eq!(gen.len(), 1);

        let record = &gen.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::ExplicitStop)
        ));

        crate::test_complete!("emission_wiring_stop_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_escalate_produces_generalized_record() {
        init_test("emission_wiring_escalate_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Escalate);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 3_000);

        let gen = supervisor.generalized_evidence();
        assert_eq!(gen.len(), 1);

        let record = &gen.entries()[0];
        assert_eq!(record.verdict, Verdict::Escalate);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::ExplicitEscalate)
        ));

        crate::test_complete!("emission_wiring_escalate_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_monotone_severity_produces_generalized_record() {
        init_test("emission_wiring_monotone_severity_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 3,
            window: Duration::from_secs(60),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        // Panicked — should produce Stop with MonotoneSeverity.
        supervisor.on_failure(
            task,
            region,
            None,
            &Outcome::Panicked(PanicPayload::new("oops")),
            4_000,
        );

        let gen = supervisor.generalized_evidence();
        let record = &gen.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::MonotoneSeverity {
                outcome_kind: "Panicked"
            })
        ));

        crate::test_complete!("emission_wiring_monotone_severity_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_window_exhaustion_produces_generalized_record() {
        init_test("emission_wiring_window_exhaustion_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 1,
            window: Duration::from_secs(60),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        // First failure: restart allowed.
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 5_000);
        // Second failure: window exhausted.
        supervisor.on_failure(task, region, None, &Outcome::Err(()), 6_000);

        let gen = supervisor.generalized_evidence();
        assert_eq!(gen.len(), 2);

        // First: restart.
        assert_eq!(gen.entries()[0].verdict, Verdict::Restart);

        // Second: stop due to window exhaustion.
        let record = &gen.entries()[1];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::WindowExhausted {
                max_restarts: 1,
                ..
            })
        ));

        crate::test_complete!("emission_wiring_window_exhaustion_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_budget_refused_produces_generalized_record() {
        init_test("emission_wiring_budget_refused_produces_generalized_record");
        use crate::evidence::{EvidenceDetail, SupervisionDetail, Verdict};

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 5,
            window: Duration::from_secs(60),
            restart_cost: 100,
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        // Budget with only 10 cost remaining — insufficient for restart_cost=100.
        let budget = Budget::new().with_cost_quota(10);
        supervisor.on_failure_with_budget(
            task,
            region,
            None,
            &Outcome::Err(()),
            7_000,
            Some(&budget),
        );

        let gen = supervisor.generalized_evidence();
        assert_eq!(gen.len(), 1);

        let record = &gen.entries()[0];
        assert_eq!(record.verdict, Verdict::Stop);
        assert!(matches!(
            record.detail,
            EvidenceDetail::Supervision(SupervisionDetail::BudgetRefused { .. })
        ));

        // Verify the constraint message contains useful info.
        if let EvidenceDetail::Supervision(SupervisionDetail::BudgetRefused { constraint }) =
            &record.detail
        {
            assert!(constraint.contains("insufficient cost"));
        }

        crate::test_complete!("emission_wiring_budget_refused_produces_generalized_record");
    }

    #[test]
    fn emission_wiring_ledgers_stay_in_sync() {
        init_test("emission_wiring_ledgers_stay_in_sync");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 5,
            window: Duration::from_secs(60),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        // Multiple decisions.
        for i in 0..3 {
            supervisor.on_failure(task, region, None, &Outcome::Err(()), (i + 1) * 1_000);
        }

        // Both ledgers should have the same count.
        assert_eq!(supervisor.evidence().len(), 3);
        assert_eq!(supervisor.generalized_evidence().len(), 3);

        // Timestamps should match entry-by-entry.
        for (domain, generalized) in supervisor
            .evidence()
            .entries()
            .iter()
            .zip(supervisor.generalized_evidence().entries().iter())
        {
            assert_eq!(domain.timestamp, generalized.timestamp);
            assert_eq!(domain.task_id, generalized.task_id);
            assert_eq!(domain.region_id, generalized.region_id);
        }

        crate::test_complete!("emission_wiring_ledgers_stay_in_sync");
    }

    #[test]
    fn emission_wiring_take_generalized_drains() {
        init_test("emission_wiring_take_generalized_drains");

        let mut supervisor = Supervisor::new(SupervisionStrategy::Stop);
        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        supervisor.on_failure(task, region, None, &Outcome::Err(()), 8_000);
        assert_eq!(supervisor.generalized_evidence().len(), 1);

        let taken = supervisor.take_generalized_evidence();
        assert_eq!(taken.len(), 1);
        assert!(supervisor.generalized_evidence().is_empty());

        // Domain-specific ledger is independent — still has its entry.
        assert_eq!(supervisor.evidence().len(), 1);

        crate::test_complete!("emission_wiring_take_generalized_drains");
    }

    #[test]
    fn emission_wiring_render_is_deterministic() {
        init_test("emission_wiring_render_is_deterministic");

        let mut sup_a = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 2,
            window: Duration::from_secs(60),
            ..Default::default()
        }));
        let mut sup_b = Supervisor::new(SupervisionStrategy::Restart(RestartConfig {
            max_restarts: 2,
            window: Duration::from_secs(60),
            ..Default::default()
        }));

        let task = TaskId::from_arena(ArenaIndex::new(0, 1));
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));

        // Same sequence of decisions on both supervisors.
        for t in [1_000u64, 2_000, 3_000] {
            sup_a.on_failure(task, region, None, &Outcome::Err(()), t);
            sup_b.on_failure(task, region, None, &Outcome::Err(()), t);
        }

        // Generalized ledger render is byte-for-byte identical.
        assert_eq!(
            sup_a.generalized_evidence().render(),
            sup_b.generalized_evidence().render()
        );

        // Render is non-empty and contains expected markers.
        let rendered = sup_a.generalized_evidence().render();
        assert!(rendered.contains("supervision"));
        assert!(rendered.contains("RESTART"));

        crate::test_complete!("emission_wiring_render_is_deterministic");
    }
}
