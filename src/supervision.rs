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

use crate::runtime::{RegionCreateError, RuntimeState, SpawnError};
use crate::types::{Budget, CancelReason, Outcome, RegionId, TaskId};

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
    /// Child specifications (including start factories).
    pub children: Vec<ChildSpec>,
    /// Deterministic start order as indices into `children`.
    pub start_order: Vec<usize>,
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
            children: builder.children,
            start_order: order,
        })
    }

    /// Spawns the supervisor as a child region under `parent_region` and starts
    /// all `start_immediately` children in the compiled order.
    ///
    /// This method is intentionally minimal: it establishes the **region-owned
    /// structure** and deterministic start ordering. Full restart semantics
    /// (one_for_one/one_for_all/rest_for_one, budgets, evidence ledgers) are
    /// layered on top by follow-up beads (bd-3ddsi, bd-1yv7a, bd-35iz1).
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
