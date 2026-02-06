//! Cancellation reason and kind types.
//!
//! Cancellation in Asupersync is a first-class protocol, not a silent drop.
//! This module defines the types that describe why and how cancellation occurred.
//!
//! # Cleanup Budget Policy
//!
//! Every cancellation carries a **cleanup budget** that bounds the resources
//! available for cleanup code (drop glue, finalizers, obligation discharge).
//! The policy is **severity-scaled**: more urgent cancellations get tighter
//! budgets but higher scheduling priority.
//!
//! | CancelKind | Poll Quota | Priority | Rationale |
//! |------------|-----------|----------|-----------|
//! | User | 1000 | 200 | Graceful; user expects orderly shutdown |
//! | Timeout/Deadline | 500 | 210 | Time-driven; moderate cleanup window |
//! | PollQuota/CostBudget | 300 | 215 | Budget violation; tight but fair |
//! | FailFast/RaceLost/Parent/Resource | 200 | 220 | Cascading; fast teardown needed |
//! | Shutdown | 50 | 255 | Urgent; minimal cleanup, max priority |
//!
//! ## Min-Plus Rules (Budget Interaction)
//!
//! When a task receives multiple cancellation requests, the cleanup budgets
//! are **combined** via the meet (∧) operation from the budget algebra
//! (see `Budget::combine`). This means:
//!
//! - Poll quotas: min (tighter quota wins)
//! - Priority: max (higher urgency wins)
//!
//! This ensures that strengthening a cancellation never *increases* the
//! cleanup budget — the monotone-narrowing property from the budget
//! semilattice is preserved.
//!
//! ## Bounded Completion Guarantee
//!
//! Because cleanup budgets have finite poll quotas:
//!
//! 1. Each `consume_poll()` call strictly decreases the remaining quota
//!    (Lemma 7 in `types::budget::tests`)
//! 2. After exactly `poll_quota` polls, the budget is exhausted
//!    (Lemma 10 in `types::budget::tests`)
//! 3. An exhausted budget causes the scheduler to stop polling the task
//!
//! Therefore cleanup terminates within `poll_quota` poll cycles, which
//! is the **sufficient-budget termination** property.
//!
//! ## Calibration Guidelines
//!
//! - **Production**: Use default quotas. If cleanup routines need more
//!   polls (e.g., flushing large buffers), increase the User/Timeout
//!   quotas proportionally but keep Shutdown ≤ 100.
//! - **Lab/Testing**: Use `Budget::MINIMAL` (100 polls) for fast
//!   deterministic runs. Set `ASUPERSYNC_CLEANUP_BUDGET_OVERRIDE` env
//!   var to override all cleanup quotas for calibration experiments.
//! - **Backpressure**: Priority elevation (200–255) ensures cancelled
//!   tasks get scheduled promptly even under load, preventing
//!   indefinite queueing of cleanup work.
//!
//! # Attribution
//!
//! Each cancellation reason includes full attribution information:
//! - **Origin**: The region and optionally task that initiated the cancellation
//! - **Timestamp**: When the cancellation was requested
//! - **Cause chain**: Optional chain of parent causes for debugging
//!
//! This enables debugging and diagnostics to trace cancellation back to its source.
//!
//! # Memory Management
//!
//! Cause chains can grow unboundedly deep in complex cancellation scenarios.
//! To prevent unbounded memory growth, use [`CancelAttributionConfig`] to set limits:
//!
//! - `max_chain_depth`: Maximum depth of cause chain to preserve (default: 16)
//! - `max_chain_memory`: Maximum total memory for cause chain (default: 4KB)
//!
//! When chains exceed limits, they are truncated with a clear marker.
//!
//! ## Memory Cost Analysis
//!
//! Memory cost per `CancelReason`:
//! - Base: ~80 bytes (ids, timestamp, kind, flags)
//! - Message: variable (static &str pointer = 16 bytes)
//! - Cause: recursive (Box pointer = 8 bytes + child cost)
//!
//! Total cost for chain of depth D with no messages:
//! ```text
//! cost = 80 * D + 8 * (D-1)  // ~88 bytes per level
//! ```
//!
//! Default limits (depth=16, memory=4KB) allow chains up to ~45 levels
//! but prefer depth limiting for predictability.

use super::{Budget, RegionId, TaskId, Time};
use core::fmt;

/// Configuration for cancel attribution chain limits.
///
/// Controls memory usage by limiting cause chain depth and total memory.
/// Use this to prevent unbounded memory growth in complex cancellation scenarios.
///
/// # Example
///
/// ```rust,ignore
/// use asupersync::types::CancelAttributionConfig;
///
/// let config = CancelAttributionConfig::default();
/// assert_eq!(config.max_chain_depth, 16);
/// assert_eq!(config.max_chain_memory, 4096);
///
/// let custom = CancelAttributionConfig::new(8, 2048);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelAttributionConfig {
    /// Maximum depth of cause chain to preserve.
    /// Deeper chains are truncated with a 'truncated' marker.
    /// Default: 16
    pub max_chain_depth: usize,

    /// Maximum total memory (in bytes) for cause chain.
    /// When exceeded, chain is truncated.
    /// Default: 4096 (4KB)
    pub max_chain_memory: usize,
}

impl CancelAttributionConfig {
    /// Default maximum chain depth.
    pub const DEFAULT_MAX_DEPTH: usize = 16;

    /// Default maximum chain memory (4KB).
    pub const DEFAULT_MAX_MEMORY: usize = 4096;

    /// Creates a new configuration with custom limits.
    #[must_use]
    pub const fn new(max_chain_depth: usize, max_chain_memory: usize) -> Self {
        Self {
            max_chain_depth,
            max_chain_memory,
        }
    }

    /// Creates a configuration with no limits (for testing or special cases).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_chain_depth: usize::MAX,
            max_chain_memory: usize::MAX,
        }
    }

    /// Returns the estimated memory cost of a single `CancelReason` (without cause chain).
    ///
    /// This is approximately:
    /// - 8 bytes: kind (enum)
    /// - 8 bytes: origin_region (RegionId)
    /// - 16 bytes: origin_task (`Option<TaskId>`)
    /// - 8 bytes: timestamp (Time)
    /// - 16 bytes: message (`Option<&'static str>`)
    /// - 8 bytes: cause (`Option<Box<...>>` pointer, not content)
    /// - 1 byte: truncated flag
    /// - 8 bytes: truncated_at_depth (`Option<usize>`)
    /// - Total: ~80 bytes (rounded up for alignment)
    #[must_use]
    pub const fn single_reason_cost() -> usize {
        80
    }

    /// Estimates memory cost for a chain of given depth.
    #[must_use]
    pub const fn estimated_chain_cost(depth: usize) -> usize {
        if depth == 0 {
            return 0;
        }
        // Each level: ~80 bytes base + 8 bytes Box overhead for parent
        Self::single_reason_cost() * depth + 8 * depth.saturating_sub(1)
    }
}

impl Default for CancelAttributionConfig {
    fn default() -> Self {
        Self {
            max_chain_depth: Self::DEFAULT_MAX_DEPTH,
            max_chain_memory: Self::DEFAULT_MAX_MEMORY,
        }
    }
}

/// The kind of cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub enum CancelKind {
    /// Explicit cancellation requested by user code.
    User,
    /// Cancellation due to timeout/deadline.
    Timeout,
    /// Cancellation due to deadline budget exhaustion (§3.2.1).
    Deadline,
    /// Cancellation due to poll quota exhaustion (§3.2.2).
    PollQuota,
    /// Cancellation due to cost budget exhaustion (§3.2.3).
    CostBudget,
    /// Cancellation due to fail-fast policy (sibling failed).
    FailFast,
    /// Cancellation due to losing a race (another branch completed first).
    RaceLost,
    /// Cancellation due to parent region being cancelled/closing.
    ParentCancelled,
    /// Cancellation due to resource unavailability (e.g., file descriptors, memory).
    ResourceUnavailable,
    /// Cancellation due to runtime shutdown.
    Shutdown,
    /// Cancellation due to a linked task's abnormal exit (Spork link propagation).
    LinkedExit,
}

// ========================================================================
// Cancellation Witnesses
// ========================================================================

/// The cancellation phase witnessed by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CancelPhase {
    /// Cancellation has been requested but not yet acknowledged.
    Requested,
    /// Task has acknowledged cancellation and is draining cleanup.
    Cancelling,
    /// Task is running finalizers.
    Finalizing,
    /// Task completed with a cancelled outcome.
    Completed,
}

impl CancelPhase {
    fn rank(self) -> u8 {
        match self {
            Self::Requested => 0,
            Self::Cancelling => 1,
            Self::Finalizing => 2,
            Self::Completed => 3,
        }
    }
}

/// A proof-of-completion token for cancellation.
///
/// This witness is emitted by the cancellation protocol to make completion
/// verifiable and to detect inconsistent or out-of-order transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelWitness {
    /// The task associated with this cancellation.
    pub task_id: TaskId,
    /// The owning region.
    pub region_id: RegionId,
    /// Cancellation epoch (increments on first request).
    pub epoch: u64,
    /// The phase observed.
    pub phase: CancelPhase,
    /// The cancellation reason.
    pub reason: CancelReason,
}

impl CancelWitness {
    /// Creates a new cancellation witness.
    #[must_use]
    pub fn new(
        task_id: TaskId,
        region_id: RegionId,
        epoch: u64,
        phase: CancelPhase,
        reason: CancelReason,
    ) -> Self {
        Self {
            task_id,
            region_id,
            epoch,
            phase,
            reason,
        }
    }

    /// Validates a transition between two witnesses.
    ///
    /// Invariants:
    /// - Same task, region, and epoch
    /// - Phase must be monotone (no regression)
    /// - Cancellation severity must not weaken
    pub fn validate_transition(prev: Option<&Self>, next: &Self) -> Result<(), CancelWitnessError> {
        let Some(prev) = prev else {
            return Ok(());
        };

        if prev.task_id != next.task_id {
            return Err(CancelWitnessError::TaskMismatch);
        }
        if prev.region_id != next.region_id {
            return Err(CancelWitnessError::RegionMismatch);
        }
        if prev.epoch != next.epoch {
            return Err(CancelWitnessError::EpochMismatch);
        }
        if next.phase.rank() < prev.phase.rank() {
            return Err(CancelWitnessError::PhaseRegression {
                from: prev.phase,
                to: next.phase,
            });
        }
        if next.reason.severity() < prev.reason.severity() {
            return Err(CancelWitnessError::ReasonWeakened {
                from: prev.reason.kind(),
                to: next.reason.kind(),
            });
        }
        Ok(())
    }
}

/// Errors when validating cancellation witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelWitnessError {
    /// Task identifiers do not match.
    TaskMismatch,
    /// Region identifiers do not match.
    RegionMismatch,
    /// Cancellation epoch differs.
    EpochMismatch,
    /// Phase regression detected.
    PhaseRegression {
        /// Previous phase observed.
        from: CancelPhase,
        /// New phase observed.
        to: CancelPhase,
    },
    /// Cancellation severity weakened.
    ReasonWeakened {
        /// Previous cancellation kind.
        from: CancelKind,
        /// New cancellation kind.
        to: CancelKind,
    },
}

impl CancelKind {
    /// Returns the severity of this cancellation kind.
    ///
    /// Higher severity cancellations take precedence when strengthening.
    /// Severity groups (low to high):
    /// - 0: User (explicit, gentle)
    /// - 1: Timeout, Deadline (time-based constraints)
    /// - 2: PollQuota, CostBudget (resource budgets)
    /// - 3: FailFast, RaceLost (sibling/peer outcomes)
    /// - 4: ParentCancelled, ResourceUnavailable (structural/resource)
    /// - 5: Shutdown (system-level)
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Timeout | Self::Deadline => 1,
            Self::PollQuota | Self::CostBudget => 2,
            Self::FailFast | Self::RaceLost | Self::LinkedExit => 3,
            Self::ParentCancelled | Self::ResourceUnavailable => 4,
            Self::Shutdown => 5,
        }
    }
}

impl fmt::Display for CancelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Timeout => write!(f, "timeout"),
            Self::Deadline => write!(f, "deadline"),
            Self::PollQuota => write!(f, "poll quota"),
            Self::CostBudget => write!(f, "cost budget"),
            Self::FailFast => write!(f, "fail-fast"),
            Self::RaceLost => write!(f, "race lost"),
            Self::ParentCancelled => write!(f, "parent cancelled"),
            Self::ResourceUnavailable => write!(f, "resource unavailable"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::LinkedExit => write!(f, "linked exit"),
        }
    }
}

/// The reason for a cancellation, including kind, attribution, and optional context.
///
/// # Attribution
///
/// Every cancellation includes full attribution:
/// - `origin_region`: The region that initiated the cancellation
/// - `origin_task`: Optionally, the specific task that initiated it
/// - `timestamp`: When the cancellation was requested
/// - `cause`: Optional parent cause for building diagnostic chains
///
/// # Cause Chains
///
/// Cancellations can form chains when one cancellation causes another.
/// For example, a timeout might trigger a parent cancellation, which then
/// cascades to children. Use [`root_cause()`][CancelReason::root_cause] to
/// find the original cause, or iterate with [`chain()`][CancelReason::chain].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelReason {
    /// The kind of cancellation.
    pub kind: CancelKind,
    /// The region that initiated this cancellation.
    pub origin_region: RegionId,
    /// The task that initiated this cancellation (if any).
    pub origin_task: Option<TaskId>,
    /// When the cancellation was requested.
    pub timestamp: Time,
    /// Optional human-readable message (static for determinism).
    pub message: Option<&'static str>,
    /// The parent cause of this cancellation (for building chains).
    pub cause: Option<Box<Self>>,
    /// True if the cause chain was truncated due to limits.
    pub truncated: bool,
    /// Depth at which truncation occurred (if truncated).
    pub truncated_at_depth: Option<usize>,
}

impl CancelReason {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Creates a new cancellation reason with the given kind and origin.
    ///
    /// This is the primary constructor that requires full attribution.
    #[must_use]
    pub const fn with_origin(kind: CancelKind, origin_region: RegionId, timestamp: Time) -> Self {
        Self {
            kind,
            origin_region,
            origin_task: None,
            timestamp,
            message: None,
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    /// Creates a new cancellation reason with minimal attribution (for testing/defaults).
    ///
    /// Uses `RegionId::testing_default()` and `Time::ZERO` for attribution.
    /// Prefer `with_origin` in production code.
    #[must_use]
    pub const fn new(kind: CancelKind) -> Self {
        Self {
            kind,
            origin_region: RegionId::testing_default(),
            origin_task: None,
            timestamp: Time::ZERO,
            message: None,
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    /// Creates a user cancellation reason with a message.
    #[must_use]
    pub const fn user(message: &'static str) -> Self {
        Self {
            kind: CancelKind::User,
            origin_region: RegionId::testing_default(),
            origin_task: None,
            timestamp: Time::ZERO,
            message: Some(message),
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    /// Creates a timeout cancellation reason.
    #[must_use]
    pub const fn timeout() -> Self {
        Self::new(CancelKind::Timeout)
    }

    /// Creates a deadline cancellation reason (budget deadline exceeded).
    #[must_use]
    pub const fn deadline() -> Self {
        Self::new(CancelKind::Deadline)
    }

    /// Creates a poll quota cancellation reason (budget poll quota exceeded).
    #[must_use]
    pub const fn poll_quota() -> Self {
        Self::new(CancelKind::PollQuota)
    }

    /// Creates a cost budget cancellation reason (budget cost quota exceeded).
    #[must_use]
    pub const fn cost_budget() -> Self {
        Self::new(CancelKind::CostBudget)
    }

    /// Creates a fail-fast cancellation reason (sibling failed).
    #[must_use]
    pub const fn sibling_failed() -> Self {
        Self::new(CancelKind::FailFast)
    }

    /// Creates a fail-fast cancellation reason (alias for sibling_failed).
    ///
    /// Used when a task is cancelled because a sibling failed in a fail-fast region.
    #[must_use]
    pub const fn fail_fast() -> Self {
        Self::new(CancelKind::FailFast)
    }

    /// Creates a race loser cancellation reason.
    ///
    /// Used when a task is cancelled because another task in a race completed first.
    #[must_use]
    pub const fn race_loser() -> Self {
        Self::new(CancelKind::RaceLost)
    }

    /// Creates a race lost cancellation reason (alias for race_loser).
    ///
    /// Used when a task is cancelled because another task in a race completed first.
    #[must_use]
    pub const fn race_lost() -> Self {
        Self::new(CancelKind::RaceLost)
    }

    /// Creates a parent-cancelled cancellation reason.
    #[must_use]
    pub const fn parent_cancelled() -> Self {
        Self::new(CancelKind::ParentCancelled)
    }

    /// Creates a resource unavailable cancellation reason.
    #[must_use]
    pub const fn resource_unavailable() -> Self {
        Self::new(CancelKind::ResourceUnavailable)
    }

    /// Creates a shutdown cancellation reason.
    #[must_use]
    pub const fn shutdown() -> Self {
        Self::new(CancelKind::Shutdown)
    }

    /// Creates a linked-exit cancellation reason (Spork link propagation).
    #[must_use]
    pub const fn linked_exit() -> Self {
        Self::new(CancelKind::LinkedExit)
    }

    // ========================================================================
    // Builder Methods
    // ========================================================================

    /// Sets the origin task for this cancellation reason.
    #[must_use]
    pub const fn with_task(mut self, task: TaskId) -> Self {
        self.origin_task = Some(task);
        self
    }

    /// Sets a message for this cancellation reason.
    #[must_use]
    pub const fn with_message(mut self, message: &'static str) -> Self {
        self.message = Some(message);
        self
    }

    /// Sets the cause chain for this cancellation reason.
    ///
    /// This does not apply any limits to the chain depth.
    /// For production use with limits, prefer [`with_cause_limited`][Self::with_cause_limited].
    #[must_use]
    pub fn with_cause(mut self, cause: Self) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// Sets the cause chain with depth and memory limits.
    ///
    /// If the chain would exceed the configured limits, it is truncated
    /// and the `truncated` flag is set.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = CancelAttributionConfig::new(4, 1024);
    /// let reason = CancelReason::shutdown()
    ///     .with_cause_limited(deep_cause_chain, &config);
    ///
    /// if reason.truncated {
    ///     println!("Chain truncated at depth {}", reason.truncated_at_depth.unwrap());
    /// }
    /// ```
    #[must_use]
    pub fn with_cause_limited(mut self, cause: Self, config: &CancelAttributionConfig) -> Self {
        // Check if adding this cause would exceed limits
        let current_depth = self.chain_depth();
        let cause_depth = cause.chain_depth();
        let total_depth = current_depth + cause_depth;

        if total_depth > config.max_chain_depth {
            // Truncate the cause chain to fit within limits
            let allowed_cause_depth = config.max_chain_depth.saturating_sub(current_depth);
            if allowed_cause_depth == 0 {
                // No room for any cause - mark as truncated
                self.truncated = true;
                self.truncated_at_depth = Some(current_depth);
                return self;
            }
            // Truncate the cause chain
            let truncated_cause = Self::truncate_chain(cause, allowed_cause_depth);
            self.cause = Some(Box::new(truncated_cause));
            self.truncated = true;
            self.truncated_at_depth = Some(current_depth + allowed_cause_depth);
            return self;
        }

        // Check memory limit
        let estimated_memory = CancelAttributionConfig::estimated_chain_cost(total_depth);
        if estimated_memory > config.max_chain_memory {
            // Calculate how deep we can go within memory budget
            let mut allowed_depth = 0;
            while CancelAttributionConfig::estimated_chain_cost(current_depth + allowed_depth + 1)
                <= config.max_chain_memory
                && allowed_depth < cause_depth
            {
                allowed_depth += 1;
            }

            if allowed_depth == 0 {
                self.truncated = true;
                self.truncated_at_depth = Some(current_depth);
                return self;
            }

            let truncated_cause = Self::truncate_chain(cause, allowed_depth);
            self.cause = Some(Box::new(truncated_cause));
            self.truncated = true;
            self.truncated_at_depth = Some(current_depth + allowed_depth);
            return self;
        }

        // Within limits - add full cause chain
        self.cause = Some(Box::new(cause));
        self
    }

    /// Truncates a cause chain to the specified maximum depth.
    ///
    /// Returns a new `CancelReason` with at most `max_depth` levels,
    /// with the `truncated` flag set on the deepest retained level.
    fn truncate_chain(reason: Self, max_depth: usize) -> Self {
        if max_depth == 0 {
            return Self {
                truncated: true,
                truncated_at_depth: Some(0),
                ..reason
            };
        }

        if max_depth == 1 || reason.cause.is_none() {
            // Keep only this level
            return Self {
                cause: None,
                truncated: reason.cause.is_some(), // Mark truncated if we removed a cause
                truncated_at_depth: if reason.cause.is_some() {
                    Some(1)
                } else {
                    reason.truncated_at_depth
                },
                ..reason
            };
        }

        // Recursively truncate the cause chain
        let truncated_cause = reason
            .cause
            .map(|boxed_cause| Box::new(Self::truncate_chain(*boxed_cause, max_depth - 1)));

        Self {
            cause: truncated_cause,
            truncated: reason.truncated,
            truncated_at_depth: reason.truncated_at_depth,
            ..reason
        }
    }

    /// Sets the timestamp for this cancellation reason.
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: Time) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the origin region for this cancellation reason.
    #[must_use]
    pub const fn with_region(mut self, region: RegionId) -> Self {
        self.origin_region = region;
        self
    }

    // ========================================================================
    // Cause Chain Traversal
    // ========================================================================

    /// Returns an iterator over the cause chain, starting with this reason.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for reason in cancel_reason.chain() {
    ///     println!("Cause: {:?}", reason.kind);
    /// }
    /// ```
    #[must_use]
    pub fn chain(&self) -> CancelReasonChain<'_> {
        CancelReasonChain {
            current: Some(self),
        }
    }

    /// Returns the root cause of this cancellation (the end of the chain).
    ///
    /// If there is no cause chain, returns `self`.
    #[must_use]
    pub fn root_cause(&self) -> &Self {
        let mut current = self;
        while let Some(ref cause) = current.cause {
            current = cause;
        }
        current
    }

    /// Returns the depth of the cause chain (1 = no parent, 2 = one parent, etc.).
    #[must_use]
    pub fn chain_depth(&self) -> usize {
        self.chain().count()
    }

    /// Returns true if this reason or any cause in the chain matches the given kind.
    #[must_use]
    pub fn any_cause_is(&self, kind: CancelKind) -> bool {
        self.chain().any(|r| r.kind == kind)
    }

    /// Returns true if this reason was directly or transitively caused by the given cause.
    ///
    /// Checks if `cause` appears anywhere in this reason's cause chain.
    #[must_use]
    pub fn caused_by(&self, cause: &Self) -> bool {
        self.chain().skip(1).any(|r| r == cause)
    }

    // ========================================================================
    // Kind Checks and Severity
    // ========================================================================

    /// Returns the severity level of this cancellation reason.
    ///
    /// Severity determines cancellation priority. Higher values are more severe
    /// and should override lower-severity cancellations.
    ///
    /// Severity levels:
    /// - 0: User (graceful, allows full cleanup)
    /// - 1: Timeout/Deadline (time pressure)
    /// - 2: PollQuota/CostBudget (resource exhaustion)
    /// - 3: FailFast/RaceLost (sibling events)
    /// - 4: ParentCancelled/ResourceUnavailable (external pressure)
    /// - 5: Shutdown (highest priority, minimal cleanup)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        self.kind.severity()
    }

    /// Returns true if this reason's kind matches the given kind.
    #[must_use]
    pub const fn is_kind(&self, kind: CancelKind) -> bool {
        matches!(
            (self.kind, kind),
            (CancelKind::User, CancelKind::User)
                | (CancelKind::Timeout, CancelKind::Timeout)
                | (CancelKind::Deadline, CancelKind::Deadline)
                | (CancelKind::PollQuota, CancelKind::PollQuota)
                | (CancelKind::CostBudget, CancelKind::CostBudget)
                | (CancelKind::FailFast, CancelKind::FailFast)
                | (CancelKind::RaceLost, CancelKind::RaceLost)
                | (CancelKind::ParentCancelled, CancelKind::ParentCancelled)
                | (
                    CancelKind::ResourceUnavailable,
                    CancelKind::ResourceUnavailable
                )
                | (CancelKind::LinkedExit, CancelKind::LinkedExit)
                | (CancelKind::Shutdown, CancelKind::Shutdown)
        )
    }

    /// Returns true if this reason indicates shutdown.
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        matches!(self.kind, CancelKind::Shutdown)
    }

    /// Returns true if this is a budget-related cancellation (Deadline, PollQuota, CostBudget).
    #[must_use]
    pub const fn is_budget_exceeded(&self) -> bool {
        matches!(
            self.kind,
            CancelKind::Deadline | CancelKind::PollQuota | CancelKind::CostBudget
        )
    }

    /// Returns true if this is a timeout or deadline cancellation.
    #[must_use]
    pub const fn is_time_exceeded(&self) -> bool {
        matches!(self.kind, CancelKind::Timeout | CancelKind::Deadline)
    }

    // ========================================================================
    // Strengthen Operation
    // ========================================================================

    /// Strengthens this reason with another, keeping the more severe one.
    ///
    /// When strengthening:
    /// - The more severe kind wins
    /// - On equal severity, the earlier timestamp wins
    /// - Messages are preserved from the winning reason
    /// - Cause chains are not merged (the winning reason's chain is kept)
    ///
    /// Returns `true` if the reason was changed.
    pub fn strengthen(&mut self, other: &Self) -> bool {
        if other.kind.severity() > self.kind.severity() {
            self.kind = other.kind;
            self.origin_region = other.origin_region;
            self.origin_task = other.origin_task;
            self.timestamp = other.timestamp;
            self.message = other.message;
            self.cause.clone_from(&other.cause);
            return true;
        }

        if other.kind.severity() < self.kind.severity() {
            return false;
        }

        // Same severity: use deterministic tie-breaking
        // Prefer earlier timestamp, then lexicographically smaller message
        if other.timestamp < self.timestamp {
            self.kind = other.kind;
            self.origin_region = other.origin_region;
            self.origin_task = other.origin_task;
            self.timestamp = other.timestamp;
            self.message = other.message;
            self.cause.clone_from(&other.cause);
            return true;
        }

        if other.timestamp > self.timestamp {
            return false;
        }

        // Same timestamp: fallback to message comparison
        match (self.message, other.message) {
            (None, Some(msg)) => {
                self.kind = other.kind;
                self.message = Some(msg);
                true
            }
            (Some(current), Some(candidate)) if candidate < current => {
                self.kind = other.kind;
                self.message = Some(candidate);
                true
            }
            _ => false,
        }
    }

    // ========================================================================
    // Cleanup Budget
    // ========================================================================

    /// Returns the appropriate cleanup budget for this cancellation reason.
    ///
    /// Different cancellation kinds get different cleanup budgets:
    /// - **User**: Generous budget (1000 polls) for user-initiated cancellation
    /// - **Timeout/Deadline**: Moderate budget (500 polls) for time-driven cleanup
    /// - **PollQuota/CostBudget**: Tight budget (300 polls) for budget violations
    /// - **FailFast/RaceLost**: Tight budget (200 polls) for sibling failure cleanup
    /// - **ParentCancelled/ResourceUnavailable**: Tight budget (200 polls) for cascading cleanup
    /// - **Shutdown**: Minimal budget (50 polls) for urgent shutdown
    ///
    /// These budgets ensure the cancellation completeness theorem holds:
    /// tasks will reach terminal state within bounded resources.
    #[must_use]
    pub fn cleanup_budget(&self) -> Budget {
        match self.kind {
            CancelKind::User => Budget::new().with_poll_quota(1000).with_priority(200),
            CancelKind::Timeout | CancelKind::Deadline => {
                Budget::new().with_poll_quota(500).with_priority(210)
            }
            CancelKind::PollQuota | CancelKind::CostBudget => {
                Budget::new().with_poll_quota(300).with_priority(215)
            }
            CancelKind::FailFast
            | CancelKind::RaceLost
            | CancelKind::ParentCancelled
            | CancelKind::ResourceUnavailable
            | CancelKind::LinkedExit => Budget::new().with_poll_quota(200).with_priority(220),
            CancelKind::Shutdown => Budget::new().with_poll_quota(50).with_priority(255),
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns the kind of this cancellation reason.
    #[must_use]
    pub const fn kind(&self) -> CancelKind {
        self.kind
    }

    /// Returns the origin region of this cancellation.
    #[must_use]
    pub const fn origin_region(&self) -> RegionId {
        self.origin_region
    }

    /// Returns the origin task of this cancellation (if any).
    #[must_use]
    pub const fn origin_task(&self) -> Option<TaskId> {
        self.origin_task
    }

    /// Returns the timestamp when this cancellation was requested.
    #[must_use]
    pub const fn timestamp(&self) -> Time {
        self.timestamp
    }

    /// Returns the message associated with this cancellation (if any).
    #[must_use]
    pub const fn message(&self) -> Option<&'static str> {
        self.message
    }

    /// Returns a reference to the parent cause (if any).
    #[must_use]
    pub fn cause(&self) -> Option<&Self> {
        self.cause.as_deref()
    }

    /// Returns true if this reason's cause chain was truncated due to limits.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns the depth at which truncation occurred (if any).
    #[must_use]
    pub const fn truncated_at_depth(&self) -> Option<usize> {
        self.truncated_at_depth
    }

    /// Returns true if this reason or any cause in the chain was truncated.
    #[must_use]
    pub fn any_truncated(&self) -> bool {
        self.chain().any(|r| r.truncated)
    }

    /// Estimates the memory cost of this entire cause chain.
    #[must_use]
    pub fn estimated_memory_cost(&self) -> usize {
        CancelAttributionConfig::estimated_chain_cost(self.chain_depth())
    }
}

/// Iterator over a cancellation reason's cause chain.
pub struct CancelReasonChain<'a> {
    current: Option<&'a CancelReason>,
}

impl<'a> Iterator for CancelReasonChain<'a> {
    type Item = &'a CancelReason;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.current?;
        self.current = current.cause.as_deref();
        Some(current)
    }
}

impl Default for CancelReason {
    fn default() -> Self {
        Self::new(CancelKind::User)
    }
}

impl fmt::Display for CancelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(msg) = self.message {
            write!(f, ": {msg}")?;
        }
        // Include origin attribution in alternate mode
        if f.alternate() {
            write!(f, " (from {} at {})", self.origin_region, self.timestamp)?;
            if let Some(ref task) = self.origin_task {
                write!(f, " task {task}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(test_name: &str) {
        init_test_logging();
        crate::test_phase!(test_name);
    }

    fn combine(mut a: CancelReason, b: &CancelReason) -> CancelReason {
        a.strengthen(b);
        a
    }

    #[test]
    fn severity_ordering() {
        init_test("severity_ordering");
        // Test severity levels are ordered correctly
        crate::assert_with_log!(
            CancelKind::User.severity() < CancelKind::Timeout.severity(),
            "User should be below Timeout",
            true,
            CancelKind::User.severity() < CancelKind::Timeout.severity()
        );
        crate::assert_with_log!(
            CancelKind::Timeout.severity() == CancelKind::Deadline.severity(),
            "Timeout and Deadline should have same severity",
            true,
            CancelKind::Timeout.severity() == CancelKind::Deadline.severity()
        );
        crate::assert_with_log!(
            CancelKind::Deadline.severity() < CancelKind::PollQuota.severity(),
            "Deadline should be below PollQuota",
            true,
            CancelKind::Deadline.severity() < CancelKind::PollQuota.severity()
        );
        crate::assert_with_log!(
            CancelKind::PollQuota.severity() == CancelKind::CostBudget.severity(),
            "PollQuota and CostBudget should have same severity",
            true,
            CancelKind::PollQuota.severity() == CancelKind::CostBudget.severity()
        );
        crate::assert_with_log!(
            CancelKind::CostBudget.severity() < CancelKind::FailFast.severity(),
            "CostBudget should be below FailFast",
            true,
            CancelKind::CostBudget.severity() < CancelKind::FailFast.severity()
        );
        crate::assert_with_log!(
            CancelKind::FailFast.severity() == CancelKind::RaceLost.severity(),
            "FailFast and RaceLost should have same severity",
            true,
            CancelKind::FailFast.severity() == CancelKind::RaceLost.severity()
        );
        crate::assert_with_log!(
            CancelKind::RaceLost.severity() < CancelKind::ParentCancelled.severity(),
            "RaceLost should be below ParentCancelled",
            true,
            CancelKind::RaceLost.severity() < CancelKind::ParentCancelled.severity()
        );
        crate::assert_with_log!(
            CancelKind::ParentCancelled.severity() == CancelKind::ResourceUnavailable.severity(),
            "ParentCancelled and ResourceUnavailable should have same severity",
            true,
            CancelKind::ParentCancelled.severity() == CancelKind::ResourceUnavailable.severity()
        );
        crate::assert_with_log!(
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity(),
            "ParentCancelled should be below Shutdown",
            true,
            CancelKind::ParentCancelled.severity() < CancelKind::Shutdown.severity()
        );
        crate::test_complete!("severity_ordering");
    }

    #[test]
    fn strengthen_takes_more_severe() {
        init_test("strengthen_takes_more_severe");
        let mut reason = CancelReason::new(CancelKind::User);
        let strengthened = reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            strengthened,
            "should strengthen to Timeout",
            true,
            strengthened
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should be Timeout",
            CancelKind::Timeout,
            reason.kind
        );

        let strengthened_shutdown = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(
            strengthened_shutdown,
            "should strengthen to Shutdown",
            true,
            strengthened_shutdown
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );

        // Less severe should not change.
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(unchanged, "less severe should not change", true, unchanged);
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should remain Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::test_complete!("strengthen_takes_more_severe");
    }

    #[test]
    fn strengthen_is_idempotent() {
        init_test("strengthen_is_idempotent");
        let mut reason = CancelReason::timeout();
        let unchanged = !reason.strengthen(&CancelReason::timeout());
        crate::assert_with_log!(
            unchanged,
            "strengthen should be idempotent",
            true,
            unchanged
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should remain Timeout",
            CancelKind::Timeout,
            reason.kind
        );
        crate::test_complete!("strengthen_is_idempotent");
    }

    #[test]
    fn strengthen_is_associative() {
        init_test("strengthen_is_associative");
        let a = CancelReason::user("a");
        let b = CancelReason::timeout();
        let c = CancelReason::shutdown();

        let left = combine(combine(a.clone(), &b), &c);
        let right = {
            let bc = combine(b, &c);
            combine(a, &bc)
        };

        crate::assert_with_log!(
            left == right,
            "strengthen should be associative",
            left,
            right
        );
        crate::test_complete!("strengthen_is_associative");
    }

    #[test]
    fn strengthen_same_kind_picks_deterministic_message() {
        init_test("strengthen_same_kind_picks_deterministic_message");
        let mut reason = CancelReason::user("b");
        let changed = reason.strengthen(&CancelReason::user("a"));
        crate::assert_with_log!(
            changed,
            "same-kind strengthen should change message",
            true,
            changed
        );
        crate::assert_with_log!(
            reason.kind == CancelKind::User,
            "kind should remain User",
            CancelKind::User,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message == Some("a"),
            "message should be deterministic",
            Some("a"),
            reason.message
        );
        crate::test_complete!("strengthen_same_kind_picks_deterministic_message");
    }

    #[test]
    fn strengthen_resets_message_when_kind_increases() {
        init_test("strengthen_resets_message_when_kind_increases");
        let mut reason = CancelReason::user("please stop");
        let changed = reason.strengthen(&CancelReason::shutdown());
        crate::assert_with_log!(changed, "kind increase should change reason", true, changed);
        crate::assert_with_log!(
            reason.kind == CancelKind::Shutdown,
            "kind should be Shutdown",
            CancelKind::Shutdown,
            reason.kind
        );
        crate::assert_with_log!(
            reason.message.is_none(),
            "message should reset on kind increase",
            true,
            reason.message.is_none()
        );
        crate::test_complete!("strengthen_resets_message_when_kind_increases");
    }

    #[test]
    fn cleanup_budget_scales_with_severity() {
        init_test("cleanup_budget_scales_with_severity");
        // User cancellation gets the most generous budget
        let user_budget = CancelReason::user("stop").cleanup_budget();
        crate::assert_with_log!(
            user_budget.poll_quota == 1000,
            "user budget poll_quota should be 1000",
            1000,
            user_budget.poll_quota
        );

        // Timeout gets moderate budget
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        crate::assert_with_log!(
            timeout_budget.poll_quota == 500,
            "timeout budget poll_quota should be 500",
            500,
            timeout_budget.poll_quota
        );

        // Budget exhaustion (PollQuota/CostBudget) gets tight budget
        let poll_quota_budget = CancelReason::poll_quota().cleanup_budget();
        crate::assert_with_log!(
            poll_quota_budget.poll_quota == 300,
            "poll_quota budget poll_quota should be 300",
            300,
            poll_quota_budget.poll_quota
        );

        // FailFast gets tight budget
        let fail_fast_budget = CancelReason::sibling_failed().cleanup_budget();
        crate::assert_with_log!(
            fail_fast_budget.poll_quota == 200,
            "fail_fast budget poll_quota should be 200",
            200,
            fail_fast_budget.poll_quota
        );

        // Shutdown gets minimal budget with highest priority
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();
        crate::assert_with_log!(
            shutdown_budget.poll_quota == 50,
            "shutdown budget poll_quota should be 50",
            50,
            shutdown_budget.poll_quota
        );
        crate::assert_with_log!(
            shutdown_budget.priority == 255,
            "shutdown budget priority should be 255",
            255,
            shutdown_budget.priority
        );

        // Priority increases with severity (cancel lane needs higher priority)
        crate::assert_with_log!(
            user_budget.priority < timeout_budget.priority,
            "user priority should be below timeout",
            true,
            user_budget.priority < timeout_budget.priority
        );
        crate::assert_with_log!(
            timeout_budget.priority < poll_quota_budget.priority,
            "timeout priority should be below poll_quota",
            true,
            timeout_budget.priority < poll_quota_budget.priority
        );
        crate::assert_with_log!(
            poll_quota_budget.priority < fail_fast_budget.priority,
            "poll_quota priority should be below fail_fast",
            true,
            poll_quota_budget.priority < fail_fast_budget.priority
        );
        crate::assert_with_log!(
            fail_fast_budget.priority < shutdown_budget.priority,
            "fail_fast priority should be below shutdown",
            true,
            fail_fast_budget.priority < shutdown_budget.priority
        );
        crate::test_complete!("cleanup_budget_scales_with_severity");
    }

    // ========================================================================
    // Bounded Cleanup Completion Tests (bd-3cq88)
    //
    // These tests verify the sufficient-budget termination property:
    // cleanup budgets have finite poll quotas, so cleanup always
    // terminates within a bounded number of polls.
    // ========================================================================

    /// Verifies that every CancelKind produces a cleanup budget with
    /// finite, positive poll quota — the precondition for bounded completion.
    #[test]
    fn cleanup_budget_always_finite_and_positive() {
        init_test("cleanup_budget_always_finite_and_positive");

        let kinds = [
            CancelKind::User,
            CancelKind::Timeout,
            CancelKind::Deadline,
            CancelKind::PollQuota,
            CancelKind::CostBudget,
            CancelKind::FailFast,
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::ResourceUnavailable,
            CancelKind::Shutdown,
        ];

        for kind in kinds {
            let reason =
                CancelReason::with_origin(kind, RegionId::new_for_test(1, 0), Time::from_secs(0));
            let budget = reason.cleanup_budget();
            crate::assert_with_log!(
                budget.poll_quota > 0 && budget.poll_quota < u32::MAX,
                "cleanup budget must be finite and positive",
                true,
                budget.poll_quota
            );
        }

        crate::test_complete!("cleanup_budget_always_finite_and_positive");
    }

    /// Verifies that consuming exactly poll_quota polls exhausts the cleanup
    /// budget — the termination bound.
    #[test]
    fn cleanup_budget_terminates_after_quota_polls() {
        init_test("cleanup_budget_terminates_after_quota_polls");

        let reason = CancelReason::timeout();
        let mut budget = reason.cleanup_budget();
        let quota = budget.poll_quota;

        // Consume exactly quota polls
        for i in 0..quota {
            let result = budget.consume_poll();
            crate::assert_with_log!(
                result.is_some(),
                "poll should succeed within budget",
                true,
                i
            );
        }

        // Now exhausted
        crate::assert_with_log!(
            budget.is_exhausted(),
            "budget exhausted after quota polls",
            true,
            budget.poll_quota
        );

        // No further progress possible
        let result = budget.consume_poll();
        crate::assert_with_log!(
            result.is_none(),
            "poll fails after exhaustion",
            true,
            result.is_none()
        );

        crate::test_complete!("cleanup_budget_terminates_after_quota_polls");
    }

    /// Verifies that combining (strengthening) cleanup budgets never
    /// increases the poll quota — monotone narrowing.
    #[test]
    fn cleanup_budget_combine_never_widens() {
        init_test("cleanup_budget_combine_never_widens");

        let user_budget = CancelReason::user("stop").cleanup_budget();
        let timeout_budget = CancelReason::timeout().cleanup_budget();
        let shutdown_budget = CancelReason::shutdown().cleanup_budget();

        // Combining user + timeout takes the tighter quota
        let combined = user_budget.combine(timeout_budget);
        crate::assert_with_log!(
            combined.poll_quota <= user_budget.poll_quota,
            "combined ≤ user",
            user_budget.poll_quota,
            combined.poll_quota
        );
        crate::assert_with_log!(
            combined.poll_quota <= timeout_budget.poll_quota,
            "combined ≤ timeout",
            timeout_budget.poll_quota,
            combined.poll_quota
        );

        // Priority should be max (more urgent wins)
        crate::assert_with_log!(
            combined.priority >= user_budget.priority,
            "combined priority ≥ user",
            user_budget.priority,
            combined.priority
        );

        // Combining with shutdown (tightest) always tightens
        let with_shutdown = combined.combine(shutdown_budget);
        crate::assert_with_log!(
            with_shutdown.poll_quota <= combined.poll_quota,
            "shutdown tightens further",
            combined.poll_quota,
            with_shutdown.poll_quota
        );
        crate::assert_with_log!(
            with_shutdown.priority == 255,
            "shutdown priority wins",
            255u8,
            with_shutdown.priority
        );

        crate::test_complete!("cleanup_budget_combine_never_widens");
    }

    /// Verifies severity ordering: more severe → fewer polls, higher priority.
    #[test]
    fn cleanup_budget_severity_monotone() {
        init_test("cleanup_budget_severity_monotone");

        let user = CancelReason::user("stop");
        let timeout = CancelReason::timeout();
        let quota = CancelReason::poll_quota();
        let fail_fast = CancelReason::sibling_failed();
        let shutdown = CancelReason::shutdown();

        let budgets = [
            user.cleanup_budget(),
            timeout.cleanup_budget(),
            quota.cleanup_budget(),
            fail_fast.cleanup_budget(),
            shutdown.cleanup_budget(),
        ];

        // Poll quotas should be non-increasing (more severe → tighter)
        for i in 1..budgets.len() {
            crate::assert_with_log!(
                budgets[i].poll_quota <= budgets[i - 1].poll_quota,
                "poll quota non-increasing with severity",
                budgets[i - 1].poll_quota,
                budgets[i].poll_quota
            );
        }

        // Priorities should be non-decreasing (more severe → higher priority)
        for i in 1..budgets.len() {
            crate::assert_with_log!(
                budgets[i].priority >= budgets[i - 1].priority,
                "priority non-decreasing with severity",
                budgets[i - 1].priority,
                budgets[i].priority
            );
        }

        crate::test_complete!("cleanup_budget_severity_monotone");
    }

    /// Verifies that cleanup budgets have no deadline — cleanup should not
    /// be time-bounded, only poll-bounded, so the scheduler can always
    /// make progress regardless of clock skew.
    #[test]
    fn cleanup_budget_has_no_deadline() {
        init_test("cleanup_budget_has_no_deadline");

        let kinds = [CancelKind::User, CancelKind::Timeout, CancelKind::Shutdown];

        for kind in kinds {
            let reason =
                CancelReason::with_origin(kind, RegionId::new_for_test(1, 0), Time::from_secs(0));
            let budget = reason.cleanup_budget();
            crate::assert_with_log!(
                budget.deadline.is_none(),
                "cleanup budget should have no deadline",
                true,
                budget.deadline.is_none()
            );
        }

        crate::test_complete!("cleanup_budget_has_no_deadline");
    }

    // ========================================================================
    // Attribution Tests
    // ========================================================================

    #[test]
    fn cancel_reason_with_full_attribution() {
        init_test("cancel_reason_with_full_attribution");
        let region = RegionId::new_for_test(1, 0);
        let task = TaskId::new_for_test(2, 0);
        let timestamp = Time::from_millis(1000);

        let reason = CancelReason::with_origin(CancelKind::Timeout, region, timestamp)
            .with_task(task)
            .with_message("test timeout");

        crate::assert_with_log!(
            reason.kind == CancelKind::Timeout,
            "kind should be Timeout",
            CancelKind::Timeout,
            reason.kind
        );
        crate::assert_with_log!(
            reason.origin_region == region,
            "origin_region should match",
            region,
            reason.origin_region
        );
        crate::assert_with_log!(
            reason.origin_task == Some(task),
            "origin_task should match",
            Some(task),
            reason.origin_task
        );
        crate::assert_with_log!(
            reason.timestamp == timestamp,
            "timestamp should match",
            timestamp,
            reason.timestamp
        );
        crate::assert_with_log!(
            reason.message == Some("test timeout"),
            "message should match",
            Some("test timeout"),
            reason.message
        );
        crate::test_complete!("cancel_reason_with_full_attribution");
    }

    // ========================================================================
    // Cause Chain Tests
    // ========================================================================

    #[test]
    fn cause_chain_single() {
        init_test("cause_chain_single");
        let reason = CancelReason::timeout();

        crate::assert_with_log!(
            reason.chain_depth() == 1,
            "single reason should have depth 1",
            1,
            reason.chain_depth()
        );

        let root = reason.root_cause();
        crate::assert_with_log!(
            root == &reason,
            "root_cause of single reason should be itself",
            true,
            root == &reason
        );
        crate::test_complete!("cause_chain_single");
    }

    #[test]
    fn cause_chain_multiple() {
        init_test("cause_chain_multiple");
        let root = CancelReason::timeout().with_message("original timeout");
        let middle = CancelReason::parent_cancelled()
            .with_message("parent cancelled")
            .with_cause(root);
        let leaf = CancelReason::shutdown()
            .with_message("shutdown")
            .with_cause(middle);

        crate::assert_with_log!(
            leaf.chain_depth() == 3,
            "three-level chain should have depth 3",
            3,
            leaf.chain_depth()
        );

        let found_root = leaf.root_cause();
        crate::assert_with_log!(
            found_root.kind == CancelKind::Timeout,
            "root_cause should be Timeout",
            CancelKind::Timeout,
            found_root.kind
        );
        crate::assert_with_log!(
            found_root.message == Some("original timeout"),
            "root_cause message should match",
            Some("original timeout"),
            found_root.message
        );
        crate::test_complete!("cause_chain_multiple");
    }

    #[test]
    fn any_cause_is_works() {
        init_test("any_cause_is_works");
        let root = CancelReason::timeout();
        let leaf = CancelReason::shutdown().with_cause(root);

        crate::assert_with_log!(
            leaf.any_cause_is(CancelKind::Shutdown),
            "should find Shutdown in chain",
            true,
            leaf.any_cause_is(CancelKind::Shutdown)
        );
        crate::assert_with_log!(
            leaf.any_cause_is(CancelKind::Timeout),
            "should find Timeout in chain",
            true,
            leaf.any_cause_is(CancelKind::Timeout)
        );
        crate::assert_with_log!(
            !leaf.any_cause_is(CancelKind::User),
            "should not find User in chain",
            false,
            leaf.any_cause_is(CancelKind::User)
        );
        crate::test_complete!("any_cause_is_works");
    }

    #[test]
    fn caused_by_works() {
        init_test("caused_by_works");
        let root = CancelReason::timeout().with_message("root");
        let leaf = CancelReason::shutdown().with_cause(root.clone());

        crate::assert_with_log!(
            leaf.caused_by(&root),
            "leaf should be caused_by root",
            true,
            leaf.caused_by(&root)
        );
        crate::assert_with_log!(
            !root.caused_by(&leaf),
            "root should not be caused_by leaf",
            false,
            root.caused_by(&leaf)
        );
        crate::assert_with_log!(
            !leaf.caused_by(&leaf),
            "leaf should not be caused_by itself",
            false,
            leaf.caused_by(&leaf)
        );
        crate::test_complete!("caused_by_works");
    }

    // ========================================================================
    // Kind Check Tests
    // ========================================================================

    #[test]
    fn is_kind_works() {
        init_test("is_kind_works");
        let reason = CancelReason::poll_quota();
        crate::assert_with_log!(
            reason.is_kind(CancelKind::PollQuota),
            "is_kind should return true for matching kind",
            true,
            reason.is_kind(CancelKind::PollQuota)
        );
        crate::assert_with_log!(
            !reason.is_kind(CancelKind::Timeout),
            "is_kind should return false for non-matching kind",
            false,
            reason.is_kind(CancelKind::Timeout)
        );
        crate::test_complete!("is_kind_works");
    }

    #[test]
    fn is_budget_exceeded_works() {
        init_test("is_budget_exceeded_works");
        crate::assert_with_log!(
            CancelReason::deadline().is_budget_exceeded(),
            "Deadline should be budget_exceeded",
            true,
            CancelReason::deadline().is_budget_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::poll_quota().is_budget_exceeded(),
            "PollQuota should be budget_exceeded",
            true,
            CancelReason::poll_quota().is_budget_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::cost_budget().is_budget_exceeded(),
            "CostBudget should be budget_exceeded",
            true,
            CancelReason::cost_budget().is_budget_exceeded()
        );
        crate::assert_with_log!(
            !CancelReason::timeout().is_budget_exceeded(),
            "Timeout should not be budget_exceeded",
            false,
            CancelReason::timeout().is_budget_exceeded()
        );
        crate::test_complete!("is_budget_exceeded_works");
    }

    #[test]
    fn is_time_exceeded_works() {
        init_test("is_time_exceeded_works");
        crate::assert_with_log!(
            CancelReason::timeout().is_time_exceeded(),
            "Timeout should be time_exceeded",
            true,
            CancelReason::timeout().is_time_exceeded()
        );
        crate::assert_with_log!(
            CancelReason::deadline().is_time_exceeded(),
            "Deadline should be time_exceeded",
            true,
            CancelReason::deadline().is_time_exceeded()
        );
        crate::assert_with_log!(
            !CancelReason::poll_quota().is_time_exceeded(),
            "PollQuota should not be time_exceeded",
            false,
            CancelReason::poll_quota().is_time_exceeded()
        );
        crate::test_complete!("is_time_exceeded_works");
    }

    // ========================================================================
    // New Variant Tests
    // ========================================================================

    #[test]
    fn new_variants_constructors() {
        init_test("new_variants_constructors");

        let deadline = CancelReason::deadline();
        crate::assert_with_log!(
            deadline.kind == CancelKind::Deadline,
            "deadline() should create Deadline kind",
            CancelKind::Deadline,
            deadline.kind
        );

        let poll_quota = CancelReason::poll_quota();
        crate::assert_with_log!(
            poll_quota.kind == CancelKind::PollQuota,
            "poll_quota() should create PollQuota kind",
            CancelKind::PollQuota,
            poll_quota.kind
        );

        let cost_budget = CancelReason::cost_budget();
        crate::assert_with_log!(
            cost_budget.kind == CancelKind::CostBudget,
            "cost_budget() should create CostBudget kind",
            CancelKind::CostBudget,
            cost_budget.kind
        );

        let resource = CancelReason::resource_unavailable();
        crate::assert_with_log!(
            resource.kind == CancelKind::ResourceUnavailable,
            "resource_unavailable() should create ResourceUnavailable kind",
            CancelKind::ResourceUnavailable,
            resource.kind
        );

        crate::test_complete!("new_variants_constructors");
    }

    #[test]
    fn new_variants_display() {
        init_test("new_variants_display");

        crate::assert_with_log!(
            format!("{}", CancelKind::Deadline) == "deadline",
            "Deadline display should be 'deadline'",
            "deadline",
            format!("{}", CancelKind::Deadline)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::PollQuota) == "poll quota",
            "PollQuota display should be 'poll quota'",
            "poll quota",
            format!("{}", CancelKind::PollQuota)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::CostBudget) == "cost budget",
            "CostBudget display should be 'cost budget'",
            "cost budget",
            format!("{}", CancelKind::CostBudget)
        );
        crate::assert_with_log!(
            format!("{}", CancelKind::ResourceUnavailable) == "resource unavailable",
            "ResourceUnavailable display should be 'resource unavailable'",
            "resource unavailable",
            format!("{}", CancelKind::ResourceUnavailable)
        );

        crate::test_complete!("new_variants_display");
    }

    // ========================================================================
    // Chain Limit and Truncation Tests
    // ========================================================================

    #[test]
    fn cancel_attribution_config_defaults() {
        init_test("cancel_attribution_config_defaults");
        let config = CancelAttributionConfig::default();
        crate::assert_with_log!(
            config.max_chain_depth == 16,
            "default max_chain_depth should be 16",
            16,
            config.max_chain_depth
        );
        crate::assert_with_log!(
            config.max_chain_memory == 4096,
            "default max_chain_memory should be 4096",
            4096,
            config.max_chain_memory
        );
        crate::test_complete!("cancel_attribution_config_defaults");
    }

    #[test]
    fn cancel_attribution_config_custom() {
        init_test("cancel_attribution_config_custom");
        let config = CancelAttributionConfig::new(8, 2048);
        crate::assert_with_log!(
            config.max_chain_depth == 8,
            "custom max_chain_depth should be 8",
            8,
            config.max_chain_depth
        );
        crate::assert_with_log!(
            config.max_chain_memory == 2048,
            "custom max_chain_memory should be 2048",
            2048,
            config.max_chain_memory
        );
        crate::test_complete!("cancel_attribution_config_custom");
    }

    #[test]
    fn cancel_attribution_config_unlimited() {
        init_test("cancel_attribution_config_unlimited");
        let config = CancelAttributionConfig::unlimited();
        crate::assert_with_log!(
            config.max_chain_depth == usize::MAX,
            "unlimited max_chain_depth should be usize::MAX",
            usize::MAX,
            config.max_chain_depth
        );
        crate::test_complete!("cancel_attribution_config_unlimited");
    }

    #[test]
    fn chain_at_exact_limit() {
        init_test("chain_at_exact_limit");
        let config = CancelAttributionConfig::new(3, usize::MAX);

        // Build a chain of exactly 3 levels
        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        crate::assert_with_log!(
            level3.chain_depth() == 3,
            "chain at limit should have depth 3",
            3,
            level3.chain_depth()
        );
        crate::assert_with_log!(
            !level3.truncated,
            "chain at limit should not be truncated",
            false,
            level3.truncated
        );
        crate::test_complete!("chain_at_exact_limit");
    }

    #[test]
    fn chain_beyond_limit_truncates() {
        init_test("chain_beyond_limit_truncates");
        let config = CancelAttributionConfig::new(2, usize::MAX);

        // Build a chain of 3 levels, which exceeds limit of 2
        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);

        // This should truncate because we'd have 3 levels total
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        crate::assert_with_log!(
            level3.chain_depth() <= 2,
            "chain beyond limit should be truncated to 2",
            2,
            level3.chain_depth()
        );
        crate::assert_with_log!(
            level3.truncated || level3.any_truncated(),
            "truncated chain should have truncated flag",
            true,
            level3.truncated || level3.any_truncated()
        );
        crate::test_complete!("chain_beyond_limit_truncates");
    }

    #[test]
    fn truncated_reason_new_fields() {
        init_test("truncated_reason_new_fields");
        let reason = CancelReason::timeout();

        crate::assert_with_log!(
            !reason.truncated,
            "new reason should not be truncated",
            false,
            reason.truncated
        );
        crate::assert_with_log!(
            reason.truncated_at_depth.is_none(),
            "new reason should have no truncated_at_depth",
            true,
            reason.truncated_at_depth.is_none()
        );
        crate::assert_with_log!(
            !reason.is_truncated(),
            "is_truncated() should be false",
            false,
            reason.is_truncated()
        );
        crate::test_complete!("truncated_reason_new_fields");
    }

    #[test]
    fn estimated_memory_cost() {
        init_test("estimated_memory_cost");
        let single = CancelReason::timeout();
        let cost1 = single.estimated_memory_cost();
        crate::assert_with_log!(
            cost1 > 0,
            "single reason should have positive memory cost",
            true,
            cost1 > 0
        );

        // Chain of 2 should cost more
        let chain2 = CancelReason::shutdown().with_cause(CancelReason::timeout());
        let cost2 = chain2.estimated_memory_cost();
        crate::assert_with_log!(
            cost2 > cost1,
            "chain of 2 should cost more than single",
            true,
            cost2 > cost1
        );

        crate::test_complete!("estimated_memory_cost");
    }

    #[test]
    fn memory_limit_triggers_truncation() {
        init_test("memory_limit_triggers_truncation");
        // Set a very tight memory limit that should trigger truncation
        let config = CancelAttributionConfig::new(usize::MAX, 100);

        let level1 = CancelReason::timeout();
        let level2 = CancelReason::parent_cancelled().with_cause(level1);
        let level3 = CancelReason::shutdown().with_cause_limited(level2, &config);

        // With only 100 bytes, we can't fit even 2 full levels
        // So truncation should occur
        let truncated = level3.truncated || level3.any_truncated();
        crate::assert_with_log!(
            truncated,
            "tight memory limit should trigger truncation",
            true,
            truncated
        );
        crate::test_complete!("memory_limit_triggers_truncation");
    }

    #[test]
    fn any_truncated_finds_nested_truncation() {
        init_test("any_truncated_finds_nested_truncation");
        // Manually create a chain where an inner level is truncated
        let inner = CancelReason {
            truncated: true,
            truncated_at_depth: Some(1),
            ..CancelReason::timeout()
        };
        let outer = CancelReason::shutdown().with_cause(inner);

        crate::assert_with_log!(
            !outer.truncated,
            "outer itself is not truncated",
            false,
            outer.truncated
        );
        crate::assert_with_log!(
            outer.any_truncated(),
            "any_truncated should find inner truncation",
            true,
            outer.any_truncated()
        );
        crate::test_complete!("any_truncated_finds_nested_truncation");
    }

    #[test]
    fn stress_deep_chain_bounded_by_config() {
        init_test("stress_deep_chain_bounded_by_config");
        let config = CancelAttributionConfig::new(16, 4096);
        let mut current = CancelReason::timeout();
        for _ in 1..100 {
            current = CancelReason::parent_cancelled().with_cause_limited(current, &config);
        }
        crate::assert_with_log!(
            current.chain_depth() <= 16,
            "deep chain must be bounded by max_chain_depth",
            true,
            current.chain_depth() <= 16
        );
        crate::assert_with_log!(
            current.any_truncated(),
            "deep chain must report truncation",
            true,
            current.any_truncated()
        );
        crate::test_complete!("stress_deep_chain_bounded_by_config");
    }

    #[test]
    fn stress_wide_fanout_bounded() {
        init_test("stress_wide_fanout_bounded");
        let config = CancelAttributionConfig::new(4, 4096);
        let root = CancelReason::shutdown();
        for _i in 0..200 {
            let child = CancelReason::parent_cancelled().with_cause_limited(root.clone(), &config);
            crate::assert_with_log!(
                child.chain_depth() <= 4,
                "fanout child must respect depth limit",
                true,
                child.chain_depth() <= 4
            );
        }
        crate::test_complete!("stress_wide_fanout_bounded");
    }

    #[test]
    fn zero_depth_config_drops_all_causes() {
        init_test("zero_depth_config_drops_all_causes");
        let config = CancelAttributionConfig::new(0, usize::MAX);
        let cause = CancelReason::timeout();
        let result = CancelReason::shutdown().with_cause_limited(cause, &config);
        crate::assert_with_log!(
            result.cause.is_none(),
            "zero depth config should prevent cause attachment",
            true,
            result.cause.is_none()
        );
        crate::assert_with_log!(
            result.truncated,
            "should be marked truncated when cause is dropped",
            true,
            result.truncated
        );
        crate::test_complete!("zero_depth_config_drops_all_causes");
    }

    #[test]
    fn depth_one_config_keeps_only_self() {
        init_test("depth_one_config_keeps_only_self");
        let config = CancelAttributionConfig::new(1, usize::MAX);
        let deep = CancelReason::timeout().with_cause(CancelReason::parent_cancelled());
        let result = CancelReason::shutdown().with_cause_limited(deep, &config);
        crate::assert_with_log!(
            result.chain_depth() <= 1,
            "depth-1 config should keep only the outermost level",
            true,
            result.chain_depth() <= 1
        );
        crate::test_complete!("depth_one_config_keeps_only_self");
    }

    #[test]
    fn zero_memory_config_drops_all_causes() {
        init_test("zero_memory_config_drops_all_causes");
        let config = CancelAttributionConfig::new(usize::MAX, 0);
        let cause = CancelReason::timeout();
        let result = CancelReason::shutdown().with_cause_limited(cause, &config);
        crate::assert_with_log!(
            result.truncated || result.any_truncated(),
            "zero memory should trigger truncation",
            true,
            result.truncated || result.any_truncated()
        );
        crate::test_complete!("zero_memory_config_drops_all_causes");
    }

    #[test]
    fn stress_incremental_chain_growth() {
        init_test("stress_incremental_chain_growth");
        let config = CancelAttributionConfig::default();
        let root_reason = CancelReason::shutdown();
        let mut parent_reason = root_reason;
        for _i in 0..50 {
            let child_reason =
                CancelReason::parent_cancelled().with_cause_limited(parent_reason.clone(), &config);
            crate::assert_with_log!(
                child_reason.chain_depth() <= config.max_chain_depth,
                "incremental chain must stay within configured depth",
                true,
                child_reason.chain_depth() <= config.max_chain_depth
            );
            parent_reason = child_reason;
        }
        crate::assert_with_log!(
            parent_reason.any_truncated(),
            "deeply nested region chain must report truncation",
            true,
            parent_reason.any_truncated()
        );
        crate::test_complete!("stress_incremental_chain_growth");
    }
}
