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
use serde::{Deserialize, Serialize};

/// br-asupersync-dyao05 — Hard cap on the cause-chain depth a
/// serde Deserializer will recurse through. The runtime
/// `CancelAttributionConfig::max_chain_depth` is 16 by default;
/// this constant sits at 64 — 4x headroom over the runtime cap so
/// no legitimate snapshot is spuriously rejected, but tight enough
/// to fire BEFORE serde_json's default recursion limit (128) and
/// well before any plausible stack-overflow boundary on the
/// MessagePack / bincode / postcard transports that have NO
/// built-in recursion limit. Crafted snapshots like
/// `{"cause": {"cause": {"cause": ... 50_000 levels ... }}}`
/// surface as `serde::de::Error::custom` so the transport layer
/// (distributed/snapshot.rs, fabric MessagePack frames, debug
/// JSON endpoints) classifies the input as malformed and refuses
/// to materialize the chain.
const MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH: usize = 64;

thread_local! {
    /// Per-thread cause-chain depth counter for `CancelReason`
    /// deserialization. Incremented on entry to
    /// `deserialize_bounded_cause`, decremented on exit (via the
    /// `CauseDepthGuard` Drop). The thread-local is sound here
    /// because serde's `Deserializer` impls are inherently
    /// single-threaded for the duration of one deserialize call —
    /// the recursion is on the stack of one thread.
    static CANCEL_CAUSE_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// RAII guard that decrements the cause-chain depth counter even
/// on panic / early-return. Critical for correctness: if a
/// deserialize call panics mid-recursion the thread-local
/// otherwise carries stale depth into the NEXT deserialize call
/// on the same thread, which would either spuriously reject valid
/// input or (worse) admit input deeper than the cap.
struct CauseDepthGuard;

impl Drop for CauseDepthGuard {
    fn drop(&mut self) {
        CANCEL_CAUSE_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// br-asupersync-dyao05 — Custom deserializer for the `cause`
/// field of `CancelReason`. Wraps the standard
/// `Option<Box<CancelReason>>::deserialize` with a depth check
/// that bails before the recursion can blow the stack or cause
/// catastrophic heap allocation.
///
/// The check fires on each recursion step (one level of
/// `Option<Box<CancelReason>>`); cumulative depth across the
/// chain is bounded by `MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH`.
fn deserialize_bounded_cause<'de, D>(deserializer: D) -> Result<Option<Box<CancelReason>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let depth = CANCEL_CAUSE_DEPTH.with(|c| {
        let new = c.get().saturating_add(1);
        c.set(new);
        new
    });
    let _guard = CauseDepthGuard;
    if depth > MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH {
        return Err(D::Error::custom(format!(
            "CancelReason cause-chain depth {depth} exceeds maximum \
             {MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH} (br-asupersync-dyao05)"
        )));
    }
    Option::<Box<CancelReason>>::deserialize(deserializer)
}

/// Configuration for cancel attribution chain limits.
///
/// Controls memory usage by limiting cause chain depth and total memory.
/// Use this to prevent unbounded memory growth in complex cancellation scenarios.
///
/// # Example
///
/// ```rust
/// use asupersync::types::CancelAttributionConfig;
///
/// let config = CancelAttributionConfig::default();
/// assert_eq!(config.max_chain_depth, 16);
/// assert_eq!(config.max_chain_memory, 4096);
///
/// let custom = CancelAttributionConfig::new(8, 2048);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    #[inline]
    #[must_use]
    pub const fn new(max_chain_depth: usize, max_chain_memory: usize) -> Self {
        Self {
            max_chain_depth,
            max_chain_memory,
        }
    }

    /// Creates a configuration with no limits (for testing or special cases).
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn single_reason_cost() -> usize {
        80
    }

    /// Estimates memory cost for a chain of given depth.
    #[inline]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    #[inline]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[inline]
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

    /// br-asupersync-9fjaqe / -f1zjwu — Centralized validator for the
    /// initial witness in a per-task witness stream. Both the witness-
    /// based oracle (`cancel_correctness`) and the event-based oracle
    /// (`cancellation_protocol`, via its `on_cancel_witness` hook)
    /// route through this method so two oracles wired to the same
    /// witness stream cannot disagree on whether the initial witness
    /// is well-formed.
    ///
    /// The first observed witness must use a non-zero epoch. Epoch 0
    /// is reserved for the "no cancel ever requested" sentinel, and a
    /// witness carrying epoch 0 indicates a runtime that emitted a
    /// witness for a task that was never actually cancelled — a
    /// protocol violation.
    pub fn validate_initial(&self) -> Result<(), CancelWitnessError> {
        if self.epoch == 0 {
            return Err(CancelWitnessError::InitialEpochZero);
        }
        Ok(())
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
    /// Initial witness used cancellation epoch 0. Epoch 0 is the
    /// "no cancel" sentinel; the first witness emitted for a task
    /// must use a non-zero epoch (br-asupersync-9fjaqe / -f1zjwu).
    InitialEpochZero,
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
    /// Returns the variant name as a static string (matches `Debug` output).
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Timeout => "Timeout",
            Self::Deadline => "Deadline",
            Self::PollQuota => "PollQuota",
            Self::CostBudget => "CostBudget",
            Self::FailFast => "FailFast",
            Self::RaceLost => "RaceLost",
            Self::ParentCancelled => "ParentCancelled",
            Self::ResourceUnavailable => "ResourceUnavailable",
            Self::Shutdown => "Shutdown",
            Self::LinkedExit => "LinkedExit",
        }
    }

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
    #[inline]
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
    #[inline]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub message: Option<String>,
    /// The parent cause of this cancellation (for building chains).
    ///
    /// br-asupersync-dyao05 — `deserialize_with` routes the
    /// recursive parse through `deserialize_bounded_cause` which
    /// rejects chains deeper than
    /// `MAX_CANCEL_CAUSE_DESERIALIZE_DEPTH = 64` BEFORE the recursion
    /// can blow the stack or OOM. The runtime cap
    /// `CancelAttributionConfig::max_chain_depth` (default 16) still
    /// applies post-deserialize for the application-level truncation;
    /// this gate is the wire-level defence-in-depth against
    /// attacker-supplied snapshots.
    #[serde(deserialize_with = "deserialize_bounded_cause")]
    pub cause: Option<Box<Self>>,
    /// True if the cause chain was truncated due to limits.
    pub truncated: bool,
    /// Depth at which truncation occurred (if truncated).
    pub truncated_at_depth: Option<usize>,
}

macro_rules! cancel_reason_constructors {
    ($(
        $(#[$meta:meta])*
        $name:ident => $kind:ident;
    )*) => {
        $(
            $(#[$meta])*
            #[inline]
            #[must_use]
            pub const fn $name() -> Self {
                Self::new(CancelKind::$kind)
            }
        )*
    };
}

impl CancelReason {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Creates a new cancellation reason with the given kind and origin.
    ///
    /// This is the primary constructor that requires full attribution.
    #[inline]
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
    /// Uses `RegionId::testing_default()` and `Time::from_nanos(1_000_000_000)` for attribution.
    /// Prefer `with_origin` in production code.
    #[inline]
    #[must_use]
    pub const fn new(kind: CancelKind) -> Self {
        Self {
            kind,
            origin_region: RegionId::testing_default(),
            origin_task: None,
            timestamp: Time::from_nanos(1_000_000_000),
            message: None,
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    /// Creates a user cancellation reason with a message.
    #[inline]
    #[must_use]
    pub fn user(message: &'static str) -> Self {
        Self {
            kind: CancelKind::User,
            origin_region: RegionId::testing_default(),
            origin_task: None,
            timestamp: Time::from_nanos(1_000_000_000),
            message: Some(message.to_string()),
            cause: None,
            truncated: false,
            truncated_at_depth: None,
        }
    }

    cancel_reason_constructors! {
        /// Creates a timeout cancellation reason.
        timeout => Timeout;
        /// Creates a deadline cancellation reason (budget deadline exceeded).
        deadline => Deadline;
        /// Creates a poll quota cancellation reason (budget poll quota exceeded).
        poll_quota => PollQuota;
        /// Creates a cost budget cancellation reason (budget cost quota exceeded).
        cost_budget => CostBudget;
        /// Creates a fail-fast cancellation reason (sibling failed).
        sibling_failed => FailFast;
        /// Creates a fail-fast cancellation reason (alias for sibling_failed).
        ///
        /// Used when a task is cancelled because a sibling failed in a fail-fast region.
        fail_fast => FailFast;
        /// Creates a race loser cancellation reason.
        ///
        /// Used when a task is cancelled because another task in a race completed first.
        race_loser => RaceLost;
        /// Creates a race lost cancellation reason (alias for race_loser).
        ///
        /// Used when a task is cancelled because another task in a race completed first.
        race_lost => RaceLost;
        /// Creates a parent-cancelled cancellation reason.
        parent_cancelled => ParentCancelled;
        /// Creates a resource unavailable cancellation reason.
        resource_unavailable => ResourceUnavailable;
        /// Creates a shutdown cancellation reason.
        shutdown => Shutdown;
        /// Creates a linked-exit cancellation reason (Spork link propagation).
        linked_exit => LinkedExit;
    }

    // ========================================================================
    // Builder Methods
    // ========================================================================

    /// Sets the origin task for this cancellation reason.
    #[inline]
    #[must_use]
    pub const fn with_task(mut self, task: TaskId) -> Self {
        self.origin_task = Some(task);
        self
    }

    /// Sets a message for this cancellation reason.
    #[inline]
    #[must_use]
    pub fn with_message(mut self, message: &'static str) -> Self {
        self.message = Some(message.to_string());
        self
    }

    /// Sets the cause chain for this cancellation reason.
    ///
    /// This does not apply any limits to the chain depth.
    /// For production use with limits, prefer [`with_cause_limited`][Self::with_cause_limited].
    #[inline]
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
        // Check if adding this cause would exceed limits.
        // Use 1 for self (not chain_depth) because self.cause will be replaced.
        let current_depth = 1_usize;
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
                cause: None,
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
    #[inline]
    #[must_use]
    pub const fn with_timestamp(mut self, timestamp: Time) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the origin region for this cancellation reason.
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn severity(&self) -> u8 {
        self.kind.severity()
    }

    /// Returns true if this reason's kind matches the given kind.
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        matches!(self.kind, CancelKind::Shutdown)
    }

    /// Returns true if this is a budget-related cancellation (Deadline, PollQuota, CostBudget).
    #[inline]
    #[must_use]
    pub const fn is_budget_exceeded(&self) -> bool {
        matches!(
            self.kind,
            CancelKind::Deadline | CancelKind::PollQuota | CancelKind::CostBudget
        )
    }

    /// Returns true if this is a timeout or deadline cancellation.
    #[inline]
    #[must_use]
    pub const fn is_time_exceeded(&self) -> bool {
        matches!(self.kind, CancelKind::Timeout | CancelKind::Deadline)
    }

    // ========================================================================
    // Strengthen Operation
    // ========================================================================

    /// Strengthens this reason with another, keeping the more severe one.
    ///
    /// Implements `inv.cancel.idempotence` (#5, SEM-INV-003):
    /// `strengthen(a, b) = max_severity(a, b)`.
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
            self.message.clone_from(&other.message);
            self.cause.clone_from(&other.cause);
            self.truncated = other.truncated;
            self.truncated_at_depth = other.truncated_at_depth;
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
            self.message.clone_from(&other.message);
            self.cause.clone_from(&other.cause);
            self.truncated = other.truncated;
            self.truncated_at_depth = other.truncated_at_depth;
            return true;
        }

        if other.timestamp > self.timestamp {
            return false;
        }

        // Same timestamp: fallback to message comparison
        let should_replace = match (&self.message, &other.message) {
            (None, Some(_)) => true,
            (Some(current), Some(candidate)) if candidate < current => true,
            _ => false,
        };
        if should_replace {
            self.kind = other.kind;
            self.origin_region = other.origin_region;
            self.origin_task = other.origin_task;
            self.timestamp = other.timestamp;
            self.message.clone_from(&other.message);
            self.cause.clone_from(&other.cause);
            self.truncated = other.truncated;
            self.truncated_at_depth = other.truncated_at_depth;
        }
        should_replace
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
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> CancelKind {
        self.kind
    }

    /// Returns the origin region of this cancellation.
    #[inline]
    #[must_use]
    pub const fn origin_region(&self) -> RegionId {
        self.origin_region
    }

    /// Returns the origin task of this cancellation (if any).
    #[inline]
    #[must_use]
    pub const fn origin_task(&self) -> Option<TaskId> {
        self.origin_task
    }

    /// Returns the timestamp when this cancellation was requested.
    #[inline]
    #[must_use]
    pub const fn timestamp(&self) -> Time {
        self.timestamp
    }

    /// Returns the message associated with this cancellation (if any).
    #[inline]
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns a reference to the parent cause (if any).
    #[inline]
    #[must_use]
    pub fn cause(&self) -> Option<&Self> {
        self.cause.as_deref()
    }

    /// Returns true if this reason's cause chain was truncated due to limits.
    #[inline]
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns the depth at which truncation occurred (if any).
    #[inline]
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
        if let Some(msg) = &self.message {
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
#[path = "cancel_inline_tests.rs"]
mod tests;
