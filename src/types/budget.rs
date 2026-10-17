//! Budget type with product semiring semantics.
//!
//! Budgets constrain the resources available to a task or region:
//!
//! - **Deadline**: Absolute time by which work must complete
//! - **Poll quota**: Maximum number of poll calls
//! - **Cost quota**: Abstract cost units (for priority scheduling)
//! - **Priority**: Scheduling priority (higher = more urgent)
//!
//! # Semiring Semantics
//!
//! Budgets form a product semiring with two key operations:
//!
//! | Operation | Deadline | Poll/Cost Quota | Priority |
//! |-----------|----------|-----------------|----------|
//! | `meet` (∧) | min (earlier wins) | min (tighter wins) | max (higher urgency wins) |
//! | identity  | None (no deadline) | u32::MAX / None | 0 (identity for max) |
//!
//! The **meet** operation (`combine`/`meet`) computes the tightest constraints
//! from two budgets. This is used when nesting regions or combining timeout
//! requirements:
//! [`Budget::new`] uses the ordinary scheduling default priority of 128; it is
//! not the algebraic identity. [`Budget::INFINITE`] uses priority 0 so meeting
//! it with any budget preserves that budget's priority.
//!
//! ```
//! # use asupersync::Budget;
//! # use asupersync::types::id::Time;
//! assert_eq!(Budget::INFINITE.priority, 0);
//! assert_eq!(Budget::INFINITE.meet(Budget::new()), Budget::new());
//!
//! let outer = Budget::new().with_deadline(Time::from_secs(30));
//! let inner = Budget::new().with_deadline(Time::from_secs(10));
//!
//! // Inner timeout is tighter, so it wins
//! let combined = outer.meet(inner);
//! assert_eq!(combined.deadline, Some(Time::from_secs(10)));
//! ```
//!
//! # HTTP Timeout Integration
//!
//! Budget maps directly to HTTP request timeout management. The pattern is:
//!
//! 1. Create a budget from the request timeout configuration
//! 2. Attach it to the request's capability context (`Cx`)
//! 3. All downstream operations inherit and respect the budget
//! 4. When budget is exhausted, operations return `Outcome::Cancelled`
//!
//! Budget deadlines are absolute `Time` instants. Convert duration-style
//! request timeouts with [`Budget::with_timeout`] at request start instead of
//! passing a duration-shaped `Time` to [`Budget::with_deadline`].
//!
//! ## Example: Request Timeout Middleware
//!
//! ```ignore
//! use asupersync::{Budget, Cx, Outcome, Time};
//! use std::time::Duration;
//!
//! // Server configuration
//! struct ServerConfig {
//!     request_timeout: Duration,
//! }
//!
//! // Middleware creates budget from config
//! async fn timeout_middleware<B>(
//!     req: Request<B>,
//!     next: Next<B>,
//!     config: &ServerConfig,
//! ) -> Outcome<Response, TimeoutError> {
//!     // Capture the current logical time from the runtime or lab clock.
//!     let now = Time::from_secs(1_000);
//!     let budget = Budget::new().with_timeout(now, config.request_timeout);
//!
//!     // Get or create Cx, attach budget
//!     let cx = req.extensions()
//!         .get::<Cx>()
//!         .cloned()
//!         .unwrap_or_else(Cx::new);
//!     let cx = cx.with_budget(budget);
//!
//!     // All downstream operations now respect the timeout
//!     match next.run_with_cx(req, &cx).await {
//!         Outcome::Cancelled(reason) if reason.is_time_exceeded() => {
//!             Outcome::Err(TimeoutError::RequestTimeout)
//!         }
//!         other => other,
//!     }
//! }
//! ```
//!
//! ## Budget Propagation Through Regions
//!
//! Budget flows through the region tree, with each nested region inheriting
//! and potentially tightening the parent's constraints:
//!
//! ```text
//! Request Region (budget: 30s deadline)
//! ├── DB Query Region
//! │   └── Inherits 30s, operation takes 5s
//! │       Budget remaining: 25s
//! ├── External API Call
//! │   └── Has own 10s timeout, meets with parent: min(25s, 10s) = 10s effective
//! │       Budget remaining: ~15s after completion
//! └── Response Serialization
//!     └── Uses remaining ~15s budget
//! ```
//!
//! ## Exhaustion Behavior
//!
//! When a budget is exhausted:
//!
//! | Resource | Trigger | Result |
//! |----------|---------|--------|
//! | Deadline | `now >= deadline` | `Outcome::Cancelled(CancelReason::deadline())` |
//! | Poll quota | `poll_quota == 0` | `Outcome::Cancelled(CancelReason::budget())` |
//! | Cost quota | `cost_quota == Some(0)` | `Outcome::Cancelled(CancelReason::budget())` |
//!
//! The runtime checks these conditions at scheduling points and propagates
//! cancellation through the region tree. A task's deadline is also armed as a
//! timer when the task is created, so a task parked in a cancel-aware wait
//! (a channel receive, a lock, a semaphore) is cancelled with
//! `CancelReason::deadline()` when the deadline passes, without waiting for a
//! checkpoint it would never reach.
//!
//! # Creating Budgets
//!
//! ```
//! # use asupersync::Budget;
//! # use asupersync::types::id::Time;
//! // Unlimited budget (default)
//! let unlimited = Budget::unlimited();
//!
//! // With an absolute logical deadline
//! let timed = Budget::with_deadline_at_secs(30);
//!
//! // With a relative timeout from the current logical time
//! # use std::time::Duration;
//! let now = Time::from_secs(1_000);
//! let request = Budget::new().with_timeout(now, Duration::from_secs(30));
//!
//! // Builder pattern for multiple constraints
//! let complex = Budget::new()
//!     .with_deadline(Time::from_secs(30))
//!     .with_poll_quota(1000)
//!     .with_cost_quota(10_000)
//!     .with_priority(200);
//! ```

use super::id::Time;
use crate::tracing_compat::{info, trace};
use core::fmt;
use std::time::Duration;

/// A budget constraining resource usage for a task or region.
///
/// Budgets form a product semiring for combination:
/// - Deadlines/quotas use min (tighter wins)
/// - Priority uses max (higher urgency wins)
///
/// # Choosing a deadline constructor
///
/// Absolute vs. relative time is the classic budget footgun. Pick from this
/// table; the `at` / `timeout` words in the names mark the semantics:
///
/// | You have | You want | Use |
/// |----------|----------|-----|
/// | An absolute logical instant (`Time`) | deadline at that instant | [`with_deadline`](Self::with_deadline) |
/// | An absolute instant in raw seconds/nanos | deadline at that instant | [`with_deadline_at_secs`](Self::with_deadline_at_secs) / [`with_deadline_at_ns`](Self::with_deadline_at_ns) |
/// | `now` + a relative timeout | deadline replaced by `now + timeout` | [`with_timeout`](Self::with_timeout) |
/// | `now` + a relative timeout | deadline tightened, never loosened | [`tightened_by_timeout`](Self::tightened_by_timeout) |
/// | A `Cx` + a relative timeout | ambient budget tightened correctly | `Cx::budget_for_timeout` |
///
/// For deadline *propagation* across calls (HTTP → handler → DB), always use
/// the tightening forms — replacing a deadline can silently extend it past
/// the caller's bound.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Absolute deadline by which work must complete.
    pub deadline: Option<Time>,
    /// Maximum number of poll operations.
    pub poll_quota: u32,
    /// Abstract cost quota (for advanced scheduling).
    pub cost_quota: Option<u64>,
    /// Scheduling priority (0 = lowest, 255 = highest).
    pub priority: u8,
}

/// A point-in-time snapshot of the remaining headroom in a [`Budget`].
///
/// Produced by [`Budget::remaining`]. Every dimension uses `None` to mean
/// "effectively unlimited" (no deadline configured, `u32::MAX` poll quota, or
/// no cost quota), so callers never need to know the sentinel encodings.
///
/// The canonical use is adaptive control flow such as "do I have time for
/// another retry?":
///
/// ```
/// # use asupersync::Budget;
/// # use asupersync::types::id::Time;
/// # use std::time::Duration;
/// # let budget = Budget::new().with_deadline(Time::from_secs(30));
/// # let now = Time::from_secs(29);
/// # let estimated_attempt = Duration::from_secs(5);
/// let left = budget.remaining(now);
/// let can_retry = left.deadline.is_none_or(|d| d > estimated_attempt);
/// # assert!(!can_retry);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemainingBudget {
    /// Time left until the deadline, or `None` if no deadline is set or the
    /// deadline has already passed with no remaining time (see
    /// [`Budget::remaining_time`] for the exact past-deadline semantics).
    pub deadline: Option<Duration>,
    /// Polls left, or `None` if effectively unlimited.
    pub polls: Option<u32>,
    /// Cost units left, or `None` if no cost quota is configured.
    pub cost: Option<u64>,
}

impl Budget {
    /// A budget with no constraints (infinite resources).
    pub const INFINITE: Self = Self {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 0,
    };

    /// A budget with zero resources (nothing allowed).
    pub const ZERO: Self = Self {
        deadline: Some(Time::ZERO),
        poll_quota: 0,
        cost_quota: Some(0),
        priority: 255,
    };

    /// A minimal budget for cleanup operations.
    ///
    /// This provides a small poll quota (100 polls) for cleanup and finalizer code
    /// to run, but no deadline or cost constraints. Used when requesting cancellation
    /// to allow tasks a bounded cleanup phase.
    pub const MINIMAL: Self = Self {
        deadline: None,
        poll_quota: 100,
        cost_quota: None,
        priority: 128,
    };

    /// Creates a new budget with default values (priority 128, unlimited quotas).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deadline: None,
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 128,
        }
    }

    /// Creates an unlimited budget (alias for [`INFINITE`](Self::INFINITE)).
    ///
    /// This is the identity element for the meet operation.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// let budget = Budget::unlimited();
    /// assert!(!budget.is_exhausted());
    /// ```
    #[inline]
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::INFINITE
    }

    /// Creates a budget with only an absolute deadline constraint (in seconds).
    ///
    /// The `at` in the name is deliberate: the value is a logical instant
    /// since the runtime epoch ("deadline AT t=30s"), not a timeout duration.
    /// For a per-operation timeout, use [`with_timeout`](Self::with_timeout)
    /// or [`tightened_by_timeout`](Self::tightened_by_timeout) with the
    /// current logical time.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let budget = Budget::with_deadline_at_secs(30);
    /// assert_eq!(budget.deadline, Some(Time::from_secs(30)));
    /// ```
    #[inline]
    #[must_use]
    pub const fn with_deadline_at_secs(secs: u64) -> Self {
        Self {
            deadline: Some(Time::from_secs(secs)),
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 128,
        }
    }

    /// Creates a budget with only an absolute deadline constraint (in nanoseconds).
    ///
    /// The `at` in the name is deliberate: the value is a logical instant
    /// since the runtime epoch, not a timeout duration. For a per-operation
    /// timeout, use [`with_timeout`](Self::with_timeout) or
    /// [`tightened_by_timeout`](Self::tightened_by_timeout) with the current
    /// logical time.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let budget = Budget::with_deadline_at_ns(30_000_000_000); // 30 seconds
    /// assert_eq!(budget.deadline, Some(Time::from_nanos(30_000_000_000)));
    /// ```
    #[inline]
    #[must_use]
    pub const fn with_deadline_at_ns(nanos: u64) -> Self {
        Self {
            deadline: Some(Time::from_nanos(nanos)),
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 128,
        }
    }

    /// Sets the absolute logical deadline.
    ///
    /// The deadline is an instant, not a duration. For example,
    /// `Time::from_secs(30)` means the runtime/lab clock value `30s`, not
    /// "30 seconds from now". For relative per-operation timeouts, use
    /// [`with_timeout`](Self::with_timeout).
    #[inline]
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Time) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Sets the deadline to `now + timeout`.
    ///
    /// Use this for request, RPC, database, and other per-operation timeout
    /// budgets. The caller supplies `now` explicitly so production and lab
    /// runtimes use the same deterministic time source.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// # use std::time::Duration;
    /// let now = Time::from_secs(100);
    /// let budget = Budget::new().with_timeout(now, Duration::from_secs(30));
    ///
    /// assert_eq!(budget.deadline, Some(Time::from_secs(130)));
    /// ```
    #[inline]
    #[must_use]
    pub fn with_timeout(mut self, now: Time, timeout: Duration) -> Self {
        self.deadline = Some(now + timeout);
        self
    }

    /// Tightens this budget with a relative timeout, never loosening it.
    ///
    /// Unlike [`with_timeout`](Self::with_timeout), which *replaces* any
    /// existing deadline, this composes via [`meet`](Self::meet): the
    /// resulting deadline is `min(existing_deadline, now + timeout)`. This is
    /// the correct operation for deadline propagation — an outer 10s request
    /// budget tightened by a 30s per-call timeout stays a 10s budget.
    ///
    /// All other dimensions (poll quota, cost quota, priority) are preserved.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// # use std::time::Duration;
    /// let now = Time::from_secs(100);
    ///
    /// // Ambient deadline at t=110s; a 30s timeout must NOT loosen it.
    /// let ambient = Budget::new().with_deadline(Time::from_secs(110));
    /// let tightened = ambient.tightened_by_timeout(now, Duration::from_secs(30));
    /// assert_eq!(tightened.deadline, Some(Time::from_secs(110)));
    ///
    /// // No ambient deadline: the timeout becomes the deadline.
    /// let open = Budget::new();
    /// let bounded = open.tightened_by_timeout(now, Duration::from_secs(30));
    /// assert_eq!(bounded.deadline, Some(Time::from_secs(130)));
    /// ```
    #[inline]
    #[must_use]
    pub fn tightened_by_timeout(self, now: Time, timeout: Duration) -> Self {
        self.meet(Self::new().with_timeout(now, timeout))
    }

    /// Sets the poll quota.
    #[inline]
    #[must_use]
    pub const fn with_poll_quota(mut self, quota: u32) -> Self {
        self.poll_quota = quota;
        self
    }

    /// Sets the cost quota.
    #[inline]
    #[must_use]
    pub const fn with_cost_quota(mut self, quota: u64) -> Self {
        self.cost_quota = Some(quota);
        self
    }

    /// Sets the priority.
    #[inline]
    #[must_use]
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Returns true if the budget has been exhausted.
    ///
    /// This checks only poll and cost quotas, not deadline (which requires current time).
    #[inline]
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.poll_quota == 0 || matches!(self.cost_quota, Some(0))
    }

    /// Returns true if the deadline has passed.
    #[inline]
    #[must_use]
    pub fn is_past_deadline(&self, now: Time) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// Decrements the poll quota by one, returning the old value.
    ///
    /// Returns `None` if already at zero.
    #[inline]
    pub fn consume_poll(&mut self) -> Option<u32> {
        if self.poll_quota > 0 {
            let old = self.poll_quota;
            self.poll_quota -= 1;
            trace!(
                polls_remaining = self.poll_quota,
                polls_consumed = 1,
                "budget poll consumed"
            );
            if self.poll_quota == 0 {
                info!(
                    exhausted_resource = "polls",
                    final_quota = 0,
                    overage_amount = 0,
                    "budget poll quota exhausted"
                );
            }
            Some(old)
        } else {
            trace!(
                polls_remaining = 0,
                "budget poll consume failed: already exhausted"
            );
            None
        }
    }

    /// Combines two budgets using product semiring semantics.
    ///
    /// - Deadlines: min (earlier wins)
    /// - Quotas: min (tighter wins)
    /// - Priority: max (higher urgency wins)
    ///
    /// This is also known as the "meet" operation (∧) in lattice terminology.
    /// See also: [`meet`](Self::meet).
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let outer = Budget::new()
    ///     .with_deadline(Time::from_secs(30))
    ///     .with_poll_quota(1000);
    ///
    /// let inner = Budget::new()
    ///     .with_deadline(Time::from_secs(10))  // tighter
    ///     .with_poll_quota(5000);              // looser
    ///
    /// let combined = outer.combine(inner);
    /// assert_eq!(combined.deadline, Some(Time::from_secs(10))); // min
    /// assert_eq!(combined.poll_quota, 1000);                    // min
    /// ```
    #[inline]
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        let combined = self.combine_untraced(other);

        // Trace when budget is tightened (any constraint becomes stricter)
        // For deadline comparison, None means "no constraint" (least restrictive),
        // so tightening occurs only when a finite deadline replaces None, or when
        // one finite deadline is earlier than another.
        let deadline_tightened = match (combined.deadline, self.deadline, other.deadline) {
            (Some(c), Some(s), _) if c < s => true,
            (Some(c), _, Some(o)) if c < o => true,
            (Some(_), None, _) | (Some(_), _, None) => true,
            _ => false,
        };
        let poll_tightened =
            combined.poll_quota < self.poll_quota || combined.poll_quota < other.poll_quota;
        let cost_tightened = match (combined.cost_quota, self.cost_quota, other.cost_quota) {
            (Some(c), Some(s), _) if c < s => true,
            (Some(c), _, Some(o)) if c < o => true,
            (Some(_), None, _) | (Some(_), _, None) => true,
            _ => false,
        };
        let priority_tightened =
            combined.priority > self.priority || combined.priority > other.priority;

        if deadline_tightened || poll_tightened || cost_tightened || priority_tightened {
            trace!(
                deadline_tightened,
                poll_tightened,
                cost_tightened,
                self_deadline = ?self.deadline,
                other_deadline = ?other.deadline,
                combined_deadline = ?combined.deadline,
                self_poll_quota = self.poll_quota,
                other_poll_quota = other.poll_quota,
                combined_poll_quota = combined.poll_quota,
                self_cost_quota = ?self.cost_quota,
                other_cost_quota = ?other.cost_quota,
                combined_cost_quota = ?combined.cost_quota,
                self_priority = self.priority,
                other_priority = other.priority,
                combined_priority = combined.priority,
                "budget combined (tightened)"
            );
        }

        combined
    }

    /// Callback-free product meet for code that already owns a runtime/Cx
    /// lock. The public [`Self::combine`] wrapper emits observability events;
    /// invoking it from a cancellation critical section would let a tracing
    /// subscriber reenter the same lock.
    #[inline]
    #[must_use]
    pub(crate) fn combine_untraced(self, other: Self) -> Self {
        Self {
            deadline: match (self.deadline, other.deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (deadline @ Some(_), None) | (None, deadline @ Some(_)) => deadline,
                (None, None) => None,
            },
            poll_quota: self.poll_quota.min(other.poll_quota),
            cost_quota: match (self.cost_quota, other.cost_quota) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (quota @ Some(_), None) | (None, quota @ Some(_)) => quota,
                (None, None) => None,
            },
            priority: self.priority.max(other.priority),
        }
    }

    /// Meet operation (∧) - alias for [`combine`](Self::combine).
    ///
    /// Computes the tightest constraints from two budgets. This is the
    /// fundamental operation for nesting budget scopes.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let parent = Budget::with_deadline_at_secs(30);
    /// let child = Budget::with_deadline_at_secs(10);
    ///
    /// // Child deadline is tighter, so it wins
    /// let effective = parent.meet(child);
    /// assert_eq!(effective.deadline, Some(Time::from_secs(10)));
    /// ```
    #[inline]
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        self.combine(other)
    }

    /// Consumes cost quota, returning `true` if successful.
    ///
    /// Returns `false` (and does not modify quota) if there isn't enough
    /// remaining cost quota. If no cost quota is set, always succeeds.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// let mut budget = Budget::new().with_cost_quota(100);
    ///
    /// assert!(budget.consume_cost(30));   // 70 remaining
    /// assert!(budget.consume_cost(70));   // 0 remaining
    /// assert!(!budget.consume_cost(1));   // fails, quota exhausted
    /// ```
    #[allow(clippy::used_underscore_binding)]
    #[inline]
    pub fn consume_cost(&mut self, cost: u64) -> bool {
        match self.cost_quota {
            None => {
                trace!(
                    cost_consumed = cost,
                    cost_remaining = "unlimited",
                    "budget cost consumed (unlimited)"
                );
                true // No quota means unlimited
            }
            Some(remaining) if remaining >= cost => {
                let new_remaining = remaining - cost;
                self.cost_quota = Some(new_remaining);
                trace!(
                    cost_consumed = cost,
                    cost_remaining = new_remaining,
                    "budget cost consumed"
                );
                if new_remaining == 0 {
                    info!(
                        exhausted_resource = "cost",
                        final_quota = 0,
                        overage_amount = 0,
                        "budget cost quota exhausted"
                    );
                }
                true
            }
            Some(remaining) => {
                #[cfg(not(feature = "tracing-integration"))]
                let _ = remaining;
                trace!(
                    cost_requested = cost,
                    cost_remaining = remaining,
                    "budget cost consume failed: insufficient quota"
                );
                false
            }
        }
    }

    /// Returns the remaining time until the deadline, if any.
    ///
    /// Returns `None` if there is no deadline or if the deadline has passed.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// # use std::time::Duration;
    /// let budget = Budget::with_deadline_at_secs(30);
    /// let now = Time::from_secs(10);
    ///
    /// let remaining = budget.remaining_time(now);
    /// assert_eq!(remaining, Some(Duration::from_secs(20)));
    /// ```
    #[inline]
    #[must_use]
    pub fn remaining_time(&self, now: Time) -> Option<Duration> {
        self.deadline.and_then(|d| {
            if now < d {
                Some(Duration::from_nanos(
                    d.as_nanos().saturating_sub(now.as_nanos()),
                ))
            } else {
                None
            }
        })
    }

    /// Returns the remaining poll quota.
    ///
    /// Returns the current poll quota value. A value of `u32::MAX` indicates
    /// effectively unlimited polls.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// let budget = Budget::new().with_poll_quota(100);
    /// assert_eq!(budget.remaining_polls(), 100);
    /// ```
    #[inline]
    #[must_use]
    pub const fn remaining_polls(&self) -> u32 {
        self.poll_quota
    }

    /// Returns the remaining cost quota, if any.
    ///
    /// Returns `None` if no cost quota is set (unlimited).
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// let budget = Budget::new().with_cost_quota(1000);
    /// assert_eq!(budget.remaining_cost(), Some(1000));
    ///
    /// let unlimited = Budget::unlimited();
    /// assert_eq!(unlimited.remaining_cost(), None);
    /// ```
    #[inline]
    #[must_use]
    pub const fn remaining_cost(&self) -> Option<u64> {
        self.cost_quota
    }

    /// Returns a point-in-time snapshot of every remaining budget dimension.
    ///
    /// This aggregates [`remaining_time`](Self::remaining_time),
    /// [`remaining_polls`](Self::remaining_polls), and
    /// [`remaining_cost`](Self::remaining_cost) into one structure, mapping
    /// "effectively unlimited" sentinel values to `None` so callers can write
    /// `if let Some(left) = snapshot.polls` without knowing the sentinels.
    ///
    /// The snapshot is valid at the moment of the call only; quotas continue
    /// to drain as the task runs.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// # use std::time::Duration;
    /// let now = Time::from_secs(10);
    /// let budget = Budget::new()
    ///     .with_deadline(Time::from_secs(30))
    ///     .with_poll_quota(100);
    ///
    /// let left = budget.remaining(now);
    /// assert_eq!(left.deadline, Some(Duration::from_secs(20)));
    /// assert_eq!(left.polls, Some(100));
    /// assert_eq!(left.cost, None); // no cost quota configured
    /// ```
    #[inline]
    #[must_use]
    pub fn remaining(&self, now: Time) -> RemainingBudget {
        RemainingBudget {
            deadline: self.remaining_time(now),
            polls: if self.poll_quota == u32::MAX {
                None
            } else {
                Some(self.poll_quota)
            },
            cost: self.cost_quota,
        }
    }

    /// Converts the deadline to a timeout duration from the given time.
    ///
    /// Returns the same value as [`remaining_time`](Self::remaining_time).
    /// This method is provided for API compatibility with timeout-based systems.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// # use std::time::Duration;
    /// let budget = Budget::with_deadline_at_secs(30);
    /// let now = Time::from_secs(5);
    ///
    /// // 25 seconds remaining
    /// let timeout = budget.to_timeout(now);
    /// assert_eq!(timeout, Some(Duration::from_secs(25)));
    /// ```
    #[inline]
    #[must_use]
    pub fn to_timeout(&self, now: Time) -> Option<Duration> {
        self.remaining_time(now)
    }
}

/// Resource dimension covered by a [`CapabilityBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityBudgetDimension {
    /// Resident memory in bytes.
    MemoryBytes,
    /// Abstract CPU units.
    CpuUnits,
    /// I/O bytes.
    IoBytes,
    /// Cleanup budget used by drain/finalizer paths.
    Cleanup,
    /// Bytes emitted as proof, trace, or evidence artifacts.
    ArtifactBytes,
}

impl CapabilityBudgetDimension {
    /// Stable lower-case identifier for logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryBytes => "memory_bytes",
            Self::CpuUnits => "cpu_units",
            Self::IoBytes => "io_bytes",
            Self::Cleanup => "cleanup",
            Self::ArtifactBytes => "artifact_bytes",
        }
    }
}

/// Required resource dimensions for fail-closed capability-budget admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilityBudgetRequirements {
    /// Require a memory envelope.
    pub memory_bytes: bool,
    /// Require a CPU envelope.
    pub cpu_units: bool,
    /// Require an I/O envelope.
    pub io_bytes: bool,
    /// Require a cleanup envelope.
    pub cleanup: bool,
    /// Require an artifact-emission envelope.
    pub artifact_bytes: bool,
}

impl CapabilityBudgetRequirements {
    /// No resource dimensions are required.
    pub const NONE: Self = Self {
        memory_bytes: false,
        cpu_units: false,
        io_bytes: false,
        cleanup: false,
        artifact_bytes: false,
    };

    /// Creates an empty requirement set.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self::NONE
    }

    /// Requires a memory envelope.
    #[inline]
    #[must_use]
    pub const fn require_memory_bytes(mut self) -> Self {
        self.memory_bytes = true;
        self
    }

    /// Requires a CPU envelope.
    #[inline]
    #[must_use]
    pub const fn require_cpu_units(mut self) -> Self {
        self.cpu_units = true;
        self
    }

    /// Requires an I/O envelope.
    #[inline]
    #[must_use]
    pub const fn require_io_bytes(mut self) -> Self {
        self.io_bytes = true;
        self
    }

    /// Requires a cleanup envelope.
    #[inline]
    #[must_use]
    pub const fn require_cleanup(mut self) -> Self {
        self.cleanup = true;
        self
    }

    /// Requires an artifact-emission envelope.
    #[inline]
    #[must_use]
    pub const fn require_artifact_bytes(mut self) -> Self {
        self.artifact_bytes = true;
        self
    }
}

/// Fail-closed refusal for capability-budget planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityBudgetRefusal {
    /// A required resource dimension had no inherited or child-supplied limit.
    MissingRequired(CapabilityBudgetDimension),
    /// A required resource dimension was present but already exhausted.
    Exhausted(CapabilityBudgetDimension),
}

impl fmt::Display for CapabilityBudgetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequired(dimension) => {
                write!(
                    f,
                    "required capability budget missing: {}",
                    dimension.as_str()
                )
            }
            Self::Exhausted(dimension) => {
                write!(f, "capability budget exhausted: {}", dimension.as_str())
            }
        }
    }
}

impl std::error::Error for CapabilityBudgetRefusal {}

/// Explicit resource envelope carried by capability contexts and regions.
///
/// `None` means no explicit envelope for that dimension. Admission can still
/// fail closed by requiring dimensions with [`CapabilityBudgetRequirements`].
/// Child envelopes inherit parent limits and can only tighten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilityBudget {
    /// Resident memory envelope in bytes.
    pub memory_bytes: Option<u64>,
    /// Abstract CPU unit envelope.
    pub cpu_units: Option<u64>,
    /// I/O byte envelope.
    pub io_bytes: Option<u64>,
    /// Cleanup/drain budget envelope.
    pub cleanup_budget: Option<Budget>,
    /// Artifact-emission byte envelope.
    pub artifact_bytes: Option<u64>,
}

impl CapabilityBudget {
    /// No explicit resource envelopes.
    pub const UNSPECIFIED: Self = Self {
        memory_bytes: None,
        cpu_units: None,
        io_bytes: None,
        cleanup_budget: None,
        artifact_bytes: None,
    };

    /// Creates an empty capability budget.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self::UNSPECIFIED
    }

    /// Sets the memory envelope in bytes.
    #[inline]
    #[must_use]
    pub const fn with_memory_bytes(mut self, bytes: u64) -> Self {
        self.memory_bytes = Some(bytes);
        self
    }

    /// Sets the CPU envelope in abstract units.
    #[inline]
    #[must_use]
    pub const fn with_cpu_units(mut self, units: u64) -> Self {
        self.cpu_units = Some(units);
        self
    }

    /// Sets the I/O envelope in bytes.
    #[inline]
    #[must_use]
    pub const fn with_io_bytes(mut self, bytes: u64) -> Self {
        self.io_bytes = Some(bytes);
        self
    }

    /// Sets the cleanup/drain budget envelope.
    #[inline]
    #[must_use]
    pub const fn with_cleanup_budget(mut self, budget: Budget) -> Self {
        self.cleanup_budget = Some(budget);
        self
    }

    /// Sets the artifact-emission envelope in bytes.
    #[inline]
    #[must_use]
    pub const fn with_artifact_bytes(mut self, bytes: u64) -> Self {
        self.artifact_bytes = Some(bytes);
        self
    }

    /// Combines parent and child capability budgets, keeping the tightest
    /// envelope for each resource dimension.
    #[inline]
    #[must_use]
    pub fn meet(self, child: Self) -> Self {
        Self {
            memory_bytes: meet_optional_u64(self.memory_bytes, child.memory_bytes),
            cpu_units: meet_optional_u64(self.cpu_units, child.cpu_units),
            io_bytes: meet_optional_u64(self.io_bytes, child.io_bytes),
            cleanup_budget: match (self.cleanup_budget, child.cleanup_budget) {
                (Some(parent), Some(child)) => Some(parent.meet(child)),
                (budget @ Some(_), None) | (None, budget @ Some(_)) => budget,
                (None, None) => None,
            },
            artifact_bytes: meet_optional_u64(self.artifact_bytes, child.artifact_bytes),
        }
    }

    /// Computes the effective child envelope and rejects if required dimensions
    /// are absent or exhausted.
    ///
    /// Use this before admitting a region/task group that needs explicit
    /// resource envelopes. On success the returned budget is the value to carry
    /// forward in the child `Cx` or region record.
    #[inline]
    pub fn plan_child(
        self,
        child: Self,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<Self, CapabilityBudgetRefusal> {
        let effective = self.meet(child);
        effective.validate(requirements)?;
        Ok(effective)
    }

    /// Validates this budget against required resource dimensions.
    #[inline]
    pub fn validate(
        self,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<(), CapabilityBudgetRefusal> {
        validate_required_u64(
            CapabilityBudgetDimension::MemoryBytes,
            self.memory_bytes,
            requirements.memory_bytes,
        )?;
        validate_required_u64(
            CapabilityBudgetDimension::CpuUnits,
            self.cpu_units,
            requirements.cpu_units,
        )?;
        validate_required_u64(
            CapabilityBudgetDimension::IoBytes,
            self.io_bytes,
            requirements.io_bytes,
        )?;
        validate_required_cleanup(self.cleanup_budget, requirements.cleanup)?;
        validate_required_u64(
            CapabilityBudgetDimension::ArtifactBytes,
            self.artifact_bytes,
            requirements.artifact_bytes,
        )
    }
}

#[inline]
const fn meet_optional_u64(parent: Option<u64>, child: Option<u64>) -> Option<u64> {
    match (parent, child) {
        (Some(parent), Some(child)) => Some(if parent < child { parent } else { child }),
        (value @ Some(_), None) | (None, value @ Some(_)) => value,
        (None, None) => None,
    }
}

#[inline]
fn validate_required_u64(
    dimension: CapabilityBudgetDimension,
    value: Option<u64>,
    required: bool,
) -> Result<(), CapabilityBudgetRefusal> {
    if !required {
        return Ok(());
    }

    match value {
        None => Err(CapabilityBudgetRefusal::MissingRequired(dimension)),
        Some(0) => Err(CapabilityBudgetRefusal::Exhausted(dimension)),
        Some(_) => Ok(()),
    }
}

#[inline]
fn validate_required_cleanup(
    budget: Option<Budget>,
    required: bool,
) -> Result<(), CapabilityBudgetRefusal> {
    if !required {
        return Ok(());
    }

    match budget {
        None => Err(CapabilityBudgetRefusal::MissingRequired(
            CapabilityBudgetDimension::Cleanup,
        )),
        Some(budget) if budget.is_exhausted() => Err(CapabilityBudgetRefusal::Exhausted(
            CapabilityBudgetDimension::Cleanup,
        )),
        Some(_) => Ok(()),
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Budget");
        if let Some(deadline) = self.deadline {
            d.field("deadline", &deadline);
        }
        if self.poll_quota < u32::MAX {
            d.field("poll_quota", &self.poll_quota);
        }
        if let Some(cost) = self.cost_quota {
            d.field("cost_quota", &cost);
        }
        d.field("priority", &self.priority);
        d.finish()
    }
}

// ============================================================================
// Min-Plus Network Calculus Curves (Hard Bounds)
// ============================================================================

/// Errors returned when constructing a min-plus curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    /// Curve samples must not be empty.
    EmptySamples,
    /// Curve samples must be nondecreasing.
    NonMonotone {
        /// Index where monotonicity was violated.
        index: usize,
        /// Previous sample value.
        prev: u64,
        /// Next sample value.
        next: u64,
    },
}

/// A discrete min-plus curve with a linear tail.
///
/// Curves are defined for nonnegative integer time `t` with:
/// - `samples[t]` for `t <= horizon`
/// - `samples[horizon] + tail_rate * (t - horizon)` for `t > horizon`
///
/// Samples must be nondecreasing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinPlusCurve {
    samples: Vec<u64>,
    tail_rate: u64,
}

impl MinPlusCurve {
    /// Creates a curve from samples and a tail rate.
    ///
    /// # Errors
    /// Returns [`CurveError::EmptySamples`] if `samples` is empty, or
    /// [`CurveError::NonMonotone`] if samples are not nondecreasing.
    #[inline]
    pub fn new(samples: Vec<u64>, tail_rate: u64) -> Result<Self, CurveError> {
        if samples.is_empty() {
            return Err(CurveError::EmptySamples);
        }

        for idx in 1..samples.len() {
            if samples[idx] < samples[idx.saturating_sub(1)] {
                return Err(CurveError::NonMonotone {
                    index: idx,
                    prev: samples[idx.saturating_sub(1)],
                    next: samples[idx],
                });
            }
        }

        Ok(Self { samples, tail_rate })
    }

    /// Creates a curve with a flat tail from samples.
    ///
    /// # Errors
    /// Returns an error if samples are empty or not nondecreasing.
    #[inline]
    pub fn from_samples(samples: Vec<u64>) -> Result<Self, CurveError> {
        Self::new(samples, 0)
    }

    /// Creates a token-bucket arrival curve `burst + rate * t`.
    #[inline]
    #[must_use]
    pub fn from_token_bucket(burst: u64, rate: u64, horizon: usize) -> Self {
        let mut samples = Vec::with_capacity(horizon.saturating_add(1));
        for t in 0..=horizon {
            let inc = rate.saturating_mul(t as u64);
            samples.push(burst.saturating_add(inc));
        }
        Self {
            samples,
            tail_rate: rate,
        }
    }

    /// Creates a rate-latency service curve `max(0, rate * (t - latency))`.
    #[inline]
    #[must_use]
    pub fn from_rate_latency(rate: u64, latency: usize, horizon: usize) -> Self {
        let mut samples = Vec::with_capacity(horizon.saturating_add(1));
        for t in 0..=horizon {
            if t <= latency {
                samples.push(0);
            } else {
                let dt = (t - latency) as u64;
                samples.push(rate.saturating_mul(dt));
            }
        }
        Self {
            samples,
            tail_rate: rate,
        }
    }

    /// Returns the discrete horizon (last sample index).
    #[must_use]
    #[inline]
    pub fn horizon(&self) -> usize {
        self.samples.len().saturating_sub(1)
    }

    /// Returns the tail rate used for extrapolation beyond the horizon.
    #[must_use]
    #[inline]
    pub fn tail_rate(&self) -> u64 {
        self.tail_rate
    }

    /// Returns the curve value at integer time `t`.
    #[must_use]
    #[inline]
    pub fn value_at(&self, t: usize) -> u64 {
        let horizon = self.horizon();
        if t <= horizon {
            self.samples[t]
        } else {
            let extra = (t - horizon) as u64;
            self.samples[horizon].saturating_add(self.tail_rate.saturating_mul(extra))
        }
    }

    /// Returns the underlying samples.
    #[must_use]
    #[inline]
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    /// Computes the min-plus convolution `(self ⊗ other)` over a horizon.
    ///
    /// This is O(horizon^2) and intended for small horizons/demonstrations.
    #[inline]
    #[must_use]
    pub fn min_plus_convolution(&self, other: &Self, horizon: usize) -> Self {
        let mut samples = Vec::with_capacity(horizon.saturating_add(1));
        for t in 0..=horizon {
            let mut best = u64::MAX;
            for s in 0..=t {
                let a = self.value_at(s);
                let b = other.value_at(t - s);
                let sum = a.saturating_add(b);
                if sum < best {
                    best = sum;
                }
            }
            samples.push(best);
        }

        Self {
            samples,
            tail_rate: self.tail_rate.min(other.tail_rate),
        }
    }
}

/// Arrival/service curve pair for admission control hard bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurveBudget {
    /// Arrival curve (demand).
    pub arrival: MinPlusCurve,
    /// Service curve (supply).
    pub service: MinPlusCurve,
}

impl CurveBudget {
    /// Computes the backlog bound `sup_t (arrival(t) - service(t))` over a horizon.
    #[must_use]
    #[inline]
    pub fn backlog_bound(&self, horizon: usize) -> u64 {
        backlog_bound(&self.arrival, &self.service, horizon)
    }

    /// Computes the delay bound over a horizon with a max delay search window.
    ///
    /// Returns `None` if no delay bound is found within `max_delay`.
    #[must_use]
    #[inline]
    pub fn delay_bound(&self, horizon: usize, max_delay: usize) -> Option<usize> {
        delay_bound(&self.arrival, &self.service, horizon, max_delay)
    }
}

/// Computes the backlog bound `sup_t (arrival(t) - service(t))` over a horizon.
#[inline]
#[must_use]
pub fn backlog_bound(arrival: &MinPlusCurve, service: &MinPlusCurve, horizon: usize) -> u64 {
    let mut worst = 0;
    for t in 0..=horizon {
        let demand = arrival.value_at(t);
        let supply = service.value_at(t);
        let backlog = demand.saturating_sub(supply);
        if backlog > worst {
            worst = backlog;
        }
    }
    worst
}

/// Computes a delay bound `d` such that `arrival(t) <= service(t + d)` for all `t`.
///
/// Returns `None` if no bound is found within `max_delay`.
#[inline]
#[must_use]
pub fn delay_bound(
    arrival: &MinPlusCurve,
    service: &MinPlusCurve,
    horizon: usize,
    max_delay: usize,
) -> Option<usize> {
    let mut worst_delay = 0;
    for t in 0..=horizon {
        let demand = arrival.value_at(t);
        let mut found = None;
        for d in 0..=max_delay {
            if service.value_at(t + d) >= demand {
                found = Some(d);
                break;
            }
        }
        let delay = found?;
        if delay > worst_delay {
            worst_delay = delay;
        }
    }
    Some(worst_delay)
}

#[cfg(test)]
#[path = "budget_inline_tests.rs"]
mod tests;
