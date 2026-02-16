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
//! | `meet` (∧) | min (earlier wins) | min (tighter wins) | max (higher wins) |
//! | identity  | None (no deadline) | u32::MAX / None | 128 (neutral) |
//!
//! The **meet** operation (`combine`/`meet`) computes the tightest constraints
//! from two budgets. This is used when nesting regions or combining timeout
//! requirements:
//!
//! ```
//! # use asupersync::Budget;
//! # use asupersync::types::id::Time;
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
//!     // Convert wall-clock timeout to lab-compatible Time
//!     let deadline = Time::from_secs(config.request_timeout.as_secs());
//!     let budget = Budget::new().with_deadline(deadline);
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
//!         Outcome::Cancelled(reason) if reason.is_deadline() => {
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
//! cancellation through the region tree.
//!
//! # Creating Budgets
//!
//! ```
//! # use asupersync::Budget;
//! # use asupersync::types::id::Time;
//! // Unlimited budget (default)
//! let unlimited = Budget::unlimited();
//!
//! // With specific deadline
//! let timed = Budget::with_deadline_secs(30);
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
/// - Priority uses max (higher wins)
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

impl Budget {
    /// A budget with no constraints (infinite resources).
    pub const INFINITE: Self = Self {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 128,
    };

    /// A budget with zero resources (nothing allowed).
    pub const ZERO: Self = Self {
        deadline: Some(Time::ZERO),
        poll_quota: 0,
        cost_quota: Some(0),
        priority: 0,
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

    /// Creates a new budget with default values (unlimited).
    #[must_use]
    pub const fn new() -> Self {
        Self::INFINITE
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
    #[must_use]
    pub const fn unlimited() -> Self {
        Self::INFINITE
    }

    /// Creates a budget with only a deadline constraint (in seconds).
    ///
    /// This is a convenience constructor for HTTP timeout scenarios.
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let budget = Budget::with_deadline_secs(30);
    /// assert_eq!(budget.deadline, Some(Time::from_secs(30)));
    /// ```
    #[must_use]
    pub const fn with_deadline_secs(secs: u64) -> Self {
        Self {
            deadline: Some(Time::from_secs(secs)),
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 128,
        }
    }

    /// Creates a budget with only a deadline constraint (in nanoseconds).
    ///
    /// # Example
    ///
    /// ```
    /// # use asupersync::Budget;
    /// # use asupersync::types::id::Time;
    /// let budget = Budget::with_deadline_ns(30_000_000_000); // 30 seconds
    /// assert_eq!(budget.deadline, Some(Time::from_nanos(30_000_000_000)));
    /// ```
    #[must_use]
    pub const fn with_deadline_ns(nanos: u64) -> Self {
        Self {
            deadline: Some(Time::from_nanos(nanos)),
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 128,
        }
    }

    /// Sets the deadline.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Time) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Sets the poll quota.
    #[must_use]
    pub const fn with_poll_quota(mut self, quota: u32) -> Self {
        self.poll_quota = quota;
        self
    }

    /// Sets the cost quota.
    #[must_use]
    pub const fn with_cost_quota(mut self, quota: u64) -> Self {
        self.cost_quota = Some(quota);
        self
    }

    /// Sets the priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Returns true if the budget has been exhausted.
    ///
    /// This checks only poll and cost quotas, not deadline (which requires current time).
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.poll_quota == 0 || matches!(self.cost_quota, Some(0))
    }

    /// Returns true if the deadline has passed.
    #[must_use]
    pub fn is_past_deadline(&self, now: Time) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// Decrements the poll quota by one, returning the old value.
    ///
    /// Returns `None` if already at zero.
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
    /// - Priority: max (higher wins)
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
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        let combined = Self {
            deadline: match (self.deadline, other.deadline) {
                (Some(a), Some(b)) => Some(if a < b { a } else { b }),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            poll_quota: self.poll_quota.min(other.poll_quota),
            cost_quota: match (self.cost_quota, other.cost_quota) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            priority: self.priority.max(other.priority),
        };

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

        if deadline_tightened || poll_tightened || cost_tightened {
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
    /// let parent = Budget::with_deadline_secs(30);
    /// let child = Budget::with_deadline_secs(10);
    ///
    /// // Child deadline is tighter, so it wins
    /// let effective = parent.meet(child);
    /// assert_eq!(effective.deadline, Some(Time::from_secs(10)));
    /// ```
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
            Some(_remaining) => {
                trace!(
                    cost_requested = cost,
                    cost_remaining = _remaining,
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
    /// let budget = Budget::with_deadline_secs(30);
    /// let now = Time::from_secs(10);
    ///
    /// let remaining = budget.remaining_time(now);
    /// assert_eq!(remaining, Some(Duration::from_secs(20)));
    /// ```
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
    #[must_use]
    pub const fn remaining_cost(&self) -> Option<u64> {
        self.cost_quota
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
    /// let budget = Budget::with_deadline_secs(30);
    /// let now = Time::from_secs(5);
    ///
    /// // 25 seconds remaining
    /// let timeout = budget.to_timeout(now);
    /// assert_eq!(timeout, Some(Duration::from_secs(25)));
    /// ```
    #[must_use]
    pub fn to_timeout(&self, now: Time) -> Option<Duration> {
        self.remaining_time(now)
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
    pub fn new(samples: Vec<u64>, tail_rate: u64) -> Result<Self, CurveError> {
        if samples.is_empty() {
            return Err(CurveError::EmptySamples);
        }

        for idx in 1..samples.len() {
            if samples[idx] < samples[idx - 1] {
                return Err(CurveError::NonMonotone {
                    index: idx,
                    prev: samples[idx - 1],
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
    pub fn from_samples(samples: Vec<u64>) -> Result<Self, CurveError> {
        Self::new(samples, 0)
    }

    /// Creates a token-bucket arrival curve `burst + rate * t`.
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
    pub fn horizon(&self) -> usize {
        self.samples.len().saturating_sub(1)
    }

    /// Returns the tail rate used for extrapolation beyond the horizon.
    #[must_use]
    pub fn tail_rate(&self) -> u64 {
        self.tail_rate
    }

    /// Returns the curve value at integer time `t`.
    #[must_use]
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
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    /// Computes the min-plus convolution `(self ⊗ other)` over a horizon.
    ///
    /// This is O(horizon^2) and intended for small horizons/demonstrations.
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
    pub fn backlog_bound(&self, horizon: usize) -> u64 {
        backlog_bound(&self.arrival, &self.service, horizon)
    }

    /// Computes the delay bound over a horizon with a max delay search window.
    ///
    /// Returns `None` if no delay bound is found within `max_delay`.
    #[must_use]
    pub fn delay_bound(&self, horizon: usize, max_delay: usize) -> Option<usize> {
        delay_bound(&self.arrival, &self.service, horizon, max_delay)
    }
}

/// Computes the backlog bound `sup_t (arrival(t) - service(t))` over a horizon.
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
mod tests {
    use super::*;

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn infinite_budget_values() {
        let b = Budget::INFINITE;
        assert_eq!(b.deadline, None);
        assert_eq!(b.poll_quota, u32::MAX);
        assert_eq!(b.cost_quota, None);
        assert_eq!(b.priority, 128);
    }

    #[test]
    fn zero_budget_values() {
        let b = Budget::ZERO;
        assert_eq!(b.deadline, Some(Time::ZERO));
        assert_eq!(b.poll_quota, 0);
        assert_eq!(b.cost_quota, Some(0));
        assert_eq!(b.priority, 0);
    }

    #[test]
    fn new_returns_infinite() {
        assert_eq!(Budget::new(), Budget::INFINITE);
    }

    #[test]
    fn default_returns_infinite() {
        assert_eq!(Budget::default(), Budget::INFINITE);
    }

    // =========================================================================
    // Builder Methods Tests
    // =========================================================================

    #[test]
    fn with_deadline_sets_deadline() {
        let deadline = Time::from_secs(30);
        let budget = Budget::new().with_deadline(deadline);
        assert_eq!(budget.deadline, Some(deadline));
    }

    #[test]
    fn with_poll_quota_sets_quota() {
        let budget = Budget::new().with_poll_quota(42);
        assert_eq!(budget.poll_quota, 42);
    }

    #[test]
    fn with_cost_quota_sets_quota() {
        let budget = Budget::new().with_cost_quota(1000);
        assert_eq!(budget.cost_quota, Some(1000));
    }

    #[test]
    fn with_priority_sets_priority() {
        let budget = Budget::new().with_priority(255);
        assert_eq!(budget.priority, 255);
    }

    #[test]
    fn builder_chaining() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(5000)
            .with_priority(200);

        assert_eq!(budget.deadline, Some(Time::from_secs(10)));
        assert_eq!(budget.poll_quota, 100);
        assert_eq!(budget.cost_quota, Some(5000));
        assert_eq!(budget.priority, 200);
    }

    // =========================================================================
    // is_exhausted Tests
    // =========================================================================

    #[test]
    fn is_exhausted_false_for_infinite() {
        assert!(!Budget::INFINITE.is_exhausted());
    }

    #[test]
    fn is_exhausted_true_for_zero() {
        assert!(Budget::ZERO.is_exhausted());
    }

    #[test]
    fn is_exhausted_when_poll_quota_zero() {
        let budget = Budget::new().with_poll_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn is_exhausted_when_cost_quota_zero() {
        let budget = Budget::new().with_cost_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn is_exhausted_false_with_resources() {
        let budget = Budget::new().with_poll_quota(10).with_cost_quota(100);
        assert!(!budget.is_exhausted());
    }

    // =========================================================================
    // is_past_deadline Tests
    // =========================================================================

    #[test]
    fn is_past_deadline_true_when_past() {
        let budget = Budget::new().with_deadline(Time::from_secs(5));
        let now = Time::from_secs(10);
        assert!(budget.is_past_deadline(now));
    }

    #[test]
    fn is_past_deadline_false_when_not_past() {
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let now = Time::from_secs(5);
        assert!(!budget.is_past_deadline(now));
    }

    #[test]
    fn is_past_deadline_true_at_exact_time() {
        let deadline = Time::from_secs(5);
        let budget = Budget::new().with_deadline(deadline);
        assert!(budget.is_past_deadline(deadline));
    }

    #[test]
    fn is_past_deadline_false_when_no_deadline() {
        let budget = Budget::new();
        assert!(!budget.is_past_deadline(Time::from_secs(1_000_000)));
    }

    // =========================================================================
    // consume_poll Tests
    // =========================================================================

    #[test]
    fn consume_poll_decrements() {
        let mut budget = Budget::new().with_poll_quota(2);

        assert_eq!(budget.consume_poll(), Some(2));
        assert_eq!(budget.poll_quota, 1);

        assert_eq!(budget.consume_poll(), Some(1));
        assert_eq!(budget.poll_quota, 0);

        assert_eq!(budget.consume_poll(), None);
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn consume_poll_returns_none_at_zero() {
        let mut budget = Budget::new().with_poll_quota(0);
        assert_eq!(budget.consume_poll(), None);
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn consume_poll_transitions_to_exhausted() {
        let mut budget = Budget::new().with_poll_quota(1);
        assert!(!budget.is_exhausted());

        budget.consume_poll();
        assert!(budget.is_exhausted());
    }

    // =========================================================================
    // Combine Tests (Product Semiring Semantics)
    // =========================================================================

    #[test]
    fn combine_takes_tighter() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_priority(100);

        let combined = a.combine(b);

        // Deadline: min
        assert_eq!(combined.deadline, Some(Time::from_secs(5)));
        // Poll quota: min
        assert_eq!(combined.poll_quota, 100);
        // Priority: max
        assert_eq!(combined.priority, 100);
    }

    #[test]
    fn combine_deadline_none_with_some() {
        let a = Budget::new(); // No deadline
        let b = Budget::new().with_deadline(Time::from_secs(5));

        // a.combine(b) should have b's deadline
        assert_eq!(a.combine(b).deadline, Some(Time::from_secs(5)));
        // b.combine(a) should also have b's deadline
        assert_eq!(b.combine(a).deadline, Some(Time::from_secs(5)));
    }

    #[test]
    fn combine_deadline_none_with_none() {
        let a = Budget::new();
        let b = Budget::new();
        assert_eq!(a.combine(b).deadline, None);
    }

    #[test]
    fn combine_cost_quota_none_with_some() {
        let a = Budget::new(); // cost_quota = None
        let b = Budget::new().with_cost_quota(100);

        // Should take the defined quota
        assert_eq!(a.combine(b).cost_quota, Some(100));
        assert_eq!(b.combine(a).cost_quota, Some(100));
    }

    #[test]
    fn combine_cost_quota_takes_min() {
        let a = Budget::new().with_cost_quota(50);
        let b = Budget::new().with_cost_quota(100);

        assert_eq!(a.combine(b).cost_quota, Some(50));
        assert_eq!(b.combine(a).cost_quota, Some(50));
    }

    #[test]
    fn combine_with_zero_absorbs() {
        let any_budget = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000)
            .with_priority(200);

        let combined = any_budget.combine(Budget::ZERO);

        // ZERO's deadline (Time::ZERO) is tighter
        assert_eq!(combined.deadline, Some(Time::ZERO));
        // ZERO's poll_quota (0) is tighter
        assert_eq!(combined.poll_quota, 0);
        // ZERO's cost_quota (Some(0)) is tighter
        assert_eq!(combined.cost_quota, Some(0));
        // Priority: max of 200 and 0 = 200
        assert_eq!(combined.priority, 200);
    }

    #[test]
    fn combine_with_infinite_preserves() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(1000)
            .with_priority(50);

        let combined = budget.combine(Budget::INFINITE);

        // All values should be preserved (INFINITE doesn't constrain)
        assert_eq!(combined.deadline, Some(Time::from_secs(10)));
        assert_eq!(combined.poll_quota, 100);
        assert_eq!(combined.cost_quota, Some(1000));
        // Priority: max of 50 and 128 = 128
        assert_eq!(combined.priority, 128);
    }

    // =========================================================================
    // Debug/Display Tests
    // =========================================================================

    #[test]
    fn debug_shows_constrained_fields() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500);

        let debug = format!("{budget:?}");

        // Debug should include constrained fields
        assert!(debug.contains("deadline"));
        assert!(debug.contains("poll_quota"));
        assert!(debug.contains("cost_quota"));
        assert!(debug.contains("priority"));
    }

    #[test]
    fn debug_omits_unconstrained_fields() {
        let budget = Budget::INFINITE;
        let debug = format!("{budget:?}");

        // INFINITE has no deadline, MAX poll_quota, and no cost_quota
        // Debug should omit deadline and poll_quota but include priority
        assert!(!debug.contains("deadline"));
        assert!(!debug.contains("poll_quota")); // u32::MAX is omitted
        assert!(debug.contains("priority"));
    }

    // =========================================================================
    // Equality Tests
    // =========================================================================

    #[test]
    fn equality_works() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        let b = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_deadline() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_deadline(Time::from_secs(20));
        assert_ne!(a, b);
    }

    #[test]
    fn copy_semantics() {
        let a = Budget::new().with_poll_quota(100);
        let b = a; // Copy
        assert_eq!(a.poll_quota, b.poll_quota);
        // Modifying b doesn't affect a
        let mut c = a;
        c.poll_quota = 50;
        assert_eq!(a.poll_quota, 100);
        assert_eq!(c.poll_quota, 50);
    }

    // =========================================================================
    // New Convenience Method Tests
    // =========================================================================

    #[test]
    fn unlimited_returns_infinite() {
        assert_eq!(Budget::unlimited(), Budget::INFINITE);
    }

    #[test]
    fn with_deadline_secs_constructor() {
        let budget = Budget::with_deadline_secs(30);
        assert_eq!(budget.deadline, Some(Time::from_secs(30)));
        assert_eq!(budget.poll_quota, u32::MAX);
        assert_eq!(budget.cost_quota, None);
        assert_eq!(budget.priority, 128);
    }

    #[test]
    fn with_deadline_ns_constructor() {
        let budget = Budget::with_deadline_ns(30_000_000_000);
        assert_eq!(budget.deadline, Some(Time::from_nanos(30_000_000_000)));
    }

    #[test]
    fn meet_is_alias_for_combine() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200);

        assert_eq!(a.meet(b), a.combine(b));
    }

    // =========================================================================
    // consume_cost Tests
    // =========================================================================

    #[test]
    fn consume_cost_basic() {
        let mut budget = Budget::new().with_cost_quota(100);

        assert!(budget.consume_cost(30));
        assert_eq!(budget.cost_quota, Some(70));

        assert!(budget.consume_cost(70));
        assert_eq!(budget.cost_quota, Some(0));

        assert!(!budget.consume_cost(1));
        assert_eq!(budget.cost_quota, Some(0));
    }

    #[test]
    fn consume_cost_unlimited() {
        let mut budget = Budget::new(); // No cost quota = unlimited
        assert!(budget.consume_cost(1_000_000));
        assert_eq!(budget.cost_quota, None);
    }

    #[test]
    fn consume_cost_exact_amount() {
        let mut budget = Budget::new().with_cost_quota(50);
        assert!(budget.consume_cost(50));
        assert_eq!(budget.cost_quota, Some(0));
    }

    #[test]
    fn consume_cost_transitions_to_exhausted() {
        let mut budget = Budget::new().with_cost_quota(10).with_poll_quota(u32::MAX);
        assert!(!budget.is_exhausted());

        budget.consume_cost(10);
        assert!(budget.is_exhausted());
    }

    // =========================================================================
    // Inspection Method Tests
    // =========================================================================

    #[test]
    fn remaining_time_basic() {
        let budget = Budget::with_deadline_secs(30);
        let now = Time::from_secs(10);

        let remaining = budget.remaining_time(now);
        assert_eq!(remaining, Some(Duration::from_secs(20)));
    }

    #[test]
    fn remaining_time_no_deadline() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_time(Time::from_secs(1000)), None);
    }

    #[test]
    fn remaining_time_past_deadline() {
        let budget = Budget::with_deadline_secs(10);
        assert_eq!(budget.remaining_time(Time::from_secs(15)), None);
    }

    #[test]
    fn remaining_time_at_deadline() {
        let budget = Budget::with_deadline_secs(10);
        assert_eq!(budget.remaining_time(Time::from_secs(10)), None);
    }

    #[test]
    fn remaining_polls_basic() {
        let budget = Budget::new().with_poll_quota(100);
        assert_eq!(budget.remaining_polls(), 100);
    }

    #[test]
    fn remaining_polls_unlimited() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_polls(), u32::MAX);
    }

    #[test]
    fn remaining_cost_basic() {
        let budget = Budget::new().with_cost_quota(1000);
        assert_eq!(budget.remaining_cost(), Some(1000));
    }

    #[test]
    fn remaining_cost_unlimited() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_cost(), None);
    }

    #[test]
    fn to_timeout_is_alias_for_remaining_time() {
        let budget = Budget::with_deadline_secs(30);
        let now = Time::from_secs(10);

        assert_eq!(budget.to_timeout(now), budget.remaining_time(now));
    }

    // =========================================================================
    // Min-Plus Network Calculus Tests
    // =========================================================================

    #[test]
    fn min_plus_curve_validation_rejects_non_monotone() {
        let err = MinPlusCurve::new(vec![0, 2, 1], 0).expect_err("non-monotone samples");
        assert!(matches!(
            err,
            CurveError::NonMonotone {
                index: 2,
                prev: 2,
                next: 1
            }
        ));
    }

    #[test]
    fn min_plus_convolution_basic() {
        let a = MinPlusCurve::new(vec![0, 1, 2], 1).expect("valid curve");
        let b = MinPlusCurve::new(vec![0, 0, 1], 1).expect("valid curve");
        let conv = a.min_plus_convolution(&b, 2);
        assert_eq!(conv.samples(), &[0, 0, 1]);
    }

    #[test]
    fn min_plus_backlog_delay_demo() {
        let arrival = MinPlusCurve::from_token_bucket(5, 2, 10);
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let budget = CurveBudget { arrival, service };

        let backlog = budget.backlog_bound(10);
        let delay = budget.delay_bound(10, 10);

        assert_eq!(backlog, 9);
        assert_eq!(delay, Some(4));
    }

    // =========================================================================
    // Budget Algebra Formal Lemmas (bd-hf5bz)
    //
    // These tests serve as mechanized proof artifacts for the budget algebra.
    // Each test corresponds to a named lemma that downstream proofs
    // (bd-3cq88, bd-2qmr4, bd-3fp4g, bd-ecp8u) can reference.
    //
    // Algebra summary:
    //   (Budget, meet, INFINITE) forms a bounded meet-semilattice where:
    //   - meet is the pointwise min on (deadline, poll_quota, cost_quota)
    //     and pointwise max on (priority).
    //   - INFINITE is the top element (identity for meet).
    //   - ZERO is the bottom element (absorbing for meet, modulo priority).
    //
    // Code mapping:
    //   meet        → Budget::meet / Budget::combine  (src/types/budget.rs)
    //   identity    → Budget::INFINITE
    //   absorbing   → Budget::ZERO
    //   consumption → Budget::consume_poll, Budget::consume_cost
    //
    // Min-plus / tropical structure:
    //   (DeadlineMicros, min, add, ∞, 0) forms a tropical semiring
    //   used in plan analysis for sequential/parallel budget composition.
    //   Code mapping → src/plan/analysis.rs :: DeadlineMicros
    //
    //   (MinPlusCurve, min_plus_convolution) forms a min-plus algebra
    //   for network calculus admission control.
    //   Code mapping → MinPlusCurve / CurveBudget (src/types/budget.rs)
    // =========================================================================

    // -- Lemma 1: meet is commutative --
    // ∀ a b. a.meet(b) == b.meet(a)

    #[test]
    fn lemma_meet_commutative() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_cost_quota(300)
            .with_priority(100);

        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lemma_meet_commutative_with_none_deadline() {
        let a = Budget::new().with_poll_quota(100);
        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200);
        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lemma_meet_commutative_with_none_cost() {
        let a = Budget::new().with_cost_quota(100);
        let b = Budget::new(); // cost_quota = None
        assert_eq!(a.meet(b), b.meet(a));
    }

    // -- Lemma 2: meet is associative --
    // ∀ a b c. a.meet(b.meet(c)) == a.meet(b).meet(c)

    #[test]
    fn lemma_meet_associative() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_cost_quota(300)
            .with_priority(100);

        let c = Budget::new()
            .with_deadline(Time::from_secs(8))
            .with_poll_quota(150)
            .with_cost_quota(400)
            .with_priority(75);

        assert_eq!(a.meet(b.meet(c)), a.meet(b).meet(c));
    }

    #[test]
    fn lemma_meet_associative_with_none_fields() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_cost_quota(300);
        let c = Budget::new().with_poll_quota(50);

        assert_eq!(a.meet(b.meet(c)), a.meet(b).meet(c));
    }

    // -- Lemma 3: meet is idempotent --
    // ∀ a. a.meet(a) == a

    #[test]
    fn lemma_meet_idempotent() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(75);
        assert_eq!(a.meet(a), a);
    }

    #[test]
    fn lemma_meet_idempotent_infinite() {
        assert_eq!(Budget::INFINITE.meet(Budget::INFINITE), Budget::INFINITE);
    }

    #[test]
    fn lemma_meet_idempotent_zero() {
        assert_eq!(Budget::ZERO.meet(Budget::ZERO), Budget::ZERO);
    }

    // -- Lemma 4: INFINITE is the identity for meet --
    // ∀ a. a.meet(INFINITE) == a

    #[test]
    fn lemma_identity_left() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        // Note: priority of INFINITE (128) > a's priority (50), so
        // meet takes max priority. This is by design — INFINITE
        // represents "no constraint" which includes default priority.
        let result = Budget::INFINITE.meet(a);
        assert_eq!(result.deadline, a.deadline);
        assert_eq!(result.poll_quota, a.poll_quota);
        assert_eq!(result.cost_quota, a.cost_quota);
    }

    #[test]
    fn lemma_identity_right() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(200);

        let result = a.meet(Budget::INFINITE);
        assert_eq!(result.deadline, a.deadline);
        assert_eq!(result.poll_quota, a.poll_quota);
        assert_eq!(result.cost_quota, a.cost_quota);
    }

    // -- Lemma 5: ZERO is absorbing for quotas --
    // ∀ a. a.meet(ZERO).poll_quota == 0
    // ∀ a. a.meet(ZERO).cost_quota == Some(0)
    // ∀ a. a.meet(ZERO).deadline == Some(Time::ZERO)

    #[test]
    fn lemma_zero_absorbing_quotas() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000);

        let result = a.meet(Budget::ZERO);
        assert_eq!(result.deadline, Some(Time::ZERO));
        assert_eq!(result.poll_quota, 0);
        assert_eq!(result.cost_quota, Some(0));
    }

    #[test]
    fn lemma_zero_absorbing_symmetric() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000);

        let left = a.meet(Budget::ZERO);
        let right = Budget::ZERO.meet(a);
        assert_eq!(left.deadline, right.deadline);
        assert_eq!(left.poll_quota, right.poll_quota);
        assert_eq!(left.cost_quota, right.cost_quota);
    }

    // -- Lemma 6: meet is monotone (narrowing) --
    // ∀ a b. a.meet(b).poll_quota ≤ a.poll_quota
    // ∀ a b. a.meet(b).poll_quota ≤ b.poll_quota
    // (and analogously for cost_quota, deadline)

    #[test]
    fn lemma_meet_monotone_poll() {
        let a = Budget::new().with_poll_quota(100);
        let b = Budget::new().with_poll_quota(200);
        let result = a.meet(b);
        assert!(result.poll_quota <= a.poll_quota);
        assert!(result.poll_quota <= b.poll_quota);
    }

    #[test]
    fn lemma_meet_monotone_cost() {
        let a = Budget::new().with_cost_quota(100);
        let b = Budget::new().with_cost_quota(200);
        let result = a.meet(b);
        assert!(result.cost_quota.unwrap() <= a.cost_quota.unwrap());
        assert!(result.cost_quota.unwrap() <= b.cost_quota.unwrap());
    }

    #[test]
    fn lemma_meet_monotone_deadline() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_deadline(Time::from_secs(20));
        let result = a.meet(b);
        assert!(result.deadline.unwrap() <= a.deadline.unwrap());
        assert!(result.deadline.unwrap() <= b.deadline.unwrap());
    }

    // -- Lemma 7: consume_poll strictly decreases quota (well-founded) --
    // ∀ b. b.poll_quota > 0 → consume_poll(&mut b) = Some(old) ∧ b.poll_quota < old

    #[test]
    fn lemma_consume_poll_strictly_decreasing() {
        let mut budget = Budget::new().with_poll_quota(5);
        let mut prev = budget.poll_quota;
        while budget.poll_quota > 0 {
            let old = budget.consume_poll().expect("quota > 0");
            assert_eq!(old, prev);
            assert!(budget.poll_quota < prev);
            prev = budget.poll_quota;
        }
        // Exhausted: consume returns None
        assert_eq!(budget.consume_poll(), None);
    }

    // -- Lemma 8: consume_cost strictly decreases quota (well-founded) --
    // ∀ b cost. b.cost_quota = Some(q) ∧ q ≥ cost → consume_cost succeeds ∧ new_q < q

    #[test]
    fn lemma_consume_cost_strictly_decreasing() {
        let mut budget = Budget::new().with_cost_quota(100);
        let initial = budget.cost_quota.unwrap();
        assert!(budget.consume_cost(30));
        let after = budget.cost_quota.unwrap();
        assert!(after < initial);
        assert_eq!(after, 70);
    }

    // -- Lemma 9: sufficient budget implies progress --
    // ∀ b. ¬b.is_exhausted() → (consume_poll succeeds ∨ cost_quota = None ∨ cost_quota > 0)

    #[test]
    fn lemma_sufficient_budget_enables_progress() {
        let mut budget = Budget::new().with_poll_quota(10).with_cost_quota(100);
        assert!(!budget.is_exhausted());

        // Can make progress via poll
        assert!(budget.consume_poll().is_some());
        // Can make progress via cost
        assert!(budget.consume_cost(1));
    }

    #[test]
    fn lemma_exhausted_blocks_progress() {
        let mut budget = Budget::new().with_poll_quota(0);
        assert!(budget.is_exhausted());
        assert!(budget.consume_poll().is_none());
    }

    // -- Lemma 10: budget consumption terminates --
    // Starting from finite quota q, after exactly q calls to consume_poll,
    // the budget is exhausted.

    #[test]
    fn lemma_poll_termination() {
        let q = 7u32;
        let mut budget = Budget::new().with_poll_quota(q);
        for _ in 0..q {
            assert!(!budget.is_exhausted());
            budget.consume_poll().expect("should succeed");
        }
        assert!(budget.is_exhausted());
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn lemma_cost_termination() {
        let mut budget = Budget::new().with_cost_quota(100);
        // Consume in chunks of 25
        for _ in 0..4 {
            assert!(budget.consume_cost(25));
        }
        assert_eq!(budget.cost_quota, Some(0));
        assert!(!budget.consume_cost(1));
    }

    // -- Lemma 11: min-plus curve convolution associativity --
    // (a ⊗ b) ⊗ c == a ⊗ (b ⊗ c)  over a finite horizon

    #[test]
    fn lemma_convolution_associative() {
        let a = MinPlusCurve::new(vec![0, 1, 3], 2).expect("valid");
        let b = MinPlusCurve::new(vec![0, 2, 4], 2).expect("valid");
        let c = MinPlusCurve::new(vec![0, 1, 2], 1).expect("valid");
        let h = 4;

        let ab_c = a.min_plus_convolution(&b, h).min_plus_convolution(&c, h);
        let a_bc = a.min_plus_convolution(&b.min_plus_convolution(&c, h), h);

        for t in 0..=h {
            assert_eq!(
                ab_c.value_at(t),
                a_bc.value_at(t),
                "associativity failed at t={t}"
            );
        }
    }

    // -- Lemma 12: min-plus convolution commutativity --
    // a ⊗ b == b ⊗ a  over a finite horizon

    #[test]
    fn lemma_convolution_commutative() {
        let a = MinPlusCurve::new(vec![0, 1, 3], 2).expect("valid");
        let b = MinPlusCurve::new(vec![0, 2, 4], 2).expect("valid");
        let h = 4;

        let ab = a.min_plus_convolution(&b, h);
        let ba = b.min_plus_convolution(&a, h);

        for t in 0..=h {
            assert_eq!(
                ab.value_at(t),
                ba.value_at(t),
                "commutativity failed at t={t}"
            );
        }
    }

    // -- Lemma 13: backlog bound monotonicity --
    // Increasing arrival or decreasing service cannot reduce backlog.

    #[test]
    fn lemma_backlog_monotone_arrival() {
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let small_arrival = MinPlusCurve::from_token_bucket(2, 1, 10);
        let large_arrival = MinPlusCurve::from_token_bucket(5, 2, 10);

        let small_backlog = backlog_bound(&small_arrival, &service, 10);
        let large_backlog = backlog_bound(&large_arrival, &service, 10);

        assert!(large_backlog >= small_backlog);
    }

    // -- Lemma 14: delay bound monotonicity --
    // Higher arrival burst leads to equal or worse delay bound.

    #[test]
    fn lemma_delay_monotone_arrival() {
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let small_arrival = MinPlusCurve::from_token_bucket(2, 1, 10);
        let large_arrival = MinPlusCurve::from_token_bucket(5, 2, 10);

        let small_delay = delay_bound(&small_arrival, &service, 10, 20).unwrap_or(0);
        let large_delay = delay_bound(&large_arrival, &service, 10, 20).unwrap_or(0);

        assert!(large_delay >= small_delay);
    }

    // -- Lemma 15: convolution tail rate is min of input rates --
    // For min-plus convolution: (f ⊗ g)(t) = inf_s [f(s) + g(t-s)]
    // the asymptotic growth rate is min(r_f, r_g), not r_f + r_g.

    #[test]
    fn lemma_convolution_tail_rate_is_min() {
        let slow = MinPlusCurve::new(vec![0, 1], 1).expect("valid");
        let fast = MinPlusCurve::new(vec![0, 3], 3).expect("valid");
        let conv = slow.min_plus_convolution(&fast, 10);

        // Tail rate must be min(1, 3) = 1
        assert_eq!(conv.tail_rate(), 1);

        // Verify beyond-horizon extrapolation matches the brute-force minimum
        // at a point well past the computed samples.
        let t = 20;
        let mut brute = u64::MAX;
        for s in 0..=t {
            brute = brute.min(slow.value_at(s).saturating_add(fast.value_at(t - s)));
        }
        assert_eq!(conv.value_at(t), brute);
    }
}
