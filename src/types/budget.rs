//! Budget type with product semiring semantics.
//!
//! Budgets constrain the resources available to a task or region:
//!
//! - **Deadline**: Absolute time by which work must complete
//! - **Poll quota**: Maximum number of poll calls
//! - **Cost quota**: Abstract cost units (for priority scheduling)
//! - **Priority**: Scheduling priority (higher = more urgent)
//!
//! Budgets combine using product semantics:
//! - Deadlines: take minimum (earlier deadline wins)
//! - Quotas: take minimum (tighter constraint wins)
//! - Priority: take maximum (higher priority wins)

use super::id::Time;
use core::fmt;

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

    /// Creates a new budget with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self::INFINITE
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
            Some(old)
        } else {
            None
        }
    }

    /// Combines two budgets using product semantics.
    ///
    /// - Deadlines: min (earlier wins)
    /// - Quotas: min (tighter wins)
    /// - Priority: max (higher wins)
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        Self {
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
        }
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
}
