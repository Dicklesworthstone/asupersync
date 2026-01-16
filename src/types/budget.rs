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
    fn consume_poll() {
        let mut budget = Budget::new().with_poll_quota(2);

        assert_eq!(budget.consume_poll(), Some(2));
        assert_eq!(budget.consume_poll(), Some(1));
        assert_eq!(budget.consume_poll(), None);
        assert!(budget.is_exhausted());
    }
}
