//! Reference implementation for timeout and deadline conformance testing.
//!
//! This module provides mathematically pure reference implementations
//! of timeout and deadline behavior for differential testing.

use std::time::Duration;

/// Reference time type for conformance testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefTime(u64);

impl RefTime {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn saturating_add_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    pub const fn saturating_sub_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_sub(nanos))
    }
}

/// Reference timeout implementation for conformance testing.
#[derive(Debug, Clone, Copy)]
pub struct RefTimeout {
    pub deadline: RefTime,
}

impl RefTimeout {
    pub const fn new(deadline: RefTime) -> Self {
        Self { deadline }
    }

    pub const fn after_nanos(now: RefTime, nanos: u64) -> Self {
        Self::new(now.saturating_add_nanos(nanos))
    }

    pub const fn after_secs(now: RefTime, secs: u64) -> Self {
        Self::after_nanos(now, secs.saturating_mul(1_000_000_000))
    }

    pub fn after(now: RefTime, duration: Duration) -> Self {
        let nanos = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        Self::after_nanos(now, nanos)
    }

    pub const fn is_expired(self, now: RefTime) -> bool {
        now >= self.deadline
    }

    pub fn remaining(self, now: RefTime) -> Duration {
        if now >= self.deadline {
            Duration::ZERO
        } else {
            let nanos = self.deadline.as_nanos().saturating_sub(now.as_nanos());
            Duration::from_nanos(nanos)
        }
    }
}

/// Reference deadline computation following the algebraic law:
/// timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
pub const fn ref_effective_deadline(requested: RefTime, existing: Option<RefTime>) -> RefTime {
    match existing {
        Some(e) if e.as_nanos() < requested.as_nanos() => e,
        _ => requested,
    }
}

/// Reference budget for deadline testing.
#[derive(Debug, Clone, PartialEq)]
pub struct RefBudget {
    pub deadline: Option<RefTime>,
    pub poll_quota: u32,
    pub cost_quota: Option<u32>,
    pub priority: u32,
}

impl RefBudget {
    pub const INFINITE: Self = Self {
        deadline: None,
        poll_quota: u32::MAX,
        cost_quota: None,
        priority: 0,
    };

    pub const fn new() -> Self {
        Self {
            deadline: None,
            poll_quota: 64,
            cost_quota: None,
            priority: 0,
        }
    }

    pub const fn with_deadline(mut self, deadline: RefTime) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub const fn with_poll_quota(mut self, quota: u32) -> Self {
        self.poll_quota = quota;
        self
    }

    pub const fn with_cost_quota(mut self, quota: u32) -> Self {
        self.cost_quota = Some(quota);
        self
    }

    pub const fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Reference deadline propagation following min() semantics.
pub fn ref_with_deadline(budget: RefBudget, deadline: RefTime) -> RefBudget {
    let new_deadline = budget.deadline.map_or(deadline, |existing| {
        RefTime::from_nanos(existing.as_nanos().min(deadline.as_nanos()))
    });

    RefBudget {
        deadline: Some(new_deadline),
        poll_quota: budget.poll_quota,
        cost_quota: budget.cost_quota,
        priority: budget.priority,
    }
}

/// Reference timeout computation from duration.
pub fn ref_with_timeout(budget: RefBudget, duration: Duration, now: RefTime) -> RefBudget {
    let nanos = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
    let deadline = now.saturating_add_nanos(nanos);
    ref_with_deadline(budget, deadline)
}

/// Reference timeout composition law verification.
pub fn ref_timeout_composition_law(
    d1: Duration,
    d2: Duration,
    now: RefTime
) -> (RefTime, RefTime) {
    // timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)

    // Left side: nested timeouts
    let inner_deadline = RefTimeout::after(now, d2).deadline;
    let outer_deadline = RefTimeout::after(now, d1).deadline;
    let effective_nested = ref_effective_deadline(outer_deadline, Some(inner_deadline));

    // Right side: single timeout with min duration
    let min_duration = Duration::from_nanos(d1.as_nanos().min(d2.as_nanos()) as u64);
    let min_deadline = RefTimeout::after(now, min_duration).deadline;

    (effective_nested, min_deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_timeout_creation() {
        let now = RefTime::ZERO;
        let timeout = RefTimeout::after_secs(now, 5);
        assert_eq!(timeout.deadline.as_nanos(), 5_000_000_000);
    }

    #[test]
    fn ref_effective_deadline_chooses_tighter() {
        let earlier = RefTime::from_secs(5);
        let later = RefTime::from_secs(10);

        assert_eq!(ref_effective_deadline(later, Some(earlier)), earlier);
        assert_eq!(ref_effective_deadline(earlier, Some(later)), earlier);
        assert_eq!(ref_effective_deadline(later, None), later);
    }

    #[test]
    fn ref_timeout_composition_law_holds() {
        let now = RefTime::from_secs(100);
        let d1 = Duration::from_secs(5);
        let d2 = Duration::from_secs(3);

        let (nested, min_timeout) = ref_timeout_composition_law(d1, d2, now);
        assert_eq!(nested, min_timeout);

        // Should equal now + min(d1, d2) = 100 + 3 = 103
        assert_eq!(min_timeout.as_nanos(), 103_000_000_000);
    }

    #[test]
    fn ref_budget_deadline_preserves_other_fields() {
        let budget = RefBudget::new()
            .with_deadline(RefTime::from_secs(10))
            .with_poll_quota(42)
            .with_cost_quota(7)
            .with_priority(99);

        let new_budget = ref_with_deadline(budget.clone(), RefTime::from_secs(5));

        assert_eq!(new_budget.deadline, Some(RefTime::from_secs(5)));
        assert_eq!(new_budget.poll_quota, 42);
        assert_eq!(new_budget.cost_quota, Some(7));
        assert_eq!(new_budget.priority, 99);
    }
}