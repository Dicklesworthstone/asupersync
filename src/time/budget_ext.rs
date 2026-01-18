//! Budget extensions for time operations.

use crate::cx::Cx;
use crate::time::{sleep_until, Elapsed, Sleep};
use crate::types::{Budget, Time};
use std::future::Future;
use std::marker::Unpin;
use std::time::Duration;

/// Extension trait for Budget deadline operations.
pub trait BudgetTimeExt {
    /// Get remaining time until deadline.
    fn remaining_duration(&self, now: Time) -> Option<Duration>;

    /// Create sleep that respects budget deadline.
    fn deadline_sleep(&self) -> Option<Sleep>;

    /// Check if deadline has passed.
    fn deadline_elapsed(&self, now: Time) -> bool;
}

impl BudgetTimeExt for Budget {
    fn remaining_duration(&self, now: Time) -> Option<Duration> {
        self.deadline.map(|d| {
            if now >= d {
                Duration::ZERO
            } else {
                Duration::from_nanos(d.as_nanos() - now.as_nanos())
            }
        })
    }

    fn deadline_sleep(&self) -> Option<Sleep> {
        self.deadline.map(sleep_until)
    }

    fn deadline_elapsed(&self, now: Time) -> bool {
        self.deadline.map(|d| d <= now).unwrap_or(false)
    }
}

/// Sleep that integrates with the provided context's budget.
///
/// This sleeps for the shorter of the requested duration or the remaining budget.
/// If the budget runs out, it returns `Err(Elapsed)`.
pub async fn budget_sleep(cx: &Cx, duration: Duration, now: Time) -> Result<(), Elapsed> {
    let budget = cx.budget();

    // Use shorter of requested duration or remaining budget
    // Use BudgetTimeExt::remaining_duration explicit call
    let remaining = BudgetTimeExt::remaining_duration(&budget, now);

    let effective_duration = match remaining {
        Some(rem) if rem < duration => rem,
        _ => duration,
    };

    if effective_duration.is_zero() && BudgetTimeExt::deadline_elapsed(&budget, now) {
        let deadline = budget.deadline.unwrap_or(now);
        return Err(Elapsed::new(deadline));
    }

    crate::time::sleep(now, effective_duration).await;

    // Check if we were cut short by budget
    if let Some(rem) = BudgetTimeExt::remaining_duration(&budget, now) {
        if rem < duration {
            // We slept for 'remaining', which means deadline is hit.
            let deadline = budget.deadline.unwrap_or(now);
            return Err(Elapsed::new(deadline));
        }
    }

    Ok(())
}

/// Timeout that respects budget deadline.
pub async fn budget_timeout<F: Future + Unpin>(
    cx: &Cx,
    duration: Duration,
    future: F,
    now: Time,
) -> Result<F::Output, Elapsed> {
    let budget = cx.budget();

    // Use shorter of requested timeout or remaining budget
    let remaining = BudgetTimeExt::remaining_duration(&budget, now);
    let effective_timeout = match remaining {
        Some(rem) if rem < duration => rem,
        _ => duration,
    };

    crate::time::timeout(now, effective_timeout, future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use std::time::Duration;

    fn test_cx(budget: Budget) -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            budget,
        )
    }

    #[test]
    fn test_budget_sleep() {
        let now = Time::from_secs(100);
        let deadline = now.saturating_add_nanos(100_000_000); // 100ms
        let budget = Budget::new().with_deadline(deadline);
        let cx = test_cx(budget);

        // Request longer sleep than budget allows
        futures_lite::future::block_on(async {
            let result = budget_sleep(&cx, Duration::from_secs(10), now).await;
            assert!(result.is_err()); // Should be cut short
        });
    }

    #[test]
    fn test_budget_timeout() {
        let now = Time::from_secs(100);
        let deadline = now.saturating_add_nanos(50_000_000); // 50ms
        let budget = Budget::new().with_deadline(deadline);
        let cx = test_cx(budget);

        futures_lite::future::block_on(async {
            // Box::pin needed because async block is !Unpin and budget_timeout requires Unpin
            let future = Box::pin(async {
                crate::time::sleep(now, Duration::from_secs(1)).await;
            });
            let result = budget_timeout(&cx, Duration::from_secs(10), future, now).await;
            assert!(result.is_err());
        });
    }
}
