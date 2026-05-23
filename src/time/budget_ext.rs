//! Budget extensions for time operations.

use crate::cx::Cx;
use crate::time::{Elapsed, Sleep, sleep_until};
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
    #[inline]
    fn remaining_duration(&self, now: Time) -> Option<Duration> {
        self.deadline.map(|d| {
            if now >= d {
                Duration::ZERO
            } else {
                let diff_nanos = d.as_nanos().saturating_sub(now.as_nanos());
                Duration::from_nanos(diff_nanos)
            }
        })
    }

    #[inline]
    fn deadline_sleep(&self) -> Option<Sleep> {
        self.deadline.map(sleep_until)
    }

    #[inline]
    fn deadline_elapsed(&self, now: Time) -> bool {
        self.deadline.is_some_and(|d| d <= now)
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
    if effective_duration < duration {
        // We slept for 'remaining', which means deadline is hit.
        let deadline = budget.deadline.unwrap_or(now);
        return Err(Elapsed::new(deadline));
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use proptest::prelude::*;
    use std::future::{pending, ready};
    use std::time::Duration;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    fn test_cx(budget: Budget) -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            budget,
        )
    }

    #[test]
    fn budget_time_ext_deadline_boundaries() {
        init_test("budget_time_ext_deadline_boundaries");

        let unconstrained = Budget::new();
        assert_eq!(
            BudgetTimeExt::remaining_duration(&unconstrained, Time::from_secs(5)),
            None
        );
        assert!(!BudgetTimeExt::deadline_elapsed(
            &unconstrained,
            Time::from_secs(5)
        ));
        assert!(BudgetTimeExt::deadline_sleep(&unconstrained).is_none());

        let deadline = Time::from_secs(10);
        let budget = Budget::new().with_deadline(deadline);

        assert_eq!(
            BudgetTimeExt::remaining_duration(&budget, Time::from_secs(4)),
            Some(Duration::from_secs(6))
        );
        assert!(!BudgetTimeExt::deadline_elapsed(
            &budget,
            Time::from_secs(4)
        ));
        assert!(BudgetTimeExt::deadline_sleep(&budget).is_some());

        assert_eq!(
            BudgetTimeExt::remaining_duration(&budget, deadline),
            Some(Duration::ZERO)
        );
        assert!(BudgetTimeExt::deadline_elapsed(&budget, deadline));

        assert_eq!(
            BudgetTimeExt::remaining_duration(&budget, Time::from_secs(12)),
            Some(Duration::ZERO)
        );
        assert!(BudgetTimeExt::deadline_elapsed(
            &budget,
            Time::from_secs(12)
        ));
        crate::test_complete!("budget_time_ext_deadline_boundaries");
    }

    proptest! {
        #[test]
        fn budget_remaining_duration_metamorphic_monotonic_as_now_advances(
            deadline_nanos in 0u64..1_000_000_000_000,
            first_now_nanos in 0u64..1_000_000_000_000,
            second_now_nanos in 0u64..1_000_000_000_000,
        ) {
            let budget = Budget::new().with_deadline(Time::from_nanos(deadline_nanos));
            let earlier_now_nanos = first_now_nanos.min(second_now_nanos);
            let later_now_nanos = first_now_nanos.max(second_now_nanos);

            let earlier_remaining = BudgetTimeExt::remaining_duration(
                &budget,
                Time::from_nanos(earlier_now_nanos),
            )
            .expect("budget has a deadline");
            let later_remaining = BudgetTimeExt::remaining_duration(
                &budget,
                Time::from_nanos(later_now_nanos),
            )
            .expect("budget has a deadline");
            let elapsed_between_reads =
                Duration::from_nanos(later_now_nanos - earlier_now_nanos);

            prop_assert!(
                later_remaining <= earlier_remaining,
                "remaining duration must not increase as now advances",
            );
            prop_assert_eq!(
                later_remaining,
                earlier_remaining.saturating_sub(elapsed_between_reads),
                "advancing now must reduce remaining duration by the elapsed interval, floored at zero",
            );
            prop_assert_eq!(
                BudgetTimeExt::deadline_elapsed(&budget, Time::from_nanos(later_now_nanos)),
                later_now_nanos >= deadline_nanos,
                "deadline_elapsed must agree with remaining_duration's zero boundary",
            );
        }
    }

    #[test]
    fn budget_timeout_respects_exhausted_deadline_boundary() {
        init_test("budget_timeout_respects_exhausted_deadline_boundary");
        let cx = test_cx(Budget::new().with_deadline(Time::ZERO));

        futures_lite::future::block_on(async {
            let elapsed = budget_timeout(&cx, Duration::from_secs(10), pending::<()>(), Time::ZERO)
                .await
                .expect_err("pending work must time out at an exhausted budget deadline");
            assert_eq!(elapsed.deadline(), Time::ZERO);

            let completed = budget_timeout(
                &cx,
                Duration::from_secs(10),
                ready("already-complete"),
                Time::ZERO,
            )
            .await
            .expect("ready work wins the timeout boundary");
            assert_eq!(completed, "already-complete");
        });
        crate::test_complete!("budget_timeout_respects_exhausted_deadline_boundary");
    }

    #[test]
    fn test_budget_sleep() {
        init_test("test_budget_sleep");
        // `Sleep`'s fallback time source starts at `Time::ZERO` on first poll.
        // Use a small deadline in the same time basis so this test remains fast.
        let now = Time::ZERO;
        let deadline = now.saturating_add_nanos(5_000_000); // 5ms
        let budget = Budget::new().with_deadline(deadline);
        let cx = test_cx(budget);

        // Request longer sleep than budget allows
        futures_lite::future::block_on(async {
            let result = budget_sleep(&cx, Duration::from_secs(10), now).await;
            let is_err = result.is_err();
            crate::assert_with_log!(is_err, "budget sleep errors", true, is_err);
        });
        crate::test_complete!("test_budget_sleep");
    }
}
