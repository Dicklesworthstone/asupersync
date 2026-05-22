//! Deadline propagation utilities.

use crate::cx::Scope;
use crate::types::{Policy, Time};
use std::time::Duration;

#[inline]
fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Updates a scope with a new deadline.
///
/// If the scope already has a tighter deadline, it is preserved.
#[must_use]
#[inline]
pub fn with_deadline<'a, P: Policy>(scope: &Scope<'a, P>, deadline: Time) -> Scope<'a, P> {
    let current_budget = scope.budget();
    // Budget::with_deadline replaces it. We want min.
    let new_deadline = current_budget
        .deadline
        .map_or(deadline, |existing| existing.min(deadline));
    let new_budget = current_budget.with_deadline(new_deadline);

    // Create new scope with updated budget
    Scope::new(scope.region_id(), new_budget)
}

/// Updates a scope with a timeout relative to a start time.
#[must_use]
#[inline]
pub fn with_timeout<'a, P: Policy>(
    scope: &Scope<'a, P>,
    duration: Duration,
    now: Time,
) -> Scope<'a, P> {
    let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
    with_deadline(scope, deadline)
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
    use crate::types::Budget;
    use crate::types::policy::FailFast;
    use crate::util::ArenaIndex;
    use proptest::prelude::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_region() -> crate::types::RegionId {
        crate::types::RegionId::from_arena(ArenaIndex::new(0, 0))
    }

    #[test]
    fn with_deadline_sets_deadline_on_scope_without_one() {
        init_test("with_deadline_sets_deadline_on_scope_without_one");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        // Budget::INFINITE has no deadline
        crate::assert_with_log!(
            scope.budget().deadline.is_none(),
            "no initial deadline",
            true,
            scope.budget().deadline.is_none()
        );

        let deadline = Time::from_secs(10);
        let new_scope = with_deadline(&scope, deadline);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(deadline),
            "deadline set",
            Some(deadline),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.region_id() == test_region(),
            "region preserved",
            test_region(),
            new_scope.region_id()
        );
        crate::test_complete!("with_deadline_sets_deadline_on_scope_without_one");
    }

    #[test]
    fn with_deadline_preserves_tighter_existing_deadline() {
        init_test("with_deadline_preserves_tighter_existing_deadline");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(5));
        let scope = Scope::<FailFast>::new(test_region(), budget);

        // Try to set a looser deadline (10s > 5s)
        let new_scope = with_deadline(&scope, Time::from_secs(10));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(5)),
            "tighter deadline preserved",
            Some(Time::from_secs(5)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_preserves_tighter_existing_deadline");
    }

    #[test]
    fn with_deadline_tightens_when_new_is_earlier() {
        init_test("with_deadline_tightens_when_new_is_earlier");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(10));
        let scope = Scope::<FailFast>::new(test_region(), budget);

        // Set a tighter deadline (3s < 10s)
        let new_scope = with_deadline(&scope, Time::from_secs(3));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(3)),
            "tighter deadline applied",
            Some(Time::from_secs(3)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_tightens_when_new_is_earlier");
    }

    #[test]
    fn with_timeout_computes_absolute_deadline() {
        init_test("with_timeout_computes_absolute_deadline");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(100);
        let duration = Duration::from_secs(5);

        let new_scope = with_timeout(&scope, duration, now);
        // Deadline should be now + duration = 105s
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(105)),
            "deadline = now + duration",
            Some(Time::from_secs(105)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_computes_absolute_deadline");
    }

    #[test]
    fn with_timeout_zero_duration_sets_deadline_to_now() {
        init_test("with_timeout_zero_duration_sets_deadline_to_now");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(42);

        let new_scope = with_timeout(&scope, Duration::ZERO, now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(now),
            "zero timeout deadline",
            Some(now),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.region_id() == test_region(),
            "region preserved",
            test_region(),
            new_scope.region_id()
        );
        crate::test_complete!("with_timeout_zero_duration_sets_deadline_to_now");
    }

    #[test]
    fn with_timeout_respects_existing_tighter_deadline() {
        init_test("with_timeout_respects_existing_tighter_deadline");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(102));
        let scope = Scope::<FailFast>::new(test_region(), budget);
        let now = Time::from_secs(100);
        let duration = Duration::from_secs(10); // Would be 110s

        let new_scope = with_timeout(&scope, duration, now);
        // Existing 102s deadline is tighter than 110s
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(102)),
            "existing tighter deadline preserved",
            Some(Time::from_secs(102)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_respects_existing_tighter_deadline");
    }

    #[test]
    fn with_timeout_saturates_at_time_max_for_huge_duration() {
        init_test("with_timeout_saturates_at_time_max_for_huge_duration");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(1);

        let new_scope = with_timeout(&scope, Duration::MAX, now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::MAX),
            "huge duration saturates to Time::MAX",
            Some(Time::MAX),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_saturates_at_time_max_for_huge_duration");
    }

    #[test]
    fn with_timeout_saturates_when_now_is_near_time_max() {
        init_test("with_timeout_saturates_when_now_is_near_time_max");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::MAX.saturating_sub_nanos(5);

        let new_scope = with_timeout(&scope, Duration::from_nanos(10), now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::MAX),
            "near-max now plus timeout saturates",
            Some(Time::MAX),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_saturates_when_now_is_near_time_max");
    }

    proptest! {
        #[test]
        fn with_timeout_metamorphic_composition_is_order_independent(
            now_nanos in 0u64..1_000_000_000,
            first_timeout_nanos in 0u64..1_000_000_000,
            second_timeout_nanos in 0u64..1_000_000_000,
        ) {
            let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
            let now = Time::from_nanos(now_nanos);
            let first_timeout = Duration::from_nanos(first_timeout_nanos);
            let second_timeout = Duration::from_nanos(second_timeout_nanos);

            let first_then_second =
                with_timeout(&with_timeout(&scope, first_timeout, now), second_timeout, now);
            let second_then_first =
                with_timeout(&with_timeout(&scope, second_timeout, now), first_timeout, now);
            let expected = now
                .saturating_add_nanos(first_timeout_nanos)
                .min(now.saturating_add_nanos(second_timeout_nanos));

            prop_assert_eq!(first_then_second.budget().deadline, Some(expected));
            prop_assert_eq!(second_then_first.budget().deadline, Some(expected));
            prop_assert_eq!(
                first_then_second.budget().deadline,
                second_then_first.budget().deadline,
                "timeout composition must keep the earliest deadline regardless of order",
            );
            prop_assert_eq!(first_then_second.region_id(), test_region());
            prop_assert_eq!(second_then_first.region_id(), test_region());
        }

        #[test]
        fn with_timeout_metamorphic_matches_explicit_saturating_deadline(
            now_nanos in any::<u64>(),
            timeout_nanos in any::<u64>(),
            existing_deadline_nanos in any::<u64>(),
        ) {
            let budget = Budget::INFINITE.with_deadline(Time::from_nanos(existing_deadline_nanos));
            let scope = Scope::<FailFast>::new(test_region(), budget);
            let now = Time::from_nanos(now_nanos);
            let timeout = Duration::from_nanos(timeout_nanos);
            let computed_deadline = now.saturating_add_nanos(timeout_nanos);

            let via_timeout = with_timeout(&scope, timeout, now);
            let via_explicit_deadline = with_deadline(&scope, computed_deadline);
            let expected = Time::from_nanos(existing_deadline_nanos).min(computed_deadline);

            prop_assert_eq!(
                via_timeout.budget().deadline,
                Some(expected),
                "with_timeout must keep the earlier of the existing and computed deadlines",
            );
            prop_assert_eq!(
                via_timeout.budget().deadline,
                via_explicit_deadline.budget().deadline,
                "with_timeout must match with_deadline using the computed absolute deadline",
            );
            prop_assert_eq!(via_timeout.region_id(), test_region());
            prop_assert_eq!(via_explicit_deadline.region_id(), test_region());
        }
    }

    #[test]
    fn with_deadline_preserves_non_deadline_budget_fields() {
        init_test("with_deadline_preserves_non_deadline_budget_fields");
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(7)
            .with_cost_quota(11)
            .with_priority(222);
        let scope = Scope::<FailFast>::new(test_region(), budget);

        let new_scope = with_deadline(&scope, Time::from_secs(3));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(3)),
            "deadline tightened",
            Some(Time::from_secs(3)),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.budget().poll_quota == 7,
            "poll quota preserved",
            7,
            new_scope.budget().poll_quota
        );
        crate::assert_with_log!(
            new_scope.budget().cost_quota == Some(11),
            "cost quota preserved",
            Some(11),
            new_scope.budget().cost_quota
        );
        crate::assert_with_log!(
            new_scope.budget().priority == 222,
            "priority preserved",
            222,
            new_scope.budget().priority
        );
        crate::test_complete!("with_deadline_preserves_non_deadline_budget_fields");
    }

    #[test]
    fn with_deadline_zero_deadline() {
        init_test("with_deadline_zero_deadline");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let new_scope = with_deadline(&scope, Time::ZERO);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::ZERO),
            "zero deadline set",
            Some(Time::ZERO),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_zero_deadline");
    }
}
