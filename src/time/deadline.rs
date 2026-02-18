//! Deadline propagation utilities.

use crate::cx::Scope;
use crate::types::{Policy, Time};
use std::time::Duration;

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Updates a scope with a new deadline.
///
/// If the scope already has a tighter deadline, it is preserved.
#[must_use]
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
    use super::*;
    use crate::types::Budget;
    use crate::types::policy::FailFast;
    use crate::util::ArenaIndex;

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
