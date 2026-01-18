//! Deadline propagation utilities.

use crate::cx::Scope;
use crate::time::budget_ext::BudgetTimeExt;
use crate::types::{Budget, Time};
use std::time::Duration;

/// Updates a scope with a new deadline.
///
/// If the scope already has a tighter deadline, it is preserved.
pub fn with_deadline(scope: Scope<'_>, deadline: Time) -> Scope<'_> {
    let current_budget = scope.budget();
    // Budget::with_deadline replaces it. We want min.
    let new_deadline = match current_budget.deadline {
        Some(existing) => existing.min(deadline),
        None => deadline,
    };
    let new_budget = current_budget.with_deadline(new_deadline);

    // Create new scope with updated budget
    Scope::new(scope.region_id(), new_budget)
}

/// Updates a scope with a timeout relative to a start time.
pub fn with_timeout(scope: Scope<'_>, duration: Duration, now: Time) -> Scope<'_> {
    let deadline = now.saturating_add_nanos(duration.as_nanos() as u64);
    with_deadline(scope, deadline)
}
