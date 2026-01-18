//! Deadline propagation utilities.

use crate::cx::Scope;
use crate::types::Time;
use std::time::Duration;

/// Updates a scope with a new deadline.
///
/// If the scope already has a tighter deadline, it is preserved.
#[must_use]
pub fn with_deadline<'a>(scope: &Scope<'a>, deadline: Time) -> Scope<'a> {
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
pub fn with_timeout<'a>(scope: &Scope<'a>, duration: Duration, now: Time) -> Scope<'a> {
    let deadline = now.saturating_add_nanos(duration.as_nanos() as u64);
    with_deadline(scope, deadline)
}
