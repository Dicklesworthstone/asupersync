//! Regression test for `Budget::remaining_time` returning a duration.

use asupersync::types::{Budget, Time};
use std::time::Duration;

#[test]
fn budget_remaining_time_returns_duration_until_deadline() {
    let budget = Budget::with_deadline_secs(100);
    let now = Time::from_secs(90);

    assert_eq!(budget.remaining_time(now), Some(Duration::from_secs(10)));
}
