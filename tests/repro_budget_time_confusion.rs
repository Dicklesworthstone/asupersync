use asupersync::types::{Budget, Time};
use std::time::Duration;

#[test]
fn repro_budget_remaining_time_returns_timestamp() {
    let budget = Budget::with_deadline_secs(100);
    let now = Time::from_secs(90);
    
    // We expect 10 seconds remaining.
    let remaining = budget.remaining_time(now).expect("should have remaining time");
    
    // Now it returns a Duration, so we can check it directly.
    assert_eq!(remaining, Duration::from_secs(10));
}
