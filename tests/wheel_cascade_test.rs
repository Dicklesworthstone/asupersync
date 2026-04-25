//! Regression coverage for timer-wheel level cascade boundaries.

use asupersync::time::TimerWheel;
use asupersync::types::Time;
use std::task::Waker;

#[test]
fn level_one_cascade_preserves_exact_timer_deadlines() {
    let waker = Waker::noop().clone();
    let mut wheel = TimerWheel::new_at(Time::from_nanos(0));

    let cascade_boundary = Time::from_nanos(256 * 1_000_000);
    let after_boundary = Time::from_nanos(257 * 1_000_000);
    wheel.register(cascade_boundary, waker.clone());
    wheel.register(after_boundary, waker);

    assert_eq!(wheel.len(), 2);

    let before_boundary = Time::from_nanos(cascade_boundary.as_nanos() - 1);
    assert!(
        wheel.collect_expired(before_boundary).is_empty(),
        "level-1 timer must not fire before the cascade boundary"
    );

    let expired = wheel.collect_expired(cascade_boundary);
    assert_eq!(
        expired.len(),
        1,
        "only the boundary timer should fire when level 1 cascades"
    );
    assert_eq!(
        wheel.len(),
        1,
        "the post-boundary timer must remain scheduled after cascade"
    );

    assert!(
        wheel
            .collect_expired(Time::from_nanos(after_boundary.as_nanos() - 1))
            .is_empty(),
        "post-boundary timer must not fire early after being cascaded"
    );

    let expired = wheel.collect_expired(after_boundary);
    assert_eq!(
        expired.len(),
        1,
        "post-boundary timer should fire on its exact level-0 tick"
    );
    assert!(
        wheel.is_empty(),
        "all cascaded timers should be removed after expiring"
    );
}
