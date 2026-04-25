//! Test for timer wheel tick skipping bounds.

use asupersync::time::TimerWheel;
use asupersync::types::Time;
use std::task::Waker;

#[test]
fn skipped_ticks_do_not_fire_timers_early_or_drop_them() {
    let mut wheel = TimerWheel::new();
    let waker = Waker::noop().clone();

    for i in 1_u64..=100 {
        wheel.register(Time::from_millis(i * 10), waker.clone());
    }

    assert_eq!(wheel.len(), 100);

    let mut expired_total = 0;
    for i in 1_u64..=100 {
        let before_deadline = Time::from_millis(i * 10 - 1);
        assert!(
            wheel.collect_expired(before_deadline).is_empty(),
            "timer fired before its deadline at {before_deadline:?}"
        );

        let at_deadline = Time::from_millis(i * 10);
        let expired = wheel.collect_expired(at_deadline);
        assert_eq!(
            expired.len(),
            1,
            "expected exactly one timer at {at_deadline:?}"
        );
        expired_total += expired.len();
    }

    assert_eq!(expired_total, 100);
    assert!(
        wheel.is_empty(),
        "all registered timers should be removed after expiring"
    );
}
