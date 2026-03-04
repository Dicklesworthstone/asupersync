#![allow(missing_docs)]
use asupersync::time::TimerWheel;
use asupersync::types::Time;
use std::sync::Arc;
use std::task::Waker;

#[test]
fn test_cascade_bug() {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWaker));

    let mut wheel = TimerWheel::new_at(Time::from_nanos(0));

    // Insert a timer at exactly 256ms (tick 256).
    // Level 0 range is 256. At tick 0, level 0 holds ticks 0..255.
    // So tick 256 goes to Level 1.
    wheel.register(Time::from_nanos(256 * 1_000_000), waker);

    // Advance to tick 256
    let expired = wheel.collect_expired(Time::from_nanos(256 * 1_000_000));
    assert_eq!(
        expired.len(),
        1,
        "Timer should fire at 256ms, but it didn't!"
    );
}
