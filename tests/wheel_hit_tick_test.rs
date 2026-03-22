//! Test for timer wheel tick skipping bounds.

use asupersync::time::TimerWheel;
use asupersync::types::Time;
use std::sync::Arc;
use std::task::{Wake, Waker};

struct NoopWaker;
impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

#[test]
fn hit_tick_is_never_less_or_equal() {
    let mut wheel = TimerWheel::new();
    let waker = Waker::from(Arc::new(NoopWaker));
    // insert a bunch of random timers
    for i in 1..1000 {
        wheel.register(Time::from_millis(i * 10), waker.clone());
    }

    // collect them in small jumps to test next_skip_tick
    for i in 1..2000 {
        wheel.collect_expired(Time::from_millis(i * 5));
    }
}
