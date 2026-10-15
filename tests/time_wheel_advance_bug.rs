#![allow(unsafe_code)]
//! Regression test for timer-wheel cursor advancement after `advance_to`.

use asupersync::time::intrusive_wheel::{TimerNode, TimerWheel};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::{Duration, Instant};

struct CounterWaker(Arc<AtomicU64>);
impl std::task::Wake for CounterWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn counter_waker(counter: Arc<AtomicU64>) -> Waker {
    Arc::new(CounterWaker(counter)).into()
}

#[test]
fn tick_after_advance_to_fires_timer_at_deadline_only() {
    let base = Instant::now();
    let mut wheel: TimerWheel<4> = TimerWheel::new_at(Duration::from_millis(1), base);

    let counter = Arc::new(AtomicU64::new(0));

    let advanced = unsafe { wheel.advance_to(base + Duration::from_millis(2)) };
    assert!(
        advanced.is_empty(),
        "empty wheel should produce no wakers during initial advance"
    );

    let mut node = Box::pin(TimerNode::new());
    let deadline = base + Duration::from_millis(6);
    unsafe {
        wheel.insert(node.as_mut(), deadline, counter_waker(Arc::clone(&counter)));
    }
    assert_eq!(wheel.len(), 1, "timer should be scheduled");

    for tick_ms in 3..6 {
        let early = unsafe { wheel.tick(base + Duration::from_millis(tick_ms)) };
        assert!(
            early.is_empty(),
            "timer for 6ms should not fire at {tick_ms}ms"
        );
    }

    let wakers = unsafe { wheel.tick(base + Duration::from_millis(6)) };
    assert_eq!(wakers.len(), 1, "timer for 6ms should fire at 6ms");

    for w in wakers {
        w.wake();
    }

    assert!(wheel.is_empty(), "timer should be removed after firing");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "timer waker should fire exactly once"
    );
}
