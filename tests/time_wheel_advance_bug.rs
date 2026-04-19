#![allow(unsafe_code)]
#![allow(missing_docs)]
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
fn test_advance_tick_sync() {
    let base = Instant::now();
    let mut wheel: TimerWheel<4> = TimerWheel::new_at(Duration::from_millis(1), base);

    let counter = Arc::new(AtomicU64::new(0));

    // Advance to 2ms
    let now = base + Duration::from_millis(2);
    let _ = unsafe { wheel.advance_to(now) };

    // Insert timer for 6ms
    let mut node = Box::pin(TimerNode::new());
    let deadline = base + Duration::from_millis(6);
    unsafe {
        wheel.insert(node.as_mut(), deadline, counter_waker(counter.clone()));
    }

    // Now call tick 4 times (for 3ms, 4ms, 5ms, 6ms)
    unsafe { wheel.tick(base + Duration::from_millis(3)) };
    unsafe { wheel.tick(base + Duration::from_millis(4)) };
    unsafe { wheel.tick(base + Duration::from_millis(5)) };
    let wakers = unsafe { wheel.tick(base + Duration::from_millis(6)) };

    for w in wakers {
        w.wake();
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "Timer for 6ms should fire at 6ms"
    );
}
