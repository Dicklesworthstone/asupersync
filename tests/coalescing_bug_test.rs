#![allow(clippy::all)]
#![allow(missing_docs)]
use asupersync::time::{CoalescingConfig, TimerWheel, TimerWheelConfig};
use asupersync::types::Time;
use std::time::Duration;

#[test]
fn test_coalescing_group_size_bug() {
    let waker = std::task::Waker::noop().clone();

    // Coalescing window: 10ms
    let config = CoalescingConfig::enabled_with_window(Duration::from_millis(10));
    let mut wheel =
        TimerWheel::with_config(Time::from_nanos(0), TimerWheelConfig::default(), config);

    // Register timer at 2ms (within window 0..10ms)
    // This timer goes into the wheel levels (level 0).
    wheel.register(Time::from_nanos(2 * 1_000_000), waker);

    // Current time: 1ms.
    // The coalescing boundary for 1ms is 10ms.
    // 2ms is <= 10ms, so it SHOULD be in the coalescing group!
    // But it's in the wheel, not in `ready`.
    let group_size = wheel.coalescing_group_size(Time::from_nanos(1_000_000));
    assert_eq!(
        group_size, 1,
        "Expected coalescing_group_size to find the timer in the wheel"
    );
}
