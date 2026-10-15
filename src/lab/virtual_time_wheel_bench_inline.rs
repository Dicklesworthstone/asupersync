//! Inline performance test for virtual_time_wheel bottlenecks
//! Run with: cargo test virtual_time_wheel_bench_inline --release -- --ignored

use std::time::Instant;
use crate::lab::virtual_time_wheel::VirtualTimerWheel;

fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

#[test]
#[ignore]
fn manual_cancel_storm_profile() {
    let timer_count = 10_000;
    let mut wheel = VirtualTimerWheel::new();
    let waker = noop_waker();

    // Setup: Insert timers spread across time range
    let mut handles = Vec::with_capacity(timer_count);
    for i in 0..timer_count {
        let deadline = (i % 1000) as u64 + 1;
        let handle = wheel.insert(deadline, waker.clone());
        handles.push(handle);
    }

    // Cancel storm: 90% of timers
    let cancel_count = (timer_count * 9) / 10;
    let cancel_start = Instant::now();
    for handle in handles.into_iter().take(cancel_count) {
        wheel.cancel(handle);
    }
    let cancel_duration = cancel_start.elapsed();

    // Bottleneck test: advance_to() which triggers cleanup_cancelled()
    let advance_start = Instant::now();
    let expired = wheel.advance_to(1000);
    let advance_duration = advance_start.elapsed();

    // Verify expected behavior
    assert_eq!(expired.len(), timer_count - cancel_count);

    // Performance expectation: advance should be much slower than cancel due to O(n log n) cleanup
    let ratio = advance_duration.as_nanos() as f64 / cancel_duration.as_nanos() as f64;

    // Performance characteristics documented for manual profiling
    #[cfg(debug_assertions)]
    {
        eprintln!("Performance profile - Advance/Cancel ratio: {:.2}x", ratio);
        if ratio > 10.0 {
            eprintln!("✓ Confirms advance_to() bottleneck under cancel storm");
        } else {
            eprintln!("? Unexpected timing ratio - investigate further");
        }
    }
}

#[test]
#[ignore]
fn manual_next_deadline_profile() {
    let timer_count = 5_000;
    let mut wheel = VirtualTimerWheel::new();
    let waker = noop_waker();

    // Insert timers at sequential deadlines
    let mut handles = Vec::with_capacity(timer_count);
    for i in 0..timer_count {
        let handle = wheel.insert(i as u64 + 1, waker.clone());
        handles.push(handle);
    }

    // Cancel the first 90% (earliest deadlines)
    let cancel_count = (timer_count * 9) / 10;
    for handle in handles.into_iter().take(cancel_count) {
        wheel.cancel(handle);
    }

    // Test next_deadline() hot loop - should scan through 90% cancelled timers
    let start = Instant::now();
    let deadline = wheel.next_deadline();
    let duration = start.elapsed();

    // Verify deadline correctness: should be around the 90th percentile
    if let Some(d) = deadline {
        let expected_deadline = cancel_count as u64 + 1;
        assert!(d >= expected_deadline, "next_deadline() should find first non-cancelled timer");
    }

    // Performance characteristics documented for manual profiling
    #[cfg(debug_assertions)]
    {
        eprintln!("next_deadline() profile - Duration: {:?}, Found: {:?}", duration, deadline);
        if duration.as_micros() > 100 {
            eprintln!("✓ Confirms next_deadline() scanning bottleneck");
        } else {
            eprintln!("? Faster than expected - may need larger test case");
        }
    }
}