//! Scheduler performance regression tests.
//!
//! These tests establish baseline performance metrics and fail if
//! performance degrades beyond acceptable thresholds. Run with:
//!
//!   cargo test --test scheduler_regression --release -- --nocapture
//!
//! Note: these tests require --release for meaningful numbers.

use std::time::Instant;

use asupersync::runtime::scheduler::{GlobalQueue, LocalQueue, Parker, Scheduler};
use asupersync::types::{TaskId, Time};

fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Throughput regression: schedule+pop 10K tasks must complete in < 50ms.
/// This is a generous threshold to avoid flaky failures on slow CI.
#[test]
fn regression_throughput_10k_schedule_pop() {
    let mut scheduler = Scheduler::new();
    let start = Instant::now();

    for i in 0..10_000u32 {
        scheduler.schedule(task(i), (i % 256) as u8);
    }
    let mut popped = 0u32;
    while scheduler.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 10_000);
    assert!(
        elapsed.as_millis() < 50,
        "throughput regression: 10K schedule+pop took {}ms (threshold: 50ms)",
        elapsed.as_millis()
    );
}

/// Local queue regression: push+pop 100K items in < 100ms.
#[test]
fn regression_local_queue_100k() {
    let queue = LocalQueue::new_for_test(99_999);
    let start = Instant::now();

    for i in 0..100_000u32 {
        queue.push(task(i));
    }
    let mut popped = 0u32;
    while queue.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 100_000);
    assert!(
        elapsed.as_millis() < 100,
        "local queue regression: 100K push+pop took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}

/// Global queue regression: push+pop 100K items in < 200ms.
#[test]
fn regression_global_queue_100k() {
    let queue = GlobalQueue::new();
    let start = Instant::now();

    for i in 0..100_000u32 {
        queue.push(task(i));
    }
    let mut popped = 0u32;
    while queue.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 100_000);
    assert!(
        elapsed.as_millis() < 200,
        "global queue regression: 100K push+pop took {}ms (threshold: 200ms)",
        elapsed.as_millis()
    );
}

/// Parker regression: 1000 unpark+park cycles in < 100ms.
#[test]
fn regression_parker_cycle_1k() {
    let parker = Parker::new();
    let start = Instant::now();

    for _ in 0..1_000 {
        parker.unpark();
        parker.park();
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 100,
        "parker regression: 1K cycles took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}

/// Mixed-lane throughput: schedule 10K tasks across all 3 lanes + pop.
#[test]
fn regression_mixed_lane_10k() {
    let mut scheduler = Scheduler::new();
    let start = Instant::now();

    for i in 0..10_000u32 {
        match i % 3 {
            0 => scheduler.schedule(task(i), 0),
            1 => scheduler.schedule_timed(task(i), Time::from_nanos(u64::from(i) * 1000)),
            _ => scheduler.schedule_cancel(task(i), 0),
        }
    }
    let mut popped = 0u32;
    while scheduler.pop().is_some() {
        popped += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(popped, 10_000);
    assert!(
        elapsed.as_millis() < 100,
        "mixed-lane regression: 10K tasks took {}ms (threshold: 100ms)",
        elapsed.as_millis()
    );
}
