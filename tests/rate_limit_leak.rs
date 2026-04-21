#![allow(clippy::all)]
//! Regression coverage for rate limiter cancellation accounting.

use asupersync::combinator::rate_limit::*;
use asupersync::types::Time;
use std::time::Duration;

#[test]
fn rate_limit_cancel_leak() {
    let rl = RateLimiter::new(RateLimitPolicy {
        rate: 1,
        period: Duration::from_secs(10),
        burst: 1,
        wait_strategy: WaitStrategy::Block,
        ..Default::default()
    });

    let now = Time::from_millis(0);
    // Exhaust token
    assert!(rl.try_acquire(1, now));

    // Enqueue a waiter
    let id = rl.enqueue(1, now).unwrap();

    // Enqueue a second waiter that should be granted after cancellation.
    let id2 = rl.enqueue(1, now).unwrap();

    // Cancel the first entry.
    rl.cancel_entry(id, now);

    // If cancelled entries leak in the wait queue, id would still be granted first.
    let later = Time::from_millis(10_000);
    let granted = rl.process_queue(later);
    assert_eq!(granted, Some(id2));
}
