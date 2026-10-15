//! Regression coverage for rate limiter cancellation accounting.

use asupersync::combinator::rate_limit::{
    RateLimitError, RateLimitPolicy, RateLimiter, WaitStrategy,
};
use asupersync::types::Time;
use std::time::Duration;

#[test]
fn cancelled_head_waiter_does_not_block_tail_grant() {
    let rl = RateLimiter::new(RateLimitPolicy {
        rate: 1,
        period: Duration::from_secs(10),
        burst: 1,
        wait_strategy: WaitStrategy::Block,
        ..Default::default()
    });

    let now = Time::from_millis(0);
    assert!(rl.try_acquire(1, now));

    let cancelled_id = rl.enqueue(1, now).expect("head waiter should enqueue");
    let live_id = rl.enqueue(1, now).expect("tail waiter should enqueue");
    assert_ne!(cancelled_id, live_id);

    rl.cancel_entry(cancelled_id, now);
    assert!(
        matches!(
            rl.check_entry(cancelled_id, now),
            Err(RateLimitError::Cancelled)
        ),
        "cancelled head waiter must be removed from the queue"
    );

    let later = Time::from_millis(10_000);
    assert_eq!(
        rl.process_queue(later),
        Some(live_id),
        "cancelled head waiter must not block the next live waiter"
    );
    assert!(
        matches!(rl.check_entry(live_id, later), Ok(true)),
        "tail waiter should observe the grant exactly once"
    );
    assert_eq!(
        rl.process_queue(later),
        None,
        "claimed tail waiter must not be granted twice"
    );
    assert!(
        !rl.try_acquire(1, later),
        "tail grant must consume the refilled token before new fast-path callers"
    );
}
