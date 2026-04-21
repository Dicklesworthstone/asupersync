#![allow(clippy::all)]
//! Regression test for long-horizon token refill precision in `RateLimiter`.

use asupersync::Time;
use asupersync::combinator::rate_limit::{
    RateLimitAlgorithm, RateLimitPolicy, RateLimiter, WaitStrategy,
};
use std::time::Duration;

#[test]
fn test_f64_precision_loss() {
    let policy = RateLimitPolicy {
        name: "test".into(),
        rate: 1,                           // 1 token
        period: Duration::from_secs(3600), // per hour
        burst: 1_000_000_000,
        default_cost: 1,
        wait_strategy: WaitStrategy::Reject,
        algorithm: RateLimitAlgorithm::TokenBucket,
    };
    let rl = RateLimiter::new(policy);

    // Drain some tokens so we have room to refill, but keep tokens high.
    assert!(rl.try_acquire(10_000, Time::from_nanos(0)));

    let mut now_ms: u64 = 0;

    // We expect to add 1 token every 3600 seconds.
    // Let's call refill every 1 ms for 3600 seconds.
    for _ in 0..3_600_000 {
        now_ms += 1;
        let _ = rl.try_acquire(0, Time::from_nanos(now_ms.saturating_mul(1_000_000)));
    }

    // Available tokens should have gone up by 1.
    let available = rl.available_tokens();

    // Wait, initially it was 1,000,000,000.
    // We drained 10,000 -> 999,990,000.
    // We should have gained 1 token -> 999,990,001.
    assert!(
        available >= 999_990_001,
        "Precision loss prevented token refill!"
    );
}
