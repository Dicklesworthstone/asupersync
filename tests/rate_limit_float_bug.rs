//! Regression test for long-horizon token refill precision in `RateLimiter`.

use asupersync::Time;
use asupersync::combinator::rate_limit::{
    RateLimitAlgorithm, RateLimitPolicy, RateLimiter, WaitStrategy,
};
use std::time::Duration;

#[test]
fn token_bucket_preserves_fractional_refill_until_hour_boundary() {
    const BURST: u32 = 1_000_000_000;
    const DRAINED: u32 = 10_000;
    const EXPECTED_AFTER_DRAIN: u32 = BURST - DRAINED;

    let policy = RateLimitPolicy {
        name: "hourly".into(),
        rate: 1,
        period: Duration::from_secs(3600),
        burst: BURST,
        default_cost: 1,
        wait_strategy: WaitStrategy::Reject,
        algorithm: RateLimitAlgorithm::TokenBucket,
    };
    let rl = RateLimiter::new(policy);

    assert!(rl.try_acquire(DRAINED, Time::ZERO));
    assert_eq!(rl.available_tokens(), EXPECTED_AFTER_DRAIN);

    rl.refill(Time::from_millis(3_599_999));
    assert_eq!(
        rl.available_tokens(),
        EXPECTED_AFTER_DRAIN,
        "sub-period fractional refill must not mint a whole token early"
    );

    rl.refill(Time::from_secs(3600));

    assert_eq!(
        rl.available_tokens(),
        EXPECTED_AFTER_DRAIN + 1,
        "fractional refill should accumulate exactly one token at the hour boundary"
    );
}
