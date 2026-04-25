//! Regression test for circuit breaker half-open probe limit normalization.

use asupersync::combinator::circuit_breaker::{CircuitBreakerPolicyBuilder, MAX_HALF_OPEN_PROBES};

#[test]
fn half_open_probe_limit_is_clamped_to_packed_state_capacity() {
    let policy = CircuitBreakerPolicyBuilder::new()
        .half_open_max_probes(MAX_HALF_OPEN_PROBES + 1)
        .build();

    assert_eq!(policy.half_open_max_probes, MAX_HALF_OPEN_PROBES);
}
