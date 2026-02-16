use asupersync::combinator::circuit_breaker::*;
use asupersync::types::Time;
use std::time::Duration;

#[test]
fn test_half_open_probes_overflow() {
    // 2^24 = 16,777,216.
    // We want to verify that setting a limit > 2^24 results in broken behavior
    // where the circuit breaker thinks it has 0 probes when it actually has 2^24.
    
    // Note: We can't easily spawn 16 million threads/tasks in a unit test to hit this.
    // But we can check if the Builder correctly clamps the configuration.
    
    let large_limit = 20_000_000; // > 2^24
    
    let policy = CircuitBreakerPolicyBuilder::new()
        .half_open_max_probes(large_limit)
        .build();
        
    // Ideally, this should be clamped to prevent overflow in the packed state.
    // MAX_HALF_OPEN_PROBES = 0x00FF_FFFF = 16777215
    
    assert_eq!(policy.half_open_max_probes, 0x00FF_FFFF);
    assert_ne!(policy.half_open_max_probes, large_limit);
}
