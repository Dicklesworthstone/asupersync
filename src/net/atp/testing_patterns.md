# ATP Testing Patterns and Guidelines

This document provides testing patterns and guidelines for ATP module development to ensure consistent, reliable, and deterministic tests.

## Core Testing Principles

1. **Deterministic by Default**: All tests should use deterministic inputs and produce reproducible results
2. **Cx-First**: Use proper `Cx` context with appropriate budgets and cancellation behavior
3. **Outcome Handling**: Test all `Outcome` variants (Ok, Err, Cancelled, Panicked) explicitly
4. **Lab Runtime**: Use lab runtime for complex concurrency and timing scenarios
5. **No External Dependencies**: Test ATP components in isolation without external QUIC crates

## Test Structure

```rust
use asupersync::net::atp::test_utils::*;
use asupersync::cx::Cx;

#[test]
fn test_atp_component() {
    let cx = test_cx();
    
    // Arrange
    let input_data = test_data::pattern_data(1024);
    let peer_id = fixtures::test_peer_id(1);
    
    // Act
    let result = component_under_test(&cx, input_data, peer_id);
    
    // Assert
    let value = assertions::assert_atp_ok(result);
    assert_eq!(value.len(), expected_len);
}
```

## Test Data Patterns

### Use Provided Test Data
- `test_data::SMALL_DATA` - 64 bytes of 0x42
- `test_data::MEDIUM_DATA` - 4KB of 0xAB
- `test_data::pattern_data(size)` - Incrementing byte pattern
- `test_data::deterministic_data(size, seed)` - Pseudo-random deterministic data

### Example
```rust
#[test]
fn test_chunking() {
    let cx = test_cx();
    let data = test_data::deterministic_data(8192, 12345);
    
    let chunks = chunk_data(&cx, &data, 1024);
    let outcome = assertions::assert_atp_ok(chunks);
    assert_eq!(outcome.len(), 8); // 8KB / 1KB = 8 chunks
}
```

## Outcome Testing Patterns

### Test Success Path
```rust
#[test]
fn test_success_case() {
    let result = operation_that_succeeds();
    let value = assertions::assert_atp_ok(result);
    // Verify value properties
}
```

### Test Error Conditions
```rust
#[test]
fn test_error_case() {
    let result = operation_that_fails();
    let error = assertions::assert_atp_err(result);
    assert!(matches!(error, SpecificError::ExpectedVariant));
}
```

### Test Cancellation
```rust
#[test]
fn test_cancellation() {
    let cx = test_cx();
    cx.request_cancel(); // Cancel before operation
    
    let result = cancellable_operation(&cx);
    assertions::assert_atp_cancelled(result);
}
```

## Deterministic Fixture Objects

Use provided fixtures for consistent test behavior:

```rust
#[test]
fn test_with_fixtures() {
    let peer_a = fixtures::test_peer_id(1);
    let peer_b = fixtures::test_peer_id(2);
    let session = fixtures::test_session_id(100);
    
    // Fixtures are deterministic - same input always produces same output
    assert_eq!(peer_a, fixtures::test_peer_id(1));
    assert_ne!(peer_a, peer_b);
}
```

## Async Testing

For async ATP operations, use proper async test setup:

```rust
#[tokio::test]
async fn test_async_operation() {
    let cx = test_cx();
    
    // Use timeout to prevent hanging tests
    let timeout = tokio::time::timeout(
        TEST_TIMEOUT,
        async_operation(&cx)
    ).await;
    
    let result = timeout.expect("Operation should not timeout");
    let value = assertions::assert_atp_ok(result);
    // Verify async result
}
```

## Property-Based Testing

For complex ATP components, consider property-based tests:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_roundtrip_property(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let cx = test_cx();
        
        let encoded = encode_data(&cx, &data);
        let encoded_value = assertions::assert_atp_ok(encoded);
        
        let decoded = decode_data(&cx, &encoded_value);
        let decoded_value = assertions::assert_atp_ok(decoded);
        
        prop_assert_eq!(data, decoded_value);
    }
}
```

## Lab Runtime Testing

For deterministic concurrency testing:

```rust
use asupersync::lab::{LabConfig, LabRuntime};

#[test]
fn test_concurrent_behavior() {
    let mut runtime = LabRuntime::new(LabConfig::new(42)); // Fixed seed
    
    // Create deterministic scenario
    runtime.run_until_quiescent();
    
    // Verify deterministic outcome
}
```

## Test Organization

### Module Tests
Place tests alongside implementation:
```rust
// In src/net/atp/component.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::test_utils::*;
    
    #[test]
    fn test_component_basic() {
        // Unit tests here
    }
}
```

### Integration Tests
Place in `tests/` directory for cross-component testing:
```rust
// In tests/atp_integration_test.rs
use asupersync::net::atp;
use asupersync::net::atp::test_utils::*;

#[tokio::test]
async fn test_end_to_end_scenario() {
    // Integration tests here
}
```

## Common Pitfalls to Avoid

1. **Non-deterministic seeds**: Always use fixed seeds for test data
2. **Timeout without budget**: Set appropriate `Cx` budget for operations
3. **Ignoring cancellation**: Test cancellation paths explicitly
4. **External dependencies**: Don't depend on external QUIC crates in tests
5. **Race conditions**: Use lab runtime for deterministic concurrency testing

## Test Categories

### Unit Tests
- Test individual functions and components
- Use deterministic fixtures for dependencies
- Focus on single responsibility
- Fast execution (< 1ms per test)

### Integration Tests
- Test component interactions
- Use real ATP types but controlled scenarios
- Moderate execution time (< 100ms per test)

### End-to-End Tests
- Test complete ATP workflows
- Use lab runtime for determinism
- Longer execution time acceptable (< 1s per test)

## Example Test Suite Structure

```
src/net/atp/
├── component/
│   ├── mod.rs          // Implementation
│   └── tests/         // Component-specific tests
├── test_utils.rs      // Shared test utilities
└── testing_patterns.md // This document

tests/
├── atp_infrastructure_test.rs  // Basic compilation test
├── atp_integration_test.rs     // Cross-component tests
└── atp_e2e_test.rs            // End-to-end scenarios
```
