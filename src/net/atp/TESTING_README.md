# ATP Testing Infrastructure

This directory contains comprehensive testing infrastructure for ATP (Asupersync Transfer Protocol) module development.

## Quick Start

### Running Tests
```bash
# Run all ATP tests
cargo test --lib atp

# Run infrastructure validation
cargo test atp_infrastructure_test

# Quick compilation check
scripts/check_atp_compilation.sh
```

### Using Test Utilities in Your Tests
```rust
use asupersync::net::atp::test_utils::*;

#[test]
fn test_my_component() {
    let cx = test_cx();
    let data = test_data::pattern_data(1024);
    let peer = fixtures::test_peer_id(1);
    
    let result = my_component(&cx, &data, peer);
    let value = assertions::assert_atp_ok(result);
    
    // Your assertions here
}
```

## What's Included

### 1. Test Utilities (`test_utils.rs`)
Comprehensive helper functions for ATP testing:
- **Test Context**: `test_cx()` creates properly configured `Cx` for testing
- **Test Data**: Pattern data, deterministic random data, small/medium fixtures
- **Assertions**: Type-safe ATP `Outcome` assertions
- **Fixtures**: Deterministic peer IDs, session IDs, and other ATP types

### 2. Infrastructure Tests (`tests/atp_infrastructure_test.rs`)
Basic compilation and functionality validation:
- Ensures ATP modules compile without errors
- Validates basic ATP type creation and usage
- Tests the test utilities themselves
- Serves as a foundation for more complex tests

### 3. Testing Patterns (`testing_patterns.md`)
Comprehensive guide covering:
- Core testing principles for ATP components
- Code examples and patterns
- Common pitfalls and how to avoid them
- Test organization strategies
- Property-based testing examples

### 4. Compilation Checker (`scripts/check_atp_compilation.sh`)
Quick validation script that checks:
- Basic ATP module compilation
- Test compilation
- Infrastructure test compilation
- Code formatting
- Basic clippy analysis

## Design Principles

### Deterministic Testing
All test utilities produce deterministic results:
- `test_data::deterministic_data(size, seed)` always produces the same output for the same inputs
- Fixture constructors always return the same objects for the same parameters
- Test contexts have consistent budget and timeout settings

### ATP-Aware Testing
Testing utilities understand ATP-specific concerns:
- Proper `Outcome<T, E>` handling with specific assertions
- `Cx` context management with appropriate budgets
- ATP protocol fixture values (PeerIds, SessionIds)
- No external QUIC dependencies

### Fail-Fast Compilation Checks
The infrastructure includes early compilation validation:
- Basic module compilation before running complex tests
- Clear error reporting for compilation issues
- Quick feedback during development

## Usage Patterns

### Unit Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::test_utils::*;
    
    #[test]
    fn test_component() {
        let cx = test_cx();
        // Test your component
    }
}
```

### Integration Testing
```rust
// In tests/atp_my_integration_test.rs
use asupersync::net::atp;
use asupersync::net::atp::test_utils::*;

#[tokio::test]
async fn test_integration_scenario() {
    let cx = test_cx();
    // Test cross-component interactions
}
```

### Property-Based Testing
```rust
use proptest::prelude::*;
use asupersync::net::atp::test_utils::*;

proptest! {
    #[test]
    fn test_property(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let cx = test_cx();
        // Test with generated data
    }
}
```

## Development Workflow

1. **Write Tests First**: Use the testing patterns and utilities to write tests for new ATP components
2. **Validate Compilation**: Run `scripts/check_atp_compilation.sh` for quick feedback
3. **Run Specific Tests**: Use `cargo test --lib component_name` for focused testing
4. **Run Full Suite**: Use `cargo test --lib atp` before committing

## Future Extensions

The testing infrastructure is designed to be extensible. Consider adding:
- Lab runtime integration for deterministic concurrency testing
- Performance benchmarking utilities
- Property-based test generators for ATP protocol compliance
- Deterministic network-condition fixtures for path testing
- Fixture corpora for complex scenarios

## Contributing

When adding new ATP components:
1. Include unit tests using the provided utilities
2. Add integration tests for cross-component interactions
3. Update `testing_patterns.md` if introducing new patterns
4. Ensure `scripts/check_atp_compilation.sh` passes
5. Consider adding property-based tests for complex behavior

This infrastructure supports the ATP development philosophy: deterministic, cancellation-correct, fail-closed testing with no external dependencies.
