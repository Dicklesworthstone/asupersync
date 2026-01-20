# Testing Guide

This document defines the test logging standards and conventions for the
Asupersync codebase. The goal is deterministic, explainable failures with
high-signal traces and minimal manual digging.

## Logging Standards

### Initialization (required)

Every test must initialize logging once at the top of the test body:

```rust
use asupersync::test_utils::init_test_logging;

#[test]
fn my_test() {
    init_test_logging();
    // ...
}
```

### Phase Markers

Use `test_phase!` for major phases and `test_section!` for smaller steps:

```rust
asupersync::test_phase!("setup");
// ...
asupersync::test_section!("spawn tasks");
// ...
```

### Assertion Logging

Use `assert_with_log!` to capture expected vs actual values:

```rust
asupersync::assert_with_log!(
    value == 42,
    "value should be the answer",
    42,
    value
);
```

### Completion Marker

Log a clean success at the end of each test:

```rust
asupersync::test_complete!("my_test");
```

## Required Log Points

Every test should log:

1. Test start (call `init_test_logging()` and a `test_phase!` marker)
2. Each major phase or step (`test_phase!`, `test_section!`)
3. Values before key assertions (`assert_with_log!`)
4. Final outcome (`test_complete!`)

## Log Level Guidelines

- TRACE: Internal details (tight loops, state diffs)
- DEBUG: Setup, intermediate values, assertions
- INFO: Phase transitions, test outcomes
- WARN: Unexpected but recoverable conditions
- ERROR: Test infrastructure failures

## Test Organization

- Integration tests live in `tests/`
- Unit tests live alongside modules in `src/`
- Shared helpers live in `src/test_utils.rs`
- Use the lab runtime (`LabRuntime`) for deterministic concurrency tests

## CI Expectations

CI should run at minimum:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

## Debugging Tips

- Use `cargo test -- --nocapture` to stream logs.
- Prefer `test_lab_with_tracing()` when you need larger trace buffers.
- When a test fails, scan for the last `test_phase!` and `assert_with_log!`
  markers to pinpoint the failure point.
