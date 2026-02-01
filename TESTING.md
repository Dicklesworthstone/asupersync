# Testing Guide

This document defines the test logging standards, categories, and execution
patterns for the Asupersync codebase. The goal is deterministic, explainable
failures with high-signal traces and minimal manual digging.

## Quick Commands

```bash
# Unit + integration tests
cargo test

# Stream logs
cargo test -- --nocapture

# Run a specific test file
cargo test --test http_verification

# Run a specific test by name (substring match)
cargo test cancellation_conformance
```

## Test Categories and Locations

- Unit tests: colocated under `src/` modules
- Integration tests: `tests/*.rs`
- E2E tests: `tests/e2e/**` (protocol stacks, cancel-correctness, tracing)
- Conformance suite: `conformance/` crate (runtime-agnostic suite)
- Fuzz tests: `fuzz/` (cargo-fuzz targets + corpora)
- Property tests: see `property-tests.yml` CI workflow and `tests/*.rs` files

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

- Shared helpers live in `src/test_utils.rs`
- Use the lab runtime (`LabRuntime`) for deterministic concurrency tests

## Conformance Suite

The conformance suite lives in the `conformance/` crate and is designed to be
runtime-agnostic. To run it:

```bash
cargo test -p asupersync-conformance
```

The `asupersync` crate also exposes conformance tooling in the CLI when the
`cli` feature is enabled (see `src/bin/asupersync.rs`).

## E2E Tests

E2E tests are organized under `tests/e2e/` and cover protocol-level behavior
with structured logging. Use `-- --nocapture` for logs and prefer deterministic
lab runtime variants where available.

## Fuzzing

Fuzzing targets live under `fuzz/` and are documented in `fuzz/README.md`.
Example:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_http2_frame -- -max_total_time=60
```

Crashes and corpora are stored under `fuzz/artifacts/` and `fuzz/corpus/`.

## CI Expectations

CI should run at minimum:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

CI also includes scheduled fuzzing via `.github/workflows/fuzz.yml` and
property tests via `.github/workflows/property-tests.yml`.

## Debugging Tips

- Use `cargo test -- --nocapture` to stream logs.
- Prefer `test_lab_with_tracing()` when you need larger trace buffers.
- When a test fails, scan for the last `test_phase!` and `assert_with_log!`
  markers to pinpoint the failure point.
