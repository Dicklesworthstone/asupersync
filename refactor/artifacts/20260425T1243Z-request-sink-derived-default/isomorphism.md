# Isomorphism Card: RequestSinkState Derived Default

## Change

Replace the hand-written `Default` impl for private `RequestSinkState` with derived `Default`, and mark `RequestSinkCloseState::Open` as the explicit enum default.

## Equivalence Contract

- Inputs covered: all `RequestSinkState::default()` and `RequestSinkState::new()` construction paths.
- Ordering preserved: unchanged; no queue or iteration order is involved.
- Tie-breaking: not applicable.
- Error semantics: unchanged; default construction remains infallible and creates no `Status`.
- Laziness: unchanged; no allocation or hook invocation occurs during default construction.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wake registration, or hook invocation.
- Rust type behavior: private helper type only; the public request sink API is unchanged.
- Drop/reclaim behavior: unchanged; default state owns no message payload and no waiter.

## Proof Notes

- The removed `Default` implementation set `close_state` to `RequestSinkCloseState::Open`, `sent_count` to `0`, `last_message` to `None`, and `waiter` to `None`.
- Derived `Default` for `RequestSinkCloseState` with `#[default] Open` yields the same close state.
- Derived `Default` for `RequestSinkState` initializes `usize` to `0` and both `Option` fields to `None`.
- `RequestSinkState::new()` already delegates to `Self::default()`, so all existing construction callsites keep the same state.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/grpc/client.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-test -p asupersync --lib grpc::client::tests::request_sink`
  - `6 passed; 0 failed; 14542 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-clippy -p asupersync --lib -- -D warnings`
