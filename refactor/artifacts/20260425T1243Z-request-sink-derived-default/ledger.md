# Refactor Ledger: RequestSinkState Derived Default

## Candidate

- File: `src/grpc/client.rs`
- Lever: derive private request-sink state defaults.
- Score: `(LOC_saved 9 * Confidence 5) / Risk 1 = 45.0`
- Decision: accepted.

## Baseline

- Source LOC before: `2194 src/grpc/client.rs`
- Git state before edit: `src/grpc/client.rs` had no local modifications.
- Existing tests covering this surface: request sink tests cover default construction, debug output, close hooks, send hooks, sent-count updates, and close-state-driven response futures.

## Expected Delta

- Add `Default` to `RequestSinkCloseState` and mark `Open` as `#[default]`.
- Add derived `Default` to `RequestSinkState`.
- Remove the hand-written `Default` impl that only spelled out field defaults.
- Source LOC after edit: `2185 src/grpc/client.rs`
- Source LOC reduction: `9`
- Preserve private construction behavior: new request sinks start open, have sent count zero, store no last message, and have no waiter.

## Verification

- PASS `rustfmt --edition 2024 --check src/grpc/client.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-test -p asupersync --lib grpc::client::tests::request_sink`
  - `6 passed; 0 failed; 14542 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-request-sink-default-1243-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the changed source after formatting. The only source delta is deriving `Default`, marking `Open` as the enum default, and removing the manual `RequestSinkState` default literal.
- Verified `RequestSinkState::new()` still delegates to `Self::default()`.
- Verified request sink send, close, drop, response future, and debug paths are unchanged.
- Verified the focused request sink test filter covers default construction, hook behavior, sent-count behavior, and response-future close-state behavior.
