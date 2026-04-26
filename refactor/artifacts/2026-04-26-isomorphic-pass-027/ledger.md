# Isomorphic Simplification Pass 027

## Candidate

- File: `src/net/websocket/client.rs`
- Lever: collapse equivalent one-sided HTTP response terminator match arms in `read_http_response`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- When both CRLFCRLF and LFLF terminators are present, both versions choose the earlier complete terminator via `std::cmp::min`.
- When exactly one terminator is present, the old arms returned that terminator position as `Some(usize)`.
- The new or-pattern binds and returns the same `Some(usize)` for both one-sided cases.
- When neither terminator is present, both versions return `None`, preserving the continue-reading and oversized-response paths.
- Header/trailing split indices, EOF handling, buffer truncation, and public APIs are unchanged.

## Metrics

- Source LOC before: 2150
- Source LOC after: 2149
- Source LOC delta: -1
- Diff numstat: `1 insertion, 2 deletions`

## Validation

- `rustfmt --edition 2024 --check src/net/websocket/client.rs`: passed
- `git diff --check -- src/net/websocket/client.rs refactor/artifacts/2026-04-26-isomorphic-pass-027/ledger.md`: passed
- Fresh-eyes validation note: the first module test run exposed an unrelated send-cancellation cleanup bug in this file; fixed separately in `6053c6453` before final pass validation.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-websocket-client-pass027-test2 -p asupersync --lib net::websocket::client`: passed, 31 passed, 0 failed
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass027-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass027-clippy-lib -p asupersync --lib -- -D warnings`: passed
