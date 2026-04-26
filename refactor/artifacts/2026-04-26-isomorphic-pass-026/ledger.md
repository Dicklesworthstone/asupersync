# Isomorphic Simplification Pass 026

## Candidate

- File: `src/net/websocket/handshake.rs`
- Lever: collapse equivalent one-sided HTTP header terminator match arms in `split_http_header_block`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- When both CRLFCRLF and LFLF terminators are present, both versions choose the earlier complete terminator via `std::cmp::min`.
- When exactly one terminator is present, the old arms returned that terminator position as `Some(usize)`.
- The new or-pattern binds and returns the same `Some(usize)` for both one-sided cases.
- When neither terminator is present, both versions return `None`, preserving the `InvalidRequest("incomplete HTTP headers")` path.
- Header/body split indices, UTF-8 parsing, request/response validation, and public APIs are unchanged.

## Metrics

- Source LOC before: 2282
- Source LOC after: 2281
- Source LOC delta: -1
- Diff numstat: `1 insertion, 2 deletions`

## Validation

- `rustfmt --edition 2024 --check src/net/websocket/handshake.rs`: passed
- `git diff --check -- src/net/websocket/handshake.rs refactor/artifacts/2026-04-26-isomorphic-pass-026/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-websocket-handshake-pass026-test -p asupersync --lib net::websocket::handshake`: passed (36 passed, 0 failed)
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass026-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass026-clippy-lib -p asupersync --lib -- -D warnings`: passed
