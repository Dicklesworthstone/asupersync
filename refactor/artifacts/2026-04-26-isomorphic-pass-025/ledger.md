# Isomorphic Simplification Pass 025

## Candidate

- File: `src/stream/zip.rs`
- Lever: collapse equivalent one-sided `Option<usize>` match arms in `Zip::size_hint`.
- Score: `(LOC_saved 1 * confidence 5) / risk 1 = 5.0`

## Isomorphism Proof

- For two finite upper bounds, both versions return the smaller bound via `a.min(b)`.
- For exactly one finite upper bound, the old arms returned that finite `Some(usize)`.
- The new or-pattern binds and returns the same `Some(usize)` for both `(Some(_), None)` and `(None, Some(_))`.
- `(None, None)` remains `None`.
- Polling behavior, queued-item handling, exhaustion behavior, lower-bound arithmetic, and public APIs are unchanged.

## Metrics

- Source commit: `db92eef5b style: rustfmt sweep across src/ - collapse multi-line, sort imports, leading-operator wraps`
- Source LOC before: 471
- Source LOC after: 470
- Source LOC delta: -1
- Diff numstat: `1 insertion, 2 deletions`

## Validation

- `rustfmt --edition 2024 --check src/stream/zip.rs`: passed
- `git diff --check -- src/stream/zip.rs refactor/artifacts/2026-04-26-isomorphic-pass-025/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-stream-zip-pass025-retry -p asupersync --lib stream::zip`: passed (9 passed, 0 failed; unrelated warnings in `src/observability/debt_runtime_integration.rs`, `src/channel/broadcast.rs`, `src/io/read_line.rs`, and `src/combinator/race.rs`)
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass025-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass025-clippy-lib-remote -p asupersync --lib -- -D warnings`: passed
