# Isomorphic Simplification Pass 018

## Candidate

- File: `src/util/det_hash.rs`
- Lever: extract the repeated `mix_byte` loop into private `DetHasher::mix_bytes`.
- Score: `(LOC_saved 2 * confidence 5) / risk 1 = 10.0`

## Isomorphism Proof

- `write(bytes)` now delegates to `mix_bytes(bytes)`, whose body is exactly the prior loop.
- `write_u16`, `write_u32`, `write_u64`, and `write_u128` still feed `to_le_bytes()` in slice order.
- The helper calls the unchanged `mix_byte`, so each byte applies the same multiply-then-xor state transition.
- `finish`, signed integer writers, and width normalization for `usize`/`isize` are unchanged.

## Metrics

- Source LOC before: 364
- Source LOC after: 352
- Source LOC delta: -12
- Diff numstat: `12 insertions, 24 deletions`

## Validation

- `rustfmt --edition 2024 --check src/util/det_hash.rs`: passed
- `git diff --check -- src/util/det_hash.rs refactor/artifacts/2026-04-25-isomorphic-pass-018/ledger.md`: passed
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-det-hash-pass018-test -p asupersync --lib util::det_hash`: passed, 13 tests
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass018-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass018-clippy-tests -p asupersync --lib --tests -- -D warnings`: passed
