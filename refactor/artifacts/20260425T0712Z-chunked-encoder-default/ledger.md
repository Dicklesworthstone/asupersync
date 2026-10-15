# Refactor Ledger: `BodyKind` Size Hint Centralization

## Scope

- Source: `src/http/h1/stream.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0712Z-chunked-encoder-default/`

## Line Delta

- Source lines before: 1578
- Source lines after: 1576
- Source reduction: 2 lines

## Proof Summary

`IncomingBody::channel_with_capacity` and
`OutgoingBody::channel_with_capacity` duplicated the same `BodyKind` to
`SizeHint` mapping. A private `BodyKind::size_hint()` helper centralizes that
mapping and each constructor stores its result directly, preserving every
variant's exact hint value.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/h1/stream.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-body-kind-size-hint-0712-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-body-kind-size-hint-0712-clippy -p asupersync --lib -- -D warnings`

## Candidate Rejection

- Rejected an initial `ChunkedEncoder::new() -> Self::default()` delegation
  because it preserved behavior but produced no source-line reduction.

## Fresh-Eyes Review

- Verified the helper maps `Empty` to `SizeHint::with_exact(0)`.
- Verified the helper maps `ContentLength(n)` to `SizeHint::with_exact(*n)`.
- Verified the helper maps `Chunked` to `SizeHint::default()`.
- Verified `BodyKind` is `Copy`, so calling `kind.size_hint()` does not move or
  alter the later `kind` field assignment or sender construction.
- Verified channel capacity, done-state computation, sender construction, and
  body fields other than `size_hint` are unchanged.
