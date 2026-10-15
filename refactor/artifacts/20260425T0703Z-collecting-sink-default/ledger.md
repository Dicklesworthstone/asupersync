# Refactor Ledger: `CollectingSink` Default Delegation

## Scope

- Source: `src/transport/sink.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0703Z-collecting-sink-default/`

## Line Delta

- Source lines before: 2466
- Source lines after: 2464
- Source reduction: 2 lines

## Proof Summary

`CollectingSink` already derives `Default`; its manual constructor duplicated
the single-field empty-vector default. Delegating through `Self::default()`
preserves the empty sink state and keeps all callers unchanged.

## Verification

- Passed: `rustfmt --edition 2024 --check src/transport/sink.rs`
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-collecting-sink-0703-check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-collecting-sink-0703-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `CollectingSink` still derives `Default`.
- Verified that `CollectingSink` has exactly one field, `symbols`.
- Verified that `Vec<AuthenticatedSymbol>::default()` is equivalent to
  `Vec::new()`.
- Verified that collection accessors and sink polling behavior are unchanged.
