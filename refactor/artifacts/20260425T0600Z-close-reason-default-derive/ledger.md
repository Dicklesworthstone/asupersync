# Refactor Ledger: `CloseReason` Default Derive

## Scope

- Source: `src/net/websocket/close.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0600Z-close-reason-default-derive/`

## Line Delta

- Source lines before: 1043
- Source lines after: 1037
- Source reduction: 6 lines

## Proof Summary

The removed default implementation delegated to `CloseReason::empty()`, which
sets all `Option` fields to `None`. Derived `Default` performs exactly that
field-by-field initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/net/websocket/close.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `CloseReason` fields remain unchanged.
- Verified that each derived field default is `None`, matching
  `CloseReason::empty()`.
- Verified that `CloseReason::empty()` remains available for explicit empty
  close-frame call sites.
- Verified that `CloseReason` still implements the same public `Default` trait.
