# Refactor Ledger: `Metrics` Default Derive

## Scope

- Source: `src/sync/contended_mutex.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0551Z-contended-metrics-default-derive/`

## Line Delta

- Source lines before: 657
- Source lines after: 643
- Source reduction: 14 lines

## Proof Summary

The removed constructor performed only field-by-field default initialization.
Derived `Default` produces identical zero-initialized atomics and padding while
preserving the struct layout attributes and all metric update/read logic.

## Verification

- Passed: `rustfmt --edition 2024 --check src/sync/contended_mutex.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib --features lock-metrics`
- Passed: `rch exec -- cargo clippy -p asupersync --lib --features lock-metrics -- -D warnings`

## Fresh-Eyes Review

- Verified that `Metrics` is private to the `lock-metrics` inner module.
- Verified that `repr(C, align(64))`, field order, and field types are unchanged.
- Verified that the only production construction site still calls
  `Metrics::default()`.
- Verified that derived defaults match the removed constructor for all fields:
  zero-initialized atomics and zeroed `[u8; 32]` padding.
