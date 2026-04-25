# Refactor Ledger: `ConcurrentSymbolSet` Default Delegation

## Scope

- Source: `src/types/symbol_set.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0745Z-concurrent-symbol-set-default/`

## Line Delta

- Source lines before: 778
- Source lines after: 776
- Source reduction: 2 lines

## Proof Summary

`ConcurrentSymbolSet` already derives `Default`; its manual constructor
duplicated the derived initialization of the `RwLock<SymbolSet>` field.
Delegating through `Self::default()` preserves the empty default-configured
symbol set while removing repeated field initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/types/symbol_set.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-concurrent-symbol-set-0745-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-concurrent-symbol-set-0745-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `ConcurrentSymbolSet` still derives `Default`.
- Verified that its only field is `inner: RwLock<SymbolSet>`.
- Verified `SymbolSet::default()` still delegates to `SymbolSet::new()`.
- Verified insert, removal, contains, stats, and snapshot methods are
  unchanged.
