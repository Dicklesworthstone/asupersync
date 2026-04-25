# Refactor Ledger: `TraceMigrator` Default Delegation

## Scope

- Source: `src/trace/compat.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0720Z-trace-migrator-default/`

## Line Delta

- Source lines before: 1230
- Source lines after: 1228
- Source reduction: 2 lines

## Proof Summary

`TraceMigrator` already derives `Default`; its manual constructor duplicated the
derived default for the migrations vector. Delegating through `Self::default()`
preserves the empty migration chain state while removing repeated field
initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/compat.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-trace-migrator-0720-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-trace-migrator-0720-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `TraceMigrator` still derives `Default`.
- Verified that the only stored field is `migrations`.
- Verified that the previous explicit `Vec::new()` maps to the same empty
  vector produced by derived `Default`.
- Verified that registration and migration application methods are unchanged.
