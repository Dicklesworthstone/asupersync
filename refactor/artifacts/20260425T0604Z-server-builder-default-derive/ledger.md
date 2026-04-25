# Refactor Ledger: `ServerBuilder` Default Derive

## Scope

- Source: `src/grpc/server.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0604Z-server-builder-default-derive/`

## Line Delta

- Source lines before: 1663
- Source lines after: 1658
- Source reduction: 5 lines

## Proof Summary

The removed implementation delegated to `ServerBuilder::new()`, whose fields
are exactly their derived defaults: default server config, empty service map,
and no reflection registry.

## Verification

- Passed: `rustfmt --edition 2024 --check src/grpc/server.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `ServerBuilder::new()` remains unchanged.
- Verified that derived `Default` matches every field constructed by `new()`.
- Verified that `Option<ReflectionService>::default()` does not require
  `ReflectionService: Default`.
- Verified that the custom `Debug` implementation is unchanged.
