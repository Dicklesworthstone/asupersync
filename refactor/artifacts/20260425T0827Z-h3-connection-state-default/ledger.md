# Refactor Ledger: `H3ConnectionState` Derived Default

## Scope

- Source: `src/http/h3_native.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0827Z-h3-connection-state-default/`

## Line Delta

- Source lines before: 6506
- Source lines after: 6500
- Source reduction: 6

## Proof Summary

`H3ConnectionState` manually implemented `Default` by calling `new()`, which
called `with_config(H3ConnectionConfig::default())`. Derived `Default` builds
the same default config plus empty maps/sets and `None` stream IDs directly,
while public constructors remain available.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/h3_native.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-h3-connection-default-0827-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-h3-connection-default-0828-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `H3ConnectionState::new()` still constructs the default client state.
- `new_server()` still overrides only `endpoint_role` before calling
  `with_config(...)`.
- `with_config(...)` remains unchanged for custom configuration.
- Derived `Default` initializes every map/set to empty and every optional stream
  ID to `None`, matching the removed manual `Default -> new -> with_config`
  path.
