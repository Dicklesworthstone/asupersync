# Refactor Ledger: `SettingsBuilder` Default Delegation

## Scope

- Source: `src/http/h2/settings.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0741Z-settings-builder-default/`

## Line Delta

- Source lines before: 469
- Source lines after: 467
- Source reduction: 2 lines

## Proof Summary

`SettingsBuilder` already derives `Default`; its manual constructor duplicated
the derived field initialization for `settings`. Delegating through
`Self::default()` preserves the initial default HTTP/2 settings while removing
repeated field initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/h2/settings.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-settings-builder-0741-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-settings-builder-0741-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `SettingsBuilder` still derives `Default`.
- Verified its only stored field is `settings: Settings`.
- Verified both the previous constructor and derived default initialize that
  field with `Settings::default()`.
- Verified `client`, `server`, setter methods, and `build()` are unchanged.
