# Refactor Ledger: `HeaderMap` Default Delegation

## Scope

- Source: `src/http/body.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0707Z-header-map-default/`

## Line Delta

- Source lines before: 1784
- Source lines after: 1781
- Source reduction: 3 lines

## Proof Summary

`HeaderMap` already derives `Default`; its manual constructor duplicated the
derived defaults for the header vector and deterministic position map.
Delegating through `Self::default()` preserves the empty map state while
removing repeated field initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/body.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-header-map-0707-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-header-map-0707-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `HeaderMap` still derives `Default`.
- Verified that `headers` maps from `Vec::new()` to the identical empty vector
  default.
- Verified that `positions` maps from explicit `DetHashMap::default()` to the
  same derived field default.
- Verified that `with_capacity` and all mutation/lookup methods are unchanged.
