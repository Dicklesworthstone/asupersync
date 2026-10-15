# Refactor Ledger: `HostPool` Derived Default

## Scope

- Source: `src/http/pool.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0753Z-host-pool-default/`

## Line Delta

- Source lines before: 1011
- Source lines after: 1005
- Source reduction: 6

## Proof Summary

`HostPool` manually initialized its only field with `HashMap::new()`. Deriving
`Default` and using `or_default()` at the missing-entry insertion site preserves
the empty per-host connection map while removing the private constructor.

## Verification

- Passed: `rustfmt --edition 2024 --check src/http/pool.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-host-pool-0800-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-host-pool-0800-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `HostPool` still contains only `connections: HashMap<u64, PooledConnectionMeta>`.
- `HashMap::default()` and `HashMap::new()` both produce an empty map.
- `or_default()` only runs for missing `PoolKey` entries, matching
  `or_insert_with(HostPool::new)` laziness for the previous private constructor.
- Existing `PooledConnectionMeta::new`, connection ID allocation, stats updates,
  and map insertion order are unchanged.
