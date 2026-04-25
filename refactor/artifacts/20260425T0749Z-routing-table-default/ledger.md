# Refactor Ledger: `RoutingTable` Derived Default

## Scope

- Source: `src/transport/router.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0749Z-routing-table-default/`

## Line Delta

- Source lines before: 3391
- Source lines after: 3381
- Source reduction: 10 lines

## Proof Summary

`RoutingTable` manually implemented `Default` by calling `new()`, and `new()`
duplicated the default states for three `RwLock` fields. Deriving `Default`
directly and delegating `new()` through it preserves the empty routing table
state while removing repeated initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/transport/router.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-routing-table-0749-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-routing-table-0749-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified `RoutingTable` fields remain `routes`, `default_route`, and
  `endpoints`.
- Verified derived defaults initialize both `HashMap`-backed locks empty and
  the default-route lock to `None`.
- Verified `RoutingTable::new()` and `RoutingTable::default()` no longer recurse
  and now produce the same empty table through the derived implementation.
- Verified endpoint registration, route mutation, lookup, pruning, and
  route-count methods are unchanged.
