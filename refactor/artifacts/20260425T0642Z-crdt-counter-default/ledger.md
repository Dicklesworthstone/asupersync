# Refactor Ledger: CRDT Counter Default Delegation

## Scope

- Source: `src/trace/distributed/crdt.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0642Z-crdt-counter-default/`

## Line Delta

- Source lines before: 1166
- Source lines after: 1161
- Source reduction: 5 lines

## Proof Summary

`GCounter` and `PNCounter` already derive `Default`; their manual constructors
duplicated those defaults exactly. Delegating through `Self::default()` removes
manual field initialization while preserving API and counter semantics.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/distributed/crdt.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-crdt-counter-0642-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `GCounter` still derives `Default`.
- Verified that `BTreeMap<NodeId, u64>::default()` is the same empty map as
  `BTreeMap::new()`.
- Verified that `PNCounter` still derives `Default`.
- Verified that `PNCounter::default()` creates two empty `GCounter` fields,
  matching the previous constructor.
- Verified that no merge, increment, decrement, or value logic changed.
