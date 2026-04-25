# Refactor Ledger: `VectorClock` Default Delegation

## Scope

- Source: `src/trace/distributed/vclock.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0647Z-vector-clock-default/`

## Line Delta

- Source lines before: 1519
- Source lines after: 1517
- Source reduction: 2 lines

## Proof Summary

`VectorClock` already derives `Default`; its manual constructor duplicated the
single-field empty-map default. Delegating through `Self::default()` preserves
the public constructor and all causal-ordering semantics.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/distributed/vclock.rs`
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-vector-clock-0647-check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-vector-clock-0647-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `VectorClock` still derives `Default`.
- Verified that `VectorClock` has exactly one field, `entries`.
- Verified that `BTreeMap<NodeId, u64>::default()` is the same empty map as
  `BTreeMap::new()`.
- Verified that `for_node`, merge, comparison, serialization, and mutation
  logic are unchanged.
