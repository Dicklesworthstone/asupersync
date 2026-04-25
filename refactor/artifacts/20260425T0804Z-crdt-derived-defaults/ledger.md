# Refactor Ledger: CRDT Merge Extension

## Scope

- Source: `src/trace/distributed/crdt.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0804Z-crdt-derived-defaults/`

## Line Delta

- Source lines before: 1161
- Source lines after: 1159
- Source reduction: 2

## Proof Summary

The first candidate in this reserved slice, deriving `Default` for generic CRDT
types, was rejected by `cargo check` because it would require `V: Default`.
The committed lever instead collapses a manual append loop in `MVRegister::merge`
to `Vec::extend` over the same `BTreeSet` iterator and cloned item type.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/distributed/crdt.rs`
- Rejected candidate:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-crdt-defaults-0804-check -p asupersync --lib`
  failed because derived `Default` would require `V: Default`.
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-crdt-extend-0807-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-crdt-extend-0807-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- The final source diff only changes `MVRegister::merge`.
- `combined.extend(other.entries.iter().cloned())` appends the same cloned
  entries that the previous `for entry in &other.entries` loop pushed.
- `BTreeSet` iteration order, dominance filtering inputs, and version-counter
  merge semantics are unchanged.
- No generic bounds were changed after the rejected derived-default attempt.
