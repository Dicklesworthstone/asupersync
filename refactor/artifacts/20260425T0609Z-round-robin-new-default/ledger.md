# Refactor Ledger: `RoundRobin::new()` Default Delegation

## Scope

- Source: `src/service/load_balance.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0609Z-round-robin-new-default/`

## Line Delta

- Source lines before: 3174
- Source lines after: 3172
- Source reduction: 2 lines

## Proof Summary

`RoundRobin` already derives `Default`, and its only field is an `AtomicUsize`.
The removed constructor set that field to zero; the derived default does the
same.

## Verification

- Passed: `rustfmt --edition 2024 --check src/service/load_balance.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `RoundRobin` still derives `Default`.
- Verified that `RoundRobin` still has exactly one `AtomicUsize` field.
- Verified that only `RoundRobin::new()` changed in `src/service/load_balance.rs`.
- Verified that `Strategy::pick()` still uses the same `next` counter.
