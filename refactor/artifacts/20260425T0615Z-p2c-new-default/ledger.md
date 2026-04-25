# Refactor Ledger: `PowerOfTwoChoices::new()` Default Delegation

## Scope

- Source: `src/service/load_balance.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0615Z-p2c-new-default/`

## Line Delta

- Source lines before: 3172
- Source lines after: 3170
- Source reduction: 2 lines

## Proof Summary

`PowerOfTwoChoices` already derives `Default`, and its only field is an
`AtomicUsize`. The removed constructor set that field to zero; the derived
default does the same.

## Verification

- Passed: `rustfmt --edition 2024 --check src/service/load_balance.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `PowerOfTwoChoices` still derives `Default`.
- Verified that `PowerOfTwoChoices` still has exactly one `AtomicUsize` field.
- Verified that only `PowerOfTwoChoices::new()` changed in
  `src/service/load_balance.rs`.
- Verified that `pseudo_random()` still uses the same `counter` field.
