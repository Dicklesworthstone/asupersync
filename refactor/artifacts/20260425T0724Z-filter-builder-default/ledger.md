# Refactor Ledger: `FilterBuilder` Default Delegation

## Scope

- Source: `src/trace/filter.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0724Z-filter-builder-default/`

## Line Delta

- Source lines before: 960
- Source lines after: 958
- Source reduction: 2 lines

## Proof Summary

`FilterBuilder` already derives `Default`; its manual constructor duplicated
derived field initialization because `TraceFilter::new()` delegates to
`TraceFilter::default()`. Delegating through `Self::default()` preserves the
initial builder filter state while removing repeated field initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/filter.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-filter-builder-0724-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-filter-builder-0724-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `FilterBuilder` still derives `Default`.
- Verified that its only field is `filter: TraceFilter`.
- Verified that `TraceFilter::new()` still delegates to
  `TraceFilter::default()`, matching the derived default field value.
- Verified that builder mutation methods and `build()` are unchanged.
