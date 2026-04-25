# Isomorphism Card: SymbolSet Derived Default

## Change

Replace the hand-written `Default` impl for `SymbolSet` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `SymbolSet::default()` construction paths.
- Collection state preserved: symbols and per-block counts start empty.
- Counters preserved: total symbol count, total byte count, and memory remaining all start at `0`.
- Memory budget preserved: default set has no memory budget.
- Threshold configuration preserved: `threshold_config` still uses `ThresholdConfig::default()`.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; construction creates empty maps and stores scalar defaults only.
- Floating-point: unchanged; the default overhead factor still comes from the existing `ThresholdConfig::default()` implementation.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, allocation beyond empty maps, or time reads.
- Drop/reclaim behavior: unchanged; default sets own no symbols.

## Proof Notes

- The removed `Default` implementation delegates to `SymbolSet::new()`.
- `SymbolSet::new()` delegates to `Self::with_config(ThresholdConfig::default())`.
- `Self::with_config()` initializes both maps empty, all counters to `0`, memory budget to `None`, and threshold config to the provided value.
- Derived `Default` initializes `HashMap`, `usize`, and `Option<usize>` fields to the same values, and calls the existing `ThresholdConfig::default()` for `threshold_config`.
- `SymbolSet::new()`, `with_config()`, and `with_memory_budget()` remain unchanged.

## Verification Plan

- `rustfmt --edition 2024 --check src/types/symbol_set.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-test -p asupersync --lib types::symbol_set::tests::insert_and_duplicate`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-clippy -p asupersync --lib -- -D warnings`

## Verification Results

- Passed: `rustfmt --edition 2024 --check src/types/symbol_set.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-test -p asupersync --lib types::symbol_set::tests::insert_and_duplicate`.
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- Re-read the changed struct, `new()`, and `with_config()` after validation.
- Confirmed derived `Default` calls `ThresholdConfig::default()` for the threshold field, preserving the non-zero default overhead and max-per-block values.
- Confirmed empty maps, zero counters, `None` memory budget, and zero memory remaining match the removed `Self::new()` path.
