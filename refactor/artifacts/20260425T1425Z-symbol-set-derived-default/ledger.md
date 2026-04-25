# Refactor Ledger: SymbolSet Derived Default

## Candidate

- File: `src/types/symbol_set.rs`
- Lever: derive default for empty maps, zero counters, no memory budget, and existing default threshold config.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `771 src/types/symbol_set.rs`
- Git state before edit: `src/types/symbol_set.rs` had no local modifications.
- Existing tests covering this surface: `insert_and_duplicate`, `threshold_tracking`, and reset/ready-block tests exercise fresh `SymbolSet::new()` state.

## Expected Delta

- Add `Default` to `SymbolSet` derives.
- Remove the hand-written `Default` impl that only delegated to `SymbolSet::new()`.
- Expected source LOC after edit: `765 src/types/symbol_set.rs`
- Expected source LOC reduction: `6`
- Preserve default set state: empty maps, zero counters, no memory budget, and `ThresholdConfig::default()`.

## Verification

- Source LOC after: `765 src/types/symbol_set.rs`
- Source LOC reduction: `6`
- Passed: `rustfmt --edition 2024 --check src/types/symbol_set.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-test -p asupersync --lib types::symbol_set::tests::insert_and_duplicate` (`1 passed; 14554 filtered out`).
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-symbol-set-default-1425-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- No bug found in the edited code.
- The derivation is isomorphic because `HashMap`, `usize`, and `Option<usize>` defaults match `with_config()`, while `threshold_config` still uses `ThresholdConfig::default()`.
- `SymbolSet::new()`, custom config construction, and memory-budget construction remain unchanged.
