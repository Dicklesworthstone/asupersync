# Refactor Ledger: SymbolSet Memory Budget Constructor

## Candidate

- File: `src/types/symbol_set.rs`
- Lever: reuse the existing `with_config` constructor for the memory-budget constructor.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `776 src/types/symbol_set.rs`
- Git state before edit: `src/types/symbol_set.rs` had no local modifications.
- Existing tests covering this surface: `types::symbol_set` includes `SymbolSet::with_memory_budget` paths.

## Expected Delta

- Remove repeated empty-map and counter initialization from `with_memory_budget`.
- Source LOC after edit: `771 src/types/symbol_set.rs`
- Source LOC reduction: `5`
- Preserve public APIs: `SymbolSet::new`, `SymbolSet::with_config`, `SymbolSet::with_memory_budget`, and `Default` remain.
- Preserve final state for memory-budget construction.

## Verification

- PASS: `rustfmt --edition 2024 --check src/types/symbol_set.rs`
- PASS: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-check -p asupersync --lib`
- PASS: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-test -p asupersync --lib types::symbol_set`
  - Result: `20 passed; 0 failed; 14513 filtered out`
- PASS: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the final `src/types/symbol_set.rs` diff after verification.
- Confirmed `with_config(config)` initializes the same empty `symbols` and `block_counts` maps, zero counters, and threshold config as the removed literal.
- Confirmed `with_memory_budget` restores the two intentional budget fields to `Some(budget_bytes)` and `budget_bytes`.
- Confirmed no public API removal, no new trait bounds, and no unrelated source edits in this pass.
