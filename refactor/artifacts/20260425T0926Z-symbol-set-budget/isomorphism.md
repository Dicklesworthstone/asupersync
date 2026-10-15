# Isomorphism Card: SymbolSet Memory Budget Constructor

## Change

Implement `SymbolSet::with_memory_budget` by starting from
`SymbolSet::with_config(config)` and assigning the two budget-specific fields.

## Equivalence Contract

- Inputs covered: all `SymbolSet::with_memory_budget(config, budget_bytes)` calls.
- Ordering preserved: yes; construction remains synchronous and no symbols exist yet.
- Tie-breaking: unchanged; no iteration or ordering logic changes.
- Error semantics: unchanged; constructor remains infallible.
- Laziness: unchanged; both versions allocate empty maps during construction.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; empty deterministic hash maps are still initialized by the same `with_config` path.
- Observable side-effects: unchanged; no tracing, logging, I/O, or runtime interaction.
- Rust type behavior: unchanged public function signature and no new trait bounds.
- Cancellation/runtime behavior: unchanged; pure synchronous initialization only.

## Proof Notes

- The old `with_memory_budget` literal matched `with_config(config)` for `symbols`, `block_counts`, `total_count`, `total_bytes`, and `threshold_config`.
- The only intentionally different fields are `memory_budget` and `memory_remaining`.
- Assigning `Some(budget_bytes)` and `budget_bytes` after `with_config(config)` yields the same final struct state as the removed literal.
- The fields are private, so the observable API remains through existing methods and insertion behavior.

## Verification Plan

- `rustfmt --edition 2024 --check src/types/symbol_set.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-test -p asupersync --lib types::symbol_set`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-symbol-set-budget-0926-clippy -p asupersync --lib -- -D warnings`
