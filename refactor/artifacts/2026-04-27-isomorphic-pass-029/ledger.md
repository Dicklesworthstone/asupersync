# Isomorphic Simplification Pass 029

## Candidate

- File: `src/distributed/assignment.rs`
- Lever: centralize repeated `ReplicaAssignment` construction for symbol assignment strategies.
- Score: `(LOC_saved 2 * confidence 5) / risk 1 = 10.0`

## Isomorphism Proof

- `assign_full`, `assign_striped`, `assign_minimum_k`, and `assign_weighted` still supply the exact `symbol_indices` vectors they computed before.
- `replica_id` is still cloned from the same `ReplicaInfo::id` at the same per-replica callsites.
- `can_decode` remains `symbol_indices.len() >= k`; for `assign_full`, `symbol_indices.len()` is exactly `symbols.len()`, matching the old predicate.
- Strategy ordering, weighted tie-breaking, `BTreeSet` sorted order for `MinimumK`, and empty-input early returns are unchanged.
- Public APIs, error semantics, allocation ownership, RNG/hash order, and observable side effects are unchanged.

## Metrics

- Source LOC before: 835
- Source LOC after: 829
- Source LOC delta: -6
- Source diff numstat: `20 insertions, 26 deletions`

## Validation

- `rustfmt --edition 2024 --check src/distributed/assignment.rs`: passed
- `git diff --check -- src/distributed/assignment.rs refactor/artifacts/2026-04-27-isomorphic-pass-029/ledger.md`: passed before final ledger update
- Initial `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass029-assignment-test -p asupersync --lib distributed::assignment`: failed with 32 passed, 1 stale golden failure; committed `b17db811a` to align `golden_plan_minimum_k_strategy` with the existing BTreeSet sorted-order implementation.
- Final `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-pass029-assignment-test-final -p asupersync --lib distributed::assignment`: passed, 33 passed, 0 failed
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass029-check -p asupersync --lib`: passed
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass029-clippy-lib -p asupersync --lib -- -D warnings`: passed
