# Isomorphic Simplification Pass 009

## Change

Reuse `ObligationTable::sorted_pending_ids_for_holder` from
`pending_obligation_ids_for_task` instead of duplicating the same holder-index
filter and sort pipeline.

## Equivalence Contract

- Inputs covered: all `TaskId` inputs accepted by both existing collectors.
- Ordering preserved: `sorted_pending_ids_for_holder` already sorts by
  `ObligationId`; the removed code used the same `sort_unstable`.
- Error semantics: unchanged; both paths ignore stale/missing arena entries.
- Laziness: unchanged at public boundary; both materialize owned IDs.
- Observable side effects: none.
- Return type: unchanged; `SmallVec::into_vec` converts to the existing `Vec`
  API after sorting.

## Verification

- `rustfmt --edition 2024 --check src/runtime/obligation_table.rs`: pass.
- `git diff --check -- src/runtime/obligation_table.rs refactor/artifacts/2026-04-25-isomorphic-pass-009/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-obligation-table-pass009-test -p asupersync --lib runtime::obligation_table`: pass, 25/25.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass009-check -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass009-clippy -p asupersync --lib -- -D warnings`: pass.

## Source LOC Delta

- `src/runtime/obligation_table.rs`: 12 deletions, 1 insertion.
