# Isomorphic Simplification Pass 011

## Change

Extracted `task_range` in the global queue test module for repeated `TaskId`
range construction.

## Equivalence Contract

- Inputs covered: property-test expected vectors built from ascending
  `usize` ranges.
- Ordering preserved: the helper iterates the same `Range<usize>` in ascending
  order.
- Error semantics: unchanged; no fallible operations.
- Laziness: preserved; expected vectors still collect at the same call sites,
  and setup loops still iterate directly without intermediate allocation.
- Observable side effects: none; this is test-only expected-value generation.
- Type conversion: unchanged; each element is still converted with
  `task(i as u32)`.

## Verification

- `rustfmt --edition 2024 --check src/runtime/scheduler/global_queue.rs`: pass.
- `git diff --check -- src/runtime/scheduler/global_queue.rs refactor/artifacts/2026-04-25-isomorphic-pass-011/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-global-queue-pass011b-test -p asupersync --lib runtime::scheduler::global_queue`: pass, 16 passed.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass011b-check -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass011b-clippy-tests -p asupersync --lib --tests -- -D warnings`: pass.

## Delta

- `src/runtime/scheduler/global_queue.rs`: 17 insertions, 20 deletions.
