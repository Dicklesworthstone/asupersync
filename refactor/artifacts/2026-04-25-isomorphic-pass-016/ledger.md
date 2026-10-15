# Isomorphic Simplification Pass 016

## Change

Extracted local-queue test setup helpers for repeated task-range pushes and
chunked push setup.

## Equivalence Contract

- Inputs covered: test-only ranges `0..total`, `0..split`, and `split..total`.
- Ordering preserved: `push_task_range` iterates the same ascending ranges and
  calls `LocalQueue::push` once per task; `push_task_chunks` builds the same
  prefix and suffix vectors and calls `push_many` in the same order.
- Error semantics: unchanged; helper bodies contain the same infallible test
  setup operations.
- Laziness/materialization: unchanged for chunked setup; prefix and suffix are
  still materialized before each `push_many` call.
- Observable side effects: unchanged; queue mutations occur in the same order
  against the same queue instances.
- Type conversion: unchanged; each integer is still converted with
  `task(id as u32)`.

## Verification

- `rustfmt --edition 2024 --check src/runtime/scheduler/local_queue.rs`: pass.
- `git diff --check -- src/runtime/scheduler/local_queue.rs refactor/artifacts/2026-04-25-isomorphic-pass-016/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-local-queue-pass016-test -p asupersync --lib runtime::scheduler::local_queue`: pass, 34 passed.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass016-check-rerun -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass016-clippy-tests -p asupersync --lib --tests -- -D warnings`: pass.

## Delta

- `src/runtime/scheduler/local_queue.rs`: 19 insertions, 22 deletions.
