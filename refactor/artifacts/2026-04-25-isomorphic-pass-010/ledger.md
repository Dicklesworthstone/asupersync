# Isomorphic Simplification Pass 010

## Change

Extracted `sorted_completed_task_ids` for blocking-pool metamorphic tests that
spawn task IDs into a pool, wait for every handle, clone the completion vector,
sort it, and return it.

Fresh-eyes validation also exposed and fixed a pre-existing test harness bug in
`mr_spawn_blocking_cancellation_states`: the test asserted pool-backed queued
cancellation semantics while using `Runtime::block_on`, which does not install
an ambient `Cx`. It now uses `Runtime::block_on_with_cx` with the runtime's
request `Cx`, so `spawn_blocking` exercises the configured blocking pool rather
than the fallback-thread path.

The same test also waited for a real blocking thread with an async virtual-time
sleep. It now waits for the real completion atomic with a bounded real-time
deadline before asserting soft-cancel completion.

The test-aware clippy gate then exposed an unrelated no-op `u32::from(step_id)`
conversion in `cancellation_visualizer` test helpers; that was reduced to
`step_id` to keep `--tests` clippy clean.

## Equivalence Contract

- Inputs covered: the original and reversed task-ID order checks, plus minimal
  and maximal thread-count checks.
- Ordering preserved: task submission order is still the slice order supplied
  by each test; returned vectors are still sorted with `sort_unstable`.
- Error semantics: unchanged; worker panics and lock poisoning still surface via
  the same `wait`/`unwrap` calls.
- Laziness: unchanged; tests still materialize completion vectors before
  assertions.
- Observable side effects: unchanged except for shared helper call stack; tasks
  sleep for the same duration and push the same IDs.
- Test harness context: `mr_spawn_blocking_cancellation_states` now matches its
  stated contract by installing the same runtime-backed `Cx` that production
  request paths use for pool-backed `spawn_blocking`.
- Soft-cancel wait: bounded real-time wait observes the blocking thread's actual
  completion instead of assuming virtual async sleep advances wall-clock work.
- Clippy cleanup: removing `u32::from(step_id)` is type-identical because
  `step_id` is already `u32`.

## Verification

- `rustfmt --edition 2024 --check src/runtime/blocking_pool/metamorphic.rs src/observability/cancellation_visualizer.rs`: pass.
- `git diff --check -- src/runtime/blocking_pool/metamorphic.rs src/observability/cancellation_visualizer.rs refactor/artifacts/2026-04-25-isomorphic-pass-010/ledger.md`: pass.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-blocking-pool-pass010-test3 -p asupersync --lib mr_spawn_blocking_cancellation_states`: pass, 1/1.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-blocking-pool-pass010-test3 -p asupersync --lib runtime::blocking_pool::metamorphic`: pass, 8/8.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-pass010-check -p asupersync --lib`: pass.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-pass010-clippy-tests -p asupersync --lib --tests -- -D warnings`: pass.

## Source LOC Delta

- `src/runtime/blocking_pool/metamorphic.rs`: 96 deletions, 45 insertions.
- `src/observability/cancellation_visualizer.rs`: 1 deletion, 1 insertion.
