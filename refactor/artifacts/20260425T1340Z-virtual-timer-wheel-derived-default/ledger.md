# Refactor Ledger: VirtualTimerWheel Derived Default

## Candidate

- File: `src/lab/virtual_time_wheel.rs`
- Lever: derive default for a pure empty-container and zero-counter timer wheel.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `783 src/lab/virtual_time_wheel.rs`
- Git state before edit: `src/lab/virtual_time_wheel.rs` had no local modifications.
- Existing tests covering this surface: `new_wheel_starts_at_zero` asserts a new wheel starts at tick 0 and is empty; timer insertion tests cover the empty-container starting state.

## Expected Delta

- Add `Default` to `VirtualTimerWheel` derives.
- Remove the hand-written `Default` impl that only delegated to `VirtualTimerWheel::new()`.
- Expected source LOC after edit: `777 src/lab/virtual_time_wheel.rs`
- Expected source LOC reduction: `6`
- Preserve default wheel state: empty heap, current tick zero, next timer id zero, and empty cancellation set.

## Verification

- Source LOC after: `777 src/lab/virtual_time_wheel.rs`
- Source LOC reduction: `6`
- Passed: `rustfmt --edition 2024 --check src/lab/virtual_time_wheel.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-test -p asupersync --lib lab::virtual_time_wheel::tests::new_wheel_starts_at_zero` (`1 passed; 14550 filtered out`).
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- No bug found in the edited code.
- The derivation is isomorphic because derived defaults for `BinaryHeap`, `BTreeSet`, and `u64` exactly match the removed manual constructor delegation.
- The custom `starting_at(tick)` constructor remains independent, so non-zero starting ticks are preserved.
