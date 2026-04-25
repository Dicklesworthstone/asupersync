# Isomorphism Card: VirtualTimerWheel Derived Default

## Change

Replace the hand-written `Default` impl for `VirtualTimerWheel` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `VirtualTimerWheel::default()` construction paths.
- Ordering preserved: unchanged; the timer heap and cancellation set start empty.
- Tie-breaking: unchanged; no timer IDs exist at construction, and `next_timer_id` remains `0`.
- Error semantics: unchanged; default construction remains infallible.
- Laziness: unchanged; construction still creates empty containers only.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable; `BTreeSet` starts empty and has deterministic ordering.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wake registration, or time reads.
- Rust type behavior: `VirtualTimerWheel` already implemented `Default`; this preserves the trait and its value.
- Drop/reclaim behavior: unchanged; default wheels own no timers or wakers.

## Proof Notes

- The removed `Default` implementation delegated to `VirtualTimerWheel::new()`.
- `VirtualTimerWheel::new()` initializes `heap` to `BinaryHeap::new()`, `current_tick` to `0`, `next_timer_id` to `0`, and `cancelled` to `BTreeSet::new()`.
- Derived `Default` initializes `BinaryHeap` and `BTreeSet` as empty, and both `u64` counters as `0`.
- `VirtualTimerWheel::new()` and `VirtualTimerWheel::starting_at(tick)` remain unchanged.

## Verification Plan

- `rustfmt --edition 2024 --check src/lab/virtual_time_wheel.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-test -p asupersync --lib lab::virtual_time_wheel::tests::new_wheel_starts_at_zero`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-clippy -p asupersync --lib -- -D warnings`

## Verification Results

- Passed: `rustfmt --edition 2024 --check src/lab/virtual_time_wheel.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-test -p asupersync --lib lab::virtual_time_wheel::tests::new_wheel_starts_at_zero`.
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-virtual-timer-wheel-default-1340-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- Re-read the changed struct and constructors after validation.
- Confirmed every derived field default equals the old `Self::new()` state: empty `BinaryHeap`, `0` current tick, `0` next timer ID, and empty `BTreeSet`.
- Confirmed `VirtualTimerWheel::starting_at(tick)` remains explicit and is not routed through `Default`, preserving custom starting ticks.
