# Isomorphism Card: Reactor Events Derived Default

## Change

Replace the hand-written `Default` impl for `Events` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `Events::default()` construction paths.
- Ordering preserved: unchanged; event insertion and iteration order are untouched.
- Tie-breaking: not applicable.
- Error semantics: unchanged; default construction remains infallible.
- Laziness: unchanged; the event buffer remains empty and unspilled.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wakeups, or reactor registration.
- Rust type behavior: unchanged public `Default` implementation; no generic bounds are introduced because `Events` is concrete.
- Drop/reclaim behavior: unchanged; there are no stored events in the default state.

## Proof Notes

- The removed `Default` implementation returned `Self::with_capacity(0)`.
- `Self::with_capacity(0)` initializes `inner` with `SmallVec::with_capacity(0)` and `capacity` with `0`.
- `smallvec 1.15.1` implements `SmallVec::default()` as `SmallVec::new()`.
- In `smallvec 1.15.1`, `SmallVec::with_capacity(0)` constructs `SmallVec::new()` and then calls `reserve_exact(0)`, which returns immediately because zero additional capacity is already available.
- Derived `Default` therefore initializes `inner` to the same empty unspilled `SmallVec<[Event; 16]>` and `capacity` to `0`.

## Verification Results

- PASS `rustfmt --edition 2024 --check src/runtime/reactor/mod.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-events-default-1158-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-events-default-1158-test-zero -p asupersync --lib runtime::reactor::tests::events_zero_capacity`
  - `1 passed; 0 failed; 14543 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-events-default-1158-clippy -p asupersync --lib -- -D warnings`
- BROADER SAME-FILE TEST NOTE: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-events-default-1158-test -p asupersync --lib runtime::reactor::tests::events_` ran 7 reactor event tests; 6 passed and `events_clear` failed because `Events::with_capacity(10)` reported capacity `16` after push/clear instead of expected `10`. This path does not call `Events::default()` and no `with_capacity`, `push`, or `clear` code changed in this refactor.
