# Isomorphism Card: Global Queue Empty Constructor

## Change

Delegate `GlobalQueue::new` to its existing derived `Default` implementation.

## Equivalence Contract

- Inputs covered: all empty `GlobalQueue::new` construction paths.
- Ordering preserved: yes; queue push/pop ordering is handled by the unchanged `SegQueue` field.
- Tie-breaking: unchanged; no scheduler dequeue logic is touched.
- Error semantics: unchanged; constructor remains infallible.
- Laziness: unchanged; the underlying `SegQueue` remains empty and allocates blocks lazily on push.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: unchanged; no randomized collections are involved.
- Observable side-effects: unchanged; construction performs no logging, tracing, I/O, task wakeups, or scheduler interaction.
- Rust type behavior: unchanged public constructor, unchanged derived `Default`, and no new trait bounds.
- Drop/reclaim behavior: unchanged; queue ownership and element drop behavior remain delegated to `SegQueue`.

## Proof Notes

- `GlobalQueue` already derives `Default`.
- `crossbeam-queue 0.3.12` implements `Default` for `SegQueue<T>` as `SegQueue::new()`.
- The removed literal initializes exactly one field, `inner`, with `SegQueue::new()`, so derived `GlobalQueue::default()` reaches the same empty queue state.
- Push, pop, len, empty checks, and all scheduler consumers are untouched.

## Verification Plan

- `rustfmt --edition 2024 --check src/runtime/scheduler/global_queue.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-test-a -p asupersync --lib runtime::scheduler::global_queue::tests::test_global_queue_default`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-test-b -p asupersync --lib runtime::scheduler::global_queue::tests::test_global_queue_push_pop_basic`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-global-queue-default-1122-clippy -p asupersync --lib -- -D warnings`
