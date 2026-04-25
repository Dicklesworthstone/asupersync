# Isomorphism Card: Work-Stealing Checker Constructor Helper

## Change

Collapse the duplicated `WorkStealingChecker::new` and `WorkStealingChecker::disabled` struct literals into one private `with_enabled` constructor.

## Equivalence Contract

- Inputs covered: enabled construction via `new`/`Default` and disabled construction via `disabled`.
- Ordering preserved: yes; field initialization order and later ownership/steal tracking logic are unchanged.
- Tie-breaking: unchanged; `sequence_counter` still starts at `0`.
- Error semantics: unchanged; constructors remain infallible.
- Laziness: unchanged; each constructor still creates fresh empty `Arc<RwLock<...>>` containers and no task state.
- Short-circuit eval: unchanged; enabled checks still branch on the same stored boolean.
- Floating-point: not applicable.
- RNG/hash order: unchanged; empty `HashMap` state is unchanged.
- Observable side-effects: unchanged; construction performs no tracing, logging, I/O, task wakeups, or scheduler interaction.
- Rust type behavior: unchanged public `Default`, `new`, and `disabled`; no derived default is introduced because `bool::default()` would change `Default` to disabled.
- Drop/reclaim behavior: unchanged; no tracked tasks, violations, or steal trackers exist in the empty state.

## Proof Notes

- The removed `new` and `disabled` literals were identical except for `enabled: true` versus `enabled: false`.
- The new private helper takes that boolean and constructs the same fresh maps, vectors, stats, atomic sequence counter, and task sequence map.
- `Default` still returns `Self::new()`, preserving the current enabled default semantics.
- Tracking, violation, reset, steal success/failure, and ordering-validation logic are untouched.

## Verification Plan

- `rustfmt --edition 2024 --check src/runtime/scheduler/work_stealing_checker.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-test -p asupersync --lib runtime::scheduler::work_stealing_checker::tests::`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-clippy -p asupersync --lib -- -D warnings`
