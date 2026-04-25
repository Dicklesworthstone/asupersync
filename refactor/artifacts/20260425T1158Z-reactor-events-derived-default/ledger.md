# Refactor Ledger: Reactor Events Derived Default

## Candidate

- File: `src/runtime/reactor/mod.rs`
- Lever: derive the existing empty-events `Default`.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1327 src/runtime/reactor/mod.rs`
- Git state before edit: `src/runtime/reactor/mod.rs` had no local modifications.
- Existing tests covering this surface: reactor event tests cover capacity, push/iterate, clear, growth, zero-capacity behavior, and iteration.

## Expected Delta

- Add `Default` to the `Events` derive list.
- Remove the hand-written `Default` impl that only called `with_capacity(0)`.
- Expected source LOC after edit: `1321 src/runtime/reactor/mod.rs`
- Expected source LOC reduction: `6`
- Preserve public API: `Events::default()` remains available.
- Preserve default state: empty unspilled event storage and `Events::capacity() == 0`.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/reactor/mod.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-events-default-1158-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-events-default-1158-test-zero -p asupersync --lib runtime::reactor::tests::events_zero_capacity`
  - `1 passed; 0 failed; 14543 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-events-default-1158-clippy -p asupersync --lib -- -D warnings`
- BROADER SAME-FILE TEST NOTE: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-events-default-1158-test -p asupersync --lib runtime::reactor::tests::events_` ran 7 tests; 6 passed and `runtime::reactor::tests::events_clear` failed on a `with_capacity(10)` path with `left: 16`, `right: 10`. This refactor does not touch `with_capacity`, `push`, or `clear`, and the default-construction path is covered by the passing `events_zero_capacity` test.

## Fresh-Eyes Review

- Re-read the changed source after formatting. The only source delta is adding `Default` to `Events` derives and removing the manual `impl Default`.
- Verified `Events::with_capacity`, `clear`, `push`, `len`, `is_empty`, `capacity`, and iterator implementations are unchanged.
- Verified derived `Default` preserves `Events::default()` as a public API and produces an empty `SmallVec` plus `capacity == 0`.
- Verified the broad `events_clear` failure is not caused by this change because it constructs with `Events::with_capacity(10)`, then mutates via existing `push` and `clear` code.
