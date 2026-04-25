# Refactor Ledger: DiffContext Derived Default

## Candidate

- File: `franken_evidence/src/render.rs`
- Lever: derive default for an empty deterministic map context.
- Score: `(LOC_saved 5 * Confidence 5) / Risk 1 = 25.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1398 franken_evidence/src/render.rs`
- Git state before edit: `franken_evidence/src/render.rs` had no local modifications.
- Existing tests covering this surface: `level3_deterministic` covers equal outputs from two fresh contexts; the Level 3 tests cover empty-context first-render behavior.

## Expected Delta

- Add `Default` to `DiffContext` derives.
- Remove the hand-written `Default` impl that only delegated to `DiffContext::new()`.
- Expected source LOC after edit: `1393 franken_evidence/src/render.rs`
- Expected source LOC reduction: `5`
- Preserve default context state: empty recent-entry `BTreeMap`.

## Verification

- Source LOC after: `1393 franken_evidence/src/render.rs`
- Source LOC reduction: `5`
- Passed: `rustfmt --edition 2024 --check franken_evidence/src/render.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-check -p franken-evidence --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-test -p franken-evidence render::tests::level3_deterministic` (`1 passed; 79 filtered out` in `src/lib.rs`, integration target had `0` matching tests).
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-diff-context-default-1401-clippy -p franken-evidence --lib -- -D warnings`.

## Fresh-Eyes Review

- No bug found in the edited code.
- The derivation is isomorphic because `BTreeMap::default()` and `BTreeMap::new()` both produce an empty deterministic map.
- The stateful rendering path remains unchanged and continues to mutate only `recent` through `level3()`.
