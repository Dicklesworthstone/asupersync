# Refactor Ledger: Generalized Ledger Empty Constructor

## Candidate

- File: `src/evidence.rs`
- Lever: reuse already-derived default for the empty generalized evidence ledger constructor.
- Score: `(LOC_saved 1 * Confidence 5) / Risk 1 = 5.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1385 src/evidence.rs`
- Git state before edit: `src/evidence.rs` had no local modifications.
- Existing tests covering this surface: generalized ledger tests cover default/clone and push/query behavior.

## Expected Delta

- Replace the repeated empty `Vec` literal in `GeneralizedLedger::new`.
- Expected source LOC after edit: `1383 src/evidence.rs`
- Expected source LOC reduction: `2`
- Preserve public API: `GeneralizedLedger::new` and the derived `Default` implementation remain.
- Preserve final empty ledger state.

## Verification

- PASS `rustfmt --edition 2024 --check src/evidence.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-test-a -p asupersync --lib evidence::tests::generalized_ledger_debug_clone_default`
  - Result: 1 passed, 0 failed, 14532 filtered.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-test-b-retry -p asupersync --lib evidence::tests::generalized_ledger_push_and_query`
  - Result: 1 passed, 0 failed, 14535 filtered.
  - Note: the first run on `/tmp/cargo-target-asupersync-generalized-ledger-default-1051-test-b` was still pending on a slow worker when the retry passed.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-generalized-ledger-default-1051-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/evidence.rs` diff after verification.
- `GeneralizedLedger` already derives `Default`; derived initialization covers the same empty `Vec` field as the removed literal.
- No new trait impls, bounds, public APIs, side effects, allocation timing differences beyond equivalent empty ledger construction, rendering behavior, query behavior, clone behavior, or serialization behavior were introduced.
