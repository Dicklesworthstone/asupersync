# Refactor Ledger: Link Empty Constructors

## Candidate

- File: `src/link.rs`
- Lever: reuse already-derived defaults for empty link collection constructors.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1956 src/link.rs`
- Git state before edit: `src/link.rs` had no local modifications.
- Existing tests covering this surface: `link` module tests cover empty peer lookup and exit-batch behavior.

## Expected Delta

- Replace repeated empty collection literals in `LinkExitBatch::new`, `LinkSet::new`, and `ExitBatch::new`.
- Expected source LOC after edit: `1948 src/link.rs`
- Expected source LOC reduction: `8`
- Preserve public APIs: all `new` constructors and derived `Default` implementations remain.
- Preserve final empty collection state.

## Verification

- PASS `rustfmt --edition 2024 --check src/link.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-link-default-1023-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-link-default-1023-test-peers -p asupersync --lib link::tests::peers_of_empty`
  - Result: 1 passed, 0 failed, 14532 filtered.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-link-default-1023-test-exit-batch -p asupersync --lib link::tests::exit_batch_empty`
  - Result: 1 passed, 0 failed, 14532 filtered.
  - Note: this worker was slow; a duplicate retry on `/tmp/cargo-target-asupersync-link-default-1023-test-exit-batch-retry` also passed.
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-link-default-1023-test-resolve -p asupersync --lib link::tests::resolve_exits_normal_is_silent`
  - Result: 1 passed, 0 failed, 14532 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-link-default-1023-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/link.rs` diff after verification.
- `LinkExitBatch` already derives `Default`; derived initialization covers the same empty `Vec` field as the removed literal.
- `LinkSet` already derives `Default`; derived initialization covers the same three empty `BTreeMap` indexes as the removed literal.
- `ExitBatch` already derives `Default`; derived initialization covers the same empty `Vec` field as the removed literal.
- No new trait impls, bounds, public APIs, side effects, allocation timing differences beyond equivalent empty collection construction, sorting behavior, link cleanup behavior, or exit-resolution behavior were introduced.
