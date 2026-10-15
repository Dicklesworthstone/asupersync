# Refactor Ledger: LatencyAnalyzer Default State

## Candidate

- File: `src/plan/latency_algebra.rs`
- Lever: derive/reuse default constructor state for `LatencyAnalyzer`.
- Score: `(LOC_saved 2 * Confidence 5) / Risk 1 = 10.0`
- Decision: accepted.

## Baseline

- Source LOC before: `2872 src/plan/latency_algebra.rs`
- Git state before edit: `src/plan/latency_algebra.rs` had no local modifications.
- Existing tests covering this surface: `plan::latency_algebra` includes `LatencyAnalyzer::new` and `LatencyAnalyzer::with_defaults` paths.

## Expected Delta

- Remove the manual default implementation.
- Remove repeated empty-map/default-curve initialization from `new` and `with_defaults`.
- Source LOC after edit: `2861 src/plan/latency_algebra.rs`
- Source LOC reduction: `11`
- Preserve public APIs: `LatencyAnalyzer::new`, `LatencyAnalyzer::with_defaults`, and `Default` remain.
- Preserve final construction state for no-default and default-curve analyzer construction.

## Verification

- PASS: `rustfmt --edition 2024 --check src/plan/latency_algebra.rs`
- PASS: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-check -p asupersync --lib`
- BASELINE BLOCKER: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-test -p asupersync --lib plan::latency_algebra`
  - Result: `45 passed; 11 failed; 14477 filtered out`
  - Failure class: insta snapshot assertions for display-format tests with missing accepted `src/plan/snapshots/asupersync__plan__latency_algebra__tests__*.snap` baselines.
  - Local artifact check: no `src/plan/snapshots/*.snap.new` files remained in the checkout after `rch` retrieval.
- PASS: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-narrow-a -p asupersync --lib plan::latency_algebra::tests::default_curves_used_for_unannotated_leaves`
  - Result: `1 passed; 0 failed; 14532 filtered out`
- PASS: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-narrow-b -p asupersync --lib plan::latency_algebra::tests::missing_annotation_no_defaults_gives_infinity`
  - Result: `1 passed; 0 failed; 14532 filtered out`
- PASS: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-latency-analyzer-0937-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the final `src/plan/latency_algebra.rs` diff after verification.
- Confirmed derived `Default` is field-equivalent to the removed `new` literal for this non-generic struct: empty `BTreeMap`, `None`, `None`.
- Confirmed `LatencyAnalyzer::new` still exposes the same no-annotation state.
- Confirmed `LatencyAnalyzer::with_defaults` starts from the same no-annotation state and assigns the same `Some(arrival)` and `Some(service)` fields as the removed literal.
- Confirmed no `.snap.new` files were left in `src/plan/snapshots`.
- Confirmed no public API removal, no new generic trait-bound surface, and no unrelated source edits in this pass.
