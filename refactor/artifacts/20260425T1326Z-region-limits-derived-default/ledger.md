# Refactor Ledger: RegionLimits Derived Default

## Candidate

- File: `src/record/region.rs`
- Lever: derive default for an all-`Option::None` limits struct.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `2800 src/record/region.rs`
- Git state before edit: `src/record/region.rs` had no local modifications.
- Existing tests covering this surface: `region_limits_debug_clone_default_eq` asserts `RegionLimits::default() == RegionLimits::UNLIMITED`.

## Expected Delta

- Add `Default` to `RegionLimits` derives.
- Remove the hand-written `Default` impl that only returned `RegionLimits::UNLIMITED`.
- Source LOC after edit: `2794 src/record/region.rs`
- Source LOC reduction: `6`
- Preserve default admission limits: every limit remains absent and `curve_budget` remains `None`.

## Verification

- PASS `rustfmt --edition 2024 --check src/record/region.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-test -p asupersync --lib record::region::tests::region_limits_debug_clone_default_eq`
  - `1 passed; 0 failed; 14547 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-region-limits-default-1326-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the changed source after formatting. The only source delta is adding `Default` to `RegionLimits` derives and removing the manual impl.
- Verified `RegionLimits::UNLIMITED` still sets all five fields to `None`.
- Verified `RegionLimits::unlimited()` still returns the explicit `UNLIMITED` constant.
- Verified `region_limits_debug_clone_default_eq` asserts the derived default still equals `RegionLimits::UNLIMITED`.
