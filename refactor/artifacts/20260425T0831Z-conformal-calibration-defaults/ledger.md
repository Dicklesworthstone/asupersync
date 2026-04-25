# Refactor Ledger: Conformal Calibration Defaults

## Scope

- Source: `src/lab/conformal.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0831Z-conformal-calibration-defaults/`

## Line Delta

- Source lines before: 1654
- Source lines after: 1631
- Source reduction: 23

## Proof Summary

The conformal calibration helpers manually initialized only empty vectors and
numeric zeroes. Derived `Default` creates the same zero-value state and allows
missing-key insertion sites to use `or_default()` directly.

## Verification

- Passed: `rustfmt --edition 2024 --check src/lab/conformal.rs`
- Passed:
  `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-conformal-defaults-0831-check -p asupersync --lib`
- Passed:
  `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-conformal-defaults-0833-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- `InvariantCalibration`, `CoverageTracker`, and `MetricCalibration` now derive
  `Default` from the same empty vector and numeric-zero field values.
- All removed constructors were module-private and had no validation or side
  effects.
- `or_default()` is used only for missing `BTreeMap` entries, matching the
  previous `or_insert_with(...::new)` insertion behavior.
- Coverage `rate()`, conformity scoring, threshold calibration, and tracking
  updates are unchanged.
