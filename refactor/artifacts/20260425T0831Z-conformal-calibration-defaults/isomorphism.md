# Isomorphism Proof: Conformal Calibration Defaults

## Change

Derive `Default` for zero-value conformal calibration helper structs, replace
manual `new()` callsites with `default()`/`or_default()`, and remove the manual
private constructors.

## Preconditions

- `Vec::<f64>::default()` is equivalent to `Vec::new()`.
- `usize::default()` is `0`.
- `f64::default()` is `0.0`.
- `CoverageTracker::new`, `InvariantCalibration::new`, and
  `MetricCalibration::new` are only used inside this module.
- `or_default()` inserts only for missing keys, matching `or_insert_with(...)`
  laziness for these zero-value constructors.

## Field Mapping

| Type | Field | Previous `new()` value | Derived `Default` value |
| --- | --- | --- | --- |
| `InvariantCalibration` | `scores` | `Vec::new()` | empty `Vec` |
| `InvariantCalibration` | `entity_sum` | `0.0` | `0.0` |
| `InvariantCalibration` | `event_sum` | `0.0` | `0.0` |
| `InvariantCalibration` | `violation_count` | `0` | `0` |
| `CoverageTracker` | `total` | `0` | `0` |
| `CoverageTracker` | `covered` | `0` | `0` |
| `MetricCalibration` | `values` | `Vec::new()` | empty `Vec` |

## Behavior Preservation

- Empty calibration state still reports the same sample counts and fallback
  rates before observations arrive.
- Coverage tracking still starts with zero predictions and zero covered
  predictions, so `rate()` still returns `1.0` for empty trackers.
- Metric thresholds still start with no calibration values.
- Prediction, quantile, and coverage update logic are unchanged.
