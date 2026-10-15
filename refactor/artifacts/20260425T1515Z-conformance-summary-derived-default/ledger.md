# Refactor Ledger: Conformance Summary Derived Defaults

## Candidate

- File: `conformance/src/runner.rs`
- Lever: derive default for zeroed conformance run summary state.
- Score: `(LOC_saved 10 * Confidence 5) / Risk 1 = 50.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1508 conformance/src/runner.rs`
- Git state before edit: `conformance/src/runner.rs` had no local modifications.
- Existing tests covering this surface: runner tests construct empty `RunSummary` and `ComparisonSummary` values and exercise result accumulation from the empty state.

## Expected Delta

- Add `Default` to `RunSummary` and `ComparisonSummary` derives.
- Remove the hand-written `Default` impls that only delegated to `new()`.
- Expected source LOC after edit: `1498 conformance/src/runner.rs`
- Expected source LOC reduction: `10`
- Preserve empty-summary state for counters, duration, and result vectors.

## Verification

- Pending.
