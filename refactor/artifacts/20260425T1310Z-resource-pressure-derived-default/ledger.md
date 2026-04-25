# Refactor Ledger: ResourcePressure Derived Default

## Candidate

- File: `src/runtime/resource_monitor.rs`
- Lever: derive default for pure field-default pressure state.
- Score: `(LOC_saved 6 * Confidence 4) / Risk 1 = 24.0`
- Decision: accepted.

## Baseline

- Source LOC before: `1158 src/runtime/resource_monitor.rs`
- Git state before edit: `src/runtime/resource_monitor.rs` had no local modifications.
- Existing tests covering this surface: `test_resource_pressure_updates` covers initial update behavior, and `test_resource_pressure_system_pressure_matches_degradation_band` covers the shared `SystemPressure` degradation band derived from resource updates.

## Expected Delta

- Add `Default` to `ResourcePressure` derives.
- Remove the hand-written `Default` impl that only delegated to `ResourcePressure::new()`.
- Source LOC after edit: `1152 src/runtime/resource_monitor.rs`
- Source LOC reduction: `6`
- Preserve default pressure state: empty measurements, empty degradation levels, empty last-change map, full system headroom, and zero monitoring overhead.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/resource_monitor.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-test -p asupersync --lib runtime::resource_monitor::tests::test_resource_pressure_system_pressure_matches_degradation_band`
  - `1 passed; 0 failed; 14547 filtered out`
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-resource-pressure-default-1310-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the changed source after formatting. The only source delta is adding `Default` to `ResourcePressure` derives and removing the manual delegating impl.
- Verified `ResourcePressure::new()` remains unchanged.
- Verified `SystemPressure::default()` still delegates to `SystemPressure::new()`, preserving full-headroom initialization.
- Verified the focused resource-pressure test covers the shared `SystemPressure` degradation-band behavior after pressure updates.
