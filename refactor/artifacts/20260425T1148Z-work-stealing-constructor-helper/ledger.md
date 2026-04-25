# Refactor Ledger: Work-Stealing Checker Constructor Helper

## Candidate

- File: `src/runtime/scheduler/work_stealing_checker.rs`
- Lever: share the duplicated empty checker constructor literal while keeping enabled default semantics.
- Score: `(LOC_saved 4 * Confidence 5) / Risk 1 = 20.0`
- Decision: accepted.

## Baseline

- Source LOC before: `537 src/runtime/scheduler/work_stealing_checker.rs`
- Git state before edit: `src/runtime/scheduler/work_stealing_checker.rs` had no local modifications.
- Existing tests covering this surface: work-stealing checker tests cover enabled ownership tracking, steals, double execution detection, and ownership violation detection.

## Expected Delta

- Add private `with_enabled(enabled: bool)` constructor.
- Replace `new` and `disabled` duplicated literals with calls to the helper.
- Expected source LOC after edit: `533 src/runtime/scheduler/work_stealing_checker.rs`
- Expected source LOC reduction: `4`
- Preserve public API: `Default`, `new`, and `disabled` remain.
- Preserve current invariant: `Default::default()` remains enabled.

## Verification

- PASS `rustfmt --edition 2024 --check src/runtime/scheduler/work_stealing_checker.rs`
- PASS `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-check -p asupersync --lib`
- PASS `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-test -p asupersync --lib runtime::scheduler::work_stealing_checker::tests::`
  - Result: 4 passed, 0 failed, 14536 filtered.
- PASS `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-work-stealing-helper-1148-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Re-read the exact `src/runtime/scheduler/work_stealing_checker.rs` diff after verification.
- `new` still constructs an enabled checker, `disabled` still constructs a disabled checker, and `Default` still delegates to the enabled `new`.
- The helper creates fresh `Arc<RwLock<...>>` containers and a fresh `AtomicU64` on every call, preserving ownership isolation between checker instances.
- No tracking logic, violation accounting, steal RAII behavior, reset behavior, or public API changed.
