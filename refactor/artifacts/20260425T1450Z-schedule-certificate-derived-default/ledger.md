# Refactor Ledger: ScheduleCertificate Derived Default

## Candidate

- File: `src/runtime/scheduler/priority.rs`
- Lever: derive default for zeroed scalar schedule-certificate state.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `3755 src/runtime/scheduler/priority.rs`
- Git state before edit: `src/runtime/scheduler/priority.rs` had no local modifications.
- Existing tests covering this surface: `certificate_empty` asserts a fresh certificate has zero decisions and no divergence; later certificate tests exercise recording and divergence transitions from the fresh state.

## Expected Delta

- Add `Default` to `ScheduleCertificate` derives.
- Remove the hand-written `Default` impl that only delegated to `ScheduleCertificate::new()`.
- Expected source LOC after edit: `3749 src/runtime/scheduler/priority.rs`
- Expected source LOC reduction: `6`
- Preserve default certificate state: hash `0`, decisions `0`, divergence step `None`.

## Verification

- `rustfmt --edition 2024 --check src/runtime/scheduler/priority.rs`: passed.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-check -p asupersync --lib`: passed.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-test -p asupersync --lib runtime::scheduler::priority::tests::certificate_empty`: passed, `1 passed; 0 failed; 14558 filtered out`.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-clippy -p asupersync --lib -- -D warnings`: passed.

## Fresh-Eyes Review

- Re-read the diff and confirmed no scheduling behavior, hashing order, divergence handling, or public method body changed.
- Confirmed derived `Default` preserves the exact `hash: 0`, `decisions: 0`, `divergence_step: None` state because those are the built-in defaults for the field types.
- Result: no fix-up required.
