# Refactor Ledger: Stdio Derived Default

## Candidate

- File: `src/process.rs`
- Lever: derive default for a unit-variant enum default.
- Score: `(LOC_saved 6 * Confidence 5) / Risk 1 = 30.0`
- Decision: accepted.

## Baseline

- Source LOC before: `3088 src/process.rs`
- Git state before edit: `src/process.rs` had no local modifications.
- Existing tests covering this surface: process stdio tests cover conversion and spawn behavior; `Command::new()` uses `Stdio::default()` for all stdio fields.

## Expected Delta

- Add `Default` to the `Stdio` derives.
- Mark `Stdio::Inherit` as the enum default with `#[default]`.
- Remove the hand-written `Default` impl that only returned `Stdio::Inherit`.
- Expected source LOC after edit: `3082 src/process.rs`
- Expected source LOC reduction: `6`
- Preserve default stdio state: inherited stdin, stdout, and stderr.

## Verification

- Source LOC after: `3082 src/process.rs`
- Source LOC reduction: `6`
- Passed: `rustfmt --edition 2024 --check src/process.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-test -p asupersync --lib process::tests::test_stdio_null` (`1 passed; 14553 filtered out`).
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- No bug found in the edited code.
- The derivation is isomorphic because Rust derives `Default` for the unit variant marked with `#[default]`, and that variant is `Stdio::Inherit`.
- Process stdio conversion and command initialization paths remain unchanged.
