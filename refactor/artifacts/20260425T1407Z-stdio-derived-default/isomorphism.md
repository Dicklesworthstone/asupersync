# Isomorphism Card: Stdio Derived Default

## Change

Replace the hand-written `Default` impl for the `Stdio` enum with derived `Default` and a `#[default]` marker on `Stdio::Inherit`.

## Equivalence Contract

- Inputs covered: all `Stdio::default()` construction paths, including `Command::new()` default stdio fields.
- Variant preserved: unchanged; `Default::default()` still returns `Stdio::Inherit`.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; enum default construction does not allocate or touch the OS.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable.
- Observable side-effects: unchanged; construction performs no I/O, process spawning, logging, or environment reads.
- Rust type behavior: `Stdio` already implemented `Default`; this preserves the trait and selected default variant.
- Conversion behavior: unchanged; `From<Stdio> for std::process::Stdio` and `Stdio::to_std()` still map `Inherit` to `std::process::Stdio::inherit()`.

## Proof Notes

- The removed `Default` implementation returned `Self::Inherit`.
- Rust enum derive with `#[default]` on a unit variant returns that exact variant.
- `Stdio::inherit()`, `Stdio::piped()`, `Stdio::null()`, and `Stdio::to_std()` remain unchanged.
- `Command::new()` still initializes stdin, stdout, and stderr from `Stdio::default()`.

## Verification Plan

- `rustfmt --edition 2024 --check src/process.rs`
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-check -p asupersync --lib`
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-test -p asupersync --lib process::tests::test_stdio_null`
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-clippy -p asupersync --lib -- -D warnings`

## Verification Results

- Passed: `rustfmt --edition 2024 --check src/process.rs`.
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-check -p asupersync --lib`.
- Passed: `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-test -p asupersync --lib process::tests::test_stdio_null`.
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-stdio-default-1407-clippy -p asupersync --lib -- -D warnings`.

## Fresh-Eyes Review

- Re-read the changed enum, constructor helpers, and `to_std()` mapping after validation.
- Confirmed `#[default]` is attached to `Stdio::Inherit`, exactly matching the removed manual default body.
- Confirmed `Command::new()` still initializes all stdio fields through `Stdio::default()`, preserving inherited defaults.
