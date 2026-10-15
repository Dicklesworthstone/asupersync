# Isomorphism Card: ScheduleCertificate Derived Default

## Change

Replace the hand-written `Default` impl for `ScheduleCertificate` with derived `Default`.

## Equivalence Contract

- Inputs covered: all `ScheduleCertificate::default()` construction paths.
- Hash state preserved: default hash starts at `0`.
- Decision count preserved: default decision count starts at `0`.
- Divergence state preserved: default divergence step starts as `None`.
- Error semantics: unchanged; construction remains infallible.
- Laziness: unchanged; construction only initializes scalar fields.
- Short-circuit eval: not applicable.
- Floating-point: not applicable.
- RNG/hash order: not applicable; the running certificate hash starts from the same scalar seed.
- Observable side-effects: unchanged; construction performs no I/O, logging, tracing, wake registration, or time reads.
- Rust type behavior: `ScheduleCertificate` already implemented `Default`; this preserves the trait and its value.

## Proof Notes

- The removed `Default` implementation delegates to `ScheduleCertificate::new()`.
- `ScheduleCertificate::new()` initializes `hash` to `0`, `decisions` to `0`, and `divergence_step` to `None`.
- Derived `Default` initializes `u64` fields to `0` and `Option<u64>` to `None`.
- `ScheduleCertificate::new()` and all recording/divergence methods remain unchanged.

## Verification Results

- `rustfmt --edition 2024 --check src/runtime/scheduler/priority.rs`: passed.
- `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-check -p asupersync --lib`: passed.
- `rch exec -- cargo test --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-test -p asupersync --lib runtime::scheduler::priority::tests::certificate_empty`: passed, `1 passed; 0 failed; 14558 filtered out`.
- `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-schedule-cert-default-1450-clippy -p asupersync --lib -- -D warnings`: passed.

## Fresh-Eyes Review

- Re-read the source diff after validation: the only source change is adding `Default` to the derive list and removing the manual `Default` impl.
- Re-checked the field defaults: `u64::default()` is `0`; `Option::<u64>::default()` is `None`.
- Re-checked behavior after construction: `ScheduleCertificate::new()`, `record`, `matches`, `mark_divergence`, and `divergence_step` are unchanged.
- Conclusion: default construction remains isomorphic.
