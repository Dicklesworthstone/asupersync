# Refactor Ledger: `TraceCertificate` Default Delegation

## Scope

- Source: `src/trace/certificate.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0658Z-trace-certificate-default/`

## Line Delta

- Source lines before: 933
- Source lines after: 921
- Source reduction: 12 lines

## Proof Summary

`TraceCertificate` already derives `Default`; its manual constructor duplicated
the derived defaults for every field. Delegating through `Self::default()`
preserves the empty-certificate state while removing repeated zero/false/none
initialization.

## Verification

- Passed: `rustfmt --edition 2024 --check src/trace/certificate.rs`
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-trace-certificate-0658-check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-trace-certificate-0658-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `TraceCertificate` still derives `Default`.
- Verified that all numeric fields are `u64`, so their derived defaults are
  `0`.
- Verified that `violation_detected` maps from `false` to `bool::default()`.
- Verified that `first_violation` maps from `None` to `Option::default()`.
- Verified that event accumulation, violation recording, hashing, and
  verification code are unchanged.
