# Refactor Ledger: TLS Empty Constructor Delegation

## Scope

- Source: `src/tls/types.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0652Z-certificate-chain-default/`

## Line Delta

- Source lines before: 934
- Source lines after: 933
- Source reduction: 1 line

## Proof Summary

`CertificateChain` already derives `Default`; its manual constructor duplicated
the single-field empty-vector default. `CertificatePinSet::new()` and
`CertificatePinSet::report_only()` also duplicated empty-pin-set construction
and differed only in enforcement mode. Delegating both through explicit empty
constructor paths preserves public behavior while removing duplicate
initialization. The PEM chain constructors now use `Result::map(Self::from)`,
which keeps success and error semantics identical to the previous `?` plus
`Ok(Self::from(...))` shape.

## Verification

- Passed: `rustfmt --edition 2024 --check src/tls/types.rs`
- Passed: `rch exec -- cargo check --target-dir /tmp/cargo-target-asupersync-tls-types-0652-check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy --target-dir /tmp/cargo-target-asupersync-tls-types-0652-clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `CertificateChain` still derives `Default`.
- Verified that `Vec<Certificate>::default()` is equivalent to `Vec::new()`.
- Verified that `Result::map(Self::from)` preserves the same successful chain
  conversion and propagates the same `TlsError` unchanged.
- Verified that `CertificatePinSet::new()` still uses `enforce = true`.
- Verified that `CertificatePinSet::report_only()` still uses
  `enforce = false`.
- Verified that TLS and non-TLS feature-gated parsing paths are unchanged.
