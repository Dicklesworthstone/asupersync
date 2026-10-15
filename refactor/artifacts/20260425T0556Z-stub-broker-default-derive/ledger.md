# Refactor Ledger: `StubBroker` Default Derive

## Scope

- Source: `src/messaging/kafka.rs`
- Artifact directory:
  `refactor/artifacts/20260425T0556Z-stub-broker-default-derive/`

## Line Delta

- Source lines before: 2813
- Source lines after: 2803
- Source reduction: 10 lines

## Proof Summary

The removed constructor delegated entirely to default constructors for the
broker state and notify primitive. Derived `Default` performs the same
field-by-field initialization while leaving feature gating and broker access
unchanged.

## Verification

- Passed: `rustfmt --edition 2024 --check src/messaging/kafka.rs`
- Passed: `rch exec -- cargo check -p asupersync --lib`
- Passed: `rch exec -- cargo clippy -p asupersync --lib -- -D warnings`

## Fresh-Eyes Review

- Verified that `StubBroker` is private and remains behind
  `#[cfg(not(feature = "kafka"))]`.
- Verified that `StubBrokerState` already derives `Default`.
- Verified that `Notify::default()` delegates directly to `Notify::new()`.
- Verified that `stub_broker()` still initializes `STUB_BROKER` with
  `StubBroker::default`.
