//! br-asupersync-snv902: TLS 1.3 0-RTT early-data replay protection is
//! enforced **fail-closed at acceptor build time**.
//!
//! Per-request enforcement (`EarlyDataReplayProtection::
//! validate_request_for_early_data`) is not yet wired into the server request
//! pipeline (h1/h2/h3) and `TlsStream` exposes no early-data signal, so
//! enabling 0-RTT for a strategy that needs per-request screening would be a
//! phantom control — captured 0-RTT requests would be replayed and processed
//! with no replay check. Until enforcement is wired, `build()` REFUSES to
//! enable 0-RTT for `SafeMethodsOnly` / `IdempotencyKeys` / `NonceValidation`
//! (and, per the pre-existing `ycuuwy` gate, for `None`). The only way to put
//! 0-RTT on the wire is the explicit `UnprotectedForTesting` acknowledgment.
//!
//! Public-API integration test: compiles the library with `cfg(test)` OFF, so
//! it verifies the deployed posture through the same surface operators use and
//! is immune to unrelated in-crate `#[cfg(test)]` churn.

#![cfg(feature = "tls")]

use asupersync::tls::{
    CertificateChain, EarlyDataReplayProtection, PrivateKey, TlsAcceptorBuilder,
};

// Self-signed localhost test cert/key (valid until 2027), shared with the TLS
// conformance suite.
const TEST_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUILC2ZkjRHPrfcHhzefebjS2lOzcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEyODIyMzkwMVoXDTI3MDEy
ODIyMzkwMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA8X9QR91omFIGbziPFqHCIt5sL5BTpMBYTLL6IU1Aalr6
so9aB1JLpWphzYXQ/rUBCSviBv5yrSL0LD7x6hw3G83zqNeqCGZXTKIgv4pkk6cu
KKtdfYcAuV1uTid1w31fknoywq5uRWdxkEl1r93f6xiwjW6Zw3bj2LCKFxiJdKht
T8kgOJwr33B2XduCw5auo3rG2+bzc/jXOVvyaev4mHLM0mjRLqScpIZ2npF5+YQz
MksNjNivQWK6TIqeTk2JSqqWUlxW8JgOg+5J9a7cZLaUUnBYPkMyV9ILxkLQIION
OXfum2roBWuV7vHGYK4aVWEWxGoYTt7ICZWWVXesRQIDAQABo1MwUTAdBgNVHQ4E
FgQU0j96nz+0aCyjZu9FVEIAQlDYAcwwHwYDVR0jBBgwFoAU0j96nz+0aCyjZu9F
VEIAQlDYAcwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQvah
cGeykFFXCARLWF9TpXWaRdjRf3r9+eMli6SQcsvrl0OzkLZ2qwLALXed73onhnbT
XZ8FjFINtbcRjUIbi2qIf6iOn2+DLTCJjZfFxGEDtXVlBBx1TjaJz6j/oIAgPEWg
2DLGS7tTbvKyB1LAGHTIEyKfEN6PZlYCEXNHp+Moz+zzAy96GHRd/yOZunJ2fYuu
EiKoSldjL6VzfrQPcMBv0uHCUDGBeB3VcMhCkdxdz/w2vQNZD813iF1R1yhlITv9
wwAjs13JGIDbcjI4zLsz9cPltIHkicvVm35hdJy6ALlJCe3rcOjb36QFodU7K4tw
uWkd54q5y+R18MtvvQ==
-----END CERTIFICATE-----";

const TEST_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDxf1BH3WiYUgZv
OI8WocIi3mwvkFOkwFhMsvohTUBqWvqyj1oHUkulamHNhdD+tQEJK+IG/nKtIvQs
PvHqHDcbzfOo16oIZldMoiC/imSTpy4oq119hwC5XW5OJ3XDfV+SejLCrm5FZ3GQ
SXWv3d/rGLCNbpnDduPYsIoXGIl0qG1PySA4nCvfcHZd24LDlq6jesbb5vNz+Nc5
W/Jp6/iYcszSaNEupJykhnaekXn5hDMySw2M2K9BYrpMip5OTYlKqpZSXFbwmA6D
7kn1rtxktpRScFg+QzJX0gvGQtAgg405d+6baugFa5Xu8cZgrhpVYRbEahhO3sgJ
lZZVd6xFAgMBAAECggEAHqLiElvaOwic3Fs2e86FjFrfKqGKmunzybci2Dquo09r
Yl+hMjCUfCWkxqflPYrE2N8CS5TYA3Lduwc5NVPjAdn8wTyqy2oARS6ELQhnffvF
dU9YCuanhtx9c9i5rdUn3LM34U6zmoZm98D59xeUooR9UVPomc1pVkH/IrLwLSY5
sYTzPIWTWqezSl+JcOBauXdwY6ynQJYTlWtxDeFM3TiTMiKiMT7SIECW5gqlxLLV
uhWRgZd5CqgewvZJ+P5CsFsLih7vdDccja/nuEj7zuW4uC0NdyS3uqHlrM+YxqnR
f9KdzJ4KFK9JUHv57Q+KHMs6cPeR5ixdwyuwcLNz+QKBgQD51uuZCZjFxlbcG5nK
EwfQetX7SUemR/OkuQqBxAAbj038dHMJxjhdML95ZxAR+jzpobqO+rGpZsRi+ErS
/B0aEIbO3LlV26xIAJOKiQv6bgIhqBpWDM6K/ayIGaDI49xK4DdDCvHg1YV/tLQ+
YcLX34226EtOZt97ak2YOCct9wKBgQD3c7vxLxyHSLuRNDC69J0LTfU6FGgn/9MQ
RtRphoDPOaB1ojL7cvvg47aC1QxnlhOLbhmHZzLzUESCdyJj8g0Yf9wZkz5UTmwH
ZZiInBhRfnKwb6eOKj6uJXFvwuMCy4HflK0w2nBSyeAdAjjG1wec+hB8+4b10p6t
gZ17TOvYowKBgQDNE6iSFzmK5jJ4PEOxhot8isfIm68vg5Iv3SANwnggJzJpjqC7
HjU38YLKQVoEl7aWRAXhxVA98Dg10P+CTiYJNhWiCbYsDsRM2gRBzBrD9rbTL6xm
g96qYm3Tzc2X+MnjwEY8RuiimEIbwJXPOun3zu4BfI4MDg9Vu71zvGwUowKBgQDW
6pXZK+nDNdBylLmeJsYfA15xSzgLRY2zHVFvNXq6gHp0sKNG8N8Cu8PQbemQLjBb
cQyLJX6DBLv79CzSUXA+Tw6Cx/fikRoScpLAU5JrdT93LgKA3wABkFOtlb5Etyvd
W+vv+kiEHwGfMEbPrALYu/eGFY9qAbv/RgvZAz3zsQKBgBgiHqIb6EYoD8vcRyBz
qP4j9OjdFe5BIjpj4GcEhTO02cWe40bWQ5Ut7zj2C7IdaUdCVQjg8k9FzeDrikK7
XDJ6t6uzuOdQSZwBxiZ9npt3GBzqLI3qiWhTMaD1+4ca3/SBUwPcGBbqPovdpKEv
W7n9v0wIyo4e/O0DO2fczXZD
-----END PRIVATE KEY-----";

fn builder() -> TlsAcceptorBuilder {
    let chain = CertificateChain::from_pem(TEST_CERT_PEM).expect("test cert parses");
    let key = PrivateKey::from_pem(TEST_KEY_PEM).expect("test key parses");
    TlsAcceptorBuilder::new(chain, key)
}

#[test]
fn zero_rtt_with_safe_methods_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::SafeMethodsOnly)
        .enable_early_data_with_protection(16384)
        .build();
    assert!(
        result.is_err(),
        "0-RTT with SafeMethodsOnly must fail closed until per-request enforcement \
         is wired (asupersync-snv902): {result:?}"
    );
}

#[test]
fn zero_rtt_with_idempotency_keys_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::IdempotencyKeys)
        .enable_early_data_with_protection(8192)
        .build();
    assert!(
        result.is_err(),
        "0-RTT with IdempotencyKeys must fail closed (asupersync-snv902): {result:?}"
    );
}

#[test]
fn zero_rtt_with_nonce_validation_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::NonceValidation)
        .enable_early_data_with_protection(32768)
        .build();
    assert!(
        result.is_err(),
        "0-RTT with NonceValidation must fail closed (asupersync-snv902): {result:?}"
    );
}

#[test]
fn zero_rtt_with_none_strategy_fails_closed() {
    // Pre-existing ycuuwy gate: 0-RTT without any strategy is rejected.
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::None)
        .enable_early_data_with_protection(16384)
        .build();
    assert!(
        result.is_err(),
        "0-RTT with None must fail closed (asupersync-ycuuwy): {result:?}"
    );
}

#[test]
fn zero_rtt_unprotected_for_testing_is_the_only_build_path() {
    // The explicit no-protection acknowledgment is the only way to actually
    // put 0-RTT on the wire; it builds successfully (and logs a loud warning).
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::UnprotectedForTesting)
        .enable_early_data_with_protection(16384)
        .build();
    assert!(
        result.is_ok(),
        "UnprotectedForTesting is the explicit 0-RTT opt-in and must build: {result:?}"
    );
}

#[test]
fn default_acceptor_builds_with_zero_rtt_disabled() {
    // 0-RTT is off by default; no replay strategy is required and build succeeds.
    let result = builder().build();
    assert!(
        result.is_ok(),
        "default acceptor (0-RTT disabled) must build: {result:?}"
    );
}
