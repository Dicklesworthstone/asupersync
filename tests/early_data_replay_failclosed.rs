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
    CertificateChain, EarlyDataReplayProtection, PrivateKey, TlsAcceptor, TlsAcceptorBuilder,
    TlsError,
};

// Self-signed localhost test cert/key (valid 2026-01-01 to 2036-01-01), shared
// with the TLS conformance suite. The previous cert expired on 2027-01-28; from
// then on build() failed certificate validation before reaching the 0-RTT gates
// (br-asupersync-kjyh84), which is why the refusal tests below assert which
// gate refused rather than just `is_err()`.
const TEST_CERT_PEM: &[u8] = br"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUYFRTlW+bpzdWqfvb/AF7dnEsU1kwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEw
MTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA44VqefSOC9LRz/tOH4Ee0ziPAvvxUg3l8xjUmY1L/bT4
vJNFW2kGBxYaBMi64RmZQVlweZ8u4kSPldJtg8UPM6ShLxuWrhIPyocTi8Gi+XdS
rcNDmGcz1VsJTw715Pp3+JnU9vxWcX59zruTT5nJSYCh49zPQeo8Co2dn2kWQHMx
wPudIaQoWXFEAFLZu4/KsLTFP34SpbrFZEm5lip7s09168aIIJn28//PR0YL/72q
OBhkjG6jGia5n7ZqNhH4zLlc4hG7ztmjTXq2xopetCDnDwBe7Ku7TqKDTIfg8YYk
8vEBqBWNgzGzB4CWCf82kLf99YikzwNpMmKIzrYxVQIDAQABo1MwUTAdBgNVHQ4E
FgQUk6j/r20V0MqXAB8JwOYEM5TTMHIwHwYDVR0jBBgwFoAUk6j/r20V0MqXAB8J
wOYEM5TTMHIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAj9FG
eRouDVKG7Zbr8Sbh9HUq0IFpyXdBZ9P7WkHT8VzjqvrwhAzzs4sFSWzFviPh15GA
F1tVSJNk3fTcCWcLtPCVpfiowKrs1KzwN+8oOKLueSvy4CRAT3mvs6CmEnd1R08F
PZFPOt2rCYcg5W209B/TuzsMfkxu23x5ChFP84n45lkzrogl7jtTgKvAX+u2Zxfz
/xLBW2+51bW7CvbROoKfviOv94dcNwiUWsFZqwI/6hzjGGNxL8hStc9C6G3wfP3j
cQZtzJcn8icW1Hlhm2G7yBwYwgwQquLFNIfTxbs/fSI30PuU+vlMpHrOMK/iwDRG
LTOhr7XjWNBgEumE9g==
-----END CERTIFICATE-----";

const TEST_KEY_PEM: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDjhWp59I4L0tHP
+04fgR7TOI8C+/FSDeXzGNSZjUv9tPi8k0VbaQYHFhoEyLrhGZlBWXB5ny7iRI+V
0m2DxQ8zpKEvG5auEg/KhxOLwaL5d1Ktw0OYZzPVWwlPDvXk+nf4mdT2/FZxfn3O
u5NPmclJgKHj3M9B6jwKjZ2faRZAczHA+50hpChZcUQAUtm7j8qwtMU/fhKlusVk
SbmWKnuzT3Xrxoggmfbz/89HRgv/vao4GGSMbqMaJrmftmo2EfjMuVziEbvO2aNN
erbGil60IOcPAF7sq7tOooNMh+DxhiTy8QGoFY2DMbMHgJYJ/zaQt/31iKTPA2ky
YojOtjFVAgMBAAECggEAMXodKEW0ESKooUmlWMkHtselI/E9bopar+V9sCGvvY2a
DMoa6lC5sJdQE6vCJfre3rzwLmadN7PQpLRUv/O9xU1/BsNBXnvLhs+egsUaZ5UY
+/QLUkxZE4PfT5uxgfis17k+PHKt6rLm8WrNk2EeSndoXSiywoMJSQM4XIbqAZwS
OXMWqd6ZaIUhXQ8jUH/2UhzrGj9HZEkrNEeu2wpgOy3F3O/dUDxaEZ+g8WjCO1qB
eV9EVSclCYgGpj9Xxk0t2R2rppZ6gahA2e4BX/0d4UZemkuzYNOXa33rbZSKD+Qn
JNvuEeTFh004/T6s34O1FjZ3UpQq38PuGcjrZwHeuQKBgQD/l9/AiI8xA5efGXgM
NB28ebmDbpXRxMxEnxe6f/krmaeEYrmx1Vw1Gpb2SjbEsDXDxKzTjKCt763uBx8M
3S8hBUadRCpOL1C25qukNithDCy8flFK2jEzqmsUAVosjkfetKycjW/GYD8Ek6Uq
n/d24KEpA1RSw8WhaxCkttJXOQKBgQDj4hsJstcWr+apBC3FNuC49Tqrqa3HIFIq
LpbJiAbxZlx3yzh9rpzJtn7YozcwbJX0YhTzd73ueL0c+ux7A7d93/wmQWzZWPtO
KQvznmnen3my4G7QTrCu1/Tdy7YVfH/cLqWzP+DM3F40mmbxWquzmbKeA+3juib3
NbIkCrfu/QKBgQCpyipJrG3zEX/XoQOul7BpVDN4rC26fBF2RHlu2zSbUieGOk9B
Y4ste8xtMD/RyXzt3+kvX2weH+pbBUALO6PjO639KxsvdR8ZYYMEQzft8DiHvyIh
p3Cn8b3QPFW644m62CsSlKJ8FdPHJo3CEyJBRlfI9v09PfA7mvQjd4+jgQKBgQCg
GzL97G3cHbgEldAGmJjoujr/ctaKafXwdw0wCOc/4bgj3l8RRoYX3qVeVcYnupLc
wbCQoleKXcAYxV8yypi30o/Y3Oy6BB+EeahRAMLHS+p4N+EDb9YI8eezkTWcAP3g
V9HJj57EsCtr7/NVrWunYtww0vfnoNlRpKNFWVaDjQKBgHFEwzGmgZjIyxyu9lXK
Vp2XuzmtsaSXOF8nxvtNc4AVraSQcYTE3bvHNUXc36KQUFgxpuJjVkvqvLhO3RJA
DI5072o3Mwp7oTd8qXfakrZkHlhn3iT3cEgaKHt9bDEczkdGcrljq3MZ8S4Bgz3t
It6qWiG3ZDpTxF0+VzavjqDm
-----END PRIVATE KEY-----";

fn builder() -> TlsAcceptorBuilder {
    let chain = CertificateChain::from_pem(TEST_CERT_PEM).expect("test cert parses");
    let key = PrivateKey::from_pem(TEST_KEY_PEM).expect("test key parses");
    TlsAcceptorBuilder::new(chain, key)
}

/// The build must be refused by the 0-RTT gate whose bead marker is `gate`,
/// not by an unrelated error such as an expired test certificate.
fn assert_refused_by(result: Result<TlsAcceptor, TlsError>, gate: &str, why: &str) {
    match result {
        Err(TlsError::Configuration(message)) => assert!(
            message.contains(gate),
            "{why}: the refusal must come from the {gate} gate, got: {message}"
        ),
        other => {
            panic!("{why}: expected a Configuration refusal from the {gate} gate, got {other:?}")
        }
    }
}

#[test]
fn zero_rtt_with_safe_methods_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::SafeMethodsOnly)
        .enable_early_data_with_protection(16384)
        .build();
    assert_refused_by(
        result,
        "asupersync-snv902",
        "0-RTT with SafeMethodsOnly must fail closed until per-request enforcement is wired",
    );
}

#[test]
fn zero_rtt_with_idempotency_keys_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::IdempotencyKeys)
        .enable_early_data_with_protection(8192)
        .build();
    assert_refused_by(
        result,
        "asupersync-snv902",
        "0-RTT with IdempotencyKeys must fail closed",
    );
}

#[test]
fn zero_rtt_with_nonce_validation_strategy_fails_closed() {
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::NonceValidation)
        .enable_early_data_with_protection(32768)
        .build();
    assert_refused_by(
        result,
        "asupersync-snv902",
        "0-RTT with NonceValidation must fail closed",
    );
}

#[test]
fn zero_rtt_with_none_strategy_fails_closed() {
    // Pre-existing ycuuwy gate: 0-RTT without any strategy is rejected.
    let result = builder()
        .with_early_data_replay_protection(EarlyDataReplayProtection::None)
        .enable_early_data_with_protection(16384)
        .build();
    assert_refused_by(
        result,
        "asupersync-ycuuwy",
        "0-RTT with None must fail closed",
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
