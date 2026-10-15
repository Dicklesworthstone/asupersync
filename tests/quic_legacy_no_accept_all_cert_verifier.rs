//! Re-introduction guard for br-asupersync-1tlabl.
//!
//! `src/net/quic/` is the parked legacy QUIC wrapper: the live `net::quic` API
//! is an inline type-alias module in `src/net/mod.rs` pointing at the
//! fail-closed `src/net/quic_native/` stack, so the legacy directory is NOT
//! wired into the crate root (uncompiled). It previously shipped a
//! `SkipServerVerification` rustls `ServerCertVerifier` whose
//! `verify_server_cert`/`verify_tls{12,13}_signature` returned
//! `…assertion()` unconditionally — an accept-all verifier. Even though the
//! directory is uncompiled today, leaving an accept-all verifier in-tree is a
//! latent MITM footgun: re-wiring the module (inline `pub mod quic { … }` →
//! file-based `mod quic;`) would make it the live client verifier.
//!
//! This test reads the source as text (so it does not depend on the legacy
//! directory being compiled) and fails closed if an accept-all certificate
//! verifier reappears in `src/net/quic/endpoint.rs`. The production QUIC path
//! (`quic_native`) is independently fail-closed (br-asupersync-7pwwwe).

/// Source of the legacy QUIC endpoint, embedded at compile time.
const LEGACY_QUIC_ENDPOINT_SRC: &str = include_str!("../src/net/quic/endpoint.rs");

#[test]
fn legacy_quic_endpoint_has_no_accept_all_cert_verifier() {
    // Each of these is a hallmark of an accept-all (always-valid) rustls
    // certificate/signature verifier. None may appear in this file.
    let forbidden = [
        "SkipServerVerification",
        "ServerCertVerified::assertion(",
        "HandshakeSignatureValid::assertion(",
    ];
    for pat in forbidden {
        assert!(
            !LEGACY_QUIC_ENDPOINT_SRC.contains(pat),
            "src/net/quic/endpoint.rs must not contain `{pat}`: an accept-all \
             certificate verifier is a latent MITM footgun even in the orphaned \
             legacy wrapper (br-asupersync-1tlabl). Use real root verification \
             (with_root_certificates) and fail closed on insecure_skip_verify."
        );
    }

    // Positive assertion that the fail-closed posture is present, so this guard
    // cannot pass merely because the file was gutted.
    assert!(
        LEGACY_QUIC_ENDPOINT_SRC.contains("with_root_certificates"),
        "legacy QUIC client config must verify against real roots \
         (with_root_certificates)"
    );
    assert!(
        LEGACY_QUIC_ENDPOINT_SRC.contains("insecure_skip_verify is disabled"),
        "legacy QUIC client must fail closed on insecure_skip_verify"
    );
}
