//! br-asupersync-b1fojq: regression proof that the default RaptorQ decode
//! configuration is **fail-closed** (per-symbol authentication required) and
//! that the insecure no-auth path is an explicit, deliberate opt-out.
//!
//! This is a public-API integration test, so it compiles the library with
//! `cfg(test)` OFF — it is immune to unrelated in-crate `#[cfg(test)]` churn —
//! and verifies the security posture through the same surface real callers use.
//!
//! Pre-fix `DecodingConfig::default()` set `verify_auth: false`, so a
//! default-config `DecodingPipeline` authenticated NOTHING and silently
//! accepted forged / unauthenticated symbols (decode-matrix poisoning).

use asupersync::decoding::{DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult};
use asupersync::net::atp::transport_rq::{RqConfig, RqError, RqSymbolAuthMode};
use asupersync::security::tag::AuthenticationTag;
use asupersync::security::{AuthenticatedSymbol, SecurityContext};
use asupersync::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};

fn unauthenticated_symbol(object_value: u64, symbol_size: u16) -> AuthenticatedSymbol {
    let symbol = Symbol::new(
        SymbolId::new(ObjectId::new_for_test(object_value), 0, 0),
        vec![0u8; usize::from(symbol_size)],
        SymbolKind::Source,
    );
    // `from_parts` produces an UNVERIFIED authenticated-symbol wrapper carrying
    // the all-zero sentinel tag — exactly what a forging peer can synthesize.
    AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero())
}

#[test]
fn default_decoding_config_is_fail_closed() {
    let secure = DecodingConfig::default();
    assert!(
        secure.verify_auth,
        "DecodingConfig::default() must be fail-closed (verify_auth=true)"
    );

    let insecure = DecodingConfig::without_auth();
    assert!(
        !insecure.verify_auth,
        "DecodingConfig::without_auth() is the explicit insecure opt-out (verify_auth=false)"
    );
}

#[test]
fn default_pipeline_rejects_unauthenticated_symbol() {
    // A pipeline built from the default config carries no SecurityContext, so
    // the fail-closed default must REJECT an unauthenticated symbol rather than
    // silently accept it.
    let mut decoder = DecodingPipeline::new(DecodingConfig::default());
    let auth = unauthenticated_symbol(7, DecodingConfig::default().symbol_size);

    let result = decoder.feed(auth).expect("feed should not error");
    assert_eq!(
        result,
        SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed),
        "default-config pipeline must reject an unauthenticated symbol"
    );
    assert_eq!(
        decoder.skipped_verifications(),
        0,
        "a rejected symbol is never counted as an auth-skipped acceptance"
    );
}

#[test]
fn without_auth_pipeline_accepts_symbol_as_explicit_opt_out() {
    // The explicit opt-out preserves the legacy erasure-only behaviour: a
    // no-auth pipeline accepts the symbol (authentication deliberately skipped)
    // and the acceptance is surfaced via `skipped_verifications()`.
    let mut decoder = DecodingPipeline::new(DecodingConfig::without_auth());
    let auth = unauthenticated_symbol(8, DecodingConfig::without_auth().symbol_size);

    let result = decoder.feed(auth).expect("feed should not error");
    assert!(
        !matches!(
            result,
            SymbolAcceptResult::Rejected(RejectReason::AuthenticationFailed)
        ),
        "without_auth() pipeline must not reject on authentication, got {result:?}"
    );
    assert_eq!(
        decoder.skipped_verifications(),
        1,
        "the accepted-without-auth symbol must be counted for operator audit"
    );
}

#[test]
fn atp_rq_config_reports_fail_closed_symbol_auth_posture() {
    let default_config = RqConfig::default();
    assert_eq!(
        default_config.symbol_auth_mode(),
        RqSymbolAuthMode::MissingAuthenticationContext,
        "ATP RaptorQ must report the fail-closed missing-auth state by default"
    );
    assert!(
        matches!(
            default_config.validate_symbol_auth_mode(),
            Err(RqError::Authentication(message)) if message.contains("symbol_auth_context")
        ),
        "default ATP RaptorQ config must reject an implicit unauthenticated symbol plane"
    );

    let trusted_lab_config = RqConfig::default().allow_unauthenticated_for_trusted_transport();
    assert_eq!(
        trusted_lab_config.symbol_auth_mode(),
        RqSymbolAuthMode::TrustedUnauthenticated,
        "trusted unauthenticated mode must be visible as an explicit opt-out"
    );
    trusted_lab_config
        .validate_symbol_auth_mode()
        .expect("trusted unauthenticated mode is deliberate");

    let authenticated_config = RqConfig::default()
        .allow_unauthenticated_for_trusted_transport()
        .with_symbol_auth(SecurityContext::for_testing(42));
    assert_eq!(
        authenticated_config.symbol_auth_mode(),
        RqSymbolAuthMode::Authenticated,
        "a configured SecurityContext must take precedence over the trusted opt-out"
    );
    authenticated_config
        .validate_symbol_auth_mode()
        .expect("configured symbol auth is valid");
}
