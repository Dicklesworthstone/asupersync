//! Regression test: a NATS user JWT carrying an EMPTY `iss` claim must be
//! rejected, not accepted without signature verification.
//!
//! `parse_nats_jwt_claims` rejected a *missing* `iss` claim, but a present-but-
//! empty one (`"iss": ""`) used to slip through: the `if !issuer_str.is_empty()`
//! guard was false, the signature-verification block was skipped, and with no
//! `else` the JWT fell through and was accepted (subject only to the expiry
//! check). An attacker could forge `{"sub":"...","iss":"","exp":<future>}` with
//! any signature and authenticate. The fix rejects both missing and empty
//! issuers (fail closed). This exercises that fix via the public fuzz wrapper.
//!
//! Gated on the features that compile the NATS surface + the test wrapper.
#![cfg(all(feature = "messaging-fabric", feature = "test-internals"))]

use asupersync::messaging::nats::fuzz_parse_nats_jwt_claims;

/// A compact JWT with `alg=ed25519-nkey`, a non-empty `sub`, an EMPTY `iss`,
/// a far-future `exp`, and an arbitrary (unverifiable) signature segment.
/// header  = {"alg":"ed25519-nkey"}
/// payload = {"sub":"UTESTSUBJECT...","iss":"","exp":9999999999}
const EMPTY_ISSUER_JWT: &str = "eyJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJzdWIiOiJVVEVTVFNVQkpFQ1RBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIiwiaXNzIjoiIiwiZXhwIjo5OTk5OTk5OTk5fQ.AAAAAAAAAAA";

#[test]
fn nats_jwt_empty_issuer_is_rejected_without_signature_bypass() {
    let result = fuzz_parse_nats_jwt_claims(EMPTY_ISSUER_JWT);
    assert!(
        result.is_err(),
        "a JWT with an empty `iss` claim must be rejected (its signature is \
         never verified), but it was accepted: {result:?}"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("issuer"),
        "rejection must cite the missing/empty issuer claim (not some other \
         parse error), got: {msg}"
    );
}
