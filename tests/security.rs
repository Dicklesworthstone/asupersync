#![allow(missing_docs)]

#[macro_use]
mod common;

#[path = "security/authenticated_tests.rs"]
mod authenticated_tests;
#[path = "security/context_tests.rs"]
mod context_tests;
#[path = "security/integration_tests.rs"]
mod integration_tests;
#[path = "security/key_tests.rs"]
mod key_tests;
#[path = "security/property_tests.rs"]
mod property_tests;
#[path = "security/tag_tests.rs"]
mod tag_tests;

use asupersync::security::{
    AuthKey, AuthMode, AuthenticatedSymbol, AuthenticationTag, SecurityContext,
};
use asupersync::types::Symbol;
use std::sync::atomic::Ordering;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

fn init_security_test(name: &str) {
    common::init_test_logging();
    test_phase!(name);
}

#[test]
fn security_sign_marks_verified_and_tag_nonzero() {
    init_security_test("security_sign_marks_verified_and_tag_nonzero");
    let ctx = SecurityContext::for_testing(42);
    let symbol = symbol_with(&[1, 2, 3]);

    let auth = ctx.sign_symbol(&symbol);

    assert_with_log!(
        auth.is_verified(),
        "symbol should be verified",
        true,
        auth.is_verified()
    );
    let nonzero = auth.tag() != &AuthenticationTag::zero();
    assert_with_log!(nonzero, "tag should be non-zero", true, nonzero);
    test_complete!("security_sign_marks_verified_and_tag_nonzero");
}

#[test]
fn security_sign_increments_signed_counter() {
    init_security_test("security_sign_increments_signed_counter");
    let ctx = SecurityContext::for_testing(7);
    let symbol = symbol_with(&[4, 5, 6]);

    let _ = ctx.sign_symbol(&symbol);
    let signed = ctx.stats().signed.load(Ordering::Relaxed);

    assert_with_log!(signed == 1, "signed counter increments", 1, signed);
    test_complete!("security_sign_increments_signed_counter");
}

#[test]
fn security_verify_valid_tag_sets_verified_and_counts() {
    init_security_test("security_verify_valid_tag_sets_verified_and_counts");
    let ctx = SecurityContext::for_testing(11);
    let symbol = symbol_with(&[9, 8, 7]);
    let signed = ctx.sign_symbol(&symbol);
    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());

    let verified_before = received.is_verified();
    assert_with_log!(
        !verified_before,
        "received should start unverified",
        false,
        verified_before
    );
    ctx.verify_authenticated_symbol(&mut received)
        .expect("verification succeeds");
    let verified_after = received.is_verified();
    assert_with_log!(
        verified_after,
        "received should be verified",
        true,
        verified_after
    );
    let verified_ok = ctx.stats().verified_ok.load(Ordering::Relaxed);
    assert_with_log!(verified_ok == 1, "verified_ok increments", 1, verified_ok);
    test_complete!("security_verify_valid_tag_sets_verified_and_counts");
}

#[test]
fn security_verify_invalid_tag_strict_errors_and_counts() {
    init_security_test("security_verify_invalid_tag_strict_errors_and_counts");
    let ctx = SecurityContext::for_testing(13).with_mode(AuthMode::Strict);
    let symbol = symbol_with(&[1, 1, 1]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);
    let err_is_invalid = matches!(result.as_ref(), Err(err) if err.is_invalid_tag());

    assert_with_log!(
        result.is_err(),
        "strict should error",
        true,
        result.is_err()
    );
    assert_with_log!(
        err_is_invalid,
        "error should be invalid tag",
        true,
        err_is_invalid
    );
    let verified_fail = ctx.stats().verified_fail.load(Ordering::Relaxed);
    assert_with_log!(
        verified_fail == 1,
        "verified_fail increments",
        1,
        verified_fail
    );
    test_complete!("security_verify_invalid_tag_strict_errors_and_counts");
}

#[test]
fn security_verify_invalid_tag_permissive_allows_and_counts() {
    init_security_test("security_verify_invalid_tag_permissive_allows_and_counts");
    let ctx = SecurityContext::for_testing(17).with_mode(AuthMode::Permissive);
    let symbol = symbol_with(&[2, 2, 2]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);
    let verified = auth.is_verified();

    assert_with_log!(
        result.is_ok(),
        "permissive should allow",
        true,
        result.is_ok()
    );
    assert_with_log!(!verified, "symbol stays unverified", false, verified);
    let failures_allowed = ctx.stats().failures_allowed.load(Ordering::Relaxed);
    assert_with_log!(
        failures_allowed == 1,
        "failures_allowed increments",
        1,
        failures_allowed
    );
    test_complete!("security_verify_invalid_tag_permissive_allows_and_counts");
}

#[test]
fn security_verify_invalid_tag_disabled_skips() {
    init_security_test("security_verify_invalid_tag_disabled_skips");
    let ctx = SecurityContext::for_testing(19).with_mode(AuthMode::Disabled);
    let symbol = symbol_with(&[3, 3, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);
    let skipped = ctx.stats().skipped.load(Ordering::Relaxed);

    assert_with_log!(
        result.is_ok(),
        "disabled should allow",
        true,
        result.is_ok()
    );
    assert_with_log!(skipped == 1, "skipped increments", 1, skipped);
    test_complete!("security_verify_invalid_tag_disabled_skips");
}

#[test]
fn security_tag_deterministic_for_same_symbol() {
    init_security_test("security_tag_deterministic_for_same_symbol");
    let key = AuthKey::from_seed(23);
    let symbol = symbol_with(&[9, 9, 9]);

    let tag1 = AuthenticationTag::compute(&key, &symbol);
    let tag2 = AuthenticationTag::compute(&key, &symbol);

    assert_with_log!(tag1 == tag2, "tags should match", tag1, tag2);
    test_complete!("security_tag_deterministic_for_same_symbol");
}

#[test]
fn security_tag_verification_fails_for_tampered_symbol() {
    init_security_test("security_tag_verification_fails_for_tampered_symbol");
    let key = AuthKey::from_seed(31);
    let mut symbol = symbol_with(&[4, 4, 4]);
    let tag = AuthenticationTag::compute(&key, &symbol);

    symbol.data_mut()[0] ^= 0xFF;
    let ok = tag.verify(&key, &symbol);

    assert_with_log!(!ok, "tampered symbol should fail", false, ok);
    test_complete!("security_tag_verification_fails_for_tampered_symbol");
}

#[test]
fn security_derive_context_changes_tag() {
    init_security_test("security_derive_context_changes_tag");
    let ctx = SecurityContext::for_testing(37);
    let derived = ctx.derive_context(b"child");
    let symbol = symbol_with(&[5, 5, 5]);

    let tag_parent = ctx.sign_symbol(&symbol).tag().to_owned();
    let tag_child = derived.sign_symbol(&symbol).tag().to_owned();

    assert_with_log!(
        tag_parent != tag_child,
        "tags should differ",
        tag_parent,
        tag_child
    );
    test_complete!("security_derive_context_changes_tag");
}

#[test]
fn security_derive_context_inherits_mode() {
    init_security_test("security_derive_context_inherits_mode");
    let ctx = SecurityContext::for_testing(41).with_mode(AuthMode::Permissive);
    let derived = ctx.derive_context(b"inherit");
    let symbol = symbol_with(&[6, 6, 6]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = derived.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_ok(),
        "derived should inherit permissive",
        true,
        result.is_ok()
    );
    test_complete!("security_derive_context_inherits_mode");
}
