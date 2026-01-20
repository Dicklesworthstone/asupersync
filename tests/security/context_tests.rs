use crate::common::*;
use asupersync::security::{AuthMode, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::Symbol;
use std::sync::atomic::Ordering;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn sign_increments_signed_counter() {
    init_test_logging();
    test_phase!("sign_increments_signed_counter");
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let _ = ctx.sign_symbol(&symbol);

    let signed = ctx.stats().signed.load(Ordering::Relaxed);
    assert_with_log!(signed == 1, "signed counter should increment", 1, signed);
    test_complete!("sign_increments_signed_counter");
}

#[test]
fn verify_success_marks_verified_and_counts() {
    init_test_logging();
    test_phase!("verify_success_marks_verified_and_counts");
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let signed = ctx.sign_symbol(&symbol);
    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());

    let verified_before = received.is_verified();
    assert_with_log!(
        !verified_before,
        "symbol should start unverified",
        false,
        verified_before
    );
    ctx.verify_authenticated_symbol(&mut received)
        .expect("verification should succeed");

    let verified_after = received.is_verified();
    assert_with_log!(
        verified_after,
        "symbol should be verified",
        true,
        verified_after
    );
    let verified_ok = ctx.stats().verified_ok.load(Ordering::Relaxed);
    assert_with_log!(
        verified_ok == 1,
        "verified_ok counter should increment",
        1,
        verified_ok
    );
    test_complete!("verify_success_marks_verified_and_counts");
}

#[test]
fn strict_mode_rejects_invalid_tag() {
    init_test_logging();
    test_phase!("strict_mode_rejects_invalid_tag");
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Strict);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_err(),
        "strict mode should reject",
        true,
        result.is_err()
    );
    let verified = auth.is_verified();
    assert_with_log!(!verified, "auth should remain unverified", false, verified);
    let verified_fail = ctx.stats().verified_fail.load(Ordering::Relaxed);
    assert_with_log!(
        verified_fail == 1,
        "verified_fail counter should increment",
        1,
        verified_fail
    );
    test_complete!("strict_mode_rejects_invalid_tag");
}

#[test]
fn permissive_mode_allows_invalid_tag() {
    init_test_logging();
    test_phase!("permissive_mode_allows_invalid_tag");
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Permissive);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_ok(),
        "permissive mode should allow",
        true,
        result.is_ok()
    );
    let verified = auth.is_verified();
    assert_with_log!(!verified, "auth should remain unverified", false, verified);
    let verified_fail = ctx.stats().verified_fail.load(Ordering::Relaxed);
    assert_with_log!(
        verified_fail == 1,
        "verified_fail counter should increment",
        1,
        verified_fail
    );
    let failures_allowed = ctx.stats().failures_allowed.load(Ordering::Relaxed);
    assert_with_log!(
        failures_allowed == 1,
        "failures_allowed counter should increment",
        1,
        failures_allowed
    );
    test_complete!("permissive_mode_allows_invalid_tag");
}

#[test]
fn disabled_mode_skips_verification() {
    init_test_logging();
    test_phase!("disabled_mode_skips_verification");
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Disabled);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_ok(),
        "disabled mode should allow",
        true,
        result.is_ok()
    );
    let verified = auth.is_verified();
    assert_with_log!(!verified, "auth should remain unverified", false, verified);
    let skipped = ctx.stats().skipped.load(Ordering::Relaxed);
    assert_with_log!(skipped == 1, "skipped counter should increment", 1, skipped);
    test_complete!("disabled_mode_skips_verification");
}

#[test]
fn default_mode_is_strict() {
    init_test_logging();
    test_phase!("default_mode_is_strict");
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_err(),
        "default mode should be strict",
        true,
        result.is_err()
    );
    let verified = auth.is_verified();
    assert_with_log!(!verified, "auth should remain unverified", false, verified);
    test_complete!("default_mode_is_strict");
}

#[test]
fn derive_context_resets_stats_and_changes_tag() {
    init_test_logging();
    test_phase!("derive_context_resets_stats_and_changes_tag");
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let signed = ctx.sign_symbol(&symbol);
    let signed_count = ctx.stats().signed.load(Ordering::Relaxed);
    assert_with_log!(
        signed_count == 1,
        "signed counter should increment",
        1,
        signed_count
    );

    let derived = ctx.derive_context(b"child");
    let derived_signed = derived.stats().signed.load(Ordering::Relaxed);
    assert_with_log!(
        derived_signed == 0,
        "derived context should reset signed counter",
        0,
        derived_signed
    );

    let derived_signed = derived.sign_symbol(&symbol);
    let derived_signed_count = derived.stats().signed.load(Ordering::Relaxed);
    assert_with_log!(
        derived_signed_count == 1,
        "derived signed counter should increment",
        1,
        derived_signed_count
    );

    let same_tag = signed.tag() == derived_signed.tag();
    assert_with_log!(!same_tag, "derived tag should differ", false, same_tag);
    test_complete!("derive_context_resets_stats_and_changes_tag");
}

#[test]
fn derived_context_inherits_mode() {
    init_test_logging();
    test_phase!("derived_context_inherits_mode");
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Permissive);
    let derived = ctx.derive_context(b"child");
    let symbol = symbol_with(&[9, 9, 9]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = derived.verify_authenticated_symbol(&mut auth);

    assert_with_log!(
        result.is_ok(),
        "derived context should allow",
        true,
        result.is_ok()
    );
    let verified_fail = derived.stats().verified_fail.load(Ordering::Relaxed);
    assert_with_log!(
        verified_fail == 1,
        "verified_fail counter should increment",
        1,
        verified_fail
    );
    let failures_allowed = derived.stats().failures_allowed.load(Ordering::Relaxed);
    assert_with_log!(
        failures_allowed == 1,
        "failures_allowed counter should increment",
        1,
        failures_allowed
    );
    test_complete!("derived_context_inherits_mode");
}
