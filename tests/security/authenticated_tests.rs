use crate::common::*;
use asupersync::security::{
    AuthenticatedSymbol, AuthenticatedSymbolState, AuthenticationTag, SecurityContext,
};
use asupersync::types::Symbol;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn sign_symbol_marks_verified() {
    init_test_logging();
    test_phase!("sign_symbol_marks_verified");
    let symbol = symbol_with(&[1, 2]);
    let ctx = SecurityContext::for_testing(7);
    let auth = ctx.sign_symbol(&symbol);
    let verified = auth.is_verified();
    assert_with_log!(verified, "symbol should be verified", true, verified);
    assert_with_log!(
        auth.symbol() == &symbol,
        "symbol should match",
        &symbol,
        auth.symbol()
    );
    test_complete!("sign_symbol_marks_verified");
}

#[test]
fn from_parts_starts_unverified() {
    init_test_logging();
    test_phase!("from_parts_starts_unverified");
    let symbol = symbol_with(&[1, 2]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::from_parts(symbol, tag);
    let verified = auth.is_verified();
    assert_with_log!(!verified, "symbol should be unverified", false, verified);
    test_complete!("from_parts_starts_unverified");
}

#[test]
fn authentication_state_distinguishes_verified_tagged_and_sentinel_symbols() {
    init_test_logging();
    test_phase!("authentication_state_distinguishes_verified_tagged_and_sentinel_symbols");
    let symbol = symbol_with(&[4, 5, 6]);
    let ctx = SecurityContext::for_testing(11);

    let signed = ctx.sign_symbol(&symbol);
    assert_with_log!(
        signed.authentication_state() == AuthenticatedSymbolState::Verified,
        "signed symbol should report verified state",
        AuthenticatedSymbolState::Verified,
        signed.authentication_state()
    );

    let mut received = AuthenticatedSymbol::from_parts(symbol.clone(), *signed.tag());
    assert_with_log!(
        received.authentication_state() == AuthenticatedSymbolState::UnverifiedTagged,
        "received non-zero tag should report unverified-tagged state before verification",
        AuthenticatedSymbolState::UnverifiedTagged,
        received.authentication_state()
    );
    ctx.verify_authenticated_symbol(&mut received)
        .expect("signed symbol verifies");
    assert_with_log!(
        received.authentication_state() == AuthenticatedSymbolState::Verified,
        "verified received symbol should report verified state",
        AuthenticatedSymbolState::Verified,
        received.authentication_state()
    );

    let sentinel = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());
    assert_with_log!(
        sentinel.authentication_state() == AuthenticatedSymbolState::UnauthenticatedSentinel,
        "zero-tag sentinel should be distinguishable from an unverified real tag",
        AuthenticatedSymbolState::UnauthenticatedSentinel,
        sentinel.authentication_state()
    );
    test_complete!("authentication_state_distinguishes_verified_tagged_and_sentinel_symbols");
}

#[test]
fn into_symbol_discards_tag_and_status() {
    init_test_logging();
    test_phase!("into_symbol_discards_tag_and_status");
    let symbol = symbol_with(&[1, 2, 3]);
    let ctx = SecurityContext::for_testing(9);
    let auth = ctx.sign_symbol(&symbol);
    let unwrapped = auth.into_symbol();

    assert_with_log!(
        unwrapped == symbol,
        "unwrapped symbol should match",
        symbol,
        unwrapped
    );
    test_complete!("into_symbol_discards_tag_and_status");
}
