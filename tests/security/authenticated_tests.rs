use crate::common::*;
use asupersync::security::{AuthenticatedSymbol, AuthenticationTag};
use asupersync::types::Symbol;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn new_verified_marks_verified() {
    init_test_logging();
    test_phase!("new_verified_marks_verified");
    let symbol = symbol_with(&[1, 2]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let verified = auth.is_verified();
    assert_with_log!(verified, "symbol should be verified", true, verified);
    assert_with_log!(
        auth.symbol() == &symbol,
        "symbol should match",
        &symbol,
        auth.symbol()
    );
    assert_with_log!(auth.tag() == &tag, "tag should match", &tag, auth.tag());
    test_complete!("new_verified_marks_verified");
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
fn into_symbol_discards_tag_and_status() {
    init_test_logging();
    test_phase!("into_symbol_discards_tag_and_status");
    let symbol = symbol_with(&[1, 2, 3]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let unwrapped = auth.into_symbol();

    assert_with_log!(
        unwrapped == symbol,
        "unwrapped symbol should match",
        symbol,
        unwrapped
    );
    test_complete!("into_symbol_discards_tag_and_status");
}
