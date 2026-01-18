use asupersync::security::{AuthenticatedSymbol, AuthenticationTag};
use asupersync::types::Symbol;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn new_verified_marks_verified() {
    let symbol = symbol_with(&[1, 2]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    assert!(auth.is_verified());
    assert_eq!(auth.symbol(), &symbol);
    assert_eq!(auth.tag(), &tag);
}

#[test]
fn from_parts_starts_unverified() {
    let symbol = symbol_with(&[1, 2]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::from_parts(symbol, tag);
    assert!(!auth.is_verified());
}

#[test]
fn into_symbol_discards_tag_and_status() {
    let symbol = symbol_with(&[1, 2, 3]);
    let tag = AuthenticationTag::zero();

    let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
    let unwrapped = auth.into_symbol();

    assert_eq!(unwrapped, symbol);
}
