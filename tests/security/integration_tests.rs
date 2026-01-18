use asupersync::security::{AuthKey, AuthMode, AuthenticatedSymbol, SecurityContext};
use asupersync::types::Symbol;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(42, 0, 0, data)
}

#[test]
fn roundtrip_sign_then_verify_with_shared_key() {
    let key = AuthKey::from_seed(77);
    let sender = SecurityContext::new(key);
    let receiver = SecurityContext::new(key);

    let symbol = symbol_with(&[10, 20, 30]);
    let signed = sender.sign_symbol(&symbol);

    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());
    receiver
        .verify_authenticated_symbol(&mut received)
        .expect("verification should succeed");

    assert!(received.is_verified());
}

#[test]
fn tampered_symbol_fails_in_strict_mode() {
    let key = AuthKey::from_seed(77);
    let sender = SecurityContext::new(key);
    let receiver = SecurityContext::new(key).with_mode(AuthMode::Strict);

    let symbol = symbol_with(&[1, 2, 3, 4]);
    let signed = sender.sign_symbol(&symbol);

    let tampered = symbol_with(&[1, 2, 3, 5]);
    let mut received = AuthenticatedSymbol::from_parts(tampered, *signed.tag());

    let result = receiver.verify_authenticated_symbol(&mut received);
    assert!(result.is_err());
    assert!(!received.is_verified());
}

#[test]
fn tampered_symbol_allowed_in_permissive_mode() {
    let key = AuthKey::from_seed(77);
    let sender = SecurityContext::new(key);
    let receiver = SecurityContext::new(key).with_mode(AuthMode::Permissive);

    let symbol = symbol_with(&[1, 2, 3, 4]);
    let signed = sender.sign_symbol(&symbol);

    let tampered = symbol_with(&[1, 2, 3, 5]);
    let mut received = AuthenticatedSymbol::from_parts(tampered, *signed.tag());

    let result = receiver.verify_authenticated_symbol(&mut received);
    assert!(result.is_ok());
    assert!(!received.is_verified());
}
