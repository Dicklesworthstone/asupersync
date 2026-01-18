use asupersync::security::{AuthMode, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::Symbol;
use std::sync::atomic::Ordering;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn sign_increments_signed_counter() {
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let _ = ctx.sign_symbol(&symbol);

    assert_eq!(ctx.stats().signed.load(Ordering::Relaxed), 1);
}

#[test]
fn verify_success_marks_verified_and_counts() {
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let signed = ctx.sign_symbol(&symbol);
    let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());

    assert!(!received.is_verified());
    ctx.verify_authenticated_symbol(&mut received)
        .expect("verification should succeed");

    assert!(received.is_verified());
    assert_eq!(ctx.stats().verified_ok.load(Ordering::Relaxed), 1);
}

#[test]
fn strict_mode_rejects_invalid_tag() {
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Strict);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert!(result.is_err());
    assert!(!auth.is_verified());
    assert_eq!(ctx.stats().verified_fail.load(Ordering::Relaxed), 1);
}

#[test]
fn permissive_mode_allows_invalid_tag() {
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Permissive);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert!(result.is_ok());
    assert!(!auth.is_verified());
    assert_eq!(ctx.stats().verified_fail.load(Ordering::Relaxed), 1);
    assert_eq!(ctx.stats().failures_allowed.load(Ordering::Relaxed), 1);
}

#[test]
fn disabled_mode_skips_verification() {
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Disabled);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert!(result.is_ok());
    assert!(!auth.is_verified());
    assert_eq!(ctx.stats().skipped.load(Ordering::Relaxed), 1);
}

#[test]
fn default_mode_is_strict() {
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = ctx.verify_authenticated_symbol(&mut auth);

    assert!(result.is_err());
    assert!(!auth.is_verified());
}

#[test]
fn derive_context_resets_stats_and_changes_tag() {
    let ctx = SecurityContext::for_testing(1);
    let symbol = symbol_with(&[1, 2, 3]);

    let signed = ctx.sign_symbol(&symbol);
    assert_eq!(ctx.stats().signed.load(Ordering::Relaxed), 1);

    let derived = ctx.derive_context(b"child");
    assert_eq!(derived.stats().signed.load(Ordering::Relaxed), 0);

    let derived_signed = derived.sign_symbol(&symbol);
    assert_eq!(derived.stats().signed.load(Ordering::Relaxed), 1);

    assert_ne!(signed.tag(), derived_signed.tag());
}

#[test]
fn derived_context_inherits_mode() {
    let ctx = SecurityContext::for_testing(1).with_mode(AuthMode::Permissive);
    let derived = ctx.derive_context(b"child");
    let symbol = symbol_with(&[9, 9, 9]);
    let mut auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

    let result = derived.verify_authenticated_symbol(&mut auth);

    assert!(result.is_ok());
    assert_eq!(derived.stats().verified_fail.load(Ordering::Relaxed), 1);
    assert_eq!(derived.stats().failures_allowed.load(Ordering::Relaxed), 1);
}
