    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::security::AuthKey;
    use crate::types::{SymbolId, SymbolKind};

    fn real_tag(symbol: &Symbol) -> AuthenticationTag {
        let key = AuthKey::from_seed(0xDEADBEEF);
        AuthenticationTag::compute(&key, symbol)
    }

    #[test]
    fn test_new_verified() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![], SymbolKind::Source);
        // br-asupersync-srqosl: a real (non-zero) tag is required to
        // observe `verified = true` from `new_verified`. The previous
        // version of this test passed AuthenticationTag::zero() and
        // still asserted is_verified() — that was exactly the
        // capability-bypass surface the fix closed.
        let tag = real_tag(&symbol);

        let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
        assert!(auth.is_verified());
        assert_eq!(auth.symbol(), &symbol);
        assert_eq!(auth.tag(), &tag);
    }

    #[test]
    fn test_new_verified_zero_tag_forces_unverified() {
        // br-asupersync-srqosl: the all-zero sentinel tag must NEVER
        // produce `verified = true`. This pins the runtime invariant
        // that protects the typed_symbol.rs zero-tag sentinel
        // callsites from forging trust.
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![], SymbolKind::Source);
        let auth = AuthenticatedSymbol::new_verified(symbol, AuthenticationTag::zero());
        assert!(
            !auth.is_verified(),
            "br-asupersync-srqosl: zero-tag sentinel must not pose as verified"
        );
    }

    #[test]
    fn test_new_unauthenticated() {
        // asupersync-8kumb7: new_unauthenticated() should create a symbol
        // that is explicitly marked as unverified and uses zero tag
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let auth = AuthenticatedSymbol::new_unauthenticated(symbol.clone());

        assert!(
            !auth.is_verified(),
            "unauthenticated symbol must not be verified"
        );
        assert!(
            auth.tag().is_zero(),
            "unauthenticated symbol must use zero tag"
        );
        assert_eq!(auth.symbol(), &symbol, "symbol data must be preserved");
    }

    #[test]
    fn test_from_parts_unverified() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![], SymbolKind::Source);
        let tag = AuthenticationTag::zero();

        let auth = AuthenticatedSymbol::from_parts(symbol, tag);
        assert!(!auth.is_verified());
    }

    #[test]
    fn test_into_symbol() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2], SymbolKind::Source);
        let tag = real_tag(&symbol);

        let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
        let unwrapped = auth.into_symbol();

        assert_eq!(unwrapped, symbol);
    }

    // =========================================================================
    // Wave 52 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn authenticated_symbol_debug_clone_eq() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = real_tag(&symbol);
        let auth = AuthenticatedSymbol::new_verified(symbol, tag);
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("AuthenticatedSymbol"), "{dbg}");
        let cloned = auth.clone();
        assert_eq!(auth, cloned);
    }

    #[test]
    fn set_verified_updates_flag() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = real_tag(&symbol);
        let mut auth = AuthenticatedSymbol::new_verified(symbol, tag);

        auth.set_verified(false);
        assert!(!auth.is_verified());

        auth.set_verified(true);
        assert!(auth.is_verified());
    }

    #[test]
    fn test_set_verified_visibility_restriction() {
        // Regression test for asupersync-x2z5dj: Authentication bypass prevention
        //
        // SECURITY INVARIANT: set_verified() must be pub(super), NOT pub(crate)
        //
        // This test documents that set_verified() is correctly restricted to the
        // security module. If someone changes the visibility from pub(super) back
        // to pub(crate), external modules could bypass authentication by directly
        // setting verified=true on unverified symbols.
        //
        // The compile-time visibility restriction prevents this attack vector.
        // Only the security module can modify verification status.
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = real_tag(&symbol);
        let mut auth = AuthenticatedSymbol::new_verified(symbol, tag);

        // This call succeeds because we're within the security module
        auth.set_verified(false);
        assert!(!auth.is_verified());

        // External modules attempting to call set_verified() would get:
        // "method `set_verified` is private" compile error
        // This is the intended security boundary.
    }
