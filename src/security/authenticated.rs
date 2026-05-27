//! Authenticated symbol wrapper.
//!
//! An `AuthenticatedSymbol` bundles a `Symbol` with its `AuthenticationTag`.
//! It tracks whether the tag has been verified against a key.

use crate::security::tag::AuthenticationTag;
use crate::types::Symbol;

/// A symbol bundled with its authentication tag.
///
/// This wrapper tracks the verification status of the symbol.
///
/// - `verified = true`: The symbol has been cryptographically verified against a key.
/// - `verified = false`: The symbol has not yet been verified (e.g., just received from network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSymbol {
    symbol: Symbol,
    tag: AuthenticationTag,
    verified: bool,
}

impl AuthenticatedSymbol {
    /// Creates a new verified authenticated symbol from an internally trusted source.
    ///
    /// br-asupersync-srqosl: the `verified` bit is now set to `true`
    /// only when the supplied tag is NOT the all-zero sentinel
    /// produced by [`AuthenticationTag::zero`]. The pre-fix shape
    /// unconditionally set `verified = true` even when callers passed
    /// `AuthenticationTag::zero()` as an unauthenticated sentinel (the three encode
    /// paths in `types/typed_symbol.rs` at lines 630/925/1204 still
    /// do this). Downstream consumers that trust `is_verified()`
    /// without re-running [`verify`](AuthenticationTag::verify)
    /// — including any `DecodingPipeline` configured with
    /// `verify_auth = false` (br-asupersync-f4mdcr) — would otherwise
    /// silently accept a zero-tagged unauthenticated symbol as
    /// authenticated.
    ///
    /// The defensive tag-shape check at construction means the
    /// `verified` flag never lies: if the tag is the zero sentinel,
    /// the symbol is reported as `is_verified() == false`, forcing
    /// every consumer to either run a real verification step or
    /// reject the symbol explicitly.
    ///
    /// asupersync-8kumb7: Callers should use `new_unauthenticated()` instead of
    /// passing zero tags to this method, as it makes the lack of authentication explicit.
    #[must_use]
    pub(crate) fn new_verified(symbol: Symbol, tag: AuthenticationTag) -> Self {
        // asupersync-8kumb7: Log warning for zero tag usage to discourage this pattern
        if tag.is_zero() {
            eprintln!(
                "WARNING: AuthenticatedSymbol::new_verified called with zero tag - consider using new_unauthenticated() instead"
            );
        }

        let verified = !tag.is_zero();
        Self {
            symbol,
            tag,
            verified,
        }
    }

    /// Creates an explicitly unauthenticated symbol.
    ///
    /// This is for encoding paths that have not yet been wired to real authentication keys.
    /// The symbol is marked as unverified and uses the zero sentinel tag.
    ///
    /// This is preferred over `new_verified(symbol, AuthenticationTag::zero())` because
    /// it makes the lack of authentication explicit in the calling code.
    #[must_use]
    pub(crate) fn new_unauthenticated(symbol: Symbol) -> Self {
        Self {
            symbol,
            tag: AuthenticationTag::zero(),
            verified: false,
        }
    }

    /// Creates an unverified authenticated symbol from parts.
    ///
    /// This is used when receiving a symbol and tag from the network.
    /// The `verified` flag is initially false.
    #[must_use]
    pub fn from_parts(symbol: Symbol, tag: AuthenticationTag) -> Self {
        Self {
            symbol,
            tag,
            verified: false,
        }
    }

    /// Returns a reference to the inner symbol.
    #[must_use]
    #[inline]
    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Returns a reference to the authentication tag.
    #[must_use]
    #[inline]
    pub fn tag(&self) -> &AuthenticationTag {
        &self.tag
    }

    /// Returns true if this symbol has been verified.
    #[must_use]
    #[inline]
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Sets the verification status (internal use).
    pub(super) fn set_verified(&mut self, verified: bool) {
        self.verified = verified;
    }

    /// Consumes the wrapper and returns the inner symbol.
    ///
    /// This discards the authentication tag and verification status.
    #[must_use]
    pub fn into_symbol(self) -> Symbol {
        self.symbol
    }
}

#[cfg(test)]
mod tests {
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
}
