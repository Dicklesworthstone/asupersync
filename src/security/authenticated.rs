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
    /// Creates a new verified authenticated symbol.
    ///
    /// This should only be called when creating a symbol locally with a known key
    /// (i.e., signing).
    #[must_use]
    pub fn new_verified(symbol: Symbol, tag: AuthenticationTag) -> Self {
        Self {
            symbol,
            tag,
            verified: true,
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
    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Returns a reference to the authentication tag.
    #[must_use]
    pub fn tag(&self) -> &AuthenticationTag {
        &self.tag
    }

    /// Returns true if this symbol has been verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Marks the symbol as verified (internal use).
    pub(crate) fn mark_verified(&mut self) {
        self.verified = true;
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
    use super::*;
    use crate::types::{SymbolId, SymbolKind};

    #[test]
    fn test_new_verified() {
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![], SymbolKind::Source);
        let tag = AuthenticationTag::zero();

        let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
        assert!(auth.is_verified());
        assert_eq!(auth.symbol(), &symbol);
        assert_eq!(auth.tag(), &tag);
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
        let tag = AuthenticationTag::zero();

        let auth = AuthenticatedSymbol::new_verified(symbol.clone(), tag);
        let unwrapped = auth.into_symbol();

        assert_eq!(unwrapped, symbol);
    }
}
