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

/// Public authentication posture of an [`AuthenticatedSymbol`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedSymbolState {
    /// The symbol tag has been cryptographically verified.
    Verified,
    /// The symbol carries a non-zero tag, but it has not been verified yet.
    UnverifiedTagged,
    /// The symbol carries the all-zero unauthenticated sentinel tag.
    UnauthenticatedSentinel,
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
    ///
    /// Core library code must stay silent, so this constructor does not log or
    /// print when it sees the sentinel. The returned verification state is the
    /// diagnostic contract.
    #[must_use]
    pub(crate) fn new_verified(symbol: Symbol, tag: AuthenticationTag) -> Self {
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

    /// Returns the symbol's authentication posture without requiring callers to
    /// inspect the tag bytes directly.
    #[must_use]
    #[inline]
    pub fn authentication_state(&self) -> AuthenticatedSymbolState {
        if self.verified {
            AuthenticatedSymbolState::Verified
        } else if self.tag.is_zero() {
            AuthenticatedSymbolState::UnauthenticatedSentinel
        } else {
            AuthenticatedSymbolState::UnverifiedTagged
        }
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
#[path = "authenticated_inline_tests.rs"]
mod tests;
