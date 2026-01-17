//! Authenticated symbol wrapper type.
//!
//! This module provides [`AuthenticatedSymbol`], which bundles a symbol
//! with its authentication tag for secure transmission.

use crate::security::error::{AuthError, AuthResult};
use crate::security::key::AuthKey;
use crate::security::tag::AuthenticationTag;
use crate::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use core::fmt;

/// A symbol bundled with its authentication tag.
///
/// `AuthenticatedSymbol` represents a symbol that has been signed with an
/// authentication tag. It can be in one of two states:
///
/// - **Unverified**: Created from received data, tag not yet checked
/// - **Verified**: Tag has been validated against a key
///
/// The type system tracks verification state, ensuring verified symbols
/// can be trusted while unverified symbols must be explicitly checked.
///
/// # Example
///
/// ```
/// use asupersync::security::{AuthKey, AuthenticatedSymbol, SecurityContext};
/// use asupersync::types::Symbol;
///
/// let key = AuthKey::from_seed(42);
/// let mut ctx = SecurityContext::new(key);
///
/// // Create and sign a symbol
/// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3, 4]);
/// let authenticated = ctx.sign_symbol(&symbol);
///
/// // Transport over network...
///
/// // Verify on receive
/// match ctx.verify_authenticated_symbol(&authenticated) {
///     Ok(verified) => println!("Symbol verified: {:?}", verified.id()),
///     Err(e) => println!("Verification failed: {}", e),
/// }
/// ```
#[derive(Clone)]
pub struct AuthenticatedSymbol {
    /// The underlying symbol.
    symbol: Symbol,
    /// The authentication tag.
    tag: AuthenticationTag,
    /// Whether the tag has been verified.
    verified: bool,
}

impl AuthenticatedSymbol {
    /// Creates an authenticated symbol by signing a symbol.
    ///
    /// The resulting symbol is considered verified since we generated the tag.
    ///
    /// # Arguments
    ///
    /// * `key` - The authentication key
    /// * `symbol` - The symbol to sign
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AuthenticatedSymbol};
    /// use asupersync::types::Symbol;
    ///
    /// let key = AuthKey::from_seed(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// let authenticated = AuthenticatedSymbol::sign(&key, symbol);
    /// assert!(authenticated.is_verified());
    /// ```
    #[must_use]
    pub fn sign(key: &AuthKey, symbol: Symbol) -> Self {
        let tag = AuthenticationTag::compute(key, &symbol);
        Self {
            symbol,
            tag,
            verified: true, // We created it, so it's trusted
        }
    }

    /// Creates an authenticated symbol from received data (unverified).
    ///
    /// The symbol starts in an unverified state. Call [`verify`](Self::verify)
    /// before trusting the data.
    ///
    /// # Arguments
    ///
    /// * `symbol` - The received symbol
    /// * `tag` - The received authentication tag
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag};
    /// use asupersync::types::Symbol;
    ///
    /// // Simulate receiving symbol and tag from network
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    /// let tag = AuthenticationTag::zero(); // From network
    ///
    /// let received = AuthenticatedSymbol::from_parts(symbol, tag);
    /// assert!(!received.is_verified());
    /// ```
    #[must_use]
    pub fn from_parts(symbol: Symbol, tag: AuthenticationTag) -> Self {
        Self {
            symbol,
            tag,
            verified: false,
        }
    }

    /// Verifies the authentication tag against a key.
    ///
    /// Returns `Ok(())` if verification succeeds, `Err(AuthError)` if it fails.
    /// After successful verification, [`is_verified`](Self::is_verified) returns `true`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] with kind [`VerificationFailed`](AuthErrorKind::VerificationFailed)
    /// if the tag doesn't match.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag};
    /// use asupersync::types::Symbol;
    ///
    /// let key = AuthKey::from_seed(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// // Create with correct tag
    /// let tag = AuthenticationTag::compute(&key, &symbol);
    /// let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);
    ///
    /// assert!(auth.verify(&key).is_ok());
    /// assert!(auth.is_verified());
    /// ```
    pub fn verify(&mut self, key: &AuthKey) -> AuthResult<()> {
        if self.tag.verify(key, &self.symbol) {
            self.verified = true;
            Ok(())
        } else {
            Err(AuthError::verification_failed()
                .with_context(format!("symbol {}", self.symbol.id())))
        }
    }

    /// Verifies and returns an immutable reference to the verified symbol.
    ///
    /// Combines verification with access in a single call. Only returns the
    /// symbol reference if verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if verification fails.
    pub fn verify_and_get(&mut self, key: &AuthKey) -> AuthResult<&Symbol> {
        self.verify(key)?;
        Ok(&self.symbol)
    }

    /// Returns `true` if the symbol has been verified.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    /// Returns a reference to the underlying symbol.
    ///
    /// # Security Warning
    ///
    /// Check [`is_verified`](Self::is_verified) before trusting the data.
    /// Unverified symbols may contain tampered data.
    #[must_use]
    pub const fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    /// Returns a reference to the authentication tag.
    #[must_use]
    pub const fn tag(&self) -> &AuthenticationTag {
        &self.tag
    }

    /// Consumes the authenticated symbol and returns its parts.
    ///
    /// Useful for serialization or when you need ownership of the symbol.
    #[must_use]
    pub fn into_parts(self) -> (Symbol, AuthenticationTag) {
        (self.symbol, self.tag)
    }

    /// Consumes the authenticated symbol and returns just the symbol.
    ///
    /// # Panics
    ///
    /// Panics if the symbol has not been verified. Use [`into_parts`](Self::into_parts)
    /// if you need the symbol without verification.
    #[must_use]
    pub fn into_verified_symbol(self) -> Symbol {
        assert!(
            self.verified,
            "cannot extract unverified symbol; call verify() first"
        );
        self.symbol
    }

    /// Attempts to consume and return the symbol if verified.
    ///
    /// Returns `Err(self)` if the symbol hasn't been verified.
    pub fn try_into_verified_symbol(self) -> Result<Symbol, Self> {
        if self.verified {
            Ok(self.symbol)
        } else {
            Err(self)
        }
    }

    // Delegate accessors to the inner symbol

    /// Returns the symbol's unique identifier.
    #[must_use]
    pub const fn id(&self) -> SymbolId {
        self.symbol.id()
    }

    /// Returns the object ID this symbol belongs to.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.symbol.object_id()
    }

    /// Returns the Source Block Number.
    #[must_use]
    pub const fn sbn(&self) -> u8 {
        self.symbol.sbn()
    }

    /// Returns the Encoding Symbol ID.
    #[must_use]
    pub const fn esi(&self) -> u32 {
        self.symbol.esi()
    }

    /// Returns the symbol's kind.
    #[must_use]
    pub const fn kind(&self) -> SymbolKind {
        self.symbol.kind()
    }

    /// Returns the symbol's data payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.symbol.data()
    }

    /// Returns the size of the data payload.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbol.len()
    }

    /// Returns `true` if the data payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbol.is_empty()
    }
}

impl fmt::Debug for AuthenticatedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedSymbol")
            .field("symbol", &self.symbol)
            .field("tag", &self.tag)
            .field("verified", &self.verified)
            .finish()
    }
}

impl fmt::Display for AuthenticatedSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.verified {
            "verified"
        } else {
            "UNVERIFIED"
        };
        write!(f, "AuthSym({}, {}, {})", self.symbol, self.tag, status)
    }
}

impl PartialEq for AuthenticatedSymbol {
    fn eq(&self, other: &Self) -> bool {
        // Two authenticated symbols are equal if their symbols and tags match
        // Verification status doesn't affect equality
        self.symbol == other.symbol && self.tag == other.tag
    }
}

impl Eq for AuthenticatedSymbol {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol(obj: u64, sbn: u8, esi: u32, data: &[u8]) -> Symbol {
        Symbol::new_for_test(obj, sbn, esi, data)
    }

    #[test]
    fn sign_creates_verified() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);

        let auth = AuthenticatedSymbol::sign(&key, symbol);
        assert!(auth.is_verified());
    }

    #[test]
    fn from_parts_creates_unverified() {
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::zero();

        let auth = AuthenticatedSymbol::from_parts(symbol, tag);
        assert!(!auth.is_verified());
    }

    #[test]
    fn verify_valid_tag() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::compute(&key, &symbol);

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);
        assert!(!auth.is_verified());

        assert!(auth.verify(&key).is_ok());
        assert!(auth.is_verified());
    }

    #[test]
    fn verify_invalid_tag() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let wrong_tag = AuthenticationTag::zero();

        let mut auth = AuthenticatedSymbol::from_parts(symbol, wrong_tag);

        let result = auth.verify(&key);
        assert!(result.is_err());
        assert!(!auth.is_verified());
    }

    #[test]
    fn verify_wrong_key() {
        let key1 = AuthKey::from_seed(42);
        let key2 = AuthKey::from_seed(43);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::compute(&key1, &symbol);

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);

        let result = auth.verify(&key2);
        assert!(result.is_err());
        assert!(!auth.is_verified());
    }

    #[test]
    fn verify_and_get_success() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::compute(&key, &symbol);

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);

        let result = auth.verify_and_get(&key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().data(), &[1, 2, 3]);
    }

    #[test]
    fn into_parts() {
        let key = AuthKey::from_seed(42);
        let original = make_symbol(1, 0, 0, &[1, 2, 3]);
        let auth = AuthenticatedSymbol::sign(&key, original.clone());

        let (symbol, _tag) = auth.into_parts();
        assert_eq!(symbol.data(), original.data());
    }

    #[test]
    fn into_verified_symbol() {
        let key = AuthKey::from_seed(42);
        let original = make_symbol(1, 0, 0, &[1, 2, 3]);
        let auth = AuthenticatedSymbol::sign(&key, original.clone());

        let symbol = auth.into_verified_symbol();
        assert_eq!(symbol.data(), original.data());
    }

    #[test]
    #[should_panic(expected = "unverified")]
    fn into_verified_symbol_panics_if_unverified() {
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::zero();
        let auth = AuthenticatedSymbol::from_parts(symbol, tag);

        let _ = auth.into_verified_symbol();
    }

    #[test]
    fn try_into_verified_symbol() {
        let key = AuthKey::from_seed(42);
        let original = make_symbol(1, 0, 0, &[1, 2, 3]);

        // Verified case
        let auth = AuthenticatedSymbol::sign(&key, original.clone());
        assert!(auth.try_into_verified_symbol().is_ok());

        // Unverified case
        let auth = AuthenticatedSymbol::from_parts(original, AuthenticationTag::zero());
        assert!(auth.try_into_verified_symbol().is_err());
    }

    #[test]
    fn accessor_delegation() {
        let key = AuthKey::from_seed(42);
        let original = make_symbol(1, 2, 3, &[4, 5, 6]);
        let auth = AuthenticatedSymbol::sign(&key, original);

        assert_eq!(auth.sbn(), 2);
        assert_eq!(auth.esi(), 3);
        assert_eq!(auth.data(), &[4, 5, 6]);
        assert_eq!(auth.len(), 3);
        assert!(!auth.is_empty());
    }

    #[test]
    fn equality() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);

        let auth1 = AuthenticatedSymbol::sign(&key, symbol.clone());

        // Same symbol with same tag from parts (unverified)
        let auth2 = AuthenticatedSymbol::from_parts(symbol, auth1.tag().clone());

        // Equal despite different verification status
        assert_eq!(auth1, auth2);
    }

    #[test]
    fn display_shows_verification_status() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);

        let verified = AuthenticatedSymbol::sign(&key, symbol.clone());
        let display = format!("{verified}");
        assert!(display.contains("verified"));
        assert!(!display.contains("UNVERIFIED"));

        let unverified = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());
        let display = format!("{unverified}");
        assert!(display.contains("UNVERIFIED"));
    }
}
