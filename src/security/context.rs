//! Security context for managing authentication operations.
//!
//! The [`SecurityContext`] provides a high-level API for signing and verifying
//! symbols while managing keys and configuration.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::security::error::{AuthError, AuthResult};
use crate::security::key::AuthKey;
use crate::security::tag::AuthenticationTag;
use crate::types::Symbol;
use crate::util::DetRng;

/// Mode for handling authentication failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// Strict mode: all symbols must pass verification (default).
    #[default]
    Strict,
    /// Permissive mode: log failures but allow unverified symbols.
    /// Use only for debugging or gradual rollout.
    Permissive,
    /// Disabled mode: no authentication checks performed.
    /// Use only in trusted environments or for testing.
    Disabled,
}

/// Statistics about authentication operations.
#[derive(Debug, Clone, Default)]
pub struct AuthStats {
    /// Number of symbols signed.
    pub symbols_signed: u64,
    /// Number of verification attempts.
    pub verifications_attempted: u64,
    /// Number of successful verifications.
    pub verifications_succeeded: u64,
    /// Number of failed verifications.
    pub verifications_failed: u64,
    /// Number of verifications skipped (in disabled mode).
    pub verifications_skipped: u64,
}

impl AuthStats {
    /// Creates new empty statistics.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            symbols_signed: 0,
            verifications_attempted: 0,
            verifications_succeeded: 0,
            verifications_failed: 0,
            verifications_skipped: 0,
        }
    }

    /// Returns the verification success rate as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for percentage display
    pub fn success_rate(&self) -> f64 {
        if self.verifications_attempted == 0 {
            0.0
        } else {
            (self.verifications_succeeded as f64 / self.verifications_attempted as f64) * 100.0
        }
    }

    /// Resets all statistics to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Security context for symbol authentication operations.
///
/// The context holds the authentication key and configuration, providing
/// a convenient API for signing and verifying symbols.
///
/// # Example
///
/// ```
/// use asupersync::security::{AuthKey, SecurityContext, AuthMode};
/// use asupersync::types::Symbol;
///
/// // Create context with a key
/// let key = AuthKey::from_seed(42);
/// let mut ctx = SecurityContext::new(key);
///
/// // Sign a symbol
/// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
/// let authenticated = ctx.sign_symbol(&symbol);
///
/// // Verify received symbol
/// let result = ctx.verify_authenticated_symbol(&authenticated);
/// assert!(result.is_ok());
///
/// // Check statistics
/// assert_eq!(ctx.stats().symbols_signed, 1);
/// assert_eq!(ctx.stats().verifications_succeeded, 1);
/// ```
#[derive(Debug)]
pub struct SecurityContext {
    /// The authentication key.
    key: AuthKey,
    /// Operating mode.
    mode: AuthMode,
    /// Statistics about operations.
    stats: AuthStats,
}

impl SecurityContext {
    /// Creates a new security context with the given key.
    ///
    /// The context starts in [`AuthMode::Strict`] mode.
    #[must_use]
    pub fn new(key: AuthKey) -> Self {
        Self {
            key,
            mode: AuthMode::Strict,
            stats: AuthStats::new(),
        }
    }

    /// Creates a context for testing with a deterministic key.
    ///
    /// Shorthand for `SecurityContext::new(AuthKey::from_seed(seed))`.
    #[must_use]
    pub fn for_testing(seed: u64) -> Self {
        Self::new(AuthKey::from_seed(seed))
    }

    /// Creates a context from a DetRng.
    ///
    /// Useful when you need to generate the context's key from an
    /// existing RNG stream while maintaining determinism.
    #[must_use]
    pub fn from_rng(rng: &mut DetRng) -> Self {
        Self::new(AuthKey::from_rng(rng))
    }

    /// Sets the authentication mode.
    #[must_use]
    pub fn with_mode(mut self, mode: AuthMode) -> Self {
        self.mode = mode;
        self
    }

    /// Returns the current authentication mode.
    #[must_use]
    pub const fn mode(&self) -> AuthMode {
        self.mode
    }

    /// Returns a reference to the authentication key.
    #[must_use]
    pub const fn key(&self) -> &AuthKey {
        &self.key
    }

    /// Returns a reference to the authentication statistics.
    #[must_use]
    pub const fn stats(&self) -> &AuthStats {
        &self.stats
    }

    /// Returns a mutable reference to the statistics.
    pub fn stats_mut(&mut self) -> &mut AuthStats {
        &mut self.stats
    }

    /// Signs a symbol and returns an authenticated wrapper.
    ///
    /// The resulting `AuthenticatedSymbol` is marked as verified since
    /// we generated the tag ourselves.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, SecurityContext};
    /// use asupersync::types::Symbol;
    ///
    /// let mut ctx = SecurityContext::for_testing(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// let auth = ctx.sign_symbol(&symbol);
    /// assert!(auth.is_verified());
    /// ```
    pub fn sign_symbol(&mut self, symbol: &Symbol) -> AuthenticatedSymbol {
        self.stats.symbols_signed += 1;
        AuthenticatedSymbol::sign(&self.key, symbol.clone())
    }

    /// Signs a symbol by consuming it.
    ///
    /// More efficient than `sign_symbol` when you don't need the original.
    pub fn sign_symbol_owned(&mut self, symbol: Symbol) -> AuthenticatedSymbol {
        self.stats.symbols_signed += 1;
        AuthenticatedSymbol::sign(&self.key, symbol)
    }

    /// Computes an authentication tag for a symbol without wrapping it.
    ///
    /// Useful when you need the tag separately (e.g., for batch operations
    /// or when serializing symbol and tag separately).
    pub fn compute_tag(&mut self, symbol: &Symbol) -> AuthenticationTag {
        self.stats.symbols_signed += 1;
        AuthenticationTag::compute(&self.key, symbol)
    }

    /// Verifies an authenticated symbol.
    ///
    /// Behavior depends on the authentication mode:
    ///
    /// - **Strict**: Returns error on failure
    /// - **Permissive**: Logs failure but returns Ok with unverified symbol
    /// - **Disabled**: Skips verification entirely
    ///
    /// # Errors
    ///
    /// In strict mode, returns [`AuthError`] if verification fails.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, SecurityContext, AuthenticatedSymbol};
    /// use asupersync::types::Symbol;
    ///
    /// let mut ctx = SecurityContext::for_testing(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// let auth = ctx.sign_symbol(&symbol);
    /// let result = ctx.verify_authenticated_symbol(&auth);
    /// assert!(result.is_ok());
    /// ```
    pub fn verify_authenticated_symbol<'a>(
        &mut self,
        auth: &'a AuthenticatedSymbol,
    ) -> AuthResult<&'a Symbol> {
        self.stats.verifications_attempted += 1;

        match self.mode {
            AuthMode::Disabled => {
                self.stats.verifications_skipped += 1;
                Ok(auth.symbol())
            }
            AuthMode::Permissive => {
                if auth.tag().verify(&self.key, auth.symbol()) {
                    self.stats.verifications_succeeded += 1;
                } else {
                    self.stats.verifications_failed += 1;
                    // In permissive mode, we continue despite failure
                }
                Ok(auth.symbol())
            }
            AuthMode::Strict => {
                if auth.tag().verify(&self.key, auth.symbol()) {
                    self.stats.verifications_succeeded += 1;
                    Ok(auth.symbol())
                } else {
                    self.stats.verifications_failed += 1;
                    Err(AuthError::verification_failed()
                        .with_context(format!("symbol {}", auth.id())))
                }
            }
        }
    }

    /// Verifies a tag against a symbol directly.
    ///
    /// Lower-level than `verify_authenticated_symbol`; use when you have
    /// the symbol and tag separately.
    pub fn verify_tag(&mut self, symbol: &Symbol, tag: &AuthenticationTag) -> AuthResult<()> {
        self.stats.verifications_attempted += 1;

        let valid = tag.verify(&self.key, symbol);

        match self.mode {
            AuthMode::Disabled => {
                self.stats.verifications_skipped += 1;
                Ok(())
            }
            AuthMode::Permissive => {
                if valid {
                    self.stats.verifications_succeeded += 1;
                } else {
                    self.stats.verifications_failed += 1;
                }
                Ok(())
            }
            AuthMode::Strict => {
                if valid {
                    self.stats.verifications_succeeded += 1;
                    Ok(())
                } else {
                    self.stats.verifications_failed += 1;
                    Err(AuthError::verification_failed()
                        .with_context(format!("symbol {}", symbol.id())))
                }
            }
        }
    }

    /// Verifies and extracts the symbol from an authenticated wrapper.
    ///
    /// Returns an owned copy of the symbol if verification succeeds.
    pub fn verify_and_extract(&mut self, auth: AuthenticatedSymbol) -> AuthResult<Symbol> {
        let _ = self.verify_authenticated_symbol(&auth)?;
        Ok(auth.into_parts().0)
    }

    /// Creates a sub-context with a derived key for a specific purpose.
    ///
    /// Useful for key separation (e.g., different keys for different channels
    /// or protocol phases).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::SecurityContext;
    ///
    /// let master = SecurityContext::for_testing(42);
    /// let channel_a = master.derive_context(b"channel-a");
    /// let channel_b = master.derive_context(b"channel-b");
    ///
    /// // Different derived contexts have different keys
    /// assert_ne!(channel_a.key(), channel_b.key());
    /// ```
    #[must_use]
    pub fn derive_context(&self, purpose: &[u8]) -> Self {
        Self::new(self.key.derive_subkey(purpose)).with_mode(self.mode)
    }
}

impl Clone for SecurityContext {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            mode: self.mode,
            stats: AuthStats::new(), // Fresh stats for the clone
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol(data: &[u8]) -> Symbol {
        Symbol::new_for_test(1, 0, 0, data)
    }

    #[test]
    fn context_creation() {
        let ctx = SecurityContext::for_testing(42);
        assert_eq!(ctx.mode(), AuthMode::Strict);
        assert_eq!(ctx.stats().symbols_signed, 0);
    }

    #[test]
    fn sign_and_verify() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);

        let auth = ctx.sign_symbol(&symbol);
        assert!(auth.is_verified());

        let result = ctx.verify_authenticated_symbol(&auth);
        assert!(result.is_ok());

        assert_eq!(ctx.stats().symbols_signed, 1);
        assert_eq!(ctx.stats().verifications_succeeded, 1);
    }

    #[test]
    fn verify_fails_wrong_tag() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);

        let auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

        let result = ctx.verify_authenticated_symbol(&auth);
        assert!(result.is_err());

        assert_eq!(ctx.stats().verifications_failed, 1);
    }

    #[test]
    fn permissive_mode_allows_failures() {
        let mut ctx = SecurityContext::for_testing(42).with_mode(AuthMode::Permissive);
        let symbol = make_symbol(&[1, 2, 3]);

        let auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

        let result = ctx.verify_authenticated_symbol(&auth);
        assert!(result.is_ok()); // Doesn't fail in permissive mode

        assert_eq!(ctx.stats().verifications_failed, 1);
    }

    #[test]
    fn disabled_mode_skips_verification() {
        let mut ctx = SecurityContext::for_testing(42).with_mode(AuthMode::Disabled);
        let symbol = make_symbol(&[1, 2, 3]);

        let auth = AuthenticatedSymbol::from_parts(symbol, AuthenticationTag::zero());

        let result = ctx.verify_authenticated_symbol(&auth);
        assert!(result.is_ok());

        assert_eq!(ctx.stats().verifications_skipped, 1);
        assert_eq!(ctx.stats().verifications_succeeded, 0);
    }

    #[test]
    fn derive_context() {
        let master = SecurityContext::for_testing(42);
        let derived1 = master.derive_context(b"purpose1");
        let derived2 = master.derive_context(b"purpose2");

        // Different purposes yield different keys
        assert_ne!(derived1.key(), derived2.key());

        // Mode is inherited
        assert_eq!(derived1.mode(), master.mode());
    }

    #[test]
    fn sign_owned() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);

        let auth = ctx.sign_symbol_owned(symbol);
        assert!(auth.is_verified());
        assert_eq!(ctx.stats().symbols_signed, 1);
    }

    #[test]
    fn compute_tag() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);

        let tag = ctx.compute_tag(&symbol);

        // Can verify manually
        assert!(tag.verify(&ctx.key, &symbol));
    }

    #[test]
    fn verify_tag_directly() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);
        let tag = AuthenticationTag::compute(ctx.key(), &symbol);

        let result = ctx.verify_tag(&symbol, &tag);
        assert!(result.is_ok());
        assert_eq!(ctx.stats().verifications_succeeded, 1);
    }

    #[test]
    fn verify_and_extract() {
        let mut ctx = SecurityContext::for_testing(42);
        let original = make_symbol(&[1, 2, 3]);

        let auth = ctx.sign_symbol(&original);

        let extracted = ctx.verify_and_extract(auth);
        assert!(extracted.is_ok());
        assert_eq!(extracted.unwrap().data(), &[1, 2, 3]);
    }

    #[test]
    fn stats_success_rate() {
        let mut stats = AuthStats::new();

        // Empty stats
        assert_eq!(stats.success_rate(), 0.0);

        // 100% success
        stats.verifications_attempted = 10;
        stats.verifications_succeeded = 10;
        assert!((stats.success_rate() - 100.0).abs() < f64::EPSILON);

        // 50% success
        stats.verifications_succeeded = 5;
        stats.verifications_failed = 5;
        assert!((stats.success_rate() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_reset() {
        let mut stats = AuthStats::new();
        stats.symbols_signed = 100;
        stats.verifications_succeeded = 50;

        stats.reset();

        assert_eq!(stats.symbols_signed, 0);
        assert_eq!(stats.verifications_succeeded, 0);
    }

    #[test]
    fn from_rng() {
        let mut rng = DetRng::new(42);
        let ctx1 = SecurityContext::from_rng(&mut rng);
        let ctx2 = SecurityContext::from_rng(&mut rng);

        // Different keys from same RNG stream
        assert_ne!(ctx1.key(), ctx2.key());

        // Same RNG state produces same key
        let mut rng2 = DetRng::new(42);
        let ctx3 = SecurityContext::from_rng(&mut rng2);
        assert_eq!(ctx1.key(), ctx3.key());
    }

    #[test]
    fn clone_has_fresh_stats() {
        let mut ctx = SecurityContext::for_testing(42);
        let symbol = make_symbol(&[1, 2, 3]);
        let _ = ctx.sign_symbol(&symbol);

        assert_eq!(ctx.stats().symbols_signed, 1);

        let clone = ctx.clone();
        assert_eq!(clone.stats().symbols_signed, 0); // Fresh stats
        assert_eq!(clone.key(), ctx.key()); // Same key
    }
}
