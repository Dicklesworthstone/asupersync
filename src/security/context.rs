//! Security context for authentication operations.
//!
//! The `SecurityContext` holds the authentication key and policy configuration.
//! It is the main entry point for signing and verifying symbols.

use crate::security::authenticated::AuthenticatedSymbol;
use crate::security::error::{AuthError, AuthErrorKind};
use crate::security::key::AuthKey;
use crate::security::tag::AuthenticationTag;
use crate::types::Symbol;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Authentication mode for the security context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Verification failures are treated as errors (default).
    Strict,
    /// Verification failures are logged but allowed.
    Permissive,
    /// Verification is skipped entirely.
    Disabled,
}

/// Statistics for authentication operations.
#[derive(Debug, Default)]
pub struct AuthStats {
    /// Number of symbols signed.
    pub signed: AtomicU64,
    /// Number of symbols successfully verified.
    pub verified_ok: AtomicU64,
    /// Number of symbols that failed verification.
    pub verified_fail: AtomicU64,
    /// Number of verification failures allowed (permissive mode).
    pub failures_allowed: AtomicU64,
    /// Number of verifications skipped (disabled mode).
    pub skipped: AtomicU64,
}

/// A context for performing security operations.
#[derive(Debug, Clone)]
pub struct SecurityContext {
    key: AuthKey,
    mode: AuthMode,
    stats: Arc<AuthStats>,
}

impl SecurityContext {
    /// Creates a new security context with the given key and default settings.
    #[must_use]
    pub fn new(key: AuthKey) -> Self {
        Self {
            key,
            mode: AuthMode::Strict,
            stats: Arc::new(AuthStats::default()),
        }
    }

    /// Creates a security context for testing with a deterministic seed.
    #[must_use]
    pub fn for_testing(seed: u64) -> Self {
        Self::new(AuthKey::from_seed(seed))
    }

    /// Sets the authentication mode.
    #[must_use]
    pub fn with_mode(mut self, mode: AuthMode) -> Self {
        self.mode = mode;
        self
    }

    /// Signs a symbol, producing an authenticated symbol.
    #[must_use]
    pub fn sign_symbol(&self, symbol: &Symbol) -> AuthenticatedSymbol {
        let tag = AuthenticationTag::compute(&self.key, symbol);
        self.stats.signed.fetch_add(1, Ordering::Relaxed);
        AuthenticatedSymbol::new_verified(symbol.clone(), tag)
    }

    /// Verifies an authenticated symbol.
    ///
    /// The behavior depends on the configured `AuthMode`:
    /// - `Strict`: Returns `Err` on failure.
    /// - `Permissive`: Returns `Ok` on failure (but `verified` flag remains false).
    /// - `Disabled`: Returns `Ok` without checking (but `verified` flag remains false).
    ///
    /// If verification succeeds, the `verified` flag on the symbol is set to true.
    pub fn verify_authenticated_symbol(
        &self,
        auth: &mut AuthenticatedSymbol,
    ) -> Result<(), AuthError> {
        if self.mode == AuthMode::Disabled {
            self.stats.skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let is_valid = auth.tag().verify(&self.key, auth.symbol());

        if is_valid {
            auth.mark_verified();
            self.stats.verified_ok.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            self.stats.verified_fail.fetch_add(1, Ordering::Relaxed);
            match self.mode {
                AuthMode::Strict => Err(AuthError::new(
                    AuthErrorKind::InvalidTag,
                    format!("symbol verification failed for {}", auth.symbol().id()),
                )),
                AuthMode::Permissive => {
                    self.stats.failures_allowed.fetch_add(1, Ordering::Relaxed);
                    // In permissive mode, we allow the failure but don't mark as verified
                    Ok(())
                }
                AuthMode::Disabled => unreachable!(),
            }
        }
    }

    /// Derives a child context with a subkey.
    #[must_use]
    pub fn derive_context(&self, purpose: &[u8]) -> Self {
        Self {
            key: self.key.derive_subkey(purpose),
            mode: self.mode,
            stats: Arc::new(AuthStats::default()), // New stats for derived context
        }
    }

    /// Returns the authentication stats.
    #[must_use]
    pub fn stats(&self) -> &AuthStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SymbolId, SymbolKind};

    #[test]
    fn context_creation() {
        let key = AuthKey::from_seed(42);
        let ctx = SecurityContext::new(key);
        // Default strict mode
        assert!(matches!(ctx.mode, AuthMode::Strict));
    }

    #[test]
    fn context_sign_and_verify() {
        let ctx = SecurityContext::for_testing(123);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let auth = ctx.sign_symbol(&symbol);
        assert!(auth.is_verified()); // Signed locally is implicitly verified

        // Reset verified flag to simulate reception
        let mut received = AuthenticatedSymbol::from_parts(auth.clone().into_symbol(), *auth.tag());
        assert!(!received.is_verified());

        // Verify
        ctx.verify_authenticated_symbol(&mut received)
            .expect("verification failed");
        assert!(received.is_verified());
    }

    #[test]
    fn disabled_mode_skips_verification() {
        let ctx = SecurityContext::for_testing(123).with_mode(AuthMode::Disabled);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = AuthenticationTag::zero(); // Invalid tag

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);

        ctx.verify_authenticated_symbol(&mut auth)
            .expect("disabled mode should not error");
        assert!(!auth.is_verified()); // Should not be marked verified
        assert_eq!(ctx.stats().skipped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn strict_mode_fails_verification() {
        let ctx = SecurityContext::for_testing(123).with_mode(AuthMode::Strict);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = AuthenticationTag::zero(); // Invalid tag

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);

        let result = ctx.verify_authenticated_symbol(&mut auth);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_invalid_tag());
        assert!(!auth.is_verified());
        assert_eq!(ctx.stats().verified_fail.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn permissive_mode_allows_failures() {
        let ctx = SecurityContext::for_testing(123).with_mode(AuthMode::Permissive);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let tag = AuthenticationTag::zero(); // Invalid tag

        let mut auth = AuthenticatedSymbol::from_parts(symbol, tag);

        let result = ctx.verify_authenticated_symbol(&mut auth);
        assert!(result.is_ok());
        assert!(!auth.is_verified());
        assert_eq!(ctx.stats().verified_fail.load(Ordering::Relaxed), 1);
        assert_eq!(ctx.stats().failures_allowed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn accessor_delegation() {
        let ctx = SecurityContext::for_testing(123);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        // Sign
        let auth = ctx.sign_symbol(&symbol);
        assert_eq!(ctx.stats().signed.load(Ordering::Relaxed), 1);
        assert_eq!(auth.symbol(), &symbol);
    }
}
