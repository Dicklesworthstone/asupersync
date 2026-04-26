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
///
/// Modes form a strict total order on enforcement:
///   Strict (most restrictive) > Permissive > Disabled (least restrictive)
///
/// br-asupersync-jgpcvp: [`SecurityContext::with_mode`] only allows
/// transitions to a STRICTER mode (an upgrade). Downgrades (Strict →
/// Permissive, Strict → Disabled, Permissive → Disabled) are
/// rejected by panicking — silent ignore is worse, since a caller
/// believing they downgraded would assume looser semantics that
/// don't apply. Tests that need to construct a context in a specific
/// mode should use [`SecurityContext::for_testing_with_mode`] which
/// sets the mode at CONSTRUCTION time (no transition needed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Verification failures are treated as errors (default).
    Strict,
    /// Verification failures are logged but allowed.
    Permissive,
    /// Verification is skipped entirely.
    Disabled,
}

impl AuthMode {
    /// br-asupersync-jgpcvp: returns `true` if `self` is at least as
    /// strict as `other`. Used to gate `with_mode` transitions —
    /// only equal-or-stricter target modes are allowed.
    ///
    /// Strictness order: Strict > Permissive > Disabled.
    #[inline]
    #[must_use]
    pub const fn is_at_least_as_strict_as(self, other: Self) -> bool {
        let lhs = self.strictness_rank();
        let rhs = other.strictness_rank();
        lhs >= rhs
    }

    /// Numeric rank used by [`Self::is_at_least_as_strict_as`].
    /// Higher = stricter. Internal helper.
    const fn strictness_rank(self) -> u8 {
        match self {
            Self::Strict => 2,
            Self::Permissive => 1,
            Self::Disabled => 0,
        }
    }
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

    /// br-asupersync-jgpcvp: test-only constructor that sets the
    /// initial mode at construction time, bypassing the no-downgrade
    /// rule on [`Self::with_mode`]. Tests that need to verify
    /// Permissive-mode or Disabled-mode behavior must use this
    /// constructor — they cannot start Strict and downgrade.
    ///
    /// Production code should NEVER need to construct a non-Strict
    /// context except via the regular Builder path which makes the
    /// mode choice an explicit deployment decision.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing_with_mode(seed: u64, mode: AuthMode) -> Self {
        let mut ctx = Self::new(AuthKey::from_seed(seed));
        ctx.mode = mode;
        ctx
    }

    /// Sets the authentication mode.
    ///
    /// # br-asupersync-jgpcvp: NO-DOWNGRADE policy
    ///
    /// `with_mode` only allows transitions to a mode that is **at
    /// least as strict** as the current mode. Strictness order is
    /// `Strict > Permissive > Disabled`, so the allowed transitions
    /// are:
    ///   * Strict → Strict    (no-op)
    ///   * Permissive → Strict / Permissive
    ///   * Disabled → Strict / Permissive / Disabled
    ///
    /// Downgrades (Strict → Permissive, Strict → Disabled,
    /// Permissive → Disabled) are REJECTED by panicking with a
    /// security-sensitive message. Pre-fix, any caller could flip a
    /// strict context to Permissive at any time, silently bypassing
    /// authentication for every subsequent symbol verification.
    ///
    /// Tests that need to verify Permissive / Disabled behavior must
    /// construct via [`Self::for_testing_with_mode`] instead.
    ///
    /// # Panics
    ///
    /// Panics if `mode` is less strict than the current mode. The
    /// panic message identifies the attempted downgrade for diagnosis.
    /// This is a security-sensitive operation; silent-ignore would
    /// leave the caller believing the downgrade succeeded.
    #[must_use]
    pub fn with_mode(mut self, mode: AuthMode) -> Self {
        assert!(
            mode.is_at_least_as_strict_as(self.mode),
            "br-asupersync-jgpcvp: SecurityContext::with_mode rejects downgrade from {:?} to {:?}. \
             Mode transitions may only INCREASE strictness (Disabled < Permissive < Strict). \
             If this is a test that needs to start in {:?} mode, use \
             SecurityContext::for_testing_with_mode instead.",
            self.mode,
            mode,
            mode,
        );
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
    /// - `Disabled`: Returns `Ok` without checking and leaves the current `verified` flag intact.
    ///
    /// If verification runs, the `verified` flag is updated to match the current result.
    pub fn verify_authenticated_symbol(
        &self,
        auth: &mut AuthenticatedSymbol,
    ) -> Result<(), AuthError> {
        if self.mode == AuthMode::Disabled {
            self.stats.skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let is_valid = auth.tag().verify(&self.key, auth.symbol());
        auth.set_verified(is_valid);

        if is_valid {
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
        // br-asupersync-jgpcvp: with_mode now rejects downgrades, so
        // a Disabled-mode context must be constructed via the test
        // ctor rather than via Strict→Disabled transition.
        let ctx = SecurityContext::for_testing_with_mode(123, AuthMode::Disabled);
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
        // jgpcvp: Strict→Strict is a no-op transition; just use the
        // default-Strict for_testing constructor directly.
        let ctx = SecurityContext::for_testing(123);
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
        // jgpcvp: Strict→Permissive is a downgrade (rejected post-fix);
        // construct directly in Permissive via for_testing_with_mode.
        let ctx = SecurityContext::for_testing_with_mode(123, AuthMode::Permissive);
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
    fn strict_mode_clears_preverified_flag_on_failure() {
        let signing_ctx = SecurityContext::for_testing(123);
        // jgpcvp: Strict→Strict no-op — use default for_testing.
        let verifying_ctx = SecurityContext::for_testing(456);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let mut auth = signing_ctx.sign_symbol(&symbol);
        assert!(auth.is_verified());

        let result = verifying_ctx.verify_authenticated_symbol(&mut auth);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_invalid_tag());
        assert!(
            !auth.is_verified(),
            "failed re-verification must clear any stale trusted state"
        );
        assert_eq!(
            verifying_ctx.stats().verified_fail.load(Ordering::Relaxed),
            1
        );
        assert_eq!(verifying_ctx.stats().verified_ok.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn permissive_mode_clears_preverified_flag_on_failure() {
        let signing_ctx = SecurityContext::for_testing(123);
        // jgpcvp: construct directly in Permissive — no downgrade.
        let verifying_ctx = SecurityContext::for_testing_with_mode(456, AuthMode::Permissive);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let mut auth = signing_ctx.sign_symbol(&symbol);
        assert!(auth.is_verified());

        let result = verifying_ctx.verify_authenticated_symbol(&mut auth);
        assert!(result.is_ok());
        assert!(
            !auth.is_verified(),
            "permissive mode may allow the symbol through, but it must not preserve a stale verified flag"
        );
        assert_eq!(
            verifying_ctx.stats().verified_fail.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            verifying_ctx
                .stats()
                .failures_allowed
                .load(Ordering::Relaxed),
            1
        );
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

    /// Invariant: derived contexts with different purposes produce incompatible keys.
    /// A tag signed by derive_context("transport") must fail verification under
    /// derive_context("storage"), even though both derive from the same primary key.
    #[test]
    fn cross_context_verification_isolation() {
        let primary = SecurityContext::for_testing(99);
        let transport_ctx = primary.derive_context(b"transport");
        let storage_ctx = primary.derive_context(b"storage");

        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![10, 20, 30], SymbolKind::Source);

        // Sign with transport context
        let auth = transport_ctx.sign_symbol(&symbol);
        assert!(auth.is_verified());

        // Simulate receiving this symbol in the storage context
        let mut received = AuthenticatedSymbol::from_parts(auth.clone().into_symbol(), *auth.tag());

        // Verification under storage context must fail (strict mode)
        let result = storage_ctx.verify_authenticated_symbol(&mut received);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_invalid_tag());
        assert!(!received.is_verified());

        // Verification under same transport context must succeed
        let mut received2 =
            AuthenticatedSymbol::from_parts(auth.clone().into_symbol(), *auth.tag());
        transport_ctx
            .verify_authenticated_symbol(&mut received2)
            .expect("same context verification must succeed");
        assert!(received2.is_verified());
    }

    /// Invariant: permissive mode with a valid tag marks the symbol as verified.
    #[test]
    fn permissive_mode_with_valid_tag_marks_verified() {
        // jgpcvp: construct directly in Permissive — no downgrade.
        let ctx = SecurityContext::for_testing_with_mode(42, AuthMode::Permissive);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![5, 6, 7], SymbolKind::Source);

        let auth = ctx.sign_symbol(&symbol);
        let mut received = AuthenticatedSymbol::from_parts(auth.clone().into_symbol(), *auth.tag());
        assert!(!received.is_verified());

        ctx.verify_authenticated_symbol(&mut received)
            .expect("valid tag in permissive mode should succeed");
        assert!(received.is_verified());
        assert_eq!(ctx.stats().verified_ok.load(Ordering::Relaxed), 1);
        assert_eq!(ctx.stats().failures_allowed.load(Ordering::Relaxed), 0);
    }

    /// Invariant: disabled mode does not alter a pre-existing verified=true flag.
    /// If a symbol was signed locally (verified=true), then passed through a disabled
    /// context, the flag should remain true since disabled mode returns early.
    #[test]
    fn disabled_mode_preserves_pre_verified_flag() {
        let signing_ctx = SecurityContext::for_testing(42);
        // jgpcvp: construct directly in Disabled — no downgrade.
        let disabled_ctx = SecurityContext::for_testing_with_mode(42, AuthMode::Disabled);

        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2], SymbolKind::Source);

        let mut auth = signing_ctx.sign_symbol(&symbol);
        assert!(auth.is_verified());

        // Pass through disabled context — flag should remain true
        disabled_ctx
            .verify_authenticated_symbol(&mut auth)
            .expect("disabled mode never errors");
        assert!(
            auth.is_verified(),
            "disabled mode must not clear pre-existing verified flag"
        );
    }

    /// Invariant: cloned contexts share the same Arc<AuthStats>.
    #[test]
    fn cloned_context_shares_stats() {
        let ctx1 = SecurityContext::for_testing(77);
        let ctx2 = ctx1.clone();

        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1], SymbolKind::Source);

        let _ = ctx1.sign_symbol(&symbol);
        let _ = ctx2.sign_symbol(&symbol);

        // Both increments must be visible from either context's stats
        assert_eq!(ctx1.stats().signed.load(Ordering::Relaxed), 2);
        assert_eq!(ctx2.stats().signed.load(Ordering::Relaxed), 2);
    }

    // ─────────────────────────────────────────────────────────────
    // br-asupersync-jgpcvp — with_mode no-downgrade regression tests
    // ─────────────────────────────────────────────────────────────

    /// jgpcvp: Strict→Permissive is a downgrade — MUST panic.
    #[test]
    #[should_panic(expected = "br-asupersync-jgpcvp")]
    fn with_mode_panics_on_strict_to_permissive_downgrade() {
        // for_testing returns a Strict context.
        let _ = SecurityContext::for_testing(1).with_mode(AuthMode::Permissive);
    }

    /// jgpcvp: Strict→Disabled is a downgrade — MUST panic.
    #[test]
    #[should_panic(expected = "br-asupersync-jgpcvp")]
    fn with_mode_panics_on_strict_to_disabled_downgrade() {
        let _ = SecurityContext::for_testing(2).with_mode(AuthMode::Disabled);
    }

    /// jgpcvp: Permissive→Disabled is a downgrade — MUST panic.
    /// Construct directly in Permissive via for_testing_with_mode,
    /// then attempt downgrade.
    #[test]
    #[should_panic(expected = "br-asupersync-jgpcvp")]
    fn with_mode_panics_on_permissive_to_disabled_downgrade() {
        let ctx = SecurityContext::for_testing_with_mode(3, AuthMode::Permissive);
        let _ = ctx.with_mode(AuthMode::Disabled);
    }

    /// jgpcvp: Strict→Strict is a no-op (allowed).
    #[test]
    fn with_mode_allows_strict_to_strict_no_op() {
        let ctx = SecurityContext::for_testing(4).with_mode(AuthMode::Strict);
        assert!(matches!(ctx.mode, AuthMode::Strict));
    }

    /// jgpcvp: Permissive→Strict is an upgrade — allowed.
    #[test]
    fn with_mode_allows_permissive_to_strict_upgrade() {
        let ctx = SecurityContext::for_testing_with_mode(5, AuthMode::Permissive);
        let upgraded = ctx.with_mode(AuthMode::Strict);
        assert!(matches!(upgraded.mode, AuthMode::Strict));
    }

    /// jgpcvp: Disabled→Permissive is an upgrade — allowed.
    #[test]
    fn with_mode_allows_disabled_to_permissive_upgrade() {
        let ctx = SecurityContext::for_testing_with_mode(6, AuthMode::Disabled);
        let upgraded = ctx.with_mode(AuthMode::Permissive);
        assert!(matches!(upgraded.mode, AuthMode::Permissive));
    }

    /// jgpcvp: Disabled→Strict is an upgrade — allowed.
    #[test]
    fn with_mode_allows_disabled_to_strict_upgrade() {
        let ctx = SecurityContext::for_testing_with_mode(7, AuthMode::Disabled);
        let upgraded = ctx.with_mode(AuthMode::Strict);
        assert!(matches!(upgraded.mode, AuthMode::Strict));
    }

    /// jgpcvp: AuthMode::is_at_least_as_strict_as ranking sanity.
    #[test]
    fn auth_mode_strictness_ordering() {
        assert!(AuthMode::Strict.is_at_least_as_strict_as(AuthMode::Strict));
        assert!(AuthMode::Strict.is_at_least_as_strict_as(AuthMode::Permissive));
        assert!(AuthMode::Strict.is_at_least_as_strict_as(AuthMode::Disabled));
        assert!(AuthMode::Permissive.is_at_least_as_strict_as(AuthMode::Permissive));
        assert!(AuthMode::Permissive.is_at_least_as_strict_as(AuthMode::Disabled));
        assert!(AuthMode::Disabled.is_at_least_as_strict_as(AuthMode::Disabled));
        assert!(!AuthMode::Permissive.is_at_least_as_strict_as(AuthMode::Strict));
        assert!(!AuthMode::Disabled.is_at_least_as_strict_as(AuthMode::Permissive));
        assert!(!AuthMode::Disabled.is_at_least_as_strict_as(AuthMode::Strict));
    }

    /// Invariant: derived contexts get fresh stats (not shared with parent).
    #[test]
    fn derived_context_has_independent_stats() {
        let primary = SecurityContext::for_testing(42);
        let derived = primary.derive_context(b"child");

        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1], SymbolKind::Source);

        let _ = primary.sign_symbol(&symbol);
        assert_eq!(primary.stats().signed.load(Ordering::Relaxed), 1);
        assert_eq!(
            derived.stats().signed.load(Ordering::Relaxed),
            0,
            "derived context must have independent stats"
        );
    }
}
