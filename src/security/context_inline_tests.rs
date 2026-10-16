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
    fn replica_authorization_basic_validation() {
        let ctx = SecurityContext::for_testing(42);

        assert!(!ctx.is_replica_authorized("replica-1", None));

        ctx.authorize_replica("replica-1", None)
            .expect("global replica authorization should mint");
        ctx.authorize_replica("node-auth", Some("region-a"))
            .expect("region-scoped replica authorization should mint");

        assert!(ctx.is_replica_authorized("replica-1", None));
        assert!(ctx.is_replica_authorized("replica-1", Some("any-region")));
        assert!(ctx.is_replica_authorized("node-auth", Some("region-a")));
        assert!(!ctx.is_replica_authorized("node-auth", Some("region-b")));
        assert!(!ctx.is_replica_authorized("node-auth", None));

        assert!(!ctx.is_replica_authorized("", None));
        assert!(!ctx.is_replica_authorized("../../../etc/passwd", None));
        assert!(!ctx.is_replica_authorized("replica\0null", None));
        assert!(!ctx.is_replica_authorized(&"x".repeat(300), None)); // too long
    }

    #[test]
    fn replica_authorization_import_rejects_tampered_records() {
        let issuer = SecurityContext::for_testing(42);
        let verifier = SecurityContext::for_testing(42);
        let mut record = issuer
            .authorize_replica("replica-2", Some("region-a"))
            .expect("issuer should mint record");

        verifier
            .import_replica_authorization(record.clone())
            .expect("matching verifier key should accept record");
        assert!(verifier.is_replica_authorized("replica-2", Some("region-a")));

        record.signature[0] ^= 0x80;
        let error = verifier
            .import_replica_authorization(record)
            .expect_err("tampered signature must fail closed");
        assert_eq!(error.kind(), AuthErrorKind::InvalidTag);
    }

    #[test]
    fn replica_authorization_revocation_removes_membership() {
        let ctx = SecurityContext::for_testing(42);
        ctx.authorize_replica("replica-3", None)
            .expect("authorization should mint");

        assert!(ctx.is_replica_authorized("replica-3", None));
        assert!(ctx.revoke_replica_authorization("replica-3"));
        assert!(!ctx.is_replica_authorized("replica-3", None));
        assert!(!ctx.revoke_replica_authorization("replica-3"));
    }

    #[test]
    fn replica_authorization_debug_redacts_signature() {
        let ctx = SecurityContext::for_testing(42);
        let record = ctx
            .authorize_replica("replica-debug", Some("region-debug"))
            .expect("authorization should mint");
        let raw_signature_debug = format!("{:?}", record.signature);

        let record_debug = format!("{record:?}");
        assert!(record_debug.contains("ReplicaAuthorization"));
        assert!(record_debug.contains("replica-debug"));
        assert!(record_debug.contains("region-debug"));
        assert!(record_debug.contains("<redacted>"));
        assert!(
            !record_debug.contains(&raw_signature_debug),
            "ReplicaAuthorization Debug must not expose the bearer signature: {record_debug}"
        );

        let context_debug = format!("{ctx:?}");
        assert!(
            !context_debug.contains(&raw_signature_debug),
            "SecurityContext Debug must not expose stored replica authorization signatures: {context_debug}"
        );
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
    fn sign_symbol_tag_matches_authenticated_symbol_tag() {
        let ctx = SecurityContext::for_testing(123);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let tag = ctx.sign_symbol_tag(&symbol);
        let auth = ctx.sign_symbol(&symbol);

        assert_eq!(tag.as_bytes(), auth.tag().as_bytes());
        assert_eq!(ctx.stats().signed.load(Ordering::Relaxed), 2);
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
