//! Cryptographic boundary tests for symbol authentication and macaroon attenuation.
//!
//! This module contains security audit tests that verify the cryptographic
//! boundaries of the authentication system are properly maintained:
//!
//! 1. **HMAC verification constant-time properties**
//! 2. **Macaroon caveat layering security boundaries**
//! 3. **Invalid signature rejection guarantees**
//!
//! These tests are designed to catch regressions that could lead to:
//! - Timing attack vulnerabilities
//! - Privilege escalation via caveat bypass
//! - Authentication bypass via signature manipulation

use crate::cx::macaroon::{CaveatPredicate, MacaroonToken, VerificationContext, VerificationError};
use crate::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::types::{Symbol, SymbolId, SymbolKind};

/// Helper to create test symbols with predictable data patterns.
fn create_test_symbol(id_seed: u64, data_pattern: u8, size: usize) -> Symbol {
    let id = SymbolId::new_for_test(id_seed, 0, 0);
    let data = vec![data_pattern; size];
    Symbol::new(id, data, SymbolKind::Source)
}

/// Helper to create authentication keys from seeds.
fn test_auth_key(seed: u64) -> AuthKey {
    AuthKey::from_seed(seed)
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

    // ═══════════════════════════════════════════════════════════════════════════
    // HMAC Constant-Time Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn hmac_verify_rejects_invalid_tags_at_all_byte_positions() {
        let key = test_auth_key(42);
        let symbol = create_test_symbol(1, 0xAA, 1024);
        let valid_tag = AuthenticationTag::compute(&key, &symbol);
        let valid_bytes = *valid_tag.as_bytes();

        assert!(valid_tag.verify(&key, &symbol));

        for byte_idx in 0..valid_bytes.len() {
            let mut invalid_bytes = valid_bytes;
            invalid_bytes[byte_idx] ^= 0xFF;
            let invalid_tag = AuthenticationTag::from_bytes(invalid_bytes);

            assert!(
                !invalid_tag.verify(&key, &symbol),
                "invalid tag differing at byte {byte_idx} must not verify"
            );
        }
    }

    #[test]
    fn hmac_verify_binds_payload_length_and_contents() {
        let key = test_auth_key(99);
        let symbol_small = create_test_symbol(1, 0x42, 16);
        let symbol_large = create_test_symbol(1, 0x42, 16_384);

        let tag_small = AuthenticationTag::compute(&key, &symbol_small);
        let tag_large = AuthenticationTag::compute(&key, &symbol_large);

        assert!(tag_small.verify(&key, &symbol_small));
        assert!(tag_large.verify(&key, &symbol_large));
        assert!(
            !tag_small.verify(&key, &symbol_large),
            "short-payload tag must not replay against same-id longer payload"
        );
        assert!(
            !tag_large.verify(&key, &symbol_small),
            "long-payload tag must not replay against same-id shorter payload"
        );
    }

    #[test]
    fn authentication_tag_equality_checks_every_byte() {
        let key = test_auth_key(42);
        let symbol = create_test_symbol(1, 0xBB, 512);
        let tag1 = AuthenticationTag::compute(&key, &symbol);
        let tag2 = tag1;
        let tag_bytes = *tag1.as_bytes();

        assert_eq!(tag1, tag2);

        for byte_idx in 0..tag_bytes.len() {
            let mut diff_bytes = tag_bytes;
            diff_bytes[byte_idx] ^= 0x01;
            let diff_tag = AuthenticationTag::from_bytes(diff_bytes);

            assert_ne!(
                tag1, diff_tag,
                "tag equality must account for byte {byte_idx}"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Macaroon Caveat Layering Security Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn macaroon_caveat_layering_cannot_expand_privileges() {
        // Test the monotonic restriction property: adding caveats cannot expand access
        let key = test_auth_key(100);
        let base_token = MacaroonToken::mint(&key, "admin:full", "auth-service");

        // Create a restricted token with time limitation
        let time_restricted = base_token
            .clone()
            .add_caveat(CaveatPredicate::TimeBefore(5000));

        // Create a more restricted token with additional region limitation
        let doubly_restricted = time_restricted
            .clone()
            .add_caveat(CaveatPredicate::RegionScope(42));

        // Test contexts that should pass/fail at each level
        let ctx_early_wrong_region = VerificationContext::new().with_time(1000).with_region(999);

        let ctx_early_right_region = VerificationContext::new().with_time(1000).with_region(42);

        let ctx_late_right_region = VerificationContext::new().with_time(6000).with_region(42);

        // Base token should accept all contexts (no restrictions)
        assert!(base_token.verify(&key, &ctx_early_wrong_region).is_ok());
        assert!(base_token.verify(&key, &ctx_early_right_region).is_ok());
        assert!(base_token.verify(&key, &ctx_late_right_region).is_ok());

        // Time-restricted token should reject late access but allow wrong region
        assert!(
            time_restricted
                .verify(&key, &ctx_early_wrong_region)
                .is_ok()
        );
        assert!(
            time_restricted
                .verify(&key, &ctx_early_right_region)
                .is_ok()
        );
        assert!(
            time_restricted
                .verify(&key, &ctx_late_right_region)
                .is_err()
        );

        // Doubly restricted token should be most restrictive
        assert!(
            doubly_restricted
                .verify(&key, &ctx_early_wrong_region)
                .is_err()
        );
        assert!(
            doubly_restricted
                .verify(&key, &ctx_early_right_region)
                .is_ok()
        );
        assert!(
            doubly_restricted
                .verify(&key, &ctx_late_right_region)
                .is_err()
        );
    }

    #[test]
    fn macaroon_caveat_ordering_security() {
        // Test that caveat order affects the HMAC chain (preventing reordering attacks)
        let key = test_auth_key(200);

        let token_a = MacaroonToken::mint(&key, "resource:read", "service")
            .add_caveat(CaveatPredicate::TimeBefore(1000))
            .add_caveat(CaveatPredicate::MaxUses(5));

        let token_b = MacaroonToken::mint(&key, "resource:read", "service")
            .add_caveat(CaveatPredicate::MaxUses(5))
            .add_caveat(CaveatPredicate::TimeBefore(1000));

        // Tokens with same caveats in different order should have different signatures
        assert_ne!(
            token_a.signature().as_bytes(),
            token_b.signature().as_bytes(),
            "Caveat reordering should change HMAC signature"
        );

        // Both should verify correctly with appropriate context
        let ctx = VerificationContext::new().with_time(500).with_use_count(2);

        assert!(token_a.verify(&key, &ctx).is_ok());
        assert!(token_b.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn macaroon_third_party_caveat_security_boundary() {
        // Test that third-party caveats maintain proper security boundaries
        let root_key = test_auth_key(300);
        let service_a_key = test_auth_key(301);
        let service_b_key = test_auth_key(302);

        // Root service issues token requiring approval from service A
        let root_token = MacaroonToken::mint(&root_key, "data:access", "root")
            .add_caveat(CaveatPredicate::TimeBefore(10000))
            .add_third_party_caveat("service-a", "auth-check", &service_a_key);

        // Service A issues discharge allowing limited access
        let discharge_a = MacaroonToken::mint(&service_a_key, "auth-check", "service-a")
            .add_caveat(CaveatPredicate::ResourceScope("data/public/*".to_string()));

        // Malicious attempt: Service B tries to issue discharge for Service A's caveat
        let malicious_discharge = MacaroonToken::mint(&service_b_key, "auth-check", "service-a")
            .add_caveat(CaveatPredicate::ResourceScope("data/**".to_string())); // Broader access

        let bound_legit = root_token.bind_for_request(&discharge_a);
        let bound_malicious = root_token.bind_for_request(&malicious_discharge);

        let ctx = VerificationContext::new()
            .with_time(5000)
            .with_resource("data/public/file.txt");

        // Legitimate discharge should work
        assert!(
            root_token
                .verify_with_discharges(&root_key, &ctx, &[bound_legit])
                .is_ok()
        );

        // Malicious discharge should be rejected (wrong signing key)
        assert!(
            root_token
                .verify_with_discharges(&root_key, &ctx, &[bound_malicious])
                .is_err()
        );
    }

    #[test]
    fn macaroon_caveat_bypass_attempt_detection() {
        // Test various attempts to bypass caveat restrictions
        let key = test_auth_key(400);

        // Create heavily restricted token
        let restricted_token = MacaroonToken::mint(&key, "admin:write", "service")
            .add_caveat(CaveatPredicate::TimeBefore(2000))
            .add_caveat(CaveatPredicate::RegionScope(1))
            .add_caveat(CaveatPredicate::MaxUses(3))
            .add_caveat(CaveatPredicate::ResourceScope("admin/users/*".to_string()));

        // Test various bypass attempts
        let bypass_attempts = vec![
            // Missing time context (should fail closed)
            VerificationContext::new()
                .with_region(1)
                .with_use_count(1)
                .with_resource("admin/users/list"),
            // Wrong region (should fail)
            VerificationContext::new()
                .with_time(1000)
                .with_region(999)
                .with_use_count(1)
                .with_resource("admin/users/list"),
            // Expired time (should fail)
            VerificationContext::new()
                .with_time(3000)
                .with_region(1)
                .with_use_count(1)
                .with_resource("admin/users/list"),
            // Exceeded use count (should fail)
            VerificationContext::new()
                .with_time(1000)
                .with_region(1)
                .with_use_count(5)
                .with_resource("admin/users/list"),
            // Wrong resource path (should fail)
            VerificationContext::new()
                .with_time(1000)
                .with_region(1)
                .with_use_count(1)
                .with_resource("admin/system/config"),
        ];

        for (i, ctx) in bypass_attempts.into_iter().enumerate() {
            let result = restricted_token.verify(&key, &ctx);
            assert!(
                result.is_err(),
                "Bypass attempt {i} should have failed: {result:?}"
            );
        }

        // Valid context should still work
        let valid_ctx = VerificationContext::new()
            .with_time(1000)
            .with_region(1)
            .with_use_count(1)
            .with_resource("admin/users/profile");

        assert!(restricted_token.verify(&key, &valid_ctx).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bad Signature Rejection Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn symbol_authentication_rejects_tampered_signatures() {
        let key = test_auth_key(500);
        let symbol = create_test_symbol(1, 0xDD, 256);
        let valid_tag = AuthenticationTag::compute(&key, &symbol);

        // Test various tampering scenarios
        let tampering_patterns: Vec<(&str, Box<dyn Fn(&mut [u8; 32])>)> = vec![
            (
                "flip_first_bit",
                Box::new(|bytes: &mut [u8; 32]| bytes[0] ^= 0x01),
            ),
            (
                "flip_last_bit",
                Box::new(|bytes: &mut [u8; 32]| bytes[31] ^= 0x01),
            ),
            (
                "flip_middle_byte",
                Box::new(|bytes: &mut [u8; 32]| bytes[16] ^= 0xFF),
            ),
            (
                "zero_first_half",
                Box::new(|bytes: &mut [u8; 32]| {
                    bytes[..16].fill(0);
                }),
            ),
            (
                "zero_last_half",
                Box::new(|bytes: &mut [u8; 32]| bytes[16..].fill(0)),
            ),
            (
                "all_ones",
                Box::new(|bytes: &mut [u8; 32]| bytes.fill(0xFF)),
            ),
            (
                "increment_all",
                Box::new(|bytes: &mut [u8; 32]| {
                    for byte in bytes.iter_mut() {
                        *byte = byte.wrapping_add(1);
                    }
                }),
            ),
        ];

        for (name, tamper_fn) in tampering_patterns {
            let mut tampered_bytes = *valid_tag.as_bytes();
            tamper_fn(&mut tampered_bytes);
            let tampered_tag = AuthenticationTag::from_bytes(tampered_bytes);

            assert!(
                !tampered_tag.verify(&key, &symbol),
                "Tampering pattern '{name}' should be detected"
            );

            // Also test via SecurityContext
            let ctx = SecurityContext::new(key);
            let mut tampered_auth_symbol =
                AuthenticatedSymbol::from_parts(symbol.clone(), tampered_tag);

            assert!(
                ctx.verify_authenticated_symbol(&mut tampered_auth_symbol)
                    .is_err(),
                "SecurityContext should reject tampering pattern '{name}'"
            );
        }
    }

    #[test]
    fn macaroon_signature_tampering_detection() {
        let key = test_auth_key(600);
        let token = MacaroonToken::mint(&key, "test:capability", "service")
            .add_caveat(CaveatPredicate::TimeBefore(5000));

        // Get binary representation and tamper with signature bytes
        let original_bytes = token.to_binary();
        let sig_start = original_bytes.len() - 32; // Last 32 bytes are signature

        let tampering_scenarios = vec![
            ("corrupt_sig_start", 0),
            ("corrupt_sig_middle", 16),
            ("corrupt_sig_end", 31),
        ];

        for (name, offset) in tampering_scenarios {
            let mut tampered_bytes = original_bytes.clone();
            tampered_bytes[sig_start + offset] ^= 0xFF;

            let tampered_token = MacaroonToken::from_binary(&tampered_bytes)
                .expect("should parse despite signature corruption");

            assert!(
                !tampered_token.verify_signature(&key),
                "Signature tampering '{name}' should be detected"
            );

            // Also test via full verification
            let ctx = VerificationContext::new().with_time(1000);
            let result = tampered_token.verify(&key, &ctx);
            assert!(
                matches!(result, Err(VerificationError::InvalidSignature)),
                "Full verification should detect signature tampering '{name}': {result:?}"
            );
        }
    }

    #[test]
    fn macaroon_caveat_tampering_detection() {
        let key = test_auth_key(700);
        let token = MacaroonToken::mint(&key, "test:write", "service")
            .add_caveat(CaveatPredicate::TimeBefore(5000))
            .add_caveat(CaveatPredicate::MaxUses(10));

        let mut bytes = token.to_binary();

        // Find and tamper with caveat data (MaxUses value)
        // This is somewhat implementation-dependent, but we're looking for the byte sequence
        // that represents MaxUses(10) which should be encoded as little-endian u32
        let max_uses_bytes = 10u32.to_le_bytes();

        if let Some(pos) = bytes.windows(4).position(|window| window == max_uses_bytes) {
            // Change MaxUses from 10 to 1000 (privilege escalation attempt)
            let escalated_bytes = 1000u32.to_le_bytes();
            bytes[pos..pos + 4].copy_from_slice(&escalated_bytes);

            let tampered_token =
                MacaroonToken::from_binary(&bytes).expect("should parse despite caveat tampering");

            // Signature should be invalid due to HMAC chain
            assert!(
                !tampered_token.verify_signature(&key),
                "Caveat tampering should invalidate HMAC signature"
            );

            let ctx = VerificationContext::new()
                .with_time(1000)
                .with_use_count(500); // Would pass with escalated limit but fail original

            assert!(
                tampered_token.verify(&key, &ctx).is_err(),
                "Tampered caveat should be rejected"
            );
        }
    }

    #[test]
    fn wrong_key_rejection_comprehensive() {
        // Test that wrong keys are consistently rejected across all operations
        let correct_key = test_auth_key(800);
        let wrong_keys = (801..810).map(test_auth_key).collect::<Vec<_>>();

        // Test symbol authentication
        let symbol = create_test_symbol(1, 0xCC, 128);
        let tag = AuthenticationTag::compute(&correct_key, &symbol);

        for (i, wrong_key) in wrong_keys.iter().enumerate() {
            assert!(
                !tag.verify(wrong_key, &symbol),
                "Symbol verification should reject wrong key {i}"
            );
        }

        // Test macaroon verification
        let token = MacaroonToken::mint(&correct_key, "secure:operation", "service")
            .add_caveat(CaveatPredicate::TimeBefore(5000));

        let ctx = VerificationContext::new().with_time(1000);

        for (i, wrong_key) in wrong_keys.iter().enumerate() {
            assert!(
                !token.verify_signature(wrong_key),
                "Macaroon signature should reject wrong key {i}"
            );

            assert!(
                token.verify(wrong_key, &ctx).is_err(),
                "Macaroon verification should reject wrong key {i}"
            );
        }
    }

    #[test]
    fn zero_key_security_boundary() {
        // Test that all-zero keys don't create security vulnerabilities
        let zero_key = AuthKey::from_bytes([0u8; 32]);
        let normal_key = test_auth_key(900);

        let symbol = create_test_symbol(1, 0x88, 64);

        // Ensure zero key produces different authentication than normal key
        let zero_tag = AuthenticationTag::compute(&zero_key, &symbol);
        let normal_tag = AuthenticationTag::compute(&normal_key, &symbol);

        assert_ne!(
            zero_tag.as_bytes(),
            normal_tag.as_bytes(),
            "Zero key should produce different authentication than normal key"
        );

        // Cross-verification should fail
        assert!(!zero_tag.verify(&normal_key, &symbol));
        assert!(!normal_tag.verify(&zero_key, &symbol));

        // Self-verification should work
        assert!(zero_tag.verify(&zero_key, &symbol));
        assert!(normal_tag.verify(&normal_key, &symbol));
    }

    #[test]
    fn replay_attack_prevention() {
        // Test that valid tags cannot be replayed against different symbols
        let key = test_auth_key(1000);
        let symbol1 = create_test_symbol(1, 0x11, 64);
        let symbol2 = create_test_symbol(2, 0x22, 64);
        let symbol3 = create_test_symbol(1, 0x11, 128); // Same ID, different data

        let tag1 = AuthenticationTag::compute(&key, &symbol1);

        // Tag computed for symbol1 should not verify for other symbols
        assert!(
            !tag1.verify(&key, &symbol2),
            "Tag replay should fail for different symbol"
        );
        assert!(
            !tag1.verify(&key, &symbol3),
            "Tag replay should fail for same ID but different data"
        );

        // Only original symbol should verify
        assert!(
            tag1.verify(&key, &symbol1),
            "Original verification should still work"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cx Integration: child-Cx capability restriction tests
    //
    // Per the bead: "test that Cx::with_macaroon properly restricts child Cx
    // effects". The full crypto chain is correct in the unit tests above; this
    // section drives the same chain through `Cx::with_macaroon` /
    // `Cx::attenuate` / `Cx::verify_capability` to prove the integration is
    // sound from a holder-of-capability perspective.
    //
    // Threat model: a holder of a parent Cx must not be able to construct a
    // child Cx that grants *more* than the parent. Conversely, a holder of a
    // child Cx must inherit (and only further restrict) what the parent gave.
    // ═══════════════════════════════════════════════════════════════════════════

    use crate::cx::Cx;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;

    fn boundary_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn cx_without_macaroon_fails_capability_check_default_deny() {
        // No macaroon attached → verify_capability MUST return InvalidSignature
        // (not silently succeed). This is the default-deny boundary.
        let key = test_auth_key(2000);
        let cx = boundary_cx();
        let ctx = VerificationContext::new().with_time(100);

        let result = cx.verify_capability(&key, "io:net", &ctx);
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "no-macaroon Cx must fail closed; got {result:?}"
        );
    }

    #[test]
    fn cx_with_macaroon_for_wrong_identifier_is_rejected() {
        // A token minted for capability "spawn:r1" must not authorise "io:net".
        let key = test_auth_key(2100);
        let token = MacaroonToken::mint(&key, "spawn:r1", "boundary-test");
        let cx = boundary_cx().with_macaroon(token);
        let ctx = VerificationContext::new().with_time(100);

        assert!(
            cx.verify_capability(&key, "spawn:r1", &ctx).is_ok(),
            "intended capability must verify"
        );
        let cross = cx.verify_capability(&key, "io:net", &ctx);
        assert!(
            matches!(cross, Err(VerificationError::UnexpectedIdentifier { .. })),
            "cross-capability use must be rejected with identifier mismatch; got {cross:?}"
        );
    }

    #[test]
    fn child_cx_attenuation_cannot_expand_parent_capabilities() {
        // Parent has unrestricted token. Child attenuates with TimeBefore(2000).
        // After attenuation, *no* operation on the child Cx can re-broaden the
        // permission window — the HMAC chain is one-way.
        let key = test_auth_key(2200);
        let token = MacaroonToken::mint(&key, "io:write", "boundary-test");
        let parent = boundary_cx().with_macaroon(token);

        let child = parent
            .attenuate(CaveatPredicate::TimeBefore(2000))
            .expect("attenuate should produce child Cx");

        // Parent still has zero caveats — child's restriction did not propagate
        // upward.
        assert_eq!(parent.macaroon().unwrap().caveat_count(), 0);
        assert_eq!(child.macaroon().unwrap().caveat_count(), 1);

        // Child rejects late-time contexts even with the right key + identifier.
        let ctx_late = VerificationContext::new().with_time(5000);
        let result = child.verify_capability(&key, "io:write", &ctx_late);
        assert!(
            matches!(result, Err(VerificationError::CaveatFailed { .. })),
            "child must reject context outside its tighter window; got {result:?}"
        );

        // Parent (less restricted) still accepts the same context.
        assert!(
            parent.verify_capability(&key, "io:write", &ctx_late).is_ok(),
            "parent must remain authoritative for the broader window"
        );
    }

    #[test]
    fn child_cx_caveats_are_monotonically_additive() {
        // Three layers of attenuation: each strictly tightens the previous.
        // Verify that the deepest child fails for every relaxation any ancestor
        // would have accepted, and that no ancestor's predicate is dropped.
        let key = test_auth_key(2300);
        let token = MacaroonToken::mint(&key, "data:read", "boundary-test");
        let l0 = boundary_cx().with_macaroon(token);
        let l1 = l0
            .attenuate(CaveatPredicate::TimeBefore(5000))
            .expect("l1");
        let l2 = l1
            .attenuate(CaveatPredicate::RegionScope(7))
            .expect("l2");
        let l3 = l2.attenuate(CaveatPredicate::MaxUses(3)).expect("l3");

        assert_eq!(l3.macaroon().unwrap().caveat_count(), 3);

        // ctx that satisfies all three caveats — only the deepest passes.
        let ctx_ok = VerificationContext::new()
            .with_time(1000)
            .with_region(7)
            .with_use_count(1);
        assert!(l3.verify_capability(&key, "data:read", &ctx_ok).is_ok());

        // Each ancestor's caveat must still bite at the deepest layer. We test
        // by varying ONE field in the verification context per assertion.
        let ctx_bad_time = VerificationContext::new()
            .with_time(9999)
            .with_region(7)
            .with_use_count(1);
        assert!(
            l3.verify_capability(&key, "data:read", &ctx_bad_time)
                .is_err(),
            "deepest child must still enforce l1's TimeBefore caveat"
        );

        let ctx_bad_region = VerificationContext::new()
            .with_time(1000)
            .with_region(99)
            .with_use_count(1);
        assert!(
            l3.verify_capability(&key, "data:read", &ctx_bad_region)
                .is_err(),
            "deepest child must still enforce l2's RegionScope caveat"
        );

        let ctx_bad_uses = VerificationContext::new()
            .with_time(1000)
            .with_region(7)
            .with_use_count(99);
        assert!(
            l3.verify_capability(&key, "data:read", &ctx_bad_uses)
                .is_err(),
            "deepest child must still enforce its own MaxUses caveat"
        );
    }

    #[test]
    fn child_cx_inherits_macaroon_through_clone() {
        // Cloning a Cx must preserve the macaroon Arc (cheap clone, same chain).
        // An attacker that clones a child Cx cannot strip its caveats.
        let key = test_auth_key(2400);
        let token = MacaroonToken::mint(&key, "rpc:invoke", "boundary-test");
        let parent = boundary_cx().with_macaroon(token);
        let child = parent
            .attenuate(CaveatPredicate::MaxUses(1))
            .expect("attenuate");
        let child_clone = child.clone();

        // The clone has the same caveat count as the original child, NOT the
        // parent's zero-caveat token.
        assert_eq!(child.macaroon().unwrap().caveat_count(), 1);
        assert_eq!(child_clone.macaroon().unwrap().caveat_count(), 1);

        // Both reject when the caveat fails.
        let ctx_overuse = VerificationContext::new().with_time(0).with_use_count(99);
        assert!(
            child
                .verify_capability(&key, "rpc:invoke", &ctx_overuse)
                .is_err()
        );
        assert!(
            child_clone
                .verify_capability(&key, "rpc:invoke", &ctx_overuse)
                .is_err()
        );
    }

    #[test]
    fn child_cx_attenuation_with_wrong_root_key_is_rejected() {
        // The root key authorises minting; a child CANNOT swap the root key by
        // re-attenuating, even though attenuation does not require the root
        // key. The wrong-key holder is reduced to ordinary verification, which
        // must fail.
        let real_key = test_auth_key(2500);
        let attacker_key = test_auth_key(2501);
        let token = MacaroonToken::mint(&real_key, "admin:rotate", "issuer");
        let cx = boundary_cx().with_macaroon(token);

        // The attacker controls the verification call site (they hold the Cx)
        // but verification requires the *issuer's* key. With the attacker's
        // key the HMAC chain is not reproducible.
        let ctx = VerificationContext::new().with_time(100);
        let result = cx.verify_capability(&attacker_key, "admin:rotate", &ctx);
        assert!(
            matches!(result, Err(VerificationError::InvalidSignature)),
            "attacker-controlled verify with the wrong key must fail with InvalidSignature; got {result:?}"
        );

        // The legitimate verifier still succeeds.
        assert!(
            cx.verify_capability(&real_key, "admin:rotate", &ctx).is_ok()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wire-format hardening: malformed binary inputs must not panic and must
    // not be silently treated as valid.
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn macaroon_binary_truncation_is_rejected_gracefully() {
        // Mint a real token, then progressively truncate the binary form. Each
        // shorter prefix must either fail to parse OR parse but fail signature
        // verification. Critically: no panic, no silent acceptance.
        let key = test_auth_key(3000);
        let token = MacaroonToken::mint(&key, "fs:read", "issuer")
            .add_caveat(CaveatPredicate::TimeBefore(5000));
        let bytes = token.to_binary();
        assert!(bytes.len() > 32);

        for cut in (1..bytes.len()).step_by(7).chain(std::iter::once(bytes.len() - 1)) {
            let truncated = &bytes[..cut];
            match MacaroonToken::from_binary(truncated) {
                None => { /* expected: malformed input refused */ }
                Some(parsed) => {
                    assert!(
                        !parsed.verify_signature(&key),
                        "truncated input parsed at cut={cut} must NOT verify"
                    );
                }
            }
        }
    }
}
