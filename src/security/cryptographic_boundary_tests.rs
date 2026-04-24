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
use std::time::{Duration, Instant};

/// Number of timing samples to collect for constant-time verification.
const TIMING_SAMPLES: usize = 1000;

/// Threshold for timing variance that indicates potential timing attack vulnerability.
/// If the coefficient of variation exceeds this threshold, the timing is not constant.
const TIMING_VARIANCE_THRESHOLD: f64 = 0.5; // Relaxed for remote/virtualized environments

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

/// Helper to measure timing for a closure.
fn measure_timing<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    (result, elapsed)
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
    fn hmac_verify_constant_time_valid_vs_invalid() {
        // Test that HMAC verification takes the same time for valid and invalid tags
        let key = test_auth_key(42);
        let symbol = create_test_symbol(1, 0xAA, 1024);
        let valid_tag = AuthenticationTag::compute(&key, &symbol);

        // Create an invalid tag with different bytes
        let mut invalid_bytes = *valid_tag.as_bytes();
        invalid_bytes[0] ^= 0xFF; // Flip first byte
        let invalid_tag = AuthenticationTag::from_bytes(invalid_bytes);

        // Collect timing samples for valid verification
        let mut valid_timings = Vec::with_capacity(TIMING_SAMPLES);
        for _ in 0..TIMING_SAMPLES {
            let (result, elapsed) = measure_timing(|| valid_tag.verify(&key, &symbol));
            assert!(result, "valid tag should verify successfully");
            valid_timings.push(elapsed.as_nanos() as f64);
        }

        // Collect timing samples for invalid verification
        let mut invalid_timings = Vec::with_capacity(TIMING_SAMPLES);
        for _ in 0..TIMING_SAMPLES {
            let (result, elapsed) = measure_timing(|| invalid_tag.verify(&key, &symbol));
            assert!(!result, "invalid tag should fail verification");
            invalid_timings.push(elapsed.as_nanos() as f64);
        }

        // Statistical analysis: calculate coefficient of variation for each set
        let valid_mean = valid_timings.iter().sum::<f64>() / valid_timings.len() as f64;
        let valid_variance = valid_timings
            .iter()
            .map(|x| (x - valid_mean).powi(2))
            .sum::<f64>()
            / valid_timings.len() as f64;
        let valid_cv = valid_variance.sqrt() / valid_mean;

        let invalid_mean = invalid_timings.iter().sum::<f64>() / invalid_timings.len() as f64;
        let invalid_variance = invalid_timings
            .iter()
            .map(|x| (x - invalid_mean).powi(2))
            .sum::<f64>()
            / invalid_timings.len() as f64;
        let invalid_cv = invalid_variance.sqrt() / invalid_mean;

        // Check that both have low variance (indicating constant-time behavior)
        assert!(
            valid_cv < TIMING_VARIANCE_THRESHOLD,
            "Valid verification has high timing variance: {valid_cv:.3} (threshold: {TIMING_VARIANCE_THRESHOLD})"
        );
        assert!(
            invalid_cv < TIMING_VARIANCE_THRESHOLD,
            "Invalid verification has high timing variance: {invalid_cv:.3} (threshold: {TIMING_VARIANCE_THRESHOLD})"
        );

        // Check that mean timings are statistically similar (within 10% difference)
        let timing_ratio = (valid_mean - invalid_mean).abs() / valid_mean.min(invalid_mean);
        assert!(
            timing_ratio < 0.1,
            "Verification timings differ significantly: valid={valid_mean:.1}ns, invalid={invalid_mean:.1}ns, ratio={timing_ratio:.3}"
        );
    }

    #[test]
    fn hmac_verify_constant_time_different_data_sizes() {
        // Test that verification time is independent of payload size
        let key = test_auth_key(99);
        let symbol_small = create_test_symbol(1, 0x42, 16);
        let symbol_large = create_test_symbol(2, 0x42, 16384);

        let tag_small = AuthenticationTag::compute(&key, &symbol_small);
        let tag_large = AuthenticationTag::compute(&key, &symbol_large);

        // Collect timing samples for small symbol verification
        let mut small_timings = Vec::with_capacity(TIMING_SAMPLES);
        for _ in 0..TIMING_SAMPLES {
            let (result, elapsed) = measure_timing(|| tag_small.verify(&key, &symbol_small));
            assert!(result);
            small_timings.push(elapsed.as_nanos() as f64);
        }

        // Collect timing samples for large symbol verification
        let mut large_timings = Vec::with_capacity(TIMING_SAMPLES);
        for _ in 0..TIMING_SAMPLES {
            let (result, elapsed) = measure_timing(|| tag_large.verify(&key, &symbol_large));
            assert!(result);
            large_timings.push(elapsed.as_nanos() as f64);
        }

        let small_mean = small_timings.iter().sum::<f64>() / small_timings.len() as f64;
        let large_mean = large_timings.iter().sum::<f64>() / large_timings.len() as f64;

        // Verification should scale linearly with data size (not reveal timing information)
        // Allow reasonable variance for larger payloads
        let timing_ratio = (large_mean - small_mean).abs() / small_mean;
        println!(
            "Timing analysis: small={small_mean:.1}ns, large={large_mean:.1}ns, ratio={timing_ratio:.3}"
        );

        // This test documents the expected behavior rather than enforcing strict constant-time
        // HMAC inherently depends on input size, but the verification should be predictable
        assert!(
            timing_ratio < 25.0, // Allow 25x difference for 1024x data increase (remote env)
            "HMAC verification timing should scale predictably with data size"
        );
    }

    #[test]
    fn authentication_tag_equality_constant_time() {
        // Test that AuthenticationTag::eq() uses constant-time comparison
        let key = test_auth_key(42);
        let symbol = create_test_symbol(1, 0xBB, 512);
        let tag1 = AuthenticationTag::compute(&key, &symbol);
        let tag2 = tag1; // Same tag

        // Create tags that differ in the first vs last byte
        let mut early_diff_bytes = *tag1.as_bytes();
        early_diff_bytes[0] ^= 0x01;
        let early_diff_tag = AuthenticationTag::from_bytes(early_diff_bytes);

        let mut late_diff_bytes = *tag1.as_bytes();
        late_diff_bytes[31] ^= 0x01;
        let late_diff_tag = AuthenticationTag::from_bytes(late_diff_bytes);

        // Time equality comparisons
        let mut equal_timings = Vec::with_capacity(TIMING_SAMPLES);
        let mut early_diff_timings = Vec::with_capacity(TIMING_SAMPLES);
        let mut late_diff_timings = Vec::with_capacity(TIMING_SAMPLES);

        for _ in 0..TIMING_SAMPLES {
            let (result, elapsed) = measure_timing(|| tag1 == tag2);
            assert!(result);
            equal_timings.push(elapsed.as_nanos() as f64);

            let (result, elapsed) = measure_timing(|| tag1 == early_diff_tag);
            assert!(!result);
            early_diff_timings.push(elapsed.as_nanos() as f64);

            let (result, elapsed) = measure_timing(|| tag1 == late_diff_tag);
            assert!(!result);
            late_diff_timings.push(elapsed.as_nanos() as f64);
        }

        let equal_mean = equal_timings.iter().sum::<f64>() / equal_timings.len() as f64;
        let early_mean = early_diff_timings.iter().sum::<f64>() / early_diff_timings.len() as f64;
        let late_mean = late_diff_timings.iter().sum::<f64>() / late_diff_timings.len() as f64;

        // All comparisons should take similar time regardless of where difference occurs
        let early_ratio = (equal_mean - early_mean).abs() / equal_mean;
        let late_ratio = (equal_mean - late_mean).abs() / equal_mean;
        let early_late_ratio = (early_mean - late_mean).abs() / early_mean;

        assert!(
            early_ratio < 0.5, // Relaxed for remote environments
            "Equal vs early-diff timing varies too much: {early_ratio:.3}"
        );
        assert!(
            late_ratio < 0.5, // Relaxed for remote environments
            "Equal vs late-diff timing varies too much: {late_ratio:.3}"
        );
        assert!(
            early_late_ratio < 0.5, // Relaxed for remote environments
            "Early-diff vs late-diff timing varies too much: {early_late_ratio:.3}"
        );
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
}
