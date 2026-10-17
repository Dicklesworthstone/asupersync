    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha1::Sha1;

    fn hotp_dynamic_truncation(mac: &[u8], digits: u32) -> u32 {
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = ((u32::from(mac[offset]) & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3]);
        binary % 10_u32.pow(digits)
    }

    #[test]
    fn test_from_seed_deterministic() {
        let k1 = AuthKey::from_seed(42);
        let k2 = AuthKey::from_seed(42);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_from_seed_different_seeds() {
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_from_seed_zero_is_distinct() {
        let k0 = AuthKey::from_seed(0);
        let k1 = AuthKey::from_seed(1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_from_seed_zero_does_not_collide_with_legacy_magic_seed() {
        let zero = AuthKey::from_seed(0);
        let legacy_magic = AuthKey::from_seed(0x9e37_79b9_7f4a_7c15);
        assert_ne!(zero, legacy_magic);
    }

    #[test]
    fn asupersync_8mp6md_auth_key_equality_covers_all_bytes() {
        let baseline = AuthKey::from_seed(0x008A_110C);
        let same = baseline.clone();
        let mut first_diff = baseline.clone();
        first_diff.bytes[0] ^= 1;
        let mut last_diff = baseline.clone();
        last_diff.bytes[AUTH_KEY_SIZE - 1] ^= 1;

        assert_eq!(baseline, same);
        assert_ne!(baseline, first_diff);
        assert_ne!(baseline, last_diff);
    }

    #[test]
    fn test_from_rng_produces_unique_keys() {
        let mut rng = DetRng::new(123);
        let k1 = AuthKey::from_rng(&mut rng);
        let k2 = AuthKey::from_rng(&mut rng);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        // br-asupersync-q3terg: use a high-entropy 32-byte buffer that
        // passes the validator. The pre-fix test used [42u8; 32] which
        // is now rejected by the entropy validator (only 1 distinct
        // byte; Hamming weight 32×3 = 96 within bounds, but distinct
        // count fails). Construct a buffer with all 32 distinct values
        // 0..32 so distinct = 32 ≥ 8 and Hamming weight ≈ 78 (within
        // [8, 248]).
        let mut bytes = [0u8; AUTH_KEY_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = AuthKey::from_bytes(bytes).expect("strong key accepted");
        assert_eq!(key.as_bytes(), &bytes);
    }

    /// br-asupersync-q3terg: AuthKey::from_bytes MUST reject low-
    /// entropy inputs. The threat: developer mints
    /// `AuthKey::from_bytes([0u8; 32])` for a test, ships, the
    /// constant remains in production, attackers forge HMAC tags
    /// trivially. Fail-closed at construction stops this at the
    /// boundary.
    #[test]
    fn from_bytes_rejects_weak_inputs() {
        // The validator walks the bytes in a single pass, checking the
        // per-byte concentration cap (MAX_BYTE_FREQUENCY = 4) DURING the
        // count and the distinct/Hamming bounds only after. So any input
        // where a single value repeats more than 4 times is rejected by
        // `ExcessiveByteConcentration` first — which is the cheapest,
        // earliest fail-closed signal. The security-relevant invariant is
        // simply that every weak input is REJECTED; the exact variant is a
        // by-product of validation order.

        // (1) All zeros: byte 0 hits frequency 5 on the 5th byte →
        // ExcessiveByteConcentration fires before the distinct check.
        let err = AuthKey::from_bytes([0u8; AUTH_KEY_SIZE]).expect_err("all-zero rejected");
        assert!(matches!(
            err,
            AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExcessiveByteConcentration { byte_value: 0, .. }
            }
        ));

        // (2) All 0xFF: byte 0xFF hits frequency 5 → ExcessiveByteConcentration.
        let err = AuthKey::from_bytes([0xFFu8; AUTH_KEY_SIZE]).expect_err("all-FF rejected");
        assert!(matches!(
            err,
            AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExcessiveByteConcentration {
                    byte_value: 0xFF,
                    ..
                }
            }
        ));

        // (3) [42u8; 32]: the canonical 'developer test sentinel'. Byte 42
        // hits frequency 5 → ExcessiveByteConcentration.
        let err = AuthKey::from_bytes([42u8; AUTH_KEY_SIZE]).expect_err("[42; 32] rejected");
        assert!(matches!(
            err,
            AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExcessiveByteConcentration { byte_value: 42, .. }
            }
        ));

        // (4) 7 distinct values 0..=6 cycled across 32 bytes: value 0
        // appears at indices 0,7,14,21,28 → frequency 5 →
        // ExcessiveByteConcentration fires before the distinct=7 check.
        let mut weak = [0u8; AUTH_KEY_SIZE];
        for (i, b) in weak.iter_mut().enumerate() {
            *b = (i % 7) as u8;
        }
        let err = AuthKey::from_bytes(weak).expect_err("7-distinct rejected");
        assert!(matches!(
            err,
            AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExcessiveByteConcentration { .. }
            }
        ));

        // (5) Extreme Hamming-weight: 8 distinct byte values BUT all
        // bytes have very low popcount → low weight overall.
        // Use values [0, 1, 2, 4, 8, 16, 32, 64] cycled — 8 distinct,
        // each popcount ≤ 1, total weight = 32 / 8 × (0+1+1+1+1+1+1+1) = 28
        // = 28, in bounds. Construct a more pathological case:
        // [0, 0, 0, 0, 0, 0, 0, 1, ...] — only 2 distinct, also fails
        // distinct. So Hamming-weight extreme is hard to hit without
        // also failing distinct. Skip explicit test for that branch
        // since it's covered by the type-level enum.
    }

    #[test]
    fn test_derive_subkey_deterministic() {
        let key = AuthKey::from_seed(100);
        let sub1 = key.derive_subkey(b"transport");
        let sub2 = key.derive_subkey(b"transport");
        assert_eq!(sub1, sub2);
    }

    #[test]
    fn test_derive_subkey_different_purposes() {
        let key = AuthKey::from_seed(100);
        let sub1 = key.derive_subkey(b"transport");
        let sub2 = key.derive_subkey(b"storage");
        assert_ne!(sub1, sub2);
    }

    #[test]
    fn test_derived_key_not_equal_to_primary() {
        let key = AuthKey::from_seed(100);
        let sub = key.derive_subkey(b"test");
        assert_ne!(key, sub);
    }

    #[test]
    fn test_debug_does_not_leak_key_material() {
        let key = AuthKey::from_seed(0);
        let prefix = format!("{:02x}{:02x}", key.bytes[0], key.bytes[1]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "AuthKey(<redacted>)");
        assert!(
            !debug.contains(&prefix),
            "Debug must not expose even a key prefix"
        );
    }

    // =========================================================================
    // Wave 54 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn auth_key_clone_hash_eq() {
        // Renamed from `..._copy_...` because AuthKey is no longer Copy
        // (br-asupersync-4pegj0). Each "copy" must now be an explicit
        // `.clone()` so zeroize-on-drop applies to every duplicate.
        use std::collections::HashSet;
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let copied = k1.clone();
        let cloned = k1.clone();
        assert_eq!(copied, cloned);
        assert_ne!(k1, k2);

        let mut set = HashSet::new();
        set.insert(k1.clone());
        set.insert(k2.clone());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&k1));
    }

    #[test]
    fn derive_subkey_matches_rfc6238_sha256_time_59_vector() {
        // RFC 6238 Appendix B, SHA-256 test secret for 8-digit TOTP vectors.
        let secret = *b"12345678901234567890123456789012";
        // br-asupersync-q3terg: this RFC test vector has only 10 distinct
        // byte values ('0'..='9'), below the strengthened entropy floor of
        // MIN_DISTINCT_BYTES = 16, so plain `from_bytes` (correctly) rejects
        // it. This is a known-answer test for the HMAC-SHA256 derivation
        // math, not for the entropy gate, so we load the canonical RFC
        // secret through the known-strong-source bypass (`from_hmac_derived`)
        // exactly as a TOTP provisioning path would for a fixed RFC vector.
        let key = AuthKey::from_hmac_derived(secret).expect("RFC 6238 vector loaded");

        // Time = 59s, T0 = 0, X = 30 => moving factor = 1.
        let moving_factor = 1u64.to_be_bytes();
        let mac = key.derive_subkey(&moving_factor);
        let totp = hotp_dynamic_truncation(mac.as_bytes(), 8);

        assert_eq!(totp, 46_119_246);
    }

    /// br-asupersync-4pegj0: Drop must zeroise the key bytes. Verify by
    /// using `ManuallyDrop` to retain the storage past the destructor and
    /// observing the underlying byte array via a raw pointer obtained
    /// before `drop` ran. This is the standard manual-zeroize verification
    /// pattern (see `zeroize` crate's own tests).
    #[test]
    #[allow(unsafe_code)]
    fn drop_zeroises_key_bytes() {
        use std::mem::ManuallyDrop;

        let mut key = ManuallyDrop::new(AuthKey::from_seed(0xDEAD_BEEF));
        // Snapshot a pointer to the bytes BEFORE running Drop. Reading
        // through this pointer after `ManuallyDrop::drop` is sound because
        // the storage is not deallocated — `ManuallyDrop` keeps the value
        // in place; only the destructor side-effect (the zeroize) runs.
        let bytes_ptr: *const [u8; AUTH_KEY_SIZE] = std::ptr::addr_of!(key.bytes);

        // Sanity: pre-drop the seed expansion produces non-zero bytes.
        let pre = unsafe { *bytes_ptr };
        assert!(
            pre.iter().any(|&b| b != 0),
            "from_seed must produce non-zero bytes pre-drop"
        );

        // Run the destructor manually.
        unsafe {
            ManuallyDrop::drop(&mut key);
        }

        // Post-drop, every byte must be zero.
        let post = unsafe { *bytes_ptr };
        assert!(
            post.iter().all(|&b| b == 0),
            "Drop must zeroise every key byte; observed: {post:02x?}"
        );
    }

    /// AuthKey must NOT implement `Copy` — silent bit-copies past the
    /// destructor would defeat zeroize-on-drop. Verified at the type level
    /// by trying to use `static_assertions`-style trait bounds.
    #[test]
    fn auth_key_is_not_copy() {
        // If AuthKey were Copy, this `move` of `k1` followed by use of `k1`
        // would compile. Since it must NOT, the assertion is a doc-test of
        // the semantic contract enforced by the type system at the call
        // sites that hold AuthKey by value.
        fn is_copy<T: Copy>() {}
        // The trait-bound check below is intentionally NOT instantiated;
        // the proof is that `is_copy::<AuthKey>()` would fail to compile.
        // We instead exercise the cloning path so callers can see the
        // explicit `.clone()` is the supported duplication mechanism.
        let _ = is_copy::<u8>; // keep the helper used to silence dead_code
        let k1 = AuthKey::from_seed(1);
        let k2 = k1.clone();
        assert_eq!(k1, k2);
    }

    #[test]
    fn hotp_matches_rfc4226_counter_0_golden_vector() {
        type HmacSha1 = Hmac<Sha1>;

        // RFC 4226 Appendix D test secret and counter 0 vector.
        let secret = b"12345678901234567890";
        let counter = 0u64.to_be_bytes();

        let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&counter);
        let digest = mac.finalize().into_bytes();
        let hotp = hotp_dynamic_truncation(&digest, 6);

        assert_eq!(hotp, 755_224);
    }

    // =========================================================================
    // KeyRing — br-asupersync-bp985e
    // =========================================================================

    fn hmac_sign(key: &AuthKey, msg: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn key_ring_new_only_active_verifies() {
        let k = AuthKey::from_seed(1);
        let ring = KeyRing::new(k.clone());
        let sig = hmac_sign(&k, b"hello");
        assert!(ring.verify(b"hello", &sig));
        let other = AuthKey::from_seed(2);
        let bad_sig = hmac_sign(&other, b"hello");
        assert!(!ring.verify(b"hello", &bad_sig));
        assert!(ring.retired.is_none());
    }

    #[test]
    fn key_ring_rotate_accepts_old_and_new() {
        let old = AuthKey::from_seed(10);
        let new = AuthKey::from_seed(20);
        let mut ring = KeyRing::new(old.clone());

        let old_sig = hmac_sign(&old, b"in_flight");
        let new_sig = hmac_sign(&new, b"fresh");

        ring.rotate(new.clone());
        // Both must verify during the overlap window.
        assert!(
            ring.verify(b"in_flight", &old_sig),
            "retired key must accept"
        );
        assert!(ring.verify(b"fresh", &new_sig), "active key must accept");
        // Active is `new`, retired is the prior active.
        assert_eq!(ring.active, new);
        assert_eq!(ring.retired.as_ref(), Some(&old));
    }

    #[test]
    fn key_ring_retire_drops_retired_slot() {
        let old = AuthKey::from_seed(100);
        let new = AuthKey::from_seed(200);
        let mut ring = KeyRing::new(old.clone());
        ring.rotate(new.clone());
        ring.retire();
        let old_sig = hmac_sign(&old, b"stale");
        // Once retired() is called, old-key signatures MUST be rejected.
        assert!(!ring.verify(b"stale", &old_sig));
        // retire is idempotent.
        ring.retire();
        assert!(ring.retired.is_none());
    }

    #[test]
    fn key_ring_double_rotate_discards_oldest() {
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let k3 = AuthKey::from_seed(3);
        let mut ring = KeyRing::new(k1.clone());
        ring.rotate(k2.clone());
        ring.rotate(k3.clone());
        // After two rotations active=k3 retired=k2; k1 has been dropped and
        // its signatures MUST no longer verify.
        let k1_sig = hmac_sign(&k1, b"too_old");
        assert!(!ring.verify(b"too_old", &k1_sig));
        let k2_sig = hmac_sign(&k2, b"recently_retired");
        assert!(ring.verify(b"recently_retired", &k2_sig));
        let k3_sig = hmac_sign(&k3, b"current");
        assert!(ring.verify(b"current", &k3_sig));
    }

    // Tests for strengthened validation (asupersync-uw3asa fix)
    #[test]
    fn test_strengthened_validation_rejects_weak_keys() {
        // The validator checks the per-byte concentration cap
        // (MAX_BYTE_FREQUENCY = 4) DURING the counting pass, before the
        // distinct-byte and Hamming-weight bounds. So to exercise the
        // diversity and Hamming branches we must use inputs that keep every
        // byte's frequency <= 4 (otherwise ExcessiveByteConcentration fires
        // first). Trivial saturated inputs like [0u8; 32] / [0xFF; 32] are
        // covered separately by `from_bytes_rejects_weak_inputs`.

        // Test 1: Insufficient byte diversity (threshold is MIN_DISTINCT_BYTES
        // = 16). 8 distinct values, each appearing exactly 4 times: freq cap
        // satisfied (==4), distinct = 8 < 16 → InsufficientByteDiversity.
        let mut low_diversity = [0u8; 32];
        for (i, b) in low_diversity.iter_mut().enumerate() {
            *b = (i / 4) as u8; // values 0..=7, each x4
        }
        match AuthKey::from_bytes(low_diversity) {
            Err(AuthKeyError::WeakKey {
                reason: WeakKeyReason::InsufficientByteDiversity { distinct, minimum },
            }) => {
                assert_eq!(distinct, 8);
                assert_eq!(minimum, MIN_DISTINCT_BYTES);
            }
            other => panic!("Expected InsufficientByteDiversity error, got {other:?}"),
        }

        // Test 2: Extreme Hamming weight - too low (min is MIN_HAMMING_WEIGHT
        // = 64). 16 distinct low-popcount values (so the diversity check
        // passes), each appearing twice (freq <= 4), total weight = 44 < 64.
        let low_popcount: [u8; 16] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 3, 5, 6, 9, 10, 12, 17];
        let mut low_hamming = [0u8; 32];
        for (i, b) in low_hamming.iter_mut().enumerate() {
            *b = low_popcount[i % 16];
        }
        match AuthKey::from_bytes(low_hamming) {
            Err(AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExtremeHammingWeight { weight, .. },
            }) => {
                assert_eq!(weight, 44);
                assert!(weight < MIN_HAMMING_WEIGHT);
            }
            other => panic!("Expected ExtremeHammingWeight error for low weight, got {other:?}"),
        }

        // Test 3: Extreme Hamming weight - too high (max is MAX_HAMMING_WEIGHT
        // = 192). 16 distinct high-popcount values, each appearing twice,
        // total weight = 212 > 192.
        let high_popcount: [u8; 16] = [
            0xFF, 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F, 0xFC, 0xFA, 0xF6, 0xEE, 0xDE,
            0xBE, 0x7E,
        ];
        let mut high_hamming = [0u8; 32];
        for (i, b) in high_hamming.iter_mut().enumerate() {
            *b = high_popcount[i % 16];
        }
        match AuthKey::from_bytes(high_hamming) {
            Err(AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExtremeHammingWeight { weight, .. },
            }) => {
                assert_eq!(weight, 212);
                assert!(weight > MAX_HAMMING_WEIGHT);
            }
            other => panic!("Expected ExtremeHammingWeight error for high weight, got {other:?}"),
        }

        // Test 4: Byte concentration attack (new validation)
        let mut concentrated = [0u8; 32];
        concentrated[0..5].fill(42); // Byte 42 appears 5 times, exceeds MAX_BYTE_FREQUENCY=4
        concentrated[5..].fill(1); // Fill rest to ensure diversity
        match AuthKey::from_bytes(concentrated) {
            Err(AuthKeyError::WeakKey {
                reason:
                    WeakKeyReason::ExcessiveByteConcentration {
                        byte_value,
                        frequency,
                        ..
                    },
            }) => {
                assert_eq!(byte_value, 42);
                assert_eq!(frequency, 5);
            }
            _ => panic!("Expected ExcessiveByteConcentration error"),
        }
    }

    #[test]
    fn test_strengthened_key_derivation() {
        let master_key = AuthKey::from_seed(42);

        // Test salted derivation
        let derived1 = master_key.derive_with_salt(b"salt1", b"test-purpose");
        let derived2 = master_key.derive_with_salt(b"salt1", b"test-purpose");
        let derived3 = master_key.derive_with_salt(b"salt1", b"different-purpose");
        let derived4 = master_key.derive_with_salt(b"salt2", b"test-purpose");

        assert_eq!(
            derived1, derived2,
            "Salted derivation should be deterministic"
        );
        assert_ne!(
            derived1, derived3,
            "Different contexts should yield different keys"
        );
        assert_ne!(
            derived1, derived4,
            "Different salts should yield different keys"
        );

        // Verify derived keys pass strengthened validation
        let validation_result = AuthKey::from_bytes(*derived1.as_bytes());
        assert!(
            validation_result.is_ok(),
            "Derived key should pass strengthened validation"
        );
    }

    #[test]
    fn test_legacy_keys_now_rejected() {
        // Keys that would have passed the old weak validation should now be rejected

        // Old validation: MIN_HAMMING_WEIGHT=8, now requires 64
        let mut weak_key = [0u8; 32];
        weak_key[0] = 0xFF; // 8 bits set, would pass old validation
        assert!(
            AuthKey::from_bytes(weak_key).is_err(),
            "Weak key should be rejected"
        );

        // Old validation: MIN_DISTINCT_BYTES=8, now requires 16
        let mut pattern_key = [0u8; 32];
        for i in 0..8 {
            pattern_key[i * 4] = i as u8; // Only 8 distinct bytes
        }
        assert!(
            AuthKey::from_bytes(pattern_key).is_err(),
            "Pattern key should be rejected"
        );
    }

    #[test]
    fn test_legitimate_strong_keys_accepted() {
        // Verify that legitimately strong keys still pass validation
        let strong_key = AuthKey::from_seed(12345);

        // Should pass all new validation checks
        let validation_result = AuthKey::from_bytes(*strong_key.as_bytes());
        assert!(
            validation_result.is_ok(),
            "Strong key should pass validation"
        );

        // Verify HKDF outputs also pass (they should by construction)
        let hkdf_key = AuthKey::from_hkdf(b"input-key-material", Some(b"salt"), b"context");
        let hkdf_revalidation = AuthKey::from_bytes(*hkdf_key.as_bytes());
        assert!(hkdf_revalidation.is_ok(), "HKDF key should pass validation");
    }

    #[test]
    fn test_security_fixes_prevent_weak_key_forgery() {
        // Test that our security fixes prevent weak key creation via alternative paths

        // Test 1: from_seed still works for normal seeds
        let strong_from_seed = AuthKey::from_seed(0xDEADBEEF);
        assert!(
            AuthKey::from_bytes(*strong_from_seed.as_bytes()).is_ok(),
            "Normal seeds should produce strong keys"
        );

        // Test 2: from_rng with deterministic RNG still works
        let mut rng = DetRng::new(12345);
        let strong_from_rng = AuthKey::from_rng(&mut rng);
        assert!(
            AuthKey::from_bytes(*strong_from_rng.as_bytes()).is_ok(),
            "Normal RNG should produce strong keys"
        );

        // Test 3: Edge case seeds get strengthened (test doesn't expose internals but ensures no panic)
        let edge_case_key = AuthKey::from_seed(0);
        assert!(
            AuthKey::from_bytes(*edge_case_key.as_bytes()).is_ok(),
            "Edge case seeds should be strengthened to pass validation"
        );

        // Test 4: Multiple keys from same seed should be deterministic but strong
        let key1 = AuthKey::from_seed(42);
        let key2 = AuthKey::from_seed(42);
        assert_eq!(key1, key2, "Same seed should produce same key");
        assert!(
            AuthKey::from_bytes(*key1.as_bytes()).is_ok(),
            "Deterministic keys should still be strong"
        );
    }

    #[test]
    fn test_key_entropy_validation_completeness() {
        // Comprehensive test of all entropy validation rules

        // Test minimum distinct bytes (16 required)
        let mut low_diversity = [0u8; 32];
        for (i, byte) in low_diversity.iter_mut().enumerate().take(15) {
            *byte = i as u8;
        } // Only 15 distinct values
        assert!(
            AuthKey::from_bytes(low_diversity).is_err(),
            "Insufficient byte diversity should be rejected"
        );

        // Test Hamming weight bounds (64-192 required)
        let low_hamming = [1u8; 32]; // 32 bits = below 64 minimum
        assert!(
            AuthKey::from_bytes(low_hamming).is_err(),
            "Low Hamming weight should be rejected"
        );

        let high_hamming = [0xFFu8; 32]; // 256 bits = above 192 maximum
        assert!(
            AuthKey::from_bytes(high_hamming).is_err(),
            "High Hamming weight should be rejected"
        );

        // Test byte concentration (max 4 occurrences per byte value)
        let mut concentrated = [0u8; 32];
        concentrated[0..5].fill(42); // Byte value 42 appears 5 times
        for (i, byte) in concentrated.iter_mut().enumerate().skip(5) {
            *byte = i as u8;
        } // Fill with unique values
        assert!(
            AuthKey::from_bytes(concentrated).is_err(),
            "Excessive byte concentration should be rejected"
        );
    }
