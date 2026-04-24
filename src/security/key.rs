//! Authentication keys and key derivation.
//!
//! Keys are 256-bit (32 byte) values used for HMAC-SHA256 authentication.

use crate::util::DetRng;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Size of an authentication key in bytes.
pub const AUTH_KEY_SIZE: usize = 32;

/// A 256-bit authentication key.
///
/// Keys should be treated as sensitive material and zeroized when dropped
/// (Phase 1+ requirement). For Phase 0, we focus on functional correctness.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthKey {
    bytes: [u8; AUTH_KEY_SIZE],
}

impl AuthKey {
    /// Creates a new key from a 64-bit seed.
    ///
    /// This uses domain-separated SHA-256 to deterministically expand the seed
    /// into 32 bytes without depending on `DetRng`'s zero-seed normalization.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::security::AuthKey::from_seed:v1");
        hasher.update(seed.to_le_bytes());
        let bytes: [u8; AUTH_KEY_SIZE] = hasher.finalize().into();
        Self { bytes }
    }

    /// Creates a new key from a deterministic RNG.
    #[must_use]
    pub fn from_rng(rng: &mut DetRng) -> Self {
        let mut bytes = [0u8; AUTH_KEY_SIZE];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Creates a new key from raw bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUTH_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the key.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.bytes
    }

    /// Derives a subkey for a specific purpose using HMAC-SHA256.
    ///
    /// Construction: `derived = HMAC-SHA256(self, purpose)`.
    #[must_use]
    pub fn derive_subkey(&self, purpose: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(&self.bytes).expect("HMAC accepts any key length");
        mac.update(purpose);
        let result = mac.finalize().into_bytes();
        Self {
            bytes: result.into(),
        }
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not leak full key material in debug logs
        write!(f, "AuthKey({:02x}{:02x}...)", self.bytes[0], self.bytes[1])
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
    fn test_from_rng_produces_unique_keys() {
        let mut rng = DetRng::new(123);
        let k1 = AuthKey::from_rng(&mut rng);
        let k2 = AuthKey::from_rng(&mut rng);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let bytes = [42u8; AUTH_KEY_SIZE];
        let key = AuthKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
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
        let debug = format!("{key:?}");
        assert!(debug.starts_with("AuthKey("));
        assert!(debug.ends_with("...)"));
        assert!(debug.len() < 30); // Should be short
    }

    // =========================================================================
    // Wave 54 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn auth_key_clone_copy_hash_eq() {
        use std::collections::HashSet;
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let copied = k1;
        let cloned = k1;
        assert_eq!(copied, cloned);
        assert_ne!(k1, k2);

        let mut set = HashSet::new();
        set.insert(k1);
        set.insert(k2);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&k1));
    }

    #[test]
    fn derive_subkey_matches_rfc6238_sha256_time_59_vector() {
        // RFC 6238 Appendix B, SHA-256 test secret for 8-digit TOTP vectors.
        let secret = *b"12345678901234567890123456789012";
        let key = AuthKey::from_bytes(secret);

        // Time = 59s, T0 = 0, X = 30 => moving factor = 1.
        let moving_factor = 1u64.to_be_bytes();
        let mac = key.derive_subkey(&moving_factor);
        let totp = hotp_dynamic_truncation(mac.as_bytes(), 8);

        assert_eq!(totp, 46_119_246);
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
}
