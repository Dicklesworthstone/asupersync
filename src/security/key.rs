//! Authentication keys and key derivation.
//!
//! Keys are 256-bit (32 byte) values used for HMAC-SHA256 authentication.

use crate::util::DetRng;
use hmac::{Hmac, Mac};
use sha2::Sha256;
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
    /// This uses a deterministic expansion to generate 32 bytes from the seed.
    /// Seed 0 is remapped to a fixed non-zero value to keep seed-to-key
    /// uniqueness while avoiding the xorshift zero-state lockup.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        };
        let mut bytes = [0u8; AUTH_KEY_SIZE];
        let mut rng = DetRng::new(seed);
        rng.fill_bytes(&mut bytes);
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
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUTH_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the key.
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
    use super::*;

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
    fn test_derived_key_not_equal_to_master() {
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
}
