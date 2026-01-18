//! Authentication keys and key derivation.
//!
//! Keys are 256-bit (32 byte) values used for HMAC-like authentication.
//! In Phase 0, we use a deterministic keyed hash that is NOT cryptographically secure.

use crate::util::DetRng;
use std::fmt;

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
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
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

    /// Derives a subkey for a specific purpose.
    ///
    /// This uses a simple KDF (Key Derivation Function) construction:
    /// `H(key || purpose)`.
    ///
    /// In Phase 0, this is simulated by XORing the key with the purpose hash.
    #[must_use]
    pub fn derive_subkey(&self, purpose: &[u8]) -> Self {
        let mut derived = self.bytes;

        // Simple non-cryptographic mixing for Phase 0
        // Mix in the purpose
        for (i, &b) in purpose.iter().enumerate() {
            derived[i % AUTH_KEY_SIZE] ^= b.wrapping_mul(31).wrapping_add(17);
        }

        // One round of mixing to avalanche
        for i in 0..AUTH_KEY_SIZE {
            derived[i] = derived[i].wrapping_add(derived[(i + 1) % AUTH_KEY_SIZE]);
            derived[i] = derived[i].rotate_left(3);
        }

        Self { bytes: derived }
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
