//! Authentication tags for symbol verification.
//!
//! Tags are fixed-size (32 byte) MACs (Message Authentication Codes) that guarantee
//! integrity and authenticity of symbols.

use crate::security::key::{AuthKey, AUTH_KEY_SIZE};
use crate::types::Symbol;
use std::fmt;

/// Size of an authentication tag in bytes.
pub const TAG_SIZE: usize = 32;

/// A cryptographic tag verifying a symbol.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticationTag {
    bytes: [u8; TAG_SIZE],
}

impl AuthenticationTag {
    /// Computes an authentication tag for a symbol using the given key.
    ///
    /// In Phase 0, this uses a non-cryptographic deterministic mix.
    /// In Phase 1+, this will use HMAC-SHA256.
    #[must_use]
    pub fn compute(key: &AuthKey, symbol: &Symbol) -> Self {
        let mut tag = [0u8; TAG_SIZE];
        let k = key.as_bytes();

        // Initialize tag with key
        tag.copy_from_slice(k);

        // Mix symbol ID
        let id_bytes = symbol.id().object_id().as_u128().to_le_bytes();
        for (i, &b) in id_bytes.iter().enumerate() {
            tag[i % TAG_SIZE] ^= b;
        }

        // Mix SBN and ESI
        tag[0] ^= symbol.sbn();
        let esi_bytes = symbol.esi().to_le_bytes();
        for (i, &b) in esi_bytes.iter().enumerate() {
            tag[(i + 1) % TAG_SIZE] ^= b;
        }

        // Mix data
        for (i, &b) in symbol.data().iter().enumerate() {
            tag[i % TAG_SIZE] =
                tag[i % TAG_SIZE].wrapping_add(b).rotate_left(3) ^ k[(i + 5) % AUTH_KEY_SIZE];
        }

        // Final avalanche
        for i in 0..TAG_SIZE {
            tag[i] = tag[i].wrapping_add(tag[(i + 1) % TAG_SIZE]);
            tag[i] ^= k[i % AUTH_KEY_SIZE];
        }

        Self { bytes: tag }
    }

    /// Verifies that this tag matches the computed tag for the symbol and key.
    ///
    /// This uses a constant-time comparison to prevent timing attacks.
    #[must_use]
    pub fn verify(&self, key: &AuthKey, symbol: &Symbol) -> bool {
        let computed = Self::compute(key, symbol);
        self.constant_time_eq(&computed)
    }

    /// Returns a zeroed tag (for testing or placeholders).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; TAG_SIZE],
        }
    }

    /// Creates a tag from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TAG_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the tag.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.bytes
    }

    /// Constant-time comparison to prevent timing attacks.
    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..TAG_SIZE {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        diff == 0
    }
}

impl fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display prefix for identification
        write!(f, "Tag({:02x}{:02x}...)", self.bytes[0], self.bytes[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SymbolId, SymbolKind};

    #[test]
    fn test_compute_deterministic() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let tag1 = AuthenticationTag::compute(&key, &symbol);
        let tag2 = AuthenticationTag::compute(&key, &symbol);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_verify_valid_tag() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let tag = AuthenticationTag::compute(&key, &symbol);
        assert!(tag.verify(&key, &symbol));
    }

    #[test]
    fn test_verify_fails_different_data() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let s1 = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);
        let s2 = Symbol::new(id, vec![1, 2, 4], SymbolKind::Source);

        let tag = AuthenticationTag::compute(&key, &s1);
        assert!(!tag.verify(&key, &s2));
    }

    #[test]
    fn test_verify_fails_different_key() {
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let tag = AuthenticationTag::compute(&k1, &symbol);
        assert!(!tag.verify(&k2, &symbol));
    }

    #[test]
    fn test_zero_tag_fails_verification() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        let tag = AuthenticationTag::zero();
        // Unless the computed tag happens to be zero (probability 2^-256)
        assert!(!tag.verify(&key, &symbol));
    }

    #[test]
    fn test_verify_fails_different_position() {
        let key = AuthKey::from_seed(42);
        let id1 = SymbolId::new_for_test(1, 0, 0);
        let id2 = SymbolId::new_for_test(1, 0, 1); // Different ESI

        let s1 = Symbol::new(id1, vec![1, 2, 3], SymbolKind::Source);
        let s2 = Symbol::new(id2, vec![1, 2, 3], SymbolKind::Source);

        let tag = AuthenticationTag::compute(&key, &s1);
        assert!(!tag.verify(&key, &s2));
    }
}
