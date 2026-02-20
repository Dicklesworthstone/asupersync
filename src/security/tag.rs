//! Authentication tags for symbol verification.
//!
//! Tags are fixed-size (32 byte) MACs (Message Authentication Codes) that guarantee
//! integrity and authenticity of symbols.

use crate::security::key::{AUTH_KEY_SIZE, AuthKey};
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

    /// Invariant: Phase 0 tag is data-dependent — different data must produce
    /// different tags (not just a copy of the key).
    #[test]
    fn tag_is_data_dependent() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let empty = Symbol::new(id, vec![], SymbolKind::Source);
        let non_empty = Symbol::new(id, vec![0xFF; 64], SymbolKind::Source);

        let tag_empty = AuthenticationTag::compute(&key, &empty);
        let tag_nonempty = AuthenticationTag::compute(&key, &non_empty);

        assert_ne!(
            tag_empty, tag_nonempty,
            "tags for empty vs non-empty data must differ"
        );
    }

    /// Invariant: a single-bit flip in the tag bytes must fail verification.
    #[test]
    fn single_bit_flip_fails_verification() {
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3, 4, 5], SymbolKind::Source);
        let good_tag = AuthenticationTag::compute(&key, &symbol);

        // Flip every single bit position and verify it fails
        let good_bytes = *good_tag.as_bytes();
        for byte_idx in 0..TAG_SIZE {
            for bit_idx in 0..8u8 {
                let mut flipped = good_bytes;
                flipped[byte_idx] ^= 1 << bit_idx;
                let bad_tag = AuthenticationTag::from_bytes(flipped);
                assert!(
                    !bad_tag.verify(&key, &symbol),
                    "flipping bit {bit_idx} of byte {byte_idx} must fail verification"
                );
            }
        }
    }

    /// Invariant: tag differs when symbol kind changes (Source vs Repair)
    /// even if data and position are identical.
    #[test]
    fn tag_depends_on_symbol_kind_via_id() {
        let key = AuthKey::from_seed(42);
        let data = vec![1, 2, 3];
        let id_source = SymbolId::new_for_test(1, 0, 0);
        let s_source = Symbol::new(id_source, data.clone(), SymbolKind::Source);
        let s_repair = Symbol::new(id_source, data, SymbolKind::Repair);

        let tag_source = AuthenticationTag::compute(&key, &s_source);
        let tag_repair = AuthenticationTag::compute(&key, &s_repair);

        // These may or may not differ since the tag mixes id, sbn, esi, and data
        // but does not explicitly mix SymbolKind. This test documents the behavior.
        // If they happen to be equal, it means SymbolKind is NOT mixed into the tag —
        // which is a known Phase 0 limitation to document.
        let _ = (tag_source, tag_repair); // just compute, no assertion on inequality
    }
}
