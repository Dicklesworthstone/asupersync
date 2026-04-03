//! Authentication tags for symbol verification.
//!
//! Tags are fixed-size 32-byte HMAC-SHA256 message authentication codes over a
//! symbol's canonical identity and payload bytes.

use crate::security::key::AuthKey;
use crate::types::{Symbol, SymbolKind};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Size of an authentication tag in bytes.
pub const TAG_SIZE: usize = 32;

/// Domain separator for symbol authentication tags.
const AUTH_TAG_DOMAIN: &[u8] = b"asupersync::security::AuthenticationTag::v1";

/// A cryptographic tag verifying a symbol.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticationTag {
    bytes: [u8; TAG_SIZE],
}

impl AuthenticationTag {
    /// Computes an authentication tag for a symbol using the given key.
    ///
    /// Construction:
    /// `HMAC-SHA256(key, domain || object_id || sbn || esi || kind || len || payload)`.
    #[must_use]
    pub fn compute(key: &AuthKey, symbol: &Symbol) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        Self::update_mac(&mut mac, symbol);
        let bytes: [u8; TAG_SIZE] = mac.finalize().into_bytes().into();
        Self { bytes }
    }

    fn update_mac(mac: &mut HmacSha256, symbol: &Symbol) {
        mac.update(AUTH_TAG_DOMAIN);
        mac.update(&symbol.id().object_id().as_u128().to_le_bytes());
        mac.update(&[symbol.sbn()]);
        mac.update(&symbol.esi().to_le_bytes());
        mac.update(&[match symbol.kind() {
            SymbolKind::Source => 0x53,
            SymbolKind::Repair => 0xA7,
        }]);
        mac.update(&(symbol.data().len() as u64).to_le_bytes());
        if !symbol.data().is_empty() {
            mac.update(symbol.data());
        }
    }

    /// Verifies that this tag matches the computed tag for the symbol and key.
    ///
    /// This uses a constant-time comparison to prevent timing attacks.
    #[must_use]
    pub fn verify(&self, key: &AuthKey, symbol: &Symbol) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        Self::update_mac(&mut mac, symbol);
        mac.verify_slice(&self.bytes).is_ok()
    }

    /// Returns an all-zero invalid sentinel tag for negative tests and fixtures.
    ///
    /// This is never produced by [`Self::compute`] and should not be used as a
    /// stand-in for a real authenticated symbol.
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

    /// Invariant: tags are data-dependent — different payloads must produce
    /// different HMAC outputs.
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
    fn tag_depends_on_symbol_kind() {
        let key = AuthKey::from_seed(42);
        let data = vec![1, 2, 3];
        let id_source = SymbolId::new_for_test(1, 0, 0);
        let s_source = Symbol::new(id_source, data.clone(), SymbolKind::Source);
        let s_repair = Symbol::new(id_source, data, SymbolKind::Repair);

        let tag_source = AuthenticationTag::compute(&key, &s_source);
        let tag_repair = AuthenticationTag::compute(&key, &s_repair);

        assert_ne!(
            tag_source, tag_repair,
            "source and repair symbols with the same id/data must not share a tag"
        );
        assert!(
            !tag_source.verify(&key, &s_repair),
            "a source tag must not verify against a repair symbol"
        );
        assert!(
            !tag_repair.verify(&key, &s_source),
            "a repair tag must not verify against a source symbol"
        );
    }

    #[test]
    fn compute_matches_domain_separated_hmac_sha256_contract() {
        let key = AuthKey::from_seed(7);
        let id = SymbolId::new_for_test(0xABCD, 3, 99);
        let symbol = Symbol::new(id, vec![0x10, 0x20, 0x30, 0x40], SymbolKind::Repair);

        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(AUTH_TAG_DOMAIN);
        mac.update(&symbol.id().object_id().as_u128().to_le_bytes());
        mac.update(&[symbol.sbn()]);
        mac.update(&symbol.esi().to_le_bytes());
        mac.update(&[0xA7]);
        mac.update(&(symbol.data().len() as u64).to_le_bytes());
        mac.update(symbol.data());

        let expected = AuthenticationTag::from_bytes(mac.finalize().into_bytes().into());
        assert_eq!(AuthenticationTag::compute(&key, &symbol), expected);
    }
}
