//! Authentication tags for symbol verification.
//!
//! Tags are fixed-size 32-byte HMAC-SHA256 message authentication codes over a
//! symbol's canonical identity and payload bytes.
//!
//! # Security Properties (asupersync-mjn8rx)
//!
//! This module provides constant-time authentication to prevent timing attacks:
//!
//! - **Constant-time verification**: All tag comparisons use `subtle::ConstantTimeEq`
//!   to prevent timing side-channels that could leak information about valid tags.
//! - **Constant-time zero detection**: Zero-tag rejection uses constant-time `is_zero()`
//!   to prevent attackers from distinguishing zero vs. non-zero tags via timing.
//! - **Unified verification path**: All verification branches take the same time
//!   regardless of tag content or validity outcome.
//! - **No early returns**: Verification always computes the expected HMAC and
//!   performs all checks before returning, eliminating timing-based oracles.

use crate::security::key::AuthKey;
use crate::types::{Symbol, SymbolKind};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

type HmacSha256 = Hmac<Sha256>;

/// Size of an authentication tag in bytes.
pub const TAG_SIZE: usize = 32;

/// Domain separator for symbol authentication tags.
const AUTH_TAG_DOMAIN: &[u8] = b"asupersync::security::AuthenticationTag::v1";

/// A cryptographic tag verifying a symbol.
#[derive(Clone, Copy, Eq, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)] // PartialEq is deliberately constant-time.
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
    ///
    /// br-asupersync-usr4ax: a tag equal to [`Self::zero`] is the
    /// unauthenticated sentinel used by upstream encoders that have not
    /// yet been wired through to a real key (see types/typed_symbol.rs
    /// callsites at lines 630 / 925). The sentinel is documented as
    /// "never produced by [`Self::compute`]" — accepting it here
    /// would defeat the authentication contract entirely.
    ///
    /// br-asupersync-ju2k01: Fixed timing side-channel vulnerability.
    /// Now uses constant-time verification to prevent timing attacks
    /// that could distinguish between zero vs non-zero authentication tags.
    /// All verification paths take the same time regardless of tag content.
    #[must_use]
    pub fn verify(&self, key: &AuthKey, symbol: &Symbol) -> bool {
        // Always compute the expected HMAC (constant time)
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        Self::update_mac(&mut mac, symbol);
        let expected_bytes = mac.finalize().into_bytes();

        // Constant-time HMAC verification
        let hmac_valid = self.bytes.ct_eq(expected_bytes.as_slice());

        // Constant-time zero check - convert bool to Choice
        // is_zero() is already constant-time internally
        let is_not_zero = Choice::from((!self.is_zero()) as u8);

        // Both conditions must be true: valid HMAC AND not zero
        // Use constant-time AND operation
        (hmac_valid & is_not_zero).into()
    }

    /// br-asupersync-usr4ax: returns `true` when the tag is the
    /// all-zero sentinel that [`Self::zero`] produces. Consumer code
    /// that needs to fail-closed against unauthenticated symbols
    /// (or call out the zero-sentinel shape in diagnostics) checks
    /// this before treating an [`AuthenticatedSymbol`] as actually
    /// authenticated.
    #[inline]
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let bytes = &self.bytes;
        let mut i = 0;
        let mut diff = 0u8;
        while i < TAG_SIZE {
            diff |= bytes[i];
            i += 1;
        }
        diff == 0
    }

    /// Returns an all-zero invalid sentinel tag for negative tests and fixtures.
    ///
    /// This is never produced by [`Self::compute`] and should not be used as a
    /// stand-in for a real authenticated symbol.
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; TAG_SIZE],
        }
    }

    /// Creates a tag from raw bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TAG_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the tag.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.bytes
    }

    /// Computes an authentication tag for a journal record using the given key.
    ///
    /// Construction:
    /// `HMAC-SHA256(key, journal_domain || record_type || record_payload_bytes)`.
    #[must_use]
    pub fn compute_for_journal_record(
        key: &AuthKey,
        record: &crate::atp::journal::JournalRecord,
    ) -> Self {
        use crate::atp::journal::JournalRecord;

        const JOURNAL_DOMAIN: &[u8] = b"asupersync::security::AuthenticationTag::journal::v1";

        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");

        // Add domain separator
        mac.update(JOURNAL_DOMAIN);

        // Add record type as a byte
        let record_type_byte = match record {
            JournalRecord::Offer { .. } => 0u8,
            JournalRecord::Accept { .. } => 1u8,
            JournalRecord::ChunkReceived { .. } => 2u8,
            JournalRecord::ChunkVerified { .. } => 3u8,
            JournalRecord::ChunkWritten { .. } => 4u8,
            JournalRecord::RepairDecode { .. } => 5u8,
            JournalRecord::CommitIntent { .. } => 6u8,
            JournalRecord::CommitComplete { .. } => 7u8,
            JournalRecord::Cancellation { .. } => 8u8,
            JournalRecord::Rollback { .. } => 9u8,
            JournalRecord::CompactionBoundary { .. } => 10u8,
            JournalRecord::ProofDigest { .. } => 11u8,
        };
        mac.update(&[record_type_byte]);

        // Add the record payload (everything except auth_tag)
        let payload = record.encode_payload_without_auth_tag();
        mac.update(&payload);

        let bytes: [u8; TAG_SIZE] = mac.finalize().into_bytes().into();
        Self { bytes }
    }
}

impl PartialEq for AuthenticationTag {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(<redacted>)")
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
    fn is_zero_rejects_single_nonzero_byte_at_every_position() {
        for byte_idx in 0..TAG_SIZE {
            let mut bytes = [0u8; TAG_SIZE];
            bytes[byte_idx] = 1;
            assert!(
                !AuthenticationTag::from_bytes(bytes).is_zero(),
                "single non-zero byte at position {byte_idx} must not be treated as zero"
            );
        }
    }

    #[test]
    fn debug_redacts_all_tag_bytes() {
        let tag = AuthenticationTag::from_bytes([0xABu8; TAG_SIZE]);
        let debug = format!("{tag:?}");

        assert_eq!(debug, "Tag(<redacted>)");
        assert!(
            !debug.contains("ab"),
            "AuthenticationTag Debug output must not expose HMAC byte prefixes"
        );
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

    #[test]
    fn verify_uses_constant_time_zero_tag_rejection() {
        // Regression test for asupersync-lo6ygl: Zero-tag verification bypass
        //
        // SECURITY INVARIANT: Zero tag rejection must use constant-time comparison
        //
        // The verify() method must use is_zero() for zero-tag detection instead of
        // direct byte array comparison. Direct comparison (self.bytes == [0u8; 32])
        // may short-circuit on the first non-zero byte, creating timing side channels.
        //
        // Constant-time is_zero() always examines all bytes regardless of their values,
        // preventing timing attacks that could distinguish zero vs non-zero tags.
        let key = AuthKey::from_seed(42);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3], SymbolKind::Source);

        // Zero tag must always fail verification
        let zero_tag = AuthenticationTag::zero();
        assert!(
            !zero_tag.verify(&key, &symbol),
            "zero tag must fail verification"
        );
        assert!(zero_tag.is_zero(), "zero tag must report as zero");

        // Non-zero tag should pass verification when computed correctly
        let valid_tag = AuthenticationTag::compute(&key, &symbol);
        assert!(
            valid_tag.verify(&key, &symbol),
            "valid tag must pass verification"
        );
        assert!(!valid_tag.is_zero(), "valid tag must not report as zero");
    }

    #[test]
    fn test_constant_time_security_properties() {
        // Security test for constant-time operations to prevent timing attacks
        let key = AuthKey::from_seed(0xDEADBEEF);
        let id = SymbolId::new_for_test(1, 0, 0);
        let symbol = Symbol::new(id, vec![1, 2, 3, 4, 5], SymbolKind::Source);

        // Create tags with varying bit patterns to test constant-time behavior
        let valid_tag = AuthenticationTag::compute(&key, &symbol);
        let zero_tag = AuthenticationTag::zero();
        let mut almost_valid = *valid_tag.as_bytes();
        almost_valid[31] ^= 1; // Flip last bit
        let almost_valid_tag = AuthenticationTag::from_bytes(almost_valid);

        // All verify calls should take constant time regardless of tag content
        // We can't easily measure timing in a unit test, but we verify behavior

        // Test 1: Valid tag verification
        assert!(valid_tag.verify(&key, &symbol));

        // Test 2: Zero tag verification (constant-time zero check)
        assert!(!zero_tag.verify(&key, &symbol));

        // Test 3: Almost-valid tag verification (constant-time HMAC check)
        assert!(!almost_valid_tag.verify(&key, &symbol));

        // Test 4: Wrong symbol verification (constant-time with wrong input)
        let wrong_symbol = Symbol::new(id, vec![9, 8, 7], SymbolKind::Source);
        assert!(!valid_tag.verify(&key, &wrong_symbol));

        // Test 5: Constant-time equality comparison
        assert_eq!(valid_tag, valid_tag);
        assert_ne!(valid_tag, zero_tag);
        assert_ne!(valid_tag, almost_valid_tag);
        assert_ne!(zero_tag, almost_valid_tag);
    }

    #[test]
    fn test_tag_forgery_resistance() {
        // Security test to verify authentication tags resist forgery attempts
        let key = AuthKey::from_seed(0x1337CAFE);
        let id = SymbolId::new_for_test(42, 0, 0);
        let symbol = Symbol::new(id, vec![0xDE, 0xAD, 0xBE, 0xEF], SymbolKind::Source);

        let valid_tag = AuthenticationTag::compute(&key, &symbol);

        // Test 1: Different key should not verify the same tag
        let different_key = AuthKey::from_seed(0xCAFEBABE);
        assert!(
            !valid_tag.verify(&different_key, &symbol),
            "Tag should not verify with different key"
        );

        // Test 2: Modified symbol should not verify with same tag
        let modified_symbol =
            Symbol::new(id, vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42], SymbolKind::Source);
        assert!(
            !valid_tag.verify(&key, &modified_symbol),
            "Tag should not verify with modified symbol"
        );

        // Test 3: Different symbol kind should not verify
        let repair_symbol = Symbol::new(id, vec![0xDE, 0xAD, 0xBE, 0xEF], SymbolKind::Repair);
        assert!(
            !valid_tag.verify(&key, &repair_symbol),
            "Tag should not verify with different symbol kind"
        );

        // Test 4: All-bits-flipped tag should not verify
        let mut flipped_bytes = *valid_tag.as_bytes();
        for byte in &mut flipped_bytes {
            *byte = !*byte;
        }
        let flipped_tag = AuthenticationTag::from_bytes(flipped_bytes);
        assert!(
            !flipped_tag.verify(&key, &symbol),
            "Completely flipped tag should not verify"
        );

        // Test 5: Zero tag should never verify (even if computed tag is zero by chance)
        let zero_tag = AuthenticationTag::zero();
        assert!(
            !zero_tag.verify(&key, &symbol),
            "Zero tag must never verify"
        );
    }
}
