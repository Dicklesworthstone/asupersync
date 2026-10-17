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

/// Domain separator for callers that authenticate an explicitly framed payload.
const DOMAIN_PAYLOAD_TAG_DOMAIN: &[u8] =
    b"asupersync::security::AuthenticationTag::domain-payload::v1";

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

    /// Computes a tag for an explicitly domain-separated, length-framed payload.
    ///
    /// This crate-internal primitive is used for authenticated control envelopes
    /// whose bytes are not naturally represented as a [`Symbol`]. Callers own
    /// the semantic domain; this layer additionally frames both the domain and
    /// payload lengths so distinct tuples cannot collide by concatenation.
    #[must_use]
    pub(crate) fn compute_for_domain_payload(key: &AuthKey, domain: &[u8], payload: &[u8]) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        Self::update_domain_payload_mac(&mut mac, domain, payload);
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

    fn update_domain_payload_mac(mac: &mut HmacSha256, domain: &[u8], payload: &[u8]) {
        mac.update(DOMAIN_PAYLOAD_TAG_DOMAIN);
        mac.update(&(domain.len() as u64).to_le_bytes());
        mac.update(domain);
        mac.update(&(payload.len() as u64).to_le_bytes());
        mac.update(payload);
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

    /// Verifies a tag produced by [`Self::compute_for_domain_payload`].
    #[must_use]
    pub(crate) fn verify_domain_payload(
        &self,
        key: &AuthKey,
        domain: &[u8],
        payload: &[u8],
    ) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        Self::update_domain_payload_mac(&mut mac, domain, payload);
        let expected_bytes = mac.finalize().into_bytes();
        let hmac_valid = self.bytes.ct_eq(expected_bytes.as_slice());
        let is_not_zero = Choice::from((!self.is_zero()) as u8);
        (hmac_valid & is_not_zero).into()
    }

    /// br-asupersync-usr4ax: returns `true` when the tag is the
    /// all-zero sentinel that [`Self::zero`] produces. Consumer code
    /// that needs to fail-closed against unauthenticated symbols
    /// (or call out the zero-sentinel shape in diagnostics) checks
    /// this before treating an [`crate::security::AuthenticatedSymbol`] as
    /// actually authenticated.
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
    #[cfg(not(target_arch = "wasm32"))]
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
#[path = "tag_inline_tests.rs"]
mod tests;
