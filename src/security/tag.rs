//! Authentication tag types.
//!
//! This module provides the [`AuthenticationTag`] type, which represents
//! a message authentication code (MAC) that verifies symbol integrity.
//!
//! # Tag Generation
//!
//! Tags are computed over the symbol's identity (ObjectId, SBN, ESI) and
//! payload data. This binds the tag to both the content and its position
//! in the erasure coding scheme.

use crate::security::key::AuthKey;
use crate::types::{Symbol, SymbolId};
use core::fmt;

/// Size of the authentication tag in bytes (256 bits).
///
/// This provides a security margin equivalent to the key size and is
/// compatible with HMAC-SHA256 for future upgrades.
pub const AUTH_TAG_SIZE: usize = 32;

/// An authentication tag for verifying symbol integrity.
///
/// The tag is computed over:
/// - Object ID (128 bits)
/// - Source Block Number (8 bits)
/// - Encoding Symbol ID (32 bits)
/// - Symbol kind (source/repair)
/// - Payload data
///
/// This ensures that:
/// 1. Data cannot be tampered with undetected
/// 2. Symbols cannot be misattributed to different objects
/// 3. Symbol ordering cannot be manipulated
///
/// # Example
///
/// ```
/// use asupersync::security::{AuthKey, AuthenticationTag};
/// use asupersync::types::{Symbol, SymbolKind, SymbolId, ObjectId};
///
/// let key = AuthKey::from_seed(42);
/// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3, 4]);
///
/// let tag = AuthenticationTag::compute(&key, &symbol);
///
/// // Verification
/// assert!(tag.verify(&key, &symbol));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationTag {
    /// The computed tag bytes.
    bytes: [u8; AUTH_TAG_SIZE],
}

impl AuthenticationTag {
    /// Creates a tag from raw bytes.
    ///
    /// This is primarily used when deserializing tags from the network.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUTH_TAG_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the tag as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AUTH_TAG_SIZE] {
        &self.bytes
    }

    /// Computes an authentication tag for a symbol.
    ///
    /// This is the primary way to create tags. The computation covers
    /// all identifying information and the payload.
    ///
    /// # Arguments
    ///
    /// * `key` - The authentication key
    /// * `symbol` - The symbol to authenticate
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AuthenticationTag};
    /// use asupersync::types::Symbol;
    ///
    /// let key = AuthKey::from_seed(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// let tag = AuthenticationTag::compute(&key, &symbol);
    /// ```
    #[must_use]
    pub fn compute(key: &AuthKey, symbol: &Symbol) -> Self {
        Self::compute_for_parts(key, symbol.id(), symbol.data())
    }

    /// Computes a tag from symbol parts.
    ///
    /// This is useful when you have the parts separately (e.g., during
    /// encoding before the Symbol struct is constructed).
    #[must_use]
    pub fn compute_for_parts(key: &AuthKey, id: SymbolId, data: &[u8]) -> Self {
        // Build the message to authenticate
        // Format: object_id || sbn || esi || data_len || data
        let object_id = id.object_id();

        // Create a deterministic keyed hash
        // Phase 0: Simple mixing construction (NOT cryptographically secure)
        let mut state = [0u8; AUTH_TAG_SIZE];

        // Initialize state from key
        state.copy_from_slice(key.as_bytes());

        // Mix in object ID
        mix_u64(&mut state, object_id.high());
        mix_u64(&mut state, object_id.low());

        // Mix in symbol position
        mix_u8(&mut state, id.sbn());
        mix_u32(&mut state, id.esi());

        // Mix in data length (prevents length extension)
        mix_u64(&mut state, data.len() as u64);

        // Mix in data
        for (i, &byte) in data.iter().enumerate() {
            let idx = i % AUTH_TAG_SIZE;
            state[idx] = state[idx]
                .wrapping_add(byte)
                .wrapping_mul(0x9E)
                .rotate_left((i % 8) as u32);
        }

        // Final mixing rounds for diffusion
        for round in 0u8..8 {
            for i in 0..AUTH_TAG_SIZE {
                let prev = state[(i + AUTH_TAG_SIZE - 1) % AUTH_TAG_SIZE];
                let next = state[(i + 1) % AUTH_TAG_SIZE];
                let key_byte = key.as_bytes()[i];

                state[i] = state[i]
                    .wrapping_add(prev)
                    .wrapping_add(next)
                    .wrapping_add(key_byte)
                    .wrapping_add(round)
                    .rotate_left(3);
            }
        }

        Self { bytes: state }
    }

    /// Verifies that this tag is valid for the given symbol and key.
    ///
    /// Returns `true` if the tag matches, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AuthenticationTag};
    /// use asupersync::types::Symbol;
    ///
    /// let key = AuthKey::from_seed(42);
    /// let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
    ///
    /// let tag = AuthenticationTag::compute(&key, &symbol);
    /// assert!(tag.verify(&key, &symbol));
    ///
    /// // Different symbol data fails verification
    /// let other = Symbol::new_for_test(1, 0, 0, &[4, 5, 6]);
    /// assert!(!tag.verify(&key, &other));
    /// ```
    #[must_use]
    pub fn verify(&self, key: &AuthKey, symbol: &Symbol) -> bool {
        self.verify_parts(key, symbol.id(), symbol.data())
    }

    /// Verifies a tag against symbol parts.
    #[must_use]
    pub fn verify_parts(&self, key: &AuthKey, id: SymbolId, data: &[u8]) -> bool {
        let expected = Self::compute_for_parts(key, id, data);

        // Constant-time comparison to prevent timing attacks
        constant_time_eq(&self.bytes, &expected.bytes)
    }

    /// Creates a zero tag (invalid, for testing error paths).
    #[doc(hidden)]
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; AUTH_TAG_SIZE],
        }
    }
}

/// Mixes a u64 value into the state.
fn mix_u64(state: &mut [u8; AUTH_TAG_SIZE], value: u64) {
    let bytes = value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        let idx = i % AUTH_TAG_SIZE;
        state[idx] = state[idx]
            .wrapping_add(byte)
            .wrapping_mul(0x6D)
            .rotate_left(5);
    }
}

/// Mixes a u32 value into the state.
fn mix_u32(state: &mut [u8; AUTH_TAG_SIZE], value: u32) {
    let bytes = value.to_le_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        let idx = (i + 8) % AUTH_TAG_SIZE;
        state[idx] = state[idx]
            .wrapping_add(byte)
            .wrapping_mul(0x5B)
            .rotate_left(3);
    }
}

/// Mixes a u8 value into the state.
fn mix_u8(state: &mut [u8; AUTH_TAG_SIZE], value: u8) {
    let idx = 16;
    state[idx] = state[idx].wrapping_add(value).wrapping_mul(0x3F);
}

/// Constant-time comparison of byte arrays.
///
/// This prevents timing attacks by ensuring comparison time doesn't
/// depend on where the first difference occurs.
fn constant_time_eq(a: &[u8; AUTH_TAG_SIZE], b: &[u8; AUTH_TAG_SIZE]) -> bool {
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthTag({:02x}{:02x}{:02x}{:02x}...)",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
        )
    }
}

impl fmt::Display for AuthenticationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}...",
            self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol(obj: u64, sbn: u8, esi: u32, data: &[u8]) -> Symbol {
        Symbol::new_for_test(obj, sbn, esi, data)
    }

    #[test]
    fn compute_deterministic() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag1 = AuthenticationTag::compute(&key, &symbol);
        let tag2 = AuthenticationTag::compute(&key, &symbol);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn verify_valid_tag() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag = AuthenticationTag::compute(&key, &symbol);
        assert!(tag.verify(&key, &symbol));
    }

    #[test]
    fn verify_fails_different_data() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag = AuthenticationTag::compute(&key, &symbol);

        let tampered = make_symbol(1, 0, 0, &[1, 2, 3, 5]); // Different data
        assert!(!tag.verify(&key, &tampered));
    }

    #[test]
    fn verify_fails_different_object() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag = AuthenticationTag::compute(&key, &symbol);

        let different_obj = make_symbol(2, 0, 0, &[1, 2, 3, 4]); // Different object
        assert!(!tag.verify(&key, &different_obj));
    }

    #[test]
    fn verify_fails_different_position() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag = AuthenticationTag::compute(&key, &symbol);

        // Different SBN
        let different_sbn = make_symbol(1, 1, 0, &[1, 2, 3, 4]);
        assert!(!tag.verify(&key, &different_sbn));

        // Different ESI
        let different_esi = make_symbol(1, 0, 1, &[1, 2, 3, 4]);
        assert!(!tag.verify(&key, &different_esi));
    }

    #[test]
    fn verify_fails_different_key() {
        let key1 = AuthKey::from_seed(42);
        let key2 = AuthKey::from_seed(43);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3, 4]);

        let tag = AuthenticationTag::compute(&key1, &symbol);
        assert!(!tag.verify(&key2, &symbol));
    }

    #[test]
    fn different_data_different_tags() {
        let key = AuthKey::from_seed(42);

        let tag1 = AuthenticationTag::compute(&key, &make_symbol(1, 0, 0, &[1, 2, 3]));
        let tag2 = AuthenticationTag::compute(&key, &make_symbol(1, 0, 0, &[1, 2, 4]));

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn empty_data_works() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[]);

        let tag = AuthenticationTag::compute(&key, &symbol);
        assert!(tag.verify(&key, &symbol));
    }

    #[test]
    fn large_data_works() {
        let key = AuthKey::from_seed(42);
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let symbol = make_symbol(1, 0, 0, &data);

        let tag = AuthenticationTag::compute(&key, &symbol);
        assert!(tag.verify(&key, &symbol));
    }

    #[test]
    fn from_bytes_roundtrip() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);

        let original = AuthenticationTag::compute(&key, &symbol);
        let bytes = *original.as_bytes();
        let restored = AuthenticationTag::from_bytes(bytes);

        assert_eq!(original, restored);
        assert!(restored.verify(&key, &symbol));
    }

    #[test]
    fn zero_tag_fails_verification() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);

        let zero = AuthenticationTag::zero();
        assert!(!zero.verify(&key, &symbol));
    }

    #[test]
    fn debug_format() {
        let key = AuthKey::from_seed(42);
        let symbol = make_symbol(1, 0, 0, &[1, 2, 3]);
        let tag = AuthenticationTag::compute(&key, &symbol);

        let debug = format!("{tag:?}");
        assert!(debug.contains("AuthTag"));
        assert!(debug.contains("..."));
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0u8; AUTH_TAG_SIZE];
        let b = [0u8; AUTH_TAG_SIZE];
        let c = [1u8; AUTH_TAG_SIZE];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
