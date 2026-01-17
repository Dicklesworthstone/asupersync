//! Authentication key types and derivation.
//!
//! This module provides the [`AuthKey`] type used for symbol authentication.
//! Keys can be derived deterministically from seeds for testing, or generated
//! from external key material in production.
//!
//! # Security Note
//!
//! The deterministic derivation using [`DetRng`] is NOT cryptographically secure.
//! For production use, keys should be derived using a proper KDF (e.g., HKDF).

use crate::util::DetRng;
use core::fmt;

/// Size of the authentication key in bytes (256 bits).
pub const AUTH_KEY_SIZE: usize = 32;

/// An authentication key for symbol signing and verification.
///
/// The key is 256 bits (32 bytes), providing sufficient security margin
/// for HMAC-based authentication schemes.
///
/// # Determinism
///
/// Keys can be derived deterministically from a seed using [`AuthKey::from_seed`],
/// which is essential for lab runtime testing and trace replay.
///
/// # Example
///
/// ```
/// use asupersync::security::AuthKey;
///
/// // Deterministic key for testing
/// let key1 = AuthKey::from_seed(42);
/// let key2 = AuthKey::from_seed(42);
/// assert_eq!(key1, key2);
///
/// // Different seeds produce different keys
/// let key3 = AuthKey::from_seed(43);
/// assert_ne!(key1, key3);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey {
    /// The 256-bit key material.
    bytes: [u8; AUTH_KEY_SIZE],
}

impl AuthKey {
    /// Creates a new authentication key from raw bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::{AuthKey, AUTH_KEY_SIZE};
    ///
    /// let bytes = [0x42u8; AUTH_KEY_SIZE];
    /// let key = AuthKey::new(bytes);
    /// assert_eq!(key.as_bytes(), &bytes);
    /// ```
    #[must_use]
    pub const fn new(bytes: [u8; AUTH_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Creates a key deterministically from a 64-bit seed.
    ///
    /// This uses the deterministic PRNG to generate key material.
    /// The same seed always produces the same key.
    ///
    /// # Security Warning
    ///
    /// This method is for testing only. The underlying PRNG is NOT
    /// cryptographically secure. Production keys must come from a
    /// secure random source.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::AuthKey;
    ///
    /// let key1 = AuthKey::from_seed(12345);
    /// let key2 = AuthKey::from_seed(12345);
    /// assert_eq!(key1, key2);
    /// ```
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = DetRng::new(seed);
        let mut bytes = [0u8; AUTH_KEY_SIZE];

        // Fill key material using the PRNG
        for chunk in bytes.chunks_exact_mut(8) {
            let value = rng.next_u64();
            chunk.copy_from_slice(&value.to_le_bytes());
        }

        Self { bytes }
    }

    /// Creates a key using the provided DetRng.
    ///
    /// This is useful when you need to generate multiple keys from
    /// a single RNG stream while maintaining determinism.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::AuthKey;
    /// use asupersync::util::DetRng;
    ///
    /// let mut rng = DetRng::new(42);
    /// let key1 = AuthKey::from_rng(&mut rng);
    /// let key2 = AuthKey::from_rng(&mut rng);
    /// assert_ne!(key1, key2); // Different keys from same stream
    /// ```
    #[must_use]
    pub fn from_rng(rng: &mut DetRng) -> Self {
        let mut bytes = [0u8; AUTH_KEY_SIZE];

        for chunk in bytes.chunks_exact_mut(8) {
            let value = rng.next_u64();
            chunk.copy_from_slice(&value.to_le_bytes());
        }

        Self { bytes }
    }

    /// Returns the key as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.bytes
    }

    /// Derives a subkey for a specific purpose.
    ///
    /// This enables key separation (e.g., one key for signing, another for
    /// encryption) without needing multiple master keys.
    ///
    /// # Arguments
    ///
    /// * `purpose` - A purpose identifier (e.g., b"sign", b"encrypt")
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::security::AuthKey;
    ///
    /// let master = AuthKey::from_seed(42);
    /// let sign_key = master.derive_subkey(b"sign");
    /// let encrypt_key = master.derive_subkey(b"encrypt");
    /// assert_ne!(sign_key, encrypt_key);
    /// ```
    #[must_use]
    pub fn derive_subkey(&self, purpose: &[u8]) -> Self {
        // Simple deterministic key derivation using mixing
        // NOT a proper KDF - for Phase 0 testing only
        let mut derived = [0u8; AUTH_KEY_SIZE];

        // Mix key bytes with purpose bytes
        for (i, byte) in derived.iter_mut().enumerate() {
            let key_byte = self.bytes[i];
            let purpose_byte = purpose.get(i % purpose.len().max(1)).copied().unwrap_or(0);
            let mix = (i as u8).wrapping_add(0x5A); // Constant for mixing

            *byte = key_byte
                .wrapping_add(purpose_byte)
                .wrapping_mul(mix.wrapping_add(1))
                .rotate_left((i % 8) as u32);
        }

        // Additional mixing passes for better diffusion
        for round in 0..4 {
            for i in 0..AUTH_KEY_SIZE {
                let prev = derived[(i + AUTH_KEY_SIZE - 1) % AUTH_KEY_SIZE];
                let next = derived[(i + 1) % AUTH_KEY_SIZE];
                derived[i] = derived[i]
                    .wrapping_add(prev)
                    .wrapping_add(next)
                    .wrapping_add(round);
            }
        }

        Self { bytes: derived }
    }

    /// Creates a zeroed key (useful for testing error paths).
    #[doc(hidden)]
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; AUTH_KEY_SIZE],
        }
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't expose key material in debug output
        write!(
            f,
            "AuthKey([{:02x}{:02x}...{:02x}{:02x}])",
            self.bytes[0],
            self.bytes[1],
            self.bytes[AUTH_KEY_SIZE - 2],
            self.bytes[AUTH_KEY_SIZE - 1]
        )
    }
}

impl fmt::Display for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even more abbreviated for display
        write!(f, "AuthKey({:02x}{:02x}...)", self.bytes[0], self.bytes[1])
    }
}

// Explicit Drop to zero out key material
impl Drop for AuthKey {
    fn drop(&mut self) {
        // Zero out key material on drop to reduce exposure window
        // Note: This is best-effort; compiler may optimize it away
        // For production, use a crate like `zeroize`
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_seed_deterministic() {
        let key1 = AuthKey::from_seed(42);
        let key2 = AuthKey::from_seed(42);
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_seeds_different_keys() {
        let key1 = AuthKey::from_seed(42);
        let key2 = AuthKey::from_seed(43);
        assert_ne!(key1, key2);
    }

    #[test]
    fn key_from_rng() {
        let mut rng = DetRng::new(12345);
        let key1 = AuthKey::from_rng(&mut rng);
        let key2 = AuthKey::from_rng(&mut rng);

        // Keys from same stream should differ
        assert_ne!(key1, key2);

        // But same RNG state produces same key
        let mut rng2 = DetRng::new(12345);
        let key3 = AuthKey::from_rng(&mut rng2);
        assert_eq!(key1, key3);
    }

    #[test]
    fn key_new_from_bytes() {
        let bytes = [0x42u8; AUTH_KEY_SIZE];
        let key = AuthKey::new(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn derive_subkey_deterministic() {
        let master = AuthKey::from_seed(42);
        let sub1 = master.derive_subkey(b"test");
        let sub2 = master.derive_subkey(b"test");
        assert_eq!(sub1, sub2);
    }

    #[test]
    fn derive_subkey_different_purposes() {
        let master = AuthKey::from_seed(42);
        let sign = master.derive_subkey(b"sign");
        let encrypt = master.derive_subkey(b"encrypt");
        assert_ne!(sign, encrypt);
    }

    #[test]
    fn derive_subkey_differs_from_master() {
        let master = AuthKey::from_seed(42);
        let derived = master.derive_subkey(b"any");
        assert_ne!(master, derived);
    }

    #[test]
    fn debug_does_not_expose_full_key() {
        let key = AuthKey::from_seed(42);
        let debug = format!("{key:?}");

        // Should show abbreviated form, not full 32 bytes
        assert!(debug.contains("AuthKey"));
        assert!(debug.contains("..."));
        assert!(debug.len() < 100); // Should be short
    }

    #[test]
    fn display_abbreviated() {
        let key = AuthKey::from_seed(42);
        let display = format!("{key}");

        assert!(display.contains("AuthKey"));
        assert!(display.contains("..."));
    }

    #[test]
    fn zero_key() {
        let key = AuthKey::zero();
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }
}
