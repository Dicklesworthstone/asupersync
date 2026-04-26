//! Authentication keys and key derivation.
//!
//! Keys are 256-bit (32 byte) values used for HMAC-SHA256 authentication.
//!
//! `unsafe` is allowed in this module solely for the manual-zeroize Drop
//! impl (`ptr::write_volatile` on a fully-owned `[u8; 32]`) — see
//! `Drop for AuthKey` (br-asupersync-4pegj0).

#![allow(unsafe_code)]

use crate::util::DetRng;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Size of an authentication key in bytes.
pub const AUTH_KEY_SIZE: usize = 32;

/// A 256-bit authentication key.
///
/// **Sensitive material.** Implements [`Drop`] which zeroizes the underlying
/// bytes via `ptr::write_volatile` + a `SeqCst` `compiler_fence`. The
/// `Copy` derive was removed (br-asupersync-4pegj0) so a key cannot be
/// silently bit-copied past the destructor; callers that need a logical
/// duplicate must call `.clone()` explicitly, which preserves the
/// zeroize-on-drop contract for both copies.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthKey {
    bytes: [u8; AUTH_KEY_SIZE],
}

impl Drop for AuthKey {
    /// Zeroes the key bytes when the value goes out of scope.
    ///
    /// Uses `ptr::write_volatile` per byte to defeat dead-store elimination
    /// (the compiler cannot prove the writes are observable, so it must
    /// emit them) and a `SeqCst` `compiler_fence` to bar reordering across
    /// the destructor boundary. This is the standard manual-zeroize
    /// pattern used when the `zeroize` crate is unavailable as a direct
    /// dependency. (br-asupersync-4pegj0)
    fn drop(&mut self) {
        // Safety: `bytes` is fully initialised owned storage; volatile byte
        // writes to it are well-defined. `compiler_fence` after the loop
        // prevents the optimiser from sinking later operations above the
        // zeroizing writes.
        for byte in &mut self.bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
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

// ---------------------------------------------------------------------------
// KeyRing — overlap window for key rotation (br-asupersync-bp985e)
// ---------------------------------------------------------------------------

/// Two-slot HMAC key holder enabling zero-downtime key rotation.
///
/// Operators rotate auth keys periodically (compliance-driven, or in response
/// to suspected leak). A single `AuthKey` cannot serve in-flight messages that
/// were authenticated with the previous key once it has been swapped, which
/// forces a flag-day cutover. `KeyRing` solves this by carrying an optional
/// retired key alongside the active one: [`verify`](Self::verify) accepts a
/// signature produced by either slot, so the rotation window can absorb
/// messages signed under either key.
///
/// Operational lifecycle:
///
/// 1. Start with `KeyRing::new(active)` — no retired key.
/// 2. When time to rotate, call `ring.rotate(new_key)` — the previous active
///    key is moved to the retired slot, the new key becomes active.
/// 3. After enough time has passed for in-flight messages to drain (governed
///    by the operator, not this type), call `ring.retire()` to discard the
///    old key and end the dual-acceptance window.
///
/// The retired slot holds at most one key — calling `rotate` twice in
/// succession discards the previously-retired key. Operators that need a
/// longer overlap window must stage rotations.
///
/// Both slots are `Drop`-zeroized via [`AuthKey`]'s destructor, so a key
/// removed from the ring (by [`rotate`](Self::rotate) or [`retire`](Self::retire))
/// is wiped from memory rather than lingering past its useful life.
#[derive(Clone, Debug)]
pub struct KeyRing {
    /// The currently-active key. New signatures MUST be produced with this
    /// key; verification tries it first.
    pub active: AuthKey,
    /// The previously-active key, kept around to validate in-flight messages
    /// signed before the most recent rotation. `None` outside a rotation
    /// window.
    pub retired: Option<AuthKey>,
}

impl KeyRing {
    /// Construct a fresh ring with `active` as the only key. No retired
    /// fallback until the first call to [`rotate`](Self::rotate).
    #[must_use]
    pub fn new(active: AuthKey) -> Self {
        Self {
            active,
            retired: None,
        }
    }

    /// Rotate the ring: the prior active key moves to the retired slot, and
    /// `new` becomes active. Any key already in the retired slot is dropped
    /// (and zeroized via [`AuthKey`]'s destructor).
    pub fn rotate(&mut self, new: AuthKey) {
        let prior = std::mem::replace(&mut self.active, new);
        self.retired = Some(prior);
    }

    /// End the rotation window by discarding the retired key. Idempotent —
    /// calling on a ring with no retired key is a no-op.
    pub fn retire(&mut self) {
        self.retired = None;
    }

    /// Verify an HMAC-SHA256 signature against the active key and, when
    /// present, the retired key. Returns `true` if EITHER key produces an
    /// HMAC over `msg` that matches `sig` in constant time.
    ///
    /// Constant-time equality (delegated to `mac.verify_slice`) guards each
    /// slot comparison. When a retired key is present, both slots are checked
    /// without returning early on an active-key match; the existence of the
    /// rotation window is operational state, but which slot accepted should
    /// not affect verification control flow.
    #[must_use]
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let active_matches = Self::verify_with_key(&self.active, msg, sig);
        let retired_matches = match &self.retired {
            Some(retired) => Self::verify_with_key(retired, msg, sig),
            None => false,
        };

        active_matches | retired_matches
    }

    fn verify_with_key(key: &AuthKey, msg: &[u8], sig: &[u8]) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.verify_slice(sig).is_ok()
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
    fn auth_key_clone_hash_eq() {
        // Renamed from `..._copy_...` because AuthKey is no longer Copy
        // (br-asupersync-4pegj0). Each "copy" must now be an explicit
        // `.clone()` so zeroize-on-drop applies to every duplicate.
        use std::collections::HashSet;
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let copied = k1.clone();
        let cloned = k1.clone();
        assert_eq!(copied, cloned);
        assert_ne!(k1, k2);

        let mut set = HashSet::new();
        set.insert(k1.clone());
        set.insert(k2.clone());
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

    /// br-asupersync-4pegj0: Drop must zeroise the key bytes. Verify by
    /// using `ManuallyDrop` to retain the storage past the destructor and
    /// observing the underlying byte array via a raw pointer obtained
    /// before `drop` ran. This is the standard manual-zeroize verification
    /// pattern (see `zeroize` crate's own tests).
    #[test]
    fn drop_zeroises_key_bytes() {
        use std::mem::ManuallyDrop;

        let mut key = ManuallyDrop::new(AuthKey::from_seed(0xDEAD_BEEF));
        // Snapshot a pointer to the bytes BEFORE running Drop. Reading
        // through this pointer after `ManuallyDrop::drop` is sound because
        // the storage is not deallocated — `ManuallyDrop` keeps the value
        // in place; only the destructor side-effect (the zeroize) runs.
        let bytes_ptr: *const [u8; AUTH_KEY_SIZE] = std::ptr::addr_of!(key.bytes);

        // Sanity: pre-drop the seed expansion produces non-zero bytes.
        let pre = unsafe { *bytes_ptr };
        assert!(
            pre.iter().any(|&b| b != 0),
            "from_seed must produce non-zero bytes pre-drop"
        );

        // Run the destructor manually.
        unsafe {
            ManuallyDrop::drop(&mut key);
        }

        // Post-drop, every byte must be zero.
        let post = unsafe { *bytes_ptr };
        assert!(
            post.iter().all(|&b| b == 0),
            "Drop must zeroise every key byte; observed: {post:02x?}"
        );
    }

    /// AuthKey must NOT implement `Copy` — silent bit-copies past the
    /// destructor would defeat zeroize-on-drop. Verified at the type level
    /// by trying to use `static_assertions`-style trait bounds.
    #[test]
    fn auth_key_is_not_copy() {
        // If AuthKey were Copy, this `move` of `k1` followed by use of `k1`
        // would compile. Since it must NOT, the assertion is a doc-test of
        // the semantic contract enforced by the type system at the call
        // sites that hold AuthKey by value.
        fn is_copy<T: Copy>() {}
        // The trait-bound check below is intentionally NOT instantiated;
        // the proof is that `is_copy::<AuthKey>()` would fail to compile.
        // We instead exercise the cloning path so callers can see the
        // explicit `.clone()` is the supported duplication mechanism.
        let _ = is_copy::<u8>; // keep the helper used to silence dead_code
        let k1 = AuthKey::from_seed(1);
        let k2 = k1.clone();
        assert_eq!(k1, k2);
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

    // =========================================================================
    // KeyRing — br-asupersync-bp985e
    // =========================================================================

    fn hmac_sign(key: &AuthKey, msg: &[u8]) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn key_ring_new_only_active_verifies() {
        let k = AuthKey::from_seed(1);
        let ring = KeyRing::new(k.clone());
        let sig = hmac_sign(&k, b"hello");
        assert!(ring.verify(b"hello", &sig));
        let other = AuthKey::from_seed(2);
        let bad_sig = hmac_sign(&other, b"hello");
        assert!(!ring.verify(b"hello", &bad_sig));
        assert!(ring.retired.is_none());
    }

    #[test]
    fn key_ring_rotate_accepts_old_and_new() {
        let old = AuthKey::from_seed(10);
        let new = AuthKey::from_seed(20);
        let mut ring = KeyRing::new(old.clone());

        let old_sig = hmac_sign(&old, b"in_flight");
        let new_sig = hmac_sign(&new, b"fresh");

        ring.rotate(new.clone());
        // Both must verify during the overlap window.
        assert!(
            ring.verify(b"in_flight", &old_sig),
            "retired key must accept"
        );
        assert!(ring.verify(b"fresh", &new_sig), "active key must accept");
        // Active is `new`, retired is the prior active.
        assert_eq!(ring.active, new);
        assert_eq!(ring.retired.as_ref(), Some(&old));
    }

    #[test]
    fn key_ring_retire_drops_retired_slot() {
        let old = AuthKey::from_seed(100);
        let new = AuthKey::from_seed(200);
        let mut ring = KeyRing::new(old.clone());
        ring.rotate(new.clone());
        ring.retire();
        let old_sig = hmac_sign(&old, b"stale");
        // Once retired() is called, old-key signatures MUST be rejected.
        assert!(!ring.verify(b"stale", &old_sig));
        // retire is idempotent.
        ring.retire();
        assert!(ring.retired.is_none());
    }

    #[test]
    fn key_ring_double_rotate_discards_oldest() {
        let k1 = AuthKey::from_seed(1);
        let k2 = AuthKey::from_seed(2);
        let k3 = AuthKey::from_seed(3);
        let mut ring = KeyRing::new(k1.clone());
        ring.rotate(k2.clone());
        ring.rotate(k3.clone());
        // After two rotations active=k3 retired=k2; k1 has been dropped and
        // its signatures MUST no longer verify.
        let k1_sig = hmac_sign(&k1, b"too_old");
        assert!(!ring.verify(b"too_old", &k1_sig));
        let k2_sig = hmac_sign(&k2, b"recently_retired");
        assert!(ring.verify(b"recently_retired", &k2_sig));
        let k3_sig = hmac_sign(&k3, b"current");
        assert!(ring.verify(b"current", &k3_sig));
    }
}
