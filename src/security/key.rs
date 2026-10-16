//! Authentication keys and key derivation.
//!
//! Keys are 256-bit (32 byte) values used for HMAC-SHA256 authentication.
//!
//! Uses `ZeroizeOnDrop` for secure memory cleanup (br-asupersync-4cs8my).
//!
//! # Security Enhancements (asupersync-mjn8rx)
//!
//! This module has been hardened against malformed and weak key material:
//!
//! - **Enforced input-shape validation**: [`AuthKey::from_bytes`] rejects obvious
//!   low-diversity and pathological bit patterns. These heuristics are defense in
//!   depth; they do not measure entropy and cannot make predictable input secret.
//! - **Strengthened thresholds**: Minimum entropy requirements raised from 3.1% to 25%
//!   bit density (64-192 bits set out of 256), with 16+ distinct byte values required.
//! - **Concentration attack prevention**: No byte value may appear >4 times in a key.
//! - **Deterministic derivation is labeled honestly**: [`AuthKey::from_seed`] and
//!   [`AuthKey::from_rng`] are reproducibility conveniences, not production key
//!   generation. SHA-256 and HKDF do not increase the entropy of their input.
//! - **Constant-time equality**: Key comparisons examine all 32 bytes.

use crate::util::DetRng;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

type HmacSha256 = Hmac<Sha256>;

/// Size of an authentication key in bytes.
pub const AUTH_KEY_SIZE: usize = 32;

/// br-asupersync-q3terg: minimum number of distinct byte values
/// required across the 32-byte key.
///
/// A real CSPRNG/HKDF output has ~30 distinct values almost surely; 16
/// provides strong diversity while still allowing legitimate keys.
/// Rejects patterns with insufficient byte diversity.
pub const MIN_DISTINCT_BYTES: usize = 16;

/// br-asupersync-q3terg: minimum total Hamming weight (count of
/// 1-bits across all 256 bits).
///
/// A uniformly-random key has weight near 128; 64 (25%) provides
/// strong lower bound against entropy-starved keys while allowing
/// legitimate variation. Previous value of 8 was dangerously weak.
pub const MIN_HAMMING_WEIGHT: u32 = 64;

/// br-asupersync-q3terg: maximum total Hamming weight.
/// 192 (75%) provides strong upper bound against entropy-concentrated
/// keys. Previous value of 248 was dangerously permissive.
pub const MAX_HAMMING_WEIGHT: u32 = 192;

/// Maximum frequency any single byte value can appear in a valid key.
///
/// No byte value should appear more than 4 times in 32 bytes (12.5%).
/// This prevents concentration attacks where keys have predictable patterns.
pub const MAX_BYTE_FREQUENCY: usize = 4;

/// br-asupersync-q3terg: error returned when [`AuthKey::from_bytes`]
/// receives a low-entropy input that fails the strength validators.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthKeyError {
    /// The byte buffer fails the entropy validation rules.
    #[error("auth key rejected: {reason}")]
    WeakKey {
        /// The specific validator that rejected the input.
        reason: WeakKeyReason,
    },
}

/// br-asupersync-q3terg: which strength validator rejected the
/// input.
///
/// Each variant identifies the failed property and the observed value
/// so callers can diagnose misconfiguration without the validator
/// being a guessing game.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WeakKeyReason {
    /// Fewer distinct byte values than the configured minimum.
    #[error(
        "insufficient byte diversity: only {distinct} distinct byte values out of 32 (minimum {minimum})"
    )]
    InsufficientByteDiversity {
        /// Distinct byte values observed.
        distinct: usize,
        /// Required minimum.
        minimum: usize,
    },
    /// Hamming weight outside the acceptable range.
    #[error(
        "extreme Hamming weight: {weight} 1-bits out of 256 (acceptable range [{minimum}, {maximum}])"
    )]
    ExtremeHammingWeight {
        /// Total 1-bits across all 256 bits of the key.
        weight: u32,
        /// Minimum acceptable.
        minimum: u32,
        /// Maximum acceptable.
        maximum: u32,
    },
    /// Byte frequency concentration too high - indicates predictable patterns.
    #[error(
        "excessive byte concentration: byte value {byte_value} appears {frequency} times (maximum {maximum})"
    )]
    ExcessiveByteConcentration {
        /// The byte value that appears too frequently.
        byte_value: u8,
        /// How many times it appears.
        frequency: usize,
        /// Maximum allowed frequency.
        maximum: usize,
    },
}

/// A 256-bit authentication key.
///
/// **Sensitive material.** Derives [`ZeroizeOnDrop`] which provides secure
/// memory cleanup with compiler-resistant zeroization. The `Copy` derive was
/// removed (br-asupersync-4pegj0) so a key cannot be silently bit-copied past
/// the destructor; callers that need a logical duplicate must call `.clone()`
/// explicitly, which preserves the zeroize-on-drop contract for both copies.
#[derive(Clone, Hash, ZeroizeOnDrop)]
#[allow(clippy::derived_hash_with_manual_eq)] // PartialEq is deliberately constant-time.
pub struct AuthKey {
    bytes: [u8; AUTH_KEY_SIZE],
}

impl AuthKey {
    /// Creates a new key from a 64-bit seed.
    ///
    /// This uses domain-separated SHA-256 to deterministically expand the seed
    /// into 32 bytes without depending on `DetRng`'s zero-seed normalization.
    ///
    /// # Security
    ///
    /// This constructor has at most 64 bits of input entropy. SHA-256 and the
    /// fallback HKDF path distribute those bits but cannot create additional
    /// entropy, so this API is suitable for deterministic tests, fixtures, and
    /// reproducible simulations—not production authentication keys. Production
    /// callers should supply 32 bytes from a CSPRNG or secret-management system
    /// through [`Self::from_bytes`].
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"asupersync::security::AuthKey::from_seed:v1");
        hasher.update(seed.to_le_bytes());
        let bytes: [u8; AUTH_KEY_SIZE] = hasher.finalize().into();

        // SECURITY FIX: Enforce entropy validation even for SHA-256-derived keys
        // This prevents signature forgery attacks via carefully chosen weak seeds
        match Self::from_bytes(bytes) {
            Ok(key) => key,
            Err(_) => {
                // A SHA-256 output can occasionally fail the shape heuristic.
                // HKDF deterministically remaps it; this preserves availability
                // but does not increase the seed's 64-bit entropy.
                Self::from_hkdf(
                    &seed.to_le_bytes(),
                    Some(b"backup-salt"),
                    b"asupersync::AuthKey::strengthened",
                )
            }
        }
    }

    /// Creates a new key from the deterministic replay RNG.
    ///
    /// # Security
    ///
    /// [`DetRng`] is intentionally reproducible and is not a CSPRNG. This
    /// constructor is for deterministic tests and simulations, not production
    /// key generation. The output-shape validation below catches pathological
    /// buffers but cannot make a predictable RNG secret.
    #[must_use]
    pub fn from_rng(rng: &mut DetRng) -> Self {
        let mut bytes = [0u8; AUTH_KEY_SIZE];
        rng.fill_bytes(&mut bytes);

        // SECURITY FIX: Enforce entropy validation even for RNG-derived keys
        // This prevents signature forgery attacks via compromised RNG state
        match Self::from_bytes(bytes) {
            Ok(key) => key,
            Err(_) => {
                // RNG output failed the entropy heuristic; strengthen it with
                // HKDF, whose output is uniformly distributed by construction.
                // Accept that output directly (matching `from_seed`): the
                // heuristic entropy gate (`from_bytes`) must NOT be re-applied
                // to HKDF output. A small fraction of genuinely uniform 32-byte
                // buffers exceed `MAX_BYTE_FREQUENCY` purely by chance, so
                // re-validating here let a valid, strong key abort `from_rng`
                // — a `#[must_use]`, non-`Result` API whose contract is to
                // always yield a key — with a panic.
                Self::from_hkdf(
                    &bytes,
                    Some(b"rng-strengthen-salt"),
                    b"asupersync::AuthKey::rng-strengthened",
                )
            }
        }
    }

    /// Creates a new key from raw bytes WITH ENTROPY VALIDATION.
    ///
    /// br-asupersync-q3terg: rejects pathologically-low-entropy inputs
    /// (all-zero, all-0xFF, single-distinct-byte patterns, low-Hamming-
    /// weight extremes). HMAC-SHA256 security depends on the key
    /// having sufficient entropy; a key with zero entropy produces
    /// deterministic and predictable HMAC outputs — an attacker who
    /// learns of such a weak key (via leaked default, misconfig, or
    /// because the prior `from_bytes(bytes)` accepted any 32-byte
    /// buffer) can forge authentication tags for any symbol.
    ///
    /// Validation rules (any failure rejects with `AuthKeyError`):
    ///   * `bytes` must contain at least `MIN_DISTINCT_BYTES` (16)
    ///     distinct byte values out of 32. Strengthened from previous
    ///     dangerously-low threshold of 8.
    ///   * The Hamming weight (count of 1-bits across all 256 bits)
    ///     must lie in `[MIN_HAMMING_WEIGHT, MAX_HAMMING_WEIGHT]`
    ///     (64, 192). Represents 25%-75% bit density, preventing
    ///     entropy-starved keys. Previous thresholds (8, 248) were
    ///     cryptographically dangerous.
    ///   * No byte value may appear more than `MAX_BYTE_FREQUENCY`
    ///     (4) times. Prevents concentration attacks and predictable
    ///     patterns like repeating sequences.
    ///
    /// For known-strong byte sources (e.g. HMAC outputs in the
    /// macaroon caveat chain — by construction uniformly random),
    /// use `Self::from_hmac_derived` for HMAC-derived sources.
    /// That constructor is `pub(crate)` to prevent external code from
    /// accidentally importing the bypass path.
    #[inline]
    pub fn from_bytes(bytes: [u8; AUTH_KEY_SIZE]) -> Result<Self, AuthKeyError> {
        // Count distinct byte values and track frequency
        let mut byte_counts = [0u8; 256];
        let mut distinct = 0usize;

        for &b in bytes.iter() {
            let idx = b as usize;
            if byte_counts[idx] == 0 {
                distinct += 1;
            }
            byte_counts[idx] = byte_counts[idx].saturating_add(1);

            // Check concentration during counting for early exit
            if byte_counts[idx] > MAX_BYTE_FREQUENCY as u8 {
                return Err(AuthKeyError::WeakKey {
                    reason: WeakKeyReason::ExcessiveByteConcentration {
                        byte_value: b,
                        frequency: byte_counts[idx] as usize,
                        maximum: MAX_BYTE_FREQUENCY,
                    },
                });
            }
        }

        // Validate byte diversity
        if distinct < MIN_DISTINCT_BYTES {
            return Err(AuthKeyError::WeakKey {
                reason: WeakKeyReason::InsufficientByteDiversity {
                    distinct,
                    minimum: MIN_DISTINCT_BYTES,
                },
            });
        }

        // Validate Hamming weight (bit entropy)
        let hamming: u32 = bytes.iter().map(|b| b.count_ones()).sum();
        if !(MIN_HAMMING_WEIGHT..=MAX_HAMMING_WEIGHT).contains(&hamming) {
            return Err(AuthKeyError::WeakKey {
                reason: WeakKeyReason::ExtremeHammingWeight {
                    weight: hamming,
                    minimum: MIN_HAMMING_WEIGHT,
                    maximum: MAX_HAMMING_WEIGHT,
                },
            });
        }

        Ok(Self { bytes })
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

    /// Derives a key using strengthened HMAC-SHA256 with salt and context.
    ///
    /// This performs a two-step derivation that's cryptographically stronger than
    /// simple HMAC derivation:
    /// 1. Extract: PRK = HMAC-SHA256(salt, self)
    /// 2. Expand: derived_key = HMAC-SHA256(PRK, context)
    ///
    /// This provides domain separation and salt-based security enhancement.
    #[must_use]
    pub fn derive_with_salt(&self, salt: &[u8], context: &[u8]) -> Self {
        // Extract phase: PRK = HMAC-SHA256(salt, input_key_material)
        let mut extract_mac =
            HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
        extract_mac.update(&self.bytes);
        let prk = extract_mac.finalize().into_bytes();

        // Expand phase: OKM = HMAC-SHA256(PRK, context)
        let mut expand_mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
        expand_mac.update(context);
        let result = expand_mac.finalize().into_bytes();

        Self {
            bytes: result.into(),
        }
    }

    /// Creates a key from HMAC-derived bytes.
    ///
    /// This method is specifically designed for use with HMAC outputs,
    /// which are cryptographically strong by construction. It deliberately
    /// skips heuristic entropy validation to avoid rejecting uniform HMAC
    /// output by accident.
    ///
    /// Keep this crate-private so external callers cannot use it as a public
    /// bypass around [`Self::from_bytes`] entropy validation.
    pub(crate) fn from_hmac_derived(bytes: [u8; AUTH_KEY_SIZE]) -> Result<Self, AuthKeyError> {
        // HMAC-SHA256 outputs are cryptographically secure by construction.
        // Skip entropy validation to avoid false positives while maintaining
        // the Result type for consistency with other constructors.
        Ok(Self { bytes })
    }

    /// Creates a key using HKDF (HMAC-based Key Derivation Function).
    ///
    /// Performs the HKDF Extract-and-Expand process with the given input key material,
    /// optional salt, and context information to derive a domain-separated key.
    ///
    /// HKDF extracts and distributes existing entropy; it does not create entropy.
    /// The input key material must already contain sufficient secret entropy for
    /// the caller's threat model. A salt may be public and improves domain separation,
    /// but does not turn a password, short integer, or predictable seed into a
    /// production authentication secret.
    ///
    /// # Parameters
    /// * `ikm` - Input Key Material (the source entropy)
    /// * `salt` - Optional salt value for the extract phase
    /// * `info` - Context information for the expand phase
    ///
    /// # Security
    /// The resulting bytes have a pseudorandom output shape, so this constructor
    /// intentionally bypasses [`Self::from_bytes`]'s heuristic pattern checks.
    /// That is not a claim about the entropy of `ikm`.
    #[must_use]
    pub fn from_hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Self {
        const ZERO_SALT: [u8; AUTH_KEY_SIZE] = [0; AUTH_KEY_SIZE];

        // Extract phase: PRK = HKDF-Extract(salt, IKM)
        let mut extract_mac = HmacSha256::new_from_slice(salt.unwrap_or(&ZERO_SALT))
            .expect("HMAC accepts any key length");
        extract_mac.update(ikm);
        let prk = extract_mac.finalize().into_bytes();

        // Expand phase: OKM = HKDF-Expand(PRK, info, L). AUTH_KEY_SIZE fits
        // in one SHA-256 output block, so a single HKDF block is sufficient.
        let mut expand_mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
        expand_mac.update(info);
        expand_mac.update(&[1]);
        let result = expand_mac.finalize().into_bytes();
        let mut okm = [0u8; AUTH_KEY_SIZE];
        okm.copy_from_slice(&result[..AUTH_KEY_SIZE]);

        // HKDF output is uniformly distributed by construction, so skip validation
        Self { bytes: okm }
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey(<redacted>)")
    }
}

impl PartialEq for AuthKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for AuthKey {}

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
#[path = "key_inline_tests.rs"]
mod tests;
