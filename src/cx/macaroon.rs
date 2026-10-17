//! Macaroon-based capability tokens for decentralized attenuation (bd-2lqyk.1).
//!
//! Macaroons are bearer tokens with chained HMAC caveats that enable
//! **decentralized capability attenuation**. Any holder can add caveats
//! (restrictions) without contacting the issuer. First-party caveats and the
//! native protected third-party envelope preserve that attenuation boundary.
//! The legacy third-party envelope exposes a prefix signature to its discharge
//! authority; see `MacaroonToken::add_third_party_caveat` before using it.
//!
//! # Token Format
//!
//! A [`MacaroonToken`] consists of:
//! - **Identifier**: Names the capability and its scope (e.g., `"spawn:region_42"`)
//! - **Location**: Hint for the issuing subsystem (e.g., `"cx/scheduler"`)
//! - **Signature**: HMAC chain over identifier + all caveats
//! - **Caveats**: Ordered list of [`Caveat`] predicates
//!
//! # HMAC Chain
//!
//! The signature chain follows the Macaroon construction from
//! Birgisson et al. 2014:
//!
//! ```text
//! sig_0 = HMAC(root_key, identifier)
//! sig_i = HMAC(sig_{i-1}, caveat_i.predicate_bytes())
//! token.signature = sig_n
//! ```
//!
//! Verification recomputes the chain from the root key and checks
//! `computed_sig == token.signature`.
//!
//! # Caveat Predicate Language
//!
//! Caveats use a simple predicate DSL:
//!
//! - `TimeBefore(deadline_ms)` — token expires at virtual time T
//! - `TimeAfter(start_ms)` — token is not valid before virtual time T
//! - `RegionScope(region_id)` — restricts to a specific region
//! - `TaskScope(task_id)` — restricts to a specific task
//! - `MaxUses(n)` — maximum number of capability checks
//! - `Custom(key, value)` — extensible key-value predicate
//!
//! # Serialization
//!
//! Binary format (little-endian):
//!
//! ```text
//! [version: u8]
//! [identifier_len: u16] [identifier: bytes]
//! [location_len: u16]   [location: bytes]
//! [caveat_count: u16]
//! for each caveat:
//!   [predicate_tag: u8]
//!   [predicate_data_len: u16] [predicate_data: bytes]
//! [signature: 32 bytes]
//! ```
//!
//! # Evidence Logging
//!
//! Capability verification events are logged to an
//! [`EvidenceSink`](crate::evidence_sink::EvidenceSink)
//! with `component="cx_macaroon"`.
//!
//! # Reference
//!
//! - Birgisson et al., "Macaroons: Cookies with Contextual Caveats for
//!   Decentralized Authorization in the Cloud" (NDSS 2014)
//! - Alien CS Graveyard §11.8 (Capability-Based Security)

use crate::security::key::{AUTH_KEY_SIZE, AuthKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current Macaroon binary schema version (v2: HMAC-SHA256 + third-party caveats).
pub const MACAROON_SCHEMA_VERSION: u8 = 2;

// Native protected verification-key identifier, version 1. The marker is not
// a valid first-party predicate tag, so its chained bytes cannot be confused
// with a first-party predicate. Legacy VIDs remain exactly 32 bytes.
const PROTECTED_VID_MARKER: u8 = 0xA1;
const PROTECTED_VID_NONCE_SIZE: usize = 24;
const PROTECTED_VID_TAG_SIZE: usize = 16;
const PROTECTED_VID_SIZE: usize =
    1 + PROTECTED_VID_NONCE_SIZE + AUTH_KEY_SIZE + PROTECTED_VID_TAG_SIZE;
const MAX_TOKEN_CAVEATS: usize = 64;

#[cfg(not(target_arch = "wasm32"))]
const PROTECTED_VID_KEY_DOMAIN: &[u8] = b"asupersync-macaroon-protected-vid-key-v1\0";
#[cfg(not(target_arch = "wasm32"))]
const PROTECTED_VID_AAD_DOMAIN: &[u8] = b"asupersync-macaroon-protected-vid-aad-v1\0";
#[cfg(not(target_arch = "wasm32"))]
const PROTECTED_VID_NONCE_DOMAIN: &[u8] = b"asupersync-macaroon-protected-vid-nonce-v1\0";

// ---------------------------------------------------------------------------
// CaveatPredicate
// ---------------------------------------------------------------------------

/// A predicate that restricts when/where a capability token is valid.
///
/// Caveats form a conjunction: all must be satisfied for the token
/// to be valid. New caveats can only narrow (never widen) access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatPredicate {
    /// Token is valid only before this virtual timestamp (milliseconds).
    TimeBefore(u64),
    /// Token is valid only after this virtual timestamp (milliseconds).
    TimeAfter(u64),
    /// Token is scoped to a specific region ID.
    RegionScope(u64),
    /// Token is scoped to a specific task ID.
    TaskScope(u64),
    /// Maximum number of times the token may be checked.
    MaxUses(u32),
    /// Token is scoped to resources matching a glob pattern.
    ///
    /// The pattern uses simple glob syntax: `*` matches any segment,
    /// `**` matches any number of segments, exact segments match literally.
    /// A path with a `.`, `..` or backslash segment never matches: check
    /// the canonical (resolved) path.
    ResourceScope(String),
    /// Windowed rate limit: at most `max_count` uses per `window_secs` seconds.
    ///
    /// Checked against a verifier-supplied window count and matching window
    /// duration. Missing or mismatched window metadata fails closed.
    RateLimit {
        /// Maximum invocations allowed in the window.
        max_count: u32,
        /// Window duration in seconds (encoded for the caveat chain,
        /// checked externally).
        window_secs: u32,
    },
    /// Custom key-value predicate for extensibility.
    Custom(String, String),
}

/// br-asupersync-5i331u — error returned by [`CaveatPredicate::validate`].
///
/// This covers string-bearing variants with payloads too large to encode in
/// the caveat wire format, which uses a `u16` length prefix. Without this
/// gate, calling `to_bytes()` on such a caveat would panic at
/// `u16::try_from(...).expect(...)` — a process-level DoS reachable from any
/// code path that constructs a `Custom` or `ResourceScope` caveat from
/// attacker-influenced input.
///
/// Callers that handle externally-supplied caveat content MUST call
/// `validate()` before passing the predicate to `Macaroon` issuance /
/// verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaveatEncodeError {
    /// `CaveatPredicate::ResourceScope`'s pattern exceeds `u16::MAX`
    /// (65535) bytes — the wire-format length prefix cannot encode it.
    PatternTooLarge {
        /// The actual byte length the caveat carries.
        actual: usize,
        /// The maximum supported length (`u16::MAX as usize`).
        max: usize,
    },
    /// `CaveatPredicate::Custom`'s key exceeds `u16::MAX` (65535) bytes.
    CustomKeyTooLarge {
        /// The actual byte length the key carries.
        actual: usize,
        /// The maximum supported length.
        max: usize,
    },
    /// `CaveatPredicate::Custom`'s value exceeds `u16::MAX` (65535) bytes.
    CustomValueTooLarge {
        /// The actual byte length the value carries.
        actual: usize,
        /// The maximum supported length.
        max: usize,
    },
}

impl std::fmt::Display for CaveatEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PatternTooLarge { actual, max } => write!(
                f,
                "ResourceScope pattern is {actual} bytes; wire format max is {max} (br-asupersync-5i331u)"
            ),
            Self::CustomKeyTooLarge { actual, max } => write!(
                f,
                "Custom caveat key is {actual} bytes; wire format max is {max} (br-asupersync-5i331u)"
            ),
            Self::CustomValueTooLarge { actual, max } => write!(
                f,
                "Custom caveat value is {actual} bytes; wire format max is {max} (br-asupersync-5i331u)"
            ),
        }
    }
}

impl std::error::Error for CaveatEncodeError {}

impl CaveatPredicate {
    /// br-asupersync-5i331u — validate that this caveat can be encoded
    /// without panic. Callers that handle externally-supplied caveat
    /// content (e.g., a capability-issuance API that takes a request-
    /// supplied resource pattern) MUST call this before passing the
    /// predicate to `Macaroon::issue`. Any string-bearing variant
    /// carrying a payload above `u16::MAX` (65535) bytes is rejected.
    ///
    /// Returns `Ok(())` if the predicate fits the wire format,
    /// `Err(CaveatEncodeError::*)` otherwise. Variants that don't
    /// carry user-controlled bytes (`TimeBefore`, `MaxUses`, etc.)
    /// always validate.
    pub fn validate(&self) -> Result<(), CaveatEncodeError> {
        const MAX: usize = u16::MAX as usize;
        match self {
            Self::ResourceScope(pattern) => {
                if pattern.len() > MAX {
                    return Err(CaveatEncodeError::PatternTooLarge {
                        actual: pattern.len(),
                        max: MAX,
                    });
                }
            }
            Self::Custom(key, value) => {
                if key.len() > MAX {
                    return Err(CaveatEncodeError::CustomKeyTooLarge {
                        actual: key.len(),
                        max: MAX,
                    });
                }
                if value.len() > MAX {
                    return Err(CaveatEncodeError::CustomValueTooLarge {
                        actual: value.len(),
                        max: MAX,
                    });
                }
            }
            // Other variants carry no user-controlled bytes.
            Self::TimeBefore(_)
            | Self::TimeAfter(_)
            | Self::RegionScope(_)
            | Self::TaskScope(_)
            | Self::MaxUses(_)
            | Self::RateLimit { .. } => {}
        }
        Ok(())
    }

    /// Encode the predicate to bytes for HMAC chaining.
    ///
    /// # Panics
    ///
    /// Panics if a string-bearing variant exceeds `u16::MAX` bytes —
    /// callers handling untrusted input MUST call [`Self::validate`]
    /// first to catch this case (br-asupersync-5i331u).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::TimeBefore(t) => {
                buf.push(0x01);
                buf.extend_from_slice(&t.to_le_bytes());
            }
            Self::TimeAfter(t) => {
                buf.push(0x02);
                buf.extend_from_slice(&t.to_le_bytes());
            }
            Self::RegionScope(id) => {
                buf.push(0x03);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            Self::TaskScope(id) => {
                buf.push(0x04);
                buf.extend_from_slice(&id.to_le_bytes());
            }
            Self::MaxUses(n) => {
                buf.push(0x05);
                buf.extend_from_slice(&n.to_le_bytes());
            }
            Self::ResourceScope(pattern) => {
                buf.push(0x07);
                let pb = pattern.as_bytes();
                let len =
                    u16::try_from(pb.len()).expect("ResourceScope pattern exceeds u16::MAX bytes");
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(pb);
            }
            Self::RateLimit {
                max_count,
                window_secs,
            } => {
                buf.push(0x08);
                buf.extend_from_slice(&max_count.to_le_bytes());
                buf.extend_from_slice(&window_secs.to_le_bytes());
            }
            Self::Custom(key, value) => {
                buf.push(0x06);
                let kb = key.as_bytes();
                let vb = value.as_bytes();
                let klen =
                    u16::try_from(kb.len()).expect("Custom caveat key exceeds u16::MAX bytes");
                let vlen =
                    u16::try_from(vb.len()).expect("Custom caveat value exceeds u16::MAX bytes");
                buf.extend_from_slice(&klen.to_le_bytes());
                buf.extend_from_slice(kb);
                buf.extend_from_slice(&vlen.to_le_bytes());
                buf.extend_from_slice(vb);
            }
        }
        buf
    }

    /// Decode a predicate from bytes. Returns the predicate and bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `None` if the bytes are malformed.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }
        let tag = data[0];
        let rest = &data[1..];

        match tag {
            0x01 => {
                if rest.len() < 8 {
                    return None;
                }
                let t = u64::from_le_bytes(rest[..8].try_into().ok()?);
                Some((Self::TimeBefore(t), 9))
            }
            0x02 => {
                if rest.len() < 8 {
                    return None;
                }
                let t = u64::from_le_bytes(rest[..8].try_into().ok()?);
                Some((Self::TimeAfter(t), 9))
            }
            0x03 => {
                if rest.len() < 8 {
                    return None;
                }
                let id = u64::from_le_bytes(rest[..8].try_into().ok()?);
                Some((Self::RegionScope(id), 9))
            }
            0x04 => {
                if rest.len() < 8 {
                    return None;
                }
                let id = u64::from_le_bytes(rest[..8].try_into().ok()?);
                Some((Self::TaskScope(id), 9))
            }
            0x05 => {
                if rest.len() < 4 {
                    return None;
                }
                let n = u32::from_le_bytes(rest[..4].try_into().ok()?);
                Some((Self::MaxUses(n), 5))
            }
            0x07 => {
                if rest.len() < 2 {
                    return None;
                }
                let pat_len = u16::from_le_bytes(rest[..2].try_into().ok()?) as usize;
                let rest = &rest[2..];
                if rest.len() < pat_len {
                    return None;
                }
                let pattern = std::str::from_utf8(&rest[..pat_len]).ok()?.to_string();
                let total = 1 + 2 + pat_len;
                Some((Self::ResourceScope(pattern), total))
            }
            0x08 => {
                if rest.len() < 8 {
                    return None;
                }
                let max_count = u32::from_le_bytes(rest[..4].try_into().ok()?);
                let window_secs = u32::from_le_bytes(rest[4..8].try_into().ok()?);
                Some((
                    Self::RateLimit {
                        max_count,
                        window_secs,
                    },
                    9,
                ))
            }
            0x06 => {
                if rest.len() < 2 {
                    return None;
                }
                let key_len = u16::from_le_bytes(rest[..2].try_into().ok()?) as usize;
                let rest = &rest[2..];
                if rest.len() < key_len + 2 {
                    return None;
                }
                let key = std::str::from_utf8(&rest[..key_len]).ok()?.to_string();
                let rest = &rest[key_len..];
                let val_len = u16::from_le_bytes(rest[..2].try_into().ok()?) as usize;
                let rest = &rest[2..];
                if rest.len() < val_len {
                    return None;
                }
                let value = std::str::from_utf8(&rest[..val_len]).ok()?.to_string();
                let total = 1 + 2 + key_len + 2 + val_len;
                Some((Self::Custom(key, value), total))
            }
            _ => None,
        }
    }

    /// Human-readable summary of this predicate.
    #[must_use]
    pub fn display_string(&self) -> String {
        match self {
            Self::TimeBefore(t) => format!("time < {t}ms"),
            Self::TimeAfter(t) => format!("time >= {t}ms"),
            Self::RegionScope(id) => format!("region == {id}"),
            Self::TaskScope(id) => format!("task == {id}"),
            Self::MaxUses(n) => format!("uses <= {n}"),
            Self::ResourceScope(p) => format!("resource ~ {p}"),
            Self::RateLimit {
                max_count,
                window_secs,
            } => format!("rate <= {max_count}/{window_secs}s"),
            Self::Custom(k, v) => format!("{k} = {v}"),
        }
    }
}

impl fmt::Display for CaveatPredicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

// ---------------------------------------------------------------------------
// Caveat
// ---------------------------------------------------------------------------

/// A single caveat in a Macaroon chain.
///
/// First-party caveats are verified by the target service using a
/// [`CaveatPredicate`]. Third-party caveats delegate verification to
/// an external authority via discharge macaroons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    /// A first-party caveat verified by the target service.
    FirstParty {
        /// The predicate to check against the verification context.
        predicate: CaveatPredicate,
    },
    /// A third-party caveat verified via a discharge macaroon.
    ThirdParty {
        /// Location hint for the third-party verifier.
        location: String,
        /// Identifier the third party uses to determine what to check.
        identifier: String,
        /// Verification-key ID: the caveat root key encrypted under
        /// the chain signature at the point this caveat was added.
        vid: Vec<u8>,
    },
}

impl Caveat {
    /// Create a first-party caveat from a predicate.
    #[must_use]
    pub fn first_party(predicate: CaveatPredicate) -> Self {
        Self::FirstParty { predicate }
    }

    /// Returns the predicate if this is a first-party caveat.
    #[must_use]
    pub fn predicate(&self) -> Option<&CaveatPredicate> {
        match self {
            Self::FirstParty { predicate } => Some(predicate),
            Self::ThirdParty { .. } => None,
        }
    }

    /// Returns the bytes used in the HMAC chain for this caveat.
    #[must_use]
    pub fn chain_bytes(&self) -> Vec<u8> {
        match self {
            Self::FirstParty { predicate } => predicate.to_bytes(),
            Self::ThirdParty {
                vid, identifier, ..
            } => {
                let mut bytes = Vec::with_capacity(vid.len() + identifier.len());
                bytes.extend_from_slice(vid);
                bytes.extend_from_slice(identifier.as_bytes());
                bytes
            }
        }
    }

    /// Returns true if this is a third-party caveat.
    #[must_use]
    pub fn is_third_party(&self) -> bool {
        matches!(self, Self::ThirdParty { .. })
    }
}

// ---------------------------------------------------------------------------
// MacaroonSignature
// ---------------------------------------------------------------------------

/// A 32-byte HMAC signature for a Macaroon token.
#[derive(Clone, Copy, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)] // PartialEq is deliberately constant-time
pub struct MacaroonSignature {
    bytes: [u8; AUTH_KEY_SIZE],
}

impl PartialEq for MacaroonSignature {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing side-channel attacks.
        let mut diff = 0u8;
        for i in 0..AUTH_KEY_SIZE {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        diff == 0
    }
}

impl Eq for MacaroonSignature {}

impl MacaroonSignature {
    /// Create a signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUTH_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.bytes
    }

    /// Constant-time equality check.
    #[must_use]
    fn constant_time_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..AUTH_KEY_SIZE {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        diff == 0
    }
}

impl fmt::Debug for MacaroonSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sig(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// MacaroonKeyRing — overlap window for signature rotation (br-asupersync-bp985e)
// ---------------------------------------------------------------------------

/// Two-slot [`MacaroonSignature`] holder enabling zero-downtime signature
/// rotation.
///
/// Mirror of [`crate::security::KeyRing`] for the macaroon-binding path: when a
/// token's binding signature is rotated (e.g., after a discharge re-issuance)
/// the prior signature stays acceptable for an operator-defined overlap window
/// so in-flight tokens carrying the old binding still verify.
///
/// Operational lifecycle:
///
/// 1. `MacaroonKeyRing::new(active)` — only the new signature is accepted.
/// 2. `ring.rotate(new_sig)` — prior signature moves to the retired slot.
/// 3. `ring.retire()` — discard the retired slot once in-flight tokens have
///    drained.
///
/// [`verify`](Self::verify) compares the candidate against the active slot
/// first via constant-time equality (inherited from
/// [`PartialEq`]); if that fails and a retired signature
/// is present, it compares against the retired slot. The active-first
/// ordering keeps the steady-state cost at one comparison.
#[derive(Clone, Debug)]
pub struct MacaroonKeyRing {
    /// The currently-active binding signature. New tokens MUST bind under
    /// this signature; verification tries it first.
    pub active: MacaroonSignature,
    /// The previously-active binding signature, retained to validate
    /// in-flight tokens issued before the most recent rotation. `None`
    /// outside a rotation window.
    pub retired: Option<MacaroonSignature>,
}

impl MacaroonKeyRing {
    /// Construct a fresh ring with `active` as the only signature.
    #[must_use]
    pub fn new(active: MacaroonSignature) -> Self {
        Self {
            active,
            retired: None,
        }
    }

    /// Rotate the ring: the prior active signature moves to the retired
    /// slot, and `new` becomes active. Any signature already in the retired
    /// slot is overwritten.
    pub fn rotate(&mut self, new: MacaroonSignature) {
        let prior = std::mem::replace(&mut self.active, new);
        self.retired = Some(prior);
    }

    /// End the rotation window by discarding the retired signature.
    /// Idempotent.
    pub fn retire(&mut self) {
        self.retired = None;
    }

    /// Verify a candidate signature against the active slot first, then the
    /// retired slot if present. Returns `true` if EITHER slot matches the
    /// candidate in constant time.
    ///
    /// Constant-time comparison is inherited from [`MacaroonSignature`]'s
    /// `PartialEq` impl, which XORs the full 32 bytes regardless of the
    /// position of the first differing byte. (br-asupersync-y4fpfl) The
    /// retired slot is also compared against in EVERY call (using a
    /// zero-filled sentinel when `retired` is `None`) so wall-clock
    /// timing does not depend on rotation state — an attacker who can
    /// time-stamp many `verify` calls cannot distinguish between
    /// "rotation window open" and "rotation window closed" by the
    /// bimodal cost of one-vs-two comparisons.
    #[must_use]
    pub fn verify(&self, candidate: &MacaroonSignature) -> bool {
        let active_match = self.active.constant_time_eq(candidate);
        // br-asupersync-y4fpfl: ALWAYS compare against the retired
        // slot, even when it's None, to keep verify wall-clock time
        // independent of rotation state. The candidate comes from the
        // caller, so a sentinel match must never count: without a retired
        // signature the comparison runs but its result is masked off
        // (otherwise an all-zero candidate would match the zero sentinel).
        let zero_signature_sentinel = MacaroonSignature::from_bytes([0u8; AUTH_KEY_SIZE]);
        let retired_ref = self.retired.as_ref().unwrap_or(&zero_signature_sentinel);
        let retired_match =
            u8::from(retired_ref.constant_time_eq(candidate)) & u8::from(self.retired.is_some());
        // OR-fold without short-circuit so the boolean combine itself
        // is also constant-time.
        u8::from(active_match) | retired_match != 0
    }
}

// ---------------------------------------------------------------------------
// MacaroonToken
// ---------------------------------------------------------------------------

/// A Macaroon bearer token with HMAC-chained caveats.
///
/// Macaroons support decentralized capability attenuation: any holder
/// can add caveats (restrictions) without the root key, but only the
/// issuer (who knows the root key) can verify the token.
#[derive(Clone, PartialEq)]
pub struct MacaroonToken {
    /// The capability identifier (e.g., "spawn:region_42").
    identifier: String,
    /// Location hint for the issuing subsystem.
    location: String,
    /// Ordered list of caveats (conjunction — all must hold).
    caveats: Vec<Caveat>,
    /// HMAC chain signature (over identifier + all caveats).
    signature: MacaroonSignature,
    /// br-asupersync-00ze7h: in-memory marker that this token has
    /// been through `bind_for_request`. A second bind would compute
    /// `HMAC(auth_sig, HMAC(auth_sig, unbound_sig))` instead of the
    /// expected `HMAC(auth_sig, unbound_sig)` — the resulting token
    /// silently fails verification and the holder cannot tell why.
    /// This flag lets `bind_for_request` reject the double-bind
    /// explicitly via [`BindError::AlreadyBound`]. NOT serialized
    /// (the binary schema is unchanged): if a holder serializes a
    /// bound token and then deserializes it the flag is lost — by
    /// convention, serialized macaroons are treated as unbound and
    /// callers must not re-bind across a serialize/deserialize
    /// round-trip.
    bound: bool,
}

impl fmt::Debug for MacaroonToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacaroonToken")
            .field("identifier", &"<redacted>")
            .field("location", &"<redacted>")
            .field("caveat_count", &self.caveats.len())
            .field("signature", &self.signature)
            .field("bound", &self.bound)
            .finish()
    }
}

struct ThirdPartyVerification<'a> {
    context: &'a VerificationContext,
    discharges: &'a [MacaroonToken],
    /// br-asupersync-bst7yx: the AUTH (root authorizing) macaroon's
    /// unbound signature. Used as the binding key for ALL nested
    /// discharge verifications, regardless of how deeply nested.
    /// Per the Macaroon spec (Birgisson 2014) and the dominant
    /// reference implementations (libmacaroons, pymacaroons,
    /// go-macaroons), every discharge in a request bundle binds to
    /// the SAME auth unbound_sig — never to a parent discharge's
    /// sig. This field replaces the previous `unbound_signature`
    /// (which was the CURRENT token's unbound sig and incorrectly
    /// flowed into the nested binding check, producing
    /// bind-to-parent semantics that contradicted the spec and the
    /// `bind_for_request` docstring).
    auth_unbound_signature: &'a MacaroonSignature,
    walk: &'a mut DischargeWalk,
}

#[cfg(test)]
std::thread_local! {
    /// Discharge verifications this thread ran (tests count the walk's work).
    static DISCHARGE_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// State of one discharge verification walk.
#[derive(Default)]
struct DischargeWalk {
    /// Explicit protected-only policy, shared by every recursive discharge.
    /// The default preserves verification of deployed legacy tokens.
    require_protected: bool,
    /// Discharges being verified on the current path (cycle detection and
    /// the depth bound).
    active: Vec<u64>,
    /// Discharges this walk already verified, with the caveat key each was
    /// verified under. A later caveat that references the same discharge
    /// under the same key reuses the result: verifying it again for every
    /// reference made fan-out discharge chains exponential (s45073 M1).
    verified: std::collections::HashSet<(u64, [u8; AUTH_KEY_SIZE])>,
}

impl MacaroonToken {
    /// Mint a new Macaroon token with no caveats.
    ///
    /// The root key is known only to the issuer and used for
    /// verification. The token stores only the computed signature.
    #[must_use]
    pub fn mint(root_key: &AuthKey, identifier: &str, location: &str) -> Self {
        let sig = hmac_compute(root_key, identifier.as_bytes());
        Self {
            identifier: identifier.to_string(),
            location: location.to_string(),
            caveats: Vec::new(),
            signature: MacaroonSignature::from_bytes(*sig.as_bytes()),
            bound: false,
        }
    }

    /// Returns true if this token has been bound to an authorizing
    /// macaroon via [`Self::bind_for_request`]. Bound tokens cannot be
    /// re-bound (the second bind would silently produce an
    /// unverifiable token). (br-asupersync-00ze7h)
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.bound
    }

    /// Add a first-party caveat to the token.
    ///
    /// This attenuates the token by adding a restriction. The HMAC
    /// chain is extended: `sig' = HMAC-SHA256(sig, predicate_bytes)`.
    ///
    /// This operation does NOT require the root key — any holder
    /// can add caveats.
    #[must_use]
    pub fn add_caveat(mut self, predicate: CaveatPredicate) -> Self {
        let pred_bytes = predicate.to_bytes();
        let current_key = AuthKey::from_hmac_derived(*self.signature.as_bytes())
            .expect("Macaroon signature should be valid HMAC output");
        let new_sig = hmac_compute(&current_key, &pred_bytes);
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(Caveat::first_party(predicate));
        self
    }

    /// Returns true if `self` is exactly `parent` attenuated by one
    /// additional first-party caveat.
    ///
    /// This is a runtime guard for callers that derive child capability
    /// contexts. It verifies that attenuation preserved the signed
    /// identifier/location, retained every parent caveat as an ordered prefix,
    /// appended the requested predicate, and produced the expected next HMAC
    /// chain signature. A failure means the derived token may have widened or
    /// corrupted the parent capability and must be rejected fail-closed.
    #[must_use]
    pub fn is_direct_attenuation_of(
        &self,
        parent: &Self,
        added_predicate: &CaveatPredicate,
    ) -> bool {
        if self.identifier != parent.identifier || self.location != parent.location {
            return false;
        }
        if self.bound != parent.bound {
            return false;
        }
        if self.caveats.len() != parent.caveats.len() + 1 {
            return false;
        }
        if !self.caveats.starts_with(&parent.caveats) {
            return false;
        }
        if !matches!(
            self.caveats.last(),
            Some(Caveat::FirstParty { predicate }) if predicate == added_predicate
        ) {
            return false;
        }

        let Ok(parent_sig_key) = AuthKey::from_hmac_derived(*parent.signature.as_bytes()) else {
            return false;
        };
        let expected_sig = hmac_compute(&parent_sig_key, &added_predicate.to_bytes());
        MacaroonSignature::from_bytes(*expected_sig.as_bytes()).constant_time_eq(&self.signature)
    }

    /// Add a legacy third-party caveat to the token.
    ///
    /// The `caveat_key` is a shared secret between the issuer and
    /// the third party. It is encrypted under the current chain
    /// signature as `vid = XOR(sig, caveat_key)` so the verifier can
    /// recover it during verification.
    ///
    /// The HMAC chain is extended over the `vid` bytes.
    ///
    /// # Security
    ///
    /// This compatibility envelope reveals the preceding chain signature to
    /// anyone who knows `caveat_key`: XORing that key with `vid` recovers it.
    /// Such a party can remove this caveat and every later caveat. New native
    /// integrations should use `add_protected_third_party_caveat` and
    /// `verify_with_protected_discharges_for_identifier` instead. Existing
    /// legacy issuance and verification are unchanged (asupersync-s45073 H2).
    #[must_use]
    pub fn add_third_party_caveat(
        mut self,
        location: &str,
        tp_identifier: &str,
        caveat_key: &AuthKey,
    ) -> Self {
        let vid = xor_pad(self.signature.as_bytes(), caveat_key.as_bytes());
        let current_key = AuthKey::from_hmac_derived(*self.signature.as_bytes())
            .expect("Macaroon signature should be valid HMAC output");
        let mut chain_bytes = Vec::with_capacity(vid.len() + tp_identifier.len());
        chain_bytes.extend_from_slice(&vid);
        chain_bytes.extend_from_slice(tp_identifier.as_bytes());
        let new_sig = hmac_compute(&current_key, &chain_bytes);
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(Caveat::ThirdParty {
            location: location.to_string(),
            identifier: tp_identifier.to_string(),
            vid,
        });
        self
    }

    /// Add an authenticated, encrypted third-party caveat on native targets.
    ///
    /// The caveat key is sealed with XChaCha20-Poly1305 under a
    /// domain-separated HMAC key derived from the current chain signature.
    /// The version and length-delimited discharge identifier are authenticated;
    /// the location remains an unsigned routing hint. A discharge authority
    /// cannot recover the preceding signature from its caveat key and this VID.
    /// Discharges are still minted with [`Self::mint`] and bound to the final
    /// authorizing token with [`Self::bind_for_request`].
    ///
    /// `nonce` should be 24 fresh CSPRNG bytes from the caller's explicit
    /// entropy capability; deterministic test entropy, clocks and task IDs are
    /// not production nonce sources. It is not used as the cipher nonce
    /// directly: the cipher nonce is an HMAC, under a key derived from the
    /// chain signature, of `nonce`, the caveat key and the authenticated
    /// identifier, and the VID carries it. A repeated `nonce` (a cloned
    /// prefix, a restarted counter) therefore never repeats the keystream for
    /// a different caveat key or identifier, so one discharge authority cannot
    /// recover another's caveat key from the two VIDs; repeating all three
    /// yields an identical VID. This method performs no ambient entropy or I/O.
    ///
    /// Use `verify_with_protected_discharges_for_identifier` at the native
    /// authorization boundary to reject legacy envelopes at every depth.
    /// Migrating an already-issued legacy capability also requires a fresh
    /// issuer key or a newly issued identifier: a previously leaked prefix
    /// signature cannot be revoked merely by rejecting visible legacy VIDs.
    /// Rotate discharge keys too if legacy tokens were issued under them.
    ///
    /// The schema-v2 outer frame is retained, with a separately tagged,
    /// fixed-size VID. Older verifiers and wasm32 verifiers refuse this new
    /// envelope; all parties that verify it must support the native profile.
    ///
    /// # Errors
    ///
    /// Refuses bound tokens and inputs that cannot round-trip through the
    /// existing bounded binary format. Encryption failure leaves no token.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn add_protected_third_party_caveat(
        mut self,
        location: &str,
        tp_identifier: &str,
        caveat_key: &AuthKey,
        nonce: [u8; 24],
    ) -> Result<Self, ProtectedCaveatError> {
        if self.bound {
            return Err(ProtectedCaveatError::AlreadyBound);
        }
        if self.caveats.len() >= MAX_TOKEN_CAVEATS
            || !self.has_encodable_wire_fields()
            || location.len() > usize::from(u16::MAX)
            || tp_identifier.len() > usize::from(u16::MAX)
        {
            return Err(ProtectedCaveatError::WireLimit);
        }

        let current_key = AuthKey::from_hmac_derived(*self.signature.as_bytes())
            .expect("Macaroon signature has the fixed HMAC output size");
        let vid = seal_protected_caveat_key(&current_key, tp_identifier, caveat_key, &nonce)?;
        let caveat = Caveat::ThirdParty {
            location: location.to_string(),
            identifier: tp_identifier.to_string(),
            vid,
        };
        let new_sig = hmac_compute(&current_key, &caveat.chain_bytes());
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(caveat);
        Ok(self)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn has_encodable_wire_fields(&self) -> bool {
        let maximum = usize::from(u16::MAX);
        self.identifier.len() <= maximum
            && self.location.len() <= maximum
            && self.caveats.len() <= MAX_TOKEN_CAVEATS
            && self.caveats.iter().all(|caveat| match caveat {
                Caveat::FirstParty { predicate } => match predicate {
                    CaveatPredicate::ResourceScope(pattern) => pattern.len() <= maximum - 3,
                    CaveatPredicate::Custom(key, value) => {
                        key.len() <= maximum - 5 && value.len() <= maximum - 5 - key.len()
                    }
                    _ => true,
                },
                Caveat::ThirdParty {
                    location,
                    identifier,
                    vid,
                } => {
                    location.len() <= maximum && identifier.len() <= maximum && vid.len() <= maximum
                }
            })
    }

    /// Bind a discharge macaroon to this authorizing macaroon.
    ///
    /// The discharge's signature is replaced with
    /// `HMAC-SHA256(auth_sig, discharge_sig)`, preventing reuse of
    /// the discharge with a different authorizing token.
    ///
    /// # Errors
    ///
    /// Returns [`BindError::AlreadyBound`] when `discharge` has
    /// already been bound. Pre-fix a double-bind silently produced a
    /// token whose signature was `HMAC(auth, HMAC(auth, unbound))`
    /// instead of `HMAC(auth, unbound)`, which then failed
    /// verification with a generic `InvalidSignature` and no
    /// indication of the cause. (br-asupersync-00ze7h)
    pub fn bind_for_request(&self, discharge: &Self) -> Result<Self, BindError> {
        if discharge.bound {
            return Err(BindError::AlreadyBound);
        }
        let binding_key = AuthKey::from_hmac_derived(*self.signature.as_bytes())
            .expect("Macaroon signature should be valid HMAC output");
        let bound_sig = hmac_compute(&binding_key, discharge.signature.as_bytes());
        Ok(Self {
            identifier: discharge.identifier.clone(),
            location: discharge.location.clone(),
            caveats: discharge.caveats.clone(),
            signature: MacaroonSignature::from_bytes(*bound_sig.as_bytes()),
            bound: true,
        })
    }

    /// Verify the token's HMAC chain against the root key.
    ///
    /// Recomputes the full chain and checks the final signature.
    /// This requires the root key (only the issuer can verify).
    #[must_use]
    pub fn verify_signature(&self, root_key: &AuthKey) -> bool {
        let computed = self.recompute_signature(root_key);
        computed.constant_time_eq(&self.signature)
    }

    /// Verify the token and check all first-party caveat predicates.
    ///
    /// Returns `Ok(())` if signature is valid AND all first-party caveats
    /// pass. No discharges are supplied, so a token with a third-party caveat
    /// fails with [`VerificationError::MissingDischarge`]; use
    /// [`verify_with_discharges`](Self::verify_with_discharges) for those.
    ///
    /// This validates integrity and caveat satisfaction only. Callers that are
    /// authorizing a specific capability should use
    /// [`verify_for_identifier`](Self::verify_for_identifier) so a token minted
    /// for one identifier cannot be replayed as a different capability.
    ///
    /// # Errors
    ///
    /// Returns a `VerificationError` describing what failed.
    pub fn verify(
        &self,
        root_key: &AuthKey,
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        self.verify_with_discharges(root_key, context, &[])
    }

    /// Verify the token for a specific capability identifier.
    ///
    /// This is the authorization-safe variant of [`Self::verify`]. It rejects
    /// tokens whose signed identifier does not match the expected capability,
    /// then verifies the signature chain and first-party caveats. As with
    /// [`Self::verify`], a third-party caveat fails with
    /// [`VerificationError::MissingDischarge`].
    pub fn verify_for_identifier(
        &self,
        root_key: &AuthKey,
        expected_identifier: &str,
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        self.verify_with_discharges_for_identifier(root_key, expected_identifier, context, &[])
    }

    /// Verify the token, checking first-party predicates and matching
    /// third-party caveats against the supplied discharge macaroons.
    ///
    /// Each discharge must be bound to this token via
    /// [`bind_for_request`](Self::bind_for_request) before calling.
    ///
    /// # Errors
    ///
    /// Returns a `VerificationError` describing what failed.
    pub fn verify_with_discharges(
        &self,
        root_key: &AuthKey,
        context: &VerificationContext,
        discharges: &[Self],
    ) -> Result<(), VerificationError> {
        let mut walk = DischargeWalk::default();
        self.verify_with_discharges_inner(root_key, context, discharges, None, None, &mut walk)
            .map(|_| ())
    }

    /// Verify the token for a specific capability identifier, including any
    /// supplied third-party discharges.
    pub fn verify_with_discharges_for_identifier(
        &self,
        root_key: &AuthKey,
        expected_identifier: &str,
        context: &VerificationContext,
        discharges: &[Self],
    ) -> Result<(), VerificationError> {
        if self.identifier != expected_identifier {
            return Err(VerificationError::UnexpectedIdentifier {
                expected: expected_identifier.to_string(),
                actual: self.identifier.clone(),
            });
        }

        let mut walk = DischargeWalk::default();
        self.verify_with_discharges_inner(root_key, context, discharges, None, None, &mut walk)
            .map(|_| ())
    }

    /// Authorize an exact capability using only native protected third-party
    /// envelopes, including every recursively referenced discharge.
    ///
    /// First-party-only tokens and discharges are accepted. A visible legacy
    /// VID is refused even when its signature and discharge are valid. Binding,
    /// first-party predicates, depth limits, and discharge memoization use the
    /// same verifier as [`Self::verify_with_discharges_for_identifier`].
    ///
    /// This is an explicit policy; the existing verification methods retain
    /// legacy acceptance. It cannot detect a legacy token whose unsafe caveat
    /// has already been stripped using a leaked prefix signature. Migrate
    /// with a fresh issuer key or a newly issued identifier, and reissue all
    /// affected grants. Do not fall back to legacy verification on failure,
    /// including while trying overlapping issuer keys during rotation.
    /// [`MacaroonKeyRing::verify`] compares signatures only and is not a
    /// substitute for this complete capability check.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::InvalidSignature`] for a top-level legacy
    /// or malformed VID, and [`VerificationError::DischargeInvalid`] when a
    /// nested discharge carries one. Other refusal shapes are unchanged.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify_with_protected_discharges_for_identifier(
        &self,
        root_key: &AuthKey,
        expected_identifier: &str,
        context: &VerificationContext,
        discharges: &[Self],
    ) -> Result<(), VerificationError> {
        if self.identifier != expected_identifier {
            return Err(VerificationError::UnexpectedIdentifier {
                expected: expected_identifier.to_string(),
                actual: self.identifier.clone(),
            });
        }
        let mut walk = DischargeWalk {
            require_protected: true,
            ..DischargeWalk::default()
        };
        self.verify_with_discharges_inner(root_key, context, discharges, None, None, &mut walk)
            .map(|_| ())
    }

    /// Maximum nesting depth for recursive third-party discharge verification.
    /// Prevents stack overflow from deeply nested (but acyclic) discharge chains.
    /// Maximum discharge depth to prevent stack overflow (br-asupersync-kya99g).
    /// Reduced from 32 to 16 for additional safety margin against stack exhaustion
    /// in environments with limited stack space.
    const MAX_DISCHARGE_DEPTH: usize = 16;

    /// Recursive verification driver.
    ///
    /// `binding_signature`: the AUTH (root authorizing) macaroon's
    /// unbound signature, used as the HMAC key for the discharge's
    /// binding-signature check. `None` at the top level (the auth
    /// itself isn't bound to anything); `Some(auth_unbound)` for
    /// every nested discharge level.
    ///
    /// `auth_unbound_signature`: the SAME auth unbound_sig propagated
    /// down the recursion so nested third-party caveats can pass it
    /// to their own recursive verifications. `None` at the top level
    /// (the auth's own unbound is computed inside this call and
    /// becomes `auth_unbound` for any first-level discharges);
    /// `Some(...)` from the first nested level onward.
    /// (br-asupersync-bst7yx)
    fn verify_with_discharges_inner(
        &self,
        root_key: &AuthKey,
        context: &VerificationContext,
        discharges: &[Self],
        binding_signature: Option<&MacaroonSignature>,
        auth_unbound_signature: Option<&MacaroonSignature>,
        walk: &mut DischargeWalk,
    ) -> Result<MacaroonSignature, VerificationError> {
        #[cfg(not(target_arch = "wasm32"))]
        if walk.require_protected && !self.has_encodable_wire_fields() {
            return Err(VerificationError::InvalidSignature);
        }
        // Enhanced depth checking to prevent stack overflow (br-asupersync-kya99g)
        if walk.active.len() >= Self::MAX_DISCHARGE_DEPTH {
            return Err(VerificationError::DischargeChainTooDeep {
                depth: walk.active.len(),
            });
        }

        // Additional stack safety check (br-asupersync-kya99g)
        // Approximate stack usage check to prevent overflow in tight loops
        const STACK_FRAME_SIZE_ESTIMATE: usize = 2048; // Conservative estimate per frame
        let approximate_stack_usage = walk.active.len() * STACK_FRAME_SIZE_ESTIMATE;
        if approximate_stack_usage > 32768 {
            // Conservative 32KB stack usage limit
            return Err(VerificationError::DischargeChainTooDeep {
                depth: walk.active.len(),
            });
        }

        let unbound_signature = self.verify_discharge_signature(root_key, binding_signature)?;
        let self_ptr = Self::discharge_stack_id(self);
        if walk.active.contains(&self_ptr) {
            return Err(Self::discharge_invalid(0, &self.identifier));
        }
        walk.active.push(self_ptr);

        // br-asupersync-bst7yx: at the top level we just computed the
        // AUTH macaroon's unbound_sig — it becomes the
        // auth_unbound_signature for ALL nested discharges. At
        // nested levels we propagate the auth's unbound unchanged so
        // every depth binds to the SAME root, per the Macaroon spec.
        let effective_auth_unbound = auth_unbound_signature.unwrap_or(&unbound_signature);

        let result = self
            .verify_caveat_chain(root_key, context, discharges, effective_auth_unbound, walk)
            .map(|()| unbound_signature);

        walk.active.pop();
        result
    }

    fn verify_discharge_signature(
        &self,
        root_key: &AuthKey,
        binding_signature: Option<&MacaroonSignature>,
    ) -> Result<MacaroonSignature, VerificationError> {
        let unbound_signature = self.recompute_signature(root_key);
        if let Some(binding_signature) = binding_signature {
            let expected_bound = hmac_compute(
                &AuthKey::from_hmac_derived(*binding_signature.as_bytes())
                    .expect("Binding signature should be valid HMAC output"),
                unbound_signature.as_bytes(),
            );
            let expected_bound_sig = MacaroonSignature::from_bytes(*expected_bound.as_bytes());
            if !expected_bound_sig.constant_time_eq(&self.signature) {
                return Err(Self::discharge_invalid(0, &self.identifier));
            }
        } else if !unbound_signature.constant_time_eq(&self.signature) {
            return Err(VerificationError::InvalidSignature);
        }

        Ok(unbound_signature)
    }

    fn verify_caveat_chain(
        &self,
        root_key: &AuthKey,
        context: &VerificationContext,
        discharges: &[Self],
        auth_unbound_signature: &MacaroonSignature,
        walk: &mut DischargeWalk,
    ) -> Result<(), VerificationError> {
        let mut sig = hmac_compute(root_key, self.identifier.as_bytes());
        let mut third_party = ThirdPartyVerification {
            context,
            discharges,
            auth_unbound_signature,
            walk,
        };
        for (index, caveat) in self.caveats.iter().enumerate() {
            sig = match caveat {
                Caveat::FirstParty { predicate } => {
                    Self::advance_first_party_caveat(index, predicate, context, &sig)?
                }
                Caveat::ThirdParty {
                    identifier: tp_id,
                    vid,
                    ..
                } => Self::advance_third_party_caveat(index, tp_id, vid, &sig, &mut third_party)?,
            };
        }

        Ok(())
    }

    fn advance_first_party_caveat(
        index: usize,
        predicate: &CaveatPredicate,
        context: &VerificationContext,
        sig: &AuthKey,
    ) -> Result<AuthKey, VerificationError> {
        if let Err(reason) = check_caveat(predicate, context) {
            return Err(VerificationError::CaveatFailed {
                index,
                predicate: predicate.display_string(),
                reason,
            });
        }

        let pred_bytes = predicate.to_bytes();
        Ok(hmac_compute(sig, &pred_bytes))
    }

    fn advance_third_party_caveat(
        index: usize,
        tp_id: &str,
        vid: &[u8],
        sig: &AuthKey,
        verification: &mut ThirdPartyVerification<'_>,
    ) -> Result<AuthKey, VerificationError> {
        let caveat_key = if vid.len() == AUTH_KEY_SIZE && !verification.walk.require_protected {
            let caveat_key_bytes = xor_pad(sig.as_bytes(), vid);
            AuthKey::from_hmac_derived(
                caveat_key_bytes
                    .try_into()
                    .map_err(|_| VerificationError::InvalidSignature)?,
            )
            .map_err(|_| VerificationError::WeakCaveatKey)?
        } else if vid.len() == PROTECTED_VID_SIZE && vid[0] == PROTECTED_VID_MARKER {
            #[cfg(not(target_arch = "wasm32"))]
            {
                open_protected_caveat_key(sig, tp_id, vid)?
            }
            // The AEAD dependency is deliberately native-only. A browser must
            // never interpret this envelope as a legacy XOR key on fallback.
            #[cfg(target_arch = "wasm32")]
            {
                return Err(VerificationError::InvalidSignature);
            }
        } else {
            return Err(VerificationError::InvalidSignature);
        };
        let discharge = Self::find_discharge(index, tp_id, verification.discharges)?;
        let discharge_ptr = Self::discharge_stack_id(discharge);
        if verification.walk.active.contains(&discharge_ptr) {
            return Err(Self::discharge_invalid(index, tp_id));
        }

        // A discharge verified under this caveat key earlier in the walk is
        // valid here too: the context and the binding (the authorizing
        // token's unbound signature) are the same for the whole walk.
        // (Recording it before verifying is safe: a failure aborts the whole
        // walk, and a discharge that references itself is caught by the
        // `active` check above first.)
        let memo = (discharge_ptr, *caveat_key.as_bytes());
        if verification.walk.verified.insert(memo) {
            #[cfg(test)]
            DISCHARGE_VERIFICATIONS.with(|count| count.set(count.get() + 1));
            // Stack overflow protection (br-asupersync-kya99g)
            if verification.walk.active.len() >= Self::MAX_DISCHARGE_DEPTH - 1 {
                return Err(VerificationError::DischargeChainTooDeep {
                    depth: verification.walk.active.len() + 1,
                });
            }

            // br-asupersync-bst7yx: bind ALL nested discharges to the
            // ROOT authorizing macaroon's unbound_sig (not the parent
            // discharge's). This matches the Macaroon spec and the
            // bind_for_request docstring.
            discharge
                .verify_with_discharges_inner(
                    &caveat_key,
                    verification.context,
                    verification.discharges,
                    Some(verification.auth_unbound_signature),
                    Some(verification.auth_unbound_signature),
                    verification.walk,
                )
                .map_err(|err| Self::map_discharge_error(index, tp_id, err))?;
        }

        let mut chain_bytes = Vec::with_capacity(vid.len() + tp_id.len());
        chain_bytes.extend_from_slice(vid);
        chain_bytes.extend_from_slice(tp_id.as_bytes());
        Ok(hmac_compute(sig, &chain_bytes))
    }

    fn find_discharge<'a>(
        index: usize,
        tp_id: &str,
        discharges: &'a [Self],
    ) -> Result<&'a Self, VerificationError> {
        discharges
            .iter()
            .find(|discharge| discharge.identifier() == tp_id)
            .ok_or_else(|| VerificationError::MissingDischarge {
                index,
                identifier: tp_id.to_string(),
            })
    }

    fn discharge_stack_id(token: &Self) -> u64 {
        // P2 FIX (asupersync-uq5m3l): Use stable content-based hash instead of memory address
        // to prevent TOCTOU attacks on discharge cycle detection. Memory addresses are unreliable
        // due to ASLR and could be manipulated to bypass or falsely trigger cycle detection.
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(token.identifier.as_bytes());
        hasher.update(token.signature.as_bytes());
        let result = hasher.finalize();
        // Use first 8 bytes as deterministic, collision-resistant identifier
        u64::from_be_bytes(
            result[..8]
                .try_into()
                .expect("SHA-256 output is always at least 8 bytes"),
        )
    }

    fn discharge_invalid(index: usize, identifier: &str) -> VerificationError {
        VerificationError::DischargeInvalid {
            index,
            identifier: identifier.to_string(),
        }
    }

    fn map_discharge_error(index: usize, tp_id: &str, err: VerificationError) -> VerificationError {
        match err {
            VerificationError::InvalidSignature
            | VerificationError::UnexpectedIdentifier { .. }
            | VerificationError::DischargeInvalid { .. }
            | VerificationError::WeakCaveatKey => Self::discharge_invalid(index, tp_id),
            VerificationError::MissingDischarge { identifier, .. } => {
                VerificationError::MissingDischarge { index, identifier }
            }
            VerificationError::CaveatFailed {
                predicate, reason, ..
            } => VerificationError::CaveatFailed {
                index,
                predicate: format!("discharge[{tp_id}]: {predicate}"),
                reason,
            },
            VerificationError::DischargeChainTooDeep { depth } => {
                VerificationError::DischargeChainTooDeep { depth }
            }
        }
    }

    /// Returns the capability identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Returns the location hint.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Returns the caveats.
    #[must_use]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Returns the number of caveats.
    #[must_use]
    pub fn caveat_count(&self) -> usize {
        self.caveats.len()
    }

    /// Returns the current signature.
    #[must_use]
    pub fn signature(&self) -> &MacaroonSignature {
        &self.signature
    }

    /// A key for replay caches and use counters: SHA-256 of the identifier
    /// followed by the signature.
    ///
    /// Do not key on [`to_binary`](Self::to_binary) bytes. The top-level
    /// location and the third-party caveat locations are unsigned hints, as
    /// in the macaroon design, so one signed token has many byte encodings
    /// that all verify. The signature covers the identifier and every caveat,
    /// so tokens with equal keys carry the same capability. The key is a hash
    /// because the signature is the bearer secret: a key stored in a shared
    /// cache or written to a log must not be enough to rebuild the token.
    #[must_use]
    pub fn replay_key(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(self.identifier.as_bytes());
        hasher.update(self.signature.as_bytes());
        hasher.finalize().into()
    }

    /// Serialize to binary format (schema v2).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_binary(&self) -> Vec<u8> {
        // Helper to write a length-prefixed byte slice, asserting u16 bounds.
        fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
            let len = u16::try_from(data.len()).expect("macaroon field exceeds u16::MAX bytes");
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(data);
        }

        let mut buf = Vec::new();
        buf.push(MACAROON_SCHEMA_VERSION);

        // Identifier
        write_len_prefixed(&mut buf, self.identifier.as_bytes());

        // Location
        write_len_prefixed(&mut buf, self.location.as_bytes());

        // Caveats
        let caveat_count =
            u16::try_from(self.caveats.len()).expect("macaroon caveat count exceeds u16::MAX");
        buf.extend_from_slice(&caveat_count.to_le_bytes());
        for caveat in &self.caveats {
            match caveat {
                Caveat::FirstParty { predicate } => {
                    buf.push(0x00);
                    let pred_bytes = predicate.to_bytes();
                    write_len_prefixed(&mut buf, &pred_bytes);
                }
                Caveat::ThirdParty {
                    location: tp_loc,
                    identifier: tp_id,
                    vid,
                } => {
                    buf.push(0x01);
                    write_len_prefixed(&mut buf, tp_loc.as_bytes());
                    write_len_prefixed(&mut buf, tp_id.as_bytes());
                    write_len_prefixed(&mut buf, vid);
                }
            }
        }

        // Signature
        buf.extend_from_slice(self.signature.as_bytes());
        buf
    }

    /// Deserialize from binary format (schema v2).
    ///
    /// The locations in the encoding are not signed, so different bytes can
    /// decode to the same signed token; key replay caches on
    /// [`replay_key`](Self::replay_key), not on these bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` if the binary data is malformed.
    #[must_use]
    pub fn from_binary(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let mut pos = 0;

        let version = data[pos];
        if version != MACAROON_SCHEMA_VERSION {
            return None;
        }
        pos += 1;

        // Identifier
        let identifier = read_len_prefixed_str(data, &mut pos)?;

        // Location
        let location = read_len_prefixed_str(data, &mut pos)?;

        // Caveats
        if pos + 2 > data.len() {
            return None;
        }
        let caveat_count_raw = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;

        // SECURITY: Prevent unbounded memory DoS by enforcing hard limit on caveat count.
        // Previous vulnerability: safe_capacity was bounded but loop ran for full caveat_count,
        // allowing attackers to cause memory exhaustion via excessive iterations.
        // Reject macaroons with excessive caveat counts immediately
        if caveat_count_raw > MAX_TOKEN_CAVEATS {
            return None;
        }

        // Every declared caveat must decode: a count that disagrees with the
        // caveats present is malformed, not a shorter token. The capacity is
        // still bounded by the bytes left (each caveat takes at least 3).
        let mut caveats = Vec::with_capacity(caveat_count_raw.min((data.len() - pos) / 3));
        for _ in 0..caveat_count_raw {
            if pos >= data.len() {
                return None;
            }
            let caveat_type = data[pos];
            pos += 1;

            match caveat_type {
                0x00 => {
                    if pos + 2 > data.len() {
                        return None;
                    }
                    let pred_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
                    pos += 2;
                    if pos + pred_len > data.len() {
                        return None;
                    }
                    // The frame holds exactly one predicate. Locations are
                    // unsigned hints, though, so token bytes are still no
                    // replay key; callers use `replay_key`.
                    let (predicate, consumed) =
                        CaveatPredicate::from_bytes(&data[pos..pos + pred_len])?;
                    if consumed != pred_len {
                        return None;
                    }
                    caveats.push(Caveat::first_party(predicate));
                    pos += pred_len;
                }
                0x01 => {
                    let tp_loc = read_len_prefixed_str(data, &mut pos)?;
                    let tp_id = read_len_prefixed_str(data, &mut pos)?;
                    let vid = read_len_prefixed_bytes(data, &mut pos)?;
                    caveats.push(Caveat::ThirdParty {
                        location: tp_loc,
                        identifier: tp_id,
                        vid,
                    });
                }
                _ => return None,
            }
        }

        // Signature
        if pos + AUTH_KEY_SIZE > data.len() {
            return None;
        }
        let sig_bytes: [u8; AUTH_KEY_SIZE] = data[pos..pos + AUTH_KEY_SIZE].try_into().ok()?;
        pos += AUTH_KEY_SIZE;

        // Reject trailing bytes — a well-formed token is exactly `pos` bytes.
        if pos != data.len() {
            return None;
        }

        let signature = MacaroonSignature::from_bytes(sig_bytes);

        Some(Self {
            identifier,
            location,
            caveats,
            signature,
            // br-asupersync-00ze7h: deserialized tokens are treated as
            // unbound — the binary schema does not carry the bound
            // flag, so callers must not re-bind across a serialize /
            // deserialize round-trip.
            bound: false,
        })
    }

    /// Recompute the HMAC chain from the root key.
    fn recompute_signature(&self, root_key: &AuthKey) -> MacaroonSignature {
        let mut sig = hmac_compute(root_key, self.identifier.as_bytes());
        for caveat in &self.caveats {
            let chain = caveat.chain_bytes();
            sig = hmac_compute(&sig, &chain);
        }
        MacaroonSignature::from_bytes(*sig.as_bytes())
    }
}

impl fmt::Display for MacaroonToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Macaroon(id=<redacted>, loc=<redacted>, caveats={}, sig={:?}, bound={})",
            self.caveats.len(),
            self.signature,
            self.bound,
        )
    }
}

// ---------------------------------------------------------------------------
// VerificationContext
// ---------------------------------------------------------------------------

/// Runtime context for checking caveat predicates.
///
/// Passed to [`MacaroonToken::verify`] to evaluate caveats against
/// current runtime state.
#[derive(Debug, Clone, Default)]
pub struct VerificationContext {
    /// Current virtual time in milliseconds.
    pub current_time_ms: Option<u64>,
    /// Current region ID (for scope checks).
    pub region_id: Option<u64>,
    /// Current task ID (for scope checks).
    pub task_id: Option<u64>,
    /// Number of times this token has been used (lifetime).
    pub use_count: Option<u32>,
    /// The resource path being accessed (for [`CaveatPredicate::ResourceScope`] checks).
    pub resource_path: Option<String>,
    /// Duration of the active rate-limit window in seconds.
    pub window_secs: Option<u32>,
    /// Number of uses in the current rate-limit window
    /// (for [`CaveatPredicate::RateLimit`] checks).
    pub window_use_count: Option<u32>,
    /// Custom key-value pairs for custom predicate evaluation.
    pub custom: Vec<(String, String)>,
}

impl VerificationContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current virtual time.
    #[must_use]
    pub const fn with_time(mut self, time_ms: u64) -> Self {
        self.current_time_ms = Some(time_ms);
        self
    }

    /// Set the current region ID.
    #[must_use]
    pub const fn with_region(mut self, region_id: u64) -> Self {
        self.region_id = Some(region_id);
        self
    }

    /// Set the current task ID.
    #[must_use]
    pub const fn with_task(mut self, task_id: u64) -> Self {
        self.task_id = Some(task_id);
        self
    }

    /// Set the use count.
    #[must_use]
    pub const fn with_use_count(mut self, count: u32) -> Self {
        self.use_count = Some(count);
        self
    }

    /// Set the resource path being accessed.
    #[must_use]
    pub fn with_resource(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(path.into());
        self
    }

    /// Set the rate-limit window duration and observed use count.
    #[must_use]
    pub const fn with_window_use_count(mut self, window_secs: u32, count: u32) -> Self {
        self.window_secs = Some(window_secs);
        self.window_use_count = Some(count);
        self
    }

    /// Add a custom key-value pair.
    #[must_use]
    pub fn with_custom(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.push((key.into(), value.into()));
        self
    }
}

// ---------------------------------------------------------------------------
// VerificationError
// ---------------------------------------------------------------------------

/// Error returned when Macaroon verification fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// The HMAC chain does not match (token was tampered with or
    /// the wrong root key was used).
    InvalidSignature,
    /// The token was valid, but for a different capability identifier.
    UnexpectedIdentifier {
        /// Capability identifier the caller required.
        expected: String,
        /// Capability identifier carried by the token.
        actual: String,
    },
    /// A first-party caveat predicate was not satisfied.
    CaveatFailed {
        /// Index of the failing caveat in the chain.
        index: usize,
        /// Human-readable predicate description.
        predicate: String,
        /// Why it failed.
        reason: String,
    },
    /// A required discharge macaroon was not provided.
    MissingDischarge {
        /// Index of the third-party caveat.
        index: usize,
        /// Identifier the discharge should carry.
        identifier: String,
    },
    /// A discharge macaroon failed verification or binding check.
    DischargeInvalid {
        /// Index of the third-party caveat.
        index: usize,
        /// Identifier of the failing discharge.
        identifier: String,
    },
    /// The discharge chain exceeded the maximum allowed nesting depth.
    /// This prevents stack overflow from deeply nested (but acyclic) chains.
    DischargeChainTooDeep {
        /// Nesting depth at which the limit was hit.
        depth: usize,
    },
    /// A caveat key derived from HMAC failed entropy validation.
    /// This indicates a potential security issue in the key derivation chain.
    WeakCaveatKey,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "macaroon signature verification failed"),
            Self::UnexpectedIdentifier { expected, actual } => {
                write!(
                    f,
                    "macaroon identifier mismatch: expected \"{expected}\", got \"{actual}\""
                )
            }
            Self::CaveatFailed {
                index,
                predicate,
                reason,
            } => {
                write!(f, "caveat {index} failed: {predicate} ({reason})")
            }
            Self::MissingDischarge { index, identifier } => {
                write!(f, "caveat {index}: missing discharge for \"{identifier}\"")
            }
            Self::DischargeInvalid { index, identifier } => {
                write!(f, "caveat {index}: discharge \"{identifier}\" invalid")
            }
            Self::DischargeChainTooDeep { depth } => {
                write!(f, "discharge chain too deep ({depth} levels)")
            }
            Self::WeakCaveatKey => {
                write!(f, "caveat key derived from HMAC failed entropy validation")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

// ---------------------------------------------------------------------------
// BindError — br-asupersync-00ze7h
// ---------------------------------------------------------------------------

/// Error returned when [`MacaroonToken::bind_for_request`] cannot
/// proceed safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The discharge has already been bound to an authorizing
    /// macaroon. A second bind would compute
    /// `HMAC(auth_sig, HMAC(auth_sig, unbound))` instead of the
    /// expected `HMAC(auth_sig, unbound)`, silently producing a
    /// token that fails verification with `InvalidSignature` — and
    /// the holder cannot tell why. (br-asupersync-00ze7h)
    AlreadyBound,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyBound => write!(
                f,
                "macaroon discharge has already been bound; a second bind \
                 would silently produce an unverifiable token \
                 (br-asupersync-00ze7h)"
            ),
        }
    }
}

impl std::error::Error for BindError {}

/// Refusal from native protected third-party caveat issuance.
///
/// No variant carries a signature, caveat key, nonce, or capability contents.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtectedCaveatError {
    /// A discharge must be attenuated before binding it to its authorizing token.
    AlreadyBound,
    /// A string, caveat frame, or caveat count exceeds the existing wire limit.
    WireLimit,
    /// The authenticated envelope could not be produced.
    Encryption,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Display for ProtectedCaveatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AlreadyBound => "cannot add a protected caveat to a bound discharge",
            Self::WireLimit => "protected macaroon exceeds its binary encoding limit",
            Self::Encryption => "protected caveat encryption failed",
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::error::Error for ProtectedCaveatError {}

/// The AAD carries an explicit version and exact identifier length. Location
/// is intentionally excluded: macaroon locations are unsigned routing hints.
#[cfg(not(target_arch = "wasm32"))]
fn protected_vid_aad(identifier: &str) -> Option<Vec<u8>> {
    let length = u16::try_from(identifier.len()).ok()?;
    let mut aad = Vec::with_capacity(PROTECTED_VID_AAD_DOMAIN.len() + 3 + identifier.len());
    aad.extend_from_slice(PROTECTED_VID_AAD_DOMAIN);
    aad.push(PROTECTED_VID_MARKER);
    aad.extend_from_slice(&length.to_le_bytes());
    aad.extend_from_slice(identifier.as_bytes());
    Some(aad)
}

#[cfg(not(target_arch = "wasm32"))]
fn seal_protected_caveat_key(
    signature_key: &AuthKey,
    identifier: &str,
    caveat_key: &AuthKey,
    nonce: &[u8; PROTECTED_VID_NONCE_SIZE],
) -> Result<Vec<u8>, ProtectedCaveatError> {
    use chacha20poly1305::aead::{AeadInOut, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use zeroize::Zeroizing;

    let key = hmac_compute(signature_key, PROTECTED_VID_KEY_DOMAIN);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("derived wrapping key has the fixed 32-byte size");
    let associated = protected_vid_aad(identifier).ok_or(ProtectedCaveatError::WireLimit)?;
    // Synthetic nonce (SIV style): the caller's nonce alone would repeat the
    // keystream whenever two caveat keys were sealed under one prefix with
    // the same nonce, and XORing the two VIDs with one known key reveals the
    // other. Binding the key and identifier in removes that.
    let nonce_key = hmac_compute(signature_key, PROTECTED_VID_NONCE_DOMAIN);
    let mut nonce_input = Zeroizing::new(Vec::with_capacity(
        PROTECTED_VID_NONCE_SIZE + AUTH_KEY_SIZE + associated.len(),
    ));
    nonce_input.extend_from_slice(nonce);
    nonce_input.extend_from_slice(caveat_key.as_bytes());
    nonce_input.extend_from_slice(&associated);
    let synthetic = hmac_compute(&nonce_key, &nonce_input);
    let sealed_nonce = &synthetic.as_bytes()[..PROTECTED_VID_NONCE_SIZE];
    let cipher_nonce = XNonce::try_from(sealed_nonce).expect("fixed 24-byte nonce");
    let mut ciphertext = Zeroizing::new(*caveat_key.as_bytes());
    let tag = cipher
        .encrypt_inout_detached(&cipher_nonce, &associated, ciphertext.as_mut_slice().into())
        .map_err(|_| ProtectedCaveatError::Encryption)?;

    let mut vid = Vec::with_capacity(PROTECTED_VID_SIZE);
    vid.push(PROTECTED_VID_MARKER);
    vid.extend_from_slice(sealed_nonce);
    vid.extend_from_slice(ciphertext.as_slice());
    vid.extend_from_slice(&tag);
    Ok(vid)
}

#[cfg(not(target_arch = "wasm32"))]
fn open_protected_caveat_key(
    signature_key: &AuthKey,
    identifier: &str,
    vid: &[u8],
) -> Result<AuthKey, VerificationError> {
    use chacha20poly1305::aead::{AeadInOut, KeyInit};
    use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
    use zeroize::Zeroizing;

    // Validate the exact envelope before any field slicing or decryption.
    // In particular, a damaged protected VID never falls back to legacy XOR.
    if vid.len() != PROTECTED_VID_SIZE || vid[0] != PROTECTED_VID_MARKER {
        return Err(VerificationError::InvalidSignature);
    }
    let associated = protected_vid_aad(identifier).ok_or(VerificationError::InvalidSignature)?;
    let key = hmac_compute(signature_key, PROTECTED_VID_KEY_DOMAIN);
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("derived wrapping key has the fixed 32-byte size");
    let ciphertext_start = 1 + PROTECTED_VID_NONCE_SIZE;
    let tag_start = ciphertext_start + AUTH_KEY_SIZE;
    let nonce = XNonce::try_from(&vid[1..ciphertext_start]).expect("fixed 24-byte nonce field");
    let tag = Tag::try_from(&vid[tag_start..]).expect("fixed 16-byte authentication tag");
    let mut plaintext = Zeroizing::new([0; AUTH_KEY_SIZE]);
    plaintext.copy_from_slice(&vid[ciphertext_start..tag_start]);
    cipher
        .decrypt_inout_detached(&nonce, &associated, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| VerificationError::InvalidSignature)?;
    AuthKey::from_hmac_derived(*plaintext).map_err(|_| VerificationError::WeakCaveatKey)
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 computation
// ---------------------------------------------------------------------------

/// Compute `HMAC-SHA256(key, message)`, returning the result as an `AuthKey`.
fn hmac_compute(key: &AuthKey, message: &[u8]) -> AuthKey {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    // br-asupersync-q3terg: HMAC-SHA256 output is uniformly random by
    // construction, but we validate to catch potential implementation issues.
    AuthKey::from_hmac_derived(result.into())
        .expect("HMAC-SHA256 output should pass entropy validation")
}

/// XOR-pad two byte slices of equal length. Used for encrypting/decrypting
/// third-party caveat verification keys.
fn xor_pad(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "xor_pad: slices must have equal length ({} vs {})",
        a.len(),
        b.len()
    );
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// ---------------------------------------------------------------------------
// Binary deserialization helpers
// ---------------------------------------------------------------------------

fn read_len_prefixed_str(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = u16::from_le_bytes(data[*pos..*pos + 2].try_into().ok()?) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .ok()?
        .to_string();
    *pos += len;
    Some(s)
}

fn read_len_prefixed_bytes(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = u16::from_le_bytes(data[*pos..*pos + 2].try_into().ok()?) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let b = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(b)
}

// ---------------------------------------------------------------------------
// Caveat checking
// ---------------------------------------------------------------------------

/// Simple glob matching for resource scope caveats.
///
/// Supports:
/// - `*` matches a single path segment (no `/`)
/// - `**` matches zero or more segments (including `/`)
/// - Literal segments match exactly
///
/// Paths are split on `/`. Leading/trailing slashes are ignored.
fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // A non-canonical path can name something outside the pattern's scope
    // once it is resolved (`files/public/../secret`), so it never matches
    // (s45073 M2).
    if segs
        .iter()
        .any(|seg| *seg == "." || *seg == ".." || seg.contains('\\'))
    {
        return false;
    }
    glob_match_parts(&pattern_parts, &segs)
}

fn glob_match_parts(pat: &[&str], path: &[&str]) -> bool {
    let mut p = 0;
    let mut s = 0;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0;

    while s < path.len() {
        if p < pat.len() && (pat[p] == "*" || pat[p] == path[s]) {
            p += 1;
            s += 1;
        } else if p < pat.len() && pat[p] == "**" {
            star_idx = Some(p);
            match_idx = s;
            p += 1;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            s = match_idx;
        } else {
            return false;
        }
    }

    while p < pat.len() && pat[p] == "**" {
        p += 1;
    }

    p == pat.len()
}

/// Check a single caveat predicate against a verification context.
fn check_caveat(predicate: &CaveatPredicate, ctx: &VerificationContext) -> Result<(), String> {
    match predicate {
        CaveatPredicate::TimeBefore(deadline) => match ctx.current_time_ms {
            Some(current_time_ms) if current_time_ms < *deadline => Ok(()),
            Some(_) => Err("current time >= deadline".to_string()),
            None => Err("no current time in context".to_string()),
        },
        CaveatPredicate::TimeAfter(start) => match ctx.current_time_ms {
            Some(current_time_ms) if current_time_ms >= *start => Ok(()),
            Some(_) => Err("current time < start".to_string()),
            None => Err("no current time in context".to_string()),
        },
        CaveatPredicate::RegionScope(expected) => match ctx.region_id {
            Some(actual) if actual == *expected => Ok(()),
            Some(actual) => Err(format!("region {actual} != expected {expected}")),
            None => Err("no region in context".to_string()),
        },
        CaveatPredicate::TaskScope(expected) => match ctx.task_id {
            Some(actual) if actual == *expected => Ok(()),
            Some(actual) => Err(format!("task {actual} != expected {expected}")),
            None => Err("no task in context".to_string()),
        },
        CaveatPredicate::MaxUses(max) => match ctx.use_count {
            Some(use_count) if use_count <= *max => Ok(()),
            Some(use_count) => Err(format!("use count {} > max {max}", use_count)),
            None => Err("no use count in context".to_string()),
        },
        CaveatPredicate::ResourceScope(pattern) => ctx.resource_path.as_ref().map_or_else(
            || Err("no resource path in context".to_string()),
            |path| {
                if glob_match(pattern, path) {
                    Ok(())
                } else {
                    Err(format!(
                        "resource {path:?} does not match pattern {pattern:?}"
                    ))
                }
            },
        ),
        CaveatPredicate::RateLimit {
            max_count,
            window_secs,
        } => match (ctx.window_secs, ctx.window_use_count) {
            (Some(actual_window_secs), Some(_window_use_count))
                if actual_window_secs != *window_secs =>
            {
                Err(format!(
                    "window seconds {actual_window_secs} != expected {window_secs}"
                ))
            }
            (Some(_), Some(window_use_count)) if window_use_count <= *max_count => Ok(()),
            (Some(_), Some(window_use_count)) => Err(format!(
                "window use count {} > max {max_count}",
                window_use_count
            )),
            (None, _) => Err("no window seconds in context".to_string()),
            (_, None) => Err("no window use count in context".to_string()),
        },
        CaveatPredicate::Custom(key, expected_value) => {
            for (k, v) in &ctx.custom {
                if k == key {
                    if v == expected_value {
                        return Ok(());
                    }
                    return Err(format!("custom {key} = {v:?}, expected {expected_value:?}"));
                }
            }
            Err(format!("custom key {key:?} not found in context"))
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "macaroon_inline_tests.rs"]
mod tests;
