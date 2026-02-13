//! Macaroon-based capability tokens for decentralized attenuation (bd-2lqyk.1).
//!
//! Macaroons are bearer tokens with chained HMAC caveats that enable
//! **decentralized capability attenuation**. Any holder can add caveats
//! (restrictions) without contacting the issuer, but nobody can remove
//! caveats without the root key.
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
//! Capability verification events are logged to an [`EvidenceSink`]
//! with `component="cx_macaroon"`.
//!
//! # Reference
//!
//! - Birgisson et al., "Macaroons: Cookies with Contextual Caveats for
//!   Decentralized Authorization in the Cloud" (NDSS 2014)
//! - Alien CS Graveyard §11.8 (Capability-Based Security)

use crate::security::key::{AuthKey, AUTH_KEY_SIZE};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current Macaroon binary schema version (v2: HMAC-SHA256 + third-party caveats).
pub const MACAROON_SCHEMA_VERSION: u8 = 2;

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
    ResourceScope(String),
    /// Windowed rate limit: at most `max_count` uses per `window_secs` seconds.
    ///
    /// Checked against `VerificationContext::window_use_count`. The caller
    /// is responsible for tracking the sliding window externally.
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

impl CaveatPredicate {
    /// Encode the predicate to bytes for HMAC chaining.
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
                #[allow(clippy::cast_possible_truncation)]
                {
                    buf.extend_from_slice(&(pb.len() as u16).to_le_bytes());
                    buf.extend_from_slice(pb);
                }
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
                #[allow(clippy::cast_possible_truncation)]
                {
                    buf.extend_from_slice(&(kb.len() as u16).to_le_bytes());
                    buf.extend_from_slice(kb);
                    buf.extend_from_slice(&(vb.len() as u16).to_le_bytes());
                    buf.extend_from_slice(vb);
                }
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
            Self::ThirdParty { vid, .. } => vid.clone(),
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacaroonSignature {
    bytes: [u8; AUTH_KEY_SIZE],
}

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
        write!(f, "Sig({:02x}{:02x}...)", self.bytes[0], self.bytes[1])
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
#[derive(Debug, Clone)]
pub struct MacaroonToken {
    /// The capability identifier (e.g., "spawn:region_42").
    identifier: String,
    /// Location hint for the issuing subsystem.
    location: String,
    /// Ordered list of caveats (conjunction — all must hold).
    caveats: Vec<Caveat>,
    /// HMAC chain signature (over identifier + all caveats).
    signature: MacaroonSignature,
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
        }
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
        let current_key = AuthKey::from_bytes(*self.signature.as_bytes());
        let new_sig = hmac_compute(&current_key, &pred_bytes);
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(Caveat::first_party(predicate));
        self
    }

    /// Add a third-party caveat to the token.
    ///
    /// The `caveat_key` is a shared secret between the issuer and
    /// the third party. It is encrypted under the current chain
    /// signature as `vid = XOR(sig, caveat_key)` so the verifier can
    /// recover it during verification.
    ///
    /// The HMAC chain is extended over the `vid` bytes.
    #[must_use]
    pub fn add_third_party_caveat(
        mut self,
        location: &str,
        tp_identifier: &str,
        caveat_key: &AuthKey,
    ) -> Self {
        let vid = xor_pad(self.signature.as_bytes(), caveat_key.as_bytes());
        let current_key = AuthKey::from_bytes(*self.signature.as_bytes());
        let new_sig = hmac_compute(&current_key, &vid);
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(Caveat::ThirdParty {
            location: location.to_string(),
            identifier: tp_identifier.to_string(),
            vid,
        });
        self
    }

    /// Bind a discharge macaroon to this authorizing macaroon.
    ///
    /// The discharge's signature is replaced with
    /// `HMAC-SHA256(auth_sig, discharge_sig)`, preventing reuse of
    /// the discharge with a different authorizing token.
    #[must_use]
    pub fn bind_for_request(&self, discharge: &Self) -> Self {
        let binding_key = AuthKey::from_bytes(*self.signature.as_bytes());
        let bound_sig = hmac_compute(&binding_key, discharge.signature.as_bytes());
        Self {
            identifier: discharge.identifier.clone(),
            location: discharge.location.clone(),
            caveats: discharge.caveats.clone(),
            signature: MacaroonSignature::from_bytes(*bound_sig.as_bytes()),
        }
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
    /// pass. Third-party caveats are **not** checked (use
    /// [`verify_with_discharges`](Self::verify_with_discharges) for that).
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
        // Step 1: Verify HMAC chain.
        if !self.verify_signature(root_key) {
            return Err(VerificationError::InvalidSignature);
        }

        // Step 2: Check all caveats, walking the chain to recover
        // intermediate signatures for third-party vid decryption.
        let mut sig = hmac_compute(root_key, self.identifier.as_bytes());
        for (i, caveat) in self.caveats.iter().enumerate() {
            match caveat {
                Caveat::FirstParty { predicate } => {
                    if let Err(reason) = check_caveat(predicate, context) {
                        return Err(VerificationError::CaveatFailed {
                            index: i,
                            predicate: predicate.display_string(),
                            reason,
                        });
                    }
                    let pred_bytes = predicate.to_bytes();
                    sig = hmac_compute(&sig, &pred_bytes);
                }
                Caveat::ThirdParty {
                    identifier: tp_id,
                    vid,
                    ..
                } => {
                    // Recover the caveat key from vid.
                    let caveat_key_bytes = xor_pad(sig.as_bytes(), vid);
                    let caveat_key = AuthKey::from_bytes(
                        caveat_key_bytes
                            .try_into()
                            .map_err(|_| VerificationError::InvalidSignature)?,
                    );

                    // Find matching discharge.
                    let discharge = discharges
                        .iter()
                        .find(|d| d.identifier() == tp_id)
                        .ok_or_else(|| VerificationError::MissingDischarge {
                            index: i,
                            identifier: tp_id.clone(),
                        })?;

                    // Verify the discharge's chain against the caveat key.
                    let unbound_sig = discharge.recompute_signature(&caveat_key);

                    // Check binding: bound_sig == HMAC(auth_sig, unbound_sig).
                    let expected_bound = hmac_compute(
                        &AuthKey::from_bytes(*self.signature.as_bytes()),
                        unbound_sig.as_bytes(),
                    );
                    let expected_bound_sig =
                        MacaroonSignature::from_bytes(*expected_bound.as_bytes());
                    if !expected_bound_sig.constant_time_eq(&discharge.signature) {
                        return Err(VerificationError::DischargeInvalid {
                            index: i,
                            identifier: tp_id.clone(),
                        });
                    }

                    sig = hmac_compute(&sig, vid);
                }
            }
        }

        Ok(())
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

    /// Serialize to binary format (schema v2).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(MACAROON_SCHEMA_VERSION);

        // Identifier
        let id_bytes = self.identifier.as_bytes();
        buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(id_bytes);

        // Location
        let loc_bytes = self.location.as_bytes();
        buf.extend_from_slice(&(loc_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(loc_bytes);

        // Caveats
        buf.extend_from_slice(&(self.caveats.len() as u16).to_le_bytes());
        for caveat in &self.caveats {
            match caveat {
                Caveat::FirstParty { predicate } => {
                    buf.push(0x00);
                    let pred_bytes = predicate.to_bytes();
                    buf.extend_from_slice(&(pred_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(&pred_bytes);
                }
                Caveat::ThirdParty {
                    location: tp_loc,
                    identifier: tp_id,
                    vid,
                } => {
                    buf.push(0x01);
                    let loc_b = tp_loc.as_bytes();
                    buf.extend_from_slice(&(loc_b.len() as u16).to_le_bytes());
                    buf.extend_from_slice(loc_b);
                    let id_b = tp_id.as_bytes();
                    buf.extend_from_slice(&(id_b.len() as u16).to_le_bytes());
                    buf.extend_from_slice(id_b);
                    buf.extend_from_slice(&(vid.len() as u16).to_le_bytes());
                    buf.extend_from_slice(vid);
                }
            }
        }

        // Signature
        buf.extend_from_slice(self.signature.as_bytes());
        buf
    }

    /// Deserialize from binary format (schema v2).
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
        let caveat_count = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;

        let mut caveats = Vec::with_capacity(caveat_count);
        for _ in 0..caveat_count {
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
                    let (predicate, _) = CaveatPredicate::from_bytes(&data[pos..pos + pred_len])?;
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
        let signature = MacaroonSignature::from_bytes(sig_bytes);

        Some(Self {
            identifier,
            location,
            caveats,
            signature,
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
            "Macaroon(id={:?}, loc={:?}, caveats={}, sig={:?})",
            self.identifier,
            self.location,
            self.caveats.len(),
            self.signature,
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
    pub current_time_ms: u64,
    /// Current region ID (for scope checks).
    pub region_id: Option<u64>,
    /// Current task ID (for scope checks).
    pub task_id: Option<u64>,
    /// Number of times this token has been used (lifetime).
    pub use_count: u32,
    /// The resource path being accessed (for [`CaveatPredicate::ResourceScope`] checks).
    pub resource_path: Option<String>,
    /// Number of uses in the current rate-limit window
    /// (for [`CaveatPredicate::RateLimit`] checks).
    pub window_use_count: u32,
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
        self.current_time_ms = time_ms;
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
        self.use_count = count;
        self
    }

    /// Set the resource path being accessed.
    #[must_use]
    pub fn with_resource(mut self, path: impl Into<String>) -> Self {
        self.resource_path = Some(path.into());
        self
    }

    /// Set the windowed use count for rate-limit checking.
    #[must_use]
    pub const fn with_window_use_count(mut self, count: u32) -> Self {
        self.window_use_count = count;
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
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "macaroon signature verification failed"),
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
        }
    }
}

impl std::error::Error for VerificationError {}

// ---------------------------------------------------------------------------
// HMAC-SHA256 computation
// ---------------------------------------------------------------------------

/// Compute `HMAC-SHA256(key, message)`, returning the result as an `AuthKey`.
fn hmac_compute(key: &AuthKey, message: &[u8]) -> AuthKey {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    AuthKey::from_bytes(result.into())
}

/// XOR-pad two byte slices of equal length. Used for encrypting/decrypting
/// third-party caveat verification keys.
fn xor_pad(a: &[u8], b: &[u8]) -> Vec<u8> {
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
    glob_match_parts(&pattern_parts, &segs)
}

fn glob_match_parts(pat: &[&str], path: &[&str]) -> bool {
    if pat.is_empty() {
        return path.is_empty();
    }
    if pat[0] == "**" {
        // ** matches zero or more segments
        // Try matching the rest of the pattern against every suffix of path
        for i in 0..=path.len() {
            if glob_match_parts(&pat[1..], &path[i..]) {
                return true;
            }
        }
        return false;
    }
    if path.is_empty() {
        return false;
    }
    let segment_matches = pat[0] == "*" || pat[0] == path[0];
    segment_matches && glob_match_parts(&pat[1..], &path[1..])
}

/// Check a single caveat predicate against a verification context.
fn check_caveat(predicate: &CaveatPredicate, ctx: &VerificationContext) -> Result<(), String> {
    match predicate {
        CaveatPredicate::TimeBefore(deadline) => {
            if ctx.current_time_ms < *deadline {
                Ok(())
            } else {
                Err(format!(
                    "current time {}ms >= deadline {}ms",
                    ctx.current_time_ms, deadline
                ))
            }
        }
        CaveatPredicate::TimeAfter(start) => {
            if ctx.current_time_ms >= *start {
                Ok(())
            } else {
                Err(format!(
                    "current time {}ms < start {}ms",
                    ctx.current_time_ms, start
                ))
            }
        }
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
        CaveatPredicate::MaxUses(max) => {
            if ctx.use_count <= *max {
                Ok(())
            } else {
                Err(format!("use count {} > max {max}", ctx.use_count))
            }
        }
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
            window_secs: _,
        } => {
            if ctx.window_use_count <= *max_count {
                Ok(())
            } else {
                Err(format!(
                    "window use count {} > max {max_count}",
                    ctx.window_use_count
                ))
            }
        }
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
mod tests {
    use super::*;

    fn test_root_key() -> AuthKey {
        AuthKey::from_seed(42)
    }

    // --- Minting and verification ---

    #[test]
    fn mint_and_verify_no_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:region_1", "cx/scheduler");

        assert!(token.verify_signature(&key));
        assert_eq!(token.identifier(), "spawn:region_1");
        assert_eq!(token.location(), "cx/scheduler");
        assert_eq!(token.caveat_count(), 0);
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let key = test_root_key();
        let wrong_key = AuthKey::from_seed(99);
        let token = MacaroonToken::mint(&key, "spawn:region_1", "cx/scheduler");

        assert!(!token.verify_signature(&wrong_key));
    }

    #[test]
    fn different_identifiers_produce_different_signatures() {
        let key = test_root_key();
        let t1 = MacaroonToken::mint(&key, "spawn:1", "loc");
        let t2 = MacaroonToken::mint(&key, "spawn:2", "loc");

        assert_ne!(t1.signature().as_bytes(), t2.signature().as_bytes());
    }

    // --- Caveat chaining ---

    #[test]
    fn add_caveat_changes_signature() {
        let key = test_root_key();
        let t1 = MacaroonToken::mint(&key, "cap", "loc");
        let sig1 = *t1.signature().as_bytes();

        let t2 = t1.add_caveat(CaveatPredicate::TimeBefore(1000));
        let sig2 = *t2.signature().as_bytes();

        assert_ne!(sig1, sig2);
        assert!(t2.verify_signature(&key));
    }

    #[test]
    fn multiple_caveats_verify() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(5000))
            .add_caveat(CaveatPredicate::RegionScope(42))
            .add_caveat(CaveatPredicate::MaxUses(10));

        assert!(token.verify_signature(&key));
        assert_eq!(token.caveat_count(), 3);
    }

    #[test]
    fn caveat_order_matters() {
        let key = test_root_key();
        let t1 = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(1000))
            .add_caveat(CaveatPredicate::MaxUses(5));

        let t2 = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::MaxUses(5))
            .add_caveat(CaveatPredicate::TimeBefore(1000));

        // Same caveats in different order → different signatures.
        assert_ne!(t1.signature().as_bytes(), t2.signature().as_bytes());
        // Both should still verify.
        assert!(t1.verify_signature(&key));
        assert!(t2.verify_signature(&key));
    }

    // --- Caveat predicate checking ---

    #[test]
    fn time_before_caveat_passes() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeBefore(1000));

        let ctx = VerificationContext::new().with_time(500);
        assert!(token.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn time_before_caveat_fails_when_expired() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeBefore(1000));

        let ctx = VerificationContext::new().with_time(1500);
        let err = token.verify(&key, &ctx).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 0, .. }
        ));
    }

    #[test]
    fn time_after_caveat_passes() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeAfter(100));

        let ctx = VerificationContext::new().with_time(200);
        assert!(token.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn time_after_caveat_fails_when_too_early() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeAfter(100));

        let ctx = VerificationContext::new().with_time(50);
        assert!(token.verify(&key, &ctx).is_err());
    }

    #[test]
    fn region_scope_caveat() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::RegionScope(42));

        let ok_ctx = VerificationContext::new().with_region(42);
        let bad_ctx = VerificationContext::new().with_region(99);
        let no_ctx = VerificationContext::new();

        assert!(token.verify(&key, &ok_ctx).is_ok());
        assert!(token.verify(&key, &bad_ctx).is_err());
        assert!(token.verify(&key, &no_ctx).is_err());
    }

    #[test]
    fn task_scope_caveat() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TaskScope(7));

        let ok_ctx = VerificationContext::new().with_task(7);
        let bad_ctx = VerificationContext::new().with_task(8);

        assert!(token.verify(&key, &ok_ctx).is_ok());
        assert!(token.verify(&key, &bad_ctx).is_err());
    }

    #[test]
    fn max_uses_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::MaxUses(3));

        let ok_ctx = VerificationContext::new().with_use_count(2);
        let limit_ctx = VerificationContext::new().with_use_count(3);
        let over_ctx = VerificationContext::new().with_use_count(4);

        assert!(token.verify(&key, &ok_ctx).is_ok());
        assert!(token.verify(&key, &limit_ctx).is_ok());
        assert!(token.verify(&key, &over_ctx).is_err());
    }

    #[test]
    fn custom_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::Custom("env".into(), "prod".into()));

        let ok_ctx = VerificationContext::new().with_custom("env", "prod");
        let bad_ctx = VerificationContext::new().with_custom("env", "dev");
        let no_ctx = VerificationContext::new();

        assert!(token.verify(&key, &ok_ctx).is_ok());
        assert!(token.verify(&key, &bad_ctx).is_err());
        assert!(token.verify(&key, &no_ctx).is_err());
    }

    #[test]
    fn conjunction_of_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(1000))
            .add_caveat(CaveatPredicate::RegionScope(5))
            .add_caveat(CaveatPredicate::MaxUses(10));

        // All caveats satisfied.
        let ok_ctx = VerificationContext::new()
            .with_time(500)
            .with_region(5)
            .with_use_count(3);
        assert!(token.verify(&key, &ok_ctx).is_ok());

        // One caveat fails (wrong region).
        let bad_ctx = VerificationContext::new()
            .with_time(500)
            .with_region(99)
            .with_use_count(3);
        let err = token.verify(&key, &bad_ctx).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 1, .. }
        ));
    }

    // --- Tamper detection ---

    #[test]
    fn removing_caveat_invalidates_signature() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(1000))
            .add_caveat(CaveatPredicate::MaxUses(5));

        // Manually construct a token with only the first caveat
        // but keeping the original's signature → should fail.
        let tampered = MacaroonToken {
            identifier: token.identifier().to_string(),
            location: token.location().to_string(),
            caveats: vec![token.caveats()[0].clone()], // Removed second caveat
            signature: *token.signature(),
        };

        assert!(!tampered.verify_signature(&key));
    }

    // --- Serialization ---

    #[test]
    fn binary_roundtrip_no_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:region_1", "cx/scheduler");

        let bytes = token.to_binary();
        let recovered = MacaroonToken::from_binary(&bytes).unwrap();

        assert_eq!(recovered.identifier(), token.identifier());
        assert_eq!(recovered.location(), token.location());
        assert_eq!(recovered.caveat_count(), 0);
        assert_eq!(
            recovered.signature().as_bytes(),
            token.signature().as_bytes()
        );
        assert!(recovered.verify_signature(&key));
    }

    #[test]
    fn binary_roundtrip_with_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:net", "cx/io")
            .add_caveat(CaveatPredicate::TimeBefore(5000))
            .add_caveat(CaveatPredicate::RegionScope(42))
            .add_caveat(CaveatPredicate::Custom("env".into(), "test".into()));

        let bytes = token.to_binary();
        let recovered = MacaroonToken::from_binary(&bytes).unwrap();

        assert_eq!(recovered.identifier(), token.identifier());
        assert_eq!(recovered.caveat_count(), 3);
        assert_eq!(recovered.caveats(), token.caveats());
        assert!(recovered.verify_signature(&key));
    }

    #[test]
    fn binary_roundtrip_all_predicate_types() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "all", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(1000))
            .add_caveat(CaveatPredicate::TimeAfter(100))
            .add_caveat(CaveatPredicate::RegionScope(42))
            .add_caveat(CaveatPredicate::TaskScope(7))
            .add_caveat(CaveatPredicate::MaxUses(5))
            .add_caveat(CaveatPredicate::Custom("k".into(), "v".into()));

        let bytes = token.to_binary();
        let recovered = MacaroonToken::from_binary(&bytes).unwrap();

        assert_eq!(recovered.caveats(), token.caveats());
        assert!(recovered.verify_signature(&key));
    }

    #[test]
    fn from_binary_rejects_invalid_version() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc");
        let mut bytes = token.to_binary();
        bytes[0] = 99; // Invalid version.
        assert!(MacaroonToken::from_binary(&bytes).is_none());
    }

    #[test]
    fn from_binary_rejects_truncated_data() {
        let key = test_root_key();
        let token =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeBefore(1000));
        let bytes = token.to_binary();

        // Truncate at various points.
        for len in [0, 1, 5, 10] {
            if len < bytes.len() {
                assert!(MacaroonToken::from_binary(&bytes[..len]).is_none());
            }
        }
    }

    // --- Predicate serialization ---

    #[test]
    fn predicate_bytes_roundtrip() {
        let predicates = vec![
            CaveatPredicate::TimeBefore(12345),
            CaveatPredicate::TimeAfter(67890),
            CaveatPredicate::RegionScope(42),
            CaveatPredicate::TaskScope(7),
            CaveatPredicate::MaxUses(100),
            CaveatPredicate::Custom("key".into(), "value".into()),
        ];

        for pred in &predicates {
            let bytes = pred.to_bytes();
            let (recovered, consumed) = CaveatPredicate::from_bytes(&bytes).unwrap();
            assert_eq!(&recovered, pred, "Roundtrip failed for {pred:?}");
            assert_eq!(consumed, bytes.len());
        }
    }

    // --- Display ---

    #[test]
    fn display_formatting() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "scheduler")
            .add_caveat(CaveatPredicate::TimeBefore(1000));

        let display = format!("{token}");
        assert!(display.contains("Macaroon"));
        assert!(display.contains("spawn:r1"));
        assert!(display.contains("caveats=1"));
    }

    #[test]
    fn predicate_display() {
        assert_eq!(CaveatPredicate::TimeBefore(100).to_string(), "time < 100ms");
        assert_eq!(CaveatPredicate::TimeAfter(50).to_string(), "time >= 50ms");
        assert_eq!(CaveatPredicate::RegionScope(3).to_string(), "region == 3");
        assert_eq!(CaveatPredicate::TaskScope(7).to_string(), "task == 7");
        assert_eq!(CaveatPredicate::MaxUses(5).to_string(), "uses <= 5");
        assert_eq!(
            CaveatPredicate::Custom("k".into(), "v".into()).to_string(),
            "k = v"
        );
    }

    // --- Determinism ---

    #[test]
    fn minting_is_deterministic() {
        let key = test_root_key();
        let t1 =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeBefore(1000));
        let t2 =
            MacaroonToken::mint(&key, "cap", "loc").add_caveat(CaveatPredicate::TimeBefore(1000));

        assert_eq!(t1.signature().as_bytes(), t2.signature().as_bytes());
    }

    // --- Attenuation without root key ---

    #[test]
    fn anyone_can_add_caveats_without_root_key() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "cap", "loc");

        // Simulate delegation: holder adds caveat without knowing root key.
        let attenuated = token.add_caveat(CaveatPredicate::MaxUses(5));

        // Issuer can still verify (they have root key).
        assert!(attenuated.verify_signature(&key));
    }

    // --- Third-party caveats ---

    #[test]
    fn third_party_caveat_changes_signature() {
        let key = test_root_key();
        let caveat_key = AuthKey::from_seed(100);
        let t1 = MacaroonToken::mint(&key, "cap", "loc");
        let sig1 = *t1.signature().as_bytes();

        let t2 = t1.add_third_party_caveat("https://auth.example", "user_check", &caveat_key);
        let sig2 = *t2.signature().as_bytes();

        assert_ne!(sig1, sig2);
        assert!(t2.verify_signature(&key));
    }

    #[test]
    fn third_party_caveat_with_discharge_verifies() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(200);

        // Issuer mints token with a third-party caveat.
        let token = MacaroonToken::mint(&root_key, "access:data", "service")
            .add_caveat(CaveatPredicate::TimeBefore(5000))
            .add_third_party_caveat("https://auth.example", "user_check", &caveat_key);

        // Third party mints a discharge macaroon.
        let discharge = MacaroonToken::mint(&caveat_key, "user_check", "https://auth.example");

        // Holder binds the discharge to the authorizing token.
        let bound_discharge = token.bind_for_request(&discharge);

        // Verifier checks everything.
        let ctx = VerificationContext::new().with_time(1000);
        assert!(token
            .verify_with_discharges(&root_key, &ctx, &[bound_discharge])
            .is_ok());
    }

    #[test]
    fn third_party_without_discharge_fails() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(300);

        let token = MacaroonToken::mint(&root_key, "cap", "loc").add_third_party_caveat(
            "tp",
            "check_id",
            &caveat_key,
        );

        let ctx = VerificationContext::new();
        let err = token
            .verify_with_discharges(&root_key, &ctx, &[])
            .unwrap_err();
        assert!(matches!(err, VerificationError::MissingDischarge { .. }));
    }

    #[test]
    fn wrong_discharge_key_fails() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(400);
        let wrong_key = AuthKey::from_seed(401);

        let token = MacaroonToken::mint(&root_key, "cap", "loc").add_third_party_caveat(
            "tp",
            "check_id",
            &caveat_key,
        );

        // Discharge minted with wrong key.
        let bad_discharge = MacaroonToken::mint(&wrong_key, "check_id", "tp");
        let bound = token.bind_for_request(&bad_discharge);

        let ctx = VerificationContext::new();
        let err = token
            .verify_with_discharges(&root_key, &ctx, &[bound])
            .unwrap_err();
        assert!(matches!(err, VerificationError::DischargeInvalid { .. }));
    }

    #[test]
    fn unbound_discharge_fails() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(500);

        let token = MacaroonToken::mint(&root_key, "cap", "loc").add_third_party_caveat(
            "tp",
            "check_id",
            &caveat_key,
        );

        // Correct key but NOT bound to the authorizing token.
        let unbound = MacaroonToken::mint(&caveat_key, "check_id", "tp");

        let ctx = VerificationContext::new();
        let err = token
            .verify_with_discharges(&root_key, &ctx, &[unbound])
            .unwrap_err();
        assert!(matches!(err, VerificationError::DischargeInvalid { .. }));
    }

    #[test]
    fn discharge_with_caveats_verifies() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(600);

        let token = MacaroonToken::mint(&root_key, "access", "svc").add_third_party_caveat(
            "tp",
            "auth_check",
            &caveat_key,
        );

        // Discharge has its own first-party caveats.
        let discharge = MacaroonToken::mint(&caveat_key, "auth_check", "tp")
            .add_caveat(CaveatPredicate::MaxUses(10));
        let bound = token.bind_for_request(&discharge);

        let ctx = VerificationContext::new();
        assert!(token
            .verify_with_discharges(&root_key, &ctx, &[bound])
            .is_ok());
    }

    #[test]
    fn third_party_binary_roundtrip() {
        let root_key = test_root_key();
        let caveat_key = AuthKey::from_seed(700);

        let token = MacaroonToken::mint(&root_key, "cap", "loc")
            .add_caveat(CaveatPredicate::TimeBefore(9000))
            .add_third_party_caveat("https://tp.example", "tp_check", &caveat_key)
            .add_caveat(CaveatPredicate::MaxUses(3));

        let bytes = token.to_binary();
        let recovered = MacaroonToken::from_binary(&bytes).unwrap();

        assert_eq!(recovered.identifier(), token.identifier());
        assert_eq!(recovered.caveat_count(), 3);
        assert_eq!(
            recovered.signature().as_bytes(),
            token.signature().as_bytes()
        );
        assert!(recovered.verify_signature(&root_key));

        // The third-party caveat should survive roundtrip.
        assert!(recovered.caveats()[1].is_third_party());
    }

    #[test]
    fn mixed_first_and_third_party_verify() {
        let root_key = test_root_key();
        let ck1 = AuthKey::from_seed(801);
        let ck2 = AuthKey::from_seed(802);

        let token = MacaroonToken::mint(&root_key, "multi", "svc")
            .add_caveat(CaveatPredicate::TimeBefore(10000))
            .add_third_party_caveat("tp1", "check1", &ck1)
            .add_caveat(CaveatPredicate::RegionScope(42))
            .add_third_party_caveat("tp2", "check2", &ck2);

        let d1 = MacaroonToken::mint(&ck1, "check1", "tp1");
        let d2 = MacaroonToken::mint(&ck2, "check2", "tp2");
        let bd1 = token.bind_for_request(&d1);
        let bd2 = token.bind_for_request(&d2);

        let ctx = VerificationContext::new().with_time(5000).with_region(42);
        assert!(token
            .verify_with_discharges(&root_key, &ctx, &[bd1, bd2])
            .is_ok());

        // Fail if a first-party caveat fails.
        let bad_ctx = VerificationContext::new().with_time(5000).with_region(99);
        assert!(token
            .verify_with_discharges(
                &root_key,
                &bad_ctx,
                &[
                    token.bind_for_request(&MacaroonToken::mint(&ck1, "check1", "tp1")),
                    token.bind_for_request(&MacaroonToken::mint(&ck2, "check2", "tp2")),
                ]
            )
            .is_err());
    }

    // --- ResourceScope caveat tests (bd-2lqyk.3) ---

    #[test]
    fn resource_scope_exact_match() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:read", "cx/io")
            .add_caveat(CaveatPredicate::ResourceScope("api/users".to_string()));

        let ctx = VerificationContext::new().with_resource("api/users");
        assert!(token.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn resource_scope_rejects_mismatch() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:read", "cx/io")
            .add_caveat(CaveatPredicate::ResourceScope("api/users".to_string()));

        let ctx = VerificationContext::new().with_resource("api/admin");
        assert!(token.verify(&key, &ctx).is_err());
    }

    #[test]
    fn resource_scope_wildcard_segment() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:read", "cx/io")
            .add_caveat(CaveatPredicate::ResourceScope("api/*/profile".to_string()));

        let ctx_ok = VerificationContext::new().with_resource("api/users/profile");
        assert!(token.verify(&key, &ctx_ok).is_ok());

        let ctx_fail = VerificationContext::new().with_resource("api/users/settings");
        assert!(token.verify(&key, &ctx_fail).is_err());
    }

    #[test]
    fn resource_scope_globstar() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:read", "cx/io")
            .add_caveat(CaveatPredicate::ResourceScope("api/**".to_string()));

        let ctx1 = VerificationContext::new().with_resource("api/users");
        assert!(token.verify(&key, &ctx1).is_ok());

        let ctx2 = VerificationContext::new().with_resource("api/users/123/profile");
        assert!(token.verify(&key, &ctx2).is_ok());

        let ctx3 = VerificationContext::new().with_resource("admin/users");
        assert!(token.verify(&key, &ctx3).is_err());
    }

    #[test]
    fn resource_scope_no_resource_in_context() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:read", "cx/io")
            .add_caveat(CaveatPredicate::ResourceScope("api/**".to_string()));

        let ctx = VerificationContext::new();
        let err = token.verify(&key, &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::CaveatFailed { .. }));
    }

    // --- RateLimit caveat tests (bd-2lqyk.3) ---

    #[test]
    fn rate_limit_passes_within_window() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "api:call", "cx/api").add_caveat(
            CaveatPredicate::RateLimit {
                max_count: 10,
                window_secs: 60,
            },
        );

        let ctx = VerificationContext::new().with_window_use_count(5);
        assert!(token.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn rate_limit_at_exact_limit() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "api:call", "cx/api").add_caveat(
            CaveatPredicate::RateLimit {
                max_count: 10,
                window_secs: 60,
            },
        );

        let ctx = VerificationContext::new().with_window_use_count(10);
        assert!(token.verify(&key, &ctx).is_ok());
    }

    #[test]
    fn rate_limit_rejects_over_limit() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "api:call", "cx/api").add_caveat(
            CaveatPredicate::RateLimit {
                max_count: 10,
                window_secs: 60,
            },
        );

        let ctx = VerificationContext::new().with_window_use_count(11);
        let err = token.verify(&key, &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::CaveatFailed { .. }));
    }

    // --- Serialization roundtrip for new predicates ---

    #[test]
    fn resource_scope_bytes_roundtrip() {
        let pred = CaveatPredicate::ResourceScope("api/**/logs".to_string());
        let bytes = pred.to_bytes();
        let (decoded, consumed) = CaveatPredicate::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, pred);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn rate_limit_bytes_roundtrip() {
        let pred = CaveatPredicate::RateLimit {
            max_count: 100,
            window_secs: 3600,
        };
        let bytes = pred.to_bytes();
        let (decoded, consumed) = CaveatPredicate::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, pred);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn new_predicates_display() {
        assert_eq!(
            CaveatPredicate::ResourceScope("api/**/logs".to_string()).display_string(),
            "resource ~ api/**/logs"
        );
        assert_eq!(
            CaveatPredicate::RateLimit {
                max_count: 10,
                window_secs: 60
            }
            .display_string(),
            "rate <= 10/60s"
        );
    }

    #[test]
    fn binary_roundtrip_new_predicates() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "api:full", "cx/api")
            .add_caveat(CaveatPredicate::ResourceScope("data/**".to_string()))
            .add_caveat(CaveatPredicate::RateLimit {
                max_count: 50,
                window_secs: 300,
            });

        let bytes = token.to_binary();
        let restored = MacaroonToken::from_binary(&bytes).expect("should decode");
        assert_eq!(restored.identifier(), token.identifier());
        assert_eq!(restored.caveat_count(), 2);
        assert!(restored.verify_signature(&key));
    }

    // --- Glob matching unit tests ---

    #[test]
    fn glob_exact_match() {
        assert!(super::glob_match("foo/bar", "foo/bar"));
        assert!(!super::glob_match("foo/bar", "foo/baz"));
    }

    #[test]
    fn glob_single_wildcard() {
        assert!(super::glob_match("foo/*/baz", "foo/bar/baz"));
        assert!(!super::glob_match("foo/*/baz", "foo/bar/qux"));
        assert!(!super::glob_match("foo/*/baz", "foo/bar/extra/baz"));
    }

    #[test]
    fn glob_double_wildcard() {
        assert!(super::glob_match("foo/**", "foo/bar"));
        assert!(super::glob_match("foo/**", "foo/bar/baz"));
        assert!(super::glob_match("foo/**", "foo"));
        assert!(!super::glob_match("foo/**", "bar/foo"));
    }

    #[test]
    fn glob_double_wildcard_middle() {
        assert!(super::glob_match("api/**/detail", "api/users/detail"));
        assert!(super::glob_match("api/**/detail", "api/users/123/detail"));
        assert!(!super::glob_match("api/**/detail", "api/users/123/summary"));
    }

    // --- Monotonic restriction property (bd-2lqyk.3) ---

    #[test]
    fn attenuation_is_monotonically_restricting() {
        let key = test_root_key();
        let token_base = MacaroonToken::mint(&key, "full", "cx");

        // Adding caveats can only restrict, never expand
        let token_time = token_base
            .clone()
            .add_caveat(CaveatPredicate::TimeBefore(5000));
        let token_scope = token_time
            .clone()
            .add_caveat(CaveatPredicate::ResourceScope("api/**".to_string()));
        let token_rate = token_scope.clone().add_caveat(CaveatPredicate::RateLimit {
            max_count: 10,
            window_secs: 60,
        });

        // Context that passes all caveats
        let ctx_ok = VerificationContext::new()
            .with_time(1000)
            .with_resource("api/users")
            .with_window_use_count(5);

        // Base passes with any context; each attenuated token also passes
        assert!(token_base.verify(&key, &ctx_ok).is_ok());
        assert!(token_time.verify(&key, &ctx_ok).is_ok());
        assert!(token_scope.verify(&key, &ctx_ok).is_ok());
        assert!(token_rate.verify(&key, &ctx_ok).is_ok());

        // Violating time: restricted tokens fail, base passes
        let ctx_expired = VerificationContext::new()
            .with_time(6000)
            .with_resource("api/users")
            .with_window_use_count(5);
        assert!(token_base.verify(&key, &ctx_expired).is_ok());
        assert!(token_time.verify(&key, &ctx_expired).is_err());
        assert!(token_scope.verify(&key, &ctx_expired).is_err());
        assert!(token_rate.verify(&key, &ctx_expired).is_err());

        // Violating scope: scope-restricted tokens fail
        let ctx_wrong_scope = VerificationContext::new()
            .with_time(1000)
            .with_resource("admin/users")
            .with_window_use_count(5);
        assert!(token_base.verify(&key, &ctx_wrong_scope).is_ok());
        assert!(token_time.verify(&key, &ctx_wrong_scope).is_ok());
        assert!(token_scope.verify(&key, &ctx_wrong_scope).is_err());
        assert!(token_rate.verify(&key, &ctx_wrong_scope).is_err());
    }
}
