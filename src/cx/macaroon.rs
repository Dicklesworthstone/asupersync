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
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current Macaroon binary schema version.
pub const MACAROON_SCHEMA_VERSION: u8 = 1;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caveat {
    /// The predicate this caveat encodes.
    pub predicate: CaveatPredicate,
}

impl Caveat {
    /// Create a new caveat from a predicate.
    #[must_use]
    pub const fn new(predicate: CaveatPredicate) -> Self {
        Self { predicate }
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
    /// chain is extended: `sig' = HMAC(sig, caveat_bytes)`.
    ///
    /// This operation does NOT require the root key — any holder
    /// can add caveats.
    #[must_use]
    pub fn add_caveat(mut self, predicate: CaveatPredicate) -> Self {
        let pred_bytes = predicate.to_bytes();
        let current_key = AuthKey::from_bytes(*self.signature.as_bytes());
        let new_sig = hmac_compute(&current_key, &pred_bytes);
        self.signature = MacaroonSignature::from_bytes(*new_sig.as_bytes());
        self.caveats.push(Caveat::new(predicate));
        self
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

    /// Verify the token and check all caveat predicates against a context.
    ///
    /// Returns `Ok(())` if signature is valid AND all caveats pass.
    ///
    /// # Errors
    ///
    /// Returns a `VerificationError` describing what failed.
    pub fn verify(
        &self,
        root_key: &AuthKey,
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        // Step 1: Verify HMAC chain.
        if !self.verify_signature(root_key) {
            return Err(VerificationError::InvalidSignature);
        }

        // Step 2: Check all caveats.
        for (i, caveat) in self.caveats.iter().enumerate() {
            if let Err(reason) = check_caveat(&caveat.predicate, context) {
                return Err(VerificationError::CaveatFailed {
                    index: i,
                    predicate: caveat.predicate.display_string(),
                    reason,
                });
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

    /// Serialize to binary format.
    #[must_use]
    pub fn to_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Version byte
        buf.push(MACAROON_SCHEMA_VERSION);

        // Identifier
        let id_bytes = self.identifier.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        {
            buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
        }
        buf.extend_from_slice(id_bytes);

        // Location
        let loc_bytes = self.location.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        {
            buf.extend_from_slice(&(loc_bytes.len() as u16).to_le_bytes());
        }
        buf.extend_from_slice(loc_bytes);

        // Caveats
        #[allow(clippy::cast_possible_truncation)]
        {
            buf.extend_from_slice(&(self.caveats.len() as u16).to_le_bytes());
        }
        for caveat in &self.caveats {
            let pred_bytes = caveat.predicate.to_bytes();
            #[allow(clippy::cast_possible_truncation)]
            {
                buf.extend_from_slice(&(pred_bytes.len() as u16).to_le_bytes());
            }
            buf.extend_from_slice(&pred_bytes);
        }

        // Signature
        buf.extend_from_slice(self.signature.as_bytes());

        buf
    }

    /// Deserialize from binary format.
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

        // Version
        let version = data[pos];
        if version != MACAROON_SCHEMA_VERSION {
            return None;
        }
        pos += 1;

        // Identifier
        if pos + 2 > data.len() {
            return None;
        }
        let id_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + id_len > data.len() {
            return None;
        }
        let identifier = std::str::from_utf8(&data[pos..pos + id_len])
            .ok()?
            .to_string();
        pos += id_len;

        // Location
        if pos + 2 > data.len() {
            return None;
        }
        let loc_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + loc_len > data.len() {
            return None;
        }
        let location = std::str::from_utf8(&data[pos..pos + loc_len])
            .ok()?
            .to_string();
        pos += loc_len;

        // Caveats
        if pos + 2 > data.len() {
            return None;
        }
        let caveat_count = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;

        let mut caveats = Vec::with_capacity(caveat_count);
        for _ in 0..caveat_count {
            if pos + 2 > data.len() {
                return None;
            }
            let pred_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
            pos += 2;
            if pos + pred_len > data.len() {
                return None;
            }
            let (predicate, _) = CaveatPredicate::from_bytes(&data[pos..pos + pred_len])?;
            caveats.push(Caveat::new(predicate));
            pos += pred_len;
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
            let pred_bytes = caveat.predicate.to_bytes();
            sig = hmac_compute(&sig, &pred_bytes);
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
    /// Number of times this token has been used.
    pub use_count: u32,
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
    /// A caveat predicate was not satisfied.
    CaveatFailed {
        /// Index of the failing caveat in the chain.
        index: usize,
        /// Human-readable predicate description.
        predicate: String,
        /// Why it failed.
        reason: String,
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
        }
    }
}

impl std::error::Error for VerificationError {}

// ---------------------------------------------------------------------------
// HMAC computation (Phase 0 — non-cryptographic)
// ---------------------------------------------------------------------------

/// Compute HMAC(key, message) using the Phase 0 non-cryptographic
/// construction from [`AuthKey::derive_subkey`].
///
/// In Phase 1+, this will be replaced with HMAC-SHA256.
fn hmac_compute(key: &AuthKey, message: &[u8]) -> AuthKey {
    key.derive_subkey(message)
}

// ---------------------------------------------------------------------------
// Caveat checking
// ---------------------------------------------------------------------------

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
}
