//! Suite-wide type substrate for FrankenSuite (bd-1usdh.1).
//!
//! Canonical identifier and version types used across all FrankenSuite
//! projects for cross-project tracing, decision logging, and schema
//! compatibility.
//!
//! All identifier types are 128-bit, `Copy`, `Send + Sync`, and
//! zero-cost abstractions over `[u8; 16]`.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::fmt;
use alloc::string::String;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TraceId — 128-bit time-ordered unique identifier
// ---------------------------------------------------------------------------

/// 128-bit unique trace identifier.
///
/// Uses UUIDv7-style layout for time-ordered generation: the high 48 bits
/// encode a millisecond Unix timestamp, the remaining 80 bits are random.
///
/// ```
/// use franken_kernel::TraceId;
///
/// let id = TraceId::from_parts(1_700_000_000_000, 0xABCD_EF01_2345_6789_AB);
/// let hex = id.to_string();
/// let parsed: TraceId = hex.parse().unwrap();
/// assert_eq!(id, parsed);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TraceId(
    /// Hex-encoded 128-bit identifier.
    #[serde(with = "hex_u128")]
    u128,
);

impl TraceId {
    /// Create a `TraceId` from raw 128-bit value.
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Create a `TraceId` from a millisecond timestamp and random bits.
    ///
    /// The high 48 bits store `ts_ms`, the low 80 bits store `random`.
    /// The `random` value is truncated to 80 bits.
    pub const fn from_parts(ts_ms: u64, random: u128) -> Self {
        let ts_bits = (ts_ms as u128) << 80;
        let rand_bits = random & 0xFFFF_FFFF_FFFF_FFFF_FFFF; // mask to 80 bits
        Self(ts_bits | rand_bits)
    }

    /// Extract the millisecond timestamp from the high 48 bits.
    pub const fn timestamp_ms(self) -> u64 {
        (self.0 >> 80) as u64
    }

    /// Return the raw 128-bit value.
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// Return the bytes in big-endian order.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Construct from big-endian bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({:032x})", self.0)
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl FromStr for TraceId {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = u128::from_str_radix(s, 16).map_err(|_| ParseIdError {
            kind: "TraceId",
            input_len: s.len(),
        })?;
        Ok(Self(val))
    }
}

// ---------------------------------------------------------------------------
// DecisionId — 128-bit decision identifier
// ---------------------------------------------------------------------------

/// 128-bit identifier linking a runtime decision to its EvidenceLedger entry.
///
/// Structurally identical to [`TraceId`] but semantically distinct.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DecisionId(#[serde(with = "hex_u128")] u128);

impl DecisionId {
    /// Create from raw 128-bit value.
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Create from millisecond timestamp and random bits.
    pub const fn from_parts(ts_ms: u64, random: u128) -> Self {
        let ts_bits = (ts_ms as u128) << 80;
        let rand_bits = random & 0xFFFF_FFFF_FFFF_FFFF_FFFF;
        Self(ts_bits | rand_bits)
    }

    /// Extract the millisecond timestamp.
    pub const fn timestamp_ms(self) -> u64 {
        (self.0 >> 80) as u64
    }

    /// Return the raw 128-bit value.
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// Return the bytes in big-endian order.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Construct from big-endian bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }
}

impl fmt::Debug for DecisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecisionId({:032x})", self.0)
    }
}

impl fmt::Display for DecisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl FromStr for DecisionId {
    type Err = ParseIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = u128::from_str_radix(s, 16).map_err(|_| ParseIdError {
            kind: "DecisionId",
            input_len: s.len(),
        })?;
        Ok(Self(val))
    }
}

// ---------------------------------------------------------------------------
// PolicyId — identifies a decision policy with version
// ---------------------------------------------------------------------------

/// Identifies a decision policy (e.g. scheduler, cancellation, budget).
///
/// Includes a version number for policy evolution tracking.
///
/// ```
/// use franken_kernel::PolicyId;
///
/// let policy = PolicyId::new("scheduler.preempt", 3);
/// assert_eq!(policy.name(), "scheduler.preempt");
/// assert_eq!(policy.version(), 3);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyId {
    /// Dotted policy name (e.g. "scheduler.preempt").
    #[serde(rename = "n")]
    name: String,
    /// Policy version — incremented when the policy logic changes.
    #[serde(rename = "v")]
    version: u32,
}

impl PolicyId {
    /// Create a new policy identifier.
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }

    /// Policy name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Policy version.
    pub const fn version(&self) -> u32 {
        self.version
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@v{}", self.name, self.version)
    }
}

// ---------------------------------------------------------------------------
// SchemaVersion — semantic version with compatibility checking
// ---------------------------------------------------------------------------

/// Semantic version (major.minor.patch) with compatibility checking.
///
/// Two versions are compatible iff their major versions match (semver rule).
///
/// ```
/// use franken_kernel::SchemaVersion;
///
/// let v1 = SchemaVersion::new(1, 2, 3);
/// let v1_compat = SchemaVersion::new(1, 5, 0);
/// let v2 = SchemaVersion::new(2, 0, 0);
///
/// assert!(v1.is_compatible(&v1_compat));
/// assert!(!v1.is_compatible(&v2));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaVersion {
    /// Major version — breaking changes.
    pub major: u32,
    /// Minor version — backwards-compatible additions.
    pub minor: u32,
    /// Patch version — backwards-compatible fixes.
    pub patch: u32,
}

impl SchemaVersion {
    /// Create a new schema version.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns `true` if `other` is compatible (same major version).
    pub const fn is_compatible(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for SchemaVersion {
    type Err = ParseVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: alloc::vec::Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ParseVersionError);
        }
        let major = parts[0].parse().map_err(|_| ParseVersionError)?;
        let minor = parts[1].parse().map_err(|_| ParseVersionError)?;
        let patch = parts[2].parse().map_err(|_| ParseVersionError)?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error returned when parsing a hex identifier string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseIdError {
    /// Which identifier type was being parsed.
    pub kind: &'static str,
    /// Length of the input string.
    pub input_len: usize,
}

impl fmt::Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} hex string (length {})",
            self.kind, self.input_len
        )
    }
}

/// Error returned when parsing a semantic version string fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseVersionError;

impl fmt::Display for ParseVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid schema version (expected major.minor.patch)")
    }
}

// ---------------------------------------------------------------------------
// Serde helper: serialize u128 as hex string
// ---------------------------------------------------------------------------

mod hex_u128 {
    use alloc::format;
    use alloc::string::String;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{value:032x}"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        u128::from_str_radix(&s, 16)
            .map_err(|_| serde::de::Error::custom(format!("invalid hex u128: {s}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::ToString;

    #[test]
    fn trace_id_from_parts_roundtrip() {
        let ts = 1_700_000_000_000_u64;
        let random = 0x00AB_CDEF_0123_4567_89AB_u128;
        let id = TraceId::from_parts(ts, random);
        assert_eq!(id.timestamp_ms(), ts);
        // Lower 80 bits preserved.
        assert_eq!(id.as_u128() & 0xFFFF_FFFF_FFFF_FFFF_FFFF, random);
    }

    #[test]
    fn trace_id_display_parse_roundtrip() {
        let id = TraceId::from_raw(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF);
        let hex = id.to_string();
        assert_eq!(hex, "0123456789abcdef0123456789abcdef");
        let parsed: TraceId = hex.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn trace_id_bytes_roundtrip() {
        let id = TraceId::from_raw(42);
        let bytes = id.to_bytes();
        let recovered = TraceId::from_bytes(bytes);
        assert_eq!(id, recovered);
    }

    #[test]
    fn trace_id_ordering() {
        let earlier = TraceId::from_parts(1000, 0);
        let later = TraceId::from_parts(2000, 0);
        assert!(earlier < later);
    }

    #[test]
    fn trace_id_serde_json() {
        let id = TraceId::from_raw(0xFF);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"000000000000000000000000000000ff\"");
        let parsed: TraceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn decision_id_from_parts_roundtrip() {
        let ts = 1_700_000_000_000_u64;
        let random = 0x0012_3456_789A_BCDE_F012_u128;
        let id = DecisionId::from_parts(ts, random);
        assert_eq!(id.timestamp_ms(), ts);
        assert_eq!(id.as_u128() & 0xFFFF_FFFF_FFFF_FFFF_FFFF, random);
    }

    #[test]
    fn decision_id_display_parse_roundtrip() {
        let id = DecisionId::from_raw(0xDEAD_BEEF);
        let hex = id.to_string();
        let parsed: DecisionId = hex.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn decision_id_serde_json() {
        let id = DecisionId::from_raw(1);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: DecisionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn policy_id_display() {
        let policy = PolicyId::new("scheduler.preempt", 3);
        assert_eq!(policy.to_string(), "scheduler.preempt@v3");
        assert_eq!(policy.name(), "scheduler.preempt");
        assert_eq!(policy.version(), 3);
    }

    #[test]
    fn policy_id_serde_json() {
        let policy = PolicyId::new("cancel.budget", 1);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"n\":"));
        assert!(json.contains("\"v\":"));
        let parsed: PolicyId = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }

    #[test]
    fn schema_version_compatible() {
        let v1_2_3 = SchemaVersion::new(1, 2, 3);
        let v1_5_0 = SchemaVersion::new(1, 5, 0);
        let v2_0_0 = SchemaVersion::new(2, 0, 0);
        assert!(v1_2_3.is_compatible(&v1_5_0));
        assert!(!v1_2_3.is_compatible(&v2_0_0));
    }

    #[test]
    fn schema_version_display_parse_roundtrip() {
        let v = SchemaVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
        let parsed: SchemaVersion = "1.2.3".parse().unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn schema_version_ordering() {
        let v1 = SchemaVersion::new(1, 0, 0);
        let v2 = SchemaVersion::new(2, 0, 0);
        assert!(v1 < v2);
    }

    #[test]
    fn schema_version_serde_json() {
        let v = SchemaVersion::new(3, 1, 4);
        let json = serde_json::to_string(&v).unwrap();
        let parsed: SchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn parse_id_error_display() {
        let err = ParseIdError {
            kind: "TraceId",
            input_len: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("TraceId"));
        assert!(msg.contains('5'));
    }

    #[test]
    fn parse_version_error_display() {
        let err = ParseVersionError;
        let msg = err.to_string();
        assert!(msg.contains("major.minor.patch"));
    }

    #[test]
    fn invalid_hex_parse_fails() {
        assert!("not-hex".parse::<TraceId>().is_err());
        assert!("not-hex".parse::<DecisionId>().is_err());
    }

    #[test]
    fn invalid_version_parse_fails() {
        assert!("1.2".parse::<SchemaVersion>().is_err());
        assert!("a.b.c".parse::<SchemaVersion>().is_err());
        assert!("1.2.3.4".parse::<SchemaVersion>().is_err());
    }

    #[test]
    fn trace_id_debug_format() {
        let id = TraceId::from_raw(0xAB);
        let dbg = std::format!("{id:?}");
        assert!(dbg.starts_with("TraceId("));
        assert!(dbg.contains("ab"));
    }

    #[test]
    fn decision_id_debug_format() {
        let id = DecisionId::from_raw(0xCD);
        let dbg = std::format!("{id:?}");
        assert!(dbg.starts_with("DecisionId("));
        assert!(dbg.contains("cd"));
    }

    #[test]
    fn trace_id_copy_semantics() {
        let id = TraceId::from_raw(42);
        let copy = id;
        assert_eq!(id, copy); // Both still usable (Copy).
    }
}
