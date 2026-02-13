//! Suite-wide type substrate for FrankenSuite (bd-1usdh.1, bd-1usdh.2).
//!
//! Canonical identifier, version, and context types used across all
//! FrankenSuite projects for cross-project tracing, decision logging,
//! capability management, and schema compatibility.
//!
//! # Identifiers
//!
//! All identifier types are 128-bit, `Copy`, `Send + Sync`, and
//! zero-cost abstractions over `[u8; 16]`.
//!
//! # Capability Context
//!
//! [`Cx`] is the core context type threaded through all operations.
//! It carries a [`TraceId`], a [`Budget`] (tropical semiring), and
//! a capability set generic parameter. Child contexts inherit the
//! parent's trace and enforce budget monotonicity.
//!
//! ```
//! use franken_kernel::{Cx, Budget, NoCaps, TraceId};
//!
//! let trace = TraceId::from_parts(1_700_000_000_000, 42);
//! let cx = Cx::new(trace, Budget::new(5000), NoCaps);
//! assert_eq!(cx.budget().remaining_ms(), 5000);
//!
//! let child = cx.child(NoCaps, Budget::new(3000));
//! assert_eq!(child.budget().remaining_ms(), 3000);
//! assert_eq!(child.depth(), 1);
//! ```

// CANONICAL TYPE ENFORCEMENT (bd-1usdh.3):
// The types defined in this crate (TraceId, DecisionId, PolicyId,
// SchemaVersion, Budget, Cx, NoCaps) are the SOLE canonical definitions
// for the entire FrankenSuite. No other crate may define competing types
// with the same names. Use `scripts/check_type_forks.sh` to verify.
// See also: `.type_fork_baseline.json` for known pre-migration forks.

#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::fmt;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;
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
// Budget — tropical semiring (min, +)
// ---------------------------------------------------------------------------

/// Time budget in the tropical semiring (min, +).
///
/// Budget decreases additively via [`consume`](Budget::consume) and the
/// constraint propagates as the minimum of parent and child budgets.
///
/// ```
/// use franken_kernel::Budget;
///
/// let b = Budget::new(1000);
/// let b2 = b.consume(300).unwrap();
/// assert_eq!(b2.remaining_ms(), 700);
/// assert!(b2.consume(800).is_none()); // would exceed budget
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Budget {
    remaining_ms: u64,
}

impl Budget {
    /// Create a budget with the given milliseconds remaining.
    pub const fn new(ms: u64) -> Self {
        Self { remaining_ms: ms }
    }

    /// Milliseconds remaining.
    pub const fn remaining_ms(self) -> u64 {
        self.remaining_ms
    }

    /// Consume `ms` milliseconds from the budget.
    ///
    /// Returns `None` if insufficient budget remains.
    pub const fn consume(self, ms: u64) -> Option<Self> {
        if self.remaining_ms >= ms {
            Some(Self {
                remaining_ms: self.remaining_ms - ms,
            })
        } else {
            None
        }
    }

    /// Whether the budget is fully exhausted.
    pub const fn is_exhausted(self) -> bool {
        self.remaining_ms == 0
    }

    /// Tropical semiring min: returns the tighter (smaller) budget.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if self.remaining_ms <= other.remaining_ms {
            self
        } else {
            other
        }
    }

    /// An unlimited budget (max u64 value).
    pub const UNLIMITED: Self = Self {
        remaining_ms: u64::MAX,
    };
}

// ---------------------------------------------------------------------------
// CapabilitySet — trait for capability collections
// ---------------------------------------------------------------------------

/// Trait for capability sets carried by [`Cx`].
///
/// Each FrankenSuite project defines its own capability types and
/// implements this trait. The trait provides introspection for logging
/// and diagnostics.
///
/// Implementations must be `Clone + Send + Sync` to allow context
/// propagation across async task boundaries.
pub trait CapabilitySet: Clone + fmt::Debug + Send + Sync {
    /// Human-readable names of the capabilities in this set.
    fn capability_names(&self) -> Vec<&str>;

    /// Number of distinct capabilities.
    fn count(&self) -> usize;

    /// Whether the capability set is empty.
    fn is_empty(&self) -> bool {
        self.count() == 0
    }
}

/// An empty capability set for contexts that carry no capabilities.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoCaps;

impl CapabilitySet for NoCaps {
    fn capability_names(&self) -> Vec<&str> {
        Vec::new()
    }

    fn count(&self) -> usize {
        0
    }
}

// ---------------------------------------------------------------------------
// Cx — capability context
// ---------------------------------------------------------------------------

/// Capability context threaded through all FrankenSuite operations.
///
/// `Cx` carries:
/// - A [`TraceId`] for distributed tracing across project boundaries.
/// - A [`Budget`] in the tropical semiring (min, +) for resource limits.
/// - A generic [`CapabilitySet`] defining available capabilities.
/// - Nesting depth for diagnostics.
///
/// The lifetime parameter `'a` ensures that child contexts cannot
/// outlive their parent scope, enforcing structured concurrency
/// invariants.
///
/// # Propagation
///
/// Child contexts are created via [`child`](Cx::child), which:
/// - Inherits the parent's `TraceId`.
/// - Takes the minimum of parent and child budgets (tropical min).
/// - Increments the nesting depth.
pub struct Cx<'a, C: CapabilitySet = NoCaps> {
    trace_id: TraceId,
    budget: Budget,
    capabilities: C,
    depth: u32,
    _scope: PhantomData<&'a ()>,
}

impl<C: CapabilitySet> Cx<'_, C> {
    /// Create a root context with the given trace, budget, and capabilities.
    pub fn new(trace_id: TraceId, budget: Budget, capabilities: C) -> Self {
        Self {
            trace_id,
            budget,
            capabilities,
            depth: 0,
            _scope: PhantomData,
        }
    }

    /// Create a child context.
    ///
    /// The child inherits this context's `TraceId` and takes the minimum
    /// of this context's budget and the provided `budget`.
    pub fn child(&self, capabilities: C, budget: Budget) -> Cx<'_, C> {
        Cx {
            trace_id: self.trace_id,
            budget: self.budget.min(budget),
            capabilities,
            depth: self.depth + 1,
            _scope: PhantomData,
        }
    }

    /// The trace identifier for this context.
    pub const fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// The remaining budget.
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// The capability set.
    pub fn capabilities(&self) -> &C {
        &self.capabilities
    }

    /// Nesting depth (0 for root contexts).
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Consume budget from this context in place.
    ///
    /// Returns `false` if insufficient budget remains (budget unchanged).
    pub fn consume_budget(&mut self, ms: u64) -> bool {
        match self.budget.consume(ms) {
            Some(new_budget) => {
                self.budget = new_budget;
                true
            }
            None => false,
        }
    }
}

impl<C: CapabilitySet> fmt::Debug for Cx<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cx")
            .field("trace_id", &self.trace_id)
            .field("budget_ms", &self.budget.remaining_ms())
            .field("capabilities", &self.capabilities)
            .field("depth", &self.depth)
            .finish()
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

    // -- Budget tests --

    #[test]
    fn budget_new_and_remaining() {
        let b = Budget::new(5000);
        assert_eq!(b.remaining_ms(), 5000);
        assert!(!b.is_exhausted());
    }

    #[test]
    fn budget_consume() {
        let b = Budget::new(1000);
        let b2 = b.consume(300).unwrap();
        assert_eq!(b2.remaining_ms(), 700);
        let b3 = b2.consume(700).unwrap();
        assert_eq!(b3.remaining_ms(), 0);
        assert!(b3.is_exhausted());
    }

    #[test]
    fn budget_consume_insufficient() {
        let b = Budget::new(100);
        assert!(b.consume(200).is_none());
    }

    #[test]
    fn budget_min() {
        let b1 = Budget::new(500);
        let b2 = Budget::new(300);
        assert_eq!(b1.min(b2).remaining_ms(), 300);
        assert_eq!(b2.min(b1).remaining_ms(), 300);
    }

    #[test]
    fn budget_unlimited() {
        let b = Budget::UNLIMITED;
        assert_eq!(b.remaining_ms(), u64::MAX);
        assert!(!b.is_exhausted());
    }

    #[test]
    fn budget_serde_json() {
        let b = Budget::new(42);
        let json = serde_json::to_string(&b).unwrap();
        let parsed: Budget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, parsed);
    }

    #[test]
    fn budget_copy_semantics() {
        let b = Budget::new(100);
        let copy = b;
        assert_eq!(b, copy); // Both usable (Copy).
    }

    // -- NoCaps tests --

    #[test]
    fn no_caps_empty() {
        let caps = NoCaps;
        assert_eq!(caps.count(), 0);
        assert!(caps.is_empty());
        assert!(caps.capability_names().is_empty());
    }

    // -- Cx tests --

    #[test]
    fn cx_root_creation() {
        let trace = TraceId::from_parts(1_700_000_000_000, 1);
        let cx = Cx::new(trace, Budget::new(5000), NoCaps);
        assert_eq!(cx.trace_id(), trace);
        assert_eq!(cx.budget().remaining_ms(), 5000);
        assert_eq!(cx.depth(), 0);
        assert!(cx.capabilities().is_empty());
    }

    #[test]
    fn cx_child_inherits_trace() {
        let trace = TraceId::from_parts(1_700_000_000_000, 42);
        let cx = Cx::new(trace, Budget::new(5000), NoCaps);
        let child = cx.child(NoCaps, Budget::new(3000));
        assert_eq!(child.trace_id(), trace);
    }

    #[test]
    fn cx_child_budget_takes_min() {
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(2000), NoCaps);
        // Child requests less than parent — child gets its request.
        let child1 = cx.child(NoCaps, Budget::new(1000));
        assert_eq!(child1.budget().remaining_ms(), 1000);
        // Child requests more than parent — capped at parent.
        let child2 = cx.child(NoCaps, Budget::new(5000));
        assert_eq!(child2.budget().remaining_ms(), 2000);
    }

    #[test]
    fn cx_child_increments_depth() {
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(1000), NoCaps);
        let child = cx.child(NoCaps, Budget::new(1000));
        assert_eq!(child.depth(), 1);
        let grandchild = child.child(NoCaps, Budget::new(1000));
        assert_eq!(grandchild.depth(), 2);
    }

    #[test]
    fn cx_consume_budget() {
        let mut cx = Cx::new(TraceId::from_raw(1), Budget::new(500), NoCaps);
        assert!(cx.consume_budget(200));
        assert_eq!(cx.budget().remaining_ms(), 300);
        assert!(!cx.consume_budget(400)); // insufficient
        assert_eq!(cx.budget().remaining_ms(), 300); // unchanged
    }

    #[test]
    fn cx_debug_format() {
        let cx = Cx::new(TraceId::from_raw(0xAB), Budget::new(100), NoCaps);
        let dbg = std::format!("{cx:?}");
        assert!(dbg.contains("Cx"));
        assert!(dbg.contains("budget_ms"));
        assert!(dbg.contains("100"));
    }

    // -- Custom CapabilitySet --

    #[derive(Clone, Debug)]
    struct TestCaps {
        can_read: bool,
        can_write: bool,
    }

    impl CapabilitySet for TestCaps {
        fn capability_names(&self) -> alloc::vec::Vec<&str> {
            let mut names = alloc::vec::Vec::new();
            if self.can_read {
                names.push("read");
            }
            if self.can_write {
                names.push("write");
            }
            names
        }

        fn count(&self) -> usize {
            usize::from(self.can_read) + usize::from(self.can_write)
        }
    }

    #[test]
    fn cx_with_custom_capabilities() {
        let caps = TestCaps {
            can_read: true,
            can_write: false,
        };
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(1000), caps);
        assert_eq!(cx.capabilities().count(), 1);
        assert_eq!(cx.capabilities().capability_names(), &["read"]);
    }

    #[test]
    fn cx_child_with_attenuated_capabilities() {
        let full_caps = TestCaps {
            can_read: true,
            can_write: true,
        };
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(1000), full_caps);
        assert_eq!(cx.capabilities().count(), 2);

        // Child gets attenuated (read-only) capabilities.
        let read_only = TestCaps {
            can_read: true,
            can_write: false,
        };
        let child = cx.child(read_only, Budget::new(500));
        assert_eq!(child.capabilities().count(), 1);
        assert!(!child.capabilities().capability_names().contains(&"write"));
    }
}
