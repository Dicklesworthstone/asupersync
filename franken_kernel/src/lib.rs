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
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    use std::string::ToString;

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }

    // -----------------------------------------------------------------------
    // TraceId tests
    // -----------------------------------------------------------------------

    #[test]
    fn trace_id_from_parts_roundtrip() {
        let ts = 1_700_000_000_000_u64;
        let random = 0x00AB_CDEF_0123_4567_89AB_u128;
        let id = TraceId::from_parts(ts, random);
        assert_eq!(id.timestamp_ms(), ts);
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
    fn trace_id_uuidv7_monotonic_ordering_10k() {
        // Generate 10,000 TraceIds with increasing timestamps; verify monotonic order.
        let ids: std::vec::Vec<TraceId> = (0..10_000)
            .map(|i| TraceId::from_parts(1_700_000_000_000 + i, 0))
            .collect();
        for window in ids.windows(2) {
            assert!(
                window[0] < window[1],
                "TraceId ordering violated: {:?} >= {:?}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn trace_id_display_parse_roundtrip_many() {
        // Roundtrip 10,000 random-ish TraceIds through Display -> FromStr.
        for i in 0..10_000_u128 {
            let raw = i.wrapping_mul(0x0123_4567_89AB_CDEF) ^ (i << 64);
            let id = TraceId::from_raw(raw);
            let hex = id.to_string();
            let parsed: TraceId = hex.parse().unwrap();
            assert_eq!(id, parsed, "roundtrip failed for raw={raw:#034x}");
        }
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
    fn trace_id_serde_roundtrip_many() {
        for i in 0..1_000_u128 {
            let id = TraceId::from_raw(i.wrapping_mul(0xDEAD_BEEF_CAFE_1234));
            let json = serde_json::to_string(&id).unwrap();
            let parsed: TraceId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, parsed);
        }
    }

    #[test]
    fn trace_id_debug_format() {
        let id = TraceId::from_raw(0xAB);
        let dbg = std::format!("{id:?}");
        assert!(dbg.starts_with("TraceId("));
        assert!(dbg.contains("ab"));
    }

    #[test]
    fn trace_id_copy_semantics() {
        let id = TraceId::from_raw(42);
        let copy = id;
        assert_eq!(id, copy); // Both still usable (Copy).
    }

    #[test]
    fn trace_id_hash_consistency() {
        let a = TraceId::from_raw(0xDEAD);
        let b = TraceId::from_raw(0xDEAD);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn trace_id_zero_and_max() {
        let zero = TraceId::from_raw(0);
        assert_eq!(zero.timestamp_ms(), 0);
        assert_eq!(zero.to_string(), "00000000000000000000000000000000");
        let roundtrip: TraceId = zero.to_string().parse().unwrap();
        assert_eq!(zero, roundtrip);

        let max = TraceId::from_raw(u128::MAX);
        assert_eq!(max.to_string(), "ffffffffffffffffffffffffffffffff");
        let roundtrip: TraceId = max.to_string().parse().unwrap();
        assert_eq!(max, roundtrip);
    }

    // -----------------------------------------------------------------------
    // DecisionId tests
    // -----------------------------------------------------------------------

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
    fn decision_id_display_parse_roundtrip_many() {
        for i in 0..10_000_u128 {
            let raw = i.wrapping_mul(0xABCD_EF01_2345_6789) ^ (i << 64);
            let id = DecisionId::from_raw(raw);
            let hex = id.to_string();
            let parsed: DecisionId = hex.parse().unwrap();
            assert_eq!(id, parsed, "roundtrip failed for raw={raw:#034x}");
        }
    }

    #[test]
    fn decision_id_ordering() {
        let earlier = DecisionId::from_parts(1000, 0);
        let later = DecisionId::from_parts(2000, 0);
        assert!(earlier < later);
    }

    #[test]
    fn decision_id_monotonic_ordering_10k() {
        let ids: std::vec::Vec<DecisionId> = (0..10_000)
            .map(|i| DecisionId::from_parts(1_700_000_000_000 + i, 0))
            .collect();
        for window in ids.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn decision_id_serde_json() {
        let id = DecisionId::from_raw(1);
        let json = serde_json::to_string(&id).unwrap();
        let parsed: DecisionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn decision_id_debug_format() {
        let id = DecisionId::from_raw(0xCD);
        let dbg = std::format!("{id:?}");
        assert!(dbg.starts_with("DecisionId("));
        assert!(dbg.contains("cd"));
    }

    #[test]
    fn decision_id_copy_semantics() {
        let id = DecisionId::from_raw(99);
        let copy = id;
        assert_eq!(id, copy);
    }

    #[test]
    fn decision_id_hash_consistency() {
        let a = DecisionId::from_raw(0xBEEF);
        let b = DecisionId::from_raw(0xBEEF);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn decision_id_bytes_roundtrip() {
        let id = DecisionId::from_raw(0x1234_5678_9ABC_DEF0);
        let bytes = id.to_bytes();
        let recovered = DecisionId::from_bytes(bytes);
        assert_eq!(id, recovered);
    }

    // -----------------------------------------------------------------------
    // PolicyId tests
    // -----------------------------------------------------------------------

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
    fn policy_id_ordering() {
        let a = PolicyId::new("a.policy", 1);
        let b = PolicyId::new("b.policy", 1);
        assert!(a < b, "PolicyId should order lexicographically by name");
        let v1 = PolicyId::new("same", 1);
        let v2 = PolicyId::new("same", 2);
        assert!(v1 < v2, "same name, should order by version");
    }

    #[test]
    fn policy_id_hash_consistency() {
        let a = PolicyId::new("test.policy", 5);
        let b = PolicyId::new("test.policy", 5);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    // -----------------------------------------------------------------------
    // SchemaVersion tests
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_compatible() {
        let v1_2_3 = SchemaVersion::new(1, 2, 3);
        let v1_5_0 = SchemaVersion::new(1, 5, 0);
        let v2_0_0 = SchemaVersion::new(2, 0, 0);
        assert!(v1_2_3.is_compatible(&v1_5_0));
        assert!(!v1_2_3.is_compatible(&v2_0_0));
    }

    #[test]
    fn schema_version_0x_edge_cases() {
        // 0.x versions: 0.1 and 0.2 both have major=0, so they ARE compatible
        // under our semver rule (same major).
        let v0_1 = SchemaVersion::new(0, 1, 0);
        let v0_2 = SchemaVersion::new(0, 2, 0);
        assert!(
            v0_1.is_compatible(&v0_2),
            "0.x versions should be compatible (same major=0)"
        );

        // 0.x vs 1.x should NOT be compatible.
        let v1_0 = SchemaVersion::new(1, 0, 0);
        assert!(!v0_1.is_compatible(&v1_0));
    }

    #[test]
    fn schema_version_display_parse_roundtrip() {
        let v = SchemaVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
        let parsed: SchemaVersion = "1.2.3".parse().unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn schema_version_ordering_comprehensive() {
        let versions = [
            SchemaVersion::new(1, 0, 0),
            SchemaVersion::new(1, 0, 1),
            SchemaVersion::new(1, 1, 0),
            SchemaVersion::new(2, 0, 0),
            SchemaVersion::new(2, 1, 0),
            SchemaVersion::new(10, 0, 0),
        ];
        for window in versions.windows(2) {
            assert!(
                window[0] < window[1],
                "{} should be < {}",
                window[0],
                window[1]
            );
        }
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
    fn schema_version_copy_semantics() {
        let v = SchemaVersion::new(1, 0, 0);
        let copy = v;
        assert_eq!(v, copy);
    }

    #[test]
    fn schema_version_hash_consistency() {
        let a = SchemaVersion::new(1, 2, 3);
        let b = SchemaVersion::new(1, 2, 3);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn schema_version_self_compatible() {
        let v = SchemaVersion::new(5, 3, 1);
        assert!(
            v.is_compatible(&v),
            "version must be compatible with itself"
        );
    }

    // -----------------------------------------------------------------------
    // Error type tests
    // -----------------------------------------------------------------------

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
        assert!("".parse::<SchemaVersion>().is_err());
    }

    // -----------------------------------------------------------------------
    // Send + Sync static assertions
    // -----------------------------------------------------------------------

    #[test]
    fn all_types_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TraceId>();
        assert_send_sync::<DecisionId>();
        assert_send_sync::<PolicyId>();
        assert_send_sync::<SchemaVersion>();
        assert_send_sync::<Budget>();
        assert_send_sync::<NoCaps>();
        // Cx requires C: CapabilitySet which requires Send + Sync.
        assert_send_sync::<Cx<'_, NoCaps>>();
    }

    // -----------------------------------------------------------------------
    // Budget tests
    // -----------------------------------------------------------------------

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
    fn budget_consume_exact() {
        let b = Budget::new(100);
        let b2 = b.consume(100).unwrap();
        assert!(b2.is_exhausted());
    }

    #[test]
    fn budget_consume_zero() {
        let b = Budget::new(100);
        let b2 = b.consume(0).unwrap();
        assert_eq!(b2.remaining_ms(), 100);
    }

    #[test]
    fn budget_min() {
        let b1 = Budget::new(500);
        let b2 = Budget::new(300);
        assert_eq!(b1.min(b2).remaining_ms(), 300);
        assert_eq!(b2.min(b1).remaining_ms(), 300);
    }

    #[test]
    fn budget_min_equal() {
        let b = Budget::new(100);
        assert_eq!(b.min(b).remaining_ms(), 100);
    }

    #[test]
    fn budget_unlimited() {
        let b = Budget::UNLIMITED;
        assert_eq!(b.remaining_ms(), u64::MAX);
        assert!(!b.is_exhausted());
    }

    #[test]
    fn budget_unlimited_min_with_finite() {
        let finite = Budget::new(1000);
        assert_eq!(Budget::UNLIMITED.min(finite).remaining_ms(), 1000);
        assert_eq!(finite.min(Budget::UNLIMITED).remaining_ms(), 1000);
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
        assert_eq!(b, copy);
    }

    #[test]
    fn budget_tropical_identity() {
        // Identity element of min is UNLIMITED (u64::MAX).
        let b = Budget::new(42);
        assert_eq!(b.min(Budget::UNLIMITED), b);
        assert_eq!(Budget::UNLIMITED.min(b), b);
    }

    #[test]
    fn budget_tropical_commutativity() {
        let a = Budget::new(100);
        let b = Budget::new(200);
        assert_eq!(a.min(b), b.min(a));
    }

    #[test]
    fn budget_tropical_associativity() {
        let a = Budget::new(100);
        let b = Budget::new(200);
        let c = Budget::new(50);
        assert_eq!(a.min(b).min(c), a.min(b.min(c)));
    }

    // -----------------------------------------------------------------------
    // NoCaps tests
    // -----------------------------------------------------------------------

    #[test]
    fn no_caps_empty() {
        let caps = NoCaps;
        assert_eq!(caps.count(), 0);
        assert!(caps.is_empty());
        assert!(caps.capability_names().is_empty());
    }

    #[test]
    fn no_caps_clone() {
        let a = NoCaps;
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Custom CapabilitySet for testing
    // -----------------------------------------------------------------------

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

    /// Layered capability set for testing attenuation chains.
    #[derive(Clone, Debug)]
    struct LayeredCaps {
        level: u32,
    }

    impl CapabilitySet for LayeredCaps {
        fn capability_names(&self) -> alloc::vec::Vec<&str> {
            if self.level > 0 {
                alloc::vec!["layer"]
            } else {
                alloc::vec::Vec::new()
            }
        }

        fn count(&self) -> usize {
            usize::from(self.level > 0)
        }
    }

    // -----------------------------------------------------------------------
    // Cx tests
    // -----------------------------------------------------------------------

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
        let child1 = cx.child(NoCaps, Budget::new(1000));
        assert_eq!(child1.budget().remaining_ms(), 1000);
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
        assert!(!cx.consume_budget(400));
        assert_eq!(cx.budget().remaining_ms(), 300);
    }

    #[test]
    fn cx_debug_format() {
        let cx = Cx::new(TraceId::from_raw(0xAB), Budget::new(100), NoCaps);
        let dbg = std::format!("{cx:?}");
        assert!(dbg.contains("Cx"));
        assert!(dbg.contains("budget_ms"));
        assert!(dbg.contains("100"));
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

        let read_only = TestCaps {
            can_read: true,
            can_write: false,
        };
        let child = cx.child(read_only, Budget::new(500));
        assert_eq!(child.capabilities().count(), 1);
        assert!(!child.capabilities().capability_names().contains(&"write"));
    }

    #[test]
    fn cx_capability_attenuation_chain_10x() {
        // Create a chain of 10 nested contexts, each with decreasing level.
        let trace = TraceId::from_raw(0x42);
        let root = Cx::new(trace, Budget::new(10_000), LayeredCaps { level: 10 });
        assert_eq!(root.capabilities().level, 10);

        let mut prev_level = 10_u32;
        let child1 = root.child(LayeredCaps { level: 9 }, Budget::new(9000));
        assert!(child1.capabilities().level < prev_level);
        prev_level = child1.capabilities().level;

        let child2 = child1.child(LayeredCaps { level: 8 }, Budget::new(8000));
        assert!(child2.capabilities().level < prev_level);
        prev_level = child2.capabilities().level;

        let child3 = child2.child(LayeredCaps { level: 7 }, Budget::new(7000));
        assert!(child3.capabilities().level < prev_level);
        prev_level = child3.capabilities().level;

        let child4 = child3.child(LayeredCaps { level: 6 }, Budget::new(6000));
        assert!(child4.capabilities().level < prev_level);
        prev_level = child4.capabilities().level;

        let child5 = child4.child(LayeredCaps { level: 5 }, Budget::new(5000));
        assert!(child5.capabilities().level < prev_level);
        prev_level = child5.capabilities().level;

        let child6 = child5.child(LayeredCaps { level: 4 }, Budget::new(4000));
        assert!(child6.capabilities().level < prev_level);
        prev_level = child6.capabilities().level;

        let child7 = child6.child(LayeredCaps { level: 3 }, Budget::new(3000));
        assert!(child7.capabilities().level < prev_level);
        prev_level = child7.capabilities().level;

        let child8 = child7.child(LayeredCaps { level: 2 }, Budget::new(2000));
        assert!(child8.capabilities().level < prev_level);
        prev_level = child8.capabilities().level;

        let child9 = child8.child(LayeredCaps { level: 1 }, Budget::new(1000));
        assert!(child9.capabilities().level < prev_level);
        prev_level = child9.capabilities().level;

        let child10 = child9.child(LayeredCaps { level: 0 }, Budget::new(500));
        assert!(child10.capabilities().level < prev_level);
        assert_eq!(child10.capabilities().level, 0);
        assert!(child10.capabilities().is_empty());
        assert_eq!(child10.depth(), 10);

        // Trace propagated through all 10 levels.
        assert_eq!(child10.trace_id(), trace);
        // Budget capped by minimum in chain: 500 ms.
        assert_eq!(child10.budget().remaining_ms(), 500);
    }

    #[test]
    fn cx_deep_nesting_budget_monotonic() {
        // Budget can only decrease or stay the same through nesting.
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(1000), NoCaps);
        let c1 = cx.child(NoCaps, Budget::new(900));
        let c2 = c1.child(NoCaps, Budget::new(800));
        let c3 = c2.child(NoCaps, Budget::new(700));
        let c4 = c3.child(NoCaps, Budget::new(600));

        assert!(c1.budget().remaining_ms() <= cx.budget().remaining_ms());
        assert!(c2.budget().remaining_ms() <= c1.budget().remaining_ms());
        assert!(c3.budget().remaining_ms() <= c2.budget().remaining_ms());
        assert!(c4.budget().remaining_ms() <= c3.budget().remaining_ms());
    }

    #[test]
    fn cx_child_cannot_exceed_parent_budget() {
        let cx = Cx::new(TraceId::from_raw(1), Budget::new(100), NoCaps);
        // Child requests much more — capped at parent's 100.
        let child = cx.child(NoCaps, Budget::UNLIMITED);
        assert_eq!(child.budget().remaining_ms(), 100);
    }

    #[test]
    fn cx_trace_propagation_through_chain() {
        let trace = TraceId::from_parts(1_700_000_000_000, 0xCAFE);
        let cx = Cx::new(trace, Budget::UNLIMITED, NoCaps);
        let c1 = cx.child(NoCaps, Budget::UNLIMITED);
        let c2 = c1.child(NoCaps, Budget::UNLIMITED);
        let c3 = c2.child(NoCaps, Budget::UNLIMITED);
        assert_eq!(c3.trace_id(), trace);
        assert_eq!(c3.depth(), 3);
    }
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    extern crate std;

    use super::*;
    use core::hash::{Hash, Hasher};
    use proptest::prelude::*;
    use std::collections::hash_map::DefaultHasher;
    use std::string::ToString;

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }

    // -- TraceId properties --

    proptest! {
        #[test]
        fn trace_id_display_fromstr_roundtrip(raw: u128) {
            let id = TraceId::from_raw(raw);
            let hex = id.to_string();
            let parsed: TraceId = hex.parse().unwrap();
            prop_assert_eq!(id, parsed);
        }

        #[test]
        fn trace_id_serde_roundtrip(raw: u128) {
            let id = TraceId::from_raw(raw);
            let json = serde_json::to_string(&id).unwrap();
            let parsed: TraceId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, parsed);
        }

        #[test]
        fn trace_id_bytes_roundtrip(raw: u128) {
            let id = TraceId::from_raw(raw);
            let bytes = id.to_bytes();
            let recovered = TraceId::from_bytes(bytes);
            prop_assert_eq!(id, recovered);
        }

        #[test]
        fn trace_id_hash_consistency(a: u128, b: u128) {
            let id_a = TraceId::from_raw(a);
            let id_b = TraceId::from_raw(b);
            if id_a == id_b {
                prop_assert_eq!(hash_of(&id_a), hash_of(&id_b));
            }
        }

        #[test]
        fn trace_id_from_parts_preserves_timestamp(ts_ms: u64, random: u128) {
            // Only 48 bits of timestamp are stored.
            let ts_masked = ts_ms & 0xFFFF_FFFF_FFFF;
            let id = TraceId::from_parts(ts_masked, random);
            prop_assert_eq!(id.timestamp_ms(), ts_masked);
        }
    }

    // -- DecisionId properties --

    proptest! {
        #[test]
        fn decision_id_display_fromstr_roundtrip(raw: u128) {
            let id = DecisionId::from_raw(raw);
            let hex = id.to_string();
            let parsed: DecisionId = hex.parse().unwrap();
            prop_assert_eq!(id, parsed);
        }

        #[test]
        fn decision_id_serde_roundtrip(raw: u128) {
            let id = DecisionId::from_raw(raw);
            let json = serde_json::to_string(&id).unwrap();
            let parsed: DecisionId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, parsed);
        }

        #[test]
        fn decision_id_hash_consistency(a: u128, b: u128) {
            let id_a = DecisionId::from_raw(a);
            let id_b = DecisionId::from_raw(b);
            if id_a == id_b {
                prop_assert_eq!(hash_of(&id_a), hash_of(&id_b));
            }
        }
    }

    // -- SchemaVersion properties --

    proptest! {
        #[test]
        fn schema_version_parse_roundtrip(major: u32, minor: u32, patch: u32) {
            let v = SchemaVersion::new(major, minor, patch);
            let s = v.to_string();
            let parsed: SchemaVersion = s.parse().unwrap();
            prop_assert_eq!(v, parsed);
        }

        #[test]
        fn schema_version_serde_roundtrip(major: u32, minor: u32, patch: u32) {
            let v = SchemaVersion::new(major, minor, patch);
            let json = serde_json::to_string(&v).unwrap();
            let parsed: SchemaVersion = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(v, parsed);
        }

        #[test]
        fn schema_version_compatible_reflexive(major: u32, minor: u32, patch: u32) {
            let v = SchemaVersion::new(major, minor, patch);
            prop_assert!(v.is_compatible(&v));
        }

        #[test]
        fn schema_version_compatible_symmetric(
            m1: u32, n1: u32, p1: u32,
            m2: u32, n2: u32, p2: u32
        ) {
            let a = SchemaVersion::new(m1, n1, p1);
            let b = SchemaVersion::new(m2, n2, p2);
            prop_assert_eq!(a.is_compatible(&b), b.is_compatible(&a));
        }

        #[test]
        fn schema_version_compatible_transitive(
            m1: u32, n1: u32, p1: u32,
            n2: u32, p2: u32,
            n3: u32, p3: u32
        ) {
            // If a and b share the same major, and b and c share the same major,
            // then a and c must share the same major.
            let a = SchemaVersion::new(m1, n1, p1);
            let b = SchemaVersion::new(m1, n2, p2);
            let c = SchemaVersion::new(m1, n3, p3);
            if a.is_compatible(&b) && b.is_compatible(&c) {
                prop_assert!(a.is_compatible(&c));
            }
        }

        #[test]
        fn schema_version_hash_consistency(
            m1: u32, n1: u32, p1: u32,
            m2: u32, n2: u32, p2: u32
        ) {
            let a = SchemaVersion::new(m1, n1, p1);
            let b = SchemaVersion::new(m2, n2, p2);
            if a == b {
                prop_assert_eq!(hash_of(&a), hash_of(&b));
            }
        }
    }

    // -- Budget tropical semiring properties --

    proptest! {
        #[test]
        fn budget_min_commutative(a: u64, b: u64) {
            let ba = Budget::new(a);
            let bb = Budget::new(b);
            prop_assert_eq!(ba.min(bb), bb.min(ba));
        }

        #[test]
        fn budget_min_associative(a: u64, b: u64, c: u64) {
            let ba = Budget::new(a);
            let bb = Budget::new(b);
            let bc = Budget::new(c);
            prop_assert_eq!(ba.min(bb).min(bc), ba.min(bb.min(bc)));
        }

        #[test]
        fn budget_min_identity(a: u64) {
            // UNLIMITED is the identity element for min.
            let ba = Budget::new(a);
            prop_assert_eq!(ba.min(Budget::UNLIMITED), ba);
            prop_assert_eq!(Budget::UNLIMITED.min(ba), ba);
        }

        #[test]
        fn budget_min_idempotent(a: u64) {
            let ba = Budget::new(a);
            prop_assert_eq!(ba.min(ba), ba);
        }

        #[test]
        fn budget_consume_additive(total in 0..=10_000_u64, a in 0..=5_000_u64, b in 0..=5_000_u64) {
            // If we can consume a+b, consuming a then b should give the same result.
            let budget = Budget::new(total);
            if a + b <= total {
                let after_both = budget.consume(a + b).unwrap();
                let after_a = budget.consume(a).unwrap();
                let after_ab = after_a.consume(b).unwrap();
                prop_assert_eq!(after_both.remaining_ms(), after_ab.remaining_ms());
            }
        }

        #[test]
        fn budget_serde_roundtrip(ms: u64) {
            let b = Budget::new(ms);
            let json = serde_json::to_string(&b).unwrap();
            let parsed: Budget = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(b, parsed);
        }

        #[test]
        fn budget_hash_consistency(a: u64, b: u64) {
            let ba = Budget::new(a);
            let bb = Budget::new(b);
            if ba == bb {
                prop_assert_eq!(hash_of(&ba), hash_of(&bb));
            }
        }
    }

    // -- Cx property tests --

    proptest! {
        #[test]
        fn cx_child_budget_never_exceeds_parent(parent_ms: u64, child_ms: u64) {
            let trace = TraceId::from_raw(1);
            let cx = Cx::new(trace, Budget::new(parent_ms), NoCaps);
            let child = cx.child(NoCaps, Budget::new(child_ms));
            prop_assert!(child.budget().remaining_ms() <= cx.budget().remaining_ms());
        }

        #[test]
        fn cx_child_trace_always_inherited(raw: u128, budget_ms: u64) {
            let trace = TraceId::from_raw(raw);
            let cx = Cx::new(trace, Budget::new(budget_ms), NoCaps);
            let child = cx.child(NoCaps, Budget::new(budget_ms));
            prop_assert_eq!(child.trace_id(), trace);
        }

        #[test]
        fn cx_child_depth_increments(raw: u128, budget_ms: u64) {
            let cx = Cx::new(TraceId::from_raw(raw), Budget::new(budget_ms), NoCaps);
            let child = cx.child(NoCaps, Budget::new(budget_ms));
            prop_assert_eq!(child.depth(), cx.depth() + 1);
        }
    }
}
