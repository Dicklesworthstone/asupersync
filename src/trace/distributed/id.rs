//! Trace identifiers for symbol-based distributed tracing.

use crate::util::DetRng;
use core::fmt;

/// A 128-bit trace identifier in W3C Trace Context wire format.
///
/// **Not** the canonical [`crate::types::TraceId`] (the timestamped
/// 128-bit identifier re-exported from `franken_kernel`). This type is
/// purpose-specific to the distributed tracing subsystem: its serialization
/// is locked by a golden snapshot (`canonical_trace_id_serialization`)
/// because the W3C 32-hex-character format is part of the on-the-wire
/// contract with downstream collectors and cannot drift. New code that
/// needs a "TraceId" for EvidenceLedger linkage should use the canonical
/// franken_kernel one. (Renamed from `TraceId` to `DistTraceId` in
/// br-asupersync-v4az2y so the name collision with the canonical type
/// goes away. Wire format — `to_w3c_string` — is unchanged.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DistTraceId {
    high: u64,
    low: u64,
}

impl DistTraceId {
    /// Creates a new trace ID from two 64-bit values.
    #[must_use]
    pub const fn new(high: u64, low: u64) -> Self {
        Self { high, low }
    }

    /// Creates a trace ID from a 128-bit value.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self {
            high: (value >> 64) as u64,
            low: value as u64,
        }
    }

    /// Converts the trace ID to a 128-bit value.
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        ((self.high as u128) << 64) | (self.low as u128)
    }

    /// Returns the high 64 bits.
    #[must_use]
    pub const fn high(self) -> u64 {
        self.high
    }

    /// Returns the low 64 bits.
    #[must_use]
    pub const fn low(self) -> u64 {
        self.low
    }

    /// Creates a random trace ID using a deterministic RNG.
    #[must_use]
    pub fn new_random(rng: &mut DetRng) -> Self {
        Self {
            high: rng.next_u64(),
            low: rng.next_u64(),
        }
    }

    /// Creates a trace ID for testing.
    #[doc(hidden)]
    #[must_use]
    pub const fn new_for_test(value: u64) -> Self {
        Self {
            high: 0,
            low: value,
        }
    }

    /// The nil (zero) trace ID.
    pub const NIL: Self = Self { high: 0, low: 0 };

    /// Returns true if this is the nil trace ID.
    #[must_use]
    pub const fn is_nil(self) -> bool {
        self.high == 0 && self.low == 0
    }

    /// Returns the W3C Trace Context format (32 hex chars).
    #[must_use]
    pub fn to_w3c_string(self) -> String {
        format!("{:016x}{:016x}", self.high, self.low)
    }

    /// Parses from W3C Trace Context format.
    #[must_use]
    pub fn from_w3c_string(s: &str) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }
        let high = u64::from_str_radix(&s[..16], 16).ok()?;
        let low = u64::from_str_radix(&s[16..], 16).ok()?;
        Some(Self { high, low })
    }
}

impl fmt::Debug for DistTraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DistTraceId({:016x}{:016x})", self.high, self.low)
    }
}

impl fmt::Display for DistTraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.high)
    }
}

/// A 64-bit span identifier within a trace.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolSpanId(u64);

impl SymbolSpanId {
    /// Creates a new span ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw ID value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Creates a random span ID.
    #[must_use]
    pub fn new_random(rng: &mut DetRng) -> Self {
        Self(rng.next_u64())
    }

    /// Creates a span ID for testing.
    #[doc(hidden)]
    #[must_use]
    pub const fn new_for_test(value: u64) -> Self {
        Self(value)
    }

    /// The nil (zero) span ID.
    pub const NIL: Self = Self(0);
}

impl fmt::Debug for SymbolSpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymbolSpanId({:016x})", self.0)
    }
}

impl fmt::Display for SymbolSpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", (self.0 & 0xFFFF_FFFF) as u32)
    }
}

#[cfg(test)]
#[path = "id_inline_tests.rs"]
mod tests;
