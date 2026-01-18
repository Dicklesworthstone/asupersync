//! Trace identifiers for symbol-based distributed tracing.

use crate::util::DetRng;
use core::fmt;

/// A 128-bit trace identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId {
    high: u64,
    low: u64,
}

impl TraceId {
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
        Self { high: 0, low: value }
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

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({:016x}{:016x})", self.high, self.low)
    }
}

impl fmt::Display for TraceId {
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
mod tests {
    use super::*;

    #[test]
    fn trace_id_w3c_roundtrip() {
        let id = TraceId::new(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210);
        let w3c = id.to_w3c_string();
        let parsed = TraceId::from_w3c_string(&w3c).expect("parse should succeed");
        assert_eq!(id, parsed);
    }

    #[test]
    fn trace_id_nil_detection() {
        let id = TraceId::NIL;
        assert!(id.is_nil());
        let id = TraceId::new(1, 0);
        assert!(!id.is_nil());
    }

    #[test]
    fn span_id_display_is_stable() {
        let id = SymbolSpanId::new(0x1234_5678_9abc_def0);
        assert_eq!(format!("{id}"), "9abcdef0");
    }
}
