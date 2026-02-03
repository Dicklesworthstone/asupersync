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

    #[test]
    fn trace_id_u128_roundtrip() {
        let values: [u128; 4] = [0, 1, u128::MAX, 0x0001_0002_0003_0004_0005_0006_0007_0008];
        for v in values {
            let id = TraceId::from_u128(v);
            assert_eq!(id.as_u128(), v, "u128 roundtrip failed for {v:#x}");
        }
    }

    #[test]
    fn trace_id_high_low_consistent_with_u128() {
        let high = 0xAABB_CCDD_EEFF_0011u64;
        let low = 0x2233_4455_6677_8899u64;
        let id = TraceId::new(high, low);
        assert_eq!(id.high(), high);
        assert_eq!(id.low(), low);
        let expected_u128 = ((high as u128) << 64) | (low as u128);
        assert_eq!(id.as_u128(), expected_u128);
        assert_eq!(TraceId::from_u128(expected_u128), id);
    }

    #[test]
    fn trace_id_deterministic_generation_with_fixed_seed() {
        let mut rng_a = DetRng::new(999);
        let mut rng_b = DetRng::new(999);
        let id_a = TraceId::new_random(&mut rng_a);
        let id_b = TraceId::new_random(&mut rng_b);
        assert_eq!(id_a, id_b, "same seed must produce same TraceId");
    }

    #[test]
    fn trace_id_different_seeds_produce_different_ids() {
        let mut rng_a = DetRng::new(1);
        let mut rng_b = DetRng::new(2);
        let id_a = TraceId::new_random(&mut rng_a);
        let id_b = TraceId::new_random(&mut rng_b);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn trace_id_w3c_invalid_length_returns_none() {
        assert!(TraceId::from_w3c_string("").is_none());
        assert!(TraceId::from_w3c_string("0123456789abcdef").is_none()); // 16 chars
        assert!(TraceId::from_w3c_string("0123456789abcdef0123456789abcdef0").is_none());
        // 33 chars
    }

    #[test]
    fn trace_id_w3c_invalid_hex_returns_none() {
        assert!(TraceId::from_w3c_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn trace_id_nil_is_zero() {
        let nil = TraceId::NIL;
        assert_eq!(nil.high(), 0);
        assert_eq!(nil.low(), 0);
        assert_eq!(nil.as_u128(), 0);
        assert!(nil.is_nil());
    }

    #[test]
    fn trace_id_new_for_test_has_zero_high() {
        let id = TraceId::new_for_test(42);
        assert_eq!(id.high(), 0);
        assert_eq!(id.low(), 42);
        assert!(!id.is_nil());
    }

    #[test]
    fn symbol_span_id_roundtrip() {
        let values: [u64; 4] = [0, 1, u64::MAX, 0xDEAD_BEEF_CAFE_BABE];
        for v in values {
            let id = SymbolSpanId::new(v);
            assert_eq!(id.as_u64(), v);
        }
    }

    #[test]
    fn symbol_span_id_deterministic_generation() {
        let mut rng_a = DetRng::new(777);
        let mut rng_b = DetRng::new(777);
        let id_a = SymbolSpanId::new_random(&mut rng_a);
        let id_b = SymbolSpanId::new_random(&mut rng_b);
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn symbol_span_id_nil_is_zero() {
        assert_eq!(SymbolSpanId::NIL.as_u64(), 0);
    }

    #[test]
    fn trace_id_w3c_max_values() {
        let id = TraceId::new(u64::MAX, u64::MAX);
        let w3c = id.to_w3c_string();
        assert_eq!(w3c, "ffffffffffffffffffffffffffffffff");
        let parsed = TraceId::from_w3c_string(&w3c).unwrap();
        assert_eq!(parsed, id);
    }
}
