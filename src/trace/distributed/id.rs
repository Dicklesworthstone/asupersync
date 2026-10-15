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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn trace_id_w3c_roundtrip() {
        let id = DistTraceId::new(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210);
        let w3c = id.to_w3c_string();
        let parsed = DistTraceId::from_w3c_string(&w3c).expect("parse should succeed");
        assert_eq!(id, parsed);
    }

    #[test]
    fn trace_id_nil_detection() {
        let id = DistTraceId::NIL;
        assert!(id.is_nil());
        let id = DistTraceId::new(1, 0);
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
            let id = DistTraceId::from_u128(v);
            assert_eq!(id.as_u128(), v, "u128 roundtrip failed for {v:#x}");
        }
    }

    #[test]
    fn trace_id_high_low_consistent_with_u128() {
        let high = 0xAABB_CCDD_EEFF_0011u64;
        let low = 0x2233_4455_6677_8899u64;
        let id = DistTraceId::new(high, low);
        assert_eq!(id.high(), high);
        assert_eq!(id.low(), low);
        let expected_u128 = (u128::from(high) << 64) | u128::from(low);
        assert_eq!(id.as_u128(), expected_u128);
        assert_eq!(DistTraceId::from_u128(expected_u128), id);
    }

    #[test]
    fn trace_id_deterministic_generation_with_fixed_seed() {
        let mut rng_a = DetRng::new(999);
        let mut rng_b = DetRng::new(999);
        let id_a = DistTraceId::new_random(&mut rng_a);
        let id_b = DistTraceId::new_random(&mut rng_b);
        assert_eq!(id_a, id_b, "same seed must produce same DistTraceId");
    }

    #[test]
    fn trace_id_different_seeds_produce_different_ids() {
        let mut rng_a = DetRng::new(1);
        let mut rng_b = DetRng::new(2);
        let id_a = DistTraceId::new_random(&mut rng_a);
        let id_b = DistTraceId::new_random(&mut rng_b);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn trace_id_w3c_invalid_length_returns_none() {
        assert!(DistTraceId::from_w3c_string("").is_none());
        assert!(DistTraceId::from_w3c_string("0123456789abcdef").is_none()); // 16 chars
        assert!(DistTraceId::from_w3c_string("0123456789abcdef0123456789abcdef0").is_none());
        // 33 chars
    }

    #[test]
    fn trace_id_w3c_invalid_hex_returns_none() {
        assert!(DistTraceId::from_w3c_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn trace_id_nil_is_zero() {
        let nil = DistTraceId::NIL;
        assert_eq!(nil.high(), 0);
        assert_eq!(nil.low(), 0);
        assert_eq!(nil.as_u128(), 0);
        assert!(nil.is_nil());
    }

    #[test]
    fn trace_id_new_for_test_has_zero_high() {
        let id = DistTraceId::new_for_test(42);
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
        let id = DistTraceId::new(u64::MAX, u64::MAX);
        let w3c = id.to_w3c_string();
        assert_eq!(w3c, "ffffffffffffffffffffffffffffffff");
        let parsed = DistTraceId::from_w3c_string(&w3c).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn trace_id_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = DistTraceId::new(1, 2);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, DistTraceId::new(3, 4));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn symbol_span_id_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = SymbolSpanId::new(42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, SymbolSpanId::new(99));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    // ------------------------------------------------------------------------
    // Golden-artifact: canonical DistTraceId / SymbolSpanId serialization snapshot.
    //
    // Three serialization forms exist per id, and two of them are
    // intentionally lossy (they're meant for human-readable log lines, not
    // round-trip). Freeze all of them so a change to any surface surfaces
    // as a reviewable diff:
    //
    //   DistTraceId:
    //     to_w3c_string()  — 32 hex chars (canonical, lossless, round-trips)
    //     Display          — 16 hex chars (HIGH ONLY, lossy by design)
    //     Debug            — "DistTraceId(<32 hex>)"
    //
    //   SymbolSpanId:
    //     Display          — 8 hex chars (LOW 32 bits of u64, lossy by design)
    //     Debug            — "SymbolSpanId(<16 hex>)"
    //
    // Canonical values picked to stress-test the boundaries:
    //   - NIL (all zero)
    //   - max (all ones)
    //   - a fixed asymmetric pattern (differentiates high vs low)
    //   - high-only (low == 0)   — locks in Display-is-high for DistTraceId
    //   - low-only  (high == 0)  — locks in Display-drops-low for DistTraceId
    //
    // Plus the from_w3c_string error surface: four distinct rejection paths
    // (empty, 16-char, 33-char, non-hex) locked to ensure none of them
    // accidentally starts succeeding.
    // ------------------------------------------------------------------------
    #[test]
    fn canonical_trace_id_serialization_snapshot() {
        fn trace_row(label: &str, id: DistTraceId) -> serde_json::Value {
            let w3c = id.to_w3c_string();
            let roundtrip = DistTraceId::from_w3c_string(&w3c).is_some_and(|p| p == id);
            serde_json::json!({
                "label":       label,
                "high":        format!("{:#018x}", id.high()),
                "low":         format!("{:#018x}", id.low()),
                "as_u128":     format!("{:#034x}", id.as_u128()),
                "is_nil":      id.is_nil(),
                "to_w3c":      w3c,
                "display":     format!("{id}"),
                "debug":       format!("{id:?}"),
                "w3c_roundtrip_ok": roundtrip,
            })
        }

        fn span_row(label: &str, id: SymbolSpanId) -> serde_json::Value {
            serde_json::json!({
                "label":   label,
                "as_u64":  format!("{:#018x}", id.as_u64()),
                "display": format!("{id}"),
                "debug":   format!("{id:?}"),
            })
        }

        let trace_ids = vec![
            trace_row("nil", DistTraceId::NIL),
            trace_row("max", DistTraceId::new(u64::MAX, u64::MAX)),
            trace_row(
                "asymmetric_pattern",
                DistTraceId::new(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210),
            ),
            trace_row("high_only", DistTraceId::new(0xAAAA_AAAA_AAAA_AAAA, 0)),
            trace_row("low_only", DistTraceId::new(0, 0xBBBB_BBBB_BBBB_BBBB)),
            trace_row("new_for_test_42", DistTraceId::new_for_test(42)),
            trace_row(
                "u128_constant",
                DistTraceId::from_u128(0x0001_0002_0003_0004_0005_0006_0007_0008),
            ),
        ];

        let span_ids = vec![
            span_row("nil", SymbolSpanId::NIL),
            span_row("max", SymbolSpanId::new(u64::MAX)),
            span_row("dead_beef", SymbolSpanId::new(0xDEAD_BEEF_CAFE_BABE)),
            span_row("classic_pattern", SymbolSpanId::new(0x1234_5678_9abc_def0)),
            span_row("new_for_test_42", SymbolSpanId::new_for_test(42)),
            // Low-32 bits all zero — locks in that Display renders "00000000"
            // rather than stripping leading zeros or rendering the high word.
            span_row("high_only", SymbolSpanId::new(0xFFFF_FFFF_0000_0000)),
        ];

        // Error-surface: four distinct from_w3c_string rejection paths. Each
        // case MUST return None. Empty string, length-16, length-33, non-hex.
        let w3c_rejects = vec![
            serde_json::json!({
                "input_label": "empty",
                "input_len":   0,
                "rejected":    DistTraceId::from_w3c_string("").is_none(),
            }),
            serde_json::json!({
                "input_label": "len_16",
                "input_len":   16,
                "rejected":    DistTraceId::from_w3c_string("0123456789abcdef").is_none(),
            }),
            serde_json::json!({
                "input_label": "len_33",
                "input_len":   33,
                "rejected":    DistTraceId::from_w3c_string("0123456789abcdef0123456789abcdef0").is_none(),
            }),
            serde_json::json!({
                "input_label": "non_hex_len_32",
                "input_len":   32,
                "rejected":    DistTraceId::from_w3c_string("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none(),
            }),
        ];

        insta::assert_json_snapshot!(
            "canonical_trace_id_serialization",
            serde_json::json!({
                "trace_ids":       trace_ids,
                "span_ids":        span_ids,
                "w3c_reject_cases": w3c_rejects,
            })
        );
    }
}
