//! Property tests for distributed trace identifiers.
//!
//! Verifies TraceId and SymbolSpanId round-trip encoding, W3C format compliance,
//! nil detection, deterministic generation, and algebraic properties.

mod common;

use asupersync::trace::distributed::id::{SymbolSpanId, TraceId};
use asupersync::util::DetRng;
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;

// ============================================================================
// Arbitrary Generators
// ============================================================================

fn arb_trace_id() -> impl Strategy<Value = TraceId> {
    (any::<u64>(), any::<u64>()).prop_map(|(h, l)| TraceId::new(h, l))
}

fn arb_u128() -> impl Strategy<Value = u128> {
    any::<u128>()
}

fn arb_span_id() -> impl Strategy<Value = SymbolSpanId> {
    any::<u64>().prop_map(SymbolSpanId::new)
}

fn arb_seed() -> impl Strategy<Value = u64> {
    any::<u64>()
}

// ============================================================================
// TraceId u128 Round-Trip
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// from_u128(as_u128(id)) == id for all TraceId values.
    #[test]
    fn trace_id_u128_roundtrip_from_parts(high in any::<u64>(), low in any::<u64>()) {
        init_test_logging();
        let id = TraceId::new(high, low);
        let reconstructed = TraceId::from_u128(id.as_u128());
        prop_assert_eq!(reconstructed.high(), id.high());
        prop_assert_eq!(reconstructed.low(), id.low());
    }

    /// as_u128(from_u128(v)) == v for all u128 values.
    #[test]
    fn trace_id_u128_roundtrip_from_value(v in arb_u128()) {
        init_test_logging();
        let id = TraceId::from_u128(v);
        prop_assert_eq!(id.as_u128(), v);
    }

    /// high/low decomposition is consistent with u128 encoding.
    #[test]
    fn trace_id_high_low_consistent(id in arb_trace_id()) {
        init_test_logging();
        let expected = (u128::from(id.high()) << 64) | u128::from(id.low());
        prop_assert_eq!(id.as_u128(), expected);
    }
}

// ============================================================================
// W3C String Format
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// W3C string round-trip: from_w3c_string(to_w3c_string(id)) == Some(id).
    #[test]
    fn trace_id_w3c_roundtrip(id in arb_trace_id()) {
        init_test_logging();
        let w3c = id.to_w3c_string();
        let parsed = TraceId::from_w3c_string(&w3c);
        prop_assert!(parsed.is_some(), "W3C string should always parse back");
        let parsed = parsed.unwrap();
        prop_assert_eq!(parsed.high(), id.high());
        prop_assert_eq!(parsed.low(), id.low());
    }

    /// W3C string is exactly 32 lowercase hex characters.
    #[test]
    fn trace_id_w3c_format(id in arb_trace_id()) {
        init_test_logging();
        let w3c = id.to_w3c_string();
        prop_assert_eq!(w3c.len(), 32, "W3C string must be 32 chars, got {}", w3c.len());
        prop_assert!(
            w3c.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "W3C string must be lowercase hex: {w3c}"
        );
    }

    /// Invalid-length strings always return None.
    #[test]
    fn trace_id_w3c_rejects_wrong_length(s in "[0-9a-f]{0,31}|[0-9a-f]{33,64}") {
        init_test_logging();
        prop_assert!(
            TraceId::from_w3c_string(&s).is_none(),
            "Wrong-length string should be rejected: len={}", s.len()
        );
    }
}

// ============================================================================
// Nil Detection
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// is_nil is true iff both high and low are zero.
    #[test]
    fn trace_id_nil_iff_zero(high in any::<u64>(), low in any::<u64>()) {
        init_test_logging();
        let id = TraceId::new(high, low);
        let expected_nil = high == 0 && low == 0;
        prop_assert!(
            id.is_nil() == expected_nil,
            "is_nil should be {} for high={:#x}, low={:#x}", expected_nil, high, low
        );
    }
}

// ============================================================================
// Deterministic RNG Generation
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Same seed always produces the same TraceId.
    #[test]
    fn trace_id_deterministic_same_seed(seed in arb_seed()) {
        init_test_logging();
        let mut rng_a = DetRng::new(seed);
        let mut rng_b = DetRng::new(seed);
        let id_a = TraceId::new_random(&mut rng_a);
        let id_b = TraceId::new_random(&mut rng_b);
        prop_assert_eq!(id_a.as_u128(), id_b.as_u128());
    }

    /// Same seed always produces the same SymbolSpanId.
    #[test]
    fn span_id_deterministic_same_seed(seed in arb_seed()) {
        init_test_logging();
        let mut rng_a = DetRng::new(seed);
        let mut rng_b = DetRng::new(seed);
        let id_a = SymbolSpanId::new_random(&mut rng_a);
        let id_b = SymbolSpanId::new_random(&mut rng_b);
        prop_assert_eq!(id_a.as_u64(), id_b.as_u64());
    }

    /// Different seeds produce different TraceIds (with overwhelming probability).
    #[test]
    fn trace_id_different_seeds(seed1 in 0u64..=u64::MAX / 2, seed2 in (u64::MAX / 2 + 1)..=u64::MAX) {
        init_test_logging();
        let mut rng_a = DetRng::new(seed1);
        let mut rng_b = DetRng::new(seed2);
        let id_a = TraceId::new_random(&mut rng_a);
        let id_b = TraceId::new_random(&mut rng_b);
        // With 128 bits of output, collision probability is negligible
        prop_assert_ne!(
            id_a.as_u128(), id_b.as_u128(),
            "different seeds should produce different IDs"
        );
    }
}

// ============================================================================
// SymbolSpanId Round-Trip
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// SymbolSpanId new/as_u64 round-trip.
    #[test]
    fn span_id_roundtrip(v in any::<u64>()) {
        init_test_logging();
        let id = SymbolSpanId::new(v);
        prop_assert_eq!(id.as_u64(), v);
    }
}

// ============================================================================
// TraceId Equality & Hashing Consistency
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Equal TraceIds produce equal u128 values.
    #[test]
    fn trace_id_eq_consistent_with_u128(h in any::<u64>(), l in any::<u64>()) {
        init_test_logging();
        let a = TraceId::new(h, l);
        let b = TraceId::new(h, l);
        prop_assert_eq!(a, b);
        prop_assert_eq!(a.as_u128(), b.as_u128());
    }

    /// Distinct high/low pairs produce distinct TraceIds.
    #[test]
    fn trace_id_distinct_parts(
        h1 in any::<u64>(), l1 in any::<u64>(),
        h2 in any::<u64>(), l2 in any::<u64>(),
    ) {
        init_test_logging();
        let a = TraceId::new(h1, l1);
        let b = TraceId::new(h2, l2);
        if h1 != h2 || l1 != l2 {
            prop_assert_ne!(a, b);
        } else {
            prop_assert_eq!(a, b);
        }
    }
}
