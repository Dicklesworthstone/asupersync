//! RFC 6330 §5.3.5.4 — `tuple_with_prime_p1` derivation-and-parity proof.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC2 (RFC-aligned parameter derivation) +
//! AC3 (metamorphic / property checks). `tuple_with_prime_p1(J, W, P, X)`
//! is the public convenience entry point that derives the RFC's
//! `P1 = smallest_prime_ge(P)` for the caller and then delegates to
//! `try_tuple(J, W, P, P1, X)`. Before this slice it had ZERO direct test
//! coverage, so nothing pinned that the derivation matches the canonical
//! fail-closed path or the repair-index expansion path.
//!
//! This harness pins four contracts using only the public API.
//!
//! Contract 1: WRAPPER EQUIVALENCE. For every (J, W, P, X),
//! `tuple_with_prime_p1(J,W,P,X)` equals
//! `next_prime_ge(P).and_then(|p1| try_tuple(J,W,P,p1,X))`; the wrapper is
//! byte-identical to computing the prime yourself and calling `try_tuple`, with
//! no argument-order or constant drift.
//!
//! Contract 2: COMPOSITE-P FIX-UP (metamorphic). When P is composite, calling
//! `try_tuple(J,W,P,P,X)` with P itself as the modulus is rejected
//! (P != smallest_prime_ge(P)), yet `tuple_with_prime_p1` SUCCEEDS by
//! substituting the corrected prime P1. This is the wrapper's reason to exist;
//! we prove the corrected output equals `try_tuple` driven with the prime.
//!
//! Contract 3: CROSS-FUNCTION PARITY. `repair_indices_for_esi(J,W,P,X)` expands
//! exactly the tuple that `tuple_with_prime_p1` produces, matching
//! `tuple_with_prime_p1(J,W,P,X).map(|t| tuple_indices(t, W, P,
//! smallest_prime_ge(P))).unwrap_or_default()`.
//!
//! Contract 4: FAIL-CLOSED. W <= 2 and P == 0 both yield `None` regardless of
//! the other inputs, and the wrapper is deterministic.
//!
//! Repro: `cargo test --test raptorq_tuple_with_prime_p1_equivalence`

use asupersync::raptorq::rfc6330::{
    next_prime_ge, repair_indices_for_esi, try_tuple, tuple_indices, tuple_with_prime_p1,
};

/// Independent primality check (does NOT share code with the production
/// `next_prime_ge` internals) so the P1 invariants are verified against a
/// re-derived oracle rather than the implementation under test.
fn ref_is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    let mut d = 3usize;
    while d * d <= n {
        if n % d == 0 {
            return false;
        }
        d += 2;
    }
    true
}

/// Re-derived smallest-prime-ge oracle, independent of production.
fn ref_next_prime_ge(n: usize) -> usize {
    let mut c = n.max(2);
    while !ref_is_prime(c) {
        c += 1;
    }
    c
}

const SYSTEMATIC_INDICES: &[usize] = &[0, 1, 5, 47, 100, 477];
const LT_WIDTHS: &[usize] = &[0, 1, 2, 3, 4, 7, 16, 50, 100];
const PI_COUNTS: &[usize] = &[0, 1, 2, 4, 5, 8, 9, 10, 11, 15, 25, 59];
const ESIS: &[u32] = &[0, 1, 7, 42, 1000, 65_535];

/// Contract 1: the wrapper is byte-identical to deriving the prime and
/// calling `try_tuple` directly — across the full input sweep.
#[test]
fn wrapper_equals_explicit_prime_try_tuple() {
    let mut checked = 0usize;
    for &j in SYSTEMATIC_INDICES {
        for &w in LT_WIDTHS {
            for &p in PI_COUNTS {
                for &x in ESIS {
                    let got = tuple_with_prime_p1(j, w, p, x);
                    let expected = next_prime_ge(p).and_then(|p1| try_tuple(j, w, p, p1, x));
                    assert_eq!(
                        got, expected,
                        "wrapper diverged from explicit-prime try_tuple at \
                         J={j} W={w} P={p} X={x}: got {got:?} expected {expected:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    // Guard the sweep didn't silently shrink to nothing.
    assert_eq!(
        checked,
        SYSTEMATIC_INDICES.len() * LT_WIDTHS.len() * PI_COUNTS.len() * ESIS.len()
    );
}

/// Contract 1b: determinism — repeated calls return identical output.
#[test]
fn wrapper_is_deterministic() {
    for &j in SYSTEMATIC_INDICES {
        for &w in LT_WIDTHS {
            for &p in PI_COUNTS {
                for &x in ESIS {
                    let a = tuple_with_prime_p1(j, w, p, x);
                    let b = tuple_with_prime_p1(j, w, p, x);
                    assert_eq!(a, b, "non-deterministic at J={j} W={w} P={p} X={x}");
                }
            }
        }
    }
}

/// Contract 2: for COMPOSITE P, passing P itself as the modulus to
/// `try_tuple` is rejected, but `tuple_with_prime_p1` succeeds via the
/// corrected prime P1 = smallest_prime_ge(P), and the corrected result
/// equals `try_tuple` driven with that prime.
#[test]
fn composite_p_is_corrected_to_prime() {
    // Composite values (each strictly between primes) with a valid W.
    let composites = [4usize, 6, 8, 9, 10, 14, 15, 21, 25, 49];
    let w = 16usize; // W > 2 so the LT gate passes
    let mut proved_fixup = 0usize;
    for &p in &composites {
        assert!(!ref_is_prime(p), "test bug: {p} is not composite");
        let p1 = ref_next_prime_ge(p);
        assert!(p1 > p, "smallest_prime_ge of composite {p} must exceed it");
        assert_eq!(
            next_prime_ge(p),
            Some(p1),
            "production prime derivation mismatch"
        );

        for &j in SYSTEMATIC_INDICES {
            for &x in ESIS {
                // Raw call with the composite as its own modulus: rejected,
                // because P != smallest_prime_ge(P).
                assert_eq!(
                    try_tuple(j, w, p, p, x),
                    None,
                    "composite modulus P={p} must be rejected by try_tuple \
                     (J={j} X={x})"
                );
                // Wrapper substitutes the prime and succeeds.
                let wrapped = tuple_with_prime_p1(j, w, p, x);
                assert!(
                    wrapped.is_some(),
                    "wrapper must succeed for composite P={p} with valid W \
                     (J={j} X={x})"
                );
                assert_eq!(
                    wrapped,
                    try_tuple(j, w, p, p1, x),
                    "corrected tuple must equal try_tuple with P1={p1} \
                     (J={j} P={p} X={x})"
                );
                proved_fixup += 1;
            }
        }
    }
    assert!(proved_fixup > 0, "fix-up sweep was empty");
}

/// Contract 3: `repair_indices_for_esi` expands exactly the tuple the
/// wrapper produces — the two public paths agree on tuple selection.
#[test]
fn repair_indices_match_wrapper_tuple_expansion() {
    for &j in SYSTEMATIC_INDICES {
        for &w in LT_WIDTHS {
            for &p in PI_COUNTS {
                for &x in ESIS {
                    let got = repair_indices_for_esi(j, w, p, x);
                    let expected = match (next_prime_ge(p), tuple_with_prime_p1(j, w, p, x)) {
                        (Some(p1), Some(t)) => tuple_indices(t, w, p, p1),
                        _ => Vec::new(),
                    };
                    assert_eq!(
                        got, expected,
                        "repair_indices diverged from wrapper tuple expansion at \
                         J={j} W={w} P={p} X={x}"
                    );
                }
            }
        }
    }
}

/// Contract 4: fail-closed gates. W <= 2 and P == 0 both yield `None`.
#[test]
fn fail_closed_on_invalid_width_or_zero_p() {
    for &w in &[0usize, 1, 2] {
        for &p in PI_COUNTS {
            for &j in SYSTEMATIC_INDICES {
                for &x in ESIS {
                    assert_eq!(
                        tuple_with_prime_p1(j, w, p, x),
                        None,
                        "W={w} (<=2) must fail closed at J={j} P={p} X={x}"
                    );
                }
            }
        }
    }
    // P == 0: next_prime_ge(0) = 2, but try_tuple rejects pi_count == 0.
    for &w in &[3usize, 16, 100] {
        for &j in SYSTEMATIC_INDICES {
            for &x in ESIS {
                assert_eq!(
                    tuple_with_prime_p1(j, w, 0, x),
                    None,
                    "P=0 must fail closed at J={j} W={w} X={x}"
                );
            }
        }
    }
}

/// Contract 2b: when the wrapper returns `Some`, the modulus it derived is
/// a genuine prime >= max(P, 2) — proven against the independent oracle by
/// checking the wrapper's success domain matches `try_tuple` at that prime.
#[test]
fn derived_modulus_is_prime_and_ge_p() {
    for &p in PI_COUNTS {
        let p1 = ref_next_prime_ge(p);
        assert!(ref_is_prime(p1), "oracle prime {p1} not prime");
        assert!(p1 >= p.max(2), "P1={p1} must be >= max(P={p}, 2)");
        assert_eq!(next_prime_ge(p), Some(p1), "production != oracle for P={p}");

        // Wherever the wrapper is Some, it must coincide with try_tuple at
        // exactly this prime modulus (and nowhere else differ).
        for &j in SYSTEMATIC_INDICES {
            for &w in LT_WIDTHS {
                for &x in ESIS {
                    let wrapped = tuple_with_prime_p1(j, w, p, x);
                    assert_eq!(
                        wrapped,
                        try_tuple(j, w, p, p1, x),
                        "wrapper must track try_tuple at prime P1={p1} \
                         (J={j} W={w} P={p} X={x})"
                    );
                }
            }
        }
    }
}
