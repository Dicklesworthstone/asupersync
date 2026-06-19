//! RFC 6330 §5.3.5.3 structural-invariant sweep for the LT/PI tuple
//! index expansion (`tuple_indices`).
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! The existing conformance suite pins `tuple_indices` against a small
//! set of fixed golden vectors (`golden_rfc6330_lt_tuples`). Those catch
//! transcription drift on specific (J,W,P,X) points but do NOT assert the
//! universal structural guarantees the RFC mandates for *every* valid
//! parameter set and ESI. This file closes that gap with a broad sweep
//! over real RFC-table parameters (`SystematicParams::for_source_block`)
//! crossed with a range of encoding symbol IDs, asserting the invariants
//! that the encoder/decoder parity code depends on:
//!
//!   1. Total index count == d + d1 (one entry per tuple degree unit).
//!   2. LT-side indices (the first d) lie in `[0, W)`.
//!   3. PI-side indices (the last d1) lie in `[W, W+P)`.
//!   4. PI-side indices are pairwise distinct. RFC §5.3.5.3 walks the PI
//!      symbols with step `a1 ∈ [1, P1)` over the prime modulus `P1`,
//!      rejecting residues `>= P`. Because `P1` is prime and `a1` is a
//!      generator, the orbit visits each residue once per cycle, so the
//!      first `d1 <= P` accepted residues are distinct.
//!   5. Determinism: identical inputs yield byte-identical index vectors.
//!
//! Repro: `cargo test --test raptorq_tuple_indices_rfc_invariants`

use asupersync::raptorq::rfc6330::{LtTuple, next_prime_ge, tuple, tuple_indices};
use asupersync::raptorq::systematic::SystematicParams;

/// Representative source-block sizes spanning the RFC systematic index
/// table: degenerate-small, the K=100 region exercised by the golden
/// vectors, and progressively larger blocks up to a healthy K.
const K_SWEEP: &[usize] = &[
    1, 2, 4, 8, 10, 26, 42, 50, 100, 101, 200, 500, 1000, 2048, 10000,
];

#[test]
fn tuple_indices_structural_invariants_sweep() {
    let mut checked_points: u64 = 0;
    let mut nonempty_points: u64 = 0;

    for &k in K_SWEEP {
        let params = SystematicParams::for_source_block(k, 64);
        let w = params.w;
        let p = params.p;
        let j = params.j;
        let p1 = next_prime_ge(p).unwrap_or(0);
        assert_ne!(p1, 0, "K={k}: next_prime_ge(P={p}) must fit in usize");

        // Sweep source ESIs (0..K') and a band of repair ESIs beyond K'.
        let esi_max = (params.k_prime as u32).saturating_add(128);
        for esi in 0..esi_max {
            let t = tuple(j, w, p, p1, esi);
            let idx = tuple_indices(t, w, p, p1);
            checked_points += 1;

            // Valid RFC params (W>2, P>0, P1 prime) always yield a
            // non-empty schedule; an empty result would mean the
            // fail-closed validity gate rejected a parameter set that
            // the systematic table itself produced — a contradiction.
            assert!(
                !idx.is_empty(),
                "K={k} ESI={esi} W={w} P={p} P1={p1}: tuple_indices returned \
                 empty for RFC-table-derived parameters (tuple={t:?}); \
                 repro='cargo test --test raptorq_tuple_indices_rfc_invariants'"
            );
            nonempty_points += 1;

            let ctx = format!(
                "K={k} ESI={esi} W={w} P={p} P1={p1} tuple={t:?} indices={idx:?} \
                 repro='cargo test --test raptorq_tuple_indices_rfc_invariants'"
            );

            // Invariant 1: count == d + d1.
            assert_eq!(idx.len(), t.d + t.d1, "{ctx}: index count != d + d1");

            // Invariant 2: LT-side indices in [0, W).
            for &lt in &idx[..t.d] {
                assert!(lt < w, "{ctx}: LT index {lt} >= W={w}");
            }

            // Invariant 3: PI-side indices in [W, W+P).
            let pi = &idx[t.d..];
            for &pidx in pi {
                assert!(
                    pidx >= w && pidx < w + p,
                    "{ctx}: PI index {pidx} outside [W, W+P)=[{w}, {})",
                    w + p
                );
            }

            // Invariant 4: PI-side indices pairwise distinct. Holds
            // whenever the number of acceptable residues (P) is at
            // least the PI degree d1 (always true for real params,
            // d1 ∈ {2,3}).
            if p >= t.d1 {
                for a in 0..pi.len() {
                    for b in (a + 1)..pi.len() {
                        assert_ne!(pi[a], pi[b], "{ctx}: PI indices not distinct at {a},{b}");
                    }
                }
            }

            // Invariant 5: determinism.
            let idx2 = tuple_indices(t, w, p, p1);
            assert_eq!(idx, idx2, "{ctx}: tuple_indices not deterministic");
        }
    }

    // Guard against a vacuous pass (e.g. if every point silently
    // short-circuited): the sweep must have exercised real schedules.
    assert!(
        nonempty_points == checked_points && checked_points > 10_000,
        "sweep was too small or produced empty schedules: \
         checked={checked_points} nonempty={nonempty_points}"
    );
}

#[test]
fn tuple_indices_fail_closed_for_malformed_tuple_inputs() {
    fn valid_tuple() -> LtTuple {
        LtTuple {
            d: 3,
            a: 5,
            b: 7,
            d1: 2,
            a1: 3,
            b1: 11,
        }
    }

    let w = 113;
    let p = 15;
    let p1 = next_prime_ge(p).unwrap_or(0);
    assert_ne!(p1, 0, "valid PI count must have a prime modulus");

    assert!(
        !tuple_indices(valid_tuple(), w, p, p1).is_empty(),
        "control tuple must be valid before fail-closed mutations are tested"
    );

    let malformed_cases: &[(&str, LtTuple, usize, usize, usize)] = &[
        ("sentinel zero tuple", LtTuple::default(), w, p, p1),
        ("W <= 2", valid_tuple(), 2, p, p1),
        ("P == 0", valid_tuple(), w, 0, p1),
        ("P1 below P", valid_tuple(), w, p, p - 1),
        ("composite P1", valid_tuple(), w, p, p + 1),
        (
            "zero LT degree",
            LtTuple {
                d: 0,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "oversized LT degree",
            LtTuple {
                d: 31,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "invalid PI degree",
            LtTuple {
                d1: 1,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "zero LT step",
            LtTuple {
                a: 0,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "LT step outside W",
            LtTuple {
                a: w,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "LT start outside W",
            LtTuple {
                b: w,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "zero PI step",
            LtTuple {
                a1: 0,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "PI step outside P1",
            LtTuple {
                a1: p1,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
        (
            "PI start outside P1",
            LtTuple {
                b1: p1,
                ..valid_tuple()
            },
            w,
            p,
            p1,
        ),
    ];

    for &(label, lt_tuple, lt_width, pi_count, pi_modulus) in malformed_cases {
        assert!(
            tuple_indices(lt_tuple, lt_width, pi_count, pi_modulus).is_empty(),
            "{label}: tuple_indices must fail closed to an empty schedule, not \
             panic or produce bogus indices; tuple={lt_tuple:?} W={lt_width} \
             P={pi_count} P1={pi_modulus}"
        );
    }
}
