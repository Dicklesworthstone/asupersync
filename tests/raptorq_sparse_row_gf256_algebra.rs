//! RaptorQ linalg: SparseRow ↔ DenseRow GF(256) algebra conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the GF(256) sparse-row primitives in
//! `raptorq::linalg` that had ZERO integration coverage:
//! `DenseRow::{to_sparse, first_nonzero, first_nonzero_from}` and
//! `SparseRow::{to_dense, scale, add, scale_add, scale_add_assign,
//! nonzero_count, first_nonzero}`.
//!
//! The strategy is differential + metamorphic: the sparse algebra is an
//! independent code path from the dense slice kernel (`row_scale_add`), so
//! cross-checking them pins both. Every test is pure and deterministic (no
//! runtime, no RNG entropy — a seeded LCG drives inputs).
//!
//! Repro: `cargo test -p asupersync --test raptorq_sparse_row_gf256_algebra`

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{row_scale_add, DenseRow, SparseRow};

/// Deterministic LCG (Knuth MMIX constants) for reproducible row generation.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// Builds a pseudo-random dense row of `len` bytes. `density` is the per-byte
/// probability (out of 256) that a position is *selected* to carry a value; the
/// value itself may still land on zero, exercising both populated and empty
/// slots so `to_sparse` filtering is covered.
fn random_dense(len: usize, seed: u64, density: u8) -> DenseRow {
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    let data: Vec<u8> = (0..len)
        .map(|_| {
            let r = lcg(&mut s);
            if (r & 0xFF) < u64::from(density) {
                (r >> 23) as u8
            } else {
                0
            }
        })
        .collect();
    DenseRow::new(data)
}

/// Reference scale-add over dense slices using the (heavily tested) GF(256)
/// slice kernel. Returns `a + c * b`.
fn dense_scale_add_ref(a: &[u8], b: &[u8], c: Gf256) -> Vec<u8> {
    let mut dst = a.to_vec();
    row_scale_add(&mut dst, b, c);
    dst
}

const LENS: [usize; 6] = [0, 1, 7, 16, 33, 129];
const DENSITIES: [u8; 4] = [8, 64, 160, 255];

/// DenseRow → SparseRow → DenseRow is the identity (round-trip preserves every
/// byte, and the sparse form drops exactly the zero positions).
#[test]
fn dense_sparse_round_trip_is_identity() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for seed in 0..16u64 {
                let dense = random_dense(len, seed, density);
                let sparse = dense.to_sparse();

                // Round-trip identity.
                let back = sparse.to_dense();
                assert_eq!(
                    back.as_slice(),
                    dense.as_slice(),
                    "round-trip mismatch len={len} density={density} seed={seed}"
                );

                // Nonzero accounting agrees across representations.
                assert_eq!(
                    sparse.nonzero_count(),
                    dense.as_slice().iter().filter(|&&b| b != 0).count(),
                    "nonzero_count mismatch len={len} density={density} seed={seed}"
                );
                assert_eq!(sparse.len(), len, "length not preserved");

                // first_nonzero agrees across representations.
                assert_eq!(
                    sparse.first_nonzero(),
                    dense.first_nonzero(),
                    "first_nonzero mismatch len={len} density={density} seed={seed}"
                );
            }
        }
    }
}

/// `DenseRow::first_nonzero_from` finds the first nonzero at or after `start`,
/// is consistent with `first_nonzero` at start=0, and returns `None` for any
/// out-of-range start.
#[test]
fn dense_first_nonzero_from_semantics() {
    for &len in &LENS {
        for seed in 0..24u64 {
            let dense = random_dense(len, seed, 96);
            assert_eq!(
                dense.first_nonzero_from(0),
                dense.first_nonzero(),
                "first_nonzero_from(0) must equal first_nonzero"
            );

            for start in 0..=len {
                let got = dense.first_nonzero_from(start);
                let expected = dense.as_slice()[start.min(len)..]
                    .iter()
                    .position(|&b| b != 0)
                    .map(|i| start + i);
                assert_eq!(
                    got, expected,
                    "first_nonzero_from({start}) wrong len={len} seed={seed}"
                );
                // Result, when present, is at or after start and is nonzero.
                if let Some(idx) = got {
                    assert!(idx >= start);
                    assert_ne!(dense.as_slice()[idx], 0);
                }
            }

            // Any start past the end yields None.
            assert_eq!(dense.first_nonzero_from(len + 1), None);
            assert_eq!(dense.first_nonzero_from(usize::MAX), None);
        }
    }
}

/// `SparseRow::scale_add(b, c)` equals `self.add(&b.scale(c))` — the contract
/// the fused method claims to compute, verified against the unfused path.
#[test]
fn scale_add_matches_scale_then_add() {
    for &len in &LENS {
        if len == 0 {
            continue;
        }
        for &density in &DENSITIES {
            for seed in 0..12u64 {
                let a = random_dense(len, seed, density).to_sparse();
                let b = random_dense(len, seed ^ 0xDEAD, density).to_sparse();
                for raw_c in [0u8, 1, 2, 5, 0x80, 0xFF] {
                    let c = Gf256::new(raw_c);
                    let fused = a.scale_add(&b, c);
                    let unfused = a.add(&b.scale(c));
                    assert_eq!(
                        fused, unfused,
                        "scale_add != add(scale) len={len} c={raw_c} seed={seed}"
                    );
                }
            }
        }
    }
}

/// In-place `scale_add_assign` is byte-identical to the functional `scale_add`
/// (the central metamorphic relation for the fused merge), and reduces to the
/// documented edge cases: c=0 is the identity, c=1 equals plain `add`.
#[test]
fn scale_add_assign_matches_functional_and_edge_cases() {
    for &len in &LENS {
        if len == 0 {
            continue;
        }
        for &density in &DENSITIES {
            for seed in 0..12u64 {
                let a = random_dense(len, seed, density).to_sparse();
                let b = random_dense(len, seed.wrapping_add(7), density).to_sparse();

                for raw_c in [0u8, 1, 3, 0x40, 0xAB, 0xFF] {
                    let c = Gf256::new(raw_c);
                    let mut in_place = a.clone();
                    in_place.scale_add_assign(&b, c);
                    assert_eq!(
                        in_place,
                        a.scale_add(&b, c),
                        "assign != functional len={len} c={raw_c} seed={seed}"
                    );
                }

                // c = 0 → identity.
                let mut z = a.clone();
                z.scale_add_assign(&b, Gf256::ZERO);
                assert_eq!(z, a, "scale_add_assign by 0 must be identity");

                // c = 1 → plain XOR add.
                let mut one = a.clone();
                one.scale_add_assign(&b, Gf256::ONE);
                assert_eq!(one, a.add(&b), "scale_add_assign by 1 must equal add");
            }
        }
    }
}

/// The sparse scale-add path agrees byte-for-byte with the dense slice kernel
/// (`row_scale_add`). This is the strong differential: two independent
/// implementations of `a + c*b` must coincide.
#[test]
fn sparse_scale_add_matches_dense_kernel() {
    for &len in &LENS {
        if len == 0 {
            continue;
        }
        for &density in &DENSITIES {
            for seed in 0..12u64 {
                let a_dense = random_dense(len, seed, density);
                let b_dense = random_dense(len, seed ^ 0x1234_5678, density);
                let a = a_dense.to_sparse();
                let b = b_dense.to_sparse();

                for raw_c in [0u8, 1, 2, 7, 0x55, 0xFE, 0xFF] {
                    let c = Gf256::new(raw_c);
                    let sparse_result = a.scale_add(&b, c).to_dense();
                    let dense_result =
                        dense_scale_add_ref(a_dense.as_slice(), b_dense.as_slice(), c);
                    assert_eq!(
                        sparse_result.as_slice(),
                        dense_result.as_slice(),
                        "sparse vs dense kernel mismatch len={len} c={raw_c} seed={seed}"
                    );
                }
            }
        }
    }
}

/// `scale` is multiplicative: `(a.scale(c)).scale(d) == a.scale(c*d)`, and the
/// degenerate scalars collapse as documented (0 → zeros, 1 → clone).
#[test]
fn scale_is_multiplicative_with_degenerate_scalars() {
    for &len in &LENS {
        if len == 0 {
            continue;
        }
        for seed in 0..16u64 {
            let a = random_dense(len, seed, 128).to_sparse();

            for raw_c in [2u8, 3, 0x10, 0x9D, 0xFF] {
                for raw_d in [2u8, 5, 0x20, 0xC3, 0xFF] {
                    let c = Gf256::new(raw_c);
                    let d = Gf256::new(raw_d);
                    assert_eq!(
                        a.scale(c).scale(d),
                        a.scale(c * d),
                        "scale not multiplicative c={raw_c} d={raw_d} seed={seed}"
                    );
                }
            }

            // Degenerate scalars.
            let zeroed = a.scale(Gf256::ZERO);
            assert!(zeroed.is_zero(), "scale by 0 must produce the zero row");
            assert_eq!(zeroed.len(), len, "scale by 0 must preserve length");
            assert_eq!(a.scale(Gf256::ONE), a, "scale by 1 must be the identity");
        }
    }
}

/// `add` is commutative and self-inverse over GF(256): `a + b == b + a`, and
/// `a + a` is the zero row (characteristic 2).
#[test]
fn add_is_commutative_and_self_inverse() {
    for &len in &LENS {
        for seed in 0..16u64 {
            let a = random_dense(len, seed, 144).to_sparse();
            let b = random_dense(len, seed ^ 0xABCD, 144).to_sparse();

            assert_eq!(a.add(&b), b.add(&a), "add not commutative len={len} seed={seed}");

            let self_sum = a.add(&a);
            assert!(
                self_sum.is_zero(),
                "a + a must be zero over GF(2^8) len={len} seed={seed}"
            );
            assert_eq!(self_sum.len(), len, "add must preserve length");
        }
    }
}
