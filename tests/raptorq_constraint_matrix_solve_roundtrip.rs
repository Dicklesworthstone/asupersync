//! RaptorQ linalg: `ConstraintMatrix::solve` GF(256) Gaussian-elimination
//! round-trip & singularity conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). `ConstraintMatrix::solve` — the min-degree
//! pivoting Gaussian solver over GF(256) that recovers the intermediate symbols
//! (A·C = D) at the heart of RFC 6330 decoding — had ZERO integration coverage
//! (no test anywhere calls `.solve()`).
//!
//! Strategy: differential round-trip against an INDEPENDENT oracle. The forward
//! direction (matrix·vector product `D = A·C` over GF(256) symbols) is computed
//! with the heavily tested `linalg::row_scale_add` kernel — a different code
//! path from solve's elimination engine. For any invertible `A` and chosen
//! solution `C`, `solve(A·C)` MUST equal `C` exactly (Gaussian elimination on a
//! full-rank square system yields the unique solution regardless of pivot order,
//! so the min-degree heuristic must not change the answer). We additionally
//! assert the recovered solution is *consistent* (`A·solution == rhs`) and that
//! provably singular matrices fail closed with `None`.
//!
//! Invertibility is guaranteed by construction:
//!   * identity (degree-1 rows — exercises the min-degree fast path),
//!   * permutation matrices (exercise the row-swap path),
//!   * triangular matrices with nonzero diagonal (det = ∏ diagonal ≠ 0 —
//!     exercise elimination + back-substitution over a dense-ish structure).
//!
//! Every test is pure and deterministic (no runtime, no entropy — a seeded LCG
//! drives inputs).
//!
//! Repro: `cargo test -p asupersync --test raptorq_constraint_matrix_solve_roundtrip`

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::row_scale_add;
use asupersync::raptorq::systematic::ConstraintMatrix;

/// Deterministic LCG (Knuth MMIX constants) for reproducible generation.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// A random byte in `0..=255` (may be zero).
fn rand_byte(s: &mut u64) -> u8 {
    (lcg(s) >> 24) as u8
}

/// A random *nonzero* GF(256) coefficient — used for matrix diagonals so the
/// matrix is invertible by construction.
fn rand_nonzero(s: &mut u64) -> u8 {
    let b = (lcg(s) >> 24) as u8;
    if b == 0 { 1 } else { b }
}

/// `count` random symbols, each `sym` bytes wide.
fn random_symbols(count: usize, sym: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..count)
        .map(|_| (0..sym).map(|_| rand_byte(&mut s)).collect())
        .collect()
}

/// Reference GF(256) matrix·vector product `D = A · C` over symbols, using the
/// independently tested `row_scale_add` kernel. `D[r] = Σ_c A[r][c] · C[c]`.
fn matvec(a: &ConstraintMatrix, c: &[Vec<u8>], sym: usize) -> Vec<Vec<u8>> {
    assert_eq!(c.len(), a.cols);
    (0..a.rows)
        .map(|r| {
            let mut acc = vec![0u8; sym];
            for (col, symbol) in c.iter().enumerate().take(a.cols) {
                let coef = a.get(r, col);
                // row_scale_add is a no-op for coef == 0; call unconditionally.
                row_scale_add(&mut acc, symbol, coef);
            }
            acc
        })
        .collect()
}

const SYMBOL_SIZES: [usize; 4] = [1, 4, 16, 40];
const DIMS: [usize; 5] = [1, 2, 3, 5, 8];

/// Builds an `n×n` identity matrix.
fn identity(n: usize) -> ConstraintMatrix {
    let mut a = ConstraintMatrix::zeros(n, n);
    for i in 0..n {
        a.set(i, i, Gf256::ONE);
    }
    a
}

/// Builds an `n×n` lower-triangular matrix with nonzero diagonal (invertible).
fn lower_triangular(n: usize, seed: u64) -> ConstraintMatrix {
    let mut s = seed ^ 0xD1B5_4A32_D192_ED03;
    let mut a = ConstraintMatrix::zeros(n, n);
    for r in 0..n {
        for c in 0..=r {
            let v = if c == r {
                rand_nonzero(&mut s)
            } else {
                rand_byte(&mut s)
            };
            a.set(r, c, Gf256::new(v));
        }
    }
    a
}

/// Builds an `n×n` upper-triangular matrix with nonzero diagonal (invertible).
fn upper_triangular(n: usize, seed: u64) -> ConstraintMatrix {
    let mut s = seed ^ 0x2545_F491_4F6C_DD1D;
    let mut a = ConstraintMatrix::zeros(n, n);
    for r in 0..n {
        for c in r..n {
            let v = if c == r {
                rand_nonzero(&mut s)
            } else {
                rand_byte(&mut s)
            };
            a.set(r, c, Gf256::new(v));
        }
    }
    a
}

/// Builds an `n×n` permutation matrix from a seeded Fisher–Yates shuffle.
fn permutation(n: usize, seed: u64) -> ConstraintMatrix {
    let mut s = seed ^ 0x8EBC_6AF0_9C88_C6E3;
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (lcg(&mut s) % (i as u64 + 1)) as usize;
        perm.swap(i, j);
    }
    let mut a = ConstraintMatrix::zeros(n, n);
    for (row, &col) in perm.iter().enumerate() {
        a.set(row, col, Gf256::ONE);
    }
    a
}

/// Drives the full round-trip + consistency assertions for a known-invertible
/// matrix across symbol sizes and seeds.
fn assert_invertible_roundtrip(a: &ConstraintMatrix, label: &str) {
    let n = a.cols;
    assert_eq!(a.rows, n, "{label}: helper expects a square matrix");
    for &sym in &SYMBOL_SIZES {
        for cseed in 0..8u64 {
            let c = random_symbols(n, sym, cseed ^ 0xC0FF_EE00);
            let rhs = matvec(a, &c, sym);

            let solved = a.solve(&rhs).unwrap_or_else(|| {
                panic!("{label}: solve returned None for an invertible matrix (n={n}, sym={sym}, seed={cseed})")
            });

            // Exact recovery of the chosen solution.
            assert_eq!(
                solved, c,
                "{label}: solve(A·C) != C (n={n}, sym={sym}, seed={cseed})"
            );

            // Independent consistency: the recovered solution reproduces rhs.
            let check = matvec(a, &solved, sym);
            assert_eq!(
                check, rhs,
                "{label}: A·solution != rhs (n={n}, sym={sym}, seed={cseed})"
            );
        }
    }
}

#[test]
fn identity_solve_recovers_rhs_exactly() {
    for &n in &DIMS {
        assert_invertible_roundtrip(&identity(n), "identity");
    }
}

#[test]
fn permutation_solve_recovers_solution() {
    for &n in &DIMS {
        for seed in 0..6u64 {
            assert_invertible_roundtrip(&permutation(n, seed), "permutation");
        }
    }
}

#[test]
fn lower_triangular_solve_roundtrip() {
    for &n in &DIMS {
        for seed in 0..6u64 {
            assert_invertible_roundtrip(&lower_triangular(n, seed), "lower_triangular");
        }
    }
}

#[test]
fn upper_triangular_solve_roundtrip() {
    for &n in &DIMS {
        for seed in 0..6u64 {
            assert_invertible_roundtrip(&upper_triangular(n, seed), "upper_triangular");
        }
    }
}

/// A hand-built 2×2 system over GF(256) with a verifiable answer, pinning the
/// solver against a fully explicit golden case rather than a generated one.
///
///   A = [[1, 1], [0, 1]]  (unit upper-triangular, its own structure)
///   Choose C = [c0, c1]; then D = [c0 ^ c1, c1].
///   solve(D) must return [c0, c1].
#[test]
fn explicit_2x2_unit_triangular_golden() {
    let mut a = ConstraintMatrix::zeros(2, 2);
    a.set(0, 0, Gf256::ONE);
    a.set(0, 1, Gf256::ONE);
    a.set(1, 1, Gf256::ONE);

    let c0 = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
    let c1 = vec![0x01u8, 0x02, 0x03, 0x04];
    // D[0] = c0 + c1 (XOR, since both coefficients are 1); D[1] = c1.
    let d0: Vec<u8> = c0.iter().zip(&c1).map(|(a, b)| a ^ b).collect();
    let rhs = vec![d0, c1.clone()];

    let solved = a.solve(&rhs).expect("unit upper-triangular is invertible");
    assert_eq!(solved, vec![c0, c1]);
}

// ---------------------------------------------------------------------------
// Singular systems must fail closed with None (no wrong-but-Some answer).
// ---------------------------------------------------------------------------

#[test]
fn zero_row_is_singular() {
    // Identity with one row zeroed → that column never gets a pivot.
    let mut a = identity(4);
    for c in 0..4 {
        a.set(2, c, Gf256::ZERO);
    }
    let rhs = random_symbols(4, 8, 1);
    assert!(
        a.solve(&rhs).is_none(),
        "matrix with an all-zero row must be singular"
    );
}

#[test]
fn zero_column_is_singular() {
    // Identity with one column zeroed → that column has no pivot.
    let mut a = identity(4);
    for r in 0..4 {
        a.set(r, 1, Gf256::ZERO);
    }
    let rhs = random_symbols(4, 8, 2);
    assert!(
        a.solve(&rhs).is_none(),
        "matrix with an all-zero column must be singular"
    );
}

#[test]
fn duplicate_rows_are_singular() {
    // Two identical rows → rank deficient → at least one column lacks a pivot.
    let mut a = identity(3);
    // Make row 1 equal to row 0 (both have a single 1 in column 0).
    a.set(1, 1, Gf256::ZERO);
    a.set(1, 0, Gf256::ONE);
    let rhs = random_symbols(3, 8, 3);
    assert!(
        a.solve(&rhs).is_none(),
        "matrix with duplicate rows must be singular"
    );
}

/// Linear dependence that is not a trivial zero row/col: row 2 = row 0 + row 1.
/// The system is rank-2 over a 3-column space → singular.
#[test]
fn linearly_dependent_row_is_singular() {
    let mut a = ConstraintMatrix::zeros(3, 3);
    // row0 = [1, 2, 3], row1 = [4, 5, 6], row2 = row0 + row1 (GF(256) XOR-add).
    let r0 = [1u8, 2, 3];
    let r1 = [4u8, 5, 6];
    for c in 0..3 {
        a.set(0, c, Gf256::new(r0[c]));
        a.set(1, c, Gf256::new(r1[c]));
        a.set(2, c, Gf256::new(r0[c] ^ r1[c]));
    }
    let rhs = random_symbols(3, 8, 4);
    assert!(
        a.solve(&rhs).is_none(),
        "row2 = row0 + row1 makes the system rank-deficient → singular"
    );
}
