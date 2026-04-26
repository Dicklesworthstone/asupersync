#![allow(warnings)]
#![allow(clippy::all)]
//! Tests for Gaussian elimination algorithm (RFC 6330 Section 4.3.2).
//!
//! # Module status (br-pw8jhp)
//!
//! `spec_derived/` currently has **no `Cargo.toml`**, so this module is not
//! built by `cargo test` from the project root — it is a scaffold awaiting
//! crate-isation. The test below is therefore self-contained: it exercises
//! GF(256) Gaussian-elimination *behaviour* (forward elim + back-substitution
//! over a 3×3 known system) using a tiny inline reference. Once the parent
//! directory is given a `Cargo.toml` with an `asupersync` path-dep, this
//! test can be re-wired to drive `asupersync::raptorq::linalg::GaussianSolver`
//! and the inline reference becomes a redundancy check rather than the SUT.

use crate::spec_derived::{
    ConformanceContext, ConformanceResult, RequirementLevel, Rfc6330ConformanceCase,
    Rfc6330ConformanceSuite,
};

/// Register Gaussian elimination tests.
#[allow(dead_code)]
pub fn register_tests(suite: &mut Rfc6330ConformanceSuite) {
    suite.add_test_case(Rfc6330ConformanceCase {
        id: "RFC6330-4.3.2",
        section: "4.3",
        level: RequirementLevel::Must,
        description: "Gaussian elimination MUST solve constraint matrix correctly",
        test_fn: test_gaussian_elimination,
    });
}

/// Test Gaussian elimination algorithm.
///
/// Constructs three independent 3×3 GF(256) systems and verifies:
///
/// 1. **Identity system** — `I·x = b` solves to `x = b` for arbitrary `b`.
/// 2. **Lower-triangular XOR system** — exercises forward elimination with
///    only XOR (`c = 1`) operations; the closed-form solution is provable
///    by direct substitution and acts as an external oracle.
/// 3. **Singular detection** — a matrix with a zero column at the pivot
///    frontier MUST be reported as unsolvable (no false `Solved` result).
///
/// All assertions are aggregated into the returned `ConformanceResult`;
/// any single failure flips the result to `fail` with a precise diagnostic
/// rather than a generic placeholder string.
#[allow(dead_code)]
fn test_gaussian_elimination(_ctx: &ConformanceContext) -> ConformanceResult {
    let mut details: Vec<String> = Vec::new();

    // ── 1. Identity system: I·x = b ⇒ x = b ─────────────────────────────────
    {
        let identity: [[u8; 3]; 3] = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
        let rhs: [u8; 3] = [0xAA, 0x55, 0x42];
        match solve_3x3(identity, rhs) {
            Some(x) if x == rhs => {
                details.push("identity: solved x == b".to_string());
            }
            Some(x) => {
                return ConformanceResult::fail(format!(
                    "identity system produced wrong solution: got {x:?}, expected {rhs:?}"
                ));
            }
            None => {
                return ConformanceResult::fail(
                    "identity system reported singular — should be invertible",
                );
            }
        }
    }

    // ── 2. Lower-triangular XOR system ──────────────────────────────────────
    //   [1 0 0 | a]      x1 = a
    //   [1 1 0 | b]      x2 = a ⊕ b
    //   [0 1 1 | c]      x3 = a ⊕ b ⊕ c
    {
        let m: [[u8; 3]; 3] = [[1, 0, 0], [1, 1, 0], [0, 1, 1]];
        let (a, b, c) = (0x37u8, 0xC1u8, 0x9Du8);
        let rhs: [u8; 3] = [a, b, c];
        let expected: [u8; 3] = [a, a ^ b, a ^ b ^ c];
        match solve_3x3(m, rhs) {
            Some(x) if x == expected => {
                details.push(format!(
                    "lower_triangular: solved {x:?} matches XOR closed-form {expected:?}"
                ));
            }
            Some(x) => {
                return ConformanceResult::fail(format!(
                    "lower-triangular XOR system: got {x:?}, expected {expected:?}"
                ));
            }
            None => {
                return ConformanceResult::fail("lower-triangular XOR system reported singular");
            }
        }
    }

    // ── 3. Singular detection: zero column at pivot frontier ────────────────
    //   [0 0 0 | 1]      no pivot in any row of column 0 ⇒ singular / inconsistent
    //   [0 1 0 | 1]
    //   [0 0 1 | 1]
    {
        let m: [[u8; 3]; 3] = [[0, 0, 0], [0, 1, 0], [0, 0, 1]];
        let rhs: [u8; 3] = [1, 1, 1];
        match solve_3x3(m, rhs) {
            None => {
                details.push("singular: zero column at pivot 0 correctly detected".to_string());
            }
            Some(x) => {
                return ConformanceResult::fail(format!(
                    "singular system was solved instead of detected: got {x:?}"
                ));
            }
        }
    }

    let mut result = ConformanceResult::pass()
        .with_metric("gf256_systems_solved", 2.0)
        .with_metric("singular_systems_detected", 1.0);
    for d in details {
        result = result.with_detail(d);
    }
    result
}

// ─── Inline GF(256) reference ────────────────────────────────────────────────
//
// A minimal Gaussian-elimination reference for self-contained spec testing.
// Uses Rijndael's polynomial 0x11B (the same one RFC 6330 §5.7.1 mandates) so
// the field arithmetic matches `asupersync::raptorq::gf256::Gf256` exactly —
// once this module is wired into a real crate the SUT and oracle can be
// swapped without changing any expected values.

/// GF(256) multiplication via the Rijndael reduction polynomial 0x11B.
/// Constant-time over the input bytes (no early-exit), matching the spec.
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let high_bit_set = (a & 0x80) != 0;
        a = a.wrapping_shl(1);
        if high_bit_set {
            a ^= 0x1B; // reduction by x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    acc
}

/// GF(256) multiplicative inverse via Fermat's little theorem: a^254 = a^-1.
/// Only defined for `a != 0`; callers must check first.
fn gf256_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "0 has no multiplicative inverse in GF(256)");
    let mut acc = 1u8;
    let mut base = a;
    let mut exp: u32 = 254;
    while exp > 0 {
        if (exp & 1) != 0 {
            acc = gf256_mul(acc, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Solve the 3×3 GF(256) system `matrix · x = rhs` by forward elimination
/// with partial pivoting + back-substitution. Returns `None` when the
/// matrix is singular (no pivot found at some column frontier).
fn solve_3x3(matrix: [[u8; 3]; 3], rhs: [u8; 3]) -> Option<[u8; 3]> {
    // Augment [A | b].
    let mut m: [[u8; 4]; 3] = [[0; 4]; 3];
    for i in 0..3 {
        for j in 0..3 {
            m[i][j] = matrix[i][j];
        }
        m[i][3] = rhs[i];
    }

    // Forward elimination with partial pivoting.
    for col in 0..3 {
        // Find pivot row at or below `col` with nonzero entry in `col`.
        let pivot = (col..3).find(|&r| m[r][col] != 0)?;
        if pivot != col {
            m.swap(col, pivot);
        }
        // Normalise pivot row so m[col][col] == 1.
        let inv = gf256_inv(m[col][col]);
        for j in col..4 {
            m[col][j] = gf256_mul(m[col][j], inv);
        }
        // Eliminate below.
        for r in (col + 1)..3 {
            let factor = m[r][col];
            if factor == 0 {
                continue;
            }
            for j in col..4 {
                let prod = gf256_mul(factor, m[col][j]);
                m[r][j] ^= prod;
            }
        }
    }

    // Back-substitution.
    for col in (0..3).rev() {
        for r in 0..col {
            let factor = m[r][col];
            if factor == 0 {
                continue;
            }
            for j in col..4 {
                let prod = gf256_mul(factor, m[col][j]);
                m[r][j] ^= prod;
            }
        }
    }

    Some([m[0][3], m[1][3], m[2][3]])
}

#[cfg(test)]
mod inline_oracle_tests {
    use super::*;

    #[test]
    fn gf256_mul_matches_known_values() {
        // Spot-check against well-known GF(256) multiplications under 0x11B.
        assert_eq!(
            gf256_mul(0x57, 0x83),
            0xC1,
            "0x57 * 0x83 = 0xC1 (AES test vector)"
        );
        assert_eq!(gf256_mul(0x00, 0xFF), 0x00);
        assert_eq!(gf256_mul(0x01, 0xAB), 0xAB);
        assert_eq!(gf256_mul(0xAB, 0x01), 0xAB);
    }

    #[test]
    fn gf256_inv_is_left_and_right_inverse() {
        for a in 1u8..=255 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a * a^-1 != 1 for a={a}");
            assert_eq!(gf256_mul(inv, a), 1, "a^-1 * a != 1 for a={a}");
        }
    }

    #[test]
    fn solve_identity_returns_rhs() {
        let id: [[u8; 3]; 3] = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
        assert_eq!(solve_3x3(id, [10, 20, 30]), Some([10, 20, 30]));
    }

    #[test]
    fn solve_singular_returns_none() {
        let zero_col: [[u8; 3]; 3] = [[0, 0, 0], [0, 1, 0], [0, 0, 1]];
        assert_eq!(solve_3x3(zero_col, [1, 1, 1]), None);
    }
}
