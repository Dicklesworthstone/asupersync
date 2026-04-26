#![no_main]

//! Cargo-fuzz target for the END-TO-END Gaussian-elimination SOLVER in
//! src/raptorq/linalg.rs (`GaussianSolver`), feeding random GF(256)
//! systems and asserting:
//!
//!   1. **No panic on any input.** Random matrix sizes (capped at
//!      MAX_ROWS×MAX_COLS to keep iters sub-second), random GF(256)
//!      coefficients, random RHS bytes — none of these MUST trigger a
//!      Rust panic. Allocation overflow is bounded by explicit caps.
//!
//!   2. **Result is one of three documented kinds.** Every solve() /
//!      solve_markowitz() call MUST return `GaussianResult::{Solved,
//!      Singular, Inconsistent}`. Stack overflow on recursive
//!      elimination, silent hang, etc. are bugs.
//!
//!   3. **Solved-result actually satisfies A · x ≡ b.** For square
//!      systems where solve returns Solved(x), the fuzzer multiplies
//!      the original matrix times the solution and compares to the
//!      original RHS. Mismatch = solver bug — the most important
//!      correctness invariant for the FEC encoder built on this solver.
//!
//!   4. **Pivot-strategy consistency.** `solve()` and `solve_markowitz()`
//!      use different pivot heuristics but solve the same system. Both
//!      MUST return the same VARIETY of result on identical input
//!      (Solved/Solved, Singular/Singular, Inconsistent/Inconsistent).
//!      Disagreement = real correctness gap in one of the strategies.
//!
//! Relationship to the existing `raptorq_linalg.rs` fuzz target: that
//! target exercises PRIMITIVES (row_xor, row_scale_add, row_swap,
//! select_pivot_basic/markowitz, DenseRow/SparseRow round-trip). This
//! one exercises the COMPOSED SOLVER end-to-end with the A·x=b
//! correctness oracle. They share GF(256) arithmetic but cover
//! different bug surfaces.

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};
use libfuzzer_sys::fuzz_target;

const MAX_ROWS: usize = 24;
const MAX_COLS: usize = 24;
const RHS_LEN: usize = 8;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let rows = (data[0] as usize % MAX_ROWS) + 1;
    let cols = (data[1] as usize % MAX_COLS) + 1;
    let payload = &data[2..];
    let coef_count = rows * cols;
    if payload.len() < coef_count {
        return;
    }

    let coef_bytes = &payload[..coef_count];
    let rhs_seed = &payload[coef_count..];

    let mut coeff_matrix: Vec<Vec<u8>> = Vec::with_capacity(rows);
    for r in 0..rows {
        coeff_matrix.push(coef_bytes[r * cols..(r + 1) * cols].to_vec());
    }
    let rhs_snapshot: Vec<DenseRow> = (0..rows).map(|r| build_rhs(rhs_seed, r)).collect();

    // ── solve() ─────────────────────────────────────────────────────────
    let mut solver_a = build_solver(&coeff_matrix, &rhs_snapshot, rows, cols);
    let res_a = solver_a.solve();
    assert_documented_kind(&res_a);

    // ── solve_markowitz() ───────────────────────────────────────────────
    let mut solver_b = build_solver(&coeff_matrix, &rhs_snapshot, rows, cols);
    let res_b = solver_b.solve_markowitz();
    assert_documented_kind(&res_b);

    // ── Pivot-strategy consistency ──────────────────────────────────────
    assert_eq!(
        result_kind(&res_a),
        result_kind(&res_b),
        "solve() and solve_markowitz() disagree on input rows={rows} cols={cols}: \
         basic={:?} markowitz={:?}",
        result_kind(&res_a),
        result_kind(&res_b)
    );

    // ── Round-trip verification on square systems with a Solved result ─
    if rows == cols {
        if let GaussianResult::Solved(solution) = &res_a {
            verify_solution(&coeff_matrix, solution, &rhs_snapshot, rows, cols);
        }
        if let GaussianResult::Solved(solution) = &res_b {
            verify_solution(&coeff_matrix, solution, &rhs_snapshot, rows, cols);
        }
    }
});

fn build_rhs(seed: &[u8], row: usize) -> DenseRow {
    let mut bytes = vec![0u8; RHS_LEN];
    let n = seed.len().max(1);
    for i in 0..RHS_LEN {
        let idx = (row.wrapping_mul(31).wrapping_add(i)) % n;
        bytes[i] = seed.get(idx).copied().unwrap_or(0);
    }
    DenseRow::new(bytes)
}

fn build_solver(
    coeffs: &[Vec<u8>],
    rhs: &[DenseRow],
    rows: usize,
    cols: usize,
) -> GaussianSolver {
    let mut s = GaussianSolver::new(rows, cols);
    for r in 0..rows {
        let r_bytes: Vec<u8> = rhs[r].as_slice().to_vec();
        s.set_row(r, &coeffs[r], DenseRow::new(r_bytes));
    }
    s
}

fn result_kind(r: &GaussianResult) -> &'static str {
    match r {
        GaussianResult::Solved(_) => "Solved",
        GaussianResult::Singular { .. } => "Singular",
        GaussianResult::Inconsistent { .. } => "Inconsistent",
    }
}

fn assert_documented_kind(r: &GaussianResult) {
    match r {
        GaussianResult::Solved(_)
        | GaussianResult::Singular { .. }
        | GaussianResult::Inconsistent { .. } => {}
    }
}

/// Verify A · x ≡ b in GF(256) byte-by-byte. The solution vector has
/// `cols` entries (one DenseRow per unknown), each carrying RHS_LEN
/// payload bytes. For each output row r, compute Σ_c (A[r][c] · x[c])
/// and compare to b[r].
fn verify_solution(
    coeffs: &[Vec<u8>],
    solution: &[DenseRow],
    rhs: &[DenseRow],
    rows: usize,
    cols: usize,
) {
    assert_eq!(
        solution.len(),
        cols,
        "Solved variant must return one DenseRow per column, got {} for cols={cols}",
        solution.len()
    );
    let payload_len = rhs
        .first()
        .map(|r| r.as_slice().len())
        .unwrap_or(RHS_LEN);

    for r in 0..rows {
        let mut acc = vec![0u8; payload_len];
        for c in 0..cols {
            let coef = Gf256::new(coeffs[r][c]);
            if coef.is_zero() {
                continue;
            }
            let xc = solution[c].as_slice();
            for i in 0..payload_len {
                let prod = coef.mul_field(Gf256::new(xc[i])).raw();
                acc[i] ^= prod;
            }
        }
        let expected = rhs[r].as_slice();
        assert_eq!(
            &acc[..payload_len],
            expected,
            "A·x ≠ b at row {r}: got {acc:?}, expected {expected:?} \
             (rows={rows} cols={cols})"
        );
    }
}
