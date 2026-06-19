//! RaptorQ linalg: `GaussianSolver` cell setter round-trip conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the two zero-coverage cell-level
//! construction setters on `raptorq::linalg::GaussianSolver`:
//! `set_coefficient` and `set_rhs`. Both are public API used to assemble a
//! system one cell at a time (as opposed to the row-at-a-time `set_row`), and
//! neither was referenced by any integration test — so their overwrite and
//! bounds semantics, and the guarantee that a system built cell-by-cell solves
//! identically to the same system built row-by-row, were unpinned.
//!
//! Strategy: oracle-free differential round-trip. We pick a KNOWN solution `X`
//! (a vector of multi-byte GF(256) symbols) and a provably invertible
//! coefficient matrix `A` (a Vandermonde over distinct nonzero nodes), compute
//! the right-hand side `b = A·X` with an independent per-byte scalar reference
//! (NOT the library's slice kernels), feed `A` and `b` to the solver purely
//! through `set_coefficient`/`set_rhs`, and assert the solver recovers `X`
//! exactly. Because `X` is chosen up front, no external solver oracle is
//! needed: the system is its own ground truth.
//!
//! Pinned properties:
//!   * round-trip: cell-built `A·X = b` ⇒ `solve()` returns `Solved` == `X`;
//!   * residual:   `A · recovered == b` (re-derived independently);
//!   * equivalence: `set_coefficient`+`set_rhs` ≡ `set_row` (same `Solved`);
//!   * `solve` and `solve_markowitz` agree on the cell-built system;
//!   * overwrite (last-write-wins) for BOTH `set_coefficient` and `set_rhs`;
//!   * fail-closed classification built via setters: `Singular` vs
//!     `Inconsistent` (zero-coef / nonzero-rhs witness);
//!   * bounds asserts panic on out-of-range row/col.
//!
//! Every test is pure and deterministic (no runtime, no entropy — a seeded LCG
//! drives the payload bytes).
//!
//! Repro: `cargo test -p asupersync --test raptorq_gaussian_solver_setter_roundtrip`
#![allow(clippy::needless_range_loop)]

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};

/// Deterministic LCG (Knuth MMIX constants) for reproducible payload bytes.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// A column-major Vandermonde matrix `V[i][j] = node_i^j` over GF(256). With
/// distinct nodes the matrix is invertible, so the system `V·X = b` has a unique
/// solution — exactly `X`. Column 0 is therefore all-ONE (`node^0`).
fn vandermonde(nodes: &[u8], cols: usize) -> Vec<Vec<u8>> {
    nodes
        .iter()
        .map(|&node| {
            let node = Gf256::new(node);
            let mut pow = Gf256::ONE;
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                row.push(pow.raw());
                pow *= node;
            }
            row
        })
        .collect()
}

/// `b = A·X` over GF(256), computed with a per-byte scalar reference that does
/// NOT touch the library's bulk slice kernels (independent oracle).
fn matvec(matrix: &[Vec<u8>], x: &[Vec<u8>], sym: usize) -> Vec<Vec<u8>> {
    let n = matrix.len();
    let cols = matrix[0].len();
    let mut b = vec![vec![0u8; sym]; n];
    for i in 0..n {
        for j in 0..cols {
            let c = Gf256::new(matrix[i][j]);
            if c.is_zero() {
                continue;
            }
            for t in 0..sym {
                let prod = Gf256::new(x[j][t]) * c;
                b[i][t] = (Gf256::new(b[i][t]) + prod).raw();
            }
        }
    }
    b
}

/// Builds a square known solution: `n` symbols of `sym` bytes each, seeded.
fn known_solution(n: usize, sym: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut state = seed;
    (0..n)
        .map(|_| (0..sym).map(|_| (lcg(&mut state) >> 24) as u8).collect())
        .collect()
}

/// Assemble a solver purely via the per-cell setters under test.
fn solver_via_cell_setters(matrix: &[Vec<u8>], rhs: &[Vec<u8>]) -> GaussianSolver {
    let n = matrix.len();
    let cols = matrix[0].len();
    let mut solver = GaussianSolver::new(n, cols);
    for i in 0..n {
        for j in 0..cols {
            solver.set_coefficient(i, j, Gf256::new(matrix[i][j]));
        }
        solver.set_rhs(i, DenseRow::new(rhs[i].clone()));
    }
    solver
}

/// The canonical fixture: invertible 5×5 Vandermonde, 7-byte symbols.
fn fixture(seed: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let nodes = [1u8, 2, 3, 4, 5];
    let sym = 7;
    let matrix = vandermonde(&nodes, nodes.len());
    let x = known_solution(nodes.len(), sym, seed);
    let b = matvec(&matrix, &x, sym);
    (matrix, x, b)
}

#[test]
fn cell_built_system_recovers_known_solution() {
    let (matrix, x, b) = fixture(0xA11CE);
    let mut solver = solver_via_cell_setters(&matrix, &b);

    let GaussianResult::Solved(solution) = solver.solve() else {
        panic!("invertible Vandermonde must solve");
    };

    assert_eq!(solution.len(), x.len(), "one symbol per column");
    for (j, sym) in x.iter().enumerate() {
        assert_eq!(
            solution[j].as_slice(),
            sym.as_slice(),
            "column {j} did not recover the planted solution",
        );
    }

    // Independent residual: re-derive b from the recovered solution; it must
    // reproduce the original right-hand side exactly.
    let recovered: Vec<Vec<u8>> = solution.iter().map(|r| r.as_slice().to_vec()).collect();
    let residual = matvec(&matrix, &recovered, b[0].len());
    assert_eq!(residual, b, "A·recovered must reproduce the original b");

    assert!(
        solver.stats().pivot_selections > 0,
        "solve must record pivot work",
    );
}

#[test]
fn cell_setters_equivalent_to_set_row() {
    let (matrix, _x, b) = fixture(0xB0B);
    let n = matrix.len();
    let cols = matrix[0].len();

    let mut by_cell = solver_via_cell_setters(&matrix, &b);

    let mut by_row = GaussianSolver::new(n, cols);
    for i in 0..n {
        by_row.set_row(i, &matrix[i], DenseRow::new(b[i].clone()));
    }

    assert_eq!(
        by_cell.solve(),
        by_row.solve(),
        "cell-by-cell construction must solve identically to row-at-a-time",
    );
}

#[test]
fn solve_and_markowitz_agree_on_cell_built_system() {
    let (matrix, x, b) = fixture(0xC0FFEE);

    let mut a = solver_via_cell_setters(&matrix, &b);
    let mut m = solver_via_cell_setters(&matrix, &b);

    let plain = a.solve();
    let marko = m.solve_markowitz();
    assert_eq!(plain, marko, "pivot strategy must not change the solution");

    let GaussianResult::Solved(solution) = plain else {
        panic!("expected Solved");
    };
    for (j, sym) in x.iter().enumerate() {
        assert_eq!(solution[j].as_slice(), sym.as_slice());
    }
}

#[test]
fn set_rhs_last_write_wins() {
    let (matrix, x, b) = fixture(0xD00D);
    let n = matrix.len();
    let cols = matrix[0].len();
    let sym = b[0].len();

    let mut solver = GaussianSolver::new(n, cols);
    for i in 0..n {
        for j in 0..cols {
            solver.set_coefficient(i, j, Gf256::new(matrix[i][j]));
        }
        // Poison the RHS first, then overwrite with the correct value.
        solver.set_rhs(i, DenseRow::new(vec![0xFF; sym]));
        solver.set_rhs(i, DenseRow::new(b[i].clone()));
    }

    let GaussianResult::Solved(solution) = solver.solve() else {
        panic!("expected Solved after correct RHS overwrite");
    };
    for (j, sym) in x.iter().enumerate() {
        assert_eq!(
            solution[j].as_slice(),
            sym.as_slice(),
            "set_rhs must overwrite, not accumulate",
        );
    }
}

#[test]
fn set_coefficient_last_write_wins() {
    let (matrix, x, b) = fixture(0xE1EE7);
    let n = matrix.len();
    let cols = matrix[0].len();

    let mut solver = GaussianSolver::new(n, cols);
    for i in 0..n {
        for j in 0..cols {
            // Poison one cell, then overwrite with the correct coefficient.
            solver.set_coefficient(i, j, Gf256::new(matrix[i][j] ^ 0x5A));
            solver.set_coefficient(i, j, Gf256::new(matrix[i][j]));
        }
        solver.set_rhs(i, DenseRow::new(b[i].clone()));
    }

    let GaussianResult::Solved(solution) = solver.solve() else {
        panic!("expected Solved after correct coefficient overwrite");
    };
    for (j, sym) in x.iter().enumerate() {
        assert_eq!(
            solution[j].as_slice(),
            sym.as_slice(),
            "set_coefficient must overwrite, not xor-accumulate",
        );
    }
}

/// A rank-deficient system whose stall column carries an all-zero coefficient
/// row with a ZERO right-hand side is genuinely `Singular`, not `Inconsistent`.
#[test]
fn cell_built_zero_column_is_singular() {
    let sym = 4;
    let mut solver = GaussianSolver::new(3, 3);
    // Identity on the first two unknowns; third column/row left all zero.
    solver.set_coefficient(0, 0, Gf256::ONE);
    solver.set_coefficient(1, 1, Gf256::ONE);
    for i in 0..3 {
        solver.set_rhs(i, DenseRow::zeros(sym));
    }

    assert_eq!(
        solver.solve(),
        GaussianResult::Singular { row: 2 },
        "all-zero stall column with zero RHS is Singular",
    );
}

/// Same skeleton, but the all-zero coefficient row carries a NONZERO RHS — a
/// `0 = b, b != 0` witness — so the system is `Inconsistent`.
#[test]
fn cell_built_zero_row_nonzero_rhs_is_inconsistent() {
    let sym = 4;
    let mut solver = GaussianSolver::new(3, 3);
    solver.set_coefficient(0, 0, Gf256::ONE);
    solver.set_coefficient(1, 1, Gf256::ONE);
    solver.set_rhs(0, DenseRow::zeros(sym));
    solver.set_rhs(1, DenseRow::zeros(sym));
    // Row 2 has all-zero coefficients but a nonzero RHS.
    solver.set_rhs(2, DenseRow::new(vec![0u8, 0, 0, 0x42]));

    assert_eq!(
        solver.solve(),
        GaussianResult::Inconsistent { row: 2 },
        "zero-coefficient row with nonzero RHS must be Inconsistent",
    );
}

#[test]
#[should_panic(expected = "row out of bounds")]
fn set_coefficient_row_out_of_bounds_panics() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_coefficient(2, 0, Gf256::ONE);
}

#[test]
#[should_panic(expected = "column out of bounds")]
fn set_coefficient_col_out_of_bounds_panics() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_coefficient(0, 2, Gf256::ONE);
}

#[test]
#[should_panic(expected = "row out of bounds")]
fn set_rhs_row_out_of_bounds_panics() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_rhs(2, DenseRow::zeros(4));
}
