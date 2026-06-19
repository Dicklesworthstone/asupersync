//! Conformance for the dense `GaussianSolver` cell-granular mutators
//! `set_coefficient` and `set_rhs` (bd-3uox5).
//!
//! These two builder methods had ZERO integration coverage: the only way the
//! decoder normally populates a system is the bulk `set_row` path, so the
//! per-cell `set_coefficient(row, col, value)` and per-row `set_rhs(row, rhs)`
//! mutators were never exercised through the public surface.
//!
//! The coefficient matrix is private, so these tests pin the mutators
//! *behaviorally* through the observable `solve()` output:
//!
//!   * DIFFERENTIAL — a square invertible system assembled cell-by-cell via
//!     `set_coefficient` + `set_rhs` must solve byte-identically to the same
//!     system assembled via the trusted bulk `set_row` path. This is an
//!     oracle-free equivalence: the two build paths can only disagree if a
//!     mutator writes the wrong cell, drops a write, or clobbers neighbours.
//!   * ARITHMETIC ORACLE — a 1x1 system `a*x = b` must solve to `x = b * a^-1`
//!     computed independently in GF(256), pinning that `set_coefficient`
//!     stores `value.raw()` into the cell elimination actually reads.
//!   * ADDRESSING — a diagonal built purely with `set_coefficient` yields the
//!     identity, whose solution is the RHS verbatim (proves correct (row,col)
//!     placement; off-diagonal cells stay structurally zero).
//!   * SEMANTICS — last-write-wins on a repeated cell; `set_rhs` replaces only
//!     the RHS and leaves coefficients intact.
//!   * FAIL-CLOSED — out-of-bounds row/col assertions panic at the mutator.
//!
//! Additive: a single new integration crate, no production code touched.

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};

/// GF(256) division `dividend / divisor`, computed independently of the
/// solver so it can serve as an oracle for the 1x1 solve.
fn gf_div(dividend: u8, divisor: u8) -> u8 {
    Gf256::new(dividend)
        .mul_field(Gf256::new(divisor).inv())
        .raw()
}

/// An upper-triangular GF(256) matrix with nonzero diagonal — guaranteed
/// invertible, so the system has a unique solution and reduces cleanly.
const COEFFS: [[u8; 3]; 3] = [[3, 1, 9], [0, 2, 5], [0, 0, 7]];
const RHS: [[u8; 2]; 3] = [[10, 20], [30, 40], [50, 60]];

fn rows(data: &[[u8; 2]]) -> Vec<DenseRow> {
    data.iter().map(|r| DenseRow::new(r.to_vec())).collect()
}

#[test]
fn cell_by_cell_assembly_solves_identically_to_set_row() {
    // Path A: trusted bulk assembly.
    let mut bulk = GaussianSolver::new(3, 3);
    for (i, coeff_row) in COEFFS.iter().enumerate() {
        bulk.set_row(i, coeff_row, DenseRow::new(RHS[i].to_vec()));
    }
    let bulk_result = bulk.solve();

    // Path B: identical system assembled exclusively through the per-cell
    // `set_coefficient` and per-row `set_rhs` mutators under test.
    let mut cells = GaussianSolver::new(3, 3);
    for (i, coeff_row) in COEFFS.iter().enumerate() {
        for (j, &v) in coeff_row.iter().enumerate() {
            cells.set_coefficient(i, j, Gf256::new(v));
        }
        cells.set_rhs(i, DenseRow::new(RHS[i].to_vec()));
    }
    let cell_result = cells.solve();

    assert!(
        matches!(bulk_result, GaussianResult::Solved(_)),
        "invertible system must solve via the bulk path"
    );
    assert_eq!(
        bulk_result, cell_result,
        "cell-by-cell mutators must reconstruct the same system the bulk path does"
    );
}

#[test]
fn cell_assembly_order_is_irrelevant() {
    // Writing coefficients in a scrambled (column-major, reversed) order must
    // not change the assembled system: each `set_coefficient` is independent.
    let mut forward = GaussianSolver::new(3, 3);
    for (i, coeff_row) in COEFFS.iter().enumerate() {
        for (j, &v) in coeff_row.iter().enumerate() {
            forward.set_coefficient(i, j, Gf256::new(v));
        }
        forward.set_rhs(i, DenseRow::new(RHS[i].to_vec()));
    }

    let mut scrambled = GaussianSolver::new(3, 3);
    // RHS first, then coefficients column-major from the bottom-right corner.
    for i in (0..3).rev() {
        scrambled.set_rhs(i, DenseRow::new(RHS[i].to_vec()));
    }
    for j in (0..3).rev() {
        for i in (0..3).rev() {
            scrambled.set_coefficient(i, j, Gf256::new(COEFFS[i][j]));
        }
    }

    assert_eq!(forward.solve(), scrambled.solve());
}

#[test]
fn one_by_one_solve_matches_gf256_division_oracle() {
    // a*x = b  =>  x = b * a^-1, computed independently in GF(256).
    let a: u8 = 7;
    let b: [u8; 3] = [13, 200, 1];

    let mut solver = GaussianSolver::new(1, 1);
    solver.set_coefficient(0, 0, Gf256::new(a));
    solver.set_rhs(0, DenseRow::new(b.to_vec()));

    let expected: Vec<u8> = b.iter().map(|&byte| gf_div(byte, a)).collect();
    match solver.solve() {
        GaussianResult::Solved(sol) => {
            assert_eq!(sol.len(), 1, "1x1 system yields a single solution row");
            assert_eq!(
                sol[0].as_slice(),
                expected.as_slice(),
                "set_coefficient must store the coefficient elimination divides by"
            );
        }
        other => panic!("expected Solved, got {other:?}"),
    }
}

#[test]
fn diagonal_built_by_set_coefficient_is_identity() {
    // Build I_3 using only diagonal `set_coefficient` writes; off-diagonal
    // cells remain the structural zeros from `new`. The identity's solution
    // is the RHS verbatim, proving (row, col) addressing is exact.
    let mut solver = GaussianSolver::new(3, 3);
    for (i, rhs) in RHS.iter().enumerate() {
        solver.set_coefficient(i, i, Gf256::ONE);
        solver.set_rhs(i, DenseRow::new(rhs.to_vec()));
    }

    match solver.solve() {
        GaussianResult::Solved(sol) => assert_eq!(sol, rows(&RHS)),
        other => panic!("identity system must solve, got {other:?}"),
    }
}

#[test]
fn repeated_set_coefficient_is_last_write_wins() {
    // Overwrite the same cell; the final value must be the one elimination uses.
    let b: u8 = 6;
    let mut solver = GaussianSolver::new(1, 1);
    solver.set_coefficient(0, 0, Gf256::new(2)); // shadowed
    solver.set_coefficient(0, 0, Gf256::new(3)); // wins
    solver.set_rhs(0, DenseRow::new(vec![b]));

    let solved = match solver.solve() {
        GaussianResult::Solved(sol) => sol[0].as_slice()[0],
        other => panic!("expected Solved, got {other:?}"),
    };
    assert_eq!(solved, gf_div(b, 3), "last write (3) must be the divisor");
    assert_ne!(
        solved,
        gf_div(b, 2),
        "the shadowed first write (2) must not influence the solution"
    );
}

#[test]
fn set_rhs_replaces_rhs_without_touching_coefficients() {
    // Populate a full row (coeff + rhs) via set_row, then overwrite ONLY the
    // RHS. The solution must reflect the new RHS while still dividing by the
    // original, untouched coefficient.
    let coeff: u8 = 5;
    let mut solver = GaussianSolver::new(1, 1);
    solver.set_row(0, &[coeff], DenseRow::new(vec![10]));
    solver.set_rhs(0, DenseRow::new(vec![15])); // replace 10 -> 15

    let solved = match solver.solve() {
        GaussianResult::Solved(sol) => sol[0].as_slice()[0],
        other => panic!("expected Solved, got {other:?}"),
    };
    assert_eq!(
        solved,
        gf_div(15, coeff),
        "solution uses the replacement RHS"
    );
    assert_ne!(solved, gf_div(10, coeff), "the old RHS must be gone");
}

#[test]
fn set_coefficient_value_is_honored_zero_is_singular() {
    // The stored byte is load-bearing: a zero diagonal has no pivot (Singular),
    // a nonzero diagonal solves. Discriminates that the *value* — not merely
    // the cell's existence — drives elimination.
    let mut zero = GaussianSolver::new(1, 1);
    zero.set_coefficient(0, 0, Gf256::ZERO);
    zero.set_rhs(0, DenseRow::zeros(0));
    assert_eq!(zero.solve(), GaussianResult::Singular { row: 0 });

    let mut nonzero = GaussianSolver::new(1, 1);
    nonzero.set_coefficient(0, 0, Gf256::ONE);
    nonzero.set_rhs(0, DenseRow::zeros(0));
    assert!(matches!(nonzero.solve(), GaussianResult::Solved(_)));
}

#[test]
#[should_panic(expected = "row out of bounds")]
fn set_coefficient_rejects_out_of_bounds_row() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_coefficient(2, 0, Gf256::ONE);
}

#[test]
#[should_panic(expected = "column out of bounds")]
fn set_coefficient_rejects_out_of_bounds_column() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_coefficient(0, 2, Gf256::ONE);
}

#[test]
#[should_panic(expected = "row out of bounds")]
fn set_rhs_rejects_out_of_bounds_row() {
    let mut solver = GaussianSolver::new(2, 2);
    solver.set_rhs(2, DenseRow::zeros(0));
}
