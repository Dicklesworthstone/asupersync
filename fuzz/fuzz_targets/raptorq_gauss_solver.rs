#![no_main]

//! Structure-aware fuzz target for the Gaussian-elimination solver in
//! `src/raptorq/linalg.rs`.
//!
//! The harness feeds arbitrary k×n BIT matrices (coefficients restricted to
//! `{0, 1}`) into the solver with a zero RHS and asserts:
//!
//! 1. `select_pivot_basic` matches a simple reference pivot scan at every
//!    elimination step.
//! 2. `select_pivot_markowitz` matches a reference "fewest nonzeros from the
//!    active column onward" candidate at every elimination step.
//! 3. `solve()` and `solve_markowitz()` agree with the reference on whether the
//!    matrix can sustain pivots through the solver's elimination path or must
//!    terminate as rank-deficient.
//! 4. Any `Solved` result actually satisfies `A · x = 0`.

use arbitrary::Arbitrary;
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{
    DenseRow, GaussianResult, GaussianSolver, select_pivot_basic, select_pivot_markowitz,
};
use libfuzzer_sys::fuzz_target;

const MAX_ROWS: usize = 24;
const MAX_COLS: usize = 24;
const ZERO_RHS_LEN: usize = 1;

#[derive(Debug, Clone, Arbitrary)]
struct GaussSolverInput {
    rows: u8,
    cols: u8,
    matrix: Vec<Vec<bool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReferenceElimination {
    stalled_at: Option<usize>,
}

fuzz_target!(|input: GaussSolverInput| {
    let (rows, cols, coeffs) = normalize_matrix(&input);
    let reference = reference_elimination_and_pivot_checks(&coeffs, rows, cols);
    let expected_singular_row = reference.stalled_at.unwrap_or(rows.min(cols));
    let expected_solved = reference.stalled_at.is_none() && rows >= cols;

    let mut solver_basic = build_zero_rhs_solver(&coeffs, rows, cols);
    let basic_result = solver_basic.solve();

    let mut solver_markowitz = build_zero_rhs_solver(&coeffs, rows, cols);
    let markowitz_result = solver_markowitz.solve_markowitz();

    assert_eq!(
        result_kind(&basic_result),
        result_kind(&markowitz_result),
        "pivot strategies disagree for rows={rows} cols={cols}: basic={:?} markowitz={:?}",
        basic_result,
        markowitz_result
    );

    assert_solver_result(
        &basic_result,
        &coeffs,
        rows,
        cols,
        expected_solved,
        expected_singular_row,
    );
    assert_solver_result(
        &markowitz_result,
        &coeffs,
        rows,
        cols,
        expected_solved,
        expected_singular_row,
    );
});

fn normalize_matrix(input: &GaussSolverInput) -> (usize, usize, Vec<Vec<u8>>) {
    let rows = usize::from(input.rows % MAX_ROWS as u8) + 1;
    let cols = usize::from(input.cols % MAX_COLS as u8) + 1;
    let mut coeffs = vec![vec![0u8; cols]; rows];

    for (row_idx, row) in input.matrix.iter().take(rows).enumerate() {
        for (col_idx, &bit) in row.iter().take(cols).enumerate() {
            coeffs[row_idx][col_idx] = u8::from(bit);
        }
    }

    (rows, cols, coeffs)
}

fn reference_elimination_and_pivot_checks(
    coeffs: &[Vec<u8>],
    rows: usize,
    cols: usize,
) -> ReferenceElimination {
    let mut work = coeffs.to_vec();
    let mut pivot_row = 0usize;
    let pivot_cols = rows.min(cols);

    for pivot_col in 0..pivot_cols {
        let matrix_refs: Vec<&[u8]> = work.iter().map(Vec::as_slice).collect();
        let expected_basic = reference_basic_pivot(&work, pivot_row, rows, pivot_col);
        let expected_markowitz = reference_markowitz_pivot(&work, pivot_row, rows, pivot_col);

        assert_eq!(
            select_pivot_basic(&matrix_refs, pivot_row, rows, pivot_col),
            expected_basic,
            "basic pivot mismatch at row={pivot_row} col={pivot_col}"
        );
        assert_eq!(
            select_pivot_markowitz(&matrix_refs, pivot_row, rows, pivot_col),
            expected_markowitz,
            "markowitz pivot mismatch at row={pivot_row} col={pivot_col}"
        );

        let Some(found_pivot) = expected_basic else {
            return ReferenceElimination {
                stalled_at: Some(pivot_col),
            };
        };

        if found_pivot != pivot_row {
            work.swap(pivot_row, found_pivot);
        }

        for row in (pivot_row + 1)..rows {
            if work[row][pivot_col] == 0 {
                continue;
            }
            for col in pivot_col..cols {
                work[row][col] ^= work[pivot_row][col];
            }
        }

        pivot_row += 1;
        if pivot_row == rows {
            break;
        }
    }

    ReferenceElimination {
        stalled_at: None,
    }
}

fn reference_basic_pivot(
    matrix: &[Vec<u8>],
    start_row: usize,
    end_row: usize,
    col: usize,
) -> Option<usize> {
    (start_row..end_row).find(|&row| matrix[row][col] != 0)
}

fn reference_markowitz_pivot(
    matrix: &[Vec<u8>],
    start_row: usize,
    end_row: usize,
    col: usize,
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;

    for row in start_row..end_row {
        if matrix[row][col] == 0 {
            continue;
        }

        let nnz = matrix[row][col..].iter().filter(|&&value| value != 0).count();
        match best {
            None => best = Some((row, nnz)),
            Some((_best_row, best_nnz)) if nnz < best_nnz => best = Some((row, nnz)),
            Some((best_row, best_nnz)) if nnz == best_nnz && row < best_row => {
                best = Some((row, nnz));
            }
            _ => {}
        }
    }

    best
}

fn build_zero_rhs_solver(coeffs: &[Vec<u8>], rows: usize, cols: usize) -> GaussianSolver {
    let mut solver = GaussianSolver::new(rows, cols);
    for row in 0..rows {
        solver.set_row(row, &coeffs[row], DenseRow::new(vec![0u8; ZERO_RHS_LEN]));
    }
    solver
}

fn result_kind(result: &GaussianResult) -> &'static str {
    match result {
        GaussianResult::Solved(_) => "Solved",
        GaussianResult::Singular { .. } => "Singular",
        GaussianResult::Inconsistent { .. } => "Inconsistent",
    }
}

fn assert_solver_result(
    result: &GaussianResult,
    coeffs: &[Vec<u8>],
    rows: usize,
    cols: usize,
    expected_solved: bool,
    expected_singular_row: usize,
) {
    match result {
        GaussianResult::Solved(solution) => {
            assert!(
                expected_solved,
                "solver unexpectedly solved rank-deficient system rows={rows} cols={cols}"
            );
            verify_zero_rhs_solution(coeffs, solution, rows, cols);
        }
        GaussianResult::Singular { row } => {
            assert!(
                !expected_solved,
                "solver reported singular despite full pivot coverage rows={rows} cols={cols}"
            );
            assert_eq!(
                *row, expected_singular_row,
                "solver singular row mismatch for rows={rows} cols={cols}"
            );
        }
        GaussianResult::Inconsistent { row } => {
            panic!(
                "zero-RHS bit matrix should not be inconsistent (row={row}, rows={rows}, cols={cols})"
            );
        }
    }
}

fn verify_zero_rhs_solution(coeffs: &[Vec<u8>], solution: &[DenseRow], rows: usize, cols: usize) {
    assert_eq!(
        solution.len(),
        cols,
        "Solved variant must return one DenseRow per column, got {} for cols={cols}",
        solution.len()
    );

    for row in 0..rows {
        let mut acc = 0u8;
        for col in 0..cols {
            let coef = Gf256::new(coeffs[row][col]);
            if coef.is_zero() {
                continue;
            }
            let value = solution[col].as_slice().first().copied().unwrap_or(0);
            acc ^= coef.mul_field(Gf256::new(value)).raw();
        }

        assert_eq!(
            acc, 0,
            "A·x != 0 at row {row} for rows={rows} cols={cols}: got {acc:#04x}"
        );
    }
}
