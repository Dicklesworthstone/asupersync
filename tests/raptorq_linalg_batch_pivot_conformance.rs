//! RaptorQ linalg: batched scale-add SIMD path ↔ scalar path equivalence, plus
//! pivot-selection differential conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the elimination-engine helpers in
//! `raptorq::linalg` that had ZERO integration coverage:
//! `row_scale_add_batch2`, `row_scale_add_batch_multi`, `collect_batch_candidates`,
//! `select_pivot_basic`, and `select_pivot_markowitz`.
//!
//! These functions exist purely as an *optimization* of Gaussian elimination
//! (the dual-kernel SIMD batch path claims a 30-50% speedup for K>=1024). Per
//! the program's first principle — "optimization only inside proven-safe
//! envelopes; never trade correctness for speed" — the batched/SIMD path MUST
//! be byte-identical to the simple scalar `row_scale_add` reference, and the
//! pivot heuristics MUST agree with a brute-force oracle. The strategy is
//! therefore differential + metamorphic, against an independent reference:
//!
//!   * `row_scale_add_batch2` / `row_scale_add_batch_multi` are cross-checked
//!     against applying the (heavily tested) scalar `row_scale_add` kernel to
//!     each (dst, src) pair individually — covering even counts, the odd-count
//!     tail fallback, the empty case, and the `c == 0` early-return no-op.
//!   * An involution check (apply the same batch op twice → identity, because
//!     GF(256) addition is XOR and `c*s ^ c*s == 0`) pins correctness without
//!     relying on the scalar oracle at all.
//!   * `select_pivot_basic` / `select_pivot_markowitz` are cross-checked against
//!     a brute-force pivot oracle.
//!   * `collect_batch_candidates` is checked structurally (only same-coefficient
//!     rows, fail-closed on zero pivot / out-of-range).
//!
//! Every test is pure and deterministic (no runtime, no entropy — a seeded LCG
//! drives inputs).
//!
//! Repro: `cargo test -p asupersync --test raptorq_linalg_batch_pivot_conformance`

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{
    DenseRow, GaussianOutcomeKind, GaussianResult, GaussianSolver, coefficient_rank_profile,
    collect_batch_candidates, row_scale_add, row_scale_add_batch_multi, row_scale_add_batch2,
    select_pivot_basic, select_pivot_markowitz,
};

/// Deterministic LCG (Knuth MMIX constants) for reproducible row generation.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// Builds a pseudo-random byte row of `len` bytes. `density` is the per-byte
/// probability (out of 256) that a position carries a (possibly zero) value;
/// the remaining positions are forced to zero so sparse rows are exercised too.
fn random_row(len: usize, seed: u64, density: u8) -> Vec<u8> {
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            let r = lcg(&mut s);
            if (r & 0xFF) < u64::from(density) {
                (r >> 23) as u8
            } else {
                0
            }
        })
        .collect()
}

/// Reference scalar scale-add over dense slices using the heavily tested GF(256)
/// kernel. Returns `dst + c * src`.
fn scalar_scale_add_ref(dst: &[u8], src: &[u8], c: Gf256) -> Vec<u8> {
    let mut out = dst.to_vec();
    row_scale_add(&mut out, src, c);
    out
}

const LENS: [usize; 7] = [0, 1, 7, 16, 31, 32, 129];
const DENSITIES: [u8; 3] = [16, 96, 255];
// Includes 0 (no-op), 1 (identity scalar), 2 (the field generator), and
// 255 (max element) to span the multiplier domain.
const SCALARS: [u8; 5] = [0, 1, 2, 7, 255];

// ---------------------------------------------------------------------------
// row_scale_add_batch2: the dual-kernel path equals two scalar scale-adds.
// ---------------------------------------------------------------------------

#[test]
fn batch2_matches_two_scalar_scale_adds() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for &raw_c in &SCALARS {
                for seed in 0..12u64 {
                    let c = Gf256::new(raw_c);

                    let mut dst_a = random_row(len, seed, density);
                    let src_a = random_row(len, seed ^ 0xA1, density);
                    let mut dst_b = random_row(len, seed ^ 0xB2, density);
                    let src_b = random_row(len, seed ^ 0xC3, density);

                    let expect_a = scalar_scale_add_ref(&dst_a, &src_a, c);
                    let expect_b = scalar_scale_add_ref(&dst_b, &src_b, c);

                    row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);

                    assert_eq!(
                        dst_a, expect_a,
                        "batch2 dst_a diverged from scalar ref \
                         (len={len}, density={density}, c={raw_c}, seed={seed})"
                    );
                    assert_eq!(
                        dst_b, expect_b,
                        "batch2 dst_b diverged from scalar ref \
                         (len={len}, density={density}, c={raw_c}, seed={seed})"
                    );
                }
            }
        }
    }
}

/// GF(256) addition is XOR, so `dst += c*src` is its own inverse: applying the
/// same batch op twice restores both destinations exactly. This pins the
/// batch kernel WITHOUT trusting the scalar oracle — a one-sided transcription
/// bug in either path that happened to agree would still fail this involution.
#[test]
fn batch2_applied_twice_is_identity() {
    for &len in &LENS {
        for &raw_c in &SCALARS {
            for seed in 0..16u64 {
                let c = Gf256::new(raw_c);

                let dst_a0 = random_row(len, seed, 200);
                let src_a = random_row(len, seed ^ 0x11, 200);
                let dst_b0 = random_row(len, seed ^ 0x22, 200);
                let src_b = random_row(len, seed ^ 0x33, 200);

                let mut dst_a = dst_a0.clone();
                let mut dst_b = dst_b0.clone();

                row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);
                row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);

                assert_eq!(dst_a, dst_a0, "batch2 not involutive on dst_a (c={raw_c})");
                assert_eq!(dst_b, dst_b0, "batch2 not involutive on dst_b (c={raw_c})");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// row_scale_add_batch_multi: N-way batch equals N scalar scale-adds, including
// the odd-count tail fallback, the empty case, and the c==0 early return.
// ---------------------------------------------------------------------------

#[test]
fn batch_multi_matches_sequential_scalar_for_all_counts() {
    // Counts span even (pairs only), odd (exercises the tail fallback), 1, and 0.
    for n in 0..9usize {
        for &len in &LENS {
            for &raw_c in &SCALARS {
                for seed in 0..6u64 {
                    let c = Gf256::new(raw_c);

                    let mut dsts: Vec<Vec<u8>> = (0..n)
                        .map(|i| random_row(len, seed ^ (i as u64) << 8, 128))
                        .collect();
                    let srcs: Vec<Vec<u8>> = (0..n)
                        .map(|i| random_row(len, seed ^ 0x5A5A ^ (i as u64), 128))
                        .collect();

                    // Independent reference: apply scalar scale-add to each pair.
                    let expected: Vec<Vec<u8>> = dsts
                        .iter()
                        .zip(&srcs)
                        .map(|(d, s)| scalar_scale_add_ref(d, s, c))
                        .collect();

                    let mut dst_refs: Vec<&mut [u8]> =
                        dsts.iter_mut().map(Vec::as_mut_slice).collect();
                    let src_refs: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
                    row_scale_add_batch_multi(&mut dst_refs, &src_refs, c);

                    assert_eq!(
                        dsts, expected,
                        "batch_multi diverged from sequential scalar ref \
                         (n={n}, len={len}, c={raw_c}, seed={seed})"
                    );
                }
            }
        }
    }
}

#[test]
fn batch_multi_zero_scalar_is_noop() {
    let mut dsts: Vec<Vec<u8>> = (0..5).map(|i| random_row(40, i, 200)).collect();
    let original = dsts.clone();
    let srcs: Vec<Vec<u8>> = (0..5).map(|i| random_row(40, i ^ 0x99, 200)).collect();

    let mut dst_refs: Vec<&mut [u8]> = dsts.iter_mut().map(Vec::as_mut_slice).collect();
    let src_refs: Vec<&[u8]> = srcs.iter().map(Vec::as_slice).collect();
    row_scale_add_batch_multi(&mut dst_refs, &src_refs, Gf256::ZERO);

    assert_eq!(dsts, original, "batch_multi with c=0 must be a no-op");
}

#[test]
fn batch_multi_empty_is_noop() {
    // Zero rows: must not panic and must leave nothing changed.
    let mut dst_refs: Vec<&mut [u8]> = Vec::new();
    let src_refs: Vec<&[u8]> = Vec::new();
    row_scale_add_batch_multi(&mut dst_refs, &src_refs, Gf256::new(3));
    assert!(dst_refs.is_empty());
}

// ---------------------------------------------------------------------------
// collect_batch_candidates: only same-pivot-coefficient rows, fail-closed.
// ---------------------------------------------------------------------------

#[test]
fn collect_candidates_matches_doc_example() {
    // Mirrors the doctest in linalg.rs exactly.
    let matrix = vec![vec![1, 0, 0], vec![1, 2, 3], vec![0, 4, 5], vec![1, 6, 7]];
    let candidates = collect_batch_candidates(&matrix, 0, 0);

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0], (vec![1, 0, 0], vec![1, 2, 3]));
    assert_eq!(candidates[1], (vec![1, 0, 0], vec![1, 6, 7]));
}

#[test]
fn collect_candidates_only_returns_matching_coefficient_rows() {
    // Pivot row 0, column 0 → pivot coefficient 5. Only rows whose column-0
    // entry equals 5 (and != pivot row) are candidates; the pivot row itself
    // and any other coefficient are excluded.
    let matrix = vec![
        vec![5, 1, 1], // pivot row (excluded)
        vec![5, 2, 2], // match
        vec![3, 9, 9], // different coeff (excluded)
        vec![0, 8, 8], // zero coeff (excluded)
        vec![5, 7, 7], // match
    ];
    let candidates = collect_batch_candidates(&matrix, 0, 0);

    assert_eq!(candidates.len(), 2);
    for (pivot_copy, cand) in &candidates {
        assert_eq!(
            pivot_copy, &matrix[0],
            "first tuple element is the pivot row"
        );
        assert_eq!(
            cand[0], matrix[0][0],
            "candidate must share the pivot column-0 coefficient"
        );
    }
}

#[test]
fn collect_candidates_fail_closed_on_zero_pivot_and_out_of_range() {
    // Zero pivot element → no elimination possible → empty.
    let zero_pivot = vec![vec![0, 1], vec![0, 2]];
    assert!(collect_batch_candidates(&zero_pivot, 0, 0).is_empty());

    // pivot_row out of range → empty (no panic).
    let m = vec![vec![1, 2], vec![3, 4]];
    assert!(collect_batch_candidates(&m, 99, 0).is_empty());

    // Empty matrix → empty (no panic).
    let empty: Vec<Vec<u8>> = Vec::new();
    assert!(collect_batch_candidates(&empty, 0, 0).is_empty());
}

// ---------------------------------------------------------------------------
// select_pivot_basic / select_pivot_markowitz: differential vs brute-force.
// ---------------------------------------------------------------------------

/// Brute-force oracle for `select_pivot_basic`: smallest row index in
/// `[start, min(end, len))` whose `col` entry is nonzero.
fn basic_oracle(rows: &[&[u8]], start: usize, end: usize, col: usize) -> Option<usize> {
    (start..end.min(rows.len())).find(|&r| rows[r].get(col).copied().unwrap_or(0) != 0)
}

/// Brute-force oracle for `select_pivot_markowitz`: among rows in
/// `[start, min(end, len))` with a nonzero `col` entry, pick the one with the
/// fewest nonzeros from `col` onward; ties broken by smallest row index.
/// Returns `(row, nnz_from_col)`.
fn markowitz_oracle(
    rows: &[&[u8]],
    start: usize,
    end: usize,
    col: usize,
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for (r, row) in rows
        .iter()
        .enumerate()
        .take(end.min(rows.len()))
        .skip(start)
    {
        if row.get(col).copied().unwrap_or(0) == 0 {
            continue;
        }
        let from = col.min(row.len());
        let nnz = row[from..].iter().filter(|&&b| b != 0).count();
        match best {
            Some((_, best_nnz)) if nnz >= best_nnz => {}
            _ => best = Some((r, nnz)),
        }
    }
    best
}

#[test]
fn pivot_selectors_match_brute_force_oracle() {
    let cols = 6usize;
    for n_rows in 0..7usize {
        for &density in &DENSITIES {
            for seed in 0..40u64 {
                let owned: Vec<Vec<u8>> = (0..n_rows)
                    .map(|i| random_row(cols, seed ^ (i as u64) << 4, density))
                    .collect();
                let rows: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

                // Sweep a representative set of (start, end, col) windows,
                // including degenerate ranges (start >= end) and an
                // out-of-bounds column.
                for col in 0..=cols {
                    for start in 0..=n_rows {
                        for end in 0..=n_rows {
                            let basic = select_pivot_basic(&rows, start, end, col);
                            assert_eq!(
                                basic,
                                basic_oracle(&rows, start, end, col),
                                "select_pivot_basic mismatch \
                                 (n={n_rows}, density={density}, seed={seed}, \
                                  start={start}, end={end}, col={col})"
                            );

                            let mark = select_pivot_markowitz(&rows, start, end, col);
                            let oracle = markowitz_oracle(&rows, start, end, col);
                            assert_eq!(
                                mark, oracle,
                                "select_pivot_markowitz mismatch \
                                 (n={n_rows}, density={density}, seed={seed}, \
                                  start={start}, end={end}, col={col})"
                            );

                            // The Markowitz winner, when present, must be a row
                            // the basic selector would also accept (nonzero at
                            // col) — the heuristics agree on *eligibility*.
                            if let Some((row, _)) = mark {
                                assert_ne!(
                                    rows[row].get(col).copied().unwrap_or(0),
                                    0,
                                    "markowitz returned a row with a zero pivot"
                                );
                                assert!(
                                    row >= start && row < end.min(n_rows),
                                    "markowitz row out of requested window"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Determinism: among equal-nonzero candidates, Markowitz must always return
/// the smallest row index, and basic must return the first nonzero row.
#[test]
fn pivot_selectors_break_ties_by_smallest_index() {
    // Col 0: row 0 has a zero pivot; rows 1,2,3 each have a single nonzero
    // (nnz_from_col == 1). The smallest eligible index is 1.
    // Col 1 is entirely zero → both selectors must report None.
    let owned = vec![vec![0u8, 0, 9], vec![3, 0, 0], vec![5, 0, 0], vec![7, 0, 0]];
    let rows: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

    assert_eq!(select_pivot_basic(&rows, 0, 4, 0), Some(1));
    assert_eq!(select_pivot_markowitz(&rows, 0, 4, 0), Some((1, 1)));

    // All-zero column → None from both.
    assert_eq!(select_pivot_basic(&rows, 0, 4, 1), None);
    assert_eq!(select_pivot_markowitz(&rows, 0, 4, 1), None);
}

#[test]
fn rank_profile_reports_stable_pivot_and_free_column_witnesses() {
    let first_order = [
        vec![0u8, 1, 1, 0],
        vec![1, 0, 1, 0],
        vec![1, 1, 0, 0], // dependent: row0 + row1 over GF(256)
        vec![0, 0, 0, 0],
    ];
    let second_order = [
        first_order[1].clone(),
        first_order[0].clone(),
        first_order[3].clone(),
        first_order[2].clone(),
    ];

    for rows in [&first_order, &second_order] {
        let row_refs = rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let profile = coefficient_rank_profile(&row_refs, 4);

        assert_eq!(profile.rows, 4);
        assert_eq!(profile.columns, 4);
        assert_eq!(profile.rank, 2);
        assert_eq!(profile.deficit, 2);
        assert_eq!(
            profile.pivot_columns,
            vec![0, 1],
            "rank profile should keep deterministic left-to-right pivot witnesses"
        );
        assert_eq!(
            profile.free_columns,
            vec![2, 3],
            "rank profile should expose every unsupported free column"
        );
    }
}

#[test]
fn rank_profile_is_stable_under_equivalent_row_space_presentations() {
    let canonical = [
        vec![1u8, 0, 0, 0],
        vec![0, 0, 1, 0],
        vec![1, 0, 1, 0],
        vec![0, 0, 0, 0],
    ];
    let scaled_and_permuted = [
        vec![0u8, 0, 9, 0],
        vec![7, 0, 9, 0],
        vec![7, 0, 0, 0],
        vec![0, 0, 0, 0],
    ];

    for rows in [&canonical, &scaled_and_permuted] {
        let row_refs = rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let profile = coefficient_rank_profile(&row_refs, 4);

        assert_eq!(profile.rows, 4);
        assert_eq!(profile.columns, 4);
        assert_eq!(profile.rank, 2);
        assert_eq!(profile.deficit, 2);
        assert_eq!(
            profile.pivot_columns,
            vec![0, 2],
            "equivalent row spaces should expose the same pivot witness"
        );
        assert_eq!(
            profile.free_columns,
            vec![1, 3],
            "equivalent row spaces should expose the same free-column witness"
        );
    }
}

fn rank_deficient_solver() -> GaussianSolver {
    let mut solver = GaussianSolver::new(3, 4);
    solver.set_row(0, &[1, 0, 0, 0], DenseRow::new(vec![0x10]));
    solver.set_row(1, &[0, 0, 1, 0], DenseRow::new(vec![0x20]));
    solver.set_row(2, &[1, 0, 1, 0], DenseRow::new(vec![0x30]));
    solver
}

fn solver_from_rows(rows: &[(&[u8], &[u8])], columns: usize) -> GaussianSolver {
    let mut solver = GaussianSolver::new(rows.len(), columns);
    for (row, (coefficients, rhs)) in rows.iter().enumerate() {
        solver.set_row(row, coefficients, DenseRow::new(rhs.to_vec()));
    }
    solver
}

fn solver_from_owned_rows(rows: &[(Vec<u8>, Vec<u8>)], columns: usize) -> GaussianSolver {
    let mut solver = GaussianSolver::new(rows.len(), columns);
    for (row, (coefficients, rhs)) in rows.iter().enumerate() {
        solver.set_row(row, coefficients, DenseRow::new(rhs.clone()));
    }
    solver
}

fn assert_solutions_match(
    expected_kind: GaussianOutcomeKind,
    a: &GaussianResult,
    b: &GaussianResult,
) {
    assert_eq!(a.outcome_kind(), expected_kind);
    assert_eq!(b.outcome_kind(), expected_kind);
    assert_eq!(
        a.is_solved(),
        matches!(expected_kind, GaussianOutcomeKind::Solved)
    );
    assert_eq!(
        b.is_solved(),
        matches!(expected_kind, GaussianOutcomeKind::Solved)
    );

    match (a, b) {
        (GaussianResult::Solved(a_solution), GaussianResult::Solved(b_solution)) => {
            assert_eq!(
                a_solution, b_solution,
                "basic and Markowitz pivoting must emit byte-identical payloads"
            );
        }
        _ => {
            assert!(
                !a.is_solved() && !b.is_solved(),
                "fail-closed outcomes must not expose partial payloads"
            );
        }
    }
}

fn equation_rhs(coefficients: &[u8], solution: &[Vec<u8>]) -> Vec<u8> {
    let width = solution.first().map_or(0, Vec::len);
    let mut rhs = vec![0u8; width];
    for (&coefficient, unknown) in coefficients.iter().zip(solution) {
        let c = Gf256::new(coefficient);
        for (dst, &value) in rhs.iter_mut().zip(unknown) {
            *dst ^= c.mul_field(Gf256::new(value)).raw();
        }
    }
    rhs
}

fn scaled_equation(coefficients: &[u8], rhs: &[u8], scale: u8) -> (Vec<u8>, Vec<u8>) {
    let s = Gf256::new(scale);
    let coefficients = coefficients
        .iter()
        .map(|&coefficient| s.mul_field(Gf256::new(coefficient)).raw())
        .collect();
    let rhs = rhs
        .iter()
        .map(|&value| s.mul_field(Gf256::new(value)).raw())
        .collect();
    (coefficients, rhs)
}

fn add_scaled_equation(
    lhs: &(Vec<u8>, Vec<u8>),
    rhs: &(Vec<u8>, Vec<u8>),
    rhs_scale: u8,
) -> (Vec<u8>, Vec<u8>) {
    let s = Gf256::new(rhs_scale);
    let coefficients = lhs
        .0
        .iter()
        .zip(&rhs.0)
        .map(|(&a, &b)| a ^ s.mul_field(Gf256::new(b)).raw())
        .collect();
    let rhs = lhs
        .1
        .iter()
        .zip(&rhs.1)
        .map(|(&a, &b)| a ^ s.mul_field(Gf256::new(b)).raw())
        .collect();
    (coefficients, rhs)
}

fn solved_payload(result: GaussianResult, label: &str) -> Vec<Vec<u8>> {
    match result {
        GaussianResult::Solved(rows) => rows
            .into_iter()
            .map(|row| row.as_slice().to_vec())
            .collect(),
        other => panic!("{label}: expected solved payload, got {other:?}"),
    }
}

#[test]
fn solver_rank_status_reports_deficit_before_fail_closed_solve() {
    let mut solver = rank_deficient_solver();
    let status = solver.rank_status();
    let profile = solver.rank_profile();

    assert_eq!(status.rows, 3);
    assert_eq!(status.columns, 4);
    assert_eq!(status.rank, 2);
    assert_eq!(status.deficit, 2);
    assert_eq!(profile.pivot_columns, vec![0, 2]);
    assert_eq!(profile.free_columns, vec![1, 3]);

    let result = solver.solve();
    assert_eq!(
        result,
        GaussianResult::Singular { row: 1 },
        "rank-deficient solver state must fail closed instead of emitting a payload"
    );
    assert!(!result.is_solved());
}

#[test]
fn markowitz_rank_status_matches_basic_and_fails_closed() {
    let basic = rank_deficient_solver();
    let mut markowitz = rank_deficient_solver();

    assert_eq!(basic.rank_status(), markowitz.rank_status());
    assert_eq!(basic.rank_profile(), markowitz.rank_profile());

    let result = markowitz.solve_markowitz();
    assert_eq!(
        result,
        GaussianResult::Singular { row: 1 },
        "Markowitz pivoting must preserve the same fail-closed rank-deficient outcome"
    );
    assert!(!result.is_solved());
}

#[test]
fn adversarial_solver_corpus_keeps_basic_and_markowitz_outcomes_aligned() {
    struct Case<'a> {
        name: &'a str,
        columns: usize,
        rows: Vec<(&'a [u8], &'a [u8])>,
        expected_rank: usize,
        expected_deficit: usize,
        expected_kind: GaussianOutcomeKind,
    }

    let full_rank_sparse_permuted = Case {
        name: "full_rank_sparse_permuted",
        columns: 3,
        rows: vec![
            (&[0, 1, 0], &[0x20]),
            (&[1, 0, 0], &[0x10]),
            (&[0, 0, 1], &[0x30]),
        ],
        expected_rank: 3,
        expected_deficit: 0,
        expected_kind: GaussianOutcomeKind::Solved,
    };
    let rank_deficient_consistent = Case {
        name: "rank_deficient_consistent",
        columns: 4,
        rows: vec![
            (&[1, 0, 0, 0], &[0x10]),
            (&[0, 0, 1, 0], &[0x20]),
            (&[1, 0, 1, 0], &[0x30]),
        ],
        expected_rank: 2,
        expected_deficit: 2,
        expected_kind: GaussianOutcomeKind::Singular,
    };
    let inconsistent_zero_row = Case {
        name: "inconsistent_zero_row",
        columns: 2,
        rows: vec![(&[1, 0], &[0x11]), (&[0, 0], &[0x22])],
        expected_rank: 1,
        expected_deficit: 1,
        expected_kind: GaussianOutcomeKind::Inconsistent,
    };
    let underdetermined_rows_less_than_columns = Case {
        name: "underdetermined_rows_less_than_columns",
        columns: 3,
        rows: vec![(&[1, 0, 0], &[0x01]), (&[0, 1, 0], &[0x02])],
        expected_rank: 2,
        expected_deficit: 1,
        expected_kind: GaussianOutcomeKind::Singular,
    };

    for case in [
        full_rank_sparse_permuted,
        rank_deficient_consistent,
        inconsistent_zero_row,
        underdetermined_rows_less_than_columns,
    ] {
        let mut basic = solver_from_rows(&case.rows, case.columns);
        let mut markowitz = solver_from_rows(&case.rows, case.columns);

        assert_eq!(
            basic.rank_status(),
            markowitz.rank_status(),
            "{}: pre-solve rank status must not depend on pivot strategy",
            case.name
        );
        assert_eq!(
            basic.rank_profile(),
            markowitz.rank_profile(),
            "{}: pre-solve rank witnesses must not depend on pivot strategy",
            case.name
        );
        assert_eq!(
            basic.rank_status().rank,
            case.expected_rank,
            "{}: rank mismatch",
            case.name
        );
        assert_eq!(
            basic.rank_status().deficit,
            case.expected_deficit,
            "{}: deficit mismatch",
            case.name
        );

        let basic_result = basic.solve();
        let markowitz_result = markowitz.solve_markowitz();
        assert_solutions_match(case.expected_kind, &basic_result, &markowitz_result);
    }
}

#[test]
fn pivot_strategies_reject_mixed_rhs_widths_even_when_coefficients_are_full_rank() {
    let rows = [
        (&[1u8, 0][..], &[0x11, 0x12][..]),
        (&[0u8, 1][..], &[0x21][..]),
    ];
    let mut basic = solver_from_rows(&rows, 2);
    let mut markowitz = solver_from_rows(&rows, 2);

    assert_eq!(basic.rank_status().rank, 2);
    assert_eq!(basic.rank_status().deficit, 0);
    assert_eq!(
        basic.rank_status(),
        markowitz.rank_status(),
        "coefficient rank is full before the RHS-width guard runs"
    );

    assert_eq!(
        basic.solve(),
        GaussianResult::Inconsistent { row: 1 },
        "basic pivoting must fail closed instead of padding or truncating RHS symbols"
    );
    assert_eq!(
        markowitz.solve_markowitz(),
        GaussianResult::Inconsistent { row: 1 },
        "Markowitz pivoting must enforce the same RHS-width guard"
    );
}

#[test]
fn inconsistent_rank_deficient_solve_preserves_rank_witness_after_failure() {
    let rows = [
        (&[1u8, 0, 0][..], &[0x10][..]),
        (&[0u8, 1, 0][..], &[0x20][..]),
        (&[1u8, 1, 0][..], &[0x40][..]),
    ];

    for (name, mut solver, solve) in [
        (
            "basic",
            solver_from_rows(&rows, 3),
            GaussianSolver::solve as fn(&mut GaussianSolver) -> GaussianResult,
        ),
        (
            "markowitz",
            solver_from_rows(&rows, 3),
            GaussianSolver::solve_markowitz,
        ),
    ] {
        let before = solver.rank_profile();
        assert_eq!(before.rank, 2, "{name}: fixture starts rank-deficient");
        assert_eq!(before.deficit, 1, "{name}: fixture has one free column");
        assert_eq!(before.pivot_columns, vec![0, 1]);
        assert_eq!(before.free_columns, vec![2]);

        assert_eq!(
            solve(&mut solver),
            GaussianResult::Inconsistent { row: 2 },
            "{name}: dependent row contradicts RHS and must fail closed"
        );

        let after = solver.rank_profile();
        assert_eq!(
            after, before,
            "{name}: failed solve must not pollute the coefficient-rank witness"
        );
    }
}

#[test]
fn full_rank_solver_payload_is_invariant_under_equivalent_row_presentations() {
    let expected_solution = vec![vec![0x10, 0x11], vec![0x20, 0x21], vec![0x30, 0x31]];
    let base_coefficients = [vec![1u8, 2, 3], vec![0, 1, 4], vec![0, 0, 1]];
    let base_rows: Vec<(Vec<u8>, Vec<u8>)> = base_coefficients
        .iter()
        .map(|coefficients| {
            (
                coefficients.clone(),
                equation_rhs(coefficients, &expected_solution),
            )
        })
        .collect();
    let scaled_permuted_rows = vec![
        scaled_equation(&base_rows[2].0, &base_rows[2].1, 9),
        scaled_equation(&base_rows[0].0, &base_rows[0].1, 7),
        scaled_equation(&base_rows[1].0, &base_rows[1].1, 5),
    ];
    let overdetermined_consistent_rows = vec![
        add_scaled_equation(&base_rows[0], &base_rows[1], 6),
        base_rows[2].clone(),
        scaled_equation(&base_rows[0].0, &base_rows[0].1, 3),
        base_rows[1].clone(),
    ];

    for (name, rows) in [
        ("base_triangular", base_rows),
        ("scaled_permuted", scaled_permuted_rows),
        ("overdetermined_consistent", overdetermined_consistent_rows),
    ] {
        let mut basic = solver_from_owned_rows(&rows, 3);
        let mut markowitz = solver_from_owned_rows(&rows, 3);

        assert_eq!(
            basic.rank_status().rank,
            3,
            "{name}: presentation must be full-rank before solve"
        );
        assert_eq!(
            basic.rank_status().deficit,
            0,
            "{name}: presentation must not report a rank deficit"
        );
        assert_eq!(
            basic.rank_status(),
            markowitz.rank_status(),
            "{name}: pivot strategy must not alter pre-solve rank"
        );

        let basic_payload = solved_payload(basic.solve(), name);
        let markowitz_payload = solved_payload(markowitz.solve_markowitz(), name);
        assert_eq!(
            basic_payload, expected_solution,
            "{name}: basic pivoting changed solved payload"
        );
        assert_eq!(
            markowitz_payload, expected_solution,
            "{name}: Markowitz pivoting changed solved payload"
        );
    }
}

#[test]
fn pivot_strategies_agree_on_deterministic_small_system_corpus() {
    for rows in 1..=5usize {
        for columns in 1..=4usize {
            for seed in 0..48u64 {
                let system_rows: Vec<(Vec<u8>, Vec<u8>)> = (0..rows)
                    .map(|row| {
                        let row_seed =
                            seed ^ ((rows as u64) << 48) ^ ((columns as u64) << 32) ^ row as u64;
                        (
                            random_row(columns, row_seed, 160),
                            random_row(2, row_seed ^ 0xD00D_F00D, 255),
                        )
                    })
                    .collect();

                let mut basic = solver_from_owned_rows(&system_rows, columns);
                let mut markowitz = solver_from_owned_rows(&system_rows, columns);

                assert_eq!(
                    basic.rank_status(),
                    markowitz.rank_status(),
                    "rank status changed by pivot strategy (rows={rows}, columns={columns}, seed={seed})"
                );

                let basic_result = basic.solve();
                let markowitz_result = markowitz.solve_markowitz();
                assert_eq!(
                    basic_result.outcome_kind(),
                    markowitz_result.outcome_kind(),
                    "pivot strategies classified the same system differently \
                     (rows={rows}, columns={columns}, seed={seed}, \
                      basic={basic_result:?}, markowitz={markowitz_result:?})"
                );

                match (&basic_result, &markowitz_result) {
                    (
                        GaussianResult::Solved(basic_payload),
                        GaussianResult::Solved(markowitz_payload),
                    ) => {
                        assert_eq!(
                            basic_payload, markowitz_payload,
                            "pivot strategies solved to different payloads \
                             (rows={rows}, columns={columns}, seed={seed})"
                        );
                    }
                    _ => {
                        assert!(
                            !basic_result.is_solved() && !markowitz_result.is_solved(),
                            "unsolved classifications must not expose payloads \
                             (rows={rows}, columns={columns}, seed={seed})"
                        );
                    }
                }
            }
        }
    }
}
