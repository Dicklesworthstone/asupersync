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
    coefficient_rank_profile, collect_batch_candidates, row_scale_add, row_scale_add_batch_multi,
    row_scale_add_batch2, select_pivot_basic, select_pivot_markowitz,
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
