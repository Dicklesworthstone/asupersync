//! Conformance harness for `asupersync::trace::boundary`.
//!
//! `trace::boundary` builds the square cell complex (vertices / causality
//! edges / commuting diamonds) and its GF(2) boundary operators ∂₁ and ∂₂.
//! Those matrices feed `BoundaryMatrix::reduce` and the persistent-homology
//! scoring pipeline. The module has a defining mathematical contract:
//!
//! > **∂₁ ∘ ∂₂ = 0** — the boundary of a boundary is zero.
//!
//! This is the chain-complex law. Any bug in square detection
//! (`from_edges`), edge indexing (`edge_index`), or matrix assembly
//! (`boundary_1` / `boundary_2`) breaks it. The inline unit tests verify it
//! on a handful of hand-built complexes; this harness verifies it on a swept
//! corpus of *randomly generated* complexes, and additionally pins:
//!
//! - `matmul_gf2` ring algebra: A·0 = 0, A·I = A, I·A = A, left/right
//!   distributivity over matrix XOR, and associativity (A·B)·C = A·(B·C).
//! - `SquareComplex` structural invariants: edges sorted/deduped/forward and
//!   in range; squares sorted/deduped with `a < b < c < d`; every square's
//!   four edges present in the edge list.
//! - Boundary-matrix shape and column-weight invariants (∂₁ columns have
//!   exactly 2 ones, ∂₂ columns exactly 4, the combined matrix has the
//!   vertex/edge/square block weights 0/2/4).
//! - Determinism: `from_edges` is invariant under input edge permutation and
//!   duplication.
//! - `h1_persistence_pairs` confines births to the edge block and deaths to
//!   the square block.
//!
//! Inputs come from a deterministic in-test SplitMix64 generator so any
//! failure reproduces from its printed seed; no `proptest` dependency. A
//! non-vacuity guard asserts the random corpus actually exercises squares.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_lines)]

use asupersync::trace::{BitVec, BoundaryMatrix, SquareComplex, matmul_gf2};

// ---------------------------------------------------------------------------
// Deterministic generation
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bool_with(&mut self, ones_in_64: u32) -> bool {
        (self.next_u64() & 63) < u64::from(ones_in_64)
    }
}

/// Generate a random forward-edge set over `n` vertices. Every candidate pair
/// `(s, t)` with `s < t` is included with probability `density/64`. This is a
/// random DAG (all edges point forward), exactly the shape `from_edges`
/// expects, and dense enough that commuting diamonds appear frequently.
fn gen_edges(rng: &mut Rng, n: usize, density: u32) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for s in 0..n {
        for t in (s + 1)..n {
            if rng.bool_with(density) {
                edges.push((s, t));
            }
        }
    }
    edges
}

/// Generate a random dense GF(2) matrix.
fn gen_matrix(rng: &mut Rng, rows: usize, cols: usize, density: u32) -> BoundaryMatrix {
    let mut m = BoundaryMatrix::zeros(rows, cols);
    for j in 0..cols {
        for i in 0..rows {
            if rng.bool_with(density) {
                m.set(i, j);
            }
        }
    }
    m
}

// ---------------------------------------------------------------------------
// Small linear-algebra helpers (kept test-local; the module ships only matmul)
// ---------------------------------------------------------------------------

/// `n x n` identity matrix over GF(2).
fn identity(n: usize) -> BoundaryMatrix {
    let mut m = BoundaryMatrix::zeros(n, n);
    for i in 0..n {
        m.set(i, i);
    }
    m
}

/// Column-wise XOR of two equally-shaped matrices (addition in GF(2)).
fn mat_xor(a: &BoundaryMatrix, b: &BoundaryMatrix) -> BoundaryMatrix {
    assert_eq!(a.rows(), b.rows());
    assert_eq!(a.cols(), b.cols());
    let mut result = a.clone();
    for j in 0..a.cols() {
        let bc = b.column(j).clone();
        result.column_mut(j).xor_assign(&bc);
    }
    result
}

fn matrices_equal(a: &BoundaryMatrix, b: &BoundaryMatrix) -> bool {
    a.rows() == b.rows()
        && a.cols() == b.cols()
        && (0..a.cols()).all(|j| a.column(j) == b.column(j))
}

fn is_zero_matrix(m: &BoundaryMatrix) -> bool {
    (0..m.cols()).all(|j| m.column(j).is_zero())
}

/// Vertex counts / densities swept by the complex-level relations.
const COMPLEX_CASES: &[(usize, u32)] = &[
    (4, 40),
    (5, 36),
    (6, 32),
    (8, 26),
    (10, 22),
    (12, 18),
    (16, 14),
    (20, 12),
];

// ===========================================================================
// The chain-complex law: ∂₁ ∘ ∂₂ = 0
// ===========================================================================

#[test]
fn boundary_of_boundary_is_zero_on_random_complexes() {
    let mut complexes_with_squares = 0usize;
    let mut total_squares = 0usize;

    for &(n, density) in COMPLEX_CASES {
        for seed in 0..40u64 {
            let mut rng = Rng::new(seed ^ 0xD1D2 ^ (n as u64) << 20);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);

            let d1 = cx.boundary_1();
            let d2 = cx.boundary_2();
            let product = matmul_gf2(&d1, &d2);

            assert!(
                is_zero_matrix(&product),
                "∂₁∘∂₂ != 0 (n={n}, density={density}, seed={seed}): \
                 {} squares, product cols={}",
                cx.squares.len(),
                product.cols()
            );

            if !cx.squares.is_empty() {
                complexes_with_squares += 1;
                total_squares += cx.squares.len();
            }
        }
    }

    // Non-vacuity: the random corpus must actually exercise ∂₂ columns,
    // otherwise ∂₁∘∂₂=0 holds trivially and proves nothing.
    assert!(
        complexes_with_squares >= 50,
        "random corpus produced too few complexes with squares ({complexes_with_squares}); \
         the chain-complex test would be near-vacuous"
    );
    assert!(
        total_squares >= 100,
        "too few total squares: {total_squares}"
    );
}

#[test]
fn boundary_of_boundary_is_zero_on_grid_lattices() {
    // Deterministic m x m diamond lattices of increasing size — these are
    // dense in commuting squares, so they stress edge_index heavily.
    for m in 2..=7usize {
        let idx = |i: usize, j: usize| i * m + j;
        let mut edges = Vec::new();
        for i in 0..m {
            for j in 0..m {
                if j + 1 < m {
                    edges.push((idx(i, j), idx(i, j + 1)));
                }
                if i + 1 < m {
                    edges.push((idx(i, j), idx(i + 1, j)));
                }
            }
        }
        let cx = SquareComplex::from_edges(m * m, edges);
        let expected_squares = (m - 1) * (m - 1);
        assert_eq!(
            cx.squares.len(),
            expected_squares,
            "{m}x{m} lattice should have {expected_squares} squares"
        );

        let product = matmul_gf2(&cx.boundary_1(), &cx.boundary_2());
        assert!(is_zero_matrix(&product), "∂₁∘∂₂ != 0 on {m}x{m} lattice");
    }
}

#[test]
fn combined_matrix_squares_to_zero() {
    // In the combined filtration matrix, ∂∘∂ = 0 as well: applying the
    // boundary operator twice annihilates every column.
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..20u64 {
            let mut rng = Rng::new(seed ^ 0xC0DE ^ (n as u64) << 20);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);
            let combined = cx.combined_boundary_matrix();
            let squared = matmul_gf2(&combined, &combined);
            assert!(
                is_zero_matrix(&squared),
                "∂∘∂ != 0 on combined matrix (n={n}, seed={seed})"
            );
        }
    }
}

// ===========================================================================
// matmul_gf2 — ring algebra
// ===========================================================================

#[test]
fn matmul_by_zero_is_zero() {
    for (rows, mid, cols) in [(3, 4, 5), (8, 8, 8), (1, 10, 2), (16, 4, 9)] {
        let mut rng = Rng::new(0x5A5A ^ (rows as u64) << 8 ^ cols as u64);
        let a = gen_matrix(&mut rng, rows, mid, 20);
        let zero_right = BoundaryMatrix::zeros(mid, cols);
        let zero_left = BoundaryMatrix::zeros(cols, rows);

        assert!(is_zero_matrix(&matmul_gf2(&a, &zero_right)), "A·0 != 0");
        assert!(is_zero_matrix(&matmul_gf2(&zero_left, &a)), "0·A != 0");
    }
}

#[test]
fn matmul_by_identity_is_identity() {
    for (rows, cols) in [(1, 1), (3, 5), (8, 8), (12, 4), (5, 20)] {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0x1D1D ^ (rows as u64) << 12 ^ cols as u64);
            let a = gen_matrix(&mut rng, rows, cols, 18);
            // A·I_cols == A
            assert!(
                matrices_equal(&matmul_gf2(&a, &identity(cols)), &a),
                "A·I != A ({rows}x{cols}, seed={seed})"
            );
            // I_rows·A == A
            assert!(
                matrices_equal(&matmul_gf2(&identity(rows), &a), &a),
                "I·A != A ({rows}x{cols}, seed={seed})"
            );
        }
    }
}

#[test]
fn matmul_is_left_distributive_over_xor() {
    // A·(B ⊕ C) == (A·B) ⊕ (A·C)
    for (rows, mid, cols) in [(3, 4, 5), (8, 6, 7), (10, 10, 10), (16, 3, 12)] {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0x1EF7 ^ (rows as u64) << 16);
            let a = gen_matrix(&mut rng, rows, mid, 16);
            let b = gen_matrix(&mut rng, mid, cols, 16);
            let c = gen_matrix(&mut rng, mid, cols, 16);

            let lhs = matmul_gf2(&a, &mat_xor(&b, &c));
            let rhs = mat_xor(&matmul_gf2(&a, &b), &matmul_gf2(&a, &c));
            assert!(
                matrices_equal(&lhs, &rhs),
                "left distributivity failed ({rows}x{mid}x{cols}, seed={seed})"
            );
        }
    }
}

#[test]
fn matmul_is_right_distributive_over_xor() {
    // (A ⊕ B)·C == (A·C) ⊕ (B·C)
    for (rows, mid, cols) in [(3, 4, 5), (8, 6, 7), (10, 10, 10), (12, 5, 16)] {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0x416B ^ (mid as u64) << 16);
            let a = gen_matrix(&mut rng, rows, mid, 16);
            let b = gen_matrix(&mut rng, rows, mid, 16);
            let c = gen_matrix(&mut rng, mid, cols, 16);

            let lhs = matmul_gf2(&mat_xor(&a, &b), &c);
            let rhs = mat_xor(&matmul_gf2(&a, &c), &matmul_gf2(&b, &c));
            assert!(
                matrices_equal(&lhs, &rhs),
                "right distributivity failed ({rows}x{mid}x{cols}, seed={seed})"
            );
        }
    }
}

#[test]
fn matmul_is_associative() {
    // (A·B)·C == A·(B·C)
    for (r, m, p, q) in [(3, 4, 5, 2), (6, 6, 6, 6), (10, 3, 8, 5), (16, 5, 4, 12)] {
        for seed in 0..8u64 {
            let mut rng = Rng::new(seed ^ 0xA550_u64 ^ (r as u64) << 20);
            let a = gen_matrix(&mut rng, r, m, 16);
            let b = gen_matrix(&mut rng, m, p, 16);
            let c = gen_matrix(&mut rng, p, q, 16);

            let lhs = matmul_gf2(&matmul_gf2(&a, &b), &c);
            let rhs = matmul_gf2(&a, &matmul_gf2(&b, &c));
            assert!(
                matrices_equal(&lhs, &rhs),
                "associativity failed ({r}x{m}x{p}x{q}, seed={seed})"
            );
        }
    }
}

#[test]
fn matmul_result_has_expected_shape() {
    for (rows, mid, cols) in [(1, 1, 1), (3, 7, 2), (9, 4, 11), (20, 5, 6)] {
        let mut rng = Rng::new(0x5417 ^ (rows as u64) << 8);
        let a = gen_matrix(&mut rng, rows, mid, 20);
        let b = gen_matrix(&mut rng, mid, cols, 20);
        let prod = matmul_gf2(&a, &b);
        assert_eq!(prod.rows(), rows, "result row count");
        assert_eq!(prod.cols(), cols, "result col count");
    }
}

// ===========================================================================
// SquareComplex — structural invariants
// ===========================================================================

#[test]
fn edges_are_sorted_deduped_forward_and_in_range() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..24u64 {
            let mut rng = Rng::new(seed ^ 0xED9E ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);

            let mut prev: Option<(usize, usize)> = None;
            for &(s, t) in &cx.edges {
                assert!(s < t, "edge ({s},{t}) not forward");
                assert!(t < n, "edge ({s},{t}) out of range (n={n})");
                if let Some(p) = prev {
                    assert!(p < (s, t), "edges not strictly sorted: {p:?} !< ({s},{t})");
                }
                prev = Some((s, t));
            }
        }
    }
}

#[test]
fn squares_are_sorted_deduped_and_strictly_ordered() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..24u64 {
            let mut rng = Rng::new(seed ^ 0x5C5C ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);

            let mut prev: Option<(usize, usize, usize, usize)> = None;
            for &(a, b, c, d) in &cx.squares {
                // a→b, a→c, b→d, c→d with b<c gives the chain a<b<c<d.
                assert!(a < b, "square ({a},{b},{c},{d}): a !< b");
                assert!(b < c, "square ({a},{b},{c},{d}): b !< c");
                assert!(c < d, "square ({a},{b},{c},{d}): c !< d");
                if let Some(p) = prev {
                    assert!(
                        p < (a, b, c, d),
                        "squares not strictly sorted: {p:?} !< ({a},{b},{c},{d})"
                    );
                }
                prev = Some((a, b, c, d));
            }
        }
    }
}

#[test]
fn every_square_edge_is_present_in_the_edge_list() {
    // A square (a,b,c,d) claims four edges. Each must actually exist in the
    // complex — otherwise boundary_2's edge_index would panic and the square
    // is spurious.
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..24u64 {
            let mut rng = Rng::new(seed ^ 0x9E5C ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);

            for &(a, b, c, d) in &cx.squares {
                for edge in [(a, b), (a, c), (b, d), (c, d)] {
                    assert!(
                        cx.edges.binary_search(&edge).is_ok(),
                        "square ({a},{b},{c},{d}) references missing edge {edge:?}"
                    );
                }
            }
            // boundary_2 internally calls edge_index for all four edges; if any
            // were missing it would panic. Exercise it explicitly.
            let _ = cx.boundary_2();
        }
    }
}

#[test]
fn boundary_1_shape_and_column_weights() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xB001 ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);
            let d1 = cx.boundary_1();

            assert_eq!(d1.rows(), n, "∂₁ row count");
            assert_eq!(d1.cols(), cx.edges.len(), "∂₁ col count");
            for (col, &(s, t)) in cx.edges.iter().enumerate() {
                assert_eq!(
                    d1.column(col).count_ones(),
                    2,
                    "∂₁ column {col} should have exactly 2 ones"
                );
                assert!(d1.get(s, col) && d1.get(t, col), "∂₁ column {col} bits");
            }
        }
    }
}

#[test]
fn boundary_2_shape_and_column_weights() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xB002 ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);
            let d2 = cx.boundary_2();

            assert_eq!(d2.rows(), cx.edges.len(), "∂₂ row count");
            assert_eq!(d2.cols(), cx.squares.len(), "∂₂ col count");
            for col in 0..d2.cols() {
                assert_eq!(
                    d2.column(col).count_ones(),
                    4,
                    "∂₂ column {col} should have exactly 4 ones (4 distinct edges)"
                );
            }
        }
    }
}

#[test]
fn combined_matrix_block_structure() {
    // Combined matrix is square; vertex columns are empty, edge columns carry
    // weight 2, square columns carry weight 4.
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xB003 ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);
            let combined = cx.combined_boundary_matrix();

            let edge_start = n;
            let square_start = edge_start + cx.edges.len();
            let total = square_start + cx.squares.len();
            assert_eq!(combined.rows(), total, "combined matrix not square (rows)");
            assert_eq!(combined.cols(), total, "combined matrix not square (cols)");

            for col in 0..total {
                let weight = combined.column(col).count_ones();
                let expected = if col < edge_start {
                    0 // vertices have no boundary
                } else if col < square_start {
                    2 // edges → 2 vertices
                } else {
                    4 // squares → 4 edges
                };
                assert_eq!(
                    weight, expected,
                    "combined column {col} weight {weight} != {expected}"
                );
            }
        }
    }
}

// ===========================================================================
// Determinism / permutation invariance
// ===========================================================================

#[test]
fn from_edges_is_invariant_under_input_permutation() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..24u64 {
            let mut rng = Rng::new(seed ^ 0x9E9E ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let baseline = SquareComplex::from_edges(n, edges.clone());

            // Fisher-Yates shuffle the input edge order.
            let mut shuffled = edges.clone();
            for i in (1..shuffled.len()).rev() {
                let j = rng.below(i + 1);
                shuffled.swap(i, j);
            }
            let permuted = SquareComplex::from_edges(n, shuffled);

            assert_eq!(
                baseline.edges, permuted.edges,
                "edges differ under permutation"
            );
            assert_eq!(
                baseline.squares, permuted.squares,
                "squares differ under permutation (n={n}, seed={seed})"
            );
        }
    }
}

#[test]
fn from_edges_is_idempotent_under_duplicate_edges() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..16u64 {
            let mut rng = Rng::new(seed ^ 0xD0D0 ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let baseline = SquareComplex::from_edges(n, edges.clone());

            // Duplicate every edge, plus a few malformed entries that must be
            // discarded (self-loops, backward, out of range).
            let mut noisy = edges.clone();
            noisy.extend(edges.iter().copied());
            noisy.push((0, 0)); // self-loop
            if n >= 2 {
                noisy.push((1, 0)); // backward
            }
            noisy.push((n + 5, 0)); // out of range
            let cleaned = SquareComplex::from_edges(n, noisy);

            assert_eq!(
                baseline.edges, cleaned.edges,
                "edges differ after dedup/clean"
            );
            assert_eq!(
                baseline.squares, cleaned.squares,
                "squares differ after dedup"
            );
        }
    }
}

// ===========================================================================
// h1_persistence_pairs — index-range confinement
// ===========================================================================

#[test]
fn h1_persistence_pairs_are_confined_to_edge_and_square_blocks() {
    for &(n, density) in COMPLEX_CASES {
        for seed in 0..30u64 {
            let mut rng = Rng::new(seed ^ 0x4111 ^ (n as u64) << 18);
            let edges = gen_edges(&mut rng, n, density);
            let cx = SquareComplex::from_edges(n, edges);

            let edge_start = n;
            let edge_end = edge_start + cx.edges.len();
            let square_start = edge_end;
            let square_end = square_start + cx.squares.len();

            let pairs = cx.h1_persistence_pairs();
            for &(birth, death) in &pairs.pairs {
                assert!(
                    (edge_start..edge_end).contains(&birth),
                    "H1 birth {birth} not in edge block [{edge_start},{edge_end})"
                );
                assert!(
                    (square_start..square_end).contains(&death),
                    "H1 death {death} not in square block [{square_start},{square_end})"
                );
            }
            for &birth in &pairs.unpaired {
                assert!(
                    (edge_start..edge_end).contains(&birth),
                    "unpaired H1 birth {birth} not in edge block"
                );
            }
        }
    }
}

#[test]
fn unfilled_cycles_carry_persistent_h1_classes() {
    // A simple k-cycle (drawn as a forward fan with a long back-edge) that has
    // no filling square must contribute at least one unpaired H1 class.
    // Concretely: an unfilled triangle on vertices {0,1,2}.
    for n in 3..=12usize {
        let cx = SquareComplex::from_edges(n, vec![(0, 1), (0, 2), (1, 2)]);
        assert!(cx.squares.is_empty(), "triangle should have no squares");
        let pairs = cx.h1_persistence_pairs();
        assert!(
            pairs.pairs.is_empty(),
            "unfilled triangle has no H1 deaths (n={n})"
        );
        assert_eq!(
            pairs.unpaired.len(),
            1,
            "unfilled triangle must carry exactly one persistent H1 class (n={n})"
        );
    }
}

#[test]
fn filled_square_kills_its_h1_cycle() {
    // The diamond (0,1,2,3) plus a tail edge: the square fills the 1-cycle,
    // so there is a finite H1 pair and no surviving unpaired class.
    let cx = SquareComplex::from_edges(5, vec![(0, 1), (0, 2), (1, 3), (2, 3), (3, 4)]);
    assert_eq!(cx.squares.len(), 1, "expected exactly one filling square");
    let pairs = cx.h1_persistence_pairs();
    assert_eq!(
        pairs.pairs.len(),
        1,
        "filled square should yield one H1 death"
    );
    assert!(
        pairs.unpaired.is_empty(),
        "the square should kill the only H1 class"
    );
}

// ===========================================================================
// Empty / degenerate complexes
// ===========================================================================

#[test]
fn degenerate_complexes_do_not_panic() {
    // Empty, vertices-only, single-edge, and edge-free complexes must produce
    // well-shaped (possibly empty) matrices and zero ∂₁∘∂₂.
    let cases: &[(usize, Vec<(usize, usize)>)] = &[
        (0, vec![]),
        (1, vec![]),
        (5, vec![]),
        (2, vec![(0, 1)]),
        (3, vec![(0, 1), (1, 2)]),
    ];
    for (n, edges) in cases {
        let cx = SquareComplex::from_edges(*n, edges.clone());
        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();
        assert_eq!(d1.rows(), *n);
        assert_eq!(d1.cols(), cx.edges.len());
        assert_eq!(d2.rows(), cx.edges.len());
        assert_eq!(d2.cols(), cx.squares.len());

        let product = matmul_gf2(&d1, &d2);
        assert!(is_zero_matrix(&product), "∂₁∘∂₂ != 0 for n={n}");

        // h1 pairs on a degenerate complex must be empty or edge/square-confined.
        let pairs = cx.h1_persistence_pairs();
        for &(birth, death) in &pairs.pairs {
            assert!(birth >= *n, "degenerate H1 birth {birth} below edge block");
            let _ = death;
        }
    }
}

// ===========================================================================
// BitVec sanity used by the helpers above (guards the test's own assumptions)
// ===========================================================================

#[test]
fn test_helpers_identity_and_mat_xor_are_correct() {
    // identity() really is the multiplicative identity for a tiny known case.
    let id = identity(3);
    for i in 0..3 {
        for j in 0..3 {
            assert_eq!(id.get(i, j), i == j, "identity entry ({i},{j})");
        }
    }
    // mat_xor is self-inverse: (A ⊕ B) ⊕ B == A.
    let mut rng = Rng::new(0x4E1B);
    let a = gen_matrix(&mut rng, 4, 4, 24);
    let b = gen_matrix(&mut rng, 4, 4, 24);
    assert!(matrices_equal(&mat_xor(&mat_xor(&a, &b), &b), &a));
    // XOR with self is the zero matrix.
    assert!(is_zero_matrix(&mat_xor(&a, &a)));
    let _ = BitVec::zeros(0); // touch the BitVec import for the degenerate path
}
