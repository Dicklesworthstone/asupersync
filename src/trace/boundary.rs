//! Boundary operators ∂₂ and ∂₁ for the square cell complex.
//!
//! # Proxy Representation Choice (bd-3tz9)
//!
//! We use a **local commutation proxy** where:
//!
//! - **0-cells (vertices):** trace events, indexed by sequence number.
//! - **1-cells (edges):** causality edges from the `TracePoset` (dependency DAG).
//! - **2-cells (squares):** commuting diamonds where two independent events
//!   can be swapped without affecting the final state.
//!
//! ## Alternatives Considered
//!
//! | Representation | Complexity | Deterministic | Rationale |
//! |----------------|------------|---------------|-----------|
//! | Full schedules (linearizations) | O(n!) | Yes | Exponential; infeasible for >20 events |
//! | Prefixes / antichains (configurations) | O(2^w) where w=width | Yes | Exponential in antichain width |
//! | **Local commutation proxy** | **O(n² · d)** | **Yes** | Polynomial; directly from TracePoset + independence |
//!
//! Where `n` = event count, `d` = max out-degree in the dependency DAG.
//!
//! ## Complexity Bounds
//!
//! - **0-cells:** O(n) — one per event.
//! - **1-cells:** O(n²) worst case, O(n·d) typical — one per dependency edge.
//! - **2-cells:** O(n² · d) worst case — one per commuting diamond.
//! - **Construction:** O(n² · d) — scan all (b,c) pairs per vertex a.
//! - **∂₂ matrix:** rows = edges, cols = squares, O(4·|squares|) entries.
//! - **∂₁ matrix:** rows = vertices, cols = edges, O(2·|edges|) entries.
//!
//! ## Why This Works for Prioritization
//!
//! The Betti numbers β₀, β₁ computed from this complex measure:
//! - β₀: connected components (independent execution groups)
//! - β₁: "holes" (scheduling choices that cannot be eliminated by commutation)
//!
//! Higher β₁ means more non-trivial scheduling freedom → more exploration
//! value → higher priority for DPOR exploration.
//!
//! # Cell Ordering
//!
//! All cells are ordered deterministically:
//! - Vertices by index.
//! - Edges lexicographically by `(source, target)`.
//! - Squares lexicographically by `(top_left, top_right, bottom_left, bottom_right)`.

use crate::trace::event_structure::TracePoset;
use crate::trace::gf2::{BoundaryMatrix, PersistencePairs};

/// A square cell complex with deterministic cell ordering.
#[derive(Debug, Clone)]
pub struct SquareComplex {
    /// Number of vertices (0-cells).
    pub num_vertices: usize,
    /// Edges (1-cells) as sorted `(source, target)` pairs with `source < target`.
    pub edges: Vec<(usize, usize)>,
    /// Squares (2-cells) as `(a, b, c, d)` where:
    /// - `a→b`, `a→c`, `b→d`, `c→d` are all edges
    /// - `a < b`, `a < c`, `b < d`, `c < d`
    /// - `b < c` (canonical ordering to avoid duplicates)
    pub squares: Vec<(usize, usize, usize, usize)>,
}

impl SquareComplex {
    /// Build a square complex from an adjacency relation.
    ///
    /// `num_vertices` is the number of 0-cells.
    /// `edges` is a list of directed edges `(i, j)` with `i < j`.
    /// Malformed edges with out-of-range or non-forward endpoints are discarded.
    ///
    /// Squares are detected as commuting diamonds: four vertices `a < b, c < d`
    /// with edges `a→b`, `a→c`, `b→d`, `c→d` and canonical order `b < c`.
    #[must_use]
    pub fn from_edges(num_vertices: usize, mut edges: Vec<(usize, usize)>) -> Self {
        edges.retain(|&(s, t)| s < num_vertices && t < num_vertices && s < t);

        // Sort edges for determinism and binary search.
        edges.sort_unstable();
        edges.dedup();

        // Build adjacency: successors[v] = sorted list of targets.
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); num_vertices];
        for &(s, t) in &edges {
            succs[s].push(t);
        }
        for s in &mut succs {
            s.sort_unstable();
            s.dedup();
        }

        // Detect squares: for each vertex `a`, look at pairs (b, c) in succs[a]
        // with b < c, and check if there exists `d` in succs[b] ∩ succs[c].
        let mut squares = Vec::new();
        for a in 0..num_vertices {
            let sa = &succs[a];
            for (ib, &b) in sa.iter().enumerate() {
                for &c in &sa[ib + 1..] {
                    // b < c guaranteed by sorted order
                    // Find common successors of b and c
                    let sb = &succs[b];
                    let sc = &succs[c];
                    let mut jb = 0;
                    let mut jc = 0;
                    while jb < sb.len() && jc < sc.len() {
                        match sb[jb].cmp(&sc[jc]) {
                            std::cmp::Ordering::Less => jb += 1,
                            std::cmp::Ordering::Greater => jc += 1,
                            std::cmp::Ordering::Equal => {
                                let d = sb[jb];
                                squares.push((a, b, c, d));
                                jb += 1;
                                jc += 1;
                            }
                        }
                    }
                }
            }
        }
        squares.sort_unstable();

        Self {
            num_vertices,
            edges,
            squares,
        }
    }

    /// Build a square complex from a [`TracePoset`].
    ///
    /// Extracts the dependency edges from the poset and constructs the
    /// commutation complex. The resulting cell ordering is deterministic.
    #[must_use]
    pub fn from_trace_poset(poset: &TracePoset) -> Self {
        let n = poset.len();
        let mut edges = Vec::new();
        for i in 0..n {
            for &j in poset.succs(i) {
                edges.push((i, j));
            }
        }
        Self::from_edges(n, edges)
    }

    /// Edge index lookup. Returns the column index for edge `(s, t)`.
    fn edge_index(&self, s: usize, t: usize) -> usize {
        self.edges
            .binary_search(&(s, t))
            .unwrap_or_else(|_| panic!("edge ({s}, {t}) not in complex"))
    }

    /// Build the boundary operator ∂₁: edges → vertices.
    ///
    /// For edge `(s, t)`, the boundary is `∂₁(s→t) = s + t` (over GF(2)).
    /// The matrix has `num_vertices` rows and `edges.len()` columns.
    #[must_use]
    pub fn boundary_1(&self) -> BoundaryMatrix {
        let mut d1 = BoundaryMatrix::zeros(self.num_vertices, self.edges.len());
        for (col, &(s, t)) in self.edges.iter().enumerate() {
            d1.set(s, col);
            d1.set(t, col);
        }
        d1
    }

    /// Build the boundary operator ∂₂: squares → edges.
    ///
    /// For square `(a, b, c, d)`, the boundary is
    /// `∂₂ = (a→b) + (a→c) + (b→d) + (c→d)` (over GF(2)).
    /// The matrix has `edges.len()` rows and `squares.len()` columns.
    #[must_use]
    pub fn boundary_2(&self) -> BoundaryMatrix {
        let mut d2 = BoundaryMatrix::zeros(self.edges.len(), self.squares.len());
        for (col, &(a, b, c, d)) in self.squares.iter().enumerate() {
            d2.set(self.edge_index(a, b), col);
            d2.set(self.edge_index(a, c), col);
            d2.set(self.edge_index(b, d), col);
            d2.set(self.edge_index(c, d), col);
        }
        d2
    }

    /// Build the full filtration boundary matrix for vertices, edges, and squares.
    ///
    /// The filtration order is:
    /// 1. Vertices `0..num_vertices`
    /// 2. Edges `num_vertices..num_vertices + edges.len()`
    /// 3. Squares after the edge block
    ///
    /// This ordering preserves the dimension boundaries needed to separate H0
    /// from H1 persistence classes after reduction.
    #[must_use]
    pub fn combined_boundary_matrix(&self) -> BoundaryMatrix {
        let edge_offset = self.num_vertices;
        let square_offset = edge_offset + self.edges.len();
        let total_cells = square_offset + self.squares.len();
        let mut matrix = BoundaryMatrix::zeros(total_cells, total_cells);

        for (edge_idx, &(s, t)) in self.edges.iter().enumerate() {
            let col = edge_offset + edge_idx;
            matrix.set(s, col);
            matrix.set(t, col);
        }

        for (square_idx, &(a, b, c, d)) in self.squares.iter().enumerate() {
            let col = square_offset + square_idx;
            matrix.set(edge_offset + self.edge_index(a, b), col);
            matrix.set(edge_offset + self.edge_index(a, c), col);
            matrix.set(edge_offset + self.edge_index(b, d), col);
            matrix.set(edge_offset + self.edge_index(c, d), col);
        }

        matrix
    }

    /// Compute H1 persistence pairs from the full filtration.
    ///
    /// The reduced matrix contains classes from every dimension. We only keep
    /// H1 classes here:
    /// - births on edge columns
    /// - deaths on square columns
    /// - unpaired edge births that persist to infinity
    #[must_use]
    pub fn h1_persistence_pairs(&self) -> PersistencePairs {
        let edge_start = self.num_vertices;
        let edge_end = edge_start + self.edges.len();
        let square_start = edge_end;
        let square_end = square_start + self.squares.len();

        let reduced = self.combined_boundary_matrix().reduce();
        let pairs = reduced.persistence_pairs();

        PersistencePairs {
            pairs: pairs
                .pairs
                .into_iter()
                .filter(|&(birth, death)| {
                    (edge_start..edge_end).contains(&birth)
                        && (square_start..square_end).contains(&death)
                })
                .collect(),
            unpaired: pairs
                .unpaired
                .into_iter()
                .filter(|birth| (edge_start..edge_end).contains(birth))
                .collect(),
        }
    }
}

/// Multiply two GF(2) boundary matrices: result = A * B.
///
/// `A` has dimensions `(r, m)` and `B` has dimensions `(m, c)`.
/// The result has dimensions `(r, c)`.
#[must_use]
pub fn matmul_gf2(a: &BoundaryMatrix, b: &BoundaryMatrix) -> BoundaryMatrix {
    assert_eq!(
        a.cols(),
        b.rows(),
        "matmul dimension mismatch: A is {}x{}, B is {}x{}",
        a.rows(),
        a.cols(),
        b.rows(),
        b.cols()
    );
    let mut result = BoundaryMatrix::zeros(a.rows(), b.cols());
    for j in 0..b.cols() {
        // result column j = A * (column j of B)
        // = XOR of A's columns where B's column j has a 1
        for row_of_b in b.column(j).ones() {
            // XOR column `row_of_b` of A into result column j
            let a_col = a.column(row_of_b).clone();
            result.column_mut(j).xor_assign(&a_col);
        }
    }
    result
}

#[cfg(test)]
#[path = "boundary_inline_tests.rs"]
mod tests;
