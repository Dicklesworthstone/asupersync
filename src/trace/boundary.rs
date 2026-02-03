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
use crate::trace::gf2::BoundaryMatrix;

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
    ///
    /// Squares are detected as commuting diamonds: four vertices `a < b, c < d`
    /// with edges `a→b`, `a→c`, `b→d`, `c→d` and canonical order `b < c`.
    #[must_use]
    pub fn from_edges(num_vertices: usize, mut edges: Vec<(usize, usize)>) -> Self {
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
mod tests {
    use super::*;
    use crate::trace::event_structure::TracePoset;
    use crate::trace::TraceEvent;
    use crate::types::{RegionId, TaskId, Time};

    /// Single edge: two vertices, one edge, no squares.
    #[test]
    fn single_edge() {
        let cx = SquareComplex::from_edges(2, vec![(0, 1)]);
        assert_eq!(cx.edges.len(), 1);
        assert_eq!(cx.squares.len(), 0);

        let d1 = cx.boundary_1();
        assert_eq!(d1.rows(), 2);
        assert_eq!(d1.cols(), 1);
        // ∂₁(0→1) = v0 + v1
        assert!(d1.get(0, 0));
        assert!(d1.get(1, 0));
    }

    /// Triangle: 3 vertices, 3 edges, no squares (no commuting diamond).
    #[test]
    fn triangle_no_squares() {
        let cx = SquareComplex::from_edges(3, vec![(0, 1), (0, 2), (1, 2)]);
        assert_eq!(cx.edges.len(), 3);
        assert_eq!(cx.squares.len(), 0); // no 4th vertex for a diamond
    }

    /// A single square: 4 vertices forming a commuting diamond.
    ///
    /// ```text
    ///     0
    ///    / \
    ///   1   2
    ///    \ /
    ///     3
    /// ```
    #[test]
    fn single_square() {
        let cx = SquareComplex::from_edges(4, vec![(0, 1), (0, 2), (1, 3), (2, 3)]);
        assert_eq!(cx.edges.len(), 4);
        assert_eq!(cx.squares.len(), 1);
        assert_eq!(cx.squares[0], (0, 1, 2, 3));
    }

    /// ∂₁ ∘ ∂₂ = 0 for a single square.
    #[test]
    fn boundary_composition_single_square() {
        let cx = SquareComplex::from_edges(4, vec![(0, 1), (0, 2), (1, 3), (2, 3)]);
        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();

        let product = matmul_gf2(&d1, &d2);
        // ∂₁ ∘ ∂₂ must be zero
        for j in 0..product.cols() {
            assert!(product.column(j).is_zero(), "∂₁∂₂ column {j} is non-zero");
        }
    }

    /// ∂₁ ∘ ∂₂ = 0 for a more complex graph with multiple squares.
    ///
    /// ```text
    ///   0 ─→ 1 ─→ 3
    ///   │    │    │
    ///   ↓    ↓    ↓
    ///   2 ─→ 4 ─→ 5
    /// ```
    #[test]
    fn boundary_composition_grid() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (1, 4), (2, 4), (3, 5), (4, 5)];
        let cx = SquareComplex::from_edges(6, edges);
        // Two squares: (0,1,2,4) and (1,3,4,5)
        assert_eq!(cx.squares.len(), 2);

        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();

        let product = matmul_gf2(&d1, &d2);
        for j in 0..product.cols() {
            assert!(product.column(j).is_zero(), "∂₁∂₂ column {j} is non-zero");
        }
    }

    /// ∂₁ ∘ ∂₂ = 0 for a large diamond lattice.
    #[test]
    fn boundary_composition_large_lattice() {
        // Build a 4x4 grid lattice: vertices (i,j) for 0≤i,j≤3
        // Edges: right (i,j)→(i,j+1) and down (i,j)→(i+1,j)
        let n = 4;
        let idx = |i: usize, j: usize| i * n + j;
        let mut edges = Vec::new();
        for i in 0..n {
            for j in 0..n {
                if j + 1 < n {
                    edges.push((idx(i, j), idx(i, j + 1)));
                }
                if i + 1 < n {
                    edges.push((idx(i, j), idx(i + 1, j)));
                }
            }
        }

        let cx = SquareComplex::from_edges(n * n, edges);
        // 3x3 = 9 squares
        assert_eq!(cx.squares.len(), 9);

        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();

        let product = matmul_gf2(&d1, &d2);
        for j in 0..product.cols() {
            assert!(
                product.column(j).is_zero(),
                "∂₁∂₂ column {j} is non-zero in {n}x{n} grid"
            );
        }
    }

    /// Verify deterministic cell ordering.
    #[test]
    fn deterministic_ordering() {
        // Same edges in different input order should yield identical complex.
        let e1 = vec![(2, 3), (0, 1), (1, 3), (0, 2)];
        let e2 = vec![(0, 2), (1, 3), (0, 1), (2, 3)];

        let cx1 = SquareComplex::from_edges(4, e1);
        let cx2 = SquareComplex::from_edges(4, e2);

        assert_eq!(cx1.edges, cx2.edges);
        assert_eq!(cx1.squares, cx2.squares);
    }

    /// Empty complex.
    #[test]
    fn empty_complex() {
        let cx = SquareComplex::from_edges(0, vec![]);
        assert_eq!(cx.edges.len(), 0);
        assert_eq!(cx.squares.len(), 0);

        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();
        assert_eq!(d1.rows(), 0);
        assert_eq!(d1.cols(), 0);
        assert_eq!(d2.rows(), 0);
        assert_eq!(d2.cols(), 0);
    }

    /// Vertices only, no edges.
    #[test]
    fn vertices_only() {
        let cx = SquareComplex::from_edges(5, vec![]);
        assert_eq!(cx.edges.len(), 0);
        assert_eq!(cx.squares.len(), 0);
    }

    // -- TracePoset integration tests (toy traces) --

    /// Two independent tasks: spawn A then spawn B on different regions.
    /// Independent events form a commuting diamond if there's a shared successor.
    #[test]
    fn toy_trace_independent_tasks() {
        let r1 = RegionId::new_for_test(1, 0);
        let r2 = RegionId::new_for_test(2, 0);
        let t1 = TaskId::new_for_test(1, 0);
        let t2 = TaskId::new_for_test(2, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), t1, r1),
            TraceEvent::spawn(2, Time::from_nanos(20), t2, r2),
        ];

        let poset = TracePoset::from_trace(&trace);
        let cx = SquareComplex::from_trace_poset(&poset);

        // Two independent events: no dependency edges at all.
        assert_eq!(cx.num_vertices, 2);
        assert_eq!(cx.edges.len(), 0);
        assert_eq!(cx.squares.len(), 0);
    }

    /// Two dependent tasks on the same region: spawn then schedule.
    /// Dependent events form a causality edge but no square.
    #[test]
    fn toy_trace_dependent_tasks() {
        let r = RegionId::new_for_test(1, 0);
        let t = TaskId::new_for_test(7, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), t, r),
            TraceEvent::schedule(2, Time::from_nanos(20), t, r),
        ];

        let poset = TracePoset::from_trace(&trace);
        let cx = SquareComplex::from_trace_poset(&poset);

        assert_eq!(cx.num_vertices, 2);
        assert_eq!(cx.edges.len(), 1);
        assert_eq!(cx.edges[0], (0, 1));
        assert_eq!(cx.squares.len(), 0);
    }

    /// Four events forming a commuting diamond:
    /// Task A spawn, Task B spawn (independent), then Task A schedule, Task B schedule.
    /// If spawn_A and spawn_B are independent, and both must precede their
    /// respective schedules, we get a diamond.
    #[test]
    fn toy_trace_diamond() {
        let r1 = RegionId::new_for_test(1, 0);
        let r2 = RegionId::new_for_test(2, 0);
        let t1 = TaskId::new_for_test(1, 0);
        let t2 = TaskId::new_for_test(2, 0);

        // Events: 0=spawn_A, 1=spawn_B, 2=schedule_A, 3=schedule_B
        // Deps: 0→2 (same task A), 1→3 (same task B)
        // Independent: 0↔1, 0↔3 (diff task+region), 1↔2, 2↔3
        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), t1, r1),
            TraceEvent::spawn(2, Time::from_nanos(20), t2, r2),
            TraceEvent::schedule(3, Time::from_nanos(30), t1, r1),
            TraceEvent::schedule(4, Time::from_nanos(40), t2, r2),
        ];

        let poset = TracePoset::from_trace(&trace);
        let cx = SquareComplex::from_trace_poset(&poset);

        assert_eq!(cx.num_vertices, 4);
        // Only dependency edges: 0→2, 1→3
        assert_eq!(cx.edges.len(), 2);
        // No square: need 4 edges forming a diamond (a→b, a→c, b→d, c→d)
        // With only 2 edges 0→2 and 1→3, no diamond possible.
        assert_eq!(cx.squares.len(), 0);

        // Verify ∂₁∘∂₂ = 0 (trivially, no squares)
        let d1 = cx.boundary_1();
        let d2 = cx.boundary_2();
        let product = matmul_gf2(&d1, &d2);
        assert_eq!(product.cols(), 0);
    }

    /// Verify that `from_trace_poset` produces the same result as manually
    /// extracting edges from the poset and calling `from_edges`.
    #[test]
    fn from_trace_poset_matches_from_edges() {
        let r = RegionId::new_for_test(1, 0);
        let t1 = TaskId::new_for_test(1, 0);
        let t2 = TaskId::new_for_test(2, 0);

        let trace = vec![
            TraceEvent::spawn(1, Time::from_nanos(10), t1, r),
            TraceEvent::spawn(2, Time::from_nanos(20), t2, r),
            TraceEvent::schedule(3, Time::from_nanos(30), t1, r),
        ];

        let poset = TracePoset::from_trace(&trace);

        // Manual extraction
        let mut manual_edges = Vec::new();
        for i in 0..poset.len() {
            for &j in poset.succs(i) {
                manual_edges.push((i, j));
            }
        }
        let cx_manual = SquareComplex::from_edges(poset.len(), manual_edges);
        let cx_poset = SquareComplex::from_trace_poset(&poset);

        assert_eq!(cx_manual.edges, cx_poset.edges);
        assert_eq!(cx_manual.squares, cx_poset.squares);
    }
}
