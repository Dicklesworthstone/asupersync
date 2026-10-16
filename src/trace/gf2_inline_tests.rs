    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // -- BitVec tests --

    #[test]
    fn bitvec_zeros() {
        let v = BitVec::zeros(100);
        assert_eq!(v.len(), 100);
        assert!(v.is_zero());
        assert_eq!(v.pivot(), None);
        assert_eq!(v.count_ones(), 0);
    }

    #[test]
    fn bitvec_singleton() {
        let v = BitVec::singleton(128, 65);
        assert!(v.get(65));
        assert!(!v.get(0));
        assert!(!v.get(64));
        assert_eq!(v.pivot(), Some(65));
        assert_eq!(v.highest_bit(), Some(65));
        assert_eq!(v.count_ones(), 1);
    }

    #[test]
    fn bitvec_set_clear_flip() {
        let mut v = BitVec::zeros(10);
        v.set(3);
        v.set(7);
        assert!(v.get(3));
        assert!(v.get(7));
        assert_eq!(v.count_ones(), 2);

        v.clear(3);
        assert!(!v.get(3));
        assert_eq!(v.count_ones(), 1);

        v.flip(7);
        assert!(!v.get(7));
        assert!(v.is_zero());

        v.flip(0);
        assert!(v.get(0));
    }

    #[test]
    fn bitvec_xor() {
        let mut a = BitVec::zeros(8);
        a.set(0);
        a.set(2);
        a.set(4); // a = {0, 2, 4}

        let mut b = BitVec::zeros(8);
        b.set(2);
        b.set(3);
        b.set(4); // b = {2, 3, 4}

        let c = a.xor(&b); // c = {0, 3}
        assert!(c.get(0));
        assert!(!c.get(2));
        assert!(c.get(3));
        assert!(!c.get(4));
        assert_eq!(c.count_ones(), 2);
    }

    #[test]
    fn bitvec_pivot_and_highest() {
        let mut v = BitVec::zeros(200);
        v.set(5);
        v.set(100);
        v.set(150);

        assert_eq!(v.pivot(), Some(5));
        assert_eq!(v.highest_bit(), Some(150));
    }

    #[test]
    fn bitvec_ones_iterator() {
        let mut v = BitVec::zeros(130);
        v.set(0);
        v.set(63);
        v.set(64);
        v.set(127);
        v.set(129);

        let ones: Vec<usize> = v.ones().collect();
        assert_eq!(ones, vec![0, 63, 64, 127, 129]);
    }

    #[test]
    fn bitvec_large_xor() {
        let mut a = BitVec::zeros(1000);
        let mut b = BitVec::zeros(1000);
        for i in (0..1000).step_by(3) {
            a.set(i);
        }
        for i in (0..1000).step_by(5) {
            b.set(i);
        }

        let c = a.xor(&b);
        // Bits in c: set in a XOR b, i.e. in exactly one of {3k} and {5k}
        for i in 0..1000 {
            let in_a = i % 3 == 0;
            let in_b = i % 5 == 0;
            assert_eq!(c.get(i), in_a ^ in_b, "mismatch at bit {i}");
        }
    }

    // -- BoundaryMatrix tests --

    #[test]
    fn matrix_basic() {
        let mut m = BoundaryMatrix::zeros(3, 3);
        m.set(0, 1);
        m.set(1, 1);
        m.set(1, 2);
        m.set(2, 2);

        assert!(m.get(0, 1));
        assert!(m.get(1, 1));
        assert!(m.get(1, 2));
        assert!(m.get(2, 2));
        assert!(!m.get(0, 0));
    }

    #[test]
    fn matrix_xor_columns() {
        let mut m = BoundaryMatrix::zeros(4, 3);
        // col 0: {0, 1}
        m.set(0, 0);
        m.set(1, 0);
        // col 1: {1, 2}
        m.set(1, 1);
        m.set(2, 1);
        // col 2: {0, 2}
        m.set(0, 2);
        m.set(2, 2);

        // XOR col 0 into col 2: col2 = {0,2} XOR {0,1} = {1,2}
        m.xor_columns(2, 0);
        assert!(!m.get(0, 2));
        assert!(m.get(1, 2));
        assert!(m.get(2, 2));
    }

    #[test]
    fn matrix_reduce_triangle() {
        // Classic triangle boundary matrix:
        //   Simplices: v0, v1, v2, e01, e02, e12, t012
        //
        // ∂1 (edges → vertices):
        //   e01 = v0 + v1, e02 = v0 + v2, e12 = v1 + v2
        //
        // ∂2 (triangle → edges):
        //   t012 = e01 + e02 + e12
        //
        // We test the ∂1 matrix reduction.
        let mut d1 = BoundaryMatrix::zeros(3, 3);
        // e01: v0 + v1
        d1.set(0, 0);
        d1.set(1, 0);
        // e02: v0 + v2
        d1.set(0, 1);
        d1.set(2, 1);
        // e12: v1 + v2
        d1.set(1, 2);
        d1.set(2, 2);

        let reduced = d1.reduce();

        // After reduction, column 2 should have been zeroed out
        // (e12 = e01 + e02 in GF(2), so it's a cycle)
        // Columns 0 and 1 have pivots at rows 0 and 0... let's check.
        let p0 = reduced.matrix.column_pivot(0);
        let p1 = reduced.matrix.column_pivot(1);
        let p2 = reduced.matrix.column_pivot(2);

        // Column 0: {0,1}, pivot is highest bit 1
        assert_eq!(p0, Some(1));
        // Column 1: {0,2}, pivot is highest bit 2 (not reduced by col 0 since pivots differ)
        assert_eq!(p1, Some(2));
        // Column 2: {1,2} XOR col 1 {0,2} -> {0,1} XOR col 0 {0,1} -> empty, pivot None
        assert_eq!(p2, None);
        let pairs = reduced.persistence_pairs();
        // Triangle has β0=1, β1=0 (connected, no holes when filled)
        // Pairs: edge deaths kill vertex births
        assert!(!pairs.pairs.is_empty(), "should have persistence pairs");
    }

    #[test]
    fn reduce_determinism() {
        // Verify that reduction is deterministic across runs
        let mut d = BoundaryMatrix::zeros(5, 5);
        d.set(0, 1);
        d.set(1, 1);
        d.set(0, 2);
        d.set(2, 2);
        d.set(1, 3);
        d.set(2, 3);
        d.set(3, 4);
        d.set(4, 4);

        let r1 = d.reduce();
        let r2 = d.reduce();

        for j in 0..5 {
            assert_eq!(
                r1.matrix.column_pivot(j),
                r2.matrix.column_pivot(j),
                "pivot mismatch at column {j}"
            );
        }
    }

    #[test]
    fn reduce_keeps_zero_column_zero() {
        let mut d = BoundaryMatrix::zeros(4, 3);
        d.set(0, 0);
        d.set(1, 0);
        d.set(2, 2);

        let reduced = d.reduce();
        assert_eq!(reduced.matrix.column_pivot(1), None);
    }

    #[test]
    fn bitvec_empty() {
        let v = BitVec::zeros(0);
        assert_eq!(v.len(), 0);
        assert!(v.is_zero());
        assert_eq!(v.pivot(), None);
        assert_eq!(v.count_ones(), 0);
        assert_eq!(v.ones().count(), 0);
    }

    #[test]
    fn bitvec_word_boundary() {
        // Test behavior at 64-bit word boundaries
        let mut v = BitVec::zeros(128);
        v.set(63);
        v.set(64);
        assert_eq!(v.pivot(), Some(63));
        assert_eq!(v.highest_bit(), Some(64));
        assert_eq!(v.count_ones(), 2);

        v.clear(63);
        assert_eq!(v.pivot(), Some(64));
    }

    #[test]
    fn persistence_pairs_simple() {
        // Two vertices, one edge: v0, v1, e01
        // ∂1: e01 = v0 + v1
        let mut d = BoundaryMatrix::zeros(2, 1);
        d.set(0, 0);
        d.set(1, 0);

        let reduced = d.reduce();
        let pairs = reduced.persistence_pairs();

        // One pair: vertex 1 killed by edge 0 (highest bit of v0+v1 is v1)
        assert_eq!(pairs.pairs.len(), 1);
        assert_eq!(pairs.pairs[0], (1, 0));
        // Vertex 1 is unpaired (it survives)
        // Actually v1 (row index 1) is not a column, so it won't appear
        // in unpaired. The unpaired list is for zero columns that aren't paired.
    }

    #[test]
    fn persistence_pairs_non_square_more_rows_than_cols() {
        // Regression test: persistence_pairs() must not panic when rows > cols.
        // Example: ∂₂ for a small complex with 6 edges (rows) and 2 squares (cols).
        let mut d = BoundaryMatrix::zeros(6, 2);
        // Square 0 boundary: edges 0, 1, 2
        d.set(0, 0);
        d.set(1, 0);
        d.set(2, 0);
        // Square 1 boundary: edges 2, 3, 4
        d.set(2, 1);
        d.set(3, 1);
        d.set(4, 1);

        let reduced = d.reduce();
        // This must not panic (previously indexed is_birth[pivot] with pivot >= cols).
        let pairs = reduced.persistence_pairs();
        // Both columns should be non-zero after reduction, giving 2 pairs.
        assert_eq!(pairs.pairs.len() + pairs.unpaired.len(), 2);
    }

    #[test]
    fn persistence_pairs_non_square_more_cols_than_rows() {
        // persistence_pairs() with cols > rows (e.g., ∂₁ in a dense graph).
        let mut d = BoundaryMatrix::zeros(3, 5);
        // 5 edges connecting 3 vertices
        d.set(0, 0);
        d.set(1, 0); // edge 0: v0-v1
        d.set(1, 1);
        d.set(2, 1); // edge 1: v1-v2
        d.set(0, 2);
        d.set(2, 2); // edge 2: v0-v2
        // edges 3,4 duplicate edge 0
        d.set(0, 3);
        d.set(1, 3);
        d.set(0, 4);
        d.set(1, 4);

        let reduced = d.reduce();
        let pairs = reduced.persistence_pairs();
        // Should not panic and results should be consistent.
        assert!(pairs.pairs.len() + pairs.unpaired.len() <= 5);
    }

    #[test]
    fn bitvec_clone_eq_hash() {
        use std::collections::HashSet;
        let mut a = BitVec::zeros(128);
        a.set(0);
        a.set(64);
        let b = a.clone();
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
    }

    #[test]
    fn persistence_pairs_debug_clone() {
        let pp = PersistencePairs {
            pairs: vec![(0, 1), (2, 3)],
            unpaired: vec![4],
        };
        let cloned = pp.clone();
        assert_eq!(cloned.pairs.len(), 2);
        assert_eq!(cloned.unpaired, vec![4]);
        let dbg = format!("{pp:?}");
        assert!(dbg.contains("PersistencePairs"));
    }
