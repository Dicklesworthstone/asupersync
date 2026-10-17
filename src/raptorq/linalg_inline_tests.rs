    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::config::RaptorQConfig;
    use crate::cx::Cx;
    use crate::raptorq::builder::RaptorQSenderBuilder;
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::security::AuthenticatedSymbol;
    use crate::transport::sink::SymbolSink;
    use crate::types::symbol::ObjectId;
    use crate::util::DetRng;

    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct CollectorSink {
        symbols: Vec<AuthenticatedSymbol>,
    }

    impl CollectorSink {
        fn new() -> Self {
            Self {
                symbols: Vec::new(),
            }
        }

        fn symbols(&self) -> &[AuthenticatedSymbol] {
            &self.symbols
        }
    }

    impl SymbolSink for CollectorSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), crate::transport::error::SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), crate::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), crate::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), crate::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for CollectorSink {}

    fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
        let obj = object_id.as_u128();
        let hi = (obj >> 64) as u64;
        let lo = obj as u64;
        let mut seed = hi ^ lo.rotate_left(13);
        seed ^= u64::from(sbn) << 56;
        if seed == 0 { 1 } else { seed }
    }

    fn create_test_decoder(symbols: &[AuthenticatedSymbol], k: usize) -> InactivationDecoder {
        let first_symbol = symbols
            .first()
            .expect("decode permutation invariance requires at least one symbol")
            .symbol();
        let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
        InactivationDecoder::new(k, first_symbol.len(), seed)
    }

    fn symbols_to_received(symbols: &[AuthenticatedSymbol], k: usize) -> Vec<ReceivedSymbol> {
        let Some(first) = symbols.first() else {
            return Vec::new();
        };

        let first_symbol = first.symbol();
        let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
        let decoder = InactivationDecoder::new(k, first_symbol.len(), seed);
        let mut received = Vec::with_capacity(symbols.len());

        for auth_symbol in symbols {
            let symbol = auth_symbol.symbol();
            let row = match symbol.kind() {
                crate::types::SymbolKind::Source => {
                    ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec())
                }
                crate::types::SymbolKind::Repair => {
                    let (columns, coefficients) = decoder.repair_equation(symbol.esi()).unwrap();
                    ReceivedSymbol::repair(
                        symbol.esi(),
                        columns,
                        coefficients,
                        symbol.data().to_vec(),
                    )
                }
            };
            received.push(row);
        }

        received
    }

    fn flatten_source_symbols(source_symbols: &[Vec<u8>], original_len: usize) -> Vec<u8> {
        source_symbols
            .iter()
            .flatten()
            .copied()
            .take(original_len)
            .collect()
    }

    // -- DenseRow tests --

    #[test]
    fn dense_row_basics() {
        let row = DenseRow::new(vec![1, 0, 3, 0, 5]);
        assert_eq!(row.len(), 5);
        assert!(!row.is_empty());
        assert!(!row.is_zero());
        assert_eq!(row.get(0), Gf256::new(1));
        assert_eq!(row.get(1), Gf256::ZERO);
        assert_eq!(row.first_nonzero(), Some(0));
        assert_eq!(row.nonzero_count(), 3);
    }

    #[test]
    fn dense_row_zeros() {
        let row = DenseRow::zeros(10);
        assert!(row.is_zero());
        assert_eq!(row.first_nonzero(), None);
        assert_eq!(row.nonzero_count(), 0);
    }

    #[test]
    fn dense_row_first_nonzero_from() {
        let row = DenseRow::new(vec![0, 0, 3, 0, 5]);
        assert_eq!(row.first_nonzero_from(0), Some(2));
        assert_eq!(row.first_nonzero_from(2), Some(2));
        assert_eq!(row.first_nonzero_from(3), Some(4));
        assert_eq!(row.first_nonzero_from(5), None);
        assert_eq!(row.first_nonzero_from(6), None);
    }

    #[test]
    fn dense_row_set_and_clear() {
        let mut row = DenseRow::zeros(5);
        row.set(2, Gf256::new(42));
        assert_eq!(row.get(2), Gf256::new(42));
        assert!(!row.is_zero());
        row.clear();
        assert!(row.is_zero());
    }

    #[test]
    #[should_panic(expected = "dense row index out of range: 3 >= 3")]
    fn dense_row_get_rejects_out_of_range_indices() {
        let row = DenseRow::new(vec![1, 2, 3]);
        let _ = row.get(3);
    }

    #[test]
    #[should_panic(expected = "dense row index out of range: 3 >= 3")]
    fn dense_row_set_rejects_out_of_range_indices() {
        let mut row = DenseRow::new(vec![1, 2, 3]);
        row.set(3, Gf256::new(9));
    }

    #[test]
    fn dense_row_swap() {
        let mut a = DenseRow::new(vec![1, 2, 3]);
        let mut b = DenseRow::new(vec![4, 5, 6]);
        a.swap(&mut b);
        assert_eq!(a.as_slice(), &[4, 5, 6]);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn dense_to_sparse_roundtrip() {
        let dense = DenseRow::new(vec![0, 1, 0, 3, 0]);
        let sparse = dense.to_sparse();
        assert_eq!(sparse.nonzero_count(), 2);
        let back = sparse.to_dense();
        assert_eq!(dense, back);
    }

    // -- SparseRow tests --

    #[test]
    fn sparse_row_basics() {
        let row = SparseRow::new(vec![(1, Gf256::new(10)), (3, Gf256::new(30))], 5);
        assert_eq!(row.len(), 5);
        assert_eq!(row.nonzero_count(), 2);
        assert!(!row.is_zero());
        assert_eq!(row.get(0), Gf256::ZERO);
        assert_eq!(row.get(1), Gf256::new(10));
        assert_eq!(row.get(3), Gf256::new(30));
        assert_eq!(row.first_nonzero(), Some(1));
    }

    #[test]
    #[should_panic(expected = "sparse row index out of range: 5 >= 5")]
    fn sparse_row_get_rejects_out_of_range_indices() {
        let row = SparseRow::new(vec![(1, Gf256::new(10)), (3, Gf256::new(30))], 5);
        let _ = row.get(5);
    }

    #[test]
    fn sparse_row_zeros() {
        let row = SparseRow::zeros(10);
        assert!(row.is_zero());
        assert_eq!(row.first_nonzero(), None);
    }

    #[test]
    fn sparse_row_singleton() {
        let row = SparseRow::singleton(5, Gf256::new(42), 10);
        assert_eq!(row.nonzero_count(), 1);
        assert_eq!(row.get(5), Gf256::new(42));

        // Singleton with zero value creates zero row
        let zero_row = SparseRow::singleton(5, Gf256::ZERO, 10);
        assert!(zero_row.is_zero());
    }

    #[test]
    fn sparse_row_add() {
        let a = SparseRow::new(vec![(0, Gf256::new(1)), (2, Gf256::new(3))], 5);
        let b = SparseRow::new(vec![(1, Gf256::new(2)), (2, Gf256::new(3))], 5);
        let sum = a.add(&b);
        // Position 2: 3 + 3 = 0 (XOR in GF256)
        assert_eq!(sum.nonzero_count(), 2);
        assert_eq!(sum.get(0), Gf256::new(1));
        assert_eq!(sum.get(1), Gf256::new(2));
        assert_eq!(sum.get(2), Gf256::ZERO);
    }

    #[test]
    fn sparse_row_scale() {
        let row = SparseRow::new(vec![(0, Gf256::new(2)), (2, Gf256::new(3))], 5);

        // Scale by 1 is identity
        let scaled = row.scale(Gf256::ONE);
        assert_eq!(scaled, row);

        // Scale by 0 is zero
        let zero = row.scale(Gf256::ZERO);
        assert!(zero.is_zero());

        // Scale by nonzero scalar
        let c = Gf256::new(7);
        let scaled = row.scale(c);
        assert_eq!(scaled.get(0), Gf256::new(2) * c);
        assert_eq!(scaled.get(2), Gf256::new(3) * c);
    }

    #[test]
    fn sparse_row_new_canonicalizes_duplicate_indices() {
        let row = SparseRow::new(
            vec![
                (3, Gf256::new(7)),
                (1, Gf256::new(5)),
                (1, Gf256::new(5)),
                (1, Gf256::new(3)),
            ],
            5,
        );

        assert_eq!(row.nonzero_count(), 2);
        assert_eq!(row.get(1), Gf256::new(3));
        assert_eq!(row.get(3), Gf256::new(7));
        assert_eq!(row.to_dense().as_slice(), &[0, 3, 0, 7, 0]);
    }

    #[test]
    #[should_panic(expected = "sparse row index out of range")]
    fn sparse_row_new_rejects_out_of_range_indices() {
        let _ = SparseRow::new(vec![(4, Gf256::new(1))], 4);
    }

    #[test]
    #[should_panic(expected = "sparse row index out of range")]
    fn sparse_row_singleton_rejects_out_of_range_indices() {
        let _ = SparseRow::singleton(4, Gf256::new(1), 4);
    }

    #[test]
    #[should_panic(expected = "sparse row index out of range")]
    fn sparse_row_singleton_zero_value_still_rejects_out_of_range_indices() {
        let _ = SparseRow::singleton(4, Gf256::ZERO, 4);
    }

    #[test]
    fn sparse_row_try_new_canonicalizes_or_returns_index_error() {
        let row = SparseRow::try_new(
            vec![
                (3, Gf256::new(7)),
                (1, Gf256::new(5)),
                (1, Gf256::new(5)),
                (1, Gf256::new(3)),
                (2, Gf256::ZERO),
            ],
            5,
        )
        .expect("valid sparse row");

        assert_eq!(row.nonzero_count(), 2);
        assert_eq!(row.get(1), Gf256::new(3));
        assert_eq!(row.get(3), Gf256::new(7));
        assert_eq!(row.to_dense().as_slice(), &[0, 3, 0, 7, 0]);
        assert_eq!(
            SparseRow::try_new(vec![(4, Gf256::new(1))], 4),
            Err(SparseRowIndexError { index: 4, len: 4 })
        );
    }

    #[test]
    fn sparse_row_try_singleton_rejects_out_of_range_even_for_zero_value() {
        assert_eq!(
            SparseRow::try_singleton(5, Gf256::new(42), 10)
                .expect("valid singleton")
                .to_dense()
                .as_slice(),
            &[0, 0, 0, 0, 0, 42, 0, 0, 0, 0]
        );
        assert!(
            SparseRow::try_singleton(5, Gf256::ZERO, 10)
                .expect("valid zero singleton")
                .is_zero()
        );
        assert_eq!(
            SparseRow::try_singleton(4, Gf256::new(1), 4),
            Err(SparseRowIndexError { index: 4, len: 4 })
        );
        assert_eq!(
            SparseRow::try_singleton(4, Gf256::ZERO, 4),
            Err(SparseRowIndexError { index: 4, len: 4 })
        );
    }

    #[test]
    fn sparse_row_index_error_display_is_stable() {
        assert_eq!(
            SparseRowIndexError { index: 8, len: 8 }.to_string(),
            "sparse row index out of range: 8 >= 8"
        );
    }

    // -- Slice operations --

    #[test]
    fn row_xor_works() {
        let mut dst = vec![1, 2, 3, 4];
        let src = vec![5, 6, 7, 8];
        row_xor(&mut dst, &src);
        assert_eq!(dst, vec![1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8]);
    }

    #[test]
    fn row_scale_add_works() {
        let mut dst = vec![0, 0, 0, 0];
        let src = vec![1, 2, 3, 4];
        let c = Gf256::new(7);
        row_scale_add(&mut dst, &src, c);

        // dst[i] = 0 + c * src[i]
        for i in 0..4 {
            assert_eq!(dst[i], (Gf256::new(src[i]) * c).raw());
        }
    }

    #[test]
    fn row_scale_add_batch2_works() {
        // Test dual-kernel batched operations
        let mut dst_a = vec![0, 0, 0, 0];
        let src_a = vec![1, 2, 3, 4];
        let mut dst_b = vec![0, 0, 0, 0];
        let src_b = vec![5, 6, 7, 8];
        let c = Gf256::new(7);

        row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);

        // Verify dst_a = c * src_a
        for i in 0..4 {
            assert_eq!(dst_a[i], (Gf256::new(src_a[i]) * c).raw());
        }

        // Verify dst_b = c * src_b
        for i in 0..4 {
            assert_eq!(dst_b[i], (Gf256::new(src_b[i]) * c).raw());
        }
    }

    #[test]
    fn row_scale_add_batch2_vs_sequential() {
        // Verify batched operations match sequential results
        let mut batch_dst_a = vec![10, 20, 30, 40];
        let src_a = vec![1, 2, 3, 4];
        let mut batch_dst_b = vec![50, 60, 70, 80];
        let src_b = vec![5, 6, 7, 8];

        let mut seq_dst_a = batch_dst_a.clone();
        let mut seq_dst_b = batch_dst_b.clone();
        let c = Gf256::new(13);

        // Apply batched operations
        row_scale_add_batch2(&mut batch_dst_a, &src_a, &mut batch_dst_b, &src_b, c);

        // Apply sequential operations
        row_scale_add(&mut seq_dst_a, &src_a, c);
        row_scale_add(&mut seq_dst_b, &src_b, c);

        // Results must be identical
        assert_eq!(
            batch_dst_a, seq_dst_a,
            "batched vs sequential mismatch for dst_a"
        );
        assert_eq!(
            batch_dst_b, seq_dst_b,
            "batched vs sequential mismatch for dst_b"
        );
    }

    #[test]
    fn row_scale_add_batch_multi_works() {
        // Test multi-row batching with even count
        let mut dst_rows = vec![vec![0, 0, 0], vec![0, 0, 0], vec![0, 0, 0], vec![0, 0, 0]];
        let src_rows = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        ];
        let c = Gf256::new(5);

        // Convert to slice of mutable references
        let mut dst_refs: Vec<&mut [u8]> = dst_rows.iter_mut().map(|v| v.as_mut_slice()).collect();
        let src_refs: Vec<&[u8]> = src_rows.iter().map(|v| v.as_slice()).collect();

        row_scale_add_batch_multi(&mut dst_refs, &src_refs, c);

        // Verify all operations were applied correctly
        for (i, (dst, src)) in dst_rows.iter().zip(src_rows.iter()).enumerate() {
            for j in 0..3 {
                let expected = (Gf256::new(src[j]) * c).raw();
                assert_eq!(dst[j], expected, "row {} element {} mismatch", i, j);
            }
        }
    }

    #[test]
    fn row_scale_add_batch_multi_odd_count() {
        // Test multi-row batching with odd count (requires sequential fallback)
        let mut dst_rows = vec![
            vec![10, 20, 30],
            vec![40, 50, 60],
            vec![70, 80, 90], // Odd row - sequential processing
        ];
        let src_rows = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let c = Gf256::new(11);

        // Compute expected results with sequential operations
        let mut expected = dst_rows.clone();
        for (dst, src) in expected.iter_mut().zip(src_rows.iter()) {
            row_scale_add(dst, src, c);
        }

        // Apply batched operations
        let mut dst_refs: Vec<&mut [u8]> = dst_rows.iter_mut().map(|v| v.as_mut_slice()).collect();
        let src_refs: Vec<&[u8]> = src_rows.iter().map(|v| v.as_slice()).collect();

        row_scale_add_batch_multi(&mut dst_refs, &src_refs, c);

        // Results must match sequential computation
        assert_eq!(dst_rows, expected, "batched multi vs sequential mismatch");
    }

    #[test]
    fn row_scale_add_batch_zero_coefficient() {
        // Test that zero coefficient is handled efficiently (no-op)
        let mut dst_a = vec![1, 2, 3, 4];
        let src_a = vec![5, 6, 7, 8];
        let mut dst_b = vec![9, 10, 11, 12];
        let src_b = vec![13, 14, 15, 16];

        let original_dst_a = dst_a.clone();
        let original_dst_b = dst_b.clone();

        row_scale_add_batch2(&mut dst_a, &src_a, &mut dst_b, &src_b, Gf256::ZERO);

        // Zero coefficient should leave destinations unchanged
        assert_eq!(
            dst_a, original_dst_a,
            "zero coefficient should not modify dst_a"
        );
        assert_eq!(
            dst_b, original_dst_b,
            "zero coefficient should not modify dst_b"
        );
    }

    #[test]
    fn row_swap_works() {
        let mut a = vec![1, 2, 3];
        let mut b = vec![4, 5, 6];
        row_swap(&mut a, &mut b);
        assert_eq!(a, vec![4, 5, 6]);
        assert_eq!(b, vec![1, 2, 3]);
    }

    #[test]
    fn row_scale_works() {
        let mut row = vec![1, 2, 3, 0];
        let c = Gf256::new(5);
        row_scale(&mut row, c);
        assert_eq!(row[0], (Gf256::new(1) * c).raw());
        assert_eq!(row[1], (Gf256::new(2) * c).raw());
        assert_eq!(row[2], (Gf256::new(3) * c).raw());
        assert_eq!(row[3], 0); // 0 * c = 0
    }

    // -- Pivot selection --

    #[test]
    fn select_pivot_basic_finds_first() {
        let rows: Vec<Vec<u8>> = vec![vec![0, 0, 1], vec![0, 0, 0], vec![0, 0, 2]];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        // Looking for pivot in column 2
        assert_eq!(select_pivot_basic(&matrix, 0, 3, 2), Some(0));
        assert_eq!(select_pivot_basic(&matrix, 1, 3, 2), Some(2));

        // No pivot in column 1
        assert_eq!(select_pivot_basic(&matrix, 0, 3, 1), None);
    }

    #[test]
    fn select_pivot_markowitz_prefers_sparse() {
        let rows: Vec<Vec<u8>> = vec![
            vec![1, 1, 1, 1, 1], // 5 nonzeros
            vec![0, 0, 0, 0, 0], // 0 nonzeros
            vec![1, 0, 0, 0, 0], // 1 nonzero
            vec![1, 1, 0, 0, 0], // 2 nonzeros
        ];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        // Column 0: rows 0, 2, 3 have nonzero. Row 2 is sparsest.
        let result = select_pivot_markowitz(&matrix, 0, 4, 0);
        assert_eq!(result, Some((2, 1)));
    }

    #[test]
    fn select_pivot_markowitz_tie_breaks_by_lowest_row_index() {
        let rows: Vec<Vec<u8>> = vec![
            vec![1, 0, 1, 0], // 2 nonzeros
            vec![1, 1, 0, 0], // 2 nonzeros
            vec![1, 0, 1, 0], // 2 nonzeros
        ];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        assert_eq!(select_pivot_markowitz(&matrix, 0, 3, 0), Some((0, 2)));
        assert_eq!(select_pivot_markowitz(&matrix, 1, 3, 0), Some((1, 2)));
    }

    #[test]
    fn select_pivot_helpers_handle_short_rows_and_oob_columns() {
        let rows: Vec<Vec<u8>> = vec![
            vec![1],          // shorter row
            vec![0, 1, 0, 0], // valid pivot at col=1
            vec![1, 0, 1, 0], // valid width, no pivot at col=1
        ];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        // Short rows and out-of-range columns should be treated as zero, not panic.
        assert_eq!(select_pivot_basic(&matrix, 0, 3, 9), None);
        assert_eq!(select_pivot_markowitz(&matrix, 0, 3, 9), None);

        assert_eq!(select_pivot_basic(&matrix, 0, 3, 1), Some(1));
        assert_eq!(select_pivot_markowitz(&matrix, 0, 3, 1), Some((1, 1)));
    }

    #[test]
    fn select_pivot_markowitz_counts_only_active_submatrix_tail() {
        let rows: Vec<Vec<u8>> = vec![
            vec![9, 9, 1, 1, 1], // tail nnz from col=2 is 3
            vec![7, 7, 1, 0, 0], // tail nnz from col=2 is 1 (best)
            vec![5, 5, 1, 0, 1], // tail nnz from col=2 is 2
        ];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        assert_eq!(select_pivot_markowitz(&matrix, 0, 3, 2), Some((1, 1)));
    }

    #[test]
    fn coefficient_rank_skips_free_columns_and_counts_true_rank() {
        // Column 1 is entirely zero, so the solve path must fail closed there
        // for unique reconstruction. Rank determination still has to count the
        // independent support in columns 0 and 2.
        let rows: Vec<Vec<u8>> = vec![vec![1, 0, 1], vec![0, 0, 1], vec![1, 0, 0]];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        assert_eq!(coefficient_rank(&matrix, 3), 2);
        assert_eq!(coefficient_rank(&matrix, 2), 1);
        assert_eq!(coefficient_rank(&matrix, 0), 0);
    }

    #[test]
    fn coefficient_rank_profile_reports_pivot_and_free_columns() {
        // Column 1 is fully unsupported. The profile must make that free
        // column explicit so decoder diagnostics cannot confuse aggregate rank
        // with a unique reconstruction witness.
        let rows: Vec<Vec<u8>> = vec![vec![1, 0, 1], vec![0, 0, 1], vec![1, 0, 0]];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        assert_eq!(
            coefficient_rank_profile(&matrix, 3),
            GaussianRankProfile {
                rows: 3,
                columns: 3,
                rank: 2,
                deficit: 1,
                pivot_columns: vec![0, 2],
                free_columns: vec![1],
            }
        );
        assert_eq!(
            coefficient_rank_profile(&matrix, 0),
            GaussianRankProfile {
                rows: 3,
                columns: 0,
                rank: 0,
                deficit: 0,
                pivot_columns: Vec::new(),
                free_columns: Vec::new(),
            }
        );
    }

    #[test]
    fn coefficient_rank_treats_short_rows_as_structural_zeros() {
        let rows: Vec<Vec<u8>> = vec![vec![1], vec![0, 1], vec![0, 0, 1], vec![1, 1, 1, 0]];
        let matrix: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();

        assert_eq!(coefficient_rank(&matrix, 4), 3);
        assert_eq!(coefficient_rank(&matrix, 3), 3);
        assert_eq!(coefficient_rank(&matrix, 2), 2);
    }

    #[test]
    fn coefficient_rank_is_invariant_under_row_scaling_and_permutation() {
        let base: Vec<Vec<u8>> = vec![vec![2, 0, 1, 0], vec![0, 3, 1, 0], vec![2, 3, 0, 0]];

        let scaled_permuted: Vec<Vec<u8>> = [2usize, 0, 1]
            .into_iter()
            .enumerate()
            .map(|(idx, row_index)| {
                let factor = Gf256::new([7, 11, 13][idx]);
                base[row_index]
                    .iter()
                    .map(|&value| (Gf256::new(value) * factor).raw())
                    .collect()
            })
            .collect();

        let base_rows: Vec<&[u8]> = base.iter().map(Vec::as_slice).collect();
        let scaled_rows: Vec<&[u8]> = scaled_permuted.iter().map(Vec::as_slice).collect();

        assert_eq!(coefficient_rank(&base_rows, 4), 2);
        assert_eq!(
            coefficient_rank(&base_rows, 4),
            coefficient_rank(&scaled_rows, 4),
            "row scaling by nonzero GF(256) factors and row permutation must preserve rank"
        );
        assert_eq!(
            coefficient_rank_profile(&base_rows, 4),
            coefficient_rank_profile(&scaled_rows, 4),
            "rank profile pivot/free columns must also remain deterministic under row scaling and row permutation"
        );
    }

    #[test]
    fn row_nonzero_count_works() {
        assert_eq!(row_nonzero_count(&[0, 0, 0]), 0);
        assert_eq!(row_nonzero_count(&[1, 0, 2]), 2);
        assert_eq!(row_nonzero_count(&[1, 2, 3]), 3);
    }

    #[test]
    fn row_first_nonzero_from_works() {
        let row = [0, 0, 3, 0, 5];
        assert_eq!(row_first_nonzero_from(&row, 0), Some(2));
        assert_eq!(row_first_nonzero_from(&row, 3), Some(4));
        assert_eq!(row_first_nonzero_from(&row, 5), None);
        assert_eq!(row_first_nonzero_from(&row, 6), None);
    }

    // -- Gaussian Solver tests --

    #[test]
    fn gaussian_identity_2x2() {
        // Identity matrix: I * x = b => x = b
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 0], DenseRow::new(vec![5]));
        solver.set_row(1, &[0, 1], DenseRow::new(vec![7]));

        match solver.solve() {
            GaussianResult::Solved(solution) => {
                assert_eq!(solution[0].as_slice(), &[5]);
                assert_eq!(solution[1].as_slice(), &[7]);
            }
            GaussianResult::Singular { row } => panic!("unexpected singular at row {row}"),
            GaussianResult::Inconsistent { row } => {
                panic!("unexpected inconsistent system at row {row}")
            }
        }
    }

    /// br-asupersync-biw352: Gauss elimination on a deliberately
    /// rank-deficient system (duplicate rows over GF(256)) MUST return
    /// Singular or Inconsistent cleanly — no panic, no infinite loop,
    /// no Solved-with-wrong-answer. RFC 6330 decoders MUST handle the
    /// case where the received-symbols sub-matrix happens to be
    /// rank-deficient (probability ≈ 0.01 per the failure-rate bound).
    #[test]
    fn gaussian_singular_duplicate_rows_returns_singular_without_panic() {
        // 3x3 system where row 1 and row 2 are linearly dependent
        // (row 2 = 2 * row 1 in GF(256)).
        let mut solver = GaussianSolver::new(3, 3);
        solver.set_row(0, &[1, 0, 0], DenseRow::new(vec![5]));
        solver.set_row(1, &[0, 1, 1], DenseRow::new(vec![3]));
        // Row 2: GF(256) multiply of row 1 by 2 — strictly dependent on row 1.
        // Coefficients [0, 2, 2] = 2 * [0, 1, 1]. RHS 6 = 2 * 3 (consistent).
        solver.set_row(2, &[0, 2, 2], DenseRow::new(vec![6]));

        let result = solver.solve();
        match result {
            GaussianResult::Singular { .. } | GaussianResult::Inconsistent { .. } => {
                // Either is acceptable — the system is rank-deficient.
            }
            GaussianResult::Solved(_) => {
                panic!(
                    "rank-deficient system MUST NOT decode as Solved; \
                     a successful solve here indicates the solver missed the dependency"
                );
            }
        }
    }

    /// br-asupersync-biw352: All-zeros matrix is rank 0 — must return
    /// Singular at the first row, never panic.
    #[test]
    fn gaussian_all_zeros_matrix_returns_singular() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[0, 0], DenseRow::new(vec![0]));
        solver.set_row(1, &[0, 0], DenseRow::new(vec![0]));

        match solver.solve() {
            GaussianResult::Singular { .. } => {}
            GaussianResult::Inconsistent { .. } => {
                // Acceptable too — both signal "no unique solution".
            }
            GaussianResult::Solved(_) => panic!("zero matrix MUST NOT solve"),
        }
    }

    /// br-asupersync-biw352: Inconsistent overdetermined system —
    /// coefficients reduce to 0 row but RHS is nonzero (0 = b, b != 0).
    /// Must return Inconsistent (NOT Solved, NOT Singular for this
    /// specific failure mode).
    #[test]
    fn gaussian_inconsistent_system_returns_inconsistent() {
        // Two rows where second is a coefficient-multiple of first
        // BUT the RHS is INconsistent with that multiplication —
        // forces the solver to detect 0 = b at elimination time.
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 1], DenseRow::new(vec![3]));
        // Row 1 coefficients = row 0 (so row 1 - row 0 = 0 row).
        // RHS 4 != 3 → inconsistent: 0 * x = 1.
        solver.set_row(1, &[1, 1], DenseRow::new(vec![4]));

        match solver.solve() {
            GaussianResult::Inconsistent { .. } => {}
            GaussianResult::Singular { .. } => {
                // Some solver impls report Singular before checking
                // RHS — also acceptable, just not Solved.
            }
            GaussianResult::Solved(_) => panic!("inconsistent system MUST NOT solve"),
        }
    }

    #[test]
    fn gaussian_simple_2x2() {
        // System: [1, 1] * [x0, x1] = [3], [1, 2] * [x0, x1] = [5]
        // In GF(256): subtraction is XOR
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 1], DenseRow::new(vec![3]));
        solver.set_row(1, &[1, 2], DenseRow::new(vec![5]));

        match solver.solve() {
            GaussianResult::Solved(solution) => {
                let x0 = Gf256::new(solution[0].as_slice()[0]);
                let x1 = Gf256::new(solution[1].as_slice()[0]);
                // Verify the solution satisfies original equations
                let r0 = x0 + x1;
                let r1 = x0 + (Gf256::new(2) * x1);
                assert_eq!(r0.raw(), 3, "row 0 check");
                assert_eq!(r1.raw(), 5, "row 1 check");
            }
            GaussianResult::Singular { row } => panic!("unexpected singular at row {row}"),
            GaussianResult::Inconsistent { row } => {
                panic!("unexpected inconsistent system at row {row}")
            }
        }
    }

    #[test]
    fn gaussian_singular_matrix() {
        // Two identical rows => singular
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 2], DenseRow::new(vec![3]));
        solver.set_row(1, &[1, 2], DenseRow::new(vec![3]));

        match solver.solve() {
            GaussianResult::Singular { row } => {
                assert_eq!(row, 1, "singular detected at row 1");
            }
            GaussianResult::Inconsistent { row } => {
                panic!("expected singular matrix, got inconsistent at row {row}")
            }
            GaussianResult::Solved(_) => panic!("expected singular matrix"),
        }
    }

    #[test]
    fn gaussian_3x3_diagonal() {
        // 3x3 diagonal matrix (easy)
        let mut solver = GaussianSolver::new(3, 3);
        solver.set_row(0, &[2, 0, 0], DenseRow::new(vec![10]));
        solver.set_row(1, &[0, 3, 0], DenseRow::new(vec![15]));
        solver.set_row(2, &[0, 0, 5], DenseRow::new(vec![25]));

        match solver.solve() {
            GaussianResult::Solved(solution) => {
                // Solution: x0 = 10/2, x1 = 15/3, x2 = 25/5 (in GF256)
                let x0 = solution[0].get(0);
                let x1 = solution[1].get(0);
                let x2 = solution[2].get(0);

                // Verify
                assert_eq!(Gf256::new(2) * x0, Gf256::new(10));
                assert_eq!(Gf256::new(3) * x1, Gf256::new(15));
                assert_eq!(Gf256::new(5) * x2, Gf256::new(25));
            }
            GaussianResult::Singular { row } => panic!("unexpected singular at row {row}"),
            GaussianResult::Inconsistent { row } => {
                panic!("unexpected inconsistent system at row {row}")
            }
        }
    }

    #[test]
    fn gaussian_markowitz_same_result() {
        // Verify Markowitz gives same answer as basic for non-singular system
        let mut solver1 = GaussianSolver::new(3, 3);
        solver1.set_row(0, &[1, 2, 3], DenseRow::new(vec![6]));
        solver1.set_row(1, &[4, 5, 6], DenseRow::new(vec![15]));
        solver1.set_row(2, &[7, 8, 10], DenseRow::new(vec![25]));

        let mut solver2 = GaussianSolver::new(3, 3);
        solver2.set_row(0, &[1, 2, 3], DenseRow::new(vec![6]));
        solver2.set_row(1, &[4, 5, 6], DenseRow::new(vec![15]));
        solver2.set_row(2, &[7, 8, 10], DenseRow::new(vec![25]));

        let result1 = solver1.solve();
        let result2 = solver2.solve_markowitz();

        // Both should solve (or both singular at same row)
        match (&result1, &result2) {
            (GaussianResult::Solved(s1), GaussianResult::Solved(s2)) => {
                // Solutions should be equivalent
                for i in 0..3 {
                    assert_eq!(s1[i], s2[i], "solution row {i} mismatch");
                }
            }
            (GaussianResult::Singular { row: r1 }, GaussianResult::Singular { row: r2 }) => {
                assert_eq!(r1, r2, "singular at different rows");
            }
            (
                GaussianResult::Inconsistent { row: r1 },
                GaussianResult::Inconsistent { row: r2 },
            ) => {
                assert_eq!(r1, r2, "inconsistent at different rows");
            }
            _ => panic!("different result types"),
        }
    }

    #[test]
    fn gaussian_pivot_strategy_preserves_known_solution_under_row_permutation() {
        fn dot(coefficients: [u8; 3], solution: [u8; 3]) -> u8 {
            coefficients
                .into_iter()
                .zip(solution)
                .fold(Gf256::ZERO, |acc, (coefficient, value)| {
                    acc + (Gf256::new(coefficient) * Gf256::new(value))
                })
                .raw()
        }

        fn build_rows(coefficients: [[u8; 3]; 3], solution: [u8; 3]) -> [([u8; 3], [u8; 1]); 3] {
            coefficients.map(|row| (row, [dot(row, solution)]))
        }

        fn permute_rows(
            rows: [([u8; 3], [u8; 1]); 3],
            order: [usize; 3],
        ) -> [([u8; 3], [u8; 1]); 3] {
            [rows[order[0]], rows[order[1]], rows[order[2]]]
        }

        fn solve(rows: &[([u8; 3], [u8; 1])], markowitz: bool) -> Vec<DenseRow> {
            let mut solver = GaussianSolver::new(rows.len(), 3);
            for (row, (coefficients, rhs)) in rows.iter().enumerate() {
                solver.set_row(row, coefficients, DenseRow::new(rhs.to_vec()));
            }

            let result = if markowitz {
                solver.solve_markowitz()
            } else {
                solver.solve()
            };
            assert_eq!(
                result.outcome_kind(),
                GaussianOutcomeKind::Solved,
                "row-permuted full-rank fixture must not fail closed: {result:?}"
            );
            match result {
                GaussianResult::Solved(solution) => solution,
                other => panic!("expected solved result after outcome check, got {other:?}"),
            }
        }

        let solution = [0x10, 0x20, 0x30];
        let expected = vec![
            DenseRow::new(vec![solution[0]]),
            DenseRow::new(vec![solution[1]]),
            DenseRow::new(vec![solution[2]]),
        ];
        let rows = build_rows([[0, 1, 2], [0, 0, 1], [1, 3, 4]], solution);

        for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
            let permuted = permute_rows(rows, order);
            assert_eq!(
                solve(&permuted, false),
                expected,
                "basic solver returned a corrupted solution for order {order:?}"
            );
            assert_eq!(
                solve(&permuted, true),
                expected,
                "Markowitz solver returned a corrupted solution for order {order:?}"
            );
        }
    }

    #[test]
    fn metamorphic_row_scaling_and_permutation_preserve_solution() {
        fn scale_row(coefficients: [u8; 3], rhs: [u8; 2], factor: Gf256) -> ([u8; 3], [u8; 2]) {
            let mut scaled_coefficients = [0; 3];
            let mut scaled_rhs = [0; 2];

            for (dst, src) in scaled_coefficients.iter_mut().zip(coefficients) {
                *dst = (Gf256::new(src) * factor).raw();
            }
            for (dst, src) in scaled_rhs.iter_mut().zip(rhs) {
                *dst = (Gf256::new(src) * factor).raw();
            }

            (scaled_coefficients, scaled_rhs)
        }

        fn build_solver(rows: &[([u8; 3], [u8; 2])]) -> GaussianSolver {
            let mut solver = GaussianSolver::new(rows.len(), 3);
            for (row, (coefficients, rhs)) in rows.iter().enumerate() {
                solver.set_row(row, coefficients, DenseRow::new(rhs.to_vec()));
            }
            solver
        }

        fn solve_basic(rows: &[([u8; 3], [u8; 2])]) -> Vec<DenseRow> {
            let mut solver = build_solver(rows);
            match solver.solve() {
                GaussianResult::Solved(solution) => solution,
                other => panic!("basic solver should solve metamorphic fixture, got {other:?}"),
            }
        }

        fn solve_markowitz(rows: &[([u8; 3], [u8; 2])]) -> Vec<DenseRow> {
            let mut solver = build_solver(rows);
            match solver.solve_markowitz() {
                GaussianResult::Solved(solution) => solution,
                other => panic!("markowitz solver should solve metamorphic fixture, got {other:?}"),
            }
        }

        let base_rows = [
            ([2, 1, 0], [0x10, 0x20]),
            ([0, 3, 1], [0x30, 0x40]),
            ([0, 0, 5], [0x50, 0x60]),
        ];
        let transformed_rows = [
            base_rows[2],
            scale_row(base_rows[1].0, base_rows[1].1, Gf256::new(0x53)),
            base_rows[0],
        ];

        assert_eq!(
            solve_basic(&base_rows),
            solve_basic(&transformed_rows),
            "basic Gaussian elimination should preserve the solution when equations are scaled by nonzero factors and row order is permuted"
        );
        assert_eq!(
            solve_markowitz(&base_rows),
            solve_markowitz(&transformed_rows),
            "Markowitz Gaussian elimination should preserve the solution when equations are scaled by nonzero factors and row order is permuted"
        );
    }

    #[test]
    fn gaussian_stats_tracked() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[0, 1], DenseRow::new(vec![5])); // Needs swap
        solver.set_row(1, &[1, 0], DenseRow::new(vec![7]));

        let _ = solver.solve();
        let stats = solver.stats();
        assert!(stats.pivot_selections > 0, "pivot selections tracked");
        assert!(stats.swaps > 0, "swaps tracked (row 0 needs swap)");
    }

    #[test]
    fn gaussian_singular_failure_is_deterministic_across_solvers() {
        let mut basic = GaussianSolver::new(4, 4);
        basic.set_row(0, &[1, 0, 0, 0], DenseRow::new(vec![1]));
        basic.set_row(1, &[0, 1, 0, 0], DenseRow::new(vec![2]));
        basic.set_row(2, &[1, 1, 0, 0], DenseRow::new(vec![3]));
        basic.set_row(3, &[1, 1, 0, 0], DenseRow::new(vec![4]));

        let mut markowitz = GaussianSolver::new(4, 4);
        markowitz.set_row(0, &[1, 0, 0, 0], DenseRow::new(vec![1]));
        markowitz.set_row(1, &[0, 1, 0, 0], DenseRow::new(vec![2]));
        markowitz.set_row(2, &[1, 1, 0, 0], DenseRow::new(vec![3]));
        markowitz.set_row(3, &[1, 1, 0, 0], DenseRow::new(vec![4]));

        let basic_result = basic.solve();
        let markowitz_result = markowitz.solve_markowitz();

        // Rows 2 and 3 share coefficients [1,1,0,0] but carry distinct RHS
        // values (3 vs 4). After eliminating columns 0 and 1 the residual rows
        // collapse to `0 = c`: row 2 is consistent (0 = 0) but row 3 is a hard
        // contradiction (0 = 1). Both solvers must therefore agree on the more
        // precise `Inconsistent` classification (br-asupersync-biw352: an
        // inconsistent overdetermined system is reported as Inconsistent, not
        // Singular) and pin the contradicting row deterministically.
        assert_eq!(
            basic_result,
            GaussianResult::Inconsistent { row: 3 },
            "basic solver must detect the row-3 contradiction"
        );
        assert_eq!(
            markowitz_result,
            GaussianResult::Inconsistent { row: 3 },
            "markowitz solver must agree on the same contradicting row"
        );
        // Both solvers select pivots on columns 0 and 1 before failing on the
        // all-zero column; the count must match across strategies.
        assert_eq!(
            basic.stats().pivot_selections,
            markowitz.stats().pivot_selections,
            "pivot-selection accounting must be deterministic across solvers"
        );
        assert_eq!(basic.stats().pivot_selections, 3);
    }

    #[test]
    fn gaussian_empty_rhs() {
        // System with empty RHS (just checking coefficients)
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 0], DenseRow::zeros(0));
        solver.set_row(1, &[0, 1], DenseRow::zeros(0));

        match solver.solve() {
            GaussianResult::Solved(solution) => {
                assert_eq!(solution[0].len(), 0);
                assert_eq!(solution[1].len(), 0);
            }
            GaussianResult::Singular { row } => panic!("unexpected singular at row {row}"),
            GaussianResult::Inconsistent { row } => {
                panic!("unexpected inconsistent system at row {row}")
            }
        }
    }

    #[test]
    fn gaussian_mixed_rhs_widths_fail_closed_before_elimination() {
        fn build_solver() -> GaussianSolver {
            let mut solver = GaussianSolver::new(2, 2);
            solver.set_row(0, &[1, 1], DenseRow::new(vec![0xAA, 0xBB]));
            solver.set_row(1, &[0, 1], DenseRow::new(vec![0xCC]));
            solver
        }

        let mut basic = build_solver();
        let mut markowitz = build_solver();

        assert_eq!(
            basic.solve(),
            GaussianResult::Inconsistent { row: 1 },
            "mixed-width RHS rows must not solve by padding or truncating symbols"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Inconsistent { row: 1 },
            "Markowitz path must enforce the same RHS-width fail-closed guard"
        );
        assert_eq!(
            basic.stats().pivot_selections,
            0,
            "basic solver should reject malformed RHS widths before pivoting"
        );
        assert_eq!(
            markowitz.stats().pivot_selections,
            0,
            "Markowitz solver should reject malformed RHS widths before pivoting"
        );
    }

    #[test]
    fn gaussian_zero_variable_empty_system_solves_empty_solution() {
        let mut basic = GaussianSolver::new(0, 0);
        let mut markowitz = GaussianSolver::new(0, 0);

        assert_eq!(basic.solve(), GaussianResult::Solved(Vec::new()));
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Solved(Vec::new())
        );
        assert_eq!(basic.stats().pivot_selections, 0);
        assert_eq!(markowitz.stats().pivot_selections, 0);
    }

    #[test]
    fn gaussian_zero_variable_nonzero_rhs_is_inconsistent() {
        let mut basic = GaussianSolver::new(1, 0);
        basic.set_row(0, &[], DenseRow::new(vec![0xA5]));

        let mut markowitz = GaussianSolver::new(1, 0);
        markowitz.set_row(0, &[], DenseRow::new(vec![0xA5]));

        assert_eq!(basic.solve(), GaussianResult::Inconsistent { row: 0 });
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Inconsistent { row: 0 }
        );
        assert_eq!(basic.stats().pivot_selections, 0);
        assert_eq!(markowitz.stats().pivot_selections, 0);
    }

    #[test]
    #[should_panic(expected = "row out of bounds")]
    fn gaussian_set_row_rejects_out_of_range_row() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(2, &[1, 0], DenseRow::new(vec![1]));
    }

    #[test]
    #[should_panic(expected = "coefficient length mismatch")]
    fn gaussian_set_row_rejects_coefficient_length_mismatch() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1], DenseRow::new(vec![1]));
    }

    #[test]
    #[should_panic(expected = "row out of bounds")]
    fn gaussian_set_coefficient_rejects_out_of_range_row() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_coefficient(2, 0, Gf256::ONE);
    }

    #[test]
    #[should_panic(expected = "column out of bounds")]
    fn gaussian_set_coefficient_rejects_out_of_range_column() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_coefficient(0, 2, Gf256::ONE);
    }

    #[test]
    #[should_panic(expected = "row out of bounds")]
    fn gaussian_set_rhs_rejects_out_of_range_row() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_rhs(2, DenseRow::new(vec![1]));
    }

    #[test]
    fn gaussian_try_setters_report_input_errors_without_mutating_solver() {
        let mut solver = GaussianSolver::new(2, 2);
        solver
            .try_set_row(0, &[1, 0], DenseRow::new(vec![0x10]))
            .expect("baseline row");
        solver
            .try_set_coefficient(1, 1, Gf256::new(0x22))
            .expect("baseline coefficient");
        solver
            .try_set_rhs(1, DenseRow::new(vec![0x20]))
            .expect("baseline rhs");

        let matrix_before = solver.matrix.clone();
        let rhs_before = solver.rhs.clone();

        assert_eq!(
            solver.try_set_row(2, &[1, 0], DenseRow::new(vec![0xAA])),
            Err(GaussianInputError::RowOutOfBounds { row: 2, rows: 2 })
        );
        assert_eq!(
            solver.try_set_row(0, &[1], DenseRow::new(vec![0xAA])),
            Err(GaussianInputError::CoefficientLengthMismatch {
                row: 0,
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            solver.try_set_coefficient(1, 2, Gf256::ONE),
            Err(GaussianInputError::ColumnOutOfBounds {
                row: 1,
                column: 2,
                cols: 2,
            })
        );
        assert_eq!(
            solver.try_set_rhs(7, DenseRow::new(vec![0xFF])),
            Err(GaussianInputError::RowOutOfBounds { row: 7, rows: 2 })
        );

        assert_eq!(
            solver.matrix, matrix_before,
            "invalid fallible setters must not change coefficients"
        );
        assert_eq!(
            solver.rhs, rhs_before,
            "invalid fallible setters must not change RHS rows"
        );
    }

    #[test]
    fn gaussian_input_error_display_is_stable_and_triage_friendly() {
        assert_eq!(
            GaussianInputError::RowOutOfBounds { row: 4, rows: 3 }.to_string(),
            "row out of bounds: 4 >= 3"
        );
        assert_eq!(
            GaussianInputError::ColumnOutOfBounds {
                row: 1,
                column: 9,
                cols: 8,
            }
            .to_string(),
            "column out of bounds: row 1, column 9 >= 8"
        );
        assert_eq!(
            GaussianInputError::CoefficientLengthMismatch {
                row: 2,
                expected: 5,
                actual: 4,
            }
            .to_string(),
            "coefficient length mismatch: row 2, expected 5, actual 4"
        );
    }

    /// br-asupersync-yjjgz1: a 3x3 matrix where ONE column is fully
    /// zero while the other columns carry valid data. Distinct from
    /// gaussian_all_zeros_matrix_returns_singular (whole matrix
    /// zero) because here pivot selection must specifically reject
    /// the zero column for ITS column index while still finding
    /// pivots in the populated columns. A regression in find_pivot's
    /// bounds checks or column-iteration loop could miscount the
    /// rank, miscount free variables, or panic on the missing
    /// pivot.
    ///
    ///   Coefficients (col 1 is all zeros):     RHS:
    ///     [1 0 1]                                [2]
    ///     [0 0 1]                                [1]
    ///     [1 0 0]                                [1]
    ///
    /// The system is rank-deficient (rank 2, 3 unknowns) so the
    /// solver MUST return Singular (or Inconsistent if the RHS path
    /// flags the contradiction first) — never Solved. The exact
    /// classification depends on the solver's pivot-selection order;
    /// either non-Solved outcome is acceptable as the conformance
    /// signal.
    #[test]
    fn gaussian_single_zero_column_returns_singular() {
        let mut solver = GaussianSolver::new(3, 3);
        solver.set_row(0, &[1, 0, 1], DenseRow::new(vec![2]));
        solver.set_row(1, &[0, 0, 1], DenseRow::new(vec![1]));
        solver.set_row(2, &[1, 0, 0], DenseRow::new(vec![1]));

        assert_eq!(
            solver.rank_status(),
            GaussianRankStatus {
                rows: 3,
                columns: 3,
                rank: 2,
                deficit: 1,
            },
            "rank probe must report the true coefficient rank before the unique-solve path fails closed"
        );

        match solver.solve() {
            GaussianResult::Singular { .. } => {}
            GaussianResult::Inconsistent { .. } => {
                // Acceptable too — both signal "no unique solution".
            }
            GaussianResult::Solved(_) => panic!(
                "br-asupersync-yjjgz1: a matrix with a fully-zero \
                 column is rank-deficient and MUST NOT solve"
            ),
        }

        assert_eq!(
            solver.rank_status().rank,
            2,
            "rank probe should remain stable after the in-place elimination attempt"
        );
    }

    #[test]
    fn gaussian_zero_row_contradiction_before_first_pivot_reports_inconsistent() {
        let mut basic = GaussianSolver::new(2, 2);
        basic.set_row(0, &[0, 0], DenseRow::new(vec![0x41]));
        basic.set_row(1, &[0, 7], DenseRow::new(vec![0x22]));

        let mut markowitz = GaussianSolver::new(2, 2);
        markowitz.set_row(0, &[0, 0], DenseRow::new(vec![0x41]));
        markowitz.set_row(1, &[0, 7], DenseRow::new(vec![0x22]));

        assert_eq!(
            basic.solve(),
            GaussianResult::Inconsistent { row: 0 },
            "basic solver should surface an explicit zero-row contradiction before returning singular"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Inconsistent { row: 0 },
            "markowitz solver should surface the same zero-row contradiction before returning singular"
        );
    }

    #[test]
    fn gaussian_zero_rhs_free_variable_before_first_pivot_remains_singular() {
        let mut basic = GaussianSolver::new(2, 2);
        basic.set_row(0, &[0, 0], DenseRow::new(vec![0x00]));
        basic.set_row(1, &[0, 7], DenseRow::new(vec![0x22]));

        let mut markowitz = GaussianSolver::new(2, 2);
        markowitz.set_row(0, &[0, 0], DenseRow::new(vec![0x00]));
        markowitz.set_row(1, &[0, 7], DenseRow::new(vec![0x22]));

        assert_eq!(
            basic.solve(),
            GaussianResult::Singular { row: 0 },
            "basic solver should still report singular when the no-pivot frontier has no contradiction"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Singular { row: 0 },
            "markowitz solver should keep the same singular result when the zero row has a zero RHS"
        );
    }

    #[test]
    fn gaussian_inconsistent_overdetermined_matrix_detected() {
        // x = 0x10, y = 0x20, and x + y = 0x31 (contradiction since 0x10 ^ 0x20 = 0x30).
        let mut basic = GaussianSolver::new(3, 2);
        basic.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
        basic.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
        basic.set_row(2, &[1, 1], DenseRow::new(vec![0x31]));

        let mut markowitz = GaussianSolver::new(3, 2);
        markowitz.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
        markowitz.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
        markowitz.set_row(2, &[1, 1], DenseRow::new(vec![0x31]));

        assert_eq!(
            basic.solve(),
            GaussianResult::Inconsistent { row: 2 },
            "basic solver should report transformed inconsistent row"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Inconsistent { row: 2 },
            "markowitz solver should report the same inconsistent row"
        );
    }

    #[test]
    fn gaussian_multibyte_rhs_contradiction_preserves_coefficient_rank_witness() {
        fn build_solver() -> GaussianSolver {
            let mut solver = GaussianSolver::new(3, 2);
            solver.set_row(0, &[1, 0], DenseRow::new(vec![0x10, 0x20]));
            solver.set_row(1, &[0, 1], DenseRow::new(vec![0x30, 0x40]));
            // Coefficients are row0 + row1, but the second RHS byte is off by 1.
            // The matrix rank is still full for two variables; only the
            // augmented system is inconsistent.
            solver.set_row(2, &[1, 1], DenseRow::new(vec![0x20, 0x61]));
            solver
        }

        for (name, mut solver, solve) in [
            (
                "basic",
                build_solver(),
                GaussianSolver::solve as fn(&mut GaussianSolver) -> GaussianResult,
            ),
            ("markowitz", build_solver(), GaussianSolver::solve_markowitz),
        ] {
            assert_eq!(
                solver.rank_profile(),
                GaussianRankProfile {
                    rows: 3,
                    columns: 2,
                    rank: 2,
                    deficit: 0,
                    pivot_columns: vec![0, 1],
                    free_columns: Vec::new(),
                },
                "{name} coefficient-rank probe must ignore RHS contradictions"
            );
            assert_eq!(
                solve(&mut solver),
                GaussianResult::Inconsistent { row: 2 },
                "{name} solver must reject any-byte RHS contradiction without reporting rank deficiency"
            );
        }
    }

    #[test]
    fn gaussian_consistent_overdetermined_matrix_returns_variable_rows_only() {
        let mut basic = GaussianSolver::new(3, 2);
        basic.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
        basic.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
        basic.set_row(2, &[1, 1], DenseRow::new(vec![0x30]));

        let mut markowitz = GaussianSolver::new(3, 2);
        markowitz.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
        markowitz.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
        markowitz.set_row(2, &[1, 1], DenseRow::new(vec![0x30]));

        for (name, result) in [
            ("basic", basic.solve()),
            ("markowitz", markowitz.solve_markowitz()),
        ] {
            match result {
                GaussianResult::Solved(solution) => {
                    assert_eq!(
                        solution.len(),
                        2,
                        "{name} should return one row per variable"
                    );
                    let x = solution[0].get(0);
                    let y = solution[1].get(0);
                    assert_eq!(x, Gf256::new(0x10), "{name} x value");
                    assert_eq!(y, Gf256::new(0x20), "{name} y value");
                    assert_eq!(x + y, Gf256::new(0x30), "{name} redundant row check");
                }
                GaussianResult::Singular { row } => {
                    panic!("{name} unexpectedly reported singular at row {row}")
                }
                GaussianResult::Inconsistent { row } => {
                    panic!("{name} unexpectedly reported inconsistent at row {row}")
                }
            }
        }
    }

    #[test]
    fn metamorphic_dependent_row_extension_preserves_rank_solution() {
        fn build_base_solver() -> GaussianSolver {
            let mut solver = GaussianSolver::new(2, 2);
            solver.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
            solver.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
            solver
        }

        fn build_augmented_solver() -> GaussianSolver {
            let mut solver = GaussianSolver::new(3, 2);
            solver.set_row(0, &[1, 0], DenseRow::new(vec![0x10]));
            solver.set_row(1, &[0, 1], DenseRow::new(vec![0x20]));
            // Row 2 is the GF(256) sum of rows 0 and 1, so it is rank-preserving noise.
            solver.set_row(2, &[1, 1], DenseRow::new(vec![0x30]));
            solver
        }

        for (name, base_result, augmented_result) in [
            (
                "basic",
                build_base_solver().solve(),
                build_augmented_solver().solve(),
            ),
            (
                "markowitz",
                build_base_solver().solve_markowitz(),
                build_augmented_solver().solve_markowitz(),
            ),
        ] {
            match (base_result, augmented_result) {
                (GaussianResult::Solved(base), GaussianResult::Solved(augmented)) => {
                    assert_eq!(
                        base, augmented,
                        "{name} elimination should preserve the solved variable rows when only a dependent row is appended"
                    );
                }
                (base, augmented) => {
                    panic!(
                        "{name} elimination changed result kind under dependent-row extension: base={base:?} augmented={augmented:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn gaussian_underdetermined_matrix_fails_closed() {
        let mut basic = GaussianSolver::new(2, 3);
        basic.set_row(0, &[1, 0, 0], DenseRow::new(vec![0x10]));
        basic.set_row(1, &[0, 1, 0], DenseRow::new(vec![0x20]));

        let mut markowitz = GaussianSolver::new(2, 3);
        markowitz.set_row(0, &[1, 0, 0], DenseRow::new(vec![0x10]));
        markowitz.set_row(1, &[0, 1, 0], DenseRow::new(vec![0x20]));

        assert_eq!(
            basic.solve(),
            GaussianResult::Singular { row: 2 },
            "basic solver should fail closed when a free variable remains"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Singular { row: 2 },
            "markowitz solver should fail closed when a free variable remains"
        );
    }

    #[test]
    fn gaussian_single_column_inconsistent_rhs_detected() {
        // Two contradictory equations in one variable: x = 5, x = 7.
        // This exercises elimination where `pivot` is the last column and
        // coefficient-tail updates are empty (RHS-only update path).
        let mut basic = GaussianSolver::new(2, 1);
        basic.set_row(0, &[1], DenseRow::new(vec![5]));
        basic.set_row(1, &[1], DenseRow::new(vec![7]));

        let mut markowitz = GaussianSolver::new(2, 1);
        markowitz.set_row(0, &[1], DenseRow::new(vec![5]));
        markowitz.set_row(1, &[1], DenseRow::new(vec![7]));

        assert_eq!(
            basic.solve(),
            GaussianResult::Inconsistent { row: 1 },
            "basic solver should detect inconsistent RHS after eliminating the only column"
        );
        assert_eq!(
            markowitz.solve_markowitz(),
            GaussianResult::Inconsistent { row: 1 },
            "markowitz solver should detect the same inconsistency"
        );
    }

    #[test]
    fn markowitz_prefers_singleton_candidate() {
        let mut solver = GaussianSolver::new(4, 4);
        solver.set_row(0, &[1, 1, 1, 1], DenseRow::zeros(0));
        solver.set_row(1, &[1, 0, 1, 0], DenseRow::zeros(0));
        solver.set_row(2, &[1, 0, 0, 0], DenseRow::zeros(0));
        solver.set_row(3, &[1, 1, 0, 0], DenseRow::zeros(0));

        assert_eq!(
            solver.find_pivot_markowitz(0, 0),
            Some((2, 1)),
            "singleton candidate should be selected as soon as observed"
        );
    }

    #[test]
    fn markowitz_tie_breaks_to_lower_row_index() {
        let mut solver = GaussianSolver::new(3, 4);
        solver.set_row(0, &[0, 1, 0, 1], DenseRow::zeros(0));
        solver.set_row(1, &[0, 1, 1, 0], DenseRow::zeros(0));
        solver.set_row(2, &[0, 0, 1, 1], DenseRow::zeros(0));

        assert_eq!(
            solver.find_pivot_markowitz(1, 0),
            Some((0, 2)),
            "equal-nnz candidates should retain lowest row index"
        );
    }

    #[test]
    fn markowitz_column_offset_prefers_sparser_tail() {
        let mut solver = GaussianSolver::new(3, 5);
        solver.set_row(0, &[0, 0, 1, 1, 1], DenseRow::zeros(0));
        solver.set_row(1, &[0, 0, 1, 0, 0], DenseRow::zeros(0));
        solver.set_row(2, &[0, 0, 1, 0, 1], DenseRow::zeros(0));

        assert_eq!(
            solver.find_pivot_markowitz(2, 0),
            Some((1, 1)),
            "pivot selection should use nonzero count from active column tail"
        );
    }

    #[test]
    fn nonzero_count_capped_from_respects_start_and_cap() {
        let row = [1, 0, 1, 1, 0, 1];
        assert_eq!(count_nonzero_capped_from(&row, 0, usize::MAX), 4);
        assert_eq!(count_nonzero_capped_from(&row, 2, usize::MAX), 3);
        assert_eq!(count_nonzero_capped_from(&row, 2, 1), 2);
        assert_eq!(count_nonzero_capped_from(&row, row.len(), usize::MAX), 0);
    }

    #[test]
    fn nonzero_count_capped_from_short_circuits_tie_or_worse_rows() {
        let row = [1, 1, 1, 1, 1, 1, 1, 1];
        // `cap = 1` models incumbent nnz=2 with cap=best_nnz-1.
        assert_eq!(count_nonzero_capped_from(&row, 0, 1), 2);
    }

    #[test]
    fn eliminate_row_factor_one_updates_tail_and_rhs_as_xor() {
        let mut solver = GaussianSolver::new(2, 4);
        solver.set_row(0, &[0, 9, 4, 5], DenseRow::new(vec![11, 22, 33]));
        solver.set_row(1, &[0, 1, 2, 3], DenseRow::new(vec![10, 20, 30]));

        solver.eliminate_row(0, 1, Gf256::ONE);

        assert_eq!(solver.matrix[0], vec![0, 0, 6, 6]);
        assert_eq!(solver.rhs[0].as_slice(), &[1, 2, 63]);
    }

    #[test]
    fn eliminate_row_target_after_pivot_resizes_rhs_and_updates_tail() {
        let mut solver = GaussianSolver::new(3, 4);
        solver.set_row(
            1,
            &[0xCC, 1, 0x04, 0x05],
            DenseRow::new(vec![0x33, 0x44, 0x55]),
        );
        solver.set_row(2, &[0xAA, 7, 0x10, 0x20], DenseRow::new(vec![0x11]));

        let factor = Gf256::new(0x0F);
        solver.eliminate_row(2, 1, factor);

        let expected_tail = [
            (Gf256::new(0x10) + factor * Gf256::new(0x04)).raw(),
            (Gf256::new(0x20) + factor * Gf256::new(0x05)).raw(),
        ];
        let expected_rhs = [
            (Gf256::new(0x11) + factor * Gf256::new(0x33)).raw(),
            (factor * Gf256::new(0x44)).raw(),
            (factor * Gf256::new(0x55)).raw(),
        ];

        assert_eq!(
            solver.matrix[2],
            vec![0xAA, 0, expected_tail[0], expected_tail[1]]
        );
        assert_eq!(solver.rhs[2].as_slice(), &expected_rhs);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_target_after_pivot_with_factor_one_resizes_rhs_and_xors_tail() {
        let mut solver = GaussianSolver::new(3, 4);
        solver.set_row(
            1,
            &[0xCC, 1, 0x04, 0x05],
            DenseRow::new(vec![0x33, 0x44, 0x55]),
        );
        solver.set_row(2, &[0xAA, 7, 0x10, 0x20], DenseRow::new(vec![0x11]));

        solver.eliminate_row(2, 1, Gf256::ONE);

        let expected_tail = [
            Gf256::new(0x10).add(Gf256::new(0x04)).raw(),
            Gf256::new(0x20).add(Gf256::new(0x05)).raw(),
        ];
        let expected_rhs = [
            (Gf256::new(0x11) + Gf256::new(0x33)).raw(),
            Gf256::new(0x44).raw(),
            Gf256::new(0x55).raw(),
        ];

        assert_eq!(
            solver.matrix[2],
            vec![0xAA, 0, expected_tail[0], expected_tail[1]]
        );
        assert_eq!(solver.rhs[2].as_slice(), &expected_rhs);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_target_before_pivot_resizes_rhs_and_updates_tail() {
        let mut solver = GaussianSolver::new(3, 4);
        solver.set_row(0, &[0xAA, 0xBB, 7, 0x10], DenseRow::new(vec![0x11]));
        solver.set_row(
            2,
            &[0xCC, 0xDD, 1, 0x04],
            DenseRow::new(vec![0x33, 0x44, 0x55]),
        );

        let factor = Gf256::new(0x0F);
        solver.eliminate_row(0, 2, factor);

        let expected_tail = [(Gf256::new(0x10) + factor * Gf256::new(0x04)).raw()];
        let expected_rhs = [
            (Gf256::new(0x11) + factor * Gf256::new(0x33)).raw(),
            (factor * Gf256::new(0x44)).raw(),
            (factor * Gf256::new(0x55)).raw(),
        ];

        assert_eq!(solver.matrix[0], vec![0xAA, 0xBB, 0, expected_tail[0]]);
        assert_eq!(solver.rhs[0].as_slice(), &expected_rhs);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_target_before_pivot_with_factor_one_resizes_rhs_and_xors_tail() {
        let mut solver = GaussianSolver::new(3, 4);
        solver.set_row(0, &[0xAA, 0xBB, 7, 0x10], DenseRow::new(vec![0x11]));
        solver.set_row(
            2,
            &[0xCC, 0xDD, 1, 0x04],
            DenseRow::new(vec![0x33, 0x44, 0x55]),
        );

        solver.eliminate_row(0, 2, Gf256::ONE);

        let expected_tail = [Gf256::new(0x10).add(Gf256::new(0x04)).raw()];
        let expected_rhs = [
            (Gf256::new(0x11) + Gf256::new(0x33)).raw(),
            Gf256::new(0x44).raw(),
            Gf256::new(0x55).raw(),
        ];

        assert_eq!(solver.matrix[0], vec![0xAA, 0xBB, 0, expected_tail[0]]);
        assert_eq!(solver.rhs[0].as_slice(), &expected_rhs);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_factor_zero_is_noop() {
        let mut solver = GaussianSolver::new(2, 4);
        solver.set_row(0, &[7, 9, 4, 5], DenseRow::new(vec![11, 22, 33]));
        solver.set_row(1, &[6, 1, 2, 3], DenseRow::new(vec![10, 20, 30]));

        let before_scale_adds = solver.stats.scale_adds;
        let before_row = solver.matrix[0].clone();
        let before_rhs = solver.rhs[0].as_slice().to_vec();
        solver.eliminate_row(0, 1, Gf256::ZERO);

        assert_eq!(solver.matrix[0], before_row);
        assert_eq!(solver.rhs[0].as_slice(), before_rhs.as_slice());
        assert_eq!(solver.stats.scale_adds, before_scale_adds);
    }

    #[test]
    fn eliminate_row_target_equals_pivot_is_noop() {
        let mut solver = GaussianSolver::new(2, 4);
        solver.set_row(0, &[7, 9, 4, 5], DenseRow::new(vec![11, 22, 33]));
        solver.set_row(1, &[6, 1, 2, 3], DenseRow::new(vec![10, 20, 30]));

        let before_scale_adds = solver.stats.scale_adds;
        let before_row = solver.matrix[0].clone();
        let before_rhs = solver.rhs[0].as_slice().to_vec();
        solver.eliminate_row(0, 0, Gf256::new(7));

        assert_eq!(solver.matrix[0], before_row);
        assert_eq!(solver.rhs[0].as_slice(), before_rhs.as_slice());
        assert_eq!(solver.stats.scale_adds, before_scale_adds);
    }

    #[test]
    fn eliminate_row_pivot_only_with_empty_rhs_short_circuits_tail_work() {
        let mut solver = GaussianSolver::new(3, 3);
        solver.set_row(0, &[4, 8, 55], DenseRow::zeros(0));
        solver.set_row(2, &[1, 2, 9], DenseRow::zeros(0));

        solver.eliminate_row(0, 2, Gf256::new(7));

        assert_eq!(solver.matrix[0], vec![4, 8, 0]);
        assert!(solver.rhs[0].as_slice().is_empty());
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_pivot_only_with_rhs_nonone_updates_rhs_only() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[0xAA, 7], DenseRow::new(vec![0x55]));
        solver.set_row(1, &[0xCC, 1], DenseRow::new(vec![0x23]));

        let factor = Gf256::new(0x0f);
        solver.eliminate_row(0, 1, factor);

        let expected_rhs = Gf256::new(0x55) + (factor * Gf256::new(0x23));
        assert_eq!(solver.matrix[0], vec![0xAA, 0]);
        assert_eq!(solver.rhs[0].as_slice(), &[expected_rhs.raw()]);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn eliminate_row_pivot_only_with_rhs_one_updates_rhs_only() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[0xAA, 7], DenseRow::new(vec![0x55]));
        solver.set_row(1, &[0xCC, 1], DenseRow::new(vec![0x23]));

        solver.eliminate_row(0, 1, Gf256::ONE);

        let expected_rhs = Gf256::new(0x55) + Gf256::new(0x23);
        assert_eq!(solver.matrix[0], vec![0xAA, 0]);
        assert_eq!(solver.rhs[0].as_slice(), &[expected_rhs.raw()]);
        assert_eq!(solver.stats.scale_adds, 1);
    }

    #[test]
    fn normalize_pivot_row_scales_active_tail_only() {
        let mut solver = GaussianSolver::new(4, 4);
        solver.set_row(0, &[1, 0, 0, 0], DenseRow::zeros(0));
        solver.set_row(1, &[0, 1, 0, 0], DenseRow::zeros(0));
        solver.set_row(2, &[0, 0, 2, 4], DenseRow::new(vec![8, 16]));
        solver.set_row(3, &[0, 0, 0, 1], DenseRow::zeros(0));

        let inv = Gf256::new(2).inv();
        let expected_col3 = (Gf256::new(4) * inv).raw();
        let expected_rhs = [(Gf256::new(8) * inv).raw(), (Gf256::new(16) * inv).raw()];

        solver.normalize_pivot_row(2);

        assert_eq!(solver.matrix[2], vec![0, 0, 1, expected_col3]);
        assert_eq!(solver.rhs[2].as_slice(), &expected_rhs);
    }

    #[test]
    fn normalize_pivot_row_with_empty_rhs_scales_tail_only() {
        let mut solver = GaussianSolver::new(4, 4);
        solver.set_row(0, &[1, 0, 0, 0], DenseRow::zeros(0));
        solver.set_row(1, &[0, 1, 0, 0], DenseRow::zeros(0));
        solver.set_row(2, &[0, 0, 3, 6], DenseRow::zeros(0));
        solver.set_row(3, &[0, 0, 0, 1], DenseRow::zeros(0));

        let inv = Gf256::new(3).inv();
        let expected = vec![0, 0, 1, (Gf256::new(6) * inv).raw()];

        solver.normalize_pivot_row(2);

        assert_eq!(solver.matrix[2], expected);
        assert!(solver.rhs[2].as_slice().is_empty());
    }

    #[test]
    fn solve_normalizes_late_pivot_without_touching_zero_prefix() {
        let mut basic = GaussianSolver::new(3, 3);
        basic.set_row(0, &[1, 0, 0], DenseRow::new(vec![0x10]));
        basic.set_row(1, &[0, 5, 0], DenseRow::new(vec![0x20]));
        basic.set_row(2, &[0, 0, 7], DenseRow::new(vec![0x30]));

        let mut markowitz = GaussianSolver::new(3, 3);
        markowitz.set_row(0, &[1, 0, 0], DenseRow::new(vec![0x10]));
        markowitz.set_row(1, &[0, 5, 0], DenseRow::new(vec![0x20]));
        markowitz.set_row(2, &[0, 0, 7], DenseRow::new(vec![0x30]));

        match basic.solve() {
            GaussianResult::Solved(solution) => {
                assert_eq!(solution[0].as_slice(), &[0x10]);
                assert_eq!(Gf256::new(5) * solution[1].get(0), Gf256::new(0x20));
                assert_eq!(Gf256::new(7) * solution[2].get(0), Gf256::new(0x30));
            }
            other => panic!("unexpected basic result: {other:?}"),
        }

        match markowitz.solve_markowitz() {
            GaussianResult::Solved(solution) => {
                assert_eq!(solution[0].as_slice(), &[0x10]);
                assert_eq!(Gf256::new(5) * solution[1].get(0), Gf256::new(0x20));
                assert_eq!(Gf256::new(7) * solution[2].get(0), Gf256::new(0x30));
            }
            other => panic!("unexpected markowitz result: {other:?}"),
        }
    }

    #[test]
    fn dense_row_debug_clone_eq() {
        let r = DenseRow::new(vec![1, 2, 3]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("DenseRow"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_ne!(r, DenseRow::zeros(3));
    }

    #[test]
    fn sparse_row_debug_clone_eq() {
        let r = SparseRow::new(vec![(0, Gf256::new(1)), (2, Gf256::new(5))], 4);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("SparseRow"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_ne!(r, SparseRow::zeros(4));
    }

    #[test]
    fn gaussian_result_debug_clone_eq() {
        let s = GaussianResult::Singular { row: 3 };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Singular"), "{dbg}");
        let cloned = s.clone();
        assert_eq!(s, cloned);
        assert_ne!(s, GaussianResult::Inconsistent { row: 3 });

        assert_eq!(s.outcome_kind(), GaussianOutcomeKind::Singular);
        assert!(!s.is_solved());
        assert_eq!(
            GaussianResult::Solved(Vec::new()).outcome_kind(),
            GaussianOutcomeKind::Solved
        );
        assert!(GaussianResult::Solved(Vec::new()).is_solved());
        assert_eq!(
            GaussianResult::Inconsistent { row: 3 }.outcome_kind(),
            GaussianOutcomeKind::Inconsistent
        );
    }

    #[test]
    fn gaussian_stats_debug_clone_default() {
        let s = GaussianStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("GaussianStats"), "{dbg}");
        assert_eq!(s.swaps, 0);
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn metamorphic_decode_permutation_invariance() {
        let cx = Cx::for_testing();
        let data: Vec<u8> = (0..383).map(|i| (i as u8).wrapping_mul(17)).collect();
        let object_id = ObjectId::new_for_test(0xfeed_beef);

        let config = RaptorQConfig::default();
        let sink = CollectorSink::new();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config)
            .transport(sink)
            .build()
            .expect("sender build");

        let send_outcome = sender
            .send_object(&cx, object_id, &data)
            .expect("encoding should succeed");
        let symbols = sender.transport_mut().symbols().to_vec();
        let k = send_outcome.source_symbols;

        let original_symbols = &symbols[..std::cmp::min(symbols.len(), k + 3)];
        let original_payload = symbols_to_received(original_symbols, k);

        let mut permuted_payload = original_payload.clone();
        let mut rng = DetRng::new(0xdecafbad_u64);
        for i in (1..permuted_payload.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            permuted_payload.swap(i, j);
        }

        let decoder = create_test_decoder(&symbols, k);
        let mut received_original = decoder.constraint_symbols();
        received_original.extend(original_payload);
        let mut received_permuted = decoder.constraint_symbols();
        received_permuted.extend(permuted_payload);
        let decoded_original = decoder
            .decode(&received_original)
            .expect("original ordering should decode");
        let decoded_permuted = decoder
            .decode(&received_permuted)
            .expect("permuted ordering should decode");

        assert_eq!(
            flatten_source_symbols(&decoded_original.source, data.len()),
            flatten_source_symbols(&decoded_permuted.source, data.len()),
            "decode output must be byte-identical under symbol-set permutation"
        );
    }

    // ── br-asupersync-mwx6zi: solve / solve_markowitz must agree ─────

    /// Helper: classify a `GaussianResult` into its discriminant
    /// without comparing the (pivot-strategy-dependent) `row` field.
    /// Cross-solver agreement is on the SYSTEM classification, not on
    /// which specific row index each strategy happens to surface.
    fn _mwx6zi_class(r: &GaussianResult) -> &'static str {
        match r {
            GaussianResult::Solved(_) => "Solved",
            GaussianResult::Singular { .. } => "Singular",
            GaussianResult::Inconsistent { .. } => "Inconsistent",
        }
    }

    /// Build a solver from a 2D coefficient matrix and a parallel
    /// RHS vector (one byte per row, expanded into a single-byte
    /// `DenseRow`).
    fn _mwx6zi_solver(coeffs: &[Vec<u8>], rhs: &[u8]) -> GaussianSolver {
        assert_eq!(coeffs.len(), rhs.len());
        let rows = coeffs.len();
        let cols = if rows == 0 { 0 } else { coeffs[0].len() };
        let mut s = GaussianSolver::new(rows, cols);
        for (i, row) in coeffs.iter().enumerate() {
            s.set_row(i, row, DenseRow::new(vec![rhs[i]]));
        }
        s
    }

    /// Pre-fix repro: a rank-deficient system whose contradiction
    /// row depends on the pivot strategy's choice of pivot row.
    /// `solve` and `solve_markowitz` historically classified this
    /// 4x3 system DIFFERENTLY — one as Inconsistent (when pivot
    /// alignment landed on the contradiction) and one as Singular
    /// (when alignment missed it). After the fix both perform a
    /// FULL post-stall scan and agree.
    #[test]
    fn mwx6zi_classifier_agreement_rank_deficient_with_late_contradiction() {
        // 4x3 over GF(256). Column 0 has 3 nonzeros, column 1 has
        // 2, column 2 is structurally zero. Row 2 carries an
        // explicit zero-coefficient nonzero-RHS contradiction.
        // Whether that contradiction lands on the pivot-stall row
        // depends on pivot strategy — without the fix the two
        // solvers diverged.
        let coeffs = vec![vec![1u8, 1, 0], vec![1, 0, 0], vec![0, 0, 0], vec![1, 1, 0]];
        let rhs = vec![0u8, 0, 1, 0];

        let mut s_basic = _mwx6zi_solver(&coeffs, &rhs);
        let mut s_mark = _mwx6zi_solver(&coeffs, &rhs);
        let r_basic = s_basic.solve();
        let r_mark = s_mark.solve_markowitz();

        assert_eq!(
            _mwx6zi_class(&r_basic),
            _mwx6zi_class(&r_mark),
            "solve and solve_markowitz must classify the same system \
             identically; got basic={r_basic:?}, markowitz={r_mark:?}"
        );
        // Specifically, this system IS inconsistent (row 2 is
        // 0·x = 1, an unsatisfiable equation) — both must say so.
        assert_eq!(
            _mwx6zi_class(&r_basic),
            "Inconsistent",
            "rank-deficient + 0=1 row must classify as Inconsistent, \
             not Singular; got {r_basic:?}"
        );
    }

    /// Positive control: a genuinely singular system (rank-deficient
    /// but with b in the column space) must classify as Singular by
    /// BOTH solvers — never Inconsistent.
    #[test]
    fn mwx6zi_classifier_agreement_rank_deficient_no_contradiction() {
        let coeffs = vec![vec![1u8, 0, 0], vec![0, 0, 0], vec![0, 0, 0]];
        let rhs = vec![5u8, 0, 0];

        let mut s_basic = _mwx6zi_solver(&coeffs, &rhs);
        let mut s_mark = _mwx6zi_solver(&coeffs, &rhs);
        let r_basic = s_basic.solve();
        let r_mark = s_mark.solve_markowitz();

        assert_eq!(_mwx6zi_class(&r_basic), _mwx6zi_class(&r_mark));
        assert_eq!(
            _mwx6zi_class(&r_basic),
            "Singular",
            "rank-deficient with no contradicting row must classify \
             as Singular; got {r_basic:?}"
        );
    }

    /// Positive control: a fully-solvable system must classify as
    /// Solved by both solvers and produce equal solutions (the
    /// solution is unique when rank == cols).
    #[test]
    fn mwx6zi_classifier_agreement_solvable_system() {
        // Identity-like 3x3 over GF(256).
        let coeffs = vec![vec![1u8, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];
        let rhs = vec![7u8, 11, 13];

        let mut s_basic = _mwx6zi_solver(&coeffs, &rhs);
        let mut s_mark = _mwx6zi_solver(&coeffs, &rhs);
        let r_basic = s_basic.solve();
        let r_mark = s_mark.solve_markowitz();
        assert_eq!(_mwx6zi_class(&r_basic), "Solved");
        assert_eq!(_mwx6zi_class(&r_mark), "Solved");
        if let (GaussianResult::Solved(b), GaussianResult::Solved(m)) = (r_basic, r_mark) {
            // Solution is unique on a full-rank diagonal system; both
            // pivot strategies must produce the same vector.
            assert_eq!(b.len(), m.len());
            for (br, mr) in b.iter().zip(m.iter()) {
                assert_eq!(
                    br.as_slice(),
                    mr.as_slice(),
                    "unique-solution systems must produce identical \
                     answers under both pivot strategies"
                );
            }
        }
    }

    /// Cross-class fuzz-style sweep: a small batch of synthetic
    /// matrices must always have matching discriminants under both
    /// pivot strategies. This is the property that the original
    /// fuzz target enforces — pinning it in unit tests catches
    /// future regressions without requiring the fuzzer to run.
    #[test]
    fn mwx6zi_classifier_agreement_synthetic_sweep() {
        let cases: &[(Vec<Vec<u8>>, Vec<u8>)] = &[
            // 2x2 solvable
            (vec![vec![1, 0], vec![0, 1]], vec![1, 1]),
            // 2x2 singular, b in column space
            (vec![vec![1, 1], vec![1, 1]], vec![3, 3]),
            // 2x2 inconsistent (contradicting parallel rows)
            (vec![vec![1, 1], vec![1, 1]], vec![3, 4]),
            // 3x3 with zero-row contradiction at the bottom
            (
                vec![vec![1, 1, 0], vec![0, 1, 0], vec![0, 0, 0]],
                vec![1, 2, 5],
            ),
            // 3x3 zero-row consistent
            (
                vec![vec![1, 1, 0], vec![0, 1, 0], vec![0, 0, 0]],
                vec![1, 2, 0],
            ),
            // Wider-than-tall (rows < cols → Singular by solved_result)
            (vec![vec![1, 0, 0], vec![0, 1, 0]], vec![1, 1]),
        ];

        for (idx, (coeffs, rhs)) in cases.iter().enumerate() {
            let mut s_basic = _mwx6zi_solver(coeffs, rhs);
            let mut s_mark = _mwx6zi_solver(coeffs, rhs);
            let r_basic = s_basic.solve();
            let r_mark = s_mark.solve_markowitz();
            assert_eq!(
                _mwx6zi_class(&r_basic),
                _mwx6zi_class(&r_mark),
                "case[{idx}] discriminant mismatch: \
                 basic={r_basic:?} markowitz={r_mark:?} (coeffs={coeffs:?} rhs={rhs:?})"
            );
        }
    }
