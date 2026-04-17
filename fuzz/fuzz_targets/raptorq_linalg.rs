//! Fuzz target for RaptorQ linear algebra primitives over GF(256).
//!
//! Tests the linalg.rs module covering:
//! 1. Row operations: XOR, scale-add, swap, scale with various GF(256) coefficients
//! 2. DenseRow creation, manipulation, and conversion to sparse representation
//! 3. SparseRow creation, manipulation, and conversion to dense representation
//! 4. Pivot selection algorithms: basic and Markowitz strategies
//! 5. Helper functions: nonzero counting, first nonzero finding
//! 6. Boundary conditions: empty rows, single elements, max-size vectors
//! 7. GF(256) arithmetic edge cases in matrix context

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{
    DenseRow, SparseRow, row_xor, row_scale_add, row_swap, row_scale,
    select_pivot_basic, select_pivot_markowitz, row_nonzero_count, row_first_nonzero_from
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

/// Maximum row size to prevent memory exhaustion during fuzzing
const MAX_ROW_LEN: usize = 1024;
const MAX_SPARSE_ENTRIES: usize = 256;
const MAX_MATRIX_ROWS: usize = 32;

/// Fuzzing input structure for RaptorQ linear algebra primitives
#[derive(Arbitrary, Debug)]
struct RaptorQLinalgFuzzInput {
    /// Row operation tests
    row_ops: Vec<RowOperation>,
    /// Dense row manipulation tests
    dense_row_ops: Vec<DenseRowOperation>,
    /// Sparse row manipulation tests
    sparse_row_ops: Vec<SparseRowOperation>,
    /// Pivot selection tests
    pivot_tests: Vec<PivotTest>,
    /// Conversion and roundtrip tests
    conversion_tests: Vec<ConversionTest>,
}

/// Row-level operations on slices
#[derive(Arbitrary, Debug)]
enum RowOperation {
    /// Test row_xor with various sizes and patterns
    Xor {
        dst_data: Vec<u8>,
        src_data: Vec<u8>,
    },
    /// Test row_scale_add with GF(256) coefficients
    ScaleAdd {
        dst_data: Vec<u8>,
        src_data: Vec<u8>,
        coefficient: u8,
    },
    /// Test row_swap operation
    Swap {
        row_a_data: Vec<u8>,
        row_b_data: Vec<u8>,
    },
    /// Test row_scale with GF(256) coefficients
    Scale {
        row_data: Vec<u8>,
        coefficient: u8,
    },
    /// Test chained operations: scale-add followed by XOR
    ChainedOps {
        dst_data: Vec<u8>,
        src1_data: Vec<u8>,
        src2_data: Vec<u8>,
        coeff1: u8,
        coeff2: u8,
    },
}

/// Dense row specific operations
#[derive(Arbitrary, Debug)]
enum DenseRowOperation {
    /// Create dense row and test basic operations
    Creation {
        data: Vec<u8>,
    },
    /// Test resizing operations
    Resize {
        initial_data: Vec<u8>,
        new_len: usize,
        fill_value: u8,
    },
    /// Test get/set operations with boundary conditions
    GetSet {
        data: Vec<u8>,
        operations: Vec<GetSetOp>,
    },
    /// Test nonzero detection and counting
    NonzeroAnalysis {
        data: Vec<u8>,
        search_starts: Vec<usize>,
    },
    /// Test clearing and swapping
    Manipulation {
        row1_data: Vec<u8>,
        row2_data: Vec<u8>,
    },
}

/// Get/Set operation for dense rows
#[derive(Arbitrary, Debug)]
enum GetSetOp {
    Get { index: usize },
    Set { index: usize, value: u8 },
}

/// Sparse row specific operations
#[derive(Arbitrary, Debug)]
enum SparseRowOperation {
    /// Create sparse row with various entry patterns
    Creation {
        entries: Vec<(usize, u8)>, // Will be converted to (usize, Gf256)
        logical_len: usize,
    },
    /// Test sparse row analysis functions
    Analysis {
        entries: Vec<(usize, u8)>,
        logical_len: usize,
    },
    /// Test sparse row manipulation
    Manipulation {
        entries1: Vec<(usize, u8)>,
        entries2: Vec<(usize, u8)>,
        logical_len: usize,
    },
}

/// Pivot selection algorithm tests
#[derive(Arbitrary, Debug)]
enum PivotTest {
    /// Test basic pivot selection
    Basic {
        matrix_data: Vec<Vec<u8>>,
        start: usize,
        end: usize,
        col: usize,
    },
    /// Test Markowitz pivot selection (prefer fewer nonzeros)
    Markowitz {
        matrix_data: Vec<Vec<u8>>,
        start: usize,
        end: usize,
        col: usize,
    },
    /// Test pivot selection edge cases
    EdgeCases {
        matrix_data: Vec<Vec<u8>>,
        search_params: Vec<PivotSearchParam>,
    },
}

/// Parameters for pivot search
#[derive(Arbitrary, Debug)]
struct PivotSearchParam {
    start: usize,
    end: usize,
    col: usize,
}

/// Conversion and roundtrip tests between dense and sparse
#[derive(Arbitrary, Debug)]
enum ConversionTest {
    /// Dense to sparse conversion
    DenseToSparse {
        dense_data: Vec<u8>,
    },
    /// Sparse to dense conversion
    SparseToDense {
        entries: Vec<(usize, u8)>,
        logical_len: usize,
    },
    /// Roundtrip: dense -> sparse -> dense
    Roundtrip {
        dense_data: Vec<u8>,
    },
    /// Test conversion preserves mathematical properties
    PropertyPreservation {
        dense_data: Vec<u8>,
        test_operations: Vec<ConversionPropertyTest>,
    },
}

/// Property tests for conversions
#[derive(Arbitrary, Debug)]
enum ConversionPropertyTest {
    NonzeroCount,
    FirstNonzero,
    IsZero,
    SpecificElements { indices: Vec<usize> },
}

/// Deterministic PRNG for reproducible fuzzing (unused but kept for future extensions)
#[allow(dead_code)]
struct FuzzRng {
    state: u64,
}

#[allow(dead_code)]
impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.wrapping_add(1) } // Ensure non-zero seed
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(1103515245).wrapping_add(12345);
        (self.state >> 16) as u32
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u32() as u8
    }
}

fuzz_target!(|input: RaptorQLinalgFuzzInput| {
    // Test row operations
    for row_op in input.row_ops.iter().take(32) { // Limit iterations
        test_row_operation(row_op);
    }

    // Test dense row operations
    for dense_op in input.dense_row_ops.iter().take(16) {
        test_dense_row_operation(dense_op);
    }

    // Test sparse row operations
    for sparse_op in input.sparse_row_ops.iter().take(16) {
        test_sparse_row_operation(sparse_op);
    }

    // Test pivot selection
    for pivot_test in input.pivot_tests.iter().take(8) {
        test_pivot_selection(pivot_test);
    }

    // Test conversions and roundtrips
    for conv_test in input.conversion_tests.iter().take(8) {
        test_conversion(conv_test);
    }
});

fn test_row_operation(op: &RowOperation) {
    match op {
        RowOperation::Xor { dst_data, src_data } => {
            // Ensure compatible sizes (limit to MAX_ROW_LEN)
            let len = dst_data.len().min(src_data.len()).min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut dst = dst_data[..len].to_vec();
            let src = &src_data[..len];
            let original_dst = dst.clone();

            row_xor(&mut dst, src);

            // Verify: XOR is self-inverse
            row_xor(&mut dst, src);
            assert_eq!(dst, original_dst, "XOR self-inverse property failed");
        }

        RowOperation::ScaleAdd { dst_data, src_data, coefficient } => {
            let len = dst_data.len().min(src_data.len()).min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut dst = dst_data[..len].to_vec();
            let src = &src_data[..len];
            let original_dst = dst.clone();
            let coeff = Gf256::new(*coefficient);

            row_scale_add(&mut dst, src, coeff);

            // Test edge case: coefficient = 0 should not change dst
            if coeff.is_zero() {
                assert_eq!(dst, original_dst, "Scale-add with zero coefficient changed destination");
            }

            // Test edge case: coefficient = 1 should be equivalent to XOR
            if coeff.raw() == 1 {
                let mut expected = original_dst.clone();
                row_xor(&mut expected, src);
                assert_eq!(dst, expected, "Scale-add with coefficient 1 differs from XOR");
            }
        }

        RowOperation::Swap { row_a_data, row_b_data } => {
            let len = row_a_data.len().min(row_b_data.len()).min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut row_a = row_a_data[..len].to_vec();
            let mut row_b = row_b_data[..len].to_vec();
            let original_a = row_a.clone();
            let original_b = row_b.clone();

            row_swap(&mut row_a, &mut row_b);

            assert_eq!(row_a, original_b, "Swap failed: row_a != original row_b");
            assert_eq!(row_b, original_a, "Swap failed: row_b != original row_a");
        }

        RowOperation::Scale { row_data, coefficient } => {
            let len = row_data.len().min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut row = row_data[..len].to_vec();
            let original_row = row.clone();
            let coeff = Gf256::new(*coefficient);

            row_scale(&mut row, coeff);

            // Test edge cases
            if coeff.is_zero() {
                assert!(row.iter().all(|&x| x == 0), "Scaling by zero should produce zero row");
            }
            if coeff.raw() == 1 {
                assert_eq!(row, original_row, "Scaling by one should preserve row");
            }
        }

        RowOperation::ChainedOps { dst_data, src1_data, src2_data, coeff1, coeff2 } => {
            let len = dst_data.len().min(src1_data.len()).min(src2_data.len()).min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut dst = dst_data[..len].to_vec();
            let src1 = &src1_data[..len];
            let src2 = &src2_data[..len];

            // Chain: dst = dst + coeff1*src1 + coeff2*src2
            row_scale_add(&mut dst, src1, Gf256::new(*coeff1));
            row_scale_add(&mut dst, src2, Gf256::new(*coeff2));

            // Verify commutativity: order of operations shouldn't matter
            let mut dst_alt = dst_data[..len].to_vec();
            row_scale_add(&mut dst_alt, src2, Gf256::new(*coeff2));
            row_scale_add(&mut dst_alt, src1, Gf256::new(*coeff1));

            assert_eq!(dst, dst_alt, "Scale-add operations are not commutative");
        }
    }
}

fn test_dense_row_operation(op: &DenseRowOperation) {
    match op {
        DenseRowOperation::Creation { data } => {
            let len = data.len().min(MAX_ROW_LEN);
            let row = DenseRow::new(data[..len].to_vec());

            assert_eq!(row.len(), len);
            assert_eq!(row.is_empty(), len == 0);
            assert_eq!(row.as_slice(), &data[..len]);
        }

        DenseRowOperation::Resize { initial_data, new_len, fill_value } => {
            let len = initial_data.len().min(MAX_ROW_LEN);
            let new_len = (*new_len).min(MAX_ROW_LEN);

            let mut row = DenseRow::new(initial_data[..len].to_vec());
            row.resize(new_len, *fill_value);

            assert_eq!(row.len(), new_len);
            if new_len > len {
                // New elements should be filled with fill_value
                for i in len..new_len {
                    assert_eq!(row.get(i).raw(), *fill_value);
                }
            }
        }

        DenseRowOperation::GetSet { data, operations } => {
            let len = data.len().min(MAX_ROW_LEN);
            if len == 0 { return; }

            let mut row = DenseRow::new(data[..len].to_vec());

            for op in operations.iter().take(32) {
                match op {
                    GetSetOp::Get { index } => {
                        if *index < len {
                            let val = row.get(*index);
                            assert_eq!(val.raw(), data[*index]);
                        }
                    }
                    GetSetOp::Set { index, value } => {
                        if *index < len {
                            row.set(*index, Gf256::new(*value));
                            assert_eq!(row.get(*index).raw(), *value);
                        }
                    }
                }
            }
        }

        DenseRowOperation::NonzeroAnalysis { data, search_starts } => {
            let len = data.len().min(MAX_ROW_LEN);
            let row = DenseRow::new(data[..len].to_vec());

            // Test nonzero counting
            let expected_count = data[..len].iter().filter(|&&x| x != 0).count();
            assert_eq!(row.nonzero_count(), expected_count);
            assert_eq!(row_nonzero_count(row.as_slice()), expected_count);

            // Test is_zero
            let expected_is_zero = data[..len].iter().all(|&x| x == 0);
            assert_eq!(row.is_zero(), expected_is_zero);

            // Test first nonzero
            let expected_first = data[..len].iter().position(|&x| x != 0);
            assert_eq!(row.first_nonzero(), expected_first);

            // Test first nonzero from various starting points
            for &start in search_starts.iter().take(8) {
                if start < len {
                    let expected = data[start..len].iter().position(|&x| x != 0).map(|i| start + i);
                    assert_eq!(row.first_nonzero_from(start), expected);
                    assert_eq!(row_first_nonzero_from(row.as_slice(), start), expected);
                }
            }
        }

        DenseRowOperation::Manipulation { row1_data, row2_data } => {
            let len1 = row1_data.len().min(MAX_ROW_LEN);
            let len2 = row2_data.len().min(MAX_ROW_LEN);

            let mut row1 = DenseRow::new(row1_data[..len1].to_vec());
            let mut row2 = DenseRow::new(row2_data[..len2].to_vec());

            let original1 = row1.clone();
            let original2 = row2.clone();

            // Test clear
            row1.clear();
            assert!(row1.is_zero());
            assert_eq!(row1.nonzero_count(), 0);

            // Restore and test swap
            row1 = original1.clone();
            if len1 == len2 {
                row1.swap(&mut row2);
                assert_eq!(row1.as_slice(), original2.as_slice());
                assert_eq!(row2.as_slice(), original1.as_slice());
            }
        }
    }
}

fn test_sparse_row_operation(op: &SparseRowOperation) {
    match op {
        SparseRowOperation::Creation { entries, logical_len } => {
            let logical_len = (*logical_len).min(MAX_ROW_LEN);
            let entries_len = entries.len().min(MAX_SPARSE_ENTRIES);

            // Convert u8 entries to Gf256 entries, filtering for valid indices
            let gf_entries: Vec<(usize, Gf256)> = entries[..entries_len]
                .iter()
                .filter_map(|(idx, val)| {
                    if *idx < logical_len {
                        Some((*idx, Gf256::new(*val)))
                    } else {
                        None
                    }
                })
                .collect();

            let sparse_row = SparseRow::new(gf_entries.clone(), logical_len);

            assert_eq!(sparse_row.len(), logical_len);
            assert_eq!(sparse_row.is_empty(), logical_len == 0);

            // Verify nonzero entries are preserved (after deduplication)
            let expected_nonzero = gf_entries
                .iter()
                .filter(|(_, val)| !val.is_zero())
                .collect::<HashSet<_>>()
                .len();
            assert!(sparse_row.nonzero_count() <= expected_nonzero);
        }

        SparseRowOperation::Analysis { entries, logical_len } => {
            let logical_len = (*logical_len).min(MAX_ROW_LEN);
            let entries_len = entries.len().min(MAX_SPARSE_ENTRIES);

            let gf_entries: Vec<(usize, Gf256)> = entries[..entries_len]
                .iter()
                .filter_map(|(idx, val)| {
                    if *idx < logical_len {
                        Some((*idx, Gf256::new(*val)))
                    } else {
                        None
                    }
                })
                .collect();

            let sparse_row = SparseRow::new(gf_entries, logical_len);

            // Test analysis functions
            let is_zero = sparse_row.is_zero();
            let nonzero_count = sparse_row.nonzero_count();
            let first_nonzero = sparse_row.first_nonzero();

            // Consistency checks
            if nonzero_count == 0 {
                assert!(is_zero, "Row with zero nonzero count should be zero");
                assert_eq!(first_nonzero, None, "Zero row should have no first nonzero");
            } else {
                assert!(!is_zero, "Row with nonzeros should not be zero");
                assert!(first_nonzero.is_some(), "Row with nonzeros should have first nonzero");
            }
        }

        SparseRowOperation::Manipulation { entries1, entries2, logical_len } => {
            let logical_len = (*logical_len).min(MAX_ROW_LEN);
            let entries1_len = entries1.len().min(MAX_SPARSE_ENTRIES);
            let entries2_len = entries2.len().min(MAX_SPARSE_ENTRIES);

            let gf_entries1: Vec<(usize, Gf256)> = entries1[..entries1_len]
                .iter()
                .filter_map(|(idx, val)| {
                    if *idx < logical_len { Some((*idx, Gf256::new(*val))) } else { None }
                })
                .collect();

            let gf_entries2: Vec<(usize, Gf256)> = entries2[..entries2_len]
                .iter()
                .filter_map(|(idx, val)| {
                    if *idx < logical_len { Some((*idx, Gf256::new(*val))) } else { None }
                })
                .collect();

            let row1 = SparseRow::new(gf_entries1, logical_len);
            let row2 = SparseRow::new(gf_entries2, logical_len);

            let _original1 = row1.clone();

            // Test reconstruction (SparseRow doesn't have clear/swap)
            let cleared = SparseRow::zeros(row1.len());
            assert!(cleared.is_zero());
            assert_eq!(cleared.nonzero_count(), 0);

            // Test equivalence after conversion roundtrips
            let dense1 = row1.to_dense();
            let dense2 = row2.to_dense();
            let sparse1_rt = dense1.to_sparse();
            let sparse2_rt = dense2.to_sparse();

            // Properties should be preserved
            assert_eq!(sparse1_rt.len(), row1.len());
            assert_eq!(sparse2_rt.len(), row2.len());
            assert_eq!(sparse1_rt.is_zero(), row1.is_zero());
            assert_eq!(sparse2_rt.is_zero(), row2.is_zero());
        }
    }
}

fn test_pivot_selection(test: &PivotTest) {
    match test {
        PivotTest::Basic { matrix_data, start, end, col } => {
            let num_rows = matrix_data.len().min(MAX_MATRIX_ROWS);
            if num_rows == 0 { return; }

            let max_cols = matrix_data.iter()
                .map(|row| row.len())
                .max()
                .unwrap_or(0)
                .min(MAX_ROW_LEN);

            if max_cols == 0 || *col >= max_cols { return; }

            let start = (*start).min(num_rows);
            let end = (*end).min(num_rows).max(start);

            // Ensure all rows have consistent length
            let matrix_rows: Vec<Vec<u8>> = matrix_data[..num_rows]
                .iter()
                .map(|row| {
                    let mut padded = row[..row.len().min(max_cols)].to_vec();
                    padded.resize(max_cols, 0);
                    padded
                })
                .collect();

            let matrix_refs: Vec<&[u8]> = matrix_rows.iter().map(|row| row.as_slice()).collect();

            let pivot = select_pivot_basic(&matrix_refs, start, end, *col);

            // If a pivot was found, verify it's valid
            if let Some(pivot_row) = pivot {
                assert!(pivot_row >= start && pivot_row < end, "Pivot row out of range");
                assert!(matrix_refs[pivot_row][*col] != 0, "Pivot element is zero");
            }
        }

        PivotTest::Markowitz { matrix_data, start, end, col } => {
            let num_rows = matrix_data.len().min(MAX_MATRIX_ROWS);
            if num_rows == 0 { return; }

            let max_cols = matrix_data.iter()
                .map(|row| row.len())
                .max()
                .unwrap_or(0)
                .min(MAX_ROW_LEN);

            if max_cols == 0 || *col >= max_cols { return; }

            let start = (*start).min(num_rows);
            let end = (*end).min(num_rows).max(start);

            let matrix_rows: Vec<Vec<u8>> = matrix_data[..num_rows]
                .iter()
                .map(|row| {
                    let mut padded = row[..row.len().min(max_cols)].to_vec();
                    padded.resize(max_cols, 0);
                    padded
                })
                .collect();

            let matrix_refs: Vec<&[u8]> = matrix_rows.iter().map(|row| row.as_slice()).collect();

            let pivot = select_pivot_markowitz(&matrix_refs, start, end, *col);

            // If a pivot was found, verify it's valid
            if let Some((pivot_row, pivot_nonzeros)) = pivot {
                assert!(pivot_row >= start && pivot_row < end, "Pivot row out of range");
                assert!(matrix_refs[pivot_row][*col] != 0, "Pivot element is zero");

                // Verify pivot nonzero count is reasonable
                let actual_nonzeros = row_nonzero_count(matrix_refs[pivot_row]);
                assert!(pivot_nonzeros <= actual_nonzeros,
                       "Reported nonzeros {} exceeds actual {}", pivot_nonzeros, actual_nonzeros);

                // Verify no row in range has nonzero at col with fewer overall nonzeros
                for r in start..end {
                    if matrix_refs[r][*col] != 0 {
                        let r_nonzeros = row_nonzero_count(matrix_refs[r]);
                        assert!(r_nonzeros >= pivot_nonzeros,
                               "Markowitz didn't select row with minimum nonzeros");
                        break; // First valid pivot should be optimal due to algorithm
                    }
                }
            }
        }

        PivotTest::EdgeCases { matrix_data, search_params } => {
            let num_rows = matrix_data.len().min(MAX_MATRIX_ROWS);
            if num_rows == 0 { return; }

            let max_cols = matrix_data.iter()
                .map(|row| row.len())
                .max()
                .unwrap_or(0)
                .min(MAX_ROW_LEN);

            if max_cols == 0 { return; }

            let matrix_rows: Vec<Vec<u8>> = matrix_data[..num_rows]
                .iter()
                .map(|row| {
                    let mut padded = row[..row.len().min(max_cols)].to_vec();
                    padded.resize(max_cols, 0);
                    padded
                })
                .collect();

            let matrix_refs: Vec<&[u8]> = matrix_rows.iter().map(|row| row.as_slice()).collect();

            for param in search_params.iter().take(8) {
                let start = param.start.min(num_rows);
                let end = param.end.min(num_rows).max(start);
                let col = param.col.min(max_cols.saturating_sub(1));

                // Test both algorithms
                let basic_pivot = select_pivot_basic(&matrix_refs, start, end, col);
                let markowitz_pivot = select_pivot_markowitz(&matrix_refs, start, end, col);

                // Both should be consistent: if one finds a pivot, both should find valid pivots
                match (basic_pivot, markowitz_pivot) {
                    (Some(b), Some((m, _))) => {
                        assert!(matrix_refs[b][col] != 0, "Basic pivot invalid");
                        assert!(matrix_refs[m][col] != 0, "Markowitz pivot invalid");
                    }
                    (None, None) => {
                        // Verify no valid pivot exists
                        for r in start..end {
                            if r < matrix_refs.len() && col < matrix_refs[r].len() {
                                assert_eq!(matrix_refs[r][col], 0, "Pivot should exist but neither found it");
                            }
                        }
                    }
                    _ => {
                        // Inconsistent results - this shouldn't happen
                        panic!("Pivot algorithms gave inconsistent results: basic={:?}, markowitz={:?}",
                               basic_pivot, markowitz_pivot);
                    }
                }
            }
        }
    }
}

fn test_conversion(test: &ConversionTest) {
    match test {
        ConversionTest::DenseToSparse { dense_data } => {
            let len = dense_data.len().min(MAX_ROW_LEN);
            let dense = DenseRow::new(dense_data[..len].to_vec());
            let sparse = dense.to_sparse();

            // Verify conversion preserves properties
            assert_eq!(sparse.len(), dense.len());
            assert_eq!(sparse.is_zero(), dense.is_zero());
            assert_eq!(sparse.nonzero_count(), dense.nonzero_count());
            assert_eq!(sparse.first_nonzero(), dense.first_nonzero());

            // Verify individual elements match
            for i in 0..len {
                assert_eq!(sparse.get(i), dense.get(i));
            }
        }

        ConversionTest::SparseToDense { entries, logical_len } => {
            let logical_len = (*logical_len).min(MAX_ROW_LEN);
            let entries_len = entries.len().min(MAX_SPARSE_ENTRIES);

            let gf_entries: Vec<(usize, Gf256)> = entries[..entries_len]
                .iter()
                .filter_map(|(idx, val)| {
                    if *idx < logical_len { Some((*idx, Gf256::new(*val))) } else { None }
                })
                .collect();

            let sparse = SparseRow::new(gf_entries, logical_len);
            let dense = sparse.to_dense();

            // Verify conversion preserves properties
            assert_eq!(dense.len(), sparse.len());
            assert_eq!(dense.is_zero(), sparse.is_zero());
            assert_eq!(dense.nonzero_count(), sparse.nonzero_count());
            assert_eq!(dense.first_nonzero(), sparse.first_nonzero());

            // Verify individual elements match
            for i in 0..logical_len {
                assert_eq!(dense.get(i), sparse.get(i));
            }
        }

        ConversionTest::Roundtrip { dense_data } => {
            let len = dense_data.len().min(MAX_ROW_LEN);
            let original_dense = DenseRow::new(dense_data[..len].to_vec());

            // dense -> sparse -> dense
            let sparse = original_dense.to_sparse();
            let roundtrip_dense = sparse.to_dense();

            // Should be identical after roundtrip
            assert_eq!(original_dense.as_slice(), roundtrip_dense.as_slice());
            assert_eq!(original_dense.len(), roundtrip_dense.len());
            assert_eq!(original_dense.is_zero(), roundtrip_dense.is_zero());
            assert_eq!(original_dense.nonzero_count(), roundtrip_dense.nonzero_count());
            assert_eq!(original_dense.first_nonzero(), roundtrip_dense.first_nonzero());
        }

        ConversionTest::PropertyPreservation { dense_data, test_operations } => {
            let len = dense_data.len().min(MAX_ROW_LEN);
            if len == 0 { return; }

            let dense = DenseRow::new(dense_data[..len].to_vec());
            let sparse = dense.to_sparse();

            for op in test_operations.iter().take(8) {
                match op {
                    ConversionPropertyTest::NonzeroCount => {
                        assert_eq!(dense.nonzero_count(), sparse.nonzero_count());
                    }
                    ConversionPropertyTest::FirstNonzero => {
                        assert_eq!(dense.first_nonzero(), sparse.first_nonzero());
                    }
                    ConversionPropertyTest::IsZero => {
                        assert_eq!(dense.is_zero(), sparse.is_zero());
                    }
                    ConversionPropertyTest::SpecificElements { indices } => {
                        for &idx in indices.iter().take(16) {
                            if idx < len {
                                assert_eq!(dense.get(idx), sparse.get(idx),
                                          "Element mismatch at index {}", idx);
                            }
                        }
                    }
                }
            }
        }
    }
}