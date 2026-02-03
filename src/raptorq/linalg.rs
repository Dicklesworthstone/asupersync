//! Linear algebra primitives for RaptorQ encoding/decoding over GF(256).
//!
//! Provides composable operations used by systematic encoding, inactivation
//! decoding, and Gaussian elimination:
//!
//! - Dense row representation (`DenseRow`) for symbol storage
//! - Sparse row representation (`SparseRow`) for efficient matrix operations
//! - Row XOR, scale-add, and swap operations
//! - Deterministic pivot selection helpers
//!
//! # Design Goals
//!
//! - **Zero allocations in inner loops**: All buffer-operating functions take
//!   pre-allocated slices.
//! - **Deterministic**: Same inputs always produce same outputs.
//! - **Composable**: Small primitives combine into encoding/decoding algorithms.
//!
//! # Usage
//!
//! ```
//! use asupersync::raptorq::linalg::{DenseRow, SparseRow, row_xor, row_scale_add};
//! use asupersync::raptorq::gf256::Gf256;
//!
//! // Dense rows for symbol data
//! let mut r1 = DenseRow::new(vec![1, 2, 3, 4]);
//! let r2 = DenseRow::new(vec![5, 6, 7, 8]);
//!
//! // XOR: r1 = r1 + r2 (in GF256, addition is XOR)
//! row_xor(r1.as_mut_slice(), r2.as_slice());
//!
//! // Scale-add: r1 = r1 + c * r2
//! row_scale_add(r1.as_mut_slice(), r2.as_slice(), Gf256::new(7));
//! ```

use super::gf256::{gf256_add_slice, gf256_addmul_slice, Gf256};

// ============================================================================
// Dense Row Representation
// ============================================================================

/// A dense row vector over GF(256).
///
/// Stores all elements contiguously in a `Vec<u8>`. Efficient for operations
/// that touch most elements (symbol-level XOR during decoding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenseRow {
    data: Vec<u8>,
}

impl DenseRow {
    /// Creates a new dense row from the given data.
    #[inline]
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Creates a dense row of zeros with the given length.
    #[inline]
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        Self { data: vec![0; len] }
    }

    /// Returns the length of the row.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the row is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the underlying data slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the underlying data slice.
    #[inline]
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Resizes the row to the given length, filling new entries with `value`.
    #[inline]
    pub fn resize(&mut self, len: usize, value: u8) {
        self.data.resize(len, value);
    }

    /// Returns the element at the given index as a `Gf256`.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Gf256 {
        Gf256::new(self.data[index])
    }

    /// Sets the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    pub fn set(&mut self, index: usize, value: Gf256) {
        self.data[index] = value.raw();
    }

    /// Returns true if the row is all zeros.
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// Finds the index of the first nonzero element, if any.
    #[inline]
    #[must_use]
    pub fn first_nonzero(&self) -> Option<usize> {
        self.data.iter().position(|&b| b != 0)
    }

    /// Finds the index of the first nonzero element starting from `start`.
    #[inline]
    #[must_use]
    pub fn first_nonzero_from(&self, start: usize) -> Option<usize> {
        self.data[start..]
            .iter()
            .position(|&b| b != 0)
            .map(|i| start + i)
    }

    /// Counts the number of nonzero elements.
    #[inline]
    #[must_use]
    pub fn nonzero_count(&self) -> usize {
        self.data.iter().filter(|&&b| b != 0).count()
    }

    /// Clears the row (sets all elements to zero).
    #[inline]
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Swaps the contents of this row with another.
    #[inline]
    pub fn swap(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.data, &mut other.data);
    }

    /// Converts to a sparse representation.
    #[must_use]
    pub fn to_sparse(&self) -> SparseRow {
        let entries: Vec<(usize, Gf256)> = self
            .data
            .iter()
            .enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, &v)| (i, Gf256::new(v)))
            .collect();
        SparseRow::new(entries, self.data.len())
    }
}

impl From<Vec<u8>> for DenseRow {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for DenseRow {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for DenseRow {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ============================================================================
// Sparse Row Representation
// ============================================================================

/// A sparse row vector over GF(256).
///
/// Stores only nonzero entries as (index, value) pairs. Efficient for rows
/// with few nonzeros (LDPC-style matrices, precode constraints).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseRow {
    /// Nonzero entries as (index, value) pairs, sorted by index.
    entries: Vec<(usize, Gf256)>,
    /// Logical length of the row.
    len: usize,
}

impl SparseRow {
    /// Creates a new sparse row from entries.
    ///
    /// Entries should be sorted by index and have unique indices.
    /// Zero-valued entries are filtered out.
    #[must_use]
    pub fn new(entries: Vec<(usize, Gf256)>, len: usize) -> Self {
        // Filter zeros and ensure sorted
        let mut filtered: Vec<_> = entries.into_iter().filter(|(_, v)| !v.is_zero()).collect();
        filtered.sort_by_key(|(i, _)| *i);
        Self {
            entries: filtered,
            len,
        }
    }

    /// Creates an empty sparse row with the given length.
    #[inline]
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        Self {
            entries: Vec::new(),
            len,
        }
    }

    /// Creates a sparse row with a single nonzero entry.
    #[inline]
    #[must_use]
    pub fn singleton(index: usize, value: Gf256, len: usize) -> Self {
        if value.is_zero() {
            Self::zeros(len)
        } else {
            Self {
                entries: vec![(index, value)],
                len,
            }
        }
    }

    /// Returns the logical length of the row.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the row is empty (zero length).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of nonzero entries.
    #[inline]
    #[must_use]
    pub fn nonzero_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the row is all zeros.
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the element at the given index.
    #[must_use]
    pub fn get(&self, index: usize) -> Gf256 {
        self.entries
            .binary_search_by_key(&index, |(i, _)| *i)
            .map(|pos| self.entries[pos].1)
            .unwrap_or(Gf256::ZERO)
    }

    /// Returns an iterator over nonzero entries as (index, value) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, Gf256)> + '_ {
        self.entries.iter().copied()
    }

    /// Returns the index of the first nonzero entry, if any.
    #[inline]
    #[must_use]
    pub fn first_nonzero(&self) -> Option<usize> {
        self.entries.first().map(|(i, _)| *i)
    }

    /// Converts to a dense representation.
    #[must_use]
    pub fn to_dense(&self) -> DenseRow {
        let mut data = vec![0u8; self.len];
        for &(i, v) in &self.entries {
            data[i] = v.raw();
        }
        DenseRow::new(data)
    }

    /// Adds another sparse row to this one (XOR).
    ///
    /// Both rows must have the same length.
    ///
    /// # Panics
    ///
    /// Panics if rows have different lengths.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.len, other.len, "row length mismatch");

        let mut result = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut i = 0;
        let mut j = 0;

        while i < self.entries.len() && j < other.entries.len() {
            let (idx_a, val_a) = self.entries[i];
            let (idx_b, val_b) = other.entries[j];

            match idx_a.cmp(&idx_b) {
                std::cmp::Ordering::Less => {
                    result.push((idx_a, val_a));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    result.push((idx_b, val_b));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let sum = val_a + val_b;
                    if !sum.is_zero() {
                        result.push((idx_a, sum));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        result.extend_from_slice(&self.entries[i..]);
        result.extend_from_slice(&other.entries[j..]);

        Self {
            entries: result,
            len: self.len,
        }
    }

    /// Scales this row by a scalar (multiplication in GF256).
    #[must_use]
    pub fn scale(&self, c: Gf256) -> Self {
        if c.is_zero() {
            return Self::zeros(self.len);
        }
        if c == Gf256::ONE {
            return self.clone();
        }
        let scaled: Vec<_> = self
            .entries
            .iter()
            .map(|&(i, v)| (i, v * c))
            .filter(|(_, v)| !v.is_zero())
            .collect();
        Self {
            entries: scaled,
            len: self.len,
        }
    }

    /// Computes `self + c * other` (scale-add).
    #[must_use]
    pub fn scale_add(&self, other: &Self, c: Gf256) -> Self {
        if c.is_zero() {
            return self.clone();
        }
        self.add(&other.scale(c))
    }
}

// ============================================================================
// Row Operations (on slices, zero-allocation)
// ============================================================================

/// XOR `src` into `dst`: `dst[i] ^= src[i]`.
///
/// This is addition in GF(256).
///
/// # Panics
///
/// Panics if slices have different lengths.
#[inline]
pub fn row_xor(dst: &mut [u8], src: &[u8]) {
    gf256_add_slice(dst, src);
}

/// Scale-add: `dst[i] += c * src[i]` in GF(256).
///
/// This is the fundamental row operation for Gaussian elimination.
///
/// # Panics
///
/// Panics if slices have different lengths.
#[inline]
pub fn row_scale_add(dst: &mut [u8], src: &[u8], c: Gf256) {
    gf256_addmul_slice(dst, src, c);
}

/// Swaps two rows (in-place, no allocation).
#[inline]
pub fn row_swap(a: &mut [u8], b: &mut [u8]) {
    assert_eq!(a.len(), b.len(), "row length mismatch");
    a.swap_with_slice(b);
}

/// Scales a row in-place: `row[i] *= c`.
#[inline]
pub fn row_scale(row: &mut [u8], c: Gf256) {
    super::gf256::gf256_mul_slice(row, c);
}

// ============================================================================
// Pivot Selection Helpers
// ============================================================================

/// Selects a pivot row for Gaussian elimination.
///
/// Searches rows `start..end` in `matrix` for a row with a nonzero entry
/// at column `col`. Returns the index of the first such row, if any.
///
/// For determinism, always returns the smallest index among candidates.
///
/// # Arguments
///
/// * `matrix` - Slice of row slices (each row is a `&[u8]`)
/// * `start` - First row to consider
/// * `end` - One past the last row to consider
/// * `col` - Column index to check for nonzero pivot
#[must_use]
pub fn select_pivot_basic(matrix: &[&[u8]], start: usize, end: usize, col: usize) -> Option<usize> {
    matrix
        .iter()
        .enumerate()
        .take(end)
        .skip(start)
        .find(|(_, row_data)| row_data[col] != 0)
        .map(|(row, _)| row)
}

/// Selects a pivot row preferring rows with fewer nonzeros (Markowitz).
///
/// This heuristic reduces fill-in during Gaussian elimination, improving
/// performance for sparse matrices like LDPC/HDPC precodes.
///
/// Returns `(row_index, nonzero_count)` of the best pivot, if any.
///
/// # Arguments
///
/// * `matrix` - Slice of row slices
/// * `start` - First row to consider
/// * `end` - One past the last row to consider
/// * `col` - Column index to check for nonzero pivot
#[must_use]
pub fn select_pivot_markowitz(
    matrix: &[&[u8]],
    start: usize,
    end: usize,
    col: usize,
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;

    for (row, row_data) in matrix.iter().enumerate().take(end).skip(start) {
        if row_data[col] == 0 {
            continue;
        }
        let nnz = row_data.iter().filter(|&&b| b != 0).count();
        match &best {
            None => best = Some((row, nnz)),
            Some((_, best_nnz)) if nnz < *best_nnz => best = Some((row, nnz)),
            Some((best_row, best_nnz)) if nnz == *best_nnz && row < *best_row => {
                best = Some((row, nnz));
            }
            _ => {}
        }
    }

    best
}

/// Counts nonzeros in a row (useful for Markowitz pivot selection).
#[inline]
#[must_use]
pub fn row_nonzero_count(row: &[u8]) -> usize {
    row.iter().filter(|&&b| b != 0).count()
}

/// Finds the first nonzero column in a row, starting from `start_col`.
#[inline]
#[must_use]
pub fn row_first_nonzero_from(row: &[u8], start_col: usize) -> Option<usize> {
    row[start_col..]
        .iter()
        .position(|&b| b != 0)
        .map(|i| start_col + i)
}

// ============================================================================
// Gaussian Elimination Engine
// ============================================================================

/// Result of Gaussian elimination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GaussianResult {
    /// System solved successfully. Contains solution vector.
    Solved(Vec<DenseRow>),
    /// Matrix is singular at the given row (no valid pivot found).
    Singular {
        /// The row index where elimination failed to find a pivot.
        row: usize,
    },
}

/// Statistics from Gaussian elimination.
#[derive(Debug, Clone, Default)]
pub struct GaussianStats {
    /// Number of row swaps performed.
    pub swaps: usize,
    /// Number of row scale-add operations.
    pub scale_adds: usize,
    /// Number of pivot selections.
    pub pivot_selections: usize,
}

/// Gaussian elimination solver over GF(256).
///
/// Solves the linear system `A * x = b` where `A` is an m x n matrix
/// and `b` is the right-hand side (represented as row data).
///
/// # Features
///
/// - **Deterministic**: Same input always produces same output
/// - **Buffer-reusing**: Modifies matrix in-place, avoids allocations in inner loops
/// - **Pivoting**: Uses Markowitz heuristic for sparse matrices
pub struct GaussianSolver {
    /// Number of rows.
    rows: usize,
    /// Number of columns in coefficient matrix.
    cols: usize,
    /// Coefficient matrix (row-major, rows x cols).
    matrix: Vec<Vec<u8>>,
    /// Right-hand side data for each row.
    rhs: Vec<DenseRow>,
    /// Statistics.
    stats: GaussianStats,
}

impl GaussianSolver {
    /// Create a new solver for an m x n system.
    #[must_use]
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            matrix: vec![vec![0; cols]; rows],
            rhs: (0..rows).map(|_| DenseRow::zeros(0)).collect(),
            stats: GaussianStats::default(),
        }
    }

    /// Set a row's coefficients and RHS data.
    ///
    /// `coefficients` should have length `cols`.
    pub fn set_row(&mut self, row: usize, coefficients: &[u8], rhs: DenseRow) {
        assert!(row < self.rows, "row out of bounds");
        assert_eq!(coefficients.len(), self.cols, "coefficient length mismatch");
        self.matrix[row].copy_from_slice(coefficients);
        self.rhs[row] = rhs;
    }

    /// Set a single coefficient.
    pub fn set_coefficient(&mut self, row: usize, col: usize, value: Gf256) {
        self.matrix[row][col] = value.raw();
    }

    /// Set RHS for a row.
    pub fn set_rhs(&mut self, row: usize, rhs: DenseRow) {
        self.rhs[row] = rhs;
    }

    /// Returns the current statistics.
    #[must_use]
    pub fn stats(&self) -> &GaussianStats {
        &self.stats
    }

    /// Solve the system using Gaussian elimination with partial pivoting.
    ///
    /// Returns `GaussianResult::Solved` with the solution if successful,
    /// or `GaussianResult::Singular` if the matrix is singular.
    pub fn solve(&mut self) -> GaussianResult {
        let n = self.rows.min(self.cols);

        // Forward elimination
        for pivot_col in 0..n {
            self.stats.pivot_selections += 1;

            // Find pivot row (first nonzero in column, starting from pivot_col)
            let Some(pivot_row) = self.find_pivot(pivot_col, pivot_col) else {
                return GaussianResult::Singular { row: pivot_col };
            };

            // Swap if needed
            if pivot_row != pivot_col {
                self.swap_rows(pivot_col, pivot_row);
            }

            // Eliminate below
            let pivot_val = Gf256::new(self.matrix[pivot_col][pivot_col]);
            let pivot_inv = pivot_val.inv();

            // Scale pivot row so pivot element becomes 1
            row_scale(&mut self.matrix[pivot_col], pivot_inv);
            row_scale(self.rhs[pivot_col].as_mut_slice(), pivot_inv);

            // Eliminate in rows below pivot
            for row in (pivot_col + 1)..self.rows {
                let factor = Gf256::new(self.matrix[row][pivot_col]);
                if !factor.is_zero() {
                    self.eliminate_row(row, pivot_col, factor);
                }
            }
        }

        // Back substitution
        for pivot_col in (0..n).rev() {
            for row in 0..pivot_col {
                let factor = Gf256::new(self.matrix[row][pivot_col]);
                if !factor.is_zero() {
                    self.eliminate_row(row, pivot_col, factor);
                }
            }
        }

        // Extract solution (RHS values after elimination)
        GaussianResult::Solved(self.rhs.clone())
    }

    /// Solve with Markowitz pivot selection (better for sparse matrices).
    pub fn solve_markowitz(&mut self) -> GaussianResult {
        let n = self.rows.min(self.cols);

        // Forward elimination with Markowitz pivoting
        for pivot_col in 0..n {
            self.stats.pivot_selections += 1;

            // Find best pivot (sparsest row with nonzero in column)
            let Some((pivot_row, _nnz)) = self.find_pivot_markowitz(pivot_col, pivot_col) else {
                return GaussianResult::Singular { row: pivot_col };
            };

            // Swap if needed
            if pivot_row != pivot_col {
                self.swap_rows(pivot_col, pivot_row);
            }

            // Scale and eliminate
            let pivot_val = Gf256::new(self.matrix[pivot_col][pivot_col]);
            let pivot_inv = pivot_val.inv();

            row_scale(&mut self.matrix[pivot_col], pivot_inv);
            row_scale(self.rhs[pivot_col].as_mut_slice(), pivot_inv);

            for row in (pivot_col + 1)..self.rows {
                let factor = Gf256::new(self.matrix[row][pivot_col]);
                if !factor.is_zero() {
                    self.eliminate_row(row, pivot_col, factor);
                }
            }
        }

        // Back substitution
        for pivot_col in (0..n).rev() {
            for row in 0..pivot_col {
                let factor = Gf256::new(self.matrix[row][pivot_col]);
                if !factor.is_zero() {
                    self.eliminate_row(row, pivot_col, factor);
                }
            }
        }

        GaussianResult::Solved(self.rhs.clone())
    }

    /// Find first nonzero pivot in column starting from given row.
    fn find_pivot(&self, col: usize, start_row: usize) -> Option<usize> {
        (start_row..self.rows).find(|&row| self.matrix[row][col] != 0)
    }

    /// Find best pivot using Markowitz heuristic.
    fn find_pivot_markowitz(&self, col: usize, start_row: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;

        for row in start_row..self.rows {
            if self.matrix[row][col] == 0 {
                continue;
            }
            let nnz = self.matrix[row].iter().filter(|&&b| b != 0).count();
            match &best {
                None => best = Some((row, nnz)),
                Some((_, best_nnz)) if nnz < *best_nnz => best = Some((row, nnz)),
                Some((best_row, best_nnz)) if nnz == *best_nnz && row < *best_row => {
                    best = Some((row, nnz));
                }
                _ => {}
            }
        }

        best
    }

    /// Swap two rows.
    fn swap_rows(&mut self, a: usize, b: usize) {
        self.stats.swaps += 1;
        self.matrix.swap(a, b);
        self.rhs.swap(a, b);
    }

    /// Eliminate: row[target] -= factor * row[pivot].
    fn eliminate_row(&mut self, target: usize, pivot: usize, factor: Gf256) {
        self.stats.scale_adds += 1;
        if target == pivot {
            return;
        }

        // Eliminate in coefficient matrix
        for col in 0..self.cols {
            let pivot_val = self.matrix[pivot][col];
            if pivot_val != 0 {
                self.matrix[target][col] ^= (Gf256::new(pivot_val) * factor).raw();
            }
        }

        // Eliminate in RHS - use split_at_mut to satisfy borrow checker
        let rhs_len = self.rhs[pivot].len();
        if rhs_len > 0 {
            if self.rhs[target].len() < rhs_len {
                self.rhs[target].data.resize(rhs_len, 0);
            }

            // Split to get separate mutable references
            let (lower, upper) = if target < pivot {
                let (lo, hi) = self.rhs.split_at_mut(pivot);
                (&mut lo[target], &hi[0])
            } else {
                let (lo, hi) = self.rhs.split_at_mut(target);
                (&mut hi[0], &lo[pivot])
            };

            row_scale_add(
                &mut lower.as_mut_slice()[..rhs_len],
                &upper.as_slice()[..rhs_len],
                factor,
            );
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        let matrix: Vec<&[u8]> = rows.iter().map(|r| r.as_slice()).collect();

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
        let matrix: Vec<&[u8]> = rows.iter().map(|r| r.as_slice()).collect();

        // Column 0: rows 0, 2, 3 have nonzero. Row 2 is sparsest.
        let result = select_pivot_markowitz(&matrix, 0, 4, 0);
        assert_eq!(result, Some((2, 1)));
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
            _ => panic!("different result types"),
        }
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
        }
    }
}
