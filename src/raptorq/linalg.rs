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

use super::gf256::{
    Gf256, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice, gf256_addmul_slices2,
    gf256_mul_slice, gf256_mul_slices2,
};

// ============================================================================
// Dense Row Representation
// ============================================================================

/// Index outside the bounds of a dense GF(256) row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenseRowIndexError {
    /// Requested element index.
    pub index: usize,
    /// Current row length.
    pub len: usize,
}

/// Index outside the bounds of a sparse GF(256) row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseRowIndexError {
    /// Requested element index.
    pub index: usize,
    /// Current row length.
    pub len: usize,
}

impl core::fmt::Display for SparseRowIndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "sparse row index out of range: {} >= {}",
            self.index, self.len
        )
    }
}

impl std::error::Error for SparseRowIndexError {}

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
        assert!(
            index < self.data.len(),
            "dense row index out of range: {index} >= {}",
            self.data.len()
        );
        Gf256::new(self.data[index])
    }

    /// br-asupersync-tda3x0 — Fallible variant of [`Self::get`] that
    /// returns `None` on out-of-range index instead of panicking.
    /// Production code paths driven by network-supplied schedules
    /// (where a malformed FEC-OTI could route an out-of-range
    /// column index here) MUST use this variant and surface the
    /// rejection as a decoder-level error, instead of letting the
    /// process panic on adversarial input. The infallible
    /// [`Self::get`] is retained for code paths whose bounds are
    /// statically guaranteed (test code, internal arithmetic that
    /// has already validated the index).
    #[inline]
    #[must_use]
    pub fn try_get(&self, index: usize) -> Option<Gf256> {
        self.data.get(index).copied().map(Gf256::new)
    }

    /// Sets the element at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[inline]
    pub fn set(&mut self, index: usize, value: Gf256) {
        assert!(
            index < self.data.len(),
            "dense row index out of range: {index} >= {}",
            self.data.len()
        );
        self.data[index] = value.raw();
    }

    /// br-asupersync-tda3x0 — Fallible variant of [`Self::set`].
    /// Returns [`DenseRowIndexError`] on out-of-range index. Same rationale as
    /// [`Self::try_get`].
    #[inline]
    pub fn try_set(&mut self, index: usize, value: Gf256) -> Result<(), DenseRowIndexError> {
        let len = self.data.len();
        match self.data.get_mut(index) {
            Some(slot) => {
                *slot = value.raw();
                Ok(())
            }
            None => Err(DenseRowIndexError { index, len }),
        }
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
        if start >= self.data.len() {
            return None;
        }
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
            .filter(|(_, v)| **v != 0)
            .map(|(i, v)| (i, Gf256::new(*v)))
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
    /// Entries may be unsorted and may contain duplicates; duplicate indices
    /// are canonicalized by GF(256) addition and zero-valued results are
    /// removed.
    ///
    /// # Panics
    ///
    /// Panics if any entry index is out of bounds for `len`.
    #[must_use]
    pub fn new(entries: Vec<(usize, Gf256)>, len: usize) -> Self {
        Self::try_new(entries, len).unwrap_or_else(|err| panic!("{err}"))
    }

    /// Fallible constructor for sparse rows built from untrusted schedules.
    ///
    /// Duplicate indices are canonicalized exactly like [`Self::new`], but
    /// out-of-range indices return a deterministic error instead of panicking.
    pub fn try_new(entries: Vec<(usize, Gf256)>, len: usize) -> Result<Self, SparseRowIndexError> {
        let mut filtered = Vec::with_capacity(entries.len());
        for (index, value) in entries {
            if index >= len {
                return Err(SparseRowIndexError { index, len });
            }
            if !value.is_zero() {
                filtered.push((index, value));
            }
        }

        Ok(Self::from_valid_entries(filtered, len))
    }

    fn from_valid_entries(mut filtered: Vec<(usize, Gf256)>, len: usize) -> Self {
        filtered.sort_by_key(|(i, _)| *i);

        let mut canonical: Vec<(usize, Gf256)> = Vec::with_capacity(filtered.len());
        for (index, value) in filtered {
            match canonical.last_mut() {
                Some((last_index, last_value)) if *last_index == index => {
                    *last_value += value;
                    if last_value.is_zero() {
                        canonical.pop();
                    }
                }
                _ => canonical.push((index, value)),
            }
        }
        Self {
            entries: canonical,
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
        Self::try_singleton(index, value, len).unwrap_or_else(|err| panic!("{err}"))
    }

    /// Fallible single-entry sparse-row constructor.
    ///
    /// Rejects out-of-range indices even when `value` is zero, matching
    /// [`Self::singleton`] without panicking.
    #[inline]
    pub fn try_singleton(
        index: usize,
        value: Gf256,
        len: usize,
    ) -> Result<Self, SparseRowIndexError> {
        if index >= len {
            return Err(SparseRowIndexError { index, len });
        }
        if value.is_zero() {
            Ok(Self::zeros(len))
        } else {
            Ok(Self {
                entries: vec![(index, value)],
                len,
            })
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
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.len()`.
    #[must_use]
    pub fn get(&self, index: usize) -> Gf256 {
        assert!(
            index < self.len,
            "sparse row index out of range: {index} >= {}",
            self.len
        );
        self.entries
            .binary_search_by_key(&index, |(i, _)| *i)
            .map_or(Gf256::ZERO, |pos| self.entries[pos].1)
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

    /// In-place scale-add: `self += c * other`.
    ///
    /// Merges `other` (scaled by `c`) into `self` without allocating an
    /// intermediate scaled copy. The resulting entries are kept sorted by
    /// index with zero entries removed.
    pub fn scale_add_assign(&mut self, other: &Self, c: Gf256) {
        assert_eq!(self.len, other.len, "row length mismatch");
        if c.is_zero() {
            return;
        }

        // Merge self.entries and scaled other.entries in-place.
        // We build the result in a temporary vec to avoid index invalidation,
        // then swap it in.
        let mut merged = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut i = 0;
        let mut j = 0;

        while i < self.entries.len() && j < other.entries.len() {
            let (idx_a, val_a) = self.entries[i];
            let (idx_b, val_b) = other.entries[j];

            match idx_a.cmp(&idx_b) {
                std::cmp::Ordering::Less => {
                    merged.push((idx_a, val_a));
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    let scaled = val_b * c;
                    if !scaled.is_zero() {
                        merged.push((idx_b, scaled));
                    }
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let sum = val_a + val_b * c;
                    if !sum.is_zero() {
                        merged.push((idx_a, sum));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        merged.extend_from_slice(&self.entries[i..]);
        for &(idx, val) in &other.entries[j..] {
            let scaled = val * c;
            if !scaled.is_zero() {
                merged.push((idx, scaled));
            }
        }

        self.entries = merged;
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

/// Batched scale-add: processes pairs of row operations with the same scalar.
///
/// Applies `dst_a[i] += c * src_a[i]` and `dst_b[i] += c * src_b[i]` using
/// fused SIMD dispatch to amortize kernel setup costs.
///
/// This is the key optimization for Gaussian elimination where multiple row
/// operations use the same scalar coefficient. The dual-kernel path can
/// achieve 30-50% speedup for K=1024+ workloads by reducing dispatch overhead
/// and improving cache locality.
///
/// # Performance
///
/// - Sequential fallback: processes operations individually via `row_scale_add`
/// - Fused SIMD: uses `gf256_addmul_slices2` dual-kernel infrastructure
/// - Threshold-based: automatically selects optimal path based on slice sizes
///
/// # Panics
///
/// Panics if any dst/src slice length mismatch.
#[inline]
pub fn row_scale_add_batch2(
    dst_a: &mut [u8],
    src_a: &[u8],
    dst_b: &mut [u8],
    src_b: &[u8],
    c: Gf256,
) {
    gf256_addmul_slices2(dst_a, src_a, dst_b, src_b, c);
}

/// Batched scale-add for multiple row pairs sharing the same scalar coefficient.
///
/// Optimized for Gaussian elimination where many row operations use the same
/// pivot element coefficient. Takes separate slices for destinations and sources
/// and processes them in batches using dual-kernel SIMD fusion.
///
/// # Performance Impact
///
/// For K=1024+ RaptorQ decoding:
/// - Reduces gf256_addmul_slice dispatch overhead by batching operations
/// - Improves cache locality through paired memory access patterns
/// - Projected 30-50% speedup in matrix elimination phase
///
/// # Implementation
///
/// Uses safe indexing to avoid borrowing conflicts. Processes pairs via
/// `row_scale_add_batch2` (dual SIMD kernel) with sequential fallback
/// for odd row counts.
///
/// # Panics
///
/// Panics if destinations and sources slices have different lengths or
/// if any destination/source slice length mismatch.
pub fn row_scale_add_batch_multi(destinations: &mut [&mut [u8]], sources: &[&[u8]], c: Gf256) {
    assert_eq!(
        destinations.len(),
        sources.len(),
        "destinations and sources length mismatch"
    );

    if c.is_zero() {
        return;
    }

    // Process pairs using dual-kernel SIMD batching
    let mut i = 0;
    while i + 1 < destinations.len() {
        // We need to split_at_mut to get non-overlapping mutable references
        let (left, right) = destinations.split_at_mut(i + 1);
        let dst_a = &mut left[i];
        let dst_b = &mut right[0]; // This is index i+1 in the original array

        let src_a = sources[i];
        let src_b = sources[i + 1];

        row_scale_add_batch2(dst_a, src_a, dst_b, src_b, c);

        i += 2;
    }

    // Handle remaining odd row with sequential operation
    if i < destinations.len() {
        row_scale_add(destinations[i], sources[i], c);
    }
}

/// Helper for matrix elimination batching: collects row operation candidates.
///
/// Scans matrix rows below a pivot and identifies operations that can be
/// batched together (same coefficient). Returns operation descriptors that
/// can be processed via `row_scale_add_batch_multi`.
///
/// # Usage in Gaussian Elimination
///
/// ```rust
/// use asupersync::raptorq::linalg::collect_batch_candidates;
///
/// let matrix = vec![
///     vec![1, 0, 0],
///     vec![1, 2, 3],
///     vec![0, 4, 5],
///     vec![1, 6, 7],
/// ];
/// let candidates = collect_batch_candidates(&matrix, 0, 0);
///
/// assert_eq!(candidates.len(), 2);
/// assert_eq!(candidates[0], (vec![1, 0, 0], vec![1, 2, 3]));
/// assert_eq!(candidates[1], (vec![1, 0, 0], vec![1, 6, 7]));
/// ```
pub fn collect_batch_candidates(
    matrix: &[Vec<u8>],
    pivot_row: usize,
    pivot_col: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut candidates = Vec::new();

    // Validate input parameters
    if pivot_row >= matrix.len() || matrix.is_empty() {
        return candidates;
    }

    let pivot_element = matrix
        .get(pivot_row)
        .and_then(|row| row.get(pivot_col))
        .copied()
        .unwrap_or(0);

    // Skip if pivot is zero (no elimination possible)
    if pivot_element == 0 {
        return candidates;
    }

    // Collect rows that have the same non-zero coefficient in the pivot column
    // These can be batch-eliminated together for efficiency
    for (row_idx, row) in matrix.iter().enumerate() {
        if row_idx == pivot_row || pivot_col >= row.len() {
            continue;
        }

        let element = row[pivot_col];
        if element != 0 && element == pivot_element {
            // Found a candidate: both pivot row and current row have same coefficient
            // Return as (pivot_row_copy, candidate_row_copy) for batch processing
            candidates.push((matrix[pivot_row].clone(), row.clone()));
        }
    }

    candidates
}

/// Tiny slices are faster with a direct XOR loop than dispatching kernels.
const XOR_TINY_FAST_PATH_MAX_BYTES: usize = 32;

#[inline]
fn row_xor_tiny(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len(), "row length mismatch");
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
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
        .find(|(_, row_data)| row_data.get(col).copied().unwrap_or(0) != 0)
        .map(|(row, _)| row)
}

/// Selects a pivot row preferring rows with fewer nonzeros (Markowitz).
///
/// This heuristic reduces fill-in during Gaussian elimination, improving
/// performance for sparse matrices like LDPC/HDPC precodes.
/// Nonzero counts are computed in the active submatrix (`col..`), which
/// matches elimination semantics after prior pivot columns are cleared.
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
        if row_data.get(col).copied().unwrap_or(0) == 0 {
            continue;
        }
        let nnz = match best {
            None => count_nonzero_capped_from(row_data, col, usize::MAX),
            Some((_, best_nnz)) => {
                // We only need to know whether this row can beat the incumbent.
                // Cap at `best_nnz - 1` to short-circuit tie/worse candidates.
                count_nonzero_capped_from(row_data, col, best_nnz.saturating_sub(1))
            }
        };
        match &best {
            None => {
                best = Some((row, nnz));
                if nnz == 1 {
                    break;
                }
            }
            Some((_, best_nnz)) if nnz < *best_nnz => {
                best = Some((row, nnz));
                if nnz == 1 {
                    break;
                }
            }
            Some((best_row, best_nnz)) if nnz == *best_nnz && row < *best_row => {
                best = Some((row, nnz));
            }
            _ => {}
        }
    }

    best
}

/// Deterministic pivot/free-column witness for a dense GF(256) matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaussianRankProfile {
    /// Number of coefficient rows.
    pub rows: usize,
    /// Number of coefficient columns / unknowns.
    pub columns: usize,
    /// GF(256) row rank of the coefficient matrix.
    pub rank: usize,
    /// Number of columns still missing independent support.
    pub deficit: usize,
    /// Sorted coefficient columns selected as pivots by deterministic rank reduction.
    pub pivot_columns: Vec<usize>,
    /// Sorted coefficient columns without independent pivot support.
    pub free_columns: Vec<usize>,
}

/// Computes the deterministic GF(256) rank profile of a dense matrix.
///
/// Rows may be shorter than `columns`; missing entries are treated as zero.
/// The reduction is deterministic: columns are considered left-to-right, and
/// the first row that creates a new basis vector for a pivot column is retained.
/// Unlike the decode solver, rank determination skips free columns and
/// therefore reports the true row rank and pivot/free-column witness of the
/// coefficient matrix even when a unique solution is impossible.
#[must_use]
pub fn coefficient_rank_profile(matrix: &[&[u8]], columns: usize) -> GaussianRankProfile {
    let mut basis = vec![None::<Vec<Gf256>>; columns];

    for row_data in matrix {
        let mut row = vec![Gf256::ZERO; columns];
        for (column, slot) in row.iter_mut().enumerate() {
            *slot = Gf256::new(row_data.get(column).copied().unwrap_or(0));
        }

        for pivot in 0..columns {
            if row[pivot].is_zero() {
                continue;
            }

            if let Some(basis_row) = basis[pivot].as_ref() {
                let factor = row[pivot];
                for (column, value) in row.iter_mut().enumerate().skip(pivot) {
                    *value += basis_row[column] * factor;
                }
            } else {
                let inv = row[pivot].inv();
                for value in row.iter_mut().skip(pivot) {
                    *value *= inv;
                }
                basis[pivot] = Some(row);
                break;
            }
        }
    }

    let mut pivot_columns = Vec::new();
    let mut free_columns = Vec::new();
    for (column, basis_row) in basis.iter().enumerate() {
        if basis_row.is_some() {
            pivot_columns.push(column);
        } else {
            free_columns.push(column);
        }
    }
    let rank = pivot_columns.len();

    GaussianRankProfile {
        rows: matrix.len(),
        columns,
        rank,
        deficit: columns.saturating_sub(rank),
        pivot_columns,
        free_columns,
    }
}

/// Computes the GF(256) coefficient rank of a dense matrix.
///
/// Rows may be shorter than `columns`; missing entries are treated as zero.
/// The reduction is deterministic: columns are considered left-to-right, and
/// the first row that creates a new basis vector for a pivot column is retained.
/// Unlike the decode solver, rank determination skips free columns and
/// therefore reports the true row rank of the coefficient matrix even when a
/// unique solution is impossible.
#[must_use]
pub fn coefficient_rank(matrix: &[&[u8]], columns: usize) -> usize {
    coefficient_rank_profile(matrix, columns).rank
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
    if start_col >= row.len() {
        return None;
    }
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
    /// Matrix coefficients reduced to zero row but RHS remained nonzero.
    ///
    /// This indicates an inconsistent system (`0 = b`, `b != 0`) and must
    /// never be treated as a successful decode.
    Inconsistent {
        /// The transformed row index witnessing inconsistency.
        row: usize,
    },
}

/// Stable classification for a [`GaussianResult`] without inspecting payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaussianOutcomeKind {
    /// Elimination produced a unique solution.
    Solved,
    /// Elimination proved the coefficient matrix is rank deficient.
    Singular,
    /// Elimination proved the coefficient/RHS system is inconsistent.
    Inconsistent,
}

impl GaussianResult {
    /// Return the deterministic outcome class for solver callers and tests.
    #[must_use]
    pub const fn outcome_kind(&self) -> GaussianOutcomeKind {
        match self {
            Self::Solved(_) => GaussianOutcomeKind::Solved,
            Self::Singular { .. } => GaussianOutcomeKind::Singular,
            Self::Inconsistent { .. } => GaussianOutcomeKind::Inconsistent,
        }
    }

    /// True only when elimination produced a solution payload.
    #[must_use]
    pub const fn is_solved(&self) -> bool {
        matches!(self, Self::Solved(_))
    }
}

/// Deterministic rank summary for a [`GaussianSolver`] coefficient matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GaussianRankStatus {
    /// Number of coefficient rows.
    pub rows: usize,
    /// Number of coefficient columns / unknowns.
    pub columns: usize,
    /// GF(256) row rank of the coefficient matrix.
    pub rank: usize,
    /// Number of columns still missing independent support.
    pub deficit: usize,
}

/// Deterministic input-construction error for [`GaussianSolver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaussianInputError {
    /// Requested row is outside the coefficient/RHS row domain.
    RowOutOfBounds {
        /// Requested row.
        row: usize,
        /// Number of rows in the solver.
        rows: usize,
    },
    /// Requested column is outside the coefficient column domain.
    ColumnOutOfBounds {
        /// Requested row.
        row: usize,
        /// Requested column.
        column: usize,
        /// Number of columns in the solver.
        cols: usize,
    },
    /// Coefficient row width does not match the solver column count.
    CoefficientLengthMismatch {
        /// Requested row.
        row: usize,
        /// Expected coefficient count.
        expected: usize,
        /// Actual coefficient count.
        actual: usize,
    },
}

impl core::fmt::Display for GaussianInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RowOutOfBounds { row, rows } => {
                write!(f, "row out of bounds: {row} >= {rows}")
            }
            Self::ColumnOutOfBounds { row, column, cols } => {
                write!(
                    f,
                    "column out of bounds: row {row}, column {column} >= {cols}"
                )
            }
            Self::CoefficientLengthMismatch {
                row,
                expected,
                actual,
            } => write!(
                f,
                "coefficient length mismatch: row {row}, expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for GaussianInputError {}

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
        if let Err(err) = self.try_set_row(row, coefficients, rhs) {
            panic!("{err}");
        }
    }

    /// Fallible row setter for untrusted solver construction paths.
    ///
    /// Returns a deterministic error instead of panicking when the row index or
    /// coefficient width is invalid.
    pub fn try_set_row(
        &mut self,
        row: usize,
        coefficients: &[u8],
        rhs: DenseRow,
    ) -> Result<(), GaussianInputError> {
        if row >= self.rows {
            return Err(GaussianInputError::RowOutOfBounds {
                row,
                rows: self.rows,
            });
        }
        if coefficients.len() != self.cols {
            return Err(GaussianInputError::CoefficientLengthMismatch {
                row,
                expected: self.cols,
                actual: coefficients.len(),
            });
        }
        self.matrix[row].copy_from_slice(coefficients);
        self.rhs[row] = rhs;
        Ok(())
    }

    /// Set a single coefficient.
    pub fn set_coefficient(&mut self, row: usize, col: usize, value: Gf256) {
        if let Err(err) = self.try_set_coefficient(row, col, value) {
            panic!("{err}");
        }
    }

    /// Fallible coefficient setter for untrusted solver construction paths.
    ///
    /// Returns a deterministic error instead of panicking on out-of-range row or
    /// column indices.
    pub fn try_set_coefficient(
        &mut self,
        row: usize,
        col: usize,
        value: Gf256,
    ) -> Result<(), GaussianInputError> {
        if row >= self.rows {
            return Err(GaussianInputError::RowOutOfBounds {
                row,
                rows: self.rows,
            });
        }
        if col >= self.cols {
            return Err(GaussianInputError::ColumnOutOfBounds {
                row,
                column: col,
                cols: self.cols,
            });
        }
        self.matrix[row][col] = value.raw();
        Ok(())
    }

    /// Set RHS for a row.
    pub fn set_rhs(&mut self, row: usize, rhs: DenseRow) {
        if let Err(err) = self.try_set_rhs(row, rhs) {
            panic!("{err}");
        }
    }

    /// Fallible RHS setter for untrusted solver construction paths.
    ///
    /// Returns a deterministic error instead of panicking on an out-of-range row.
    pub fn try_set_rhs(&mut self, row: usize, rhs: DenseRow) -> Result<(), GaussianInputError> {
        if row >= self.rows {
            return Err(GaussianInputError::RowOutOfBounds {
                row,
                rows: self.rows,
            });
        }
        self.rhs[row] = rhs;
        Ok(())
    }

    /// Returns the current statistics.
    #[must_use]
    pub fn stats(&self) -> &GaussianStats {
        &self.stats
    }

    /// Computes the current coefficient rank without considering RHS data.
    ///
    /// This is an opt-in rank probe rather than part of the hot solve path. It
    /// treats missing coefficients as zero and skips free columns, so it reports
    /// true matrix rank even when `solve` must fail closed at the first missing
    /// pivot because a unique solution cannot be reconstructed.
    #[must_use]
    pub fn rank_status(&self) -> GaussianRankStatus {
        let profile = self.rank_profile();
        GaussianRankStatus {
            rows: self.rows,
            columns: self.cols,
            rank: profile.rank,
            deficit: profile.deficit,
        }
    }

    /// Computes the current deterministic coefficient rank profile.
    ///
    /// This exposes the exact pivot/free-column witness used by rank probes,
    /// without changing solver behavior or treating rank-deficient systems as
    /// successful decodes.
    #[must_use]
    pub fn rank_profile(&self) -> GaussianRankProfile {
        let rows: Vec<&[u8]> = self.matrix.iter().map(Vec::as_slice).collect();
        coefficient_rank_profile(&rows, self.cols)
    }

    /// Solve the system using Gaussian elimination with partial pivoting.
    ///
    /// Returns `GaussianResult::Solved` with the solution if successful,
    /// `GaussianResult::Singular` if no pivot exists, or
    /// `GaussianResult::Inconsistent` for contradictory overdetermined systems.
    pub fn solve(&mut self) -> GaussianResult {
        if let Some(row) = self.rhs_width_mismatch_row() {
            return GaussianResult::Inconsistent { row };
        }
        let n = self.rows.min(self.cols);

        // Forward elimination
        for pivot_col in 0..n {
            self.stats.pivot_selections += 1;

            // Find pivot row (first nonzero in column, starting from pivot_col)
            let Some(pivot_row) = self.find_pivot(pivot_col, pivot_col) else {
                // br-asupersync-mwx6zi: classification must be a
                // function of the system, not of the pivot strategy.
                // Pre-fix this branch only checked the row aligned
                // to `pivot_col` for an explicit contradiction —
                // which meant the same rank-deficient system could
                // classify as Inconsistent under one pivot strategy
                // and Singular under another, depending on which
                // row happened to land at the stall column. Now we
                // scan ALL remaining rows (>= pivot_col) for a
                // zero-coefficient nonzero-RHS row; if any exists
                // the system is genuinely Inconsistent, otherwise
                // it is genuinely Singular. Both solvers use the
                // same scan, so they cannot disagree on the same
                // input.
                return self.classify_missing_pivot(pivot_col);
            };

            // Swap if needed
            if pivot_row != pivot_col {
                self.swap_rows(pivot_col, pivot_row);
            }

            self.normalize_pivot_row(pivot_col);

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

        if let Some(row) = self.first_inconsistent_row() {
            return GaussianResult::Inconsistent { row };
        }

        self.solved_result(n)
    }

    /// Solve with Markowitz pivot selection (better for sparse matrices).
    pub fn solve_markowitz(&mut self) -> GaussianResult {
        if let Some(row) = self.rhs_width_mismatch_row() {
            return GaussianResult::Inconsistent { row };
        }
        let n = self.rows.min(self.cols);

        // Forward elimination with Markowitz pivoting
        for pivot_col in 0..n {
            self.stats.pivot_selections += 1;

            // Find best pivot (sparsest row with nonzero in column)
            let Some((pivot_row, _nnz)) = self.find_pivot_markowitz(pivot_col, pivot_col) else {
                // br-asupersync-mwx6zi: same FULL-scan classification
                // as `solve` so both pivot strategies yield identical
                // outcomes on every input. See the parallel comment
                // in `solve` for the rationale (cross-solver
                // agreement is a function of the system, not of the
                // pivot strategy).
                return self.classify_missing_pivot(pivot_col);
            };

            // Swap if needed
            if pivot_row != pivot_col {
                self.swap_rows(pivot_col, pivot_row);
            }

            self.normalize_pivot_row(pivot_col);

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

        if let Some(row) = self.first_inconsistent_row() {
            return GaussianResult::Inconsistent { row };
        }

        self.solved_result(n)
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
            let row_slice = self.matrix[row].as_slice();
            debug_assert!(
                row_slice[..col.min(row_slice.len())]
                    .iter()
                    .all(|&coef| coef == 0),
                "markowitz expects columns before current pivot to be structurally zero"
            );
            let nnz = match best {
                None => count_nonzero_capped_from(row_slice, col, usize::MAX),
                Some((_, current_best)) => {
                    // Cap at `current_best - 1`; >= current_best cannot improve pivot.
                    count_nonzero_capped_from(row_slice, col, current_best.saturating_sub(1))
                }
            };
            match &best {
                None => {
                    best = Some((row, nnz));
                    if nnz == 1 {
                        break;
                    }
                }
                Some((_, best_nnz)) if nnz < *best_nnz => {
                    best = Some((row, nnz));
                    if nnz == 1 {
                        break;
                    }
                }
                Some((best_row, best_nnz)) if nnz == *best_nnz && row < *best_row => {
                    best = Some((row, nnz));
                }
                _ => {}
            }
        }

        best
    }

    /// Returns the first transformed row that is all-zero in coefficients but
    /// has a non-zero RHS, indicating an inconsistent system.
    fn first_inconsistent_row(&self) -> Option<usize> {
        self.first_inconsistent_row_from(0)
    }

    fn rhs_width_mismatch_row(&self) -> Option<usize> {
        let expected = self.rhs.first().map_or(0, DenseRow::len);
        self.rhs
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(row, rhs)| (rhs.len() != expected).then_some(row))
    }

    fn first_inconsistent_row_from(&self, start_row: usize) -> Option<usize> {
        (start_row..self.rows).find(|&row| self.is_inconsistent_row(row))
    }

    fn classify_missing_pivot(&self, pivot_col: usize) -> GaussianResult {
        self.first_inconsistent_row_from(pivot_col)
            .or_else(|| self.first_augmented_inconsistent_row())
            .map_or(GaussianResult::Singular { row: pivot_col }, |row| {
                GaussianResult::Inconsistent { row }
            })
    }

    fn first_augmented_inconsistent_row(&self) -> Option<usize> {
        let rhs_width = self.rhs.first().map_or(0, DenseRow::len);
        if rhs_width == 0 {
            return None;
        }

        let total_columns = self.cols + rhs_width;
        let mut augmented = Vec::with_capacity(self.rows);
        for (coefficients, rhs) in self.matrix.iter().zip(&self.rhs) {
            let mut row = Vec::with_capacity(total_columns);
            row.extend(coefficients.iter().copied().map(Gf256::new));
            row.extend(rhs.as_slice().iter().copied().map(Gf256::new));
            augmented.push(row);
        }

        let mut pivot_row = 0usize;
        for pivot_col in 0..self.cols {
            let Some(selected_row) =
                (pivot_row..self.rows).find(|&row| !augmented[row][pivot_col].is_zero())
            else {
                continue;
            };
            if selected_row != pivot_row {
                augmented.swap(pivot_row, selected_row);
            }

            let inv = augmented[pivot_row][pivot_col].inv();
            for value in augmented[pivot_row].iter_mut().skip(pivot_col) {
                *value *= inv;
            }
            let pivot_tail = augmented[pivot_row][pivot_col..total_columns].to_vec();

            for row in 0..self.rows {
                if row == pivot_row {
                    continue;
                }
                let factor = augmented[row][pivot_col];
                if factor.is_zero() {
                    continue;
                }
                for (offset, &pivot_value) in pivot_tail.iter().enumerate() {
                    augmented[row][pivot_col + offset] += pivot_value * factor;
                }
            }

            pivot_row += 1;
            if pivot_row == self.rows {
                break;
            }
        }

        augmented.iter().position(|row| {
            row[..self.cols].iter().all(|value| value.is_zero())
                && row[self.cols..].iter().any(|value| !value.is_zero())
        })
    }

    /// True when a transformed row is `0 = b` with non-zero RHS.
    fn is_inconsistent_row(&self, row: usize) -> bool {
        self.matrix[row].iter().all(|&coef| coef == 0) // ubs:ignore - math coefficient, not a secret
            && self.rhs[row].as_slice().iter().any(|&byte| byte != 0)
    }

    fn solved_result(&self, pivot_count: usize) -> GaussianResult {
        if self.rows < self.cols {
            return GaussianResult::Singular { row: pivot_count };
        }
        GaussianResult::Solved(self.rhs[..self.cols].to_vec())
    }

    /// Normalize the pivot row so `matrix[pivot][pivot] == 1`, scaling only
    /// the active coefficient tail and RHS instead of the full row.
    fn normalize_pivot_row(&mut self, pivot: usize) {
        debug_assert!(
            self.matrix[pivot][..pivot.min(self.matrix[pivot].len())]
                .iter()
                .all(|&coef| coef == 0),
            "pivot normalization expects columns before the pivot to be structurally zero"
        );
        let pivot_val = Gf256::new(self.matrix[pivot][pivot]);
        let pivot_inv = pivot_val.inv();
        let rhs_len = self.rhs[pivot].len();
        let coeff_tail = &mut self.matrix[pivot][pivot..];

        if rhs_len == 0 {
            gf256_mul_slice(coeff_tail, pivot_inv);
            return;
        }

        gf256_mul_slices2(coeff_tail, self.rhs[pivot].as_mut_slice(), pivot_inv);
    }

    /// Swap two rows.
    fn swap_rows(&mut self, a: usize, b: usize) {
        self.stats.swaps += 1;
        self.matrix.swap(a, b);
        self.rhs.swap(a, b);
    }

    /// Eliminate: row[target] -= factor * row[pivot].
    fn eliminate_row(&mut self, target: usize, pivot: usize, factor: Gf256) {
        if target == pivot {
            return;
        }
        if factor == Gf256::ZERO {
            return;
        }
        self.stats.scale_adds += 1;
        let factor_is_one = factor == Gf256::ONE;
        let cols = self.matrix[target].len();
        let tail_start = (pivot + 1).min(cols);
        // Eliminate the pivot coefficient directly; this is always required.
        self.matrix[target][pivot] = 0;

        // Eliminate in RHS - use split_at_mut to satisfy borrow checker.
        // When there is no coefficient tail, we can skip matrix split/borrow
        // and run the cheaper RHS-only path.
        let rhs_len = self.rhs[pivot].len();
        if tail_start >= cols && rhs_len == 0 {
            return;
        }
        if tail_start >= cols {
            if self.rhs[target].len() < rhs_len {
                self.rhs[target].data.resize(rhs_len, 0);
            }
            let (lower, upper) = if target < pivot {
                let (lo, hi) = self.rhs.split_at_mut(pivot);
                (&mut lo[target], &hi[0])
            } else {
                let (lo, hi) = self.rhs.split_at_mut(target);
                (&mut hi[0], &lo[pivot])
            };
            let rhs_target = &mut lower.as_mut_slice()[..rhs_len];
            let rhs_pivot = &upper.as_slice()[..rhs_len];
            if factor_is_one {
                if rhs_len <= XOR_TINY_FAST_PATH_MAX_BYTES {
                    row_xor_tiny(rhs_target, rhs_pivot);
                } else {
                    gf256_add_slice(rhs_target, rhs_pivot);
                }
            } else {
                gf256_addmul_slice(rhs_target, rhs_pivot, factor);
            }
            return;
        }

        // Coefficient-tail + optional RHS path.
        let (target_row, pivot_row) = if target < pivot {
            let (lo, hi) = self.matrix.split_at_mut(pivot);
            (&mut lo[target], hi[0].as_slice())
        } else {
            let (lo, hi) = self.matrix.split_at_mut(target);
            (&mut hi[0], lo[pivot].as_slice())
        };
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

            let rhs_target = &mut lower.as_mut_slice()[..rhs_len];
            let rhs_pivot = &upper.as_slice()[..rhs_len];
            debug_assert!(tail_start < cols);
            if factor_is_one {
                let tail_target = &mut target_row[tail_start..];
                let tail_pivot = &pivot_row[tail_start..];
                if tail_target.len() <= XOR_TINY_FAST_PATH_MAX_BYTES
                    && rhs_len <= XOR_TINY_FAST_PATH_MAX_BYTES
                {
                    row_xor_tiny(tail_target, tail_pivot);
                    row_xor_tiny(rhs_target, rhs_pivot);
                } else {
                    gf256_add_slices2(tail_target, tail_pivot, rhs_target, rhs_pivot);
                }
            } else {
                gf256_addmul_slices2(
                    &mut target_row[tail_start..],
                    &pivot_row[tail_start..],
                    rhs_target,
                    rhs_pivot,
                    factor,
                );
            }
        } else if factor_is_one {
            let tail_target = &mut target_row[tail_start..];
            let tail_pivot = &pivot_row[tail_start..];
            if tail_target.len() <= XOR_TINY_FAST_PATH_MAX_BYTES {
                row_xor_tiny(tail_target, tail_pivot);
            } else {
                gf256_add_slice(tail_target, tail_pivot);
            }
        } else {
            gf256_addmul_slice(
                &mut target_row[tail_start..],
                &pivot_row[tail_start..],
                factor,
            );
        }
    }
}

/// Counts non-zero coefficients in `row[start_col..]`, stopping once the count
/// exceeds `cap`. This keeps Markowitz scans bounded once a good candidate
/// exists and skips structural-zero prefix columns.
///
/// Typical Markowitz usage passes `cap = best_nnz - 1`: any value returned
/// above `cap` proves the row cannot beat the incumbent and allows early exit.
fn count_nonzero_capped_from(row: &[u8], start_col: usize, cap: usize) -> usize {
    let start = start_col.min(row.len());
    let mut count = 0usize;
    for &coef in &row[start..] {
        if coef != 0 {
            count += 1;
            if count > cap {
                break;
            }
        }
    }
    count
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "linalg_inline_tests.rs"]
mod tests;
