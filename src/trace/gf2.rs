//! GF(2) bitset linear algebra for persistent homology.
//!
//! Provides deterministic bitset operations over the Galois field GF(2) = {0, 1},
//! used by boundary-matrix reduction in the persistent homology pipeline.
//!
//! # Operations
//!
//! - XOR columns (addition in GF(2))
//! - Pivot finding (lowest set bit, for reduced column form)
//! - Column reduction (stable elimination order)
//! - Boundary matrix representation
//!
//! # Determinism
//!
//! All operations are deterministic: same input produces identical output
//! regardless of platform or run. This is critical for the lab runtime's
//! reproducibility guarantees.

use std::fmt;

// ============================================================================
// BitVec — Dense bitset for GF(2) vectors
// ============================================================================

/// A dense bitset representing a vector over GF(2).
///
/// Internally stored as a `Vec<u64>` where each u64 holds 64 bits.
/// Bit `i` corresponds to word `i / 64`, bit position `i % 64`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BitVec {
    /// Packed 64-bit words. Bit `i` is `(words[i/64] >> (i%64)) & 1`.
    words: Vec<u64>,
    /// Number of logical bits (may exceed `words.len() * 64` conceptually,
    /// but trailing words are zero-extended on read).
    len: usize,
}

impl BitVec {
    /// Creates a zero vector of the given length.
    #[must_use]
    pub fn zeros(len: usize) -> Self {
        let word_count = len.div_ceil(64);
        Self {
            words: vec![0; word_count],
            len,
        }
    }

    /// Creates a vector with a single bit set.
    #[must_use]
    pub fn singleton(len: usize, bit: usize) -> Self {
        let mut v = Self::zeros(len);
        v.set(bit);
        v
    }

    /// Returns the number of logical bits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the vector has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the vector is the zero vector.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Returns true if bit `i` is set.
    ///
    /// # Panics
    /// Panics if `i >= self.len`.
    #[must_use]
    pub fn get(&self, i: usize) -> bool {
        assert!(
            i < self.len,
            "bit index {i} out of range (len={})",
            self.len
        );
        let word = i / 64;
        let bit = i % 64;
        (self.words[word] >> bit) & 1 == 1
    }

    /// Sets bit `i` to 1.
    ///
    /// # Panics
    /// Panics if `i >= self.len`.
    pub fn set(&mut self, i: usize) {
        assert!(
            i < self.len,
            "bit index {i} out of range (len={})",
            self.len
        );
        let word = i / 64;
        let bit = i % 64;
        self.words[word] |= 1u64 << bit;
    }

    /// Clears bit `i` to 0.
    ///
    /// # Panics
    /// Panics if `i >= self.len`.
    pub fn clear(&mut self, i: usize) {
        assert!(
            i < self.len,
            "bit index {i} out of range (len={})",
            self.len
        );
        let word = i / 64;
        let bit = i % 64;
        self.words[word] &= !(1u64 << bit);
    }

    /// Flips bit `i`.
    ///
    /// # Panics
    /// Panics if `i >= self.len`.
    pub fn flip(&mut self, i: usize) {
        assert!(
            i < self.len,
            "bit index {i} out of range (len={})",
            self.len
        );
        let word = i / 64;
        let bit = i % 64;
        self.words[word] ^= 1u64 << bit;
    }

    /// XOR-assigns another vector into this one (addition in GF(2)).
    ///
    /// Vectors must have the same length.
    ///
    /// # Panics
    /// Panics if lengths differ.
    pub fn xor_assign(&mut self, other: &Self) {
        assert_eq!(
            self.len, other.len,
            "xor_assign: length mismatch ({} vs {})",
            self.len, other.len
        );
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a ^= b;
        }
    }

    /// Returns the XOR of two vectors (addition in GF(2)).
    #[must_use]
    pub fn xor(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.xor_assign(other);
        result
    }

    /// Returns the index of the lowest set bit (the "pivot" in column reduction).
    ///
    /// Returns `None` if the vector is zero.
    #[must_use]
    pub fn pivot(&self) -> Option<usize> {
        for (word_idx, &word) in self.words.iter().enumerate() {
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let index = word_idx * 64 + bit;
                if index < self.len {
                    return Some(index);
                }
            }
        }
        None
    }

    /// Returns the index of the highest set bit.
    ///
    /// Returns `None` if the vector is zero.
    #[must_use]
    pub fn highest_bit(&self) -> Option<usize> {
        for (word_idx, &word) in self.words.iter().enumerate().rev() {
            let mut w = word;
            // Mask out bits past `self.len` in the last word
            if word_idx == self.words.len() - 1 {
                let rem = self.len % 64;
                if rem != 0 {
                    w &= (1u64 << rem) - 1;
                }
            }
            if w != 0 {
                let bit = 63 - w.leading_zeros() as usize;
                return Some(word_idx * 64 + bit);
            }
        }
        None
    }

    /// Returns the number of set bits (popcount / Hamming weight).
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Returns an iterator over the indices of set bits, in ascending order.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(move |(word_idx, &word)| {
                let base = word_idx * 64;
                BitIter {
                    word,
                    base,
                    len: self.len,
                }
            })
    }
}

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitVec({}, [", self.len)?;
        let mut first = true;
        for i in self.ones() {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{i}")?;
            first = false;
        }
        write!(f, "])")
    }
}

/// Iterator over set bit indices in a single u64 word.
struct BitIter {
    word: u64,
    base: usize,
    len: usize,
}

impl Iterator for BitIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.word == 0 {
            return None;
        }
        let bit = self.word.trailing_zeros() as usize;
        let index = self.base + bit;
        if index >= self.len {
            self.word = 0;
            return None;
        }
        // Clear the lowest set bit
        self.word &= self.word - 1;
        Some(index)
    }
}

// ============================================================================
// BoundaryMatrix — Sparse column matrix over GF(2)
// ============================================================================

/// A column-oriented matrix over GF(2) for boundary operator representation.
///
/// Each column is a `BitVec`. The matrix supports the standard column
/// reduction algorithm used in persistent homology computation.
#[derive(Clone)]
pub struct BoundaryMatrix {
    /// Number of rows.
    rows: usize,
    /// Columns stored as dense bitsets.
    columns: Vec<BitVec>,
}

impl BoundaryMatrix {
    /// Creates a zero matrix with the given dimensions.
    #[must_use]
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            columns: (0..cols).map(|_| BitVec::zeros(rows)).collect(),
        }
    }

    /// Creates a matrix from column vectors.
    ///
    /// # Panics
    /// Panics if any column has a different length than `rows`.
    #[must_use]
    pub fn from_columns(rows: usize, columns: Vec<BitVec>) -> Self {
        for (i, col) in columns.iter().enumerate() {
            assert_eq!(
                col.len(),
                rows,
                "column {i} has length {}, expected {rows}",
                col.len()
            );
        }
        Self { rows, columns }
    }

    /// Returns the number of rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns.
    #[must_use]
    pub fn cols(&self) -> usize {
        self.columns.len()
    }

    /// Returns a reference to column `j`.
    ///
    /// # Panics
    /// Panics if `j >= self.cols()`.
    #[must_use]
    pub fn column(&self, j: usize) -> &BitVec {
        &self.columns[j]
    }

    /// Returns a mutable reference to column `j`.
    pub fn column_mut(&mut self, j: usize) -> &mut BitVec {
        &mut self.columns[j]
    }

    /// Sets entry (i, j) to 1.
    pub fn set(&mut self, i: usize, j: usize) {
        self.columns[j].set(i);
    }

    /// Returns entry (i, j).
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> bool {
        self.columns[j].get(i)
    }

    /// XOR column `src` into column `dst` (column addition in GF(2)).
    ///
    /// # Panics
    /// Panics if `src == dst` or indices are out of range.
    pub fn xor_columns(&mut self, dst: usize, src: usize) {
        assert_ne!(dst, src, "xor_columns: src and dst must differ");
        // Safety: src != dst ensures no aliasing.
        let src_col = self.columns[src].clone();
        self.columns[dst].xor_assign(&src_col);
    }

    /// Returns the pivot (highest set bit index) of column `j`.
    #[must_use]
    pub fn column_pivot(&self, j: usize) -> Option<usize> {
        self.columns[j].highest_bit()
    }

    /// Performs standard column reduction (left-to-right) and returns
    /// the reduced matrix along with the pivot map.
    ///
    /// The pivot map maps `pivot_row -> column_index` for non-zero columns.
    /// A pair `(i, j)` in the pivot map means column `j` has its highest
    /// set bit at row `i` after reduction.
    ///
    /// This is the standard algorithm for computing persistent homology.
    /// The elimination order is deterministic: columns are processed
    /// left-to-right, and for each column, the leftmost column with the
    /// same pivot is used for elimination.
    #[must_use]
    pub fn reduce(&self) -> ReducedMatrix {
        let mut reduced = self.clone();
        let mut pivot_map: Vec<Option<usize>> = vec![None; self.rows];

        for j in 0..reduced.cols() {
            // Reduce column j until its pivot is unique or it becomes zero
            while let Some(pivot) = reduced.column_pivot(j) {
                let Some(existing_col) = pivot_map[pivot] else {
                    // No column has this pivot yet — record and stop
                    pivot_map[pivot] = Some(j);
                    break;
                };

                // Another column has the same pivot — XOR to eliminate
                let existing = reduced.columns[existing_col].clone();
                reduced.columns[j].xor_assign(&existing);
            }
        }

        ReducedMatrix {
            matrix: reduced,
            pivot_map,
        }
    }
}

impl fmt::Debug for BoundaryMatrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "BoundaryMatrix({}x{}):", self.rows, self.cols())?;
        for i in 0..self.rows {
            write!(f, "  ")?;
            for j in 0..self.cols() {
                write!(f, "{}", u8::from(self.get(i, j)))?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

// ============================================================================
// ReducedMatrix — Result of column reduction
// ============================================================================

/// The result of reducing a boundary matrix.
#[derive(Clone)]
pub struct ReducedMatrix {
    /// The reduced matrix.
    pub matrix: BoundaryMatrix,
    /// `pivot_map[row]` = `Some(col)` if column `col` has its lowest bit at `row`.
    pub pivot_map: Vec<Option<usize>>,
}

impl ReducedMatrix {
    /// Returns persistence pairs: `(birth, death)` indices.
    ///
    /// A pair `(i, j)` means the feature born at simplex `i` dies at simplex `j`.
    /// Unpaired births are features that persist to infinity.
    #[must_use]
    pub fn persistence_pairs(&self) -> PersistencePairs {
        let mut pairs = Vec::new();
        let mut unpaired = Vec::new();

        for j in 0..self.matrix.cols() {
            if let Some(pivot) = self.matrix.column_pivot(j) {
                pairs.push((pivot, j));
            }
        }

        // Find unpaired columns (births without deaths).
        // `is_death` tracks column indices (0..cols), while `is_birth` tracks
        // row indices (pivot positions, 0..rows). These dimensions differ for
        // non-square matrices, so they must be sized independently.
        let mut is_death = vec![false; self.matrix.cols()];
        let mut is_birth = vec![false; self.matrix.rows()];
        for &(birth, death) in &pairs {
            is_birth[birth] = true;
            is_death[death] = true;
        }

        for j in 0..self.matrix.cols() {
            // For square (combined filtration) matrices, row `j` and column `j`
            // refer to the same simplex, so is_birth[j] correctly identifies
            // columns that are already paired as births. For non-square boundary
            // operators (rows != cols), the check only applies when `j < rows`.
            let j_is_birth = j < self.matrix.rows() && is_birth[j];
            if !is_death[j] && !j_is_birth && self.matrix.column(j).is_zero() {
                // Zero column that is not paired as a birth — it's an unpaired cycle
                unpaired.push(j);
            }
        }

        PersistencePairs { pairs, unpaired }
    }
}

/// Persistence pairs from a reduced boundary matrix.
#[derive(Debug, Clone)]
pub struct PersistencePairs {
    /// Paired features: `(birth_index, death_index)`.
    pub pairs: Vec<(usize, usize)>,
    /// Unpaired features (persist to infinity).
    pub unpaired: Vec<usize>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "gf2_inline_tests.rs"]
mod tests;
