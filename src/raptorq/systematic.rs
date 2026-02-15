//! RFC 6330-grade systematic RaptorQ encoder.
//!
//! Implements a deterministic systematic encoder that produces:
//! 1. K source symbols (systematic part — data passed through unchanged)
//! 2. Repair symbols constructed from intermediate symbols via LT encoding
//!
//! # Architecture
//!
//! ```text
//! Source Data (K symbols)
//!     │
//!     ▼
//! Precode Matrix (A)  ←── LDPC + HDPC + LT constraints
//!     │
//!     ▼
//! Intermediate Symbols (L = K' + S + H)
//!     │
//!     ▼
//! LT Encode (ISI → repair symbol)
//! ```
//!
//! # Determinism
//!
//! Randomness is used in precode-constraint generation only; repair
//! equations follow RFC tuple semantics for each ESI. For a fixed
//! `(source, symbol_size, seed)` input, output is identical across runs.

#![allow(clippy::many_single_char_names)]

use crate::raptorq::gf256::{gf256_addmul_slice, Gf256};
use crate::raptorq::rfc6330::repair_indices_for_esi;
#[cfg(test)]
use crate::util::DetRng;

// ============================================================================
// Parameters (RFC 6330 Section 5.3)
// ============================================================================

/// Systematic encoding parameters for a single source block.
///
/// RFC 6330 defines several derived parameters:
/// - K': extended source block size selected from the systematic index table
/// - L = K' + S + H: total intermediate symbols
/// - W: number of LT symbols (non-PI symbols), table-driven
/// - P = L - W: number of PI symbols
/// - B = W - S: number of non-LDPC LT symbols
#[derive(Debug, Clone)]
pub struct SystematicParams {
    /// K: number of source symbols in this block.
    pub k: usize,
    /// K': RFC 6330 extended source block size selected for K.
    pub k_prime: usize,
    /// J(K'): RFC 6330 systematic index.
    pub j: usize,
    /// S: number of LDPC symbols.
    pub s: usize,
    /// H: number of HDPC (Half-Distance) symbols.
    pub h: usize,
    /// L = K' + S + H: total intermediate symbols.
    pub l: usize,
    /// W: number of LT symbols.
    pub w: usize,
    /// P = L - W: number of PI symbols.
    pub p: usize,
    /// B = W - S: number of non-LDPC LT symbols.
    pub b: usize,
    /// Symbol size in bytes.
    pub symbol_size: usize,
}

/// RFC 6330 Table 2 rows: `(K', J(K'), S(K'), H(K'), W(K'))`.
///
/// Source: RFC 6330 Section 5.6.
const SYSTEMATIC_INDEX_TABLE: &[(u32, u16, u16, u8, u32)] =
    &include!("rfc6330_systematic_index_table.inc");

/// Explicit lookup failure for source block parameter derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystematicParamError {
    /// Requested `K` is larger than the maximum K' covered by RFC 6330 Table 2.
    UnsupportedSourceBlockSize {
        /// Requested source block symbol count.
        requested: usize,
        /// Largest supported source block symbol count in this implementation.
        max_supported: usize,
    },
}

impl SystematicParams {
    /// Compute encoding parameters for `k` source symbols of given size.
    ///
    /// Derived parameters per RFC 6330 systematic index table:
    /// - K' = smallest table entry >= K
    /// - J, S, H, W selected from that K' row
    /// - P = L - W (PI symbols)
    /// - B = W - S (non-LDPC LT symbols)
    /// - L = K' + S + H
    #[must_use]
    pub fn for_source_block(k: usize, symbol_size: usize) -> Self {
        assert!(k > 0, "source block must have at least one symbol");
        Self::try_for_source_block(k, symbol_size).unwrap_or_else(|err| match err {
            SystematicParamError::UnsupportedSourceBlockSize {
                requested,
                max_supported,
            } => {
                panic!(
                    "unsupported source block size K={requested}; supported range is 1..={max_supported}"
                )
            }
        })
    }

    /// Fallible parameter lookup from the RFC 6330 systematic index table.
    pub fn try_for_source_block(
        k: usize,
        symbol_size: usize,
    ) -> Result<Self, SystematicParamError> {
        let max_supported = SYSTEMATIC_INDEX_TABLE
            .last()
            .map_or(0usize, |row| row.0 as usize);
        if k == 0 || k > max_supported {
            return Err(SystematicParamError::UnsupportedSourceBlockSize {
                requested: k,
                max_supported,
            });
        }
        let idx = SYSTEMATIC_INDEX_TABLE.partition_point(|row| row.0 < k as u32);
        debug_assert!(idx < SYSTEMATIC_INDEX_TABLE.len());

        let (k_prime, j, s, h, w) = SYSTEMATIC_INDEX_TABLE[idx];
        let k_prime = k_prime as usize;
        let j = j as usize;
        let s = s as usize;
        let h = h as usize;
        let w = w as usize;
        let l = k_prime + s + h;
        let b = w
            .checked_sub(s)
            .expect("RFC table invariant violated: W < S");
        let p = l
            .checked_sub(w)
            .expect("RFC table invariant violated: W > L");

        Ok(Self {
            k,
            k_prime,
            j,
            s,
            h,
            l,
            w,
            p,
            b,
            symbol_size,
        })
    }

    /// Generate the RFC 6330 repair equation (columns + coefficients) for an ESI.
    ///
    /// This helper centralizes decoder/encoder tuple semantics so parity checks
    /// can use one source of truth for RFC tuple expansion.
    #[must_use]
    pub fn rfc_repair_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        let columns = repair_indices_for_esi(self.j, self.w, self.p, esi);
        let coefficients = vec![Gf256::ONE; columns.len()];
        (columns, coefficients)
    }
}

// ============================================================================
// Degree distribution (Robust Soliton)
// ============================================================================

/// Robust soliton degree distribution for LT encoding.
///
/// Combines the ideal soliton distribution with a perturbation τ to
/// ensure the intermediate symbols can be recovered with high probability.
#[derive(Debug, Clone)]
pub struct RobustSoliton {
    /// Cumulative distribution function (CDF) scaled to u32::MAX.
    cdf: Vec<u32>,
    /// K parameter (number of input symbols).
    k: usize,
}

impl RobustSoliton {
    /// Build the robust soliton CDF for `k` input symbols.
    ///
    /// Parameters `c` and `delta` control the trade-off between
    /// overhead and decoding failure probability.
    /// - `c`: free parameter (typically 0.1–0.5)
    /// - `delta`: failure probability bound (typically 0.01–0.1)
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    pub fn new(k: usize, c: f64, delta: f64) -> Self {
        assert!(k > 0);
        let k_f = k as f64;

        // R = c * ln(K/delta) * sqrt(K)
        let r = c * (k_f / delta).ln() * k_f.sqrt();

        // Ideal soliton ρ(d)
        let mut rho = vec![0.0f64; k + 1];
        rho[1] = 1.0 / k_f;
        for (d, value) in rho.iter_mut().enumerate().skip(2) {
            let d_f = d as f64;
            *value = 1.0 / (d_f * (d_f - 1.0));
        }

        // Perturbation τ(d)
        let mut tau = vec![0.0f64; k + 1];
        let threshold = (k_f / r).floor() as usize;
        let max_d = k.min(threshold.max(1));
        for (d, value) in tau.iter_mut().enumerate().skip(1).take(max_d) {
            if d < threshold {
                *value = r / (d as f64 * k_f);
            } else {
                *value = r * (r / delta).ln() / k_f;
            }
        }

        // μ(d) = ρ(d) + τ(d), then normalize
        let mut mu: Vec<f64> = rho.iter().zip(tau.iter()).map(|(r, t)| r + t).collect();
        let sum: f64 = mu.iter().sum();
        if sum > 0.0 {
            for m in &mut mu {
                *m /= sum;
            }
        }

        // Build CDF scaled to u32::MAX
        let mut cdf = Vec::with_capacity(k + 1);
        let mut cumulative = 0.0f64;
        let scale = f64::from(u32::MAX);
        for &p in &mu {
            cumulative += p;
            cdf.push((cumulative * scale).min(scale) as u32);
        }
        // Ensure last entry is exactly MAX
        if let Some(last) = cdf.last_mut() {
            *last = u32::MAX;
        }

        Self { cdf, k }
    }

    /// Sample a degree from the distribution using a raw u32 random value.
    #[must_use]
    pub fn sample(&self, rand_val: u32) -> usize {
        // Binary search for the bucket
        match self.cdf.binary_search(&rand_val) {
            Ok(idx) | Err(idx) => idx.max(1).min(self.k),
        }
    }

    /// Number of input symbols (K).
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Maximum possible degree (equals K).
    #[must_use]
    pub fn max_degree(&self) -> usize {
        self.k
    }

    /// Validate parameters before construction. Returns an error string if invalid.
    #[must_use]
    pub fn validate_params(k: usize, c: f64, delta: f64) -> Option<&'static str> {
        if k == 0 {
            return Some("k must be positive");
        }
        if c <= 0.0 || !c.is_finite() {
            return Some("c must be a positive finite number");
        }
        if delta <= 0.0 || delta >= 1.0 || !delta.is_finite() {
            return Some("delta must be in (0, 1)");
        }
        None
    }
}

// ============================================================================
// Constraint matrix construction
// ============================================================================

/// Row-major constraint matrix over GF(256).
///
/// Represents the encoding constraint matrix A such that A · C = D,
/// where C is the vector of intermediate symbols and D is the vector
/// of known symbols (source + constraint zeros).
#[derive(Debug, Clone)]
pub struct ConstraintMatrix {
    /// Row-major storage: `rows` × `cols` elements.
    data: Vec<Gf256>,
    /// Number of rows.
    pub rows: usize,
    /// Number of columns (= L, intermediate symbol count).
    pub cols: usize,
}

impl ConstraintMatrix {
    /// Create a zero matrix.
    #[must_use]
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self {
            data: vec![Gf256::ZERO; rows * cols],
            rows,
            cols,
        }
    }

    /// Get element at (row, col).
    #[inline]
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> Gf256 {
        self.data[row * self.cols + col]
    }

    /// Set element at (row, col).
    #[inline]
    pub fn set(&mut self, row: usize, col: usize, val: Gf256) {
        self.data[row * self.cols + col] = val;
    }

    /// Add `val` to element at (row, col).
    #[inline]
    pub fn add_assign(&mut self, row: usize, col: usize, val: Gf256) {
        self.data[row * self.cols + col] += val;
    }

    /// Build the full constraint matrix for a source block.
    ///
    /// The matrix has structure:
    /// ```text
    /// ┌─────────────────┐
    /// │  LDPC (S rows)  │  S × L
    /// │  HDPC (H rows)  │  H × L
    /// │  LT  (K' rows)  │  K' × L
    /// └─────────────────┘
    /// ```
    #[must_use]
    pub fn build(params: &SystematicParams, seed: u64) -> Self {
        let l = params.l;
        let total_rows = params.s + params.h + params.k_prime;
        let mut matrix = Self::zeros(total_rows, l);

        // LDPC constraints (rows 0..S)
        build_ldpc_rows(&mut matrix, params, seed);

        // HDPC constraints (rows S..S+H)
        build_hdpc_rows(&mut matrix, params, seed);

        // LT constraints for systematic symbols (rows S+H..S+H+K')
        build_lt_rows(&mut matrix, params, seed);

        matrix
    }

    /// Solve the system A·C = D using Gaussian elimination over GF(256).
    ///
    /// `rhs` is a matrix of `rows` rows, each `symbol_size` bytes wide.
    /// Returns the `cols`-row solution matrix (intermediate symbols).
    ///
    /// Returns `None` if the matrix is singular.
    #[must_use]
    pub fn solve(&self, rhs: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        assert_eq!(rhs.len(), self.rows);
        let symbol_size = if rhs.is_empty() { 0 } else { rhs[0].len() };
        let n = self.cols;

        // Augmented system: copy matrix and RHS
        let mut a = self.data.clone();
        let cols = self.cols;
        let mut b: Vec<Vec<u8>> = rhs.to_vec();

        // Pivots: column index for each row
        let mut pivot_col = vec![usize::MAX; self.rows];
        let mut used_col = vec![false; cols];

        // Forward elimination with minimum-degree row selection.
        //
        // At each step, select the unprocessed row with the fewest nonzero
        // entries in unused columns (minimum degree). This preferentially
        // pivots on identity rows (degree 1), preventing them from losing
        // their column to denser rows. This strategy is a simplified form
        // of RFC 6330 Section 5.4's inactivation decoding heuristic.
        let mut used_row = vec![false; self.rows];
        for step in 0..self.rows.min(n) {
            // Find unprocessed row with minimum degree in unused columns.
            let mut best: Option<(usize, usize, usize)> = None; // (row, col, degree)
            for r in 0..self.rows {
                if used_row[r] {
                    continue;
                }
                let mut deg = 0usize;
                let mut first_col = None;
                for c in 0..cols {
                    if !used_col[c] && !a[r * cols + c].is_zero() {
                        if first_col.is_none() {
                            first_col = Some(c);
                        }
                        deg += 1;
                    }
                }
                if let Some(fc) = first_col {
                    if best.is_none() || deg < best.unwrap().2 {
                        best = Some((r, fc, deg));
                        if deg == 1 {
                            break; // Can't do better than degree 1
                        }
                    }
                }
            }

            let Some((pivot_row, col, _)) = best else {
                continue; // no more rows with nonzeros
            };
            used_row[pivot_row] = true;

            // Swap the chosen row into position `step` for clean output ordering.
            if pivot_row != step {
                for c in 0..cols {
                    let idx_a = step * cols + c;
                    let idx_b = pivot_row * cols + c;
                    a.swap(idx_a, idx_b);
                }
                b.swap(step, pivot_row);
                pivot_col.swap(step, pivot_row);
                used_row.swap(step, pivot_row);
            }
            let row = step;

            used_col[col] = true;
            pivot_col[row] = col;

            // Scale pivot row so pivot = 1
            let inv = a[row * cols + col].inv();
            for c in 0..cols {
                a[row * cols + c] *= inv;
            }
            gf256_mul_slice_inplace(&mut b[row], inv);

            // Eliminate column in all other rows
            for other in 0..self.rows {
                if other == row {
                    continue;
                }
                let factor = a[other * cols + col];
                if factor.is_zero() {
                    continue;
                }
                for c in 0..cols {
                    let val = a[row * cols + c];
                    a[other * cols + c] += factor * val;
                }
                // b[other] += factor * b[row]
                // Use take/restore to avoid cloning the row RHS.
                let row_rhs = std::mem::take(&mut b[row]);
                gf256_addmul_slice(&mut b[other], &row_rhs, factor);
                b[row] = row_rhs;
            }
        }

        // Verify all columns have been assigned pivots (non-singular check).
        let mut col_has_pivot = vec![false; n];
        for &col in &pivot_col {
            if col < n {
                col_has_pivot[col] = true;
            }
        }
        if col_has_pivot.iter().any(|&has| !has) {
            return None; // Singular matrix: at least one column has no pivot
        }

        // Extract solution: intermediate[col] = b[row] where pivot_col[row] == col
        let mut result = vec![vec![0u8; symbol_size]; n];
        for (row, &col) in pivot_col.iter().enumerate() {
            if col < n {
                result[col].clone_from(&b[row]);
            }
        }

        Some(result)
    }
}

fn gf256_mul_slice_inplace(data: &mut [u8], c: Gf256) {
    crate::raptorq::gf256::gf256_mul_slice(data, c);
}

// ============================================================================
// Constraint row builders
// ============================================================================

/// Build LDPC constraint rows (rows 0..S).
///
/// RFC 6330 Section 5.3.3.3: LDPC pre-coding relationships.
///
/// Two parts:
/// 1. For i = 0..K'-1: each intermediate symbol C[i] participates
///    in 3 LDPC rows via a circulant pattern with step a = 1 + floor(i/S).
/// 2. Identity block: row i has coefficient 1 in column K'+i, tying
///    each LDPC row to its check symbol C[K'+i].
///
/// Identity blocks are placed at non-overlapping column ranges:
///   LT: 0..K'-1, LDPC: K'..K'+S-1, HDPC: K'+S..L-1
fn build_ldpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let k_prime = params.k_prime;

    // Part 1: Circulant connections over all K' intermediate symbols.
    // RFC 6330 Section 5.3.3.3: For i = 0, ..., K'-1
    //   a = 1 + floor(i/S)
    //   b_val = i % S
    //   D[b_val] = D[b_val] + C[i]; b_val = (b_val + a) % S
    //   D[b_val] = D[b_val] + C[i]; b_val = (b_val + a) % S
    //   D[b_val] = D[b_val] + C[i]
    for i in 0..k_prime {
        let a = 1 + i / s.max(1);
        let mut row = i % s;
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
    }

    // Part 2: LDPC check symbol identity block.
    // Each LDPC row i is tied to check symbol C[K'+i], placed at column K'+i
    // so that identity blocks (LT: 0..K'-1, LDPC: K'..K'+S-1, HDPC: K'+S..L-1)
    // are non-overlapping and cover all L columns.
    for i in 0..s {
        matrix.set(i, k_prime + i, Gf256::ONE);
    }
}

/// Build HDPC constraint rows (rows S..S+H).
///
/// RFC 6330 Section 5.3.3.3: HDPC pre-coding relationships.
///
/// The HDPC constraint is: GAMMA x MT x C[0..K'+S-1] + C[K'+S..L-1] = 0
///
/// Where:
/// - MT is an H x (K'+S) matrix built from the RFC 6330 Rand function
/// - GAMMA is an H x H lower-triangular matrix with GAMMA[i][j] = alpha^(i-j)
/// - Each HDPC row r has a 1 in column K'+S+r (identity block)
fn build_hdpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    use crate::raptorq::rfc6330::rand;

    let s = params.s;
    let h = params.h;
    let k_prime = params.k_prime;
    // MT covers all non-HDPC intermediate symbols: K'+S columns (RFC 6330 Section 5.3.3.3).
    let ks = k_prime + s;

    if h == 0 {
        return;
    }

    // Step 1: Build MT matrix (H x (K'+S)) in a temporary buffer.
    let mut mt = vec![Gf256::ZERO; h * ks];

    for j in 0..ks.saturating_sub(1) {
        let rand1 = rand((j + 1) as u32, 6, h as u32) as usize;
        let rand2 = if h > 1 {
            rand((j + 1) as u32, 7, (h - 1) as u32) as usize
        } else {
            0
        };
        let i2 = (rand1 + rand2 + 1) % h;

        mt[rand1 * ks + j] += Gf256::ONE;
        if i2 != rand1 {
            mt[i2 * ks + j] += Gf256::ONE;
        }
    }

    // Last column: MT[i, K'+S-1] = alpha^i (Vandermonde column)
    if ks > 0 {
        let last_col = ks - 1;
        for i in 0..h {
            mt[i * ks + last_col] = Gf256::ALPHA.pow((i % 255) as u8);
        }
    }

    // Step 2: Compute GAMMA x MT and write into the constraint matrix.
    // GAMMA[i][j] = alpha^(i-j) for j <= i, 0 otherwise (lower triangular).
    for r in 0..h {
        for c in 0..ks {
            let mut val = Gf256::ZERO;
            for t in 0..=r {
                let mt_val = mt[t * ks + c];
                if !mt_val.is_zero() {
                    let gamma_coeff = Gf256::ALPHA.pow(((r - t) % 255) as u8);
                    val += gamma_coeff * mt_val;
                }
            }
            if !val.is_zero() {
                matrix.set(s + r, c, val);
            }
        }
    }

    // Step 3: HDPC identity block at columns K'+S..L-1.
    // Placed after the LT (0..K'-1) and LDPC (K'..K'+S-1) identity blocks
    // so all three are non-overlapping, covering all L columns.
    for r in 0..h {
        matrix.set(s + r, ks + r, Gf256::ONE);
    }
}

/// Build LT constraint rows for systematic symbols (rows S+H..S+H+K').
///
/// For systematic encoding, source symbol i maps directly to intermediate
/// symbol i. Each LT row i has exactly a 1 in column i, creating an
/// identity block. Combined with the LDPC and HDPC identity blocks,
/// the column coverage is:
///
///   LT identity:   columns 0..K'-1
///   LDPC identity:  columns K'..K'+S-1
///   HDPC identity:  columns K'+S..L-1
///
/// This ensures all L columns are covered by non-overlapping identity
/// entries, making the matrix structurally full rank.
fn build_lt_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let h = params.h;
    let k_prime = params.k_prime;

    for i in 0..k_prime {
        let row = s + h + i;
        matrix.set(row, i, Gf256::ONE);
    }
}

// ============================================================================
// Systematic encoder
// ============================================================================

// ============================================================================
// Encoding statistics
// ============================================================================

/// Statistics from encoding, useful for tuning and debugging.
#[derive(Debug, Clone, Default)]
pub struct EncodingStats {
    /// Number of source symbols (K).
    pub source_symbol_count: usize,
    /// Number of LDPC symbols (S).
    pub ldpc_symbol_count: usize,
    /// Number of HDPC symbols (H).
    pub hdpc_symbol_count: usize,
    /// Total intermediate symbols (L = K' + S + H).
    pub intermediate_symbol_count: usize,
    /// Symbol size in bytes.
    pub symbol_size: usize,
    /// Number of repair symbols generated so far.
    pub repair_symbols_generated: usize,
    /// Seed used for deterministic encoding.
    pub seed: u64,
    /// Degree distribution sample stats (min, max, sum, count) for generated repairs.
    pub degree_min: usize,
    /// Maximum repair symbol degree observed.
    pub degree_max: usize,
    /// Sum of repair symbol degrees observed.
    pub degree_sum: usize,
    /// Number of repair symbols sampled for degree stats.
    pub degree_count: usize,
    /// Total bytes emitted as systematic (source) symbols.
    pub systematic_bytes_emitted: usize,
    /// Total bytes emitted as repair symbols.
    pub repair_bytes_emitted: usize,
}

impl EncodingStats {
    /// Average degree of generated repair symbols, or 0.0 if none generated.
    #[must_use]
    pub fn average_degree(&self) -> f64 {
        if self.degree_count == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let sum = self.degree_sum as f64;
            #[allow(clippy::cast_precision_loss)]
            let count = self.degree_count as f64;
            sum / count
        }
    }

    /// Overhead ratio: L / K (how many intermediate symbols per source symbol).
    #[must_use]
    pub fn overhead_ratio(&self) -> f64 {
        if self.source_symbol_count == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let intermediate = self.intermediate_symbol_count as f64;
            #[allow(clippy::cast_precision_loss)]
            let source = self.source_symbol_count as f64;
            intermediate / source
        }
    }

    /// Total bytes emitted across both systematic and repair symbols.
    #[must_use]
    pub const fn total_bytes_emitted(&self) -> usize {
        self.systematic_bytes_emitted + self.repair_bytes_emitted
    }

    /// Encoding efficiency: systematic bytes / total emitted bytes.
    ///
    /// Returns 0.0 if nothing has been emitted. A value near 1.0 means most
    /// bandwidth carries source data; lower values indicate more repair overhead.
    #[must_use]
    pub fn encoding_efficiency(&self) -> f64 {
        let total = self.total_bytes_emitted();
        if total == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let sys = self.systematic_bytes_emitted as f64;
            #[allow(clippy::cast_precision_loss)]
            let tot = total as f64;
            sys / tot
        }
    }

    /// Repair overhead ratio: repair bytes / systematic bytes.
    ///
    /// Returns 0.0 if no systematic bytes have been emitted. Useful for tuning
    /// how many repair symbols to generate relative to source data.
    #[must_use]
    pub fn repair_overhead(&self) -> f64 {
        if self.systematic_bytes_emitted == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let repair = self.repair_bytes_emitted as f64;
            #[allow(clippy::cast_precision_loss)]
            let sys = self.systematic_bytes_emitted as f64;
            repair / sys
        }
    }
}

impl std::fmt::Display for EncodingStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncodingStats(K={}, S={}, H={}, L={}, sym={}B, repairs={}, \
             bytes={}sys+{}rep, avg_deg={:.1}, overhead={:.2})",
            self.source_symbol_count,
            self.ldpc_symbol_count,
            self.hdpc_symbol_count,
            self.intermediate_symbol_count,
            self.symbol_size,
            self.repair_symbols_generated,
            self.systematic_bytes_emitted,
            self.repair_bytes_emitted,
            self.average_degree(),
            self.overhead_ratio(),
        )
    }
}

// ============================================================================
// Emitted symbol (systematic + repair)
// ============================================================================

/// An emitted symbol from the encoder, with metadata.
#[derive(Debug, Clone)]
pub struct EmittedSymbol {
    /// Encoding Symbol Index (ESI): 0..K for source, K.. for repair.
    pub esi: u32,
    /// The symbol data.
    pub data: Vec<u8>,
    /// Whether this is a source (systematic) or repair symbol.
    pub is_source: bool,
    /// Degree of the LT encoding (1 for source, variable for repair).
    pub degree: usize,
}

// ============================================================================
// Systematic encoder
// ============================================================================

/// A deterministic, systematic RaptorQ encoder for a single source block.
///
/// Computes intermediate symbols from source data, then generates
/// repair symbols on demand via LT encoding.
///
/// # Emission Order
///
/// Symbols are emitted in deterministic order:
/// 1. Source symbols (ESI 0..K-1) in ascending order
/// 2. Repair symbols (ESI K..) in ascending order
///
/// Use [`emit_systematic`] for source-only, [`emit_repair`] for repair-only,
/// or [`emit_all`] for a combined stream.
#[derive(Debug)]
pub struct SystematicEncoder {
    params: SystematicParams,
    /// Intermediate symbols (L symbols, each `symbol_size` bytes).
    intermediate: Vec<Vec<u8>>,
    /// Source symbols (preserved for systematic emission).
    source_symbols: Vec<Vec<u8>>,
    /// Seed for deterministic repair generation.
    seed: u64,
    /// Running statistics.
    stats: EncodingStats,
    /// Whether systematic symbols have been emitted via `emit_systematic()`.
    systematic_emitted: bool,
    /// Next repair ESI to emit (monotonic cursor, starts at K).
    next_repair_esi: u32,
}

impl SystematicEncoder {
    /// Create a new systematic encoder for the given source block.
    ///
    /// `source_symbols` must have exactly `k` entries, each `symbol_size` bytes.
    /// `seed` controls all deterministic randomness.
    ///
    /// Returns `None` if the constraint matrix is singular (should not happen
    /// for well-chosen parameters).
    #[must_use]
    pub fn new(source_symbols: &[Vec<u8>], symbol_size: usize, seed: u64) -> Option<Self> {
        let k = source_symbols.len();
        assert!(k > 0, "need at least one source symbol");
        assert!(
            source_symbols.iter().all(|s| s.len() == symbol_size),
            "all source symbols must be symbol_size bytes"
        );

        let params = SystematicParams::for_source_block(k, symbol_size);
        let matrix = ConstraintMatrix::build(&params, seed);

        // Build RHS: zeros for LDPC/HDPC rows, source data for K LT rows,
        // then explicit zeros for the padded LT rows (K..K').
        let mut rhs = Vec::with_capacity(matrix.rows);
        for _ in 0..params.s + params.h {
            rhs.push(vec![0u8; symbol_size]);
        }
        for sym in source_symbols {
            rhs.push(sym.clone());
        }
        for _ in k..params.k_prime {
            rhs.push(vec![0u8; symbol_size]);
        }

        let intermediate = matrix.solve(&rhs)?;

        // Initialize stats
        let stats = EncodingStats {
            source_symbol_count: k,
            ldpc_symbol_count: params.s,
            hdpc_symbol_count: params.h,
            intermediate_symbol_count: params.l,
            symbol_size,
            seed,
            repair_symbols_generated: 0,
            degree_min: usize::MAX,
            degree_max: 0,
            degree_sum: 0,
            degree_count: 0,
            systematic_bytes_emitted: 0,
            repair_bytes_emitted: 0,
        };

        Some(Self {
            params,
            intermediate,
            source_symbols: source_symbols.to_vec(),
            seed,
            stats,
            systematic_emitted: false,
            next_repair_esi: k as u32,
        })
    }

    /// Returns the encoding parameters.
    #[must_use]
    pub const fn params(&self) -> &SystematicParams {
        &self.params
    }

    /// Generate a repair symbol for the given encoding symbol index (ESI).
    ///
    /// ESI values >= K produce repair symbols. The same ESI always
    /// produces the same repair symbol (deterministic).
    #[must_use]
    pub fn repair_symbol(&self, esi: u32) -> Vec<u8> {
        self.repair_symbol_with_degree(esi).0
    }

    /// Generate a repair symbol into a caller-provided buffer.
    ///
    /// Writes the repair symbol data into `buf[..symbol_size]`, avoiding
    /// heap allocation for the result. `buf` must be at least `symbol_size` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < symbol_size`.
    pub fn repair_symbol_into(&self, esi: u32, buf: &mut [u8]) {
        assert!(
            buf.len() >= self.params.symbol_size,
            "buf too small: {} < {}",
            buf.len(),
            self.params.symbol_size
        );
        self.repair_symbol_into_with_degree(esi, buf);
    }

    /// Returns a reference to intermediate symbol `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i >= L`.
    #[must_use]
    pub fn intermediate_symbol(&self, i: usize) -> &[u8] {
        &self.intermediate[i]
    }

    /// Returns the current encoding statistics.
    #[must_use]
    pub fn stats(&self) -> &EncodingStats {
        &self.stats
    }

    /// Returns the seed used for encoding.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Emit all source (systematic) symbols in deterministic order (ESI 0..K-1).
    ///
    /// Source symbols are emitted unchanged from the input, in index order.
    /// Each has degree=1 since it maps directly to one intermediate symbol.
    ///
    /// Updates `systematic_bytes_emitted` in stats and sets the emission flag.
    pub fn emit_systematic(&mut self) -> Vec<EmittedSymbol> {
        let symbols: Vec<EmittedSymbol> = self
            .source_symbols
            .iter()
            .enumerate()
            .map(|(i, data)| EmittedSymbol {
                esi: i as u32,
                data: data.clone(),
                is_source: true,
                degree: 1,
            })
            .collect();

        // Invariant: ESIs are strictly ascending 0..K
        debug_assert!(
            symbols.iter().enumerate().all(|(i, s)| s.esi == i as u32),
            "systematic emission ESIs must be 0..K in order"
        );

        // Track bytes emitted
        let bytes: usize = symbols.iter().map(|s| s.data.len()).sum();
        self.stats.systematic_bytes_emitted += bytes;
        self.systematic_emitted = true;

        symbols
    }

    /// Emit repair symbols in deterministic order from the current cursor position.
    ///
    /// `count` specifies how many repair symbols to generate.
    /// Symbols are emitted in ascending ESI order, continuing from where
    /// the previous call left off (starting at ESI = K for the first call).
    ///
    /// This method updates internal statistics and advances the emission cursor.
    /// Multiple calls emit non-overlapping, monotonically increasing ESI sequences.
    pub fn emit_repair(&mut self, count: usize) -> Vec<EmittedSymbol> {
        let start_esi = self.next_repair_esi;
        let symbol_size = self.params.symbol_size;
        let mut result = Vec::with_capacity(count);

        // Reuse buffer across iterations to avoid per-symbol allocation.
        let mut buf = vec![0u8; symbol_size];

        for i in 0..count {
            let esi = start_esi + i as u32;
            let degree = self.repair_symbol_into_with_degree(esi, &mut buf);
            let data = buf[..symbol_size].to_vec();

            // Update stats
            self.stats.repair_symbols_generated += 1;
            self.stats.degree_min = self.stats.degree_min.min(degree);
            self.stats.degree_max = self.stats.degree_max.max(degree);
            self.stats.degree_sum += degree;
            self.stats.degree_count += 1;
            self.stats.repair_bytes_emitted += data.len();

            result.push(EmittedSymbol {
                esi,
                data,
                is_source: false,
                degree,
            });
        }

        // Advance cursor
        self.next_repair_esi = start_esi + count as u32;

        // Invariant: all emitted ESIs are strictly ascending and >= K
        debug_assert!(
            result
                .iter()
                .enumerate()
                .all(|(i, s)| s.esi == start_esi + i as u32),
            "repair emission ESIs must be monotonically ascending"
        );
        debug_assert!(
            result.iter().all(|s| s.esi >= self.params.k as u32),
            "repair ESIs must be >= K"
        );

        result
    }

    /// Emit all symbols (systematic + repair) in deterministic order.
    ///
    /// First emits K source symbols (ESI 0..K-1), then `repair_count` repair
    /// symbols (ESI K..K+repair_count-1).
    pub fn emit_all(&mut self, repair_count: usize) -> Vec<EmittedSymbol> {
        let mut result: Vec<EmittedSymbol> = self.emit_systematic();
        result.extend(self.emit_repair(repair_count));

        // Invariant: combined stream has source before repair, ESIs strictly ascending
        debug_assert!(
            result.windows(2).all(|w| w[0].esi < w[1].esi),
            "combined emission must have strictly ascending ESIs"
        );

        result
    }

    /// Returns the next repair ESI that will be emitted.
    ///
    /// Starts at K and advances with each `emit_repair()` call.
    #[must_use]
    pub const fn next_repair_esi(&self) -> u32 {
        self.next_repair_esi
    }

    /// Returns whether systematic symbols have been emitted.
    #[must_use]
    pub const fn systematic_emitted(&self) -> bool {
        self.systematic_emitted
    }

    /// Generate a repair symbol into `buf` using RFC tuple-derived equation terms.
    ///
    /// `buf` must be at least `symbol_size` bytes; it is zeroed then filled.
    fn repair_symbol_into_with_degree(&self, esi: u32, buf: &mut [u8]) -> usize {
        let symbol_size = self.params.symbol_size;
        buf[..symbol_size].fill(0);

        let (columns, coefficients) = self.params.rfc_repair_equation(esi);
        debug_assert_eq!(
            columns.len(),
            coefficients.len(),
            "RFC repair equation columns/coefficients mismatch"
        );
        debug_assert!(
            columns.iter().all(|&idx| idx < self.params.l),
            "RFC repair equation index out of range"
        );

        for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
            if coefficient.is_zero() {
                continue;
            }
            gf256_addmul_slice(
                &mut buf[..symbol_size],
                &self.intermediate[column],
                coefficient,
            );
        }

        columns.len()
    }

    /// Generate a repair symbol and return both data and degree.
    fn repair_symbol_with_degree(&self, esi: u32) -> (Vec<u8>, usize) {
        let mut result = vec![0u8; self.params.symbol_size];
        let degree = self.repair_symbol_into_with_degree(esi, &mut result);
        (result, degree)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    /// Try to create an encoder, returning None if the constraint matrix is
    /// singular (known issue tracked by bd-uix9 for small K values).
    fn try_encoder(k: usize, symbol_size: usize, seed: u64) -> Option<SystematicEncoder> {
        let source = make_source_symbols(k, symbol_size);
        SystematicEncoder::new(&source, symbol_size, seed)
    }

    /// Create an encoder with parameters known to produce a non-singular matrix,
    /// or skip the test if no working configuration is found.
    /// Tries the given (k, symbol_size, seed) first, then fallback values.
    fn require_encoder(k: usize, symbol_size: usize, seed: u64) -> SystematicEncoder {
        if let Some(enc) = try_encoder(k, symbol_size, seed) {
            return enc;
        }
        // Fallback: try larger K values that have better rank coverage
        for try_k in [k, 16, 32, 64, 128] {
            for &try_seed in &[seed, 42, 99, 7777] {
                if let Some(enc) = try_encoder(try_k, symbol_size, try_seed) {
                    return enc;
                }
            }
        }
        panic!(
            "could not create encoder for any tested (k, seed) combination; \
             matrix singularity issue (bd-uix9)"
        );
    }

    #[test]
    fn params_small() {
        let p = SystematicParams::for_source_block(4, 64);
        assert_eq!(p.k, 4);
        assert_eq!(p.k_prime, 10);
        assert_eq!(p.j, 254);
        assert_eq!(p.s, 7);
        assert_eq!(p.h, 10);
        assert_eq!(p.w, 17);
        assert_eq!(p.b, p.w - p.s);
        assert_eq!(p.p, p.l - p.w);
        assert_eq!(p.l, p.k_prime + p.s + p.h);
    }

    #[test]
    fn params_medium() {
        let p = SystematicParams::for_source_block(100, 256);
        assert_eq!(p.k, 100);
        assert_eq!(p.k_prime, 101);
        assert_eq!(p.j, 562);
        assert_eq!(p.s, 17);
        assert_eq!(p.h, 10);
        assert_eq!(p.w, 113);
        assert_eq!(p.b, p.w - p.s);
        assert_eq!(p.p, p.l - p.w);
        assert_eq!(p.l, p.k_prime + p.s + p.h);
    }

    #[test]
    fn params_lookup_uses_smallest_k_prime_ge_k() {
        let p = SystematicParams::for_source_block(11, 64);
        assert_eq!(p.k, 11);
        assert_eq!(p.k_prime, 12);
        assert_eq!(p.j, 630);
        assert_eq!(p.s, 7);
        assert_eq!(p.h, 10);
        assert_eq!(p.w, 19);
    }

    #[test]
    fn params_lookup_reports_unsupported_k() {
        let err = SystematicParams::try_for_source_block(56404, 64).unwrap_err();
        assert_eq!(
            err,
            SystematicParamError::UnsupportedSourceBlockSize {
                requested: 56404,
                max_supported: 56403
            }
        );
    }

    #[test]
    fn params_lookup_rejects_zero_k() {
        let err = SystematicParams::try_for_source_block(0, 64).unwrap_err();
        assert_eq!(
            err,
            SystematicParamError::UnsupportedSourceBlockSize {
                requested: 0,
                max_supported: 56403
            }
        );
    }

    #[test]
    fn params_lookup_rejects_wrapped_large_k() {
        let huge_k = (u32::MAX as usize) + 1;
        let err = SystematicParams::try_for_source_block(huge_k, 64).unwrap_err();
        assert_eq!(
            err,
            SystematicParamError::UnsupportedSourceBlockSize {
                requested: huge_k,
                max_supported: 56403
            }
        );
    }

    #[test]
    fn soliton_samples_valid_degrees() {
        let sol = RobustSoliton::new(50, 0.2, 0.05);
        let mut rng = DetRng::new(42);
        for _ in 0..1000 {
            let d = sol.sample(rng.next_u64() as u32);
            assert!((1..=50).contains(&d), "degree {d} out of range");
        }
    }

    #[test]
    fn soliton_degree_distribution_not_degenerate() {
        let sol = RobustSoliton::new(20, 0.2, 0.05);
        let mut rng = DetRng::new(123);
        let mut degrees = [0u32; 21];
        for _ in 0..10_000 {
            let d = sol.sample(rng.next_u64() as u32);
            degrees[d] += 1;
        }
        // Multiple degrees should appear (not degenerate)
        let nonzero = degrees.iter().filter(|&&c| c > 0).count();
        assert!(
            nonzero >= 3,
            "distribution too concentrated: {nonzero} nonzero"
        );
        // Low degrees (1-3) should collectively be common
        let low: u32 = degrees[1..=3].iter().sum();
        assert!(
            low > 1000,
            "low degrees should appear frequently: {low}/10000"
        );
    }

    #[test]
    fn soliton_deterministic_same_seed() {
        let sol = RobustSoliton::new(30, 0.2, 0.05);
        let run = |seed: u64| -> Vec<usize> {
            let mut rng = DetRng::new(seed);
            (0..100)
                .map(|_| sol.sample(rng.next_u64() as u32))
                .collect()
        };
        let a = run(42);
        let b = run(42);
        assert_eq!(a, b, "same seed must produce identical degree sequence");
    }

    #[test]
    fn soliton_different_seeds_differ() {
        let sol = RobustSoliton::new(30, 0.2, 0.05);
        let run = |seed: u64| -> Vec<usize> {
            let mut rng = DetRng::new(seed);
            (0..100)
                .map(|_| sol.sample(rng.next_u64() as u32))
                .collect()
        };
        let a = run(42);
        let b = run(12345);
        assert_ne!(a, b, "different seeds should produce different sequences");
    }

    #[test]
    fn soliton_k_accessor() {
        let sol = RobustSoliton::new(42, 0.2, 0.05);
        assert_eq!(sol.k(), 42);
        assert_eq!(sol.max_degree(), 42);
    }

    #[test]
    fn soliton_validate_params() {
        assert!(RobustSoliton::validate_params(50, 0.2, 0.05).is_none());
        assert!(RobustSoliton::validate_params(0, 0.2, 0.05).is_some());
        assert!(RobustSoliton::validate_params(50, -0.1, 0.05).is_some());
        assert!(RobustSoliton::validate_params(50, 0.2, 0.0).is_some());
        assert!(RobustSoliton::validate_params(50, 0.2, 1.0).is_some());
        assert!(RobustSoliton::validate_params(50, f64::NAN, 0.05).is_some());
        assert!(RobustSoliton::validate_params(50, 0.2, f64::INFINITY).is_some());
    }

    #[test]
    fn soliton_k_1_produces_degree_1() {
        let sol = RobustSoliton::new(1, 0.2, 0.05);
        let mut rng = DetRng::new(0);
        for _ in 0..100 {
            let d = sol.sample(rng.next_u64() as u32);
            assert_eq!(d, 1, "k=1 should always produce degree 1");
        }
    }

    #[test]
    fn soliton_large_k_low_degrees_dominate() {
        let sol = RobustSoliton::new(1000, 0.2, 0.05);
        let mut rng = DetRng::new(99);
        let mut low_count = 0;
        let n = 10_000;
        for _ in 0..n {
            let d = sol.sample(rng.next_u64() as u32);
            if d <= 10 {
                low_count += 1;
            }
        }
        // Low degrees should dominate for robust soliton
        assert!(
            low_count > n / 2,
            "low degrees should dominate: {low_count}/{n}"
        );
    }

    #[test]
    fn soliton_configurable_parameters() {
        // Different c and delta produce different distributions
        let sol_a = RobustSoliton::new(50, 0.1, 0.01);
        let sol_b = RobustSoliton::new(50, 0.5, 0.1);
        let mut rng_a = DetRng::new(42);
        let mut rng_b = DetRng::new(42);
        let a: Vec<usize> = (0..100)
            .map(|_| sol_a.sample(rng_a.next_u64() as u32))
            .collect();
        let b: Vec<usize> = (0..100)
            .map(|_| sol_b.sample(rng_b.next_u64() as u32))
            .collect();
        // Same seed but different distributions should differ
        assert_ne!(
            a, b,
            "different parameters should produce different samples"
        );
    }

    #[test]
    fn constraint_matrix_dimensions() {
        let params = SystematicParams::for_source_block(10, 32);
        let matrix = ConstraintMatrix::build(&params, 42);
        assert_eq!(matrix.rows, params.s + params.h + params.k_prime);
        assert_eq!(matrix.cols, params.l);
    }

    #[test]
    fn encoder_creates_successfully() {
        let k = 4;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 42);
        assert!(enc.is_some(), "encoder should be constructible for k={k}");
    }

    #[test]
    fn encoder_deterministic() {
        let k = 8;
        let symbol_size = 64;
        let source = make_source_symbols(k, symbol_size);

        let enc1 = SystematicEncoder::new(&source, symbol_size, 42).unwrap();
        let enc2 = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        // Repair symbols must be identical
        for esi in 0..10u32 {
            assert_eq!(
                enc1.repair_symbol(esi),
                enc2.repair_symbol(esi),
                "repair symbol {esi} differs between runs"
            );
        }
    }

    #[test]
    fn repair_symbols_differ_across_esi() {
        let k = 8;
        let symbol_size = 64;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let r0 = enc.repair_symbol(0);
        let r1 = enc.repair_symbol(1);
        let r2 = enc.repair_symbol(2);

        // Very unlikely all three are identical for different ESIs
        assert!(
            r0 != r1 && r1 != r2,
            "repair symbols should generally differ"
        );
    }

    #[test]
    fn repair_symbol_matches_rfc_equation_terms() {
        let k = 12;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        for esi in (k as u32)..(k as u32 + 8) {
            let repair = enc.repair_symbol(esi);
            let (columns, coefficients) = enc.params().rfc_repair_equation(esi);
            let mut expected = vec![0u8; symbol_size];

            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                gf256_addmul_slice(&mut expected, enc.intermediate_symbol(column), coefficient);
            }

            assert_eq!(
                repair, expected,
                "repair symbol must equal RFC tuple-derived equation expansion for esi={esi}"
            );
        }
    }

    #[test]
    fn emitted_repair_degree_matches_rfc_equation_width() {
        let k = 10;
        let symbol_size = 24;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 7).unwrap();
        let emitted = enc.emit_repair(6);

        for symbol in emitted {
            let (columns, _) = enc.params().rfc_repair_equation(symbol.esi);
            assert_eq!(
                symbol.degree,
                columns.len(),
                "degree metadata must match RFC tuple term count for esi={}",
                symbol.esi
            );
        }
    }

    #[test]
    fn different_seeds_different_repair() {
        let k = 4;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);

        let enc1 = SystematicEncoder::new(&source, symbol_size, 1).unwrap();
        let enc2 = SystematicEncoder::new(&source, symbol_size, 2).unwrap();

        // Intermediate symbols are determined solely by the constraint matrix
        // and source data, so they are seed-independent. Repair symbols use
        // the seed, so those must differ.
        let esi = k as u32; // first repair ESI
        assert_ne!(
            enc1.repair_symbol(esi),
            enc2.repair_symbol(esi),
            "different seeds should produce different repair symbols"
        );
    }

    #[test]
    fn intermediate_symbol_count_equals_l() {
        let k = 10;
        let symbol_size = 16;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 99).unwrap();
        let l = enc.params().l;
        // Access all intermediate symbols without panic
        for i in 0..l {
            assert_eq!(enc.intermediate_symbol(i).len(), symbol_size);
        }
    }

    #[test]
    fn repair_symbol_correct_size() {
        let k = 6;
        let symbol_size = 48;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 77).unwrap();
        for esi in 0..20u32 {
            assert_eq!(enc.repair_symbol(esi).len(), symbol_size);
        }
    }

    // ========================================================================
    // Emission order and stats tests
    // ========================================================================

    #[test]
    fn emit_systematic_order() {
        let k = 5;
        let symbol_size = 16;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let emitted = enc.emit_systematic();

        assert_eq!(emitted.len(), k, "should emit exactly K source symbols");
        for (i, sym) in emitted.iter().enumerate() {
            assert_eq!(sym.esi, i as u32, "ESI should be in order");
            assert!(sym.is_source, "should be marked as source");
            assert_eq!(sym.degree, 1, "source symbols have degree 1");
            assert_eq!(sym.data, source[i], "data should match input");
        }
    }

    #[test]
    fn emit_repair_order() {
        let k = 4;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let repair_count = 10;
        let emitted = enc.emit_repair(repair_count);

        assert_eq!(emitted.len(), repair_count, "should emit requested count");
        for (i, sym) in emitted.iter().enumerate() {
            let expected_esi = k as u32 + i as u32;
            assert_eq!(sym.esi, expected_esi, "ESI should start at K");
            assert!(!sym.is_source, "should be marked as repair");
            assert!(sym.degree >= 1, "degree should be at least 1");
            assert_eq!(sym.data.len(), symbol_size, "correct symbol size");
        }
    }

    #[test]
    fn emit_all_order() {
        let k = 3;
        let symbol_size = 24;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 99).unwrap();

        let repair_count = 5;
        let emitted = enc.emit_all(repair_count);

        assert_eq!(emitted.len(), k + repair_count, "total count");

        // First K are source
        for (i, sym) in emitted.iter().take(k).enumerate() {
            assert_eq!(sym.esi, i as u32);
            assert!(sym.is_source);
        }

        // Rest are repair
        for (i, sym) in emitted.iter().skip(k).enumerate() {
            assert_eq!(sym.esi, (k + i) as u32);
            assert!(!sym.is_source);
        }
    }

    #[test]
    fn emit_repair_deterministic() {
        let k = 6;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);

        let mut enc1 = SystematicEncoder::new(&source, symbol_size, 42).unwrap();
        let mut enc2 = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let r1 = enc1.emit_repair(10);
        let r2 = enc2.emit_repair(10);

        for (s1, s2) in r1.iter().zip(r2.iter()) {
            assert_eq!(s1.esi, s2.esi);
            assert_eq!(s1.data, s2.data);
            assert_eq!(s1.degree, s2.degree);
        }
    }

    #[test]
    fn stats_initialized() {
        let k = 8;
        let symbol_size = 64;
        let seed = 12345u64;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        let stats = enc.stats();
        assert_eq!(stats.source_symbol_count, k);
        assert_eq!(stats.symbol_size, symbol_size);
        assert_eq!(stats.seed, seed);
        assert_eq!(stats.intermediate_symbol_count, enc.params().l);
        assert_eq!(stats.ldpc_symbol_count, enc.params().s);
        assert_eq!(stats.hdpc_symbol_count, enc.params().h);
        assert_eq!(stats.repair_symbols_generated, 0);
    }

    #[test]
    fn stats_updated_on_emit_repair() {
        let k = 4;
        let symbol_size = 16;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        assert_eq!(enc.stats().repair_symbols_generated, 0);
        assert_eq!(enc.stats().degree_count, 0);

        enc.emit_repair(5);

        let stats = enc.stats();
        assert_eq!(stats.repair_symbols_generated, 5);
        assert_eq!(stats.degree_count, 5);
        assert!(stats.degree_min >= 1);
        assert!(stats.degree_max >= stats.degree_min);
        assert!(stats.degree_sum >= 5); // at least 1 per symbol
    }

    #[test]
    fn stats_average_degree() {
        let k = 10;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        // Before any repairs
        let baseline = enc.stats().average_degree();
        assert!(baseline.abs() < f64::EPSILON);

        enc.emit_repair(100);

        let avg = enc.stats().average_degree();
        assert!(avg >= 1.0, "average degree should be at least 1");
        #[allow(clippy::cast_precision_loss)]
        let max_degree = enc.params().l as f64;
        assert!(avg <= max_degree, "average should not exceed L");
    }

    #[test]
    fn stats_overhead_ratio() {
        let k = 20;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let ratio = enc.stats().overhead_ratio();
        // L = K' + S + H, so ratio > 1.0
        assert!(ratio > 1.0, "overhead ratio should be > 1");
        assert!(ratio < 2.0, "overhead ratio should be reasonable");
    }

    #[test]
    fn seed_accessor() {
        let seed = 0xDEAD_BEEF_u64;
        let source = make_source_symbols(4, 16);
        let enc = SystematicEncoder::new(&source, 16, seed).unwrap();
        assert_eq!(enc.seed(), seed);
    }

    // ========================================================================
    // Emission cursor and enhanced stats tests (bd-362e)
    // ========================================================================

    #[test]
    fn repair_cursor_advances_across_calls() {
        let symbol_size = 16;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        assert_eq!(enc.next_repair_esi(), k as u32, "cursor starts at K");

        let batch1 = enc.emit_repair(3);
        assert_eq!(enc.next_repair_esi(), k as u32 + 3);
        assert_eq!(batch1[0].esi, k as u32);
        assert_eq!(batch1[2].esi, k as u32 + 2);

        let batch2 = enc.emit_repair(5);
        assert_eq!(enc.next_repair_esi(), k as u32 + 8);
        assert_eq!(
            batch2[0].esi,
            k as u32 + 3,
            "second batch continues from cursor"
        );
        assert_eq!(batch2[4].esi, k as u32 + 7);
    }

    #[test]
    fn repair_cursor_no_overlap() {
        let symbol_size = 32;
        let mut enc = require_encoder(16, symbol_size, 99);

        let a = enc.emit_repair(4);
        let b = enc.emit_repair(4);

        // ESI ranges must not overlap
        let a_esis: Vec<u32> = a.iter().map(|s| s.esi).collect();
        let b_esis: Vec<u32> = b.iter().map(|s| s.esi).collect();
        for esi in &a_esis {
            assert!(!b_esis.contains(esi), "ESI {esi} appears in both batches");
        }
    }

    #[test]
    fn systematic_emitted_flag() {
        let symbol_size = 16;
        let mut enc = require_encoder(16, symbol_size, 42);

        assert!(!enc.systematic_emitted(), "not emitted initially");
        enc.emit_systematic();
        assert!(enc.systematic_emitted(), "flag set after emission");
    }

    #[test]
    fn stats_bytes_tracking() {
        let symbol_size = 32;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        assert_eq!(enc.stats().systematic_bytes_emitted, 0);
        assert_eq!(enc.stats().repair_bytes_emitted, 0);
        assert_eq!(enc.stats().total_bytes_emitted(), 0);

        enc.emit_systematic();
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            k * symbol_size,
            "systematic bytes = K * symbol_size"
        );
        assert_eq!(enc.stats().repair_bytes_emitted, 0);

        let repair_count = 6;
        enc.emit_repair(repair_count);
        assert_eq!(
            enc.stats().repair_bytes_emitted,
            repair_count * symbol_size,
            "repair bytes = count * symbol_size"
        );
        assert_eq!(
            enc.stats().total_bytes_emitted(),
            (k + repair_count) * symbol_size
        );
    }

    #[test]
    fn stats_encoding_efficiency() {
        let symbol_size = 64;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        // Before emission
        assert!(enc.stats().encoding_efficiency().abs() < f64::EPSILON);

        // Systematic only: efficiency = 1.0
        enc.emit_systematic();
        assert!(
            (enc.stats().encoding_efficiency() - 1.0).abs() < f64::EPSILON,
            "systematic-only emission has efficiency 1.0"
        );

        // After adding repairs: efficiency < 1.0
        enc.emit_repair(k);
        let eff = enc.stats().encoding_efficiency();
        assert!(eff > 0.0 && eff < 1.0, "efficiency with repairs: {eff}");
        // With equal source and repair counts, efficiency should be ~0.5
        assert!(
            (eff - 0.5).abs() < f64::EPSILON,
            "equal source/repair count should give 0.5 efficiency"
        );
    }

    #[test]
    fn stats_repair_overhead() {
        let symbol_size = 16;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        // Before emission
        assert!(enc.stats().repair_overhead().abs() < f64::EPSILON);

        enc.emit_systematic();
        assert!(
            enc.stats().repair_overhead().abs() < f64::EPSILON,
            "no repairs yet, overhead is 0"
        );

        enc.emit_repair(k); // same count as source
        let overhead = enc.stats().repair_overhead();
        assert!(
            (overhead - 1.0).abs() < f64::EPSILON,
            "equal repair/source should give overhead 1.0, got {overhead}"
        );
    }

    #[test]
    fn stats_display_stable() {
        let symbol_size = 16;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        enc.emit_systematic();
        enc.emit_repair(3);

        let display = format!("{}", enc.stats());

        // Display should contain key structural info
        assert!(
            display.contains(&format!("K={k}")),
            "should contain K value"
        );
        assert!(display.contains("sym=16B"), "should contain symbol size");
        assert!(display.contains("repairs=3"), "should contain repair count");

        // Same encoder state should produce identical display
        let display2 = format!("{}", enc.stats());
        assert_eq!(display, display2, "Display must be stable");
    }

    #[test]
    fn stats_cumulative_across_batches() {
        let symbol_size = 32;
        let mut enc = require_encoder(16, symbol_size, 42);

        enc.emit_repair(5);
        let after_first = enc.stats().clone();

        enc.emit_repair(3);
        let after_second = enc.stats().clone();

        assert_eq!(after_second.repair_symbols_generated, 8);
        assert_eq!(after_second.degree_count, 8);
        assert_eq!(after_second.repair_bytes_emitted, 8 * symbol_size);
        assert!(after_second.degree_sum >= after_first.degree_sum);
        assert!(after_second.degree_min <= after_first.degree_min);
        assert!(after_second.degree_max >= after_first.degree_max);
    }

    #[test]
    fn emit_all_esi_strictly_ascending() {
        let symbol_size = 24;
        let mut enc = require_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        let all = enc.emit_all(10);

        // Verify strict ascending ESI order across the entire stream
        for w in all.windows(2) {
            assert!(
                w[0].esi < w[1].esi,
                "ESIs must be strictly ascending: {} vs {}",
                w[0].esi,
                w[1].esi
            );
        }

        // Source-before-repair invariant
        let source_esis: Vec<u32> = all.iter().filter(|s| s.is_source).map(|s| s.esi).collect();
        let repair_esis: Vec<u32> = all.iter().filter(|s| !s.is_source).map(|s| s.esi).collect();
        assert_eq!(source_esis.len(), k, "should have K source symbols");
        if let (Some(&max_src), Some(&min_rep)) = (source_esis.last(), repair_esis.first()) {
            assert!(
                max_src < min_rep,
                "all source ESIs must precede repair ESIs"
            );
        }
    }
}
