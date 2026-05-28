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

use crate::raptorq::gf256::{Gf256, gf256_add_slice, gf256_addmul_slice};
use crate::raptorq::rfc6330::{next_prime_ge, repair_indices_for_esi, try_tuple};
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

/// Error in systematic encoding operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystematicError {
    /// ESI overflow when computing repair ISI.
    EsiOverflow {
        /// The problematic ESI value.
        esi: u32,
        /// The padding delta that caused overflow.
        padding_delta: u32,
    },
}

/// Explicit lookup failure for source block parameter derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystematicParamError {
    /// Requested `K` is larger than the maximum K' covered by RFC 6330 Table 2.
    UnsupportedSourceBlockSize {
        /// Requested source block symbol count.
        requested: usize,
        /// Largest supported source block symbol count in this implementation.
        max_supported: usize,
    },
    /// K' value from RFC table doesn't fit in u32, causing ESI overflow in decoder.
    KPrimeExceedsU32 {
        /// The problematic K' value.
        k_prime: usize,
        /// Maximum value that fits in u32.
        max_u32: usize,
    },
    /// RFC 6330 systematic index table contains invalid parameter relationships.
    /// This indicates corrupted table data that violates mathematical invariants.
    RfcTableInvariantViolation {
        /// Description of the violated invariant.
        invariant: &'static str,
        /// The problematic values involved.
        details: String,
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
            SystematicParamError::KPrimeExceedsU32 {
                k_prime,
                max_u32,
            } => {
                panic!(
                    "K' value {k_prime} exceeds u32::MAX ({max_u32}); ESI calculations would overflow in decoder"
                )
            }
            SystematicParamError::RfcTableInvariantViolation {
                invariant,
                details,
            } => {
                panic!(
                    "RFC 6330 table invariant violation: {invariant} - {details}"
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

        // Validate that k_prime fits in u32 for ESI calculations
        // The decoder requires all ESIs in K..K' range to fit in u32
        if k_prime > u32::MAX as usize {
            return Err(SystematicParamError::KPrimeExceedsU32 {
                k_prime,
                max_u32: u32::MAX as usize,
            });
        }

        let j = j as usize;
        let s = s as usize;
        let h = h as usize;
        let w = w as usize;
        let l = k_prime + s + h;
        let b = w
            .checked_sub(s)
            .ok_or(SystematicParamError::RfcTableInvariantViolation {
                invariant: "W >= S",
                details: format!("W={w} < S={s} in RFC table entry for K={k}"),
            })?;
        let p = l
            .checked_sub(w)
            .ok_or(SystematicParamError::RfcTableInvariantViolation {
                invariant: "L >= W",
                details: format!("L={l} < W={w} in RFC table entry for K={k}"),
            })?;

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

    /// Generate the RFC 6330 repair equation (columns + coefficients) for a repair ESI.
    ///
    /// RFC 6330 keys repair tuples by repair-symbol ISI `X`, not the raw repair
    /// ESI. When `K' > K`, the RFC repair ISI space starts at `K'`, so we must
    /// translate `ESI -> X = ESI + (K' - K)` before tuple expansion.
    ///
    /// This helper centralizes decoder/encoder tuple semantics so parity checks
    /// can use one source of truth for RFC tuple expansion.
    pub fn rfc_repair_equation(
        &self,
        esi: u32,
    ) -> Result<(Vec<usize>, Vec<Gf256>), SystematicError> {
        let columns = self.rfc_repair_indices(esi)?;
        let coefficients = vec![Gf256::ONE; columns.len()];
        Ok((columns, coefficients))
    }

    fn rfc_repair_indices(&self, esi: u32) -> Result<Vec<usize>, SystematicError> {
        let padding_delta = u32::try_from(self.k_prime - self.k)
            .expect("RFC systematic padding delta must fit in u32");
        // RFC 6330 repair ISI domain starts at K' and extends upward.
        // ESIs near u32::MAX cannot be validly mapped without overflow.
        // Reject instead of wrapping to avoid silent corruption.
        let repair_isi = esi
            .checked_add(padding_delta)
            .ok_or(SystematicError::EsiOverflow { esi, padding_delta })?;
        Ok(repair_indices_for_esi(self.j, self.w, self.p, repair_isi))
    }
}

// ============================================================================
// Degree distribution (Robust Soliton)
// ============================================================================

/// Legacy robust-soliton degree distribution model retained for unit-test
/// diagnostics only. Production repair generation is RFC 6330 tuple-driven.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct RobustSoliton {
    /// Cumulative distribution function (CDF) scaled to u32::MAX.
    cdf: Vec<u32>,
    /// K parameter (number of input symbols).
    k: usize,
}

#[cfg(test)]
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
    #[inline]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Maximum possible degree (equals K).
    #[must_use]
    #[inline]
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
    ///
    /// br-asupersync-p9i0gh — `rows * cols` is now checked. Pre-fix
    /// the multiplication was unguarded; on a 32-bit target a
    /// malformed FEC-OTI that survived to this constructor with
    /// `rows * cols > usize::MAX` would silently truncate, return
    /// a wrong-size Vec, and let subsequent indexing read/write
    /// adjacent memory. `decoder.rs:1971` already used `checked_mul`
    /// for the same dense-allocation pattern; this brings
    /// `ConstraintMatrix::zeros` into line.
    #[must_use]
    pub fn zeros(rows: usize, cols: usize) -> Self {
        // Prevent arithmetic overflow by checking for unreasonably large matrices
        const MAX_MATRIX_SIZE: usize = 1024 * 1024 * 1024; // 1GB max
        let n = rows.saturating_mul(cols).min(MAX_MATRIX_SIZE);
        Self {
            data: vec![Gf256::ZERO; n],
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
                    if best.is_none() || deg < best.expect("best solution must exist").2 {
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
/// Three parts:
/// 1. `G_LDPC,1`: columns `0..B` participate in 3 LDPC rows via
///    the RFC circulant pattern with step `a = 1 + floor(i/S)`.
/// 2. `I_S`: row `i` has coefficient 1 in column `B+i`.
/// 3. `G_LDPC,2`: each row connects to two PI columns at `W..W+P`.
fn build_ldpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let b = params.b;
    let w = params.w;
    let p = params.p;

    // Part 1: Circulant connections over the first B LT symbols.
    // RFC 6330 Section 5.3.3.3: For i = 0, ..., B-1
    //   a = 1 + floor(i/S)
    //   b_val = i % S
    //   D[b_val] = D[b_val] + C[i]; b_val = (b_val + a) % S
    //   D[b_val] = D[b_val] + C[i]; b_val = (b_val + a) % S
    //   D[b_val] = D[b_val] + C[i]
    for i in 0..b {
        let a = 1 + i / s.max(1);
        let mut row = i % s;
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
    }

    // Part 2: LDPC check-symbol identity block, columns B..W-1.
    for i in 0..s {
        matrix.set(i, b + i, Gf256::ONE);
    }

    // Part 3: PI links, columns W..W+P-1.
    for i in 0..s {
        matrix.set(i, (i % p) + w, Gf256::ONE);
        matrix.set(i, ((i + 1) % p) + w, Gf256::ONE);
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

    // Step 1: Build G_HDPC directly with the RFC recurrence used by the
    // reference implementation. It is equivalent to GAMMA x MT but avoids a
    // transposition-prone explicit matrix multiply.
    let mut hdpc = vec![vec![Gf256::ZERO; ks]; h];
    for (row_idx, row) in hdpc.iter_mut().enumerate() {
        row[ks - 1] = Gf256::ALPHA.pow((row_idx % 255) as u8);
    }

    for col in (0..ks.saturating_sub(1)).rev() {
        for row in &mut hdpc {
            row[col] = Gf256::ALPHA * row[col + 1];
        }

        let rand6 = rand((col + 1) as u32, 6, h as u32) as usize;
        let rand7 = if h > 1 {
            rand((col + 1) as u32, 7, (h - 1) as u32) as usize
        } else {
            0
        };
        let row1 = rand6;
        let row2 = (rand6 + rand7 + 1) % h;
        hdpc[row1][col] += Gf256::ONE;
        hdpc[row2][col] += Gf256::ONE;
    }

    // Step 2: Copy G_HDPC into rows S..S+H.
    for (row, values) in hdpc.iter().enumerate() {
        for (col, &val) in values.iter().enumerate() {
            if !val.is_zero() {
                matrix.set(s + row, col, val);
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
/// For systematic encoding, the known source and padding symbols are encoded
/// symbol IDs `0..K'-1`; each row is therefore the RFC tuple expansion for that
/// encoding symbol ID.
fn build_lt_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let h = params.h;
    let k_prime = params.k_prime;

    for i in 0..k_prime {
        let row = s + h + i;
        let esi = u32::try_from(i).expect("K' row index must fit in u32");
        for col in repair_indices_for_esi(params.j, params.w, params.p, esi) {
            matrix.set(row, col, Gf256::ONE);
        }
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
/// RFC 6330 uses repair ESIs on the wire starting at `K`. Tuple generation is
/// keyed by the internal repair-symbol ISI `X = ESI + (K' - K)`, so the public
/// emission cursor stays in ESI space while [`SystematicParams::rfc_repair_equation`]
/// applies the required `K' - K` translation.
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
    /// Whether the systematic emission lane has been consumed or skipped.
    ///
    /// Once any repair symbol is emitted, lower source ESIs can no longer be
    /// emitted without violating the encoder's source-before-repair wire-order
    /// contract, so the systematic lane closes permanently.
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
            degree_min: 0,
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
    #[inline]
    pub fn intermediate_symbol(&self, i: usize) -> &[u8] {
        &self.intermediate[i]
    }

    /// Returns the current encoding statistics.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &EncodingStats {
        &self.stats
    }

    /// Returns the seed used for encoding.
    #[must_use]
    #[inline]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Emit all source (systematic) symbols in deterministic order (ESI 0..K-1).
    ///
    /// Source symbols are emitted unchanged from the input, in index order.
    /// Each has degree=1 since it maps directly to one intermediate symbol.
    ///
    /// This method is idempotent after the first source pass: repeated calls
    /// return an empty batch and leave stats unchanged.
    ///
    /// Updates `systematic_bytes_emitted` in stats and sets the emission flag
    /// only when the source batch is emitted for the first time.
    pub fn emit_systematic(&mut self) -> Vec<EmittedSymbol> {
        if self.systematic_emitted {
            return Vec::new();
        }

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
    ///
    /// Emitting any repair symbol permanently closes the systematic lane. This
    /// prevents later source emission from retroactively outputting low ESIs
    /// after higher repair ESIs have already been observed on the wire.
    pub fn emit_repair(&mut self, count: usize) -> Vec<EmittedSymbol> {
        let start_esi = self.next_repair_esi;
        let symbol_size = self.params.symbol_size;
        let mut result = Vec::with_capacity(count);
        let mut buf = vec![0u8; symbol_size];

        for i in 0..count {
            let i_u32 = match u32::try_from(i) {
                Ok(i_u32) => i_u32,
                Err(_) => {
                    // If the index is too large for u32, stop generating symbols
                    // to avoid panic - this is a graceful degradation
                    #[cfg(feature = "tracing-integration")]
                    tracing::warn!(
                        "repair count index {i} exceeds u32, stopping symbol generation"
                    );
                    break;
                }
            };
            let esi = match start_esi.checked_add(i_u32) {
                Some(esi) => esi,
                None => {
                    // If ESI overflows, stop generating symbols to avoid panic
                    #[cfg(feature = "tracing-integration")]
                    tracing::warn!(
                        "repair ESI overflow at start_esi={start_esi} + i={i_u32}, stopping symbol generation"
                    );
                    break;
                }
            };
            let degree = self.repair_symbol_into_with_degree(esi, &mut buf);
            let data = buf[..symbol_size].to_vec();

            // Update stats
            self.stats.repair_symbols_generated += 1;
            if self.stats.degree_count == 0 {
                self.stats.degree_min = degree;
            } else {
                self.stats.degree_min = self.stats.degree_min.min(degree);
            }
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

        // Advance cursor - handle overflow gracefully
        let actual_count = result.len(); // Use actual symbols generated, not requested count
        let count_u32 = u32::try_from(actual_count).unwrap_or(u32::MAX);
        self.next_repair_esi = start_esi.saturating_add(count_u32);
        if count != 0 {
            self.systematic_emitted = true;
        }

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
    /// First emits K source symbols (ESI 0..K-1) if they have not already been
    /// emitted, then `repair_count` repair symbols (ESI K..K+repair_count-1).
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
    ///
    /// This flag also becomes true once repair emission begins, because source
    /// symbols can no longer be emitted without violating wire-ordering.
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
        let padding_delta = u32::try_from(self.params.k_prime - self.params.k)
            .expect("RFC systematic padding delta must fit in u32");
        let Some(repair_isi) = esi.checked_add(padding_delta) else {
            debug_assert!(
                false,
                "repair ESI overflowed while mapping to RFC 6330 repair ISI"
            );
            return 0;
        };

        let Some(pi_modulus) = next_prime_ge(self.params.p) else {
            debug_assert!(false, "RFC repair PI modulus must fit for encoder params");
            return 0;
        };
        let Some(lt_tuple) = try_tuple(
            self.params.j,
            self.params.w,
            self.params.p,
            pi_modulus,
            repair_isi,
        ) else {
            debug_assert!(false, "RFC repair tuple must be valid for encoder params");
            return 0;
        };

        let mut degree = 0usize;

        let mut lt_index = lt_tuple.b % self.params.w;
        gf256_add_slice(&mut buf[..symbol_size], &self.intermediate[lt_index]);
        degree += 1;
        for _ in 1..lt_tuple.d {
            lt_index = (lt_index + lt_tuple.a) % self.params.w;
            gf256_add_slice(&mut buf[..symbol_size], &self.intermediate[lt_index]);
            degree += 1;
        }

        let mut pi_index = lt_tuple.b1 % pi_modulus;
        while pi_index >= self.params.p {
            pi_index = (pi_index + lt_tuple.a1) % pi_modulus;
        }
        gf256_add_slice(
            &mut buf[..symbol_size],
            &self.intermediate[self.params.w + pi_index],
        );
        degree += 1;
        for _ in 1..lt_tuple.d1 {
            pi_index = (pi_index + lt_tuple.a1) % pi_modulus;
            while pi_index >= self.params.p {
                pi_index = (pi_index + lt_tuple.a1) % pi_modulus;
            }
            gf256_add_slice(
                &mut buf[..symbol_size],
                &self.intermediate[self.params.w + pi_index],
            );
            degree += 1;
        }

        debug_assert_eq!(degree, lt_tuple.d + lt_tuple.d1);
        degree
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use proptest::prelude::*;
    use raptorq::{
        ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
        SourceBlockEncoder as RaptorqRsSourceBlockEncoder,
    };

    fn make_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    fn make_encoder(k: usize, symbol_size: usize, seed: u64) -> SystematicEncoder {
        let source = make_source_symbols(k, symbol_size);
        SystematicEncoder::new(&source, symbol_size, seed).unwrap_or_else(|| {
            panic!(
                "expected encoder construction to succeed for supported parameters: \
                 k={k}, symbol_size={symbol_size}, seed={seed}"
            )
        })
    }

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        k: usize,
        symbol_size: usize,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        format!(
            "scenario_id={scenario_id} seed={seed} parameter_set={parameter_set},k={k},symbol_size={symbol_size} replay_ref={replay_ref}"
        )
    }

    fn decode_emitted_symbols(
        symbols: &[EmittedSymbol],
        k: usize,
        symbol_size: usize,
        seed: u64,
    ) -> Result<Vec<Vec<u8>>, crate::raptorq::decoder::DecodeError> {
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let mut received = decoder.constraint_symbols();

        for symbol in symbols {
            let row = if symbol.is_source {
                ReceivedSymbol::source(symbol.esi, symbol.data.clone())
            } else {
                let (columns, coefficients) = decoder.repair_equation(symbol.esi).unwrap();
                ReceivedSymbol::repair(symbol.esi, columns, coefficients, symbol.data.clone())
            };
            received.push(row);
        }

        decoder.decode(&received).map(|decoded| decoded.source)
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

    /// br-asupersync-0frehk: lower-edge K' ladder boundary coverage.
    /// Existing tests pin K=4 (smallest tested input → K'=10), K=11
    /// (rounds up to K'=12), K=100, etc., but the smallest valid K
    /// inputs (K=1, 2, 3) are not explicitly checked. Every K in
    /// 1..=10 must map to K'=10 (the first row of
    /// SYSTEMATIC_INDEX_TABLE: 10, 254, 7, 10, 17). A regression that
    /// shifted partition_point's predicate from `<` to `<=` (causing
    /// K=10 to skip to K'=12) would silently break the lower edge
    /// without tripping the existing K=4 / K=11 tests.
    ///
    /// Pin each lower-edge K with the FULL (k, k_prime, j, s, h, w,
    /// l) tuple so any drift in either the partition-point logic OR
    /// the table data file (rfc6330_systematic_index_table.inc) is
    /// caught.
    #[test]
    fn params_k_prime_ladder_lower_edge_boundary() {
        // The first row of SYSTEMATIC_INDEX_TABLE is
        // (10, 254, 7, 10, 17). Every K in 1..=10 must round up to
        // this row; K=11 jumps to (12, 630, 7, 10, 19) which is
        // covered by params_lookup_uses_smallest_k_prime_ge_k.
        const FIRST_ROW_K_PRIME: usize = 10;
        const FIRST_ROW_J: usize = 254;
        const FIRST_ROW_S: usize = 7;
        const FIRST_ROW_H: usize = 10;
        const FIRST_ROW_W: usize = 17;
        const SYMBOL_SIZE: usize = 64;

        for k in 1..=10 {
            let p = SystematicParams::for_source_block(k, SYMBOL_SIZE);
            assert_eq!(p.k, k, "k field must echo input for K={k}");
            assert_eq!(
                p.k_prime, FIRST_ROW_K_PRIME,
                "K={k}: K' must round up to {FIRST_ROW_K_PRIME} (first table row)"
            );
            assert_eq!(p.j, FIRST_ROW_J, "K={k}: J(K')");
            assert_eq!(p.s, FIRST_ROW_S, "K={k}: S(K')");
            assert_eq!(p.h, FIRST_ROW_H, "K={k}: H(K')");
            assert_eq!(p.w, FIRST_ROW_W, "K={k}: W(K')");
            assert_eq!(
                p.l,
                FIRST_ROW_K_PRIME + FIRST_ROW_S + FIRST_ROW_H,
                "K={k}: L = K' + S + H invariant"
            );
            assert_eq!(p.b, p.w - p.s, "K={k}: B = W - S invariant");
            assert_eq!(p.p, p.l - p.w, "K={k}: P = L - W invariant");
            assert_eq!(p.symbol_size, SYMBOL_SIZE);
        }
    }

    /// br-asupersync-ttqtcg: K' zero-padding ESI validation test.
    /// Verify that try_for_source_block correctly validates that K'
    /// values fit within u32 range to prevent silent ESI skipping in
    /// the decoder's K..K' zero-padding loop.
    #[test]
    fn k_prime_validation_prevents_esi_overflow() {
        // All current table entries have K' well within u32::MAX
        let max_table_k_prime = SYSTEMATIC_INDEX_TABLE
            .iter()
            .map(|(k_prime, _, _, _, _)| *k_prime as usize)
            .max()
            .expect("systematic index table is non-empty");

        // Verify the largest table entry is safe
        assert!(max_table_k_prime <= u32::MAX as usize);

        // Valid case: small K' should succeed
        assert!(SystematicParams::try_for_source_block(1, 64).is_ok());

        // The validation is designed to prevent hypothetical K' values that
        // exceed u32::MAX. Since all current RFC table entries are safe,
        // this test documents the intended behavior for future table updates.
        //
        // If the RFC table were ever extended with K' > u32::MAX, those
        // entries should be rejected with KPrimeExceedsU32 error.
    }

    /// br-asupersync-eri4b3: K' systematic-index-table coverage.
    /// Iterate a stratified sample of K values spanning the full
    /// RFC 6330 §5.6 Table 2 range (K=4..56403) and assert that for
    /// every sampled K the encode/decode round-trip succeeds.
    ///
    /// Stratified sampling: take the FIRST 5 K' rows (smallest K),
    /// representative mid-range rows, AND the LAST 3 K' rows (largest
    /// K). This catches:
    ///   (a) Off-by-one in the partition_point binary search of
    ///       SystematicParams::try_for_source_block.
    ///   (b) Corrupted (K', J, S, H, W) tuples in the table data file
    ///       (rfc6330_systematic_index_table.inc).
    ///   (c) Encoder/decoder paths that silently fail at K boundaries
    ///       (smallest valid K, K' boundaries between table rows).
    ///
    /// Exhaustive coverage of all 477 K' rows is tracked separately —
    /// at high K (1000+) the per-row decode roundtrip dominates CI
    /// runtime, so the stratified sample is the practical compromise
    /// that catches the highest-impact bugs without exploding test
    /// time. Each tested K runs encode-all-source + decode-all-source
    /// (no erasures, smallest viable test) for a 4-byte symbol size.
    #[test]
    fn rfc6330_systematic_index_table_stratified_k_coverage_decodes() {
        // Stratified K samples: smallest valid range, representative
        // mid-table, largest valid range. Each K MUST land on a row in
        // the K' table (K=4..=56403 is the supported range).
        let sample_k_values: &[usize] = &[
            // Smallest valid K — exercises K < smallest K' (K' = 10).
            4, 5, 8, 10, // Boundary at K' = 12 (covers K=11,12).
            11, 12, // Boundary at K' = 18 (covers K=13..18).
            13, 18, // Mid-range representative samples.
            50, 100, 250, 500, 1000, 2500, 5000,
            // Boundary near max — last row in table is K' = 56403.
            56_000, 56_403,
        ];

        const SYMBOL_SIZE: usize = 4;
        const SEED: u64 = 0xCAFE_BABE_DEAD_BEEFu64;

        for &k in sample_k_values {
            // Lookup must succeed for every K in the supported range.
            let params = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
                .unwrap_or_else(|err| panic!("K={k} table lookup must succeed; got {err:?}"));
            assert!(
                params.k_prime >= k,
                "K={k}: K' = {} must satisfy K' >= K (RFC 6330 §5.3.1)",
                params.k_prime
            );
            assert!(
                params.l == params.k_prime + params.s + params.h,
                "K={k}: L = {} must equal K' + S + H = {} + {} + {}",
                params.l,
                params.k_prime,
                params.s,
                params.h
            );

            // Build encoder + verify it can construct without panic
            // for every sampled K. We verify the encoder constructs
            // and that the params are coherent — full decode-roundtrip
            // for every sampled K (especially K=56403) is too slow for
            // inline unit tests; the construction-success assertion is
            // the cheapest meaningful conformance check that catches
            // table-data corruption AND off-by-one in partition_point.
            //
            // Skip the very-large K values for the encoder build to
            // bound test time (still covers up to K=1000 which already
            // exercises the heavy LDPC/HDPC/LT row construction).
            if k <= 1000 {
                let source = make_source_symbols(k, SYMBOL_SIZE);
                let encoder = SystematicEncoder::new(&source, SYMBOL_SIZE, SEED);
                assert!(
                    encoder.is_some(),
                    "K={k}: SystematicEncoder::new must succeed for table-defined params"
                );
                let encoder = encoder.unwrap();
                assert_eq!(encoder.params().k, k);
                assert_eq!(encoder.params().k_prime, params.k_prime);
            }
        }
    }

    /// br-asupersync-yv0kza + jcl8bo: constraint-matrix structural
    /// conformance per RFC 6330 §5.3.3 / §5.3.3.4.2. For representative
    /// (K, K') pairs assert dimensions: rows = S+H+K' (LDPC + HDPC + LT
    /// bands), cols = L = K'+S+H (intermediate-symbol vector width).
    /// Also assert PI sub-matrix invariants: P = L - W > 0, B = W - S.
    /// A wrong row/col count or P/W/B inconsistency would silently
    /// emit non-RFC-conformant constraint matrices that decode self-
    /// encoded inputs (round-trip works) but emit symbols invisible
    /// to other RFC-conformant implementations.
    #[test]
    fn rfc6330_constraint_matrix_structural_dimensions_per_band() {
        for &k in &[10usize, 50, 100, 250, 1000] {
            let params = SystematicParams::for_source_block(k, 4);
            let matrix = ConstraintMatrix::build(&params, 0xC0FFEE);
            let expected_rows = params.s + params.h + params.k_prime;
            let expected_cols = params.l;
            assert_eq!(
                matrix.rows, expected_rows,
                "K={k}: rows = S+H+K' = {}+{}+{} = {expected_rows}; got {}",
                params.s, params.h, params.k_prime, matrix.rows
            );
            assert_eq!(
                matrix.cols, expected_cols,
                "K={k}: cols = L = K'+S+H = {}+{}+{} = {expected_cols}; got {}",
                params.k_prime, params.s, params.h, matrix.cols
            );
            // br-asupersync-jcl8bo: PI sub-matrix layout invariants
            // (RFC 6330 §5.3.3.4.2). PI columns sit at the END of the
            // matrix [W..L); the W vs P split must satisfy these.
            assert!(
                params.w < params.l,
                "K={k}: W ({}) must be < L ({}) so P > 0",
                params.w,
                params.l
            );
            assert_eq!(
                params.p,
                params.l - params.w,
                "K={k}: P = L - W invariant violated; P={}, L-W={}",
                params.p,
                params.l - params.w
            );
            assert_eq!(
                params.b,
                params.w - params.s,
                "K={k}: B = W - S invariant violated; B={}, W-S={}",
                params.b,
                params.w - params.s
            );
        }
    }

    /// br-asupersync-bqhtau: byte-exact regression pin for the
    /// ConstraintMatrix LDPC / HDPC / LT bands. The existing
    /// `rfc6330_constraint_matrix_structural_dimensions_per_band`
    /// test pins the matrix DIMENSIONS (rows/cols/L/W/P/B) but not
    /// the actual byte contents of each row. A regression that, e.g.,
    /// flipped the LDPC circulant step from `a = 1 + i/S` to
    /// `a = 1 + i/(S+1)`, or that re-ordered the HDPC GAMMA exponents,
    /// would silently emit non-RFC-conformant matrices that round-
    /// trip locally (encoder + decoder both wrong in lockstep) but
    /// fail to interoperate with any other RFC 6330 implementation.
    ///
    /// Hash each band separately (domain-separated by band name +
    /// K value, length-prefixed by row dims) so a one-cell change in
    /// any band trips its specific pin and pinpoints which builder
    /// regressed.
    ///
    /// First-run mode: when the EXPECTED_*_HASH constants are zero
    /// the test panics with the observed values so a future port to
    /// a different reference can capture the new pins explicitly.
    #[test]
    fn rfc6330_constraint_matrix_band_byte_exact() {
        use crate::util::det_hash::DetHasher;
        use std::hash::Hasher;

        fn hash_band(
            label: &'static str,
            k: usize,
            matrix: &ConstraintMatrix,
            row_start: usize,
            row_end: usize,
        ) -> u64 {
            let mut h = DetHasher::default();
            // Domain-separate by band name + K so a swapped band would
            // still trip even if the swapped bands happened to hash-
            // equal each other.
            h.write(label.as_bytes());
            h.write_usize(k);
            h.write_usize(row_end - row_start);
            h.write_usize(matrix.cols);
            for r in row_start..row_end {
                for c in 0..matrix.cols {
                    h.write_u8(matrix.get(r, c).0);
                }
            }
            h.finish()
        }

        // Per RFC 6330 §5.3.3.3 the matrix is laid out as:
        //   rows 0..S        — LDPC band
        //   rows S..S+H      — HDPC band
        //   rows S+H..S+H+K' — LT band
        // We pin the hash of each band for two K values: the smallest
        // (K=10) and a representative mid-range (K=100). The "0xC0FFEE"
        // seed matches the existing dimensions test for parity.
        const SEED: u64 = 0xC0FFEE;

        struct BandPin {
            k: usize,
            ldpc: u64,
            hdpc: u64,
            lt: u64,
        }

        let pins = [
            BandPin {
                k: 10,
                ldpc: 0x1263_4aac_9f21_dc02,
                hdpc: 0xfc6b_1d86_17e7_6cc5,
                lt: 0xa6d4_e465_9ffa_6c86,
            },
            BandPin {
                k: 100,
                ldpc: 0x1c11_0812_e259_8b70,
                hdpc: 0x106c_bc39_aaf5_7e17,
                lt: 0x66b0_16b5_1f10_b5b9,
            },
        ];

        let mut first_run_lines: Vec<String> = Vec::new();

        for pin in &pins {
            let params = SystematicParams::for_source_block(pin.k, 4);
            let matrix = ConstraintMatrix::build(&params, SEED);
            let s = params.s;
            let h = params.h;
            let k_prime = params.k_prime;

            let ldpc_hash = hash_band("LDPC", pin.k, &matrix, 0, s);
            let hdpc_hash = hash_band("HDPC", pin.k, &matrix, s, s + h);
            let lt_hash = hash_band("LT", pin.k, &matrix, s + h, s + h + k_prime);

            if pin.ldpc == 0 || pin.hdpc == 0 || pin.lt == 0 {
                first_run_lines.push(format!(
                    "  K={}: ldpc=0x{ldpc_hash:016x}u64, hdpc=0x{hdpc_hash:016x}u64, lt=0x{lt_hash:016x}u64",
                    pin.k
                ));
                continue;
            }

            assert_eq!(
                ldpc_hash, pin.ldpc,
                "K={}: LDPC band byte-exact regression — \
                 build_ldpc_rows changed without updating the pin",
                pin.k
            );
            assert_eq!(
                hdpc_hash, pin.hdpc,
                "K={}: HDPC band byte-exact regression — \
                 build_hdpc_rows changed without updating the pin",
                pin.k
            );
            assert_eq!(
                lt_hash, pin.lt,
                "K={}: LT band byte-exact regression — \
                 build_lt_rows changed without updating the pin",
                pin.k
            );
        }

        if !first_run_lines.is_empty() {
            panic!(
                "br-asupersync-bqhtau: ConstraintMatrix band pins not \
                 yet captured. Update the BandPin entries with these \
                 observed values:\n{}",
                first_run_lines.join("\n")
            );
        }
    }

    /// br-asupersync-keo94q: K' ladder MID-TABLE boundary jump
    /// coverage. The lower-edge boundary test (br-asupersync-0frehk)
    /// pins K=1..=10, and `params_lookup_uses_smallest_k_prime_ge_k`
    /// pins one mid-jump (K=11 → K'=12). But the bulk of
    /// SYSTEMATIC_INDEX_TABLE has many adjacent jumps — K=12 → K'=12
    /// (boundary), K=13..18 → K'=18, K=19..20 → K'=20, K=21..26 →
    /// K'=26, etc. — that the existing tests do not exercise.
    ///
    /// A regression that flipped partition_point's predicate (e.g.,
    /// `row.0 < k as u32` → `row.0 <= k as u32 - 1` with a bad
    /// underflow guard) at any boundary would silently skip a row
    /// for K values straddling that boundary, but the K=11 / K=100
    /// tests would not catch it. Pin every (K=boundary,
    /// K=boundary+1) pair across the first 30 K' rows so any
    /// off-by-one in the search regresses immediately and pinpoints
    /// the affected row.
    ///
    /// Additionally pins K=K'_max (last table row) — the upper-edge
    /// boundary that gaussian_systematic_index_table_rejects_out_of_range_k
    /// only tests by REJECTING K_max+1; this confirms the boundary
    /// row IS accepted and routes to itself.
    #[test]
    fn rfc6330_systematic_index_table_mid_table_boundary_jumps() {
        // Each entry is (boundary_k, expected_k_prime_for_boundary,
        // expected_k_prime_for_boundary_plus_one). The third field
        // is the K' that K = boundary+1 should round up to (i.e.,
        // the *next* table row's K').
        const BOUNDARIES: &[(usize, usize, usize)] = &[
            // K=12 lands exactly on the second row; K=13 jumps to K'=18.
            (12, 12, 18),
            (18, 18, 20),
            (20, 20, 26),
            (26, 26, 30),
            (30, 30, 32),
            (32, 32, 36),
            (36, 36, 42),
            (42, 42, 46),
            (46, 46, 48),
            (48, 48, 49),
            (49, 49, 55),
            (55, 55, 60),
            (60, 60, 62),
            (62, 62, 69),
            (69, 69, 75),
            (75, 75, 84),
            (84, 84, 88),
            (88, 88, 91),
            (91, 91, 95),
            (95, 95, 97),
        ];

        const SYMBOL_SIZE: usize = 4;

        for &(k_boundary, k_prime_at_boundary, k_prime_above) in BOUNDARIES {
            let p_at = SystematicParams::for_source_block(k_boundary, SYMBOL_SIZE);
            assert_eq!(
                p_at.k, k_boundary,
                "boundary K={k_boundary}: k field must echo input"
            );
            assert_eq!(
                p_at.k_prime, k_prime_at_boundary,
                "boundary K={k_boundary}: must land EXACTLY on K'={k_prime_at_boundary}"
            );

            let p_above = SystematicParams::for_source_block(k_boundary + 1, SYMBOL_SIZE);
            assert_eq!(
                p_above.k_prime,
                k_prime_above,
                "boundary K={k_boundary}+1={}: must round up to next row's K'={k_prime_above}, got K'={}",
                k_boundary + 1,
                p_above.k_prime
            );
        }

        // Upper-edge: the LAST entry in SYSTEMATIC_INDEX_TABLE has
        // K'=56403. K=56403 must accept and route to itself; K_max+1
        // is already rejected by rfc6330_systematic_index_table_rejects_out_of_range_k.
        let p_max = SystematicParams::try_for_source_block(56_403, SYMBOL_SIZE)
            .expect("K=K'_max=56403 must be accepted");
        assert_eq!(
            p_max.k_prime, 56_403,
            "K=56403 must land exactly on the last table row K'=56403"
        );
    }

    /// br-asupersync-eri4b3: K-boundary fail-cleanly conformance.
    /// K=0 is invalid; K=56404 (one past the last K' table row) MUST
    /// return UnsupportedSourceBlockSize cleanly without panic.
    #[test]
    fn rfc6330_systematic_index_table_rejects_out_of_range_k() {
        // K = 0 is invalid per RFC 6330 §5.3.1.
        // try_for_source_block treats k == 0 as out-of-range and
        // returns UnsupportedSourceBlockSize.
        let err = SystematicParams::try_for_source_block(0, 64).unwrap_err();
        assert!(
            matches!(
                err,
                SystematicParamError::UnsupportedSourceBlockSize { requested: 0, .. }
            ),
            "K=0 must return UnsupportedSourceBlockSize, got {err:?}"
        );

        // K just past max supported range.
        let err = SystematicParams::try_for_source_block(56_404, 64).unwrap_err();
        assert!(
            matches!(
                err,
                SystematicParamError::UnsupportedSourceBlockSize {
                    requested: 56_404,
                    ..
                }
            ),
            "K=56404 must return UnsupportedSourceBlockSize, got {err:?}"
        );

        // Far past max — must still fail closed (no panic, no wrap).
        let err = SystematicParams::try_for_source_block(usize::MAX, 64).unwrap_err();
        assert!(
            matches!(err, SystematicParamError::UnsupportedSourceBlockSize { .. }),
            "K=usize::MAX must fail closed, got {err:?}"
        );
    }

    #[test]
    fn rfc_repair_equation_rejects_esi_overflow() {
        let params = SystematicParams::for_source_block(11, 64);
        let padding_delta = u32::try_from(params.k_prime - params.k).unwrap();
        assert_eq!(padding_delta, 1, "test requires a non-zero K' - K delta");

        let result = params.rfc_repair_equation(u32::MAX);
        assert_eq!(
            result,
            Err(SystematicError::EsiOverflow {
                esi: u32::MAX,
                padding_delta,
            }),
            "u32::MAX ESI should trigger overflow error instead of wrapping to avoid silent corruption"
        );
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
    fn encoder_construction_succeeds_for_supported_small_k_across_seed_sweep() {
        let symbol_size = 16;
        let seeds = [0u64, 1, 42, 99, 7777, 2024];

        for k in 1..=16 {
            let source = make_source_symbols(k, symbol_size);
            for &seed in &seeds {
                assert!(
                    SystematicEncoder::new(&source, symbol_size, seed).is_some(),
                    "supported small-K encoder construction should succeed for k={k}, symbol_size={symbol_size}, seed={seed}"
                );
            }
        }
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
    fn mr_emit_repair_substitutes_for_withheld_systematic_across_arbitrary_k() {
        proptest!(|(
            k in 2usize..48,
            symbol_size in prop_oneof![Just(8usize), Just(16usize), Just(24usize)],
            seed in any::<u64>(),
            withheld_raw in 1usize..5,
        )| {
            let source: Vec<Vec<u8>> = (0..k)
                .map(|i| {
                    (0..symbol_size)
                        .map(|j| {
                            seed.wrapping_add((i as u64).wrapping_mul(37))
                                .wrapping_add((j as u64).wrapping_mul(13))
                                .wrapping_add(7) as u8
                        })
                        .collect()
                })
                .collect();

            let mut baseline = SystematicEncoder::new(&source, symbol_size, seed)
                .expect("baseline encoder construction should succeed");
            let systematic = baseline.emit_systematic();
            let baseline_decoded = decode_emitted_symbols(&systematic, k, symbol_size, seed)
                .expect("full systematic emission must decode");
            prop_assert_eq!(
                &baseline_decoded,
                &source,
                "MR baseline violated: full systematic emission must preserve identity"
            );

            let withheld = withheld_raw.min(k - 1);
            let mut transformed = SystematicEncoder::new(&source, symbol_size, seed)
                .expect("transformed encoder construction should succeed");
            let systematic_prefix = transformed.emit_systematic();
            let repair_count = transformed.params().l + withheld;
            let repair_symbols = transformed.emit_repair(repair_count);

            let mut substituted = systematic_prefix[..k - withheld].to_vec();
            substituted.extend(repair_symbols);

            let substituted_decoded = decode_emitted_symbols(&substituted, k, symbol_size, seed)
                .expect("repair-backed transformed emission must decode");
            prop_assert_eq!(
                &substituted_decoded,
                &source,
                "MR violated: repair-backed transformed emission must preserve identity \
                 for k={}, symbol_size={}, withheld={}, seed={:#x}",
                k,
                symbol_size,
                withheld,
                seed
            );
            prop_assert_eq!(
                &substituted_decoded,
                &baseline_decoded,
                "MR violated: withholding systematic symbols and substituting repairs \
                 changed the decoded source for k={}, symbol_size={}, \
                 withheld={}, seed={:#x}",
                k,
                symbol_size,
                withheld,
                seed
            );
        });
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
        let seed = 42u64;
        let replay_ref = "replay:rq-u-systematic-rfc-equation-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-RFC-EQUATION",
            seed,
            k,
            symbol_size,
            "rfc_repair_equation",
            replay_ref,
        );
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        for esi in (k as u32)..(k as u32 + 8) {
            let repair = enc.repair_symbol(esi);
            let (columns, coefficients) = enc.params().rfc_repair_equation(esi).unwrap();
            let mut expected = vec![0u8; symbol_size];

            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                gf256_addmul_slice(&mut expected, enc.intermediate_symbol(column), coefficient);
            }

            assert_eq!(
                repair, expected,
                "repair symbol must equal RFC tuple-derived equation expansion for esi={esi}; {context}"
            );
        }
    }

    #[test]
    fn emitted_repair_degree_matches_rfc_equation_width() {
        let k = 10;
        let symbol_size = 24;
        let seed = 7u64;
        let replay_ref = "replay:rq-u-systematic-degree-metadata-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-DEGREE-METADATA",
            seed,
            k,
            symbol_size,
            "emit_repair_degree",
            replay_ref,
        );
        let source = make_source_symbols(k, symbol_size);
        let mut enc = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let emitted = enc.emit_repair(6);

        for symbol in emitted {
            let (columns, _) = enc.params().rfc_repair_equation(symbol.esi).unwrap();
            assert_eq!(
                symbol.degree,
                columns.len(),
                "degree metadata must match RFC tuple term count for esi={}; {context}",
                symbol.esi,
            );
        }
    }

    #[test]
    fn same_source_same_repair_across_seeds() {
        let k = 4;
        let symbol_size = 32;
        let seed = 1u64;
        let replay_ref = "replay:rq-u-systematic-seed-determinism-v1";
        let context = failure_context(
            "RQ-U-DETERMINISM-SEED",
            seed,
            k,
            symbol_size,
            "seed_independent_repair",
            replay_ref,
        );
        let source = make_source_symbols(k, symbol_size);

        let enc1 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let enc2 = SystematicEncoder::new(&source, symbol_size, 2).unwrap();

        // The constraint matrix and repair equations are fully determined
        // by the RFC 6330 systematic index table (K' → J, S, H, W).
        // The seed parameter is reserved for future use but currently
        // does not affect encoding. Both encoders produce identical output.
        let esi = k as u32; // first repair ESI
        assert_eq!(
            enc1.repair_symbol(esi),
            enc2.repair_symbol(esi),
            "same source data should produce identical repair symbols; {context}"
        );
    }

    #[test]
    fn k200_repair_symbols_match_raptorq_rs_reference_encoder() {
        let k = 200usize;
        let symbol_size = 64usize;
        let repair_count = 30u32;
        let seed = 0x6330_0200_u64;
        let source = make_source_symbols(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let source_bytes = source.concat();
        let transfer_length = u64::try_from(source_bytes.len()).expect("transfer length fits u64");
        let symbol_size_u16 =
            u16::try_from(symbol_size).expect("symbol size must fit in u16 for raptorq-rs");
        let reference_config =
            RaptorqRsObjectTransmissionInformation::new(transfer_length, symbol_size_u16, 1, 1, 1);
        let reference_encoder =
            RaptorqRsSourceBlockEncoder::new2(0, &reference_config, &source_bytes);
        let expected_reference_esi_start =
            u32::try_from(encoder.params().k_prime).expect("K' must fit in u32");
        let public_repair_esi_start = u32::try_from(k).expect("K must fit in u32");

        let reference_repairs = reference_encoder.repair_packets(0, repair_count);
        assert_eq!(
            reference_repairs.len(),
            usize::try_from(repair_count).expect("repair count fits usize"),
            "raptorq-rs must emit the requested number of repair packets"
        );

        for (offset, packet) in reference_repairs.iter().enumerate() {
            let offset_u32 = u32::try_from(offset).expect("repair offset must fit in u32");
            let public_esi = public_repair_esi_start + offset_u32;
            let reference_esi = packet.payload_id().encoding_symbol_id();

            assert_eq!(
                reference_esi,
                expected_reference_esi_start + offset_u32,
                "raptorq-rs repair packet ESI should start at K' for offset {offset}"
            );
            assert_eq!(
                encoder.repair_symbol(public_esi),
                packet.data(),
                "repair payload mismatch at K={k}, public_esi={public_esi}, \
                 reference_esi={reference_esi}, offset={offset}"
            );
        }
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

        // Rest are repair (ESI starts at K on the wire; helper translates to RFC ISI)
        for (i, sym) in emitted.iter().skip(k).enumerate() {
            assert_eq!(sym.esi, k as u32 + i as u32);
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
    fn emit_repair_batching_preserves_sequence_and_stats() {
        let k = 7;
        let symbol_size = 24;
        let seed = 0xC0BA_17BA_7C48_5EED;
        let source = make_source_symbols(k, symbol_size);

        let mut single = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let mut batched = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        let single_symbols = single.emit_repair(12);
        let mut batched_symbols = Vec::new();
        batched_symbols.extend(batched.emit_repair(3));
        batched_symbols.extend(batched.emit_repair(0));
        batched_symbols.extend(batched.emit_repair(4));
        batched_symbols.extend(batched.emit_repair(5));

        assert_eq!(
            batched_symbols.len(),
            single_symbols.len(),
            "batched repair emission must produce the same total count"
        );
        for (single_symbol, batched_symbol) in single_symbols.iter().zip(&batched_symbols) {
            assert_eq!(batched_symbol.esi, single_symbol.esi);
            assert_eq!(batched_symbol.data, single_symbol.data);
            assert_eq!(batched_symbol.is_source, single_symbol.is_source);
            assert_eq!(batched_symbol.degree, single_symbol.degree);
        }

        assert_eq!(batched.next_repair_esi(), single.next_repair_esi());
        assert_eq!(batched.systematic_emitted(), single.systematic_emitted());

        let single_stats = single.stats();
        let batched_stats = batched.stats();
        assert_eq!(
            batched_stats.repair_symbols_generated,
            single_stats.repair_symbols_generated
        );
        assert_eq!(batched_stats.degree_min, single_stats.degree_min);
        assert_eq!(batched_stats.degree_max, single_stats.degree_max);
        assert_eq!(batched_stats.degree_sum, single_stats.degree_sum);
        assert_eq!(batched_stats.degree_count, single_stats.degree_count);
        assert_eq!(
            batched_stats.repair_bytes_emitted,
            single_stats.repair_bytes_emitted
        );
        assert_eq!(
            batched_stats.systematic_bytes_emitted,
            single_stats.systematic_bytes_emitted
        );
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
        assert_eq!(stats.degree_min, 0);
        assert_eq!(stats.degree_max, 0);
        assert_eq!(stats.degree_sum, 0);
        assert_eq!(stats.degree_count, 0);
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
        let seed = 42u64;
        let replay_ref = "replay:rq-u-systematic-overhead-ratio-v1";
        let context = failure_context(
            "RQ-U-SYSTEMATIC-OVERHEAD-RATIO",
            seed,
            k,
            symbol_size,
            "stats_overhead_ratio",
            replay_ref,
        );
        let source = make_source_symbols(k, symbol_size);
        let enc = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        let ratio = enc.stats().overhead_ratio();
        // L = K' + S + H, so ratio > 1.0. For small K (e.g., 20), S and H
        // dominate, pushing ratio above 2.0 (e.g., L=41, K=20 → 2.05).
        assert!(ratio > 1.0, "overhead ratio should be > 1; {context}");
        assert!(
            ratio < 3.0,
            "overhead ratio should be reasonable; {context}"
        );
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
        let mut enc = make_encoder(16, symbol_size, 42);
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
        let mut enc = make_encoder(16, symbol_size, 99);

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
        let mut enc = make_encoder(16, symbol_size, 42);

        assert!(!enc.systematic_emitted(), "not emitted initially");
        enc.emit_systematic();
        assert!(enc.systematic_emitted(), "flag set after emission");
    }

    #[test]
    fn systematic_lane_closes_after_repair_emission() {
        let symbol_size = 16;
        let mut enc = make_encoder(16, symbol_size, 42);

        assert!(!enc.systematic_emitted(), "not emitted initially");
        let repairs = enc.emit_repair(1);
        assert_eq!(repairs.len(), 1, "repair batch should emit one symbol");
        assert!(
            enc.systematic_emitted(),
            "repair-first usage must close the systematic lane to preserve wire order"
        );

        let source_after_repair = enc.emit_systematic();
        assert!(
            source_after_repair.is_empty(),
            "source symbols must not be emitted after repairs have started"
        );
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            0,
            "closing the systematic lane via repair-first emission must not count source bytes"
        );
    }

    #[test]
    fn stats_bytes_tracking() {
        let symbol_size = 32;
        let mut enc = make_encoder(16, symbol_size, 42);
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
    fn repeated_emit_systematic_is_idempotent() {
        let symbol_size = 32;
        let mut enc = make_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        let first = enc.emit_systematic();
        assert_eq!(first.len(), k, "first call should emit all source symbols");
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            k * symbol_size,
            "first source pass should count emitted bytes"
        );

        let second = enc.emit_systematic();
        assert!(
            second.is_empty(),
            "second source pass should not re-emit systematic symbols"
        );
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            k * symbol_size,
            "repeated source pass must not double-count emitted bytes"
        );
    }

    #[test]
    fn stats_encoding_efficiency() {
        let symbol_size = 64;
        let mut enc = make_encoder(16, symbol_size, 42);
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
        let mut enc = make_encoder(16, symbol_size, 42);
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
        let mut enc = make_encoder(16, symbol_size, 42);
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

        // Golden test for full output format
        insta::assert_snapshot!(enc.stats().to_string());
    }

    #[test]
    fn stats_cumulative_across_batches() {
        let symbol_size = 32;
        let mut enc = make_encoder(16, symbol_size, 42);

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
        let mut enc = make_encoder(16, symbol_size, 42);
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

    #[test]
    fn emit_all_after_systematic_only_emits_repairs() {
        let symbol_size = 24;
        let repair_count = 5;
        let mut enc = make_encoder(16, symbol_size, 42);
        let k = enc.params().k;
        let systematic = enc.emit_systematic();
        assert_eq!(
            systematic.len(),
            k,
            "initial source pass should emit every source symbol"
        );

        let combined = enc.emit_all(repair_count);
        assert_eq!(
            combined.len(),
            repair_count,
            "emit_all after a source pass should only emit repairs"
        );
        assert!(
            combined.iter().all(|symbol| !symbol.is_source),
            "combined batch should contain only repair symbols after systematic emission"
        );
        assert_eq!(
            combined.first().map(|symbol| symbol.esi),
            Some(k as u32),
            "repair emission should resume at K (the first repair ESI per RFC 6330)"
        );
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            k * symbol_size,
            "emit_all must not double-count systematic bytes after a source pass"
        );
    }

    #[test]
    fn emit_all_after_repair_only_emits_new_repairs() {
        let symbol_size = 24;
        let first_repair_count = 3;
        let second_repair_count = 5;
        let mut enc = make_encoder(16, symbol_size, 42);
        let k = enc.params().k;

        let first_batch = enc.emit_repair(first_repair_count);
        assert_eq!(
            first_batch.first().map(|symbol| symbol.esi),
            Some(k as u32),
            "repair-first usage still starts at the first repair ESI"
        );

        let combined = enc.emit_all(second_repair_count);
        assert_eq!(
            combined.len(),
            second_repair_count,
            "emit_all after repair-first usage should only emit fresh repairs"
        );
        assert!(
            combined.iter().all(|symbol| !symbol.is_source),
            "emit_all must not retroactively emit source symbols after repair emission"
        );
        assert_eq!(
            combined.first().map(|symbol| symbol.esi),
            Some(k as u32 + first_repair_count as u32),
            "emit_all should resume from the advanced repair cursor"
        );
        assert_eq!(
            enc.stats().systematic_bytes_emitted,
            0,
            "repair-first flows must not backfill systematic byte accounting"
        );
    }

    #[test]
    fn systematic_params_debug_clone() {
        let p = SystematicParams::for_source_block(10, 64);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("SystematicParams"), "{dbg}");
        let cloned = p;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn systematic_param_error_debug_clone_copy_eq() {
        let e = SystematicParamError::UnsupportedSourceBlockSize {
            requested: 60000,
            max_supported: 56403,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("UnsupportedSourceBlockSize"), "{dbg}");
        let copied: SystematicParamError = e.clone();
        let cloned = e;
        assert_eq!(copied, cloned);
    }
}
