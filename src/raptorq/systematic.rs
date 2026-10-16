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
    /// ESI is in the source-symbol range and cannot name a repair symbol.
    RepairEsiBelowK {
        /// The problematic ESI value.
        esi: u32,
        /// First valid repair ESI for this source block.
        k: u32,
    },
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

    fn repair_isi_for_esi(&self, esi: u32) -> Result<u32, SystematicError> {
        let k = u32::try_from(self.k).expect("RFC source block size must fit in u32");
        if esi < k {
            return Err(SystematicError::RepairEsiBelowK { esi, k });
        }

        let padding_delta = u32::try_from(self.k_prime - self.k)
            .expect("RFC systematic padding delta must fit in u32");
        // RFC 6330 repair ISI domain starts at K' and extends upward.
        // ESIs near u32::MAX cannot be validly mapped without overflow.
        // Reject instead of wrapping to avoid silent corruption.
        esi.checked_add(padding_delta)
            .ok_or(SystematicError::EsiOverflow { esi, padding_delta })
    }

    fn rfc_repair_indices(&self, esi: u32) -> Result<Vec<usize>, SystematicError> {
        let repair_isi = self.repair_isi_for_esi(esi)?;
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
        // Allocate exactly `rows * cols` cells. A previous version capped the
        // allocation at `min(rows*cols, 1GiB)` while still storing the full
        // `rows`/`cols`, so any matrix above 1 GiB was backed by a buffer
        // SHORTER than its declared dimensions — `get`/`set`/`add_assign`
        // (`data[row*cols+col]`) would then index out of bounds at a confusing
        // downstream site. `saturating_mul` was also the wrong shape for an
        // alloc (see the same reasoning at `decoder.rs` `snapshot_dense_rhs`):
        // on real overflow it would silently produce a wrong-size buffer. Use
        // `checked_mul` so an overflowing (malformed/impossible) request fails
        // closed at the allocation site with a clear message instead.
        let n = rows
            .checked_mul(cols)
            .expect("constraint matrix dimensions (rows * cols) overflow usize");
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
/// Use [`SystematicEncoder::emit_systematic`] for source-only,
/// [`SystematicEncoder::emit_repair`] for repair-only, or
/// [`SystematicEncoder::emit_all`] for a combined stream.
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
    ///
    /// # Panics
    ///
    /// Panics if `esi < K` or if the RFC repair-ISI mapping overflows.
    #[must_use]
    pub fn repair_symbol(&self, esi: u32) -> Vec<u8> {
        self.try_repair_symbol(esi)
            .unwrap_or_else(|err| panic!("invalid repair ESI {esi}: {err:?}"))
    }

    /// Fallible repair-symbol generation for callers that need to surface
    /// malformed repair ESIs instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SystematicError::RepairEsiBelowK`] when `esi` names a source
    /// symbol and [`SystematicError::EsiOverflow`] when `esi` cannot be mapped
    /// into the RFC repair-ISI domain without overflow.
    pub fn try_repair_symbol(&self, esi: u32) -> Result<Vec<u8>, SystematicError> {
        let mut result = vec![0u8; self.params.symbol_size];
        self.try_repair_symbol_into_with_degree(esi, &mut result)?;
        Ok(result)
    }

    /// Generate a repair symbol into a caller-provided buffer.
    ///
    /// Writes the repair symbol data into `buf[..symbol_size]`, avoiding
    /// heap allocation for the result. `buf` must be at least `symbol_size` bytes.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < symbol_size`, if `esi < K`, or if the RFC
    /// repair-ISI mapping overflows.
    pub fn repair_symbol_into(&self, esi: u32, buf: &mut [u8]) {
        self.try_repair_symbol_into(esi, buf)
            .unwrap_or_else(|err| panic!("invalid repair ESI {esi}: {err:?}"));
    }

    /// Fallible allocation-free repair-symbol generation.
    ///
    /// # Errors
    ///
    /// Returns [`SystematicError::RepairEsiBelowK`] when `esi` names a source
    /// symbol and [`SystematicError::EsiOverflow`] when `esi` cannot be mapped
    /// into the RFC repair-ISI domain without overflow.
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < symbol_size`.
    pub fn try_repair_symbol_into(&self, esi: u32, buf: &mut [u8]) -> Result<(), SystematicError> {
        assert!(
            buf.len() >= self.params.symbol_size,
            "buf too small: {} < {}",
            buf.len(),
            self.params.symbol_size
        );
        self.try_repair_symbol_into_with_degree(esi, buf)?;
        Ok(())
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
            let degree = match self.try_repair_symbol_into_with_degree(esi, &mut buf) {
                Ok(degree) => degree,
                Err(err) => {
                    #[cfg(feature = "tracing-integration")]
                    tracing::warn!(
                        "repair ESI {esi} cannot be mapped into RFC 6330 repair domain: {err:?}"
                    );
                    #[cfg(not(feature = "tracing-integration"))]
                    let _ = err;
                    break;
                }
            };
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
    fn try_repair_symbol_into_with_degree(
        &self,
        esi: u32,
        buf: &mut [u8],
    ) -> Result<usize, SystematicError> {
        let symbol_size = self.params.symbol_size;
        buf[..symbol_size].fill(0);
        let repair_isi = self.params.repair_isi_for_esi(esi)?;

        let Some(pi_modulus) = next_prime_ge(self.params.p) else {
            debug_assert!(false, "RFC repair PI modulus must fit for encoder params");
            return Ok(0);
        };
        let Some(lt_tuple) = try_tuple(
            self.params.j,
            self.params.w,
            self.params.p,
            pi_modulus,
            repair_isi,
        ) else {
            debug_assert!(false, "RFC repair tuple must be valid for encoder params");
            return Ok(0);
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
        Ok(degree)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "systematic_inline_tests.rs"]
mod tests;
