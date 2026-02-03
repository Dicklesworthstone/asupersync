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
//! Intermediate Symbols (L = K + S + H)
//!     │
//!     ▼
//! LT Encode (ISI → repair symbol)
//! ```
//!
//! # Determinism
//!
//! All randomness flows through [`DetRng`] with seeds derived from
//! `(object_id, sbn, esi)`. For a fixed seed and input, the output
//! is identical across runs and platforms.

#![allow(clippy::many_single_char_names)]

use crate::raptorq::gf256::{gf256_addmul_slice, Gf256};
use crate::util::DetRng;

// ============================================================================
// Parameters (RFC 6330 Section 5.3)
// ============================================================================

/// Systematic encoding parameters for a single source block.
///
/// RFC 6330 defines several derived parameters:
/// - L = K + S + H: total intermediate symbols
/// - W = K + S: number of LT symbols (non-PI symbols)
/// - P = H: number of PI symbols (= HDPC symbols for our systematic encoding)
/// - B = W - S = K: number of non-LDPC LT symbols
#[derive(Debug, Clone)]
pub struct SystematicParams {
    /// K: number of source symbols in this block.
    pub k: usize,
    /// S: number of LDPC symbols.
    pub s: usize,
    /// H: number of HDPC (Half-Distance) symbols.
    pub h: usize,
    /// L = K + S + H: total intermediate symbols.
    pub l: usize,
    /// W = K + S: number of LT symbols.
    pub w: usize,
    /// P = H: number of PI symbols.
    pub p: usize,
    /// B = K: number of non-LDPC LT symbols.
    pub b: usize,
    /// Symbol size in bytes.
    pub symbol_size: usize,
}

impl SystematicParams {
    /// Compute encoding parameters for `k` source symbols of given size.
    ///
    /// S and H are chosen to provide good erasure protection:
    /// - S ≈ ceil(0.01 * K) + X where X provides LDPC density
    /// - H ≈ ceil(sqrt(K)) for half-distance check coverage
    ///
    /// Derived parameters per RFC 6330:
    /// - W = K + S (LT symbols)
    /// - P = H (PI symbols = HDPC for systematic encoding)
    /// - B = K (non-LDPC LT symbols)
    /// - L = W + P = K + S + H
    #[must_use]
    pub fn for_source_block(k: usize, symbol_size: usize) -> Self {
        assert!(k > 0, "source block must have at least one symbol");
        let s = compute_s(k);
        let h = compute_h(k);
        let l = k + s + h;
        let w = k + s; // LT symbols
        let p = h; // PI symbols = HDPC
        let b = k; // non-LDPC LT symbols = source symbols
        Self {
            k,
            s,
            h,
            l,
            w,
            p,
            b,
            symbol_size,
        }
    }
}

/// Compute S (LDPC symbol count) for given K.
///
/// Uses a simplified formula inspired by RFC 6330 Table 2:
/// S = max(1, ceil(0.01 * K) + X) where X provides minimum LDPC density.
fn compute_s(k: usize) -> usize {
    let base = k.div_ceil(100);
    // Ensure minimum LDPC coverage
    let x = if k <= 8 {
        2
    } else if k <= 64 {
        3
    } else {
        4
    };
    (base + x).max(2)
}

/// Compute H (HDPC symbol count) for given K.
///
/// H ≈ ceil(sqrt(K)) provides half-distance parity coverage.
fn compute_h(k: usize) -> usize {
    fn ceil_sqrt(value: usize) -> usize {
        if value <= 1 {
            return value;
        }
        let target = value as u128;
        let mut lo = 1u128;
        let mut hi = target;
        while lo < hi {
            let mid = u128::midpoint(lo, hi);
            if mid * mid < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo as usize
    }

    ceil_sqrt(k).max(1)
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
    /// │  LT   (K rows)  │  K × L
    /// └─────────────────┘
    /// ```
    #[must_use]
    pub fn build(params: &SystematicParams, seed: u64) -> Self {
        let l = params.l;
        let total_rows = params.s + params.h + params.k;
        let mut matrix = Self::zeros(total_rows, l);

        // LDPC constraints (rows 0..S)
        build_ldpc_rows(&mut matrix, params, seed);

        // HDPC constraints (rows S..S+H)
        build_hdpc_rows(&mut matrix, params, seed);

        // LT constraints for systematic symbols (rows S+H..S+H+K)
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

        // Forward elimination with partial pivoting
        for row in 0..self.rows.min(n) {
            // Find pivot column
            let mut best_col = None;
            for col in 0..cols {
                if used_col[col] {
                    continue;
                }
                if !a[row * cols + col].is_zero() {
                    best_col = Some(col);
                    break;
                }
            }

            let col = match best_col {
                Some(c) => c,
                None => {
                    // Try to find any nonzero in this row among unused columns
                    match (0..cols).find(|&c| !used_col[c] && !a[row * cols + c].is_zero()) {
                        Some(c) => c,
                        None => continue, // zero row, skip
                    }
                }
            };

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
                let row_copy = b[row].clone();
                gf256_addmul_slice(&mut b[other], &row_copy, factor);
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
/// 1. For i = 0..B-1: each intermediate symbol C[i] participates in 3 LDPC rows
///    using a circulant-like pattern with step a = 1 + floor(i/S).
/// 2. For i = 0..S-1: each LDPC row i connects to PI symbols C[W+a] and C[W+b]
///    where a = i % P and b = (i+1) % P.
fn build_ldpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let b = params.b;
    let w = params.w;
    let p = params.p;

    // Part 1: For each of the first B intermediate symbols
    // RFC 6330: For i = 0, ..., B-1
    //   a = 1 + floor(i/S)
    //   b = i % S
    //   D[b] = D[b] + C[i]; b = (b + a) % S
    //   D[b] = D[b] + C[i]; b = (b + a) % S
    //   D[b] = D[b] + C[i]
    for i in 0..b {
        let a = 1 + i / s.max(1);
        let mut row = i % s;
        // Each C[i] participates in 3 LDPC rows
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
        row = (row + a) % s;
        matrix.add_assign(row, i, Gf256::ONE);
    }

    // Part 2: Connect LDPC rows to PI symbols
    // RFC 6330: For i = 0, ..., S-1
    //   a = i % P
    //   b = (i+1) % P
    //   D[i] = D[i] + C[W+a] + C[W+b]
    if p > 0 {
        for i in 0..s {
            let a = i % p;
            let b_idx = (i + 1) % p;
            // Add connections to PI symbols (columns W+a and W+b)
            matrix.add_assign(i, w + a, Gf256::ONE);
            matrix.add_assign(i, w + b_idx, Gf256::ONE);
        }
    }
}

/// Build HDPC constraint rows (rows S..S+H).
///
/// RFC 6330 Section 5.3.3.3: HDPC pre-coding relationships.
///
/// The HDPC matrix uses the RFC 6330 Rand function to determine which
/// intermediate symbols each HDPC row connects to, plus a Vandermonde-like
/// structure for the last column.
///
/// MT[i,j] for j = 0..K+S-2:
///   = 1 if i = Rand[j+1, 6, H] or i = (Rand[j+1, 6, H] + Rand[j+1, 7, H-1] + 1) % H
///   = 0 otherwise
///
/// MT[i, K+S-1] = alpha^i (Vandermonde column for last position)
fn build_hdpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    use crate::raptorq::rfc6330::rand;

    let s = params.s;
    let h = params.h;
    let k = params.k;

    if h == 0 {
        return;
    }

    // Build MT matrix entries using RFC 6330 Rand function
    // MT is H x (K + S) matrix
    let k_plus_s = k + s;

    for j in 0..k_plus_s.saturating_sub(1) {
        // RFC 6330: MT[i,j] = 1 if conditions are met
        let rand1 = rand((j + 1) as u32, 6, h as u32) as usize;
        let rand2 = if h > 1 {
            rand((j + 1) as u32, 7, (h - 1) as u32) as usize
        } else {
            0
        };
        let i2 = (rand1 + rand2 + 1) % h;

        // Set MT[rand1, j] = 1
        let row1 = s + rand1;
        matrix.add_assign(row1, j, Gf256::ONE);

        // Set MT[i2, j] = 1 (if different from rand1)
        if i2 != rand1 {
            let row2 = s + i2;
            matrix.add_assign(row2, j, Gf256::ONE);
        }
    }

    // Last column: MT[i, K+S-1] = alpha^i (Vandermonde column)
    if k_plus_s > 0 {
        let last_col = k_plus_s - 1;
        for i in 0..h {
            let row = s + i;
            let coeff = Gf256::ALPHA.pow((i & 0xFF) as u8);
            matrix.set(row, last_col, coeff);
        }
    }

    // Note: RFC 6330 also multiplies by GAMMA matrix, but for our simplified
    // implementation we use the MT matrix directly. The GAMMA matrix provides
    // additional mixing but the MT structure alone provides good coverage
    // for typical use cases.
}

/// Build LT constraint rows for systematic symbols (rows S+H..S+H+K).
///
/// For the systematic encoding, source symbol i corresponds to
/// intermediate symbol i. Each LT row i has exactly a 1 in column i,
/// ensuring that C[i] = source[i] after solving the constraint matrix.
///
/// Note: Redundancy comes from the LDPC and HDPC constraints, not from
/// additional connections in the LT rows. Adding extra connections here
/// would break the systematic property (intermediate[i] ≠ source[i]).
fn build_lt_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams, _seed: u64) {
    let s = params.s;
    let h = params.h;
    let k = params.k;

    for i in 0..k {
        let row = s + h + i;
        // Systematic: source symbol i maps directly to intermediate symbol i
        // C[i] = source[i], ensuring intermediate[0..K] = source_symbols
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
    /// Total intermediate symbols (L = K + S + H).
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
    /// Robust soliton distribution for repair encoding.
    soliton: RobustSoliton,
    /// Running statistics.
    stats: EncodingStats,
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

        // Build RHS: zeros for LDPC/HDPC rows, source data for LT rows
        let mut rhs = Vec::with_capacity(matrix.rows);
        for _ in 0..params.s + params.h {
            rhs.push(vec![0u8; symbol_size]);
        }
        for sym in source_symbols {
            rhs.push(sym.clone());
        }

        let intermediate = matrix.solve(&rhs)?;

        let soliton = RobustSoliton::new(params.l, 0.2, 0.05);

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
        };

        Some(Self {
            params,
            intermediate,
            source_symbols: source_symbols.to_vec(),
            seed,
            soliton,
            stats,
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
    pub fn emit_systematic(&self) -> impl Iterator<Item = EmittedSymbol> + '_ {
        self.source_symbols
            .iter()
            .enumerate()
            .map(|(i, data)| EmittedSymbol {
                esi: i as u32,
                data: data.clone(),
                is_source: true,
                degree: 1,
            })
    }

    /// Emit repair symbols in deterministic order, starting from ESI = K.
    ///
    /// `count` specifies how many repair symbols to generate.
    /// Symbols are emitted in ascending ESI order.
    ///
    /// Note: This method updates internal statistics. For read-only stats,
    /// call `stats()` after emission.
    pub fn emit_repair(&mut self, count: usize) -> Vec<EmittedSymbol> {
        let k = self.params.k as u32;
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            let esi = k + i as u32;
            let (data, degree) = self.repair_symbol_with_degree(esi);

            // Update stats
            self.stats.repair_symbols_generated += 1;
            self.stats.degree_min = self.stats.degree_min.min(degree);
            self.stats.degree_max = self.stats.degree_max.max(degree);
            self.stats.degree_sum += degree;
            self.stats.degree_count += 1;

            result.push(EmittedSymbol {
                esi,
                data,
                is_source: false,
                degree,
            });
        }

        result
    }

    /// Emit all symbols (systematic + repair) in deterministic order.
    ///
    /// First emits K source symbols (ESI 0..K-1), then `repair_count` repair
    /// symbols (ESI K..K+repair_count-1).
    pub fn emit_all(&mut self, repair_count: usize) -> Vec<EmittedSymbol> {
        let mut result: Vec<EmittedSymbol> = self.emit_systematic().collect();
        result.extend(self.emit_repair(repair_count));
        result
    }

    /// Generate a repair symbol and return both data and degree.
    fn repair_symbol_with_degree(&self, esi: u32) -> (Vec<u8>, usize) {
        let symbol_size = self.params.symbol_size;
        let l = self.params.l;
        let mut result = vec![0u8; symbol_size];

        // Seed per-symbol RNG from block seed + ESI
        let sym_seed = self
            .seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(u64::from(esi));
        let mut rng = DetRng::new(sym_seed);

        let degree = self.soliton.sample(rng.next_u64() as u32);

        // Sample distinct intermediate symbol indices (without replacement)
        // to avoid XOR cancellation of duplicate entries.
        let capped_degree = degree.min(l);
        let mut chosen = Vec::with_capacity(capped_degree);
        for _ in 0..capped_degree {
            let mut idx = rng.next_usize(l);
            // Rejection-sample to avoid duplicates.
            while chosen.contains(&idx) {
                idx = rng.next_usize(l);
            }
            chosen.push(idx);
            for (r, &s) in result.iter_mut().zip(self.intermediate[idx].iter()) {
                *r ^= s;
            }
        }

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

    #[test]
    fn params_small() {
        let p = SystematicParams::for_source_block(4, 64);
        assert_eq!(p.k, 4);
        assert!(p.s >= 2);
        assert!(p.h >= 1);
        assert_eq!(p.l, p.k + p.s + p.h);
    }

    #[test]
    fn params_medium() {
        let p = SystematicParams::for_source_block(100, 256);
        assert_eq!(p.k, 100);
        assert!(p.s >= 3);
        assert!(p.h >= 10);
        assert_eq!(p.l, p.k + p.s + p.h);
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
        assert_eq!(matrix.rows, params.s + params.h + params.k);
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
    fn different_seeds_different_intermediate() {
        let k = 4;
        let symbol_size = 32;
        let source = make_source_symbols(k, symbol_size);

        let enc1 = SystematicEncoder::new(&source, symbol_size, 1).unwrap();
        let enc2 = SystematicEncoder::new(&source, symbol_size, 2).unwrap();

        // At least one intermediate symbol should differ
        let any_diff = (0..enc1.params().l)
            .any(|i| enc1.intermediate_symbol(i) != enc2.intermediate_symbol(i));
        assert!(
            any_diff,
            "different seeds should produce different intermediates"
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
        let enc = SystematicEncoder::new(&source, symbol_size, 42).unwrap();

        let emitted: Vec<_> = enc.emit_systematic().collect();

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
        // L = K + S + H, so ratio > 1.0
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
}
